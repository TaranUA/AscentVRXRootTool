"""Reverse-shell listener and interactive console bridge.

The rooted VRX connects back with BusyBox ``telnet``. Because the remote shell
runs on a FIFO (not a tty), input is line-buffered and echoed locally, and
output is translated to Windows CRLF by the host.
"""

from __future__ import annotations

import contextlib
import os
import queue
import socket
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

IAC = 255
DONT = 254
DO = 253
WONT = 252
WILL = 251
SB = 250
SE = 240


class TelnetFilter:
    """Strip telnet negotiation from shell output and answer it politely."""

    def __init__(self) -> None:
        self._state = "data"
        self._command = 0

    def feed(self, data: bytes) -> tuple[bytes, bytes]:
        output = bytearray()
        replies = bytearray()

        for byte in data:
            if self._state == "data":
                if byte == IAC:
                    self._state = "iac"
                else:
                    output.append(byte)

            elif self._state == "iac":
                if byte == IAC:
                    output.append(IAC)  # escaped literal 0xFF
                    self._state = "data"
                elif byte in (WILL, WONT, DO, DONT):
                    self._command = byte
                    self._state = "option"
                elif byte == SB:
                    self._state = "subneg"
                else:
                    self._state = "data"

            elif self._state == "option":
                if self._command == DO:
                    replies.extend((IAC, WONT, byte))
                elif self._command == WILL:
                    replies.extend((IAC, DONT, byte))
                self._state = "data"

            elif self._state == "subneg":
                if byte == IAC:
                    self._state = "subneg_iac"

            elif self._state == "subneg_iac":
                self._state = "data" if byte == SE else "subneg"

        return bytes(output), bytes(replies)


class ConsoleWriter:
    """Write remote output with sane CRLF translation and preserve bare CR."""

    def __init__(self, stream=None) -> None:
        self.stream = stream or sys.stdout
        self._last_was_cr = False

    def write(self, text: str) -> None:
        if not text:
            return
        out: list[str] = []
        for char in text:
            if char == "\n":
                if not self._last_was_cr:
                    out.append("\r\n")
                else:
                    out.append("\n")
                self._last_was_cr = False
            else:
                out.append(char)
                self._last_was_cr = char == "\r"
        self.stream.write("".join(out))
        self.stream.flush()


@dataclass
class ShellSession:
    conn: socket.socket
    writer: ConsoleWriter = field(default_factory=ConsoleWriter)
    echo: bool = True
    raw: bool = False
    line: str = ""
    closed: bool = False
    quit_requested: bool = False
    peer: str = ""
    auto_read: bool = True
    _telnet: TelnetFilter = field(default_factory=TelnetFilter)
    _queue: queue.Queue[bytes] = field(default_factory=queue.Queue)
    _send_lock: threading.Lock = field(default_factory=threading.Lock)
    _reader: threading.Thread | None = None
    _esc_state: int = 0

    def __post_init__(self) -> None:
        if self.auto_read:
            self._reader = threading.Thread(
                target=self._read_loop, name="vrx-shell-reader", daemon=True
            )
            self._reader.start()

    # ------------------------------------------------------------------ I/O

    def send(self, text: str) -> None:
        if self.closed:
            return
        data = text.encode("utf-8", errors="replace")
        try:
            with self._send_lock:
                self.conn.sendall(data)
        except OSError:
            self.closed = True

    def _read_loop(self) -> None:
        try:
            while not self.closed:
                try:
                    data = self.conn.recv(4096)
                except OSError:
                    break
                if not data:
                    break
                clean, replies = self._telnet.feed(data)
                if replies:
                    try:
                        with self._send_lock:
                            self.conn.sendall(replies)
                    except OSError:
                        break
                if clean:
                    self._queue.put(clean)
        finally:
            self.closed = True

    def drain(self) -> None:
        while True:
            try:
                data = self._queue.get_nowait()
            except queue.Empty:
                return
            self.writer.write(data.decode("utf-8", errors="replace"))

    def local(self, text: str) -> None:
        self.writer.write(text)

    # ------------------------------------------------------------------ input

    def feed_key(self, char: str) -> None:
        if self.closed or self.quit_requested:
            return

        # Arrow-key escape sequences (POSIX terminals / some Windows input).
        if self._esc_state == 1:
            self._esc_state = 2 if char == "[" else 0
            return
        if self._esc_state == 2:
            self._esc_state = 0
            return
        if char == "\x1b":
            self._esc_state = 1
            return

        if self.raw:
            self._feed_raw(char)
        else:
            self._feed_line(char)

    def _feed_raw(self, char: str) -> None:
        if char in ("\r", "\n"):
            self.send("\n")
            self.local("\r\n")
            return
        if char in ("\x08", "\x7f"):
            self.send("\x7f")
            if self.echo:
                self.local("\b \b")
            return
        if char == "\x03":
            self.send("\x03")
            return
        if char == "\x04":
            self.send("exit\n")
            self.quit_requested = True
            return
        if char == "\t":
            self.send("\t")
            return
        if char.isprintable():
            self.send(char)
            if self.echo:
                self.local(char)

    def _feed_line(self, char: str) -> None:
        if char in ("\r", "\n"):
            self._submit()
            return

        if char in ("\x08", "\x7f"):
            if self.line:
                self.line = self.line[:-1]
                if self.echo:
                    self.local("\b \b")
            return

        if char == "\x03":
            self.line = ""
            self.local("^C\r\n")
            return

        if char == "\x04":
            if not self.line:
                self.send("exit\n")
                self.quit_requested = True
            return

        if char == "\t":
            # The FIFO shell has no readline completion; tabs add noise.
            return

        if char.isprintable():
            self.line += char
            if self.echo:
                self.local(char)

    def _submit(self) -> None:
        line = self.line
        self.line = ""

        self.local("\r\n")

        if not line:
            self.send("\n")
            return

        if line.startswith(":"):
            self._meta(line[1:].strip())
            return

        self.send(line + "\n")

    # ------------------------------------------------------------ local meta

    def _meta(self, command: str) -> None:
        name, _, argument = command.partition(" ")
        name = name.lower()
        argument = argument.strip().lower()

        if name in ("help", "h", "?"):
            self.local(
                "Local commands (not sent to the VRX):\n"
                "  :help             show this help\n"
                "  :echo on|off      local echo of what you type\n"
                "  :raw on|off       send each key immediately (for editors)\n"
                "  :clear            clear this console window\n"
                "  :status           show session details\n"
                "  :quit             close the shell and exit\n"
            )
        elif name in ("quit", "exit", "q"):
            self.send("exit\n")
            self.quit_requested = True
        elif name == "echo":
            if argument in ("on", "1", "yes"):
                self.echo = True
                self.local("Local echo enabled.\n")
            elif argument in ("off", "0", "no"):
                self.echo = False
                self.local("Local echo disabled.\n")
            else:
                self.local(f"Local echo is {'on' if self.echo else 'off'}.\n")
        elif name == "raw":
            if argument in ("on", "1", "yes"):
                self.raw = True
                self.local("Raw mode enabled (keys are sent immediately).\n")
            elif argument in ("off", "0", "no"):
                self.raw = False
                self.local("Line mode enabled (Enter sends the line).\n")
            else:
                self.local(f"Raw mode is {'on' if self.raw else 'off'}.\n")
        elif name == "clear":
            self.local("\x1b[2J\x1b[H")
        elif name == "status":
            self.local(
                f"Peer: {self.peer}\n"
                f"Mode: {'raw' if self.raw else 'line'}, "
                f"echo: {'on' if self.echo else 'off'}\n"
            )
        else:
            self.local(f"Unknown local command ':{name}'. Try :help\n")


class ReverseShellServer:
    """Single-connection TCP listener for the VRX reverse shell."""

    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.last_peer: tuple[str, int] | None = None
        self._socket: socket.socket | None = None

    def open(self) -> int:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((self.host, self.port))
            sock.listen(1)
            self.port = sock.getsockname()[1]
        except OSError:
            sock.close()
            raise
        self._socket = sock
        return self.port

    def accept(
        self,
        timeout: float = 30.0,
        on_wait: Callable[[float], None] | None = None,
    ) -> socket.socket | None:
        if self._socket is None:
            raise RuntimeError("listener is not open")

        self._socket.settimeout(0.5)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if on_wait is not None:
                on_wait(timeout - max(0.0, deadline - time.monotonic()))
            try:
                conn, address = self._socket.accept()
            except TimeoutError:
                continue
            except OSError:
                return None
            conn.settimeout(None)
            try:
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            self.last_peer = address
            return conn
        return None

    def close(self) -> None:
        if self._socket is None:
            return
        try:
            self._socket.close()
        except OSError:
            pass
        self._socket = None


# ============================================================
# Console modes
# ============================================================


@contextlib.contextmanager
def _windows_raw_input():
    import ctypes
    import msvcrt  # noqa: F401  (ensures the console module is available)

    kernel32 = ctypes.windll.kernel32
    handle = kernel32.GetStdHandle(-10)  # STD_INPUT_HANDLE
    mode = ctypes.c_uint32()
    have_mode = bool(kernel32.GetConsoleMode(handle, ctypes.byref(mode)))
    original = mode.value

    if have_mode:
        # Disable line input, echo, Ctrl+C processing and QuickEdit; enable
        # extended flags so QuickEdit can actually be turned off.
        new_mode = (original | 0x0080) & ~(0x0001 | 0x0002 | 0x0004 | 0x0040)
        kernel32.SetConsoleMode(handle, new_mode)

    try:
        yield
    finally:
        if have_mode:
            kernel32.SetConsoleMode(handle, original)


def _windows_char() -> str | None:
    """Read one keypress without blocking, or return None."""
    import msvcrt

    if not msvcrt.kbhit():
        return None
    char = msvcrt.getwch()
    if char in ("\x00", "\u00e0"):
        msvcrt.getwch()  # consume the extended-key code; arrows are not used
        return ""
    return char


def run_shell(
    conn: socket.socket,
    *,
    echo: bool = True,
    raw: bool = False,
    notice: str = "",
    peer: str = "",
) -> str:
    """Run the interactive bridge until the shell closes."""
    session = ShellSession(conn=conn, echo=echo, raw=raw)
    session.peer = peer

    if notice:
        session.local(notice)

    try:
        if os.name == "nt":
            _run_windows(session)
        else:
            _run_posix(session)
    finally:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            conn.close()
        except OSError:
            pass

    return "quit" if session.quit_requested else "closed"


def _run_windows(session: ShellSession) -> None:
    with _windows_raw_input():
        while not session.closed and not session.quit_requested:
            session.drain()
            char = _windows_char()
            if char is None:
                time.sleep(0.01)
                continue
            if char:
                session.feed_key(char)
        # Drain whatever arrived just before the peer closed.
        session.drain()


def _run_posix(session: ShellSession) -> None:
    import select
    import termios
    import tty

    fd = sys.stdin.fileno()
    original = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        while not session.closed and not session.quit_requested:
            session.drain()
            ready, _, _ = select.select([fd], [], [], 0.05)
            if fd not in ready:
                continue
            data = os.read(fd, 1024)
            if not data:
                break
            for char in data.decode("utf-8", errors="replace"):
                session.feed_key(char)
        session.drain()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, original)
