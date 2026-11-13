"""Windows USB/RNDIS network checks and fixes for the Ascent VRX.

The VRX exposes a USB composite gadget: a CDC-ACM serial port and an RNDIS
network interface with the fixed address ``192.168.3.102/24``. The host needs
an address in the same subnet (``192.168.3.103`` by convention) and an inbound
firewall rule for the reverse shell port.
"""

from __future__ import annotations

import base64
import ctypes
import ipaddress
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

VRX_IP = ipaddress.IPv4Address("192.168.3.102")
USB_SUBNET = ipaddress.IPv4Network("192.168.3.0/24")
PREFERRED_HOST_IP = ipaddress.IPv4Address("192.168.3.103")
USB_PREFIX = 24

STATE_PATH = (
    Path(os.environ.get("LOCALAPPDATA", str(Path.home())))
    / "AscentVRXRootTool"
    / "network_state.json"
)

RNDIS_KEYWORDS = (
    "rndis",
    "remote ndis",
    "usb ethernet",
    "usb ncm",
    "cdc ncm",
    "cdc ecm",
    "gadget",
    "usb lan",
    "caddx",
    "walksnail",
    "ascent",
    "vrx",
)

# Ports that are open on a stock Ascent VRX Max and make good reachability probes.
PROBE_TCP_PORTS = (22, 554, 80, 23)

_PS_PRELUDE = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8\n"


class NetworkError(RuntimeError):
    """Network inspection or configuration failed."""


# ============================================================
# Data types
# ============================================================


@dataclass(frozen=True)
class IPConfig:
    address: ipaddress.IPv4Address
    prefix: int
    origin: str = ""

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Network(f"{self.address}/{self.prefix}", strict=False)

    @property
    def cidr(self) -> str:
        return f"{self.address}/{self.prefix}"

    def contains(self, other: ipaddress.IPv4Address) -> bool:
        return other in self.network


@dataclass
class Adapter:
    ifindex: int
    name: str
    description: str
    status: str
    mac: str = ""
    link_speed: str = ""
    ips: list[IPConfig] = field(default_factory=list)

    @property
    def is_up(self) -> bool:
        return self.status.strip().lower() == "up"

    @property
    def is_rndis(self) -> bool:
        text = f"{self.name} {self.description}".lower()
        return any(word in text for word in RNDIS_KEYWORDS)

    @property
    def label(self) -> str:
        return f"{self.description or self.name} ({self.name})"

    def usable_ips(self, target: ipaddress.IPv4Address = VRX_IP) -> list[IPConfig]:
        return [ip for ip in self.ips if ip.contains(target)]

    def sorted_ips(self) -> list[IPConfig]:
        return sorted(self.ips, key=lambda ip: (ip.address == VRX_IP, ip.address))


@dataclass(frozen=True)
class Reachability:
    present: bool
    method: str
    detail: str
    elapsed_ms: int = 0


@dataclass
class NetworkState:
    adapters: list[Adapter]
    adapter: Adapter | None
    host_ip: ipaddress.IPv4Address | None
    problem: str | None
    problem_detail: str = ""
    proposed_host_ip: ipaddress.IPv4Address | None = None
    proposed_prefix: int = USB_PREFIX

    @property
    def configured(self) -> bool:
        return self.problem is None and self.host_ip is not None


# ============================================================
# PowerShell helpers
# ============================================================


def is_windows() -> bool:
    return os.name == "nt"


def is_admin() -> bool:
    if not is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001 - ctypes probing is best-effort
        return False


@dataclass
class PsResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def text(self) -> str:
        return (self.stdout + "\n" + self.stderr).strip()


def _run_ps(script: str, timeout: float = 60.0) -> PsResult:
    if not is_windows():
        raise NetworkError("PowerShell is only available on Windows")

    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    command = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        encoded,
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            timeout=timeout,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired as error:
        raise NetworkError("PowerShell command timed out") from error

    return PsResult(
        returncode=completed.returncode,
        stdout=completed.stdout.decode("utf-8", "replace").strip(),
        stderr=completed.stderr.decode("utf-8", "replace").strip(),
    )


def _run_ps_json(script: str, timeout: float = 60.0):
    result = _run_ps(_PS_PRELUDE + script, timeout)
    if result.returncode != 0:
        raise NetworkError(result.stderr or result.stdout or "PowerShell failed")
    text = result.stdout.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError as error:
        raise NetworkError(f"unexpected PowerShell output: {text[:300]}") from error


def _read_admin_log(log_path: Path, attempts: int = 5, delay: float = 0.2) -> str | None:
    """Read the elevated task log.

    Returns the trimmed text, an empty string when no log was written, or
    ``None`` when the log stays unreadable. Windows can briefly deny access
    while the elevated process is still closing the file, so retry a few
    times instead of turning a successful fix into a crash.
    """
    for attempt in range(1, attempts + 1):
        try:
            return log_path.read_text(encoding="utf-8-sig", errors="replace").strip()
        except FileNotFoundError:
            return ""
        except OSError:
            if attempt >= attempts:
                return None
            time.sleep(delay)
    return None


def _run_admin(script: str, timeout: float = 180.0) -> tuple[bool, str]:
    """Run a PowerShell script directly if elevated, otherwise via UAC."""
    if not is_windows():
        return False, "Windows is required"

    if is_admin():
        result = _run_ps(_PS_PRELUDE + "$ErrorActionPreference='Stop'\n" + script, timeout)
        return result.returncode == 0, result.text

    temp_dir = Path(tempfile.mkdtemp(prefix="ascent_root_"))
    script_path = temp_dir / "task.ps1"
    log_path = temp_dir / "result.txt"
    # Create the log from this (unelevated) process so it inherits our ACLs.
    # When the elevated process creates it instead, the DACL it leaves behind
    # can be unreadable here even though the operation itself succeeded.
    log_path.touch()
    escaped_script = str(script_path).replace("'", "''")
    escaped_log = str(log_path).replace("'", "''")

    script_path.write_text(
        "$ErrorActionPreference='Stop'\n"
        "try {\n"
        "  & {\n"
        f"{script}\n"
        "  } *> '" + escaped_log + "'\n"
        "  exit 0\n"
        "} catch {\n"
        "  ('ERROR: ' + $_.Exception.Message) | "
        "Out-File -FilePath '" + escaped_log + "' -Append -Encoding utf8\n"
        "  exit 1\n"
        "}\n",
        encoding="utf-8-sig",
    )

    outer = (
        "$ErrorActionPreference='Stop'\n"
        "try {\n"
        "  $p = Start-Process -FilePath 'powershell.exe' -Verb RunAs "
        "-WindowStyle Hidden -Wait -PassThru "
        f"-ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File','{escaped_script}')\n"
        "  exit $p.ExitCode\n"
        "} catch {\n"
        "  Write-Error $_.Exception.Message\n"
        "  exit 1\n"
        "}\n"
    )

    try:
        result = _run_ps(outer, timeout)
        log_text = _read_admin_log(log_path)
        if log_text is None:
            detail = f": {result.text}" if result.text else ""
            message = "the elevated operation completed but its output could not be read" + detail
        else:
            message = log_text or result.text or "the elevated operation did not run"
        return result.returncode == 0, message
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


# ============================================================
# Adapter discovery
# ============================================================


def parse_adapters_json(raw) -> list[Adapter]:
    """Convert ``Get-NetAdapter`` JSON into :class:`Adapter` objects."""
    if raw is None:
        return []
    if isinstance(raw, dict):
        raw = [raw]

    adapters: list[Adapter] = []
    for item in raw:
        if not isinstance(item, dict):
            continue

        raw_ips = item.get("ips") or []
        if isinstance(raw_ips, dict):
            raw_ips = [raw_ips]

        ips: list[IPConfig] = []
        for raw_ip in raw_ips:
            if not isinstance(raw_ip, dict):
                continue
            try:
                address = ipaddress.IPv4Address(str(raw_ip.get("IPAddress", "")))
                prefix = int(raw_ip.get("PrefixLength", 24))
            except (ipaddress.AddressValueError, ValueError, TypeError):
                continue
            ips.append(
                IPConfig(
                    address=address,
                    prefix=prefix,
                    origin=str(raw_ip.get("PrefixOrigin", "")),
                )
            )

        try:
            ifindex = int(item.get("ifIndex", 0))
        except (TypeError, ValueError):
            continue

        adapters.append(
            Adapter(
                ifindex=ifindex,
                name=str(item.get("name", "")),
                description=str(item.get("description", "")),
                status=str(item.get("status", "")),
                mac=str(item.get("mac", "")),
                link_speed=str(item.get("linkSpeed", "")),
                ips=ips,
            )
        )
    return adapters


def list_adapters() -> list[Adapter]:
    script = r"""
$rows = @(
  Get-NetAdapter | Sort-Object ifIndex | ForEach-Object {
    $a = $_
    $ips = @(
      Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Select-Object IPAddress, PrefixLength, PrefixOrigin
    )
    [pscustomobject]@{
      ifIndex     = [int]$a.ifIndex
      name        = [string]$a.Name
      description = [string]$a.InterfaceDescription
      status      = [string]$a.Status
      mac         = [string]$a.MacAddress
      linkSpeed   = [string]$a.LinkSpeed
      ips         = @($ips)
    }
  }
)
ConvertTo-Json -InputObject $rows -Depth 6 -Compress
"""
    return parse_adapters_json(_run_ps_json(script))


def select_adapter(
    adapters: Sequence[Adapter], target: ipaddress.IPv4Address = VRX_IP
) -> Adapter | None:
    up = [adapter for adapter in adapters if adapter.is_up]

    # The USB gadget is always the best match, even before it has an address.
    rndis_in_subnet = [adapter for adapter in up if adapter.is_rndis and adapter.usable_ips(target)]
    if rndis_in_subnet:
        return max(rndis_in_subnet, key=lambda adapter: adapter.ifindex)

    rndis_up = [adapter for adapter in up if adapter.is_rndis]
    if rndis_up:
        return max(rndis_up, key=lambda adapter: adapter.ifindex)

    # Fallback: a non-USB adapter that already sits in the VRX subnet.
    in_subnet = [adapter for adapter in up if adapter.usable_ips(target)]
    if in_subnet:
        return max(in_subnet, key=lambda adapter: adapter.ifindex)

    rndis_any = [adapter for adapter in adapters if adapter.is_rndis]
    if rndis_any:
        return max(rndis_any, key=lambda adapter: (adapter.is_up, adapter.ifindex))

    return None


def local_addresses(adapters: Iterable[Adapter]) -> set[ipaddress.IPv4Address]:
    used: set[ipaddress.IPv4Address] = set()
    for adapter in adapters:
        used.update(ip.address for ip in adapter.ips)
    return used


def choose_available_host_ip(
    adapters: Sequence[Adapter],
    target: ipaddress.IPv4Address = VRX_IP,
    preferred: ipaddress.IPv4Address = PREFERRED_HOST_IP,
) -> ipaddress.IPv4Address:
    used = local_addresses(adapters)

    if preferred != target and preferred not in used:
        return preferred

    for last in (100, 101, 104, 105, 106, 107, 108, 109, 110, 50, 51, 60, 61, 62):
        candidate = ipaddress.IPv4Address(int(USB_SUBNET.network_address) + last)
        if candidate != target and candidate not in used:
            return candidate

    raise NetworkError("could not find a free address in 192.168.3.0/24")


def _pick_host_ip(adapter: Adapter, target: ipaddress.IPv4Address) -> ipaddress.IPv4Address | None:
    candidates = [ip.address for ip in adapter.usable_ips(target)]
    if not candidates:
        return None
    # Prefer a non-VRX address, then the conventional .103, then the lowest.
    candidates.sort(
        key=lambda address: (
            address == target,
            address != PREFERRED_HOST_IP,
            int(address),
        )
    )
    return candidates[0]


# ============================================================
# State analysis
# ============================================================


def analyze(adapters: Sequence[Adapter] | None = None) -> NetworkState:
    if adapters is None and not is_windows():
        return NetworkState(
            adapters=list(adapters or []),
            adapter=None,
            host_ip=None,
            problem="not-windows",
            problem_detail="automatic USB network checks are only available on Windows",
        )

    adapters = list(list_adapters() if adapters is None else adapters)
    adapter = select_adapter(adapters)

    if adapter is None:
        return NetworkState(
            adapters=adapters,
            adapter=None,
            host_ip=None,
            problem="no-adapter",
            problem_detail=(
                "no USB Ethernet / RNDIS adapter was found - connect the VRX "
                "with a USB data cable and power it on"
            ),
            proposed_host_ip=choose_available_host_ip(adapters),
        )

    if not adapter.is_up:
        return NetworkState(
            adapters=adapters,
            adapter=adapter,
            host_ip=None,
            problem="adapter-down",
            problem_detail=(
                f"{adapter.label} is {adapter.status or 'not connected'} - "
                "check the USB cable and the VRX power"
            ),
            proposed_host_ip=choose_available_host_ip(adapters),
        )

    host_ip = _pick_host_ip(adapter, VRX_IP)
    if host_ip is None:
        proposed = choose_available_host_ip(adapters)
        return NetworkState(
            adapters=adapters,
            adapter=adapter,
            host_ip=None,
            problem="not-in-subnet",
            problem_detail=(f"{adapter.label} has no address in {USB_SUBNET} (VRX is {VRX_IP})"),
            proposed_host_ip=proposed,
        )

    if host_ip == VRX_IP:
        proposed = choose_available_host_ip(adapters)
        return NetworkState(
            adapters=adapters,
            adapter=adapter,
            host_ip=None,
            problem="ip-conflict",
            problem_detail=(f"this PC is using {VRX_IP}, which is the VRX's own address"),
            proposed_host_ip=proposed,
        )

    # The prefix can be wider than /24 and still work; reject only networks
    # that cannot contain the VRX address.
    return NetworkState(
        adapters=adapters,
        adapter=adapter,
        host_ip=host_ip,
        problem=None,
        problem_detail="",
    )


def describe_state(state: NetworkState) -> list[tuple[str, str, str | None]]:
    """Build (label, value, status) rows for the UI."""
    rows: list[tuple[str, str, str | None]] = []

    if state.adapter is None:
        rows.append(("USB adapter", "not found", "bad"))
    else:
        status_text = state.adapter.status or "unknown"
        rows.append(
            (
                "USB adapter",
                f"{state.adapter.label}  [{status_text}]",
                "ok" if state.adapter.is_up else "bad",
            )
        )

    if state.host_ip is not None:
        rows.append(("Host address", str(state.host_ip), "ok"))
    elif state.adapter is not None and state.adapter.ips:
        rows.append(
            ("Host address", ", ".join(ip.cidr for ip in state.adapter.sorted_ips()), "bad")
        )
    else:
        rows.append(("Host address", "none", "bad"))

    rows.append(("VRX address", str(VRX_IP), None))

    if state.problem is None:
        rows.append(("USB network", f"ready ({USB_SUBNET})", "ok"))
    else:
        rows.append(("USB network", state.problem_detail, "bad"))

    return rows


# ============================================================
# Reachability
# ============================================================


def _ping(address: ipaddress.IPv4Address, timeout_ms: int = 1200) -> tuple[bool, int]:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            ["ping", "-4", "-n", "1", "-w", str(timeout_ms), str(address)],
            capture_output=True,
            timeout=(timeout_ms / 1000.0) + 3.0,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, 0
    elapsed = int((time.monotonic() - started) * 1000)
    return completed.returncode == 0, elapsed


def neighbor_state(
    address: ipaddress.IPv4Address,
    ifindex: int | None = None,
) -> tuple[str, str, int]:
    script = f"""
$rows = @(
  Get-NetNeighbor -IPAddress '{address}' -ErrorAction SilentlyContinue |
    Select-Object state, mac, ifIndex
)
ConvertTo-Json -InputObject $rows -Depth 3 -Compress
"""
    try:
        raw = _run_ps_json(script, timeout=15)
    except NetworkError:
        return "UNKNOWN", "", ifindex or 0

    if isinstance(raw, dict):
        raw = [raw]
    if not raw:
        return "NONE", "", ifindex or 0

    entries = [entry for entry in raw if isinstance(entry, dict)]
    if ifindex is not None:
        matching = [entry for entry in entries if int(entry.get("ifIndex", -1)) == ifindex]
        if matching:
            entries = matching

    for entry in entries:
        state = str(entry.get("state", "NONE")).upper()
        mac = str(entry.get("mac", ""))
        index = int(entry.get("ifIndex", 0) or 0)
        if state not in ("UNREACHABLE", "INCOMPLETE"):
            return state, mac, index

    state = str(entries[0].get("state", "NONE")).upper() if entries else "NONE"
    return state, "", int(entries[0].get("ifIndex", 0) or 0) if entries else (ifindex or 0)


def _probe_tcp(
    address: ipaddress.IPv4Address,
    ports: Sequence[int] = PROBE_TCP_PORTS,
    timeout: float = 0.45,
) -> list[int]:
    open_ports: list[int] = []
    for port in ports:
        try:
            with socket.create_connection((str(address), port), timeout=timeout):
                open_ports.append(port)
        except OSError:
            continue
    return open_ports


def check_reachability(
    address: ipaddress.IPv4Address = VRX_IP,
    ifindex: int | None = None,
) -> Reachability:
    started = time.monotonic()

    ping_ok, ping_ms = _ping(address)
    if ping_ok:
        return Reachability(
            True,
            "ICMP",
            f"ping reply in {ping_ms} ms",
            int((time.monotonic() - started) * 1000),
        )

    state, mac, _ = neighbor_state(address, ifindex)
    if state not in ("NONE", "UNKNOWN", "UNREACHABLE", "INCOMPLETE") and mac:
        return Reachability(
            True,
            "ARP",
            f"neighbor {state.lower()} ({mac})",
            int((time.monotonic() - started) * 1000),
        )

    open_ports = _probe_tcp(address)
    if open_ports:
        port_text = ", ".join(str(port) for port in open_ports)
        return Reachability(
            True,
            "TCP",
            f"open TCP port(s): {port_text}",
            int((time.monotonic() - started) * 1000),
        )

    state, mac, _ = neighbor_state(address, ifindex)
    detail = "no ICMP reply, no ARP entry and no open probe ports"
    if state not in ("NONE", "UNKNOWN"):
        detail += f" (ARP state: {state.lower()})"
    return Reachability(
        False,
        "none",
        detail,
        int((time.monotonic() - started) * 1000),
    )


# ============================================================
# Fixes
# ============================================================


def netmask_for(prefix: int) -> str:
    return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}", strict=False).netmask)


def manual_static_ip_command(
    adapter: Adapter, host_ip: ipaddress.IPv4Address, prefix: int = USB_PREFIX
) -> str:
    return (
        f'netsh interface ipv4 set address name="{adapter.name}" '
        f"static {host_ip} {netmask_for(prefix)}"
    )


def apply_static_ip(
    adapter: Adapter,
    host_ip: ipaddress.IPv4Address,
    prefix: int = USB_PREFIX,
) -> tuple[bool, str]:
    adapter_name = adapter.name.replace("'", "''")
    script = f"""
$idx = {adapter.ifindex}
Set-NetIPInterface -InterfaceIndex $idx -Dhcp Disabled -ErrorAction Stop
foreach ($ip in @(Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {{
  try {{
    Remove-NetIPAddress -IPAddress $ip.IPAddress -InterfaceIndex $idx -Confirm:$false -ErrorAction Stop
  }} catch {{
    Write-Output ('WARN: could not remove ' + $ip.IPAddress + ': ' + $_.Exception.Message)
  }}
}}
New-NetIPAddress -InterfaceIndex $idx -IPAddress '{host_ip}' -PrefixLength {prefix} -ErrorAction Stop | Out-Null
Write-Output ('OK: set {host_ip}/{prefix} on {adapter_name}')
"""
    return _run_admin(script)


# ============================================================
# Saved state / restore
# ============================================================


def save_network_state(adapter: Adapter, *, overwrite: bool = False) -> Path:
    if STATE_PATH.exists() and not overwrite:
        try:
            existing = json.loads(STATE_PATH.read_text(encoding="utf-8"))
            if existing.get("adapter_name") == adapter.name:
                return STATE_PATH
        except (OSError, json.JSONDecodeError):
            pass

    script = f"""
$idx = {adapter.ifindex}
$iface = Get-NetIPInterface -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction Stop
$ips = @(Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  ForEach-Object {{ "$($_.IPAddress)/$($_.PrefixLength)" }})
$gateways = @(Get-NetRoute -InterfaceIndex $idx -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
  ForEach-Object {{ $_.NextHop }})
$dns = @(Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  ForEach-Object {{ $_.ServerAddresses }})
[pscustomobject]@{{
  adapter_name = [string](Get-NetAdapter -InterfaceIndex $idx).Name
  ifindex      = $idx
  dhcp         = ([string]$iface.Dhcp)
  ips          = @($ips)
  gateways     = @($gateways)
  dns          = @($dns)
}} | ConvertTo-Json -Depth 4 -Compress
"""
    raw = _run_ps_json(script)
    if not isinstance(raw, dict):
        raise NetworkError("could not read the current network configuration")

    raw["saved_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(raw, indent=2), encoding="utf-8")
    return STATE_PATH


def load_network_state() -> dict | None:
    if not STATE_PATH.exists():
        return None
    try:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def describe_saved_state(state: dict) -> str:
    ips = ", ".join(state.get("ips") or []) or "none"
    mode = "DHCP" if str(state.get("dhcp", "")).lower() == "enabled" else "static"
    return f"{state.get('adapter_name', '?')}: {mode}, {ips}"


def restore_network_state(state: dict | None = None) -> tuple[bool, str]:
    state = state or load_network_state()
    if not state:
        return False, "no saved network state"

    adapter_name = str(state.get("adapter_name", "")).replace("'", "''")
    ifindex = int(state.get("ifindex", 0) or 0)
    dhcp = str(state.get("dhcp", "")).lower() == "enabled"
    ips = [str(value) for value in (state.get("ips") or [])]
    gateways = [str(value) for value in (state.get("gateways") or [])]
    dns = [str(value) for value in (state.get("dns") or [])]

    lines: list[str] = []
    lines.append("$idx = " + str(ifindex))
    lines.append("if (-not (Get-NetAdapter -InterfaceIndex $idx -ErrorAction SilentlyContinue)) {")
    lines.append(f"  $a = Get-NetAdapter -Name '{adapter_name}' -ErrorAction SilentlyContinue")
    lines.append("  if (-not $a) { throw 'the USB network adapter is no longer present' }")
    lines.append("  $idx = $a.ifIndex")
    lines.append("}")
    lines.append(
        "Set-NetIPInterface -InterfaceIndex $idx -Dhcp Disabled -ErrorAction SilentlyContinue"
    )
    lines.append(
        "Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
        "ForEach-Object { Remove-NetIPAddress -IPAddress $_.IPAddress -InterfaceIndex $idx "
        "-Confirm:$false -ErrorAction SilentlyContinue }"
    )

    if dhcp:
        lines.append("Set-NetIPInterface -InterfaceIndex $idx -Dhcp Enabled -ErrorAction Stop")
        lines.append("Write-Output 'OK: DHCP enabled'")
    else:
        for cidr in ips:
            try:
                interface = ipaddress.IPv4Interface(cidr)
            except ValueError:
                continue
            lines.append(
                f"New-NetIPAddress -InterfaceIndex $idx -IPAddress '{interface.ip}' "
                f"-PrefixLength {interface.network.prefixlen} -ErrorAction SilentlyContinue | Out-Null"
            )
        for gateway in gateways:
            lines.append(
                f"New-NetRoute -InterfaceIndex $idx -DestinationPrefix '0.0.0.0/0' "
                f"-NextHop '{gateway}' -ErrorAction SilentlyContinue | Out-Null"
            )
        if dns:
            dns_list = ",".join(f"'{server}'" for server in dns)
            lines.append(
                f"Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses @({dns_list}) "
                "-ErrorAction SilentlyContinue"
            )
        lines.append("Write-Output 'OK: previous static configuration restored'")

    ok, message = _run_admin("\n".join(lines))
    if ok:
        try:
            STATE_PATH.unlink(missing_ok=True)
        except OSError:
            pass
    return ok, message


# ============================================================
# Firewall / ports
# ============================================================


def firewall_rule_name(port: int) -> str:
    return f"Ascent VRX Root Tool (TCP {port})"


def firewall_enabled_profiles() -> list[str]:
    if not is_windows():
        return []
    try:
        result = _run_ps(
            _PS_PRELUDE + "@(Get-NetFirewallProfile | Where-Object { $_.Enabled -eq 'True' } | "
            "ForEach-Object { $_.Name }) -join ','",
            timeout=20,
        )
    except NetworkError:
        return ["unknown"]
    if result.returncode != 0:
        return ["unknown"]
    text = result.stdout.strip()
    return [part for part in text.split(",") if part] or []


def firewall_rule_exists(port: int) -> bool:
    if not is_windows():
        return False
    name = firewall_rule_name(port).replace("'", "''")
    try:
        result = _run_ps(
            _PS_PRELUDE
            + f"$r = Get-NetFirewallRule -DisplayName '{name}' -ErrorAction SilentlyContinue; "
            "if ($r -and $r.Enabled -eq 'True') { 'YES' } else { 'NO' }",
            timeout=20,
        )
    except NetworkError:
        return False
    return result.stdout.strip().upper() == "YES"


def ensure_firewall_rule(port: int) -> tuple[bool, str]:
    name = firewall_rule_name(port)
    escaped = name.replace("'", "''")
    script = f"""
$existing = Get-NetFirewallRule -DisplayName '{escaped}' -ErrorAction SilentlyContinue
if (-not $existing) {{
  New-NetFirewallRule -DisplayName '{escaped}' -Direction Inbound -Action Allow `
    -Protocol TCP -LocalPort {port} -RemoteAddress LocalSubnet -Profile Any `
    -Description 'Allows a rooted Ascent VRX to open a reverse shell back to this PC.' | Out-Null
  Write-Output 'OK: firewall rule created'
}} elseif ($existing.Enabled -ne 'True') {{
  Enable-NetFirewallRule -DisplayName '{escaped}' -ErrorAction Stop | Out-Null
  Write-Output 'OK: firewall rule enabled'
}} else {{
  Write-Output 'OK: firewall rule already present'
}}
"""
    return _run_admin(script)


def port_is_free(port: int, host: str = "0.0.0.0") -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def pick_shell_port(preferred: int = 4444, attempts: int = 25) -> int:
    last = min(65535, preferred + attempts - 1)
    for port in range(preferred, last + 1):
        if port_is_free(port):
            return port
    raise NetworkError(f"no free TCP port in {preferred}-{last}")
