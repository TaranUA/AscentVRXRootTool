#!/usr/bin/env python3
"""Interactive root-shell tool for Caddx / Walksnail Ascent VRX receivers.

Flow:
  1. pick the VRX USB serial port and verify it with GET_DEVICE_INFO
  2. verify (and if needed fix) the host's USB RNDIS network configuration
  3. open an inbound firewall port
  4. inject the reverse-shell payload and bridge the root shell to the console

Authorized use only. This tool writes temporary files in /tmp on the device
and does not modify the firmware.
"""

from __future__ import annotations

import argparse
import importlib
import ipaddress
import socket
import subprocess
import sys
import time

MIN_PYTHON = (3, 10)
PYTHON_DOWNLOAD = "https://www.python.org/downloads/windows/"


def _check_python_version(info: tuple = tuple(sys.version_info)) -> None:
    """Fail early and clearly on interpreters older than the tool supports."""
    if info >= MIN_PYTHON:
        return

    required = ".".join(str(part) for part in MIN_PYTHON)
    current = ".".join(str(part) for part in info[:3])
    print(
        f"Ascent VRX Root Tool needs Python {required} or newer, "
        f"but this interpreter is {current}.",
        file=sys.stderr,
    )
    print(f"  interpreter: {sys.executable}", file=sys.stderr)
    print(f"  download:    {PYTHON_DOWNLOAD}", file=sys.stderr)
    print(
        'Install it with "Add python.exe to PATH" enabled, then run the tool again.',
        file=sys.stderr,
    )
    raise SystemExit(1)


_check_python_version()

from ascent_root import __version__, network, protocol
from ascent_root.shell import ReverseShellServer, run_shell
from ascent_root.ui import UI, configure_console

TOTAL_STEPS = 4


class ToolkitError(RuntimeError):
    """Fatal, user-facing error."""


class UserQuit(Exception):
    """The user chose to stop."""


# ============================================================
# Small helpers
# ============================================================


def parse_ipv4(text: str) -> ipaddress.IPv4Address:
    try:
        return ipaddress.IPv4Address(text.strip())
    except ipaddress.AddressValueError as error:
        raise ToolkitError(f"'{text}' is not a valid IPv4 address") from error


def _required_pyserial() -> str:
    minimum = ".".join(str(part) for part in protocol.MIN_PYSERIAL_VERSION)
    return f"pyserial>={minimum}"


def pyserial_install_hint() -> str:
    """Return the exact command a user can paste to install/upgrade pyserial."""
    return f'"{sys.executable}" -m pip install --upgrade "{_required_pyserial()}"'


def ensure_pyserial(ui: UI, auto: bool) -> None:
    """Make sure an importable pyserial >= 3.5 is available.

    Missing releases are installed and outdated ones upgraded, but only after
    the user agrees (``--yes`` answers yes). An unknown version is reported and
    tolerated so unusual distributions are not blocked.
    """
    minimum = ".".join(str(part) for part in protocol.MIN_PYSERIAL_VERSION)

    if not protocol.HAS_PYSERIAL:
        ui.warn("pyserial is required to talk to the VRX but is not installed.")
        if not ui.confirm("Install pyserial automatically with pip?", True, auto):
            raise ToolkitError(f"Install it with: {pyserial_install_hint()}")
        command = [sys.executable, "-m", "pip", "install", _required_pyserial()]
    else:
        supported = protocol.pyserial_supported()
        version = protocol.pyserial_version() or "unknown"

        if supported is True:
            return
        if supported is None:
            ui.warn(f"Could not determine the pyserial version (reported: {version}).")
            ui.info(f"If the serial port misbehaves, run: {pyserial_install_hint()}")
            return

        ui.warn(f"pyserial {version} is too old; {minimum} or newer is required.")
        if not ui.confirm(f"Upgrade pyserial to {minimum}+ with pip?", True, auto):
            raise ToolkitError(f"Upgrade it with: {pyserial_install_hint()}")
        command = [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--upgrade",
            _required_pyserial(),
        ]

    ui.info("Running: " + " ".join(command))
    try:
        completed = subprocess.run(command, check=False)
    except OSError as error:
        raise ToolkitError(f"could not run pip: {error}") from error

    if completed.returncode != 0:
        raise ToolkitError(
            "pip could not install pyserial. Run it manually: " + pyserial_install_hint()
        )

    importlib.invalidate_caches()
    if not protocol.reload_pyserial():
        raise ToolkitError(
            "pyserial was installed but still cannot be imported. "
            "Run the install manually: " + pyserial_install_hint()
        )

    supported = protocol.pyserial_supported()
    version = protocol.pyserial_version() or "unknown"
    if supported is False:
        raise ToolkitError(
            f"pyserial {version} is still older than {minimum}. "
            "Run the upgrade manually: " + pyserial_install_hint()
        )
    if supported is None:
        ui.ok("pyserial installed (version could not be verified)")
    else:
        ui.ok(f"pyserial {version} ready")


def tag_port(port: protocol.PortInfo) -> str:
    score = protocol.port_score(port)
    if score >= 80:
        return "   <- likely VRX"
    if port.is_bluetooth:
        return "   [Bluetooth]"
    if score > 0:
        return "   [USB serial]"
    return ""


# ============================================================
# Step 1 - serial port and device identity
# ============================================================


def choose_port(ui: UI, args: argparse.Namespace, ignore_override: bool = False) -> str:
    if args.port and not ignore_override:
        ui.ok(f"Using serial port {args.port} (--port)")
        return args.port

    while True:
        try:
            ports = protocol.list_serial_ports()
        except protocol.DependencyError as error:
            raise ToolkitError(str(error)) from error

        if not ports:
            ui.warn("No serial ports found.")
            ui.bullet("Connect the VRX with a USB data cable (not charge-only).")
            ui.bullet("Power the VRX on and wait for it to boot.")
            ui.bullet('Check Device Manager > Ports (COM & LPT) for a "USB Serial Device".')
            if args.yes:
                raise ToolkitError("no serial ports available")

            choice = ui.choose(
                "What now?",
                ["Rescan", "Quit"],
                default=0,
            )
            if choice != 0:
                raise UserQuit
            time.sleep(1.5)
            continue

        ranked = sorted(ports, key=lambda port: (-protocol.port_score(port), port.device))
        options = [f"{port.device:<7} {port.summary}{tag_port(port)}" for port in ranked]
        if protocol.port_score(ranked[0]) >= 40:
            options[0] += "   (recommended)"

        ui.section("Select the VRX serial port")
        choice = ui.choose(
            "Port",
            options,
            default=0,
            auto=args.yes,
            allow_quit=True,
        )
        if choice < 0:
            raise UserQuit
        return ranked[choice].device


def try_probe(ui: UI, port: str) -> protocol.DeviceInfo | None:
    ui.section(f"Verifying the VRX on {port}")
    ui.wait_status(f"Opening {port} and asking the updater for device info ...")
    try:
        link = protocol.AscentLink(port, log=ui.debug)
        try:
            link.open()
            link.reset_buffers()
            info = link.get_device_info(timeout=3.0, retries=2)
        finally:
            link.close()
        ui.end_wait()
        return info
    except protocol.SerialDisconnected as error:
        ui.end_wait()
        ui.error(f"Cannot use {port}: {error}")
        ui.detail(
            "Close the Caddx web updater, the browser serial tab or any other serial monitor."
        )
    except protocol.SerialTimeout:
        ui.end_wait()
        ui.error(f"The device on {port} did not answer the updater handshake.")
        ui.detail("Wrong port, the VRX is still booting, or the upgrade service is busy.")
    except protocol.ProtocolError as error:
        ui.end_wait()
        ui.error(f"Unexpected device response: {error}")
    return None


def show_device_info(ui: UI, port: str, info: protocol.DeviceInfo | None) -> None:
    if info is None:
        ui.warn(f"Continuing without verifying {port}.")
        return

    if info.looks_like_vrx:
        ui.ok(f"Caddx VRX detected on {port}")
    else:
        ui.warn("The device answered, but its name does not look like an Ascent VRX.")

    ui.item("Model", info.device_name or "unknown")
    ui.item("Firmware", info.firmware_info or "unknown")
    ui.item("SDK", info.sdk_version or "unknown")
    ui.item("Serial", info.serial_number or "unknown")
    ui.item("Hardware", info.hardware_version or "unknown")
    ui.item("CPU temp", f"{info.cpu_temp} °C")


def select_and_probe(ui: UI, args: argparse.Namespace) -> tuple[str, protocol.DeviceInfo | None]:
    ui.step(1, TOTAL_STEPS, "Detect the VRX")
    port = choose_port(ui, args)

    while True:
        info = try_probe(ui, port)
        if info is not None:
            show_device_info(ui, port, info)
            return port, info

        if args.yes:
            raise ToolkitError(f"the VRX did not answer on {port}")

        choice = ui.choose(
            "What do you want to do?",
            [
                "Retry the handshake",
                "Choose another serial port",
                "Continue anyway (unusual firmware)",
                "Quit",
            ],
            default=0,
        )
        if choice == 0:
            continue
        if choice == 1:
            port = choose_port(ui, args, ignore_override=True)
            continue
        if choice == 2:
            show_device_info(ui, port, None)
            return port, None
        raise UserQuit


# ============================================================
# Step 2 - USB network
# ============================================================


def display_network(
    ui: UI,
    state: network.NetworkState,
    reach: network.Reachability | None = None,
) -> None:
    for label, value, status in network.describe_state(state):
        ui.item(label, value, status)
    if reach is not None:
        ui.item("Reachability", reach.detail, "ok" if reach.present else "bad")

    # When the USB gadget was not recognized, show what Windows does see so
    # the user can spot a disabled adapter or a missing driver.
    if state.adapter is None and state.adapters:
        ui.blank()
        ui.info("Adapters Windows reports:")
        for adapter in state.adapters:
            addresses = ", ".join(ip.cidr for ip in adapter.sorted_ips()) or "no IPv4 address"
            ui.bullet(
                f"{adapter.name}: {adapter.description} [{adapter.status or '?'}] {addresses}"
            )


def ask_manual_host_ip(ui: UI, args: argparse.Namespace) -> ipaddress.IPv4Address:
    ui.info("Enter the IPv4 address of this PC that the VRX can reach.")
    ui.detail("Over USB, the VRX is 192.168.3.102 and this PC is normally 192.168.3.103.")
    while True:
        text = ui.ask("Host IP:", str(network.PREFERRED_HOST_IP), args.yes)
        try:
            return ipaddress.IPv4Address(text)
        except ipaddress.AddressValueError:
            ui.warn(f"'{text}' is not a valid IPv4 address.")


def apply_proposed_fix(
    ui: UI,
    args: argparse.Namespace,
    state: network.NetworkState,
) -> bool:
    adapter = state.adapter
    proposed = state.proposed_host_ip
    if adapter is None or proposed is None:
        return False

    prefix = state.proposed_prefix
    ui.blank()
    ui.info(f'Proposed fix: set {proposed}/{prefix} on "{adapter.name}" ({adapter.description})')
    ui.detail("Administrator rights are required; Windows will show a UAC prompt.")
    if not ui.confirm("Apply this USB network setting now?", True, args.yes):
        return False

    try:
        saved_path = network.save_network_state(adapter)
        ui.debug(f"saved previous network state to {saved_path}")
    except network.NetworkError as error:
        ui.warn(f"Could not save the previous settings: {error}")

    ui.wait_status("Applying the USB network setting ...")
    try:
        ok, message = network.apply_static_ip(adapter, proposed, prefix)
    except network.NetworkError as error:
        ok, message = False, str(error)
    ui.end_wait()

    if not ok:
        ui.error(f"Could not apply the setting: {message}")
        ui.info("You can apply it manually from an elevated Command Prompt:")
        ui.detail(network.manual_static_ip_command(adapter, proposed, prefix))
        return False

    ui.ok(message or f"Set {proposed}/{prefix}")
    return True


def wait_for_network(ui: UI, seconds: float = 12.0) -> network.NetworkState | None:
    ui.wait_status("Waiting for the new address to become active ...")
    deadline = time.monotonic() + seconds
    last: network.NetworkState | None = None
    while time.monotonic() < deadline:
        time.sleep(0.6)
        try:
            last = network.analyze()
        except network.NetworkError:
            continue
        if last.configured:
            break
    ui.end_wait()
    return last


def check_reachability(ui: UI, args: argparse.Namespace, state: network.NetworkState) -> None:
    if not network.is_windows():
        return

    ifindex = state.adapter.ifindex if state.adapter is not None else None

    while True:
        ui.wait_status(f"Checking whether {network.VRX_IP} is reachable ...")
        reach = network.check_reachability(network.VRX_IP, ifindex)
        ui.end_wait()
        ui.item("VRX reachable", reach.detail, "ok" if reach.present else "bad")
        if reach.present:
            return

        ui.warn(f"{network.VRX_IP} did not answer from this PC.")
        ui.bullet("The VRX may still be booting - wait a few seconds and retry.")
        ui.bullet("The reverse shell is an outbound connection, so it can still work.")
        ui.bullet("If it never connects, check the USB cable, VRX power and host firewall.")

        if args.yes:
            return

        choice = ui.choose(
            "What do you want to do?",
            ["Check again", "Continue anyway", "Quit"],
            default=0,
        )
        if choice == 0:
            time.sleep(1.0)
            continue
        if choice == 1:
            return
        raise UserQuit


def ensure_network(
    ui: UI,
    args: argparse.Namespace,
    state: network.NetworkState,
) -> tuple[ipaddress.IPv4Address, bool]:
    """Return the host IP to embed in the payload and whether we changed settings."""
    changed = False

    if args.host_ip:
        host = parse_ipv4(args.host_ip)
        display_network(ui, state)
        ui.ok(f"Using host IP {host} (from --host-ip)")
        check_reachability(ui, args, state)
        return host, False

    if state.problem in ("not-windows", "ps-error"):
        display_network(ui, state)
        ui.warn(state.problem_detail)
        host = ask_manual_host_ip(ui, args)
        return host, False

    attempted_fix = False
    while True:
        display_network(ui, state)

        if state.configured and state.host_ip is not None:
            ui.ok(f"Host is on the VRX USB subnet ({network.USB_SUBNET}).")
            if state.adapter is not None and not state.adapter.is_rndis:
                ui.warn(f'"{state.adapter.name}" does not look like the VRX USB network adapter.')
                ui.detail("The VRX is normally reachable only through its RNDIS interface.")
            break

        ui.warn(state.problem_detail)
        if (
            not attempted_fix
            and state.adapter is not None
            and state.proposed_host_ip is not None
            and state.problem in ("not-in-subnet", "ip-conflict")
        ):
            attempted_fix = True
            if apply_proposed_fix(ui, args, state):
                changed = True
                new_state = wait_for_network(ui)
                if new_state is not None:
                    state = new_state
                    continue
            ui.blank()

        options = ["Rescan the USB network", "Enter this PC's IP manually", "Quit"]
        if args.yes:
            raise ToolkitError(
                state.problem_detail
                or "the USB network is not configured; rerun without --yes to fix it"
            )
        choice = ui.choose("What do you want to do?", options, default=0)
        if choice == 0:
            time.sleep(1.0)
            try:
                state = network.analyze()
            except network.NetworkError as error:
                ui.error(str(error))
                raise UserQuit
            continue
        if choice == 1:
            host = ask_manual_host_ip(ui, args)
            check_reachability(ui, args, state)
            return host, changed
        raise UserQuit

    check_reachability(ui, args, state)
    assert state.host_ip is not None
    return state.host_ip, changed


# ============================================================
# Step 3 - firewall / reverse-shell port
# ============================================================


def prepare_shell_port(ui: UI, args: argparse.Namespace) -> int:
    try:
        port = network.pick_shell_port(args.shell_port)
    except network.NetworkError as error:
        raise ToolkitError(str(error)) from error

    if port != args.shell_port:
        ui.warn(
            f"TCP port {args.shell_port} is already in use; "
            f"the reverse shell will use {port} instead."
        )
    else:
        ui.ok(f"Local TCP port {port} is free.")

    if not network.is_windows():
        return port

    profiles = network.firewall_enabled_profiles()
    if "unknown" in profiles:
        ui.warn("Could not read the Windows Firewall state; continuing.")
        return port
    if not profiles:
        ui.ok("Windows Firewall is disabled; no inbound rule is needed.")
        return port

    if network.firewall_rule_exists(port):
        ui.ok(f'Windows Firewall allows inbound TCP {port} ("{network.firewall_rule_name(port)}").')
        return port

    ui.warn(f"Windows Firewall has no inbound rule for TCP {port}.")
    ui.detail("Without it, the VRX cannot connect back to this PC.")
    if ui.confirm(
        "Create the inbound firewall rule? (administrator required)",
        True,
        args.yes,
    ):
        ui.wait_status("Creating the firewall rule ...")
        try:
            ok, message = network.ensure_firewall_rule(port)
        except network.NetworkError as error:
            ok, message = False, str(error)
        ui.end_wait()
        if ok:
            ui.ok(message)
        else:
            ui.warn(f"Could not create the firewall rule: {message}")
            ui.detail("The shell may still work if another firewall/AV allows it.")
    else:
        ui.warn("Continuing without a firewall rule; the connection may be blocked.")

    return port


# ============================================================
# Step 4 - inject, wait, shell
# ============================================================


def inject_payload(ui: UI, port: str, command: str) -> None:
    writes = protocol.injection_write_count(command)
    ui.section("Injecting the root payload")
    ui.detail(
        "The payload is split into short file names; the firmware's md5sum call "
        "executes each fragment."
    )

    def on_step(number: int, total: int, step: protocol.InjectionStep) -> None:
        if step.is_launcher:
            label = "execute reverse shell"
        elif step.label == "/":
            label = "write '/'"
        else:
            label = f'write "{step.label}"'
        ui.progress(number, total, label)

    try:
        protocol.inject_command_reconnecting(
            port,
            command,
            on_step=on_step,
            log=ui.debug,
        )
    finally:
        ui.end_progress()

    ui.ok(f"Payload injected ({writes} writes).")


def wait_for_connection(
    ui: UI,
    listener: ReverseShellServer,
    host: ipaddress.IPv4Address,
    shell_port: int,
    timeout: float,
) -> socket.socket | None:
    ui.section("Waiting for the root shell")
    last_update = [0.0]

    def on_wait(elapsed: float) -> None:
        now = time.monotonic()
        if now - last_update[0] < 0.25:
            return
        last_update[0] = now
        ui.wait_status(
            f"{network.VRX_IP} -> {host}:{shell_port}   ({elapsed:.0f}s / {timeout:.0f}s)"
        )

    connection = listener.accept(timeout=timeout, on_wait=on_wait)
    ui.end_wait()
    return connection


def handle_no_connection(
    ui: UI,
    args: argparse.Namespace,
    listener: ReverseShellServer,
    port: str,
    command: str,
    host: ipaddress.IPv4Address,
    shell_port: int,
) -> socket.socket | None:
    while True:
        ui.error("The VRX did not connect back.")
        ui.bullet("The payload may not have run yet, or Windows blocked the connection.")
        ui.bullet(f"Expected connection: {network.VRX_IP} -> {host}:{shell_port}")
        ui.bullet("Close any other app that might be using the VRX's telnet/FIFO.")

        if args.yes:
            return None

        choice = ui.choose(
            "What do you want to do?",
            [
                "Wait 60 more seconds",
                "Re-run the payload launcher",
                "Re-inject the whole payload",
                "Give up",
            ],
            default=0,
        )

        if choice == 0:
            connection = wait_for_connection(ui, listener, host, shell_port, 60.0)
            if connection is not None:
                return connection
            continue

        if choice in (1, 2):
            try:
                if choice == 1:
                    ui.info("Re-running the launcher ...")
                    with protocol.AscentLink(port, log=ui.debug) as link:
                        link.reset_buffers()
                        protocol.run_launcher(link)
                    ui.ok("Launcher re-run.")
                else:
                    inject_payload(ui, port, command)
            except (protocol.ProtocolError, OSError) as error:
                ui.error(f"Retry failed: {error}")
                continue

            connection = wait_for_connection(ui, listener, host, shell_port, args.wait)
            if connection is not None:
                return connection
            continue

        return None


def run_root_shell(
    ui: UI,
    args: argparse.Namespace,
    port: str,
    host: ipaddress.IPv4Address,
    shell_port: int,
) -> bool:
    command = protocol.build_reverse_shell_command(str(host), shell_port)
    listener = ReverseShellServer("0.0.0.0", shell_port)
    try:
        listener.open()
    except OSError as error:
        raise ToolkitError(f"cannot listen on TCP {shell_port}: {error}") from error

    connection: socket.socket | None = None
    try:
        attempts_left = 0 if args.yes else 2
        while True:
            try:
                inject_payload(ui, port, command)
                break
            except (protocol.ProtocolError, OSError) as error:
                ui.error(f"Injection failed: {error}")
                ui.detail(
                    "The firmware was not modified; a transient serial error is safe to retry."
                )
                if args.yes or attempts_left <= 0:
                    return False
                attempts_left -= 1
                if not ui.confirm("Try the injection again?", True, auto=False):
                    return False

        connection = wait_for_connection(ui, listener, host, shell_port, args.wait)
        if connection is None:
            connection = handle_no_connection(ui, args, listener, port, command, host, shell_port)
        if connection is None:
            return False

        peer = listener.last_peer or ("?", 0)
        ui.ok(f"Root shell connected from {peer[0]}:{peer[1]}")
        ui.section("Root shell")
        ui.info("Local commands: :help   :quit   :echo on|off   :raw on|off")
        ui.detail("The remote shell has no tty; full-screen editors are limited.")

        reason = run_shell(connection, peer=f"{peer[0]}:{peer[1]}")
        ui.section("Session ended")
        if reason == "quit":
            ui.ok("Shell closed.")
        else:
            ui.warn("The VRX closed the connection.")
        ui.detail("The injected /tmp/e script stays on the device until it reboots.")
        return True
    finally:
        listener.close()
        if connection is not None:
            try:
                connection.close()
            except OSError:
                pass


def finish_network_settings(ui: UI, args: argparse.Namespace, changed: bool) -> None:
    if not changed:
        return

    saved = network.load_network_state()
    ui.section("USB network settings")
    if saved is None:
        ui.info("The session changed the USB adapter, but no saved state was found.")
        return

    ui.item("Previous state", network.describe_saved_state(saved))
    if args.keep_network:
        ui.info("Keeping the current settings (--keep-network).")
        return

    if ui.confirm("Restore the previous USB network settings?", True, args.yes):
        ui.wait_status("Restoring the previous network settings ...")
        try:
            ok, message = network.restore_network_state(saved)
        except network.NetworkError as error:
            ok, message = False, str(error)
        ui.end_wait()
        if ok:
            ui.ok(message)
        else:
            ui.warn(f"Could not restore the settings: {message}")
            ui.detail(f"Saved state kept at {network.STATE_PATH}")
    else:
        ui.info("Keeping the current settings.")
        ui.detail("Restore them later with: python root_tool.py --restore-network")


def cmd_root(ui: UI, args: argparse.Namespace) -> int:
    changed = False
    try:
        port, info = select_and_probe(ui, args)

        ui.step(2, TOTAL_STEPS, "Check the USB network")
        try:
            state = network.analyze()
        except network.NetworkError as error:
            state = network.NetworkState(
                adapters=[],
                adapter=None,
                host_ip=None,
                problem="ps-error",
                problem_detail=f"network inspection failed: {error}",
            )
        host, changed = ensure_network(ui, args, state)

        ui.step(3, TOTAL_STEPS, "Prepare the reverse shell")
        shell_port = prepare_shell_port(ui, args)

        command = protocol.build_reverse_shell_command(str(host), shell_port)
        writes = protocol.injection_write_count(command)

        ui.step(4, TOTAL_STEPS, "Root the VRX")
        ui.section("Ready to root")
        ui.item("Serial port", port)
        ui.item(
            "Device",
            f"{info.device_name}  {info.firmware_info}".strip() if info else "unverified",
        )
        ui.item("Host IP", str(host))
        ui.item("VRX IP", str(network.VRX_IP))
        ui.item("Reverse shell", f"telnet {host} {shell_port}")
        ui.item("Injection writes", str(writes))
        ui.detail("Temporary files are written under /tmp; the firmware is not modified.")

        if not ui.confirm("Start rooting now?", True, args.yes):
            ui.info("Cancelled.")
            return 0

        success = run_root_shell(ui, args, port, host, shell_port)
        return 0 if success else 1
    finally:
        finish_network_settings(ui, args, changed)


# ============================================================
# --check
# ============================================================


def cmd_check(ui: UI, args: argparse.Namespace) -> int:
    ui.section("Serial ports")
    try:
        ports = protocol.list_serial_ports()
    except protocol.DependencyError as error:
        ui.error(str(error))
        ports = []

    if ports:
        for port in sorted(ports, key=lambda item: (-protocol.port_score(item), item.device)):
            ui.bullet(f"{port.device:<7} {port.summary}{tag_port(port)}")
    else:
        ui.warn("No serial ports found.")

    if args.port:
        info = try_probe(ui, args.port)
        if info is not None:
            show_device_info(ui, args.port, info)

    ui.section("USB network")
    state: network.NetworkState | None = None
    reach: network.Reachability | None = None
    try:
        state = network.analyze()
        if state.configured:
            reach = network.check_reachability(
                network.VRX_IP,
                state.adapter.ifindex if state.adapter else None,
            )
        display_network(ui, state, reach)
    except network.NetworkError as error:
        ui.error(f"Network inspection failed: {error}")

    if state is not None and not state.configured:
        if state.adapter is not None and state.proposed_host_ip is not None:
            ui.blank()
            ui.info(
                f"Suggested fix: set {state.proposed_host_ip}/{state.proposed_prefix} "
                f'on "{state.adapter.name}"'
            )
            ui.detail(network.manual_static_ip_command(state.adapter, state.proposed_host_ip))
        ui.detail("Run the tool without --check to apply fixes automatically.")

    if network.is_windows():
        ui.section("Windows Firewall")
        profiles = network.firewall_enabled_profiles()
        if "unknown" in profiles or not profiles:
            ui.warn("Firewall state could not be read (or the firewall is disabled).")
        else:
            ui.info("Enabled profiles: " + ", ".join(profiles))
            port = args.shell_port
            if network.firewall_rule_exists(port):
                ui.ok(f"Inbound TCP {port} is allowed.")
            else:
                ui.warn(
                    f'No inbound rule for TCP {port} yet ("{network.firewall_rule_name(port)}").'
                )

    ui.section("Summary")
    if state is not None and state.configured:
        ui.ok("USB network configuration looks usable.")
    else:
        ui.warn("USB network configuration needs attention.")
    if reach is not None and reach.present:
        ui.ok(f"VRX is reachable ({reach.detail}).")
    elif reach is not None:
        ui.warn(f"VRX is not reachable ({reach.detail}).")
    ui.detail("Run: python root_tool.py")
    return 0


# ============================================================
# --restore-network
# ============================================================


def cmd_restore_network(ui: UI, args: argparse.Namespace) -> int:
    if not network.is_windows():
        raise ToolkitError("network restore is only available on Windows")

    state = network.load_network_state()
    ui.section("Restore USB network settings")
    if state is None:
        ui.error(f"No saved network state at {network.STATE_PATH}")
        return 1

    ui.item("Adapter", str(state.get("adapter_name", "?")))
    ui.item("Previous state", network.describe_saved_state(state))
    ui.item("Saved at", str(state.get("saved_at", "unknown")))

    if not ui.confirm("Restore these settings now?", True, args.yes):
        ui.info("Cancelled.")
        return 0

    ui.wait_status("Restoring ...")
    try:
        ok, message = network.restore_network_state(state)
    except network.NetworkError as error:
        ok, message = False, str(error)
    ui.end_wait()
    if ok:
        ui.ok(message)
        return 0
    ui.error(f"Could not restore the settings: {message}")
    return 1


# ============================================================
# CLI
# ============================================================


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="root_tool.py",
        description=(
            "Interactive root shell for Caddx / Walksnail Ascent VRX receivers "
            "over USB serial + RNDIS."
        ),
    )
    parser.add_argument("--port", metavar="COMx", help="serial port (skip the port picker)")
    parser.add_argument(
        "--host-ip",
        metavar="IP",
        help="IPv4 address of this PC as seen by the VRX (skip auto-detection)",
    )
    parser.add_argument(
        "--shell-port",
        type=int,
        default=4444,
        metavar="PORT",
        help="local TCP port for the reverse shell (default: 4444)",
    )
    parser.add_argument(
        "--wait",
        type=float,
        default=30.0,
        metavar="SECONDS",
        help="how long to wait for the reverse shell (default: 30)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="diagnose the serial port, USB network and firewall, then exit",
    )
    parser.add_argument(
        "--restore-network",
        action="store_true",
        help="restore USB network settings saved by a previous run",
    )
    parser.add_argument(
        "--keep-network",
        action="store_true",
        help="keep the USB network settings changed during this run",
    )
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="accept recommended defaults and apply fixes without asking",
    )
    parser.add_argument("--verbose", action="store_true", help="show protocol debug output")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not 1 <= args.shell_port <= 65535:
        parser.error("--shell-port must be between 1 and 65535")
    if args.wait <= 0:
        parser.error("--wait must be greater than zero")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    configure_console()
    ui = UI(color=False if args.no_color else None, verbose=args.verbose)
    ui.banner(__version__)

    try:
        if args.restore_network:
            return cmd_restore_network(ui, args)

        ensure_pyserial(ui, args.yes)

        if not network.is_windows():
            ui.warn("Automatic USB network checks are Windows-only in this version.")
            ui.info("You will be asked for the host IP manually.")

        if args.check:
            return cmd_check(ui, args)

        return cmd_root(ui, args)
    except UserQuit:
        ui.blank()
        ui.info("Cancelled.")
        return 130
    except ToolkitError as error:
        ui.blank()
        ui.error(str(error))
        return 1
    except KeyboardInterrupt:
        ui.blank()
        ui.info("Interrupted.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
