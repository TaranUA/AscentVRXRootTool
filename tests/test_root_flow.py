"""Integration test for the root_tool orchestrator with simulated hardware."""

from __future__ import annotations

import argparse
import contextlib
import io
import ipaddress
import unittest
from typing import ClassVar
from unittest import mock

import root_tool
from ascent_root import network, protocol
from ascent_root.ui import UI

ADAPTER = network.Adapter(
    ifindex=12,
    name="Ethernet 5",
    description="USB Ethernet/RNDIS Gadget",
    status="Up",
    mac="02-00-00-00-00-01",
    ips=[
        network.IPConfig(
            address=ipaddress.IPv4Address("192.168.3.103"),
            prefix=24,
            origin="Manual",
        )
    ],
)

PORT = protocol.PortInfo(
    device="COM5",
    description="USB Serial Device (COM5)",
    hwid="USB VID:PID=1D77:A4A2",
    vid=0x1D77,
    pid=0xA4A2,
)

DEVICE_INFO = protocol.DeviceInfo(
    receive_max_size=1024 * 1024,
    sdk_version="1.2.3",
    device_name="Ascent_VRX_Max",
    cpu_temp=42,
    firmware_info="16.5.7",
    serial_number="SN123456",
    hardware_version="HW-1",
    status=0,
    detail="OK",
)


class FakeLink:
    instances: ClassVar[list[FakeLink]] = []

    def __init__(self, port: str, baudrate: int = protocol.DEFAULT_BAUDRATE, log=None) -> None:
        self.port = port
        self.opened = False
        FakeLink.instances.append(self)

    def open(self) -> None:
        self.opened = True

    def close(self) -> None:
        self.opened = False

    def reset_buffers(self) -> None:
        pass

    def get_device_info(self, timeout: float = 3.0, retries: int = 2) -> protocol.DeviceInfo:
        return DEVICE_INFO

    def __enter__(self) -> FakeLink:  # noqa: PYI034 - Self requires Python 3.11
        self.open()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class FakeConnection:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class FakeListener:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.last_peer: tuple[str, int] | None = ("192.168.3.102", 50000)
        self.connection = FakeConnection()

    def open(self) -> int:
        return self.port

    def accept(self, timeout: float = 30.0, on_wait=None):
        return self.connection

    def close(self) -> None:
        pass


def make_args(**overrides) -> argparse.Namespace:
    defaults = {
        "port": "COM5",
        "host_ip": "192.168.3.103",
        "shell_port": 4444,
        "wait": 1.0,
        "check": False,
        "restore_network": False,
        "keep_network": True,
        "yes": True,
        "verbose": False,
        "no_color": True,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class RootFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        FakeLink.instances = []

    def test_full_flow_with_simulated_hardware(self) -> None:
        state = network.NetworkState(
            adapters=[ADAPTER],
            adapter=ADAPTER,
            host_ip=ipaddress.IPv4Address("192.168.3.103"),
            problem=None,
        )
        injected: list[str] = []

        with (
            mock.patch.object(protocol, "list_serial_ports", return_value=[PORT]),
            mock.patch.object(protocol, "AscentLink", FakeLink),
            mock.patch.object(network, "analyze", return_value=state),
            mock.patch.object(
                network,
                "check_reachability",
                return_value=network.Reachability(True, "ICMP", "ping reply in 1 ms"),
            ),
            mock.patch.object(network, "pick_shell_port", return_value=4444),
            mock.patch.object(network, "firewall_enabled_profiles", return_value=[]),
            mock.patch.object(
                root_tool,
                "inject_payload",
                side_effect=lambda _ui, _port, cmd: injected.append(cmd),
            ),
            mock.patch.object(root_tool, "ReverseShellServer", FakeListener),
            mock.patch.object(root_tool, "run_shell", return_value="quit"),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            code = root_tool.cmd_root(UI(color=False), make_args())

        self.assertEqual(code, 0)
        self.assertEqual(len(injected), 1)
        self.assertIn("telnet 192.168.3.103 4444", injected[0])
        self.assertTrue(FakeLink.instances)
        self.assertEqual(FakeLink.instances[0].port, "COM5")

    def test_handshake_failure_is_fatal_with_yes(self) -> None:
        class BadLink(FakeLink):
            def get_device_info(self, timeout: float = 3.0, retries: int = 2):
                raise protocol.SerialTimeout("no answer")

        with (
            mock.patch.object(protocol, "list_serial_ports", return_value=[PORT]),
            mock.patch.object(protocol, "AscentLink", BadLink),
            self.assertRaises(root_tool.ToolkitError),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            root_tool.cmd_root(UI(color=False), make_args())

    def test_missing_adapter_is_fatal_with_yes(self) -> None:
        state = network.NetworkState(
            adapters=[],
            adapter=None,
            host_ip=None,
            problem="no-adapter",
            problem_detail="no USB Ethernet / RNDIS adapter was found",
            proposed_host_ip=ipaddress.IPv4Address("192.168.3.103"),
        )
        with (
            mock.patch.object(protocol, "list_serial_ports", return_value=[PORT]),
            mock.patch.object(protocol, "AscentLink", FakeLink),
            mock.patch.object(network, "analyze", return_value=state),
            self.assertRaises(root_tool.ToolkitError),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            root_tool.cmd_root(UI(color=False), make_args(host_ip=None))

    def test_injection_command_fits_and_is_valid(self) -> None:
        command = protocol.build_reverse_shell_command("192.168.3.103", 4444)
        steps = protocol.build_injection_steps(command)
        self.assertTrue(steps[-1].is_launcher)
        self.assertTrue(all(len(step.path) <= protocol.MAX_INJECT_PATH for step in steps))


if __name__ == "__main__":
    unittest.main()
