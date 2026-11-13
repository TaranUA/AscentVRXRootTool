"""Tests for network adapter discovery and USB-subnet decisions."""

from __future__ import annotations

import ipaddress
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ascent_root import network


def make_adapter(
    ifindex: int,
    name: str,
    description: str,
    status: str = "Up",
    cidrs: tuple[str, ...] = (),
) -> network.Adapter:
    ips = []
    for cidr in cidrs:
        interface = ipaddress.IPv4Interface(cidr)
        ips.append(
            network.IPConfig(
                address=interface.ip,
                prefix=interface.network.prefixlen,
                origin="Manual",
            )
        )
    return network.Adapter(
        ifindex=ifindex,
        name=name,
        description=description,
        status=status,
        ips=ips,
    )


class AdapterParsingTests(unittest.TestCase):
    def test_single_object_and_single_ip(self) -> None:
        raw = {
            "ifIndex": 12,
            "name": "Ethernet 5",
            "description": "USB Ethernet/RNDIS Gadget",
            "status": "Up",
            "mac": "02-00-00-00-00-01",
            "linkSpeed": "426 Mbps",
            "ips": {
                "IPAddress": "192.168.3.103",
                "PrefixLength": 24,
                "PrefixOrigin": "Manual",
            },
        }
        adapters = network.parse_adapters_json(raw)
        self.assertEqual(len(adapters), 1)
        self.assertTrue(adapters[0].is_rndis)
        self.assertTrue(adapters[0].is_up)
        self.assertEqual(adapters[0].ips[0].cidr, "192.168.3.103/24")

    def test_invalid_ip_is_skipped(self) -> None:
        raw = [
            {
                "ifIndex": 3,
                "name": "Ethernet",
                "description": "Realtek",
                "status": "Up",
                "ips": [
                    {"IPAddress": "not-an-ip", "PrefixLength": 24},
                    {"IPAddress": "10.0.0.5", "PrefixLength": 8},
                ],
            }
        ]
        adapters = network.parse_adapters_json(raw)
        self.assertEqual(len(adapters[0].ips), 1)
        self.assertEqual(adapters[0].ips[0].cidr, "10.0.0.5/8")


class SelectionTests(unittest.TestCase):
    def test_prefers_rndis_adapter_in_subnet(self) -> None:
        wifi = make_adapter(5, "Wi-Fi", "Intel Wi-Fi", cidrs=("192.168.3.50/24",))
        usb = make_adapter(
            12,
            "Ethernet 5",
            "USB Ethernet/RNDIS Gadget",
            cidrs=("192.168.3.103/24",),
        )
        self.assertIs(network.select_adapter([wifi, usb]), usb)

    def test_down_rndis_adapter_is_still_returned_for_diagnostics(self) -> None:
        down = make_adapter(
            12,
            "Ethernet 5",
            "USB Ethernet/RNDIS Gadget",
            status="Disconnected",
            cidrs=("192.168.3.103/24",),
        )
        self.assertIs(network.select_adapter([down]), down)  # still useful for diagnostics

    def test_rndis_wins_over_unrelated_subnet_adapter(self) -> None:
        wifi = make_adapter(5, "Wi-Fi", "Intel Wi-Fi", cidrs=("192.168.3.50/24",))
        usb = make_adapter(
            12,
            "Ethernet 5",
            "USB Ethernet/RNDIS Gadget",
            cidrs=("169.254.10.20/16",),
        )
        self.assertIs(network.select_adapter([wifi, usb]), usb)

    def test_non_rndis_subnet_adapter_is_used_as_fallback(self) -> None:
        wifi = make_adapter(5, "Wi-Fi", "Intel Wi-Fi", cidrs=("192.168.3.50/24",))
        self.assertIs(network.select_adapter([wifi]), wifi)

    def test_no_adapter(self) -> None:
        self.assertIsNone(network.select_adapter([]))


class AnalyzeTests(unittest.TestCase):
    def test_configured(self) -> None:
        adapter = make_adapter(
            12,
            "Ethernet 5",
            "USB Ethernet/RNDIS Gadget",
            cidrs=("192.168.3.103/24",),
        )
        state = network.analyze([adapter])
        self.assertTrue(state.configured)
        self.assertEqual(state.host_ip, ipaddress.IPv4Address("192.168.3.103"))
        self.assertIsNone(state.problem)

    def test_prefix_wider_than_24_is_accepted(self) -> None:
        adapter = make_adapter(
            12,
            "Ethernet 5",
            "USB Ethernet/RNDIS Gadget",
            cidrs=("192.168.3.103/16",),
        )
        state = network.analyze([adapter])
        self.assertTrue(state.configured)

    def test_wrong_subnet_proposes_a_fix(self) -> None:
        adapter = make_adapter(
            12,
            "Ethernet 5",
            "USB Ethernet/RNDIS Gadget",
            cidrs=("169.254.10.20/16",),
        )
        state = network.analyze([adapter])
        self.assertFalse(state.configured)
        self.assertEqual(state.problem, "not-in-subnet")
        self.assertEqual(state.proposed_host_ip, network.PREFERRED_HOST_IP)

    def test_address_conflict_proposes_a_different_address(self) -> None:
        adapter = make_adapter(
            12,
            "Ethernet 5",
            "USB Ethernet/RNDIS Gadget",
            cidrs=("192.168.3.102/24",),
        )
        state = network.analyze([adapter])
        self.assertFalse(state.configured)
        self.assertEqual(state.problem, "ip-conflict")
        self.assertNotEqual(state.proposed_host_ip, network.VRX_IP)

    def test_chooses_free_address_when_preferred_is_used(self) -> None:
        occupied = make_adapter(5, "Wi-Fi", "Intel Wi-Fi", cidrs=("192.168.3.103/24",))
        chosen = network.choose_available_host_ip([occupied])
        self.assertNotEqual(chosen, ipaddress.IPv4Address("192.168.3.103"))
        self.assertNotEqual(chosen, network.VRX_IP)
        self.assertIn(chosen, network.USB_SUBNET)

    def test_describe_state_marks_bad_network(self) -> None:
        adapter = make_adapter(
            12,
            "Ethernet 5",
            "USB Ethernet/RNDIS Gadget",
            cidrs=("169.254.10.20/16",),
        )
        rows = network.describe_state(network.analyze([adapter]))
        labels = {label: status for label, _value, status in rows}
        self.assertEqual(labels["USB network"], "bad")
        self.assertEqual(labels["Host address"], "bad")


class InterfaceMathTests(unittest.TestCase):
    def test_netmask(self) -> None:
        self.assertEqual(network.netmask_for(24), "255.255.255.0")
        self.assertEqual(network.netmask_for(16), "255.255.0.0")

    def test_pick_shell_port_handles_upper_boundary(self) -> None:
        # 65535 is the last valid port; the range must include it.
        original = network.port_is_free
        try:
            checked: list[int] = []

            def fake_free(port: int, host: str = "0.0.0.0") -> bool:
                checked.append(port)
                return port == 65535

            network.port_is_free = fake_free  # type: ignore[assignment]
            self.assertEqual(network.pick_shell_port(65535, attempts=25), 65535)
            self.assertEqual(checked, [65535])
        finally:
            network.port_is_free = original  # type: ignore[assignment]

    def test_manual_command_quotes_adapter_name(self) -> None:
        adapter = make_adapter(12, "Ethernet 5", "USB Ethernet/RNDIS Gadget", cidrs=())
        command = network.manual_static_ip_command(adapter, ipaddress.IPv4Address("192.168.3.103"))
        self.assertIn('name="Ethernet 5"', command)
        self.assertIn("static 192.168.3.103 255.255.255.0", command)


class AdminLogTests(unittest.TestCase):
    def make_temp_dir(self) -> Path:
        path = Path(tempfile.mkdtemp(prefix="ascent_root_test_"))
        self.addCleanup(shutil.rmtree, path, ignore_errors=True)
        return path

    def test_missing_or_empty_log_reads_as_empty(self) -> None:
        temp_dir = self.make_temp_dir()
        self.assertEqual(network._read_admin_log(temp_dir / "missing.txt"), "")

        empty = temp_dir / "empty.txt"
        empty.touch()
        self.assertEqual(network._read_admin_log(empty), "")

    def test_transient_permission_error_is_retried(self) -> None:
        log_path = self.make_temp_dir() / "result.txt"
        log_path.write_text("OK: applied\n", encoding="utf-8")
        original = Path.read_text
        calls = 0

        def flaky(self, *args, **kwargs):
            nonlocal calls
            calls += 1
            if calls < 3:
                raise PermissionError(13, "Permission denied", str(self))
            return original(self, *args, **kwargs)

        with (
            mock.patch.object(Path, "read_text", flaky),
            mock.patch.object(network.time, "sleep"),
        ):
            text = network._read_admin_log(log_path)

        self.assertEqual(text, "OK: applied")
        self.assertEqual(calls, 3)

    def test_permanently_unreadable_log_returns_none(self) -> None:
        def denied(*_args, **_kwargs):
            raise PermissionError(13, "Permission denied")

        with (
            mock.patch.object(Path, "read_text", denied),
            mock.patch.object(network.time, "sleep") as sleep,
        ):
            text = network._read_admin_log(Path("result.txt"), attempts=3)

        self.assertIsNone(text)
        self.assertEqual(sleep.call_count, 2)

    def test_run_admin_uses_ps_output_when_log_is_empty(self) -> None:
        temp_dir = self.make_temp_dir()
        with (
            mock.patch.object(network, "is_windows", return_value=True),
            mock.patch.object(network, "is_admin", return_value=False),
            mock.patch.object(network.tempfile, "mkdtemp", return_value=str(temp_dir)),
            mock.patch.object(
                network,
                "_run_ps",
                return_value=network.PsResult(0, "", "OK: from PowerShell"),
            ),
        ):
            ok, message = network._run_admin("Write-Output 'hi'")

        self.assertTrue(ok)
        self.assertEqual(message, "OK: from PowerShell")
        self.assertFalse(temp_dir.exists())

    def test_run_admin_reports_unreadable_output_without_crashing(self) -> None:
        temp_dir = self.make_temp_dir()
        with (
            mock.patch.object(network, "is_windows", return_value=True),
            mock.patch.object(network, "is_admin", return_value=False),
            mock.patch.object(network.tempfile, "mkdtemp", return_value=str(temp_dir)),
            mock.patch.object(network, "_run_ps", return_value=network.PsResult(0, "", "")),
            mock.patch.object(
                Path,
                "read_text",
                side_effect=PermissionError(13, "Permission denied"),
            ),
            mock.patch.object(network.time, "sleep"),
        ):
            ok, message = network._run_admin("Write-Output 'hi'")

        self.assertTrue(ok)
        self.assertIn("could not be read", message)
        self.assertFalse(temp_dir.exists())


if __name__ == "__main__":
    unittest.main()
