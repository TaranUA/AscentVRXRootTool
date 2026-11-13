"""End-to-end simulation of injection and reverse-shell connection.

A fake VRX implements just enough of the upgrade protocol to execute the
injected file names and connect back to the listener. No hardware is needed.
"""

from __future__ import annotations

import re
import socket
import struct
import threading
import time
import unittest

from ascent_root import protocol
from ascent_root.shell import ReverseShellServer

DATA_RE = re.compile(
    r"^/tmp/;echo -n '(?P<chunk>.*?)'(?P<redirect>>>|>)\$\(pwd\|cut -c1\)"
    r"tmp\$\(pwd\|cut -c1\)e$"
)


def _response_payload(ok: bool = True) -> bytes:
    return struct.pack("<i", 0 if ok else -1) + b"OK\x00"


def _file_payload(written: int) -> bytes:
    return struct.pack("<IIII", written, written, written, 0) + b"OK\x00"


class FakeVrx:
    """Serial endpoint that emulates the VRX upgrade service."""

    is_open = True

    def __init__(self, connect_target: tuple[str, int]) -> None:
        self.connect_target = connect_target
        self.incoming = bytearray()
        self.buffer = bytearray()
        self.files: dict[str, bytes] = {}
        self.current_path: str | None = None
        self.script = ""
        self.launched = False
        self.commands: list[int] = []
        self.lock = threading.Lock()

    # -- pyserial surface -------------------------------------------------

    def read(self, size: int) -> bytes:
        with self.lock:
            chunk = bytes(self.incoming[:size])
            del self.incoming[:size]
            return chunk

    def write(self, data: bytes) -> int:
        with self.lock:
            self.buffer.extend(data)
            while len(self.buffer) >= protocol.HEADER_SIZE:
                header = bytes(self.buffer[: protocol.HEADER_SIZE])
                info = protocol.parse_header(header)
                total = protocol.HEADER_SIZE + info["payload_len"]
                if len(self.buffer) < total:
                    break
                payload = bytes(self.buffer[protocol.HEADER_SIZE : total])
                del self.buffer[:total]
                self.commands.append(info["cmd"])
                self._handle(info, payload)
        return len(data)

    def flush(self) -> None:
        pass

    def reset_input_buffer(self) -> None:
        with self.lock:
            self.incoming.clear()

    def reset_output_buffer(self) -> None:
        pass

    # -- protocol ---------------------------------------------------------

    def _respond(self, command: int, sequence: int, payload: bytes) -> None:
        self.incoming.extend(protocol.build_packet(command, sequence, payload))

    def _handle(self, info: dict, payload: bytes) -> None:
        command = info["cmd"]
        sequence = info["seq"]

        if command in (protocol.CMD_RESET_SESSION, protocol.CMD_FILE_INFO):
            if command == protocol.CMD_FILE_INFO:
                path = payload[72:200].split(b"\x00", 1)[0].decode("utf-8", "replace")
                self.current_path = path
            self._respond(command, sequence, _response_payload())

        elif command == protocol.CMD_FILE_DATA:
            assert self.current_path is not None
            self.files[self.current_path] = payload
            self._respond(command, sequence, _file_payload(len(payload)))

        elif command == protocol.CMD_FILE_DONE:
            assert self.current_path is not None
            if self.current_path == protocol.LAUNCHER_PATH:
                self._launch()
                # The real device blocks in the shell and never answers 0x75.
            else:
                self._execute(self.current_path)
                self._respond(command, sequence, _file_payload(4))

    def _execute(self, path: str) -> None:
        if path == protocol.LAUNCHER_PATH:
            self._launch()
            return
        match = DATA_RE.match(path)
        if match:
            if match.group("redirect") == ">":
                self.script = ""
            self.script += match.group("chunk")
        elif path.startswith("/tmp/;P="):
            self.script += "/"

    def _launch(self) -> None:
        if self.launched:
            return
        self.launched = True

        def worker() -> None:
            try:
                with socket.create_connection(self.connect_target, timeout=2.0) as sock:
                    sock.sendall(b"fake-vrx-root-shell\n")
                    time.sleep(0.2)
            except OSError:
                pass

        threading.Thread(target=worker, daemon=True).start()


class SimulationTests(unittest.TestCase):
    def test_injection_rebuilds_script_and_connects_back(self) -> None:
        listener = ReverseShellServer("127.0.0.1", 0)
        port = listener.open()
        host = "127.0.0.1"

        fake = FakeVrx((host, port))
        link = protocol.AscentLink("FAKE")
        link._ser = fake
        command = protocol.build_reverse_shell_command(host, port)

        try:
            steps = protocol.inject_command(link, command, step_delay=0.0, exec_timeout=0.2)

            connection = listener.accept(timeout=2.0)
            self.assertIsNotNone(connection)
            assert connection is not None
            connection.settimeout(2.0)
            banner = connection.recv(1024)
            connection.close()

            self.assertEqual(fake.script, command)
            self.assertTrue(fake.launched)
            self.assertEqual(banner, b"fake-vrx-root-shell\n")
            self.assertEqual(len(steps), protocol.injection_write_count(command))
            self.assertGreater(len(fake.files), 0)
            self.assertLessEqual(len(fake.files), len(steps))
            self.assertTrue(
                all(content == protocol.DEFAULT_FILE_CONTENT for content in fake.files.values())
            )

            # 0x72 arg=0/1 precede 0x73/0x74/0x75 for every step.
            self.assertEqual(fake.commands.count(protocol.CMD_RESET_SESSION), len(steps) * 2)
            self.assertEqual(fake.commands.count(protocol.CMD_FILE_INFO), len(steps))
            self.assertEqual(fake.commands.count(protocol.CMD_FILE_DATA), len(steps))
            self.assertEqual(fake.commands.count(protocol.CMD_FILE_DONE), len(steps))
        finally:
            listener.close()
            link.close()


if __name__ == "__main__":
    unittest.main()
