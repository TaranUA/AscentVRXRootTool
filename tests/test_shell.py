"""Tests for the telnet filter and console output translation."""

from __future__ import annotations

import io
import unittest

from ascent_root.shell import (
    DO,
    DONT,
    IAC,
    WILL,
    WONT,
    ConsoleWriter,
    ShellSession,
    TelnetFilter,
)


class TelnetFilterTests(unittest.TestCase):
    def test_plain_data_passes_through(self) -> None:
        output, replies = TelnetFilter().feed(b"hello\r\n")
        self.assertEqual(output, b"hello\r\n")
        self.assertEqual(replies, b"")

    def test_negotiation_is_stripped_and_answered(self) -> None:
        output, replies = TelnetFilter().feed(
            b"a" + bytes([IAC, WILL, 1]) + b"b" + bytes([IAC, DO, 3]) + b"c"
        )
        self.assertEqual(output, b"abc")
        self.assertEqual(replies, bytes([IAC, DONT, 1, IAC, WONT, 3]))

    def test_escaped_iac_is_kept(self) -> None:
        output, replies = TelnetFilter().feed(b"x" + bytes([IAC, IAC]) + b"y")
        self.assertEqual(output, b"x" + bytes([IAC]) + b"y")
        self.assertEqual(replies, b"")

    def test_subnegotiation_is_removed(self) -> None:
        payload = b"a" + bytes([IAC, 250, 24, 1, 2]) + bytes([IAC, 240]) + b"b"
        output, replies = TelnetFilter().feed(payload)
        self.assertEqual(output, b"ab")
        self.assertEqual(replies, b"")

    def test_negotiation_split_across_packets(self) -> None:
        telnet = TelnetFilter()
        first, replies = telnet.feed(bytes([IAC, WILL]))
        self.assertEqual(first, b"")
        self.assertEqual(replies, b"")
        second, replies = telnet.feed(bytes([1]) + b"ok")
        self.assertEqual(second, b"ok")
        self.assertEqual(replies, bytes([IAC, DONT, 1]))


class ConsoleWriterTests(unittest.TestCase):
    def test_lf_becomes_crlf(self) -> None:
        stream = io.StringIO()
        writer = ConsoleWriter(stream)
        writer.write("one\ntwo\n")
        self.assertEqual(stream.getvalue(), "one\r\ntwo\r\n")

    def test_existing_crlf_is_not_doubled(self) -> None:
        stream = io.StringIO()
        writer = ConsoleWriter(stream)
        writer.write("one\r\ntwo\r\n")
        self.assertEqual(stream.getvalue(), "one\r\ntwo\r\n")

    def test_crlf_split_across_writes(self) -> None:
        stream = io.StringIO()
        writer = ConsoleWriter(stream)
        writer.write("progress\r")
        writer.write("\ndone\n")
        self.assertEqual(stream.getvalue(), "progress\r\ndone\r\n")

    def test_bare_cr_is_preserved(self) -> None:
        stream = io.StringIO()
        writer = ConsoleWriter(stream)
        writer.write("10%\r20%")
        self.assertEqual(stream.getvalue(), "10%\r20%")


class FakeSocket:
    def __init__(self) -> None:
        self.sent = bytearray()

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)


class ShellSessionTests(unittest.TestCase):
    def make_session(self, **kwargs):
        stream = io.StringIO()
        session = ShellSession(
            conn=FakeSocket(),
            writer=ConsoleWriter(stream),
            auto_read=False,
            **kwargs,
        )
        return session, stream

    def type_text(self, session, text: str) -> None:
        for char in text:
            session.feed_key(char)

    def test_line_mode_sends_whole_line(self) -> None:
        session, stream = self.make_session()
        self.type_text(session, "ls -la\r")
        self.assertEqual(bytes(session.conn.sent), b"ls -la\n")
        self.assertIn("ls -la", stream.getvalue())

    def test_backspace_edits_before_sending(self) -> None:
        session, _stream = self.make_session()
        self.type_text(session, "lsx\x08\r")
        self.assertEqual(bytes(session.conn.sent), b"ls\n")

    def test_meta_echo_off_stops_local_echo(self) -> None:
        session, stream = self.make_session()
        self.type_text(session, ":echo off\r")
        before = len(stream.getvalue())
        self.type_text(session, "abc\r")
        self.assertEqual(bytes(session.conn.sent), b"abc\n")
        self.assertEqual(stream.getvalue()[before:], "\r\n")
        self.assertFalse(session.echo)

    def test_meta_quit(self) -> None:
        session, _stream = self.make_session()
        self.type_text(session, ":quit\r")
        self.assertEqual(bytes(session.conn.sent), b"exit\n")
        self.assertTrue(session.quit_requested)

    def test_raw_mode_sends_each_key(self) -> None:
        session, _stream = self.make_session(raw=True)
        self.type_text(session, "ab\r")
        self.assertEqual(bytes(session.conn.sent), b"ab\n")

    def test_drain_translates_output(self) -> None:
        session, stream = self.make_session()
        session._queue.put(b"hello\nworld\r\n")
        session.drain()
        self.assertEqual(stream.getvalue(), "hello\r\nworld\r\n")

    def test_ctrl_c_clears_the_line(self) -> None:
        session, _stream = self.make_session()
        self.type_text(session, "bad\x03")
        self.assertEqual(session.line, "")
        self.type_text(session, "ok\r")
        self.assertEqual(bytes(session.conn.sent), b"ok\n")


if __name__ == "__main__":
    unittest.main()
