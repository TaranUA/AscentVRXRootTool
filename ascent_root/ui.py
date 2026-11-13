"""Console UI helpers used by the root tool."""

from __future__ import annotations

import os
import sys
from collections.abc import Sequence

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
GREY = "\033[90m"


def configure_console() -> None:
    """Enable UTF-8 and ANSI escape handling on Windows consoles."""
    if os.name == "nt":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleOutputCP(65001)
            kernel32.SetConsoleCP(65001)
            handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # VT processing
        except Exception:  # noqa: BLE001, S110 - console setup is best-effort
            pass

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001, S110 - console setup is best-effort
            pass


class UI:
    """Small, dependency-free console UI."""

    def __init__(self, color: bool | None = None, verbose: bool = False) -> None:
        self.verbose = verbose
        self._tty = bool(getattr(sys.stdout, "isatty", lambda: False)())
        if color is None:
            color = self._tty and os.environ.get("NO_COLOR") is None
        self.color = bool(color)
        self._progress_active = False

    # ------------------------------------------------------------------ style

    def _paint(self, text: str, style: str) -> str:
        if not self.color:
            return text
        return f"{style}{text}{RESET}"

    def bold(self, text: str) -> str:
        return self._paint(text, BOLD)

    def dim(self, text: str) -> str:
        return self._paint(text, DIM)

    # ----------------------------------------------------------------- output

    def banner(self, version: str) -> None:
        title = f" Ascent VRX Root Tool  v{version} "
        line = "─" * len(title)
        print()
        print(self._paint(f"╭{line}╮", CYAN))
        print(self._paint("│", CYAN) + self._paint(title, BOLD + CYAN) + self._paint("│", CYAN))
        print(self._paint(f"╰{line}╯", CYAN))
        print(self.dim(" Root shell over USB serial + RNDIS for Caddx / Walksnail Ascent VRX"))
        print(self.dim(" For personal, authorized device recovery and research only."))

    def section(self, title: str) -> None:
        self.end_progress()
        pad = max(0, 58 - len(title))
        print()
        print(self._paint(f"── {title} ", CYAN) + self._paint("─" * pad, GREY))

    def step(self, number: int, total: int, title: str) -> None:
        tag = self._paint(f"[{number}/{total}]", CYAN)
        print()
        print(f"{tag} {self.bold(title)}")

    def info(self, message: str) -> None:
        print(f"  {message}")

    def detail(self, message: str) -> None:
        print(f"    {self.dim(message)}")

    def ok(self, message: str) -> None:
        print(f"  {self._paint('✓', GREEN)} {message}")

    def warn(self, message: str) -> None:
        print(f"  {self._paint('!', YELLOW)} {message}")

    def error(self, message: str) -> None:
        print(f"  {self._paint('✗', RED)} {message}")

    def item(self, label: str, value: str, status: str | None = None) -> None:
        """Print an aligned key/value row.

        ``status`` is ``"ok"``, ``"warn"``, ``"bad"`` or ``None``.
        """
        marker = ""
        if status == "ok":
            marker = f"  {self._paint('✓', GREEN)}"
        elif status == "warn":
            marker = f"  {self._paint('!', YELLOW)}"
        elif status == "bad":
            marker = f"  {self._paint('✗', RED)}"
        print(f"  {label:<16} {value}{marker}")

    def bullet(self, message: str) -> None:
        print(f"  {self._paint('•', GREY)} {message}")

    def debug(self, message: str) -> None:
        if self.verbose:
            print(f"  {self._paint('[debug] ' + message, GREY)}")

    def blank(self) -> None:
        print()

    # ------------------------------------------------------------------ input

    def confirm(self, prompt: str, default: bool = True, auto: bool = False) -> bool:
        suffix = " [Y/n] " if default else " [y/N] "
        if auto:
            print(f"  {prompt}{suffix}{'yes' if default else 'no'} (auto)")
            return default
        while True:
            try:
                answer = input(f"  {prompt}{suffix}").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                return default
            if not answer:
                return default
            if answer in ("y", "yes"):
                return True
            if answer in ("n", "no"):
                return False
            self.warn("Please answer yes or no.")

    def ask(self, prompt: str, default: str = "", auto: bool = False) -> str:
        if auto:
            print(f"  {prompt} {default} (auto)")
            return default
        try:
            answer = input(f"  {prompt} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return default
        return answer or default

    def choose(
        self,
        prompt: str,
        options: Sequence[str],
        default: int = 0,
        auto: bool = False,
        allow_quit: bool = False,
    ) -> int:
        """Show a numbered menu and return a zero-based index."""
        for index, option in enumerate(options, start=1):
            marker = self._paint("(default)", GREEN) if index - 1 == default else ""
            print(f"   {self.bold(str(index))}. {option} {marker}")
        if allow_quit:
            print(f"   {self.bold('q')}. Quit")

        if auto:
            print(f"  {prompt} {default + 1} (auto)")
            return default

        while True:
            try:
                answer = input(f"  {prompt} [{default + 1}]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                return default
            if not answer:
                return default
            if allow_quit and answer in ("q", "quit", "exit"):
                return -1
            if answer.isdigit() and 1 <= int(answer) <= len(options):
                return int(answer) - 1
            self.warn(f"Enter a number between 1 and {len(options)}.")

    # --------------------------------------------------------------- progress

    def progress(self, done: int, total: int, label: str = "") -> None:
        total = max(1, total)
        if not self._tty:
            if done == 1 or done == total or done % 5 == 0:
                print(f"  [{done:>3}/{total}] {label}")
            return

        width = 22
        filled = int(width * done / total)
        bar = "█" * filled + "·" * (width - filled)
        label = (label[:44] + "…") if len(label) > 45 else label
        sys.stdout.write(f"\r  {self._paint('[' + bar + ']', CYAN)} {done:>3}/{total}  {label:<46}")
        sys.stdout.flush()
        self._progress_active = True

    def end_progress(self) -> None:
        if self._progress_active:
            sys.stdout.write("\n")
            sys.stdout.flush()
            self._progress_active = False

    def wait_status(self, message: str) -> None:
        if not self._tty:
            return
        sys.stdout.write(f"\r  {message:<72}")
        sys.stdout.flush()

    def end_wait(self) -> None:
        if self._tty:
            sys.stdout.write("\r" + " " * 76 + "\r")
            sys.stdout.flush()
