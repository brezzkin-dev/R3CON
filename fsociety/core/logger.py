from __future__ import annotations

import sys
import time

_COLORS = {
    "debug": "\033[90m",
    "info": "\033[36m",
    "ok": "\033[32m",
    "warn": "\033[33m",
    "err": "\033[31m",
    "hit": "\033[95m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


class Log:
    def __init__(self, name: str, level: str = "info", color: bool = True, quiet: bool = False):
        self.name = name
        self.level = level
        self.quiet = quiet
        self.color = color and sys.stderr.isatty() and not quiet
        self._order = {"debug": 10, "info": 20, "ok": 20, "warn": 30, "err": 40, "hit": 20}

    def _emit(self, level: str, msg: str) -> None:
        if self._order.get(level, 20) < self._order.get(self.level, 20) or self.quiet:
            return
        stamp = time.strftime("%H:%M:%S")
        tag = level.upper().ljust(5)
        head = f"{_COLORS.get(level, '')}{_BOLD}[{stamp}] {tag}{_RESET}" if self.color else f"[{stamp}] {tag}"
        sys.stderr.write(f"{head} {self.name}: {msg}\n")
        sys.stderr.flush()

    def debug(self, m): self._emit("debug", m)
    def info(self, m): self._emit("info", m)
    def ok(self, m): self._emit("ok", m)
    def warn(self, m): self._emit("warn", m)
    def err(self, m): self._emit("err", m)
    def hit(self, m): self._emit("hit", m)
