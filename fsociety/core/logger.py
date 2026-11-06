from __future__ import annotations

import json
import os
import sys
import threading
import time
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Optional

_COLORS = {
    "debug": "\033[90m",
    "info": "\033[36m",
    "ok": "\033[32m",
    "success": "\033[32m",
    "warn": "\033[33m",
    "err": "\033[31m",
    "fail": "\033[31m",
    "hit": "\033[95m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"

_LEVEL_VALUES = {
    "debug": 10,
    "info": 20,
    "hit": 20,
    "ok": 20,
    "success": 20,
    "warn": 30,
    "err": 40,
    "fail": 40,
}

_GLOBAL_LEVEL = "info"
_MODULE_LEVELS: dict[str, str] = {}
_LEVEL_LOCK = threading.Lock()


def set_global_level(level: str) -> None:
    global _GLOBAL_LEVEL
    with _LEVEL_LOCK:
        _GLOBAL_LEVEL = level


def set_module_level(module: str, level: str) -> None:
    with _LEVEL_LOCK:
        _MODULE_LEVELS[module] = level


def _threshold_for(name: str, fallback: str) -> int:
    with _LEVEL_LOCK:
        active = _MODULE_LEVELS.get(name, _GLOBAL_LEVEL) or fallback
    return _LEVEL_VALUES.get(active, 20)


class _RotatingFile:
    """Size-based rotation. Safe for concurrent writes via internal lock."""

    def __init__(self, path: Path, max_bytes: int = 5 * 1024 * 1024, backups: int = 3):
        self.path = path
        self.max_bytes = max_bytes
        self.backups = backups
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._rotate_if_needed()

    def _rotate_if_needed(self) -> None:
        try:
            if self.path.exists() and self.path.stat().st_size >= self.max_bytes:
                for i in range(self.backups - 1, 0, -1):
                    older = self.path.with_name(f"{self.path.name}.{i}")
                    newer = self.path.with_name(f"{self.path.name}.{i + 1}")
                    if older.exists():
                        os.replace(older, newer)
                os.replace(self.path, self.path.with_name(f"{self.path.name}.1"))
        except OSError:
            pass

    def write(self, line: str) -> None:
        with self._lock:
            try:
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
                self._rotate_if_needed()
            except OSError:
                pass


class _Webhook:
    def __init__(self, url: Optional[str] = None, kind: str = "discord", chat_id: str = ""):
        self.url = url
        self.kind = kind
        self.chat_id = chat_id

    def send(self, level: str, name: str, message: str) -> None:
        if not self.url:
            return
        payload = self._build(level, name, message)
        threading.Thread(target=self._post, args=(payload,), daemon=True).start()

    def _build(self, level: str, name: str, message: str) -> dict:
        if self.kind == "discord":
            return {"content": f"**{level.upper()}** `{name}` — {message}"}
        if self.kind == "telegram":
            return {"chat_id": self.chat_id,
                    "text": f"{level.upper()} [{name}] {message}"}
        return {"level": level, "module": name, "message": message}

    def _post(self, payload: dict) -> None:
        try:
            data = json.dumps(payload).encode()
            req = urllib.request.Request(self.url, data=data,
                                         headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5).close()
        except Exception:
            pass


class Log:
    def __init__(self, name: str, level: str = "info", color: bool = True,
                 file: Optional[str | Path] = None, json_lines: bool = False,
                 max_bytes: int = 5 * 1024 * 1024, backups: int = 3,
                 webhook_url: Optional[str] = None, webhook_kind: str = "discord",
                 webhook_chat_id: str = "", quiet: bool = False):
        self.name = name
        self.level = level
        self.quiet = quiet
        self.color = color and sys.stderr.isatty() and not quiet
        self.json_lines = json_lines
        self._file = _RotatingFile(Path(file), max_bytes, backups) if file else None
        self._webhook = _Webhook(webhook_url, webhook_kind, webhook_chat_id)
        self._emit_lock = threading.Lock()
        self._spinner_thread: Optional[threading.Thread] = None
        self._spinner_stop = threading.Event()

    def _format_human(self, level: str, msg: str) -> str:
        stamp = time.strftime("%H:%M:%S")
        tag = level.upper().ljust(7)
        if self.color:
            head = f"{_COLORS.get(level, '')}{_BOLD}[{stamp}] {tag}{_RESET}"
        else:
            head = f"[{stamp}] {tag}"
        return f"{head} {self.name}: {msg}"

    def _format_json(self, level: str, msg: str) -> dict:
        return {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "level": level,
            "module": self.name,
            "message": msg,
            "pid": os.getpid(),
            "thread": threading.current_thread().name,
        }

    def _emit(self, level: str, msg: str, extra: Optional[dict] = None) -> None:
        if _LEVEL_VALUES.get(level, 20) < _threshold_for(self.name, self.level):
            return
        with self._emit_lock:
            if not self.quiet:
                sys.stderr.write(self._format_human(level, msg) + "\n")
                sys.stderr.flush()
            if self._file:
                if self.json_lines:
                    record = self._format_json(level, msg)
                    if extra:
                        record.update(extra)
                    self._file.write(json.dumps(record))
                else:
                    self._file.write(self._format_human(level, msg))
        if _LEVEL_VALUES.get(level, 20) >= 30:
            self._webhook.send(level, self.name, msg)

    # Standard methods used across all 20 F-SOCIETY tools
    def debug(self, m): self._emit("debug", m)
    def info(self, m): self._emit("info", m)
    def ok(self, m): self._emit("ok", m)
    def hit(self, m): self._emit("hit", m)
    def warn(self, m): self._emit("warn", m)
    def err(self, m): self._emit("err", m)

    # Extended methods
    def success(self, m): self._emit("success", m)
    def fail(self, m): self._emit("fail", m)

    def structured(self, level: str, message: str, **fields: Any) -> None:
        if self._file and self.json_lines:
            record = self._format_json(level, message)
            record.update(fields)
            self._file.write(json.dumps(record))
        if not self.quiet:
            suffix = " ".join(f"{k}={v}" for k, v in fields.items())
            self._emit(level, f"{message}  {suffix}")

    def progress(self, current: int, total: int, label: str = "") -> None:
        if self.quiet:
            return
        pct = (current / total * 100) if total else 0.0
        bar_len = 30
        filled = int(bar_len * current / total) if total else 0
        bar = "█" * filled + "░" * (bar_len - filled)
        line = f"\r{label:<20} [{bar}] {current}/{total} ({pct:5.1f}%)"
        with self._emit_lock:
            sys.stderr.write(line)
            sys.stderr.flush()
        if current >= total:
            sys.stderr.write("\n")

    def spinner(self, message: str = "working") -> None:
        if self.quiet or not self.color:
            self.info(message)
            return
        frames = "|/-\\"
        self._spinner_stop.clear()

        def spin():
            i = 0
            while not self._spinner_stop.is_set():
                sys.stderr.write(f"\r{message} {frames[i % 4]}")
                sys.stderr.flush()
                i += 1
                time.sleep(0.1)
            sys.stderr.write(f"\r{message} ... done\n")
            sys.stderr.flush()

        self._spinner_thread = threading.Thread(target=spin, daemon=True)
        self._spinner_thread.start()

    def stop_spinner(self) -> None:
        if self._spinner_thread:
            self._spinner_stop.set()
            self._spinner_thread.join(timeout=1)
            self._spinner_thread = None

    @contextmanager
    def timer(self, label: str = "operation"):
        start = time.perf_counter()
        try:
            yield
        finally:
            elapsed = time.perf_counter() - start
            self.ok(f"{label} finished in {elapsed:.3f}s")

    def child(self, name: str) -> "Log":
        """Derive a logger sharing the file/webhook but with a new module tag."""
        child = Log(
            f"{self.name}.{name}",
            level=self.level,
            color=self.color,
            json_lines=self.json_lines,
            quiet=self.quiet,
        )
        child._file = self._file
        child._webhook = self._webhook
        return child
