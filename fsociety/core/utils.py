from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path
from typing import Iterator


def load_lines(path: str | Path) -> list[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        return [line.rstrip("\r\n") for line in fh if line.strip()]


def random_name(length: int = 16) -> str:
    return "".join(secrets.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(length))


def parse_targets(spec: str) -> list[str]:
    spec = spec.strip()
    if spec.startswith("@"):
        return [x for x in load_lines(spec[1:]) if x]
    out: list[str] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part and part.count(".") == 3:
            left, right = part.split("-", 1)
            head, a = left.rsplit(".", 1)
            b = right.rsplit(".", 1)[-1]
            if a.isdigit() and b.isdigit():
                for i in range(int(a), int(b) + 1):
                    out.append(f"{head}.{i}")
                continue
        out.append(part)
    return out
