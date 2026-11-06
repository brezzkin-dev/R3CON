from __future__ import annotations

import hashlib
import math
import os
import secrets
import stat
import string
import time
from collections import Counter
from pathlib import Path
from typing import Iterator, Sequence

CHUNK = 1024 * 1024
ALNUM = string.ascii_letters + string.digits


def human_bytes(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    value = float(n)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{n} B"


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def digest(data: bytes, algorithm: str = "sha256") -> str:
    return hashlib.new(algorithm, data).hexdigest()


def file_digest(path: str | Path, algorithm: str = "sha256") -> str:
    h = hashlib.new(algorithm)
    with open(path, "rb") as fh:
        while chunk := fh.read(CHUNK):
            h.update(chunk)
    return h.hexdigest()


def iter_files(root: str | Path, follow: bool = False) -> Iterator[Path]:
    root = Path(root)
    if root.is_file():
        yield root
        return
    for base, dirs, files in os.walk(root, followlinks=follow):
        for name in files:
            yield Path(base) / name


def load_lines(path: str | Path) -> list[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        return [line.rstrip("\r\n") for line in fh if line.strip()]


def is_regular(path: str | Path) -> bool:
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return False


def random_name(length: int = 16) -> str:
    return "".join(secrets.choice(ALNUM) for _ in range(length))


def stamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def ensure_dir(path: str | Path) -> Path:
    target = Path(path)
    target.mkdir(parents=True, exist_ok=True)
    return target


def parse_targets(spec: str) -> list[str]:
    """Accepts comma lists, files (@path) and ranges (10.0.0.1-10.0.0.5)."""
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
