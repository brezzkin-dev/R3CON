from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Sequence


def table(rows: Sequence[Sequence[str]], headers: Sequence[str]) -> str:
    cols = len(headers)
    widths = [len(h) for h in headers]
    for row in rows:
        for i in range(cols):
            widths[i] = max(widths[i], len(str(row[i])))
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    sep = "  ".join("-" * widths[i] for i in range(cols))
    body = [
        "  ".join(str(row[i]).ljust(widths[i]) for i in range(cols))
        for row in rows
    ]
    return "\n".join([line, sep, *body])


def dump_json(payload, path: str | Path | None = None, indent: int = 2) -> str:
    text = json.dumps(payload, indent=indent, default=str, ensure_ascii=False)
    if path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return text


def write_lines(lines: Iterable[str], path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as fh:
        for line in lines:
            fh.write(f"{line}\n")
    return target
