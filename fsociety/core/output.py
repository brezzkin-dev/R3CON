from __future__ import annotations

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
