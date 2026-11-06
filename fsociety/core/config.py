from __future__ import annotations

import os
from pathlib import Path

VERSION = "1.0.0"
CODENAME = "F-SOCIETY"
AUTHOR = "L1ghtXr"
CONTRIBUTOR = "DevBrezz"

HOME = Path(os.environ.get("FSOCIETY_HOME", Path.home() / ".fsociety"))
LOOT = HOME / "loot"
CACHE = HOME / "cache"
LOGS = HOME / "logs"

BANNER = r"""
 ______     ______  _____   _____ ______ _______ ______ __   __
|  ____|   / ____ \|  __ \ / ____|  ____|__   __|  ____|\ \ / /
| |__ _____| (___ | |  | | |    | |__     | |  | |__    \ V /
|  __|______ \___ \| |  | | |    |  __|    | |  |  __|    | |
| |         ____) | |__| | |____| |____   | |  | |____   | |
|_|        |_____/|_____/ \_____|______|  |_|  |______|  |_|
"""


def ensure_dirs() -> None:
    for path in (HOME, LOOT, CACHE, LOGS):
        path.mkdir(parents=True, exist_ok=True)
