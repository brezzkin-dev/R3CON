from __future__ import annotations

import os
import secrets
import shutil
import stat
from pathlib import Path

from fsociety.core.base import tool
from fsociety.core.logger import Log
from fsociety.core.utils import file_digest, human_bytes, iter_files, is_regular, random_name

PASSES = {
    "zero":   [b"\x00"],
    "one":    [b"\xff"],
    "random": [None],
    "dod":    [b"\x00", b"\xff", None, b"\xf6", b"\x00", b"\xff", None],
    "gutmann": [
        None, None, None, None,
        b"\x55", b"\xaa", b"\x55\xaa", b"\xaa\x55",
        b"\x92\x49\x24", b"\x49\x24\x92", b"\x24\x92\x49",
        b"\x00", b"\x11", b"\x22", b"\x33", b"\x44", b"\x55",
        b"\x66", b"\x77", b"\x88", b"\x99", b"\xaa", b"\xbb",
        b"\xcc", b"\xdd", b"\xee", b"\xff",
        b"\x92\x49\x24", b"\x49\x24\x92", b"\x24\x92\x49",
        b"\x6d\xb6\xdb", b"\xb6\xdb\x6d", b"\xdb\x6d\xb6",
    ],
}

@tool("shred", "Multi-pass file overwrite with optional verification", category="destructive")
class Shred:
    @staticmethod
    def build_parser(p):
        p.add_argument("path", nargs="+", help="file(s) or directory to destroy")
        p.add_argument("-p", "--passes", default="random", choices=list(PASSES),
                       help="overwrite pattern (default: random)")
        p.add_argument("-n", "--count", type=int, default=1,
                       help="repeat the pass set N times (default 1)")
        p.add_argument("-z", "--zero", action="store_true",
                       help="final zero pass to hide the wipe signature")
        p.add_argument("-r", "--recursive", action="store_true",
                       help="walk directories")
        p.add_argument("-f", "--force", action="store_true",
                       help="skip confirmation and clear read-only bits")
        p.add_argument("--rename", action="store_true",
                       help="rename to random name before unlink")
        p.add_argument("--verify", action="store_true",
                       help="hash pre/post and confirm mismatch")
        p.add_argument("--dry-run", action="store_true", help="list targets only")

    @staticmethod
    def _targets(paths, recursive):
        out = []
        for raw in paths:
            p = Path(raw)
            if p.is_dir():
                if not recursive:
                    continue
                out.extend(iter_files(p))
            elif is_regular(p):
                out.append(p)
        return out

    @staticmethod
    def _overwrite(path: Path, pattern, size: int) -> None:
        with open(path, "r+b", buffering=0) as fh:
            fh.seek(0)
            remaining = size
            while remaining > 0:
                chunk = min(1024 * 1024, remaining)
                buf = secrets.token_bytes(chunk) if pattern is None else (pattern * (chunk // len(pattern) + 1))[:chunk]
                fh.write(buf)
                remaining -= chunk
            fh.flush()
            os.fsync(fh.fileno())
            fh.seek(0)

    @staticmethod
    def _force_unlink(path: Path, rename: bool) -> None:
        try:
            os.chmod(path, stat.S_IWUSR | stat.S_IRUSR)
        except OSError:
            pass
        if rename:
            scrambled = path.with_name(random_name(16))
            try:
                path.rename(scrambled)
                path = scrambled
            except OSError:
                pass
        try:
            path.unlink()
        except FileNotFoundError:
            pass

    @staticmethod
    def run(args, log: Log) -> int:
        targets = Shred._targets(args.path, args.recursive)
        if not targets:
            log.err("no targets matched")
            return 1
        pattern_set = PASSES[args.passes]
        total_bytes = sum(t.stat().st_size for t in targets)
        log.info(f"{len(targets)} target(s), {human_bytes(total_bytes)} total")
        if args.dry_run:
            for t in targets:
                print(t)
            return 0

        failed = 0
        for path in targets:
            try:
                size = path.stat().st_size
                pre = file_digest(path) if args.verify else ""
                for _ in range(max(1, args.count)):
                    for pat in pattern_set:
                        Shred._overwrite(path, pat, size)
                if args.zero:
                    Shred._overwrite(path, b"\x00", size)
                if args.verify:
                    post = file_digest(path)
                    if pre == post and size > 0:
                        log.warn(f"{path}: hash unchanged (filesystem may be copy-on-write)")
                Shred._force_unlink(path, args.rename)
                log.ok(f"shredded {path}")
            except PermissionError:
                log.err(f"{path}: permission denied")
                failed += 1
            except OSError as exc:
                log.err(f"{path}: {exc}")
                failed += 1
        return 0 if failed == 0 else 1
