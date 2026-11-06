from __future__ import annotations

import binascii
import re
import struct
from pathlib import Path

from fsociety.core.base import tool
from fsociety.core.logger import Log

@tool("hexer", "Binary inspector and patcher: hexdump, strings, search, replace", category="binary")
class Hexer:
    @staticmethod
    def build_parser(p):
        sub = p.add_subparsers(dest="cmd", required=True)

        dump = sub.add_parser("dump", help="hexdump with ASCII column")
        dump.add_argument("path")
        dump.add_argument("-o", "--offset", type=lambda x: int(x, 0), default=0)
        dump.add_argument("-l", "--length", type=lambda x: int(x, 0), default=256)
        dump.add_argument("-w", "--width", type=int, default=16)

        strings = sub.add_parser("strings", help="extract printable strings")
        strings.add_argument("path")
        strings.add_argument("-n", "--min", type=int, default=4)
        strings.add_argument("-o", "--offset", type=lambda x: int(x, 0), default=0)
        strings.add_argument("-l", "--length", type=lambda x: int(x, 0), default=0)

        search = sub.add_parser("search", help="search for a hex sequence")
        search.add_argument("path")
        search.add_argument("hexbytes")
        search.add_argument("--limit", type=int, default=20)

        patch = sub.add_parser("patch", help="overwrite bytes at an offset")
        patch.add_argument("path")
        patch.add_argument("--offset", type=lambda x: int(x, 0), required=True)
        patch.add_argument("--bytes", required=True, dest="hexbytes")
        patch.add_argument("--backup", action="store_true")

        disasm = sub.add_parser("disasm", help="disassemble a slice with objdump")
        disasm.add_argument("path")
        disasm.add_argument("--offset", type=lambda x: int(x, 0), default=0)
        disasm.add_argument("--length", type=lambda x: int(x, 0), default=128)

        info = sub.add_parser("info", help="report structure and entropy")
        info.add_argument("path")

    @staticmethod
    def _hexdump(data: bytes, offset: int, width: int = 16):
        out = []
        for i in range(0, len(data), width):
            chunk = data[i:i + width]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            out.append(f"{offset + i:08x}  {hex_part:<{width * 3}}  |{ascii_part}|")
        return "\n".join(out)

    @staticmethod
    def _hexbytes(spec: str) -> bytes:
        spec = spec.strip().replace(" ", "")
        if spec.startswith("0x"):
            spec = spec[2:]
        if len(spec) % 2:
            spec = "0" + spec
        return binascii.unhexlify(spec)

    @staticmethod
    def _strings(data: bytes, min_len: int):
        pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
        for match in pattern.finditer(data):
            yield match.start(), match.group().decode("latin-1")

    @staticmethod
    def run(args, log: Log) -> int:
        path = Path(args.path)
        if not path.exists():
            log.err(f"missing: {path}")
            return 1

        if args.cmd == "dump":
            with open(path, "rb") as fh:
                fh.seek(args.offset)
                data = fh.read(args.length)
            print(Hexer._hexdump(data, args.offset, args.width))
            return 0

        if args.cmd == "strings":
            with open(path, "rb") as fh:
                if args.offset:
                    fh.seek(args.offset)
                data = fh.read(args.length) if args.length else fh.read()
            for offset, text in Hexer._strings(data, args.min):
                print(f"{args.offset + offset:08x}  {text}")
            return 0

        if args.cmd == "search":
            needle = Hexer._hexbytes(args.hexbytes)
            data = path.read_bytes()
            start = 0
            count = 0
            while count < args.limit:
                idx = data.find(needle, start)
                if idx < 0:
                    break
                ctx_start = max(0, idx - 8)
                ctx_end = min(len(data), idx + len(needle) + 8)
                print(f"{idx:08x}  {data[ctx_start:ctx_end].hex()}")
                start = idx + 1
                count += 1
            log.ok(f"{count} match(es)")
            return 0 if count else 1

        if args.cmd == "patch":
            data = path.read_bytes()
            patch = Hexer._hexbytes(args.hexbytes)
            if args.backup:
                path.with_suffix(path.suffix + ".bak").write_bytes(data)
            if args.offset + len(patch) > len(data):
                log.err("patch exceeds file size")
                return 1
            mutated = bytearray(data)
            mutated[args.offset:args.offset + len(patch)] = patch
            path.write_bytes(mutated)
            log.ok(f"patched {len(patch)}B at {args.offset:#x}")
            return 0

        if args.cmd == "disasm":
            if not Path("/usr/bin/objdump").exists():
                log.err("objdump not found")
                return 1
            import subprocess
            tmp = path.parent / (path.name + ".slice")
            tmp.write_bytes(path.read_bytes()[args.offset:args.offset + args.length])
            try:
                out = subprocess.run(["objdump", "-D", "-b", "binary", "-m", "i386:x86-64", str(tmp)],
                                     capture_output=True, text=True, timeout=30)
                print(out.stdout)
            finally:
                tmp.unlink(missing_ok=True)
            return 0

        if args.cmd == "info":
            import math
            from collections import Counter
            data = path.read_bytes()
            counts = Counter(data)
            entropy = -sum((c / len(data)) * math.log2(c / len(data)) for c in counts.values()) if data else 0
            magic = {
                b"\x7fELF": "ELF", b"MZ": "PE", b"\xca\xfe\xba\xbe": "Mach-O fat",
                b"\xcf\xfa\xed\xfe": "Mach-O 64", b"PK\x03\x04": "ZIP",
                b"\x1f\x8b": "GZIP", b"%PDF": "PDF", b"\x89PNG": "PNG",
            }.get(data[:4], "unknown")
            print(f"size: {len(data)}")
            print(f"entropy: {entropy:.3f}")
            print(f"magic: {magic}")
            print(f"first16: {data[:16].hex()}")
            return 0

        return 2
