from __future__ import annotations

import struct
from pathlib import Path

from fsociety.core.base import tool
from fsociety.core.logger import Log

@tool("sploit", "Exploit dev helpers: pattern, offset, payload, ROP scan", category="exploit")
class Sploit:
    @staticmethod
    def build_parser(p):
        sub = p.add_subparsers(dest="cmd", required=True)

        pat = sub.add_parser("pattern", help="cyclic pattern generator")
        pat.add_argument("length", type=int)
        pat.add_argument("-o", "--out", help="write to file")

        off = sub.add_parser("offset", help="find offset of a value in pattern")
        off.add_argument("value", help="little-endian hex, e.g. 0x41326341 or Aa2c")
        off.add_argument("-l", "--length", type=int, default=8192)

        pay = sub.add_parser("payload", help="build a payload buffer")
        pay.add_argument("--offset", type=int, required=True)
        pay.add_argument("--ret", required=True, help="target return address (hex)")
        pay.add_argument("--shell", default="", help="hex bytes to append after RET")
        pay.add_argument("--bad", default="", help="comma list of bad bytes, e.g. 0x00,0x0a")
        pay.add_argument("--nop", type=int, default=16)
        pay.add_argument("-o", "--out", help="write raw bytes to file")

        rop = sub.add_parser("rop", help="scan a binary for simple gadgets")
        rop.add_argument("binary")
        rop.add_argument("--max", type=int, default=40)
        rop.add_argument("--arch", default="x64", choices=["x64", "x86"])

        pad = sub.add_parser("pad", help="pad hex bytes to size with 0x90")
        pad.add_argument("hexbytes")
        pad.add_argument("size", type=int)

    @staticmethod
    def _pattern(length: int) -> bytes:
        out = bytearray()
        a, b, c = ord("A"), ord("a"), ord("0")
        while len(out) < length:
            out += bytes([a, b, c])
            a = ord("A") + (a - ord("A") + 1) % 26
            if a == ord("A"):
                b = ord("a") + (b - ord("a") + 1) % 26
                if b == ord("a"):
                    c = ord("0") + (c - ord("0") + 1) % 10
        return bytes(out[:length])

    @staticmethod
    def _parse_target(value: str) -> int | None:
        v = value.strip()
        if v.lower().startswith("0x"):
            try:
                return int(v, 16)
            except ValueError:
                return None
        if 4 <= len(v) <= 8:
            try:
                raw = v.encode("latin-1")
                while len(raw) < 8:
                    raw += b"\x00"
                return struct.unpack("<Q", raw)[:1][0] & ((1 << (8 * len(v))) - 1)
            except Exception:
                return None
        return None

    @staticmethod
    def _find_offset(value: int, length: int) -> int | None:
        target_bytes = struct.pack("<I", value & 0xffffffff)
        if value > 0xffffffff:
            target_bytes = struct.pack("<Q", value)
        haystack = Sploit._pattern(length)
        idx = haystack.find(target_bytes)
        return idx if idx >= 0 else None

    @staticmethod
    def _write_binary(path: str, data: bytes) -> None:
        Path(path).write_bytes(data)

    @staticmethod
    def _parse_hex(spec: str) -> bytes:
        spec = spec.strip().replace(" ", "")
        if spec.startswith("0x"):
            spec = spec[2:]
        if len(spec) % 2:
            spec = "0" + spec
        return bytes.fromhex(spec)

    @staticmethod
    def _build_payload(offset, ret_addr, shell_hex, bad_bytes, nop_count):
        filler = bytearray()
        alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        i = 0
        while len(filler) < offset:
            b = alphabet[i % 26]
            if b not in bad_bytes:
                filler.append(b)
            i += 1
        ret = struct.pack("<Q", ret_addr)
        for b in ret:
            if b in bad_bytes:
                raise ValueError(f"bad byte {b:#x} present in return address")
        shell = Sploit._parse_hex(shell_hex) if shell_hex else b""
        for b in shell:
            if b in bad_bytes:
                raise ValueError(f"bad byte {b:#x} present in shell code")
        nop = b"\x90" * max(0, nop_count)
        return bytes(filler) + ret + nop + shell

    @staticmethod
    def _scan_rop(path: str, max_hits: int, arch: str):
        data = Path(path).read_bytes()
        patterns = {
            "x64": [
                ("pop rdi ; ret",  b"\x5f\xc3"),
                ("pop rsi ; ret",  b"\x5e\xc3"),
                ("pop rdx ; ret",  b"\x5a\xc3"),
                ("pop rax ; ret",  b"\x58\xc3"),
                ("syscall ; ret",  b"\x0f\x05\xc3"),
                ("leave ; ret",    b"\xc9\xc3"),
            ],
            "x86": [
                ("pop eax ; ret",  b"\x58\xc3"),
                ("pop ebx ; ret",  b"\x5b\xc3"),
                ("pop ecx ; ret",  b"\x59\xc3"),
                ("pop edx ; ret",  b"\x5a\xc3"),
                ("int 0x80 ; ret", b"\xcd\x80\xc3"),
            ],
        }[arch]
        hits = []
        for name, needle in patterns:
            start = 0
            count = 0
            while count < max_hits:
                idx = data.find(needle, start)
                if idx < 0:
                    break
                hits.append({"gadget": name, "offset": idx, "bytes": needle.hex()})
                start = idx + 1
                count += 1
        return hits

    @staticmethod
    def run(args, log: Log) -> int:
        cmd = args.cmd

        if cmd == "pattern":
            data = Sploit._pattern(args.length)
            if args.out:
                Sploit._write_binary(args.out, data)
                log.ok(f"wrote {args.length} bytes to {args.out}")
            else:
                print(data.decode("latin-1"))
            return 0

        if cmd == "offset":
            value = Sploit._parse_target(args.value)
            if value is None:
                log.err("could not parse value")
                return 2
            offset = Sploit._find_offset(value, args.length)
            if offset is None:
                log.err(f"pattern did not contain {args.value}")
                return 1
            log.ok(f"offset = {offset}")
            return 0

        if cmd == "payload":
            bad = set()
            if args.bad:
                for tok in args.bad.split(","):
                    bad.add(Sploit._parse_hex(tok)[0])
            ret_addr = int(args.ret, 16) if args.ret.lower().startswith("0x") else int(args.ret, 16)
            try:
                buf = Sploit._build_payload(args.offset, ret_addr,
                                             args.shell, bad, args.nop)
            except ValueError as exc:
                log.err(str(exc))
                return 2
            if args.out:
                Sploit._write_binary(args.out, buf)
                log.ok(f"payload {len(buf)}B -> {args.out}")
            else:
                print(buf.hex())
            return 0

        if cmd == "rop":
            hits = Sploit._scan_rop(args.binary, args.max, args.arch)
            for h in hits:
                print(f"{h['offset']:#010x}  {h['bytes']:<12}  {h['gadget']}")
            log.ok(f"{len(hits)} gadget(s)")
            return 0

        if cmd == "pad":
            raw = Sploit._parse_hex(args.hexbytes)
            if len(raw) >= args.size:
                print(raw[:args.size].hex())
            else:
                padded = raw + b"\x90" * (args.size - len(raw))
                print(padded.hex())
            return 0

        return 2
