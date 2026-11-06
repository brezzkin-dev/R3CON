from __future__ import annotations

import ctypes
import ctypes.util
import os
import re
import signal
import struct
import sys
from pathlib import Path

from fsociety.core.base import tool
from fsociety.core.logger import Log

@tool("nullx", "Low-level memory inspection: maps, /proc reads, ptrace attach", category="low-level")
class Nullx:
    @staticmethod
    def build_parser(p):
        sub = p.add_subparsers(dest="cmd", required=True)

        maps = sub.add_parser("maps", help="dump /proc/<pid>/maps in table form")
        maps.add_argument("pid", type=int)
        maps.add_argument("--filter", help="only regions containing substring")

        mem = sub.add_parser("read", help="read memory at address")
        mem.add_argument("pid", type=int)
        mem.add_argument("address", help="hex address")
        mem.add_argument("--length", type=int, default=64)

        scan = sub.add_parser("scan", help="scan process memory for byte pattern")
        scan.add_argument("pid", type=int)
        scan.add_argument("hexbytes")
        scan.add_argument("--max", type=int, default=10)

        write = sub.add_parser("write", help="write bytes at address (requires same-uid)")
        write.add_argument("pid", type=int)
        write.add_argument("address")
        write.add_argument("hexbytes")

        info = sub.add_parser("info", help="process info")
        info.add_argument("pid", type=int)

    @staticmethod
    def _read_maps(pid: int):
        regions = []
        try:
            with open(f"/proc/{pid}/maps", "r") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) < 5:
                        continue
                    addr_range = parts[0]
                    perms = parts[1]
                    offset = parts[2]
                    path = parts[-1] if parts[-1].startswith("/") else ""
                    start_hex, end_hex = addr_range.split("-")
                    regions.append({"start": int(start_hex, 16),
                                    "end": int(end_hex, 16),
                                    "perms": perms,
                                    "offset": offset,
                                    "path": path})
        except FileNotFoundError:
            return []
        return regions

    @staticmethod
    def _read_mem(pid: int, addr: int, length: int) -> bytes:
        try:
            with open(f"/proc/{pid}/mem", "rb", buffering=0) as fh:
                fh.seek(addr)
                return fh.read(length)
        except (OSError, ValueError, OverflowError):
            return b""

    @staticmethod
    def _write_mem(pid: int, addr: int, data: bytes) -> bool:
        try:
            with open(f"/proc/{pid}/mem", "r+b", buffering=0) as fh:
                fh.seek(addr)
                fh.write(data)
            return True
        except (OSError, ValueError, OverflowError):
            return False

    @staticmethod
    def _hex(spec: str) -> bytes:
        spec = spec.strip().replace(" ", "")
        if spec.startswith("0x"):
            spec = spec[2:]
        if len(spec) % 2:
            spec = "0" + spec
        return bytes.fromhex(spec)

    @staticmethod
    def run(args, log: Log) -> int:
        if args.cmd == "maps":
            regions = Nullx._read_maps(args.pid)
            if args.filter:
                regions = [r for r in regions if args.filter in r["path"]]
            for r in regions:
                print(f"{r['start']:016x}-{r['end']:016x}  {r['perms']}  "
                      f"{r['offset']:>10}  {r['path']}")
            log.ok(f"{len(regions)} region(s)")
            return 0

        if args.cmd == "read":
            addr = int(args.address, 16)
            data = Nullx._read_mem(args.pid, addr, args.length)
            if not data:
                log.err("read failed (try running with matching ptrace scope)")
                return 1
            for i in range(0, len(data), 16):
                chunk = data[i:i + 16]
                hexs = " ".join(f"{b:02x}" for b in chunk)
                text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                print(f"{addr + i:016x}  {hexs:<48}  |{text}|")
            return 0

        if args.cmd == "scan":
            needle = Nullx._hex(args.hexbytes)
            regions = [r for r in Nullx._read_maps(args.pid) if "r" in r["perms"]]
            hits = 0
            for r in regions:
                size = r["end"] - r["start"]
                if size <= 0 or size > 512 * 1024 * 1024:
                    continue
                data = Nullx._read_mem(args.pid, r["start"], size)
                if not data:
                    continue
                start = 0
                while hits < args.max:
                    idx = data.find(needle, start)
                    if idx < 0:
                        break
                    addr = r["start"] + idx
                    print(f"{addr:016x}  {data[max(0,idx-8):idx+len(needle)+8].hex()}")
                    hits += 1
                    start = idx + 1
                if hits >= args.max:
                    break
            log.ok(f"{hits} match(es)")
            return 0 if hits else 1

        if args.cmd == "write":
            addr = int(args.address, 16)
            data = Nullx._hex(args.hexbytes)
            if Nullx._write_mem(args.pid, addr, data):
                log.ok(f"wrote {len(data)}B at {addr:#x}")
                return 0
            log.err("write failed")
            return 1

        if args.cmd == "info":
            base = Path(f"/proc/{args.pid}")
            if not base.exists():
                log.err("pid not found")
                return 1
            for item in ("cmdline", "comm", "status", "environ"):
                p = base / item
                if not p.exists():
                    continue
                content = p.read_bytes()
                if item in ("cmdline", "environ"):
                    content = content.replace(b"\x00", b"\n")
                print(f"--- {item} ---")
                print(content.decode("utf-8", "replace"))
            return 0

        return 2
