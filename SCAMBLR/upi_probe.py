"""UPI VPA enumeration and validity probing via NPCI-compatible endpoints."""
from __future__ import annotations

import random
import string
import threading
import time

import requests


UPI_HANDLES = [
    "okhdfcbank", "okaxis", "oksbi", "okicici", "ybl", "paytm",
    "apl", "axl", "ibl", "upi", "sbi", "hdfcbank", "icici", "axisbank",
    "kotak", "yesbank", "federal", "rbl", "idfcbank",
]

# Public VPA-verification endpoints that NPCI exposes for merchant integration.
# No auth required; rate limits per IP.
VERIFY_ENDPOINTS = [
    "https://api.razorpay.com/v1/upi/verify-vpa",
    "https://api.cashfree.com/verification/vpa",
]


class UPIProbe:
    def __init__(self, base_name: str | None = None, proxies: list[str] | None = None):
        self.base = base_name or "".join(random.choices(string.ascii_lowercase, k=8))
        self.proxies = proxies or []
        self.valid_vpas: list[str] = []
        self._lock = threading.Lock()

    def _verify(self, vpa: str) -> bool:
        for ep in VERIFY_ENDPOINTS:
            try:
                p = random.choice(self.proxies) if self.proxies else None
                r = requests.post(ep, json={"vpa": vpa},
                                  proxies={"https": p} if p else None,
                                  timeout=8)
                if r.status_code == 200:
                    body = r.json()
                    if body.get("valid") or body.get("status") == "SUCCESS":
                        return True
                elif r.status_code == 400:
                    # invalid VPA — 400 from Razorpay is definitive
                    return False
            except requests.RequestException:
                continue
        return False

    def probe_handles(self, workers: int = 10) -> list[str]:
        def worker(handle):
            vpa = f"{self.base}@{handle}"
            if self._verify(vpa):
                with self._lock:
                    self.valid_vpas.append(vpa)
        ts = [threading.Thread(target=worker, args=(h,), daemon=True) for h in UPI_HANDLES]
        for t in ts: t.start()
        for t in ts: t.join()
        return self.valid_vpas

    def brute_suffix(self, phone_last4: str, workers: int = 20) -> list[str]:
        """Probe name+suffix VPAs seeded from scammer's phone last-4."""
        candidates = [f"{self.base}{phone_last4}@{h}" for h in UPI_HANDLES]
        candidates += [f"{self.base}.{phone_last4}@{h}" for h in UPI_HANDLES]
        candidates += [f"{self.base}_{phone_last4}@{h}" for h in UPI_HANDLES]

        def worker(vpa):
            if self._verify(vpa):
                with self._lock:
                    self.valid_vpas.append(vpa)
        ts = [threading.Thread(target=worker, args=(v,), daemon=True) for v in candidates]
        for t in ts: t.start()
        for t in ts: t.join()
        return self.valid_vpas
