from __future__ import annotations
import json
import subprocess
import sys
import importlib.util
from concurrent.futures import ThreadPoolExecutor, as_completed
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
import requests
from bs4 import BeautifulSoup

from fsociety.core.base import tool
from fsociety.core.logger import Log

def ensure_deps():
    deps = ["phonenumbers", "requests", "beautifulsoup4"]
    missing = [d for d in deps if importlib.util.find_spec(d.replace("-", "_")) is None]
    if missing:
        subprocess.run([sys.executable, "-m", "pip", "install", *missing], check=True, capture_output=True)

HEADERS = {"User-Agent": "Mozilla/5.0"}

@tool("phonenumscan", "Phone number OSINT and social media presence", category="recon")
class PhoneNumScan:
    @staticmethod
    def build_parser(p):
        p.add_argument("number", help="Phone number with country code (e.g., +628123456789)")
        p.add_argument("--threads", type=int, default=10)

    @staticmethod
    def run(args, log: Log) -> int:
        ensure_deps()
        raw = args.number.strip()
        try:
            if not raw.startswith("+"): raw = "+" + raw
            parsed = phonenumbers.parse(raw, None)
        except Exception:
            log.err("Invalid format")
            return 1
            
        log.info(f"Format: {phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)}")
        log.info(f"Region: {geocoder.description_for_number(parsed, 'en')}")
        log.info(f"Carrier: {carrier.name_for_number(parsed, 'en')}")
        log.info(f"Timezone: {timezone.time_zones_for_number(parsed)}")
        
        digits = str(parsed.national_number)
        session = requests.Session()
        session.headers.update(HEADERS)
        
        def check_wa():
            try:
                r = session.get(f"https://wa.me/{digits}", timeout=10)
                return "Registered" if "invalid" not in r.text else "Not Registered"
            except Exception: return "Error"
            
        def check_tg():
            try:
                r = session.get(f"https://t.me/+{digits}", timeout=10)
                return "Registered" if "tgme_page_title" in r.text else "Not Registered"
            except Exception: return "Error"
            
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futures = {ex.submit(check_wa): "WhatsApp", ex.submit(check_tg): "Telegram"}
            for f in as_completed(futures):
                log.hit(f"{futures[f]}: {f.result()}")
                
        return 0
