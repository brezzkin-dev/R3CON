from __future__ import annotations
import json
import subprocess
import sys
import importlib.util
import os
import dns.resolver
import requests
import urllib.parse
import ipaddress

from fsociety.core.base import tool
from fsociety.core.logger import Log

def ensure_deps():
    deps = ["requests", "dnspython"]
    missing = [d for d in deps if importlib.util.find_spec(d.replace("-", "_")) is None]
    if missing:
        subprocess.run([sys.executable, "-m", "pip", "install", *missing], check=True, capture_output=True)

@tool("tracecore", "Zero-API-key OSINT engine: DNS, RDAP, CT Logs", category="recon")
class TraceCore:
    @staticmethod
    def build_parser(p):
        p.add_argument("target", help="Domain, IP, URL, email, username, or phone")
        p.add_argument("--json", action="store_true", help="Output raw JSON")

    @staticmethod
    def run(args, log: Log) -> int:
        ensure_deps()
        target = args.target.strip()
        t_type = "domain"
        if "://" in target: t_type = "url"
        elif "@" in target: t_type = "email"
        elif target.replace(".", "").isdigit(): t_type = "ipv4"
        
        if t_type == "url":
            target = urllib.parse.urlparse(target).hostname
            t_type = "domain"
            
        if args.json: print(json.dumps({"target": target, "type": t_type}))
        else: log.info(f"Initializing TraceCore for target: {target} ({t_type})")
        
        if t_type == "domain":
            for rtype in ["A", "MX", "TXT", "NS"]:
                try:
                    ans = dns.resolver.resolve(target, rtype, lifetime=3)
                    for r in ans:
                        log.hit(f"DNS {rtype}: {r}")
                except Exception: pass
            
            try:
                r = requests.get(f"https://rdap.org/domain/{target}", timeout=5)
                if r.status_code == 200:
                    data = r.json()
                    for ev in data.get("events", []):
                        log.info(f"RDAP {ev.get('eventAction')}: {ev.get('eventDate')}")
            except Exception: pass
        return 0
