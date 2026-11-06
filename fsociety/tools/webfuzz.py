from __future__ import annotations
import http.client
import os
import random
import string
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from fsociety.core.base import tool
from fsociety.core.logger import Log

COMMON_PATHS = [
    "admin", "login", "wp-admin", "wp-login.php", ".git/config", ".env",
    "robots.txt", "sitemap.xml", "api", "api/v1", "api/v2", "graphql",
    "backup", "backups", "config", "config.php", "phpinfo.php", "info.php",
    "server-status", "actuator", "actuator/health", "debug", "console",
    "adminer.php", "db.php", "upload", "uploads", "files", "static",
    ".htaccess", ".DS_Store", "crossdomain.xml", "swagger.json", "openapi.json",
    "vendor", "test", "tests", "dev", "staging", "private", "internal"
]

@tool("webfuzz", "High-concurrency directory and file fuzzer", category="web")
class WebFuzz:
    @staticmethod
    def build_parser(p):
        p.add_argument("url", help="Target URL (e.g. http://site/FUZZ)")
        p.add_argument("-w", "--wordlist", required=True, help="Path to wordlist")
        p.add_argument("-t", "--threads", type=int, default=20)
        p.add_argument("--timeout", type=float, default=5.0)
        p.add_argument("--status", default="200,204,301,302,307,401,403,405")
        p.add_argument("-o", "--output", help="Save JSON results")

    @staticmethod
    def _request(url, word, timeout):
        target = url.replace("FUZZ", word)
        parsed = urllib.parse.urlparse(target)
        scheme = parsed.scheme or "http"
        host = parsed.hostname
        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query: path += "?" + parsed.query

        conn = (http.client.HTTPSConnection(host, port, timeout=timeout) if scheme == "https" else http.client.HTTPConnection(host, port, timeout=timeout))
        try:
            conn.request("GET", path, headers={"User-Agent": "Mozilla/5.0"})
            resp = conn.getresponse()
            return resp.status, len(resp.read())
        except Exception:
            return None, 0
        finally:
            conn.close()

    @staticmethod
    def run(args, log: Log) -> int:
        if not Path(args.wordlist).exists():
            log.err(f"Wordlist not found: {args.wordlist}")
            return 1

        words = [w.strip() for w in Path(args.wordlist).read_text().splitlines() if w.strip()]
        interesting = {int(s) for s in args.status.split(",") if s.strip().isdigit()}
        hits = []

        log.info(f"Fuzzing {args.url} with {len(words)} words, {args.threads} threads.")
        
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futures = {ex.submit(WebFuzz._request, args.url, w, args.timeout): w for w in words}
            for fut in as_completed(futures):
                word = futures[fut]
                status, length = fut.result()
                if status in interesting:
                    hits.append({"path": word, "status": status, "length": length})
                    log.hit(f"[{status}] /{word} ({length} bytes)")

        log.ok(f"Found {len(hits)} endpoints.")
        return 0 if hits else 1
