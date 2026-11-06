from __future__ import annotations

import json
import re
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Iterator

from fsociety.core.base import tool
from fsociety.core.logger import Log
from fsociety.core.output import dump_json

LOGIN_RE = re.compile(r"^(?P<url>\S+)?\s*(?P<user>[^\s:]+)[:\s](?P<pw>.+)$")
URL_RE = re.compile(r"(https?://\S+)")
USER_RE = re.compile(r"(?:login|username|user|email|login_email)[\"']?\s*[:=]\s*[\"']?([^\"'\s,}]+)", re.I)
PASS_RE = re.compile(r"(?:password|passwd|pwd)[\"']?\s*[:=]\s*[\"']?([^\"'\s,}]+)", re.I)
COOKIE_RE = re.compile(r"^(?:\S+\t){6}\S+$")


def _looks_like_login(line: str) -> bool:
    if line.count(":") >= 1 and not line.startswith("#"):
        return True
    return "://" in line


def _parse_login(line: str):
    m = LOGIN_RE.match(line.strip())
    if not m:
        return None
    url = m.group("url") or ""
    user = m.group("user")
    pw = m.group("pw")
    if pw in ("", " ", None):
        return None
    return {"url": url, "username": user, "password": pw, "source": "text"}


@tool("ripper", "Extract credentials from text, sqlite, JSON, and browser stores", category="credential")
class Ripper:
    @staticmethod
    def build_parser(p):
        p.add_argument("path", help="file or directory to parse")
        p.add_argument("-r", "--recursive", action="store_true", help="walk directories")
        p.add_argument("--kind", default="auto",
                       choices=["auto", "text", "sqlite", "json", "cookies", "history"],
                       help="parser to use")
        p.add_argument("--domain", help="filter results by domain substring")
        p.add_argument("-o", "--out", help="write results (json) to path")
        p.add_argument("--dedupe", action="store_true", help="unique (user,password) pairs")

    @staticmethod
    def _iter_text(path: Path) -> Iterator[dict]:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                rec = _parse_login(line)
                if rec:
                    rec["source_file"] = str(path)
                    yield rec

    @staticmethod
    def _iter_json(path: Path) -> Iterator[dict]:
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            return
        stack = [data]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                url = str(node.get("url") or node.get("origin") or "")
                user = node.get("username") or node.get("user") or node.get("email") or node.get("login")
                pw = node.get("password") or node.get("pass") or node.get("pwd")
                if user and pw:
                    yield {"url": url, "username": str(user), "password": str(pw),
                           "source": "json", "source_file": str(path)}
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)

    @staticmethod
    def _iter_sqlite(path: Path) -> Iterator[dict]:
        try:
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        except sqlite3.Error:
            return
        try:
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [r[0] for r in cur.fetchall()]
            for table in tables:
                try:
                    cur.execute(f'SELECT * FROM "{table}" LIMIT 5000')
                    cols = [d[0].lower() for d in cur.description]
                    user_col = next((i for i, c in enumerate(cols) if "user" in c or "email" in c or "login" in c), None)
                    pw_col = next((i for i, c in enumerate(cols) if c in ("password", "passwd", "pwd", "encrypted_password")), None)
                    url_col = next((i for i, c in enumerate(cols) if "url" in c or "origin" in c or "host" in c), None)
                    if user_col is None or pw_col is None:
                        continue
                    for row in cur.fetchall():
                        user = row[user_col]
                        pw = row[pw_col]
                        if not user or not pw:
                            continue
                        yield {
                            "url": str(row[url_col]) if url_col is not None else "",
                            "username": str(user),
                            "password": str(pw),
                            "source": f"sqlite:{table}",
                            "source_file": str(path),
                        }
                except sqlite3.Error:
                    continue
        finally:
            conn.close()

    @staticmethod
    def _iter_cookies(path: Path) -> Iterator[dict]:
        if path.suffix.lower() == ".sqlite" or path.name == "Cookies":
            for rec in Ripper._iter_sqlite(path):
                if rec["username"]:
                    yield {**rec, "source": "cookie-store"}
            return
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.rstrip("\r\n")
                if not line or line.startswith("#"):
                    continue
                if COOKIE_RE.match(line):
                    parts = line.split("\t")
                    yield {"url": parts[0], "username": "", "password": parts[6] if len(parts) > 6 else "",
                           "source": "cookies", "source_file": str(path)}

    @staticmethod
    def _iter_history(path: Path) -> Iterator[dict]:
        for rec in Ripper._iter_sqlite(path):
            yield rec
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    for match in URL_RE.findall(line):
                        yield {"url": match, "username": "", "password": "",
                               "source": "history", "source_file": str(path)}
        except Exception:
            return

    @staticmethod
    def _walk(path: Path, recursive: bool) -> Iterator[Path]:
        if path.is_file():
            yield path
        elif path.is_dir() and recursive:
            for child in path.rglob("*"):
                if child.is_file():
                    yield child

    @staticmethod
    def _process(path: Path, kind: str):
        ext = path.suffix.lower()
        name = path.name.lower()
        if kind == "auto":
            if ext == ".json":
                kind = "json"
            elif ext in (".sqlite", ".db") or name in ("logins.json", "cookies", "history", "places.sqlite", "Login Data"):
                kind = "sqlite"
            elif name in ("cookies", "cookies.txt"):
                kind = "cookies"
            else:
                kind = "text"
        if kind == "json":
            yield from Ripper._iter_json(path)
        elif kind == "sqlite":
            yield from Ripper._iter_sqlite(path)
        elif kind == "cookies":
            yield from Ripper._iter_cookies(path)
        elif kind == "history":
            yield from Ripper._iter_history(path)
        else:
            yield from Ripper._iter_text(path)

    @staticmethod
    def run(args, log: Log) -> int:
        root = Path(args.path)
        if not root.exists():
            log.err(f"missing path: {root}")
            return 1
        results = []
        seen = set()
        for file in Ripper._walk(root, args.recursive):
            try:
                for rec in Ripper._process(file, args.kind):
                    if args.domain and args.domain.lower() not in (rec.get("url") or "").lower():
                        continue
                    key = (rec["username"], rec["password"])
                    if args.dedupe and key in seen:
                        continue
                    seen.add(key)
                    results.append(rec)
            except Exception as exc:
                log.warn(f"{file}: {exc}")
        log.ok(f"extracted {len(results)} credential record(s)")
        if args.out:
            dump_json(results, args.out)
            log.info(f"written to {args.out}")
        else:
            for rec in results[:200]:
                print(f"{rec.get('url','-')}\t{rec['username']}\t{rec['password']}")
        return 0
