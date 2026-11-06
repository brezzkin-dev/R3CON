from __future__ import annotations

import base64
import http.client
import json
import re
import socket
import urllib.parse
from pathlib import Path

from fsociety.core.base import tool
from fsociety.core.logger import Log
from fsociety.core.utils import load_lines, parse_targets

@tool("pwnd", "Offensive recon and target state probe", category="offensive")
class Pwnd:
    @staticmethod
    def build_parser(p):
        sub = p.add_subparsers(dest="cmd", required=True)

        probe = sub.add_parser("probe", help="TCP connect sweep and banner grab")
        probe.add_argument("target", help="hosts spec: '1.1.1.1,2.2.2.2' or @file or range '10.0.0.1-10.0.0.10'")
        probe.add_argument("-p", "--ports",
                           default="21,22,23,25,53,80,110,139,143,443,445,3306,3389,5432,6379,8080,8443",
                           help="comma list or range start-end")
        probe.add_argument("-t", "--timeout", type=float, default=2.0)
        probe.add_argument("--banner", action="store_true", help="read service banner")
        probe.add_argument("--threads", type=int, default=64)
        probe.add_argument("-o", "--out", help="write JSON")

        parse = sub.add_parser("parse", help="parse nmap XML or grepable output")
        parse.add_argument("path")
        parse.add_argument("-o", "--out")

        check = sub.add_parser("check", help="verify banner against known service signatures")
        check.add_argument("banner", help="raw banner string")
        check.add_argument("--port", type=int)

        brute = sub.add_parser("brute", help="sequential credential probe against a service")
        brute.add_argument("host")
        brute.add_argument("--port", type=int, required=True)
        brute.add_argument("--userlist", required=True)
        brute.add_argument("--passlist", required=True)
        brute.add_argument("--proto", default="tcp", choices=["tcp", "http-basic"])
        brute.add_argument("--url", help="http-basic target URL")
        brute.add_argument("--timeout", type=float, default=5.0)
        brute.add_argument("-o", "--out")

    @staticmethod
    def _ports(spec: str) -> list[int]:
        ports = []
        for tok in spec.split(","):
            tok = tok.strip()
            if "-" in tok:
                a, b = tok.split("-", 1)
                ports.extend(range(int(a), int(b) + 1))
            elif tok.isdigit():
                ports.append(int(tok))
        return sorted(set(ports))

    @staticmethod
    def _grab(host: str, port: int, timeout: float):
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
        except (OSError, socket.timeout):
            return None, b""
        banner = b""
        try:
            sock.settimeout(timeout)
            try:
                sock.sendall(b"\r\n")
                banner = sock.recv(512)
            except (socket.timeout, OSError):
                pass
        finally:
            sock.close()
        return True, banner

    @staticmethod
    def _probe(args, log: Log) -> int:
        targets = parse_targets(args.target)
        ports = Pwnd._ports(args.ports)
        log.info(f"{len(targets)} host(s) x {len(ports)} port(s)")
        results = []

        from concurrent.futures import ThreadPoolExecutor, as_completed

        def one(host, port):
            open_, banner = Pwnd._grab(host, port, args.timeout)
            if open_:
                return host, port, banner
            return None

        with ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
            futures = [ex.submit(one, h, p) for h in targets for p in ports]
            for fut in as_completed(futures):
                res = fut.result()
                if not res:
                    continue
                host, port, banner = res
                entry = {"host": host, "port": port,
                         "banner": banner.decode("latin-1").strip() if args.banner else ""}
                results.append(entry)
                log.hit(f"{host}:{port} open" + (f" | {entry['banner'][:60]}" if entry["banner"] else ""))

        if args.out:
            Path(args.out).write_text(json.dumps(results, indent=2))
            log.ok(f"{len(results)} open port(s) -> {args.out}")
        return 0

    @staticmethod
    def _parse_nmap(args, log: Log) -> int:
        path = Path(args.path)
        text = path.read_text(encoding="utf-8", errors="ignore")
        hosts = []
        if text.lstrip().startswith("<?xml") or "<nmaprun" in text:
            host_blocks = re.findall(r"<host[ >].*?</host>", text, re.S)
            for block in host_blocks:
                addr = re.search(r'<address addr="([^"]+)" addrtype="ipv4"', block)
                if not addr:
                    continue
                ports = []
                for pm in re.finditer(r'<port protocol="(\w+)" portid="(\d+)">(.*?)</port>', block, re.S):
                    proto, pid, body = pm.groups()
                    state = re.search(r'<state state="([^"]+)"', body)
                    svc = re.search(r'<service name="([^"]*)"', body)
                    ports.append({"proto": proto, "port": int(pid),
                                  "state": state.group(1) if state else "",
                                  "service": svc.group(1) if svc else ""})
                hosts.append({"host": addr.group(1), "ports": ports})
        else:
            for line in text.splitlines():
                m = re.match(r"Host:\s*(\S+)\s*\(?[^)]*\)?\s*Ports:\s*(.+)", line)
                if not m:
                    continue
                host = m.group(1)
                ports = []
                for item in m.group(2).split(","):
                    bits = item.strip().split("/")
                    if len(bits) >= 3:
                        ports.append({"port": int(bits[0]), "state": bits[1],
                                      "proto": bits[2],
                                      "service": bits[4] if len(bits) > 4 else ""})
                hosts.append({"host": host, "ports": ports})
        print(json.dumps(hosts, indent=2))
        if args.out:
            Path(args.out).write_text(json.dumps(hosts, indent=2))
            log.ok(f"written: {args.out}")
        return 0

    @staticmethod
    def _check(banner: str, port: int | None) -> int:
        sigs = {
            "ssh": "SSH-",
            "ftp": "220",
            "smtp": "220",
            "http": "HTTP/",
            "mysql": "mysql_native_password",
            "redis": "-ERR",
            "rdp": "\x03\x00\x00",
            "vnc": "RFB",
        }
        for name, token in sigs.items():
            if token in banner:
                print(json.dumps({"service": name, "port": port}))
                return 0
        print(json.dumps({"service": "unknown", "port": port}))
        return 1

    @staticmethod
    def _http_basic(host, port, url, user, pw, timeout):
        parsed = urllib.parse.urlparse(url or f"http://{host}:{port}/")
        auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
        conn = http.client.HTTPConnection(parsed.hostname, parsed.port or port, timeout=timeout)
        try:
            conn.request("GET", parsed.path or "/",
                         headers={"Authorization": f"Basic {auth}"})
            resp = conn.getresponse()
            resp.read(1024)
            return resp.status != 401
        except OSError:
            return False
        finally:
            conn.close()

    @staticmethod
    def _brute(args, log: Log) -> int:
        users = load_lines(args.userlist)
        pwds = load_lines(args.passlist)
        if args.proto == "http-basic" and not args.url:
            log.err("--url required for http-basic")
            return 2
        hits = []
        log.info(f"{len(users)} user(s) x {len(pwds)} pass(es)")
        for u in users:
            for pw in pwds:
                ok = False
                if args.proto == "http-basic":
                    ok = Pwnd._http_basic(args.host, args.port, args.url, u, pw, args.timeout)
                else:
                    try:
                        sock = socket.create_connection((args.host, args.port), timeout=args.timeout)
                        sock.sendall(f"{u}:{pw}\r\n".encode())
                        resp = sock.recv(256)
                        sock.close()
                        ok = b"230" in resp or b"OK" in resp
                    except OSError:
                        ok = False
                if ok:
                    log.hit(f"{u}:{pw} works")
                    hits.append({"user": u, "pass": pw})
                    break
        if args.out and hits:
            Path(args.out).write_text(json.dumps(hits, indent=2))
        log.ok(f"{len(hits)} valid")
        return 0

    @staticmethod
    def run(args, log: Log) -> int:
        if args.cmd == "probe":
            return Pwnd._probe(args, log)
        if args.cmd == "parse":
            return Pwnd._parse_nmap(args, log)
        if args.cmd == "check":
            return Pwnd._check(args.banner, args.port)
        if args.cmd == "brute":
            return Pwnd._brute(args, log)
        return 2
