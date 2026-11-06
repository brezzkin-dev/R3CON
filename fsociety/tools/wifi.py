from __future__ import annotations

import subprocess
import shutil
from pathlib import Path

from fsociety.core.base import tool
from fsociety.core.logger import Log

@tool("wifi", "Wi-Fi deauthentication and monitoring", category="wifi")
class Wifi:
    @staticmethod
    def build_parser(p):
        sub = p.add_subparsers(dest="cmd", required=True)
        deauth = sub.add_parser("deauth", help="Send deauth frames via aireplay-ng")
        deauth.add_argument("interface")
        deauth.add_argument("bssid")
        deauth.add_argument("client", default="FF:FF:FF:FF:FF:FF", nargs="?")
        deauth.add_argument("--count", type=int, default=10)
        scan = sub.add_parser("scan", help="Dump nearby APs")

    @staticmethod
    def run(args, log: Log) -> int:
        if args.cmd == "deauth":
            if not shutil.which("aireplay-ng"):
                log.err("aireplay-ng not installed (apt install aircrack-ng)")
                return 1
            cmd = ["aireplay-ng", "--deauth", str(args.count), "-a", args.bssid, args.interface]
            if args.client != "FF:FF:FF:FF:FF:FF": cmd += ["-c", args.client]
            log.info(f"Deauthing {args.bssid} on {args.interface}")
            subprocess.run(cmd)
            return 0
        if args.cmd == "scan":
            if not shutil.which("iw"):
                log.err("iw not installed")
                return 1
            subprocess.run(["iw", "dev"])
            subprocess.run(["iwlist", "scan"])
            return 0
        return 2
