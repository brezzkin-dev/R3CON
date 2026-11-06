from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from fsociety.core.base import tool
from fsociety.core.logger import Log

@tool("packetforge", "Raw packet manipulation, sniffing, and injection", category="network")
class PacketForge:
    @staticmethod
    def build_parser(p):
        sub = p.add_subparsers(dest="cmd", required=True)
        sniff = sub.add_parser("sniff", help="Sniff packets on an interface")
        sniff.add_argument("interface")
        sniff.add_argument("--filter", default="", help="BPF filter (e.g., 'tcp port 80')")
        inject = sub.add_parser("inject", help="Inject a raw hex packet")
        inject.add_argument("interface")
        inject.add_argument("hex_data", help="Raw hex string of the packet")
        arp = sub.add_parser("arp", help="ARP Poisoning (MITM)")
        arp.add_argument("interface")
        arp.add_argument("target_ip")
        arp.add_argument("gateway_ip")

    @staticmethod
    def run(args, log: Log) -> int:
        if os.geteuid() != 0:
            log.err("Raw packet operations require root.")
            return 1
        src = Path(__file__).parent / "src" / "packetforge.c"
        bin_path = Path(__file__).parent / "src" / "packetforge"
        if not src.exists():
            log.err("Source code missing.")
            return 1
        if not bin_path.exists():
            log.info("Compiling packetforge.c...")
            if not shutil.which("gcc"):
                log.err("gcc not found.")
                return 1
            proc = subprocess.run(["gcc", "-O3", str(src), "-o", str(bin_path), "-lpcap"])
            if proc.returncode != 0:
                log.err("Compilation failed. Ensure libpcap-dev is installed.")
                return 1
        cmd = [str(bin_path), args.interface]
        if args.cmd == "sniff": cmd.extend(["sniff", args.filter])
        elif args.cmd == "inject": cmd.extend(["inject", args.hex_data])
        elif args.cmd == "arp": cmd.extend(["arp", args.target_ip, args.gateway_ip])
        subprocess.run(cmd)
        return 0
