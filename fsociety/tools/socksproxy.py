from __future__ import annotations
import os
import shutil
import subprocess
from pathlib import Path

from fsociety.core.base import tool
from fsociety.core.logger import Log

@tool("socksproxy", "High-performance Go SOCKS5 proxy with auth and UDP tunnel", category="network")
class SocksProxy:
    @staticmethod
    def build_parser(p):
        p.add_argument("--listen", default="0.0.0.0:1080", help="Listen address")
        p.add_argument("--user", default="", help="Username for auth")
        p.add_argument("--pass", dest="password", default="", help="Password for auth")
        p.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")

    @staticmethod
    def run(args, log: Log) -> int:
        src_dir = Path(__file__).parent / "src" / "socksproxy"
        bin_path = src_dir / "socksproxy"
        main_go = src_dir / "main.go"

        if not main_go.exists():
            log.err("main.go source missing.")
            return 1

        if not bin_path.exists():
            if not shutil.which("go"):
                log.err("Go toolchain not installed.")
                return 1
            log.info("Compiling SOCKS5 proxy...")
            proc = subprocess.run(["go", "build", "-ldflags=-s -w", "-o", str(bin_path), "main.go"], cwd=str(src_dir))
            if proc.returncode != 0:
                log.err("Compilation failed.")
                return 1

        cmd = [str(bin_path), "--listen", args.listen]
        if args.user: cmd.extend(["--user", args.user, "--pass", args.password])
        if args.verbose: cmd.append("-v")

        log.info(f"Starting SOCKS5 proxy on {args.listen}")
        try: subprocess.run(cmd)
        except KeyboardInterrupt: log.warn("Stopped.")
        return 0
