from __future__ import annotations

import os
import pwd
import grp
import platform
import shutil
import socket
import stat
import subprocess
from pathlib import Path

from fsociety.core.base import tool
from fsociety.core.logger import Log
from fsociety.core.output import dump_json

CRON_DIRS = [Path("/etc/cron.d"), Path("/etc/cron.daily"), Path("/etc/cron.hourly"),
             Path("/etc/cron.weekly"), Path("/etc/cron.monthly")]
SENSITIVE = ["/etc/shadow", "/etc/passwd", "/etc/sudoers", "/root/.ssh",
             "/etc/ssh/sshd_config", "/var/log/auth.log"]

@tool("pwnix", "Linux host enumeration: SUID, caps, cron, writables, network", category="recon")
class Pwnix:
    @staticmethod
    def build_parser(p):
        p.add_argument("--root", default="/", help="filesystem root to scan")
        p.add_argument("--suid", action="store_true", help="find SUID/SGID binaries")
        p.add_argument("--caps", action="store_true", help="enumerate file capabilities")
        p.add_argument("--cron", action="store_true", help="inspect cron jobs")
        p.add_argument("--writable", action="store_true", help="world-writable files and dirs")
        p.add_argument("--network", action="store_true", help="list interfaces and listeners")
        p.add_argument("--sensitive", action="store_true", help="check sensitive file perms")
        p.add_argument("--all", action="store_true", help="run every module")
        p.add_argument("-o", "--out", help="write JSON report")

    @staticmethod
    def _suid(root: Path):
        hits = []
        for base, dirs, files in os.walk(root):
            if base.startswith(("/proc", "/sys", "/dev")):
                dirs[:] = []
                continue
            for name in files:
                path = Path(base) / name
                try:
                    st = path.lstat()
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                mode = st.st_mode
                if mode & stat.S_ISUID or mode & stat.S_ISGID:
                    try:
                        owner = pwd.getpwuid(st.st_uid).pw_name
                    except KeyError:
                        owner = str(st.st_uid)
                    hits.append({"path": str(path), "owner": owner,
                                 "suid": bool(mode & stat.S_ISUID),
                                 "sgid": bool(mode & stat.S_ISGID),
                                 "perm": oct(mode & 0o7777)})
        return hits

    @staticmethod
    def _caps(root: Path):
        if not shutil.which("getcap"):
            return []
        try:
            out = subprocess.run(["getcap", "-r", str(root)],
                                 capture_output=True, text=True, timeout=120)
        except (subprocess.SubprocessError, OSError):
            return []
        return [{"entry": line.strip()} for line in out.stdout.splitlines() if line.strip()]

    @staticmethod
    def _cron():
        hits = []
        for d in CRON_DIRS:
            if d.is_dir():
                for f in d.iterdir():
                    try:
                        hits.append({"file": str(f), "writable": os.access(f, os.W_OK)})
                    except OSError:
                        continue
        for candidate in (Path("/etc/crontab"), Path("/var/spool/cron")):
            if candidate.exists():
                hits.append({"file": str(candidate),
                             "writable": os.access(candidate, os.W_OK)})
        return hits

    @staticmethod
    def _writable(root: Path):
        dirs, files = [], []
        for base, subdirs, names in os.walk(root):
            if base.startswith(("/proc", "/sys", "/dev")):
                subdirs[:] = []
                continue
            for d in subdirs:
                path = Path(base) / d
                try:
                    if os.lstat(path).st_mode & stat.S_IWOTH:
                        dirs.append(str(path))
                except OSError:
                    continue
            for n in names:
                path = Path(base) / n
                try:
                    st = path.lstat()
                    if stat.S_ISREG(st.st_mode) and st.st_mode & stat.S_IWOTH:
                        files.append(str(path))
                except OSError:
                    continue
        return {"dirs": dirs[:500], "files": files[:500]}

    @staticmethod
    def _network():
        ifaces = []
        for idx, name in socket.if_nameindex():
            ifaces.append({"index": idx, "name": name})
        listeners = []
        for kind, path in (("tcp", "/proc/net/tcp"), ("tcp6", "/proc/net/tcp6"),
                           ("udp", "/proc/net/udp"), ("udp6", "/proc/net/udp6")):
            try:
                with open(path, "r") as fh:
                    next(fh)
                    for line in fh:
                        parts = line.split()
                        if len(parts) < 4:
                            continue
                        local = parts[1]
                        state = parts[3]
                        host_hex, port_hex = local.split(":")
                        port = int(port_hex, 16)
                        listeners.append({"proto": kind, "port": port,
                                          "state": state, "addr_hex": host_hex})
            except (OSError, StopIteration):
                continue
        return {"interfaces": ifaces, "sockets": listeners}

    @staticmethod
    def _sensitive():
        rows = []
        for spec in SENSITIVE:
            p = Path(spec)
            if not p.exists():
                continue
            try:
                st = p.stat()
                rows.append({"path": spec, "mode": oct(st.st_mode & 0o7777),
                             "uid": st.st_uid, "gid": st.st_gid})
            except OSError:
                continue
        return rows

    @staticmethod
    def run(args, log: Log) -> int:
        root = Path(args.root).resolve()
        report = {"host": platform.node(), "kernel": platform.release(),
                  "uid": os.getuid(), "gid": os.getgid(),
                  "root": str(root)}
        do = lambda flag: flag or args.all
        if do(args.suid):
            report["suid"] = Pwnix._suid(root)
            log.ok(f"suid/sgid: {len(report['suid'])}")
        if do(args.caps):
            report["caps"] = Pwnix._caps(root)
            log.ok(f"caps: {len(report['caps'])}")
        if do(args.cron):
            report["cron"] = Pwnix._cron()
            log.ok(f"cron entries: {len(report['cron'])}")
        if do(args.writable):
            report["writable"] = Pwnix._writable(root)
            log.ok(f"writable dirs={len(report['writable']['dirs'])} "
                   f"files={len(report['writable']['files'])}")
        if do(args.network):
            report["network"] = Pwnix._network()
            log.ok(f"sockets: {len(report['network']['sockets'])}")
        if do(args.sensitive):
            report["sensitive"] = Pwnix._sensitive()
            log.ok(f"sensitive files: {len(report['sensitive'])}")

        if args.out:
            dump_json(report, args.out)
            log.info(f"written: {args.out}")
        else:
            import json
            print(json.dumps(report, indent=2, default=str))
        return 0
