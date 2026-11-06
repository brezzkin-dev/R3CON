from __future__ import annotations

import os
import pwd
import shutil
import subprocess
from pathlib import Path

from fsociety.core.base import tool
from fsociety.core.logger import Log
from fsociety.core.output import dump_json

GTFOBINS = {
    "bash": "bash -p",
    "sh": "sh -p",
    "python": "python -c 'import os; os.system(\"/bin/sh\")'",
    "python3": "python3 -c 'import os; os.system(\"/bin/sh\")'",
    "perl": "perl -e 'exec \"/bin/sh\";'",
    "ruby": "ruby -e 'exec \"/bin/sh\"'",
    "vim": "vim -c ':!/bin/sh'",
    "vi": "vi -c ':!/bin/sh'",
    "nano": "nano -s /bin/sh",
    "find": "find . -exec /bin/sh -p \\; -quit",
    "awk": "awk 'BEGIN {system(\"/bin/sh\")}'",
    "less": "less /etc/passwd then !/bin/sh",
    "more": "more /etc/passwd then !/bin/sh",
    "man": "man man then !/bin/sh",
    "tar": "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
    "cp": "cp /bin/sh /tmp/sh && chmod +s /tmp/sh",
    "mv": "mv /bin/sh /tmp/x && chmod +s /tmp/x",
    "tee": "echo cmVhbGx5Cg== | base64 -d | tee /bin/sh",
    "chmod": "chmod +s /bin/sh",
    "chown": "chown root:root /bin/sh",
    "env": "env /bin/sh",
    "nmap": "nmap --interactive then !sh",
    "git": "git help config then !sh",
    "ftp": "ftp then !/bin/sh",
    "gdb": "gdb -nx -ex '!sh' -ex quit",
    "mysql": "mysql -e '\\! /bin/sh'",
    "sqlite3": "sqlite3 /dev/null '.shell /bin/sh'",
    "dd": "dd if=/dev/zero of=/tmp/sh bs=1 count=0",
}

SUDO_RISKY = [
    "NOPASSWD", "env_keep+=", "SETENV", "!authenticate", "ALL", "SETENV:",
    "LD_PRELOAD", "LD_LIBRARY_PATH",
]

@tool("rootx", "Privilege audit: sudo, SUID, groups, writable service units", category="privilege")
class Rootx:
    @staticmethod
    def build_parser(p):
        p.add_argument("--sudo", action="store_true", help="run 'sudo -l' and summarize")
        p.add_argument("--suid", action="store_true", help="enumerate SUID binaries")
        p.add_argument("--gtfobins", action="store_true", help="match SUID files against GTFOBINS")
        p.add_argument("--groups", action="store_true", help="current user groups")
        p.add_argument("--services", action="store_true", help="writable systemd unit files")
        p.add_argument("--env", action="store_true", help="interesting environment variables")
        p.add_argument("--kernel", action="store_true", help="kernel version and sysctl highlights")
        p.add_argument("--all", action="store_true")
        p.add_argument("-o", "--out", help="write JSON report")

    @staticmethod
    def _sudo():
        if not shutil.which("sudo"):
            return {"error": "sudo not installed"}
        try:
            out = subprocess.run(["sudo", "-n", "-l"], capture_output=True, text=True, timeout=15)
        except (subprocess.SubprocessError, OSError) as exc:
            return {"error": str(exc)}
        lines = [l for l in (out.stdout or "").splitlines() + (out.stderr or "").splitlines() if l.strip()]
        hits = [l for l in lines if any(token in l for token in SUDO_RISKY)]
        return {"raw": lines, "risky": hits}

    @staticmethod
    def _suid():
        hits = []
        for base in ("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin",
                     "/usr/local/sbin", "/opt", "/tmp"):
            root = Path(base)
            if not root.exists():
                continue
            for path in root.rglob("*"):
                try:
                    st = path.stat()
                except OSError:
                    continue
                if st.st_mode & 0o4000 or st.st_mode & 0o2000:
                    hits.append({"path": str(path),
                                 "perm": oct(st.st_mode & 0o7777),
                                 "owner": pwd.getpwuid(st.st_uid).pw_name})
        return hits

    @staticmethod
    def _gtfobins(suid_entries):
        matches = []
        for entry in suid_entries:
            name = Path(entry["path"]).name
            if name in GTFOBINS:
                matches.append({"path": entry["path"], "hint": GTFOBINS[name]})
        return matches

    @staticmethod
    def _groups():
        groups = []
        try:
            import grp
            gids = os.getgroups()
            for gid in gids:
                try:
                    groups.append(grp.getgrgid(gid).gr_name)
                except KeyError:
                    groups.append(str(gid))
        except Exception:
            pass
        return {"uid": os.getuid(), "euid": os.geteuid(),
                "user": pwd.getpwuid(os.getuid()).pw_name,
                "groups": groups}

    @staticmethod
    def _services():
        hits = []
        for base in ("/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"):
            root = Path(base)
            if not root.exists():
                continue
            for unit in root.glob("*.service"):
                try:
                    if os.access(unit, os.W_OK):
                        hits.append(str(unit))
                except OSError:
                    continue
        return hits

    @staticmethod
    def _env():
        watched = ("PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH",
                   "PERL5LIB", "RUBYLIB", "BASH_ENV", "ENV", "PS4")
        return {k: os.environ[k] for k in watched if k in os.environ}

    @staticmethod
    def _kernel():
        info = {}
        try:
            info["release"] = os.uname().release
        except AttributeError:
            info["release"] = ""
        interesting = ["kernel.unprivileged_bpf_disabled", "kernel.dmesg_restrict",
                       "kernel.kptr_restrict", "kernel.yama.ptrace_scope",
                       "net.ipv4.ip_forward", "fs.protected_symlinks",
                       "fs.protected_hardlinks"]
        found = {}
        for key in interesting:
            try:
                with open(f"/proc/sys/{key.replace('.', '/')}", "r") as fh:
                    found[key] = fh.read().strip()
            except OSError:
                continue
        info["sysctl"] = found
        return info

    @staticmethod
    def run(args, log: Log) -> int:
        do = lambda flag: flag or args.all
        report = {}
        suid = None

        if do(args.groups):
            report["groups"] = Rootx._groups()
            log.ok(f"user={report['groups']['user']} groups={report['groups']['groups']}")

        if do(args.suid):
            suid = Rootx._suid()
            report["suid"] = suid
            log.ok(f"suid/sgid: {len(suid)}")

        if do(args.gtfobins):
            if suid is None:
                suid = Rootx._suid()
            report["gtfobins"] = Rootx._gtfobins(suid)
            log.ok(f"gtfobins matches: {len(report['gtfobins'])}")

        if do(args.sudo):
            report["sudo"] = Rootx._sudo()
            log.ok(f"sudo risky lines: {len(report['sudo'].get('risky', []))}")

        if do(args.services):
            report["services"] = Rootx._services()
            log.ok(f"writable units: {len(report['services'])}")

        if do(args.env):
            report["env"] = Rootx._env()
            log.ok(f"env hits: {len(report['env'])}")

        if do(args.kernel):
            report["kernel"] = Rootx._kernel()
            log.ok(f"kernel={report['kernel']['release']}")

        if args.out:
            dump_json(report, args.out)
            log.info(f"written: {args.out}")
        else:
            import json
            print(json.dumps(report, indent=2, default=str))
        return 0
