from __future__ import annotations

import json
import os
from pathlib import Path

from fsociety.core.base import tool, all_tools
from fsociety.core.logger import Log
from fsociety.core.output import table

CHEATSHEET = {
    "recon": [
        ("host discovery", "nmap -sn 10.0.0.0/24"),
        ("port scan", "nmap -sS -p- --min-rate 1000 -Pn 10.0.0.5"),
        ("service scan", "nmap -sV -sC -p 1-10000 10.0.0.5"),
        ("vhost discovery", "ffuf -u http://host -H 'Host: FUZZ.host' -w vhosts.txt"),
    ],
    "web": [
        ("directory bust", "ffuf -u http://host/FUZZ -w wordlist.txt"),
        ("param fuzz", "arjun -u http://host/page"),
        ("screenshot", "gowitness single -u http://host"),
        ("burp proxy", "burpsuite --project=myproj"),
    ],
    "cred": [
        ("hashid", "hashid 'hash'"),
        ("crack with rules", "fsociety crackx 'hash' -w rockyou.txt -r digit -r leeto"),
        ("password spray", "fsociety brutal spray http://login --userlist users.txt --password 'Spring2024!'"),
    ],
    "linux": [
        ("linpeas", "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh"),
        ("suid sweep", "find / -perm -4000 -type f 2>/dev/null"),
        ("sudo audit", "sudo -l"),
        ("capabilities", "getcap -r / 2>/dev/null"),
    ],
    "notes": [
        ("tmux cheat", "ctrl-b + c new, ctrl-b + n next, ctrl-b + d detach"),
        ("keep it clean", "log every command with `script -a session.log`"),
    ],
}

@tool("noobsec", "Onboarding menu, cheatsheets, and guided walkthroughs", category="education")
class Noobsec:
    @staticmethod
    def build_parser(p):
        sub = p.add_subparsers(dest="cmd", required=True)

        menu = sub.add_parser("menu", help="print tool menu grouped by category")
        menu.add_argument("--category")

        sheet = sub.add_parser("cheatsheet", help="print handy commands")
        sheet.add_argument("--topic", choices=list(CHEATSHEET) + ["all"], default="all")

        walk = sub.add_parser("walkthrough", help="step-by-step first engagement")
        walk.add_argument("--target", required=True)
        walk.add_argument("--out")

        check = sub.add_parser("check", help="verify environment and installed deps")

    @staticmethod
    def _menu(category):
        entries = all_tools()
        if category:
            entries = [t for t in entries if t.category == category]
        rows = [(t.name, t.category, t.summary) for t in entries]
        print(table(rows, ["TOOL", "CATEGORY", "SUMMARY"]))
        return 0

    @staticmethod
    def _cheatsheet(topic):
        topics = list(CHEATSHEET) if topic == "all" else [topic]
        for t in topics:
            print(f"\n== {t} ==")
            for label, cmd in CHEATSHEET[t]:
                print(f"  {label:<24} {cmd}")
        return 0

    @staticmethod
    def _walk(target, out):
        steps = [
            ("1. finger", f"nmap -sn -PR {target}"),
            ("2. top ports", f"nmap -sS -Pn -p 1-10000 --min-rate 1000 {target}"),
            ("3. full ports", f"nmap -sS -Pn -p- --min-rate 5000 {target}"),
            ("4. services", f"nmap -sV -sC -p <ports> {target}"),
            ("5. web head", f"curl -sI http://{target}"),
            ("6. paths", f"fsociety fuzza http://{target}/ --paths -t 20"),
            ("7. check TLS", f"nmap -p443 --script ssl-enum-ciphers {target}"),
            ("8. host osint", "whois, dig, crt.sh lookup"),
            ("9. note", "record every finding before moving on"),
        ]
        for label, cmd in steps:
            print(f"{label:<18} {cmd}")
        if out:
            Path(out).write_text(json.dumps(steps, indent=2))
        return 0

    @staticmethod
    def _check():
        import shutil
        deps = ["python3", "nmap", "curl", "openssl", "git", "objdump"]
        rows = []
        for dep in deps:
            rows.append((dep, shutil.which(dep) or "MISSING"))
        print(table(rows, ["DEP", "STATUS"]))
        return 0

    @staticmethod
    def run(args, log: Log) -> int:
        if args.cmd == "menu":
            return Noobsec._menu(args.category)
        if args.cmd == "cheatsheet":
            return Noobsec._cheatsheet(args.topic)
        if args.cmd == "walkthrough":
            return Noobsec._walk(args.target, args.out)
        if args.cmd == "check":
            return Noobsec._check()
        return 2
