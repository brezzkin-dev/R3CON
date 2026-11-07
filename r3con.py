#!/usr/bin/env python3
"""
R3CON — entry point.
Platform gate -> root gate -> root-aware menu -> dispatch.
"""
import os
import sys
import time
import platform
import subprocess
import importlib
from pathlib import Path

# ---------- ANSI ----------
RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"


def banner():
    print(f"""{RED}{BOLD}
██████╗ ██████╗  ██████╗ ██████╗ ███╗   ██╗
██╔══██╗╚════██╗██╔════╝██╔═══██╗████╗  ██║
██████╔╝ █████╔╝██║     ██║   ██║██╔██╗ ██║
██╔══██╗ ╚═══██╗██║     ██║   ██║██║╚██╗██║
██║  ██║██████╔╝╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
    {CYAN}ollie's bench — R3CON build{RESET}
""")


def detect_platform():
    sysname = platform.system().lower()
    if "android" in sysname or "ANDROID_ROOT" in os.environ:
        return "ANDROID"
    if sysname in ("linux", "darwin", "windows"):
        return "PC"
    return "PC"


def ask_platform():
    print(f"{BOLD}Choose platform:{RESET}")
    print(f"  {GREEN}[1]{RESET} ANDROID")
    print(f"  {GREEN}[2]{RESET} PC")
    while True:
        raw = input(f"{CYAN}platform > {RESET}").strip()
        if raw == "1":
            return "ANDROID"
        if raw == "2":
            return "PC"
        print(f"{RED}1 or 2, boss.{RESET}")


def is_rooted_android():
    if platform.system().lower() != "linux":
        return False
    try:
        out = subprocess.run(
            ["id", "-u"], capture_output=True, text=True, timeout=2
        ).stdout.strip()
        if out == "0":
            return True
    except Exception:
        pass
    for p in ("/system/xbin/su", "/system/bin/su", "/sbin/su", "/su/bin/su"):
        if os.path.exists(p):
            return True
    try:
        if subprocess.run(["which", "su"], capture_output=True, timeout=2).returncode == 0:
            return True
    except Exception:
        pass
    return False


def ask_rooted():
    print(f"{BOLD}Is this Android device rooted?{RESET}")
    print(f"  {GREEN}[1]{RESET} rooted")
    print(f"  {GREEN}[2]{RESET} not rooted")
    while True:
        raw = input(f"{CYAN}root > {RESET}").strip()
        if raw == "1":
            return True
        if raw == "2":
            return False
        print(f"{RED}1 or 2, boss.{RESET}")


# ---------- tool registry ----------
# module: dotted path. entry: callable name. requires_root: bool.
# platforms: subset of {"ANDROID","PC"}.

TOOLS = [
    {"key": "1", "name": "fsociety",       "module": "fsociety.fsociety",       "entry": "main", "requires_root": False, "platforms": {"ANDROID", "PC"}},
    {"key": "2", "name": "CINT",           "module": "CINT.cint",               "entry": "main", "requires_root": False, "platforms": {"ANDROID", "PC"}},
    {"key": "3", "name": "MC-KILLER",      "module": "MC_KILLER.mc_killer",     "entry": "main", "requires_root": False, "platforms": {"ANDROID", "PC"}},
    {"key": "4", "name": "PAYLOADFORGE",   "module": "PAYLOADFORGE.payloadforge","entry": "main", "requires_root": False, "platforms": {"ANDROID", "PC"}},
    {"key": "5", "name": "SCAMBLR",        "module": "SCAMBLR.scamblr",         "entry": "main", "requires_root": False, "platforms": {"ANDROID", "PC"}},
    {"key": "6", "name": "FLOOD (DDoS/DoS)","module": "FLOOD.flood_entry",      "entry": "main", "requires_root": False, "platforms": {"ANDROID", "PC"}},
    {"key": "7", "name": "ROOTKIT-SIM",    "module": "ROOTKIT_SIM.rootkit_sim", "entry": "main", "requires_root": True,  "platforms": {"ANDROID", "PC"}},
    {"key": "8", "name": "PCAP-CAPTURE",   "module": "PCAP_CAPTURE.pcap_capture","entry": "main", "requires_root": True, "platforms": {"ANDROID", "PC"}},
]


def visible_tools(plat, rooted):
    out = []
    for t in TOOLS:
        if plat not in t["platforms"]:
            continue
        if t["requires_root"] and not rooted:
            continue
        out.append(t)
    return out


def render_menu(tools, plat, rooted):
    tag = f"{GREEN}rooted{RESET}" if rooted else f"{YELLOW}non-root{RESET}"
    print(f"\n{BOLD}R3CON // platform={CYAN}{plat}{RESET} // {tag}")
    print(f"{DIM}----------------------------------------{RESET}")
    for t in tools:
        lock = f" {RED}[root]{RESET}" if t["requires_root"] else ""
        print(f"  {GREEN}[{t['key']}]{RESET} {t['name']}{lock}")
    print(f"  {GREEN}[0]{RESET} exit")
    print(f"  {GREEN}[99]{RESET} self-test (count 1..300)")
    print(f"{DIM}----------------------------------------{RESET}")


def run_self_test():
    print(f"{CYAN}self-test: counting 1..300{RESET}")
    t0 = time.time()
    for i in range(1, 301):
        print(f"  [{i:03d}] ok")
    dt = time.time() - t0
    print(f"{GREEN}done — 300/300 in {dt:.2f}s{RESET}")


def dispatch(tool):
    try:
        mod = importlib.import_module(tool["module"])
    except ImportError as e:
        print(f"{RED}module missing: {tool['module']} ({e}){RESET}")
        return
    fn = getattr(mod, tool["entry"], None)
    if not callable(fn):
        print(f"{RED}entry not found: {tool['module']}.{tool['entry']}{RESET}")
        return
    try:
        fn()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}aborted{RESET}")


def main():
    banner()
    plat = ask_platform()
    rooted = False
    if plat == "ANDROID":
        rooted = ask_rooted()
        # if the user says rooted but we can't see su, still honor their word
        # (they may run it via tsu/termux-sudo)
    tools = visible_tools(plat, rooted)
    by_key = {t["key"]: t for t in tools}
    while True:
        render_menu(tools, plat, rooted)
        raw = input(f"{CYAN}r3con > {RESET}").strip()
        if raw in ("0", "q", "exit"):
            print(f"{DIM}fridge hum off. {RESET}")
            return
        if raw == "99":
            run_self_test()
            continue
        t = by_key.get(raw)
        if not t:
            print(f"{RED}no such slot, boss.{RESET}")
            continue
        dispatch(t)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}bench lights off.{RESET}")
