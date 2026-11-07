# FILE: r3con.py
#!/usr/bin/env python3
"""
R3CON — main menu and launcher.
Modules: fsociety, CINT, MC-KILLER, PAYLOADFORGE, SCAMBLR.
"""
from __future__ import annotations

import os
import sys
import time
import subprocess

BASE = os.path.dirname(os.path.abspath(__file__))

# ─── ANSI palette ──────────────────────────────────────────────────────────
CYAN = "\033[1;36m"
GRAY = "\033[90m"
WHITE = "\033[97m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

BANNER = rf"""{CYAN}
 ██████╗ ██████╗  ██████╗ ██████╗ ███╗   ██╗
 ██╔══██╗╚════██╗██╔════╝██╔═══██╗████╗  ██║
 ██████╔╝ █████╔╝██║     ██║   ██║██╔██╗ ██║
 ██╔══██╗ ╚═══██╗██║     ██║   ██║██║╚██╗██║
 ██║  ██║██████╔╝╚██████╗╚██████╔╝██║ ╚████║
 ╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{RESET}{WHITE}R3CON — Modular Offensive Toolkit{RESET}
{GRAY}recon · osint · payloads · floods · osint-in{RESET}
"""

# ─── helpers ───────────────────────────────────────────────────────────────

def clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def pause() -> None:
    input(f"\n{GRAY}Press Enter to return...{RESET}")


def launch(py_path: str, label: str) -> None:
    """Launch a python module in a subprocess, then return to R3CON."""
    if not os.path.exists(py_path):
        print(f"\n{RED}[!] {label} not found at {py_path}{RESET}")
        pause()
        return
    try:
        subprocess.run([sys.executable, py_path])
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        print(f"\n{RED}[!] {label} crashed: {exc}{RESET}")
        pause()
        return
    print(f"\n{GRAY}[*] Closing {label}, returning to R3CON...{RESET}")
    time.sleep(1)


# ─── module launchers ──────────────────────────────────────────────────────

def launch_fsociety():
    launch(os.path.join(BASE, "fsociety", "fsociety.py"), "FSOCIETY")


def launch_cint():
    launch(os.path.join(BASE, "CINT", "cint.py"), "CINT")


def launch_mc_killer():
    launch(os.path.join(BASE, "MC-KILLER", "mc_killer.py"), "MC-KILLER")


def launch_payloadforge():
    launch(os.path.join(BASE, "PAYLOADFORGE", "payloadforge.py"), "PAYLOADFORGE")


def launch_scamblr():
    launch(os.path.join(BASE, "SCAMBLR", "scamblr_entry.py"), "SCAMBLR")


# ─── menu ──────────────────────────────────────────────────────────────────

MENU_WIDTH = 64


def _line(text: str, color: str = WHITE, pad: int = MENU_WIDTH) -> str:
    # Visible length is text without ANSI codes; build padded row.
    import re
    visible = re.sub(r"\033\[[0-9;]*m", "", text)
    pad_n = max(0, pad - len(visible))
    return f"{CYAN}║{RESET} {color}{text}{RESET}{' ' * pad_n}{CYAN}║{RESET}"


def draw_menu() -> None:
    print(BANNER)
    print(f"{CYAN}╔{'═' * MENU_WIDTH}╗")
    print(_line("R3CON MAIN MENU", WHITE))
    print(f"{CYAN}╠{'═' * MENU_WIDTH}╣")
    print(_line("[01] FSOCIETY      - OSINT / recon framework", GREEN))
    print(_line("[02] CINT          - Contact intelligence", GREEN))
    print(_line("[03] MC-KILLER     - Minecraft server killer", GREEN))
    print(_line("[04] PAYLOADFORGE  - Payload gen + obfuscation", GREEN))
    print(_line("[05] SCAMBLR       - Anti-scammer attack toolkit", GREEN))
    print(_line("[06] ...           - Coming soon", GRAY))
    print(_line("[Q]  Quit", GRAY))
    print(f"{CYAN}╚{'═' * MENU_WIDTH}╝{RESET}")


# ─── main ──────────────────────────────────────────────────────────────────

def main() -> None:
    while True:
        clear()
        draw_menu()
        try:
            choice = input(f"\n{GREEN}r3con> {RESET}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if choice in ("1", "01", "fsociety"):
            launch_fsociety()
        elif choice in ("2", "02", "cint"):
            launch_cint()
        elif choice in ("3", "03", "mc-killer", "mckiller", "mc"):
            launch_mc_killer()
        elif choice in ("4", "04", "payloadforge", "pf"):
            launch_payloadforge()
        elif choice in ("5", "05", "scamblr", "sc"):
            launch_scamblr()
        elif choice in ("6", "06"):
            print(f"\n{YELLOW}[*] coming soon — the bench is still cooking{RESET}")
            time.sleep(1)
        elif choice in ("q", "quit", "exit"):
            break
        else:
            print(f"\n{RED}[!] unknown option: {choice}{RESET}")
            time.sleep(1)

    print(f"\n{CYAN}[*] R3CON signing off.{RESET}")


if __name__ == "__main__":
    main()
