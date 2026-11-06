import os
import sys
import time
import subprocess

try:
    from fsociety.core.splash import show_splash
    from fsociety.core.menu import interactive_menu
    FSOCIETY_AVAILABLE = True
except ImportError:
    FSOCIETY_AVAILABLE = False

CYAN = "\033[1;36m"
GRAY = "\033[90m"
WHITE = "\033[97m"
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

R3CON_BANNER = rf"""{CYAN}
██████╗ ██████╗  ██████╗ ██████╗ ███╗   ██╗
██╔══██╗╚════██╗██╔════╝██╔═══██╗████╗  ██║
██████╔╝ █████╔╝██║     ██║   ██║██╔██╗ ██║
██╔══██╗ ╚═══██╗██║     ██║   ██║██║╚██╗██║
██║  ██║██████╔╝╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{RESET}
{WHITE}Author: L1ghtXr | Contributor: DevBrezz{RESET}
{GRAY}All-in-One Offensive Security Framework{RESET}
"""

def launch_fsociety():
    if not FSOCIETY_AVAILABLE:
        print(f"\n{RED}[!] F-SOCIETY core modules not found.{RESET}")
        print(f"{GRAY}    Ensure the 'fsociety' directory exists in the same folder as r3con.py.{RESET}")
        input(f"\n{GRAY}Press Enter to return...{RESET}")
        return
    show_splash()
    interactive_menu()
    print(f"\n{GRAY}[*] Closing F-SOCIETY, returning to R3CON...{RESET}")
    time.sleep(1)

def launch_cint():
    cint_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cint.py")
    if not os.path.exists(cint_path):
        print(f"\n{RED}[!] cint.py not found in R3CON root.{RESET}")
        input(f"\n{GRAY}Press Enter to return...{RESET}")
        return
    subprocess.run([sys.executable, cint_path])
    print(f"\n{GRAY}[*] Closing CINT, returning to R3CON...{RESET}")
    time.sleep(1)

def main_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(R3CON_BANNER)
        print(f"{CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║ {WHITE}AVAILABLE TOOLKITS{RESET}                                          {CYAN}║")
        print(f"╠══════════════════════════════════════════════════════════════╣")
        print(f"║ {GREEN}[01]{RESET} F-SOCIETY - Network & Exploitation Suite           {CYAN}║")
        print(f"║ {GREEN}[02]{RESET} CINT      - Cyber Intelligence Toolkit (Go)        {CYAN}║")
        print(f"║ {GRAY}[03] CLINT     - Coming Soon...{RESET}                             {CYAN}║")
        print(f"║ {GRAY}[04] ...       - Coming Soon...{RESET}                             {CYAN}║")
        print(f"╚══════════════════════════════════════════════════════════════╝{RESET}")

        choice = input(f"\n{GREEN}root@r3con:~#{RESET} ").strip()

        if choice == "1":
            launch_fsociety()
        elif choice == "2":
            launch_cint()
        elif choice.lower() in ("q", "exit"):
            print(f"\n{GRAY}[*] Exiting R3CON...{RESET}")
            sys.exit(0)

if __name__ == "__main__":
    main_menu()
