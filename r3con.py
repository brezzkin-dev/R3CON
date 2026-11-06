import os
import sys
import time

from fsociety.core.splash import show_splash
from fsociety.core.menu import interactive_menu

CYAN = "\033[1;36m"
GRAY = "\033[90m"
WHITE = "\033[97m"
GREEN = "\033[92m"
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
    show_splash()
    interactive_menu()
    print(f"\n{GRAY}[*] Closing F-SOCIETY, returning to R3CON...{RESET}")
    time.sleep(1)

def main():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(R3CON_BANNER)
        print(f"{CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║ {WHITE}AVAILABLE TOOLKITS{RESET}                                          {CYAN}║")
        print(f"╠══════════════════════════════════════════════════════════════╣")
        print(f"║ {GREEN}[01]{RESET} F-SOCIETY - Network & Exploitation Suite           {CYAN}║")
        print(f"╚══════════════════════════════════════════════════════════════╝{RESET}")
        
        choice = input(f"\n{GREEN}root@r3con:~#{RESET} ").strip()
        
        if choice == "1":
            launch_fsociety()
        elif choice.lower() in ("q", "exit"):
            sys.exit(0)

if __name__ == "__main__":
    main()
