import os
import sys
import time

# Import F-SOCIETY components directly
from fsociety.core.splash import show_splash
from fsociety.core.menu import interactive_menu

CYAN = "\033[1;36m"
PURPLE = "\033[95m"
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

def main_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(R3CON_BANNER)
        print(f"{CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║ {WHITE}AVAILABLE TOOLKITS{RESET}                                          {CYAN}║")
        print(f"╠══════════════════════════════════════════════════════════════╣")
        print(f"║ {GREEN}[01]{RESET} F-SOCIETY - Network & Exploitation Suite           {CYAN}║")
        print(f"║ {GRAY}[02] CLINT     - Coming Soon...{RESET}                             {CYAN}║")
        print(f"║ {GRAY}[03] ...       - Coming Soon...{RESET}                             {CYAN}║")
        print(f"╚══════════════════════════════════════════════════════════════╝{RESET}")
        
        choice = input(f"\n{GREEN}root@r3con:~#{RESET} ").strip()
        
        if choice == "1":
            launch_fsociety()
        elif choice.lower() in ("q", "exit"):
            print(f"\n{GRAY}[*] Exiting R3CON...{RESET}")
            sys.exit(0)

def launch_fsociety():
    # 1. Play the F-SOCIETY splash screen (Symbol -> Wordmark -> 6s Delay -> Clear)
    show_splash()
    
    # 2. Drop into the F-SOCIETY 3-Column Interactive Menu
    interactive_menu()
    
    # 3. Once the user quits F-SOCIETY (types 'Q'), it returns here
    print(f"\n{GRAY}[*] Closing F-SOCIETY, returning to R3CON...{RESET}")
    time.sleep(1)

if __name__ == "__main__":
    main_menu()
