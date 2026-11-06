import os
import sys
import subprocess
import shutil

CYAN = "\033[1;36m"
PURPLE = "\033[95m"
GRAY = "\033[90m"
WHITE = "\033[97m"
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

CINT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "CINT")

CINT_BANNER = rf"""{CYAN}
  ██████╗██╗███╗   ██╗████████╗
 ██╔════╝██║████╗  ██║╚══██╔══╝
 ██║     ██║██╔██╗ ██║   ██║   
 ██║     ██║██║╚██╗██║   ██║   
 ╚██████╗██║██║ ╚████║   ██║   
  ╚═════╝╚═╝╚═╝  ╚═══╝   ╚═╝   
{RESET}
{WHITE}Cyber Intelligence Toolkit{RESET}
{GRAY}RECON · ANALYZE · INVESTIGATE · DEFEND{RESET}
"""

def check_deps():
    if not shutil.which("go"):
        print(f"{RED}[!] Go toolchain not found. Install Go 1.21+.{RESET}")
        print(f"{GRAY}    Termux: pkg install golang{RESET}")
        return False
    return True

def ensure_repo():
    if not os.path.exists(CINT_DIR):
        print(f"{CYAN}[*] Cloning CINT repository...{RESET}")
        r = subprocess.run(
            ["git", "clone", "https://github.com/brezzkin-dev/CINT.git", CINT_DIR],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            print(f"{RED}[!] Clone failed: {r.stderr}{RESET}")
            return False
    return True

def build_binaries():
    bin_dir = os.path.join(CINT_DIR, "bin")
    os.makedirs(bin_dir, exist_ok=True)

    targets = {
        "phantomfs": "./cmd/phantomfs",
        "universe": "./cmd/universe",
        "obsidian": "./cmd/obsidian",
        "l1ghtxr": "./cmd/l1ghtxr",
    }

    for name, path in targets.items():
        out = os.path.join(bin_dir, name)
        if os.path.exists(out) and os.access(out, os.X_OK):
            continue
        
        print(f"{CYAN}[*] Building {name}...{RESET}")
        
        # Try standard cmd/ layout first
        r = subprocess.run(
            ["go", "build", "-ldflags=-s -w", "-o", out, path],
            cwd=CINT_DIR, capture_output=True, text=True,
        )
        
        # Fallback: try building from root of that folder if cmd/ structure doesn't exist
        if r.returncode != 0:
            path = f"./{name}"
            r = subprocess.run(
                ["go", "build", "-ldflags=-s -w", "-o", out, path],
                cwd=CINT_DIR, capture_output=True, text=True,
            )
            
        if r.returncode != 0:
            print(f"{RED}[!] Build failed for {name}:{RESET}")
            print(f"{GRAY}{r.stderr}{RESET}")
            return False

    return True

def run_tool(binary, args=None):
    bin_path = os.path.join(CINT_DIR, "bin", binary)
    if not os.path.exists(bin_path):
        print(f"{RED}[!] Binary {binary} not built.{RESET}")
        return

    if args:
        subprocess.run([bin_path] + args)
    else:
        subprocess.run([bin_path])

def interactive():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(CINT_BANNER)
        print(f"\n{CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║ {WHITE}AVAILABLE CINT MODULES{RESET}                                      {CYAN}║")
        print(f"╠══════════════════════════════════════════════════════════════╣")
        print(f"║ {GREEN}[01]{RESET} phantomfs  - Filesystem intelligence (16 cmds)    {CYAN}║")
        print(f"║ {GREEN}[02]{RESET} universe   - OSINT / Forensics / Net (40 tools){CYAN}║")
        print(f"║ {GREEN}[03]{RESET} obsidian   - Security toolkit (10 tools)          {CYAN}║")
        print(f"║ {GREEN}[04]{RESET} l1ghtxr    - Alternate cyber CLI (10 tools)       {CYAN}║")
        print(f"║ {GRAY}[B]{RESET}  Back to R3CON                                   {CYAN}║")
        print(f"╚══════════════════════════════════════════════════════════════╝{RESET}\n")

        choice = input(f"{GREEN}root@cint:~#{RESET} ").strip()

        if choice.lower() in ("b", "back", "q", "exit"):
            break
        elif choice == "1":
            run_tool("phantomfs")
            input(f"\n{GRAY}Press Enter to return...{RESET}")
        elif choice == "2":
            run_tool("universe")
            input(f"\n{GRAY}Press Enter to return...{RESET}")
        elif choice == "3":
            run_tool("obsidian")
            input(f"\n{GRAY}Press Enter to return...{RESET}")
        elif choice == "4":
            run_tool("l1ghtxr")
            input(f"\n{GRAY}Press Enter to return...{RESET}")
        else:
            # Allow direct command execution from within the menu
            parts = choice.split()
            if parts:
                binary = parts[0]
                if binary in ("phantomfs", "universe", "obsidian", "l1ghtxr"):
                    run_tool(binary, parts[1:])
                    input(f"\n{GRAY}Press Enter to return...{RESET}")

def main():
    if not check_deps():
        sys.exit(1)

    if not ensure_repo():
        sys.exit(1)

    print(f"{CYAN}[*] Preparing CINT binaries...{RESET}")
    if not build_binaries():
        sys.exit(1)

    print(f"{GREEN}[+] CINT is ready.{RESET}\n")

    if len(sys.argv) > 1:
        # Direct command mode: python3 cint.py universe domainx -domain example.com
        binary = sys.argv[1]
        if binary in ("phantomfs", "universe", "obsidian", "l1ghtxr"):
            run_tool(binary, sys.argv[2:])
        else:
            print(f"{RED}[!] Unknown CINT binary: {binary}{RESET}")
            sys.exit(1)
    else:
        interactive()

if __name__ == "__main__":
    main()
