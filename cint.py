import os
import sys
import subprocess
import shutil

CYAN = "\033[1;36m"
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

# ---------- COMMAND DEFINITIONS ----------

PHANTOMFS_COMMANDS = {
    "scan": "scan -root /path [-max-depth N] [-min-size B] [-workers N] [-json]",
    "hidden": "hidden -root /path [-json]",
    "dupes": "dupes -root /path [-json]",
    "watch": "watch -root /path [-mode auto|poll|inotify] [-poll 2s] [-json]",
    "tree": "tree -root /path",
    "classify": "classify -root /path [-json]",
    "recover": "recover -root /path",
    "snapshot": "snapshot -root /path [-out snapshot.phfs]",
    "diff": "diff -old old.phfs -new new.phfs [-json]",
    "carve": "carve -file disk.img [-out carved/] [-json]",
    "perm": "perm -root /path [-json]",
    "entropy": "entropy -root /path [-block 4096] [-min 7.0] [-json]",
    "dedup": "dedup -root /path [-min 512] [-avg 4096] [-max 65536] [-json]",
    "bloom": "bloom -root /path [-check-file path] [-check-hash hex] [-fp 0.001] [-json]",
    "hash": "hash -file path [-json]",
    "magic": "magic -file path [-json]",
}

UNIVERSE_COMMANDS = {
    "osintcore": "osintcore -target <indicator>",
    "geoint": "geoint -ip <ip> | -coords lat,lon | -image photo.jpg",
    "domaintrace": "domaintrace -domain example.com",
    "ipintel": "ipintel -ip 1.1.1.1",
    "userfinder": "userfinder -user <username>",
    "mailtrace": "mailtrace -email user@example.com",
    "phototrace": "phototrace -file image.jpg [-deep]",
    "socialmap": "socialmap -user <username>",
    "linktrace": "linktrace -url https://example.com",
    "metatrack": "metatrack -file <file>",
    "breachwatch": "breachwatch -email user@example.com | -domain example.com",
    "darkintel": "darkintel -ioc <ioc> | -feed urlhaus|threatfox|feodo",
    "certtrace": "certtrace -domain example.com",
    "geoarchive": "geoarchive -coords lat,lon | -place <place>",
    "entitylink": "entitylink -target <target>",
    "memoryx": "memoryx -file memory.dump [-min 6]",
    "binarycore": "binarycore -file sample.exe",
    "evidencevault": "evidencevault init -vault ./case01",
    "timelinex": "timelinex -in file1.json,file2.jsonl",
    "intelgraph": "intelgraph -in report1.json,report2.json -format dot -out graph.dot",
    "shadowtrace": "shadowtrace -target <target>",
    "ghostint": "ghostint -ioc <ioc> [-feed all]",
    "entityx": "entityx -in file1.txt,file2.json [-min 2]",
    "geocrypt": "geocrypt -coords lat,lon [-from <from> -to <to>]",
    "ipnexus": "ipnexus -ip 8.8.8.8",
    "domainx": "domainx -domain example.com",
    "identrace": "identrace -user <user> [-email user@example.com]",
    "mailscope": "mailscope -file message.eml",
    "photontrace": "photontrace -url <url> | -file image.jpg -compare other.jpg",
    "forensix": "forensix [-root ~] [-recent-days 7]",
    "malshield": "malshield -file sample.exe",
    "packetx": "packetx -file capture.pcap",
    "vulnintel": "vulnintel cve -id CVE-2024-3094",
    "certnexus": "certnexus -domain example.com",
    "l1xcore": "l1xcore -target <target>",
    "webcrawl": "webcrawl -seed https://example.com [-depth 3] [-pages 100]",
    "subdomx": "subdomx -domain example.com [-resolve]",
    "hashcrack": "hashcrack -hash <hash> -wordlist <file> [-rules]",
    "portx": "portx -target <target> [-ports top|full|1-1024|22,80]",
    "wifi": "wifi -file capture.pcap",
}

OBSIDIAN_COMMANDS = {
    "intel": "intel [-file iocs.txt] | -ioc <ioc> [-out report.json]",
    "malscope": "malscope -file sample.bin [-yara custom.yara] [-out report.json]",
    "dfir": "dfir [-root /] [-out report.json]",
    "asm": "asm -domain example.com [-full-ports] [-out report.json]",
    "wsa": "wsa -url https://target.example [-inject] [-takeover] [-out report.json]",
    "pcap": "pcap -file capture.pcap [-out report.json]",
    "cryptan": "cryptan id -hash <hash> | crack | jwt | encrypt | decrypt | freq | xor | vig | rsa | ecb",
    "sysaudit": "sysaudit [-root /] [-out report.json]",
    "phish": "phish -url https://suspicious.example [-out report.json]",
    "vulnintel": "vulnintel cve -id CVE-2024-3094 | vulnintel packages",
}

CINT_TOOLS = {
    "phantomfs": {"desc": "Filesystem intelligence (16 cmds)", "commands": PHANTOMFS_COMMANDS},
    "universe": {"desc": "OSINT / Forensics / Net (40 tools)", "commands": UNIVERSE_COMMANDS},
    "obsidian": {"desc": "Security toolkit (10 tools)", "commands": OBSIDIAN_COMMANDS},
    "l1ghtxr": {"desc": "Alternate cyber CLI (10 tools)", "commands": OBSIDIAN_COMMANDS},
}

# ---------- DEPENDENCY CHECK ----------

def check_deps():
    if not shutil.which("go"):
        print(f"{RED}[!] Go toolchain not found. Install Go 1.21+.{RESET}")
        print(f"{GRAY}    Termux: pkg install golang{RESET}")
        return False
    return True

# ---------- REPO + BUILD ----------

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
        r = subprocess.run(
            ["go", "build", "-ldflags=-s -w", "-o", out, path],
            cwd=CINT_DIR, capture_output=True, text=True,
        )

        # Fallback for alternate layout
        if r.returncode != 0:
            r = subprocess.run(
                ["go", "build", "-ldflags=-s -w", "-o", out, f"./{name}"],
                cwd=CINT_DIR, capture_output=True, text=True,
            )

        if r.returncode != 0:
            print(f"{RED}[!] Build failed for {name}:{RESET}")
            print(f"{GRAY}{r.stderr}{RESET}")
            return False

    return True

# ---------- TOOL EXECUTION ----------

def run_tool(binary, args):
    bin_path = os.path.join(CINT_DIR, "bin", binary)
    if not os.path.exists(bin_path):
        print(f"{RED}[!] Binary {binary} not built.{RESET}")
        return
    subprocess.run([bin_path] + args)

# ---------- MENU RENDERING ----------

def render_cint_menu():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(CINT_BANNER)
    print(f"\n{CYAN}╔══════════════════════════════════════════════════════════════╗")
    print(f"║ {WHITE}CINT — MODULE SELECTOR{RESET}                                      {CYAN}║")
    print(f"╠══════════════════════════════════════════════════════════════╣")
    for i, (name, info) in enumerate(CINT_TOOLS.items(), 1):
        print(f"║ {GREEN}[{i:02d}]{RESET} {name:<12} - {info['desc']:<40} {CYAN}║")
    print(f"║ {GRAY}[B]{RESET}  Back to R3CON                                          {CYAN}║")
    print(f"╚══════════════════════════════════════════════════════════════╝{RESET}")


def render_tool_menu(tool_name, tool_info):
    os.system('cls' if os.name == 'nt' else 'clear')
    print(CINT_BANNER)
    print(f"\n{CYAN}╔══════════════════════════════════════════════════════════════╗")
    print(f"║ {WHITE}{tool_name.upper()} — {tool_info['desc']}{RESET}")
    print(f"╠══════════════════════════════════════════════════════════════╣")

    cmds = list(tool_info["commands"].items())
    for name, usage in cmds:
        # Keep single line, truncate usage to fit
        short = usage[:50]
        print(f"║ {GREEN}{name:<14}{RESET} \033[90m{short:<50}\033[0m {CYAN}║")

    print(f"╚══════════════════════════════════════════════════════════════╝{RESET}")
    print(f"\n\033[92m[Q]\033[0m Back to CINT menu | Type a command + args to execute.")
    print(f"\033[90mExample:\033[0m {list(tool_info['commands'].keys())[0]} --help")

# ---------- INTERACTIVE ----------

def tool_interface(tool_name):
    tool_info = CINT_TOOLS[tool_name]

    while True:
        render_tool_menu(tool_name, tool_info)
        try:
            raw = input(f"\n{GREEN}{tool_name}~#{RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if raw.lower() in ("q", "back", "exit", "b"):
            break
        if not raw:
            continue

        parts = raw.split()
        cmd = parts[0]
        args = parts[1:]

        # Allow direct execution of any command
        run_tool(tool_name, [cmd] + args)
        input(f"\n{GRAY}Press Enter to return to {tool_name} menu...{RESET}")


def cint_menu():
    while True:
        render_cint_menu()
        try:
            choice = input(f"\n{GREEN}root@cint:~#{RESET} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if choice in ("q", "exit", "b", "back"):
            break

        # Numbered selection
        if choice.isdigit():
            idx = int(choice) - 1
            keys = list(CINT_TOOLS.keys())
            if 0 <= idx < len(keys):
                tool_interface(keys[idx])
            else:
                print(f"{RED}[!] Invalid selection.{RESET}")
                input("Press Enter to continue...")
        else:
            # Direct command: "phantomfs scan -root /tmp"
            parts = choice.split()
            if parts and parts[0] in CINT_TOOLS:
                tool_name = parts[0]
                if len(parts) == 1:
                    tool_interface(tool_name)
                else:
                    run_tool(tool_name, parts[1:])
                    input(f"\n{GRAY}Press Enter to return...{RESET}")

# ---------- ENTRY POINT ----------

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
        binary = sys.argv[1]
        if binary in CINT_TOOLS:
            run_tool(binary, sys.argv[2:])
        else:
            print(f"{RED}[!] Unknown CINT binary: {binary}{RESET}")
            sys.exit(1)
    else:
        cint_menu()

if __name__ == "__main__":
    main()
