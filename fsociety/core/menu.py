import os
import sys
import subprocess
from fsociety.core import base
from fsociety.core.splash import ALIAS_BANNER


def render_menu():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(ALIAS_BANNER)
    print("\n")

    from fsociety.cli import get_load_errors
    errors = get_load_errors()
    tools = base.all_tools()

    print(f"\033[96m╔══════════════════════════════════════════════════════════════════════════════╗")
    print(f"║ \033[97mF-SOCIETY — {len(tools)} TOOLS LOADED\033[96m")
    print(f"╠══════════════════════════════════════════════════════════════════════════════╣\033[0m")

    if tools:
        col_len = (len(tools) + 2) // 3
        cols = [tools[i:i + col_len] for i in range(0, len(tools), col_len)]
        for i in range(col_len):
            line = "  "
            for col in cols:
                if i < len(col):
                    t = col[i]
                    line += f"\033[95m[{t.name[:12]:<12}]\033[0m \033[90m{t.category[:15]:<15}\033[0m | "
                else:
                    line += " " * 32 + " | "
            print(line)

    print(f"\033[96m╚══════════════════════════════════════════════════════════════════════════════╝\033[0m")

    if errors:
        print(f"\n\033[91m[!] {len(errors)} TOOL(S) FAILED TO LOAD:\033[0m")
        for name, err in errors:
            short = err if len(err) < 100 else err[:100] + "..."
            print(f"    \033[93m{name}\033[0m: {short}")
        print("\033[90mRun 'fsociety --doctor' for full tracebacks.\033[0m")

    print("\n\033[92m[Q]\033[0m Quit | \033[92m[D]\033[0m Doctor | Type a tool name or full command.")


def interactive_menu():
    from fsociety.cli import load_tools
    load_tools()

    while True:
        render_menu()
        try:
            cmd_input = input("\n\033[92mroot@fsociety:~#\033[0m ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if cmd_input.lower() in ("q", "exit", "back"):
            break

        if cmd_input.lower() in ("d", "doctor"):
            subprocess.run([sys.executable, "-m", "fsociety", "--doctor"])
            input("\nPress Enter to return...")
            continue

        if cmd_input.startswith("fsociety "):
            cmd_input = cmd_input[9:]

        parts = cmd_input.split()
        if not parts:
            continue

        tool_name = parts[0]
        entry = base.resolve(tool_name)

        if entry:
            if len(parts) == 1:
                os.system('cls' if os.name == 'nt' else 'clear')
                print(f"\033[96m=== F-SOCIETY: {entry.name.upper()} ===\033[0m\n")
                print(f"\033[90m{entry.summary}\033[0m\n")
                subprocess.run([sys.executable, "-m", "fsociety", entry.name, "--help"])
                print(f"\n\033[92mTo run: {entry.name} <args>\033[0m")
                input("\nPress Enter to return...")
            else:
                os.system('cls' if os.name == 'nt' else 'clear')
                print(f"\033[96m[*] Executing: fsociety {' '.join(parts)}\033[0m\n")
                try:
                    subprocess.run([sys.executable, "-m", "fsociety", *parts])
                except KeyboardInterrupt:
                    print("\n\033[93m[!] Interrupted.\033[0m")
                input("\nPress Enter to return...")
        else:
            print(f"\033[91m[!] Tool '{tool_name}' not found.\033[0m")
            if len(parts) > 1:
                print(f"\033[90mHint: the tool '{tool_name}' may have failed to load. Type 'D' to run doctor.\033[0m")
            input("Press Enter to continue...")
