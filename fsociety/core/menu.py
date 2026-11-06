import os
import sys
import subprocess
from fsociety.core import base
from fsociety.core.splash import ALIAS_BANNER
from fsociety.core.logger import Log

def render_menu():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(ALIAS_BANNER)
    print("\n")
    
    # Get all registered tools
    tools = base.all_tools()
    
    if not tools:
        print("\033[91m[!] No tools detected.\033[0m")
        print("1. Check if 'fsociety/tools/__init__.py' exists.")
        print("2. Check if your tool files have the @tool decorator.")
    else:
        print(f"\033[96m╔══════════════════════════════════════════════════════════════════════════════╗")
        print(f"║ \033[97mF-SOCIETY — {len(tools)} TOOLS LOADED\033[96m                                        ║")
        print(f"╠══════════════════════════════════════════════════════════════════════════════╣\033[0m")
        
        # Split tools into 3 columns
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
        print("\n\033[92m[Q]\033[0m Quit \033[90m| Type a tool name for options, or a full command to execute.\033[0m")

def interactive_menu():
    # CRITICAL: Load tools into registry before rendering
    from fsociety.cli import load_tools
    errors = load_tools()
    for name, err in errors:
        print(f"\033[91m[import-fail] {name}: {err}\033[0m")

    while True:
        render_menu()
        try:
            cmd_input = input("\n\033[92mroot@fsociety:~#\033[0m ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
            
        if cmd_input.lower() in ("q", "exit", "back"):
            break

        # Strip 'fsociety ' prefix if the user typed it
        if cmd_input.startswith("fsociety "):
            cmd_input = cmd_input[9:]

        parts = cmd_input.split()
        if not parts:
            continue

        tool_name = parts[0]
        entry = base.resolve(tool_name)

        if entry:
            if len(parts) == 1:
                # User just typed the tool name -> show help
                os.system('cls' if os.name == 'nt' else 'clear')
                print(f"\033[96m=== F-SOCIETY: {entry.name.upper()} ===\033[0m\n")
                print(f"\033[90m{entry.summary}\033[0m\n")
                
                subprocess.run([sys.executable, "-m", "fsociety", entry.name, "--help"])
                
                print(f"\n\033[92mTo run: {entry.name} <args>\033[0m (or type 'back' to quit)")
                input("\nPress Enter to return to menu...")
            else:
                # User typed arguments -> execute the tool directly
                os.system('cls' if os.name == 'nt' else 'clear')
                print(f"\033[96m[*] Executing: fsociety {' '.join(parts)}\033[0m\n")
                try:
                    subprocess.run([sys.executable, "-m", "fsociety", *parts])
                except KeyboardInterrupt:
                    print("\n\033[93m[!] Execution interrupted.\033[0m")
                print()
                input("\nPress Enter to return to menu...")
        else:
            print(f"\033[91m[!] Tool '{tool_name}' not found.\033[0m")
            input("Press Enter to continue...")
