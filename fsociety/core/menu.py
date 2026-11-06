import os
import sys
import subprocess
from fsociety.core import base
from fsociety.core.splash import ALIAS_BANNER

def render_menu():
    os.system('cls' if os.name == 'nt' else 'clear')
    
    print(f"\033[96m{ALIAS_BANNER}\033[0m")
    print()
    
    # Load errors
    from fsociety.cli import get_load_errors
    errors = get_load_errors()
    tools = base.all_tools()
    
    # Sort tools by category, then by name for a professional look
    tools = sorted(tools, key=lambda t: (t.category, t.name))
    total_tools = len(tools)

    # Define strict column widths
    col_width = 28
    total_width = (col_width * 3) + 4
    
    # Print Header Box
    print(f"\033[90m┌{'─' * col_width}┬{'─' * col_width}┬{'─' * col_width}┐\033[0m")
    
    title = "F-SOCIETY FRAMEWORK"
    status = f"{total_tools} TOOLS ACTIVE"
    
    # Center-aligned header text
    header_line = f"\033[1;97m{title:<30}\033[0m\033[90m{' ' * 9}\033[0m\033[1;96m{status:>30}\033[0m"
    print(f"\033[90m│\033[0m {header_line} \033[90m│\033[0m")
    print(f"\033[90m├{'─' * col_width}┬{'─' * col_width}┬{'─' * col_width}┤\033[0m")

    # Split into 3 columns
    col_len = (total_tools + 2) // 3
    cols = [tools[i:i + col_len] for i in range(0, total_tools, col_len)]
    
    # Pad cols to ensure they all have the same length
    for c in cols:
        while len(c) < col_len:
            c.append(None)

    # Print Rows
    for i in range(col_len):
        line = "\033[90m│\033[0m"
        for col in cols:
            t = col[i]
            if t:
                name = t.name[:15]
                cat = t.category[:9]
                # Cell content: [name] category
                cell = f"\033[97m[{name:<15}]\033[0m \033[90m{cat:<9}\033[0m"
                line += f" {cell} \033[90m│\033[0m"
            else:
                line += " " * col_width + "\033[90m│\033[0m"
        print(line)

    # Print Footer Box
    print(f"\033[90m├{'─' * col_width}┴{'─' * col_width}┴{'─' * col_width}┤\033[0m")
    
    nav = "  [Q] Quit    |    [D] Doctor    |    Type tool name or full command"
    print(f"\033[90m│\033[0m \033[92m{nav:<{total_width - 3}}\033[0m \033[90m│\033[0m")
    print(f"\033[90m└{'─' * col_width}┴{'─' * col_width}┴{'─' * col_width}┘\033[0m")

    # Print Import Errors if any
    if errors:
        print(f"\n\033[91m[!] {len(errors)} TOOL(S) FAILED TO LOAD:\033[0m")
        for name, err in errors:
            short_err = err if len(err) < 80 else err[:77] + "..."
            print(f"    \033[93m{name}\033[0m: \033[90m{short_err}\033[0m")
        print("\033[90mRun 'D' to execute --doctor for full tracebacks.\033[0m")


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
            input("\n\033[90mPress Enter to return...\033[0m")
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
                # Show tool help
                os.system('cls' if os.name == 'nt' else 'clear')
                print(f"\033[1;96m=== F-SOCIETY :: {entry.name.upper()} ===\033[0m\n")
                print(f"\033[90m{entry.summary}\033[0m\n")
                subprocess.run([sys.executable, "-m", "fsociety", entry.name, "--help"])
                print(f"\n\033[92mTo execute:\033[0m {entry.name} <args>")
                input("\n\033[90mPress Enter to return...\033[0m")
            else:
                # Execute tool
                os.system('cls' if os.name == 'nt' else 'clear')
                print(f"\033[1;96m[*] Executing: fsociety {' '.join(parts)}\033[0m\n")
                try:
                    subprocess.run([sys.executable, "-m", "fsociety", *parts])
                except KeyboardInterrupt:
                    print("\n\033[93m[!] Execution interrupted.\033[0m")
                input("\n\033[90mPress Enter to return...\033[0m")
        else:
            print(f"\033[91m[!] Tool '{tool_name}' not found.\033[0m")
            if len(parts) > 1:
                print(f"\033[90mHint: The tool may have failed to load. Type 'D' to diagnose.\033[0m")
            input("Press Enter to continue...")
