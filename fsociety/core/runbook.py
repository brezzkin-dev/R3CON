import os
import sys
import subprocess


def tool_interface(tool_name: str):
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"--- F-SOCIETY {tool_name.upper()} ---\n")
    subprocess.run([sys.executable, "-m", "fsociety", tool_name, "--help"])
    print("\nType 'back' to return.\n")

    while True:
        try:
            cmd = input("\033[92mroot@fsociety:~#\033[0m ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if cmd.lower() in ("back", "exit", "menu", "q"):
            break
        if cmd.startswith("fsociety "):
            cmd = cmd[9:]
        if cmd:
            subprocess.run([sys.executable, "-m", "fsociety", *cmd.split()])
            print()
