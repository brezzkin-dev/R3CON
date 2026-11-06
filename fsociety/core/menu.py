import os
import sys
from fsociety.core import base
from fsociety.core.splash import ALIAS_BANNER
from fsociety.core.logger import Log


def render_menu(page=1):
    os.system('cls' if os.name == 'nt' else 'clear')
    print(ALIAS_BANNER)
    print("\n (Menu layout placeholder - tools are registered via CLI) \n")


def interactive_menu():
    # A minimal fallback loop. The full 3-column menu is for the standalone CLI.
    while True:
        render_menu(1)
        choice = input("\n\033[92mroot@fsociety:~#\033[0m ").strip().lower()
        if choice in ("q", "exit", "back"):
            break
