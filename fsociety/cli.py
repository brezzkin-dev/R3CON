# fsociety/cli.py
from __future__ import annotations

import warnings
warnings.filterwarnings("ignore")

import argparse
import importlib
import pkgutil
import sys
import traceback

from fsociety.core import base, config
from fsociety.core.logger import Log
from fsociety.core.output import table


_LOAD_ERRORS: list[tuple[str, str]] = []


def load_tools(verbose: bool = False) -> list[tuple[str, str]]:
    global _LOAD_ERRORS
    _LOAD_ERRORS = []

    try:
        pkg = importlib.import_module("fsociety.tools")
    except Exception as exc:
        err = f"{type(exc).__name__}: {exc}"
        _LOAD_ERRORS.append(("fsociety.tools", err))
        if verbose:
            print(f"\n\033[91m=== IMPORT FAILED: fsociety.tools ===\033[0m", file=sys.stdout)
            traceback.print_exc(file=sys.stdout)
        return _LOAD_ERRORS

    path = getattr(pkg, "__path__", None)
    if not path:
        _LOAD_ERRORS.append(("fsociety.tools", "__path__ missing"))
        return _LOAD_ERRORS

    for mod in pkgutil.iter_modules(path):
        if mod.name.startswith("_"):
            continue
        full = f"fsociety.tools.{mod.name}"
        try:
            importlib.import_module(full)
        except Exception as exc:
            err = f"{type(exc).__name__}: {exc}"
            _LOAD_ERRORS.append((full, err))
            if verbose:
                print(f"\n\033[91m=== IMPORT FAILED: {full} ===\033[0m", file=sys.stdout)
                traceback.print_exc(file=sys.stdout)

    return _LOAD_ERRORS


def get_load_errors() -> list[tuple[str, str]]:
    return _LOAD_ERRORS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fsociety",
        description=f"{config.CODENAME} v{config.VERSION} — {config.AUTHOR}",
        epilog="Run 'fsociety --doctor' to diagnose load failures.",
    )
    parser.add_argument("--list", action="store_true", help="list registered tools")
    parser.add_argument("--category", help="filter --list by category")
    parser.add_argument("--version", action="version", version=config.VERSION)
    parser.add_argument("--debug", action="store_true", help="verbose logging")
    parser.add_argument("--doctor", action="store_true", help="diagnose tool load failures")
    return parser


def cmd_doctor() -> int:
    print("\033[96m╔══════════════════════════════════════════════════════════════╗")
    print("║ \033[97mF-SOCIETY DOCTOR\033[96m                                            ║")
    print("╚══════════════════════════════════════════════════════════════╝\033[0m\n")

    print(f"\033[90mPython:\033[0m {sys.version.split()[0]}")
    print(f"\033[90mPlatform:\033[0m {sys.platform}")
    print(f"\033[90mExecutable:\033[0m {sys.executable}\n")

    errors = load_tools(verbose=True)
    tools = base.all_tools()

    print(f"\n\033[92m[+] Loaded {len(tools)} tools successfully.\033[0m")

    if errors:
        print(f"\n\033[91m[!] {len(errors)} tool(s) failed to load:\033[0m")
        for name, err in errors:
            print(f"    \033[93m{name}\033[0m")
            print(f"        \033[90m{err}\033[0m")
        print(f"\n\033[93mHint: most failures are missing Python packages.\033[0m")
        print(f"\033[93mInstall with: pip install <package-name>\033[0m")
        return 1

    print("\033[92m[+] All tools loaded without errors.\033[0m")

    # quick health check
    print("\n\033[96m[*] Dependency check:\033[0m")
    for pkg_name in ("requests", "dnspython", "phonenumbers", "bs4", "paramiko"):
        try:
            importlib.import_module(pkg_name.replace("-", "_"))
            print(f"    \033[92m[OK]\033[0m  {pkg_name}")
        except ImportError:
            print(f"    \033[91m[MISS]\033[0m {pkg_name}")

    # raw socket check
    print("\n\033[96m[*] Raw socket check:\033[0m")
    import os
    if os.geteuid() == 0:
        print("    \033[92m[OK]\033[0m  running as root — ddos / dos / fury / packetforge / amp will work")
    else:
        print("    \033[93m[WARN]\033[0m not root — raw socket tools (ddos, dos, fury, packetforge, amp) will fail")
        print("    \033[90m      run: sudo python3 r3con.py\033[0m")

    return 0


def cmd_list(category: str | None = None) -> int:
    entries = base.all_tools()
    if category:
        entries = [t for t in entries if t.category.lower() == category.lower()]

    if not entries:
        print(f"\033[91m[!] No tools found{f' in category {category!r}' if category else ''}.\033[0m")
        return 1

    rows = [(t.name, t.category, ", ".join(t.aliases) or "-", t.summary) for t in entries]
    print(table(rows, ["TOOL", "CATEGORY", "ALIASES", "SUMMARY"]))
    print(f"\n\033[90mTotal: {len(entries)} tool(s)\033[0m")
    return 0


def cmd_run_tool(name: str, tool_args: list[str]) -> int:
    entry = base.resolve(name)
    if entry is None:
        print(f"\033[91m[!] unknown tool: {name}\033[0m", file=sys.stderr)
        if _LOAD_ERRORS:
            print(f"\n\033[93m{len(_LOAD_ERRORS)} tool(s) failed to load:\033[0m", file=sys.stderr)
            for n, e in _LOAD_ERRORS:
                print(f"  \033[90m{n}\033[0m: {e}", file=sys.stderr)
            print(f"\n\033[90mRun 'fsociety --doctor' for full tracebacks.\033[0m", file=sys.stderr)
        return 2

    sub = argparse.ArgumentParser(
        prog=f"fsociety {entry.name}",
        description=entry.summary,
    )
    sub.add_argument("--debug", action="store_true", help="verbose logging")
    try:
        entry.build_parser(sub)
    except Exception as exc:
        print(f"\033[91m[!] Failed to build parser for {entry.name}: {exc}\033[0m", file=sys.stderr)
        traceback.print_exc()
        return 1

    try:
        args = sub.parse_args(tool_args)
    except SystemExit as exc:
        return int(exc.code or 0)

    config.ensure_dirs()
    log = Log(entry.name, level="debug" if getattr(args, "debug", False) else "info")

    try:
        return int(entry.run(args, log) or 0)
    except KeyboardInterrupt:
        print()
        log.warn("interrupted")
        return 130
    except SystemExit:
        raise
    except Exception:
        print(f"\n\033[91m[!] Tool {entry.name} crashed:\033[0m", file=sys.stderr)
        traceback.print_exc()
        return 1


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # --doctor runs before menu (needs full traceback output)
    if argv and argv[0] == "--doctor":
        return cmd_doctor()

    # Load tools quietly (errors surface inside menu or doctor)
    load_tools(verbose=False)

    # No args -> splash + interactive menu
    if not argv:
        from fsociety.core.splash import show_splash
        from fsociety.core.menu import interactive_menu
        show_splash()
        interactive_menu()
        return 0

    # --list
    if argv[0] in ("--list", "-l"):
        root = build_parser()
        try:
            parsed, _ = root.parse_known_args(argv)
        except SystemExit:
            return 1
        return cmd_list(parsed.category)

    # --version
    if argv[0] in ("--version", "-v"):
        print(config.VERSION)
        return 0

    # Otherwise: treat argv[0] as tool name, argv[1:] as its arguments
    return cmd_run_tool(argv[0], argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
