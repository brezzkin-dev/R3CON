from __future__ import annotations
import argparse
import importlib
import pkgutil
import sys
import traceback
import io

from fsociety.core import base, config
from fsociety.core.logger import Log
from fsociety.core.output import table

_LOAD_ERRORS = []

def load_tools(verbose=False) -> list[tuple[str, str]]:
    global _LOAD_ERRORS
    _LOAD_ERRORS = []
    try:
        pkg = importlib.import_module("fsociety.tools")
    except Exception as exc:
        err = f"{type(exc).__name__}: {exc}"
        _LOAD_ERRORS.append(("fsociety.tools", err))
        if verbose: traceback.print_exc()
        return _LOAD_ERRORS

    path = getattr(pkg, "__path__", None)
    if not path:
        return _LOAD_ERRORS

    for mod in pkgutil.iter_modules(path):
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


def get_load_errors():
    return _LOAD_ERRORS


def build_parser():
    parser = argparse.ArgumentParser(prog="fsociety")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--category")
    parser.add_argument("--version", action="version", version=config.VERSION)
    parser.add_argument("--debug", action="store_true")
    return parser


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # `fsociety --doctor` prints every import failure with full traceback
    if argv and argv[0] == "--doctor":
        print("\033[96m=== F-SOCIETY DOCTOR ===\033[0m\n")
        errors = load_tools(verbose=True)
        tools = base.all_tools()
        print(f"\n\033[92m[+] Loaded {len(tools)} tools successfully.\033[0m")
        if errors:
            print(f"\n\033[91m[!] {len(errors)} tool(s) failed to load:\033[0m")
            for name, err in errors:
                print(f"    \033[93m{name}\033[0m: {err}")
        else:
            print("\033[92m[+] All tools loaded without errors.\033[0m")
        return 0

    errors = load_tools()

    if not argv:
        from fsociety.core.splash import show_splash
        from fsociety.core.menu import interactive_menu
        show_splash()
        interactive_menu()
        return 0

    root = build_parser()
    if argv[0] in ("--list", "-l"):
        pre = root.parse_args(argv)
        entries = base.all_tools()
        if pre.category:
            entries = [t for t in entries if t.category == pre.category]
        rows = [(t.name, t.category, ", ".join(t.aliases) or "-", t.summary) for t in entries]
        print(table(rows, ["TOOL", "CATEGORY", "ALIASES", "SUMMARY"]))
        return 0

    name = argv[0]
    entry = base.resolve(name)
    if entry is None:
        print(f"\n\033[91munknown tool: {name}\033[0m", file=sys.stderr)
        if errors:
            print("\033[93mFailed imports:\033[0m", file=sys.stderr)
            for n, e in errors:
                print(f"  {n}: {e}", file=sys.stderr)
        return 2

    sub = argparse.ArgumentParser(prog=f"fsociety {entry.name}", description=entry.summary)
    sub.add_argument("--debug", action="store_true")
    entry.build_parser(sub)
    args = sub.parse_args(argv[1:])

    config.ensure_dirs()
    log = Log(entry.name, level="debug" if getattr(args, "debug", False) else "info")
    try:
        return int(entry.run(args, log) or 0)
    except KeyboardInterrupt:
        return 130
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
