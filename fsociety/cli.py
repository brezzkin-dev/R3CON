# fsociety/cli.py
from __future__ import annotations

import argparse
import importlib
import pkgutil
import sys
import traceback

from fsociety.core import base, config
from fsociety.core.logger import Log
from fsociety.core.output import table


def load_tools() -> list[tuple[str, str]]:
    errors: list[tuple[str, str]] = []
    try:
        pkg = importlib.import_module("fsociety.tools")
    except Exception as exc:
        errors.append(("fsociety.tools", f"{type(exc).__name__}: {exc}"))
        return errors

    path = getattr(pkg, "__path__", None)
    if not path:
        errors.append(("fsociety.tools", "__path__ missing"))
        return errors

    for mod in pkgutil.iter_modules(path):
        full = f"fsociety.tools.{mod.name}"
        try:
            importlib.import_module(full)
        except Exception as exc:
            errors.append((full, f"{type(exc).__name__}: {exc}"))
    return errors


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fsociety",
        description=f"{config.CODENAME} v{config.VERSION} — {config.AUTHOR}",
        epilog="Use 'fsociety --list' to enumerate modules.",
    )
    parser.add_argument("--list", action="store_true", help="list registered tools")
    parser.add_argument("--category", help="filter --list by category")
    parser.add_argument("--version", action="version", version=config.VERSION)
    parser.add_argument("--no-banner", action="store_true", help="suppress banner")
    parser.add_argument("--debug", action="store_true", help="verbose logging")
    return parser


def main(argv=None) -> int:
    errors = load_tools()
    for name, err in errors:
        sys.stderr.write(f"[import-fail] {name}: {err}\n")

    argv = list(sys.argv[1:] if argv is None else argv)
    root = build_parser()

    if not argv:
        print(config.BANNER, file=sys.stderr)
        root.print_help(sys.stderr)
        return 0

    if argv[0] in ("--list", "-l"):
        pre = root.parse_args(argv)
        entries = base.all_tools()
        if pre.category:
            entries = [t for t in entries if t.category == pre.category]
        if not entries:
            print("no tools registered", file=sys.stderr)
            return 1
        rows = [(t.name, t.category, ", ".join(t.aliases) or "-", t.summary) for t in entries]
        print(table(rows, ["TOOL", "CATEGORY", "ALIASES", "SUMMARY"]))
        return 0

    name = argv[0]
    entry = base.resolve(name)
    if entry is None:
        root.print_help(sys.stderr)
        print(f"\nunknown tool: {name}", file=sys.stderr)
        return 2

    sub = argparse.ArgumentParser(prog=f"fsociety {entry.name}", description=entry.summary)
    sub.add_argument("--debug", action="store_true", help="verbose logging")
    entry.build_parser(sub)
    args = sub.parse_args(argv[1:])
    if not getattr(args, "no_banner", False):
        print(config.BANNER, file=sys.stderr)

    config.ensure_dirs()
    log = Log(entry.name, level="debug" if getattr(args, "debug", False) else "info")
    try:
        return int(entry.run(args, log) or 0)
    except KeyboardInterrupt:
        log.warn("interrupted")
        return 130
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
