from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from typing import Callable, Dict, List


@dataclass(frozen=True)
class Tool:
    name: str
    summary: str
    category: str
    build_parser: Callable[[argparse.ArgumentParser], None]
    run: Callable[[argparse.Namespace], int]
    aliases: List[str] = field(default_factory=list)


_TOOLS: Dict[str, Tool] = {}
_ALIAS: Dict[str, str] = {}


def tool(name: str, summary: str, category: str = "general", aliases=None):
    """Register a tool class. Class must expose build_parser(p) and run(args)."""
    def decorator(cls):
        entry = Tool(
            name=name,
            summary=summary,
            category=category,
            build_parser=cls.build_parser,
            run=cls.run,
            aliases=list(aliases or []),
        )
        _TOOLS[name] = entry
        for alias in entry.aliases:
            _ALIAS[alias] = name
        return cls
    return decorator


def resolve(name: str):
    if name in _TOOLS:
        return _TOOLS[name]
    if name in _ALIAS:
        return _TOOLS[_ALIAS[name]]
    return None


def all_tools() -> List[Tool]:
    return sorted(_TOOLS.values(), key=lambda t: t.name)


def categories() -> List[str]:
    return sorted({t.category for t in _TOOLS.values()})
