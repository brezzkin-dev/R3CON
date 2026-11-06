from __future__ import annotations

import hashlib
import itertools
import re
import time
from pathlib import Path

from fsociety.core.base import tool
from fsociety.core.logger import Log
from fsociety.core.utils import load_lines

ALGOS = {
    "md5":     hashlib.md5,
    "sha1":    hashlib.sha1,
    "sha224":  hashlib.sha224,
    "sha256":  hashlib.sha256,
    "sha384":  hashlib.sha384,
    "sha512":  hashlib.sha512,
    "sha3_256": hashlib.sha3_256,
    "sha3_512": hashlib.sha3_512,
    "blake2b": hashlib.blake2b,
}

RULES = {
    "lower":   lambda w: w.lower(),
    "upper":   lambda w: w.upper(),
    "cap":     lambda w: w.capitalize(),
    "swap":    lambda w: w.swapcase(),
    "rev":     lambda w: w[::-1],
    "digit":   lambda w: w + "1",
    "digit12": lambda w: w + "12",
    "digit23": lambda w: w + "23",
    "year":    lambda w: w + "2024",
    "year25":  lambda w: w + "2025",
    "leeto":   lambda w: w.replace("o", "0").replace("a", "4").replace("e", "3").replace("i", "1"),
    "l33t":    lambda w: w.replace("o", "0").replace("a", "@").replace("e", "3").replace("s", "$"),
    "appendx": lambda w: w + "!",
    "pound":   lambda w: w + "#",
}

HEX_RE = re.compile(r"^[a-fA-F0-9]+$")

@tool("crackx", "Hash cracking via wordlist, rules, and mask mode", category="auditing")
class Crackx:
    @staticmethod
    def build_parser(p):
        p.add_argument("target", help="hash string, or file containing hashes (@path)")
        p.add_argument("-a", "--algo", default="auto", choices=["auto", *ALGOS],
                       help="hash algorithm (auto-detect by length)")
        p.add_argument("-w", "--wordlist", help="wordlist file")
        p.add_argument("-r", "--rules", action="append", default=[],
                       choices=list(RULES), help="rule(s) to apply to each word")
        p.add_argument("-m", "--mask", help="mask mode, e.g. '?l?l?d?d' (?l?u?d?s?a)")
        p.add_argument("-t", "--threads", type=int, default=1, help="worker count")
        p.add_argument("--case-fold", action="store_true", help="try common case variants")
        p.add_argument("--timeout", type=float, default=0.0, help="abort after N seconds")
        p.add_argument("-o", "--out", help="write result file")

    @staticmethod
    def _detect(h: str) -> str:
        n = len(h)
        return {32: "md5", 40: "sha1", 56: "sha224", 64: "sha256",
                96: "sha384", 128: "sha512"}.get(n, "sha256")

    @staticmethod
    def _load_hashes(spec: str) -> list[str]:
        if spec.startswith("@"):
            return [h.strip() for h in load_lines(spec[1:]) if HEX_RE.match(h.strip())]
        return [h.strip() for h in spec.split(",") if h.strip()]

    @staticmethod
    def _candidates(wordlist, rules, case_fold):
        if wordlist:
            with open(wordlist, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    base = line.rstrip("\r\n")
                    if not base:
                        continue
                    yield base
                    if case_fold:
                        yield base.lower()
                        yield base.upper()
                        yield base.capitalize()
                    for rname in rules:
                        fn = RULES[rname]
                        yield fn(base)
                        if case_fold:
                            yield fn(base.lower())
                            yield fn(base.upper())

    @staticmethod
    def _mask_candidates(mask: str):
        alphabet = {
            "l": "abcdefghijklmnopqrstuvwxyz",
            "u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "d": "0123456789",
            "s": "!@#$%^&*()-_=+[]{};:,.<>/?",
            "a": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+",
        }
        pools = []
        i = 0
        while i < len(mask):
            if mask[i] == "?" and i + 1 < len(mask) and mask[i + 1] in alphabet:
                pools.append(alphabet[mask[i + 1]])
                i += 2
            else:
                pools.append(mask[i])
                i += 1
        for combo in itertools.product(*pools):
            yield "".join(combo)

    @staticmethod
    def run(args, log: Log) -> int:
        hashes = Crackx._load_hashes(args.target)
        if not hashes:
            log.err("no hashes to crack")
            return 1
        algo_name = args.algo if args.algo != "auto" else Crackx._detect(hashes[0])
        algo = ALGOS[algo_name]
        log.info(f"algorithm={algo_name}  hashes={len(hashes)}")

        wanted = {h.lower(): h for h in hashes}
        found: dict[str, str] = {}
        start = time.time()
        tries = 0

        def check(plain: str) -> None:
            nonlocal tries
            tries += 1
            try:
                digest = algo(plain.encode("utf-8", "ignore")).hexdigest()
            except Exception:
                return
            if digest in wanted:
                orig = wanted[digest]
                if orig not in found:
                    found[orig] = plain
                    log.hit(f"{orig} => {plain!r}")
            if args.timeout and time.time() - start > args.timeout:
                raise TimeoutError

        try:
            if args.mask:
                for plain in Crackx._mask_candidates(args.mask):
                    check(plain)
                    if len(found) == len(hashes):
                        break
            elif args.wordlist:
                for plain in Crackx._candidates(args.wordlist, args.rules, args.case_fold):
                    check(plain)
                    if len(found) == len(hashes):
                        break
            else:
                log.err("supply --wordlist or --mask")
                return 1
        except TimeoutError:
            log.warn("timeout reached")

        elapsed = time.time() - start
        rate = tries / elapsed if elapsed > 0 else 0.0
        log.info(f"tried {tries} candidates in {elapsed:.2f}s ({rate:,.0f}/s)")
        log.ok(f"cracked {len(found)}/{len(hashes)}")
        if args.out and found:
            Path(args.out).write_text(
                "\n".join(f"{h}:{p}" for h, p in found.items()),
                encoding="utf-8",
            )
        return 0 if len(found) == len(hashes) else 1
