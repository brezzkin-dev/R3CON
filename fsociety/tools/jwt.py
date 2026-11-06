from __future__ import annotations
import base64
import json
import hmac
import hashlib
from fsociety.core.base import tool
from fsociety.core.logger import Log

COMMON_SECRETS = ["secret", "password", "123456", "jwt", "key", "admin", "changeme", "default"]

@tool("jwt", "JWT Weakness Analyzer", category="web")
class JWTScanner:
    @staticmethod
    def build_parser(p):
        p.add_argument("--token", required=True, help="JWT string to analyze")

    @staticmethod
    def _decode(part: str) -> dict:
        try:
            part += "=" * (-len(part) % 4)
            return json.loads(base64.urlsafe_b64decode(part).decode('utf-8'))
        except Exception:
            return {}

    @staticmethod
    def run(args, log: Log) -> int:
        parts = args.token.split(".")
        if len(parts) != 3:
            log.err("Invalid JWT format")
            return 1

        header = JWTScanner._decode(parts[0])
        payload = JWTScanner._decode(parts[1])
        signature = parts[2]

        alg = header.get("alg", "").lower()
        if alg == "none":
            log.hit("CRITICAL: alg='none' detected. Signature bypass possible.")
            
        if "exp" not in payload:
            log.warn("WARNING: Token lacks 'exp' claim.")
            
        if alg in ("hs256", "hs384", "hs512"):
            signing_input = f"{parts[0]}.{parts[1]}".encode()
            hash_fn = getattr(hashlib, alg.replace("hs", "sha"))
            
            for secret in COMMON_SECRETS:
                expected = base64.urlsafe_b64encode(hmac.new(secret.encode(), signing_input, hash_fn).digest()).decode().rstrip("=")
                if hmac.compare_digest(expected, signature):
                    log.hit(f"CRITICAL: Weak secret cracked -> '{secret}'")
                    break
        else:
            log.info(f"Algorithm: {alg.upper()}")
            
        return 0
