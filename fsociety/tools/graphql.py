from __future__ import annotations
import http.client
import json
import ssl
import urllib.parse
from fsociety.core.base import tool
from fsociety.core.logger import Log

INTROSPECTION_QUERY = """
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
          kind
        }
      }
    }
  }
}
"""

@tool("graphql", "GraphQL introspection and security scanner", category="web")
class GraphQL:
    @staticmethod
    def build_parser(p):
        p.add_argument("url", help="Target GraphQL URL (e.g. http://site/graphql)")
        p.add_argument("--insecure", action="store_true")

    @staticmethod
    def run(args, log: Log) -> int:
        ctx = ssl.create_default_context()
        if args.insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        parsed = urllib.parse.urlparse(args.url)
        scheme = parsed.scheme or "http"
        host = parsed.hostname
        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"

        headers = {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}
        payload = json.dumps({"query": INTROSPECTION_QUERY})

        conn = (http.client.HTTPSConnection(host, port, timeout=10, context=ctx) if scheme == "https" else http.client.HTTPConnection(host, port, timeout=10))
        
        log.info(f"Probing GraphQL Introspection on {args.url}")
        try:
            conn.request("POST", path, body=payload, headers=headers)
            resp = conn.getresponse()
            body = resp.read().decode("utf-8", "ignore")
            
            if resp.status == 200 and "__schema" in body:
                data = json.loads(body)
                types = data.get("data", {}).get("__schema", {}).get("types", [])
                log.hit(f"Introspection is ENABLED! Found {len(types)} types.")
                
                sensitive = ["User", "Admin", "Password", "Token", "Auth", "Secret"]
                for t in types:
                    name = t.get("name", "")
                    if any(s.lower() in name.lower() for s in sensitive):
                        log.hit(f"Sensitive Type Exposed: {name}")
                        for f in t.get("fields", []):
                            log.info(f"  - {f.get('name')} ({f.get('type', {}).get('name')})")
                return 0
            else:
                log.info("Introspection is disabled or endpoint is protected.")
                return 1
        except Exception as e:
            log.err(f"Connection failed: {e}")
            return 1
        finally:
            conn.close()
