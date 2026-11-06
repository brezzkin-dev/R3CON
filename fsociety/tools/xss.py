from __future__ import annotations
import urllib.parse
import requests
import hashlib
import uuid
import re

from fsociety.core.base import tool
from fsociety.core.logger import Log

@tool("xss", "Context-Aware Reflected XSS Scanner", category="web")
class XSSScanner:
    @staticmethod
    def build_parser(p):
        p.add_argument("url", help="Target URL (e.g. http://site/search?q=test)")
        p.add_argument("--timeout", type=float, default=10.0)

    @staticmethod
    def run(args, log: Log) -> int:
        session = requests.Session()
        session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        
        parsed = urllib.parse.urlparse(args.url)
        qs = urllib.parse.parse_qs(parsed.query)
        if not qs:
            log.err("No URL parameters found to test.")
            return 1

        found = False
        for param, values in qs.items():
            base_val = values[0]
            marker = f"fsocietyXSS{uuid.uuid4().hex[:6]}"
            
            qs[param] = [marker]
            test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()

            try:
                r = session.get(test_url, timeout=args.timeout)
                if marker not in r.text:
                    continue
                
                context = "HTML"
                poc = f"<img src=x onerror=console.log('{marker}')>"
                
                if re.search(r'["\'].*?' + marker + r'.*?["\']', r.text):
                    context = "Attribute"
                    poc = f'"><img src=x onerror=console.log(\'{marker}\')>'
                elif re.search(r'<script[^>]*>.*?' + marker + r'.*?</script>', r.text, re.DOTALL):
                    context = "JavaScript"
                    poc = f"';console.log('{marker}');//"
                
                qs[param] = [poc]
                poc_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                r_poc = session.get(poc_url, timeout=args.timeout)
                
                if poc in r_poc.text:
                    log.hit(f"Reflected XSS confirmed in {context} context!")
                    log.hit(f"Payload: {poc_url}")
                    found = True
            except requests.RequestException:
                pass
            finally:
                qs[param] = [base_val]
                
        if not found:
            log.info("No XSS vulnerabilities detected.")
        return 0 if found else 1
