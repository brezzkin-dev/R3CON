"""OSINT for Indian phone numbers — carrier, circle, spam-reputation lookup."""
from __future__ import annotations

import re
from typing import Any

import requests


class IndianNumberOSINT:
    INDIAN_CIRCLES = {
        "11": "Delhi", "22": "Mumbai", "33": "Kolkata", "44": "Chennai",
        "40": "Hyderabad", "80": "Bangalore", "20": "Pune", "79": "Ahmedabad",
    }

    # Operators by first digit of the 10-digit number (approximate as of TRAI 2024)
    OPERATOR_PREFIXES = {
        "70": "Airtel", "71": "Airtel", "72": "Airtel", "73": "Airtel",
        "74": "Airtel", "75": "Vi", "76": "Vi", "77": "Vi", "78": "Vi", "79": "Vi",
        "80": "Airtel", "81": "Airtel", "82": "Jio", "83": "Jio", "84": "Jio",
        "85": "Jio", "86": "Jio", "87": "Jio", "88": "Jio", "89": "Jio",
        "90": "Airtel", "91": "Airtel", "92": "Airtel", "93": "Airtel",
        "94": "Airtel", "95": "Airtel", "96": "Airtel", "97": "Airtel", "98": "Airtel",
        "99": "Airtel",
    }

    def __init__(self, number: str):
        digits = re.sub(r"\D", "", number)
        if digits.startswith("91"):
            digits = digits[2:]
        if len(digits) != 10:
            raise ValueError("Indian number must be 10 digits after +91")
        self.number = "+91" + digits
        self.digits = digits

    def carrier_lookup(self) -> str:
        return self.OPERATOR_PREFIXES.get(self.digits[:2], "Unknown")

    def circle_lookup(self) -> str:
        # Circle is impossible from digits alone post-MNP; use prefix heuristics.
        # Fall back to a real HLR API if you have one.
        return "MNP-enabled (true circle unavailable from prefix)"

    def truecaller_public(self, endpoint: str = "https://truecaller4.p.rapidapi.com/api/v1/getDetails",
                          rapidapi_key: str | None = None) -> dict[str, Any]:
        """Hit TrueCaller's public lookup via RapidAPI. Returns whatever the endpoint exposes."""
        if not rapidapi_key:
            return {"error": "rapidapi_key required — set it in SCAMBLR config"}
        try:
            r = requests.get(endpoint,
                             params={"phone": self.digits, "countryCode": "IN"},
                             headers={
                                 "X-RapidAPI-Key": rapidapi_key,
                                 "X-RapidAPI-Host": "truecaller4.p.rapidapi.com",
                             }, timeout=10)
            return r.json()
        except Exception as e:
            return {"error": str(e)}

    def scam_report_lookup(self) -> dict[str, Any]:
        """Check against public scam-report databases."""
        results = {}
        try:
            r = requests.get(f"https://api.syphon.io/v1/lookup/{self.number}", timeout=10)
            if r.status_code == 200:
                results["syphon"] = r.json()
        except Exception:
            pass
        try:
            r = requests.get(f"https://www.shouldianswer.net/api/v2/phone/{self.number}", timeout=10)
            if r.status_code == 200:
                results["shouldianswer"] = r.json()
        except Exception:
            pass
        return results

    def full_report(self, rapidapi_key: str | None = None) -> dict[str, Any]:
        return {
            "number": self.number,
            "carrier": self.carrier_lookup(),
            "circle": self.circle_lookup(),
            "truecaller": self.truecaller_public(rapidapi_key=rapidapi_key),
            "scam_reports": self.scam_report_lookup(),
        }
