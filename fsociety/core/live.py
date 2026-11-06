import sys
import time
import threading

class LiveAttack:
    def __init__(self, target: str, mode: str, threads: int, batch: int, duration: int, vector: str = ""):
        self.target = target
        self.mode = mode
        self.threads = threads
        self.batch = batch
        self.duration = duration
        self.vector = vector
        self.start_time = None
        self.stop_event = threading.Event()
        self._peak_pps = 0
        self._last_sent = 0
        self._last_time = 0
        self._monitor_thread = None

    def start(self):
        self.start_time = time.time()
        self._last_time = self.start_time
        sys.stdout.write("\n")
        sys.stdout.flush()
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()

    def _monitor_loop(self):
        while not self.stop_event.is_set():
            elapsed = time.time() - self.start_time
            if elapsed >= self.duration:
                break
            time.sleep(0.1)

    def render(self, total_sent: int):
        elapsed = time.time() - self.start_time
        dt = elapsed - (self._last_time - self.start_time)
        if dt <= 0:
            dt = 0.001
        pps = (total_sent - self._last_sent) / dt
        if pps > self._peak_pps:
            self._peak_pps = pps
        self._last_sent = total_sent
        self._last_time = time.time()

        remaining = max(0, self.duration - elapsed)
        pct = min(1.0, elapsed / max(1, self.duration))
        bar_len = 30
        filled = int(bar_len * pct)
        bar = "\033[92m" + "█" * filled + "\033[90m" + "░" * (bar_len - filled) + "\033[0m"

        if pps > 5_000_000:
            color = "\033[91m"
        elif pps > 1_000_000:
            color = "\033[93m"
        else:
            color = "\033[96m"

        line = (
            f"\r\033[2K{bar} \033[97m{elapsed:5.1f}s\033[0m/\033[90m{self.duration}s\033[0m "
            f"| {color}{pps:>12,.0f} PPS\033[0m "
            f"| \033[95mTotal: {total_sent:>15,}\033[0m "
            f"| \033[93mPeak: {self._peak_pps:>12,.0f}\033[0m "
            f"| \033[90mRem: {remaining:4.1f}s\033[0m"
        )
        sys.stdout.write(line)
        sys.stdout.flush()

    def finish(self, total_sent: int):
        self.stop_event.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=1)
        elapsed = time.time() - self.start_time
        avg_pps = total_sent / max(0.001, elapsed)

        sys.stdout.write("\n\n")
        sys.stdout.write("\033[96m══════════════════════════════════════════════════════════════════════════════════\033[0m\n")
        sys.stdout.write("\033[92m  [✓] ATTACK COMPLETED SUCCESSFULLY\033[0m\n")
        sys.stdout.write("\033[96m══════════════════════════════════════════════════════════════════════════════════\033[0m\n")
        sys.stdout.write(f"  \033[97mTarget:\033[0m       {self.target}\n")
        sys.stdout.write(f"  \033[97mMode:\033[0m         {self.mode.upper()}\n")
        sys.stdout.write(f"  \033[97mThreads:\033[0m      {self.threads}\n")
        sys.stdout.write(f"  \033[97mBatch Size:\033[0m   {self.batch} pkts/syscall\n")
        sys.stdout.write(f"  \033[97mDuration:\033[0m     {elapsed:.2f}s\n")
        sys.stdout.write(f"  \033[92mTotal Packets:\033[0m \033[97m{total_sent:,}\033[0m\n")
        sys.stdout.write(f"  \033[93mAverage PPS:\033[0m  {avg_pps:,.0f}\n")
        sys.stdout.write(f"  \033[91mPeak PPS:\033[0m     {self._peak_pps:,.0f}\n")
        est_bytes = total_sent * 1500
        sys.stdout.write(f"  \033[97mEst. Data:\033[0m    {est_bytes / (1024**3):.2f} GB\n")
        sys.stdout.write("\033[96m══════════════════════════════════════════════════════════════════════════════════\033[0m\n\n")
        sys.stdout.flush()
