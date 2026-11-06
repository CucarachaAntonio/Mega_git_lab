"""Observed process RSS sampling, including native model memory; no estimated peaks."""
import threading
import time
import psutil

class ResourceSampler:
    def __init__(self):
        self.process = psutil.Process()
        self.max_rss = self.process.memory_info().rss
        self.samples = 0
        self.interval = 0.1
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        while not self.stop_event.is_set():
            try:
                self.max_rss = max(self.max_rss, self.process.memory_info().rss)
                self.samples += 1
            except psutil.Error:
                pass
            self.stop_event.wait(self.interval)

    def start(self):
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.thread.join(timeout=1)
        return {"sampled_peak_rss_bytes": self.max_rss, "rss_sample_count": self.samples,
                "rss_sampling_interval_seconds": self.interval,
                "memory_note": "Sampled RSS maximum; may miss peaks shorter than interval, not total system usage"}
