"""``llama-server`` bellek bekçisi (tasarım §2.2 "Bellek bekçisi").

Ölçü pilotun tanımıdır (``scripts/measurement/llm_pilot.py:594-632`` ``_footprint_gb`` ve
``model_bellegi``; ``:986-991`` ``bellek_ust``): llama.cpp'de üst sınır = RSS + phys_footprint
(GiB = 1024³), değerler 3 basamağa yuvarlanır. Eşik ``MEMORY_LIMIT_GIB`` (pilotun
``BELLEK_ESIGI_GB``'si, ``llm_pilot.py:65``); kapıdaki gibi ``≤ eşik`` geçer, ``> eşik`` aşımdır.

Pilottan tek fark seçimdedir, tanımda değil: pilot ``ps -axo`` ile LM Studio motor süreçlerinin en
büyüğünü bulur; ürün sürecin kimliğini bildiği için yalnız o PID'i ölçer (``ps -o rss= -p``).

Ölçülemeyen değer uydurulmaz: süreç yoksa örnek ``None``; ``footprint`` yoksa (macOS dışı ya da araç
hata verdi) ``footprint_gib`` ``None`` ve örnek ``complete=False`` (üst sınır o zaman yalnız RSS'tir,
pilotta da ``fp or 0.0``).

Kullanıcı uç noktasında bekçi çalışmaz (bellek başka makinededir); karar arka ucun
``capabilities().memory_guard`` alanındadır.
"""
from __future__ import annotations

import re
import subprocess
import threading
from dataclasses import dataclass
from typing import Any, Callable, Optional

from karadul.lm import MEMORY_LIMIT_GIB, MEMORY_POLL_SEC, MEMORY_ROUND_DIGITS
from karadul.lm.audit import AuditLog, now_iso

# llm_pilot.py:600-603: footprint çıktısındaki toplam ve birim çarpanları (GiB'a).
FOOTPRINT_RE = re.compile(r"Footprint:\s*([\d.]+)\s*(KB|MB|GB)")
_UNIT_GIB = {"KB": 1 / 1048576, "MB": 1 / 1024, "GB": 1.0}
_KIB_PER_GIB = 1048576           # ps rss= KiB verir (llm_pilot.py:615)
_FOOTPRINT_TIMEOUT_SEC = 60      # llm_pilot.py:597
_PS_TIMEOUT_SEC = 30

Runner = Callable[..., Any]


def parse_footprint_gib(stdout: str) -> Optional[float]:
    """``footprint -p PID`` çıktısından toplam footprint (GiB); bulunamazsa ``None``."""
    m = FOOTPRINT_RE.search(stdout or "")
    if not m:
        return None
    return float(m.group(1)) * _UNIT_GIB[m.group(2)]


def parse_rss_gib(stdout: str) -> Optional[float]:
    """``ps -o rss= -p PID`` çıktısından RSS (GiB); süreç yoksa çıktı boştur → ``None``."""
    s = (stdout or "").strip()
    if not s:
        return None
    try:
        return int(s.split()[0]) / _KIB_PER_GIB
    except ValueError:
        return None


def upper_bound_gib(rss_gib: float, footprint_gib: Optional[float]) -> float:
    """Pilotun llama-server üst sınırı: RSS + footprint (footprint yoksa 0 sayılır), yuvarlanmış."""
    return round(rss_gib + (footprint_gib or 0.0), MEMORY_ROUND_DIGITS)


@dataclass(frozen=True)
class MemorySample:
    pid: int
    rss_gib: float
    footprint_gib: Optional[float]
    upper_gib: float
    complete: bool          # footprint ölçülebildi mi
    at: str

    def as_dict(self) -> dict[str, Any]:
        return {"pid": self.pid, "rss_gib": self.rss_gib, "footprint_gib": self.footprint_gib,
                "ust_gib": self.upper_gib, "tam": self.complete, "zaman": self.at}


def measure_process(pid: int, run: Runner = subprocess.run) -> Optional[MemorySample]:
    """Tek sürecin RSS + footprint ölçümü; süreç yoksa ``None``."""
    try:
        r = run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True, timeout=_PS_TIMEOUT_SEC)
    except (OSError, subprocess.TimeoutExpired):
        return None
    rss = parse_rss_gib(r.stdout)
    if rss is None:
        return None
    try:
        f = run(["footprint", "-p", str(pid)], capture_output=True, text=True, timeout=_FOOTPRINT_TIMEOUT_SEC)
        fp = parse_footprint_gib(f.stdout)
    except (OSError, subprocess.TimeoutExpired):
        fp = None
    return MemorySample(pid=pid, rss_gib=round(rss, MEMORY_ROUND_DIGITS),
                        footprint_gib=None if fp is None else round(fp, MEMORY_ROUND_DIGITS),
                        upper_gib=upper_bound_gib(rss, fp), complete=fp is not None, at=now_iso())


class MemoryGuard:
    """Eşik aşımında durdurma çağrısı yapan bekçi.

    ``check()`` her model çağrısından sonra çağrılır; ``start()`` boşta ``interval`` saniyede bir
    ölçen artalan iş parçacığını açar. Aşımda ``on_exceed(sample)`` bir kez çağrılır, denetim
    günlüğüne ``bellek_durdu`` yazılır ve bekçi durur (yeniden kurulmadan tekrar tetiklenmez).
    """

    def __init__(self, pid_provider: Callable[[], Optional[int]], on_exceed: Callable[[MemorySample], None], *,
                 limit_gib: float = MEMORY_LIMIT_GIB, measure: Callable[[int], Optional[MemorySample]] = measure_process,
                 audit: Optional[AuditLog] = None):
        self.pid_provider = pid_provider
        self.on_exceed = on_exceed
        self.limit_gib = limit_gib
        self.measure = measure
        self.audit = audit
        self.last: Optional[MemorySample] = None
        self.peak: Optional[MemorySample] = None
        self.tripped: Optional[MemorySample] = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def exceeds(self, sample: MemorySample) -> bool:
        return sample.upper_gib > self.limit_gib

    def check(self) -> Optional[MemorySample]:
        """Bir ölçüm alır; süreç yoksa ``None``. Eşik aşılırsa durdurma çağrılır."""
        pid = self.pid_provider()
        if pid is None:
            return None
        sample = self.measure(pid)
        if sample is None:
            return None
        fire = False
        with self._lock:
            self.last = sample
            if self.peak is None or sample.upper_gib > self.peak.upper_gib:
                self.peak = sample
            if self.tripped is None and self.exceeds(sample):
                self.tripped = sample
                fire = True
        if fire:
            self._stop.set()
            if self.audit is not None:
                self.audit.write("bellek_durdu", bellek=sample.as_dict(), esik_gib=self.limit_gib)
            self.on_exceed(sample)
        return sample

    def start(self, interval: float = MEMORY_POLL_SEC) -> None:
        """Artalanda ``interval`` saniyede bir ``check()``; ``stop()`` ya da aşımla biter."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()

        def loop() -> None:
            while not self._stop.is_set():
                self.check()
                if self._stop.wait(interval):
                    break

        self._thread = threading.Thread(target=loop, name="karadullm-bellek-bekcisi", daemon=True)
        self._thread.start()

    def stop(self, timeout: Optional[float] = None) -> None:
        self._stop.set()
        t = self._thread
        if t is not None and t is not threading.current_thread():
            t.join(timeout)
        self._thread = None
