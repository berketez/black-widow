#!/usr/bin/env python3
"""Gece koşusu: ÖLÇ-1 (ÖLÇEK taban ölçümü) + HZ-0 (HIZ taban ölçümü) tek kuyrukta, boş makinede.

Kararlar: KARARLAR A-18 (ÖLÇ-1 duvarları 2 saat; ÖLÇ-1 ile HZ-0 tek koşu), A-9 (oranla kabul).
Planlar: ``olcek/PLAN.md`` ÖLÇ-1, ``hiz/PLAN.md`` §1 ve HZ-0. Ön kayıtlar koşudan ÖNCE commit'li olmalı:
``olcek/on_kayit_olc1.md``, ``hiz/on_kayit_hz0.md``. Tahminler ve bölme önerisi ``olcek/GECE_PLANI.md``.

Kuyruk (öntanım sıra; ``--yalniz`` / ``--gece`` ile seçilir):
  hz0       K1 O1 B1 K2 O2 B2 K3 O3 B3 (duvar 10 800 sn; her birine ``hz0_ek.py`` eşlik eder)
  p16c      K ve O için çözümleyici başına otomatik analiz süreleri (``p16c_sure.py kos``; HZ-0 adım 5)
  k_appcds  K × 4, ``-XX:+AutoCreateSharedArchive`` (ilki arşivi kurar; HZ-0 adım 5b)
  avast     K1 O1 K2 O2 K3 O3, kök ``~/karadul_olcum/runs/hiz-avast-dislama/<commit>/`` (Berke bu dizini
            Avast'ta dışlar; ``--avast-dislama-yapildi`` verilmezse grup atlanır ve kayda geçer)
  b_jfr     B × 1, JFR kaydı (``settings=profile``; HZ-0 adım 5; medyana girmez)
  olc1      T100, T300, PAKET (duvar 7 200 sn; A-18). T25 = HZ-0'ın B'si (ayrı koşulmaz)
  paket_e   PAKET-E (Element.app; yalnız ``--paket-e`` ile)
  duman     cat × 1 (yalnız ``--yalniz duman``; gündüz duman koşusu için, JFR denemesiyle)

Her koşu ``scripts/measurement/olcek_kos.py`` ile ve ``~/karadul_olcum/ghidra_kuyruk.sh`` içinde
(aynı anda tek Ghidra). Koşu kökü ``<kök>/<grup>/<kod>/<tekrar>/``.

Boş makine (``hiz/PLAN.md`` §1): koşu başında ve sonunda 1 dk yük ortalaması < 0,25 × ``os.cpu_count()``.
- Başlamadan önce yük eşiğin altına inene kadar en çok ``--yuk-bekle-sn`` beklenir (bir önceki koşunun
  kendi yükü sönsün); inmezse koşu başlatılmaz (deneme geçersiz sayılır).
- Başlangıç yükü koşucunun kendi kaydıdır (``kunye.json`` ``yuk_bas``: kuyruk kilidi alındıktan sonra).
- Bitişte yük en çok ``--son-bekle-sn`` (180) içinde eşiğin altına inmelidir. Gerekçe: 1 dk ortalama üstel
  söner (zaman sabiti 60 sn); koşunun kendi yükü 14'ten başlasa bile 180 sn sonra 14 × e^-3 ≈ 0,7 kalır.
  Bu sürede inmeyen yük dışarıdandır.
- Geçersiz deneme ``<tekrar>.gecersiz<k>`` adıyla saklanır ve en çok 2 kez yinelenir (toplam 3 deneme).
  Sonuç ``<koşu kökü>/gece_durum.json``.

HZ-0 kabulü: bir hedefin geçerli tekrarlarında uçtan uca süre yayılımı (en büyük − en küçük) / ortanca
0,10'u aşarsa o hedefe en çok 2 ek tekrar (``<tekrar>`` = 4, 5) koşulur (``--yayilim-ek-yok`` ile kapanır).

Sürdürme: ``BITTI`` olan koşu atlanır (``kesildi`` hariç); ``BITTI``'siz yarım dizin ``<tekrar>.yarim<k>``
adıyla saklanıp koşu yeniden başlar. Disk boş alanı ``--disk-alt-gb``'ın altına inerse kuyruk durur.

Kullanım (ana ağaç kökünden):
    python scripts/arge/olcek/gece_kosusu.py --commit <hash> --kuru            # plan + TAHMİNİ süre
    python scripts/arge/olcek/gece_kosusu.py --commit <hash> --gece 1 [--avast-dislama-yapildi]
    python scripts/arge/olcek/gece_kosusu.py --commit <hash> --gece 2 [--paket-e]
Sonda ``<kök>/ozet.json``.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

DEPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(DEPO / "scripts" / "measurement"))
sys.path.insert(0, str(DEPO / "scripts" / "arge" / "hiz"))
from urun_kos import CALISMA_VERISI, agac_kunyesi  # noqa: E402
from olcek_kos import KILL_BEKLE_SN  # noqa: E402  (SIGTERM → SIGKILL payı; tek tanım orada)
from hz0_ek import donanim_kunyesi  # noqa: E402

ANA_DEPO = Path("/Users/apple/Black_Widow")
OLCUM = Path.home() / "karadul_olcum"
KUYRUK = OLCUM / "ghidra_kuyruk.sh"
OLCEK_KOS = DEPO / "scripts" / "measurement" / "olcek_kos.py"
HZ0_EK = DEPO / "scripts" / "arge" / "hiz" / "hz0_ek.py"
P16C = DEPO / "scripts" / "measurement" / "p16c_sure.py"
S8_TABAN = OLCUM / "runs" / "urun-onarim-a62f15e"
GOSTERI = OLCUM / "runs" / "gosteri-2026-11-19" / "ollama"

DUVAR_HZ0_SN = 10800   # HZ-0 adım 4 (B hedefi = T25)
DUVAR_OLC1_SN = 7200   # A-18: T100 / T300 / PAKET duvarı 2 saat
DUVAR_DUMAN_SN = 900
KUYRUK_PAYI_SN = 1800  # kilit bekleme + künye toplama payı (dış zaman sınırı)
YUK_ORANI = 0.25       # hiz/PLAN §1: 1 dk yük < 0,25 × os.cpu_count()
YUK_BEKLE_SN = 900
SON_BEKLE_SN = 180
EN_COK_DENEME = 3      # 1 + en çok 2 yineleme
DISK_ALT_GB = 40
GECE_SN = 36000        # tek gece ≈ 10 sa
YUK_YOKLAMA_SN = 10
YAYILIM_ESIGI = 0.10   # HZ-0 kabulü: (en büyük − en küçük) / ortanca ≤ 0,10; aşarsa en çok 2 tekrar daha
EK_TEKRAR = 2

# TAHMİN (sn, [alt; üst]) ve kaynağı. Ayrıntı GECE_PLANI.md; hiçbiri boş makinede ölçülmedi.
TAHMIN: dict[str, tuple[float | None, float, str]] = {
    "K": (47, 108, "S8 tabanı b6aceb9 sort 47,3 sn (2026-11-20, yük ~5–7) ↔ a62f15e 119 koşusu 107,9 sn"),
    "O": (219, 403, "S8 tabanı b6aceb9 mac/tmux 219,5 sn ↔ a62f15e 403,2 sn"),
    "B": (3170, 7730, "gösteri 7 729 sn (yük 40–60) × [0,41; 1]; 0,41 = S8 ↔ 119 süre oranlarının en küçüğü"),
    "cat": (33, 81, "S8 tabanı b6aceb9 cat 32,9 sn ↔ a62f15e 80,5 sn"),
    "T100": (7200, 7290, "duvar 7 200 + SIGTERM payı; köprü TAHMİN A [14,5; 39,4] sa (BULGULAR §3.5)"),
    "T300": (7200, 7290, "duvar 7 200 + SIGTERM payı; köprü TAHMİN A [77,9; 447,5] sa"),
    "PAKET": (7200, 7290, "duvar 7 200 + SIGTERM payı; statik S0 doğrusal [177; 345] sa (§3.6)"),
    "PAKET-E": (None, 7290, "alt bilinmiyor (büyük asar ile hiç koşulmadı); üst = duvar + pay"),
    "p16c": (103, 231, "köprü süreleri: sort 17,0–41,6 + tmux 86,2–145,2 sn (S8 ↔ a62f15e) + JVM"),
}
ARA_TAHMIN = (60, 180, "koşu arası yük sönümü: 14 → 3,5 için ≥ 83 sn (60 × ln 4); üst = son bekleme sınırı")

KUYRUK_GRUPLARI = ("hz0", "p16c", "k_appcds", "avast", "b_jfr", "olc1", "paket_e", "duman")
GECE_GRUPLARI = {"1": ("hz0", "p16c", "k_appcds", "avast"), "2": ("b_jfr", "olc1", "paket_e"),
                 "hepsi": KUYRUK_GRUPLARI[:-1]}


@dataclass
class Kosu:
    grup: str
    kod: str
    tekrar: int
    kok: Path
    hedef: Path | None
    duvar: float
    etiket: str
    ayar: Path | None = None
    java_ek: str = ""
    hz0_ek: bool = False
    tur: str = "olcek"  # olcek | p16c
    hazirla: list[Path] = field(default_factory=list)  # koşudan önce açılacak dizinler

    @property
    def tahmin(self) -> tuple[float | None, float, str]:
        return TAHMIN["p16c" if self.tur == "p16c" else self.kod]


# ---------------------------------------------------------------------------- yardımcılar

def _simdi() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def yuk_oku() -> float:
    return os.getloadavg()[0]


def uyu(sn: float) -> None:
    time.sleep(sn)


def yuk_esigi() -> float:
    return YUK_ORANI * (os.cpu_count() or 1)


def bekle_sessiz(esik: float, en_uzun: float, oku: Callable[[], float] | None = None,
                 bekle: Callable[[float], None] | None = None) -> tuple[bool, list[float], float]:
    """1 dk yük eşiğin altına inene dek en çok ``en_uzun`` sn bekle. Dönen: (indi mi, okumalar, süre)."""
    oku = oku or yuk_oku
    bekle = bekle or uyu
    okumalar, gecen = [], 0.0
    while True:
        y = oku()
        okumalar.append(round(y, 2))
        if y < esik:
            return True, okumalar, gecen
        if gecen >= en_uzun:
            return False, okumalar, gecen
        adim = min(YUK_YOKLAMA_SN, max(0.0, en_uzun - gecen)) or YUK_YOKLAMA_SN
        bekle(adim)
        gecen += adim


def gecerlilik(yuk_bas: float | None, son_indi: bool, esik: float) -> tuple[bool, str]:
    """Boş makine hükmü: başlangıç yükü (koşucunun kaydı) ve bitişte sönüm."""
    if yuk_bas is None:
        return False, "başlangıç yükü kaydı yok"
    if not yuk_bas < esik:
        return False, f"başlangıç 1 dk yükü {yuk_bas:.2f} ≥ eşik {esik:.2f}"
    if not son_indi:
        return False, f"bitişte yük {SON_BEKLE_SN} sn içinde eşiğin ({esik:.2f}) altına inmedi"
    return True, "boş makine"


def ham_girdi(kosu: Path) -> Path:
    """Taban koşusunun ``ws/workspaces/<ad>/<zaman>/raw`` altındaki tek ikili (sha256 denetimiyle)."""
    hamlar = sorted((kosu / "ws" / "workspaces").glob("*/*/raw"))
    if len(hamlar) != 1:
        raise SystemExit(f"{kosu}: {len(hamlar)} raw dizini (tam olarak bir tane olmalı)")
    bilgi = json.loads((hamlar[0] / "target_info.json").read_text(encoding="utf-8"))
    dosyalar = sorted(p for p in hamlar[0].iterdir() if p.is_file() and p.name != "target_info.json")
    if len(dosyalar) != 1:
        raise SystemExit(f"{hamlar[0]}: {len(dosyalar)} girdi dosyası")
    import hashlib
    h = hashlib.sha256(dosyalar[0].read_bytes()).hexdigest()
    if h != bilgi.get("file_hash"):
        raise SystemExit(f"{dosyalar[0]}: sha256 target_info.json ile tutmuyor")
    return dosyalar[0]


def hedef_yolu(kod: str, kuru: bool) -> tuple[Path | None, Path | None]:
    """Hedef ve (varsa) ayar dosyası. Kuru kipte eksik hedef hata değil, None."""
    s8 = {"K": "debian/coreutils/sort", "O": "mac/tmux", "cat": "debian/coreutils/cat"}
    sabit = {"T100": Path("/opt/homebrew/Cellar/llvm/23.1.6/bin/mlir-transform-opt"),
             "T300": Path("/opt/anaconda3/envs/project_env/lib/python3.12/site-packages/tensorflow/"
                          "libtensorflow_cc.2.dylib"),
             "PAKET": Path("/Applications/FreeCAD.app"), "PAKET-E": Path("/Applications/Element.app")}
    if kod in s8:
        try:
            return ham_girdi(S8_TABAN / s8[kod]), None
        except (SystemExit, OSError):
            if kuru:
                return None, None
            raise
    if kod == "B":
        # Gösteri koşusunun koşulu: "Objective-C Message Analyzer" kapalı (gosteri.yaml)
        return GOSTERI / "girdi" / "Ollama", GOSTERI / "gosteri.yaml"
    return sabit[kod], None


def kuyruk_olustur(gruplar: tuple[str, ...], kok: Path, avast_kok: Path, kuru: bool) -> list[Kosu]:
    out: list[Kosu] = []

    def ekle(grup: str, kod: str, n: int, duvar: float, taban: Path | None = None, **kw: Any) -> None:
        hedef, ayar = hedef_yolu(kod, kuru)
        k_kok = (taban or kok / grup) / kod / str(n)
        out.append(Kosu(grup=grup, kod=kod, tekrar=n, kok=k_kok, hedef=hedef, ayar=ayar, duvar=duvar,
                        etiket=f"{grup}:{kod}#{n}", **kw))

    for grup in gruplar:
        if grup == "hz0":
            for n in (1, 2, 3):
                for kod in ("K", "O", "B"):
                    ekle(grup, kod, n, DUVAR_HZ0_SN, hz0_ek=True)
        elif grup == "p16c":
            out.append(Kosu(grup="p16c", kod="K+O", tekrar=1, kok=kok / "p16c", hedef=None, duvar=3600,
                            etiket="p16c:K+O", tur="p16c"))
        elif grup == "k_appcds":
            cds = kok / grup / "cds"
            for n in (1, 2, 3, 4):
                ekle(grup, "K", n, DUVAR_HZ0_SN, java_ek=(
                    f"-XX:+AutoCreateSharedArchive -XX:SharedArchiveFile={cds / 'karadul.jsa'}"),
                    hazirla=[cds])
        elif grup == "avast":
            for n in (1, 2, 3):
                for kod in ("K", "O"):
                    ekle(grup, kod, n, DUVAR_HZ0_SN, taban=avast_kok, hz0_ek=True)
        elif grup == "b_jfr":
            ekle(grup, "B", 1, DUVAR_HZ0_SN, hz0_ek=True, java_ek=jfr_secenekleri(kok / grup / "B" / "1"))
        elif grup == "olc1":
            for kod in ("T100", "T300", "PAKET"):
                ekle(grup, kod, 1, DUVAR_OLC1_SN)
        elif grup == "paket_e":
            ekle(grup, "PAKET-E", 1, DUVAR_OLC1_SN)
        elif grup == "duman":
            # JFR ile AutoCreateSharedArchive aynı koşuda olmaz: arşiv dökülürken JVM JFR'ı kapatır
            # ("JFR will be disabled during CDS dumping"; `java -version` ile denendi). Duman JFR'ı sınar.
            ekle(grup, "cat", 1, DUVAR_DUMAN_SN, hz0_ek=True, java_ek=jfr_secenekleri(kok / grup / "cat" / "1"))
            out[-1].etiket = "duman:cat"
    return out


def jfr_secenekleri(k_kok: Path) -> str:
    """JFR: çıkışta döküm + diske kayıt ve saklanan depo.

    PyGhidra JVM'inde (JPype) çıkıştaki döküm "Unable to complete I/O operation" ile 0 baytta kalıyor
    (duman koşusu 2026-11-20 09:05; Ghidra'sız JPype + JDK 27 denemesinde de aynı). ``disk=true`` +
    ``preserve-repository=true`` ile kayıt parçaları ``jfr_repo/<zaman>_<pid>/*.jfr`` olarak kalır ve
    ``jfr`` ile okunur (denendi: 3 sn'lik parça, ``jdk.ExecutionSample`` var). ``maxsize``: öntanım 250 MB
    sınırı uzun koşuda eski parçaları siler (CFG / xref aralıkları koşunun ortasında).
    ``%p``: pyghidra başlatıcısının kısa ömürlü JVM'leri de JAVA_TOOL_OPTIONS'ı okur; dosya ayrı kalsın.
    """
    return (f"-XX:StartFlightRecording=settings=profile,disk=true,maxsize=3g,dumponexit=true,"
            f"filename={k_kok / 'kayit_%p.jfr'} "
            f"-XX:FlightRecorderOptions=repository={k_kok / 'jfr_repo'},preserve-repository=true")


def tahmin_ozeti(kuyruk: list[Kosu]) -> dict[str, Any]:
    gruplar: dict[str, list[float]] = {}
    alt_bilinmeyen = []
    for k in kuyruk:
        alt, ust, _ = k.tahmin
        g = gruplar.setdefault(k.grup, [0.0, 0.0, 0])
        g[0] += (alt or 0.0) + ARA_TAHMIN[0]
        g[1] += ust + ARA_TAHMIN[1]
        g[2] += 1
        if alt is None:
            alt_bilinmeyen.append(k.etiket)
    alt = sum(v[0] for v in gruplar.values())
    ust = sum(v[1] for v in gruplar.values())
    return {"gruplar": {g: {"kosu": int(v[2]), "alt_sn": round(v[0]), "ust_sn": round(v[1])}
                        for g, v in gruplar.items()},
            "toplam_alt_sn": round(alt), "toplam_ust_sn": round(ust),
            "toplam_alt_sa": round(alt / 3600, 1), "toplam_ust_sa": round(ust / 3600, 1),
            "tek_geceye_sigar_mi": ust <= GECE_SN, "alt_siniri_bilinmeyen": alt_bilinmeyen,
            "not": "TAHMİN; boş makinede ölçülmedi; koşu arası pay her koşuya eklendi"}


def agac_hazirla(commit: str, ana_depo: Path, kuru: bool) -> tuple[Path, str]:
    """``~/karadul_olcum/urun-<kısa>``; yoksa ``git worktree add --detach`` + çalışma verisi bağları."""
    tam = subprocess.run(["git", "-C", str(ana_depo), "rev-parse", "--verify", f"{commit}^{{commit}}"],
                         capture_output=True, text=True, check=True).stdout.strip()
    kisa = tam[:7]
    agac = OLCUM / f"urun-{kisa}"
    if agac.exists() or kuru:
        return agac, kisa
    subprocess.run(["git", "-C", str(ana_depo), "worktree", "add", "--detach", str(agac), tam], check=True)
    for ad in CALISMA_VERISI:
        (agac / ad).symlink_to(ana_depo / ad)
    return agac, kisa


# ---------------------------------------------------------------------------- koşturma

class DiskDolu(Exception):
    pass


_AKTIF: set[int] = set()  # koşan kuyruk / hz0_ek süreç grupları (kesilirse SIGTERM gider)


def _kesinti(signum, _cerceve):  # noqa: ANN001
    for pgid in list(_AKTIF):
        try:
            os.killpg(pgid, signal.SIGTERM)  # olcek_kos SIGTERM'de karadul'u kapatır, BITTI = kesildi
        except ProcessLookupError:
            pass
    raise SystemExit(128 + signum)


def _gunluk(kok: Path, metin: str) -> None:
    satir = f"{_simdi()} {metin}"
    print(satir, flush=True)
    with open(kok / "gece.log", "a", encoding="utf-8") as f:
        f.write(satir + "\n")


def _canli(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _sakla(kok: Path, ek: str) -> Path:
    """``kok``'u ``<kok>.<ek><k>`` adıyla kenara al (silme yok)."""
    k = 1
    while kok.with_name(f"{kok.name}.{ek}{k}").exists():
        k += 1
    hedef = kok.with_name(f"{kok.name}.{ek}{k}")
    kok.rename(hedef)
    return hedef


def bitti_mi(kok: Path) -> bool:
    try:
        return (kok / "BITTI").read_text(encoding="utf-8").strip() not in ("", "kesildi")
    except OSError:
        return False


def _komut(k: Kosu, agac: Path, paket: str, deneme: int) -> list[str]:
    etiket = k.etiket if deneme == 1 else f"{k.etiket}/d{deneme}"
    if k.tur == "p16c":
        ic = [sys.executable, str(P16C), "kos", "--kok", str(k.kok), "--etiket", "hz0",
              "--yalniz", "debian/coreutils/sort", "--yalniz", "mac/tmux", "--agac", str(agac)]
    else:
        ic = [sys.executable, str(OLCEK_KOS), "--agac", str(agac), "--hedef", str(k.hedef),
              "--kok", str(k.kok), "--duvar-sn", str(int(k.duvar)), "--etiket", k.etiket,
              "--kill-bekle-sn", str(KILL_BEKLE_SN)]
        if k.ayar:
            ic += ["--ayar", str(k.ayar)]
        if k.java_ek:
            ic += [f"--java-ek={k.java_ek}"]  # değer "-XX:" ile başlıyor: ayrı belirteç argparse'ı bozar
    return [str(KUYRUK), paket, etiket, *ic]


def calistir(k: Kosu, agac: Path, paket: str, deneme: int, gunluk_kok: Path) -> dict[str, Any]:
    """Tek denemeyi kuyrukta koştur; eşlik eden ``hz0_ek``'i başlat. Dönen: süreç bilgisi."""
    k.kok.mkdir(parents=True, exist_ok=True)
    ortam = dict(os.environ, PYTHONHASHSEED="0", PYTHONDONTWRITEBYTECODE="1")
    if k.tur == "p16c":
        ortam["KARADUL_CACHE_DIR"] = str(k.kok / "cache")
    t0 = time.monotonic()
    with open(k.kok.parent / f"{k.kok.name}.kuyruk.log", "a", encoding="utf-8") as log:
        p = subprocess.Popen(_komut(k, agac, paket, deneme), cwd=DEPO, env=ortam, stdout=log,
                             stderr=subprocess.STDOUT, start_new_session=True)
        _AKTIF.add(p.pid)
        ek = None
        if k.hz0_ek:
            while p.poll() is None and not (k.kok / "pid.json").exists():
                uyu(1.0)
            pj = _oku(k.kok / "pid.json") or {}
            if pj.get("karadul_pid") and p.poll() is None:
                ek = subprocess.Popen([sys.executable, str(HZ0_EK), "--pid", str(pj["karadul_pid"]),
                                       "--kok", str(k.kok)], cwd=DEPO, env=ortam, stdout=log,
                                      stderr=subprocess.STDOUT, start_new_session=True)
                _AKTIF.add(ek.pid)
        try:
            kod = p.wait(timeout=k.duvar + KILL_BEKLE_SN + KUYRUK_PAYI_SN)
            disari = None
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGTERM)
            try:
                kod = p.wait(timeout=120)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                kod = p.wait()
            disari = "dış zaman sınırı"
        if ek is not None:
            try:
                ek.wait(timeout=900)
            except subprocess.TimeoutExpired:
                os.killpg(ek.pid, signal.SIGTERM)
            _AKTIF.discard(ek.pid)
        _AKTIF.discard(p.pid)
    if k.tur == "p16c" and kod == 0 and disari is None:
        (k.kok / "BITTI").write_text("tamam\n", encoding="utf-8")
    return {"cikis": kod, "sure_sn": round(time.monotonic() - t0, 1), "dis_sinir": disari}


def _oku(p: Path) -> Any:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def kos_bir(k: Kosu, agac: Path, a: argparse.Namespace, esik: float,
            calistirici: Callable[..., dict[str, Any]] | None = None) -> dict[str, Any]:
    """Bir koşu: sürdürme, boş makine bekleme / denetimi, en çok ``a.en_cok_deneme`` deneme."""
    calistirici = calistirici or calistir
    sonuc: dict[str, Any] = {"etiket": k.etiket, "kok": str(k.kok), "denemeler": []}
    if bitti_mi(k.kok):
        sonuc["durum"] = "atlandi_bitti"
        sonuc["gece_durum"] = _oku(k.kok / "gece_durum.json")
        return sonuc
    if k.kok.exists():
        pj = _oku(k.kok / "pid.json") or {}
        if _canli(pj.get("time_pid")) or _canli(pj.get("karadul_pid")):
            raise SystemExit(f"{k.kok}: önceki koşu hâlâ çalışıyor (pid.json); bekleyin ya da sonlandırın")
        sonuc["yarim_saklandi"] = str(_sakla(k.kok, "yarim"))
    en_cok = 1 if a.yuk_uyar else a.en_cok_deneme
    for deneme in range(1, en_cok + 1):
        bos = shutil.disk_usage(k.kok.parent if k.kok.parent.exists() else OLCUM).free
        if bos < a.disk_alt_gb * 1e9:
            raise DiskDolu(f"boş alan {bos / 1e9:.1f} GB < {a.disk_alt_gb} GB")
        for d in k.hazirla:
            d.mkdir(parents=True, exist_ok=True)
        indi, okumalar, _ = bekle_sessiz(esik, a.yuk_bekle_sn)
        kayit: dict[str, Any] = {"deneme": deneme, "esik": esik, "on_bekleme_yuk": okumalar}
        if not indi and not a.yuk_uyar:
            kayit.update(gecerli=False, neden="başlamadan önce yük eşiğin altına inmedi; başlatılmadı")
            sonuc["denemeler"].append(kayit)
            continue
        kayit["calisma"] = calistirici(k, agac, a.kuyruk_paket, deneme, a.kok)
        son_indi, son_okuma, son_sn = bekle_sessiz(esik, a.son_bekle_sn)
        kunye = _oku(k.kok / "kunye.json") or {}
        yuk_bas = (kunye.get("yuk_bas") or [None])[0]
        if yuk_bas is None and k.tur == "p16c":
            yuk_bas = okumalar[-1]
        gecerli, neden = gecerlilik(yuk_bas, son_indi, esik)
        kayit.update(yuk_bas=yuk_bas, son_yuk=son_okuma, son_bekleme_sn=son_sn, gecerli=gecerli,
                     neden=neden, bitti=(k.kok / "BITTI").read_text().strip()
                     if (k.kok / "BITTI").exists() else None)
        sonuc["denemeler"].append(kayit)
        if kayit["bitti"] is None:
            kayit["neden"] = f"koşu BITTI yazmadı (çıkış {kayit['calisma'].get('cikis')}); yinelenmez"
            sonuc["durum"] = "hata"
            return sonuc
        (k.kok / "gece_durum.json").write_text(json.dumps(kayit, ensure_ascii=False, indent=1) + "\n",
                                               encoding="utf-8")
        if gecerli or a.yuk_uyar or deneme == en_cok:
            sonuc["durum"] = "gecerli" if gecerli else "gecersiz"
            return sonuc
        sonuc.setdefault("gecersiz_saklanan", []).append(str(_sakla(k.kok, "gecersiz")))
    sonuc["durum"] = "baslatilamadi"
    return sonuc


def yayilim(kokler: list[Path]) -> float | None:
    """Geçerli tekrarların uçtan uca sürelerinde (en büyük − en küçük) / ortanca; < 3 geçerli → None."""
    import statistics
    degerler = []
    for kok in kokler:
        durum = _oku(kok / "gece_durum.json") or {}
        toplam = ((_oku(kok / "kunye.json") or {}).get("boru") or {}).get("toplam_sn")
        if durum.get("gecerli") and isinstance(toplam, (int, float)):
            degerler.append(float(toplam))
    if len(degerler) < 3:
        return None
    return (max(degerler) - min(degerler)) / statistics.median(degerler)


def hz0_ek_tekrarlar(hz0: list[Kosu], agac: Path, a: argparse.Namespace, esik: float,
                     kosucu: Callable[..., dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """HZ-0 kabulü: hedefte yayılım > 0,10 ise en çok ``EK_TEKRAR`` tekrar daha (yayılım düşünce durur)."""
    kosucu = kosucu or kos_bir
    sonuclar = []
    for kod in dict.fromkeys(k.kod for k in hz0):
        kosular = [k for k in hz0 if k.kod == kod]
        for _ in range(EK_TEKRAR):
            y = yayilim([k.kok for k in kosular])
            if y is None or y <= YAYILIM_ESIGI:
                break
            ilk = kosular[0]
            n = max(k.tekrar for k in kosular) + 1
            yeni = Kosu(grup=ilk.grup, kod=kod, tekrar=n, kok=ilk.kok.parent / str(n), hedef=ilk.hedef,
                        duvar=ilk.duvar, etiket=f"{ilk.grup}:{kod}#{n}", ayar=ilk.ayar, java_ek=ilk.java_ek,
                        hz0_ek=ilk.hz0_ek)
            _gunluk(a.kok, f"{kod}: yayılım {y:.3f} > {YAYILIM_ESIGI} → ek tekrar {yeni.etiket}")
            s = kosucu(yeni, agac, a, esik)
            s["ek_tekrar_nedeni"] = f"yayılım {y:.3f} > {YAYILIM_ESIGI}"
            sonuclar.append(s)
            kosular.append(yeni)
    return sonuclar


# ---------------------------------------------------------------------------- ana akış

def _gruplar(a: argparse.Namespace) -> tuple[str, ...]:
    secili = list(GECE_GRUPLARI[a.gece]) if a.gece else []
    secili += [g for g in a.yalniz if g not in secili]
    if not secili:
        secili = list(GECE_GRUPLARI["hepsi"])
    if not a.paket_e and "paket_e" in secili and "paket_e" not in a.yalniz:
        secili.remove("paket_e")
    return tuple(g for g in KUYRUK_GRUPLARI if g in secili)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--commit", required=True, help="ölçülecek ürün commit'i")
    ap.add_argument("--agac", type=Path, default=None, help="ürün ağacı (öntanım ~/karadul_olcum/urun-<kısa>)")
    ap.add_argument("--ana-depo", type=Path, default=ANA_DEPO)
    ap.add_argument("--kok", type=Path, default=None, help="öntanım ~/karadul_olcum/runs/gece-<kısa>")
    ap.add_argument("--avast-kok", type=Path, default=None,
                    help="öntanım ~/karadul_olcum/runs/hiz-avast-dislama/<kısa>")
    ap.add_argument("--gece", choices=sorted(GECE_GRUPLARI), default=None)
    ap.add_argument("--yalniz", action="append", default=[], choices=KUYRUK_GRUPLARI)
    ap.add_argument("--kuru", action="store_true", help="koşma; planı ve TAHMİNİ süreyi bas")
    ap.add_argument("--avast-dislama-yapildi", action="store_true",
                    help="Berke avast kökünü Avast'ta dışladı (yoksa avast grubu atlanır)")
    ap.add_argument("--avast-hazirla", action="store_true", help="yalnız avast kökünü oluştur ve yolunu bas")
    ap.add_argument("--paket-e", action="store_true", help="isteğe bağlı PAKET-E'yi kuyruğa ekle")
    ap.add_argument("--kuyruk-paket", default="GECE", help="ghidra_kuyruk.sh paket adı")
    ap.add_argument("--en-cok-deneme", type=int, default=EN_COK_DENEME)
    ap.add_argument("--yuk-bekle-sn", type=float, default=YUK_BEKLE_SN)
    ap.add_argument("--son-bekle-sn", type=float, default=SON_BEKLE_SN)
    ap.add_argument("--yuk-uyar", action="store_true",
                    help="yük denetimi koşuyu engellemez, yalnız geçersiz işaretler (tek deneme; gündüz dumanı)")
    ap.add_argument("--disk-alt-gb", type=float, default=DISK_ALT_GB)
    ap.add_argument("--yayilim-ek-yok", action="store_true",
                    help="HZ-0 yayılımı > 0,10 olan hedefe ek tekrar koşma (öntanım: en çok 2 ek tekrar)")
    a = ap.parse_args(argv)

    if a.agac is not None:
        agac, kisa = a.agac.expanduser().resolve(), a.commit[:7]
    else:
        agac, kisa = agac_hazirla(a.commit, a.ana_depo, a.kuru)
    a.kok = (a.kok or OLCUM / "runs" / f"gece-{kisa}").expanduser()
    avast_kok = (a.avast_kok or OLCUM / "runs" / "hiz-avast-dislama" / kisa).expanduser()
    if a.avast_hazirla:
        avast_kok.mkdir(parents=True, exist_ok=True)
        print(avast_kok)
        return 0
    gruplar = _gruplar(a)
    kuyruk = kuyruk_olustur(gruplar, a.kok, avast_kok, a.kuru)
    esik = yuk_esigi()
    tahmin = tahmin_ozeti(kuyruk)
    plan = {"commit": a.commit, "agac": str(agac), "kok": str(a.kok), "avast_kok": str(avast_kok),
            "gruplar": list(gruplar), "yuk_esigi": esik, "tahmin": tahmin,
            "kosular": [{"etiket": k.etiket, "kok": str(k.kok), "hedef": str(k.hedef) if k.hedef else None,
                         "ayar": str(k.ayar) if k.ayar else None, "duvar_sn": k.duvar, "java_ek": k.java_ek,
                         "hz0_ek": k.hz0_ek, "tahmin_sn": list(k.tahmin[:2]), "kaynak": k.tahmin[2]}
                        for k in kuyruk]}
    if a.kuru:
        print(f"Gece kuyruğu ({len(kuyruk)} koşu; ürün {a.commit} → {agac}{'' if agac.exists() else ' [oluşturulacak]'})")
        print(f"kök {a.kok}; avast kökü {avast_kok}; boş makine eşiği 1 dk yük < {esik:.2f}")
        for k in kuyruk:
            alt, ust, kaynak = k.tahmin
            print(f"  {k.etiket:16} duvar {int(k.duvar):>5} sn  TAHMİN [{'?' if alt is None else int(alt)}; "
                  f"{int(ust)}] sn  {k.hedef if k.hedef else ''}{'  + hz0_ek' if k.hz0_ek else ''}")
        for g, v in tahmin["gruplar"].items():
            print(f"  grup {g:9} {v['kosu']:2} koşu  TAHMİN [{v['alt_sn'] / 3600:.1f}; {v['ust_sn'] / 3600:.1f}] sa "
                  f"(koşu arası pay dahil)")
        print(f"TAHMİNİ toplam [{tahmin['toplam_alt_sa']}; {tahmin['toplam_ust_sa']}] sa; tek geceye (10 sa) "
              f"{'sığar' if tahmin['tek_geceye_sigar_mi'] else 'SIĞMAZ'}")
        if "hz0" in gruplar and not a.yayilim_ek_yok:
            ek = sum(EK_TEKRAR * (TAHMIN[kod][1] + ARA_TAHMIN[1]) for kod in ("K", "O", "B"))
            print(f"  en kötü durum: HZ-0 yayılımı > {YAYILIM_ESIGI} çıkan her hedefe en çok {EK_TEKRAR} ek "
                  f"tekrar; üçünde birden üst TAHMİN +{ek / 3600:.1f} sa (yalnız B: "
                  f"+{EK_TEKRAR * (TAHMIN['B'][1] + ARA_TAHMIN[1]) / 3600:.1f} sa)")
        if "avast" in gruplar and not a.avast_dislama_yapildi:
            print("  not: --avast-dislama-yapildi verilmedi → avast grubu koşuda atlanır")
        return 0

    a.kok.mkdir(parents=True, exist_ok=True)
    kilit = a.kok / "gece.pid"
    eski = _oku(kilit) or {}
    if _canli(eski.get("pid")) and eski.get("pid") != os.getpid():
        raise SystemExit(f"başka bir gece koşusu çalışıyor (pid {eski['pid']})")
    kilit.write_text(json.dumps({"pid": os.getpid(), "baslangic": _simdi()}) + "\n")
    for s in (signal.SIGTERM, signal.SIGINT):
        signal.signal(s, _kesinti)
    agac_bas = agac_kunyesi(agac)  # yanlış ağaçta hiç başlamaz
    ozet: dict[str, Any] = {"plan": plan, "agac": agac_bas, "donanim": donanim_kunyesi(),
                            "baslangic": _simdi(), "sonuclar": []}
    (a.kok / "plan.json").write_text(json.dumps(plan, ensure_ascii=False, indent=1) + "\n")
    _gunluk(a.kok, f"başladı: {len(kuyruk)} koşu, gruplar {','.join(gruplar)}, eşik {esik:.2f}")
    hz0 = [k for k in kuyruk if k.grup == "hz0"]
    try:
        for k in kuyruk:
            if k.grup == "avast" and not a.avast_dislama_yapildi:
                ozet["sonuclar"].append({"etiket": k.etiket, "durum": "atlandi_onay_yok",
                                         "neden": "Berke'nin Avast dışlaması bildirilmedi (--avast-dislama-yapildi)"})
                continue
            _gunluk(a.kok, f"{k.etiket} başlıyor (TAHMİN üst {int(k.tahmin[1])} sn)")
            s = kos_bir(k, agac, a, esik)
            ozet["sonuclar"].append(s)
            _gunluk(a.kok, f"{k.etiket}: {s['durum']} ({len(s['denemeler'])} deneme)")
            if hz0 and k is hz0[-1] and not a.yayilim_ek_yok:
                ozet["sonuclar"].extend(hz0_ek_tekrarlar(hz0, agac, a, esik))
    except DiskDolu as e:
        ozet["durdu"] = f"disk: {e}"
        _gunluk(a.kok, f"DURDU: {e}")
    finally:
        ozet["bitis"] = _simdi()
        ozet["sayim"] = {d: sum(1 for s in ozet["sonuclar"] if s.get("durum") == d)
                         for d in ("gecerli", "gecersiz", "atlandi_bitti", "atlandi_onay_yok", "hata",
                                   "baslatilamadi")}
        damga = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        for ad in ("ozet.json", f"ozet_{damga}.json"):
            (a.kok / ad).write_text(json.dumps(ozet, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        kilit.unlink(missing_ok=True)
    _gunluk(a.kok, f"bitti: {ozet['sayim']}")
    return 0 if not ozet.get("durdu") and not ozet["sayim"]["hata"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
