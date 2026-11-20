#!/usr/bin/env python3
"""ÖLÇ-A ölçek koşucusu: tek hedef için ``karadul analyze``'ı süre, bellek, disk ve JVM gözlemiyle sarar.

Plan: ``docs/arge/2026-11-19_mythos/olcek/PLAN.md`` ÖLÇ-A. Ürün kodu değişmez; ürün ``--agac``'tan
yüklenir ve bu koşudan önce denetlenir (``urun_kos.agac_kunyesi``; kod kopyalanmaz, içe aktarılır).

Kullanım (depo kökünden; Ghidra başlatan her komut ``~/karadul_olcum/ghidra_kuyruk.sh`` ile sarılır):

    python scripts/measurement/olcek_kos.py --agac ~/karadul_olcum/urun-<commit> \\
        --hedef <dosya ya da .app> --kok <koşu dizini> --duvar-sn 7200 [--ayar <yaml>] [--etiket <ad>] \\
        [--java-ek "<ek JVM seçenekleri>"]

Koşu: ``/usr/bin/time -l <python> -m karadul analyze <hedef> --skip-dynamic --output-dir <kök>/ws
--output <kök>/out [--config <yaml>]``; ortam ``PYTHONHASHSEED=0``, ``KARADUL_CACHE_DIR=<kök>/cache``,
``JAVA_TOOL_OPTIONS=-Xlog:gc*:file=<kök>/gc.log:time,uptime`` (+ ``--java-ek``). Çıktı ``<kök>/kosu.log``.

Kökte oluşanlar:
- ``pid.json``: ``time`` süreci ve ``karadul`` süreci (eşlik eden örnekleyiciler için; ör. HZ-0 ``hz0_ek.py``);
- ``ornekler.csv``: 10 sn'de bir süreç ağacının RSS'i (``ps -A -o pid=,ppid=,rss=``: kök süreç + bütün
  torunları), yük ortalaması; 60 sn'de bir kökün disk kullanımı (``os.scandir``, ayrılan bayt). Disk
  taraması uzarsa (çok dosya) bir sonraki tarama en erken taramanın 5 katı sonra yapılır: ölçüm koşuyu
  boğmasın (künyede ``disk_tarama_en_uzun_sn``);
- ``BITTI``: tek satır durum (``tamam`` / ``kismi`` / ``zaman_asimi`` / ``cikis_<n>`` / ``kesildi``),
  ``CIKIS``: çıkış kodu;
- ``kunye.json``: başlangıç / bitiş, çıkış kodu, ``time -l`` alanları, tepe RSS (örneklerden), tepe disk,
  yük (baş / son), Ghidra adım süreleri ve kaynağı, aşama süreleri, ilk rapor zamanı, dosya sayısı,
  GC duraklama özeti, paket bileşenleri, ağaç künyesi (baş / son).

Duvar: ``--duvar-sn`` dolunca ``karadul`` sürecine (``time``'ın çocuklarına) SIGTERM, ``--kill-bekle-sn``
(öntanım 60) sonra süreç grubuna SIGKILL; ``BITTI`` = ``zaman_asimi``. ``time``'a SIGTERM gönderilmez:
``time -l`` satırları kısa kesilen koşuda da yazılsın (gösteri 1. denemedeki gibi).

Ghidra adım süreleri: ``static/ghidra_status.json``'da ``adim_sureleri`` alanı varsa (HZ-1) o; yoksa
``ghidra_output/*.json`` dosyalarının değişim zamanlarından (``scripts/arge/olcek/olcek_topla.py``
``ghidra_adim_sureleri`` mantığı; işlev buraya taşındı, araştırma betiği değişmedi). Köprü yarıda
kaldıysa (``ghidra_status.json`` yok) her çıktının koşu başından beri saniyesi ve "nerede kaldı".

Test kancası: ``--komut "<komut>"`` analiz komutunun yerine geçer (Ghidra'sız testler); geri kalan her şey
(``time -l``, ortam, örnekleyici, duvar, künye) aynıdır.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from urun_kos import GHIDRA, agac_kunyesi  # noqa: E402  (kod kopyalanmaz: ÖLÇ-A adım 1)

ORNEK_ARALIK_SN = 10.0
DISK_ARALIK_SN = 60.0
KILL_BEKLE_SN = 60.0
DISK_TARAMA_CARPANI = 5.0
ZAMANLAYICI = "/usr/bin/time"
CSV_BASLIK = ("zaman", "gecen_sn", "rss_kib", "surec", "disk_ayrilan_bayt", "disk_dosya",
              "disk_tarama_sn", "yuk1", "yuk5", "yuk15")

# Köprünün adımları çıktısını adım bitince yazar (karadul/ghidra/headless.py:_analyze_pyghidra).
# Sıra ve etiketler scripts/arge/olcek/olcek_topla.py GHIDRA_ADIM_SIRASI ile aynı.
GHIDRA_ADIM_SIRASI = (
    ("functions.json", "otomatik_analiz+fonksiyonlar"),
    ("strings.json", "dizgiler"),
    ("call_graph.json", "cagri_grafigi"),
    ("decompiled.json", "decompile"),
    ("types.json", "tipler"),
    ("xrefs.json", "xref"),
    ("pcode.json", "pcode_yazimi"),
    ("cfg.json", "cfg"),
    ("function_id.json", "function_id"),
    ("bsim_shadow.json", "bsim"),
    ("combined_results.json", "ozet"),
)

_TIME_RUS = re.compile(r"^\s*(\d+(?:\.\d+)?)\s+real\s+(\d+(?:\.\d+)?)\s+user\s+(\d+(?:\.\d+)?)\s+sys\s*$",
                       re.M)
_TIME_KV = re.compile(r"^\s*(\d+)\s+([a-z][a-z ]*[a-z])\s*$", re.M)
# -Xlog:gc*:...:time,uptime biçiminde etiket görünmez; duraklama özet satırı yığın geçişini taşır:
# "[..][..] GC(12) Pause Young (Normal) (G1 Evacuation Pause) 100M->50M(200M) 12.345ms"
_GC_DURAKLAMA = re.compile(r"GC\((\d+)\)\s+Pause\b.*?\d+[KMG]->\d+[KMG]\(\d+[KMG]\)\s+(\d+(?:\.\d+)?)ms\s*$",
                           re.M)


def _simdi() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def _sha(yol: Path) -> str:
    h = hashlib.sha256()
    with open(yol, "rb") as f:
        for parca in iter(lambda: f.read(1 << 20), b""):
            h.update(parca)
    return h.hexdigest()


def _oku_json(p: Path) -> Any:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _yaz_json(p: Path, veri: Any) -> None:
    gecici = p.with_name(p.name + ".yaziliyor")
    gecici.write_text(json.dumps(veri, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    os.replace(gecici, p)


# ---------------------------------------------------------------------------- ayrıştırıcılar

def time_l_ayristir(metin: str | None) -> dict[str, Any]:
    """``/usr/bin/time -l`` çıktısı: son ``real/user/sys`` satırı ve ardından gelen sayaç satırları."""
    if not metin:
        return {}
    eslesmeler = list(_TIME_RUS.finditer(metin))
    if not eslesmeler:
        return {}
    m = eslesmeler[-1]
    out: dict[str, Any] = {"real_sn": float(m.group(1)), "user_sn": float(m.group(2)),
                           "sys_sn": float(m.group(3))}
    for v, ad in _TIME_KV.findall(metin[m.end():]):
        out[ad.replace(" ", "_")] = int(v)
    return out


def gc_ozeti(yol: Path) -> dict[str, Any]:
    """JVM ``-Xlog:gc*`` günlüğünden duraklama sayısı ve toplamı (ms)."""
    try:
        metin = yol.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {"gc_log_var": False}
    sureler = [float(ms) for _, ms in _GC_DURAKLAMA.findall(metin)]
    return {"gc_log_var": True, "gc_log_bayt": len(metin.encode("utf-8")),
            "duraklama_sayisi": len(sureler),
            "duraklama_toplam_ms": round(sum(sureler), 3),
            "duraklama_en_uzun_ms": max(sureler) if sureler else None}


def ghidra_adim_sureleri(go: Path, ghidra_sn: float | None) -> dict[str, Any]:
    """``ghidra_output/`` dosyalarının değişim zamanından adım süreleri (sn).

    Başlangıç = ``combined_results.json`` zamanı − ``ghidra_sn`` (köprünün toplam süresi). İlk adım
    JVM açılışı + içe aktarma + otomatik analiz + fonksiyon listesidir. Dosyası olmayan adım atlanır;
    süresi bir sonrakine eklenir. (``scripts/arge/olcek/olcek_topla.py``'den taşındı.)
    """
    zaman = {}
    for ad, _ in GHIDRA_ADIM_SIRASI:
        try:
            zaman[ad] = (go / ad).stat().st_mtime
        except OSError:
            pass
    if "combined_results.json" not in zaman or not ghidra_sn:
        return {}
    onceki = zaman["combined_results.json"] - float(ghidra_sn)
    out: dict[str, Any] = {}
    for ad, etiket in GHIDRA_ADIM_SIRASI:
        if ad in zaman:
            out[etiket] = round(zaman[ad] - onceki, 3)
            onceki = zaman[ad]
    return out


def _disk(kok: Path) -> dict[str, int]:
    """Ayrılan bayt (st_blocks × 512), görünen bayt ve dosya sayısı (bağlar izlenmez)."""
    ayrilan = gorunen = dosya = 0
    yigin = [kok]
    while yigin:
        d = yigin.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        if e.is_dir(follow_symlinks=False):
                            yigin.append(Path(e.path))
                            continue
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    ayrilan += st.st_blocks * 512
                    gorunen += st.st_size
                    dosya += 1
        except OSError:
            continue
    return {"ayrilan": ayrilan, "gorunen": gorunen, "dosya": dosya}


def _dogum(p: Path) -> tuple[float | None, str]:
    try:
        st = p.stat()
    except OSError:
        return None, "yok"
    t = getattr(st, "st_birthtime", None)
    return (t, "st_birthtime") if t else (st.st_mtime, "st_mtime")


# ---------------------------------------------------------------------------- süreç ağacı

def _ps_tablosu() -> dict[int, tuple[int, int]]:
    """pid → (ppid, rss KiB)."""
    out = subprocess.run(["ps", "-A", "-o", "pid=,ppid=,rss="], capture_output=True, text=True).stdout
    tablo: dict[int, tuple[int, int]] = {}
    for satir in out.splitlines():
        p = satir.split()
        if len(p) == 3 and all(x.isdigit() for x in p):
            tablo[int(p[0])] = (int(p[1]), int(p[2]))
    return tablo


def torunlar(kok_pid: int, tablo: dict[int, tuple[int, int]] | None = None) -> list[int]:
    """``kok_pid``'in bütün torunları (kendisi hariç), genişlik öncelikli."""
    tablo = _ps_tablosu() if tablo is None else tablo
    cocuklar: dict[int, list[int]] = {}
    for pid, (ppid, _) in tablo.items():
        cocuklar.setdefault(ppid, []).append(pid)
    sira, kuyruk = [], list(cocuklar.get(kok_pid, []))
    while kuyruk:
        p = kuyruk.pop(0)
        sira.append(p)
        kuyruk.extend(cocuklar.get(p, []))
    return sira


def agac_rss(kok_pid: int) -> tuple[int, int] | None:
    """Kök süreç + torunlarının RSS toplamı (KiB) ve süreç sayısı; kök yoksa None."""
    tablo = _ps_tablosu()
    if kok_pid not in tablo:
        return None
    pidler = [kok_pid, *torunlar(kok_pid, tablo)]
    return sum(tablo[p][1] for p in pidler if p in tablo), len(pidler)


class Ornekleyici(threading.Thread):
    """``aralik`` sn'de bir RSS ve yük; ``disk_aralik`` sn'de bir kökün diski → ``ornekler.csv``."""

    def __init__(self, kok: Path, pid: int, t0: float, aralik: float, disk_aralik: float) -> None:
        super().__init__(daemon=True)
        self.kok, self.pid, self.t0 = kok, pid, t0
        self.aralik, self.disk_aralik = aralik, disk_aralik
        self.dur = threading.Event()
        self.tepe_rss_kib = 0
        self.tepe_rss_sn: float | None = None
        self.tepe_disk = 0
        self.disk_en_uzun_sn = 0.0
        self.satir = 0

    def run(self) -> None:
        sonraki_disk = 0.0
        with open(self.kok / "ornekler.csv", "w", encoding="utf-8") as f:
            f.write(",".join(CSV_BASLIK) + "\n")
            f.flush()
            while True:
                simdi = time.monotonic()
                gecen = simdi - self.t0
                rss = agac_rss(self.pid)
                disk, tarama = None, None
                if simdi >= sonraki_disk:
                    d0 = time.monotonic()
                    disk = _disk(self.kok)
                    tarama = time.monotonic() - d0
                    self.disk_en_uzun_sn = max(self.disk_en_uzun_sn, tarama)
                    self.tepe_disk = max(self.tepe_disk, disk["ayrilan"])
                    sonraki_disk = simdi + max(self.disk_aralik, DISK_TARAMA_CARPANI * tarama)
                if rss is not None and rss[0] > self.tepe_rss_kib:
                    self.tepe_rss_kib, self.tepe_rss_sn = rss[0], round(gecen, 1)
                y = os.getloadavg()
                f.write(",".join(str(x) for x in (
                    _simdi(), round(gecen, 1), "" if rss is None else rss[0],
                    "" if rss is None else rss[1], "" if disk is None else disk["ayrilan"],
                    "" if disk is None else disk["dosya"], "" if tarama is None else round(tarama, 3),
                    round(y[0], 2), round(y[1], 2), round(y[2], 2))) + "\n")
                f.flush()
                self.satir += 1
                if self.dur.wait(self.aralik):
                    return


# ---------------------------------------------------------------------------- künye toplama

def _calisma_alanlari(kok: Path) -> list[Path]:
    return sorted(p for p in (kok / "ws" / "workspaces").glob("*/*") if p.is_dir())


def ghidra_kunyesi(ws: Path, t0_epoch: float) -> dict[str, Any]:
    """Bir çalışma alanının Ghidra adım süreleri ve kaynağı; yarıda kaldıysa nerede kaldığı."""
    static = ws / "static"
    go = static / "ghidra_output"
    durum = _oku_json(static / "ghidra_status.json")
    out: dict[str, Any] = {"ghidra_status_var": isinstance(durum, dict)}
    if isinstance(durum, dict):
        out["ghidra_sn"] = durum.get("duration_seconds")
        out["ghidra_basari"] = durum.get("success")
        out["fonksiyon"] = (durum.get("functions") or {}).get("total")
        if isinstance(durum.get("analysis"), dict):
            out["ghidra_analysis"] = durum["analysis"]
        adim = durum.get("adim_sureleri")
        if isinstance(adim, dict) and adim:
            out["adim_sureleri"], out["adim_kaynagi"] = adim, "ghidra_status.adim_sureleri"
    if "adim_sureleri" not in out:
        adim = ghidra_adim_sureleri(go, out.get("ghidra_sn"))
        out["adim_sureleri"] = adim or None
        out["adim_kaynagi"] = "dosya_zamani" if adim else "yok"
    # Her çıktının koşu başından beri saniyesi ve son biten adım (yarıda kalan koşu için).
    zamanlar: dict[str, float] = {}
    son_adim = None
    for ad, etiket in GHIDRA_ADIM_SIRASI:
        try:
            zamanlar[ad] = round((go / ad).stat().st_mtime - t0_epoch, 1)
            son_adim = etiket
        except OSError:
            pass
    out["cikti_zamani_sn"] = zamanlar
    out["son_biten_adim"] = son_adim
    dec = go / "decompiled"
    if dec.is_dir():
        sayi, son = 0, None
        with os.scandir(dec) as it:
            for e in it:
                if e.is_file():
                    sayi += 1
                    m = e.stat().st_mtime
                    son = m if son is None or m > son else son
        out["decompiled_c"] = {"sayi": sayi, "son_sn": round(son - t0_epoch, 1) if son else None}
    return out


def boru_kunyesi(ws: Path, t0_epoch: float) -> dict[str, Any]:
    pr = _oku_json(ws / "reports" / "pipeline_result.json")
    out: dict[str, Any] = {"pipeline_result_var": isinstance(pr, dict)}
    if isinstance(pr, dict):
        out["toplam_sn"] = pr.get("total_duration")
        out["basari"] = pr.get("success")
        out["asama_sn"] = {ad: (s or {}).get("duration_seconds")
                           for ad, s in (pr.get("stages") or {}).items()}
        rc = ((pr.get("stages") or {}).get("reconstruct") or {}).get("stats") or {}
        out["reconstruct_timing"] = {k[len("timing_"):]: v for k, v in rc.items()
                                     if k.startswith("timing_") and isinstance(v, (int, float))}
    t, kaynak = _dogum(ws / "reports" / "report.json")
    out["ilk_rapor_sn"] = round(t - t0_epoch, 1) if t is not None else None
    out["ilk_rapor_kaynagi"] = kaynak
    return out


def paket_kunyesi(ws: Path) -> dict[str, Any] | None:
    """``.app`` hedefi: biten bileşenler (``components/*/static/ghidra_status.json``)."""
    bilesen_dizinleri = sorted(p for p in (ws / "components").glob("*") if p.is_dir())
    if not bilesen_dizinleri:
        return None
    biten = []
    for b in bilesen_dizinleri:
        st = _oku_json(b / "static" / "ghidra_status.json")
        if isinstance(st, dict):
            biten.append({"bilesen": b.name, "ghidra_sn": st.get("duration_seconds"),
                          "basari": st.get("success")})
    return {"bilesen_dizini": len(bilesen_dizinleri), "ghidra_biten": len(biten), "bilesenler": biten,
            "bundle_analysis_var": (ws / "static" / "bundle_analysis.json").exists()}


def _java_ek_dosyalari(java_ek: str) -> dict[str, Any]:
    """``--java-ek`` içindeki dosya yolları (JFR kaydı, CDS arşivi): koşu sonunda var mı, boyutu."""
    out = {}
    for anahtar, desen in (("jfr", r"filename=([^,\s]+)"), ("cds", r"SharedArchiveFile=(\S+)")):
        m = re.search(desen, java_ek)
        if m:
            p = Path(m.group(1))
            out[anahtar] = {"yol": str(p), "var": p.exists(),
                            "bayt": p.stat().st_size if p.exists() else None}
    return out


# ---------------------------------------------------------------------------- koşu

class _Kesildi(Exception):
    pass


def _sonlandir(surec: subprocess.Popen, zamanlayici_var: bool, kill_bekle: float) -> str:
    """Duvar doldu: karadul'a SIGTERM, ``kill_bekle`` sn sonra gruba SIGKILL. Dönen: yol adı."""
    hedefler = [surec.pid]
    if zamanlayici_var:  # time'ın doğrudan çocukları (karadul); time'a dokunulmaz
        hedefler = [p for p, (pp, _) in _ps_tablosu().items() if pp == surec.pid] or hedefler
    for p in hedefler:
        try:
            os.kill(p, signal.SIGTERM)
        except ProcessLookupError:
            pass
    try:
        surec.wait(timeout=kill_bekle)
        return "sigterm"
    except subprocess.TimeoutExpired:
        try:
            os.killpg(surec.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        surec.wait()
        return "sigkill"


def _grubu_temizle(pgid: int) -> None:
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def analiz_komutu(hedef: Path, kok: Path, ayar: Path | None) -> list[str]:
    komut = [sys.executable, "-m", "karadul", "analyze", str(hedef), "--skip-dynamic",
             "--output-dir", str(kok / "ws"), "--output", str(kok / "out")]
    if ayar is not None:
        komut += ["--config", str(ayar)]
    return komut


def kos(a: argparse.Namespace) -> int:
    agac = a.agac.expanduser().resolve()
    kok = a.kok.expanduser().resolve()
    hedef = a.hedef.expanduser().resolve()
    ayar = a.ayar.expanduser().resolve() if a.ayar else None
    if a.duvar_sn <= 0:
        raise SystemExit("--duvar-sn > 0 olmalı")
    if re.search(r"\s", str(kok)):
        raise SystemExit(f"kök yolunda boşluk var ({kok}): JAVA_TOOL_OPTIONS ayrıştırması bozulur")
    if not hedef.exists():
        raise SystemExit(f"hedef yok: {hedef}")
    if ayar is not None and not ayar.is_file():
        raise SystemExit(f"ayar dosyası yok: {ayar}")
    if (kok / "BITTI").exists():
        raise SystemExit(f"{kok}: BITTI var (koşu bitmiş); yeni koşu için boş bir kök verin")
    agac_bas = agac_kunyesi(agac)  # yanlış ağaç → SystemExit; koşu başlamaz
    kok.mkdir(parents=True, exist_ok=True)
    (kok / "cache").mkdir(exist_ok=True)

    java = f"-Xlog:gc*:file={kok / 'gc.log'}:time,uptime"
    if a.java_ek:
        java += " " + a.java_ek
    ortam = dict(os.environ, PYTHONPATH=str(agac), PYTHONHASHSEED="0",
                 KARADUL_CACHE_DIR=str(kok / "cache"), JAVA_TOOL_OPTIONS=java)
    ortam.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA))
    ic = shlex.split(a.komut) if a.komut else analiz_komutu(hedef, kok, ayar)
    zamanlayici_var = os.access(ZAMANLAYICI, os.X_OK)
    komut = ([ZAMANLAYICI, "-l"] if zamanlayici_var else []) + ic

    kunye: dict[str, Any] = {
        "amac": "ÖLÇ-A ölçek koşusu (olcek/PLAN.md)", "etiket": a.etiket, "durum": "suruyor",
        "hedef": {"yol": str(hedef), "tur": "dizin" if hedef.is_dir() else "dosya",
                  "bayt": hedef.stat().st_size if hedef.is_file() else None,
                  "sha256": _sha(hedef) if hedef.is_file() else None},
        "ayar": {"yol": str(ayar), "sha256": _sha(ayar)} if ayar else None,
        "agac": agac_bas, "komut": komut, "test_komutu": bool(a.komut),
        "ortam": {k: ortam.get(k) for k in ("PYTHONHASHSEED", "KARADUL_CACHE_DIR", "JAVA_TOOL_OPTIONS",
                                            "GHIDRA_INSTALL_DIR", "PYTHONDONTWRITEBYTECODE", "PYTHONPATH")},
        "python": sys.version.split()[0], "duvar_sn": a.duvar_sn, "kill_bekle_sn": a.kill_bekle_sn,
        "ornek_aralik_sn": a.ornek_aralik, "disk_aralik_sn": a.disk_aralik,
        "cpu_sayisi": os.cpu_count(), "yuk_bas": list(os.getloadavg()), "baslangic": _simdi(),
    }
    _yaz_json(kok / "kunye.json", kunye)

    t0_epoch, t0 = time.time(), time.monotonic()
    durum, yol, kod = "kesildi", None, None

    def _sinyal(signum, _cerceve):  # noqa: ANN001
        raise _Kesildi(signum)

    eski = {s: signal.signal(s, _sinyal) for s in (signal.SIGTERM, signal.SIGINT)}
    ornekleyici = None
    surec = None
    try:
        with open(kok / "kosu.log", "w", encoding="utf-8") as gunluk:
            surec = subprocess.Popen(komut, cwd=agac, env=ortam, stdout=gunluk,
                                     stderr=subprocess.STDOUT, start_new_session=True)
            karadul_pid = None
            if zamanlayici_var:
                for _ in range(50):
                    cocuk = [p for p, (pp, _) in _ps_tablosu().items() if pp == surec.pid]
                    if cocuk or surec.poll() is not None:
                        karadul_pid = cocuk[0] if cocuk else None
                        break
                    time.sleep(0.1)
            else:
                karadul_pid = surec.pid
            _yaz_json(kok / "pid.json", {"time_pid": surec.pid if zamanlayici_var else None,
                                         "karadul_pid": karadul_pid, "baslangic": kunye["baslangic"]})
            ornekleyici = Ornekleyici(kok, surec.pid, t0, a.ornek_aralik, a.disk_aralik)
            ornekleyici.start()
            try:
                kod = surec.wait(timeout=a.duvar_sn)
                durum = {0: "tamam", 3: "kismi"}.get(kod, f"cikis_{kod}")
            except subprocess.TimeoutExpired:
                yol = _sonlandir(surec, zamanlayici_var, a.kill_bekle_sn)
                kod = surec.returncode
                durum = "zaman_asimi"
    except _Kesildi:
        if surec is not None and surec.poll() is None:
            yol = _sonlandir(surec, zamanlayici_var, min(a.kill_bekle_sn, 10.0))
            kod = surec.returncode
        durum = "kesildi"
    finally:
        for s, h in eski.items():
            signal.signal(s, h)
        if surec is not None:
            _grubu_temizle(surec.pid)
        if ornekleyici is not None:
            ornekleyici.dur.set()
            ornekleyici.join(timeout=30)
        sure = time.monotonic() - t0
        (kok / "BITTI").write_text(durum + "\n", encoding="utf-8")
        (kok / "CIKIS").write_text(f"{kod}\n", encoding="utf-8")
        kunye.update(_bitis_kunyesi(kok, agac, t0_epoch, sure, durum, yol, kod, ornekleyici,
                                    a.java_ek or ""))
        _yaz_json(kok / "kunye.json", kunye)
    print(f"[olcek_kos] {a.etiket or hedef.name}: {durum} ({kunye['sure_sn']} sn); künye {kok / 'kunye.json'}",
          flush=True)
    return 0 if durum in ("tamam", "kismi") else (4 if durum == "zaman_asimi" else 1)


def _bitis_kunyesi(kok: Path, agac: Path, t0_epoch: float, sure: float, durum: str, yol: str | None,
                   kod: int | None, ornekleyici: Ornekleyici | None, java_ek: str) -> dict[str, Any]:
    try:
        gunluk = (kok / "kosu.log").read_text(encoding="utf-8", errors="replace")
    except OSError:
        gunluk = ""
    out: dict[str, Any] = {
        "durum": durum, "sonlandirma": yol, "cikis_kodu": kod, "bitis": _simdi(),
        "sure_sn": round(sure, 1), "yuk_son": list(os.getloadavg()),
        "time_l": time_l_ayristir(gunluk),
        "ornek_sayisi": ornekleyici.satir if ornekleyici else 0,
        "tepe_rss_bayt": (ornekleyici.tepe_rss_kib * 1024) if ornekleyici else None,
        "tepe_rss_sn": ornekleyici.tepe_rss_sn if ornekleyici else None,
        "tepe_disk_bayt": ornekleyici.tepe_disk if ornekleyici else None,
        "disk_tarama_en_uzun_sn": round(ornekleyici.disk_en_uzun_sn, 3) if ornekleyici else None,
        "gc": gc_ozeti(kok / "gc.log"),
        "java_ek_dosyalari": _java_ek_dosyalari(java_ek),
        "disk_son": {"kok": _disk(kok), "ws": _disk(kok / "ws"), "out": _disk(kok / "out")},
    }
    alanlar = _calisma_alanlari(kok)
    out["calisma_alani"] = str(alanlar[-1]) if alanlar else None
    if alanlar:
        ws = alanlar[-1]
        out["ghidra"] = ghidra_kunyesi(ws, t0_epoch)
        out["boru"] = boru_kunyesi(ws, t0_epoch)
        out["paket"] = paket_kunyesi(ws)
    try:
        son = agac_kunyesi(agac)
        out["agac_bitiste"] = son
    except SystemExit as e:  # ağaç koşu sırasında bozulduysa künyeye yazılır
        out["agac_bitiste"] = {"hata": str(e)}
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--agac", type=Path, required=True, help="ürünün yükleneceği git ağacı")
    ap.add_argument("--hedef", type=Path, required=True, help="analiz edilecek dosya ya da .app")
    ap.add_argument("--kok", type=Path, required=True, help="koşu dizini (boş ya da yeni)")
    ap.add_argument("--duvar-sn", type=float, required=True, help="duvar sınırı (sn)")
    ap.add_argument("--ayar", type=Path, default=None, help="karadul --config yaml")
    ap.add_argument("--etiket", default="")
    ap.add_argument("--java-ek", default="", help="JAVA_TOOL_OPTIONS'a eklenecek JVM seçenekleri")
    ap.add_argument("--ornek-aralik", type=float, default=ORNEK_ARALIK_SN)
    ap.add_argument("--disk-aralik", type=float, default=DISK_ARALIK_SN)
    ap.add_argument("--kill-bekle-sn", type=float, default=KILL_BEKLE_SN)
    ap.add_argument("--komut", default=None, help="TEST KANCASI: analiz komutunun yerine (shlex)")
    return kos(ap.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
