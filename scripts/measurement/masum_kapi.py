#!/usr/bin/env python3
"""Masum ikili kapısı: tespit ve iddia katmanlarının zararsız ikililerde ürettiği iddiaları sayar.

Aynı koşuda gerçek pozitif seti de ölçülür; sıkılaştırma doğru tespiti düşürürse kapı düşer.
Ölçüt ve dosyalar: ``docs/arge/2026-11-18_onarim/P00.md`` (el kitabı).

İki kip:

* **doğrudan** (``--set``): ham ikili, Ghidra'sız. Katmanlar ürünün çağırdığı biçimde çağrılır:
  ``bi`` (``MachOAnalyzer.analyze_static``, Ghidra adımı devre dışı → ``intelligence_report``;
  IMZA-01), ``antidebug`` (IMZA-02/03), ``packer`` (IMZA-04), ``yara`` (IMZA-05), ``capa`` (IMZA-06).
* **çıktı** (``--kosu``): ``urun_kos.py`` düzenindeki bir koşu dizininin yapıtları
  (bileşim şablonları, koddaki algoritma ve ``@security`` etiketleri, SARIF, blok yorumu,
  ``types.h``, ``intelligence_report.json`` ...). Ayrıntı: ``CIKTI_KATMANLARI``.

Her iddia ``(katman, ikili, etiket)`` üçlüsüdür; kanıtı yanında yazılır. Masum setlerdeki
iddia, eşik dosyasındaki ``dogru_iddialar`` listesine uymuyorsa **yanlış** sayılır.
Pozitif setteki iddialar yanlış sayılmaz; onlar ``gercek_pozitifler`` beklentileriyle sınanır.

Çıkış kodu: 0 = eşik içinde ve zorunlu gerçek pozitifler yerinde; 1 = eşik aşıldı ya da
zorunlu gerçek pozitif kayboldu; 2 = kurulum hatası (yanlış ağaç, sabit set girdisi değişmiş, ...).

Kullanım:
    python scripts/measurement/masum_kapi.py --agac . --set gelistirme,macos,pe,pozitif \
        --cikti-dizin ~/karadul_olcum/runs/onarim-2026-11-18/<PAKET>/masum_once
    python scripts/measurement/masum_kapi.py --agac . --kosu ~/karadul_olcum/runs/<koşu> \
        --cikti-dizin <dizin> --karsilastir <önceki>/masum_kapi.json
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures as cf
import datetime as dt
import fnmatch
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

DEPO = Path(__file__).resolve().parents[2]
ESIK_DOSYASI = DEPO / "scripts/measurement/masum_kapi_esik.json"
SETLER_DOSYASI = DEPO / "docs/arge/2026-11-18_onarim/P00/setler.json"
POZITIF_KAYNAK = DEPO / "scripts/measurement/masum_kapi_pozitif"
POZITIF_DIZIN = Path.home() / "karadul_olcum/masum_kapi/pozitif"
GHIDRA_KOKU = Path.home() / "Library/BlackWidowBuild/ghidra_12.1.2_PUBLIC"

SETLER = ("gelistirme", "macos", "pe", "pozitif")
MASUM_SETLER = ("gelistirme", "macos", "pe")
DOGRUDAN_KATMANLAR = ("bi", "antidebug", "packer", "yara", "capa")

# (b) macOS sistem ikilileri. Evrensel (x86_64 + arm64e) ikililer bilerek içeride: ürün
# evrensel ikilide önce arm64, yoksa x86_64 dilimini seçer (macho.py lipo adımı).
MACOS_YOLLARI = (
    "/bin/ls", "/bin/cat", "/bin/cp", "/bin/mv", "/bin/pwd", "/bin/chmod", "/bin/mkdir",
    "/bin/rm", "/bin/echo", "/bin/date", "/bin/dd", "/bin/ps", "/bin/kill", "/bin/zsh",
    "/bin/bash",
    "/usr/bin/true", "/usr/bin/vim", "/usr/bin/ssh", "/usr/bin/top", "/usr/bin/openssl",
    "/usr/bin/curl", "/usr/bin/grep", "/usr/bin/find", "/usr/bin/gzip", "/usr/bin/zip",
    "/usr/bin/unzip", "/usr/bin/less", "/usr/bin/awk", "/usr/bin/sed", "/usr/bin/diff",
    "/usr/bin/sort", "/usr/bin/wc", "/usr/bin/head", "/usr/bin/tail", "/usr/bin/file",
    "/usr/bin/hexdump", "/usr/bin/bc", "/usr/bin/sqlite3", "/usr/bin/base64", "/usr/bin/rsync",
    "/usr/sbin/sysctl", "/usr/sbin/chown", "/usr/sbin/netstat", "/usr/sbin/lsof",
    "/usr/sbin/cron", "/usr/sbin/sshd", "/usr/sbin/ioreg",
    "/usr/lib/dyld",
)

# (c) Masum PE'ler. IMZA kulvarının 11 masum PE'si (distlib 6 + makensis 4 + pnpm fastlist x86)
# bu listenin alt kümesidir; Ghidra'nın kendi Windows araçları eklenir.
PE_DESENLERI = (
    str(GHIDRA_KOKU / "**/*.exe"),
    "/opt/anaconda3/lib/python3.12/site-packages/pip/_vendor/distlib/*.exe",
    "/opt/homebrew/Cellar/makensis/3.13/share/nsis/Bin/*.exe",
    "/opt/homebrew/lib/node_modules/pnpm/dist/vendor/fastlist-0.3.0-*.exe",
)
# IMZA kulvarının 11'i: distlib 6 + makensis GenPat, MakeLangId, zip2exe, makensisw + fastlist x86.
# Bu makinedeki makensis 3.13'te makensisw.exe yok; yerine makensis.exe sayılır (eşik dosyasında
# ``izlenen_yanlislar`` → ``imza11_fsg``).

# (d) Gerçek pozitifler. Beklentiler eşik dosyasında (``gercek_pozitifler``); burada yalnız girdi.
# ``kaynak`` → ``--pozitif-kur`` kopyalayıp paketler ya da derler; ikililer depo dışında durur.
POZITIF_GIRDILER = (
    {"ad": "openssl_cli", "yol": "/opt/homebrew/opt/openssl@3/bin/openssl",
     "not": "OpenSSL 3 komut satırı aracı (Mach-O arm64); kripto adları ve yardım metni"},
    {"ad": "libcrypto", "yol": "/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib",
     "not": "OpenSSL 3 kripto kitaplığı (Mach-O arm64 dylib); AES/SHA sabitleri gövdede"},
    {"ad": "upx_pe_t32", "yol": str(POZITIF_DIZIN / "upx_t32.exe"),
     "kaynak": ("upx", "/opt/anaconda3/lib/python3.12/site-packages/pip/_vendor/distlib/t32.exe"),
     "not": "distlib t32.exe (x86 PE32) kopyası, UPX ile paketli"},
    {"ad": "upx_pe_t64", "yol": str(POZITIF_DIZIN / "upx_t64.exe"),
     "kaynak": ("upx", "/opt/anaconda3/lib/python3.12/site-packages/pip/_vendor/distlib/t64.exe"),
     "not": "distlib t64.exe (x86-64 PE32+) kopyası, UPX ile paketli"},
    {"ad": "upx_elf_true", "yol": str(POZITIF_DIZIN / "upx_debian_true"),
     "kaynak": ("upx", "gelistirme:debian/coreutils/true"),
     "not": "Debian coreutils true (ELF AArch64) kopyası, UPX ile paketli"},
    {"ad": "antidebug_x86_64", "yol": str(POZITIF_DIZIN / "antidebug_x86_64"),
     "kaynak": ("clang", str(POZITIF_KAYNAK / "antidebug.c")),
     "not": "x86-64 Mach-O: rdtsc + ptrace(PT_DENY_ATTACH) + sysctl(KERN_PROC_PID) P_TRACED"},
)

ZAMAN_ASIMI_UPX = 120


# ---------------------------------------------------------------------------
# Genel yardımcılar
# ---------------------------------------------------------------------------

def _simdi() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def _sha(yol: Path) -> str:
    h = hashlib.sha256()
    with open(yol, "rb") as f:
        for parca in iter(lambda: f.read(1 << 20), b""):
            h.update(parca)
    return h.hexdigest()


def _git(agac: Path, *arg: str) -> str:
    return subprocess.run(["git", "-C", str(agac), *arg], capture_output=True, text=True,
                          check=True).stdout.strip()


def ana_depo() -> Path:
    """Worktree'de bile ana deponun kökü (git'in ortak dizininin üstü)."""
    try:
        ortak = Path(_git(DEPO, "rev-parse", "--path-format=absolute", "--git-common-dir"))
        return ortak.parent
    except (subprocess.CalledProcessError, OSError):
        return DEPO


def _urun_kos():
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        import urun_kos  # noqa: PLC0415
    finally:
        sys.path.pop(0)
    return urun_kos


def agaci_yukle(agac: Path) -> dict:
    """``karadul``'u verilen ağaçtan yükler; başka ağaç yüklenirse durur (editable kurulum tuzağı)."""
    agac = agac.expanduser().resolve()
    if "karadul" in sys.modules:
        yuklu = Path(sys.modules["karadul"].__file__).resolve()
    else:
        sys.path.insert(0, str(agac))
        import karadul  # noqa: PLC0415
        yuklu = Path(karadul.__file__).resolve()
    if not str(yuklu).startswith(str(agac) + os.sep):
        raise SystemExit(f"[kapı] karadul {yuklu} yükleniyor, {agac} DEĞİL: yanlış ağaç ölçülürdü")
    import karadul  # noqa: PLC0415
    kirli = _git(agac, "status", "--porcelain", "--untracked-files=no")
    return {"agac": str(agac), "commit": _git(agac, "rev-parse", "HEAD"),
            "kirli": kirli.splitlines() if kirli else [],
            "karadul_dosyasi": str(yuklu), "karadul_surumu": getattr(karadul, "__version__", "?")}


# ---------------------------------------------------------------------------
# Setler
# ---------------------------------------------------------------------------

def set_girdileri(ad: str, taban_debian: Path | None = None,
                  taban_mac: Path | None = None) -> list[dict]:
    """Bir setin girdileri: ``{"anahtar", "yol", "sha256"?}``. sha256 yoksa hesaplanır."""
    if ad == "gelistirme":
        uk = _urun_kos()
        tm = taban_mac or uk.TABAN_MAC
        if not tm.exists():  # worktree'de workspaces/ yok: ana depodakini kullan
            tm = ana_depo() / tm.relative_to(uk.DEPO)
        isler = uk.isleri_topla(taban_debian or uk.TABAN_DEBIAN, tm)
        return [{"anahtar": i["anahtar"], "yol": str(i["girdi"]), "sha256": i["sha256"]}
                for i in isler]
    if ad == "macos":
        return [{"anahtar": y, "yol": y} for y in MACOS_YOLLARI]
    if ad == "pe":
        yollar: set[str] = set()
        for desen in PE_DESENLERI:
            yollar.update(glob.glob(desen, recursive=True))
        return [{"anahtar": y, "yol": y} for y in sorted(yollar)]
    if ad == "pozitif":
        return [{"anahtar": g["ad"], "yol": g["yol"]} for g in POZITIF_GIRDILER]
    raise SystemExit(f"[kapı] bilinmeyen set: {ad}")


def setleri_sabitle(setler: list[str], hedef: Path) -> dict:
    """Setlerin girdilerini yol + sha256 ile ``setler.json``'a yazar (sabit liste)."""
    kayit = {"olusturma": _simdi(), "setler": {}}
    if hedef.exists():
        kayit = json.loads(hedef.read_text(encoding="utf-8"))
        kayit["guncelleme"] = _simdi()
    for s in setler:
        girdiler = []
        for g in set_girdileri(s):
            p = Path(g["yol"])
            if not p.is_file():
                raise SystemExit(f"[kapı] {s}: girdi yok: {p} (pozitif set için önce --pozitif-kur)")
            girdiler.append({"anahtar": g["anahtar"], "yol": g["yol"],
                             "gercek_yol": str(p.resolve()), "boyut": p.stat().st_size,
                             "sha256": _sha(p)})
        kayit["setler"][s] = girdiler
    hedef.parent.mkdir(parents=True, exist_ok=True)
    hedef.write_text(json.dumps(kayit, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return kayit


def sabit_set(ad: str, setler_dosyasi: Path) -> list[dict]:
    """Sabitlenmiş girdiler; dosyada set yoksa durur."""
    if not setler_dosyasi.exists():
        raise SystemExit(f"[kapı] {setler_dosyasi} yok: önce --setleri-sabitle")
    kayit = json.loads(setler_dosyasi.read_text(encoding="utf-8"))
    if ad not in kayit.get("setler", {}):
        raise SystemExit(f"[kapı] {setler_dosyasi}: '{ad}' seti sabitlenmemiş")
    return kayit["setler"][ad]


# ---------------------------------------------------------------------------
# Pozitif set kurulumu
# ---------------------------------------------------------------------------

def pozitif_kur(setler_dosyasi: Path) -> list[dict]:
    """UPX'li kopyaları ve anti-debug örneğini ``POZITIF_DIZIN`` altında üretir."""
    POZITIF_DIZIN.mkdir(parents=True, exist_ok=True)
    gunluk = []
    for g in POZITIF_GIRDILER:
        if "kaynak" not in g:
            continue
        arac, kaynak = g["kaynak"]
        hedef = Path(g["yol"])
        if kaynak.startswith("gelistirme:"):
            anahtar = kaynak.split(":", 1)[1]
            kaynak = next(x["yol"] for x in set_girdileri("gelistirme") if x["anahtar"] == anahtar)
        if arac == "upx":
            gecici = hedef.with_suffix(hedef.suffix + ".kaynak")
            shutil.copyfile(kaynak, gecici)
            gecici.chmod(0o755)  # upx yürütülemez dosyayı paketlemez
            if hedef.exists():
                hedef.unlink()
            komut = ["upx", "-9", "-q", "-o", str(hedef), str(gecici)]
            try:
                s = subprocess.run(komut, capture_output=True, text=True, timeout=ZAMAN_ASIMI_UPX)
            finally:
                gecici.unlink(missing_ok=True)
        elif arac == "clang":
            komut = ["clang", "-arch", "x86_64", "-O0", "-o", str(hedef), kaynak]
            s = subprocess.run(komut, capture_output=True, text=True, timeout=ZAMAN_ASIMI_UPX)
        else:
            raise SystemExit(f"[kapı] bilinmeyen araç {arac}")
        gunluk.append({"ad": g["ad"], "komut": " ".join(komut), "cikis": s.returncode,
                       "kaynak_sha256": _sha(Path(kaynak)),
                       "cikti": (s.stdout + s.stderr).strip()[-400:]})
        if s.returncode != 0 or not hedef.exists():
            raise SystemExit(f"[kapı] {g['ad']} kurulamadı: {s.stderr.strip()[-400:]}")
    (POZITIF_DIZIN / "kurulum.json").write_text(
        json.dumps({"zaman": _simdi(), "adimlar": gunluk}, ensure_ascii=False, indent=1) + "\n",
        encoding="utf-8")
    return gunluk


# ---------------------------------------------------------------------------
# Doğrudan kip: katman çağrıları (ürünün çağırdığı biçimde)
# ---------------------------------------------------------------------------

def _iddia(etiket: str, kanit: Any, **ek: Any) -> dict:
    d = {"etiket": etiket, "kanit": kanit}
    d.update(ek)
    return d


def _hazirla(yol: Path, calisma: Path) -> dict:
    """Hedef tanıma + ``MachOAnalyzer.analyze_static`` (Ghidra adımı devre dışı).

    Ürünün statik aşaması (``karadul/stages.py`` → ``MachOAnalyzer.analyze_static``) evrensel
    ikilide ``raw/<ad>_arm64`` dilimini çıkarır, dizgi/simge/dylib toplar ve
    ``BinaryIntelligence``'ı koşar. Burada yalnız ``_run_ghidra`` None döndürür; gerisi üründür.
    """
    from karadul.analyzers.macho import MachOAnalyzer
    from karadul.config import Config
    from karadul.core.target import TargetDetector
    from karadul.core.workspace import Workspace

    hedef = TargetDetector().detect(yol)
    cfg = Config.load(None)
    ws = Workspace(calisma, hedef.name, workspace_dir=calisma / "ws")
    ws.create()
    an = MachOAnalyzer(cfg)
    an._run_ghidra = lambda *a, **k: None  # Ghidra koşusu yok
    t0 = time.monotonic()
    sonuc = None
    hata = None
    if hedef.target_type in an.supported_types:
        try:
            sonuc = an.analyze_static(hedef, ws)
        except Exception as exc:  # pragma: no cover - ürün hatası kayda geçer
            hata = f"{type(exc).__name__}: {exc}"
    else:
        hata = f"uygulanmaz: hedef türü {hedef.target_type.value} (ürün MachOAnalyzer'ı çağırmaz)"
    dilim = ws.get_stage_dir("raw") / f"{hedef.name}_arm64"
    return {"hedef": hedef, "cfg": cfg, "ws": ws, "statik": sonuc, "statik_hata": hata,
            "statik_sn": round(time.monotonic() - t0, 2),
            # binary_prep: evrensel ikilide dilim, yoksa hedefin kendisi (bayt taraması için)
            "bayt_ikilisi": dilim if dilim.exists() else hedef.path}


def katman_bi(h: dict) -> dict:
    if h["statik_hata"]:
        durum = "uygulanmaz" if h["statik_hata"].startswith("uygulanmaz") else "calismadi"
        return {"durum": durum, "neden": h["statik_hata"], "iddialar": []}
    rapor = h["ws"].get_stage_dir("static") / "intelligence_report.json"
    if not rapor.exists():
        hatalar = [e for e in (h["statik"].errors if h["statik"] else []) if "Intelligence" in e]
        return {"durum": "calismadi", "neden": "; ".join(hatalar) or "intelligence_report yazılmadı",
                "iddialar": []}
    return {"durum": "calisti", "iddialar": bi_iddialari(json.loads(rapor.read_text("utf-8")))}


BI_ALANLARI = (("algorithms", "algoritma"), ("subsystems", "altsistem"),
               ("security", "guvenlik"), ("protocols", "protokol"))


def bi_iddialari(rapor: dict) -> list[dict]:
    """``intelligence_report.json`` → iddialar (``algoritma:SHA-256`` ...)."""
    mimari = rapor.get("architecture", {})
    iddialar = []
    for alan, onek in BI_ALANLARI:
        for kayit in mimari.get(alan, []) or []:
            ek = {}
            if "risk_level" in kayit:
                ek["risk"] = kayit["risk_level"]
            if "confidence" in kayit:
                ek["guven"] = kayit["confidence"]
            iddialar.append(_iddia(f"{onek}:{kayit.get('name')}",
                                   list(dict.fromkeys(kayit.get("evidence", [])))[:5], **ek))
    return iddialar


def _anti_debug_seviye(puan: float) -> str:
    # markdown_report._severity_icon ile aynı eşikler (>=0,7 HIGH, >=0,4 MED)
    return "HIGH" if puan >= 0.7 else ("MED" if puan >= 0.4 else "INFO")


def katman_antidebug(h: dict) -> dict:
    from karadul.analyzers.anti_debug_detector import AntiDebugDetector
    try:
        d = AntiDebugDetector(target=h["hedef"], binary_path=h["bayt_ikilisi"])
        nesneler = d.detect()
        bulgular = [f.to_dict() for f in nesneler]
        ozet = d.summary(nesneler)  # pipeline/steps/anti_debug.py da boş listede çağırıyor
    except Exception as exc:
        return {"durum": "hata", "neden": f"{type(exc).__name__}: {exc}", "iddialar": []}
    return {"durum": "calisti", "iddialar": antidebug_iddialari(
        {"findings": bulgular, "summary": ozet})}


def antidebug_iddialari(veri: dict) -> list[dict]:
    """``anti_debug_findings.json`` biçimi → iddialar. Seviye rapordaki başlığı verir."""
    bulgular = veri.get("findings", []) or []
    puan = float((veri.get("summary") or {}).get("anti_debug_score", 0.0) or 0.0)
    seviye = _anti_debug_seviye(puan) if bulgular else None
    teknikler: dict[str, dict] = {}
    for b in bulgular:
        t = b.get("technique", "?")
        onceki = teknikler.get(t)
        if onceki is None or b.get("confidence", 0) > onceki["guven"]:
            teknikler[t] = {"guven": b.get("confidence", 0.0),
                            "kanit": b.get("evidence"), "kategori": b.get("category")}
    return [_iddia(f"teknik:{t}", v["kanit"], guven=v["guven"], kategori=v["kategori"],
                   rapor_seviyesi=seviye, puan=puan)
            for t, v in sorted(teknikler.items())]


def katman_packer(h: dict) -> dict:
    from karadul.analyzers.packer_fingerprint import PackerFingerprintDetector
    try:
        izler = [f.to_dict() for f in PackerFingerprintDetector(h["bayt_ikilisi"]).detect()]
    except Exception as exc:
        return {"durum": "hata", "neden": f"{type(exc).__name__}: {exc}", "iddialar": []}
    return {"durum": "calisti", "iddialar": packer_iddialari({"fingerprints": izler})}


def _sarif_packer_duzeyi(guven: float) -> str:
    # sarif_report._extract_packer_fingerprint_results ile aynı eşikler
    return "error" if guven >= 0.7 else ("warning" if guven >= 0.4 else "note")


def packer_iddialari(veri: dict) -> list[dict]:
    iddialar = []
    for fp in veri.get("fingerprints", []) or []:
        g = float(fp.get("confidence", 0.0) or 0.0)
        iddialar.append(_iddia(f"paketleyici:{fp.get('packer_name')}", fp.get("evidence"),
                               guven=g, katman_sayisi=fp.get("layers_matched"),
                               sarif=_sarif_packer_duzeyi(g)))
    return iddialar


def katman_yara(h: dict) -> dict:
    from karadul.analyzers.yara_scanner import YaraScanner
    try:
        tarayici = YaraScanner()
        kural = tarayici.load_builtin_rules()
        sonuc = tarayici.scan_file(h["hedef"].path)  # stages.py: target.path (dilim değil)
    except Exception as exc:
        return {"durum": "hata", "neden": f"{type(exc).__name__}: {exc}", "iddialar": []}
    iddialar = []
    for m in sonuc.matches:
        dizgiler = [repr(veri[:24]) for _, _, veri in (m.strings or [])[:4]]
        iddialar.append(_iddia(f"kural:{m.rule}", dizgiler, etiketler=list(m.tags or [])))
    durum = "calisti" if not sonuc.errors else "hata"
    return {"durum": durum, "neden": "; ".join(sonuc.errors) or None, "iddialar": iddialar,
            "arka_uc": sonuc.backend, "kural_sayisi": kural}


def katman_capa(h: dict) -> dict:
    from karadul.analyzers.capa_scanner import CAPAScanner
    br = h["cfg"].binary_reconstruction
    if not br.enable_capa:
        return {"durum": "calismadi", "neden": "enable_capa kapalı", "iddialar": []}
    try:
        tarayici = CAPAScanner(rules_path=br.capa_rules_path or None, timeout=br.capa_timeout)
        if not tarayici.is_available():
            return {"durum": "calismadi", "neden": "capa bulunamadı (is_available False)",
                    "iddialar": []}
        sonuc = tarayici.scan(h["hedef"].path)
    except Exception as exc:
        return {"durum": "calismadi", "neden": f"{type(exc).__name__}: {exc}", "iddialar": []}
    if not sonuc.success:
        return {"durum": "calismadi", "neden": "; ".join(sonuc.errors) or "success False",
                "iddialar": []}
    iddialar = []
    for c in list(sonuc.file_capabilities) + [x for v in sonuc.function_capabilities.values()
                                               for x in v]:
        iddialar.append(_iddia(f"yetenek:{c.name}", getattr(c, "namespace", None)))
    tekil = {i["etiket"]: i for i in iddialar}
    return {"durum": "calisti", "iddialar": list(tekil.values())}


DOGRUDAN_CAGRI: dict[str, Callable[[dict], dict]] = {
    "bi": katman_bi, "antidebug": katman_antidebug, "packer": katman_packer,
    "yara": katman_yara, "capa": katman_capa,
}


def _isci_baslat(agac: str) -> None:
    """Süreç havuzu işçisi: aynı ağacı yükle (spawn sys.path'i taşır; yine de denetle)."""
    import logging
    logging.disable(logging.WARNING)
    agaci_yukle(Path(agac))


def ikili_olc(girdi: dict, katmanlar: list[str], calisma_koku: str) -> dict:
    """Tek ikili, seçilen katmanlar. Süreç havuzunda koşar."""
    yol = Path(girdi["yol"])
    kayit: dict[str, Any] = {"anahtar": girdi["anahtar"], "yol": girdi["yol"],
                             "sha256": girdi.get("sha256"), "katmanlar": {}}
    if not yol.is_file():
        kayit["hata"] = "girdi yok"
        return kayit
    gercek = _sha(yol)
    if girdi.get("sha256") and gercek != girdi["sha256"]:
        kayit["hata"] = f"girdi değişmiş: sha256 {gercek[:12]} ≠ sabit {girdi['sha256'][:12]}"
        return kayit
    kayit["sha256"] = gercek
    with tempfile.TemporaryDirectory(dir=calisma_koku) as td:
        h = _hazirla(yol, Path(td))
        kayit["hedef_turu"] = h["hedef"].target_type.value
        kayit["bayt_ikilisi"] = "dilim" if h["bayt_ikilisi"] != h["hedef"].path else "hedef"
        kayit["statik_sn"] = h["statik_sn"]
        for k in katmanlar:
            t0 = time.monotonic()
            sonuc = DOGRUDAN_CAGRI[k](h)
            sonuc["sure_sn"] = round(time.monotonic() - t0, 2)
            kayit["katmanlar"][k] = sonuc
    return kayit


# ---------------------------------------------------------------------------
# Hüküm: yanlış / doğru bilinen / pozitif set
# ---------------------------------------------------------------------------

def _uyar(kural: dict, set_adi: str, anahtar: str, katman: str, etiket: str) -> bool:
    if kural.get("katman") not in (None, katman, KATMAN_ESI.get(katman)):
        return False
    if kural.get("set") not in (None, set_adi):
        return False
    if not any(fnmatch.fnmatchcase(anahtar, d) for d in kural.get("ikili", ["*"])):
        return False
    return re.search(kural["etiket_re"], etiket) is not None


def _kanit_uyar(kural: dict, iddia: dict) -> bool:
    """``kanit_re`` verilmişse iddianın kanıt listesinden biri uymalı."""
    if "kanit_re" not in kural:
        return True
    kanit = iddia.get("kanit")
    ogeler = kanit if isinstance(kanit, list) else [kanit]
    return any(re.search(kural["kanit_re"], str(o)) for o in ogeler if o is not None)


def _sarif_yara_dogru(set_adi: str, anahtar: str, katman: str, iddia: dict, dogrular: list) -> bool:
    """``sarif`` katmanındaki bilgi düzeyi YARA iddiası, ``yara`` katmanının doğru iddia kuralına
    (``kural:<ad>``) uyuyor mu (``_SARIF_YARA_BILGI_KURALLARI``)."""
    kural = iddia.get("yara_kurali")
    if katman != "sarif" or not kural:
        return False
    if iddia["etiket"].split(":", 1)[0] not in _SARIF_YARA_BILGI_KURALLARI:
        return False
    return any(_uyar(d, set_adi, anahtar, "yara", f"kural:{kural}") and _kanit_uyar(d, iddia)
               for d in dogrular)


def hukumle(kayitlar: dict[str, list[dict]], esik: dict) -> None:
    """Her iddiaya ``hukum`` yazar: yanlis | dogru_bilinen | pozitif_set."""
    dogrular = esik.get("dogru_iddialar", [])
    for set_adi, liste in kayitlar.items():
        for kayit in liste:
            for katman, ks in kayit.get("katmanlar", {}).items():
                for i in ks.get("iddialar", []):
                    if set_adi not in MASUM_SETLER:
                        i["hukum"] = "pozitif_set"
                    elif any(_uyar(d, set_adi, kayit["anahtar"], katman, i["etiket"])
                             and _kanit_uyar(d, i) for d in dogrular):
                        i["hukum"] = "dogru_bilinen"
                    elif _sarif_yara_dogru(set_adi, kayit["anahtar"], katman, i, dogrular):
                        i["hukum"] = "dogru_bilinen"
                    else:
                        i["hukum"] = "yanlis"


def ozetle(kayitlar: dict[str, list[dict]]) -> dict:
    """katman × set özeti: ikili sayısı, durumlar, yanlış iddia, etiket dağılımı."""
    ozet: dict[str, dict] = {}
    for set_adi, liste in kayitlar.items():
        for kayit in liste:
            for katman, ks in kayit.get("katmanlar", {}).items():
                o = ozet.setdefault(katman, {}).setdefault(set_adi, {
                    "ikili": 0, "durum": collections.Counter(), "neden": collections.Counter(),
                    "iddia": 0, "yanlis": 0, "dogru_bilinen": 0, "yanlis_ikili": 0,
                    "adet": 0, "yanlis_adet": 0,
                    "etiket": collections.Counter(), "ikili_basina_yanlis": {}})
                o["ikili"] += 1
                o["durum"][ks.get("durum", "?")] += 1
                if ks.get("neden"):
                    o["neden"][str(ks["neden"])[:160]] += 1
                iddialar = ks.get("iddialar", [])
                y = sum(1 for i in iddialar if i.get("hukum") == "yanlis")
                o["iddia"] += len(iddialar)
                o["yanlis"] += y
                o["dogru_bilinen"] += sum(1 for i in iddialar if i.get("hukum") == "dogru_bilinen")
                o["yanlis_ikili"] += 1 if y else 0
                o["ikili_basina_yanlis"][kayit["anahtar"]] = y
                # adet: çıktı katmanlarında bir etiketin ikilideki tekrar sayısı (ör. 8 fonksiyonda
                # "Galois field"); iddia sayısı ikili başına etiketi bir kez sayar.
                o["adet"] += sum(i.get("adet", 1) for i in iddialar)
                o["yanlis_adet"] += sum(i.get("adet", 1) for i in iddialar if i.get("hukum") == "yanlis")
                for i in iddialar:
                    o["etiket"][i["etiket"]] += 1
    for katman in ozet.values():
        for o in katman.values():
            o["durum"] = dict(o["durum"])
            o["neden"] = dict(o["neden"].most_common(5))
            o["etiket"] = dict(sorted(o["etiket"].items(), key=lambda kv: (-kv[1], kv[0])))
    return ozet


def ek_sayaclar(kayitlar: dict[str, list[dict]]) -> dict:
    """Rapordaki görünür düzeyler: anti-debug [MED]/[HIGH] başlığı, SARIF paketleyici düzeyi."""
    ek: dict[str, dict] = {}
    for set_adi, liste in kayitlar.items():
        for kayit in liste:
            ks = kayit.get("katmanlar", {})
            ad = ks.get("antidebug", {}).get("iddialar", [])
            if ad:
                sev = ad[0].get("rapor_seviyesi")
                c = ek.setdefault("antidebug_rapor_seviyesi", {}).setdefault(set_adi, {})
                c[sev] = c.get(sev, 0) + 1
            for i in ks.get("packer", {}).get("iddialar", []):
                c = ek.setdefault("packer_sarif_duzeyi", {}).setdefault(set_adi, {})
                c[i["sarif"]] = c.get(i["sarif"], 0) + 1
            for i in ks.get("bi", {}).get("iddialar", []):
                if i.get("risk") == "kernel":
                    c = ek.setdefault("bi_kernel_riskli_guvenlik", {}).setdefault(set_adi, {})
                    c[i["etiket"]] = c.get(i["etiket"], 0) + 1
    return ek


def izlenenleri_say(kayitlar: dict[str, list[dict]], esik: dict) -> list[dict]:
    """Eşik dosyasındaki ``izlenen_yanlislar``: rapordaki bilinen yanlış etiketlerin ikili sayısı."""
    sonuc = []
    for iz in esik.get("izlenen_yanlislar", []):
        for set_adi, liste in kayitlar.items():
            if iz.get("set", set_adi if set_adi in MASUM_SETLER else None) != set_adi:
                continue  # set verilmemişse yalnız masum setler
            # kural katmanı doğrudan kipteyse çıktı kipteki eşi de sayılır (bi ↔ intel ...)
            for katman in [iz["katman"]] + [c for c, d in KATMAN_ESI.items() if d == iz["katman"]]:
                olculen = [k for k in liste if katman in k.get("katmanlar", {})
                           and any(fnmatch.fnmatchcase(k["anahtar"], d)
                                   for d in iz.get("ikili", ["*"]))]
                if not olculen:
                    continue
                tutan, adet = [], 0
                for k in olculen:
                    uyan = [i for i in k["katmanlar"][katman].get("iddialar", [])
                            if re.search(iz["etiket_re"], i["etiket"])]
                    if uyan:
                        tutan.append(k["anahtar"])
                        adet += sum(i.get("adet", 1) for i in uyan)
                sonuc.append({"ad": iz["ad"], "katman": katman, "set": set_adi,
                              "etiket_re": iz["etiket_re"], "ikili": len(tutan), "adet": adet,
                              "olculen": len(olculen), "rapordaki": iz.get("rapordaki"),
                              "ornek": tutan[:5]})
    return sonuc


def gercek_pozitifleri_sina(kayitlar: dict[str, list[dict]], esik: dict) -> list[dict]:
    sonuc = []
    dizin = {(s, k["anahtar"]): k for s, liste in kayitlar.items() for k in liste}
    for b in esik.get("gercek_pozitifler", []):
        kayit = dizin.get((b["set"], b["ikili"]))
        # Beklenti doğrudan kip katmanıyla yazılır; çıktı kipinde eşi sınanır (bi → intel ...).
        adaylar = [b["katman"]] + [c for c, d in KATMAN_ESI.items() if d == b["katman"]]
        katman = next((k for k in adaylar if kayit and k in kayit.get("katmanlar", {})), None)
        if katman is None:
            # Ölçülmeyen beklenti kapıyı düşürmez (alt küme ölçümü); md'de "olculmedi" görünür.
            sonuc.append({**b, "sonuc": "olculmedi"})
            continue
        ks = kayit["katmanlar"][katman]
        bulunan = [i["etiket"] for i in ks.get("iddialar", []) if re.search(b["etiket_re"], i["etiket"])]
        sonuc.append({**b, "olculen_katman": katman, "sonuc": "var" if bulunan else "yok",
                      "bulunan": bulunan[:5], "katman_durumu": ks.get("durum")})
    return sonuc


def esigi_sina(ozet: dict, esik: dict, kip: str) -> list[dict]:
    """Eşik: katman × set için yanlış iddia, ölçülen ikililer üstünden taban toplamı."""
    sonuc = []
    for katman, setler in ozet.items():
        for set_adi, o in setler.items():
            if set_adi not in MASUM_SETLER:
                continue  # pozitif set yanlışla değil gerçek pozitif beklentileriyle sınanır
            e = esik.get("esikler", {}).get(kip, {}).get(katman, {}).get(set_adi)
            if e is None:
                sonuc.append({"katman": katman, "set": set_adi, "sonuc": "esik_yok",
                              "yanlis": o["yanlis"]})
                continue
            taban = e.get("ikililer", {})
            ibs = o["ikili_basina_yanlis"]
            # Eşik yalnız tabanı olan ikililer üstünden; tabansız ikili ayrıca yazılır, düşürmez.
            yanlis = sum(n for a, n in ibs.items() if a in taban)
            ust = sum(taban[a] for a in ibs if a in taban)
            esiksiz = {a: n for a, n in ibs.items() if a not in taban}
            artan = sorted(a for a, n in ibs.items() if a in taban and n > taban[a])
            sonuc.append({"katman": katman, "set": set_adi, "yanlis": yanlis, "ust": ust,
                          "sonuc": "asildi" if yanlis > ust else "icinde",
                          "esikli_ikili": len(ibs) - len(esiksiz),
                          "esiksiz_ikili": len(esiksiz),
                          "esiksiz_yanlis": sum(esiksiz.values()), "artan_ikili": artan})
    return sonuc


def karsilastir(simdi: dict, onceki: dict) -> list[dict]:
    """İki kapı çıktısının katman × set yanlış/iddia farkı ve etiket bazında değişim."""
    satirlar = []
    for katman in sorted(set(simdi["ozet"]) | set(onceki["ozet"])):
        for set_adi in sorted(set(simdi["ozet"].get(katman, {})) | set(onceki["ozet"].get(katman, {}))):
            a = onceki["ozet"].get(katman, {}).get(set_adi)
            b = simdi["ozet"].get(katman, {}).get(set_adi)
            ea, eb = (a or {}).get("etiket", {}), (b or {}).get("etiket", {})
            degisen = {e: [ea.get(e, 0), eb.get(e, 0)] for e in set(ea) | set(eb)
                       if ea.get(e, 0) != eb.get(e, 0)}
            satirlar.append({"katman": katman, "set": set_adi,
                             "yanlis": [(a or {}).get("yanlis"), (b or {}).get("yanlis")],
                             "iddia": [(a or {}).get("iddia"), (b or {}).get("iddia")],
                             "ikili": [(a or {}).get("ikili"), (b or {}).get("ikili")],
                             "etiket_degisimi": dict(sorted(degisen.items(),
                                                            key=lambda kv: kv[1][0] - kv[1][1]))})
    return satirlar


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def markdown(c: dict, en_cok_etiket: int = 8) -> str:
    s = [f"# Masum ikili kapısı — {c['kip']} kip", "",
         f"- Zaman: {c['baslangic']} → {c['bitis']} ({c['sure_sn']} sn)",
         f"- Ağaç: `{c['agac']['agac']}` @ `{c['agac']['commit'][:10]}` (karadul {c['agac']['karadul_surumu']}; "
         f"`{c['agac']['karadul_dosyasi']}`); kirli: {len(c['agac']['kirli'])} dosya"]
    if c.get("kosu"):
        s.append(f"- Koşu: `{c['kosu']['kok']}` ({c['kosu']['ikili']} ikili; koşunun ağacı "
                 f"`{(c['kosu'].get('commit') or '?')[:10]}`, karadul {c['kosu'].get('surum') or '?'})")
        if c["kosu"].get("agac_farkli"):
            s.append("  - **Dikkat:** koşuyu üreten commit ölçülen ağaçtan farklı; bileşim şablon "
                     "listesi ölçülen ağaçtan okunur.")
    s.append(f"- Kapı: **{c['kapi']['sonuc']}** (çıkış {c['kapi']['cikis_kodu']})")
    for n in c["kapi"].get("nedenler", []):
        s.append(f"  - {n}")
    s += ["", "## Katman × set: yanlış iddia", "",
          "| Katman | Set | İkili | Durum | İddia | Yanlış | Doğru bilinen | Yanlışlı ikili | Adet (yanlış) | Eşik |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    esik = {(e["katman"], e["set"]): e for e in c["esik_sinamasi"]}
    for katman, setler in c["ozet"].items():
        for set_adi, o in setler.items():
            e = esik.get((katman, set_adi), {})
            if "ust" in e:
                es = f"{e['yanlis']} ≤ {e['ust']} ({e['sonuc']}; {e['esikli_ikili']} ikili)"
                if e["esiksiz_ikili"]:
                    es += f"; eşiksiz {e['esiksiz_ikili']} ikilide yanlış {e['esiksiz_yanlis']}"
            else:
                es = e.get("sonuc", "—")
            durum = ", ".join(f"{k} {v}" for k, v in o["durum"].items())
            s.append(f"| {katman} | {set_adi} | {o['ikili']} | {durum} | {o['iddia']} | {o['yanlis']} "
                     f"| {o['dogru_bilinen']} | {o['yanlis_ikili']} | {o['adet']} ({o['yanlis_adet']}) | {es} |")
    s += ["", "## En sık etiketler (ikili sayısı değil, iddia sayısı; bir ikilide etiket bir kez)", ""]
    for katman, setler in c["ozet"].items():
        for set_adi, o in setler.items():
            if not o["etiket"] and not o["neden"]:
                continue
            ilk = list(o["etiket"].items())[:en_cok_etiket]
            s.append(f"- **{katman} / {set_adi}**: " + (", ".join(f"`{e}` {n}" for e, n in ilk) or "—"))
            for n, sayi in o["neden"].items():
                s.append(f"  - neden ({sayi} ikili): {n}")
    if c.get("izlenen"):
        s += ["", "## İzlenen yanlış etiketler (rapordaki bulgular; ikili sayısı)", "",
              "| Ad | Katman | Set | Etiket | İkili / ölçülen | Adet | Rapordaki |",
              "|---|---|---|---|---|---|---|"]
        for z in c["izlenen"]:
            s.append(f"| {z['ad']} | {z['katman']} | {z['set']} | `{z['etiket_re']}` | "
                     f"{z['ikili']} / {z['olculen']} | {z.get('adet', '—')} | {z.get('rapordaki') or '—'} |")
    if c.get("ek_sayaclar"):
        s += ["", "## Rapora yansıyan düzeyler", ""]
        for ad, setler in c["ek_sayaclar"].items():
            for set_adi, d in setler.items():
                s.append(f"- {ad} / {set_adi}: " + ", ".join(f"{k} {v}" for k, v in d.items()))
    s += ["", "## Gerçek pozitifler", "", "| Set | İkili | Katman | Beklenen | Zorunlu | Sonuç |",
          "|---|---|---|---|---|---|"]
    for g in c["gercek_pozitifler"]:
        s.append(f"| {g['set']} | `{g['ikili']}` | {g['katman']} | `{g['etiket_re']}` | "
                 f"{'evet' if g.get('zorunlu') else 'hayır'} | {g['sonuc']} {', '.join(g.get('bulunan', [])[:2])} |")
    if c.get("karsilastirma"):
        s += ["", "## Karşılaştırma (önce → sonra)", "",
              "| Katman | Set | Yanlış | İddia | En çok değişen etiketler |", "|---|---|---|---|---|"]
        for k in c["karsilastirma"]:
            d = list(k["etiket_degisimi"].items())[:5]
            s.append(f"| {k['katman']} | {k['set']} | {k['yanlis'][0]} → {k['yanlis'][1]} | "
                     f"{k['iddia'][0]} → {k['iddia'][1]} | "
                     + ", ".join(f"`{e}` {a}→{b}" for e, (a, b) in d) + " |")
    if c.get("girdi_hatalari"):
        s += ["", "## Girdi hataları", ""] + [f"- `{a}`: {h}" for a, h in c["girdi_hatalari"]]
    return "\n".join(s) + "\n"


# ---------------------------------------------------------------------------
# Ana akış
# ---------------------------------------------------------------------------

def esik_yukle(yol: Path) -> dict:
    return json.loads(yol.read_text(encoding="utf-8")) if yol.exists() else {}


def esik_yaz(kapi_ciktilari: list[Path], esik_yolu: Path) -> list[str]:
    """Kapı çıktılarındaki ikili başına yanlış sayısını eşik olarak yazar (taban ya da sıkılaştırma).

    Eşik dosyasının elle yazılan bölümleri (``dogru_iddialar``, ``gercek_pozitifler``,
    ``izlenen_yanlislar``) korunur; yalnız ``esikler[kip][katman][set]`` değişir.
    """
    esik = esik_yukle(esik_yolu)
    satirlar = []
    for yol in kapi_ciktilari:
        c = json.loads(yol.read_text(encoding="utf-8"))
        for katman, setler in c["ozet"].items():
            for set_adi, o in setler.items():
                if set_adi not in MASUM_SETLER:
                    continue
                yer = esik.setdefault("esikler", {}).setdefault(c["kip"], {}).setdefault(katman, {})
                eski = yer.get(set_adi, {})
                ikililer = dict(eski.get("ikililer", {}))
                ikililer.update(o["ikili_basina_yanlis"])  # ölçülen ikililer güncellenir, öbürleri kalır
                commit = (c.get("kosu") or {}).get("commit") or c["agac"]["commit"]
                kaynaklar = [k for k in eski.get("kaynaklar", []) if k["kaynak"] != str(yol)]
                kaynaklar.append({"kaynak": str(yol), "commit": (commit or "?")[:10],
                                  "tarih": c["bitis"], "ikili": o["ikili"], "yanlis": o["yanlis"]})
                yer[set_adi] = {"yanlis_toplam": sum(ikililer.values()), "ikili": len(ikililer),
                                "kaynaklar": kaynaklar, "ikililer": dict(sorted(ikililer.items()))}
                satirlar.append(f"{c['kip']}/{katman}/{set_adi}: yanlış {o['yanlis']} "
                                f"({o['ikili']} ikili)")
    esik_yolu.write_text(json.dumps(esik, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return satirlar


def kapi_hukmu(c: dict) -> dict:
    nedenler = []
    for e in c["esik_sinamasi"]:
        if e["sonuc"] == "asildi":
            nedenler.append(f"eşik aşıldı: {e['katman']}/{e['set']} yanlış {e['yanlis']} > {e['ust']}")
    for g in c["gercek_pozitifler"]:
        if g.get("zorunlu") and g["sonuc"] == "yok":
            nedenler.append(f"zorunlu gerçek pozitif {g['sonuc']}: {g['set']}/{g['ikili']} "
                            f"{g['katman']} `{g['etiket_re']}`")
    if c.get("girdi_hatalari"):
        nedenler.append(f"{len(c['girdi_hatalari'])} girdi ölçülemedi")
    kod = 1 if nedenler else 0
    return {"sonuc": "GEÇTİ" if kod == 0 else "DÜŞTÜ", "cikis_kodu": kod, "nedenler": nedenler}


def dogrudan_kos(setler: list[str], katmanlar: list[str], setler_dosyasi: Path, paralel: int,
                 calisma_koku: Path, agac: str) -> tuple[dict, list]:
    kayitlar: dict[str, list[dict]] = {}
    hatalar = []
    calisma_koku.mkdir(parents=True, exist_ok=True)
    for s in setler:
        girdiler = sabit_set(s, setler_dosyasi)
        kayitlar[s] = []
        with cf.ProcessPoolExecutor(max_workers=max(1, paralel), initializer=_isci_baslat,
                                    initargs=(agac,)) as havuz:
            gel = {havuz.submit(ikili_olc, g, katmanlar, str(calisma_koku)): g for g in girdiler}
            for n, f in enumerate(cf.as_completed(gel), 1):
                k = f.result()
                kayitlar[s].append(k)
                if k.get("hata"):
                    hatalar.append((f"{s}:{k['anahtar']}", k["hata"]))
                if n % 20 == 0 or n == len(girdiler):
                    print(f"[kapı] {s}: {n}/{len(girdiler)}", flush=True)
        kayitlar[s].sort(key=lambda k: k["anahtar"])
    return kayitlar, hatalar


# ---------------------------------------------------------------------------
# Çıktı kipi: bir koşu dizininin yapıtları
# ---------------------------------------------------------------------------

_BILESIM_BOLUMU = re.compile(r"^### Algorithm Compositions[^\n]*\n(.*?)(?=^#{2,3} |\Z)", re.M | re.S)
_BILESIM_SATIRI = re.compile(r"^- \*\*(.+?)\*\* \((\w+), confidence: (\d+)%\)", re.M)
_ALGORITMA_BASLIGI = re.compile(r"^\s*\*\s*@algorithm\s+(.+?)\s+\((\w+), confidence: (\d+)%\)\s*$", re.M)
_SECURITY_BASLIGI = re.compile(r"^\s*\*\s*@security\s+(.+?)\s*$", re.M)
_BLOK_YORUMU = re.compile(r"^\s*// --- ([^:\n]{3,60}):", re.M)
_YAPI_TANIMI = re.compile(r"^struct (recovered_struct_\d+) \{", re.M)


def _bilesim_sablonlari() -> set[str]:
    """Ölçülen ağaçtaki alan şablonu adları (``KNOWN_COMPOSITIONS``); çağrı zinciri adları değil."""
    from karadul.reconstruction.engineering.composition_analyzer import KNOWN_COMPOSITIONS
    return {t["name_template"] for t in KNOWN_COMPOSITIONS.values()}


def _say(desen: re.Pattern, dosyalar: list[Path], kok: Path) -> dict[str, dict]:
    """Desenin ilk grubu → {adet, ornek dosyalar}; dosyalar ``kok``'e göreli."""
    sayac: dict[str, dict] = {}
    for f in dosyalar:
        try:
            metin = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in desen.finditer(metin):
            d = sayac.setdefault(m.group(1).strip(), {"adet": 0, "ornek": []})
            d["adet"] += 1
            if len(d["ornek"]) < 3:
                d["ornek"].append(str(f.relative_to(kok)))
    return sayac


def _sayac_iddialari(onek: str, sayac: dict[str, dict]) -> list[dict]:
    return [_iddia(f"{onek}:{ad}", v["ornek"], adet=v["adet"]) for ad, v in sorted(sayac.items())]


def _json_oku(yol: Path) -> Any:
    return json.loads(yol.read_text(encoding="utf-8")) if yol.is_file() else None


def _yok(yapit: str) -> dict:
    return {"durum": "yapit_yok", "neden": f"{yapit} yok", "iddialar": []}


def cikti_bilesim(ws: Path, out: Path, sablonlar: set[str]) -> dict:
    """MUH-03 / ARAYUZ-01: ``reports/report.md`` "Algorithm Compositions" bölümündeki alan şablonları."""
    rapor = ws / "reports/report.md"
    if not rapor.is_file():
        return _yok("reports/report.md")
    m = _BILESIM_BOLUMU.search(rapor.read_text(encoding="utf-8", errors="replace"))
    iddialar, genel = [], 0
    for ad, desen, guven in (_BILESIM_SATIRI.findall(m.group(1)) if m else []):
        if ad in sablonlar:
            iddialar.append(_iddia(f"sablon:{ad}", f"{desen}, confidence {guven}%", guven=int(guven)))
        else:
            genel += 1  # "X -> Y Pipeline", "Fork-Join at …": çağrı zinciri betimi, alan iddiası değil
    return {"durum": "calisti", "iddialar": iddialar, "genel_desen": genel}


def _c_dosyalari(out: Path) -> list[Path]:
    return sorted((out / "src").rglob("*.c")) if (out / "src").is_dir() else []


def cikti_algoritma_kod(ws: Path, out: Path, _s) -> dict:
    """TIP-09: ürün kodundaki ``@algorithm`` başlıkları (adet = etiketli fonksiyon sayısı)."""
    dosyalar = _c_dosyalari(out)
    if not dosyalar:
        return _yok("out/src/**/*.c")
    return {"durum": "calisti", "iddialar": _sayac_iddialari(
        "algoritma", _say(_ALGORITMA_BASLIGI, dosyalar, out))}


def cikti_algoritma_json(ws: Path, out: Path, _s) -> dict:
    """TIP-09: ``reconstructed/algorithms.json`` (yapısal kanıt ``: matched`` ayrıca sayılır)."""
    veri = _json_oku(ws / "reconstructed/algorithms.json")
    if veri is None:
        return _yok("reconstructed/algorithms.json")
    sayac: dict[str, dict] = {}
    for a in veri.get("algorithms", []) or []:
        d = sayac.setdefault(a.get("name", "?"), {"adet": 0, "yapisal": 0, "ornek": []})
        d["adet"] += 1
        kanit = " ".join(map(str, a.get("evidence", []) or []))
        d["yapisal"] += 1 if ": matched" in kanit else 0
        if len(d["ornek"]) < 3:
            d["ornek"].append(f"{a.get('function')}: {kanit[:80]}")
    return {"durum": "calisti", "iddialar": [
        _iddia(f"algoritma:{ad}", v["ornek"], adet=v["adet"], yapisal=v["yapisal"])
        for ad, v in sorted(sayac.items())]}


def cikti_security_etiketi(ws: Path, out: Path, _s) -> dict:
    """TIP-08: ürün kodundaki ``@security`` başlıkları."""
    dosyalar = _c_dosyalari(out)
    if not dosyalar:
        return _yok("out/src/**/*.c")
    return {"durum": "calisti", "iddialar": _sayac_iddialari(
        "security", _say(_SECURITY_BASLIGI, dosyalar, out))}


def cikti_blok_yorumu(ws: Path, out: Path, _s) -> dict:
    """MUH-07: blok yorumcusunun ``// --- <betim>:`` satırları ("Row-major matrix access" ...)."""
    dosyalar = _c_dosyalari(out)
    if not dosyalar:
        return _yok("out/src/**/*.c")
    return {"durum": "calisti", "iddialar": _sayac_iddialari(
        "blok", _say(_BLOK_YORUMU, dosyalar, out))}


def cikti_types_h(ws: Path, out: Path, _s) -> dict:
    """TIP-07: ``out/src/include/types.h``'deki ``recovered_struct_NNN`` tanımları (adet)."""
    yol = out / "src/include/types.h"
    if not yol.is_file():
        return _yok("out/src/include/types.h")
    adlar = _YAPI_TANIMI.findall(yol.read_text(encoding="utf-8", errors="replace"))
    if not adlar:
        return {"durum": "calisti", "iddialar": []}
    return {"durum": "calisti", "iddialar": [
        _iddia("yapi:recovered_struct", adlar[:3], adet=len(adlar))]}


def _sarif_adi(sonuc: dict) -> str:
    p = sonuc.get("properties", {}) or {}
    for anahtar in ("technology_name", "packer_name", "yara_rule"):
        if p.get(anahtar):
            return str(p[anahtar]).split(" (")[0]
    return re.sub(r"\s+", " ", sonuc.get("message", {}).get("text", "?"))[:80]


# P07 sonrası SARIF, başka katmanların zaten kapıdan geçirdiği yapıtları da yansıtıyor: kripto
# (KRDL001, ``reconstructed/algorithms.json`` -> algoritma_json katmanı), anti-debug (KRDL003,
# ``anti_debug_findings`` -> antidebug_cikti katmanı). Bunlar burada yeniden sayılmaz (çift
# sayım); KRDL002 aracın kendi ad güvenilirliği uyarısıdır, ikili hakkında iddia değildir.
# Bu katman YARA, paketleyici izi ve IOC sonuçlarını sayar.
_SARIF_BASKA_KATMAN_KAYNAGI = frozenset({"reconstructed/algorithms.json", "anti_debug_findings"})
_SARIF_IDDIA_DEGIL = frozenset({"KRDL002"})
# SARIF'teki bir YARA isabeti iki iddia taşır: kuralın ikilide eşleştiği (``yara`` katmanının
# ``kural:<ad>`` iddiası) ve SARIF kategorisi (``ruleId``). Kategori bilgi düzeyindeyse (KRDL001 kripto
# kitaplığı / sabiti, KRDL007 derleyici / kitaplık parmak izi: "şüpheli değil") iddia, ``yara``
# katmanının ``dogru_iddialar`` kurallarıyla hükme bağlanır (OLCUM kalem 3: P07'den sonra 12 doğru
# iddia yanlış sayılıyordu). Şüpheli / paketli / gizlenmiş / zararlı kategorisindeki (KRDL003-006)
# aynı isabet yanlış suçlamadır: kural doğru olsa da yanlış kalır.
_SARIF_YARA_BILGI_KURALLARI = frozenset({"KRDL001", "KRDL007"})


def _sarif_yara_kurali(sonuc: dict) -> str | None:
    """SARIF sonucu bir YARA isabetiyse kuralın adı; değilse None.

    P07 sonrası: ``properties.source == "yara"`` ve ``yara_rule``. Öncesi (1.22.1): ``technology_name``
    (``detected_tech`` dizgisi ``"<kural> (<etiketler>)"``).
    """
    p = sonuc.get("properties", {}) or {}
    if p.get("source") == "yara" and p.get("yara_rule"):
        return str(p["yara_rule"])
    if p.get("technology_name"):
        return str(p["technology_name"]).split(" (")[0]
    return None


def cikti_sarif(ws: Path, out: Path, _s) -> dict:
    """ARAYUZ-17: ``reports/report.sarif.json`` sonuçları (``KRDL003:MPRESS_Packed`` ...)."""
    veri = _json_oku(ws / "reports/report.sarif.json")
    if veri is None:
        return _yok("reports/report.sarif.json")
    sayac: dict[str, dict] = {}
    for run in veri.get("runs", []) or []:
        for r in run.get("results", []) or []:
            if r.get("ruleId") in _SARIF_IDDIA_DEGIL or (
                    (r.get("properties") or {}).get("source") in _SARIF_BASKA_KATMAN_KAYNAGI):
                continue
            d = sayac.setdefault(f"{r.get('ruleId')}:{_sarif_adi(r)}",
                                 {"adet": 0, "duzey": r.get("level"), "ornek": [], "yara": set()})
            d["adet"] += 1
            d["yara"].add(_sarif_yara_kurali(r))
            if len(d["ornek"]) < 2:
                d["ornek"].append(r.get("message", {}).get("text", "")[:160])
    iddialar = []
    for e, v in sorted(sayac.items()):
        ek = {"adet": v["adet"], "duzey": v["duzey"]}
        # aynı etikette YARA dışı bir sonuç da varsa YARA kuralı yazılmaz (hüküm yalnız etiketle)
        if len(v["yara"]) == 1 and None not in v["yara"]:
            ek["yara_kurali"] = next(iter(v["yara"]))
        iddialar.append(_iddia(e, v["ornek"], **ek))
    return {"durum": "calisti", "iddialar": iddialar}


def cikti_intel(ws: Path, out: Path, _s) -> dict:
    """IMZA-01'in ürün çıktısı: ``static/intelligence_report.json``."""
    veri = _json_oku(ws / "static/intelligence_report.json")
    return _yok("static/intelligence_report.json") if veri is None else {
        "durum": "calisti", "iddialar": bi_iddialari(veri)}


def cikti_antidebug(ws: Path, out: Path, _s) -> dict:
    veri = _json_oku(ws / "static/anti_debug_findings.json")
    return _yok("static/anti_debug_findings.json") if veri is None else {
        "durum": "calisti", "iddialar": antidebug_iddialari(veri)}


def cikti_packer(ws: Path, out: Path, _s) -> dict:
    veri = _json_oku(ws / "static/packer_fingerprints.json")
    return _yok("static/packer_fingerprints.json") if veri is None else {
        "durum": "calisti", "iddialar": packer_iddialari(veri)}


def cikti_yara(ws: Path, out: Path, _s) -> dict:
    """IMZA-05'in ürün çıktısı: ``pipeline_result.json`` → ``static.stats.detected_tech``.

    stages.py yalnız eşleşme varsa yazar; boş liste "tarandı, temiz" ile "taranmadı"yı ayırmaz
    (IMZA-15). ``yara_backend`` alanı varsa durum "calisti", yoksa "bilinmiyor".
    """
    veri = _json_oku(ws / "reports/pipeline_result.json")
    if veri is None:
        return _yok("reports/pipeline_result.json")
    st = (veri.get("stages", {}).get("static", {}) or {}).get("stats", {}) or {}
    iddialar = [_iddia(f"kural:{t.split(' (')[0]}", t) for t in st.get("detected_tech", []) or []]
    return {"durum": "calisti" if "yara_backend" in st else "bilinmiyor", "iddialar": iddialar,
            "neden": None if "yara_backend" in st else "yara_backend yok: tarandı mı bilinmiyor"}


def cikti_bilesim_yeniden(ws: Path, out: Path, sablonlar: set[str]) -> dict:
    """MUH-03'ün **yeniden oynatması**: ölçülen ağacın bileşim çözümleyicisi, koşunun kayıtlı
    girdileriyle (Ghidra'sız). Girdiler ``pipeline/steps/deep_tracing.py``'nin verdikleri:
    çağrı çizgesi (varsa genişletilmiş), ``algorithms.json`` + ``engineering_algorithms.json``,
    ``data_flow/data_flow.json``, ``dispatch_resolution.json``. HEAD koşusunda şablon adları
    14/14 ikilide kayıtlı ``algorithm_compositions.json`` ile aynı (P00.md).
    """
    from karadul.reconstruction.engineering import AlgorithmCompositionAnalyzer
    r, st = ws / "reconstructed", ws / "static"
    gerekli = [r / "algorithms.json", r / "engineering_algorithms.json", st / "ghidra_call_graph.json"]
    eksik = [str(p.relative_to(ws)) for p in gerekli if not p.is_file()]
    if eksik:
        return _yok(", ".join(eksik))
    genis = sorted(r.glob("*augmented*")) + sorted(st.glob("*augmented*"))
    cg = _json_oku(genis[0] if genis else st / "ghidra_call_graph.json")
    algos = ((_json_oku(r / "algorithms.json") or {}).get("algorithms", [])
             + (_json_oku(r / "engineering_algorithms.json") or {}).get("algorithms", []))
    sonuc = AlgorithmCompositionAnalyzer().analyze(
        call_graph=cg, algorithms=algos, data_flow=_json_oku(r / "data_flow/data_flow.json"),
        dispatch_result=_json_oku(r / "dispatch_resolution.json"))
    iddialar = {}
    for c in sonuc.compositions:
        if c.name in sablonlar and c.name not in iddialar:
            iddialar[c.name] = _iddia(f"sablon:{c.name}", [s.name for s in c.stages][:4],
                                      guven=round(float(c.confidence) * 100))
    return {"durum": "calisti", "iddialar": list(iddialar.values())}


def cikti_algoritma_yeniden(ws: Path, out: Path, _s) -> dict:
    """TIP-09'un **yeniden oynatması**: ölçülen ağacın ``CAlgorithmIdentifier``'ı, koşunun kayıtlı
    Ghidra çıktısıyla (``static/ghidra_output/decompiled`` + fonksiyon/dizgi JSON'u; Ghidra'sız).
    HEAD koşusunda (ad, fonksiyon) çoklu kümesi 14/14 ikilide ``algorithms.json`` ile aynı.
    """
    from karadul.config import Config
    from karadul.reconstruction.c_algorithm_id import CAlgorithmIdentifier
    st = ws / "static"
    if not (st / "ghidra_output/decompiled").is_dir():
        return _yok("static/ghidra_output/decompiled")
    sonuc = CAlgorithmIdentifier(Config.load(None)).identify(
        st / "ghidra_output/decompiled", st / "ghidra_functions.json", st / "ghidra_strings.json")
    sayac: dict[str, dict] = {}
    for a in sonuc.algorithms:
        d = sayac.setdefault(a.name, {"adet": 0, "yapisal": 0, "ornek": []})
        d["adet"] += 1
        kanit = " ".join(map(str, getattr(a, "evidence", []) or []))
        d["yapisal"] += 1 if ": matched" in kanit else 0
        if len(d["ornek"]) < 3:
            d["ornek"].append(f"{a.function_name}: {kanit[:80]}")
    return {"durum": "calisti", "iddialar": [
        _iddia(f"algoritma:{ad}", v["ornek"], adet=v["adet"], yapisal=v["yapisal"])
        for ad, v in sorted(sayac.items())]}


CIKTI_CAGRI: dict[str, Callable[[Path, Path, set], dict]] = {
    "bilesim": cikti_bilesim, "algoritma_kod": cikti_algoritma_kod,
    "algoritma_json": cikti_algoritma_json, "security_etiketi": cikti_security_etiketi,
    "sarif": cikti_sarif, "blok_yorumu": cikti_blok_yorumu, "types_h": cikti_types_h,
    "intel": cikti_intel, "antidebug_cikti": cikti_antidebug, "packer_cikti": cikti_packer,
    "yara_cikti": cikti_yara,
    "bilesim_yeniden": cikti_bilesim_yeniden, "algoritma_yeniden": cikti_algoritma_yeniden,
}
CIKTI_KATMANLARI = tuple(CIKTI_CAGRI)
# Çıktı katmanı → doğrudan kipteki eşi: dogru_iddialar ve izlenen_yanlislar kuralları ikisine de uyar.
KATMAN_ESI = {"intel": "bi", "antidebug_cikti": "antidebug", "packer_cikti": "packer",
              "yara_cikti": "yara", "bilesim_yeniden": "bilesim",
              "algoritma_yeniden": "algoritma_json"}


def kosu_ikilileri(kok: Path) -> list[tuple[str, Path, Path, bool]]:
    """``urun_kos.py`` düzeni: ``<kök>/<anahtar>/{ws,out,BITTI}`` → (anahtar, ws, out, bitti)."""
    sonuc = []
    for d in sorted(p.parent for p in kok.rglob("out") if p.is_dir() and (p.parent / "ws").is_dir()):
        wsler = sorted((d / "ws/workspaces").glob("*/*"))
        if not wsler:
            continue
        sonuc.append((str(d.relative_to(kok)), wsler[-1], d / "out", (d / "BITTI").exists()))
    return sonuc


def cikti_kos(kok: Path, set_adi: str, katmanlar: list[str] | None) -> tuple[dict, list, dict]:
    katmanlar = katmanlar or list(CIKTI_KATMANLARI)
    bilinmeyen = [k for k in katmanlar if k not in CIKTI_CAGRI]
    if bilinmeyen:
        raise SystemExit(f"[kapı] bilinmeyen çıktı katmanı: {bilinmeyen}")
    sablonlar = _bilesim_sablonlari()
    kunye = _json_oku(kok / "kosu_kunyesi.json") or {}
    ikililer = kosu_ikilileri(kok)
    if not ikililer:
        raise SystemExit(f"[kapı] {kok}: ws/ + out/ taşıyan ikili dizini yok")
    kayitlar, hatalar = [], []
    beklenen = kunye.get("secilen_is")
    if isinstance(beklenen, int) and beklenen != len(ikililer):
        # yalnız biten kayıtları sayan kapı yarım koşuyu geçirir: beklenen sayıyla karşılaştır
        hatalar.append(("<koşu>", f"künyede {beklenen} iş, dizinde {len(ikililer)} ikili"))
    for anahtar, ws, out, bitti in ikililer:
        kayit: dict[str, Any] = {"anahtar": anahtar, "ws": str(ws), "bitti": bitti, "katmanlar": {}}
        if not bitti:
            hatalar.append((anahtar, "BITTI yok: koşu yarım ya da başarısız"))
        for k in katmanlar:
            try:
                kayit["katmanlar"][k] = CIKTI_CAGRI[k](ws, out, sablonlar)
            except Exception as exc:  # bozuk yapıt kayda geçer, sayım sürer
                kayit["katmanlar"][k] = {"durum": "hata", "neden": f"{type(exc).__name__}: {exc}",
                                         "iddialar": []}
        kayitlar.append(kayit)
    bilgi = {"kok": str(kok), "commit": (kunye.get("agac") or {}).get("commit"),
             "surum": (kunye.get("agac") or {}).get("karadul_surumu"),
             "ikili": len(ikililer), "katmanlar": katmanlar, "set": set_adi,
             "sablon_sayisi": len(sablonlar)}
    return {set_adi: kayitlar}, hatalar, bilgi


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--agac", type=Path, default=DEPO, help="ölçülen kod ağacı (depo kökü)")
    ap.add_argument("--set", default=None, help=f"doğrudan kip setleri, virgüllü ({','.join(SETLER)})")
    ap.add_argument("--katman", default=None, help="katman alt kümesi, virgüllü")
    ap.add_argument("--kosu", type=Path, default=None, help="çıktı kipi: koşu dizini")
    ap.add_argument("--kosu-seti", default="gelistirme", help="çıktı kipinde koşunun set adı")
    ap.add_argument("--cikti-dizin", type=Path, default=None, help="masum_kapi.json + .md buraya")
    ap.add_argument("--karsilastir", type=Path, default=None, help="önceki masum_kapi.json")
    ap.add_argument("--esik", type=Path, default=ESIK_DOSYASI)
    ap.add_argument("--setler-dosyasi", type=Path, default=SETLER_DOSYASI)
    ap.add_argument("--paralel", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    ap.add_argument("--setleri-sabitle", action="store_true", help="--set girdilerini sha256 ile yaz")
    ap.add_argument("--pozitif-kur", action="store_true", help="UPX'li kopyaları ve örneği üret")
    ap.add_argument("--esik-yaz", type=Path, nargs="+", default=None,
                    help="bu kapı çıktılarının (masum_kapi.json) yanlış sayılarını eşik yap")
    a = ap.parse_args(argv)

    if a.esik_yaz:
        for satir in esik_yaz(a.esik_yaz, a.esik):
            print(f"[kapı] eşik {satir} → {a.esik}")
        return 0
    if a.pozitif_kur:
        for adim in pozitif_kur(a.setler_dosyasi):
            print(f"[kapı] pozitif {adim['ad']}: çıkış {adim['cikis']}")
        return 0
    if a.setleri_sabitle:
        setler = (a.set or ",".join(SETLER)).split(",")
        kayit = setleri_sabitle(setler, a.setler_dosyasi)
        for s in setler:
            print(f"[kapı] {s}: {len(kayit['setler'][s])} girdi sabitlendi → {a.setler_dosyasi}")
        return 0
    if bool(a.set) == bool(a.kosu):
        ap.error("ya --set (doğrudan kip) ya --kosu (çıktı kipi) verin")

    t0 = time.monotonic()
    agac = agaci_yukle(a.agac)
    esik = esik_yukle(a.esik)
    c: dict[str, Any] = {"arac": "masum_kapi", "surum": 1, "baslangic": _simdi(), "agac": agac,
                         "python": sys.version.split()[0], "esik_dosyasi": str(a.esik)}
    if a.set:
        setler = a.set.split(",")
        katmanlar = (a.katman or ",".join(DOGRUDAN_KATMANLAR)).split(",")
        bilinmeyen = [k for k in katmanlar if k not in DOGRUDAN_CAGRI]
        if bilinmeyen:
            ap.error(f"bilinmeyen doğrudan katman: {bilinmeyen}")
        c.update({"kip": "dogrudan", "setler": setler, "katmanlar": katmanlar,
                  "araclar": {t: shutil.which(t) for t in ("strings", "nm", "lipo", "otool")}})
        calisma = Path(tempfile.gettempdir()) / f"masum_kapi_{os.getpid()}"
        kayitlar, hatalar = dogrudan_kos(setler, katmanlar, a.setler_dosyasi, a.paralel, calisma,
                                         agac["agac"])
        shutil.rmtree(calisma, ignore_errors=True)
    else:
        c["kip"] = "cikti"
        kayitlar, hatalar, kosu_bilgi = cikti_kos(a.kosu.expanduser().resolve(), a.kosu_seti,
                                                  (a.katman.split(",") if a.katman else None))
        kosu_bilgi["agac_farkli"] = bool(kosu_bilgi.get("commit")) and \
            kosu_bilgi["commit"] != agac["commit"]
        c["kosu"] = kosu_bilgi
    hukumle(kayitlar, esik)
    c["ozet"] = ozetle(kayitlar)
    c["ek_sayaclar"] = ek_sayaclar(kayitlar)
    c["izlenen"] = izlenenleri_say(kayitlar, esik)
    c["gercek_pozitifler"] = gercek_pozitifleri_sina(kayitlar, esik)
    c["esik_sinamasi"] = esigi_sina(c["ozet"], esik, c["kip"])
    c["girdi_hatalari"] = hatalar
    if a.karsilastir:
        c["karsilastirma"] = karsilastir(c, json.loads(a.karsilastir.read_text("utf-8")))
    c["kapi"] = kapi_hukmu(c)
    c["bitis"] = _simdi()
    c["sure_sn"] = round(time.monotonic() - t0, 1)
    c["kayitlar"] = kayitlar
    md = markdown(c)
    if a.cikti_dizin:
        a.cikti_dizin.mkdir(parents=True, exist_ok=True)
        (a.cikti_dizin / "masum_kapi.json").write_text(
            json.dumps(c, ensure_ascii=False, indent=1, default=str) + "\n", encoding="utf-8")
        (a.cikti_dizin / "masum_kapi.md").write_text(md, encoding="utf-8")
        # Kayıtsız özet: depoya konabilecek boyutta; --karsilastir için yeter.
        ozet = {k: v for k, v in c.items() if k != "kayitlar"}
        (a.cikti_dizin / "masum_kapi_ozet.json").write_text(
            json.dumps(ozet, ensure_ascii=False, indent=1, default=str) + "\n", encoding="utf-8")
        print(f"[kapı] yazıldı: {a.cikti_dizin}/masum_kapi{{.json,.md,_ozet.json}}")
    print(md if len(md) < 6000 else md[:6000] + "\n…(kısaltıldı)")
    return c["kapi"]["cikis_kodu"]


if __name__ == "__main__":
    raise SystemExit(main())
