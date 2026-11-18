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
    if kural.get("katman") not in (None, katman):
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
            olculen = [k for k in liste if iz["katman"] in k.get("katmanlar", {})
                       and any(fnmatch.fnmatchcase(k["anahtar"], d) for d in iz.get("ikili", ["*"]))]
            if not olculen:
                continue
            tutan = [k["anahtar"] for k in olculen
                     if any(re.search(iz["etiket_re"], i["etiket"])
                            for i in k["katmanlar"][iz["katman"]].get("iddialar", []))]
            sonuc.append({"ad": iz["ad"], "katman": iz["katman"], "set": set_adi,
                          "etiket_re": iz["etiket_re"], "ikili": len(tutan),
                          "olculen": len(olculen), "rapordaki": iz.get("rapordaki"),
                          "ornek": tutan[:5]})
    return sonuc


def gercek_pozitifleri_sina(kayitlar: dict[str, list[dict]], esik: dict) -> list[dict]:
    sonuc = []
    dizin = {(s, k["anahtar"]): k for s, liste in kayitlar.items() for k in liste}
    for b in esik.get("gercek_pozitifler", []):
        kayit = dizin.get((b["set"], b["ikili"]))
        if kayit is None or b["katman"] not in kayit.get("katmanlar", {}):
            sonuc.append({**b, "sonuc": "olculmedi"})
            continue
        ks = kayit["katmanlar"][b["katman"]]
        bulunan = [i["etiket"] for i in ks.get("iddialar", []) if re.search(b["etiket_re"], i["etiket"])]
        sonuc.append({**b, "sonuc": "var" if bulunan else "yok", "bulunan": bulunan[:5],
                      "katman_durumu": ks.get("durum")})
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
            esiksiz = [a for a in o["ikili_basina_yanlis"] if a not in taban]
            ust = sum(taban.get(a, 0) for a in o["ikili_basina_yanlis"])
            artan = sorted(a for a, n in o["ikili_basina_yanlis"].items()
                           if a in taban and n > taban[a])
            sonuc.append({"katman": katman, "set": set_adi, "yanlis": o["yanlis"], "ust": ust,
                          "sonuc": "asildi" if o["yanlis"] > ust else "icinde",
                          "esiksiz_ikili": esiksiz, "artan_ikili": artan})
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
        s.append(f"- Koşu: `{c['kosu']['kok']}` (koşunun ağacı `{c['kosu'].get('commit') or '?'}`)")
    s.append(f"- Kapı: **{c['kapi']['sonuc']}** (çıkış {c['kapi']['cikis_kodu']})")
    for n in c["kapi"].get("nedenler", []):
        s.append(f"  - {n}")
    s += ["", "## Katman × set: yanlış iddia", "",
          "| Katman | Set | İkili | Durum | İddia | Yanlış | Doğru bilinen | Yanlışlı ikili | Eşik |",
          "|---|---|---|---|---|---|---|---|---|"]
    esik = {(e["katman"], e["set"]): e for e in c["esik_sinamasi"]}
    for katman, setler in c["ozet"].items():
        for set_adi, o in setler.items():
            e = esik.get((katman, set_adi), {})
            es = (f"{e.get('ust')} ({e['sonuc']})" if "ust" in e else e.get("sonuc", "—"))
            durum = ", ".join(f"{k} {v}" for k, v in o["durum"].items())
            s.append(f"| {katman} | {set_adi} | {o['ikili']} | {durum} | {o['iddia']} | {o['yanlis']} "
                     f"| {o['dogru_bilinen']} | {o['yanlis_ikili']} | {es} |")
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
              "| Ad | Katman | Set | Etiket | İkili / ölçülen | Rapordaki |", "|---|---|---|---|---|---|"]
        for z in c["izlenen"]:
            s.append(f"| {z['ad']} | {z['katman']} | {z['set']} | `{z['etiket_re']}` | "
                     f"{z['ikili']} / {z['olculen']} | {z.get('rapordaki') or '—'} |")
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
                esik.setdefault("esikler", {}).setdefault(c["kip"], {}).setdefault(katman, {})[
                    set_adi] = {"yanlis": o["yanlis"], "ikili": o["ikili"],
                                "kaynak": str(yol), "commit": c["agac"]["commit"][:10],
                                "tarih": c["bitis"], "ikililer": o["ikili_basina_yanlis"]}
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
        if g.get("zorunlu") and g["sonuc"] != "var":
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


def cikti_kos(kok: Path, set_adi: str, katmanlar: list[str] | None) -> tuple[dict, list, dict]:
    raise SystemExit("[kapı] çıktı kipi henüz kurulmadı (P00 İş 1b)")


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
