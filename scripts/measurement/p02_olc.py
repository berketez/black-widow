"""P02 ölçümü: anti-debug ve paketleyici dedektörlerinin masum / gerçek pozitif setteki hükümleri.

Ürünün çağırdığı biçim (``karadul/pipeline/steps/anti_debug.py`` ve
``karadul/pipeline/steps/packer_fingerprint.py``)::

    AntiDebugDetector(target=..., binary_path=<ham ikili>).detect() + .summary()
    PackerFingerprintDetector(<ham ikili>).detect()

Ghidra yok, tam ürün koşusu yok; dedektörler ham ikili üstünde koşar. Adım
evrensel Mach-O'da ``binary_prep``'in ürettiği arm64 dilimini verir; burada
ham (evrensel) dosya verilir ki x86-64 dilimi de sınansın (daha sıkı sınav).

Setler:
  gelistirme  — ``urun_kos.isleri_topla`` (119 ikili; çoğu Debian AArch64 ELF)
  macos       — /bin, /usr/bin, /usr/sbin, /usr/lib/dyld (evrenseller x86-64 dilimi taşır)
  pe_masum    — Ghidra, pip/distlib, setuptools, pnpm fastlist, makensis PE'leri
  pozitif     — ``~/karadul_olcum/runs/onarim-2026-11-18/P02/pozitif/`` (yerelde üretilir;
                bkz. ``scripts/measurement/p02_pozitif/uret.sh``)

YARA yerleşik kuralları (P03'ün işi) ayrı sütunda sayılır, karıştırılmasın diye.

Kullanım (worktree kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/measurement/p02_olc.py --etiket once
    PYTHONDONTWRITEBYTECODE=1 python scripts/measurement/p02_olc.py --etiket sonra
    python scripts/measurement/p02_olc.py --kiyas once sonra
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

DEPO = Path(__file__).resolve().parents[2]
if str(DEPO) not in sys.path:
    sys.path.insert(0, str(DEPO))

ANA_DEPO = Path("/Users/apple/Black_Widow")
CIKTI = Path.home() / "karadul_olcum/runs/onarim-2026-11-18/P02"
POZITIF = CIKTI / "pozitif"

MACOS_IKILILER = [
    "/bin/ls", "/bin/cat", "/bin/cp", "/bin/mv", "/bin/ps", "/bin/sh", "/bin/zsh",
    "/bin/dd", "/bin/df", "/bin/chmod", "/bin/date", "/bin/kill", "/bin/ln",
    "/bin/mkdir", "/bin/rm", "/bin/pwd", "/bin/test", "/bin/expr",
    "/usr/bin/ssh", "/usr/bin/top", "/usr/bin/vim", "/usr/bin/curl",
    "/usr/bin/less", "/usr/bin/grep", "/usr/bin/find", "/usr/bin/tar",
    "/usr/bin/zip", "/usr/bin/lldb", "/usr/bin/login", "/usr/sbin/sysctl",
    "/usr/lib/dyld",
]

PE_KOKLERI = [
    (Path.home() / "Library/BlackWidowBuild/ghidra_12.1.2_PUBLIC", "**/*.exe"),
    (Path("/opt/anaconda3/lib/python3.12/site-packages/pip/_vendor/distlib"), "*.exe"),
    (Path("/opt/homebrew/lib/python3.11/site-packages/setuptools"), "*.exe"),
    (Path("/opt/homebrew/lib/node_modules/pnpm/dist/vendor"), "*.exe"),
    (Path("/opt/homebrew/Cellar/makensis/3.13/share/nsis"), "**/*.exe"),
]

# Rapor eşikleri (karadul/reporting/markdown_report.py::_severity_icon ile aynı).
ESIK_HIGH = 0.7
ESIK_MED = 0.4


def _sha(yol: Path) -> str:
    h = hashlib.sha256()
    with open(yol, "rb") as f:
        for parca in iter(lambda: f.read(1 << 20), b""):
            h.update(parca)
    return h.hexdigest()


def _derece(puan: float) -> str:
    if puan >= ESIK_HIGH:
        return "HIGH"
    if puan >= ESIK_MED:
        return "MED"
    return "INFO"


def setleri_topla() -> dict[str, list[tuple[str, Path]]]:
    from scripts.measurement.urun_kos import TABAN_DEBIAN, isleri_topla

    taban_mac = ANA_DEPO / "workspaces/olcum_mac/runs/ol7-c-b7faeac"
    gelistirme = [(i["anahtar"], Path(i["girdi"])) for i in isleri_topla(TABAN_DEBIAN, taban_mac)]
    macos = [(y, Path(y)) for y in MACOS_IKILILER if Path(y).is_file() and os.access(y, os.R_OK)]
    pe: list[tuple[str, Path]] = []
    gorulen: set[str] = set()
    for kok, desen in PE_KOKLERI:
        if not kok.is_dir():
            continue
        for p in sorted(kok.glob(desen)):
            if p.is_file() and str(p) not in gorulen:
                gorulen.add(str(p))
                pe.append((str(p), p))
    pozitif = sorted(((p.name, p) for p in POZITIF.glob("*") if p.is_file()), key=lambda t: t[0])
    return {"gelistirme": gelistirme, "macos": macos, "pe_masum": pe, "pozitif": pozitif}


def tek_ikili(yol: Path) -> dict:
    from karadul.analyzers.anti_debug_detector import AntiDebugDetector
    from karadul.analyzers.packer_fingerprint import PackerFingerprintDetector
    from karadul.analyzers.yara_scanner import YaraScanner

    kayit: dict = {"yol": str(yol), "sha256": _sha(yol), "boyut": yol.stat().st_size}
    try:
        det = AntiDebugDetector(binary_path=yol)
        bulgular = det.detect()
        ozet = det.summary(bulgular)
        kayit["anti_debug"] = {
            "puan": ozet.get("anti_debug_score", 0.0),
            "derece": _derece(float(ozet.get("anti_debug_score", 0.0))) if bulgular else "yok",
            "bulgular": [
                {"teknik": f.technique, "kategori": f.category, "guven": f.confidence,
                 "kanit": f.evidence}
                for f in bulgular
            ],
        }
    except Exception as exc:  # ölçüm betiği: hatayı kayda geçir, sayıma "hata" diye girsin
        kayit["anti_debug"] = {"hata": repr(exc)}
    try:
        fps = PackerFingerprintDetector(yol).detect()
        kayit["paketleyici"] = [
            {"ad": fp.packer_name, "guven": round(fp.confidence, 3), "kanit": fp.evidence,
             "katman": fp.layers_matched}
            for fp in fps
        ]
    except Exception as exc:
        kayit["paketleyici"] = {"hata": repr(exc)}
    try:
        tarayici = YaraScanner()
        tarayici.load_builtin_rules()
        kayit["yara_p03"] = sorted({m.rule for m in tarayici.scan_file(yol).matches})
    except Exception as exc:
        kayit["yara_p03"] = {"hata": repr(exc)}
    return kayit


def _kunye() -> dict:
    def git(*a: str) -> str:
        return subprocess.run(["git", "-C", str(DEPO), *a], capture_output=True, text=True,
                              check=True).stdout.strip()
    import karadul
    return {"commit": git("rev-parse", "HEAD"),
            "kirli": git("status", "--porcelain", "--untracked-files=no").splitlines(),
            "karadul_dosyasi": karadul.__file__}


def olc(etiket: str) -> Path:
    logging.disable(logging.WARNING)
    setler = setleri_topla()
    sonuc = {"kunye": _kunye(), "setler": {}}
    for ad, ikililer in setler.items():
        sonuc["setler"][ad] = {anahtar: tek_ikili(yol) for anahtar, yol in ikililer}
        print(f"{ad}: {len(ikililer)} ikili", file=sys.stderr)
    CIKTI.mkdir(parents=True, exist_ok=True)
    hedef = CIKTI / f"{etiket}.json"
    hedef.write_text(json.dumps(sonuc, indent=1, ensure_ascii=False), encoding="utf-8")
    print(tablo(sonuc, etiket))
    return hedef


def say(set_kayit: dict) -> dict:
    """Bir setin sayımları: teknik / derece / paketleyici / YARA kuralı başına kaç ikili."""
    teknik: Counter = Counter()
    teknik_guclu: Counter = Counter()   # güven >= 0,4 olan bulgu
    derece: Counter = Counter()
    paket: Counter = Counter()
    yara: Counter = Counter()
    hata = 0
    for kayit in set_kayit.values():
        ad = kayit.get("anti_debug", {})
        if "hata" in ad:
            hata += 1
        else:
            derece[ad["derece"]] += 1
            for t in {b["teknik"] for b in ad["bulgular"]}:
                teknik[t] += 1
            for t in {b["teknik"] for b in ad["bulgular"] if b["guven"] >= ESIK_MED}:
                teknik_guclu[t] += 1
        pk = kayit.get("paketleyici")
        if isinstance(pk, dict):
            hata += 1
        else:
            for p in {x["ad"] for x in pk}:
                paket[p] += 1
        yr = kayit.get("yara_p03")
        if isinstance(yr, list):
            for r in yr:
                yara[r] += 1
    return {"n": len(set_kayit), "teknik": teknik, "teknik_guclu": teknik_guclu,
            "derece": derece, "paket": paket, "yara": yara, "hata": hata}


def _sayac_metni(c: Counter) -> str:
    return ", ".join(f"{k} {v}" for k, v in sorted(c.items(), key=lambda t: (-t[1], t[0]))) or "—"


def tablo(sonuc: dict, etiket: str) -> str:
    satirlar = [f"### {etiket} — commit {sonuc['kunye']['commit'][:7]}"
                f"{' (kirli)' if sonuc['kunye']['kirli'] else ''}", "",
                "| Set | İkili | Anti-debug derecesi (ikili) | Teknik (ikili; tümü) | "
                "Teknik (ikili; güven ≥ 0,4) | Paketleyici (ikili) | YARA, P03 (ikili) | Hata |",
                "|---|---|---|---|---|---|---|---|"]
    for ad, set_kayit in sonuc["setler"].items():
        s = say(set_kayit)
        satirlar.append(
            f"| {ad} | {s['n']} | {_sayac_metni(s['derece'])} | {_sayac_metni(s['teknik'])} | "
            f"{_sayac_metni(s['teknik_guclu'])} | {_sayac_metni(s['paket'])} | "
            f"{_sayac_metni(s['yara'])} | {s['hata']} |")
    return "\n".join(satirlar)


def pozitif_ayrinti(sonuc: dict) -> str:
    satirlar = ["| Örnek | Anti-debug (derece, puan) | Teknikler (güven) | Paketleyici (güven) |",
                "|---|---|---|---|"]
    for ad, k in sorted(sonuc["setler"].get("pozitif", {}).items()):
        a = k.get("anti_debug", {})
        tek = ", ".join(f"{b['teknik']} {b['guven']}" for b in a.get("bulgular", [])) or "—"
        pk = k.get("paketleyici")
        pkm = ", ".join(f"{x['ad']} {x['guven']}" for x in pk) if isinstance(pk, list) else str(pk)
        satirlar.append(f"| {ad} | {a.get('derece')} {a.get('puan')} | {tek} | {pkm or '—'} |")
    return "\n".join(satirlar)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--etiket", help="ölçüm etiketi (çıktı: <CIKTI>/<etiket>.json)")
    ap.add_argument("--kiyas", nargs=2, metavar=("ONCE", "SONRA"), help="iki ölçümün tablosunu bas")
    args = ap.parse_args()
    if args.kiyas:
        for et in args.kiyas:
            sonuc = json.loads((CIKTI / f"{et}.json").read_text(encoding="utf-8"))
            print(tablo(sonuc, et))
            print()
            print(pozitif_ayrinti(sonuc))
            print()
        return
    if not args.etiket:
        ap.error("--etiket ya da --kiyas gerekli")
    olc(args.etiket)


if __name__ == "__main__":
    main()
