#!/usr/bin/env python3
"""Ürün ölçümü koşucusu: saklı taban koşularının ham girdilerini verilen ağaçtaki ürünle koşar.

GT okunmaz; yalnız Karadul çıktısı üretilir. Yerleşim tabanla aynıdır (``urun_olc.py`` bunu okur):

    <kök>/debian/<program>/<ikili>/{ws,out,kosu.log,BITTI}
    <kök>/mac/<ikili>/{ws,out,kosu.log,BITTI}

Girdi, taban koşusunun çalışma alanındaki ``raw/`` kopyasıdır; sha256'sı ``raw/target_info.json``
ile karşılaştırılır (iki kol aynı dosyayı ölçsün). Ürün ``--agac`` ile verilen ağaçtan yüklenir ve
bunun gerçekten öyle olduğu koşudan önce denetlenir (worktree ve editable kurulum tuzağı).

Kullanım:
    python scripts/measurement/urun_kos.py --agac ~/karadul_olcum/urun-<commit> \
        --kok ~/karadul_olcum/runs/urun-yeni-<commit> --paralel 3
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

DEPO = Path(__file__).resolve().parents[2]
GHIDRA = Path.home() / "Library/BlackWidowBuild/ghidra_12.1.2_PUBLIC"
TABAN_DEBIAN = Path.home() / "karadul_olcum/n1_debian13"
TABAN_MAC = DEPO / "workspaces/olcum_mac/runs/ol7-c-b7faeac"
# Ağaçta bulunması gereken, git'in izlemediği çalışma zamanı verisi (measure.RUNTIME_DATA ile aynı).
CALISMA_VERISI = ("sigs", "vendor", "signatures_homebrew.json",
                  "signatures_homebrew_bytes.json", "sigs_macos_system.json")
ZAMAN_ASIMI_SN = 3600
BITTI = "BITTI"


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


def _ham_girdi(kosu: Path) -> tuple[Path, str]:
    """``<kosu>/ws/workspaces/<ad>/<zaman>/raw`` altındaki tek ikili ve beklenen sha256'sı."""
    hamlar = sorted((kosu / "ws" / "workspaces").glob("*/*/raw"))
    if len(hamlar) != 1:
        raise SystemExit(f"{kosu}: {len(hamlar)} raw dizini (tam olarak bir tane olmalı)")
    ham = hamlar[0]
    bilgi = json.loads((ham / "target_info.json").read_text(encoding="utf-8"))
    dosyalar = sorted(p for p in ham.iterdir() if p.is_file() and p.name != "target_info.json")
    if len(dosyalar) != 1:
        raise SystemExit(f"{ham}: {len(dosyalar)} girdi dosyası (tam olarak bir tane olmalı)")
    return dosyalar[0], bilgi["file_hash"]


def isleri_topla(taban_debian: Path, taban_mac: Path) -> list[dict]:
    """Her iş: anahtar (``debian/<program>/<ikili>`` ya da ``mac/<ikili>``), girdi, beklenen sha256."""
    isler = []
    for prog in sorted(p for p in taban_debian.iterdir() if p.is_dir()):
        for d in sorted(p for p in prog.iterdir() if p.is_dir()):
            girdi, ozet = _ham_girdi(d)
            isler.append({"anahtar": f"debian/{prog.name}/{d.name}", "girdi": girdi, "sha256": ozet})
    for d in sorted(p for p in taban_mac.iterdir() if p.is_dir() and (p / "ws").is_dir()):
        girdi, ozet = _ham_girdi(d)
        isler.append({"anahtar": f"mac/{d.name}", "girdi": girdi, "sha256": ozet})
    return isler


def agac_kunyesi(agac: Path) -> dict:
    """Ağacın commit'i, kirli dosyaları ve ``karadul``'un gerçekten oradan yüklendiği."""
    ortam = dict(os.environ, PYTHONPATH=str(agac))
    yoklama = subprocess.run(
        [sys.executable, "-c", "import karadul; print(karadul.__file__); print(karadul.__version__)"],
        cwd=agac, env=ortam, capture_output=True, text=True, check=True).stdout.split()
    paket = Path(yoklama[0]).resolve()
    if not str(paket).startswith(str(agac.resolve()) + os.sep):
        raise SystemExit(f"karadul {paket} yükleniyor, {agac} DEĞİL: koşu yanlış ağacı ölçerdi")
    eksik = [n for n in CALISMA_VERISI if not (agac / n).exists()]
    if eksik:
        raise SystemExit(f"{agac}: çalışma zamanı verisi yok: {eksik} (ana depodakilere bağ verin)")
    kirli = _git(agac, "status", "--porcelain", "--untracked-files=no")
    return {"agac": str(agac), "commit": _git(agac, "rev-parse", "HEAD"),
            "kirli": kirli.splitlines() if kirli else [],
            "karadul_dosyasi": str(paket), "karadul_surumu": yoklama[1]}


def calistir(is_: dict, agac: Path, kok: Path, zaman_asimi: int) -> dict:
    hedef = kok / is_["anahtar"]
    hedef.mkdir(parents=True, exist_ok=True)
    gercek = _sha(is_["girdi"])
    if gercek != is_["sha256"]:
        return {"anahtar": is_["anahtar"], "durum": "girdi_degismis", "sure_sn": 0.0}
    ortam = dict(os.environ, GHIDRA_INSTALL_DIR=str(GHIDRA), PYTHONPATH=str(agac))
    komut = [sys.executable, "-m", "karadul", "analyze", str(is_["girdi"]), "--skip-dynamic",
             "--output-dir", str(hedef / "ws"), "--output", str(hedef / "out")]
    t0 = time.monotonic()
    with open(hedef / "kosu.log", "w", encoding="utf-8") as gunluk:
        surec = subprocess.Popen(komut, cwd=agac, env=ortam, stdout=gunluk,
                                 stderr=subprocess.STDOUT, start_new_session=True)
        try:
            kod = surec.wait(timeout=zaman_asimi)
            durum = "tamam" if kod == 0 else f"cikis_{kod}"
        except subprocess.TimeoutExpired:
            os.killpg(surec.pid, signal.SIGKILL)
            surec.wait()
            durum = "zaman_asimi"
    if durum == "tamam":
        (hedef / BITTI).write_text("0\n", encoding="utf-8")
    return {"anahtar": is_["anahtar"], "durum": durum, "sure_sn": round(time.monotonic() - t0, 1)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--agac", type=Path, required=True, help="ürünün yükleneceği git ağacı")
    ap.add_argument("--kok", type=Path, required=True, help="yeni koşu kökü")
    ap.add_argument("--paralel", type=int, default=3)
    ap.add_argument("--zaman-asimi", type=int, default=ZAMAN_ASIMI_SN, help="ikili başına saniye")
    ap.add_argument("--taban-debian", type=Path, default=TABAN_DEBIAN)
    ap.add_argument("--taban-mac", type=Path, default=TABAN_MAC)
    ap.add_argument("--yalniz", action="append", default=[],
                    help="yalnız bu anahtar(lar) (ör. debian/tree/tree); yinelenebilir")
    a = ap.parse_args(argv)

    agac, kok = a.agac.expanduser().resolve(), a.kok.expanduser().resolve()
    isler = isleri_topla(a.taban_debian.expanduser(), a.taban_mac.expanduser())
    toplam = len(isler)
    if a.yalniz:
        isler = [i for i in isler if i["anahtar"] in set(a.yalniz)]
    # Büyük girdiler önce: uzun işler koşunun sonuna kalmasın.
    isler.sort(key=lambda i: (-i["girdi"].stat().st_size, i["anahtar"]))
    bekleyen = [i for i in isler if not (kok / i["anahtar"] / BITTI).exists()]

    kok.mkdir(parents=True, exist_ok=True)
    kunye = {"amac": "ürün ölçümü, yeni kol; GT kullanılmadan üretilen Karadul çıktıları",
             "agac": agac_kunyesi(agac), "ghidra": str(GHIDRA), "python": sys.version.split()[0],
             "komut": "python -m karadul analyze <girdi> --skip-dynamic --output-dir <d>/ws --output <d>/out",
             "taban_debian": str(a.taban_debian), "taban_mac": str(a.taban_mac),
             "paralel": a.paralel, "zaman_asimi_sn": a.zaman_asimi,
             "PYTHONHASHSEED": os.environ.get("PYTHONHASHSEED"),
             "tabandaki_is": toplam, "secilen_is": len(isler), "bekleyen_is": len(bekleyen),
             "baslangic": _simdi()}
    kunye_yolu = kok / "kosu_kunyesi.json"
    kunye_yolu.write_text(json.dumps(kunye, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"[kos] {kunye['agac']['commit'][:10]} ({kunye['agac']['karadul_dosyasi']}); "
          f"{len(bekleyen)} / {len(isler)} iş koşacak, paralel {a.paralel}", flush=True)

    sonuclar = []
    with cf.ThreadPoolExecutor(max_workers=max(1, a.paralel)) as havuz:
        gelecekler = [havuz.submit(calistir, i, agac, kok, a.zaman_asimi) for i in bekleyen]
        for n, g in enumerate(cf.as_completed(gelecekler), 1):
            s = g.result()
            sonuclar.append(s)
            print(f"[{n:3}/{len(bekleyen)}] {s['anahtar']:40} {s['durum']:12} {s['sure_sn']:8.1f} sn",
                  flush=True)

    sonuclar.sort(key=lambda s: s["anahtar"])
    bitmeyen = [s for s in sonuclar if s["durum"] != "tamam"]
    son = agac_kunyesi(agac)
    kunye.update({"bitis": _simdi(), "sonuclar": sonuclar, "bitmeyen": bitmeyen,
                  "agac_bitiste": son,
                  "agac_degisti": (son["commit"], son["kirli"]) != (kunye["agac"]["commit"],
                                                                   kunye["agac"]["kirli"])})
    kunye_yolu.write_text(json.dumps(kunye, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"[kos] bitti: {len(sonuclar) - len(bitmeyen)} tamam, {len(bitmeyen)} bitmeyen", flush=True)
    return 1 if bitmeyen else 0


if __name__ == "__main__":
    raise SystemExit(main())
