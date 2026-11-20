#!/usr/bin/env python
"""KİMLİK Dalga 0 — sıralı Ghidra koşu sürücüsü (statik aşama), makine kuyruğuyla.

İş listesi düz metin: satır başına bir kimlik (``tabA/tmux/tmux``, ``v1gcc/tree``, ``kitaplik/libzstd`` …; ``#``
yorum). Sürücü her işten önce listeyi YENİDEN okur (çalışırken listeye iş eklenebilir / sıra değiştirilebilir) ve
işaret dosyası olmayan ilk işi koşar. Her iş ayrı çağrı (kilit iş başına alınır, ORTAK_D0 §3):

    ~/karadul_olcum/ghidra_kuyruk.sh KIMLIK <etiket> timeout -k 30 <sn> env … python -m karadul analyze <ikili>
        --skip-dynamic --stage static --output-dir <D>/ws --output <D>/out

``<D>`` = ``d0_veri.KOSU/<kimlik>``; ürün ağacı ``--agac`` (öntanım ``~/karadul_olcum/urun-b6aceb9``, ``urun_kos.agac_kunyesi``
ile denetlenir); ``KARADUL_CACHE_DIR=<D>/cache`` (koşuya özel); ``PYTHONHASHSEED=0``.
İşaretler: ``BITTI`` (çıkış 0 ya da 3: tam / kısmi), ``HATA`` (başka çıkış), ``ZAMAN_ASIMI``. İşaretli iş yeniden
koşulmaz. Girdi sha256'sı künyedekiyle uyuşmazsa iş ``HATA`` (girdi_degismis) olur, koşulmaz.

Kullanım (worktree kökünden): ``python scripts/arge/kimlik/d0_kos.py --isler <liste> [--zaman-asimi 1800]``
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

_BURASI = Path(__file__).resolve().parent
sys.path.insert(0, str(_BURASI))
import d0_veri  # noqa: E402

sys.path.insert(0, str(d0_veri.REPO / "scripts" / "measurement"))
import urun_kos  # noqa: E402

KUYRUK = Path.home() / "karadul_olcum" / "ghidra_kuyruk.sh"
KUYRUK_PAKETI = "KIMLIK"
AGAC = Path.home() / "karadul_olcum" / "urun-b6aceb9"
GHIDRA = Path.home() / "Library" / "BlackWidowBuild" / "ghidra_12.1.2_PUBLIC"
TIMEOUT = "/opt/homebrew/bin/timeout"
ISARETLER = ("BITTI", "HATA", "ZAMAN_ASIMI")


def sha256(yol: Path) -> str:
    h = hashlib.sha256()
    with open(yol, "rb") as f:
        for p in iter(lambda: f.read(1 << 20), b""):
            h.update(p)
    return h.hexdigest()


def isleri_oku(liste: Path) -> list[str]:
    out = []
    for s in liste.read_text(encoding="utf-8").splitlines():
        s = s.split("#", 1)[0].strip()
        if s:
            out.append(s)
    return out


def isaretli(d: Path) -> bool:
    return any((d / i).exists() for i in ISARETLER)


def kos(kimlik: str, agac: Path, zaman_asimi: int, gunluk: Path) -> dict:
    d = d0_veri.KOSU / kimlik
    d.mkdir(parents=True, exist_ok=True)
    ikili, beklenen = d0_veri.girdi(kimlik)
    gercek = sha256(ikili)
    kayit = {"kimlik": kimlik, "girdi": str(ikili), "sha256": gercek, "beklenen_sha256": beklenen}
    if beklenen and gercek != beklenen:
        (d / "HATA").write_text("girdi_degismis\n", encoding="utf-8")
        return dict(kayit, durum="girdi_degismis")
    ortam = dict(os.environ, PYTHONHASHSEED="0", PYTHONDONTWRITEBYTECODE="1", KARADUL_CACHE_DIR=str(d / "cache"),
                 GHIDRA_INSTALL_DIR=str(GHIDRA), PYTHONPATH=str(agac))
    komut = [str(KUYRUK), KUYRUK_PAKETI, f"D0:{kimlik}", TIMEOUT, "-k", "30", str(zaman_asimi),
             sys.executable, "-m", "karadul", "analyze", str(ikili), "--skip-dynamic", "--stage", "static",
             "--output-dir", str(d / "ws"), "--output", str(d / "out")]
    t0 = time.time()
    yuk0 = os.getloadavg()
    with open(d / "kosu.log", "w", encoding="utf-8") as g:
        kod = subprocess.run(komut, cwd=agac, env=ortam, stdout=g, stderr=subprocess.STDOUT).returncode
    sure = round(time.time() - t0, 1)
    if kod in (0, 3):
        (d / "BITTI").write_text(f"{kod}\n", encoding="utf-8")
        durum = "tamam" if kod == 0 else "kismi"
    elif kod == 124:
        (d / "ZAMAN_ASIMI").write_text(f"{zaman_asimi}\n", encoding="utf-8")
        durum = "zaman_asimi"
    else:
        (d / "HATA").write_text(f"cikis_{kod}\n", encoding="utf-8")
        durum = f"cikis_{kod}"
    kayit.update(durum=durum, cikis=kod, sure_sn_kuyruk_dahil=sure, yuk_baslangic=[round(x, 2) for x in yuk0],
                 bitis=time.strftime("%Y-%m-%dT%H:%M:%S"))
    (d / "kosu_kaydi.json").write_text(json.dumps(kayit, ensure_ascii=False, indent=1), encoding="utf-8")
    with open(gunluk, "a", encoding="utf-8") as g:
        g.write(json.dumps(kayit, ensure_ascii=False) + "\n")
    return kayit


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--isler", type=Path, required=True)
    ap.add_argument("--agac", type=Path, default=AGAC)
    ap.add_argument("--zaman-asimi", type=int, default=1800)
    a = ap.parse_args(argv)
    agac = a.agac.expanduser().resolve()
    kunye = urun_kos.agac_kunyesi(agac)
    if kunye["kirli"]:
        raise SystemExit(f"ürün ağacı kirli: {kunye['kirli'][:5]}")
    d0_veri.KOK.mkdir(parents=True, exist_ok=True)
    (d0_veri.KOK / "agac_kunyesi.json").write_text(json.dumps(kunye, ensure_ascii=False, indent=1), encoding="utf-8")
    gunluk = d0_veri.KOK / "kos.jsonl"
    while True:
        bekleyen = [k for k in isleri_oku(a.isler) if not isaretli(d0_veri.KOSU / k)]
        if not bekleyen:
            print("BITTI_HEPSI", flush=True)
            return 0
        k = bekleyen[0]
        print(f"{time.strftime('%H:%M:%S')} başlıyor {k} (kalan {len(bekleyen)})", flush=True)
        r = kos(k, agac, a.zaman_asimi, gunluk)
        print(f"{time.strftime('%H:%M:%S')} {k} {r['durum']} {r.get('sure_sn_kuyruk_dahil')} sn", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
