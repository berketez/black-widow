#!/usr/bin/env python
"""ÖLÇEK kalem 3: kod bölümü boyutu (ELF ``.text``, Mach-O ``__text``) — ölçekleme değişkeni.

Gösteri dilimi (Go + Swift) 26,6 MB ama kodu 5,5 MB: dosya baytı xref / CFG maliyetinin kötü
vekili. Bu betik ``olcek_topla.py`` künyesindeki her ikilinin analiz edilen kopyasında
(``raw/``) bölüm başlıklarını ``llvm-size -A`` ile okur ve ``metin_bayt`` ekler. Geliştirme seti
ikilileri açık kaynaktır (Debian / Homebrew paketleri); yalnız bölüm başlığı okunur.

Ayrıca ``--ek`` ile verilen AÇIK KAYNAK Mach-O dosyaları için ``__text`` boyutu ve
``LC_FUNCTION_STARTS`` girdi sayısı (``llvm-objdump --macho --function-starts``) yazılır: büyük
ikililerde bayt başına fonksiyon yoğunluğunun kalibrasyonu. Kapalı kaynak dosya VERİLMEZ.

Kullanım (depo kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcek/metin_boyutu.py \
        --kunye ~/karadul_olcum/runs/arge-2026-11-19/olcek/olcek_a62f15e.json \
        --cikti ~/karadul_olcum/runs/arge-2026-11-19/olcek/olcek_a62f15e_metin.json \
        [--ek-liste DOSYA_LISTESI.txt --ek-cikti yogunluk.json]
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

LLVM = Path("/opt/homebrew/Cellar/llvm/23.1.6/bin")
_SATIR = re.compile(r"^(\S+)\s+(\d+)\s+(\d+)\s*$")


def metin(yol: Path, arch: str | None = None) -> int | None:
    kom = [str(LLVM / "llvm-size"), "-A"]
    if arch:
        kom.append(f"--arch={arch}")
    r = subprocess.run([*kom, str(yol)], capture_output=True, text=True)
    if r.returncode != 0:
        return None
    toplam = 0
    bulundu = False
    for s in r.stdout.splitlines():
        m = _SATIR.match(s.strip())
        if m and m.group(1) in (".text", "__text"):
            toplam += int(m.group(2))
            bulundu = True
    return toplam if bulundu else None


def fonksiyon_baslangici(yol: Path, arch: str | None) -> int | None:
    kom = [str(LLVM / "llvm-objdump"), "--macho", "--function-starts"]
    if arch:
        kom.append(f"--arch={arch}")
    r = subprocess.run([*kom, str(yol)], capture_output=True, text=True)
    if r.returncode != 0:
        return None
    return sum(1 for s in r.stdout.splitlines() if re.match(r"^[0-9a-fA-F]{6,}", s.strip()))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--kunye", type=Path)
    ap.add_argument("--cikti", type=Path)
    ap.add_argument("--ek-liste", type=Path,
                    help="satır başına: <yol>\\t<arch|->\\t<etiket>\\t<mimari sayısı>")
    ap.add_argument("--ek-cikti", type=Path)
    a = ap.parse_args(argv)
    if a.kunye and a.cikti:
        d = json.loads(a.kunye.read_text(encoding="utf-8"))
        eksik = 0
        for k in d["kayitlar"]:
            raw = Path(k["calisma_alani"]) / "raw"
            aday = sorted(p for p in raw.iterdir() if p.is_file() and p.suffix != ".json")
            # analiz edilen kopya: dilim varsa <ad>_<arch>, yoksa tek dosya
            secilen = next((p for p in aday if k.get("dilim") and p.name.endswith("_" + k["dilim"])), None)
            secilen = secilen or (aday[0] if aday else None)
            k["metin_bayt"] = metin(secilen) if secilen else None
            eksik += k["metin_bayt"] is None
        a.cikti.write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"metin boyutu: {len(d['kayitlar'])} kayıt, eksik {eksik}", file=sys.stderr)
    if a.ek_liste and a.ek_cikti:
        out = []
        for satir in a.ek_liste.read_text(encoding="utf-8").splitlines():
            if not satir.strip():
                continue
            yol, arch, etiket, mimari = (satir.split("\t") + ["", "", "1"])[:4]
            arch = None if arch in ("", "-") else arch
            p = Path(yol)
            m = metin(p, arch)
            f = fonksiyon_baslangici(p, arch)
            out.append({"yol": yol, "arch": arch, "etiket": etiket, "dosya_bayt": p.stat().st_size,
                        "mimari_sayisi": int(mimari or 1),
                        "metin_bayt": m, "fonksiyon_baslangici": f,
                        "fonk_per_metin_mib": round(f / (m / 2**20), 1) if m and f else None})
            print(f"{etiket:12} {p.name[:40]:40} metin {((m or 0)/2**20):7.1f} MiB  fonk {f}  "
                  f"yoğunluk {out[-1]['fonk_per_metin_mib']}", file=sys.stderr, flush=True)
        a.ek_cikti.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
