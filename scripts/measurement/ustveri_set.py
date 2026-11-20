#!/usr/bin/env python3
"""ÜST VERİ hedef seti (P-ÜV8 kalem 1): sembollü ikililerin kopyası, soyulmuş kopyası ve GT'si.

Soru: üst veri kanallarının (Go ``pclntab``, ObjC yöntem listesi, Swift erişim fonksiyonu, C++ RTTI)
verdiği ad gerçek adla aynı mı? Gerçek ad (GT) sembolü duran ikilinin kendi sembol tablosundan gelir;
kanal ve ürün aynı ikilinin ``/usr/bin/strip`` ile soyulmuş kopyasında ölçülür.

Veri kökü (depo dışı; ikili ve ad listesi commit'lenmez)::

    <kök>/<ad>/orig/<ad>        özgün ince dilim (evrensel dosyada arm64 dilimi bayt bayt)
    <kök>/<ad>/bin/<ad>         /usr/bin/strip ile soyulmuş kopya
    <kök>/<ad>/gt/<ad>.gt.json  GT (adres → ad kümesi; ``macho_f1`` biçimiyle uyumlu ``functions``)
    <kök>/manifest.json         künye: kaynak, sha256'lar, sürüm, lisans, bölme, soyma denetimi, sayılar

Bölme (ön kayıt ``docs/arge/2026-11-19_mythos/ustveri/olcum/on_kayit_HEDEF.md``): keşif =
terminal-notifier, docker-cli; sınama = docker-compose, iTerm2, llama-server. Sınama ikililerinde kanal
kesinliği okuyucular dondurulduktan sonra bir kez alınır (Dalga 2).

Hiçbir hedef ikili çalıştırılmaz; özgün dosyalar yerinde değiştirilmez. Araçlar mutlak yoldan:
``/usr/bin/strip``, ``/usr/bin/nm``, ``/usr/bin/xcrun dyld_info`` (PATH'teki conda araçları değil).

Kullanım::

    python scripts/measurement/ustveri_set.py hazirla [--kok ~/karadul_olcum/ustveri_set] [--yalniz <ad>]
    python scripts/measurement/ustveri_set.py ozet [--kok …]     # adsız sayılar (JSON)
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import struct
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Optional

_BURASI = Path(__file__).resolve().parent
if str(_BURASI) not in sys.path:
    sys.path.insert(0, str(_BURASI))

SEMA_GT = "karadul-ustveri-gt/1"
SEMA_MANIFEST = "karadul-ustveri-set/1"
VARSAYILAN_KOK = Path.home() / "karadul_olcum" / "ustveri_set"

BOLME_KESIF = "kesif"
BOLME_SINAMA = "sinama"
# Ön kayıtla sabit (on_kayit_HEDEF.md §1). Değişirse ön kayıt da değişmeli.
KESIF_IKILILERI = ("terminal-notifier", "docker-cli")
SINAMA_IKILILERI = ("docker-compose", "iTerm2", "llama-server")

# §9'daki sembollü ikililer. ``dilim`` None: ince dosya; "arm64": evrensel dosyanın arm64 dilimi.
SET: dict[str, dict[str, Any]] = {
    "terminal-notifier": {
        "kaynak": "/opt/homebrew/Cellar/terminal-notifier/3.1.0/terminal-notifier.app/Contents/MacOS/terminal-notifier",
        "dilim": None, "dil": "Objective-C", "surum": "3.1.0", "lisans": "MIT"},
    "docker-cli": {
        "kaynak": "/Applications/Docker.app/Contents/Resources/bin/docker",
        "dilim": None, "dil": "Go 1.24.4", "surum": "29.x (Docker Desktop paketi)", "lisans": "Apache-2.0"},
    "docker-compose": {
        "kaynak": "/Applications/Docker.app/Contents/Resources/cli-plugins/docker-compose",
        "dilim": None, "dil": "Go 1.23.8", "surum": "Docker Desktop paketi", "lisans": "Apache-2.0"},
    "iTerm2": {
        "kaynak": "~/Applications/iTerm.app/Contents/MacOS/iTerm2",
        "dilim": "arm64", "dil": "Objective-C + Swift + C++", "surum": "3.7.7", "lisans": "GPL-2.0"},
    "llama-server": {
        "kaynak": "/Applications/Ollama.app/Contents/Resources/llama-server",
        "dilim": "arm64", "dil": "C++", "surum": "Ollama 0.40.3 paketi", "lisans": "MIT"},
}

FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
CPU_ADI = {0x01000007: "x86_64", 0x0100000C: "arm64"}
# nm sembol türleri: T/t kod (__TEXT,__text); RTTI nesneleri veri bölümlerinde (S/s/D/d).
_NM_SATIR_RE = re.compile(r"^([0-9A-Fa-f]+) ([A-Za-z]) (.+)$")
RTTI_ONEKLERI = ("__ZTI", "__ZTV")
AD_TURLERI = ("objc", "swift", "cxx", "diger")


class SetHatasi(RuntimeError):
    """Setin geçerliliğini bozan durum: hazırlık durur."""


def bolme(ad: str) -> str:
    if ad in KESIF_IKILILERI:
        return BOLME_KESIF
    if ad in SINAMA_IKILILERI:
        return BOLME_SINAMA
    raise SetHatasi(f"{ad}: bölmede yok")


def sha256_bayt(veri: bytes) -> str:
    return hashlib.sha256(veri).hexdigest()


def sha256_dosya(yol: Path) -> str:
    h = hashlib.sha256()
    with open(yol, "rb") as f:
        for parca in iter(lambda: f.read(1 << 20), b""):
            h.update(parca)
    return h.hexdigest()


def dilimler(ham: bytes) -> list[tuple[str, int, int]]:
    """(mimari, ofset, boyut). İnce dosyada tek öğe (ofset 0)."""
    if len(ham) < 8:
        raise SetHatasi("dosya Mach-O olamayacak kadar kısa")
    magic_be = struct.unpack_from(">I", ham, 0)[0]
    if magic_be in (FAT_MAGIC, FAT_MAGIC_64):
        n = struct.unpack_from(">I", ham, 4)[0]
        out, pos = [], 8
        for _ in range(n):
            if magic_be == FAT_MAGIC:
                cpu, _alt, ofs, boy, _hiza = struct.unpack_from(">IIIII", ham, pos)
                pos += 20
            else:
                cpu, _alt, ofs, boy, _hiza, _ayr = struct.unpack_from(">IIQQII", ham, pos)
                pos += 32
            out.append((CPU_ADI.get(cpu, hex(cpu)), ofs, boy))
        return out
    cpu = struct.unpack_from("<I", ham, 4)[0]
    return [(CPU_ADI.get(cpu, hex(cpu)), 0, len(ham))]


def dilim_kes(ham: bytes, dilim: Optional[str]) -> bytes:
    """Evrensel dosyadan istenen dilimi bayt bayt kes; ince dosyada dilim None olmalı."""
    ds = dilimler(ham)
    if dilim is None:
        if len(ds) != 1:
            raise SetHatasi(f"evrensel dosya ({[d[0] for d in ds]}): dilim adı zorunlu")
        return ham
    secilen = [d for d in ds if d[0] == dilim]
    if len(secilen) != 1:
        raise SetHatasi(f"dilim {dilim!r} yok ya da birden çok: {[d[0] for d in ds]}")
    _m, ofs, boy = secilen[0]
    return ham[ofs:ofs + boy]


def macho_c_adi(ad: str) -> str:
    """Mach-O C sembol önekini (baştaki tek ``_``) soy; ObjC ``-[`` / ``+[`` adları değişmez."""
    return ad[1:] if ad.startswith("_") else ad


def ad_turu(ad: str) -> str:
    """GT adının biçim türü (sayım için): objc / swift / cxx / diger (C, Go)."""
    if ad.startswith(("-[", "+[")):
        return "objc"
    c = macho_c_adi(ad)
    if c.startswith(("$s", "$S", "_T0")):
        return "swift"
    if c.startswith("_Z"):
        return "cxx"
    return "diger"


def nm_ayristir(metin: str) -> tuple[dict[int, list[str]], dict[int, list[str]]]:
    """``nm -n -U`` metninden (fonksiyon GT, RTTI GT). Fonksiyon: T/t, ``__mh_execute_header`` hariç;
    RTTI: adı ``__ZTI`` / ``__ZTV`` ile başlayan tanımlı sembol (tür fark etmez)."""
    import macho_f1 as mf
    fonk = mf.parse_nm(metin)
    rtti: dict[int, list[str]] = {}
    for satir in metin.splitlines():
        m = _NM_SATIR_RE.match(satir.strip())
        if not m:
            continue
        ad = m.group(3)
        if ad.startswith(RTTI_ONEKLERI):
            adlar = rtti.setdefault(int(m.group(1), 16), [])
            if ad not in adlar:
                adlar.append(ad)
    return fonk, rtti


def gt_sayilari(fonk: dict[int, list[str]], rtti: dict[int, list[str]]) -> dict[str, Any]:
    """GT'nin adsız sayıları: adres, ad, ad türü (her adres için türlerin kümesi), sınıf."""
    import macho_f1 as mf
    tur_adres = Counter()
    for adlar in fonk.values():
        for t in sorted({ad_turu(a) for a in adlar}):
            tur_adres[t] += 1
    sinif = Counter(mf.fragment_class(a) for a in fonk.values())
    return {"fonksiyon_adresi": len(fonk), "fonksiyon_adi": sum(len(v) for v in fonk.values()),
            "cok_adli_adres": sum(1 for v in fonk.values() if len(v) > 1),
            "ad_turu_adres": {t: tur_adres.get(t, 0) for t in AD_TURLERI},
            "sinif": dict(sinif),
            "rtti_adresi": len(rtti),
            "typeinfo_adi": sum(1 for v in rtti.values() for a in v if a.startswith("__ZTI")),
            "vtable_adi": sum(1 for v in rtti.values() for a in v if a.startswith("__ZTV"))}


def gt_belgesi(ad: str, fonk: dict[int, list[str]], rtti: dict[int, list[str]], orig_sha: str,
               bin_sha: Optional[str], nm_kunye: dict[str, Any]) -> dict[str, Any]:
    import macho_f1 as mf
    return {
        "schema": SEMA_GT, "binary": ad, "orig_sha256": orig_sha, "stripped_sha256": bin_sha,
        "nm": nm_kunye,
        "functions": [{"addr": f"0x{a:x}", "names": n, "sinif": mf.fragment_class(n)}
                      for a, n in sorted(fonk.items())],
        "rtti": [{"addr": f"0x{a:x}", "names": n} for a, n in sorted(rtti.items())],
        "counts": gt_sayilari(fonk, rtti),
    }


def gt_oku(yol: Path) -> tuple[dict[int, list[str]], dict[int, list[str]], dict[str, Any]]:
    """GT dosyasından (fonksiyon GT, RTTI GT, belge)."""
    belge = json.loads(Path(yol).read_text(encoding="utf-8"))
    if belge.get("schema") != SEMA_GT:
        raise SetHatasi(f"{yol}: şema {belge.get('schema')!r}, beklenen {SEMA_GT!r}")
    fonk = {int(f["addr"], 16): list(f["names"]) for f in belge["functions"]}
    rtti = {int(f["addr"], 16): list(f["names"]) for f in belge.get("rtti", [])}
    return fonk, rtti, belge


def yollar(kok: Path, ad: str) -> dict[str, Path]:
    return {"orig": kok / ad / "orig" / ad, "bin": kok / ad / "bin" / ad,
            "gt": kok / ad / "gt" / f"{ad}.gt.json"}


def kilit_kesisimi(adlar: list[str]) -> list[str]:
    """Kilitli test seti havuzuyla kesişim (liste açılmaz; yalnız kesişim döner)."""
    from test_seti_kura import POOL, STRESS
    kilitli = set(POOL) | set(STRESS)
    kaynak_adlari = {Path(os.path.expanduser(SET[a]["kaynak"])).name for a in adlar if a in SET}
    return sorted((set(adlar) | kaynak_adlari) & kilitli)


def _simdi() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def hazirla_bir(ad: str, kok: Path) -> dict[str, Any]:
    """Bir ikiliyi hazırla: dilim kopyası, Apple strip, soyma denetimi, GT. Künye döner."""
    import macho_f1 as mf
    import macho_measure as mm
    tanim = SET[ad]
    kaynak = Path(os.path.expanduser(tanim["kaynak"]))
    if not kaynak.is_file():
        raise SetHatasi(f"{ad}: kaynak yok: {kaynak}")
    ham = kaynak.read_bytes()
    kaynak_sha = sha256_bayt(ham)
    dilim = dilim_kes(ham, tanim["dilim"])
    y = yollar(kok, ad)
    for p in y.values():
        p.parent.mkdir(parents=True, exist_ok=True)
    orig_sha = sha256_bayt(dilim)
    if not y["orig"].is_file() or sha256_dosya(y["orig"]) != orig_sha:
        if y["orig"].exists():
            y["orig"].chmod(0o644)
        y["orig"].write_bytes(dilim)
        y["orig"].chmod(0o444)
    mm.strip_binary(y["orig"], y["bin"])
    disa = mm.read_exports(y["bin"])
    artik = mf.parse_nm(mf.run_nm(y["bin"]))
    bin_sha = sha256_dosya(y["bin"])
    nm_metin = mf.run_nm(y["orig"])
    fonk, rtti = nm_ayristir(nm_metin)
    nm_kunye = {"path": mf.NM_PATH, "version": mf.nm_version(), "args": "-n -U"}
    gt = gt_belgesi(ad, fonk, rtti, orig_sha, bin_sha, nm_kunye)
    y["gt"].write_text(json.dumps(gt, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    fazla_disa = sorted(set(disa) - mm.ALLOWED_EXPORTS)
    return {
        "bolme": bolme(ad), "kaynak": tanim["kaynak"], "kaynak_sha256": kaynak_sha,
        "kaynak_boyut": len(ham), "dilim": tanim["dilim"], "dil": tanim["dil"], "surum": tanim["surum"],
        "lisans": tanim["lisans"], "orig_sha256": orig_sha, "orig_boyut": len(dilim),
        "stripped_sha256": bin_sha, "stripped_boyut": y["bin"].stat().st_size,
        "soyma": {"disa_aktarim_kalan": len(disa), "izinli_disi_disa_aktarim": len(fazla_disa),
                  "kalan_fonksiyon_sembolu": len(artik),
                  "temiz": not fazla_disa and not artik},
        "gt": gt["counts"], "hazirlandi": _simdi(),
    }


def hazirla(kok: Path, yalniz: Optional[list[str]] = None) -> dict[str, Any]:
    import macho_measure as mm
    adlar = [a for a in SET if not yalniz or a in yalniz]
    kesisim = kilit_kesisimi(adlar)
    if kesisim:
        raise SetHatasi(f"kilitli test setiyle kesişim: {kesisim}")
    kok.mkdir(parents=True, exist_ok=True)
    mpath = kok / "manifest.json"
    manifest = (json.loads(mpath.read_text(encoding="utf-8")) if mpath.is_file()
                else {"schema": SEMA_MANIFEST, "ikililer": {}})
    for ad in adlar:
        print(f"[hazirla] {ad}", flush=True)
        manifest["ikililer"][ad] = hazirla_bir(ad, kok)
        k = manifest["ikililer"][ad]
        print(f"  orig {k['orig_sha256'][:16]} bin {k['stripped_sha256'][:16]} soyma={k['soyma']} "
              f"gt_fonksiyon={k['gt']['fonksiyon_adresi']}", flush=True)
    manifest.update({"schema": SEMA_MANIFEST, "bolme": {BOLME_KESIF: list(KESIF_IKILILERI), BOLME_SINAMA: list(SINAMA_IKILILERI)},
                     "araclar": mm.tool_info(), "guncellendi": _simdi()})
    mpath.write_text(json.dumps(manifest, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return manifest


def manifest_oku(kok: Path) -> dict[str, Any]:
    belge = json.loads((Path(kok) / "manifest.json").read_text(encoding="utf-8"))
    if belge.get("schema") != SEMA_MANIFEST:
        raise SetHatasi(f"{kok}/manifest.json: şema {belge.get('schema')!r}")
    return belge


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    alt = ap.add_subparsers(dest="komut", required=True)
    h = alt.add_parser("hazirla")
    h.add_argument("--kok", type=Path, default=VARSAYILAN_KOK)
    h.add_argument("--yalniz", action="append", default=[])
    o = alt.add_parser("ozet")
    o.add_argument("--kok", type=Path, default=VARSAYILAN_KOK)
    a = ap.parse_args(argv)
    kok = a.kok.expanduser()
    if a.komut == "hazirla":
        hazirla(kok, a.yalniz or None)
        return 0
    m = manifest_oku(kok)
    print(json.dumps({ad: {k: v for k, v in kayit.items() if k != "kaynak"}
                      for ad, kayit in m["ikililer"].items()}, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
