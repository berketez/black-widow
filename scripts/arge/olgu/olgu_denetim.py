#!/usr/bin/env python3
"""OLGU tablosunun ek denetimleri: DEFTER.md'deki sayıların betiği.

Alt komutlar (depo kökünden; çıktı JSON, stdout'a):

``dwarfsiz``      DWARF eşleşmesi olmayan iç fonksiyonlar: GT adının kalıbına (libgcc yüzer nokta,
                  libgcc atomik, bağlayıcı kaplaması, diğer) ve bölümüne göre sayım. ``derleyici``
                  kuralının (SEMA.md §4) geliştirme setindeki denetimi.
``kayit_capraz``  Kayıt çifti komşularının bağımsız denetimi: hedef bir Ghidra dizgisinin başıysa,
                  Ghidra'nın o dizgiye verdiği veri xref'leri bizim yuvamızı içeriyor mu (RELATIVE /
                  fixup okumasının Ghidra'yla uyumu). Ghidra dizgisi olmayan hedefler ayrı sayılır.
``on_ad_tekil``   ``on_ad:gnulib`` kanalının nüfustaki doğru adları kaç tekil (sınıf, GT adı)
                  çiftinden geliyor. Çıktıda GT adı geçer (geliştirme seti; BUTCE.md'ye yazılmaz).
``ozet``          Kanıt alanlarının satır sayıları (pcode, dizgi, veri yeri, kayıt çifti, çağrı dizgisi).
``dizgi_kaynagi`` ``ghidra_xrefs.json`` ``strings_used`` ile ``ghidra_strings.json`` ``xrefs[].from_func_addr``
                  aynı (fonksiyon → dizgi kümesi) mı; 119 ikilide fonksiyon başına.

    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olgu/olgu_denetim.py dwarfsiz
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True
_BURASI = Path(__file__).resolve().parent
if str(_BURASI) not in sys.path:
    sys.path.insert(0, str(_BURASI))

import olgu_ikili as oi  # noqa: E402
import olgu_tablosu as ot  # noqa: E402

YUZER_RE = re.compile(r"^__(?:(?:add|sub|mul|div|neg|eq|ne|le|lt|ge|gt|unord)(?:tf|bf|sf|df)[23]|"
                      r"(?:fix|fixuns|float|floatun|extend|trunc)\w*(?:tf|bf|sf|df)\w*|sfp_handle_exceptions)$")
ATOMIK_RE = re.compile(r"^(?:__aarch64_\w+|init_have_lse_atomics)$")
KAPLAMA_RE = re.compile(r"^e8(?:43419|35769)@")


def _kunye(tablo: Path) -> dict[str, Any]:
    return json.loads(tablo.with_name(tablo.name.replace(".jsonl.gz", "") + "_kunye.json").read_text("utf-8"))


def dwarfsiz(tablo: Path) -> dict[str, Any]:
    kunye = _kunye(tablo)
    static = {(i["birim"], i["ikili"]): Path(i["static"]) for i in kunye["ikililer"]}
    goruntu: dict[tuple, Any] = {}
    sayac: Counter = Counter()
    for s in ot.tablo_oku(tablo):
        if s["thunk"] or s["dis"] or s["platform"] != "debian" or s["dw_eslesme"] != "yok":
            continue
        ad = (s["gt_adlari"] or [None])[0]
        if ad is None:
            kalip = "gt_yok"
        elif ATOMIK_RE.match(ad):
            kalip = "libgcc_atomik"
        elif YUZER_RE.match(ad):
            kalip = "libgcc_yuzer"
        elif KAPLAMA_RE.match(ad):
            kalip = "baglayici_kaplamasi"
        elif s["gt_crt"]:
            kalip = "crt"
        else:
            kalip = "diger"
        anahtar = (s["birim"], s["ikili"])
        if anahtar not in goruntu:
            hedef = json.loads((static[anahtar].parent / "raw" / "target_info.json").read_text("utf-8"))
            goruntu[anahtar] = oi.elf_oku(Path(hedef["path"]))[0]
        b = goruntu[anahtar].bolum_bul(s["dosya_adresi"])
        sayac[json.dumps([kalip, b.ad if b else None, s["nufusta"], s["kaynak_sinifi"]], ensure_ascii=False)] += 1
    return {"satir": sum(sayac.values()), "kalip_bolum_nufus_sinif": dict(sorted(sayac.items()))}


def kayit_capraz(tablo: Path) -> dict[str, Any]:
    kunye = _kunye(tablo)
    static = {(i["birim"], i["ikili"]): Path(i["static"]) for i in kunye["ikililer"]}
    xref_onbellek: dict[tuple, dict[int, set[int]]] = {}
    sayac: Counter = Counter()
    for s in ot.tablo_oku(tablo):
        if not s.get("veri_yerleri"):
            continue
        anahtar = (s["birim"], s["ikili"])
        if anahtar not in xref_onbellek:
            xr: dict[int, set[int]] = defaultdict(set)
            for d in json.loads((static[anahtar] / "ghidra_strings.json").read_text("utf-8"))["strings"]:
                a = ot._hex(d.get("address"))
                if a is None:
                    continue
                for x in d.get("xrefs") or []:
                    f = ot._hex(x.get("from_address"))
                    if f is not None:
                        xr[a].add(f)
                xr.setdefault(a, set())
            xref_onbellek[anahtar] = xr
        xr = xref_onbellek[anahtar]
        for y in s["veri_yerleri"]:
            sayac[f"{s['platform']}:yer"] += 1
            sayac[f"{s['platform']}:yer_got"] += int(y["got"])
            for d in y["d"]:
                yuva = y["y"] + d["o"] * oi.ISARETCI_GENISLIGI
                if d["a"] in xr:
                    if yuva in xr[d["a"]]:
                        durum = "yuvadan_xref_var"
                    elif xr[d["a"]]:
                        durum = "yuvadan_xref_yok_baska_xref_var"
                    else:
                        durum = "dizginin_hic_xrefi_yok"
                    sayac[f"{s['platform']}:ghidra_dizgisi:{durum}"] += 1
                else:
                    sayac[f"{s['platform']}:ghidra_dizgisi_degil:uzunluk_{'<4' if len(d['m']) < 4 else '>=4'}"] += 1
    return dict(sorted(sayac.items()))


def on_ad_tekil(tablo: Path) -> dict[str, Any]:
    c: Counter = Counter()
    for s in ot.tablo_oku(tablo):
        if s["nufusta"] and s["urun_olcude"] and s["kanal"] == "on_ad:gnulib" and s["hukum"] == "dogru":
            c[json.dumps([s["kaynak_sinifi"], s["gt_adlari"][0]], ensure_ascii=False)] += 1
    return {"dogru": sum(c.values()), "tekil": len(c), "dagilim": dict(c.most_common())}


def ozet(tablo: Path) -> dict[str, Any]:
    c: Counter = Counter()
    for s in ot.tablo_oku(tablo):
        c["satir"] += 1
        for alan in ("pcode_var", "kayit_cifti_var", "yaprak", "dolayli_cagri"):
            c[alan] += int(bool(s.get(alan)))
        c["dizgili"] += int(bool(s.get("dizgi_sayisi")))
        c["veri_yerli"] += int(bool(s.get("veri_yeri_sayisi")))
        c["cagri_dizgili"] += int(bool(s.get("cagri_dizgileri")))
        c["veri_yeri"] += s.get("veri_yeri_sayisi") or 0
        c["kayit_komsu_dizgi"] += sum(len(y["d"]) for y in s.get("veri_yerleri") or [])
        c["kayit_komsu_dizgi_ghidra"] += sum(1 for y in s.get("veri_yerleri") or [] for d in y["d"] if d.get("g"))
        c["cagri_dizgisi"] += len(s.get("cagri_dizgileri") or [])
        c["cagri_ciftleri_desteklenmiyor"] += int(s.get("cagri_ciftleri") == "desteklenmiyor")
    return dict(c)


def dizgi_kaynagi(tablo: Path) -> dict[str, Any]:
    kunye = _kunye(tablo)
    c: Counter = Counter()
    for i in kunye["ikililer"]:
        st = Path(i["static"])
        xr = json.loads((st / "ghidra_xrefs.json").read_text("utf-8"))["function_xrefs"]
        by: dict[str, set] = defaultdict(set)
        for d in json.loads((st / "ghidra_strings.json").read_text("utf-8"))["strings"]:
            for x in d.get("xrefs") or []:
                if x.get("from_func_addr"):
                    by[x["from_func_addr"]].add(d["address"])
        for a, v in xr.items():
            c["ayni" if {d["address"] for d in v.get("strings_used") or []} == by.get(a, set()) else "farkli"] += 1
        c["fazla_fonksiyon"] += len(set(by) - set(xr))
    return dict(c)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("komut", choices=("dwarfsiz", "kayit_capraz", "on_ad_tekil", "ozet", "dizgi_kaynagi"))
    ap.add_argument("--tablo", type=Path, default=ot.VARSAYILAN_TABLO)
    a = ap.parse_args(argv)
    fonk = {"dwarfsiz": dwarfsiz, "kayit_capraz": kayit_capraz, "on_ad_tekil": on_ad_tekil, "ozet": ozet,
            "dizgi_kaynagi": dizgi_kaynagi}[a.komut]
    print(json.dumps(fonk(a.tablo), ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
