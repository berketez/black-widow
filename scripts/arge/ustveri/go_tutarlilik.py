"""Go `pclntab` adlarının zorunlu yapılarla çapraz denetimi (I4 tasarımı; ARGE, ürün kodu değil).

Denetimler (fonksiyon başına işaret üretir):
  T1  itab: `itab.Fun[i]`'nin gösterdiği fonksiyonun adı, arayüzün i. yönteminin adıyla bitmeli.
      (Fun göstericisi arayüz çağrısı için zorunlu; arayüz yöntem adı `itabInit`'te dizgi olarak karşılaştırılır.)
  T2  yöntem tablosu: somut tipin `Method.Tfn` / `Ifn` adresindeki fonksiyonun adı yöntem adıyla bitmeli;
      paket öneki tipin `PkgPath`'i olmalı.
  T3  dosya ↔ paket: fonksiyonun kaynak dosya yolunun dizini, adındaki paket yoluyla uyuşmalı.
  T4  derleme birimi: aynı `cuOffset`'i paylaşan fonksiyonların çoğunluk paketi dışındaki paket şüphelidir.
  T5  funcID çapası: özel funcID taşıyan fonksiyon `runtime.` adını taşımalı (sürüm tablosu varsa tam ad).
  T6  biçim: ad geçerli UTF-8, denetim karakteri yok, paket bileşeni var.

Kullanım:
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ustveri/go_tutarlilik.py <ikili> [--dilim arm64] [--cikti x.json]
İkiliyi çalıştırmaz.
"""
from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import go_pclntab as G  # noqa: E402
import go_tip  # noqa: E402
import macho  # noqa: E402

_SURUM_RE = re.compile(r"@v[^/]+")


def koseli_soy(ad: str) -> str:
    """Tip parametresi köşeli ayraç öbeklerini (iç içe dahil) at: `T[go.shape.int].M` → `T.M`."""
    out = []
    d = 0
    for c in ad:
        if c == "[":
            d += 1
        elif c == "]":
            d = max(0, d - 1)
        elif d == 0:
            out.append(c)
    return "".join(out)


def kacis_coz(pkg: str) -> str:
    """Sembol adındaki `%2e` gibi kaçışları çöz (bağlayıcı, son yol öğesindeki noktayı kaçırır)."""
    return re.sub(r"%([0-9a-fA-F]{2})", lambda mo: chr(int(mo.group(1), 16)), pkg)


def son_bilesen(ad: str) -> str:
    """Adın son bileşeni: `pkg.(*T[…]).M` → `M`; tip parametreleri ve `-fm` eki soyulur."""
    g = koseli_soy(ad)
    if g.endswith("-fm"):
        g = g[:-3]
    return g.rsplit(".", 1)[-1]


def dosya_paketi(dosya: str) -> str:
    """Kaynak dosya yolundan paket dizini: sürüm eki (`@v1.2.3`) atılır."""
    d = dosya.rsplit("/", 1)[0] if "/" in dosya else ""
    return _SURUM_RE.sub("", d)


def denetle(m, p=None):
    """Dönen: (işaretler: {giriş adresi: {denetim adı, …}}, kapsam: {denetim: kapsanan giriş kümesi}, özet)."""
    p = p or G.PclnTab(m)
    fs = p.funcs()
    es = {f.entry: f for f in fs}
    bi = G.buildinfo(m) or {}
    isaret = collections.defaultdict(set)
    kapsam = collections.defaultdict(set)
    ozet = {}

    # ---- T1 / T2 --------------------------------------------------------
    tip = go_tip.GoTipleri(m, p, bi.get("surum") or "")
    itablar = tip.itabs() if tip.types else []
    t1_bak = t1_uy = 0
    for _a, _inter, _typ, ms, fun in itablar:
        for (mad, _off), adr in zip(ms, fun):
            f = es.get(adr)
            if f is None or mad is None:
                continue
            if f.name == "runtime.unreachableMethod":   # bağlayıcının budadığı yöntemin yer tutucusu
                continue
            t1_bak += 1
            kapsam["T1"].add(adr)
            if son_bilesen(f.name) == mad:
                t1_uy += 1
            else:
                isaret[adr].add("T1")
    tipler = tip.ulasilan_tipler(itablar) if tip.types else set()
    t2_bak = t2_uy = t2_pkg_bak = t2_pkg_uy = 0
    yontemli_tip = 0
    for t in tipler:
        u = tip.uncommon(t)
        if not u:
            continue
        pkg, ys = u
        if ys:
            yontemli_tip += 1
        for mad, _off, ifn, tfn in ys:
            for adr in (ifn, tfn):
                f = es.get(adr)
                if f is None or mad is None:
                    continue
                t2_bak += 1
                kapsam["T2"].add(adr)
                tamam = son_bilesen(f.name) == mad
                if tamam:
                    t2_uy += 1
                else:
                    isaret[adr].add("T2")
                if pkg:
                    t2_pkg_bak += 1
                    if kacis_coz(G.pkg_of(f.name)) == pkg:
                        t2_pkg_uy += 1
                    else:
                        isaret[adr].add("T2p")
    ozet["T1"] = {"itab": len(itablar), "bakilan_yuva": t1_bak, "uyan": t1_uy,
                  "kapsanan_fonksiyon": len(kapsam["T1"])}
    ozet["T2"] = {"ulasilan_tip": len(tipler), "yontemli_tip": yontemli_tip, "bakilan": t2_bak, "uyan": t2_uy,
                  "paket_bakilan": t2_pkg_bak, "paket_uyan": t2_pkg_uy,
                  "kapsanan_fonksiyon": len(kapsam["T2"])}

    # ---- T3: dosya ↔ paket ---------------------------------------------
    ana_paket = bi.get("path")
    t3_bak = t3_uy = 0
    for f in fs:
        if not f.name:
            continue
        pkg = kacis_coz(G.pkg_of(f.name))
        dosya = p.file_of(f)
        if not dosya or not pkg or pkg.startswith(("type:", "go:")) or dosya.startswith("<"):
            continue
        dp = dosya_paketi(dosya)
        t3_bak += 1
        kapsam["T3"].add(f.entry)
        if dp == pkg or (pkg == "main" and ana_paket and dp == ana_paket) or dp.endswith("/" + pkg) \
                or (pkg.startswith("vendor/") and dp.endswith(pkg)):
            t3_uy += 1
        else:
            isaret[f.entry].add("T3")
    ozet["T3"] = {"bakilan": t3_bak, "uyan": t3_uy}

    # ---- T4: derleme birimi çoğunluğu ----------------------------------
    cu = collections.defaultdict(list)
    for f in fs:
        if f.name:
            cu[f.cu_offset].append(f)
    t4_bak = t4_uy = 0
    for _c, liste in cu.items():
        say = collections.Counter(G.pkg_of(f.name) for f in liste
                                  if not G.pkg_of(f.name).startswith(("type:", "go:")) and G.pkg_of(f.name))
        if not say:
            continue
        cogunluk, _n = say.most_common(1)[0]
        for f in liste:
            pk = G.pkg_of(f.name)
            if not pk or pk.startswith(("type:", "go:")):
                continue
            t4_bak += 1
            kapsam["T4"].add(f.entry)
            if pk == cogunluk:
                t4_uy += 1
            else:
                isaret[f.entry].add("T4")
    ozet["T4"] = {"derleme_birimi": len(cu), "bakilan": t4_bak, "uyan": t4_uy}

    # ---- T5: funcID çapası ---------------------------------------------
    sarma = max(f.func_id for f in fs)
    t5_bak = t5_uy = 0
    for f in fs:
        if 0 < f.func_id < sarma:
            t5_bak += 1
            kapsam["T5"].add(f.entry)
            bek = G.FUNC_ID_ADI.get(G.FUNC_ID[f.func_id]) if sarma == 23 else None
            if (bek is not None and f.name == bek) or (bek is None and f.name.startswith("runtime.")):
                t5_uy += 1
            else:
                isaret[f.entry].add("T5")
    ozet["T5"] = {"bakilan": t5_bak, "uyan": t5_uy}

    # ---- T6: biçim ------------------------------------------------------
    t6 = 0
    for f in fs:
        if not f.name:
            continue
        if "�" in f.name or any(ord(c) < 0x20 for c in f.name):
            isaret[f.entry].add("T6")
            t6 += 1
    ozet["T6"] = {"bicimsiz": t6}
    ozet["fonksiyon"] = len(fs)
    ozet["isaretli_fonksiyon"] = len(isaret)
    ozet["isaret_dagilimi"] = dict(collections.Counter(k for v in isaret.values() for k in v))
    ozet["cift_kaynakli_fonksiyon"] = len(kapsam["T1"] | kapsam["T2"] | kapsam["T5"])
    return isaret, kapsam, ozet


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ikili")
    ap.add_argument("--dilim")
    ap.add_argument("--cikti")
    a = ap.parse_args()
    m = macho.load(a.ikili, a.dilim)
    _isaret, _kapsam, ozet = denetle(m)
    ozet["ikili"] = a.ikili
    s = json.dumps(ozet, ensure_ascii=False, indent=1)
    if a.cikti:
        Path(a.cikti).write_text(s + "\n")
    print(s)


if __name__ == "__main__":
    main()
