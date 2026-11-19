"""C++ (Itanium ABI) RTTI / vtable taraması — SEMBOLSÜZ (ARGE, ÜST VERİ hattı; ürün kodu değil).

Yöntem (sembol tablosuna bakmadan):
1. typeinfo nesnesi = ilk sözcüğü `__cxxabiv1::__class_type_info` / `__si_class_type_info` /
   `__vmi_class_type_info` vtable'ına içe aktarım bağı (dyld bağı; ada göre çözülür) olan veri nesnesi.
   İkinci sözcük ad dizgisine gösterici (Apple arm64'te en üst bit "tekil olmayan RTTI" işareti).
2. vtable = [tepeye uzaklık (tam sayı, düzeltme yeri değil)] [typeinfo göstericisi] [işlev göstericileri…];
   typeinfo göstericisi başka bir typeinfo nesnesinin içinde değilse ve ardından kod göstericisi geliyorsa.
3. Yuva = vtable'da kod bölümüne gösteren ardışık göstericiler (`__cxa_pure_virtual` gibi içe aktarımlar atlanır).

Biçim kaynağı: Itanium C++ ABI §2.5 (vtable yerleşimi), §2.9.5 (RTTI yerleşimi)
(https://itanium-cxx-abi.github.io/cxx-abi/abi.html) ve llvm-project `libcxxabi/src/private_typeinfo.h`.
Doğrulama: sembollü ikilide `__ZTI` / `__ZTV` / `__ZTS` sembolleriyle bire bir karşılaştırma.

Kullanım:
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ustveri/cpp_rtti_tara.py <ikili> [--dilim arm64] [--cikti x.json]
İkiliyi çalıştırmaz.
"""
from __future__ import annotations

import argparse
import collections
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import macho  # noqa: E402

TI_VTABLE = {
    "__ZTVN10__cxxabiv117__class_type_infoE": "class",
    "__ZTVN10__cxxabiv120__si_class_type_infoE": "si",
    "__ZTVN10__cxxabiv121__vmi_class_type_infoE": "vmi",
}
MASKE = (1 << 56) - 1


def demangle(adlar):
    """`c++filt` ile toplu çözme (sistem aracı; hedef ikili çalıştırılmaz)."""
    adlar = list(adlar)
    if not adlar:
        return {}
    girdi = "\n".join("__ZTS" + a for a in adlar) + "\n"
    try:
        out = subprocess.run(["/usr/bin/c++filt"], input=girdi, capture_output=True, text=True, timeout=120).stdout
    except (OSError, subprocess.TimeoutExpired):
        return {a: a for a in adlar}
    res = {}
    for a, satir in zip(adlar, out.splitlines()):
        on = "typeinfo name for "
        res[a] = satir[len(on):] if satir.startswith(on) else a
    return res


def tara(m):
    fx = m.fixups()
    if not fx:
        return None
    imps = m.imports()
    text = m.text_sections()
    # Zayıf (birleştirilebilir) semboller ada göre bağlanır ama tanım aynı ikilidedir: adı yerel adrese çevir.
    yerel_tanim = {}
    for sy in m.defined_symbols():
        if sy.n_type & macho.N_EXT:
            yerel_tanim.setdefault(sy.name, sy.value)

    def kodda(a):
        return any(t.addr <= a < t.addr + t.size for t in text)

    def coz(loc):
        """Düzeltme yerini çöz: ('yerel', adres, bağ adı ya da None) | ('dis', ad) | None."""
        e = fx.get(loc)
        if e is None:
            return None
        if e[0] == "rebase":
            return ("yerel", e[1] & MASKE, None, bool(e[1] >> 63))
        ad = imps[e[1]] if e[1] < len(imps) else None
        if ad in yerel_tanim:
            return ("yerel", yerel_tanim[ad], ad, False)
        return ("dis", ad)

    # 1. typeinfo nesneleri
    ti = {}
    for loc, e in fx.items():
        if e[0] == "bind" and e[1] < len(imps) and imps[e[1]] in TI_VTABLE:
            tur = TI_VTABLE[imps[e[1]]]
            ad_c = coz(loc + 8)
            if not ad_c or ad_c[0] != "yerel":
                continue
            ad = m.cstr(ad_c[1], 2048)
            if ad is None:
                continue
            tabanlar = []
            boyut = 16
            if tur == "si":
                tabanlar.append(coz(loc + 16))
                boyut = 24
            elif tur == "vmi":
                n = m.u32(loc + 20) or 0
                if n > 64:
                    n = 0
                for i in range(n):
                    tabanlar.append(coz(loc + 24 + 16 * i))
                boyut = 24 + 16 * n
            ti[loc] = {"tur": tur, "ad": ad, "ad_adresi": ad_c[1], "tekil_olmayan": ad_c[3],
                       "zayif_adla_bagli": ad_c[2] is not None, "taban": tabanlar, "boyut": boyut}
    # typeinfo nesnelerinin kapladığı aralıklar (içlerindeki typeinfo başvuruları vtable değildir)
    ic = set()
    for loc, t in ti.items():
        for off in range(8, t["boyut"], 8):
            ic.add(loc + off)

    def ti_basvurusu(loc):
        c = coz(loc)
        return c[1] if c and c[0] == "yerel" and c[1] in ti else None

    # 2. vtable'lar
    vt = []
    for loc in fx:
        if loc in ic:
            continue
        tia = ti_basvurusu(loc)
        if tia is None:
            continue
        if (loc - 8) in fx:      # tepeye uzaklık düzeltme yeri olamaz
            continue
        ott = m.u64(loc - 8)
        if ott is None:
            continue
        if ott >= 1 << 63:
            ott -= 1 << 64
        if not (-(1 << 20) <= ott <= 0):
            continue
        yuvalar = []
        zayif = 0
        a = loc + 8
        while True:
            c = coz(a)
            if c is None:
                break
            if c[0] == "dis":
                yuvalar.append(None)   # içe aktarılan işlev (ör. saf sanal)
            else:
                if not kodda(c[1]):
                    break
                yuvalar.append(c[1])
                if c[2] is not None:
                    zayif += 1
            a += 8
            if a in ic or ti_basvurusu(a) is not None:
                break
        if not yuvalar:
            continue
        vt.append({"adres": loc - 8, "typeinfo": tia, "tepeye_uzaklik": ott, "yuva": yuvalar,
                   "zayif_adli_yuva": zayif})
    return ti, vt


def say(path, dilim):
    m = macho.load(path, dilim)
    r = {"ikili": path, "dilim": m.cpu}
    sonuc = tara(m)
    if sonuc is None:
        r["durum"] = "zincirli düzeltme yok (bu betik yalnız LC_DYLD_CHAINED_FIXUPS okur)"
        return r
    ti, vt = sonuc
    cozuk = demangle({t["ad"] for t in ti.values()})
    fstarts = m.function_starts()
    fset = set(fstarts) if fstarts is not None else None
    ti_vt = collections.defaultdict(list)
    for v in vt:
        ti_vt[v["typeinfo"]].append(v)
    islev_sinif = collections.defaultdict(set)
    for v in vt:
        for i, h in enumerate(v["yuva"]):
            if h:
                islev_sinif[h].add((ti[v["typeinfo"]]["ad"], v["tepeye_uzaklik"], i))
    r.update({
        "typeinfo": len(ti), "typeinfo_tur": dict(collections.Counter(t["tur"] for t in ti.values())),
        "ayrik_sinif_adi": len({t["ad"] for t in ti.values()}),
        "cozulen_ad": sum(1 for a in cozuk if cozuk[a] != a),
        "tekil_olmayan_ad": sum(1 for t in ti.values() if t["tekil_olmayan"]),
        "zayif_adla_bagli_typeinfo": sum(1 for t in ti.values() if t["zayif_adla_bagli"]),
        "zayif_adli_yuva": sum(v["zayif_adli_yuva"] for v in vt),
        "vtable": len(vt), "birincil_vtable": sum(1 for v in vt if v["tepeye_uzaklik"] == 0),
        "vtable_olan_sinif": len(ti_vt),
        "yuva": sum(len(v["yuva"]) for v in vt),
        "ice_aktarim_yuvasi": sum(1 for v in vt for h in v["yuva"] if h is None),
        "ayrik_islev": len(islev_sinif),
        "tek_sinifta_gorunen_islev": sum(1 for s in islev_sinif.values() if len({x[0] for x in s}) == 1),
        "cok_sinifta_gorunen_islev": sum(1 for s in islev_sinif.values() if len({x[0] for x in s}) > 1),
        "islev_fonksiyon_baslangici": (sum(1 for h in islev_sinif if h in fset) if fset is not None else None),
        "LC_FUNCTION_STARTS": len(fstarts) if fstarts is not None else None,
    })
    # ---- sembol tablosu (GT) --------------------------------------------
    syms = m.defined_symbols()
    zti = {s.value: s.name for s in syms if s.name.startswith("__ZTI")}
    ztv = {s.value: s.name for s in syms if s.name.startswith("__ZTV")}
    kod_sym = collections.defaultdict(set)
    tsec = {t.index for t in m.text_sections()}
    for s in syms:
        if s.n_sect in tsec:
            kod_sym[s.value].add(s.name)
    gt = {"ZTI_sembolu": len(zti), "ZTV_sembolu": len(ztv)}
    if zti:
        bulunan = [a for a in ti if a in zti]
        gt["typeinfo_sembollu"] = len(bulunan)
        gt["typeinfo_adi_ayni"] = sum(1 for a in bulunan if zti[a] == "__ZTI" + ti[a]["ad"])
        gt["sembolu_olup_bulunamayan_ZTI"] = sum(1 for a in zti if a not in ti)
        gt["sembolsuz_typeinfo"] = len(ti) - len(bulunan)
    if ztv:
        birincil = [v for v in vt if v["tepeye_uzaklik"] == 0]
        bul = [v for v in birincil if v["adres"] in ztv]
        gt["birincil_vtable_sembollu"] = len(bul)
        gt["vtable_adi_ayni"] = sum(1 for v in bul if ztv[v["adres"]] == "__ZTV" + ti[v["typeinfo"]]["ad"])
        gt["sembolu_olup_bulunamayan_ZTV"] = sum(1 for a in ztv if a not in {v["adres"] for v in vt})
        # yuva işlevinin sembolü sınıfın kendi adını ya da bir taban sınıfının adını taşıyor mu
        def taban_adlari(tia, gor=None):
            gor = gor or set()
            if tia in gor or tia not in ti:
                return set()
            gor.add(tia)
            s = {ti[tia]["ad"]}
            for b in ti[tia]["taban"]:
                if b and b[0] == "yerel":
                    s |= taban_adlari(b[1], gor)
            return s
        sembollu = kendi = taban = baska = thunk = 0
        ornek = []
        for h, yerler in islev_sinif.items():
            adlar = kod_sym.get(h)
            if not adlar:
                continue
            sembollu += 1
            if any(n.startswith(("__ZTh", "__ZTv", "__ZThn", "__ZTc")) for n in adlar):
                thunk += 1
                continue
            siniflar = {x[0] for x in yerler}
            tia_ler = {v["typeinfo"] for v in vt if h in v["yuva"]}
            def govde(ad):  # N…E sarmalını soy: iç içe ad bileşenleri
                return ad[1:-1] if ad.startswith("N") and ad.endswith("E") else ad
            if any(govde(c) in n for c in siniflar for n in adlar):
                kendi += 1
                continue
            tb = set()
            for t in tia_ler:
                tb |= taban_adlari(t)
            if any(govde(c) in n for c in tb for n in adlar):
                taban += 1
            else:
                baska += 1
                if len(ornek) < 6:
                    ornek.append((sorted(siniflar)[0][:60], sorted(adlar)[0][:60]))
        gt["yuva_islevi"] = {"sembollu": sembollu, "sinifin_kendi_adi": kendi, "taban_sinif_adi": taban,
                             "thunk": thunk, "baska": baska, "baska_ornek": ornek}
    r["sembol_tablosu"] = gt
    r["ornek_sinif"] = [x[:70] for x in sorted(cozuk.values(), key=len)[:5]]
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ikili")
    ap.add_argument("--dilim")
    ap.add_argument("--cikti")
    a = ap.parse_args()
    r = say(a.ikili, a.dilim)
    s = json.dumps(r, ensure_ascii=False, indent=1)
    if a.cikti:
        Path(a.cikti).write_text(s + "\n")
    print(s)


if __name__ == "__main__":
    main()
