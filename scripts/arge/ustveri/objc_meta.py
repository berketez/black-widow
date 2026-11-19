"""Objective-C sınıf / kategori / yöntem listesi okuyucu ve sayım (ARGE, ÜST VERİ hattı; ürün kodu değil).

Biçim kaynağı: apple-oss-distributions/objc4 `runtime/objc-runtime-new.h` (2026-11-19'da okundu):
`objc_class` (isa, superclass, cache 2 sözcük, bits; `FAST_DATA_MASK` 0x…7ffffffffff8), `class_ro_t`,
`entsize_list_tt` (entsizeAndFlags, count), `method_t` (`big`: SEL name, types, imp; `small`: üç
`RelativePointer` int32, 12 bayt; paylaşılan önbellek dışında `name` bir seçici başvurusuna (selref) gösterir),
`smallMethodListFlag` 0x80000000, `relativeMethodSelectorsAreDirectFlag` 0x40000000, `category_t`, `protocol_t`.

Kullanım:
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ustveri/objc_meta.py <ikili> [--dilim arm64] [--cikti x.json] [--liste x.tsv]
İkiliyi çalıştırmaz.
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import macho  # noqa: E402

DATA_MASK = 0x00007FFFFFFFFFF8
SMALL = 0x80000000
DIRECT_SEL = 0x40000000
FLAG_MASK = 0xFFFF0003


def tip_arguman_sayisi(enc: str):
    """ObjC yöntem tip kodlamasındaki öğe sayısı (dönüş + self + _cmd + argümanlar). Çözülemezse None."""
    i = 0
    n = len(enc)
    say = 0

    def atla_tip(i):
        while i < n and enc[i] in "rnNoORVAj":
            i += 1
        if i >= n:
            return None
        c = enc[i]
        if c in "{(":
            kapat = "}" if c == "{" else ")"
            d = 0
            while i < n:
                if enc[i] == c:
                    d += 1
                elif enc[i] == kapat:
                    d -= 1
                    if d == 0:
                        return i + 1
                elif enc[i] == '"':
                    j = enc.find('"', i + 1)
                    if j < 0:
                        return None
                    i = j
                i += 1
            return None
        if c == "[":
            d = 0
            while i < n:
                if enc[i] == "[":
                    d += 1
                elif enc[i] == "]":
                    d -= 1
                    if d == 0:
                        return i + 1
                i += 1
            return None
        if c == "^":
            return atla_tip(i + 1)
        if c == "b":
            i += 1
            while i < n and enc[i].isdigit():
                i += 1
            return i
        if c == "@":
            i += 1
            if i < n and enc[i] == "?":
                i += 1
                if i < n and enc[i] == "<":  # blok imzası
                    d = 0
                    while i < n:
                        if enc[i] == "<":
                            d += 1
                        elif enc[i] == ">":
                            d -= 1
                            if d == 0:
                                return i + 1
                        i += 1
                    return None
                return i
            if i < n and enc[i] == '"':
                j = enc.find('"', i + 1)
                return None if j < 0 else j + 1
            return i
        return i + 1

    while i < n:
        i = atla_tip(i)
        if i is None:
            return None
        if i < n and enc[i] in "+-":
            i += 1
        while i < n and enc[i].isdigit():
            i += 1
        say += 1
    return say


class ObjC:
    def __init__(self, m):
        self.m = m
        self.hatalar = collections.Counter()

    def _ptr(self, addr):
        v = self.m.ptr(addr)
        return v

    def _local(self, addr):
        v = self.m.ptr(addr)
        return v if isinstance(v, int) else None

    def method_list(self, addr):
        """[(seçici, tip kodlaması, imp)]"""
        m = self.m
        if not addr:
            return []
        addr &= ~3
        ef = m.u32(addr)
        count = m.u32(addr + 4)
        if ef is None or count is None or count > 100000:
            self.hatalar["yontem_listesi_okunamadi"] += 1
            return []
        entsize = ef & ~FLAG_MASK
        out = []
        base = addr + 8
        if ef & SMALL:
            if entsize != 12:
                self.hatalar["kucuk_liste_boyutu"] += 1
                return []
            for i in range(count):
                e = base + 12 * i
                n = m.i32(e)
                t = m.i32(e + 4)
                p = m.i32(e + 8)
                if n is None:
                    break
                hedef = e + n
                if ef & DIRECT_SEL:
                    sel = m.cstr(hedef)
                else:
                    s = self._local(hedef)
                    sel = m.cstr(s) if s else None
                tip = m.cstr(e + 4 + t) if t else None
                imp = e + 8 + p if p else 0
                out.append((sel, tip, imp))
        else:
            if entsize != 24:
                self.hatalar["buyuk_liste_boyutu"] += 1
                return []
            for i in range(count):
                e = base + 24 * i
                s = self._local(e)
                t = self._local(e + 8)
                p = self._local(e + 16)
                out.append((m.cstr(s) if s else None, m.cstr(t) if t else None, p or 0))
        return out

    def class_ro(self, cls_addr):
        bits = self.m.ptr(cls_addr + 32)
        if not isinstance(bits, int):
            return None, 0
        return bits & DATA_MASK, bits & 7

    def protocol_selectors(self, proto_addr):
        m = self.m
        ad_p = self._local(proto_addr + 8)
        ad = m.cstr(ad_p) if ad_p else None
        sels = set()
        for off in (24, 32, 40, 48):
            ml = self._local(proto_addr + off)
            for sel, _t, _i in self.method_list(ml) if ml else []:
                sels.add(sel)
        return ad, sels

    def protocol_list(self, addr):
        if not addr:
            return []
        n = self.m.u64(addr)
        if n is None or n > 10000:
            return []
        out = []
        for i in range(n):
            p = self._local(addr + 8 + 8 * i)
            if p:
                out.append(p)
        return out

    def classes(self):
        """Yerel sınıflar: {adres: bilgi}"""
        m = self.m
        out = {}
        for sec in m.secs_named("__objc_classlist") + m.secs_named("__objc_nlclslist"):
            for i in range(sec.size // 8):
                c = self._local(sec.addr + 8 * i)
                if not c or c in out:
                    continue
                ro, bayrak = self.class_ro(c)
                if not ro:
                    self.hatalar["sinif_ro_yok"] += 1
                    continue
                name_p = self._local(ro + 24)
                ust = m.ptr(c + 8)
                meta = self._local(c)
                bilgi = {
                    "ad": m.cstr(name_p) if name_p else None, "swift": bool(bayrak & 3),
                    "ust": ust, "ro": ro, "meta": meta,
                    "yontem": self.method_list(self._local(ro + 32) or 0),
                    "protokol": self.protocol_list(self._local(ro + 40) or 0),
                    "sinif_yontemi": [],
                }
                if meta:
                    mro, _b = self.class_ro(meta)
                    if mro:
                        bilgi["sinif_yontemi"] = self.method_list(self._local(mro + 32) or 0)
                        bilgi["protokol"] += self.protocol_list(self._local(mro + 40) or 0)
                out[c] = bilgi
        return out

    def categories(self):
        m = self.m
        out = []
        gor = set()
        for sec in m.secs_named("__objc_catlist") + m.secs_named("__objc_nlcatlist"):
            for i in range(sec.size // 8):
                c = self._local(sec.addr + 8 * i)
                if not c or c in gor:
                    continue
                gor.add(c)
                name_p = self._local(c)
                cls = m.ptr(c + 8)
                out.append({
                    "ad": m.cstr(name_p) if name_p else None, "sinif": cls,
                    "yontem": self.method_list(self._local(c + 16) or 0),
                    "sinif_yontemi": self.method_list(self._local(c + 24) or 0),
                    "protokol": self.protocol_list(self._local(c + 32) or 0),
                })
        return out

    def protocols(self):
        out = {}
        for sec in self.m.secs_named("__objc_protolist"):
            for i in range(sec.size // 8):
                p = self._local(sec.addr + 8 * i)
                if p and p not in out:
                    out[p] = self.protocol_selectors(p)
        return out


def sinif_adi(cls, siniflar):
    """Sınıf göstericisinden ad: yerel sınıf ya da içe aktarılan `_OBJC_CLASS_$_X`."""
    if isinstance(cls, tuple):
        ad = cls[1]
        for on in ("_OBJC_CLASS_$_", "_OBJC_METACLASS_$_"):
            if ad.startswith(on):
                return ad[len(on):], True
        return ad, True
    if cls in siniflar:
        return siniflar[cls]["ad"], False
    return None, False


def yontemler(m):
    """Her yöntem için sözlük listesi + özet bilgiler."""
    o = ObjC(m)
    siniflar = o.classes()
    kategoriler = o.categories()
    protokoller = o.protocols()
    satirlar = []

    def protokol_secicileri(plist):
        s = set()
        for p in plist:
            if p in protokoller:
                s |= protokoller[p][1]
            else:
                s |= o.protocol_selectors(p)[1]
        return s

    for _c, b in siniflar.items():
        ps = protokol_secicileri(b["protokol"])
        ust_ad, ust_dis = sinif_adi(b["ust"], siniflar)
        for tur, liste in (("-", b["yontem"]), ("+", b["sinif_yontemi"])):
            for sel, tip, imp in liste:
                satirlar.append({"tur": tur, "sinif": b["ad"], "kategori": None, "secici": sel, "tip": tip,
                                 "imp": imp, "swift": b["swift"], "protokolde": sel in ps,
                                 "ust_dis": ust_dis, "ust": ust_ad, "sinif_dis": False})
    for k in kategoriler:
        ad, dis = sinif_adi(k["sinif"], siniflar)
        ps = protokol_secicileri(k["protokol"])
        for tur, liste in (("-", k["yontem"]), ("+", k["sinif_yontemi"])):
            for sel, tip, imp in liste:
                satirlar.append({"tur": tur, "sinif": ad, "kategori": k["ad"], "secici": sel, "tip": tip,
                                 "imp": imp, "swift": False, "protokolde": sel in ps,
                                 "ust_dis": None, "ust": None, "sinif_dis": dis})
    return o, siniflar, kategoriler, protokoller, satirlar


def say(path, dilim, liste):
    m = macho.load(path, dilim)
    o, siniflar, kategoriler, protokoller, satirlar = yontemler(m)
    text = m.text_sections()
    fstarts = m.function_starts()
    fset = set(fstarts) if fstarts is not None else None

    def kodda(a):
        return any(s.addr <= a < s.addr + s.size for s in text)

    impli = [s for s in satirlar if s["imp"]]
    imp_adlari = collections.defaultdict(set)
    for s in impli:
        if s["sinif"] and s["secici"]:
            imp_adlari[s["imp"]].add(f'{s["tur"]}[{s["sinif"]} {s["secici"]}]')
    arite_uyan = arite_uymayan = arite_cozulemedi = 0
    for s in impli:
        if s["tip"] is None or s["secici"] is None:
            arite_cozulemedi += 1
            continue
        n = tip_arguman_sayisi(s["tip"])
        if n is None:
            arite_cozulemedi += 1
        elif n - 3 == s["secici"].count(":"):
            arite_uyan += 1
        else:
            arite_uymayan += 1
    r = {
        "ikili": path, "dilim": m.cpu,
        "sinif": len(siniflar), "swift_sinifi": sum(1 for b in siniflar.values() if b["swift"]),
        "kategori": len(kategoriler), "protokol": len(protokoller),
        "yontem_kaydi": len(satirlar), "imp_li_kayit": len(impli),
        "adsiz_kayit": sum(1 for s in impli if not s["sinif"] or not s["secici"]),
        "ayrik_imp": len(imp_adlari),
        "birden_cok_adli_imp": sum(1 for v in imp_adlari.values() if len(v) > 1),
        "imp_kod_bolumunde": sum(1 for a in imp_adlari if kodda(a)),
        "imp_fonksiyon_baslangici": (sum(1 for a in imp_adlari if a in fset) if fset is not None else None),
        "LC_FUNCTION_STARTS": len(fstarts) if fstarts is not None else None,
        "arite": {"uyan": arite_uyan, "uymayan": arite_uymayan, "cozulemedi": arite_cozulemedi},
        "protokol_yontemi_olan_kayit": sum(1 for s in impli if s["protokolde"]),
        "swift_sinifinda_kayit": sum(1 for s in impli if s["swift"]),
        "kategori_kaydi": sum(1 for s in impli if s["kategori"] is not None),
        "dis_sinifa_kategori_kaydi": sum(1 for s in impli if s["sinif_dis"]),
        "okuma_hatalari": dict(o.hatalar),
    }
    # ---- sembol tablosuyla karşılaştırma (soyulmamış ikilide GT) --------
    sym = collections.defaultdict(set)
    for s in m.defined_symbols():
        if s.name.startswith(("-[", "+[")):
            sym[s.value].add(s.name)
    objc_sym_adres = len(sym)
    ayni = kategori_yazimi = farkli = sembolsuz = 0
    ornek = []
    for a, adlar in imp_adlari.items():
        if a not in sym:
            sembolsuz += 1
            continue
        if adlar & sym[a]:
            ayni += 1
            continue
        # sembol kategori adını taşır: -[Sinif(Kategori) secici]
        yalin = set()
        for n in sym[a]:
            i = n.find("(")
            j = n.find(")")
            sp = n.find(" ")
            yalin.add(n[:i] + n[j + 1:] if 0 < i < j < sp else n)
        if adlar & yalin:
            kategori_yazimi += 1
        else:
            farkli += 1
            if len(ornek) < 6:
                ornek.append((hex(a), sorted(adlar)[:2], sorted(sym[a])[:2]))
    r["sembol_tablosu"] = {
        "objc_sembollu_adres": objc_sym_adres, "imp_sembollu": len(imp_adlari) - sembolsuz,
        "ad_ayni": ayni, "ad_kategori_yazimiyla_ayni": kategori_yazimi, "ad_farkli": farkli,
        "imp_sembolsuz": sembolsuz,
        "sembolu_olup_listede_olmayan": sum(1 for a in sym if a not in imp_adlari),
        "farkli_ornek": ornek,
    }
    if liste:
        with open(liste, "w") as f:
            for s in impli:
                f.write(f'{s["imp"]:#x}\t{s["tur"]}\t{s["sinif"]}\t{s["kategori"] or ""}\t{s["secici"]}\t'
                        f'{int(s["protokolde"])}\t{int(s["swift"])}\t{s["tip"] or ""}\n')
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ikili")
    ap.add_argument("--dilim")
    ap.add_argument("--cikti")
    ap.add_argument("--liste")
    a = ap.parse_args()
    r = say(a.ikili, a.dilim, a.liste)
    s = json.dumps(r, ensure_ascii=False, indent=1)
    if a.cikti:
        Path(a.cikti).write_text(s + "\n")
    print(s)


if __name__ == "__main__":
    main()
