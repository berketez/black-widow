"""Swift tip üst verisi okuyucu ve sayım (ARGE, ÜST VERİ hattı; ürün kodu değil).

Biçim kaynağı (swiftlang/swift `main`, 2026-11-19'da okundu):
- `include/swift/ABI/MetadataValues.h`: `ContextDescriptorKind` (Module 0, Extension 1, Anonymous 2, Protocol 3,
  OpaqueType 4, Class 16, Struct 17, Enum 18), `ContextDescriptorFlags` (tür 0x1F, IsUnique 0x40, IsGeneric 0x80,
  türe özgü bayraklar üst 16 bit), `TypeContextDescriptorFlags` (MetadataInitialization bit 0–1,
  Class_HasResilientSuperclass 13, Class_HasOverrideTable 14, Class_HasVTable 15), `MethodDescriptorFlags`
  (tür 0x0F: Method 0, Init 1, Getter 2, Setter 3, ModifyCoroutine 4, ReadCoroutine 5; IsInstance 0x10;
  IsDynamic 0x20; IsAsync 0x40), `ConformanceFlags` (tip başvuru türü bit 3–5).
- `include/swift/ABI/Metadata.h`: `TargetContextDescriptor` (Flags, Parent), `TargetTypeContextDescriptor`
  (Name, AccessFunctionPtr, Fields), `TargetClassDescriptor` (SuperclassType, 2 × u32, NumImmediateMembers,
  NumFields, FieldOffsetVectorOffset) ve artçı nesne sırası (genel bağlam başlığı, ResilientSuperclass,
  ForeignMetadataInitialization, SingletonMetadataInitialization, VTableDescriptorHeader, MethodDescriptor…,
  OverrideTableHeader, MethodOverrideDescriptor…), `TargetProtocolConformanceDescriptor`
  (Protocol, TypeRef, WitnessTablePattern, Flags), `TargetWitnessTable` (ilk sözcük: Description).
- `include/swift/ABI/GenericContext.h`: `TargetGenericContextDescriptorHeader` (4 × u16) ve artçı sıra.
Göreli göstericiler 32 bit; dolaylı olabilenlerde en düşük bit "dolaylı" demektir (`swift/Basic/RelativePointer.h`).
Yerleşim ayrıca ikiliden doğrulanır: sembollü ikilide erişim fonksiyonu adresindeki sembol `…Ma` ile bitmeli.

Kullanım:
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ustveri/swift_meta.py <ikili> [--dilim arm64] [--cikti x.json]
İkiliyi çalıştırmaz.
"""
from __future__ import annotations

import argparse
import collections
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import macho  # noqa: E402

TUR = {0: "modul", 1: "uzanti", 2: "adsiz", 3: "protokol", 4: "opak", 16: "sinif", 17: "yapi", 18: "enum"}
YONTEM_TURU = {0: "yontem", 1: "init", 2: "getter", 3: "setter", 4: "modify", 5: "read"}


class Swift:
    def __init__(self, m):
        self.m = m
        self.sorun = collections.Counter()

    def rel(self, addr):
        """Doğrudan göreli gösterici (0 → None)."""
        v = self.m.i32(addr)
        if v is None or v == 0:
            return None
        return addr + v

    def rel_ind(self, addr):
        """Dolaylı olabilen göreli gösterici: (hedef, dolaylı mı). Dolaylıysa hedef GOT yuvasından okunur."""
        v = self.m.i32(addr)
        if v is None or v == 0:
            return None, False
        if v & 1:
            yuva = addr + (v & ~1)
            p = self.m.ptr(yuva)
            return p, True
        return addr + (v & ~3), False

    def context_name(self, addr, derinlik=0):
        """Bağlam betimleyicisinin nitelikli adı (modül.Tip.İçTip)."""
        if addr is None or isinstance(addr, tuple) or derinlik > 16:
            return addr[1] if isinstance(addr, tuple) else None
        flags = self.m.u32(addr)
        if flags is None:
            return None
        tur = flags & 0x1F
        ust, _d = self.rel_ind(addr + 4)
        ust_ad = self.context_name(ust, derinlik + 1) if ust else None
        if tur == 0:
            p = self.rel(addr + 8)
            return self.m.cstr(p) if p else None
        if tur in (16, 17, 18, 3):
            p = self.rel(addr + 8)
            ad = self.m.cstr(p) if p else None
            return f"{ust_ad}.{ad}" if ust_ad else ad
        if tur == 1:
            return f"{ust_ad}.(uzantı)" if ust_ad else "(uzantı)"
        if tur == 2:
            return f"{ust_ad}.(adsız)" if ust_ad else "(adsız)"
        return ust_ad

    def generic_atla(self, pos):
        """Tip genel bağlam başlığını ve artçılarını atla. Çözülemeyen bayrakta None."""
        m = self.m
        nparams, nreq, _nkey, gflags = struct.unpack("<HHHH", m.read(pos + 8, 8))
        if gflags & ~1:
            self.sorun["genel_bayrak_desteklenmiyor"] += 1
            return None
        pos += 16
        pos += nparams
        pos += (-pos) % 4
        pos += 12 * nreq
        if gflags & 1:  # HasTypePacks: GenericPackShapeHeader + betimleyiciler
            npacks, _nshape = struct.unpack("<HH", m.read(pos, 4))
            pos += 4 + 8 * npacks
        return pos

    def types(self):
        m = self.m
        out = []
        for sec in m.secs_named("__swift5_types") + m.secs_named("__swift5_types2"):
            for i in range(sec.size // 4):
                a = sec.addr + 4 * i
                d, _dol = self.rel_ind(a)
                if not isinstance(d, int):
                    self.sorun["tip_kaydi_cozulemedi"] += 1
                    continue
                flags = m.u32(d)
                tur = flags & 0x1F
                kf = flags >> 16
                ad = self.context_name(d)
                acc = self.rel(d + 12)
                t = {"adres": d, "tur": TUR.get(tur, str(tur)), "genel": bool(flags & 0x80), "ad": ad,
                     "erisim": acc, "yontem": [], "gecersiz_kilma": [], "vtable_cozuldu": None}
                if tur == 16:
                    pos = d + 44
                    tamam = True
                    if flags & 0x20:  # hasInvertibleProtocols: artçı düzeni farklı
                        self.sorun["invertible"] += 1
                        tamam = False
                    if tamam and flags & 0x80:
                        pos = self.generic_atla(pos)
                        tamam = pos is not None
                    if tamam:
                        if kf & (1 << 13):
                            pos += 4
                        mi = kf & 3
                        if mi == 2:
                            pos += 4
                        elif mi == 1:
                            pos += 12
                        if kf & (1 << 15):
                            _voff, vsize = struct.unpack("<II", m.read(pos, 8))
                            pos += 8
                            if vsize > 20000:
                                self.sorun["vtable_boyutu_asiri"] += 1
                                tamam = False
                            else:
                                for j in range(vsize):
                                    mf = m.u32(pos)
                                    impl = self.rel(pos + 4)
                                    t["yontem"].append((YONTEM_TURU.get(mf & 0xF, "?"), bool(mf & 0x10),
                                                        bool(mf & 0x20), bool(mf & 0x40), impl))
                                    pos += 8
                        if tamam and kf & (1 << 14):
                            n = m.u32(pos)
                            pos += 4
                            if n > 20000:
                                self.sorun["gecersiz_kilma_boyutu_asiri"] += 1
                                tamam = False
                            else:
                                for j in range(n):
                                    impl = self.rel(pos + 8)
                                    t["gecersiz_kilma"].append(impl)
                                    pos += 12
                    t["vtable_cozuldu"] = tamam
                out.append(t)
        return out

    def conformances(self):
        m = self.m
        out = []
        for sec in m.secs_named("__swift5_proto"):
            for i in range(sec.size // 4):
                d = self.rel(sec.addr + 4 * i)
                if d is None:
                    continue
                proto, _pd = self.rel_ind(d)
                flags = m.u32(d + 12)
                tk = (flags >> 3) & 7
                tip_ad = None
                if tk in (0, 1):
                    v = m.i32(d + 4)
                    if tk == 0:
                        tip = d + 4 + v
                    else:
                        tip = m.ptr(d + 4 + v)
                    tip_ad = self.context_name(tip) if tip else None
                wt = self.rel(d + 8)
                out.append({"adres": d, "protokol": self.context_name(proto) if proto else None,
                            "protokol_yerel": isinstance(proto, int), "tip": tip_ad, "wt": wt, "bayrak": flags,
                            "protokol_adres": proto if isinstance(proto, int) else None})
        return out


def say(path, dilim):
    m = macho.load(path, dilim)
    s = Swift(m)
    tipler = s.types()
    uyumlar = s.conformances()
    text = m.text_sections()
    fstarts = m.function_starts()
    fset = set(fstarts) if fstarts is not None else set()

    def kodda(a):
        return a is not None and any(t.addr <= a < t.addr + t.size for t in text)

    sym = collections.defaultdict(set)
    tsec = {t.index for t in text}
    for x in m.defined_symbols():
        if x.n_sect in tsec:
            sym[x.value].add(x.name)
    swift_sym = {a: n for a, n in sym.items() if any(k.startswith(("_$s", "_$S")) for k in n)}

    tur_say = collections.Counter(t["tur"] for t in tipler)
    erisim = [t["erisim"] for t in tipler if t["erisim"]]
    er_set = set(erisim)
    r = {
        "ikili": path, "dilim": m.cpu,
        "bolumler": {x.sectname: x.size for x in m.sections if x.sectname.startswith("__swift")},
        "tip": len(tipler), "tur": dict(tur_say), "genel_tip": sum(1 for t in tipler if t["genel"]),
        "adli_tip": sum(1 for t in tipler if t["ad"]),
        "erisim_fonksiyonu": len(er_set),
        "erisim_kodda": sum(1 for a in er_set if kodda(a)),
        "erisim_fonksiyon_baslangici": sum(1 for a in er_set if a in fset) if fstarts is not None else None,
        "LC_FUNCTION_STARTS": len(fstarts) if fstarts is not None else None,
        "sorun": dict(s.sorun),
    }
    # vtable
    siniflar = [t for t in tipler if t["tur"] == "sinif"]
    yontem = [(t["ad"], i, y) for t in siniflar for i, y in enumerate(t["yontem"])]
    impl = {y[4] for _a, _i, y in yontem if y[4]}
    gk = {a for t in siniflar for a in t["gecersiz_kilma"] if a}
    r["vtable"] = {
        "sinif": len(siniflar), "cozulen_sinif": sum(1 for t in siniflar if t["vtable_cozuldu"]),
        "yontem_betimleyici": len(yontem), "impl_bos": sum(1 for _a, _i, y in yontem if not y[4]),
        "ayrik_impl": len(impl), "impl_kodda": sum(1 for a in impl if kodda(a)),
        "impl_fonksiyon_baslangici": sum(1 for a in impl if a in fset) if fstarts is not None else None,
        "tur": dict(collections.Counter(y[0] for _a, _i, y in yontem)),
        "gecersiz_kilma_kaydi": sum(len(t["gecersiz_kilma"]) for t in siniflar),
        "gecersiz_kilma_ayrik_impl": len(gk), "gecersiz_kilma_kodda": sum(1 for a in gk if kodda(a)),
        "gecersiz_kilma_fonksiyon_baslangici": sum(1 for a in gk if a in fset) if fstarts is not None else None,
    }
    # tanık tabloları: ilk sözcük uyum betimleyicisi; ardından kod göstericisi olan ardışık yuvalar sayılır
    wt_adres = {u["wt"] for u in uyumlar if u["wt"]}
    tanik = set()
    wt_dogrulanan = 0
    yerel_proto_gereksinim = {}
    for u in uyumlar:
        wt = u["wt"]
        if not wt:
            continue
        ilk = m.ptr(wt)
        if ilk != u["adres"]:
            continue
        wt_dogrulanan += 1
        sinir = None
        if u["protokol_adres"]:
            pa = u["protokol_adres"]
            if pa not in yerel_proto_gereksinim:
                yerel_proto_gereksinim[pa] = m.u32(pa + 16)  # NumRequirements
            sinir = yerel_proto_gereksinim[pa]
        j = 1
        while True:
            if sinir is not None and j > sinir:
                break
            a = wt + 8 * j
            if sinir is None and (a in wt_adres or j > 512):
                break
            p = m.ptr(a)
            if isinstance(p, int) and kodda(p):
                tanik.add(p)
            elif sinir is None:
                break
            j += 1
    r["uyum"] = {
        "uyum_kaydi": len(uyumlar), "yerel_protokole": sum(1 for u in uyumlar if u["protokol_yerel"]),
        "tanik_tablosu_olan": len(wt_adres), "ilk_sozcugu_dogrulanan": wt_dogrulanan,
        "tanik_kod_gostericisi_ayrik": len(tanik),
        "tanik_fonksiyon_baslangici": sum(1 for a in tanik if a in fset) if fstarts is not None else None,
    }
    tum = er_set | impl | gk | tanik
    r["birlesim"] = {
        "erisim": len(er_set), "vtable_impl": len(impl), "gecersiz_kilma": len(gk), "tanik": len(tanik),
        "ayrik_toplam": len(tum),
        "kesin_ad_verilebilen": len(er_set),
        "tip_ve_yuva_verilebilen": len((impl | gk | tanik) - er_set),
    }
    # ---- sembol tablosu (soyulmamış ikilide GT) -------------------------
    def son_ek_say(adresler, ekler):
        var = uyan = 0
        for a in adresler:
            adlar = sym.get(a)
            if not adlar:
                continue
            var += 1
            if any(n.endswith(ekler) for n in adlar):
                uyan += 1
        return var, uyan

    er_var, er_ma = son_ek_say(er_set, ("Ma",))
    tw_var, tw_uyan = son_ek_say(tanik, ("TW", "TWTm"))
    tur_ek = {"getter": ("vg", "ig", "vgTj"), "setter": ("vs", "is"), "modify": ("vM", "iM"),
              "read": ("vr", "ir"), "init": ("fC", "fc", "fCTj"), "yontem": ("F", "FZ")}
    tur_gt = {}
    for tur, ekler in tur_ek.items():
        adr = {y[4] for _a, _i, y in yontem if y[0] == tur and y[4]}
        var, uy = son_ek_say(adr, ekler)
        tur_gt[tur] = {"impl": len(adr), "sembollu": var, "son_ek_uyan": uy}
    # tip adı sembolde geçiyor mu: erişim fonksiyonunun sembolü tipin kısa adını uzunluk önekiyle içerir
    ad_gecen = ad_bakilan = 0
    for t in tipler:
        a = t["erisim"]
        if not a or a not in sym or not t["ad"]:
            continue
        kisa = t["ad"].rsplit(".", 1)[-1]
        ad_bakilan += 1
        if any(f"{len(kisa.encode())}{kisa}" in n for n in sym[a]):
            ad_gecen += 1
    r["sembol_tablosu"] = {
        "kod_sembollu_adres": len(sym), "swift_sembollu_adres": len(swift_sym),
        "erisim_sembollu": er_var, "erisim_Ma_ekli": er_ma,
        "erisim_tip_adi_sembolde": f"{ad_gecen} / {ad_bakilan}",
        "tanik_sembollu": tw_var, "tanik_TW_ekli": tw_uyan,
        "vtable_tur": tur_gt,
        "ust_veriden_ulasilan_swift_sembollu_adres": len(tum & set(swift_sym)),
    }
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
