"""G8 ek koşullar: K0 (C0 tekrarı), K1, K1y, K2, K3_C0, K3_C3 (onkayit_ek.md).

Kullanım:  python3 -I -B ek_deney.py K0 K1 K1y K2 K3_C0 K3_C3

Her koşul taban projenin ayrı bir kopyasında koşulur (projeler/<koşul>/). Decompile ve ölçüm
deney.py'nin `olc_koşul` işleviyle (aynı ayarlar, ısınma, iki koşu) yapılır.
Ek olarak `yerlesim` komutu, Karadul yapılarının alan doğruluğunu DWARF'la doğrulanmış
window_pane yerleşimine karşı hesaplar (decompile yok).
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ortak  # noqa: E402
import deney  # noqa: E402
import tipler  # noqa: E402

# Karadul'un types.h başındaki tanımlar + stdint + Ghidra'nın yerleşik adları (onkayit_ek §1 K1)
ON_TANIM = """
typedef unsigned char uint8_t; typedef unsigned short uint16_t; typedef unsigned int uint32_t;
typedef unsigned long long uint64_t; typedef signed char int8_t; typedef short int16_t;
typedef int int32_t; typedef long long int64_t; typedef long intptr_t; typedef unsigned long uintptr_t;
typedef unsigned long size_t; typedef long ssize_t;
typedef uint8_t undefined1; typedef uint16_t undefined2; typedef uint32_t undefined4; typedef uint64_t undefined8;
typedef void *undefined; typedef void (*code)(void); typedef intptr_t addr; typedef uintptr_t uaddr;
typedef unsigned int uint; typedef unsigned long ulong; typedef unsigned short ushort; typedef unsigned char uchar;
typedef unsigned char byte; typedef long long longlong; typedef unsigned long long ulonglong;
"""


def karadul_ayristir(k1: dict) -> tuple[dict, dict, dict]:
    """K1 prototipleri ve K1y yapıları: (fdefs {adres: FunctionDefinition}, yapilar {ad: Structure},
    rapor)."""
    from ghidra.program.model.data import StandAloneDataTypeManager  # type: ignore
    from ghidra.app.util.cparser.C import CParser  # type: ignore
    from java.io import ByteArrayInputStream  # type: ignore

    rapor: dict = {"prototip_ayristirilan": 0, "prototip_hatasi": [], "yapi": {}}
    dtm = StandAloneDataTypeManager("g8_k1", tipler.veri_duzeni())
    tx = dtm.startTransaction("k1")
    fdefs: dict = {}
    yapilar: dict = {}
    try:
        p0 = CParser(dtm, True, None)
        p0.parse(ByteArrayInputStream(ON_TANIM.encode()))
        for h in k1["hedefler"]:
            if not h["prototip_yazilir"]:
                continue
            metin = h["karadul_imza"]["metin"] + ";"
            p = CParser(dtm, True, None)
            try:
                p.parse(ByteArrayInputStream(metin.encode()))
                fd = p.getFunctions().get(h["karadul_imza"]["ad"])
                if fd is None:
                    raise RuntimeError("fonksiyon tanımı yok")
                fdefs[h["adres"]] = fd
                rapor["prototip_ayristirilan"] += 1
            except Exception as exc:
                rapor["prototip_hatasi"].append({"adres": h["adres"], "metin": metin, "hata": str(exc)[:300]})
        # K1y yapıları: types.h metninden alan tipleri, Karadul'un ofsetleriyle
        for ad in sorted({h["bagli_yapi"] for h in k1["hedefler"] if h["bagli_yapi"]}):
            y = k1["ilgili_yapilar"][ad]
            yapilar[ad], rapor["yapi"][ad] = _yapi_kur(ad, y, alan_tipleri(dtm, ad, y))
    finally:
        dtm.endTransaction(tx, True)
    return fdefs, yapilar, rapor


def alan_adi(bildirim: str) -> str | None:
    """Karadul alan bildiriminden alan adı: 'long field_0x08', 'char padding_0x00[8]',
    'void (*func_ptr_0x10)(void *)'."""
    import re
    m = re.search(r"\(\*\s*([A-Za-z_]\w*)\s*\)", bildirim)
    if m:
        return m.group(1)
    m = re.search(r"([A-Za-z_]\w*)\s*(\[[^\]]*\])?\s*$", bildirim)
    return m.group(1) if m else None


def alan_tipleri(dtm, ad: str, y: dict) -> dict:
    """Yapının alan bildirimlerini Ghidra C ayrıştırıcısıyla çözer: {alan_adı: DataType}."""
    from ghidra.app.util.cparser.C import CParser  # type: ignore
    from java.io import ByteArrayInputStream  # type: ignore
    govde = "\n".join(f"  {a['bildirim']};" for a in y["alanlar"])
    p = CParser(dtm, True, None)
    p.parse(ByteArrayInputStream(f"struct {ad}_alanlar {{\n{govde}\n}};".encode()))
    gecici = [c for c in dtm.getAllComposites() if c.getName() == f"{ad}_alanlar"][0]
    return {str(c.getFieldName()): c.getDataType() for c in gecici.getDefinedComponents()}


def _yapi_kur(ad: str, y: dict, tip_ad: dict):
    """Karadul'un ofsetleriyle paketlenmemiş yapı; çakışan ya da sığmayan alan yerleştirilmez."""
    from ghidra.program.model.data import StructureDataType, CategoryPath  # type: ignore
    s = StructureDataType(CategoryPath("/karadul"), ad, y["boyut"])
    dolu: list[tuple[int, int]] = []
    yerlesen, yerlesmeyen = [], []
    for a in y["alanlar"]:
        alan = alan_adi(a["bildirim"])
        if alan is None or alan.startswith("padding_"):
            continue
        dt = tip_ad.get(alan)
        if dt is None:
            yerlesmeyen.append({"alan": a["bildirim"], "neden": "tip çözülemedi"})
            continue
        o, n = a["ofset"], dt.getLength()
        if o + n > y["boyut"] or any(o < b and a0 < o + n for a0, b in dolu):
            yerlesmeyen.append({"alan": a["bildirim"], "ofset": o, "boyut": n, "neden": "çakışma ya da taşma"})
            continue
        s.replaceAtOffset(o, dt, n, alan, None)
        dolu.append((o, o + n))
        yerlesen.append({"alan": alan, "ofset": o, "boyut": n})
    return s, {"boyut": y["boyut"], "yerlesen": yerlesen, "yerlesmeyen": yerlesmeyen}


def void_esle(dt, onbellek: dict, bilinen: set):
    """K2: yerleşimi bilinmeyen yapıya giden işaretçileri void'e giden işaretçiye çevirir.

    Yerleşimi bilinen = programda (tabanda) zaten tam olarak bulunan yapı (bilinen kümesi).
    Değerle geçen bilinmeyen yapı içi boş yer tutucu olur (C2'deki gibi)."""
    from ghidra.program.model.data import (Pointer, PointerDataType, VoidDataType, TypeDef,  # type: ignore
                                           TypedefDataType, FunctionDefinition,
                                           FunctionDefinitionDataType, ParameterDefinitionImpl,
                                           Composite, Array, ArrayDataType)
    if dt is None:
        return dt
    anahtar = (str(dt.getPathName()), dt.getClass().getName())
    if anahtar in onbellek:
        return onbellek[anahtar]
    sonuc = dt
    if isinstance(dt, Pointer):
        hedef = dt.getDataType()
        taban = hedef
        while isinstance(taban, TypeDef):
            taban = taban.getBaseDataType()
        if isinstance(taban, Composite) and str(taban.getPathName()) not in bilinen:
            sonuc = PointerDataType(VoidDataType.dataType, dt.getLength())
        elif hedef is not None:
            yeni = void_esle(hedef, onbellek, bilinen)
            if yeni is not hedef:
                sonuc = PointerDataType(yeni, dt.getLength())
    elif isinstance(dt, TypeDef):
        yeni = void_esle(dt.getDataType(), onbellek, bilinen)
        if yeni is not dt.getDataType():
            sonuc = TypedefDataType(dt.getCategoryPath(), dt.getName(), yeni)
    elif isinstance(dt, Array):
        yeni = void_esle(dt.getDataType(), onbellek, bilinen)
        if yeni is not dt.getDataType():
            sonuc = ArrayDataType(yeni, dt.getNumElements(), dt.getElementLength())
    elif isinstance(dt, FunctionDefinition):
        donus = void_esle(dt.getReturnType(), onbellek, bilinen)
        argv = [void_esle(a.getDataType(), onbellek, bilinen) for a in dt.getArguments()]
        if donus is not dt.getReturnType() or any(n is not a.getDataType() for n, a in zip(argv, dt.getArguments())):
            f = FunctionDefinitionDataType(dt.getCategoryPath(), dt.getName())
            f.setReturnType(donus)
            f.setArguments([ParameterDefinitionImpl(a.getName(), n, a.getComment())
                            for n, a in zip(argv, dt.getArguments())])
            f.setVarArgs(dt.hasVarArgs())
            f.setNoReturn(dt.hasNoReturn())
            sonuc = f
    elif isinstance(dt, Composite) and str(dt.getPathName()) not in bilinen:
        sonuc = deney.yer_tutucu(dt)
    onbellek[anahtar] = sonuc
    return sonuc


def prototip_uygula(program, adres: str, fd) -> dict:
    from ghidra.program.model.symbol import SourceType  # type: ignore
    from ghidra.app.cmd.function import ApplyFunctionSignatureCmd, FunctionRenameOption  # type: ignore
    from ghidra.program.model.data import DataTypeConflictHandler  # type: ignore
    from ghidra.util.task import ConsoleTaskMonitor  # type: ignore
    pdtm = program.getDataTypeManager()
    fd_p = pdtm.resolve(fd, DataTypeConflictHandler.KEEP_HANDLER)
    giris = ortak.adres(program, adres)
    cmd = ApplyFunctionSignatureCmd(giris, fd_p, SourceType.USER_DEFINED, True, FunctionRenameOption.NO_CHANGE)
    ok = bool(cmd.applyTo(program, ConsoleTaskMonitor()))
    f = program.getFunctionManager().getFunctionAt(giris)
    return {"adres": adres, "uygulandi": ok, "hata": None if ok else str(cmd.getStatusMsg()),
            "hedef_prototip": str(fd.getPrototypeString()),
            "programdaki_prototip": str(f.getSignature().getPrototypeString()),
            "imza_kaynagi": str(f.getSignatureSource())}


def geri_yaz_k1(program, kosul: str, k1: dict, fdefs: dict, yapilar: dict) -> dict:
    from ghidra.program.model.symbol import SourceType  # type: ignore
    from ghidra.program.model.data import (FunctionDefinitionDataType, ParameterDefinitionImpl,  # type: ignore
                                           PointerDataType, DataTypeConflictHandler)
    rapor: dict = {"kosul": kosul, "ad": [], "prototip": [], "yapi_baglanan": []}
    t0 = time.perf_counter()
    fm = program.getFunctionManager()
    pdtm = program.getDataTypeManager()
    tx = program.startTransaction(f"G8 {kosul}")
    ok = False
    try:
        for h in k1["hedefler"]:
            f = fm.getFunctionAt(ortak.adres(program, h["adres"]))
            if h["karadul_ad"]:
                f.setName(h["karadul_ad"], SourceType.USER_DEFINED)
                rapor["ad"].append({"adres": h["adres"], "ad": h["karadul_ad"]})
            fd = fdefs.get(h["adres"])
            if kosul == "K1y" and h["bagli_yapi"] and fd is not None:
                s = pdtm.resolve(yapilar[h["bagli_yapi"]], DataTypeConflictHandler.KEEP_HANDLER)
                yeni = FunctionDefinitionDataType(fd.getCategoryPath(), fd.getName())
                yeni.setReturnType(fd.getReturnType())
                argv = list(fd.getArguments())
                argv[0] = ParameterDefinitionImpl(argv[0].getName(), PointerDataType(s), argv[0].getComment())
                yeni.setArguments(argv)
                yeni.setVarArgs(fd.hasVarArgs())
                fd = yeni
                rapor["yapi_baglanan"].append({"adres": h["adres"], "yapi": h["bagli_yapi"],
                                               "boyut": s.getLength(), "bilesen": s.getNumDefinedComponents()})
            if fd is not None:
                rapor["prototip"].append(prototip_uygula(program, h["adres"], fd))
        ok = True
    finally:
        program.endTransaction(tx, ok)
    rapor["uygulama_sn"] = round(time.perf_counter() - t0, 3)
    rapor["ad_yazilan"] = len(rapor["ad"])
    rapor["prototip_uygulanan"] = sum(1 for p in rapor["prototip"] if p["uygulandi"])
    return rapor


def geri_yaz_k2(program, hedefler: list[dict], fdefs: dict) -> dict:
    from ghidra.program.model.symbol import SourceType  # type: ignore
    rapor: dict = {"kosul": "K2", "prototip": [], "void_eslenen_parametre": 0}
    t0 = time.perf_counter()
    fm = program.getFunctionManager()
    tx = program.startTransaction("G8 K2")
    ok = False
    onbellek: dict = {}
    from ghidra.program.model.data import Composite  # type: ignore
    pdtm0 = program.getDataTypeManager()
    bilinen = {str(d.getPathName()) for d in pdtm0.getAllComposites() if d.getNumComponents() > 0}
    try:
        for h in hedefler:
            f = fm.getFunctionAt(ortak.adres(program, h["adres"]))
            f.setName(h["ad"], SourceType.USER_DEFINED)
            fd = fdefs[h["ad"]]
            yeni = void_esle(fd, onbellek, bilinen)
            rapor["void_eslenen_parametre"] += sum(
                1 for a, b in zip(fd.getArguments(), yeni.getArguments()) if a.getDataType() is not b.getDataType())
            rapor["prototip"].append(prototip_uygula(program, h["adres"], yeni))
        ok = True
    finally:
        program.endTransaction(tx, ok)
    pdtm = program.getDataTypeManager()
    rapor["programdaki_bilesik_tip_sayisi_tmux"] = sum(1 for d in pdtm.getAllComposites()
                                                      if str(d.getCategoryPath()).startswith("/tmux.h"))
    rapor["uygulama_sn"] = round(time.perf_counter() - t0, 3)
    rapor["ad_yazilan"] = len(hedefler)
    rapor["prototip_uygulanan"] = sum(1 for p in rapor["prototip"] if p["uygulandi"])
    return rapor


def kaynak_prototipleri(hedefler: list[dict]):
    dtm, parser, rapor = tipler.tipleri_ayristir(deney.prototip_metni(hedefler))
    if rapor["ayristirma"] != "başarılı":
        raise SystemExit("ayrıştırma başarısız")
    tum = parser.getFunctions()
    fdefs = {}
    tx = dtm.startTransaction("ad")
    try:
        for h in hedefler:
            fd = tum.get(deney.ONEK + h["ad"])
            if fd is None:
                raise SystemExit(f"prototip ayrıştırılamadı: {h['ad']}")
            fd.setName(h["ad"])
            fdefs[h["ad"]] = fd
    finally:
        dtm.endTransaction(tx, True)
    return dtm, fdefs


def kosul_calistir(k: str, secim: dict, uygula) -> None:
    hedef = ortak.PROJELER / k
    ortak.proje_kopyala(ortak.PROJELER / "taban", hedef)
    proje, program = ortak.proje_ac(hedef)
    try:
        uygulama = uygula(program)
        proje.save(program)
        t0 = time.perf_counter()
        kayitlar = deney.olc_koşul(program, secim, k)
        sure = time.perf_counter() - t0
    finally:
        proje.close()
    ortak.json_yaz(ortak.VERI / f"olcum_{k}.json", {"kunye": ortak.kunye(), "kosul": k, "uygulama": uygulama,
                                                    "olcum_toplam_sn": round(sure, 1), "fonksiyonlar": kayitlar})
    print(k, {a: uygulama.get(a) for a in ("ad_yazilan", "prototip_uygulanan", "uygulama_sn")},
          "başarısız:", sum(1 for x in kayitlar if x["olcut"] is None),
          "belirlenimci değil:", sum(1 for x in kayitlar if x.get("belirlenimci") is False), "süre:", round(sure, 1))


def yapraklar(dt, taban: int = 0, yol: str = "") -> list[tuple[int, int, str]]:
    """Doğrulanmış yerleşimi yaprak alanlara açar: değerle gömülü yapı/birlik özyinelemeli,
    sayıl dizinin her elemanı bir yaprak (onkayit_ek §1)."""
    from ghidra.program.model.data import Composite, Array, TypeDef  # type: ignore

    def coz(t):
        while isinstance(t, TypeDef):
            t = t.getBaseDataType()
        return t

    out = []
    for c in dt.getDefinedComponents():
        t = coz(c.getDataType())
        o = taban + c.getOffset()
        ad = f"{yol}.{c.getFieldName()}" if yol else str(c.getFieldName())
        if isinstance(t, Composite) and t.getNumComponents() > 0:
            out += yapraklar(t, o, ad)
        elif isinstance(t, Array):
            e = coz(t.getDataType())
            el = t.getElementLength()
            for i in range(t.getNumElements()):
                if isinstance(e, Composite) and e.getNumComponents() > 0:
                    out += yapraklar(e, o + i * el, f"{ad}[{i}]")
                else:
                    out.append((o + i * el, el, f"{ad}[{i}]"))
        else:
            out.append((o, c.getLength(), ad))
    return out


def yerlesim_dogrulugu() -> None:
    """Karadul yapılarının alanlarını window_pane'in doğrulanmış yaprak alanlarıyla sınıflar."""
    k1 = json.loads((ortak.VERI / "k1_karadul.json").read_text())
    ortak.jvm_baslat()
    from ghidra.program.model.data import StandAloneDataTypeManager  # type: ignore
    from ghidra.app.util.cparser.C import CParser  # type: ignore
    from java.io import ByteArrayInputStream  # type: ignore
    dtm_t, _, rapor = tipler.tipleri_ayristir()
    wp = tipler.yapilar(dtm_t, "window_pane")[0]
    yap = yapraklar(wp)
    bas = {}
    for o, n, ad in yap:
        bas.setdefault(o, []).append((n, ad))
    dtm = StandAloneDataTypeManager("g8_k1_dogruluk", tipler.veri_duzeni())
    tx = dtm.startTransaction("d")
    try:
        CParser(dtm, True, None).parse(ByteArrayInputStream(ON_TANIM.encode()))
        bagli = {h["bagli_yapi"] for h in k1["hedefler"] if h["bagli_yapi"]}
        sonuclar = {}
        for ad, y in k1["ilgili_yapilar"].items():
            try:
                tip_ad = alan_tipleri(dtm, ad, y)
            except Exception as exc:
                sonuclar[ad] = {"hata": str(exc)[:300]}
                continue
            siniflar = {"dogru": [], "ofset_dogru_boyut_yanlis": [], "yanlis": [], "tipi_cozulemeyen": []}
            for a in y["alanlar"]:
                alan = alan_adi(a["bildirim"])
                if alan is None or alan.startswith("padding_"):
                    continue
                dt = tip_ad.get(alan)
                if dt is None:
                    siniflar["tipi_cozulemeyen"].append(alan)
                    continue
                o, n = a["ofset"], dt.getLength()
                kayit = {"alan": alan, "ofset": o, "boyut": n}
                if o in bas and any(m == n for m, _ in bas[o]):
                    kayit["gercek"] = [x for m, x in bas[o] if m == n]
                    siniflar["dogru"].append(kayit)
                elif o in bas:
                    kayit["gercek"] = [f"{x} ({m} bayt)" for m, x in bas[o]]
                    siniflar["ofset_dogru_boyut_yanlis"].append(kayit)
                else:
                    siniflar["yanlis"].append(kayit)
            sonuclar[ad] = {"bagli": ad in bagli, "boyut": y["boyut"], "kaynaklar": y["kaynaklar"],
                            "sayilar": {k: len(v) for k, v in siniflar.items()}, "ayrinti": siniflar}
    finally:
        dtm.endTransaction(tx, True)

    def topla(secici):
        t = {"dogru": 0, "ofset_dogru_boyut_yanlis": 0, "yanlis": 0, "tipi_cozulemeyen": 0}
        for v in sonuclar.values():
            if "sayilar" in v and secici(v):
                for k in t:
                    t[k] += v["sayilar"][k]
        return t

    cikti = {"kunye": ortak.kunye(), "gercek": {"yapi": "window_pane", "boyut": wp.getLength(),
                                                "yaprak_sayisi": len(yap)},
             "bagli_toplam": topla(lambda v: v["bagli"]),
             "kaynak_listesindeki_toplam": topla(lambda v: True),
             "yapilar": sonuclar}
    ortak.json_yaz(ortak.VERI / "k1_yerlesim_dogrulugu.json", cikti)
    print("yaprak:", len(yap), "bağlı:", cikti["bagli_toplam"], "kaynak listesi:", cikti["kaynak_listesindeki_toplam"])
    for ad, v in sonuclar.items():
        if v.get("bagli"):
            print("  ", ad, v["boyut"], v["sayilar"], [ (x["alan"], x.get("gercek")) for x in v["ayrinti"]["dogru"]][:6])


def main(kosullar: list[str]) -> None:
    if kosullar == ["yerlesim"]:
        yerlesim_dogrulugu()
        return
    secim = json.loads((ortak.VERI / "secim.json").read_text())
    k3 = json.loads((ortak.VERI / "k3_secim.json").read_text()) if any(k.startswith("K3") for k in kosullar) else None
    k1 = json.loads((ortak.VERI / "k1_karadul.json").read_text())
    ortak.jvm_baslat()
    if any(k in ("K1", "K1y") for k in kosullar):
        fdefs_k1, yapilar_k1, k1_rapor = karadul_ayristir(k1)
        ortak.json_yaz(ortak.VERI / "k1_ayristirma.json", k1_rapor)
    for k in kosullar:
        if k == "K0":
            kosul_calistir(k, secim, lambda program: {"kosul": "K0"})
        elif k in ("K1", "K1y"):
            kosul_calistir(k, secim, lambda program, k=k: {**geri_yaz_k1(program, k, k1, fdefs_k1, yapilar_k1),
                                                           "ayristirma": k1_rapor})
        elif k == "K2":
            _, fdefs = kaynak_prototipleri(secim["hedefler"])
            kosul_calistir(k, secim, lambda program: geri_yaz_k2(program, secim["hedefler"], fdefs))
        elif k == "K3_C0":
            kosul_calistir(k, k3, lambda program: {"kosul": "K3_C0"})
        elif k == "K3_C3":
            dtm3, fdefs3 = kaynak_prototipleri(k3["hedefler"])
            deney.YAPI = "client"
            kosul_calistir(k, k3, lambda program: {**deney.geri_yaz(program, "C3", k3["hedefler"], dtm3, fdefs3),
                                                   "kosul": "K3_C3", "yapi": "client"})
        else:
            raise SystemExit(f"bilinmeyen koşul {k}")


if __name__ == "__main__":
    main(sys.argv[1:])
