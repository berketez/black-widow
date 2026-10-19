"""G8 tip kaynağı: tmux başlıklarını Ghidra'nın C ayrıştırıcısıyla ayrıştırır.

Adımlar
1. Ön işleme: `tmux.h` + 20 hedef fonksiyonun kaynak imzaları tek bir çeviri
   birimine konur; gerçek derlemenin (build_g/make.log, window.c satırı) bütün
   -D/-I bayraklarıyla, macOS SDK ve Homebrew bağımlılık başlıklarına karşı
   `clang -E` ile ön işlenir.
2. Uyarlama: Ghidra'nın C ayrıştırıcısının tanımadığı, yerleşimi etkilemeyen
   sözdizimi metinden çıkarılır (UYARLAMALAR listesi, her birinin sayısı kayda geçer).
   Yerleşimi etkileyen iki öznitelik (packed, aligned) silinmeden önce ait oldukları
   yapı adıyla kaydedilir ve ayrıştırmadan sonra Ghidra tipine uygulanır.
3. Ayrıştırma: hedef programın veri düzeniyle (AARCH64 AppleSilicon, default
   derleyici tanımı) kurulan bir StandAloneDataTypeManager'a.

Bu modül hem kütüphane (geri_yazma.py içinden `tipleri_ayristir`) hem de betik
olarak kullanılır: `python3 -I -B tipler.py` yerleşimi DWARF'la karşılaştırır.
"""

from __future__ import annotations

import json
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ortak  # noqa: E402

TU_C = ortak.VERI / "g8_tipler.c"
TU_I = ortak.VERI / "g8_tipler.i"
TU_UYARLI = ortak.VERI / "g8_tipler.uyarli.i"

DIL = "AARCH64:LE:64:AppleSilicon"
DERLEYICI = "default"

# Ön işleme sırasında eklenen tanımlar: clang'a özgü boşluk niteleyicileri (yerleşimi
# etkilemez) silinir, bloklar (^) kapatılır (SDK'daki _b işlevleri derlenmez).
EK_CPP = ["-fno-blocks", "-D_Nullable=", "-D_Nonnull=", "-D_Null_unspecified=",
          "-D_Nullable_result="]


def cpp_bayraklari() -> list[str]:
    """Gerçek derlemedeki window.c komut satırından ön işleme bayrakları."""
    satirlar = (ortak.BUILD_G / "make.log").read_text().splitlines()
    satir = [s for s in satirlar if s.startswith("clang ") and s.rstrip().endswith("/window.c")][0]
    arg = shlex.split(satir)[1:]
    out, atla = [], False
    for a in arg:
        if atla:
            atla = False
            continue
        if a == "-o":
            atla = True
            continue
        if a in ("-c", "-g", "-O2", "-Os") or a.endswith(".c"):
            continue
        out.append(a)
    return out


def on_isle(ek_bildirimler: str = "") -> Path:
    TU_C.write_text('#include <sys/types.h>\n#include "tmux.h"\n' + ek_bildirimler)
    cmd = ["/usr/bin/clang", "-E"] + cpp_bayraklari() + EK_CPP + [str(TU_C), "-o", str(TU_I)]
    r = subprocess.run(cmd, cwd=ortak.BUILD_G, capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        raise RuntimeError("clang -E başarısız:\n" + r.stderr[-4000:])
    return TU_I


# ---------------------------------------------------------------------------
# Uyarlamalar
# ---------------------------------------------------------------------------

def _kapanis(s: str, i: int) -> int:
    d = 0
    for k in range(i, len(s)):
        if s[k] == "(":
            d += 1
        elif s[k] == ")":
            d -= 1
            if d == 0:
                return k
    return -1


RE_YAPI_SONU = re.compile(r"(struct|union)\s+(\w+)\s*\{")


def oznitelikleri_ayikla(src: str) -> tuple[str, dict]:
    """Bütün __attribute__((...)) öbeklerini siler; yapı tanımının kapanış
    '}' işaretinden hemen sonra gelen packed/aligned özniteliklerini yapı adıyla döndürür."""
    out: list[str] = []
    yerlesim: dict[str, dict] = {}
    i = 0
    sayac = 0
    while True:
        j = src.find("__attribute__", i)
        if j == -1:
            out.append(src[i:])
            break
        k = j + len("__attribute__")
        while k < len(src) and src[k] in " \t\n":
            k += 1
        if k >= len(src) or src[k] != "(":
            out.append(src[i:k])
            i = k
            continue
        son = _kapanis(src, k)
        icerik = src[k:son + 1]
        onceki = "".join(out) + src[i:j]
        # Bu öznitelik bir yapı tanımının '}' işaretinin hemen ardında mı?
        geri = onceki.rstrip()
        if geri.endswith("}") and re.search(r"\b(__packed__|packed|aligned|__aligned__)\b", icerik):
            # eşleşen '{' ve önündeki struct/union adı
            d = 0
            for p in range(len(geri) - 1, -1, -1):
                if geri[p] == "}":
                    d += 1
                elif geri[p] == "{":
                    d -= 1
                    if d == 0:
                        bas = geri[max(0, p - 200):p + 1]
                        m = list(RE_YAPI_SONU.finditer(bas))
                        if m and bas.rstrip().endswith("{"):
                            ad = m[-1].group(2)
                            kayit = yerlesim.setdefault(ad, {})
                            if re.search(r"\b(__packed__|packed)\b", icerik):
                                kayit["packed"] = True
                            ma = re.search(r"aligned\s*\(\s*(\d+)\s*\)", icerik)
                            if ma:
                                kayit["aligned"] = int(ma.group(1))
                        break
        out.append(src[i:j])
        out.append(" ")
        sayac += 1
        i = son + 1
    return "".join(out), {"silinen_oznitelik": sayac, "yerlesim_oznitelikleri": yerlesim}


# (desen, yerine, gerekçe)
UYARLAMALAR = [
    (r"\b__builtin_va_list\b", "char *",
     "Darwin arm64 ABI'sinde va_list = char * (8 bayt); Ghidra yerleşik tipi tanımıyor"),
    (r"\brestrict\b", "",
     "C99 'restrict' niteleyicisi yerleşimi etkilemez; Ghidra ayrıştırıcısı tanımıyor "
     "(Ghidra'nın kendi macOS profili de -Drestrict ile siler)"),
]


def uyarla(src: str) -> tuple[str, dict]:
    rapor: dict = {"desenler": []}
    for desen, yerine, neden in UYARLAMALAR:
        src, n = re.subn(desen, yerine, src)
        rapor["desenler"].append({"desen": desen, "yerine": yerine, "neden": neden, "sayi": n})
    src, oz = oznitelikleri_ayikla(src)
    rapor.update(oz)
    return src, rapor


# ---------------------------------------------------------------------------
# Ayrıştırma
# ---------------------------------------------------------------------------

def veri_duzeni():
    from ghidra.program.model.lang import LanguageID, CompilerSpecID  # type: ignore
    from ghidra.program.util import DefaultLanguageService  # type: ignore
    lang = DefaultLanguageService.getLanguageService().getLanguage(LanguageID(DIL))
    return lang.getCompilerSpecByID(CompilerSpecID(DERLEYICI)).getDataOrganization()


def tipleri_ayristir(ek_bildirimler: str = "") -> tuple[object, object, dict]:
    """(dtm, parser, rapor). dtm: StandAloneDataTypeManager (hedef veri düzeniyle)."""
    from ghidra.program.model.data import StandAloneDataTypeManager  # type: ignore
    from ghidra.app.util.cparser.C import CParser  # type: ignore
    from java.io import ByteArrayInputStream  # type: ignore

    t0 = time.time()
    on_isle(ek_bildirimler)
    src, rapor = uyarla(TU_I.read_text(encoding="utf-8", errors="replace"))
    TU_UYARLI.write_text(src, encoding="utf-8")
    rapor["on_isleme_sn"] = round(time.time() - t0, 2)
    rapor["on_islenmis_satir"] = src.count("\n")
    rapor["on_islenmis_sha256"] = ortak.sha256(TU_UYARLI)

    dtm = StandAloneDataTypeManager("g8_tmux", veri_duzeni())
    tx = dtm.startTransaction("C ayrıştırma")
    # clang'ın yerleşik 128 bit tipleri (yalnız SDK'nın NEON durum yapısında geçiyor):
    # Ghidra'nın 16 baytlık tamsayı tipleriyle önceden tanımlanır.
    from ghidra.program.model.data import (TypedefDataType, CategoryPath,  # type: ignore
                                           Integer16DataType, UnsignedInteger16DataType,
                                           DataTypeConflictHandler)
    for ad, taban in (("__uint128_t", UnsignedInteger16DataType.dataType),
                      ("__int128_t", Integer16DataType.dataType)):
        dtm.resolve(TypedefDataType(CategoryPath.ROOT, ad, taban), DataTypeConflictHandler.DEFAULT_HANDLER)
    rapor["onceden_tanimlanan"] = ["__uint128_t = uint16 (16 bayt)", "__int128_t = int16 (16 bayt)"]
    parser = CParser(dtm, True, None)
    parser.setParseFileName("g8_tipler.i")
    t1 = time.time()
    try:
        parser.parse(ByteArrayInputStream(src.encode("utf-8")))
        rapor["ayristirma"] = "başarılı"
    except Exception as exc:  # ParseException
        rapor["ayristirma"] = "hata"
        rapor["ayristirma_hatasi"] = str(exc)[:4000]
    rapor["ayristirma_sn"] = round(time.time() - t1, 2)
    rapor["ayristirma_iletileri"] = str(parser.getParseMessages())[:4000]

    # packed / aligned özniteliklerini uygula
    uygulanan = []
    for ad, oz in rapor["yerlesim_oznitelikleri"].items():
        for s in yapilar(dtm, ad):
            if oz.get("packed"):
                s.setExplicitPackingValue(1)
            if oz.get("aligned"):
                s.setExplicitMinimumAlignment(oz["aligned"])
            uygulanan.append({"ad": ad, **oz, "boyut": s.getLength()})
    rapor["uygulanan_yerlesim_oznitelikleri"] = uygulanan
    dtm.endTransaction(tx, True)
    return dtm, parser, rapor


def yapilar(dtm, ad: str) -> list:
    from ghidra.program.model.data import Composite  # type: ignore
    out = []
    for dt in dtm.getAllComposites():
        if dt.getName() == ad:
            out.append(dt)
    return out


def yerlesim_dok(dt) -> dict:
    """Bir yapı/birlik tipinin yerleşimi: boyut, hizalama, bileşenler."""
    return {
        "ad": dt.getName(),
        "yol": str(dt.getPathName()),
        "boyut": dt.getLength(),
        "hizalama": dt.getAlignment(),
        "bilesenler": [
            {"ofset": c.getOffset(), "ad": c.getFieldName(), "tip": str(c.getDataType().getDisplayName()),
             "boyut": c.getLength()}
            for c in dt.getDefinedComponents()
        ],
    }


# ---------------------------------------------------------------------------
# DWARF karşılaştırması (bağımsız doğrulama: -g derlemenin dSYM'i)
# ---------------------------------------------------------------------------

def dwarf_yapilari(dsym: Path) -> dict:
    """dwarfdump çıktısından adlı struct/union yerleşimleri: {ad: {boyut, uyeler:{ad: ofset}}}.
    Aynı adın birden çok derleme biriminde tekrarlanan tanımları tutarlı olmalı."""
    if dsym.suffix == ".txt":
        metin = dsym.read_text(encoding="utf-8", errors="replace")
    else:
        metin = subprocess.run(["/usr/bin/dwarfdump", "--debug-info", str(dsym)],
                               capture_output=True, text=True, timeout=600).stdout
    out: dict[str, dict] = {}
    yigin: list[tuple[int, dict | None]] = []  # (girinti, yapı kaydı)
    cur_tag = None
    cur_indent = 0
    pending: dict = {}
    satirlar = metin.splitlines()

    def tamamla():
        nonlocal pending
        if not pending:
            return
        tag, ind, attrs = pending["tag"], pending["ind"], pending["attrs"]
        # yığını girintiye göre kırp
        while yigin and yigin[-1][0] >= ind:
            yigin.pop()
        kayit = None
        if tag in ("DW_TAG_structure_type", "DW_TAG_union_type") and "DW_AT_name" in attrs \
                and "DW_AT_declaration" not in attrs and "DW_AT_byte_size" in attrs:
            kayit = {"boyut": int(attrs["DW_AT_byte_size"], 0), "uyeler": {},
                     "tur": "union" if tag == "DW_TAG_union_type" else "struct"}
            ad = attrs["DW_AT_name"]
            onceki = out.get(ad)
            if onceki is None:
                out[ad] = kayit
            else:
                kayit = None if onceki["boyut"] == int(attrs["DW_AT_byte_size"], 0) else kayit
                if kayit is not None:
                    out.setdefault("__celiski__", {}).setdefault(ad, []).append(kayit["boyut"])
                    kayit = None
        elif tag == "DW_TAG_member" and yigin and yigin[-1][1] is not None and yigin[-1][0] < ind:
            ust = yigin[-1][1]
            ad = attrs.get("DW_AT_name", f"<anon@{attrs.get('DW_AT_data_member_location', '?')}>")
            loc = attrs.get("DW_AT_data_member_location")
            if loc is not None:
                try:
                    ust["uyeler"][ad] = int(loc, 0)
                except ValueError:
                    pass
        yigin.append((ind, kayit if tag in ("DW_TAG_structure_type", "DW_TAG_union_type") else None))
        pending = {}

    for s in satirlar:
        m = re.match(r"^0x[0-9a-f]+:(\s+)(DW_TAG_\w+)", s)
        if m:
            tamamla()
            pending = {"tag": m.group(2), "ind": len(m.group(1)), "attrs": {}}
            continue
        m = re.match(r"^\s+(DW_AT_\w+)\s+\((.*)\)\s*$", s)
        if m and pending:
            k, v = m.group(1), m.group(2)
            if v.startswith('"') and v.endswith('"'):
                v = v[1:-1]
            pending["attrs"][k] = v
    tamamla()
    return out


def kapanis_kumesi(dt) -> list:
    """Bir yapının değerle gömdüğü (işaretçi arkası değil) bütün yapı/birlik tipleri:
    kendisi dahil, dizi elemanları ve typedef'ler açılarak."""
    from ghidra.program.model.data import Composite, Array, TypeDef  # type: ignore
    gorulen: dict[str, object] = {}

    def gez(t):
        while isinstance(t, (Array, TypeDef)):
            t = t.getDataType() if isinstance(t, Array) else t.getBaseDataType()
        if isinstance(t, Composite):
            if t.getPathName() in gorulen:
                return
            gorulen[t.getPathName()] = t
            for c in t.getDefinedComponents():
                gez(c.getDataType())

    gez(dt)
    return list(gorulen.values())


def karsilastir(dt, dwarf: dict) -> dict:
    """Ghidra yerleşimi ile DWARF yerleşimini karşılaştır (adlı yapı için)."""
    ad = dt.getName()
    d = dwarf.get(ad)
    if dt.getNumComponents() == 0:
        return {"ad": ad, "durum": "yalnız ileri bildirim", "boyut_ghidra": dt.getLength(),
                "boyut_dwarf": d["boyut"] if d else None}
    if d is None:
        return {"ad": ad, "durum": "dwarf'ta yok", "boyut_ghidra": dt.getLength()}
    farklar = []
    if d["boyut"] != dt.getLength():
        farklar.append({"alan": "<boyut>", "dwarf": d["boyut"], "ghidra": dt.getLength()})
    gh = {c.getFieldName(): c.getOffset() for c in dt.getDefinedComponents() if c.getFieldName()}
    for uye, ofs in d["uyeler"].items():
        if uye.startswith("<anon@"):
            continue
        if uye not in gh:
            farklar.append({"alan": uye, "dwarf": ofs, "ghidra": None})
        elif gh[uye] != ofs:
            farklar.append({"alan": uye, "dwarf": ofs, "ghidra": gh[uye]})
    return {"ad": ad, "durum": "eşit" if not farklar else "farklı", "boyut": dt.getLength(),
            "alan_sayisi_dwarf": len(d["uyeler"]), "farklar": farklar}


def main() -> None:
    """Yerleşim doğrulaması (ön kayıt §4 madde 1): Ghidra C ayrıştırıcısının yerleşimi
    ile -g derlemenin DWARF yerleşimi. Çıktı: BELGE/yerlesim_dogrulama.json"""
    ortak.jvm_baslat()
    dtm, parser, rapor = tipleri_ayristir()
    if rapor["ayristirma"] != "başarılı":
        raise SystemExit("ayrıştırma başarısız")
    dwarf = dwarf_yapilari(ortak.VERI / "dwarf_debug_info.txt")
    wp = yapilar(dtm, "window_pane")
    if len(wp) != 1:
        raise SystemExit(f"window_pane sayısı {len(wp)}")
    kapanis = kapanis_kumesi(wp[0])
    kap = [karsilastir(t, dwarf) for t in kapanis]
    tmux_h = [dt for dt in dtm.getAllComposites() if str(dt.getCategoryPath()) == "/tmux.h"]
    tum = [karsilastir(t, dwarf) for t in tmux_h]

    def ozet(liste):
        c = {"eşit": 0, "farklı": 0, "dwarf'ta yok": 0, "yalnız ileri bildirim": 0}
        for x in liste:
            c[x["durum"]] += 1
        return c

    from ghidra.program.model.data import BitFieldDataType  # type: ignore
    bitalan = [str(t.getPathName()) for t in kapanis
               if any(isinstance(c.getDataType(), BitFieldDataType) for c in t.getDefinedComponents())]
    cikti = {
        "kunye": ortak.kunye(),
        "yontem": "clang -E (gerçek derleme bayrakları) + Ghidra CParser; hedef veri düzeni "
                  f"{DIL}/{DERLEYICI}; doğrulama: aynı seçeneklerle -g derlemenin DWARF'ı",
        "ayristirma_raporu": rapor,
        "window_pane": yerlesim_dok(wp[0]),
        "kapanis": {"yapi_sayisi": len(kapanis), "adli": sum(1 for x in kap if x["durum"] != "dwarf'ta yok"),
                    "ozet": ozet(kap), "bit_alanli_yapilar": bitalan, "ayrinti": kap},
        "tmux_h_yapilari": {"sayi": len(tmux_h), "ozet": ozet(tum),
                            "farkli": [x for x in tum if x["durum"] == "farklı"],
                            "dwarfta_yok": sorted(x["ad"] for x in tum if x["durum"] == "dwarf'ta yok"),
                            "yalniz_ileri_bildirim": sorted(x["ad"] for x in tum
                                                            if x["durum"] == "yalnız ileri bildirim")},
        "dwarf_celiskisi": dwarf.get("__celiski__"),
    }
    ortak.json_yaz(ortak.BELGE / "yerlesim_dogrulama.json", cikti)
    print("window_pane:", cikti["window_pane"]["boyut"], "bayt,", len(cikti["window_pane"]["bilesenler"]), "alan")
    print("kapanış:", cikti["kapanis"]["yapi_sayisi"], "yapı;", cikti["kapanis"]["ozet"],
          "bit alanlı:", bitalan)
    for x in kap:
        print("  ", x["ad"], x["durum"], x.get("boyut", x.get("boyut_ghidra")), x.get("farklar", ""))
    print("tmux.h yapıları:", cikti["tmux_h_yapilari"]["sayi"], cikti["tmux_h_yapilari"]["ozet"])
    for x in cikti["tmux_h_yapilari"]["farkli"]:
        print("  FARKLI", x["ad"], x["farklar"][:5])


if __name__ == "__main__":
    main()
