#!/usr/bin/env python3
"""P09 ölçümü: tip ve yapı kurtarmayı kayıtlı ürün koşusu üstünde Ghidra'sız yeniden oynatır.

Kayıtlı ürün koşusunun çalışma dizini tip kurtarıcının girdisini tutar. İlk yinelemede
``CTypeRecoverer.recover`` girdisi ``reconstructed/merged/``, çıktısı ``reconstructed/typed/``'dir;
ardından XTRIDE (``_feedback_typing_extras.run_xtride_typing``) ``typed/`` içindeki dosyaları
yerinde değiştirir. ``c_project_builder`` ilk yinelemenin ``typed/types.h``'sini ürünün
``out/src/include/types.h``'sine taşır. Bu betik ölçülen ağacın (çalıştığı worktree) kodunu aynı
girdilerle koşar; JSON yolları ``ghidra_metadata._resolve_json_paths`` kuralıyladır
(``deobfuscated/`` önce, sonra ``static/``; ``decompiled.json`` yoksa ``static/ghidra_output/``).

Alt komutlar
------------
    kos          --kosu <kayıtlı koşu kökü> --kok <çıktı kökü> --etiket <ad> [--yalniz a,b] [--sakla]
    karsilastir  --kok <çıktı kökü> --once <etiket> --sonra <etiket>

Ölçüler (ikili başına; ``ozet.json`` toplamları)
-----------------------------------------------
dogrulama
    Yeniden oynatılan ``typed/`` dosyalarından kayıtlı ``typed/`` ile bayt bayt aynı olanlar.
    Yalnız ölçülen ağaç kayıtlı koşuyu üreten kodla aynı davranıyorsa anlamlıdır (taban).
yapi
    ``types_h_recovered_struct``: ``types.h``'deki ``struct recovered_struct_N {`` tanımları.
    ``types_h_sabit_080``: ``confidence: 0.80`` taşıyan alan satırları.
    ``types_h_ortusen``: alanları açıklamadaki ofset ve tip boyutuyla üst üste binen yapılar
    (boyut tablosu ``BOYUT``; bilinmeyen tipli alan denetimi o yapıda keser).
    ``koda_bagli``: adı en az bir ``.c`` dosyasında (kod içinde) geçen ``recovered_struct_N``.
    ``aday_dosyasi``: ``types_candidates.txt`` varsa içindeki tanım sayısı (yoksa ``None``).
degisim
    ``merged/`` (Ghidra + adlandırma) ile ``typed/`` (tip kurtarma + XTRIDE) arasında bildirim
    tipi değişen (fonksiyon, değişken) çiftleri; parametreler imzadan sırayla, yereller satır başı
    bildiriminden. Sınıflar: ``ontanim`` (``undefinedN`` → ``_UNDEFINED_DEFAULTS``),
    ``cikarim`` (geri kalan), ``double_yeni`` (yeni tip ``double``/``float``, eski değil),
    ``genislik_bozan`` (iki tipin de boyutu bilinir ve farklı), ``somut_ezilen`` (eski tip
    ``undefined*`` değil, yeni tip işaretçi değil).
dwarf
    T0b hizalama belgesi (``--hizalama``) olan ikililerde, adresle bulunan fonksiyonun
    ``eslesme == "tam"`` parametreleri (``depolama_ortagi`` = Ghidra parametre sırası). Ghidra tipi
    ``merged/`` imzasından, Karadul tipi ``typed/`` imzasından. Hüküm (``hukum``): ``bilgisiz``
    (``undefined*``, bilinmeyen ad), ``dogru`` / ``yanlis`` (tür: işaretçi / kayan / tamsayı;
    tamsayıda iki boyut da biliniyorsa boyut). DWARF sınıfı ``yapi_degerle``/``diger`` olanlar
    sayılmaz. ``kotulesen``: tip değişti, Karadul ``yanlis``, Ghidra ``yanlis`` değil.
    ``iyilesen``: tip değişti, Karadul ``dogru``, Ghidra ``dogru`` değil. İkili imzanın parametre
    sayısı hizalamadaki ``ghidra_parametre`` ile tutmazsa fonksiyon ``imza_uyusmadi`` sayılır.
"""

from __future__ import annotations

import argparse
import filecmp
import json
import re
import shutil
import sys
import time
from pathlib import Path
from types import SimpleNamespace

ARAC = "p09_olc/1"
DEPO = Path(__file__).resolve().parents[2]
YAPI_ADAY_DOSYA_ADI = "types_candidates.txt"

# Ghidra'nın ve C'nin tip adları -> bayt.  ``undefined`` Ghidra'da 1 bayttır.
BOYUT: dict[str, int] = {
    "char": 1, "uchar": 1, "byte": 1, "bool": 1, "_Bool": 1, "undefined1": 1, "undefined": 1,
    "int8_t": 1, "uint8_t": 1, "signed char": 1, "unsigned char": 1, "sbyte": 1,
    "short": 2, "ushort": 2, "undefined2": 2, "int16_t": 2, "uint16_t": 2, "word": 2,
    "unsigned short": 2, "short int": 2, "short unsigned int": 2, "wchar16": 2,
    "int": 4, "uint": 4, "undefined4": 4, "int32_t": 4, "uint32_t": 4, "float": 4, "dword": 4,
    "unsigned int": 4, "unsigned": 4, "pid_t": 4, "uid_t": 4, "gid_t": 4, "mode_t": 4,
    "wchar_t": 4, "wchar32": 4, "socklen_t": 4,
    "long": 8, "ulong": 8, "undefined8": 8, "int64_t": 8, "uint64_t": 8, "double": 8,
    "longlong": 8, "ulonglong": 8, "long long": 8, "size_t": 8, "ssize_t": 8, "off_t": 8,
    "time_t": 8, "intptr_t": 8, "uintptr_t": 8, "qword": 8, "long int": 8,
    "long unsigned int": 8, "long long int": 8, "long long unsigned int": 8,
    "unsigned long": 8, "ptrdiff_t": 8, "uint64": 8,
}
KAYAN = {"float", "double", "long double", "float10"}
ONTANIM = {"undefined1": "uint8_t", "undefined2": "uint16_t", "undefined4": "int32_t",
           "undefined8": "uint64_t", "undefined": "uint64_t"}
ISARETCI_DWARF = {"char*", "void*", "yapi*", "skaler*", "ptr**", "fonk*"}

_KOD_DISI = re.compile(
    r'"(?:\\.|[^"\\\n])*(?:"|(?=\n)|\Z)'
    r"|'(?:\\.|[^'\\\n])*(?:'|(?=\n)|\Z)"
    r"|//[^\n]*"
    r"|/\*.*?(?:\*/|\Z)",
    re.DOTALL,
)
_ADRES = re.compile(r"^// Address:\s*([0-9a-fA-F]+)\s*$", re.MULTILINE)
_IMZA = re.compile(
    r"^(?P<rtype>[A-Za-z_][\w \t\*]*?)[ \t\*]+(?P<fname>[A-Za-z_]\w*)[ \t]*\((?P<params>[^)]*)\)"
    r"\s*\n?\s*\{",
    re.MULTILINE,
)
_YEREL = re.compile(
    r"^[ \t]+(?P<type>(?:(?:const|unsigned|signed|struct|union|enum)\s+)*[A-Za-z_]\w*"
    r"(?:\s*\*)*)\s*(?P<ptr>\**)\s*(?P<var>[A-Za-z_]\w*)\s*(?:\[[^\]\n]*\]\s*)*;[ \t]*$",
    re.MULTILINE,
)
_ANAHTAR_SOZ = {"return", "goto", "case", "else", "do", "break", "continue", "typedef"}
_YAPI_TANIM = re.compile(r"^struct (recovered_struct_\d+) \{$", re.MULTILINE)
_ALAN = re.compile(
    r"^\s+(?P<type>[^;]+?)\s+(?P<name>\w+)(?P<dizi>\[\d+\])?;\s+/\* 0x(?P<off>[0-9A-Fa-f]+) \*/")


def ontanim_mi(eski: str, yeni: str) -> bool:
    """Değişim yalnız ``undefinedN`` sözcüklerinin öntanıma çevrilmesi mi (``undefined8 *`` dahil)."""
    return re.sub(r"\bundefined[1248]?\b", lambda m: ONTANIM[m.group(0)], eski) == yeni


def kod_ort(metin: str) -> str:
    """Dizgi, karakter sabiti ve yorumları aynı uzunlukta boşlukla ört (satırlar korunur)."""
    return _KOD_DISI.sub(lambda m: "".join("\n" if c == "\n" else " " for c in m.group(0)), metin)


def tip_normal(t: str) -> str:
    t = re.sub(r"\s+", " ", t.strip())
    t = re.sub(r"\s*\*", " *", t).replace("* *", "**").strip()
    while "* *" in t:
        t = t.replace("* *", "**")
    return t


def tip_boyutu(t: str) -> int | None:
    t = tip_normal(t)
    if "*" in t:
        return 8
    t = re.sub(r"^(const|volatile) ", "", t)
    return BOYUT.get(t)


def tip_turu(t: str) -> str:
    """``isaretci`` | ``kayan`` | ``tamsayi`` | ``bilinmiyor``."""
    t = tip_normal(t)
    if "*" in t:
        return "isaretci"
    t = re.sub(r"^(const|volatile) ", "", t)
    if t.startswith("undefined"):
        return "bilinmiyor"
    if t in KAYAN:
        return "kayan"
    if t in BOYUT:
        return "tamsayi"
    return "bilinmiyor"


# ---------------------------------------------------------------------------
# Çalışma dizini ve yeniden oynatma
# ---------------------------------------------------------------------------

def calisma_dizini(kosu: Path, anahtar: str) -> Path:
    adaylar = sorted((kosu / anahtar / "ws" / "workspaces").glob("*/*/reconstructed"))
    if len(adaylar) != 1:
        raise SystemExit(f"{kosu / anahtar}: {len(adaylar)} reconstructed dizini (bir olmalı)")
    return adaylar[0].parent


def json_yollari(ws: Path) -> dict[str, Path]:
    st, de = ws / "static", ws / "deobfuscated"

    def sec(ad: str) -> Path:
        p = de / ad
        return p if p.exists() else st / ad

    dj = sec("decompiled.json")
    if not dj.exists():
        dj = st / "ghidra_output" / "decompiled.json"
    return {
        "functions": sec("ghidra_functions.json"),
        "strings": sec("ghidra_strings.json"),
        "types": sec("ghidra_types.json"),
        "call_graph": sec("ghidra_call_graph.json"),
        "decompiled": dj,
    }


def tip_girdisi(ws: Path) -> Path:
    """İlk yinelemenin tip kurtarma girdisi: ad birleştiricinin ``merged/``'i, yoksa ``src/``."""
    rec = ws / "reconstructed"
    return rec / "merged" if (rec / "merged").is_dir() else rec / "src"


def yeniden_oynat(ws: Path, hedef: Path) -> dict:
    from karadul.config import Config
    from karadul.pipeline.steps._feedback_typing_extras import run_xtride_typing
    from karadul.reconstruction.c_type_recoverer import CTypeRecoverer

    y = json_yollari(ws)
    girdi = tip_girdisi(ws)
    typed = hedef / "typed"
    if typed.exists():
        shutil.rmtree(typed)
    cfg = Config()
    bas = time.monotonic()
    sonuc = CTypeRecoverer(cfg).recover(
        girdi, y["functions"], typed,
        strings_json=y["strings"], ghidra_types_json=y["types"],
        computation_structs=None, call_graph_json=y["call_graph"],
        decompiled_json=y["decompiled"] if y["decompiled"].exists() else None,
    )
    sure_tip = time.monotonic() - bas
    stats: dict = {}
    hatalar: list[str] = []
    ctx = SimpleNamespace(pipeline_context=SimpleNamespace(config=cfg))
    bas = time.monotonic()
    if sonuc.success and sonuc.output_files:
        run_xtride_typing(ctx=ctx, iter_index=0, decompiled_dir=typed,
                          incremental_files=None, stats=stats, errors=hatalar)
    return {
        "basari": bool(sonuc.success),
        "hata_sayisi": len(sonuc.errors) + len(hatalar),
        "hata_ornek": (list(sonuc.errors) + hatalar)[:3],
        "sonuc_structs": len(sonuc.structs),
        "sonuc_aday": len(getattr(sonuc, "struct_candidates", []) or []),
        "total_types_recovered": sonuc.total_types_recovered,
        "geri_alinan": sonuc.type_recovery_reverted,
        "xtride": {k: v for k, v in stats.items() if not k.startswith("timing")},
        "sure_sn": {"tip": round(sure_tip, 1), "xtride": round(time.monotonic() - bas, 1)},
    }


def dogrula(ws: Path, typed: Path) -> dict:
    kayitli = ws / "reconstructed" / "typed"
    ayni = farkli = 0
    ornek: list[str] = []
    for f in sorted(kayitli.iterdir()):
        if not f.is_file():
            continue
        g = typed / f.name
        if g.exists() and filecmp.cmp(f, g, shallow=False):
            ayni += 1
        else:
            farkli += 1
            if len(ornek) < 5:
                ornek.append(f.name)
    return {"ayni": ayni, "farkli": farkli, "farkli_ornek": ornek}


# ---------------------------------------------------------------------------
# Yapı sayımı
# ---------------------------------------------------------------------------

def ortusen_say(metin: str) -> int:
    """Alanları açıklamadaki ofset ve tip boyutuyla üst üste binen ``recovered_struct`` sayısı."""
    ortusen = 0
    for blok in re.split(r"^struct ", metin, flags=re.MULTILINE)[1:]:
        if not blok.startswith("recovered_struct_"):
            continue
        govde = blok.split("\n};", 1)[0]
        onceki_son = 0
        for satir in govde.split("\n")[1:]:
            m = _ALAN.match(satir)
            if not m:
                continue
            boy = tip_boyutu(m.group("type"))
            if boy is None:
                break
            if m.group("dizi"):
                boy *= int(m.group("dizi")[1:-1])
            off = int(m.group("off"), 16)
            if off < onceki_son:
                ortusen += 1
                break
            onceki_son = off + boy
    return ortusen


def yapi_say(typed: Path) -> dict:
    th = typed / "types.h"
    metin = th.read_text(encoding="utf-8", errors="replace") if th.exists() else ""
    tanimlar = _YAPI_TANIM.findall(metin)
    ortusen = ortusen_say(metin)
    adlar = set(tanimlar)
    bagli: set[str] = set()
    if adlar:
        desen = re.compile(r"\brecovered_struct_\d+\b")
        for c in typed.glob("*.c"):
            for ad in desen.findall(kod_ort(c.read_text(encoding="utf-8", errors="replace"))):
                bagli.add(ad)
    aday = typed / YAPI_ADAY_DOSYA_ADI
    aday_sayi = aday_ortusen = None
    if aday.exists():
        aday_metin = aday.read_text(encoding="utf-8")
        aday_sayi = len(re.findall(r"^struct \w+ \{$", aday_metin, re.MULTILINE))
        aday_ortusen = ortusen_say(aday_metin)
    return {
        "types_h_recovered_struct": len(tanimlar),
        "types_h_sabit_080": metin.count("confidence: 0.80"),
        "types_h_ortusen": ortusen,
        "koda_bagli": len(bagli & adlar),
        "kodda_tanimsiz_yapi_adi": len(bagli - adlar),
        "aday_dosyasi": aday_sayi,
        "aday_ortusen": aday_ortusen,
    }


# ---------------------------------------------------------------------------
# Bildirim değişimi
# ---------------------------------------------------------------------------

def bildirimler(metin: str) -> dict:
    """{(fonksiyon, değişken): tip}, {fonksiyon: [parametre tipi, ...]}, {fonksiyon: adres}."""
    kod = kod_ort(metin)
    adres_m = _ADRES.search(metin)
    adres = int(adres_m.group(1), 16) if adres_m else None
    tipler: dict[tuple[str, str], str] = {}
    paramlar: dict[str, list[str]] = {}
    adresler: dict[str, int | None] = {}
    imzalar = list(_IMZA.finditer(kod))
    for i, m in enumerate(imzalar):
        fn = m.group("fname")
        if fn in _ANAHTAR_SOZ or m.group("rtype").split()[0] in _ANAHTAR_SOZ:
            continue
        adresler.setdefault(fn, adres if i == 0 else None)
        liste: list[str] = []
        ps = m.group("params").strip()
        if ps and ps != "void":
            for p in ps.split(","):
                p = p.strip()
                pm = re.match(r"^(?P<type>.*?[\s\*])(?P<var>[A-Za-z_]\w*)\s*$", p)
                if not pm:
                    liste.append(tip_normal(p))
                    continue
                t = tip_normal(pm.group("type"))
                liste.append(t)
                tipler[(fn, pm.group("var"))] = t
        paramlar[fn] = liste
        son = imzalar[i + 1].start() if i + 1 < len(imzalar) else len(kod)
        for d in _YEREL.finditer(kod, m.end(), son):
            ilk = d.group("type").split()[0]
            if ilk in _ANAHTAR_SOZ:
                continue
            tipler[(fn, d.group("var"))] = tip_normal(d.group("type") + " " + d.group("ptr"))
    return {"tipler": tipler, "paramlar": paramlar, "adresler": adresler}


# Öz-tutarlılık (doğruluk ölçüsü DEĞİL): çıkarılan tipin, değişkenin KENDİ fonksiyonunun
# kodunda (dizgi ve yorum örtülü) en basit kanıtı var mı?  TIP-06'nın birinci kusuru (kanıt bir
# fonksiyondan, tip başka fonksiyona) burada "kanıtsız" olarak görünür.
OZ_KANIT: dict[str, list[str]] = {
    "char *": [r"\b(?:strcmp|strncmp|strlen|strcpy|strncpy|strcat|strncat|printf|sprintf|snprintf"
               r"|puts|fputs|strstr|strchr)\s*\(\s*{v}\b"],
    "void *": [r"\b{v}\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc)\s*\(",
               r"\*\s*{v}\s*[;=,)\]]", r"\b{v}\s*\[", r"\b{v}\s*\+\s*(?:0x[0-9a-fA-F]+|\d+)\s*\)",
               r"\b{v}\s*[!=]=\s*(?:\(\s*\w+\s*\*?\s*\)\s*)?(?:NULL|0x0)\b", r"\b{v}\s*->"],
    "double": [r"\b{v}\s*=(?!=)[^;]*\b\d+\.\d+"],
}


def govdeler(metin: str) -> dict[str, str]:
    """{fonksiyon: dizgi ve yorumu örtülmüş gövde metni}."""
    kod = kod_ort(metin)
    imzalar = [m for m in _IMZA.finditer(kod) if m.group("fname") not in _ANAHTAR_SOZ]
    out = {}
    for i, m in enumerate(imzalar):
        son = imzalar[i + 1].start() if i + 1 < len(imzalar) else len(kod)
        out.setdefault(m.group("fname"), kod[m.start():son])
    return out


def oz_kanit_var(govde: str, var: str, tip: str) -> bool | None:
    kurallar = OZ_KANIT.get(tip)
    if not kurallar:
        return None
    return any(re.search(k.format(v=re.escape(var)), govde) for k in kurallar)


def degisim_say(merged: Path, typed: Path, ornek_sayisi: int = 8) -> dict:
    sayac = {"degisen": 0, "ontanim": 0, "cikarim": 0, "double_yeni": 0,
             "genislik_bozan": 0, "somut_ezilen": 0, "oz_kanit_denetlenen": 0, "kanitsiz": 0}
    ornek: dict[str, list[str]] = {"double_yeni": [], "genislik_bozan": [], "somut_ezilen": [],
                                   "kanitsiz": []}
    for mf in sorted(merged.glob("*.c")):
        tf = typed / mf.name
        if not tf.exists():
            continue
        mt = mf.read_text(encoding="utf-8", errors="replace")
        a = bildirimler(mt)["tipler"]
        b = bildirimler(tf.read_text(encoding="utf-8", errors="replace"))["tipler"]
        gov = None
        for k, eski in a.items():
            yeni = b.get(k)
            if yeni is None or yeni == eski:
                continue
            sayac["degisen"] += 1
            if ontanim_mi(eski, yeni):
                sayac["ontanim"] += 1
                continue
            sayac["cikarim"] += 1
            etiket = f"{mf.name}:{k[0]}:{k[1]}: {eski} -> {yeni}"
            if gov is None:
                gov = govdeler(mt)
            kanit = oz_kanit_var(gov.get(k[0], ""), k[1], tip_normal(yeni))
            if kanit is not None:
                sayac["oz_kanit_denetlenen"] += 1
                if not kanit:
                    sayac["kanitsiz"] += 1
                    if len(ornek["kanitsiz"]) < ornek_sayisi:
                        ornek["kanitsiz"].append(etiket)
            if tip_turu(yeni) == "kayan" and tip_turu(eski) != "kayan":
                sayac["double_yeni"] += 1
                if len(ornek["double_yeni"]) < ornek_sayisi:
                    ornek["double_yeni"].append(etiket)
            be, by = tip_boyutu(eski), tip_boyutu(yeni)
            if be is not None and by is not None and be != by:
                sayac["genislik_bozan"] += 1
                if len(ornek["genislik_bozan"]) < ornek_sayisi:
                    ornek["genislik_bozan"].append(etiket)
            if not tip_normal(eski).startswith("undefined") and tip_turu(yeni) != "isaretci":
                sayac["somut_ezilen"] += 1
                if len(ornek["somut_ezilen"]) < ornek_sayisi:
                    ornek["somut_ezilen"].append(etiket)
    return {"sayac": sayac, "ornek": ornek}


# ---------------------------------------------------------------------------
# DWARF parametre karşılaştırması
# ---------------------------------------------------------------------------

def dwarf_turu(p: dict) -> tuple[str | None, int | None]:
    sinif, tip = p.get("sinif"), (p.get("tip") or "").strip()
    if sinif in ISARETCI_DWARF:
        return "isaretci", 8
    if sinif == "skaler":
        t = re.sub(r"^(const|volatile) ", "", tip)
        if t in KAYAN:
            return "kayan", BOYUT.get(t)
        return "tamsayi", BOYUT.get(t)
    return None, None


def hukum(tip: str, d_tur: str, d_boy: int | None) -> str:
    tur = tip_turu(tip)
    if tur == "bilinmiyor":
        return "bilgisiz"
    if tur != d_tur:
        return "yanlis"
    if tur == "tamsayi":
        boy = tip_boyutu(tip)
        if boy is not None and d_boy is not None and boy != d_boy:
            return "yanlis"
    return "dogru"


def dwarf_karsilastir(hizalama: Path, merged: Path, typed: Path, sha256: str | None) -> dict:
    doc = json.loads(hizalama.read_text(encoding="utf-8"))
    girdi = doc.get("girdi", {})
    if sha256 and girdi.get("ghidra_ikili_sha256") and girdi["ghidra_ikili_sha256"] != sha256:
        return {"durum": "sha_uyusmadi"}
    adres_dosya: dict[int, Path] = {}
    for mf in merged.glob("*.c"):
        m = _ADRES.search(mf.read_text(encoding="utf-8", errors="replace")[:600])
        if m:
            adres_dosya[int(m.group(1), 16)] = mf
    s = {"parametre": 0, "degisen": 0, "kotulesen": 0, "iyilesen": 0,
         "degisen_cikarim": 0, "kotulesen_cikarim": 0, "iyilesen_cikarim": 0,
         "ghidra": {"dogru": 0, "yanlis": 0, "bilgisiz": 0},
         "karadul": {"dogru": 0, "yanlis": 0, "bilgisiz": 0},
         "fonksiyon_yok": 0, "imza_uyusmadi": 0}
    ornek: list[str] = []
    for f in doc.get("fonksiyonlar", []):
        g = f.get("ghidra") or {}
        if not g.get("giris") or g.get("thunk"):
            continue
        tam = [p for p in f.get("parametreler", [])
               if p.get("eslesme") == "tam" and p.get("depolama_ortagi")]
        if not tam:
            continue
        mf = adres_dosya.get(int(g["giris"], 16))
        if mf is None or not (typed / mf.name).exists():
            s["fonksiyon_yok"] += 1
            continue
        a = bildirimler(mf.read_text(encoding="utf-8", errors="replace"))
        b = bildirimler((typed / mf.name).read_text(encoding="utf-8", errors="replace"))
        fa = [fn for fn, ad in a["adresler"].items() if ad == int(g["giris"], 16)]
        if not fa or fa[0] not in b["paramlar"]:
            s["fonksiyon_yok"] += 1
            continue
        pa, pb = a["paramlar"][fa[0]], b["paramlar"][fa[0]]
        if len(pa) != f.get("ghidra_parametre") or len(pb) != len(pa):
            s["imza_uyusmadi"] += 1
            continue
        for p in tam:
            d_tur, d_boy = dwarf_turu(p["dwarf"])
            if d_tur is None:
                continue
            i = p["depolama_ortagi"] - 1
            if i >= len(pa):
                continue
            hg, hk = hukum(pa[i], d_tur, d_boy), hukum(pb[i], d_tur, d_boy)
            s["parametre"] += 1
            s["ghidra"][hg] += 1
            s["karadul"][hk] += 1
            if pa[i] != pb[i]:
                cikarim = not ontanim_mi(pa[i], pb[i])
                s["degisen"] += 1
                s["degisen_cikarim"] += cikarim
                if hk == "yanlis" and hg != "yanlis":
                    s["kotulesen"] += 1
                    s["kotulesen_cikarim"] += cikarim
                    if cikarim and len(ornek) < 8:
                        ornek.append(f"{fa[0]} p{i + 1}: {pa[i]} -> {pb[i]} (DWARF {p['dwarf'].get('tip')})")
                if hk == "dogru" and hg != "dogru":
                    s["iyilesen"] += 1
                    s["iyilesen_cikarim"] += cikarim
    s["kotulesen_ornek"] = ornek
    s["durum"] = "olculdu"
    return s


# ---------------------------------------------------------------------------
# Komutlar
# ---------------------------------------------------------------------------

def hizalama_bul(hizalama_kok: Path | None, anahtar: str) -> Path | None:
    if hizalama_kok is None:
        return None
    p = hizalama_kok / f"{anahtar.rsplit('/', 1)[-1]}.json"
    if not p.exists() or not anahtar.startswith("debian/"):
        return None
    paket = anahtar.split("/")[1]
    doc = json.loads(p.read_text(encoding="utf-8"))
    return p if doc.get("girdi", {}).get("paket") == paket else None


def anahtarlar(kosu: Path) -> list[str]:
    out = []
    for bitti in sorted(kosu.glob("**/BITTI")):
        out.append(str(bitti.parent.relative_to(kosu)))
    return out


def ikili_sha(ws: Path) -> str | None:
    p = ws / "raw" / "target_info.json"
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8")).get("file_hash")


def kos(arg: argparse.Namespace) -> int:
    kosu = Path(arg.kosu).expanduser()
    kok = Path(arg.kok).expanduser() / arg.etiket
    kok.mkdir(parents=True, exist_ok=True)
    hepsi = anahtarlar(kosu)
    if arg.yalniz:
        istenen = [a.strip() for a in arg.yalniz.split(",") if a.strip()]
        eksik = [a for a in istenen if a not in hepsi]
        if eksik:
            raise SystemExit(f"koşuda yok: {eksik}")
        hepsi = istenen
    hizalama_kok = Path(arg.hizalama).expanduser() if arg.hizalama else None
    sonuc = {}
    for anahtar in hepsi:
        ws = calisma_dizini(kosu, anahtar)
        hedef = kok / anahtar
        hedef.mkdir(parents=True, exist_ok=True)
        r = yeniden_oynat(ws, hedef)
        typed = hedef / "typed"
        r["dogrulama"] = dogrula(ws, typed)
        r["yapi"] = yapi_say(typed)
        r["degisim"] = degisim_say(tip_girdisi(ws), typed)
        hz = hizalama_bul(hizalama_kok, anahtar)
        r["dwarf"] = (dwarf_karsilastir(hz, tip_girdisi(ws), typed, ikili_sha(ws))
                      if hz else {"durum": "hizalama_yok"})
        (hedef / "olcum.json").write_text(json.dumps(r, ensure_ascii=False, indent=1),
                                          encoding="utf-8")
        if not arg.sakla:
            for c in typed.glob("*.c"):
                c.unlink()
        sonuc[anahtar] = r
        print(f"{anahtar}: yapı {r['yapi']['types_h_recovered_struct']} bağlı "
              f"{r['yapi']['koda_bagli']} aday {r['yapi']['aday_dosyasi']} | çıkarım "
              f"{r['degisim']['sayac']['cikarim']} double {r['degisim']['sayac']['double_yeni']} | "
              f"doğrulama {r['dogrulama']['ayni']}/{r['dogrulama']['ayni'] + r['dogrulama']['farkli']}",
              flush=True)
    ozet = toplam(sonuc)
    kunye = {"arac": ARAC, "kosu": str(kosu), "etiket": arg.etiket, "agac": str(DEPO),
             "ikili": len(sonuc)}
    try:
        import subprocess
        kunye["commit"] = subprocess.run(["git", "-C", str(DEPO), "rev-parse", "HEAD"],
                                         capture_output=True, text=True).stdout.strip()
        kunye["kirli"] = subprocess.run(["git", "-C", str(DEPO), "status", "--porcelain",
                                         "karadul"], capture_output=True, text=True).stdout.split("\n")
        kunye["kirli"] = [k for k in kunye["kirli"] if k.strip()]
    except OSError:
        pass
    (kok / "ozet.json").write_text(json.dumps({"kunye": kunye, "toplam": ozet,
                                               "ikililer": sonuc}, ensure_ascii=False, indent=1),
                                   encoding="utf-8")
    print(json.dumps(ozet, ensure_ascii=False, indent=1))
    return 0


def toplam(sonuc: dict) -> dict:
    t: dict = {"ikili": len(sonuc), "yapi": {}, "degisim": {}, "dwarf": {}, "dogrulama": {}}
    for r in sonuc.values():
        for k, v in r["yapi"].items():
            if isinstance(v, int):
                t["yapi"][k] = t["yapi"].get(k, 0) + v
        for k, v in r["degisim"]["sayac"].items():
            t["degisim"][k] = t["degisim"].get(k, 0) + v
        for k in ("ayni", "farkli"):
            t["dogrulama"][k] = t["dogrulama"].get(k, 0) + r["dogrulama"][k]
        d = r["dwarf"]
        if d.get("durum") == "olculdu":
            t["dwarf"]["ikili"] = t["dwarf"].get("ikili", 0) + 1
            for k in ("parametre", "degisen", "kotulesen", "iyilesen", "degisen_cikarim",
                      "kotulesen_cikarim", "iyilesen_cikarim", "fonksiyon_yok", "imza_uyusmadi"):
                t["dwarf"][k] = t["dwarf"].get(k, 0) + d[k]
            for taraf in ("ghidra", "karadul"):
                for h, v in d[taraf].items():
                    t["dwarf"][f"{taraf}_{h}"] = t["dwarf"].get(f"{taraf}_{h}", 0) + v
    dw = t["dwarf"]
    if dw.get("degisen"):
        dw["kotulesen_orani"] = round(dw["kotulesen"] / dw["degisen"], 4)
    if dw.get("degisen_cikarim"):
        dw["kotulesen_cikarim_orani"] = round(dw["kotulesen_cikarim"] / dw["degisen_cikarim"], 4)
    return t


def karsilastir(arg: argparse.Namespace) -> int:
    kok = Path(arg.kok).expanduser()
    a = json.loads((kok / arg.once / "ozet.json").read_text(encoding="utf-8"))["toplam"]
    b = json.loads((kok / arg.sonra / "ozet.json").read_text(encoding="utf-8"))["toplam"]
    print(f"| ölçü | {arg.once} | {arg.sonra} |\n|---|---|---|")
    for bolum in ("yapi", "degisim", "dwarf", "dogrulama"):
        for k in sorted(set(a.get(bolum, {})) | set(b.get(bolum, {}))):
            print(f"| {bolum}.{k} | {a.get(bolum, {}).get(k, '—')} | {b.get(bolum, {}).get(k, '—')} |")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    alt = ap.add_subparsers(dest="komut", required=True)
    k = alt.add_parser("kos")
    k.add_argument("--kosu", required=True)
    k.add_argument("--kok", required=True)
    k.add_argument("--etiket", required=True)
    k.add_argument("--yalniz", default="")
    k.add_argument("--hizalama", default="~/karadul_olcum/runs/t0b-1acba60/hizalama")
    k.add_argument("--sakla", action="store_true")
    c = alt.add_parser("karsilastir")
    c.add_argument("--kok", required=True)
    c.add_argument("--once", required=True)
    c.add_argument("--sonra", required=True)
    arg = ap.parse_args(argv)
    sys.path.insert(0, str(DEPO))
    return kos(arg) if arg.komut == "kos" else karsilastir(arg)


if __name__ == "__main__":
    raise SystemExit(main())
