#!/usr/bin/env python3
"""GK-0: bugünkü çıktının derlenebilirlik ölçümü (geri kurma hattı, A-41).

Bir Karadul çıktı projesindeki (``out/src``) her ``.c`` dosyasını
``clang -fsyntax-only`` ile dener ve sayar. Hiçbir şey çalıştırılmaz;
``-fsyntax-only`` nesne dosyası da üretmez. Girdi kökleri salt okunur;
bütün çıktı ``--cikti`` altına yazılır.

Sayılanlar
----------
* dosya düzeyi: hatasız geçen ``.c`` dosyası (iki kip, aşağıda);
* işlev düzeyi: (a) hatasız dosyadaki işlevler, (b) kendi satır aralığında
  hata bulunmayan işlevler (başlıktan gelen hatalar ayrı sayılır);
* hata sınıfları: derleyicinin iletisinden mekanik türetilir (tırnak içi
  adlar ve sayılar silinir = ``kalip``), ayrıca kaba sınıf (``sinif``) ve
  tanımsız adlarda ad ailesi (``DAT_``, ``FUN_``, Ghidra işleci, …);
* hatanın yeri: ``.c`` dosyasının kendisi mi, projenin başlığı mı;
* basamak B0 için: derleyicinin "Parse Issue" / "Lexical or Preprocessor
  Issue" kategorisinde hatası olmayan dosya.

Kipler
------
``K`` (katı): ``clang -std=c11 -I<proje>/include`` — derleyicinin öntanımlı
hata kümesi (C99 sonrası hataya yükseltilmiş uyarılar dahil).
``G`` (gevşek; türetilmiş): ``K`` koşusunda ``[-W…]`` etiketi taşıyan
hatalar (hataya yükseltilmiş uyarılar: örtük işlev bildirimi, tamsayı /
işaretçi dönüşümü …) sayılmaz. ``-Wno-error=…`` ile derlemenin karşılığıdır;
ayrı koşu değildir.
Projenin kendi ``Makefile`` / ``CMakeLists`` dosyası ``-w`` kullanır;
``--dogrula-w`` verilirse her dosya gerçekten ``-w`` ile de derlenir ve
hükmün ``K`` ile aynı olup olmadığı sayılır (bu clang sürümünde ``-w``
hataya yükseltilmiş uyarıları susturmuyor: ölçüldü, varsayılmadı).

``--onsoz`` (karşı olgu kipi): projenin ``types.h`` başlığı ``-D_TYPES_H_``
ile devre dışı bırakılır, yerine yalnız Ghidra'nın temel tip adlarını
tanımlayan küçük bir önsöz (``ONSOZ_METNI``) ``-include`` ile verilir.
"Başlık onarılsa gövdeler ne durumda" sorusunun ölçümüdür; ürün çıktısının
derlenebilirliği DEĞİLDİR ve ayrı adla raporlanır.

İşlev sınırı sezgiseldir: yorumlar ve dizgiler atıldıktan sonra üst düzeyde
``)`` ardından açılan küme ayracı bir işlev gövdesi sayılır.

Örneklem ve süre sınırı: dosyalar tohumla belirlenimci karıştırılır; süre
sınırı dolarsa işlenen önek rastgele örneklemdir ve sayısı raporlanır.

Örnek::

    python scripts/arge/gerikurma/derlenebilirlik.py \
        --kok debian/cat=<...>/cat/out/src --cikti <GK0>/k_kipi --is 4
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import datetime
import hashlib
import json
import os
import random
import re
import subprocess
import sys
import time
from pathlib import Path

C_DERLEYICISI = "/usr/bin/clang"
TEMEL_BAYRAKLAR = ["-fsyntax-only", "-std=c11"]
TANI_BAYRAKLARI = [
    "-ferror-limit=0",
    "-fno-color-diagnostics",
    "-fno-caret-diagnostics",
    "-fno-diagnostics-fixit-info",
    "-fdiagnostics-show-category=name",
]
#: Bir dosyadan saklanan en çok hata kaydı (sayım hepsini kapsar).
DOSYA_BASINA_SAKLANAN = 400
ONTANIM_IS = 4
ONTANIM_TOHUM = 20261124
ONTANIM_DOSYA_ZAMAN_ASIMI_SN = 60
#: types.h'nin başlık koruması (``--onsoz`` bununla başlığı devre dışı bırakır).
TYPES_H_KORUMASI = "_TYPES_H_"
#: ``--onsoz`` kipinin önsözü: yalnız Ghidra'nın temel tip adları. Kurtarılmış
#: hiçbir tip, hiçbir işlev bildirimi, hiçbir p-code işleci içermez.
ONSOZ_METNI = """\
/* GK-0 karşı olgu önsözü: derlenebilirlik.py --onsoz üretir. */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
typedef uint8_t undefined; typedef uint8_t undefined1; typedef uint16_t undefined2;
typedef uint32_t undefined3; typedef uint32_t undefined4; typedef uint64_t undefined5;
typedef uint64_t undefined6; typedef uint64_t undefined7; typedef uint64_t undefined8;
typedef void (*code)(void);
typedef intptr_t addr; typedef uintptr_t uaddr;
typedef uint8_t byte; typedef int8_t sbyte; typedef uint8_t uchar;
typedef uint16_t word; typedef int16_t sword; typedef uint16_t ushort;
typedef uint32_t dword; typedef int32_t sdword; typedef uint32_t uint;
typedef uint64_t qword; typedef int64_t sqword; typedef unsigned long ulong;
typedef long long longlong; typedef unsigned long long ulonglong;
typedef float float4; typedef double float8; typedef long double float10;
typedef int32_t int3; typedef uint32_t uint3; typedef int64_t int5; typedef uint64_t uint5;
typedef int64_t int6; typedef uint64_t uint6; typedef int64_t int7; typedef uint64_t uint7;
typedef __int128 int16; typedef unsigned __int128 uint16;
typedef void *pointer;
"""

_TANI = re.compile(
    r"^(?P<yol>.+?):(?P<satir>\d+):(?P<sutun>\d+): "
    r"(?P<tur>fatal error|error|warning|note): (?P<ileti>.*)$"
)
_YOLSUZ_TANI = re.compile(r"^(?:clang: )?(?P<tur>fatal error|error): (?P<ileti>.*)$")
_KUYRUK = re.compile(r"\s\[([^\[\]]+)\]$")
_TIRNAK = re.compile(r"'[^']*'")
_SAYI = re.compile(r"\b\d+\b")

# Kaba sınıflar: (ad, düzenli ifade). İlk eşleşen kazanır; sıra önemlidir.
_SINIFLAR: list[tuple[str, re.Pattern[str]]] = [
    ("onislemci_dosya_yok", re.compile(r"file not found")),
    ("eksik_bildirim_islev", re.compile(
        r"call to undeclared (library )?function|implicit declaration of function"
        r"|implicitly declaring library function")),
    ("eksik_bildirim_tanimlayici", re.compile(r"use of undeclared identifier|undeclared label")),
    ("bilinmeyen_tip_adi", re.compile(r"unknown type name|must use '(struct|union|enum)' tag")),
    ("tip_celiskisi_bildirim", re.compile(
        r"conflicting types for|redefinition of .* with a different type"
        r"|redefinition with different types|redeclared as different kind"
        r"|redefinition of .* as different kind|different kind of symbol"
        r"|static declaration of .* follows non-static|non-static declaration of .* follows static")),
    ("yeniden_tanim", re.compile(r"redefinition of|duplicate member|duplicate case")),
    ("tamamlanmamis_tip", re.compile(
        r"incomplete (type|definition of type)|has incomplete type"
        r"|incomplete result type|sizeof.* to an incomplete type|tentative definition has type")),
    ("uye_yok", re.compile(r"no member named")),
    ("uye_erisimi_tip", re.compile(
        r"member reference (base )?type|is not a (structure or union|pointer)"
        r"|subscripted value|indirection requires pointer|cannot take the address")),
    ("cagri_tip", re.compile(
        r"too (many|few) arguments|called object type|passing .* to parameter"
        r"|incompatible function pointer")),
    ("deger_tip_uyusmazligi", re.compile(
        r"incompatible|invalid operands|assigning to|initializing|returning"
        r"|cannot be (cast|converted|assigned)|used type|not assignable"
        r"|pointer cannot be cast|arithmetic on|operand of type|array type"
        r"|void function .* should not return|non-void function .* should return"
        r"|expression is not|is not a constant|not an integer constant"
        r"|statement requires expression of|variable-sized object")),
    ("ortuk_int", re.compile(r"type specifier missing|defaults to 'int'|implicit int")),
    ("sozdizimi_beklenen", re.compile(r"^expected |^extraneous |^unexpected ")),
    ("gecersiz_bildirim", re.compile(
        r"cannot combine with previous|declaration of|a parameter list without types"
        r"|function cannot return|array has|field has|illegal|invalid|not allowed")),
]

# Tanımsız ad aileleri (tırnak içindeki ilk ada bakılır). Sıra önemlidir.
_AD_AILELERI: list[tuple[str, re.Pattern[str]]] = [
    ("ghidra_pcode_isleci", re.compile(
        r"^(CONCAT\d+|SUB\d+|ZEXT\d+|SEXT\d+|CARRY\d+|SCARRY\d+|SBORROW\d+|LZCOUNT|POPCOUNT"
        r"|NAN|ABS|SQRT|ROUND|CEIL|FLOOR|TRUNC|FLOAT2FLOAT|INT2FLOAT|CONCAT|SUB|ZEXT|SEXT)$")),
    ("ghidra_undefined_tipi", re.compile(r"^(undefined\d*|code|byte|word|dword|qword|uint|ulong|ushort|uchar|longlong|ulonglong|bool\d|float\d+|int\d+|uint\d+)$")),
    ("ghidra_DAT_PTR", re.compile(r"^(DAT_|PTR_|_DAT_|UNK_|s_[A-Za-z0-9_]*_[0-9a-fA-F]{6,}$)")),
    ("ghidra_LAB_switch", re.compile(r"^(LAB_|switchD_|caseD_|joined_r0x|code_r0x|UNRECOVERED_JUMPTABLE)")),
    ("ghidra_FUN_thunk", re.compile(r"^(FUN_|thunk_|_?func_0x|SUB_)")),
    ("ghidra_yazmac_degiskeni", re.compile(
        r"^(in_|unaff_|extraout_|register0x|tpidr|[xwvqdsb]\d{1,2}$|sp$|pc$|lr$)")),
    ("ghidra_yigin_degiskeni", re.compile(r"^(local_|param_\d|[a-z]{1,3}Stack_|[a-z]{1,3}Var\d|auStack|stack0x)")),
    ("objc_cxx_adi", re.compile(r"^(_?objc_|_OBJC_|__Z|_Z[A-Z0-9]|__swift|_\$s|\$s)")),
]


def _kalip(ileti: str) -> str:
    """İletiyi ad ve sayıdan arındır: mekanik hata kalıbı."""
    return _SAYI.sub("N", _TIRNAK.sub("'…'", ileti))


def _sinif(ileti: str, kategori: str) -> str:
    for ad, desen in _SINIFLAR:
        if desen.search(ileti):
            return ad
    if kategori == "Parse Issue":
        return "sozdizimi_diger"
    if kategori == "Lexical or Preprocessor Issue":
        return "onislemci_diger"
    return "diger_anlamsal"


def _ad_ailesi(ileti: str) -> str:
    m = _TIRNAK.search(ileti)
    if not m:
        return "adsiz"
    ad = m.group(0)[1:-1].split(" ")[-1].lstrip("*&")
    for aile, desen in _AD_AILELERI:
        if desen.search(ad):
            return aile
    return "diger_ad"


def islev_araliklari(metin: str) -> list[tuple[int, int]]:
    """Üst düzey işlev gövdelerinin (başlangıç, bitiş) satır aralıkları (1 tabanlı).

    Sezgisel: yorum, dizgi ve karakter sabitleri atlanır; derinlik 0'da ``)``
    ardından gelen ``{`` bir işlev gövdesi açar. Başlangıç, bir önceki üst
    düzey ``;`` ya da ``}``'den sonraki ilk dolu satırdır.
    """
    araliklar: list[tuple[int, int]] = []
    i, n = 0, len(metin)
    satir = 1
    derinlik = 0
    onceki = ""  # derinlik 0'daki son boşluk olmayan karakter
    bildirim_basi: int | None = None
    acik: int | None = None
    satir_basi = True
    while i < n:
        c = metin[i]
        if c == "\n":
            satir += 1
            satir_basi = True
            i += 1
            continue
        if c in " \t\r":
            i += 1
            continue
        if satir_basi and c == "#":  # önişlemci satırı (devam satırlarıyla)
            while i < n and metin[i] != "\n":
                if metin[i] == "\\" and i + 1 < n and metin[i + 1] == "\n":
                    satir += 1
                    i += 1
                i += 1
            continue
        satir_basi = False
        if c == "/" and i + 1 < n and metin[i + 1] == "/":
            while i < n and metin[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and metin[i + 1] == "*":
            j = metin.find("*/", i + 2)
            j = n - 2 if j < 0 else j
            satir += metin.count("\n", i, j + 2)
            i = j + 2
            continue
        if c in "\"'":
            j = i + 1
            while j < n and metin[j] != c:
                if metin[j] == "\\":
                    j += 1
                elif metin[j] == "\n":
                    break
                j += 1
            i = j + 1
            if derinlik == 0:
                onceki = c
            continue
        if derinlik == 0 and bildirim_basi is None:
            bildirim_basi = satir
        if c == "{":
            if derinlik == 0 and onceki == ")":
                acik = bildirim_basi if bildirim_basi is not None else satir
            derinlik += 1
        elif c == "}":
            derinlik = max(0, derinlik - 1)
            if derinlik == 0:
                if acik is not None:
                    araliklar.append((acik, satir))
                    acik = None
                bildirim_basi = None
                onceki = "}"
                i += 1
                continue
        elif c == ";" and derinlik == 0:
            bildirim_basi = None
            onceki = ";"
            i += 1
            continue
        if derinlik == 0:
            onceki = c
        i += 1
    return araliklar


def _clang(dosya: Path, proje: Path, ek: list[str], zaman_asimi: int) -> tuple[int | None, str, float]:
    komut = [C_DERLEYICISI, *TEMEL_BAYRAKLAR, f"-I{proje / 'include'}", *TANI_BAYRAKLARI, *ek, str(dosya)]
    t0 = time.monotonic()
    try:
        s = subprocess.run(
            komut, cwd=str(proje), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, timeout=zaman_asimi, check=False,
        )
        return s.returncode, s.stderr.decode("utf-8", "replace"), time.monotonic() - t0
    except subprocess.TimeoutExpired:
        return None, "", time.monotonic() - t0


def _tanilari_ayir(cikti: str, dosya: Path, proje: Path) -> list[dict]:
    hatalar: list[dict] = []
    son: dict | None = None
    for satir in cikti.splitlines():
        m = _TANI.match(satir)
        if not m:
            y = _YOLSUZ_TANI.match(satir)
            if y:
                hatalar.append({"yer": "komut", "baslik": "", "satir": 0, "ileti": y["ileti"],
                                "kategori": "", "secenek": "", "sdk_notu": False})
            continue
        tur = m["tur"]
        if tur == "note":
            if son is not None and "/SDKs/" in m["yol"]:
                son["sdk_notu"] = True
            continue
        if tur == "warning":
            son = None
            continue
        ileti = m["ileti"]
        kategori, secenek = "", ""
        k = _KUYRUK.search(ileti)
        if k:
            parcalar = [p.strip() for p in k.group(1).split(",")]
            if any(p.startswith("-W") or p in ("Semantic Issue", "Parse Issue") or "Issue" in p
                   for p in parcalar):
                ileti = ileti[: k.start()]
                for p in parcalar:
                    if p.startswith("-W"):
                        secenek = p
                    else:
                        kategori = p
        yol = Path(m["yol"])
        if not yol.is_absolute():
            yol = proje / yol
        try:
            ayni = yol.resolve() == dosya.resolve()
        except OSError:
            ayni = False
        if ayni:
            yer, baslik = "kendi", ""
        elif "/SDKs/" in str(yol) or "/lib/clang/" in str(yol):
            yer, baslik = "sistem_basligi", yol.name
        else:
            yer, baslik = "proje_basligi", yol.name
        son = {"yer": yer, "baslik": baslik, "satir": int(m["satir"]), "ileti": ileti,
               "kategori": kategori, "secenek": secenek, "sdk_notu": False}
        hatalar.append(son)
    return hatalar


def dosyayi_olc(dosya: Path, proje: Path, ek: list[str], zaman_asimi: int, dogrula_w: bool) -> dict:
    kod, cikti, sure = _clang(dosya, proje, ek, zaman_asimi)
    try:
        metin = dosya.read_text(encoding="utf-8", errors="replace")
    except OSError:
        metin = ""
    araliklar = islev_araliklari(metin)
    kayit: dict = {
        "dosya": str(dosya.relative_to(proje)),
        "satir_sayisi": metin.count("\n") + 1,
        "islev_sayisi": len(araliklar),
        "sure_sn": round(sure, 4),
    }
    if kod is None:
        kayit["durum"] = "zaman_asimi"
        return kayit
    hatalar = _tanilari_ayir(cikti, dosya, proje)
    for h in hatalar:
        h["sinif"] = _sinif(h["ileti"], h["kategori"])
        h["kalip"] = _kalip(h["ileti"])
        if h["sinif"] in ("eksik_bildirim_islev", "eksik_bildirim_tanimlayici", "bilinmeyen_tip_adi"):
            h["aile"] = _ad_ailesi(h["ileti"])
        else:
            h["aile"] = ""
        if h["sdk_notu"]:
            h["sinif"] += "+sdk_cakismasi"
    kati = [h for h in hatalar]
    gevsek = [h for h in hatalar if not h["secenek"]]
    kendi = [h for h in kati if h["yer"] == "kendi"]
    hatali_islev_k = set()
    hatali_islev_g = set()
    for h in kendi:
        for no, (b, s) in enumerate(araliklar):
            if b <= h["satir"] <= s:
                hatali_islev_k.add(no)
                if not h["secenek"]:
                    hatali_islev_g.add(no)
                break
    kayit.update({
        "durum": "tamam",
        "cikis_kodu": kod,
        "hata_K": len(kati),
        "hata_G": len(gevsek),
        "hata_kendi_K": len(kendi),
        "hata_kendi_G": len([h for h in kendi if not h["secenek"]]),
        "hata_baslik_K": len([h for h in kati if h["yer"] != "kendi"]),
        "hata_baslik_G": len([h for h in gevsek if h["yer"] != "kendi"]),
        "ayristirma_hatasi": len([h for h in kati if h["kategori"] in
                                  ("Parse Issue", "Lexical or Preprocessor Issue")]),
        "ayristirma_hatasi_kendi": len([h for h in kendi if h["kategori"] in
                                        ("Parse Issue", "Lexical or Preprocessor Issue")]),
        "govdesi_temiz_islev_K": len(araliklar) - len(hatali_islev_k),
        "govdesi_temiz_islev_G": len(araliklar) - len(hatali_islev_g),
        "hatalar": [
            {a: h[a] for a in ("yer", "baslik", "satir", "sinif", "aile", "kalip", "kategori", "secenek")}
            for h in kati[:DOSYA_BASINA_SAKLANAN]
        ],
        "sayim": dict(collections.Counter(
            (h["yer"], h["sinif"], h["aile"], bool(h["secenek"])) .__repr__() for h in kati)),
    })
    if dogrula_w:
        kod_w, cikti_w, _ = _clang(dosya, proje, [*ek, "-w"], zaman_asimi)
        kayit["gercek_w_hata"] = None if kod_w is None else len(_tanilari_ayir(cikti_w, dosya, proje))
    return kayit


def _oran(pay: int, payda: int) -> str:
    return "—" if payda == 0 else f"{100.0 * pay / payda:.1f}"


def koku_olc(etiket: str, proje: Path, cikti: Path, args: argparse.Namespace, bitis: float | None) -> dict:
    dosyalar = sorted((proje / "src").rglob("*.c")) if (proje / "src").is_dir() else sorted(proje.rglob("*.c"))
    toplam = len(dosyalar)
    sira = list(dosyalar)
    random.Random(f"{args.tohum}:{etiket}").shuffle(sira)
    if args.orneklem and args.orneklem < len(sira):
        sira = sira[: args.orneklem]
    kok_cikti = cikti / etiket.replace("/", "__")
    kok_cikti.mkdir(parents=True, exist_ok=True)
    kayitlar: list[dict] = []
    t0 = time.monotonic()
    atlanan = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.is_sayisi) as havuz:
        bekleyen = []
        for d in sira:
            bekleyen.append(havuz.submit(_sinirli, d, proje, args, bitis))
        for f in bekleyen:
            k = f.result()
            if k is None:
                atlanan += 1
            else:
                kayitlar.append(k)
    sure = time.monotonic() - t0
    with (kok_cikti / "dosyalar.jsonl").open("w", encoding="utf-8") as fh:
        for k in kayitlar:
            fh.write(json.dumps(k, ensure_ascii=False) + "\n")
    ozet = _ozetle(etiket, proje, toplam, len(sira), atlanan, kayitlar, sure, args)
    (kok_cikti / "ozet.json").write_text(json.dumps(ozet, ensure_ascii=False, indent=1), encoding="utf-8")
    return ozet


def _sinirli(d: Path, proje: Path, args: argparse.Namespace, bitis: float | None) -> dict | None:
    if bitis is not None and time.monotonic() > bitis:
        return None
    return dosyayi_olc(d, proje, args.ek_bayrak, args.dosya_zaman_asimi, args.dogrula_w)


def _ozetle(etiket: str, proje: Path, toplam: int, secilen: int, atlanan: int,
            kayitlar: list[dict], sure: float, args: argparse.Namespace) -> dict:
    tamam = [k for k in kayitlar if k["durum"] == "tamam"]
    n = len(tamam)
    islev = sum(k["islev_sayisi"] for k in tamam)
    sinif_hata: collections.Counter = collections.Counter()
    sinif_dosya: collections.Counter = collections.Counter()
    sinif_ilk: collections.Counter = collections.Counter()
    kalip_hata: collections.Counter = collections.Counter()
    kalip_dosya: collections.Counter = collections.Counter()
    yer_hata: collections.Counter = collections.Counter()
    baslik_hata: collections.Counter = collections.Counter()
    kesik = 0
    for k in tamam:
        gorulen_sinif, gorulen_kalip = set(), set()
        if k["hata_K"] > len(k["hatalar"]):
            kesik += 1
        for sira, h in enumerate(k["hatalar"]):
            anahtar = h["sinif"] + (f"[{h['aile']}]" if h["aile"] else "")
            anahtar = f"{h['yer']}:{anahtar}"
            sinif_hata[anahtar] += 1
            kalip_hata[(h["yer"], h["kalip"])] += 1
            yer_hata[h["yer"]] += 1
            if h["yer"] != "kendi":
                baslik_hata[_baslik_sinifi(h["baslik"])] += 1
            gorulen_sinif.add(anahtar)
            gorulen_kalip.add((h["yer"], h["kalip"]))
            if sira == 0:
                sinif_ilk[anahtar] += 1
        for a in gorulen_sinif:
            sinif_dosya[a] += 1
        for a in gorulen_kalip:
            kalip_dosya[a] += 1
    ozet = {
        "etiket": etiket,
        "proje": str(proje),
        "c_dosyasi_toplam": toplam,
        "secilen": secilen,
        "olculen": n,
        "sure_sinirinda_atlanan": atlanan,
        "zaman_asimi": len([k for k in kayitlar if k["durum"] == "zaman_asimi"]),
        "sure_sn": round(sure, 1),
        "islev_toplam": islev,
        "dosya_gecen_K": sum(1 for k in tamam if k["hata_K"] == 0),
        "dosya_gecen_G": sum(1 for k in tamam if k["hata_G"] == 0),
        "dosya_kendi_hatasiz_K": sum(1 for k in tamam if k["hata_kendi_K"] == 0),
        "dosya_kendi_hatasiz_G": sum(1 for k in tamam if k["hata_kendi_G"] == 0),
        "dosya_baslik_hatasiz_K": sum(1 for k in tamam if k["hata_baslik_K"] == 0),
        "dosya_baslik_hatasiz_G": sum(1 for k in tamam if k["hata_baslik_G"] == 0),
        "dosya_ayristirma_hatasiz": sum(1 for k in tamam if k["ayristirma_hatasi"] == 0),
        "dosya_ayristirma_hatasiz_kendi": sum(1 for k in tamam if k["ayristirma_hatasi_kendi"] == 0),
        "islev_dosyasi_gecen_K": sum(k["islev_sayisi"] for k in tamam if k["hata_K"] == 0),
        "islev_dosyasi_gecen_G": sum(k["islev_sayisi"] for k in tamam if k["hata_G"] == 0),
        "islev_govdesi_temiz_K": sum(k["govdesi_temiz_islev_K"] for k in tamam),
        "islev_govdesi_temiz_G": sum(k["govdesi_temiz_islev_G"] for k in tamam),
        "hata_toplam_K": sum(k["hata_K"] for k in tamam),
        "hata_toplam_G": sum(k["hata_G"] for k in tamam),
        "hata_kendi_K": sum(k["hata_kendi_K"] for k in tamam),
        "hata_baslik_K": sum(k["hata_baslik_K"] for k in tamam),
        "hata_listesi_kesilen_dosya": kesik,
        "yer_hata": dict(yer_hata),
        "baslik_hata": dict(baslik_hata.most_common(12)),
        "sinif": [
            {"sinif": a, "hata": c, "dosya": sinif_dosya[a], "ilk_hata_oldugu_dosya": sinif_ilk[a]}
            for a, c in sinif_hata.most_common(40)
        ],
        "kalip": [
            {"yer": a[0], "kalip": a[1], "hata": c, "dosya": kalip_dosya[a]}
            for a, c in kalip_hata.most_common(40)
        ],
    }
    if args.dogrula_w:
        olc = [k for k in tamam if k.get("gercek_w_hata") is not None]
        ozet["dogrula_w"] = {
            "karsilastirilan": len(olc),
            "gecme_hukmu_ayni": sum(1 for k in olc if (k["hata_K"] == 0) == (k["gercek_w_hata"] == 0)),
            "hata_sayisi_ayni": sum(1 for k in olc if k["hata_K"] == k["gercek_w_hata"]),
            "gercek_w_gecen": sum(1 for k in olc if k["gercek_w_hata"] == 0),
        }
    return ozet


def _baslik_sinifi(ad: str) -> str:
    if ad == "types.h":
        return "types.h"
    if ad.startswith("subsystem_") or ad == "import_thunks.h":
        return "alt sistem başlığı"
    return "öbür başlık"


def _md(ozetler: list[dict], kunye: dict) -> str:
    s: list[str] = []
    s.append("# GK-0 derlenebilirlik ölçümü\n")
    s.append(f"Üretildi: {kunye['bitis']} · derleyici: `{kunye['clang_surumu']}` · "
             f"ek bayrak: `{' '.join(kunye['ek_bayrak']) or '—'}` · tohum {kunye['tohum']} · "
             f"eşzamanlı iş {kunye['is']}\n")
    s.append("K = derleyicinin öntanımlı hata kümesi; G = gevşek (K koşusunda `[-W…]` etiketli, "
             "yani hataya yükseltilmiş uyarı olan hatalar sayılmaz; türetilmiş). "
             "Oranlar ölçülen dosya / işlev üstünden, yüzde.\n")
    if kunye.get("onsoz"):
        s.append("**KARŞI OLGU KİPİ (`--onsoz`):** projenin `types.h` başlığı devre dışı, yerine yalnız "
                 "Ghidra temel tip önsözü. Bu tablo ürün çıktısının derlenebilirliği değildir.\n")
    s.append("| Çıktı | .c (ölçülen / toplam) | işlev | dosya geçer K | dosya geçer G | "
             "kendi satırlarında hatasız K | G | ayrıştırma hatasız (B0) | kendi satırlarında B0 | "
             "işlev: dosyası geçer K | G | işlev: gövdesi temiz K | G | hata K | başlıkta |")
    s.append("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for o in ozetler:
        n, f = o["olculen"], o["islev_toplam"]
        s.append(
            f"| {o['etiket']} | {n} / {o['c_dosyasi_toplam']} | {f} | "
            f"{o['dosya_gecen_K']} (%{_oran(o['dosya_gecen_K'], n)}) | "
            f"{o['dosya_gecen_G']} (%{_oran(o['dosya_gecen_G'], n)}) | "
            f"{o['dosya_kendi_hatasiz_K']} (%{_oran(o['dosya_kendi_hatasiz_K'], n)}) | "
            f"{o['dosya_kendi_hatasiz_G']} (%{_oran(o['dosya_kendi_hatasiz_G'], n)}) | "
            f"{o['dosya_ayristirma_hatasiz']} (%{_oran(o['dosya_ayristirma_hatasiz'], n)}) | "
            f"{o['dosya_ayristirma_hatasiz_kendi']} (%{_oran(o['dosya_ayristirma_hatasiz_kendi'], n)}) | "
            f"{o['islev_dosyasi_gecen_K']} (%{_oran(o['islev_dosyasi_gecen_K'], f)}) | "
            f"{o['islev_dosyasi_gecen_G']} (%{_oran(o['islev_dosyasi_gecen_G'], f)}) | "
            f"{o['islev_govdesi_temiz_K']} (%{_oran(o['islev_govdesi_temiz_K'], f)}) | "
            f"{o['islev_govdesi_temiz_G']} (%{_oran(o['islev_govdesi_temiz_G'], f)}) | "
            f"{o['hata_toplam_K']} | {o['hata_baslik_K']} (%{_oran(o['hata_baslik_K'], o['hata_toplam_K'])}) |"
        )
    for o in ozetler:
        s.append(f"\n## {o['etiket']}\n")
        s.append(f"Süre {o['sure_sn']} sn; süre sınırında atlanan {o['sure_sinirinda_atlanan']}; "
                 f"dosya zaman aşımı {o['zaman_asimi']}; hata listesi kesilen dosya "
                 f"{o['hata_listesi_kesilen_dosya']} (dosya başına en çok {DOSYA_BASINA_SAKLANAN} kayıt "
                 "sınıflanır).\n")
        if "dogrula_w" in o:
            d = o["dogrula_w"]
            s.append(f"`-w` doğrulaması: {d['karsilastirilan']} dosyada gerçek `-w` koşusu; geçme hükmü K ile "
                     f"aynı {d['gecme_hukmu_ayni']}, hata sayısı K ile aynı {d['hata_sayisi_ayni']}, "
                     f"gerçek `-w` ile geçen {d['gercek_w_gecen']}.\n")
        s.append(f"Başlık kaynaklı hataların dağılımı: {json.dumps(o['baslik_hata'], ensure_ascii=False)}\n")
        s.append("| Sıra | Sınıf (yer:sınıf[ad ailesi]) | hata | pay % | görüldüğü dosya | dosya % | ilk hata olduğu dosya |")
        s.append("|---|---|---|---|---|---|---|")
        siniflanan = sum(x["hata"] for x in o["sinif"]) or 1
        for i, x in enumerate(o["sinif"][:20], 1):
            s.append(f"| {i} | `{x['sinif']}` | {x['hata']} | {_oran(x['hata'], siniflanan)} | "
                     f"{x['dosya']} | {_oran(x['dosya'], o['olculen'])} | {x['ilk_hata_oldugu_dosya']} |")
        s.append("\nEn sık 12 derleyici ileti kalıbı (adlar ve sayılar silinmiş):\n")
        s.append("| yer | kalıp | hata | dosya |")
        s.append("|---|---|---|---|")
        for x in o["kalip"][:12]:
            s.append(f"| {x['yer']} | `{x['kalip'][:150]}` | {x['hata']} | {x['dosya']} |")
    return "\n".join(s) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--kok", action="append", required=True, metavar="ETİKET=YOL",
                    help="çıktı projesi kökü (içinde src/ ve include/); yinelenebilir")
    ap.add_argument("--cikti", required=True, type=Path, help="çıktı dizini (girdi köklerine yazılmaz)")
    ap.add_argument("--is", dest="is_sayisi", type=int, default=ONTANIM_IS, help="eşzamanlı clang sayısı")
    ap.add_argument("--orneklem", type=int, default=0, help="kök başına en çok dosya (0 = hepsi)")
    ap.add_argument("--tohum", type=int, default=ONTANIM_TOHUM)
    ap.add_argument("--sure-siniri", type=int, default=0, help="toplam süre sınırı, sn (0 = yok)")
    ap.add_argument("--dosya-zaman-asimi", type=int, default=ONTANIM_DOSYA_ZAMAN_ASIMI_SN)
    ap.add_argument("--ek-bayrak", action="append", default=[], help="clang'a eklenecek bayrak; yinelenebilir")
    ap.add_argument("--dogrula-w", action="store_true", help="her dosyayı gerçekten -w ile de derle; hükmü K ile karşılaştır")
    ap.add_argument("--onsoz", action="store_true",
                    help="karşı olgu kipi: types.h devre dışı, yerine Ghidra temel tip önsözü")
    ap.add_argument("--ad", default="derlenebilirlik", help="özet dosyalarının adı")
    args = ap.parse_args()

    cikti: Path = args.cikti.expanduser().resolve()
    kokler: list[tuple[str, Path]] = []
    for k in args.kok:
        etiket, _, yol = k.partition("=")
        p = Path(yol).expanduser().resolve()
        if not p.is_dir():
            print(f"kök yok: {p}", file=sys.stderr)
            return 2
        if cikti == p or p in cikti.parents:
            print(f"çıktı dizini girdi kökünün içinde olamaz: {cikti}", file=sys.stderr)
            return 2
        kokler.append((etiket, p))
    cikti.mkdir(parents=True, exist_ok=True)
    (cikti / "ozet").mkdir(exist_ok=True)
    if args.onsoz:
        onsoz = cikti / "onsoz" / "gk0_onsoz.h"
        onsoz.parent.mkdir(exist_ok=True)
        onsoz.write_text(ONSOZ_METNI, encoding="utf-8")
        args.ek_bayrak = [*args.ek_bayrak, f"-D{TYPES_H_KORUMASI}", "-include", str(onsoz)]
    surum = subprocess.run([C_DERLEYICISI, "--version"], capture_output=True, text=True, check=False).stdout.splitlines()
    baslangic = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
    bitis = time.monotonic() + args.sure_siniri if args.sure_siniri else None
    ozetler = []
    for etiket, p in kokler:
        print(f"[{datetime.datetime.now():%H:%M:%S}] {etiket}: {p}", flush=True)
        o = koku_olc(etiket, p, cikti, args, bitis)
        print(f"    ölçülen {o['olculen']} / {o['c_dosyasi_toplam']}; geçen K {o['dosya_gecen_K']}, "
              f"G {o['dosya_gecen_G']}; {o['sure_sn']} sn", flush=True)
        ozetler.append(o)
    kunye = {
        "betik": str(Path(__file__).resolve()),
        "betik_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "clang": C_DERLEYICISI,
        "clang_surumu": surum[0] if surum else "?",
        "clang_hedef": surum[1] if len(surum) > 1 else "?",
        "temel_bayraklar": TEMEL_BAYRAKLAR,
        "tani_bayraklari": TANI_BAYRAKLARI,
        "ek_bayrak": args.ek_bayrak,
        "is": args.is_sayisi,
        "tohum": args.tohum,
        "orneklem": args.orneklem,
        "sure_siniri_sn": args.sure_siniri,
        "dogrula_w": args.dogrula_w,
        "onsoz": args.onsoz,
        "baslangic": baslangic,
        "bitis": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "kokler": {e: str(p) for e, p in kokler},
        "pid": os.getpid(),
    }
    (cikti / "ozet" / f"{args.ad}.json").write_text(
        json.dumps({"kunye": kunye, "ozetler": ozetler}, ensure_ascii=False, indent=1), encoding="utf-8")
    (cikti / "ozet" / f"{args.ad}.md").write_text(_md(ozetler, kunye), encoding="utf-8")
    print(f"özet: {cikti / 'ozet' / (args.ad + '.md')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
