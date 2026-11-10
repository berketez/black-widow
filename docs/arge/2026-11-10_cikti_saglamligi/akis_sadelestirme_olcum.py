#!/usr/bin/env python3
"""Akış sadeleştirme (c_flow_simplifier) önce/sonra ölçümü.

Ne ölçer
--------
Geliştirme setinin (117 Debian ELF + 2 Mach-O) Ghidra decompile
dosyalarının her birinde ``CFlowSimplifier._simplify_content`` bellekte
çalıştırılır; hiçbir dosya yazılmaz. İki sürüm karşılaştırılır:

* ``once``  — onarımdan önceki kod (``git show <ONCE_COMMIT>:…``).
* ``sonra`` — çalışma ağacındaki kod.

İki girdi kümesi:

* ``ham``    — ``static/ghidra_output/decompiled`` (Ghidra'nın ham çıktısı).
* ``struct`` — ``reconstructed/struct_recovered`` (akış sadeleştirmeden
  önce saklanan son aşama; Ghidra uyarı yorumları silinmiş, adlar
  değişmiş). Hattaki gerçek girdiye en yakın saklı metin budur.

Her fonksiyon için üç ayrı hüküm:

1. **Denetçinin ölçütü** (``denetle.py``, 2026-11-10 çıktı sağlamlığı
   denetimi; yardımcıları içe aktarılır, K4 döngüsündeki akış ölçütleri
   ``denetci_olcutu`` içinde birebir yinelenir): ayraç/parantez bozuk;
   akış anlamı değişen (ihtiyatlı ve üst sınır); birleşik.
2. **Bağımsız ard koşul** (``_postcondition_violation``): denge,
   ayrıştırma, etiket, goto, çağrı kaybı, return kümesi, denetim akış
   grafı eşdeğerliği.
3. (yalnız ``sonra``) ürünün kendi sayaçları: ard koşul yüzünden özgün
   metne dönen ve ayrıştırılamadığı için atlanan fonksiyon.

``once`` için ayrıca her geçiş tek başına çalıştırılıp bozulmalar dönüşüm
türüne ve kök nedene göre sınıflanır.

Çıktı ad içermez: yalnız sayılar (program ve boyut tabakası başına).

Kullanım (worktree kökünden)::

    python docs/arge/2026-11-10_cikti_saglamligi/akis_sadelestirme_olcum.py \
        --is 6 --cikti docs/arge/2026-11-10_cikti_saglamligi/akis_sadelestirme_olcum.json

GT ve kilitli veri açılmaz; yalnız ``*.c`` decompile dosyaları okunur.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import importlib.util
import json
import multiprocessing
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

BETIK_DIZINI = os.path.dirname(os.path.abspath(__file__))
DEPO = os.path.abspath(os.path.join(BETIK_DIZINI, "..", "..", ".."))
MODUL_YOLU = "karadul/reconstruction/c_flow_simplifier.py"
ONCE_COMMIT = "4fba538"          # onarımdan önceki son commit
DEBIAN_KOK = os.path.expanduser("~/karadul_olcum/n1_debian13")
# Mach-O koşuları ana ağaçta (worktree'de yok); salt okunur
MAC_KOK = "/Users/apple/Black_Widow/workspaces/olcum_mac/runs/ol7-c-b7faeac"
MAC_PROGRAMLAR = ("tmux", "htop")
SINIF_JSON = os.path.join(DEPO, "docs", "arge", "2026-10-21_g11_n1", "ks1_sinif.json")
# Denetçinin betiği: önce bu dizinde, yoksa ana ağaçta aranır
DENETLE_ADAYLARI = (
    os.path.join(BETIK_DIZINI, "denetle.py"),
    "/Users/apple/Black_Widow/docs/arge/2026-11-10_cikti_saglamligi/denetle.py",
)
GIRDI_DIZINLERI = {
    "ham": os.path.join("static", "ghidra_output", "decompiled"),
    "struct": os.path.join("reconstructed", "struct_recovered"),
}
BEKLENEN_IKILI = 119
ORNEK_SINIRI = 40
ESKI_GECISLER = (
    "cascade", "ifelse", "early_return", "break_continue",
    "multi_inline", "single_inline", "rename",
)
# Hüküm "bozuk" sayılmayanlar: eşdeğer ya da girdi yüzünden hükümsüz
IYI_HUKUMLER = ("eşdeğer", "hükümsüz")
RE_YENI_ETIKET = re.compile(
    r"^[ \t]*(cleanup_and_return|error_cleanup|exit_function|error_exit)(?:_\d+)?[ \t]*:",
    re.M)
RE_SATIR_ICI_YORUM = re.compile(
    r"/\* (?:error )?cleanup \(inlined from (LAB_[0-9a-fA-F]+)\) \*/")


# ---------------------------------------------------------------------------
# Modül yükleme
# ---------------------------------------------------------------------------
def modul_yukle(ad: str, yol: str):
    spec = importlib.util.spec_from_file_location(ad, yol)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[ad] = mod
    spec.loader.exec_module(mod)
    return mod


def denetle_yolu() -> str:
    for aday in DENETLE_ADAYLARI:
        if os.path.isfile(aday):
            return aday
    raise SystemExit("denetle.py bulunamadı: " + ", ".join(DENETLE_ADAYLARI))


def once_kaynagi() -> str:
    return subprocess.run(
        ["git", "-C", DEPO, "show", f"{ONCE_COMMIT}:{MODUL_YOLU}"],
        check=True, capture_output=True, text=True).stdout


_D = _ESKI = _YENI = None


def isci_hazirla(eski_yol: str) -> None:
    """Her işçide bir kez: denetçi, eski ve yeni modüller."""
    global _D, _ESKI, _YENI
    _D = modul_yukle("akis_denetle", denetle_yolu())
    _ESKI = modul_yukle("akis_eski_sadelestirici", eski_yol)
    _YENI = modul_yukle("akis_yeni_sadelestirici", os.path.join(DEPO, MODUL_YOLU))


# ---------------------------------------------------------------------------
# Birimler
# ---------------------------------------------------------------------------
def calisma_alani(kok: str):
    wk = os.path.join(kok, "ws", "workspaces")
    adaylar = []
    if os.path.isdir(wk):
        for ad in sorted(os.listdir(wk)):
            d = os.path.join(wk, ad)
            if os.path.isdir(d):
                for zaman in sorted(os.listdir(d)):
                    z = os.path.join(d, zaman)
                    if os.path.isdir(z):
                        adaylar.append(z)
    return adaylar


def birimleri_bul() -> list[dict]:
    with open(SINIF_JSON, encoding="utf-8") as f:
        tabaka = {k: v.get("boyut_tabakasi")
                  for k, v in json.load(f).get("birimler", {}).items()}
    birimler = []
    for program in sorted(os.listdir(DEBIAN_KOK)):
        pd = os.path.join(DEBIAN_KOK, program)
        if not os.path.isdir(pd):
            continue
        for elf in sorted(os.listdir(pd)):
            kd = os.path.join(pd, elf)
            if os.path.isdir(kd):
                birimler.append({"program": f"debian/{program}", "kok": kd,
                                 "tabaka": tabaka.get(f"debian/{program}")})
    for program in MAC_PROGRAMLAR:
        kd = os.path.join(MAC_KOK, program)
        if os.path.isdir(kd):
            birimler.append({"program": f"mac/{program}", "kok": kd,
                             "tabaka": tabaka.get(f"mac/{program}")})
    return birimler


# ---------------------------------------------------------------------------
# Hükümler
# ---------------------------------------------------------------------------
def denetci_olcutu(ham_metin: str, son_metin: str) -> collections.Counter:
    """denetle.py ``kosu_denetle`` K4 döngüsündeki akış ölçütleri.

    Fonksiyonlar adresle eşlenir (``// Address:`` başlığı). Sayaç adları
    denetçinin adlarıdır. Ölçüt değiştirilmedi.
    """
    D = _D
    c = collections.Counter()
    ham = {}
    for blok in D.bloklara_bol(ham_metin):
        k = D.blok_coz(blok, True)
        k["metin"] = blok
        ham.setdefault(k["adres"], k)
    son = {}
    for blok in D.bloklara_bol(son_metin):
        k = D.blok_coz(blok, True)
        k["metin"] = blok
        son.setdefault(k["adres"], k)
    for adres, hk in ham.items():
        c["fonksiyon"] += 1
        if hk["durum"] != "tam" or hk["parantez"] != 0:
            c["ham_bozuk"] += 1
        if hk["goto"]:
            c["ham_goto_iceren_fonksiyon"] += 1
        sk = son.get(adres)
        if sk is None:
            c["son_cikti_yok"] += 1
            continue
        soz_bozuk = sk["durum"] != "tam" or sk["parantez"] != 0
        if soz_bozuk:
            c["soz_bozuk"] += 1
            c["soz_bozuk:" + (sk["durum"] if sk["durum"] != "tam" else "parantez")] += 1
        if sk["cagri"] - hk["cagri"] < 0:
            c["cagri_azalan_fonksiyon"] += 1
            if not soz_bozuk:
                c["cagri_azalan_sozdizimi_saglam"] += 1
        if (sk["noktali"] - sk["goto"]) - (hk["noktali"] - hk["goto"]) < 0:
            c["deyim_azalan_fonksiyon"] += 1
            if not soz_bozuk:
                c["deyim_azalan_sozdizimi_saglam"] += 1
        if hk["dizgiler"] - sk["dizgiler"]:
            c["dizgi_kaybeden_fonksiyon"] += 1
        anlam_bozuk = False
        anlam_ihtiyatli = False
        for etiket in sorted(set(D.RE_SATIR_ICI.findall(sk["metin"]))):
            c["satir_icine_alinan_etiket"] += 1
            hs = hk["kod"].split("\n")
            etiket_satiri = None
            for i, satir in enumerate(hs):
                if re.match(r"^\s*" + re.escape(etiket) + r"\s*:", satir):
                    etiket_satiri = i
                    break
            if etiket_satiri is None:
                continue
            blok_satirlari = []
            for satir in hs[etiket_satiri + 1:]:
                b = satir.strip()
                if not b:
                    continue
                blok_satirlari.append(b)
                if b.startswith(("return ", "break;", "goto ")) or b == "return;":
                    break
            blok_satir = D.ust_duzey_deyim(" ".join(blok_satirlari))
            j = etiket_satiri - 1
            while j >= 0 and not hs[j].strip():
                j -= 1
            onceki = hs[j].strip() if j >= 0 else ""
            atlama = re.match(r"^(goto\s+\w+|return\b[^;]*|break|continue)\s*;$", onceki)
            donmez = any(onceki.startswith(d + "(") for d in D.DONMEYEN)
            if not atlama and not donmez:
                c["dusmeli_etiket_satir_icine_alindi"] += 1
                if etiket + ":" not in sk["kod"]:
                    c["dusmeli_etiket_silindi"] += 1
                    anlam_bozuk = True
                    if onceki.endswith((";", "{")):
                        c["dusmeli_etiket_silindi_ihtiyatli"] += 1
                        anlam_ihtiyatli = True
            if blok_satir >= 2:
                sonda = re.search(
                    r"(?:\)|\belse)[ \t]*\n(?:[ \t]*(?:/\*[^\n]*\*/|//[^\n]*)[ \t]*\n)*?"
                    r"[ \t]*/\* (?:error )?cleanup \(inlined from " + re.escape(etiket) + r"\) \*/",
                    sk["metin"])
                if sonda:
                    c["ayracsiz_kosula_blok_sonda_gorulen"] += 1
                    anlam_ihtiyatli = True
                for satir in hs:
                    b = satir.strip()
                    if re.search(r"\bgoto\s+" + re.escape(etiket) + r"\s*;", b) and not b.startswith("goto"):
                        c["ayracsiz_kosula_blok_gomuldu"] += 1
                        anlam_bozuk = True
        if anlam_bozuk:
            c["akis_anlami_bozulan_fonksiyon"] += 1
        if anlam_ihtiyatli:
            c["akis_anlami_bozulan_fonksiyon_ihtiyatli"] += 1
        if anlam_bozuk or soz_bozuk:
            c["akis_sadelestirmenin_bozdugu_fonksiyon"] += 1
        if anlam_ihtiyatli or soz_bozuk:
            c["akis_sadelestirmenin_bozdugu_fonksiyon_ihtiyatli"] += 1
    return c


def bagimsiz_hukum(once: str, sonra: str) -> str | None:
    """Dosya düzeyinde bağımsız hüküm.

    ``None``: metin aynı. ``"eşdeğer"``: değişti ve her gövde ard koşulları
    sağlıyor. ``"hükümsüz"``: değişen gövdenin girdisi ayrıştırılamıyor.
    Aksi hâlde ilk ihlalin adı (``denge``, ``ayrıştırma``, ``etiket``,
    ``goto``, ``çağrı``, ``return``, ``akış``).
    """
    if once == sonra:
        return None
    F = _YENI
    kod0 = F._mask(once)[0]
    kod1 = F._mask(sonra)[0]
    g0 = F._function_bodies(kod0)
    g1 = F._function_bodies(kod1)
    if g0 is None:
        return "girdi-dengesiz"
    if g1 is None or len(g0) != len(g1):
        return "denge"
    for (b0, s0), (b1, s1) in zip(g0, g1):
        if once[b0:s0] == sonra[b1:s1]:
            continue
        try:
            F._Analysis(once[b0:s0])
        except (F._ParseError, RecursionError):
            # Girdi (Ghidra'nın ham metni) ayrıştırılamıyor: hüküm verilemez.
            return "hükümsüz"
        ihlal = F._postcondition_violation(once[b0:s0], sonra[b1:s1], None)
        if ihlal is not None:
            return ihlal
    return "eşdeğer"


def ayracsiz_gomme_sayisi(sonra: str) -> int:
    """Çıktıda, ``if (k)``/``else`` altına ayraçsız konmuş çok deyimli blok.

    Denetçinin (b) ölçütünün çıktıya bakan biçimi: satır içine alma
    yorumundan önceki son kod karakteri ``)`` ya da ``else`` ise ve yorumun
    ardındaki blokta birden çok deyim varsa sayılır.
    """
    F = _YENI
    kod = F._mask(sonra)[0]
    n = 0
    for m in RE_SATIR_ICI_YORUM.finditer(sonra):
        p = m.start() - 1
        while p >= 0 and kod[p] in " \t\n":
            p -= 1
        if p < 0:
            continue
        ayracsiz = kod[p] == ")" or kod[max(0, p - 3):p + 1] == "else"
        if not ayracsiz:
            continue
        # yorumdan sonra aynı derinlikte ilk iki ';' arasında kapanış yoksa çok deyim
        q = m.end()
        noktali = 0
        derinlik = 0
        while q < len(kod) and noktali < 2:
            ch = kod[q]
            if ch == "{":
                derinlik += 1
            elif ch == "}":
                derinlik -= 1
                if derinlik < 0:
                    break
            elif ch == ";" and derinlik == 0:
                noktali += 1
            q += 1
        if noktali >= 2:
            n += 1
    return n


def gec_bildirim_var(metin: str) -> int:
    """goto içeren gövdelerden kaçında baştaki bildirim öbeği dışında bildirim var?

    Yeni sürüm, böyle bir adı anan metni taşımaz (kapsam değişebilir). Ard
    koşul denetimi kapsamı ayrıca sınamaz; bu sayı o varsayımın veride ne
    kadar sık devreye girdiğini gösterir.
    """
    F = _YENI
    kod = F._mask(metin)[0]
    govdeler = F._function_bodies(kod)
    n = 0
    for b, s in govdeler or ():
        if "goto" not in kod[b:s]:
            continue
        try:
            an = F._Analysis(metin[b:s])
        except (F._ParseError, RecursionError):
            continue
        if an.late_declared:
            n += 1
    return n


def belirtiler(once: str, sonra: str) -> collections.Counter:
    """Çıktıda yeni ortaya çıkan belirtiler (gövdeler ayrışabiliyorsa).

    * ``erisilemez``: koşulsuz atlamadan hemen sonra, etiketsiz gelen deyim.
    * ``cift_donus``: art arda iki ``return``.
    Girdideki sayıdan fazlası sayılır.
    """
    F = _YENI
    c = collections.Counter()

    def say(metin):
        kod = F._mask(metin)[0]
        govdeler = F._function_bodies(kod)
        if govdeler is None:
            return None
        e = d = 0
        for b, s in govdeler:
            try:
                an = F._Analysis(metin[b:s])
            except (F._ParseError, RecursionError):
                return None
            for blok in an.blocks:
                ogeler = blok.items
                for i in range(1, len(ogeler)):
                    onceki, bu = ogeler[i - 1], ogeler[i]
                    if onceki.kind in ("goto", "return", "break", "continue") \
                            and bu.kind not in ("label", "case"):
                        e += 1
                        if onceki.kind == "return" and bu.kind == "return":
                            d += 1
        return e, d

    a = say(once)
    b = say(sonra)
    if a is None or b is None:
        return c
    if b[0] > a[0]:
        c["erisilemez"] = 1
    if b[1] > a[1]:
        c["cift_donus"] = 1
    return c


# ---------------------------------------------------------------------------
# Derleyiciyle bağımsız denetim (isteğe bağlı: --clang)
# ---------------------------------------------------------------------------
# Ghidra'nın tip adları; tanı gürültüsünü azaltır (her iki tarafta aynı)
CLANG_ON_EK = (
    "typedef unsigned char undefined; typedef unsigned char undefined1; "
    "typedef unsigned short undefined2; typedef unsigned int undefined4; "
    "typedef unsigned long undefined8; typedef unsigned char byte; "
    "typedef unsigned int uint; typedef unsigned long ulong; "
    "typedef unsigned short ushort; typedef unsigned char uchar; "
    "typedef long long longlong; typedef unsigned long long ulonglong; "
    "typedef unsigned char bool; typedef void code; typedef unsigned long size_t;\n"
)
RE_CLANG_HATA = re.compile(r"^<stdin>:\d+:\d+: (?:fatal )?error: (.*)$", re.M)
RE_TIRNAKLI_AD = re.compile(r"'[^']*[A-Za-z0-9_][^']*'")
# struct_recovered dosyaları '#include "types.h"' ile başlar; dosya bulunamayınca
# clang ilk satırda durur ve karşılaştırma boşalır. Satır boşaltılır.
RE_INCLUDE = re.compile(r"^[ \t]*#[ \t]*include\b[^\n]*$", re.M)


def clang_tani_turleri(metin: str):
    """``clang -fsyntax-only`` hata iletilerinin kümesi (konumsuz, adsız).

    Ghidra çıktısı tek başına derlenmez (bildirilmemiş tipler ve küreseller);
    bu yüzden ölçüt farktır: dönüşüm, girdide olmayan bir hata **türü**
    üretmemeli. Tırnak içindeki adlar ``'AD'`` yapılır (çıktıya ad yazılmaz;
    etiket adı değişse de ileti aynı kalır); ``'}'`` gibi imler korunur.
    ``#include`` satırları boşaltılır (başlık dosyası yanında değil).
    Dönen: küme ya da (clang çalışmadıysa) ``None``.
    """
    try:
        p = subprocess.run(
            ["clang", "-fsyntax-only", "-x", "c", "-std=gnu89", "-ferror-limit=0",
             "-w", "-fno-color-diagnostics", "-fno-caret-diagnostics", "-"],
            input=CLANG_ON_EK + RE_INCLUDE.sub("", metin),
            capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return {RE_TIRNAKLI_AD.sub("'AD'", ileti) for ileti in RE_CLANG_HATA.findall(p.stderr)}


# ---------------------------------------------------------------------------
# Eski sürümün geçişlerini tek tek çalıştırma ve kök neden sınıflaması
# ---------------------------------------------------------------------------
def eski_gecis(ad: str, metin: str) -> str:
    E = _ESKI
    s = E.CFlowSimplifier()
    if ad == "cascade":
        return s._pass_cascading_goto(metin)[0]
    if ad == "ifelse":
        return s._pass_ifelse_restructure(metin)[0]
    if ad == "early_return":
        return s._pass_early_return(metin)[0]
    if ad == "break_continue":
        return s._pass_break_continue(metin)[0]
    if ad == "multi_inline":
        return s._pass_multi_target_cleanup(metin)[0]
    # tek hedefli satır içine alma ve yeniden adlandırma _simplify_content'in
    # içinde; öbür geçişler etkisiz kılınır
    for g in ("_pass_cascading_goto", "_pass_ifelse_restructure",
              "_pass_early_return", "_pass_break_continue",
              "_pass_multi_target_cleanup"):
        setattr(s, g, lambda c: (c, 0))
    if ad == "single_inline":
        s._classify_label = lambda name, block: name
    elif ad == "rename":
        s._is_cleanup_block = lambda block: False
    else:
        raise ValueError(ad)
    return s._simplify_content(metin)[0]


def eski_gomme_kok_nedenleri(metin: str, cok_hedefli: bool) -> collections.Counter:
    """Eski satır içine alma geçişinin girdide tetiklediği kök nedenler.

    Eski kodun kendi blok çıkarıcısı (``_extract_label_block``) ve aday
    kuralı kullanılır; her aday etiket için hangi hatalı varsayımın geçerli
    olduğu yeni ayrıştırıcıyla saptanır. Dönen sayaç fonksiyon başına 0/1.
    """
    E, F = _ESKI, _YENI
    c = collections.Counter()
    s = E.CFlowSimplifier()
    kod = F._mask(metin)[0]
    govdeler = F._function_bodies(kod)
    if govdeler is None:
        return c
    for b, son in govdeler:
        govde = metin[b:son]
        try:
            an = F._Analysis(govde)
        except (F._ParseError, RecursionError):
            c["ayrıştırılamadı"] = 1
            continue
        for ad, etiket in an.labels.items():
            if not F._LAB_NAME_RE.match(ad):
                continue
            hedefler = an.gotos.get(ad, [])
            n = len(hedefler)
            if cok_hedefli:
                if n < 2 or n > 10:
                    continue
            elif n != 1:
                continue
            blok = s._extract_label_block(govde, etiket.end)
            if not blok or not s._is_cleanup_block(blok):
                continue
            if cok_hedefli:
                if blok.count("\n") > 5:
                    continue
            elif blok.count("\n") > s._max_inline_lines:
                continue
            c["aday_etiket_var"] = 1
            # K1: blok tam deyimlerden oluşmuyor (ayraç sınırını aşıyor ya
            # da iç içe bloğun içindeki return/goto'da kesiliyor)
            blok_kod = F._mask(blok)[0]
            derinlik = 0
            asti = False
            for ch in blok_kod:
                if ch == "{":
                    derinlik += 1
                elif ch == "}":
                    derinlik -= 1
                    if derinlik < 0:
                        asti = True
                        break
            if asti or derinlik != 0:
                c["K1_blok_ayrac_sinirini_asiyor"] = 1
            # K2: goto ayraçsız alt deyim ve blok birden çok deyim
            cok_deyim = _D.ust_duzey_deyim(blok_kod) >= 2
            if cok_deyim and any(g.parent.kind != "block" for g in hedefler):
                c["K2_ayracsiz_kosula_cok_deyim"] = 1
            # K3: etikete düşerek ulaşılıyor ama blok siliniyor
            if not an.no_fallthrough(etiket):
                c["K3_duserek_ulasilan_blok_silindi"] = 1
            # K4: silinen uzunluk bloğun gerçek uzunluğundan kısa
            # (eski kod: etiket sonu + len(blok); boş satırlar ve satır
            # sonu hesaba katılmıyor)
            son_satir = blok.split("\n")[-1]
            gercek_son = govde.find(son_satir, etiket.end)
            if gercek_son >= 0:
                gercek_uzunluk = gercek_son + len(son_satir) - etiket.end
                artik = gercek_uzunluk - len(blok)
                if artik > 1:
                    c["K4_silme_kisa_kuyruk_kaldi"] = 1
                elif artik == 1:
                    c["K4b_yalniz_noktali_virgul_kaldi"] = 1
    return c


def eski_atlama_kok_nedenleri(metin: str, gecis: str) -> collections.Counter:
    """Eski break/continue ve erken dönüş geçişlerinin kök nedenleri.

    Girdinin yeni ayrıştırıcıyla çözümünden okunur; fonksiyon başına 0/1.

    * ``B1``: goto'nun etiketi bir döngünün hemen ardında, goto o döngünün
      içinde ama arada başka bir döngü ya da switch var (``break`` içtekine
      bağlanır).
    * ``B2``: etiket döngünün hemen önünde ve döngü ``for`` ya da koşullu
      ``do-while`` (``continue`` başa atlamakla aynı değil).
    * ``B3``: etiket döngünün ardında/önünde ama aynı blokta kardeş değil
      (eski kod satır numarasıyla eşliyordu).
    * ``E1``: ``L: return x;`` etiketine düşerek de ulaşılıyor; eski kod
      goto'lar bitince etiketle birlikte ``return``'ü de siliyor.
    """
    F = _YENI
    c = collections.Counter()
    kod = F._mask(metin)[0]
    govdeler = F._function_bodies(kod)
    if govdeler is None:
        return c
    for b, son in govdeler:
        govde = metin[b:son]
        try:
            an = F._Analysis(govde)
        except (F._ParseError, RecursionError):
            continue
        if gecis == "early_return":
            for ad, etiket in an.labels.items():
                if not F._LAB_NAME_RE.match(ad) or not an.gotos.get(ad):
                    continue
                sonraki = an.next_real(etiket)
                if sonraki is not None and sonraki.kind == "return" \
                        and not an.no_fallthrough(etiket):
                    c["E1_duserek_ulasilan_return_silindi"] = 1
            continue
        def satir(konum):
            return an.code.count("\n", 0, konum)

        donguler = [n for n in an.nodes if n.kind in ("while", "do", "for")]
        for ad, hedefler in an.gotos.items():
            etiket = an.labels.get(ad)
            if etiket is None or not F._LAB_NAME_RE.match(ad):
                continue
            es = satir(etiket.start)
            for g in hedefler:
                for d in donguler:
                    if not (d.start <= g.start < d.end):
                        continue
                    kardes_sonra = etiket.parent is d.parent and etiket.index == d.index + 1
                    kardes_once = etiket.parent is d.parent and etiket.index == d.index - 1
                    satir_sonra = es in (satir(d.end - 1), satir(d.end - 1) + 1)
                    satir_once = es in (satir(d.start), satir(d.start) - 1)
                    if satir_sonra:
                        if g.brk is not d:
                            c["B1_break_icteki_donguye_ya_da_switch_e_baglaniyor"] = 1
                        elif not kardes_sonra:
                            c["B3_etiket_kardes_degil"] = 1
                    if satir_once:
                        if g.loop is not d:
                            c["B1_break_icteki_donguye_ya_da_switch_e_baglaniyor"] = 1
                        elif d.kind == "for" or (
                                d.kind == "do"
                                and F._norm(an.code[d.cond[0]:d.cond[1]]) not in F._ALWAYS_TRUE):
                            c["B2_continue_for_ya_da_kosullu_do_while"] = 1
                        elif not kardes_once:
                            c["B3_etiket_kardes_degil"] = 1
    return c


# ---------------------------------------------------------------------------
# Birim işleme
# ---------------------------------------------------------------------------
def birim_isle(gorev):
    birim, girdi, ornek_ac, clang_ac = gorev
    alanlar = calisma_alani(birim["kok"])
    c = collections.Counter()
    ornekler: dict[str, list] = collections.defaultdict(list)
    if len(alanlar) != 1:
        return birim["program"], birim["tabaka"], girdi, {"hata_calisma_alani": 1}, {}
    dizin = os.path.join(alanlar[0], GIRDI_DIZINLERI[girdi])
    if not os.path.isdir(dizin):
        return birim["program"], birim["tabaka"], girdi, {"hata_dizin_yok": 1}, {}
    c["ikili"] = 1
    eski = _ESKI.CFlowSimplifier()
    yeni = _YENI.CFlowSimplifier()
    bozuk_ikili = collections.Counter()

    def ornek(sinif, yol):
        if ornek_ac and len(ornekler[sinif]) < ORNEK_SINIRI:
            ornekler[sinif].append(yol)

    for ad in sorted(os.listdir(dizin)):
        if not ad.endswith(".c"):
            continue
        yol = os.path.join(dizin, ad)
        with open(yol, encoding="utf-8", errors="replace") as f:
            metin = f.read()
        c["dosya"] += 1
        if "goto" not in metin and "LAB_" not in metin:
            # iki sürüm de dokunmaz; yalnız fonksiyon sayısı
            c["fonksiyon"] += len(_D.RE_BASLIK_AD.findall(metin))
            continue
        c["goto_iceren_govdede_gec_bildirim"] += gec_bildirim_var(metin)
        girdi_tanilari = False      # False: henüz hesaplanmadı
        for surum, sade in (("once", eski), ("sonra", yeni)):
            try:
                cikti, ist = sade._simplify_content(metin)
            except Exception as exc:      # eski sürüm bazı girdilerde hata verebilir
                c[f"{surum}/hata"] += 1
                ornek(f"{surum}/hata", f"{yol}\t{type(exc).__name__}")
                cikti, ist = metin, {}
            dc = denetci_olcutu(metin, cikti)
            if surum == "once":
                for k in ("fonksiyon", "ham_bozuk", "ham_goto_iceren_fonksiyon"):
                    c[k] += dc.get(k, 0)
            for k, v in dc.items():
                if k not in ("fonksiyon", "ham_bozuk", "ham_goto_iceren_fonksiyon"):
                    c[f"{surum}/denetci/{k}"] += v
            hukum = bagimsiz_hukum(metin, cikti)
            if hukum is not None:
                c[f"{surum}/degisen_dosya"] += 1
                c[f"{surum}/bagimsiz/{hukum}"] += 1
                if hukum not in IYI_HUKUMLER:
                    c[f"{surum}/bagimsiz_bozuk"] += 1
                    ornek(f"{surum}/bagimsiz/{hukum}", yol)
                elif hukum == "eşdeğer" and dc.get("akis_sadelestirmenin_bozdugu_fonksiyon"):
                    # denetçinin üst sınır ölçütü sayıyor ama akış eşdeğer
                    c[f"{surum}/denetci_ust_sinir_ama_esdeger"] += 1
                    if not ayracsiz_gomme_sayisi(cikti):
                        c[f"{surum}/denetci_ust_sinir_ama_esdeger_ve_ayracli"] += 1
                b = belirtiler(metin, cikti)
                for k, v in b.items():
                    c[f"{surum}/belirti/{k}"] += v
                n_ayracsiz = ayracsiz_gomme_sayisi(cikti)
                if n_ayracsiz:
                    c[f"{surum}/ayracsiz_gomme_fonksiyon"] += 1
                    c[f"{surum}/ayracsiz_gomme_blok"] += n_ayracsiz
            if clang_ac and hukum is not None:
                if girdi_tanilari is False:
                    girdi_tanilari = clang_tani_turleri(metin)
                cikti_tanilari = clang_tani_turleri(cikti)
                if girdi_tanilari is None or cikti_tanilari is None:
                    c[f"{surum}/clang/calismadi"] += 1
                else:
                    c[f"{surum}/clang/denetlenen"] += 1
                    yeni_turler = cikti_tanilari - girdi_tanilari
                    if yeni_turler:
                        c[f"{surum}/clang/yeni_hata_turu_olan"] += 1
                        ornek(f"{surum}/clang_yeni_hata", yol)
                        for tur in sorted(yeni_turler):
                            c[f"{surum}/clang/tur/{tur.replace('/', '|')}"] += 1
            if dc.get("akis_sadelestirmenin_bozdugu_fonksiyon_ihtiyatli"):
                bozuk_ikili[surum + "/ihtiyatli"] = 1
                ornek(f"{surum}/denetci_ihtiyatli", yol)
            elif dc.get("akis_sadelestirmenin_bozdugu_fonksiyon"):
                ornek(f"{surum}/denetci_yalniz_ust_sinir", yol)
            if dc.get("akis_sadelestirmenin_bozdugu_fonksiyon"):
                bozuk_ikili[surum + "/ust"] = 1
            if hukum is not None and hukum not in IYI_HUKUMLER:
                bozuk_ikili[surum + "/bagimsiz"] = 1
            if surum == "sonra":
                for k, v in ist.items():
                    if v:
                        c[f"sonra/urun/{k}"] += v
                if cikti != metin:
                    for ad in RE_YENI_ETIKET.findall(_YENI._mask(cikti)[0]):
                        c[f"sonra/etiket_adi/{ad}"] += 1
                if ist.get("functions_reverted"):
                    ornek("sonra/ozgune_donen", yol)
                if ist.get("functions_skipped"):
                    ornek("sonra/atlanan", yol)
                # belirlenimcilik: aynı girdi, yeni nesne, aynı çıktı
                if _YENI.CFlowSimplifier()._simplify_content(metin)[0] != cikti:
                    c["sonra/belirlenimsiz"] += 1
                # yeniden uygulama da ard koşulları sağlamalı
                ikinci = yeni._simplify_content(cikti)[0]
                h2 = bagimsiz_hukum(cikti, ikinci)
                if h2 is not None:
                    c["sonra/ikinci_uygulama_degisen"] += 1
                    if h2 not in IYI_HUKUMLER:
                        c["sonra/ikinci_uygulama_bozuk"] += 1
                        ornek("sonra/ikinci_uygulama_bozuk", yol)

        # eski sürüm: geçişler tek tek
        for gecis in ESKI_GECISLER:
            try:
                cikti = eski_gecis(gecis, metin)
            except Exception:
                c[f"once_gecis/{gecis}/hata"] += 1
                continue
            hukum = bagimsiz_hukum(metin, cikti)
            if hukum is None:
                continue
            c[f"once_gecis/{gecis}/degisen"] += 1
            c[f"once_gecis/{gecis}/{hukum}"] += 1
            if hukum not in IYI_HUKUMLER:
                c[f"once_gecis/{gecis}/bozuk"] += 1
                ornek(f"once_gecis/{gecis}/{hukum}", yol)
                for k, v in belirtiler(metin, cikti).items():
                    c[f"once_gecis/{gecis}/belirti/{k}"] += v
                if gecis in ("multi_inline", "single_inline"):
                    kn = eski_gomme_kok_nedenleri(metin, gecis == "multi_inline")
                elif gecis in ("break_continue", "early_return"):
                    kn = eski_atlama_kok_nedenleri(metin, gecis)
                else:
                    kn = {}
                for k, v in kn.items():
                    c[f"once_gecis/{gecis}/kok/{k}"] += v
                if gecis != "ifelse" and not any(k[0] in "KBE" for k in kn):
                    c[f"once_gecis/{gecis}/kok/siniflanmadi"] += 1
                    ornek(f"once_gecis/{gecis}/kok_yok", yol)
    for k in bozuk_ikili:
        c[f"bozuk_ikili/{k}"] = 1
    return birim["program"], birim["tabaka"], girdi, dict(c), dict(ornekler)


# ---------------------------------------------------------------------------
# Toplama ve çıktı
# ---------------------------------------------------------------------------
def agaca_cevir(duz: dict) -> dict:
    kok: dict = {}
    for anahtar in sorted(duz):
        d = kok
        parcalar = anahtar.split("/")
        for p in parcalar[:-1]:
            d = d.setdefault(p, {})
            if not isinstance(d, dict):
                raise ValueError(anahtar)
        d[parcalar[-1]] = duz[anahtar]
    return kok


def sha1_dosya(yol: str) -> str:
    with open(yol, "rb") as f:
        return hashlib.sha1(f.read()).hexdigest()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--is", dest="isci", type=int, default=4)
    ap.add_argument("--girdi", choices=("ham", "struct", "ikisi"), default="ikisi")
    ap.add_argument("--cikti", default=os.path.join(BETIK_DIZINI, "akis_sadelestirme_olcum.json"))
    ap.add_argument("--ornek-dizini", default=None,
                    help="sınıf başına örnek dosya yolları (ad içerir; depoya yazılmaz)")
    ap.add_argument("--program", default=None, help="yalnız bu program (ör. debian/tree)")
    ap.add_argument("--clang", action="store_true",
                    help="değişen her dosyada clang -fsyntax-only tanı türlerini karşılaştır")
    args = ap.parse_args(argv)

    t0 = time.time()
    gecici = tempfile.mkdtemp(prefix="akis-olcum-")
    eski_yol = os.path.join(gecici, "eski_c_flow_simplifier.py")
    with open(eski_yol, "w", encoding="utf-8") as f:
        f.write(once_kaynagi())

    birimler = birimleri_bul()
    if args.program:
        birimler = [b for b in birimler if b["program"] == args.program]
    girdiler = ("ham", "struct") if args.girdi == "ikisi" else (args.girdi,)
    gorevler = [(b, g, bool(args.ornek_dizini), args.clang) for g in girdiler for b in birimler]

    toplam: dict = {g: collections.Counter() for g in girdiler}
    program: dict = {g: collections.defaultdict(collections.Counter) for g in girdiler}
    tabaka: dict = {g: collections.defaultdict(collections.Counter) for g in girdiler}
    ornekler: dict = collections.defaultdict(list)
    with multiprocessing.Pool(args.isci, initializer=isci_hazirla, initargs=(eski_yol,)) as havuz:
        for prog, tab, girdi, c, orn in havuz.imap(birim_isle, gorevler):
            toplam[girdi].update(c)
            program[girdi][prog].update(c)
            tabaka[girdi][tab or "bilinmiyor"].update(c)
            for k, v in orn.items():
                kalan = ORNEK_SINIRI - len(ornekler[f"{girdi}/{k}"])
                ornekler[f"{girdi}/{k}"].extend(v[:max(0, kalan)])
    shutil.rmtree(gecici, ignore_errors=True)      # yalnız eski sürümün geçici kopyası

    commit = subprocess.run(["git", "-C", DEPO, "rev-parse", "HEAD"],
                            capture_output=True, text=True).stdout.strip()
    kirli = subprocess.run(["git", "-C", DEPO, "status", "--porcelain", "--", MODUL_YOLU],
                           capture_output=True, text=True).stdout.strip()
    sonuc = {
        "kunye": {
            "betik": os.path.relpath(os.path.abspath(__file__), DEPO),
            "tarih": time.strftime("%Y-%m-%d %H:%M:%S"),
            "sure_s": round(time.time() - t0, 1),
            "once_commit": ONCE_COMMIT,
            "sonra_commit": commit,
            "sonra_modul_commitsiz_degisiklik": bool(kirli),
            "sonra_modul_sha1": sha1_dosya(os.path.join(DEPO, MODUL_YOLU)),
            "denetle_sha1": sha1_dosya(denetle_yolu()),
            "girdi_kokleri": [DEBIAN_KOK, MAC_KOK],
            "girdi_dizinleri": GIRDI_DIZINLERI,
            "beklenen_ikili": BEKLENEN_IKILI,
            "program_suzgeci": args.program,
            "clang": subprocess.run(["clang", "--version"], capture_output=True,
                                    text=True).stdout.split("\n")[0] if args.clang else None,
            "aciklama": {
                "denetci": "denetle.py K4 akış ölçütleri (birebir); "
                           "akis_sadelestirmenin_bozdugu_fonksiyon_ihtiyatli = rapordaki 4 661",
                "bagimsiz": "_postcondition_violation ile dosya düzeyi hüküm "
                            "(denge/ayrıştırma/etiket/goto/çağrı/return/akış)",
                "urun": "yeni sürümün kendi sayaçları (functions_reverted = ard koşul "
                        "yüzünden özgün metne dönen fonksiyon)",
                "once_gecis": "eski sürümün her geçişi ham girdide tek başına",
                "clang": "değişen dosyada clang -fsyntax-only hata türleri; "
                         "yeni_hata_turu_olan = girdide olmayan bir hata türü çıkan dosya",
            },
        },
        "girdi": {},
    }
    for g in girdiler:
        sonuc["girdi"][g] = {
            "toplam": agaca_cevir(toplam[g]),
            "program": {p: agaca_cevir(program[g][p]) for p in sorted(program[g])},
            "tabaka": {t: agaca_cevir(tabaka[g][t]) for t in sorted(tabaka[g])},
        }
    with open(args.cikti, "w", encoding="utf-8") as f:
        json.dump(sonuc, f, ensure_ascii=False, indent=1, sort_keys=True)
        f.write("\n")
    if args.ornek_dizini:
        os.makedirs(args.ornek_dizini, exist_ok=True)
        with open(os.path.join(args.ornek_dizini, "ornekler.json"), "w", encoding="utf-8") as f:
            json.dump(ornekler, f, ensure_ascii=False, indent=1, sort_keys=True)

    for g in girdiler:
        t = toplam[g]
        print(f"[{g}] ikili {t['ikili']}/{BEKLENEN_IKILI}, fonksiyon {t['fonksiyon']}, "
              f"goto içeren {t['ham_goto_iceren_fonksiyon']}")
        for s in ("once", "sonra"):
            print(f"  {s}: değişen dosya {t[s + '/degisen_dosya']}, "
                  f"denetçi söz bozuk {t[s + '/denetci/soz_bozuk']}, "
                  f"denetçi birleşik ihtiyatlı {t[s + '/denetci/akis_sadelestirmenin_bozdugu_fonksiyon_ihtiyatli']}, "
                  f"üst sınır {t[s + '/denetci/akis_sadelestirmenin_bozdugu_fonksiyon']}, "
                  f"bağımsız bozuk {t[s + '/bagimsiz_bozuk']}")
        print(f"  sonra: özgüne dönen {t['sonra/urun/functions_reverted']}, "
              f"atlanan {t['sonra/urun/functions_skipped']}, "
              f"belirlenimsiz {t['sonra/belirlenimsiz']}")
    eksik = [g for g in girdiler if toplam[g]["ikili"] != BEKLENEN_IKILI]
    if eksik and not args.program:
        print("UYARI: beklenen ikili sayısı tutmuyor:", eksik)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
