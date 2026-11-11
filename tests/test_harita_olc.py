"""scripts/measurement/harita_olc.py — harita ölçümünün (ürün modülü ↔ kaynak dosya) testleri.

Bütün testler sentetik verilerle koşar: sentetik çalışma alanları (``reconstructed/project/src``
ağacı, ``ghidra_functions.json``), bellekte kurulan sentetik DWARF (``dwarf_tip.Die`` /
``DwarfDosyasi``) ve sentetik GT etiketleri. Gerçek GT, dbgsym ya da ürün koşusu okunmaz.
Kilitlenen davranışlar:
  (a) ürün tarafı: adres başlığından modül (ad kullanılmaz), kök modül, birleşik dosya, çoklu modül,
      atanamayan, Ghidra dışı adres; ürünün kendi kurucusunun (``CProjectBuilder``) çıktısı,
  (b) GT tarafı: kaynak birim seçimi (kendi birimi, LTO'da köken birimi, kısmi birim, yapay birim),
      kaynak dosya yolu (satır tablosu, ad), CRT, gövdesiz, çelişkili, ofset,
  (c) ölçüler: çift sayımlı kesinlik, duyarlılık, F1, düzeltilmiş Rand indeksi, V-ölçüsü; elle
      hesaplanmış örnekler ve bağımsız (kaba kuvvet) hesapla karşılaştırma,
  (d) tabanlar: B0 (karma; tohum, ortalama, yüzdelik, p değeri), B1 (bitişik bölme), yozlaşmış sınırlar,
  (e) giriş kuralı: N_MIN, tek sınıf, hepsi ayrı, yol kaynağı,
  (f) toplama ve karar: birim, program, makro; B1'e ve rastgeleye karşı kararlar,
  (g) ``olc`` uçtan uca (bilinen cevap), eksiksizlik, C++ ve Mach-O dışarıda, çıktıda ad yok,
  (h) ``kuru``: çapraz tablo kurulmaz; ikili başına hata yazılır,
  (i) ön koşullar: ön kayıt commit'i ve sha256'lar.

Mutasyon koruması: ``scripts/measurement/mutation_specs_harita_olc.json``.
"""
from __future__ import annotations

import importlib.util
import itertools
import json
import math
import random
import subprocess
import sys
from fractions import Fraction
from pathlib import Path

import pytest

_KOK = Path(__file__).resolve().parents[1]
_PATH = _KOK / "scripts" / "measurement" / "harita_olc.py"
_spec = importlib.util.spec_from_file_location("harita_olc_under_test", _PATH)
ho = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = ho
_spec.loader.exec_module(ho)
ks1 = ho.ks1
dt = ho.dt

ZAMAN = "20261110_000000"      # sentetik çalışma alanı dizini; tests/test_urun_olc.py ile aynı değer
F = Fraction


# --------------------------------------------------------------------------------------------
# Sentetik çalışma alanı


def fonk(adres, ad=None, thunk=False, dis=False):
    return {"name": ad or f"FUN_{adres:08x}", "address": f"{adres:08x}", "is_thunk": thunk,
            "is_external": dis, "size": 4}


def govde_metni(adres, ad="islev"):
    """Ürünün yazdığı biçimde tek fonksiyonluk kaynak (başlık + gövde)."""
    return (f'#include "types.h"\n\n// Function: {ad}\n// Address:  {adres:08x}\n// Size:     4 bytes\n\n'
            f"void {ad}(void)\n{{\n  return;\n}}\n")


def src_yaz(ws, yerlesim):
    """``yerlesim``: ``src``'ye göre dosya yolu → adres listesi (dosyadaki fonksiyon başlıkları)."""
    src = ws / "reconstructed" / "project" / "src"
    src.mkdir(parents=True, exist_ok=True)
    for goreli, adresler in yerlesim.items():
        yol = src / goreli
        yol.parent.mkdir(parents=True, exist_ok=True)
        yol.write_text("".join(govde_metni(a) for a in adresler) or "// başlıksız\n", encoding="utf-8")
    return src


def alan_kur(kok, platform_, program, elf, fonksiyonlar, yerlesim=None, bitti=True, surum="12.1.2"):
    """Bir ikilinin koşu dizini: ``ks1_olc`` yerleşimiyle (Debian'da ``BITTI`` dosyalı)."""
    taban = kok / program / elf if platform_ == "debian" else kok / program
    ws = taban / "ws" / "workspaces" / elf / ZAMAN
    (ws / "static").mkdir(parents=True)
    (ws / "static" / "ghidra_functions.json").write_text(json.dumps({"functions": fonksiyonlar}))
    (ws / "static" / "ghidra_strings.json").write_text(json.dumps({"strings": []}))
    (ws / "reports").mkdir()
    (ws / "reports" / "report.json").write_text(json.dumps(
        {"environment": {"ghidra": {"version": surum, "matches_pinned": True}}}))
    if yerlesim is not None:
        src_yaz(ws, yerlesim)
    if bitti and platform_ == "debian":
        (taban / "BITTI").write_text("")
    return ws


def gt_tarafi(etiket, fonksiyon=None, yol_ad=0, yapay=0):
    """Sentetik GT: adres → kaynak dosya yolu."""
    sayac = {"gt_fonksiyon": len(etiket), "crt": 0, "govdesiz": 0, "etiketsiz": 0, "celiskili": 0,
             "etiketli": len(etiket), "koken_birimi": 0, "yol_ad": yol_ad,
             "kaynak_dosya": len(set(etiket.values())),
             "dizin": len({ho.dizin_etiketi(y) for y in etiket.values()})}
    return ho.GtTarafi(dict(etiket), set(etiket if fonksiyon is None else fonksiyon), sayac,
                       {"debug": "sentetik.debug", "ofset": "0x0", "ofset_kaynagi": "sentetik",
                        "dwarf": {"ek_yontemi": "altlink_yok", "govde": len(etiket),
                                  "yapay_birimde_govde": yapay, "yalniz_ranges_govde": 0,
                                  "ayni_adli_kaynak": 0}})


def gt_tak(monkeypatch, tablo):
    """GT okuyucu yerine sentetik tablo (ikili adı → GtTarafi ya da fırlatılacak hata)."""
    def oku(e, indir, onbellek=None):
        deger = tablo[e.ad]
        if isinstance(deger, Exception):
            raise deger
        return deger
    monkeypatch.setattr(ho, "gt_oku", oku)


ADRESLER = [0x1000 + 0x10 * i for i in range(12)]


def uc_dosya(sira="bitisik"):
    """12 fonksiyon, üç kaynak dosya (dörder). ``bitisik``: adres sırasında öbek öbek;
    ``serpik``: a, b, c, a, b, c, … (aynı dosyanın fonksiyonları yan yana değil)."""
    yollar = ["src/a.c", "src/b.c", "lib/c.c"]
    if sira == "bitisik":
        return {a: yollar[i // 4] for i, a in enumerate(ADRESLER)}
    return {a: yollar[i % 3] for i, a in enumerate(ADRESLER)}


def yerlesim_kur(atama):
    """adres → modül sözlüğünden ``src`` yerleşimi (fonksiyon başına bir dosya)."""
    return {(f"{m}/f_{a:x}.c" if m != ho.KOK_MODUL else f"f_{a:x}.c"): [a] for a, m in atama.items()}


# --------------------------------------------------------------------------------------------
# Bağımsız (kaba kuvvet) hesaplar: betikteki formüllerden ayrı yol


def kaba_cift(u, v):
    ortak = urun = gt = toplam = 0
    for i, j in itertools.combinations(range(len(u)), 2):
        toplam += 1
        ayni_u, ayni_v = u[i] == u[j], v[i] == v[j]
        urun += ayni_u
        gt += ayni_v
        ortak += ayni_u and ayni_v
    return {"n": len(u), "toplam": toplam, "urun": urun, "gt": gt, "ortak": ortak}


def kaba_ari(u, v):
    s = kaba_cift(u, v)
    beklenen = F(s["urun"] * s["gt"], s["toplam"])
    return (s["ortak"] - beklenen) / (F(s["urun"] + s["gt"], 2) - beklenen)


def kaba_kosullu_entropi(hedef, kosul):
    """H(hedef | koşul) = Σ_k p(k) · H(hedef | koşul = k)."""
    n = len(hedef)
    toplam = 0.0
    for k in set(kosul):
        alt = [hedef[i] for i in range(n) if kosul[i] == k]
        h = -sum(alt.count(x) / len(alt) * math.log(alt.count(x) / len(alt)) for x in set(alt))
        toplam += len(alt) / n * h
    return toplam


def kaba_entropi(dizi):
    return -sum(dizi.count(x) / len(dizi) * math.log(dizi.count(x) / len(dizi)) for x in set(dizi))


# --------------------------------------------------------------------------------------------
# (i) Sabitler ks1_olc'den


def test_sabitler_ks1den():
    assert ho.N_MIN == ks1.N_MIN == 10
    assert ho.EN_AZ_PROGRAM == ks1.EN_AZ_PROGRAM == 2
    assert ho.ONDALIK == ks1.ONDALIK
    assert ho.OnkosulHatasi is ks1.OnkosulHatasi
    assert ho.PROJE_SRC_REL == Path("reconstructed") / "project" / "src"
    assert ho.KARAR_DUZEYI == "dosya" and ho.KARAR_OLCUSU == "ari"
    assert ho.B0_PERMUTASYON >= 200
    assert ho.FARK_ESIGI == F(1, 20) and ho.COGUNLUK == F(2, 3)
    # olc ve kuru, nüfusun beklenen büyüklüğünü ks1_olc'den alır
    assert ho.olc.__defaults__[2] is ks1.BEKLENEN_ELF
    assert ho.kuru.__defaults__[1] is ks1.BEKLENEN_ELF
    for rel in ho.OLCUM_DOSYALARI:
        assert (_KOK / rel).is_file(), rel
    assert "scripts/measurement/harita_olc.py" in ho.OLCUM_DOSYALARI
    assert "scripts/measurement/dwarf_tip.py" in ho.OLCUM_DOSYALARI
    assert set(ho.OLCUM_DOSYALARI) < set(ho.SABIT_DOSYALAR)


# --------------------------------------------------------------------------------------------
# (a) Ürün tarafı


def test_urun_oku_adresle_modul(tmp_path):
    """Modül, başlıktaki adresle okunur; aynı adlı iki fonksiyon ayrı adresleriyle ayrı kalır."""
    src = tmp_path / "reconstructed" / "project" / "src"
    (src / "subsystem_group_0").mkdir(parents=True)
    (src / "subsystem_memory").mkdir()
    (src / "subsystem_group_0" / "islev.c").write_text(govde_metni(0x1000, "islev"))
    (src / "subsystem_memory" / "islev_00002000.c").write_text(govde_metni(0x2000, "islev"))
    (src / "main.c").write_text("// === entry ===\n" + govde_metni(0x3000, "entry"))
    u = ho.urun_oku(tmp_path, [0x1000, 0x2000, 0x3000])
    assert u.modul == {0x1000: "subsystem_group_0", 0x2000: "subsystem_memory", 0x3000: ho.KOK_MODUL}
    assert u.sayac == {"kaynak_dosya": 3, "basliksiz_dosya": 0, "baslik": 3, "ghidra_fonksiyon": 3,
                       "atanan": 3, "atanamayan": 0, "coklu_modul": 0, "yinelenen": 0, "ghidra_disi": 0,
                       "modul": 3}


def test_urun_oku_birlesik_dosya_ve_sayaclar(tmp_path):
    src_yaz(tmp_path, {
        "subsystem_group_0/thunks_and_stubs.c": [0x10, 0x20, 0x30],     # birleşik: üç başlık
        "subsystem_group_0/a.c": [0x40],
        "subsystem_misc/b.c": [0x50],
        "subsystem_misc/b_kopya.c": [0x50],       # aynı modülde iki kez: atanır, sayılır
        "subsystem_group_1/c.c": [0x60],
        "subsystem_misc/c_kopya.c": [0x60],       # iki ayrı modülde: atanmaz
        "subsystem_misc/yabanci.c": [0x999],      # Ghidra'nın fonksiyon listesinde yok
        "subsystem_misc/bos.c": [],               # adres başlığı yok
    })
    u = ho.urun_oku(tmp_path, [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70])
    assert u.modul == {0x10: "subsystem_group_0", 0x20: "subsystem_group_0", 0x30: "subsystem_group_0",
                       0x40: "subsystem_group_0", 0x50: "subsystem_misc"}
    assert u.sayac == {"kaynak_dosya": 8, "basliksiz_dosya": 1, "baslik": 9, "ghidra_fonksiyon": 7,
                       "atanan": 5, "atanamayan": 1, "coklu_modul": 1, "yinelenen": 1, "ghidra_disi": 1,
                       "modul": 2}


def test_urun_oku_baslik_bicimi(tmp_path):
    """Yalnız satırın tamamı olan ``// Address:  <onaltılık>`` başlıktır; gövdedeki benzer metin değil."""
    src = tmp_path / "reconstructed" / "project" / "src" / "subsystem_misc"
    src.mkdir(parents=True)
    (src / "a.c").write_text(
        "// Function: a\n// Address:  00001a2B\n\nvoid a(void) {\n"
        "  /* @address 00009999 */\n  puts(\"// Address:  00008888 değil\");\n"
        "  x = 1; // Address:  00007777\n// Address:  00006666 (eski)\n}\n")
    u = ho.urun_oku(tmp_path, [0x1A2B, 0x9999, 0x8888, 0x7777, 0x6666])
    assert u.modul == {0x1A2B: "subsystem_misc"}
    assert u.sayac["atanamayan"] == 4 and u.sayac["baslik"] == 1


def test_dosya_modulu_ve_turu():
    assert ho.dosya_modulu(Path("subsystem_group_3/f.c")) == "subsystem_group_3"
    assert ho.dosya_modulu(Path("subsystem_group_3/alt/f.c")) == "subsystem_group_3"
    assert ho.dosya_modulu(Path("main.c")) == ho.KOK_MODUL
    assert ho.modul_turu(ho.KOK_MODUL) == ho.TUR_GIRIS
    assert ho.modul_turu("subsystem_group_12") == ho.TUR_TOPLULUK
    assert ho.modul_turu("subsystem_misc") == ho.TUR_MISC
    assert ho.modul_turu("subsystem_file_io") == ho.TUR_KURAL
    assert ho.modul_turu("subsystem_group_x") == ho.TUR_KURAL      # topluluk adı yalnız sayıyla biter
    assert ho.modul_turu("baska") == ho.TUR_DIGER


def test_proje_agaci_yoksa(tmp_path):
    with pytest.raises(ho.OnkosulHatasi, match="proje ağacı yok"):
        ho.urun_oku(tmp_path, [1])
    var = tmp_path / "var"
    src_yaz(var, {"subsystem_misc/a.c": [1]})
    yok = tmp_path / "yok"
    yok.mkdir()
    elfler = [ks1.Elf("debian", "p", "var", var / "static", var),
              ks1.Elf("debian", "p", "yok", yok / "static", yok),
              ks1.Elf("debian", "p", "bekleyen", None, yok)]
    isaretli = ho.projesizleri_isaretle(elfler)
    assert [e.static is None for e in isaretli] == [False, True, True]


def test_urun_oku_urunun_kurucusuyla(tmp_path):
    """Ürünün kendi kurucusu (``CProjectBuilder``) yazar, ölçüm okur: her fonksiyon tam bir modülde
    ve modül, kurucunun dosyayı koyduğu dizin. Ürünün yerleşim biçimi değişirse bu test kırılır."""
    import karadul
    assert _KOK in Path(karadul.__file__).resolve().parents, karadul.__file__
    from karadul.reconstruction.c_project_builder import CProjectBuilder

    class CalismaAlani:
        def __init__(self, kok):
            self._kok = kok

        def get_stage_dir(self, ad):
            return self._kok / ad

    def kaynak(ad, adres, satir):
        return (f"// Function: {ad}\n// Address:  {adres:08x}\n\nvoid {ad}(void)\n{{\n"
                + "  adim();\n" * satir + "}\n")

    # iki çağrı grafı topluluğu (üçer üyeli), bir API kuralı (malloc → memory), bir giriş noktası,
    # grafta olmayan bir fonksiyon (misc) ve kısa (birleştirilen) fonksiyonlar
    adlar = {"FUN_00001000": 0x1000, "FUN_00001010": 0x1010, "FUN_00001020": 0x1020,
             "FUN_00002000": 0x2000, "FUN_00002010": 0x2010, "FUN_00002020": 0x2020,
             "FUN_00003000": 0x3000, "entry": 0x4000, "FUN_00005000": 0x5000,
             "FUN_00006000": 0x6000, "FUN_00006010": 0x6010}
    kisa = {"FUN_00006000", "FUN_00006010", "FUN_00001020"}
    for ad, adres in adlar.items():
        yol = tmp_path / "kaynak" / f"{ad}.c"
        yol.parent.mkdir(parents=True, exist_ok=True)
        yol.write_text(kaynak(ad, adres, 2 if ad in kisa else 12))
    kenarlar = [("FUN_00001000", "FUN_00001010"), ("FUN_00001010", "FUN_00001020"),
                ("FUN_00001000", "FUN_00001020"), ("FUN_00002000", "FUN_00002010"),
                ("FUN_00002010", "FUN_00002020"), ("FUN_00002000", "FUN_00002020")]
    graf = {"program": "sentetik",
            "nodes": {f"{adres:08x}": {"name": ad, "address": f"{adres:08x}",
                                       "callees": [{"name": "malloc"}] if ad == "FUN_00003000" else []}
                      for ad, adres in adlar.items() if ad != "FUN_00005000"},
            "edges": [{"from_name": a, "to_name": b} for a, b in kenarlar]}
    (tmp_path / "static").mkdir()
    (tmp_path / "static" / "ghidra_call_graph.json").write_text(json.dumps(graf))
    cikti = tmp_path / "reconstructed" / "project"
    sonuc = CProjectBuilder(None).build(tmp_path / "kaynak", cikti, workspace=CalismaAlani(tmp_path))
    assert sonuc.success and sonuc.functions_placed == len(adlar)

    u = ho.urun_oku(tmp_path, adlar.values())
    assert set(u.modul) == set(adlar.values())
    assert u.sayac["atanamayan"] == u.sayac["coklu_modul"] == u.sayac["ghidra_disi"] == 0
    assert u.sayac["basliksiz_dosya"] == 0
    # bağımsız doğrulama: kurucunun dosyayı koyduğu dizin (içerikte fonksiyon adı aranır)
    for ad, adres in adlar.items():
        dizinler = {p.parent.relative_to(cikti / "src").as_posix()
                    for p in (cikti / "src").rglob("*.c") if f"void {ad}(void)" in p.read_text()}
        assert dizinler == {u.modul[adres]}, ad
    m = u.modul
    assert m[0x1000] == m[0x1010] == m[0x1020] != m[0x2000] == m[0x2010] == m[0x2020]
    assert {ho.modul_turu(m[0x1000]), ho.modul_turu(m[0x2000])} == {ho.TUR_TOPLULUK}
    assert m[0x3000] == "subsystem_memory" and m[0x4000] == ho.KOK_MODUL
    assert m[0x5000] == ho.MISC_MODUL
    assert u.sayac["baslik"] == len(adlar) > u.sayac["kaynak_dosya"]      # birleşik dosya okundu


# --------------------------------------------------------------------------------------------
# (b) GT tarafı: sentetik DWARF

CU = "DW_TAG_compile_unit"
PU = "DW_TAG_partial_unit"


def die(ofset, etiket, birim, **oz):
    return dt.Die(ofset, etiket, {f"DW_AT_{k}": v for k, v in oz.items()}, [], birim, None)


def ad_oz(metin):
    return ("DW_FORM_string", 0, metin)


def govde(ofset, birim, adres, koken=None):
    oz = {"low_pc": ("DW_FORM_addr", adres, adres)}
    if koken is not None:
        oz["abstract_origin"] = ("DW_FORM_ref_addr", koken, koken)
    return die(ofset, "DW_TAG_subprogram", birim, **oz)


def dwarf(dieler, birimler, altlink=None):
    """``birimler``: birim ofseti → (üst DIE ofseti, etiket, dosya tablosu)."""
    return dt.DwarfDosyasi(dt.ANA, {d.ofset: d for d in dieler},
                           {b: {"ust": ust, "etiket": etiket, "dieler": [], "dosya_tablosu": tablo}
                            for b, (ust, etiket, tablo) in birimler.items()}, altlink=altlink)


def tablo5(*yollar):
    return {"taban": 0, "yollar": list(yollar)}


def lto_ornegi():
    """Birim 0: ``src/a.c`` (kendi gövdesi 0x100). Birim 100: ``src/b.c`` (köken DIE'leri).
    Birim 200: yapay (LTRANS): 0x200 gövdesinin kökeni ``src/b.c``'de, 0x300 gövdesinin kökeni yok.
    Birim 300: kısmi birim (dwz; adı olsa da kaynak dosya değil): 0x400 gövdesinin kökeni orada;
    gövde ``src/a.c``'de. 0x600 gövdesi ``src/a.c`` biriminde, kökeni ``src/b.c``'de (en derin köken
    kazanır)."""
    dieler = [
        die(1, CU, 0, name=ad_oz("src/a.c")), govde(10, 0, 0x100),
        die(101, CU, 100, name=ad_oz("src/b.c")), die(110, "DW_TAG_subprogram", 100, name=ad_oz("f")),
        die(201, CU, 200, name=ad_oz("<artificial>")), govde(210, 200, 0x200, koken=110),
        govde(220, 200, 0x300),
        die(301, PU, 300, name=ad_oz("<dwz>")), die(310, "DW_TAG_subprogram", 300, name=ad_oz("g")),
        govde(20, 0, 0x400, koken=310),
        govde(30, 0, 0x500, koken=9999),          # çözülemeyen köken: kendi birimine düşer
        govde(60, 0, 0x600, koken=110),
    ]
    return dwarf(dieler, {0: (1, CU, tablo5("src/a.c", "/usr/include/x.h")),
                          100: (101, CU, tablo5("src/b.c")),
                          200: (201, CU, tablo5("/build/src/<artificial>")),
                          300: (301, PU, None)})


def test_kaynak_birimi_kurallari():
    ana = lto_ornegi()
    c = dt.Cozucu(ana)
    d = ana.dieler
    assert ho.kaynak_birimi(c, d[10]) == ((dt.ANA, 0, "src/a.c"), ho.KOKEN_KENDI)
    # LTO: somut gövde yapay birimde, kaynak dosya kökenin birimi
    assert ho.kaynak_birimi(c, d[210]) == ((dt.ANA, 100, "src/b.c"), ho.KOKEN_KOKEN)
    # yalnız yapay birim: etiket yok
    assert ho.kaynak_birimi(c, d[220]) == (None, None)
    # köken kısmi birimde (dwz): atlanır, gövdenin kendi birimi
    assert ho.kaynak_birimi(c, d[20]) == ((dt.ANA, 0, "src/a.c"), ho.KOKEN_KENDI)
    # köken çözülemiyor: gövdenin kendi birimi
    assert ho.kaynak_birimi(c, d[30]) == ((dt.ANA, 0, "src/a.c"), ho.KOKEN_KENDI)
    # iki birim de gerçek: en derin kökenin birimi
    assert ho.kaynak_birimi(c, d[60]) == ((dt.ANA, 100, "src/b.c"), ho.KOKEN_KOKEN)


def test_kaynak_birimi_dwarf_tip_kuraliyla_ayni():
    """Seçilen birimin adı ``dwarf_tip.Cozucu.fonksiyon``'un ``birim`` alanıyla aynı; ölçüm yalnız
    kimliği ekler ve yapay birimi etiket saymaz."""
    ana = lto_ornegi()
    c = dt.Cozucu(ana)
    for ofset in (10, 210, 220, 20, 30, 60):
        secim, _ = ho.kaynak_birimi(c, ana.dieler[ofset])
        beklenen = c.fonksiyon(ana.dieler[ofset])["birim"]
        if secim is None:
            assert beklenen in (None, ho.YAPAY_BIRIM)
        else:
            assert secim[2] == beklenen


def test_birim_yolu():
    dieler = [die(1, CU, 0, name=ad_oz("ortak.c")), die(101, CU, 100, name=ad_oz("ortak.c")),
              die(201, CU, 200, name=ad_oz("../modules/./v/vek.c")), die(301, CU, 300, name=ad_oz("lib//x.c")),
              die(401, CU, 400, name=ad_oz("y.c")), die(501, CU, 500, name=ad_oz("z.c")),
              die(601, CU, 600, name=ad_oz("w.c"))]
    ana = dwarf(dieler, {0: (1, CU, tablo5("src/ortak.c")), 100: (101, CU, tablo5("deps/kitap/ortak.c")),
                         200: (201, CU, tablo5("modules/v/vek.c")),
                         300: (301, CU, {"taban": 1, "yollar": ["baska/x.c"]}),   # DWARF 4: 0. dosya yok
                         400: (401, CU, {"hata": "bozuk"}), 500: (501, CU, None),
                         600: (601, CU, tablo5("src/baska.c"))})                  # ad uyuşmuyor
    c = dt.Cozucu(ana)
    # aynı adlı iki birim, satır tablosundaki yolla ayrışır
    assert ho.birim_yolu(c, dt.ANA, 0, "ortak.c") == ("src/ortak.c", ho.YOL_SATIR_TABLOSU)
    assert ho.birim_yolu(c, dt.ANA, 100, "ortak.c") == ("deps/kitap/ortak.c", ho.YOL_SATIR_TABLOSU)
    assert ho.birim_yolu(c, dt.ANA, 200, "../modules/./v/vek.c") == ("modules/v/vek.c", ho.YOL_SATIR_TABLOSU)
    assert ho.birim_yolu(c, dt.ANA, 300, "lib//x.c") == ("lib/x.c", ho.YOL_AD)
    assert ho.birim_yolu(c, dt.ANA, 400, "y.c") == ("y.c", ho.YOL_AD)
    assert ho.birim_yolu(c, dt.ANA, 500, "z.c") == ("z.c", ho.YOL_AD)
    assert ho.birim_yolu(c, dt.ANA, 600, "w.c") == ("w.c", ho.YOL_AD)
    assert ho.dizin_etiketi("src/ortak.c") == "src" and ho.dizin_etiketi("deps/kitap/ortak.c") == "deps/kitap"
    assert ho.dizin_etiketi("tree.c") == ho.KOK_DIZIN


def test_dwarf_govdeleri(monkeypatch):
    ana = lto_ornegi()
    ana.dieler[40] = die(40, "DW_TAG_subprogram", 0, name=ad_oz("bildirim"))    # low_pc yok: gövde değil
    ana.dieler[50] = die(50, "DW_TAG_variable", 0, low_pc=("DW_FORM_addr", 0x900, 0x900))
    monkeypatch.setattr(dt, "dosya_yukle", lambda yol, rol: ana)
    monkeypatch.setattr(dt, "ek_yukle", lambda a, yol, onbellek=None: (None, "altlink_yok", []))
    govdeler, kunye = ho.dwarf_govdeleri(Path("x.debug"))
    assert sorted((g.adres, g.yol, g.koken, g.yol_kaynagi) for g in govdeler if g.yol) == [
        (0x100, "src/a.c", "kendi", "satir_tablosu"), (0x200, "src/b.c", "koken", "satir_tablosu"),
        (0x400, "src/a.c", "kendi", "satir_tablosu"), (0x500, "src/a.c", "kendi", "satir_tablosu"),
        (0x600, "src/b.c", "koken", "satir_tablosu")]
    assert [(g.adres, g.yol, g.koken) for g in govdeler if not g.yol] == [(0x300, None, None)]
    assert kunye == {"ek_yontemi": "altlink_yok", "govde": 6, "yapay_birimde_govde": 2,
                     "yalniz_ranges_govde": 0, "ayni_adli_kaynak": 0}
    # aynı adı taşıyan iki ayrı kaynak dosya (ayrı dizinlerde) sayılır ve ayrı etiket alır
    ikiz = dwarf([die(1, CU, 0, name=ad_oz("ortak.c")), govde(10, 0, 0x100), govde(11, 0, 0x110),
                  die(101, CU, 100, name=ad_oz("./ortak.c")), govde(110, 100, 0x200),
                  die(201, CU, 200, name=ad_oz("tek.c")), govde(210, 200, 0x300)],
                 {0: (1, CU, tablo5("src/ortak.c")), 100: (101, CU, tablo5("deps/kitap/ortak.c")),
                  200: (201, CU, tablo5("src/tek.c"))})
    monkeypatch.setattr(dt, "dosya_yukle", lambda yol, rol: ikiz)
    govdeler, kunye = ho.dwarf_govdeleri(Path("x.debug"))
    assert sorted({g.yol for g in govdeler}) == ["deps/kitap/ortak.c", "src/ortak.c", "src/tek.c"]
    assert kunye["ayni_adli_kaynak"] == 1 and kunye["govde"] == 4


def test_dwarf_govdeleri_ek_dosya_bulunamazsa_durur(monkeypatch):
    ana = lto_ornegi()
    ana.altlink = ("/usr/lib/debug/.dwz/x.debug", "ab" * 20)
    monkeypatch.setattr(dt, "dosya_yukle", lambda yol, rol: ana)
    monkeypatch.setattr(dt, "ek_yukle", lambda a, yol, onbellek=None: (None, "bulunamadi", []))
    with pytest.raises(ho.OnkosulHatasi, match="ek dosyası bulunamadı"):
        ho.dwarf_govdeleri(Path("x.debug"))


def test_gt_etiketle():
    G = ho.Govde
    ofset = 0x100000
    govdeler = [
        G(0x10, "src/a.c", "kendi", "satir_tablosu"),
        G(0x20, "src/b.c", "koken", "satir_tablosu"),
        G(0x30, None, None, None),                          # yalnız yapay birim
        G(0x40, "src/a.c", "kendi", "satir_tablosu"), G(0x40, "src/b.c", "kendi", "satir_tablosu"),
        G(0x50, "lib/c.c", "kendi", "ad"),
        G(0x60, "src/a.c", "kendi", "satir_tablosu"), G(0x60, None, None, None),   # etiketli + etiketsiz
        G(0x70, "src/a.c", "kendi", "satir_tablosu"),       # GT fonksiyon listesinde yok
        G(0x90, "csu/start.c", "kendi", "satir_tablosu"),   # CRT adı: gövdesi olsa da dışarıda
    ]
    adlar = {ofset + 0x10: ["f1"], ofset + 0x20: ["f2"], ofset + 0x30: ["f3"], ofset + 0x40: ["f4"],
             ofset + 0x50: ["f5"], ofset + 0x60: ["f6", "f6_takma"], ofset + 0x80: ["gövdesiz"],
             ofset + 0x90: ["_start"], ofset + 0xA0: ["frame_dummy", "kendi_adim"]}
    etiket, fonksiyon, sayac = ho.gt_etiketle(adlar, govdeler, ofset)
    assert etiket == {ofset + 0x10: "src/a.c", ofset + 0x20: "src/b.c", ofset + 0x50: "lib/c.c",
                      ofset + 0x60: "src/a.c"}
    assert fonksiyon == set(adlar) - {ofset + 0x90}
    assert sayac == {"gt_fonksiyon": 9, "crt": 1, "govdesiz": 2, "etiketsiz": 1, "celiskili": 1,
                     "etiketli": 4, "koken_birimi": 1, "yol_ad": 1, "kaynak_dosya": 3, "dizin": 2}
    # ofset uygulanmazsa hiçbir adres eşleşmez
    assert ho.gt_etiketle(adlar, govdeler, 0)[0] == {}


def test_gt_oku_ks1_gt_elf_ve_dwarf(monkeypatch):
    """Fonksiyon evreni, hata ayıklama dosyası ve ofset ``ks1_olc.gt_elf``'ten gelir."""
    cagri = {}

    def gt_elf(e, indir):
        cagri["gt_elf"] = (e.ad, indir)
        return ks1.GtBirimi(adlar={0x100010: ["f1"], 0x100020: ["f2"]}, nufus=set(), export_gt=set(),
                            kunye={"debug": "/d/x.debug", "ofset": "0x100000", "ofset_kaynagi": "goruntu_tabani"})

    def govdeler(debug, onbellek=None):
        cagri["debug"] = (debug, onbellek)
        return ([ho.Govde(0x10, "src/a.c", "kendi", "satir_tablosu"),
                 ho.Govde(0x20, "src/b.c", "kendi", "satir_tablosu")],
                {"ek_yontemi": "altlink_yok", "govde": 2, "yapay_birimde_govde": 0, "yalniz_ranges_govde": 0})

    monkeypatch.setattr(ks1, "gt_elf", gt_elf)
    monkeypatch.setattr(ho, "dwarf_govdeleri", govdeler)
    onbellek = {}
    e = ks1.Elf("debian", "p", "x", Path("."), Path("."))
    gt = ho.gt_oku(e, Path("/indir"), onbellek)
    assert cagri["gt_elf"] == ("x", Path("/indir"))
    assert cagri["debug"] == (Path("/d/x.debug"), onbellek) and cagri["debug"][1] is onbellek
    assert gt.etiket == {0x100010: "src/a.c", 0x100020: "src/b.c"}
    assert gt.kunye["ofset_kaynagi"] == "goruntu_tabani" and gt.kunye["dwarf"]["govde"] == 2


# --------------------------------------------------------------------------------------------
# (c) Ölçüler


def test_cift_olculeri_elle_hesap():
    """Modüller (3, 3), sınıflar (2, 2, 2); tablo a:{x:2, y:1}, b:{y:1, z:2}.
    Çiftler: toplam 15, aynı modülde 6, aynı sınıfta 3, ikisi de 2.
    Beklenen = 6·3/15 = 6/5; ARI = (2 − 6/5) / (9/2 − 6/5) = 8/33."""
    u = ["a", "a", "a", "b", "b", "b"]
    v = ["x", "x", "y", "y", "z", "z"]
    tablo = ho.capraz_tablo(u, v)
    assert dict(tablo) == {("a", "x"): 2, ("a", "y"): 1, ("b", "y"): 1, ("b", "z"): 2}
    s = ho.cift_sayilari(tablo)
    assert s == {"n": 6, "toplam": 15, "urun": 6, "gt": 3, "ortak": 2}
    o = ho.cift_olculeri(s)
    assert o == {"kesinlik": F(1, 3), "duyarlilik": F(2, 3), "f1": F(4, 9), "ari": F(8, 33)}


def test_v_olcusu_elle_hesap():
    """Aynı örnek: H(sınıf) = ln 3, H(modül) = ln 2. H(sınıf | modül) = h(2/3, 1/3);
    H(modül | sınıf) = (1/3)·ln 2 (yalnız y sınıfı iki modüle bölünür)."""
    u = ["a", "a", "a", "b", "b", "b"]
    v = ["x", "x", "y", "y", "z", "z"]
    h = -(2 / 3 * math.log(2 / 3) + 1 / 3 * math.log(1 / 3))
    turdeslik = 1 - h / math.log(3)
    tamlik = 1 - (math.log(2) / 3) / math.log(2)
    o = ho.v_olcusu(ho.capraz_tablo(u, v))
    assert o["turdeslik"] == pytest.approx(turdeslik, abs=1e-12)
    assert o["tamlik"] == pytest.approx(tamlik, abs=1e-12) == pytest.approx(2 / 3, abs=1e-12)
    assert o["v"] == pytest.approx(2 * turdeslik * tamlik / (turdeslik + tamlik), abs=1e-12)
    # türdeşlik ile tamlık yer değiştirir: bölmeler yer değişince
    ters = ho.v_olcusu(ho.capraz_tablo(v, u))
    assert ters["turdeslik"] == pytest.approx(tamlik, abs=1e-12)
    assert ters["tamlik"] == pytest.approx(turdeslik, abs=1e-12)


def test_olculer_uc_durum():
    ayni = ho.olculer(["a", "a", "b", "b"], ["x", "x", "y", "y"])
    assert [ayni[a] for a in ho.OLCU_ADLARI] == [1, 1, 1, 1, 1.0, 1.0, 1.0] and ayni["modul"] == 2
    # dik bölmeler: ortak çift yok; ARI rastgelenin altında (negatif)
    dik = ho.olculer(["a", "a", "b", "b"], ["x", "y", "x", "y"])
    assert [dik[a] for a in ho.CIFT_OLCULERI] == [0, 0, 0, F(-1, 2)]
    assert dik["turdeslik"] == pytest.approx(0, abs=1e-12) and dik["v"] == 0.0
    # modül, sınıfın alt bölmesi: kesinlik 1, duyarlılık < 1; türdeşlik 1, tamlık < 1
    ince = ho.olculer(["a", "a", "b", "b", "c", "c"], ["x", "x", "x", "x", "y", "y"])
    assert ince["kesinlik"] == 1 and ince["duyarlilik"] == F(3, 7)
    assert ince["turdeslik"] == pytest.approx(1.0) and ince["tamlik"] < 1
    # sınıf, modülün alt bölmesi: tersi
    kaba = ho.olculer(["a", "a", "a", "a", "b", "b"], ["x", "x", "y", "y", "z", "z"])
    assert kaba["duyarlilik"] == 1 and kaba["kesinlik"] == F(3, 7)
    assert kaba["tamlik"] == pytest.approx(1.0) and kaba["turdeslik"] < 1


def test_olculer_yozlasmis_sinirlar():
    v = ["x"] * 4 + ["y"] * 4 + ["z"] * 4
    tek = ho.olculer([0] * 12, v)
    # tek modül: her çift aynı modülde; kesinlik = GT çift yoğunluğu, duyarlılık 1, ARI 0
    assert tek["kesinlik"] == F(18, 66) and tek["duyarlilik"] == 1 and tek["ari"] == 0
    assert tek["turdeslik"] == pytest.approx(0, abs=1e-12) and tek["tamlik"] == 1.0 and tek["v"] == 0.0
    ayri = ho.olculer(list(range(12)), v)
    # her fonksiyon ayrı: aynı modülde çift yok; kesinlik tanımsız, duyarlılık 0, ARI 0
    assert ayri["kesinlik"] is None and ayri["duyarlilik"] == 0 and ayri["f1"] == 0 and ayri["ari"] == 0
    # V-ölçüsü şansa göre düzeltilmez: hepsi ayrı bölmede türdeşlik 1 ve V sıfırdan büyük
    assert ayri["turdeslik"] == 1.0 and ayri["v"] > 0.5
    # iki bölme de tek öbek: ARI tanımsız (payda sıfır)
    assert ho.olculer([0] * 5, ["x"] * 5)["ari"] is None
    assert ho.cift_olculeri({"n": 1, "toplam": 0, "urun": 0, "gt": 0, "ortak": 0}) == {
        "kesinlik": None, "duyarlilik": None, "f1": None, "ari": None}
    assert ho.v_olcusu(ho.capraz_tablo([], [])) == {"turdeslik": None, "tamlik": None, "v": None}
    with pytest.raises(ValueError, match="eşit uzunlukta"):
        ho.capraz_tablo([1, 2], [1])


def test_olculer_kaba_kuvvetle_ayni():
    """Formüller, çiftleri tek tek sayan ve koşullu entropiyi tanımından hesaplayan bağımsız yolla aynı."""
    rng = random.Random(20261111)
    for _ in range(40):
        n = rng.randint(4, 40)
        u = [rng.randrange(rng.randint(1, 6)) for _ in range(n)]
        v = [rng.randrange(rng.randint(2, 7)) for _ in range(n)]
        o = ho.olculer(u, v)
        s = kaba_cift(u, v)
        assert o["cift"] == s
        if F(s["urun"] + s["gt"], 2) != F(s["urun"] * s["gt"], s["toplam"]):
            assert o["ari"] == kaba_ari(u, v)
        if s["urun"]:
            assert o["kesinlik"] == F(s["ortak"], s["urun"])
        if s["gt"]:
            assert o["duyarlilik"] == F(s["ortak"], s["gt"])
        h_v, h_u = kaba_entropi(v), kaba_entropi(u)
        if h_v > 0:
            assert o["turdeslik"] == pytest.approx(1 - kaba_kosullu_entropi(v, u) / h_v, abs=1e-9)
        if h_u > 0:
            assert o["tamlik"] == pytest.approx(1 - kaba_kosullu_entropi(u, v) / h_u, abs=1e-9)


def test_bitisiklik_ve_modul_turu_dokumu():
    b = ho.bitisiklik(["a", "a", "b", "b", "c"])
    assert b == {"kosu": 3, "sinif": 3, "oran": 1}
    b = ho.bitisiklik(["a", "b", "a", "b", "a", "c"])
    assert b == {"kosu": 6, "sinif": 3, "oran": F(1, 2)}
    assert ho.bitisiklik(["a", "b", "a"]) == {"kosu": 3, "sinif": 2, "oran": F(2, 3)}   # ilk öbek de sayılır
    assert ho.bitisiklik([]) == {"kosu": 0, "sinif": 0, "oran": None}
    moduller = ["subsystem_group_0"] * 3 + ["subsystem_group_1"] * 2 + ["subsystem_misc"] * 3 + [
        "subsystem_memory", "subsystem_memory", "."]
    siniflar = ["a", "a", "b", "c", "c", "a", "b", "c", "d", "d", "e"]
    d = ho.modul_turu_dokumu(moduller, siniflar)
    assert d["topluluk"] == {"modul": 2, "fonksiyon": 5, "cift": 3 + 1, "ortak": 1 + 1}
    assert d["misc"] == {"modul": 1, "fonksiyon": 3, "cift": 3, "ortak": 0}
    assert d["kural"] == {"modul": 1, "fonksiyon": 2, "cift": 1, "ortak": 1}
    assert d["giris"] == {"modul": 1, "fonksiyon": 1, "cift": 0, "ortak": 0}
    assert d["diger"] == {"modul": 0, "fonksiyon": 0, "cift": 0, "ortak": 0}
    # türlerin toplamı bütünün çift sayılarıdır
    s = ho.cift_sayilari(ho.capraz_tablo(moduller, siniflar))
    assert sum(t["cift"] for t in d.values()) == s["urun"]
    assert sum(t["ortak"] for t in d.values()) == s["ortak"]


# --------------------------------------------------------------------------------------------
# (d) Tabanlar


def test_b1_bolme():
    assert ho.b1_bolme(7, 3) == [0, 0, 0, 1, 1, 2, 2]
    assert ho.b1_bolme(6, 3) == [0, 0, 1, 1, 2, 2]
    assert ho.b1_bolme(5, 1) == [0] * 5
    assert ho.b1_bolme(4, 4) == [0, 1, 2, 3]
    for n, k in ((100, 7), (13, 13), (50, 9)):
        b = ho.b1_bolme(n, k)
        boyut = [b.count(i) for i in range(k)]
        assert len(b) == n and b == sorted(b) and max(boyut) - min(boyut) <= 1 and min(boyut) >= 1
    for n, k in ((5, 0), (5, 6)):
        with pytest.raises(ValueError):
            ho.b1_bolme(n, k)


def test_misc_tekil_ve_yuzdelik():
    m = ["subsystem_misc", "subsystem_group_0", "subsystem_misc", "subsystem_group_0"]
    t = ho.misc_tekil(m)
    assert t[1] == t[3] == "subsystem_group_0" and t[0] != t[2] and len(set(t)) == 3
    assert ho.yuzdelik(list(range(1, 201))) == 190         # ⌈0,95 · 200⌉ = 190. değer
    assert ho.yuzdelik([5, 1, 3]) == 5 and ho.yuzdelik([7]) == 7
    assert ho.yuzdelik(list(range(1, 101)), F(1, 2)) == 50


def test_b0_ozeti():
    v = ["x"] * 10 + ["y"] * 10 + ["z"] * 10
    u = ["a"] * 10 + ["b"] * 20                          # ilk dosya ayrı modül, öbür ikisi birleşik
    urun = ho.olculer(u, v)
    assert urun["cift"] == {"n": 30, "toplam": 435, "urun": 235, "gt": 135, "ortak": 135}
    b0 = ho.b0_ozeti(u, v, "tohum-1", urun["ari"])
    assert b0["adet"] == ho.B0_PERMUTASYON == 200 and b0["modul"] == 2
    # boyutlar korunur: kapalı biçim beklenen değerler (kesinlik = GT çift yoğunluğu, duyarlılık =
    # ürün çift yoğunluğu, ARI 0) ve karmaların ortalaması
    assert b0["beklenen"] == {"kesinlik": F(135, 435), "duyarlilik": F(235, 435), "ari": 0}
    assert abs(b0["ari"]) < 0.03
    assert b0["kesinlik"] == pytest.approx(135 / 435, abs=0.02)
    assert b0["duyarlilik"] == pytest.approx(235 / 435, abs=0.02)
    assert 0 < b0["ari_p95"] < 0.2 < urun["ari"]
    # ürünün uyumunu hiçbir karma yakalamaz: p = 1 / (adet + 1)
    assert b0["ari_p"] == F(1, 201)
    # eşitlik de sayılır: dört fonksiyonda tam uyumu karmaların yaklaşık üçte biri yakalar
    p4 = ho.b0_ozeti(["a", "a", "b", "b"], ["x", "x", "y", "y"], "tohum-1", F(1), adet=60)["ari_p"]
    assert F(1, 6) < p4 < F(1, 2)
    # aynı tohum aynı sonuç; başka tohum başka karmalar
    assert ho.b0_ozeti(u, v, "tohum-1", urun["ari"]) == b0
    assert ho.b0_ozeti(u, v, "tohum-2", urun["ari"])["ari"] != b0["ari"]
    # ürün rastgele düzeyindeyse p büyük
    rng = random.Random(7)
    karisik = list(u)
    rng.shuffle(karisik)
    p = ho.b0_ozeti(karisik, v, "tohum-1", ho.olculer(karisik, v)["ari"])["ari_p"]
    assert p > F(1, 20)
    # az karmayla: p paydası adet + 1
    assert ho.b0_ozeti(u, v, "tohum-1", urun["ari"], adet=9)["ari_p"] == F(1, 10)


# --------------------------------------------------------------------------------------------
# (e) Giriş kuralı ve ikili düzeyi


def test_giris_engeli():
    on = ["a"] * 5 + ["b"] * 5
    assert ho.giris_engeli(10, on) is None
    assert ho.giris_engeli(9, on[:9]) == ho.NEDEN_KUCUK
    assert ho.giris_engeli(12, ["a"] * 12) == ho.NEDEN_TEK_SINIF
    assert ho.giris_engeli(12, list(range(12))) == ho.NEDEN_HEPSI_AYRI
    assert ho.giris_engeli(11, list(range(10)) + [0]) is None       # tek bir çift yeter
    assert ho.giris_engeli(10, on, yol_ad=1) == ho.NEDEN_YOL_AD


def test_duzey_olcumu_satirlar():
    """Bitişik üç dosya (dörder fonksiyon), ürün iki modül (6 + 6): B1 ürünle aynı bölme, GT sayısıyla
    bölme tam uyum."""
    siniflar = ["a.c"] * 4 + ["b.c"] * 4 + ["c.c"] * 4
    moduller = ["subsystem_group_0"] * 6 + ["subsystem_misc"] * 6
    d = ho.duzey_olcumu(moduller, siniflar, "tohum")
    assert (d["n"], d["modul"], d["sinif"], d["giris"], d["neden"]) == (12, 2, 3, True, None)
    s = d["satirlar"]
    assert set(s) == set(ho.SATIRLAR)
    # ürün: aynı modülde 2·C(6,2) = 30 çift; aynı dosyada 3·C(4,2) = 18; ikisi de 2·(6 + 1) = 14
    assert s["urun"]["cift"] == {"n": 12, "toplam": 66, "urun": 30, "gt": 18, "ortak": 14}
    assert s["urun"]["kesinlik"] == F(14, 30) and s["urun"]["duyarlilik"] == F(14, 18)
    assert s["urun"]["ari"] == kaba_ari(moduller, siniflar)
    assert s["b1"]["ari"] == s["urun"]["ari"] and s["b1"]["modul"] == 2
    assert s["b1_gt"]["ari"] == 1 and s["b1_gt"]["modul"] == 3
    assert s["tek_modul"]["ari"] == 0 and s["tek_modul"]["modul"] == 1
    assert s["hepsi_ayri"]["ari"] == 0 and s["hepsi_ayri"]["modul"] == 12
    # misc tekil: misc'teki 15 çift kalkar; kalan modülde 15 çiftin 7'si aynı dosyada
    assert s["urun_misc_tekil"]["cift"]["urun"] == 15 and s["urun_misc_tekil"]["cift"]["ortak"] == 7
    assert s["urun_misc_tekil"]["modul"] == 7
    assert s["b0"]["adet"] == 200 and s["b0"]["ari_p"] is not None
    assert d["bitisiklik"] == {"kosu": 3, "sinif": 3, "oran": 1}
    assert d["modul_turleri"]["topluluk"]["cift"] == 15 and d["modul_turleri"]["misc"]["ortak"] == 7
    # giremeyen ikilide satır hesaplanmaz
    kucuk = ho.duzey_olcumu(moduller[:8], siniflar[:8], "tohum")
    assert kucuk == {"n": 8, "modul": 2, "sinif": 2, "giris": False, "neden": ho.NEDEN_KUCUK}


def test_b1_adres_sirasina_dayanir():
    """Serpik GT'de (a, b, c, a, b, c, …) bitişik bölme kaynak dosyayı yakalayamaz; ürün yakalar."""
    siniflar = ["a.c", "b.c", "c.c"] * 4
    moduller = ["subsystem_group_0", "subsystem_group_1", "subsystem_group_2"] * 4
    d = ho.duzey_olcumu(moduller, siniflar, "tohum")
    assert d["satirlar"]["urun"]["ari"] == 1
    assert d["satirlar"]["b1"]["ari"] < 0
    assert d["bitisiklik"]["oran"] == F(3, 12)


def test_elf_olcumu_ortak_nufus_ve_ogeler():
    gt = gt_tarafi({**uc_dosya(), 0x9000: "src/a.c"})            # 0x9000: üründe yok
    atama = {a: f"subsystem_group_{i // 4}" for i, a in enumerate(ADRESLER)}
    atama[0x8000] = "subsystem_misc"                              # GT etiketi yok
    urun = ho.UrunTarafi(atama, {})
    assert ho.ortak_nufus(urun, gt) == ADRESLER
    e = ho.elf_olcumu(urun, gt, "tohum")
    assert e["duzeyler"]["dosya"]["n"] == 12 and e["duzeyler"]["dosya"]["sinif"] == 3
    assert e["duzeyler"]["dizin"]["sinif"] == 2                   # src, lib
    assert e["duzeyler"]["dosya"]["satirlar"]["urun"]["ari"] == 1
    # dizin düzeyi: src (8) + lib (4); ürünün üç modülü src'yi ikiye böler
    assert e["duzeyler"]["dizin"]["satirlar"]["urun"]["kesinlik"] == 1
    assert e["duzeyler"]["dizin"]["satirlar"]["urun"]["duyarlilik"] == F(18, 34)
    assert e["moduller"] == ["subsystem_group_0", "subsystem_group_1", "subsystem_group_2"]
    # öğeler: adres → "modül no  dosya no  dizin no" (sınıflar yol sırasıyla numaralanır; ad yok)
    assert e["ogeler"]["1000"] == "0 1 1" and e["ogeler"]["1040"] == "1 2 1" and e["ogeler"]["1080"] == "2 0 0"
    assert set(e["ogeler"]) == {f"{a:x}" for a in ADRESLER}
    # yolu satır tablosundan okunamayan etiket varsa ikili iki düzeyde de dışarıda (bütünlük koşulu)
    disarida = ho.elf_olcumu(urun, gt_tarafi(uc_dosya(), yol_ad=2), "tohum")
    assert [disarida["duzeyler"][d]["neden"] for d in ho.DUZEYLER] == [ho.NEDEN_YOL_AD] * 2
    # huninin giriş öngörüsü ölçümle aynı kuralı uygular
    assert ho.huni(urun, gt, set(ADRESLER))["ortak"]["giris"] == {"dosya": None, "dizin": None}
    assert ho.huni(urun, gt_tarafi(uc_dosya(), yol_ad=2), set(ADRESLER))["ortak"]["giris"] == {
        "dosya": ho.NEDEN_YOL_AD, "dizin": ho.NEDEN_YOL_AD}


# --------------------------------------------------------------------------------------------
# (f) Toplama ve karar


def _elf(ari, giris=True, duzey="dosya"):
    satirlar = {s: {a: None for a in ho.OLCU_ADLARI} for s in ho.SATIRLAR}
    satirlar["urun"]["ari"] = ari
    return {"duzeyler": {duzey: {"giris": giris, "neden": None if giris else "kucuk", "satirlar": satirlar}}}


def test_ortalama_birim_program_makro():
    assert ho.ortalama([F(1, 2), None, F(1, 4)]) == F(3, 8)
    assert ho.ortalama([None]) is None and ho.ortalama([]) is None
    elfler = [_elf(F(1, 2)), _elf(F(1, 4)), _elf(F(9, 10), giris=False)]
    assert ho.birim_degeri(elfler, "dosya", "urun", "ari") == F(3, 8)      # giremeyen ikili sayılmaz
    assert ho.birim_degeri([_elf(F(1), giris=False)], "dosya", "urun", "ari") is None
    # aynı programın platform birimleri önce ortalanır, sonra programlar eşit ağırlıkla
    birimler = {"mac/tmux": F(1, 5), "debian/tmux": F(3, 5), "debian/tree": F(1), "debian/sqlite3": None}
    assert ho.program_degerleri(birimler) == {"tmux": F(2, 5), "tree": F(1)}
    m = ho.makro(birimler)
    assert m["makro"] == F(7, 10) and m["giren_birimler"] == ["debian/tmux", "debian/tree", "mac/tmux"]
    # 106 ikilili bir program tek ikilili programla eşit ağırlıkta
    cok = {"debian/coreutils": ho.birim_degeri([_elf(F(0))] * 106, "dosya", "urun", "ari"),
           "debian/tree": F(1)}
    assert ho.makro(cok)["makro"] == F(1, 2)
    assert ho.makro({})["makro"] is None


def test_karsilastirma_karari():
    K = ho.karsilastirma_karari
    urun = {"a": F(5, 10), "b": F(4, 10), "c": F(6, 10)}
    taban = {"a": F(2, 10), "b": F(3, 10), "c": F(7, 10)}
    k = K(urun, taban)
    # farklar +0,3, +0,1, −0,1: makro +0,1 ≥ 0,05; pozitif 2 ≥ ⌈2/3 · 3⌉ = 2
    assert k["farklar"] == {"a": F(3, 10), "b": F(1, 10), "c": F(-1, 10)}
    assert (k["makro_fark"], k["pozitif"], k["negatif"], k["gerekli"]) == (F(1, 10), 2, 1, 2)
    assert k["karar"] == ho.KARAR_URUN
    assert K(taban, urun)["karar"] == ho.KARAR_TABAN
    # fark eşiğin altında: ayrışmıyor (iki yönde de)
    yakin = {"a": F(24, 100), "b": F(34, 100), "c": F(74, 100)}
    assert K(yakin, taban)["makro_fark"] == F(4, 100) and K(yakin, taban)["karar"] == ho.KARAR_AYRISMIYOR
    assert K(taban, yakin)["karar"] == ho.KARAR_AYRISMIYOR
    # fark tam eşikte: geçer
    esikte = {p: v + F(5, 100) for p, v in taban.items()}
    assert K(esikte, taban)["karar"] == ho.KARAR_URUN and K(taban, esikte)["karar"] == ho.KARAR_TABAN
    # makro büyük ama yön çoğunlukta değil (tek program taşıyor): ayrışmıyor
    tek = {"a": F(99, 100), "b": F(29, 100), "c": F(69, 100)}
    k = K(tek, taban)
    assert k["makro_fark"] > ho.FARK_ESIGI and k["pozitif"] == 1 and k["karar"] == ho.KARAR_AYRISMIYOR
    assert K(taban, tek)["negatif"] == 1 and K(taban, tek)["karar"] == ho.KARAR_AYRISMIYOR
    # yedi programda çoğunluk 5
    assert K({str(i): F(1) for i in range(7)}, {str(i): F(0) for i in range(7)})["gerekli"] == 5
    # yalnız iki tarafta da değeri olan programlar; en az iki program
    assert K({"a": F(1), "b": F(1)}, {"a": F(0), "z": F(0)})["karar"] == ho.KARAR_YETERSIZ
    assert K({}, {})["karar"] == ho.KARAR_YETERSIZ
    assert K({"a": F(1), "b": F(1)}, {"a": F(0), "b": F(0)})["karar"] == ho.KARAR_URUN


def test_rastgele_karari():
    R = ho.rastgele_karari
    p95 = {"a": F(1, 20), "b": F(1, 20), "c": F(1, 20)}
    assert R({"a": F(1, 2), "b": F(1, 10), "c": F(0)}, p95) == {
        "programlar": ["a", "b", "c"], "ustte": 2, "gerekli": 2, "karar": ho.KARAR_RASTGELEDEN_IYI}
    assert R({"a": F(1, 2), "b": F(1, 20), "c": F(0)}, p95)["karar"] == ho.KARAR_AYIRT_EDILEMIYOR   # eşit: üstte değil
    assert R({"a": F(1)}, {"a": F(0)})["karar"] == ho.KARAR_YETERSIZ


def test_duzey_ozeti_kararlari():
    """Kararlar doğru satırlardan beslenir: rastgeleye karşı B0'ın 95. yüzdeliği (ortalaması değil),
    B1'e karşı ürünün modül sayısıyla bölme (GT sınıf sayısıyla olan değil)."""
    def ikili(urun, b0, b0_p95, b1, b1_gt):
        satirlar = {s: {a: None for a in ho.OLCU_ADLARI} for s in ho.SATIRLAR}
        satirlar["urun"]["ari"], satirlar["b0"]["ari"], satirlar["b1"]["ari"] = urun, b0, b1
        satirlar["b1_gt"]["ari"], satirlar["b0"]["ari_p95"] = b1_gt, b0_p95
        return {"duzeyler": {"dosya": {
            "giris": True, "neden": None, "satirlar": satirlar, "bitisiklik": {"oran": urun},
            "modul_turleri": {"topluluk": {"modul": 2, "fonksiyon": 8, "cift": 12, "ortak": 5}}}}}

    birimler = {
        "debian/a": {"elfler": {"x": ikili(F(50, 100), F(0), F(10, 100), F(20, 100), F(90, 100)),
                                "y": ikili(F(30, 100), F(0), F(10, 100), F(20, 100), F(90, 100))}},
        "debian/b": {"elfler": {"z": ikili(F(8, 100), F(0), F(10, 100), F(2, 100), F(80, 100))}},
        "debian/c": {"elfler": {"w": ikili(F(60, 100), F(0), F(10, 100), F(40, 100), F(95, 100)),
                                "disarida": {"duzeyler": {"dosya": {"giris": False, "neden": "kucuk"}}}}},
    }
    o = ho.duzey_ozeti(birimler, "dosya")
    assert o["giren_ikili"] == {"debian/a": 2, "debian/b": 1, "debian/c": 1}
    assert o["disarida"] == {"kucuk": 1}
    assert o["satirlar"]["urun"]["ari"]["program"] == {"a": F(40, 100), "b": F(8, 100), "c": F(60, 100)}
    # b programı B0 ortalamasının üstünde ama 95. yüzdeliğinin altında
    assert o["kararlar"]["rastgele"] == {"programlar": ["a", "b", "c"], "ustte": 2, "gerekli": 2,
                                         "karar": ho.KARAR_RASTGELEDEN_IYI}
    kb = o["kararlar"]["b1"]
    assert kb["farklar"] == {"a": F(20, 100), "b": F(6, 100), "c": F(20, 100)}
    assert kb["karar"] == ho.KARAR_URUN
    # yalnız rapor: bitişiklik program düzeyi makro, modül türü dökümü giren ikililerin toplamı
    assert o["bitisiklik"]["program"] == {"a": F(40, 100), "b": F(8, 100), "c": F(60, 100)}
    assert o["bitisiklik"]["makro"] == F(36, 100)
    assert o["modul_turleri"]["topluluk"] == {"modul": 8, "fonksiyon": 32, "cift": 48, "ortak": 20}
    assert o["modul_turleri"]["misc"] == {"modul": 0, "fonksiyon": 0, "cift": 0, "ortak": 0}
    birimler["debian/a"]["elfler"]["x"]["duzeyler"]["dosya"]["satirlar"]["urun"]["ari"] = F(-10, 100)
    birimler["debian/a"]["elfler"]["y"]["duzeyler"]["dosya"]["satirlar"]["urun"]["ari"] = F(0)
    assert ho.duzey_ozeti(birimler, "dosya")["kararlar"]["rastgele"]["karar"] == ho.KARAR_AYIRT_EDILEMIYOR


# --------------------------------------------------------------------------------------------
# (g) olc uçtan uca


def olcum_kur(tmp_path, monkeypatch):
    """Üç program, bilinen cevap (dosya düzeyi):
    - alfa: GT bitişik, ürün dosyayla aynı → ürün ARI 1, B1 ARI 1;
    - beta: GT bitişik, ürün serpik (mod 3) → ürün ARI < 0, B1 ARI 1;
    - gama: GT serpik, ürün dosyayla aynı → ürün ARI 1, B1 ARI < 0.
    Ayrıca: küçük ikili (nüfus < N_MIN), C++ ikili, Mach-O ikili (GT etiketi yok)."""
    kok = tmp_path / "debian"
    fonksiyonlar = [fonk(a) for a in ADRESLER] + [fonk(0x5000, "malloc", thunk=True)]
    ayni = {a: f"subsystem_group_{i // 4}" for i, a in enumerate(ADRESLER)}
    serpik = {a: f"subsystem_group_{i % 3}" for i, a in enumerate(ADRESLER)}
    alan_kur(kok, "debian", "alfa", "alfa", fonksiyonlar, yerlesim_kur({**ayni, 0x5000: "subsystem_memory"}))
    alan_kur(kok, "debian", "alfa", "alfa2", fonksiyonlar, yerlesim_kur(ayni))     # alfa ile aynı veri
    alan_kur(kok, "debian", "beta", "beta", fonksiyonlar, yerlesim_kur(serpik))
    alan_kur(kok, "debian", "gama", "gama", fonksiyonlar, yerlesim_kur(serpik))
    alan_kur(kok, "debian", "gama", "kucuk", fonksiyonlar[:6], yerlesim_kur({a: "subsystem_misc" for a in ADRESLER[:6]}))
    alan_kur(kok, "debian", "gama", "cpp", fonksiyonlar + [fonk(0x6000, "__cxa_throw", thunk=True)],
             yerlesim_kur(ayni))
    mac = tmp_path / "mac"
    alan_kur(mac, "mac", "alfa", "alfa", fonksiyonlar, yerlesim_kur(ayni))
    gt_tak(monkeypatch, {"alfa": gt_tarafi(uc_dosya()), "alfa2": gt_tarafi(uc_dosya()),
                         "beta": gt_tarafi(uc_dosya()), "gama": gt_tarafi(uc_dosya("serpik")),
                         "kucuk": gt_tarafi({a: "src/a.c" for a in ADRESLER[:6]})})
    elfler = ks1.elfleri_topla(mac, kok)
    beklenen = {"debian/alfa": 2, "debian/beta": 1, "debian/gama": 3, "mac/alfa": 1}
    return elfler, beklenen


def test_olc_uctan_uca(tmp_path, monkeypatch):
    elfler, beklenen = olcum_kur(tmp_path, monkeypatch)
    s = ho.olc(elfler, None, None, denetle=False, beklenen=beklenen)
    assert s["sema"] == ho.SEMA and s["onkosul"] == {"denetlenmedi": True}
    # Mach-O: GT derleme birimi taşımıyor, ölçülmez; C++ dışarıda
    assert s["gt_etiketsiz"] == {"mac/alfa/alfa": ho.MAC_GT_NEDENI}
    assert s["birimler"]["debian/gama"]["cpp_disarida"] == ["cpp"]
    assert sorted(s["birimler"]) == ["debian/alfa", "debian/beta", "debian/gama"]
    assert sorted(s["birimler"]["debian/gama"]["elfler"]) == ["gama", "kucuk"]

    def satir(birim, elf, ad, duzey="dosya"):
        return s["birimler"][birim]["elfler"][elf]["duzeyler"][duzey]["satirlar"][ad]

    serpik = [f"g{i % 3}" for i in range(12)]
    bitisik = [f"d{i // 4}" for i in range(12)]
    beta_ari = kaba_ari(serpik, bitisik)
    assert beta_ari < 0
    assert satir("debian/alfa", "alfa", "urun")["ari"] == 1 and satir("debian/alfa", "alfa", "b1")["ari"] == 1
    assert satir("debian/beta", "beta", "urun")["ari"] == beta_ari and satir("debian/beta", "beta", "b1")["ari"] == 1
    assert satir("debian/gama", "gama", "urun")["ari"] == 1 and satir("debian/gama", "gama", "b1")["ari"] == beta_ari
    # B0 tohumu ikiliye bağlı: aynı veriyi taşıyan iki ikilinin karmaları ayrı
    assert satir("debian/alfa", "alfa", "urun") == satir("debian/alfa", "alfa2", "urun")
    assert satir("debian/alfa", "alfa", "b0")["ari"] != satir("debian/alfa", "alfa2", "b0")["ari"]
    # thunk (GT etiketi yok) nüfusa girmez
    assert s["birimler"]["debian/alfa"]["elfler"]["alfa"]["duzeyler"]["dosya"]["n"] == 12
    assert s["birimler"]["debian/alfa"]["elfler"]["alfa"]["huni"]["urun"]["atanan"] == 13
    # küçük ikili ölçüye girmez; birimin değeri giren tek ikiliden
    kucuk = s["birimler"]["debian/gama"]["elfler"]["kucuk"]["duzeyler"]["dosya"]
    assert (kucuk["giris"], kucuk["neden"], kucuk["n"]) == (False, ho.NEDEN_KUCUK, 6)
    o = s["ozet"]["dosya"]
    assert o["giren_ikili"] == {"debian/alfa": 2, "debian/beta": 1, "debian/gama": 1}
    assert o["disarida"] == {ho.NEDEN_KUCUK: 1}
    urun = o["satirlar"]["urun"]["ari"]
    assert urun["program"] == {"alfa": 1, "beta": beta_ari, "gama": 1}
    assert urun["makro"] == (2 + beta_ari) / 3
    assert o["satirlar"]["b1"]["ari"]["program"] == {"alfa": 1, "beta": 1, "gama": beta_ari}
    assert o["satirlar"]["tek_modul"]["ari"]["makro"] == 0 and o["satirlar"]["hepsi_ayri"]["ari"]["makro"] == 0
    assert abs(o["satirlar"]["b0"]["ari"]["makro"]) < 0.05
    kb = o["kararlar"]["b1"]
    assert kb["farklar"] == {"alfa": 0, "beta": beta_ari - 1, "gama": 1 - beta_ari}
    assert kb["makro_fark"] == 0 and kb["karar"] == ho.KARAR_AYRISMIYOR
    kr = o["kararlar"]["rastgele"]
    assert (kr["ustte"], kr["gerekli"], kr["karar"]) == (2, 2, ho.KARAR_RASTGELEDEN_IYI)
    # yalnız rapor: bitişiklik (alfa ve beta bitişik, gama serpik) ve modül türü dökümü.
    # Giren dört ikilide üçer topluluk modülü (dörder fonksiyon): 4 · 3 · C(4,2) = 72 çift;
    # aynı dosyada olanlar: alfa 18, alfa2 18, beta 3, gama 18
    assert o["bitisiklik"]["program"] == {"alfa": 1, "beta": 1, "gama": F(3, 12)}
    assert o["modul_turleri"]["topluluk"] == {"modul": 12, "fonksiyon": 48, "cift": 72, "ortak": 57}
    assert o["modul_turleri"]["kural"]["fonksiyon"] == 0          # thunk'ın modülü nüfusta yok
    # dizin düzeyi: iki sınıf (src, lib); aynı ikililer girer
    assert s["ozet"]["dizin"]["giren_ikili"] == o["giren_ikili"]
    assert satir("debian/alfa", "alfa", "urun", "dizin")["kesinlik"] == 1


def test_olc_ciktisinda_ad_yok_ve_belirlenimli(tmp_path, monkeypatch):
    elfler, beklenen = olcum_kur(tmp_path, monkeypatch)
    s1 = ho.olc(elfler, None, None, denetle=False, beklenen=beklenen)
    s2 = ho.olc(elfler, None, None, denetle=False, beklenen=beklenen)
    j1 = json.dumps(ho.yuvarla(s1), ensure_ascii=False, sort_keys=True)
    assert j1 == json.dumps(ho.yuvarla(s2), ensure_ascii=False, sort_keys=True)
    md = ho.olc_markdown(s1)
    for metin in (j1, md):
        for yasak in ("src/a.c", "src/b.c", "lib/c.c", "a.c", "FUN_", "islev", "malloc"):
            assert yasak not in metin, yasak
    assert "ayrismiyor" in md and "rastgeleden_iyi" in md and "mac/alfa/alfa" in md
    assert "| `topluluk` | 12 | 48 | 72 | 57 | 0,792 |" in md and "GT bitişikliği" in md
    assert "Koşu künyesi: okunmadı" in md
    # yuvarlanmış çıktı JSON'a yazılabilir; kesirler ondalığa döner
    geri = json.loads(j1)
    assert geri["ozet"]["dosya"]["satirlar"]["urun"]["ari"]["program"]["alfa"] == 1.0
    assert geri["secimler"]["fark_esigi"] == 0.05


def test_olc_eksik_kosuda_durur(tmp_path, monkeypatch):
    elfler, beklenen = olcum_kur(tmp_path, monkeypatch)
    with pytest.raises(ho.OnkosulHatasi, match="nüfus eksik"):
        ho.olc(elfler, None, None, denetle=False, beklenen={**beklenen, "debian/alfa": 3})
    # proje ağacı yazılmamış koşu bitmemiş sayılır
    alan_kur(tmp_path / "debian", "debian", "beta", "projesiz", [fonk(a) for a in ADRESLER])
    elfler = ks1.elfleri_topla(tmp_path / "mac", tmp_path / "debian")
    with pytest.raises(ho.OnkosulHatasi, match="bitmemiş"):
        ho.olc(elfler, None, None, denetle=False, beklenen={**beklenen, "debian/beta": 2})
    s = ho.olc(elfler, None, None, denetle=False, beklenen={**beklenen, "debian/beta": 2}, eksik_izinli=True)
    assert sorted(s["birimler"]["debian/beta"]["elfler"]) == ["beta"]
    assert any("projesiz" in x for x in s["nufus"]["sorunlar"])


def test_olc_gt_hatasinda_durur(tmp_path, monkeypatch):
    elfler, beklenen = olcum_kur(tmp_path, monkeypatch)
    gt_tak(monkeypatch, {"alfa": ho.OnkosulHatasi("ofset kanıtlanamıyor")})
    with pytest.raises(ho.OnkosulHatasi, match="ofset"):
        ho.olc(elfler, None, None, denetle=False, beklenen=beklenen)


def test_olc_on_kosul_once_denetlenir(monkeypatch):
    """Ön kayıt tutmuyorsa ölçüm hiçbir veri okumadan durur."""
    def tutmaz():
        raise ho.OnkosulHatasi("ön kayıt commit'lenmemiş: sentetik")
    monkeypatch.setattr(ho, "onkosullari_denetle", tutmaz)

    class Patlar:
        def __iter__(self):
            raise AssertionError("ön koşuldan önce veri okundu")
    with pytest.raises(ho.OnkosulHatasi, match="commit'lenmemiş"):
        ho.olc(Patlar(), None, None)


def test_main_olc_on_kosulsuz_kosmaz(tmp_path, monkeypatch, capsys):
    """CLI'da ``olc`` her zaman ön koşulları denetler (``denetle`` kapatılamaz)."""
    elfler, _ = olcum_kur(tmp_path, monkeypatch)
    gorulen = {}

    def sahte_olc(elfler, indir, mac_veri, **kw):
        gorulen.update(kw)
        raise ho.OnkosulHatasi("ön kayıt commit'lenmemiş: sentetik")
    monkeypatch.setattr(ho, "olc", sahte_olc)
    kod = ho.main(["olc", "--debian-kosu", str(tmp_path / "debian"), "--json", str(tmp_path / "o.json")])
    assert kod == 2 and "DURDU" in capsys.readouterr().err
    assert "denetle" not in gorulen and not (tmp_path / "o.json").exists()


def test_main_olc_ciktilari_yazar(tmp_path, monkeypatch, capsys):
    """Ön koşullar tutunca ``olc`` komutu JSON ve Markdown'u yazar (sentetik nüfus; ön koşul denetimi
    burada sahtesiyle değiştirilir, komutun kendisi kapatamaz)."""
    elfler, beklenen = olcum_kur(tmp_path, monkeypatch)
    monkeypatch.setattr(ho, "onkosullari_denetle", lambda: {"onkayit_commit": "a" * 40, "sha256": {}})
    asil = ho.olc
    monkeypatch.setattr(ho, "olc", lambda elfler, indir, mac_veri, eksik_izinli=False: asil(
        elfler, indir, mac_veri, beklenen=beklenen, eksik_izinli=eksik_izinli))
    (tmp_path / "kosu_kunyesi.json").write_text(json.dumps({"agac": {"commit": "c" * 40, "kirli": []}}))
    kod = ho.main(["olc", "--debian-kosu", str(tmp_path / "debian"), "--mac-kosu", str(tmp_path / "mac"),
                   "--json", str(tmp_path / "o.json"), "--md", str(tmp_path / "o.md")])
    assert kod == 0 and "olc: 3 birim, 5 ikili" in capsys.readouterr().out
    belge = json.loads((tmp_path / "o.json").read_text())
    assert belge["onkosul"]["onkayit_commit"] == "a" * 40 and belge["kosu_kunyesi"]["commit"] == "c" * 40
    assert belge["arac"]["ghidra"] == {"surum": "12.1.2", "elf": 7}
    assert belge["ozet"]["dosya"]["kararlar"]["b1"]["karar"] == ho.KARAR_AYRISMIYOR
    assert belge["ozet"]["dosya"]["satirlar"]["urun"]["ari"]["program"]["alfa"] == 1.0
    md = (tmp_path / "o.md").read_text()
    assert f"Ön kayıt commit'i: `{'a' * 40}`" in md and "Ghidra `12.1.2`" in md
    assert "LTO'lu ikili taşıyan birimler: yok." in md and "## Düzey: dizin" in md


# --------------------------------------------------------------------------------------------
# (h) kuru


def test_kuru_caprazlamaz(tmp_path, monkeypatch):
    """Kuru koşu çapraz tablo kurmaz ve çıktısında hiçbir uyum ölçüsü yoktur."""
    elfler, beklenen = olcum_kur(tmp_path, monkeypatch)

    def yasak(*a, **k):
        raise AssertionError("kuru koşu modül ile GT etiketini çaprazladı")
    for ad in ("capraz_tablo", "olculer", "duzey_olcumu", "elf_olcumu", "b0_ozeti"):
        monkeypatch.setattr(ho, ad, yasak)
    monkeypatch.setattr(ho, "mac_gt_bilgisi", lambda e, veri: {"neden": ho.MAC_GT_NEDENI, "gt_okundu": False})
    s = ho.kuru(elfler, None, None, beklenen=beklenen)
    assert s["sema"] == ho.KURU_SEMA
    metin = json.dumps(ho.yuvarla(s), ensure_ascii=False)
    for alan in ho.OLCU_ADLARI + ("satirlar", "ogeler", "cift", "bitisiklik"):
        assert f'"{alan}"' not in metin, alan            # hiçbir uyum ölçüsü ya da çapraz sayım alanı yok
    for ad in ("src/a.c", "lib/c.c", "FUN_"):
        assert ad not in metin, ad
    alfa = s["birimler"]["debian/alfa"]["elfler"]["alfa"]
    assert alfa["urun"]["ghidra_fonksiyon"] == 13 and alfa["urun"]["thunk"] == 1
    assert alfa["urun"]["atanan"] == 13 and alfa["urun"]["modul"] == 4
    assert alfa["gt"]["etiketli"] == 12 and alfa["gt"]["kaynak_dosya"] == 3 and alfa["gt"]["dizin"] == 2
    assert alfa["esleme"] == {"gt_fonksiyon_ghidrada": 12, "gt_fonksiyon_orani": 1.0,
                              "etiketli_ghidrada": 12, "etiketli_orani": 1.0}
    assert alfa["ortak"] == {"n": 12, "modul": 3, "kaynak_dosya": 3, "dizin": 2,
                             "giris": {"dosya": None, "dizin": None}}
    assert alfa["gt_etiketi"] is True and alfa["lto"] is False
    # giriş öngörüsü yalnız nüfusun büyüklüğüne ve GT sınıflarına bakar
    assert s["birimler"]["debian/gama"]["elfler"]["kucuk"]["ortak"]["giris"] == {
        "dosya": ho.NEDEN_KUCUK, "dizin": ho.NEDEN_KUCUK}
    assert s["toplam"]["debian/gama"]["girer"] == {"dosya": 1, "dizin": 1}
    assert s["toplam"]["debian/alfa"]["girer"] == {"dosya": 2, "dizin": 2}
    # ölçümü durduracak Ghidra sürümü ön koşulu kuru koşuda da sınanır
    assert s["arac"]["ghidra"] == {"surum": "12.1.2", "elf": 7}
    mac = s["birimler"]["mac/alfa"]["elfler"]["alfa"]
    assert mac["gt_etiketi"] is False and mac["gt"]["neden"] == ho.MAC_GT_NEDENI and mac["urun"]["atanan"] == 12
    t = s["toplam"]
    assert t["debian/gama"]["ikili"] == 2 and t["debian/gama"]["cpp_disarida"] == 1
    assert t["debian/gama"]["iki_taraf_okunan"] == 2 and t["debian/gama"]["n_min_alti"] == 1
    assert t["debian/gama"]["tek_kaynak_dosya"] == 1 and t["debian/gama"]["ortak_n"] == 18
    assert t["mac/alfa"]["urun_okunan"] == 1 and "gt" not in t["mac/alfa"]
    md = ho.kuru_markdown(s)
    assert "çaprazlanmaz" in md and "debian/gama" in md and ho.MAC_GT_NEDENI in md
    assert "Ghidra sürümü denetimi: tamam, sürüm 12.1.2, 7 ikili" in md
    assert "| debian/gama | 2 | 18 | 1 | 1 | 1 | 1 | 1 |" in md       # ortak nüfus ve giriş öngörüsü
    assert f"| {ho.NEDEN_KUCUK}; {ho.NEDEN_KUCUK} |" in md
    assert "src/a.c" not in md and "FUN_" not in md


def test_kuru_esleme_orani_ve_gt_hatasi(tmp_path, monkeypatch):
    kok = tmp_path / "debian"
    fonksiyonlar = [fonk(a) for a in ADRESLER[:8]]              # Ghidra son dört fonksiyonu bulamadı
    alan_kur(kok, "debian", "p", "eksik", fonksiyonlar, yerlesim_kur({a: "subsystem_misc" for a in ADRESLER[:6]}))
    alan_kur(kok, "debian", "p", "hatali", fonksiyonlar, yerlesim_kur({a: "subsystem_misc" for a in ADRESLER[:6]}),
             surum="11.4")                                      # başka Ghidra sürümü: ölçümü durdurur
    gt_tak(monkeypatch, {"eksik": gt_tarafi(uc_dosya(), fonksiyon=ADRESLER + [0x7000], yapay=3),
                         "hatali": ho.OnkosulHatasi("ofset kanıtlanamıyor")})
    s = ho.kuru(ks1.elfleri_topla(None, kok), None, None, beklenen={"debian/p": 2})
    e = s["birimler"]["debian/p"]["elfler"]["eksik"]
    assert e["esleme"] == {"gt_fonksiyon_ghidrada": 8, "gt_fonksiyon_orani": round(8 / 13, 6),
                           "etiketli_ghidrada": 8, "etiketli_orani": round(8 / 12, 6)}
    assert e["urun"]["atanan"] == 6 and e["urun"]["atanamayan"] == 2
    assert e["ortak"] == {"n": 6, "modul": 1, "kaynak_dosya": 2, "dizin": 1,
                          "giris": {"dosya": ho.NEDEN_KUCUK, "dizin": ho.NEDEN_KUCUK}} and e["lto"] is True
    h = s["birimler"]["debian/p"]["elfler"]["hatali"]
    assert h["gt_etiketi"] is False and h["gt"]["neden"] == ho.GT_OKUNAMADI and "ofset" in h["gt"]["hata"]
    t = s["toplam"]["debian/p"]
    assert (t["gt_okunamayan"], t["urun_okunan"], t["gt_okunan"], t["iki_taraf_okunan"]) == (1, 2, 1, 1)
    assert t["lto_ikili"] == 1 and t["n_min_alti"] == 1 and t["tek_dizin"] == 1
    assert t["ayni_adli_kaynak"] == 0
    # Ghidra sürümü ön koşulu tutmuyor: kuru koşu durmaz, hatayı yazar
    assert "farklı Ghidra sürümleriyle" in s["arac"]["ghidra"]["hata"]
    md = ho.kuru_markdown(s)
    assert ho.GT_OKUNAMADI in md and "Ghidra sürümü denetimi: DURUR" in md


def test_mac_gt_bilgisi(tmp_path, monkeypatch):
    gt_yolu = tmp_path / "x.gt.json"
    gt_yolu.write_text(json.dumps({"functions": [{"addr": "0x1", "names": ["_a"], "sinif": "program"},
                                                 {"addr": "0x2", "names": ["_b"], "sinif": "program"}]}))
    monkeypatch.setattr(ks1, "gt_mac", lambda e, veri: ks1.GtBirimi(
        adlar={1: ["_a"], 2: ["_b"]}, nufus=set(), export_gt=set(), kunye={"gt": str(gt_yolu)}))
    e = ks1.Elf("mac", "x", "x", tmp_path, tmp_path)
    assert ho.mac_gt_bilgisi(e, tmp_path) == {"neden": ho.MAC_GT_NEDENI, "gt_okundu": True, "gt_fonksiyon": 2,
                                              "gt_kayit_alanlari": ["addr", "names", "sinif"]}
    assert ho.mac_gt_bilgisi(e, None) == {"neden": ho.MAC_GT_NEDENI, "gt_okundu": False}

    # GT dosyası yoksa (ör. worktree'de varsayılan veri dizini) kuru koşu durmaz, hatayı yazar
    def yok(e, veri):
        raise FileNotFoundError("x.gt.json")
    monkeypatch.setattr(ks1, "gt_mac", yok)
    b = ho.mac_gt_bilgisi(e, tmp_path)
    assert b["gt_okundu"] is False and b["neden"] == ho.MAC_GT_NEDENI and "FileNotFoundError" in b["hata"]


# --------------------------------------------------------------------------------------------
# (i) Ön koşullar


def _git(kok, *a):
    subprocess.run(["git", *a], cwd=kok, check=True, capture_output=True,
                   env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
                        "GIT_COMMITTER_EMAIL": "t@t", "PATH": "/usr/bin:/bin:/opt/homebrew/bin",
                        "HOME": str(kok)})


def _depo(tmp_path):
    kok = tmp_path / "depo"
    for rel in ho.SABIT_DOSYALAR:
        (kok / rel).parent.mkdir(parents=True, exist_ok=True)
        (kok / rel).write_text(f"# {rel}\n")
    d = kok / "docs" / "arge" / "2026-11-11_harita"
    d.mkdir(parents=True)
    _git(kok, "init", "-q")
    _git(kok, "add", "-A")
    _git(kok, "commit", "-q", "-m", "kod")
    return kok, d


def test_sabitle_ve_onkosullar(tmp_path):
    kok, d = _depo(tmp_path)
    onkayit, sabitler = d / "onkayit.md", d / "harita_sabitler.json"
    belge = ho.sabitle(kok, sabitler)
    assert belge["sema"] == ks1.SABITLER_SEMA and sorted(belge["dosyalar"]) == sorted(ho.SABIT_DOSYALAR)
    assert json.loads(sabitler.read_text()) == belge
    onkayit.write_text("# ön kayıt\n")
    with pytest.raises(ho.OnkosulHatasi, match="commit'lenmemiş"):
        ho.onkosullari_denetle(kok, onkayit, sabitler)      # yazıldı ama commit'lenmedi
    _git(kok, "add", "-A")
    _git(kok, "commit", "-q", "-m", "ön kayıt")
    o = ho.onkosullari_denetle(kok, onkayit, sabitler)
    assert o["onkayit_commit_atasi"] is True and len(o["onkayit_commit"]) == 40
    assert sorted(o["sha256"]) == sorted(ho.OLCUM_DOSYALARI)


@pytest.mark.parametrize("rel", ho.OLCUM_DOSYALARI)
def test_onkosul_olcum_dosyasi_degisince_durur(tmp_path, rel):
    kok, d = _depo(tmp_path)
    ho.sabitle(kok, d / "harita_sabitler.json")
    (d / "onkayit.md").write_text("# ön kayıt\n")
    _git(kok, "add", "-A")
    _git(kok, "commit", "-q", "-m", "ön kayıt")
    (kok / rel).write_text("# değişti\n")
    with pytest.raises(ho.OnkosulHatasi, match="sha256"):
        ho.onkosullari_denetle(kok, d / "onkayit.md", d / "harita_sabitler.json")


def test_onkosul_sabitlerde_eksik_dosya(tmp_path):
    kok, d = _depo(tmp_path)
    belge = ho.sabitle(kok, d / "harita_sabitler.json")
    del belge["dosyalar"]["scripts/measurement/dwarf_tip.py"]
    (d / "harita_sabitler.json").write_text(json.dumps(belge))
    (d / "onkayit.md").write_text("# ön kayıt\n")
    _git(kok, "add", "-A")
    _git(kok, "commit", "-q", "-m", "ön kayıt")
    with pytest.raises(ho.OnkosulHatasi, match="sha256 yok"):
        ho.onkosullari_denetle(kok, d / "onkayit.md", d / "harita_sabitler.json")


def test_kosu_kunyesi_ve_main_kuru(tmp_path, monkeypatch, capsys):
    """Künye koşu kökünden (``debian`` dizininin üstü) okunur; ``kuru`` komutu çıktıya yazar."""
    elfler, beklenen = olcum_kur(tmp_path, monkeypatch)
    assert ho.kosu_kunyesi(tmp_path / "debian") is None and ho.kosu_kunyesi(None) is None
    (tmp_path / "kosu_kunyesi.json").write_text(json.dumps(
        {"agac": {"commit": "c" * 40, "kirli": [], "karadul_surumu": "1.2.3"}, "paralel": 3}))
    k = ho.kosu_kunyesi(tmp_path / "debian")
    assert k == {"dosya": str(tmp_path / "kosu_kunyesi.json"), "commit": "c" * 40, "kirli": [],
                 "karadul_surumu": "1.2.3"}
    asil = ho.kuru      # sentetik nüfus: beklenen ikili sayıları ve Mach-O GT'si olmadan
    monkeypatch.setattr(ho, "kuru", lambda elfler, indir, mac_veri, eksik_izinli=False: asil(
        elfler, indir, None, beklenen=beklenen, eksik_izinli=eksik_izinli))
    kod = ho.main(["kuru", "--debian-kosu", str(tmp_path / "debian"), "--mac-kosu", str(tmp_path / "mac"),
                   "--json", str(tmp_path / "k.json"), "--md", str(tmp_path / "k.md")])
    assert kod == 0 and "kuru: 4 birim, 6 ikili" in capsys.readouterr().out
    belge = json.loads((tmp_path / "k.json").read_text())
    assert belge["kosu_kunyesi"]["commit"] == "c" * 40 and belge["sema"] == ho.KURU_SEMA
    assert f"ürün commit'i `{'c' * 40}`, sürüm 1.2.3, kirli dosya 0" in (tmp_path / "k.md").read_text()


def test_yuvarla_ve_sayi():
    assert ho.yuvarla({"a": F(1, 3), 2: [F(1, 2), None, True, "x", 1.23456789]}) == {
        "a": 0.333333, "2": [0.5, None, True, "x", 1.234568]}
    assert ho.sayi(F(1, 3)) == "0,333" and ho.sayi(None) == "—" and ho.sayi(0.05, 2) == "0,05"
