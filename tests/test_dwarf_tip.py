"""scripts/measurement/dwarf_tip.py — dwz farkında DWARF tip okuyucusunun testleri (plan v2.2 T0a).

Saf mantık testleri sahte DIE'lerle kurulmuş iki dosyalı küçük bir dünyada koşar (ana dosya +
dwz ek dosyası). Kilitlenen davranışlar:
  (a) başvuru biçimleri: birim içi biçim birim başlığına göre, ``ref_addr`` aynı dosyaya,
      ``GNU_ref_alt`` ek dosyaya gider; ana ve ek dosyada aynı ofsette farklı DIE varken doğru
      dosya seçilir; ``GNU_strp_alt`` ek dosyanın ``.debug_str``'ından okunur,
  (b) kanonik biçim: typedef soyulur, ``const``/``volatile``/``restrict``/``_Atomic`` atılır ve
      kaydedilir, işaretçi derinliği tutulur, anonim yapı ofsetle kimlik alır; sınıflar,
  (c) fonksiyon: ad ve tip ``abstract_origin`` zinciriyle bulunur; ``sira`` bildirim sırası,
      ``somut_sira`` somut DIE sırası; klon bayrağı sonekten ya da ``abstract_origin``'den,
  (d) ``DW_TAG_imported_unit`` kapanışı: bildirimden tanıma yalnız erişilen kısmi birimlerde
      gidilir; çözülemeyen tiplerin nedenleri,
  (e) özet ve kimlik denetimi; dwarfdump çıktısının ayrıştırılması; ek dosyanın bulunması.
Yerel coreutils 9.4 dbgsym verisi varsa gerçek dosyada tümleşik testler de koşar (yoksa atlanır;
depoya ikili fikstür konmaz).

Mutasyon koruması: ``scripts/measurement/mutation_specs_dwarf_tip.json``
(``PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec <o dosya>``).
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parents[1] / "scripts" / "measurement" / "dwarf_tip.py"
_spec = importlib.util.spec_from_file_location("dwarf_tip_under_test", _PATH)
dt = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = dt
_spec.loader.exec_module(dt)


# --------------------------------------------------------------------------------------------
# Sahte DIE dünyası


def ad(s):
    return ("DW_FORM_string", s, s)


def strp_alt(o):
    return ("DW_FORM_GNU_strp_alt", o, o)


def ref_alt(o):
    return ("DW_FORM_GNU_ref_alt", o, o)


def ref_addr(o):
    return ("DW_FORM_ref_addr", o, o)


def ref4(o):
    return ("DW_FORM_ref4", o, o)


def veri(v, bicim="DW_FORM_data1"):
    return (bicim, v, v)


BAYRAK = ("DW_FORM_flag_present", True, True)


def adres(v):
    return ("DW_FORM_addr", v, v)


def D(ofset, etiket, ust=None, birim=0, **oz):
    return dt.Die(ofset, "DW_TAG_" + etiket, {"DW_AT_" + k: v for k, v in oz.items()}, [], birim,
                  ust)


def dosya(rol, dieler, dizgi=b"", semboller=None, altlink=None):
    harita = {d.ofset: d for d in dieler}
    for d in dieler:
        if d.ust is not None:
            harita[d.ust].cocuklar.append(d.ofset)
    birimler = {}
    for d in dieler:
        if d.ust is None:
            birimler[d.birim] = {"ust": d.ofset, "etiket": d.etiket, "dieler": []}
    for d in dieler:
        birimler[d.birim]["dieler"].append(d.ofset)
    return dt.DwarfDosyasi(rol, harita, birimler, dizgi, semboller or {}, altlink=altlink)


def ek_dosya():
    """dwz ek dosyası: 3 kısmi birim. 0x0 ve 0x300 ana dosyadan ithal ediliyor, 0x200 edilmiyor."""
    b = 0xB
    dieler = [
        D(b, "partial_unit"),
        D(0x10, "base_type", b, name=ad("char"), encoding=veri(8), byte_size=veri(1)),
        D(0x14, "base_type", b, name=ad("int"), encoding=veri(5), byte_size=veri(4)),
        D(0x18, "base_type", b, name=ad("signed char"), encoding=veri(6), byte_size=veri(1)),
        D(0x1C, "base_type", b, name=ad("_Bool"), encoding=veri(2), byte_size=veri(1)),
        D(0x20, "const_type", b, type=ref_addr(0x10)),                  # const char
        D(0x24, "pointer_type", b, type=ref_addr(0x20)),                # const char *
        D(0x28, "pointer_type", b, type=ref_addr(0x24)),                # const char **
        D(0x2C, "restrict_type", b, type=ref_addr(0x24)),               # const char *restrict
        D(0x30, "structure_type", b, name=ad("foo"), byte_size=veri(16)),
        D(0x34, "member", 0x30, name=ad("a"), type=ref_addr(0x14), data_member_location=veri(0)),
        D(0x38, "member", 0x30, name=ad("b"), type=ref_addr(0x24), data_member_location=veri(8)),
        D(0x40, "typedef", b, name=ad("foo_t"), type=ref_addr(0x30)),
        D(0x44, "pointer_type", b, type=ref_addr(0x40)),                # foo_t *
        D(0x48, "structure_type", b, byte_size=veri(4)),                # anonim
        D(0x4C, "member", 0x48, name=ad("x"), type=ref_addr(0x14), data_member_location=veri(0)),
        D(0x50, "typedef", b, name=ad("anon_t"), type=ref_addr(0x48)),
        D(0x54, "pointer_type", b, type=ref_addr(0x50)),                # anon_t *
        D(0x58, "pointer_type", b),                                     # void *
        D(0x5C, "const_type", b),                                       # const void
        D(0x60, "pointer_type", b, type=ref_addr(0x5C)),                # const void *
        D(0x64, "subroutine_type", b, prototyped=BAYRAK, type=ref_addr(0x14)),
        D(0x68, "formal_parameter", 0x64, type=ref_addr(0x44)),
        D(0x6C, "unspecified_parameters", 0x64),
        D(0x70, "pointer_type", b, type=ref_addr(0x64)),                # int (*)(foo_t *, ...)
        D(0x74, "array_type", b, type=ref_addr(0x14)),
        D(0x78, "subrange_type", 0x74, upper_bound=veri(9)),
        D(0x7C, "pointer_type", b, type=ref_addr(0x74)),                # int (*)[10]
        D(0x80, "enumeration_type", b, name=ad("renk"), byte_size=veri(4)),
        D(0x84, "pointer_type", b, type=ref_addr(0x80)),
        D(0x88, "union_type", b, name=ad("birlik"), byte_size=veri(8)),
        D(0x8C, "pointer_type", b, type=ref_addr(0x88)),
        D(0x90, "volatile_type", b, type=ref_addr(0x14)),
        D(0x94, "atomic_type", b, type=ref_addr(0x14)),
        D(0x98, "pointer_type", b, type=ref_addr(0x18)),                # signed char *
        D(0x9C, "pointer_type", b, type=ref_addr(0x1C)),                # _Bool *
        D(0xA0, "typedef", b, name=ad("dongu_a"), type=ref_addr(0xA4)),
        D(0xA4, "typedef", b, name=ad("dongu_b"), type=ref_addr(0xA0)),
        D(0xA8, "ptr_to_member_type", b),
        D(0xAC, "pointer_type", b, type=ref_alt(0x10)),                 # ek içinden ref_alt
        D(0xB0, "subroutine_type", b),                                  # void (*)() prototipsiz
        D(0xB4, "pointer_type", b, type=ref_addr(0xB0)),
        # 0x200: ithal EDİLMEYEN kısmi birim (başka bir ikilinin "bar"ı)
        D(0x20B, "partial_unit", birim=0x200),
        D(0x210, "structure_type", 0x20B, 0x200, name=ad("bar"), byte_size=veri(32)),
        D(0x214, "member", 0x210, 0x200, name=ad("z"), type=ref_addr(0x14),
          data_member_location=veri(0)),
        # 0x300: ithal edilen kısmi birim (bu ikilinin "bar"ı)
        D(0x30B, "partial_unit", birim=0x300),
        D(0x310, "structure_type", 0x30B, 0x300, name=ad("bar"), byte_size=veri(4)),
        D(0x314, "member", 0x310, 0x300, name=ad("q"), type=ref_addr(0x14),
          data_member_location=veri(0)),
    ]
    return dosya(dt.EK, dieler, dizgi=b"\0alt_adi\0")


def ana_dieleri():
    b = 0xB
    return [
        D(b, "compile_unit", name=ad("src/t.c")),
        D(0x10, "imported_unit", b, **{"import": ref_alt(0xB)}),
        D(0x12, "imported_unit", b, **{"import": ref_alt(0x30B)}),
        D(0x14, "base_type", b, name=ad("long"), encoding=veri(5), byte_size=veri(8)),  # ek 0x14 ile aynı ofset
        D(0x18, "structure_type", b, name=ad("bar"), declaration=BAYRAK),
        D(0x1C, "pointer_type", b, type=ref4(0x18)),
        D(0x100, "subprogram", b, name=ad("f"), low_pc=adres(0x1000),
          high_pc=veri(0x40, "DW_FORM_data4"), external=BAYRAK, prototyped=BAYRAK),
        D(0x110, "formal_parameter", 0x100, name=ad("p"), type=ref_alt(0x44)),
        D(0x118, "formal_parameter", 0x100, name=strp_alt(1), type=ref_alt(0x2C)),
        D(0x120, "formal_parameter", 0x100, name=ad("n"), type=ref_alt(0x14)),
        D(0x128, "formal_parameter", 0x100, name=ad("b"), type=ref4(0x1C)),
        D(0x130, "unspecified_parameters", 0x100),
        D(0x200, "subprogram", b, name=ad("g"), inline=veri(3), prototyped=BAYRAK),
        D(0x210, "formal_parameter", 0x200, name=ad("x"), type=ref_alt(0x14)),
        D(0x218, "formal_parameter", 0x200, name=ad("y"), type=ref_alt(0x24)),
        D(0x300, "subprogram", b, low_pc=adres(0x2000), high_pc=veri(0x10),
          abstract_origin=ref4(0x200)),
        D(0x310, "formal_parameter", 0x300, abstract_origin=ref4(0x218)),   # önce y
        D(0x318, "formal_parameter", 0x300, abstract_origin=ref4(0x210)),   # sonra x
        D(0x400, "subprogram", b, name=ad("h"), low_pc=adres(0x3000), high_pc=veri(8)),
        D(0x410, "formal_parameter", 0x400, name=ad("q"), type=ref_alt(0x14)),
        # ikinci derleme birimi 0x1000'de: birim içi başvurular 0x1000'e göre
        D(0x100B, "compile_unit", birim=0x1000, name=ad("src/u.c")),
        D(0x1010, "base_type", 0x100B, 0x1000, name=ad("short int"), encoding=veri(5),
          byte_size=veri(2)),
        D(0x1020, "pointer_type", 0x100B, 0x1000, type=ref4(0x10)),
        D(0x1030, "subprogram", 0x100B, 0x1000, name=ad("k"), low_pc=adres(0x4000),
          high_pc=veri(4)),
        D(0x1040, "formal_parameter", 0x1030, 0x1000, name=ad("s"), type=ref4(0x20)),
    ]


ANA_SEMBOLLERI = {0x1000: ["f"], 0x2000: ["g"], 0x3000: ["h.isra.0"], 0x4000: ["k"]}


def ana_dosya(ek_dieler=(), ek_semboller=None):
    semboller = {**ANA_SEMBOLLERI, **(ek_semboller or {})}
    return dosya(dt.ANA, ana_dieleri() + list(ek_dieler), dizgi=b"\0yanlis_ana\0",
                 semboller=semboller)


@pytest.fixture
def coz():
    return dt.Cozucu(ana_dosya(), ek_dosya())


def _fonk(coz, ad_):
    return next(f for f in coz.fonksiyonlar() if f["ad"] == ad_)


def _ek_tip(coz, ofset):
    return coz.tip_coz(dt.EK, coz.die(dt.EK, ofset))


# --------------------------------------------------------------------------------------------
# (a) başvurular ve dizgiler


def test_basvuru_hedefi_bicimleri():
    assert dt.basvuru_hedefi("ana", 0x100, "DW_FORM_ref4", 0x10) == ("ana", 0x110)
    assert dt.basvuru_hedefi("ek", 0x100, "DW_FORM_ref_udata", 0x10) == ("ek", 0x110)
    assert dt.basvuru_hedefi("ana", 0x100, "DW_FORM_ref_addr", 0x10) == ("ana", 0x10)
    assert dt.basvuru_hedefi("ana", 0x100, "DW_FORM_GNU_ref_alt", 0x10) == ("ek", 0x10)
    assert dt.basvuru_hedefi("ana", 0x100, "DW_FORM_ref_sup4", 0x10) == ("ek", 0x10)
    for rol, bicim, neden in (("ek", "DW_FORM_GNU_ref_alt", "ek_icinden_ek_basvurusu"),
                              ("ana", "DW_FORM_ref_sig8", "ref_sig8"),
                              ("ana", "DW_FORM_data1", "bilinmeyen_bicim")):
        with pytest.raises(dt.CozumHatasi) as h:
            dt.basvuru_hedefi(rol, 0, bicim, 0x10)
        assert h.value.neden == neden


def test_ref_alt_ek_dosyasinda_cozulur(coz):
    """Ana ve ek dosyada 0x14'te farklı temel tip var; ref_alt ek dosyadakini seçmeli."""
    n = _fonk(coz, "f")["parametreler"][2]
    assert n["ad"] == "n"
    assert n["tip_kaynagi"] == {"yol": "kendi", "die": "ana:0x120", "bicim": "DW_FORM_GNU_ref_alt",
                                "hedef": "ek:0x14"}
    assert n["tip"]["kanonik"] == "int"
    assert n["tip"]["ham"] == [{"etiket": "base_type", "konum": "ek:0x14", "ad": "int"}]


def test_strp_alt_ek_dizgi_tablosundan(coz):
    p = _fonk(coz, "f")["parametreler"][1]
    assert p["ad"] == "alt_adi"
    assert p["ad_kaynagi"] == {"yol": "kendi", "die": "ana:0x118", "bicim": "DW_FORM_GNU_strp_alt",
                               "ofset": 1}


def test_dizgi_oku_kuyruk_paylasimi_ve_sinir():
    tablo = b"\0quote_name\0"
    assert dt.dizgi_oku(tablo, 1) == "quote_name"
    assert dt.dizgi_oku(tablo, 7) == "name"          # bağlayıcının kuyruk paylaşımı
    with pytest.raises(dt.CozumHatasi) as h:
        dt.dizgi_oku(tablo, 99)
    assert h.value.neden == "gecersiz_dizgi_ofseti"


def test_yerel_basvuru_birim_basligina_gore(coz):
    s = _fonk(coz, "k")["parametreler"][0]
    assert s["tip_kaynagi"]["hedef"] == "ana:0x1020"
    assert (s["tip"]["kanonik"], s["tip"]["sinif"]) == ("short int *", "skaler*")


def test_altlink_coz():
    veri_ = b"/usr/lib/debug/.dwz/aarch64-linux-gnu/coreutils.debug\0" + bytes.fromhex("e99641")
    assert dt.altlink_coz(veri_) == ("/usr/lib/debug/.dwz/aarch64-linux-gnu/coreutils.debug",
                                     "e99641")
    with pytest.raises(ValueError):
        dt.altlink_coz(b"yolsuz")


# --------------------------------------------------------------------------------------------
# (b) kanonik biçim ve sınıflar


def test_kanonik_typedef_soyulur(coz):
    p = _fonk(coz, "f")["parametreler"][0]
    t = p["tip"]
    assert (t["kanonik"], t["sinif"], t["derinlik"]) == ("struct foo *", "yapi*", 1)
    assert t["typedefler"] == ["foo_t"]
    assert t["kok"]["kimlik"] == "struct foo" and t["kok"]["konum"] == "ek:0x30"
    assert [(a["etiket"], a["konum"], a.get("ad")) for a in t["ham"]] == [
        ("pointer_type", "ek:0x44", None), ("typedef", "ek:0x40", "foo_t"),
        ("structure_type", "ek:0x30", "foo")]


def test_niteleyiciler_atilir_ve_kaydedilir(coz):
    t = _ek_tip(coz, 0x2C)                             # const char *restrict
    assert (t["kanonik"], t["sinif"]) == ("char *", "char*")
    assert t["niteleyiciler"] == ["restrict", "const"]
    t = _ek_tip(coz, 0x60)                             # const void *
    assert (t["kanonik"], t["sinif"], t["niteleyiciler"]) == ("void *", "void*", ["const"])
    assert _ek_tip(coz, 0x90)["kanonik"] == "int"      # volatile int
    t = _ek_tip(coz, 0x94)                             # _Atomic int
    assert (t["kanonik"], t["niteleyiciler"]) == ("int", ["_Atomic"])


@pytest.mark.parametrize("ofset,kanonik,sinif,derinlik", [
    (0x28, "char **", "ptr**", 2),
    (0x24, "char *", "char*", 1),
    (0x98, "signed char *", "char*", 1),
    (0x9C, "_Bool *", "skaler*", 1),
    (0x58, "void *", "void*", 1),
    (0x54, "struct <anon@ek:0x48> *", "yapi*", 1),
    (0x8C, "union birlik *", "yapi*", 1),
    (0x84, "enum renk *", "skaler*", 1),
    (0x70, "fonk(int; struct foo *, ...) *", "fonk*", 1),
    (0xB4, "fonk(void; ?) *", "fonk*", 1),
    (0x7C, "int[10] *", "diger", 1),
    (0x30, "struct foo", "yapi_degerle", 0),
    (0x80, "enum renk", "skaler", 0),
    (0x14, "int", "skaler", 0),
])
def test_isaretci_derinligi_ve_siniflar(coz, ofset, kanonik, sinif, derinlik):
    t = _ek_tip(coz, ofset)
    assert t["cozuldu"], t
    assert (t["kanonik"], t["sinif"], t["derinlik"]) == (kanonik, sinif, derinlik)


def test_anonim_yapi_typedef_adi_zincirde_kalir(coz):
    t = _ek_tip(coz, 0x54)
    assert t["kok"] == {"tur": "struct", "ad": None, "kimlik": "struct <anon@ek:0x48>",
                        "konum": "ek:0x48", "bildirim": False, "boyut": 4}
    assert t["typedefler"] == ["anon_t"]


def test_sinifla_char_ailesi_yalniz_bir_bayt():
    kok = {"tur": "temel", "kodlama": "unsigned_char", "boyut": 1}
    assert dt.sinifla(kok, 1) == "char*"
    assert dt.sinifla(dict(kok, kodlama="signed"), 1) == "skaler*"
    assert dt.sinifla(dict(kok, boyut=2), 1) == "skaler*"
    assert dt.sinifla({"tur": "struct"}, 2) == "ptr**"
    assert dt.sinifla({"tur": "fonk"}, 0) == "diger"


# --------------------------------------------------------------------------------------------
# (c) fonksiyonlar, köken zinciri, klonlar


def test_abstract_origin_ad_ve_sira(coz):
    g = _fonk(coz, "g")
    assert g["konum"] == "ana:0x300" and g["adres"] == "0x2000"
    assert g["ad_kaynagi"]["yol"] == "abstract_origin"
    p1, p2 = g["parametreler"]
    assert (p1["somut_sira"], p1["sira"], p1["ad"], p1["tip"]["kanonik"]) == (1, 2, "y", "char *")
    assert (p2["somut_sira"], p2["sira"], p2["ad"], p2["tip"]["kanonik"]) == (2, 1, "x", "int")
    assert p1["soyut_konum"] == "ana:0x218"
    assert p1["tip_kaynagi"]["yol"] == "abstract_origin"
    assert g["prototipli"] is True
    assert g["soyut_parametre_sayisi"] == 2 and _fonk(coz, "f")["soyut_parametre_sayisi"] is None


def test_klon_dusen_ve_tekrar_parametre():
    """constprop benzeri iki klon: 0x5000'de x düşmüş; 0x6000'de y için ikinci bir DIE var
    (LTO'lu IPA-CP klonunda sabit değer betimi): tekrar sayılır, düşen sayılmaz."""
    klon = [D(0x500, "subprogram", 0xB, low_pc=adres(0x5000), high_pc=veri(4),
              abstract_origin=ref4(0x200)),
            D(0x510, "formal_parameter", 0x500, abstract_origin=ref4(0x218)),
            D(0x600, "subprogram", 0xB, low_pc=adres(0x6000), high_pc=veri(4),
              abstract_origin=ref4(0x200)),
            D(0x610, "formal_parameter", 0x600, abstract_origin=ref4(0x210),
              location=("DW_FORM_sec_offset", 0x40, 0x40)),
            D(0x618, "formal_parameter", 0x600, abstract_origin=ref4(0x218)),
            D(0x620, "formal_parameter", 0x600, abstract_origin=ref4(0x218),
              location=("DW_FORM_exprloc", [0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0x9F],
                        [0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0x9F]))]
    coz = dt.Cozucu(ana_dosya(klon, {0x5000: ["g.constprop.0"], 0x6000: ["g.constprop.1"]}),
                    ek_dosya())
    fonks = {f["adres"]: f for f in coz.fonksiyonlar()}
    a, b = fonks["0x5000"], fonks["0x6000"]
    assert a["ad"] == "g" and a["klon"]["sonekler"] == [".constprop"]
    assert [(p["somut_sira"], p["sira"], p["ad"], p["tekrar"]) for p in a["parametreler"]] == [
        (1, 2, "y", False)]
    assert a["soyut_parametre_sayisi"] == 2
    assert [(p["sira"], p["tekrar"], p["yer"]) for p in b["parametreler"]] == [
        (1, False, "loclist"), (2, False, None), (2, True, "exprloc")]
    s = dt.parametre_sayimlari(list(fonks.values()))
    assert (s["eksik_parametreli_fonksiyon"], s["tekrarli_fonksiyon"], s["tekrar_parametre"]) == (
        1, 1, 1)
    assert s["sira_farkli_fonksiyon"] == 2           # g (y, x sırası) ve 0x5000 (yalnız y)


def test_klon_sonekleri():
    assert dt.klon_sonekleri(["foo.constprop.0.isra.0"]) == [".constprop", ".isra"]
    assert dt.klon_sonekleri(["foo.part.0", "foo.cold"]) == [".cold", ".part"]
    assert dt.klon_sonekleri(["foo.partial", "bar.lto_priv.0", "baz"]) == []


def test_klon_bayragi(coz):
    f, g, h = _fonk(coz, "f"), _fonk(coz, "g"), _fonk(coz, "h")
    assert f["klon"] == {"sonekler": [], "abstract_origin": False, "origin_inline": None,
                         "bayrak": False}
    assert g["klon"] == {"sonekler": [], "abstract_origin": True,
                         "origin_inline": "declared_inlined", "bayrak": True}
    assert h["klon"] == {"sonekler": [".isra"], "abstract_origin": False, "origin_inline": None,
                         "bayrak": True}
    assert h["semboller"] == ["h.isra.0"]


def test_fonksiyon_kunyesi(coz):
    f = _fonk(coz, "f")
    assert (f["adres"], f["boyut"], f["birim"]) == ("0x1000", 0x40, "src/t.c")
    assert f["harici"] and f["prototipli"] and f["degisken_arguman"]
    assert f["parametre_kaynagi"] == "somut"
    assert [p["sira"] for p in f["parametreler"]] == [1, 2, 3, 4]
    assert [f_["ad"] for f_ in coz.fonksiyonlar()] == ["f", "g", "h", "k"]   # adrese göre


# --------------------------------------------------------------------------------------------
# (d) ithal birimleri, tanımlar, çözülemeyenler


def test_ithal_kapanisi_ve_tanimlar(coz):
    erisilen, ithal = coz.erisim()
    assert {(r, b) for r, b in erisilen if r == dt.EK} == {(dt.EK, 0x0), (dt.EK, 0x300)}
    assert dict(ithal) == {"ana>ek": 2}
    fonks = coz.fonksiyonlar()
    tablo = coz.yapilar(fonks)
    bar = tablo["ana:0x18"]                          # bildirim
    assert bar["bildirim"] is True and bar["uyeler"] is None
    assert bar["tanimlar"] == ["ek:0x310"]           # ithal edilmeyen 0x200'deki "bar" değil
    assert tablo["ek:0x310"]["uyeler"] == [
        {"ad": "q", "ofset": 0, "kanonik": "int", "sinif": "skaler"}]
    assert "ek:0x210" not in tablo
    assert tablo["ek:0x30"]["uyeler"][1] == {"ad": "b", "ofset": 8, "kanonik": "char *",
                                             "sinif": "char*"}
    oz = coz.birim_ozeti()
    assert (oz["ana_derleme"], oz["ek_toplam"], oz["ek_erisilen"]) == (2, 3, 2)


def test_cozulemeyen_nedenleri(coz):
    for ofset, neden in ((0xA0, "dongu"), (0xA8, "bilinmeyen_etiket"),
                         (0xAC, "ek_icinden_ek_basvurusu")):
        t = _ek_tip(coz, ofset)
        assert (t["cozuldu"], t["neden"]) == (False, neden)
    sahte = dt.Die(0x9000, "DW_TAG_formal_parameter", {"DW_AT_type": ref_alt(0x9999)})
    assert coz.parametre_tipi(dt.ANA, sahte)[1]["neden"] == "gecersiz_ofset"
    tipsiz = dt.Die(0x9010, "DW_TAG_formal_parameter", {"DW_AT_name": ad("x")})
    assert coz.parametre_tipi(dt.ANA, tipsiz)[1]["neden"] == "tip_yok"


def test_ek_dosya_yoksa_neden_yazilir():
    coz = dt.Cozucu(ana_dosya(), None)
    f = _fonk(coz, "f")
    p, adi, n, b = f["parametreler"]
    assert (p["tip"]["cozuldu"], p["tip"]["neden"]) == (False, "ek_dosya_yok")
    assert p["tip_kaynagi"]["hedef"] == "ek:0x44"
    assert adi["ad"] is None and adi["ad_kaynagi"] == {"yol": "hata", "neden": "ek_dosya_yok"}
    assert b["tip"]["kanonik"] == "struct bar *"     # ana dosyada kalan tip yine çözülür
    assert coz.birim_ozeti()["ithal"] == {"cozulemeyen:ek_dosya_yok": 2}


def test_tum_parametre_taramasi(coz):
    t = coz.tum_parametre_taramasi()
    assert (t["toplam"], t["cozulen"], t["nedenler"]) == (10, 10, {})
    assert t["ust_turune_gore"] == {"somut": {"toplam": 8, "cozulen": 8},
                                    "soyut": {"toplam": 2, "cozulen": 2}}


# --------------------------------------------------------------------------------------------
# (e) özet, kimlik denetimi, dwarfdump ayrıştırma, ek dosyanın bulunması


def _yapi(ad_, boyut, uyeler, tur="struct"):
    return {"tur": tur, "ad": ad_, "kimlik": f"{tur} {ad_}" if ad_ else f"{tur} <anon>",
            "bildirim": False, "boyut": boyut,
            "uyeler": [{"ad": a, "ofset": o, "kanonik": k} for a, o, k in uyeler]}


def test_kimlik_denetimi_kopya_cakisma_anonim():
    yapilar = {
        "ana:0x10": _yapi("dict", 56, [("type", 0, "struct dictType *"),
                                       ("v", 8, "union <anon@ana:0x11>")]),
        "ana:0x20": _yapi("dict", 56, [("type", 0, "struct dictType *"),
                                       ("v", 8, "union <anon@ana:0x21>")]),   # kopya
        "ana:0x30": _yapi("dict", 48, [("table", 0, "struct dictEntry **")]),  # farklı yerleşim
        "ana:0x40": _yapi("iter", 8, [("i", 0, "int")]),
        "ana:0x50": _yapi(None, 4, [("x", 0, "int")]),
        "ek:0x60": _yapi(None, 4, [("x", 0, "int")]),
    }
    k = dt.kimlik_denetimi(yapilar)
    assert k == {"ayni_adli_farkli_yerlesim": ["struct dict"], "ayni_adli_kopyalar": ["struct dict"],
                 "ayni_yerlesimli_anonim_gruplar": [["ana:0x50", "ek:0x60"]]}


def test_ozetle_paylar(tmp_path):
    belge = dt.belge_uret(ana_dosya(), ek_dosya(), ek_yontemi="elle", arac={})
    assert belge["sema"] == dt.SEMA
    yol = tmp_path / "grup" / "t.json"
    dt._yaz_json(yol, belge)
    dt._yaz_json(tmp_path / "grup" / "toplu.json", {"sema": dt.TOPLU_SEMA})   # atlanmalı
    oz = dt.ozetle(dt.belgeleri_topla([tmp_path / "grup"]))
    assert oz["girdi_betik_sha256"] == ["None"]          # arac={} verildi
    t = oz["toplam"]
    assert (t["dosya"], t["fonksiyon"], t["parametre"], t["tip_cozulen"]) == (1, 4, 8, 8)
    assert t["cozulen_payi"] == 1.0
    assert t["tipi_ek_dosyada"] == 6 and t["ek_dosya_payi"] == 0.75
    assert t["sinif"]["yapi*"] == 2 and t["sinif"]["char*"] == 2 and t["sinif"]["skaler"] == 3
    assert t["klon"] == {"abstract_origin": 1, "abstract_origin_inline_kokenli": 1, "bayrak": 2,
                         "sonekli": 1}
    assert t["klon_payi"]["bayrak"] == 0.5
    assert (t["sira_farkli_fonksiyon"], t["eksik_parametreli_fonksiyon"]) == (1, 0)
    assert t["niteleyici"] == {"const": 2, "restrict": 1}
    assert t["yer"] == {"None": 8}                   # sahte dünyada konum bilgisi yok
    assert t["yalniz_ranges_govde"] == 0
    assert t["tum_fp_kendi_tip_bicimi"] == {"DW_FORM_GNU_ref_alt": 6, "DW_FORM_ref4": 2}
    assert t["tum_fp_kendi_tipi_ref_alt_payi"] == 0.75
    assert list(oz["gruplar"]) == ["grup"]


_DD_ORNEK = """/x/coreutils.debug:\tfile format elf64-littleaarch64

.debug_info contents:

0x00000365: DW_TAG_pointer_type [2]   (0x000001d5)
              DW_AT_byte_size [DW_FORM_implicit_const]\t(8)
              DW_AT_type [DW_FORM_ref_udata]\t(cu + 0x191 => {0x0000035a} "::FILE")

0x00000370: DW_TAG_base_type [3]   (0x000001d5)
"""


def test_dwarfdump_ayristirma():
    d = dt.dd_ayristir(_DD_ORNEK)
    assert (d["ofset"], d["etiket"]) == (0x365, "DW_TAG_pointer_type")
    assert set(d["oz"]) == {"DW_AT_byte_size", "DW_AT_type"}      # yalnız ilk DIE
    assert dt.dd_basvuru(d["oz"]["DW_AT_type"][1]) == ("ayni", 0x35A)
    assert dt.dd_basvuru("<alt 0x16ef1>") == ("ek", 0x16EF1)
    assert dt.dd_basvuru('0x0000000000016ef1 "const char *"') == ("ayni", 0x16EF1)
    assert dt.dd_dizgi("alt indirect string, offset: 0xd4f0") == ("ek_ofset", 0xD4F0)
    assert dt.dd_dizgi(' .debug_str[0x0000159f] = "_IO_FILE"') == ("dizgi", "_IO_FILE")
    assert dt.dd_dizgi('"i"') == ("dizgi", "i")
    assert dt.dd_ayristir("bos cikti\n") is None
    tablo = dt.dd_str_tablosu('0x00000000: "SR10"\n0x00000005: "_NL_WABMON_10"\n')
    assert dt.dd_ofsetteki_dizgi(tablo, 5) == "_NL_WABMON_10"
    assert dt.dd_ofsetteki_dizgi(tablo, 9) == "WABMON_10"     # "_NL_" atlanır
    assert dt.dd_ofsetteki_dizgi(tablo, 0x100) is None


def test_capraz_farklar():
    param = {"ad": "argv", "ad_kaynagi": {"yol": "kendi"},
             "tip_kaynagi": {"die": "ana:0x10", "bicim": "DW_FORM_GNU_ref_alt", "hedef": "ek:0x20"},
             "tip": {"kanonik": "char *", "ham": [{"etiket": "pointer_type", "konum": "ek:0x20"},
                                                  {"etiket": "base_type", "konum": "ek:0x11",
                                                   "ad": "char"}]}}
    dd = {"ad": "argv", "ad_ofseti": None, "hata": None, "kanonik": "char *",
          "tip_kaynagi": {"die": "ana:0x10", "bicim": "DW_FORM_GNU_ref_alt"},
          "ham": [{"etiket": "pointer_type", "konum": "ek:0x20"},
                  {"etiket": "base_type", "konum": "ek:0x11", "ad": "char"}]}
    assert dt.capraz_farklar(param, dd) == []
    bozuk = dict(dd, ham=[dd["ham"][0], {"etiket": "base_type", "konum": "ek:0x12", "ad": "char"}])
    assert len(dt.capraz_farklar(param, bozuk)) == 1
    assert dt.capraz_farklar(param, dict(dd, hata="DIE yok")) == ["dwarfdump: DIE yok"]


def test_ek_dosyasini_bul(tmp_path, monkeypatch):
    kok = tmp_path / "x_paket" / "data" / "usr" / "lib" / "debug"
    ana = kok / ".build-id" / "ab" / "cdef.debug"
    ek = kok / ".dwz" / "aarch64-linux-gnu" / "paket.debug"
    for p in (ana, ek):
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"x")
    monkeypatch.setattr(dt, "elf_build_id", lambda p: "beklenen" if p.name == "paket.debug" else None)
    mutlak = ("/usr/lib/debug/.dwz/aarch64-linux-gnu/paket.debug", "beklenen")
    assert dt.ek_dosyasini_bul(ana, mutlak) == (ek.resolve(), "debugaltlink", [])
    goreli = ("../../.dwz/aarch64-linux-gnu/paket.debug", "beklenen")
    assert dt.ek_dosyasini_bul(ana, goreli) == (ek.resolve(), "debugaltlink", [])
    assert dt.ek_dosyasini_bul(ana, None) == (None, "altlink_yok", [])
    monkeypatch.setattr(dt, "elf_build_id", lambda p: "baska")
    yol, yontem, uymayan = dt.ek_dosyasini_bul(ana, mutlak)
    assert (yol, yontem, uymayan) == (None, "bulunamadi", [str(ek.resolve())])


# --------------------------------------------------------------------------------------------
# Tümleşik: yerel coreutils 9.4 dbgsym (geliştirme seti). Veri yoksa atlanır.

_INDIR = Path.home() / "karadul_olcum" / "downloads"
_PINKY = (_INDIR / "x_coreutils-dbgsym_9.4-3_arm64/data/usr/lib/debug/.build-id/71"
          / "c956ca2242bed063c4f1208b91ab1d3c0469a2.debug")
_UBUNTU_YES = (_INDIR / "x_coreutils-dbgsym_9.4-3ubuntu6_arm64/data/usr/lib/debug/.build-id/00"
               / "496f67910c23cd107aab1f98a1349fbee59e13.debug")
debian_yok = pytest.mark.skipif(not _PINKY.is_file(), reason="yerel Debian coreutils 9.4-3 dbgsym yok")
ubuntu_yok = pytest.mark.skipif(not _UBUNTU_YES.is_file(),
                                reason="yerel Ubuntu coreutils 9.4-3ubuntu6 dbgsym yok")


@pytest.fixture(scope="module")
def pinky():
    return dt.cikar(_PINKY)


@debian_yok
def test_gercek_debian_pinky(pinky):
    b, s = pinky, pinky["sayimlar"]
    assert b["girdi"]["ek_yontemi"] == "debugaltlink"
    assert b["girdi"]["ek"]["build_id"] == b["girdi"]["debugaltlink"]["build_id"]
    assert (s["fonksiyon"], s["parametre"], s["tip_cozulen"], s["tipi_ek_dosyada"]) == (90, 215, 215,
                                                                                        172)
    assert s["tum_formal_parameter"]["toplam"] == s["tum_formal_parameter"]["cozulen"] == 954
    main = next(f for f in b["fonksiyonlar"] if f["ad"] == "main")
    assert main["birim"] == "src/pinky.c"
    assert [(p["ad"], p["tip"]["kanonik"], p["tip"]["sinif"]) for p in main["parametreler"]] == [
        ("argc", "int", "skaler"), ("argv", "char **", "ptr**")]
    assert b["birimler"]["ithal"]["ana>ek"] > 0 and b["birimler"]["ek_erisilen"] > 0


@ubuntu_yok
def test_gercek_ubuntu_lto_her_govde_abstract_origin_li():
    b = dt.cikar(_UBUNTU_YES)
    s = b["sayimlar"]
    assert s["fonksiyon"] > 0 and s["parametre"] == s["tip_cozulen"]
    assert all(f["klon"]["abstract_origin"] and f["klon"]["origin_inline"] is None
               for f in b["fonksiyonlar"])
    assert all(p["sira"] is not None for f in b["fonksiyonlar"] for p in f["parametreler"])
    assert all(f["birim"] != "<artificial>" for f in b["fonksiyonlar"])


@debian_yok
@pytest.mark.skipif(not Path(dt.DWARFDUMP_YOLU).exists(), reason="Apple dwarfdump yok")
def test_gercek_capraz_denetim(pinky, tmp_path):
    yol = tmp_path / "pinky.json"
    dt._yaz_json(yol, pinky)
    sonuc = dt.capraz(dt.belgeleri_topla([yol]), n=8)
    assert (sonuc["n"], sonuc["tutarli"]) == (8, 8), [o["farklar"] for o in sonuc["ornekler"]]
    assert json.loads(json.dumps(sonuc))["sema"] == dt.CAPRAZ_SEMA
