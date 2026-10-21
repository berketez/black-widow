"""scripts/measurement/parametre_hizala.py — Ghidra ↔ DWARF parametre hizalaması (plan v2.2 T0b).

Saf mantık testleri sahte belgelerle koşar. Kilitlenen davranışlar:
  (a) yükleme tabanı: Ghidra ``image_base`` − en küçük ``PT_LOAD``, ``.text`` farkı ve tarama
      aynı farkı vermeli; uyuşmazlık işaretlenir; sanal adresten dosya ofsetine çeviri,
  (b) yazmaç eşleme: ``w``/``x`` aynı GPR, ``b/h/s/d/q/v`` aynı SIMD yazmacı; DWARF girişteki
      konumdan anahtar (argüman dışı yazmaç anahtar vermez); AAPCS64 beklentisi (GPR ve SIMD
      sayaçları ayrı, HFA, 16 bayttan büyük yapı dolaylı, 16 bayt hizalı çift yazmaç, yığına
      taşma),
  (c) hizalama ve sınıflar: karışık int/double imzada depolamayla doğru, sırayla yanlış eşleme;
      x8 dönüş işaretçisi, değişken argüman fazlası, bölünen yapı, ABI yedeği, Ghidra'nın az
      gördüğü parametre, klon, decompile hatası; fonksiyon sınıfı,
  (d) özet sayımları; dwarfdump konum metninin ayrıştırılması ve normalleştirilmesi.
Yerel T0b koşusu (``~/karadul_olcum/runs/t0b-*``) varsa tree üstünde tümleşik test de koşar.

Mutasyon koruması: ``scripts/measurement/mutation_specs_parametre_hizala.json``.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_KOK = Path(__file__).resolve().parents[1] / "scripts" / "measurement"


def _yukle(ad: str, dosya: str):
    spec = importlib.util.spec_from_file_location(ad, _KOK / dosya)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


ph = _yukle("parametre_hizala_under_test", "parametre_hizala.py")
gp = _yukle("ghidra_parametre_under_test", "ghidra_parametre.py")


# --------------------------------------------------------------------------------------------
# Sahte belgeler


def tip(kanonik, sinif, derinlik=0, **kok):
    return {"cozuldu": True, "kanonik": kanonik, "sinif": sinif, "derinlik": derinlik, "kok": kok}


INT = tip("int", "skaler", tur="temel", kodlama="signed", boyut=4)
LONG = tip("long unsigned int", "skaler", tur="temel", kodlama="unsigned", boyut=8)
DOUBLE = tip("double", "skaler", tur="temel", kodlama="float", boyut=8)
FLOAT = tip("float", "skaler", tur="temel", kodlama="float", boyut=4)
LDOUBLE = tip("long double", "skaler", tur="temel", kodlama="float", boyut=16)
INT128 = tip("__int128", "skaler", tur="temel", kodlama="signed", boyut=16)
CHARP = tip("char *", "char*", 1, tur="temel", kodlama="signed_char", boyut=1)


def yapi_tipi(konum, ad=None):
    return tip(f"struct {ad}" if ad else f"struct <anon@{konum}>", "yapi_degerle", tur="struct",
               ad=ad, konum=konum, boyut=None, bildirim=False)


YAPILAR = {
    "ana:0x10": {"tur": "struct", "ad": "nokta", "kimlik": "struct nokta", "bildirim": False,
                 "boyut": 16, "uyeler": [{"ad": "x", "ofset": 0, "kanonik": "double"},
                                         {"ad": "y", "ofset": 8, "kanonik": "double"}]},
    "ana:0x20": {"tur": "struct", "ad": "uc", "kimlik": "struct uc", "bildirim": False,
                 "boyut": 12, "uyeler": [{"ad": "a", "ofset": 0, "kanonik": "int"},
                                         {"ad": "b", "ofset": 4, "kanonik": "int"},
                                         {"ad": "c", "ofset": 8, "kanonik": "int"}]},
    "ana:0x30": {"tur": "struct", "ad": "buyuk", "kimlik": "struct buyuk", "bildirim": False,
                 "boyut": 24, "uyeler": [{"ad": "a", "ofset": 0, "kanonik": "long int"},
                                         {"ad": "b", "ofset": 8, "kanonik": "long int"},
                                         {"ad": "c", "ofset": 16, "kanonik": "long int"}]},
    "ana:0x40": {"tur": "struct", "ad": "vek", "kimlik": "struct vek", "bildirim": True,
                 "boyut": None, "uyeler": None, "tanimlar": ["ana:0x48"]},
    "ana:0x48": {"tur": "struct", "ad": "vek", "kimlik": "struct vek", "bildirim": False,
                 "boyut": 16, "uyeler": [{"ad": "v", "ofset": 0, "kanonik": "float[4]"}]},
}


def yazmac(ad_, arguman=True):
    return {"tur": "yazmac", "yazmac": ad_, "arguman": arguman, "ifade": f"<{ad_}>"}


def dp(sira, ad_, tip_, giris, somut_sira=None, tekrar=False):
    return {"sira": sira, "somut_sira": somut_sira if somut_sira is not None else sira, "ad": ad_,
            "konum": f"ana:0x{0x1000 + sira * 8 + (4 if tekrar else 0):x}", "tekrar": tekrar,
            "tip": tip_, "giris": giris}


def dfonk(ad_, adres, parametreler, *, degisken=False, sonekler=()):
    return {"ad": ad_, "adres": f"0x{adres:x}", "konum": f"ana:0x{adres:x}",
            "klon": {"sonekler": list(sonekler), "abstract_origin": False, "origin_inline": None,
                     "bayrak": bool(sonekler)},
            "degisken_arguman": degisken, "parametreler": parametreler,
            "soyut_parametre_sayisi": None, "dil": 0x1D}


def gparam(sira, tip_, *parcalar):
    p = []
    for x in parcalar:
        if isinstance(x, int):
            p.append({"tur": "yigin", "ofset": x, "boyut": 8})
        else:
            p.append({"tur": "yazmac", "ad": x, "boyut": 8})
    return {"sira": sira, "ad": f"param_{sira}", "tip": tip_, "boyut": 8,
            "depolama": {"metin": ",".join(map(str, parcalar)), "parcalar": p, "ozel": None}}


def gfonk(giris, parametreler, *, basarili=True, ad_=None):
    return {"ad": ad_ or f"FUN_{giris:08x}", "giris": f"0x{giris:x}", "govde": [[giris, giris + 0x3F]],
            "thunk": False, "imza_kaynagi": "DEFAULT", "liste_parametreleri": [],
            "ilk_baytlar": None,
            "decompile": {"basarili": basarili, "parametreler": parametreler, "imza": "?",
                          "model": "__cdecl"}}


# --------------------------------------------------------------------------------------------
# (a) yükleme tabanı


def _ghidra_belge(fonks, image_base="0x100000", text="0x104000"):
    return {"program": {"image_base": image_base,
                        "bloklar": [{"ad": ".text", "bas": text}]},
            "fonksiyonlar": fonks}


ELF = {"e_type": "ET_DYN",
       "yukler": [{"vaddr": 0x0, "memsz": 0x9000, "offset": 0x0, "filesz": 0x9000, "flags": 5},
                  {"vaddr": 0x1FD00, "memsz": 0x900, "offset": 0xFD00, "filesz": 0x300, "flags": 6}],
       "bolumler": {".text": {"addr": 0x4000, "size": 0x4000, "offset": 0x4000}}}


def test_pie_tabani_uc_yol_ayni():
    dwarf = [0x4100, 0x4200, 0x4300, 0x4380]
    fonks = [gfonk(a + 0x100000, []) for a in dwarf] + [gfonk(0x104040, [])]
    t = ph.pie_tabani(_ghidra_belge(fonks), ELF, dwarf)
    assert (t["fark_image_base"], t["fark_text"], t["tarama_en_sik"]) == (0x100000,) * 3
    assert t["uc_yol_ayni"] is True and t["secilen"] == 0x100000
    assert t["aday_eslesme_paylari"]["0x100000"] == 1.0
    assert t["aday_eslesme_paylari"]["0x0"] == 0.0
    t2 = ph.pie_tabani(_ghidra_belge(fonks, text="0x105000"), ELF, dwarf)
    assert t2["uc_yol_ayni"] is False                 # .text yolu farklı fark veriyor


def test_vaddr_dosya_ofseti():
    assert ph.vaddr_dosya_ofseti(ELF["yukler"], 0x4100) == 0x4100
    assert ph.vaddr_dosya_ofseti(ELF["yukler"], 0x1FD10) == 0xFD10
    assert ph.vaddr_dosya_ofseti(ELF["yukler"], 0x20100) is None     # .bss: dosyada yok


def test_govde_indeksi():
    g = ph.GovdeIndeksi([gfonk(0x1000, []), gfonk(0x2000, [])])
    assert g.icinde(0x1010) == "0x1000" and g.icinde(0x203F) == "0x2000"
    assert g.icinde(0x1800) is None


# --------------------------------------------------------------------------------------------
# (b) yazmaç eşleme ve AAPCS64


def test_yazmac_anahtari():
    assert ph.yazmac_anahtari("w3") == ph.yazmac_anahtari("x3") == ("x", 3)
    for ad_ in ("b0", "h0", "s0", "d0", "q0", "v0"):
        assert ph.yazmac_anahtari(ad_) == ("v", 0)
    for ad_ in ("sp", "xzr", "x31", "lr", None, ""):
        assert ph.yazmac_anahtari(ad_) is None


def test_ghidra_ve_dwarf_anahtarlari():
    assert ph.ghidra_anahtarlari(gparam(1, "int", "w0")) == [("x", 0)]
    assert ph.ghidra_anahtarlari(gparam(2, "double", "d1")) == [("v", 1)]
    assert ph.ghidra_anahtarlari(gparam(3, "long", 8)) == [("yigin", 8)]
    assert ph.ghidra_anahtarlari(gparam(4, "s", "x2", "x3")) == [("x", 2), ("x", 3)]
    assert ph.dwarf_anahtarlari(yazmac("x0")) == [("x", 0)]
    assert ph.dwarf_anahtarlari(yazmac("v2")) == [("v", 2)]
    assert ph.dwarf_anahtarlari(yazmac("x19", arguman=False)) is None
    assert ph.dwarf_anahtarlari({"tur": "yigin", "ofset": 16}) == [("yigin", 16)]
    assert ph.dwarf_anahtarlari({"tur": "dolayli", "yazmac": "x1", "arguman": True,
                                 "kaynak": "loclist"}) == [("x", 1)]
    # exprloc ile yazılmış dolaylı konum prolog sonrasının yazmacı olabilir (error_tail va_list)
    assert ph.dwarf_anahtarlari({"tur": "dolayli", "yazmac": "x4", "arguman": True,
                                 "kaynak": "exprloc"}) is None
    assert ph.dwarf_anahtarlari(dict(yazmac("x0"), kaynak="exprloc")) == [("x", 0)]
    assert ph.dwarf_anahtarlari({"tur": "dolayli", "yazmac": "x22", "arguman": False}) is None
    parcali = {"tur": "parcali", "parcalar": [yazmac("x2"), {"tur": "konumsuz"}]}
    assert ph.dwarf_anahtarlari(parcali) == [("x", 2), None]
    for yok in ({"tur": "konumsuz"}, {"tur": "sabit"}, {"tur": "yerel_yuva", "ofset": -16}, None):
        assert ph.dwarf_anahtarlari(yok) is None


def _abi(tipler):
    ps = [{"tip": t} for t in tipler]
    return [None if a is None else ([ph.anahtar_metni(k) for k in a["anahtarlar"]], a["dolayli"])
            for a in ph.aapcs64(ps, YAPILAR)]


def test_aapcs64_ayri_sayaclar_ve_kumeler():
    assert _abi([CHARP, DOUBLE, LONG, FLOAT, INT]) == [
        (["x0"], False), (["v0"], False), (["x1"], False), (["v1"], False), (["x2"], False)]
    assert _abi([yapi_tipi("ana:0x10", "nokta"), INT]) == [(["v0", "v1"], False), (["x0"], False)]
    assert _abi([yapi_tipi("ana:0x20", "uc"), INT]) == [(["x0", "x1"], False), (["x2"], False)]
    assert _abi([yapi_tipi("ana:0x30", "buyuk"), INT]) == [(["x0"], True), (["x1"], False)]
    assert _abi([yapi_tipi("ana:0x40", "vek")]) == [(["v0", "v1", "v2", "v3"], False)]   # bildirim->tanım
    assert _abi([LDOUBLE, DOUBLE]) == [(["v0"], False), (["v1"], False)]
    assert _abi([INT, INT128]) == [(["x0"], False), (["x2", "x3"], False)]           # çift hizalı


def test_aapcs64_yigina_tasma_ve_belirsiz():
    sonuc = _abi([LONG] * 9 + [DOUBLE] * 9)
    assert [k for k, _ in sonuc[:8]] == [[f"x{i}"] for i in range(8)]
    assert sonuc[8] == (["Stack[0]"], False)
    assert sonuc[17] == (["Stack[8]"], False)                       # v0-v7 dolunca yığın
    belirsiz = tip("class foo", "yapi_degerle", tur="class", konum="ana:0x99")
    assert _abi([INT, belirsiz, INT]) == [(["x0"], False), None, None]


def test_klon_nedenleri():
    f = dfonk("g", 0x10, [dp(2, "y", INT, yazmac("x0"), somut_sira=1)], sonekler=(".isra",))
    assert ph.klon_nedenleri(f) == [".isra", "sira_degisik"]
    f2 = dfonk("h", 0x20, [dp(1, "a", INT, yazmac("x0")), dp(1, "a", INT, None, tekrar=True)])
    assert ph.klon_nedenleri(f2) == ["tekrar_die"]
    assert ph.klon_nedenleri(dfonk("k", 0x30, [dp(1, "a", INT, yazmac("x0"))])) == []


# --------------------------------------------------------------------------------------------
# (c) hizalama ve sınıflar


def _satirlar(h):
    return [(s["dwarf"]["ad"], s["depolama_ortagi"], s["depolama_kaynagi"], s["eslesme"],
             s["sinif"], s.get("sira_durumu")) for s in h["parametreler"]]


def test_karisik_imza_depolamayla_dogru_sirayla_yanlis():
    """htop Meter_humanUnit(char *buffer, double value, size_t size): Ghidra double'ı başa alır."""
    df = dfonk("Meter_humanUnit", 0x10A4, [dp(1, "buffer", CHARP, yazmac("x0")),
                                           dp(2, "value", DOUBLE, yazmac("v0")),
                                           dp(3, "size", LONG, yazmac("x1"))])
    gf = gfonk(0x1010A4, [gparam(1, "double", "d0"), gparam(2, "undefined8", "x0"),
                          gparam(3, "undefined8", "x1")])
    h = ph.parametre_hizala(df, gf, YAPILAR)
    assert _satirlar(h) == [("buffer", 2, "dwarf", "tam", None, "celiski"),
                            ("value", 1, "dwarf", "tam", None, "celiski"),
                            ("size", 3, "dwarf", "tam", None, "uyumlu")]
    assert [s["yazmac_sinifi_farki"] for s in h["parametreler"][:2]] == [True, True]
    assert all(s["abi_uyumu"] for s in h["parametreler"])
    assert h["ghidra_fazlasi"] == [] and h["fonksiyon_sinifi"] == "sira_bozuk"


def test_x8_donus_isaretcisi_sirayi_kaydirir():
    df = dfonk("listdir", 0x8740, [dp(1, "dirname", CHARP, yazmac("x0")),
                                   dp(2, "lev", INT, yazmac("x1"))])
    gf = gfonk(0x108740, [gparam(1, "long *", "x8"), gparam(2, "char *", "x0"),
                          gparam(3, "uint", "w1")])
    h = ph.parametre_hizala(df, gf, YAPILAR)
    assert _satirlar(h) == [("dirname", 2, "dwarf", "tam", None, "celiski"),
                            ("lev", 3, "dwarf", "tam", None, "celiski")]
    assert [(g["ad"], g["sinif"]) for g in h["ghidra_fazlasi"]] == [("param_1", "x8_donus")]
    assert h["fonksiyon_sinifi"] == "ghidra_fazla"


def test_degisken_arguman_fazlasi():
    df = dfonk("xAsprintf", 0x1FE0, [dp(1, "strp", CHARP, yazmac("x0")),
                                     dp(2, "fmt", CHARP, yazmac("x1"))], degisken=True)
    gf = gfonk(0x101FE0, [gparam(i + 1, "undefined8", f"x{i}") for i in range(8)])
    h = ph.parametre_hizala(df, gf, YAPILAR)
    assert [g["sinif"] for g in h["ghidra_fazlasi"]] == ["degisken_arguman"] * 6
    assert h["fonksiyon_sinifi"] == "tam_uyum"
    df["degisken_arguman"] = False
    h2 = ph.parametre_hizala(df, gf, YAPILAR)
    assert {g["sinif"] for g in h2["ghidra_fazlasi"]} == {"fazla"}


def test_degerle_yapi_bolunmesi():
    df = dfonk("redisSetTimeout", 0xC008, [
        dp(1, "c", CHARP, yazmac("x0")),
        dp(2, "tv", yapi_tipi("ana:0x10", "nokta") | {"kanonik": "struct timeval"},
           {"tur": "parcali", "parcalar": [yazmac("x1"), yazmac("x2")]})])
    gf = gfonk(0x10C008, [gparam(1, "long", "x0"), gparam(2, "long", "x1"),
                          gparam(3, "long", "x2")])
    h = ph.parametre_hizala(df, gf, {})
    s = h["parametreler"][1]
    assert (s["depolama_ortagi"], s["eslesme"], s["ortak_parcalar"]) == (2, "yapi_bolunmesi", [2, 3])
    assert h["ghidra_fazlasi"] == []                   # param_3 yapının ikinci parçası
    gf_tam = gfonk(0x10C008, [gparam(1, "long", "x0"), gparam(2, "timeval", "x1", "x2")])
    assert ph.parametre_hizala(df, gf_tam, {})["parametreler"][1]["eslesme"] == "tam"


def test_abi_yedegi_ve_optimize_parametre():
    """DWARF girişte yer vermiyor (konumsuz); klon değilse AAPCS64 beklentisi eşler."""
    df = dfonk("f", 0x100, [dp(1, "a", INT, yazmac("x0")),
                            dp(2, "b", INT, {"tur": "konumsuz", "kaynak": "loclist"})])
    h = ph.parametre_hizala(df, gfonk(0x100100, [gparam(1, "int", "w0"), gparam(2, "int", "w1")]),
                            YAPILAR)
    assert _satirlar(h)[1] == ("b", 2, "abi", "tam", None, "uyumlu")
    h2 = ph.parametre_hizala(df, gfonk(0x100100, [gparam(1, "int", "w0")]), YAPILAR)
    assert _satirlar(h2)[1] == ("b", None, None, None, "kullanilmayan_ya_da_optimize", "ortaksiz")
    assert h2["fonksiyon_sinifi"] == "tam_uyum"        # girişte olmayanın yokluğu uyumsuzluk değil
    yerel = dfonk("g", 0x200, [dp(1, "p", INT, {"tur": "yerel_yuva", "ofset": -16})])
    h3 = ph.parametre_hizala(yerel, gfonk(0x100200, [gparam(1, "int", "w0")]), YAPILAR)
    assert _satirlar(h3)[0] == ("p", 1, "abi", "tam", None, "uyumlu")


def test_ghidra_az_atladi_ve_yigin():
    df = dfonk("f", 0x100, [dp(1, "a", INT, yazmac("x0")), dp(2, "b", INT, yazmac("x1")),
                            dp(3, "c", INT, yazmac("x2")),
                            dp(4, "d", LONG, {"tur": "yigin", "ofset": 0})])
    h = ph.parametre_hizala(df, gfonk(0x100100, [gparam(1, "int", "w0"),
                                                 gparam(2, "int", "w2")]), YAPILAR)
    assert [s["sinif"] for s in h["parametreler"]] == [None, "ghidra_atladi", None, "yigin_eksik"]
    h2 = ph.parametre_hizala(df, gfonk(0x100100, [gparam(1, "int", "w0")]), YAPILAR)
    assert [s["sinif"] for s in h2["parametreler"]] == [None, "ghidra_az", "ghidra_az",
                                                        "yigin_eksik"]
    assert h2["fonksiyon_sinifi"] == "ghidra_eksik"


def test_klon_ve_decompile_hatasi():
    df = dfonk("g", 0x100, [dp(2, "y", INT, yazmac("x2"), somut_sira=1),
                            dp(1, "this", CHARP, {"tur": "deger", "alt": "cagri_yeri"},
                               somut_sira=2)], sonekler=(".isra",))
    h = ph.parametre_hizala(df, gfonk(0x100100, [gparam(1, "long", "x0"),
                                                 gparam(2, "long", "x2")]), YAPILAR)
    assert _satirlar(h) == [("y", 2, "dwarf", "tam", None, "uyumlu"),     # bildirim sırası 2
                            ("this", None, None, None, "klon", "yalniz_sira")]
    assert [g["sinif"] for g in h["ghidra_fazlasi"]] == ["klon"]
    assert h["parametreler"][0]["abi_anahtar"] is None              # klonda ABI beklentisi yok
    assert h["fonksiyon_sinifi"] == "klon"
    h2 = ph.parametre_hizala(dfonk("k", 0x300, [dp(1, "a", INT, yazmac("x0"))]),
                             gfonk(0x100300, [], basarili=False), YAPILAR)
    assert _satirlar(h2) == [("a", None, None, None, "decompile_yok", "ortaksiz")]
    assert h2["fonksiyon_sinifi"] == "decompile_yok"


# --------------------------------------------------------------------------------------------
# (d) ikili düzeyi, özet, dwarfdump


def _dwarf_belge(fonks, yapilar=None):
    return {"sema": ph.DWARF_SEMA, "girdi": {"ana": {"build_id": "ab", "yol": "/yok"},
                                             "ikili": {"ad": "t"}},
            "fonksiyonlar": fonks, "yapilar": yapilar or {}}


def test_hizala_ikili_ve_ozet():
    dfs = [dfonk("a", 0x4100, [dp(1, "x", INT, yazmac("x0"))]),
           dfonk("b", 0x4200, [dp(1, "y", DOUBLE, yazmac("v0")), dp(2, "z", INT, yazmac("x0"))]),
           dfonk("c", 0x4210, [dp(1, "w", INT, yazmac("x0"))]),     # b'nin gövdesinde
           dfonk("d", 0x8000, [])]                                   # Ghidra'da yok
    gfs = [gfonk(0x104100, [gparam(1, "int", "w0")]),
           gfonk(0x104200, [gparam(1, "double", "d0"), gparam(2, "int", "w0")])]
    h = ph.hizala_ikili(_dwarf_belge(dfs), {"girdi": {"sha256": "x"}, **_ghidra_belge(gfs)},
                        elf=ELF)
    assert h["pie_tabani"]["secilen"] == 0x100000
    assert [f["eslesme"] for f in h["fonksiyonlar"]] == ["adres", "adres", "govde_icinde", "yok"]
    oz = ph.ozet_sayimlari([h])
    assert oz["fonksiyon_eslesmesi"] == {"adres": 2, "govde_icinde": 1, "yok": 1}
    assert oz["a_adresle_eslenen_payi"] == 0.5
    assert (oz["dwarf_parametre"], oz["b_depolama_dwarf"], oz["b_depolama_abi"]) == (3, 3, 0)
    assert oz["b_sira"] == {"uyumlu": 3, "celiski": 0, "yalniz_sira": 0, "ortaksiz": 0}
    assert oz["fonksiyon_sinifi"]["tam_uyum"] == 2


_DD_PARAM = """0x00006032: DW_TAG_formal_parameter [95]   (0x00006019)
              DW_AT_name [DW_FORM_strp]\t( .debug_str[0x000027db] = "argc")
              DW_AT_location [DW_FORM_sec_offset]\t(0x000024dc:
                 [0x0000000000004100, 0x0000000000004140): DW_OP_reg0 W0
                 [0x0000000000004140, 0x0000000000004314): DW_OP_reg21 W21
                 [0x00000000000044c8, 0x0000000000004f48): DW_OP_entry_value(DW_OP_reg0 W0), DW_OP_stack_value)
              DW_AT_GNU_locviews [DW_FORM_sec_offset]\t(0x000024c4)
"""


def test_dwarfdump_konum_ayristirma_ve_normal():
    assert ph.dd_giris_ifadesi(_DD_PARAM, 0x4100) == {"bicim": "DW_FORM_sec_offset",
                                                     "ifade": "DW_OP_reg0 W0"}
    assert ph.dd_giris_ifadesi(_DD_PARAM, 0x44C8)["ifade"] == (
        "DW_OP_entry_value(DW_OP_reg0 W0), DW_OP_stack_value")
    assert ph.dd_giris_ifadesi(_DD_PARAM, 0x4400)["ifade"] is None
    expr = "  DW_AT_location [DW_FORM_exprloc]\t(DW_OP_breg22 W22+0)\n"
    assert ph.dd_giris_ifadesi(expr, 0)["ifade"] == "DW_OP_breg22 W22+0"
    for dd, benim in (("DW_OP_reg0 W0", "DW_OP_reg0"),
                      ("DW_OP_breg22 W22+0", "DW_OP_breg22 0"),
                      ("DW_OP_fbreg -184", "DW_OP_fbreg -184"),
                      ("DW_OP_regx B0", "DW_OP_regx 64"),
                      ("DW_OP_reg2 W2, DW_OP_piece 0x8", "DW_OP_reg2, DW_OP_piece 8"),
                      ("DW_OP_entry_value(DW_OP_reg1 W1), DW_OP_stack_value",
                       "DW_OP_entry_value(DW_OP_reg1), DW_OP_stack_value")):
        assert ph.ifade_normal(dd) == ph.ifade_normal(benim), (dd, benim)
    assert ph.ifade_normal("DW_OP_reg0 W0") != ph.ifade_normal("DW_OP_reg1")


def test_secim_tohumlu_ve_kararli(tmp_path):
    kok = tmp_path / "x_coreutils_9.7-3_arm64" / "usr" / "bin"
    kok.mkdir(parents=True)
    for i in range(20):
        (kok / f"p{i:02d}").write_bytes(b"\x7fELF" + bytes(8))
    (kok / "betik").write_text("#!/bin/sh\n")
    a = ph.secim(tmp_path, n=5)
    b = ph.secim(tmp_path, n=5)
    assert a["coreutils_secilen"] == b["coreutils_secilen"] and len(a["coreutils_secilen"]) == 5
    assert a["coreutils_evreni"] == 20                # ELF olmayan dosya evrende değil
    assert ph.secim(tmp_path, n=5, tohum_metni="baska")["coreutils_secilen"] != a["coreutils_secilen"]


def test_ghidra_parametre_saf_yardimcilar(tmp_path):
    assert gp.depolama_turu(gparam(1, "int", "w0")) == "yazmac"
    assert gp.depolama_turu(gparam(1, "s", "x0", "x1")) == "parcali"
    assert gp.depolama_turu(gparam(1, "long", 8)) == "yigin"
    assert gp.depolama_turu({"depolama": {"parcalar": [], "ozel": "atanmamis"}}) == "atanmamis"
    liste = tmp_path / "l.txt"
    liste.write_text("# yorum\n/a/b\n\n~/c\n")
    assert gp.liste_oku(liste) == [Path("/a/b"), Path.home() / "c"]
    liste.write_text(json.dumps({"ikililer": [{"ikili": "/x/y"}]}))
    assert gp.liste_oku(liste) == [Path("/x/y")]


# --------------------------------------------------------------------------------------------
# Tümleşik: yerel T0b koşusu (geliştirme seti, tree). Veri yoksa atlanır.

_KOSU = sorted((Path.home() / "karadul_olcum" / "runs").glob("t0b-*/ghidra/tree.json"))
_TREE_DBG = (Path.home() / "karadul_olcum/downloads/debian13/x_tree-dbgsym_2.2.1-1_arm64/usr/lib"
             / "debug/.build-id/d9/2a927b3c35989420228a9112c46d7c864a9aed.debug")


@pytest.mark.skipif(not _KOSU or not _TREE_DBG.is_file(), reason="yerel T0b koşusu yok")
def test_gercek_tree_hizalamasi():
    dt = _yukle("dwarf_tip_t0b", "dwarf_tip.py")
    ghidra = json.loads(_KOSU[-1].read_text(encoding="utf-8"))
    h = ph.hizala_ikili(dt.cikar(_TREE_DBG), ghidra, ikili=Path(ghidra["girdi"]["ikili"]))
    t = h["pie_tabani"]
    assert t["uc_yol_ayni"] and t["secilen"] == 0x100000 and t["elf_en_kucuk_vaddr"] == "0x0"
    assert h["bayt_dogrulamasi"]["ayni"] == 110 and h["bayt_dogrulamasi"]["farkli"] == 0
    oz = ph.ozet_sayimlari([h])
    assert oz["fonksiyon_eslesmesi"]["adres"] == oz["dwarf_fonksiyon"] == 110
    assert oz["dwarf_abi_uyumu"].get("farkli", 0) == 0
    listdir = next(f for f in h["fonksiyonlar"] if f["dwarf"]["ad"] == "listdir")
    assert [g["sinif"] for g in listdir["ghidra_fazlasi"]] == ["x8_donus"]


def test_hfa_karari_ic_yapi_acilmadan():
    """Kayan olmayan üye varsa iç yapı tanımı aranmadan HFA değil; yalnız kayan + iç yapı
    varsa ve iç yapı tabloda yoksa belirsiz."""
    yapilar = {"ana:0x50": {"tur": "struct", "ad": "sonuc", "kimlik": "struct sonuc",
                            "bildirim": False, "boyut": 40,
                            "uyeler": [{"ad": "t", "ofset": 0, "kanonik": "struct ic",
                                        "sinif": "yapi_degerle"},
                                       {"ad": "n", "ofset": 32, "kanonik": "long int"}]},
               "ana:0x60": {"tur": "struct", "ad": "kayan", "kimlik": "struct kayan",
                            "bildirim": False, "boyut": 16,
                            "uyeler": [{"ad": "a", "ofset": 0, "kanonik": "struct ic2",
                                        "sinif": "yapi_degerle"},
                                       {"ad": "b", "ofset": 8, "kanonik": "double"}]}}
    assert ph.hfa_uyeleri(yapilar["ana:0x50"], yapilar) is None
    with pytest.raises(ValueError):
        ph.hfa_uyeleri(yapilar["ana:0x60"], yapilar)
    assert ph.abi_sinifi(yapi_tipi("ana:0x50", "sonuc"), yapilar) == ("ref", 8, 8, 1)
    birlik = {"tur": "union", "ad": "u", "kimlik": "union u", "bildirim": False, "boyut": 8,
              "uyeler": [{"ad": "f", "kanonik": "float[2]"}, {"ad": "g", "kanonik": "float"}]}
    assert ph.hfa_uyeleri(birlik, {}) == ("float", 2)            # toplam değil en büyük üye
    assert ph.abi_sinifi(yapi_tipi("ana:0x60", "kayan"), yapilar) is None


def test_x8_ust_sinira_girmez_ve_c_girdisi():
    """ZSTD_getParams_internal: dönüş x8'de; x1-x3 Ghidra'da yok -> ghidra_az (atladı değil).
    C'de in_x2 olarak görünen girdi işaretlenir."""
    df = dfonk("ZSTD_getParams_internal", 0xD6AC, [
        dp(1, "compressionLevel", INT, yazmac("x0")), dp(2, "srcSizeHint", LONG, yazmac("x1")),
        dp(3, "dictSize", LONG, yazmac("x2"))])
    gf = gfonk(0x10D6AC, [gparam(1, "undefined8 *", "x8"), gparam(2, "undefined4", "w0")])
    gf["decompile"]["c"] = "void f(undefined8 *param_1,undefined4 param_2)\n{ g(in_x2); }"
    h = ph.parametre_hizala(df, gf, YAPILAR)
    assert [s["sinif"] for s in h["parametreler"]] == [None, "ghidra_az", "ghidra_az"]
    assert [s.get("c_girdisi") for s in h["parametreler"]] == [None, None, "in_x2"]
    assert ph.c_girdi_yazmaclari("in_w3 + in_d0 + in_stack_00000008 + in_lr") == {
        ("x", 3): "in_w3", ("v", 0): "in_d0"}


def test_zor_vaka_evreni_ve_kapsam_ozeti():
    dfs = [dfonk("b", 0x4200, [dp(1, "y", CHARP, yazmac("x0")), dp(2, "z", DOUBLE, yazmac("v0"))])]
    gfs = [gfonk(0x104200, [gparam(1, "double", "d0"), gparam(2, "char *", "x0")])]
    h = ph.hizala_ikili(_dwarf_belge(dfs), {"girdi": {"sha256": "x"}, **_ghidra_belge(gfs)},
                       elf=ELF)
    h["girdi"]["ikili"] = "t"
    assert len(ph.denetim_evreni([h], "zor")) == 2 == len(ph.denetim_evreni([h], "hepsi"))
    h["fonksiyonlar"][0]["parametreler"][0]["sira_durumu"] = "uyumlu"
    h["fonksiyonlar"][0]["parametreler"][1]["sira_durumu"] = "uyumlu"
    assert ph.denetim_evreni([h], "zor") == []
    with pytest.raises(ValueError):
        ph.denetim_evreni([h], "baska")
    oz = ph.ozet_sayimlari([h])
    assert oz["tip_sinifi_kapsami"]["char*"]["eslenen"] == 1
    assert oz["govde_farkli_fonksiyon"] == 1          # DWARF boyutu sahte belgede yok


def test_ghidra_thunk_sinifi():
    """DWARF'ta gövdesi olan fonksiyonu Ghidra thunk sayıyorsa (tek sıçrama) eşleşmeyen
    parametreler ``ghidra_thunk``; fonksiyon sınıfı da öyle."""
    df = dfonk("setlocale_null_r", 0x6900, [dp(1, "category", INT, yazmac("x0")),
                                            dp(2, "buf", CHARP, yazmac("x1"))])
    gf = gfonk(0x106900, [])
    gf["thunk"] = True
    h = ph.parametre_hizala(df, gf, YAPILAR)
    assert [s["sinif"] for s in h["parametreler"]] == ["ghidra_thunk", "ghidra_thunk"]
    assert h["fonksiyon_sinifi"] == "ghidra_thunk"
