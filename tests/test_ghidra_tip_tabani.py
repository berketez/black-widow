"""scripts/measurement/ghidra_tip_tabani.py — çıplak Ghidra tip tabanı ve K1 ölçüleri (plan v2.2 T0c).

Saf mantık sentetik verilerle sınanır. Kilitlenen davranışlar:
  (a) Ghidra tip dizgisi: yerleşik adların C adına çevrilmesi, ``typedef AD TABAN`` biçimi, işaretçi
      derinliği, undefinedN/dizi/code aday vermez, Ghidra typedef haritasında yerleşiğe inen ad;
      DWARF'ın kabul ettiği (ad, derinlik) çiftleri (zincirdeki typedef'ler önlerindeki işaretçi
      sayısıyla, kök adı, takma adlar); adlı tip doğruluğu derinlik eşleşmesi ister,
  (b) K1 sayımları: çiftler ikili içinde, kapsam en az iki üyeli kümeler, B-cubed, kâhin kapsamı;
      makro ortalamada tanımsız program dışarıda; tabaka kısıtlaması; katı ve aile düzeyi,
  (c) önemsiz tabanlar, (d) negatif kontrol (karıştırma, en yakın sıra yüzdeliği, tohum),
  (e) nüfus: uygun fonksiyon (klon, thunk, C++ dışarıda), yalnız DWARF konumuyla tam eşleşme,
      Ghidra parametresi depolama ortağından (sıradan değil).
Yerel T0b ve T0c koşu dizinleri varsa gerçek veride T0b'nin 9 433 / 9 821 sayıları da sınanır.

Mutasyon koruması: ``scripts/measurement/mutation_specs_ghidra_tip_tabani.json``
(``PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec <o dosya>``).
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parents[1] / "scripts" / "measurement" / "ghidra_tip_tabani.py"
_spec = importlib.util.spec_from_file_location("ghidra_tip_tabani_under_test", _PATH)
gt = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = gt
_spec.loader.exec_module(gt)


# --------------------------------------------------------------------------------------------
# (a) Ghidra tip dizgisi ve adlı tip doğruluğu


@pytest.mark.parametrize("metin,typedefler,tur,taban,derinlik,adaylar", [
    ("undefined8", {}, "bilinmiyor", "undefined8", 0, []),
    ("undefined8 *", {}, "bilinmiyor", "undefined8", 1, []),
    ("ulong", {}, "temel", "ulong", 0, [["long unsigned int", 0]]),
    ("char * *", {}, "temel", "char", 2, [["char", 2]]),
    ("byte *", {}, "temel", "byte", 1, [["unsigned char", 1]]),
    ("FILE *", {}, "adli", "FILE", 1, [["FILE", 1]]),
    ("struct stat *", {}, "adli", "stat", 1, [["stat", 1]]),
    ("size_t *", {"size_t": "ulong"}, "temel_typedef", "size_t", 1,
     [["long unsigned int", 1], ["size_t", 1]]),
    ("size_t *", {}, "adli", "size_t", 1, [["size_t", 1]]),
    ("undefined1[16] *", {}, "dizi", "undefined1[16]", 1, []),
    ("code *", {}, "kod", "code", 1, []),
    ("void *", {}, "void", "void", 1, [["void", 1]]),
    ("", {}, "bos", None, 0, []),
])
def test_ghidra_tipi(metin, typedefler, tur, taban, derinlik, adaylar):
    g = gt.ghidra_tipi(metin, typedefler)
    assert (g["tur"], g["taban"], g["derinlik"], g["adaylar"]) == (tur, taban, derinlik, adaylar)


def test_ghidra_tipi_typedef_bicimi():
    g = gt.ghidra_tipi("typedef size_t ulong")
    assert (g["tur"], g["taban"], g["adaylar"]) == ("typedef", "size_t",
                                                     [["long unsigned int", 0], ["size_t", 0]])
    g = gt.ghidra_tipi("typedef foo_t undefined4")
    assert g["adaylar"] == [["foo_t", 0]]
    g = gt.ghidra_tipi("typedef foo_ptr bar *")
    assert gt.etkin_derinlik(g) == 1 and gt.ghidra_yapi_etiketi(g) == "bar"


def test_ghidra_typedef_haritasi_ve_yerlesige_inme():
    harita, cakisan = gt.ghidra_typedef_haritasi(
        ["typedef size_t ulong", "typedef __off_t long", "typedef x int", "typedef x uint",
         "FILE *", "typedef socklen_t __socklen_t", "typedef __socklen_t uint",
         "typedef p_t bar *", "typedef a b", "typedef b a"])
    assert cakisan == ["x"] and harita["size_t"] == "ulong"
    assert gt.ghidra_tipi("socklen_t *", harita)["tur"] == "temel_typedef"
    assert gt.ghidra_tipi("socklen_t *", harita)["adaylar"] == [["socklen_t", 1],
                                                                ["unsigned int", 1]]
    assert gt.ghidra_tipi("p_t *", harita)["tur"] == "adli"      # işaretçi typedef'i skaler değil
    assert gt.ghidra_tipi("a *", harita)["tur"] == "adli"        # döngü


@pytest.mark.parametrize("metin,etiket", [
    ("char *", "char*"), ("byte *", "char*"), ("uint *", "temel*"), ("long", "temel"),
    ("undefined8 *", "bilinmiyor*"), ("undefined4", "bilinmiyor"), ("FILE *", "adli*"),
    ("void *", "void*"), ("typedef size_t ulong", "typedef:temel"), ("code *", "kod*"),
])
def test_ghidra_turu_etiketi(metin, etiket):
    assert gt.ghidra_turu_etiketi(gt.ghidra_tipi(metin)) == etiket


def test_ghidra_yapi_etiketi():
    harita = {"size_t": "ulong"}
    etiket = {m: gt.ghidra_yapi_etiketi(gt.ghidra_tipi(m, harita))
              for m in ("FILE *", "FILE * *", "size_t *", "long *", "stat", "BIO *",
                        "undefined8 *", "void *")}
    assert etiket == {"FILE *": "FILE", "FILE * *": None, "size_t *": None, "long *": None,
                      "stat": None, "BIO *": "BIO", "undefined8 *": None, "void *": None}


def _tip(ham, kok, derinlik, kanonik="?", sinif="yapi*"):
    return {"cozuldu": True, "kanonik": kanonik, "sinif": sinif, "derinlik": derinlik,
            "kok": kok, "ham": [{"etiket": e, "konum": f"ana:0x{i:x}", **({"ad": a} if a else {})}
                                for i, (e, a) in enumerate(ham)]}


FILE_TIPI = _tip([("pointer_type", None), ("typedef", "FILE"), ("structure_type", "_IO_FILE")],
                 {"tur": "struct", "ad": "_IO_FILE", "konum": "ana:0x2"}, 1, "struct _IO_FILE *")
SIZE_T = _tip([("typedef", "size_t"), ("base_type", "long unsigned int")],
              {"tur": "temel", "ad": "long unsigned int"}, 0, "long unsigned int", "skaler")


def test_dwarf_kabul_ciftleri():
    assert gt.dwarf_kabul_ciftleri(FILE_TIPI) == {("FILE", 1), ("_IO_FILE", 1)}
    assert gt.dwarf_kabul_ciftleri(FILE_TIPI, ["__FILE"]) == {("FILE", 1), ("_IO_FILE", 1),
                                                              ("__FILE", 1)}
    p_tipi = _tip([("typedef", "foo_ptr"), ("pointer_type", None), ("structure_type", "foo")],
                  {"tur": "struct", "ad": "foo", "konum": "ana:0x2"}, 1)
    assert gt.dwarf_kabul_ciftleri(p_tipi) == {("foo_ptr", 0), ("foo", 1)}
    assert gt.dwarf_kabul_ciftleri(SIZE_T) == {("size_t", 0), ("long unsigned int", 0)}
    anonim = _tip([("pointer_type", None), ("typedef", "mbstate_t"), ("typedef", "__mbstate_t"),
                   ("structure_type", None)], {"tur": "struct", "ad": None, "konum": "ek:0x9"}, 1)
    assert gt.dwarf_kabul_ciftleri(anonim) == {("mbstate_t", 1), ("__mbstate_t", 1)}
    bos = _tip([("pointer_type", None)], {"tur": "void"}, 1, "void *", "void*")
    assert gt.dwarf_kabul_ciftleri(bos) == {("void", 1)}
    assert gt.dwarf_kabul_ciftleri({"cozuldu": False}) == set()


@pytest.mark.parametrize("ghidra,tip,dogru", [
    ("FILE *", FILE_TIPI, True), ("_IO_FILE *", FILE_TIPI, True), ("FILE * *", FILE_TIPI, False),
    ("SHA256_CTX *", _tip([("pointer_type", None), ("structure_type", "sha256_ctx")],
                          {"tur": "struct", "ad": "sha256_ctx", "konum": "ana:0x1"}, 1), False),
    ("undefined8 *", FILE_TIPI, False), ("long", FILE_TIPI, False),
    ("typedef size_t ulong", SIZE_T, True), ("ulong", SIZE_T, True), ("long", SIZE_T, False),
    ("typedef foo_t undefined4", _tip([("typedef", "foo_t"), ("base_type", "int")],
                                      {"tur": "temel", "ad": "int"}, 0, "int", "skaler"), True),
    ("long", _tip([("base_type", "long long int")], {"tur": "temel", "ad": "long long int"}, 0,
                  "long long int", "skaler"), False),
])
def test_adli_tip_dogru_mu(ghidra, tip, dogru):
    assert gt.adli_tip_dogru_mu(gt.ghidra_tipi(ghidra), gt.dwarf_kabul_ciftleri(tip)) is dogru


# --------------------------------------------------------------------------------------------
# (b) K1 sayımları, makro, yüzdelik, negatif kontrol


ORNEK = [("A", "x"), ("A", "x"), ("A", "y"), ("B", "z"), ("B", "z"), (None, "z"), (None, "w"),
         ("C", "v")]


def test_k1_sayimlari_ve_oranlar():
    s = gt.k1_sayimlari(ORNEK)
    assert (s["n"], s["kapsanan"], s["kume_cifti"], s["dogru_cift"], s["gercek_cift"]) == (
        8, 5, 4, 2, 4)
    assert s["kahin_kapsanan"] == 5
    o = gt.k1_oranlari(s)
    assert (o["cift_kesinligi"], o["cift_duyarliligi"], o["kapsam"]) == (0.5, 0.5, 0.625)
    assert o["b3_kesinlik"] == round(11 / 15, 6) and o["b3_duyarlilik"] == round(11 / 15, 6)
    assert o["kahin_kapsam"] == 0.625
    assert gt.k1_oranlari(gt.k1_sayimlari([(None, "x")]))["cift_kesinligi"] is None


def test_program_k1_ciftler_ikili_icinde():
    """İki ikilide birer FILE parametresi: ikililer arası çift kurulmaz."""
    p = gt.program_k1({"a": [("FILE", "struct _IO_FILE #1")], "b": [("FILE", "struct _IO_FILE #1")]})
    assert p["sayimlar"]["kume_cifti"] == 0 and p["cift_kesinligi"] is None and p["kapsam"] == 0.0
    p = gt.program_k1({"a": [("F", "t"), ("F", "t")], "b": [("F", "t"), ("F", "u")]})
    assert (p["sayimlar"]["kume_cifti"], p["sayimlar"]["dogru_cift"], p["cift_kesinligi"]) == (
        2, 1, 0.5)


def test_makro_tanimsiz_program_disarida():
    assert gt.makro([1.0, None, 0.5]) == {"deger": 0.75, "program_sayisi": 2}
    assert gt.makro([None]) == {"deger": None, "program_sayisi": 0}


def test_yuzdelik_en_yakin_sira():
    assert gt.yuzdelik([float(i) for i in range(100, 0, -1)], 0.99) == 99.0
    assert gt.yuzdelik([5.0], 0.99) == 5.0 and gt.yuzdelik([], 0.99) is None


def _veri(ogeler):
    return {"p": {"i": ogeler}}


def test_karistirma_kontrolu():
    tek = _veri([("tek", t) for t in "xxxxxyyyyy"])
    k = gt.karistirma_kontrolu(tek, n=20)
    assert k["gozlenen"] == k["karisik_yuzdelik"] and k["fark"] == 0.0   # tek küme değişmez
    saf = _veri([("A", "x")] * 10 + [("B", "y")] * 10)
    k1 = gt.karistirma_kontrolu(saf, n=200)
    assert k1["gozlenen"] == 1.0 and k1["karisik_yuzdelik"] < 0.9 and k1["fark"] > 0.1
    assert k1 == gt.karistirma_kontrolu(saf, n=200)                   # tohumlu, belirlenimci
    assert k1["tohum"] == gt.tohum(gt.KARISTIRMA_TOHUM_METNI)
    assert gt.karistirma_kontrolu(saf, n=200, tohum_metni="baska") != k1


# --------------------------------------------------------------------------------------------
# (e) nüfus ve uçtan uca


def test_uygun_mu():
    f = {"eslesme": "adres", "klon": [], "ghidra": {"thunk": False}, "dwarf": {"dil": "C"},
         "decompile": True}
    assert gt.uygun_mu(f)
    for degisiklik in ({"klon": ["sira_degisik"]}, {"ghidra": {"thunk": True}},
                       {"dwarf": {"dil": "C++"}}, {"decompile": False}, {"eslesme": "yok"}):
        assert not gt.uygun_mu({**f, **degisiklik}), degisiklik


def _yapi(ad_, ozet, *, bildirim=False, takma=(), sinif="program", tanimlar=None, ilk_uye=()):
    return {"tur": "struct", "ad": ad_, "kimlik": f"struct {ad_}", "bildirim": bildirim,
            "boyut": None if bildirim else 8, "uyeler": None if bildirim else [],
            "yerlesim": None if bildirim else {"durum": "tam", "ozet": ozet, "imza": "struct/8/-"},
            "ilk_uye": list(ilk_uye), "takma_adlar": list(takma),
            "koken": {"dosya": None, "kaynak": None, "sinif": sinif,
                      "tanimsiz": bildirim and not tanimlar},
            "tanimlar": list(tanimlar or [])}


def _ptip(ad_, konum_, typedef=None, bildirim=False):
    ham = [("pointer_type", None)] + ([("typedef", typedef)] if typedef else []) + [
        ("structure_type", ad_)]
    return _tip(ham, {"tur": "struct", "ad": ad_, "konum": konum_, "bildirim": bildirim}, 1,
                f"struct {ad_} *")


def _belgeler(tmp_path=None):
    """Sentetik T0b/T0c belgeleri: tek ikili 'x' (paket 'p')."""
    def hfonk(ad_, giris, konum_, parametreler, **ek):
        f = {"eslesme": "adres", "klon": [], "decompile": True,
             "ghidra": {"giris": giris, "thunk": False}, "parametreler": parametreler,
             "dwarf": {"ad": ad_, "adres": "0x0", "konum": konum_, "dil": "C"}}
        for a, v in ek.items():
            f[a] = {**f[a], **v} if isinstance(v, dict) and a in f else v
        return f

    def hpar(konum_, tip, sinif, ortak, kaynak="dwarf", eslesme="tam", sira=1):
        return {"dwarf": {"sira": sira, "konum": konum_, "tip": tip, "sinif": sinif},
                "depolama_ortagi": ortak, "depolama_kaynagi": kaynak if ortak else None,
                "eslesme": eslesme if ortak else None, "sinif": None if ortak else "ghidra_az"}

    foo = "struct foo *"
    h = {"sema": gt.HIZALAMA_SEMA, "girdi": {"ikili": "x", "build_id": "b1", "paket": "p"},
         "fonksiyonlar": [
             hfonk("f1", "0x10", "ana:0x100", [
                 hpar("ana:0x110", foo, "yapi*", 2, sira=1),        # sıra 1, depolama yuva 2
                 hpar("ana:0x118", "int", "skaler", 1, sira=2),
                 hpar("ana:0x120", foo, "yapi*", 3, kaynak="abi"),  # ABI yedeği: dışarıda
                 hpar("ana:0x128", foo, "yapi*", None)]),           # hizalanmadı: tavanda
             hfonk("f2", "0x20", "ana:0x200", [hpar("ana:0x210", foo, "yapi*", 1)],
                   klon=["sira_degisik"]),
             hfonk("f3", "0x30", "ana:0x300", [hpar("ana:0x310", foo, "yapi*", 1)],
                   ghidra={"thunk": True}),
             hfonk("f4", "0x40", "ana:0x400", [hpar("ana:0x410", foo, "yapi*", 1)],
                   dwarf={"dil": "C++"}),
             hfonk("f6", "0x60", "ana:0x600", [hpar("ana:0x610", foo, "yapi*", 1)]),
             hfonk("f7", "0x70", "ana:0x700", [hpar("ana:0x710", "struct bar *", "yapi*", 1),
                                               hpar("ana:0x718", "struct dict *", "yapi*", 2)]),
             {"eslesme": "govde_icinde", "dwarf": {"konum": "ana:0x800"}, "parametreler": []},
         ]}
    g = {"sema": gt.GHIDRA_SEMA, "girdi": {"sha256": "s"}, "fonksiyonlar": [
        {"giris": "0x10", "decompile": {"parametreler": [{"tip": "int"}, {"tip": "foo_t *"},
                                                         {"tip": "undefined8"}]}},
        {"giris": "0x20", "decompile": {"parametreler": [{"tip": "foo_t *"}]}},
        {"giris": "0x30", "decompile": {"parametreler": [{"tip": "foo_t *"}]}},
        {"giris": "0x40", "decompile": {"parametreler": [{"tip": "foo_t *"}]}},
        {"giris": "0x60", "decompile": {"parametreler": [{"tip": "foo_t *", "tip_kilitli": True}]}},
        {"giris": "0x70", "decompile": {"parametreler": [{"tip": "long"}, {"tip": "dict *"}]}},
    ]}
    tfoo = _ptip("foo", "ana:0x50", typedef="foo_t")
    tbar = _ptip("bar", "ana:0x60", bildirim=True)
    tdict = _ptip("dict", "ana:0x70", bildirim=True)
    int_tipi = _tip([("base_type", "int")], {"tur": "temel", "ad": "int"}, 0, "int", "skaler")

    def dpar(konum_, tip):
        return {"konum": konum_, "tip": tip}

    d = {"sema": gt.DWARF_SEMA, "girdi": {"ana": {"build_id": "b1"}}, "fonksiyonlar": [
        {"konum": "ana:0x100", "parametreler": [dpar("ana:0x110", tfoo), dpar("ana:0x118", int_tipi),
                                                dpar("ana:0x120", tfoo), dpar("ana:0x128", tfoo)]},
        {"konum": "ana:0x600", "parametreler": [dpar("ana:0x610", tfoo)]},
        {"konum": "ana:0x700", "parametreler": [dpar("ana:0x710", tbar), dpar("ana:0x718", tdict)]},
    ], "yapilar": {
        "ana:0x50": _yapi("foo", "f0", takma=["foo_t"], tanimlar=["ana:0x50"],
                          ilk_uye=[{"tur": "struct", "ad": "base", "ozet": "b0", "takma_ad": None}]),
        "ana:0x60": _yapi("bar", None, bildirim=True, sinif=None),
        "ana:0x70": _yapi("dict", None, bildirim=True, tanimlar=["ana:0x71", "ana:0x72"]),
        "ana:0x71": _yapi("dict", "d56"), "ana:0x72": _yapi("dict", "d48"),
    }}
    if tmp_path is None:
        return h, g, d
    for alt, ad_, b in (("hizalama", "x.json", h), ("ghidra", "x.json", g), ("dwarf/p", "x.json", d)):
        (tmp_path / alt).mkdir(parents=True, exist_ok=True)
        (tmp_path / alt / ad_).write_text(json.dumps(b), encoding="utf-8")
    (tmp_path / "dwarf/p/toplu.json").write_text(json.dumps(
        {"dosyalar": [{"build_id": "b1", "cikti": "x.json"}]}), encoding="utf-8")
    return tmp_path


def test_ikili_kayitlari_nufus_ve_esleme():
    h, g, d = _belgeler()
    s = gt.ikili_kayitlari(h, g, d, {})
    k = {r["konum"]: r for r in s["kayitlar"]}
    assert set(k) == {"ana:0x110", "ana:0x118", "ana:0x610", "ana:0x710", "ana:0x718"}
    assert k["ana:0x110"]["ghidra_tip"] == "foo_t *"          # depolama ortağı, sıra değil
    assert k["ana:0x118"]["ghidra_tip"] == "int" and k["ana:0x118"]["adli_dogru"]
    assert k["ana:0x110"]["adli_dogru"] and k["ana:0x110"]["ghidra_etiketi"] == "foo_t"
    assert k["ana:0x610"]["tip_kilitli"] is True
    assert (k["ana:0x110"]["kimlik"], k["ana:0x110"]["aile"]) == ("struct foo #f0", "struct base #b0")
    assert (k["ana:0x710"]["k1_durum"], k["ana:0x710"]["tabaka"],
            k["ana:0x710"]["tabaka_tanimsiz_dis"]) == ("opak", "bilinmiyor", "kutuphane")
    assert (k["ana:0x718"]["k1_durum"], k["ana:0x718"]["kimlik"]) == ("cok_tanimli", None)
    # (a) ada bakar: "dict *" adca doğru; K1'de kimlik çok tanımlı olduğu için karar dışı
    assert k["ana:0x718"]["ghidra_etiketi"] == "dict" and k["ana:0x718"]["adli_dogru"]
    assert not k["ana:0x710"]["adli_dogru"] and k["ana:0x710"]["ghidra_etiketi"] is None
    sy = s["sayac"]
    assert (sy["dwarf_yapi_hepsi"], sy["uygun_yapi"]) == (9, 6)
    assert sy["uygun_yapi_disari:abi:tam:None"] == 1
    assert sy["uygun_yapi_disari:None:None:ghidra_az"] == 1
    assert sy.get("tip_uyusmazligi", 0) == 0
    h["fonksiyonlar"][0]["parametreler"][1]["dwarf"]["tip"] = "long"
    assert gt.ikili_kayitlari(h, g, d, {})["sayac"]["tip_uyusmazligi"] == 1


def _kayit(ikili, etiket, kimlik, aile=None, tabaka="program"):
    return {"ikili": ikili, "dwarf_sinif": "yapi*", "kimlik": kimlik, "aile": aile or kimlik,
            "tabaka": tabaka, "tabaka_tanimsiz_dis": tabaka, "ghidra_etiketi": etiket,
            "kahin_boyut": None, "k1_durum": "tanim" if kimlik else "cok_tanimli"}


def test_k1_tablosu_tabaka_duzey_ve_onemsizler():
    veri = {"p": {"i": [_kayit("i", "F", "t1", "a", "kutuphane"), _kayit("i", "F", "t1", "a", "kutuphane"),
                        _kayit("i", "F", "t2", "a", "program"), _kayit("i", None, "t2", "a", "program"),
                        _kayit("i", "F", None)]}}
    t = gt.k1_tablosu(veri, "ghidra_etiketi")
    hepsi = t["hepsi"]["kati"]["program"]["p"]
    assert (hepsi["sayimlar"]["n"], hepsi["sayimlar"]["kume_cifti"], hepsi["cift_kesinligi"]) == (
        4, 3, round(1 / 3, 6))                                # kimliksiz öğe dışarıda
    assert t["hepsi"]["aile"]["program"]["p"]["cift_kesinligi"] == 1.0
    kut = t["kutuphane"]["kati"]["program"]["p"]
    assert (kut["sayimlar"]["n"], kut["cift_kesinligi"], kut["kapsam"]) == (2, 1.0, 1.0)
    prg = t["program"]["kati"]["program"]["p"]
    assert (prg["sayimlar"]["n"], prg["sayimlar"]["kume_cifti"], prg["kapsam"]) == (2, 0, 0.0)
    tek = gt.k1_tablosu(veri, "tek_sinif")["hepsi"]["kati"]["program"]["p"]
    assert (tek["cift_kesinligi"], tek["cift_duyarliligi"], tek["kapsam"]) == (round(2 / 6, 6),
                                                                               1.0, 1.0)
    tekil = gt.k1_tablosu(veri, "tekil")["hepsi"]["kati"]["program"]["p"]
    assert (tekil["cift_kesinligi"], tekil["kapsam"]) == (None, 0.0)


def test_olc_uctan_uca(tmp_path):
    kok = _belgeler(tmp_path)
    oz = gt.olc(kok / "hizalama", kok / "ghidra", kok / "dwarf", kok / "cikti", karistirma=10)
    n = oz["nufus"]["toplam"]
    assert (n["dwarf_yapi_hepsi"], n["uygun_yapi"], n["hizalanan_yapi"], n["k1_nufus"],
            n["kimliksiz"]) == (9, 6, 4, 3, 1)
    assert n["tavan"] == round(4 / 6, 6)
    assert oz["tutarlilik"] == {"tip_uyusmazligi": 0, "parametre_bulunamadi": 0,
                                "fonksiyon_bulunamadi": 0}
    a = oz["a_adli_tip"]["program"]["p"]
    assert (a["yapi*"]["n"], a["yapi*"]["dogru"], a["skaler"]["pay"]) == (4, 3, 1.0)
    assert a["yapi*"]["kilitli_n"] == 1
    m = oz["b_ghidra_k1"]["hepsi"]["kati"]["program"]["p"]
    assert (m["sayimlar"]["kume_cifti"], m["cift_kesinligi"], m["kapsam"]) == (1, 1.0,
                                                                               round(2 / 3, 6))
    satirlar = (kok / "cikti/parametreler.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(satirlar) == 5
    assert json.loads((kok / "cikti/taban.json").read_text(encoding="utf-8"))["sema"] == gt.SEMA


def test_ev_yolu():
    assert gt.ev_yolu(Path.home() / "karadul_olcum" / "x") == "~/karadul_olcum/x"
    assert gt.ev_yolu("/opt/x") == "/opt/x"


_R = Path.home() / "karadul_olcum" / "runs"


@pytest.mark.skipif(not (_R / "t0b-1acba60/hizalama").is_dir() or not (_R / "t0c-a10fde3/dwarf").is_dir(),
                    reason="yerel T0b/T0c koşu dizinleri yok")
def test_gercek_t0b_nufusu_yeniden_uretilir(tmp_path):
    oz = gt.olc(_R / "t0b-1acba60/hizalama", _R / "t0b-1acba60/ghidra_2", _R / "t0c-a10fde3/dwarf",
                tmp_path, karistirma=3)
    n = oz["nufus"]["toplam"]
    assert (n["dwarf_yapi_hepsi"], n["uygun_yapi"], n["hizalanan_yapi"]) == (10537, 9821, 9433)
    assert n["tavan"] == round(9433 / 9821, 6)
    assert oz["tutarlilik"] == {"tip_uyusmazligi": 0, "parametre_bulunamadi": 0,
                                "fonksiyon_bulunamadi": 0}
    assert oz["nufus"]["program"]["redis-tools"]["hizalanan_yapi"] == 4486
