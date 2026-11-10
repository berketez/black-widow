"""karadul/reconstruction/tarif/baglama.py — KS-1 bağlama modülünün testleri (plan v2.2 N1 adım 3).

Tasarım: ``docs/arge/2026-11-10_n1_adim3/baglama_tasarimi_taslak.md`` §2, §4.1, §5.4 (3. satır).
Testler sentetik ``static/`` dizinleri ve elle kurulmuş çapalarla koşar; GT, dbgsym ya da koşu verisi
okunmaz. Okunan tek ölçüm dosyası adım 2'nin ad içermeyen çıktısıdır (``ks1_olcum.json``).
Kilitlenen davranışlar:
  (a) geçiş kuralı: adım 2 kararı ve havuz sayılarından satır durumu; dört satırı, sınırı, N0b
      kuralıyla eşitliği; gerçek ölçüm sayılarıyla çıkan tablo; ürün tablosu "aç"a kadar susar,
  (b) satır tanımı ``ks1_olc.gorunum`` ile aynı; parça satır taşımaz,
  (c) etiket kuralı: en iyi satır; C++ ikilide "kesin" yok; susan satır ad vermez,
  (d) C++ işareti ölçüm betiğiyle aynı (Mach-O'da baştaki tek ``_`` soyulur),
  (e) anahtar: yalnız ``FUN_<onaltılık>``; parça ve export ad almaz; ad olduğu gibi yazılır,
  (f) ön ad sözlüğüne yazma: ``main`` ve elle ad korunur, Faz 1 adı ezilir ve sayılır, ikinci çağrı
      değişiklik yapmaz, sayaç değişmezi,
  (g) durum kodları: girdi eksik, desteklenmeyen platform, hata, kapalı,
  (h) künye yardımcıları: tür işaretleme, ad uyuşmazlığı, etiket, yazım, işleme sırası,
  (i) yan çıktı ve belirlenimcilik.

Mutasyon koruması: ``scripts/measurement/mutation_specs_adim3_baglama.json``
(``PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec <o dosya>``).
"""
from __future__ import annotations

import copy
import importlib.util
import itertools
import json
import random
import sys
from pathlib import Path

import pytest

from karadul.reconstruction.tarif import baglama as B
from karadul.reconstruction.tarif import kesin as K

KOK = Path(__file__).resolve().parents[1]


def _yukle(ad: str, yol: Path):
    spec = importlib.util.spec_from_file_location(ad, yol)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


# Sabit ölçüm betikleri: ürün bunları içe aktarmaz; tanımların eşitliği burada kilitlenir.
ko = _yukle("ks1_olc_baglama_testi", KOK / "scripts" / "measurement" / "ks1_olc.py")
ak = _yukle("alt_kanal_baglama_testi", KOK / "scripts" / "measurement" / "alt_kanal.py")

sys.path.insert(0, str(KOK / "tests"))
from test_tarif_kesin import (  # noqa: E402
    ASSERT_FAIL, ASSERT_RTN, DZ, ELF, LOG, MACHO, Ikili, aapcs_log, adr, bl, darwin_log, temel)

OLCUM = KOK / "docs" / "arge" / "2026-10-21_g11_n1" / "ks1_olcum.json"

# Sınamalarda kullanılan satır tablosu (ürün tablosu değil): dört durumun hepsi görünsün diye
TABLO = {B.ROW_ASSERT: B.STATUS_SILENT, B.ROW_ASSERT_LIFTED: B.STATUS_UNVERIFIED,
         B.ROW_FUNC: B.STATUS_KESIN, B.ROW_FORWARD: B.STATUS_UNVERIFIED}
HEPSI_KESIN = {r: B.STATUS_KESIN for r in B.DECISION_ROWS}


# --------------------------------------------------------------------------------------------
# (a) geçiş kuralı


def test_gecis_kurali_dort_satir():
    # karar kesin → kesin (yanlış oranına bakılmaz)
    assert B.row_status_from_measurement("kesin", 262, 13) == "kesin"
    # kesin değil / yetersiz, L ≤ %10 → doğrulanmadı
    assert B.row_status_from_measurement("yetersiz", 36, 0) == "dogrulanmadi"
    assert B.row_status_from_measurement("kesin_degil", 100, 12) == "dogrulanmadi"
    # kesin değil / yetersiz, L > %10 → sus
    assert B.row_status_from_measurement("kesin_degil", 228, 40) == "sus"
    assert B.row_status_from_measurement("yetersiz", 20, 10) == "sus"
    # n = 0 → sus (karar ne olursa olsun)
    for karar in B.MEASUREMENT_DECISIONS:
        assert B.row_status_from_measurement(karar, 0, 0) == "sus"


def test_gecis_kurali_kesin_yalniz_kesin_karardan():
    for karar, n in itertools.product(("kesin_degil", "yetersiz"), (1, 7, 36, 500)):
        for yanlis in range(0, n + 1, max(1, n // 7)):
            assert B.row_status_from_measurement(karar, n, yanlis) != B.STATUS_KESIN
    assert B.row_status_from_measurement("kesin", 1, 0) == B.STATUS_KESIN


def test_gecis_kurali_sinir_esitlikte_dogrulanmadi():
    # L tam hedefe eşitse satır kalır: kural "L > hedef susar"
    alt, _ = B.wilson(40, 228)
    assert alt > B.WRONG_RATE_TARGET
    assert B.row_status_from_measurement("kesin_degil", 228, 40, target=alt) == "dogrulanmadi"
    assert B.row_status_from_measurement("kesin_degil", 228, 40, target=alt - 1e-9) == "sus"
    # tam sayı sınırı: n = 100'de L, 15 yanlışta %9,3 (kalır), 16 yanlışta %10,1 (susar)
    assert B.wilson(15, 100)[0] <= 0.10 < B.wilson(16, 100)[0]
    assert B.row_status_from_measurement("yetersiz", 100, 15) == "dogrulanmadi"
    assert B.row_status_from_measurement("yetersiz", 100, 16) == "sus"


def test_gecis_kurali_n0b_kuraliyla_ayni():
    """Ölçüt N0b'nin susturma kuralıyla aynı: zayıf ve ölçülemeyen susar, kalan "doğrulanmadı"."""
    assert B.WRONG_RATE_TARGET == ak.YANLIS_HEDEFI and B.WILSON_Z == ak.WILSON_Z
    for n in range(0, 61):
        for yanlis in range(0, n + 1):
            beklenen = "dogrulanmadi" if ak.karar(n, yanlis)["urunde"] else "sus"
            for karar in ("kesin_degil", "yetersiz"):
                assert B.row_status_from_measurement(karar, n, yanlis) == beklenen, (n, yanlis)
            if n:
                assert B.wilson(yanlis, n) == pytest.approx(ak.wilson(yanlis, n), abs=1e-15)
    assert B.wilson(0, 0) == (0.0, 1.0)


@pytest.mark.parametrize("karar, n, yanlis", [
    ("belki", 10, 1), ("", 10, 1), ("kesin", -1, 0), ("kesin", 5, 6), ("yetersiz", 5, -1)])
def test_gecis_kurali_gecersiz_girdi(karar, n, yanlis):
    with pytest.raises(ValueError):
        B.row_status_from_measurement(karar, n, yanlis)


def _olcum_sayilari() -> dict[str, tuple[str, int, int]]:
    """Adım 2 çıktısından satır → (karar, havuz tekil n, tam ada eşit olmayan)."""
    belge = json.loads(OLCUM.read_text(encoding="utf-8"))
    return {satir: (k["karar"], k["havuz"]["n"], k["havuz"]["n"] - k["havuz"]["k"])
            for satir, k in belge["kararlar"].items()}


def test_gecis_kurali_gercek_olcum_sayilariyla():
    """Adım 2'nin (commit 5d0b528) sayılarıyla çıkan tablo. Ürün tablosuna yazılması "aç" commit'inin
    işidir; burada yalnız kuralın bu sayılarla ne verdiği kilitlenir."""
    sayilar = _olcum_sayilari()
    assert sayilar == {"assert": ("kesin_degil", 228, 40), "assert_ust": ("yetersiz", 7, 2),
                       "func_kalibi": ("kesin", 262, 13), "func_aktarma": ("yetersiz", 36, 0)}
    assert {k for k, _, _ in sayilar.values()} <= set(B.MEASUREMENT_DECISIONS)
    tablo = B.row_status_table(sayilar)
    assert tablo == {"assert": "sus", "assert_ust": "dogrulanmadi",
                     "func_kalibi": "kesin", "func_aktarma": "dogrulanmadi"}
    assert list(tablo) == list(B.DECISION_ROWS)
    # sınırların yeri: assert'te L %13,2 (> %10), assert_ust'te L %8,2 (≤ %10)
    assert B.wilson(40, 228)[0] == pytest.approx(0.1316, abs=5e-4)
    assert B.wilson(2, 7)[0] == pytest.approx(0.0822, abs=5e-4)


def test_satir_tablosu_eksik_satir_susar_yabanci_satir_hata():
    assert B.row_status_table({}) == {r: "sus" for r in B.DECISION_ROWS}
    assert B.row_status_table({"func_kalibi": ("kesin", 10, 0)}) == {
        "assert": "sus", "assert_ust": "sus", "func_kalibi": "kesin", "func_aktarma": "sus"}
    for yabanci in ("export", "dizgi_turleri"):
        with pytest.raises(ValueError):
            B.row_status_table({yabanci: ("kesin", 10, 0)})


def test_urun_tablosu_olcumden_turer_ve_kilitli():
    """ "Aç" commit'i: tablo elle yazılmaz, geçiş kuralının adım 2 sayılarına uygulanmasıdır."""
    assert dict(B.ROW_STATUS) == B.row_status_table(B.STEP2_MEASUREMENT) == TABLO
    assert set(B.STEP2_MEASUREMENT) == set(B.DECISION_ROWS)
    with pytest.raises(TypeError):
        B.ROW_STATUS["func_kalibi"] = "sus"   # type: ignore[index]
    with pytest.raises(TypeError):
        B.STEP2_MEASUREMENT["assert"] = ("kesin", 1, 0)   # type: ignore[index]


def test_adim2_sayilari_olcum_dosyasiyla_ayni():
    """Koddaki sayılar commit'li ölçüm dosyasından (ks1_olcum.json) okunanla aynı olmalı."""
    import json
    from pathlib import Path
    yol = Path(__file__).resolve().parents[1] / "docs/arge/2026-10-21_g11_n1/ks1_olcum.json"
    kararlar = json.loads(yol.read_text(encoding="utf-8"))["kararlar"]
    assert set(kararlar) == set(B.DECISION_ROWS)
    for satir, (karar, n, yanlis) in B.STEP2_MEASUREMENT.items():
        havuz = kararlar[satir]["havuz"]
        assert kararlar[satir]["karar"] == karar, satir
        assert (havuz["n"], havuz["n"] - havuz["k"]) == (n, yanlis), satir


# --------------------------------------------------------------------------------------------
# (b) satır tanımı


def _alt_kumeler(ogeler):
    return [c for n in range(1, len(ogeler) + 1) for c in itertools.combinations(ogeler, n)]


def test_karar_satirlari_olcumle_ayni():
    assert B.DECISION_ROWS == ko.KARAR_SATIRLARI
    assert (B.ROW_ASSERT, B.ROW_FUNC, B.ROW_FORWARD) == K.STRING_TYPES
    assert B.ROW_ASSERT_LIFTED == ko.ASSERT_UST


@pytest.mark.parametrize("turler", _alt_kumeler(K.ALL_TYPES))
@pytest.mark.parametrize("rol", [K.ROLE_OWN, K.ROLE_LIFTED, K.ROLE_FRAGMENT])
def test_satir_tanimi_gorunum_ile_ayni(turler, rol):
    kayit = {"turler": list(turler), "rol": rol, "dizgi": bool(set(turler) & set(K.STRING_TYPES))}
    olcumde = tuple(s for s in ko.KARAR_SATIRLARI if ko.gorunum([kayit], s))
    if rol == K.ROLE_FRAGMENT:
        # ölçüm parçayı assert_ust görünümünde ayrı sayar; üründe parça satır taşımaz
        assert "assert_ust" in olcumde
        assert B.anchor_rows(turler, rol) == ()
    else:
        assert B.anchor_rows(turler, rol) == olcumde


@pytest.mark.parametrize("turler, rol, beklenen", [
    (("assert",), "kendi", ("assert",)),
    (("assert",), "ust", ("assert_ust",)),
    (("func_kalibi",), "kendi", ("func_kalibi",)),
    (("func_aktarma",), "kendi", ("func_aktarma",)),
    (("assert", "func_kalibi"), "kendi", ("assert", "func_kalibi")),
    (("assert", "func_kalibi"), "ust", ("assert_ust", "func_kalibi")),
    (("func_kalibi", "func_aktarma"), "kendi", ("func_kalibi", "func_aktarma")),
    (("export",), "kendi", ()),
    (("assert",), "parca", ()),
    (("assert", "func_kalibi"), "parca", ()),
])
def test_satir_tanimi_tablo(turler, rol, beklenen):
    assert B.anchor_rows(turler, rol) == beklenen


# --------------------------------------------------------------------------------------------
# (c) etiket kuralı


def test_etiket_en_iyi_satir():
    # en az bir satır kesin → "kesin" (öbür satır susuyor olsa da)
    assert B.anchor_label(("assert", "func_kalibi"), cpp=False, row_status=TABLO) == "kesin"
    assert B.anchor_label(("func_kalibi", "func_aktarma"), cpp=False, row_status=TABLO) == "kesin"
    assert B.anchor_label(("func_kalibi",), cpp=False, row_status=TABLO) == "kesin"
    # kesin yok, en az biri doğrulanmadı → "doğrulanmadı"
    assert B.anchor_label(("assert", "func_aktarma"), cpp=False, row_status=TABLO) == "doğrulanmadı"
    assert B.anchor_label(("assert_ust",), cpp=False, row_status=TABLO) == "doğrulanmadı"


def test_etiket_susan_satir_ad_vermez():
    assert B.anchor_label(("assert",), cpp=False, row_status=TABLO) is None
    assert B.anchor_label((), cpp=False, row_status=HEPSI_KESIN) is None
    # hepsi susan tablo: hiçbir satır bileşimi ad vermez
    sus = {r: B.STATUS_SILENT for r in B.DECISION_ROWS}
    for satirlar in _alt_kumeler(B.DECISION_ROWS):
        assert B.anchor_label(satirlar, cpp=False, row_status=sus) is None
        assert B.anchor_label(satirlar, cpp=True, row_status=sus) is None
    # öntanımlı tablo ürün tablosudur: sınama tablosuyla aynı etiketi verir
    for satirlar in _alt_kumeler(B.DECISION_ROWS):
        for cpp in (False, True):
            assert B.anchor_label(satirlar, cpp=cpp) == B.anchor_label(satirlar, cpp=cpp, row_status=TABLO)
    assert B.anchor_label(("assert",), cpp=False) is None
    assert B.anchor_label(("func_kalibi",), cpp=False) == "kesin"


def test_etiket_tabloda_olmayan_satir_susar():
    assert B.anchor_label(("func_kalibi",), cpp=False, row_status={}) is None
    assert B.anchor_label(("func_kalibi", "assert_ust"), cpp=False,
                          row_status={"assert_ust": "dogrulanmadi"}) == "doğrulanmadı"


def test_etiket_cpp_ikilide_kesin_yok():
    for satirlar in _alt_kumeler(B.DECISION_ROWS):
        c = B.anchor_label(satirlar, cpp=False, row_status=TABLO)
        cpp = B.anchor_label(satirlar, cpp=True, row_status=TABLO)
        assert cpp != "kesin"
        # C++ yalnız etiketi düşürür: ad veren çapa yine ad verir, susan yine susar
        assert (cpp is None) == (c is None)
    assert B.anchor_label(("func_kalibi",), cpp=True, row_status=TABLO) == "doğrulanmadı"
    assert B.anchor_label(("assert",), cpp=True, row_status=TABLO) is None


def test_etiket_yazimi_n0b_ile_ayni():
    assert B.LABEL_UNVERIFIED == ak.GUVEN_ETIKETLERI["belirsiz"] == "doğrulanmadı"
    assert B.LABELS == ("kesin", "doğrulanmadı")


# --------------------------------------------------------------------------------------------
# (d) C++ işareti


def _f(ad: str, thunk: bool = False, dis: bool = False) -> dict:
    return {"name": ad, "is_thunk": thunk, "is_external": dis}


def test_cpp_isaretleri_olcumle_ayni():
    assert B.CPP_MARKERS == ko.CPP_ISARETLERI


@pytest.mark.parametrize("fonksiyonlar, macho, beklenen", [
    ([_f("_Znwm", thunk=True)], False, True),
    ([_f("__gxx_personality_v0", dis=True)], False, True),
    ([_f("__cxa_throw", thunk=True)], False, True),
    ([_f("__cxa_begin_catch", thunk=True)], False, True),
    ([_f("__cxa_end_catch", dis=True)], False, True),
    ([_f("__cxa_rethrow", thunk=True)], False, True),
    # C ikililerinde de bulunanlar işaret değil
    ([_f("__cxa_finalize", thunk=True), _f("__cxa_atexit", thunk=True)], False, False),
    # iç fonksiyonun adı işaret değil: yalnız içe aktarılan adlar
    ([_f("_ZN3fooE"), _f("malloc", thunk=True)], False, False),
    ([], False, False),
    # Mach-O: baştaki tek ``_`` soyulur
    ([_f("__Znwm", thunk=True)], True, True),
    ([_f("___cxa_throw", thunk=True)], True, True),
    ([_f("_ZSTD_compress", thunk=True)], True, False),
    ([_f("___assert_rtn", thunk=True)], True, False),
    # ELF'te soyulmaz
    ([_f("__Znwm", thunk=True)], False, False),
    ([_f("_ZSTD_compress", thunk=True)], False, True),
])
def test_cpp_ikili(fonksiyonlar, macho, beklenen):
    assert B.is_cpp_binary(fonksiyonlar, macho=macho) is beklenen
    assert ko.cpp_ikili_mi(fonksiyonlar, ko.PLATFORM_MAC if macho else ko.PLATFORM_DEBIAN) is beklenen


def test_cpp_ikili_olcumle_ayni_rastgele():
    rnd = random.Random(20261110)
    havuz = ["malloc", "_malloc", "__Znwm", "_Znwm", "_ZSTD_x", "__ZSTD_x", "___cxa_throw", "__cxa_throw",
             "__cxa_atexit", "___gxx_personality_v0", "__gxx_personality_v0", "FUN_00101000", "", "_",
             "___cxa_rethrow", "__cxa_end_catch", "printf", "_printf", "Z", "_Z"]
    gorulen = set()
    for _ in range(400):
        liste = [{"name": rnd.choice(havuz), "is_thunk": rnd.random() < 0.4,
                  "is_external": rnd.random() < 0.2} for _ in range(rnd.randint(0, 4))]
        if rnd.random() < 0.1:
            liste.append({"is_thunk": True})   # adı olmayan kayıt
        for macho, platform_ in ((True, ko.PLATFORM_MAC), (False, ko.PLATFORM_DEBIAN)):
            sonuc = B.is_cpp_binary(liste, macho=macho)
            assert sonuc is ko.cpp_ikili_mi(liste, platform_)
            gorulen.add((macho, sonuc))
    assert len(gorulen) == 4


def test_macho_bicimi():
    assert B.is_macho(MACHO) and B.is_macho("mach-o (fat)")
    assert not B.is_macho(ELF) and not B.is_macho("")


# --------------------------------------------------------------------------------------------
# (e) anahtar ve bağlama


@pytest.mark.parametrize("ad, anahtar", [
    ("FUN_00101234", "FUN_00101234"), ("FUN_1000a3f0c", "FUN_1000a3f0c"), ("FUN_ABCDEF", "FUN_ABCDEF"),
    ("entry", ""), ("thunk_FUN_00101234", ""), ("_INIT_1", ""), ("_FINI_0", ""), ("LAB_00101234", ""),
    ("SUB_00101234", ""), ("sub_00101234", ""), ("FUN_", ""), ("FUN_xyz", ""), ("FUN_0010 ", ""),
    ("fun_00101234", ""), ("Meter_init", ""), ("", ""), (None, ""),
])
def test_anahtar_yalniz_fun(ad, anahtar):
    assert B.pre_name_key(ad) == anahtar


def test_anahtar_bicimi_c_namer_ile_ayni():
    """Anahtar, c_namer'ın Ghidra yer tutucusu saydığı adla aynı biçimde olmalı."""
    import karadul.reconstruction.c_namer as cn
    assert B.FUN_KEY_RE.pattern == cn._GHIDRA_AUTO_FUNC.pattern


def _capa(adres: int, ad: str, turler=("func_kalibi",), rol: str = K.ROLE_OWN) -> K.Anchor:
    kanit = tuple(K.Evidence(t, 0x5000 + i, adres, adres + 8, "FUN_gunluk", rol)
                  for i, t in enumerate(turler))
    return K.Anchor(f"{adres:x}", ad, tuple(turler), rol, kanit)


def _sonuc(*capalar: K.Anchor, ghidra: dict[int, str] | None = None):
    """Elle kurulmuş çıkarım sonucu ve fonksiyon tablosu (ad: öntanımlı ``FUN_<adres>``)."""
    ghidra = ghidra or {}
    fonk = {}
    for c in capalar:
        a = int(c.address, 16)
        fonk[a] = K.Function(a, ghidra.get(a, f"FUN_{a:08x}"), False, False, "DEFAULT", 16)
    r = K.Ks1Result("prog", K.ABI_AAPCS, K.ALL_TYPES, {c.address: c for c in capalar}, {}, [])
    return r, fonk


def _bagla(*capalar: K.Anchor, ghidra=None, cpp: bool = False, tablo=None) -> B.Binding:
    r, fonk = _sonuc(*capalar, ghidra=ghidra)
    return B.bind(r, fonk, cpp=cpp, row_status=TABLO if tablo is None else tablo)


def test_baglama_fun_disi_anahtar_atlanir():
    b = _bagla(_capa(0x1000, "oturum_ac"), _capa(0x2000, "giris_yap"), _capa(0x3000, "kur_bunu"),
               ghidra={0x2000: "entry", 0x3000: "_INIT_1"})
    assert [(a.address, a.key, a.skip) for a in b.anchors] == [
        ("1000", "FUN_00001000", None), ("2000", "", "anahtar_fun_degil"),
        ("3000", "", "anahtar_fun_degil")]
    assert b.skipped() == {"anahtar_fun_degil": 2}
    assert [a.name for a in b.named()] == ["oturum_ac"]
    # atlanan çapanın etiketi yine kayıtta (bedel sonradan sayılabilsin)
    assert b.anchors[1].label == "kesin" and b.anchors[1].function_name == "entry"


def test_baglama_anahtar_adresten_kurulmaz():
    # fonksiyon tablosunda olmayan adres: anahtar uydurulmaz
    r, _ = _sonuc(_capa(0x1000, "oturum_ac"))
    b = B.bind(r, {}, cpp=False, row_status=TABLO)
    assert b.anchors[0].key == "" and b.anchors[0].skip == "anahtar_fun_degil" and b.named() == []


def test_baglama_parca_ad_almaz_kayda_gecer():
    b = _bagla(_capa(0x1000, "satir_sil", ("assert",), K.ROLE_LIFTED),
               _capa(0x8000, "satir_sil", ("assert",), K.ROLE_FRAGMENT),
               _capa(0x9000, "satir_sil", ("assert", "func_kalibi"), K.ROLE_FRAGMENT),
               tablo=HEPSI_KESIN)
    assert [(a.address, a.rows, a.label, a.skip) for a in b.anchors] == [
        ("1000", ("assert_ust",), "kesin", None),
        ("8000", (), None, "parca"), ("9000", (), None, "parca")]
    assert b.fragments() == [{"adres": "8000", "ust_ad": "satir_sil"},
                             {"adres": "9000", "ust_ad": "satir_sil"}]
    assert b.skipped() == {"parca": 2}
    assert [a.key for a in b.named()] == ["FUN_00001000"]
    belge = b.as_dict()
    assert [c["adres"] for c in belge["capalar"]] == ["1000"]
    assert belge["parcalar"] == b.fragments()


def test_baglama_export_ad_almaz_yalniz_sayilir():
    b = _bagla(_capa(0x1000, "oturum_ac"), _capa(0x4000, "Meter_init", ("export",)),
               _capa(0x4100, "Meter_done", ("export",)),
               ghidra={0x4000: "Meter_init", 0x4100: "Meter_done"}, tablo=HEPSI_KESIN)
    assert b.export_count == 2
    assert [a.address for a in b.anchors] == ["1000"]
    assert b.skipped() == {}
    assert b.as_dict()["export"] == 2


def test_baglama_susan_satir_ad_vermez():
    b = _bagla(_capa(0x1000, "denetle", ("assert",)), _capa(0x2000, "oturum_ac"),
               _capa(0x3000, "bul_bunu", ("func_aktarma",)))
    assert [(a.rows, a.label, a.skip) for a in b.anchors] == [
        (("assert",), None, "satir_sus"), (("func_kalibi",), "kesin", None),
        (("func_aktarma",), "doğrulanmadı", None)]
    # hepsi susan tabloyla hiçbir çapa ad vermez
    sus = {x: "sus" for x in B.DECISION_ROWS}
    r, fonk = _sonuc(_capa(0x1000, "denetle", ("assert",)), _capa(0x2000, "oturum_ac"))
    b0 = B.bind(r, fonk, cpp=False, row_status=sus)
    assert b0.named() == [] and b0.skipped() == {"satir_sus": 2}
    assert b0.row_status == sus
    # öntanımlı tablo ürün tablosudur: yalnız assert'e dayanan çapa susar
    b1 = B.bind(r, fonk, cpp=False)
    assert [(a.rows, a.label, a.skip) for a in b1.anchors] == [
        (("assert",), None, "satir_sus"), (("func_kalibi",), "kesin", None)]
    assert b1.row_status == TABLO


def test_baglama_cok_turlu_capa_en_iyi_satirla():
    b = _bagla(_capa(0x1000, "denetle_bunu", ("assert", "func_kalibi")),
               _capa(0x2000, "denetle_sunu", ("assert", "func_aktarma")))
    assert [(a.rows, a.label) for a in b.anchors] == [
        (("assert", "func_kalibi"), "kesin"), (("assert", "func_aktarma"), "doğrulanmadı")]


def test_baglama_cpp_ikilide_kesin_yok():
    b = _bagla(_capa(0x1000, "oturum_ac"), _capa(0x2000, "denetle", ("assert",)), cpp=True)
    assert [(a.label, a.skip) for a in b.anchors] == [("doğrulanmadı", None), (None, "satir_sus")]
    assert b.cpp is True and b.as_dict()["cpp"] is True


def test_baglama_ad_oldugu_gibi_ve_tanimlayici():
    # c_namer'ın temizlemesinin değiştireceği adlar (büyük harf, baştaki alt çizgi, çift alt çizgi)
    b = _bagla(_capa(0x1000, "Vector_add"), _capa(0x2000, "_grid_check"), _capa(0x3000, "foo__bar"),
               _capa(0x4000, "a-b"), _capa(0x5000, "x"), tablo=HEPSI_KESIN)
    assert [(a.name, a.skip) for a in b.anchors] == [
        ("Vector_add", None), ("_grid_check", None), ("foo__bar", None),
        ("a-b", "ad_bicimi"), ("x", "ad_bicimi")]
    for a in b.named():
        m = a.meta()
        assert m["name"] == a.name and m["exact"] is True and B.is_exact(m)


def test_baglama_kunye_bicimi():
    c = _capa(0x1000, "oturum_ac", ("assert", "func_kalibi"))
    b = _bagla(c)
    m = b.anchors[0].meta()
    assert m == {"kind": "ks1", "name": "oturum_ac", "exact": True, "label": "kesin",
                 "ks1": {"adres": "1000", "turler": ["assert", "func_kalibi"], "rol": "kendi",
                         "satirlar": ["assert", "func_kalibi"],
                         "kanitlar": [e.as_dict() for e in c.evidence]}}
    json.dumps(m)   # JSON'a yazılabilir (köken kaydına girer)


def test_baglama_gecersiz_satir_tablosu():
    r, fonk = _sonuc(_capa(0x1000, "oturum_ac"))
    for tablo in ({"export": "kesin"}, {"func_kalibi": "evet"}, {"func_kalibi": "doğrulanmadı"}):
        with pytest.raises(ValueError):
            B.bind(r, fonk, cpp=False, row_status=tablo)
        with pytest.raises(ValueError):
            B.bind_static(None, row_status=tablo)


# --------------------------------------------------------------------------------------------
# Sentetik static/ üzerinde uçtan uca


F_FUNC, F_ASSERT, F_AKTARAN, F_CAGIRAN, F_UST, F_PARCA = (
    0x100001000, 0x100001100, 0x100002000, 0x100001200, 0x100001300, 0x100008000)
F_GIRIS, F_IKI_TUR, F_EXPORT = 0x100001400, 0x100001500, 0x100004000


def karma(bicim: str = ELF) -> Ikili:
    """Her karar satırından bir çapa, bir parça, anahtarı ``entry`` olan bir çapa ve bir export."""
    ik = temel(bicim)
    gunluk = aapcs_log if bicim == ELF else darwin_log
    fmt = ik.dizgi(DZ, "%s: x=%d")
    dosya, ifade = ik.dizgi(DZ + 0x20, "izgara.c"), ik.dizgi(DZ + 0x40, "p != 0")

    def assert_cagrisi(ad: int) -> list[str]:
        if bicim == ELF:   # __assert_fail(ifade, dosya, satır, fonksiyon)
            return adr(0, ifade) + adr(1, dosya) + ["mov w2,#0x10"] + adr(3, ad) + [bl(ASSERT_FAIL)]
        return adr(0, ad) + adr(1, dosya) + ["mov w2,#0x10"] + adr(3, ifade) + [bl(ASSERT_RTN)]

    ik.fonksiyon(F_FUNC, gunluk(fmt, ik.dizgi(DZ + 0x100, "Vector_add")) + ["ret"])
    ik.fonksiyon(F_ASSERT, assert_cagrisi(ik.dizgi(DZ + 0x120, "kume_sil")) + ["ret"])
    if bicim == ELF:   # aktarıcı: parametre 0 → x1 (biçimden sonraki ilk argüman)
        ik.fonksiyon(F_AKTARAN, ["mov x1,x0"] + adr(0, fmt) + [bl(LOG), "ret"])
    else:              # Darwin: parametre 0 → [sp]
        ik.fonksiyon(F_AKTARAN, ["mov x19,x0", "str x19,[sp]"] + adr(0, fmt) + [bl(LOG), "ret"])
    ik.fonksiyon(F_CAGIRAN, adr(0, ik.dizgi(DZ + 0x140, "bul_oturum")) + [bl(F_AKTARAN), "ret"])
    ik.fonksiyon(F_PARCA, assert_cagrisi(ik.dizgi(DZ + 0x160, "satir_sil")))   # dönmez: parça
    ik.fonksiyon(F_UST, [f"cbz x0,0x{F_UST + 8:x}", bl(F_PARCA), "ret"])
    ik.fonksiyon(F_GIRIS, gunluk(fmt, ik.dizgi(DZ + 0x180, "giris_yap")) + ["ret"], ad="entry")
    iki = ik.dizgi(DZ + 0x1A0, "denetle_bunu")
    ik.fonksiyon(F_IKI_TUR, assert_cagrisi(iki) + gunluk(fmt, iki) + ["ret"])
    ik.fonksiyon(F_EXPORT, ["ret"], ad="Meter_init", kaynak="IMPORTED")
    return ik


def _fun(adres: int) -> str:
    return f"FUN_{adres:x}"


@pytest.mark.parametrize("bicim", [ELF, MACHO])
def test_uctan_uca_karma_ikili(tmp_path, bicim):
    b = B.bind_static(karma(bicim).yaz(tmp_path), row_status=TABLO)
    assert b.status == "ok" and b.detail == "" and b.cpp is False and b.program == "prog"
    assert b.abi == (K.ABI_AAPCS if bicim == ELF else K.ABI_DARWIN)
    assert b.export_count == 1
    ozet = {int(a.address, 16): (a.key, a.name, a.rows, a.label, a.skip) for a in b.anchors}
    assert ozet == {
        F_FUNC: (_fun(F_FUNC), "Vector_add", ("func_kalibi",), "kesin", None),
        F_ASSERT: (_fun(F_ASSERT), "kume_sil", ("assert",), None, "satir_sus"),
        F_CAGIRAN: (_fun(F_CAGIRAN), "bul_oturum", ("func_aktarma",), "doğrulanmadı", None),
        F_UST: (_fun(F_UST), "satir_sil", ("assert_ust",), "doğrulanmadı", None),
        F_PARCA: (_fun(F_PARCA), "satir_sil", (), None, "parca"),
        F_GIRIS: ("", "giris_yap", ("func_kalibi",), "kesin", "anahtar_fun_degil"),
        F_IKI_TUR: (_fun(F_IKI_TUR), "denetle_bunu", ("assert", "func_kalibi"), "kesin", None),
    }
    assert [int(a.address, 16) for a in b.anchors] == sorted(ozet)
    assert b.skipped() == {"anahtar_fun_degil": 1, "parca": 1, "satir_sus": 1}
    assert b.fragments() == [{"adres": f"{F_PARCA:x}", "ust_ad": "satir_sil"}]
    # kanıtlar çıkarıcının dökümüyle aynı
    r = K.extract_anchors(tmp_path / "static")
    for a in b.anchors:
        assert list(a.evidence) == [e.as_dict() for e in r.anchors[a.address].evidence]
    # ad veren çapaların adları tekildir (aynı ad iki anahtara gitmez)
    adlar = [a.name for a in b.named()]
    assert len(adlar) == len(set(adlar)) == 4

    adlar_, kunye, stats = {}, {}, {}
    o = B.apply_binding(adlar_, b, kunye, stats)
    assert adlar_ == {_fun(F_FUNC): "Vector_add", _fun(F_CAGIRAN): "bul_oturum",
                      _fun(F_UST): "satir_sil", _fun(F_IKI_TUR): "denetle_bunu"}
    assert {k: (v["kind"], v["label"], v["exact"]) for k, v in kunye.items()} == {
        _fun(F_FUNC): ("ks1", "kesin", True), _fun(F_CAGIRAN): ("ks1", "doğrulanmadı", True),
        _fun(F_UST): ("ks1", "doğrulanmadı", True), _fun(F_IKI_TUR): ("ks1", "kesin", True)}
    assert o == {"written": 4, "named": 4, "kesin": 2, "overrode": {},
                 "skipped": {"anahtar_fun_degil": 1, "parca": 1, "satir_sus": 1}}
    assert stats == {"ks1_status": "ok", "ks1_anchors": 7, "ks1_export": 1, "ks1_named": 4,
                     "ks1_kesin": 2, "ks1_overrode": {},
                     "ks1_skipped": {"anahtar_fun_degil": 1, "parca": 1, "satir_sus": 1}}


def test_uctan_uca_hepsi_susan_tabloyla_ad_yok(tmp_path):
    """Hepsi susan tablo: çapalar kayda geçer, hiçbiri ad vermez."""
    sus = {r: B.STATUS_SILENT for r in B.DECISION_ROWS}
    b = B.bind_static(karma().yaz(tmp_path), row_status=sus)
    assert b.status == "ok" and len(b.anchors) == 7 and b.named() == []
    assert all(a.label is None for a in b.anchors)
    adlar, kunye = {"FUN_1": "eski"}, {}
    assert B.apply_binding(adlar, b, kunye)["written"] == 0
    assert adlar == {"FUN_1": "eski"} and kunye == {}


def test_uctan_uca_ontanimli_tablo_urun_tablosudur(tmp_path):
    """Öntanımlı çağrı ("aç"tan beri) ölçümden türeyen tabloyla bağlar."""
    dizin = karma().yaz(tmp_path)
    b, bt = B.bind_static(dizin), B.bind_static(dizin, row_status=TABLO)
    assert [a.as_dict() for a in b.anchors] == [a.as_dict() for a in bt.anchors]
    assert len(b.anchors) == 7 and len(b.named()) == 4
    assert sorted(a.label for a in b.named()) == ["doğrulanmadı", "doğrulanmadı", "kesin", "kesin"]
    assert b.skipped() == {"anahtar_fun_degil": 1, "parca": 1, "satir_sus": 1}


@pytest.mark.parametrize("bicim, thunk, cpp", [
    (ELF, "__gxx_personality_v0", True), (ELF, "_Znwm", True), (ELF, "malloc", False),
    (MACHO, "__Znwm", True), (MACHO, "___cxa_throw", True), (MACHO, "_ZSTD_compress", False),
])
def test_uctan_uca_cpp_ikili(tmp_path, bicim, thunk, cpp):
    ik = karma(bicim)
    ik.fonksiyon(0x100090100, ["b 0x200000100"], ad=thunk, thunk=True, kaynak="IMPORTED")
    b = B.bind_static(ik.yaz(tmp_path), row_status=TABLO)
    assert b.status == "ok" and b.cpp is cpp
    etiketler = {a.label for a in b.named()}
    assert len(b.named()) == 4   # C++ ad vermeyi kapatmaz
    assert etiketler == ({"doğrulanmadı"} if cpp else {"kesin", "doğrulanmadı"})
    stats: dict = {}
    B.apply_binding({}, b, {}, stats)
    assert stats["ks1_named"] == 4 and stats["ks1_kesin"] == (0 if cpp else 2)


# --------------------------------------------------------------------------------------------
# (f) ön ad sözlüğüne yazma


def test_yazma_faz1_adi_ezilir_ve_sayilir():
    b = _bagla(_capa(0x1000, "oturum_ac"), _capa(0x2000, "bul_bunu", ("func_aktarma",)),
               _capa(0x3000, "kur_bunu"))
    adlar = {"FUN_00001000": "eski_ad", "FUN_00002000": "bul_bunu", "FUN_00009000": "baska"}
    kunye, stats = {}, {}
    o = B.apply_binding(adlar, b, kunye, stats)
    assert adlar == {"FUN_00001000": "oturum_ac", "FUN_00002000": "bul_bunu",
                     "FUN_00003000": "kur_bunu", "FUN_00009000": "baska"}
    # yalnız adı değişen anahtar "ezildi" sayılır; aynı adı taşıyan anahtarın künyesi KS-1 olur
    assert o["overrode"] == {"faz1": 1} and stats["ks1_overrode"] == {"faz1": 1}
    assert o["written"] == 3 and o["named"] == 3
    assert sorted(kunye) == ["FUN_00001000", "FUN_00002000", "FUN_00003000"]
    assert all(v["kind"] == "ks1" for v in kunye.values())


def test_yazma_gnulib_adi_ezilir_turuyle_sayilir():
    b = _bagla(_capa(0x1000, "oturum_ac"))
    adlar = {"FUN_00001000": "xalloc_die"}
    kunye = {"FUN_00001000": B.make_meta(B.KIND_GNULIB, "xalloc_die")}
    assert B.apply_binding(adlar, b, kunye)["overrode"] == {"gnulib": 1}
    assert adlar == {"FUN_00001000": "oturum_ac"} and kunye["FUN_00001000"]["kind"] == "ks1"


def test_yazma_main_korunur():
    b = _bagla(_capa(0x1000, "oturum_ac"), _capa(0x2000, "kur_bunu"))
    # künyesiz de olsa adı ``main`` olan anahtara yazılmaz
    adlar, kunye, stats = {"FUN_00001000": "main"}, {}, {}
    o = B.apply_binding(adlar, b, kunye, stats)
    assert adlar == {"FUN_00001000": "main", "FUN_00002000": "kur_bunu"}
    assert "FUN_00001000" not in kunye
    assert o["skipped"] == {"korunan_anahtar": 1} and o["overrode"] == {}
    assert stats["ks1_named"] == 1 and stats["ks1_anchors"] == 2


def test_yazma_main_girisi_kunyesi_korunur():
    # tür künyeden okunur: ``main`` girişi künyeli anahtar, adı ne olursa olsun korunur
    b = _bagla(_capa(0x1000, "oturum_ac"))
    adlar = {"FUN_00001000": "ana_giris"}
    kunye = {"FUN_00001000": B.make_meta(B.KIND_MAIN, "ana_giris")}
    once = copy.deepcopy(kunye)
    o = B.apply_binding(adlar, b, kunye)
    assert adlar == {"FUN_00001000": "ana_giris"} and kunye == once
    assert o["skipped"] == {"korunan_anahtar": 1} and o["written"] == 0


def test_yazma_elle_ad_korunur():
    b = _bagla(_capa(0x1000, "oturum_ac"))
    adlar = {"FUN_00001000": "Process_new"}
    kunye = {"FUN_00001000": B.make_meta(B.KIND_MANUAL, "Process_new")}
    once = copy.deepcopy(kunye)
    o = B.apply_binding(adlar, b, kunye)
    assert adlar == {"FUN_00001000": "Process_new"} and kunye == once
    assert o["skipped"] == {"korunan_anahtar": 1} and o["named"] == 0


def test_yazma_main_adi_ikinci_anahtara_verilmez():
    b = _bagla(_capa(0x1000, "main", ("func_kalibi",)), _capa(0x2000, "kur_bunu"), tablo=HEPSI_KESIN)
    adlar, kunye = {"FUN_00007000": "main"}, {}
    o = B.apply_binding(adlar, b, kunye)
    assert adlar == {"FUN_00007000": "main", "FUN_00002000": "kur_bunu"}
    assert o["skipped"] == {"ad_main_dolu": 1} and "FUN_00001000" not in kunye
    # ``main`` başka hiçbir anahtarda değilse çapa adını verir
    adlar, kunye = {"FUN_00007000": "baska"}, {}
    B.apply_binding(adlar, b, kunye)
    assert adlar["FUN_00001000"] == "main" and kunye["FUN_00001000"]["kind"] == "ks1"


def test_yazma_ikinci_cagri_degisiklik_yapmaz():
    b = _bagla(_capa(0x1000, "oturum_ac"), _capa(0x2000, "bul_bunu", ("func_aktarma",)),
               _capa(0x3000, "denetle", ("assert",)), _capa(0x4000, "giris_yap"),
               ghidra={0x4000: "entry"})
    adlar = {"FUN_00001000": "eski_ad", "FUN_00009000": "main"}
    kunye, stats = {"FUN_00009000": B.make_meta(B.KIND_MAIN, "main")}, {}
    ilk = B.apply_binding(adlar, b, kunye, stats)
    assert ilk["written"] == 2 and ilk["overrode"] == {"faz1": 1}
    anlik = copy.deepcopy((adlar, kunye, stats))
    ikinci = B.apply_binding(adlar, b, kunye, stats)
    assert (adlar, kunye, stats) == anlik
    assert ikinci["written"] == 0 and ikinci["overrode"] == {}
    assert ikinci["named"] == ilk["named"] == 2 and ikinci["skipped"] == ilk["skipped"]
    assert stats["ks1_overrode"] == {"faz1": 1}   # birikir, ikinci çağrıda şişmez


def test_yazma_elle_ad_sonradan_ezerse_ikinci_cagri_dokunmaz():
    """Tohum sırası: main → KS-1 → gnulib → önyük → elle; sonra aynı sıra bir kez daha."""
    b = _bagla(_capa(0x1000, "oturum_ac"), _capa(0x2000, "kur_bunu"))
    adlar, kunye, stats = {}, {}, {}
    B.apply_binding(adlar, b, kunye, stats)
    once = dict(adlar)
    adlar["FUN_00001000"] = "Analist_Adi"                       # elle ad KS-1'i ezer
    assert B.mark_changed(kunye, once, adlar, B.KIND_MANUAL) == ["FUN_00001000"]
    anlik = copy.deepcopy((adlar, kunye))
    o = B.apply_binding(adlar, b, kunye, stats)
    assert (adlar, kunye) == anlik
    assert o["written"] == 0 and o["named"] == 1 and o["skipped"] == {"korunan_anahtar": 1}
    assert stats["ks1_named"] == 1 and stats["ks1_skipped"] == {"korunan_anahtar": 1}


def test_yazma_kunye_adi_uyusmayan_anahtar_faz1_sayilir():
    # elle künyeli ad sonradan başka bir kaynakça ezilmiş: künye geçersiz, anahtar korunmaz
    b = _bagla(_capa(0x1000, "oturum_ac"))
    adlar = {"FUN_00001000": "bindiff_adi"}
    kunye = {"FUN_00001000": B.make_meta(B.KIND_MANUAL, "Analist_Adi")}
    o = B.apply_binding(adlar, b, kunye)
    assert adlar == {"FUN_00001000": "oturum_ac"} and o["overrode"] == {"faz1": 1}


@pytest.mark.parametrize("tablo", [TABLO, HEPSI_KESIN, None])
def test_yazma_sayac_degismezi(tmp_path, tablo):
    b = B.bind_static(karma().yaz(tmp_path), **({} if tablo is None else {"row_status": tablo}))
    adlar = {_fun(F_FUNC): "main", _fun(F_UST): "eski"}
    kunye, stats = {}, {}
    for _ in range(2):
        B.apply_binding(adlar, b, kunye, stats)
        assert stats["ks1_anchors"] == stats["ks1_named"] + sum(stats["ks1_skipped"].values())
        assert stats["ks1_anchors"] == len(b.anchors) == 7
        assert stats["ks1_kesin"] <= stats["ks1_named"]
        assert set(stats["ks1_skipped"]) <= set(B.SKIP_REASONS)


def test_yazma_yapit_yoksa_dokunmaz():
    adlar, kunye, stats = {"FUN_1": "eski"}, {}, {"main_recovered": "FUN_2"}
    o = B.apply_binding(adlar, None, kunye, stats)
    assert adlar == {"FUN_1": "eski"} and kunye == {} and stats == {"main_recovered": "FUN_2"}
    assert o == {"written": 0, "named": 0, "kesin": 0, "skipped": {}, "overrode": {}}
    # kapalı bayrak: yalnız durum yazılır
    B.apply_binding(adlar, B.disabled(), kunye, stats)
    assert adlar == {"FUN_1": "eski"} and kunye == {}
    assert stats["ks1_status"] == "kapali" and stats["ks1_named"] == 0 and stats["ks1_anchors"] == 0


# --------------------------------------------------------------------------------------------
# (g) durum kodları


def test_durum_kapali():
    b = B.disabled()
    assert b.status == "kapali" and b.anchors == [] and b.as_dict()["durum"] == "kapali"
    assert B.RUN_STATUSES == ("ok", "kapali", "girdi_eksik", "desteklenmeyen_platform", "hata")


def test_durum_girdi_eksik_dizin(tmp_path):
    for yol in (None, tmp_path / "yok", tmp_path / "dosya.txt"):
        if yol is not None and yol.suffix:
            yol.write_text("x")
        b = B.bind_static(yol, row_status=TABLO)
        assert b.status == "girdi_eksik" and b.anchors == [] and b.detail == "static dizini yok"
        assert b.row_status == TABLO   # kullanılan tablo, ad çıkmasa da kayıtta


@pytest.mark.parametrize("dosya", B.REQUIRED_FILES)
def test_durum_girdi_eksik_dosya(tmp_path, dosya):
    st = karma().yaz(tmp_path)
    (st / dosya).unlink()
    b = B.bind_static(st, row_status=TABLO)
    assert b.status == "girdi_eksik" and dosya in b.detail and b.named() == []


def test_durum_girdi_eksik_disassembly_yok(tmp_path):
    st = karma().yaz(tmp_path)
    for c in (st / "ghidra_output" / "decompiled").glob("*.c"):
        c.unlink()
    b = B.bind_static(st, row_status=TABLO)
    assert b.status == "girdi_eksik" and b.detail == "gömülü disassembly yok" and b.anchors == []


def test_durum_desteklenmeyen_platform(tmp_path):
    ik = karma()
    ik.islemci = "x86"
    b = B.bind_static(ik.yaz(tmp_path), row_status=TABLO)
    assert b.status == "desteklenmeyen_platform" and b.abi is None
    assert b.anchors == [] and b.export_count == 1   # dizgi türleri çıkmaz; export yine sayılır
    assert "x86" in b.detail
    stats: dict = {}
    B.apply_binding({}, b, {}, stats)
    assert stats["ks1_status"] == "desteklenmeyen_platform" and stats["ks1_named"] == 0


@pytest.mark.parametrize("dosya", ["ghidra_functions.json", "ghidra_strings.json", "ghidra_xrefs.json"])
def test_durum_hata_bozuk_girdi(tmp_path, dosya):
    st = karma().yaz(tmp_path)
    (st / dosya).write_text("{bozuk")
    b = B.bind_static(st, row_status=TABLO)   # hata fırlatmaz
    assert b.status == "hata" and b.detail.startswith("JSONDecodeError") and b.anchors == []


def test_durum_hata_cikarim_patlarsa(tmp_path, monkeypatch):
    st = karma().yaz(tmp_path)

    def patla(*a, **k):
        raise RuntimeError("çıkarım bozuk")
    monkeypatch.setattr(K, "extract", patla)
    b = B.bind_static(st, row_status=TABLO)
    assert b.status == "hata" and b.detail == "RuntimeError: çıkarım bozuk"
    assert b.row_status == TABLO and B.disabled().row_status == dict(B.ROW_STATUS)


def test_cikarim_turleri_daraltilmaz(tmp_path, monkeypatch):
    """Bağlama çıkarıcıyı öntanımlı türlerle çağırır (ölçümle aynı çapa kümesi)."""
    cagrilar = []
    asil = K.extract

    def izle(inp, **kw):
        cagrilar.append(kw)
        return asil(inp, **kw)
    monkeypatch.setattr(K, "extract", izle)
    B.bind_static(karma().yaz(tmp_path), row_status=TABLO)
    assert cagrilar == [{}]


# --------------------------------------------------------------------------------------------
# (h) künye yardımcıları


def test_tur_sabitleri_ve_oncelik():
    assert B.KIND_PRIORITY == ("elle", "main_giris", "ks1", "faz1", "gnulib", "elf_onyuk")
    assert B.PRE_NAME_ORDER == ("elle", "main_giris", "ks1")
    assert B.EXACT_KINDS == {"ks1", "elle"} and B.PROTECTED_KINDS == {"elle", "main_giris"}
    # KS-1'den yüksek öncelikli türler korunur, düşükler ezilir
    sira = B.KIND_PRIORITY.index
    assert {k for k in B.KIND_PRIORITY if sira(k) < sira("ks1")} == set(B.PROTECTED_KINDS)


def test_kunye_kur():
    assert B.make_meta("elle", "Process_new") == {"kind": "elle", "name": "Process_new", "exact": True}
    assert B.make_meta("gnulib", "xalloc_die") == {"kind": "gnulib", "name": "xalloc_die",
                                                   "exact": False}
    for tur in ("main_giris", "faz1", "elf_onyuk"):
        assert B.make_meta(tur, "x")["exact"] is False
    with pytest.raises(ValueError):
        B.make_meta("tarif", "x")


def test_tur_isaretleme_yalniz_degisen_anahtarlar():
    once = {"FUN_1": "a", "FUN_2": "b", "FUN_3": "c"}
    sonra = {"FUN_1": "a", "FUN_2": "main", "FUN_3": "c", "FUN_4": "yeni"}
    kunye = {"FUN_1": B.make_meta("faz1", "a"), "FUN_2": {"kind": "ks1", "name": "b", "exact": True,
                                                         "label": "kesin", "ks1": {}}}
    assert B.mark_changed(kunye, once, sonra, B.KIND_MAIN) == ["FUN_2", "FUN_4"]
    assert kunye == {"FUN_1": {"kind": "faz1", "name": "a", "exact": False},
                     "FUN_2": {"kind": "main_giris", "name": "main", "exact": False},
                     "FUN_4": {"kind": "main_giris", "name": "yeni", "exact": False}}
    # değişiklik yoksa hiçbir şey yazılmaz
    assert B.mark_changed(kunye, sonra, sonra, B.KIND_GNULIB) == []


def test_kunye_ad_uyusmazliginda_yok_sayilir():
    ks1 = {"kind": "ks1", "name": "oturum_ac", "exact": True, "label": "kesin", "ks1": {}}
    kunye = {"FUN_1": ks1, "FUN_2": {"kind": "tarif", "name": "x"}, "FUN_3": "bozuk"}
    assert B.meta_for(kunye, "FUN_1", "oturum_ac") is ks1
    assert B.meta_for(kunye, "FUN_1", "bindiff_adi") is None   # ad sonradan ezilmiş
    assert B.meta_for(kunye, "FUN_2", "x") is None             # bilinmeyen tür
    assert B.meta_for(kunye, "FUN_3", "bozuk") is None
    assert B.meta_for(kunye, "FUN_9", "x") is None and B.meta_for(None, "FUN_1", "oturum_ac") is None


def test_on_ad_etiketi():
    assert B.entry_label({"kind": "ks1", "label": "kesin"}) == "kesin"
    assert B.entry_label({"kind": "ks1", "label": "doğrulanmadı"}) == "doğrulanmadı"
    assert B.entry_label({"kind": "ks1"}) == "doğrulanmadı"
    assert B.entry_label({"kind": "ks1", "label": "doğrulandı"}) == "doğrulanmadı"
    assert B.entry_label({"kind": "elle", "label": "kesin"}) is None      # elle ad etiket taşımaz
    assert B.entry_label(None) == "doğrulanmadı"                          # künyesiz ön ad
    # KS-1 dışı tür künyesinde ne yazarsa yazsın "kesin" alamaz
    for tur in ("main_giris", "gnulib", "elf_onyuk", "faz1", "tarif", None):
        assert B.entry_label({"kind": tur, "label": "kesin"}) == "doğrulanmadı"


def test_on_ad_yazimi():
    assert B.is_exact({"kind": "ks1", "exact": True}) and B.is_exact({"kind": "elle", "exact": True})
    assert not B.is_exact({"kind": "ks1", "exact": False}) and not B.is_exact({"kind": "ks1"})
    assert not B.is_exact({"kind": "gnulib", "exact": True}) and not B.is_exact(None)
    assert not B.is_exact({"kind": "ks1", "exact": 1})


def test_on_ad_isleme_sirasi():
    adlar = {"FUN_a": "faz_bir", "FUN_b": "ortak", "FUN_c": "ks_bir", "FUN_d": "main",
             "FUN_e": "Elle_Ad", "FUN_f": "ortak", "FUN_g": "gnu_bir", "FUN_h": "ks_iki"}
    kunye = {"FUN_c": {"kind": "ks1", "name": "ks_bir"}, "FUN_h": {"kind": "ks1", "name": "ks_iki"},
             "FUN_d": B.make_meta("main_giris", "main"), "FUN_e": B.make_meta("elle", "Elle_Ad"),
             "FUN_f": {"kind": "ks1", "name": "ortak"}, "FUN_g": B.make_meta("gnulib", "gnu_bir"),
             "FUN_a": {"kind": "ks1", "name": "eski_ad"}}   # adı uyuşmayan künye: sıra almaz
    assert [k for k, _ in B.ordered_pre_names(adlar, kunye)] == [
        "FUN_e", "FUN_d", "FUN_c", "FUN_f", "FUN_h", "FUN_a", "FUN_b", "FUN_g"]
    # aynı ad iki anahtarda: KS-1 künyeli olan (FUN_f) künyesizden (FUN_b) önce gelir
    assert B.ordered_pre_names(adlar, kunye)[3] == ("FUN_f", "ortak")
    # künye yoksa özgün sıra
    assert B.ordered_pre_names(adlar, None) == list(adlar.items())
    assert B.ordered_pre_names(adlar, {}) == list(adlar.items())


# --------------------------------------------------------------------------------------------
# (i) yan çıktı ve belirlenimcilik


def test_yan_cikti_bicimi(tmp_path):
    b = B.bind_static(karma().yaz(tmp_path), row_status=TABLO)
    belge = json.loads(json.dumps(b.as_dict(), ensure_ascii=False))
    assert set(belge) == {"sema", "surum", "ks1_surumu", "durum", "ayrinti", "program", "abi", "cpp",
                          "satir_durumu", "capalar", "parcalar", "export", "ad_veren", "atlanan",
                          "sayaclar"}
    assert belge["sema"] == "karadul.ks1_baglama" and belge["surum"] == 1
    assert belge["ks1_surumu"] == K.KS1_VERSION and belge["durum"] == "ok"
    assert belge["satir_durumu"] == TABLO and belge["ad_veren"] == 4 and belge["export"] == 1
    assert belge["atlanan"] == {"anahtar_fun_degil": 1, "parca": 1, "satir_sus": 1}
    assert belge["sayaclar"]["9_capa:func_kalibi"] == 3 and belge["sayaclar"]["capa_parca"] == 1
    assert len(belge["capalar"]) == 6 and len(belge["parcalar"]) == 1
    giris = next(c for c in belge["capalar"] if c["ghidra_adi"] == "entry")
    assert giris == {"adres": f"{F_GIRIS:x}", "anahtar": None, "ghidra_adi": "entry",
                     "ad": "giris_yap", "turler": ["func_kalibi"], "rol": "kendi",
                     "satirlar": ["func_kalibi"], "etiket": "kesin", "atlama": "anahtar_fun_degil",
                     "kanitlar": giris["kanitlar"]}
    assert set(giris["kanitlar"][0]) == {"tur", "dizgi_adresi", "cagri_fonksiyonu", "cagri_yeri",
                                         "cagrilan", "rol"}


def test_girdi_sirasindan_bagimsiz(tmp_path):
    ik = karma()
    ilk = json.dumps(B.bind_static(ik.yaz(tmp_path / "a"), row_status=TABLO).as_dict(), sort_keys=True)
    for tohum in (1, 2, 3):
        b = B.bind_static(ik.yaz(tmp_path / f"k{tohum}", karistir=tohum), row_status=TABLO)
        assert json.dumps(b.as_dict(), sort_keys=True) == ilk
        adresler = [int(a.address, 16) for a in b.anchors]
        assert adresler == sorted(adresler)


def test_baglama_adrese_gore_sirali():
    b = _bagla(_capa(0x10000, "uc_bir"), _capa(0x9000, "iki_bir"), _capa(0x2000, "bir_bir"))
    assert [a.address for a in b.anchors] == ["2000", "9000", "10000"]   # sayısal, sözlük sırası değil
