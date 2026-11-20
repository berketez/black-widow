"""scripts/measurement/ad_bicimi.py — biçim düzeyi hükmünün testleri (ÖLÇÜ planı P-Ö1).

Kilitlenen davranışlar (PLAN.md §3 P-Ö1 "Sınama ve mutasyon"): deve yazımı ↔ küçük harf, ``_N``
çakışma eki, derleyici ekleri (``.part.0`` / ``.isra.0`` / ``.cold.1``, art arda), Mach-O baştaki
``_``, boş ad ve yalnız rakam (eşleşmez), bir harf farkı (eşleşmez), iki GT takma adı; derleyici eki
ifadesi ``ks1_olc``'den gelir (kopya yok); taşınan işlevler araştırma betiğiyle aynı sonucu verir.

Mutasyon koruması: ``scripts/measurement/mutation_specs_po1.json``.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_KOK = Path(__file__).resolve().parents[1]
_OLCUM = _KOK / "scripts" / "measurement"
if str(_OLCUM) not in sys.path:
    sys.path.insert(0, str(_OLCUM))

import ad_bicimi as ab  # noqa: E402
import ks1_olc  # noqa: E402


def _arastirma_olcu():
    """Başvuru uygulaması: ``scripts/arge/olcu/olcu.py`` (salt okunur; karşılaştırma için)."""
    yol = _KOK / "scripts" / "arge" / "olcu" / "olcu.py"
    spec = importlib.util.spec_from_file_location("arge_olcu_basvuru", yol)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_deve_yazimi_kucuk_harf_dogru():
    assert ab.harf_tam("FSE_buildDTable_internal", ["fse_builddtable_internal"])
    assert ab.harf_tam("fse_builddtable_internal", ["FSE_buildDTable_internal"])
    assert ab.harf_dizisi("FSE_buildDTable") == "fsebuilddtable"


def test_cakisma_eki_soyulur():
    assert ab.harf_tam("agac_gez_2", ["agac_gez"])
    assert ab.harf_tam("agac_gez", ["agac_gez_12"])
    assert ab.harf_dizisi("agac_gez_2") == "agacgez"
    # yalnız sondaki ``_<rakam>``: ortadaki rakam ve alt çizgisiz rakam korunur
    assert not ab.harf_tam("sha_256_hesapla", ["sha_hesapla"])
    assert not ab.harf_tam("sha256", ["sha"])


def test_derleyici_eki_soyulur():
    assert ab.harf_tam("satir_birak", ["satir_birak.part.0"])
    assert ab.harf_tam("dosya_ac", ["dosya_ac.isra.0"])
    assert ab.harf_tam("kume_sil", ["kume_sil.cold.1"])
    assert ab.harf_tam("kume_sil", ["kume_sil.constprop.0.isra.0"])     # art arda ekler
    assert ab.ek_soy("kume_sil.constprop.0.isra.0") == "kume_sil"
    assert ab.ek_soy("kume_sil") == "kume_sil"


def test_derleyici_eki_ifadesi_ks1_olcden():
    """Ek ifadesi kopyalanmaz: KS-1 ön kaydıyla sabit nesnenin kendisi."""
    assert ab.KLON_EKI_RE is ks1_olc.KLON_EKI_RE


def test_macho_bastaki_alt_cizgi():
    assert ab.harf_tam("_komut_bul", ["komut_bul"])
    assert ab.harf_tam("komut_bul", ["_komut_bul"])


def test_bos_ad_ve_yalniz_rakam_eslesmez():
    assert not ab.harf_tam("", [""])
    assert not ab.harf_tam("", ["kume_kur"])
    assert not ab.harf_tam("___", ["__"])                 # harf-rakam dışı: boş dizi
    assert not ab.harf_tam("_2", ["_3"])                  # yalnız çakışma eki: boş dizi
    assert ab.harf_dizisi("_2") == ""


def test_bir_harf_farki_yanlis():
    assert not ab.harf_tam("kume_kur", ["kume_kul"])
    assert not ab.harf_tam("kume_kurx", ["kume_kur"])


def test_iki_gt_takma_adi():
    assert ab.harf_tam("Takma_Iki", ["takma_bir", "takma_iki"])
    assert ab.harf_tam("takma_bir", ["takma_bir", "takma_iki"])
    assert not ab.harf_tam("takma_uc", ["takma_bir", "takma_iki"])
    assert not ab.harf_tam("kume_kur", [])                # GT adı yok


def test_tasima_arastirma_betigiyle_ayni():
    """Üç işlev ``olcu.py``'den aynen taşındı: aynı girdilerde aynı çıktı."""
    m = _arastirma_olcu()
    adlar = ["FSE_buildDTable_internal", "agac_gez_2", "satir_birak.part.0", "_komut_bul", "", "_2",
             "kume_sil.constprop.0.isra.0", "sha256", "HTTPServer_start", "x__y__", "a.cold"]
    for a in adlar:
        assert ab.ek_soy(a) == m.ek_soy(a), a
        assert ab.harf_dizisi(a) == m.harf_dizisi(a), a
        for g in adlar:
            assert ab.harf_tam(a, [g]) == m.harf_tam(a, [g]), (a, g)
