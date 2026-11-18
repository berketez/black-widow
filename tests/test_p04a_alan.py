"""P04a kalem 3 — alan sınıflandırıcı (MUH-04).

Gerçek örnek: redis-check-rdb ``ACLHashPassword`` (SHA-256, ``category:hash->crypto``,
conf 0,55). 1.22.1 çıktısında ikilinin BÜTÜN dizgilerindeki "element, stress, yield"
ve "delta, var, option" yüzünden ``structural`` seçilmişti (en yüksek skor finance
iken, "fark < 0.10" öncelik kuralıyla).
"""
from __future__ import annotations

from karadul.reconstruction.c_algorithm_id import AlgorithmMatch
from karadul.reconstruction.engineering.domain_classifier import DomainClassifier

# redis ikilisinin dizgilerinden (structural + finance ipuçları)
_IKILI_DIZGILERI = [
    "element", "stress", "yield", "delta", "var", "option", "sample", "filter",
    "weight", "0123456789abcdef",
]


def _algo(ad, kategori, fonk, guven):
    return AlgorithmMatch(name=ad, category=kategori, confidence=guven,
                          detection_method="constant", evidence=["e"],
                          function_name=fonk, address="0x0")


def _sinif(rapor, fonk):
    return next(c for c in rapor.classifications if c.function_name == fonk)


def test_aclhashpassword_crypto():
    """Düz ikili dizgi listesi (ürünün bugünkü çağrısı) fonksiyona kanıt sayılmaz."""
    rapor = DomainClassifier().classify(
        [_algo("SHA-256", "hash", "ACLHashPassword", 0.55)], strings=_IKILI_DIZGILERI)
    c = _sinif(rapor, "ACLHashPassword")
    assert c.primary_domain == "crypto"
    assert not any(e.startswith("string_hint") for e in c.evidence)


def test_duz_liste_skorlari_degistirmez():
    algos = [_algo("SHA-256", "hash", "f", 0.55), _algo("x", "fea_integration", "f", 0.3)]
    a = _sinif(DomainClassifier().classify(algos, strings=_IKILI_DIZGILERI), "f")
    b = _sinif(DomainClassifier().classify(algos, strings=None), "f")
    assert a.domain_scores == b.domain_scores
    assert a.primary_domain == b.primary_domain


def test_yalniz_dizgi_kanitli_alan_secilmez():
    """Fonksiyonun KENDİ dizgileri structural/finance dese bile tek güçlü kanıt crypto."""
    rapor = DomainClassifier().classify(
        [_algo("SHA-256", "hash", "ACLHashPassword", 0.55)],
        function_strings={"ACLHashPassword": _IKILI_DIZGILERI})
    c = _sinif(rapor, "ACLHashPassword")
    assert any(e.startswith("string_hint:structural") for e in c.evidence)
    assert c.domain_scores["structural"] > c.domain_scores["crypto"]
    assert c.primary_domain == "crypto"


def test_dizgi_yalniz_kendi_fonksiyonuna_gider():
    algos = [_algo("x", "fea_integration", "asm", 0.5), _algo("y", "fea_integration", "oth", 0.5)]
    rapor = DomainClassifier().classify(
        algos, function_strings={"asm": ["stiffness", "element"], "oth": []})
    assert any(e.startswith("string_hint") for e in _sinif(rapor, "asm").evidence)
    assert not any(e.startswith("string_hint") for e in _sinif(rapor, "oth").evidence)


def test_esitlik_yalniz_tam_esitlikte_oncelik():
    # tam eşit: structural (öncelik 9) crypto'nun (2) önünde
    esit = _sinif(DomainClassifier().classify(
        [_algo("a", "fea_integration", "f", 0.5), _algo("b", "hash", "f", 0.5)]), "f")
    assert esit.primary_domain == "structural"
    # yakın ama eşit değil (eski kural: fark < 0.10 → structural): yüksek skor kazanır
    yakin = _sinif(DomainClassifier().classify(
        [_algo("a", "fea_integration", "f", 0.45), _algo("b", "hash", "f", 0.5)]), "f")
    assert yakin.primary_domain == "crypto"


def test_gercek_fea_fonksiyonu_structural():
    rapor = DomainClassifier().classify(
        [_algo("gauss_quadrature", "fea_integration", "mafillsm", 0.8)],
        function_strings={"mafillsm": ["stiffness", "element"]})
    assert _sinif(rapor, "mafillsm").primary_domain == "structural"


def test_mapping_strings_geriye_uyum():
    """``strings`` fonksiyon → dizgi eşlemesi verilirse function_strings gibi davranır."""
    rapor = DomainClassifier().classify(
        [_algo("x", "fea_integration", "asm", 0.5)], strings={"asm": ["stiffness"]})
    assert any(e.startswith("string_hint") for e in _sinif(rapor, "asm").evidence)
