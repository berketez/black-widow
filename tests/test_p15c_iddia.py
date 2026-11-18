"""P15c / K-2: imza veritabanının dizgi / çağrı deseni kayıtları kimlik değil davranış tahminidir.

Geliştirme setinde (genel taramanın 14 ikilisi, 236 kayıt) ``string_ref`` / ``call_pattern``
adları tam adla 0 / 236 doğru; gevşek ölçütle 5 / 153 ve 19 / 83. Kilitlenen davranış:
- kayıt ``claim = davranis`` taşır, adı (``matched_name``) değişmez (kanal susturulmaz);
- ``confidence`` ölçülmüş gevşek kesinliğin Wilson alt sınırıdır, ham puan ``match_score``'da;
- kanıt satırları (eşleşen dizgi / çağrılan API'ler) kayıtta;
- simge eşleşmesi ``kimlik`` kalır ve güveni değişmez.
"""

from __future__ import annotations

import pytest

from karadul.analyzers.signature_db import (
    CLAIM_BEHAVIOR,
    CLAIM_IDENTITY,
    SignatureDB,
    SignatureMatch,
    behavior_confidence,
    claim_for_method,
    signature_source_label,
)
from karadul.computation.fusion.measured_precision import MEASURED_PRECISION
from karadul.reconstruction.tarif.baglama import wilson


def _clean_db() -> SignatureDB:
    db = SignatureDB()
    with db._lock:
        db._string_sigs = {}
        db._call_sigs = []
        db._byte_signatures = []
        db._symbol_db = {}
        db._lmdb_backend = None
        db._string_sigs_version += 1
    return db


def test_yontemden_iddia_turu() -> None:
    assert claim_for_method("string_ref") == CLAIM_BEHAVIOR
    assert claim_for_method("call_pattern") == CLAIM_BEHAVIOR
    assert claim_for_method("symbol") == CLAIM_IDENTITY
    assert claim_for_method("byte_pattern") == CLAIM_IDENTITY
    assert signature_source_label("call_pattern") == "signature_db:davranis"
    assert signature_source_label("symbol") == "signature_db:kimlik"
    # Dataclass yöntemden türetir; açıkça verilen değer korunur.
    assert SignatureMatch("a", "b", "", 0.5, "string_ref").claim == CLAIM_BEHAVIOR
    assert SignatureMatch("a", "b", "", 0.5, "symbol").claim == CLAIM_IDENTITY


def test_dizgi_kaydi_davranis_kanitli_olculmus_guven() -> None:
    db = _clean_db()
    db.add_string_signature(frozenset({"environment"}), "read_env_var", "config",
                            "environment variable reading")
    m = db._match_by_strings(["Could not read process environment.", "other"])
    assert m is not None
    assert m.matched_name == "read_env_var"          # ad değişmez (K-2)
    assert m.claim == CLAIM_BEHAVIOR
    assert m.match_score == pytest.approx(0.72)        # ham puan korunur
    assert m.confidence == pytest.approx(0.014)        # ölçülmüş alt sınır
    assert m.confidence == behavior_confidence("string_ref")
    assert m.evidence and any("Could not read process environment." in e for e in m.evidence)
    d = m.to_dict()
    assert d["claim"] == CLAIM_BEHAVIOR and d["match_score"] == pytest.approx(0.72)
    assert d["evidence"] == m.evidence


def test_cagri_kaydi_davranis_kanitli_olculmus_guven() -> None:
    db = _clean_db()
    db.add_call_pattern(frozenset({"pthread_cond_wait", "pthread_mutex_lock"}),
                        "wait_on_condition", "libpthread", "cond wait", confidence=0.85)
    m = db._match_by_calls(["pthread_mutex_lock", "pthread_cond_wait", "FUN_1234"])
    assert m is not None
    assert m.matched_name == "wait_on_condition"
    assert m.claim == CLAIM_BEHAVIOR
    assert m.confidence == pytest.approx(0.1517)
    assert m.match_score == pytest.approx(0.85 * (0.7 + 0.3 * 2 / 3))
    assert m.evidence[0] == "çağırır: pthread_cond_wait, pthread_mutex_lock"
    assert m.evidence[1] == "desen kapsaması: 2 / 3 farklı çağrı"


def test_lmdb_yedek_yolu_da_davranis() -> None:
    db = _clean_db()

    class _Fake:
        def lookup_string_sig(self, strings):
            return ("detect_x", "lib", "purpose")

        def lookup_call_sig(self, apis):
            return ("call_x", "lib", "purpose", 0.9)

    db._lmdb_backend = _Fake()
    s = db._match_by_strings(["a", "b"])
    c = db._match_by_calls(["f", "g"])
    assert s.claim == CLAIM_BEHAVIOR and s.confidence == pytest.approx(0.014)
    assert s.match_score == pytest.approx(min(0.92, 0.65 + 2 * 0.07))
    assert s.evidence and s.evidence[0].startswith("dizgi kümesi tam eşleşti")
    assert c.claim == CLAIM_BEHAVIOR and c.confidence == pytest.approx(0.1517)
    assert c.match_score == pytest.approx(0.9)
    assert c.evidence == ["çağrı kümesi tam eşleşti: f, g"]


def test_simge_kimlik_kalir_guveni_degismez() -> None:
    db = _clean_db()
    db.add_symbol("SSL_CTX_new", {"lib": "openssl", "purpose": "ctx"})
    m = db.match_function(func_name="SSL_CTX_new")
    assert m is not None and m.match_method == "symbol"
    assert m.claim == CLAIM_IDENTITY
    assert m.match_score is None
    assert m.confidence > 0.9


def test_iki_yontem_eslesince_secim_ham_puanla_ad_degismez() -> None:
    """Aynı adsız fonksiyonda dizgi ve çağrı deseni: seçim ham puanla (ad davranışı değişmez).

    Ölçülmüş kesinlikle (çağrı 0,152 > dizgi 0,014) seçmek geliştirme setinde gevşek doğruyu
    2 düşürdü; bu yüzden seçim ``match_score`` ile, güven ölçülmüş alt sınır.
    """
    db = _clean_db()
    db.add_string_signature(frozenset({"a", "b", "c"}), "STR", "l", "p")   # ham 0.86
    db.add_call_pattern(frozenset({"x"}), "CALL", "l", "p", confidence=0.5)  # ham 0.5
    m = db.match_function(func_name="FUN_1", strings_used=["a", "b", "c"], callees=["x"])
    assert m.matched_name == "STR"
    assert m.confidence == pytest.approx(0.014) and m.match_score == pytest.approx(0.86)


def test_olcum_tablosu_wilson_ile_tutarli_eski_kayit_duruyor() -> None:
    dav = MEASURED_PRECISION["davranis"]["kaynaklar"]
    for key, (k, n) in {"imza:call_pattern": (19, 83), "imza:string_ref": (5, 153)}.items():
        row = dav[key]
        assert (row["dogru"], row["n"]) == (k, n)
        assert row["wilson_alt"] == pytest.approx(round(wilson(k, n)[0], 4))
        assert behavior_confidence(key.split(":", 1)[1]) == row["wilson_alt"]
    # P11'in tam-ad kaydı (füzyonun okuduğu) silinmedi, değişmedi.
    assert MEASURED_PRECISION["kaynaklar"]["imza:call_pattern"] == {"n": 76, "dogru": 0,
                                                                     "wilson_alt": 0.0}
    assert MEASURED_PRECISION["kaynaklar"]["imza:string_ref"] == {"n": 132, "dogru": 0,
                                                                   "wilson_alt": 0.0}
    assert MEASURED_PRECISION["davranis"]["_kaynak"]["tarih"] == "2026-11-18"
