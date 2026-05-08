"""sig_db event_utils migration testleri (Faz A-DELETE sonrasi).

v1.13 Dalga 2 A-DELETE: legacy ``_*_SIGNATURES`` inline literal bloklari
silindi, signature_db.py artik
``from sigdb_builtin.event_utils import SIGNATURES`` referansi uzerinden
dogrudan import yapiyor. AST parse parity testleri tautolojik hale geldigi
icin kaldirildi.

Korunan parity katmanlari:
1. Runtime identity (``is`` check)
2. Coverage count
3. Cross-dict overlap kontrolu
4. Bilinen sembol lookup
5. Post-A-DELETE: signature_db.py'da inline literal YOK + dogrudan
   ``_BUILTIN_EVENT_UTILS_SIGS`` referansi VAR.

Kapsam (9 alt-kategori, 364 imza).
"""
from __future__ import annotations

import pytest


_EXPECTED_KEYS = {
    "libuv_signatures",
    "libevent_signatures",
    "regex_signatures",
    "icu_signatures",
    "math_signatures",
    "qt_signatures",
    "testing_signatures",
    "misc_signatures",
    "msgqueue_signatures",
}

_EXPECTED_COUNTS = {
    "libuv_signatures": 69,
    "libevent_signatures": 29,
    "regex_signatures": 18,
    "icu_signatures": 41,
    "math_signatures": 77,
    "qt_signatures": 16,
    "testing_signatures": 9,
    "misc_signatures": 44,
    "msgqueue_signatures": 61,
}

_TOTAL_EXPECTED = 364

_KEY_TO_ORIG = {
    "libuv_signatures": "_LIBUV_SIGNATURES",
    "libevent_signatures": "_LIBEVENT_SIGNATURES",
    "regex_signatures": "_REGEX_SIGNATURES",
    "icu_signatures": "_ICU_SIGNATURES",
    "math_signatures": "_MATH_SIGNATURES",
    "qt_signatures": "_QT_SIGNATURES",
    "testing_signatures": "_TESTING_SIGNATURES",
    "misc_signatures": "_MISC_SIGNATURES",
    "msgqueue_signatures": "_MSGQUEUE_SIGNATURES",
}


# ---------------------------------------------------------------------------
# 1. Modul yuklenebilir mi?
# ---------------------------------------------------------------------------

def test_sigdb_builtin_event_utils_importable() -> None:
    """sigdb_builtin.event_utils import edilebilir ve SIGNATURES dict'i var."""
    from karadul.analyzers.sigdb_builtin import event_utils

    assert hasattr(event_utils, "SIGNATURES")
    assert isinstance(event_utils.SIGNATURES, dict)
    assert len(event_utils.SIGNATURES) == 9


def test_sigdb_builtin_event_utils_has_expected_keys() -> None:
    """SIGNATURES 9 top-level anahtar icerir."""
    from karadul.analyzers.sigdb_builtin import event_utils

    assert set(event_utils.SIGNATURES.keys()) == _EXPECTED_KEYS


def test_sigdb_builtin_event_utils_entry_counts() -> None:
    """Her kategori beklenen entry sayisina sahip."""
    from karadul.analyzers.sigdb_builtin import event_utils

    for key, expected in _EXPECTED_COUNTS.items():
        actual = len(event_utils.SIGNATURES[key])
        assert actual == expected, f"{key}: expected {expected}, got {actual}"

    total = sum(len(v) for v in event_utils.SIGNATURES.values())
    assert total == _TOTAL_EXPECTED, (
        f"Total event_utils entry count: expected {_TOTAL_EXPECTED}, got {total}"
    )


def test_no_duplicate_keys_within_dicts() -> None:
    """Her dict icindeki anahtarlar tekildir."""
    from karadul.analyzers.sigdb_builtin import event_utils

    for key, dct in event_utils.SIGNATURES.items():
        assert len(dct) == _EXPECTED_COUNTS[key], (
            f"{key} entry sayisi expected {_EXPECTED_COUNTS[key]}, got {len(dct)}"
        )


# ---------------------------------------------------------------------------
# 2. Cross-dict anahtar overlap'lari
# ---------------------------------------------------------------------------

def test_minimal_cross_dict_overlap() -> None:
    """Mantikli cifter arasinda anahtar kesişimi olmamali."""
    from karadul.analyzers.sigdb_builtin import event_utils

    keys_by_cat = {k: set(v.keys()) for k, v in event_utils.SIGNATURES.items()}
    pairs = [
        ("libuv_signatures", "libevent_signatures"),
        ("libuv_signatures", "misc_signatures"),
        ("libevent_signatures", "misc_signatures"),
        ("regex_signatures", "icu_signatures"),
        ("math_signatures", "qt_signatures"),
        ("qt_signatures", "testing_signatures"),
        ("testing_signatures", "misc_signatures"),
        ("misc_signatures", "msgqueue_signatures"),
        ("msgqueue_signatures", "libuv_signatures"),
    ]
    for a, b in pairs:
        overlap = keys_by_cat[a] & keys_by_cat[b]
        assert not overlap, f"Anahtar kesişimi {a} <-> {b}: {overlap}"


# ---------------------------------------------------------------------------
# 3. Runtime identity
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("builtin_key,legacy_name", sorted(_KEY_TO_ORIG.items()))
def test_runtime_identity_each_dict(builtin_key: str, legacy_name: str) -> None:
    """signature_db._<NAME> ile builtin event_utils[<key>] AYNI obje (`is`)."""
    from karadul.analyzers import signature_db as sdb
    from karadul.analyzers.sigdb_builtin import event_utils

    legacy = getattr(sdb, legacy_name)
    migrated = event_utils.SIGNATURES[builtin_key]
    assert legacy is migrated, (
        f"{legacy_name} <-> {builtin_key} runtime identity ihlali"
    )
    assert len(migrated) == _EXPECTED_COUNTS[builtin_key]


# ---------------------------------------------------------------------------
# 4. Dispatcher arabirim varligi
# ---------------------------------------------------------------------------

def test_event_utils_module_arayuzu() -> None:
    """event_utils.SIGNATURES dolu dict, beklenen 9 anahtarli."""
    from karadul.analyzers.sigdb_builtin import event_utils

    sigs = event_utils.SIGNATURES
    assert isinstance(sigs, dict)
    assert len(sigs) == 9
    for key in _EXPECTED_KEYS:
        assert key in sigs
        assert isinstance(sigs[key], dict)
        assert len(sigs[key]) > 0


# ---------------------------------------------------------------------------
# 5. Bilindik sembol noktasal kontrolleri
# ---------------------------------------------------------------------------

def test_known_event_utils_symbols_present() -> None:
    """Bilindik sembollerin her kategoride mevcut oldugunu dogrula."""
    from karadul.analyzers.sigdb_builtin import event_utils

    sigs = event_utils.SIGNATURES
    assert "_uv_loop_init" in sigs["libuv_signatures"]
    assert sigs["libuv_signatures"]["_uv_loop_init"]["lib"] == "libuv"
    assert "_uv_tcp_init" in sigs["libuv_signatures"]
    assert "_uv_fs_open" in sigs["libuv_signatures"]
    assert "_event_base_new" in sigs["libevent_signatures"]
    assert sigs["libevent_signatures"]["_event_base_new"]["lib"] == "libevent"
    assert "_evhttp_new" in sigs["libevent_signatures"]
    assert "_pcre2_compile_8" in sigs["regex_signatures"]
    assert sigs["regex_signatures"]["_pcre2_compile_8"]["lib"] == "pcre2"
    assert "_regcomp" in sigs["regex_signatures"]
    assert "_u_init" in sigs["icu_signatures"]
    assert sigs["icu_signatures"]["_u_init"]["lib"] == "icu"
    assert "_uregex_open" in sigs["icu_signatures"]
    assert "_sin" in sigs["math_signatures"]
    assert sigs["math_signatures"]["_sin"]["lib"] == "libm"
    assert "_cblas_sgemm" in sigs["math_signatures"]
    assert "_dgesv_" in sigs["math_signatures"]
    assert sigs["math_signatures"]["_dgesv_"]["lib"] == "lapack"
    assert "__ZN7QObjectC1EPS_" in sigs["qt_signatures"]
    assert sigs["qt_signatures"]["__ZN7QObjectC1EPS_"]["lib"] == "qt"
    assert "__ZN7testing4TestC1Ev" in sigs["testing_signatures"]
    assert sigs["testing_signatures"]["__ZN7testing4TestC1Ev"]["lib"] == "gtest"
    assert "_CU_initialize_registry" in sigs["testing_signatures"]
    assert "_getopt" in sigs["misc_signatures"]
    assert "_uuid_generate" in sigs["misc_signatures"]
    assert "_g_malloc" in sigs["misc_signatures"]
    assert sigs["misc_signatures"]["_g_main_loop_run"]["category"] == "event_loop"
    assert "zmq_ctx_new" in sigs["msgqueue_signatures"]
    assert sigs["msgqueue_signatures"]["zmq_ctx_new"]["lib"] == "zeromq"
    assert "amqp_new_connection" in sigs["msgqueue_signatures"]
    assert "rd_kafka_new" in sigs["msgqueue_signatures"]
    assert "MQTTClient_create" in sigs["msgqueue_signatures"]


def test_entry_schema_consistency() -> None:
    """Her entry 'lib', 'purpose', 'category' anahtarlarini tasimali."""
    from karadul.analyzers.sigdb_builtin import event_utils

    required_keys = {"lib", "purpose", "category"}
    for cat_key, dct in event_utils.SIGNATURES.items():
        for sym, entry in dct.items():
            assert isinstance(entry, dict), f"{cat_key}::{sym} entry dict degil"
            assert required_keys <= set(entry.keys()), (
                f"{cat_key}::{sym} eksik anahtar: "
                f"{required_keys - set(entry.keys())}"
            )
            for k in required_keys:
                assert isinstance(entry[k], str), (
                    f"{cat_key}::{sym}::{k} string degil"
                )


def test_total_coverage_count() -> None:
    """Toplam entry sayisi 364."""
    from karadul.analyzers.sigdb_builtin import event_utils

    total = sum(len(v) for v in event_utils.SIGNATURES.values())
    assert total == _TOTAL_EXPECTED


# ---------------------------------------------------------------------------
# 6. Post-A-DELETE: legacy literal silindi, dogrudan referans
# ---------------------------------------------------------------------------

def test_post_a_delete_no_inline_literal() -> None:
    """signature_db.py'da legacy ``_<KAT>_SIGNATURES = {...}`` literal'leri YOK."""
    from pathlib import Path

    text = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    assert (
        '_LIBUV_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_EVENT_UTILS_SIGS["libuv_signatures"]'
    ) in text
    assert (
        '_MATH_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_EVENT_UTILS_SIGS["math_signatures"]'
    ) in text
    for legacy in _KEY_TO_ORIG.values():
        assert f'\n{legacy}: dict[str, dict[str, str]] = {{' not in text, (
            f"{legacy} hala inline literal olarak duruyor"
        )


def test_post_a_delete_direct_import() -> None:
    """signature_db.py event_utils SIGNATURES'i ``sigdb_builtin.event_utils``'dan dogrudan alir."""
    from pathlib import Path

    text = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    assert "_BUILTIN_EVENT_UTILS_SIGS" in text
    assert "sigdb_builtin" in text and "event_utils" in text


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
