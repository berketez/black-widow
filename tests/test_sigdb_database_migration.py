"""sig_db database migration testleri (Faz A-DELETE sonrasi).

v1.13 Dalga 2 A-DELETE: legacy ``_*_SIGNATURES`` inline literal bloklari
silindi, signature_db.py artik
``from sigdb_builtin.database import SIGNATURES`` referansi uzerinden
dogrudan import yapiyor. AST parse parity testleri tautolojik hale geldigi
icin kaldirildi.

Korunan parity katmanlari:
1. Runtime identity (``is`` check)
2. Coverage count (toplam 579 imza)
3. Anahtar kesismez (her cift arasi)
4. Bilinen sembol lookup (sqlite/mysql/protobuf/json/xml/flatbuffers)
5. Protobuf namespace formati korunmus (``::``-li isimler)
6. Post-A-DELETE: signature_db.py'da inline literal YOK + dogrudan
   ``_BUILTIN_DATABASE_SIGS`` referansi VAR.
"""
from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------------

_KEY_TO_ORIG: dict[str, str] = {
    "sqlite_signatures": "_SQLITE_SIGNATURES",
    "database_ext_signatures": "_DATABASE_EXT_SIGNATURES",
    "protobuf_signatures": "_PROTOBUF_SIGNATURES",
    "json_signatures": "_JSON_SIGNATURES",
    "xml_signatures": "_XML_SIGNATURES",
    "serialization_signatures": "_SERIALIZATION_SIGNATURES",
}

_EXPECTED_KEYS: frozenset[str] = frozenset(_KEY_TO_ORIG.keys())

_EXPECTED_COUNTS: dict[str, int] = {
    "sqlite_signatures": 144,
    "database_ext_signatures": 96,
    "protobuf_signatures": 86,
    "json_signatures": 116,
    "xml_signatures": 93,
    "serialization_signatures": 44,
}

_EXPECTED_TOTAL = sum(_EXPECTED_COUNTS.values())  # 579


# ---------------------------------------------------------------------------
# 1. Modul yuklenebilir mi?
# ---------------------------------------------------------------------------

def test_sigdb_builtin_database_importable() -> None:
    """sigdb_builtin.database import edilebilir ve SIGNATURES dict'i var."""
    from karadul.analyzers.sigdb_builtin import database

    assert hasattr(database, "SIGNATURES")
    assert isinstance(database.SIGNATURES, dict)
    assert len(database.SIGNATURES) == 6


def test_sigdb_builtin_database_has_expected_keys() -> None:
    """SIGNATURES tam olarak beklenen 6 top-level anahtari icerir."""
    from karadul.analyzers.sigdb_builtin import database

    assert set(database.SIGNATURES.keys()) == _EXPECTED_KEYS


def test_coverage_count() -> None:
    """Her kategori beklenen entry sayisina sahip ve toplam 579 imza."""
    from karadul.analyzers.sigdb_builtin import database

    for key, expected in _EXPECTED_COUNTS.items():
        actual = len(database.SIGNATURES[key])
        assert actual == expected, f"{key}: expected {expected}, got {actual}"

    total = sum(len(v) for v in database.SIGNATURES.values())
    assert total == _EXPECTED_TOTAL, (
        f"Total database entry count: expected {_EXPECTED_TOTAL}, got {total}"
    )


# ---------------------------------------------------------------------------
# 2. Anahtar kesismez (cross-dict)
# ---------------------------------------------------------------------------

def test_no_duplicate_keys() -> None:
    """6 alt-dict arasinda anahtar kesismez (entry leak korumasi)."""
    from karadul.analyzers.sigdb_builtin import database

    sigs = database.SIGNATURES
    keys_per = {k: set(v.keys()) for k, v in sigs.items()}

    keys_list = list(keys_per.items())
    for i in range(len(keys_list)):
        for j in range(i + 1, len(keys_list)):
            ki, vi = keys_list[i]
            kj, vj = keys_list[j]
            overlap = vi & vj
            assert not overlap, (
                f"Anahtar kesisimi: {ki} <-> {kj}: {sorted(overlap)[:5]}"
            )


# ---------------------------------------------------------------------------
# 3. Runtime identity
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("builtin_key,legacy_name", sorted(_KEY_TO_ORIG.items()))
def test_runtime_identity_each_dict(builtin_key: str, legacy_name: str) -> None:
    """signature_db._<NAME> ile builtin database[<key>] AYNI obje (`is`)."""
    from karadul.analyzers import signature_db as sdb
    from karadul.analyzers.sigdb_builtin import database

    legacy = getattr(sdb, legacy_name)
    migrated = database.SIGNATURES[builtin_key]
    assert legacy is migrated, (
        f"{legacy_name} <-> {builtin_key} runtime identity ihlali"
    )
    assert len(migrated) == _EXPECTED_COUNTS[builtin_key]


# ---------------------------------------------------------------------------
# 4. Dispatcher (get_category)
# ---------------------------------------------------------------------------

def test_get_category_database_returns_data() -> None:
    """sigdb_builtin.get_category('database') dolu dict dondurur."""
    from karadul.analyzers.sigdb_builtin import get_category

    sigs = get_category("database")
    assert isinstance(sigs, dict)
    assert len(sigs) == 6
    assert set(sigs.keys()) == _EXPECTED_KEYS


# ---------------------------------------------------------------------------
# 5. Protobuf namespace formati korunmus mu?
# ---------------------------------------------------------------------------

def test_protobuf_namespace_preserved() -> None:
    """``_PROTOBUF_SIGNATURES`` icindeki namespace'li (``::``-li) anahtarlar
    aynen korunmus olmali."""
    from karadul.analyzers.sigdb_builtin import database

    proto = database.SIGNATURES["protobuf_signatures"]

    sentinels = [
        "google::protobuf::MessageLite::SerializeToString",
        "google::protobuf::MessageLite::ParseFromString",
        "google::protobuf::MessageLite::SerializeToArray",
        "google::protobuf::Message::CopyFrom",
        "google::protobuf::Message::MergeFrom",
        "google::protobuf::Message::Clear",
        "google::protobuf::Message::DebugString",
        "google::protobuf::Arena::CreateMessage",
        "google::protobuf::DescriptorPool::FindFileByName",
        "google::protobuf::io::CodedOutputStream::WriteVarint32",
        "google::protobuf::io::CodedInputStream::ReadVarint32",
        "google::protobuf::TextFormat::PrintToString",
        "google::protobuf::util::JsonStringToMessage",
    ]
    for name in sentinels:
        assert name in proto, f"Namespace'li proto sembolu kayip: {name!r}"
        info = proto[name]
        assert info["lib"] == "protobuf"
        assert info["category"] == "serialization"

    ns_keys = [k for k in proto if "::" in k]
    assert len(ns_keys) >= 30, (
        f"Beklenen >=30 namespace'li proto entry, bulundu {len(ns_keys)}"
    )

    for name in ns_keys:
        basename = name.rsplit("::", 1)[-1]
        assert basename and "::" not in basename, (
            f"Basename cikarimi bozuldu: {name!r} -> {basename!r}"
        )

    # Mangled (Itanium) varyantlar da hala mevcut.
    assert "_ZN6google8protobuf7MessageC1Ev" in proto
    assert "_ZN6google8protobuf11MessageLite18SerializeToStringEPNSt" in proto


# ---------------------------------------------------------------------------
# 6. Bilindik sembol noktasal kontrolleri
# ---------------------------------------------------------------------------

def test_known_sqlite_symbols_present() -> None:
    """Temel SQLite C API sembolleri migrate olmus."""
    from karadul.analyzers.sigdb_builtin import database

    sqlite = database.SIGNATURES["sqlite_signatures"]
    for sym in [
        "_sqlite3_open",
        "_sqlite3_close",
        "_sqlite3_exec",
        "_sqlite3_prepare_v2",
        "_sqlite3_step",
        "_sqlite3_finalize",
        "_sqlite3_bind_text",
        "_sqlite3_column_text",
        "_sqlite3_libversion",
    ]:
        assert sym in sqlite, f"SQLite sembol kayip: {sym}"
        assert sqlite[sym]["lib"] == "sqlite3"
        assert sqlite[sym]["category"] == "database"


def test_known_database_ext_symbols_present() -> None:
    """MySQL/PostgreSQL/Redis/LMDB/LevelDB sembolleri migrate olmus."""
    from karadul.analyzers.sigdb_builtin import database

    db_ext = database.SIGNATURES["database_ext_signatures"]
    assert "mysql_init" in db_ext
    assert db_ext["mysql_init"]["lib"] == "libmysqlclient"
    assert "PQconnectdb" in db_ext
    assert db_ext["PQconnectdb"]["lib"] == "libpq"
    assert "redisConnect" in db_ext
    assert db_ext["redisConnect"]["lib"] == "hiredis"
    assert "mdb_env_create" in db_ext
    assert db_ext["mdb_env_create"]["lib"] == "lmdb"
    assert "leveldb_open" in db_ext
    assert db_ext["leveldb_open"]["lib"] == "leveldb"


def test_known_json_xml_serialization_symbols_present() -> None:
    """cJSON / yyjson / jansson / libxml2 / expat / FlatBuffers / msgpack."""
    from karadul.analyzers.sigdb_builtin import database

    sigs = database.SIGNATURES
    assert "_cJSON_Parse" in sigs["json_signatures"]
    assert "_yyjson_read" in sigs["json_signatures"]
    assert "_json_loads" in sigs["json_signatures"]
    assert sigs["json_signatures"]["_json_loads"]["lib"] == "jansson"
    assert "_xmlReadMemory" in sigs["xml_signatures"]
    assert sigs["xml_signatures"]["_xmlReadMemory"]["lib"] == "libxml2"
    assert "_XML_ParserCreate" in sigs["xml_signatures"]
    assert sigs["xml_signatures"]["_XML_ParserCreate"]["lib"] == "expat"
    ser = sigs["serialization_signatures"]
    assert "__ZN11flatbuffers17FlatBufferBuilder" in ser
    assert ser["__ZN11flatbuffers17FlatBufferBuilder"]["lib"] == "flatbuffers"
    assert "__ZN5capnp14MessageBuilder" in ser
    assert ser["__ZN5capnp14MessageBuilder"]["lib"] == "capnproto"
    assert "_msgpack_pack_int" in ser
    assert ser["_msgpack_pack_int"]["lib"] == "msgpack"


# ---------------------------------------------------------------------------
# 7. Schema consistency
# ---------------------------------------------------------------------------

def test_entry_schema_consistency() -> None:
    """Her entry dict 'lib', 'purpose', 'category' anahtarlarini icerir."""
    from karadul.analyzers.sigdb_builtin import database

    required = {"lib", "purpose", "category"}
    bad: dict[str, set[str]] = {}
    for cat_key, cat_dict in database.SIGNATURES.items():
        for sym, info in cat_dict.items():
            assert isinstance(info, dict), f"{cat_key}/{sym}: dict degil"
            missing = required - info.keys()
            if missing:
                bad[f"{cat_key}/{sym}"] = missing
    assert not bad, f"Eksik schema alanlari: {dict(list(bad.items())[:5])}"


# ---------------------------------------------------------------------------
# 8. Post-A-DELETE: legacy literal silindi, dogrudan referans
# ---------------------------------------------------------------------------

def test_post_a_delete_no_inline_literal() -> None:
    """signature_db.py'da legacy ``_<KAT>_SIGNATURES = {...}`` literal'leri YOK."""
    from pathlib import Path

    text = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    assert (
        '_SQLITE_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_DATABASE_SIGS["sqlite_signatures"]'
    ) in text
    assert (
        '_PROTOBUF_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_DATABASE_SIGS["protobuf_signatures"]'
    ) in text
    for legacy in _KEY_TO_ORIG.values():
        assert f'\n{legacy}: dict[str, dict[str, str]] = {{' not in text, (
            f"{legacy} hala inline literal olarak duruyor"
        )


def test_post_a_delete_direct_import() -> None:
    """signature_db.py database SIGNATURES'i ``sigdb_builtin.database``'dan dogrudan alir."""
    from pathlib import Path

    text = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    assert "_BUILTIN_DATABASE_SIGS" in text
    assert "sigdb_builtin" in text and "database" in text


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
