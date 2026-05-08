"""sig_db languages migration testleri (Faz A-DELETE sonrasi).

v1.13 Dalga 2 A-DELETE: legacy ``_V8_NODE_SIGNATURES``, ``_LUA_SIGNATURES``
ve ``_RUBY_SIGNATURES`` inline literal bloklari silindi, signature_db.py
artik ``from sigdb_builtin.languages import SIGNATURES`` referansi uzerinden
dogrudan import yapiyor. AST parse parity testleri (eski
``_load_original_ast_values`` + ``test_identity_parity_*``) tautolojik hale
geldigi icin kaldirildi.

Korunan parity katmanlari:
1. Runtime identity (``is`` check, v8_node/lua/ruby)
2. Coverage count (73 + 52 + 30 = 155 imza)
3. No duplicate keys (cross-dict)
4. Bilinen sembol lookup (v8::Isolate::New, napi_*, luaL_newstate, ruby_init)
5. SignatureDB instance entegrasyon
6. Post-A-DELETE: signature_db.py'da inline literal YOK + dogrudan
   ``_BUILTIN_LANG_SIGNATURES`` referansi VAR.
"""
from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# 1. Yeni modul dogru yukleniyor mu?
# ---------------------------------------------------------------------------

def test_sigdb_builtin_languages_importable() -> None:
    """sigdb_builtin.languages import edilebilir ve SIGNATURES dict'i var."""
    from karadul.analyzers.sigdb_builtin import languages as lang_mod

    assert hasattr(lang_mod, "SIGNATURES")
    assert isinstance(lang_mod.SIGNATURES, dict)
    assert len(lang_mod.SIGNATURES) == 3


def test_sigdb_builtin_languages_has_expected_keys() -> None:
    """SIGNATURES 3 top-level anahtar icerir."""
    from karadul.analyzers.sigdb_builtin import languages as lang_mod

    expected = {"v8_node", "lua", "ruby"}
    assert set(lang_mod.SIGNATURES.keys()) == expected


def test_coverage_count() -> None:
    """Her kategori beklenen entry sayisina sahip (AST'den dogrulanan)."""
    from karadul.analyzers.sigdb_builtin import languages as lang_mod

    expected_counts = {
        "v8_node": 73,
        "lua": 52,
        "ruby": 30,
    }
    for key, expected in expected_counts.items():
        actual = len(lang_mod.SIGNATURES[key])
        assert actual == expected, f"{key}: expected {expected}, got {actual}"

    total = sum(len(v) for v in lang_mod.SIGNATURES.values())
    assert total == 155, f"Total languages entry count: expected 155, got {total}"


def test_no_duplicate_keys() -> None:
    """Uc dict arasinda anahtar kesişmesi olmamali (entry leak korumasi)."""
    from karadul.analyzers.sigdb_builtin import languages as lang_mod

    keys = (
        list(lang_mod.SIGNATURES["v8_node"])
        + list(lang_mod.SIGNATURES["lua"])
        + list(lang_mod.SIGNATURES["ruby"])
    )
    assert len(keys) == len(set(keys)), "duplicate fonksiyon adi tespit edildi"


# ---------------------------------------------------------------------------
# 2. Dispatcher (get_category) calisiyor mu?
# ---------------------------------------------------------------------------

def test_get_category_languages_returns_data() -> None:
    """sigdb_builtin.get_category('languages') dolu dict dondurur."""
    from karadul.analyzers.sigdb_builtin import get_category

    sigs = get_category("languages")
    assert isinstance(sigs, dict)
    assert len(sigs) == 3
    assert "v8_node" in sigs
    assert "lua" in sigs
    assert "ruby" in sigs


# ---------------------------------------------------------------------------
# 3. signature_db.py override aktif mi? (identity check)
# ---------------------------------------------------------------------------

def test_override_languages_identity() -> None:
    """signature_db._XXX_SIGNATURES ile builtin.languages ayni obje (Tip A bind)."""
    from karadul.analyzers import signature_db as sdb
    from karadul.analyzers.sigdb_builtin.languages import SIGNATURES as builtin

    assert sdb._BUILTIN_LANG_SIGNATURES is not None
    assert sdb._V8_NODE_SIGNATURES is builtin["v8_node"]
    assert sdb._LUA_SIGNATURES is builtin["lua"]
    assert sdb._RUBY_SIGNATURES is builtin["ruby"]


def test_legacy_languages_attributes_still_accessible() -> None:
    """Backward compat: eski _XXX_SIGNATURES attribute hala erisilebilir."""
    from karadul.analyzers import signature_db as sdb

    assert hasattr(sdb, "_V8_NODE_SIGNATURES")
    assert hasattr(sdb, "_LUA_SIGNATURES")
    assert hasattr(sdb, "_RUBY_SIGNATURES")
    # Ve dolular (bos degil)
    assert len(sdb._V8_NODE_SIGNATURES) == 73
    assert len(sdb._LUA_SIGNATURES) == 52
    assert len(sdb._RUBY_SIGNATURES) == 30


# ---------------------------------------------------------------------------
# 4. Post-A-DELETE: legacy literal silindi, dogrudan import kullaniliyor
# ---------------------------------------------------------------------------

def test_post_a_delete_no_inline_literal() -> None:
    """signature_db.py'da legacy ``_V8_NODE/_LUA/_RUBY_SIGNATURES = {...}``
    literal'leri YOK.

    A-DELETE sonrasi signature_db.py languages dict'lerini sadece
    ``_BUILTIN_LANG_SIGNATURES["..."]`` lookup'u uzerinden tutar.
    """
    from pathlib import Path

    text = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    # Reference assignment'lar olmali
    assert (
        '_V8_NODE_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_LANG_SIGNATURES["v8_node"]'
    ) in text
    assert (
        '_LUA_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_LANG_SIGNATURES["lua"]'
    ) in text
    assert (
        '_RUBY_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_LANG_SIGNATURES["ruby"]'
    ) in text
    # Inline literal blok baslangici YOK
    assert "_V8_NODE_SIGNATURES: dict[str, dict[str, str]] = {" not in text
    assert "_LUA_SIGNATURES: dict[str, dict[str, str]] = {" not in text
    assert "_RUBY_SIGNATURES: dict[str, dict[str, str]] = {" not in text


def test_post_a_delete_direct_import() -> None:
    """signature_db.py languages SIGNATURES'i ``sigdb_builtin.languages``'tan
    dogrudan alir."""
    from pathlib import Path

    text = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    assert "_BUILTIN_LANG_SIGNATURES" in text
    assert "sigdb_builtin" in text and "languages" in text


# ---------------------------------------------------------------------------
# 5. SignatureDB class kullanimi — bozulmus mu?
# ---------------------------------------------------------------------------

def test_signature_db_instance_uses_migrated_languages_data() -> None:
    """SignatureDB() instance languages signature'larini tasinmis kaynaktan alir."""
    from karadul.analyzers.signature_db import SignatureDB

    db = SignatureDB()
    assert db is not None


def test_v8_known_symbol_lookup() -> None:
    """Override sonrasi bilindik bir V8 sembolu hala bulunabilir."""
    from karadul.analyzers import signature_db as sdb

    # v8::Isolate::New — temel API, migration kirikligi belirleyici
    assert "v8::Isolate::New" in sdb._V8_NODE_SIGNATURES
    entry = sdb._V8_NODE_SIGNATURES["v8::Isolate::New"]
    assert entry["lib"] == "v8"
    assert entry["category"] == "v8"


def test_napi_known_symbol_lookup() -> None:
    """Node.js N-API sembolleri migrate olmus."""
    from karadul.analyzers import signature_db as sdb

    assert "napi_create_function" in sdb._V8_NODE_SIGNATURES
    assert "napi_throw_error" in sdb._V8_NODE_SIGNATURES
    assert sdb._V8_NODE_SIGNATURES["napi_create_function"]["lib"] == "node"
    assert sdb._V8_NODE_SIGNATURES["napi_create_function"]["category"] == "node"


def test_lua_known_symbol_lookup() -> None:
    """Lua C API sembolleri migrate olmus."""
    from karadul.analyzers import signature_db as sdb

    assert "luaL_newstate" in sdb._LUA_SIGNATURES
    assert "lua_pcall" in sdb._LUA_SIGNATURES
    assert sdb._LUA_SIGNATURES["luaL_newstate"]["lib"] == "lua"
    assert sdb._LUA_SIGNATURES["luaL_newstate"]["category"] == "lua"


def test_ruby_known_symbol_lookup() -> None:
    """Ruby C extension sembolleri migrate olmus."""
    from karadul.analyzers import signature_db as sdb

    assert "ruby_init" in sdb._RUBY_SIGNATURES
    assert "rb_define_class" in sdb._RUBY_SIGNATURES
    assert "Data_Wrap_Struct" in sdb._RUBY_SIGNATURES
    assert sdb._RUBY_SIGNATURES["ruby_init"]["lib"] == "ruby"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
