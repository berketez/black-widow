"""Karadul v1.10.0 M2 T4 -- SignatureDB params -> semantic_namer koprusu testleri.

Bu testler iki dosyayi dogrular:
  * ``karadul/analyzers/signature_db.py`` -- SignatureMatch dataclass'ta
    ``params`` field'i ve tum match path'lerinde propagasyon.
  * ``karadul/reconstruction/engineering/semantic_namer.py`` -- sig DB
    payload params'inin API_PARAM_DB statik lookup'tan ONCE kullanilmasi.

Regresyon seti: feature flag off/on, fallback davranisi, source attribution.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from karadul.analyzers.signature_db import SignatureDB, SignatureMatch
from karadul.config import Config
from karadul.reconstruction.engineering.semantic_namer import (
    SemanticName,
    SemanticParameterNamer,
    _names_from_sig_db_params_worker,
    _worker_apply_signature_based,
    _worker_init,
)


# ---------------------------------------------------------------------------
# 1. SignatureMatch dataclass -- default None
# ---------------------------------------------------------------------------

def test_signature_match_params_default_none() -> None:
    """params field'i default None -- geri uyumluluk icin."""
    match = SignatureMatch(
        original_name="FUN_001",
        matched_name="strcpy",
        library="libc",
        confidence=0.98,
        match_method="symbol",
    )
    assert match.params is None
    # to_dict'te de gorunmeli
    d = match.to_dict()
    assert "params" in d
    assert d["params"] is None


# ---------------------------------------------------------------------------
# 2. match_function propagates params (builtin symbol_db path)
# ---------------------------------------------------------------------------

def test_match_function_propagates_params(tmp_path: Path) -> None:
    """SignatureDB'ye params'li sig enjekte et, match_function dondurdugunde
    ``match.params`` ayni payload olmali."""
    cfg = Config()
    cfg.perf.use_lmdb_sigdb = False
    db = SignatureDB(cfg)

    # Builtin symbol DB'ye params'li bir sig enjekte et (test tarafinda izole)
    injected_name = "__karadul_test_sig_params_fn"
    injected_params = [
        {"name": "buffer", "type": "char *", "index": 0},
        {"name": "size", "type": "size_t", "index": 1},
    ]
    db._symbol_db[injected_name] = {
        "lib": "test_lib",
        "purpose": "test fixture",
        "category": "test",
        "params": injected_params,
    }

    match = db.match_function(injected_name)
    assert match is not None
    assert match.matched_name == injected_name.lstrip("_")
    assert match.library == "test_lib"
    assert match.params is not None
    assert match.params == injected_params

    # Cleanup (dict class-level; diger testleri etkilememeli)
    db._symbol_db.pop(injected_name, None)


# ---------------------------------------------------------------------------
# 3. _match_by_symbol macOS _ prefix path params propagasyonu
# ---------------------------------------------------------------------------

def test_match_by_symbol_propagates_params(tmp_path: Path) -> None:
    """macOS _ prefix yolu (func_name=foo, sig=_foo) params tasimali."""
    cfg = Config()
    cfg.perf.use_lmdb_sigdb = False
    db = SignatureDB(cfg)

    # Tek _ prefix kullan -- lstrip("_") ile tek seferde bare isme doner
    prefixed_name = "_karadul_test_prefixed_fn"   # DB'de _ prefix'li
    bare_name = "karadul_test_prefixed_fn"        # Fonksiyonda _ yok
    injected_params = [{"name": "arg0", "type": "int", "index": 0}]
    db._symbol_db[prefixed_name] = {
        "lib": "testlib",
        "purpose": "",
        "category": "",
        "params": injected_params,
    }

    match = db.match_function(bare_name)
    assert match is not None
    # Bu yol L9336: matched_name = func_name (bare), confidence 0.97
    assert match.confidence == 0.97
    assert match.params == injected_params

    db._symbol_db.pop(prefixed_name, None)


# ---------------------------------------------------------------------------
# 4. LMDB match_by_symbol path params propagasyonu (mock backend)
# ---------------------------------------------------------------------------

class _StubLMDB:
    """Minimal LMDB stub: lookup_symbol tek sembol dondurur."""

    def __init__(self, name: str, payload: dict) -> None:
        self._name = name
        self._payload = payload

    def lookup_symbol(self, name: str) -> dict | None:
        if name == self._name:
            return self._payload
        return None


def test_lmdb_match_propagates_params() -> None:
    """LMDB backend'den gelen sig params'i SignatureMatch.params olarak akmali."""
    cfg = Config()
    cfg.perf.use_lmdb_sigdb = False  # adapter LMDB backend'ini kendi kurmasin
    db = SignatureDB(cfg)

    fake_params = [
        {"name": "ppDb", "type": "sqlite3 **", "index": 1},
        {"name": "filename", "type": "const char *", "index": 0},
    ]
    db._lmdb_backend = _StubLMDB(
        name="_sqlite3_open_fake",
        payload={
            "lib": "sqlite3",
            "purpose": "open database",
            "category": "database",
            "params": fake_params,
        },
    )
    # _match_by_symbol LMDB varsa ONCE ona bakar (L9270 branch)
    match = db._match_by_symbol("_sqlite3_open_fake", target_platform=None)
    assert match is not None
    assert match.library == "sqlite3"
    assert match.match_method == "symbol"
    assert match.params == fake_params
    assert match.confidence == 0.98  # LMDB full-name path


# ---------------------------------------------------------------------------
# 5. semantic_namer sig_db_params API_PARAM_DB'den ONCE kullanir
# ---------------------------------------------------------------------------

class _StubAPIParamDB:
    """APIParamDB fake: verilen isim icin ceyrek param listesi dondurur."""

    def __init__(self, params_map: dict[str, list[str]]) -> None:
        self._map = params_map

    def get_param_names(self, name: str) -> list[str] | None:
        return self._map.get(name)

    def propagate_params(self, c_code: str) -> dict[str, str]:  # pragma: no cover
        return {}


def _make_namer_with_sig(
    *,
    sig_params: list[dict] | None,
    api_params: list[str] | None,
    config: Config | None = None,
) -> tuple[SemanticParameterNamer, SignatureMatch]:
    """Testler icin minimal namer + SignatureMatch fixture'i."""
    cfg = config or Config()
    namer = SemanticParameterNamer(cfg)
    sm = SignatureMatch(
        original_name="FUN_001",
        matched_name="doThing",
        library="testlib",
        confidence=0.98,
        match_method="symbol",
        purpose="",
        category="",
        params=sig_params,
    )
    namer._sig_matches["FUN_001"] = sm
    if api_params is not None:
        namer._api_param_db = _StubAPIParamDB({"doThing": api_params})
    else:
        namer._api_param_db = _StubAPIParamDB({})
    return namer, sm


def test_semantic_namer_uses_sig_params_over_api_db() -> None:
    """Hem sig hem API_PARAM_DB varsa sig DB kazanir (0.95 > 0.92)."""
    sig_params = [
        {"name": "sig_buffer", "type": "void *", "index": 0},
        {"name": "sig_length", "type": "size_t", "index": 1},
    ]
    api_params = ["api_buffer", "api_length"]
    namer, _ = _make_namer_with_sig(sig_params=sig_params, api_params=api_params)

    params = [
        {"name": "param_1", "type": "void *", "position": 0},
        {"name": "param_2", "type": "size_t", "position": 1},
    ]
    names = namer._apply_signature_based_naming("FUN_001", params)

    assert len(names) == 2
    sources = {n.source for n in names}
    assert sources == {"sig_db_params"}, f"Expected sig_db_params, got {sources}"
    # Isimler sig DB'den geldi, API_PARAM_DB'den DEGIL
    semantic_names = {n.semantic_name for n in names}
    assert semantic_names == {"sig_buffer", "sig_length"}
    # Confidence ~ 0.95 * sig_confidence (0.98) = 0.931, clamp <= 0.98
    for n in names:
        assert 0.90 <= n.confidence <= 0.98


def test_semantic_namer_falls_back_to_api_db_when_sig_empty() -> None:
    """sig.params None ise API_PARAM_DB yoluyla isim uretilmeli (0.92 source)."""
    api_params = ["fallback_buffer", "fallback_length"]
    namer, _ = _make_namer_with_sig(sig_params=None, api_params=api_params)

    params = [
        {"name": "param_1", "type": "void *", "position": 0},
        {"name": "param_2", "type": "size_t", "position": 1},
    ]
    names = namer._apply_signature_based_naming("FUN_001", params)

    assert len(names) == 2
    sources = {n.source for n in names}
    assert sources == {"signature_based"}, f"Expected signature_based, got {sources}"
    semantic_names = {n.semantic_name for n in names}
    assert semantic_names == {"fallback_buffer", "fallback_length"}


# ---------------------------------------------------------------------------
# 6. Feature flag off davranisa geri donus
# ---------------------------------------------------------------------------

def test_feature_flag_off_falls_back() -> None:
    """sig_params_enabled=False iken sig.params dolu olsa bile API_PARAM_DB yolu
    kullanilir -- eski (v1.7.2) davranis."""
    cfg = Config()
    cfg.binary_reconstruction.sig_params_enabled = False

    sig_params = [{"name": "should_be_ignored", "type": "int", "index": 0}]
    api_params = ["api_name"]
    namer, _ = _make_namer_with_sig(
        sig_params=sig_params, api_params=api_params, config=cfg,
    )

    params = [{"name": "param_1", "type": "int", "position": 0}]
    names = namer._apply_signature_based_naming("FUN_001", params)

    assert len(names) == 1
    assert names[0].source == "signature_based"
    assert names[0].semantic_name == "api_name"


# ---------------------------------------------------------------------------
# 7. Source attribution -- NameMerger'a giden source literal
# ---------------------------------------------------------------------------

def test_source_attribution_sig_db_params() -> None:
    """Uretilen SemanticName'in source alani tam olarak 'sig_db_params' olmali."""
    sig_params = [{"name": "x", "type": "int", "index": 0}]
    namer, _ = _make_namer_with_sig(sig_params=sig_params, api_params=None)

    params = [{"name": "param_1", "type": "int", "position": 0}]
    names = namer._apply_signature_based_naming("FUN_001", params)

    assert len(names) == 1
    assert names[0].source == "sig_db_params"
    # Priority tablosu da bilmeli
    assert SemanticParameterNamer._STRATEGY_PRIORITY["sig_db_params"] > \
        SemanticParameterNamer._STRATEGY_PRIORITY["signature_based"]
    assert SemanticParameterNamer._BASE_CONFIDENCE["sig_db_params"] > \
        SemanticParameterNamer._BASE_CONFIDENCE["signature_based"]


# ---------------------------------------------------------------------------
# 8. Worker versiyonu ayni davranisi gosterir
# ---------------------------------------------------------------------------

def test_worker_apply_signature_based_uses_sig_db_params() -> None:
    """Worker fonksiyonu da sig_db_params'i API_PARAM_DB'den ONCE denemeli.

    Worker module-global state kullanir; _worker_init ile set ediyoruz.
    """
    sig_params = [
        {"name": "worker_buf", "type": "char *", "index": 0},
    ]
    sm = SignatureMatch(
        original_name="FUN_W",
        matched_name="workerFn",
        library="wlib",
        confidence=0.97,
        match_method="symbol",
        params=sig_params,
    )
    _worker_init(
        func_codes={"FUN_W": "void workerFn(char* param_1) { /* body */ }"},
        functions={"FUN_W": {"params": [{"name": "param_1", "type": "char *", "position": 0}]}},
        func_algorithms={},
        func_domains={"FUN_W": "generic"},
        sig_matches={"FUN_W": sm},
        enriched_structs=None,
        reverse_graph={},
        sig_params_enabled=True,
        sig_params_weight=0.95,
    )
    names = _worker_apply_signature_based(
        "FUN_W",
        [{"name": "param_1", "type": "char *", "position": 0}],
    )
    assert len(names) == 1
    assert names[0].source == "sig_db_params"
    assert names[0].semantic_name == "worker_buf"


# ---------------------------------------------------------------------------
# 9. Ek (saglikli davranis): sig_db_params index olmadan liste sirasiyla eslesir
# ---------------------------------------------------------------------------

def test_sig_db_params_without_index_uses_sequence() -> None:
    """Payload'ta index yoksa liste sirasi (0,1,2,...) kullanilmali."""
    sig_params = [
        {"name": "first", "type": "int"},   # index yok
        {"name": "second", "type": "int"},
    ]
    out = _names_from_sig_db_params_worker(
        func_name="F",
        matched_name="F",
        library="lib",
        sig_confidence=1.0,
        sig_db_params=sig_params,
        params=[
            {"name": "param_1", "type": "int", "position": 0},
            {"name": "param_2", "type": "int", "position": 1},
        ],
        domain="generic",
        base_conf=0.95,
    )
    assert [n.semantic_name for n in out] == ["first", "second"]


# ---------------------------------------------------------------------------
# 10. Ek: non-generic param isimlerine dokunulmaz
# ---------------------------------------------------------------------------

def test_sig_db_params_skips_non_generic_names() -> None:
    """Kullanici-verili (Ghidra-auto olmayan) param ismi varsa yeniden adlandirma
    yapilmaz -- diger stratejilerle tutarlilik."""
    sig_params = [{"name": "should_not_override", "type": "int", "index": 0}]
    out = _names_from_sig_db_params_worker(
        func_name="F",
        matched_name="F",
        library="lib",
        sig_confidence=1.0,
        sig_db_params=sig_params,
        params=[{"name": "user_named_param", "type": "int", "position": 0}],
        domain="generic",
        base_conf=0.95,
    )
    assert out == []
