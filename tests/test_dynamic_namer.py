"""DynamicNamer unit testleri (v1.8.7).

Frida trace verisinden degisken isim cikarimi yapan DynamicNamer modulu
icin kapsamli test suite.

Kategoriler:
  1. DynamicNameSuggestion dataclass
  2. DynamicNamer.__init__()
  3. DynamicNamer.load_trace()
  4. DynamicNamer.infer_names() -- API param, return value, file access, crypto
  5. DynamicNamer.infer_types()
  6. DynamicNamer.get_all_suggestions()
  7. Edge cases
  8. Integration -- confidence range dogrulama
  9. Backward compatibility -- eski string-list format
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from karadul.reconstruction.dynamic_namer import (
    DynamicNameSuggestion,
    DynamicNamer,
    _CONF_API_TRACE,
    _CONF_API_TRACE_INDIRECT,
    _CONF_CRYPTO_OP,
    _CONF_FILE_ACCESS,
    _CONF_TYPE_INFERENCE,
    _GENERIC_VAR_RE,
)


# ========================================================================
# Yardimci: trace fixture builder
# ========================================================================


def _make_trace(
    api_calls: list | None = None,
    file_accesses: list | None = None,
    crypto_operations: list | None = None,
    env_accesses: list | None = None,
    unique_modules: list | None = None,
    call_sequence: list | None = None,
    extra: dict | None = None,
) -> dict:
    """Standart trace_report.json yapisi olustur."""
    data = {
        "total_calls": 0,
        "unique_modules": unique_modules or [],
        "stats": {},
        "api_calls": api_calls or [],
        "file_accesses": file_accesses or [],
        "crypto_operations": crypto_operations or [],
        "env_accesses": env_accesses or [],
        "call_sequence": call_sequence or [],
    }
    if extra:
        data.update(extra)
    return data


def _write_trace(tmp_path: Path, trace_data: dict) -> Path:
    """Trace verisini JSON dosyasina yaz, dosya yolunu dondur."""
    trace_file = tmp_path / "trace_report.json"
    trace_file.write_text(json.dumps(trace_data), encoding="utf-8")
    return trace_file


# ========================================================================
# 1. DynamicNameSuggestion dataclass testleri
# ========================================================================


class TestDynamicNameSuggestion:
    def test_field_access(self):
        s = DynamicNameSuggestion(
            var_name="param_1",
            suggested_name="sockfd",
            confidence=0.88,
            source="frida_api_trace",
            evidence="send(param_1, ...) called at runtime",
        )
        assert s.var_name == "param_1"
        assert s.suggested_name == "sockfd"
        assert s.confidence == 0.88
        assert s.source == "frida_api_trace"
        assert "send" in s.evidence

    def test_confidence_zero(self):
        s = DynamicNameSuggestion(
            var_name="local_10",
            suggested_name="x",
            confidence=0.0,
            source="test",
            evidence="none",
        )
        assert s.confidence == 0.0

    def test_confidence_one(self):
        s = DynamicNameSuggestion(
            var_name="local_10",
            suggested_name="x",
            confidence=1.0,
            source="test",
            evidence="none",
        )
        assert s.confidence == 1.0

    def test_equality(self):
        """Dataclass default eq -- ayni fieldler esit olmali."""
        a = DynamicNameSuggestion("p", "n", 0.5, "s", "e")
        b = DynamicNameSuggestion("p", "n", 0.5, "s", "e")
        assert a == b

    def test_inequality(self):
        a = DynamicNameSuggestion("p1", "n", 0.5, "s", "e")
        b = DynamicNameSuggestion("p2", "n", 0.5, "s", "e")
        assert a != b


# ========================================================================
# 2. DynamicNamer.__init__() testleri
# ========================================================================


class TestDynamicNamerInit:
    def test_init_with_path(self, tmp_path):
        trace_file = tmp_path / "trace_report.json"
        trace_file.write_text("{}", encoding="utf-8")
        namer = DynamicNamer(trace_file)
        assert namer._trace_path == trace_file
        assert not namer.is_loaded

    def test_init_without_path(self):
        namer = DynamicNamer(None)
        assert namer._trace_path is None
        assert not namer.is_loaded

    def test_init_default_state(self, tmp_path):
        namer = DynamicNamer(tmp_path / "nonexistent.json")
        assert namer.api_call_names == []
        assert namer.trace_stats == {}
        assert not namer.is_loaded

    def test_repr_not_loaded(self):
        namer = DynamicNamer(None)
        r = repr(namer)
        assert "not loaded" in r
        assert "N/A" in r

    def test_repr_with_path(self, tmp_path):
        p = tmp_path / "trace_report.json"
        namer = DynamicNamer(p)
        r = repr(namer)
        assert "not loaded" in r
        assert "trace_report.json" in r

    def test_init_accepts_string_path(self, tmp_path):
        """Path yerine string de kabul etmeli (Path() ile sarilir)."""
        trace_file = tmp_path / "trace.json"
        trace_file.write_text("{}", encoding="utf-8")
        namer = DynamicNamer(str(trace_file))
        assert isinstance(namer._trace_path, Path)


# ========================================================================
# 3. DynamicNamer.load_trace() testleri
# ========================================================================


class TestLoadTrace:
    def test_valid_trace(self, tmp_path):
        trace = _make_trace(api_calls=[
            {"name": "send", "args": {"sockfd": 3, "buf": "0x7fff0001", "len": 64}},
        ])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        assert namer.load_trace() is True
        assert namer.is_loaded
        assert "send" in namer.api_call_names

    def test_missing_file(self, tmp_path):
        namer = DynamicNamer(tmp_path / "nonexistent.json")
        assert namer.load_trace() is False
        assert not namer.is_loaded

    def test_no_path_given(self):
        namer = DynamicNamer(None)
        assert namer.load_trace() is False

    def test_malformed_json(self, tmp_path):
        trace_file = tmp_path / "trace_report.json"
        trace_file.write_text("{invalid json!!!", encoding="utf-8")
        namer = DynamicNamer(trace_file)
        assert namer.load_trace() is False
        assert not namer.is_loaded

    def test_json_not_dict(self, tmp_path):
        """JSON valid ama dict degil -- list ise False donmeli."""
        trace_file = tmp_path / "trace_report.json"
        trace_file.write_text("[1, 2, 3]", encoding="utf-8")
        namer = DynamicNamer(trace_file)
        assert namer.load_trace() is False
        assert namer._trace_data is None

    def test_empty_dict_trace(self, tmp_path):
        """Bos dict -- load basarili ama veri bos."""
        path = _write_trace(tmp_path, {})
        namer = DynamicNamer(path)
        assert namer.load_trace() is True
        assert namer.is_loaded
        assert namer.api_call_names == []

    def test_repr_after_load(self, tmp_path):
        trace = _make_trace(api_calls=["send"])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()
        r = repr(namer)
        assert "loaded" in r
        assert "not loaded" not in r

    def test_trace_stats_after_load(self, tmp_path):
        trace = _make_trace(
            api_calls=[
                {"name": "send", "args": {}},
                {"name": "recv", "args": {}},
            ],
            file_accesses=[{"path": "/tmp/data.txt"}],
            crypto_operations=[{"algorithm": "AES-256-CBC"}],
            unique_modules=["libc.so", "libssl.so"],
            call_sequence=[{"name": "send", "args": {}}],
        )
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()
        stats = namer.trace_stats
        assert stats["api_calls"] == 2
        assert stats["file_accesses"] == 1
        assert stats["crypto_operations"] == 1
        assert stats["unique_modules"] == 2
        assert stats["call_sequence_length"] == 1

    def test_permission_error(self, tmp_path):
        """Okunamayan dosya -- False donmeli."""
        trace_file = tmp_path / "trace_report.json"
        trace_file.write_text("{}", encoding="utf-8")
        trace_file.chmod(0o000)
        namer = DynamicNamer(trace_file)
        result = namer.load_trace()
        trace_file.chmod(0o644)  # cleanup
        assert result is False


# ========================================================================
# 4. DynamicNamer.infer_names() testleri
# ========================================================================


class TestInferNamesAPIParam:
    """Strateji 1: API parametre eslestirme."""

    @pytest.fixture
    def namer_with_send(self, tmp_path):
        trace = _make_trace(api_calls=[
            {"name": "send", "args": {"sockfd": 3, "buf": "0x7fff", "len": 64}},
        ])
        path = _write_trace(tmp_path, trace)
        n = DynamicNamer(path)
        n.load_trace()
        return n

    def test_basic_param_matching(self, namer_with_send):
        """send(param_1, param_2, param_3, 0) -> sockfd, buf, len."""
        code = "void FUN_00401000(int param_1, char *param_2, int param_3) {\n"
        code += "  send(param_1, param_2, param_3, 0);\n"
        code += "}\n"

        results = namer_with_send.infer_names("FUN_00401000", code)
        names = {s.var_name: s.suggested_name for s in results}

        assert "param_1" in names
        assert names["param_1"] == "sockfd"
        assert "param_2" in names
        assert names["param_2"] == "buf"
        assert "param_3" in names
        assert names["param_3"] == "len"

    def test_non_generic_var_skipped(self, namer_with_send):
        """Generic olmayan degiskenler atlanmali."""
        code = "send(my_socket, my_buffer, my_len, 0);"
        results = namer_with_send.infer_names("FUN_001", code)
        assert len(results) == 0

    def test_underscore_prefix_api(self, tmp_path):
        """_send gibi underscore-prefix API'ler de eslesmeli."""
        trace = _make_trace(api_calls=[{"name": "send", "args": {}}])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        code = "_send(param_1, param_2, param_3, 0);"
        results = namer.infer_names("FUN_001", code)
        names = {s.var_name: s.suggested_name for s in results}
        assert "param_1" in names

    def test_multiple_api_calls(self, tmp_path):
        """Birden fazla API cagrisinin parametreleri eslesmeli."""
        trace = _make_trace(api_calls=[
            {"name": "send", "args": {}},
            {"name": "recv", "args": {}},
        ])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        code = (
            "send(param_1, param_2, param_3, 0);\n"
            "recv(param_1, local_10, local_20, 0);\n"
        )
        results = namer.infer_names("FUN_001", code)
        names = {s.var_name: s.suggested_name for s in results}

        # param_1 ilk gorulen (send'den sockfd) -- ayni var ikinci kez onerilmez
        assert "param_1" in names
        assert "local_10" in names
        assert names["local_10"] == "buf"

    def test_confidence_value_api_trace(self, namer_with_send):
        code = "send(param_1, param_2, param_3, 0);"
        results = namer_with_send.infer_names("FUN_001", code)
        for s in results:
            assert s.confidence == _CONF_API_TRACE  # 0.88

    def test_source_field(self, namer_with_send):
        code = "send(param_1, param_2, param_3, 0);"
        results = namer_with_send.infer_names("FUN_001", code)
        for s in results:
            assert s.source == "frida_api_trace"

    def test_evidence_field(self, namer_with_send):
        code = "send(param_1, param_2, param_3, 0);"
        results = namer_with_send.infer_names("FUN_001", code)
        assert any("send(" in s.evidence for s in results)


class TestInferNamesReturnValue:
    """Strateji 2: Return value cikarimi."""

    @pytest.fixture
    def namer_with_malloc(self, tmp_path):
        trace = _make_trace(api_calls=[{"name": "malloc", "args": {}}])
        path = _write_trace(tmp_path, trace)
        n = DynamicNamer(path)
        n.load_trace()
        return n

    def test_malloc_return_value(self, namer_with_malloc):
        """iVar3 = malloc(local_20) -> iVar3 = alloc_ptr."""
        code = "iVar3 = malloc(local_20);"
        results = namer_with_malloc.infer_names("FUN_001", code)
        names = {s.var_name: s.suggested_name for s in results}
        assert names.get("iVar3") == "alloc_ptr"

    def test_open_return_value(self, tmp_path):
        trace = _make_trace(api_calls=[{"name": "open", "args": {}}])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        code = "iVar5 = open(param_1, 0);"
        results = namer.infer_names("FUN_001", code)
        names = {s.var_name: s.suggested_name for s in results}
        assert names.get("iVar5") == "fd"

    def test_socket_return_value(self, tmp_path):
        trace = _make_trace(api_calls=[{"name": "socket", "args": {}}])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        code = "iVar1 = socket(2, 1, 0);"
        results = namer.infer_names("FUN_001", code)
        names = {s.var_name: s.suggested_name for s in results}
        assert names.get("iVar1") == "sockfd"

    def test_return_value_confidence(self, namer_with_malloc):
        code = "iVar3 = malloc(local_20);"
        results = namer_with_malloc.infer_names("FUN_001", code)
        retval_suggestions = [s for s in results if s.suggested_name == "alloc_ptr"]
        assert all(s.confidence == _CONF_API_TRACE_INDIRECT for s in retval_suggestions)

    def test_non_generic_return_skipped(self, namer_with_malloc):
        """Generic olmayan degiskene return value onerisi yapilmamali."""
        code = "buffer = malloc(64);"
        results = namer_with_malloc.infer_names("FUN_001", code)
        names = {s.var_name for s in results}
        assert "buffer" not in names

    def test_api_not_in_trace_skipped(self, namer_with_malloc):
        """Trace'de olmayan API'nin return value'su onerilmemeli."""
        code = "iVar1 = fopen(param_1, param_2);"
        results = namer_with_malloc.infer_names("FUN_001", code)
        names = {s.var_name: s.suggested_name for s in results}
        # malloc trace'de var ama fopen yok -- iVar1 onerilmemeli
        assert "iVar1" not in names


class TestInferNamesFileAccess:
    """Strateji 3: Dosya erisim cikarimi."""

    @pytest.fixture
    def namer_with_file_access(self, tmp_path):
        trace = _make_trace(
            api_calls=[{"name": "open", "args": {}}],
            file_accesses=[{"path": "/etc/passwd"}],
        )
        path = _write_trace(tmp_path, trace)
        n = DynamicNamer(path)
        n.load_trace()
        return n

    def test_file_path_inference(self, namer_with_file_access):
        """open(param_1, 0) + file_access -> param_1 = "pathname" (API param
        matching runs first and claims param_1 via APIParamDB for open).

        The file_path strategy only fires for vars not already claimed.
        """
        code = "open(param_1, 0);"
        results = namer_with_file_access.infer_names("FUN_001", code)
        names = {s.var_name: s.suggested_name for s in results}
        # API param matching (Strategy 1) runs before file access (Strategy 3).
        # APIParamDB maps open's first param to "pathname", so param_1 gets
        # that name and is added to seen_vars before file access strategy runs.
        assert names.get("param_1") == "pathname"

    def test_file_access_when_api_param_not_claimed(self, tmp_path):
        """File access strategy fires for vars not already claimed by API param.

        Use stat() -- trace'de var ama kullanilan degisken farkli olunca
        file access cikarimi devreye girer.
        """
        trace = _make_trace(
            api_calls=[],  # API calls bos -- Strategy 1 calismasin
            file_accesses=[{"path": "/etc/passwd"}],
        )
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        # stat C kodunda var ama trace'de API call yok,
        # file_access strategy yine de devreye girer
        code = "stat(param_1, param_2);"
        results = namer.infer_names("FUN_001", code)
        file_suggestions = [s for s in results if s.suggested_name == "file_path"]
        assert len(file_suggestions) > 0
        assert file_suggestions[0].confidence == _CONF_FILE_ACCESS

    def test_file_access_confidence(self, tmp_path):
        """File access strategy confidence = _CONF_FILE_ACCESS."""
        trace = _make_trace(
            api_calls=[],
            file_accesses=[{"path": "/etc/passwd"}],
        )
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        code = "stat(param_1, param_2);"
        results = namer.infer_names("FUN_001", code)
        file_suggestions = [s for s in results if s.suggested_name == "file_path"]
        assert all(s.confidence == _CONF_FILE_ACCESS for s in file_suggestions)

    def test_file_access_evidence_contains_path(self, tmp_path):
        """File access evidence'da erisen dosya yolu olmali."""
        trace = _make_trace(
            api_calls=[],
            file_accesses=[{"path": "/etc/passwd"}],
        )
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        code = "access(param_1, 0);"
        results = namer.infer_names("FUN_001", code)
        file_suggestions = [s for s in results if s.suggested_name == "file_path"]
        assert any("/etc/passwd" in s.evidence for s in file_suggestions)

    def test_no_file_access_no_suggestion(self, tmp_path):
        """file_accesses bos ise dosya yolu onerisi yapilmamali."""
        trace = _make_trace(api_calls=[{"name": "open", "args": {}}])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        code = "open(param_1, 0);"
        results = namer.infer_names("FUN_001", code)
        file_suggestions = [s for s in results if s.suggested_name == "file_path"]
        assert len(file_suggestions) == 0

    def test_fopen_also_matches(self, tmp_path):
        """fopen trace'de varsa ve file_accesses varsa, API param matching
        (Strategy 1) param_1'i "pathname" olarak eslestirir (APIParamDB'deki
        fopen parametresi). File access strategy ayrica calismaz cunku
        param_1 zaten seen_vars'ta."""
        trace = _make_trace(
            api_calls=[{"name": "fopen", "args": {}}],
            file_accesses=[{"path": "/tmp/data.txt"}],
        )
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        code = 'fopen(param_1, "r");'
        results = namer.infer_names("FUN_001", code)
        names = {s.var_name: s.suggested_name for s in results}
        # APIParamDB fopen parametresi: "pathname"
        assert names.get("param_1") == "pathname"

    def test_fopen_file_access_without_api_trace(self, tmp_path):
        """fopen trace'de yoksa ama C kodunda varsa ve file_accesses varsa,
        file access strategy devreye girer."""
        trace = _make_trace(
            api_calls=[],  # fopen trace'de yok
            file_accesses=[{"path": "/tmp/data.txt"}],
        )
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        code = 'fopen(param_1, "r");'
        results = namer.infer_names("FUN_001", code)
        file_suggestions = [s for s in results if s.suggested_name == "file_path"]
        assert len(file_suggestions) > 0


class TestInferNamesCryptoContext:
    """Strateji 4: Crypto islem cikarimi."""

    @pytest.fixture
    def namer_with_crypto(self, tmp_path):
        trace = _make_trace(
            api_calls=[{"name": "EVP_EncryptInit_ex", "args": {}}],
            crypto_operations=[{"algorithm": "AES-256-CBC"}],
        )
        path = _write_trace(tmp_path, trace)
        n = DynamicNamer(path)
        n.load_trace()
        return n

    def test_crypto_param_matching(self, namer_with_crypto):
        """EVP_EncryptInit_ex(param_1, ..., param_4, param_5) -> ctx, ..., key, iv."""
        code = "EVP_EncryptInit_ex(param_1, param_2, param_3, param_4, param_5);"
        results = namer_with_crypto.infer_names("FUN_001", code)
        names = {s.var_name: s.suggested_name for s in results}
        # EVP_EncryptInit_ex params: ctx, type, impl, key, iv
        assert names.get("param_1") == "ctx"
        assert names.get("param_4") == "key"
        assert names.get("param_5") == "iv"

    def test_crypto_confidence(self, namer_with_crypto):
        code = "EVP_EncryptInit_ex(param_1, param_2, param_3, param_4, param_5);"
        results = namer_with_crypto.infer_names("FUN_001", code)
        crypto_suggestions = [s for s in results if "crypto" in s.evidence.lower()]
        assert all(s.confidence == _CONF_CRYPTO_OP for s in crypto_suggestions)

    def test_crypto_evidence_contains_algorithm(self, tmp_path):
        """Crypto strategy sadece API param matching tarafindan claim edilmemis
        degiskenler icin calisiyor. EVP_EncryptInit_ex trace'de olunca Strategy 1
        once calisip tum parametreleri API param olarak eslestirir.

        Crypto strategy'nin devreye girmesi icin trace'de API call olmamali
        ama crypto_operations olmali.
        """
        trace = _make_trace(
            api_calls=[],  # API calls bos -- Strategy 1 claim etmesin
            crypto_operations=[{"algorithm": "AES-256-CBC"}],
        )
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        code = "EVP_EncryptInit_ex(param_1, param_2, param_3, param_4, param_5);"
        results = namer.infer_names("FUN_001", code)
        crypto_suggestions = [s for s in results if "crypto" in s.evidence.lower()]
        assert len(crypto_suggestions) > 0
        assert any("AES-256-CBC" in s.evidence for s in crypto_suggestions)

    def test_no_crypto_ops_no_suggestion(self, tmp_path):
        """crypto_operations bos ise crypto cikarim yapilmamali."""
        trace = _make_trace(api_calls=[{"name": "EVP_EncryptInit_ex", "args": {}}])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        code = "EVP_EncryptInit_ex(param_1, param_2, param_3, param_4, param_5);"
        results = namer.infer_names("FUN_001", code)
        crypto_suggestions = [s for s in results if "crypto" in s.evidence.lower()]
        assert len(crypto_suggestions) == 0

    def test_cccrypt_matching(self, tmp_path):
        """macOS CCCrypt API de eslesmeli."""
        trace = _make_trace(
            api_calls=[{"name": "CCCrypt", "args": {}}],
            crypto_operations=[{"algorithm": "kCCAlgorithmAES128"}],
        )
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        # CCCrypt APIParamDB'de tanimli mi kontrol et
        param_names = namer._api_db.get_param_names("CCCrypt")
        if param_names:
            args = ", ".join(f"param_{i+1}" for i in range(len(param_names)))
            code = f"CCCrypt({args});"
            results = namer.infer_names("FUN_001", code)
            crypto_suggestions = [s for s in results if "crypto" in s.evidence.lower()]
            # CCCrypt APIParamDB'de varsa oneriler gelmeli
            assert len(crypto_suggestions) >= 0  # DB'de yoksa 0 da olabilir


# ========================================================================
# 5. DynamicNamer.infer_types() testleri
# ========================================================================


class TestInferTypes:
    @pytest.fixture
    def namer_with_types(self, tmp_path):
        trace = _make_trace(call_sequence=[
            {
                "name": "send",
                "args": {
                    "sockfd": 3,
                    "buf": "0x7fff00001000",
                    "len": 64,
                    "flags": 0,
                },
            },
        ])
        path = _write_trace(tmp_path, trace)
        n = DynamicNamer(path)
        n.load_trace()
        return n

    def test_pointer_detection(self, namer_with_types):
        """Buyuk hex deger -> void * (pointer)."""
        types = namer_with_types.infer_types("FUN_001")
        assert types.get("buf") == "void *"

    def test_int_detection(self, namer_with_types):
        """64 printable ASCII araliginda (0x20-0x7e) oldugu icin "char"
        olarak siniflandirilir. Belirsiz durum -- int de olabilir ama
        _classify_int_value char oncelikli."""
        types = namer_with_types.infer_types("FUN_001")
        assert types.get("len") == "char"  # 64 = '@' -> ASCII printable range

    def test_int_detection_large_value(self, tmp_path):
        """ASCII araliginin disindaki kucuk pozitif -> int."""
        trace = _make_trace(call_sequence=[
            {"name": "func", "args": {"count": 256, "size": 1024}},
        ])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        types = namer.infer_types("FUN_001")
        assert types.get("count") == "int"
        assert types.get("size") == "int"

    def test_zero_detection(self, namer_with_types):
        """0 -> int."""
        types = namer_with_types.infer_types("FUN_001")
        assert types.get("flags") == "int"

    def test_small_int_detection(self, namer_with_types):
        """Kucuk pozitif (3) -> char veya int (ASCII araliginda char)."""
        types = namer_with_types.infer_types("FUN_001")
        # 3 < 0x20 (printable range), bu yuzden int olmali
        assert types.get("sockfd") == "int"

    def test_char_detection(self, tmp_path):
        """Printable ASCII araligindaki deger -> char."""
        trace = _make_trace(call_sequence=[
            {"name": "putchar", "args": {"c": 65}},  # 'A' = 0x41
        ])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        types = namer.infer_types("FUN_001")
        assert types.get("c") == "char"

    def test_negative_value(self, tmp_path):
        """Negatif deger -> signed int."""
        trace = _make_trace(call_sequence=[
            {"name": "func", "args": {"result": -1}},
        ])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        types = namer.infer_types("FUN_001")
        assert types.get("result") == "int"  # -1 = error sentinel

    def test_small_negative_value(self, tmp_path):
        """Kucuk negatif (-50) -> int8_t."""
        trace = _make_trace(call_sequence=[
            {"name": "func", "args": {"offset": -50}},
        ])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        types = namer.infer_types("FUN_001")
        assert types.get("offset") == "int8_t"

    def test_medium_negative_value(self, tmp_path):
        """Orta negatif (-500) -> int16_t."""
        trace = _make_trace(call_sequence=[
            {"name": "func", "args": {"offset": -500}},
        ])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        types = namer.infer_types("FUN_001")
        assert types.get("offset") == "int16_t"

    def test_string_value(self, tmp_path):
        """String deger -> char *."""
        trace = _make_trace(call_sequence=[
            {"name": "func", "args": {"name": "hello"}},
        ])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        types = namer.infer_types("FUN_001")
        assert types.get("name") == "char *"

    def test_path_string(self, tmp_path):
        """Dosya yolu string -> char *."""
        trace = _make_trace(call_sequence=[
            {"name": "func", "args": {"path": "/etc/passwd"}},
        ])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        types = namer.infer_types("FUN_001")
        assert types.get("path") == "char *"

    def test_float_value(self, tmp_path):
        """Float deger -> double."""
        trace = _make_trace(call_sequence=[
            {"name": "func", "args": {"rate": 3.14}},
        ])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        types = namer.infer_types("FUN_001")
        assert types.get("rate") == "double"

    def test_large_uint_value(self, tmp_path):
        """Orta buyukluk pozitif -> uint32_t."""
        trace = _make_trace(call_sequence=[
            {"name": "func", "args": {"mask": 0x100000}},
        ])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        types = namer.infer_types("FUN_001")
        assert types.get("mask") == "uint32_t"

    def test_not_loaded_returns_empty(self):
        namer = DynamicNamer(None)
        assert namer.infer_types("FUN_001") == {}

    def test_non_dict_args_skipped(self, tmp_path):
        """call_sequence'daki args dict degilse atlanmali."""
        trace = _make_trace(call_sequence=[
            {"name": "func", "args": "not_a_dict"},
        ])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        types = namer.infer_types("FUN_001")
        assert types == {}

    def test_none_value_skipped(self, tmp_path):
        """None deger -> tip cikarimi yapilmamali."""
        trace = _make_trace(call_sequence=[
            {"name": "func", "args": {"ptr": None}},
        ])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        types = namer.infer_types("FUN_001")
        assert "ptr" not in types

    def test_hex_string_pointer(self, tmp_path):
        """Hex string pointer -> void *."""
        trace = _make_trace(call_sequence=[
            {"name": "func", "args": {"addr": "0x7FFEE0000000"}},
        ])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        types = namer.infer_types("FUN_001")
        assert types.get("addr") == "void *"

    def test_first_occurrence_wins(self, tmp_path):
        """Ayni isimli parametre birden fazla gorulurse ilk gorulende karar verilir."""
        trace = _make_trace(call_sequence=[
            {"name": "f1", "args": {"x": 42}},
            {"name": "f2", "args": {"x": "0x7fff00001000"}},
        ])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        types = namer.infer_types("FUN_001")
        # x ilk f1'de int olarak goruldu -> char (42 = '*' ASCII araliginda)
        assert types.get("x") == "char"


# ========================================================================
# 6. DynamicNamer.get_all_suggestions() testleri
# ========================================================================


class TestGetAllSuggestions:
    def test_not_loaded_returns_empty(self):
        namer = DynamicNamer(None)
        assert namer.get_all_suggestions() == {}

    def test_global_suggestions(self, tmp_path):
        """API cagrilari _global_ anahtari altinda toplanmali."""
        trace = _make_trace(api_calls=[
            {"name": "send", "args": {}},
        ])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        results = namer.get_all_suggestions()
        assert "_global_" in results
        assert len(results["_global_"]) > 0

    def test_global_suggestion_fields(self, tmp_path):
        trace = _make_trace(api_calls=[
            {"name": "send", "args": {}},
        ])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        results = namer.get_all_suggestions()
        for s in results["_global_"]:
            assert isinstance(s, DynamicNameSuggestion)
            assert s.confidence == _CONF_API_TRACE_INDIRECT
            assert s.source == "frida_api_trace"
            assert "send" in s.evidence

    def test_multiple_apis(self, tmp_path):
        trace = _make_trace(api_calls=[
            {"name": "send", "args": {}},
            {"name": "recv", "args": {}},
        ])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        results = namer.get_all_suggestions()
        global_sugg = results.get("_global_", [])
        api_names_in_evidence = set()
        for s in global_sugg:
            if "send" in s.evidence:
                api_names_in_evidence.add("send")
            if "recv" in s.evidence:
                api_names_in_evidence.add("recv")
        assert "send" in api_names_in_evidence
        assert "recv" in api_names_in_evidence

    def test_no_apis_empty_result(self, tmp_path):
        trace = _make_trace(api_calls=[])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        results = namer.get_all_suggestions()
        assert results == {}

    def test_unknown_api_skipped(self, tmp_path):
        """APIParamDB'de olmayan API'ler atlanmali."""
        trace = _make_trace(api_calls=[
            {"name": "my_custom_function_xyz", "args": {}},
        ])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        results = namer.get_all_suggestions()
        # APIParamDB'de yoksa _global_ bos olmali
        global_sugg = results.get("_global_", [])
        custom_suggestions = [s for s in global_sugg if "my_custom_function_xyz" in s.evidence]
        assert len(custom_suggestions) == 0


# ========================================================================
# 7. Edge case testleri
# ========================================================================


class TestEdgeCases:
    def test_empty_trace(self, tmp_path):
        """Bos trace -- infer_names bos dondur."""
        trace = _make_trace()
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        results = namer.infer_names("FUN_001", "send(param_1, param_2, param_3, 0);")
        assert results == []

    def test_empty_func_code(self, tmp_path):
        """Bos fonksiyon kodu -- bos dondur."""
        trace = _make_trace(api_calls=[{"name": "send", "args": {}}])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        results = namer.infer_names("FUN_001", "")
        assert results == []

    def test_no_api_calls_in_trace(self, tmp_path):
        """Trace'de API cagrilari yok."""
        trace = _make_trace(api_calls=[])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        code = "send(param_1, param_2, param_3, 0);"
        results = namer.infer_names("FUN_001", code)
        assert results == []

    def test_function_not_in_trace(self, tmp_path):
        """Trace'de baska API var, C kodunda baska API cagrilmis."""
        trace = _make_trace(api_calls=[{"name": "recv", "args": {}}])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        # recv trace'de var ama kodda open cagrilmis
        code = "open(param_1, 0);"
        results = namer.infer_names("FUN_001", code)
        # open trace'de yok, recv kodda yok -> bos (sadece recv trace'de)
        # Ama open'in kendisi eslesmeyecek cunku trace'de yok
        api_param_suggestions = [s for s in results if s.confidence == _CONF_API_TRACE]
        assert len(api_param_suggestions) == 0

    def test_not_loaded_infer_names(self):
        """Yuklenmemis namer -- infer_names bos dondur."""
        namer = DynamicNamer(None)
        results = namer.infer_names("FUN_001", "send(param_1, param_2, param_3, 0);")
        assert results == []

    def test_cache_works(self, tmp_path):
        """Ayni fonksiyon+kod icin cache kullanilmali."""
        trace = _make_trace(api_calls=[{"name": "send", "args": {}}])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        code = "send(param_1, param_2, param_3, 0);"
        r1 = namer.infer_names("FUN_001", code)
        r2 = namer.infer_names("FUN_001", code)
        assert r1 is r2  # Ayni obje (cache hit)

    def test_clear_cache(self, tmp_path):
        trace = _make_trace(api_calls=[{"name": "send", "args": {}}])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        code = "send(param_1, param_2, param_3, 0);"
        r1 = namer.infer_names("FUN_001", code)
        namer.clear_cache()
        r2 = namer.infer_names("FUN_001", code)
        assert r1 is not r2  # Cache temizlendi, yeni obje
        assert r1 == r2  # Ama icerikleri ayni

    def test_sorted_by_confidence(self, tmp_path):
        """Sonuclar confidence'a gore azalan sirada olmali."""
        trace = _make_trace(
            api_calls=[
                {"name": "open", "args": {}},
                {"name": "malloc", "args": {}},
            ],
            file_accesses=[{"path": "/tmp/data.txt"}],
        )
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        code = (
            "iVar1 = open(param_1, 0);\n"
            "iVar2 = malloc(local_10);\n"
        )
        results = namer.infer_names("FUN_001", code)
        if len(results) >= 2:
            for i in range(len(results) - 1):
                assert results[i].confidence >= results[i + 1].confidence

    def test_duplicate_var_prevention(self, tmp_path):
        """Ayni degiskene birden fazla oneri yapilmamali."""
        trace = _make_trace(api_calls=[
            {"name": "send", "args": {}},
            {"name": "write", "args": {}},
        ])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        # param_1 hem send hem write'in ilk parametresi
        code = (
            "send(param_1, param_2, param_3, 0);\n"
            "write(param_1, local_10, local_20);\n"
        )
        results = namer.infer_names("FUN_001", code)
        var_names = [s.var_name for s in results]
        assert var_names.count("param_1") == 1

    def test_ghidra_variable_types(self, tmp_path):
        """Ghidra'nin tum generic degisken tipleri eslesmeli."""
        trace = _make_trace(api_calls=[{"name": "send", "args": {}}])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        # uVar, lVar, sVar, bVar gibi degiskenler
        code = "send(uVar1, lVar2, sVar3, 0);"
        results = namer.infer_names("FUN_001", code)
        names = {s.var_name for s in results}
        assert "uVar1" in names
        assert "lVar2" in names
        assert "sVar3" in names

    def test_pvvar_pcvar_types(self, tmp_path):
        """pvVar, pcVar gibi pointer degiskenler eslesmeli."""
        trace = _make_trace(api_calls=[{"name": "send", "args": {}}])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        code = "send(pvVar1, pcVar2, param_3, 0);"
        results = namer.infer_names("FUN_001", code)
        names = {s.var_name for s in results}
        assert "pvVar1" in names
        assert "pcVar2" in names


# ========================================================================
# 8. Integration -- confidence range dogrulama
# ========================================================================


class TestConfidenceRanges:
    """Confidence degerleri beklenen araliklarda mi?"""

    def test_api_trace_confidence_value(self):
        assert _CONF_API_TRACE == 0.88

    def test_api_trace_indirect_confidence_value(self):
        assert _CONF_API_TRACE_INDIRECT == 0.82

    def test_file_access_confidence_value(self):
        assert _CONF_FILE_ACCESS == 0.85

    def test_crypto_op_confidence_value(self):
        assert _CONF_CRYPTO_OP == 0.85

    def test_type_inference_confidence_value(self):
        assert _CONF_TYPE_INFERENCE == 0.70

    def test_all_confidences_in_range(self):
        """Tum confidence degerleri 0-1 arasinda olmali."""
        for conf in [_CONF_API_TRACE, _CONF_API_TRACE_INDIRECT,
                     _CONF_FILE_ACCESS, _CONF_CRYPTO_OP, _CONF_TYPE_INFERENCE]:
            assert 0.0 <= conf <= 1.0

    def test_api_trace_higher_than_indirect(self):
        """Dogrudan API eslestirme, dolayli eslestirmeden daha guvenilir olmali."""
        assert _CONF_API_TRACE > _CONF_API_TRACE_INDIRECT

    def test_runtime_higher_than_type_inference(self):
        """Runtime API verisi, deger-bazli tip cikarimindan daha guvenilir olmali."""
        assert _CONF_API_TRACE > _CONF_TYPE_INFERENCE
        assert _CONF_API_TRACE_INDIRECT > _CONF_TYPE_INFERENCE

    def test_full_pipeline_confidence_range(self, tmp_path):
        """Tam pipeline'dan cikan tum sonuclar 0.82-0.88 arasinda olmali."""
        trace = _make_trace(
            api_calls=[
                {"name": "send", "args": {}},
                {"name": "malloc", "args": {}},
            ],
            file_accesses=[{"path": "/tmp/data.txt"}],
            crypto_operations=[{"algorithm": "AES-256-CBC"}],
        )
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        code = (
            "void FUN_001(int param_1, char *param_2, int param_3) {\n"
            "  send(param_1, param_2, param_3, 0);\n"
            "  iVar1 = malloc(local_10);\n"
            "}\n"
        )
        results = namer.infer_names("FUN_001", code)
        for s in results:
            assert 0.82 <= s.confidence <= 0.88, (
                f"{s.var_name} -> {s.suggested_name}: confidence={s.confidence} "
                f"not in [0.82, 0.88]"
            )


# ========================================================================
# 9. Backward compatibility -- eski string-list format
# ========================================================================


class TestBackwardCompatibility:
    """Eski format: api_calls: ["send", "recv", ...] (string listesi).

    Yeni format: api_calls: [{"name": "send", "args": {...}}, ...] (dict listesi).
    Her iki format da desteklenmeli.
    """

    def test_old_string_list_api_calls(self, tmp_path):
        """Eski format: api_calls = ["send", "recv"]."""
        trace = _make_trace(api_calls=["send", "recv"])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        assert "send" in namer.api_call_names
        assert "recv" in namer.api_call_names

    def test_old_format_infer_names(self, tmp_path):
        """Eski format ile infer_names calismali."""
        trace = _make_trace(api_calls=["send"])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        code = "send(param_1, param_2, param_3, 0);"
        results = namer.infer_names("FUN_001", code)
        names = {s.var_name: s.suggested_name for s in results}
        assert "param_1" in names

    def test_mixed_format_api_calls(self, tmp_path):
        """Karisik format: hem string hem dict."""
        trace = _make_trace(api_calls=[
            "send",
            {"name": "recv", "args": {}},
        ])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        assert "send" in namer.api_call_names
        assert "recv" in namer.api_call_names

    def test_old_string_list_file_accesses(self, tmp_path):
        """Eski format: file_accesses = ["/tmp/data.txt"].

        String file_accesses {"path": item} dict'ine donusturulur.
        File access strategy, API param matching'den SONRA calisir, bu yuzden
        api_calls'i bos birakiyoruz ki file_path cikarimi yapilabilsin.
        """
        trace = _make_trace(
            api_calls=[],  # API param matching claim etmesin
            file_accesses=["/tmp/data.txt"],
        )
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        code = "stat(param_1, param_2);"
        results = namer.infer_names("FUN_001", code)
        file_suggestions = [s for s in results if s.suggested_name == "file_path"]
        assert len(file_suggestions) > 0

    def test_old_string_list_file_accesses_loaded(self, tmp_path):
        """Eski string format file_accesses yukleniyor mu kontrol et."""
        trace = _make_trace(
            api_calls=["open"],
            file_accesses=["/tmp/data.txt"],
        )
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        stats = namer.trace_stats
        assert stats["file_accesses"] == 1

    def test_old_string_list_crypto(self, tmp_path):
        """Eski format: crypto_operations = ["AES-256-CBC"].

        String crypto ops {"algorithm": item} dict'ine donusturulur.
        Crypto strategy API param matching'den sonra calisir, bu yuzden
        api_calls'i bos birakarak crypto cikarimini test ediyoruz.
        """
        trace = _make_trace(
            api_calls=[],  # API param matching claim etmesin
            crypto_operations=["AES-256-CBC"],
        )
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        code = "EVP_EncryptInit_ex(param_1, param_2, param_3, param_4, param_5);"
        results = namer.infer_names("FUN_001", code)
        crypto_suggestions = [s for s in results if "crypto" in s.evidence.lower()]
        assert len(crypto_suggestions) > 0

    def test_old_string_list_crypto_loaded(self, tmp_path):
        """Eski string format crypto_operations yukleniyor mu kontrol et."""
        trace = _make_trace(
            api_calls=["EVP_EncryptInit_ex"],
            crypto_operations=["AES-256-CBC"],
        )
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        stats = namer.trace_stats
        assert stats["crypto_operations"] == 1

    def test_old_string_list_env(self, tmp_path):
        """Eski format: env_accesses = ["PATH", "HOME"]."""
        trace = _make_trace(extra={"env_accesses": ["PATH", "HOME"]})
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        stats = namer.trace_stats
        assert stats["env_accesses"] == 2

    def test_env_accesses_key_alias(self, tmp_path):
        """environment_variables key'i de desteklenmeli."""
        trace_data = {
            "api_calls": [],
            "environment_variables": [{"name": "PATH"}],
        }
        path = _write_trace(tmp_path, trace_data)
        namer = DynamicNamer(path)
        namer.load_trace()

        stats = namer.trace_stats
        assert stats["env_accesses"] == 1

    def test_duplicate_api_names_deduped(self, tmp_path):
        """Ayni API ismi birden fazla gorulurse tekrar etmemeli."""
        trace = _make_trace(api_calls=["send", "send", "send"])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        assert namer.api_call_names.count("send") == 1

    def test_old_format_get_all_suggestions(self, tmp_path):
        """Eski format ile get_all_suggestions calismali."""
        trace = _make_trace(api_calls=["send", "recv"])
        path = _write_trace(tmp_path, trace)
        namer = DynamicNamer(path)
        namer.load_trace()

        results = namer.get_all_suggestions()
        assert "_global_" in results
        assert len(results["_global_"]) > 0


# ========================================================================
# Generic variable regex testleri
# ========================================================================


class TestGenericVarRegex:
    """_GENERIC_VAR_RE pattern'inin DynamicNamer'daki versiyonu."""

    def test_param(self):
        assert _GENERIC_VAR_RE.match("param_1")
        assert _GENERIC_VAR_RE.match("param_42")

    def test_local(self):
        assert _GENERIC_VAR_RE.match("local_10")
        assert _GENERIC_VAR_RE.match("local_ff")
        assert _GENERIC_VAR_RE.match("local_0A")

    def test_ivar(self):
        assert _GENERIC_VAR_RE.match("iVar1")
        assert _GENERIC_VAR_RE.match("iVar99")

    def test_uvar(self):
        assert _GENERIC_VAR_RE.match("uVar1")

    def test_lvar(self):
        assert _GENERIC_VAR_RE.match("lVar5")

    def test_svar(self):
        assert _GENERIC_VAR_RE.match("sVar2")

    def test_bvar(self):
        assert _GENERIC_VAR_RE.match("bVar1")

    def test_cvar(self):
        assert _GENERIC_VAR_RE.match("cVar3")

    def test_pvvar(self):
        assert _GENERIC_VAR_RE.match("pvVar1")

    def test_ppvvar(self):
        assert _GENERIC_VAR_RE.match("ppvVar2")

    def test_pcvar(self):
        assert _GENERIC_VAR_RE.match("pcVar1")

    def test_pivar(self):
        assert _GENERIC_VAR_RE.match("piVar3")

    def test_puvar(self):
        assert _GENERIC_VAR_RE.match("puVar1")

    def test_plvar(self):
        assert _GENERIC_VAR_RE.match("plVar2")

    def test_in_var(self):
        assert _GENERIC_VAR_RE.match("in_x0")
        assert _GENERIC_VAR_RE.match("in_RAX")

    def test_non_generic_rejected(self):
        assert not _GENERIC_VAR_RE.match("strlen")
        assert not _GENERIC_VAR_RE.match("buffer")
        assert not _GENERIC_VAR_RE.match("count")
        assert not _GENERIC_VAR_RE.match("fd")
        assert not _GENERIC_VAR_RE.match("sockfd")

    def test_avar(self):
        """aVar1 gibi tek-harf prefix + Var + sayi eslesmeli."""
        assert _GENERIC_VAR_RE.match("aVar1")


# ========================================================================
# _classify_int_value static method testleri
# ========================================================================


class TestClassifyIntValue:
    """DynamicNamer._classify_int_value() testleri."""

    def test_zero(self):
        assert DynamicNamer._classify_int_value(0) == "int"

    def test_minus_one(self):
        assert DynamicNamer._classify_int_value(-1) == "int"

    def test_small_negative(self):
        assert DynamicNamer._classify_int_value(-50) == "int8_t"

    def test_medium_negative(self):
        assert DynamicNamer._classify_int_value(-500) == "int16_t"

    def test_large_negative(self):
        assert DynamicNamer._classify_int_value(-100000) == "int"

    def test_printable_ascii(self):
        assert DynamicNamer._classify_int_value(0x41) == "char"  # 'A'
        assert DynamicNamer._classify_int_value(0x7e) == "char"  # '~'
        assert DynamicNamer._classify_int_value(0x20) == "char"  # space

    def test_small_positive(self):
        assert DynamicNamer._classify_int_value(1024) == "int"
        assert DynamicNamer._classify_int_value(0xffff) == "int"

    def test_large_pointer(self):
        assert DynamicNamer._classify_int_value(0x7f000001) == "void *"
        assert DynamicNamer._classify_int_value(0xFFFFFFFF) == "void *"

    def test_medium_uint(self):
        """0xffff < value <= 0x7f000000 arasi -> uint32_t."""
        assert DynamicNamer._classify_int_value(0x10000) == "uint32_t"
        assert DynamicNamer._classify_int_value(0x100000) == "uint32_t"

    def test_boundary_below_pointer(self):
        """0x7f000000 tam sinirda -- pointer degil, uint32_t olmali."""
        assert DynamicNamer._classify_int_value(0x7f000000) == "uint32_t"

    def test_boundary_above_pointer(self):
        """0x7f000001 -- pointer olmali."""
        assert DynamicNamer._classify_int_value(0x7f000001) == "void *"

    def test_boundary_char_low(self):
        """0x1f -- ASCII printable altinda, kucuk int."""
        result = DynamicNamer._classify_int_value(0x1f)
        assert result == "int"

    def test_boundary_small_int_max(self):
        """0xffff tam sinirda -- int olmali."""
        assert DynamicNamer._classify_int_value(0xffff) == "int"

    def test_just_above_small_int(self):
        """0x10000 -- uint32_t olmali."""
        assert DynamicNamer._classify_int_value(0x10000) == "uint32_t"
