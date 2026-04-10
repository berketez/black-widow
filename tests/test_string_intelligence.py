"""StringIntelligence modulu testleri -- Karadul v1.0

4 katman (Assert/Debug, Error Message, Protocol Handler, Telemetry)
icin pattern matching dogruluk testleri.
"""

from __future__ import annotations

import pytest

from karadul.reconstruction.string_intelligence import (
    StringIntelligence,
    StringIntelResult,
    _sanitize_name,
    _is_valid_identifier,
    _verb_noun_to_name,
)


@pytest.fixture
def si() -> StringIntelligence:
    """StringIntelligence instance."""
    return StringIntelligence()


def _make_string(value: str, address: int = 0x1000) -> dict:
    """Test icin string_data dict olustur."""
    return {"address": address, "value": value}


# ---------------------------------------------------------------------------
# Yardimci fonksiyon testleri
# ---------------------------------------------------------------------------

class TestHelpers:
    """Yardimci fonksiyonlarin dogruluugu."""

    def test_sanitize_name_basic(self):
        assert _sanitize_name("hello_world") == "hello_world"

    def test_sanitize_name_special_chars(self):
        assert _sanitize_name("foo::bar") == "foo_bar"

    def test_sanitize_name_leading_digit(self):
        assert _sanitize_name("123abc") == "_123abc"

    def test_sanitize_name_multiple_underscores(self):
        assert _sanitize_name("foo___bar") == "foo_bar"

    def test_sanitize_name_empty(self):
        assert _sanitize_name("") == "unknown"

    def test_is_valid_identifier_ok(self):
        assert _is_valid_identifier("ParseConfig") is True
        assert _is_valid_identifier("my_function") is True

    def test_is_valid_identifier_too_short(self):
        assert _is_valid_identifier("x") is False
        assert _is_valid_identifier("") is False

    def test_is_valid_identifier_generic(self):
        assert _is_valid_identifier("error") is False
        assert _is_valid_identifier("data") is False
        assert _is_valid_identifier("true") is False

    def test_verb_noun_to_name(self):
        assert _verb_noun_to_name("initialize", "renderer") == "initialize_renderer"
        assert _verb_noun_to_name("Open", "Database") == "open_database"


# ---------------------------------------------------------------------------
# Katman A: Assert/Debug Pattern Testleri
# ---------------------------------------------------------------------------

class TestAssertDebug:
    """Katman A: Assert/Debug string parsing."""

    def test_glibc_assert_with_function(self, si: StringIntelligence):
        """glibc-style: 'prog: file.c:10: my_func: Assertion `x > 0` failed.'"""
        s = _make_string("myapp: utils.c:42: parse_config: Assertion `cfg != NULL` failed.")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "parse_config" in names
        # Confidence 0.80+ olmali
        for r in results:
            if r.name == "parse_config":
                assert r.confidence >= 0.80
                assert r.pattern_type == "assert"

    def test_glibc_assert_class_method(self, si: StringIntelligence):
        """glibc-style: '... CSocket::Connect: Assertion ...'"""
        s = _make_string("app: net.cpp:99: CSocket::Connect: Assertion `sock >= 0` failed.")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        # Class ve method cikarilmis olmali
        assert any("CSocket" in n for n in names)

    def test_file_line_func_assertion(self, si: StringIntelligence):
        """file:line:Class::Method: assertion failed"""
        s = _make_string("renderer.cpp:123: MyRenderer::Initialize: assertion failed")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert any("MyRenderer" in n for n in names)
        assert any("Initialize" in n for n in names)

    def test_qt_assert(self, si: StringIntelligence):
        """Qt Q_ASSERT_X style"""
        s = _make_string("ASSERT: 'buffer != nullptr' in file widget.cpp, line 55 function QWidget::paintEvent")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert any("QWidget" in n for n in names)

    def test_boost_assert(self, si: StringIntelligence):
        """Boost BOOST_ASSERT style"""
        s = _make_string("Boost.Assert failure in function 'NetworkManager::SendPacket'")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert any("NetworkManager" in n for n in names)

    def test_pretty_function_macro(self, si: StringIntelligence):
        """__PRETTY_FUNCTION__ kalintisi"""
        s = _make_string("void AudioEngine::ProcessBuffer(int, float*)")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert any("AudioEngine" in n for n in names)

    def test_assert_call_expression(self, si: StringIntelligence):
        """assert(obj->Initialize()) icindeki fonksiyon"""
        s = _make_string("assert(pManager->Initialize(")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "Initialize" in names

    def test_windows_assertion(self, si: StringIntelligence):
        """Windows-style assertion"""
        s = _make_string("Assertion failed: ValidateInput")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "ValidateInput" in names

    def test_assert_confidence_range(self, si: StringIntelligence):
        """Assert pattern'lerinin confidence araligi 0.80-0.95"""
        strings = [
            _make_string("file.c:10: my_func: Assertion `x` failed."),
            _make_string("void MyClass::Method(int)"),
        ]
        results = si.analyze_strings(strings)
        for r in results:
            if r.pattern_type == "assert":
                assert 0.80 <= r.confidence <= 0.95, \
                    f"{r.name}: confidence {r.confidence} disinda"


# ---------------------------------------------------------------------------
# Katman B: Error Message Pattern Testleri
# ---------------------------------------------------------------------------

class TestErrorMessages:
    """Katman B: Error message pattern matching."""

    def test_error_in_func(self, si: StringIntelligence):
        """'Error in ParseConfig: invalid format'"""
        s = _make_string("Error in ParseConfig: invalid format")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "ParseConfig" in names

    def test_class_method_failed(self, si: StringIntelligence):
        """'CSocket::Connect failed'"""
        s = _make_string("CSocket::Connect failed with error 10061")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        types = {r.name: r.target_type for r in results}
        assert "CSocket_Connect" in names
        assert "CSocket" in names
        assert types.get("CSocket") == "class"

    def test_log_prefix_class(self, si: StringIntelligence):
        """'[ERROR] AudioManager: buffer underrun'"""
        s = _make_string("[ERROR] AudioManager: buffer underrun detected")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "AudioManager" in names
        # Class olarak tanimlanmis olmali
        for r in results:
            if r.name == "AudioManager":
                assert r.target_type == "class"

    def test_log_prefix_warning(self, si: StringIntelligence):
        """'[WARNING] RenderEngine: ...'"""
        s = _make_string("[WARNING] RenderEngine: frame drop detected")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "RenderEngine" in names

    def test_failed_to_verb_noun(self, si: StringIntelligence):
        """'Failed to initialize renderer'"""
        s = _make_string("Failed to initialize renderer")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "initialize_renderer" in names

    def test_cannot_verb_noun(self, si: StringIntelligence):
        """'Cannot open database'"""
        s = _make_string("Cannot open database connection")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "open_database" in names

    def test_unable_to_verb_noun(self, si: StringIntelligence):
        """'Unable to parse configuration'"""
        s = _make_string("Unable to parse configuration file")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "parse_configuration" in names

    def test_class_method_returned(self, si: StringIntelligence):
        """'MyClass::Init() returned error'"""
        s = _make_string("MyClass::Init() returned error code 5")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "MyClass_Init" in names

    def test_class_error(self, si: StringIntelligence):
        """'NetworkManager error: connection reset'"""
        s = _make_string("NetworkManager error: connection reset by peer")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "NetworkManager" in names

    def test_snake_func_error(self, si: StringIntelligence):
        """'process_input: error reading buffer'"""
        s = _make_string("process_input: error reading buffer from stream")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "process_input" in names

    def test_error_confidence_range(self, si: StringIntelligence):
        """Error pattern'lerinin confidence araligi 0.60-0.85"""
        strings = [
            _make_string("Error in ParseConfig: bad"),
            _make_string("CSocket::Connect failed"),
            _make_string("[WARNING] AudioMgr: x"),
        ]
        results = si.analyze_strings(strings)
        for r in results:
            if r.pattern_type == "error_msg":
                assert 0.60 <= r.confidence <= 0.85, \
                    f"{r.name}: confidence {r.confidence} disinda"


# ---------------------------------------------------------------------------
# Katman C: Protocol/Message Handler Testleri
# ---------------------------------------------------------------------------

class TestProtocolHandlers:
    """Katman C: Protocol/message handler naming."""

    def test_steam_emsg(self, si: StringIntelligence):
        """k_EMsgClientLogon -> HandleClientLogon"""
        s = _make_string("Processing message k_EMsgClientLogon from peer")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "HandleClientLogon" in names

    def test_steam_emsg_gs(self, si: StringIntelligence):
        """k_EMsgGSStatusReply -> HandleGSStatusReply"""
        s = _make_string("Received k_EMsgGSStatusReply")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "HandleGSStatusReply" in names

    def test_msg_type_enum(self, si: StringIntelligence):
        """MSG_LOGIN -> Handler_Login"""
        s = _make_string("Handling MSG_LOGIN from client")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "Handler_Login" in names

    def test_msg_type_heartbeat(self, si: StringIntelligence):
        """MSG_HEARTBEAT -> Handler_Heartbeat"""
        s = _make_string("Sending MSG_HEARTBEAT to server")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "Handler_Heartbeat" in names

    def test_grpc_service(self, si: StringIntelligence):
        """'/com.example.UserService/GetUser' -> UserService_GetUser"""
        s = _make_string("/com.example.UserService/GetUser")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "UserService_GetUser" in names

    def test_http_route(self, si: StringIntelligence):
        """HTTP route string"""
        s = _make_string('"/api/v1/users/create"')
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert any("handle_api" in n for n in names)

    def test_com_interface(self, si: StringIntelligence):
        """IDirectSound::CreateSoundBuffer"""
        s = _make_string("IDirectSound::CreateSoundBuffer failed")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert any("IDirectSound" in n for n in names)

    def test_windows_message(self, si: StringIntelligence):
        """WM_CREATE -> OnCreate"""
        s = _make_string("Processing WM_CREATE message")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "OnCreate" in names

    def test_windows_message_paint(self, si: StringIntelligence):
        """WM_PAINT -> OnPaint"""
        s = _make_string("Handling WM_PAINT")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "OnPaint" in names

    def test_dbus_method(self, si: StringIntelligence):
        """org.freedesktop.NetworkManager.GetDevices"""
        s = _make_string("Calling org.freedesktop.NetworkManager.GetDevices")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert any("GetDevices" in n for n in names)

    def test_protocol_confidence_range(self, si: StringIntelligence):
        """Protocol pattern'lerinin confidence araligi 0.70-0.90"""
        strings = [
            _make_string("k_EMsgClientLogon"),
            _make_string("/svc.Test/Method"),
            _make_string("WM_CREATE"),
        ]
        results = si.analyze_strings(strings)
        for r in results:
            if r.pattern_type == "protocol":
                assert 0.70 <= r.confidence <= 0.90, \
                    f"{r.name}: confidence {r.confidence} disinda"


# ---------------------------------------------------------------------------
# Katman D: Telemetry/Analytics Event Testleri
# ---------------------------------------------------------------------------

class TestTelemetryEvents:
    """Katman D: Telemetry/analytics event naming."""

    def test_track_event(self, si: StringIntelligence):
        """TrackEvent('page_load') -> track_page_load"""
        s = _make_string("TrackEvent('page_load')")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "track_page_load" in names

    def test_analytics_log_event(self, si: StringIntelligence):
        """analytics.logEvent('user_login') -> log_user_login"""
        s = _make_string("analytics.logEvent('user_login')")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "log_user_login" in names

    def test_metrics_track(self, si: StringIntelligence):
        """metrics.track('purchase_complete')"""
        s = _make_string("metrics.track('purchase_complete')")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert any("purchase_complete" in n for n in names)

    def test_telemetry_send(self, si: StringIntelligence):
        """telemetry.send('session_start')"""
        s = _make_string("telemetry.send('session_start')")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert any("session_start" in n for n in names)

    def test_metric_tag(self, si: StringIntelligence):
        """[metric] render_time_ms -> measure_render_time_ms"""
        s = _make_string("[metric] render_time_ms")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "measure_render_time_ms" in names

    def test_perf_tag(self, si: StringIntelligence):
        """[perf] frame_duration"""
        s = _make_string("[perf] frame_duration")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "measure_frame_duration" in names

    def test_event_constant(self, si: StringIntelligence):
        """EVENT_USER_LOGIN -> handle_user_login"""
        s = _make_string("Logging EVENT_USER_LOGIN")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "handle_user_login" in names

    def test_breadcrumb(self, si: StringIntelligence):
        """breadcrumb:checkout_started"""
        s = _make_string("breadcrumb:checkout_started")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert any("checkout_started" in n for n in names)

    def test_telemetry_confidence_range(self, si: StringIntelligence):
        """Telemetry pattern'lerinin confidence araligi 0.65-0.80"""
        strings = [
            _make_string("TrackEvent('page_load')"),
            _make_string("[metric] render_time_ms"),
            _make_string("EVENT_USER_LOGIN"),
        ]
        results = si.analyze_strings(strings)
        for r in results:
            if r.pattern_type == "telemetry":
                assert 0.65 <= r.confidence <= 0.80, \
                    f"{r.name}: confidence {r.confidence} disinda"


# ---------------------------------------------------------------------------
# Entegrasyon / genel testler
# ---------------------------------------------------------------------------

class TestIntegration:
    """Genel entegrasyon testleri."""

    def test_empty_strings(self, si: StringIntelligence):
        """Bos string listesinde hata vermez."""
        results = si.analyze_strings([])
        assert results == []

    def test_short_strings_skipped(self, si: StringIntelligence):
        """4 karakterden kisa string'ler atlanir."""
        results = si.analyze_strings([_make_string("abc")])
        assert results == []

    def test_results_sorted_by_confidence(self, si: StringIntelligence):
        """Sonuclar confidence'a gore buyukten kucuge sirali."""
        strings = [
            _make_string("Error in ParseConfig: bad"),                     # 0.82
            _make_string("void AudioEngine::ProcessBuffer(int, float*)"),  # 0.93
            _make_string("[metric] render_time_ms"),                        # 0.72
        ]
        results = si.analyze_strings(strings)
        if len(results) >= 2:
            for i in range(len(results) - 1):
                assert results[i].confidence >= results[i + 1].confidence

    def test_deduplicate_same_name(self, si: StringIntelligence):
        """Ayni isim farkli string'lerden cikarsa en yuksek confidence tutulur."""
        strings = [
            # Hem assert'ten hem error'dan "ParseConfig" cikabilir
            _make_string("file.c:10: ParseConfig: Assertion `x` failed."),
            _make_string("Error in ParseConfig: invalid"),
        ]
        results = si.analyze_strings(strings)
        # ParseConfig + function olarak sadece bir kez olmali
        parse_configs = [r for r in results if r.name == "ParseConfig" and r.target_type == "function"]
        assert len(parse_configs) == 1
        # Assert'ten gelen daha yuksek confidence'a sahip olmali
        assert parse_configs[0].confidence >= 0.82

    def test_multiple_patterns_same_string(self, si: StringIntelligence):
        """Bir string birden fazla pattern'e uyabilir."""
        s = _make_string("CSocket::Connect failed with MSG_LOGIN")
        results = si.analyze_strings([s])
        pattern_types = {r.pattern_type for r in results}
        # Hem error_msg hem protocol yakalamis olmali
        assert "error_msg" in pattern_types
        assert "protocol" in pattern_types

    def test_get_function_name_suggestions(self, si: StringIntelligence):
        """get_function_name_suggestions xref-based filtreleme yapar."""
        strings = [
            {"address": 0x1000, "value": "Error in ParseConfig: bad", "xrefs": [0xAA]},
            {"address": 0x2000, "value": "Error in SendPacket: timeout", "xrefs": [0xBB]},
        ]
        results = si.get_function_name_suggestions(0xAA, strings)
        names = [r.name for r in results]
        assert "ParseConfig" in names
        # SendPacket bu fonksiyona ait degil, olmamali
        assert "SendPacket" not in names

    def test_result_dataclass_fields(self, si: StringIntelligence):
        """StringIntelResult'in tum alanlari dogru doluyor."""
        s = _make_string("CSocket::Connect failed", address=0x4567)
        results = si.analyze_strings([s])
        assert len(results) > 0
        r = results[0]
        assert isinstance(r.name, str)
        assert isinstance(r.confidence, float)
        assert isinstance(r.source_string, str)
        assert isinstance(r.pattern_type, str)
        assert isinstance(r.target_type, str)
        assert r.address == 0x4567

    def test_no_false_positives_on_generic(self, si: StringIntelligence):
        """Genel kelimeler (error, data, value) fonksiyon ismi olarak dondurulmemeli."""
        strings = [
            _make_string("An error occurred during processing"),
            _make_string("Invalid data format"),
            _make_string("The value is out of range"),
        ]
        results = si.analyze_strings(strings)
        bad_names = {"error", "data", "value", "result", "status", "code", "type"}
        for r in results:
            assert r.name not in bad_names, \
                f"False positive: '{r.name}' should not be extracted"

    def test_xrefs_parameter(self, si: StringIntelligence):
        """xrefs dict parametresi calisiyor."""
        strings = [
            {"address": 0x1000, "value": "Error in ParseConfig: bad"},
        ]
        xrefs = {0x1000: [0xAA, 0xBB]}
        results = si.get_function_name_suggestions(0xAA, strings, xrefs=xrefs)
        names = [r.name for r in results]
        assert "ParseConfig" in names


# ---------------------------------------------------------------------------
# Katman E: API Name String Detection Testleri
# ---------------------------------------------------------------------------

class TestApiNameStrings:
    """Katman E: API name string detection."""

    def test_exact_api_name_sqlite3(self, si: StringIntelligence):
        """Tam sqlite3 API ismi: 'sqlite3_open'"""
        s = _make_string("sqlite3_open")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "sqlite3_open" in names
        # Known prefix -> yuksek confidence
        for r in results:
            if r.name == "sqlite3_open":
                assert r.confidence >= 0.88
                assert r.pattern_type == "api_name"

    def test_exact_api_name_generic(self, si: StringIntelligence):
        """Genel API ismi: 'compression_stream_init'"""
        s = _make_string("compression_stream_init")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "compression_stream_init" in names
        for r in results:
            if r.name == "compression_stream_init":
                assert r.confidence >= 0.80
                assert r.pattern_type == "api_name"

    def test_exact_api_name_sha3(self, si: StringIntelligence):
        """'sha3_query' -- kisa ama gecerli API ismi."""
        s = _make_string("sha3_query")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "sha3_query" in names

    def test_exact_api_name_with_prefix(self, si: StringIntelligence):
        """Bilinen kutuphane prefix'i: 'curl_easy_init'"""
        s = _make_string("curl_easy_init")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "curl_easy_init" in names
        for r in results:
            if r.name == "curl_easy_init":
                assert r.confidence == 0.90  # Known prefix

    def test_embedded_api_call(self, si: StringIntelligence):
        """API ismi parantez ile: 'sqlite3_close() returns %d'"""
        s = _make_string("Error: sqlite3_close() returns %d: %s")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "sqlite3_close" in names
        for r in results:
            if r.name == "sqlite3_close":
                assert r.pattern_type == "api_name"
                assert r.confidence >= 0.80

    def test_embedded_api_get_table(self, si: StringIntelligence):
        """'sqlite3_get_table() called with two or more...'"""
        s = _make_string("sqlite3_get_table() called with two or more incompatible queries")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "sqlite3_get_table" in names

    def test_api_prefix_message(self, si: StringIntelligence):
        """API ismi message prefix'i: 'sqlite3_expert_new: %s'"""
        s = _make_string("sqlite3_expert_new: %s\n")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "sqlite3_expert_new" in names

    def test_embedded_api_error(self, si: StringIntelligence):
        """Embedded API + error words: 'sqlite3_open_v2 open failed with %d'"""
        s = _make_string("sqlite3_open_v2 open failed with %d")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "sqlite3_open_v2" in names

    def test_no_false_positive_on_common_strings(self, si: StringIntelligence):
        """Genel string'ler API ismi olarak yakalanmamali."""
        false_positives = [
            "read_only",
            "utf_8",
            "big_endian",
            "file_name",
        ]
        for fp_val in false_positives:
            results = si.analyze_strings([_make_string(fp_val)])
            names = [r.name for r in results if r.pattern_type == "api_name"]
            assert fp_val not in [n.name for n in results if n.pattern_type == "api_name"], \
                f"False positive: '{fp_val}' should not be extracted as API name"

    def test_short_two_letter_parts_skipped(self, si: StringIntelligence):
        """Cok kisa parcali isimler (or: 'a_b') atlanir."""
        s = _make_string("to_do")
        results = si.analyze_strings([s])
        api_results = [r for r in results if r.pattern_type == "api_name"]
        assert len(api_results) == 0

    def test_api_name_confidence_range(self, si: StringIntelligence):
        """API name pattern'lerinin confidence araligi 0.55-0.90"""
        strings = [
            _make_string("sqlite3_open"),          # known prefix -> 0.90
            _make_string("my_custom_func"),         # generic -> 0.85
            _make_string("sqlite3_close() returns"),  # call pattern -> 0.88
        ]
        results = si.analyze_strings(strings)
        for r in results:
            if r.pattern_type == "api_name":
                assert 0.55 <= r.confidence <= 0.90, \
                    f"{r.name}: confidence {r.confidence} disinda"

    def test_multiple_api_names_in_function(self, si: StringIntelligence):
        """Bir fonksiyonun referans ettigi birden fazla API ismi."""
        strings = [
            _make_string("sqlar_compress"),
            _make_string("sqlar_uncompress"),
        ]
        results = si.analyze_strings(strings)
        names = [r.name for r in results]
        assert "sqlar_compress" in names
        assert "sqlar_uncompress" in names

    def test_long_string_with_embedded_api(self, si: StringIntelligence):
        """Uzun error mesajinda gomulu API ismi."""
        s = _make_string(
            "sqlite3_deserialize() returned error code while trying to load database"
        )
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "sqlite3_deserialize" in names

    def test_fts3_tokenizer(self, si: StringIntelligence):
        """FTS3 tokenizer: 'fts3_tokenizer'"""
        s = _make_string("fts3_tokenizer")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "fts3_tokenizer" in names
        for r in results:
            if r.name == "fts3_tokenizer":
                assert r.confidence == 0.90  # fts3_ is known prefix

    def test_generate_series(self, si: StringIntelligence):
        """'generate_series' -- generic API name."""
        s = _make_string("generate_series")
        results = si.analyze_strings([s])
        names = [r.name for r in results]
        assert "generate_series" in names
