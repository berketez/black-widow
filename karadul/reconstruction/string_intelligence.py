"""Advanced string intelligence for binary name recovery -- Karadul v1.0

Analyzes strings found in binaries to extract function names, class names,
and variable names through pattern matching on debug messages, error strings,
protocol definitions, and telemetry events.

5 Katman:
  A. Assert/Debug String Parser   (conf 0.80-0.95) -- assert(), __func__, Q_ASSERT, BOOST_ASSERT
  B. Error Message Pattern Match   (conf 0.60-0.85) -- "Error in X:", "X::Y failed", log prefixes
  C. Protocol/Message Handler      (conf 0.70-0.90) -- k_EMsg, MSG_TYPE, gRPC, HTTP routes
  D. Telemetry/Analytics Events    (conf 0.65-0.80) -- TrackEvent, analytics.log, [metric]
  E. API Name String Detection     (conf 0.55-0.90) -- Strings that ARE function names or contain
     embedded API names (e.g. "sqlite3_open", "compression_stream_init",
     "sqlite3_open_v2 open failed with %d")

Kullanim:
    from karadul.reconstruction.string_intelligence import StringIntelligence

    si = StringIntelligence()
    results = si.analyze_strings(strings_data)
    for r in results:
        print(f"{r.name} ({r.target_type}) conf={r.confidence:.2f} from '{r.source_string[:60]}'")

Entegrasyon:
    BinaryNameExtractor.extract() icinde 5. strateji olarak cagrilir.
    Sonuclar ExtractedName'e donusturulup mevcut merge pipeline'ina beslenir.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Sonuc veri yapisi
# ---------------------------------------------------------------------------

@dataclass
class StringIntelResult:
    """A name extracted from string analysis."""

    name: str               # Kurtarilan isim (ornek: "ParseConfig", "CSocket_Connect")
    confidence: float        # 0.0-1.0
    source_string: str       # Ismin cikarildig? kaynak string
    pattern_type: str        # "assert", "error_msg", "protocol", "telemetry"
    target_type: str         # "function", "class", "method", "variable"
    address: int = 0         # String adresi (xref ile fonksiyon eslestirme icin)
    class_name: str = ""     # Ait oldugu class (varsa)
    method_name: str = ""    # Method ismi (varsa)


# ---------------------------------------------------------------------------
# Yardimci fonksiyonlar
# ---------------------------------------------------------------------------

def _sanitize_name(name: str) -> str:
    """C/C++ identifier kurallarina uygun isim uret."""
    sanitized = re.sub(r'[^A-Za-z0-9_]', '_', name)
    sanitized = re.sub(r'_+', '_', sanitized)
    sanitized = sanitized.strip('_')
    # Basa sayi gelemez -- strip sonrasi kontrol et
    if sanitized and sanitized[0].isdigit():
        sanitized = '_' + sanitized
    return sanitized or 'unknown'


def _verb_noun_to_name(verb: str, noun: str) -> str:
    """'initialize' + 'renderer' -> 'initialize_renderer'"""
    v = verb.lower().strip()
    n = noun.lower().strip()
    return _sanitize_name(f"{v}_{n}")


def _is_valid_identifier(name: str) -> bool:
    """Cikarilan ismin gecerli ve anlamli olup olmadigini kontrol et."""
    if not name or len(name) < 2:
        return False
    # Sadece sayi veya underscore degilse
    if re.match(r'^[_0-9]+$', name):
        return False
    # Cok genel kelimeler (false positive kaynagi)
    too_generic = {
        'error', 'warning', 'info', 'debug', 'failed', 'success',
        'true', 'false', 'null', 'none', 'invalid', 'unknown',
        'the', 'and', 'for', 'not', 'this', 'that', 'with',
        'data', 'value', 'result', 'status', 'code', 'type',
    }
    if name.lower() in too_generic:
        return False
    return True


# ---------------------------------------------------------------------------
# Pattern tanimlari -- her katman icin ayri
# ---------------------------------------------------------------------------

# ==================== KATMAN A: Assert/Debug ====================

# Standart C assert: "file.cpp:123: MyClass::MyMethod: Assertion `expr` failed."
_ASSERT_FILE_LINE_FUNC_RE = re.compile(
    r'[\w./\\]+\.(?:cpp|cc|c|h|hpp|cxx|mm):\d+:\s*'  # dosya:satir:
    r'(\w+(?:::\w+)*)'                                  # fonksiyon/class::method
    r':\s*(?:Assertion|assertion)',
    re.IGNORECASE,
)

# glibc-style assert: "prog: file.c:10: func_name: Assertion `...` failed."
_GLIBC_ASSERT_RE = re.compile(
    r':\s*(\w+(?:::\w+)*)\s*:\s*Assertion\s+[`\'"](.*?)[`\'"]',
)

# Qt Q_ASSERT / Q_ASSERT_X: "ASSERT: 'condition' in file ..., line ... function ..."
_QT_ASSERT_RE = re.compile(
    r'(?:Q_ASSERT|ASSERT)(?:_X)?.*?function\s+(\w+(?:::\w+)*)',
    re.IGNORECASE,
)

# Boost BOOST_ASSERT: "Boost.Assert failure in ... function '...'"
_BOOST_ASSERT_RE = re.compile(
    r'(?:BOOST_ASSERT|boost[.:]Assert|boost::assertion).*?function\s+[\'"]?(\w+(?:::\w+)*)',
    re.IGNORECASE,
)

# __func__ / __FUNCTION__ / __PRETTY_FUNCTION__ macro kalintilari
# Bunlar binary'de string olarak kalabilir: "void MyClass::MyMethod(int)"
_PRETTY_FUNCTION_RE = re.compile(
    r'(?:void|int|bool|char|unsigned|long|float|double|auto|const)\s+'
    r'(\w+(?:::\w+)+)\s*\(',
)

# Assertion expression icinde fonksiyon/method ismi
# "assert(myObj->Initialize())" -> Initialize
_ASSERT_CALL_RE = re.compile(
    r'(?:assert|ASSERT|Assert|CHECK|DCHECK|VERIFY)\s*\(\s*'
    r'(?:\w+(?:->|\.))?\s*(\w{3,})\s*\(',
    re.IGNORECASE,
)

# Windows-style assert: "Assertion failed: expr, file ..., line ..."
_WIN_ASSERT_RE = re.compile(
    r'Assertion\s+failed:\s*(\w+(?:::\w+)*)',
    re.IGNORECASE,
)


# ==================== KATMAN B: Error Message ====================

# "Error in ParseConfig: ..." -> fonksiyon: ParseConfig
_ERROR_IN_FUNC_RE = re.compile(
    r'(?:Error|error|ERROR)\s+in\s+(\w{3,})(?:\s*[:(])',
)

# "CSocket::Connect failed" -> class: CSocket, method: Connect
_CLASS_METHOD_FAILED_RE = re.compile(
    r'(\w{2,})::(\w{2,})\s+(?:failed|error|invalid|timeout|exception|aborted|refused)',
    re.IGNORECASE,
)

# "[ERROR] AudioManager: buffer underrun" -> class: AudioManager
_LOG_PREFIX_CLASS_RE = re.compile(
    r'\[(?:ERROR|WARNING|WARN|INFO|DEBUG|FATAL|CRITICAL|TRACE|VERBOSE)\]\s+'
    r'(\w{3,})\s*[:\-]',
    re.IGNORECASE,
)

# "Failed to initialize renderer" -> initialize_renderer
_FAILED_TO_VERB_NOUN_RE = re.compile(
    r'[Ff]ailed\s+to\s+(\w{3,})\s+(\w{3,})',
)

# "Cannot open database" -> open_database
_CANNOT_VERB_NOUN_RE = re.compile(
    r'[Cc]annot\s+(\w{3,})\s+(\w{3,})',
)

# "Unable to parse configuration" -> parse_configuration
_UNABLE_TO_VERB_NOUN_RE = re.compile(
    r'[Uu]nable\s+to\s+(\w{3,})\s+(\w{3,})',
)

# "MyClass::Initialize() returned error" -> class: MyClass, method: Initialize
_CLASS_METHOD_RETURNED_RE = re.compile(
    r'(\w{2,})::(\w{2,})\s*\(\)\s*(?:returned|threw|raised)',
    re.IGNORECASE,
)

# "<ClassName> error: ..." veya "<ClassName>: error ..."
_CLASS_ERROR_RE = re.compile(
    r'(\b[A-Z][A-Za-z0-9]{2,})\s*(?:error|Error|ERROR)\s*[:\-]',
)

# "function_name: error message" (snake_case function)
_SNAKE_FUNC_ERROR_RE = re.compile(
    r'(\b[a-z][a-z0-9_]{4,})\s*:\s*(?:error|failed|invalid|cannot|unable)',
    re.IGNORECASE,
)


# ==================== KATMAN C: Protocol/Message Handler ====================

# Steam k_EMsg style: k_EMsgClientLogon -> HandleClientLogon
_STEAM_EMSG_RE = re.compile(
    r'\b(k_EMsg\w{3,})\b',
)

# Generic MSG_TYPE enum: MSG_LOGIN, MSG_HEARTBEAT -> Handler_Login
_MSG_TYPE_ENUM_RE = re.compile(
    r'\b(MSG_[A-Z][A-Z0-9_]{2,})\b',
)

# Protocol buffer / gRPC service method: "/package.Service/MethodName"
# Requires at least one dot in the service path to avoid matching filesystem paths
# like "/usr/lib" (which has no dots in the path components).
_GRPC_SERVICE_RE = re.compile(
    r'/(\w+\.\w+(?:\.\w+)*)/([\w]+)',
)

# HTTP route string: "/api/v1/users" -> handle_api_v1_users
_HTTP_ROUTE_RE = re.compile(
    r'["\']/(api|v\d+|auth|admin|user|health|status|config|internal)'
    r'(?:/[\w]+){0,5}["\']',
)

# HTTP route extraction (daha genel): bir path string'i
_HTTP_PATH_EXTRACT_RE = re.compile(
    r'/((?:api|v\d+|auth|admin|internal)/[\w/]+)',
)

# COM/DCOM interface method: "IMyInterface::Method"
_COM_INTERFACE_RE = re.compile(
    r'\b(I[A-Z][A-Za-z0-9]+)::([\w]+)',
)

# Windows message handler: WM_CREATE, WM_PAINT, WM_COMMAND
_WIN_MSG_RE = re.compile(
    r'\b(WM_[A-Z][A-Z0-9_]{2,})\b',
)

# D-Bus interface/method: "org.freedesktop.DBus.Method"
_DBUS_METHOD_RE = re.compile(
    r'\b(org\.\w+(?:\.\w+){2,})\b',
)


# ==================== KATMAN D: Telemetry/Analytics ====================

# TrackEvent('event_name') / trackEvent("event_name")
_TRACK_EVENT_RE = re.compile(
    r'[Tt]rack[Ee]vent\s*\(\s*[\'"](\w{3,})[\'"]',
)

# analytics.logEvent('user_login') / analytics.log('event')
_ANALYTICS_LOG_RE = re.compile(
    r'(?:analytics|telemetry|metrics|logger)\s*\.\s*'
    r'(?:log|track|record|send|emit|report)\w*\s*\(\s*[\'"](\w{3,})[\'"]',
    re.IGNORECASE,
)

# [metric] render_time_ms / [perf] frame_duration
_METRIC_TAG_RE = re.compile(
    r'\[(?:metric|perf|timer|counter|gauge|stat|measurement)\]\s*(\w{3,})',
    re.IGNORECASE,
)

# Sentry/Crashlytics breadcrumb: "breadcrumb:user_action"
_BREADCRUMB_RE = re.compile(
    r'(?:breadcrumb|event|action)\s*[:\-]\s*(\w{3,})',
    re.IGNORECASE,
)

# Firebase/Amplitude style: "screen_view", "purchase_complete" as standalone
_EVENT_NAME_RE = re.compile(
    r'[\'"]([a-z][a-z0-9]*(?:_[a-z0-9]+){1,5})[\'"]',
)

# Logging with event ID: "EVENT_USER_LOGIN", "EVT_PURCHASE"
_EVENT_CONST_RE = re.compile(
    r'\b((?:EVENT|EVT|METRIC|STAT)_[A-Z][A-Z0-9_]{2,})\b',
)


# ==================== KATMAN E: API Name String Detection ====================

# Exact API name string: the ENTIRE string is a C identifier with underscores.
# Matches strings like "sqlite3_open", "compression_stream_init", "sha3_query".
# Must be 4-60 chars, start with a lowercase letter, contain at least one underscore.
# UPPER_CASE only strings (like "SQLITE_OK", "DB_UNCHANGED") are excluded
# because they are constants/enums, not function names.
_EXACT_API_NAME_RE = re.compile(
    r'^[a-z][a-zA-Z0-9]*(?:_[a-zA-Z0-9]+)+$',
)

# Embedded API name in error/format strings.
# Looks for function_name patterns followed by typical error/format suffixes.
# "sqlite3_open_v2 open failed with %d" -> sqlite3_open_v2
# "sqlite3_close() returns %d" -> sqlite3_close
# "sqlite3_get_table() called with ..." -> sqlite3_get_table
_EMBEDDED_API_CALL_RE = re.compile(
    r'\b([a-z][a-z0-9]*(?:_[a-z0-9]+)+)\s*\(\)',
)

# Embedded API name followed by error/status words (no parentheses)
# "sqlite3_open_v2 open failed with %d" -> sqlite3_open_v2
_EMBEDDED_API_ERROR_RE = re.compile(
    r'\b([a-z][a-z0-9]*(?:_[a-z0-9]+)+)\s+'
    r'(?:open|close|read|write|init|create|delete|insert|update|select|'
    r'failed|error|returned|called|returns|missing|invalid|'
    r'not found|undefined|unsupported|succeeded|ok|done)',
    re.IGNORECASE,
)

# API name at start of format/error string (before ":" or "%")
# "sqlite3_expert_new: %s\n" -> sqlite3_expert_new
# "parse_create_index: out of memory" -> parse_create_index
_API_PREFIX_MSG_RE = re.compile(
    r'^([a-z][a-z0-9]*(?:_[a-z0-9]+)+)\s*[:]\s',
)

# UPPER_CASE constant names that indicate operation names
# "SQLITE_OK", "BEGIN_ATOMIC_WRITE" etc. -- these name the function's domain
# We don't use these directly as function names but they indicate context.
# NOT extracted as API names (too many false positives).

# Known library prefixes for higher confidence matching
_KNOWN_LIB_PREFIXES = frozenset({
    'sqlite3_', 'sqlite_', 'ssl_', 'crypto_', 'ev_', 'uv_',
    'curl_', 'pcre_', 'pcre2_', 'zlib_', 'png_', 'jpeg_',
    'xml_', 'json_', 'yaml_', 'http_', 'tcp_', 'udp_',
    'gzip_', 'bzip2_', 'lz4_', 'zstd_',
    'lua_', 'python_', 'rb_', 'js_', 'v8_',
    'gl_', 'vk_', 'dx_', 'sdl_', 'sfml_',
    'pthread_', 'sem_', 'shm_', 'mq_',
    'av_', 'snd_', 'alsa_', 'pulse_',
    'dbus_', 'gio_', 'gtk_', 'qt_',
    'fts3_', 'fts5_', 'rtree_',
    'lief_', 'capstone_', 'keystone_',
})


# ---------------------------------------------------------------------------
# Ana sinif
# ---------------------------------------------------------------------------

class StringIntelligence:
    """Central string intelligence engine for binary name recovery.

    Binary'deki string'leri analiz ederek fonksiyon/class/degisken isimlerini
    cikarir. 4 katmanli pattern matching kullanir:

    A) Assert/Debug string'leri -- en yuksek confidence
    B) Error message pattern'leri -- orta-yuksek confidence
    C) Protocol/message handler isimleri -- orta-yuksek confidence
    D) Telemetry/analytics event isimleri -- orta confidence

    Her katman bagimsiz calisir ve sonuclari StringIntelResult listesi olarak doner.
    """

    def __init__(self) -> None:
        """Initialize pattern sets."""
        # Pattern listelerini register et -- her tuple:
        # (compiled_regex, handler_function)
        # Handler'lar _analyze_* methodlari icinde

    def analyze_strings(
        self,
        strings_data: list[dict],
        xrefs: Optional[dict] = None,
    ) -> list[StringIntelResult]:
        """Analyze all strings and extract naming intelligence.

        Args:
            strings_data: List of {"address": int, "value": str}
                          Opsiyonel: "xrefs": [int] (string'i reference eden fonksiyon adresleri)
            xrefs: Optional mapping of string_addr -> [func_addr] for reverse lookup.
                   Eger string_data icinde xrefs yoksa bu parametre kullanilir.

        Returns:
            List of StringIntelResult with extracted names, sorted by confidence desc.
        """
        results: list[StringIntelResult] = []

        for s in strings_data:
            addr = s.get("address", 0)
            value = s.get("value", "")
            if not value or len(value) < 4:
                continue

            # String'in referans edildigi fonksiyon adresleri
            func_addrs: list[int] = s.get("xrefs", [])
            if not func_addrs and xrefs:
                func_addrs = xrefs.get(addr, [])

            # 5 katman analiz
            results.extend(self._analyze_assert_debug(value, addr))
            results.extend(self._analyze_error_messages(value, addr))
            results.extend(self._analyze_protocol_handlers(value, addr))
            results.extend(self._analyze_telemetry_events(value, addr))
            results.extend(self._analyze_api_name_strings(value, addr))

        # Deduplicate: ayni (name, target_type) icin en yuksek confidence olani tut
        results = self._deduplicate(results)

        # Confidence'a gore sirala (yuksekten dusuge)
        results.sort(key=lambda r: r.confidence, reverse=True)

        return results

    def get_function_name_suggestions(
        self,
        func_address: int,
        strings_data: list[dict],
        xrefs: Optional[dict] = None,
    ) -> list[StringIntelResult]:
        """Get name suggestions for a specific function based on its string references.

        Verilen fonksiyon adresini referans eden string'leri bulur ve
        sadece o string'ler uzerinde analiz yapar.

        Args:
            func_address: Fonksiyonun adresi.
            strings_data: Tum string verileri.
            xrefs: string_addr -> [func_addr] mapping.

        Returns:
            Bu fonksiyona ait name suggestion'lar, confidence'a gore sirali.
        """
        # Bu fonksiyonu referans eden string'leri filtrele
        relevant: list[dict] = []

        for s in strings_data:
            func_addrs: list[int] = s.get("xrefs", [])
            if not func_addrs and xrefs:
                func_addrs = xrefs.get(s.get("address", 0), [])
            if func_address in func_addrs:
                relevant.append(s)

        if not relevant:
            return []

        return self.analyze_strings(relevant)

    # =======================================================================
    # Katman A: Assert/Debug String Parser (conf: 0.80-0.95)
    # =======================================================================

    def _analyze_assert_debug(self, value: str, address: int) -> list[StringIntelResult]:
        """Assert, debug macro ve __FUNCTION__ kalintilariindan isim cikar.

        Pattern'ler:
        - glibc/POSIX assert: "file.c:10: func: Assertion `expr` failed."
        - file:line:func format: "foo.cpp:123: MyClass::MyMethod: assertion"
        - Qt Q_ASSERT: "ASSERT: ... function MyClass::Method"
        - Boost BOOST_ASSERT: "function 'MyFunc'"
        - __PRETTY_FUNCTION__ kalintisi: "void MyClass::Method(int)"
        - assert(obj->Method()) icindeki method cagrilari
        - Windows assertion: "Assertion failed: expr"
        """
        results: list[StringIntelResult] = []

        # --- glibc assert: "file.c:10: func_name: Assertion `expr` failed." ---
        m = _GLIBC_ASSERT_RE.search(value)
        if m:
            func_raw = m.group(1)
            results.extend(
                self._parse_class_or_func(func_raw, value, address, "assert", 0.92)
            )

        # --- file:line:func:assertion format ---
        m = _ASSERT_FILE_LINE_FUNC_RE.search(value)
        if m:
            func_raw = m.group(1)
            results.extend(
                self._parse_class_or_func(func_raw, value, address, "assert", 0.90)
            )

        # --- Qt Q_ASSERT ---
        m = _QT_ASSERT_RE.search(value)
        if m:
            func_raw = m.group(1)
            results.extend(
                self._parse_class_or_func(func_raw, value, address, "assert", 0.88)
            )

        # --- Boost BOOST_ASSERT ---
        m = _BOOST_ASSERT_RE.search(value)
        if m:
            func_raw = m.group(1)
            results.extend(
                self._parse_class_or_func(func_raw, value, address, "assert", 0.87)
            )

        # --- __PRETTY_FUNCTION__ kalintisi ---
        m = _PRETTY_FUNCTION_RE.search(value)
        if m:
            func_raw = m.group(1)
            results.extend(
                self._parse_class_or_func(func_raw, value, address, "assert", 0.93)
            )

        # --- assert(obj->Method()) icindeki call ---
        m = _ASSERT_CALL_RE.search(value)
        if m:
            func_name = m.group(1)
            if _is_valid_identifier(func_name):
                results.append(StringIntelResult(
                    name=func_name,
                    confidence=0.80,
                    source_string=value,
                    pattern_type="assert",
                    target_type="function",
                    address=address,
                ))

        # --- Windows assertion ---
        m = _WIN_ASSERT_RE.search(value)
        if m:
            func_raw = m.group(1)
            results.extend(
                self._parse_class_or_func(func_raw, value, address, "assert", 0.85)
            )

        return results

    # =======================================================================
    # Katman B: Error Message Pattern Matching (conf: 0.60-0.85)
    # =======================================================================

    def _analyze_error_messages(self, value: str, address: int) -> list[StringIntelResult]:
        """Error/warning/log mesajlarindan fonksiyon ve class isimleri cikar.

        Pattern'ler:
        - "Error in ParseConfig: invalid format" -> ParseConfig
        - "CSocket::Connect failed" -> CSocket, Connect
        - "[ERROR] AudioManager: buffer underrun" -> AudioManager
        - "Failed to initialize renderer" -> initialize_renderer
        - "Cannot open database" -> open_database
        - "Unable to parse configuration" -> parse_configuration
        - "MyClass::Init() returned error" -> MyClass, Init
        - "MyClass error: ..." -> MyClass
        - "my_function: error ..." -> my_function
        """
        results: list[StringIntelResult] = []

        # --- "Error in FuncName:" ---
        m = _ERROR_IN_FUNC_RE.search(value)
        if m:
            func_name = m.group(1)
            if _is_valid_identifier(func_name):
                results.append(StringIntelResult(
                    name=func_name,
                    confidence=0.82,
                    source_string=value,
                    pattern_type="error_msg",
                    target_type="function",
                    address=address,
                ))

        # --- "Class::Method failed/error" ---
        m = _CLASS_METHOD_FAILED_RE.search(value)
        if m:
            cls = m.group(1)
            method = m.group(2)
            if _is_valid_identifier(cls) and _is_valid_identifier(method):
                results.append(StringIntelResult(
                    name=f"{cls}_{method}",
                    confidence=0.85,
                    source_string=value,
                    pattern_type="error_msg",
                    target_type="method",
                    address=address,
                    class_name=cls,
                    method_name=method,
                ))
                results.append(StringIntelResult(
                    name=cls,
                    confidence=0.83,
                    source_string=value,
                    pattern_type="error_msg",
                    target_type="class",
                    address=address,
                    class_name=cls,
                ))

        # --- "[ERROR/WARNING/...] ClassName:" ---
        m = _LOG_PREFIX_CLASS_RE.search(value)
        if m:
            cls = m.group(1)
            if _is_valid_identifier(cls) and cls[0].isupper():
                results.append(StringIntelResult(
                    name=cls,
                    confidence=0.75,
                    source_string=value,
                    pattern_type="error_msg",
                    target_type="class",
                    address=address,
                    class_name=cls,
                ))

        # --- "Failed to verb noun" ---
        m = _FAILED_TO_VERB_NOUN_RE.search(value)
        if m:
            name = _verb_noun_to_name(m.group(1), m.group(2))
            if _is_valid_identifier(name):
                results.append(StringIntelResult(
                    name=name,
                    confidence=0.70,
                    source_string=value,
                    pattern_type="error_msg",
                    target_type="function",
                    address=address,
                ))

        # --- "Cannot verb noun" ---
        m = _CANNOT_VERB_NOUN_RE.search(value)
        if m:
            name = _verb_noun_to_name(m.group(1), m.group(2))
            if _is_valid_identifier(name):
                results.append(StringIntelResult(
                    name=name,
                    confidence=0.68,
                    source_string=value,
                    pattern_type="error_msg",
                    target_type="function",
                    address=address,
                ))

        # --- "Unable to verb noun" ---
        m = _UNABLE_TO_VERB_NOUN_RE.search(value)
        if m:
            name = _verb_noun_to_name(m.group(1), m.group(2))
            if _is_valid_identifier(name):
                results.append(StringIntelResult(
                    name=name,
                    confidence=0.68,
                    source_string=value,
                    pattern_type="error_msg",
                    target_type="function",
                    address=address,
                ))

        # --- "Class::Method() returned error" ---
        m = _CLASS_METHOD_RETURNED_RE.search(value)
        if m:
            cls = m.group(1)
            method = m.group(2)
            if _is_valid_identifier(cls) and _is_valid_identifier(method):
                results.append(StringIntelResult(
                    name=f"{cls}_{method}",
                    confidence=0.80,
                    source_string=value,
                    pattern_type="error_msg",
                    target_type="method",
                    address=address,
                    class_name=cls,
                    method_name=method,
                ))

        # --- "ClassName error:" ---
        m = _CLASS_ERROR_RE.search(value)
        if m:
            cls = m.group(1)
            if _is_valid_identifier(cls):
                results.append(StringIntelResult(
                    name=cls,
                    confidence=0.65,
                    source_string=value,
                    pattern_type="error_msg",
                    target_type="class",
                    address=address,
                    class_name=cls,
                ))

        # --- "snake_func_name: error ..." ---
        m = _SNAKE_FUNC_ERROR_RE.search(value)
        if m:
            func_name = m.group(1)
            if _is_valid_identifier(func_name):
                results.append(StringIntelResult(
                    name=func_name,
                    confidence=0.60,
                    source_string=value,
                    pattern_type="error_msg",
                    target_type="function",
                    address=address,
                ))

        return results

    # =======================================================================
    # Katman C: Protocol/Message Handler Naming (conf: 0.70-0.90)
    # =======================================================================

    def _analyze_protocol_handlers(self, value: str, address: int) -> list[StringIntelResult]:
        """Protocol/message handler isimlerini cikar.

        Pattern'ler:
        - k_EMsgClientLogon -> HandleClientLogon
        - MSG_LOGIN -> Handler_Login
        - /package.Service/MethodName -> ServiceMethod
        - "/api/v1/users" -> handle_api_v1_users
        - IMyInterface::Method -> COM method
        - WM_CREATE -> OnCreate
        - org.freedesktop.DBus.Method -> dbus method
        """
        results: list[StringIntelResult] = []

        # --- Steam k_EMsg style ---
        for m in _STEAM_EMSG_RE.finditer(value):
            enum_name = m.group(1)
            # k_EMsgClientLogon -> ClientLogon -> HandleClientLogon
            handler = self._emsg_to_handler(enum_name)
            if handler and _is_valid_identifier(handler):
                results.append(StringIntelResult(
                    name=handler,
                    confidence=0.85,
                    source_string=value,
                    pattern_type="protocol",
                    target_type="function",
                    address=address,
                ))

        # --- MSG_TYPE enum ---
        for m in _MSG_TYPE_ENUM_RE.finditer(value):
            msg_type = m.group(1)
            # MSG_LOGIN -> Handler_Login
            handler = self._msg_type_to_handler(msg_type)
            if handler and _is_valid_identifier(handler):
                results.append(StringIntelResult(
                    name=handler,
                    confidence=0.78,
                    source_string=value,
                    pattern_type="protocol",
                    target_type="function",
                    address=address,
                ))

        # --- gRPC service/method ---
        m = _GRPC_SERVICE_RE.search(value)
        if m:
            service_path = m.group(1)
            method_name = m.group(2)
            # Son component service ismi
            service = service_path.split('.')[-1] if '.' in service_path else service_path
            full_name = f"{service}_{method_name}"
            if _is_valid_identifier(full_name):
                results.append(StringIntelResult(
                    name=full_name,
                    confidence=0.88,
                    source_string=value,
                    pattern_type="protocol",
                    target_type="method",
                    address=address,
                    class_name=service,
                    method_name=method_name,
                ))

        # --- HTTP route ---
        m = _HTTP_PATH_EXTRACT_RE.search(value)
        if m:
            route = m.group(1)
            # "/api/v1/users/create" -> handle_api_v1_users_create
            handler = "handle_" + re.sub(r'[/\-]', '_', route).strip('_')
            handler = _sanitize_name(handler)
            if _is_valid_identifier(handler) and len(handler) > 8:
                results.append(StringIntelResult(
                    name=handler,
                    confidence=0.72,
                    source_string=value,
                    pattern_type="protocol",
                    target_type="function",
                    address=address,
                ))

        # --- COM interface ---
        m = _COM_INTERFACE_RE.search(value)
        if m:
            iface = m.group(1)
            method = m.group(2)
            if _is_valid_identifier(iface) and _is_valid_identifier(method):
                results.append(StringIntelResult(
                    name=f"{iface}_{method}",
                    confidence=0.82,
                    source_string=value,
                    pattern_type="protocol",
                    target_type="method",
                    address=address,
                    class_name=iface,
                    method_name=method,
                ))

        # --- Windows message ---
        for m in _WIN_MSG_RE.finditer(value):
            msg = m.group(1)
            # WM_CREATE -> OnCreate, WM_PAINT -> OnPaint
            handler = self._wm_to_handler(msg)
            if handler and _is_valid_identifier(handler):
                results.append(StringIntelResult(
                    name=handler,
                    confidence=0.75,
                    source_string=value,
                    pattern_type="protocol",
                    target_type="function",
                    address=address,
                ))

        # --- D-Bus method ---
        m = _DBUS_METHOD_RE.search(value)
        if m:
            full_path = m.group(1)
            parts = full_path.split('.')
            if len(parts) >= 3:
                method = parts[-1]
                service = parts[-2]
                if _is_valid_identifier(method):
                    results.append(StringIntelResult(
                        name=f"{service}_{method}",
                        confidence=0.70,
                        source_string=value,
                        pattern_type="protocol",
                        target_type="method",
                        address=address,
                        class_name=service,
                        method_name=method,
                    ))

        return results

    # =======================================================================
    # Katman D: Telemetry/Analytics Event Naming (conf: 0.65-0.80)
    # =======================================================================

    def _analyze_telemetry_events(self, value: str, address: int) -> list[StringIntelResult]:
        """Telemetry/analytics event isimlerinden fonksiyon ismi cikar.

        Pattern'ler:
        - TrackEvent('page_load') -> track_page_load
        - analytics.logEvent('user_login') -> log_user_login
        - [metric] render_time_ms -> measure_render_time_ms
        - breadcrumb:user_action -> handle_user_action
        - EVENT_USER_LOGIN -> handle_user_login
        """
        results: list[StringIntelResult] = []

        # --- TrackEvent('event_name') ---
        m = _TRACK_EVENT_RE.search(value)
        if m:
            event = m.group(1)
            func_name = f"track_{event}"
            if _is_valid_identifier(func_name):
                results.append(StringIntelResult(
                    name=func_name,
                    confidence=0.78,
                    source_string=value,
                    pattern_type="telemetry",
                    target_type="function",
                    address=address,
                ))

        # --- analytics.logEvent('event_name') ---
        m = _ANALYTICS_LOG_RE.search(value)
        if m:
            event = m.group(1)
            func_name = f"log_{event}"
            if _is_valid_identifier(func_name):
                results.append(StringIntelResult(
                    name=func_name,
                    confidence=0.75,
                    source_string=value,
                    pattern_type="telemetry",
                    target_type="function",
                    address=address,
                ))

        # --- [metric] metric_name ---
        m = _METRIC_TAG_RE.search(value)
        if m:
            metric = m.group(1)
            func_name = f"measure_{metric}"
            if _is_valid_identifier(func_name):
                results.append(StringIntelResult(
                    name=func_name,
                    confidence=0.72,
                    source_string=value,
                    pattern_type="telemetry",
                    target_type="function",
                    address=address,
                ))

        # --- breadcrumb:action_name ---
        m = _BREADCRUMB_RE.search(value)
        if m:
            action = m.group(1)
            # Cok genel kelimeleri (error, warning, info) atla -- zaten error_msg katmaninda yakalanir
            if _is_valid_identifier(action) and action.lower() not in {
                'error', 'warning', 'info', 'debug', 'fatal', 'critical',
                'trace', 'verbose', 'message', 'event',
            }:
                func_name = f"handle_{action}"
                results.append(StringIntelResult(
                    name=func_name,
                    confidence=0.65,
                    source_string=value,
                    pattern_type="telemetry",
                    target_type="function",
                    address=address,
                ))

        # --- EVENT_USER_LOGIN constant ---
        for m_const in _EVENT_CONST_RE.finditer(value):
            const = m_const.group(1)
            # EVENT_USER_LOGIN -> handle_user_login
            # Prefix'i (EVENT_, EVT_, METRIC_, STAT_) kaldir
            stripped = re.sub(r'^(?:EVENT|EVT|METRIC|STAT)_', '', const)
            func_name = f"handle_{stripped.lower()}"
            func_name = _sanitize_name(func_name)
            if _is_valid_identifier(func_name):
                results.append(StringIntelResult(
                    name=func_name,
                    confidence=0.68,
                    source_string=value,
                    pattern_type="telemetry",
                    target_type="function",
                    address=address,
                ))

        return results

    # =======================================================================
    # Katman E: API Name String Detection (conf: 0.55-0.90)
    # =======================================================================

    def _analyze_api_name_strings(self, value: str, address: int) -> list[StringIntelResult]:
        """Detect strings that ARE function/API names or contain embedded API names.

        This layer catches common C library patterns where:
        1. A string IS a function name: "sqlite3_open", "compression_stream_init"
        2. A string contains an API call: "sqlite3_close() returns %d"
        3. A string starts with an API name: "sqlite3_expert_new: %s"
        4. A string mentions an API name before error words: "sqlite3_open_v2 open failed"

        These patterns are extremely common in C binaries where function names
        appear in error messages, debug output, and registration tables.

        Confidence:
        - Known library prefix + exact match: 0.90
        - Exact API name (full string is the name): 0.85
        - API name with () call syntax: 0.82
        - API name as prefix before ':': 0.78
        - Embedded API name before error words: 0.72
        """
        results: list[StringIntelResult] = []
        stripped = value.strip()

        # Minimum length and skip overly long strings (likely not names)
        if len(stripped) < 4 or len(stripped) > 60:
            # For embedded patterns, allow longer strings
            if len(stripped) > 200:
                return results
            # But for exact match, skip long strings
            if len(stripped) > 60:
                stripped_for_exact = None
            else:
                stripped_for_exact = stripped
        else:
            stripped_for_exact = stripped

        # --- Pattern 1: Exact API name string ---
        # The entire string is a C function name (e.g., "sqlite3_open")
        if stripped_for_exact and _EXACT_API_NAME_RE.match(stripped_for_exact):
            name = stripped_for_exact
            if _is_valid_identifier(name) and not self._is_common_non_api_string(name):
                # Check for known library prefix for higher confidence
                has_known_prefix = any(
                    name.startswith(prefix) for prefix in _KNOWN_LIB_PREFIXES
                )
                conf = 0.90 if has_known_prefix else 0.85
                results.append(StringIntelResult(
                    name=name,
                    confidence=conf,
                    source_string=value,
                    pattern_type="api_name",
                    target_type="function",
                    address=address,
                ))

        # --- Pattern 2: API name with () call syntax ---
        # "sqlite3_close() returns %d" -> sqlite3_close
        for m in _EMBEDDED_API_CALL_RE.finditer(value):
            api_name = m.group(1)
            if _is_valid_identifier(api_name) and len(api_name) >= 4:
                has_known_prefix = any(
                    api_name.startswith(prefix) for prefix in _KNOWN_LIB_PREFIXES
                )
                conf = 0.88 if has_known_prefix else 0.82
                results.append(StringIntelResult(
                    name=api_name,
                    confidence=conf,
                    source_string=value,
                    pattern_type="api_name",
                    target_type="function",
                    address=address,
                ))

        # --- Pattern 3: API name as message prefix ---
        # "sqlite3_expert_new: %s\n" -> sqlite3_expert_new
        m = _API_PREFIX_MSG_RE.match(stripped)
        if m:
            api_name = m.group(1)
            if _is_valid_identifier(api_name) and not self._is_common_non_api_string(api_name):
                has_known_prefix = any(
                    api_name.startswith(prefix) for prefix in _KNOWN_LIB_PREFIXES
                )
                conf = 0.85 if has_known_prefix else 0.78
                results.append(StringIntelResult(
                    name=api_name,
                    confidence=conf,
                    source_string=value,
                    pattern_type="api_name",
                    target_type="function",
                    address=address,
                ))

        # --- Pattern 4: Embedded API name before error/status words ---
        # "sqlite3_open_v2 open failed with %d" -> sqlite3_open_v2
        # Skip if already matched as exact name (avoid dups from Pattern 1)
        m = _EMBEDDED_API_ERROR_RE.search(value)
        if m:
            api_name = m.group(1)
            if _is_valid_identifier(api_name) and len(api_name) >= 4:
                if not self._is_common_non_api_string(api_name):
                    has_known_prefix = any(
                        api_name.startswith(prefix) for prefix in _KNOWN_LIB_PREFIXES
                    )
                    conf = 0.80 if has_known_prefix else 0.72
                    results.append(StringIntelResult(
                        name=api_name,
                        confidence=conf,
                        source_string=value,
                        pattern_type="api_name",
                        target_type="function",
                        address=address,
                    ))

        return results

    @staticmethod
    def _is_common_non_api_string(name: str) -> bool:
        """Filter out strings that look like identifiers but are not API names.

        Common false positives: file format names, encoding names, generic terms
        that happen to have underscores, and ALL_CAPS constants.
        """
        # ALL_CAPS strings are constants/enums, not function names
        # Examples: SQLITE_OK, DB_UNCHANGED, BEGIN_ATOMIC_WRITE
        if re.match(r'^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$', name):
            return True

        lower = name.lower()
        # Common non-API identifier-like strings
        non_api = {
            'utf_8', 'utf_16', 'utf_32', 'iso_8859', 'us_ascii',
            'big_endian', 'little_endian', 'byte_order',
            'file_name', 'file_path', 'file_type', 'file_size',
            'true_type', 'open_type',
            'no_error', 'no_memory', 'out_of_memory',
            'read_only', 'read_write', 'write_only',
            'max_size', 'min_size', 'max_length', 'min_length',
            'end_of_file', 'end_of_stream',
        }
        if lower in non_api:
            return True
        # Very short names with single underscore are often not API names
        parts = lower.split('_')
        if len(parts) == 2 and all(len(p) <= 3 for p in parts):
            return True
        return False

    # =======================================================================
    # Yardimci private method'lar
    # =======================================================================

    def _parse_class_or_func(
        self,
        raw_name: str,
        source_string: str,
        address: int,
        pattern_type: str,
        confidence: float,
    ) -> list[StringIntelResult]:
        """Class::Method veya duz fonksiyon ismini parse edip sonuclara donustur.

        "MyClass::MyMethod" -> class + method results
        "my_function" -> function result
        """
        results: list[StringIntelResult] = []

        if '::' in raw_name:
            parts = raw_name.split('::')
            cls = parts[0]
            method = parts[-1] if len(parts) > 1 else ""

            if cls and _is_valid_identifier(cls):
                # Class result
                results.append(StringIntelResult(
                    name=cls,
                    confidence=confidence,
                    source_string=source_string,
                    pattern_type=pattern_type,
                    target_type="class",
                    address=address,
                    class_name=cls,
                ))

            if method and _is_valid_identifier(method):
                # Method result -- destructor (~) handle
                clean_method = method.lstrip('~')
                if clean_method and _is_valid_identifier(clean_method):
                    results.append(StringIntelResult(
                        name=f"{cls}_{method}" if cls else method,
                        confidence=confidence,
                        source_string=source_string,
                        pattern_type=pattern_type,
                        target_type="method",
                        address=address,
                        class_name=cls,
                        method_name=method,
                    ))
        else:
            # Duz fonksiyon ismi
            if _is_valid_identifier(raw_name):
                results.append(StringIntelResult(
                    name=raw_name,
                    confidence=confidence,
                    source_string=source_string,
                    pattern_type=pattern_type,
                    target_type="function",
                    address=address,
                ))

        return results

    def _emsg_to_handler(self, enum_name: str) -> Optional[str]:
        """Steam k_EMsg enum isminden handler fonksiyon ismi olustur.

        k_EMsgClientLogon -> HandleClientLogon
        k_EMsgGSStatusReply -> HandleGSStatusReply
        """
        name = enum_name
        # k_ prefix kaldir
        if name.startswith('k_'):
            name = name[2:]
        # EMsg prefix kaldir
        if name.startswith('EMsg'):
            name = name[4:]
        elif name.startswith('E') and len(name) > 1 and name[1].isupper():
            name = name[1:]

        if len(name) < 3:
            return None
        return f"Handle{name}"

    def _msg_type_to_handler(self, msg_type: str) -> Optional[str]:
        """MSG_TYPE enum isminden handler ismi olustur.

        MSG_LOGIN -> Handler_Login
        MSG_HEARTBEAT -> Handler_Heartbeat
        """
        # MSG_ prefix kaldir
        name = msg_type
        if name.startswith('MSG_'):
            name = name[4:]

        if len(name) < 2:
            return None

        # UPPER_CASE -> Title_Case
        parts = name.split('_')
        titled = '_'.join(p.capitalize() for p in parts if p)
        return f"Handler_{titled}"

    def _wm_to_handler(self, wm_msg: str) -> Optional[str]:
        """Windows mesajindan handler ismi olustur.

        WM_CREATE -> OnCreate
        WM_PAINT -> OnPaint
        WM_LBUTTONDOWN -> OnLButtonDown
        """
        name = wm_msg
        if name.startswith('WM_'):
            name = name[3:]

        if len(name) < 2:
            return None

        # UPPER -> Title
        # WM_LBUTTONDOWN -> LButtonDown (genel pattern)
        parts = name.split('_')
        titled = ''.join(p.capitalize() for p in parts if p)
        return f"On{titled}"

    def _deduplicate(self, results: list[StringIntelResult]) -> list[StringIntelResult]:
        """Ayni (name, target_type) kombinasyonu icin en yuksek confidence olani tut."""
        best: dict[tuple[str, str], StringIntelResult] = {}

        for r in results:
            key = (r.name, r.target_type)
            existing = best.get(key)
            if existing is None or r.confidence > existing.confidence:
                best[key] = r

        return list(best.values())
