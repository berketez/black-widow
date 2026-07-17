"""Ghidra Decompiled C Kodu Isimlendirme -- Karadul v1.0

FUN_xxx, param_N, local_XX, DAT_xxx gibi Ghidra otomatik isimlerini
6 katmanli strateji ile anlamli isimlere donusturur:

  Strateji 1: Symbol-Based     (conf 0.95)  -- Export/debug symbol'ler
  Strateji 2: String-Context   (conf 0.7-0.9) -- String literal'lerden isim
  Strateji 3: API-Call          (conf 0.6-0.8) -- Sistem API pattern'leri
  Strateji 4: Call-Graph        (conf 0.5-0.7) -- Graf pozisyonundan isim
  Strateji 5: Dataflow          (conf 0.3-0.5) -- Parametre kullanimindan isim
  Strateji 6: Type-Based        (conf 0.2-0.4) -- Tip bilgisinden isim
  Strateji 7: API-Param-Prop   (conf 0.6-0.8) -- API parametre propagasyonu
  Strateji 8: Reverse-Prop     (conf 0.75)    -- Callback isim propagasyonu
  Strateji 9: Local-Var-Naming (conf 0.25-0.55) -- Ghidra lokal degisken isimlendirme
  Strateji 10: Fortran-InStack (conf 0.80-0.85) -- ARM64 in_stack -> param_N + Fortran DB

Kullanim:
    from karadul.reconstruction.c_namer import CVariableNamer
    from karadul.config import Config

    namer = CVariableNamer(Config())
    result = namer.analyze_and_rename(
        decompiled_dir=Path("workspace/static/ghidra_output/decompiled"),
        functions_json=Path("workspace/static/ghidra_functions.json"),
        strings_json=Path("workspace/static/ghidra_strings.json"),
        call_graph_json=Path("workspace/static/ghidra_call_graph.json"),
        output_dir=Path("workspace/reconstruction/named_c"),
    )
    print(f"Renamed: {result.total_renamed}, High conf: {result.high_confidence}")
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from concurrent.futures import (
    BrokenExecutor,
    ProcessPoolExecutor,
    ThreadPoolExecutor,
    as_completed,
)
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from karadul.config import CPU_PERF_CORES, Config
from karadul.reconstruction.aho_replacer import AhoFinder, AhoReplacer
from karadul.reconstruction.c_namer_patterns import (
    COMBO_PATTERNS as _EXTENDED_COMBO_PATTERNS,
    SINGLE_API_HINTS as _EXTENDED_SINGLE_API_HINTS,
    STEAM_KEYWORDS as _STEAM_KEYWORDS,
    URL_HINTS as _URL_HINTS,
    ERROR_HINTS as _ERROR_HINTS,
    LOG_HINTS as _LOG_HINTS,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex guvenlik notu
# ---------------------------------------------------------------------------
# v1.8.0: _MAX_REGEX_BODY esigi KALDIRILDI.  Butun regex pattern'leri
# artik SATIR-BAZLI calistiriliyor: body.splitlines() ile parcalanip her
# satir (~100 char) uzerinde aranir.  Boylece 500KB body bile O(n) kalir
# ve HICBIR dosya atlanmaz (%100 kod islenebilirlik hedefi).

# ---------------------------------------------------------------------------
# Sonuc veri yapisi
# ---------------------------------------------------------------------------

@dataclass
class CNamingResult:
    """C kodu isimlendirme sonucu.

    Attributes:
        success: Islem basarili mi.
        output_files: Isimlendirilmis C dosyalari.
        naming_map: Eski ad -> yeni ad eslesmesi.
        total_renamed: Toplam yeniden adlandirilan sembol sayisi.
        by_strategy: Strateji -> yeniden adlandirma sayisi.
        high_confidence: >= 0.7 confidence ile isimlendirilen sayisi.
        medium_confidence: 0.4 - 0.7 arasi.
        low_confidence: < 0.4.
        errors: Hata mesajlari.
    """

    success: bool
    output_files: list[Path] = field(default_factory=list)
    naming_map: dict[str, str] = field(default_factory=dict)
    total_renamed: int = 0
    by_strategy: dict[str, int] = field(default_factory=dict)
    high_confidence: int = 0
    medium_confidence: int = 0
    low_confidence: int = 0
    errors: list[str] = field(default_factory=list)
    # FIX (2026-07-12): per-isim gercek confidence + strateji. NameMerger'in
    # flat 0.70 ile duzlemesini onler -> zayif yapisal isimler (helper_<adr>,
    # dispatcher_<adr>) gercek dusuk guveniyle merger'a girer, UNK esigi altinda
    # kalip FUN_xxx olarak birakilir (korroborasyon yoksa). old_name -> deger.
    confidence_map: dict[str, float] = field(default_factory=dict)
    strategy_map: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Dahili veri yapilari
# ---------------------------------------------------------------------------

@dataclass
class _NamingCandidate:
    """Bir sembol icin tek bir isimlendirme onerisi."""

    old_name: str
    new_name: str
    confidence: float
    strategy: str
    reason: str = ""


@dataclass
class _FunctionInfo:
    """Ghidra fonksiyon meta bilgisi (ghidra_functions.json'dan)."""

    name: str
    address: str
    size: int = 0
    params: list[dict[str, str]] = field(default_factory=list)
    return_type: str = ""
    calling_convention: str = ""


@dataclass
class _StringRef:
    """Ghidra string referansi (ghidra_strings.json'dan)."""

    value: str
    address: str
    refs: list[str] = field(default_factory=list)  # fonksiyon adresleri


# ---------------------------------------------------------------------------
# Ghidra otomatik isim pattern'leri
# ---------------------------------------------------------------------------

_GHIDRA_AUTO_FUNC = re.compile(r"^FUN_[0-9a-fA-F]+$")
_GHIDRA_AUTO_PARAM = re.compile(r"^param_\d+$")
_GHIDRA_AUTO_LOCAL = re.compile(r"^local_[0-9a-fA-F]+$")
_GHIDRA_AUTO_DAT = re.compile(r"^DAT_[0-9a-fA-F]+$")
_GHIDRA_AUTO_PTR = re.compile(r"^PTR_[0-9a-fA-F]+$")
_GHIDRA_AUTO_VAR = re.compile(r"^[a-z]Var\d+$")  # uVar1, iVar2, etc.
_GHIDRA_AUTO_STACK = re.compile(r"^Stack\[0x[0-9a-fA-F]+\]$")

# ObjC class pattern
_OBJC_CLASS = re.compile(r"_OBJC_CLASS_\$_(\w+)")
# C++ mangled names
_CPP_MANGLED = re.compile(r"^_Z[A-Z]")

# C kodu icinde fonksiyon cagrisi: ident(
_C_FUNC_CALL = re.compile(r"\b(\w+)\s*\(")
# Parametre kullanimi: fonksiyon(param_N)
_C_PARAM_USAGE = re.compile(r"\b(param_\d+)\b")
# Local kullanimi
_C_LOCAL_USAGE = re.compile(r"\b(local_[0-9a-fA-F]+)\b")
# DAT kullanimi
_C_DAT_USAGE = re.compile(r"\b(DAT_[0-9a-fA-F]+)\b")
# Ghidra auto var kullanimi
_C_AUTOVAR_USAGE = re.compile(r"\b([a-z]Var\d+)\b")

# String/char literal'leri brace sayimindan cikarmak icin (P1-10 fix)
_STR_LITERAL_RE = re.compile(r'"(?:[^"\\]|\\.)*"')
_CHAR_LITERAL_RE = re.compile(r"'(?:[^'\\]|\\.)*'")


def _count_braces(line: str) -> int:
    """String ve char literal'leri disindaki brace'leri say.

    Ghidra ciktisinda printf(\"{key: %d}\", val) gibi satirlarda
    string icindeki { } karakterleri brace sayimini bozuyordu (P1-10).
    """
    stripped = _STR_LITERAL_RE.sub('""', line)
    stripped = _CHAR_LITERAL_RE.sub("''", stripped)
    return stripped.count("{") - stripped.count("}")



def _is_ghidra_auto_name(name: str) -> bool:
    """Verilen isim Ghidra'nin otomatik urettigi bir isim mi."""
    return bool(
        _GHIDRA_AUTO_FUNC.match(name)
        or _GHIDRA_AUTO_PARAM.match(name)
        or _GHIDRA_AUTO_LOCAL.match(name)
        or _GHIDRA_AUTO_DAT.match(name)
        or _GHIDRA_AUTO_PTR.match(name)
        or _GHIDRA_AUTO_VAR.match(name)
        or _GHIDRA_AUTO_STACK.match(name)
    )


# v1.10.0 H1: Fortran trailing-underscore heuristic'i libc/GCC ASM stub
# isimleri icin false positive verir. Conservative blacklist ile bunlar
# Fortran sayilmaz (gfortran callee hint yoksa).
_NON_FORTRAN_UNDERSCORE_NAMES: frozenset[str] = frozenset({
    "_memcpy_", "_memset_", "_memmove_", "_memcmp_",
    "_strcpy_", "_strncpy_", "_strcmp_", "_strncmp_",
    "_strlen_", "_strcat_", "_strncat_",
    "_gcc_personality_v0_",
    "_unwind_resume_", "_unwind_backtrace_",
    "_dl_runtime_resolve_", "_dl_fini_",
    "_init_", "_fini_",  # ELF init/fini sections
    "_start_", "_end_",
    "_exit_", "___exit_",
})

# _pthread_*_ ve __libc_*_ pattern'lerini ayri regex ile yakala.
_PTHREAD_UNDERSCORE_RE = re.compile(r"^_pthread_\w+_$")
_LIBC_UNDERSCORE_RE = re.compile(r"^__libc_\w+_$")


def _is_non_fortran_underscore_name(name: str) -> bool:
    """ASM stub/libc wrapper isimlerini Fortran detection'dan hariç tut.

    `name.startswith("_") and name.endswith("_")` heuristic'i
    Fortran name mangling icin iyi calisir AMA _memcpy_, _pthread_*_,
    _gcc_personality_v0_ gibi libc/GCC wrapper isimleri de bu pattern'e
    uyar. Bu fn conservative blacklist uygular -- emin isimleri eler.

    Args:
        name: Fonksiyon ismi (zaten startswith/endswith "_" garantili).

    Returns:
        True ise isim Fortran DEGIL, heuristic reddedilmeli.
    """
    lower = name.lower()
    if lower in _NON_FORTRAN_UNDERSCORE_NAMES:
        return True
    if _PTHREAD_UNDERSCORE_RE.match(lower):
        return True
    if _LIBC_UNDERSCORE_RE.match(lower):
        return True
    return False


def _sanitize_c_name(name: str, preserve_case: bool = False) -> str:
    """Onerilen ismi gecerli C identifier'a donustur.

    Args:
        name: Ham isim.
        preserve_case: True ise CamelCase korunur (Swift/ObjC isimleri icin).
    """
    # Bosluk ve ozel karakterleri alt cizgiye cevir
    name = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    # Basa rakam gelirse _ ekle
    if name and name[0].isdigit():
        name = "_" + name
    # Birden fazla alt cizgiyi teke indir
    name = re.sub(r"_+", "_", name)
    # Bas/son alt cizgiyi kaldir (C convention icin)
    name = name.strip("_")
    # Bos kaldiysa fallback
    if not name:
        name = "unnamed"
    return name if preserve_case else name.lower()


def _extract_keywords_from_string(s: str) -> list[str]:
    """String literal'den anlamli anahtar kelimeleri cikar.

    "Failed to open database connection" -> ["open", "database", "connection"]
    """
    # Kisa stringlerde kelime cikarma
    if len(s) < 3:
        return []

    # URL, path, format string parcalarina ayir
    # Sadece alfanumerik kelimeleri al
    words = re.findall(r"[a-zA-Z]{3,}", s)

    # Stopword filtresi
    stopwords = {
        "the", "and", "for", "not", "but", "has", "had", "was", "are",
        "can", "did", "does", "with", "from", "that", "this", "will",
        "you", "your", "all", "been", "have", "its", "may", "our",
        "too", "use", "way", "who", "how", "its", "let", "put",
        "say", "she", "his", "her", "him", "get", "got", "set",
        "try", "yes", "yet", "than", "into", "just", "also",
        "failed", "error", "success", "warning", "info", "debug",
        "true", "false", "null", "none", "invalid", "unknown",
        # Build system / path noise
        "opt", "usr", "lib", "bin", "var", "tmp", "etc",
        "build", "buildbot", "buildworker", "hotfix",
        "release", "client", "server", "public",
        "src", "include", "framework", "frameworks",
        "system", "library", "versions", "darwin",
    }

    filtered = [w.lower() for w in words if w.lower() not in stopwords]

    # En fazla 4 kelime (cok uzun isimlerden kacin)
    return filtered[:4]


def _extract_name_from_string_aggressive(s: str) -> tuple[str, float] | None:
    """String'den daha agresif sekilde fonksiyon ismi cikar.

    Geleneksel keyword extraction'a ek olarak:
    - Steam/Valve keyword'leri
    - URL path component'leri
    - Hata mesaji verb'leri
    - ClassName::MethodName pattern'leri
    - Dosya yolu component'leri (buildbot path'leri)

    Returns:
        (suggested_name, confidence) tuple veya None
    """
    if not s or len(s) < 3:
        return None

    # 1. ClassName::MethodName pattern (en yuksek confidence)
    # Ornek: "CSteamNetworkingSockets::GetDetailedConnectionStatus"
    class_method = re.match(r"^C?(\w{3,})::(\w{3,})", s)
    if class_method:
        cls_name = class_method.group(1)
        method = class_method.group(2)
        name = _sanitize_c_name(f"{cls_name}_{method}")
        if name and name != "unnamed":
            return (name, 0.85)

    # 2. FuncName() pattern  -- log mesajlarinda
    func_paren = re.match(r"^(\w{3,})\s*\(\)", s)
    if func_paren:
        name = _sanitize_c_name(func_paren.group(1))
        if name and name != "unnamed":
            return (name, 0.80)

    # 3. Source path'i: .../src/xxx/yyy/zzz.cpp
    # Buildbot path'lerini de yakalayip son anlamli parcalarini cikar
    # Confidence yuksek (0.75) cunku dosya adi gercek kaynak kodunu gosterir
    src_match = re.search(r"/src/(.+?)\.(?:cpp|c|h|cc|mm)\b", s)
    if src_match:
        path_part = src_match.group(1)
        parts = [p for p in path_part.split("/") if p]
        # Son 2 parcayi al (modul + dosya adi)
        if len(parts) >= 2:
            module = parts[-2]
            filename = parts[-1]
            name = _sanitize_c_name(f"{module}_{filename}")
            if name and name != "unnamed" and len(name) > 4:
                return (name, 0.75)
        elif len(parts) == 1:
            name = _sanitize_c_name(parts[0])
            if name and name != "unnamed" and len(name) > 3:
                return (name, 0.65)

    # 4. Steam/Valve keyword'leri
    for keyword, hint in _STEAM_KEYWORDS.items():
        if keyword in s:
            # Keyword yanindaki baska kelimeleri de ekle
            idx = s.find(keyword)
            context_words = re.findall(r"[a-zA-Z]{3,}", s[max(0, idx-30):idx+len(keyword)+30])
            extra = [w.lower() for w in context_words
                     if w.lower() != hint and len(w) >= 4
                     and w.lower() not in {"error", "failed", "warning", "debug", "info",
                                           "true", "false", "null", "none", "the", "and",
                                           "for", "not", "with", "from", "that", "this"}]
            if extra:
                name = _sanitize_c_name(f"{hint}_{extra[0]}")
            else:
                name = hint
            if name and name != "unnamed":
                return (name, 0.65)

    # 5. URL path component
    for url_re, prefix in _URL_HINTS:
        m = url_re.search(s)
        if m:
            component = m.group(1) if m.lastindex else prefix
            name = _sanitize_c_name(f"{prefix}_{component}" if component != prefix else prefix)
            if name and name != "unnamed":
                return (name, 0.60)

    # 6. Error message verb extraction: "Failed to initialize XXX"
    for err_re, _ in _ERROR_HINTS:
        m = err_re.search(s)
        if m:
            verb = m.group(1).lower()
            if len(verb) >= 3:
                # "Failed to connect" -> handle_connect_error
                name = _sanitize_c_name(f"handle_{verb}")
                if name and name != "unnamed":
                    return (name, 0.55)

    # 7. ObjC selector pattern: "handleGetURLEvent:withReplyEvent:"
    objc_sel = re.match(r"^([a-z]\w{3,}):(?:\w+:)*$", s)
    if objc_sel:
        name = _sanitize_c_name(objc_sel.group(1))
        if name and name != "unnamed":
            return (name, 0.70)

    # 8. Assertion expression: "num > 0", "ptr != NULL"
    assert_match = re.match(r"^(\w+)\s*[!><=]+\s*\w+$", s)
    if assert_match:
        var_name = assert_match.group(1)
        if len(var_name) >= 3:
            return (_sanitize_c_name(f"assert_{var_name}"), 0.45)

    return None


# ---------------------------------------------------------------------------
# API pattern tanimlari
# ---------------------------------------------------------------------------

# Her pattern: frozenset(api_calls) -> (fonksiyon_ismi, confidence)
# Birden fazla API'nin birlikte kullanimi belirli islemi gosterir

_API_COMBO_PATTERNS: list[tuple[frozenset[str], str, float]] = [
    # Network
    (frozenset({"socket", "connect", "send"}), "send_network_request", 0.8),
    (frozenset({"socket", "connect", "recv"}), "receive_network_data", 0.8),
    (frozenset({"socket", "bind", "listen", "accept"}), "start_server_socket", 0.8),
    (frozenset({"socket", "connect"}), "connect_socket", 0.75),
    (frozenset({"socket", "bind", "listen"}), "setup_listener", 0.75),
    (frozenset({"send", "recv"}), "network_io", 0.65),
    (frozenset({"getaddrinfo"}), "resolve_address", 0.7),
    (frozenset({"gethostbyname"}), "resolve_hostname", 0.7),
    (frozenset({"htons", "inet_addr"}), "prepare_sockaddr", 0.65),
    (frozenset({"select"}), "wait_for_io", 0.65),
    (frozenset({"poll"}), "poll_descriptors", 0.65),
    (frozenset({"epoll_create", "epoll_ctl"}), "setup_epoll", 0.7),

    # File I/O
    (frozenset({"fopen", "fread", "fclose"}), "read_file", 0.8),
    (frozenset({"fopen", "fwrite", "fclose"}), "write_file", 0.8),
    (frozenset({"fopen", "fgets", "fclose"}), "read_file_lines", 0.8),
    (frozenset({"fopen", "fprintf", "fclose"}), "write_formatted_file", 0.8),
    (frozenset({"open", "read", "close"}), "read_raw_file", 0.75),
    (frozenset({"open", "write", "close"}), "write_raw_file", 0.75),
    (frozenset({"fopen", "fseek", "ftell"}), "get_file_size", 0.7),
    (frozenset({"stat", "access"}), "check_file_access", 0.7),
    (frozenset({"opendir", "readdir", "closedir"}), "list_directory", 0.8),
    (frozenset({"mkdir"}), "create_directory", 0.7),
    (frozenset({"unlink"}), "delete_file", 0.7),
    (frozenset({"rename"}), "rename_file", 0.7),
    (frozenset({"mmap", "munmap"}), "map_file_memory", 0.75),

    # Memory
    (frozenset({"malloc", "memcpy", "free"}), "copy_buffer", 0.75),
    (frozenset({"malloc", "memset"}), "allocate_zeroed", 0.7),
    (frozenset({"calloc"}), "allocate_zeroed_array", 0.65),
    (frozenset({"realloc"}), "resize_buffer", 0.65),
    (frozenset({"malloc", "free"}), "manage_memory", 0.6),
    (frozenset({"mmap", "mprotect"}), "setup_memory_mapping", 0.7),

    # String
    (frozenset({"strlen", "strcpy"}), "copy_string", 0.7),
    (frozenset({"strlen", "strcat"}), "concat_string", 0.7),
    (frozenset({"strcmp"}), "compare_strings", 0.7),
    (frozenset({"strncmp"}), "compare_strings_n", 0.7),
    (frozenset({"strstr"}), "find_substring", 0.7),
    (frozenset({"strchr"}), "find_char_in_string", 0.7),
    (frozenset({"strtok"}), "tokenize_string", 0.7),
    (frozenset({"sprintf", "snprintf"}), "format_string", 0.65),
    (frozenset({"sscanf"}), "parse_formatted_string", 0.7),
    (frozenset({"atoi"}), "parse_integer", 0.7),
    (frozenset({"atof"}), "parse_float", 0.7),
    (frozenset({"strtol"}), "parse_long", 0.7),
    (frozenset({"strtoul"}), "parse_unsigned_long", 0.7),

    # Process
    (frozenset({"fork", "exec"}), "spawn_process", 0.8),
    (frozenset({"fork", "execve"}), "spawn_process", 0.8),
    (frozenset({"fork", "waitpid"}), "fork_and_wait", 0.8),
    (frozenset({"system"}), "run_shell_command", 0.7),
    (frozenset({"popen", "pclose"}), "run_piped_command", 0.75),
    (frozenset({"pipe", "fork"}), "setup_ipc_pipe", 0.75),
    (frozenset({"kill"}), "send_signal", 0.65),
    (frozenset({"signal", "sigaction"}), "setup_signal_handler", 0.7),
    (frozenset({"waitpid"}), "wait_for_child", 0.65),
    (frozenset({"exit", "_exit"}), "terminate_process", 0.65),

    # Thread
    (frozenset({"pthread_create"}), "create_thread", 0.75),
    (frozenset({"pthread_join"}), "join_thread", 0.7),
    (frozenset({"pthread_mutex_lock", "pthread_mutex_unlock"}), "synchronized_access", 0.7),
    (frozenset({"pthread_cond_wait", "pthread_cond_signal"}), "wait_for_condition", 0.7),
    (frozenset({"sem_wait", "sem_post"}), "semaphore_sync", 0.7),

    # Crypto / SSL
    (frozenset({"SSL_CTX_new", "SSL_new", "SSL_connect"}), "ssl_connect", 0.8),
    (frozenset({"SSL_read", "SSL_write"}), "ssl_io", 0.75),
    (frozenset({"EVP_EncryptInit", "EVP_EncryptUpdate", "EVP_EncryptFinal"}), "encrypt_data", 0.8),
    (frozenset({"EVP_DecryptInit", "EVP_DecryptUpdate", "EVP_DecryptFinal"}), "decrypt_data", 0.8),
    (frozenset({"EVP_DigestInit", "EVP_DigestUpdate", "EVP_DigestFinal"}), "compute_hash", 0.8),
    (frozenset({"MD5_Init", "MD5_Update", "MD5_Final"}), "compute_md5", 0.8),
    (frozenset({"SHA256_Init", "SHA256_Update", "SHA256_Final"}), "compute_sha256", 0.8),

    # ObjC / macOS
    (frozenset({"objc_msgSend", "objc_getClass"}), "objc_dispatch", 0.7),
    (frozenset({"CFRelease"}), "release_cf_object", 0.6),
    (frozenset({"dispatch_async"}), "dispatch_async_task", 0.7),
    (frozenset({"dispatch_sync"}), "dispatch_sync_task", 0.7),
    (frozenset({"NSLog"}), "log_message", 0.6),

    # Dynamic loading
    (frozenset({"dlopen", "dlsym"}), "load_dynamic_library", 0.8),
    (frozenset({"dlclose"}), "unload_library", 0.7),

    # Time
    (frozenset({"time", "localtime"}), "get_local_time", 0.7),
    (frozenset({"gettimeofday"}), "get_precise_time", 0.7),
    (frozenset({"clock_gettime"}), "get_clock_time", 0.7),
    (frozenset({"sleep", "usleep", "nanosleep"}), "delay_execution", 0.65),

    # Error
    (frozenset({"perror"}), "print_error", 0.65),
    (frozenset({"strerror"}), "get_error_string", 0.65),
    (frozenset({"errno"}), "check_error", 0.6),

    # I/O
    (frozenset({"printf"}), "print_output", 0.5),
    (frozenset({"puts"}), "print_line", 0.5),
    (frozenset({"scanf"}), "read_input", 0.6),
    (frozenset({"fgets"}), "read_line", 0.6),
    (frozenset({"getchar"}), "read_char", 0.6),
]

# Genisletilmis combo pattern'leri mevcut listeye merge et
# Mevcut set'teki frozenset key'lerini takip ederek cakismayanlari ekle
_existing_combos = {p[0] for p in _API_COMBO_PATTERNS}
for combo_set, name, conf in _EXTENDED_COMBO_PATTERNS:
    if combo_set not in _existing_combos:
        _API_COMBO_PATTERNS.append((combo_set, name, conf))
        _existing_combos.add(combo_set)

# Combo'lari eleman sayisina gore sirala (en spesifik once)
_API_COMBO_PATTERNS.sort(key=lambda x: len(x[0]), reverse=True)

# Tek API cagrisi -> (suggested prefix, confidence)
_SINGLE_API_HINTS: dict[str, tuple[str, float]] = {
    "malloc": ("alloc_", 0.5),
    "calloc": ("alloc_", 0.5),
    "free": ("cleanup_", 0.5),
    "realloc": ("resize_", 0.5),
    "memcpy": ("copy_", 0.5),
    "memset": ("init_", 0.5),
    "memmove": ("move_", 0.5),
    "printf": ("print_", 0.4),
    "fprintf": ("write_", 0.5),
    "sprintf": ("format_", 0.5),
    "snprintf": ("format_", 0.5),
    "fopen": ("open_", 0.5),
    "fclose": ("close_", 0.5),
    "fread": ("read_", 0.5),
    "fwrite": ("write_", 0.5),
    "socket": ("net_", 0.5),
    "connect": ("connect_", 0.5),
    "send": ("send_", 0.5),
    "recv": ("receive_", 0.5),
    "fork": ("spawn_", 0.5),
    "execve": ("exec_", 0.5),
    "pthread_create": ("thread_", 0.5),
    "objc_msgSend": ("objc_call_", 0.4),
    "dlopen": ("load_lib_", 0.6),
    "dlsym": ("resolve_sym_", 0.6),
    "SSL_connect": ("ssl_", 0.5),
    "SSL_read": ("ssl_read_", 0.5),
    "SSL_write": ("ssl_write_", 0.5),
}

# Genisletilmis single hint'leri merge et (mevcut key'leri ezmeden)
for api_name, hint in _EXTENDED_SINGLE_API_HINTS.items():
    if api_name not in _SINGLE_API_HINTS:
        _SINGLE_API_HINTS[api_name] = hint

# Parametre kullanim pattern'leri: regex -> (suggested_name, confidence)
_PARAM_USAGE_PATTERNS: list[tuple[re.Pattern[str], str, float]] = [
    # String isleme
    (re.compile(r"strlen\s*\(\s*PARAM\s*\)"), "input_str", 0.45),
    (re.compile(r"strcpy\s*\([^,]+,\s*PARAM\s*\)"), "src_str", 0.45),
    (re.compile(r"strcpy\s*\(\s*PARAM\s*,"), "dst_str", 0.45),
    (re.compile(r"strcmp\s*\(\s*PARAM\s*,"), "str_a", 0.4),
    (re.compile(r"strcat\s*\(\s*PARAM\s*,"), "base_str", 0.4),
    (re.compile(r"strstr\s*\(\s*PARAM\s*,"), "haystack", 0.45),
    (re.compile(r"strstr\s*\([^,]+,\s*PARAM\s*\)"), "needle", 0.45),

    # Memory
    (re.compile(r"free\s*\(\s*PARAM\s*\)"), "buffer", 0.4),
    (re.compile(r"memcpy\s*\(\s*PARAM\s*,"), "dst_buf", 0.4),
    (re.compile(r"memcpy\s*\([^,]+,\s*PARAM\s*,"), "src_buf", 0.4),
    (re.compile(r"memset\s*\(\s*PARAM\s*,"), "target_buf", 0.4),
    (re.compile(r"realloc\s*\(\s*PARAM\s*,"), "old_buf", 0.4),

    # Aritmetik / pointer
    (re.compile(r"PARAM\s*\+\s*(?:0x)?[0-9a-fA-F]+"), "base_ptr", 0.35),
    (re.compile(r"\*\s*PARAM"), "ptr", 0.35),
    (re.compile(r"PARAM\s*\[\s*\w+\s*\]"), "array", 0.4),
    (re.compile(r"PARAM\s*->\s*\w+"), "obj_ptr", 0.4),

    # NULL check
    (re.compile(r"if\s*\(\s*PARAM\s*==\s*(?:NULL|0|0x0)\s*\)"), "optional_ptr", 0.35),
    (re.compile(r"if\s*\(\s*PARAM\s*!=\s*(?:NULL|0|0x0)\s*\)"), "optional_ptr", 0.35),
    (re.compile(r"if\s*\(\s*!\s*PARAM\s*\)"), "optional_ptr", 0.3),

    # Karsilastirma
    (re.compile(r"PARAM\s*[<>]=?\s*\d"), "count", 0.3),
    (re.compile(r"PARAM\s*==\s*\d"), "status", 0.3),
    (re.compile(r"PARAM\s*!=\s*-1"), "result", 0.3),

    # Dongu / index
    (re.compile(r"for\s*\([^;]*PARAM\s*=\s*0"), "index", 0.4),
    (re.compile(r"while\s*\(\s*PARAM\s*"), "condition", 0.3),

    # I/O
    (re.compile(r"printf\s*\([^,]+,\s*PARAM\s*\)"), "value", 0.3),
    (re.compile(r"write\s*\(\s*PARAM\s*,"), "fd", 0.45),
    (re.compile(r"read\s*\(\s*PARAM\s*,"), "fd", 0.45),
    (re.compile(r"fwrite\s*\([^,]+,[^,]+,[^,]+,\s*PARAM\s*\)"), "file_handle", 0.45),
    (re.compile(r"fread\s*\([^,]+,[^,]+,[^,]+,\s*PARAM\s*\)"), "file_handle", 0.45),

    # Socket
    (re.compile(r"(?:send|write)\s*\(\s*PARAM\s*,"), "socket_fd", 0.45),
    (re.compile(r"(?:recv|read)\s*\(\s*PARAM\s*,"), "socket_fd", 0.45),
    (re.compile(r"connect\s*\(\s*PARAM\s*,"), "socket_fd", 0.45),
    (re.compile(r"bind\s*\(\s*PARAM\s*,"), "socket_fd", 0.45),
    (re.compile(r"listen\s*\(\s*PARAM\s*,"), "socket_fd", 0.45),
    (re.compile(r"close\s*\(\s*PARAM\s*\)"), "fd", 0.4),
]

# Tip bazli isimlendirme: (type_pattern, suggested_name, confidence)
_TYPE_NAMING: list[tuple[re.Pattern[str], str, float]] = [
    (re.compile(r"^char\s*\*$"), "str", 0.3),
    (re.compile(r"^const\s+char\s*\*$"), "str", 0.35),
    (re.compile(r"^unsigned?\s*char\s*\*$"), "byte_buf", 0.3),
    (re.compile(r"^int$"), "result", 0.2),
    (re.compile(r"^unsigned\s+int$"), "value", 0.2),
    (re.compile(r"^long$"), "value", 0.2),
    (re.compile(r"^long\s+long$"), "value", 0.2),
    (re.compile(r"^unsigned\s+long$"), "size", 0.25),
    (re.compile(r"^size_t$"), "size", 0.35),
    (re.compile(r"^ssize_t$"), "bytes_count", 0.35),
    (re.compile(r"^void\s*\*$"), "data_ptr", 0.25),
    (re.compile(r"^bool$"), "flag", 0.25),
    (re.compile(r"^_Bool$"), "flag", 0.25),
    (re.compile(r"^float$"), "fval", 0.2),
    (re.compile(r"^double$"), "dval", 0.2),
    (re.compile(r"^FILE\s*\*$"), "file_handle", 0.4),
    (re.compile(r"^DIR\s*\*$"), "dir_handle", 0.4),
    (re.compile(r"^pthread_t$"), "thread", 0.4),
    (re.compile(r"^pthread_mutex_t\s*\*$"), "mutex", 0.4),
    (re.compile(r"^struct\s+sockaddr"), "addr", 0.35),
    (re.compile(r"^SSL\s*\*$"), "ssl_conn", 0.4),
    (re.compile(r"^SSL_CTX\s*\*$"), "ssl_ctx", 0.4),
    (re.compile(r"^EVP_MD_CTX\s*\*$"), "digest_ctx", 0.4),
    (re.compile(r"^EVP_CIPHER_CTX\s*\*$"), "cipher_ctx", 0.4),
    # Ghidra undefined tipler
    (re.compile(r"^undefined\d*$"), "raw_value", 0.2),
    (re.compile(r"^undefined8$"), "qword_val", 0.2),
    (re.compile(r"^undefined4$"), "dword_val", 0.2),
    (re.compile(r"^undefined2$"), "word_val", 0.2),
    (re.compile(r"^undefined1$"), "byte_val", 0.2),
    # Pointer tipler
    (re.compile(r"^long\s*\*$"), "long_array", 0.25),
    (re.compile(r"^int\s*\*$"), "int_array", 0.25),
]


# ---------------------------------------------------------------------------
# Local variable usage patterns (Strateji 9)
# ---------------------------------------------------------------------------
# Pattern, suggested_name, confidence
# PARAM placeholder will be replaced with the actual variable name

_LOCAL_VAR_USAGE_PATTERNS: list[tuple[re.Pattern[str], str, float]] = [
    # --- Loop counters ---
    # for (x = 0; ...)  or  for (x = 1; ...)
    (re.compile(r"for\s*\([^;]*\bPARAM\s*=\s*[01]\s*;"), "i", 0.55),
    # Nested loop detection: already renamed an 'i', second loop var -> j
    # (handled in code logic, not pattern)

    # --- Return value capture ---
    # x = func_name(...) where func is known
    (re.compile(r"\bPARAM\s*=\s*_?malloc\s*\("), "buf", 0.55),
    (re.compile(r"\bPARAM\s*=\s*_?calloc\s*\("), "buf", 0.55),
    (re.compile(r"\bPARAM\s*=\s*_?realloc\s*\("), "buf", 0.50),
    (re.compile(r"\bPARAM\s*=\s*_?strdup\s*\("), "str_copy", 0.55),
    (re.compile(r"\bPARAM\s*=\s*_?fopen\s*\("), "fp", 0.55),
    (re.compile(r"\bPARAM\s*=\s*_?open\s*\("), "fd", 0.55),
    (re.compile(r"\bPARAM\s*=\s*_?socket\s*\("), "sock_fd", 0.55),
    (re.compile(r"\bPARAM\s*=\s*_?accept\s*\("), "client_fd", 0.55),
    (re.compile(r"\bPARAM\s*=\s*_?fork\s*\("), "pid", 0.55),
    (re.compile(r"\bPARAM\s*=\s*_?getpid\s*\("), "pid", 0.55),
    (re.compile(r"\bPARAM\s*=\s*_?strlen\s*\("), "len", 0.55),
    (re.compile(r"\bPARAM\s*=\s*_?sizeof\s*\("), "size", 0.50),
    (re.compile(r"\bPARAM\s*=\s*_?atoi\s*\("), "num", 0.55),
    (re.compile(r"\bPARAM\s*=\s*_?atol\s*\("), "num", 0.55),
    (re.compile(r"\bPARAM\s*=\s*_?strtol\s*\("), "num", 0.55),
    (re.compile(r"\bPARAM\s*=\s*_?strtoul\s*\("), "num", 0.55),
    (re.compile(r"\bPARAM\s*=\s*_?time\s*\("), "timestamp", 0.50),
    (re.compile(r"\bPARAM\s*=\s*_?getenv\s*\("), "env_val", 0.55),
    (re.compile(r"\bPARAM\s*=\s*_?strchr\s*\("), "pos", 0.50),
    (re.compile(r"\bPARAM\s*=\s*_?strstr\s*\("), "pos", 0.50),
    (re.compile(r"\bPARAM\s*=\s*_?strrchr\s*\("), "pos", 0.50),
    (re.compile(r"\bPARAM\s*=\s*_?mmap\s*\("), "mapped", 0.50),
    (re.compile(r"\bPARAM\s*=\s*_?dlopen\s*\("), "lib_handle", 0.55),
    (re.compile(r"\bPARAM\s*=\s*_?dlsym\s*\("), "sym_ptr", 0.55),
    (re.compile(r"\bPARAM\s*=\s*_?pthread_create\s*\("), "thread_ret", 0.50),
    # Generic function return capture (lower confidence)
    (re.compile(r"\bPARAM\s*=\s*\w+\s*\("), "ret", 0.30),

    # --- Error/status check patterns ---
    # if (x < 0) or if (x == -1) or if (x != 0) -> error code
    (re.compile(r"if\s*\(\s*PARAM\s*<\s*0\s*\)"), "err", 0.50),
    (re.compile(r"if\s*\(\s*PARAM\s*==\s*-1\s*\)"), "err", 0.50),
    (re.compile(r"if\s*\(\s*PARAM\s*!=\s*0\s*\)"), "status", 0.45),
    (re.compile(r"if\s*\(\s*PARAM\s*==\s*0\s*\)"), "status", 0.45),
    # perror / strerror usage
    (re.compile(r"perror\s*\([^)]*\).*\bPARAM\b"), "err", 0.45),

    # --- Array index patterns ---
    (re.compile(r"\w+\s*\[\s*PARAM\s*\]"), "idx", 0.50),
    (re.compile(r"\[\s*PARAM\s*\*"), "idx", 0.45),

    # --- Pointer arithmetic ---
    (re.compile(r"\*\s*\(\s*\w+\s*\+\s*PARAM\s*\)"), "offset", 0.45),
    (re.compile(r"PARAM\s*\+\s*(?:0x)?[0-9a-fA-F]+\b"), "offset", 0.40),

    # --- String operation patterns ---
    (re.compile(r"_?strlen\s*\(\s*PARAM\s*\)"), "str", 0.50),
    (re.compile(r"_?strcpy\s*\(\s*PARAM\s*,"), "dst_str", 0.50),
    (re.compile(r"_?strcpy\s*\([^,]+,\s*PARAM\s*\)"), "src_str", 0.50),
    (re.compile(r"_?strncpy\s*\(\s*PARAM\s*,"), "dst_str", 0.50),
    (re.compile(r"_?strcat\s*\(\s*PARAM\s*,"), "base_str", 0.45),
    (re.compile(r"_?strcmp\s*\(\s*PARAM\s*,"), "str_a", 0.45),
    (re.compile(r"_?strcmp\s*\([^,]+,\s*PARAM\s*\)"), "str_b", 0.45),
    (re.compile(r"_?sprintf\s*\(\s*PARAM\s*,"), "out_buf", 0.50),
    (re.compile(r"_?snprintf\s*\(\s*PARAM\s*,"), "out_buf", 0.50),

    # --- Memory operation patterns ---
    (re.compile(r"_?free\s*\(\s*PARAM\s*\)"), "buf", 0.45),
    (re.compile(r"_?memcpy\s*\(\s*PARAM\s*,"), "dst_buf", 0.45),
    (re.compile(r"_?memcpy\s*\([^,]+,\s*PARAM\s*,"), "src_buf", 0.45),
    (re.compile(r"_?memset\s*\(\s*PARAM\s*,"), "buf", 0.45),
    (re.compile(r"_?memcmp\s*\(\s*PARAM\s*,"), "buf_a", 0.45),

    # --- I/O patterns ---
    (re.compile(r"_?write\s*\(\s*PARAM\s*,"), "fd", 0.50),
    (re.compile(r"_?read\s*\(\s*PARAM\s*,"), "fd", 0.50),
    (re.compile(r"_?fwrite\s*\([^,]+,[^,]+,[^,]+,\s*PARAM\s*\)"), "fp", 0.50),
    (re.compile(r"_?fread\s*\([^,]+,[^,]+,[^,]+,\s*PARAM\s*\)"), "fp", 0.50),
    (re.compile(r"_?fclose\s*\(\s*PARAM\s*\)"), "fp", 0.50),
    (re.compile(r"_?close\s*\(\s*PARAM\s*\)"), "fd", 0.45),
    (re.compile(r"_?send\s*\(\s*PARAM\s*,"), "sock_fd", 0.50),
    (re.compile(r"_?recv\s*\(\s*PARAM\s*,"), "sock_fd", 0.50),
    (re.compile(r"_?connect\s*\(\s*PARAM\s*,"), "sock_fd", 0.50),
    (re.compile(r"_?bind\s*\(\s*PARAM\s*,"), "sock_fd", 0.50),

    # --- Boolean/flag patterns ---
    (re.compile(r"if\s*\(\s*PARAM\s*\)"), "flag", 0.35),
    (re.compile(r"if\s*\(\s*!\s*PARAM\s*\)"), "flag", 0.35),
    (re.compile(r"while\s*\(\s*PARAM\s*\)"), "done", 0.40),
    (re.compile(r"while\s*\(\s*!\s*PARAM\s*\)"), "running", 0.40),

    # --- Return value assignment then return ---
    (re.compile(r"return\s+PARAM\s*;"), "result", 0.40),

    # ===================================================================
    # v1.9.0: Domain-specific local variable naming patterns
    # ===================================================================

    # --- Accumulator patterns ---
    # sum += val;  or  sum = sum + val;
    (re.compile(r"\bPARAM\s*\+="), "accumulator", 0.50),
    (re.compile(r"\bPARAM\s*=\s*PARAM\s*\+\s*[^\s;]"), "accumulator", 0.50),
    # product *= val;  or  product = product * val;
    (re.compile(r"\bPARAM\s*\*="), "product", 0.50),
    (re.compile(r"\bPARAM\s*=\s*PARAM\s*\*\s*[^\s;]"), "product", 0.50),
    # count++;  or  count = count + 1;  or  count += 1;
    (re.compile(r"\bPARAM\s*\+\+"), "counter", 0.50),
    (re.compile(r"\+\+\s*PARAM\b"), "counter", 0.50),
    (re.compile(r"\bPARAM\s*=\s*PARAM\s*\+\s*1\s*;"), "counter", 0.50),
    # var -= val;  or  var = var - val; (decrement accumulator)
    (re.compile(r"\bPARAM\s*-="), "decrement", 0.45),
    (re.compile(r"\bPARAM\s*--"), "counter", 0.50),
    (re.compile(r"--\s*PARAM\b"), "counter", 0.50),
    # Bitwise accumulator: var |= val;  var &= val;  var ^= val;
    (re.compile(r"\bPARAM\s*\|="), "flags", 0.45),
    (re.compile(r"\bPARAM\s*&="), "mask", 0.45),
    (re.compile(r"\bPARAM\s*\^="), "toggle", 0.45),

    # --- Array stride detection ---
    # var[i*3+0], var[i*3+1], var[i*3+2]  -> coordinate/vector access
    (re.compile(r"\bPARAM\s*\[\s*\w+\s*\*\s*3\s*\+\s*[012]\s*\]"), "coord_array", 0.50),
    # var[i*4+j] -> matrix/RGBA component
    (re.compile(r"\bPARAM\s*\[\s*\w+\s*\*\s*4\s*\+\s*\w+\s*\]"), "rgba_array", 0.45),
    # var[i*6+j] -> tensor/matrix component (6 = symmetric 3x3)
    (re.compile(r"\bPARAM\s*\[\s*\w+\s*\*\s*6\s*\+\s*\w+\s*\]"), "tensor_array", 0.45),
    # var[i*N+j] general strided access (N is any digit 2-9)
    (re.compile(r"\bPARAM\s*\[\s*\w+\s*\*\s*[2-9]\s*\+\s*\w+\s*\]"), "strided_array", 0.40),
    # var[i*N] where N > 1 (general stride)
    (re.compile(r"\bPARAM\s*\[\s*\w+\s*\*\s*[2-9]\d*\s*\]"), "strided_array", 0.40),

    # --- Comparison target patterns ---
    # if (var > something) or if (var >= something) where something is not 0
    (re.compile(r"if\s*\([^)]*\bPARAM\s*>\s*[1-9]"), "threshold_val", 0.40),
    (re.compile(r"if\s*\([^)]*\bPARAM\s*>=\s*[1-9]"), "threshold_val", 0.40),
    # if (var < limit) break;  -> bound check
    (re.compile(r"if\s*\([^)]*\bPARAM\s*<\s*\w+\s*\)\s*break"), "bound_check", 0.45),
    (re.compile(r"if\s*\([^)]*\bPARAM\s*>=\s*\w+\s*\)\s*break"), "bound_check", 0.45),
    # if (var == 0) return (early return on zero/null -> status)
    (re.compile(r"if\s*\(\s*PARAM\s*==\s*0\s*\)\s*return"), "status", 0.45),
    # if (var == NULL) or if (var == (void *)0x0)
    (re.compile(r"if\s*\(\s*PARAM\s*==\s*(?:NULL|0x0|\(\s*void\s*\*\s*\)\s*0x0)\s*\)"), "nullable_ptr", 0.45),
    (re.compile(r"if\s*\(\s*PARAM\s*!=\s*(?:NULL|0x0|\(\s*void\s*\*\s*\)\s*0x0)\s*\)"), "nullable_ptr", 0.45),
    # switch (var) -> selector/discriminant
    (re.compile(r"switch\s*\(\s*PARAM\s*\)"), "selector", 0.45),

    # --- Pointer chain patterns ---
    # ptr = *(long *)(base + 0xNN);  -> field dereference
    (re.compile(r"\bPARAM\s*=\s*\*\s*\([^)]*\*\s*\)\s*\(\s*\w+\s*\+\s*0x[0-9a-fA-F]+\s*\)"), "field_ptr", 0.45),
    # ptr = *(type *)ptr;  -> linked list traversal (self-referential deref)
    (re.compile(r"\bPARAM\s*=\s*\*\s*\([^)]*\*\s*\)\s*PARAM\s*;"), "current_node", 0.50),
    # ptr = *(type *)(ptr + 0xNN);  -> linked list next pointer
    (re.compile(r"\bPARAM\s*=\s*\*\s*\([^)]*\*\s*\)\s*\(\s*PARAM\s*\+\s*0x[0-9a-fA-F]+\s*\)"), "next_ptr", 0.50),
    # ptr->field pattern: *(type *)(ptr + offset)  used as lvalue (write through ptr)
    (re.compile(r"\*\s*\([^)]*\*\s*\)\s*\(\s*PARAM\s*\+\s*0x[0-9a-fA-F]+\s*\)\s*="), "obj_ptr", 0.45),

    # --- Math operation patterns ---
    # var = sqrt(...)  -> magnitude or distance
    (re.compile(r"\bPARAM\s*=\s*_?sqrt\s*\("), "magnitude", 0.50),
    (re.compile(r"\bPARAM\s*=\s*_?sqrtf?\s*\("), "magnitude", 0.50),
    # var = exp(...)  -> exponential value
    (re.compile(r"\bPARAM\s*=\s*_?exp\s*\("), "exp_val", 0.45),
    (re.compile(r"\bPARAM\s*=\s*_?expf?\s*\("), "exp_val", 0.45),
    # var = log(...)  -> logarithmic value
    (re.compile(r"\bPARAM\s*=\s*_?log[2f]?\s*\("), "log_val", 0.45),
    # var = sin/cos/tan(...)  -> trigonometric value
    (re.compile(r"\bPARAM\s*=\s*_?sinf?\s*\("), "sin_val", 0.45),
    (re.compile(r"\bPARAM\s*=\s*_?cosf?\s*\("), "cos_val", 0.45),
    (re.compile(r"\bPARAM\s*=\s*_?tanf?\s*\("), "tan_val", 0.45),
    # var = atan2(...)  -> angle
    (re.compile(r"\bPARAM\s*=\s*_?atan2f?\s*\("), "angle", 0.50),
    # var = abs/fabs(...)  -> absolute value
    (re.compile(r"\bPARAM\s*=\s*_?f?abs\s*\("), "abs_val", 0.45),
    # var = pow(...)  -> power result
    (re.compile(r"\bPARAM\s*=\s*_?powf?\s*\("), "power_val", 0.45),
    # var = floor/ceil/round(...)  -> rounded value
    (re.compile(r"\bPARAM\s*=\s*_?floorf?\s*\("), "floor_val", 0.45),
    (re.compile(r"\bPARAM\s*=\s*_?ceilf?\s*\("), "ceil_val", 0.45),
    (re.compile(r"\bPARAM\s*=\s*_?roundf?\s*\("), "rounded", 0.45),
    # var = a / b;  (division -> ratio)
    (re.compile(r"\bPARAM\s*=\s*\w+\s*/\s*\w+\s*;"), "ratio", 0.35),
    # var = a % b;  (modulo -> remainder)
    (re.compile(r"\bPARAM\s*=\s*\w+\s*%\s*\w+\s*;"), "remainder", 0.40),

    # --- Conditional assignment patterns ---
    # var = (a < b) ? a : b;  -> min_val
    (re.compile(r"\bPARAM\s*=\s*\([^)]+<[^)]+\)\s*\?\s*\w+\s*:\s*\w+\s*;"), "min_val", 0.50),
    # var = (a > b) ? a : b;  -> max_val
    (re.compile(r"\bPARAM\s*=\s*\([^)]+>[^)]+\)\s*\?\s*\w+\s*:\s*\w+\s*;"), "max_val", 0.50),
    # var = (cond) ? a : b;  -> general ternary selection
    (re.compile(r"\bPARAM\s*=\s*[^;]*\?\s*\w+\s*:\s*\w+\s*;"), "selected", 0.35),

    # --- Shift operation patterns ---
    # var = val >> N  or  var = val << N  -> shifted value / bit extraction
    (re.compile(r"\bPARAM\s*=\s*\w+\s*>>\s*\d+\s*;"), "shifted", 0.40),
    (re.compile(r"\bPARAM\s*=\s*\w+\s*<<\s*\d+\s*;"), "shifted", 0.40),
    (re.compile(r"\bPARAM\s*=\s*\w+\s*&\s*0x[0-9a-fA-F]+\s*;"), "masked", 0.40),
    (re.compile(r"\bPARAM\s*>>="), "shifted", 0.40),
    (re.compile(r"\bPARAM\s*<<="), "shifted", 0.40),

    # --- Cast patterns (Ghidra-specific) ---
    # var = (type)expr;  where var is assigned a cast value
    (re.compile(r"\bPARAM\s*=\s*\(float\)"), "fval", 0.35),
    (re.compile(r"\bPARAM\s*=\s*\(double\)"), "dval", 0.35),
    (re.compile(r"\bPARAM\s*=\s*\(int\)"), "ival", 0.35),
    (re.compile(r"\bPARAM\s*=\s*\(uint\)"), "uval", 0.35),
    (re.compile(r"\bPARAM\s*=\s*\(long\)"), "lval", 0.35),
    (re.compile(r"\bPARAM\s*=\s*\(char\s*\*\)"), "str", 0.35),
]

# Ghidra auto-var prefix -> fallback name (when no usage pattern matches)
# These are low-confidence (0.25) fallbacks that are still better than uVar1/iVar2
_GHIDRA_PREFIX_FALLBACK: dict[str, tuple[str, float]] = {
    # Format: prefix letter -> (suggested_name, confidence)
    "u": ("val", 0.25),       # uVar -> unsigned value
    "i": ("ret", 0.25),       # iVar -> int, often return value
    "l": ("lval", 0.25),      # lVar -> long value
    "b": ("flag", 0.25),      # bVar -> bool
    "c": ("ch", 0.25),        # cVar -> char
    "s": ("sval", 0.25),      # sVar -> short
    "f": ("fval", 0.25),      # fVar -> float
    "d": ("dval", 0.25),      # dVar -> double
    "p": ("ptr", 0.25),       # pVar / pcVar / plVar -> pointer
    "a": ("arr", 0.25),       # aVar -> array
}

# v1.9.0: Return value semantic naming - functions to skip (already handled
# by specific patterns in _LOCAL_VAR_USAGE_PATTERNS with better names)
_RET_SEMANTIC_SKIP: frozenset[str] = frozenset({
    # Already handled as specific patterns (malloc->buf, strlen->len, etc.)
    "malloc", "calloc", "realloc", "free", "strdup",
    "fopen", "open", "socket", "accept", "fork", "getpid",
    "strlen", "sizeof", "atoi", "atol", "strtol", "strtoul",
    "time", "getenv", "strchr", "strstr", "strrchr",
    "mmap", "dlopen", "dlsym", "pthread_create",
    # C keywords / casts that look like function calls
    "if", "while", "for", "switch", "return", "sizeof",
    # Math functions (already have specific patterns)
    "sqrt", "sqrtf", "exp", "expf", "log", "logf", "log2", "log2f",
    "sin", "sinf", "cos", "cosf", "tan", "tanf",
    "atan2", "atan2f", "fabs", "fabsf", "abs",
    "pow", "powf", "floor", "floorf", "ceil", "ceilf",
    "round", "roundf",
})

# Regex for extracting local variable type declarations from C code body
# Matches: "  type_spec var_name;" at start of function
# Examples:
#   uint uVar1;
#   char *pcVar5;
#   undefined8 local_78;
#   bool bVar1;
#   int iVar2;
#   long lVar3;
# Multi-letter prefix auto-var pattern (pcVar5, plVar3, ppvVar7, etc.)
_GHIDRA_AUTO_VAR_WIDE = re.compile(r"^[a-z]{1,4}Var\d+$")
# Finder regex for multi-letter prefix auto-vars in body text
_C_AUTOVAR_USAGE_WIDE = re.compile(r"\b([a-z]{1,4}Var\d+)\b")

# Matches two forms:
#   "  uint uVar1;"          -> type="uint", var="uVar1"
#   "  char *pcVar5;"        -> type="char *", var="pcVar5"  (pointer star before var)
#   "  undefined8 local_78;" -> type="undefined8", var="local_78"
_LOCAL_DECL_RE = re.compile(
    r"^\s+"                          # leading whitespace
    r"((?:(?:const|unsigned|signed|long|short|struct|enum|union|volatile)\s+)*"  # type qualifiers
    r"(?:undefined[1248]?|uint|int|char|long|short|bool|_Bool|float|double|void|size_t|ssize_t|"
    r"FILE|DIR|SSL|SSL_CTX|pthread_t|pthread_mutex_t|EVP_MD_CTX|EVP_CIPHER_CTX|"
    r"\w+_t)"                        # base type
    r"(?:\s*\*+\s*|\s+))"           # pointer stars (with optional spaces) OR mandatory space
    r"([a-z]{1,4}Var\d+|local_[0-9a-fA-F]+)"  # Ghidra auto-var name (1-4 char prefix)
    r"\s*;",                          # semicolon
    re.MULTILINE,
)


# ---------------------------------------------------------------------------
# Gövde-tabanlı parametre isimlendirme (Strateji 11)
# ---------------------------------------------------------------------------
# KISIT / KÖK SEBEP (2026-07-16): Bu binary'lerde (ARM64 stripped Mach-O)
# Ghidra `ghidra_functions.json`'a params=[] yazıyor — parametre metadata'sı
# üretmiyor. Sonuç: `func_info.params` BOŞ → _strategy_dataflow ve
# _strategy_type_based'in parametre döngüsü HİÇ ateşlenmiyor (boş liste üstünde
# döner). `param_N` isimleri yalnızca decompiled C GÖVDESİNDE (imza satırı +
# kullanım) yaşıyor. Bu strateji param_N'i GÖVDEDEN okuyup KULLANIM ŞEKLİNDEN
# isim çıkarır. Domain'den bağımsızdır (kripto/CFD/hangi alan olursa).
# LEAKAGE YOK: kural kaynak (DWARF) adından değil, makine kodundaki kullanım
# desenlerinden türer.

# İmzadan parametre bloğunu çıkarmak için: "<ret> <fname>(<params>)"
# (fname regex'e dışarıdan escape edilip gömülür).

# param_N'in sabit-offset struct alanı erişimi (ctx/state sinyali):
#   *param            -> offset 0
#   param[0x10]       -> sabit indeks
#   param + 0x18      -> sabit offset (parantezli veya değil)
#   param->field      -> ok erişimi
def _param_fixed_offsets(body: str, esc: str) -> set[str]:
    """param'ın eriştiği AYRIK sabit-offset kümesi. >=3 ayrık offset = struct/
    context pointer'ı güçlü kanıtı (tek/iki alan tesadüfi olabilir)."""
    offsets: set[str] = set()
    if re.search(r"\*\s*" + esc + r"\b", body):
        offsets.add("0")
    for m in re.finditer(esc + r"\s*\[\s*(0x[0-9a-fA-F]+|\d+)\s*\]", body):
        offsets.add(m.group(1))
    # `param + 0xNN` (memcpy(param+0x1c,..) veya *(T*)(param+0x18) — ikisini de yakalar)
    for m in re.finditer(esc + r"\s*\+\s*(0x[0-9a-fA-F]+|\d+)\b", body):
        offsets.add(m.group(1))
    if re.search(esc + r"\s*->", body):
        offsets.add("arrow")
    return offsets


# Cephe 1b — yön (WRITE/READ) tespiti. `_param_fixed_offsets` bir offset'e
# ERİŞİLDİĞİNİ sayar ama STORE (lvalue) mü LOAD (rvalue) mu ayırmaz. Bir çıktı-
# tamponuna (`*(T*)(param+off) = digest`) baskın YAZMA yapılıyorsa bile "≥3 offset
# → ctx" kuralına takılır (belgelenmiş resbuf→ctx / output→ctx FP kök sebebi).
# Aşağıdaki iki helper offset erişimini yönüne göre ayırır: bir deref'in hemen
# sağında (boşlukları atlayarak) `=` var ve `==` DEĞİLSE STORE (write), aksi
# halde LOAD (read). Cephe 1c (disambiguation) için de yön metadata'sı üretir.
_PTR_CAST_RE = r"\*\s*\([^()]*\)\s*"  # *(T *)  — cast, iç içe parantez yok


def _param_offset_directions(body: str, esc: str) -> tuple[set[str], set[str]]:
    """param'ın sabit-offset erişimlerini (writes, reads) offset kümesi olarak ayır.

    WRITE = deref/index/arrow'un hemen sağında düz atama (`=`, `==` değil).
    READ  = diğer tüm bağlamlar (koşul, RHS, alt-ifade, fonksiyon argümanı).
    `memcpy(param, ..)` (dst=arg0) → yazma; `memcpy(dst, param, ..)` (src=arg1)
    → okuma sinyali de dahildir (offset yerine sentetik "mem" etiketiyle).

    Yalnız yön kararına yardımcı; isim üretmez. `_param_fixed_offsets` ile aynı
    offset alfabesini (0 / sayı / arrow) kullanır ki iki sayım karşılaştırılabilsin.
    """
    writes: set[str] = set()
    reads: set[str] = set()
    # (regex, offset-kaynağı) — 0: offset "0", "arrow": ok erişimi, 1: grup(1)
    access_res: list[tuple[re.Pattern[str], object]] = [
        # *(T *)(param + off)  — cast'li offset deref
        (re.compile(_PTR_CAST_RE + r"\(\s*" + esc + r"\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)"), 1),
        # *(T *)param  — cast'li offset 0
        (re.compile(_PTR_CAST_RE + esc + r"\b"), 0),
        # param[idx]  — sabit indeks
        (re.compile(esc + r"\s*\[\s*(0x[0-9a-fA-F]+|\d+)\s*\]"), 1),
        # *param  — çıplak offset 0
        (re.compile(r"\*\s*" + esc + r"\b"), 0),
        # param->field  — ok erişimi
        (re.compile(esc + r"\s*->\s*[A-Za-z_]\w*"), "arrow"),
    ]
    for rx, grp in access_res:
        for m in rx.finditer(body):
            if grp == 0:
                off = "0"
            elif grp == "arrow":
                off = "arrow"
            else:
                off = m.group(1)
            tail = body[m.end():m.end() + 3].lstrip()
            if tail.startswith("=") and not tail.startswith("=="):
                writes.add(off)
            else:
                reads.add(off)
    # mem-kopya: param dst (arg0) → yazma, param src (arg1) → okuma
    if re.search(_MEMFUNC + r"\s*\(\s*" + esc + r"\b", body) or \
            re.search(_MEMFUNC + r"\s*\(\s*" + esc + r"\s*\+", body):
        writes.add("mem")
    if re.search(_MEMFUNC + r"\s*\([^,;]*,\s*" + esc + r"\b", body):
        reads.add("mem")
    return writes, reads


def _param_has_computed_write(body: str, esc: str) -> bool:
    """param'a yapılan store'lardan en az biri SABİT-OLMAYAN (hesaplanmış) değer mi?

    Ayırt edici (kök gözlem): `*_init_ctx` bir struct'a SABİT başlangıç değerleri
    yazar (`*param_1 = 0x67452301`) — bu bir CTX başlatmadır, çıktı tamponu değil
    (GT = ctx). Gerçek çıktı tamponu HESAPLANMIŞ değer yazar (`*(uint*)(buf+4) =
    uVar2`). Bu ayrım, saf-yazma init-ctx'i yanlışlıkla output sanıp silmeyi
    (regresyon) önler: 2a yalnız hesaplanmış-yazma varsa ateşlenir.
    """
    store_res = [
        _PTR_CAST_RE + r"\(\s*" + esc + r"\s*\+\s*(?:0x[0-9a-fA-F]+|\d+)\s*\)\s*=(?!=)\s*([^;]+);",
        _PTR_CAST_RE + esc + r"\s*=(?!=)\s*([^;]+);",
        esc + r"\s*\[\s*(?:0x[0-9a-fA-F]+|\d+)\s*\]\s*=(?!=)\s*([^;]+);",
        r"\*\s*" + esc + r"\s*=(?!=)\s*([^;]+);",
        esc + r"\s*->\s*\w+\s*=(?!=)\s*([^;]+);",
    ]
    for pat in store_res:
        for m in re.finditer(pat, body):
            rhs = m.group(1).strip()
            if not re.fullmatch(r"0x[0-9a-fA-F]+|\d+", rhs):
                return True  # değişken/ifade = hesaplanmış çıktı
    return False


def _param_write_offsets(body: str, esc: str) -> set[str]:
    """param'a YAZILAN (lvalue store) ayrık offset kümesi (çıktı-tamponu sinyali)."""
    return _param_offset_directions(body, esc)[0]


def _param_read_offsets(body: str, esc: str) -> set[str]:
    """param'dan OKUNAN (rvalue load) ayrık offset kümesi (girdi/state sinyali)."""
    return _param_offset_directions(body, esc)[1]


def _split_top_level_commas(blob: str) -> list[str]:
    """Virgülle böl AMA parantez/köşeli/süslü içindeki virgülleri sayma
    (fonksiyon-pointer parametreleri `void (*)(int,int)` bölünmesin)."""
    parts: list[str] = []
    depth = 0
    cur: list[str] = []
    for ch in blob:
        if ch in "([{":
            depth += 1
            cur.append(ch)
        elif ch in ")]}":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur))
    return parts


def _param_is_iterated(body: str, esc: str) -> bool:
    """param DEĞİŞKEN indeks/offset ile geziliyor mu (veri tamponu sinyali):
    param[i] veya param + i (i sabit değil)."""
    return bool(
        re.search(esc + r"\s*\[\s*[A-Za-z_]", body)
        or re.search(esc + r"\s*\+\s*[A-Za-z_]", body)
    )


_MEMFUNC = (r"(?:memcpy|memmove|memset|memcmp|strcpy|strncpy|strcat"
            r"|memcpy_chk|memmove_chk|memset_chk)")


def _param_is_buffer_scalar(body: str, esc: str) -> bool:
    """Scalar (ulong/long) param aslında veri-pointer'ı mı: GERÇEK deref
    (*(T*)param / *param) VEYA bir mem/str kopya fonksiyonunda POINTER
    pozisyonunda (arg0/arg1 = dst/src) geçiyor.

    KISIT/OVERFIT KORUMASI (2026-07-16):
      - `a + b` düz aritmetiğini KAPSAMAZ (add(a,b)'nin 'a'sını buf sanma tuzağı).
      - mem-fonksiyonun BOYUT arg'ını (arg2+) KAPSAMAZ (len'i buf sanma tuzağı) —
        yalnız ilk iki argümanı (dst/src) pointer sayarız. Boyut param'ı zaten
        _param_has_size_usage ile len'e gider (bu fonksiyondan ÖNCE denenir)."""
    if re.search(r"\*\s*\([^)]*\)\s*\(?\s*" + esc + r"\b", body):  # *(T *)param / *(T*)(param+..)
        return True
    if re.search(r"\*\s*" + esc + r"\b", body):                    # *param
        return True
    if re.search(_MEMFUNC + r"\s*\(\s*" + esc + r"\b", body):      # memfunc(param, ...) = dst
        return True
    if re.search(_MEMFUNC + r"\s*\([^,;]*,\s*" + esc + r"\b", body):  # memfunc(x, param, ...) = src
        return True
    return False


def _param_has_size_usage(body: str, esc: str) -> bool:
    """param bir uzunluk/sayaç gibi kullanılıyor mu (scalar için):
    döngü sınırı (< param / param <), boyut aritmetiği (param/4, (uint)param,
    param>>0x20 — 64-bit boyutun üst yarısı), azaltma (param--), blok maskesi
    (param & 0x..c0). Klasik `n--` / `for i<n` sezgisi."""
    return bool(
        re.search(r"[<>]=?\s*" + esc + r"\b", body)          # X <= param
        or re.search(r"\b" + esc + r"\s*[<>]=?", body)        # param < X
        or re.search(r"\b" + esc + r"\s*/\s*\d", body)        # param / 4
        or re.search(r"\(\s*uint\s*\)\s*" + esc + r"\b", body)  # (uint)param (64->32 boyut)
        or re.search(r"\b" + esc + r"\s*>>\s*0x", body)       # param >> 0x20
        or re.search(r"\b" + esc + r"\s*--", body)            # param--
        or re.search(r"--\s*" + esc + r"\b", body)            # --param
        or re.search(r"\b" + esc + r"\s*&\s*0x[0-9a-fA-F]*c0\b", body)  # param & 0x..c0 (blok)
    )


def _classify_body_param(body: str, pname: str, is_ptr: bool
                         ) -> tuple[str, float, str] | None:
    """param_N'in KULLANIMINDAN (name, confidence, reason) çıkar. None = sinyal yok.

    Öncelik (domain-bağımsız, savunulabilir):
      pointer + >=3 ayrık sabit offset  -> ctx  (struct/context state pointer'ı)
      pointer + iterasyon / >=1 offset   -> buf  (veri tamponu)
      scalar  + >=3 ayrık sabit offset   -> ctx  (long/ulong struct tabanı)
      scalar  + boyut/döngü kullanımı     -> len  (uzunluk/sayaç)
      scalar  + iterasyon                 -> buf
    Ölçüm eşleşmesi: ctx≡{context,state}, buf≡{buffer,data,bytes}, len≡{length,
    size,count,num} (tests/benchmark/metrics.py SEMANTIC_EQUIV) — jenerik ad
    yeterli, tam kaynak adı gerekmez.
    """
    esc = re.escape(pname)
    offsets = _param_fixed_offsets(body, esc)
    iterated = _param_is_iterated(body, esc)
    if is_ptr:
        if len(offsets) >= 3:
            # Cephe 1b — Katman 2a (yön kapısı, YALNIZ pointer param):
            # ≥3 offset "ctx" demek için gerekli ama YETERLİ DEĞİL. Offset'e
            # baskın YAZMA yapılıyorsa (writes>=2 AND reads<=1) bu bir ÇIKTI
            # tamponudur, state ctx'i DEĞİL → yanlış "ctx" üretmektense param_N
            # bırak (None). Belgelenmiş output→ctx FP'lerini siler; precision'ı
            # korur (missing < wrong). `out` ETİKETİ ÜRETMEZ (o Katman 2b, kapsam
            # dışı). Karışık kullanım (hem yaz hem oku = inout state) → eski ctx
            # davranışı (güvenli varsayılan). Scalar'da output çıkarımı YAPILMAZ
            # (çok gürültülü — bu dal yalnız is_ptr).
            writes = _param_write_offsets(body, esc)
            reads = _param_read_offsets(body, esc)
            # Baskın yazma + HESAPLANMIŞ değer = çıktı tamponu → ctx DEME.
            # Sabit-init (`*_init_ctx` struct başlatma) baskın-yazma AMA sabit
            # değer → GERÇEK ctx (GT), silme (regresyon koruması).
            if (len(writes) >= 2 and len(reads) <= 1
                    and _param_has_computed_write(body, esc)):
                return None  # baskın hesaplanmış yazma → çıktı tamponu
            return ("ctx", 0.42, f"pointer struct erişimi ({len(offsets)} ayrık offset)")
        if iterated or len(offsets) >= 1:
            return ("buf", 0.38, "pointer veri tamponu (iterasyon/deref)")
        return None
    # scalar: boyut (len) önce — mem-fonksiyon boyut arg'ı buf'a kaçmasın.
    # NOT: scalar için `param + var` (düz aritmetik, ör. add(a,b)) buf SAYILMAZ;
    # yalnız gerçek deref / mem-kopya arg'ı buf olur (overfit koruması).
    if len(offsets) >= 3:
        return ("ctx", 0.40, f"scalar struct tabanı ({len(offsets)} ayrık offset)")
    if _param_has_size_usage(body, esc):
        return ("len", 0.42, "boyut/döngü aritmetiği")
    if _param_is_buffer_scalar(body, esc):
        return ("buf", 0.35, "scalar veri-pointer (deref/mem-kopya)")
    return None


# ---------------------------------------------------------------------------
# Cephe 1b — Alg 1 (pass-through miras) yardımcıları — module-level
# ---------------------------------------------------------------------------

# Miras için minimum KAYNAK (callee param) güveni. 0.40 altı sinyaller gürültülü
# (scalar buf 0.35 vb.) → zayıf kaynak zayıf miras = hata yayılımı. Tasarım §6.2.
_PASSTHROUGH_MIN_SOURCE_CONF = 0.40
# Miras sönümlemesi: her hop conf × bu (uzak komşu = daha az güven; min_confidence
# tabanı 4-5 hop'ta doğal ölüm sağlar → sonsuz zincir precision katili olamaz).
_PASSTHROUGH_DAMPING = 0.85
# Transitif zincir için fixed-point üst sınırı (fixture'da en derin zincir 3 hop).
_PASSTHROUGH_MAX_ROUNDS = 5


def _extract_sig_params(body: str, fname: str) -> list[tuple[str, bool]] | None:
    """Fonksiyon gövdesindeki imzadan (pozisyon sırasıyla) [(param_adı, is_ptr)]
    çıkar. Variadic (`...`) veya ayrıştırılamaz imza → None (pozisyon güvensiz).

    `_strategy_body_param_naming`'in imza-çıkarma mantığıyla aynı çıpayı kullanır
    (fonksiyon adına bağlı, docstring/@param yorumlarını atlar).
    """
    if not body or fname not in body:
        return None
    esc_fn = re.escape(fname)
    sig_re = re.compile(
        r"(?m)^(?!\s*[/*#])\s*[A-Za-z_][\w\s\*]*?\b" + esc_fn + r"\s*\(([^;{]*)\)"
    )
    sm = sig_re.search(body)
    if not sm:
        return None
    blob = sm.group(1).strip()
    if not blob or blob == "void":
        return []
    if "..." in blob:
        return None  # variadic → pozisyon kayması riski, propagasyona kapalı
    params: list[tuple[str, bool]] = []
    for part in _split_top_level_commas(blob):
        part = part.strip()
        if not part:
            continue
        toks = re.findall(r"[A-Za-z_]\w*", part.replace("*", " "))
        if not toks:
            return None  # ayrıştırılamayan parça → tüm imzaya güvenme
        params.append((toks[-1], "*" in part))
    return params


def _build_param_alias(body: str) -> dict[str, str]:
    """Caller gövdesinde `local_X = param_N;` copy-propagation alias'ı kur.

    O0 codegen her param'ı stack'e döküp reload eder (`local_18 = param_1;`),
    çağrı argümanı doğrudan param_N değil local kopyasıdır. Bu harita argümanı
    param'a geri çözer. GUARD: local_X birden fazla kez atanıyorsa (yeniden-
    kullanılan slot) alias'a GÜVENME (tasarım §6.2 #4).
    """
    alias: dict[str, str] = {}
    # RHS TAM olarak param_N olmalı (deyim `;` ile bitmeli). `local = param + 4`,
    # `local = param->f`, `local = param == 0` SAF KOPYA DEĞİLDİR — local param'ın
    # kendisi değil türevidir; bunları alias sayarsak yanlış miras yayılır
    # (precision katili). Cast'li kopya (`local = (ulong)param`) zaten `=` sonrası
    # `(` geldiği için eşleşmez → alias kurulmaz (güvenli-atla).
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*=\s*(param_\d+)\s*;", body):
        lhs, rhs = m.group(1), m.group(2)
        if lhs == rhs or _GHIDRA_AUTO_PARAM.match(lhs):
            continue
        # lhs kaç kez atanıyor? (tek düz atama = güvenilir alias)
        n = len(re.findall(r"\b" + re.escape(lhs) + r"\s*=(?!=)", body))
        if n == 1:
            alias[lhs] = rhs
    return alias


# ---------------------------------------------------------------------------
# ProcessPoolExecutor worker fonksiyonlari -- module-level (pickle edilebilir)
# ---------------------------------------------------------------------------

# Her worker process'te global olarak tutulan CVariableNamer instance'i.
# _init_heuristic_worker tarafindan doldurulur (initializer pattern).
_worker_namer: "CVariableNamer | None" = None


def _init_heuristic_worker(
    config: "Config",
    min_confidence: float,
    func_bodies: dict[str, str],
    string_refs_by_func: dict[str, list[str]],
    callee_names: dict[str, set[str]],
    caller_names: dict[str, set[str]],
    call_graph_in: dict[str, int],
    call_graph_out: dict[str, int],
    functions: dict[str, "_FunctionInfo"],
    func_by_name: dict[str, "_FunctionInfo"],
    strings: list["_StringRef"],
) -> None:
    """Her worker process'te bir kez calisir, read-only state'i kurar.

    CVariableNamer instance'i __new__ ile olusturulur (overhead yok),
    read-only alanlar set edilir.  Her worker kendi candidates dict'ini
    tutar -- shared state YOK, sonuclar ana process'e donduruluyor.
    """
    global _worker_namer
    namer = CVariableNamer.__new__(CVariableNamer)
    namer._config = config
    namer._min_confidence = min_confidence
    namer._func_bodies = func_bodies
    namer._string_refs_by_func = string_refs_by_func
    namer._callee_names = callee_names
    namer._caller_names = caller_names
    namer._call_graph_in = call_graph_in
    namer._call_graph_out = call_graph_out
    namer._functions = functions
    namer._func_by_name = func_by_name
    namer._strings = strings
    namer._candidates = {}
    namer._candidates_lock = threading.Lock()
    _worker_namer = namer


def _run_heuristics_worker(
    func_info: "_FunctionInfo",
) -> "tuple[str | None, dict[str, list[_NamingCandidate]]]":
    """Tek bir fonksiyon icin heuristik stratejileri calistir (process-safe).

    ProcessPoolExecutor icin module-level fonksiyon.  Global _worker_namer
    uzerinde stratejileri calistirir, sonra biriken candidates dict'ini
    dondurur.

    Returns:
        (error_name_or_none, {key: [NamingCandidate, ...]})
        Hata yoksa error_name None.
    """
    assert _worker_namer is not None, "_init_heuristic_worker cagirilmadi"
    namer = _worker_namer
    # Her cagri oncesi candidates temizle -- tek fonksiyon isleniyor
    namer._candidates.clear()
    try:
        namer._strategy_symbol(func_info)
        namer._strategy_string_context(func_info)
        namer._strategy_api_call(func_info)
        namer._strategy_call_graph(func_info)
        namer._strategy_dataflow(func_info)
        namer._strategy_type_based(func_info)
        namer._strategy_api_param_propagation(func_info)
        namer._strategy_body_param_naming(func_info)
        namer._strategy_fortran_in_stack(func_info)
        namer._strategy_local_var_naming(func_info)
        # candidates'i kopyala ve dondur (clear oncesi)
        result = dict(namer._candidates)
        return (None, result)
    except Exception as exc:
        result = dict(namer._candidates)
        return (func_info.name, result)


# ---------------------------------------------------------------------------
# Ana sinif
# ---------------------------------------------------------------------------

class CVariableNamer:
    """Ghidra decompiled C kodundaki otomatik isimleri anlamli isimlere ceviren sinif.

    9 heuristik + 1 ML strateji kullanir (symbol, string-context, api-call,
    call-graph, dataflow, type-based, api-param, local-var-naming,
    llm4decompile). Her strateji bir confidence degeri dondurur,
    en yuksek confidence'li isim secilir.

    Args:
        config: Merkezi konfigurasyon (Config).
        min_confidence: Bu esik altindaki oneriler uygulanmaz. Varsayilan 0.15.
    """

    # v1.5.5: Global prefix'ler -- bu prefix'li isimler TUM dosyalarda ayni
    # sekilde rename edilir (scope-independent). Fonksiyon-lokal degiskenler
    # (param_N, local_XX, iVar1 vb.) ise fonksiyon bazli scope'lanir.
    _GLOBAL_PREFIXES = ("DAT_", "FUN_", "PTR_", "switchD_", "caseD_", "thunk_")

    def __init__(self, config: Config, min_confidence: float = 0.15) -> None:
        self._config = config
        self._min_confidence = min_confidence

        # Dahili state -- analyze_and_rename sirasinda doldurulan
        self._functions: dict[str, _FunctionInfo] = {}     # address -> info
        self._func_by_name: dict[str, _FunctionInfo] = {}  # name -> info
        self._strings: list[_StringRef] = []
        self._string_refs_by_func: dict[str, list[str]] = {}  # func_addr -> [string_values]
        self._call_graph_in: dict[str, int] = {}   # address -> in_degree
        self._call_graph_out: dict[str, int] = {}  # address -> out_degree
        self._callee_names: dict[str, set[str]] = {}  # func_addr -> {callee_names}
        self._caller_names: dict[str, set[str]] = {}  # func_addr -> {caller_names}

        # C kodunun fonksiyon body'lerini tutar: func_name -> body_text
        self._func_bodies: dict[str, str] = {}

        # Sonuc: tum naming candidate'lar
        self._candidates: dict[str, list[_NamingCandidate]] = {}  # old_name -> [candidates]

        # Thread-safe erisim icin lock (_candidates dict'e concurrent yazim)
        self._candidates_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_and_rename(
        self,
        decompiled_dir: Path,
        functions_json: Path,
        strings_json: Path,
        call_graph_json: Path,
        output_dir: Path,
        pre_names: dict[str, str] | None = None,
        xrefs_json: Path | None = None,
    ) -> CNamingResult:
        """Tam pipeline: JSON'lari yukle, stratejileri calistir, C dosyalarini yeniden yaz.

        Args:
            decompiled_dir: Ghidra'dan gelen decompiled .c dosyalari dizini.
            functions_json: ghidra_functions.json yolu.
            strings_json: ghidra_strings.json yolu.
            call_graph_json: ghidra_call_graph.json yolu.
            output_dir: Isimlendirilmis C dosyalarinin yazilacagi dizin.
            pre_names: BinaryNameExtractor'dan gelen isimlendirmeler (opsiyonel).
            xrefs_json: ghidra_xrefs.json yolu (opsiyonel). Varsa string
                referanslarini ve callee bilgilerini fonksiyon bazinda yukler.

        Returns:
            CNamingResult: Tam sonuc.
        """
        errors: list[str] = []

        # 1. JSON dosyalarini yukle
        try:
            self._load_functions(functions_json)
        except (OSError, json.JSONDecodeError, KeyError) as exc:
            errors.append(f"ghidra_functions.json yuklenemedi: {exc}")
            logger.error("Functions JSON hatasi: %s", exc)

        try:
            self._load_strings(strings_json)
        except (OSError, json.JSONDecodeError, KeyError) as exc:
            errors.append(f"ghidra_strings.json yuklenemedi: {exc}")
            logger.error("Strings JSON hatasi: %s", exc)

        try:
            self._load_call_graph(call_graph_json)
        except (OSError, json.JSONDecodeError, KeyError) as exc:
            errors.append(f"ghidra_call_graph.json yuklenemedi: {exc}")
            logger.error("Call graph JSON hatasi: %s", exc)

        # Xrefs dosyasi varsa yukle (string_refs_by_func'u zenginlestirir)
        if xrefs_json is not None:
            try:
                self._load_xrefs(xrefs_json)
            except (OSError, json.JSONDecodeError, KeyError) as exc:
                errors.append(f"ghidra_xrefs.json yuklenemedi: {exc}")
                logger.warning("Xrefs JSON hatasi (atlaniyor): %s", exc)

        # Fonksiyon yoksa yapacak bir sey yok
        if not self._functions:
            return CNamingResult(
                success=False,
                errors=errors or ["Hicbir fonksiyon bilgisi yuklenemedi"],
            )

        # 2. C dosyalarini oku, fonksiyon body'lerini cikar
        c_files = sorted(decompiled_dir.glob("*.c")) if decompiled_dir.exists() else []
        if not c_files:
            errors.append(f"Decompiled C dosyasi bulunamadi: {decompiled_dir}")
            return CNamingResult(success=False, errors=errors)

        logger.info(
            "C namer basliyor: %d fonksiyon, %d string, %d C dosyasi",
            len(self._functions),
            len(self._strings),
            len(c_files),
        )

        # v1.2.2: Dosya okuma + body extraction paralel (10 P-core)
        def _read_and_extract(c_file: Path) -> tuple[str, str | None]:
            try:
                content = c_file.read_text(encoding="utf-8", errors="replace")
                return (content, None)
            except OSError as exc:
                return ("", f"C dosyasi okunamadi: {c_file.name}: {exc}")

        with ThreadPoolExecutor(max_workers=CPU_PERF_CORES) as pool:
            read_results = list(pool.map(_read_and_extract, c_files))

        for content, err in read_results:
            if err:
                errors.append(err)
            elif content:
                self._extract_function_bodies(content)

        # 3. Her fonksiyon icin 9 stratejiyi calistir (paralel -- ProcessPool, GIL bypass)
        self._candidates.clear()

        func_list = list(self._functions.values())
        total_funcs = len(func_list)
        num_workers = min(CPU_PERF_CORES, os.cpu_count() or CPU_PERF_CORES)
        logger.info(
            "Paralel strateji baslatiyor: %d fonksiyon, %d process (ProcessPool)",
            total_funcs, num_workers,
        )

        # --- Heuristik stratejiler (1-9) paralel (ProcessPoolExecutor) ---
        # Her worker process'te _init_heuristic_worker ile CVariableNamer
        # instance'i olusturulur.  Read-only veriler initargs ile aktarilir.
        # Her worker _run_heuristics_worker ile tek fonksiyon isler,
        # kendi candidates dict'ini dondurur.  Ana process merge eder.
        processed = 0
        failed = 0

        # callee_names dict'inde set'ler var -- set pickle edilebilir, OK
        initargs = (
            self._config,
            self._min_confidence,
            self._func_bodies,
            self._string_refs_by_func,
            self._callee_names,
            self._caller_names,
            self._call_graph_in,
            self._call_graph_out,
            self._functions,
            self._func_by_name,
            self._strings,
        )

        with ProcessPoolExecutor(
            max_workers=num_workers,
            initializer=_init_heuristic_worker,
            initargs=initargs,
        ) as proc_pool:
            futs = {
                proc_pool.submit(_run_heuristics_worker, fi): fi
                for fi in func_list
            }
            try:
                for future in as_completed(futs, timeout=1200):
                    processed += 1
                    try:
                        err_name, worker_candidates = future.result(timeout=300)
                    except TimeoutError:
                        failed += 1
                        errors.append(f"Heuristik timeout: {futs[future].name}")
                        continue
                    except Exception as exc:
                        failed += 1
                        errors.append(
                            f"Heuristik worker hatasi ({futs[future].name}): {exc}"
                        )
                        continue

                    if err_name:
                        failed += 1
                        errors.append(f"Heuristik strateji hatasi: {err_name}")

                    # Worker'dan gelen candidates'i ana dict'e merge et
                    for key, cands in worker_candidates.items():
                        if key not in self._candidates:
                            self._candidates[key] = []
                        self._candidates[key].extend(cands)

                    if processed % 500 == 0:
                        logger.info(
                            "  Heuristik ilerleme: %d/%d fonksiyon (%.0f%%)",
                            processed, total_funcs, 100.0 * processed / total_funcs,
                        )
            except TimeoutError:
                errors.append(
                    "Heuristik asamasi toplam timeout (1200s) asildi, "
                    "bazi fonksiyonlar islenmemis olabilir"
                )
            except BrokenExecutor as exc:
                errors.append(f"Heuristik ProcessPool crash: {exc}")

        logger.info(
            "Heuristik stratejiler tamamlandi: %d basarili, %d hatali",
            processed - failed, failed,
        )

        # NOT (2026-05-13): LLM4Decompile blogu kaldirildi (B11, feedback_no_llm.md).

        # Cephe 1b — Alg 1: cross-function pass-through param miras (sıralı post-pass).
        # Worker'lar per-fonksiyon izole (bir worker komşu fonksiyonun adayını
        # göremez), bu yüzden gather'dan SONRA, çözümlemeden ÖNCE main-process'te
        # çalışır. Yalnız BOŞ param_N'lere miras verir (mevcut adayı EZMEZ).
        try:
            self._propagate_passthrough_params()
        except Exception as exc:  # savunmacı: propagasyon hatası pipeline'ı düşürmesin
            errors.append(f"pass-through propagasyon hatasi: {exc}")
            logger.warning("pass-through propagasyon atlandi: %s", exc, exc_info=True)

        # 4. En yuksek confidence'li ismi sec
        naming_map: dict[str, str] = {}
        by_strategy: dict[str, int] = {}
        confidence_map: dict[str, float] = {}  # old_name -> best.confidence
        strategy_map: dict[str, str] = {}      # old_name -> best.strategy
        high_conf = 0
        medium_conf = 0
        low_conf = 0
        used_new_names: set[str] = set()  # Cakisma onleme

        # Pre-names: BinaryNameExtractor'dan gelen yuksek guvenirlikli isimler
        if pre_names:
            for old_name, new_name in pre_names.items():
                if not old_name or len(old_name) < 2:
                    continue
                # CamelCase'i koru (Swift/ObjC isimleri icin)
                has_camel = any(c.isupper() for c in new_name[1:]) if len(new_name) > 1 else False
                sanitized = _sanitize_c_name(new_name, preserve_case=has_camel) if hasattr(new_name, '__len__') else str(new_name)
                if sanitized and sanitized != "unnamed" and sanitized not in used_new_names:
                    naming_map[old_name] = sanitized
                    used_new_names.add(sanitized)
                    by_strategy["binary_extract"] = by_strategy.get("binary_extract", 0) + 1
                    # pre_names = FIX-1 main / gnulib fingerprint / boilerplate /
                    # binary_extractor -> yuksek guven (deterministik kurtarma).
                    confidence_map[old_name] = 0.95
                    strategy_map[old_name] = "binary_extract"
                    high_conf += 1
            logger.info("Pre-names: %d isim binary extractor'dan eklendi", len(pre_names))

        # v1.5.5: Scope-aware naming map -- fonksiyon-lokal degiskenleri
        # ayri tutarak farkli fonksiyonlardaki ayni Ghidra otomatik ismin
        # (iVar1, param_1 vb.) birbirine karismamasi saglanir.
        per_func_maps: dict[str, dict[str, str]] = {}  # func_name -> {old: new}
        global_map: dict[str, str] = {}  # DAT_, FUN_ gibi globaller

        for key, candidates in self._candidates.items():
            if not candidates:
                continue

            # Confidence'a gore sirala, en yuksek olan kazanir
            candidates.sort(key=lambda c: c.confidence, reverse=True)
            best = candidates[0]

            if best.confidence < self._min_confidence:
                continue

            if "::" in key:
                func_name, old_name = key.split("::", 1)
            else:
                func_name = ""
                old_name = key

            # FIX (2026-07-12): GLOBAL fonksiyon adlarinda adres-gomulu/jenerik
            # heuristik stratejileri (call_graph -> helper_<adr>/dispatcher_<adr>,
            # callee_based -> <prefix>_<adr>, api_call -> manage_memory/calls_X)
            # naming_map'e KOYMA. Bunlar GT ile eslesmez (precision katili) ve
            # semantik bilgi degeri ~0 (adres = anlam degil). Yuksek-guven kaynaklar
            # (symbol/string_context/pre_names/api_param) gecer. Berke precision
            # sozlesmesi (150/160): dogru koyamayacaksan FUN_xxx birak. Bu isimler
            # ileride korroborasyon (byte-sig/cfg_iso/BSim) veya Claude katmaninda
            # yeniden degerlendirilir. (per_func degisken isimleri etkilenmez.)
            if not func_name and best.strategy in (
                "call_graph", "callee_based", "api_call",
            ):
                continue

            # Extractor zaten isimlendirdiyse atla (global map)
            if old_name in naming_map:
                continue

            # Cakisma kontrolu: ayni yeni isim birden fazla eski isme verilmesin
            new_name = best.new_name
            if new_name in used_new_names:
                # Suffix ekle
                suffix = 2
                while f"{new_name}_{suffix}" in used_new_names:
                    suffix += 1
                new_name = f"{new_name}_{suffix}"

            used_new_names.add(new_name)
            by_strategy[best.strategy] = by_strategy.get(best.strategy, 0) + 1
            # Gercek confidence + strateji'yi disa aktar (NameMerger'in flat 0.70
            # duzlemesini onlemek icin). Zayif yapisal stratejiler (call_graph,
            # callee_based) burada gercek 0.5-0.65 tasir; merger'da c_namer_structural
            # dusuk-agirlik source'una etiketlenip UNK esigi altinda elenir.
            confidence_map[old_name] = best.confidence
            strategy_map[old_name] = best.strategy

            if best.confidence >= 0.7:
                high_conf += 1
            elif best.confidence >= 0.4:
                medium_conf += 1
            else:
                low_conf += 1

            if func_name:
                # Fonksiyon-bazli lokal rename
                per_func_maps.setdefault(func_name, {})[old_name] = new_name
            else:
                # Global rename (DAT_, FUN_ vb.)
                global_map[old_name] = new_name

        # naming_map = global_map + pre_names (flat map, backward compat)
        naming_map.update(global_map)

        # Istatistik: toplam lokal rename sayisi
        total_local = sum(len(m) for m in per_func_maps.values())

        logger.info(
            "Isimlendirme karari: %d global + %d fonksiyon-lokal (%d fonksiyon), "
            "%d high, %d medium, %d low confidence",
            len(naming_map),
            total_local,
            len(per_func_maps),
            high_conf,
            medium_conf,
            low_conf,
        )
        for strategy, count in sorted(by_strategy.items(), key=lambda x: -x[1]):
            logger.info("  Strateji %s: %d isim", strategy, count)

        # 5. C dosyalarina uygula (paralel -- 10 core)
        # v1.5.5: Global AhoReplacer + per-function AhoReplacer
        output_dir.mkdir(parents=True, exist_ok=True)
        output_files: list[Path] = []

        # Global Aho-Corasick automaton: DAT_, FUN_ gibi tum dosyalarda gecerli
        _global_replacer = AhoReplacer(naming_map) if naming_map else None

        # Per-function AhoReplacer'lar onceden olustur (thread-safe)
        _func_replacers: dict[str, AhoReplacer] = {}
        for fn, fmap in per_func_maps.items():
            if fmap:
                _func_replacers[fn] = AhoReplacer(fmap)

        def _rename_one(c_file):
            content = c_file.read_text(encoding="utf-8", errors="replace")

            # 1. Global replace (DAT_, FUN_ vb. -- tum dosyalarda)
            if _global_replacer:
                content = _global_replacer.replace(content)

            # 2. Fonksiyon-bazli replace: dosya adi = fonksiyon adi
            # Ghidra her fonksiyonu ayri .c dosyasina yazdigindan
            # dosya stem'i fonksiyon adidir (orn: FUN_001234ab.c)
            func_name = c_file.stem
            func_replacer = _func_replacers.get(func_name)
            if func_replacer:
                content = func_replacer.replace(content)

            out_path = output_dir / c_file.name
            out_path.write_text(content, encoding="utf-8")
            return out_path

        with ThreadPoolExecutor(max_workers=CPU_PERF_CORES) as pool:
            for result in pool.map(_rename_one, c_files):
                output_files.append(result)

        # Naming map'i de JSON olarak kaydet (global + per-func ayri)
        map_file = output_dir / "naming_map.json"
        try:
            # Backward compat: flat map + per_func_maps ayri bolumde
            full_map = {
                "global": naming_map,
                "per_function": per_func_maps,
            }
            map_file.write_text(
                json.dumps(full_map, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError as e:
            logger.debug("naming_map.json yazilamadi (%s): %s", map_file, e, exc_info=True)

        total_renamed = len(naming_map) + total_local
        logger.info(
            "C namer tamamlandi: %d sembol yeniden adlandirildi "
            "(%d global, %d lokal), %d dosya yazildi",
            total_renamed,
            len(naming_map),
            total_local,
            len(output_files),
        )

        # Ornek mappings
        for old, new in list(naming_map.items())[:15]:
            logger.info("  [global] %s -> %s", old, new)
        for fn, fmap in list(per_func_maps.items())[:5]:
            for old, new in list(fmap.items())[:3]:
                logger.info("  [%s] %s -> %s", fn, old, new)

        return CNamingResult(
            success=True,
            output_files=output_files,
            naming_map=naming_map,
            total_renamed=total_renamed,
            by_strategy=by_strategy,
            high_confidence=high_conf,
            medium_confidence=medium_conf,
            low_confidence=low_conf,
            errors=errors,
            confidence_map=confidence_map,
            strategy_map=strategy_map,
        )

    # ------------------------------------------------------------------
    # JSON yukleyiciler
    # ------------------------------------------------------------------

    def _load_functions(self, path: Path) -> None:
        """ghidra_functions.json'u yukle."""
        if not path.exists():
            logger.warning("ghidra_functions.json bulunamadi: %s", path)
            return

        data = json.loads(path.read_text(encoding="utf-8"))
        funcs = data.get("functions", [])

        self._functions.clear()
        self._func_by_name.clear()

        for raw in funcs:
            info = _FunctionInfo(
                name=raw.get("name", ""),
                address=raw.get("address", ""),
                size=raw.get("size", 0),
                params=raw.get("parameters", raw.get("params", [])),
                return_type=raw.get("return_type", ""),
                calling_convention=raw.get("calling_convention", ""),
            )
            if info.address:
                self._functions[info.address] = info
            if info.name:
                self._func_by_name[info.name] = info

        logger.info("Fonksiyonlar yuklendi: %d adet", len(self._functions))

    def _load_strings(self, path: Path) -> None:
        """ghidra_strings.json'u yukle, fonksiyona gore indeksle.

        Buyuk dosyalar (>50MB) icin lazy/streaming mode: tum JSON'u RAM'e
        almak yerine satirlik okuyarak sadece fonksiyon-string indeksini
        (_string_refs_by_func) olusturur. _strings listesi buyuk dosyada
        bos kalir -- c_namer stratejileri zaten _string_refs_by_func
        uzerinden calisir.
        """
        if not path.exists():
            logger.warning("ghidra_strings.json bulunamadi: %s", path)
            return

        file_size = path.stat().st_size
        # 50MB ustu dosyalar icin streaming mode
        large_file_threshold = 50 * 1024 * 1024

        if file_size > large_file_threshold:
            self._load_strings_streaming(path, file_size)
        else:
            self._load_strings_full(path)

    def _load_strings_full(self, path: Path) -> None:
        """Kucuk dosyalar icin tam JSON yukleme (mevcut davranis)."""
        data = json.loads(path.read_text(encoding="utf-8"))
        raw_strings = data.get("strings", [])

        self._strings.clear()
        self._string_refs_by_func.clear()

        for raw in raw_strings:
            # refs veya function alanini kullan
            refs = raw.get("refs", [])
            func_field = raw.get("function")
            if not refs and func_field:
                refs = [func_field] if isinstance(func_field, str) else []

            # xrefs alanindaki fonksiyon adreslerini de refs'e ekle
            # (string_extractor.py xref fix ciktisi)
            raw_xrefs = raw.get("xrefs", [])
            if raw_xrefs:
                existing_refs = set(refs)
                for xr in raw_xrefs:
                    if isinstance(xr, dict):
                        func_addr_ref = xr.get("from_func_addr")
                        if func_addr_ref and func_addr_ref not in existing_refs:
                            refs.append(func_addr_ref)
                            existing_refs.add(func_addr_ref)

            sref = _StringRef(
                value=raw.get("value", ""),
                address=raw.get("address", ""),
                refs=refs,
            )
            self._strings.append(sref)

            # Fonksiyon adresine gore indeksle
            for func_addr in sref.refs:
                if func_addr not in self._string_refs_by_func:
                    self._string_refs_by_func[func_addr] = []
                self._string_refs_by_func[func_addr].append(sref.value)

        logger.info(
            "String'ler yuklendi: %d adet, %d fonksiyona referans",
            len(self._strings),
            len(self._string_refs_by_func),
        )

    def _load_strings_streaming(self, path: Path, file_size: int) -> None:
        """Buyuk dosyalar icin streaming JSON parsing.

        Tum JSON'u RAM'e almak yerine json.JSONDecoder ile incremental
        parse yapar. Sadece fonksiyon-string indeksini olusturur,
        _StringRef objeleri RAM'de tutulmaz.
        """
        logger.info(
            "Buyuk strings dosyasi (%.1f MB): streaming mode ile yukleniyor",
            file_size / (1024 * 1024),
        )

        self._strings.clear()
        self._string_refs_by_func.clear()

        string_count = 0

        # ijson varsa streaming JSON, yoksa chunk'li okuma
        try:
            import ijson
            with open(path, "rb") as f:
                # "strings.item" prefix'i ile her string objesini teker teker al
                for raw in ijson.items(f, "strings.item"):
                    refs = raw.get("refs", [])
                    func_field = raw.get("function")
                    if not refs and func_field:
                        refs = [func_field] if isinstance(func_field, str) else []

                    raw_xrefs = raw.get("xrefs", [])
                    if raw_xrefs:
                        existing_refs = set(refs)
                        for xr in raw_xrefs:
                            if isinstance(xr, dict):
                                func_addr_ref = xr.get("from_func_addr")
                                if func_addr_ref and func_addr_ref not in existing_refs:
                                    refs.append(func_addr_ref)
                                    existing_refs.add(func_addr_ref)

                    value = raw.get("value", "")
                    string_count += 1

                    for func_addr in refs:
                        if func_addr not in self._string_refs_by_func:
                            self._string_refs_by_func[func_addr] = []
                        self._string_refs_by_func[func_addr].append(value)

                    if string_count % 50000 == 0:
                        logger.info(
                            "Streaming strings: %d string islendi, %d fonksiyon indekslendi",
                            string_count, len(self._string_refs_by_func),
                        )

        except ImportError:
            # ijson yok -- fallback: standart json ile oku ama string objelerini tutma
            logger.info("ijson bulunamadi, standart json fallback (daha fazla RAM kullanacak)")
            data = json.loads(path.read_text(encoding="utf-8"))
            raw_strings = data.get("strings", [])

            for raw in raw_strings:
                refs = raw.get("refs", [])
                func_field = raw.get("function")
                if not refs and func_field:
                    refs = [func_field] if isinstance(func_field, str) else []

                raw_xrefs = raw.get("xrefs", [])
                if raw_xrefs:
                    existing_refs = set(refs)
                    for xr in raw_xrefs:
                        if isinstance(xr, dict):
                            func_addr_ref = xr.get("from_func_addr")
                            if func_addr_ref and func_addr_ref not in existing_refs:
                                refs.append(func_addr_ref)
                                existing_refs.add(func_addr_ref)

                value = raw.get("value", "")
                string_count += 1

                for func_addr in refs:
                    if func_addr not in self._string_refs_by_func:
                        self._string_refs_by_func[func_addr] = []
                    self._string_refs_by_func[func_addr].append(value)

            # data referansini hemen serbest birak
            del data, raw_strings

        logger.info(
            "String'ler (streaming) yuklendi: %d adet, %d fonksiyona referans",
            string_count,
            len(self._string_refs_by_func),
        )

    def _load_call_graph(self, path: Path) -> None:
        """ghidra_call_graph.json'u yukle, in/out degree hesapla."""
        if not path.exists():
            logger.warning("ghidra_call_graph.json bulunamadi: %s", path)
            return

        data = json.loads(path.read_text(encoding="utf-8"))
        raw_nodes = data.get("nodes", {})
        edges = data.get("edges", [])

        self._call_graph_in.clear()
        self._call_graph_out.clear()
        self._callee_names.clear()
        self._caller_names.clear()

        # nodes dict veya list olabilir
        if isinstance(raw_nodes, dict):
            nodes = list(raw_nodes.values())
        elif isinstance(raw_nodes, list):
            nodes = raw_nodes
        else:
            nodes = []

        # Adres -> isim map'i
        addr_to_name: dict[str, str] = {}
        for node in nodes:
            if isinstance(node, str):
                continue
            addr = node.get("address", "")
            name = node.get("name", "")
            if addr:
                addr_to_name[addr] = name
                self._call_graph_in[addr] = 0
                self._call_graph_out[addr] = 0
                self._callee_names[addr] = set()
                self._caller_names[addr] = set()

        for edge in edges:
            src = edge.get("from", "")
            dst = edge.get("to", "")

            if src in self._call_graph_out:
                self._call_graph_out[src] += 1
            if dst in self._call_graph_in:
                self._call_graph_in[dst] += 1

            # Callee/caller isimlerini kaydet
            dst_name = addr_to_name.get(dst, "")
            src_name = addr_to_name.get(src, "")
            if src in self._callee_names and dst_name:
                self._callee_names[src].add(dst_name)
            if dst in self._caller_names and src_name:
                self._caller_names[dst].add(src_name)

        logger.info(
            "Call graph yuklendi: %d node, %d edge",
            len(nodes),
            len(edges),
        )

    def _load_xrefs(self, path: Path) -> None:
        """ghidra_xrefs.json'u yukle, string referanslarini ve callee'leri zenginlestir.

        Xrefs dosyasi fonksiyon bazinda strings_used ve functions_called bilgisi icerir.
        Bu bilgiler ghidra_strings.json'daki bos refs alanlarini tamamlar.
        """
        if not path.exists():
            logger.warning("ghidra_xrefs.json bulunamadi: %s", path)
            return

        data = json.loads(path.read_text(encoding="utf-8"))
        fxrefs = data.get("function_xrefs", {})

        if not fxrefs:
            logger.info("Xrefs dosyasinda function_xrefs bulunamadi")
            return

        enriched_strings = 0
        enriched_callees = 0

        for addr, info in fxrefs.items():
            func_name = info.get("name", "")
            func_addr = info.get("address", addr)

            # String referanslarini ekle
            strings_used = info.get("strings_used", [])
            if strings_used:
                if func_addr not in self._string_refs_by_func:
                    self._string_refs_by_func[func_addr] = []
                existing = set(self._string_refs_by_func[func_addr])
                for s in strings_used:
                    val = s if isinstance(s, str) else s.get("value", "") if isinstance(s, dict) else ""
                    if val and val not in existing:
                        self._string_refs_by_func[func_addr].append(val)
                        existing.add(val)
                        enriched_strings += 1

            # Callee isimlerini ekle (call graph'i tamamla)
            funcs_called = info.get("functions_called", [])
            if funcs_called and func_addr in self._callee_names:
                for called in funcs_called:
                    cname = called.get("name", "") if isinstance(called, dict) else str(called)
                    if cname:
                        if cname not in self._callee_names[func_addr]:
                            self._callee_names[func_addr].add(cname)
                            enriched_callees += 1

        logger.info(
            "Xrefs yuklendi: %d ek string ref, %d ek callee (toplam %d fonksiyon)",
            enriched_strings, enriched_callees, len(fxrefs),
        )

    # ------------------------------------------------------------------
    # C dosyasindan fonksiyon body cikarma
    # ------------------------------------------------------------------

    def _extract_function_bodies(self, content: str) -> None:
        """C dosyasindan fonksiyon body'lerini cikar (basit heuristic).

        Ghidra ciktisi genelde:
            return_type func_name(params) {
                ...
            }
        seklindedir.
        """
        # Fonksiyon baslangicini bul: tip + isim + parantez + {
        # Basit yaklasim: her bilinen fonksiyon ismi icin body'yi bul
        lines = content.split("\n")

        current_func: str | None = None
        brace_depth = 0
        body_lines: list[str] = []

        # Aho-Corasick ile fonksiyon isimlerini ara -- O(N+M)
        # (Eski yontem: devasa alternation regex O(N*M), 22K+ isim)
        all_names = list(self._func_by_name.keys())
        func_finder = AhoFinder(all_names) if all_names else None
        # Suffix dogrulama: isimden sonra \s*\([^)]*\)\s*\{?\s*$ olmali
        _func_suffix_re = re.compile(r"\s*\([^)]*\)\s*\{?\s*$")

        for line in lines:
            if current_func is None:
                if func_finder:
                    # Satirdaki TUM fonksiyon isimlerini bul
                    # (ayni isim birden fazla yerde olabilir, suffix uyani ariyoruz)
                    all_hits = func_finder.find_all_words(line)
                    matched_func = None
                    for start_pos, name in all_hits:
                        after = line[start_pos + len(name):]
                        if _func_suffix_re.match(after):
                            matched_func = name
                            break
                    if matched_func:
                        current_func = matched_func
                        brace_depth = _count_braces(line)
                        body_lines = [line]
            else:
                body_lines.append(line)
                brace_depth += _count_braces(line)

                if brace_depth <= 0 and "{" in "".join(body_lines):
                    # Fonksiyon bitti
                    self._func_bodies[current_func] = "\n".join(body_lines)
                    current_func = None
                    body_lines = []

        # Son fonksiyon kapanmamis olabilir
        if current_func and body_lines:
            self._func_bodies[current_func] = "\n".join(body_lines)

    # ------------------------------------------------------------------
    # Strateji calistirma
    # ------------------------------------------------------------------

    def _run_all_strategies(self, func_info: _FunctionInfo) -> None:
        """Bir fonksiyon icin tum 8 stratejiyi calistir (backward compat).

        NOT: analyze_and_rename artik paralel calistirma kullaniyor.
        Bu metot harici kullanim veya test icin korundu.
        """
        self._run_heuristic_strategies(func_info)
        # NOT (2026-05-13): _strategy_llm4decompile kaldirildi (B11)

    def _run_heuristic_strategies(self, func_info: _FunctionInfo) -> None:
        """Heuristik stratejileri calistir (ML haric, thread-safe)."""
        self._strategy_symbol(func_info)
        self._strategy_string_context(func_info)
        self._strategy_api_call(func_info)
        self._strategy_call_graph(func_info)
        self._strategy_dataflow(func_info)
        self._strategy_type_based(func_info)
        self._strategy_api_param_propagation(func_info)
        self._strategy_body_param_naming(func_info)
        self._strategy_fortran_in_stack(func_info)
        self._strategy_local_var_naming(func_info)

    def _add_candidate(self, candidate: _NamingCandidate, func_name: str = "") -> None:
        """Candidate listesine ekle (thread-safe).

        v1.5.5: Scope-aware key -- fonksiyon-lokal degiskenler (param_N,
        local_XX, iVar1 vb.) ``func_name::old_name`` formatinda key alir.
        Boylece farkli fonksiyonlardaki ayni otonom isim birbirine karismaz.

        Global semboller (DAT_, FUN_, PTR_ vb.) ise eski davranisi korur:
        tek key = old_name, tum dosyalarda ayni sekilde rename edilir.
        """
        with self._candidates_lock:
            # Global prefix'ler scope-independent kalmali
            if func_name and not candidate.old_name.startswith(self._GLOBAL_PREFIXES):
                key = "%s::%s" % (func_name, candidate.old_name)
            else:
                key = candidate.old_name
            if key not in self._candidates:
                self._candidates[key] = []
            self._candidates[key].append(candidate)

    # ------------------------------------------------------------------
    # Cephe 1b — Alg 1: cross-function pass-through param miras
    # ------------------------------------------------------------------

    def _build_resolved_param_map(
        self,
        _sig_cache: dict[str, list[tuple[str, bool]] | None] | None = None,
    ) -> dict[str, dict[int, tuple[str, float]]]:
        """func -> {pozisyon: (en-iyi-aday-adı, conf)} çözülmüş param haritası.

        Kaynak = mevcut self._candidates (body_param/dataflow/type_based/api_param
        + önceki propagasyon turları). Pozisyon imza sırasından (`_extract_sig_
        params`) gelir — param_N indeksine değil imza pozisyonuna bağlıdır, böylece
        karışık (kısmen adlandırılmış) imzalarda da hizalama doğru kalır.

        İŞ 2 (2026-07-17): ``_sig_cache`` verilirse imza-param çıkarımı memoize
        edilir. ``_extract_sig_params`` gövdenin SAF fonksiyonu ve _func_bodies
        propagasyon boyunca değişmez → fixed-point turları arasında (5×'e kadar)
        yeniden hesaplamak boşunadır. Davranış-nötr: sonuç birebir aynı, yalnız
        tekrar hesap önlenir. Cache yoksa (None) eski davranış korunur.
        """
        resolved: dict[str, dict[int, tuple[str, float]]] = {}
        for fname, body in self._func_bodies.items():
            if _sig_cache is None:
                params = _extract_sig_params(body, fname)
            elif fname in _sig_cache:
                params = _sig_cache[fname]
            else:
                params = _extract_sig_params(body, fname)
                _sig_cache[fname] = params
            if not params:
                continue
            posmap: dict[int, tuple[str, float]] = {}
            for i, (pname, _is_ptr) in enumerate(params):
                cands = self._candidates.get("%s::%s" % (fname, pname))
                if not cands:
                    continue
                best = max(cands, key=lambda c: c.confidence)
                posmap[i] = (best.new_name, best.confidence)
            if posmap:
                resolved[fname] = posmap
        return resolved

    def _propagate_passthrough_params(self) -> None:
        """Caller'ın BOŞ param_N'lerine, çağrılan iç fonksiyonun çözülmüş param
        adını miras ettir (cross-function pass-through, sıralı post-pass).

        call-graph.json argüman POZİSYONU içermez → pozisyon yalnız decompiled
        `.c` gövdesindeki çağrı-site ifadesinde var. Bu metod caller gövdesini
        parse eder (`_split_args_balanced` reuse), copy-propagation alias'ıyla
        (`local_X=param_N`) argümanı caller param'ına çözer, callee'nin o pozisyon-
        daki çözülmüş adını yukarı taşır. Fixed-point (transitif zincir) + 7 guard
        (tasarım §6.2). Miras conf = kaynak × sönümleme; çözümleme en yüksek conf'u
        seçtiğinden fonksiyonun KENDİ doğrudan-kullanım sinyali mirası yener.
        """
        from karadul.reconstruction.api_param_db import APIParamDB
        split_args = APIParamDB._split_args_balanced
        extract_args = APIParamDB._extract_balanced_args

        # İŞ 2 (2026-07-17, davranış-nötr memoization) — imza-param çıkarımı ve
        # copy-propagation alias'ı gövdenin SAF fonksiyonudur; _func_bodies
        # propagasyon boyunca DEĞİŞMEZ → fixed-point turları arasında (5×'e kadar)
        # yeniden hesaplamak boşunadır. Bir kez hesapla, hem caller döngüsünde
        # hem _build_resolved_param_map'te (aynı cache dict) reuse et. Sonuç
        # birebir aynı; yalnız tekrar hesap önlenir.
        # NOT: `_sig_params` hem callee (aşağıdaki n_params) hem caller (cparams)
        # imzasını verir — eski ayrı callee_param_cache ile birleştirildi.
        _sig_params_cache: dict[str, list[tuple[str, bool]] | None] = {}

        def _sig_params(name: str) -> list[tuple[str, bool]] | None:
            if name not in _sig_params_cache:
                _sig_params_cache[name] = _extract_sig_params(
                    self._func_bodies.get(name, ""), name)
            return _sig_params_cache[name]

        _alias_cache: dict[str, dict[str, str]] = {}

        def _param_alias(name: str) -> dict[str, str]:
            a = _alias_cache.get(name)
            if a is None:
                a = _build_param_alias(self._func_bodies.get(name, ""))
                _alias_cache[name] = a
            return a

        # İŞ 2 — regex-derleme cache. `_call_arg_lists` her callee için taze
        # `re.compile(re.escape(callee)+...)` derliyordu; binlerce distinct callee
        # Python'un 512-kapasiteli `re._cache`'ini thrash eder (aynı callee her
        # tur + her caller için yeniden derlenir). Derlenen deseni callee başına
        # bir kez cache'le — desen callee'nin saf fonksiyonu, davranış birebir.
        _pat_cache: dict[str, "re.Pattern[str]"] = {}

        def _callee_call_pattern(callee: str) -> "re.Pattern[str]":
            pat = _pat_cache.get(callee)
            if pat is None:
                pat = re.compile(r"(?<![\w])" + re.escape(callee) + r"\s*\(")
                _pat_cache[callee] = pat
            return pat

        def _call_arg_lists(body: str, callee: str) -> list[list[str]]:
            """callee(args) çağrılarının argüman-listelerini döndür."""
            out: list[list[str]] = []
            for m in _callee_call_pattern(callee).finditer(body):
                paren = m.end() - 1
                args_str = extract_args(body, paren)
                if args_str is None:
                    continue
                out.append(split_args(args_str))
            return out

        propagated: set[tuple[str, int]] = set()  # (caller, pos) — çift-miras önleme
        added_total = 0
        callers = list(self._func_bodies.keys())

        for _round in range(_PASSTHROUGH_MAX_ROUNDS):
            # İŞ 2: sig-cache'i paylaş — resolved map imza çıkarımını memoize eder,
            # sonraki caller döngüsü ve turlar aynı cache'ten okur.
            resolved = self._build_resolved_param_map(_sig_cache=_sig_params_cache)
            if not resolved:
                break
            new_this_round = 0
            for caller in callers:
                body = self._func_bodies.get(caller, "")
                if not body or "param_" not in body:
                    continue
                cparams = _sig_params(caller)  # İŞ 2: memoize (statik)
                if not cparams:
                    continue
                # caller param adı -> imza pozisyonu
                cpos = {pname: i for i, (pname, _ip) in enumerate(cparams)}
                alias = _param_alias(caller)  # İŞ 2: memoize (statik)

                for callee, cres in resolved.items():
                    if callee == caller:
                        continue  # self-recursion (self-edge) atla
                    # Ucuz ön-eleme: callee adı caller gövdesinde HİÇ geçmiyorsa
                    # çağrı-site yok → imza çıkarma + regex taramasını atla. Bu
                    # O(F×R×|gövde|) iç döngüyü büyük binary'lerde (binlerce fn)
                    # pratik hale getirir; substring yoksa çağrı da yok →
                    # davranış birebir korunur.
                    if callee not in body:
                        continue
                    callee_params = _sig_params(callee)  # İŞ 2: birleşik cache
                    if callee_params is None:
                        continue  # variadic/ayrıştırılamaz → pozisyon güvensiz
                    n_params = len(callee_params)
                    for args in _call_arg_lists(body, callee):
                        # Guard #3: arg sayısı == callee param sayısı (variadic/
                        # kısmi-inline → pozisyon kayması → yanlış miras).
                        if len(args) != n_params:
                            continue
                        for k, arg in enumerate(args):
                            src = cres.get(k)
                            if src is None:
                                continue  # callee bu pozisyonu adlandırmamış
                            src_name, src_conf = src
                            # Guard #1: kaynak güveni eşiği.
                            if src_conf < _PASSTHROUGH_MIN_SOURCE_CONF:
                                continue
                            # Argümanı caller param'ına çöz (düz param_N veya
                            # tek-atamalı local_X alias'ı; aritmetik/adres-alma
                            # → karmaşık ifade, atla — tasarım §6.3).
                            arg = arg.strip()
                            if _GHIDRA_AUTO_PARAM.match(arg):
                                pname = arg
                            elif arg in alias:
                                pname = alias[arg]
                            else:
                                continue
                            pos = cpos.get(pname)
                            if pos is None:
                                continue
                            # Guard #2: yalnız BOŞ param_N hedefi.
                            tgt_name, tgt_is_ptr = cparams[pos]
                            if not _GHIDRA_AUTO_PARAM.match(tgt_name):
                                continue
                            if (caller, pos) in propagated:
                                continue
                            if self._candidates.get("%s::%s" % (caller, tgt_name)):
                                continue  # zaten adayı var → EZME
                            # Guard #5: tip uyumu (açık ptr↔scalar çelişkisi atla).
                            if tgt_is_ptr != callee_params[k][1]:
                                continue
                            # Guard #6: sönümleme + min_confidence tabanı.
                            new_conf = src_conf * _PASSTHROUGH_DAMPING
                            if new_conf < self._min_confidence:
                                continue
                            self._add_candidate(_NamingCandidate(
                                old_name=tgt_name,
                                new_name=src_name,
                                confidence=new_conf,
                                strategy="passthrough",
                                reason=(f"pass-through: {callee} pos{k} "
                                        f"'{src_name}' (conf {src_conf:.2f}×"
                                        f"{_PASSTHROUGH_DAMPING})"),
                            ), func_name=caller)
                            propagated.add((caller, pos))
                            new_this_round += 1
            added_total += new_this_round
            if new_this_round == 0:
                break  # fixed-point: yeni miras yok
        if added_total:
            logger.info("Pass-through miras: %d param komşudan adlandırıldı",
                        added_total)

    # ------------------------------------------------------------------
    # Strateji 1: Symbol-Based (confidence: 0.95)
    # ------------------------------------------------------------------

    def _strategy_symbol(self, func_info: _FunctionInfo) -> None:
        """Export/debug symbol'leri kontrol et. Gercek isimler olduklari gibi birakilir."""
        name = func_info.name
        if not name:
            return

        # Ghidra otomatik ismi degilse -> gercek sembol, koru
        if not _is_ghidra_auto_name(name):
            # ObjC class ismi: _OBJC_CLASS_$_XXX -> class adini cikar
            objc_match = _OBJC_CLASS.search(name)
            if objc_match:
                class_name = objc_match.group(1)
                self._add_candidate(_NamingCandidate(
                    old_name=name,
                    new_name=_sanitize_c_name(class_name),
                    confidence=0.95,
                    strategy="symbol",
                    reason=f"ObjC class: {class_name}",
                ), func_name=func_info.name)
                return

            # C++ mangled name
            if _CPP_MANGLED.match(name):
                demangled = self._try_demangle_cpp(name)
                if demangled and demangled != name:
                    self._add_candidate(_NamingCandidate(
                        old_name=name,
                        new_name=_sanitize_c_name(demangled),
                        confidence=0.95,
                        strategy="symbol",
                        reason=f"C++ demangled: {demangled}",
                    ), func_name=func_info.name)
                return

            # Gercek isim -- dokunma (candidate ekleme, zaten anlamli)
            return

    @staticmethod
    def _try_demangle_cpp(mangled: str) -> str | None:
        """C++ mangled name'i demangle etmeyi dene.

        Basit heuristic -- tam demangle icin c++filt lazim ama
        burada en yaygin pattern'leri yakaliyoruz.
        """
        # _ZN<len>name<len>name...E -> namespace::class::method
        match = re.match(r"_ZN(\d+\w+)+E", mangled)
        if match:
            parts: list[str] = []
            remainder = mangled[3:]  # _ZN'den sonrasi
            while remainder and remainder[0].isdigit():
                # Uzunluk oku
                len_str = ""
                while remainder and remainder[0].isdigit():
                    len_str += remainder[0]
                    remainder = remainder[1:]
                length = int(len_str)
                if length > 0 and length <= len(remainder):
                    parts.append(remainder[:length])
                    remainder = remainder[length:]
                else:
                    break
            if parts:
                return "_".join(parts)

        # _Z<len>name... (namespace'siz)
        match = re.match(r"_Z(\d+)(\w+)", mangled)
        if match:
            length = int(match.group(1))
            name = match.group(2)
            if length <= len(name):
                return name[:length]

        return None

    # ------------------------------------------------------------------
    # Strateji 2: String-Context (confidence: 0.7-0.9)
    # ------------------------------------------------------------------

    def _strategy_string_context(self, func_info: _FunctionInfo) -> None:
        """Fonksiyondaki string literal'lerden isim cikar.

        Iki asama:
        1. Agresif: ClassName::Method, ObjC selector, Valve path, URL, hata mesaji
        2. Klasik: Keyword extraction (mevcut davranis)
        """
        if not _is_ghidra_auto_name(func_info.name):
            return  # Zaten anlamli ismi var

        # Fonksiyona referans veren string'leri bul
        strings = self._string_refs_by_func.get(func_info.address, [])

        # Ek olarak fonksiyon body'sindeki string literal'leri tara
        body = self._func_bodies.get(func_info.name, "")
        # v1.8.0: [^"]{3,80} negated char class -> O(n) linear, boyut siniri gereksiz.
        inline_strings = re.findall(r'"([^"]{3,80})"', body)
        all_strings = strings + inline_strings

        if not all_strings:
            return

        # --- Asama 1: Agresif string pattern matching ---
        best_aggressive: tuple[str, float, str] | None = None
        for s in all_strings:
            result = _extract_name_from_string_aggressive(s)
            if result:
                name, conf = result
                if best_aggressive is None or conf > best_aggressive[1]:
                    best_aggressive = (name, conf, s)

        if best_aggressive:
            name, conf, src_string = best_aggressive
            self._add_candidate(_NamingCandidate(
                old_name=func_info.name,
                new_name=name,
                confidence=conf,
                strategy="string_context",
                reason=f'Aggressive: "{src_string[:60]}"',
            ), func_name=func_info.name)
            # Agresif match bulduysa klasik'e de devam et (daha iyi isim olabilir)
            # Ama confidence zaten yuksekse atla
            if conf >= 0.75:
                return

        # --- Asama 2: Klasik keyword extraction ---
        scored: list[tuple[float, str, list[str]]] = []

        for s in all_strings:
            keywords = _extract_keywords_from_string(s)
            if not keywords:
                continue

            # Skor: kelime sayisi * ortalama kelime uzunlugu (spesifiklik)
            avg_len = sum(len(w) for w in keywords) / len(keywords)
            score = len(keywords) * avg_len
            # Cok uzun string'leri cezalandir
            if len(s) > 100:
                score *= 0.5
            scored.append((score, s, keywords))

        if not scored:
            return

        scored.sort(key=lambda x: x[0], reverse=True)
        best_score, best_string, best_keywords = scored[0]

        # Isim olustur: kelimeleri birlestir
        new_name = "_".join(best_keywords[:3])
        new_name = _sanitize_c_name(new_name)

        if not new_name or new_name == "unnamed":
            return

        # Confidence: daha fazla keyword = daha yuksek
        confidence = min(0.9, 0.7 + len(best_keywords) * 0.05)

        self._add_candidate(_NamingCandidate(
            old_name=func_info.name,
            new_name=new_name,
            confidence=confidence,
            strategy="string_context",
            reason=f'String: "{best_string[:60]}"',
        ), func_name=func_info.name)

    # ------------------------------------------------------------------
    # Strateji 3: API-Call (confidence: 0.6-0.8)
    # ------------------------------------------------------------------

    def _strategy_api_call(self, func_info: _FunctionInfo) -> None:
        """Fonksiyonun cagirdigi API'lerden isim cikar."""
        if not _is_ghidra_auto_name(func_info.name):
            return

        # Fonksiyonun cagirdigi isimler
        callee_names = self._callee_names.get(func_info.address, set())

        # Ek olarak body'den fonksiyon cagrilarini cikar
        body = self._func_bodies.get(func_info.name, "")
        if body:
            # v1.8.0: _C_FUNC_CALL = r"\b(\w+)\s*\(" -- O(n) safe,
            # negated char class degil ama \w ve \s arasinda overlap yok.
            body_calls = set(_C_FUNC_CALL.findall(body))
            # C keyword'lerini filtrele
            c_keywords = {
                "if", "else", "for", "while", "do", "switch", "case",
                "return", "sizeof", "typeof", "goto", "break", "continue",
            }
            body_calls -= c_keywords
            callee_names = callee_names | body_calls

        if not callee_names:
            return

        # Callee isimlerini normalize et: leading underscore strip
        # Ghidra callee isimleri '_CGRectGetWidth' gibi basta _ ile gelir
        # ama COMBO_PATTERNS/SINGLE_API_HINTS bunu icermez.
        # Hem orijinal hem stripped versiyonu tut (FUN_xxx korunsun).
        normalized_callees: set[str] = set()
        for cn in callee_names:
            normalized_callees.add(cn)
            stripped = cn.lstrip("_")
            if stripped and stripped != cn:
                normalized_callees.add(stripped)
        callee_names = normalized_callees

        # Combo pattern'leri kontrol et (en spesifik once)
        best_match: tuple[str, float] | None = None

        for required_apis, suggested_name, confidence in _API_COMBO_PATTERNS:
            # required_apis'in tamaminin callee'lerde bulunmasi gerek
            if required_apis.issubset(callee_names):
                if best_match is None or confidence > best_match[1]:
                    best_match = (suggested_name, confidence)

        if best_match:
            self._add_candidate(_NamingCandidate(
                old_name=func_info.name,
                new_name=best_match[0],
                confidence=best_match[1],
                strategy="api_call",
                reason=f"API combo match: {', '.join(sorted(callee_names)[:5])}",
            ), func_name=func_info.name)
            return

        # Combo bulunamazsa, en belirgin tek API'den isim cikar
        # Single API hint'leri confidence'a gore sirala
        api_hits: list[tuple[str, str, float]] = []
        for api_name in callee_names:
            if api_name in _SINGLE_API_HINTS:
                prefix, conf = _SINGLE_API_HINTS[api_name]
                api_hits.append((api_name, prefix, conf))

        if api_hits:
            # En yuksek confidence'li olanini sec
            api_hits.sort(key=lambda x: x[2], reverse=True)
            api_name, prefix, conf = api_hits[0]
            self._add_candidate(_NamingCandidate(
                old_name=func_info.name,
                new_name=f"{prefix}{func_info.address[-4:]}",
                confidence=conf,
                strategy="api_call",
                reason=f"Single API: {api_name}",
            ), func_name=func_info.name)
            return

        # Hala bulunamadiysa: bilinen (non-FUN_xxx) callee'den isim turet
        # Sadece standart libc/system fonksiyonu OLMAYAN callee'leri kullan
        # (standart fonksiyonlar zaten _SINGLE_API_HINTS'te yakalanmis olmali)
        _COMMON_LIBC = {
            "malloc", "calloc", "realloc", "free", "memcpy", "memset", "memmove",
            "strlen", "strcmp", "strncmp", "strcpy", "strncpy", "strcat", "strncat",
            "strstr", "strchr", "strrchr", "printf", "fprintf", "sprintf", "snprintf",
            "fopen", "fclose", "fread", "fwrite", "fgets", "open", "close", "read",
            "write", "stat", "fstat", "access", "exit", "abort", "atoi", "strtol",
            "memcmp", "bzero", "puts", "fputs", "sscanf", "qsort", "tolower", "toupper",
            "strerror", "perror", "getenv", "setenv",
        }
        known_callees = sorted(
            (n for n in callee_names if not _is_ghidra_auto_name(n)
             and not n.startswith("thunk_") and len(n) > 3
             and n.lstrip("_") not in _COMMON_LIBC),
            key=len,
        )
        if known_callees:
            # En spesifik (en uzun isimli) callee'yi dominant callee olarak sec
            dominant = known_callees[-1]
            # Temizle: ___ prefix'leri kaldir
            clean = dominant.lstrip("_")
            name = _sanitize_c_name(f"calls_{clean}")
            if name and name != "unnamed" and name != "calls_":
                self._add_candidate(_NamingCandidate(
                    old_name=func_info.name,
                    new_name=name,
                    confidence=0.40,
                    strategy="api_call",
                    reason=f"Dominant callee: {dominant}",
                ), func_name=func_info.name)

    # ------------------------------------------------------------------
    # Strateji 4: Call-Graph Positional (confidence: 0.5-0.7)
    # ------------------------------------------------------------------

    def _strategy_call_graph(self, func_info: _FunctionInfo) -> None:
        """Call graph pozisyonundan ve callee kombinasyonundan isim cikar.

        Iki alt strateji:
        1. Positional: in/out degree'den isim (leaf, root, handler, dispatcher)
        2. Callee-based: FUN_xxx'in cagirdigi bilinen fonksiyonlardan isim tahmin et
           Ornek: fopen+fread+fclose cagrisi -> "read_file"
        """
        if not _is_ghidra_auto_name(func_info.name):
            return

        addr = func_info.address
        in_deg = self._call_graph_in.get(addr, 0)
        out_deg = self._call_graph_out.get(addr, 0)

        # Callee-based naming: Fonksiyonun cagirdigi bilinen API'leri kullanarak
        # _API_COMBO_PATTERNS'ten isim tahmin et. Body'den callee'leri cikar.
        callee_names = self._callee_names.get(addr, set())
        body = self._func_bodies.get(func_info.name, "")
        if body:
            # v1.8.0: _C_FUNC_CALL = r"\b(\w+)\s*\(" -- O(n) safe
            body_calls = set(_C_FUNC_CALL.findall(body))
            c_keywords = {
                "if", "else", "for", "while", "do", "switch", "case",
                "return", "sizeof", "typeof", "goto", "break", "continue",
            }
            body_calls -= c_keywords
            callee_names = callee_names | body_calls

        # Callee isimlerini normalize et: leading underscore strip
        # (ayni normalizasyon _strategy_api_call'da da var)
        normalized_cg: set[str] = set()
        for cn in callee_names:
            normalized_cg.add(cn)
            stripped = cn.lstrip("_")
            if stripped and stripped != cn:
                normalized_cg.add(stripped)
        callee_names = normalized_cg

        if callee_names:
            # Bilinen (Ghidra otomatik ismi OLMAYAN) callee'leri filtrele
            known_callees = {
                n for n in callee_names if not _is_ghidra_auto_name(n)
            }
            unknown_callees = {
                n for n in callee_names if _is_ghidra_auto_name(n)
            }

            # Eger tum callee'ler biliniyorsa (veya cogunlugu biliniyorsa)
            # callee kombinasyonundan isim tahmin et
            total_callees = len(known_callees) + len(unknown_callees)
            if known_callees and total_callees > 0:
                known_ratio = len(known_callees) / total_callees

                # Combo pattern eslestirmesi -- en spesifik once
                best_combo: tuple[str, float] | None = None
                for required_apis, suggested_name, confidence in _API_COMBO_PATTERNS:
                    if required_apis.issubset(known_callees):
                        if best_combo is None or confidence > best_combo[1]:
                            best_combo = (suggested_name, confidence)

                if best_combo:
                    # Callee-based naming _strategy_api_call'dan farkli:
                    # Burada call graph verisini de kullaniyoruz, bu yuzden
                    # eger api_call stratejisi calismazsa fallback olarak
                    # callee-based naming devreye girer.
                    # Confidence'i biraz dusur cunku body parse hatasi olabilir
                    adjusted_conf = best_combo[1] * (0.85 if known_ratio >= 0.8 else 0.7)
                    self._add_candidate(_NamingCandidate(
                        old_name=func_info.name,
                        new_name=best_combo[0],
                        confidence=adjusted_conf,
                        strategy="callee_based",
                        reason=f"Callee combo: {', '.join(sorted(known_callees)[:5])} "
                               f"(known_ratio={known_ratio:.0%})",
                    ), func_name=func_info.name)
                    # Combo bulduysa positional heuristik'e gerek yok
                    return

                # Combo bulunamazsa: SINGLE_API_HINTS'ten en belirgin callee
                for api_name in known_callees:
                    if api_name in _SINGLE_API_HINTS:
                        prefix, conf = _SINGLE_API_HINTS[api_name]
                        adjusted_conf = conf * (0.85 if known_ratio >= 0.8 else 0.7)
                        self._add_candidate(_NamingCandidate(
                            old_name=func_info.name,
                            new_name=f"{prefix}{func_info.address[-4:]}",
                            confidence=adjusted_conf,
                            strategy="callee_based",
                            reason=f"Callee single API: {api_name} "
                                   f"(known_ratio={known_ratio:.0%})",
                        ), func_name=func_info.name)
                        break  # En iyi bulduguyla devam et

        if in_deg == 0 and out_deg == 0:
            return  # Izole fonksiyon, bilgi yok

        # Leaf node: hicbir fonksiyon cagirmiyor -> utility/helper
        if out_deg == 0 and in_deg > 0:
            # Cok fazla cagiriliyorsa -> cok kullanilan utility
            if in_deg >= 10:
                suffix = "utility"
                confidence = 0.65
            elif in_deg >= 3:
                suffix = "helper"
                confidence = 0.55
            else:
                suffix = "leaf"
                confidence = 0.5

            self._add_candidate(_NamingCandidate(
                old_name=func_info.name,
                new_name=f"{suffix}_{func_info.address[-4:]}",
                confidence=confidence,
                strategy="call_graph",
                reason=f"Leaf node: in={in_deg}, out={out_deg}",
            ), func_name=func_info.name)
            return

        # Root node: kimse cagirmiyor ama cok cagiriyor -> entry/init
        if in_deg == 0 and out_deg > 0:
            if out_deg >= 5:
                suffix = "init"
                confidence = 0.6
            else:
                suffix = "entry_point"
                confidence = 0.55

            self._add_candidate(_NamingCandidate(
                old_name=func_info.name,
                new_name=f"{suffix}_{func_info.address[-4:]}",
                confidence=confidence,
                strategy="call_graph",
                reason=f"Root node: in={in_deg}, out={out_deg}",
            ), func_name=func_info.name)
            return

        # High in-degree -> handler/callback
        if in_deg >= 5:
            self._add_candidate(_NamingCandidate(
                old_name=func_info.name,
                new_name=f"handler_{func_info.address[-4:]}",
                confidence=0.55,
                strategy="call_graph",
                reason=f"High in-degree: {in_deg}",
            ), func_name=func_info.name)
            return

        # High out-degree -> dispatcher
        if out_deg >= 8:
            self._add_candidate(_NamingCandidate(
                old_name=func_info.name,
                new_name=f"dispatcher_{func_info.address[-4:]}",
                confidence=0.55,
                strategy="call_graph",
                reason=f"High out-degree: {out_deg}",
            ), func_name=func_info.name)
            return

    # ------------------------------------------------------------------
    # Strateji 5: Dataflow (confidence: 0.3-0.5)
    # ------------------------------------------------------------------

    def _strategy_dataflow(self, func_info: _FunctionInfo) -> None:
        """Parametre kullanimindan parametre isimlerini cikar.

        C kodunu regex ile parse ederek param_N'in nasil kullanildigini analiz eder.

        v1.8.0: Tum regex aramalari SATIR BAZLI yapilir.  Body once
        splitlines() ile parcalanir, her satir (~100 char) uzerinde aranir.
        52 pattern * 200 degisken * 100 char = ~1M karakter (guvenli).
        Boyut siniri YOK, hicbir fonksiyon atlanmaz.
        """
        body = self._func_bodies.get(func_info.name, "")
        if not body:
            return

        # v1.8.0: Body'yi ONCE satirlara parcala (tek maliyet O(n))
        body_lines = body.splitlines()

        def _line_search(pattern: re.Pattern[str]) -> bool:
            """Herhangi bir satirda pattern eslesiyor mu."""
            for ln in body_lines:
                if pattern.search(ln):
                    return True
            return False

        # Her parametre icin usage pattern'lerini kontrol et
        params = func_info.params
        for i, param_raw in enumerate(params):
            if isinstance(param_raw, str):
                param_name = param_raw
                param_type = ""
            elif isinstance(param_raw, dict):
                param_name = param_raw.get("name", f"param_{i + 1}")
                param_type = param_raw.get("type", "")
            else:
                continue

            if not _is_ghidra_auto_name(param_name):
                continue  # Zaten anlamli ismi var

            # Hizli on-filtre: param_name body'de yok -> atla
            if param_name not in body:
                continue

            best_name: str | None = None
            best_conf: float = 0.0

            for pattern, suggested, conf in _PARAM_USAGE_PATTERNS:
                # Pattern'deki PARAM'i gercek parametre ismiyle degistir
                specific_pattern = re.compile(
                    pattern.pattern.replace("PARAM", re.escape(param_name))
                )
                if _line_search(specific_pattern):
                    if conf > best_conf:
                        best_conf = conf
                        best_name = suggested

            if best_name and best_conf >= self._min_confidence:
                # Ayni fonksiyondaki diger parametrelerle cakisma kontrolu
                # Param index'i suffix olarak ekle
                final_name = best_name
                if i > 0:
                    final_name = f"{best_name}_{i + 1}"

                self._add_candidate(_NamingCandidate(
                    old_name=param_name,
                    new_name=final_name,
                    confidence=best_conf,
                    strategy="dataflow",
                    reason=f"Usage pattern in {func_info.name}",
                ), func_name=func_info.name)

        # local_XX degiskenleri icin de analiz yap
        local_vars = set(_C_LOCAL_USAGE.findall(body))
        for local_name in local_vars:
            if not _is_ghidra_auto_name(local_name):
                continue

            best_name = None
            best_conf = 0.0

            for pattern, suggested, conf in _PARAM_USAGE_PATTERNS:
                specific_pattern = re.compile(
                    pattern.pattern.replace("PARAM", re.escape(local_name))
                )
                if _line_search(specific_pattern):
                    if conf > best_conf:
                        best_conf = conf
                        best_name = suggested

            if best_name and best_conf >= self._min_confidence:
                self._add_candidate(_NamingCandidate(
                    old_name=local_name,
                    new_name=best_name,
                    confidence=best_conf,
                    strategy="dataflow",
                    reason=f"Local usage in {func_info.name}",
                ), func_name=func_info.name)

        # DAT_xxx global degiskenleri
        dat_vars = set(_C_DAT_USAGE.findall(body))
        for dat_name in dat_vars:
            if not _is_ghidra_auto_name(dat_name):
                continue

            # DAT degiskenlerinin string referanslarindan isim cikarilabilir
            # (basit heuristic: body'de DAT'in yakininda string varsa)
            # Burada sadece tip-bazli fallback
            self._add_candidate(_NamingCandidate(
                old_name=dat_name,
                new_name=f"global_{dat_name[-4:]}",
                confidence=0.3,
                strategy="dataflow",
                reason=f"Global data reference in {func_info.name}",
            ), func_name=func_info.name)

        # Ghidra auto-var'lar: uVar1, iVar2 vb.
        auto_vars = set(_C_AUTOVAR_USAGE.findall(body))
        for var_name in auto_vars:
            if not _GHIDRA_AUTO_VAR.match(var_name):
                continue

            # Hizli on-filtre
            if var_name not in body:
                continue

            best_name = None
            best_conf = 0.0

            for pattern, suggested, conf in _PARAM_USAGE_PATTERNS:
                specific_pattern = re.compile(
                    pattern.pattern.replace("PARAM", re.escape(var_name))
                )
                if _line_search(specific_pattern):
                    if conf > best_conf:
                        best_conf = conf
                        best_name = suggested

            if best_name and best_conf >= self._min_confidence:
                self._add_candidate(_NamingCandidate(
                    old_name=var_name,
                    new_name=best_name,
                    confidence=best_conf,
                    strategy="dataflow",
                    reason=f"Auto-var usage in {func_info.name}",
                ), func_name=func_info.name)

    # ------------------------------------------------------------------
    # Strateji 6: Type-Based (confidence: 0.2-0.4)
    # ------------------------------------------------------------------

    def _strategy_type_based(self, func_info: _FunctionInfo) -> None:
        """Ghidra'nin verdigi tip bilgisinden isim cikar."""
        # Fonksiyon parametreleri
        for i, param_raw in enumerate(func_info.params):
            if isinstance(param_raw, str):
                param_name = param_raw
                param_type = ""
            elif isinstance(param_raw, dict):
                param_name = param_raw.get("name", f"param_{i + 1}")
                param_type = param_raw.get("type", "")
            else:
                continue

            if not _is_ghidra_auto_name(param_name):
                continue
            if not param_type:
                continue

            for type_pattern, suggested, conf in _TYPE_NAMING:
                if type_pattern.match(param_type.strip()):
                    final_name = suggested
                    # Ayni fonksiyonda birden fazla ayni tipte parametre olabilir
                    if i > 0:
                        final_name = f"{suggested}_{i + 1}"

                    self._add_candidate(_NamingCandidate(
                        old_name=param_name,
                        new_name=final_name,
                        confidence=conf,
                        strategy="type_based",
                        reason=f"Type: {param_type}",
                    ), func_name=func_info.name)
                    break  # Ilk eslesen yeterli

        # Fonksiyon return type'indan fonksiyon ismi ipucu
        if _is_ghidra_auto_name(func_info.name) and func_info.return_type:
            ret_type = func_info.return_type.strip()

            # void return -> muhtemelen setter/handler/callback
            if ret_type == "void":
                self._add_candidate(_NamingCandidate(
                    old_name=func_info.name,
                    new_name=f"proc_{func_info.address[-4:]}",
                    confidence=0.25,
                    strategy="type_based",
                    reason=f"Return type: void",
                ), func_name=func_info.name)
            # int return -> muhtemelen status/error kodu
            elif ret_type in ("int", "long"):
                self._add_candidate(_NamingCandidate(
                    old_name=func_info.name,
                    new_name=f"check_{func_info.address[-4:]}",
                    confidence=0.2,
                    strategy="type_based",
                    reason=f"Return type: {ret_type}",
                ), func_name=func_info.name)
            # bool return
            elif ret_type in ("bool", "_Bool"):
                self._add_candidate(_NamingCandidate(
                    old_name=func_info.name,
                    new_name=f"is_{func_info.address[-4:]}",
                    confidence=0.3,
                    strategy="type_based",
                    reason=f"Return type: {ret_type}",
                ), func_name=func_info.name)
            # pointer return
            elif ret_type.endswith("*"):
                self._add_candidate(_NamingCandidate(
                    old_name=func_info.name,
                    new_name=f"get_{func_info.address[-4:]}",
                    confidence=0.25,
                    strategy="type_based",
                    reason=f"Return type: {ret_type} (pointer)",
                ), func_name=func_info.name)

    # ------------------------------------------------------------------
    # Strateji 7: API Param Propagation (confidence: 0.60-0.80)
    # ------------------------------------------------------------------

    def _strategy_api_param_propagation(self, func_info: _FunctionInfo) -> None:
        """Bilinen API cagrilarindan parametre isimlerini propagate et.

        Forward: send(param_1, param_2, param_3, 0) -> param_1=sockfd, param_2=buf, param_3=len
        Reverse: SSL_CTX_set_verify(ctx, mode, FUN_xxx) -> FUN_xxx=verify_callback
        """
        body = self._func_bodies.get(func_info.name, "")
        if not body:
            return

        try:
            from karadul.reconstruction.api_param_db import APIParamDB
        except ImportError as e:
            logger.debug("api_param_db import edilemedi, strateji atlandi: %s", e, exc_info=True)
            return

        if not hasattr(self, '_api_param_db'):
            self._api_param_db = APIParamDB()

        # Forward propagation: param_N -> anlamli isim
        renames = self._api_param_db.propagate_params(body)
        for old_name, new_name in renames.items():
            self._add_candidate(_NamingCandidate(
                old_name=old_name,
                new_name=new_name,
                confidence=0.70,
                strategy="api_param",
                reason="API parameter propagation (forward)",
            ), func_name=func_info.name)

        # Reverse propagation: FUN_xxx parametre olarak geciyorsa isim ver
        reverse_renames = self._api_param_db.reverse_propagate_function_names(body)
        for old_name, new_name in reverse_renames.items():
            self._add_candidate(_NamingCandidate(
                old_name=old_name,
                new_name=new_name,
                confidence=0.75,
                strategy="api_param_reverse",
                reason="API callback reverse propagation",
            ), func_name=func_info.name)

    # ------------------------------------------------------------------
    # Strateji 11: Gövde-tabanlı Parametre İsimlendirme (confidence: 0.35-0.42)
    # ------------------------------------------------------------------

    def _strategy_body_param_naming(self, func_info: _FunctionInfo) -> None:
        """param_N'i decompiled C GÖVDESİNDEN çıkarıp kullanım-şekliyle isimlendir.

        KÖK SEBEP (2026-07-16): ARM64 stripped Mach-O'da Ghidra
        ghidra_functions.json'a params=[] yazıyor → func_info.params BOŞ →
        _strategy_dataflow/_strategy_type_based'in parametre döngüleri hiç
        ateşlenmiyor. param_N yalnızca gövde imzasında + kullanımında var. Bu
        strateji onu oradan okur (domain-bağımsız, leakage-siz — kural kaynak
        adından değil, makine-kodu kullanımından türer).

        Not: param sayısı çok az binary'de metadata'dan gelebilir; o durumda
        _strategy_dataflow zaten çalışır ve buradaki adaylar onunla yarışır
        (confidence'a göre en yüksek kazanır). İki yol çakışmaz.
        """
        body = self._func_bodies.get(func_info.name, "")
        if not body or "param_" not in body:
            return

        # İmzadaki parametre bloğunu fonksiyon adıyla çıpala:
        #   "<ret> <fname>(<params>)"  (docstring/@param yorumlarını atla)
        esc_fn = re.escape(func_info.name)
        sig_re = re.compile(
            r"(?m)^(?!\s*[/*#])\s*[A-Za-z_][\w\s\*]*?\b" + esc_fn + r"\s*\(([^;{]*)\)"
        )
        sm = sig_re.search(body)
        if not sm:
            return
        params_blob = sm.group(1).strip()
        if not params_blob or params_blob == "void":
            return

        # Kullanım taraması için imza satırının kendisini (tip bildirimi gürültüsü)
        # gövdeden çıkarmaya gerek yok: tüm regex'ler param_N'e çıpalı ve
        # DISASSEMBLY bloğu _func_bodies'te YOK (kapanış '}'sinden önce biter).
        for part in _split_top_level_commas(params_blob):
            part = part.strip()
            if not part:
                continue
            toks = re.findall(r"[A-Za-z_]\w*", part.replace("*", " "))
            if not toks:
                continue
            pname = toks[-1]
            if not _GHIDRA_AUTO_PARAM.match(pname):
                continue  # zaten anlamlı adı var (ör. library-sig'den crc/buf/len)
            if pname not in body:
                continue
            is_ptr = "*" in part
            verdict = _classify_body_param(body, pname, is_ptr)
            if verdict is None:
                continue
            new_name, conf, reason = verdict
            if conf < self._min_confidence:
                continue
            self._add_candidate(_NamingCandidate(
                old_name=pname,
                new_name=new_name,
                confidence=conf,
                strategy="body_param",
                reason=reason,
            ), func_name=func_info.name)

    # ------------------------------------------------------------------
    # Strateji 10: Fortran in_stack Reconstruction (confidence: 0.80)
    # ------------------------------------------------------------------

    def _strategy_fortran_in_stack(self, func_info: _FunctionInfo) -> None:
        """Fortran-derlenmi fonksiyonlarda in_stack_XXXXXXXX -> param_N donusumu.

        ARM64'te Ghidra, 8'den fazla parametreli fonksiyonlarda stack
        parametrelerini in_stack_XXXXXXXX olarak gosterir. Bu strateji:
        1. Fonksiyonun Fortran-derlenmi olup olmadigini tespit eder
        2. in_stack degiskenlerini offset sirasina gore param_N olarak isimlendirir
        3. FortranParamDB'den bilinen parametre isimlerini uygular

        Fortran tespit kriterleri:
        - Fonksiyon adi _name_ formatinda (trailing underscore)
        - Callee listesinde gfortran runtime cagrilari var
        """
        body = self._func_bodies.get(func_info.name, "")
        if not body:
            return

        try:
            from karadul.reconstruction.fortran_param_db import (
                FortranParamDB,
                InStackReconstructor,
                _IN_STACK_RE,
            )
        except ImportError as e:
            logger.debug("fortran_param_db import edilemedi, strateji atlandi: %s", e, exc_info=True)
            return

        # in_stack var mi hizli kontrol
        if "in_stack_" not in body:
            return

        # Fortran fonksiyon tespiti: callee'lerde gfortran var mi?
        callee_names = self._callee_names.get(func_info.address, set())
        if not hasattr(self, '_fortran_param_db'):
            self._fortran_param_db = FortranParamDB()

        is_fortran = self._fortran_param_db.has_gfortran_callees(callee_names)

        # Trailing underscore kontrolu (fallback).
        # v1.10.0 H1 fix: _memcpy_, _gcc_personality_v0_, _pthread_*_ gibi
        # libc/GCC ASM stub/wrapper isimleri de `_..._` pattern'ine uyuyor ama
        # Fortran DEGIL. Conservative blacklist ile false positive'i azaltiyoruz.
        if not is_fortran:
            name = func_info.name
            if (len(name) >= 3
                    and name.startswith("_")
                    and name.endswith("_")
                    and not name.startswith("__")
                    and not _is_non_fortran_underscore_name(name)):
                is_fortran = True

        if not is_fortran:
            return

        # in_stack -> param_N mapping
        reconstructor = InStackReconstructor(self._fortran_param_db)
        result = reconstructor.reconstruct(body, func_name=func_info.name)

        if not result.success or not result.mappings:
            return

        for mapping in result.mappings:
            self._add_candidate(_NamingCandidate(
                old_name=mapping.in_stack_name,
                new_name=mapping.param_name,
                confidence=0.80,
                strategy="fortran_in_stack",
                reason=f"ARM64 stack param (offset 0x{mapping.offset:x})",
            ), func_name=func_info.name)

        # FortranParamDB'den bilinen isimleri de uygula
        known_names = self._fortran_param_db.get_param_names(func_info.name)
        if known_names:
            total_params = result.register_param_count + result.in_stack_count
            for i in range(min(total_params, len(known_names))):
                old_param = f"param_{i + 1}"
                new_name = known_names[i]
                if old_param != new_name:
                    self._add_candidate(_NamingCandidate(
                        old_name=old_param,
                        new_name=new_name,
                        confidence=0.85,
                        strategy="fortran_param_db",
                        reason=f"Fortran param DB: {func_info.name}",
                    ), func_name=func_info.name)

    # ------------------------------------------------------------------
    # Strateji 9: Local Variable Naming (confidence: 0.25-0.55)
    # ------------------------------------------------------------------

    def _strategy_local_var_naming(self, func_info: _FunctionInfo) -> None:
        """Ghidra auto-var'lara (uVar1, iVar2, local_XX, bVar5) anlamli isim ver.

        Uc katmanli analiz:
        1. Type-declaration: Fonksiyon body'sindeki tip bildirimlerinden isim cikar
           (uint uVar1; -> val, char *pcVar5; -> str, bool bVar1; -> flag)
        2. Usage-based: Degiskenin nasil kullanildigini analiz et
           (loop counter -> i, malloc return -> buf, strlen arg -> str)
        3. Prefix fallback: Hicbir pattern eslesmediyse Ghidra prefix'inden isim cikar
           (uVar -> val, iVar -> ret, bVar -> flag)

        v1.8.0: Tum regex aramalari SATIR BAZLI yapilir.  Boyut siniri
        kaldirildi -- hicbir fonksiyon atlanmaz.
        """
        body = self._func_bodies.get(func_info.name, "")
        if not body:
            return

        # v1.8.0: Body'yi ONCE satirlara parcala
        body_lines = body.splitlines()

        def _line_search(pattern: re.Pattern[str]) -> bool:
            for ln in body_lines:
                if pattern.search(ln):
                    return True
            return False

        # 1. Collect ALL Ghidra auto-vars in this function
        # Use wide regex to also catch pcVar5, plVar3, ppvVar7, etc.
        auto_vars = set(_C_AUTOVAR_USAGE_WIDE.findall(body))
        local_vars = set(_C_LOCAL_USAGE.findall(body))
        all_ghidra_vars: set[str] = set()

        for v in auto_vars:
            if _GHIDRA_AUTO_VAR_WIDE.match(v):
                all_ghidra_vars.add(v)
        for v in local_vars:
            if _GHIDRA_AUTO_LOCAL.match(v):
                all_ghidra_vars.add(v)

        if not all_ghidra_vars:
            return

        # 2. Parse type declarations from function body (line-by-line)
        #    Extracts: "uint uVar1;" -> ("uint", "uVar1")
        var_types: dict[str, str] = {}
        for line in body_lines:
            m = _LOCAL_DECL_RE.match(line)
            if m:
                decl_type = m.group(1).strip()
                var_name = m.group(2).strip()
                if var_name in all_ghidra_vars:
                    var_types[var_name] = decl_type

        # Track loop counter names used (for i/j/k allocation)
        loop_counter_names_used: list[str] = []

        for var_name in sorted(all_ghidra_vars):
            # Skip if already has a high-confidence candidate from other strategies
            key = f"{func_info.name}::{var_name}"
            existing = self._candidates.get(key, [])
            if any(c.confidence >= 0.50 for c in existing):
                continue

            # Hizli on-filtre: var_name body'de yok -> atla
            if var_name not in body:
                continue

            best_name: str | None = None
            best_conf: float = 0.0
            best_reason: str = ""

            # --- Layer 1: Usage-based analysis (highest priority) ---
            # v1.8.0: Satir bazli arama
            for pattern, suggested, conf in _LOCAL_VAR_USAGE_PATTERNS:
                try:
                    specific = re.compile(
                        pattern.pattern.replace("PARAM", re.escape(var_name))
                    )
                except re.error as e:
                    logger.debug(
                        "Local var pattern derlenemedi (var=%s, pattern=%r): %s",
                        var_name, pattern.pattern, e,
                    )
                    continue
                if _line_search(specific):
                    if conf > best_conf:
                        best_conf = conf
                        best_name = suggested
                        best_reason = f"Usage pattern: {suggested}"

            # Special: loop counter assignment (i -> j -> k for nested)
            if best_name == "i":
                _LOOP_NAMES = ["i", "j", "k", "m", "n"]
                # Find next available loop counter name
                for ln in _LOOP_NAMES:
                    if ln not in loop_counter_names_used:
                        best_name = ln
                        loop_counter_names_used.append(ln)
                        break
                else:
                    best_name = f"idx_{len(loop_counter_names_used)}"
                    loop_counter_names_used.append(best_name)

            # --- Layer 1.5: Return value semantic naming ---
            # If generic "ret" matched (conf 0.30), try to extract function name
            # for a more descriptive name: var = someFunc(...) -> someFunc_ret
            if best_name == "ret" and best_conf <= 0.35:
                _ret_capture_re = re.compile(
                    r"\b" + re.escape(var_name) + r"\s*=\s*(\w+)\s*\("
                )
                for ln in body_lines:
                    m = _ret_capture_re.search(ln)
                    if m:
                        func_called = m.group(1)
                        # Skip Ghidra auto-names and C keywords
                        if (not _is_ghidra_auto_name(func_called)
                                and func_called not in _RET_SEMANTIC_SKIP
                                and len(func_called) > 2):
                            # Use function name to build descriptive return name
                            # Strip leading underscore(s) from libc-style names
                            clean = func_called.lstrip("_")
                            if clean:
                                best_name = f"{clean}_ret"
                                best_conf = 0.40
                                best_reason = f"Return capture: {func_called}()"
                        break

            # --- Layer 2: Type-declaration based (medium priority) ---
            if best_conf < 0.40 and var_name in var_types:
                decl_type = var_types[var_name]
                for type_pattern, type_suggested, type_conf in _TYPE_NAMING:
                    if type_pattern.match(decl_type):
                        # Boost confidence slightly since we have actual type info
                        boosted_conf = min(type_conf + 0.10, 0.45)
                        if boosted_conf > best_conf:
                            best_conf = boosted_conf
                            best_name = type_suggested
                            best_reason = f"Type declaration: {decl_type}"
                        break

            # --- Layer 3: Ghidra prefix fallback (lowest priority) ---
            if best_conf < 0.25 and _GHIDRA_AUTO_VAR_WIDE.match(var_name):
                # Extract prefix before "Var": uVar1->u, pcVar5->p, plVar3->p
                prefix_part = var_name[:var_name.index("Var")]
                prefix_char = prefix_part[0]  # Use first char for fallback lookup
                # Multi-letter prefix -> more specific fallback
                if len(prefix_part) >= 2 and prefix_part.startswith("pc"):
                    fallback_name, fallback_conf = "str", 0.30
                elif len(prefix_part) >= 2 and prefix_part.startswith("pl"):
                    fallback_name, fallback_conf = "long_ptr", 0.25
                elif len(prefix_part) >= 2 and prefix_part.startswith("pp"):
                    fallback_name, fallback_conf = "ptr_ptr", 0.25
                elif len(prefix_part) >= 2 and prefix_part.startswith("pu"):
                    fallback_name, fallback_conf = "uint_ptr", 0.25
                elif len(prefix_part) >= 2 and prefix_part.startswith("pi"):
                    fallback_name, fallback_conf = "int_ptr", 0.25
                elif prefix_char in _GHIDRA_PREFIX_FALLBACK:
                    fallback_name, fallback_conf = _GHIDRA_PREFIX_FALLBACK[prefix_char]
                else:
                    fallback_name, fallback_conf = "val", 0.20

                if fallback_conf > best_conf:
                    best_conf = fallback_conf
                    best_name = fallback_name
                    best_reason = f"Prefix fallback: {prefix_part}Var -> {fallback_name}"

            # For local_XX: if no usage pattern matched, keep with type prefix
            if best_conf < 0.25 and _GHIDRA_AUTO_LOCAL.match(var_name):
                if var_name in var_types:
                    decl_type = var_types[var_name]
                    # undefined8 local_78 -> qword_78
                    if "undefined8" in decl_type:
                        best_name = f"qword_{var_name[-2:]}"
                        best_conf = 0.25
                        best_reason = f"Typed local: {decl_type}"
                    elif "undefined4" in decl_type:
                        best_name = f"dword_{var_name[-2:]}"
                        best_conf = 0.25
                        best_reason = f"Typed local: {decl_type}"
                    elif "undefined2" in decl_type:
                        best_name = f"word_{var_name[-2:]}"
                        best_conf = 0.25
                        best_reason = f"Typed local: {decl_type}"
                    elif "undefined1" in decl_type or "undefined" in decl_type:
                        best_name = f"byte_{var_name[-2:]}"
                        best_conf = 0.25
                        best_reason = f"Typed local: {decl_type}"
                    elif "char" in decl_type and "*" in decl_type:
                        best_name = f"str_{var_name[-2:]}"
                        best_conf = 0.30
                        best_reason = f"Typed local: {decl_type}"
                    elif "int" in decl_type or "long" in decl_type:
                        best_name = f"val_{var_name[-2:]}"
                        best_conf = 0.25
                        best_reason = f"Typed local: {decl_type}"
                    elif "bool" in decl_type or "_Bool" in decl_type:
                        best_name = f"is_{var_name[-2:]}"
                        best_conf = 0.25
                        best_reason = f"Typed local: {decl_type}"
                    elif "*" in decl_type:
                        best_name = f"ptr_{var_name[-2:]}"
                        best_conf = 0.25
                        best_reason = f"Typed local: {decl_type}"

            if best_name and best_conf >= self._min_confidence:
                self._add_candidate(_NamingCandidate(
                    old_name=var_name,
                    new_name=best_name,
                    confidence=best_conf,
                    strategy="local_var",
                    reason=best_reason,
                ), func_name=func_info.name)

    # ------------------------------------------------------------------
    # NOT (2026-05-13): Strateji 10 _strategy_llm4decompile kaldirildi
    # Berke kalici karari: feedback_no_llm.md — deterministic, CPU-only.
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Naming map'i C koduna uygulama
    # ------------------------------------------------------------------

    @staticmethod
    def _apply_naming_map(content: str, naming_map: dict[str, str]) -> str:
        """Naming map'i C kaynak koduna uygula.

        Aho-Corasick automaton ile tek geciste tum replace'leri yapar.
        O(N + matches) karmasiklik -- regex alternation'a kiyasla
        pattern sayisindan bagimsiz.
        """
        if not naming_map:
            return content

        replacer = AhoReplacer(naming_map)
        return replacer.replace(content)

    # ------------------------------------------------------------------
    # Istatistik
    # ------------------------------------------------------------------

    def get_stats(self, result: CNamingResult) -> dict[str, Any]:
        """CNamingResult'tan ozet istatistik cikar.

        Args:
            result: analyze_and_rename sonucu.

        Returns:
            Ozet dict.
        """
        return {
            "total_renamed": result.total_renamed,
            "by_strategy": result.by_strategy,
            "high_confidence": result.high_confidence,
            "medium_confidence": result.medium_confidence,
            "low_confidence": result.low_confidence,
            "confidence_distribution": {
                "0.0-0.2": result.low_confidence,
                "0.2-0.4": sum(
                    1 for cands in self._candidates.values()
                    for c in cands
                    if 0.2 <= c.confidence < 0.4
                    and c.old_name in result.naming_map
                ),
                "0.4-0.7": result.medium_confidence,
                "0.7-1.0": result.high_confidence,
            },
            "total_functions": len(self._functions),
            "auto_named_functions": sum(
                1 for f in self._functions.values()
                if _is_ghidra_auto_name(f.name)
            ),
            "total_strings": len(self._strings),
            "output_files": len(result.output_files),
            "errors": len(result.errors),
        }
