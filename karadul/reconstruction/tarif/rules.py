"""Tarif kuralları: kanıt paketinden davranışı anlatan isim (deterministik, LLM'siz).

Öncelik sırası:
  1. Geri çağrı rolü: fonksiyon bir kütüphaneye geri çağrı olarak veriliyorsa rolü API
     sözleşmesinden gelir (qsort karşılaştırıcısı, libevent zamanlayıcı/okuma işleyicisi...).
  2. Log mesajı: fonksiyonun kendi log mesajı ana işini anlatır. Hata mesajları atlanır, çünkü
     ana işi değil hata durumunu anlatırlar.
  3. API birliktelikleri: gereken kümenin tamamı çağrılıyorsa isim + puan. API yalnız
     fonksiyonun asıl işiyse sayılır (büyük gövdede tek yan çağrı isim vermez).
     Sabit string argümanı nesne olarak eklenir: ``sysctlbyname("hw.memsize")`` → ``get_hw_memsize``.
  4. Tek-API sarmalayıcı: kısa gövde, yalnız bellek ayırma/bırakma.

Ölçümler (2026-10-15, tmux/htop, kör etiketleme): geri çağrı bağlamı %83, log %49, API
kuralları ~%50 "amacı doğru anlatan" oranında. Ayrıntı: docs/arge/2026-10-15_isimlendirme_plani.md
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

from karadul.reconstruction.tarif.evidence import EvidencePack


@dataclass(frozen=True)
class Naming:
    """Bir fonksiyona verilen isim ve kaynağı."""

    name: str
    source: str  # "kesin:...", "geri_cagri:...", "log", "api:...", "yayilim:...", "ipucu:..."
    score: float

    @property
    def is_hint(self) -> bool:
        """İpucu isimler başarı sayılmaz, yorum olarak gösterilir."""
        return self.source.startswith("ipucu")


# Her yerde geçen API'ler tek başına isim vermez.
GENERIC_APIS = frozenset({
    "free", "stack_chk_fail", "chkstk_darwin", "strlen", "strnlen", "memcpy", "memmove", "bzero", "memset",
    "memset_pattern16", "strcmp", "strncmp", "strchr", "strrchr", "maskrune", "error", "assert_rtn", "malloc",
    "calloc", "realloc", "strdup", "strndup", "snprintf", "vsnprintf", "strlcpy", "strlcat", "strlcpy_chk",
    "strlcat_chk", "memcpy_chk", "strncpy", "strncpy_chk", "strncat_chk", "stpcpy", "tolower", "toupper",
    "memchr", "memcmp", "strstr", "strcasestr", "strcasecmp", "strncasecmp", "strcspn", "strspn", "strsep",
    "strpbrk", "close", "fclose", "evbuffer_get_length", "evbuffer_pullup", "evbuffer_drain", "evbuffer_free",
    "evbuffer_new", "event_initialized", "event_pending", "fileno", "ferror", "feof", "getpid", "time",
    "abort", "exit", "fflush", "CFRelease", "IOObjectRelease", "mach_port_deallocate", "exp10", "log10",
})


def _any(*names: str) -> frozenset[str]:
    return frozenset(names)


_OPEN = _any("open", "fopen$DARWIN_EXTSN", "fopen", "fdopen$DARWIN_EXTSN")
_EXEC = _any("execvp", "execl", "execlp", "execv")

# (gereken API grupları, isim, puan). Her grup alternatiflerden oluşur, hepsinden en az biri çağrılmalı.
COMBOS: tuple[tuple[tuple[frozenset[str], ...], str, int], ...] = (
    ((_any("socket"), _any("connect")), "connect_socket", 10),
    ((_any("socket"), _any("bind"), _any("listen")), "listen_on_socket", 10),
    ((_any("fork"), _EXEC), "spawn_process", 10),
    ((_any("pipe", "socketpair"), _any("fork")), "spawn_with_pipe", 9),
    ((_OPEN, _any("read", "fread", "fgets", "getline", "getc")), "read_file", 9),
    ((_OPEN, _any("write", "fwrite", "fputc")), "write_file", 9),
    ((_any("mkstemp"), _any("rename")), "write_file_atomically", 9),
    ((_any("regcomp"), _any("regexec")), "match_regex", 9),
    ((_any("localtime_r", "localtime"), _any("strftime")), "format_time", 9),
    ((_any("tcgetattr"), _any("tcsetattr")), "configure_terminal", 9),
    ((_any("opendir"), _any("readdir")), "list_directory", 9),
    ((_any("backtrace"), _any("backtrace_symbols_fd")), "print_backtrace", 9),
    ((_any("getpriority"), _any("setpriority")), "change_process_priority", 9),
    ((_any("initscr"),), "init_screen", 9),
    ((_any("endwin"),), "close_screen", 8),
    ((_any("start_color", "init_pair", "use_default_colors"),), "init_colors", 8),
    ((_any("exit", "abort"), _any("vasprintf", "vsnprintf", "fprintf", "strerror")), "report_fatal_error", 8),
    ((_any("res_9_b64_ntop"),), "base64_encode", 9),
    ((_any("res_9_b64_pton"),), "base64_decode", 9),
    ((_any("IOPSCopyPowerSourcesInfo", "IOPSCopyPowerSourcesList"),), "get_battery_info", 9),
    ((_any("getloadavg"),), "get_load_average", 9),
    ((_any("proc_pidinfo"),), "get_process_info", 8),
    ((_any("getpwuid", "getpwnam"),), "lookup_user", 8),
    ((_any("getgrnam"),), "lookup_group", 8),
    ((_any("gethostname"),), "get_hostname", 8),
    ((_any("ttyname"),), "get_tty_name", 8),
    ((_any("glob"),), "expand_glob", 8),
    ((_any("system"),), "run_shell_command", 8),
    ((_any("flock"),), "lock_file", 8),
    ((_any("waitpid"),), "wait_for_child", 8),
    ((_any("kill", "killpg"),), "send_signal", 8),
    ((_any("shutdown"),), "shutdown_socket", 8),
    ((_EXEC,), "exec_program", 8),
    ((_any("bufferevent_new"),), "create_buffered_connection", 7),
    ((_any("evbuffer_readln", "evbuffer_readline"),), "read_line_from_buffer", 7),
    ((_any("sigaction", "signal"),), "install_signal_handler", 7),
    ((_any("uname"),), "get_system_info", 7),
    ((_any("chdir"),), "change_directory", 7),
    ((_any("getcwd"),), "get_current_directory", 7),
    ((_any("unlink"),), "delete_file", 7),
    ((_any("mkdir"),), "create_directory", 7),
    ((_any("realpath$DARWIN_EXTSN", "realpath"),), "resolve_path", 7),
    ((_any("setlocale"),), "set_locale", 7),
    ((_any("fork"),), "fork_process", 7),
    ((_any("poll", "select$DARWIN_EXTSN", "select"),), "wait_for_input", 7),
    ((_any("strftime", "ctime_r"),), "format_time", 7),
    ((_any("wgetch", "getmouse"),), "read_input_key", 7),
    ((_any("sysctl", "sysctlbyname"),), "query_system_info", 6),
    ((_any("sigprocmask"),), "block_signals", 6),
    ((_any("qsort"),), "sort_items", 6),
    ((_any("bsearch"),), "search_sorted_items", 6),
    ((_any("getenv"),), "get_env", 6),
    ((_any("setenv"),), "set_env", 6),
    ((_any("isatty"),), "check_is_tty", 6),
    ((_any("access"),), "check_file_access", 6),
    ((_any("fnmatch"),), "match_pattern", 6),
    ((_any("dup2"),), "redirect_fd", 6),
    ((_any("tiparm_s", "tputs"),), "emit_terminal_sequence", 6),
    ((_any("bufferevent_write", "bufferevent_write_buffer"),), "send_data", 5),
    ((_any("event_add"), _any("event_set")), "schedule_event", 5),
    ((_any("event_once"),), "schedule_event", 5),
    ((_any("event_del"),), "cancel_event", 5),
    ((_any("strtonum", "strtol", "strtoul", "strtoll", "strtod", "atoi"),), "parse_number", 5),
    ((_any("ioctl"),), "device_control", 5),
    ((_any("wcwidth", "wctomb", "mbrtowc", "btowc"),), "convert_wide_char", 5),
    ((_any("evbuffer_add_printf", "evbuffer_add", "evbuffer_add_vprintf"),), "write_to_buffer", 4),
    ((_any("gettimeofday", "clock_gettime", "mach_timebase_info", "clock_get_time"),), "get_current_time", 4),
    ((_any("wmove", "waddnstr", "wattrset", "whline", "waddch", "wadd_wchnstr", "wvline", "wclear",
           "wadd_wch"),), "draw_on_screen", 4),
)
THRESHOLD = 5.0
# Büyük gövdede (çok iç çağrı) API'nin isim vermesi için anlamlı API çağrılarının tüm çağrılara oranı
MIN_API_SHARE = 0.3
MAX_INTERNAL_FOR_ANY_API = 3

# İsim -> (sabit string argümanı okunacak API'ler, fiil)
LITERAL_APIS: dict[str, tuple[tuple[str, ...], str]] = {
    "query_system_info": (("sysctlbyname",), "get"),
    "read_file": (("fopen", "open"), "read"),
    "write_file": (("fopen", "open"), "write"),
    "delete_file": (("unlink",), "delete"),
    "create_directory": (("mkdir",), "create"),
    "set_env": (("setenv",), "set"),
    "get_env": (("getenv",), "get"),
}

# Log mesajı süzgeci
_STOP = frozenset({
    "the", "and", "for", "with", "from", "has", "have", "into", "not", "now", "was", "are", "this", "that",
    "got", "too", "via", "all", "any", "but", "use", "using", "its",
})
_FAIL = frozenset({
    "bad", "could", "unrecognized", "unrecognised", "invalid", "failed", "fail", "error", "unknown", "missing",
    "cannot", "unable", "wrong", "exit", "exited", "ignoring", "ignored", "overflow", "not", "too",
})
# Kelime çiftiyle tanınan hata mesajları ("out of range": sınır denetimi hatası; ölçümde 23 yanlışın 10'u)
_FAIL_PAIRS = (frozenset({"out", "range"}),)
_FORMAT_SPEC = re.compile(r"%[-#0-9.*]*(?:hh|h|ll|l|z|j|t)?[a-zA-Z]")
_FIRST_STRING_ARG = re.compile(r"\b(FUN_[0-9a-f]+)\s*\(\s*\"((?:[^\"\\]|\\.)*)\"")

_VERBISH = frozenset({
    "reset", "start", "create", "set", "init", "update", "check", "add", "remove", "new", "open", "free",
    "destroy", "get", "make", "run", "fire", "do", "begin", "end", "stop", "clear", "draw", "helper",
})


def context_prefix(name: str) -> str:
    """Bağlam öneki: sondaki fiilleri at, en fazla 3 token tut (``alerts_reset`` → ``alerts``)."""
    tokens = [t for t in name.split("_") if t]
    while len(tokens) > 1 and tokens[-1] in _VERBISH:
        tokens = tokens[:-1]
    return "_".join(tokens[:3])


def find_logger(packs: Mapping[str, EvidencePack], min_distinct: int = 20) -> str | None:
    """İlk argümanı format dizesi olan en çok farklı dizeyi alan iç fonksiyon: kaydedici (logger)."""
    formats: dict[str, set[str]] = {}
    for p in packs.values():
        for m in _FIRST_STRING_ARG.finditer(p.read_code()):
            if "%" in m.group(2):
                formats.setdefault(m.group(1), set()).add(m.group(2))
    if not formats:
        return None
    best, msgs = max(formats.items(), key=lambda kv: len(kv[1]))
    return best if len(msgs) >= min_distinct else None


def _is_failure(words: list[str]) -> bool:
    ws = set(words)
    return bool(ws & _FAIL) or any(pair <= ws for pair in _FAIL_PAIRS)


def name_from_log(code: str, logger: str | None) -> str | None:
    """Fonksiyonun kendi log mesajlarından isim; format belirteçleri, dolgu ve hata mesajları atılır."""
    if not logger:
        return None
    pattern = re.compile(r"\b" + re.escape(logger) + r"\s*\(\s*\"((?:[^\"\\]|\\.)*)\"")
    best: list[str] = []
    for msg in pattern.findall(code):
        clean = _FORMAT_SPEC.sub(" ", msg)
        raw = [w.lower() for w in re.findall(r"[A-Za-z][A-Za-z0-9]{1,}", clean)]
        if _is_failure(raw):
            continue
        words = [w for w in raw if len(w) >= 3 and w not in _STOP]
        if len(words) > len(best):
            best = words
    if len(best) < 2:
        return None
    return "_".join(best[:4])


def callback_role(api: str, registrar_code: str, target: str) -> str | None:
    """Geri çağrının rolü, kaydeden çağrının API sözleşmesinden ve argüman konumundan."""
    if api == "qsort":
        return "compare_for_sort"
    if api == "bsearch":
        return "compare_for_search"
    if api in ("sigaction", "signal"):
        return "handle_signal"
    if api == "atexit":
        return "cleanup_at_exit"
    if api == "pthread_create":
        return "thread_main"
    if api == "event_once":
        return "on_timeout"
    pat = re.compile(r"\b_?" + re.escape(api) + r"\s*\(([^;]*?(?:FUN|LAB)_" + re.escape(target) + r"\b[^;]*)\)",
                     re.I)
    m = pat.search(registrar_code)
    args = [a.strip() for a in m.group(1).split(",")] if m else []
    if api == "event_set":
        if len(args) < 3:
            return "on_event"
        try:
            flags = int(args[2], 0)
        except ValueError:
            return "on_event"
        if flags & 0x02:
            return "on_readable"
        if flags & 0x04:
            return "on_writable"
        if flags & 0x08:
            return "on_signal"
        return "on_timer"
    if api == "bufferevent_new":
        pos = next((i for i, a in enumerate(args) if target in a.lower()), -1)
        return {1: "on_read", 2: "on_write", 3: "on_error"}.get(pos, "on_event")
    return None


def _slug(literal: str) -> str:
    s = literal.rsplit("/", 1)[-1]  # yol ise son parça
    s = re.sub(r"[^A-Za-z0-9]+", "_", s).strip("_").lower()
    return "_".join(x for x in s.split("_") if x)[:40]


def literal_object(code: str, combo_name: str) -> str | None:
    """API'nin sabit string argümanını nesne olarak kullan: ``sysctlbyname("hw.memsize")`` → ``get_hw_memsize``."""
    spec = LITERAL_APIS.get(combo_name)
    if not spec:
        return None
    apis, verb = spec
    for api in apis:
        m = re.search(r"\b_?" + re.escape(api) + r"(?:\$DARWIN_EXTSN)?\s*\(\s*\"([^\"]{2,60})\"", code)
        if m:
            obj = _slug(m.group(1))
            if obj and not obj.isdigit():
                return f"{verb}_{obj}"
    return None


def _api_is_main_work(p: EvidencePack) -> bool:
    meaningful = sum(n for a, n in p.api_counts.items() if a not in GENERIC_APIS)
    total = sum(p.api_counts.values()) + len(p.internal_callees)
    if len(p.internal_callees) <= MAX_INTERNAL_FOR_ANY_API:
        return True
    return total > 0 and meaningful / total >= MIN_API_SHARE


def best_combo(apis: set[str]) -> tuple[str, str, float] | None:
    best: tuple[str, str, float] | None = None
    for groups, name, score in COMBOS:
        if all(apis & g for g in groups) and (best is None or score > best[2]):
            used = "+".join(sorted(next(iter(sorted(apis & g))) for g in groups))
            best = (name, f"api:{used}", float(score))
    return best


def name_function(
    p: EvidencePack,
    packs: Mapping[str, EvidencePack],
    reliable: Mapping[str, str],
    logger: str | None,
) -> Naming | None:
    """Tek bir fonksiyon için tarif ismi; yeterli kanıt yoksa ``None``."""
    # 1. Geri çağrı rolü (kaydedenin güvenilir adı varsa bağlam öneki)
    for reg in p.registered_as_callback:
        registrar = packs.get(reg["registrar"])
        role = callback_role(reg["api"], registrar.read_code() if registrar else "", p.address)
        if role:
            ctx = context_prefix(reliable[reg["registrar"]]) if reg["registrar"] in reliable else ""
            return Naming(f"{ctx}_{role}" if ctx else role, f"geri_cagri:{reg['api']}", 9.0)

    code = p.read_code()
    combo = best_combo(set(p.apis)) if _api_is_main_work(p) else None
    # 2. Log mesajı (güçlü bir API birlikteliği yoksa)
    if combo is None or combo[2] < 8:
        log_name = name_from_log(code, logger)
        if log_name:
            return Naming(log_name, "log", 7.5)
    # 3. API birliktelikleri (+ sabit argümandan nesne)
    if combo and combo[2] >= THRESHOLD:
        name, source, score = combo
        obj = literal_object(code, name)
        if obj:
            return Naming(obj, source + "+sabit", score + 1.0)
        return Naming(name, source, score)
    # 4. Tek-API sarmalayıcı
    apis = set(p.apis)
    if p.line_count <= 25 and not p.internal_callees:
        if apis and apis <= {"free"} and p.api_counts.get("free", 0) >= 2:
            return Naming("free_structure", "api:free*", 5.0)
        if apis & {"strdup", "strndup"} and not (apis - GENERIC_APIS):
            return Naming("duplicate_string", "api:strdup", 5.0)
    return None
