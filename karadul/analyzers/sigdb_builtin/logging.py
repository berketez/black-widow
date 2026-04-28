"""Logging category signatures — sig_db Faz 9 pilot migrasyonu.

Kaynak: karadul/analyzers/signature_db.py
  - _LOGGING_SIGNATURES        (45 entry, satir 3820-3873)  -> spdlog/log4cxx/glog/glib/android/os_log/asl
  - _LOGGING_EXT_SIGNATURES    (38 entry, satir 6590-6640)  -> syslog/journald/dbus/ETW/PDH

Toplam: 83 signature.

ADR 0008 Faz 9 (pilot) — Grup 10 "Logging" (~83 entry, ~103 LOC). Tip A
yumusak override pattern'i: signature_db.py'de orijinal dict gövdeleri
SILINMEDI; runtime'da bu modulden gelen veriyle yeniden baglanir. Rollback
icin override blogu silinince (try/except ImportError) eski inline veri
otomatik geri devreye girer.

Anahtar isimleri signature_db.py'deki orijinal dict adlariyla uyumludur:
  ``logging_signatures``       <-> ``_LOGGING_SIGNATURES``
  ``logging_ext_signatures``   <-> ``_LOGGING_EXT_SIGNATURES``

Bilgi: ``_LOGGING_EXT_SIGNATURES`` icindeki ``ipc`` / ``win_etw`` / ``win_perf``
kategorili entry'ler tarihsel olarak ayni dict'te tutulmustur (logging
yakininda yer alan observability/IPC). Ayri kategorilere bolme islemi Faz 9
kapsami disindadir; mevcut anlamsal grup korunur.
"""
from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# logging (45 entry) — spdlog, log4cxx, glog, GLib log, Android logcat,
# Apple unified logging (os_log), Apple System Log (legacy ASL).
# Kaynak: signature_db.py satir 3820-3873.
# ---------------------------------------------------------------------------
_LOGGING_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # spdlog
    "__ZN6spdlog3get": {"lib": "spdlog", "purpose": "spdlog::get (get logger by name)", "category": "logging"},
    "__ZN6spdlog11set_pattern": {"lib": "spdlog", "purpose": "spdlog::set_pattern (set log format)", "category": "logging"},
    "__ZN6spdlog9set_level": {"lib": "spdlog", "purpose": "spdlog::set_level (set log level)", "category": "logging"},
    "__ZN6spdlog6logger3log": {"lib": "spdlog", "purpose": "spdlog::logger::log (write log entry)", "category": "logging"},
    "__ZN6spdlog6logger5flush": {"lib": "spdlog", "purpose": "spdlog::logger::flush (flush log buffer)", "category": "logging"},
    "__ZN6spdlog6logger4info": {"lib": "spdlog", "purpose": "spdlog::logger::info (log info level)", "category": "logging"},
    "__ZN6spdlog6logger4warn": {"lib": "spdlog", "purpose": "spdlog::logger::warn (log warn level)", "category": "logging"},
    "__ZN6spdlog6logger5error": {"lib": "spdlog", "purpose": "spdlog::logger::error (log error level)", "category": "logging"},
    "__ZN6spdlog6logger5debug": {"lib": "spdlog", "purpose": "spdlog::logger::debug (log debug level)", "category": "logging"},
    "__ZN6spdlog6logger8critical": {"lib": "spdlog", "purpose": "spdlog::logger::critical (log critical level)", "category": "logging"},
    "__ZN6spdlog7details11thread_pool": {"lib": "spdlog", "purpose": "spdlog::details::thread_pool (async logging)", "category": "logging"},
    "__ZN6spdlog5sinks": {"lib": "spdlog", "purpose": "spdlog::sinks namespace (partial mangled)", "category": "logging"},
    "__ZN6spdlog10basic_logger_mt": {"lib": "spdlog", "purpose": "spdlog::basic_logger_mt (create file logger)", "category": "logging"},
    "__ZN6spdlog12rotating_logger_mt": {"lib": "spdlog", "purpose": "spdlog::rotating_logger_mt (rotating file logger)", "category": "logging"},
    "__ZN6spdlog11daily_logger_mt": {"lib": "spdlog", "purpose": "spdlog::daily_logger_mt (daily rotating logger)", "category": "logging"},
    "__ZN6spdlog13stdout_color_mt": {"lib": "spdlog", "purpose": "spdlog::stdout_color_mt (colored stdout logger)", "category": "logging"},
    "__ZN6spdlog": {"lib": "spdlog", "purpose": "spdlog:: namespace (partial mangled prefix)", "category": "logging"},
    # log4cxx
    "__ZN7log4cxx6Logger": {"lib": "log4cxx", "purpose": "log4cxx::Logger (partial mangled)", "category": "logging"},
    "__ZN7log4cxx10BasicConfigurator": {"lib": "log4cxx", "purpose": "log4cxx::BasicConfigurator (partial mangled)", "category": "logging"},
    "__ZN7log4cxx20PropertyConfigurator": {"lib": "log4cxx", "purpose": "log4cxx::PropertyConfigurator (partial mangled)", "category": "logging"},
    "__ZN7log4cxx18DOMConfigurator": {"lib": "log4cxx", "purpose": "log4cxx::DOMConfigurator (partial mangled)", "category": "logging"},
    "__ZN7log4cxx5Level": {"lib": "log4cxx", "purpose": "log4cxx::Level (partial mangled)", "category": "logging"},
    "__ZN7log4cxx": {"lib": "log4cxx", "purpose": "log4cxx:: namespace (partial mangled prefix)", "category": "logging"},
    # glog
    "__ZN6google17InitGoogleLogging": {"lib": "glog", "purpose": "google::InitGoogleLogging (init glog)", "category": "logging"},
    "__ZN6google10LogMessage": {"lib": "glog", "purpose": "google::LogMessage (log message class)", "category": "logging"},
    "__ZN6google20ShutdownGoogleLogging": {"lib": "glog", "purpose": "google::ShutdownGoogleLogging (shutdown glog)", "category": "logging"},
    "__ZN6google11SetLogDestination": {"lib": "glog", "purpose": "google::SetLogDestination (set log output)", "category": "logging"},
    "__ZN6google17SetLogFilenameExtension": {"lib": "glog", "purpose": "google::SetLogFilenameExtension (set log extension)", "category": "logging"},
    "__ZN6google15InstallFailureSignalHandler": {"lib": "glog", "purpose": "google::InstallFailureSignalHandler (crash handler)", "category": "logging"},
    "__ZN6google8RawLog__": {"lib": "glog", "purpose": "google::RawLog__ (raw log without allocations)", "category": "logging"},
    # GLib logging
    "_g_log": {"lib": "glib", "purpose": "GLib structured log message", "category": "logging"},
    "_g_warning": {"lib": "glib", "purpose": "GLib warning message", "category": "logging"},
    "_g_error": {"lib": "glib", "purpose": "GLib error message (aborts)", "category": "logging"},
    "_g_message": {"lib": "glib", "purpose": "GLib informational message", "category": "logging"},
    "_g_debug": {"lib": "glib", "purpose": "GLib debug message", "category": "logging"},
    # Android logging
    "___android_log_print": {"lib": "android", "purpose": "Android logcat print (printf-style)", "category": "logging"},
    "___android_log_write": {"lib": "android", "purpose": "Android logcat write (simple string)", "category": "logging"},
    # macOS unified logging (os_log)
    "_os_log_create": {"lib": "os_log", "purpose": "Create os_log object (subsystem+category)", "category": "logging"},
    "_os_log": {"lib": "os_log", "purpose": "Log message via unified logging", "category": "logging"},
    "_os_log_error": {"lib": "os_log", "purpose": "Log error via unified logging", "category": "logging"},
    "_os_log_debug": {"lib": "os_log", "purpose": "Log debug via unified logging", "category": "logging"},
    "_os_log_info": {"lib": "os_log", "purpose": "Log info via unified logging", "category": "logging"},
    # Apple System Log (legacy)
    "_asl_open": {"lib": "asl", "purpose": "Open ASL client handle (legacy)", "category": "logging"},
    "_asl_log": {"lib": "asl", "purpose": "Log message via ASL (legacy)", "category": "logging"},
    "_asl_close": {"lib": "asl", "purpose": "Close ASL client handle (legacy)", "category": "logging"},
}


# ---------------------------------------------------------------------------
# logging_ext (38 entry) — POSIX syslog, systemd journal/sd-bus, libdbus,
# Windows ETW (Event Tracing for Windows), Windows Performance Data Helper.
# Kaynak: signature_db.py satir 6590-6640.
#
# NOT: Bu dict tarihsel olarak "logging/observability" sepetinde tutulmustur;
# ``ipc`` (D-Bus) ve ``win_perf`` (PDH) kategorileri burada *misafir*. Faz 9
# kapsami sadece tasimadir; yeniden kategorize etme islemi A-DELETE veya
# sonraki rafinaj fazlarinda ele alinir.
# ---------------------------------------------------------------------------
_LOGGING_EXT_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # --- syslog ---
    "openlog": {"lib": "libc", "purpose": "open connection to syslog", "category": "logging"},
    "syslog": {"lib": "libc", "purpose": "submit message to syslog", "category": "logging"},
    "closelog": {"lib": "libc", "purpose": "close syslog connection", "category": "logging"},
    "setlogmask": {"lib": "libc", "purpose": "set syslog priority mask", "category": "logging"},
    "vsyslog": {"lib": "libc", "purpose": "submit formatted message to syslog", "category": "logging"},

    # --- systemd journal ---
    "sd_journal_print": {"lib": "libsystemd", "purpose": "submit message to systemd journal", "category": "logging"},
    "sd_journal_send": {"lib": "libsystemd", "purpose": "submit structured entry to journal", "category": "logging"},
    "sd_journal_open": {"lib": "libsystemd", "purpose": "open journal for reading", "category": "logging"},
    "sd_journal_close": {"lib": "libsystemd", "purpose": "close journal handle", "category": "logging"},
    "sd_journal_next": {"lib": "libsystemd", "purpose": "advance to next journal entry", "category": "logging"},
    "sd_journal_get_data": {"lib": "libsystemd", "purpose": "get journal entry field data", "category": "logging"},
    "sd_journal_seek_tail": {"lib": "libsystemd", "purpose": "seek to end of journal", "category": "logging"},
    "sd_journal_wait": {"lib": "libsystemd", "purpose": "wait for new journal entries", "category": "logging"},

    # --- systemd misc ---
    "sd_notify": {"lib": "libsystemd", "purpose": "notify systemd about service state", "category": "logging"},
    "sd_bus_open_system": {"lib": "libsystemd", "purpose": "open system D-Bus connection", "category": "ipc"},
    "sd_bus_open_user": {"lib": "libsystemd", "purpose": "open user D-Bus connection", "category": "ipc"},
    "sd_bus_call_method": {"lib": "libsystemd", "purpose": "call D-Bus method", "category": "ipc"},
    "sd_bus_message_read": {"lib": "libsystemd", "purpose": "read D-Bus message data", "category": "ipc"},

    # --- D-Bus (libdbus) ---
    "dbus_bus_get": {"lib": "libdbus", "purpose": "connect to message bus", "category": "ipc"},
    "dbus_connection_send": {"lib": "libdbus", "purpose": "send D-Bus message", "category": "ipc"},
    "dbus_connection_flush": {"lib": "libdbus", "purpose": "flush D-Bus connection", "category": "ipc"},
    "dbus_message_new_method_call": {"lib": "libdbus", "purpose": "create D-Bus method call message", "category": "ipc"},
    "dbus_message_append_args": {"lib": "libdbus", "purpose": "append arguments to D-Bus message", "category": "ipc"},
    "dbus_message_get_args": {"lib": "libdbus", "purpose": "get arguments from D-Bus message", "category": "ipc"},
    "dbus_message_unref": {"lib": "libdbus", "purpose": "release D-Bus message reference", "category": "ipc"},
    "dbus_connection_read_write": {"lib": "libdbus", "purpose": "read/write on D-Bus connection", "category": "ipc"},
    "dbus_connection_pop_message": {"lib": "libdbus", "purpose": "pop incoming D-Bus message", "category": "ipc"},
    "dbus_connection_unref": {"lib": "libdbus", "purpose": "release D-Bus connection reference", "category": "ipc"},

    # --- Windows ETW ---
    "EventRegister": {"lib": "advapi32", "purpose": "register ETW event provider", "category": "win_etw"},
    "EventWrite": {"lib": "advapi32", "purpose": "write ETW event", "category": "win_etw"},
    "EventUnregister": {"lib": "advapi32", "purpose": "unregister ETW event provider", "category": "win_etw"},
    "EventWriteTransfer": {"lib": "advapi32", "purpose": "write ETW event with activity transfer", "category": "win_etw"},
    "EventActivityIdControl": {"lib": "advapi32", "purpose": "manage ETW activity ID", "category": "win_etw"},

    # --- Windows Performance Counters ---
    "PdhOpenQueryA": {"lib": "pdh", "purpose": "open PDH query handle", "category": "win_perf"},
    "PdhAddCounterA": {"lib": "pdh", "purpose": "add performance counter to query", "category": "win_perf"},
    "PdhCollectQueryData": {"lib": "pdh", "purpose": "collect performance data", "category": "win_perf"},
    "PdhGetFormattedCounterValue": {"lib": "pdh", "purpose": "get formatted counter value", "category": "win_perf"},
    "PdhCloseQuery": {"lib": "pdh", "purpose": "close PDH query handle", "category": "win_perf"},
}


# ---------------------------------------------------------------------------
# Dispatcher hook — sigdb_builtin.get_category("logging") bu dict'i alir.
# Anahtar isimleri signature_db.py'deki orijinal dict adlariyla uyumludur
# (ornek: "logging_signatures" <-> _LOGGING_SIGNATURES).
# ---------------------------------------------------------------------------
SIGNATURES: dict[str, Any] = {
    "logging_signatures": _LOGGING_SIGNATURES_DATA,
    "logging_ext_signatures": _LOGGING_EXT_SIGNATURES_DATA,
}


__all__ = ["SIGNATURES"]
