"""Strings/STL/Boost kategori signature'lari — sig_db v1.13 Dalga 2 Faz A12.

Kaynak: ``karadul/analyzers/signature_db.py``
  - ``_CPP_STL_SIGNATURES``    (60 entry, satir 1809-2025)  -> libc++ STL & ABI
  - ``_BOOST_SIGNATURES``      (58 entry, satir 2628-2696)  -> Boost C++
  - ``_ABSEIL_SIGNATURES``     (43 entry, satir 2703-2755)  -> Google Abseil
  - ``_FOLLY_SIGNATURES``      (32 entry, satir 2762-2805)  -> Facebook Folly

Toplam: 193 imza.

ADR 0007 v1.13 Dalga 2 Faz A12 kapsami sadece "shadow copy" olusturmaktir;
``signature_db.py`` legacy in-place dict gövdeleri korunur (dokunulmaz). Identity
/ shadow-bind / dismantle islemi v1.13 sonrasi A-DELETE fazinda yapilir.

Anahtar isimleri ``signature_db.py`` orijinal dict adlariyla uyumludur:
  ``cpp_stl``    <-> ``_CPP_STL_SIGNATURES``
  ``boost``      <-> ``_BOOST_SIGNATURES``
  ``abseil``     <-> ``_ABSEIL_SIGNATURES``
  ``folly``      <-> ``_FOLLY_SIGNATURES``

Veri format: ``dict[str, dict[str, str]]`` — her entry {"lib","purpose","category"}.
"""
from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# C++ STL (libc++ mangled names) — 60 entry
# Kaynak: signature_db.py satir 1809-2025
# ---------------------------------------------------------------------------
_CPP_STL_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # std::string
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1Ev": {
        "lib": "libc++", "purpose": "std::string default constructor", "category": "stl",
    },
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1EPKc": {
        "lib": "libc++", "purpose": "std::string(const char*) constructor", "category": "stl",
    },
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED1Ev": {
        "lib": "libc++", "purpose": "std::string destructor", "category": "stl",
    },
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKc": {
        "lib": "libc++", "purpose": "std::string::append(const char*)", "category": "stl",
    },
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6assignEPKc": {
        "lib": "libc++", "purpose": "std::string::assign(const char*)", "category": "stl",
    },
    "__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4findEPKcm": {
        "lib": "libc++", "purpose": "std::string::find(const char*, pos)", "category": "stl",
    },
    "__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6substrEmm": {
        "lib": "libc++", "purpose": "std::string::substr(pos, len)", "category": "stl",
    },
    "__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5c_strEv": {
        "lib": "libc++", "purpose": "std::string::c_str()", "category": "stl",
    },

    # std::vector (partial mangled prefixes -- pattern match yapilabilir)
    "__ZNSt3__16vectorI": {
        "lib": "libc++", "purpose": "std::vector<T> method (partial mangled)", "category": "stl",
    },

    # std::map
    "__ZNSt3__13mapI": {
        "lib": "libc++", "purpose": "std::map<K,V> method (partial mangled)", "category": "stl",
    },

    # std::unordered_map
    "__ZNSt3__113unordered_mapI": {
        "lib": "libc++", "purpose": "std::unordered_map<K,V> method (partial mangled)", "category": "stl",
    },

    # std::list
    "__ZNSt3__14listI": {
        "lib": "libc++", "purpose": "std::list<T> method (partial mangled)", "category": "stl",
    },

    # std::deque
    "__ZNSt3__15dequeI": {
        "lib": "libc++", "purpose": "std::deque<T> method (partial mangled)", "category": "stl",
    },

    # std::set
    "__ZNSt3__13setI": {
        "lib": "libc++", "purpose": "std::set<T> method (partial mangled)", "category": "stl",
    },

    # std::sort
    "__ZNSt3__14sortI": {
        "lib": "libc++", "purpose": "std::sort<Iter> (partial mangled)", "category": "stl",
    },

    # std::mutex
    "__ZNSt3__15mutexC1Ev": {
        "lib": "libc++", "purpose": "std::mutex default constructor", "category": "stl",
    },
    "__ZNSt3__15mutex4lockEv": {
        "lib": "libc++", "purpose": "std::mutex::lock()", "category": "stl",
    },
    "__ZNSt3__15mutex6unlockEv": {
        "lib": "libc++", "purpose": "std::mutex::unlock()", "category": "stl",
    },
    "__ZNSt3__15mutex8try_lockEv": {
        "lib": "libc++", "purpose": "std::mutex::try_lock()", "category": "stl",
    },
    "__ZNSt3__15mutexD1Ev": {
        "lib": "libc++", "purpose": "std::mutex destructor", "category": "stl",
    },

    # std::condition_variable
    "__ZNSt3__118condition_variableC1Ev": {
        "lib": "libc++", "purpose": "std::condition_variable constructor", "category": "stl",
    },
    "__ZNSt3__118condition_variableD1Ev": {
        "lib": "libc++", "purpose": "std::condition_variable destructor", "category": "stl",
    },
    "__ZNSt3__118condition_variable4waitERNS_11unique_lockINS_5mutexEEE": {
        "lib": "libc++", "purpose": "std::condition_variable::wait(unique_lock&)", "category": "stl",
    },
    "__ZNSt3__118condition_variable10notify_oneEv": {
        "lib": "libc++", "purpose": "std::condition_variable::notify_one()", "category": "stl",
    },
    "__ZNSt3__118condition_variable10notify_allEv": {
        "lib": "libc++", "purpose": "std::condition_variable::notify_all()", "category": "stl",
    },

    # std::thread
    "__ZNSt3__16threadC1I": {
        "lib": "libc++", "purpose": "std::thread constructor (partial mangled)", "category": "stl",
    },
    "__ZNSt3__16threadD1Ev": {
        "lib": "libc++", "purpose": "std::thread destructor", "category": "stl",
    },
    "__ZNSt3__16thread4joinEv": {
        "lib": "libc++", "purpose": "std::thread::join()", "category": "stl",
    },
    "__ZNSt3__16thread6detachEv": {
        "lib": "libc++", "purpose": "std::thread::detach()", "category": "stl",
    },

    # I/O streams
    "__ZNSt3__114basic_ifstreamIcNS_11char_traitsIcEEEC1Ev": {
        "lib": "libc++", "purpose": "std::ifstream default constructor", "category": "stl",
    },
    "__ZNSt3__114basic_ifstreamIcNS_11char_traitsIcEEED1Ev": {
        "lib": "libc++", "purpose": "std::ifstream destructor", "category": "stl",
    },
    "__ZNSt3__114basic_ofstreamIcNS_11char_traitsIcEEEC1Ev": {
        "lib": "libc++", "purpose": "std::ofstream default constructor", "category": "stl",
    },
    "__ZNSt3__114basic_ofstreamIcNS_11char_traitsIcEEED1Ev": {
        "lib": "libc++", "purpose": "std::ofstream destructor", "category": "stl",
    },
    "__ZNSt3__118basic_stringstreamIcNS_11char_traitsIcEENS_9allocatorIcEEEC1Ev": {
        "lib": "libc++", "purpose": "std::stringstream default constructor", "category": "stl",
    },
    "__ZNSt3__118basic_stringstreamIcNS_11char_traitsIcEENS_9allocatorIcEEED1Ev": {
        "lib": "libc++", "purpose": "std::stringstream destructor", "category": "stl",
    },

    # std::cerr, std::cout globals
    "__ZNSt3__14cerrE": {
        "lib": "libc++", "purpose": "std::cerr global error stream", "category": "stl",
    },
    "__ZNSt3__14coutE": {
        "lib": "libc++", "purpose": "std::cout global output stream", "category": "stl",
    },
    "__ZNSt3__14clogE": {
        "lib": "libc++", "purpose": "std::clog global log stream", "category": "stl",
    },
    "__ZNSt3__14cinE": {
        "lib": "libc++", "purpose": "std::cin global input stream", "category": "stl",
    },

    # C++ exception handling (ABI)
    "___cxa_throw": {
        "lib": "libc++abi", "purpose": "C++ throw exception", "category": "stl",
    },
    "___cxa_begin_catch": {
        "lib": "libc++abi", "purpose": "C++ catch block begin", "category": "stl",
    },
    "___cxa_end_catch": {
        "lib": "libc++abi", "purpose": "C++ catch block end", "category": "stl",
    },
    "___cxa_rethrow": {
        "lib": "libc++abi", "purpose": "C++ rethrow exception", "category": "stl",
    },
    "___cxa_allocate_exception": {
        "lib": "libc++abi", "purpose": "C++ allocate exception object", "category": "stl",
    },
    "___cxa_free_exception": {
        "lib": "libc++abi", "purpose": "C++ free exception object", "category": "stl",
    },
    "___cxa_pure_virtual": {
        "lib": "libc++abi", "purpose": "C++ pure virtual function called (abort)", "category": "stl",
    },

    # terminate / unexpected
    "__ZSt9terminatev": {
        "lib": "libc++abi", "purpose": "std::terminate()", "category": "stl",
    },
    "__ZSt14set_unexpectedPFvvE": {
        "lib": "libc++abi", "purpose": "std::set_unexpected(handler)", "category": "stl",
    },
    "__ZSt13set_terminatePFvvE": {
        "lib": "libc++abi", "purpose": "std::set_terminate(handler)", "category": "stl",
    },

    # operator new / delete
    "__Znwm": {
        "lib": "libc++", "purpose": "operator new(size_t)", "category": "stl",
    },
    "__ZnwmRKSt9nothrow_t": {
        "lib": "libc++", "purpose": "operator new(size_t, nothrow_t)", "category": "stl",
    },
    "__Znam": {
        "lib": "libc++", "purpose": "operator new[](size_t)", "category": "stl",
    },
    "__ZdlPv": {
        "lib": "libc++", "purpose": "operator delete(void*)", "category": "stl",
    },
    "__ZdlPvm": {
        "lib": "libc++", "purpose": "operator delete(void*, size_t)", "category": "stl",
    },
    "__ZdaPv": {
        "lib": "libc++", "purpose": "operator delete[](void*)", "category": "stl",
    },

    # RTTI
    "__ZTI": {
        "lib": "libc++abi", "purpose": "C++ typeinfo (partial mangled prefix)", "category": "stl",
    },
    "__ZTS": {
        "lib": "libc++abi", "purpose": "C++ typeinfo name (partial mangled prefix)", "category": "stl",
    },
    "__ZTV": {
        "lib": "libc++abi", "purpose": "C++ vtable (partial mangled prefix)", "category": "stl",
    },

    # std::shared_ptr / weak_ptr internals
    "__ZNSt3__120__shared_ptr_emplace": {
        "lib": "libc++", "purpose": "std::shared_ptr emplace (partial mangled)", "category": "stl",
    },
    "__ZNSt3__115__thread_struct": {
        "lib": "libc++", "purpose": "std::__thread_struct internal (partial mangled)", "category": "stl",
    },
}


# ---------------------------------------------------------------------------
# Boost C++ Libraries — 58 entry
# Kaynak: signature_db.py satir 2628-2696
# ---------------------------------------------------------------------------
_BOOST_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # boost::asio
    "__ZN5boost4asio10io_context": {"lib": "boost", "purpose": "boost::asio::io_context (partial mangled)", "category": "network"},
    "__ZN5boost4asio2ip3tcp6socket": {"lib": "boost", "purpose": "boost::asio::ip::tcp::socket (partial mangled)", "category": "network"},
    "__ZN5boost4asio2ip3tcp8acceptor": {"lib": "boost", "purpose": "boost::asio::ip::tcp::acceptor (partial mangled)", "category": "network"},
    "__ZN5boost4asio2ip3tcp8resolver": {"lib": "boost", "purpose": "boost::asio::ip::tcp::resolver (partial mangled)", "category": "network"},
    "__ZN5boost4asio2ip3udp6socket": {"lib": "boost", "purpose": "boost::asio::ip::udp::socket (partial mangled)", "category": "network"},
    "__ZN5boost4asio3ssl6stream": {"lib": "boost", "purpose": "boost::asio::ssl::stream (partial mangled)", "category": "network"},
    "__ZN5boost4asio14deadline_timer": {"lib": "boost", "purpose": "boost::asio::deadline_timer (partial mangled)", "category": "network"},
    "__ZN5boost4asio12steady_timer": {"lib": "boost", "purpose": "boost::asio::steady_timer (partial mangled)", "category": "network"},
    "__ZN5boost4asio10async_read": {"lib": "boost", "purpose": "boost::asio::async_read (partial mangled)", "category": "network"},
    "__ZN5boost4asio11async_write": {"lib": "boost", "purpose": "boost::asio::async_write (partial mangled)", "category": "network"},
    "__ZN5boost4asio13async_connect": {"lib": "boost", "purpose": "boost::asio::async_connect (partial mangled)", "category": "network"},
    "__ZN5boost4asio": {"lib": "boost", "purpose": "boost::asio namespace (partial mangled prefix)", "category": "network"},
    # boost::filesystem
    "__ZN5boost10filesystem4path": {"lib": "boost", "purpose": "boost::filesystem::path (partial mangled)", "category": "filesystem"},
    "__ZN5boost10filesystem18directory_iterator": {"lib": "boost", "purpose": "boost::filesystem::directory_iterator (partial mangled)", "category": "filesystem"},
    "__ZN5boost10filesystem28recursive_directory_iterator": {"lib": "boost", "purpose": "boost::filesystem::recursive_directory_iterator (partial mangled)", "category": "filesystem"},
    "__ZN5boost10filesystem18create_directories": {"lib": "boost", "purpose": "boost::filesystem::create_directories (partial mangled)", "category": "filesystem"},
    "__ZN5boost10filesystem10remove_all": {"lib": "boost", "purpose": "boost::filesystem::remove_all (partial mangled)", "category": "filesystem"},
    "__ZN5boost10filesystem9copy_file": {"lib": "boost", "purpose": "boost::filesystem::copy_file (partial mangled)", "category": "filesystem"},
    "__ZN5boost10filesystem6exists": {"lib": "boost", "purpose": "boost::filesystem::exists (partial mangled)", "category": "filesystem"},
    "__ZN5boost10filesystem12is_directory": {"lib": "boost", "purpose": "boost::filesystem::is_directory (partial mangled)", "category": "filesystem"},
    "__ZN5boost10filesystem12is_regular_f": {"lib": "boost", "purpose": "boost::filesystem::is_regular_file (partial mangled)", "category": "filesystem"},
    "__ZN5boost10filesystem9file_size": {"lib": "boost", "purpose": "boost::filesystem::file_size (partial mangled)", "category": "filesystem"},
    "__ZN5boost10filesystem": {"lib": "boost", "purpose": "boost::filesystem namespace (partial mangled prefix)", "category": "filesystem"},
    # boost::thread
    "__ZN5boost6thread": {"lib": "boost", "purpose": "boost::thread (partial mangled)", "category": "concurrency"},
    "__ZN5boost5mutex": {"lib": "boost", "purpose": "boost::mutex (partial mangled)", "category": "concurrency"},
    "__ZN5boost12shared_mutex": {"lib": "boost", "purpose": "boost::shared_mutex (partial mangled)", "category": "concurrency"},
    "__ZN5boost18condition_variable": {"lib": "boost", "purpose": "boost::condition_variable (partial mangled)", "category": "concurrency"},
    "__ZN5boost6future": {"lib": "boost", "purpose": "boost::future (partial mangled)", "category": "concurrency"},
    "__ZN5boost7promise": {"lib": "boost", "purpose": "boost::promise (partial mangled)", "category": "concurrency"},
    # boost::algorithm
    "__ZN5boost9algorithm8to_lower": {"lib": "boost", "purpose": "boost::algorithm::to_lower (partial mangled)", "category": "string"},
    "__ZN5boost9algorithm8to_upper": {"lib": "boost", "purpose": "boost::algorithm::to_upper (partial mangled)", "category": "string"},
    "__ZN5boost9algorithm4trim": {"lib": "boost", "purpose": "boost::algorithm::trim (partial mangled)", "category": "string"},
    "__ZN5boost9algorithm5split": {"lib": "boost", "purpose": "boost::algorithm::split (partial mangled)", "category": "string"},
    "__ZN5boost9algorithm4join": {"lib": "boost", "purpose": "boost::algorithm::join (partial mangled)", "category": "string"},
    "__ZN5boost9algorithm11replace_all": {"lib": "boost", "purpose": "boost::algorithm::replace_all (partial mangled)", "category": "string"},
    "__ZN5boost9algorithm": {"lib": "boost", "purpose": "boost::algorithm namespace (partial mangled prefix)", "category": "string"},
    # boost::program_options
    "__ZN5boost15program_options19options_description": {"lib": "boost", "purpose": "boost::program_options::options_description (partial mangled)", "category": "config"},
    "__ZN5boost15program_options13variables_map": {"lib": "boost", "purpose": "boost::program_options::variables_map (partial mangled)", "category": "config"},
    "__ZN5boost15program_options5store": {"lib": "boost", "purpose": "boost::program_options::store (partial mangled)", "category": "config"},
    "__ZN5boost15program_options6notify": {"lib": "boost", "purpose": "boost::program_options::notify (partial mangled)", "category": "config"},
    "__ZN5boost15program_options": {"lib": "boost", "purpose": "boost::program_options namespace (partial mangled prefix)", "category": "config"},
    # boost::beast
    "__ZN5boost5beast4http7request": {"lib": "boost", "purpose": "boost::beast::http::request (partial mangled)", "category": "network"},
    "__ZN5boost5beast4http8response": {"lib": "boost", "purpose": "boost::beast::http::response (partial mangled)", "category": "network"},
    "__ZN5boost5beast4http4read": {"lib": "boost", "purpose": "boost::beast::http::read (partial mangled)", "category": "network"},
    "__ZN5boost5beast4http5write": {"lib": "boost", "purpose": "boost::beast::http::write (partial mangled)", "category": "network"},
    "__ZN5boost5beast9websocket6stream": {"lib": "boost", "purpose": "boost::beast::websocket::stream (partial mangled)", "category": "network"},
    "__ZN5boost5beast": {"lib": "boost", "purpose": "boost::beast namespace (partial mangled prefix)", "category": "network"},
    # boost::json
    "__ZN5boost4json5parse": {"lib": "boost", "purpose": "boost::json::parse (partial mangled)", "category": "serialization"},
    "__ZN5boost4json9serialize": {"lib": "boost", "purpose": "boost::json::serialize (partial mangled)", "category": "serialization"},
    "__ZN5boost4json5value": {"lib": "boost", "purpose": "boost::json::value (partial mangled)", "category": "serialization"},
    "__ZN5boost4json6object": {"lib": "boost", "purpose": "boost::json::object (partial mangled)", "category": "serialization"},
    "__ZN5boost4json5array": {"lib": "boost", "purpose": "boost::json::array (partial mangled)", "category": "serialization"},
    "__ZN5boost4json": {"lib": "boost", "purpose": "boost::json namespace (partial mangled prefix)", "category": "serialization"},
    # boost::log
    "__ZN5boost3log": {"lib": "boost", "purpose": "boost::log namespace (partial mangled prefix)", "category": "logging"},
    # boost::regex
    "__ZN5boost5regex": {"lib": "boost", "purpose": "boost::regex (partial mangled)", "category": "string"},
    "__ZN5boost11regex_match": {"lib": "boost", "purpose": "boost::regex_match (partial mangled)", "category": "string"},
    "__ZN5boost12regex_search": {"lib": "boost", "purpose": "boost::regex_search (partial mangled)", "category": "string"},
    "__ZN5boost13regex_replace": {"lib": "boost", "purpose": "boost::regex_replace (partial mangled)", "category": "string"},
}


# ---------------------------------------------------------------------------
# Google Abseil — 43 entry
# Kaynak: signature_db.py satir 2703-2755
# ---------------------------------------------------------------------------
_ABSEIL_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    "__ZN4absl": {"lib": "abseil", "purpose": "absl:: namespace (partial mangled prefix)", "category": "utility"},
    # String utilities
    "__ZN4absl6StrCat": {"lib": "abseil", "purpose": "absl::StrCat (partial mangled)", "category": "string"},
    "__ZN4absl7StrJoin": {"lib": "abseil", "purpose": "absl::StrJoin (partial mangled)", "category": "string"},
    "__ZN4absl8StrSplit": {"lib": "abseil", "purpose": "absl::StrSplit (partial mangled)", "category": "string"},
    "__ZN4absl9StrFormat": {"lib": "abseil", "purpose": "absl::StrFormat (partial mangled)", "category": "string"},
    "__ZN4absl10Substitute": {"lib": "abseil", "purpose": "absl::Substitute (partial mangled)", "category": "string"},
    "__ZN4absl9StrAppend": {"lib": "abseil", "purpose": "absl::StrAppend (partial mangled)", "category": "string"},
    "__ZN4absl11string_view": {"lib": "abseil", "purpose": "absl::string_view (partial mangled)", "category": "string"},
    # Containers
    "__ZN4absl13flat_hash_map": {"lib": "abseil", "purpose": "absl::flat_hash_map (partial mangled)", "category": "container"},
    "__ZN4absl13flat_hash_set": {"lib": "abseil", "purpose": "absl::flat_hash_set (partial mangled)", "category": "container"},
    "__ZN4absl13node_hash_map": {"lib": "abseil", "purpose": "absl::node_hash_map (partial mangled)", "category": "container"},
    "__ZN4absl13node_hash_set": {"lib": "abseil", "purpose": "absl::node_hash_set (partial mangled)", "category": "container"},
    "__ZN4absl13InlinedVector": {"lib": "abseil", "purpose": "absl::InlinedVector (partial mangled)", "category": "container"},
    "__ZN4absl10FixedArray": {"lib": "abseil", "purpose": "absl::FixedArray (partial mangled)", "category": "container"},
    "__ZN4absl4Span": {"lib": "abseil", "purpose": "absl::Span (partial mangled)", "category": "container"},
    "__ZN4absl15btree_multimap": {"lib": "abseil", "purpose": "absl::btree_multimap (partial mangled)", "category": "container"},
    "__ZN4absl9btree_map": {"lib": "abseil", "purpose": "absl::btree_map (partial mangled)", "category": "container"},
    "__ZN4absl9btree_set": {"lib": "abseil", "purpose": "absl::btree_set (partial mangled)", "category": "container"},
    # Status
    "__ZN4absl6Status": {"lib": "abseil", "purpose": "absl::Status (partial mangled)", "category": "error"},
    "__ZN4absl8StatusOr": {"lib": "abseil", "purpose": "absl::StatusOr (partial mangled)", "category": "error"},
    "__ZN4absl8OkStatus": {"lib": "abseil", "purpose": "absl::OkStatus (partial mangled)", "category": "error"},
    "__ZN4absl15AbortedError": {"lib": "abseil", "purpose": "absl::AbortedError (partial mangled)", "category": "error"},
    "__ZN4absl18InvalidArgumentError": {"lib": "abseil", "purpose": "absl::InvalidArgumentError (partial mangled)", "category": "error"},
    "__ZN4absl14NotFoundError": {"lib": "abseil", "purpose": "absl::NotFoundError (partial mangled)", "category": "error"},
    # Synchronization
    "__ZN4absl5Mutex": {"lib": "abseil", "purpose": "absl::Mutex (partial mangled)", "category": "concurrency"},
    "__ZN4absl9MutexLock": {"lib": "abseil", "purpose": "absl::MutexLock (partial mangled)", "category": "concurrency"},
    "__ZN4absl7CondVar": {"lib": "abseil", "purpose": "absl::CondVar (partial mangled)", "category": "concurrency"},
    "__ZN4absl13base_internal8SpinLock": {"lib": "abseil", "purpose": "absl::base_internal::SpinLock (partial mangled)", "category": "concurrency"},
    "__ZN4absl11Notification": {"lib": "abseil", "purpose": "absl::Notification (partial mangled)", "category": "concurrency"},
    # Time
    "__ZN4absl8Duration": {"lib": "abseil", "purpose": "absl::Duration (partial mangled)", "category": "time"},
    "__ZN4absl4Time": {"lib": "abseil", "purpose": "absl::Time (partial mangled)", "category": "time"},
    "__ZN4absl3Now": {"lib": "abseil", "purpose": "absl::Now (partial mangled)", "category": "time"},
    "__ZN4absl8SleepFor": {"lib": "abseil", "purpose": "absl::SleepFor (partial mangled)", "category": "time"},
    "__ZN4absl7Seconds": {"lib": "abseil", "purpose": "absl::Seconds (partial mangled)", "category": "time"},
    "__ZN4absl12Milliseconds": {"lib": "abseil", "purpose": "absl::Milliseconds (partial mangled)", "category": "time"},
    "__ZN4absl12Microseconds": {"lib": "abseil", "purpose": "absl::Microseconds (partial mangled)", "category": "time"},
    "__ZN4absl11Nanoseconds": {"lib": "abseil", "purpose": "absl::Nanoseconds (partial mangled)", "category": "time"},
    # Flags
    "__ZN4absl7GetFlag": {"lib": "abseil", "purpose": "absl::GetFlag (partial mangled)", "category": "config"},
    "__ZN4absl7SetFlag": {"lib": "abseil", "purpose": "absl::SetFlag (partial mangled)", "category": "config"},
    "__ZN4absl16ParseCommandLine": {"lib": "abseil", "purpose": "absl::ParseCommandLine (partial mangled)", "category": "config"},
    # Logging
    "__ZN4absl10LogMessage": {"lib": "abseil", "purpose": "absl::LogMessage (partial mangled)", "category": "logging"},
    # Hashing
    "__ZN4absl7HashOf": {"lib": "abseil", "purpose": "absl::HashOf (partial mangled)", "category": "utility"},
    "__ZN4absl11MakeHashState": {"lib": "abseil", "purpose": "absl::MakeHashState (partial mangled)", "category": "utility"},
}


# ---------------------------------------------------------------------------
# Facebook Folly — 32 entry
# Kaynak: signature_db.py satir 2762-2805
# ---------------------------------------------------------------------------
_FOLLY_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    "__ZN5folly": {"lib": "folly", "purpose": "folly:: namespace (partial mangled prefix)", "category": "utility"},
    # Futures & Promises
    "__ZN5folly6Future": {"lib": "folly", "purpose": "folly::Future (partial mangled)", "category": "concurrency"},
    "__ZN5folly7Promise": {"lib": "folly", "purpose": "folly::Promise (partial mangled)", "category": "concurrency"},
    "__ZN5folly10makeFuture": {"lib": "folly", "purpose": "folly::makeFuture (partial mangled)", "category": "concurrency"},
    "__ZN5folly12SemiFuture": {"lib": "folly", "purpose": "folly::SemiFuture (partial mangled)", "category": "concurrency"},
    # Strings & Data
    "__ZN5folly8fbstring": {"lib": "folly", "purpose": "folly::fbstring (partial mangled)", "category": "string"},
    "__ZN5folly8fbvector": {"lib": "folly", "purpose": "folly::fbvector (partial mangled)", "category": "container"},
    "__ZN5folly7dynamic": {"lib": "folly", "purpose": "folly::dynamic (partial mangled)", "category": "serialization"},
    "__ZN5folly9parseJson": {"lib": "folly", "purpose": "folly::parseJson (partial mangled)", "category": "serialization"},
    "__ZN5folly6toJson": {"lib": "folly", "purpose": "folly::toJson (partial mangled)", "category": "serialization"},
    "__ZN5folly11toPrettyJson": {"lib": "folly", "purpose": "folly::toPrettyJson (partial mangled)", "category": "serialization"},
    # IO
    "__ZN5folly5IOBuf": {"lib": "folly", "purpose": "folly::IOBuf (partial mangled)", "category": "io"},
    "__ZN5folly10IOBufQueue": {"lib": "folly", "purpose": "folly::IOBufQueue (partial mangled)", "category": "io"},
    # Event & Async
    "__ZN5folly9EventBase": {"lib": "folly", "purpose": "folly::EventBase (partial mangled)", "category": "network"},
    "__ZN5folly11AsyncSocket": {"lib": "folly", "purpose": "folly::AsyncSocket (partial mangled)", "category": "network"},
    "__ZN5folly17AsyncServerSocket": {"lib": "folly", "purpose": "folly::AsyncServerSocket (partial mangled)", "category": "network"},
    "__ZN5folly17AsyncSSLSocket": {"lib": "folly", "purpose": "folly::AsyncSSLSocket (partial mangled)", "category": "network"},
    # Executors
    "__ZN5folly8Executor": {"lib": "folly", "purpose": "folly::Executor (partial mangled)", "category": "concurrency"},
    "__ZN5folly21CPUThreadPoolExecutor": {"lib": "folly", "purpose": "folly::CPUThreadPoolExecutor (partial mangled)", "category": "concurrency"},
    "__ZN5folly20IOThreadPoolExecutor": {"lib": "folly", "purpose": "folly::IOThreadPoolExecutor (partial mangled)", "category": "concurrency"},
    "__ZN5folly13ManualExecutor": {"lib": "folly", "purpose": "folly::ManualExecutor (partial mangled)", "category": "concurrency"},
    "__ZN5folly15InlineExecutor": {"lib": "folly", "purpose": "folly::InlineExecutor (partial mangled)", "category": "concurrency"},
    # Singleton & Init
    "__ZN5folly9Singleton": {"lib": "folly", "purpose": "folly::Singleton (partial mangled)", "category": "utility"},
    "__ZN5folly4init": {"lib": "folly", "purpose": "folly::init (partial mangled)", "category": "utility"},
    # Optional / Expected
    "__ZN5folly8Optional": {"lib": "folly", "purpose": "folly::Optional (partial mangled)", "category": "utility"},
    "__ZN5folly8Expected": {"lib": "folly", "purpose": "folly::Expected (partial mangled)", "category": "utility"},
    # Concurrent containers
    "__ZN5folly17ConcurrentHashMap": {"lib": "folly", "purpose": "folly::ConcurrentHashMap (partial mangled)", "category": "container"},
    "__ZN5folly14AtomicHashMap": {"lib": "folly", "purpose": "folly::AtomicHashMap (partial mangled)", "category": "container"},
    "__ZN5folly17AtomicLinkedList": {"lib": "folly", "purpose": "folly::AtomicLinkedList (partial mangled)", "category": "container"},
    # Conv (type conversion)
    "__ZN5folly2to": {"lib": "folly", "purpose": "folly::to<T> conversion (partial mangled)", "category": "utility"},
    # Format
    "__ZN5folly6format": {"lib": "folly", "purpose": "folly::format (partial mangled)", "category": "string"},
    "__ZN5folly7sformat": {"lib": "folly", "purpose": "folly::sformat (partial mangled)", "category": "string"},
}


# ---------------------------------------------------------------------------
# Public surface — dispatcher tarafindan ``get_category("strings_module")``
# ile cagirilan agg dict.
# ---------------------------------------------------------------------------
SIGNATURES: dict[str, Any] = {
    "cpp_stl": _CPP_STL_SIGNATURES_DATA,
    "boost": _BOOST_SIGNATURES_DATA,
    "abseil": _ABSEIL_SIGNATURES_DATA,
    "folly": _FOLLY_SIGNATURES_DATA,
}


__all__ = ["SIGNATURES"]
