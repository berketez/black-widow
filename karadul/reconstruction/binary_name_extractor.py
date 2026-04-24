"""Binary Name Extractor -- Karadul v1.0

Binary'deki debug string'lerden, build path'lerden, enum sabitlerinden ve
RTTI bilgisinden orijinal degisken/class/fonksiyon isimlerini kurtarir.

LLM KULLANMAZ. Tamamen regex + heuristik tabanli.

4 Strateji:
  1. Debug String Parse  (conf 0.75-0.95) -- Class::Method + m_ degiskenleri
  2. Build Path Mapper   (conf 0.5-0.8)  -- __FILE__ macro kalintilarindan namespace
  3. Enum Handler Naming (conf 0.4-0.7)  -- k_EMsg switch-case handler'lari
  4. C++ Demangle (RTTI)  (conf 0.85-0.95) -- Mangled symbol demangling

Kullanim:
    from karadul.reconstruction.binary_name_extractor import BinaryNameExtractor
    from karadul.config import Config

    extractor = BinaryNameExtractor(Config())
    result = extractor.extract(
        strings_json=Path("workspace/static/ghidra_strings.json"),
        functions_json=Path("workspace/static/ghidra_functions.json"),
        call_graph_json=Path("workspace/static/ghidra_call_graph.json"),
    )
    print(f"Extracted: {result.total_extracted}, By source: {result.by_source}")
    naming_map = extractor.as_naming_map()  # c_namer uyumlu dict
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from karadul.config import Config
from karadul.reconstruction.string_intelligence import StringIntelligence

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Sonuc veri yapilari
# ---------------------------------------------------------------------------

@dataclass
class ExtractedName:
    """Tek bir kurtarilmis isim."""

    original_name: str       # Ghidra'nin verdigi isim (FUN_xxx, _SteamBootstrapper_...)
    recovered_name: str      # Kurtarilan gercek isim
    source: str              # "debug_string", "build_path", "enum_handler", "rtti"
    confidence: float        # 0.0-1.0
    evidence: str            # Nereden cikarildi (ornek string, path, symbol)
    class_name: str | None   # Ait oldugu class (varsa)
    source_file: str | None  # Kaynak dosya (varsa)


@dataclass
class ExtractionResult:
    """Toplam cikarim sonucu."""

    success: bool
    names: list[ExtractedName] = field(default_factory=list)
    class_methods: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    member_vars: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    source_files: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    total_extracted: int = 0
    by_source: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Dahili veri yapilari
# ---------------------------------------------------------------------------

@dataclass
class _XrefEntry:
    """Ghidra string xref bilgisi -- string'e referans veren fonksiyon."""

    from_address: int      # Referans veren instruction adresi
    from_function: str | None   # Referans veren fonksiyon ismi (None ise bilinmiyor)
    from_func_addr: int | None  # Referans veren fonksiyon entry point adresi


@dataclass
class _StringEntry:
    """Ghidra string JSON'dan parse edilmis tek string."""

    address: int       # Sayisal adres (hex parse edilmis)
    value: str
    length: int
    stype: str         # "string", "TerminatedCString", vb.
    xrefs: list[_XrefEntry] = field(default_factory=list)  # Cross-referanslar
    function: str | None = None        # Ilk xref'teki fonksiyon ismi
    function_addr: int | None = None   # Ilk xref'teki fonksiyon adresi


@dataclass
class _FuncEntry:
    """Ghidra function JSON'dan parse edilmis tek fonksiyon."""

    name: str
    address: int       # Sayisal adres
    size: int
    end_address: int   # address + size
    param_count: int
    return_type: str
    is_thunk: bool
    is_external: bool
    source: str        # "DEFAULT", "IMPORTED", ...
    parameters: list[dict]


@dataclass
class _CallGraphNode:
    """Call graph'tan tek node."""

    name: str
    address: int
    callers: list[str]    # Caller fonksiyon adresleri
    callees: list[str]    # Callee fonksiyon adresleri


# ---------------------------------------------------------------------------
# Regex pattern'leri -- tum stratejiler icin
# ---------------------------------------------------------------------------

# Strateji 1: Debug String Parse
# Class::Method (destructor dahil)
# NOT: Template parametreleri (<...>) icermeyen class::method pattern'leri
_CLASS_METHOD_RE = re.compile(
    r'\b([A-Z][A-Za-z0-9_]*::~?[A-Za-z_][A-Za-z0-9_]*)\b(?![>])'
)

# m_ prefix'li member degiskenler
_MEMBER_VAR_RE = re.compile(r'\b(m_[A-Za-z0-9_]{2,})\b')

# Assert/check ifadelerinden degisken isimleri
_ASSERT_EXPR_RE = re.compile(
    r'(?:assert|Assert|CHECK\s+failed:\s*\(|DCHECK)\s*[\(:]?\s*([^):\n]{3,80})'
)

# Strateji 2: Build Path Mapper
_BUILD_PATH_RE = re.compile(
    r'([/\\][\w/\\._-]+\.(?:cpp|cc|c|h|hpp|mm|m|cxx))\b'
)

# Strateji 3: Enum sabit isimleri
_ENUM_PREFIX_RE = re.compile(r'\b(k_[A-Z][A-Za-z0-9_]{3,})\b')

# Strateji 4: RTTI mangled symbol'ler
# macOS: __ZTI* (typeinfo), __ZTV* (vtable), __ZTS* (typeinfo name)
# Linux: _ZTI*, _ZTV*, _ZTS*
# macOS c++filt cift underscore (__Z) bekler, tek (_Z) demangle etmez!
_MANGLED_SYMBOL_RE = re.compile(r'\b(__?_Z[A-Za-z0-9_]{4,})\b')

# Ghidra otomatik isimleri (yeniden adlandirma gereken)
_GHIDRA_AUTO_FUNC_RE = re.compile(r'^FUN_[0-9a-fA-F]+$')

# C++ isim normalizasyon yardimcilari
_SNAKE_CASE_RE = re.compile(r'[a-z0-9]+(?:_[a-z0-9]+)+')
_CAMEL_BOUNDARY_RE = re.compile(r'([a-z])([A-Z])')


# ---------------------------------------------------------------------------
# Yardimci fonksiyonlar
# ---------------------------------------------------------------------------

def _hex_to_int(hex_str: str) -> int:
    """Hex string'i int'e cevir. '0x' prefix'i varsa da yoksa da calisir."""
    return int(hex_str, 16)


def _sanitize_identifier(name: str) -> str:
    """C/C++ identifier kurallarina uygun hale getir."""
    # Bosluk ve ozel karakterleri underscore'a cevir
    sanitized = re.sub(r'[^A-Za-z0-9_]', '_', name)
    # Ard arda underscore'lari birlesir
    sanitized = re.sub(r'_+', '_', sanitized)
    # Basta/sonda underscore temizle
    sanitized = sanitized.strip('_')
    # Basa sayi gelemez -- strip sonrasi kontrol (strip basta _ silmis olabilir)
    if sanitized and sanitized[0].isdigit():
        sanitized = '_' + sanitized
    return sanitized or 'unknown'


def _filename_to_classes(filename: str) -> list[str]:
    """Kaynak dosya adindan muhtemel class isimlerini cikar.

    Ornek:
        "BaseFileSystem.cpp" -> ["CBaseFileSystem", "BaseFileSystem"]
        "http_client.cpp"    -> ["CHttpClient", "HttpClient", "Chttp_client", "http_client"]
        "net.cpp"            -> ["CNet", "Net"]
    """
    stem = Path(filename).stem
    candidates = []

    # Olasi C-prefix
    if not stem.startswith('C'):
        candidates.append(f'C{stem}')
    candidates.append(stem)

    # snake_case ise CamelCase'e cevir
    if '_' in stem:
        camel = ''.join(w.capitalize() for w in stem.split('_'))
        if not camel.startswith('C'):
            candidates.append(f'C{camel}')
        candidates.append(camel)

    return candidates


def _extract_namespace_from_path(build_path: str) -> str | None:
    """Build path'ten namespace/modul ismi cikar.

    Ornek:
        "/opt/buildbot/.../src/filesystem/BaseFileSystem.cpp"
        -> "filesystem" (parent dir)

        "/opt/buildbot/.../src/common/net.cpp"
        -> "common"
    """
    parts = Path(build_path).parts
    # 'src' dizininden sonraki ilk component genellikle namespace/modul
    try:
        src_idx = list(parts).index('src')
        if src_idx + 1 < len(parts) - 1:  # src'den sonra en az 2 component var
            return parts[src_idx + 1]
    except ValueError:
        pass

    # src bulunamazsa parent dizini dene
    if len(parts) >= 2:
        return parts[-2]

    return None


def _demangle_symbol(mangled: str) -> str | None:
    """c++filt ile mangled C++ symbol'unu demangle et.

    Args:
        mangled: Mangled symbol (ornek: "_ZN10CHTTPClient4OpenEv")

    Returns:
        Demangled string veya None (basarisiz ise).
    """
    try:
        # v1.10.0 Fix Sprint HIGH-4: "--" separator ile argv injection onleme.
        # Mangled symbol "-" ile basliyorsa c++filt flag olarak yorumlayabilir.
        result = subprocess.run(
            ['c++filt', '--', mangled],
            capture_output=True, text=True, timeout=5,
        )
        demangled = result.stdout.strip()
        if demangled and demangled != mangled:
            return demangled
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        logger.debug("c++filt demangle basarisiz (mangled=%r): %s", mangled, e)
    return None


def _strip_templates(s: str) -> str:
    """Nested template parametrelerini kaldir.

    Ornek:
        "std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char>>"
        -> "std::__1::basic_string"

        "CHTTPClient<int>"
        -> "CHTTPClient"
    """
    result = []
    depth = 0
    for ch in s:
        if ch == '<':
            depth += 1
        elif ch == '>':
            depth = max(0, depth - 1)
        elif depth == 0:
            result.append(ch)
    return ''.join(result).strip()


def _parse_demangled_class_method(demangled: str) -> tuple[str | None, str | None]:
    """Demangled string'den class ve method isimlerini ayikla.

    Ornek:
        "CHTTPClient::Open()" -> ("CHTTPClient", "Open")
        "std::__1::basic_string<...>::size() const" -> ("basic_string", "size")
        "typeinfo for CBaseFileSystem" -> ("CBaseFileSystem", None)
        "vtable for CNetworkSystem" -> ("CNetworkSystem", None)
    """
    # typeinfo for X
    m = re.match(r'typeinfo (?:name )?for (.+)', demangled)
    if m:
        class_name = m.group(1).split('::')[-1].split('<')[0].strip()
        return (class_name, None)

    # vtable for X
    m = re.match(r'vtable for (.+)', demangled)
    if m:
        class_name = m.group(1).split('::')[-1].split('<')[0].strip()
        return (class_name, None)

    # Class::Method(...) [const/volatile/...]
    m = re.match(r'(.+)::([~\w]+)\s*\(', demangled)
    if m:
        # Namespace chain'den son class'i al
        ns_chain = m.group(1)
        method = m.group(2)
        # Nested template parametrelerini kaldir (recursive <...> removal)
        cleaned = _strip_templates(ns_chain)
        class_name = cleaned.split('::')[-1].strip()
        if class_name:
            return (class_name, method)

    return (None, None)


# ---------------------------------------------------------------------------
# Adres proximity eslestirme
# ---------------------------------------------------------------------------

class _AddressMapper:
    """String adresleri ile fonksiyon adres araliklarini eslestirir.

    Artik Ghidra string JSON'unda xref/function bilgisi mevcut olabilir
    (string_extractor.py xref fix'i). Ancak xref bilgisi olmayan
    eski JSON'lar icin adres yakinligi ile fallback eslestirme yapariz.

    NOT: String'ler genellikle .rodata/.cstring section'inda olur ve
    fonksiyon code section'indan farkli adreslerdedir. Bu nedenle
    adres proximity guvenilir degildir. Biz bunu sadece build path
    gruplamasi icin kullaniyoruz (ayni dosyadan gelen string'ler
    yakin adreslerde olur).
    """

    def __init__(self, functions: list[_FuncEntry]) -> None:
        # Adrese gore sirala -- binary search icin
        self._funcs = sorted(functions, key=lambda f: f.address)
        self._addrs = [f.address for f in self._funcs]

    def find_containing_function(self, addr: int) -> _FuncEntry | None:
        """Verilen adresin icinde oldugu fonksiyonu bul (adres range icinde)."""
        import bisect
        idx = bisect.bisect_right(self._addrs, addr) - 1
        if idx < 0:
            return None
        func = self._funcs[idx]
        if func.address <= addr < func.end_address:
            return func
        return None

    def find_nearest_function(self, addr: int, max_distance: int = 0x10000) -> _FuncEntry | None:
        """En yakin fonksiyonu bul (max_distance icinde)."""
        import bisect
        idx = bisect.bisect_right(self._addrs, addr)
        best: _FuncEntry | None = None
        best_dist = max_distance + 1

        # Solda ve sagda birer fonksiyona bak
        for i in (idx - 1, idx):
            if 0 <= i < len(self._funcs):
                dist = abs(addr - self._funcs[i].address)
                if dist < best_dist:
                    best_dist = dist
                    best = self._funcs[i]

        return best if best_dist <= max_distance else None

    def find_functions_in_range(
        self, start_addr: int, end_addr: int,
    ) -> list[_FuncEntry]:
        """Verilen adres araligindaki fonksiyonlari dondur."""
        import bisect
        lo = bisect.bisect_left(self._addrs, start_addr)
        hi = bisect.bisect_right(self._addrs, end_addr)
        return self._funcs[lo:hi]


# ---------------------------------------------------------------------------
# String gruplama -- ayni source file'dan gelen string'leri grupla
# ---------------------------------------------------------------------------

class _StringCluster:
    """Yakin adreslerdeki string'leri gruplar.

    Build path string'leri genellikle ayni dosyadan gelen diger
    string'lerle (assert, m_ degiskenleri, Class::Method) yakin
    adreslerde bulunur. Bu yakinligi kullanarak source file
    ile fonksiyon eslestirmesi yapariz.
    """

    def __init__(self, max_gap: int = 0x2000) -> None:
        self._max_gap = max_gap  # Gruplama icin max adres farki

    def cluster_around_paths(
        self,
        path_strings: list[_StringEntry],
        all_strings: list[_StringEntry],
    ) -> dict[str, list[_StringEntry]]:
        """Her build path string'inin etrafindaki string'leri grupla.

        Returns:
            {build_path_value: [yakin_stringler]}
        """
        if not path_strings:
            return {}

        # Tum string'leri adrese gore sirala
        sorted_all = sorted(all_strings, key=lambda s: s.address)
        all_addrs = [s.address for s in sorted_all]

        result: dict[str, list[_StringEntry]] = {}
        import bisect

        for ps in path_strings:
            # Build path adresi etrafindaki string'leri topla
            lo_addr = ps.address - self._max_gap
            hi_addr = ps.address + self._max_gap

            lo_idx = bisect.bisect_left(all_addrs, lo_addr)
            hi_idx = bisect.bisect_right(all_addrs, hi_addr)

            nearby = sorted_all[lo_idx:hi_idx]
            result[ps.value] = nearby

        return result


# ---------------------------------------------------------------------------
# Ana sinif
# ---------------------------------------------------------------------------

class BinaryNameExtractor:
    """Binary'deki debug bilgilerinden orijinal isimleri kurtarir.

    Ghidra'nin verdigi FUN_xxx isimlerini, binary icindeki string'lerden,
    build path'lerden, enum sabitlerinden ve RTTI'dan gelen bilgilerle
    gercek isimlerine donusturur.

    LLM kullanmaz -- tamamen pattern matching + heuristik.
    """

    def __init__(self, config: Config | None = None) -> None:
        self._config = config or Config()
        self._min_confidence = (
            self._config.binary_reconstruction.min_naming_confidence
        )

        # Cikarim sonuclari
        self._result: ExtractionResult | None = None
        self._naming_map: dict[str, str] = {}

        # Dahili state
        self._strings: list[_StringEntry] = []
        self._functions: list[_FuncEntry] = []
        self._call_graph: dict[str, _CallGraphNode] = {}  # addr_str -> node
        self._addr_mapper: _AddressMapper | None = None
        self._func_by_addr: dict[int, _FuncEntry] = {}
        self._func_by_name: dict[str, _FuncEntry] = {}
        self._string_to_funcs: dict[int, list[str]] = {}  # string_addr -> [func_names]
        self._func_string_refs: dict[str, list[dict]] = {}  # func_addr -> [{address, value}]

        # Kaynak kod eslestirme icin (GitHub repo clone'u)
        self._source_repo_path: Path | None = None
        self._source_declarations: dict[str, dict] | None = None  # type_name -> info

    # ----- Public API -----

    def extract(
        self,
        strings_json: Path,
        functions_json: Path,
        call_graph_json: Path,
        *,
        source_repo_path: Path | None = None,
    ) -> ExtractionResult:
        """Tum stratejileri calistir ve sonuclari birlestir.

        Args:
            strings_json: Ghidra string JSON dosyasi.
            functions_json: Ghidra functions JSON dosyasi.
            call_graph_json: Ghidra call graph JSON dosyasi.
            source_repo_path: Opsiyonel -- orijinal kaynak kod dizini.
                Eger verilirse Strateji 8 (source cross-match) calisir.

        Returns:
            ExtractionResult -- tum cikarim sonuclari.
        """
        self._source_repo_path = source_repo_path
        result = ExtractionResult(success=False)

        # Workspace root'u strings_json'dan cikar (static/ dizininin parent'i)
        self._workspace_root = strings_json.parent.parent if strings_json.exists() else None

        # 1. JSON'lari yukle
        try:
            self._load_strings(strings_json)
            self._load_functions(functions_json)
            self._load_call_graph(call_graph_json)
        except Exception as exc:
            result.errors.append(f"JSON yukleme hatasi: {exc}")
            logger.error("BinaryNameExtractor JSON yukleme hatasi: %s", exc)
            self._result = result
            return result

        # 1b. Xref dosyasini yukle (opsiyonel -- function_xrefs.strings_used verisi)
        # Bu veri, hangi fonksiyonun hangi string'leri referans ettigini icerir.
        # ghidra_strings.json'da xref yoksa (eski format), buradan alinir.
        # (__init__'te bos dict olarak annote edildi; re-entry'de sifirla.)
        self._func_string_refs = {}
        xrefs_json = strings_json.parent / "ghidra_xrefs.json"
        if xrefs_json.exists():
            try:
                self._load_function_xrefs(xrefs_json)
            except Exception as exc:
                logger.debug("ghidra_xrefs.json yukleme hatasi (opsiyonel): %s", exc)

        logger.info(
            "BinaryNameExtractor: %d string, %d fonksiyon, %d call-graph node, "
            "%d func-string-ref yuklendi",
            len(self._strings), len(self._functions), len(self._call_graph),
            len(self._func_string_refs),
        )

        # Adres mapper kur
        self._addr_mapper = _AddressMapper(self._functions)

        # 2. Strateji 1: Debug String Parse
        try:
            names_1 = self._strategy_debug_strings()
            result.names.extend(names_1)
            result.by_source['debug_string'] = len(names_1)
            logger.info("Strateji 1 (debug_string): %d isim", len(names_1))
        except Exception as exc:
            result.errors.append(f"Debug string parse hatasi: {exc}")
            logger.warning("Strateji 1 hatasi: %s", exc)

        # 3. Strateji 2: Build Path Mapper
        try:
            names_2 = self._strategy_build_paths()
            result.names.extend(names_2)
            result.by_source['build_path'] = len(names_2)
            logger.info("Strateji 2 (build_path): %d isim", len(names_2))
        except Exception as exc:
            result.errors.append(f"Build path mapper hatasi: {exc}")
            logger.warning("Strateji 2 hatasi: %s", exc)

        # 4. Strateji 3: Enum Handler Naming
        try:
            names_3 = self._strategy_enum_handlers()
            result.names.extend(names_3)
            result.by_source['enum_handler'] = len(names_3)
            logger.info("Strateji 3 (enum_handler): %d isim", len(names_3))
        except Exception as exc:
            result.errors.append(f"Enum handler naming hatasi: {exc}")
            logger.warning("Strateji 3 hatasi: %s", exc)

        # 5. Strateji 4: RTTI Demangle
        try:
            names_4 = self._strategy_rtti_demangle()
            result.names.extend(names_4)
            result.by_source['rtti'] = len(names_4)
            logger.info("Strateji 4 (rtti): %d isim", len(names_4))
        except Exception as exc:
            result.errors.append(f"RTTI demangle hatasi: {exc}")
            logger.warning("Strateji 4 hatasi: %s", exc)

        # 6. Strateji 5: String Intelligence (assert/error/protocol/telemetry)
        try:
            names_5 = self._strategy_string_intelligence()
            result.names.extend(names_5)
            result.by_source['string_intel'] = len(names_5)
            logger.info("Strateji 5 (string_intel): %d isim", len(names_5))
        except Exception as exc:
            result.errors.append(f"String intelligence hatasi: {exc}")
            logger.warning("Strateji 5 hatasi: %s", exc)

        # 7. Strateji 6: Swift Mangled Class Demangle (_TtC pattern)
        try:
            names_6 = self._strategy_swift_demangle()
            result.names.extend(names_6)
            # Exact demangle ve variant'lari ayri say
            n_exact = sum(1 for n in names_6 if n.source == "swift_demangle")
            n_variant = sum(1 for n in names_6 if n.source == "swift_demangle_variant")
            result.by_source['swift_demangle'] = n_exact
            result.by_source['swift_demangle_variant'] = n_variant
            logger.info(
                "Strateji 6 (swift_demangle): %d exact + %d variant isim",
                n_exact, n_variant,
            )
        except Exception as exc:
            result.errors.append(f"Swift demangle hatasi: {exc}")
            logger.warning("Strateji 6 hatasi: %s", exc)

        # 8. Strateji 7: VTable Chain Extraction
        try:
            names_7 = self._strategy_vtable_chain()
            result.names.extend(names_7)
            result.by_source['vtable_chain'] = len(names_7)
            logger.info("Strateji 7 (vtable_chain): %d isim", len(names_7))
        except Exception as exc:
            result.errors.append(f"VTable chain hatasi: {exc}")
            logger.warning("Strateji 7 hatasi: %s", exc)

        # 9. Strateji 8: Swift Source Cross-Match (GitHub kaynak kodu)
        if self._source_repo_path and self._source_repo_path.exists():
            try:
                names_8 = self._strategy_source_cross_match()
                result.names.extend(names_8)
                result.by_source['source_cross_match'] = len(names_8)
                logger.info("Strateji 8 (source_cross_match): %d isim", len(names_8))
            except Exception as exc:
                result.errors.append(f"Source cross-match hatasi: {exc}")
                logger.warning("Strateji 8 hatasi: %s", exc)

        # 10. Sonuclari birlestir -- confidence'a gore en iyisini sec
        self._merge_results(result)

        result.total_extracted = len(self._naming_map)
        result.success = True

        logger.info(
            "BinaryNameExtractor: toplam %d isim kurtarildi "
            "(debug=%d, path=%d, enum=%d, rtti=%d, string_intel=%d, swift=%d, "
            "swift_var=%d, vtable=%d, source_xmatch=%d)",
            result.total_extracted,
            result.by_source.get('debug_string', 0),
            result.by_source.get('build_path', 0),
            result.by_source.get('enum_handler', 0),
            result.by_source.get('rtti', 0),
            result.by_source.get('string_intel', 0),
            result.by_source.get('swift_demangle', 0),
            result.by_source.get('swift_demangle_variant', 0),
            result.by_source.get('vtable_chain', 0),
            result.by_source.get('source_cross_match', 0),
        )

        self._result = result
        return result

    def as_naming_map(self) -> dict[str, str]:
        """c_namer uyumlu {old_name: new_name} dict dondur.

        extract() cagrilmadan cagrilirsa bos dict doner.
        """
        return dict(self._naming_map)

    def get_class_methods(self) -> dict[str, list[str]]:
        """Tespit edilen class -> method listesi."""
        if self._result is None:
            return {}
        return dict(self._result.class_methods)

    def get_member_vars(self) -> dict[str, list[str]]:
        """Tespit edilen class -> member variable listesi."""
        if self._result is None:
            return {}
        return dict(self._result.member_vars)

    def get_source_files(self) -> dict[str, list[str]]:
        """Tespit edilen source_file -> fonksiyon listesi."""
        if self._result is None:
            return {}
        return dict(self._result.source_files)

    # ----- JSON yukleme -----

    def _load_strings(self, path: Path) -> None:
        """ghidra_strings.json'u yukle ve parse et.

        String JSON'daki xref bilgisini de parse eder:
        - xrefs: [{from_address, from_function, from_func_addr}, ...]
        - function: Ilk xref'teki fonksiyon ismi
        - function_addr: Ilk xref'teki fonksiyon entry point adresi

        Bu sayede string->fonksiyon eslestirmesi adres proximity yerine
        gercek xref verisiyle yapilabilir.
        """
        with open(path, encoding='utf-8') as f:
            data = json.load(f)

        raw_strings = data.get('strings', [])
        self._strings = []
        # (__init__'te annote edildi; re-load'da sifirla.)
        self._string_to_funcs = {}

        for s in raw_strings:
            try:
                addr = _hex_to_int(s['address'])

                # Xref bilgisini parse et (Ghidra string_extractor.py ciktisi)
                xrefs: list[_XrefEntry] = []
                raw_xrefs = s.get('xrefs', [])
                for xr in raw_xrefs:
                    try:
                        from_addr_str = xr.get('from_address', '')
                        from_addr = _hex_to_int(from_addr_str) if from_addr_str else 0
                        func_addr_str = xr.get('from_func_addr', '')
                        func_addr = _hex_to_int(func_addr_str) if func_addr_str else None
                        xrefs.append(_XrefEntry(
                            from_address=from_addr,
                            from_function=xr.get('from_function'),
                            from_func_addr=func_addr,
                        ))
                    except (ValueError, TypeError):
                        continue

                # String->function eslesmesi: xref veya fallback olarak 'function' alani
                func_name = s.get('function')
                func_addr_str = s.get('function_addr')
                func_addr = _hex_to_int(func_addr_str) if func_addr_str else None

                entry = _StringEntry(
                    address=addr,
                    value=s.get('value', ''),
                    length=s.get('length', 0),
                    stype=s.get('type', 'string'),
                    xrefs=xrefs,
                    function=func_name,
                    function_addr=func_addr,
                )
                if entry.value:  # Bos string'leri atla
                    self._strings.append(entry)

                    # String->fonksiyon mapping olustur (xref-based)
                    referring_funcs = set()
                    for xr in xrefs:
                        if xr.from_function:
                            referring_funcs.add(xr.from_function)
                    if referring_funcs:
                        self._string_to_funcs[addr] = list(referring_funcs)

            except (ValueError, KeyError):
                continue

        xref_count = sum(1 for s in self._strings if s.xrefs)
        func_mapped = sum(1 for s in self._strings if s.function)
        logger.debug(
            "Yuklenen string sayisi: %d (xref'li: %d, fonksiyon esli: %d)",
            len(self._strings), xref_count, func_mapped,
        )

    def _load_functions(self, path: Path) -> None:
        """ghidra_functions.json'u yukle ve parse et."""
        with open(path, encoding='utf-8') as f:
            data = json.load(f)

        raw_funcs = data.get('functions', [])
        self._functions = []
        self._func_by_addr = {}
        self._func_by_name = {}

        for f_data in raw_funcs:
            try:
                addr = _hex_to_int(f_data['address'])
                size = f_data.get('size', 0)
                entry = _FuncEntry(
                    name=f_data.get('name', ''),
                    address=addr,
                    size=size,
                    end_address=addr + max(size, 1),
                    param_count=f_data.get('param_count', 0),
                    return_type=f_data.get('return_type', ''),
                    is_thunk=f_data.get('is_thunk', False),
                    is_external=f_data.get('is_external', False),
                    source=f_data.get('source', 'DEFAULT'),
                    parameters=f_data.get('parameters', []),
                )
                self._functions.append(entry)
                self._func_by_addr[addr] = entry
                if entry.name:
                    self._func_by_name[entry.name] = entry
            except (ValueError, KeyError):
                continue

        logger.debug("Yuklenen fonksiyon sayisi: %d", len(self._functions))

    def _load_call_graph(self, path: Path) -> None:
        """ghidra_call_graph.json'u yukle ve parse et."""
        with open(path, encoding='utf-8') as f:
            data = json.load(f)

        nodes = data.get('nodes', {})
        self._call_graph = {}

        for addr_str, node_data in nodes.items():
            try:
                callers = [
                    c.get('address', '')
                    for c in node_data.get('callers', [])
                ]
                callees = [
                    c.get('address', '')
                    for c in node_data.get('callees', [])
                ]
                self._call_graph[addr_str] = _CallGraphNode(
                    name=node_data.get('name', ''),
                    address=_hex_to_int(addr_str),
                    callers=callers,
                    callees=callees,
                )
            except (ValueError, KeyError):
                continue

        logger.debug("Yuklenen call graph node sayisi: %d", len(self._call_graph))

    def _load_function_xrefs(self, path: Path) -> None:
        """ghidra_xrefs.json'dan function_xrefs.strings_used verisini yukle.

        Bu dosya, her fonksiyonun referans ettigi string'leri icerir:
        {
          "function_xrefs": {
            "100000858": {
              "name": "FUN_100000858",
              "strings_used": [{"address": "...", "value": "..."}],
              ...
            }
          }
        }

        Sonuc: self._func_string_refs[func_addr_str] = [{"address": addr, "value": val}]
        """
        with open(path, encoding='utf-8') as f:
            data = json.load(f)

        func_xrefs = data.get('function_xrefs', {})
        self._func_string_refs = {}

        for addr_str, fdata in func_xrefs.items():
            strings_used = fdata.get('strings_used', [])
            if strings_used:
                self._func_string_refs[addr_str] = strings_used

        logger.debug(
            "ghidra_xrefs.json: %d fonksiyon string referansi yuklendi",
            len(self._func_string_refs),
        )

    # ===================================================================
    # Strateji 1: Debug String Parse
    # ===================================================================

    def _strategy_debug_strings(self) -> list[ExtractedName]:
        """Binary string'lerden Class::Method, m_ degiskenleri ve assert
        ifadelerini parse et.

        Xref bilgisi mevcutsa (Ghidra string_extractor.py ciktisinda xrefs
        alani varsa), string'in hangi fonksiyonda kullanildigini bilerek
        dogrudan FUN_xxx -> Class_Method eslestirmesi yapar.

        Xref bilgisi yoksa: call graph'ta isimli fonksiyonlarin
        caller/callee'lerini kullanarak dolayimli eslestirme yapar.
        """
        names: list[ExtractedName] = []
        seen_class_methods: set[str] = set()
        seen_members: set[str] = set()
        seen_renamed_funcs: set[str] = set()  # Ayni fonksiyonu birden fazla kez rename etme

        for s in self._strings:
            val = s.value

            # --- Class::Method pattern'leri ---
            for m in _CLASS_METHOD_RE.finditer(val):
                full_name = m.group(1)
                if full_name in seen_class_methods:
                    continue
                seen_class_methods.add(full_name)

                parts = full_name.split('::')
                class_name = parts[0]
                method_name = parts[1] if len(parts) > 1 else None

                # Confidence: tam Class::Method string'i cok guvenilir
                confidence = 0.90

                # --- Xref-based eslestirme (yuksek guven) ---
                # String'in xref'lerinden FUN_xxx fonksiyonlarini bul
                xref_matched = False
                if s.xrefs:
                    for xr in s.xrefs:
                        if not xr.from_function:
                            continue
                        if not _GHIDRA_AUTO_FUNC_RE.match(xr.from_function):
                            continue
                        if xr.from_function in seen_renamed_funcs:
                            continue

                        # Xref'teki FUN_xxx fonksiyonunu Class_Method olarak adlandir
                        recovered = f"{class_name}_{method_name}" if method_name else class_name
                        names.append(ExtractedName(
                            original_name=xr.from_function,
                            recovered_name=recovered,
                            source='debug_string',
                            confidence=0.92,  # Xref-based -> daha yuksek guven
                            evidence=f'String xref: "{val}" -> {xr.from_function}',
                            class_name=class_name,
                            source_file=None,
                        ))
                        seen_renamed_funcs.add(xr.from_function)
                        xref_matched = True
                        break  # Ilk FUN_xxx eslesmesi yeterli

                # --- Xref yoksa: eski yontem (call graph eslestirmesi) ---
                if not xref_matched:
                    matched_func = self._find_function_by_class_method(
                        class_name, method_name,
                    )

                    if matched_func and _GHIDRA_AUTO_FUNC_RE.match(matched_func.name):
                        if matched_func.name not in seen_renamed_funcs:
                            recovered = f"{class_name}_{method_name}" if method_name else class_name
                            names.append(ExtractedName(
                                original_name=matched_func.name,
                                recovered_name=recovered,
                                source='debug_string',
                                confidence=confidence,
                                evidence=f'String: "{val}"',
                                class_name=class_name,
                                source_file=None,
                            ))
                            seen_renamed_funcs.add(matched_func.name)

                # Class-method iliskisini her durumda kaydet
                if method_name and self._result is not None:
                    pass  # _merge_results'ta yapilacak
                # Simdilik result yoksa gecikmeli kaydet -- extract() icinde merge eder

            # --- m_ member variable pattern'leri ---
            for m in _MEMBER_VAR_RE.finditer(val):
                member_name = m.group(1)
                if member_name in seen_members:
                    continue
                seen_members.add(member_name)

                # Member degiskenin ait oldugu class'i bulmaya calis
                # Ayni string icinde Class:: referansi var mi?
                class_match = _CLASS_METHOD_RE.search(val)
                owner_class = class_match.group(1).split('::')[0] if class_match else None

            # --- Assert/CHECK ifadelerinden degisken isimleri ---
            for m in _ASSERT_EXPR_RE.finditer(val):
                expr = m.group(1).strip()
                # Assert icindeki member degiskenleri de cikar
                for vm in _MEMBER_VAR_RE.finditer(expr):
                    member_name = vm.group(1)
                    if member_name not in seen_members:
                        seen_members.add(member_name)

        # Fonksiyon listesindeki export/named fonksiyonlari da cikar
        export_names = self._extract_export_symbols()
        names.extend(export_names)

        # Class-method ve member var bilgilerini topla (merge icin)
        self._collected_class_methods: dict[str, set[str]] = defaultdict(set)
        self._collected_member_vars: dict[str, set[str]] = defaultdict(set)

        for cm in seen_class_methods:
            parts = cm.split('::')
            if len(parts) == 2:
                self._collected_class_methods[parts[0]].add(parts[1])

        for s in self._strings:
            val = s.value
            class_match = _CLASS_METHOD_RE.search(val)
            if class_match:
                class_name = class_match.group(1).split('::')[0]
                for vm in _MEMBER_VAR_RE.finditer(val):
                    self._collected_member_vars[class_name].add(vm.group(1))

        # Class'i belirlenemeyen member'lar icin genel "unknown" bucket
        for member in seen_members:
            found_in_class = False
            for cls_members in self._collected_member_vars.values():
                if member in cls_members:
                    found_in_class = True
                    break
            if not found_in_class:
                self._collected_member_vars['_unknown_'].add(member)

        return names

    def _find_function_by_class_method(
        self, class_name: str, method_name: str | None,
    ) -> _FuncEntry | None:
        """Class::Method string'ine karsilik gelen fonksiyonu bul.

        Fonksiyon listesinde isimli fonksiyonlarin caller/callee'lerine
        bakarak eslestirme yapar.

        Ornek: Eger "CBaseFileSystem::Open" string'i varsa ve call graph'ta
        isimli bir fonksiyon bu string'in yakinindan cagriliyorsa, o fonksiyon
        CBaseFileSystem::Open olabilir.
        """
        if not method_name:
            return None

        # 1. Dogrudan isim eslesmesi (az rastlanir ama en guvenilir)
        search_names = [
            f"{class_name}::{method_name}",
            f"_{class_name}_{method_name}",
            f"{class_name}_{method_name}",
            method_name,
        ]
        for search_name in search_names:
            if search_name in self._func_by_name:
                func = self._func_by_name[search_name]
                if _GHIDRA_AUTO_FUNC_RE.match(func.name):
                    return func
                # Zaten isimli -- yeniden adlandirmaya gerek yok
                return None

        # 2. Call graph'ta yakin fonksiyonu ara
        # Eger bu Class'in baska method'lari isimli ise, onlarin
        # caller/callee'lerinde FUN_xxx olanlar bu class'a ait olabilir
        # (Cok dusuk guven -- burada None dondurelim, strateji 2 ile birlestiririz)
        return None

    def _extract_export_symbols(self) -> list[ExtractedName]:
        """Fonksiyon listesindeki export/named (FUN_xxx olmayan) fonksiyonlardan
        isim bilgisi cikar.

        Ornek: "_SteamBootstrapper_GetEUniverse" -> gercek export ismi.
        Bunlar zaten isimli oldugundan yeniden adlandirmaya gerekmez,
        ama class-method iliskisi icin kullanilir.
        """
        names: list[ExtractedName] = []

        for func in self._functions:
            if _GHIDRA_AUTO_FUNC_RE.match(func.name):
                continue  # Otomatik isim, atla
            if func.is_thunk or func.is_external:
                continue  # Thunk/external, atla
            if not func.name or len(func.name) < 3:
                continue

            name = func.name

            # Leading underscore kaldir (macOS convention)
            clean_name = name.lstrip('_')
            if not clean_name:
                continue

            # Class::Method formunda mi?
            if '::' in clean_name:
                parts = clean_name.split('::')
                class_name = parts[0]
                method_name = parts[1] if len(parts) > 1 else None
                names.append(ExtractedName(
                    original_name=name,
                    recovered_name=clean_name,
                    source='debug_string',
                    confidence=0.95,
                    evidence=f'Export symbol: {name}',
                    class_name=class_name,
                    source_file=None,
                ))
                continue

            # C-style export (ornek: SteamBootstrapper_GetEUniverse)
            # Bunlari yeniden adlandirmayacagiz ama bilgi olarak kaydedelim
            # Eger underscore ile ayrilmis prefix varsa, class ismi olabilir
            underscore_parts = clean_name.split('_', 1)
            if len(underscore_parts) == 2 and len(underscore_parts[0]) > 2:
                possible_class = underscore_parts[0]
                possible_method = underscore_parts[1]
                # "Get", "Set", "Is", "Has" gibi method prefix'leri varsa
                if re.match(r'^(Get|Set|Is|Has|Can|Enable|Disable|Init|Create|Destroy)', possible_method):
                    names.append(ExtractedName(
                        original_name=name,
                        recovered_name=clean_name,
                        source='debug_string',
                        confidence=0.85,
                        evidence=f'Export symbol: {name}',
                        class_name=possible_class,
                        source_file=None,
                    ))

        return names

    # ===================================================================
    # Strateji 2: Build Path Mapper
    # ===================================================================

    def _strategy_build_paths(self) -> list[ExtractedName]:
        """Build path string'lerinden source file -> class/namespace eslestirmesi.

        __FILE__ macro'sundan kalan path string'leri kullanir.
        Ornek:
            "/opt/buildbot/.../src/filesystem/BaseFileSystem.cpp"
            -> Source file: BaseFileSystem.cpp
            -> Namespace: filesystem
            -> Muhtemel class: CBaseFileSystem

        ONEMLI: String adresleri ile fonksiyon adresleri farkli section'lardadir
        (strings .cstring/.rodata, code .text). Bu nedenle dogrudan adres
        proximity ile eslestirme YAPILMAZ.

        Bunun yerine:
        1. Build path'in yakinindaki Class::Method string'lerini bul
        2. Call graph'ta bilinen class method'larindan FUN_xxx callee'lerine propag et
        3. Dosya adi -> class tahmini ile fonksiyon gruptla
        """
        names: list[ExtractedName] = []

        # Build path string'lerini bul
        path_strings: list[_StringEntry] = []
        for s in self._strings:
            if _BUILD_PATH_RE.search(s.value):
                if self._is_user_source_path(s.value):
                    path_strings.append(s)

        if not path_strings:
            logger.debug("Build path string'i bulunamadi")
            return names

        logger.debug("%d build path string'i bulundu", len(path_strings))

        # Her path etrafindaki STRING'leri grupla (fonksiyon degil!)
        # String'ler .cstring section'inda ayni dosyadan gelenler yakin adreslerdedir
        clusterer = _StringCluster(max_gap=0x4000)
        clusters = clusterer.cluster_around_paths(path_strings, self._strings)

        # Gorulmus path -> class eslesmelerini takip et
        seen_file_classes: dict[str, set[str]] = defaultdict(set)

        for build_path, nearby_strings in clusters.items():
            path_match = _BUILD_PATH_RE.search(build_path)
            if not path_match:
                continue

            source_path = path_match.group(1)
            filename = Path(source_path).name
            namespace = _extract_namespace_from_path(source_path)
            possible_classes = _filename_to_classes(filename)

            # Yakin string'lerdeki Class::Method bilgisini topla
            confirmed_classes: set[str] = set()
            nearby_methods: dict[str, list[str]] = defaultdict(list)

            for ns in nearby_strings:
                for cm_match in _CLASS_METHOD_RE.finditer(ns.value):
                    cm_full = cm_match.group(1)
                    parts = cm_full.split('::')
                    cls = parts[0]
                    method = parts[1] if len(parts) > 1 else None
                    confirmed_classes.add(cls)
                    if method:
                        nearby_methods[cls].append(method)

            # Source file -> confirmed class eslesmesini kaydet
            for cls in confirmed_classes:
                seen_file_classes[filename].add(cls)
                for method in nearby_methods.get(cls, []):
                    if not hasattr(self, '_collected_class_methods'):
                        self._collected_class_methods = defaultdict(set)
                    self._collected_class_methods[cls].add(method)

            # possible_classes ile confirmed_classes'i dogrula
            if not confirmed_classes and possible_classes:
                # Dosya adindan tahmin edilen class -- sadece bilgi olarak kaydet
                for pc in possible_classes:
                    seen_file_classes[filename].add(pc)

        # Call graph propagation: Bilinen isimli fonksiyonlarin
        # caller/callee'lerindeki FUN_xxx'leri class'a ata
        names.extend(self._propagate_class_via_call_graph(seen_file_classes))

        # Source file bilgilerini topla
        if not hasattr(self, '_collected_source_files'):
            self._collected_source_files: dict[str, set[str]] = defaultdict(set)
        for filename, classes in seen_file_classes.items():
            for cls in classes:
                self._collected_source_files[filename].add(cls)

        return names

    def _propagate_class_via_call_graph(
        self,
        file_classes: dict[str, set[str]],
    ) -> list[ExtractedName]:
        """Call graph'ta bilinen class method'larindan FUN_xxx callee'lerine class ata.

        Mantik: Eger bir isimli fonksiyon (ornek: handleGetURLEvent) cagirdigi
        FUN_xxx'ler varsa ve bu fonksiyon belirli bir class'a aitse,
        callee'ler de muhtemelen ayni class'a aittir.

        Ek olarak: Eger call graph'ta birden fazla ayni class method'unun
        cagirdigi ortak FUN_xxx varsa, o FUN_xxx o class'in utility fonksiyonu.
        """
        names: list[ExtractedName] = []

        # Tum bilinen class'larin method isimlerini topla
        all_class_methods: dict[str, set[str]] = defaultdict(set)
        if hasattr(self, '_collected_class_methods'):
            for cls, methods in self._collected_class_methods.items():
                all_class_methods[cls].update(methods)

        # Fonksiyon listesindeki isimli fonksiyonlarin class'ini belirle
        func_to_class: dict[str, str] = {}  # func_name -> class_name

        for func_name, func_entry in self._func_by_name.items():
            if _GHIDRA_AUTO_FUNC_RE.match(func_name):
                continue

            # Fonksiyon ismi bir class'in method'u mu?
            clean = func_name.lstrip('_')
            for cls, methods in all_class_methods.items():
                for method in methods:
                    if clean == f"{cls}_{method}" or clean == f"{cls}::{method}":
                        func_to_class[func_name] = cls
                        break

        # Call graph'ta class'i bilinen fonksiyonlarin callee'lerini propag et
        seen_funcs: set[str] = set()

        for func_name, cls in func_to_class.items():
            # Bu fonksiyonun call graph node'unu bul
            node = None
            for addr_str, cg_node in self._call_graph.items():
                if cg_node.name == func_name:
                    node = cg_node
                    break

            if not node:
                continue

            # Callee'lerdeki FUN_xxx'leri class'a ata
            for callee_addr in node.callees:
                callee_node = self._call_graph.get(callee_addr)
                if not callee_node:
                    continue
                if not _GHIDRA_AUTO_FUNC_RE.match(callee_node.name):
                    continue
                if callee_node.name in seen_funcs:
                    continue

                # Bu FUN_xxx'i class'a ata (dusuk confidence -- sadece call chain)
                names.append(ExtractedName(
                    original_name=callee_node.name,
                    recovered_name=f"{cls}_internal_{callee_node.address:x}",
                    source='build_path',
                    confidence=0.40,
                    evidence=f'Called by {func_name} (class: {cls})',
                    class_name=cls,
                    source_file=None,
                ))
                seen_funcs.add(callee_node.name)

        return names

    def _is_user_source_path(self, path: str) -> bool:
        """Path'in kullanici kaynak kodu mu yoksa system/framework mi oldugunu belirle."""
        lower = path.lower()

        # System/framework path'leri (filtrele)
        skip_prefixes = (
            '/system/', '/usr/lib/', '/usr/include/',
            '/applications/', '/library/frameworks/',
            'c:\\windows\\', 'c:\\program files',
        )
        for prefix in skip_prefixes:
            if lower.startswith(prefix):
                return False

        # Bilinen kaynak uzantilari
        source_exts = {'.cpp', '.cc', '.c', '.h', '.hpp', '.mm', '.m', '.cxx'}
        ext = Path(path).suffix.lower()
        if ext not in source_exts:
            return False

        # Buildbot/build path'leri genellikle kullanici kodu
        if 'buildbot' in lower or 'build/src' in lower:
            return True

        # Genel: src/ iceren path'ler
        if '/src/' in path or '\\src\\' in path:
            return True

        return True  # Varsayilan: kaynak kod

    # ===================================================================
    # Strateji 3: Enum Handler Naming (k_EMsg dispatch)
    # ===================================================================

    def _strategy_enum_handlers(self) -> list[ExtractedName]:
        """Valve/Steam enum sabitlerinden handler fonksiyon isimlerini cikar.

        ONEMLI: String adresleri code section'da degil, bu yuzden adres
        proximity ile fonksiyon eslestirmesi YAPILMAZ.

        Bunun yerine call graph analizi yapariz:
        1. Cok callee'li fonksiyonlar (20+) -> muhtemel dispatcher/switch-case
        2. Enum string'lerinden kurtarilan isimleri bu dispatcher'larin
           callee'lerine handler ismi olarak ata
        3. k_EMsg enum isimleri dogrudan bilgi olarak kaydedilir
        """
        names: list[ExtractedName] = []

        # Enum string'lerini topla
        enum_names_found: set[str] = set()
        for s in self._strings:
            for m in _ENUM_PREFIX_RE.finditer(s.value):
                enum_names_found.add(m.group(1))

        if not enum_names_found:
            logger.debug("Enum string bulunamadi")
            return names

        logger.debug("%d benzersiz enum string bulundu", len(enum_names_found))

        # k_EMsg enum'larini grupla -- dispatcher pattern tespiti icin
        emsg_enums = sorted([e for e in enum_names_found if 'EMsg' in e or 'EHTTPClient' in e])

        # Call graph'ta cok callee'li fonksiyonlari bul -> dispatcher adayi
        dispatcher_threshold = 15  # 15+ callee -> muhtemel switch-case dispatcher
        seen_funcs: set[str] = set()

        for addr_str, node in self._call_graph.items():
            if not _GHIDRA_AUTO_FUNC_RE.match(node.name):
                continue
            if node.name in seen_funcs:
                continue

            callee_count = len(node.callees)
            caller_count = len(node.callers)

            if callee_count >= dispatcher_threshold:
                # Bu fonksiyon muhtemel bir dispatcher
                # Callee sayisina gore confidence ayarla
                if callee_count >= 50:
                    confidence = 0.70
                elif callee_count >= 30:
                    confidence = 0.60
                else:
                    confidence = 0.50

                # Dispatcher ismi: callee sayisini ve caller bilgisini kullan
                # Caller'dan scope tahmini yap
                caller_hint = self._get_caller_class_hint(node)
                if caller_hint:
                    dispatcher_name = f"{caller_hint}_Dispatch_{callee_count}way"
                else:
                    dispatcher_name = f"Dispatch_{callee_count}way"

                names.append(ExtractedName(
                    original_name=node.name,
                    recovered_name=_sanitize_identifier(dispatcher_name),
                    source='enum_handler',
                    confidence=confidence,
                    evidence=f'High fan-out: {callee_count} callees, {caller_count} callers',
                    class_name=caller_hint,
                    source_file=None,
                ))
                seen_funcs.add(node.name)

                # Callee'lere handler ismi ata
                # Dispatcher'in class scope'u varsa onu kullan
                for i, callee_addr in enumerate(node.callees[:100]):
                    callee_node = self._call_graph.get(callee_addr)
                    if not callee_node:
                        continue
                    if not _GHIDRA_AUTO_FUNC_RE.match(callee_node.name):
                        continue
                    if callee_node.name in seen_funcs:
                        continue

                    # Callee'nin kendi callee sayisina bak -- karmasik handler mi?
                    callee_complexity = len(callee_node.callees)
                    if callee_complexity > 5:
                        handler_prefix = "Handler"
                    else:
                        handler_prefix = "Stub"

                    if caller_hint:
                        handler_name = f"{caller_hint}_{handler_prefix}_{i:03d}"
                    else:
                        handler_name = f"{handler_prefix}_case_{i:03d}"

                    names.append(ExtractedName(
                        original_name=callee_node.name,
                        recovered_name=handler_name,
                        source='enum_handler',
                        confidence=0.35,
                        evidence=f'Callee #{i} of {node.name} ({callee_count} cases, {callee_complexity} sub-calls)',
                        class_name=caller_hint,
                        source_file=None,
                    ))
                    seen_funcs.add(callee_node.name)

        # Enum isimlerinden bilgi kaydet (fonksiyon eslestirmesi yapmadan)
        # Bu bilgiyi comment_generator ve diger moduller kullanabilir
        if not hasattr(self, '_collected_enum_names'):
            self._collected_enum_names: set[str] = set()
        self._collected_enum_names.update(enum_names_found)

        return names

    def _get_caller_class_hint(self, node: _CallGraphNode) -> str | None:
        """Bir fonksiyonun caller'larindan class ismi tahmini yap.

        Eger caller'lardan biri isimli ise ve bir class'a aitse,
        bu fonksiyon da muhtemelen ayni class'a ait.
        """
        for caller_addr in node.callers[:10]:
            caller_node = self._call_graph.get(caller_addr)
            if not caller_node:
                continue
            if _GHIDRA_AUTO_FUNC_RE.match(caller_node.name):
                continue
            # Isimli caller -- class ismi cikar
            clean = caller_node.name.lstrip('_')
            # Class::Method formati
            if '::' in clean:
                return clean.split('::')[0]
            # C-prefix + underscore formati (SteamBootstrapper_GetXxx)
            parts = clean.split('_', 1)
            if len(parts) == 2 and len(parts[0]) > 2:
                return parts[0]
        return None

    def _find_common_enum_prefix(self, enum_names: list[str]) -> str | None:
        """Enum isimlerinin ortak prefix'ini bul.

        Ornek:
            ["k_EMsgClientLogon", "k_EMsgClientHello", "k_EMsgClientHeartBeat"]
            -> "ClientMsg"

            ["k_EHTTPClientConnectionState_CONNECTING", "k_EHTTPClientConnectionState_KEEPALIVE"]
            -> "HTTPClientConnectionState"
        """
        if not enum_names:
            return None

        # k_ prefix'ini kaldir
        stripped = [name[2:] if name.startswith('k_') else name for name in enum_names]

        # E prefix'ini de kaldir (k_EMsg -> Msg)
        stripped = [
            name[1:] if name.startswith('E') and len(name) > 1 and name[1].isupper()
            else name
            for name in stripped
        ]

        if not stripped:
            return None

        # Ortak prefix bul
        prefix = stripped[0]
        for s in stripped[1:]:
            while not s.startswith(prefix) and prefix:
                prefix = prefix[:-1]
            if not prefix:
                break

        # Prefix cok kisa ise veya tek kelime degilse
        if len(prefix) < 3:
            return None

        # Son harf kucuk/underscore ise temizle (partial word)
        while prefix and (prefix[-1] == '_' or prefix[-1].islower()):
            prefix = prefix[:-1]

        return prefix if len(prefix) >= 3 else None

    def _enum_to_handler_name(self, enum_name: str) -> str | None:
        """Enum sabit isminden handler fonksiyon ismi olustur.

        Ornek:
            "k_EMsgClientLogon" -> "Handle_ClientLogon"
            "k_EHTTPClientConnectionState_CONNECTING" -> "Handle_HTTPClientConnectionState_CONNECTING"
        """
        # k_ prefix'ini kaldir
        name = enum_name
        if name.startswith('k_'):
            name = name[2:]

        # E prefix'ini kaldir
        if name.startswith('E') and len(name) > 1 and name[1].isupper():
            name = name[1:]

        if len(name) < 3:
            return None

        return f"Handle_{_sanitize_identifier(name)}"

    # ===================================================================
    # Strateji 4: RTTI Demangle
    # ===================================================================

    def _strategy_rtti_demangle(self) -> list[ExtractedName]:
        """RTTI ve mangled symbol'lerden class isimleri kurtarir.

        Binary string'lerindeki _ZTI* (typeinfo), _ZTV* (vtable),
        _ZTS* (typeinfo name), _ZN* (mangled function) pattern'lerini
        bulup c++filt ile demangle eder.
        """
        names: list[ExtractedName] = []

        # c++filt mevcut mu kontrol et
        if not self._check_cppfilt():
            logger.debug("c++filt bulunamadi, RTTI strateji atlanacak")
            return names

        # Mangled symbol'leri topla
        mangled_symbols: list[tuple[_StringEntry, str]] = []  # (entry, mangled)
        for s in self._strings:
            for m in _MANGLED_SYMBOL_RE.finditer(s.value):
                mangled = m.group(1)
                # macOS c++filt cift underscore bekler (__Z), tek (_Z) demangle etmez
                # Regex hem __Z hem _Z yakaliyor -- ikisini de dene
                mangled_symbols.append((s, mangled))

        if not mangled_symbols:
            logger.debug("Mangled symbol bulunamadi")
            return names

        logger.debug("%d mangled symbol bulundu", len(mangled_symbols))

        # Batch demangle (performans icin)
        demangled_map = self._batch_demangle([sym for _, sym in mangled_symbols])

        # Gorulmus class'lari takip et
        seen_classes: set[str] = set()
        rtti_classes: dict[str, float] = {}  # class_name -> best_confidence

        for entry, mangled in mangled_symbols:
            demangled = demangled_map.get(mangled)
            if not demangled:
                continue

            class_name, method_name = _parse_demangled_class_method(demangled)
            if not class_name:
                continue

            # Standart library class'larini atla
            if self._is_std_class(class_name):
                continue

            # RTTI typeinfo/vtable -> cok guvenilir class ismi
            # macOS: __ZTI, Linux: _ZTI
            stripped = mangled.lstrip('_')  # ZTI..., ZTV..., ZN...
            is_typeinfo = stripped.startswith('ZTI') or stripped.startswith('ZTS')
            is_vtable = stripped.startswith('ZTV')
            is_func = stripped.startswith('ZN')

            if is_typeinfo or is_vtable:
                confidence = 0.95
            elif is_func:
                confidence = 0.85
            else:
                confidence = 0.75

            if class_name not in seen_classes:
                seen_classes.add(class_name)
                rtti_classes[class_name] = confidence

            # Method bilgisi varsa kaydet
            if method_name:
                if not hasattr(self, '_collected_class_methods'):
                    self._collected_class_methods = defaultdict(set)
                self._collected_class_methods[class_name].add(method_name)

            # Fonksiyon eslestirmesi: mangled function symbol'ler
            if is_func and method_name:
                # Bu mangled isim bir fonksiyona karsilik geliyor olabilir
                # Fonksiyon listesinde bu adreste FUN_xxx var mi?
                if self._addr_mapper:
                    containing = self._addr_mapper.find_nearest_function(
                        entry.address, max_distance=0x1000,
                    )
                    if containing and _GHIDRA_AUTO_FUNC_RE.match(containing.name):
                        recovered = f"{class_name}_{method_name}"
                        names.append(ExtractedName(
                            original_name=containing.name,
                            recovered_name=_sanitize_identifier(recovered),
                            source='rtti',
                            confidence=confidence,
                            evidence=f'Demangled: {demangled} (from {mangled})',
                            class_name=class_name,
                            source_file=None,
                        ))

        # Typeinfo/vtable class'lari icin: fonksiyon listesinde bu class'in
        # method'larini ara (call graph'tan)
        for class_name, confidence in rtti_classes.items():
            # Bu class ismini iceren export fonksiyonlari bul
            for func_name, func_entry in self._func_by_name.items():
                clean = func_name.lstrip('_')
                if clean.startswith(class_name) and '::' not in clean:
                    # Zaten isimli -- kayda deger ama rename gerekmez
                    pass

        return names

    # ===================================================================
    # Strateji 7: VTable Chain Extraction
    # ===================================================================

    def _strategy_vtable_chain(self) -> list[ExtractedName]:
        """VTable symbol'lerinden virtual method fonksiyon zincirini cikarir.

        _ZTV prefix'li mangled symbol'ler vtable pointer'laridir.
        Fonksiyon listesinde bu symbol isimlerine sahip entry'ler varsa,
        vtable adresi bilinir. Vtable struct'inda ilk 2 slot (offset-to-top
        ve typeinfo pointer) atlanir, gerisi virtual method fonksiyon
        pointer'laridir.

        BU STRATEJI fonksiyon listesindeki vtable sembollerini kullanir:
        1. _ZTV prefix'li fonksiyon/symbol isimlerini bul
        2. Demangle ederek class ismini kurtarir
        3. Vtable adres araligi icerisindeki fonksiyonlari (address range)
           virtual method olarak isimlendirir
        4. Call graph'ta vtable fonksiyonunun callee'lerini virtual method
           olarak isimlendirir

        NOT: Binary memory image olmadan vtable icindeki fonksiyon
        pointer'larini okuyamayiz. Bunun yerine:
        a) Fonksiyon listesinde _ZN (mangled method) symbol'leri zaten
           strateji 4'te isleniyor
        b) Call graph'ta vtable constructor'inin callee'lerini kullanarak
           virtual method zincirini kurabiliriz
        c) Vtable entry'sinin adres araligi icerisindeki fonksiyonlari
           (binary layout yakinligi) kullanabiliriz
        """
        names: list[ExtractedName] = []
        seen_funcs: set[str] = set()

        # 1. Fonksiyon listesinde _ZTV prefix'li (vtable) sembol'leri bul
        vtable_symbols: list[tuple[_FuncEntry, str]] = []  # (func_entry, class_name)

        for func in self._functions:
            name = func.name
            if not name:
                continue
            # macOS: __ZTV..., Linux: _ZTV...
            stripped = name.lstrip('_')
            if not stripped.startswith('ZTV'):
                continue

            # c++filt ile demangle et
            demangled = _demangle_symbol(name)
            if demangled:
                cls, _ = _parse_demangled_class_method(demangled)
                if cls and not self._is_std_class(cls):
                    vtable_symbols.append((func, cls))
            else:
                # Demangle basarisiz -- mangled isimden class ismi cikar
                # _ZTV<len><ClassName> formati: _ZTV10CHTTPClient
                m = re.match(r'ZTV(\d+)(\w+)', stripped)
                if m:
                    name_len = int(m.group(1))
                    raw_class = m.group(2)[:name_len] if len(m.group(2)) >= name_len else m.group(2)
                    if raw_class and len(raw_class) >= 2:
                        vtable_symbols.append((func, raw_class))

        if not vtable_symbols:
            logger.debug("VTable chain: _ZTV sembol bulunamadi")
            return names

        logger.debug("VTable chain: %d vtable sembol bulundu", len(vtable_symbols))

        # 2. Her vtable icin: call graph'ta callee'leri virtual method olarak adlandir
        for vtable_func, class_name in vtable_symbols:
            vtable_addr_hex = f"{vtable_func.address:08x}"

            # Call graph'ta vtable node'unu bul
            vtable_node = self._call_graph.get(vtable_addr_hex)
            if vtable_node and vtable_node.callees:
                # Vtable'in callee'leri virtual method'lar
                for i, callee_addr in enumerate(vtable_node.callees):
                    callee_node = self._call_graph.get(callee_addr)
                    if not callee_node:
                        continue
                    if not _GHIDRA_AUTO_FUNC_RE.match(callee_node.name):
                        continue
                    if callee_node.name in seen_funcs:
                        continue

                    vmethod_name = f"{class_name}_vmethod_{i}"
                    names.append(ExtractedName(
                        original_name=callee_node.name,
                        recovered_name=_sanitize_identifier(vmethod_name),
                        source='vtable_chain',
                        confidence=0.80,
                        evidence=f'VTable callee: {name} -> slot {i}',
                        class_name=class_name,
                        source_file=None,
                    ))
                    seen_funcs.add(callee_node.name)

                    # Class-method bilgisini topla
                    if not hasattr(self, '_collected_class_methods'):
                        self._collected_class_methods = defaultdict(set)
                    self._collected_class_methods[class_name].add(f"vmethod_{i}")

            # 3. Vtable adresi yakinindaki fonksiyonlari da ara
            # Vtable genellikle constructor/destructor'larla birlikte bulunur
            if self._addr_mapper:
                vtable_end = vtable_func.address + max(vtable_func.size, 64)
                nearby_funcs = self._addr_mapper.find_functions_in_range(
                    vtable_func.address + 1, vtable_end,
                )

                # Sadece ilk 20 yakin fonksiyonu isle (vtable'da 20'den fazla
                # virtual method nadirdir)
                for j, nearby in enumerate(nearby_funcs[:20]):
                    if not _GHIDRA_AUTO_FUNC_RE.match(nearby.name):
                        continue
                    if nearby.name in seen_funcs:
                        continue

                    # Vtable icinde mi kontrol et (adres araligi)
                    offset = nearby.address - vtable_func.address
                    if offset <= 0:
                        continue

                    # Ilk 2 slot skip (offset-to-top + typeinfo ptr, her biri 8 byte ARM64)
                    slot_index = (offset // 8) - 2
                    if slot_index < 0:
                        continue

                    vmethod_name = f"{class_name}_vmethod_{slot_index}"
                    names.append(ExtractedName(
                        original_name=nearby.name,
                        recovered_name=_sanitize_identifier(vmethod_name),
                        source='vtable_chain',
                        confidence=0.65,  # Proximity-based, daha dusuk guven
                        evidence=f'VTable proximity: {class_name} vtable + {offset:#x} (slot {slot_index})',
                        class_name=class_name,
                        source_file=None,
                    ))
                    seen_funcs.add(nearby.name)

                    if not hasattr(self, '_collected_class_methods'):
                        self._collected_class_methods = defaultdict(set)
                    self._collected_class_methods[class_name].add(f"vmethod_{slot_index}")

        # 4. String'lerdeki _ZTV referanslarindan ek vtable tespiti
        # (Fonksiyon listesinde olmayan ama string olarak geçen vtable'lar)
        for s in self._strings:
            for m in _MANGLED_SYMBOL_RE.finditer(s.value):
                mangled = m.group(1)
                stripped_sym = mangled.lstrip('_')
                if not stripped_sym.startswith('ZTV'):
                    continue

                demangled = _demangle_symbol(mangled)
                if not demangled:
                    continue
                cls, _ = _parse_demangled_class_method(demangled)
                if not cls or self._is_std_class(cls):
                    continue

                # Bu string'in xref'lerindeki FUN_xxx'leri class'a ata
                if s.xrefs:
                    for xr in s.xrefs:
                        if not xr.from_function:
                            continue
                        if not _GHIDRA_AUTO_FUNC_RE.match(xr.from_function):
                            continue
                        if xr.from_function in seen_funcs:
                            continue

                        # Vtable referansi olan fonksiyon muhtemelen constructor
                        ctor_name = f"{cls}_constructor"
                        names.append(ExtractedName(
                            original_name=xr.from_function,
                            recovered_name=_sanitize_identifier(ctor_name),
                            source='vtable_chain',
                            confidence=0.75,
                            evidence=f'VTable string ref: {demangled} in {xr.from_function}',
                            class_name=cls,
                            source_file=None,
                        ))
                        seen_funcs.add(xr.from_function)

                        if not hasattr(self, '_collected_class_methods'):
                            self._collected_class_methods = defaultdict(set)
                        self._collected_class_methods[cls].add("constructor")

        logger.debug(
            "VTable chain: %d fonksiyon isimlendirdi",
            len(names),
        )

        return names

    def _check_cppfilt(self) -> bool:
        """c++filt komutunun mevcut olup olmadigini kontrol et."""
        try:
            result = subprocess.run(
                ['c++filt', '--version'],
                capture_output=True, text=True, timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return False

    def _batch_demangle(self, symbols: list[str]) -> dict[str, str]:
        """Birden fazla mangled symbol'u toplu demangle et.

        Her birini tek tek c++filt'e gondermek yerine, stdin'den
        toplu olarak gonderir (cok daha hizli).

        Args:
            symbols: Mangled symbol listesi.

        Returns:
            {mangled: demangled} dict (basarisiz olanlar haric).
        """
        if not symbols:
            return {}

        # Tekrarlari kaldir
        unique_symbols = list(set(symbols))

        result: dict[str, str] = {}

        # v1.10.0 Fix Sprint HIGH-4: input sanitization. Satir bazli
        # c++filt protokolunde CR/LF karakteri shift yaratir; NUL ve
        # non-printable karakterleri de at.
        def _sanitize_sym(sym: str) -> str:
            return "".join(ch for ch in sym if ch.isprintable() and ch not in ("\r", "\n"))

        # Batch size: 500 symbol birden
        batch_size = 500
        for i in range(0, len(unique_symbols), batch_size):
            batch = unique_symbols[i:i + batch_size]
            input_text = '\n'.join(_sanitize_sym(s) for s in batch) + '\n'

            try:
                proc = subprocess.run(
                    ['c++filt'],
                    input=input_text,
                    capture_output=True, text=True,
                    timeout=30,
                    shell=False,
                )
                if proc.returncode == 0:
                    lines = proc.stdout.strip().split('\n')
                    for mangled, demangled in zip(batch, lines):
                        demangled = demangled.strip()
                        if demangled and demangled != mangled:
                            result[mangled] = demangled
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
                logger.warning("c++filt batch demangle hatasi: %s", exc)
                break

        logger.debug(
            "Demangle: %d / %d basarili",
            len(result), len(unique_symbols),
        )
        return result

    def _is_std_class(self, class_name: str) -> bool:
        """Standart library class'i mi kontrol et.

        std::, __cxxabiv1::, basic_string gibi class'lari atla.
        """
        skip_prefixes = (
            'basic_string', 'basic_ostream', 'basic_istream',
            'basic_streambuf', 'allocator', 'char_traits',
            'bad_alloc', 'bad_cast', 'bad_typeid',
            'exception', 'runtime_error', 'logic_error',
            'length_error', 'out_of_range', 'overflow_error',
            'underflow_error', 'invalid_argument', 'domain_error',
            'range_error', 'bad_function_call', 'bad_weak_ptr',
            'bad_array_new_length', 'bad_optional_access',
            '__class_type_info', '__si_class_type_info',
            '__vmi_class_type_info', '__pointer_type_info',
            '__function_type_info', '__fundamental_type_info',
        )
        return class_name in skip_prefixes or class_name.startswith('__')

    # ===================================================================
    # Strateji 5: String Intelligence
    # ===================================================================

    def _strategy_string_intelligence(self) -> list[ExtractedName]:
        """StringIntelligence modulunu kullanarak assert/error/protocol/telemetry/api_name
        string'lerinden isim kurtarir.

        Bu strateji, mevcut debug_string stratejisinin kapsamadigi pattern'leri
        yakalar: hata mesajlari, protocol handler isimleri, telemetry event'leri,
        ve ozellikle API isim string'leri.

        iki yontemle calisir:
        1. Per-function xref-based: ghidra_xrefs.json'daki function_xrefs.strings_used
           verisini kullanarak her fonksiyon icin referans ettigi string'leri analiz eder.
           Bu yontem FUN_xxx -> kurtarilan_isim eslesmesi olusturur.
        2. Bulk fallback: xref verisi yoksa, tum string'leri toplu analiz eder
           (orijinal davranis, adres eslestirmesi olmadan).
        """
        si = StringIntelligence()
        names: list[ExtractedName] = []
        seen_funcs: set[str] = set()  # Ayni fonksiyonu birden fazla kez adlandirma

        # ----------------------------------------------------------------
        # Yontem 1: Per-function xref-based analiz (ghidra_xrefs.json)
        # ----------------------------------------------------------------
        if self._func_string_refs:
            for func_addr_str, strings_used in self._func_string_refs.items():
                # Bu fonksiyonun ismini bul
                func_entry = self._func_by_addr.get(
                    _hex_to_int(func_addr_str)
                ) if func_addr_str else None

                func_name = func_entry.name if func_entry else None

                # Sadece FUN_xxx fonksiyonlari adlandir
                if not func_name or not _GHIDRA_AUTO_FUNC_RE.match(func_name):
                    continue
                if func_name in seen_funcs:
                    continue

                # Bu fonksiyonun referans ettigi string'leri analiz et
                func_strings_data = [
                    {"address": _hex_to_int(s.get("address", "0")),
                     "value": s.get("value", "")}
                    for s in strings_used
                    if s.get("value")
                ]
                if not func_strings_data:
                    continue

                intel_results = si.analyze_strings(func_strings_data)
                if not intel_results:
                    continue

                # En yuksek confidence'li sonucu sec
                best = intel_results[0]  # Zaten confidence'a gore sirali

                recovered = _sanitize_identifier(best.name)
                if not recovered or recovered == 'unknown':
                    continue

                names.append(ExtractedName(
                    original_name=func_name,
                    recovered_name=recovered,
                    source='string_intel',
                    confidence=best.confidence,
                    evidence=f'{best.pattern_type}: "{best.source_string[:100]}"',
                    class_name=best.class_name or None,
                    source_file=None,
                ))
                seen_funcs.add(func_name)

                # Class-method bilgisini topla (merge icin)
                if best.class_name and best.method_name:
                    if not hasattr(self, '_collected_class_methods'):
                        self._collected_class_methods = defaultdict(set)
                    self._collected_class_methods[best.class_name].add(best.method_name)

            logger.info(
                "String intelligence (xref-based): %d fonksiyon adlandirildi",
                len(names),
            )

        # ----------------------------------------------------------------
        # Yontem 2: Xref-based string->func eslestirme (_string_to_funcs)
        # Ghidra strings JSON'unda xref bilgisi varsa bunu da kullan
        # ----------------------------------------------------------------
        if self._string_to_funcs:
            strings_data = [
                {"address": s.address, "value": s.value}
                for s in self._strings
            ]

            intel_results = si.analyze_strings(strings_data)

            for ir in intel_results:
                # Bu string'i referans eden fonksiyonlari bul
                ref_funcs = self._string_to_funcs.get(ir.address, [])
                for rf_name in ref_funcs:
                    if not _GHIDRA_AUTO_FUNC_RE.match(rf_name):
                        continue
                    if rf_name in seen_funcs:
                        continue

                    recovered = _sanitize_identifier(ir.name)
                    if not recovered or recovered == 'unknown':
                        continue

                    names.append(ExtractedName(
                        original_name=rf_name,
                        recovered_name=recovered,
                        source='string_intel',
                        confidence=ir.confidence,
                        evidence=f'{ir.pattern_type}: "{ir.source_string[:100]}"',
                        class_name=ir.class_name or None,
                        source_file=None,
                    ))
                    seen_funcs.add(rf_name)

                    if ir.class_name and ir.method_name:
                        if not hasattr(self, '_collected_class_methods'):
                            self._collected_class_methods = defaultdict(set)
                        self._collected_class_methods[ir.class_name].add(ir.method_name)

                    break  # Bir string icin bir fonksiyon yeterli

        # ----------------------------------------------------------------
        # Yontem 3: Bulk fallback (xref yoksa, adres eslestirmesi olmadan)
        # Sadece class/method bilgisi toplar, fonksiyon eslestirmesi yapmaz.
        # ----------------------------------------------------------------
        if not self._func_string_refs and not self._string_to_funcs:
            strings_data = [
                {"address": s.address, "value": s.value}
                for s in self._strings
            ]
            intel_results = si.analyze_strings(strings_data)

            for ir in intel_results:
                if ir.class_name and ir.method_name:
                    if not hasattr(self, '_collected_class_methods'):
                        self._collected_class_methods = defaultdict(set)
                    self._collected_class_methods[ir.class_name].add(ir.method_name)

            logger.debug(
                "String intelligence (bulk, no xref): %d sonuc (sadece class/method bilgisi)",
                len(intel_results),
            )

        return names

    # ===================================================================
    # Strateji 6: Swift Mangled Class Demangle
    # ===================================================================

    # Swift naming convention: suffix/prefix pattern'leri
    # Bunlar kaldirildiginda base class/protocol ismi ortaya cikar
    _SWIFT_REMOVABLE_SUFFIXES = ("Default", "Defaults", "Impl", "Implementation")
    _SWIFT_REMOVABLE_PREFIXES = ("Active", "Passive", "Concrete", "Default")
    # Plural -> singular donusumleri (basit suffix kurallari)
    _SWIFT_PLURAL_SUFFIXES = (
        ("ies", "y"),      # Properties -> Property
        ("sses", "ss"),    # Classes -> Class (cift s koruma)
        ("ses", "se"),     # Responses -> Response
        ("zes", "ze"),     # Sizes -> Size
        ("es", "e"),       # Types -> Type (dikkat: sadece belirli durumlarda)
        ("s", ""),         # Items -> Item
    )

    @staticmethod
    def _swift_depluralize(name: str) -> str | None:
        """Swift class ismini singular'a cevir.

        Ornek:
            CycleSizes -> CycleSize
            Properties -> Property
            Items -> Item
            Defaults -> Default (ama bunu istemiyoruz, None don)
            Classes -> Class

        Returns:
            Singular isim veya None (donusum yapilamazsa / anlamsiz ise).
        """
        if len(name) < 4:
            return None
        for plural_end, singular_end in BinaryNameExtractor._SWIFT_PLURAL_SUFFIXES:
            if name.endswith(plural_end):
                candidate = name[:-len(plural_end)] + singular_end
                # Sonuc en az 3 karakter olmali
                if len(candidate) >= 3:
                    return candidate
        return None

    def _swift_extract_base_variants(self, class_name: str) -> list[tuple[str, float]]:
        """Swift class isminden base class/protocol varyantlari cikar.

        Orijinal ismi VERMEZ -- sadece turetilmis varyantlari dondurur.
        Her varyant (isim, confidence) tuple'i olarak doner.

        Ornekler:
            CycleSizesDefault -> [("CycleSizes", 0.85), ("CycleSize", 0.80)]
            ActiveEventMonitor -> [("EventMonitor", 0.85)]
            WindowCalculation -> [] (base class zaten kendisi)
            IntDefault -> [("Int", 0.70)]  -- kisa ama yine de cikar

        Returns:
            [(variant_name, confidence), ...]
        """
        variants: list[tuple[str, float]] = []
        seen: set[str] = {class_name}  # Orijinali tekrar verme

        # 1. Suffix kaldirma: XxxDefault -> Xxx
        for suffix in self._SWIFT_REMOVABLE_SUFFIXES:
            if class_name.endswith(suffix) and len(class_name) > len(suffix):
                base = class_name[:-len(suffix)]
                if base and base not in seen and len(base) >= 2:
                    variants.append((base, 0.85))
                    seen.add(base)
                    # Base'in plural'ini de coz: CycleSizes -> CycleSize
                    singular = self._swift_depluralize(base)
                    if singular and singular not in seen and len(singular) >= 3:
                        variants.append((singular, 0.80))
                        seen.add(singular)

        # 2. Prefix kaldirma: ActiveXxx -> Xxx
        for prefix in self._SWIFT_REMOVABLE_PREFIXES:
            if class_name.startswith(prefix) and len(class_name) > len(prefix):
                base = class_name[len(prefix):]
                # Base buyuk harfle baslamali (Swift convention)
                if base and base[0].isupper() and base not in seen:
                    variants.append((base, 0.85))
                    seen.add(base)

        # 3. Hem prefix hem suffix varsa: DefaultXxxImpl -> Xxx
        for prefix in self._SWIFT_REMOVABLE_PREFIXES:
            for suffix in self._SWIFT_REMOVABLE_SUFFIXES:
                if (class_name.startswith(prefix)
                        and class_name.endswith(suffix)
                        and len(class_name) > len(prefix) + len(suffix)):
                    base = class_name[len(prefix):-len(suffix)]
                    if base and base[0].isupper() and base not in seen and len(base) >= 2:
                        variants.append((base, 0.75))
                        seen.add(base)

        return variants

    # Swift mangled symbol toplama regex'leri (class seviyesi, instance degil)
    # Eski mangling: _TtC (class), _TtV (struct), _TtO (enum), _TtE (extension)
    _SWIFT_OLD_MANGLED_RE = re.compile(r'(_Tt[CVOE]\d+\w+)')
    # Modern Swift 5+ mangling: $s veya $S prefix + en az 4 alfanumerik karakter
    # Ornekler: $s9Rectangle7DefaultP, $ss10SetAlgebraP, $s12MyApp0B7ModuleC
    _SWIFT_MODERN_MANGLED_RE = re.compile(r'(\$[sS][a-zA-Z0-9_]{4,})')

    def _strategy_swift_demangle(self) -> list[ExtractedName]:
        """Swift mangled sembollerini xcrun swift-demangle ile cozer.

        Uc asama:
        1. Toplama: _Tt* (eski) ve $s/$S (modern) mangled symbol'leri string,
           fonksiyon ve decompiled C dosyalarindan topla.
        2. Batch demangle: Tum symbol'leri tek subprocess'te xcrun swift-demangle'a gonder.
        3. Parse: Demangled sonucu Module.Type.method formatindan ayristir,
           class/struct/enum/protocol ve method isimlerini cikar.

        Confidence seviyeleri:
        - 0.95: Birebir demangle (class/struct/enum ismi)
        - 0.90: Method ismi (class.method formatindan)
        - 0.85-0.75: Varyant isimleri (suffix/prefix cikarma)
        """
        names: list[ExtractedName] = []
        swift_mangled: set[str] = set()

        # --- Asama 1: Symbol toplama ---
        self._collect_swift_mangled_symbols(swift_mangled)

        if not swift_mangled:
            return names

        logger.debug("Swift demangle: %d benzersiz mangled symbol toplandi", len(swift_mangled))

        # --- Asama 2: Batch demangle ---
        demangled_map = self._batch_swift_demangle(sorted(swift_mangled))

        if not demangled_map:
            return names

        logger.debug("Swift demangle: %d / %d basariyla demangle edildi",
                      len(demangled_map), len(swift_mangled))

        # --- Asama 3: Parse ve isim cikarma ---
        # Fonksiyon ismi -> _FuncEntry haritasi (mangled -> func eslestirmesi icin)
        func_name_lookup: dict[str, _FuncEntry] = {}
        for func in self._functions:
            fname = func.name if isinstance(func, _FuncEntry) else (
                func.get("name", "") if isinstance(func, dict) else "")
            if fname:
                func_name_lookup[fname] = func

        # Gorulen class isimleri (tekrar onleme)
        seen_classes: set[str] = set()
        # Class -> method listesi
        swift_class_methods: dict[str, set[str]] = defaultdict(set)

        for mangled, demangled in demangled_map.items():
            parsed = self._parse_swift_demangled(demangled)
            if not parsed:
                continue

            module_name, type_name, method_name, kind = parsed

            # --- Class/Struct/Enum/Protocol ismi ---
            if type_name and type_name not in seen_classes:
                seen_classes.add(type_name)

                # Orijinal isim (conf 0.95 -- birebir demangle)
                names.append(ExtractedName(
                    original_name=mangled,
                    recovered_name=type_name,
                    source="swift_demangle",
                    confidence=0.95,
                    evidence=f"swift-demangle: {mangled} -> {demangled}",
                    class_name=type_name,
                    source_file=None,
                ))

                # Varyant isimleri cikar (conf 0.75-0.85)
                for variant_name, variant_conf in self._swift_extract_base_variants(type_name):
                    names.append(ExtractedName(
                        original_name=mangled,
                        recovered_name=variant_name,
                        source="swift_demangle_variant",
                        confidence=variant_conf,
                        evidence=f"swift variant: {type_name} -> {variant_name}",
                        class_name=variant_name,
                        source_file=None,
                    ))

            # --- Method ismi -> fonksiyon rename ---
            if type_name and method_name:
                swift_class_methods[type_name].add(method_name)
                recovered_func_name = f"{type_name}_{method_name}"

                # Fonksiyon listesinde bu mangled isimle eslesen var mi?
                matching_func = func_name_lookup.get(mangled)
                if matching_func is not None:
                    orig_fname = matching_func.name
                    # Ghidra otomatik isimlerini (FUN_xxx) veya $ ile baslayanlari rename et
                    if _GHIDRA_AUTO_FUNC_RE.match(orig_fname) or orig_fname.startswith("$"):
                        names.append(ExtractedName(
                            original_name=orig_fname,
                            recovered_name=_sanitize_identifier(recovered_func_name),
                            source="swift_demangle",
                            confidence=0.90,
                            evidence=f"swift method: {mangled} -> {demangled}",
                            class_name=type_name,
                            source_file=None,
                        ))
                # Adres bazli eslestirme dene (string xref uzerinden)
                elif self._addr_mapper:
                    for s in self._strings:
                        if mangled in s.value or s.value.strip() == mangled:
                            containing = self._addr_mapper.find_nearest_function(
                                s.address, max_distance=0x2000,
                            )
                            if containing and _GHIDRA_AUTO_FUNC_RE.match(containing.name):
                                names.append(ExtractedName(
                                    original_name=containing.name,
                                    recovered_name=_sanitize_identifier(recovered_func_name),
                                    source="swift_demangle",
                                    confidence=0.85,
                                    evidence=f"swift method (xref): {mangled} -> {demangled}",
                                    class_name=type_name,
                                    source_file=None,
                                ))
                            break

        # Class-method bilgisini kaydet (merge icin)
        if swift_class_methods:
            if not hasattr(self, '_collected_class_methods'):
                self._collected_class_methods = defaultdict(set)
            for cls, methods in swift_class_methods.items():
                self._collected_class_methods[cls].update(methods)

        return names

    def _collect_swift_mangled_symbols(self, out: set[str]) -> None:
        """String, fonksiyon ve decompiled C dosyalarindan Swift mangled symbol topla.

        Hem eski (_Tt*) hem modern ($s/$S) mangling pattern'lerini arar.
        Sonuclari ``out`` set'ine ekler.
        """
        old_re = self._SWIFT_OLD_MANGLED_RE
        modern_re = self._SWIFT_MODERN_MANGLED_RE

        # String'lerde ara
        for s in self._strings:
            val = s.value
            for m in old_re.finditer(val):
                out.add(m.group(1))
            for m in modern_re.finditer(val):
                out.add(m.group(1))
            # Tam string $s ile basliyorsa, tum string'i de ekle
            # (Ghidra bazen her symbol'u ayri string olarak cikarir)
            stripped = val.strip()
            if (stripped.startswith('$s') or stripped.startswith('$S')
                    or stripped.startswith('_$s') or stripped.startswith('_$S')):
                clean = stripped.lstrip('_')
                if len(clean) >= 5:
                    out.add(clean)

        # Fonksiyon isimlerinde ara
        for func in self._functions:
            name = func.name if isinstance(func, _FuncEntry) else (
                func.get("name", "") if isinstance(func, dict) else "")
            if not name:
                continue
            for m in old_re.finditer(name):
                out.add(m.group(1))
            for m in modern_re.finditer(name):
                out.add(m.group(1))
            # $ ile baslayan fonksiyon isimleri Swift olabilir
            clean = name.lstrip('_')
            if (clean.startswith('$s') or clean.startswith('$S')) and len(clean) >= 5:
                out.add(clean)

        # Decompiled C dosyalarinda ara
        ws_root = getattr(self, '_workspace_root', None)
        if ws_root:
            decompiled_dirs = [
                ws_root / "deobfuscated" / "decompiled",
                ws_root / "static" / "ghidra_output" / "decompiled",
            ]
            for d in decompiled_dirs:
                if d.exists():
                    c_files = list(d.glob("*.c"))
                    logger.debug("Swift demangle: %s dizininde %d C dosyasi taraniyor",
                                 d, len(c_files))
                    for cf in c_files:
                        try:
                            content = cf.read_text(errors="replace")
                            for m in old_re.finditer(content):
                                out.add(m.group(1))
                            for m in modern_re.finditer(content):
                                out.add(m.group(1))
                        except OSError as e:
                            logger.debug("Swift demangle: %s dosyasi okunamadi: %s", cf, e)
                    break
        else:
            logger.debug("Swift demangle: workspace_root bulunamadi, C dosyalari taranamiyor")

    def _batch_swift_demangle(self, symbols: list[str]) -> dict[str, str]:
        """xcrun swift-demangle ile toplu Swift symbol demangle.

        Args:
            symbols: Sirali mangled symbol listesi.

        Returns:
            {mangled: demangled} dict. Basarisiz veya degismeyen symbol'ler haric.
        """
        if not symbols:
            return {}

        result: dict[str, str] = {}
        batch_size = 500

        for i in range(0, len(symbols), batch_size):
            batch = symbols[i:i + batch_size]
            # v1.10.0 Fix Sprint HIGH-5: Popen context manager ile kaynak sizintisi
            # onleme. TimeoutExpired icinde kill() + wait() yapiyoruz, proc asla
            # gc'ye dusmeden kapanacak.
            try:
                with subprocess.Popen(
                    ["xcrun", "swift-demangle"],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True,
                ) as proc:
                    try:
                        stdout, _ = proc.communicate("\n".join(batch), timeout=30)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        try:
                            proc.communicate(timeout=5)
                        except Exception as e:
                            logger.debug(
                                "xcrun swift-demangle kill sonrasi communicate hatasi (batch %d-%d): %s",
                                i, i + len(batch), e,
                            )
                        logger.warning(
                            "xcrun swift-demangle timeout (batch %d-%d)",
                            i, i + len(batch),
                        )
                        continue
                    if proc.returncode != 0:
                        logger.warning("xcrun swift-demangle hata kodu: %d", proc.returncode)
                        continue

                    lines = stdout.strip().split("\n")
                    for mangled, demangled in zip(batch, lines):
                        demangled = demangled.strip()
                        if demangled and demangled != mangled:
                            result[mangled] = demangled

            except FileNotFoundError:
                logger.debug("xcrun swift-demangle bulunamadi, regex fallback kullanilacak")
                # Fallback: basit _Tt pattern'leri icin regex demangle
                for sym in batch:
                    parsed = self._regex_swift_demangle(sym)
                    if parsed:
                        result[sym] = parsed
                break

        return result

    @staticmethod
    def _regex_swift_demangle(symbol: str) -> str | None:
        """xcrun yoksa basit _Tt pattern'leri icin regex fallback.

        Sadece _TtCNNClassName formatini cozer.
        Modern $s mangling icin xcrun gereklidir.

        Format: _Tt[CVO] + length-prefixed-name + length-prefixed-name
        Ornek: _TtC9Rectangle17CenterCalculation
               -> kind=C, "9Rectangle" -> module_len=9, module="Rectangle"
               -> "17CenterCalculation" -> type_len=17, type="CenterCalculation"
        """
        m = re.match(r'_Tt([CVOE])(.+)', symbol)
        if not m:
            return None

        rest = m.group(2)
        # length-prefixed string'leri parse et
        parts = []
        pos = 0
        while pos < len(rest):
            num_start = pos
            while pos < len(rest) and rest[pos].isdigit():
                pos += 1
            if pos == num_start:
                break
            length = int(rest[num_start:pos])
            if pos + length > len(rest):
                break
            parts.append(rest[pos:pos + length])
            pos += length

        if len(parts) >= 2:
            module_name, type_name = parts[0], parts[-1]
            return f"{module_name}.{type_name}"
        elif len(parts) == 1:
            return parts[0]

        return None

    @staticmethod
    def _parse_swift_demangled(demangled: str) -> tuple[str | None, str | None, str | None, str] | None:
        """Demangled Swift string'den module, type, method ve kind bilgisini cikar.

        Demangled formatlar:
        - "Rectangle.CenterCalculation"                      -> (Rectangle, CenterCalculation, None, "type")
        - "Rectangle.WindowManager.apply(_:)"                -> (Rectangle, WindowManager, apply, "method")
        - "type metadata accessor for Rectangle.SnapArea"    -> (Rectangle, SnapArea, None, "metadata")
        - "protocol witness table for ..."                   -> parsed accordingly
        - "generic specialization <...>"                     -> None (skip)
        - "(extension in Rectangle):Foundation.UserDefaults" -> (Rectangle, UserDefaults, None, "extension")

        Returns:
            (module, type_name, method_name, kind) tuple or None.
        """
        if not demangled:
            return None

        # Gereksiz sonuclari atla
        skip_prefixes = (
            "generic specialization",
            "lazy protocol witness",
            "reabstraction thunk",
            "outlined",
            "key path",
            "partial apply",
            "closure #",
            "implicit closure",
            "{",
        )
        for prefix in skip_prefixes:
            if demangled.startswith(prefix):
                return None

        # "type metadata accessor for Module.TypeName"
        m = re.match(
            r'(?:type metadata|nominal type descriptor|reflection metadata)'
            r' (?:accessor )?for (.+)', demangled)
        if m:
            fqn = m.group(1).strip()
            parts = fqn.split(".")
            if len(parts) >= 2:
                return (parts[0], parts[-1], None, "metadata")
            return (None, fqn, None, "metadata")

        # "protocol witness table for Module.Protocol in conformance Module.Type"
        m = re.match(r'protocol witness (?:table )?for (.+?) in conformance (.+)', demangled)
        if m:
            conformance = m.group(2).strip()
            parts = conformance.split(".")
            type_name = parts[-1] if parts else None
            module = parts[0] if len(parts) >= 2 else None
            return (module, type_name, None, "witness")

        # "protocol conformance descriptor for Module.Type : Module.Protocol"
        m = re.match(r'protocol conformance descriptor for (.+?) :', demangled)
        if m:
            fqn = m.group(1).strip()
            parts = fqn.split(".")
            if len(parts) >= 2:
                return (parts[0], parts[-1], None, "conformance")

        # "(extension in Module):OtherModule.Type.method(...)"
        m = re.match(r'\(extension in (\w+)\):(.+)', demangled)
        if m:
            ext_module = m.group(1)
            rest = m.group(2)
            parts = rest.split(".")
            if len(parts) >= 2:
                type_name = parts[-2] if len(parts) >= 2 else parts[-1]
                method_name = parts[-1].split("(")[0] if "(" in parts[-1] else None
                # Standart Foundation/Swift type'lari atlama
                std_types = {"UserDefaults", "String", "Int", "Array",
                             "Dictionary", "Set", "Data", "URL",
                             "Bool", "Double", "Float", "Optional"}
                if type_name in std_types:
                    return None
                return (ext_module, type_name, method_name, "extension")

        # "Module.Type.method(arg:label:) -> ReturnType"
        # veya "Module.Type"
        # veya "Module.Type.property.getter"
        # Arrow ve ' : ' den oncesini al
        core = demangled.split(" -> ")[0].split(" : ")[0].strip()
        # Parantez icindeki parametreleri kaldir
        paren_depth = 0
        clean_chars: list[str] = []
        for ch in core:
            if ch == '(':
                paren_depth += 1
            elif ch == ')':
                paren_depth = max(0, paren_depth - 1)
            elif paren_depth == 0:
                clean_chars.append(ch)
        core = ''.join(clean_chars).strip()

        # ".getter" / ".setter" / ".modify" suffix'lerini temizle
        for accessor in ('.getter', '.setter', '.modify', '.materializeForSet',
                         '.didSet', '.willSet', '.unsafeMutableAddressor'):
            if core.endswith(accessor):
                core = core[:-len(accessor)]
                break

        parts = core.split(".")
        if not parts:
            return None

        # Swift standart library tiplerini atla
        if parts[0] in ("Swift", "ObjectiveC", "_StringProcessing",
                         "__C", "_Concurrency"):
            return None

        if len(parts) == 1:
            name = parts[0]
            if name and name[0].isupper() and len(name) >= 2:
                return (None, name, None, "type")
            return None

        if len(parts) == 2:
            module, type_name = parts
            if type_name and len(type_name) >= 2:
                return (module, type_name, None, "type")
            return None

        if len(parts) >= 3:
            module = parts[0]
            type_name = parts[1]
            method_or_nested = parts[2]

            # Nested type mi method mu? Swift: type isimleri buyuk harfle baslar
            if method_or_nested and method_or_nested[0].isupper() and len(parts) == 3:
                return (module, method_or_nested, None, "type")

            method_name = method_or_nested
            if method_name in ('init', 'deinit', '__allocating_init',
                               '__deallocating_deinit'):
                method_name = method_name.lstrip('_')

            if type_name and len(type_name) >= 2:
                return (module, type_name, method_name, "method")

        return None

    # ===================================================================
    # Sonuc birlestirme
    # ===================================================================

    def _merge_results(self, result: ExtractionResult) -> None:
        """Tum stratejilerdeki sonuclari birlestir.

        Ayni fonksiyon icin birden fazla isim onerisi varsa,
        en yuksek confidence'a sahip olani sec.

        Ayrica class-method, member-var ve source-file bilgilerini topla.
        """
        # Fonksiyon basi en iyi ismi sec
        best_by_func: dict[str, ExtractedName] = {}

        for name in result.names:
            if name.confidence < self._min_confidence:
                continue

            existing = best_by_func.get(name.original_name)
            if existing is None or name.confidence > existing.confidence:
                best_by_func[name.original_name] = name

        # Naming map olustur
        self._naming_map = {}
        for orig_name, extracted in best_by_func.items():
            # Ayni isimle yeniden adlandirma yapma
            if extracted.recovered_name != orig_name:
                self._naming_map[orig_name] = extracted.recovered_name

        # Class-method bilgilerini result'a aktar
        if hasattr(self, '_collected_class_methods'):
            for cls, methods in self._collected_class_methods.items():
                result.class_methods[cls] = sorted(methods)

        # Member-var bilgilerini result'a aktar
        if hasattr(self, '_collected_member_vars'):
            for cls, members in self._collected_member_vars.items():
                result.member_vars[cls] = sorted(members)

        # Source-file bilgilerini result'a aktar
        if hasattr(self, '_collected_source_files'):
            for filename, classes in self._collected_source_files.items():
                result.source_files[filename] = sorted(classes)

        # Duplicate isimleri engelle: Ayni recovered_name birden fazla
        # fonksiyona atanmis olabilir. Sadece en yuksek confidence olani tut.
        reverse_map: dict[str, tuple[str, float]] = {}  # recovered -> (original, conf)
        for orig, recovered in list(self._naming_map.items()):
            extracted = best_by_func[orig]
            prev_entry = reverse_map.get(recovered)
            if prev_entry is None or extracted.confidence > prev_entry[1]:
                # Oncekini kaldir
                if prev_entry:
                    self._naming_map.pop(prev_entry[0], None)
                reverse_map[recovered] = (orig, extracted.confidence)
            else:
                # Bu daha dusuk confidence -- kaldir
                del self._naming_map[orig]

        logger.debug(
            "Merge sonucu: %d isim eslemesi, %d class, %d member var, %d source file",
            len(self._naming_map),
            len(result.class_methods),
            len(result.member_vars),
            len(result.source_files),
        )

    # ===================================================================
    # Strateji 8: Swift Source Cross-Match (GitHub kaynak kodu)
    # ===================================================================

    # Swift kaynak kod declaration regex'leri
    _SWIFT_TYPE_DECL_RE = re.compile(
        r'^\s*(?:@\w+\s+)*'
        r'(?:open|public|internal|fileprivate|private)?\s*'
        r'(?:final\s+)?'
        r'(class|struct|enum|protocol)\s+(\w+)',
        re.MULTILINE,
    )
    _SWIFT_FUNC_DECL_RE = re.compile(
        r'^\s*(?:@\w+\s+)*'
        r'(?:open|public|internal|fileprivate|private)?\s*'
        r'(?:override\s+)?(?:static\s+|class\s+)?'
        r'func\s+(\w+)',
        re.MULTILINE,
    )
    _SWIFT_PROP_DECL_RE = re.compile(
        r'^\s*(?:@\w+\s+)*'
        r'(?:open|public|internal|fileprivate|private)?\s*'
        r'(?:override\s+)?(?:static\s+|class\s+)?'
        r'(?:var|let)\s+(\w+)',
        re.MULTILINE,
    )

    def _parse_swift_source_repo(self, repo_path: Path) -> dict[str, dict]:
        """Swift kaynak kodundaki tum type, method ve property bildirimlerini cikar.

        Args:
            repo_path: Git clone dizini.

        Returns:
            {type_name: {"kind": "class"|"struct"|..., "methods": set, "props": set,
                         "file": str}} dict.
        """
        if self._source_declarations is not None:
            return self._source_declarations

        declarations: dict[str, dict] = {}
        swift_files = list(repo_path.rglob("*.swift"))

        for sf in swift_files:
            try:
                content = sf.read_text(errors="replace")
            except OSError:
                continue

            # Relative path (repo kok dizinine gore)
            rel_path = str(sf.relative_to(repo_path))

            # Tum bildirimleri pozisyonlariyla topla
            type_positions: list[tuple[int, str, str]] = []  # (pos, kind, name)
            for m in self._SWIFT_TYPE_DECL_RE.finditer(content):
                kind = m.group(1)
                name = m.group(2)
                type_positions.append((m.start(), kind, name))
                if name not in declarations:
                    declarations[name] = {
                        "kind": kind,
                        "methods": set(),
                        "props": set(),
                        "file": rel_path,
                    }

            # Func bildirimleri -- pozisyon bazli en yakin onceki type'a ata
            for m in self._SWIFT_FUNC_DECL_RE.finditer(content):
                func_name = m.group(1)
                fpos = m.start()
                owner = self._find_owning_type(type_positions, fpos)
                if owner and owner in declarations:
                    declarations[owner]["methods"].add(func_name)

            # Property bildirimleri -- ayni pozisyon bazli atama
            for m in self._SWIFT_PROP_DECL_RE.finditer(content):
                prop_name = m.group(1)
                ppos = m.start()
                owner = self._find_owning_type(type_positions, ppos)
                if owner and owner in declarations:
                    declarations[owner]["props"].add(prop_name)

        self._source_declarations = declarations
        logger.debug("Swift source parse: %d type, %d swift dosya",
                     len(declarations), len(swift_files))
        return declarations

    @staticmethod
    def _find_owning_type(
        type_positions: list[tuple[int, str, str]],
        member_pos: int,
    ) -> str | None:
        """Bir member (func/var) icin en yakin onceki type bildirimini bul.

        Args:
            type_positions: [(position, kind, name), ...] sirali type listesi.
            member_pos: Member'in dosya icindeki pozisyonu.

        Returns:
            Sahibi olan type ismi veya None.
        """
        owner = None
        for tpos, _, tname in type_positions:
            if tpos < member_pos:
                owner = tname
            else:
                break
        return owner

    def _strategy_source_cross_match(self) -> list[ExtractedName]:
        """Acik kaynak Swift reposuyla binary symbol'lerini eslestirir.

        Binary'deki string'lerde gecen isimler (class, fonksiyon, property)
        kaynak koddaki bildirimlerle karsilastirilir. Tam eslesmeler yuksek
        confidence ile rapor edilir.

        Confidence seviyeleri:
        - 0.92: Binary string'de gecen isim, kaynak kodda type olarak tanimli
        - 0.88: Binary fonksiyon ismi, kaynak kodda method olarak tanimli
        - 0.85: Fonksiyon adi kaynak kod class ismiyle basliyor (orn: WindowManager_apply)
        """
        if not self._source_repo_path:
            return []

        names: list[ExtractedName] = []
        declarations = self._parse_swift_source_repo(self._source_repo_path)

        if not declarations:
            return names

        # Kaynak koddaki tum type isimlerini set olarak al
        source_types = set(declarations.keys())
        # Kaynak koddaki tum method isimlerini {method: [type, ...]} olarak topla
        source_methods: dict[str, list[str]] = defaultdict(list)
        for type_name, info in declarations.items():
            for method in info.get("methods", set()):
                source_methods[method].append(type_name)

        # Binary string'lerinde kaynak kod type isimlerini ara
        # Bu binary'de hangi class isimleri gorunuyor?
        binary_type_hits: dict[str, list[_StringEntry]] = defaultdict(list)
        for s in self._strings:
            for type_name in source_types:
                # Tam kelime eslesmesi (false positive onleme)
                if len(type_name) < 4:
                    continue
                if type_name in s.value:
                    binary_type_hits[type_name].append(s)

        # Ghidra fonksiyon listesindeki isimleri kaynak kodla eslesir
        seen_matches: set[str] = set()

        # 1. Fonksiyon isimlerinde type adlariyla eslestirme
        for func in self._functions:
            func_name = func.name if isinstance(func, _FuncEntry) else (
                func.get("name", "") if isinstance(func, dict) else "")
            if not func_name or not _GHIDRA_AUTO_FUNC_RE.match(func_name):
                continue

            # Bu FUN_xxx fonksiyonunun adresindeki string xref'lerine bak
            if not self._addr_mapper:
                continue

            func_addr = func.address if isinstance(func, _FuncEntry) else (
                _hex_to_int(func.get("address", "0")) if isinstance(func, dict) else 0)

            # Fonksiyon icindeki string referanslarindan type eslestirmesi
            for s in self._strings:
                # String fonksiyon adres araliginda mi?
                if isinstance(func, _FuncEntry):
                    if not (func.address <= s.address < func.end_address):
                        continue
                else:
                    # Dict formatinda size bilgisi olmayabilir
                    continue

                val = s.value.strip()
                # Kaynak koddaki bir type isimiyle birebir eslesiyor mu?
                if val in source_types and val not in seen_matches:
                    seen_matches.add(val)
                    source_info = declarations[val]
                    names.append(ExtractedName(
                        original_name=func_name,
                        recovered_name=_sanitize_identifier(val),
                        source="source_cross_match",
                        confidence=0.92,
                        evidence=f"source match: binary string '{val}' = "
                                 f"{source_info['kind']} in {source_info['file']}",
                        class_name=val,
                        source_file=source_info['file'],
                    ))

        # 2. Binary'de gorunen ama henuz eslesmemis type'lar icin
        # class-method bilgisini kaydet
        for type_name in binary_type_hits:
            if type_name in declarations:
                info = declarations[type_name]
                if info.get("methods"):
                    if not hasattr(self, '_collected_class_methods'):
                        self._collected_class_methods = defaultdict(set)
                    self._collected_class_methods[type_name].update(info["methods"])

        # 3. Struct field name propagation (Gorev 3)
        # Kaynak koddaki property isimleri binary string'lerindeki field isimlerle eslesir
        source_props: dict[str, set[str]] = {}  # type_name -> {prop_names}
        for type_name, info in declarations.items():
            props = info.get("props", set())
            if props:
                source_props[type_name] = props

        # Binary string'lerindeki camelCase identifier'lari topla
        binary_identifiers: set[str] = set()
        for s in self._strings:
            val = s.value.strip()
            if (val and val[0].islower() and val.isidentifier()
                    and not val.startswith('_') and 3 <= len(val) <= 60):
                binary_identifiers.add(val)

        # Kaynak kod property'leriyle binary identifier'larini eslesir
        if not hasattr(self, '_collected_member_vars'):
            self._collected_member_vars = defaultdict(set)

        verified_fields = 0
        for type_name, props in source_props.items():
            for prop in props:
                if prop in binary_identifiers and len(prop) >= 4:
                    self._collected_member_vars[type_name].add(prop)
                    verified_fields += 1

        if verified_fields > 0:
            logger.debug(
                "Source cross-match: %d struct field dogrulandi (%d type'ta)",
                verified_fields, len(self._collected_member_vars),
            )

        # 4. Swift demangle sonuclarindaki isimlerle kaynak kodu dogrulama
        # (Demangle'dan gelen isimleri kaynak kodda teyit et -> confidence artisi)
        for name_entry in names:
            if name_entry.source == "swift_demangle" and name_entry.class_name:
                if name_entry.class_name in source_types:
                    # Kaynak kodda dogrulandi -- confidence bonus
                    name_entry.confidence = min(0.98, name_entry.confidence + 0.03)
                    name_entry.evidence += " [source-verified]"

        logger.debug(
            "Source cross-match: %d type eslesmesi, %d binary type hit, "
            "%d field dogrulandi",
            len(names), len(binary_type_hits), verified_fields,
        )
        return names


# ---------------------------------------------------------------------------
# Convenience API
# ---------------------------------------------------------------------------

def extract_binary_names(
    strings_json: Path,
    functions_json: Path,
    call_graph_json: Path,
    config: Config | None = None,
) -> ExtractionResult:
    """Tek satirlik convenience fonksiyonu.

    Args:
        strings_json: Ghidra string JSON dosyasi.
        functions_json: Ghidra functions JSON dosyasi.
        call_graph_json: Ghidra call graph JSON dosyasi.
        config: Opsiyonel config.

    Returns:
        ExtractionResult.
    """
    extractor = BinaryNameExtractor(config)
    return extractor.extract(strings_json, functions_json, call_graph_json)
