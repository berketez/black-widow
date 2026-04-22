"""C++ RTTI / vtable reconstruction (v1.10.0 M3 T9 + Batch 3E).

Kapsam:
  - Itanium ABI (Linux/macOS g++/clang): single + multi + virtual inheritance,
    diamond pattern (__vmi_class_type_info / __si_class_type_info).
    Sembol pattern: _ZTI<m> (type_info), _ZTV<m> (vtable),
    _ZN<class>E (qualified name).
  - MSVC (Windows C++) RTTI: .?AV<Name>@@ type_info mangling, Complete Object
    Locator (COL), Class Hierarchy Descriptor (CHD), BaseClassDescriptor (BCD),
    x86 + x86_64, template + nested namespace demangling.

Yuksek seviye API:
  - `CppRttiAnalyzer.analyze(binary_path)` -> `CppRttiResult`
       Binary tipini (ELF/Mach-O -> Itanium, PE -> MSVC) otomatik secer.
  - `RTTIParser` (Itanium) ve `MSVCRTTIParser` (MSVC) alt-katman.

NOTE: MSVC x64 RTTI parser is EXPERIMENTAL in v1.10.0 (Batch 6C Codex teyit).
  - object_base field semantics may be pSelf (under review)
  - vftable_addr inference (col_va + ptr_size) is ABI-unsafe for x64
  - Confidence score dusurulmus (0.6 -> 0.4) belirsizlik gostergesi olarak
  See Batch 6A for planned fixes (v1.10.1+).
"""
from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Itanium ABI sabitleri
# ---------------------------------------------------------------------------
_ITANIUM_TYPEINFO_PREFIX = "_ZTI"
_ITANIUM_VTABLE_PREFIX = "_ZTV"
_ITANIUM_MANGLED_PREFIX = "_Z"
_POINTER_SIZE = 8              # x86_64 default
_VTABLE_HEADER_SLOTS = 2       # offset-to-top + typeinfo ptr

# Itanium __vmi_class_type_info flags (libcxxabi / GCC libsupc++)
_VMI_FLAG_NON_DIAMOND_REPEAT = 0x1
_VMI_FLAG_DIAMOND_SHAPED = 0x2

# Itanium __base_class_type_info offset_flags masks
_BASE_FLAG_VIRTUAL = 0x1
_BASE_FLAG_PUBLIC = 0x2
_BASE_OFFSET_SHIFT = 8  # signed >>

# ---------------------------------------------------------------------------
# MSVC RTTI sabitleri
# ---------------------------------------------------------------------------
# COL signature (MSVC ABI)
_MSVC_COL_SIG_X86 = 0
_MSVC_COL_SIG_X64 = 1

# Class Hierarchy Descriptor (CHD) attribute flags
_MSVC_CHD_MULTIPLE_INHERITANCE = 0x00000001
_MSVC_CHD_VIRTUAL_INHERITANCE = 0x00000002
_MSVC_CHD_AMBIGUOUS = 0x00000004

# BaseClassDescriptor (BCD) attribute flags
_MSVC_BCD_NOT_VISIBLE = 0x00000001
_MSVC_BCD_AMBIGUOUS = 0x00000002
_MSVC_BCD_PRIVATE = 0x00000004
_MSVC_BCD_PRIV_ORPROT_BASE = 0x00000008
_MSVC_BCD_VIRTUAL = 0x00000010
_MSVC_BCD_NONPOLYMORPHIC = 0x00000020
_MSVC_BCD_HAS_HIERARCHY_DESCRIPTOR = 0x00000040

# .?AV type_info prefix (class) / .?AU (struct)
_MSVC_TYPEDESC_PREFIX_CLASS = b".?AV"
_MSVC_TYPEDESC_PREFIX_STRUCT = b".?AU"
_MSVC_TYPEDESC_SUFFIX = b"@@"


# ===========================================================================
# Shared dataclasses
# ===========================================================================
@dataclass
class CppClass:
    """Tek bir C++ sinifinin RTTI/vtable bilgisi (Itanium + MSVC ortak)."""

    name: str                                       # demangled, "MyClass"
    mangled_name: str                               # "_ZTI7MyClass" veya ".?AV7MyClass@@"
    typeinfo_addr: str                              # hex
    vtable_addr: str                                # hex
    methods: list[dict[str, Any]] = field(default_factory=list)
    base_classes: list[str] = field(default_factory=list)
    # Zenginlestirilmis base bilgisi (v1.10.0 Batch 3E):
    #   {"name": str, "offset": int, "is_virtual": bool, "is_public": bool}
    bases: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ClassHierarchy:
    """Bir binary'deki tum C++ siniflarinin toplu gorunumu."""

    classes: list[CppClass] = field(default_factory=list)
    address_to_class: dict[str, CppClass] = field(default_factory=dict)

    def get_method_binding(
        self, vtable_addr: str, offset: int,
    ) -> Optional[tuple[str, str]]:
        """vtable[offset] -> (class_name, method_name)."""
        cls = self.address_to_class.get(vtable_addr)
        if cls is None:
            return None
        for m in cls.methods:
            if m.get("offset_in_vtable") == offset:
                return (cls.name, m.get("name", ""))
        return None


@dataclass
class CppRttiResult:
    """Unified RTTI sonucu — Itanium VEYA MSVC."""

    abi: str                                        # "itanium" | "msvc" | "unknown"
    hierarchy: ClassHierarchy = field(default_factory=ClassHierarchy)
    # MSVC'ye ozgu raw COL listesi (debug / ileri analiz)
    msvc_locators: list["MSVCCompleteObjectLocator"] = field(default_factory=list)


# ===========================================================================
# Itanium demangling
# ===========================================================================
def demangle_itanium(mangled: str) -> str:
    """Itanium mangled isim -> demangled. cxxfilt -> c++filt -> original.

    Tek-sembol API'si. Toplu demangle icin `batch_demangle(names)` kullanin
    (c++filt process'ini tek kez spawn eder).
    """
    if not mangled:
        return mangled
    # Mach-O "__Z..." -> "_Z..."
    candidate = mangled[1:] if mangled.startswith("__Z") else mangled
    try:
        import cxxfilt  # type: ignore
        try:
            return cxxfilt.demangle(candidate)
        except cxxfilt.InvalidName:
            return mangled
    except ImportError:
        logger.debug("cxxfilt yok, c++filt fallback")
    try:
        # '--' separator: candidate "--" ile baslarsa bile flag olarak yorumlanmaz
        result = subprocess.run(
            ["c++filt", "--", candidate],
            capture_output=True, text=True, timeout=5.0,
        )
        if result.returncode == 0:
            demangled = result.stdout.strip()
            return demangled if demangled else mangled
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("c++filt fallback basarisiz: %s", exc)
    return mangled


def batch_demangle(names: list[str]) -> dict[str, str]:
    """Toplu Itanium demangle (v1.10.0 H9)."""
    if not names:
        return {}
    unique: list[str] = []
    seen: set[str] = set()
    for n in names:
        if n and n not in seen:
            seen.add(n)
            unique.append(n)
    candidates = [
        (orig, orig[1:] if orig.startswith("__Z") else orig)
        for orig in unique
    ]
    try:
        import cxxfilt  # type: ignore
        out: dict[str, str] = {}
        for orig, cand in candidates:
            try:
                out[orig] = cxxfilt.demangle(cand)
            except cxxfilt.InvalidName:
                out[orig] = orig
        return out
    except ImportError:
        pass

    def _sanitize(sym: str) -> str:
        return "".join(ch for ch in sym if ch.isprintable() and ch not in ("\r", "\n"))

    try:
        input_text = "\n".join(_sanitize(cand) for _, cand in candidates) + "\n"
        result = subprocess.run(
            ["c++filt"],
            input=input_text,
            capture_output=True,
            text=True,
            timeout=30.0,
            shell=False,
        )
        if result.returncode == 0:
            lines = result.stdout.splitlines()
            out2: dict[str, str] = {}
            for i, (orig, _cand) in enumerate(candidates):
                if i < len(lines):
                    dem = lines[i].strip()
                    out2[orig] = dem if dem else orig
                else:
                    out2[orig] = orig
            return out2
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("batch c++filt basarisiz: %s", exc)
    return {orig: orig for orig in unique}


def _strip_macho_underscore(sym: str) -> str:
    """Mach-O '_' prefix'ini kaldirir (ELF icin no-op)."""
    return sym[1:] if sym.startswith("__Z") else sym


def _class_name_from_typeinfo(
    ti_sym: str,
    demangled_cache: Optional[dict[str, str]] = None,
) -> str:
    """_ZTI<mangled> -> demangled sinif ismi."""
    if demangled_cache is not None and ti_sym in demangled_cache:
        demangled = demangled_cache[ti_sym]
    else:
        demangled = demangle_itanium(ti_sym)
    if demangled.startswith("typeinfo for "):
        return demangled[len("typeinfo for "):].strip()
    stripped = _strip_macho_underscore(ti_sym)
    if stripped.startswith(_ITANIUM_TYPEINFO_PREFIX):
        return stripped[len(_ITANIUM_TYPEINFO_PREFIX):]
    return demangled


def _method_name_from_mangled(
    sym: str,
    demangled_cache: Optional[dict[str, str]] = None,
) -> str:
    """Metod mangled -> demangled okunabilir isim."""
    if demangled_cache is not None and sym in demangled_cache:
        demangled = demangled_cache[sym]
    else:
        demangled = demangle_itanium(sym)
    return demangled if demangled != sym else _strip_macho_underscore(sym)


# ===========================================================================
# MSVC demangling (basit kurallarla, subprocess fallback yok — cxxfilt
# UndName'i tasimiyor; ileride opsiyonel `undname.exe`/`llvm-undname` fallback
# eklenebilir, ama bu modul sadece `.?AV...@@` format'ini decode eder).
# ===========================================================================
def demangle_msvc(name: str) -> str:
    """MSVC type_info mangled ismi demangle eder.

    Ornek dönüsümler:
      ".?AVMyClass@@"                  -> "class MyClass"
      ".?AUMyStruct@@"                 -> "struct MyStruct"
      ".?AVNested@Outer@@"             -> "class Outer::Nested"
      ".?AV?$Template@H@@"             -> "class Template<int>"  (primitive)
      ".?AV?$Vector@VMyClass@@@@"      -> "class Vector<class MyClass>"
      ".?AVMyClass@NS@@"               -> "class NS::MyClass"
      ".?AVA@B@C@@"                    -> "class C::B::A"

    Tam Microsoft Undname uygulamasi degil; yaygin pattern'leri cozer. Karmasik
    durumlarda (function signature icerikli mangling) input'u oldugu gibi
    dondurur. Cagiran tarafin fallback stratejisi (llvm-undname subprocess)
    uygulamasi opsiyonel.
    """
    if not name:
        return name
    # Byte input -> str (bazi call-site'lardan bytes gelebiliyor)
    if isinstance(name, (bytes, bytearray)):
        try:
            name = name.decode("ascii", errors="replace")
        except Exception:
            return str(name)

    orig = name
    # Mach-O benzeri leading dot optional; bizde ".?AV" / ".?AU" bekliyoruz
    if name.startswith(".?AV"):
        kind = "class"
        body = name[4:]
    elif name.startswith(".?AU"):
        kind = "struct"
        body = name[4:]
    elif name.startswith("?AV"):
        kind = "class"
        body = name[3:]
    elif name.startswith("?AU"):
        kind = "struct"
        body = name[3:]
    else:
        return orig

    if not body:
        return orig

    # Trailing "@@" terminator'i korunarak decode; _msvc_decode_name icerideki
    # "@@" seperator'unu template arg terminator'u olarak yorumlar. Non-template
    # durumda body "Name@@" seklinde (son @@ = class adi terminator).
    demangled = _msvc_decode_name(body)
    if demangled is None:
        return orig
    return f"{kind} {demangled}"


def _msvc_decode_name(body: str) -> Optional[str]:
    """Inner name decoder. Namespace @ separatorlu listeyi isler.

    Body trailing "@@" terminator'i koruyarak gelir. Non-template durumunda
    segmentler "@" ile ayrilir ve son "@@" terminator'dur. Template durumunda
    icerideki "@@" template arg list sonunu isaretler.

    Ornekler (body):
      "MyClass@@"                       -> "MyClass"
      "Inner@Outer@@"                   -> "Outer::Inner"
      "?$Tpl@H@@"                       -> "Tpl<int>"
      "?$Tpl@VInner@@@@"                -> "Tpl<class Inner>"
      "?$Tpl@H@NS@@"                    -> "NS::Tpl<int>"
    """
    if not body:
        return None

    # Template: body "?$<TemplateName>@<args>@@<namespace...>@@"
    if body.startswith("?$"):
        rest = body[2:]
        at_idx = rest.find("@")
        if at_idx < 0:
            return None
        tpl_name = rest[:at_idx]
        args_part = rest[at_idx + 1:]
        args_list, remainder = _msvc_parse_template_args(args_part)
        if args_list is None:
            return None
        inner = f"{tpl_name}<{', '.join(args_list)}>"
        # remainder: trailing "@@" terminator'i strip
        remainder = remainder.rstrip("@")
        if not remainder:
            return inner
        ns_parts = [p for p in remainder.split("@") if p]
        ns_parts.reverse()
        return "::".join(ns_parts + [inner])

    # Non-template: sondaki "@@" terminator, trailing @ strip
    trimmed = body.rstrip("@")
    parts = [p for p in trimmed.split("@") if p]
    if not parts:
        return None
    parts.reverse()
    return "::".join(parts)


_MSVC_PRIMITIVE_CODES = {
    "X": "void",
    "D": "char",
    "C": "signed char",
    "E": "unsigned char",
    "F": "short",
    "G": "unsigned short",
    "H": "int",
    "I": "unsigned int",
    "J": "long",
    "K": "unsigned long",
    "M": "float",
    "N": "double",
    "_N": "bool",
    "_J": "int64_t",
    "_K": "uint64_t",
    "_W": "wchar_t",
}


def _msvc_parse_template_args(s: str) -> tuple[Optional[list[str]], str]:
    """Basit template-arg parser.

    MSVC mangling kuralları:
    - Primitive tip kodları (H=int, D=char, vb.) tek karakter; arkalarına
      ayraç gelmez — bir sonraki karakter doğrudan sonraki argümandır.
    - V/U nested class/struct argümanları kendi "@@" terminator'ına sahip.
    - Template argüman listesi, tek `@` ile kapanır (outer name'e geri döner).

    Ornekler:
      "H@@"         -> (["int"], "")            # H arg, @ term, @ class term
      "VInner@@@@"  -> (["class Inner"], "@")   # VInner@@ arg, @ term, @@ cls
      "H@NS@@"      -> (["int"], "NS@@")        # H arg, @ term, "NS@@" remain
    """
    args: list[str] = []
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        # Template arg listesi bitis: tek '@'
        if ch == "@":
            # Bu noktada kalan string remainder (namespace veya class terminator)
            return args, s[i + 1:]

        if ch == "V" or ch == "U":
            # Nested class/struct: V<Name>@@
            kind = "class" if ch == "V" else "struct"
            i += 1
            end = s.find("@@", i)
            if end < 0:
                return None, ""
            inner = s[i:end]
            inner_parts = [p for p in inner.split("@") if p]
            inner_parts.reverse()
            args.append(f"{kind} {'::'.join(inner_parts)}")
            i = end + 2
            continue
        if ch == "_" and i + 1 < n:
            code = s[i:i + 2]
            if code in _MSVC_PRIMITIVE_CODES:
                args.append(_MSVC_PRIMITIVE_CODES[code])
                i += 2
                continue
        if ch in _MSVC_PRIMITIVE_CODES:
            args.append(_MSVC_PRIMITIVE_CODES[ch])
            i += 1
            continue
        return None, ""
    return None, ""


# ===========================================================================
# Itanium vtable reader (ortak)
# ===========================================================================
def read_vtable_entries(
    binary: Any,
    vtable_addr: int,
    count: int,
    pointer_size: int = _POINTER_SIZE,
) -> list[int]:
    """vtable'in ilk `count` entry'sini little-endian pointer olarak okur.

    PERF (v1.10.0 C2): section.content uzerinde `memoryview` kullanilir.
    """
    if count <= 0:
        return []
    try:
        section = binary.section_from_virtual_address(vtable_addr)
    except Exception as exc:
        logger.debug("section_from_virtual_address hata: %s", exc)
        return []
    if section is None:
        return []
    try:
        raw = section.content
        try:
            view = memoryview(raw)
        except TypeError:
            view = memoryview(bytes(raw))
        section_va = int(section.virtual_address)
    except Exception as exc:
        logger.debug("section.content okunamadi: %s", exc)
        return []
    offset = vtable_addr - section_va
    if offset < 0 or offset >= len(view):
        return []
    entries: list[int] = []
    end_total = min(offset + count * pointer_size, len(view))
    slice_view = view[offset:end_total]
    pos = 0
    slen = len(slice_view)
    for _ in range(count):
        end = pos + pointer_size
        if end > slen:
            break
        entries.append(
            int.from_bytes(bytes(slice_view[pos:end]), "little", signed=False)
        )
        pos = end
    return entries


# ===========================================================================
# Itanium: __vmi_class_type_info parser (multi/virtual inheritance)
# ===========================================================================
@dataclass
class ItaniumBaseInfo:
    """__vmi_class_type_info base[] entry."""

    base_typeinfo_name: str        # mangled ya da demangled class ismi
    offset: int                    # offset (virtual ise vbase index * ptr_size)
    is_virtual: bool
    is_public: bool


@dataclass
class ItaniumClassTypeInfo:
    """Itanium __class_type_info / __si_class_type_info / __vmi_class_type_info."""

    kind: str                      # "none" | "single" | "vmi"
    class_name: str
    flags: int = 0                 # vmi flags
    bases: list[ItaniumBaseInfo] = field(default_factory=list)


def parse_itanium_vmi_bytes(
    raw: bytes,
    symbols_by_addr: dict[int, str],
    pointer_size: int = _POINTER_SIZE,
) -> Optional[ItaniumClassTypeInfo]:
    """__vmi_class_type_info struct'ini parse eder.

    Layout (Itanium C++ ABI §2.9.5):
      vtable_ptr (ptr)
      name_ptr   (ptr) -> "NxClass" (external type_info string)
      flags      (u32)
      base_count (u32)
      base_info[base_count]:
        base_type  (ptr) -> typeinfo pointer
        offset_flags (ptrdiff_t = ptr_size)

    Not: Bu fonksiyon __vmi icin `flags` + `base_count` word'lerini 4-byte int
    olarak okur; ortak layout soyle:
      [ptr, ptr, u32 flags, u32 base_count, base_info...]
    """
    if pointer_size not in (4, 8):
        return None
    hdr = 2 * pointer_size + 8  # 2 ptr + 2 * u32
    if len(raw) < hdr:
        return None
    # Flags + base_count 4-byte little endian
    flags = int.from_bytes(raw[2 * pointer_size:2 * pointer_size + 4], "little", signed=False)
    base_count = int.from_bytes(raw[2 * pointer_size + 4:hdr], "little", signed=False)
    if base_count > 64 or base_count == 0:
        # sanite: absurd base_count red
        return None
    expected = hdr + base_count * (pointer_size * 2)
    if len(raw) < expected:
        return None
    bases: list[ItaniumBaseInfo] = []
    cursor = hdr
    for _ in range(base_count):
        base_ptr = int.from_bytes(
            raw[cursor:cursor + pointer_size], "little", signed=False,
        )
        cursor += pointer_size
        offset_flags = int.from_bytes(
            raw[cursor:cursor + pointer_size], "little", signed=True,
        )
        cursor += pointer_size
        is_virtual = bool(offset_flags & _BASE_FLAG_VIRTUAL)
        is_public = bool(offset_flags & _BASE_FLAG_PUBLIC)
        offset = offset_flags >> _BASE_OFFSET_SHIFT
        base_name = symbols_by_addr.get(base_ptr, f"sub_{base_ptr:x}")
        # _ZTI prefix varsa sil
        if base_name.startswith(_ITANIUM_TYPEINFO_PREFIX):
            base_name = base_name[len(_ITANIUM_TYPEINFO_PREFIX):]
        elif base_name.startswith("__ZTI"):
            base_name = base_name[len("__ZTI"):]
        bases.append(
            ItaniumBaseInfo(
                base_typeinfo_name=base_name,
                offset=offset,
                is_virtual=is_virtual,
                is_public=is_public,
            )
        )
    return ItaniumClassTypeInfo(
        kind="vmi",
        class_name="",   # caller fills
        flags=flags,
        bases=bases,
    )


def parse_itanium_si_bytes(
    raw: bytes,
    symbols_by_addr: dict[int, str],
    pointer_size: int = _POINTER_SIZE,
) -> Optional[ItaniumClassTypeInfo]:
    """__si_class_type_info: tek base, non-virtual, public, offset=0.

    Layout:
      vtable_ptr (ptr)
      name_ptr   (ptr)
      base_type  (ptr) -> typeinfo
    """
    hdr = 3 * pointer_size
    if len(raw) < hdr:
        return None
    base_ptr = int.from_bytes(
        raw[2 * pointer_size:3 * pointer_size], "little", signed=False,
    )
    if base_ptr == 0:
        return None
    base_name = symbols_by_addr.get(base_ptr, f"sub_{base_ptr:x}")
    if base_name.startswith(_ITANIUM_TYPEINFO_PREFIX):
        base_name = base_name[len(_ITANIUM_TYPEINFO_PREFIX):]
    elif base_name.startswith("__ZTI"):
        base_name = base_name[len("__ZTI"):]
    return ItaniumClassTypeInfo(
        kind="single",
        class_name="",
        flags=0,
        bases=[
            ItaniumBaseInfo(
                base_typeinfo_name=base_name,
                offset=0,
                is_virtual=False,
                is_public=True,
            ),
        ],
    )


# ===========================================================================
# Itanium RTTI Parser (enhanced: multi/virtual inheritance)
# ===========================================================================
class RTTIParser:
    """Itanium ABI RTTI parser."""

    def __init__(self, config: Any = None) -> None:
        self.config = config
        self._max_entries = int(
            getattr(config, "rtti_max_vtable_entries", 64) if config else 64,
        )

    def _load_binary(self, binary_path: Path) -> Any:
        """lief.Binary objesi dondur (yoksa None)."""
        try:
            import lief  # type: ignore
        except ImportError:
            logger.warning("lief kurulu degil, RTTI parse atlanacak")
            return None
        try:
            return lief.parse(str(binary_path))
        except Exception as exc:
            logger.warning("lief parse hatasi: %s", exc)
            return None

    def _load_symbols(self, binary_path: Path) -> dict[str, int]:
        """Binary sembollerinden Itanium mangled olanlari dict olarak dondur."""
        binary = self._load_binary(binary_path)
        if binary is None:
            return {}
        symbols: dict[str, int] = {}
        try:
            for s in binary.symbols:
                name = getattr(s, "name", None)
                if not name:
                    continue
                if name.startswith(_ITANIUM_MANGLED_PREFIX) or name.startswith("__Z"):
                    try:
                        symbols[name] = int(s.value)
                    except (TypeError, ValueError):
                        continue
        except Exception as exc:
            logger.debug("sembol iterasyon hatasi: %s", exc)
        return symbols

    def _read_bytes_at_va(
        self, binary: Any, addr: int, count: int,
    ) -> Optional[bytes]:
        """Binary section'dan VA'da `count` byte okur."""
        if binary is None or count <= 0:
            return None
        try:
            section = binary.section_from_virtual_address(addr)
        except Exception:
            return None
        if section is None:
            return None
        try:
            raw = section.content
            try:
                view = memoryview(raw)
            except TypeError:
                view = memoryview(bytes(raw))
            section_va = int(section.virtual_address)
        except Exception:
            return None
        offset = addr - section_va
        if offset < 0 or offset + count > len(view):
            return None
        return bytes(view[offset:offset + count])

    def _parse_base_classes(
        self,
        binary: Any,
        typeinfo_addr: int,
        symbols_by_addr: dict[int, str],
        pointer_size: int,
    ) -> list[ItaniumBaseInfo]:
        """Bir typeinfo adresinden __si_/__vmi_ variant'ini tespit edip
        base class listesini dondurur."""
        # vtable_ptr'yi oku, hangi type_info variant oldugunu belirlemek icin
        # libstdc++ __cxxabiv1::__si_class_type_info vs __vmi_class_type_info
        # vtable ismini symbol tablo ile karsilastiracagiz.
        header = self._read_bytes_at_va(binary, typeinfo_addr, 2 * pointer_size)
        if header is None:
            return []
        vtable_ptr = int.from_bytes(header[:pointer_size], "little", signed=False)
        # vtable ptr +16/+8 offset typeinfo vtable content'a point eder.
        # Sembol adini suanki adres yerine yakininda ara (4 ptr-size geriye).
        candidate_ptrs = [
            vtable_ptr,
            vtable_ptr - pointer_size,
            vtable_ptr - 2 * pointer_size,
        ]
        ti_variant = "none"
        for cand in candidate_ptrs:
            sym = symbols_by_addr.get(cand, "")
            if "vmi_class_type_info" in sym:
                ti_variant = "vmi"
                break
            if "si_class_type_info" in sym:
                ti_variant = "single"
                break
            if "class_type_info" in sym:
                ti_variant = "none"
                break
        # Variant'a gore gerekli byte sayisi
        if ti_variant == "single":
            needed = 3 * pointer_size
            raw = self._read_bytes_at_va(binary, typeinfo_addr, needed)
            if raw is None:
                return []
            info = parse_itanium_si_bytes(raw, symbols_by_addr, pointer_size)
        elif ti_variant == "vmi":
            # Header'i oku ve base_count'a gore yeniden oku (adaptif)
            hdr_size = 2 * pointer_size + 8
            hdr_bytes = self._read_bytes_at_va(binary, typeinfo_addr, hdr_size)
            if hdr_bytes is None:
                return []
            base_count = int.from_bytes(
                hdr_bytes[2 * pointer_size + 4:hdr_size], "little", signed=False,
            )
            if base_count == 0 or base_count > 64:
                return []
            total = hdr_size + base_count * pointer_size * 2
            raw = self._read_bytes_at_va(binary, typeinfo_addr, total)
            if raw is None:
                return []
            info = parse_itanium_vmi_bytes(raw, symbols_by_addr, pointer_size)
        else:
            return []
        if info is None:
            return []
        return info.bases

    def parse_itanium(
        self,
        binary_path: Path,
        symbols: Optional[dict[str, int]] = None,
        binary: Any = None,
    ) -> ClassHierarchy:
        """Itanium ABI RTTI/vtable parse -> ClassHierarchy."""
        if symbols is None:
            symbols = self._load_symbols(binary_path)
        if not symbols:
            logger.info("Itanium RTTI sembolu yok: %s", binary_path)
            return ClassHierarchy()
        if binary is None:
            binary = self._load_binary(binary_path)

        typeinfos: dict[str, int] = {}
        vtables: dict[str, int] = {}
        for name, addr in symbols.items():
            bare = _strip_macho_underscore(name)
            if bare.startswith(_ITANIUM_TYPEINFO_PREFIX):
                typeinfos[bare] = addr
            elif bare.startswith(_ITANIUM_VTABLE_PREFIX):
                vtables[bare] = addr

        hierarchy = ClassHierarchy()
        reconstructor = VTableReconstructor(self.config)
        va_to_sym: dict[int, str] = {}
        for sym_name, sym_va in symbols.items():
            if sym_va not in va_to_sym:
                va_to_sym[sym_va] = sym_name
        demangle_inputs = list(typeinfos.keys()) + list(symbols.keys())
        demangled_cache = batch_demangle(demangle_inputs)
        for ti_name, ti_addr in typeinfos.items():
            class_mangled = ti_name[len(_ITANIUM_TYPEINFO_PREFIX):]
            vtable_sym = _ITANIUM_VTABLE_PREFIX + class_mangled
            vtable_addr = vtables.get(vtable_sym)
            cls = CppClass(
                name=_class_name_from_typeinfo(ti_name, demangled_cache),
                mangled_name=ti_name,
                typeinfo_addr=f"0x{ti_addr:x}",
                vtable_addr=f"0x{vtable_addr:x}" if vtable_addr else "",
            )
            # Base class recovery (multi/virtual inheritance)
            if binary is not None:
                try:
                    base_infos = self._parse_base_classes(
                        binary, ti_addr, va_to_sym, _POINTER_SIZE,
                    )
                    for bi in base_infos:
                        demangled_base = _class_name_from_typeinfo(
                            _ITANIUM_TYPEINFO_PREFIX + bi.base_typeinfo_name,
                            demangled_cache,
                        )
                        cls.base_classes.append(demangled_base)
                        cls.bases.append({
                            "name": demangled_base,
                            "offset": bi.offset,
                            "is_virtual": bi.is_virtual,
                            "is_public": bi.is_public,
                        })
                except Exception as exc:
                    logger.debug(
                        "base class parse hatasi (%s): %s", ti_name, exc,
                    )
            if vtable_addr and binary is not None:
                try:
                    method_map = reconstructor.build(
                        cls, binary, symbols, va_to_sym=va_to_sym,
                    )
                    cls.methods = reconstructor.format_methods(
                        method_map, demangled_cache=demangled_cache,
                    )
                except Exception as exc:
                    logger.debug("vtable reconstruct hata (%s): %s", ti_name, exc)
            hierarchy.classes.append(cls)
            if cls.vtable_addr:
                hierarchy.address_to_class[cls.vtable_addr] = cls
        logger.info(
            "Itanium RTTI: %d sinif, %d vtable",
            len(hierarchy.classes),
            sum(1 for c in hierarchy.classes if c.vtable_addr),
        )
        return hierarchy


class VTableReconstructor:
    """Vtable layout -> method slot -> sembol isim mapping."""

    def __init__(self, config: Any = None) -> None:
        self.config = config
        self._max_entries = int(
            getattr(config, "rtti_max_vtable_entries", 64) if config else 64,
        )

    def build(
        self,
        cls: CppClass,
        binary: Any,
        symbols: dict[str, int],
        va_to_sym: Optional[dict[int, str]] = None,
    ) -> dict[int, str]:
        if not cls.vtable_addr or binary is None:
            return {}
        try:
            vtable_va = int(cls.vtable_addr, 16)
        except ValueError:
            return {}
        entries = read_vtable_entries(
            binary, vtable_va, self._max_entries + _VTABLE_HEADER_SLOTS,
        )
        if len(entries) <= _VTABLE_HEADER_SLOTS:
            return {}
        if va_to_sym is None:
            va_to_sym = {}
            for sym_name, sym_va in symbols.items():
                if sym_va not in va_to_sym:
                    va_to_sym[sym_va] = sym_name
        method_map: dict[int, str] = {}
        for idx, entry in enumerate(entries[_VTABLE_HEADER_SLOTS:]):
            if entry == 0:
                break
            sym = va_to_sym.get(entry)
            method_map[entry] = sym if sym else f"sub_{entry:x}"
            if idx + 1 >= self._max_entries:
                break
        return method_map

    def format_methods(
        self,
        method_map: dict[int, str],
        demangled_cache: Optional[dict[str, str]] = None,
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for offset, (addr, sym) in enumerate(method_map.items()):
            out.append({
                "name": _method_name_from_mangled(sym, demangled_cache),
                "mangled": sym,
                "addr": f"0x{addr:x}",
                "offset_in_vtable": offset,
            })
        return out


# ===========================================================================
# MSVC RTTI dataclass'lari
# ===========================================================================
@dataclass
class MSVCTypeDescriptor:
    """MSVC TypeDescriptor (type_info).

    Layout (x86):
      vftable_ptr    (4B) -> type_info::`vftable'
      spare          (4B) -> runtime'da doldurulur, genelde 0
      name           (0-terminated ASCII) -> ".?AVClassName@@"
    Layout (x64):
      vftable_ptr    (8B)
      spare          (8B)
      name           (0-terminated ASCII)
    """

    addr: int                      # VA
    vftable_ptr: int
    spare: int
    name: str                      # ".?AVClassName@@"
    demangled: str = ""            # "class ClassName"


@dataclass
class MSVCBaseClassDescriptor:
    """MSVC BaseClassDescriptor (BCD).

    Layout (8 * 4 = 32 byte, image-base-relative pointers x64; absolute x86):
      pTypeDescriptor       (4B x86 VA / 4B x64 RVA)
      numContainedBases     (u32)
      where_mdisp           (u32) -- PMD::mdisp (member displacement)
      where_pdisp           (i32) -- PMD::pdisp (vbtable displacement, -1 yoksa)
      where_vdisp           (u32) -- PMD::vdisp (vbtable displacement offset)
      attributes            (u32) -- BCD flags
      pClassHierarchyDescriptor (4B) -- opsiyonel (HAS_HIERARCHY_DESCRIPTOR flag)
    """

    addr: int
    type_descriptor: int           # RVA veya VA
    num_contained_bases: int
    pmd_mdisp: int                 # member displacement
    pmd_pdisp: int                 # vbtable displacement (-1 = no vbtable)
    pmd_vdisp: int                 # vbtable offset
    attributes: int                # BCD flags
    class_hierarchy: int = 0       # RVA/VA CHD
    # Resolved (caller doldurur)
    type_name: str = ""            # "class MyClass"

    @property
    def is_virtual(self) -> bool:
        return bool(self.attributes & _MSVC_BCD_VIRTUAL)

    @property
    def is_public(self) -> bool:
        return not (self.attributes & (_MSVC_BCD_PRIVATE | _MSVC_BCD_PRIV_ORPROT_BASE))


@dataclass
class MSVCClassHierarchyDescriptor:
    """MSVC ClassHierarchyDescriptor (CHD).

    Layout (16 byte):
      signature          (u32) -- genelde 0
      attributes         (u32) -- CHD flags (MULTIPLE/VIRTUAL/AMBIGUOUS)
      numBaseClasses     (u32)
      pBaseClassArray    (4B RVA x64 / 4B VA x86) -> RTTIBaseClassArray
    """

    addr: int
    signature: int
    attributes: int
    num_base_classes: int
    base_class_array: int           # RVA/VA
    base_descriptors: list[MSVCBaseClassDescriptor] = field(default_factory=list)

    @property
    def has_multiple_inheritance(self) -> bool:
        return bool(self.attributes & _MSVC_CHD_MULTIPLE_INHERITANCE)

    @property
    def has_virtual_inheritance(self) -> bool:
        return bool(self.attributes & _MSVC_CHD_VIRTUAL_INHERITANCE)


@dataclass
class MSVCCompleteObjectLocator:
    """MSVC Complete Object Locator (COL).

    Layout x86 (20 byte):
      signature              (u32) -- 0
      offset                 (u32) -- subobject offset
      cdOffset               (u32) -- constructor displacement
      pTypeDescriptor        (u32) -- VA
      pClassDescriptor       (u32) -- VA -> CHD
    Layout x64 (24 byte):
      signature              (u32) -- 1
      offset                 (u32)
      cdOffset               (u32)
      pTypeDescriptor        (u32 RVA)
      pClassDescriptor       (u32 RVA)
      pSelf                  (u32 RVA) -- COL'un kendi RVA'si (pSelf semantik).
                                          image_base cross-check:
                                          image_base = col.addr - pSelf.

    v1.10.0 Batch 6A (Codex audit): Field ismi ``object_base`` oldugu
    icin backward-compat korundu; fakat semantik olarak MSVC bu alani
    ``pSelf`` olarak anlar (COL kendi RVA'si, NOT "base object"). ``pSelf``
    property alias asagida, yeni kod bu ismi kullanmali.

    ``vftable_addr`` hesabi (col.addr + pointer_size) ABI-unsafe:
    MSVC linker vftable'i COL'a bitisik koymayabilir. ``vftable_confidence``
    alani hesaplamanin ne kadar guvenilir oldugunu raporlar (0.5 = fallback,
    1.0 = xref dogrulandi).
    """

    addr: int                          # COL kendisinin VA'si
    signature: int                     # 0 x86, 1 x64
    offset: int                        # subobject offset
    cd_offset: int
    type_descriptor: int               # VA (x86) veya RVA (x64)
    class_hierarchy: int               # VA (x86) veya RVA (x64)
    object_base: int = 0               # x64 only; SEMANTIK: pSelf (COL RVA)
    # Resolved
    type_desc_obj: Optional[MSVCTypeDescriptor] = None
    chd_obj: Optional[MSVCClassHierarchyDescriptor] = None
    vftable_addr: int = 0              # vftable baslangici (COL'dan +ptr_size fallback)
    # v1.10.0 Batch 6A: vftable kesinlik derecesi. 1.0 = xref dogrulandi,
    # 0.5 = col+ptr_size fallback (ABI guvenilmez ama pratik). Raporda
    # dusuk confidence uyari tetikler.
    vftable_confidence: float = 0.5
    # v1.10.0 Batch 6A: image_base cross-check sonucu. True = pSelf'ten
    # hesaplanan image_base loader-reported ile tutarli; False = uyumsuz
    # (COL yanlis classification olabilir).
    image_base_validated: bool = False

    @property
    def pSelf(self) -> int:
        """Batch 6A: MSVC ``pSelf`` semantik alias. ``object_base`` ismi
        yaniltici olduğu için yeni kodda ``pSelf`` tercih edilir.
        """
        return self.object_base

    @pSelf.setter
    def pSelf(self, value: int) -> None:
        self.object_base = int(value)


# ===========================================================================
# MSVC RTTI Parser
# ===========================================================================
class MSVCRTTIParser:
    """MSVC (Windows C++) RTTI parser.

    Strateji:
      1. `.rdata` section'inda `.?AV` / `.?AU` tipindeki type_info stringlerini
         scan et.
      2. Her type_info icin vftable_ptr + spare offset'ten TypeDescriptor VA'si
         hesapla.
      3. `.rdata` scan ile COL aday'larini bul (signature + typedesc pointer
         eslesmesi).
      4. COL'dan CHD'yi cozup base class array'i decode et.
      5. COL adresinden +pointer_size, vftable baslangicidir.
    """

    def __init__(self, config: Any = None) -> None:
        self.config = config
        self._max_entries = int(
            getattr(config, "rtti_max_vtable_entries", 64) if config else 64,
        )

    # ---- binary loading
    def _load_binary(self, binary_path: Path) -> Any:
        try:
            import lief  # type: ignore
        except ImportError:
            logger.warning("lief kurulu degil, MSVC RTTI parse atlanacak")
            return None
        try:
            return lief.parse(str(binary_path))
        except Exception as exc:
            logger.warning("lief parse hatasi: %s", exc)
            return None

    # ---- section helpers
    def _section_bytes(self, binary: Any, name: str) -> tuple[Optional[bytes], int]:
        """Isimle section icerigini oku; (content, virtual_address)."""
        try:
            for section in binary.sections:
                sname = getattr(section, "name", "")
                if isinstance(sname, bytes):
                    try:
                        sname = sname.decode("ascii", errors="replace")
                    except Exception:
                        sname = ""
                if sname == name:
                    raw = section.content
                    try:
                        data = bytes(raw)
                    except Exception:
                        data = b""
                    return data, int(section.virtual_address)
        except Exception as exc:
            logger.debug("section iterasyon hatasi: %s", exc)
        return None, 0

    def _read_at_va(
        self, binary: Any, va: int, count: int,
    ) -> Optional[bytes]:
        try:
            sec = binary.section_from_virtual_address(va)
        except Exception:
            return None
        if sec is None:
            return None
        try:
            data = bytes(sec.content)
            sec_va = int(sec.virtual_address)
        except Exception:
            return None
        off = va - sec_va
        if off < 0 or off + count > len(data):
            return None
        return data[off:off + count]

    # ---- image base
    def _image_base(self, binary: Any) -> int:
        for attr in ("imagebase", "optional_header"):
            try:
                if attr == "imagebase":
                    return int(getattr(binary, attr, 0))
                opt = getattr(binary, attr, None)
                if opt is not None:
                    return int(getattr(opt, "imagebase", 0))
            except Exception:
                continue
        return 0

    # ---- type descriptor scan
    def scan_type_descriptors(
        self,
        binary: Any,
        image_base: int,
        pointer_size: int = 8,
    ) -> dict[int, MSVCTypeDescriptor]:
        """`.rdata` icinden .?AV / .?AU stringlerini bulup TypeDescriptor'lari
        insa eder. TypeDescriptor VA'si name stringinden `2 * pointer_size`
        kadar geridedir.

        Returns:
            {type_descriptor_va: MSVCTypeDescriptor}
        """
        rdata, rdata_va = self._section_bytes(binary, ".rdata")
        if not rdata:
            # fallback: __data / .data
            for alt in (".data", "__data"):
                rdata, rdata_va = self._section_bytes(binary, alt)
                if rdata:
                    break
        if not rdata:
            return {}
        descriptors: dict[int, MSVCTypeDescriptor] = {}
        patterns = [_MSVC_TYPEDESC_PREFIX_CLASS, _MSVC_TYPEDESC_PREFIX_STRUCT]
        for pattern in patterns:
            start = 0
            while True:
                idx = rdata.find(pattern, start)
                if idx < 0:
                    break
                # null-terminator ara
                end = rdata.find(b"\x00", idx)
                if end < 0:
                    break
                raw_name = rdata[idx:end]
                # @@ ile bitmeli; sag tarafta mutlaka @@ olmali (aksi halde
                # daha uzun bir type ismi olabilir — @@ bulana kadar ilerle).
                if _MSVC_TYPEDESC_SUFFIX not in raw_name:
                    start = idx + 1
                    continue
                name_str = raw_name.decode("ascii", errors="replace")
                # TypeDescriptor baslangici: name stringinden 2*ptr geri
                name_va = rdata_va + idx
                td_va = name_va - 2 * pointer_size
                # header oku
                hdr = self._read_at_va(binary, td_va, 2 * pointer_size)
                if hdr is None:
                    start = end + 1
                    continue
                vftable_ptr = int.from_bytes(
                    hdr[:pointer_size], "little", signed=False,
                )
                spare = int.from_bytes(
                    hdr[pointer_size:2 * pointer_size], "little", signed=False,
                )
                descriptors[td_va] = MSVCTypeDescriptor(
                    addr=td_va,
                    vftable_ptr=vftable_ptr,
                    spare=spare,
                    name=name_str,
                    demangled=demangle_msvc(name_str),
                )
                start = end + 1
        return descriptors

    # ---- COL scan
    def scan_complete_object_locators(
        self,
        binary: Any,
        type_descriptors: dict[int, MSVCTypeDescriptor],
        image_base: int,
        pointer_size: int = 8,
    ) -> list[MSVCCompleteObjectLocator]:
        """`.rdata` icinde COL aday'larini scan eder.

        COL x64 icin signature=1, pTypeDescriptor RVA'si type_descriptors
        setindeki bir VA'ya denk gelmeli. x86 icin signature=0 ve absolute VA.
        """
        rdata, rdata_va = self._section_bytes(binary, ".rdata")
        if not rdata:
            return []
        out: list[MSVCCompleteObjectLocator] = []
        col_size = 24 if pointer_size == 8 else 20
        td_vas = set(type_descriptors.keys())
        # 4-byte aligned tara
        for off in range(0, len(rdata) - col_size + 1, 4):
            sig_bytes = rdata[off:off + 4]
            sig = int.from_bytes(sig_bytes, "little", signed=False)
            if pointer_size == 8 and sig != _MSVC_COL_SIG_X64:
                continue
            if pointer_size == 4 and sig != _MSVC_COL_SIG_X86:
                continue
            blob = rdata[off:off + col_size]
            offset_val = int.from_bytes(blob[4:8], "little", signed=False)
            cd_offset = int.from_bytes(blob[8:12], "little", signed=False)
            td_ptr = int.from_bytes(blob[12:16], "little", signed=False)
            chd_ptr = int.from_bytes(blob[16:20], "little", signed=False)
            object_base = 0
            if pointer_size == 8:
                object_base = int.from_bytes(
                    blob[20:24], "little", signed=False,
                )
            # x64: td_ptr + image_base -> VA
            td_va = td_ptr + image_base if pointer_size == 8 else td_ptr
            chd_va = chd_ptr + image_base if pointer_size == 8 else chd_ptr
            if td_va not in td_vas:
                continue
            # Sanite: offset/cd_offset gercekci (max 1MB)
            if offset_val > 0x100000 or cd_offset > 0x100:
                continue
            col_va = rdata_va + off
            # v1.10.0 Batch 6A (Codex audit): image_base cross-check.
            # pSelf (= object_base RVA) x64 icin COL'un kendi RVA'si.
            # image_base = col.addr - pSelf seklinde dogrulayabiliriz.
            # Tutarsizlik COL yanlis siniflandirildigina isaret (continue).
            image_base_validated = False
            if pointer_size == 8 and object_base:
                derived_image_base = col_va - object_base
                if derived_image_base == image_base:
                    image_base_validated = True
                elif derived_image_base > 0 and abs(
                    derived_image_base - image_base,
                ) > 0x100000:
                    # 1MB'den buyuk sapma -> bu COL degil, false positive.
                    # Conservative: yine de ekliyoruz ama validated=False
                    # kalsin, rapor katmani dusuk confidence raporlar.
                    image_base_validated = False
            # v1.10.0 Batch 6A: vftable_addr = col_va + ptr_size ABI-unsafe.
            # Kesin adres xref ile teyit edilir (caller sorumlulugu, burada
            # fallback + confidence=0.5 raporlaniyor). Berke raporda
            # "vftable_confidence" alanini kullanarak guvensiz slot'lari
            # filtreleyebilir.
            out.append(
                MSVCCompleteObjectLocator(
                    addr=col_va,
                    signature=sig,
                    offset=offset_val,
                    cd_offset=cd_offset,
                    type_descriptor=td_va,
                    class_hierarchy=chd_va,
                    object_base=object_base,
                    type_desc_obj=type_descriptors.get(td_va),
                    vftable_addr=col_va + pointer_size,
                    vftable_confidence=0.5,  # fallback; xref ile 1.0'a cikar
                    image_base_validated=image_base_validated,
                )
            )
        return out

    def resolve_vftable_addresses_from_xrefs(
        self,
        cols: list[MSVCCompleteObjectLocator],
        xrefs_to_col: dict[int, list[int]],
        pointer_size: int = 8,
    ) -> None:
        """Ghidra xref bilgisinden vftable adreslerini dogrula.

        v1.10.0 Batch 6A (Codex audit): vftable, COL'a pointer eden slot[-1]
        olarak class'in vtable[0]'da bulunur. Eger xref'lere bakip COL'u
        isaret eden slot'u bulursak, gercek vftable baslangic adresini
        hesaplayip ``vftable_confidence=1.0`` yapariz.

        Args:
            cols: COL listesi (in-place guncellenir).
            xrefs_to_col: ``col.addr`` -> COL'a edilen adres listesi.
                Ghidra scripts'ten gelir (XREF TO analizi).
            pointer_size: 8 (x64) veya 4 (x86).

        Side effect: ``col.vftable_addr`` ve ``col.vftable_confidence``
        guncellenir.
        """
        for col in cols:
            refs = xrefs_to_col.get(col.addr, [])
            if not refs:
                continue  # fallback vftable_addr korunur, confidence=0.5
            # En yakin XREF'i vtable[-1] slot'u kabul et.
            # vtable baslangici = ref - pointer_size * 0 (ref zaten slot[-1]).
            # Ornek: class X { vfptr -> vtable[0]=method0, vtable[-1]=&COL }.
            # Bu durumda xref'teki adres vtable slot'udur, vtable BASI ise
            # ref + pointer_size (vtable[-1] -> vtable[0]).
            # NOT: Bazi derleyicilerde layout farkli (single-inheritance
            # basit varsayim). Multi-inheritance'ta birden fazla vtable
            # olabilir ve her biri kendi COL'a isaret eder.
            best_ref = min(refs)
            col.vftable_addr = best_ref + pointer_size
            col.vftable_confidence = 1.0

    # ---- CHD + BCD parse
    def parse_class_hierarchy_descriptor(
        self,
        binary: Any,
        chd_va: int,
        image_base: int,
        pointer_size: int = 8,
        type_descriptors: Optional[dict[int, MSVCTypeDescriptor]] = None,
    ) -> Optional[MSVCClassHierarchyDescriptor]:
        """CHD + BaseClassArray decode."""
        blob = self._read_at_va(binary, chd_va, 16)
        if blob is None:
            return None
        sig = int.from_bytes(blob[0:4], "little", signed=False)
        attrs = int.from_bytes(blob[4:8], "little", signed=False)
        num_bases = int.from_bytes(blob[8:12], "little", signed=False)
        bca_ptr = int.from_bytes(blob[12:16], "little", signed=False)
        if num_bases > 256:
            return None
        bca_va = bca_ptr + image_base if pointer_size == 8 else bca_ptr
        chd = MSVCClassHierarchyDescriptor(
            addr=chd_va,
            signature=sig,
            attributes=attrs,
            num_base_classes=num_bases,
            base_class_array=bca_va,
        )
        # BaseClassArray: num_bases * pointer (4B RVA x64, 4B VA x86)
        bca_blob = self._read_at_va(binary, bca_va, num_bases * 4)
        if bca_blob is None:
            return chd
        for i in range(num_bases):
            bcd_ptr = int.from_bytes(
                bca_blob[i * 4:(i + 1) * 4], "little", signed=False,
            )
            bcd_va = bcd_ptr + image_base if pointer_size == 8 else bcd_ptr
            bcd = self._parse_base_class_descriptor(
                binary, bcd_va, image_base, pointer_size,
                type_descriptors=type_descriptors,
            )
            if bcd:
                chd.base_descriptors.append(bcd)
        return chd

    def _parse_base_class_descriptor(
        self,
        binary: Any,
        bcd_va: int,
        image_base: int,
        pointer_size: int = 8,
        type_descriptors: Optional[dict[int, MSVCTypeDescriptor]] = None,
    ) -> Optional[MSVCBaseClassDescriptor]:
        """BCD parse eder; 24 byte (opsiyonel CHD pointer dahil 28)."""
        blob = self._read_at_va(binary, bcd_va, 28)
        if blob is None:
            return None
        td_ptr = int.from_bytes(blob[0:4], "little", signed=False)
        num_contained = int.from_bytes(blob[4:8], "little", signed=False)
        mdisp = int.from_bytes(blob[8:12], "little", signed=True)
        pdisp = int.from_bytes(blob[12:16], "little", signed=True)
        vdisp = int.from_bytes(blob[16:20], "little", signed=True)
        attrs = int.from_bytes(blob[20:24], "little", signed=False)
        chd_ptr = int.from_bytes(blob[24:28], "little", signed=False)
        td_va = td_ptr + image_base if pointer_size == 8 else td_ptr
        chd_va = chd_ptr + image_base if pointer_size == 8 else chd_ptr
        if attrs & ~0xFF:
            # attrs genelde 8-bit flag; ust bit'ler dolu ise hatali
            return None
        type_name = ""
        if type_descriptors is not None:
            td = type_descriptors.get(td_va)
            if td is not None:
                type_name = td.demangled or td.name
        return MSVCBaseClassDescriptor(
            addr=bcd_va,
            type_descriptor=td_va,
            num_contained_bases=num_contained,
            pmd_mdisp=mdisp,
            pmd_pdisp=pdisp,
            pmd_vdisp=vdisp,
            attributes=attrs,
            class_hierarchy=chd_va,
            type_name=type_name,
        )

    # ---- public entry
    def parse_msvc(
        self,
        binary_path: Path,
        binary: Any = None,
        pointer_size: int = 8,
    ) -> tuple[ClassHierarchy, list[MSVCCompleteObjectLocator]]:
        """MSVC RTTI'yi binary'den tam parse eder.

        Returns:
            (ClassHierarchy, raw COL listesi)
        """
        if binary is None:
            binary = self._load_binary(binary_path)
        if binary is None:
            return ClassHierarchy(), []
        image_base = self._image_base(binary)
        type_descs = self.scan_type_descriptors(binary, image_base, pointer_size)
        if not type_descs:
            logger.info("MSVC .?AV string bulunamadi: %s", binary_path)
            return ClassHierarchy(), []
        cols = self.scan_complete_object_locators(
            binary, type_descs, image_base, pointer_size,
        )
        hierarchy = ClassHierarchy()
        # Her COL -> CppClass
        for col in cols:
            td = col.type_desc_obj
            if td is None:
                continue
            chd = self.parse_class_hierarchy_descriptor(
                binary, col.class_hierarchy, image_base, pointer_size,
                type_descriptors=type_descs,
            )
            col.chd_obj = chd
            cls = CppClass(
                name=td.demangled or td.name,
                mangled_name=td.name,
                typeinfo_addr=f"0x{td.addr:x}",
                vtable_addr=f"0x{col.vftable_addr:x}",
            )
            if chd is not None:
                for bcd in chd.base_descriptors:
                    # ilk BCD genelde class'in kendisi (num_contained = N-1)
                    if bcd.type_descriptor == td.addr:
                        continue
                    cls.base_classes.append(bcd.type_name)
                    cls.bases.append({
                        "name": bcd.type_name,
                        "offset": bcd.pmd_mdisp,
                        "is_virtual": bcd.is_virtual,
                        "is_public": bcd.is_public,
                    })
            hierarchy.classes.append(cls)
            hierarchy.address_to_class[cls.vtable_addr] = cls
        logger.info(
            "MSVC RTTI: %d type_descriptor, %d COL, %d class",
            len(type_descs), len(cols), len(hierarchy.classes),
        )
        return hierarchy, cols


# ===========================================================================
# Unified analyzer
# ===========================================================================
class CppRttiAnalyzer:
    """Binary tipini otomatik tespit edip uygun parser'i calistirir."""

    def __init__(self, config: Any = None) -> None:
        self.config = config
        self.itanium = RTTIParser(config)
        self.msvc = MSVCRTTIParser(config)

    def _detect_format(self, binary_path: Path) -> str:
        """ELF / Mach-O / PE detection. File header magic'e bakar."""
        try:
            with open(binary_path, "rb") as f:
                head = f.read(16)
        except OSError:
            return "unknown"
        if len(head) < 4:
            return "unknown"
        if head[:4] == b"\x7fELF":
            return "elf"
        if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                        b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce"):
            return "macho"
        # fat mach-o
        if head[:4] in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
            return "macho"
        if head[:2] == b"MZ":
            return "pe"
        return "unknown"

    def _detect_pointer_size(self, binary: Any, fallback: int = 8) -> int:
        """PE icin COFF header.Machine'e bak (0x8664 = x64, 0x14c = x86)."""
        try:
            header = getattr(binary, "header", None)
            if header is not None:
                machine = getattr(header, "machine", None)
                if machine is not None:
                    machine_int = int(machine)
                    if machine_int == 0x14c:  # IMAGE_FILE_MACHINE_I386
                        return 4
                    if machine_int == 0x8664:  # AMD64
                        return 8
        except Exception:
            pass
        return fallback

    def analyze(self, binary_path: Path) -> CppRttiResult:
        fmt = self._detect_format(binary_path)
        if fmt == "pe":
            binary = self.msvc._load_binary(binary_path)
            if binary is None:
                return CppRttiResult(abi="msvc")
            ptr_size = self._detect_pointer_size(binary, fallback=8)
            hierarchy, cols = self.msvc.parse_msvc(
                binary_path, binary=binary, pointer_size=ptr_size,
            )
            return CppRttiResult(
                abi="msvc", hierarchy=hierarchy, msvc_locators=cols,
            )
        if fmt in ("elf", "macho"):
            hierarchy = self.itanium.parse_itanium(binary_path)
            return CppRttiResult(abi="itanium", hierarchy=hierarchy)
        return CppRttiResult(abi="unknown")
