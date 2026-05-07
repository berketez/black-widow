"""Go sembol demangler modulu.

Go derleyicisinin urettigi sembolleri insan-okunabilir hale getirir ve
yapisal bilgilerini cikarir. Saf algoritmik (regex/string) bir yaklasim
kullanir; LLM/3rd-party kutuphane kullanmaz.

Desteklenen Go sembol kaliplari:
- Top-level fonksiyon         : ``main.main``, ``fmt.Println``
- Paket yolu                  : ``github.com/user/repo/pkg.Func``
- Value-receiver methodu      : ``time.Time.Format``
- Pointer-receiver methodu    : ``time.(*Time).Format``
- Anonim/closure              : ``main.main.func1``, ``main.main.func1.1``
- Generic instantiations      : ``slices.Sort[int]`` veya
                                ``slices.Sort[go.shape.int_0]``  (Go 1.18+)
- Compiler-generated          : ``type..eq.[5]int``, ``type..hash.string``
- Runtime / cgo               : ``runtime.morestack``, ``_cgo_*``, ``__cgo_*``

Bu modul tek basina bir demangler kutuphanesi gibi davranir; karadul'un
diger Go analiz adimlari (``go_binary.py``) bu yardimcilara baglanabilir.

Paralel ajan notu (2026-05-07): rust_demangler.py ve sigdb_builtin/crypto.py
paralel ajanlar tarafindan yaziliyor; bu dosya onlardan bagimsizdir.
"""

from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------------
# Tespit kaliplari
# ---------------------------------------------------------------------------

# Go sembolu olabilecek genel sekil:
#   <import-path>.<isim>[generic-args]
#
# Import path'inde slash, nokta, tire, alfasayisal karakterler bulunabilir;
# isim kismi nokta ile baslar ve harf/_/digit/(*Type) icerebilir.
#
# Heuristic: sembol icinde en az bir nokta var, ve son noktadan sonra
# bir Go-uyumlu identifier veya parantezli receiver bulunuyor.
_GO_SYMBOL_HEURISTIC = re.compile(
    r"""
    ^
    (?P<path>[\w./\-]+)            # import path / paket
    \.                             # ayirici nokta
    (?P<rest>[\w*.()\[\],/\-<>:; ]+) # isim + olasi receiver/generic
    $
    """,
    re.VERBOSE,
)

# C++ Itanium veya Rust mangling ile baslayan semboller Go DEGILDIR.
_NON_GO_PREFIXES = ("_Z", "_R", "$s", "$S", "_$s", "??_", "?")

# Compiler-generated (auto-generated) kaliplari. Bu semboller Go derleyicisinin
# tip esitlik / hash / interface / GC altyapisi icin urettigi semboller.
_COMPILER_GENERATED_PREFIXES = (
    "type..eq.",
    "type..hash.",
    "type..namedata.",
    "type..importpath.",
    "type..eqfunc.",
    "type..hashfunc.",
    "go.itab.",
    "go.info.",
    "go.string.",
    "go.builtin.",
    "go.func.",
    "go.loc.",
    "go.cuinfo.",
    "gcbits.",
    "go:itab.",
    "go:info.",
)

# Cgo tarafindan uretilen sarmalayici sembolleri.
_CGO_PREFIXES = ("_cgo_", "__cgo_", "x_cgo_", "_Cfunc_", "_C2func_")

# Runtime sembolleri (paket adi ``runtime``).
_RUNTIME_PACKAGE = "runtime"

# Closure / anonim fonksiyon kaliplari:
#   parent.func1
#   parent.func1.1
#   parent.func1.2.3
_CLOSURE_RE = re.compile(r"\.func\d+(?:\.\d+)*$")

# Generic instantiation: koseli parantez icindeki argumanlar.
# Go 1.18+ "go.shape" prefix'i ile tip-shape parametreleri ekler.
_GENERIC_RE = re.compile(r"\[(?P<args>[^\[\]]+)\]$")

# Pointer receiver: ``pkg.(*Type).Method``
_POINTER_RECEIVER_RE = re.compile(
    r"""
    ^
    (?P<package>[\w./\-]+)         # import path
    \.\(\*                         # .(*
    (?P<type>[\w]+)                # Type
    \)                             # )
    \.
    (?P<rest>[\w$.]+)              # Method[+closure suffix]
    $
    """,
    re.VERBOSE,
)

# Value receiver method: ``pkg.Type.Method`` (Type buyuk harfle baslar,
# ardindan tek bir nokta + Method gelir). Cok kolay false-positive
# verebilir; bu yuzden sadece "tek tip + tek metod" durumuna izin veririz.
_VALUE_RECEIVER_RE = re.compile(
    r"""
    ^
    (?P<package>[\w./\-]+?)        # import path (lazy)
    \.
    (?P<type>[A-Z]\w*)             # Type (buyuk harfle baslar)
    \.
    (?P<rest>[A-Za-z_]\w*(?:\.\w+)*) # Method, opsiyonel closure suffix
    $
    """,
    re.VERBOSE,
)

# Top-level fonksiyon: ``pkg.Func`` (path + tek nokta + identifier + opsiyonel suffix)
_TOPLEVEL_RE = re.compile(
    r"""
    ^
    (?P<package>[\w./\-]+)         # path
    \.
    (?P<func>[A-Za-z_]\w*(?:\.\w+)*)
    $
    """,
    re.VERBOSE,
)

# Sadece son segmenti paket olarak almak icin yardimci.
_LAST_SEGMENT_RE = re.compile(r"[^/]+$")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def is_go_symbol(symbol: str) -> bool:
    """Heuristic Go sembol tespiti.

    Bir sembolun Go derleyicisi tarafindan uretilmis olabilecegini
    ucuz bir kontrolle dogrular. Compiler-generated, cgo ve runtime
    semboller de Go kabul edilir.

    Args:
        symbol: Mangled (ya da yari-mangled) sembol metni.

    Returns:
        Sembol Go formatlarindan birine uyuyorsa ``True``.
    """
    if not symbol or not isinstance(symbol, str):
        return False
    s = symbol.strip()
    if not s:
        return False

    # Belirgin Go OLMAYAN prefix'ler
    if s.startswith(_NON_GO_PREFIXES):
        # ``_Cfunc_`` ile cakismayi onle (cgo!)
        if not s.startswith(_CGO_PREFIXES):
            return False

    # Compiler-generated / cgo / runtime hizli yollari
    if s.startswith(_COMPILER_GENERATED_PREFIXES):
        return True
    if s.startswith(_CGO_PREFIXES):
        return True

    # Pointer receiver kalibi karakteristik
    if "(*" in s and ")." in s:
        return bool(_POINTER_RECEIVER_RE.match(_strip_generics(s)))

    # Closure suffix
    if _CLOSURE_RE.search(s):
        return True

    # Genel kalip: en az bir nokta var ve sembol Go-uyumlu karakterlerden
    if "." not in s:
        return False

    # Bosluk veya goz onunde olmayan karakterler Go'da olmaz
    if any(c in s for c in (" ", "\t", "\n")):
        return False

    # Path sonrasi son segment harf/altcizgi ile baslamali
    base = _strip_generics(s)
    return bool(_GO_SYMBOL_HEURISTIC.match(base))


def parse_symbol(symbol: str) -> dict[str, Any] | None:
    """Go sembolunu yapisal alanlara ayrir.

    Donus sozlugu su anahtarlari icerir:

    - ``package``        : str | None  - import path (\"main\", \"net/http\", ...)
    - ``type``           : str | None  - method ise receiver tipi
    - ``receiver_kind``  : "value" | "pointer" | None
    - ``function``       : str         - islev/metod adi (closure suffix dahil)
    - ``is_method``      : bool        - method mi?
    - ``is_closure``     : bool        - closure / anonim mi?
    - ``is_compiler_generated`` : bool - type..eq, runtime.*, cgo, vb.
    - ``generic_args``   : list[str] | None - Go 1.18+ generic argumanlari
    - ``raw``            : str         - orijinal sembol

    Sembol Go uyumlu degilse ``None`` doner.
    """
    if not is_go_symbol(symbol):
        return None

    raw = symbol.strip()
    info: dict[str, Any] = {
        "package": None,
        "type": None,
        "receiver_kind": None,
        "function": "",
        "is_method": False,
        "is_closure": False,
        "is_compiler_generated": False,
        "generic_args": None,
        "raw": raw,
    }

    # --- Compiler-generated / cgo erken tespit ---
    if raw.startswith(_COMPILER_GENERATED_PREFIXES):
        return _parse_compiler_generated(raw, info)

    if raw.startswith(_CGO_PREFIXES):
        info["is_compiler_generated"] = True
        info["package"] = "cgo"
        info["function"] = raw
        return info

    # --- Generic argumanlari ayikla (sondaki [..]) ---
    body, generic_args = _split_generics(raw)
    if generic_args is not None:
        info["generic_args"] = generic_args

    # --- Closure suffix tespiti (.funcN[.M]*) ---
    # Eger sembol closure ise sondaki ``.funcN[.M]*`` blogunu fonksiyon adi
    # olarak ayirip kalan kismi normal kalibna gore parse ederiz. Bu sayede
    # ``main.main.func1`` → package=main, function=main.func1 olur (parent
    # fonksiyon ``main.main`` icindeki anonim).
    closure_match = _CLOSURE_RE.search(body)
    closure_suffix = ""
    body_for_match = body
    if closure_match:
        info["is_closure"] = True
        closure_suffix = closure_match.group(0)  # ".func1[.1]"
        body_for_match = body[: closure_match.start()]

    # --- Pointer receiver: pkg.(*Type).Method ---
    m = _POINTER_RECEIVER_RE.match(body_for_match)
    if m:
        info["package"] = m.group("package")
        info["type"] = m.group("type")
        info["receiver_kind"] = "pointer"
        info["function"] = m.group("rest") + closure_suffix
        info["is_method"] = True
        if info["package"] == _RUNTIME_PACKAGE:
            info["is_compiler_generated"] = True
        return info

    # --- Value receiver: pkg.Type.Method ---
    # Bu kalibin pozitif olabilmesi icin sembolde tam olarak iki nokta-arasi
    # segment olmali (path.Type.Method). Path icindeki noktalar lazy match
    # ile minimuma indirilir.
    m = _VALUE_RECEIVER_RE.match(body_for_match)
    if m:
        package = m.group("package")
        type_name = m.group("type")
        rest = m.group("rest")
        if package and type_name:
            info["package"] = package
            info["type"] = type_name
            info["receiver_kind"] = "value"
            info["function"] = rest + closure_suffix
            info["is_method"] = True
            if package == _RUNTIME_PACKAGE:
                info["is_compiler_generated"] = True
            return info

    # --- Top-level fonksiyon: pkg.Func ---
    m = _TOPLEVEL_RE.match(body_for_match)
    if m:
        package = m.group("package")
        func = m.group("func")
        info["package"] = package
        info["function"] = func + closure_suffix
        if package == _RUNTIME_PACKAGE:
            info["is_compiler_generated"] = True
        return info

    # Hicbir kaliba uymuyorsa ham olarak dondur
    info["function"] = body
    return info


def demangle(symbol: str) -> str | None:
    """Go sembolunu insan-okunabilir bicime cevir.

    Asagidakileri yapar:
    - Pointer receiver: ``pkg.(*Type).Method`` → ``(*pkg.Type).Method``
    - Value receiver  : ``pkg.Type.Method``    → ``pkg.Type.Method``
    - Generic args ile birlikte birakilir.
    - Top-level islev: ``pkg.Func``           → ``pkg.Func``
    - Closure         : suffix korunur.
    - Compiler-gen.   : aciklayici metin uretir
                        ``type..eq.[5]int`` → ``compiler-generated: type equality for [5]int``
    Sembol Go degilse ``None``.
    """
    info = parse_symbol(symbol)
    if info is None:
        return None

    raw = info["raw"]

    # Cgo semboller (compiler-generated kontrolunden ONCE; cgo da
    # is_compiler_generated=True olarak isaretli)
    if info["package"] == "cgo":
        return f"cgo wrapper: {raw}"

    # Compiler-generated semboller icin aciklayici metin
    if info["is_compiler_generated"] and info["package"] != _RUNTIME_PACKAGE:
        return _describe_compiler_generated(raw)

    pkg = info["package"] or ""
    fn = info["function"] or ""
    generics = ""
    if info["generic_args"]:
        generics = "[" + ", ".join(info["generic_args"]) + "]"

    if info["is_method"] and info["type"]:
        if info["receiver_kind"] == "pointer":
            base = f"(*{pkg}.{info['type']}).{fn}"
        else:
            base = f"{pkg}.{info['type']}.{fn}"
    else:
        base = f"{pkg}.{fn}" if pkg else fn

    return base + generics


# ---------------------------------------------------------------------------
# Yardimci fonksiyonlar
# ---------------------------------------------------------------------------


def _split_generics(symbol: str) -> tuple[str, list[str] | None]:
    """Generic argumanlari sembolden ayir.

    Sondaki ``[...]`` bloku varsa argumanlari virgulle ayirip dondur.
    Ic ice ``[]`` durumlari icin bracket-balanced bir tarama yapilir.
    """
    if not symbol.endswith("]"):
        return symbol, None

    # Bracket-balanced geri tarama
    depth = 0
    start = -1
    for i in range(len(symbol) - 1, -1, -1):
        ch = symbol[i]
        if ch == "]":
            depth += 1
        elif ch == "[":
            depth -= 1
            if depth == 0:
                start = i
                break
    if start == -1:
        return symbol, None

    inside = symbol[start + 1 : -1]
    body = symbol[:start]
    args = [a.strip() for a in inside.split(",") if a.strip()]
    if not args:
        return symbol, None
    return body, args


def _strip_generics(symbol: str) -> str:
    """Generic argumanlari kirpip sade sembolu dondur."""
    body, _ = _split_generics(symbol)
    return body


def _parse_compiler_generated(symbol: str, info: dict[str, Any]) -> dict[str, Any]:
    """Compiler-generated sembolu doldur."""
    info["is_compiler_generated"] = True
    info["function"] = symbol
    # Paket adi ilk segmentin oncesi
    # Ornek: type..eq.[5]int  → package="type"
    #        go.itab.*os.File,io.Reader → package="go"
    head, _, _ = symbol.partition(".")
    info["package"] = head or None
    return info


def _describe_compiler_generated(symbol: str) -> str:
    """Compiler-generated sembol icin aciklayici metin uret."""
    if symbol.startswith("type..eq."):
        return f"compiler-generated: type equality for {symbol[len('type..eq.'):]}"
    if symbol.startswith("type..hash."):
        return f"compiler-generated: type hash for {symbol[len('type..hash.'):]}"
    if symbol.startswith("type..eqfunc."):
        return f"compiler-generated: equality function for {symbol[len('type..eqfunc.'):]}"
    if symbol.startswith("type..hashfunc."):
        return f"compiler-generated: hash function for {symbol[len('type..hashfunc.'):]}"
    if symbol.startswith("type..namedata."):
        return f"compiler-generated: type name data for {symbol[len('type..namedata.'):]}"
    if symbol.startswith("type..importpath."):
        return f"compiler-generated: import path data for {symbol[len('type..importpath.'):]}"
    if symbol.startswith(("go.itab.", "go:itab.")):
        prefix_len = len("go.itab.") if symbol.startswith("go.itab.") else len("go:itab.")
        return f"compiler-generated: itab (interface table) for {symbol[prefix_len:]}"
    if symbol.startswith(("go.info.", "go:info.")):
        return f"compiler-generated: dwarf info for {symbol.split('.', 2)[-1]}"
    if symbol.startswith("go.string."):
        return f"compiler-generated: string literal {symbol[len('go.string.'):]}"
    if symbol.startswith("go.func."):
        return f"compiler-generated: anonymous func descriptor {symbol[len('go.func.'):]}"
    if symbol.startswith("gcbits."):
        return f"compiler-generated: GC bitmap for {symbol[len('gcbits.'):]}"
    return f"compiler-generated: {symbol}"


__all__ = [
    "demangle",
    "parse_symbol",
    "is_go_symbol",
]
