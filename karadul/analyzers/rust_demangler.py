"""Rust mangled symbol demangler.

Bu modul Rust tarafindan uretilen mangled (sembolik isimleri encode
edilmis) sembolleri insan-okunur formata cevirir. Saf algoritmik
deterministic implementasyon -- LLM kullanilmaz.

Desteklenen formatlar
---------------------

1. **Legacy mangling** (`_ZN...E`)
   Itanium C++ ABI alt-kumesi. Rust 2018 oncesi varsayilan.
   Format: ``_ZN<len><name>...E[$<hash>$]`` veya ``_ZN<len><name>...17h<16hex>E``
   Ornek: ``_ZN4core3fmt5write17h1234567890abcdefE`` -> ``core::fmt::write``

2. **Modern v0 mangling** (`_R...`)
   RFC 2603 (https://rust-lang.github.io/rfcs/2603-rust-symbol-name-mangling-v0.html)
   Punycode-tabanlı, generic ve trait icin tasarlandi.
   Tam parser yazmak buyuk is -- bu modul *pragmatic subset* destekler:
   - Path dugumleri (`N`, `C`, `M`, `X`, `Y`, `K`)
   - Identifier (`<len><name>` ve `u<len><punycoded>`)
   - Disambiguator (`s<base62>_`)
   - Backref takibi (`B<base62>_`) -- temel destek
   - Generic argumentlar (`I...E`) -- atlama (sembol sonunda truncate)
   Ornek: ``_RNvCs1234_3foo3bar`` -> ``foo::bar``

Cagri Hiyerarsisi
-----------------
1. ``demangle(symbol)`` ile API'yi cagir.
2. ``rustfilt`` CLI mevcutsa (cache), subprocess'le tek-sembol modunda
   delege edilir. Bu en dogru sonucu verir.
3. Yoksa native parser cagrilir.
4. Native parser hata verirse veya tam decode edemezse, en son care
   olarak length-prefixed parts cikarip ``::`` ile birlestirilir.
5. Hicbiri olmazsa orijinal sembol degisir; ``demangle()`` None doner.

Karadul entegrasyonu (planlanan, bu modul disinda):
- ``karadul/analyzers/rust_binary.py`` ``_demangle_itanium`` ve
  ``_demangle_rust`` metodlarini bu modulden ``demangle_batch`` ve
  ``demangle`` cagirisina delege edecek.
- ``karadul/analyzers/demangler_registry.py`` (henuz yok, sequential
  asamada eklenecek) bu modulu, ``go_demangler.py`` (paralel ajan
  uretiyor) ve mevcut Swift/C++ demangler'larini ortak interface'te
  toplayacak. Onerilen ortak interface:
  ``Demangler.detect(symbol) -> bool``,
  ``Demangler.demangle(symbol) -> str | None``,
  ``Demangler.format_name() -> str``.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from typing import Literal

from karadul.core.safe_subprocess import resolve_tool, safe_run

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pattern'ler ve format tespiti
# ---------------------------------------------------------------------------

# Legacy: _Z[N]<digits>... veya _Z<digits>...
# Bazi platformlarda __ZN (cift underscore, macOS) gorulur.
_LEGACY_PREFIX_RE = re.compile(r"^_{1,2}Z")

# Modern v0: _R basliyor, sonrasinda harf veya digit veya $ gelebilir.
# Bazi platformlarda __R (cift underscore) gorulur.
_V0_PREFIX_RE = re.compile(r"^_{1,2}R[A-Za-z0-9_]")

# Hash suffix: 17h<16-hex>
# Rust legacy hash format'inda son segment "h" + 16 hex karakter olur,
# tum segment uzunlugu 17 olur (1 + 16). Yorumlanmasini istiyoruz cunku
# disambiguator amaclidir.
_LEGACY_HASH_RE = re.compile(r"^h[0-9a-f]{16}$")

# rustfilt cache -- shutil.which sonucunu hatirlat
_RUSTFILT_PATH: str | None | Literal[False] = False  # False = henuz kontrol edilmedi
_RUSTFILT_TIMEOUT = 2.0  # saniye


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_format(symbol: str) -> Literal["legacy", "v0", "unknown"]:
    """Sembol formatini tespit et.

    Args:
        symbol: Mangled sembol adi (orn: "_ZN3std3fooE" veya "_RNvC3foo").

    Returns:
        - "legacy" -> Itanium ABI tabanli (`_ZN...E`)
        - "v0" -> Modern RFC 2603 (`_R...`)
        - "unknown" -> Mangled degil veya bilinmeyen format
    """
    if not symbol or not isinstance(symbol, str):
        return "unknown"

    # v0 once kontrol et: _R sonrasi harf gelirse v0.
    # _Z baslangici legacy.
    if _V0_PREFIX_RE.match(symbol):
        return "v0"
    if _LEGACY_PREFIX_RE.match(symbol):
        return "legacy"
    return "unknown"


def demangle(symbol: str) -> str | None:
    """Tek bir Rust mangled sembolu insan-okunur formata cevir.

    Args:
        symbol: Mangled sembol adi.

    Returns:
        Demangle edilmis string. Eger sembol mangled degilse veya
        format tanimlanmazsa None doner. Bilinen format ama parse
        hatasi durumunda en iyi-cabayla bir string doner (orijinal
        sembolu DEGISMEZ olarak dondurmek yerine None doner ki cagiran
        ayirt edebilsin).
    """
    if not symbol or not isinstance(symbol, str):
        return None

    fmt = detect_format(symbol)
    if fmt == "unknown":
        return None

    # 1) rustfilt varsa subprocess delege (en dogru sonuc)
    rf = _resolve_rustfilt()
    if rf:
        result = _demangle_via_rustfilt(rf, symbol)
        if result and result != symbol:
            return result
        # rustfilt sembolu degistirmediyse fallback'a dus

    # 2) Native parser
    if fmt == "legacy":
        out = _demangle_legacy(symbol)
        return out if out else None
    if fmt == "v0":
        out = _demangle_v0(symbol)
        return out if out else None

    return None


def demangle_batch(symbols: list[str]) -> dict[str, str]:
    """Bir liste sembolu toplu demangle et.

    Mangled olmayanlar (None donenler) sonuc dict'inde **bulunmaz**.
    Bu, cagiranin orijinal listede gezip eslesmeyenleri atlamasini
    saglar.

    rustfilt mevcutsa tek seferde butun sembolleri stdin'e verir
    (cok daha hizli). Yoksa tek tek native parser cagrir.

    Args:
        symbols: Mangled sembol adlari listesi.

    Returns:
        ``{original_symbol: demangled}`` map. Mangled olmayan veya
        decode edilemeyen sembolleri icermez.
    """
    if not symbols:
        return {}

    out: dict[str, str] = {}

    # rustfilt batch optimizasyonu
    rf = _resolve_rustfilt()
    if rf:
        batch_result = _demangle_batch_via_rustfilt(rf, symbols)
        if batch_result:
            # rustfilt'in cevirdigini al, ancak gerceketen sembol degistiyse.
            for orig, dem in batch_result.items():
                if dem and dem != orig:
                    out[orig] = dem
            # rustfilt'in atladigi sembolleri (ya cevirememis ya da
            # tam degistirmemis) native parser'a ver.
            missing = [s for s in symbols if s not in out]
        else:
            missing = list(symbols)
    else:
        missing = list(symbols)

    # Kalan sembolleri native parser ile dene
    for sym in missing:
        fmt = detect_format(sym)
        if fmt == "unknown":
            continue
        native_dem: str | None
        try:
            if fmt == "legacy":
                native_dem = _demangle_legacy(sym)
            else:
                native_dem = _demangle_v0(sym)
        except Exception as exc:  # noqa: BLE001
            # Parser hatasi -> sembolu atla (silent except DEGIL,
            # logger.debug ile kayit dustugu icin gizli kalmiyor).
            logger.debug("demangle hatasi: %s -> %s", sym, exc)
            continue
        if native_dem and native_dem != sym:
            out[sym] = native_dem
    return out


# ---------------------------------------------------------------------------
# rustfilt subprocess delegasyonu
# ---------------------------------------------------------------------------

def _resolve_rustfilt() -> str | None:
    """rustfilt CLI yolunu bul. Cache'le. Yoksa None doner.

    B21: resolve_tool whitelist (PATH hijack koruma). $PATH icindeki
    attacker-controlled dizinleri reddeder.
    """
    global _RUSTFILT_PATH
    if _RUSTFILT_PATH is False:
        path = resolve_tool("rustfilt")
        _RUSTFILT_PATH = path  # str veya None
        if path:
            logger.debug("rustfilt bulundu (whitelist): %s", path)
        else:
            logger.debug("rustfilt mevcut degil, native parser kullaniliyor")
    return _RUSTFILT_PATH if _RUSTFILT_PATH else None


def _demangle_via_rustfilt(rustfilt: str, symbol: str) -> str | None:
    """rustfilt'i tek sembol icin cagir."""
    try:
        # B21: safe_run -- LD_PRELOAD/DYLD env temizligi. rustfilt yolu
        # _resolve_rustfilt icinde whitelist'ten alindi.
        proc = safe_run(
            [rustfilt],
            input=symbol,
            capture_output=True,
            text=True,
            timeout=_RUSTFILT_TIMEOUT,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("rustfilt cagri hatasi: %s", exc)
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def _demangle_batch_via_rustfilt(
    rustfilt: str, symbols: list[str],
) -> dict[str, str] | None:
    """rustfilt'i toplu sembol icin cagir.

    rustfilt stdin'den satir-bazli sembol kabul eder ve her satira
    karsilik demangle edilmis sonucu yazar. Bu nedenle batch isleme
    cok daha hizlidir (process baslatma maliyeti tek seferdir).
    """
    if not symbols:
        return {}
    try:
        # B21: safe_run -- LD_PRELOAD/DYLD env temizligi.
        proc = safe_run(
            [rustfilt],
            input="\n".join(symbols),
            capture_output=True,
            text=True,
            timeout=max(_RUSTFILT_TIMEOUT, len(symbols) * 0.01 + 5.0),
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("rustfilt batch hatasi: %s", exc)
        return None
    if proc.returncode != 0:
        return None
    lines = proc.stdout.splitlines()
    out: dict[str, str] = {}
    for orig, dem in zip(symbols, lines):
        out[orig] = dem.strip()
    return out


# ---------------------------------------------------------------------------
# Legacy (_ZN...E) parser
# ---------------------------------------------------------------------------

def _demangle_legacy(symbol: str) -> str | None:
    """Legacy Rust mangling (Itanium ABI alt-kumesi) demangle.

    Format:
        _ZN<len><name><len><name>...E[$<hash>$]

    Ornekler:
        _ZN3foo3barE                       -> foo::bar
        _ZN4core3fmt5write17h0123456789abcdefE -> core::fmt::write

    rust hash suffix (17h + 16 hex) atlanir, cunku disambiguation
    icindir, kullaniciya semantik bilgi vermez.

    Returns:
        Demangle edilmis string veya parse hatasinda None.
    """
    s = symbol
    # _Z veya __Z ve N onekini kaldir
    m = re.match(r"^_{1,2}Z(N)?", s)
    if not m:
        return None
    s = s[m.end():]

    parts: list[str] = []
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c == "E":
            # Mangling sonu
            i += 1
            break
        if not c.isdigit():
            # Beklenmedik karakter -- buyuk olasilikla template/generic
            # ya da ozel modifier (legacy mangling cok kisitli, generic
            # bilesenlerini buyuk olcude template "T" veya "I" ile gosterir
            # ki Rust legacy'de pek gorulmez). Bu nedenle dur.
            break
        # Length-prefixed identifier oku
        j = i
        while j < n and s[j].isdigit():
            j += 1
        try:
            length = int(s[i:j])
        except ValueError:
            return None
        if length <= 0 or j + length > n:
            return None
        ident = s[j:j + length]
        parts.append(ident)
        i = j + length

    if not parts:
        return None

    # Hash suffix'i kaldir: son segment "h" + 16 hex karakter
    if parts and _LEGACY_HASH_RE.match(parts[-1]):
        parts = parts[:-1]

    if not parts:
        return None

    return "::".join(parts)


# ---------------------------------------------------------------------------
# Modern v0 (_R...) parser -- pragmatic subset
# ---------------------------------------------------------------------------
#
# RFC 2603 simdiye gore karmaşik bir grammar tanımlar. Tam destek icin
# rustc-demangle crate'i gibi bir referans uygulama gerekir. Bu modulde
# pragmatic subset uygularız:
#
# Grammar (tam degil, kullanılan üst-küme):
#   <symbol-name> = "_R" <decimal-digit> * <path>
#   <path> = "N" <namespace> <path> <identifier>     # nested path
#          | "C" <identifier>                         # crate root
#          | "M" <impl-path> <type>                   # inherent impl
#          | "X" <impl-path> <type> <path>            # trait impl
#          | "Y" <type> <path>                        # trait definition
#          | "K" <const>                              # const generic
#          | "I" <path> <generic-arg>* "E"            # generic instantiation
#          | "B" <base62-num> "_"                     # backref
#   <identifier> = <disambiguator>? <undisambiguated-identifier>
#   <undisambiguated-identifier> = "u"? <decimal-digit>+ "_"? <bytes>
#   <disambiguator> = "s" <base62-num> "_"
#   <namespace> = lowercase letter (v=value, t=type, ...) | uppercase reserved
#
# Bu parser path bilesenlerini cikarir ve generic instantiation icindeki
# argumentleri ATLAR (Rust 1.0 - 1.40 araligindaki gibi temel kullanim
# icin yeterli). Backref'leri dener -- bulamazsa atlar.

_BASE62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


class _V0ParseError(Exception):
    """v0 parser parse hatasi (toparlanabilir, fallback yapilabilir)."""


class _V0Parser:
    """Tek seferlik kullanilan recursive descent parser.

    Pragmatic subset: tam grammar'i icermez. Path bilesenleri ve
    identifier cikarir, type/const/lifetime icindeki ayrintilari
    atlar (placeholder ile gosterilir veya atlanir).
    """

    # Generic ve type icindeki nest seviyesi sinirli tut (sonsuz dongu
    # kismeni). Tum recursive cagrilar bu sinira tabi.
    MAX_DEPTH = 32

    def __init__(self, body: str) -> None:
        self.body = body  # _R prefix'inden sonrasi
        self.pos = 0
        self.depth = 0
        # Backref yardimcisi: pos -> daha onceki path/type referansi.
        # Pragmatic destek: backref'i atla (placeholder yerlestir).
        self._backref_table: dict[int, str] = {}

    # ------------------------------------------------------------------
    # Yardimci okuyucular
    # ------------------------------------------------------------------

    def _peek(self) -> str:
        if self.pos >= len(self.body):
            raise _V0ParseError("beklenmeyen EOF")
        return self.body[self.pos]

    def _eat(self, c: str) -> None:
        if self._peek() != c:
            raise _V0ParseError(f"beklenen '{c}', goruldu '{self._peek()}'")
        self.pos += 1

    def _read_decimal(self) -> int:
        start = self.pos
        while self.pos < len(self.body) and self.body[self.pos].isdigit():
            self.pos += 1
        if self.pos == start:
            raise _V0ParseError("decimal bekleniyor")
        return int(self.body[start:self.pos])

    def _read_base62_until_underscore(self) -> int:
        """base62-num ardindan zorunlu '_' okur. Bos ise 0 doner."""
        start = self.pos
        while self.pos < len(self.body) and self.body[self.pos] in _BASE62:
            self.pos += 1
        token = self.body[start:self.pos]
        if self.pos >= len(self.body) or self.body[self.pos] != "_":
            raise _V0ParseError("base62-num sonunda '_' bekleniyor")
        self.pos += 1  # '_' yut
        if not token:
            return 0
        # base62 decode
        value = 0
        for ch in token:
            value = value * 62 + _BASE62.index(ch)
        return value + 1  # RFC 2603: stored value+1, gerçek deger value

    # ------------------------------------------------------------------
    # Identifier
    # ------------------------------------------------------------------

    def _parse_undisambiguated_identifier(self) -> str:
        """``u?<decimal>_?<bytes>`` formati."""
        is_punycoded = False
        if self.pos < len(self.body) and self.body[self.pos] == "u":
            is_punycoded = True
            self.pos += 1
        length = self._read_decimal()
        # Optional underscore separator (rare, but in spec)
        if self.pos < len(self.body) and self.body[self.pos] == "_":
            self.pos += 1
        if self.pos + length > len(self.body):
            raise _V0ParseError(
                f"identifier uzunlugu ({length}) buffer disinda",
            )
        text = self.body[self.pos:self.pos + length]
        self.pos += length
        if is_punycoded:
            # RFC 2603 punycode decoding -- pragmatic: deflated halini
            # geri verme zor; ham metni "punycoded:" prefix'i ile dondur.
            # Cogu Rust sembolu ASCII oldugu icin nadiren tetiklenir.
            return text  # placeholder: tam decode yapilmadi
        return text

    def _parse_identifier(self) -> str:
        """Optional disambiguator + undisambiguated identifier."""
        if self.pos < len(self.body) and self.body[self.pos] == "s":
            # disambiguator: s<base62>_
            saved = self.pos
            self.pos += 1
            try:
                self._read_base62_until_underscore()
            except _V0ParseError:
                # disambiguator parsing failed; geri don ve identifier
                # olarak dene (s ile baslayan identifier mumkun degil
                # cunku decimal bekleniyor)
                self.pos = saved
        return self._parse_undisambiguated_identifier()

    # ------------------------------------------------------------------
    # Path
    # ------------------------------------------------------------------

    def _parse_path(self) -> str:
        """``<path>`` ureticisi -- path string'ini olustur."""
        if self.depth > self.MAX_DEPTH:
            raise _V0ParseError("max derinlige ulasildi")
        self.depth += 1
        try:
            tag = self._peek()
            self.pos += 1

            if tag == "C":
                # crate root: <identifier>
                return self._parse_identifier()

            if tag == "N":
                # nested: <namespace> <path> <identifier>
                # namespace bir lowercase harf (v/t/...) veya uppercase
                if self.pos >= len(self.body):
                    raise _V0ParseError("namespace tag eksik")
                ns = self.body[self.pos]
                self.pos += 1
                parent = self._parse_path()
                ident = self._parse_identifier()
                if not ident:
                    return parent
                # namespace lowercase ise gizle, uppercase ise gosterme
                # (cogu insan-okunur output namespace'i atlar)
                _ = ns
                return f"{parent}::{ident}"

            if tag == "M" or tag == "X" or tag == "Y":
                # impl-path veya trait def -- type ve path icer
                # Pragmatic: <impl-path> = <disambiguator>? <path>
                # Disambiguator:
                if self.pos < len(self.body) and self.body[self.pos] == "s":
                    self.pos += 1
                    self._read_base62_until_underscore()
                # M: <impl-path> <type>
                # X: <impl-path> <type> <path>
                # Y: <type> <path>
                if tag == "Y":
                    type_str = self._parse_type()
                    trait = self._parse_path()
                    return f"<{type_str} as {trait}>"
                # M/X icin: impl-path -> path
                impl_parent = self._parse_path()
                type_str = self._parse_type()
                if tag == "M":
                    return f"<{type_str}>"
                # X: trait impl
                trait = self._parse_path()
                _ = impl_parent
                return f"<{type_str} as {trait}>"

            if tag == "I":
                # generic instantiation: <path> <generic-arg>* "E"
                base = self._parse_path()
                # Generic argumentleri atla
                args: list[str] = []
                while self.pos < len(self.body) and self.body[self.pos] != "E":
                    try:
                        args.append(self._parse_generic_arg())
                    except _V0ParseError:
                        # Tip parsing hatasi -- generic'i atla
                        # E'ye kadar zorla ileri sar
                        self._skip_until("E")
                        break
                if self.pos < len(self.body) and self.body[self.pos] == "E":
                    self.pos += 1
                if args:
                    return f"{base}<{', '.join(args)}>"
                return base

            if tag == "B":
                # Backref: B<base62>_
                num = self._read_base62_until_underscore()
                # Pragmatic: backref'i takip etmek karmasik. Placeholder
                # ile gosterelim. Cogu kullanim icin bu yeterli.
                return f"_B{num}"

            if tag == "K":
                # const generic: K<const>
                self._skip_const()
                return "_const"

            # Bilinmeyen tag -> hata
            raise _V0ParseError(f"bilinmeyen path tag: {tag!r}")
        finally:
            self.depth -= 1

    # ------------------------------------------------------------------
    # Type / generic-arg
    # ------------------------------------------------------------------

    def _parse_generic_arg(self) -> str:
        """``L<lifetime>`` | ``T<type>`` | ``K<const>`` (bu RFC'de)
        veya direk type.
        """
        if self.pos >= len(self.body):
            raise _V0ParseError("generic-arg EOF")
        c = self.body[self.pos]
        if c == "L":
            # lifetime: L<base62>_
            self.pos += 1
            self._read_base62_until_underscore()
            return "'_"
        if c == "K":
            self.pos += 1
            self._skip_const()
            return "_const"
        # Aksi halde dogrudan type
        return self._parse_type()

    # Basic type primitives (RFC 2603 kismi)
    _PRIMITIVE_TYPES = {
        "a": "i8",  "b": "bool", "c": "char", "d": "f64", "e": "str",
        "f": "f32", "h": "u8",   "i": "isize","j": "usize", "l": "i32",
        "m": "u32", "n": "i128", "o": "u128", "s": "i16",  "t": "u16",
        "u": "()",  "v": "...",  "x": "i64",  "y": "u64",  "z": "!",
        "p": "_",
    }

    def _parse_type(self) -> str:
        """Pragmatic type parser. Tam degil ama sik kullanilanlari isler."""
        if self.depth > self.MAX_DEPTH:
            raise _V0ParseError("max type derinlige ulasildi")
        self.depth += 1
        try:
            if self.pos >= len(self.body):
                raise _V0ParseError("type EOF")
            c = self.body[self.pos]
            # Primitive
            if c in self._PRIMITIVE_TYPES:
                self.pos += 1
                return self._PRIMITIVE_TYPES[c]
            # Reference: R<lifetime>?<type>, mut R: Q<lifetime>?<type>
            if c in ("R", "Q"):
                self.pos += 1
                prefix = "&" if c == "R" else "&mut "
                if self.pos < len(self.body) and self.body[self.pos] == "L":
                    self.pos += 1
                    self._read_base62_until_underscore()
                inner = self._parse_type()
                return f"{prefix}{inner}"
            # Pointer: P<type> (const), O<type> (mut)
            if c in ("P", "O"):
                self.pos += 1
                inner = self._parse_type()
                return f"*{inner}"
            # Array: A<type><const>
            if c == "A":
                self.pos += 1
                inner = self._parse_type()
                self._skip_const()
                return f"[{inner}; _]"
            # Slice: S<type>
            if c == "S":
                self.pos += 1
                inner = self._parse_type()
                return f"[{inner}]"
            # Tuple: T<type>*E
            if c == "T":
                self.pos += 1
                items: list[str] = []
                while self.pos < len(self.body) and self.body[self.pos] != "E":
                    items.append(self._parse_type())
                if self.pos < len(self.body) and self.body[self.pos] == "E":
                    self.pos += 1
                return f"({', '.join(items)})"
            # Backref
            if c == "B":
                self.pos += 1
                num = self._read_base62_until_underscore()
                return f"_B{num}"
            # Diger durumda path olarak dene
            return self._parse_path()
        finally:
            self.depth -= 1

    # ------------------------------------------------------------------
    # Yardimcilar
    # ------------------------------------------------------------------

    def _skip_const(self) -> None:
        """Const generic ifadesini atla."""
        # K tag'i zaten yutuldu varsayalim. Const ya bir type+value ya da
        # backref olabilir. Pragmatic: en yakin "_" karakterine kadar veya
        # E gorene kadar atla. RFC daha karmaşik ama bizim icin yeterli.
        if self.pos >= len(self.body):
            return
        c = self.body[self.pos]
        if c == "p":
            self.pos += 1
            return
        if c == "B":
            self.pos += 1
            self._read_base62_until_underscore()
            return
        # type-prefixed const: <type><value>_
        try:
            self._parse_type()
        except _V0ParseError:
            pass
        # Value kismi: hex/digit + '_'
        while self.pos < len(self.body) and self.body[self.pos] != "_":
            self.pos += 1
        if self.pos < len(self.body) and self.body[self.pos] == "_":
            self.pos += 1

    def _skip_until(self, target: str) -> None:
        """Belirli bir karaktere kadar ileri sar (parse etmeden)."""
        while self.pos < len(self.body) and self.body[self.pos] != target:
            self.pos += 1


def _demangle_v0(symbol: str) -> str | None:
    """Modern v0 (RFC 2603) sembolu demangle et.

    Pragmatic subset destekler. Tam parse mumkun degilse kismi sonuc
    veya None doner.
    """
    # _R veya __R prefix'ini soy
    m = re.match(r"^_{1,2}R", symbol)
    if not m:
        return None
    body = symbol[m.end():]

    # RFC 2603: prefix'ten sonra optional encoding version (decimal digits)
    # bulunabilir. Genelde Rust 1.x'te bos.
    pos = 0
    while pos < len(body) and body[pos].isdigit():
        pos += 1
    body = body[pos:]

    if not body:
        return None

    parser = _V0Parser(body)
    try:
        result = parser._parse_path()
    except _V0ParseError as exc:
        logger.debug("v0 parser hatasi: %s -> %s", symbol, exc)
        # Fallback: heuristic length-prefixed cikarma
        return _demangle_v0_heuristic(body)
    except RecursionError:
        logger.debug("v0 parser recursion limit: %s", symbol)
        return _demangle_v0_heuristic(body)

    # Hash suffix (.llvm.<...>) kaldir
    if "." in result:
        result = result.split(".", 1)[0]

    return result if result else None


def _demangle_v0_heuristic(body: str) -> str | None:
    """v0 parser basarisiz olursa heuristic fallback.

    Sadece length-prefixed identifier'lari cikarir, namespace mantigi
    uygulamaz. Eksik ama hicbir seyden iyidir.
    """
    parts: list[str] = []
    i = 0
    n = len(body)
    while i < n:
        c = body[i]
        if c.isdigit():
            # length-prefixed ident
            j = i
            while j < n and body[j].isdigit():
                j += 1
            try:
                length = int(body[i:j])
            except ValueError:
                break
            if length <= 0 or j + length > n:
                break
            ident = body[j:j + length]
            # Hash suffix benzeri ise (h + hex) atla
            if not _LEGACY_HASH_RE.match(ident):
                # Ascii ve makul ise ekle
                if all(ch.isalnum() or ch == "_" for ch in ident):
                    parts.append(ident)
            i = j + length
        else:
            i += 1

    if not parts:
        return None
    return "::".join(parts)


# ---------------------------------------------------------------------------
# Public yardimci -- format ve gostermeyen API'lar __all__ disinda
# ---------------------------------------------------------------------------

__all__ = ["demangle", "demangle_batch", "detect_format"]
