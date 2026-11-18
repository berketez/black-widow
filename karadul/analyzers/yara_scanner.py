"""YARA rule engine entegrasyonu.

YARA, binary/dosya pattern tarama icin endustri standardi.
Binlerce hazir kural (malware, packer, crypto, compiler) mevcut.

Karadul'da kullanim:
1. Binary'deki bilinen kutuphaneleri tespit (crypto, compression)
2. Packer/protector tespiti (UPX, VMProtect, Themida)
3. Compiler tespiti (GCC, MSVC, Clang, Rust, Go)
4. Anti-debug/anti-analysis tespiti

YARA kurulu degilse graceful fallback: regex-based scanning.

Hukum modeli (P03 / IMZA-05, 2026-11-18):
    Eski surumde her dizgi ``nocase`` ve her kuralin kosulu ``any of them``
    idi; ``compress`` icindeki "mpress" coreutils ``ls``'i "MPRESS ile
    paketli", ``tObject`` redis'i "Delphi" yapiyordu. Artik:

    - Iki arka uc (yara-python ve regex yedegi) yalnizca *dizgi isabeti*
      toplar: ``kimlik -> [ofset, ...]``. Kimlikler iki arka uçta aynidir
      (bayt desenleri ``$b0..``, metin desenleri ``$s0..``).
    - Hukmu TEK bir Python degerlendiricisi verir (``_evaluate``): bicim
      (PE/ELF/Mach-O), mimari bolgesi (or. yalniz x86 kod tasiyan dilim),
      kod imzasi bolgesinin dislanmasi, PE bolum adlari, giris noktasi
      baytlari, Rich basligi ve kural kosulu (``N of``, ``ve/veya``,
      baska kuralin eslesmesi). Boylece iki arka uc ayni anlambilimle
      calisir; YARA kaynagindaki kosul yalnizca gerekli bir on suzgectir.
    - Metin desenleri ontanimli olarak harf DUYARLIDIR; harf duyarsizlik
      yalnizca gerektiginde ``(?i)`` onekiyle istenir. ``(?s)`` oneki
      ``.``'nin her bayta uymasini saglar (YARA'da ``s`` niteleyicisi).

Kullanim:
    scanner = YaraScanner()
    scanner.load_builtin_rules()
    matches = scanner.scan_file("/path/to/binary")
    # matches.matches: [YaraMatch(rule="OpenSSL_1_1", tags=["crypto"], ...)]
"""

from __future__ import annotations

import logging
import re
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional, Union

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tarama durumu (P03 durum sozlesmesi; capa_scanner ile ayni degerler)
# ---------------------------------------------------------------------------

STATUS_RAN = "calisti"              # tarama tamamlandi (0 eslesme = "tarandi, temiz")
STATUS_NO_TOOL = "arac_yok"         # arac/kural kaynagi yok (YARA'da kullanilmaz: yedek esleyici var)
STATUS_ERROR = "hata"               # tarama tamamlanamadi; neden ``status_reason``'da
STATUS_UNSUPPORTED = "desteklenmiyor"  # bicim/mimari aracin kapsami disinda

# Bir kimlik icin saklanan en cok isabet (iki arka uçta ayni sinir).
_MAX_INSTANCES_PER_STRING = 64


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class YaraMatch:
    """Tek bir YARA kural eslesmesi."""
    rule: str
    tags: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    strings: list[tuple[int, str, bytes]] = field(default_factory=list)
    namespace: str = ""

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable dict."""
        return {
            "rule": self.rule,
            "tags": self.tags,
            "meta": self.meta,
            "strings": [
                {"offset": off, "identifier": ident, "data": data.hex()}
                for off, ident, data in self.strings
            ],
            "namespace": self.namespace,
        }


@dataclass
class ScanResult:
    """Tarama sonucu.

    Durum alanlari (P03):
        status: ``calisti`` (tarama bitti; eslesme 0 olabilir = temiz) ya da
            ``hata`` (dosya okunamadi, kural yok, tarama yarida kaldi).
        status_reason: ``hata`` ise neden; ``calisti`` ise bos.
        fallback_reason: yara-python kurulu oldugu halde regex yedegine
            dusulduyse nedeni (or. derleme hatasi); bos = dusulmedi.
        target_format: hedefin bicimi (``pe`` / ``elf`` / ``macho`` / ``""``).
    """
    total_rules: int = 0
    matches: list[YaraMatch] = field(default_factory=list)
    scan_time_ms: float = 0.0
    errors: list[str] = field(default_factory=list)
    backend: str = ""  # "yara-python" veya "regex-fallback" (gercekte kullanilan)
    status: str = STATUS_ERROR
    status_reason: str = ""
    fallback_reason: str = ""
    target_format: str = ""

    @property
    def matched_rules(self) -> list[str]:
        """Eslesen kural isimlerini dondur."""
        return [m.rule for m in self.matches]

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "status_reason": self.status_reason,
            "total_rules": self.total_rules,
            "matches": [m.to_dict() for m in self.matches],
            "scan_time_ms": round(self.scan_time_ms, 3),
            "errors": self.errors,
            "backend": self.backend,
            "fallback_reason": self.fallback_reason,
            "target_format": self.target_format,
        }


def _error_result(reason: str) -> ScanResult:
    return ScanResult(errors=[reason], status=STATUS_ERROR, status_reason=reason)


# ---------------------------------------------------------------------------
# Ikili yapi bilgisi (bicim, mimari bolgeleri, PE bolumleri, kod imzasi)
# ---------------------------------------------------------------------------
# Kotu niyetli girdiye karsi: her okuma sinir denetimli, sayilar ust sinirli,
# hata -> bos bilgi (istisna disari sizmaz).

_MACHO_THIN_MAGICS = {
    b"\xfe\xed\xfa\xce": (">", False), b"\xfe\xed\xfa\xcf": (">", True),
    b"\xce\xfa\xed\xfe": ("<", False), b"\xcf\xfa\xed\xfe": ("<", True),
}
_LC_CODE_SIGNATURE = 0x1D
_CPU_X86 = 7
_CPU_X86_64 = 0x01000007
_ELF_X86 = {3, 62}             # EM_386, EM_X86_64
_PE_X86 = {0x14C, 0x8664}      # IMAGE_FILE_MACHINE_I386 / AMD64


@dataclass
class _PeInfo:
    sections: list[str] = field(default_factory=list)
    entry_bytes: bytes = b""
    e_lfanew: int = 0
    machine: int = 0
    security_dir: Optional[tuple[int, int]] = None  # (dosya ofseti, boyut)


@dataclass
class _BinaryInfo:
    fmt: str = ""
    # (baslangic, bitis, mimari) -- mimari: "x86" | "other"
    arch_regions: list[tuple[int, int, str]] = field(default_factory=list)
    # Programin icerigi olmayan bolgeler (kod imzasi / Authenticode sertifikasi)
    excluded_regions: list[tuple[int, int]] = field(default_factory=list)
    pe: Optional[_PeInfo] = None


def _detect_format(data: bytes) -> str:
    """Magic byte'tan binary formatini tespit et: pe | elf | macho | ''."""
    if data[:2] == b"MZ":
        return "pe"
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:4] in _MACHO_THIN_MAGICS or data[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        return "macho"
    return ""


def _u(fmt: str, data: bytes, off: int) -> Optional[tuple]:
    size = struct.calcsize(fmt)
    if off < 0 or off + size > len(data):
        return None
    return struct.unpack_from(fmt, data, off)


def _parse_pe(data: bytes) -> Optional[_PeInfo]:
    hdr = _u("<I", data, 0x3C)
    if hdr is None:
        return None
    e_lfanew = hdr[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return None
    fh = _u("<HHIIIHH", data, e_lfanew + 4)
    if fh is None:
        return None
    machine, nsec, _, _, _, opt_size, _ = fh
    opt = e_lfanew + 24
    magic = _u("<H", data, opt)
    if magic is None:
        return None
    info = _PeInfo(e_lfanew=e_lfanew, machine=machine)
    ep = _u("<I", data, opt + 16)
    dd_off = opt + (96 if magic[0] == 0x10B else 112)
    sec_dir = _u("<II", data, dd_off + 4 * 8)  # IMAGE_DIRECTORY_ENTRY_SECURITY
    if sec_dir and sec_dir[0] and sec_dir[1]:
        info.security_dir = (sec_dir[0], sec_dir[1])
    sec_tab = opt + opt_size
    sections: list[tuple[str, int, int, int, int]] = []
    for i in range(min(nsec, 96)):
        s = _u("<8sIIII", data, sec_tab + 40 * i)
        if s is None:
            break
        name = s[0].rstrip(b"\x00").decode("latin-1")
        sections.append((name, s[1], s[2], s[3], s[4]))  # vsize, va, rawsize, rawptr
    info.sections = [s[0] for s in sections]
    if ep is not None:
        ep_rva = ep[0]
        for _, vsize, va, rawsize, rawptr in sections:
            if va <= ep_rva < va + max(vsize, rawsize):
                foff = rawptr + (ep_rva - va)
                info.entry_bytes = data[foff:foff + 16]
                break
    return info


def _macho_slice(data: bytes, base: int, end: int, info: _BinaryInfo) -> None:
    """Ince Mach-O dilimi: mimari bolgesi + LC_CODE_SIGNATURE bolgesi."""
    magic = data[base:base + 4]
    if magic not in _MACHO_THIN_MAGICS:
        return
    endian, is64 = _MACHO_THIN_MAGICS[magic]
    hdr = _u(endian + "iiIIII", data, base + 4)
    if hdr is None:
        return
    cputype, _, _, ncmds, sizeofcmds, _ = hdr
    arch = "x86" if cputype in (_CPU_X86, _CPU_X86_64) else "other"
    info.arch_regions.append((base, end, arch))
    off = base + (32 if is64 else 28)
    stop = min(off + sizeofcmds, end)
    for _ in range(min(ncmds, 4096)):
        lc = _u(endian + "II", data, off)
        if lc is None or off + 8 > stop:
            break
        cmd, cmdsize = lc
        if cmd == _LC_CODE_SIGNATURE:
            ls = _u(endian + "II", data, off + 8)
            if ls is not None:
                start = base + ls[0]
                info.excluded_regions.append((start, start + ls[1]))
        if cmdsize < 8:
            break
        off += cmdsize


def _binary_info(data: bytes) -> _BinaryInfo:
    info = _BinaryInfo(fmt=_detect_format(data))
    try:
        if info.fmt == "pe":
            info.pe = _parse_pe(data)
            if info.pe is not None:
                arch = "x86" if info.pe.machine in _PE_X86 else "other"
                info.arch_regions.append((0, len(data), arch))
                if info.pe.security_dir:
                    off, size = info.pe.security_dir
                    info.excluded_regions.append((off, off + size))
        elif info.fmt == "elf":
            ei_data = data[5:6]
            endian = ">" if ei_data == b"\x02" else "<"
            em = _u(endian + "H", data, 0x12)
            arch = "x86" if em and em[0] in _ELF_X86 else "other"
            info.arch_regions.append((0, len(data), arch))
        elif info.fmt == "macho":
            magic = data[:4]
            if magic in _MACHO_THIN_MAGICS:
                _macho_slice(data, 0, len(data), info)
            else:
                is64 = magic == b"\xca\xfe\xba\xbf"
                nfat = _u(">I", data, 4)
                n = nfat[0] if nfat else 0
                if n <= 64:
                    for i in range(n):
                        if is64:
                            fa = _u(">iiQQI", data, 8 + 32 * i)
                        else:
                            fa = _u(">iiIII", data, 8 + 20 * i)
                        if fa is None:
                            break
                        off, size = fa[2], fa[3]
                        if 0 < off < len(data):
                            _macho_slice(data, off, min(off + size, len(data)), info)
    except Exception:  # pragma: no cover - savunma; yapi bilgisi yoksa bos kalir
        logger.debug("YARA: ikili yapi bilgisi okunamadi", exc_info=True)
    return info


# ---------------------------------------------------------------------------
# Kural kosullari (iki arka ucun ortak hakemi)
# ---------------------------------------------------------------------------

@dataclass
class RuleEvidence:
    """Bir kural icin toplanan kanit (bolge suzgecinden SONRA)."""
    hits: dict[str, list[tuple[int, bytes]]]
    ids: list[str]
    binfo: _BinaryInfo
    matched_rules: set[str] = field(default_factory=set)

    def has(self, ident: str) -> bool:
        return bool(self.hits.get(ident))

    def count(self, ident: str) -> int:
        return len(self.hits.get(ident, ()))

    def distinct(self, idents: Optional[list[str]] = None) -> int:
        return sum(1 for i in (idents if idents is not None else self.ids) if self.has(i))


class Cond:
    """Kural kosulu dugumu: ``cond(ev) -> bool`` ve okunur ``describe()``."""

    def __init__(self, fn: Callable[[RuleEvidence], bool], text: str) -> None:
        self._fn = fn
        self._text = text

    def __call__(self, ev: RuleEvidence) -> bool:
        return bool(self._fn(ev))

    def describe(self) -> str:
        return self._text


def of(n: int, *idents: str) -> Cond:
    """Listelenen kimliklerden (bos = kuralin tum dizgileri) en az ``n`` farkli kimlik."""
    ids = list(idents) or None
    label = "them" if ids is None else "(" + ", ".join(ids) + ")"
    return Cond(lambda ev: ev.distinct(ids) >= n, f"{n} of {label}")


def has(ident: str) -> Cond:
    return Cond(lambda ev: ev.has(ident), ident)


def count_at_least(ident: str, n: int) -> Cond:
    return Cond(lambda ev: ev.count(ident) >= n, f"#{ident[1:]} >= {n}")


def all_(*conds: Cond) -> Cond:
    return Cond(lambda ev: all(c(ev) for c in conds),
                "(" + " and ".join(c.describe() for c in conds) + ")")


def any_(*conds: Cond) -> Cond:
    return Cond(lambda ev: any(c(ev) for c in conds),
                "(" + " or ".join(c.describe() for c in conds) + ")")


def pe_section(*names: str) -> Cond:
    """PE bolum tablosunda bu adlardan biri (tam ad, harf duyarli) var."""
    wanted = set(names)
    return Cond(
        lambda ev: ev.binfo.pe is not None and any(s in wanted for s in ev.binfo.pe.sections),
        "pe.section in {" + ", ".join(sorted(wanted)) + "}",
    )


def pe_section_re(pattern: str) -> Cond:
    rx = re.compile(pattern)
    return Cond(
        lambda ev: ev.binfo.pe is not None and any(rx.fullmatch(s) for s in ev.binfo.pe.sections),
        f"pe.section =~ /{pattern}/",
    )


def pe_entry(*prefixes: bytes) -> Cond:
    """PE giris noktasindaki baytlar bu oneklerden biriyle basliyor."""
    return Cond(
        lambda ev: ev.binfo.pe is not None
        and any(ev.binfo.pe.entry_bytes.startswith(p) for p in prefixes),
        "pe.entry_point starts " + " | ".join(p.hex(" ") for p in prefixes),
    )


def pe_rich_header() -> Cond:
    """MS bagdastiricisinin Rich basligi: DOS koku ile PE basligi arasinda ``Rich``."""
    return Cond(lambda ev: ev.has("$rich"), "rich_header")


def rule_matched(*names: str) -> Cond:
    """Ayni dosyada baska bir kuralin eslesmis olmasi (baglam kaniti)."""
    return Cond(lambda ev: any(n in ev.matched_rules for n in names),
                "rule(" + " | ".join(names) + ")")


# ---------------------------------------------------------------------------
# Dahili kural tanimi
# ---------------------------------------------------------------------------

@dataclass
class BuiltinRule:
    """Python tarafinda tanimlanan dahili kural.

    YARA kurulu ise yara.compile() icin kaynak uretilebilir.
    Degilse regex/byte-pattern fallback icin kullanilir.

    Her kuralda ya ``byte_patterns`` (bayt dizisi listesi)
    ya da ``string_patterns`` (regex listesi) bulunur. Kimlikler:
    bayt desenleri ``$b0, $b1, ...``, metin desenleri ``$s0, $s1, ...``.

    Metin desenleri harf duyarlidir; ``(?i)`` oneki harf duyarsiz, ``(?s)``
    oneki "nokta her bayta uyar" anlamina gelir (birlikte: ``(?is)``).

    ``condition``: ``"any"`` | ``"all"`` | ``int`` (N farkli dizgi) | ``Cond``.
    ``formats``: kuralin gecerli oldugu bicimler (bos = hepsi).
    ``arch``: ``["x86"]`` ise yalniz x86 kod tasiyan bolgelerdeki
        (x86 ELF/PE, evrensel Mach-O'nun x86 dilimi) isabetler sayilir.
    """
    name: str
    tags: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    byte_patterns: list[bytes] = field(default_factory=list)
    string_patterns: list[str] = field(default_factory=list)
    condition: Union[str, int, Cond] = "any"
    # Bu kuralin yalnizca gecerli oldugu binary formatlari ("pe", "elf",
    # "macho"). Bos = format-agnostik (her yerde gecerli). Ornek: coreutils
    # `cat` icindeki "Richard M. Stallman" krediisi `b"Rich"` byte
    # pattern'ine eslesip ELF'i "MSVC compiled" gosteriyordu.
    formats: list[str] = field(default_factory=list)
    arch: list[str] = field(default_factory=list)

    def pattern_ids(self) -> list[str]:
        return ([f"$b{i}" for i in range(len(self.byte_patterns))]
                + [f"$s{i}" for i in range(len(self.string_patterns))])

    def resolved_condition(self) -> Cond:
        c = self.condition
        if isinstance(c, Cond):
            return c
        if c == "all":
            n = len(self.pattern_ids())
            return Cond(lambda ev: ev.distinct() >= n and n > 0, "all of them")
        if isinstance(c, int):
            return of(c)
        return of(1)

    def yara_prefilter(self) -> str:
        """YARA kaynagi icin GEREKLI on kosul (son hukmu _evaluate verir)."""
        c = self.condition
        if c == "all":
            return "all of them"
        if isinstance(c, int) and c > 1:
            return f"{c} of them"
        return "any of them"


def _hex(s: str) -> bytes:
    """Hex string'i bytes'a cevir. Bosluklar ignore edilir."""
    return bytes.fromhex(s.replace(" ", ""))


def _split_flags(pattern: str) -> tuple[str, bool, bool]:
    """``(?i)``, ``(?s)``, ``(?is)`` onekini ayir -> (desen, nocase, dotall)."""
    m = re.match(r"^\(\?([is]+)\)", pattern)
    if not m:
        return pattern, False, False
    flags = m.group(1)
    return pattern[m.end():], "i" in flags, "s" in flags


# Rich basligi: DOS koku ile PE basligi arasinda olmali; bu ozel kimlik
# yalniz MSVC kuralinda, yapisal olarak (Python tarafinda) doldurulur.
def _rich_header_hit(data: bytes, binfo: _BinaryInfo) -> list[tuple[int, bytes]]:
    if binfo.pe is None:
        return []
    end = min(binfo.pe.e_lfanew, len(data))
    pos = data.find(b"Rich", 0x40, end)
    return [(pos, b"Rich")] if pos >= 0 else []


def _builtin_rules() -> list[BuiltinRule]:
    """Karadul dahili YARA kurallarini dondurur."""
    rules: list[BuiltinRule] = []

    # ===================================================================
    # CRYPTO KUTUPHANE TESPITI
    # ===================================================================

    rules.append(BuiltinRule(
        name="AES_SBox",
        tags=["crypto", "aes"],
        meta={"description": "AES S-Box lookup table", "severity": "info"},
        byte_patterns=[
            # AES S-box ilk 16 byte
            _hex("63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76"),
        ],
    ))

    rules.append(BuiltinRule(
        name="SHA256_Init_Constants",
        tags=["crypto", "sha256"],
        meta={"description": "SHA-256 initialization hash values (H0..H3)", "severity": "info"},
        byte_patterns=[
            # SHA-256 H0..H3 (big-endian): 6a09e667 bb67ae85 3c6ef372 a54ff53a
            _hex("6A09E667 BB67AE85 3C6EF372 A54FF53A"),
        ],
    ))

    rules.append(BuiltinRule(
        name="SHA256_Round_Constants",
        tags=["crypto", "sha256"],
        meta={"description": "SHA-256 round constants (K[0..3])", "severity": "info"},
        byte_patterns=[
            # K[0..3]: 428a2f98 71374491 b5c0fbcf e9b5dba5
            _hex("428A2F98 71374491 B5C0FBCF E9B5DBA5"),
        ],
    ))

    rules.append(BuiltinRule(
        name="OpenSSL_Library",
        tags=["crypto", "openssl"],
        meta={"description": "OpenSSL library strings", "severity": "info"},
        string_patterns=[
            r"OpenSSL \d+\.\d+\.\d+",          # surum afisi: "OpenSSL 3.5.0 8 Apr 2025"
            r"\bSSLeay\b",
            r"\blibssl[.\-](so|dylib|\d)",     # bagli kitaplik adi: libssl.so.3, libssl.3.dylib
        ],
    ))

    rules.append(BuiltinRule(
        name="wolfSSL_Library",
        tags=["crypto", "wolfssl"],
        meta={"description": "wolfSSL embedded TLS library", "severity": "info"},
        string_patterns=[
            r"\bwolfSSL",
            r"\bCyaSSL",
            r"\bwolfCrypt",
        ],
    ))

    rules.append(BuiltinRule(
        name="mbedTLS_Library",
        tags=["crypto", "mbedtls"],
        meta={"description": "Mbed TLS (formerly PolarSSL) library", "severity": "info"},
        string_patterns=[
            r"\bmbedTLS\b",
            r"\bmbed TLS\b",
            r"\bPolarSSL\b",
            r"\bmbedtls_ssl_",
        ],
    ))

    rules.append(BuiltinRule(
        name="libsodium_Library",
        tags=["crypto", "libsodium"],
        meta={"description": "libsodium (NaCl) crypto library", "severity": "info"},
        string_patterns=[
            r"\bsodium_init\b",
            r"\bcrypto_secretbox",
            r"\bcrypto_box_seal",
            r"\bcrypto_aead_",
        ],
        # Tek API adi (crypto_aead_ baska NaCl turevlerinde de var) yetmez.
        condition=2,
    ))

    rules.append(BuiltinRule(
        name="RSA_Public_Key_Constants",
        tags=["crypto", "rsa"],
        meta={"description": "RSA ASN.1 OID or common public exponent", "severity": "info"},
        byte_patterns=[
            # RSA OID: 1.2.840.113549.1.1.1 (DER encoded). Kod imzasi
            # (Mach-O LC_CODE_SIGNATURE, PE Authenticode) bolgesindeki
            # sertifika eslesmeleri genel bolge suzgeciyle dislanir.
            _hex("06 09 2A 86 48 86 F7 0D 01 01 01"),
        ],
    ))

    # ===================================================================
    # PACKER / PROTECTOR TESPITI
    # Paketleyici hukmu bolum adi / giris noktasi / paketleyici imzasi
    # gibi bicime bagli kanitla verilir; tek alt dizgi yetmez.
    # ===================================================================

    rules.append(BuiltinRule(
        name="UPX_Packed",
        tags=["packer", "upx"],
        meta={"description": "UPX packed binary", "severity": "warning"},
        byte_patterns=[
            b"UPX!",                       # $b0: UPX ust bilgi imzasi
        ],
        string_patterns=[
            r"\bUPX0\b",                   # $s0: bolum adlari
            r"\bUPX1\b",                   # $s1
            r"\$Info: This file is packed with the UPX",  # $s2
        ],
        # Imza + bolum adi ya da imza + $Info: iki bagimsiz kanit.
        condition=2,
    ))

    rules.append(BuiltinRule(
        name="VMProtect_Packed",
        tags=["packer", "vmprotect"],
        meta={"description": "VMProtect protected binary", "severity": "warning"},
        string_patterns=[
            r"\.vmp\d",                    # $s0: .vmp0/.vmp1 bolum adlari
            r"VMProtect begin",            # $s1: SDK isaretleri
            r"VMProtect end",              # $s2
        ],
        formats=["pe"],
        condition=any_(pe_section_re(r"\.vmp\d"), of(2, "$s1", "$s2")),
    ))

    rules.append(BuiltinRule(
        name="Themida_Packed",
        tags=["packer", "themida"],
        meta={"description": "Themida/WinLicense protected binary", "severity": "warning"},
        string_patterns=[
            r"\bThemida\b",                # $s0
            r"\bWinLicense\b",             # $s1
            r"\.themida",                  # $s2: bolum adi
            r"\.winlice",                  # $s3: bolum adi
        ],
        formats=["pe"],
        condition=any_(pe_section(".themida", ".winlice"), of(2, "$s0", "$s1")),
    ))

    rules.append(BuiltinRule(
        name="ASPack_Packed",
        tags=["packer", "aspack"],
        meta={"description": "ASPack packed binary", "severity": "warning"},
        string_patterns=[
            r"\.aspack",                   # $s0: bolum adi
            r"\.adata",                    # $s1: bolum adi
        ],
        formats=["pe"],
        # ASPack: kendi bolumu + giris noktasinda pushad; call (60 E8).
        condition=all_(pe_section(".aspack", ".adata"), pe_entry(_hex("60 E8"))),
    ))

    rules.append(BuiltinRule(
        name="PECompact_Packed",
        tags=["packer", "pecompact"],
        meta={"description": "PECompact packed binary", "severity": "warning"},
        string_patterns=[
            r"\bPECompact2\b",             # $s0
            r"\bPEC2",                     # $s1: bolum adi oneki
        ],
        formats=["pe"],
        condition=any_(has("$s0"), pe_section("PEC2", "PEC2TO", "PEC2MO")),
    ))

    rules.append(BuiltinRule(
        name="MPRESS_Packed",
        tags=["packer", "mpress"],
        meta={"description": "MPRESS packed binary", "severity": "warning"},
        string_patterns=[
            r"\.MPRESS1",                  # $s0: bolum adi
            r"\.MPRESS2",                  # $s1: bolum adi
        ],
        formats=["pe"],
        # MPRESS hukmu yalniz PE bolum tablosundaki .MPRESS1/.MPRESS2 ile.
        condition=pe_section(".MPRESS1", ".MPRESS2"),
    ))

    rules.append(BuiltinRule(
        name="Enigma_Protector",
        tags=["packer", "enigma"],
        meta={"description": "Enigma Protector", "severity": "warning"},
        string_patterns=[
            r"\bEnigma [Pp]rotector\b",    # $s0
            r"\.enigma\d",                 # $s1: bolum adi
        ],
        formats=["pe"],
        condition=any_(pe_section(".enigma1", ".enigma2"), has("$s0")),
    ))

    # ===================================================================
    # COMPILER TESPITI
    # ===================================================================

    rules.append(BuiltinRule(
        name="GCC_Compiler",
        tags=["compiler", "gcc"],
        meta={"description": "GCC compiled binary", "severity": "info"},
        string_patterns=[
            r"GCC: \(",                       # "GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0"
            r"\bgcc[ _\-]version\b",
            r"\bGNU C\d+ \d",
            r"\bcompiled by GNU C\b",
        ],
    ))

    rules.append(BuiltinRule(
        name="MSVC_Compiler",
        tags=["compiler", "msvc"],
        meta={"description": "MSVC compiled binary", "severity": "info"},
        string_patterns=[
            r"Microsoft \(R\) Optimizing Compiler",   # $s0
            r"\bMSVC\b",                               # $s1 (MSVCRT/MSVCP140 sayilmaz)
            r"\bVisual C\+\+",                         # $s2
            r"\bMicrosoft Visual Studio\b",            # $s3
            r"\b_MSC_VER\b",                           # $s4
        ],
        # MSVC + Rich header yalnizca Windows PE'de anlamli. Rich basligi
        # DOS koku ile PE basligi arasinda aranir (dosyanin herhangi bir
        # yerindeki "Rich", or. "Richard", sayilmaz).
        formats=["pe"],
        condition=any_(pe_rich_header(), of(2, "$s0", "$s1", "$s2", "$s3", "$s4")),
    ))

    rules.append(BuiltinRule(
        name="Clang_Compiler",
        tags=["compiler", "clang"],
        meta={"description": "Clang/LLVM compiled binary", "severity": "info"},
        string_patterns=[
            r"\bclang version \d+",
            r"\bApple LLVM\b",
            r"\bApple clang\b",
            r"\bLinker: LLD\b",
        ],
    ))

    rules.append(BuiltinRule(
        name="Rust_Compiler",
        tags=["compiler", "rust"],
        meta={"description": "Rust compiled binary", "severity": "info"},
        string_patterns=[
            r"\brustc/\d+\.\d+",               # "rustc/1.74.0"
            r"\brust_begin_unwind\b",
            r"\brust_panic\b",
            r"\bcore::panicking\b",
            r"\bstd::rt::lang_start\b",
        ],
    ))

    rules.append(BuiltinRule(
        name="Go_Compiler",
        tags=["compiler", "go"],
        meta={"description": "Go compiled binary", "severity": "info"},
        string_patterns=[
            r"\bgo1\.\d+(\.\d+)?\b",           # go1.21.0 gibi (tek basina zayif)
            r"Go build ID: ",
            r"\bruntime\.gopanic\b",
            r"\bruntime\.goexit\b",
            r"\bruntime/internal/",
        ],
        condition=2,
    ))

    rules.append(BuiltinRule(
        name="Swift_Compiler",
        tags=["compiler", "swift"],
        meta={"description": "Swift compiled binary", "severity": "info"},
        string_patterns=[
            r"\b_?swift_release\b",
            r"\b_?swift_retain\b",
            r"\bSwift runtime\b",
            r"\b_?swift_allocObject\b",
            r"\bswiftCore\b",
        ],
        condition=2,
    ))

    rules.append(BuiltinRule(
        name="Delphi_Compiler",
        tags=["compiler", "delphi"],
        meta={"description": "Delphi/Object Pascal compiled binary", "severity": "info"},
        byte_patterns=[
            # $b0: Pascal kisa dizgisi (uzunluk oneki 7) "TObject" -- RTTI tip
            # adi. C/C++ adlarindaki "TObject"/"tObject" bu bicimde olmaz.
            b"\x07TObject",
        ],
        string_patterns=[
            r"\bEmbarcadero Delphi\b",          # $s0
            r"\bBorland Delphi\b",              # $s1
            r"\bSystem\.SysUtils\b",            # $s2: XE2+ birim adi
            r"(?i)Software\\Borland\\Delphi\\RTL",  # $s3: RTL kayit defteri anahtari
        ],
        # Delphi'ye ozgu en az iki bagimsiz kanit.
        condition=2,
    ))

    rules.append(BuiltinRule(
        name="Nim_Compiler",
        tags=["compiler", "nim"],
        meta={"description": "Nim compiled binary", "severity": "info"},
        string_patterns=[
            r"\bNim/\d+\.\d+",
            r"\bnimMain\b",
            r"\bNimMain",
            r"\bnimGC_",
        ],
    ))

    # ===================================================================
    # ANTI-DEBUG / ANTI-ANALYSIS
    # Olagan calisma zamani API'leri (clock_gettime, QueryPerformanceCounter,
    # GetTickCount, sysctl, IsDebuggerPresent, SetUnhandledExceptionFilter
    # -- MSVC CRT bunlari her ikiliye koyar) tek basina kanit sayilmaz.
    # ===================================================================

    rules.append(BuiltinRule(
        name="AntiDebug_Ptrace",
        tags=["antidebug", "linux", "macos"],
        meta={"description": "ptrace-based anti-debugging (PTRACE_DENY_ATTACH)", "severity": "high"},
        string_patterns=[
            r"\bPTRACE_DENY_ATTACH\b",         # $s0
            r"\bPT_DENY_ATTACH\b",             # $s1
            # $s2: dogrudan sistem cagrisi -- mov eax, 0x200001A (macOS
            # ptrace) ve ardindan 16 bayt icinde syscall (0F 05).
            r"(?s)\xB8\x1A\x00\x00\x02.{0,16}\x0F\x05",
        ],
        condition=any_(has("$s0"), has("$s1"),
                       all_(has("$s2"), Cond(lambda ev: ev.binfo.fmt == "macho",
                                             "macho"))),
    ))

    rules.append(BuiltinRule(
        name="AntiDebug_IsDebuggerPresent",
        tags=["antidebug", "windows"],
        meta={"description": "Windows IsDebuggerPresent API call", "severity": "high"},
        string_patterns=[
            r"\bCheckRemoteDebuggerPresent\b",  # $s0: tek basina ayirt edici
            r"\bNtQueryInformationProcess\b",   # $s1
            r"\bIsDebuggerPresent\b",           # $s2: MSVC CRT'de olagan
            r"\bOutputDebugString[AW]?\b",      # $s3: MSVC CRT'de olagan
        ],
        formats=["pe"],
        # IsDebuggerPresent / OutputDebugString CRT'nin __report_gsfailure
        # yolunda her ikiliye girer; hukum CheckRemoteDebuggerPresent ile.
        condition=has("$s0"),
    ))

    rules.append(BuiltinRule(
        name="AntiDebug_Timing",
        tags=["antidebug", "timing"],
        meta={"description": "Timing-based anti-debug checks", "severity": "medium"},
        string_patterns=[
            # $s0: 32 bayt icinde iki rdtsc (0F 31) -- olcum + karsilastirma.
            r"(?s)\x0F\x31.{0,32}\x0F\x31",
        ],
        arch=["x86"],
        # rdtsc cifti zamanlama olcumunde de olagan (vim, ssh, top); hukum
        # yalniz ayni ikilide guclu bir anti-debug kaniti da varsa.
        condition=all_(has("$s0"), rule_matched(
            "AntiDebug_Ptrace", "AntiDebug_SysctlCheck", "AntiDebug_IsDebuggerPresent")),
    ))

    rules.append(BuiltinRule(
        name="AntiDebug_SysctlCheck",
        tags=["antidebug", "macos"],
        meta={"description": "macOS sysctl-based debugger detection", "severity": "high"},
        string_patterns=[
            r"\b_?sysctl\b",                   # $s0: sysctl simgesi
            r"\b_?getpid\b",                   # $s1: surecin kendi pid'i
            # $s2-$s4: mib = {CTL_KERN(1), KERN_PROC(14), KERN_PROC_PID(1)}
            r"(?s)\xC7\x45.\x01\x00\x00\x00\xC7\x45.\x0E\x00\x00\x00\xC7\x45.\x01\x00\x00\x00",
            r"(?s)\xC7\x44\x24.\x01\x00\x00\x00\xC7\x44\x24.\x0E\x00\x00\x00\xC7\x44\x24.\x01\x00\x00\x00",
            r"\x01\x00\x00\x00\x0E\x00\x00\x00\x01\x00\x00\x00",
            r"\bkern\.proc\.pid\b",            # $s5: sysctlbyname bicimi
        ],
        formats=["macho"],
        # sysctl tek basina olagan (ps, top, htop); kendi pid'iyle
        # KERN_PROC_PID sorgusu = sysctl + getpid + mib kaniti birlikte.
        condition=all_(has("$s0"), has("$s1"), of(1, "$s2", "$s3", "$s4", "$s5")),
    ))

    rules.append(BuiltinRule(
        name="AntiVM_Detection",
        tags=["antidebug", "antivm"],
        meta={"description": "Virtual machine detection patterns", "severity": "high"},
        string_patterns=[
            r"\bVMware\b",
            r"\bVirtualBox\b",
            r"\bQEMU\b",
            r"\bHyper-V\b",
            r"(?i)\bvboxguest\b",
            r"(?i)\bvmtoolsd\b",
        ],
        # Tek sanal makine adi (yardim metni, uyumluluk listesi) yetmez.
        condition=2,
    ))

    rules.append(BuiltinRule(
        name="AntiDebug_ProcessEnum",
        tags=["antidebug"],
        meta={"description": "Process enumeration for debugger/sandbox detection", "severity": "medium"},
        string_patterns=[
            r"\bCreateToolhelp32Snapshot\b",   # $s0
            r"\bProcess32First(W)?\b",         # $s1
            r"\bProcess32Next(W)?\b",          # $s2
            r"\bEnumProcesses\b",              # $s3
            # $s4: aranan analiz araci surec adlari (baglam kaniti)
            r"(?i)\b(ollydbg|x64dbg|x32dbg|windbg|idaq|idaq64|ida64|immunitydebugger|"
            r"wireshark|procmon|procmon64|procexp|procexp64|processhacker|fiddler)\.exe\b",
        ],
        formats=["pe"],
        # Surec listelemek tek basina hata ayiklayici aramak degildir
        # (or. pnpm fastlist bir surec listeleyicisidir).
        condition=all_(of(2, "$s0", "$s1", "$s2", "$s3"), has("$s4")),
    ))

    rules.append(BuiltinRule(
        name="AntiDebug_ExceptionTricks",
        tags=["antidebug"],
        meta={"description": "SEH/exception-based anti-debug tricks", "severity": "medium"},
        string_patterns=[
            r"\bUnhandledExceptionFilter\b",
            r"\bSetUnhandledExceptionFilter\b",
            r"\bRaiseException\b",
            r"\b__try\b",
        ],
        formats=["pe"],
        # Bu API'ler MSVC CRT'de olagan; hukum yalniz ayni ikilide guclu bir
        # anti-debug kaniti da varsa.
        condition=all_(of(2), rule_matched(
            "AntiDebug_IsDebuggerPresent", "AntiDebug_Ptrace", "AntiDebug_SysctlCheck")),
    ))

    # ===================================================================
    # OBFUSCATION TESPITI
    # ===================================================================

    rules.append(BuiltinRule(
        name="String_Encryption_XOR",
        # NOT: 'xor' YARA reserved keyword'u oldugu icin tag olarak
        # kullanilamaz (compile 377. satirda "unexpected <xor>" patliyordu).
        # 'xorobf' (XOR obfuscation) ile degistirildi -- v1.21 bug fix.
        tags=["obfuscation", "xorobf"],
        meta={"description": "XOR-based string encryption pattern", "severity": "medium"},
        byte_patterns=[
            # xor byte ptr [ecx+edx], al ; inc edx -- XOR cozme dongusu
            _hex("30 04 11 42"),           # $b0 (32-bit)
            _hex("30 04 0A FF C2"),        # $b1 (64-bit varyant)
        ],
        string_patterns=[
            r"\bxor_decode\b",
            r"\bdecrypt_string\b",
            r"\bstring_decrypt\b",
        ],
        arch=["x86"],
    ))

    rules.append(BuiltinRule(
        name="String_Encryption_RC4",
        tags=["obfuscation", "rc4"],
        meta={"description": "RC4-based string decryption", "severity": "medium"},
        string_patterns=[
            r"\brc4_crypt\b",
            r"\bRC4_set_key\b",
            r"\barcfour\b",
        ],
        # Kripto kitapliginin RC4 API'si (OpenSSL RC4_set_key) tek basina
        # dizgi sifrelemesi degildir.
        condition=2,
    ))

    rules.append(BuiltinRule(
        name="Control_Flow_Flattening",
        tags=["obfuscation", "cff"],
        meta={"description": "Control flow flattening markers", "severity": "medium"},
        string_patterns=[
            r"\b__ollvm_",
            r"\bOLLVM\b",
            r"\bobfuscator-llvm\b",
            r"\bbogus control flow\b",
        ],
    ))

    rules.append(BuiltinRule(
        name="Opaque_Predicates",
        tags=["obfuscation"],
        meta={"description": "Opaque predicate patterns (junk code)", "severity": "low"},
        byte_patterns=[
            # Tipik opaque predicate: xor eax,eax; jz always_taken
            _hex("33 C0 74"),               # $b0: xor eax,eax; jz (short)
            _hex("31 C0 74"),               # $b1: xor eax,eax; jz (short) - AT&T
        ],
        arch=["x86"],
        # Tek ornek derleyici ciktisinda rastlantisal olabilir; gizleyici
        # bunlari cok sayida ekler.
        condition=any_(count_at_least("$b0", 3), count_at_least("$b1", 3)),
    ))

    rules.append(BuiltinRule(
        name="Stack_String_Construction",
        tags=["obfuscation", "stackstrings"],
        meta={"description": "Stack-based string construction (anti-static analysis)", "severity": "medium"},
        string_patterns=[
            r"\bstack_string\b",
            r"\bstackStrings\b",
            # mov byte [rbp+d8], 'c' x6 ardisik (yazdirilabilir karakter)
            r"(?s)(\xC6\x45.[\x20-\x7E]){6}",
            # mov byte [rsp+d8], 'c' x6 ardisik
            r"(?s)(\xC6\x44\x24.[\x20-\x7E]){6}",
        ],
        arch=["x86"],
    ))

    # ===================================================================
    # COMPRESSION TESPITI
    # Veri imzasi (zlib 78 9C, LZ4/Zstd cerceve sihirli sayisi) kitapligin
    # varligini gostermez (or. `file` ikilisinin sihirli sayi tablosu);
    # yalniz destekleyici kanittir.
    # ===================================================================

    rules.append(BuiltinRule(
        name="Zlib_Library",
        tags=["compression", "zlib"],
        meta={"description": "zlib compression library", "severity": "info"},
        string_patterns=[
            r"\bdeflate \d+\.\d+(\.\d+)? Copyright",  # gomulu zlib telif afisi
            r"\binflate \d+\.\d+(\.\d+)? Copyright",
            r"\bzlib/\d+",
            r"\blibz\.(so\.1|1\.dylib|dylib)\b",     # bagli kitaplik
            r"\b_?(deflateInit2_|inflateInit2_|inflateInit_|deflateInit_|zlibVersion)\b",
        ],
    ))

    rules.append(BuiltinRule(
        name="LZ4_Library",
        tags=["compression", "lz4"],
        meta={"description": "LZ4 compression library", "severity": "info"},
        byte_patterns=[
            _hex("04 22 4D 18"),            # $b0: cerceve sihirli sayisi (destekleyici)
        ],
        string_patterns=[
            r"\b_?LZ4_compress",            # $s0
            r"\b_?LZ4_decompress",          # $s1
            r"\blz4/\d+",                   # $s2
            r"\bliblz4\.(so|\d|dylib)",     # $s3
        ],
        condition=of(1, "$s0", "$s1", "$s2", "$s3"),
    ))

    rules.append(BuiltinRule(
        name="Zstd_Library",
        tags=["compression", "zstd"],
        meta={"description": "Zstandard compression library", "severity": "info"},
        byte_patterns=[
            _hex("28 B5 2F FD"),            # $b0: cerceve sihirli sayisi (destekleyici)
        ],
        string_patterns=[
            r"\b_?ZSTD_compress",           # $s0
            r"\b_?ZSTD_decompress",         # $s1
            r"\bzstd/\d+",                  # $s2
            r"\blibzstd\.(so|\d|dylib)",    # $s3
        ],
        condition=of(1, "$s0", "$s1", "$s2", "$s3"),
    ))

    return rules


# ---------------------------------------------------------------------------
# YARA kural kaynak kodu uretimi
# ---------------------------------------------------------------------------

# YARA identifier syntax: [A-Za-z_][A-Za-z0-9_]* (en fazla 128 karakter)
_YARA_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")

# YARA dilinde ayrilmis kelimeler (libyara grammar). Bunlar rule adi VEYA
# tag olarak kullanilamaz; karakter setine uysalar bile compiler
# "unexpected <keyword>" syntax hatasi verir. v1.21 bug fix: 'xor' tag'i
# String_Encryption_XOR kuralinda compile'i 377. satirda patlatiyordu.
_YARA_RESERVED_KEYWORDS = frozenset({
    "all", "and", "any", "ascii", "at", "base64", "base64wide", "condition",
    "contains", "defined", "endswith", "entrypoint", "filesize", "for",
    "fullword", "global", "icontains", "iendswith", "iequals", "import", "in",
    "include", "int16", "int16be", "int32", "int32be", "int8", "int8be",
    "istartswith", "matches", "meta", "nocase", "none", "not", "of", "or",
    "private", "rule", "startswith", "strings", "them", "true", "false",
    "uint16", "uint16be", "uint32", "uint32be", "uint8", "uint8be", "wide",
    "xor",
})


def _validate_yara_identifier(name: str, kind: str = "identifier") -> str:
    """v1.10.0 Fix Sprint MED-2: YARA rule name / tag identifier dogrulama.

    Identifier YARA syntax'ine uygun olmali; uygun degilse rule injection
    onlemek icin ValueError atar. _rule_to_yara_source icinde cagrildigi
    yer: rule.name ve rule.tags. add_rule kullanan kodun bu kisiti bilmesi
    gerekir.

    v1.21 bug fix: Karakter seti regex'ine ek olarak YARA reserved keyword
    kontrolu eklendi. 'xor', 'all', 'and' gibi kelimeler regex'ten gecer ama
    YARA compiler bunlari rule adi/tag olarak reddeder (syntax error). Boyle
    bir kelime tespit edilirse ValueError atilir -- arayan kod isim/tag'i
    duzeltmelidir (ornegin 'xor' -> 'xorobf').
    """
    if not isinstance(name, str) or not _YARA_IDENT_RE.match(name):
        raise ValueError(
            f"Gecersiz YARA {kind}: {name!r} "
            f"(izinli: ^[A-Za-z_][A-Za-z0-9_]{{0,127}}$)"
        )
    if name.lower() in _YARA_RESERVED_KEYWORDS:
        raise ValueError(
            f"Gecersiz YARA {kind}: {name!r} YARA reserved keyword "
            f"(rule adi/tag olarak kullanilamaz)"
        )
    return name


def _escape_yara_meta(value: str) -> str:
    """v1.10.0 Fix Sprint MED-2: YARA meta string value escape.

    YARA meta stringleri double-quote ile delimit edilir. Kotu niyetli
    girdiler (rule injection) backslash ve double-quote kullanarak meta
    bloklarini kirip yeni rule/condition enjekte edebilir. Ayrica control
    karakterler (0x00-0x1F) YARA syntax'i bozabilir.

    Args:
        value: Escape edilecek string.

    Returns:
        Guvenli escape edilmis string.

    Raises:
        ValueError: value icinde control karakter (0x00-0x1F) varsa.
    """
    if not isinstance(value, str):
        value = str(value)
    for c in value:
        if ord(c) < 0x20:
            raise ValueError(
                f"YARA meta icinde control character yasak: 0x{ord(c):02x}"
            )
    # Sirasi onemli: once backslash, sonra double-quote
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _rule_to_yara_source(rule: BuiltinRule) -> str:
    """BuiltinRule'dan YARA kaynak kodu uret (yara-python compile icin).

    Uretilen kural formati:
        rule RuleName : tag1 tag2 {
            meta:
                description = "..."
            strings:
                $b0 = { HEX }
                $s0 = /regex/            (harf duyarli)
                $s1 = /regex/ nocase     (yalniz (?i) onekli desen)
            condition:
                N of them                (gerekli on kosul)
        }

    Kosulun tamami (bicim, bolum, giris noktasi, mimari, kod imzasi
    dislamasi, baska kural) Python tarafinda ``_evaluate`` ile iki arka uca
    ortak uygulanir; buradaki kosul yalniz gerekli bir on suzgectir.
    """
    parts = []

    # v1.10.0 Fix Sprint MED-2: Rule name ve tag identifier validasyonu
    # (kullanici add_rule ile enjekte edilmis ise rule injection riskine karsi).
    safe_name = _validate_yara_identifier(rule.name, kind="rule name")
    safe_tags = [_validate_yara_identifier(t, kind="tag") for t in (rule.tags or [])]

    # Rule header
    tag_str = " ".join(safe_tags)
    if tag_str:
        parts.append(f"rule {safe_name} : {tag_str} {{")
    else:
        parts.append(f"rule {safe_name} {{")

    # Meta
    if rule.meta:
        parts.append("    meta:")
        for k, v in rule.meta.items():
            if isinstance(v, str):
                # v1.10.0 Fix Sprint MED-2: YARA meta value icinde backslash/
                # double-quote escape, control char (0x00-0x1F) reddet.
                escaped = _escape_yara_meta(v)
                parts.append(f'        {k} = "{escaped}"')
            elif isinstance(v, bool):
                val = "true" if v else "false"
                parts.append(f"        {k} = {val}")
            elif isinstance(v, (int, float)):
                # sayisal degerleri dogrudan emit et (tip guvenligi)
                parts.append(f"        {k} = {v}")
            else:
                # Bilinmeyen tip (obje vb.) str'e cast ederken escape et
                escaped = _escape_yara_meta(str(v))
                parts.append(f'        {k} = "{escaped}"')

    # Strings -- kimlikler regex yedegiyle ayni ($b0.., $s0..)
    string_defs = []
    for i, bp in enumerate(rule.byte_patterns):
        hex_str = " ".join(f"{b:02X}" for b in bp)
        string_defs.append(f"        $b{i} = {{ {hex_str} }}")
    for i, sp in enumerate(rule.string_patterns):
        body, nocase, dotall = _split_flags(sp)
        escaped_sp = body.replace("/", "\\/")  # v1.9.1: YARA regex delimiter escape
        regex_lit = f"/{escaped_sp}/" + ("s" if dotall else "")
        mods = " nocase" if nocase else ""
        string_defs.append(f"        $s{i} = {regex_lit}{mods}")

    if string_defs:
        parts.append("    strings:")
        parts.extend(string_defs)

    parts.append("    condition:")
    parts.append(f"        {rule.yara_prefilter()}")

    parts.append("}")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Ortak hakem: isabet suzgeci + kosul degerlendirmesi
# ---------------------------------------------------------------------------

RawHits = dict[str, dict[str, list[tuple[int, bytes]]]]  # kural -> kimlik -> [(ofset, veri)]


def _in_regions(off: int, regions: list[tuple[int, int]]) -> bool:
    return any(a <= off < b for a, b in regions)


def _evaluate(
    rules: list[BuiltinRule], raw: RawHits, data: bytes, binfo: _BinaryInfo,
) -> list[YaraMatch]:
    """Iki arka ucun topladigi ham isabetten hukmu ver (tek anlambilim)."""
    x86_regions = [(a, b) for a, b, arch in binfo.arch_regions if arch == "x86"]

    def _filtered(rule: BuiltinRule) -> dict[str, list[tuple[int, bytes]]]:
        out: dict[str, list[tuple[int, bytes]]] = {}
        for ident, inst in raw.get(rule.name, {}).items():
            keep = []
            for off, blob in sorted(inst, key=lambda t: t[0]):
                if _in_regions(off, binfo.excluded_regions):
                    continue
                if "x86" in rule.arch and not _in_regions(off, x86_regions):
                    continue
                keep.append((off, blob))
                if len(keep) >= _MAX_INSTANCES_PER_STRING:
                    break
            if keep:
                out[ident] = keep
        if rule.name == "MSVC_Compiler":
            rich = _rich_header_hit(data, binfo)
            if rich:
                out["$rich"] = rich
        return out

    matched: list[YaraMatch] = []
    matched_names: set[str] = set()
    # Baska kurala dayanan kosullar ikinci turda (tek duzey bagimlilik).
    first = [r for r in rules if "rule(" not in r.resolved_condition().describe()]
    second = [r for r in rules if r not in first]
    for group in (first, second):
        for rule in group:
            if rule.formats and binfo.fmt not in rule.formats:
                continue
            hits = _filtered(rule)
            if not hits:
                continue
            ev = RuleEvidence(hits=hits, ids=rule.pattern_ids(), binfo=binfo,
                              matched_rules=set(matched_names))
            try:
                ok = rule.resolved_condition()(ev)
            except Exception:
                logger.debug("YARA: %s kosulu degerlendirilemedi", rule.name, exc_info=True)
                ok = False
            if not ok:
                continue
            matched_names.add(rule.name)
            strings = [(off, ident, blob)
                       for ident, inst in hits.items() for off, blob in inst]
            strings.sort(key=lambda t: (t[0], t[1]))
            meta = dict(rule.meta)
            meta.setdefault("condition", rule.resolved_condition().describe())
            matched.append(YaraMatch(
                rule=rule.name, tags=list(rule.tags), meta=meta,
                strings=strings, namespace="builtin",
            ))
    # Kural tanim sirasini koru (deterministik cikti).
    order = {r.name: i for i, r in enumerate(rules)}
    matched.sort(key=lambda m: order.get(m.rule, 0))
    return matched


# ---------------------------------------------------------------------------
# Ana scanner sinifi
# ---------------------------------------------------------------------------

class YaraScanner:
    """YARA rule scanner -- binary pattern matching.

    yara-python kurulu ise native YARA kullanir.
    Kurulu degilse regex-based fallback kullanir. Iki arka uc ayni ham
    isabeti toplar; hukmu ortak ``_evaluate`` verir.

    Attributes:
        yara_available: yara-python kurulu mu?
    """

    def __init__(self) -> None:
        self._yara_available = False
        self._yara: Any = None           # yara module reference
        self._compiled_rules: Any = None  # yara.Rules nesnesi (veya tuple birlesik)
        self._compile_error: str = ""
        self._builtin_rules: list[BuiltinRule] = []
        self._external_rule_paths: list[Path] = []
        self._rules_compiled = False

        try:
            import yara
            self._yara = yara
            self._yara_available = True
            logger.debug("yara-python mevcut, native backend kullanilacak")
        except ImportError:
            logger.debug("yara-python bulunamadi, regex fallback kullanilacak")

    @property
    def yara_available(self) -> bool:
        """yara-python kurulu mu?"""
        return self._yara_available

    @property
    def rule_count(self) -> int:
        """Yuklenmis toplam kural sayisi."""
        return len(self._builtin_rules)

    # ------------------------------------------------------------------
    # Kural yukleme
    # ------------------------------------------------------------------

    def load_builtin_rules(self) -> int:
        """Karadul'un dahili YARA kurallarini yukle.

        Dahili kurallar:
        - Crypto kutuphane tespiti (OpenSSL, libsodium, wolfSSL, mbedTLS)
        - Packer tespiti (UPX, VMProtect, Themida, ASPack, PECompact, MPRESS)
        - Compiler tespiti (GCC, MSVC, Clang, Rust, Go, Swift, Delphi, Nim)
        - Anti-debug pattern'leri (ptrace, IsDebuggerPresent, timing, VM)
        - String obfuscation tespiti (XOR, RC4, CFF, opaque predicates)
        - Compression (zlib, LZ4, Zstandard)

        Returns:
            Yuklenen kural sayisi.
        """
        self._builtin_rules = _builtin_rules()
        self._rules_compiled = False  # Yeniden compile gerekecek
        count = len(self._builtin_rules)
        logger.info("Dahili YARA kurallari yuklendi: %d kural", count)
        return count

    def load_rules(self, rules_path: Path) -> int:
        """YARA kural dosyalarini yukle (.yar, .yara).

        Sadece yara-python kuruluysa calisir. Kurulu degilse 0 dondurur ve
        uyari loglar.

        Args:
            rules_path: Tek dosya veya dizin. Dizin ise recursive tarar.

        Returns:
            Yuklenen dosya sayisi.
        """
        rules_path = Path(rules_path)

        if not self._yara_available:
            logger.warning(
                "yara-python kurulu degil, harici .yar dosyalari yuklenemez. "
                "Dahili kurallar (load_builtin_rules) regex fallback ile calisir."
            )
            return 0

        if not rules_path.exists():
            logger.error("YARA kural yolu bulunamadi: %s", rules_path)
            return 0

        paths: list[Path] = []
        if rules_path.is_file():
            paths.append(rules_path)
        else:
            for ext in ("*.yar", "*.yara"):
                paths.extend(sorted(rules_path.rglob(ext)))

        self._external_rule_paths.extend(paths)
        self._rules_compiled = False
        logger.info("Harici YARA dosyalari yuklendi: %d dosya", len(paths))
        return len(paths)

    def add_rule(self, rule: BuiltinRule) -> None:
        """Tek bir dahili kural ekle."""
        self._builtin_rules.append(rule)
        self._rules_compiled = False

    # ------------------------------------------------------------------
    # Tarama
    # ------------------------------------------------------------------

    def scan_file(self, file_path: Path) -> ScanResult:
        """Dosyayi YARA kurallariyla tara.

        Args:
            file_path: Taranacak dosya.

        Returns:
            ScanResult: Eslesmeler, sure, hatalar, durum.
        """
        file_path = Path(file_path)
        if not file_path.exists():
            return _error_result(f"Dosya bulunamadi: {file_path}")
        if not file_path.is_file():
            return _error_result(f"Dosya degil: {file_path}")

        try:
            data = file_path.read_bytes()
        except (OSError, PermissionError) as exc:
            return _error_result(f"Dosya okunamadi: {exc}")

        return self.scan_bytes(data)

    def scan_bytes(self, data: bytes) -> ScanResult:
        """Ham byte verisi tara.

        YARA kuruluysa native engine kullanir, yoksa regex fallback.
        Iki yolda da hukum ``_evaluate`` ile verilir.

        Args:
            data: Taranacak byte verisi.

        Returns:
            ScanResult
        """
        if not self._builtin_rules and not self._external_rule_paths:
            return _error_result("Kural yuklenmemis. Once load_builtin_rules() cagiriniz.")

        start = time.perf_counter()
        binfo = _binary_info(data)
        errors: list[str] = []
        fallback_reason = ""
        ext_matches: list[YaraMatch] = []

        raw: Optional[RawHits] = None
        backend = "regex-fallback"
        if self._yara_available:
            raw, ext_matches, yara_errors = self._raw_hits_yara(data)
            if raw is not None:
                backend = "yara-python"
            else:
                fallback_reason = "; ".join(yara_errors) or "yara-python taramasi basarisiz"
                errors.extend(yara_errors)
        if raw is None:
            raw = self._raw_hits_fallback(data)

        matches = _evaluate(self._builtin_rules, raw, data, binfo) + ext_matches

        elapsed_ms = (time.perf_counter() - start) * 1000.0

        return ScanResult(
            total_rules=self.rule_count,
            matches=matches,
            scan_time_ms=elapsed_ms,
            errors=errors,
            backend=backend,
            status=STATUS_RAN,
            status_reason="",
            fallback_reason=fallback_reason,
            target_format=binfo.fmt,
        )

    @staticmethod
    def _detect_format(data: bytes) -> str:
        """Magic byte'tan binary formatini tespit et: pe | elf | macho | ''.

        Bos string = bilinmeyen/format-agnostik (ham veri, arsiv vb.).
        """
        return _detect_format(data)

    # ------------------------------------------------------------------
    # Native YARA backend
    # ------------------------------------------------------------------

    def _compile_yara(self) -> None:
        """Tum kurallari yara-python ile compile et."""
        if self._rules_compiled and self._compiled_rules is not None:
            return

        yara = self._yara
        assert yara is not None, "_compile_yara called without yara module"
        sources: dict[str, str] = {}
        self._compile_error = ""

        # Dahili kurallar -> YARA kaynak koduna cevir
        if self._builtin_rules:
            builtin_src = "\n\n".join(
                _rule_to_yara_source(r) for r in self._builtin_rules
            )
            sources["builtin"] = builtin_src

        try:
            builtin = yara.compile(sources=sources) if sources else None
            ext = None
            if self._external_rule_paths:
                # Not: yara-python tek compile() cagrisinda sources +
                # filepaths birlestirilemiyor; ayri derlenir.
                filepaths = {
                    f"ext_{i}": str(p)
                    for i, p in enumerate(self._external_rule_paths)
                }
                ext = yara.compile(filepaths=filepaths)
            self._compiled_rules = (builtin, ext)
            self._rules_compiled = True
        except Exception as exc:
            logger.error("YARA compile hatasi: %s", exc)
            self._compile_error = f"YARA compile hatasi: {exc}"
            self._compiled_rules = None
            self._rules_compiled = False

    @staticmethod
    def _yara_instances(m: Any) -> dict[str, list[tuple[int, bytes]]]:
        out: dict[str, list[tuple[int, bytes]]] = {}
        for s in getattr(m, "strings", []) or []:
            if hasattr(s, "instances"):
                # yara-python >= 4.3
                for inst in s.instances:
                    out.setdefault(s.identifier, []).append(
                        (inst.offset, bytes(inst.matched_data)))
            else:
                # yara-python < 4.3: (offset, identifier, data) tuple
                out.setdefault(s[1], []).append((s[0], bytes(s[2])))
        return out

    def _raw_hits_yara(
        self, data: bytes,
    ) -> tuple[Optional[RawHits], list[YaraMatch], list[str]]:
        """yara-python ile ham isabet; basarisizsa (None, [], hatalar)."""
        try:
            self._compile_yara()
        except Exception as exc:  # pragma: no cover - _compile_yara kendi yakalar
            return None, [], [f"YARA compile hatasi: {exc}"]
        if self._compiled_rules is None:
            return None, [], [self._compile_error or "YARA kurallari compile edilemedi"]

        builtin, ext = self._compiled_rules
        raw: RawHits = {}
        ext_matches: list[YaraMatch] = []
        try:
            if builtin is not None:
                for m in builtin.match(data=data):
                    raw[m.rule] = self._yara_instances(m)
            if ext is not None:
                # Harici .yar kurallari kendi kosuluyla hukmeder (yerlesik
                # hakemin disinda; kosullari kullanicinin sorumlulugunda).
                for m in ext.match(data=data):
                    inst = self._yara_instances(m)
                    ext_matches.append(YaraMatch(
                        rule=m.rule,
                        tags=list(getattr(m, "tags", []) or []),
                        meta=dict(getattr(m, "meta", {}) or {}),
                        strings=sorted((o, i, b) for i, lst in inst.items() for o, b in lst),
                        namespace=getattr(m, "namespace", ""),
                    ))
        except Exception as exc:
            return None, [], [f"YARA scan hatasi: {exc}"]
        return raw, ext_matches, []

    # ------------------------------------------------------------------
    # Regex fallback backend
    # ------------------------------------------------------------------

    def _raw_hits_fallback(self, data: bytes) -> RawHits:
        """YARA yoksa regex-based ham isabet toplama.

        Bayt desenleri literal, metin desenleri bytes regex olarak (YARA ile
        ayni kimliklerle) aranir. PERF/MEM (v1.10.0 C5): regex dogrudan bytes
        uzerinde calisir, `decode` kopyasi yok.
        """
        raw: RawHits = {}
        for rule in self._builtin_rules:
            per: dict[str, list[tuple[int, bytes]]] = {}
            for i, bp in enumerate(rule.byte_patterns):
                inst = self._finditer(re.compile(re.escape(bp), re.DOTALL), data)
                if inst:
                    per[f"$b{i}"] = inst
            for i, sp in enumerate(rule.string_patterns):
                body, nocase, dotall = _split_flags(sp)
                flags = (re.IGNORECASE if nocase else 0) | (re.DOTALL if dotall else 0)
                try:
                    rx = re.compile(body.encode("latin-1"), flags)
                except re.error:
                    logger.debug("YARA fallback: regex derlenemedi (%s), literal", sp)
                    rx = re.compile(re.escape(body.encode("latin-1")), flags)
                inst = self._finditer(rx, data)
                if inst:
                    per[f"$s{i}"] = inst
            if per:
                raw[rule.name] = per
        return raw

    @staticmethod
    def _finditer(rx: re.Pattern, data: bytes) -> list[tuple[int, bytes]]:
        out: list[tuple[int, bytes]] = []
        for m in rx.finditer(data):
            out.append((m.start(), m.group()))
            # Hakem bolge suzgeci sonrasi en cok _MAX_INSTANCES_PER_STRING
            # tutar; dislanan bolgeler (kod imzasi) icin pay birakilir.
            if len(out) >= _MAX_INSTANCES_PER_STRING * 16:
                break
        return out

    # Geriye donuk ad: eski testler/araclar _scan_with_fallback cagirabilir.
    def _scan_with_fallback(self, data: bytes) -> tuple[list[YaraMatch], list[str]]:
        raw = self._raw_hits_fallback(data)
        return _evaluate(self._builtin_rules, raw, data, _binary_info(data)), []

    # ------------------------------------------------------------------
    # Yardimci
    # ------------------------------------------------------------------

    def get_rules_by_tag(self, tag: str) -> list[BuiltinRule]:
        """Belirli bir tag'a sahip dahili kurallari getir."""
        return [r for r in self._builtin_rules if tag in r.tags]

    def get_rule_names(self) -> list[str]:
        """Tum dahili kural isimlerini dondur."""
        return [r.name for r in self._builtin_rules]

    def get_stats(self) -> dict[str, Any]:
        """Scanner istatistikleri."""
        tag_counts: dict[str, int] = {}
        for rule in self._builtin_rules:
            for tag in rule.tags:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1

        return {
            "backend": "yara-python" if self._yara_available else "regex-fallback",
            "builtin_rules": len(self._builtin_rules),
            "external_files": len(self._external_rule_paths),
            "compiled": self._rules_compiled,
            "tag_distribution": tag_counts,
        }

    def __repr__(self) -> str:
        backend = "yara" if self._yara_available else "fallback"
        return f"<YaraScanner backend={backend} rules={self.rule_count}>"
