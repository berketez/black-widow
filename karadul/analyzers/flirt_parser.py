"""IDA FLIRT .pat dosyasi parser ve SignatureDB entegrasyonu.

FLIRT (Fast Library Identification and Recognition Technology):
- IDA Pro'nun kutuphane fonksiyon tanima sistemi
- Byte pattern + isim eslestirmesi
- %100 dogruluk (bilinen kutuphane fonksiyonlari)

Desteklenen formatlar:
1. .pat (text pattern) -- IDA FLIRT pattern dosyalari (genisletilmis,
   public + reference + tail bytes destekli)
2. .json (Karadul native) -- build-signature-db.py ciktisi
   v2 girdisi (``"sig_format": 2``, 2026-09-25): seçici imza -- maskeli ön ek +
   fonksiyon uzunluğu + maskeli CRC16 + çağrı referansları. Üretici
   ``scripts/flirt/build_selective_signatures.py``; doğrulama
   ``selective_signature_from_entry``, eşleştirme ``BytePatternMatcher``.
3. nm export -- Dogrudan binary'den symbol extraction

v1.14 D1 genislemesi:
- ``FlirtPattern`` normalize internal IR (public symbols, references,
  wildcards, CRC16, tail bytes)
- ``FlirtTrieMatcher`` -- prefix byte trie + sliding window binary
  taramasi, O(n*alpha) lookup, CRC16 sekonder dogrulama
- ``parse_pat_file_full()`` -- yeni IR formatinda donus

Kullanim (eski API, backward compat):
    from karadul.analyzers.flirt_parser import FLIRTParser

    parser = FLIRTParser()

    # .pat dosyasindan yukle
    sigs = parser.load_pat_file("libc.pat")

    # nm ile dogrudan binary'den cikar
    sigs = parser.extract_from_binary("/usr/lib/libssl.dylib")

    # JSON'dan yukle
    sigs = parser.load_json_signatures("homebrew_sigs.json")

    # Tumunu SignatureDB'ye ekle
    parser.inject_into_signature_db(signature_db_instance, sigs)

Kullanim (v1.14 yeni IR + trie matcher):
    from karadul.analyzers.flirt_parser import (
        FLIRTParser, FlirtTrieMatcher, parse_pat_file_full,
    )

    patterns = parse_pat_file_full("libc.pat")  # list[FlirtPattern]
    matcher = FlirtTrieMatcher(patterns)
    matches = matcher.scan_binary(binary_bytes)
    # matches: list[FlirtMatch] (offset, pattern, crc_ok, score)
"""

from __future__ import annotations

import binascii
import json
import logging
import re
import shutil
import struct
import subprocess
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from karadul.core.safe_subprocess import resolve_tool

logger = logging.getLogger(__name__)

# v1.10.0 Batch 5B MED-15/16: FLIRT DoS koruma sabitleri.
# Bu degerler modul sabit -- caller istenirse monkey-patch edebilir.
# SecurityConfig ile tutarli:
#   max_flirt_entries=100_000
#   max_flirt_hex_length=512
_MAX_FLIRT_ENTRIES = 100_000
_MAX_FLIRT_HEX_LENGTH = 512

# .pat satir formati regex:
# HEXBYTES(.. wildcard iceren) CRC16 SIZE TOTAL :OFFSET NAME [REFERENCED...]
# Ornekler:
#   558BEC83EC10 0C 0025 003A :0000 _my_function
#   558BEC........8B4508 00 0000 001F :0000 _another_func ^0010 _ref_func
#   --- (separator / comment)
_PAT_LINE_RE = re.compile(
    r"^"
    r"(?P<hexbytes>[0-9A-Fa-f.]+)"   # Hex bytes (.. = wildcard)
    r"\s+"
    # v1.10.0 H7 (revize, Batch 3C): FLIRT .pat formatinda bu alan aslinda
    # "CRC16 alanin uzunlugu" (CRC'nin hesaplandigi byte sayisi, 0-255) ya
    # da dogrudan CRC16 degeri olabilir. IDA sigmake tool'u cogu zaman 2
    # hex digit (1 byte) olarak yazar (ornek: "0C", "AB"). Eski "{4}" kisiti
    # gecerli .pat satirlarini None'a dusuruyordu. 2 VEYA 4 digit kabul et.
    r"(?P<crc16>[0-9A-Fa-f]{2,4})"   # CRC16 alani (2 veya 4 hex digit)
    r"\s+"
    r"(?P<size>[0-9A-Fa-f]{4})"      # Fonksiyon boyutu (hex)
    r"\s+"
    r"(?P<total>[0-9A-Fa-f]{4})"     # Toplam boyut (hex)
    r"\s+"
    r":(?P<offset>[0-9A-Fa-f]{4})"   # Pattern offset
    r"\s+"
    r"(?P<name>\S+)"                  # Fonksiyon adi
    r"(?P<rest>.*)"                   # Geri kalan (referanslar vs.)
    r"$"
)

# v1.14 D1: Public symbol token (ilkinden sonrakiler):  ":NNNN [@]name"
# IDA .pat formatinda ek public ve local sembol tokenleri:
#   :0000 main :0010 helper :0020 @local
# '@' on eki: local (non-exported) sembolu isaret eder.
_PUBLIC_TOKEN_RE = re.compile(
    r":(?P<offset>[0-9A-Fa-f]+)\s+(?P<at>@?)(?P<name>[A-Za-z_$][A-Za-z0-9_$.@?]*)"
)

# v1.14 D1: Reference token: "^NNNN name"  (offset NNNN'de fonksiyon "name"e
# referans). Ornek: ^0010 _malloc
_REFERENCE_TOKEN_RE = re.compile(
    r"\^(?P<offset>[0-9A-Fa-f]+)\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$.@?]*)"
)

# v1.14 D1: Tail bytes blok: rest icinde son '...' ile baslayan ek hex/wildcard
# zinciri olabilir. (Cok seyrek, IDA "more bytes" devami)
_TAIL_BYTES_RE = re.compile(r"(?<!\S)(?P<tail>[0-9A-Fa-f.]{4,})$")

# nm cikti satiri: "0000000100001234 T _function_name"
_NM_LINE_RE = re.compile(
    r"^(?P<addr>[0-9a-fA-F]+)\s+(?P<type>[TtDdBbSs])\s+(?P<name>\S+)$"
)


@dataclass
class FLIRTSignature:
    """FLIRT formatinda tek bir fonksiyon imzasi.

    v1.14 D1 ekleri (geri uyumlu, default bos):
        public_symbols: ek public/local sembol listesi  [(offset, name), ...]
        references:     ``^OFFSET NAME`` referanslari   [(offset, name), ...]
        tail_bytes:     CRC sonrasi ek bayt zinciri (varsa)
        tail_mask:      tail icin maske
    """

    name: str
    library: str
    byte_pattern: bytes = b""       # Ilk N byte (leading bytes)
    mask: bytes = b""               # Wildcard mask (0xFF = kesin, 0x00 = wildcard)
    size: int = 0                   # Fonksiyon boyutu (biliniyorsa)
    offset: int = 0                 # Pattern offset
    crc16: int = 0                  # CRC16 kontrol
    confidence: float = 0.95        # FLIRT eslestirmeleri cok guvenilir
    category: str = ""              # "crypto", "compression", "network", ...
    purpose: str = ""               # "AES encryption initialization"
    # v1.14 D1 ekleri
    public_symbols: list[tuple[int, str]] = field(default_factory=list)
    references: list[tuple[int, str]] = field(default_factory=list)
    tail_bytes: bytes = b""
    tail_mask: bytes = b""
    # v2 seçici imza (2026-09-25). Varsayılanlar eski (v1) davranışı korur:
    # sig_format=1 olan imza eşleştiricide eskisi gibi işlenir.
    #   sig_format=2 -> ``size`` fonksiyon uzunluğu, ``crc16`` CRC DEĞERİ,
    #   ``crc16_length`` ön ekten sonra CRC'ye giren bayt sayısı, ``mask_rule``
    #   hedef baytlardan maskeyi yeniden türeten kural ("arm64").
    #   (.pat yolunda ``crc16`` alanı tarihsel olarak CRC uzunluğunu taşır;
    #   o yol değişmedi.)
    sig_format: int = 1
    crc16_length: int = 0
    mask_rule: str = ""

    def to_dict(self) -> dict[str, Any]:
        """JSON serialization icin dict'e cevir."""
        return {
            "name": self.name,
            "library": self.library,
            "category": self.category or self.library,
            "purpose": self.purpose,
            "confidence": self.confidence,
            "size": self.size,
        }


class FLIRTParser:
    """FLIRT pattern parser ve SignatureDB entegratoru.

    Bagimsiz modul: signature_db'ye import bagimliligi YOK.
    inject_into_signature_db() ile disaridan verilen herhangi bir
    SignatureDB objesine enjeksiyon yapilir.
    """

    def __init__(self) -> None:
        self._nm_path: Optional[str] = None
        self._otool_path: Optional[str] = None
        self._detect_tools()

    def _detect_tools(self) -> None:
        """nm ve otool araclarinin varligi kontrol et.

        v1.10.0 Batch 5B CRITICAL-2: resolve_tool ile PATH hijack koruma.
        shutil.which `$PATH` siralamasina baglidir; attacker
        ``~/.local/bin/nm`` yerlestirirse hijack edilir. resolve_tool
        yalnizca OS-kurulu whitelist path'lerden arac secer.
        """
        # macOS system nm tercih (Anaconda nm dylib okuyamayabilir)
        for candidate in ["/usr/bin/nm", "/Library/Developer/CommandLineTools/usr/bin/nm"]:
            if Path(candidate).is_file():
                self._nm_path = candidate
                break
        if not self._nm_path:
            self._nm_path = resolve_tool("nm")

        for candidate in ["/usr/bin/otool"]:
            if Path(candidate).is_file():
                self._otool_path = candidate
                break
        if not self._otool_path:
            self._otool_path = resolve_tool("otool")

    # ------------------------------------------------------------------
    # .pat dosyasi parsing
    # ------------------------------------------------------------------

    def load_pat_file(self, pat_path: str | Path) -> list[FLIRTSignature]:
        """IDA .pat (text pattern) dosyasini parse et.

        Format: HEXBYTES CRC16 SIZE TOTAL :OFFSET NAME [REFERENCED_NAMES...]

        Ornekler:
            558BEC83EC10 0C 0025 003A :0000 _my_function
            558BEC........8B4508 00 0000 001F :0000 _another_func

        ".." = wildcard byte

        Args:
            pat_path: .pat dosyasinin yolu.

        Returns:
            FLIRTSignature listesi.
        """
        pat_path = Path(pat_path)
        if not pat_path.exists():
            logger.warning("PAT dosyasi bulunamadi: %s", pat_path)
            return []

        signatures: list[FLIRTSignature] = []
        library_name = pat_path.stem  # dosya adi = kutuphane adi

        try:
            content = pat_path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.error("PAT dosyasi okunamadi: %s -- %s", pat_path, e)
            return []

        # v1.10.0 Batch 5B MED-15: entry sayisi ust siniri.
        # Malicious .pat 100M satir olabilir -> RAM patlar.
        for line_no, line in enumerate(content.splitlines(), 1):
            if len(signatures) >= _MAX_FLIRT_ENTRIES:
                logger.warning(
                    "FLIRT entry limit %d asildi (%s), geri kalan atlandi",
                    _MAX_FLIRT_ENTRIES, pat_path.name,
                )
                break
            line = line.strip()
            # Bos satir, yorum, separator
            if not line or line.startswith("#") or line.startswith("---"):
                continue

            sig = self._parse_pat_line(line, library_name)
            if sig is not None:
                signatures.append(sig)
            else:
                # Parse edilemeyen satirlar debug seviyesinde logla
                logger.debug("PAT satir %d parse edilemedi: %.80s", line_no, line)

        logger.info("PAT dosyasi yuklendi: %s -> %d imza", pat_path.name, len(signatures))
        return signatures

    def _parse_pat_line(self, line: str, library: str = "unknown") -> Optional[FLIRTSignature]:
        """Tek bir .pat satirini parse et.

        Args:
            line: .pat dosyasindan tek satir.
            library: Kutuphane adi (dosya adindan veya kullanicidan).

        Returns:
            FLIRTSignature veya None (parse edilemezse).
        """
        # v1.10.0 Batch 5B MED-16: hex pattern CPU DoS reddedici.
        # _PAT_LINE_RE icindeki `[0-9A-Fa-f.]+` quantifier O(n) ama satir
        # basi 100KB olsa regex match yine uzun surebilir. On-fly length
        # check hem regex'i hem sonraki hex->bytes donusumunu kisaltir.
        if len(line) > _MAX_FLIRT_HEX_LENGTH * 2:
            # Hex + meta fields toplami, guvenli ust sinir
            logger.debug("FLIRT .pat line cok uzun reddedildi: len=%d", len(line))
            return None

        m = _PAT_LINE_RE.match(line)
        if not m:
            return None

        hex_str = m.group("hexbytes")
        if len(hex_str) > _MAX_FLIRT_HEX_LENGTH:
            logger.warning(
                "FLIRT hex pattern %d > max %d, reddedildi",
                len(hex_str), _MAX_FLIRT_HEX_LENGTH,
            )
            return None
        crc16 = int(m.group("crc16"), 16)
        size = int(m.group("size"), 16)
        offset = int(m.group("offset"), 16)
        name = m.group("name")
        rest = m.group("rest") or ""

        # Isim filtreleme: bos veya internal IDA isimler
        if not name or name.startswith("?"):
            return None

        byte_pattern, mask = self._hex_to_bytes_with_mask(hex_str)

        # v1.14 D1: rest icinden public + reference + tail bytes parse et
        publics, refs, tail_b, tail_m = _parse_pat_rest(rest)

        return FLIRTSignature(
            name=name,
            library=library,
            byte_pattern=byte_pattern,
            mask=mask,
            size=size,
            offset=offset,
            crc16=crc16,
            confidence=0.95,
            public_symbols=publics,
            references=refs,
            tail_bytes=tail_b,
            tail_mask=tail_m,
        )

    def _hex_to_bytes_with_mask(self, hex_str: str) -> tuple[bytes, bytes]:
        """Hex string'i byte + mask'a cevir.

        "558BEC..8B45" -> (b'\\x55\\x8b\\xec\\x00\\x8b\\x45', b'\\xff\\xff\\xff\\x00\\xff\\xff')
        ".." = wildcard (mask=0x00)

        Args:
            hex_str: Hex string (".." wildcard iceren).

        Returns:
            (byte_pattern, mask) tuple.
        """
        pattern_bytes = bytearray()
        mask_bytes = bytearray()

        i = 0
        while i < len(hex_str):
            if i + 1 < len(hex_str) and hex_str[i] == "." and hex_str[i + 1] == ".":
                # Wildcard byte
                pattern_bytes.append(0x00)
                mask_bytes.append(0x00)
                i += 2
            elif i + 1 < len(hex_str):
                # Normal hex byte
                try:
                    byte_val = int(hex_str[i:i + 2], 16)
                    pattern_bytes.append(byte_val)
                    mask_bytes.append(0xFF)
                    i += 2
                except ValueError:
                    # Gecersiz hex char -- wildcard olarak isle
                    pattern_bytes.append(0x00)
                    mask_bytes.append(0x00)
                    i += 2
            else:
                # Tek kalan karakter -- atla
                i += 1

        return bytes(pattern_bytes), bytes(mask_bytes)

    # ------------------------------------------------------------------
    # nm/otool ile binary'den imza cikarma
    # ------------------------------------------------------------------

    def extract_from_binary(
        self, binary_path: str | Path, library_name: str = ""
    ) -> list[FLIRTSignature]:
        """nm ile binary'den FLIRT-benzeri imzalar cikar.

        1. nm -g ile export sembollerini al
        2. __TEXT segment offset bilgisini bul (otool -l veya varsayilan)
        3. Her sembol adresinden dogrudan binary okuma ile ilk 32 byte al
        4. FLIRTSignature olustur

        Bu gercek FLIRT degil ama ayni prensibi kullaniyor:
        bilinen kutuphanelerdeki fonksiyon isimlerini byte pattern'le
        eslestirmeye hazirlama.

        Args:
            binary_path: Binary dosya yolu (.dylib, .a, Mach-O).
            library_name: Kutuphane adi (bos ise dosya adindan turetilir).

        Returns:
            FLIRTSignature listesi.
        """
        binary_path = Path(binary_path)
        if not binary_path.exists():
            logger.warning("Binary bulunamadi: %s", binary_path)
            return []

        if not self._nm_path:
            logger.warning("nm araci bulunamadi, binary extraction yapilamaz")
            return []

        if not library_name:
            library_name = binary_path.stem
            # lib prefix'ini kaldir (libssl -> ssl, libcurl -> curl)
            if library_name.startswith("lib"):
                library_name = library_name[3:]

        # 1. nm -g ile global (export) sembollerini al
        symbols = self._run_nm(binary_path)
        if not symbols:
            return []

        # 2. __TEXT segment bilgisini al (vmaddr, fileoff)
        text_vmaddr, text_fileoff = self._get_text_segment_info(binary_path)

        # 3. Binary dosya boyutunu al (bounds check icin)
        try:
            file_size = binary_path.stat().st_size
        except OSError:
            file_size = 0

        signatures: list[FLIRTSignature] = []
        for addr, sym_type, name in symbols:
            # Sadece text (code) sembolleri: T veya t
            if sym_type.upper() != "T":
                continue

            # Internal/compiler sembollerini filtrele
            if self._should_skip_symbol(name):
                continue

            # Dogrudan binary'den ilk 32 byte'i oku
            byte_pattern = b""
            if text_vmaddr is not None and text_fileoff is not None and file_size > 0:
                file_offset = addr - text_vmaddr + text_fileoff
                if 0 <= file_offset < file_size:
                    byte_pattern = self._read_bytes_at_offset(
                        binary_path, file_offset, size=32,
                    )

            sig = FLIRTSignature(
                name=name,
                library=library_name,
                byte_pattern=byte_pattern,
                mask=b"\xff" * len(byte_pattern) if byte_pattern else b"",
                confidence=0.90 if byte_pattern else 0.85,
            )
            signatures.append(sig)

        logger.info(
            "Binary extraction: %s -> %d sembol (%d byte pattern'li)",
            binary_path.name,
            len(signatures),
            sum(1 for s in signatures if s.byte_pattern),
        )
        return signatures

    def _run_nm(self, binary_path: Path) -> list[tuple[int, str, str]]:
        """nm -g ile export sembollerini cikar.

        Returns:
            [(address, type, name), ...] listesi.
        """
        if not self._nm_path:
            return []
        try:
            result = subprocess.run(
                [self._nm_path, "-g", str(binary_path)],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            logger.warning("nm komutu basarisiz: %s -- %s", binary_path, e)
            return []

        symbols: list[tuple[int, str, str]] = []
        for line in result.stdout.splitlines():
            m = _NM_LINE_RE.match(line.strip())
            if m:
                addr = int(m.group("addr"), 16)
                sym_type = m.group("type")
                name = m.group("name")
                symbols.append((addr, sym_type, name))

        return symbols

    def _get_text_segment_info(self, binary_path: Path) -> tuple[Optional[int], Optional[int]]:
        """__TEXT segment'in vmaddr ve fileoff degerlerini bul.

        otool -l veya objdump ile Mach-O header'dan __TEXT segment
        bilgisini cikarir. ELF/PE binary'ler icin basit heuristik
        kullanir (vmaddr=0, fileoff=0 varsayimi).

        Returns:
            (vmaddr, fileoff) tuple. Bulunamazsa (None, None).
        """
        if self._otool_path:
            return self._parse_text_segment_otool(binary_path)

        # otool yoksa binary header'dan basit parse dene
        return self._parse_text_segment_header(binary_path)

    def _parse_text_segment_otool(self, binary_path: Path) -> tuple[Optional[int], Optional[int]]:
        """otool -l ciktisından __TEXT segment vmaddr ve fileoff parse et."""
        if not self._otool_path:
            return None, None
        try:
            result = subprocess.run(
                [self._otool_path, "-l", str(binary_path)],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            logger.warning("otool -l basarisiz: %s -- %s", binary_path, e)
            return None, None

        if result.returncode != 0:
            return None, None

        # otool -l ciktisinda __TEXT segment'i bul:
        #   cmd LC_SEGMENT_64
        #   cmdsize ...
        #   segname __TEXT
        #   vmaddr 0x0000000100000000
        #   ...
        #   fileoff 0
        lines = result.stdout.splitlines()
        in_text_segment = False
        vmaddr: Optional[int] = None
        fileoff: Optional[int] = None

        for line in lines:
            stripped = line.strip()

            if stripped.startswith("segname __TEXT"):
                in_text_segment = True
                continue

            if in_text_segment:
                if stripped.startswith("segname "):
                    # Baska bir segment'e gectik
                    break

                if stripped.startswith("vmaddr "):
                    try:
                        vmaddr = int(stripped.split()[-1], 0)
                    except (ValueError, IndexError):
                        pass

                if stripped.startswith("fileoff "):
                    try:
                        fileoff = int(stripped.split()[-1], 0)
                    except (ValueError, IndexError):
                        pass

                if vmaddr is not None and fileoff is not None:
                    break

        if vmaddr is not None and fileoff is not None:
            logger.debug(
                "__TEXT segment: vmaddr=0x%x, fileoff=0x%x", vmaddr, fileoff,
            )
            return vmaddr, fileoff

        logger.debug("__TEXT segment bilgisi bulunamadi: %s", binary_path)
        return None, None

    def _parse_text_segment_header(self, binary_path: Path) -> tuple[Optional[int], Optional[int]]:
        """Binary header'dan basit __TEXT segment bilgisi cikar.

        otool yoksa fallback: Mach-O magic ile minimal parse.
        ELF/PE icin basit heuristik (segment base = 0 varsayimi).
        """
        try:
            with open(binary_path, "rb") as f:
                magic = f.read(4)
        except OSError:
            return None, None

        # ELF binary: segment base genellikle 0 (pie haricinide)
        # Basit heuristik: vmaddr = 0, fileoff = 0
        if magic[:4] == b"\x7fELF":
            # ELF'de .text section offset daha karmasik ama
            # basit durumlarda adres = file offset yaklasimi calisir
            logger.debug("ELF binary tespit edildi, basit offset varsayimi")
            return 0, 0

        # PE binary: MZ header
        if magic[:2] == b"MZ":
            logger.debug("PE binary tespit edildi, basit offset varsayimi")
            return 0, 0

        return None, None

    def _read_bytes_at_offset(self, binary_path: Path, offset: int, size: int = 32) -> bytes:
        """Binary dosyadan belirli offset'ten N byte oku.

        Args:
            binary_path: Binary dosya yolu.
            offset: Okunacak file offset.
            size: Okunacak byte sayisi (varsayilan 32).

        Returns:
            Okunan byte'lar. Hata olursa bos bytes.
        """
        try:
            with open(binary_path, "rb") as f:
                f.seek(offset)
                return f.read(size)
        except OSError as e:
            logger.debug("Binary okuma hatasi (offset=%d): %s", offset, e)
            return b""

    def _should_skip_symbol(self, name: str) -> bool:
        """Internal/compiler sembollerini filtrele.

        Args:
            name: Sembol adi.

        Returns:
            True ise atla.
        """
        # Bos isim
        if not name:
            return True

        # ObjC metadata, Swift metadata
        skip_prefixes = (
            "___", "ltmp", "l_", "L_", "GCC_except",
            "_OBJC_CLASS_$", "_OBJC_METACLASS_$", "_OBJC_IVAR_$",
            "__GLOBAL_", ".L",
        )
        for prefix in skip_prefixes:
            if name.startswith(prefix):
                return True

        # Cok kisa (< 2 karakter, muhtemelen label)
        clean = name.lstrip("_")
        if len(clean) < 2:
            return True

        return False

    # ------------------------------------------------------------------
    # JSON signature yukleme (build-signature-db.py ciktisi)
    # ------------------------------------------------------------------

    def load_json_signatures(self, json_path: str | Path) -> list[FLIRTSignature]:
        """build-signature-db.py ciktisini (JSON) yukle.

        JSON formati:
            {
                "signatures": [
                    {"name": "func", "library": "lib", "category": "cat", ...},
                    ...
                ],
                "total": 12345
            }

        Args:
            json_path: JSON dosyasinin yolu.

        Returns:
            FLIRTSignature listesi.
        """
        json_path = Path(json_path)
        if not json_path.exists():
            logger.warning("JSON signature dosyasi bulunamadi: %s", json_path)
            return []

        try:
            with open(json_path, encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.error("JSON parse hatasi: %s -- %s", json_path, e)
            return []

        entries = data.get("signatures", [])
        if not isinstance(entries, list):
            logger.warning("JSON dosyasinda 'signatures' listesi yok: %s", json_path)
            return []

        signatures: list[FLIRTSignature] = []
        rejected_selective = 0
        for entry in entries:
            if not isinstance(entry, dict):
                continue

            name = entry.get("name", "")
            if not name:
                continue

            # v2 seçici imza: alanları doğrulanamazsa imza ATILIR; asla eski
            # (yalnız ön ek) imzaya düşürülmez -- düşerse seçicilik sessizce kaybolur.
            if SELECTIVE_ENTRY_KEY in entry:
                sel = selective_signature_from_entry(entry)
                if sel is None:
                    rejected_selective += 1
                else:
                    signatures.append(sel)
                continue

            lib = entry.get("library", "unknown")
            category = entry.get("category", lib)
            purpose = entry.get("purpose", "")
            confidence = entry.get("confidence", 0.85)
            size = entry.get("size", 0)

            # Byte pattern (eger varsa)
            byte_pattern = b""
            mask = b""
            if "byte_pattern" in entry:
                try:
                    byte_pattern = bytes.fromhex(entry["byte_pattern"])
                    mask = b"\xff" * len(byte_pattern)
                except (ValueError, TypeError):
                    pass

            signatures.append(FLIRTSignature(
                name=name,
                library=lib,
                byte_pattern=byte_pattern,
                mask=mask,
                size=size,
                confidence=confidence,
                category=category,
                purpose=purpose,
            ))

        if rejected_selective:
            logger.warning(
                "JSON signatures: %s -> %d secici (v2) imza gecersiz, atlandi",
                json_path.name, rejected_selective,
            )
        logger.info("JSON signatures yuklendi: %s -> %d imza", json_path.name, len(signatures))
        return signatures

    # ------------------------------------------------------------------
    # Dizin tarama
    # ------------------------------------------------------------------

    def load_directory(self, dir_path: str | Path) -> list[FLIRTSignature]:
        """Bir dizindeki tum .pat, .json dosyalarini yukle.

        Args:
            dir_path: Taranacak dizin yolu.

        Returns:
            Tum dosyalardan birlestirilen FLIRTSignature listesi.
        """
        dir_path = Path(dir_path)
        if not dir_path.is_dir():
            logger.warning("Dizin bulunamadi: %s", dir_path)
            return []

        all_sigs: list[FLIRTSignature] = []

        # .pat dosyalari
        for pat_file in sorted(dir_path.glob("*.pat")):
            sigs = self.load_pat_file(pat_file)
            all_sigs.extend(sigs)

        # .json dosyalari
        for json_file in sorted(dir_path.glob("*.json")):
            sigs = self.load_json_signatures(json_file)
            all_sigs.extend(sigs)

        logger.info("Dizin taramasi: %s -> toplam %d imza", dir_path, len(all_sigs))
        return all_sigs

    # ------------------------------------------------------------------
    # SignatureDB entegrasyonu
    # ------------------------------------------------------------------

    def inject_into_signature_db(
        self,
        sig_db: Any,
        signatures: list[FLIRTSignature],
    ) -> tuple[int, int]:
        """Imzalari mevcut SignatureDB'ye ekle.

        sig_db._symbol_db dict'ine symbol-based eslestirme icin eklenir.
        Byte pattern'li imzalar sig_db.add_byte_signature() ile eklenir
        (eger sig_db'de bu metod varsa).

        Duplikasyon kontrolu yapilir: zaten var olan semboller atlanir
        (builtin DB onceligini korur).

        Args:
            sig_db: SignatureDB instance'i. Dogrudan import etmiyoruz,
                    duck-typing ile _symbol_db ve add_byte_signature kullaniriz.
            signatures: Eklenecek FLIRTSignature listesi.

        Returns:
            (eklenen_symbol_sayisi, eklenen_byte_pattern_sayisi) tuple.
        """
        if not hasattr(sig_db, "_symbol_db"):
            logger.error("sig_db'de _symbol_db bulunamadi -- SignatureDB degil mi?")
            return 0, 0

        added_symbols = 0
        added_byte_patterns = 0
        skipped = 0

        for sig in signatures:
            if not sig.name:
                continue

            # Symbol DB'ye ekle (duplikasyon kontrolu)
            if sig.name not in sig_db._symbol_db:
                sig_db._symbol_db[sig.name] = {
                    "lib": sig.library,
                    "purpose": sig.purpose,
                    "category": sig.category or sig.library,
                }
                added_symbols += 1
            else:
                skipped += 1

            # Byte pattern varsa, byte signature olarak da ekle
            if sig.byte_pattern and hasattr(sig_db, "add_byte_signature"):
                from karadul.analyzers.signature_db import FunctionSignature

                func_sig = FunctionSignature(
                    name=sig.name,
                    library=sig.library,
                    byte_pattern=sig.byte_pattern,
                    byte_mask=sig.mask,
                    size_range=(sig.size, sig.size) if sig.size > 0 else (0, 0),
                    purpose=sig.purpose,
                    category=sig.category or sig.library,
                )
                try:
                    sig_db.add_byte_signature(func_sig)
                    added_byte_patterns += 1
                except ValueError as e:
                    logger.debug("Byte pattern eklenemedi: %s -- %s", sig.name, e)

        logger.info(
            "SignatureDB injection: %d symbol eklendi, %d byte pattern eklendi, %d duplike atlandi",
            added_symbols, added_byte_patterns, skipped,
        )
        return added_symbols, added_byte_patterns

    # ------------------------------------------------------------------
    # Byte pattern eslestirme (standalone, SignatureDB olmadan)
    # ------------------------------------------------------------------

    def match_function_bytes(
        self,
        func_bytes: bytes,
        signatures: list[FLIRTSignature],
    ) -> list[tuple[FLIRTSignature, float]]:
        """Fonksiyonun ilk N byte'ini FLIRT imzalariyla karsilastir.

        Wildcard destegi: mask byte'i 0x00 olan pozisyonlar atlanir.

        Args:
            func_bytes: Fonksiyonun ilk N byte'i.
            signatures: Karsilastirilacak FLIRTSignature listesi.

        Returns:
            [(FLIRTSignature, confidence), ...] eslesen imza listesi,
            confidence'a gore azalan sirada.
        """
        if not func_bytes or not signatures:
            return []

        matches: list[tuple[FLIRTSignature, float]] = []

        for sig in signatures:
            if not sig.byte_pattern:
                continue

            pattern = sig.byte_pattern
            mask = sig.mask
            plen = len(pattern)

            # func_bytes yeterli uzunlukta mi
            if len(func_bytes) < plen:
                continue

            # Mask ve pattern uzunluk kontrolu
            if len(mask) != plen:
                continue

            # Masked compare
            matched = True
            for i in range(plen):
                if mask[i] == 0xFF:
                    if func_bytes[i] != pattern[i]:
                        matched = False
                        break
                # mask[i] == 0x00 -> wildcard, skip

            if matched:
                # Confidence: sabit byte orani
                fixed_bytes = sum(1 for b in mask if b == 0xFF)
                if plen > 0:
                    conf = min(0.98, sig.confidence * (fixed_bytes / plen))
                else:
                    conf = 0.0
                matches.append((sig, conf))

        # Confidence'a gore sirala
        matches.sort(key=lambda x: x[1], reverse=True)
        return matches

    # ------------------------------------------------------------------
    # Convenience: tek seferde yukle + inject
    # ------------------------------------------------------------------

    def load_and_inject(
        self,
        sig_db: Any,
        paths: list[str | Path],
    ) -> int:
        """Birden fazla dosya/dizinden yukle ve SignatureDB'ye inject et.

        Args:
            sig_db: SignatureDB instance'i.
            paths: .pat, .json dosya yollari veya dizin yollari.

        Returns:
            Toplam eklenen signature sayisi.
        """
        total_added = 0

        for path_str in paths:
            p = Path(path_str)

            if p.is_dir():
                sigs = self.load_directory(p)
            elif p.is_file():
                if p.suffix == ".pat":
                    sigs = self.load_pat_file(p)
                elif p.suffix == ".json":
                    sigs = self.load_json_signatures(p)
                else:
                    logger.warning("Desteklenmeyen dosya formati: %s", p)
                    continue
            else:
                logger.warning("Dosya/dizin bulunamadi: %s", p)
                continue

            added_sym, added_bp = self.inject_into_signature_db(sig_db, sigs)
            total_added += added_sym
            logger.info(
                "External signatures loaded: %s (%d sigs, %d new symbols)",
                p.name, len(sigs), added_sym,
            )

        return total_added

    # ------------------------------------------------------------------
    # Bulk JSON export (extract sonuclari kaydetmek icin)
    # ------------------------------------------------------------------

    def export_to_json(
        self,
        signatures: list[FLIRTSignature],
        output_path: str | Path,
        meta: Optional[dict[str, Any]] = None,
    ) -> None:
        """Signature listesini JSON olarak kaydet.

        build-signature-db.py uyumlu format kullanilir.

        Args:
            signatures: Kaydedilecek FLIRTSignature listesi.
            output_path: Cikti dosyasi yolu.
            meta: Ek metadata (generator, version vs).
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        data: dict[str, Any] = {
            "meta": meta or {"generator": "flirt_parser", "version": "1.0"},
            "signatures": [sig.to_dict() for sig in signatures],
            "total": len(signatures),
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        logger.info("JSON export: %s -> %d imza", output_path, len(signatures))


# ===========================================================================
# v1.14 Dalga 1 -- Genisletilmis FLIRT destegi
# ===========================================================================
#
# Bu blok eski FLIRTParser API'sini DEGISTIRMEZ. Yalnizca yeni veri yapilari
# ve ek fonksiyonlar ekler:
#   - _parse_pat_rest      : .pat satir 'rest' kismi -> publics + refs + tail
#   - compute_flirt_crc16  : IDA FLIRT CRC16 hesabi (CCITT-False)
#   - FlirtPattern         : Normalize internal IR (dataclass)
#   - parse_pat_file_full  : .pat -> list[FlirtPattern]
#   - FlirtMatch           : trie matcher cikti dataclass
#   - FlirtTrieMatcher     : prefix byte trie + sliding window scan
# ===========================================================================


def _parse_pat_rest(
    rest: str,
) -> tuple[list[tuple[int, str]], list[tuple[int, str]], bytes, bytes]:
    """``.pat`` satirinin 'rest' kismindan public + reference + tail bytes
    parse et.

    .pat satiri formati (rest):
        [:OFFSET NAME ...] [^OFFSET NAME ...] [TAILHEX]

    Args:
        rest: ana sembolden sonra kalan ham metin.

    Returns:
        ``(public_symbols, references, tail_bytes, tail_mask)`` tuple'i.
    """
    if not rest:
        return [], [], b"", b""

    publics: list[tuple[int, str]] = []
    references: list[tuple[int, str]] = []

    # Public ek sembol token'lari
    for pm in _PUBLIC_TOKEN_RE.finditer(rest):
        try:
            off = int(pm.group("offset"), 16)
        except ValueError:
            continue
        name = pm.group("name")
        if not name:
            continue
        publics.append((off, name))

    # Reference token'lari
    for rm in _REFERENCE_TOKEN_RE.finditer(rest):
        try:
            off = int(rm.group("offset"), 16)
        except ValueError:
            continue
        name = rm.group("name")
        if not name:
            continue
        references.append((off, name))

    # Tail bytes: rest'in sonunda 'AABB..CC' gibi bagimsiz hex grubu varsa.
    # Public/reference token'lari `:NAME` veya `^NAME` icerdigi icin
    # tail_bytes_re yalnizca SAF hex grubunu yakalar.
    tail_bytes = b""
    tail_mask = b""
    # rest'in sonunda public/reference TOKEN'inden sonra GELMIS hex grubu
    # arariz. Strateji: rest'i son public/reference end'inden itibaren al,
    # son token bitti ise oradan sonrasini tail kabul et.
    last_end = 0
    for pm in _PUBLIC_TOKEN_RE.finditer(rest):
        last_end = max(last_end, pm.end())
    for rm in _REFERENCE_TOKEN_RE.finditer(rest):
        last_end = max(last_end, rm.end())
    suffix = rest[last_end:].strip()
    if suffix:
        tm = _TAIL_BYTES_RE.search(suffix)
        if tm:
            tail_hex = tm.group("tail")
            # _hex_to_bytes_with_mask icin local kopya
            tail_bytes, tail_mask = _hex_to_bytes_with_mask_local(tail_hex)

    return publics, references, tail_bytes, tail_mask


def _hex_to_bytes_with_mask_local(hex_str: str) -> tuple[bytes, bytes]:
    """``FLIRTParser._hex_to_bytes_with_mask`` modul-duzeyi ikiz; saf
    fonksiyon olarak ihtiyac olan yerden cagirilabilir.
    """
    pattern_bytes = bytearray()
    mask_bytes = bytearray()
    i = 0
    n = len(hex_str)
    while i < n:
        if i + 1 < n and hex_str[i] == "." and hex_str[i + 1] == ".":
            pattern_bytes.append(0x00)
            mask_bytes.append(0x00)
            i += 2
        elif i + 1 < n:
            try:
                byte_val = int(hex_str[i:i + 2], 16)
                pattern_bytes.append(byte_val)
                mask_bytes.append(0xFF)
                i += 2
            except ValueError:
                pattern_bytes.append(0x00)
                mask_bytes.append(0x00)
                i += 2
        else:
            i += 1
    return bytes(pattern_bytes), bytes(mask_bytes)


# ---------------------------------------------------------------------------
# CRC16 (CCITT-False, IDA FLIRT konvansiyonu)
# ---------------------------------------------------------------------------
# Polinom 0x1021, baslangic 0xFFFF, refleksiyon yok, son XOR 0x0000.
# IDA FLIRT'in kullandigi varyant budur. Wildcard byte iceren bir bolge
# CRC'ye dahil edilemez -- caller wildcard'siz blok vermelidir.

def compute_flirt_crc16(data: bytes) -> int:
    """IDA FLIRT CRC16 (CCITT-False, poly 0x1021, init 0xFFFF).

    Args:
        data: Ham bayt blogu (wildcard YOK).

    Returns:
        16-bit CRC degeri (int).
    """
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


# ---------------------------------------------------------------------------
# Normalize internal IR
# ---------------------------------------------------------------------------

@dataclass
class FlirtPattern:
    """Normalize edilmis FLIRT pattern (v1.14 D1).

    Tek bir .pat satirina karsilik gelen, trie matcher icin uygun temiz
    veri yapisi.

    Alanlar:
        prefix_bytes:    ilk 32 bayt (tipik FLIRT "leading" bolge)
        prefix_mask:     prefix maskesi (0xFF=kesin, 0x00=wildcard)
        crc16_length:    CRC16'nin hesaplanacagi byte sayisi (.pat 2.alani)
        crc16:           beklenen CRC16 degeri
        tail_length:     toplam fonksiyon (TOTAL alani, .pat 4.alani)
        module_length:   bagimsiz modul uzunlugu (.pat 3.alani, SIZE)
        public_symbols:  ana + ek public/local sembol listesi
                         [(offset, name), ...]
        references:      ``^OFFSET NAME`` referanslar [(offset, name), ...]
        wildcards:       prefix icindeki wildcard araliklari
                         [(start, end), ...]  (yarim acik [start, end))
        tail_bytes:      varsa CRC sonrasi ek hex blogu
        tail_mask:       tail icin maske
        library:         imza kutuphanesi (kaynak .pat dosya adi)
    """

    prefix_bytes: bytes
    prefix_mask: bytes
    crc16_length: int
    crc16: int
    tail_length: int
    module_length: int
    public_symbols: list[tuple[int, str]] = field(default_factory=list)
    references: list[tuple[int, str]] = field(default_factory=list)
    wildcards: list[tuple[int, int]] = field(default_factory=list)
    tail_bytes: bytes = b""
    tail_mask: bytes = b""
    library: str = ""

    @property
    def primary_name(self) -> str:
        """Ana fonksiyon adi (offset 0'da olan public, yoksa ilk public)."""
        if not self.public_symbols:
            return ""
        for off, name in self.public_symbols:
            if off == 0:
                return name
        return self.public_symbols[0][1]

    @classmethod
    def from_signature(cls, sig: FLIRTSignature) -> "FlirtPattern":
        """Eski ``FLIRTSignature`` objesinden yeni IR olustur."""
        # Wildcard araliklari mask'tan tureyen [start, end) listesi
        wildcards: list[tuple[int, int]] = []
        in_wild = False
        wstart = 0
        for i, mb in enumerate(sig.mask):
            if mb == 0x00 and not in_wild:
                in_wild = True
                wstart = i
            elif mb != 0x00 and in_wild:
                in_wild = False
                wildcards.append((wstart, i))
        if in_wild:
            wildcards.append((wstart, len(sig.mask)))

        publics: list[tuple[int, str]] = [(sig.offset, sig.name)]
        # Eski parser ek public'leri sig.public_symbols'a koyar
        for off, nm in sig.public_symbols:
            if (off, nm) not in publics:
                publics.append((off, nm))

        return cls(
            prefix_bytes=sig.byte_pattern,
            prefix_mask=sig.mask,
            crc16_length=sig.size if sig.size else 0,
            crc16=sig.crc16,
            tail_length=sig.size,
            module_length=sig.size,
            public_symbols=publics,
            references=list(sig.references),
            wildcards=wildcards,
            tail_bytes=sig.tail_bytes,
            tail_mask=sig.tail_mask,
            library=sig.library,
        )


def parse_pat_file_full(pat_path: str | Path) -> list[FlirtPattern]:
    """``.pat`` dosyasini parse et ve normalize ``FlirtPattern`` listesi don.

    Bu fonksiyon ``FLIRTParser.load_pat_file`` ustunde ince bir adapter'dir;
    her ``FLIRTSignature`` ``FlirtPattern.from_signature`` ile cevrilir.

    Args:
        pat_path: .pat dosya yolu.

    Returns:
        Normalize edilmis pattern listesi (parse hatasi olanlar atlanir).
    """
    parser = FLIRTParser()
    sigs = parser.load_pat_file(pat_path)
    return [FlirtPattern.from_signature(s) for s in sigs]


# ---------------------------------------------------------------------------
# Trie matcher
# ---------------------------------------------------------------------------

@dataclass
class FlirtMatch:
    """Trie matcher cikti kaydi (v1.14 D1)."""

    offset: int                # Binary icindeki match baslangic offset'i
    pattern: FlirtPattern      # Eslesen pattern
    crc_ok: bool               # CRC16 dogrulama gectiyse True
    score: float               # 0..1, sabit byte orani * (crc_ok ? 1 : 0.5)


class _TrieNode:
    """Internal trie dugumu.

    children: byte -> _TrieNode
    wildcard_child: tek dugum (wildcard pozisyonu icin)
    terminal: bu dugumde biten pattern listesi (cogu terminal tek ama
              prefix paylasimi olabilir)
    """

    __slots__ = ("children", "wildcard_child", "terminal")

    def __init__(self) -> None:
        self.children: dict[int, _TrieNode] = {}
        self.wildcard_child: Optional[_TrieNode] = None
        self.terminal: list[FlirtPattern] = []


class FlirtTrieMatcher:
    """Prefix byte trie + sliding-window binary tarayici.

    Kullanim:
        matcher = FlirtTrieMatcher(patterns)
        matches = matcher.scan_binary(binary_bytes)

    Karmaşıklık:
        - Insa: O(toplam_prefix_uzunlugu)
        - Tarama: O(N * d_avg)  N = binary boyu, d_avg = wildcard
          dali genisligi (cogu prefix'te wildcard nadir oldugu icin
          d_avg ~ 1).
        - CRC16 dogrulama: yalnizca prefix eslesirse calisir, O(crc_len).

    Notlar:
        - Wildcard byte (mask=0x00) trie'de ayri "wildcard_child" dali
          olarak temsil edilir; tarama sirasinda butun byte degerlerini
          kabul eder.
        - Skor: prefix sabit-byte orani * (crc_ok ? 1.0 : 0.5).
        - score >= ``min_score`` filtresi caller'a sunulur (varsayilan
          0.0 -> hepsi).
    """

    def __init__(self, patterns: list[FlirtPattern]) -> None:
        self._root = _TrieNode()
        self._patterns: list[FlirtPattern] = []
        self._max_prefix_len = 0
        for pat in patterns:
            self._insert(pat)

    # -- insa --------------------------------------------------------------

    def _insert(self, pat: FlirtPattern) -> None:
        prefix = pat.prefix_bytes
        mask = pat.prefix_mask
        if not prefix or len(prefix) != len(mask):
            # Bos veya bozuk pattern -- atla
            return
        node = self._root
        for b, m in zip(prefix, mask, strict=False):
            if m == 0xFF:
                child = node.children.get(b)
                if child is None:
                    child = _TrieNode()
                    node.children[b] = child
                node = child
            else:
                if node.wildcard_child is None:
                    node.wildcard_child = _TrieNode()
                node = node.wildcard_child
        node.terminal.append(pat)
        self._patterns.append(pat)
        if len(prefix) > self._max_prefix_len:
            self._max_prefix_len = len(prefix)

    # -- tarama ------------------------------------------------------------

    def scan_binary(
        self,
        data: bytes,
        *,
        verify_crc: bool = True,
        min_score: float = 0.0,
        step: int = 1,
    ) -> list[FlirtMatch]:
        """Binary (bayt blogu) uzerinde sliding window tarama.

        Args:
            data: Taranacak binary icerik.
            verify_crc: CRC16 sekonder dogrulama yapilacak mi.
            min_score: bu eşiğin altindaki match'ler atilir.
            step: tarama adimi (varsayilan 1; bayt-bayt).

        Returns:
            Eslesme listesi (offset'e gore artan).
        """
        out: list[FlirtMatch] = []
        if not data or self._max_prefix_len == 0:
            return out

        n = len(data)
        # Her offset icin trie'de hosting
        # Trie wildcard cocuk varligi nedeniyle BFS frontier kullaniriz.
        for off in range(0, n, step):
            terminals = self._walk_at(data, off)
            if not terminals:
                continue
            for pat in terminals:
                score, crc_ok = self._verify_match(data, off, pat, verify_crc)
                if score < min_score:
                    continue
                out.append(FlirtMatch(
                    offset=off, pattern=pat, crc_ok=crc_ok, score=score,
                ))
        return out

    def _walk_at(self, data: bytes, start: int) -> list[FlirtPattern]:
        """``start`` offset'inden trie'yi yur, terminal pattern'lari topla.

        Wildcard cocuklar varsa frontier dallanir (BFS).
        """
        # Frontier: aktif (node, depth) tuple listesi
        frontier: list[tuple[_TrieNode, int]] = [(self._root, 0)]
        terminals: list[FlirtPattern] = []
        while frontier:
            new_frontier: list[tuple[_TrieNode, int]] = []
            for node, depth in frontier:
                # Eger bu dugum terminal ise topla (depth==prefix_len)
                if node.terminal:
                    # Yalniz pattern.prefix_len == depth olanlari al
                    for pat in node.terminal:
                        if len(pat.prefix_bytes) == depth:
                            terminals.append(pat)
                pos = start + depth
                if pos >= len(data):
                    continue
                b = data[pos]
                # Sabit byte cocuk
                child = node.children.get(b)
                if child is not None:
                    new_frontier.append((child, depth + 1))
                # Wildcard cocuk (her zaman gecerli)
                if node.wildcard_child is not None:
                    new_frontier.append((node.wildcard_child, depth + 1))
            frontier = new_frontier
        return terminals

    def _verify_match(
        self,
        data: bytes,
        off: int,
        pat: FlirtPattern,
        verify_crc: bool,
    ) -> tuple[float, bool]:
        """Eslesen pattern icin skor + CRC16 dogrulama.

        Skor: prefix icindeki sabit byte orani.
        CRC16: pat.crc16_length > 0 ise data[off+plen : off+plen+crc_len]
        bloku uzerinde hesapla, pat.crc16 ile karsilastir.
        """
        plen = len(pat.prefix_bytes)
        fixed = sum(1 for m in pat.prefix_mask if m == 0xFF)
        score = (fixed / plen) if plen else 0.0

        crc_ok = True
        if verify_crc and pat.crc16_length > 0:
            crc_start = off + plen
            crc_end = crc_start + pat.crc16_length
            if crc_end <= len(data):
                actual = compute_flirt_crc16(data[crc_start:crc_end])
                crc_ok = (actual == pat.crc16)
            else:
                crc_ok = False
            if not crc_ok:
                score *= 0.5

        return score, crc_ok

    # -- enviromental yardimcilar ----------------------------------------

    @property
    def max_prefix_len(self) -> int:
        """En uzun pattern prefix uzunlugu."""
        return self._max_prefix_len

    @property
    def pattern_count(self) -> int:
        """Trie'ye yuklenmis toplam pattern sayisi."""
        return len(self._patterns)


# ===========================================================================
# v2 seçici imza (2026-09-25) -- IDA FLIRT mantığı: ön ek + uzunluk + CRC16
# ===========================================================================
#
# Ölçülen sorun: v1 imzası yalnız fonksiyonun ilk 32 baytı (maskesiz). Tipik
# arm64 prologları bu 32 baytı paylaşıyor; imzaların kaynağında olmayan
# redis-server'da 162 isim / 0 doğru, jxl_from_tree'de 104 / 0.
# v2 imzası IDA FLIRT'ün ayırt edicilerini ekler:
#   * ön ek (32 bayt) -- bağlama adresine bağlı bitler maskeli,
#   * fonksiyon uzunluğu (``size``),
#   * ön ekten sonraki en fazla 255 baytın maskeli CRC16'sı.
# CRC bölgesinin maskesi imzada saklanmaz: hedef baytlardan AYNI kuralla
# yeniden türetilir. Kural yalnız maskelenmeyen (opcode/yazmaç) bitlere
# baktığı için aynı kod farklı adrese bağlansa da aynı maskeyi verir.

SELECTIVE_ENTRY_KEY = "sig_format"   # JSON'da v2 girdisini işaretleyen alan
SELECTIVE_SIG_FORMAT = 2
SELECTIVE_PREFIX_LEN = 32
SELECTIVE_MAX_CRC_LEN = 255          # IDA FLIRT: CRC uzunluğu tek bayt
MASK_RULE_ARM64 = "arm64"
# Çağrı referansı olmayan imza için en az "içerik kelimesi" (bkz.
# ``arm64_content_words``). Ölçüm (2026-09-25, ayar kümesi: imzaların kaynağında
# olmayan 17 Homebrew binary'si): referans kontrolünden sonra kalan 12 yanlış
# eşleşmenin hepsi referanssız ve içeriği 1-4 kelime; doğru eşleşmelerin
# (libzstd, statik bağlı zstd, cmake, elan-init; 743) 10'u <= 4. Bir kelime pay.
SELECTIVE_MIN_CONTENT_WORDS = 6


def arm64_reloc_mask(code: bytes) -> bytes:
    """arm64 kodunda bağlama/yükleme adresine bağlı bitleri sıfırlayan maske.

    Kelime (4 bayt, little-endian) bazında; 1 bit = karşılaştırılır:
      ADR / ADRP                   -> immlo + immhi maskeli (op + Rd kalır)
      B / BL (imm26)               -> hedef maskeli (yalnız opcode kalır)
      LDR / PRFM (literal, imm19)  -> ofset maskeli
      ADD (imm, 64-bit) ve LDR/STR (işaretsiz imm): taban yazmacı daha önce
          bir ADRP'nin hedefiyse imm12 maskeli (``:lo12:`` sayfa içi ofset)
    Diğer kelimeler maskelenmez (B.cond/CBZ/TBZ fonksiyon içidir, konumdan
    bağımsızdır). Kural yalnız maskelenmeyen bitlere baktığından
    ``arm64_reloc_mask(apply_mask(code, m)) == m`` (m = bu fonksiyonun çıktısı).
    Sonda 4'e tamamlanmayan baytlar maskelenmez.

    Doğrulama (2026-09-25): libzstd.1.5.7.dylib ile aynı sürümün libzstd.a'sını
    statik bağlayan program arasında 850 ortak fonksiyonun 610'u bayt-bayt aynı,
    240'ı yalnız bu kuralın maskelediği bitlerde farklı; kalan fark 0.
    """
    n_words = len(code) // 4
    masks: list[int] = []
    page_regs = 0  # ADRP hedefi olmuş yazmaçlar (bit i = x_i)
    for (w,) in struct.iter_unpack("<I", code[: 4 * n_words]):
        if (w & 0x1F000000) == 0x10000000:            # ADR / ADRP
            m = 0x9F00001F
            if w & 0x80000000:                         # ADRP: Rd sayfa adresi
                page_regs |= 1 << (w & 0x1F)
        elif (w & 0x7C000000) == 0x14000000:          # B / BL
            m = 0xFC000000
        elif (w & 0x3B000000) == 0x18000000:          # LDR / PRFM (literal)
            m = 0xFF00001F
        elif (
            (w & 0xFFC00000) == 0x91000000             # ADD Xd, Xn, #imm12
            or (w & 0x3B000000) == 0x39000000          # LDR/STR [Xn, #uimm12]
        ) and (page_regs >> ((w >> 5) & 0x1F)) & 1:
            m = 0xFFC003FF
        else:
            m = 0xFFFFFFFF
        masks.append(m)
    return struct.pack(f"<{n_words}I", *masks) + b"\xff" * (len(code) - 4 * n_words)


MASK_RULES: dict[str, Callable[[bytes], bytes]] = {
    MASK_RULE_ARM64: arm64_reloc_mask,
}


def _arm64_is_frame_or_move(word: int) -> bool:
    """Her fonksiyonda geçen kalıp kelimeler: bilgi taşımaz.

    SP tabanlı çift yükle/sakla (STP/LDP, GPR ve SIMD), SP'den/SP'ye ADD/SUB
    (``mov x29, sp``, ``sub sp, sp, #n``), yazmaçtan yazmaca MOV, RET, NOP.
    """
    if (word & 0x3A000000) == 0x28000000 and ((word >> 5) & 0x1F) == 31:
        return True                                     # STP/LDP ... [sp]
    if (word & 0xBF000000) == 0x91000000 and ((word >> 5) & 0x1F) == 31 and (word & 0x1F) in (29, 31):
        return True                                     # ADD/SUB x29|sp, sp, #imm
    if (word & 0x7FE0FFE0) == 0x2A0003E0:
        return True                                     # MOV Rd, Rm (ORR Rd, ZR, Rm)
    return word in (0xD65F03C0, 0xD503201F)             # RET, NOP


def arm64_content_words(code: bytes) -> int:
    """İmzanın bilgi miktarı: maskelenmeyen ve kalıp olmayan kelime sayısı.

    Relokasyonlu kelimeler (``arm64_reloc_mask``) ve ``_arm64_is_frame_or_move``
    kalıpları sayılmaz. Örnek: yalnız çerçeve kurup bir fonksiyonu çağırıp
    dönen sarmalayıcıların içeriği 0-1; bir enum->metin tablo fonksiyonu 3.
    """
    n_words = len(code) // 4
    mask = arm64_reloc_mask(code[: 4 * n_words])
    count = 0
    for (w,), (m,) in zip(
        struct.iter_unpack("<I", code[: 4 * n_words]), struct.iter_unpack("<I", mask),
    ):
        if m == 0xFFFFFFFF and not _arm64_is_frame_or_move(w):
            count += 1
    return count


def arm64_branch_target(word: int, pc: int) -> Optional[int]:
    """B/BL kelimesinin hedef adresi (``pc`` = kelimenin adresi); B/BL değilse None."""
    if (word & 0x7C000000) != 0x14000000:
        return None
    imm = word & 0x03FFFFFF
    if imm & 0x02000000:
        imm -= 1 << 26
    return pc + imm * 4


def arm64_call_refs(body: bytes, address: int) -> list[tuple[int, int]]:
    """Fonksiyon DIŞINA giden B/BL'ler: [(fonksiyon içi ofset, hedef adres), ...].

    ``body`` fonksiyonun tam gövdesi, ``address`` başlangıç adresi. Fonksiyon
    içine dallanan B'ler (döngü/atlama) referans değildir.
    """
    refs: list[tuple[int, int]] = []
    end = address + len(body)
    for i, (w,) in enumerate(struct.iter_unpack("<I", body[: len(body) // 4 * 4])):
        target = arm64_branch_target(w, address + 4 * i)
        if target is not None and not address <= target < end:
            refs.append((4 * i, target))
    return refs


def apply_mask(data: bytes, mask: bytes) -> bytes:
    """``data & mask`` (bayt bayt). Uzunluklar farklıysa kısa olana göre kesilir."""
    n = min(len(data), len(mask))
    if n == 0:
        return b""
    return (
        int.from_bytes(data[:n], "little") & int.from_bytes(mask[:n], "little")
    ).to_bytes(n, "little")


def masked_crc16(data: bytes, mask: bytes) -> int:
    """Maskeli bayt bloğunun IDA FLIRT CRC16'sı (CCITT-False, poly 0x1021, init 0xFFFF).

    ``binascii.crc_hqx(x, 0xFFFF)`` ``compute_flirt_crc16(x)`` ile aynı sonucu
    verir (C hızında; test ile kilitli).
    """
    return binascii.crc_hqx(apply_mask(data, mask), 0xFFFF)


def is_selective_signature(sig: Any) -> bool:
    """İmza v2 (seçici) biçiminde mi? Eski imzalarda alan yok -> False."""
    return getattr(sig, "sig_format", 1) >= SELECTIVE_SIG_FORMAT


def is_weak_selective(
    body: bytes,
    has_refs: bool,
    min_content_words: int = SELECTIVE_MIN_CONTENT_WORDS,
) -> bool:
    """Çağrı referansı yok ve içerik az -> bayt imzası fonksiyonu tanımlayamaz.

    Böyle fonksiyonlar (sarmalayıcı, yıkıcı thunk'ı, erişimci, enum->metin
    tablosu) başka programlarda maskeli olarak birebir tekrar ediyor; ölçümde
    imzaların kaynağında olmayan binary'lerdeki kalan yanlışların tamamı bu sınıf.
    """
    return not has_refs and arm64_content_words(body) < min_content_words


def build_selective_entry(
    name: str,
    library: str,
    body: bytes,
    *,
    category: str = "",
    purpose: str = "",
    confidence: float = 0.9,
    aliases: Iterable[str] = (),
    refs: Iterable[tuple[int, str]] = (),
    mask_rule: str = MASK_RULE_ARM64,
    min_content_words: int = SELECTIVE_MIN_CONTENT_WORDS,
) -> Optional[dict[str, Any]]:
    """Fonksiyonun TAM gövdesinden (``body`` = [başlangıç, bitiş)) v2 JSON girdisi.

    None döner:
      * gövde ön ekten kısaysa -- ön ek fonksiyonun dışına taşar (v1'in hatası:
        12 baytlık bir fonksiyonun 32 baytlık imzası sonraki fonksiyonu da içeriyordu);
      * imza zayıfsa (``is_weak_selective``: referans yok + içerik az).
    ``refs``: (ofset, isim) -- ofsetteki B/BL'nin hedefi, DB'de imzası olan bu
    isimli fonksiyon olmalı (IDA ``^OFFSET name``). Maskelenen çağrı hedefi
    yüzünden bayt olarak ikiz olan küçük sarmalayıcıları ayırır.
    Üretici (scripts/flirt) ve testler bu tek fonksiyonu kullanır; eşleştirici
    aynı ``MASK_RULES`` + ``masked_crc16`` ile doğrular.
    """
    rule = MASK_RULES[mask_rule]
    size = len(body)
    refs = list(refs)
    if size < SELECTIVE_PREFIX_LEN:
        return None
    if is_weak_selective(body, bool(refs), min_content_words):
        return None
    crc_len = min(size - SELECTIVE_PREFIX_LEN, SELECTIVE_MAX_CRC_LEN)
    region = body[: SELECTIVE_PREFIX_LEN + crc_len]
    mask = rule(region)
    return {
        "name": name,
        "library": library,
        "category": category or library,
        "purpose": purpose,
        "confidence": confidence,
        SELECTIVE_ENTRY_KEY: SELECTIVE_SIG_FORMAT,
        "mask_rule": mask_rule,
        "size": size,
        "byte_pattern": apply_mask(
            region[:SELECTIVE_PREFIX_LEN], mask[:SELECTIVE_PREFIX_LEN],
        ).hex(),
        "mask": mask[:SELECTIVE_PREFIX_LEN].hex(),
        "crc_len": crc_len,
        "crc16": masked_crc16(
            region[SELECTIVE_PREFIX_LEN:], mask[SELECTIVE_PREFIX_LEN:],
        ),
        "aliases": sorted(set(aliases) - {name}),
        "refs": [[int(off), str(ref)] for off, ref in sorted(set(refs))],
    }


def selective_signature_from_entry(entry: dict[str, Any]) -> Optional[FLIRTSignature]:
    """v2 JSON girdisini doğrulayıp ``FLIRTSignature``'a çevir; geçersizse None.

    Geçersiz sayılanlar: bilinmeyen biçim/maske kuralı, 32 bayt olmayan ön ek,
    desen-maske uzunluk farkı, fonksiyonun dışına taşan CRC bölgesi, 255'ten
    uzun CRC, maskesi kuraldan yeniden türetilemeyen ya da maskelenmiş bitleri
    sıfır olmayan desen (bozuk/elle düzenlenmiş DB).
    """
    try:
        if int(entry.get(SELECTIVE_ENTRY_KEY, 0)) != SELECTIVE_SIG_FORMAT:
            return None
        name = str(entry["name"])
        pattern = bytes.fromhex(entry["byte_pattern"])
        mask = bytes.fromhex(entry["mask"])
        size = int(entry["size"])
        crc_len = int(entry["crc_len"])
        crc = int(entry["crc16"])
        rule_name = str(entry["mask_rule"])
        confidence = float(entry.get("confidence", 0.9))
        aliases = [str(a) for a in (entry.get("aliases") or []) if a]
        refs = [(int(off), str(ref)) for off, ref in (entry.get("refs") or [])]
    except (KeyError, TypeError, ValueError, AttributeError):
        return None
    # Referans ofseti fonksiyon içinde, 4 hizalı bir kelime ve isim boş olmamalı.
    if any(off < 0 or off % 4 or off + 4 > size or not ref for off, ref in refs):
        return None
    rule = MASK_RULES.get(rule_name)
    if (
        not name
        or rule is None
        or len(pattern) != SELECTIVE_PREFIX_LEN
        or len(mask) != len(pattern)
        or not 0 <= crc_len <= SELECTIVE_MAX_CRC_LEN
        or size < len(pattern) + crc_len
        or not 0 <= crc <= 0xFFFF
    ):
        return None
    if apply_mask(pattern, mask) != pattern or rule(pattern) != mask:
        return None
    lib = entry.get("library", "unknown")
    return FLIRTSignature(
        name=name,
        library=lib,
        byte_pattern=pattern,
        mask=mask,
        size=size,
        crc16=crc,
        confidence=confidence,
        category=entry.get("category", lib),
        purpose=entry.get("purpose", ""),
        public_symbols=[(0, a) for a in aliases],
        references=refs,
        sig_format=SELECTIVE_SIG_FORMAT,
        crc16_length=crc_len,
        mask_rule=rule_name,
    )
