"""IDA FLIRT .pat dosyasi parser ve SignatureDB entegrasyonu.

FLIRT (Fast Library Identification and Recognition Technology):
- IDA Pro'nun kutuphane fonksiyon tanima sistemi
- Byte pattern + isim eslestirmesi
- %100 dogruluk (bilinen kutuphane fonksiyonlari)

Desteklenen formatlar:
1. .pat (text pattern) -- IDA FLIRT pattern dosyalari
2. .json (Karadul native) -- build-signature-db.py ciktisi
3. nm export -- Dogrudan binary'den symbol extraction

Kullanim:
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
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
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

# nm cikti satiri: "0000000100001234 T _function_name"
_NM_LINE_RE = re.compile(
    r"^(?P<addr>[0-9a-fA-F]+)\s+(?P<type>[TtDdBbSs])\s+(?P<name>\S+)$"
)


@dataclass
class FLIRTSignature:
    """FLIRT formatinda tek bir fonksiyon imzasi."""

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

        # Isim filtreleme: bos veya internal IDA isimler
        if not name or name.startswith("?"):
            return None

        byte_pattern, mask = self._hex_to_bytes_with_mask(hex_str)

        return FLIRTSignature(
            name=name,
            library=library,
            byte_pattern=byte_pattern,
            mask=mask,
            size=size,
            offset=offset,
            crc16=crc16,
            confidence=0.95,
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
        for entry in entries:
            if not isinstance(entry, dict):
                continue

            name = entry.get("name", "")
            if not name:
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
