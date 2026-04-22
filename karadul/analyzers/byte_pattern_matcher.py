"""FUN_xxx fonksiyonlarini byte pattern ile tanima modulu.

Ghidra JSON'daki her fonksiyonun adres/boyut bilgisini kullanarak
binary'den byte'lari okur ve bilinen kutuphane fonksiyonlarinin
byte pattern'lariyla karsilastirir.

Pipeline entegrasyonu:
    ReconstructionStage._execute_binary() icinde c_namer'dan ONCE calistirilir.
    Sonuclar extracted_names dict'ine eklenir -> pre_names olarak c_namer'a gider.

Kullanim:
    from karadul.analyzers.byte_pattern_matcher import BytePatternMatcher

    matcher = BytePatternMatcher()
    result = matcher.match_unknown_functions(
        binary_path="/path/to/binary",
        functions_json="/path/to/ghidra_functions.json",
        known_signatures=flirt_signatures,  # list[FLIRTSignature]
    )
    print(f"{result.total_matched} FUN_xxx tanindi")
    for name, info in result.matches.items():
        print(f"  {name} -> {info['matched_name']} ({info['library']})")
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Ghidra auto-generated isimler: FUN_xxxxx, thunk_FUN_xxxxx, switch_FUN_xxxxx
_GHIDRA_AUTO_NAME_RE = re.compile(
    r"^(thunk_|switch_)?FUN_[0-9a-fA-F]+$"
)

# Minimum byte pattern uzunlugu (false positive onleme)
MIN_PATTERN_LENGTH = 16


@dataclass
class ByteMatchResult:
    """Byte pattern eslestirme sonucu."""

    total_functions: int = 0
    total_unknown: int = 0       # FUN_xxx sayisi
    total_matched: int = 0       # Byte pattern ile tanınan FUN_xxx sayisi
    matches: dict[str, dict[str, Any]] = field(default_factory=dict)
    # matches: {original_name: {matched_name, library, confidence, category, purpose}}
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    @property
    def match_rate(self) -> float:
        if self.total_unknown == 0:
            return 0.0
        return self.total_matched / self.total_unknown


class BytePatternMatcher:
    """Ghidra FUN_xxx fonksiyonlarini byte pattern ile tanima.

    1. Binary'den __TEXT segment offset bilgisini cikarir (otool -l)
    2. Ghidra functions.json'dan FUN_xxx fonksiyonlarinin adres/boyutunu okur
    3. Binary'den her FUN_xxx'in ilk 32 byte'ini okur
    4. Bilinen kutuphane signature'lariyla karsilastirir (masked compare)
    """

    def __init__(
        self,
        min_pattern_length: int = MIN_PATTERN_LENGTH,
        min_confidence: float = 0.60,
        read_size: int = 32,
        max_selective: Optional[int] = None,
        max_suspicious: int = 20,
    ) -> None:
        """
        Args:
            min_pattern_length: Eslestirme icin minimum byte pattern uzunlugu.
                16'dan kucuk pattern'ler false positive uretir.
            min_confidence: Eslestirme icin minimum confidence esigi.
            read_size: Her fonksiyondan okunacak byte sayisi.
            max_selective: Bu sayiya kadar match -> penalty yok (1-max_selective).
                None (default) ise ``max(2, min_pattern_length // 8)`` formulu
                kullanilir -- pattern ne kadar uzun olursa o kadar fazla
                eslestirmeye tolerans tanir (v1.10.0 M7). Kisa pattern + cok
                match = false positive; uzun pattern + cok match = normal
                compiler helper paylasimi.
            max_suspicious: Bu sayinin uzerinde match -> discard (max_suspicious+).
                max_selective+1 ile max_suspicious arasi confidence * 0.5.
        """
        self._min_pattern_length = max(min_pattern_length, 8)
        self._min_confidence = min_confidence
        self._read_size = read_size
        # v1.10.0 M7: pattern uzunluguna orantili selective esigi.
        # min_pattern_length=16 -> max_selective=2 (sıkı)
        # min_pattern_length=64 -> max_selective=8 (genis)
        if max_selective is None:
            max_selective = max(2, self._min_pattern_length // 8)
        self._max_selective = max_selective
        self._max_suspicious = max_suspicious
        self._otool_path = self._find_otool()
        self._lipo_path = self._find_lipo()

    @staticmethod
    def _find_otool() -> Optional[str]:
        """otool binary'sinin yolunu bul."""
        import shutil
        for candidate in ["/usr/bin/otool"]:
            if Path(candidate).is_file():
                return candidate
        return shutil.which("otool")

    @staticmethod
    def _find_lipo() -> Optional[str]:
        """lipo binary'sinin yolunu bul (universal binary fat header icin)."""
        import shutil
        for candidate in ["/usr/bin/lipo"]:
            if Path(candidate).is_file():
                return candidate
        return shutil.which("lipo")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def match_unknown_functions(
        self,
        binary_path: str | Path,
        functions_json: str | Path,
        known_signatures: list[Any],
    ) -> ByteMatchResult:
        """FUN_xxx fonksiyonlarinin byte'larini bilinen signature'larla karsilastir.

        Args:
            binary_path: Analiz edilen binary dosya yolu.
            functions_json: Ghidra functions.json dosya yolu.
            known_signatures: FLIRTSignature listesi (byte_pattern ve mask field'lari olan).

        Returns:
            ByteMatchResult -- eslestirme sonuclari.
        """
        start = time.monotonic()
        result = ByteMatchResult()
        binary_path = Path(binary_path)
        functions_json = Path(functions_json)

        # 1. Validate inputs
        if not binary_path.exists():
            result.errors.append(f"Binary bulunamadi: {binary_path}")
            return result
        if not functions_json.exists():
            result.errors.append(f"Functions JSON bulunamadi: {functions_json}")
            return result

        # Byte pattern'i olan signature'lari filtrele
        byte_sigs = [
            s for s in known_signatures
            if getattr(s, "byte_pattern", b"")
            and len(getattr(s, "byte_pattern", b"")) >= self._min_pattern_length
        ]
        if not byte_sigs:
            logger.debug("BytePatternMatcher: Yeterli uzunlukta byte pattern yok, atlaniyor")
            result.duration_seconds = time.monotonic() - start
            return result

        logger.info(
            "BytePatternMatcher: %d signature (>=%d byte pattern) ile eslestirme basliyor",
            len(byte_sigs), self._min_pattern_length,
        )

        # 2. __TEXT segment offset bilgisini al (fat_offset dahil)
        text_vmaddr, text_fileoff, fat_offset = self._get_text_segment_info(binary_path)
        if text_vmaddr is None or text_fileoff is None:
            result.errors.append("__TEXT segment bilgisi alinamadi")
            result.duration_seconds = time.monotonic() - start
            return result

        # 3. Binary dosya boyutu (bounds check)
        try:
            file_size = binary_path.stat().st_size
        except OSError as e:
            result.errors.append(f"Binary stat hatasi: {e}")
            result.duration_seconds = time.monotonic() - start
            return result

        # 4. Ghidra functions.json'u oku
        func_list = self._load_functions(functions_json)
        if func_list is None:
            result.errors.append("Functions JSON okunamadi veya parse edilemedi")
            result.duration_seconds = time.monotonic() - start
            return result

        result.total_functions = len(func_list)

        # 5. FUN_xxx fonksiyonlarini filtrele ve byte'larini oku
        unknown_funcs: list[dict[str, Any]] = []
        for func_entry in func_list:
            name = func_entry.get("name", "")
            if _GHIDRA_AUTO_NAME_RE.match(name):
                unknown_funcs.append(func_entry)

        result.total_unknown = len(unknown_funcs)

        if not unknown_funcs:
            logger.info("BytePatternMatcher: FUN_xxx fonksiyonu yok, atlaniyor")
            result.duration_seconds = time.monotonic() - start
            return result

        # 6. Binary'den tum FUN_xxx byte'larini oku (GPU ve Python path ortak)
        func_names: list[str] = []
        func_bytes_list: list[bytes] = []
        func_sizes: list[int] = []
        try:
            with open(binary_path, "rb") as bf:
                for func_entry in unknown_funcs:
                    name = func_entry.get("name", "")
                    addr_str = func_entry.get("address", func_entry.get("entry_point", ""))
                    func_size = func_entry.get("size", 0)

                    if not addr_str:
                        continue

                    # Adres parse
                    try:
                        addr = int(addr_str, 16) if isinstance(addr_str, str) else int(addr_str)
                    except (ValueError, TypeError):
                        continue

                    # File offset hesapla (fat_offset: universal binary slice offset)
                    file_offset = addr - text_vmaddr + text_fileoff + fat_offset
                    if file_offset < 0 or file_offset >= file_size:
                        continue

                    # Binary'den byte oku
                    fb = self._read_bytes(bf, file_offset, self._read_size)
                    if not fb or len(fb) < self._min_pattern_length:
                        continue

                    func_names.append(name)
                    func_bytes_list.append(fb)
                    func_sizes.append(func_size)

        except OSError as e:
            result.errors.append(f"Binary okuma hatasi: {e}")
            result.duration_seconds = time.monotonic() - start
            return result

        if not func_names:
            result.duration_seconds = time.monotonic() - start
            return result

        # 7. Byte pattern matching -- two-pass with selectivity
        #
        # Pass 1: Tum match'leri topla, her signature index icin usage count tut.
        #   raw_matches: [(func_index, matched_sig_index, match_tuple), ...]
        #   sig_usage:   Counter{sig_index: count}
        #
        # Pass 2: Selectivity filtresi uygula.
        #   count 1..max_selective  -> penalty yok
        #   count max_selective+1..max_suspicious -> confidence * 0.5
        #   count max_suspicious+1 -> discard (listeye ekleme)
        #
        sig_index = self._build_sig_index(byte_sigs)

        # Pass 1: raw matches + signature usage count
        raw_matches: list[tuple[int, int, tuple[str, str, float, str, str]]] = []
        sig_usage: Counter = Counter()

        for i, name in enumerate(func_names):
            func_bytes = func_bytes_list[i]
            func_size = func_sizes[i]

            match_with_idx = self._match_bytes_with_sig_index(
                func_bytes, func_size, byte_sigs, sig_index,
            )
            if match_with_idx is not None:
                best_sig_idx, match_tuple = match_with_idx
                raw_matches.append((i, best_sig_idx, match_tuple))
                sig_usage[best_sig_idx] += 1

        # Pass 2: selectivity filter
        matched_count = 0
        discarded_count = 0
        penalized_count = 0

        for func_i, best_sig_idx, match_tuple in raw_matches:
            matched_name, library, confidence, category, purpose = match_tuple
            usage_count = sig_usage[best_sig_idx]

            if usage_count > self._max_suspicious:
                # Too many matches -- noise, discard
                discarded_count += 1
                continue
            elif usage_count > self._max_selective:
                # Suspicious range -- apply penalty
                confidence = confidence * 0.5
                penalized_count += 1
                if confidence < self._min_confidence:
                    discarded_count += 1
                    continue

            name = func_names[func_i]
            result.matches[name] = {
                "matched_name": matched_name,
                "library": library,
                "confidence": round(confidence, 4),
                "category": category,
                "purpose": purpose,
                "match_method": "byte_pattern",
            }
            matched_count += 1

        result.total_matched = matched_count

        if discarded_count > 0 or penalized_count > 0:
            logger.info(
                "BytePatternMatcher selectivity: %d discarded, %d penalized "
                "(max_selective=%d, max_suspicious=%d)",
                discarded_count, penalized_count,
                self._max_selective, self._max_suspicious,
            )
        result.duration_seconds = time.monotonic() - start

        logger.info(
            "BytePatternMatcher: %d/%d FUN_xxx tanindi (%.1f%%) -- %.2fs",
            matched_count,
            result.total_unknown,
            result.match_rate * 100,
            result.duration_seconds,
        )

        return result

    def extract_function_bytes(
        self,
        binary_path: str | Path,
        functions_json: str | Path,
    ) -> dict[str, bytes]:
        """Her fonksiyonun ilk N byte'ini binary'den oku.

        Standalone kullanim icin: byte'lari cikar, eslestirmeyi disarida yap.

        Args:
            binary_path: Binary dosya yolu.
            functions_json: Ghidra functions.json yolu.

        Returns:
            {func_name: first_N_bytes} dict.
        """
        binary_path = Path(binary_path)
        functions_json = Path(functions_json)

        if not binary_path.exists() or not functions_json.exists():
            return {}

        text_vmaddr, text_fileoff, fat_offset = self._get_text_segment_info(binary_path)
        if text_vmaddr is None or text_fileoff is None:
            return {}

        try:
            file_size = binary_path.stat().st_size
        except OSError:
            return {}

        func_list = self._load_functions(functions_json)
        if not func_list:
            return {}

        result: dict[str, bytes] = {}
        try:
            with open(binary_path, "rb") as bf:
                for func_entry in func_list:
                    name = func_entry.get("name", "")
                    addr_str = func_entry.get("address", func_entry.get("entry_point", ""))
                    if not name or not addr_str:
                        continue

                    try:
                        addr = int(addr_str, 16) if isinstance(addr_str, str) else int(addr_str)
                    except (ValueError, TypeError):
                        continue

                    file_offset = addr - text_vmaddr + text_fileoff + fat_offset
                    if file_offset < 0 or file_offset >= file_size:
                        continue

                    func_bytes = self._read_bytes(bf, file_offset, self._read_size)
                    if func_bytes:
                        result[name] = func_bytes
        except OSError:
            pass

        return result

    # ------------------------------------------------------------------
    # Internal: segment info
    # ------------------------------------------------------------------

    def _get_text_segment_info(
        self, binary_path: Path
    ) -> tuple[Optional[int], Optional[int], int]:
        """__TEXT segment vmaddr, fileoff ve fat offset degerlerini bul.

        Universal (fat) binary ise ilk architecture'un slice offset'ini
        fat_offset olarak dondurur. Normal binary'ler icin fat_offset=0.

        Returns:
            (vmaddr, fileoff, fat_offset) tuple.
            vmaddr/fileoff None ise bulunamadi.
        """
        # Fat offset'i bul (universal binary mi?)
        fat_offset = self._get_fat_offset(binary_path)

        if self._otool_path:
            vmaddr, fileoff = self._parse_text_segment_otool(binary_path)
            return vmaddr, fileoff, fat_offset

        # otool yoksa basit Mach-O header parse
        vmaddr, fileoff = self._parse_text_segment_header(binary_path)
        return vmaddr, fileoff, fat_offset

    # Mach-O CPU type sabitleri (mach/machine.h)
    _CPU_TYPE_X86_64 = 0x01000007   # CPU_TYPE_X86 (7) | CPU_ARCH_ABI64 (0x01000000)
    _CPU_TYPE_ARM64 = 0x0100000C    # CPU_TYPE_ARM (12) | CPU_ARCH_ABI64
    _CPU_TYPE_X86 = 0x00000007
    _CPU_TYPE_ARM = 0x0000000C

    @staticmethod
    def _preferred_cputype() -> int:
        """Host mimarisi icin tercih edilen Mach-O cputype."""
        import platform as _platform
        m = _platform.machine().lower()
        if m in ("arm64", "aarch64"):
            return BytePatternMatcher._CPU_TYPE_ARM64
        if m in ("x86_64", "amd64"):
            return BytePatternMatcher._CPU_TYPE_X86_64
        if m.startswith("arm"):
            return BytePatternMatcher._CPU_TYPE_ARM
        return BytePatternMatcher._CPU_TYPE_X86_64  # yaygin default

    def _get_fat_offset(self, binary_path: Path) -> int:
        """Universal (fat) binary'nin dogru slice offset'ini dondur.

        v1.10.0 H11: Eskiden HER ZAMAN ilk arch'in offset'i donuyordu.
        Universal binary'de ilk arch genelde x86_64 oldugundan Apple Silicon
        uzerinde yanlis slice tarandi (pattern eslesmeleri kayiyordu). Yeni
        versiyon:
          1. Host mimarisini `platform.machine()` ile tespit et
          2. Tum fat_arch entries'lerini dogru cputype icin tara
          3. Bulursa: o slice'in offset'ini don
          4. Bulamazsa: fallback olarak ilk arch'in offset'i (eski davranis)

        Mach-O fat binary (magic 0xCAFEBABE veya 0xBEBAFECA). Normal Mach-O
        veya diger format ise 0 dondurur.
        """
        try:
            with open(binary_path, "rb") as f:
                magic = f.read(4)
        except OSError:
            return 0

        # Fat binary magic: 0xCAFEBABE (big-endian) veya 0xBEBAFECA (little-endian)
        fat_magic_be = b"\xca\xfe\xba\xbe"
        fat_magic_le = b"\xbe\xba\xfe\xca"

        if magic != fat_magic_be and magic != fat_magic_le:
            return 0

        preferred_cpu = self._preferred_cputype()

        # Fat binary -- tum arch entries'lerini parse et, dogru cputype'i sec
        import struct
        try:
            with open(binary_path, "rb") as f:
                f.read(4)  # magic (zaten okuduk)
                nfat_raw = f.read(4)
                if len(nfat_raw) < 4:
                    return 0

                if magic == fat_magic_be:
                    nfat = struct.unpack(">I", nfat_raw)[0]
                    fmt = ">5I"
                else:
                    nfat = struct.unpack("<I", nfat_raw)[0]
                    fmt = "<5I"

                if nfat == 0:
                    return 0
                # Mantiksiz nfat (dosya bozuksa) koru
                if nfat > 64:
                    logger.debug(
                        "BytePatternMatcher: nfat %d cok yuksek, 64 ile sinirlandi",
                        nfat,
                    )
                    nfat = 64

                first_offset: Optional[int] = None
                preferred_offset: Optional[int] = None
                # Her fat_arch struct 20 byte:
                #   uint32_t cputype, cpusubtype, offset, size, align
                for _idx in range(nfat):
                    arch_raw = f.read(20)
                    if len(arch_raw) < 20:
                        break
                    cputype, _cpusubtype, offset, _size, _align = struct.unpack(
                        fmt, arch_raw,
                    )
                    if first_offset is None:
                        first_offset = offset
                    if cputype == preferred_cpu:
                        preferred_offset = offset
                        break

                chosen = (
                    preferred_offset
                    if preferred_offset is not None
                    else first_offset
                )
                if chosen is None:
                    return 0

                logger.debug(
                    "BytePatternMatcher: Fat binary, slice offset=0x%x "
                    "(nfat=%d, preferred_cpu=0x%x, matched=%s)",
                    chosen, nfat, preferred_cpu,
                    preferred_offset is not None,
                )
                return chosen

        except (OSError, struct.error) as e:
            logger.debug("Fat header parse hatasi: %s", e)
            return 0

    def _parse_text_segment_otool(
        self, binary_path: Path
    ) -> tuple[Optional[int], Optional[int]]:
        """otool -l ciktisindann __TEXT segment vmaddr ve fileoff parse et."""
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

        lines = result.stdout.splitlines()
        in_text_segment = False
        vmaddr: Optional[int] = None
        fileoff: Optional[int] = None

        for line in lines:
            stripped = line.strip()

            if stripped.startswith("segname __TEXT"):
                in_text_segment = True
                vmaddr = None
                fileoff = None
                continue

            if in_text_segment:
                if stripped.startswith("segname "):
                    # Baska bir segment'e gectik -- ilk __TEXT'i bulduk
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
                "BytePatternMatcher: __TEXT vmaddr=0x%x, fileoff=0x%x",
                vmaddr, fileoff,
            )
            return vmaddr, fileoff

        logger.debug("BytePatternMatcher: __TEXT segment bulunamadi: %s", binary_path)
        return None, None

    def _parse_text_segment_header(
        self, binary_path: Path
    ) -> tuple[Optional[int], Optional[int]]:
        """Binary header'dan basit heuristik ile segment info."""
        try:
            with open(binary_path, "rb") as f:
                magic = f.read(4)
        except OSError:
            return None, None

        if magic[:4] == b"\x7fELF":
            return 0, 0
        if magic[:2] == b"MZ":
            return 0, 0

        return None, None

    # ------------------------------------------------------------------
    # Internal: JSON loading
    # ------------------------------------------------------------------

    @staticmethod
    def _load_functions(functions_json: Path) -> Optional[list[dict]]:
        """Ghidra functions.json'u yukle ve fonksiyon listesini dondur."""
        try:
            with open(functions_json, encoding="utf-8", errors="replace") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.error("Functions JSON okunamadi: %s -- %s", functions_json, e)
            return None

        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("functions", [])
        return None

    # ------------------------------------------------------------------
    # Internal: binary read
    # ------------------------------------------------------------------

    @staticmethod
    def _read_bytes(file_obj: Any, offset: int, size: int) -> bytes:
        """Binary dosyadan belirli offset'ten N byte oku.

        Hatalar sessizce bos bytes dondurur (log yok, performans icin).
        """
        try:
            file_obj.seek(offset)
            return file_obj.read(size)
        except OSError:
            return b""

    # ------------------------------------------------------------------
    # Internal: signature index (hiz optimizasyonu)
    # ------------------------------------------------------------------

    @staticmethod
    def _build_sig_index(
        signatures: list[Any],
    ) -> dict[bytes, list[int]]:
        """Ilk 4 byte'a gore hash index olustur.

        O(n*m) brute force yerine, once ilk 4 byte ile filtreleme yapar.
        Wildcard iceren signature'lar icin ayri bucket ("" key).

        Returns:
            {first_4_bytes: [sig_index_list]} dict.
        """
        index: dict[bytes, list[int]] = {}

        for i, sig in enumerate(signatures):
            pattern = getattr(sig, "byte_pattern", b"")
            mask = getattr(sig, "mask", b"") or getattr(sig, "byte_mask", b"")
            if not pattern or len(pattern) < 4:
                continue

            # Ilk 4 byte'ta wildcard var mi kontrol et
            has_wildcard = False
            if mask and len(mask) >= 4:
                for j in range(4):
                    if mask[j] != 0xFF:
                        has_wildcard = True
                        break

            if has_wildcard:
                # Wildcard olan sig'ler her zaman kontrol edilecek
                index.setdefault(b"WILD", []).append(i)
            else:
                # Ilk 4 byte sabit -- hash key olarak kullan
                key = pattern[:4]
                index.setdefault(key, []).append(i)

        return index

    # ------------------------------------------------------------------
    # Internal: byte eslestirme
    # ------------------------------------------------------------------

    # NOT (v1.10.0 H5): Esas implementasyon `_match_bytes_with_sig_index`'ta.
    # Eski API (sadece info tuple'i donen) testler icin wrapper alias olarak
    # korunuyor -- v1.10.0 Batch 3C Fix #2.

    def _match_bytes(
        self,
        func_bytes: bytes,
        func_size: int,
        signatures: list[Any],
        sig_index: dict[bytes, list[int]],
    ) -> Optional[tuple[str, str, float, str, str]]:
        """Backward-compat wrapper: (name, library, conf, category, purpose).

        Yeni kod `_match_bytes_with_sig_index` kullanir (sig index'i de
        dondurur). Eski API -- testler ve external caller'lar icin.
        """
        result = self._match_bytes_with_sig_index(
            func_bytes, func_size, signatures, sig_index,
        )
        if result is None:
            return None
        _idx, info = result
        return info

    def _match_bytes_with_sig_index(
        self,
        func_bytes: bytes,
        func_size: int,
        signatures: list[Any],
        sig_index: dict[bytes, list[int]],
    ) -> Optional[tuple[int, tuple[str, str, float, str, str]]]:
        """_match_bytes ile ayni, ama ek olarak kazanan signature'in index'ini dondurur.

        Two-pass selectivity icin gerekli: hangi signature kac fonksiyona eslesti?

        Returns:
            (best_sig_index, (matched_name, library, confidence, category, purpose))
            veya None.
        """
        if len(func_bytes) < self._min_pattern_length:
            return None

        best: Optional[tuple[int, tuple[str, str, float, str, str]]] = None
        best_conf = 0.0

        candidate_indices: list[int] = []
        key = func_bytes[:4]
        if key in sig_index:
            candidate_indices.extend(sig_index[key])
        if b"WILD" in sig_index:
            candidate_indices.extend(sig_index[b"WILD"])

        if not candidate_indices:
            return None

        for idx in candidate_indices:
            sig = signatures[idx]
            pattern = getattr(sig, "byte_pattern", b"")
            mask = getattr(sig, "mask", b"") or getattr(sig, "byte_mask", b"")

            plen = len(pattern)
            if plen < self._min_pattern_length:
                continue
            if len(func_bytes) < plen:
                continue

            if not mask or len(mask) != plen:
                mask = b"\xff" * plen

            size_range = getattr(sig, "size_range", (0, 0))
            if size_range != (0, 0) and func_size > 0:
                min_s, max_s = size_range
                if func_size < min_s or func_size > max_s:
                    continue

            # v1.10.0 H5 (perf fix): Python loop yerine integer XOR ile
            # maskeli karsilastirma. plen tipik 16-32 byte -> int(128-256 bit).
            # `(func XOR pattern) AND mask == 0` formulu:
            #   - mask'in 0xFF oldugu pozisyonda XOR non-zero ise fail.
            #   - mask'in 0x00 oldugu pozisyonda (wildcard) sonuc 0.
            # Bu pure-C path -- Python-level loop tamamen kalkar. Mask'i
            # 0/0xFF disindaki biledik byte'lar icin de dogru calisir.
            sub = func_bytes[:plen]
            sub_i = int.from_bytes(sub, "big")
            pat_i = int.from_bytes(pattern, "big")
            mask_i = int.from_bytes(mask, "big")
            matched = ((sub_i ^ pat_i) & mask_i) == 0

            if matched:
                fixed_bytes = mask.count(b"\xff")
                fixed_ratio = fixed_bytes / plen if plen > 0 else 0
                length_bonus = min(0.10, (plen - 16) * 0.005) if plen > 16 else 0.0
                conf = min(0.95, 0.60 + fixed_ratio * 0.30 + length_bonus)

                if conf > best_conf and conf >= self._min_confidence:
                    best_conf = conf
                    best = (
                        idx,
                        (
                            getattr(sig, "name", "unknown"),
                            getattr(sig, "library", "unknown"),
                            conf,
                            getattr(sig, "category", "") or getattr(sig, "library", ""),
                            getattr(sig, "purpose", ""),
                        ),
                    )

        return best

    # ------------------------------------------------------------------
    # Convenience: sonuclari extracted_names formatina cevir
    # ------------------------------------------------------------------

    @staticmethod
    def to_naming_map(result: ByteMatchResult) -> dict[str, str]:
        """ByteMatchResult'u {old_name: new_name} dict'ine cevir.

        stages.py'deki extracted_names dict'ine merge edilebilir.

        Name formatting:
            - Leading _ kaldirilir (macOS convention)
            - Bos isimleri atlar
        """
        naming_map: dict[str, str] = {}
        for original_name, info in result.matches.items():
            matched = info.get("matched_name", "")
            if matched:
                # macOS C convention: leading _ kaldir
                clean_name = matched.lstrip("_") if matched.startswith("_") else matched
                if clean_name:
                    naming_map[original_name] = clean_name
        return naming_map
