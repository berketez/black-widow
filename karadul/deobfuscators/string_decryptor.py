"""Gelismis string decryption modulu.

Obfuscated binary'lerdeki sifrelenmis/gizlenmis stringleri cozumler:
1. XOR variations (single-byte, multi-byte, rolling)
2. RC4 decryption (S-box pattern tespiti)
3. Base64 encoded string'ler
4. Stack string reconstruction (char-by-char push)
5. XOR + ADD/SUB combined
6. String table index-based lookup

Config uyumlu: BinaryReconstructionConfig.enable_string_decryption
"""

from __future__ import annotations

import base64
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class DecryptedString:
    """Cozumlenmis string bilgisi."""
    encrypted_data: str  # Orijinal hex veya pattern
    decrypted_value: str
    method: str  # "xor_single", "xor_multi", "xor_rolling", "rc4", "base64", "stack_string"
    confidence: float
    location: str = ""  # Dosya:satir bilgisi
    key: str = ""  # Sifreleme anahtari (biliniyorsa)


@dataclass
class StringDecryptionResult:
    """String decryption sonucu."""
    total_encrypted: int = 0
    total_decrypted: int = 0
    decrypted_strings: list[DecryptedString] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class StringDecryptor:
    """Gelismis string decryption motoru.

    Obfuscated C kodundaki sifrelenmis string'leri tespit edip cozer.
    Ghidra decompile ciktisi uzerinde calisir.
    """

    def __init__(self):
        self._init_patterns()

    def _init_patterns(self):
        """Regex pattern'lerini derle."""
        # XOR single-byte: buf[i] ^= 0xNN
        self._xor_single = re.compile(
            r"(\w+)\[(\w+)\]\s*(?:\^=|=\s*\1\[\2\]\s*\^)\s*(0x[0-9a-fA-F]{1,2})\b"
        )

        # XOR multi-byte key: buf[i] ^= key[i % keylen]
        self._xor_multi = re.compile(
            r"(\w+)\[\w+\]\s*(?:\^=|=\s*\1\[\w+\]\s*\^)\s*(\w+)\[.*?%\s*(\d+)\]"
        )

        # Rolling XOR: prev = buf[i] ^ prev
        self._xor_rolling = re.compile(
            r"(\w+)\s*=\s*(\w+)\[(\w+)\]\s*\^\s*\1"
        )

        # RC4 S-box init: for(i=0;i<256;i++) S[i]=i
        self._rc4_init = re.compile(
            r"for\s*\([^)]*(?:256|0x100)[^)]*\)\s*\{[^}]*"
            r"\w+\[\w+\]\s*=\s*\w+"
        )

        # RC4 swap: swap(S[i], S[j])
        self._rc4_swap = re.compile(
            r"(\w+)\s*=\s*(\w+)\[(\w+)\].*?"
            r"\2\[\3\]\s*=\s*\2\[(\w+)\].*?"
            r"\2\[\4\]\s*=\s*\1",
            re.DOTALL,
        )

        # Base64 encoded string: {"SGVsbG8=", "dGVzdA=="}
        self._base64_str = re.compile(
            r'"([A-Za-z0-9+/]{4,}={0,2})"'
        )

        # Stack string: mov [rbp-0x20], 'H'; mov [rbp-0x1f], 'e'...
        # Ghidra decompile'da: local_28 = 0x48; local_27 = 0x65; ...
        self._stack_string_hex = re.compile(
            r"(local_[0-9a-fA-F]+|[a-z]Var\d+)\s*=\s*(0x[2-7][0-9a-fA-F])\b"
        )

        # Stack string char: local_28 = 'H';
        self._stack_string_char = re.compile(
            r"(local_[0-9a-fA-F]+|[a-z]Var\d+)\s*=\s*'(.)'"
        )

        # Hex byte array: {0x48, 0x65, 0x6c, 0x6c, 0x6f}
        self._hex_array = re.compile(
            r"\{\s*((?:0x[0-9a-fA-F]{1,2}\s*,\s*){3,}0x[0-9a-fA-F]{1,2})\s*\}"
        )

        # String table: string_table[idx]
        self._string_table = re.compile(
            r"(\w+_table|\w+_strings|\w+_strs)\s*\[\s*(\d+|0x[0-9a-fA-F]+)\s*\]"
        )

    def decrypt_in_code(self, code: str, filename: str = "") -> StringDecryptionResult:
        """C kodundaki sifrelenmis string'leri tespit edip coz.

        Args:
            code: Ghidra decompile ciktisi (tek dosya).
            filename: Dosya adi (loglama icin).

        Returns:
            StringDecryptionResult: Cozumlenmis string'ler.
        """
        result = StringDecryptionResult()

        # 1. Stack string reconstruction
        stack_strings = self._find_stack_strings(code, filename)
        result.decrypted_strings.extend(stack_strings)
        result.total_encrypted += len(stack_strings)
        result.total_decrypted += len(stack_strings)

        # 2. Hex byte array decoding
        hex_strings = self._find_hex_arrays(code, filename)
        result.decrypted_strings.extend(hex_strings)
        result.total_encrypted += len(hex_strings)
        result.total_decrypted += len(hex_strings)

        # 3. Base64 strings
        b64_strings = self._find_base64_strings(code, filename)
        result.decrypted_strings.extend(b64_strings)
        result.total_encrypted += len(b64_strings)
        result.total_decrypted += len(b64_strings)

        # 4. XOR patterns (tek byte)
        xor_info = self._find_xor_patterns(code, filename)
        result.decrypted_strings.extend(xor_info)
        result.total_encrypted += len(xor_info)

        # 5. RC4 patterns
        rc4_info = self._find_rc4_patterns(code, filename)
        result.decrypted_strings.extend(rc4_info)
        result.total_encrypted += len(rc4_info)

        return result

    def decrypt_in_directory(self, directory: Path) -> StringDecryptionResult:
        """Bir dizindeki tum C dosyalarini tara."""
        combined = StringDecryptionResult()

        c_files = sorted(directory.glob("*.c"))
        for c_file in c_files:
            try:
                code = c_file.read_text(errors="replace")
                result = self.decrypt_in_code(code, c_file.name)
                combined.total_encrypted += result.total_encrypted
                combined.total_decrypted += result.total_decrypted
                combined.decrypted_strings.extend(result.decrypted_strings)
                combined.errors.extend(result.errors)
            except Exception as e:
                combined.errors.append(f"{c_file.name}: {e}")

        logger.info(
            "String decryption: %d sifrelenmis, %d cozumlenmis, %d hata",
            combined.total_encrypted, combined.total_decrypted, len(combined.errors),
        )
        return combined

    # ------------------------------------------------------------------
    # Stack string reconstruction
    # ------------------------------------------------------------------

    def _find_stack_strings(self, code: str, filename: str) -> list[DecryptedString]:
        """Stack string kalintlarini bul ve birlestir.

        Pattern: Ghidra decompile'da ardisik local degiskenlere
        tek karakter atamasi -> stack string.

        Ornek:
            local_28 = 0x48;  // 'H'
            local_27 = 0x65;  // 'e'
            local_26 = 0x6c;  // 'l'
            local_25 = 0x6c;  // 'l'
            local_24 = 0x6f;  // 'o'
        -> "Hello"
        """
        results = []

        # Hex atamalari bul
        hex_matches = list(self._stack_string_hex.finditer(code))
        char_matches = list(self._stack_string_char.finditer(code))

        # Ardisik atamalari grupla
        if hex_matches:
            groups = self._group_consecutive_assignments(hex_matches, code)
            for group in groups:
                chars = []
                for m in group:
                    val = int(m.group(2), 16)
                    if 0x20 <= val <= 0x7e:  # Printable ASCII
                        chars.append(chr(val))
                    else:
                        break

                if len(chars) >= 3:
                    decrypted = "".join(chars)
                    results.append(DecryptedString(
                        encrypted_data=f"stack_string_{len(chars)}_bytes",
                        decrypted_value=decrypted,
                        method="stack_string",
                        confidence=0.85,
                        location=filename,
                    ))

        # Char atamalari
        if char_matches:
            groups = self._group_consecutive_assignments(char_matches, code)
            for group in groups:
                chars = [m.group(2) for m in group]
                if len(chars) >= 3:
                    decrypted = "".join(chars)
                    results.append(DecryptedString(
                        encrypted_data=f"stack_string_{len(chars)}_chars",
                        decrypted_value=decrypted,
                        method="stack_string",
                        confidence=0.90,
                        location=filename,
                    ))

        return results

    def _group_consecutive_assignments(
        self, matches: list, code: str, max_gap: int = 100,
    ) -> list[list]:
        """Ardisik (yakindaki) atamalari grupla."""
        if not matches:
            return []

        groups = []
        current_group = [matches[0]]

        for i in range(1, len(matches)):
            prev_end = matches[i - 1].end()
            curr_start = matches[i].start()
            gap = curr_start - prev_end

            if gap <= max_gap:
                current_group.append(matches[i])
            else:
                if len(current_group) >= 3:
                    groups.append(current_group)
                current_group = [matches[i]]

        if len(current_group) >= 3:
            groups.append(current_group)

        return groups

    # ------------------------------------------------------------------
    # Hex byte array
    # ------------------------------------------------------------------

    def _find_hex_arrays(self, code: str, filename: str) -> list[DecryptedString]:
        """Hex byte array'leri bul ve decode et."""
        results = []

        for match in self._hex_array.finditer(code):
            hex_str = match.group(1)
            try:
                # 0x48, 0x65, 0x6c, ... -> bytes
                byte_vals = [
                    int(b.strip(), 16)
                    for b in hex_str.split(",")
                    if b.strip().startswith("0x")
                ]

                # Printable mi kontrol et
                if all(0x20 <= b <= 0x7e for b in byte_vals):
                    decrypted = bytes(byte_vals).decode("ascii")
                    if len(decrypted) >= 3:
                        results.append(DecryptedString(
                            encrypted_data=hex_str[:100],
                            decrypted_value=decrypted,
                            method="hex_array",
                            confidence=0.90,
                            location=filename,
                        ))
            except (ValueError, UnicodeDecodeError):
                pass

        return results

    # ------------------------------------------------------------------
    # Base64
    # ------------------------------------------------------------------

    def _find_base64_strings(self, code: str, filename: str) -> list[DecryptedString]:
        """Base64 encoded string'leri bul ve decode et."""
        results = []

        for match in self._base64_str.finditer(code):
            b64_str = match.group(1)

            # Cok kisa string'leri atla (8 -> 16: hex constant ve
            # degisken isimleri false positive yapiyordu)
            if len(b64_str) < 16:
                continue

            # Padding veya mixed case/digit kontrolu:
            # Gercek base64 genellikle '=' ile biter veya hem buyuk hem
            # kucuk harf hem de rakam icerir. Sadece lowercase/hex gibi
            # gorunen string'leri atla.
            has_padding = b64_str.endswith("=")
            has_upper = any(c.isupper() for c in b64_str)
            has_lower = any(c.islower() for c in b64_str)
            has_digit = any(c.isdigit() for c in b64_str)
            if not (has_padding or (has_upper and has_lower and has_digit)):
                continue

            try:
                decoded_bytes = base64.b64decode(b64_str)
                decoded = decoded_bytes.decode("utf-8")

                # Gecerli text mi kontrol et
                if all(c.isprintable() or c in "\n\r\t" for c in decoded):
                    results.append(DecryptedString(
                        encrypted_data=b64_str[:100],
                        decrypted_value=decoded[:500],
                        method="base64",
                        confidence=0.75,
                        location=filename,
                    ))
            except (base64.binascii.Error, UnicodeDecodeError, ValueError):
                pass

        return results

    # ------------------------------------------------------------------
    # XOR patterns
    # ------------------------------------------------------------------

    def _find_xor_patterns(self, code: str, filename: str) -> list[DecryptedString]:
        """XOR encryption pattern'lerini tespit et."""
        results = []

        # Single-byte XOR
        for match in self._xor_single.finditer(code):
            key = match.group(3)
            results.append(DecryptedString(
                encrypted_data=match.group(0)[:200],
                decrypted_value=f"[XOR_SINGLE key={key}]",
                method="xor_single",
                confidence=0.70,
                location=filename,
                key=key,
            ))

        # Multi-byte XOR
        for match in self._xor_multi.finditer(code):
            key_var = match.group(2)
            key_len = match.group(3)
            results.append(DecryptedString(
                encrypted_data=match.group(0)[:200],
                decrypted_value=f"[XOR_MULTI key_var={key_var} len={key_len}]",
                method="xor_multi",
                confidence=0.65,
                location=filename,
                key=f"{key_var}[{key_len}]",
            ))

        # Rolling XOR
        for match in self._xor_rolling.finditer(code):
            results.append(DecryptedString(
                encrypted_data=match.group(0)[:200],
                decrypted_value="[XOR_ROLLING detected]",
                method="xor_rolling",
                confidence=0.60,
                location=filename,
            ))

        return results

    # ------------------------------------------------------------------
    # RC4 patterns
    # ------------------------------------------------------------------

    def _find_rc4_patterns(self, code: str, filename: str) -> list[DecryptedString]:
        """RC4 S-box initialization pattern'lerini tespit et."""
        results = []

        # RC4 init loop (256 elements)
        for match in self._rc4_init.finditer(code):
            # Yakininda swap pattern var mi?
            context = code[match.start():min(match.end() + 500, len(code))]
            if self._rc4_swap.search(context):
                results.append(DecryptedString(
                    encrypted_data="RC4 S-box initialization detected",
                    decrypted_value="[RC4 cipher detected — dynamic analysis needed for key]",
                    method="rc4",
                    confidence=0.80,
                    location=filename,
                ))

        return results

    # ------------------------------------------------------------------
    # XOR brute-force (kisa string'ler icin)
    # ------------------------------------------------------------------

    @staticmethod
    def xor_decrypt(data: bytes, key: bytes) -> bytes:
        """XOR decryption yap."""
        return bytes(d ^ key[i % len(key)] for i, d in enumerate(data))

    @staticmethod
    def try_single_byte_xor(data: bytes) -> list[tuple[int, str, float]]:
        """Tum 256 tek-byte anahtari dene, en iyi sonuclari dondur.

        Returns:
            [(key, decrypted_text, score), ...] en iyi 5
        """
        results = []

        for key in range(1, 256):  # 0 skip (no-op)
            decrypted = bytes(b ^ key for b in data)
            try:
                text = decrypted.decode("ascii")
                # Printable karakter orani
                printable = sum(1 for c in text if c.isprintable() or c in " \n\r\t")
                score = printable / max(len(text), 1)
                if score > 0.7:
                    results.append((key, text, score))
            except UnicodeDecodeError:
                pass

        results.sort(key=lambda x: -x[2])
        return results[:5]
