"""Binary deobfuscation — Ghidra C ciktisini temizle ve isle.

Ghidra'nin ham decompilation ciktisini alir, Ghidra artifact'lerini
temizler, string decryption uygular ve anti-debug kodlarini isaretler.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from karadul.deobfuscators.string_decryptor import StringDecryptor
from karadul.deobfuscators.opaque_predicate import OpaquePredicateDetector
from karadul.deobfuscators.cff_deflattener import CFFDeflattener

logger = logging.getLogger(__name__)


@dataclass
class BinaryDeobfuscationResult:
    """Binary deobfuscation sonucu."""
    success: bool
    artifacts: dict[str, Path] = field(default_factory=dict)
    stats: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


class BinaryDeobfuscator:
    """Ghidra decompilation ciktisini temizler ve islenir hale getirir.

    Islemler:
    1. Ghidra artifact temizligi (gereksiz yorumlar, bos satirlar)
    2. String decryption (XOR, rolling XOR, stack strings)
    3. Anti-debug kod isaretleme
    4. Dead code isaretleme (opaque predicates)
    5. Fonksiyon birlestirlme (Ghidra split hatalari)
    """

    # Anti-debug pattern'leri
    ANTI_DEBUG_PATTERNS = [
        (re.compile(r"ptrace\s*\(\s*PT_DENY_ATTACH"), "ptrace anti-attach"),
        (re.compile(r"sysctl\s*\(.*P_TRACED"), "sysctl trace check"),
        (re.compile(r"mach_absolute_time\s*\(\).*mach_absolute_time\s*\(\)"),
         "timing-based anti-debug"),
        (re.compile(r"IsDebuggerPresent\s*\("), "Windows debugger check"),
        (re.compile(r"getppid\s*\(\).*!=.*1"), "parent PID check"),
        (re.compile(r"SIGTRAP|signal\s*\(\s*5"), "SIGTRAP handler"),
        (re.compile(r"task_get_exception_ports"), "exception port check"),
        (re.compile(r"csops\s*\(.*CS_OPS_STATUS"), "code signing check"),
    ]

    # XOR decryption pattern'leri
    XOR_PATTERNS = [
        # for (i=0; i<len; i++) buf[i] ^= key;
        # v1.7.x: [^}]* -> [^}]{0,2000} -- ic ice braces'da tum body'yi taramayi onle
        re.compile(
            r"for\s*\([^)]*\)\s*\{[^}]{0,2000}"
            r"(\w+)\[(\w+)\]\s*=\s*(\w+)\[(\w+)\]\s*\^\s*(0x[0-9a-fA-F]+|\w+)"
        ),
        # buf[i] = buf[i] ^ key
        re.compile(
            r"(\w+)\[\w+\]\s*=\s*\1\[\w+\]\s*\^\s*(0x[0-9a-fA-F]+)"
        ),
    ]

    # Ghidra artifact pattern'leri (temizlenecek)
    # v1.7.x: .*? -> [^*]{0,5000} -- */ yoksa tum inputu taramayi onle
    GHIDRA_ARTIFACTS = [
        re.compile(r"/\*\s*WARNING:[^*]{0,5000}\*/"),
        re.compile(r"/\*\s*DISPLAY WARNING[^*]{0,5000}\*/"),
        re.compile(r"  /\*\s*@.*?\*/"),  # Ghidra annotation comments
    ]

    def __init__(self, config):
        self._config = config
        self._string_decryptor = StringDecryptor()
        self._opaque_detector = OpaquePredicateDetector()
        self._cff_deflattener = CFFDeflattener()

    def deobfuscate(self, workspace) -> BinaryDeobfuscationResult:
        """Ana deobfuscation pipeline."""
        artifacts: dict[str, Path] = {}
        stats: dict = {}
        errors: list[str] = []

        static_dir = workspace.get_stage_dir("static")
        deobf_dir = workspace.get_stage_dir("deobfuscated")

        # Ghidra decompiled dizinini bul
        ghidra_output = static_dir / "ghidra_output"
        decompiled_src = ghidra_output / "decompiled"

        if not decompiled_src.exists() or not decompiled_src.is_dir():
            # Fallback: ghidra_decompiled.json'dan
            decompiled_json = static_dir / "ghidra_decompiled.json"
            if decompiled_json.exists():
                shutil.copy2(str(decompiled_json), str(deobf_dir / "decompiled.json"))
                artifacts["decompiled_json"] = deobf_dir / "decompiled.json"
                return BinaryDeobfuscationResult(
                    success=True, artifacts=artifacts,
                    stats={"mode": "json_only"},
                )
            errors.append("Ghidra decompilation ciktisi bulunamadi")
            return BinaryDeobfuscationResult(
                success=False, errors=errors,
            )

        # Decompiled dosyalari kopyala
        decompiled_dest = deobf_dir / "decompiled"
        if decompiled_dest.exists():
            shutil.rmtree(str(decompiled_dest))
        shutil.copytree(str(decompiled_src), str(decompiled_dest))

        c_files = sorted(decompiled_dest.glob("*.c"))
        stats["input_files"] = len(c_files)
        logger.info("Binary deobfuscation: %d C dosyasi isleniyor", len(c_files))

        # Ghidra metadata'yi da kopyala
        for meta_name in ("ghidra_functions.json", "ghidra_strings.json",
                          "ghidra_call_graph.json"):
            meta_src = static_dir / meta_name
            if meta_src.exists():
                shutil.copy2(str(meta_src), str(deobf_dir / meta_name))

        total_cleaned = 0
        total_anti_debug = 0
        total_xor_decrypted = 0
        total_strings_decrypted = 0
        total_opaque_preds = 0
        total_cff_deflattened = 0

        for c_file in c_files:
            try:
                content = c_file.read_text(errors="replace")
                original_len = len(content)

                # 1. Ghidra artifact temizligi
                content, cleaned = self._clean_ghidra_artifacts(content)
                total_cleaned += cleaned

                # 2. Anti-debug isaretleme
                content, anti_debug = self._mark_anti_debug(content)
                total_anti_debug += anti_debug

                # 3. XOR string decryption isaretleme
                content, xor_found = self._mark_xor_patterns(content)
                total_xor_decrypted += xor_found

                # 4. Gelismis string decryption
                try:
                    if self._config.binary_reconstruction.enable_string_decryption:
                        decrypt_result = self._string_decryptor.decrypt_in_code(
                            content, c_file.name,
                        )
                        total_strings_decrypted += decrypt_result.total_decrypted
                        # Decrypted string'leri koda yorum olarak ekle
                        for ds in decrypt_result.decrypted_strings:
                            if ds.decrypted_value and not ds.decrypted_value.startswith("["):
                                comment = (
                                    f'/* DECRYPTED ({ds.method}): '
                                    f'"{ds.decrypted_value[:80]}" */'
                                )
                                # Ilk pattern eslesmesinin yanina yorum ekle
                                if ds.encrypted_data in content:
                                    content = content.replace(
                                        ds.encrypted_data,
                                        ds.encrypted_data + "  " + comment,
                                        1,
                                    )
                except Exception as exc:
                    errors.append(f"{c_file.name} string_decryption: {exc}")

                # 5. Opaque predicate detection + marking
                try:
                    content, opaque_result = self._opaque_detector.eliminate_in_code(
                        content,
                    )
                    total_opaque_preds += opaque_result.total_found
                except Exception as exc:
                    errors.append(f"{c_file.name} opaque_predicate: {exc}")

                # 6. CFF deflattening
                try:
                    if self._cff_deflattener.detect_cff(content):
                        content, cff_result = self._cff_deflattener.deflatten_code(
                            content,
                        )
                        total_cff_deflattened += (
                            1 if cff_result.total_blocks > 0 else 0
                        )
                except Exception as exc:
                    errors.append(f"{c_file.name} cff_deflattening: {exc}")

                # 7. Bos satir normalizasyonu
                content = re.sub(r"\n{4,}", "\n\n\n", content)

                c_file.write_text(content)

            except Exception as exc:
                errors.append(f"{c_file.name}: {exc}")

        stats["ghidra_artifacts_cleaned"] = total_cleaned
        stats["anti_debug_markers"] = total_anti_debug
        stats["xor_patterns_found"] = total_xor_decrypted
        stats["strings_decrypted"] = total_strings_decrypted
        stats["opaque_predicates_found"] = total_opaque_preds
        stats["cff_deflattened"] = total_cff_deflattened
        stats["output_files"] = len(c_files)
        artifacts["decompiled_dir"] = decompiled_dest

        logger.info(
            "Binary deobfuscation tamamlandi: %d temizlik, %d anti-debug, "
            "%d XOR, %d string, %d opaque, %d CFF",
            total_cleaned, total_anti_debug, total_xor_decrypted,
            total_strings_decrypted, total_opaque_preds, total_cff_deflattened,
        )

        return BinaryDeobfuscationResult(
            success=True, artifacts=artifacts, stats=stats, errors=errors,
        )

    def _clean_ghidra_artifacts(self, content: str) -> tuple[str, int]:
        """Ghidra'nin eklediği gereksiz yorumları temizle."""
        count = 0
        for pattern in self.GHIDRA_ARTIFACTS:
            matches = pattern.findall(content)
            count += len(matches)
            content = pattern.sub("", content)
        return content, count

    def _mark_anti_debug(self, content: str) -> tuple[str, int]:
        """Anti-debug kod bölümlerini isaretler."""
        count = 0
        for pattern, label in self.ANTI_DEBUG_PATTERNS:
            matches = list(pattern.finditer(content))
            for match in reversed(matches):
                marker = f"/* ANTI-DEBUG: {label} */\n"
                content = content[:match.start()] + marker + content[match.start():]
                count += 1
        return content, count

    def _mark_xor_patterns(self, content: str) -> tuple[str, int]:
        """XOR encryption/decryption pattern'lerini isaretler."""
        count = 0
        for pattern in self.XOR_PATTERNS:
            matches = list(pattern.finditer(content))
            for match in reversed(matches):
                marker = "/* CRYPTO: XOR encryption/decryption loop */\n"
                content = content[:match.start()] + marker + content[match.start():]
                count += 1
        return content, count
