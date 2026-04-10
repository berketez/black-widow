"""Assembly-level analiz modulu.

Ghidra decompiler bazen basarisiz olur veya bilgi kaybeder.
Bu modul dogrudan assembly'den ek bilgi cikarir:

1. Calling convention'dan parametre register'lari
2. Register lifetime analysis -> degisken mapping
3. Stack frame analysis -> local degisken layout
4. SIMD instruction pattern -> vectorized loop tespiti
5. Inline assembly fragments -> crypto/hash tespiti

Capstone disassembly framework kullanir.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class RegisterUsage:
    """Bir register'in kullanim bilgisi."""
    register: str
    first_write: int  # Instruction index
    last_read: int
    access_count: int
    likely_type: str = ""  # "param", "local", "return", "callee_saved"


@dataclass
class StackVariable:
    """Stack frame'deki bir degisken."""
    offset: int  # rbp/rsp'den offset
    size: int  # Byte cinsinden boyut
    access_count: int
    likely_type: str = ""  # "int", "pointer", "float", "struct", "array"
    name_hint: str = ""  # Tahmin edilen isim


@dataclass
class SIMDPattern:
    """Tespit edilen SIMD/vectorization pattern'i."""
    instruction_type: str  # "SSE", "AVX", "NEON"
    operation: str  # "add", "mul", "xor", "shuffle"
    data_type: str  # "float32x4", "int32x8", etc.
    likely_purpose: str = ""  # "dot_product", "memcpy", "aes_round"


@dataclass
class AssemblyAnalysisResult:
    """Assembly analiz sonucu."""
    calling_convention: str = ""  # "cdecl", "stdcall", "fastcall", "sysv_amd64", "aapcs64"
    param_count: int = 0
    registers: list[RegisterUsage] = field(default_factory=list)
    stack_variables: list[StackVariable] = field(default_factory=list)
    stack_frame_size: int = 0
    simd_patterns: list[SIMDPattern] = field(default_factory=list)
    has_crypto_instructions: bool = False
    is_leaf_function: bool = True  # Baska fonksiyon cagirmiyorsa
    estimated_complexity: str = "simple"  # "simple", "moderate", "complex"


# Calling convention register mappings
SYSV_AMD64_PARAMS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
SYSV_AMD64_CALLEE_SAVED = ["rbx", "rbp", "r12", "r13", "r14", "r15"]
SYSV_AMD64_RETURN = ["rax", "rdx"]

WIN64_PARAMS = ["rcx", "rdx", "r8", "r9"]
WIN64_CALLEE_SAVED = ["rbx", "rbp", "rdi", "rsi", "r12", "r13", "r14", "r15"]

AAPCS64_PARAMS = [f"x{i}" for i in range(8)]  # x0-x7
AAPCS64_CALLEE_SAVED = [f"x{i}" for i in range(19, 29)]  # x19-x28
AAPCS64_RETURN = ["x0", "x1"]

# SIMD instruction sets
SSE_INSTRUCTIONS = {
    "addps", "subps", "mulps", "divps", "movaps", "movups",
    "addpd", "subpd", "mulpd", "divpd", "movapd", "movupd",
    "paddb", "paddw", "paddd", "paddq", "pxor", "pand", "por",
    "pshufb", "pshufd", "punpcklbw",
}

AVX_INSTRUCTIONS = {
    "vaddps", "vsubps", "vmulps", "vdivps", "vmovaps", "vmovups",
    "vaddpd", "vsubpd", "vmulpd", "vdivpd", "vmovapd",
    "vpxor", "vpand", "vpor", "vpshufd", "vpshufb",
    "vfmadd132ps", "vfmadd213ps", "vfmadd231ps",  # FMA
}

NEON_INSTRUCTIONS = {
    "fmla", "fadd", "fsub", "fmul", "fdiv",
    "add", "sub", "mul",  # vector variants (with .4s, .2d suffixes)
    "eor", "and", "orr",
    "ld1", "st1", "ld2", "st2",
}

# Crypto instruction patterns
CRYPTO_INSTRUCTIONS = {
    "aesenc", "aesdec", "aesenclast", "aesdeclast", "aeskeygenassist",  # AES-NI
    "sha1rnds4", "sha1nexte", "sha1msg1", "sha1msg2",  # SHA
    "sha256rnds2", "sha256msg1", "sha256msg2",  # SHA-256
    "pclmulqdq",  # Carry-less multiply (GCM)
    "aese", "aesd", "aesmc", "aesimc",  # ARM crypto extensions
}


class AssemblyAnalyzer:
    """Assembly-level analiz motoru.

    Ghidra decompiler'in kacirdigi bilgileri dogrudan
    assembly instruction'lardan cikarir.
    """

    def __init__(self):
        self._capstone_available = False
        try:
            import capstone  # noqa: F401
            self._capstone_available = True
        except ImportError:
            logger.info("capstone bulunamadi, assembly analizi sinirli olacak")

    def analyze_function_asm(
        self,
        asm_text: str,
        arch: str = "x86_64",
    ) -> AssemblyAnalysisResult:
        """Fonksiyon assembly kodunu analiz et.

        Args:
            asm_text: Assembly text (Ghidra export veya objdump).
            arch: Mimari ("x86_64", "aarch64", "x86_32").

        Returns:
            AssemblyAnalysisResult
        """
        result = AssemblyAnalysisResult()
        lines = [l.strip() for l in asm_text.split("\n") if l.strip()]

        if not lines:
            return result

        # Calling convention tespit
        result.calling_convention = self._detect_calling_convention(lines, arch)

        # Parametre sayisi
        result.param_count = self._count_parameters(lines, arch)

        # Stack frame boyutu
        result.stack_frame_size = self._detect_stack_frame(lines, arch)

        # Stack degiskenleri
        result.stack_variables = self._analyze_stack_variables(lines, arch)

        # SIMD pattern'leri
        result.simd_patterns = self._detect_simd_patterns(lines)

        # Crypto instruction'lar
        result.has_crypto_instructions = self._has_crypto(lines)

        # Leaf function mi?
        result.is_leaf_function = not any(
            re.search(r"\bcall\b|\bbl\b|\bblr\b", l, re.IGNORECASE)
            for l in lines
        )

        # Karmasiklik tahmini
        result.estimated_complexity = self._estimate_complexity(lines)

        return result

    def analyze_from_ghidra_json(
        self,
        functions_json: Path,
        arch: str = "x86_64",
    ) -> dict[str, AssemblyAnalysisResult]:
        """Ghidra export'undan assembly bilgisi cikar ve analiz et."""
        results = {}

        # Ghidra JSON'dan assembly varsa kullan
        # (Ghidra export_results.py tarafindan disasm field'i eklenebilir)
        # Yoksa bos dict dondur
        try:
            import json
            data = json.loads(functions_json.read_text())
            functions = data if isinstance(data, list) else data.get("functions", [])

            for func in functions:
                asm = func.get("disassembly", "")
                if asm:
                    name = func.get("name", func.get("address", "unknown"))
                    results[name] = self.analyze_function_asm(asm, arch)
        except Exception as e:
            logger.debug("Ghidra assembly analizi: %s", e)

        return results

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _detect_calling_convention(self, lines: list[str], arch: str) -> str:
        """Calling convention tespit et."""
        if arch == "aarch64":
            return "aapcs64"

        # x86_64: ilk birkac satirdaki register kullanimi
        first_lines = "\n".join(lines[:20]).lower()

        # System V AMD64: rdi, rsi, rdx parametreler
        if re.search(r"\brdi\b", first_lines) and re.search(r"\brsi\b", first_lines):
            return "sysv_amd64"

        # Windows x64: rcx, rdx parametreler
        if re.search(r"\brcx\b", first_lines) and re.search(r"\brdx\b", first_lines):
            if not re.search(r"\brdi\b", first_lines):
                return "win64"

        return "sysv_amd64"  # macOS/Linux default

    def _count_parameters(self, lines: list[str], arch: str) -> int:
        """Fonksiyonun kac parametre aldigini tahmin et."""
        first_lines = "\n".join(lines[:30]).lower()

        if arch == "aarch64":
            params = AAPCS64_PARAMS
        elif "win" in self._detect_calling_convention(lines, arch):
            params = WIN64_PARAMS
        else:
            params = SYSV_AMD64_PARAMS

        count = 0
        for reg in params:
            if re.search(rf"\b{reg}\b", first_lines):
                count += 1
            else:
                break  # Ardisik olmali

        return count

    def _detect_stack_frame(self, lines: list[str], arch: str) -> int:
        """Stack frame boyutunu tespit et."""
        for line in lines[:10]:
            # sub rsp, 0x48 -> 72 byte frame
            match = re.search(r"sub\s+(?:rsp|sp)\s*,\s*(0x[0-9a-fA-F]+|\d+)", line, re.IGNORECASE)
            if match:
                val = match.group(1)
                return int(val, 16) if val.startswith("0x") else int(val)
        return 0

    def _analyze_stack_variables(self, lines: list[str], arch: str) -> list[StackVariable]:
        """Stack frame'deki degiskenleri analiz et."""
        offsets: dict[int, StackVariable] = {}
        text = "\n".join(lines)

        # [rbp-0xNN] veya [rsp+0xNN] pattern'leri
        for match in re.finditer(r"\[(?:rbp|ebp)\s*-\s*(0x[0-9a-fA-F]+)\]", text, re.IGNORECASE):
            offset = int(match.group(1), 16)
            if offset not in offsets:
                offsets[offset] = StackVariable(
                    offset=offset, size=8, access_count=0,
                )
            offsets[offset].access_count += 1

        # Boyut ve tip tahmini
        sorted_offsets = sorted(offsets.keys())
        for i, offset in enumerate(sorted_offsets):
            var = offsets[offset]
            # Sonraki degiskenle aradaki fark = bu degiskenin boyutu
            if i + 1 < len(sorted_offsets):
                var.size = sorted_offsets[i + 1] - offset
            else:
                var.size = 8  # Default

            # Tip tahmini
            if var.size == 1:
                var.likely_type = "char"
            elif var.size == 4:
                var.likely_type = "int"
            elif var.size == 8:
                var.likely_type = "pointer"
            elif var.size > 16:
                var.likely_type = "struct"

        return sorted(offsets.values(), key=lambda v: v.offset)

    def _detect_simd_patterns(self, lines: list[str]) -> list[SIMDPattern]:
        """SIMD instruction pattern'lerini tespit et."""
        patterns = []
        text = "\n".join(lines).lower()

        # SSE
        for instr in SSE_INSTRUCTIONS:
            if re.search(rf"\b{instr}\b", text):
                patterns.append(SIMDPattern(
                    instruction_type="SSE",
                    operation=instr,
                    data_type="float32x4" if "ps" in instr else "float64x2",
                ))

        # AVX
        for instr in AVX_INSTRUCTIONS:
            if re.search(rf"\b{instr}\b", text):
                patterns.append(SIMDPattern(
                    instruction_type="AVX",
                    operation=instr,
                    data_type="float32x8" if "ps" in instr else "float64x4",
                ))

        # FMA detection -> likely dot product / matrix multiply
        if any(p.operation.startswith("vfmadd") for p in patterns):
            patterns.append(SIMDPattern(
                instruction_type="AVX",
                operation="fma",
                data_type="float32",
                likely_purpose="dot_product_or_matrix_multiply",
            ))

        return patterns

    def _has_crypto(self, lines: list[str]) -> bool:
        """Crypto instruction'lar var mi?"""
        text = "\n".join(lines).lower()
        return any(
            re.search(rf"\b{instr}\b", text)
            for instr in CRYPTO_INSTRUCTIONS
        )

    def _estimate_complexity(self, lines: list[str]) -> str:
        """Fonksiyon karmasikligini tahmin et."""
        n = len(lines)
        if n < 20:
            return "simple"
        elif n < 100:
            return "moderate"
        else:
            return "complex"
