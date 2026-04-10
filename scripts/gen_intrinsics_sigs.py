#!/usr/bin/env python3
"""
Compiler Intrinsics Signature Generator for Karadul.

Parses Clang/LLVM builtin headers to extract SSE/AVX/NEON/SVE intrinsic
function names, then adds comprehensive hardcoded compiler builtins.

Output: sigs/compiler_intrinsics.json
"""

import json
import os
import re
import subprocess
import sys
from datetime import datetime
from collections import defaultdict

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SIGS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sigs")
OUTPUT = os.path.join(SIGS_DIR, "compiler_intrinsics.json")

# ---------------------------------------------------------------------------
# 1. Find Clang resource dir
# ---------------------------------------------------------------------------
def get_clang_include_dir():
    """Get Clang's builtin header directory."""
    try:
        result = subprocess.run(
            ["clang", "-print-resource-dir"],
            capture_output=True, text=True, check=True
        )
        return os.path.join(result.stdout.strip(), "include")
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Fallback for macOS
        fallback = "/Library/Developer/CommandLineTools/usr/lib/clang/17/include"
        if os.path.isdir(fallback):
            return fallback
        print("ERROR: Cannot find Clang include directory", file=sys.stderr)
        sys.exit(1)

# ---------------------------------------------------------------------------
# 2. Header -> library category mapping
# ---------------------------------------------------------------------------
HEADER_LIB_MAP = {
    # x86 SSE family
    "mmintrin.h": "mmx",
    "xmmintrin.h": "sse",
    "emmintrin.h": "sse2",
    "pmmintrin.h": "sse3",
    "tmmintrin.h": "ssse3",
    "smmintrin.h": "sse4.1",
    "nmmintrin.h": "sse4.2",
    "wmmintrin.h": "aes_pclmul",
    "ammintrin.h": "sse4a",
    "popcntintrin.h": "popcnt",

    # x86 AVX family
    "avxintrin.h": "avx",
    "avx2intrin.h": "avx2",
    "avx512fintrin.h": "avx512f",
    "avx512bwintrin.h": "avx512bw",
    "avx512cdintrin.h": "avx512cd",
    "avx512dqintrin.h": "avx512dq",
    "avx512vlintrin.h": "avx512vl",
    "avx512vlbwintrin.h": "avx512vl_bw",
    "avx512vldqintrin.h": "avx512vl_dq",
    "avx512vlcdintrin.h": "avx512vl_cd",
    "avx512ifmaintrin.h": "avx512ifma",
    "avx512ifmavlintrin.h": "avx512ifma_vl",
    "avx512vbmiintrin.h": "avx512vbmi",
    "avx512vbmivlintrin.h": "avx512vbmi_vl",
    "avx512vbmi2intrin.h": "avx512vbmi2",
    "avx512vlvbmi2intrin.h": "avx512vl_vbmi2",
    "avx512vnniintrin.h": "avx512vnni",
    "avx512vlvnniintrin.h": "avx512vl_vnni",
    "avx512bf16intrin.h": "avx512bf16",
    "avx512vlbf16intrin.h": "avx512vl_bf16",
    "avx512fp16intrin.h": "avx512fp16",
    "avx512vlfp16intrin.h": "avx512vl_fp16",
    "avx512bitalgintrin.h": "avx512bitalg",
    "avx512vlbitalgintrin.h": "avx512vl_bitalg",
    "avx512vpopcntdqintrin.h": "avx512vpopcntdq",
    "avx512vpopcntdqvlintrin.h": "avx512vpopcntdq_vl",
    "avx512vp2intersectintrin.h": "avx512vp2intersect",
    "avx512vlvp2intersectintrin.h": "avx512vl_vp2intersect",
    "avxvnniintrin.h": "avxvnni",
    "avxvnniint8intrin.h": "avxvnniint8",
    "avxvnniint16intrin.h": "avxvnniint16",
    "avxifmaintrin.h": "avxifma",
    "avxneconvertintrin.h": "avxneconvert",

    # x86 other extensions
    "fmaintrin.h": "fma",
    "fma4intrin.h": "fma4",
    "f16cintrin.h": "f16c",
    "bmiintrin.h": "bmi",
    "bmi2intrin.h": "bmi2",
    "lzcntintrin.h": "lzcnt",
    "tbmintrin.h": "tbm",
    "lwpintrin.h": "lwp",
    "xopintrin.h": "xop",
    "adcintrin.h": "adc",
    "adxintrin.h": "adx",
    "rtmintrin.h": "rtm",
    "shaintrin.h": "sha",
    "sha512intrin.h": "sha512",
    "sm3intrin.h": "sm3",
    "sm4intrin.h": "sm4",
    "gfniintrin.h": "gfni",
    "vaesintrin.h": "vaes",
    "vpclmulqdqintrin.h": "vpclmulqdq",
    "crc32intrin.h": "crc32",
    "cetintrin.h": "cet",
    "clflushoptintrin.h": "clflushopt",
    "clwbintrin.h": "clwb",
    "clzerointrin.h": "clzero",
    "cldemoteintrin.h": "cldemote",
    "movdirintrin.h": "movdir",
    "waitpkgintrin.h": "waitpkg",
    "enqcmdintrin.h": "enqcmd",
    "serializeintrin.h": "serialize",
    "hresetintrin.h": "hreset",
    "amxintrin.h": "amx",
    "amxfp16intrin.h": "amx_fp16",
    "amxcomplexintrin.h": "amx_complex",
    "cmpccxaddintrin.h": "cmpccxadd",
    "raointintrin.h": "raoint",
    "keylockerintrin.h": "keylocker",
    "xsaveintrin.h": "xsave",
    "xsaveoptintrin.h": "xsaveopt",
    "xsavecintrin.h": "xsavec",
    "xsavesintrin.h": "xsaves",
    "fxsrintrin.h": "fxsr",
    "rdseedintrin.h": "rdseed",
    "prfchwintrin.h": "prefetchw",
    "prfchiintrin.h": "prefetchi",
    "mwaitxintrin.h": "mwaitx",
    "ia32intrin.h": "ia32",
    "x86gprintrin.h": "x86gpr",
    "ptwriteintrin.h": "ptwrite",
    "invpcidintrin.h": "invpcid",
    "sgxintrin.h": "sgx",
    "pconfigintrin.h": "pconfig",
    "tsxldtrkintrin.h": "tsx",
    "uintrintrin.h": "uintr",
    "usermsrintrin.h": "usermsr",
    "pkuintrin.h": "pku",
    "rdpruintrin.h": "rdpru",
    "wbnoinvdintrin.h": "wbnoinvd",
    "htmintrin.h": "htm",
    "htmxlintrin.h": "htm_xl",

    # ARM NEON
    "arm_neon.h": "neon",
    "arm_neon_sve_bridge.h": "neon_sve_bridge",
    "arm_fp16.h": "arm_fp16",
    "arm_bf16.h": "arm_bf16",
    "arm_acle.h": "arm_acle",
    "arm_cde.h": "arm_cde",
    "arm_cmse.h": "arm_cmse",
    "arm_mve.h": "arm_mve",

    # ARM SVE
    "arm_sve.h": "sve",
    "arm_sme.h": "sme",

    # Meta headers (these include others)
    "immintrin.h": "immintrin_meta",
    "intrin.h": "intrin_meta",
    "x86intrin.h": "x86intrin_meta",
}

# ---------------------------------------------------------------------------
# 3. Regex patterns for extracting function names from headers
# ---------------------------------------------------------------------------
# Pattern 1: static __inline__ ... FUNCNAME(
# Matches: static __inline__ __m128 __DEFAULT_FN_ATTRS\n_mm_add_ps(...)
FUNC_PATTERNS = [
    # x86 style: function name starts with _ on next line after static __inline__
    re.compile(r'^\s*(_mm\w+|_mm256\w+|_mm512\w+|__lzcnt\w*|__tzcnt\w*|__rdtsc\w*|__bswap\w*|_bextr\w*|_blsi\w*|_blsr\w*|_blsmsk\w*|_bzhi\w*|_pdep\w*|_pext\w*|_andn\w*|_addcarry\w*|_subborrow\w*|_store_be\w*|_load_be\w*|_castf\w*|_castu\w*|_cvt\w*|_t1mskc\w*|_tzmsk\w*|__rol\w*|__ror\w*|_xbegin|_xend|_xabort|_xtest|__incsspd|__incsspq|__rdsspd|__rdsspq|__saveprevssp|__rstorssp|__wrssd|__wrssq|__wrussd|__wrussq|__setssbsy|__clrssbsy|_encodekey\w*|_aesenc\w*|_aesdec\w*|_loadiwkey|_enqcmd\w*|_serialize|_hreset|_cmpccxadd\w*|_rao\w*)\s*\(', re.MULTILINE),

    # ARM NEON style: __ai ... FUNCNAME(
    re.compile(r'__ai\s+(?:__attribute__\(\([^)]*\)\)\s+)*\w[\w\s*]*?\s+(v\w+)\s*\(', re.MULTILINE),

    # ARM SVE style: __ai ... svFUNCNAME(
    re.compile(r'(?:__ai|__aio)\s+(?:__attribute__\(\([^)]*\)\)\s+)*\w[\w\s*]*?\s+(sv\w+)\s*\(', re.MULTILINE),

    # Generic static inline with intrinsic-looking names
    re.compile(r'static\s+(?:__inline__|__inline|inline)\s+[\w\s*]+?\s+(__\w*intrin\w*|_mm\w+|_mm256\w+|_mm512\w+)\s*\(', re.MULTILINE),
]

# Also capture #define macros that act as intrinsics
MACRO_PATTERN = re.compile(r'#define\s+(_mm\w+|_mm256\w+|_mm512\w+)\s*\(', re.MULTILINE)


def classify_intrinsic(name, lib):
    """Classify an intrinsic function into a descriptive category and purpose."""
    purpose = "SIMD intrinsic"
    category = "simd_intrinsic"

    # Determine category based on prefix
    if name.startswith("_mm512_"):
        category = "avx512_intrinsic"
    elif name.startswith("_mm256_"):
        category = "avx_intrinsic"
    elif name.startswith("_mm_"):
        category = "sse_intrinsic"
    elif name.startswith("sv"):
        category = "sve_intrinsic"
    elif name.startswith("v") and not name.startswith("__"):
        category = "neon_intrinsic"
    elif name.startswith("__builtin_"):
        category = "compiler_builtin"

    # Extract operation from name
    # SSE/AVX: _mm[256|512]_OP_SUFFIX
    op = name
    for prefix in ("_mm512_", "_mm256_", "_mm_"):
        if name.startswith(prefix):
            op = name[len(prefix):]
            break

    # Determine purpose from operation name
    op_purposes = {
        "add": "Add packed elements",
        "sub": "Subtract packed elements",
        "mul": "Multiply packed elements",
        "div": "Divide packed elements",
        "sqrt": "Square root of packed elements",
        "rsqrt": "Reciprocal square root",
        "rcp": "Reciprocal approximation",
        "max": "Maximum of packed elements",
        "min": "Minimum of packed elements",
        "and": "Bitwise AND",
        "andnot": "Bitwise AND-NOT",
        "or": "Bitwise OR",
        "xor": "Bitwise XOR",
        "load": "Load from memory",
        "store": "Store to memory",
        "loadu": "Unaligned load from memory",
        "storeu": "Unaligned store to memory",
        "set": "Set packed elements",
        "set1": "Broadcast single value",
        "setzero": "Set all elements to zero",
        "setr": "Set packed elements in reverse",
        "movemask": "Create bitmask from sign bits",
        "shuffle": "Shuffle packed elements",
        "unpackhi": "Unpack and interleave high elements",
        "unpacklo": "Unpack and interleave low elements",
        "blend": "Blend packed elements",
        "blendv": "Variable blend packed elements",
        "permute": "Permute packed elements",
        "broadcast": "Broadcast element",
        "gather": "Gather from memory using indices",
        "scatter": "Scatter to memory using indices",
        "cmp": "Compare packed elements",
        "cmpeq": "Compare equal",
        "cmplt": "Compare less than",
        "cmpgt": "Compare greater than",
        "cmpge": "Compare greater or equal",
        "cmple": "Compare less or equal",
        "cmpneq": "Compare not equal",
        "cmpord": "Compare ordered",
        "cmpunord": "Compare unordered",
        "cvt": "Convert between types",
        "cvtt": "Convert with truncation",
        "cast": "Reinterpret cast",
        "extract": "Extract element",
        "insert": "Insert element",
        "hadd": "Horizontal add",
        "hsub": "Horizontal subtract",
        "dp": "Dot product",
        "madd": "Multiply and add",
        "fmadd": "Fused multiply-add",
        "fmsub": "Fused multiply-subtract",
        "fnmadd": "Fused negate-multiply-add",
        "fnmsub": "Fused negate-multiply-subtract",
        "sad": "Sum of absolute differences",
        "avg": "Average of packed elements",
        "abs": "Absolute value",
        "sign": "Negate based on sign",
        "sll": "Shift left logical",
        "srl": "Shift right logical",
        "sra": "Shift right arithmetic",
        "slli": "Shift left logical immediate",
        "srli": "Shift right logical immediate",
        "srai": "Shift right arithmetic immediate",
        "ror": "Rotate right",
        "rol": "Rotate left",
        "test": "Bitwise test",
        "testz": "Test all zeros",
        "testc": "Test all carry",
        "testnzc": "Test not zero and not carry",
        "pause": "Spin-loop hint",
        "sfence": "Store fence",
        "lfence": "Load fence",
        "mfence": "Memory fence",
        "clflush": "Cache line flush",
        "prefetch": "Prefetch data",
        "stream": "Non-temporal store/load",
        "mask": "Masked operation",
        "alignr": "Byte-align right",
        "packs": "Pack with saturation",
        "packus": "Pack unsigned with saturation",
        "movdup": "Move and duplicate",
        "movedup": "Move and duplicate low",
        "movehdup": "Move and duplicate high",
        "moveldup": "Move and duplicate low",
        "ceil": "Ceiling (round up)",
        "floor": "Floor (round down)",
        "round": "Round to nearest",
        "conflict": "Detect conflicts",
        "lzcnt": "Leading zero count",
        "tzcnt": "Trailing zero count",
        "popcnt": "Population count (bit count)",
        "ternarylogic": "Ternary logic operation",
        "compress": "Compress elements",
        "expand": "Expand elements",
        "reduce": "Reduce vector to scalar",
        "fixupimm": "Fix up special values",
        "getexp": "Get exponent",
        "getmant": "Get mantissa",
        "scalef": "Scale by power of 2",
        "range": "Range restriction",
        "fpclass": "Floating-point classify",
    }

    op_lower = op.lower()
    for key, desc in op_purposes.items():
        if op_lower.startswith(key):
            purpose = desc
            break

    # NEON-specific purposes
    if category == "neon_intrinsic":
        neon_ops = {
            "vadd": "Add vectors",
            "vsub": "Subtract vectors",
            "vmul": "Multiply vectors",
            "vdiv": "Divide vectors",
            "vfma": "Fused multiply-accumulate",
            "vmla": "Multiply-accumulate",
            "vmls": "Multiply-subtract",
            "vld": "Load from memory",
            "vst": "Store to memory",
            "vdup": "Duplicate scalar to vector",
            "vmov": "Move/copy vector",
            "vand": "Bitwise AND",
            "vorr": "Bitwise OR",
            "veor": "Bitwise XOR",
            "vbic": "Bit clear",
            "vorn": "Bitwise OR-NOT",
            "vneg": "Negate",
            "vabs": "Absolute value",
            "vmax": "Maximum",
            "vmin": "Minimum",
            "vcmp": "Compare",
            "vceq": "Compare equal",
            "vcge": "Compare greater or equal",
            "vcgt": "Compare greater than",
            "vcle": "Compare less or equal",
            "vclt": "Compare less than",
            "vshl": "Shift left",
            "vshr": "Shift right",
            "vrshr": "Rounding shift right",
            "vcvt": "Convert type",
            "vrev": "Reverse elements",
            "vzip": "Zip/interleave vectors",
            "vuzp": "Unzip/deinterleave vectors",
            "vtrn": "Transpose vectors",
            "vtbl": "Table lookup",
            "vtbx": "Table extension",
            "vext": "Extract from pair",
            "vcnt": "Count set bits",
            "vclz": "Count leading zeros",
            "vrec": "Reciprocal estimate",
            "vrsqrt": "Reciprocal square root estimate",
            "vpmax": "Pairwise maximum",
            "vpmin": "Pairwise minimum",
            "vpadd": "Pairwise add",
            "vqdmul": "Saturating doubling multiply",
            "vqadd": "Saturating add",
            "vqsub": "Saturating subtract",
            "vqshl": "Saturating shift left",
            "vqrshl": "Saturating rounding shift left",
            "vqmov": "Saturating move/narrow",
            "vhadd": "Halving add",
            "vhsub": "Halving subtract",
            "vrhadd": "Rounding halving add",
            "vbfdot": "BFloat16 dot product",
            "vbfmla": "BFloat16 multiply-accumulate",
            "vbfcvt": "BFloat16 convert",
            "vreinterpret": "Reinterpret cast",
            "vcreate": "Create vector from integer",
            "vget": "Get lane/element",
            "vset": "Set lane/element",
            "vcombine": "Combine two vectors",
        }
        name_lower = name.lower()
        for key, desc in neon_ops.items():
            if name_lower.startswith(key):
                purpose = desc
                break

    # SVE-specific purposes
    if category == "sve_intrinsic":
        sve_ops = {
            "svld": "Load from memory",
            "svst": "Store to memory",
            "svadd": "Add vectors",
            "svsub": "Subtract vectors",
            "svmul": "Multiply vectors",
            "svdiv": "Divide vectors",
            "svand": "Bitwise AND",
            "svorr": "Bitwise OR",
            "sveor": "Bitwise XOR",
            "svnot": "Bitwise NOT",
            "svmax": "Maximum",
            "svmin": "Minimum",
            "svabs": "Absolute value",
            "svneg": "Negate",
            "svcmp": "Compare",
            "svdup": "Duplicate/broadcast",
            "svindex": "Create index vector",
            "svwhile": "While predicate",
            "svptrue": "All-true predicate",
            "svpfalse": "All-false predicate",
            "svcnt": "Count elements",
            "svlen": "Vector length query",
            "svmla": "Multiply-accumulate",
            "svmls": "Multiply-subtract",
            "svmad": "Multiply-add (alt)",
            "svmsb": "Multiply-subtract (alt)",
            "svcvt": "Convert type",
            "svrev": "Reverse elements",
            "svsel": "Select using predicate",
            "svmov": "Move/copy",
            "svext": "Extract",
            "svtbl": "Table lookup",
            "svzip": "Zip/interleave",
            "svuzp": "Unzip/deinterleave",
            "svtrn": "Transpose",
            "svclz": "Count leading zeros",
            "svcnt": "Count set bits",
            "svrec": "Reciprocal estimate",
            "svrsqrt": "Reciprocal square root estimate",
            "svprf": "Prefetch",
            "svlast": "Extract last active element",
            "svclast": "Conditionally extract last",
            "svcompact": "Compact active elements",
            "svsplice": "Splice vectors",
            "svreinterpret": "Reinterpret cast",
        }
        name_lower = name.lower()
        for key, desc in sve_ops.items():
            if name_lower.startswith(key):
                purpose = desc
                break

    return purpose, category


def parse_header(filepath):
    """Parse a single header file and extract intrinsic function names."""
    basename = os.path.basename(filepath)
    lib = HEADER_LIB_MAP.get(basename, basename.replace("intrin.h", "").replace(".h", ""))

    try:
        with open(filepath, "r", errors="replace") as f:
            content = f.read()
    except Exception as e:
        print(f"  WARNING: Cannot read {filepath}: {e}", file=sys.stderr)
        return {}

    found = {}

    # Multi-line pattern: static __inline__ RETTYPE ATTRS\nFUNCNAME(
    # This handles the common case where function name is on the next line
    multiline_pattern = re.compile(
        r'(?:static\s+__inline__\s+[\w\s*]+\s+\w+\s*\n\s*'  # static __inline__ type ATTRS
        r'|__ai\s+(?:__attribute__\(\([^)]*\)\)\s+)*[\w\s*]+\s+)'  # or __ai [attrs] type
        r'(_mm\w+|_mm256\w+|_mm512\w+|v\w+|sv\w+|__\w+)\s*\(',
        re.MULTILINE
    )

    for m in multiline_pattern.finditer(content):
        name = m.group(1)
        # Skip internal helpers like __noswap_, __rev_, type aliases
        if name.startswith("__noswap_") or name.startswith("__rev"):
            continue
        if name in found:
            continue
        purpose, category = classify_intrinsic(name, lib)
        found[name] = {
            "lib": lib,
            "purpose": purpose,
            "category": category,
            "header": basename
        }

    # Also try the simpler patterns
    for pat in FUNC_PATTERNS:
        for m in pat.finditer(content):
            name = m.group(1)
            if name.startswith("__noswap_") or name.startswith("__rev"):
                continue
            if name in found:
                continue
            purpose, category = classify_intrinsic(name, lib)
            found[name] = {
                "lib": lib,
                "purpose": purpose,
                "category": category,
                "header": basename
            }

    # Macro-defined intrinsics
    for m in MACRO_PATTERN.finditer(content):
        name = m.group(1)
        if name in found:
            continue
        purpose, category = classify_intrinsic(name, lib)
        found[name] = {
            "lib": lib,
            "purpose": purpose,
            "category": category,
            "header": basename
        }

    return found


# ---------------------------------------------------------------------------
# 4. Compiler builtins (hardcoded -- these are not in headers, they are
#    built into the compiler itself)
# ---------------------------------------------------------------------------
def get_compiler_builtins():
    """Return comprehensive list of GCC/Clang compiler builtins."""
    builtins = {}

    # -- Bit manipulation --
    for suffix in ("", "l", "ll"):
        builtins[f"__builtin_popcount{suffix}"] = {
            "lib": "compiler", "purpose": "Count set bits (popcount)",
            "category": "compiler_builtin"
        }
        builtins[f"__builtin_clz{suffix}"] = {
            "lib": "compiler", "purpose": "Count leading zeros",
            "category": "compiler_builtin"
        }
        builtins[f"__builtin_ctz{suffix}"] = {
            "lib": "compiler", "purpose": "Count trailing zeros",
            "category": "compiler_builtin"
        }
        builtins[f"__builtin_parity{suffix}"] = {
            "lib": "compiler", "purpose": "Parity of set bits",
            "category": "compiler_builtin"
        }
        builtins[f"__builtin_ffs{suffix}"] = {
            "lib": "compiler", "purpose": "Find first set bit",
            "category": "compiler_builtin"
        }

    # Byte swap
    for bits in (16, 32, 64):
        builtins[f"__builtin_bswap{bits}"] = {
            "lib": "compiler", "purpose": f"Byte-swap {bits}-bit integer",
            "category": "compiler_builtin"
        }

    # Bit reverse
    for bits in (8, 16, 32, 64):
        builtins[f"__builtin_bitreverse{bits}"] = {
            "lib": "compiler", "purpose": f"Reverse bits of {bits}-bit integer",
            "category": "compiler_builtin"
        }

    # Rotate
    for bits in (8, 16, 32, 64):
        builtins[f"__builtin_rotateleft{bits}"] = {
            "lib": "compiler", "purpose": f"Rotate left {bits}-bit",
            "category": "compiler_builtin"
        }
        builtins[f"__builtin_rotateright{bits}"] = {
            "lib": "compiler", "purpose": f"Rotate right {bits}-bit",
            "category": "compiler_builtin"
        }

    # -- Branch prediction --
    builtins["__builtin_expect"] = {
        "lib": "compiler", "purpose": "Branch prediction hint (likely/unlikely)",
        "category": "compiler_builtin"
    }
    builtins["__builtin_expect_with_probability"] = {
        "lib": "compiler", "purpose": "Branch prediction with probability",
        "category": "compiler_builtin"
    }
    builtins["__builtin_unpredictable"] = {
        "lib": "compiler", "purpose": "Mark branch as unpredictable",
        "category": "compiler_builtin"
    }

    # -- Memory operations --
    mem_ops = {
        "__builtin_memcpy": "Copy memory (optimized)",
        "__builtin_memmove": "Move memory (overlapping safe)",
        "__builtin_memset": "Fill memory with byte value",
        "__builtin_memcmp": "Compare memory blocks",
        "__builtin_strlen": "String length",
        "__builtin_strcmp": "String compare",
        "__builtin_strncmp": "String compare (bounded)",
        "__builtin_strcpy": "String copy",
        "__builtin_strncpy": "String copy (bounded)",
        "__builtin_strcat": "String concatenate",
        "__builtin_strncat": "String concatenate (bounded)",
        "__builtin_strchr": "Find character in string",
        "__builtin_strrchr": "Find last character in string",
        "__builtin_strstr": "Find substring",
        "__builtin_bzero": "Zero memory",
        "__builtin_bcopy": "Copy memory (legacy BSD)",
        "__builtin___memcpy_chk": "Checked memcpy (fortified)",
        "__builtin___memmove_chk": "Checked memmove (fortified)",
        "__builtin___memset_chk": "Checked memset (fortified)",
        "__builtin___strcpy_chk": "Checked strcpy (fortified)",
        "__builtin___strncpy_chk": "Checked strncpy (fortified)",
        "__builtin___strcat_chk": "Checked strcat (fortified)",
        "__builtin___strncat_chk": "Checked strncat (fortified)",
        "__builtin_object_size": "Object size for bounds checking",
        "__builtin_dynamic_object_size": "Dynamic object size",
    }
    for name, purpose in mem_ops.items():
        builtins[name] = {"lib": "compiler", "purpose": purpose, "category": "compiler_builtin"}

    # -- Math builtins --
    math_funcs = [
        "abs", "labs", "llabs",
        "fabs", "fabsf", "fabsl",
        "ceil", "ceilf", "ceill",
        "floor", "floorf", "floorl",
        "round", "roundf", "roundl",
        "trunc", "truncf", "truncl",
        "nearbyint", "nearbyintf", "nearbyintl",
        "rint", "rintf", "rintl",
        "sqrt", "sqrtf", "sqrtl",
        "cbrt", "cbrtf", "cbrtl",
        "pow", "powf", "powl",
        "exp", "expf", "expl",
        "exp2", "exp2f", "exp2l",
        "expm1", "expm1f", "expm1l",
        "log", "logf", "logl",
        "log2", "log2f", "log2l",
        "log10", "log10f", "log10l",
        "log1p", "log1pf", "log1pl",
        "sin", "sinf", "sinl",
        "cos", "cosf", "cosl",
        "tan", "tanf", "tanl",
        "asin", "asinf", "asinl",
        "acos", "acosf", "acosl",
        "atan", "atanf", "atanl",
        "atan2", "atan2f", "atan2l",
        "sinh", "sinhf", "sinhl",
        "cosh", "coshf", "coshl",
        "tanh", "tanhf", "tanhl",
        "fma", "fmaf", "fmal",
        "fmax", "fmaxf", "fmaxl",
        "fmin", "fminf", "fminl",
        "fmod", "fmodf", "fmodl",
        "remainder", "remainderf", "remainderl",
        "copysign", "copysignf", "copysignl",
        "nan", "nanf", "nanl",
        "inf", "inff", "infl",
        "huge_val", "huge_valf", "huge_vall",
        "isnan", "isinf", "isfinite", "isnormal",
        "fpclassify", "signbit",
        "frexp", "frexpf", "frexpl",
        "ldexp", "ldexpf", "ldexpl",
        "scalbn", "scalbnf", "scalbnl",
        "logb", "logbf", "logbl",
        "ilogb", "ilogbf", "ilogbl",
        "hypot", "hypotf", "hypotl",
        "erf", "erff", "erfl",
        "erfc", "erfcf", "erfcl",
        "lgamma", "lgammaf", "lgammal",
        "tgamma", "tgammaf", "tgammal",
    ]
    for func in math_funcs:
        builtins[f"__builtin_{func}"] = {
            "lib": "compiler", "purpose": f"Math: {func}",
            "category": "compiler_builtin_math"
        }

    # -- Atomic operations --
    atomic_ops = {
        "__atomic_load": "Atomic load",
        "__atomic_load_n": "Atomic load (scalar)",
        "__atomic_store": "Atomic store",
        "__atomic_store_n": "Atomic store (scalar)",
        "__atomic_exchange": "Atomic exchange",
        "__atomic_exchange_n": "Atomic exchange (scalar)",
        "__atomic_compare_exchange": "Atomic compare-and-exchange",
        "__atomic_compare_exchange_n": "Atomic compare-and-exchange (scalar)",
        "__atomic_add_fetch": "Atomic add and fetch result",
        "__atomic_sub_fetch": "Atomic subtract and fetch result",
        "__atomic_and_fetch": "Atomic AND and fetch result",
        "__atomic_or_fetch": "Atomic OR and fetch result",
        "__atomic_xor_fetch": "Atomic XOR and fetch result",
        "__atomic_nand_fetch": "Atomic NAND and fetch result",
        "__atomic_fetch_add": "Atomic fetch and add",
        "__atomic_fetch_sub": "Atomic fetch and subtract",
        "__atomic_fetch_and": "Atomic fetch and AND",
        "__atomic_fetch_or": "Atomic fetch and OR",
        "__atomic_fetch_xor": "Atomic fetch and XOR",
        "__atomic_fetch_nand": "Atomic fetch and NAND",
        "__atomic_test_and_set": "Atomic test-and-set",
        "__atomic_clear": "Atomic clear flag",
        "__atomic_thread_fence": "Atomic thread fence",
        "__atomic_signal_fence": "Atomic signal fence",
        "__atomic_always_lock_free": "Check if always lock-free",
        "__atomic_is_lock_free": "Check if lock-free",
        # Legacy __sync builtins
        "__sync_fetch_and_add": "Legacy atomic fetch-and-add",
        "__sync_fetch_and_sub": "Legacy atomic fetch-and-subtract",
        "__sync_fetch_and_or": "Legacy atomic fetch-and-OR",
        "__sync_fetch_and_and": "Legacy atomic fetch-and-AND",
        "__sync_fetch_and_xor": "Legacy atomic fetch-and-XOR",
        "__sync_fetch_and_nand": "Legacy atomic fetch-and-NAND",
        "__sync_add_and_fetch": "Legacy atomic add-and-fetch",
        "__sync_sub_and_fetch": "Legacy atomic subtract-and-fetch",
        "__sync_or_and_fetch": "Legacy atomic OR-and-fetch",
        "__sync_and_and_fetch": "Legacy atomic AND-and-fetch",
        "__sync_xor_and_fetch": "Legacy atomic XOR-and-fetch",
        "__sync_nand_and_fetch": "Legacy atomic NAND-and-fetch",
        "__sync_bool_compare_and_swap": "Legacy atomic CAS (bool)",
        "__sync_val_compare_and_swap": "Legacy atomic CAS (value)",
        "__sync_lock_test_and_set": "Legacy atomic test-and-set",
        "__sync_lock_release": "Legacy atomic release",
        "__sync_synchronize": "Legacy full memory barrier",
    }
    for name, purpose in atomic_ops.items():
        builtins[name] = {"lib": "compiler", "purpose": purpose, "category": "compiler_builtin_atomic"}

    # -- Overflow checking --
    for op in ("add", "sub", "mul"):
        for suffix in ("", "l", "ll"):
            builtins[f"__builtin_{op}_overflow"] = {
                "lib": "compiler", "purpose": f"Checked {op} with overflow detection",
                "category": "compiler_builtin"
            }
            builtins[f"__builtin_s{op}{suffix}_overflow"] = {
                "lib": "compiler", "purpose": f"Signed {op} overflow check",
                "category": "compiler_builtin"
            }
            builtins[f"__builtin_u{op}{suffix}_overflow"] = {
                "lib": "compiler", "purpose": f"Unsigned {op} overflow check",
                "category": "compiler_builtin"
            }

    # -- Type properties --
    type_ops = {
        "__builtin_types_compatible_p": "Check type compatibility",
        "__builtin_classify_type": "Classify expression type",
        "__builtin_constant_p": "Check if compile-time constant",
        "__builtin_is_constant_evaluated": "Check if in constant evaluation",
        "__builtin_choose_expr": "Compile-time expression selection",
        "__builtin_offsetof": "Offset of member in struct",
        "__builtin_alignof": "Alignment requirement of type",
        "__builtin_sizeof": "Size of type",
    }
    for name, purpose in type_ops.items():
        builtins[name] = {"lib": "compiler", "purpose": purpose, "category": "compiler_builtin"}

    # -- Control flow --
    cf_ops = {
        "__builtin_unreachable": "Mark unreachable code path",
        "__builtin_trap": "Generate trap instruction (abort)",
        "__builtin_debugtrap": "Generate debug trap (breakpoint)",
        "__builtin_abort": "Abort execution",
        "__builtin_exit": "Exit program",
        "__builtin_return_address": "Get return address of current/parent frame",
        "__builtin_frame_address": "Get frame pointer of current/parent frame",
        "__builtin_extract_return_addr": "Extract return address from pointer",
        "__builtin_setjmp": "Save execution context",
        "__builtin_longjmp": "Restore execution context",
    }
    for name, purpose in cf_ops.items():
        builtins[name] = {"lib": "compiler", "purpose": purpose, "category": "compiler_builtin"}

    # -- Variadic --
    va_ops = {
        "__builtin_va_start": "Initialize variadic argument list",
        "__builtin_va_end": "End variadic argument list",
        "__builtin_va_arg": "Get next variadic argument",
        "__builtin_va_copy": "Copy variadic argument list",
    }
    for name, purpose in va_ops.items():
        builtins[name] = {"lib": "compiler", "purpose": purpose, "category": "compiler_builtin"}

    # -- Prefetch / cache --
    builtins["__builtin_prefetch"] = {
        "lib": "compiler", "purpose": "Prefetch data into cache",
        "category": "compiler_builtin"
    }
    builtins["__builtin_clear_cache"] = {
        "lib": "compiler", "purpose": "Clear instruction cache",
        "category": "compiler_builtin"
    }

    # -- Sanitizer / instrumentation --
    san_ops = {
        "__builtin_assume": "Optimization hint (assume condition true)",
        "__builtin_assume_aligned": "Pointer alignment hint",
        "__builtin___clear_cache": "Clear instruction cache range",
        "__builtin_annotation": "Source-level annotation",
        "__builtin_launder": "Pointer laundering (prevent optimization)",
    }
    for name, purpose in san_ops.items():
        builtins[name] = {"lib": "compiler", "purpose": purpose, "category": "compiler_builtin"}

    # -- Clang-specific --
    clang_ops = {
        "__builtin_addressof": "Get address (bypasses operator&)",
        "__builtin_coro_resume": "Coroutine resume",
        "__builtin_coro_destroy": "Coroutine destroy",
        "__builtin_coro_done": "Check if coroutine done",
        "__builtin_coro_promise": "Get coroutine promise object",
        "__builtin_coro_size": "Coroutine frame size",
        "__builtin_coro_begin": "Coroutine begin",
        "__builtin_coro_end": "Coroutine end",
        "__builtin_coro_suspend": "Coroutine suspend point",
        "__builtin_coro_noop": "No-op coroutine",
        "__builtin_operator_new": "Optimized operator new",
        "__builtin_operator_delete": "Optimized operator delete",
        "__builtin_char_memchr": "memchr returning char*",
        "__builtin_dump_struct": "Debug: dump struct fields",
        "__builtin_FILE": "Current file name",
        "__builtin_FUNCTION": "Current function name",
        "__builtin_LINE": "Current line number",
        "__builtin_COLUMN": "Current column number",
        "__builtin_source_location": "Source location object",
        "__builtin_convertvector": "Convert vector element types",
        "__builtin_shufflevector": "Shuffle vector elements",
        "__builtin_reduce_add": "Reduce vector by addition",
        "__builtin_reduce_mul": "Reduce vector by multiplication",
        "__builtin_reduce_and": "Reduce vector by AND",
        "__builtin_reduce_or": "Reduce vector by OR",
        "__builtin_reduce_xor": "Reduce vector by XOR",
        "__builtin_reduce_max": "Reduce vector to maximum",
        "__builtin_reduce_min": "Reduce vector to minimum",
        "__builtin_elementwise_abs": "Element-wise absolute value",
        "__builtin_elementwise_max": "Element-wise maximum",
        "__builtin_elementwise_min": "Element-wise minimum",
        "__builtin_elementwise_ceil": "Element-wise ceiling",
        "__builtin_elementwise_floor": "Element-wise floor",
        "__builtin_elementwise_roundeven": "Element-wise round to even",
        "__builtin_elementwise_trunc": "Element-wise truncate",
        "__builtin_elementwise_canonicalize": "Element-wise canonicalize float",
        "__builtin_elementwise_copysign": "Element-wise copysign",
        "__builtin_elementwise_fma": "Element-wise fused multiply-add",
        "__builtin_elementwise_add_sat": "Element-wise saturating add",
        "__builtin_elementwise_sub_sat": "Element-wise saturating subtract",
        "__builtin_matrix_transpose": "Transpose matrix",
        "__builtin_matrix_column_major_load": "Load column-major matrix",
        "__builtin_matrix_column_major_store": "Store column-major matrix",
    }
    for name, purpose in clang_ops.items():
        builtins[name] = {"lib": "compiler", "purpose": purpose, "category": "compiler_builtin"}

    # -- MSVC-compatible builtins --
    msvc_ops = {
        "_BitScanForward": "Find first set bit (forward)",
        "_BitScanReverse": "Find first set bit (reverse)",
        "_BitScanForward64": "Find first set bit forward (64-bit)",
        "_BitScanReverse64": "Find first set bit reverse (64-bit)",
        "_InterlockedExchange": "Atomic exchange (32-bit)",
        "_InterlockedExchange64": "Atomic exchange (64-bit)",
        "_InterlockedExchangeAdd": "Atomic exchange-add (32-bit)",
        "_InterlockedExchangeAdd64": "Atomic exchange-add (64-bit)",
        "_InterlockedCompareExchange": "Atomic CAS (32-bit)",
        "_InterlockedCompareExchange64": "Atomic CAS (64-bit)",
        "_InterlockedCompareExchange128": "Atomic CAS (128-bit)",
        "_InterlockedIncrement": "Atomic increment (32-bit)",
        "_InterlockedDecrement": "Atomic decrement (32-bit)",
        "_InterlockedIncrement64": "Atomic increment (64-bit)",
        "_InterlockedDecrement64": "Atomic decrement (64-bit)",
        "_InterlockedAnd": "Atomic AND (32-bit)",
        "_InterlockedOr": "Atomic OR (32-bit)",
        "_InterlockedXor": "Atomic XOR (32-bit)",
        "_InterlockedAnd64": "Atomic AND (64-bit)",
        "_InterlockedOr64": "Atomic OR (64-bit)",
        "_InterlockedXor64": "Atomic XOR (64-bit)",
        "_ReadWriteBarrier": "Compiler read-write barrier",
        "_ReadBarrier": "Compiler read barrier",
        "_WriteBarrier": "Compiler write barrier",
        "__debugbreak": "Debug breakpoint",
        "__nop": "No operation",
        "__cpuid": "CPU identification",
        "__cpuidex": "Extended CPU identification",
        "__rdtsc": "Read time-stamp counter",
        "__rdtscp": "Read time-stamp counter with processor ID",
        "_byteswap_ushort": "Byte-swap 16-bit",
        "_byteswap_ulong": "Byte-swap 32-bit",
        "_byteswap_uint64": "Byte-swap 64-bit",
        "__popcnt": "Population count (32-bit)",
        "__popcnt64": "Population count (64-bit)",
        "_lzcnt_u32": "Leading zero count (32-bit)",
        "_lzcnt_u64": "Leading zero count (64-bit)",
        "_tzcnt_u32": "Trailing zero count (32-bit)",
        "_tzcnt_u64": "Trailing zero count (64-bit)",
        "__stosb": "Store byte string",
        "__stosd": "Store dword string",
        "__stosq": "Store qword string",
        "__movsb": "Move byte string",
        "__movsd": "Move dword string",
        "__movsq": "Move qword string",
        "_mul128": "128-bit multiply",
        "_umul128": "Unsigned 128-bit multiply",
        "__mulh": "Multiply high (signed)",
        "__umulh": "Multiply high (unsigned)",
        "_div128": "128-bit divide",
        "_udiv128": "Unsigned 128-bit divide",
        "__emul": "Extended multiply",
        "__emulu": "Extended unsigned multiply",
        "_ReturnAddress": "Get return address",
        "_AddressOfReturnAddress": "Get address of return address",
    }
    for name, purpose in msvc_ops.items():
        builtins[name] = {"lib": "msvc_compat", "purpose": purpose, "category": "compiler_builtin_msvc"}

    return builtins


# ---------------------------------------------------------------------------
# 5. Main
# ---------------------------------------------------------------------------
def main():
    print("=" * 70)
    print("Karadul Compiler Intrinsics Signature Generator")
    print("=" * 70)

    clang_dir = get_clang_include_dir()
    print(f"\nClang include dir: {clang_dir}")

    # Collect all headers
    all_headers = []
    for root, dirs, files in os.walk(clang_dir):
        # Skip ppc_wrappers -- those are PPC reimplementations of x86 intrinsics
        if "ppc_wrappers" in root or "openmp_wrappers" in root:
            continue
        for f in files:
            if f.endswith(".h"):
                all_headers.append(os.path.join(root, f))

    # Filter to intrinsic-related headers
    intrinsic_headers = []
    for h in all_headers:
        basename = os.path.basename(h)
        if (basename in HEADER_LIB_MAP or
            "intrin" in basename.lower() or
            basename.startswith("arm_")):
            intrinsic_headers.append(h)

    print(f"Found {len(intrinsic_headers)} intrinsic headers (from {len(all_headers)} total)\n")

    # Parse each header
    all_sigs = {}
    header_stats = {}

    for h in sorted(intrinsic_headers):
        basename = os.path.basename(h)
        sigs = parse_header(h)
        new_count = 0
        for name, info in sigs.items():
            if name not in all_sigs:
                all_sigs[name] = info
                new_count += 1
        header_stats[basename] = {"total": len(sigs), "new": new_count}
        if len(sigs) > 0:
            print(f"  {basename:45s}  {len(sigs):>6d} found, {new_count:>6d} new")

    # Add compiler builtins
    builtins = get_compiler_builtins()
    builtin_new = 0
    for name, info in builtins.items():
        if name not in all_sigs:
            all_sigs[name] = info
            builtin_new += 1
    print(f"\n  {'[compiler builtins]':45s}  {len(builtins):>6d} found, {builtin_new:>6d} new")

    # Statistics
    cat_counts = defaultdict(int)
    lib_counts = defaultdict(int)
    for info in all_sigs.values():
        cat_counts[info["category"]] += 1
        lib_counts[info["lib"]] += 1

    print(f"\n{'=' * 70}")
    print(f"TOTAL UNIQUE SIGNATURES: {len(all_sigs):,}")
    print(f"{'=' * 70}")

    print(f"\nBy category:")
    for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
        print(f"  {cat:40s} {count:>8,d}")

    print(f"\nTop 20 libraries:")
    for lib, count in sorted(lib_counts.items(), key=lambda x: -x[1])[:20]:
        print(f"  {lib:40s} {count:>8,d}")

    # Build output JSON
    # Use list format to be consistent with combined_1M.json
    sig_list = []
    for name, info in sorted(all_sigs.items()):
        entry = {"name": name}
        entry.update(info)
        # Rename 'lib' -> 'library' for consistency with other sig files
        if "lib" in entry:
            entry["library"] = entry.pop("lib")
        sig_list.append(entry)

    output = {
        "meta": {
            "generator": "karadul-sig-gen-intrinsics",
            "date": datetime.now().strftime("%Y-%m-%d"),
            "version": "1.0",
            "description": "Compiler intrinsics: SSE/AVX/NEON/SVE + GCC/Clang/MSVC builtins",
            "clang_include_dir": clang_dir,
            "total": len(sig_list),
            "stats": {
                "by_category": dict(sorted(cat_counts.items(), key=lambda x: -x[1])),
                "by_library": dict(sorted(lib_counts.items(), key=lambda x: -x[1])[:30]),
                "headers_parsed": len([h for h, s in header_stats.items() if s["total"] > 0]),
            }
        },
        "signatures": sig_list
    }

    os.makedirs(SIGS_DIR, exist_ok=True)
    with open(OUTPUT, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\nOutput: {OUTPUT}")
    print(f"File size: {os.path.getsize(OUTPUT) / (1024*1024):.1f} MB")


if __name__ == "__main__":
    main()
