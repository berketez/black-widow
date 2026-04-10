"""Ground truth generator for Karadul benchmark suite.

Extracts export symbols from real binaries (macOS dylib/Mach-O) using nm,
producing structured ground truth data for accuracy measurement.

Key differences from BenchmarkRunner._extract_symbols_nm:
- That method targets debug binaries, converting to Ghidra FUN_XXXXXXXX format.
- This module targets EXPORT symbols from shared libraries (nm -gU),
  keeps raw hex addresses, applies C++ demangling, and filters
  Ghidra auto-names (FUN_xxx, sub_xxx, etc.).

Usage:
    gen = GroundTruthGenerator()

    # From any binary with nm
    symbols = gen.generate_from_nm(Path("/usr/lib/libsqlite3.dylib"))

    # Full ground truth with JSON output
    gt = gen.generate_from_binary(
        binary_path=Path("/usr/lib/libcrypto.dylib"),
        output_path=Path("ground_truth_libcrypto.json"),
    )

    # Compare with Karadul results
    metrics = gen.compare_with_karadul(gt, karadul_naming_map)

Note on optimization levels:
    nm -gU only shows EXPORTED symbols. Static/inline functions are invisible.
    - O0: ~90-95% coverage of public API
    - O2: ~75% (inline losses)
    - O3+LTO: ~55% (aggressive inlining)
    SQLite amalgamation is particularly affected (many static helpers).
    OpenSSL is a better benchmark target (more exported symbols).
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from tests.benchmark.metrics import AccuracyCalculator, BenchmarkMetrics

logger = logging.getLogger(__name__)


# Patterns matching Ghidra/IDA auto-generated placeholder names.
_GHIDRA_AUTO_PATTERNS = [
    re.compile(r"^FUN_[0-9a-fA-F]+$"),
    re.compile(r"^sub_[0-9a-fA-F]+$"),
    re.compile(r"^DAT_[0-9a-fA-F]+$"),
    re.compile(r"^PTR_[0-9a-fA-F]+$"),
    re.compile(r"^thunk_FUN_[0-9a-fA-F]+$"),
    re.compile(r"^LAB_[0-9a-fA-F]+$"),
    re.compile(r"^switchD_[0-9a-fA-F]+$"),
    re.compile(r"^caseD_[0-9a-fA-F]+$"),
]

# Compiler/runtime internal symbols to skip
_INTERNAL_PREFIXES = (
    "__",
    "_OBJC_",
    "_objc_",
    "GCC_",
    "GLIBC_",
    "dyld_",
    "radr://",
    ".objc_",
)

# nm output line: "00000000000abcde T _symbol_name"
# macOS nm uses leading underscore for C symbols
_NM_LINE_PATTERN = re.compile(
    r"^([0-9a-fA-F]+)\s+([A-Za-z])\s+_?(.+)$"
)


@dataclass
class GroundTruthSymbol:
    """A single symbol from the ground truth."""

    address: str  # hex string, e.g. "0x00001234"
    name: str  # demangled symbol name
    symbol_type: str  # nm type: T (text/code), D (data), B (bss), etc.

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "name": self.name,
            "type": self.symbol_type,
        }


@dataclass
class GroundTruth:
    """Complete ground truth for a binary."""

    binary_path: str
    symbols: list[GroundTruthSymbol] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    @property
    def symbol_count(self) -> int:
        return len(self.symbols)

    @property
    def function_count(self) -> int:
        """Count only code symbols (T/t type)."""
        return sum(1 for s in self.symbols if s.symbol_type in ("T", "t"))

    @property
    def data_count(self) -> int:
        """Count data symbols (D/d/B/b/S/s type)."""
        return sum(
            1 for s in self.symbols
            if s.symbol_type.lower() in ("d", "b", "s")
        )

    def as_address_map(self) -> dict[str, str]:
        """Return {hex_address: symbol_name} dict."""
        return {s.address: s.name for s in self.symbols}

    def as_name_set(self) -> set[str]:
        """Return set of all symbol names."""
        return {s.name for s in self.symbols}

    def functions_only(self) -> dict[str, str]:
        """Return {address: name} for code symbols only."""
        return {
            s.address: s.name
            for s in self.symbols
            if s.symbol_type in ("T", "t")
        }

    def to_dict(self) -> dict:
        return {
            "binary_path": self.binary_path,
            "symbol_count": self.symbol_count,
            "function_count": self.function_count,
            "data_count": self.data_count,
            "metadata": self.metadata,
            "symbols": [s.to_dict() for s in self.symbols],
        }

    def save_json(self, path: Path) -> Path:
        """Save ground truth to JSON file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info(
            "Ground truth saved to %s (%d symbols)", path, self.symbol_count
        )
        return path

    @classmethod
    def load_json(cls, path: Path) -> "GroundTruth":
        """Load ground truth from JSON file."""
        data = json.loads(path.read_text(encoding="utf-8"))
        symbols = [
            GroundTruthSymbol(
                address=s["address"],
                name=s["name"],
                symbol_type=s["type"],
            )
            for s in data.get("symbols", [])
        ]
        return cls(
            binary_path=data.get("binary_path", str(path)),
            symbols=symbols,
            metadata=data.get("metadata", {}),
        )


def _is_ghidra_auto_name(name: str) -> bool:
    """Check if a name looks like a Ghidra/IDA auto-generated placeholder."""
    return any(p.match(name) for p in _GHIDRA_AUTO_PATTERNS)


def _is_internal_symbol(name: str) -> bool:
    """Check if symbol is a compiler/runtime internal."""
    return name.startswith(_INTERNAL_PREFIXES)


class GroundTruthGenerator:
    """Generates ground truth symbol tables from binaries using nm.

    Designed for macOS arm64 binaries (dylib, Mach-O executables).
    Uses nm -gU for external defined symbols, with optional C++ demangling.
    """

    def __init__(
        self,
        demangle: bool = True,
        include_data: bool = False,
        filter_internal: bool = True,
    ) -> None:
        """
        Args:
            demangle: Apply C++ demangling (nm --demangle or c++filt).
            include_data: Include data symbols (D/d/B/b), not just functions.
            filter_internal: Skip compiler/runtime internal symbols (__xxx).
        """
        self.demangle = demangle
        self.include_data = include_data
        self.filter_internal = filter_internal

    def generate_from_binary(
        self,
        binary_path: Path,
        output_path: Optional[Path] = None,
    ) -> GroundTruth:
        """Extract export symbols from binary and optionally save to JSON.

        Args:
            binary_path: Path to the binary (dylib, executable, .o).
            output_path: If given, save ground truth JSON here.

        Returns:
            GroundTruth object with all extracted symbols.
        """
        symbols_raw = self.generate_from_nm(binary_path)

        symbols = [
            GroundTruthSymbol(address=addr, name=name, symbol_type=stype)
            for addr, (name, stype) in symbols_raw.items()
        ]

        gt = GroundTruth(
            binary_path=str(binary_path),
            symbols=symbols,
            metadata={
                "generator": "GroundTruthGenerator",
                "demangle": self.demangle,
                "include_data": self.include_data,
                "filter_internal": self.filter_internal,
            },
        )

        if output_path is not None:
            gt.save_json(output_path)

        return gt

    def generate_from_nm(
        self, binary_path: Path
    ) -> dict[str, tuple[str, str]]:
        """Run nm on binary and parse output.

        Returns:
            Dict mapping hex_address -> (symbol_name, nm_type).
            Address format: "0x" + lowercase hex, e.g. "0x00001a3f".
        """
        nm_output = self._run_nm(binary_path)
        if nm_output is None:
            return {}

        result: dict[str, tuple[str, str]] = {}

        for line in nm_output.splitlines():
            line = line.strip()
            if not line:
                continue

            m = _NM_LINE_PATTERN.match(line)
            if not m:
                continue

            raw_addr = m.group(1)
            sym_type = m.group(2)
            sym_name = m.group(3)

            # Filter by type
            if not self.include_data and sym_type.lower() not in ("t",):
                continue

            # Filter internal symbols
            if self.filter_internal and _is_internal_symbol(sym_name):
                continue

            # Filter Ghidra auto-names (shouldn't appear in nm output,
            # but defensive check)
            if _is_ghidra_auto_name(sym_name):
                continue

            # Normalize address
            addr = f"0x{raw_addr.lower()}"

            result[addr] = (sym_name, sym_type)

        logger.info(
            "Parsed %d symbols from nm output of %s",
            len(result),
            binary_path,
        )
        return result

    def compare_with_karadul(
        self,
        ground_truth: GroundTruth,
        karadul_naming_map: dict[str, str],
    ) -> BenchmarkMetrics:
        """Compare Karadul's recovered names against ground truth.

        The naming_map keys should be Ghidra-style placeholders (FUN_xxx)
        or addresses. Values are recovered names.

        This builds a comparison by matching addresses where possible,
        then delegates to AccuracyCalculator for scoring.

        Args:
            ground_truth: GroundTruth from generate_from_binary().
            karadul_naming_map: {placeholder_or_addr: recovered_name}.

        Returns:
            BenchmarkMetrics with accuracy scores.
        """
        calc = AccuracyCalculator()
        comparisons = []

        gt_map = ground_truth.as_address_map()

        for addr, original_name in gt_map.items():
            # Try direct address match
            recovered = karadul_naming_map.get(addr)

            # Try Ghidra FUN_xxx format (strip 0x, zero-pad to 8+)
            if recovered is None:
                hex_part = addr.replace("0x", "").lstrip("0") or "0"
                ghidra_key = f"FUN_{hex_part.zfill(8)}"
                recovered = karadul_naming_map.get(ghidra_key)

            # Try uppercase variant
            if recovered is None:
                ghidra_key_upper = f"FUN_{hex_part.upper().zfill(8)}"
                recovered = karadul_naming_map.get(ghidra_key_upper)

            # If still not found, treat as unnamed
            if recovered is None:
                recovered = f"FUN_{hex_part.zfill(8)}"

            result = calc.compare_name(original_name, recovered)
            comparisons.append(result)

        return calc.calculate_metrics(comparisons)

    def _run_nm(self, binary_path: Path) -> Optional[str]:
        """Run nm command and return stdout.

        Uses nm -gU (global/external, defined-only) on macOS.
        Falls back to plain nm if -gU fails.
        """
        # macOS nm: -g = external only, -U = defined only (not undefined)
        # --demangle for C++ names (GNU nm flag, also works on macOS)
        cmd = ["nm", "-gU"]
        if self.demangle:
            cmd.append("--demangle")
        cmd.append(str(binary_path))

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except FileNotFoundError:
            logger.error("nm command not found in PATH")
            return None
        except subprocess.TimeoutExpired:
            logger.error("nm timed out on %s", binary_path)
            return None

        if proc.returncode != 0:
            # Fallback: try without --demangle (some nm versions differ)
            logger.debug(
                "nm -gU failed (rc=%d), trying without --demangle",
                proc.returncode,
            )
            fallback_cmd = ["nm", "-gU", str(binary_path)]
            try:
                proc = subprocess.run(
                    fallback_cmd,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
            except (FileNotFoundError, subprocess.TimeoutExpired):
                return None

            if proc.returncode != 0:
                logger.error(
                    "nm failed on %s: %s", binary_path, proc.stderr[:200]
                )
                return None

        return proc.stdout

    def _demangle_cppfilt(self, name: str) -> str:
        """Demangle a single C++ name using c++filt (fallback).

        Not used when nm --demangle works, but available as backup.
        """
        try:
            proc = subprocess.run(
                ["c++filt", name],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return name


# -------------------------------------------------------------------
# Convenience: Library-specific ground truth generators
# -------------------------------------------------------------------


def generate_libcrypto_ground_truth(
    binary_path: Optional[Path] = None,
    output_path: Optional[Path] = None,
) -> GroundTruth:
    """Generate ground truth from OpenSSL libcrypto.

    Default binary path (Homebrew on Apple Silicon):
        /opt/homebrew/Cellar/openssl@3/3.6.1/lib/libcrypto.3.dylib

    Expected ~4000 export functions with prefixes:
        EVP_*, BN_*, RSA_*, EC_*, SHA_*, AES_*, HMAC_*, X509_*,
        PKCS7_*, PEM_*, BIO_*, SSL_*, CRYPTO_*, OSSL_*, DH_*, DSA_*

    Args:
        binary_path: Override default libcrypto path.
        output_path: Save JSON here (optional).

    Returns:
        GroundTruth with libcrypto export symbols.
    """
    if binary_path is None:
        # Try common Homebrew paths
        candidates = [
            Path("/opt/homebrew/Cellar/openssl@3/3.6.1/lib/libcrypto.3.dylib"),
            Path("/opt/homebrew/lib/libcrypto.3.dylib"),
            Path("/usr/local/lib/libcrypto.3.dylib"),
            Path("/usr/lib/libcrypto.dylib"),
        ]
        binary_path = _find_first_existing(candidates)
        if binary_path is None:
            raise FileNotFoundError(
                "libcrypto not found. Install OpenSSL: brew install openssl@3"
            )

    gen = GroundTruthGenerator(demangle=True, include_data=False)
    gt = gen.generate_from_binary(binary_path, output_path)

    # Add library-specific metadata
    gt.metadata["library"] = "OpenSSL libcrypto"
    gt.metadata["expected_prefixes"] = [
        "EVP_", "BN_", "RSA_", "EC_", "SHA_", "AES_",
        "HMAC_", "X509_", "PKCS7_", "PEM_", "BIO_",
        "CRYPTO_", "OSSL_", "DH_", "DSA_", "ERR_",
    ]

    # Validate: should have many known-prefix symbols
    known_prefix_count = sum(
        1 for s in gt.symbols
        if any(s.name.startswith(p) for p in gt.metadata["expected_prefixes"])
    )
    gt.metadata["known_prefix_count"] = known_prefix_count
    gt.metadata["known_prefix_ratio"] = (
        round(known_prefix_count / gt.symbol_count, 3)
        if gt.symbol_count > 0
        else 0.0
    )

    logger.info(
        "libcrypto ground truth: %d symbols, %d with known prefixes (%.1f%%)",
        gt.symbol_count,
        known_prefix_count,
        gt.metadata["known_prefix_ratio"] * 100,
    )

    return gt


def generate_libsqlite_ground_truth(
    binary_path: Optional[Path] = None,
    output_path: Optional[Path] = None,
) -> GroundTruth:
    """Generate ground truth from SQLite libsqlite3.

    Default binary path (Homebrew on Apple Silicon):
        /opt/homebrew/Cellar/sqlite/3.52.0/lib/libsqlite3.3.52.0.dylib

    Expected ~600 export API functions, almost all with sqlite3_* prefix.

    WARNING: SQLite is an amalgamation build. Most internal helper functions
    are static and will NOT appear in nm output. Only the public sqlite3_*
    API is exported. This means ground truth coverage is limited to the
    public API surface (~600 functions out of ~2000+ total).

    Args:
        binary_path: Override default libsqlite3 path.
        output_path: Save JSON here (optional).

    Returns:
        GroundTruth with libsqlite3 export symbols.
    """
    if binary_path is None:
        candidates = [
            Path("/opt/homebrew/Cellar/sqlite/3.52.0/lib/libsqlite3.3.52.0.dylib"),
            Path("/opt/homebrew/lib/libsqlite3.dylib"),
            Path("/usr/local/lib/libsqlite3.dylib"),
            Path("/usr/lib/libsqlite3.dylib"),
        ]
        binary_path = _find_first_existing(candidates)
        if binary_path is None:
            raise FileNotFoundError(
                "libsqlite3 not found. Install SQLite: brew install sqlite"
            )

    gen = GroundTruthGenerator(demangle=True, include_data=False)
    gt = gen.generate_from_binary(binary_path, output_path)

    gt.metadata["library"] = "SQLite"
    gt.metadata["expected_prefix"] = "sqlite3_"
    gt.metadata["amalgamation_warning"] = (
        "SQLite is an amalgamation build. Static/internal functions "
        "are not exported and thus not included in ground truth."
    )

    sqlite3_count = sum(
        1 for s in gt.symbols if s.name.startswith("sqlite3_")
    )
    gt.metadata["sqlite3_prefix_count"] = sqlite3_count
    gt.metadata["sqlite3_prefix_ratio"] = (
        round(sqlite3_count / gt.symbol_count, 3)
        if gt.symbol_count > 0
        else 0.0
    )

    logger.info(
        "libsqlite3 ground truth: %d symbols, %d sqlite3_* (%.1f%%)",
        gt.symbol_count,
        sqlite3_count,
        gt.metadata["sqlite3_prefix_ratio"] * 100,
    )

    return gt


def _find_first_existing(paths: list[Path]) -> Optional[Path]:
    """Return the first path that exists on disk, or None."""
    for p in paths:
        if p.exists():
            return p
    return None
