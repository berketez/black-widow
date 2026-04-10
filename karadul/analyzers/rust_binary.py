"""Rust binary analyzer.

MachOAnalyzer uzerine Rust-spesifik ek analizler ekler:
- Mangled symbol demangling
- Panic handler tespiti
- Crate isimlerini cikartma
- Rust string literal pattern'leri
"""

from __future__ import annotations

import logging
import re
import time
from pathlib import Path
from typing import Any

from karadul.analyzers import register_analyzer
from karadul.analyzers.macho import MachOAnalyzer
from karadul.config import Config
from karadul.core.result import StageResult
from karadul.core.target import TargetInfo, TargetType
from karadul.core.workspace import Workspace

logger = logging.getLogger(__name__)

# Rust mangled symbol pattern'leri
# _ZN: Itanium ABI mangling (eski Rust)
# _RN: Rust v0 mangling (yeni Rust)
_RUST_MANGLED_PATTERN = re.compile(r"^_[ZR]N\d+")

# Crate ismi cikarma pattern'i
# _ZN4core3fmt... -> crate = "core"
# _ZN3std2io... -> crate = "std"
_CRATE_FROM_ITANIUM = re.compile(r"^_ZN(\d+)(\w+)")
_CRATE_FROM_V0 = re.compile(r"^_RN[a-z](\d+)(\w+)")

# Panic handler pattern'leri
_PANIC_PATTERNS = [
    "rust_begin_unwind",
    "rust_panic",
    "core::panicking::panic",
    "core::panicking::panic_fmt",
    "std::panicking::begin_panic",
    "std::panicking::rust_panic_with_hook",
    "core::result::unwrap_failed",
    "core::option::expect_failed",
]


class RustBinaryAnalyzer(MachOAnalyzer):
    """Rust binary'lere ozel ek analizler.

    MachOAnalyzer'in tum islevselligini miras alir ve uzerine
    Rust-spesifik bilgi cikarimi ekler.
    """

    supported_types = [TargetType.MACHO_BINARY]

    def analyze_static(self, target: TargetInfo, workspace: Workspace) -> StageResult:
        """Rust binary statik analizi.

        1. MachOAnalyzer.analyze_static() calistir
        2. Rust-spesifik ek analizler:
           - Mangled symbol demangling
           - Panic handler tespiti
           - Crate isimleri cikarma
           - Rust string literal pattern'leri

        Args:
            target: Hedef bilgileri.
            workspace: Calisma dizini.

        Returns:
            StageResult: Genisletilmis statik analiz sonucu.
        """
        # Once MachO analizi
        result = super().analyze_static(target, workspace)

        # Rust ek analizi
        rust_start = time.monotonic()
        rust_data: dict[str, Any] = {}

        # symbols.json'u oku (MachO analizi tarafindan uretilmis olmali)
        symbols_data = workspace.load_json("static", "symbols")

        if symbols_data and "symbols" in symbols_data:
            raw_symbols = symbols_data["symbols"]

            # Demangling
            demangled = self._demangle_symbols(raw_symbols)
            if demangled:
                demangled_path = workspace.save_json("static", "symbols_demangled", demangled)
                result.artifacts["symbols_demangled"] = demangled_path
                rust_data["demangled_count"] = demangled["demangled_count"]

            # Crate tespiti
            crates = self._extract_crates(raw_symbols)
            if crates:
                crates_path = workspace.save_json("static", "rust_crates", crates)
                result.artifacts["rust_crates"] = crates_path
                rust_data["crate_count"] = len(crates.get("crates", []))

            # Panic handler tespiti
            panics = self._detect_panic_handlers(raw_symbols)
            rust_data["panic_handlers"] = panics

        # String'lerden Rust pattern'leri cikar
        strings_data = workspace.load_json("static", "strings_raw")
        if strings_data and "strings" in strings_data:
            rust_strings = self._find_rust_strings(strings_data["strings"])
            if rust_strings:
                rs_path = workspace.save_json("static", "rust_strings", rust_strings)
                result.artifacts["rust_strings"] = rs_path
                rust_data["rust_string_count"] = len(rust_strings.get("patterns", []))

        # rustfilt varsa kullan
        rustfilt_available = self._check_rustfilt()
        rust_data["rustfilt_available"] = rustfilt_available

        # Stats guncelle
        result.stats["rust_analysis"] = rust_data
        result.stats["rust_analysis_duration"] = round(
            time.monotonic() - rust_start, 3,
        )

        return result

    def _demangle_symbols(self, symbols: list[dict]) -> dict[str, Any]:
        """Rust mangled sembolleri demangle et.

        Oncelikle rustfilt araci kullanilir (mevcutsa).
        Degilse basit heuristic demangling uygulanir.
        """
        demangled_symbols = []
        demangled_count = 0

        for sym in symbols:
            name = sym.get("name", "")
            if not name:
                continue

            if _RUST_MANGLED_PATTERN.match(name):
                demangled_name = self._demangle_rust(name)
                if demangled_name != name:
                    demangled_count += 1
                demangled_symbols.append({
                    "original": name,
                    "demangled": demangled_name,
                    "address": sym.get("address"),
                    "type": sym.get("type"),
                })

        return {
            "total": len(demangled_symbols),
            "demangled_count": demangled_count,
            "symbols": demangled_symbols,
        }

    def _demangle_rust(self, mangled: str) -> str:
        """Rust mangled symbol'u demangle et.

        Basit heuristic: Itanium ABI mangling'den
        namespace::function formatina donusturur.
        Tam demangling icin rustfilt araci gereklidir.

        Args:
            mangled: Mangled symbol adi (orn: "_ZN4core3fmt5write...")

        Returns:
            Demangle edilmis isim veya orjinal (basarisizsa).
        """
        if not mangled:
            return mangled

        # Itanium ABI: _ZN<len1><name1><len2><name2>...E
        if mangled.startswith("_ZN"):
            return self._demangle_itanium(mangled[3:])

        # Rust v0: _RN<...>
        if mangled.startswith("_RN"):
            # v0 mangling daha karmasik, basit cikarma dene
            return self._demangle_itanium(mangled[3:])

        return mangled

    @staticmethod
    def _demangle_itanium(encoded: str) -> str:
        """Itanium ABI name mangling'den parcalari cikar.

        Format: <length><name><length><name>...E[<hash>]
        Ornek: "4core3fmt5write17h..." -> "core::fmt::write"
        """
        parts = []
        pos = 0

        while pos < len(encoded):
            # 'E' mangling sonunu isaret eder
            if encoded[pos] == 'E':
                break

            # Sayi oku (isim uzunlugu)
            num_start = pos
            while pos < len(encoded) and encoded[pos].isdigit():
                pos += 1

            if pos == num_start:
                # Sayi bulunamadi, dur
                break

            length = int(encoded[num_start:pos])

            if pos + length > len(encoded):
                break

            name = encoded[pos:pos + length]
            parts.append(name)
            pos += length

        if parts:
            result = "::".join(parts)
            # Hash suffix'i kaldir (genellikle son parca 17h... seklinde)
            if parts and len(parts[-1]) > 16 and parts[-1].startswith("h"):
                result = "::".join(parts[:-1])
            return result

        return encoded

    def _extract_crates(self, symbols: list[dict]) -> dict[str, Any]:
        """Symbol isimlerinden Rust crate isimlerini cikar."""
        crate_counts: dict[str, int] = {}

        for sym in symbols:
            name = sym.get("name", "")
            if not name:
                continue

            crate_name = None

            # Itanium ABI: _ZN<len><crate_name><len><module>...
            match = _CRATE_FROM_ITANIUM.match(name)
            if match:
                length = int(match.group(1))
                candidate = match.group(2)[:length]
                if len(candidate) == length:
                    crate_name = candidate

            # v0: _RN<tag><len><crate_name>...
            if not crate_name:
                match = _CRATE_FROM_V0.match(name)
                if match:
                    length = int(match.group(1))
                    candidate = match.group(2)[:length]
                    if len(candidate) == length:
                        crate_name = candidate

            if crate_name:
                crate_counts[crate_name] = crate_counts.get(crate_name, 0) + 1

        # Siralanmis crate listesi
        sorted_crates = sorted(crate_counts.items(), key=lambda x: -x[1])
        crates = [{"name": name, "symbol_count": count} for name, count in sorted_crates]

        return {
            "total": len(crates),
            "crates": crates,
        }

    def _detect_panic_handlers(self, symbols: list[dict]) -> list[dict]:
        """Panic handler fonksiyonlarini tespit et."""
        found = []
        for sym in symbols:
            name = sym.get("name", "")
            for pattern in _PANIC_PATTERNS:
                if pattern in name:
                    found.append({
                        "symbol": name,
                        "pattern": pattern,
                        "address": sym.get("address"),
                    })
                    break
        return found

    def _find_rust_strings(self, strings: list[str]) -> dict[str, Any]:
        """String listesinden Rust-spesifik pattern'leri bul.

        Aranacak pattern'ler:
        - Panic mesajlari ("called `Result::unwrap()` on an `Err` value")
        - Cargo.toml referanslari
        - Crate versiyonlari
        - Rust error mesajlari
        """
        patterns = []

        # Rust'a ozel pattern'ler
        rust_indicators = [
            (r"called `(?:Result|Option)::\w+\(\)`", "unwrap_pattern"),
            (r"panicked at", "panic_message"),
            (r"thread '.*' panicked", "thread_panic"),
            (r"Cargo\.toml", "cargo_reference"),
            (r"\bcrate\b", "crate_reference"),
            (r"rustc", "rustc_reference"),
            (r"/\.cargo/registry/", "cargo_registry"),
            (r"core::fmt", "core_fmt"),
            (r"std::\w+::\w+", "std_reference"),
            (r"alloc::", "alloc_reference"),
        ]

        for s in strings:
            if not isinstance(s, str):
                continue
            for regex, category in rust_indicators:
                if re.search(regex, s):
                    patterns.append({
                        "value": s[:500],  # max 500 karakter
                        "category": category,
                    })
                    break

        # Kategori istatistikleri
        cat_stats: dict[str, int] = {}
        for p in patterns:
            cat = p["category"]
            cat_stats[cat] = cat_stats.get(cat, 0) + 1

        return {
            "total": len(patterns),
            "category_stats": cat_stats,
            "patterns": patterns[:1000],  # max 1000 pattern
        }

    def _check_rustfilt(self) -> bool:
        """rustfilt aracinin mevcut olup olmadigini kontrol et."""
        result = self.runner.run_command(
            ["rustfilt", "--version"],
            timeout=5,
        )
        return result.success
