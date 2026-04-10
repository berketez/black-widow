"""Reference Binary Differ -- known software version detection + CFG-based function matching.

Stripped bir binary'nin icerisindeki string'lerden hangi yazilimi/kutuphanenin
hangi surumunu icerdigini tespit eder, onceden hazirlanmis debug binary'nin
Ghidra ciktilariyla CFG-bazli fonksiyon eslestirmesi yaparak TUM fonksiyon
isimlerini transfer eder.

Bu, bilinen yazilimlar icin en yuksek ROI teknigidir: SQLite, OpenSSL, zlib,
curl gibi sik gomulu kutuphanelerin %90+ fonksiyonu 1:1 eslesir.

Eslestirme Stratejisi (sirasiz, yuksek confidence oncelikli):
    1. String fingerprint: Ayni string'lere referans veren fonksiyonlar
    2. CFG feature similarity: block/edge/complexity/call metrikleri
    3. Call graph propagation: Eslesmis komsulardan propagasyon
    4. Size + constant matching: Boyut + sabit deger profili

Kullanim:
    from karadul.reconstruction.reference_differ import ReferenceDiffer, VersionDetector

    # 1. Versiyon tespiti
    detector = VersionDetector()
    detections = detector.detect_from_strings(strings_json)
    # [Detection(library="sqlite3", version="3.46.0", confidence=0.95)]

    # 2. Reference DB'den eslestirme
    differ = ReferenceDiffer(reference_db_path="path/to/ref_db/")
    result = differ.match(
        target_functions=functions_json,
        target_strings=strings_json,
        target_cfg=cfg_json,
        target_call_graph=call_graph_json,
        detection=detections[0],
    )
    # result.naming_map: {"FUN_001234": "sqlite3_exec", ...}

v1.7.3: Ilk implementasyon -- version detection + CFG matching framework.
         Auto-download/compile yok, sadece local reference DB destegi.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Version detection patterns
# ---------------------------------------------------------------------------

# Her pattern: (regex, library_name, version_group_index)
# Regex'te version grubunu yakala, library_name sabit.
# Pattern'ler once specifik (tam match), sonra genel (fallback) sirayla denenir.

_VERSION_PATTERNS: list[tuple[re.Pattern, str, int]] = [
    # --- SQLite ---
    (re.compile(r"SQLite\s+(?:format\s+)?(\d+\.\d+\.\d+)"), "sqlite3", 1),
    (re.compile(r"sqlite[_-]?(\d+\.\d+\.\d+)"), "sqlite3", 1),
    (re.compile(r"(\d+\.\d+\.\d+)\b.*\bSQLite"), "sqlite3", 1),

    # --- OpenSSL / LibreSSL ---
    (re.compile(r"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)"), "openssl", 1),
    (re.compile(r"LibreSSL\s+(\d+\.\d+\.\d+)"), "libressl", 1),
    (re.compile(r"BoringSSL"), "boringssl", 0),  # BoringSSL has no stable versions

    # --- zlib ---
    (re.compile(r"zlib\s+(\d+\.\d+\.\d+(?:\.\d+)?)"), "zlib", 1),
    (re.compile(r"(?:deflate|inflate)\s+(\d+\.\d+\.\d+(?:\.\d+)?)"), "zlib", 1),

    # --- curl / libcurl ---
    (re.compile(r"(?:lib)?curl[/\s]+(\d+\.\d+\.\d+)"), "libcurl", 1),
    (re.compile(r"curl/(\d+\.\d+\.\d+)"), "libcurl", 1),

    # --- Go runtime ---
    (re.compile(r"go(\d+\.\d+(?:\.\d+)?)"), "go_runtime", 1),

    # --- libpng ---
    (re.compile(r"libpng\s+(\d+\.\d+\.\d+)"), "libpng", 1),
    (re.compile(r"PNG\s+(?:image\s+)?library\s+(\d+\.\d+\.\d+)"), "libpng", 1),

    # --- libjpeg ---
    (re.compile(r"(?:lib)?jpeg(?:-turbo)?\s+(\d+[a-z]?\d*)"), "libjpeg", 1),

    # --- mbedTLS ---
    (re.compile(r"(?:mbed\s*TLS|PolarSSL)\s+(\d+\.\d+\.\d+)"), "mbedtls", 1),

    # --- wolfSSL ---
    (re.compile(r"wolfSSL\s+(\d+\.\d+\.\d+)"), "wolfssl", 1),

    # --- expat XML parser ---
    (re.compile(r"expat\s+(?:XML\s+parser\s+)?(\d+\.\d+\.\d+)"), "expat", 1),

    # --- pcre ---
    (re.compile(r"PCRE2?\s+(\d+\.\d+(?:\.\d+)?)"), "pcre", 1),

    # --- lua ---
    (re.compile(r"Lua\s+(\d+\.\d+(?:\.\d+)?)"), "lua", 1),

    # --- freetype ---
    (re.compile(r"FreeType\s+(\d+\.\d+\.\d+)"), "freetype", 1),

    # --- libevent ---
    (re.compile(r"libevent[/-](\d+\.\d+\.\d+)"), "libevent", 1),

    # --- bzip2 ---
    (re.compile(r"bzip2[,/\s]+(?:v|version\s+)?(\d+\.\d+\.\d+)"), "bzip2", 1),

    # --- lz4 ---
    (re.compile(r"LZ4\s+(?:compression\s+)?(?:v)?(\d+\.\d+\.\d+)"), "lz4", 1),

    # --- zstd ---
    (re.compile(r"(?:Zstd|zstd|ZSTD)\s+(?:v)?(\d+\.\d+\.\d+)"), "zstd", 1),
]

# Dogrulama string'leri: bir kutuphane tespit edildiginde, bu string'lerden
# birinin de mevcut olup olmadigina bakilir. Confidence artirir.
_VALIDATION_STRINGS: dict[str, list[str]] = {
    "sqlite3": ["CREATE TABLE", "SELECT", "INSERT INTO", "PRAGMA", "sqlite_master"],
    "openssl": ["SSL_CTX_new", "EVP_", "RSA_", "X509_", "PEM_read"],
    "libressl": ["SSL_CTX_new", "EVP_", "X509_"],
    "zlib": ["inflate", "deflate", "adler32", "crc32", "gzip"],
    "libcurl": ["CURLOPT_", "curl_easy_", "HTTP/", "Transfer-Encoding"],
    "go_runtime": ["runtime.", "goroutine", "GOROOT", "GOOS", "GOARCH"],
    "libpng": ["PNG", "IHDR", "IDAT", "IEND", "png_"],
    "mbedtls": ["mbedtls_", "ssl_handshake", "x509_crt"],
    "wolfssl": ["wolfSSL_", "WOLFSSL_"],
    "lua": ["Lua", "lua_", "luaL_", "dofile"],
    "pcre": ["pcre2_", "pcre_compile", "pcre_exec"],
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class Detection:
    """Tespit edilen kutuphane/yazilim bilgisi."""
    library: str         # "sqlite3", "openssl", "zlib", ...
    version: str         # "3.46.0", "3.1.2", ...
    confidence: float    # 0.0 - 1.0
    evidence: list[str] = field(default_factory=list)  # Eslesen string'ler


@dataclass
class FunctionMatch:
    """Tek bir fonksiyon eslesmesi (reference -> target)."""
    ref_name: str         # Debug binary'deki fonksiyon adi
    ref_address: str      # Debug binary'deki adres
    target_name: str      # Stripped binary'deki adi (FUN_xxx)
    target_address: str   # Stripped binary'deki adres
    confidence: float     # 0.0 - 1.0
    method: str           # "string_fingerprint", "cfg_similarity", "call_propagation", "size_constant"


@dataclass
class ReferenceMatchResult:
    """Reference binary eslestirme sonucu."""
    detection: Detection
    total_ref_functions: int = 0
    total_target_functions: int = 0
    matched: int = 0
    matches: list[FunctionMatch] = field(default_factory=list)
    match_rate: float = 0.0
    naming_map: dict[str, str] = field(default_factory=dict)  # target_name -> ref_name

    def summary(self) -> dict:
        return {
            "library": self.detection.library,
            "version": self.detection.version,
            "total_ref": self.total_ref_functions,
            "total_target": self.total_target_functions,
            "matched": self.matched,
            "match_rate": round(self.match_rate, 4),
            "by_method": dict(Counter(m.method for m in self.matches)),
        }


@dataclass
class ReferenceDBEntry:
    """Reference DB'deki tek bir kutuphane kaydi.

    Her kutuphane icin Ghidra ciktilari:
    - functions.json
    - strings.json
    - cfg.json (opsiyonel)
    - call_graph.json (opsiyonel)
    """
    library: str
    version: str
    db_path: Path
    functions_json: Path
    strings_json: Optional[Path] = None
    cfg_json: Optional[Path] = None
    call_graph_json: Optional[Path] = None
    metadata: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# CFG Feature Extraction (lightweight, pairwise matching icin)
# ---------------------------------------------------------------------------

# Normalizasyon sabitleri
_NORM_SCALES = {
    "block_count": 100.0,
    "edge_count": 200.0,
    "cyclomatic_complexity": 50.0,
    "instruction_count": 500.0,
    "call_count": 20.0,
    "string_ref_count": 10.0,
}


def _extract_cfg_features(func_cfg: dict[str, Any]) -> list[float]:
    """Fonksiyondan 12-boyutlu lightweight CFG feature vector cikar.

    cfg_fingerprint.py'nin 24-dim vectorunden farkli: pairwise matching icin
    optimize edilmis, daha az ama daha ayirt edici feature'lar.

    Features:
        0: block_count (log-normalized)
        1: edge_count (log-normalized)
        2: cyclomatic_complexity (log-normalized)
        3: loop_count (normalized)
        4: avg_block_size (normalized)
        5: max_block_size (normalized)
        6: call_count (normalized)
        7: conditional_edge_ratio
        8: back_edge_ratio
        9: linear_chain_ratio
        10: diamond_ratio (join points)
        11: string_ref_count (normalized)
    """
    blocks = func_cfg.get("blocks", [])
    edges = func_cfg.get("edges", [])
    loop_headers = func_cfg.get("loop_headers", [])
    back_edges = func_cfg.get("back_edges", [])

    n_blocks = len(blocks)
    n_edges = len(edges)
    n_loops = len(loop_headers)
    n_back_edges = len(back_edges)
    complexity = func_cfg.get("cyclomatic_complexity", 0)

    # Block metrikleri
    block_sizes = []
    for b in blocks:
        ic = b.get("instruction_count", 0)
        if ic <= 0:
            ic = max(b.get("size", 0) // 4, 1)
        block_sizes.append(ic)
    avg_block_size = (sum(block_sizes) / n_blocks) if n_blocks > 0 else 0.0
    max_block_size = max(block_sizes, default=0)

    # Edge metrikleri
    out_degree: dict[str, int] = {}
    in_degree: dict[str, int] = {}
    conditional_count = 0

    for b in blocks:
        addr = b.get("start_address", "")
        out_degree[addr] = 0
        in_degree[addr] = 0

    for e in edges:
        src = e.get("from_block", "")
        dst = e.get("to_block", "")
        if src in out_degree:
            out_degree[src] += 1
        if dst in in_degree:
            in_degree[dst] += 1
        if e.get("edge_type") == "conditional_jump":
            conditional_count += 1

    # Diamond (join) count
    diamond_count = sum(
        1 for addr in out_degree
        if in_degree.get(addr, 0) >= 2 and out_degree.get(addr, 0) >= 1
    )

    # Linear chain ratio
    linear_count = sum(
        1 for addr in out_degree
        if in_degree.get(addr, 0) == 1 and out_degree.get(addr, 0) == 1
    )
    linear_chain_ratio = (linear_count / n_blocks) if n_blocks > 0 else 0.0

    # Call count
    call_count = sum(
        1 for b in blocks
        if b.get("has_call") or b.get("call_count", 0) > 0
    )

    # String reference count
    str_ref_count = func_cfg.get("string_ref_count", 0)

    def _norm_log(val: float, scale: float) -> float:
        if val <= 0:
            return 0.0
        return min(math.log1p(val) / math.log1p(scale), 1.0)

    def _norm(val: float, scale: float) -> float:
        if val <= 0:
            return 0.0
        return min(val / scale, 1.0)

    def _ratio(num: float, den: float) -> float:
        if den <= 0:
            return 0.0
        return min(num / den, 1.0)

    fv = [
        _norm_log(n_blocks, _NORM_SCALES["block_count"]),         # 0
        _norm_log(n_edges, _NORM_SCALES["edge_count"]),           # 1
        _norm_log(complexity, _NORM_SCALES["cyclomatic_complexity"]),  # 2
        _norm(n_loops, 10.0),                                      # 3
        _norm(avg_block_size, 30.0),                               # 4
        _norm(max_block_size, 100.0),                              # 5
        _norm(call_count, _NORM_SCALES["call_count"]),             # 6
        _ratio(conditional_count, n_edges),                        # 7
        _ratio(n_back_edges, n_edges),                             # 8
        linear_chain_ratio,                                        # 9
        _ratio(diamond_count, n_blocks),                           # 10
        _norm(str_ref_count, _NORM_SCALES["string_ref_count"]),    # 11
    ]

    return [round(v, 4) for v in fv]


def _cosine_similarity(v1: list[float], v2: list[float]) -> float:
    """Cosine similarity [0,1]. Zero vector = 0.0."""
    if not v1 or not v2:
        return 0.0
    # Pad shorter vector
    max_len = max(len(v1), len(v2))
    if len(v1) < max_len:
        v1 = v1 + [0.0] * (max_len - len(v1))
    if len(v2) < max_len:
        v2 = v2 + [0.0] * (max_len - len(v2))

    dot = sum(a * b for a, b in zip(v1, v2))
    mag1 = math.sqrt(sum(a * a for a in v1))
    mag2 = math.sqrt(sum(b * b for b in v2))

    if mag1 < 1e-10 or mag2 < 1e-10:
        return 0.0
    return dot / (mag1 * mag2)


def _extract_constants(func_data: dict) -> set[int]:
    """Fonksiyondaki sabit degerleri cikar (decompiled code veya instruction'lardan)."""
    constants: set[int] = set()

    # Decompiled code'dan sabit cikar
    code = func_data.get("code") or func_data.get("body") or ""
    if code:
        # Hex sabitleri
        for m in re.finditer(r"\b0x([0-9a-fA-F]+)\b", code):
            try:
                val = int(m.group(1), 16)
                # Cok kucuk (0-15) ve cok buyuk (adres gibi) sabitleri atla
                if 16 <= val <= 0xFFFFFFFF:
                    constants.add(val)
            except ValueError:
                pass
        # Decimal sabitleri
        for m in re.finditer(r"\b(\d{2,10})\b", code):
            try:
                val = int(m.group(1))
                if 16 <= val <= 0xFFFFFFFF:
                    constants.add(val)
            except ValueError:
                pass

    return constants


# ---------------------------------------------------------------------------
# VersionDetector
# ---------------------------------------------------------------------------


class VersionDetector:
    """Binary string'lerinden yazilim/kutuphane versiyon tespiti.

    Ghidra strings.json ciktisini veya duz string listesini girdi alir,
    bilinen kutuphane pattern'leriyle eslestirir.
    """

    def detect_from_strings(
        self,
        strings_data: dict[str, Any] | list[str],
        min_confidence: float = 0.5,
    ) -> list[Detection]:
        """String verisinden kutuphane tespiti yap.

        Args:
            strings_data: Ghidra strings.json dict'i ({"strings": [...]}) veya
                         duz string listesi (["str1", "str2", ...]).
            min_confidence: Minimum tespit guvenligi.

        Returns:
            list[Detection]: Tespit edilen kutuphaneler, confidence'a gore sirali.
        """
        # String listesini normalize et
        if isinstance(strings_data, dict):
            raw_strings = [
                s.get("value", "") for s in strings_data.get("strings", [])
            ]
        elif isinstance(strings_data, list):
            raw_strings = strings_data
        else:
            return []

        if not raw_strings:
            return []

        # Tum string'leri tek bir blob'a birlestir (hizli arama icin)
        string_set = set(raw_strings)
        all_text = "\n".join(raw_strings)

        detections: list[Detection] = []
        seen_libraries: set[str] = set()

        for pattern, library, version_group in _VERSION_PATTERNS:
            if library in seen_libraries:
                continue

            match = pattern.search(all_text)
            if not match:
                continue

            version = match.group(version_group) if version_group > 0 else "unknown"
            evidence = [match.group(0)]

            # Confidence: baz 0.70, validation string'leri bulunursa artirilir
            confidence = 0.70

            # Validation string'leri kontrol et
            validators = _VALIDATION_STRINGS.get(library, [])
            found_validators = 0
            for v in validators:
                if any(v in s for s in string_set):
                    found_validators += 1
                    evidence.append(f"validator: {v}")

            if validators:
                # En az 1 validator: +0.10, 2+: +0.20, 3+: +0.25
                if found_validators >= 3:
                    confidence += 0.25
                elif found_validators >= 2:
                    confidence += 0.20
                elif found_validators >= 1:
                    confidence += 0.10

            # Versiyon numarasi varsa +0.05 (kesinlestiriyor)
            if version != "unknown":
                confidence += 0.05

            confidence = min(confidence, 0.99)

            if confidence >= min_confidence:
                detections.append(Detection(
                    library=library,
                    version=version,
                    confidence=confidence,
                    evidence=evidence,
                ))
                seen_libraries.add(library)

        # Confidence'a gore sirala
        detections.sort(key=lambda d: d.confidence, reverse=True)

        if detections:
            logger.info(
                "VersionDetector: %d kutuphane tespit edildi: %s",
                len(detections),
                [(d.library, d.version, d.confidence) for d in detections],
            )

        return detections


# ---------------------------------------------------------------------------
# ReferenceDB -- local reference binary database
# ---------------------------------------------------------------------------


class ReferenceDB:
    """Local reference binary veritabani.

    Dizin yapisi:
        ref_db/
            index.json           -- tum entry'lerin metadata'si
            sqlite3/
                3.46.0/
                    ghidra_functions.json
                    ghidra_strings.json
                    ghidra_cfg.json       (opsiyonel)
                    ghidra_call_graph.json (opsiyonel)
                    metadata.json         (compile flags, arch, vb.)
            openssl/
                3.1.2/
                    ...
    """

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._index: dict[str, dict[str, ReferenceDBEntry]] = {}
        self._load_index()

    def _load_index(self) -> None:
        """Veritabani indeksini yukle."""
        index_path = self._db_path / "index.json"
        if index_path.exists():
            try:
                data = json.loads(index_path.read_text(encoding="utf-8"))
                for entry in data.get("entries", []):
                    lib = entry.get("library", "")
                    ver = entry.get("version", "")
                    if lib and ver:
                        lib_dir = self._db_path / lib / ver
                        if lib_dir.exists():
                            self._index.setdefault(lib, {})[ver] = ReferenceDBEntry(
                                library=lib,
                                version=ver,
                                db_path=lib_dir,
                                functions_json=lib_dir / "ghidra_functions.json",
                                strings_json=lib_dir / "ghidra_strings.json" if (lib_dir / "ghidra_strings.json").exists() else None,
                                cfg_json=lib_dir / "ghidra_cfg.json" if (lib_dir / "ghidra_cfg.json").exists() else None,
                                call_graph_json=lib_dir / "ghidra_call_graph.json" if (lib_dir / "ghidra_call_graph.json").exists() else None,
                                metadata=entry.get("metadata", {}),
                            )
                logger.info("ReferenceDB: %d kutuphane, %d versiyon yuklendi",
                           len(self._index), sum(len(v) for v in self._index.values()))
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("ReferenceDB index okunamiyor: %s -- %s", index_path, exc)
        else:
            # Index dosyasi yoksa dizin yapisi taranir
            self._scan_directory()

    def _scan_directory(self) -> None:
        """Dizin yapisini tarayarak indeks olustur."""
        if not self._db_path.exists():
            return

        for lib_dir in sorted(self._db_path.iterdir()):
            if not lib_dir.is_dir() or lib_dir.name.startswith("."):
                continue
            lib_name = lib_dir.name

            for ver_dir in sorted(lib_dir.iterdir()):
                if not ver_dir.is_dir() or ver_dir.name.startswith("."):
                    continue
                version = ver_dir.name

                functions_json = ver_dir / "ghidra_functions.json"
                if not functions_json.exists():
                    continue

                self._index.setdefault(lib_name, {})[version] = ReferenceDBEntry(
                    library=lib_name,
                    version=version,
                    db_path=ver_dir,
                    functions_json=functions_json,
                    strings_json=ver_dir / "ghidra_strings.json" if (ver_dir / "ghidra_strings.json").exists() else None,
                    cfg_json=ver_dir / "ghidra_cfg.json" if (ver_dir / "ghidra_cfg.json").exists() else None,
                    call_graph_json=ver_dir / "ghidra_call_graph.json" if (ver_dir / "ghidra_call_graph.json").exists() else None,
                )

        if self._index:
            logger.info("ReferenceDB scan: %d kutuphane bulundu", len(self._index))

    def lookup(self, library: str, version: str) -> Optional[ReferenceDBEntry]:
        """Verilen kutuphane + versiyon icin referans entry dondur.

        Exact version eslesmesi arar. Bulamazsa None.
        """
        versions = self._index.get(library, {})
        return versions.get(version)

    def lookup_closest(self, library: str, version: str) -> Optional[ReferenceDBEntry]:
        """Exact match yoksa en yakin versiyonu dondur.

        Versiyon karsilastirmasi basit string prefix match: "3.46" -> "3.46.0" eslesiyor.
        Birden fazla match varsa en uzun (en specifik) olanini al.
        """
        exact = self.lookup(library, version)
        if exact:
            return exact

        versions = self._index.get(library, {})
        if not versions:
            return None

        # Prefix match dene
        candidates = []
        for v, entry in versions.items():
            if v.startswith(version) or version.startswith(v):
                candidates.append((v, entry))

        if not candidates:
            return None

        # En uzun version string = en specifik
        candidates.sort(key=lambda x: len(x[0]), reverse=True)
        logger.info("ReferenceDB: %s %s bulunamadi, en yakin: %s", library, version, candidates[0][0])
        return candidates[0][1]

    @property
    def libraries(self) -> list[str]:
        """Mevcut kutuphane listesi."""
        return list(self._index.keys())

    def all_entries(self) -> list[ReferenceDBEntry]:
        """Tum reference DB entry'lerini duz liste olarak dondur.

        BinDiff otomatik entegrasyonunda ref_db'deki tum kutuphanelerin
        Ghidra ciktilarina erismek icin kullanilir.
        """
        result: list[ReferenceDBEntry] = []
        for versions in self._index.values():
            for entry in versions.values():
                result.append(entry)
        return result

    def save_index(self) -> None:
        """Mevcut indeksi index.json'a kaydet."""
        entries = []
        for lib, versions in self._index.items():
            for ver, entry in versions.items():
                entries.append({
                    "library": lib,
                    "version": ver,
                    "metadata": entry.metadata,
                })
        data = {"version": 1, "entries": entries}
        index_path = self._db_path / "index.json"
        index_path.parent.mkdir(parents=True, exist_ok=True)
        index_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# ReferenceDiffer -- ana eslestirme sinifi
# ---------------------------------------------------------------------------


class ReferenceDiffer:
    """Reference binary ile stripped binary arasinda fonksiyon eslestirmesi.

    4 strateji sirayla uygulanir (greedy matching):
    1. String fingerprint (confidence: 0.92)
    2. CFG feature similarity (confidence: 0.88)
    3. Call graph propagation (confidence: 0.85)
    4. Size + constant matching (confidence: 0.80)

    Args:
        reference_db_path: ReferenceDB dizin yolu. None ise sadece
            dogrudan reference data ile calisir (match_direct).
        min_similarity: Minimum CFG cosine similarity (default 0.85).
        min_confidence: Minimum transfer confidence (default 0.80).
        auto_populate: True ise reference DB'de bulunamayan kutuphaneler
            icin otomatik kaynak indirme/derleme/analiz tetiklenir.
    """

    def __init__(
        self,
        reference_db_path: Optional[Path] = None,
        min_similarity: float = 0.85,
        min_confidence: float = 0.80,
        auto_populate: bool = False,
    ) -> None:
        self._db: Optional[ReferenceDB] = None
        if reference_db_path and Path(reference_db_path).exists():
            self._db = ReferenceDB(Path(reference_db_path))
        self._min_similarity = min_similarity
        self._min_confidence = min_confidence
        self._auto_populate = auto_populate
        self._populator = None  # lazy init

    def match(
        self,
        target_functions: dict,
        target_strings: Optional[dict] = None,
        target_cfg: Optional[dict] = None,
        target_call_graph: Optional[dict] = None,
        detection: Optional[Detection] = None,
    ) -> Optional[ReferenceMatchResult]:
        """Tespit edilen kutuphane icin reference DB'den eslestirme yap.

        Args:
            target_functions: Stripped binary'nin Ghidra functions.json.
            target_strings: Stripped binary'nin Ghidra strings.json.
            target_cfg: Stripped binary'nin Ghidra CFG JSON.
            target_call_graph: Stripped binary'nin Ghidra call_graph.json.
            detection: VersionDetector sonucu.

        Returns:
            ReferenceMatchResult veya None (reference DB'de bulunamazsa).
        """
        if not detection:
            return None

        if not self._db and not self._auto_populate:
            return None

        entry = None
        if self._db:
            entry = self._db.lookup_closest(detection.library, detection.version)

        # Auto-populate: reference DB'de yoksa otomatik olustur
        if not entry and self._auto_populate:
            entry = self._try_auto_populate(detection)

        if not entry:
            logger.info("Reference DB'de %s %s bulunamadi", detection.library, detection.version)
            return None

        # Reference verilerini yukle
        try:
            ref_funcs_data = json.loads(
                entry.functions_json.read_text(encoding="utf-8", errors="replace")
            )
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("Reference functions.json okunamiyor: %s", exc)
            return None

        ref_strings = None
        if entry.strings_json and entry.strings_json.exists():
            try:
                ref_strings = json.loads(
                    entry.strings_json.read_text(encoding="utf-8", errors="replace")
                )
            except (json.JSONDecodeError, OSError):
                pass

        ref_cfg = None
        if entry.cfg_json and entry.cfg_json.exists():
            try:
                ref_cfg = json.loads(
                    entry.cfg_json.read_text(encoding="utf-8", errors="replace")
                )
            except (json.JSONDecodeError, OSError):
                pass

        ref_call_graph = None
        if entry.call_graph_json and entry.call_graph_json.exists():
            try:
                ref_call_graph = json.loads(
                    entry.call_graph_json.read_text(encoding="utf-8", errors="replace")
                )
            except (json.JSONDecodeError, OSError):
                pass

        return self.match_direct(
            ref_functions=ref_funcs_data,
            ref_strings=ref_strings,
            ref_cfg=ref_cfg,
            ref_call_graph=ref_call_graph,
            target_functions=target_functions,
            target_strings=target_strings,
            target_cfg=target_cfg,
            target_call_graph=target_call_graph,
            detection=detection,
        )

    def match_direct(
        self,
        ref_functions: dict,
        target_functions: dict,
        ref_strings: Optional[dict] = None,
        target_strings: Optional[dict] = None,
        ref_cfg: Optional[dict] = None,
        target_cfg: Optional[dict] = None,
        ref_call_graph: Optional[dict] = None,
        target_call_graph: Optional[dict] = None,
        detection: Optional[Detection] = None,
    ) -> ReferenceMatchResult:
        """Dogrudan reference ve target verisi ile eslestirme.

        ReferenceDB olmadan, dogrudan Ghidra JSON verileriyle calisir.
        Test ve entegrasyon icin kullanisli.
        """
        if detection is None:
            detection = Detection(library="unknown", version="unknown", confidence=0.5)

        ref_funcs = ref_functions.get("functions", [])
        target_funcs = target_functions.get("functions", [])

        result = ReferenceMatchResult(
            detection=detection,
            total_ref_functions=len(ref_funcs),
            total_target_functions=len(target_funcs),
        )

        if not ref_funcs or not target_funcs:
            return result

        # Adres bazli indeks
        ref_by_addr = {f["address"]: f for f in ref_funcs}
        target_by_addr = {f["address"]: f for f in target_funcs}
        unmatched_ref = set(ref_by_addr.keys())
        unmatched_target = set(target_by_addr.keys())

        # --- Strateji 1: String fingerprint ---
        if ref_strings and target_strings:
            matches = self._strategy_string_fingerprint(
                ref_funcs, target_funcs, ref_strings, target_strings,
                unmatched_ref, unmatched_target,
            )
            for m in matches:
                if m.confidence >= self._min_confidence:
                    result.matches.append(m)
                    unmatched_ref.discard(m.ref_address)
                    unmatched_target.discard(m.target_address)

        # --- Strateji 2: CFG feature similarity ---
        if ref_cfg and target_cfg:
            remaining_ref = [ref_by_addr[a] for a in unmatched_ref if a in ref_by_addr]
            remaining_target = [target_by_addr[a] for a in unmatched_target if a in target_by_addr]

            matches = self._strategy_cfg_similarity(
                remaining_ref, remaining_target, ref_cfg, target_cfg,
            )
            for m in matches:
                if m.confidence >= self._min_confidence:
                    result.matches.append(m)
                    unmatched_ref.discard(m.ref_address)
                    unmatched_target.discard(m.target_address)

        # --- Strateji 3: Call graph propagation ---
        if ref_call_graph and target_call_graph and result.matches:
            remaining_ref = [ref_by_addr[a] for a in unmatched_ref if a in ref_by_addr]
            remaining_target = [target_by_addr[a] for a in unmatched_target if a in target_by_addr]

            matches = self._strategy_call_propagation(
                remaining_ref, remaining_target,
                ref_call_graph, target_call_graph,
                result.matches,
            )
            for m in matches:
                if m.confidence >= self._min_confidence:
                    result.matches.append(m)
                    unmatched_ref.discard(m.ref_address)
                    unmatched_target.discard(m.target_address)

        # --- Strateji 4: Size + constant matching ---
        remaining_ref = [ref_by_addr[a] for a in unmatched_ref if a in ref_by_addr]
        remaining_target = [target_by_addr[a] for a in unmatched_target if a in target_by_addr]

        matches = self._strategy_size_constant(remaining_ref, remaining_target)
        for m in matches:
            if m.confidence >= self._min_confidence:
                result.matches.append(m)
                unmatched_ref.discard(m.ref_address)
                unmatched_target.discard(m.target_address)

        # Sonuclari hesapla
        result.matched = len(result.matches)
        denominator = min(result.total_ref_functions, result.total_target_functions)
        if denominator > 0:
            result.match_rate = result.matched / denominator

        # Naming map olustur
        result.naming_map = self._build_naming_map(result.matches)

        logger.info(
            "ReferenceDiffer: %s %s -- %d/%d eslesti (%.1f%%), methods: %s",
            detection.library, detection.version,
            result.matched, denominator,
            result.match_rate * 100,
            dict(Counter(m.method for m in result.matches)),
        )

        return result

    # ------------------------------------------------------------------
    # Auto-populate entegrasyon
    # ------------------------------------------------------------------

    def _try_auto_populate(self, detection: Detection) -> Optional[ReferenceDBEntry]:
        """Reference DB'de bulunmayan kutuphane icin auto-populate dene.

        ReferencePopulator lazy-init edilir, sadece gerektiginde import edilir.
        Basarisiz olursa None dondurur, hata loglanir.
        """
        try:
            if self._populator is None:
                from karadul.reconstruction.reference_populator import ReferencePopulator
                self._populator = ReferencePopulator(skip_ghidra=False)

            if not self._populator.is_library_supported(detection.library):
                logger.debug(
                    "Auto-populate: %s desteklenmiyor", detection.library
                )
                return None

            logger.info(
                "Auto-populate baslatiliyor: %s %s",
                detection.library, detection.version,
            )
            result = self._populator.populate(detection)

            if result.success and result.entry:
                logger.info(
                    "Auto-populate basarili: %s %s (steps: %s)",
                    detection.library, detection.version,
                    result.steps_completed,
                )
                return result.entry
            else:
                logger.warning(
                    "Auto-populate basarisiz: %s %s -- %s",
                    detection.library, detection.version,
                    result.error,
                )
                return None

        except Exception as exc:
            logger.error("Auto-populate hatasi: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Strateji 1: String Fingerprint
    # ------------------------------------------------------------------

    def _strategy_string_fingerprint(
        self,
        ref_funcs: list[dict],
        target_funcs: list[dict],
        ref_strings: dict,
        target_strings: dict,
        unmatched_ref: set[str],
        unmatched_target: set[str],
    ) -> list[FunctionMatch]:
        """Fonksiyonlarin referans ettigi string kumelerini karsilastir.

        Ayni 2+ string'e referans veren fonksiyonlar yuksek ihtimalle ayni.
        Jaccard similarity ile eslestirme yapilir.

        Confidence: jaccard * 0.92
        """
        matches: list[FunctionMatch] = []

        ref_str_map = self._build_func_string_map(ref_strings, unmatched_ref)
        target_str_map = self._build_func_string_map(target_strings, unmatched_target)

        if not ref_str_map or not target_str_map:
            return matches

        ref_func_by_addr = {f["address"]: f for f in ref_funcs if f["address"] in unmatched_ref}
        target_func_by_addr = {f["address"]: f for f in target_funcs if f["address"] in unmatched_target}

        # Greedy matching: yuksek jaccard'dan dusuge
        candidates: list[tuple[float, str, str]] = []
        for r_addr, r_strings in ref_str_map.items():
            if len(r_strings) < 2:
                continue
            best_score = 0.0
            best_target = ""
            for t_addr, t_strings in target_str_map.items():
                if len(t_strings) < 2:
                    continue
                jaccard = self._jaccard(r_strings, t_strings)
                if jaccard > best_score:
                    best_score = jaccard
                    best_target = t_addr

            if best_score >= 0.5 and best_target:
                candidates.append((best_score, r_addr, best_target))

        candidates.sort(key=lambda x: -x[0])
        used_targets: set[str] = set()

        for score, r_addr, t_addr in candidates:
            if t_addr in used_targets:
                continue
            if r_addr not in ref_func_by_addr or t_addr not in target_func_by_addr:
                continue

            r_func = ref_func_by_addr[r_addr]
            t_func = target_func_by_addr[t_addr]

            matches.append(FunctionMatch(
                ref_name=r_func.get("name", ""),
                ref_address=r_addr,
                target_name=t_func.get("name", ""),
                target_address=t_addr,
                confidence=round(min(score * 0.92, 0.95), 4),
                method="string_fingerprint",
            ))
            used_targets.add(t_addr)

        return matches

    # ------------------------------------------------------------------
    # Strateji 2: CFG Feature Similarity
    # ------------------------------------------------------------------

    def _strategy_cfg_similarity(
        self,
        ref_funcs: list[dict],
        target_funcs: list[dict],
        ref_cfg: dict,
        target_cfg: dict,
    ) -> list[FunctionMatch]:
        """CFG feature vectorleri ile pairwise cosine similarity eslestirme.

        Her fonksiyonun 12-dim feature vector'unu cikarip, en yuksek similarity
        ciftlerini greedy eslestirir.

        Confidence: similarity * 0.88 (CFG yapisal benzerlik kuvvetli sinyaldir)
        """
        matches: list[FunctionMatch] = []

        # CFG fonksiyon lookup: address -> cfg_data
        ref_cfg_by_addr = {
            f.get("address", ""): f
            for f in ref_cfg.get("functions", [])
        }
        target_cfg_by_addr = {
            f.get("address", ""): f
            for f in target_cfg.get("functions", [])
        }

        # Feature vector'leri cikar
        ref_features: list[tuple[dict, list[float]]] = []
        for f in ref_funcs:
            cfg_data = ref_cfg_by_addr.get(f["address"])
            if cfg_data and len(cfg_data.get("blocks", [])) >= 3:
                fv = _extract_cfg_features(cfg_data)
                ref_features.append((f, fv))

        target_features: list[tuple[dict, list[float]]] = []
        for f in target_funcs:
            cfg_data = target_cfg_by_addr.get(f["address"])
            if cfg_data and len(cfg_data.get("blocks", [])) >= 3:
                fv = _extract_cfg_features(cfg_data)
                target_features.append((f, fv))

        if not ref_features or not target_features:
            return matches

        # Pairwise similarity + greedy matching
        candidates: list[tuple[float, dict, dict]] = []
        for r_func, r_fv in ref_features:
            best_sim = 0.0
            best_target: Optional[dict] = None
            for t_func, t_fv in target_features:
                sim = _cosine_similarity(r_fv, t_fv)
                if sim > best_sim:
                    best_sim = sim
                    best_target = t_func

            if best_sim >= self._min_similarity and best_target is not None:
                candidates.append((best_sim, r_func, best_target))

        # Greedy: yuksek similarity oncelikli
        candidates.sort(key=lambda x: -x[0])
        used_targets: set[str] = set()

        for sim, r_func, t_func in candidates:
            t_addr = t_func["address"]
            if t_addr in used_targets:
                continue

            # Size cross-check: boyut farki %30'dan fazlaysa skip
            r_size = r_func.get("size", 0)
            t_size = t_func.get("size", 0)
            if r_size > 0 and t_size > 0:
                size_ratio = min(r_size, t_size) / max(r_size, t_size)
                if size_ratio < 0.70:
                    continue

            matches.append(FunctionMatch(
                ref_name=r_func.get("name", ""),
                ref_address=r_func["address"],
                target_name=t_func.get("name", ""),
                target_address=t_addr,
                confidence=round(min(sim * 0.88, 0.95), 4),
                method="cfg_similarity",
            ))
            used_targets.add(t_addr)

        return matches

    # ------------------------------------------------------------------
    # Strateji 3: Call Graph Propagation
    # ------------------------------------------------------------------

    def _strategy_call_propagation(
        self,
        ref_funcs: list[dict],
        target_funcs: list[dict],
        ref_call_graph: dict,
        target_call_graph: dict,
        existing_matches: list[FunctionMatch],
    ) -> list[FunctionMatch]:
        """Onceki eslesmelerden call graph uzerinde propagasyon.

        Eslesmis fonksiyonlarin caller/callee komsularina bakarak
        henuz eslesmemis fonksiyonlari eslestir.

        Ornek: f(A) -> g(B) eslesmis. A, C'yi cagiriyor. B, FUN_xxx'i
        cagiriyor. Eger C ve FUN_xxx boyut/parametre olarak benzer ise
        eslestir.

        Confidence: 0.85
        """
        matches: list[FunctionMatch] = []

        # Call graph'lari pars et
        ref_callers: dict[str, set[str]] = {}   # addr -> {caller_addrs}
        ref_callees: dict[str, set[str]] = {}   # addr -> {callee_addrs}
        target_callers: dict[str, set[str]] = {}
        target_callees: dict[str, set[str]] = {}

        for edge in ref_call_graph.get("edges", []):
            src = edge.get("source") or edge.get("from", "")
            dst = edge.get("target") or edge.get("to", "")
            if src and dst:
                ref_callees.setdefault(src, set()).add(dst)
                ref_callers.setdefault(dst, set()).add(src)

        for edge in target_call_graph.get("edges", []):
            src = edge.get("source") or edge.get("from", "")
            dst = edge.get("target") or edge.get("to", "")
            if src and dst:
                target_callees.setdefault(src, set()).add(dst)
                target_callers.setdefault(dst, set()).add(src)

        # Mevcut eslesmelerden adres mapping'i cikart
        ref_to_target: dict[str, str] = {}  # ref_addr -> target_addr
        for m in existing_matches:
            ref_to_target[m.ref_address] = m.target_address

        # Lookup indeksler
        ref_by_addr = {f["address"]: f for f in ref_funcs}
        target_by_addr = {f["address"]: f for f in target_funcs}
        used_targets: set[str] = set()

        # Propagation: her eslesmis fonksiyon cifti icin
        # eslesmemis callee/caller'lari esle
        for r_addr, t_addr in ref_to_target.items():
            # Callee propagation
            r_callees = ref_callees.get(r_addr, set())
            t_callees = target_callees.get(t_addr, set())

            # Eslesmemis callee'ler
            unmatched_r = [c for c in r_callees if c not in ref_to_target and c in ref_by_addr]
            unmatched_t = [c for c in t_callees if c not in {m.target_address for m in existing_matches} and c in target_by_addr]

            if len(unmatched_r) == 1 and len(unmatched_t) == 1:
                # 1:1 callee match
                r_func = ref_by_addr[unmatched_r[0]]
                t_func = target_by_addr[unmatched_t[0]]

                # Size check
                r_size = r_func.get("size", 0)
                t_size = t_func.get("size", 0)
                if r_size > 0 and t_size > 0:
                    size_ratio = min(r_size, t_size) / max(r_size, t_size)
                    if size_ratio < 0.50:
                        continue

                if t_func["address"] not in used_targets:
                    matches.append(FunctionMatch(
                        ref_name=r_func.get("name", ""),
                        ref_address=r_func["address"],
                        target_name=t_func.get("name", ""),
                        target_address=t_func["address"],
                        confidence=0.85,
                        method="call_propagation",
                    ))
                    used_targets.add(t_func["address"])

        return matches

    # ------------------------------------------------------------------
    # Strateji 4: Size + Constant Matching
    # ------------------------------------------------------------------

    def _strategy_size_constant(
        self,
        ref_funcs: list[dict],
        target_funcs: list[dict],
    ) -> list[FunctionMatch]:
        """Fonksiyon boyutu + constant profil eslestirmesi.

        Buyuk fonksiyonlarda (>=64 byte) boyut + parametre sayisi + constant
        degerler kombinasyonuyla eslestirme.

        Confidence: 0.80
        """
        matches: list[FunctionMatch] = []

        # Kucuk fonksiyonlari filtrele
        ref_large = [f for f in ref_funcs if f.get("size", 0) >= 64]
        target_large = [f for f in target_funcs if f.get("size", 0) >= 64]

        if not ref_large or not target_large:
            return matches

        # Size + param fingerprint
        def _fingerprint(f: dict) -> str:
            size = f.get("size", 0)
            # Size'i 8-byte alignment ile quantize et (kucuk farklar compiler artifact'i)
            size_q = (size + 7) // 8
            params = f.get("param_count", 0)
            ret = f.get("return_type", "?")
            return f"{size_q}:{params}:{ret}"

        ref_by_fp: dict[str, list[dict]] = {}
        for f in ref_large:
            fp = _fingerprint(f)
            ref_by_fp.setdefault(fp, []).append(f)

        target_by_fp: dict[str, list[dict]] = {}
        for f in target_large:
            fp = _fingerprint(f)
            target_by_fp.setdefault(fp, []).append(f)

        used_targets: set[str] = set()

        for fp, ref_entries in ref_by_fp.items():
            target_entries = target_by_fp.get(fp)
            if not target_entries:
                continue

            # 1:1 eslestirme: sadece tek ref + tek target
            if len(ref_entries) == 1 and len(target_entries) == 1:
                r = ref_entries[0]
                t = target_entries[0]
                if t["address"] in used_targets:
                    continue

                # Constant cross-check (varsa)
                r_constants = _extract_constants(r)
                t_constants = _extract_constants(t)
                confidence = 0.80

                if r_constants and t_constants:
                    common = len(r_constants & t_constants)
                    total = len(r_constants | t_constants)
                    if total > 0 and common / total >= 0.5:
                        confidence = min(confidence + 0.05, 0.88)

                matches.append(FunctionMatch(
                    ref_name=r.get("name", ""),
                    ref_address=r["address"],
                    target_name=t.get("name", ""),
                    target_address=t["address"],
                    confidence=confidence,
                    method="size_constant",
                ))
                used_targets.add(t["address"])

        return matches

    # ------------------------------------------------------------------
    # Yardimci metodlar
    # ------------------------------------------------------------------

    @staticmethod
    def _build_func_string_map(
        strings_data: dict,
        valid_addrs: set[str],
    ) -> dict[str, set[str]]:
        """strings.json'dan func_addr -> {string_values} haritasi."""
        result: dict[str, set[str]] = {}
        for s in strings_data.get("strings", []):
            value = s.get("value", "")
            if not value or len(value) < 3:
                continue

            xrefs = s.get("xrefs", [])
            for xref in xrefs:
                func_addr = xref.get("from_func_addr")
                if func_addr and func_addr in valid_addrs:
                    result.setdefault(func_addr, set()).add(value)

            func_addr = s.get("function_addr")
            if func_addr and func_addr in valid_addrs:
                result.setdefault(func_addr, set()).add(value)

        return result

    @staticmethod
    def _jaccard(set_a: set, set_b: set) -> float:
        """Jaccard similarity [0,1]."""
        if not set_a or not set_b:
            return 0.0
        intersection = len(set_a & set_b)
        union = len(set_a | set_b)
        return intersection / union if union > 0 else 0.0

    @staticmethod
    def _build_naming_map(matches: list[FunctionMatch]) -> dict[str, str]:
        """Matches'ten naming_map olustur: target_name -> ref_name.

        Ayni target_name icin birden fazla match varsa en yuksek
        confidence'li olanini al.
        """
        best: dict[str, tuple[str, float]] = {}
        for m in matches:
            if not m.target_name or not m.ref_name:
                continue
            existing = best.get(m.target_name)
            if existing is None or m.confidence > existing[1]:
                best[m.target_name] = (m.ref_name, m.confidence)
        return {target: ref for target, (ref, _) in best.items()}
