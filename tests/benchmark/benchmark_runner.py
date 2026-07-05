"""Benchmark runner for Karadul reverse engineering accuracy.

Usage:
    # With mock data (for testing):
    runner = BenchmarkRunner()
    result = runner.run_mock(SAMPLE_GROUND_TRUTH, naming_map)

    # With real binaries (needs nm/objdump):
    runner = BenchmarkRunner(output_dir=Path("benchmark_results"))
    result = runner.run_from_naming_map(
        ground_truth_json=Path("ground_truth.json"),
        naming_map_json=Path("workspace/reconstruction/named_c/naming_map.json"),
    )

    # With debug+strip binary pair:
    result = runner.run_from_binaries(
        debug_binary=Path("myapp_debug"),
        naming_map_json=Path("workspace/reconstruction/named_c/naming_map.json"),
    )

Output JSON format:
    {
        "timestamp": "2026-03-22T14:30:00",
        "config": { ... },
        "metrics": {
            "total_symbols": 150,
            "accuracy": 42.5,
            "recovery_rate": 78.0,
            ...
        },
        "per_symbol": [
            {
                "original": "send_packet",
                "recovered": "transmit_data",
                "score": 0.8,
                "match_type": "semantic"
            },
            ...
        ]
    }
"""

from __future__ import annotations

import json
import logging
import subprocess
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from tests.benchmark.metrics import AccuracyCalculator, BenchmarkMetrics, NamingResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# v1.11.0 Bug 2 fix: Symbol mapping helper
# Naming map anahtarları genelde sembol adı ("_print_info") olurken ground
# truth anahtarları Ghidra tarzı ("FUN_1000004ac") olabilir. Workspace içindeki
# ghidra_functions.json ve symbols.json dosyalarından adres↔sembol eşlemesi
# çıkarıp iki namespace arası normalizasyon yaparız.
# ---------------------------------------------------------------------------


def _addr_to_fun_key(addr: str) -> str:
    """Ham adres stringini FUN_<hex> formatına çevir.

    Örn: "100000460" -> "FUN_00000000100000460" değil, "FUN_100000460"
    Ground truth üreticisi `hex_part.lstrip("0").zfill(8)` kullanıyor; aynı
    kuralı buraya uyguluyoruz ki iki taraf tutarlı olsun.
    """
    addr = (addr or "").strip()
    if not addr:
        return ""
    # 0x önekini at, başındaki sıfırları kırp, min 8 hex'e pad et.
    clean = addr.lower().replace("0x", "").lstrip("0") or "0"
    return f"FUN_{clean.zfill(8)}"


def find_symbol_mapping(workspace_dir: Optional[Path]) -> dict[str, str]:
    """Workspace içinden FUN_<addr> ↔ symbol_name eşlemesi çıkar.

    Kaynaklar (öncelik sırası):
      1. `<ws>/static/ghidra_functions.json` — Ghidra'nın fonksiyon listesi
      2. `<ws>/static/symbols.json` — nm tabanlı sembol listesi

    Returns:
        {"FUN_100000460": "_add", "_add": "FUN_100000460", ...} — çift yönlü
        bir sözlük. Hem adres hem isim anahtar olabilir (normalizasyon kolay
        olsun diye). İsim çakışmasında Ghidra kayıtları kazanır.
    """
    mapping: dict[str, str] = {}
    if not workspace_dir or not workspace_dir.exists():
        return mapping

    # 1) ghidra_functions.json
    gf_path = workspace_dir / "static" / "ghidra_functions.json"
    if gf_path.is_file():
        try:
            data = json.loads(gf_path.read_text(encoding="utf-8"))
            for fn in data.get("functions", []):
                name = fn.get("name") or ""
                addr = fn.get("address") or ""
                if not name or not addr:
                    continue
                fun_key = _addr_to_fun_key(addr)
                if fun_key:
                    mapping[fun_key] = name
                    mapping[name] = fun_key
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("ghidra_functions.json okunamadı: %s", exc)

    # 2) symbols.json — yalnızca ghidra'da olmayanları ekle
    sym_path = workspace_dir / "static" / "symbols.json"
    if sym_path.is_file():
        try:
            data = json.loads(sym_path.read_text(encoding="utf-8"))
            for s in data.get("symbols", []):
                name = s.get("name") or ""
                addr = s.get("address") or ""
                if not name or not addr:
                    continue
                fun_key = _addr_to_fun_key(addr)
                if not fun_key:
                    continue
                mapping.setdefault(fun_key, name)
                mapping.setdefault(name, fun_key)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("symbols.json okunamadı: %s", exc)

    return mapping


# ---------------------------------------------------------------------------
# Sample ground truth for quick testing without real binaries
# ---------------------------------------------------------------------------

SAMPLE_GROUND_TRUTH: dict[str, str] = {
    # address/placeholder -> original name
    "FUN_00401000": "main",
    "FUN_00401100": "parse_config",
    "FUN_00401200": "send_packet",
    "FUN_00401300": "recv_response",
    "FUN_00401400": "init_crypto",
    "FUN_00401500": "encrypt_buffer",
    "FUN_00401600": "decrypt_message",
    "FUN_00401700": "handle_connection",
    "FUN_00401800": "validate_input",
    "FUN_00401900": "cleanup_resources",
    "FUN_00401a00": "alloc_context",
    "FUN_00401b00": "free_context",
    "FUN_00401c00": "log_error",
    "FUN_00401d00": "hash_password",
    "FUN_00401e00": "verify_signature",
    "FUN_00401f00": "connect_server",
    "FUN_00402000": "close_socket",
    "FUN_00402100": "serialize_data",
    "FUN_00402200": "deserialize_data",
    "FUN_00402300": "sort_entries",
    "FUN_00402400": "search_table",
    "FUN_00402500": "copy_buffer",
    "FUN_00402600": "compare_keys",
    "FUN_00402700": "generate_nonce",
    "FUN_00402800": "setup_tls",
    # Variables
    "DAT_00603000": "g_config",
    "DAT_00603100": "g_connection_pool",
    "DAT_00603200": "g_debug_level",
}

# A "decent" naming map — simulates realistic Karadul output
# (some exact, some semantic, some partial, some wrong, some missing)
SAMPLE_NAMING_MAP: dict[str, str] = {
    "FUN_00401000": "main",                 # exact
    "FUN_00401100": "read_config",          # semantic (parse ~ read)
    "FUN_00401200": "transmit_packet",      # semantic (send ~ transmit)
    "FUN_00401300": "receive_data",         # semantic (recv ~ receive, response ~ data: partial overlap)
    "FUN_00401400": "initialize_crypto",    # semantic (init ~ initialize)
    "FUN_00401500": "encrypt_data",         # partial (encrypt matches, buffer vs data)
    "FUN_00401600": "decrypt_msg",          # semantic (message ~ msg)
    "FUN_00401700": "process_connection",   # semantic (handle ~ process)
    "FUN_00401800": "check_input",          # semantic (validate ~ check)
    "FUN_00401900": "teardown_resources",   # semantic (cleanup ~ teardown)
    "FUN_00401a00": "create_context",       # semantic (alloc ~ create)
    "FUN_00401b00": "release_context",      # semantic (free ~ release)
    "FUN_00401c00": "print_error",          # semantic (log ~ print)
    "FUN_00401d00": "digest_password",      # semantic (hash ~ digest)
    "FUN_00401e00": "auth_signature",       # partial (verify_signature has signature, auth is related)
    "FUN_00401f00": "open_connection",      # partial (connect ~ open, server vs connection)
    "FUN_00402000": "shutdown_socket",      # partial (close ~ shutdown, socket matches)
    "FUN_00402100": "encode_data",          # semantic (serialize ~ encode)
    "FUN_00402200": "decode_data",          # semantic (deserialize ~ decode)
    "FUN_00402300": "order_entries",        # semantic (sort ~ order)
    "FUN_00402400": "find_in_table",        # semantic (search ~ find, table matches)
    "FUN_00402500": "duplicate_buffer",     # semantic (copy ~ duplicate)
    "FUN_00402600": "wrong_function_name",  # wrong - completely unrelated
    # FUN_00402700 missing - not renamed
    # FUN_00402800 missing - not renamed
    "DAT_00603000": "g_settings",           # partial (config ~ settings)
    "DAT_00603100": "g_conn_pool",          # semantic abbreviation
    # DAT_00603200 missing
}


@dataclass
class BenchmarkResult:
    """Full result of a benchmark run."""

    metrics: BenchmarkMetrics
    per_symbol: list[NamingResult]
    timestamp: str = ""
    config_info: dict = field(default_factory=dict)
    ground_truth_source: str = ""  # "mock", "nm", "json"

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp or datetime.now().isoformat(timespec="seconds"),
            "config": self.config_info,
            "ground_truth_source": self.ground_truth_source,
            # v1.15.5: GT kaynak dağılımı top-level olarak da görünür.
            "ground_truth_breakdown": dict(self.metrics.ground_truth_breakdown),
            "metrics": self.metrics.to_dict(),
            "per_symbol": [
                {
                    "original": r.original,
                    "recovered": r.recovered,
                    "score": r.score,
                    "match_type": r.match_type,
                }
                for r in self.per_symbol
            ],
        }

    def save_json(self, path: Path) -> Path:
        """Save result to JSON file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info("Benchmark result saved to %s", path)
        return path


class BenchmarkRunner:
    """Runs accuracy benchmarks comparing Karadul output vs ground truth.

    Supports three modes:
    1. Mock data — for unit testing (no binaries needed)
    2. JSON-based — ground truth JSON + naming_map JSON
    3. Binary-based — debug binary (nm symbols) + naming_map JSON
    """

    def __init__(self, output_dir: Optional[Path] = None) -> None:
        self.calculator = AccuracyCalculator()
        self.output_dir = output_dir

    @staticmethod
    def _load_naming_map(path: Path) -> dict:
        """Load naming_map.json. v1.5.5 formatını olduğu gibi döndürür;
        düzleştirme `_flatten_naming_map` içinde yapılır.
        """
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    @staticmethod
    def _flatten_naming_map(naming_map: dict) -> dict[str, str]:
        """v1.5.5 formatındaki naming_map'i `{isim: yeni_isim}` sözlüğüne indirger.

        Yapı örnekleri:
          - `{"FUN_1": "main"}` → düz, olduğu gibi döner.
          - `{"global": {...}, "per_function": {fn: {var: renamed}}}` → tüm
            haritalar tek seviyede birleşir. Global kazanır (çakışmada).
        """
        if not isinstance(naming_map, dict):
            return {}
        # BUG #9: output_formatter'ın ürettiği "mappings" şeması:
        #   {"mappings": {orig: {"new_name": <ad>, "source": ..., ...}}, ...}
        # Bu şemada "global"/"per_function" yok; eski kod naive flat branch'e
        # düşüp yalnızca skalar top-level string'leri alıyor, her sembol
        # "missing" skorluyordu. Gerçek şemaya göre {orig: new_name} indir.
        mappings = naming_map.get("mappings")
        if isinstance(mappings, dict):
            flat_m: dict[str, str] = {}
            for k, v in mappings.items():
                if isinstance(v, dict):
                    nn = v.get("new_name")
                    if isinstance(nn, str):
                        flat_m[k] = nn
                elif isinstance(v, str):
                    flat_m[k] = v
            return flat_m
        if "global" not in naming_map and "per_function" not in naming_map:
            # Düz harita: değerlerin string olduğunu varsay.
            return {k: v for k, v in naming_map.items() if isinstance(v, str)}

        flat: dict[str, str] = {}
        pf = naming_map.get("per_function") or {}
        if isinstance(pf, dict):
            for _fn, inner in pf.items():
                if isinstance(inner, dict):
                    for k, v in inner.items():
                        if isinstance(v, str):
                            flat[k] = v
        # Global son yazılır ki çakışmada global kazansın.
        gl = naming_map.get("global") or {}
        if isinstance(gl, dict):
            for k, v in gl.items():
                if isinstance(v, str):
                    flat[k] = v
        return flat

    # ------------------------------------------------------------------
    # Mode 1: Mock data
    # ------------------------------------------------------------------

    def run_mock(
        self,
        ground_truth: dict[str, str],
        naming_map: dict,
        config_info: Optional[dict] = None,
        workspace_dir: Optional[Path] = None,
    ) -> BenchmarkResult:
        """Run benchmark with in-memory dictionaries.

        Args:
            ground_truth: placeholder -> original_name mapping.
            naming_map: Karadul naming map — düz `{placeholder: name}` veya
                v1.5.5 formatı (`{"global": {...}, "per_function": {...}}`)
                olabilir.
            config_info: Optional metadata about the run.
            workspace_dir: Varsa `<ws>/static/` dizinindeki ghidra_functions +
                symbols dosyalarından adres↔sembol cross-ref için kullanılır.
        """
        sym_map = find_symbol_mapping(workspace_dir) if workspace_dir else {}
        unresolved = self.collect_unresolved_funs(workspace_dir)
        comparisons = self._compare_maps(
            ground_truth, naming_map, sym_map, unresolved_funs=unresolved
        )
        metrics = self.calculator.calculate_metrics(comparisons)

        # Bug 3: FUN_ residue oranı raporla.
        flat_nm = self._flatten_naming_map(naming_map)
        metrics.fun_residue_pct = self.calculator.calculate_fun_residue(flat_nm)

        # v1.15.5: GT kaynak dağılımı.
        metrics.ground_truth_breakdown = self._build_gt_breakdown(
            ground_truth, unresolved
        )

        result = BenchmarkResult(
            metrics=metrics,
            per_symbol=comparisons,
            timestamp=datetime.now().isoformat(timespec="seconds"),
            config_info=config_info or {},
            ground_truth_source="mock",
        )

        if self.output_dir:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            result.save_json(self.output_dir / f"benchmark_mock_{ts}.json")

        return result

    # ------------------------------------------------------------------
    # Mode 2: JSON files
    # ------------------------------------------------------------------

    def run_from_naming_map(
        self,
        ground_truth_json: Path,
        naming_map_json: Path,
        config_info: Optional[dict] = None,
        workspace_dir: Optional[Path] = None,
    ) -> BenchmarkResult:
        """Run benchmark from JSON files.

        Args:
            ground_truth_json: JSON file with {placeholder: original_name}.
            naming_map_json: Karadul's naming_map.json output.
            config_info: Optional metadata.

        Ground truth JSON format:
            {
                "FUN_00401000": "main",
                "FUN_00401100": "parse_config",
                ...
            }
        """
        with open(ground_truth_json, encoding="utf-8") as f:
            ground_truth = json.load(f)

        naming_map = self._load_naming_map(naming_map_json)
        sym_map = find_symbol_mapping(workspace_dir) if workspace_dir else {}
        unresolved = self.collect_unresolved_funs(workspace_dir)

        comparisons = self._compare_maps(
            ground_truth, naming_map, sym_map, unresolved_funs=unresolved
        )
        metrics = self.calculator.calculate_metrics(comparisons)
        metrics.fun_residue_pct = self.calculator.calculate_fun_residue(
            self._flatten_naming_map(naming_map)
        )
        metrics.ground_truth_breakdown = self._build_gt_breakdown(
            ground_truth, unresolved
        )

        result = BenchmarkResult(
            metrics=metrics,
            per_symbol=comparisons,
            timestamp=datetime.now().isoformat(timespec="seconds"),
            config_info=config_info or {
                "ground_truth_file": str(ground_truth_json),
                "naming_map_file": str(naming_map_json),
            },
            ground_truth_source="json",
        )

        if self.output_dir:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            result.save_json(self.output_dir / f"benchmark_json_{ts}.json")

        return result

    # ------------------------------------------------------------------
    # Mode 3: Debug binary (nm) + naming map
    # ------------------------------------------------------------------

    def run_from_binaries(
        self,
        debug_binary: Path,
        naming_map_json: Path,
        config_info: Optional[dict] = None,
        workspace_dir: Optional[Path] = None,
    ) -> BenchmarkResult:
        """Run benchmark by extracting ground truth from a debug binary with nm.

        Args:
            debug_binary: Binary compiled with debug symbols (not stripped).
            naming_map_json: Karadul's naming_map.json output.
            config_info: Optional metadata.
            workspace_dir: Varsa Ghidra'nın FUN_xxx bıraktığı fonksiyonları
                (asıl challenge) GT'ye katmak için kullanılır.

        The binary must have been compiled with -g (debug symbols).
        We use `nm` to extract symbol names and map them to Ghidra-style
        addresses (FUN_XXXXXXXX format).
        """
        ground_truth = self._extract_symbols_nm(debug_binary)
        if not ground_truth:
            raise RuntimeError(
                f"No symbols extracted from {debug_binary}. "
                "Ensure it was compiled with debug symbols (-g)."
            )

        naming_map = self._load_naming_map(naming_map_json)
        unresolved = self.collect_unresolved_funs(workspace_dir)

        comparisons = self._compare_maps(
            ground_truth, naming_map, unresolved_funs=unresolved
        )
        metrics = self.calculator.calculate_metrics(comparisons)
        metrics.fun_residue_pct = self.calculator.calculate_fun_residue(
            self._flatten_naming_map(naming_map)
        )
        metrics.ground_truth_breakdown = self._build_gt_breakdown(
            ground_truth, unresolved
        )

        result = BenchmarkResult(
            metrics=metrics,
            per_symbol=comparisons,
            timestamp=datetime.now().isoformat(timespec="seconds"),
            config_info=config_info or {
                "debug_binary": str(debug_binary),
                "naming_map_file": str(naming_map_json),
                "extracted_symbols": len(ground_truth),
            },
            ground_truth_source="nm",
        )

        if self.output_dir:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            binary_name = debug_binary.stem
            result.save_json(
                self.output_dir / f"benchmark_{binary_name}_{ts}.json"
            )

        return result

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _build_gt_breakdown(
        ground_truth: dict[str, str],
        unresolved_funs: Optional[set[str]],
    ) -> dict[str, int]:
        """v1.15.5: GT kaynak dağılımını hesapla.

        from_nm     = GT anahtar sayısı (nm export'ları).
        from_fun_xxx = GT'de OLMAYAN unresolved FUN_xxx sayısı (çift sayma yok).
        total       = from_nm + from_fun_xxx.
        """
        from_nm = len(ground_truth)
        gt_keys = set(ground_truth.keys())
        from_fun_xxx = 0
        if unresolved_funs:
            from_fun_xxx = sum(1 for f in unresolved_funs if f not in gt_keys)
        return {
            "from_nm": from_nm,
            "from_fun_xxx": from_fun_xxx,
            "total": from_nm + from_fun_xxx,
        }

    def _compare_maps(
        self,
        ground_truth: dict[str, str],
        naming_map: dict,
        symbol_mapping: Optional[dict[str, str]] = None,
        unresolved_funs: Optional[set[str]] = None,
    ) -> list[NamingResult]:
        """Compare ground truth against naming map, symbol by symbol.

        v1.11.0 Bug 2 fix: Naming map hem düz, hem v1.5.5 scoped format
        (`global` + `per_function`) olabilir. Ground truth genelde `FUN_<hex>`
        anahtarlı, naming_map ise fonksiyon adı (ör: `_print_info`) anahtarlı
        olabilir. `symbol_mapping` (ghidra_functions.json üzerinden üretilen
        `FUN_<hex>` ↔ `<name>` haritası) ile bu iki namespace arası arama
        yaparız.

        Arama sırası:
          1. Düz naming_map'e `placeholder` ile bak.
          2. `symbol_mapping[placeholder]` varsa (ör. `FUN_xxx` → `_print_info`)
             yeni isimle düz haritada tekrar dene.
          3. Ground truth değeri (sembol adı) naming_map anahtarı olabilir mi
             diye kontrol et.
          4. Hiçbiri yoksa → missing.

        v1.15.5 SAHTE F1 FIX: `unresolved_funs` — Ghidra'nın FUN_xxx olarak
        bıraktığı (isimlendiremediği) fonksiyonlar. Asıl challenge bunlar.
        nm GT döngüsünden sonra her FUN_xxx için:
          - GT'de zaten varsa ATLA (çift sayma yok).
          - Aksi halde flat_nm'den karadul'un verdiği ismi al:
              * isim yok veya hâlâ placeholder → "missing" (rename başarısız)
              * anlamlı isim → "partial" (score 0.5; GT bilinmiyor, exact
                diyemeyiz ama karadul bir şey üretti).
        """
        comparisons: list[NamingResult] = []
        flat_nm = self._flatten_naming_map(naming_map)
        sym_map = symbol_mapping or {}

        for placeholder, original_name in ground_truth.items():
            recovered: Optional[str] = None

            # 1) Direkt anahtar — gerçek challenge: Ghidra FUN_xxx bıraktı,
            #    karadul bu placeholder'ı rename etti. Bunu skorlarız.
            if placeholder in flat_nm:
                recovered = flat_nm[placeholder]

            # 2) v1.11.0 Dalga 5 preserved-detection — BUG #5 FİX: step 2/3'ün
            #    ÜSTÜNE taşındı. sym_map[placeholder] gerçek (FUN_ ile başlamayan)
            #    bir isimse, Ghidra bu sembolü ZATEN biliyordu (stripped olmadı,
            #    binary'den doğrudan okundu) → CHALLENGE DEĞİL. Eskiden bu kontrol
            #    step 4'teydi; step 2/3 önce sym_map/orijinal-isim üzerinden çözüp
            #    "exact/semantic" puanladığı için preserved-exclusion boşa çıkıyor,
            #    non-challenge sembollerle F1 şişiyordu. Artık burada, skorlamadan
            #    önce yakalanır. (Step 1 doğrudan FUN_ anahtarı gerçek bir
            #    rename'dir — ona dokunmuyoruz.)
            if recovered is None and placeholder in sym_map:
                preserved = sym_map[placeholder]
                # sym_map FUN_xxx -> name ve name -> FUN_xxx her iki yönü tutuyor;
                # biz burada FUN_xxx yönünü kullanıyoruz.
                if preserved and not preserved.startswith("FUN_"):
                    comparisons.append(NamingResult(
                        original=original_name,
                        recovered=preserved,
                        score=0.0,  # F1 hesabında TP sayılmayacağı için 0
                        match_type="preserved",
                        source="",
                    ))
                    continue

            # 3) Sembol-eşlemesi: FUN_xxx -> <symbol_name> -> flat_nm
            #    (preserved DEĞİL — Ghidra placeholder bıraktı ama karadul sembol
            #    adı anahtarı altında rename etmiş olabilir).
            if recovered is None and placeholder in sym_map:
                alt_key = sym_map[placeholder]
                if alt_key in flat_nm:
                    recovered = flat_nm[alt_key]

            # 4) Orijinal isim naming_map anahtarı olmuş olabilir
            #    (karadul bazı fonksiyonlar için orijinal adı koruyor)
            if recovered is None and original_name in flat_nm:
                recovered = flat_nm[original_name]

            # 5) Yine de bulamadık → placeholder kalmış kabul et
            if recovered is None:
                recovered = placeholder

            result = self.calculator.compare_name(original_name, recovered)
            comparisons.append(result)

        # v1.15.5: Ghidra'nın FUN_xxx bıraktığı asıl challenge fonksiyonları.
        if unresolved_funs:
            gt_keys = set(ground_truth.keys())
            for fun in sorted(unresolved_funs):
                # GT'de zaten ölçüldüyse çift sayma.
                if fun in gt_keys:
                    continue
                recovered = flat_nm.get(fun)
                if recovered is None or self.calculator._is_unnamed(recovered):
                    # Karadul hiç isim üretemedi (rename yok ya da yine
                    # placeholder) → gerçek, doğrulanabilir bir başarısızlık:
                    # missing (FN). Ne üretildiğini biliyoruz, "yok".
                    comparisons.append(NamingResult(
                        original=fun,
                        recovered=recovered if recovered is not None else fun,
                        score=0.0,
                        match_type="missing",
                        source="",
                    ))
                else:
                    # BUG #4 FİX: Karadul anlamlı bir isim verdi AMA bu
                    # fonksiyonun ground truth'u YOK (nm export'u değil, Ghidra
                    # da isimlendiremedi). İsmin doğru mu yanlış mı olduğunu
                    # DOĞRULAYAMAYIZ → TP de FP de diyemeyiz. Eskiden partial=0.5
                    # (TP) veriliyordu; bu, çekirdek challenge setinde precision'ın
                    # ASLA cezalanamamasına ve F1'in yapay şişmesine yol açıyordu
                    # (isimlendirilen her unresolved FUN_xxx otomatik TP). Artık
                    # "unverified": precision/recall/accuracy'den TAMAMEN hariç,
                    # ayrı raporlanır (per_symbol + confusion_matrix'te görünür).
                    comparisons.append(NamingResult(
                        original=fun,
                        recovered=recovered,
                        score=0.0,
                        match_type="unverified",
                        source="",
                    ))

        return comparisons

    @staticmethod
    def collect_unresolved_funs(workspace_dir: Optional[Path]) -> set[str]:
        """v1.15.5: Workspace'den Ghidra'nın FUN_xxx bıraktığı isimleri topla.

        `<ws>/static/ghidra_functions.json` içindeki `functions[].name`
        alanlarından SADECE `FUN_` ile başlayanları (yani Ghidra'nın
        isimlendiremediği asıl challenge fonksiyonlarını) döndürür.

        Args:
            workspace_dir: Karadul workspace kökü. None ise boş set.

        Returns:
            `{"FUN_100000460", "FUN_100000600", ...}` — ham FUN_xxx isim seti.
            Dosya yoksa / okunamazsa boş set.
        """
        if not workspace_dir:
            return set()
        gf_path = Path(workspace_dir) / "static" / "ghidra_functions.json"
        if not gf_path.is_file():
            return set()
        try:
            data = json.loads(gf_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("ghidra_functions.json okunamadı: %s", exc)
            return set()
        funs: set[str] = set()
        for fn in data.get("functions", []):
            name = fn.get("name") or ""
            if name.startswith("FUN_"):
                funs.add(name)
        return funs

    @staticmethod
    def _extract_symbols_nm(binary_path: Path) -> dict[str, str]:
        """Extract function symbols from a binary using nm.

        Returns dict mapping FUN_XXXXXXXX -> original_name.
        Only includes text (T/t) symbols — actual functions.
        """
        try:
            result = subprocess.run(
                ["nm", "--defined-only", str(binary_path)],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except FileNotFoundError:
            logger.error("nm not found in PATH")
            return {}
        except subprocess.TimeoutExpired:
            logger.error("nm timed out on %s", binary_path)
            return {}

        if result.returncode != 0:
            # Try macOS nm without --defined-only
            try:
                result = subprocess.run(
                    ["nm", str(binary_path)],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
            except (FileNotFoundError, subprocess.TimeoutExpired):
                return {}

        ground_truth: dict[str, str] = {}
        # nm output format: "00000000004011a0 T function_name"
        # BUG #10: Yalnızca text/code sembolleri ([Tt]). Eski [TtDdBb] data (D/d)
        # ve bss (B/b) sembollerini de yakalıyordu; bunlar FUN_<addr> GT anahtarına
        # dönüşüp asla eşleşemiyor, F1'i haksız düşürüyordu. Docstring "text-only"
        # diyor ve GroundTruthGenerator da fonksiyonları symbol_type in (T,t) ile
        # tanımlıyor — buraya da aynı kısıt uygulanır.
        nm_pattern = re.compile(r"^([0-9a-fA-F]+)\s+[Tt]\s+_?(\w+)$", re.MULTILINE)

        for match in nm_pattern.finditer(result.stdout):
            # v1.21 Mach-O fix: macOS `nm` adresleri 16-hane zero-padded döner
            # (örn. arm64 base 0x100000000 → "0000000100000540"). Ghidra ise
            # leading-zero'suz kısa hex kullanır ("100000540"). İki taraf aynı
            # FUN_<hex> anahtarına normalize edilmeli; aksi halde nm GT anahtarı
            # `FUN_0000000100000540`, naming_map ise `FUN_100000540` üretir ve
            # KESİŞİM BOŞ kalır → F1=0 (sahte sıfır-recovery). `_addr_to_fun_key`
            # ve ground_truth_generator zaten `lstrip("0").zfill(8)` kullanıyor;
            # burada da aynı kuralı uyguluyoruz.
            addr = match.group(1).lower().lstrip("0").zfill(8) or "0".zfill(8)
            name = match.group(2)

            # Skip compiler/runtime internals
            if name.startswith(("__", "GCC_", "GLIBC_", "atexit", "frame_dummy",
                                "register_tm", "deregister_tm", "_start")):
                continue

            # Convert address to Ghidra-style FUN_XXXXXXXX
            ghidra_name = f"FUN_{addr}"
            ground_truth[ghidra_name] = name

        logger.info(
            "Extracted %d symbols from %s via nm", len(ground_truth), binary_path
        )
        return ground_truth

    @staticmethod
    def _extract_symbols_objdump(binary_path: Path) -> dict[str, str]:
        """Alternative: extract symbols using objdump (fallback for nm).

        Returns dict mapping FUN_XXXXXXXX -> original_name.
        """
        try:
            result = subprocess.run(
                ["objdump", "-t", str(binary_path)],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return {}

        ground_truth: dict[str, str] = {}
        # objdump -t output: "addr flags section alignment name"
        # Example: "00000000004011a0 g     F .text  00000042 main"
        pattern = re.compile(
            r"^([0-9a-fA-F]+)\s+.*?\.text\s+[0-9a-fA-F]+\s+(\w+)$",
            re.MULTILINE,
        )

        for match in pattern.finditer(result.stdout):
            addr = match.group(1).lower().zfill(8)
            name = match.group(2)

            if name.startswith(("__", "GCC_", "_start", "frame_dummy")):
                continue

            ghidra_name = f"FUN_{addr}"
            ground_truth[ghidra_name] = name

        return ground_truth


def run_sample_benchmark() -> BenchmarkResult:
    """Convenience: run the built-in sample benchmark and return result.

    Useful for quick sanity checks:
        from tests.benchmark.benchmark_runner import run_sample_benchmark
        result = run_sample_benchmark()
        print(result.metrics.summary())
    """
    runner = BenchmarkRunner()
    return runner.run_mock(SAMPLE_GROUND_TRUTH, SAMPLE_NAMING_MAP)
