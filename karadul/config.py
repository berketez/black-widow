"""Merkezi konfigürasyon — TÜM path'ler, timeout'lar, sabitler burada."""

from __future__ import annotations

import os
import glob
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml  # type: ignore[import-untyped]

from karadul.computation.config import ComputationConfig


import logging

logger = logging.getLogger(__name__)
def _detect_cpu_cores() -> int:
    """Performans cekirdek sayisini tespit et (E-core haric)."""
    total = os.cpu_count() or 4
    # Apple Silicon: P-core sayisi genellikle toplamin %70-75'i
    # M4 Max: 14 toplam, 10 P-core. M3 Pro: 12 toplam, 6 P-core.
    # Genel heuristik: performance core ~ total * 0.7, min 2
    try:
        # macOS: sysctl ile gercek P-core sayisi
        # B21: safe_run + resolve_tool ile LD_PRELOAD/DYLD koruma.
        from karadul.core.safe_subprocess import resolve_tool, safe_run
        sysctl_path = resolve_tool("sysctl")
        if sysctl_path is not None:
            result = safe_run(
                [sysctl_path, "-n", "hw.perflevel0.logicalcpu"],
                capture_output=True, text=True, timeout=5.0,
            )
            if result.returncode == 0 and result.stdout.strip().isdigit():
                return int(result.stdout.strip())
    except Exception:
        logger.debug("sysctl P-core sayisi okunamadi, fallback kullaniliyor", exc_info=True)
    return max(2, int(total * 0.7))


def _read_cgroup_memory_limit_mb() -> Optional[int]:
    """Container (cgroup) bellek limitini MB olarak oku; yoksa None.

    cgroup v2: ``/sys/fs/cgroup/memory.max``
    cgroup v1: ``/sys/fs/cgroup/memory/memory.limit_in_bytes``

    ``"max"`` veya cok buyuk deger (limitsiz sentinel) -> None dondurur.
    """
    candidates = (
        "/sys/fs/cgroup/memory.max",                    # cgroup v2
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",  # cgroup v1
    )
    for path in candidates:
        try:
            raw = Path(path).read_text().strip()
        except OSError:
            continue
        if raw == "max":
            return None
        try:
            limit_bytes = int(raw)
        except ValueError:
            continue
        # cgroup v1 "limitsiz" cok buyuk bir sentinel deger olarak gelir.
        if limit_bytes <= 0 or limit_bytes >= (1 << 62):
            return None
        return int(limit_bytes / (1024 * 1024))
    return None


def _detect_available_memory_mb() -> int:
    """Kullanilabilir RAM miktarini MB olarak dondur.

    Container icinde cgroup bellek limiti varsa host RAM ile min'i alinir.
    Aksi halde Ghidra heap (RAM*0.4, config.py) cgroup limitini asip
    cgroup OOM-kill'e yol acar (Docker olcum container'i, v1.20.5).
    """
    host_mb: Optional[int] = None
    try:
        total = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
        host_mb = int(total / (1024 * 1024))
    except (ValueError, OSError, AttributeError):
        pass
    if host_mb is None:
        try:
            # B21: safe_run + resolve_tool ile LD_PRELOAD/DYLD koruma.
            from karadul.core.safe_subprocess import resolve_tool, safe_run
            sysctl_path = resolve_tool("sysctl")
            if sysctl_path is not None:
                result = safe_run(
                    [sysctl_path, "-n", "hw.memsize"],
                    capture_output=True, text=True, timeout=5.0,
                )
                if result.returncode == 0:
                    host_mb = int(result.stdout.strip()) // (1024 * 1024)
        except Exception:
            logger.debug("sysctl memsize okunamadi, fallback kullaniliyor", exc_info=True)

    cgroup_mb = _read_cgroup_memory_limit_mb()
    if host_mb is not None and cgroup_mb is not None:
        return min(host_mb, cgroup_mb)
    if cgroup_mb is not None:
        return cgroup_mb
    if host_mb is not None:
        return host_mb
    return 8192  # fallback: 8GB


# Modül seviyesinde bir kez hesapla
CPU_PERF_CORES = _detect_cpu_cores()
TOTAL_MEMORY_MB = _detect_available_memory_mb()
# Ghidra heap: toplam RAM'in %40'i, min 4GB, max 32GB
GHIDRA_HEAP_MB = max(4096, min(32768, int(TOTAL_MEMORY_MB * 0.4)))


def _resolve_path(p: str) -> Path:
    return Path(os.path.expanduser(p)).resolve()


# Berke'nin bilinen Ghidra install dizini (geriye uyum + bilinen-iyi aday)
_GHIDRA_KNOWN_DIR = "~/Desktop/dosyalar/uygulamalar/ghidra/build/dist/ghidra_12.0_DEV"


def _find_ghidra_tool(rel: str, fallback: str) -> Path:
    """Ghidra alt-aracını esnek bul (``rel`` = install-dir'e göreli, ör
    ``support/analyzeHeadless``).

    Öncelik: env (``GHIDRA_INSTALL_DIR``/``GHIDRA_HOME``) -> Berke'nin bilinen
    yolu -> yaygın konum glob'ları -> PATH -> eski hardcoded fallback. Böylece
    .app/launcher ``GHIDRA_INSTALL_DIR`` ile taşınabilir; env yoksa mevcut
    davranış korunur (bilinen yol bulunur). Ghidra yolu ``karadul.yaml``'a
    KONULMAZ (ayar paneli whitelist'i onu silerdi) -> env tek güvenli override.
    """
    bases: list[Path] = []
    for ev in ("GHIDRA_INSTALL_DIR", "GHIDRA_HOME"):
        v = os.environ.get(ev)
        if v:
            bases.append(Path(os.path.expanduser(v)))
    bases.append(_resolve_path(_GHIDRA_KNOWN_DIR))
    for pat in ("~/ghidra*", "~/Ghidra*", "/Applications/ghidra*",
                "/opt/homebrew/Caskroom/ghidra/*/ghidra_*", "/opt/ghidra*",
                "~/Desktop/*/ghidra*"):
        bases += [Path(p) for p in sorted(glob.glob(os.path.expanduser(pat)), reverse=True)]
    for base in bases:
        cand = base / rel
        if cand.exists():
            return cand.resolve()
    which = shutil.which(os.path.basename(rel))
    if which:
        return Path(which)
    return _resolve_path(fallback)


@dataclass
class ToolPaths:
    """Dış araç konumları."""
    ghidra_headless: Path = field(default_factory=lambda: _find_ghidra_tool(
        "support/analyzeHeadless",
        "~/Desktop/dosyalar/uygulamalar/ghidra/build/dist/ghidra_12.0_DEV/support/analyzeHeadless",
    ))
    ghidra_run: Path = field(default_factory=lambda: _find_ghidra_tool(
        "ghidraRun",
        "~/Desktop/dosyalar/uygulamalar/ghidra/build/dist/ghidra_12.0_DEV/ghidraRun",
    ))
    synchrony: Path = field(default_factory=lambda: Path("/opt/homebrew/bin/synchrony"))
    radare2: Path = field(default_factory=lambda: Path("/opt/homebrew/bin/r2"))
    node: Path = field(default_factory=lambda: Path("node"))
    npm: Path = field(default_factory=lambda: Path("npm"))
    otool: Path = field(default_factory=lambda: Path("otool"))
    strings: Path = field(default_factory=lambda: Path("strings"))
    nm: Path = field(default_factory=lambda: Path("nm"))
    lipo: Path = field(default_factory=lambda: Path("lipo"))
    codesign: Path = field(default_factory=lambda: Path("codesign"))
    frida: Path = field(default_factory=lambda: Path("frida"))


@dataclass
class Timeouts:
    """Zaman aşımı süreleri (saniye)."""
    ghidra: int = 7200  # 2 saat — buyuk binary icin
    frida_attach: int = 30
    frida_spawn_wait: float = 2.0
    subprocess: int = 7200  # buyuk binary strings/nm icin
    babel_parse: int = 60
    synchrony: int = 120


@dataclass
class RetryConfig:
    """Hata kurtarma ayarları."""
    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 30.0
    circuit_breaker_threshold: int = 5
    circuit_breaker_reset: float = 60.0


@dataclass
class AnalysisConfig:
    """Analiz parametreleri."""
    max_file_size_mb: int = 500
    string_min_length: int = 4
    ghidra_max_heap_mb: int = field(default_factory=lambda: GHIDRA_HEAP_MB)
    webpack_module_min_size: int = 50
    deobfuscation_chain: list[str] = field(
        default_factory=lambda: ["beautify", "synchrony", "babel_transforms"]
    )
    use_deep_deobfuscation: bool = True
    # NOT (2026-05-13): LLM-Assisted Variable Naming kaldirildi.
    # Berke kalici karari: feedback_no_llm.md — deterministic, CPU-only.


@dataclass
class SourceMatchConfig:
    """Source matching ayarlari -- minified fonksiyonlari orijinal kaynakla eslestirme.

    NpmFingerprinter eslestirmesinden sonra, eslesen paketlerin orijinal
    kaynak kodunu cekip fonksiyon bazli eslestirme yapar.
    """
    enabled: bool = False                  # Source matching default OFF (B12: network kapali)
    min_similarity: float = 0.65           # Minimum fonksiyon benzerlik skoru (0.0-1.0)
    consistency_ratio: float = 0.3         # Toplu tutarlilik esigi
    unpkg_timeout: int = 10                # Tek HTTP istek timeout (saniye)
    unpkg_delay_ms: int = 50               # Istekler arasi bekleme (rate limit)
    max_packages: int = 100                # En fazla kac paket indirilecek
    npm_pack_fallback: bool = True         # unpkg basarisiz olursa npm pack dene
    fingerprint_cache: bool = True         # Fingerprint sonuclarini cache'le


# NOT (2026-05-13): MLConfig kaldirildi (Berke karari feedback_no_llm.md).
# Eski alanlar: enable_llm4decompile, llm4decompile_model_path, ml_device,
# ml_dtype, max_new_tokens, ml_temperature, ml_batch_size, ml_min/max_function_size.


@dataclass
class NetworkConfig:
    """Tum network erisimleri default OFF (deterministic / offline kalmak icin).

    Berke karari (2026-05-13): karadul varsayilan olarak hicbir HTTP/urllib cagrisi
    yapmamali. `--enable-network` veya `--online` CLI flag'i ile veya YAML'da
    `network.enabled: true` ile acilir.

    Alt-konfigler `SourceMatchConfig.enabled` ve reference_populator/dts_namer
    kendi `allow_network` parametrelerini bu master switch'ten alir.
    """
    enabled: bool = False
    allow_dts_fetch: bool = False
    allow_reference_download: bool = False
    allow_source_match: bool = False


@dataclass
class NameMergerConfig:
    """Bayesian isim birlestirme ayarlari.

    Kaynak bazli agirliklar (w_i): korelasyonu absorbe eder.
    w_i = 1.0 -> tamamen bagimsiz kaynak (naive Bayes).
    w_i < 1.0 -> diger kaynaklarla korelasyonlu, bilgi azaltilir.

    Bkz: docs/IMPOSSIBLE-RE-MATH-ANALYSIS.md Bolum 4.4
    """
    source_weights: dict[str, float] = field(default_factory=lambda: {
        "binary_extractor": 1.0,    # Bagimsiz (debug strings, RTTI)
        "c_namer": 1.0,             # Zaten min_confidence ile filtrelenmis, cift zayiflatma gereksiz
        # FIX (2026-07-12): c_namer'in zayif yapisal stratejileri (call_graph/
        # callee_based -> helper_<adr>, dispatcher_<adr> adres-gomulu uydurmalar).
        # weight NORMAL (1.0), ama bu isimlerin confidence'i _add_c_namer'da 0.25'e
        # SABITLENIR (adres-gomulu isim = sahte 0.55-0.65 guveni, gercek bilgi ~0).
        # Tek-kaynak: sigmoid(logit(0.25))=0.25 < UNK(0.30) -> FUN_xxx birakilir.
        # Byte-sig/cfg_iso korrobore olursa posterior yukselir -> isim verilir.
        # (weight dusurmek posterior'i 0.5'e YAKLASTIRIR, UNK'a degil -- bu yuzden
        #  cozum weight degil confidence sabitleme.)
        "c_namer_structural": 1.0,
        "string_intel": 0.8,        # Kismen bagimsiz
        "signature_db": 1.0,        # Tamamen bagimsiz (FLIRT)
        "swift_demangle": 1.0,      # Tamamen bagimsiz
        "pcode_dataflow": 0.9,      # P-Code def-use chain analizi
        "source_matcher": 0.85,     # Bagimsiz kaynak, yuksek kesinlik
        # B11 (2026-05-13): llm4decompile kaldirildi (feedback_no_llm.md)
        "byte_pattern": 1.0,        # Tamamen bagimsiz
        # B8/B7/B18 (2026-05-13): yeni naming kanallari
        "dwarf": 0.95,              # DWARF .debug_info — compiler-emitted ground truth
        "pdb": 0.95,                # PDB symbol recovery (PE-only)
        "bn_symbol": 0.85,          # BinaryNinja symbol extraction
        "trex_struct": 0.75,        # TRex lifted IL struct inference
        "rust_demangler": 0.95,     # Rust ABI deterministic demangle
        "go_demangler": 0.90,       # Go heuristic demangle
        "function_id": 0.95,        # Ghidra FunctionID -- yuksek guvenilirlik (hash-based)
        "bsim": 0.85,              # BSim fonksiyon benzerligi
        "computation_recovery": 0.9, # Computation pipeline (cfg match, constant analysis)
        "signature_fusion": 0.95,    # Dempster-Shafer fusion -- bagimsiz evidence birlesimi
        "reference_differ": 0.95,    # Reference binary match -- FLIRT/FID seviyesinde guvenilir
        "interprocedural_propagation": 0.85,  # Inter-procedural param name propagation -- call-arg graph based
        "cross_binary_transfer": 0.80,         # CFG fingerprint cache -- cross-binary eslestirme
        "callee_profile": 0.75,                # Callee-profile propagation -- domain-based inference
        "capa_capability": 0.85,               # CAPA capability detection -- Mandiant rule-based
        # v1.10.0 C1 fix: Semantic namer kaynaklarini Bayesian weight tablosuna ekle.
        # Bu kaynaklar daha once tanimsizdi -> default_weight=0.7 aliyorlardi (yanlis).
        "sig_db_params": 1.0,            # FLIRT/BSim sig DB payload params -- tam guven
        "signature_based": 0.95,         # API_PARAM_DB statik lookup (libc/POSIX)
        "algorithm_template": 0.85,      # Algoritma template match (crypto/hash vb.)
        "call_graph_propagation": 0.75,  # Call graph hop-based propagation
        "struct_context": 0.70,          # Struct field context isim cikarimi
        "call_context": 0.65,            # Callee-based inference
        "type_heuristic": 0.55,          # Tip ve kullanim oruntusu
        # v1.10.0 M4 entegrasyon: computation paketleri NameMerger evidence source'u
        "cfg_iso_template": 0.85,            # CFG hibrit iso template eslemesi
        "computation_fusion": 0.90,          # Log-odds ensemble fusion (byte+CFG+proto)
        "computation_struct_recovery": 0.80, # MaxSMT struct layout kurtarma
        # v1.21 (2026-05-14): Engineering algorithm fusion -- karadul/reconstruction/engineering
        # paketi pipeline'a fuse edildi. Constant/API/Formula tabanli 3 ayri kanal.
        "engineering_constant": 0.85,        # IEEE-754 sabit eslesmesi (Gauss, k-eps, FEA)
        "engineering_api": 0.90,             # BLAS/LAPACK/FFTW/PETSc cagri imzalari (yuksek precision)
        "engineering_formula": 0.88,         # FormulaReconstructor template eslesmesi (algoritma sabit + yapi)
    })
    default_weight: float = 0.7     # Bilinmeyen kaynak icin fallback
    unk_threshold: float = 0.30     # Altinda isim atanmaz (UNK)
    max_confidence: float = 0.99    # Ust sinir (asla %100 deme)
    min_confidence: float = 0.01    # Alt sinir (asla %0 deme)
    multi_source_prior: float = 0.5 # Baslangic prior (uniform)

    @classmethod
    def load_tuned_weights(cls, path: Path) -> "NameMergerConfig":
        """`scripts/tune_merger_weights.py` ciktisindan weight'leri yukle.

        v1.10.0 Batch 5A: Tuning JSON'u source_weights'i override eder.
        Diger alanlar varsayilanlari korur. Dosya yoksa/bozuksa varsayilan
        config dondurulur + uyari log'lanir.

        Args:
            path: `sigs/tuned_weights.json` yolu.

        Returns:
            NameMergerConfig instance (tuned veya default fallback).
        """
        import json as _json
        import logging as _logging
        _log = _logging.getLogger(__name__)
        cfg = cls()
        p = Path(path) if not isinstance(path, Path) else path
        if not p.exists():
            _log.warning("tuned_weights.json bulunamadi: %s", p)
            return cfg
        try:
            data = _json.loads(p.read_text(encoding="utf-8"))
        except (OSError, _json.JSONDecodeError) as exc:
            _log.error("tuned_weights.json parse hatasi: %s", exc)
            return cfg
        weights = data.get("weights")
        if not isinstance(weights, dict):
            _log.error("tuned_weights.json formatsız (weights key yok)")
            return cfg
        # Mevcut source_weights'i overlay et
        updated = dict(cfg.source_weights)
        for k, v in weights.items():
            if isinstance(v, (int, float)) and 0.0 <= v <= 1.0:
                updated[k] = float(v)
        cfg.source_weights = updated
        return cfg


@dataclass
class BinaryReconstructionConfig:
    """Binary tersine muhendislik ayarlari."""
    enable_c_naming: bool = True
    enable_type_recovery: bool = True
    enable_algorithm_id: bool = True
    enable_comment_generation: bool = True
    enable_string_decryption: bool = True
    enable_packed_detection: bool = True
    enable_binary_name_extraction: bool = True
    enable_byte_pattern_matching: bool = True  # FUN_xxx byte pattern ile kutuphane fonksiyonu tanima
    enable_engineering_analysis: bool = True  # Muhendislik/finans/ML/DSP algoritma tespiti
    enable_struct_recovery: bool = True       # Algoritma-bazli struct field isimlendirme
    enable_semantic_naming: bool = True       # Parametre semantik isimlendirme
    enable_block_annotation: bool = True      # Kod blogu muhendislik annotasyonu
    enable_xtride_typing: bool = True         # v1.8.6: XTRIDE n-gram tabanli degisken tip cikarimi
    enable_ngram_naming: bool = True          # v1.8.7: N-gram degisken isim tahmini (STRIDE/XTRIDE)
    ngram_confidence_threshold: float = 0.55  # v1.8.7: Minimum confidence (0.0-1.0)
    enable_dynamic_naming: bool = True        # v1.9.0: Frida trace -> degisken isimlendirme
    enable_flow_simplification: bool = True   # Goto elimination / label renaming (v1.5.5)
    goto_max_inline_lines: int = 15           # Tek-hedefli goto inline icin max block satir sayisi
    max_algo_matches: int = 0                   # Algorithm match budget (0 = unlimited)
    pdb_auto_load: bool = True              # Windows PE icin PDB otomatik yukleme
    pdb_search_paths: list[str] = field(default_factory=list)  # Ek PDB arama dizinleri
    enable_function_id: bool = True         # Ghidra FunctionID analyzer
    function_id_db_paths: list[str] = field(default_factory=list)  # Ek .fidb dosyalari
    min_naming_confidence: float = 0.7  # NSA-grade: dusuk confidence isim verme, yanlis isim isimsizden kotu
    max_functions_to_process: int = 0  # 0 = limitsiz, tum fonksiyonlari isle
    max_decompile_timeout_per_func: int = 30
    # Harici signature JSON dosyalari (build-signature-db.py ciktilari)
    external_signature_paths: list[str] = field(default_factory=list)
    # BinDiff: referans binary yolu (debug sembollerle). Verilirse karsilastirma yapilir.
    reference_binary: str = ""
    # Reference Differ: bilinen yazilim tespiti + reference binary eslestirme
    enable_reference_differ: bool = True  # String'lerden versiyon tespiti + CFG matching
    reference_db_path: str = ""           # Reference binary DB dizini (bos ise atlaniyor)
    # Ghidra Data Type Archive (.gdt) dosya yollari.
    # macOS system type'lari icin: mac_osx.gdt, generic_clib.gdt vb.
    # Ghidra kurulum dizinindeki Ghidra/Features/Base/data/typeinfo/ altinda bulunur.
    # Tam yol verilirse o kullanilir, kisa isim verilirse Ghidra typeinfo'da aranir.
    ghidra_data_type_archives: list[str] = field(default_factory=list)
    # --- Buyuk binary destegi (224MB+) ---
    # Ghidra decompile batch boyutu: kac fonksiyon ayni anda islenir.
    # Buyuk binary'lerde tum fonksiyonlari tek seferde decompile etmek
    # JVM heap'i patlatir. 5000'lik batch'lerde GC nefes alir.
    ghidra_batch_size: int = 5000
    # Bu boyutun ustundeki binary'ler "buyuk" kabul edilir (MB).
    # mmap, chunked decompile ve lazy string loading aktif olur.
    large_binary_threshold_mb: int = 100
    # Buyuk binary icin Ghidra timeout carpani.
    # Normal timeout * bu deger = buyuk binary timeout.
    large_binary_timeout_multiplier: float = 4.0
    enable_pcode_extraction: bool = True   # P-Code selective extraction (v1.5: lightweight JSONL)
    pcode_format: str = "jsonl"             # "jsonl" (compact streaming) veya "legacy" (eski 4.7GB JSON)
    pcode_selective_ops: list[str] = field(default_factory=lambda: [
        "COPY", "LOAD", "STORE", "CALL", "CALLIND", "RETURN",
        "INT_ADD", "INT_SUB", "INT_MULT", "INT_DIV",
        "INT_AND", "INT_OR", "INT_XOR", "INT_LEFT", "INT_RIGHT",
        "FLOAT_ADD", "FLOAT_SUB", "FLOAT_MULT", "FLOAT_DIV",
        "CBRANCH", "PTRADD",
    ])
    # v1.7.4: Pipeline feedback loop -- type recovery <-> naming iterasyonu
    pipeline_iterations: int = 3           # Max iterasyon sayisi (1 = eski davranis, loop yok)
    pipeline_convergence_threshold: float = 0.01  # Yeni isim orani < %1 ise dur
    # v1.10.0 M1 T3.4: per-iteration timeout (guvenlik agi)
    pipeline_iteration_timeout: float = 600.0  # Saniye, iter bu kadardan uzun surerse sonrakiler atlanir
    # v1.10.0 M2 T6: minimum yeni isim esigi. Bu altinda ise converge.
    # 1 default -> hic yeni isim yoksa converge kabul et (yoksa max_iter'a kadar devam).
    pipeline_min_new_names_per_iter: int = 1
    # v1.8.6: CAPA capability detection -- Mandiant CAPA ile fonksiyon capability tespiti
    enable_capa: bool = True                # CAPA scan aktif mi (flare-capa yoksa sessiz atla)
    capa_rules_path: str = ""               # Bos = ~/.cache/karadul/capa-rules/ (default)
    capa_timeout: int = 600                 # CAPA scan timeout (saniye)
    # v1.10.0 M2 T4: SignatureDB params -> semantic_namer koprusu.
    # SignatureMatch.params None degilse (sig DB'de orijinal param isimleri var),
    # API_PARAM_DB statik lookup'tan ONCE denenir ve daha yuksek confidence ile yazilir.
    # Default True (bug fix niteliginde, feature flag yalnizca acil geri cikis icin).
    sig_params_enabled: bool = True
    sig_params_source_weight: float = 0.95  # API_PARAM_DB (0.92) ve digerlerinden yuksek
    # v1.10.0 M3 T8: TypeForge struct reconstruction (opsiyonel, harici arac).
    # TypeForge kurulu degilse ya da flag off ise pipeline aynen devam eder.
    # Graceful: kurulum eksikse sessiz atlama, hata fiyasko degil.
    enable_typeforge: bool = False
    typeforge_path: str | None = None        # Bos -> PATH'te 'typeforge' aranir
    typeforge_timeout: float = 600.0         # Subprocess timeout (saniye)
    typeforge_min_confidence: float = 0.85   # Merge icin minimum guven esigi
    # v1.10.0 M3 T9: C++ RTTI/vtable reconstruction (Itanium ABI, single inheritance)
    enable_rtti_recovery: bool = False       # Default kapali, opt-in feature
    rtti_abi: str = "itanium"                # "itanium" | "msvc" (msvc v1.10.1'de)
    rtti_max_vtable_entries: int = 64        # Vtable basina max okunacak method slot
    # v1.13 Dalga 1: anti-debug + packer fingerprint pipeline step'leri.
    # Default True -- opt-out flag'leri. KARADUL_DISABLE_ANTI_DEBUG vb.
    # ile ileride env override eklenebilir.
    enable_anti_debug_detection: bool = True  # AntiDebugStep
    enable_packer_fingerprint: bool = True    # PackerFingerprintStep
    # v1.14 D2: FLIRT trie matcher entegrasyonu (byte_pattern step).
    # Imza sayisi flirt_trie_threshold'u astiginda klasik linear path yerine
    # FlirtTrieMatcher kullanilir (prefix trie + sliding window O(n*d_avg)).
    # flirt_use_trie=False -> her zaman eski (linear) path. Acil geri cikis.
    flirt_use_trie: bool = True               # Genel switch (False ile linear yol)
    flirt_trie_threshold: int = 50            # >threshold imza varsa trie path
    # Faz 2 (2026-07-14): Analist manuel override JSON dosyasi (acik yol).
    # Bos/None -> ~/.karadul/overrides/<binary_hash>.json otomatik kesfedilir
    # (stages._apply_manual_overrides hash'ten bulur). Bu alan SADECE
    # default-olmayan bir yol icin -- auto-discover'a EK ikinci kaynaktir.
    overrides_path: Optional[str] = None


@dataclass
class BSimConfig:
    """BSim fonksiyon benzerlik analizi ayarlari."""
    enabled: bool = True                    # v1.11.0 shadow default AKTIF (guvenli)
    default_database: str = "karadul_bsim"
    db_path: str = ""                       # Bos = ~/.cache/karadul/bsim/
    auto_query: bool = True                 # Analiz sonrasi otomatik sorgu
    min_similarity: float = 0.7             # Minimum benzerlik esigi
    max_results_per_function: int = 5       # Fonksiyon basina max sonuc
    # v1.11.0 shadow-mode: pipeline step'i fusion/NameMerger'a YAZMAZ,
    # sadece artifacts/bsim_shadow.json dump eder. Hafta 2 veri toplandiktan
    # sonra False'a cekilip fusion'a baglanacak.
    shadow_mode: bool = True
    # v1.11.0 Hafta 2 kopru: shadow_mode=False VE use_bsim_fusion=True
    # oldugunda name merger collect_candidates icinde BSim evidence'i
    # source="bsim" ile eklenir. Varsayilan False -- opt-in. Rollback:
    # use_bsim_fusion=False yeter, shadow dump davranisi aynen kalir.
    use_bsim_fusion: bool = False
    # Fusion'da BSim evidence'ini kabul etmek icin minimum similarity.
    # min_similarity (0.7) query esigi; bu (fusion_min_similarity) fusion'a
    # evidence'in gecmesi icin gerekli ek esik. shadow payload zaten
    # min_similarity uzerindekilerle dolu, burasi fusion icin ekstra filtre.
    fusion_min_similarity: float = 0.7
    # Fonksiyon basina fusion'a en fazla kac BSim adayi eklenecek.
    # (Cok fazla aday ayni evidence'i birden fazla sayar; top-N ile sinirla.)
    fusion_max_candidates_per_function: int = 3


@dataclass
class DeepTraceConfig:
    """v1.2 Deep Algorithm Tracing ayarlari."""
    max_trace_depth: int = 10           # DFS max derinlik
    max_trace_targets: int = 5          # Otomatik trace icin max hedef sayisi
    skip_runtime_functions: bool = True  # ObjC runtime, GCD, CF atlama
    enable_dispatch_resolution: bool = True   # ObjC/C++ dispatch cozumleme
    enable_data_flow: bool = True            # Fonksiyonlar arasi veri akisi
    enable_composition: bool = True          # Algoritma kompozisyon analizi
    enable_deep_trace: bool = True           # Derin cagri zinciri izleme
    min_dispatch_confidence: float = 0.3     # Dispatch cozumleme esigi
    composition_min_stages: int = 2          # Min asamali kompozisyon


@dataclass
class DebuggerConfig:
    """Debugger bridge ayarlari.

    GDB/LLDB ile runtime deger yakalama icin konfigürasyon.
    Binary'leri debugger altinda calistirarak register ve stack
    degerlerini toplar. Ghidra'nin statik tip tahminlerini
    dogrulamak icin kullanilir.

    UYARI: Binary'leri calistirmak guvenlik riski tasir.
    Sadece guvenilir binary'ler icin kullanin.
    """
    enabled: bool = False                   # Varsayilan KAPALI
    preferred_debugger: str = "auto"        # "auto", "lldb", "gdb"
    capture_timeout: float = 30.0           # Saniye
    max_breakpoints: int = 50
    max_captures_per_bp: int = 10
    auto_type_verification: bool = False    # Otomatik tip dogrulama


@dataclass
class ComputationRecoveryConfig:
    """Hesaplama bazli kurtarma (v1.4.0) ayarlari.

    4 katmanli opsiyonel pipeline: struct constraint solving, CFG fingerprinting,
    signature fusion ve formula extraction.  Varsayilan KAPALI -- CLI'da
    ``--compute-recovery`` ile veya YAML'da ``computation_recovery.enabled: true``
    ile aktif edilir.

    Her katman bagimsiz acilip kapatilabilir; bagimliliklari (z3-solver, sympy)
    yoksa graceful fallback uygulanir.
    """
    enabled: bool = False                       # Varsayilan KAPALI
    # --- Katman toggle'lari ---
    enable_constraint_solver: bool = True       # Layer 1: Z3/heuristic struct constraint
    enable_cfg_fingerprint: bool = True         # Layer 2: CFG template matching
    # v1.10.0 C2+C3: Dempster-Shafer fusion DEPRECATED -- double-counting
    # riski (codex teyit). Log-odds ensemble + Platt calibration icin
    # ``ComputationConfig.enable_computation_fusion`` kullanilmali.
    # Default True -> False yapildi; v1.11.0'da tamamen kaldirilacak.
    enable_signature_fusion: bool = False        # DEPRECATED: v1.11.0'da kaldirilacak. Yerine ComputationConfig.enable_computation_fusion kullan.
    enable_formula_extraction: bool = True      # Layer 4: C -> math formula
    # --- Threshold'lar ---
    constraint_min_fields: int = 2              # Struct olarak kabul icin min field sayisi
    constraint_min_confidence: float = 0.6      # Constraint sonucu min guven
    cfg_similarity_threshold: float = 0.93      # CFG cosine similarity esigi (v1.5.1: 0.75->0.93, FP azaltma)
    fusion_min_belief: float = 0.5              # Dempster-Shafer min belief
    formula_min_complexity: int = 3             # Formul cikarma icin min AST dugum sayisi
    # --- Propagasyon ---
    type_propagation_max_depth: int = 5         # BFS ile struct kimlik yayilim derinligi
    # --- Propagasyon (v1.5.9) ---
    fusion_propagation_decay: float = 0.50      # Hop basina guven azaltma carpani
    fusion_max_hops: int = 2                    # Maksimum propagasyon hop sayisi
    fusion_min_hint: float = 0.15               # Bu esik altindaki hint'ler atlanir
    # --- Formula extraction (v1.5.9) ---
    max_functions_for_formula: int = 2000       # Formula cikarma fonksiyon limiti
    # --- Go specific (v1.5.9) ---
    go_specific_patterns: bool = True           # Go dilinin ozel pattern'lerini kullan
    # --- Performans ---
    max_functions_per_layer: int = 0            # 0 = limitsiz
    # --- CFG Isomorphism (v1.10.0 M4 beta) ---
    # Hibrit matching: WL fingerprint + LSH -> VF2 rerank -> anchor validation.
    # Codex uyarisi: tek algoritma %60 tavan, hibrit sart.
    # v1.10.0: Berke karari "ship it" -- default AKTIF. Kapatmak icin
    # cli.py --no-cfg-iso veya YAML computation_recovery.enable_cfg_iso: false.
    enable_cfg_iso: bool = True                 # v1.10.0'dan itibaren default AKTIF
    cfg_iso_num_wl_iterations: int = 3          # WL iterasyon sayisi
    cfg_iso_lsh_num_hashes: int = 128           # MinHash imza boyutu
    # v1.10.0 Batch 6A: band_size 4 -> 8 (Codex audit). num_bands=128/band_size,
    # threshold t = (1/num_bands)^(1/band_size). 4 -> t~0.50 (cok gevsek, s=0.5'te
    # %87 candidate); 8 -> t~0.71 (orta sert); 16 -> t~0.84 (cok sert).
    # Siki sinif: s=0.71'in altinda candidate oranini dusurerek false positive'i
    # azaltir; VF2 rerank listesi daha anlamli olur.
    cfg_iso_lsh_band_size: int = 8              # LSH band boyutu
    cfg_iso_top_k_candidates: int = 10          # LSH top-K aday sayisi
    cfg_iso_min_confidence: float = 0.7         # Final min confidence
    cfg_iso_anchor_required_for_small_cfg: bool = True  # Kucuk CFG ambiguous guard
    cfg_iso_small_cfg_threshold: int = 4        # Altinda "kucuk" CFG sayilir
    cfg_iso_small_cfg_penalty: float = 0.4      # Kucuk CFG + anchor yok cezasi
    # v1.10.0 C1 (perf fix): VF2 NP-complete; buyuk CFG'lerde saniyeler
    # surebilir. Her VF2 match cagrisi icin saniye cinsi timeout. 0 -> disabled.
    # v1.10.0 Batch 6A: default 5s -> 30s (Codex audit). Artik hard-stop
    # multiprocessing ile korumaliyiz, timeout bitince CPU geri aliniyor.
    # Node cap (500) ile buyuk CFG'ler zaten VF2 atlar; 30s icin bile
    # pathological graflarda takilma riski yok.
    cfg_iso_vf2_timeout_s: float = 30.0         # Saniye cinsinden VF2 timeout
    cfg_iso_vf2_node_cap: int = 500             # VF2 max node sayisi; ustunde atla


@dataclass
class PipelineConfig:
    """v1.10.0: Step registry pipeline konfigurasyonu.

    use_step_registry=True default (B2, 2026-05-13) — yeni karadul.pipeline
    paketinden step'ler calisir (canli yol). False ise eski stages.py monolith'i
    (obsolete; monolith->step migrasyonu henuz tamamen silinmedi).

    v1.15-B16 (paralel runner):
        parallel_steps=True default -- topological order'da ayni level'daki
            (birbirine baglilik yok) step'ler ThreadPoolExecutor ile paralel
            calisir. Subprocess agirlikli step'ler (Ghidra/TRex/BN/PDB) GIL'i
            tutmadigi icin ThreadPool yeterli. ProcessPool gerekmiyor.
        parallel_max_workers: paralel calisacak max step sayisi. Berke kurali:
            max 7 (paralel ajan limitiyle ayni felsefe). None ise hard cap 7.
    """
    use_step_registry: bool = True  # B2 (2026-05-13): default True, eski monolith yolu obsolete
    parallel_steps: bool = True
    parallel_max_workers: Optional[int] = None


@dataclass
class PerfConfig:
    """v1.10.0: Performans / bellek optimizasyonu ayarlari.

    LMDB-backed SignatureDB:
      use_lmdb_sigdb=False default -- eski dict-based SignatureDB kullanilir (~3GB RAM).
      True ise karadul.analyzers.sigdb_lmdb.LMDBSignatureDB kullanilir (~250MB RAM).
      Gecis icin: scripts/build_sig_lmdb.py ile LMDB olusturulmali.

    lmdb_l1_cache_size: Sicak sembol lookup icin in-process LRU cache boyutu.
    sig_lmdb_path: None ise ~/.karadul/signatures.lmdb kullanilir.

    Naming ThreadPool paralelligi (M2 T2):
      parallel_naming=False default -- eski ProcessPool yolu korunur.
      True ise karadul.naming.ParallelNamingRunner kullanilir (file-level
      ThreadPool, 3-5x hiz hedefi).

    naming_max_workers: None -> CPU_PERF_CORES kullanilir.
    naming_chunk_size: Her thread'e verilen c_file sayisi (cache-friendly
      256 varsayilan).
    naming_chunk_timeout: Tek chunk'in max calisma suresi (saniye). Asilirsa
      chunk basarisiz isaretlenir ve errors listesine eklenir.
    """
    # v1.12.0 sig_db Faz 1: Default True'ya cektik (auto-detect).
    # Davranis: flag True iken ~/.karadul/signatures.lmdb VARSA LMDB backend
    # aktif, YOKSA FileNotFoundError yakalanir ve eski dict yoluna graceful
    # fallback olur (bkz. SignatureDB._init_lmdb_backend). Boylece kullanici
    # LMDB insa etmemise de eski davranis korunur; insa ederse otomatik
    # dusuk-RAM moduna gecer.
    #
    # Tarihce (v1.10.0 M2): Default False idi -- LMDB DB fixture farki
    # (Ornek: `_dispatch_once` LMDB'de libSystem, dict'te libdispatch). Bu
    # risk artik sadece LMDB DOSYASI VAR VE ICERIGI ESKI/FARKLI ise geciyor;
    # dosya yoksa risk sifir (dict yolu calisir).
    use_lmdb_sigdb: bool = True
    sig_lmdb_path: Optional[Path] = None
    lmdb_l1_cache_size: int = 8192
    parallel_naming: bool = False
    naming_max_workers: Optional[int] = None
    naming_chunk_size: int = 256
    naming_chunk_timeout: float = 60.0

    # v1.11.0 Jython Sunset Faz 1: Ghidra scriptleri icin PyGhidra 3.0 /
    # Python 3 migrasyonu. Default False -> yeni migrate edilmis script'ler
    # (karadul/ghidra/scripts/*.py) kullanilir. True -> legacy/ altindaki
    # Jython 2.7 orijinaller kullanilir (acil rollback icin).
    # Env override: KARADUL_USE_LEGACY_JYTHON=1 (ileride eklenecek).
    # Faz 1 kapsami: function_lister.py (Faz 2'de string_extractor,
    # type_recovery; Faz 3'te kalan 7 script).
    use_legacy_jython_scripts: bool = False


@dataclass
class SecurityConfig:
    """v1.10.0 Fix Sprint + Batch 5B: Guvenlik sinirlari.

    max_archive_extract_size: ZIP/TAR bomb koruma sinir (byte). Arsiv
        icindeki uncompressed_size toplami bu degeri asarsa extraction
        reddedilir. Default 2GB.

    max_download_size: _download_file chunked read ust siniri (byte).
        Response bu degeri asarsa baglanti kesilir. Default 500MB.

    allowed_download_schemes: _download_file tarafindan kabul edilen
        URL scheme'leri (case-insensitive). "http" default DEGIL --
        sadece TLS.

    restrict_download_redirects_to_same_host: True ise urllib redirect'te
        ilk URL'nin hostname'inden farkli bir host'a yonlendirme
        reddedilir (Host header SSRF koruma).

    v1.10.0 Batch 5B (Red Team 2. tur):
    max_jar_attr_len_bytes: .class dosyasi attribute_info.attribute_length
        (u4) ust siniri. 4GB allocation DoS koruma.

    max_binary_size_bytes: analiz edilecek binary dosyanin max boyutu.
        packed_binary full-read() 10GB OOM koruma.

    max_decompress_bytes: Streaming zlib/gzip decompress ust siniri. Tek
        bir payload'un uncompressed hali bu degeri gecemez.

    max_z3_access_count: struct constraint solver'a verilen access listesi
        uzunlugu. Z3 exponential timeout koruma.

    max_flirt_entries: FLIRT signature DB'ye yukleme esnasinda tek dosya
        basi kabul edilen signature sayisi. Malicious .pat (1M entry)
        memory koruma.

    max_flirt_hex_length: .pat satirindaki hex pattern string uzunlugu.
        Regex CPU DoS.

    pyinstaller_reserved_names: Windows reserved dosya isimleri; extraction
        esnasinda bu isimlere denk gelen entry'ler reddedilir (Windows
        host uzerinde device acilmasini onler).
    """
    max_archive_extract_size: int = 2 * 1024 ** 3         # 2GB
    max_download_size: int = 500 * 1024 ** 2              # 500MB
    allowed_download_schemes: tuple[str, ...] = ("https",)
    restrict_download_redirects_to_same_host: bool = True
    # v1.10.0 Batch 5B
    max_jar_attr_len_bytes: int = 10 * 1024 * 1024        # 10MB
    max_binary_size_bytes: int = 500 * 1024 * 1024        # 500MB
    max_decompress_bytes: int = 100 * 1024 * 1024         # 100MB
    max_z3_access_count: int = 10_000
    max_flirt_entries: int = 100_000
    max_flirt_hex_length: int = 512
    max_otool_output_bytes: int = 64 * 1024 * 1024        # 64MB
    max_capa_stderr_bytes: int = 1 * 1024 * 1024          # 1MB
    # Windows reserved names (extraction reject) -- CVE COM1.txt vs.
    pyinstaller_reserved_names: tuple[str, ...] = (
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    )


@dataclass
class MinConfidencePresets:
    """B22 (2026-05-13): Merkezi min_confidence esikleri (CLAUDE.md Kural 11).

    Onceden 11 ayri modulde hardcoded'di (0.01 - 0.85 arasinda 10 farkli
    sayi). Magic number drift'ini onlemek icin TUM `min_confidence` esikleri
    burada tanimlanir, tuketiciler `Config.min_confidence.X` uzerinden okur.

    Default'lar onceki hardcoded davranisi BIREBIR korur — bu refactor
    davranis degisikligi DEGILDIR, tek-kaynak-of-truth saglar.
    """
    bindiff_match: float = 0.7
    cfg_iso_matcher: float = 0.7
    reference_differ_detect: float = 0.5
    reference_differ_transfer: float = 0.80
    signature_db_filter: float = 0.5
    byte_pattern_match: float = 0.60
    context_namer: float = 0.1
    c_namer_apply: float = 0.15
    name_merger_legacy_param: float = 0.3
    param_recovery_apply: float = 0.6
    struct_recovery_rewrite: float = 0.6
    callee_profile: float = 0.30
    signature_fusion: float = 0.40
    binary_intel_subsystem: float = 0.3
    dispatch_resolver: float = 0.3
    calibrator_floor: float = 0.01

    def __post_init__(self) -> None:
        for fld in self.__dataclass_fields__:
            val = getattr(self, fld)
            if not (0.0 <= float(val) <= 1.0):
                raise ValueError(
                    f"MinConfidencePresets.{fld} [0,1] disinda: {val}",
                )


@dataclass
class DecompilersConfig:
    """v1.10.0 M2 T10: Decompiler backend secimi (Ghidra lock-in kirma).

    primary_backend: "ghidra" (default) | "angr". angr opsiyonel extra;
        kurulu degilse runtime'da `is_available()` False doner ve calistirma
        RuntimeError atar. Ghidra hicbir durumda kaldirilmaz -- default path.

    enable_parallel_decomp: True ise primary + secondary backend paralel
        calistirilir ve sonuclar karsilastirilabilir (ileriki sprint; bu
        version'da hala tek backend cagirilir, flag yer tutucudur).

    secondary_backend: Paralel mod icin ikinci backend. None ise paralel
        kapali.
    """
    primary_backend: str = "ghidra"
    enable_parallel_decomp: bool = False
    secondary_backend: Optional[str] = None
    # v1.11.0 Phase 1B: Fallback chain. Primary backend `is_available()` False
    # dondurur veya decompile() sirasinda RuntimeError firlatilirsa, listedeki
    # siradaki backend denenir. Default ["ghidra"] -- angr primary secilirse
    # Ghidra'ya duserim; ghidra primary ise (default) bos chain gibi davranir
    # (primary==fallback[0] ise tekrar denenmez).
    fallback_chain: list = field(default_factory=lambda: ["ghidra"])


@dataclass
class Config:
    """Ana konfigürasyon."""
    tools: ToolPaths = field(default_factory=ToolPaths)
    timeouts: Timeouts = field(default_factory=Timeouts)
    retry: RetryConfig = field(default_factory=RetryConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    source_match: SourceMatchConfig = field(default_factory=SourceMatchConfig)
    binary_reconstruction: BinaryReconstructionConfig = field(
        default_factory=BinaryReconstructionConfig,
    )
    network: NetworkConfig = field(default_factory=NetworkConfig)
    min_confidence: MinConfidencePresets = field(default_factory=MinConfidencePresets)
    name_merger: NameMergerConfig = field(default_factory=NameMergerConfig)
    deep_trace: DeepTraceConfig = field(default_factory=DeepTraceConfig)
    bsim: BSimConfig = field(default_factory=BSimConfig)
    debugger: DebuggerConfig = field(default_factory=DebuggerConfig)
    computation_recovery: ComputationRecoveryConfig = field(
        default_factory=ComputationRecoveryConfig,
    )
    # v1.4.0.alpha: LLM'siz hesaplama bazli kurtarma (MaxSMT struct vb.).
    computation: ComputationConfig = field(default_factory=ComputationConfig)
    pipeline: PipelineConfig = field(default_factory=PipelineConfig)
    perf: PerfConfig = field(default_factory=PerfConfig)
    decompilers: DecompilersConfig = field(default_factory=DecompilersConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    project_root: Path = field(default_factory=lambda: Path.cwd())
    scripts_dir: Path = field(default_factory=lambda: Path(__file__).parent.parent / "scripts")
    ghidra_scripts_dir: Path = field(default_factory=lambda: Path(__file__).parent / "ghidra" / "scripts")

    @classmethod
    def load(cls, path: Optional[Path] = None) -> Config:
        """YAML dosyasından yükle, yoksa varsayılan."""
        if path and path.exists():
            with open(path) as f:
                data = yaml.safe_load(f) or {}
            return cls._from_dict(data)
        # Varsayılan config dosyası kontrolü
        default_path = Path.cwd() / "karadul.yaml"
        if default_path.exists():
            with open(default_path) as f:
                data = yaml.safe_load(f) or {}
            return cls._from_dict(data)
        return cls()

    @classmethod
    def _from_dict(cls, data: dict) -> Config:
        cfg = cls()
        if "tools" in data:
            for k, v in data["tools"].items():
                if hasattr(cfg.tools, k):
                    setattr(cfg.tools, k, Path(v))
        if "timeouts" in data:
            for k, v in data["timeouts"].items():
                if hasattr(cfg.timeouts, k):
                    setattr(cfg.timeouts, k, v)
        if "retry" in data:
            for k, v in data["retry"].items():
                if hasattr(cfg.retry, k):
                    setattr(cfg.retry, k, v)
        if "analysis" in data:
            for k, v in data["analysis"].items():
                if hasattr(cfg.analysis, k):
                    setattr(cfg.analysis, k, v)
        if "source_match" in data:
            for k, v in data["source_match"].items():
                if hasattr(cfg.source_match, k):
                    setattr(cfg.source_match, k, v)
        if "binary_reconstruction" in data:
            for k, v in data["binary_reconstruction"].items():
                if hasattr(cfg.binary_reconstruction, k):
                    setattr(cfg.binary_reconstruction, k, v)
        # v1.15.5: ölü `ml`/LLM4Decompile YAML bloğu kaldırıldı. Config.ml field'ı
        # B11'de (LLM-free vizyon, feedback_no_llm.md) silinmişti ama bu yükleyici
        # bloğu kalmıştı → mypy "Config has no attribute ml" + YAML'da "ml" anahtarı
        # gelirse AttributeError. Karadul LLM kullanmaz, bu blok artık yok.
        if "name_merger" in data:
            for k, v in data["name_merger"].items():
                if hasattr(cfg.name_merger, k):
                    setattr(cfg.name_merger, k, v)
        if "deep_trace" in data:
            for k, v in data["deep_trace"].items():
                if hasattr(cfg.deep_trace, k):
                    setattr(cfg.deep_trace, k, v)
        if "bsim" in data:
            for k, v in data["bsim"].items():
                if hasattr(cfg.bsim, k):
                    setattr(cfg.bsim, k, v)
        if "debugger" in data:
            for k, v in data["debugger"].items():
                if hasattr(cfg.debugger, k):
                    setattr(cfg.debugger, k, v)
        if "computation_recovery" in data:
            for k, v in data["computation_recovery"].items():
                if hasattr(cfg.computation_recovery, k):
                    setattr(cfg.computation_recovery, k, v)
        if "network" in data:
            # NetworkConfig docstring'i "YAML'da network.enabled ile acilir" diyor
            # ama bu wiring onceden eksikti (UI ayar paneli network toggle'i icin
            # gerekli; reviewer 2026-07-14). hasattr guard'i sifir-risk kilar.
            for k, v in data["network"].items():
                if hasattr(cfg.network, k):
                    setattr(cfg.network, k, v)
        if "computation" in data:
            for k, v in data["computation"].items():
                if hasattr(cfg.computation, k):
                    setattr(cfg.computation, k, v)
        if "pipeline" in data:
            for k, v in data["pipeline"].items():
                if hasattr(cfg.pipeline, k):
                    setattr(cfg.pipeline, k, v)
        if "perf" in data:
            for k, v in data["perf"].items():
                if hasattr(cfg.perf, k):
                    if k == "sig_lmdb_path" and v is not None:
                        setattr(cfg.perf, k, Path(v))
                    else:
                        setattr(cfg.perf, k, v)
        if "decompilers" in data:
            for k, v in data["decompilers"].items():
                if hasattr(cfg.decompilers, k):
                    setattr(cfg.decompilers, k, v)
        if "security" in data:
            for k, v in data["security"].items():
                if hasattr(cfg.security, k):
                    if k in ("allowed_download_schemes", "pyinstaller_reserved_names") and isinstance(v, list):
                        setattr(cfg.security, k, tuple(v))
                    else:
                        setattr(cfg.security, k, v)
        return cfg

    def validate(self) -> list[str]:
        """Kritik araçların varlığını kontrol et."""
        warnings_list = []
        if not self.tools.ghidra_headless.exists():
            warnings_list.append(f"Ghidra analyzeHeadless bulunamadı: {self.tools.ghidra_headless}")
        if not self.tools.synchrony.exists():
            warnings_list.append(f"synchrony bulunamadı: {self.tools.synchrony}")
        # v1.10.0 Fix-10: Config bridge / double-counting guard.
        # Eski D-S fusion + yeni log-odds fusion AYNI ANDA aktif olursa kanit
        # iki kere sayiliyor (codex teyit: belief mass double-counting).
        # Fail-loud: uyari listesine ekle, engine tarafi da DeprecationWarning atar.
        if (
            self.computation_recovery.enable_signature_fusion
            and self.computation.enable_computation_fusion
        ):
            warnings_list.append(
                "ComputationRecoveryConfig.enable_signature_fusion (D-S, "
                "DEPRECATED) ve ComputationConfig.enable_computation_fusion "
                "(log-odds) AYNI ANDA aktif -- double-counting riski. "
                "D-S'yi kapatin (v1.11.0'da otomatik kaldirilacak)."
            )
        return warnings_list
