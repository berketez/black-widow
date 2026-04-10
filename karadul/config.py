"""Merkezi konfigürasyon — TÜM path'ler, timeout'lar, sabitler burada."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


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
        import subprocess
        result = subprocess.run(
            ["sysctl", "-n", "hw.perflevel0.logicalcpu"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip().isdigit():
            return int(result.stdout.strip())
    except Exception:
        logger.debug("sysctl P-core sayisi okunamadi, fallback kullaniliyor", exc_info=True)
    return max(2, int(total * 0.7))


def _detect_available_memory_mb() -> int:
    """Kullanilabilir RAM miktarini MB olarak dondur."""
    try:
        total = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
        return int(total / (1024 * 1024))
    except (ValueError, OSError, AttributeError):
        pass
    try:
        import subprocess
        result = subprocess.run(
            ["sysctl", "-n", "hw.memsize"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return int(result.stdout.strip()) // (1024 * 1024)
    except Exception:
        logger.debug("sysctl memsize okunamadi, fallback 8GB kullaniliyor", exc_info=True)
    return 8192  # fallback: 8GB


# Modül seviyesinde bir kez hesapla
CPU_PERF_CORES = _detect_cpu_cores()
TOTAL_MEMORY_MB = _detect_available_memory_mb()
# Ghidra heap: toplam RAM'in %40'i, min 4GB, max 32GB
GHIDRA_HEAP_MB = max(4096, min(32768, int(TOTAL_MEMORY_MB * 0.4)))


def _resolve_path(p: str) -> Path:
    return Path(os.path.expanduser(p)).resolve()


@dataclass
class ToolPaths:
    """Dış araç konumları."""
    ghidra_headless: Path = field(default_factory=lambda: _resolve_path(
        "~/Desktop/dosyalar/uygulamalar/ghidra/build/dist/ghidra_12.0_DEV/support/analyzeHeadless"
    ))
    ghidra_run: Path = field(default_factory=lambda: _resolve_path(
        "~/Desktop/dosyalar/uygulamalar/ghidra/build/dist/ghidra_12.0_DEV/ghidraRun"
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
    # LLM-assisted variable naming (Claude CLI)
    use_llm_naming: bool = False
    llm_model: str = "sonnet"


@dataclass
class SourceMatchConfig:
    """Source matching ayarlari -- minified fonksiyonlari orijinal kaynakla eslestirme.

    NpmFingerprinter eslestirmesinden sonra, eslesen paketlerin orijinal
    kaynak kodunu cekip fonksiyon bazli eslestirme yapar.
    """
    enabled: bool = True                   # Source matching aktif mi
    min_similarity: float = 0.65           # Minimum fonksiyon benzerlik skoru (0.0-1.0)
    consistency_ratio: float = 0.3         # Toplu tutarlilik esigi
    unpkg_timeout: int = 10                # Tek HTTP istek timeout (saniye)
    unpkg_delay_ms: int = 50               # Istekler arasi bekleme (rate limit)
    max_packages: int = 100                # En fazla kac paket indirilecek
    npm_pack_fallback: bool = True         # unpkg basarisiz olursa npm pack dene
    fingerprint_cache: bool = True         # Fingerprint sonuclarini cache'le


@dataclass
class MLConfig:
    """ML model ayarlari."""
    enable_llm4decompile: bool = False  # Kapali: fonksiyon basi ~30s, buyuk binary'lerde saatler alir
    llm4decompile_model_path: Path = field(
        default_factory=lambda: Path.home() / ".cache" / "karadul" / "models" / "llm4decompile-6.7b-v1.5"
    )
    ml_device: str = "auto"  # "auto", "mps", "cuda", "cpu"
    ml_dtype: str = "auto"  # "auto", "float16", "bfloat16", "float32"
    max_new_tokens: int = 512
    ml_temperature: float = 0.0  # 0 = greedy (deterministic)
    ml_batch_size: int = 1  # Sirali islem (bellek tasarrufu)
    ml_min_function_size: int = 3  # Bu satirdan kisa fonksiyonlari atlama
    ml_max_function_size: int = 200  # Bu satirdan uzun fonksiyonlari kirpma


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
        "string_intel": 0.8,        # Kismen bagimsiz
        "signature_db": 1.0,        # Tamamen bagimsiz (FLIRT)
        "swift_demangle": 1.0,      # Tamamen bagimsiz
        "pcode_dataflow": 0.9,      # P-Code def-use chain analizi
        "source_matcher": 0.85,     # Bagimsiz kaynak, yuksek kesinlik
        "llm4decompile": 0.5,       # Tum kaynaklarla korelasyonlu
        "byte_pattern": 1.0,        # Tamamen bagimsiz
        "function_id": 0.95,        # Ghidra FunctionID -- yuksek guvenilirlik (hash-based)
        "bsim": 0.85,              # BSim fonksiyon benzerligi
        "computation_recovery": 0.9, # Computation pipeline (cfg match, constant analysis)
        "signature_fusion": 0.95,    # Dempster-Shafer fusion -- bagimsiz evidence birlesimi
        "reference_differ": 0.95,    # Reference binary match -- FLIRT/FID seviyesinde guvenilir
        "interprocedural_propagation": 0.85,  # Inter-procedural param name propagation -- call-arg graph based
        "cross_binary_transfer": 0.80,         # CFG fingerprint cache -- cross-binary eslestirme
        "callee_profile": 0.75,                # Callee-profile propagation -- domain-based inference
        "capa_capability": 0.85,               # CAPA capability detection -- Mandiant rule-based
    })
    default_weight: float = 0.7     # Bilinmeyen kaynak icin fallback
    unk_threshold: float = 0.30     # Altinda isim atanmaz (UNK)
    max_confidence: float = 0.99    # Ust sinir (asla %100 deme)
    min_confidence: float = 0.01    # Alt sinir (asla %0 deme)
    multi_source_prior: float = 0.5 # Baslangic prior (uniform)


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
    # v1.8.6: CAPA capability detection -- Mandiant CAPA ile fonksiyon capability tespiti
    enable_capa: bool = True                # CAPA scan aktif mi (flare-capa yoksa sessiz atla)
    capa_rules_path: str = ""               # Bos = ~/.cache/karadul/capa-rules/ (default)
    capa_timeout: int = 600                 # CAPA scan timeout (saniye)


@dataclass
class BSimConfig:
    """BSim fonksiyon benzerlik analizi ayarlari."""
    enabled: bool = False                   # Varsayilan kapali (agir islem)
    default_database: str = "karadul_bsim"
    db_path: str = ""                       # Bos = ~/.cache/karadul/bsim/
    auto_query: bool = True                 # Analiz sonrasi otomatik sorgu
    min_similarity: float = 0.7             # Minimum benzerlik esigi
    max_results_per_function: int = 5       # Fonksiyon basina max sonuc


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
    enable_signature_fusion: bool = True        # Layer 3: Dempster-Shafer fusion
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
    ml: MLConfig = field(default_factory=MLConfig)
    name_merger: NameMergerConfig = field(default_factory=NameMergerConfig)
    deep_trace: DeepTraceConfig = field(default_factory=DeepTraceConfig)
    bsim: BSimConfig = field(default_factory=BSimConfig)
    debugger: DebuggerConfig = field(default_factory=DebuggerConfig)
    computation_recovery: ComputationRecoveryConfig = field(
        default_factory=ComputationRecoveryConfig,
    )
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
        if "ml" in data:
            for k, v in data["ml"].items():
                if hasattr(cfg.ml, k):
                    if k == "llm4decompile_model_path":
                        setattr(cfg.ml, k, Path(v))
                    else:
                        setattr(cfg.ml, k, v)
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
        return cfg

    def validate(self) -> list[str]:
        """Kritik araçların varlığını kontrol et."""
        warnings = []
        if not self.tools.ghidra_headless.exists():
            warnings.append(f"Ghidra analyzeHeadless bulunamadı: {self.tools.ghidra_headless}")
        if not self.tools.synchrony.exists():
            warnings.append(f"synchrony bulunamadı: {self.tools.synchrony}")
        return warnings
