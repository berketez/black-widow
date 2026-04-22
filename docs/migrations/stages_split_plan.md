# stages.py `_execute_binary` Split Planı (v1.12.0)

**Yazar:** Architect agent
**Tarih:** 2026-04-22
**Durum:** PLAN ONLY — kod değişikliği yok
**Hedef sürüm:** v1.12.0 (Phase 2 hot-path #2)
**Önceki referanslar:** v1.10.0 Step Registry (M1 T3.5), 2026-04-20 fiyaskosu
**ÖNEMLİ:** `karadul/stages.py` TABU dosyadır — bu planı yazan okudu, yazmadı. Uygulama aşamasında **tek developer + tek branch** kuralı geçerli (paralel ajan YASAK).

---

## 1. Durum Analizi (Audit)

| Metrik | Değer | Not |
|---|---|---|
| Dosya: `karadul/stages.py` | **4906 satır** | Brief'teki 4465 değeri güncel değil |
| Toplam `def` (metod + fonksiyon) | 30 | Grep count |
| Sınıf sayısı | 6 | Identify, StaticAnalysis, DynamicAnalysis, Deobfuscation, **Reconstruction**, Report |
| `_execute_binary` — küçük kopya | satır **753–834** (81 satır, DeobfuscationStage) | Bu plan kapsamında DEĞİL |
| `_execute_binary` — **hedef canavar** | satır **1147–4319** (**3173 satır**, ReconstructionStage) | Split edilecek olan budur |
| Canavar gövdesi | 3173 satır | Brief'te "300–800" tahmini çok düşüktü |
| Cyclomatic Complexity (iddia) | ~800 | Brief; bu plan CC'yi doğrulamadı, sadece guru sayar. 3173 satırda try/except derinliği 4+, for iç içe 3+, if ladder 10+ birleşince makul |
| Mevcut direkt birim test | **0** (ReconstructionStage sadece `import` ve `__init__` flag test edilmiş) | `tests/test_reconstruction.py` satır 911–925 |
| İlgili test dosyaları | `test_reconstruction.py` (44 test), `test_binary_reconstruction.py` (202 test) — toplam **246** | Büyük çoğunluğu alt-katman (reconstruction/) unit test, stage-level değil |

### Kritik bulgu: "Step Registry shim" zaten yarım tamam

`_execute_binary` içinde satır 1158–1169 arasında feature flag var: `context.config.pipeline.use_step_registry`. True ise **10 Phase-1 step**'i (binary_prep … assembly_analysis) `karadul.pipeline.runner.PipelineRunner` üzerinden çalıştırıp sonuçları local değişkenlere geri kopyalıyor. **Phase 2** (feedback_loop + struct_recovery) eski yolda kalıyor, **Phase 3** (satır 3677–3752) 10 post-step için ikinci bir runner üzerinden çalışıyor ve **early return** yapıyor.

Yani: stages.py'nin büyük kısmı (satır 1550–3670 arası ~2100 satır) **şu an bile** step registry flag açılırsa çalıştırılmayan kodun "eski monolith fallback"ı. v1.10.0 M4'te bile Berke HEM registry HEM monolith yolunu korumak istemiş (satır 3408 yorumu). **Split'in asıl işi bu "eski monolith" bloğunu step registry'ye tam devretmek** — sıfırdan 18 metot yazmak değil.

---

## 2. İç Yapı: 7 Mantıksal Bölüm

Canavarın 3173 satırı aşağıdaki **7 bölüme** ayrılıyor. Satır aralıkları grep ile doğrulandı.

| # | Bölüm | Satır aralığı | Satır sayısı | Ana iş |
|---|---|---|---|---|
| 1 | **Setup & Registry Shim** | 1147–1427 | ~280 | Workspace dizinleri, config parse, `_use_step_registry` dal ayrımı, Phase 1 runner çağrısı + artifact geri aktarımı |
| 2 | **Static Metadata (eski monolith Phase 1)** | 1428–2018 | ~590 | Sig DB matching, Byte pattern, P-Code, CFG, FID — **flag kapalıyken çalışır** |
| 3 | **Assembly Fallback** | 2019–2109 | ~90 | Ghidra decompiler fallback (flag kapalıyken) |
| 4 | **Feedback Loop (Phase 2 çekirdek)** | 2110–3397 | **~1290** | v1.7.5 iteratif computation → c_naming → name_merger → type_recovery. **Dosyanın en yoğun bölgesi.** Iç adımlar (1.4, 2.0, 2.4, 2.4b, 2.5, 3.0) sayılı yorumlarla ayrılmış |
| 5 | **Computation Fusion (M4 monolith)** | 3398–3593 | ~200 | CFG iso + signature fusion + MaxSMT struct recovery (monolith kopyası, flag-independent) |
| 6 | **Struct Recovery + Phase 3 Early Return** | 3594–3752 | ~160 | Engineering struct recovery; sonrasında `_use_step_registry` ise Phase 3 runner çalışır ve **return** |
| 7 | **Eski Monolith Phase 3 (post-feedback)** | 3753–4319 | ~570 | Inline detection, semantic naming, flow simplify, comment gen, capa annot, eng annot, project build, eng analysis, deep tracing, timing özeti, return StageResult |

### Bölüm bazlı side-effect haritası

| Bölüm | Dosya I/O | Subprocess | State mutation | Dependency (önce-sonra) |
|---|---|---|---|---|
| 1 Setup | workspace dirs oluştur | — | `artifacts`, `stats`, `errors` init | Giriş |
| 2 Static | JSON okuma/yazma (sig, byte_pattern, pcode, cfg) | — | `sig_matches`, `_pcode_result`, `cfg_result`, vs. → **local namespace**'e >20 ad eklenir | 1 sonra |
| 3 Assembly | Ghidra decomp yazma | **Ghidra headless (indirekt)** | `decompiled_dir` güncelleme | 2 sonra |
| 4 Feedback | çok sayıda `.c` dosyası okuma/yazma, symlink | — | `naming_result`, `type_rec_result`, `_computation_result`, `_prev_named_set`, `_iteration_stats` (loop invariant!) | 3 sonra, 5'ten önce |
| 5 Fusion | — | — | `_cfg_iso_matches_monolith`, `_fused_matches_monolith`, `_computation_struct_candidates` | 4 sonra |
| 6 Struct Recov | `.c` dosyaları düzenleme | — | `struct_recovery_result` | 5 sonra; `_use_step_registry` ise Phase 3 runner delegation sonra return |
| 7 Post-Monolith | çok sayıda `.c` dosyası yazma | — | inline_patterns, semantic_params, comments, capa annots, project dir, eng_analysis, deep_traces | 6 sonra |

### Kritik sıralama kuralları

1. **Phase 1 output → Phase 2 input**: `functions_json`, `strings_json`, `call_graph_json`, `xrefs_json`, `pcode_json`, `cfg_json`, `fid_json`, `decompiled_json` yolları Phase 1'de üretilir, Phase 2'den sonuna kadar gereklidir.
2. **Feedback loop stateful**: `_prev_named_set` her iterasyonda convergence kontrolü için lazım; loop-level değişkendir. Split'te loop'u fonksiyon parametresi olarak dışarıya çıkarsa bu state hala closure/attribute ile taşınmalı.
3. **`decompiled_dir` iterasyonlar arası değişir**: `_loop_decompiled_dir` her iter sonunda güncellenir; bir sonraki iter'de source olarak kullanılır.
4. **`file_cache` paylaşımlı**: `_file_cache: dict[str, str]` cache'i Phase 1'de doldurulur, feedback loop sırasında güncellenir, Phase 3'te de kullanılır (ör. satır 3769 `InlineDetector`).

---

## 3. 18 Alt Metot Önerisi

**Tasarım ilkeleri:**
- Her metot saf Python metod (sınıf üyesi) — modül-level fonksiyon değil (ReconstructionStage attribute'larına erişmesi gerekebilir).
- Ortak state için **`_ReconCtx` dataclass** önerisi (bkz §4). `ctx` objesi (PipelineContext) başka state taşıyor, karışmasın.
- Tüm metotlar `(self, ctx: PipelineContext, rc: _ReconCtx) -> None` signature'ı kullanır. Mutation `rc` üzerinden. Metod dönüş değeri yoktur → side-effect açık.
- Her metot için CC tahmini (optik şeref: branching/for-derinliği üzerinden kaba tahmin).

| # | Metot | Kapsadığı satır | Sorumluluk | Mutate ettiği `rc` alanı | CC tahmini |
|---|---|---|---|---|---|
| 1 | `_prepare_workspace` | 1147–1157 | Workspace dirs, artifacts/stats/errors init | `rc.artifacts`, `rc.stats`, `rc.errors`, `rc.dirs` | <5 |
| 2 | `_dispatch_phase1` | 1158–1427 | Step registry flag'e göre Phase 1'i runner ya da monolith ile çalıştır, artifact'ları `rc`'ye yükle | `rc.ph1_artifacts` (20+ path + data) | ~25 |
| 3 | `_run_signature_matching` | 1428–1470 (monolith kolu) | Sig DB matching — yalnızca flag kapalıysa çağrılır | `rc.sig_matches` | ~12 |
| 4 | `_run_byte_pattern` | 1471–1561 | Byte pattern matching | `rc.byte_pattern_matches` | ~15 |
| 5 | `_run_pcode_analysis` | 1562–1642 | P-Code dataflow (stats_only / jsonl / legacy) | `rc.pcode_result`, `rc.pcode_naming_candidates` | ~18 |
| 6 | `_run_cfg_analysis` | 1643–1831 | CFG analizi, function fingerprints, naming candidates | `rc.cfg_result`, `rc.cfg_naming` | ~22 |
| 7 | `_run_algorithm_engineering` | 1832–2018 | Confidence calibration + engineering + crypto merge + byte pattern enjekte + CAPA | `rc.algo_result`, `rc.eng_result`, `rc.extracted_names`, `rc.capa_capabilities` | ~30 |
| 8 | `_run_assembly_analysis` | 2019–2109 | Ghidra assembly fallback | `rc.asm_result` | ~15 |
| 9 | `_prepare_feedback_loop` | 2110–2209 | Loop state init: max_iterations, cg_neighbors, rglob cache, pre-instantiation (QW4) | `rc.loop_state` (iterator, caches, engines) | ~15 |
| 10 | `_feedback_iter_computation` | 2231–2363 (loop body kısmı 1) | Tek iter'in computation recovery adımı | `rc.loop_state.computation_result` | ~25 |
| 11 | `_feedback_iter_naming` | 2364–2443 | Tek iter'in C naming adımı | `rc.loop_state.naming_result` | ~18 |
| 12 | `_feedback_iter_bindiff_refdiff` | 2444–2706 | Tek iter'in BinDiff + ReferenceDiff adımları | `rc.loop_state.bindiff_matches`, `rc.loop_state.refdiff_matches` | ~30 |
| 13 | `_feedback_iter_name_merger` | 2707–2985 | Tek iter'in Name Merger adımı (en yoğun) | `rc.loop_state.merged_names`, `rc.extracted_names` | ~40 |
| 14 | `_feedback_iter_type_recovery` | 2986–3397 | Tek iter'in Type Recovery + convergence check + incremental file set güncelleme | `rc.loop_state.type_rec_result`, `rc.loop_state.prev_named_set` | ~35 |
| 15 | `_run_computation_fusion_monolith` | 3398–3593 | M4 monolith fusion (cfg_iso + signature fusion + MaxSMT) | `rc.fusion_result`, `rc.struct_candidates` | ~30 |
| 16 | `_run_struct_recovery` | 3594–3671 | Engineering struct recovery | `rc.struct_recovery_result` | ~18 |
| 17 | `_run_phase3_registry` | 3672–3752 | Flag açıksa Phase 3 runner, early return StageResult | (return) | ~10 |
| 18 | `_run_phase3_monolith` | 3753–4296 | Eski monolith Phase 3: inline, semantic, flow, comments, capa annot, eng annot, project build, eng analysis, deep tracing | `rc.stats["timing_*"]`, `rc.artifacts` | ~45 |
| + | `_finalize_result` | 4297–4319 | Timing özeti, StageResult döndür | (return StageResult) | <5 |

**Toplam:** 18 ana + 1 finalize = **19 metot**. Orijinal CC~800 yerine ortalama CC ~22, max CC ~45 (`_run_phase3_monolith`). Python-radon ile gerçek CC ölçümü v1.12.0-alpha1 kabul kriteri olmalı.

### Yeni `_execute_binary` nihai hali (~25 satır)

```python
def _execute_binary(self, context: PipelineContext, start: float) -> StageResult:
    """Binary reconstruction — yüksek seviye koordinatör (bkz: stages_split_plan.md v1.12.0)."""
    rc = _ReconCtx(start=start, stage_name=self.name)

    self._prepare_workspace(context, rc)

    phase1_ok = self._dispatch_phase1(context, rc)
    if not phase1_ok:
        return rc.as_failure()
    if rc.phase1_short_circuit:  # step registry + error
        return rc.phase1_early_return

    if not rc.used_step_registry:
        self._run_signature_matching(context, rc)
        self._run_byte_pattern(context, rc)
        self._run_pcode_analysis(context, rc)
        self._run_cfg_analysis(context, rc)
        self._run_algorithm_engineering(context, rc)
        self._run_assembly_analysis(context, rc)

    self._prepare_feedback_loop(context, rc)
    for iter_idx in range(rc.loop_state.max_iterations):
        rc.loop_state.iter_idx = iter_idx
        self._feedback_iter_computation(context, rc)
        self._feedback_iter_naming(context, rc)
        self._feedback_iter_bindiff_refdiff(context, rc)
        self._feedback_iter_name_merger(context, rc)
        converged = self._feedback_iter_type_recovery(context, rc)
        if converged:
            break

    self._run_computation_fusion_monolith(context, rc)
    self._run_struct_recovery(context, rc)

    if rc.used_step_registry:
        return self._run_phase3_registry(context, rc)

    self._run_phase3_monolith(context, rc)
    return self._finalize_result(context, rc)
```

Okunur, 15 dakikada yabancı bir geliştirici yapıyı kavrar. Her metot bağımsız test edilebilir.

---

## 4. State Flow / `_ReconCtx` Dataclass

3173 satırlık monolith'in bir nedeni: **>40 lokal değişken** fonksiyon scope'unda yaşıyor (ör. `sig_matches`, `algo_result`, `eng_result`, `_computation_result`, `naming_result`, `_prev_named_set`, `_iteration_stats`, `_loop_decompiled_dir`, `_file_cache`, `_cg_neighbors`, `_rglob_c_files`…). Split ederken bu state'i **açıkça geçirmek şart**.

### Çözüm: `karadul/pipeline/_recon_ctx.py` (yeni dosya)

```python
@dataclass
class _ReconLoopState:
    max_iterations: int
    iter_idx: int = 0
    prev_named_set: set[str] = field(default_factory=set)
    iteration_stats: list[dict] = field(default_factory=list)
    loop_decompiled_dir: Path | None = None
    cg_neighbors: dict[str, set[str]] = field(default_factory=dict)
    cfile_by_name: dict[str, Path] = field(default_factory=dict)
    incremental_files: list[Path] | None = None
    rglob_c_files: list[Path] = field(default_factory=list)
    rglob_cfile_map: dict[str, Path] = field(default_factory=dict)
    rglob_cached_dir: Path | None = None
    # pre-instantiated modules (QW4)
    pre_comp_engine: Any = None
    pre_c_namer: Any = None
    pre_type_rec: Any = None
    # iter-local
    computation_result: Any = None
    naming_result: Any = None
    bindiff_matches: dict = field(default_factory=dict)
    refdiff_matches: dict = field(default_factory=dict)
    merged_names: dict = field(default_factory=dict)
    type_rec_result: Any = None


@dataclass
class _ReconCtx:
    """`_execute_binary` içindeki tüm lokal state'in explicit konteyneri."""
    start: float
    stage_name: str
    artifacts: dict[str, Path] = field(default_factory=dict)
    stats: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    dirs: dict[str, Path] = field(default_factory=dict)     # static/deob/reconstructed
    # Phase 1 artifacts (runner veya monolith)
    ph1_artifacts: dict[str, Any] = field(default_factory=dict)
    # flags
    used_step_registry: bool = False
    phase1_short_circuit: bool = False
    phase1_early_return: StageResult | None = None
    # Analyzer results
    sig_matches: list = field(default_factory=list)
    byte_pattern_matches: list = field(default_factory=list)
    pcode_result: Any = None
    pcode_naming_candidates: list = field(default_factory=list)
    cfg_result: Any = None
    algo_result: Any = None
    eng_result: Any = None
    extracted_names: dict = field(default_factory=dict)
    capa_capabilities: dict = field(default_factory=dict)
    asm_result: Any = None
    # Loop + fusion
    loop_state: _ReconLoopState | None = None
    fusion_result: Any = None
    struct_candidates: list = field(default_factory=list)
    struct_recovery_result: Any = None
```

**Avantaj:**
- State mutation noktası **tek** (`rc.X`). Grep'lenebilir.
- Unit testlerde `rc` prefab'i hazırlanır, bir metot izole çağrılır, `rc`'nin sonraki hali assert edilir.
- Yeni alan eklemek için tek yerde değişiklik.

**Dezavantaj:**
- `rc.loop_state.computation_result` gibi nested erişim uzayabilir. Kabul edilebilir ödün.
- Dataclass serileşemeyen alanlar (engine instance'ları) içerir; pickle edilmemeli. Kısıtlamayı comment ile belgele.

### Pure vs Side-effect bölümü

18 metotun 1'i (`_finalize_result`) puredur. 17'si side-effect'li. Bu RE pipeline'ı için **normal**: binary analiz dosya okumadan/yazmadan imkansız. Hedef saf fonksiyonel mimari değil; hedef **her side-effect'i tek yere kapsüllemek**.

---

## 5. Test Stratejisi

### Mevcut durum (doğrulanmış)

- `test_reconstruction.py`: 44 test. `_execute_binary` **direkt çağrılmıyor**; sadece `ReconstructionStage()` ctor + flag testleri (satır 911–925).
- `test_binary_reconstruction.py`: 202 test. Çoğunluğu alt-modül (`reconstruction/`, `analyzers/`) birim testleri.
- Toplam **246 test** dolaylı kapsam sağlıyor. Feedback loop iterasyonu, incremental file set, convergence threshold — bunların **tamamı regression olarak test edilmiyor**. Tehlikeli boşluk.

### v1.12.0 test planı (üç katman)

1. **Coverage baseline (önce)** — split'ten ÖNCE `_execute_binary` üzerinden coverage raporu çıkar:
   ```bash
   pytest tests/ --cov=karadul.stages --cov-report=html:cov_before
   ```
   Branch coverage yüzdesi belgele. Split sonrası **düşmemeli**.

2. **Yeni unit testler (her metot için)** — 18 metot × en az 2 test = **36+ yeni test**:
   - Happy path: normal input → beklenen `rc` mutation.
   - Edge case: ilgili feature flag off / input dosyası yok / boş sonuç.
   - Bazıları (4, 5, 10, 13, 14) için 3+ test lazım (dallı kod).
   - **Fixture**: `_recon_ctx_factory()` — önceki metotların tamamlandığı varsayılan `rc` prefab'ı döndürür. Her test kendi metodunu izole çağırır.

3. **Regression integration test (tek, büyük)** — mevcut 246 testin split sonrası **tamamı geçmeli**. Ek olarak bir "altın binary" üzerinde tam pipeline (flag on + flag off iki varyant) E2E çalıştırılıp SHA256 karşılaştırmalı artifact diff:
   ```python
   def test_execute_binary_artifact_parity_golden():
       # Pre-split commit'teki çıktı imzasıyla karşılaştır
       ...
   ```
   Golden fixture `tests/golden/v1_11_execute_binary_output.json` olarak çek.

### Paralel ajan fiyaskosu korumalari (test-tarafi)

- Her metot commit'inde `pytest -x` green olmadan split ilerlemez.
- Her fazda `pytest --lf` (last failed) yeterli; tüm suite her commit'te gerekmez.
- CI pipeline'ında branch protection: stages.py değiştiren PR sadece tek reviewer kabul etmez, **iki reviewer + tester ajanı onayı** zorunlu olsun.

---

## 6. Migration Güvenlik Stratejisi (3 Faz)

### Faz 1 — v1.12.0-alpha1: **18 metot EKLE, orijinal kod bozulmadan**

**Yaklaşım: Strangler Fig.** 18 metot oluştur. Her metot **sadece orijinal kod aralığını olduğu gibi** içerir (kesme-yapıştır, hiçbir mantık değişikliği YOK). `_execute_binary` bu metotları sırayla çağırır. Hiçbir kod fiilen taşınmadı, sadece etiketlendi.

- Yeni dosya: `karadul/pipeline/_recon_ctx.py` (dataclass).
- `stages.py` satır 1147–4319 yerinde kalır ama **her mantıksal bölüm kendi `_run_XXX` metoduna delege eder**. Bölüm sayısı 18, aralık satır sayısı aynı.
- Örn. satır 1428–1470 arası kod olduğu gibi `_run_signature_matching` metoduna kopyalanır, orijinal satırlar `self._run_signature_matching(context, rc)` ile değiştirilir.
- **Net LOC artışı**: +400 satır (metot imza overhead + dataclass). Kabul edilebilir.
- **Davranış değişikliği**: 0 byte. Artifact SHA256 aynı.
- Git tag: `v1.12.0-alpha1-structural`. Rollback → `git revert`.

### Faz 2 — v1.12.0-alpha2: **Dead monolith yolunu kaldır**

Step Registry default'u `True` yap. `_use_step_registry=False` dalı (~2100 satır dead code) birkaç release boyunca `@deprecated` kalır. v1.12.0-alpha2'de kaldır:
- `_run_signature_matching` … `_run_assembly_analysis` (metot 3–8) silinebilir, çünkü Phase 1 step registry artık yapar.
- `_run_computation_fusion_monolith` (metot 15) silinebilir — step registry M4'ü zaten içeriyor.
- `_run_phase3_monolith` (metot 18) silinebilir — `_run_phase3_registry` hep çalışır.
- **Kalan:** Phase 2 feedback loop (metot 9–14) + struct recovery (metot 16). Feedback loop henüz step registry'e taşınmadı (brief: "Phase 2 hot-path #2"). Bu split'in asıl ödülü: Phase 2'yi step registry formatına hazırlayan temiz metot sınırları.
- **Net LOC azalışı**: ~-2100 satır.
- Git tag: `v1.12.0-alpha2-dead-code-removed`.

### Faz 3 — v1.12.0-beta: **Feedback loop'u step registry'ye taşı**

Metot 9–14 (`_prepare_feedback_loop` … `_feedback_iter_type_recovery`) her birini bir step haline getir:
- `karadul/pipeline/steps/feedback_loop_v2/` altında: `comp_recovery_step.py`, `c_naming_step.py`, `bindiff_step.py`, `name_merger_step.py`, `type_recovery_step.py`.
- Iteration mantığı `PipelineRunner` üzerinde yeni bir "loop step" abstraction'ı gerektirebilir. Alternatif: `FeedbackLoopOrchestrator` helper sınıfı (tek dosyada kalır, step registry dışı).
- Convergence threshold + incremental file set — loop state `PipelineContext.metadata["feedback_loop"]` altında.
- Git tag: `v1.12.0-beta-steps-migrated`.

### Faz 4 — v1.12.0 release

- `_execute_binary` tamamen koordinatör (~25 satır).
- `stages.py` ~4906 → ~2500 satıra iner.
- CHANGELOG, migration guide, ADR-006 ("Step Registry Full Migration") yazılır.

---

## 7. Risk Matrisi

| # | Risk | Önem | Olasılık | Mitigation |
|---|---|---|---|---|
| 1 | **Paralel ajan çakışması** — 2026-04-20 fiyaskosunun tekrarı | KRİTİK | ORTA (diskiplinsizlik durumunda) | Tek developer + tek branch, `CODEOWNERS` dosyasında `karadul/stages.py` için tek onaylayıcı. PR'a "[STAGES-SPLIT]" etiketi zorunlu. v1.12.0 süresince diğer ajanlar **asla** stages.py'ye PR açmaz |
| 2 | **Sessiz state mutation bug'ı** — `_ReconCtx` alanı split sırasında yanlış mutate edilir, 3 iterasyon sonra fark edilir | KRİTİK | ORTA | Faz 1'de 0 mantık değişikliği (sadece kesme-yapıştır). Her metot commit'inde `pytest` + golden artifact diff. Faz 2'ye geçmeden 1 tam hafta soak süresi |
| 3 | **Ghidra subprocess sıralama bozulması** | YÜKSEK | DÜŞÜK (Phase 1 zaten step registry'ye taşınmış) | Integration test golden binary üzerinde. Ghidra headless invocation order metot 2 (`_dispatch_phase1`) içinde kilitli |
| 4 | **Test coverage boşluğu** — `_execute_binary` direkt test edilmediği için split sonrası regresyon görünmez | YÜKSEK | YÜKSEK (mevcut durum) | Split'ten **önce** golden artifact fixture çıkar. 36+ yeni unit test (§5). Branch coverage ölçüsü baseline |
| 5 | **Feedback loop convergence değişikliği** — iterasyon state'i `_ReconLoopState`'e taşınırken default değer farklı olursa iter sayısı değişir, artifact farkı oluşur | YÜKSEK | ORTA | Dataclass `field(default_factory=...)` kullan, `__post_init__` validation. Golden fixture iter-by-iter stats diff kontrol |
| 6 | **LOC artışı (Faz 1 +400 satır)** reviewer'ı boğar | DÜŞÜK | YÜKSEK | Faz 1 PR'ı tek commit — kolay review. Faz 2/3 PR'ları LOC net negatif |
| 7 | **Step Registry API'sinde eksik feature** — feedback loop taşınamayabilir | ORTA | ORTA | Faz 3'e geçmeden Step Registry'e loop abstraction eklenmesi MİMAR gerektirir. Alternatif: `FeedbackLoopOrchestrator` helper (kısıtlı migration) |
| 8 | **Hafıza tüketimi** — `_ReconCtx` büyük dict'leri persistent tutar, GC ertelenebilir | DÜŞÜK | ORTA | Profile-guided. Gerekirse metot 14 sonunda büyük cache'leri (`file_cache`) explicit `.clear()` |

---

## 8. Zaman Tahmini

Tek developer, 1M context (uzun fonksiyonu başta-sonda akılda tutabilecek).

| Faz | İş | Süre |
|---|---|---|
| **Pre-work** | Coverage baseline, golden fixture | 1 gün |
| **Faz 1** | 18 metot + `_ReconCtx` (kesme-yapıştır, 0 mantık) | 2 gün |
| **Soak (Faz 1)** | Günde 1 kez tam suite, golden diff izle | 2-3 gün (passive) |
| **Faz 2** | Dead monolith kaldır, flag flip | 2 gün |
| **Faz 3** | Feedback loop step'leri | 3 gün |
| **Test** | 36+ unit test + E2E + CI entegrasyon | 2 gün |
| **Docs** | ADR-006, CHANGELOG, migration guide | 1 gün |
| **Toplam** | — | **~11 gün (1.5 hafta net)**; soak dahil **~2 hafta takvim** |

Brief'teki "1 hafta" çok iyimserdi — Faz 3 (feedback loop migration) hafife alınmış.

---

## 9. Kabul Kriterleri (Definition of Done)

- [ ] `_execute_binary` ≤ 50 satır (hedef: ~25).
- [ ] 18 metottan hiçbiri CC ≥ 50 (radon ile doğrula).
- [ ] 246 mevcut test + 36 yeni test = **≥ 282 test** geçer.
- [ ] Golden binary artifact SHA256 parity — pre/post split aynı.
- [ ] Branch coverage `karadul/stages.py` üzerinde **düşmez**.
- [ ] `stages.py` satır sayısı ≤ 2700 (mevcut 4906'dan ≥ %45 azalma).
- [ ] ADR-006 yazılı ve `docs/adr/` altında.
- [ ] CHANGELOG'da kullanıcı-yüzü değişiklik: **0** (iç refactor, davranış değişikliği yok).

---

## 10. Açık Sorular (Berke onayı gerekli)

1. **Step Registry default `True` ne zaman oluyor?** Faz 2 bu flag'i çevirmeye dayanıyor; Berke daha önce "HEM registry HEM monolith" istemişti (satır 3408 yorumu). Deprecation window kaç release?
2. **`_ReconCtx` private mi, export mi?** Dataclass'ı sadece stages.py içinde private (`__init__.py`'de yok) tutmayı öneriyorum — dış kullanıcılar `PipelineContext`'i bilmeli, bu iç detay.
3. **Feedback loop step abstraction** — yeni bir `LoopStep` base class'ı mı, yoksa `FeedbackLoopOrchestrator` helper'ı mı? Birincisi daha temiz ama Step Registry core'a dokunur (risk). İkincisi pragmatik.
4. **Paralel ajan yasağı ne kadar sert?** v1.12.0 süresince `stages.py` dokunan herhangi başka PR açıkça reddedilmeli. Git `pre-commit` hook ile engellenebilir.

---

**SON NOT:** Bu plan `docs/migrations/stages_split_plan.md` dosyasıdır. Uygulama, bu plan ile gelen PR'ı Berke explicit onayladıktan sonra başlar. Plan değişikliği istenirse önce bu dosya güncellenir, sonra kod. Diğer ajanlar bu dosyaya okuma yapar, **yazma yapmaz**.
