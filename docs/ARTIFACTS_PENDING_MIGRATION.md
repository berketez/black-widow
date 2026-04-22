# `artifacts_pending` -> `StepContext.produce_artifact` Migration Plani

**Hedef release:** v1.11.0
**Durum:** TAMAMLANDI (2026-04-21) — Phase 1C
**Etkilenen step sayisi:** 14 step (14 dosya, 21 occurrence)

## TAMAMLANDI — Degisiklik Ozeti (v1.11.0)

- `StepContext.produce_artifact(key, value)` API eklendi (`context.py`).
- `StepContext._stage_artifacts` (private) + `stage_artifacts` property
  (read-only view) stage-level artifact'lar icin ayri kanal.
- Runner step execution sirasinda `ctx._current_step_meta = spec` enjekte
  eder (`runner.py:80`), step bitince temizler (`finally` guard).
- 14 step'te `pc.metadata.setdefault("artifacts_pending", {})[key] = value`
  deseni `ctx.produce_artifact(key, value)` ile degistirildi.
- Helper fonksiyonlar (`_pin_artifact`, `_publish_artifact`, `_absorb_artifacts`,
  `_make_publish_artifact`) ctx uzerinden calisacak sekilde refactor edildi.
- `finalize.py` oncelikli olarak `ctx.stage_artifacts`'tan okur; legacy
  `pc.metadata["artifacts_pending"]` fallback olarak korundu (stages.py shim
  ve henuz migrate edilmemis testler icin).
- `produce_artifact` geriye uyumluluk icin `pc.metadata["artifacts_pending"]`
  mirror'unu da yazar — v1.12.0'da bu mirror kaldirilacak.
- Yeni test dosyasi: `tests/test_produce_artifact.py` (12 test).
- Toplam: 157 PASS (step testleri + pipeline smoke + produce_artifact), 0 FAIL.

---

## 1. Mevcut Durum

### Problem

v1.10.0'da pipeline refactor sirasinda, eski `stages.py` monolitik akistan
atomik step'lere gecis yapilirken **kisa yol** olarak `artifacts_pending`
dict pattern'i tutuldu:

```python
# Mevcut pattern (shim)
def run(self, pc: PipelineContext) -> None:
    pending = pc.metadata.setdefault("artifacts_pending", {})
    pending["c_files_updated"] = self._rewrite_files(...)
    pending["naming_map_v2"] = self._build_map(...)
```

Sonra `finalize.py` bu dict'i okuyup pipeline ciktilarini birlestiriyor.

### Kullanim — 14 Step

`karadul/pipeline/steps/` altinda `artifacts_pending` kullanan dosyalar:

| Step dosyasi | Occurrence |
|---|---|
| `_confidence_helpers.py` | 2 |
| `algorithm_id.py` | 1 |
| `assembly_analysis.py` | 2 |
| `byte_pattern.py` | 1 |
| `comment_generation.py` | 2 |
| `deep_tracing.py` | 1 |
| `engineering_analysis.py` | 1 |
| `engineering_annotation.py` | 1 |
| `feedback_loop.py` | 2 |
| `finalize.py` | 3 (reader) |
| `ghidra_metadata.py` | 1 |
| `parallel_algo_eng.py` | 2 |
| `project_build.py` | 1 |
| `struct_recovery.py` | 1 |

Toplam **21 occurrence**, 14 step.

### Sorun

1. **Step izolasyonu kiriliyor:** Registry `produces=[...]` contract'i
   `pc.metadata["artifacts_pending"]` uzerinden bypass ediliyor. Runner'in
   `extra_keys` validation'i (`karadul/pipeline/runner.py:98-103`) bu
   kanala uygulanmiyor.

2. **Artifact sahipligi belirsiz:** Ayni key'i birden fazla step yazabilir,
   sonuncu kazanir. Runner'daki duplicate producer error'i
   (`runner.py:136`) sessizce atlaniyor.

3. **Incremental/resume kirik:** Bir step yeniden calistirilinca
   `artifacts_pending`'e hangi key'leri yazdigi bilinmiyor; eski degerler
   ya da kismi mutation kaliyor.

4. **Test zorlugu:** Step'in urettigi artifact'lari mock'lamak icin
   `pc.metadata["artifacts_pending"]` icine elle yazmak gerekiyor.
   Registry'den turetilmis unit test fixture'lari calismiyor.

---

## 2. Hedef API

### Yeni `StepContext` metodu

Dosya: `karadul/pipeline/context.py`

```python
class StepContext:
    ...
    def produce_artifact(self, key: str, value: Any) -> None:
        """Step'in registry'de declared bir artifact uretmesi.

        Raises:
            ValueError: key, step'in `produces` listesinde yoksa.
            RuntimeError: ayni key daha once bu step tarafindan yazildiysa
                (overwrite guard). Explicit override icin
                ``produce_artifact(..., overwrite=True)``.
        """
        spec = self._current_spec  # runner enjeksiyonu
        if key not in spec.produces:
            raise ValueError(
                f"Step '{spec.name}' artifact '{key}' ureti ama registry'de "
                f"declared degil. Beklenen: {list(spec.produces)}"
            )
        if key in self._produced_artifacts:
            raise RuntimeError(
                f"Step '{spec.name}' artifact '{key}'i ikinci kez yaziyor."
            )
        self._produced_artifacts[key] = value
```

### Runner entegrasyonu

`karadul/pipeline/runner.py:95-105` civari — step calismasindan sonra
`ctx._produced_artifacts` validator `extra_keys` kontrolune besleniyor;
return value yerine context'ten okuyor.

```python
# Once: new_artifacts = step.run(pc)  # dict donuyordu
# Simdi:
ctx = StepContext(pc, current_spec=spec)
step.run(ctx)
new_artifacts = ctx._produced_artifacts
# extra_keys validation ZATEN burada; produce_artifact pre-check'i
# ikinci savunma hatti.
```

---

## 3. Migration Adimlari

### Adim 1 — `StepContext.produce_artifact` ekle

- `context.py`: metod + `_produced_artifacts` dict + `_current_spec` field
- `runner.py`: step calisirken `ctx._current_spec = spec` enjeksiyonu
- Unit test: `tests/test_pipeline_step_context.py`
  - declared olmayan key → ValueError
  - ayni key iki kez → RuntimeError
  - valid key → `pc.artifacts`'a yansiyor

**Risk:** Dusuk. Yeni API, eski pattern'e dokunmuyor.
**Diff boyutu:** ~60 satir.

### Adim 2 — 14 step'i tek tek migrate et

Her step icin:

1. `pc.metadata["artifacts_pending"][key] = value` → `ctx.produce_artifact(key, value)`
2. Registry'de `produces=[...]` listesine ilgili key'i ekle (eksikse).
3. Step'in unit testi varsa `artifacts_pending` mock'unu `ctx` fixture'a cevir.
4. PR basi 2-3 step (review edilebilirlik).

**Onerilen sira (risk dusukten yuksege):**

| Grup | Step'ler | Gerekce |
|---|---|---|
| Grup A (basit) | `byte_pattern`, `ghidra_metadata`, `algorithm_id`, `assembly_analysis` | Tek pending key, minimal state |
| Grup B (orta) | `engineering_analysis`, `engineering_annotation`, `comment_generation`, `deep_tracing`, `project_build` | Birden fazla pending key |
| Grup C (karmasik) | `feedback_loop`, `parallel_algo_eng`, `struct_recovery`, `_confidence_helpers` | Iteratif/stateful, feedback ile etkilesim |
| Grup D (reader) | `finalize` | Tum writer'lar bitince sondan oku |

**Risk:** Orta-Yuksek. Feedback loop step'i iteratif yazma yapiyor;
overwrite guard'i `overwrite=True` flag'iyle gevsetmek gerekebilir.
**Diff boyutu:** ~250-400 satir (test dahil).

### Adim 3 — Legacy `artifacts_pending` dict'e fallback + DeprecationWarning

Gecis doneminde hem eski hem yeni yol calissin:

```python
# runner.py step postprocessing
legacy = pc.metadata.get("artifacts_pending", {})
if legacy:
    warnings.warn(
        f"Step '{spec.name}' artifacts_pending dict'ini kullaniyor. "
        f"StepContext.produce_artifact'a gec. v1.11.0'da kaldirilacak.",
        DeprecationWarning,
        stacklevel=2,
    )
    for k, v in legacy.items():
        if k in spec.produces:
            pc.artifacts[k] = v
    pc.metadata["artifacts_pending"].clear()
```

**Risk:** Dusuk. Sadece CI warning'leri icin. Third-party step plugin'i
varsa (yok), onlar da upgrade edebilsin.

### Adim 4 — `finalize.py` yeni yola bagla

`finalize.py` su an `pc.metadata["artifacts_pending"]` okuyor (3 yerde).
`pc.artifacts` uzerinden okusun; migrate edilmis step'ler burada
zaten yazmis olur.

**Risk:** Dusuk. `finalize` en son calisir, tum writer'lar bitmis olur.

### Adim 5 — v1.11.0'da `artifacts_pending` shim'i kaldir

- `pc.metadata["artifacts_pending"]` referanslarini sil.
- DeprecationWarning → hard error (raise).
- CHANGELOG Known Limitations'tan kaldir.

---

## 4. Risk & Test Stratejisi

### Kritik riskler

1. **Feedback loop regression:** Iteratif yazma overwrite guard'a takilir.
   Cozum: feedback loop step'i `overwrite=True` ile ayri API kullanir
   veya iterasyon basina yeni context olusturur.

2. **Finalize'in siralama bagimliligi:** `artifacts_pending` dict-order'a
   guveniyor olabilir (Python 3.7+ insertion order). `pc.artifacts` da
   ayni ordering'i saglamali.

3. **Test coverage kritik:** Her step migration'i ayni PR'da
   - ilgili step'in mevcut unit testi PASS kalmali
   - registry `produces` validation eklenmiş olmali
   - integration smoke test (`test_pipeline_integration_smoke.py`)
     yesil kalmali.

### Baseline metrikleri

Migration oncesi:
- Test toplami: 3197 PASS (v1.10.0)
- Step sayisi: 20
- `artifacts_pending` kullanimi: 14 step, 21 occurrence

Migration sonrasi (hedef):
- Test toplami: >=3197 PASS + ~20 yeni test (her step icin 1 + StepContext icin 3-5)
- `artifacts_pending` kullanimi: 0

---

## 5. Takvim

| Milestone | Hafta | Icerik |
|---|---|---|
| M1 — API | 1 | Adim 1 (StepContext.produce_artifact + test) |
| M2 — Grup A+B migration | 2-3 | 9 step + testler |
| M3 — Grup C migration | 4-5 | 5 step (feedback loop dahil), regression testler |
| M4 — Cleanup + fallback kaldirma | 6 | Adim 4+5, `artifacts_pending` silinir |

**Toplam:** 6 hafta, v1.11.0 release hedefi.

---

## 6. Ilgili Dosyalar (Referans)

- `karadul/pipeline/context.py` — StepContext tanimi
- `karadul/pipeline/runner.py:95-140` — Step execution + validation
- `karadul/pipeline/registry.py` — StepSpec (`produces`, `requires`)
- `karadul/pipeline/steps/` — 14 migrate edilecek step
- `karadul/pipeline/steps/finalize.py` — Reader (son migration)
- `tests/test_pipeline_integration_smoke.py` — Regression guard
