# Jython Sunset Faz 1 Planı (v1.11.0)

**Tarih:** 2026-04-22
**Yazar:** Architect (team)
**Bağlam:** Codex/Berke kararı = **aşamalı** sunset (Gemini'nin "v1.12 tam" önerisinin aksine). Bu döküman SADECE Faz 1'in (v1.11.0) scope'unu, migration şablonunu, test ve rollback stratejisini planlar. Kod yazılmamıştır; script dosyalarına dokunulmamıştır.

---

## 1. Script Envanteri

Dizin: `karadul/ghidra/scripts/` — toplam **10 aktif Jython 2.7 script** (devops raporundaki 11 rakamı `__init__.py`'yi sayıyordu; o boş bir init).

Ordered `get_default_scripts()` (karadul/ghidra/headless.py:2113-2136) sırası aşağıdaki tabloya yansıtıldı.

| # | Script | Satır | Üretilen Artefakt | Çağrıldığı Yer (karadul/) | Downstream Tüketici(ler) | CI/Benchmark Etkisi | Kritiklik |
|---|--------|-------|-------------------|---------------------------|---------------------------|---------------------|-----------|
| 1 | `function_lister.py` | 96 | `functions.json` | `ghidra/headless.py:2118`, `tests/test_ghidra.py:93` | `binary_name_extractor`, `c_comment_generator`, `byte_pattern_matcher`, `capa_scanner`, `signature_db`, `bindiff`, `pipeline/steps/ghidra_metadata.py`, `reference_populator` | **YÜKSEK** — benchmark_runner GT anahtarları + naming_map bu dosyaya dayanıyor. Tester'ın 04-22 raporunda F1=0 bug'ının kök nedeni bu katmandaki key-space uyumsuzluğuydu | **KRİTİK-1** |
| 2 | `string_extractor.py` | 167 | `strings.json` (xref'li) | `ghidra/headless.py:2119` | `binary_name_extractor.py:334,697,853`, `c_namer.py:1509` | **ORTA** — c_namer string-based naming heuristics bu xref bilgisine bağlı; F1'e dolaylı (~%3-5) | **KRİTİK-2** |
| 3 | `call_graph.py` | 190 | `call_graph.json` | `ghidra/headless.py:253` (PyGhidra native) + `:2120` (fallback script) | `stages.py:1208,1219`, `hacker_cli.py:240,960` | **ORTA** — `config.py:194` `call_graph_propagation=0.75` weight (feedback loop) | NORMAL (PyGhidra path zaten var; script fallback'tir) |
| 4 | `decompile_all.py` | 439 | `decompile.json` + per-bb mnemonic | `ghidra/headless.py:2121` | `pipeline/steps/cfg_iso_match.py:36` | **ORTA** — CFG isomorphism matching + assembly_analyzer | NORMAL |
| 5 | `type_recovery.py` | 262 | `types.json` | `ghidra/headless.py:2122` | `config.py:253` flag, `stages.py:2113,2203,2989,3083` (pipeline iter'larında) | **YÜKSEK** — SURE 2025 karşılaştırmasında type P/R metriği bu veriye bağlı (Tester önerdi metrics.py'a ekleme) | **KRİTİK-3** |
| 6 | `xref_analysis.py` | 437 | `xrefs.json` | `ghidra/headless.py:2123` | stages.py dolaylı (xref propagation) | ORTA | NORMAL |
| 7 | `pcode_analysis.py` | 339 | `pcode.json` | `ghidra/headless.py:2124`, `tests/test_pcode_analyzer.py` | `analyzers/pcode_analyzer.py:153` | ORTA | NORMAL |
| 8 | `cfg_extraction.py` | 341 | `cfg.json` | `ghidra/headless.py:2125`, `tests/test_step_pcode_cfg.py` | `analyzers/cfg_analyzer.py:118` | ORTA | NORMAL |
| 9 | `function_id_extractor.py` | 132 | `function_id_matches.json` | `ghidra/headless.py:2126` | library recall metric (signature_db verify) | DÜŞÜK-ORTA | NORMAL |
| 10 | `export_results.py` | 182 | `results.json` (hepsi birleşik) | `ghidra/headless.py:2127` (son çalışan), `tests/test_ghidra.py:94,100` | `analyzers/assembly_analyzer.py:186` | **YÜKSEK** — tüm önceki çıktıları tek JSON'a birleştirir; SCRIPT_ORDER-son assertion'ı CI'da guard olarak duruyor | Semi-kritik ama migration kolay (sadece JSON merge) |

**Toplam:** 2,585 satır Jython 2.7 (exclude `__init__.py`).

---

## 2. Faz 1 Scope Kararı (v1.11.0 — 1 hafta)

Kritiklik + benchmark/CI etkisi + downstream fan-out gözetilerek **3 script** Faz 1'de migrate edilir:

1. **`function_lister.py`** — 96 satır, **en çok downstream** (8+ modül), benchmark F1 temeli
2. **`string_extractor.py`** — 167 satır, c_namer + binary_name_extractor bağımlılığı
3. **`type_recovery.py`** — 262 satır, SURE 2025 type P/R metriği + pipeline iter döngüsü

**Neden bu üçü?**
- `function_lister` → **benchmark taban noktası**. `functions.json` FUN_\<hex\>/sembol map anahtarı, Tester 04-22 raporu F1=0 buraya bağlıydı.
- `string_extractor` → naming heuristics'in %2-5'i buna bağlı, ölçüm gürültüsünden arınmak için.
- `type_recovery` → SURE 2025 karşılaştırması type recovery P/R metriğini gerektiriyor, bu metrik direkt type_recovery artefaktından çıkar. Ayrıca `stages.py` iter döngüsünde her turda yeniden çalışıyor — en yüksek çalışma frekansı.

**Faz 1 DIŞINDA tutulan script'ler ve gerekçe:**
- `call_graph.py` — `headless.py:253` zaten native PyGhidra path'i kullanıyor (`_extract_call_graph`). Script fallback; önceliği DÜŞÜK.
- `decompile_all.py` (439 LOC) + `pcode_analysis.py` (339 LOC) + `xref_analysis.py` (437 LOC) + `cfg_extraction.py` (341 LOC) — büyük, Ghidra API ile yoğun etkileşimli. Faz 2'de (v1.12.0) batch olarak.
- `function_id_extractor.py` — düşük kullanım, Faz 2/3.
- `export_results.py` — son, migration trivial (JSON merge) ama geri kalan scriptler migrate olmadan önce migrate edilirse "yarısı Jython yarısı PyGhidra" karışık output'u birleştirmek zorunda kalır. Faz 2 sonunda migrate edilir.

---

## 3. Migration Detayları

### 3.1 Genel Gözlem (Tüm Script'ler İçin Geçerli)

`karadul/ghidra/scripts/*.py` dosyalarının kısa statik taraması (grep: `print ` statement, `xrange`, `iteritems`, `basestring`, `u''/u""`, `except ... ,` Python2 yakalama formu):

- **`print X` statement formu YOK** — tümü `print("...")` ya da `print(X)` fonksiyon formunda
- **`xrange`, `iteritems`, `iterkeys`, `itervalues`, `basestring`, `u''` literal YOK**
- **`%` string formatting** var (f-string yerine, Jython 2 uyumu için) — Python 3'te de çalışır
- **`except (X, Y) as e:`** modern formu kullanılıyor (örn. export_results.py:49)

**Sonuç:** Script'ler zaten **2/3 ortak alt küme**yle yazılmış. Gerçek Python 3 migrasyonu minimal; asıl risk noktası **PyGhidra 3.0'ın JPype tipleri altında Ghidra API iterasyonu** ve **unicode/bytes boundary**.

### 3.2 Script: function_lister.py (KRİTİK-1)

**Mevcut Durum:**
- Dil: Jython 2.7 (çalışma zamanı), Python 2/3 ortak syntax (yazım)
- Satır: 96
- Import pattern: stdlib only (`json`, `os`, `sys`, `tempfile`) + global `currentProgram` (Ghidra runtime injected)
- Çağrıldığı yer: `karadul/ghidra/headless.py:2118` (CLI fallback modunda subprocess scriptPath olarak)
- PyGhidra native eşdeğeri **YOK**, headless.py sadece bu script üzerinden `functions.json` üretiyor

**Migration:**
- Hedef: PyGhidra 3.0 — **iki yoldan biri** seçilecek (review kararı):
  - **Opsiyon A (tercih):** Script olarak KAL, sadece Jython 2.7 kısıtını kaldır (`print(...)` format-string zaten Python3 uyumlu). Script PyGhidra 3.0 engine'i altında da çalışır — engine değişti, syntax aynı kaldı.
  - **Opsiyon B:** `headless.py` içine native Python fonksiyonu olarak taşı (`_extract_functions(program)`) — `call_graph` için yapılanın aynısı. Subprocess overhead'ini kaldırır (~2-4s tasarruf).
- **Karar önerisi:** **Opsiyon A** Faz 1'de. Opsiyon B v1.12.0'a (hem test riski düşük kalır hem subprocess fallback path'i korunur).
- Değişiklikler (Opsiyon A):
  - Header güncelle: `Jython 2.7 uyumlu` → `PyGhidra 3.0 (Python 3.10+) uyumlu`
  - `# Python 3 syntax'i KULLANILMAMALIDIR` uyarısını kaldır
  - `open(path, "w")` → `open(path, "w", encoding="utf-8")` (Jython'da ignore edilirdi, Py3'te anlamlı)
  - `str(func.getName())` tüm yerlerde **JPype→Python str** dönüşümü zorla (JPype `java.lang.String` ↔ Python `str` boundary'si için defansif)
  - `% formatting` (satır 30, 93) → f-string'e çevir (isteğe bağlı kalite; zorunlu değil)
- Test:
  - `tests/test_ghidra.py` SCRIPT_ORDER testi değişmeden geçmeli (dosya adı aynı)
  - **Yeni test:** `tests/test_function_lister_py3.py` — bir fixture binary'de mini entegrasyon (PyGhidra 3.0 ile launch, script'i `pyghidra.run_script` üzerinden çağır, `functions.json` schema doğrula)
  - Benchmark: v1.11.0 baseline (F1=0.909, P=0.833, R=1.0) korunmalı → `sample_macho` üzerinde regresyon = 0

**Beklenen sorunlar:**
- `func.getName()` → JPype string proxy dönebilir; `str(...)` wrap defansif şart
- `func.getBody().getNumAddresses()` → JPype `long` / `int` boundary (Py3'te tek tip); `int(...)` wrap
- `param.getOrdinal()` → yine int wrap
- `func.getSymbol().getSource()` — `SourceType` enum'u `str(...)` ile stringify edilmeli (JPype enum repr farklı olabilir)
- **Unicode:** Binary'lerde non-ASCII fonksiyon adı (örn. mangled C++) → JSON encode'da `ensure_ascii=False` + explicit utf-8 file handle

**Efor:** 0.5 gün kod + 0.5 gün test = **1 gün**

---

### 3.3 Script: string_extractor.py (KRİTİK-2)

**Mevcut Durum:**
- Satır: 167
- Import: `ghidra.program.model.data.StringDataType`, `ghidra.program.util.DefinedDataIterator`
- Üretim: `strings.json` + xref bilgisi (binary_name_extractor bunu parse ediyor, c_namer:1509 xref fix'ine bağlı)
- Satır 131'de format specifier tespiti: `elif "%" in val and any(c in val for c in "dsfxplu")` — Python 2/3 ortak, değişmez

**Migration:**
- Opsiyon A (tercih): Script kalır, header güncellenir
- JPype tipleri: `DefinedDataIterator` iteratorü PyGhidra 3.0'da Java iterator proxy'si döner — `for data in iter:` Py3 için sorunsuz ama `iter.hasNext() / iter.next()` kullanımı VARSA Python 3 `__next__` çağrısına dönmeli (script'te `for x in iter` kullanılmış, risk düşük)
- String decode: Ghidra `getValue()` dönüşü `java.lang.String` → `str(...)` wrap
- **Xref Bilgisi:** Binary_name_extractor:697 comment'inde "xref fix'i" var — mevcut format string'i "address -> address" şeklinde; Py3 migration'da format değişmemeli (downstream parser aynı)

**Test:**
- Yeni test: `tests/test_string_extractor_py3.py` — libc içeren binary'de string count + xref sayısı eski Jython çıktısıyla ≥%99 eşleşsin (byte-exact değil, schema eşleşmesi)
- **A/B paralel test** burası için zorunlu: Aynı binary'de Jython path + PyGhidra path → iki `strings.json` diff

**Beklenen sorunlar:**
- **Encoding:** Binary içi string'ler UTF-8 olmayabilir (UTF-16LE, ASCII, Shift-JIS). Jython 2.7 `str` = bytes davranışı, Py3'te `str` = unicode. `getValue()` dönüşü Ghidra'nın kendi decode'u → güvenli
- **Null bytes:** Py3 `json.dump` ` ` literal'lerde throw etmez ama downstream parser'ımız ne yapar? `binary_name_extractor.py:697-750` incele — **Reviewer görevi**

**Efor:** 0.5 gün kod + 1 gün test (A/B diff harness) = **1.5 gün**

---

### 3.4 Script: type_recovery.py (KRİTİK-3)

**Mevcut Durum:**
- Satır: 262 (en büyük Faz 1 script'i)
- Import: `ghidra.program.model.data.{Structure, Union, Enum, TypeDef, FunctionDefinition, Pointer}`
- Üretim: `types.json` (struct/enum/typedef + alan ayrıntıları)
- Downstream: `config.py:253 enable_type_recovery`, `stages.py:2113,2203,2989,3083` (pipeline iter döngüsünde **her turda** çalışıyor)

**Migration:**
- Opsiyon A (tercih) — script kalır
- `DataTypeManager.getAllDataTypes()` iteratorü PyGhidra 3.0'da `java.util.Iterator` proxy — Py3'te `for dt in dtm.getAllDataTypes():` çalışır
- `isinstance(dt, Structure)` — JPype'ta Java class isinstance DESTEKLENİR ama defansif: `dt.getClass().getSimpleName() == "Structure"` fallback hazır dursun
- **Recursive type walking** (struct içinde struct) — Jython'da recursion depth 1000, Py3'te aynı; ama `sys.setrecursionlimit` elle set edilmeli (büyük binary'lerde zaten problem olabilir, bu script'in bilinen limiti)

**Test:**
- `tests/test_type_recovery_py3.py` — struct-heavy binary (C++ std::vector içeren) üzerinde:
  - Type sayısı eşleşsin
  - Field count eşleşsin
  - Nested struct alan adları eşleşsin
- **SURE 2025 metriği:** metrics.py'a Tester'ın önerdiği `calculate_type_precision_recall` eklenmeli (bu Developer'ın işi, plan DIŞI ama bağlantılı)

**Beklenen sorunlar:**
- **`str(Category path)`** — Ghidra CategoryPath Py3'te `toString()` vs `__str__` — `str(...)` wrap şart
- **`FunctionDefinition.getArguments()`** iteratorü — JPype array proxy, `list(...)` wrap
- **Recursion:** İleri süreçte büyük tip grafiklerinde RecursionError — mevcut Jython kodunda iterative traversal varsa korunmalı

**Efor:** 1 gün kod + 1 gün test = **2 gün**

---

### 3.5 Ortak Migration Şablonu (Tüm 3 Script İçin)

Her script için aynı akış:

1. **Header Güncelle:**
   ```python
   # Ghidra Python Script -- PyGhidra 3.0 (Python 3.10+) uyumlu
   # @category BlackWidow
   # @description ...
   # (Jython 2.7 geriye uyumluluk: scripts/legacy/<ad>.py backup'ta mevcut)
   ```
2. **`# Python 3 syntax'i KULLANILMAMALIDIR` uyarısını kaldır**
3. **JPype boundary defansifleri:**
   - `str(...)` her Java string referansında
   - `int(...)` her Java long/int boundary'sinde
   - `list(...)` iterator → list materialize (büyük binary'lerde bellek testine tabi)
4. **File handle:** `open(path, "w", encoding="utf-8")` + `json.dump(..., ensure_ascii=False)`
5. **Import dokunma:** `ghidra.*` ve `java.*` import'ları PyGhidra 3.0 altında değişmez (PyGhidra zaten Ghidra's Jython bridge'inin yerine JPype kullanıyor, import syntax aynı)
6. **Legacy yedek:** Mevcut dosya `karadul/ghidra/scripts/legacy/<ad>.py` altına `git mv` + eski içerik korunsun (rollback için)

---

## 4. PyGhidra Dependency Pin (pyproject.toml önerisi)

**Mevcut durum:** `pyproject.toml`'da `pyghidra` PIN YOK (devops raporu doğrulandı, grep'te `pyghidra` yok).

**Önerilen ekleme** (Faz 1 başlangıcında):

```toml
[project.optional-dependencies]
ghidra = [
    "capstone>=5.0",
    "lief>=0.14",
    "pyghidra>=3.0.0,<4.0",
]
```

**Not:** PyGhidra 3.0.0 sadece **Ghidra 11.3+ / 12.0+** ile uyumlu. Karadul kurulumunu /opt/ghidra-12.0 hedefliyor (devops). `docs/setup.md`'de minimum Ghidra sürümü 12.0 olarak belgelensin.

**Önemli:** pyproject.toml'a DOKUNMAYACAĞIM (planda sadece öneri); Developer Faz 1 kick-off'unda ekleyecek.

---

## 5. Test Stratejisi

### 5.1 A/B Paralel Test (Faz 1 Şart)

Migration süresince (1 hafta) her iki path de çalışabilir olmalı:

```
Binary X
  ├── Jython 2.7 path (eski) → scripts/legacy/<ad>.py → output_legacy/*.json
  └── PyGhidra 3.0 path (yeni) → scripts/<ad>.py → output/*.json

Diff harness: tests/ab/test_script_parity.py
  - functions.json: aynı fonksiyon adresleri
  - strings.json: ≥%99 string eşleşmesi
  - types.json: struct/enum adları + field sayıları eşleşmesi
```

**Çıkış kriteri:** 3 kritik script için ≥ %99 A/B parity. %100 beklenmiyor çünkü PyGhidra 3.0 bazı Ghidra API davranışlarını farklı dönebilir (örn. "undefined" tip stringify'ı).

### 5.2 Benchmark Regresyon Kontrolü

- **Baseline:** v1.11.0-alpha (Developer 04-22 raporu): **F1=0.909, P=0.833, R=1.0, Exact=5/6, FUN_residue=0%**
- **Kabul kriteri:** Faz 1 sonunda benchmark ≤ %1 sapma (F1 ≥ 0.900). Aksi halde rollback.
- **CI Gate:** Gemini'nin önerdiği "Performance Gate" bu sprint'te aktif olmalı. Baseline %5 düşüşte hard-fail.

### 5.3 Headless Smoke Test

DevOps'un 04-22 smoke testi (sample_macho arm64 import) PyGhidra path'i altında tekrarlanmalı. Subprocess fallback path'i (`get_default_scripts()` → CLI analyzeHeadless) ayrıca test edilmeli:

```bash
KARADUL_GHIDRA_MODE=subprocess python -m karadul analyze tests/fixtures/sample_macho
KARADUL_GHIDRA_MODE=pyghidra   python -m karadul analyze tests/fixtures/sample_macho
```

Her ikisi aynı functions.json/strings.json/types.json üretmeli.

### 5.4 Unit Test Matrisi

| Test dosyası | Kapsam | Durum |
|--------------|--------|-------|
| `tests/test_ghidra.py` | SCRIPT_ORDER, dosya adı asertleri | Mevcut, değişmeden geçmeli |
| `tests/test_function_lister_py3.py` | Yeni — PyGhidra 3.0 altında function_lister | **YENİ** |
| `tests/test_string_extractor_py3.py` | Yeni — string + xref parity | **YENİ** |
| `tests/test_type_recovery_py3.py` | Yeni — struct/enum/typedef parity | **YENİ** |
| `tests/ab/test_script_parity.py` | A/B diff harness | **YENİ** |
| `tests/test_security_fixes_v1100.py` | Mevcut — 5 script adı referansı | Değişmeyecek |
| `tests/test_step_pcode_cfg.py`, `tests/test_pcode_analyzer.py` | Faz 1 DIŞI (pcode Faz 2) | Değişmeyecek |

---

## 6. Zaman Tahmini

**Faz 1 — v1.11.0 (1 hafta = 5 iş günü):**

| Gün | İş | Sahip |
|-----|-----|-------|
| Gün 1 | pyproject.toml pyghidra PIN + `scripts/legacy/` backup + A/B harness iskelet | Developer |
| Gün 2 | `function_lister.py` migration + test | Developer |
| Gün 3 | `string_extractor.py` migration + A/B parity test | Developer |
| Gün 4 | `type_recovery.py` migration + struct-heavy fixture test | Developer |
| Gün 5 | Benchmark regresyon + CI Performance Gate + rollback drill | Tester + DevOps |

**Buffer:** +2 gün JPype boundary bug fix (Reviewer 04-22 "kör noktalar" uyarısı gereği)

**Toplam Faz 1:** **5-7 iş günü** (1 takvim haftası)

**Faz 2 — v1.12.0 (3 hafta):**
- `decompile_all.py` (439 LOC, en büyük)
- `pcode_analysis.py` (339 LOC)
- `xref_analysis.py` (437 LOC)
- `cfg_extraction.py` (341 LOC)
- `call_graph.py` (190 LOC, native path zaten var — sadece fallback senkron)
- `function_id_extractor.py` (132 LOC)

**Faz 3 — v1.13.0 opsiyonel:**
- `export_results.py` (JSON merge trivial; Faz 2 bittiğinde bloklayıcı olur çünkü önceki 9 script yeni format'ta yazıyor. Faz 2 tamamlanana kadar Jython'da tutulabilir, sonra taşınır)
- Jython 2.7 tamamen kaldırılır, `scripts/legacy/` silinir, `use_legacy_jython_scripts` flag'i kaldırılır

---

## 7. Risk Matrisi

| Risk | Önem | Olasılık | Mitigation |
|------|------|----------|-----------|
| JPype string/int boundary bug (Java proxy → Python tip dönüşüm) | **YÜKSEK** | YÜKSEK | Her Ghidra API dönüşüne `str()`/`int()`/`list()` wrap defansif; unit test her boundary'yi kapsasın |
| Unicode handling (non-ASCII function/string names) | YÜKSEK | ORTA | `encoding="utf-8"` file handle + `ensure_ascii=False` json.dump; A/B parity %99 kabul eşiği |
| PyGhidra 3.0 Ghidra 12.0 DEV build uyumsuzluğu (devops: DEV kurulu, stabil 12.0.4 yok) | ORTA | ORTA | Kurulum yönergelerinde **stabil Ghidra 12.0.4 (Mart 2026) mandatory** belirt; CI'da 12.0.4 image kullan |
| Benchmark F1 regresyonu (%1'den fazla) | YÜKSEK | DÜŞÜK | CI Performance Gate hard-fail; her commit sonrası benchmark run |
| Subprocess fallback path'inin Faz 1'den sonra bozulması | ORTA | ORTA | `KARADUL_GHIDRA_MODE=subprocess` smoke test CI'a ekle; hem pyghidra hem CLI path test edilsin |
| Integer division (`/` vs `//`) — script'lerde gözlenmedi ama kör nokta | DÜŞÜK | DÜŞÜK | `grep -n '[a-z)] / [0-9a-z]' scripts/*.py` pre-migration audit |
| Downstream parser (binary_name_extractor, c_namer) yeni JSON formatında breakage | YÜKSEK | DÜŞÜK | JSON schema **değiştirilmeyecek**; reviewer Faz 1 sonunda schema diff yapsın |
| Tester'ın 04-22 raporu key-space mismatch'i Faz 1 ile tekrar ortaya çıkar | ORTA | DÜŞÜK | `function_lister` migration'ı developer benchmark_runner fix'inden (commit sonrası) sonra yapılsın — sıralama önemli |

---

## 8. Rollback Planı

### 8.1 Script-Bazlı Rollback

Her migration sonrası **ayrı git commit**:
```
git tag v1.11.0-alpha.1  # function_lister migrated
git tag v1.11.0-alpha.2  # string_extractor migrated
git tag v1.11.0-alpha.3  # type_recovery migrated
```

Tek script bozulursa o tag'e revert; diğer migrasyonlar korunur.

### 8.2 Feature Flag

`karadul/config.py` içine:
```python
use_legacy_jython_scripts: bool = False  # KARADUL_USE_LEGACY_JYTHON=1 ile override
```

`karadul/ghidra/headless.py:get_default_scripts()` içinde:
```python
if self.config.use_legacy_jython_scripts:
    scripts_dir = scripts_dir / "legacy"
```

CI/prod'da hata görülürse env var ile anında geri dönülür — commit revert beklemeden.

### 8.3 Legacy Backup

```
karadul/ghidra/scripts/
  legacy/
    __init__.py
    function_lister.py    # Jython 2.7 orijinal
    string_extractor.py
    type_recovery.py
  function_lister.py      # PyGhidra 3.0 yeni
  string_extractor.py
  type_recovery.py
```

`git mv` ile taşı — diff korunsun, git history blame'leri bozulmasın.

### 8.4 Benchmark Regression Gate

CI'da:
```yaml
- name: Benchmark Gate
  run: python -m karadul benchmark --baseline 0.900 --fail-under 0.870
```

F1 < 0.870 → PR merge bloklanır.

---

## 9. Faz 1 Çıkış Kriterleri (DoD)

- [ ] 3 kritik script PyGhidra 3.0 Python 3 uyumlu (`function_lister`, `string_extractor`, `type_recovery`)
- [ ] `scripts/legacy/` altında 3 Jython backup mevcut
- [ ] `use_legacy_jython_scripts` feature flag çalışır
- [ ] A/B parity ≥ %99 (3 script için)
- [ ] Benchmark F1 ≥ 0.900 (baseline 0.909'dan ≤ %1 sapma)
- [ ] Headless smoke test her iki mode'da (pyghidra + subprocess) başarılı
- [ ] `tests/test_ghidra.py` SCRIPT_ORDER + name asertleri PASS
- [ ] 3 yeni test dosyası (PyGhidra 3.0 tabanlı) PASS
- [ ] CI Performance Gate aktif
- [ ] `pyproject.toml` `pyghidra>=3.0.0,<4.0` PIN eklendi
- [ ] `docs/decompiler_backends.md` Ghidra 12.0.4 min sürüm + PyGhidra 3.0 uyumsuzluk notu güncel

---

## 10. Faz 2/3 Bakış (Özet)

**Faz 2 (v1.12.0, ~3 hafta):** decompile_all, pcode_analysis, xref_analysis, cfg_extraction, call_graph (fallback senkron), function_id_extractor.
- Opsiyonel: `headless.py` native Python fonksiyonlarına bazı script'leri eritme (özellikle `call_graph` için yapılmış, diğerleri için subprocess maliyetinden tasarruf). Bu **performans optimizasyonu**, sunset kapsamı değil.

**Faz 3 (v1.13.0, opsiyonel, ~1 hafta):** export_results migration + Jython 2.7 bağımlılığının tamamen kaldırılması, `scripts/legacy/` silinir, `use_legacy_jython_scripts` flag kaldırılır. Tek "son şans rollback" için 1 release cycle beklenir.

---

## 11. Açık Sorular (Developer/Reviewer Cevaplamalı)

1. **Opsiyon A vs B (script kalır mı, native'e eritilir mi)?** — Plan A öneriyor; Developer Faz 1'de Opsiyon A'yı benimsesin, Faz 2'de B kararı verilir.
2. **Jython 2.7'yi subprocess path'inde destekleme niyeti var mı?** — Varsa `use_legacy_jython_scripts` flag'i kalıcı; yoksa v1.13.0'da kaldırılır.
3. **CI için Ghidra 12.0.4 (Mart 2026) image hazır mı?** — DevOps hazırlayacak (ayrı iş, bu plan kapsamı DIŞI).
4. **A/B parity eşiği %99 yeterli mi yoksa %100 beklenmeli mi?** — %100 idealist ama Ghidra API davranış farkı (örn. `"undefined"` stringify) nedeniyle gerçekçi değil; %99 önerildi.
5. **Feature flag default** — Faz 1 sonunda `use_legacy_jython_scripts=False` default, v1.12.0'da `True` default'u yok; sadece acil rollback için.

---

## 12. Tartışma Notu — Gemini İtirazı

Gemini (04-22): "v1.12.0 tam sunset, all-or-nothing."
Codex+Berke: "Aşamalı; Faz 1 = v1.11 kritik, Faz 2 = v1.12 geri kalan, Faz 3 = v1.13 rare."

**Architect görüşü:**

Aşamalı yaklaşım **DOĞRU**, ancak Gemini'nin endişesi (hibrit sürekli teknik borç = sessiz sabotaj) de geçerli. Mitigation:
- Faz 1 + 2 arasında **≤ 4 hafta** geç (takvim olarak). Daha uzun sürerse hibrit gerçekten bottleneck olur.
- Faz 3 **OPSIYONEL değil, ZORUNLU** — v1.13.0 kısıtlı bir release olsa bile sadece Jython kaldırma için yapılsın. `scripts/legacy/` sonsuza kadar tutulmaz.
- Her Faz sonrası **benchmark regression raporu** (Performance Gate). Hibrit katman sessizce F1'i düşürürse hemen yakalanır.

Böylece Berke'nin aşamalı kararı Gemini'nin "all-or-nothing" endişesini karşılar — tam sunset yine olur, sadece 3 release'e yayılmış olur.

---

**Plan sahibi:** Architect
**Uygulayıcı:** Developer (Faz 1 sprint)
**Doğrulayıcı:** Tester (A/B parity + benchmark gate), Reviewer (JSON schema + downstream parser audit)
**Kick-off kararı:** Berke
