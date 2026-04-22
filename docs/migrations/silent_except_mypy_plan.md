# Silent Except + mypy Hot-Path Planı (v1.12.0)

Tarih: 2026-04-22
Hazırlayan: Reviewer (takım kod denetimi)
Scope: **Sadece PLAN — kod fix yok, yeni test yok.** Uygulama Hafta 2-3'e.

---

## 0. Özet

**Audit sayıları (gerçek, bu doküman yazılırken ölçülen — audit raporundaki 168 tahmin yerine):**

| Metrik | Değer |
|--------|-------|
| Taranan Python dosyası (`karadul/`) | 251 |
| Toplam silent except | **183** |
| Kritik scope (v1.12.0 fix) | **99** (pipeline + reconstruction + recovery_layers + core + decompilers + stages.py) |
| Normal scope (v1.13.0'a sarkabilir) | 74 |
| Diğer (deobfuscators, computation, config) | 10 |
| mypy hatası, strict DIŞI, tüm `karadul/` | 311 (83 dosya) |
| mypy hatası, `--strict` clean, sadece `pipeline/` | **568** (89 dosya, çapraz import dahil) |
| mypy strict genişleme ufku (4 scope) | ~1400–1800 hata tahmini (aşağıda detay) |

**Ana karar:** Audit raporundaki 168 sayısı eksik tahminle (tek-satır pattern'e bakıyordu). Multi-line bloklarla **183 gerçek silent except** var. Bunların %54'ü kritik scope'ta.

---

## 1. Silent Except Durum

### 1.1 Kategorilere Göre Dağılım

| Tip | Desen | Sayı | Tehlike seviyesi |
|-----|-------|------|-------------------|
| **Type A** | `except ...: pass` | **115** | YÜKSEK — hata tamamen yutulur |
| **Type B1** | `except ...: return None` | 13 | ORTA — caller sessizce None alır, debug zor |
| **Type B2** | `except ...: return` | 2 | ORTA — void caller, sessiz fail |
| **Type C** | `except ...: continue` | **53** | DÜŞÜK-ORTA — loop'ta recovery ama log yok |
| Type D | `except ...: ...` (ellipsis) | 0 | — |
| Bare `except:` | — | 0 | (v1.10.0 sprint'te hepsi temizlenmiş) |
| **TOPLAM** | | **183** | |

### 1.2 Scope Ayrımı

Ajanın önerdiği 3-kategorili model (KRİTİK / NORMAL / KABUL):

| Scope | Tip-A | Tip-B1 | Tip-B2 | Tip-C | Toplam |
|-------|-------|--------|--------|-------|--------|
| **KRİTİK (v1.12.0 fix)** | | | | | **99** |
| `pipeline/steps/` | 3 | 0 | 0 | 1 | 4 |
| `reconstruction/` (doğrudan) | 39 | 0 | 2 | 17 | 58 |
| `reconstruction/recovery_layers/` | 0 | 0 | 0 | 17 | 17 |
| `core/` | 5 | 4 | 0 | 2 | 11 |
| `decompilers/` | 1 | 0 | 0 | 0 | 1 |
| `stages.py` (mega-dosya, hot path) | 4 | 0 | 0 | 4 | 8 |
| **NORMAL (v1.13.0 sarkabilir)** | | | | | **74** |
| `analyzers/` | 38 | 7 | 0 | 10 | 55 |
| `ghidra/` | 15 | 1 | 0 | 1 | 17 |
| `quality/` | 0 | 1 | 0 | 0 | 1 |
| `cli/` | 1 | 0 | 0 | 0 | 1 |
| **DİĞER (ayrı değerlendir)** | | | | | **10** |
| `deobfuscators/` | 4 | 0 | 0 | 0 | 4 |
| `computation/` | 2 | 0 | 0 | 0 | 2 |
| `config.py` | 1 | 0 | 0 | 0 | 1 |
| Misc (3 dosya, 3 adet) | 3 | 0 | 0 | 0 | 3 |

### 1.3 En Yüklü Dosyalar (kritik scope)

| Dosya | Silent except sayısı |
|-------|-----------------------|
| `karadul/reconstruction/recovery_layers/constraint_solver.py` | 17 (Type C — tümü) |
| `karadul/reconstruction/binary_name_extractor.py` | 10 (A+C karışık) |
| `karadul/stages.py` | 8 (A=4, C=4) |
| `karadul/reconstruction/project_builder.py` | 6 (Type A) |
| `karadul/reconstruction/reference_differ.py` | 5 (Type A) |
| `karadul/reconstruction/c_namer.py` | 4 (B2=2, C=2) |
| `karadul/core/target.py` | 2 (Type B1) |
| `karadul/core/target_resolver.py` | 1 |
| `karadul/core/report_generator.py` | 1 |

### 1.4 Örnek Satırlar (birer temsilci)

**Type A — `except: pass` (en tehlikeli):**
```
karadul/reconstruction/binary_name_extractor.py:234-235
    except ValueError:
        pass     # ← src_idx parse fail, None döner ama neden bilinmez
```

**Type B1 — `except: return None`:**
```
karadul/analyzers/cpp_rtti.py:663-664
    except (ValueError, TypeError):
        return None   # ← RTTI parse fail, hangi type'ta ne oldu kaybolur
```

**Type B2 — `except: return`:**
```
karadul/reconstruction/c_namer.py:2534-2535
    except KeyError:
        return   # ← void function, caller error-free varsayımıyla devam eder
```

**Type C — `except: continue` (loop recovery):**
```
karadul/reconstruction/recovery_layers/constraint_solver.py:691-692
    except OSError:
        continue   # ← Binary read fail, skip — ama kaç dosya skip'lendi?
```

**"İyi" referans (fix sonrası hedef form):**
```python
# Type A düzeltmesi (pipeline hot path):
except ValueError as e:
    logger.debug("src_idx parse başarısız", exc_info=True, extra={"parts": parts})

# Type B1 düzeltmesi (RTTI parser):
except (ValueError, TypeError) as e:
    logger.debug("RTTI entry parse hatası: %s", e, exc_info=True)
    return None

# Type C düzeltmesi (loop recovery):
except OSError as e:
    logger.debug("binary okuma başarısız, atlanıyor: %s (%s)", path, e)
    skipped_count += 1   # metric
    continue
```

---

## 2. Silent Except Çözüm Önerileri (Pattern Rehberi)

### Pattern 1 — Type A → logger.debug + exc_info
**Kural:** Her `except ...: pass` → `except ... as e: logger.debug("ne oldu", exc_info=True)`.

- Eğer blok gerçekten "boş by design" ise (örn: optional import fallback), **inline yorum ekle**: `# noqa: INTENTIONAL — ImportError: fallback to default` ve logger'a **bir kez** INFO yaz.
- Logger yoksa, modül başına `logger = logging.getLogger(__name__)` ekle.

### Pattern 2 — Type B1/B2 → spesifik exception + sebep log
**Kural:** Çıplak `Exception` yakalamayı **daralt**: hangi hata yakalanıyor → o tip `ValueError`, `KeyError`, `OSError`, domain-specific `KaradulError` alt-sınıfı.
- Return None/return'den önce `logger.debug(...)` + caller'a None dönmesinin sebebi dokümantasyon string'ine yazılsın (`"""... returns None if parse fails."""`).

### Pattern 3 — Type C → skipped metric + DEBUG log
**Kural:** Loop içinde `continue` kabul edilebilir, AMA:
1. **Counter ekle** (`skipped: Dict[str, int]` — scope başına bir tane)
2. `logger.debug("skip: %s reason=%s", item_id, e)` at
3. Loop sonunda `logger.info("döngü bitti: N=%d skipped=%d", ...)` at

### Pattern 4 — Geniş `except Exception` yakalamaları
Audit aracı bare `except:` yakalamadı (0 adet — v1.10.0 temizliği başarılı), ama **Type A'nın 115 adetinin önemli kısmı `except Exception: pass`** formunda olabilir. Fix sırasında ayrıca daraltılmalı:
- `except Exception:` → `except (TypeError, ValueError, KeyError):` veya ilgili spesifik tip.
- Eğer gerçekten geniş recovery gerekiyorsa (örn: plugin sınırı) → `except Exception as e: logger.exception("plugin fail")` + yeniden raise değil, kontrollü degradation.

### KABUL EDİLEBİLİR (dokunma) Durumlar

Bu kategoride silent except **bilinçli** olabilir:
1. **Optional import fallback** (`except ImportError: pass` + sonraki kod `if feature_available:` kontrolü yapıyor) — test var mı yokmuş mu kontrol edip KORU.
2. **Graceful degradation test edilmiş** — eğer `tests/` altında ilgili kod için "fail olursa None döner" testi varsa, behavior-preserving şekilde `logger.debug` eklenir, return None kalır.
3. **Cleanup/__del__ blokları** — shutdown path'inde silent yutma genelde doğru; sadece `logger.debug` yeterli, raise etme.

**Manuel review zorunlu:** 183'ü de otomatik fix'lememek gerek. Her fix için mini-checklist:
- [ ] Bu blok intentional mı? (git blame + yorum ara)
- [ ] Test var mı? (behavior-preserving fix seç)
- [ ] Log spam riski var mı? (loop ise DEBUG level + rate-limit düşün)

---

## 3. mypy Mevcut Durum

### 3.1 Kurulu Ayar (`mypy.ini`)

```ini
[mypy]
python_version = 3.12
warn_unused_ignores = True
warn_redundant_casts = True
strict_optional = True
ignore_missing_imports = True

# Kısmi strict (disallow_untyped_defs + check_untyped_defs):
[mypy-karadul.pipeline.*]
[mypy-karadul.quality.*]
[mypy-karadul.decompilers.*]
[mypy-karadul.exceptions]
[mypy-karadul.core.logging_config]
```

**Durum:** `--strict` bayrağı **hiçbir scope'ta aktif değil**. Sadece `disallow_untyped_defs + check_untyped_defs` aktif, bu `--strict`'in parçasıdır ama tamamı değil.

`--strict` şunları içerir (aktive edildiğinde açılacak ek kurallar):
- `disallow_any_generics` → `List` yerine `List[str]` zorunlu
- `disallow_incomplete_defs`, `disallow_subclassing_any`, `disallow_untyped_calls`
- `no_implicit_optional`
- `warn_return_any`, `warn_unused_configs`
- `no_implicit_reexport`

### 3.2 Ölçülen Hata Sayıları (2026-04-22)

| Scope | Non-strict (mevcut config) | `--strict` tahmini* |
|-------|-----------------------------|---------------------|
| `pipeline/` (43 dosya) | 281 hata | **568** hata (89 dosya, clean cache ile doğrulandı) |
| `reconstruction/` (76 dosya) | 184 hata | **~450–520** hata (pipeline ratio × file count) |
| `decompilers/` + `analyzers/typeforge_adapter.py` (7 dosya) | 153 hata | **~280–320** hata |
| `core/` (15 dosya) | 281 hata (pipeline çapraz import ile aynı sayı) | **~450** hata |
| `stages.py` (mega-dosya) | (yukarıdaki dahil) | 80–120 hata |
| **TOPLAM KRİTİK SCOPE (strict clean)** | ~900 | **~1400–1800** |

*Strict tahminleri pipeline `568/281 ≈ 2.0x` oranına dayanmaktadır. Audit raporundaki "1193" sayısı muhtemelen bir ara konfigürasyon ölçümüdür; clean-cache strict ile bu doğrulanmalı.

### 3.3 Top-5 Hata Tipleri (strict pipeline clean sonucu)

| Hata kodu | Sayı | Anlamı | Fix zorluğu |
|-----------|------|--------|-------------|
| `[type-arg]` | 335 | `List`/`Dict` generic parametre eksik | DÜŞÜK (otomatize edilebilir, `List` → `List[str]`) |
| `[str]` | 64 | string interpolation type mismatch | ORTA |
| `[no-untyped-def]` | 59 | Fonksiyon imza eksik | ORTA (her fonksiyon manuel) |
| `[no-any-return]` | 39 | `Any` dönüş tipi, strict'te red | ORTA-YÜKSEK (return path'in gerçek tipini bulmak) |
| `[assignment]` | 33 | atama tipinde uyuşmazlık | YÜKSEK (logic implication) |
| `[unused-ignore]` | 16 | gereksiz `# type: ignore` | DÜŞÜK (sil) |

### 3.4 Audit "1193 hata" Söylemi ile Uyuşmazlık

- Bu ölçümde (clean cache, `--strict` tek scope):
  - `pipeline/` alone: 568
  - Tüm kritik 4 scope `--strict` clean çalıştırılırsa tahmini **1400–1800**
- Audit raporundaki 1193 rakamı muhtemelen **tüm karadul/** `--strict` ile (analyzers dahil) ölçüldü. Bu tutarlı: analyzers zaten 29 dosya + adapter katmanı.
- **Aksiyon:** Hafta 2 başında Developer **full-repo `mypy --strict --no-incremental karadul/`** çalıştırıp tam baseline'ı dondurmalı (`docs/migrations/mypy_baseline_2026_04.txt`).

---

## 4. mypy Strict Genişletme Scope

### 4.1 Scope Tablosu

| Scope | Dosya sayısı | Strict hata (tahmin) | Tahmini süre (fix) |
|-------|--------------|-----------------------|---------------------|
| `pipeline/` + `pipeline/steps/` | 43 | 568 | 24–40 saat |
| `reconstruction/` + `recovery_layers/` | 76 | ~500 | 30–50 saat |
| `decompilers/` + `analyzers/typeforge_adapter.py` | 7 | ~300 | 10–18 saat |
| `core/` (yarısı `pipeline` ile çapraz) | 15 | ~180 net | 6–10 saat |
| **TOPLAM** | 141 dosya | **~1550** | **70–118 saat** |

Süre hesabı: Ortalama 2-5 dakika/hata. Ama `[type-arg]` gibi kolay olanlar 30 saniye (search-replace), `[assignment]` hatalarının bazıları 15 dakika+ (logic değişikliği). 3 dakika/hata ortalama → 1550 × 3 dk = 77.5 saat ≈ **2 developer haftası** (1 developer, 40 saat/hafta).

### 4.2 En Sık Hata Tipi Fix Stratejisi

1. **`[type-arg]` (335 adet, pipeline)** → toplu fix. `sed`/pycharm inspection ile `List` → `List[Any]` veya daha iyisi `List[ConcreteType]`. **İlk pass, 4-6 saatte 300 hatayı indirir.**
2. **`[unused-ignore]` (16 adet)** → sil. 30 dakika iş.
3. **`[no-untyped-def]` (59 adet)** → her fonksiyonu manuel anote et. Yardımcı: `monkeytype` veya `pyannotate` ile runtime trace → ön-tahmin üretir. Ama pipeline test coverage sınırlı olduğundan manuel daha güvenli. 6-10 saat.
4. **`[no-any-return]` (39 adet)** → return path'i incele, gerçek tip belirt. 5-8 saat.
5. **`[str]` (64 adet)** → f-string formatı kontrol. 3-4 saat.
6. **`[assignment]` (33 adet)** → logic review, kısmen `cast()` ile geçici workaround. 4-6 saat.
7. **Kalan 20+ adet rare errors** → case-by-case. 4-6 saat.

**Toplam pipeline/ strict fix:** ~25-35 saat net. Reconstruction daha büyük, aynı oranla ~40-50 saat.

---

## 5. Öncelik Sırası (3 Faz)

### Faz 1 — Hafta 2, İlk Yarı (3 gün, ~24 saat)

Hedef: **Kritik silent except'in %80'i + mypy pipeline strict opsiyonel basit fix'ler.**

| İş | Miktar | Süre |
|----|--------|------|
| Silent except Type A (kritik scope) | 48 adet (pipeline/steps=3, recon=39, recovery_layers=0, core=5, dec=1) | 8–10 saat |
| Silent except Type C kritik scope (recovery_layers+recon) | 34 adet | 6–8 saat |
| `stages.py` 8 adet silent except → fix (önce review karmaşık kontroller) | 8 adet | 2–3 saat |
| mypy `[type-arg]` otomatik fix (pipeline + recon): `List[Any]`/`Dict[str, Any]` yama | ~400 hata | 4–6 saat |
| mypy `[unused-ignore]` toplu temizlik | ~30 hata | 1 saat |
| Her fix için test çalıştırma (3576 PASS bozulmamalı) | — | sürekli |
| **Faz 1 toplam** | **~490 silent + mypy fix** | **~24 saat** |

### Faz 2 — Hafta 2, İkinci Yarı (2 gün, ~16 saat)

Hedef: **Kalan kritik silent except + mypy pipeline/ strict = 0.**

| İş | Miktar | Süre |
|----|--------|------|
| Silent except Type B1 (core=4) | 4 adet | 1 saat |
| Silent except Type B2 (recon=2) | 2 adet | 0.5 saat |
| Kalan kritik Type A/C (yoksa — Faz 1 bitirmiş olmalı) | — | — |
| mypy pipeline/ strict `[no-untyped-def]` | 59 | 8–10 saat |
| mypy pipeline/ strict `[no-any-return]` + `[str]` | 103 | 4–6 saat |
| mypy.ini'ye `--strict = True` YAZ `[mypy-karadul.pipeline.*]` bloğuna | config | 10 dk |
| CI gate ekle: `pipeline/` strict fail = build fail | devops işi | 1 saat |
| **Faz 2 toplam** | | **~16 saat** |

### Faz 3 — Hafta 3 (Normal scope + kalan)

Hedef: **Normal scope silent except + mypy reconstruction/ + decompilers/ strict.**

| İş | Miktar | Süre |
|----|--------|------|
| Silent except NORMAL — analyzers/ | 55 adet | 12–16 saat |
| Silent except NORMAL — ghidra/ | 17 adet | 4–6 saat |
| Silent except diğer — deobfuscators/, computation/, cli/, quality/, config | 10 adet | 2–3 saat |
| mypy `reconstruction/` + `recovery_layers/` strict fix | ~500 hata | 20–30 saat |
| mypy `decompilers/` + `analyzers/typeforge_adapter.py` strict fix | ~300 hata | 10–15 saat |
| mypy `core/` strict fix | ~180 hata | 6–10 saat |
| mypy.ini'ye 4 scope için `--strict = True` bloklarını yaz | config | 30 dk |
| **Faz 3 toplam** | | **~55–80 saat (1.5–2 hafta)** |

---

## 6. Risk Analizi

| # | Risk | Olasılık | Etki | Mitigation |
|---|------|----------|------|------------|
| 1 | **Behavior change**: silent except fix'i yanlış exception yakalıyordu, şimdi propagate ediyor | ORTA | YÜKSEK | Her fix sonrası `pytest -x` çalıştır. Tek commit = max 10 silent except fix. Git bisect kolay olsun. |
| 2 | **Log spam**: DEBUG log'lar prod'da INFO/WARNING dolar | ORTA | DÜŞÜK | `logger.debug()` kullan (WARN değil). Pytest'te `caplog.set_level(INFO)` → DEBUG görünmez. Ama CI log toplama sistemi filtrelemeli. |
| 3 | **mypy strict aniden 1000+ hata** — developer motivation çöker | YÜKSEK | ORTA | **Kademeli**: scope-by-scope aç. İlk `pipeline/` → sonra `reconstruction/` → sonra `decompilers/`. CI'a "strict regression" check ekle (yeni hata eklenmesin). |
| 4 | **CI build time artar**: `mypy --strict` yavaş | ORTA | DÜŞÜK | Cache kullan (`.mypy_cache` volume). Paralel job'lara böl (scope başına ayrı job). |
| 5 | **Fixture test'ler silent except'e güvenmişse kırılır** (örn: parse fail → None dönme beklentisi) | DÜŞÜK-ORTA | ORTA | Fix öncesi `grep -r "== None\|is None" tests/` → hangi testler None bekliyor, kontrol. Behavior-preserving fix seç. |
| 6 | **`stages.py` mega-dosya riski** — 8 silent except'in fix'i 10242 LOC'luk dosyayı kırabilir | YÜKSEK | YÜKSEK | Architect'in D planındaki stages.py split'i (Hafta 2 sonu) beklensin; silent except fix'leri split sonrası yapılsın. Ya da önce güvenli 8 fix + yoğun test. |
| 7 | **Benchmark regresyon**: fix'ler naming F1'i düşürür (recovery counter'ı etkileyebilir) | DÜŞÜK | YÜKSEK | Hafta 2 başında baseline ölç (Tester raporu: F1=0.909). Her faz sonunda tekrar ölç. %5'ten fazla düşüş → rollback. |
| 8 | **Jython script'leri** (`karadul/ghidra/scripts/`) Python 2.7 → mypy hatası verecek | YÜKSEK | DÜŞÜK | `mypy.ini`'de `[mypy-karadul.ghidra.scripts.*] ignore_errors = True` ekle. Jython sunset v1.12.0 (DevOps + Gemini önerisi) sonrası kaldır. |

---

## 7. Bağımlılıklar ve Önkoşullar

1. **Benchmark CI gate aktif olmalı** — fix'ten önce. F1 threshold = mevcut 0.909 × 0.95 = 0.864.
2. **Logging config hazır** — `karadul/core/logging_config.py` zaten var. Tüm fix'lerde `logger = logging.getLogger(__name__)` pattern'i kullan.
3. **Developer alet takımı:**
   - `mypy 1.14.1` (kurulu, anaconda)
   - `ruff check --select E722,BLE001` (bare except + blind except warning)
   - `pytest` (3576 test pass baseline)
4. **Architect onayı**: `stages.py` split kararı bu plandan önce verilmeli.

---

## 8. Toplam Zaman Tahmini

| Faz | Kapsam | Süre |
|-----|--------|------|
| Faz 1 | Kritik silent except %80 + kolay mypy | 24 saat (3 gün) |
| Faz 2 | Kalan kritik silent + mypy pipeline strict = 0 | 16 saat (2 gün) |
| Faz 3 | Normal scope silent + mypy 3 scope strict | 55–80 saat (7–10 gün) |
| **Toplam** | | **95–120 saat ≈ 12–15 iş günü ≈ 2.5–3 hafta** (1 developer) |

Eğer 2 developer paralel çalışırsa (Gemini'nin "max 3 paralel ajan" kuralı dahilinde):
- Silent except → 1 developer (pattern'ler tekdüze, conflict riski düşük)
- mypy strict → 1 developer (scope-scope, conflict yok)
- **Paralel süre: ~1.5 hafta**

---

## 9. İleri Adımlar (bu plan onaylanırsa)

1. **Hafta 2 başı** (04-24):
   - [ ] Developer mypy baseline'ı donduruyor: `mypy --strict --no-incremental karadul/ > docs/migrations/mypy_baseline_2026_04.txt`
   - [ ] Silent except baseline'ı donduruyor: `/tmp/silent_except_audit.json` → `docs/migrations/silent_except_baseline_2026_04.json` (tam bilgi)
   - [ ] Benchmark baseline: F1=0.909 kayıt → `docs/migrations/benchmark_baseline_2026_04.json`
2. **Her faz sonu:**
   - [ ] Test suite yeşil (3576 PASS, 0 skip artışı)
   - [ ] Benchmark F1 ≥ 0.864
   - [ ] CHANGELOG'a sayaçlar: "silent except 99→0 kritik scope, mypy pipeline strict errors 568→0"
3. **v1.12.0 release kriteri (bu plan hedefi):**
   - Kritik scope silent except = 0
   - `pipeline/` + `core/` strict = 0 hata
   - Normal/Other scope silent except < 40 (v1.13.0 devri)

---

## 10. KABUL Edilmemesi Gereken Yanlış Yaklaşımlar

1. **"Tüm silent except'i tek PR'da fix edelim"** — HAYIR. 183 fix tek commit = regresyon garantili. 10–20 fix/PR max.
2. **"mypy'i tüm karadul/'da aynı anda açalım"** — HAYIR. Scope-scope. Önce `pipeline/`, yeşil olunca `reconstruction/`, vs.
3. **"`except Exception: logger.error(...)` yeter"** — HAYIR. Spesifik exception daraltmadan log eklemek code smell'i gizler.
4. **"Test eklemeye gerek yok, silent except zaten test edilmiyordu"** — HAYIR. Fix sonrası `raises(SpecificError)` tipi test eklenmeli, özellikle Type B1/B2 için (caller'ın None beklemesi doğru mu test edilmeli).
5. **"stages.py fix'i önce yapalım, split sonra"** — HAYIR. Architect'in split kararını bekle; 10242 LOC dosyada izole fix zor.

---

**Hazırlayan:** Reviewer agent (takım kod denetimi, 2026-04-22)
**Görüş birliği:** Architect, Developer, Tester, DevOps, Gemini ile `~/.claude/team-state/discussion.md` üzerinden uyumlu.
**Sonraki adım:** Berke onayı → Developer Faz 1 başlar.
