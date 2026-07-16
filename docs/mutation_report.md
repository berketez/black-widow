# Mutation Testing Raporu — Karadul

**Amaç:** "Yeşil test kanıt değil." Bir testin gerçekten bir mutantı (kasıtlı
bug'ı) ÖLDÜRDÜĞÜNÜ — yani mutant koda karşı KIRMIZI olduğunu — tekrarlanabilir
biçimde kanıtlamak. 5381 yeşil testten 7 gerçek bug geçmişti (commit `15f83f1`);
sebep, testlerin "kod çağrıldı mı"ya bakıp "doğru çıktı mı"ya bakmamasıydı.

## Harness: `scripts/mutation_probe.py`

Git-güvenli, hedefli mutasyon harness'i. Bir kaynak dosyaya tek bir mutant enjekte
eder (literal veya regex ile bir operatörü/sabiti değiştirir), SADECE ilgili testi
koşar, sonucu raporlar ve MUTLAKA kaynağı geri alır.

**Güvenlik (üç katmanlı geri alma):**
1. Orijinal baytlar belleğe alınır; her koşumun sonunda (`try/finally`) geri yazılır
   — crash / `KeyboardInterrupt` dahil.
2. `atexit` + `SIGINT`/`SIGTERM` handler'ları yarım kalan mutasyonu geri alır.
3. Dosya başlangıçta git-temizse ek olarak `git checkout -- <file>` ile de doğrulanır
   (commit'lenmemiş değişiklik varsa git checkout ATLANIR — bayt geri-yazımı yeter).
4. Geri alma sonrası dosya baytları orijinalle karşılaştırılır; uymazsa `error`.

**Terminoloji:**
- `killed`   — test mutant koda karşı FAIL etti → testimiz mutantı yakalıyor (İYİ).
- `survived` — test mutant koda karşı PASS etti → test deliği (KÖTÜ).
- `error`    — mutant uygulanamadı (find eşleşmedi / geri alma başarısız).

**⚠️ Bulunan+düzeltilen harness bug'ı — STALE `.pyc` tuzağı (2026-07-16):**
İlk sürüm kaynağı doğru geri alıyordu (`git status` temiz) ama mutant kod bir
subprocess tarafından import edilince CPython mutant'ı `__pycache__/*.pyc`'ye
yazıyordu (source-mtime = mutant zamanı). Kaynak AYNI saniye içinde ve AYNI
boyutta geri yazılırsa (ör. `0.4`→`0.7`, tek karakter) CPython'un mtime+size
geçerlilik kontrolü stale `.pyc`'yi taze sanıyor → **restore edilmiş temiz
kaynağa rağmen MUTANT davranış yükleniyor.** Tam suite'te `t5_med_threshold_raised`
mutantı `_severity_icon`'u kirletip 2 testi (biri mevcut) yanlışlıkla kırdı.
Düzeltme: (1) test subprocess'i `PYTHONDONTWRITEBYTECODE=1` ile koşulur (mutant
`.pyc` hiç yazılmaz), (2) restore sonrası modülün `.pyc`'si fiziksel silinir
(`_invalidate_pyc`). Doğrulama: spec koşumundan sonra `_severity_icon(0.55)`
tekrar `MED` döner (stale kirlilik yok). **Ders: "git temiz" ≠ "runtime temiz";
mutasyon harness'i bytecode cache'ini de invalide etmeli.**

### Kullanım

```bash
# Tüm mutant setini koş (docs/mutation_specs.json):
python scripts/mutation_probe.py --spec docs/mutation_specs.json

# Sadece bir grup (id virgülle):
python scripts/mutation_probe.py --spec docs/mutation_specs.json --id t2_gnulib_name_guard

# Tek seferlik (spec'siz):
python scripts/mutation_probe.py \
    --module karadul/reconstruction/c_comment_generator.py \
    --test  "tests/test_comment_offset_and_data_codeunit.py::test_offset_window_feeds_logic_error_consumer" \
    --find  "content[line_offset:line_offset + 500]" \
    --replace "content[line_offset:line_offset + 0]" \
    --expect killed
```

Çıkış kodu: tüm mutantlar beklentiyle (killed/survived) uyuşursa `0`, aksi halde `1`.
Mutant tanımları `docs/mutation_specs.json` içinde (list[dict]: `module`, `test`,
`find`, `replace`, `regex?`, `occurrence?`, `expect`, `desc`).

### Örnek koşum (bu cephe, 19 mutant)

```
$ python scripts/mutation_probe.py --spec docs/mutation_specs.json
== mutation_probe: 19 mutant ==
  t1_comment_offset_window_zero    OLDU     (beklenen killed) [BEKLENEN]
  ...
  t4_classic_sort_reverse          OLDU     (beklenen killed) [BEKLENEN]
== ozet: 19 killed, 0 survived, 0 error ==
```

---

## Geçmiş envanter (commit `15f83f1`, 2026-07-16)

İlk elle-hedefli mutasyon taraması: **6 kritik modül, 42 mutant, 23 hayatta kaldı
= %55 delik.** O tarama ad-hoc'tu (script kaydedilmedi — bu raporun ve
`mutation_probe.py`'nin varlık sebebi budur). Modül bazlı nitel özet (discussion
kaydından):

| Modül | En önemli HAYATTA KALAN (test deliği) |
|---|---|
| `c_namer` body_param | ptr ctx alt-sınırı (`>=3`→`>=2`), auto-param guard, min_confidence filtresi |
| `c_type_recoverer` overlap | **160x-şişme guard'ı HİÇ test edilmiyordu** (regex koruyordu), control-keyword guard |
| headless data-code-unit | (hepsi killed — testler sağlam) |
| `c_comment` offset | **testler gerçek fonksiyonu değil KOPYASINI (`_yeni_offsets`) test ediyordu** |
| packer report (md/sarif) | çoğu eşdeğer (tek-confidence `max==min`) / cross-file kapsanan |
| `stages` seed | gnulib + boilerplate recovery çağrıları seed testinde doğrulanmıyordu |

**Kapatılan 6 (commit `15f83f1`, `tests/test_mutation_gap_closures.py`):**

| Test | Öldürdüğü mutant |
|---|---|
| `test_ptr_two_offsets_is_buf_not_ctx` | c_namer ptr ctx `>= 3` → `>= 2` |
| `test_body_param_respects_min_confidence` | c_namer min_confidence filtresi kaldırma |
| `test_named_param_with_usage_not_renamed` | c_namer zaten-isimli param guard |
| `test_col0_else_if_actually_exercises_keyword_guard` | c_type_recoverer control-keyword (`fname=='if'`) guard |
| `test_nested_col0_definition_overlap_no_bloat` | c_type_recoverer overlap/160x guard (`func_start < last_end`) |
| `test_real_annotate_file_uses_correct_line_offset` | c_comment offset (kopya değil GERÇEK `_annotate_file`) |

→ 42 − 6 = **17 açık** (Cephe 2 girişinde).

---

## Cephe 2 (2026-07-16): 5 hedef, 19 mutant, hepsi killed

Kalan açıkların en değerli 5'ini davranış testleriyle kapattık. **Kaynak koda
SIFIR dokunuş** — sadece test eklendi (mutant kapatmak = test eklemek). Her mutant
`mutation_probe.py` ile "killed" olarak kanıtlandı (`docs/mutation_specs.json`).

### T1 — `c_comment_generator._annotate_file` offset penceresi + tüketen dallar

Delik: `content[line_offset:line_offset+500]` penceresinin genişliği ve onu tüketen
`_check_logic_pattern`/`_check_control_flow` dalları test edilmiyordu (offset
kapatılmış ama tüketiciler doğrulanmamış). Yeni testler GERÇEK `_annotate_file`'ı
pencere-bağımlı içerikle çağırır.

| Mutant id | Değişim | Öldüren test |
|---|---|---|
| `t1_comment_offset_window_zero` | `+ 500` → `+ 0` | `test_offset_window_feeds_logic_error_consumer` |
| `t1_comment_offset_window_50` | `+ 500` → `+ 50` | `test_offset_window_feeds_logic_error_consumer` |
| `t1_logic_error_return_branch` | `_logic_error_return` zengin dalı → fallback | `test_offset_window_feeds_logic_error_consumer` |
| `t1_null_check_goto_branch` | `_logic_null_check` goto dalı → jenerik | `test_offset_window_null_check_consumer_branch` |
| `t1_control_flow_forinf_comment` | control-flow yorumu → boş | `test_control_flow_branch_reached_and_emitted` |

### T2 — `stages._seed_recovery_pre_names` gnulib recovery

Delik: gnulib/boilerplate recovery çağrıları HİÇ test edilmiyordu — "gerçek kurtarma
0→8" (commit `7c83288`) düzeltmesinin regresyona en açık noktası. Yeni testler gnulib
UPSTREAM anchor'lı fixture .c dosyalarıyla GERÇEK `_recover_gnulib_from_fingerprints`
+ `_seed_recovery_pre_names`'i çağırır (GT-leakage yok).

| Mutant id | Değişim | Öldüren test |
|---|---|---|
| `t2_gnulib_name_guard` | `if name:` → `if not name:` (aday toplanmaz) | `test_string_fp_recovers_unique_names` |
| `t2_gnulib_unique_constraint` | unique-in-binary `!= 1` → `== 1` | `test_ambiguous_name_not_assigned_by_unique_path` |
| `t2_gnulib_prename_guard` | pre_name guard `is not None` → `is None` (main ezilir) | `test_does_not_overwrite_existing_prename` |
| `t2_gnulib_call_removed_from_seed` | seed helper'daki gnulib çağrısı → `pass` | `test_seed_helper_calls_both_main_and_gnulib` |

### T3 — `c_type_recoverer` brace-matching gövde sonu

Delik: bloat testleri sadece toplam ratio'ya bakıyordu; `body_end`'i hesaplayan
brace-matching'in SINIR davranışı (`depth==0` koşulu, for-else dalı) test
edilmiyordu. Yeni testler `body_end`'in replace kapsamını belirlediği için davranışla
kanıtlar.

| Mutant id | Değişim | Öldüren test |
|---|---|---|
| `t3_depth_eq_zero_to_ne` | `if depth == 0` → `!= 0` (ilk iç-`}`'te erken durur) | `test_brace_matching_nested_block_boundary` |
| `t3_for_else_body_end` | for-else `body_end=len(content)` → `body_start` | `test_brace_matching_unterminated_body_takes_rest` |
| `t3_depth_dec_to_inc` | `depth -= 1` → `+= 1` (depth hiç 0 olmaz) | `test_multiple_real_definitions_all_processed` |

### T4 — `c_namer._strategy_string_context` aday sıralama / ilk-seçim / eşik

Delik: agresif max-seçim (`conf > best`), 0.75 erken-dönüş eşiği (`>=`) ve klasik
`scored.sort(reverse=True); scored[0]` davranışsal test edilmiyordu. Yeni testler
GERÇEK `_strategy_string_context`'i çağırır. **Cephe 1b'nin Alg1/2a body-param
koduna DOKUNULMADI** (o kodun kendi enjeksiyon testleri var).

| Mutant id | Değişim | Öldüren test |
|---|---|---|
| `t4_aggressive_max_gt_to_lt` | `conf > best` → `conf < best` | `test_aggressive_max_selection_picks_highest_confidence` |
| `t4_aggressive_max_gt_to_ge` | `>` → `>=` (eşitlikte son adayı seçer) | `test_aggressive_tie_keeps_first_seen` |
| `t4_aggressive_075_ge_to_gt` | `if conf >= 0.75` → `> 0.75` (klasik fazladan aday) | `test_aggressive_075_threshold_blocks_classic` |
| `t4_classic_sort_reverse` | `scored.sort(reverse=True)` → `False` | `test_classic_scored_sort_picks_highest_score` |

### T5 — Packer raporu skor türetimi (`markdown_report._resolve_score`)

Delik: mevcut packer testleri TEK fingerprint kullanıyordu (`max==min`) → `max→min`
mutantı hayatta kalıyordu. Yeni testler iki farklı-güven fingerprint ile severity'nin
en YÜKSEK güvenden türediğini + eşik bantlarını kilitler.

| Mutant id | Değişim | Öldüren test |
|---|---|---|
| `t5_packer_score_max_to_min` | `max(confidences)` → `min` | `test_markdown_packer_score_is_max_of_confidences` |
| `t5_high_threshold_lowered` | severity `>= 0.7` → `>= 0.4` | `test_markdown_packer_medium_when_max_below_high` |
| `t5_med_threshold_raised` | severity `>= 0.4` → `>= 0.7` | `test_markdown_packer_medium_when_max_below_high` |

---

## Dürüst sınırlar / kapatılmayanlar (eşdeğer veya kapsam dışı)

Aşağıdakiler DELİK DEĞİL (eşdeğer mutant) ya da bu cephenin kapsamı dışı — dürüstçe
işaretlenir; sahte "kapattım" yazılmaz:

- **`c_type_recoverer` `body_end = i+1` → `i` (off-by-one): EŞDEĞER.** Tek fonksiyonda
  kapanış `}` yalnızca çıktı parçaları arasında yer değiştirir; nihai birleştirme aynı
  ve `}` hiçbir replace hedefi değil. Çok-fonksiyonda da normalde araya `\n` girdiği
  için overlap-guard değişmez. Test edilmedi (davranış değiştirmiyor).
- **`c_comment` `_check_control_flow(stripped, content)`'te `content` → `stripped`
  argümanı: pratikte EŞDEĞER.** Tek full_content-tüketen control-flow dalı `switch`
  (`_describe_switch`), ama o LOGIC katmanının `dispatch on` pattern'i tarafından
  gölgeleniyor ve control_flow'a hiç ulaşmıyor. Bu yüzden argüman mutantı davranış
  değiştirmiyor (belgelendi).
- **Disk-erişimi / TCC (commit `a21a0e4`): KAPSAM DIŞI.** Bu mantık tümüyle
  `ui/server.py` içinde (bu cephede DOKUNMA listesinde). Karadul çekirdeğinde
  (`karadul/`) disk-erişimi rapor-anahtarı yok; test edilecek çekirdek kod yok.
  Bu yüzden T5'in "disk-erişimi" kısmı yerine PACKER skor türetimi hedeflendi.
- **Orijinal 42-mutant enumerasyonu kalıcılaştırılmamıştı.** Bu cephe 5 öncelikli
  hedefe odaklandı (19 mutant). Kalan tarihsel survivor'lar (headless dışı modüllerin
  ikincil mutantları) bu spec'e henüz eklenmedi; `mutation_probe.py` + `mutation_specs.json`
  ile artık kademeli genişletilebilir.

---

## Tekrarlanabilirlik

```bash
# 1) Mutant seti (hepsi killed olmalı, exit 0):
python scripts/mutation_probe.py --spec docs/mutation_specs.json

# 2) İlgili test dosyaları (regresyon):
python -m pytest -q \
    tests/test_comment_offset_and_data_codeunit.py \
    tests/test_c_type_recoverer_bloat.py \
    tests/test_main_gnulib_seed_ordering.py \
    tests/test_report_packer_real_schema.py \
    tests/test_c_namer_candidate_selection.py
```

**Kanıt disiplini:** Yeni bir test eklerken önce mutant koda karşı koştur (KIRMIZI
olmalı), sonra temiz koda karşı (YEŞİL). `mutation_probe.py` bunu otomatikleştirir:
`expect: killed` olan bir mutant `survived` çıkarsa harness `[!! BEKLENMEYEN]` işaretler
ve exit 1 döner.
