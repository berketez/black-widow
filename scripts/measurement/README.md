# Fonksiyon-ismi ölçüm zemini (karadul)

Stripped Linux ELF'lerde karadul'un fonksiyonlara verdiği isimleri, **aynı build'in**
debug sembolleriyle adres bazında karşılaştıran ölçüm düzeneği. Taban: HEAD `2304560`
→ [`baseline_2304560.json`](baseline_2304560.json).

```bash
# Tabanı sıfırdan yeniden üret (worktree hazırsa; ~6 dk, 10 koşu, 2 paralel)
python scripts/measurement/measure.py all \
    --tree ~/karadul_olcum/baseline-2304560 --label baseline-2304560 \
    --out scripts/measurement/baseline_2304560.json
```

| Dosya | Görev |
|---|---|
| `function_f1.py` | **Tek puanlama kaynağı**: GT çıkarımı (debug ELF `.symtab`) + adres eşleme + P/R/F1 + kapsama |
| `measure.py` | Orkestratör: `prepare` (indir/aç/GT) · `analyze` (karadul'u bir ağaçtan koş) · `score` · `compare` · `all` |
| `corpus.json` | Sabit korpus: paket URL'leri + sha256, binary listesi |
| `baseline_2304560.json` | Taban sonuçları (binary başına metrik + fonksiyon başına durum) |
| `mutation_specs_function_f1.json` | Harness kurallarının mutation koruması (18 mutant) |
| `tests/test_function_f1.py` | Birim testler (sentetik GT + naming_map) |

Ölçüm verisi depo **dışında**: `~/karadul_olcum/` (`KARADUL_OLCUM_DIR` ile değişir).

```
~/karadul_olcum/
  downloads/                 .deb/.ddeb + açılmış halleri
  corpus/<korpus>/bin/<ad>   karadul'un gördüğü TEK dosya (stripped)
  corpus/<korpus>/debug/     GT kaynağı (karadul'a hiç verilmez; ayrı dizin)
  corpus/<korpus>/gt/        <ad>.gt.json
  runs/<etiket>/<korpus>/<ad>/{ws,out,karadul.log,run.json}
  results/<etiket>.json
  baseline-2304560/          HEAD 2304560 git worktree'si (A/B için SİLMEYİN)
```

## 1. Teşhis: eski GT neden 25 sembol?

Kısa cevap: **GT eksik değildi; payda yanlıştı ve binary LTO'lu.**

| İddia (2026-07-28) | Ölçülen gerçek |
|---|---|
| GT fonksiyonların ~%15'ini kapsıyor (22/146) | cat'te Ghidra'nın 147 fonksiyonunun **121'i thunk**: 60'ı `.plt` (59 import stub + PLT başlığı), 61'i Ghidra'nın EXTERNAL bloğunda 1 baytlık sahte fonksiyon. Kodda kalan 26 fonksiyonun **25'i GT'de** (%96). Dışarıda kalan tek fonksiyon `0x2d7c`'deki 4 baytlık `nop` hizalama dolgusu. Korpustaki 5 Ubuntu binary'sinde kapsama %96,2-97,6. |
| static (`t`) semboller yok | `cat.gt.txt`'nin 25 satırının **21'i `t`**. `.symtab` eksiksiz. |
| Neden bu kadar az? | Ubuntu coreutils **LTO ile** derleniyor: DWARF'ta `.text`'in tamamını kapsayan `<artificial>` LTRANS CU var; gnulib + `cat.c` birleşip inline oluyor → 16 program fonksiyonu + 9 CRT. Aynı kaynak sürümünün (9.4-3) LTO'suz Debian build'inde cat'te **97** fonksiyon sembolü var. |
| `DW_TAG_subprogram` = 0 | Tekrarlanamadı: pyelftools 0.32 `iter_DIEs` ve `llvm-dwarfdump` ikisi de **235** buluyor. Ama adresli (low_pc) 16 subprogram'ın **hiçbirinde doğrudan `DW_AT_name` yok** (LTO erken-debug DIE'sine `DW_AT_abstract_origin` ile bağlı); 159 isim `DW_FORM_GNU_strp_alt` ile dwz ek dosyasında (`/usr/lib/debug/.dwz/aarch64-linux-gnu/coreutils.debug`, ddeb'de var, `~/coreutils_gt`'ye kopyalanmamış); ilk CU yalnız `imported_unit` içeren `DW_TAG_partial_unit`. "İsimli + adresli subprogram" sayımı bu yüzden 0 çıkar. GT için DWARF gerekmiyor: `.symtab` yeterli. |
| "~22 sembol" | Eski SKIP filtresi (`mac_f1_eval.py`) sonrası cat'te **17** sembol puanlanıyordu (`legacy.gt_symbols`). |

Kaynak: `~/coreutils_gt/*.stripped`, `coreutils_9.4-3ubuntu6_arm64.deb` içindeki binary'lerle
**bayt-bayt aynı** (cat/cut/wc/expr/comm/head/tr/fold/paste/nl/join/fmt, sha256); `.debug`
dosyaları aynı sürümün dbgsym ddeb'inden (BuildID eşleşmesi). `.gt.txt` = bu dosyaların
GNU `nm` T/t satırları.

## 2. Korpus

Aynı upstream kaynak (GNU coreutils 9.4, arm64), iki build. Paketler `corpus.json`'da
sha256 ile sabit; her binary için debug dosyası `.build-id/xx/yyyy.debug` yolundan
**BuildID ile** bulunur ve `extract_gt` eşleşmeyi tekrar doğrular (uyuşmazsa hata).

| Korpus | Build | GT fonksiyonu (puanlanan) |
|---|---|---|
| `ubuntu-9.4-3ubuntu6` | Ubuntu 24.04, LTO **açık** | cat 25 (16) · cut 31 (22) · wc 41 (26) · expr 36 (27) · comm 32 (23) |
| `debian-9.4-3` | Debian snapshot, LTO **kapalı** | cat 97 (88) · cut 103 (94) · wc 122 (107) · expr 104 (95) · comm 109 (100) |

Ubuntu korpusu tarihsel ölçümlerle süreklilik içindir; **zengin GT Debian korpusudur**
(484 puanlanan fonksiyon; bir fonksiyon recall'u ~0,2 puan oynatır, Ubuntu'da ~0,9).

## 3. Tanımlar ve sahte-F1 korumaları

- **GT**: debug ELF `.symtab` → `STT_FUNC`/`STT_GNU_IFUNC`, yürütülebilir bölüm, adres≠0;
  aynı adresteki adlar tek fonksiyon (takma ad). Puanlanmayanlar (kapsamaya sayılır):
  CRT/linker (`_start`, `_init`, `_fini`, `call_weak_fn`, `(de)register_tm_clones`,
  `__do_global_dtors_aux`, `frame_dummy`, `atexit` …, açık liste) ve stripped binary'nin
  `.dynsym`'inden **ihraç edilenler** (wc'deki 6 `_obstack_*`: isim binary'de duruyor).
- **Tespit (kod)**: Ghidra fonksiyonlarından stripped binary'nin yürütülebilir, PLT olmayan
  bölümlerine düşenler. Ghidra adres ofseti ELF `e_entry` ile Ghidra `entry` fonksiyonundan
  türetilir (PIE'de 0x100000; sabit kodlanmaz).
- **Kapsama** = |GT ∩ tespit| / |tespit|.
- **Tahmin** = karadul `naming_map`'inin (workspace `reconstructed/src/naming_map.json`,
  `global`) o fonksiyona verdiği ad; anahtar olarak Ghidra adı **ve** `FUN_<adres>` denenir
  (karadul `entry`/`_FINI_0` fonksiyonlarını `FUN_` anahtarıyla yazıyor).
- **Jenerik (tahmin sayılmaz)**: `FUN_/sub_/thunk_FUN_/LAB_/DAT_/uVar…` yer tutucuları,
  Ghidra oto-adları (`entry`, `_INIT_0`), ve fonksiyonun **kendi adresini** taşıyan adlar
  (`leaf_2de0`, `read_fd_3144` — c_namer'ın `{rol}_{adres[-4:]}` geri dönüşü).
  `calls_nl_langinfo` gibi adres taşımayan adlar tahmindir (yanlışsa FP).
- **strict (birincil)**: TP ⇔ `normalize(tahmin) == normalize(GT)`; normalizasyon projenin
  tek kuralı `tests/benchmark/metrics.py::AccuracyCalculator._normalize` (FIX-4: `.constprop.N`,
  `.part.N`, `.isra.N`, `.cold`, `.lto_priv.N`, `.clone.N` soyulur; `_N` dedup eki soyulur).
  FP = jenerik olmayan yanlış tahmin. FN = puanlanan GT − TP (tespitsiz + isimsiz + yanlış).
  `P = TP/(TP+FP)`, `R = TP/|puanlanan GT|`. Yanlış isim **hem FP hem FN**'dir.
- **lenient (ikincil)**: aynı popülasyon, TP = `AccuracyCalculator.compare_name`
  exact/semantic/partial.
- **legacy**: eski `benchmark_runner` Mode 3 tanımı (GT dışı FUN_xxx "unverified", FN=yalnız
  isimsiz). Yalnız tarihsel köprü; A/B'de kullanmayın.
- **Toplama**: mikro (korpus içi TP/FP/GT toplanır) ve makro (binary F1 ortalaması).

| Tuzak | Koruma | Mutant |
|---|---|---|
| GT'de olmayan fonksiyonu TP sayma | Popülasyon GT'dir; GT dışı isimli fonksiyonlar yalnız `outside_gt` sayacında | `f1_outside_gt_counted_tp` |
| FUN_/adres etiketli adı "isimlendirilmiş" sayma | `is_generic_name` | `f1_generic_address_off`, `f1_generic_placeholder_off` |
| GT'yi isim kaynağı yapma (leakage) | karadul yalnız `corpus/<k>/bin/`'i görür; debug ayrı dizinde; `extract_gt` stripped değilse veya BuildID tutmazsa reddeder; koşu sonrası analiz edilen dosyanın sha256'sı GT ile karşılaştırılır; Ghidra bir GT fonksiyonunu kendisi isimlendirirse uyarı | `f1_buildid_guard_off`, `f1_strip_guard_off`, `f1_ghidra_leak_flag_off` |
| GCC sufiksleri | FIX-4 kuralı (metrics.py, tek kaynak) | `f1_suffix_normalize_off` |
| Thunk'ları paydaya katma | PLT + EXTERNAL hariç | `f1_plt_thunk_counted_as_code`, `f1_external_thunk_counted_as_code` |
| Ghidra'nın koyduğu adı karadul'a yazma | Tahmin yalnız naming_map; `fdadvise` gibi `b posix_fadvise` thunk'ının Ghidra adı tanı listesinde | `f1_ghidra_name_counted_as_prediction` |

Mutation doğrulaması (18/18 killed, her biri gerçek assertion hatasıyla):

```bash
python scripts/mutation_probe.py --spec scripts/measurement/mutation_specs_function_f1.json -v
python -m pytest -q tests/test_function_f1.py
```

## 4. Taban: HEAD 2304560 (Ghidra 12.1.2)

| Korpus | puanlanan | kapsama | TP | FP | FN | P | R | F1 mikro | F1 makro | lenient F1 |
|---|---|---|---|---|---|---|---|---|---|---|
| ubuntu-9.4-3ubuntu6 (LTO) | 114 | %97,1 | 41 | 16 | 73 | 0,719 | 0,360 | **0,479** | 0,490 | 0,503 |
| debian-9.4-3 (LTO'suz) | 484 | %99,1 | 35 | 51 | 449 | 0,407 | 0,072 | **0,123** | 0,124 | 0,154 |

Binary başına tablo ve fonksiyon başına durum: `baseline_2304560.json`. Tüm GT fonksiyonlarını
Ghidra buldu (`gt_detection_ratio` = 1,0 her binary'de).

Okuma notları:
- Ubuntu sayısı tarihsel "0,45-0,49" bandıyla uyumlu. Debian'da çöküş gerçek: LTO'lu
  yerleşime göre ayarlanmış gnulib parmak izleri LTO'suz yerleşimde yanlış fonksiyona
  düşüyor (`version_etc_arn ← version_etc`, `setlocale_null_r ← hard_locale`,
  `safe_write ← full_write`); her Debian binary'sinde `quote`/`quotearg` ailesinin 33
  fonksiyonunun ve `x*alloc` ailesinin ~20 fonksiyonunun hiçbiri isimlenmiyor. FP örnekleri
  string sabitinden türetilmiş adlar: `utf`, `ascii`, `argv_passed_through`,
  `general_help_using`, `memory_exhausted`.
- Tarihsel sayılar A/B için karşılaştırılabilir değildir (farklı tanım/GT); köprü için her
  binary'de `legacy` alanı var.

## 5. Tekrar üretme

**Worktree** (taban kodu; ana ağaçta başka ajanlar çalışıyor olabilir):

```bash
git worktree add ~/karadul_olcum/baseline-2304560 2304560
# karadul proje köküne (cwd) göre arar; git'e girmeyen çalışma zamanı verisi:
for n in sigs vendor signatures_homebrew.json signatures_homebrew_bytes.json sigs_macos_system.json; do
  ln -s "$PWD/$n" ~/karadul_olcum/baseline-2304560/$n
done
```

`measure.py analyze` koşudan önce `karadul`'un gerçekten `--tree` ağacından yüklendiğini
doğrular (yoksa durur), eksik çalışma zamanı verisini uyarır. Koşu komutu:
`python -m karadul analyze <bin> --skip-dynamic --output-dir <ws> --output <out>`,
cwd = ağaç, `PYTHONPATH` = ağaç, `GHIDRA_INSTALL_DIR` = `--ghidra`
(varsayılan `~/Library/BlackWidowBuild/ghidra_12.1.2_PUBLIC`, `KARADUL_MEAS_GHIDRA`).
Bir binary 15 dk'yı aşarsa öldürülür ve raporda "ÖLÇÜLEMEDİ" görünür.

**Parite kanıtı (worktree = HEAD 2304560 davranışı):** motor koruma A/B kaydının
girdileri olan `tests/fixtures/coreutils/binaries/stripped/{cat,cut,wc}` worktree'den
koşuldu → **146 / 156 / 180** fonksiyon (kayıtla aynı). Not: bu fixture'lar farklı bir
Ubuntu build'i (cat BuildID `5d7650c2…`, ne 9.4-3ubuntu6 ne 6.3); korpustaki Ubuntu cat
147 fonksiyon verir (Temmuz 11 koşusuyla aynı). Değişken sayısı kayıttan farklı
(cat 168 ↔ 172); kod o kayıttan bu yana 10 commit ilerledi, nedeni doğrulanmadı.

**Determinizm:** taban iki kez bağımsız koşuldu (`baseline-2304560` ve
`baseline-2304560-rerun`): 598 puanlanan fonksiyonun **hiçbirinde durum farkı yok**,
tüm metrikler aynı. Tek isim farkı expr'de iki fonksiyonun `non_integer_argument` /
`non_integer_argument_2` dedup ekinin yer değiştirmesi (normalizasyon `_N`'yi soyduğu için
metriğe etkisi yok). Ghidra 12.0_DEV ile iki cat de 12.1.2 ile fonksiyon başına aynı.

## 6. Aday ölçümü (A/B) — nasıl yapılır

Aday kod (ör. ana ağaç) **aynı komutla** ölçülür; taban koşuları tekrar gerekmez:

```bash
SHA=$(git rev-parse --short HEAD)          # kirli dosyalar raporda "dirty_files" olarak listelenir
python scripts/measurement/measure.py analyze --tree . --label aday-$SHA
python scripts/measurement/measure.py score --label aday-$SHA --out ~/karadul_olcum/results/aday-$SHA.json
# harness (function_f1.py / metrics.py) değiştiyse tabanı da AYNI harness ile yeniden puanla (koşu yok):
python scripts/measurement/measure.py score --label baseline-2304560 --out ~/karadul_olcum/results/baseline-2304560.json
python scripts/measurement/measure.py compare ~/karadul_olcum/results/baseline-2304560.json ~/karadul_olcum/results/aday-$SHA.json
```

`compare` binary başına ΔF1, kazanılan/kaybedilen TP fonksiyonlarını ve korpus başına
eşleştirilmiş işaret testi p-değerini (McNemar tam binom) verir; farklı harness parmak izi
veya Ghidra sürümü varsa uyarır. Kararı ΔF1'e değil, **Debian korpusunun kazanılan/kaybedilen
listesine** bakarak verin; Ubuntu korpusu küçük (114 fonksiyon).

Kurallar: aynı Ghidra; aynı `corpus.json`; en fazla 2 paralel koşu (`--jobs`); iyileştirmeyi
gördükten sonra harness kuralını (jenerik listesi, eşanlam tablosu) değiştirmeyin — değişirse
iki tarafı yeniden puanlayıp iki sayıyı birlikte raporlayın.

## 7. Sınırlar / riskler

- **Tek mimari/tek program ailesi:** arm64 + coreutils 9.4. x86-64 veya başka projeye genelleme
  ölçülmedi. Debian korpusu karadul'un ayarlandığı binary'ler değil (iyi: ezber riski düşük),
  ama gnulib ağırlıklı.
- **Çapraz-binary önbellek** (`~/.cache/karadul/cfg_cache`, HOME'a sabit, env ile izole
  edilemiyor): karadul oradaki başka binary'lerin isimlerini aday olarak aktarabiliyor.
  Bu koşular önbelleğe yazmadı, hiçbir koşuda `cross_binary_candidates` oluşmadı; yine de her
  koşu öncesi önbellek içeriği `run.json`/rapor `cfg_cache_before`'a yazılıyor, oluşursa
  `score` uyarır.
- **Değişken isimleri deterministik değil:** aynı iki koşuda `per_function` değişken
  eşlemelerinin 894/2275'i farklı (883'ü yalnız `_N` numaralandırma sırası). Bu harness
  yalnız fonksiyon adını ölçer; değişken-adı A/B'si için ayrıca normalizasyon/determinizm gerekir.
- **Ghidra'nın kendi adları** (`fdadvise` → `posix_fadvise` thunk adı) karadul çıktısında
  görünür ama tahmin sayılmaz; kullanıcıya görünen yanlış ad olarak ayrıca `ghidra_thunk_named`
  listesinde durur.
- `strict` eşleşme kasıtlı olarak katıdır (eşanlamlı isim FP sayılır); rapor edilen F1 bir alt sınırdır.
- **Taban `--output-dir` ile alındı; bu FLIRT'ü ve `sigs/ngram_name_db`'yi kapatır.** CLI
  `--output-dir` verilince `project_root`'u çıktı dizinine çeviriyor, imza/n-gram verisi o kökten
  aranıp bulunamıyor (2026-09-25 FLIRT bulgusu, commit 93dc480). Bu, arayüzün gerçek davranışıdır
  (arayüz her analizi `--output-dir` ile başlatır); yani taban "kullanıcının aldığını" ölçer. Depo
  kökünden `--output-dir`'siz CLI koşusu FLIRT'ü açar ve farklı sonuç verir. Veri kökü sorunu
  çözülünce taban yeniden koşulmalı; iki koşuyu karıştırma.
