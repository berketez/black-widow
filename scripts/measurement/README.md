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

## 8. Mac (Mach-O) ölçüm hattı (plan v2 G3d)

ELF hattıyla aynı düzen, ayrı dosyalar. İsim kuralları (normalizasyon, jenerik isim,
strict/lenient) tek kaynaktan gelir: `function_f1.py`. Mac'e özgü olan yalnız GT okuma,
popülasyon, derleyici parçası sınıfları ve sonek kurallarıdır.

| Dosya | Görev |
|---|---|
| `macho_f1.py` | Puanlayıcı: GT (`nm`), popülasyon, sınıflar, sonek kuralları, P/R/F1 + %95 Wilson aralığı; ÖL-3 erişim sınıfları ve talimat ağırlığı (§8.6) |
| `macho_measure.py` | Orkestratör: `prepare` · `analyze` · `score` · `compare` · `all` |
| `macho_reach.py` | İsteğe bağlı erişim bölümü (`--reach`): isim bekleyenlerden kaçı çağrı zinciriyle kütüphaneye ulaşıyor. 15 Ekim `tarif/reach.py`'nin taşınmış hâli, sayıları aynı |
| `macho_corpus.json` | Korpus: özgün ikilinin yerel yolu + sha256, beklenen strip sha256'sı, Homebrew şişe kaydı, küme (`gelistirme` / `dogrulama`) |
| `tests/test_macho_f1.py`, `tests/test_macho_measure.py` | Birim testler (sentetik `nm` metni, Ghidra listesi, naming_map; strip/dyld_info/karadul sahte) |

```bash
# Tek komut: prepare + analyze + score; ikililer sırayla, ikili başına en çok 2400 sn
python scripts/measurement/macho_measure.py all --tree . --label taban-v2-$(git rev-parse --short HEAD) --reach
# Parça parça
python scripts/measurement/macho_measure.py prepare                     # özgün sha256 → strip → export trie → GT
python scripts/measurement/macho_measure.py analyze --tree . --label <etiket> [--only htop]
python scripts/measurement/macho_measure.py score --label <etiket> [--reach]
python scripts/measurement/macho_measure.py compare <A.json> <B.json>   # program sınıfı; kazanılan/kaybedilen TP, yeni/düzelen yanlış
# Tek koşuyu elle puanla (macho_score.json koşu dizinine; --out ile başka yere)
python scripts/measurement/macho_f1.py score --gt <gt.json> --run-dir <koşu>
```

Veri dizini depo içinde ama git dışı ve Spotlight dışı (`~/Black_Widow` Arama Gizliliği'nde);
`KARADUL_OLCUM_MAC_DIR` ile değişir. `~/karadul_olcum` kullanılmaz: Spotlight orayı dizinliyor.

```
workspaces/olcum_mac/
  corpus/<ad>/orig/<ad>        sembollü özgün (GT kaynağı; karadul'a hiç verilmez)
  corpus/<ad>/bin/<ad>         /usr/bin/strip'li kopya: karadul'un gördüğü TEK dosya
  corpus/<ad>/gt/<ad>.gt.json  GT + sınıflar + nm künyesi
  corpus/manifest.json         hazırlık künyesi: sha256'lar, strip sonrası export listesi,
                               araçların yolu/çözülen ikilisi/sha256'sı, CLT sürümü
  runs/<etiket>/session.json   ağaç (commit, kirli dosyalar; koşu sonunda yeniden), Ghidra, Python
  runs/<etiket>/<ad>/{ws,out,karadul.log,run.json,macho_score.json}
  results/<etiket>.json        tek sonuç tablosu (bütün sayılar buradan)
```

Koşu komutu ELF'tekiyle aynı: `python -m karadul analyze <strip'li> --skip-dynamic --output-dir
<koşu>/ws --output <koşu>/out`; cwd ve `PYTHONPATH` = `--tree`, `GHIDRA_INSTALL_DIR` = sabitlenen
kurulum. Varsayılan `--jobs 1` (makine paylaşılıyor). Ghidra sürümü ve yolu `karadul.config`
(`GHIDRA_PINNED_VERSION`, `GHIDRA_PINNED_DIR`) üzerinden `measure.py`'nin `ghidra_info` ve
`require_pinned_ghidra` işlevlerinden gelir; sabitlenen sürüm değilse `analyze` durur
(`--farkli-ghidra-izinli` ile bilerek açılır, raporda uyarı olarak kalır).

### 8.1 Tanımlar

- **GT**: `/usr/bin/nm -n -U <özgün>` çıktısındaki `T`/`t` sembolleri; `__mh_execute_header`
  hariç. Aynı adresteki adlar tek fonksiyondur (tmux'ta 2583 ad, 2572 adres: ortak gövdeli
  `*_RB_NEXT`/`*_RB_REMOVE` aileleri). Çok mimarili nm çıktısı reddedilir.
- **Popülasyon (isim bekleyen)**: GT'de olup strip'li kopyada Ghidra'nın thunk OLMAYAN ve
  jenerik adlı (kendisinin adlandıramadığı) fonksiyonları. Dışarıda kalanlar ayrı sayılır:
  `undetected_thunk` (Ghidra o adreste thunk görüyor; tek `b` komutlu sarmalayıcılar),
  `undetected_missing` (o adreste fonksiyon yok), `ghidra_known_from_exports` (adı Ghidra
  kendisi biliyor; Apple strip'te 0 beklenir, GT'nin %1'ini aşarsa uyarı).
- **Sınıf (`sinif`)**: `program` / `cold` (`.cold.N`, sıcak-soğuk bölme) / `outlined`
  (`OUTLINED_FUNCTION_N`, LLVM makine dışlayıcısı); kurallar `macho_f1.FRAGMENT_CLASS_RULES`.
  Başlık sayısı **program sınıfıdır** (plan v2 §4, "Payda"); parçalar ayrı satırda.
- **Sonek kuralları** (`macho_f1.SUFFIX_RULES`): `.cold.N`, `.llvm.<sayı>`, `.__uniq.<sayı>`,
  Darwin varyantı `$INODE64`/`$DARWIN_EXTSN`/`$NOCANCEL` eşleştirmede temel ada indirgenir;
  GT'ye ve tahmine simetrik. GCC ekleri zaten `normalize_name` (metrics FIX-4) içinde.
- **Durum**: `tp` / `wrong` / `unnamed`, strict kural ELF'le aynı; `lenient` = tp ya da
  `compare_name` exact/semantic/partial tutan yanlış. P = TP/(TP+yanlış), R = TP/popülasyon.
- **`macho_score.json`** = `{"summary", "rows"}`. `rows`'taki `addr, gt, pred, status, lenient`
  15 Ekim biçimiyle aynıdır (etiket araçları okuyor); yeni anahtar yalnız `sinif`. Özetteki eski
  anahtarlar (`tp`, `wrong`, `precision` …) 15 Ekim tanımıyla **bütün sınıfları birlikte** sayar;
  sınıf ayrımı `summary.siniflar`'da.
- **Geçerli koşu** (`score`): hedef türü Mach-O (`macho_binary`/`universal_binary`; üç kaynakta
  da: `out/report.json` identify, çalışma alanı `reports/report.json`, `raw/target_info.json`),
  analiz edilen dosyanın sha256'sı GT'nin strip'li kopyasıyla aynı, raporun `environment.ghidra`
  sürümü oturumla aynı, tek çalışma alanı. Geçersiz koşu tabloda nedeniyle görünür, toplamlara girmez.

### 8.2 Tuzaklar ve korumalar

| Tuzak | Koruma | Mutant |
|---|---|---|
| PATH'te `/opt/anaconda3/bin/strip` önde; conda strip export trie'yi bırakıyor (htop'ta 476, tmux'ta 1533 export) ve Ghidra bu adları okuyor | `STRIP_PATH = "/usr/bin/strip"`; göreli yol reddedilir | strip göreli yoldan |
| Strip sonrası export trie'nin boş olduğunu varsaymak | `xcrun dyld_info -exports`: `__mh_execute_header` dışında ad kalırsa ya da çıktı tanınmazsa hat durur, doğrulanmamış kopya silinir; ayrıca strip'li kopyada `nm -U` boş olmalı | denetim kapalı; kopya silinmiyor |
| PATH'te conda `nm` de önde | `NM_PATH = "/usr/bin/nm"` | nm göreli yoldan |
| Go yanlış tanıma: 15 Ekim'de htop `go_binary` sanıldı, Mac adımları koşmadı (0c9649e'de düzeltildi) | Hedef türü üç kaynaktan denetlenir; Mach-O değilse koşu geçersiz | denetim kapalı |
| Ghidra sürüm kayması | `require_pinned_ghidra`; karadul'a `GHIDRA_INSTALL_DIR` verilir; rapordaki sürüm oturumla karşılaştırılır | denetim çağrısı silindi; env verilmiyor |
| Yanlış özgün dosya | Korpustaki sha256 tutmazsa strip'e geçmeden durur; kaynak klasör silindiyse yalnız aynı sha256'lı önceki kopya kullanılır | sha256 denetimi kapalı |
| Test seti sızıntısı | Korpus yükleyici `test_seti_kura.py`'deki 25 programı (ana küme, yedekler, stres) ve `gelistirme`/`dogrulama` dışındaki kümeleri reddeder | kilit kapalı |
| Thunk ve Ghidra'nın bildiği ad paydada | Popülasyon dışı; ayrı sayaç | thunk sayılır; Ghidra adı popülasyonda |
| `.cold`/`OUTLINED` parçaları ve ekler | Sınıf kuralları ve sonek kuralları | dört ayrı mutant |
| Satır şemasının etiket araçlarını kırması | Eski anahtarlar sabit sırada | `lenient` yeniden adlandırıldı |
| Paralel ajanlar ağacı koşu sırasında değiştirir | Ağaç künyesi koşu başında ve sonunda alınır; değişen yollar kayda geçer. `karadul/` ya da çalışma zamanı verisi değiştiyse (iki uçta da kirli dosyada sha256 kıyası) koşu geçersiz, başka dosyalar değiştiyse uyarı | geçersiz sayılmıyor; motor yolu aranmıyor; porcelain satırı sabit ofsetle kesiliyor |

Mutation doğrulaması (2026-10-19): 21 mutantın 21'i yakalandı; her biri gerçek assertion
hatasıyla, kendi modülünün test dosyasında. Mutantlar `PYTHONDONTWRITEBYTECODE=1` ile koşuldu,
mutant uzunluğu özgünden farklıydı, geri yüklemede `touch` + `.pyc` silme (bayat bytecode tuzağı).

### 8.3 Sınırlar

- Popülasyon Ghidra'nın fonksiyon sınırlarına bağlıdır; Ghidra'nın thunk saydığı GT fonksiyonları
  paydada yoktur (`undetected_thunk`).
- `strict` kasıtlı olarak katıdır (eşanlamlı isim yanlış sayılır); P ve R alt sınırdır. Plan v2
  §4'teki "yakın isim" ve "yanlış isim" ölçütleri insan etiketinden gelir (G4), bu tablodan değil.
- Özgün ikililerin kaynağı yerel dosya: `workspaces/2026-10-15_oturum_scratchpad/macho/orig/`
  (git dışı). Homebrew Cellar'daki ikililer bunlarla bayt bayt aynı (2026-10-19); korpusta
  formül, sürüm ve şişe etiketi (`arm64_tahoe`) kayıtlı. `prepare`'in yaptığı kopya
  (`corpus/<ad>/orig/`) da sha256 denetimiyle yedek kaynak olarak kullanılır.
- Apple strip deterministik: 2026-10-19'da (CLT 27.0.0.0.1788430756) aynı özgünden iki kez
  soyulan kopyalar birbirinin ve 15 Ekim'de soyulan kopyaların bayt bayt aynısı çıktı. Strip
  sürümü değişip çıktı değişirse `prepare` uyarır (`expected_strip_sha256`); export trie
  denetimi yine zorunludur.

### 8.4 Eşdeğerlik: 15 Ekim puanlayıcısı

`macho_f1.py`, 15 Ekim koşularına (`runs_apple/{htop,tmux}`, aynı özgün ikililer) uygulandı.
Özetin 14 eski anahtarının hepsi ve satırların eski beş anahtarı **birebir aynı** (htop 597,
tmux 2561 satır). `macho_reach.py` da aynı cümleyi aynı sayılarla verdi. Fark yalnız yeni sınıf
ayrımında: tmux'ta 16 parça (15 `.cold.N`, 1 `OUTLINED_FUNCTION_0`) program sınıfından çıkıyor.

| tmux (15 Ekim koşusu) | popülasyon | isim | TP | yanlış | isimsiz |
|---|---|---|---|---|---|
| tümü (eski tanım) | 2561 | 871 | 105 | 766 | 1690 |
| program | 2545 | 857 | 104 | 753 | 1688 |
| cold | 15 | 13 | 1 (`grid_create.cold.1` ← `grid_create`) | 12 | 2 |
| outlined | 1 | 1 | 0 | 1 (`grid_check_clear`) | 0 |

Parçalara verilen 12 yanlış adın tamamı: `celldata`, `cellused`, `cellsize`, `extddata`,
`extdsize`, `flags`, `time`, `linedata`, `linedata_2`, `extdsize_extddata`, `cellsize_celldata`,
`cellused_cellsize` (`grid_check_is_clear.cold.1-9` ve `grid_free_line.cold.1-3`).

### 8.5 Taban v2 (makine kısmı): karadul 62ad154, Ghidra 12.1.2

`macho_measure.py all --tree ~/Black_Widow --label taban-v2-62ad154 --reach`, 2026-10-19
12:04–12:23, ikililer sırayla (htop 193 sn, tmux 924 sn). Sonuç: `workspaces/olcum_mac/results/taban-v2-62ad154.json`.

| ikili | GT | thunk | Ghidra biliyor | popülasyon (program) | isim verilen | TP | yanlış | isimsiz | P [%95] | R [%95] | F1 | lenient P | cold pop/isim/TP | outlined pop/isim/TP |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| htop 3.5.3 | 605 | 8 | 0 | 597 | 101 | 0 | 101 | 496 | 0,000 [0,000–0,037] | 0,000 [0,000–0,006] | 0,000 | 0,069 | 0/0/0 | 0/0/0 |
| tmux 3.8 | 2572 | 11 | 0 | 2545 | 857 | 104 | 753 | 1688 | 0,121 [0,101–0,145] | 0,041 [0,034–0,049] | 0,061 | 0,373 | 15/13/1 | 1/1/0 |
| geliştirme (mikro) | | | | 3142 | 958 | 104 | 854 | 2184 | 0,109 [0,090–0,130] | 0,033 [0,027–0,040] | 0,051 (makro 0,031) | 0,341 | | |

Künye: özgün sha256 htop `29449bae…f1158`, tmux `dfbb8c54…9998b`; analiz edilen (strip'li)
htop `50d172ce…0f1c3`, tmux `10fa0411…997b7` (karadul'un `target_info.json`'ıyla aynı). Hedef
türü iki ikilide de üç kaynakta `macho_binary`; çalışma alanı raporunda Ghidra 12.1.2
(`matches_pinned: true`). Koşu sırasında ağaca iki commit girdi (f530685, 15425fe), ikisi de
`karadul/` ve çalışma zamanı verisi dışında; uyarı olarak kayıtlı, koşu geçerli.

Okuma notları:
- Her iki ikilide de bütün satırların durumu 15 Ekim koşusuyla aynı; tahmin farkları (htop 2,
  tmux 45) yalnız `_N` tekilleştirme ekinin yer değiştirmesi. htop 15 Ekim'de `go_binary`
  sanılmıştı; bu koşuda Mac statik adımları koştu (`dylib_count`, `intel_*` istatistikleri var)
  ama hiçbir fonksiyonun adı değişmedi.
- htop'ta karadul'un verdiği 101 adın hiçbiri strict ölçütle doğru değil; 7'si lenient tutuyor.

### 8.6 ÖL-3: erişim sınıfları ve talimat ağırlığı

```bash
# Karadul'u yeniden koşmadan yeniden puanla; koşu dizinindeki macho_score.json ve eski sonuç kalır
python scripts/measurement/macho_measure.py score --label taban-v2-62ad154 --sonuc-etiketi taban-v2-62ad154-ol3
# Elle: tek koşu
python scripts/measurement/macho_f1.py score --gt <gt.json> --run-dir <koşu> --stripped <strip'li> --out <json>
```

Satırlara yalnız iki anahtar eklenir: `erisim` ve `talimat`. Erişim tablosu `summary.erisim_siniflari`'nda
ve yalnız program sınıfı içinde verilir. Parçalar (cold/outlined) ebeveynden dallanmayla girdiği için
tabloya alınmaz; satırlarında `erisim` yine yazılır.

**Yöntem**
- **`dogrudan`**: Fonksiyonun, koşunun `static/ghidra_call_graph.json`'ında en az bir çağıranı var;
  öz-kenar sayılmaz. Kenarlar, Ghidra'da fonksiyon girişine giden `isCall()` referanslarıdır
  (`karadul/ghidra/headless.py`, `_extract_call_graph`). `b` ile yapılan kuyruk çağrısı ve gövdenin
  ortasına giden çağrı kenar sayılmaz.
- **`tablo`**: Doğrudan çağıranı yok, ama strip'li ikilideki bir rebase fixup'ının hedefi tam olarak
  fonksiyon başı. Fixup'lar `xcrun dyld_info -fixups <strip'li>` ile okunur. Bu araç
  `LC_DYLD_CHAINED_FIXUPS` zincirlerini (ve klasik `LC_DYLD_INFO` rebase komutlarını) çözer; her yuvayı
  segment, bölüm, adres, tür ve hedef olarak yazar. Rebase hedefi mutlak sanal adrestir. Bind'ler dış
  semboldür, sayılmaz. Ghidra yeniden açılmaz.
- **`referanssiz`**: İkisi de yok.
- **Bağımsız kıyas (2026-10-19)**: Her rebase yuvasının 8 baytı dosyadan okundu ve
  `DYLD_CHAINED_PTR_64_OFFSET` biçimiyle (pointer_format 6; hedef = `__TEXT` + düşük 36 bit) çözüldü.
  dyld_info'nun hedefleriyle htop'ta 1250/1250, tmux'ta 5993/5993 yuva aynı çıktı. Bind yuvalarının
  hepsinde bind biti açıktı (220/220, 232/232).
- **`referanssiz` tanısı** (yalnız tanı, sınıfı değiştirmez; `/usr/bin/objdump -d` taraması):
  - *Kodda adresi alınan*: `adrp xN`'den sonra en çok 16 komut içinde `add xD, xN, #imm` ile, ya da
    `adr` ile adresi hesaplanan fonksiyon başları (geri çağırmalar). Yazmacı (`xN`/`wN`) yazan başka bir
    komut sayfa bilgisini siler.
  - *Kuyruk çağrısı*: Başka bir fonksiyonun içinden `b` ya da `b.cond` ile gidilen fonksiyon başları.
  - Pencere ölçümle seçildi. Sınırsız eşleştirme htop'ta `add x20, x20, #0x8` döngü artışını 2219 komut
    önceki `adrp` ile eşleyip yanlış pozitif üretiyordu; 4, 8 ve 16 komutluk pencereler aynı sonucu verdi.
- **Talimat (`talimat`)**: Ghidra fonksiyon gövdesi baytı (`getBody().getNumAddresses()`) / 4; yalnız
  korpusta `arch: arm64` olan ikililerde. Sınıf bloklarına sayıyla kapsam eklendi
  (isim verilen / popülasyon, Wilson aralığıyla). Yanına talimatla ağırlıklı üç oran geldi:
  kapsam (isim verilenlerin talimatı / popülasyonun talimatı), doğruluk (TP talimatı / isim
  verilenlerin talimatı) ve R.

**Taban v2 (karadul 62ad154; sonuç `results/taban-v2-62ad154-ol3.json`)**

| ikili | kapsam (sayı) [%95] | talimat kapsamı | P (sayı) [%95] | talimat doğruluğu |
|---|---|---|---|---|
| htop | 0,169 [0,141–0,201] | 0,454 | 0,000 [0,000–0,037] | 0,000 |
| tmux | 0,337 [0,319–0,355] | 0,598 | 0,121 [0,101–0,145] | 0,102 |
| geliştirme (mikro) | 0,305 [0,289–0,321] | 0,575 | 0,109 [0,090–0,130] | 0,089 |

| ikili | erişim | popülasyon | isim verilen | TP | yanlış | kapsam [%95] | P [%95] | talimat | talimat kapsamı | talimat doğruluğu |
|---|---|---|---|---|---|---|---|---|---|---|
| htop | dogrudan | 381 | 53 | 0 | 53 | 0,139 [0,108–0,177] | 0,000 [0,000–0,068] | 20813 | 0,415 | 0,000 |
| htop | tablo | 133 | 33 | 0 | 33 | 0,248 [0,182–0,328] | 0,000 [0,000–0,104] | 7628 | 0,472 | 0,000 |
| htop | referanssiz | 83 | 15 | 0 | 15 | 0,181 [0,113–0,277] | 0,000 [0,000–0,204] | 3899 | 0,628 | 0,000 |
| tmux | dogrudan | 1784 | 623 | 89 | 534 | 0,349 [0,327–0,372] | 0,143 [0,118–0,172] | 125283 | 0,577 | 0,106 |
| tmux | tablo | 450 | 153 | 9 | 144 | 0,340 [0,298–0,385] | 0,059 [0,031–0,108] | 26542 | 0,752 | 0,074 |
| tmux | referanssiz | 311 | 81 | 6 | 75 | 0,261 [0,215–0,312] | 0,074 [0,034–0,152] | 16853 | 0,517 | 0,127 |
| geliştirme | dogrudan | 2165 | 676 | 89 | 587 | 0,312 [0,293–0,332] | 0,132 [0,108–0,159] | 146096 | 0,553 | 0,095 |
| geliştirme | tablo | 583 | 186 | 9 | 177 | 0,319 [0,282–0,358] | 0,048 [0,026–0,089] | 34170 | 0,690 | 0,063 |
| geliştirme | referanssiz | 394 | 96 | 6 | 90 | 0,244 [0,204–0,288] | 0,062 [0,029–0,130] | 20752 | 0,537 | 0,099 |

`referanssiz` tanısı:

| ikili | referanssiz | kodda adresi alınan | kuyruk çağrısı | hiçbiri |
|---|---|---|---|---|
| htop | 83 | 55 | 2 | 26 |
| tmux | 311 | 201 | 0 | 110 |

Fixup sayımı:

| ikili | rebase | bind | hedefi fonksiyon başı olan rebase yuvası | gösterilen farklı fonksiyon |
|---|---|---|---|---|
| htop | 1250 | 220 | 268 | 150 |
| tmux | 5993 | 232 | 595 | 464 |

Okuma notları:
- Talimat kapsamı sayıyla kapsamdan yüksek (htop 2,7, tmux 1,8 katı): karadul büyük fonksiyonlara
  daha sık ad veriyor. Doğruluk ise talimatla ağırlıklandırınca düşüyor (tmux 0,121 → 0,102).
- tmux'ta tablodan çağrılanların strict P'si 0,059 [0,031–0,108], doğrudan çağrılanlarınki
  0,143 [0,118–0,172]; aralıklar örtüşmüyor.

**Sınırlar**
- **Çağrı grafı yalnız `isCall` kenarlarından oluşuyor.** Bu yüzden `referanssiz`'in çoğu gerçekte
  kodda adresi alınan geri çağırmalar: htop'ta 83'ün 55'i, tmux'ta 311'in 201'i. Sınıf, Ghidra'nın
  grafına bağlı bir ölçüdür. G9-G10'daki çağrı grafı onarımı (KS-2, TR-1) sınıfları değiştirir; eski ve
  yeni taban aynı tanımla kıyaslanmalı.
- **`tablo` yalnız tam fonksiyon başını gösteren rebase'leri sayar.** Ofsetli işaretçiler, göreli ofset
  tabloları (switch tabloları), ObjC/Swift meta verisi ve PAC'li (arm64e) işaretçiler denenmedi.
- **Kod taraması sezgiseldir.** Dallanmalar arası veri akışı izlenmez. Kuyruk çağrısında içeren
  fonksiyon, "başlangıcı komut adresinden küçük-eşit en büyük fonksiyon" kabulüyle bulunur; bitişik
  olmayan gövdede yanılabilir. Tanı sayıları sınıfları değiştirmez.
- **Talimat ağırlığı Ghidra'nın fonksiyon sınırlarına bağlıdır.** Gövde bitişik olmayan aralıkları
  içerebilir. `.cold` parçaları ayrı fonksiyon olduğu için ebeveynin talimatına girmez.
- **Ağırlıklı oranlar binom değildir;** Wilson aralığı yalnız sayıyla oranlarda verilir. Ağırlıklı
  oranlar için aralık gerekirse fonksiyon düzeyinde bootstrap yazılmalı (henüz yok).
- **İnsan etiketi yok:** strict P otomatik puandır. Plan v2 §4'teki "yakın/yanlış" oranları G4
  etiketlerinden gelir, bu tablodan değil.
