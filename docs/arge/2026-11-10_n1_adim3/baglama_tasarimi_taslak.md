# N1 adım 3: KS-1'in ürüne bağlanması, susturma ve güven etiketi — tasarım taslağı

- **Tarih:** 2026-11-10.
- **Durum:** TASLAK. Yalnız belge; kod, test ve betik değişmedi. Ana oturum inceleyip karara bağlayacak.
- **Kör yazıldı:** adım 2'nin (`ks1_olc.py olc`) GT'li sonucu görülmeden yazıldı. Satır kararlarına bağlı her kural bu yüzden parametreli (§2.5). Sonuç dosyaları (`ks1_olcum.*`) belge biterken ağaçta belirdi; açılmadı.
- **Plan:** v2.2 §3 N1 (`docs/arge/2026-10-21_plan_v2_2.md:70`), §2 "eşik son çıktıda" (`:55-58`), §2 dosya sahipliği (`:59-62`), G12 (`:139`), G26 (`:152`), §10 (`:217`).
- **Dayanak:**
  - KS-1 kesin ön kaydı, commit a22d833 (`docs/arge/2026-10-21_g11_n1/ks1_onkayit.md` §8, §10). Sapma kaydı 1 (commit 0da58cf, `ks1_sapma_1.md`) bu belge yazılırken girdi; içeriği okunmadı.
  - N0b ön kaydı ve tablosu (`docs/arge/2026-10-21_g10_n0b/alt_kanal_onkayit.md` §5-§6, `kesinlik_tablosu.md:66-70`).
  - N2 taslağı (`docs/arge/2026-10-21_n2_onkayit_taslak.md:108-113, 232-241, 371`): N2, adım 3'ün köken kaydını donuk `alt_kanal.py` ile okuyacak.
- **Karar bekleyen maddeler:** **[seçim]** diye işaretli; özet §7'de (26 madde).
- **Satır numaraları:** HEAD 0da58cf'ye göre. Ağaç bu belge yazılırken iki kez ilerledi (`ks1_olc.py` değişti); uygulamadan önce yeniden bakılmalı.

## 0. Özet

**Beş tasarım kararı:**

| # | Karar | Gerekçe (tek cümle) |
|---|---|---|
| 1 | KS-1 adları `pre_names` kanalından girer; çıkarım Faz 1'de ayrı bir adımdır, köken ve etiket anahtarı aynı olan bir yan sözlükle (`pre_name_meta`) taşınır | `pre_names` c_namer'da her adayı yener ve puanlayıcının okuduğu `reconstructed/src/naming_map.json`'a düşer; başka kanal fiilen yok (§1.2) |
| 2 | Susturma c_namer'ın ana sürecinde, adaylar toplandıktan sonra ve seçimden önce tek bir süzgeçtir; `_strategy_string_context` değişmez | Strateji tek dizgi seçmeyi sürdürdüğü için "sonraki dizgiye geçme" kendiliğinden imkânsızdır; donuk N0b testleri de yeşil kalır (§3) |
| 3 | Alt kanal tanımı ürüne kopyalanır (`tarif/alt_kanal.py`), ölçüm betiği donuk kalır, eşitlik testle kilitlenir; köken şeması sürüm 1'de kalır, yalnız alan eklenir | N2 ön koşulu donuk `alt_kanal.py`'yi (sha256 `d0e6f544…`) yeni ürünün köken kaydı üzerinde koşturacak; betik şema 1 dışını reddediyor (`alt_kanal.py:678`) |
| 4 | Eşik ve etiket tek yerde, c_namer'ın seçim döngüsünde kesinleşir; biçimlendirici yalnız taşır ve `1.0` yazmayı bırakır | c_namer adı C metnine doğrudan yazıyor; sonradan geri alınamaz (§1.3). 0,7 eşiği bugün hiçbir yerde uygulanmıyor |
| 5 | Davranış tek bir "aç" commit'inde değişir; ondan önceki her commit bayraklar kapalıyken HEAD ile aynı ad haritasını üretir | Tehlikeli dört dosya tek elden ve ikiye bölünebilir biçimde değişir; GT'siz regresyon kapısı kurulabilir (§5, §6.4) |

**İş yükü (dürüst tahmin):** üretim kodu ≈ 900 satır, test ≈ 1 600 satır, ≈ 50 mutant; tek elden 2-3 iş günü. Plan G12 bu işe bir gün ayırıyor (`plan_v2_2.md:139`); takvim kayar (§5.5).

## 1. Bugünkü akış

### 1.1 Canlı yol (step registry)

`use_step_registry=False` verilse de yol zorla step registry'ye çevrilir (`karadul/stages.py:3051-3064`). Aşağıdaki tablo bir fonksiyon adının izlediği gerçek yoldur.

| # | Adım | Dosya:satır | Ne olur | Güven ve köken |
|---|---|---|---|---|
| 1 | Faz 1 koşucusu | `stages.py:3074-3105` | 17 adım; `extracted_names` üretilir (`:3146`) | Ad → ad sözlüğü; kaynak bilgisi yok |
| 2 | Faz 1 ön adları | `pipeline/steps/confidence_filter.py:70-126`, `_confidence_helpers.py:209-223, 258-274` | BinaryNameExtractor, byte pattern, CAPA adları boş yuvalara girer | Hangi kaynaktan geldiği sözlükte tutulmaz |
| 3 | Kurtarma tohumları (1. çağrı) | `stages.py:3171-3174` → `:2574-2603` | Sıra: `main` (`:2605`, var olanı ezer `:2657`), gnulib (`:2666`, boş yuvaya `:2730-2732`), ELF önyükü (`:2843`), elle (`:2914`, ezer `:2965`) | Tür yalnız `stats` sayaçlarında (`main_recovered`, `gnulib_recovered` …) |
| 4 | Faz 2 koşucusu | `stages.py:3184-3192` | `feedback_loop`, `computation_struct_recovery`, `struct_recovery`; tohumlu sözlük `seed_artifacts` ile geçer | — |
| 5 | c_namer kurulur | `pipeline/steps/feedback_loop.py:260-263` | `CVariableNamer(pc.config)`: eşik öntanımlı 0,15 (`reconstruction/c_namer.py:1657`) | Ürün eşiği (0,7) verilmez |
| 6 | Aday üretimi | `c_namer.py:1821-1877` (işçi havuzu), `:1611-1620` (strateji sırası) | Fonksiyon başına 10 strateji; `string_context` en çok iki aday üretir: agresif (`:2884-2897`) ve klasik (`:2937-2947`) | Aday güveni, stratejisi, kanıtı aday nesnesinde (`:112-133`) |
| 7 | Ön adlar | `c_namer.py:1915-1936` | `pre_names` önce yazılır; ad `_sanitize_c_name`'den geçer (`:1920-1921`); aynı ad ikinci kez gelirse sessizce atlanır (`:1922`) | **Kayıp 1:** hepsi `binary_extract`, güven 0,95 (`:1928-1929`) |
| 8 | Seçim | `c_namer.py:1944-2021` | En yüksek güvenli aday; 0,15 altı elenir (`:1952`); genel adda yapısal süzgeç (`:1975-1980`); ön adı olan atlanır (`:1983-1986`); çakışmaya ek (`:1990-1995`) | Güven ve strateji `confidence_map`, `strategy_map`'te (`:2003-2004`) |
| 9 | Metne uygulama | `c_namer.py:2051-2080` | Genel harita bütün dosyalara, yerel harita kendi dosyasına; çıktı `reconstructed/src/` | **Geri dönüş yok:** `FUN_x` yazısı metinden silinir |
| 10 | Harita ve köken | `c_namer.py:2083-2095`, `:2102-2122` | `src/naming_map.json` (`global`, `per_function`) ve `src/naming_provenance.json` | Köken kaydı tam: strateji, kanıt, güven, rakipler (`:205-369`) |
| 11 | NameMerger adayları | `pipeline/steps/_feedback_naming_candidates.py:393-432` | Ön adlar 0,85 `binary_extractor`; c_namer adları gerçek güvenle | — |
| 12 | NameMerger | `pipeline/steps/_feedback_naming_merger.py:65-68, 106-107` | Eşik `unk_threshold` 0,30 (`reconstruction/name_merger.py:207, 237`; `config.py:396`). `min_confidence` (0,7) yalnız saklanır (`name_merger.py:199-206`) | **Kayıp 2:** 0,7 burada uygulanmıyor |
| 13 | `merged/` | `_feedback_naming_merger.py:144-208` | Aho-Corasick `src/` dosyalarına uygulanır (`_feedback_naming.py:121-129` dizini `src/`'ye çevirir). `FUN_x` yazısı kalmadığı için değişiklik olmaz | `merged/` = `src/` |
| 14 | Yineleme 1 | `feedback_loop.py:105-137`, `_feedback_naming.py:245-268` | c_namer alt küme üzerinde yeniden koşar; çıktı `src_iter1/` (harita ve köken yeniden yazılır) | İstatistikler ezilir (`_feedback_naming.py:291-293`) |
| 15 | Faz 3 | `stages.py:5097-5109` | `semantic_naming` … `project_build`; ürün ağacı `reconstructed/project/` (`pipeline/steps/project_build.py:50-56`) | — |
| 16 | Biçimlendirici: kaynak | `core/output_formatter.py:256-260` | `project/` ağacı `out/src/`'ye kopyalanır | — |
| 17 | Biçimlendirici: harita | `output_formatter.py:605-660` | `src/naming_map.json` ve `src_iter*/naming_map.json` `global` bölümleri okunur; son yineleme kazanır (`:619-631`) | **Kayıp 3:** her ada `"source": "c_namer", "confidence": 1.0` (`:651-657`); köken kaydı hiç okunmaz |
| 18 | Rapor | `output_formatter.py:731-784` | `report.json` aşama istatistiklerini taşır (`naming_by_strategy`, `naming_high_confidence`) | Ad başına bilgi yok |
| 19 | Arayüz: liste | `ui/server.py:120-122, 212-224` | Fonksiyon listesi `reconstructed/src/naming_map.json` `global`'den | Güven ve köken yok |
| 20 | Arayüz: kanıt kartı | `ui/server.py:360-380, 569-574`; `ui/index.html:1168, 1189-1199` | Köken `clean/naming_map.json`'dan: `source` ve `confidence` | **Kayıp 4:** kullanıcı `c_namer · 1.00` görür |

### 1.2 Fiilî öncelik

- `pre_names` > c_namer adayı > gerisi. Kanıt: `c_namer.py:1983-1986` (ön ad varsa aday atlanır) ve satır 13 (NameMerger metni değiştiremiyor).
- Ölçüm (salt okur sayım, `ol7-c-b7faeac` tmux): `merged/` ile `src/` 2 821 dosyanın 2 821'inde bayt bayt aynı.
- Puanlayıcılar `reconstructed/src/naming_map.json` `global`'i okur (`scripts/measurement/function_f1.py:417`; `scripts/measurement/README.md` "Tahmin" maddesi). Yani ölçülen şey c_namer'ın yineleme 0 haritasıdır.
- Sonuç: KS-1 adı ancak `pre_names`'ten girerse hem metne hem ölçülen haritaya düşer. `run_tarif`'i ürün kodunda (`karadul/`) paket dışından çağıran yok; çağıranlar yalnız `tests/test_tarif.py:12` ve iki ölçüm betiği (`scripts/measurement/tarif_olc.py:24`, `llm_pilot.py:1096`).

### 1.3 Güvenin ve kökenin kaybolduğu yerler

| # | Yer | Ne kayboluyor | Kanıt |
|---|---|---|---|
| K1 | `c_namer.py:1928-1929` | Ön adın türü (main, gnulib, önyük, elle, Faz 1). Hepsi `binary_extract` / 0,95 | 119 çalışma alanında 1 431 `FUN_` ön adı tek etiketle |
| K2 | `name_merger.py:199-207` | Ürün eşiği. `min_naming_confidence` (0,7; `config.py:472`) hiçbir karara girmiyor | Aşağıdaki sayım |
| K3 | `output_formatter.py:651-657` | Gerçek güven, strateji, kanıt. Hepsi `c_namer` / 1.0 | tmux Mac ürün haritası: 1 145 `c_namer` adının 1 145'i 1.0 |
| K4 | `ui/server.py:572` | Arayüze yalnız `source` ve `confidence` geçiyor | `ui/index.html:1199` `_fmtConf` → `1.00` |
| K5 | `c_namer.py:1920-1922` | Ön adın yazımı ve varlığı: temizleme adı değiştirir, aynı ad ikinci anahtarda sessizce düşer | §2.4 |
| K6 | `output_formatter.py:619-631` ile `ui/server.py:122` | Tutarlılık: biçimlendirici son yinelemeyi, arayüz listesi ve puanlayıcı ilk yinelemeyi okuyor | 119 çalışma alanında 14 adın eki farklı, 8 ad yalnız yineleme 1'de |

**Eşik sayımı** (GT'siz; 117 Debian + 2 Mac çalışma alanının `reconstructed/src/naming_provenance.json` dosyaları):

| Anahtar öneki | Kaynak / strateji | Kayıt | Güven < 0,7 |
|---|---|---|---|
| `FUN_` | aday / `string_context` | 4 967 | 0 |
| `FUN_` | `pre_names` / `binary_extract` | 1 431 | 0 |
| `FUN_` | aday / `api_param_reverse` | 56 | 0 |
| `DAT_` | aday / `dataflow` | 9 217 | 9 217 (hepsi 0,30) |

- 0,30 güvenli 9 217 `DAT_` adının hepsi üründe ve `1.0` ile gösteriliyor (tmux Mac 269/269, htop Mac 104/104 ürün haritasında aynı adla).
- Bu adlar `global_<adresin son dört hanesi>` biçimindedir (`c_namer.py:3345-3351`). Bilgi taşımaz; adresi kısalttığı için bilgi kaybettirir.
- Geliştirme setinde 0,15-0,7 arasında hiç `FUN_` adı yok. Bu yüzden eşiğin uygulanmaması bugüne kadar fonksiyon adı ölçümlerini değiştirmedi.

### 1.4 Ölü ve yarı ölü yollar

| Yer | Durum | Not |
|---|---|---|
| `stages.py:3226-3283` (`else` dalı) | Ölü | `_use_step_registry` her zaman `True` (`:3064`) |
| `stages.py:3486-3494` | Ölü amaçlı | c_namer yalnız aşağıdaki ölü döngü için kurulur |
| `stages.py:3513-4763` (monolith döngüsü) | Ölü | `_loop_iterations = 0` (`:3513`). İçindeki `analyze_and_rename` (`:3719-3722`), NameMerger (`:4037-4330`) ve elle adın koşulsuz zorlanması (`:4262-4267`) hiç çalışmaz |
| `stages.py:3291-3295` (tohum, 2. çağrı) | Canlı, etkisiz | Korumalar yüzünden ikinci çağrı değişiklik yapmaz |
| `stages.py:4766` | **Canlı ve zararlı** | Ölü döngünün sayacı canlı istatistiği eziyor: bütün koşularda `pipeline_iterations_run: 0`, oysa `src_iter1/` var |
| `stages.py:4961-5037` | Canlı | Step yolunda da çalışıyor; `struct_recovery` adımıyla çift koşup koşmadığına bakılmadı (doğrulanmadı, kapsam dışı) |
| `_feedback_naming_parallel.py:21-41` | Fiilen ölü | `CVariableNamer`'da `rename_c_file` ve `extract_names_from_file` yok; bayrak açılsa da seri yola düşer |
| `core/report_generator.py:711-738` | Canlı, eksik | HTML raporun ad tablosu c_namer adlarını hiç göstermiyor (yalnız `binary_names` ve `signature_matches`) |

Adım 3 ölü yollara dokunmaz. Yalnız şunu bilerek yapar: `stages.py:3719-3722`'deki ölü çağrı yeni parametreleri almaz.

## 2. KS-1'in bağlanma noktası

### 2.1 Adım ve girdi

- **Yeni adım:** `kesin_anchors` (yeni dosya `karadul/pipeline/steps/kesin_anchors.py`), Faz 1 listesine eklenir (`stages.py:3074-3104`, `ghidra_metadata`'dan sonra). **[seçim 4]**
  - `requires=["functions_json_path"]` (sıra `ghidra_metadata`'dan sonraya düşsün), `produces=["kesin_anchors"]`.
  - Bayrak kapalıysa işlem yapmaz; çıktı `{"durum": "kapali"}`.
  - Gerekçe: tohum fonksiyonu iki kez çağrılıyor (`stages.py:3172, 3293`); çıkarım bir kez yapılıp sonuç saklanmalı. Adım ayrıca süre ve hata kaydını öbür adımlarla aynı biçimde tutar.
- **Girdi:** `workspace.get_stage_dir("static")`, yani ölçümdeki dizinin aynısı (`scripts/measurement/ks1_olc.py:414`, `ks1_onkayit.md` §2).
  - c_namer JSON'ları `deobfuscated/`'tan okur (`pipeline/steps/ghidra_metadata.py:94-104`); KS-1 için bu yol kullanılmaz. Ölçülen girdi `static/`'tir.
- **Çağrı:** `kesin.load_static(static_dir)` → `kesin.extract(inp)` (`karadul/reconstruction/tarif/kesin.py:233, 783`). Türler öntanımlı (`ALL_TYPES`), ölçümle aynı.
  - Tür listesi daraltılmaz: daraltılırsa K3 (gövdede tek ad) başka sonuç verir ve çapa kümesi ölçülenden ayrılır (`kesin.py:785`).
  - `load_static` ayrıca çağrılır, çünkü anahtar için fonksiyon adı gerekir (§2.2); `extract_anchors` bunu dışarı vermiyor.
- **`kesin.py` değişmez.** Sha256'sı ön kayıtla sabit (`ks1_sabitler.json`; dokuz dosya; sapma kaydı 1'in ayrı sabitleri `ks1_sapma_1_sabitler.json`'da). Bağlama mantığı yeni bir modüldedir: `karadul/reconstruction/tarif/baglama.py`.
- **Hata davranışı:** girdi eksikse, platform desteklenmiyorsa ya da çıkarım hata verirse hat düşmez; `stats["ks1_status"]` şu değerlerden birini alır: `ok`, `kapali`, `girdi_eksik`, `desteklenmeyen_platform`, `hata`.
- **Yan çıktı:** `reconstructed/kesin_capalar.json` (çapalar, satırlar, etiketler, atlananlar ve nedenleri). GT değildir; ürünün kendi kanıt dökümüdür.

### 2.2 Anahtar

- `pre_names` anahtarı Ghidra'nın o anki fonksiyon adıdır. Çapa adresinden (`Anchor.address`) `inp.functions[adres].name` ile bulunur.
  - Adresten `FUN_%08x` kurulmaz: Ghidra'nın adlandırdığı fonksiyonda bu anahtar metinde geçmez. Bugünkü önyük ve gnulib çağrı şekli tohumları bunu yapıyor (`stages.py:2771, 2884`); ölçüm README'si de not ediyor.
- **Yalnız `FUN_<onaltılık>` anahtarlı çapalar ad alır.** **[seçim 5]**
  - KS-1 `entry`, `thunk_FUN_`, `_INIT_n`, `_FINI_n`, `LAB_`, `SUB_` adlarını da jenerik sayar (`kesin.py:94-96`).
  - `AhoReplacer` yalnız sözcük sınırına bakar; dizgi literallerinin içini de değiştirir (`reconstruction/aho_replacer.py:60-87, 211-264`). `entry → main` genel değişimi başka gövdelerdeki `"no such entry"` gibi dizgileri de bozar.
  - Bedeli: Mac'te `main` (Ghidra adı `entry`) KS-1'den ad alamaz; ikili başına en çok bir fonksiyon. Atlananlar `ks1_skipped["anahtar_fun_degil"]` sayacına ve yan çıktıya yazılır.

### 2.3 Kanal, köken ve etiketin taşınması

- **Ad:** `extracted_names[anahtar] = ad` (var olan sözlük; türü değişmez).
- **Künye:** aynı anahtarla ikinci bir sözlük, `pre_name_meta`.

| Alan | İçerik |
|---|---|
| `kind` | `ks1` \| `main_giris` \| `gnulib` \| `elf_onyuk` \| `elle` \| `faz1` |
| `name` | Sözlüğe yazılan ad (c_namer uyuşmayı denetler) |
| `exact` | Ad olduğu gibi yazılsın mı (§2.4) |
| `label` | `kesin` \| `doğrulanmadı` (yalnız `ks1`; öbür türlerde c_namer öntanımlıyı yazar) |
| `ks1` | `{adres, turler, rol, satirlar, kanitlar}`; `kanitlar` `Evidence.as_dict()` çıktısıdır (`kesin.py:673-678`) |

- **Öbür türlerin künyesi:** tohum fonksiyonlarının imzası değişmez. `_seed_recovery_pre_names` her tohumdan önce ve sonra sözlüğü karşılaştırır; eklenen ya da değişen anahtara türünü yazar. `elle` için dönen `manual_map` kullanılır.
  - Gerekçe: donuk N0b betiği üç tohumu konumsal argümanla çağırıyor (`scripts/measurement/alt_kanal.py:597-599`); imza değişirse `uret` kırılır.
- **Yol:** `stages.py` sözlüğü Faz 2'nin `seed_artifacts`'ına koyar (`:3189-3192`) → `_run_c_namer` `ctx.artifacts.get("pre_name_meta")` ile okur (`_feedback_naming.py:284-289`) → `analyze_and_rename(..., pre_name_meta=...)`.
  - `StepContext.artifacts` salt okurdur (`pipeline/context.py:57-64`); sözlük `dict(step_ctx.artifacts)` kopyasına eklenir.
  - `LoopState`, `run_naming_phase` ve `run_one_iteration` imzaları değişmez.
- **c_namer'da:**
  - Künyesi `ks1` olan ön ad `strategy="ks1"` alır; köken kaydına `label`, `pre_name_kind` ve `ks1` alanları yazılır.
  - Künyedeki `name` sözlükteki adla aynı değilse künye yok sayılır (ör. `extracted_names.update(bindiff_names)` anahtarı ezdiyse; `_feedback_naming_bindiff.py:69`, `_feedback_naming_refdiff.py:75`). Ad `binary_extract` / "doğrulanmadı" olur.
  - Güven: bütün ön adlar bugünkü 0,95'i taşır. **[seçim 16]** Etiket anlamı taşır; güven kalibrasyonu N6'nın işi (`plan_v2_2.md:75`).
- **"string_context'ten çıkma" kendiliğinden olur:** ön adı olan anahtarın adayları `pre_named` diye elenir (`c_namer.py:1983-1986`).
- **N2'nin beklediği kayıt** (`n2_onkayit_taslak.md:371`): KS-1 adları köken kaydında `strategy == "ks1"`, `source == "pre_names"`; tür `ks1.turler`'de, satır `ks1.satirlar`'da.

### 2.4 Yazım ve çakışma: ön ad kanalının iki tuzağı

**Tuzak 1: temizleme adı değiştirir** (`c_namer.py:474-493, 1920-1921`).

| Ad | Bugün yazılan | Neden |
|---|---|---|
| `Vector_add` | `vector_add` | Büyük harf yalnız başta; `has_camel` yanlış, ad küçültülür |
| `_grid_check` | `grid_check` | Baştaki ve sondaki alt çizgi atılır |
| `foo__bar` | `foo_bar` | Art arda alt çizgi teke iner |

- KS-1 "tam ad" iddia ediyor (`ks1_onkayit.md` §1, §6). Temizleme doğru çapayı yanlışa çevirir.
- **Tasarım:** künyesinde `exact` olan ön ad temizlenmez. KS-1 adı zaten `^[A-Za-z_][A-Za-z0-9_]+$` biçimindedir (`kesin.py:86`). **[seçim 11]**
- `elle` türü de `exact` olur: analistin `Process_new` adı bugün `process_new` yazılıyor. Bu ayrı bir hata düzeltmesidir; ölçüm koşularında elle ad yok.
- **Önce ölç (Ö4):** geliştirme setinde kaç çapanın adı temizlemeyle değişirdi. GT gerektirmez.

**Tuzak 2: aynı ad iki anahtarda** (`c_namer.py:1922`).

- İkinci anahtar sessizce düşer. Sıra sözlük sırasıdır: Faz 1 adları önce, elle adlar en sonda.
- **Tasarım:** c_namer ön adları öncelik sırasıyla işler: `elle`, `main_giris`, `ks1`, sonra kalanlar özgün sırayla. Düşen ön ad köken kaydının özetine sayılır (`pre_names_dropped_duplicate`).
- KS-1 adı çakışma eki almaz: ön adlar adaylardan önce yazılır, eki sonra gelen aday alır (`c_namer.py:1990-1995`).

### 2.5 Satır, etiket ve "ad verir mi"

**Çapanın satırları** `ks1_olc.gorunum` ile aynı tanımdan hesaplanır (`scripts/measurement/ks1_olc.py:535-547`):

| Koşul | Satır |
|---|---|
| tür `assert` ve rol `kendi` | `assert` |
| rol `ust` | `assert_ust` |
| tür `func_kalibi` | `func_kalibi` |
| tür `func_aktarma` | `func_aktarma` |

Ölçüm `parca` rolünü de `assert_ust` görünümünde ayrı sayar; parça üründe ad almadığı için (§2.6) satır hesabına girmez.

**Satır durumu** ürün modülünde tek tabloda durur (`baglama.ROW_STATUS`): `kesin` \| `dogrulanmadi` \| `sus`. Tablo "aç" commit'ine kadar dört satırda da `sus`'tur.

**Adım 2 sonucundan satır durumuna geçiş kuralı** (adım 2 görülmeden yazıldı) **[seçim 7]**:

| Adım 2 kararı | Havuzlanmış tekil yanlış oranı (1 − tam ad kesinliği), Wilson %95 [L, U] | Satır durumu | Üründe |
|---|---|---|---|
| `kesin` | — | `kesin` | Ad verir, etiket "kesin" |
| `kesin_degil` ya da `yetersiz` | L ≤ %10 | `dogrulanmadi` | Ad verir, etiket "doğrulanmadı" |
| `kesin_degil` ya da `yetersiz` | L > %10 | `sus` | Ad vermez |
| herhangi biri | n = 0 | `sus` | Ad vermez |

- Ölçüt N0b'nin kuralıyla aynıdır (`alt_kanal_onkayit.md:232-239`); N2'nin D8 dalı da aynı ayrımı yapıyor (`n2_onkayit_taslak.md:305`).
- "Yanlış" burada tam eşitsizliktir; N0b'deki rubrik etiketinden katıdır. Tutucu yöndedir.
- Ön kayıt, `assert_ust` ve `func_aktarma`'nın `yetersiz` çıkacağını ölçümden önce yazdı (`ks1_onkayit.md:331-336`). Bu iki satır "kesin" olamaz; kural onların ad verip vermeyeceğini belirler.
- Kural saf bir fonksiyondur (`row_status_from_measurement(karar, n, yanlis)`); tablo "aç" commit'inde bu fonksiyonun adım 2 sayılarına uygulanmasıyla doldurulur ve testle kilitlenir.

**Çapanın etiketi** **[seçim 8]**:
- Satırlarından en az biri `kesin` ise "kesin".
- Değilse en az biri `dogrulanmadi` ise "doğrulanmadı".
- Hepsi `sus` ise ad verilmez; fonksiyon c_namer'ın olağan yoluna kalır (`oz_ad` vb. N0b kararına uyar).
- Gerekçe: ölçüm de çok türlü çapayı her satırında sayıyor (`ks1_onkayit.md:298`); birbirini doğrulayan iki kanıt tek kanıttan zayıf olamaz.

**C++ ikili:** "kesin" hiç verilmez; çapa ad verir, etiket "doğrulanmadı". **[seçim 9]**
- Tanım ölçümdekiyle aynı: içe aktarılan adlardan biri `_Z`, `__gxx_personality`, `__cxa_begin_catch`, `__cxa_end_catch`, `__cxa_throw`, `__cxa_rethrow` ile başlar; Mach-O'da baştaki tek `_` soyulur (`ks1_olc.py:123-128, 333-340`).
- Tanım ürün modülüne kopyalanır; ölçüm betiğiyle eşitliği testle kilitlenir (betik sabit, değiştirilemez).
- Gerilim: N0b "ölçülmemiş kanal ad vermez" demişti (`alt_kanal_onkayit.md:243-245`). Verilen karar "kesin etiketi verilmez" olduğu için öntanımlı ad vermektir; alternatif C++'ta KS-1'i tümüyle kapatmaktır.

**Desteklenmeyen platform** (AArch64 dışı; `kesin.py:288-297`): dizgi türleri çıkmaz, `ks1_status = desteklenmeyen_platform`. Susturma yine açıktır; x86-64 ikilide ürün çok az ad verir. Bu, ürün duruşunun sonucudur; sürüm notuna yazılmalı.

### 2.6 Parça çapaları

- Rolü `parca` olan çapa üst fonksiyonun adını taşır (`kesin.py:1037-1049`). `kesin_mapping` bunları öntanımlı dışarıda bırakır (`kesin.py:1060-1065`).
- **Tasarım:** parça ad almaz. Yan çıktıya `{adres, ust_ad}` olarak yazılır; arayüz ileride "X'in soğuk parçası" notunu buradan gösterebilir. **[seçim 6]**
- Gerekçe: aynı ad iki fonksiyona verilemez (ikincisi düşer, §2.4); `X.cold.1` geçerli bir C adı değil; parçalar kesinlik ölçüsüne girmiyor (`ks1_onkayit.md` §6).

### 2.7 Ghidra'nın adlandırdığı fonksiyonlarla çakışma

| Durum | Kim çözüyor | Sonuç |
|---|---|---|
| Fonksiyonun Ghidra adı jenerik değil | K5 (`kesin.py:1021-1023`) | Dizgi türlerinden çapa yok |
| Çapa adı Ghidra'nın başka bir fonksiyona verdiği ad | K4 `K4_ghidra_adi_dolu` (`kesin.py:999-1017`) | Çapa yok |
| `export` türü | Bağlama | Ad atanmaz (Ghidra'nın adı zaten metinde); yalnız yan çıktıda sayılır **[seçim 18]** |
| Çapa adı başka bir ön adla aynı (başka anahtar) | c_namer öncelik sırası (§2.4) | Yüksek öncelikli kalır, öbürü sayılarak düşer |

### 2.8 Öncelik sırası

`_seed_recovery_pre_names` içinde tek tanım (`stages.py:2584-2587` yorumu güncellenir) **[seçim 10]**:

| Sıra | Tür | Davranış | Gerekçe |
|---|---|---|---|
| 1 | `elle` | Her şeyi ezer | Analistin açık kararı |
| 2 | `main_giris` (`__libc_start_main` ilk argümanı) | Var olanı ezer; KS-1 bu anahtara yazamaz, başka anahtara `main` adını veremez | Yükleyicinin bilgisi. `main`'in gövdesinde başka ad taşıyan bir çapa, inline edilmiş bir fonksiyonun izidir |
| 3 | `ks1` (ad veren satırlar) | Faz 1 ön adlarını ezer; ezilen sayılır | Ad ikilinin kendi yuvasından okunur ve kesinliği ön kayıtla ölçülür |
| 4 | `faz1` (BinaryNameExtractor, byte pattern, CAPA) | Bugünkü gibi | — |
| 5 | `gnulib` (parmak izi, çağrı şekli, ayrıştırma) | Yalnız boş yuvaya | Bugünkü kural (`stages.py:2730-2731`) |
| 6 | `elf_onyuk` | Yalnız boş yuvaya | Bugünkü kural (`stages.py:2902-2903`) |

- Çağrı sırası: `main` → KS-1 → gnulib → önyük → elle. İkinci çağrı değişiklik yapmaz (KS-1 işlemesi aynı adı görünce atlar).
- KS-1 ile gnulib aynı anahtarda ayrı ad önerirse KS-1 kalır; sayı `ks1_gnulib_celiski` sayacına yazılır. **Önce ölç (Ö5).**
- `gnulib`, `elf_onyuk`, `main_giris` ve `faz1` adlarının etiketi "doğrulanmadı"dır: kanal başına ön kayıtlı ölçümleri yok. `elle` etiket taşımaz; kökeni "elle"dir. **[seçim 17]**

## 3. Susturma

### 3.1 Ne susar

N0b kararı (`kesinlik_tablosu.md:66-70`):

| Durum | Alt kanallar |
|---|---|
| Susar (9) | `agresif`, `kod_parcasi`, `bicim_parcasi`, `tek_sozcuk`, `tanimlayici`, `hata_iletisi`, `bicim_dizgisi`, `duz_metin`, `diger` |
| Kalır, "doğrulanmadı" (2) | `oz_ad`, `kebap_ad` |

### 3.2 Tanımların kaynağı

Kısıtlar:
- Ürün ölçüm betiğini içe aktaramaz (`scripts/` uygulama paketine girmez).
- `scripts/measurement/alt_kanal.py` donuk: N0b adım 2 ve N2 ön koşulu sha256'sını denetliyor (`alt_kanal_onkayit.md:223-226`; `n2_onkayit_taslak.md:112`).
- Betik zaten c_namer'ın üç parçasını dondurulmuş kopya olarak taşıyor ve testle eşitliyor (`alt_kanal.py:128-150`; `tests/test_alt_kanal.py:413-459`).

| Seçenek | Ne olur | Sonuç |
|---|---|---|
| A (öneri) | Ürün modülü `karadul/reconstruction/tarif/alt_kanal.py`: sınıflayıcının kopyası (sabitler, yüklemler, sıra) ve karar tablosu. Ölçüm betiği değişmez. Yeni test iki kopyayı eşitler | Ölçülen nüfus ve sha256 korunur; iki kopya testle kilitli |
| B | Ölçüm betiği tanımları üründen içe aktarır | Betiğin sha256'sı değişir; N0b'nin yeniden üretimi ve N2 ön koşulu sapma kaydı ister |
| C | Tanımlar üçüncü bir ortak modüle taşınır, ikisi de oradan alır | B'nin sakıncası aynen; ek dosya |

**[seçim 2]** Öneri A. Kural: sürüm 1'in başvuru kopyası donuk betiktir; sürüm 2 tanımı olursa kaynak ürün modülü olur ve yeni ölçüm betiği onu içe aktarır (ölçüm üründen alabilir, ürün ölçümden alamaz).

**Eşitlik testi** (`tests/test_tarif_alt_kanal.py`, yeni):
1. Sabitler aynı: düzenli ifadelerin `.pattern` ve bayrakları, durak sözcük kümesi, şablon yer tutucuları, alt kanal adları ve sırası.
2. Sınıflama aynı: `tests/test_alt_kanal.py`'deki sapma dizgileri ve tohumlu rastgele dizgiler üzerinde iki sınıflayıcı aynı alt kanalı verir.
3. Depodaki atamalar: `kayitlar_*.jsonl` satırları ürün sınıflayıcısıyla da aynı alt kanala düşer (`tests/test_alt_kanal.py:471-489` ile aynı döngü ve aynı alanlar).
4. Anahtar sözcük çıkarımı c_namer'la aynı (`c_namer._extract_keywords_from_string`).
5. Karar tablosu: susan küme ile `kesinlik_tablosu`'ndaki kararlar aynı. (`kesinlik_tablosu.json`'ın şeması açılmadı; alan adları uygulamada doğrulanır.)

Ürün modülü yalnız standart kitaplığı kullanır; `tarif` paketinin öbür modülleri de öyle. c_namer'ın bu modülü içe aktarması döngü yaratmaz (`tarif/` c_namer'ı içe aktarmıyor).

### 3.3 Süzgecin yeri ve "sonraki dizgiye geçmeme"

**Yer:** `c_namer.py`, işçi sonuçları birleştirildikten ve köken kaydedici kurulduktan sonra (`:1908-1912`), ön adlardan önce (`:1914`). **[seçim 1]**

**Davranış:**
- Yalnız genel anahtarlar (içinde `::` olmayan) ve yalnız `strategy == "string_context"` adayları.
- Her aday tek tek sınıflanır. Girdi dört alandır ve köken kaydına yazılanlarla aynıdır: `evidence`, `new_name` (çakışma ekinden önceki ad), `code_path`, `evidence_origin` (`c_namer.py:130-133, 246-256`). N0b'nin sınıfladığı alanlar bunlardır (`alt_kanal.py:248-253`).
- Alt kanalı susan aday listeden çıkarılır. Liste sırası korunur; kalan adayların seçimi değişmez.
- Bütün adayları süzülen anahtar `all_candidates_silenced` nedeniyle sayılır.

**"Sonraki dizgiye geçmeme" nereye düşüyor:**

| Kod | Bugünkü davranış | Adım 3'te |
|---|---|---|
| `c_namer.py:2924-2925` | Dizgiler puana göre sıralanır, yalnız birincisi (`scored[0]`) kullanılır | **Değişmez.** İkinci dizgi hiç denenmez; süzgeç ancak bu tek adayı siler |
| `c_namer.py:2900-2901` | Agresif aday ≥ 0,75 ise klasik yol hiç koşmaz | **Değişmez.** Agresif aday susar; klasik aday da üretilmemiştir. Fonksiyon öbür stratejilere kalır |
| `c_namer.py:2884-2897` | Agresif aday < 0,75 ise klasik aday da eklenir | **Değişmez.** İkisi ayrı ayrı sınıflanır |

- Süzgeç strateji fonksiyonunun dışında olduğu için yasak yapısal olarak sağlanır: `_strategy_string_context`'te tek satır değişmez.
- Bu, N0b'nin halef modeliyle aynıdır: kazanan aday yarıştan çıkar, yerine kayıtlı rakiplerden ilk susturulmamış olan geçer (`alt_kanal.py:367-391`).
- Verilen karar "aday üretilirken" diyor. Süzgeç aday aşamasındadır (seçimden önce), ama strateji fonksiyonunun içinde değildir. Seçilen ad kümesi iki yerleşimde aynıdır.
- Alternatif (strateji içinde `_add_candidate`'i atlamak): susan küme işçi süreçlerine taşınmalıdır (`c_namer.py:1556-1590, 1798-1810`); susan aday sayıları ana sürece dönmez; kazancı yoktur.

**Kurucu öntanımlısı kapalıdır.** `CVariableNamer(config)` bugünkü gibi davranır; susan kümeyi hat verir (`feedback_loop.py:263`).
- Donuk N0b `uret` komutu c_namer'ı öntanımlı kurar ve çıktısını yeniden üretir (`alt_kanal.py:567-632`); bu bozulmaz.
- `tests/test_alt_kanal.py:425-443` c_namer'ın klasik adaylarını doğrudan sınıyor; etkilenmez.
- 12 test dosyasındaki `CVariableNamer(...)` çağrıları değişmeden geçer.

**Dokunulmayacak metin:** `c_namer.py:1975-1977`. `tests/test_alt_kanal.py:454-459` bu üç satırı kaynak metni olarak arıyor; girinti ya da satır bölme değişirse donuk test kırılır.

### 3.4 Halefler ve yan etkiler

| Konu | Olgu | Tasarım |
|---|---|---|
| `api_param_reverse` halefi | Mac geliştirme setinde 16 fonksiyon (`n2_onkayit_taslak.md:139`); güven 0,75 (`c_namer.py:3498-3506`). G4'te 5 öğenin 5'i yanlış, karar yok (`kesinlik_tablosu.md:46`) | Kalır, etiket "doğrulanmadı". Karar N2'de (`n2_onkayit_taslak.md:268, 331`). **[seçim 15]** |
| `type_based` fonksiyon adları | `proc_<adr>`, `check_<adr>`, `get_<adr>`; güven 0,2-0,3 (`c_namer.py:3423-3461`); yapısal süzgeçte değil | Bugün uykuda: bakılan 5 ikilide `FUN_` fonksiyonlarının `return_type` alanı hep `undefined`. Genel eşik (§4.4) kalıcı olarak kapatır |
| Çakışma ekleri | Susan aday bir adı tutmayı bırakınca kalan adayın eki değişebilir (`foo_2` → `foo`) | Karşılaştırmalar taban adla yapılır (`alt_kanal.py:224-228`); N2 ve ablasyon böyle okur |
| NameMerger'ın öbür kaynakları | Susan fonksiyon metinde `FUN_x` kalır; computation, pcode, engineering, FunctionID adayları ≥ 0,30 ise `merged/`'de ad yazabilir (`_feedback_naming_candidates.py:470-581`) | Bugün sıfır (`merged/` = `src/`). Susturmadan sonrası bilinmiyor: **önce ölç (Ö3)**; kapı §6.4 K-D |
| Yineleme 1 | c_namer yeniden koşar; aynı süzgeç uygulanır | 119 çalışma alanında iki yinelemenin `FUN_` adları: 6 440 aynı, 14 yalnız ek farklı, 8 yalnız yineleme 1'de (hepsi `body_literal` kanıtlı). Arka kapı küçük ve `kod_parcasi` susunca daralır |

## 4. Güven ve etiket kanalı

### 4.1 Etiket sözlüğü

| Etiket | Anlam | Kim alır |
|---|---|---|
| "kesin" | Ad ikilinin kendi ad yuvasından okundu; satırın tam ad kesinliği ön kayıtlı ölçümde `kesin` çıktı | Yalnız KS-1 çapası; satır durumu `kesin` ve ikili C++ değil |
| "doğrulanmadı" | Kanal ölçülmedi ya da ölçüm hedefi göstermedi | Kalan her fonksiyon adı |
| (etiketsiz) | Analistin verdiği ad | `elle` |

- Değerler N0b'nin sözlüğüyle aynı yazılır (`alt_kanal.py:183`); sabitler ürün modülünde bir kez tanımlanır.
- N0b'nin üçüncü değeri "doğrulandı" bugün boş (hiçbir alt kanal U ≤ %10 çıkmadı). Alan bu değeri de taşıyabilir; adım 3 üretmez.

### 4.2 Köken kaydı: eklenen alanlar

Şema adı ve sürümü değişmez (`karadul.naming_provenance`, 1; `c_namer.py:167-168`). **[seçim 3]**
- Gerekçe: donuk `alt_kanal.py` sürüm 1 dışını reddediyor (`:678`); N2 onu yeni ürünün kaydı üzerinde koşturacak. Betik alanları adıyla okuyor (`:695-705`); fazla alan zararsız.
- Var olan alanların anlamı değişmez. `strategy` alanına yeni bir değer (`ks1`) gelir.

| Yer | Alan | İçerik |
|---|---|---|
| `global` kaydı | `label` | Etiket (elle adda yok) |
| `global` kaydı, `string_context` | `sub_channel` | Ürün sınıflayıcısının verdiği alt kanal |
| `global` kaydı, ön ad | `pre_name_kind` | Künye varsa türü |
| `global` kaydı, `ks1` | `ks1` | `{adres, turler, rol, satirlar, kanitlar}` |
| üst düzey | `silencing` | `{enabled, definition_version, silenced, candidates_dropped: {alt kanal: sayı}}` |
| üst düzey | `global_min_confidence` | Uygulanan eşik ya da `null` |
| `summary` | `labels_global`, `pre_names_dropped_duplicate` | Sayılar |
| `eliminated_keys` | `all_candidates_silenced`, `below_global_min_confidence` | Var olan biçimde (kapsam → strateji → sayı) |

- `per_function` (yerel ad) kayıtlarına etiket yazılmaz; yerel adlar bu adımın kapsamı dışındadır.
- Değişmez korunur: "her aday anahtarı seçim döngüsünden tam bir kez çıkar" (`tests/test_c_namer_provenance.py:307-312`); yeni iki neden bu toplamı tamamlar.
- `CNamingResult`'a `label_map` ve `silenced_counts` eklenir (`c_namer.py:74-104`); `_run_c_namer` bunları `stats["naming_by_label"]` ve `stats["naming_silenced"]` olarak yazar.

### 4.3 Biçimlendirici, rapor, arayüz

**Biçimlendirici** (`output_formatter.py:605-660`):
- Her `naming_map.json`'ın yanındaki `naming_provenance.json` okunur; kayıt anahtarla bulunur. Ad ve köken aynı yinelemeden gelir (K6'yı kapatır).
- Yazılan giriş: `{"new_name", "source": "c_namer", "confidence": <gerçek>, "label", "channel", "evidence"}`.
  - `source` değeri `c_namer` kalır: `alt_kanal.py:737-738` ve arayüz bu değeri okuyor.
  - `channel`: `ks1:<satırlar>`, `string_context/<alt kanal>`, `api_param_reverse`, `on_ad:<tür>`.
  - `evidence`: `string_context`'te kanıt dizgisi; `ks1`'de `{rol, kanit_sayisi}`.
- Köken kaydı yoksa ya da kayıt bulunamazsa: `confidence: null`, `label: "doğrulanmadı"`, `channel: null`. **Hiçbir durumda `1.0` yazılmaz.**
- Öbür kaynaklar (`signature_db`, `byte_pattern`, `computation_recovery`; `:510-583`) kendi güvenlerini zaten taşıyor. Bu adımda etiket almazlar; G26'ya kalır.

**Rapor JSON:** `report.json` aşama istatistiklerini olduğu gibi taşır (`output_formatter.py:752-762`). Eklenen anahtarlar:

| Anahtar | İçerik |
|---|---|
| `naming_flags` | `{ks1, silencing, global_threshold, ks1_row_status, definition_version}`: koşunun kol kimliği |
| `ks1_status`, `ks1_anchors`, `ks1_named`, `ks1_kesin`, `ks1_skipped` | Bağlama sayaçları ve atlama nedenleri |
| `naming_by_label` | `{kesin: n, doğrulanmadı: n}` |
| `naming_silenced` | Alt kanal → süzülen aday sayısı |

**Arayüz:**
- `ui/server.py:569-574`: `label`, `channel`, `evidence` de geçer.
- **Bayat kayıt koruması:** kullanıcı adı elle değiştirince `reconstructed/src/naming_map.json` güncellenir ama `clean/naming_map.json` güncellenmez (`ui/server.py:591-630`). Kayıttaki `new_name` o anki adla aynı değilse köken "elle" gösterilir, etiket gösterilmez.
- `ui/index.html:1189-1199`: etiket rozeti ("kesin" / "doğrulanmadı"), yanında gerçek puan; ipucunda kanal ve kanıt.
- Liste rozeti: `build_model` (`ui/server.py:212`) her fonksiyona `label` ekler; liste satırında küçük işaret. **[seçim 19]**
- `ui/server.py:1648-1650`: "yüksek-güven isim" satırı `naming_by_label` sayılarıyla değişir.
- Sahte veri yasağı: rozet yalnız kayıtta etiket varsa çizilir; yoksa hiçbir şey çizilmez.
- Ayar panelindeki "İsim güven eşiği" (`ui/index.html:589`) bugün fonksiyon adlarına etkisiz; §4.4 ile gerçekten çalışır hâle gelir. "İsim atama alt sınırı" (`:593`) yalnız NameMerger'ın öbür kaynaklarını etkiler; açıklaması düzeltilmeli.

### 4.4 Eşiğin son çıktıda uygulanması

- **Sorun:** ürün eşiği (0,7) bir ayar olarak var, ama hiçbir yerde uygulanmıyor (§1.3 K2). c_namer 0,15 ile metne yazıyor.
- **"Son çıktı" neresi:** genel adlar için c_namer'ın seçim döngüsü. Ad metne orada yazılır ve geri alınamaz; puanlayıcı ve arayüz de o haritayı okur.
- **Tasarım:** c_namer kurucusuna `global_min_confidence` (öntanımlı `None`). Genel anahtarda en iyi adayın güveni eşiğin altındaysa anahtar ad almaz ve `below_global_min_confidence` diye sayılır. Denetim, ön ad denetiminden sonra ve çakışma denetiminden önce durur (`c_namer.py:1986` ile `:1988` arası). **[seçim 12]**
  - Hat değeri `binary_reconstruction.min_naming_confidence`'tan verir (`config.py:472`).
  - Yerel adlar (parametre, yerel değişken) etkilenmez; 0,15 ve `_LOCAL_MIN_CONF` sürer.
- **NameMerger:** aynı eşik `final_naming_map`'e de uygulanır (`_feedback_naming_merger.py:107-122`; `merge_result.merged_names[...].final_confidence`). **[seçim 14]** Gerekçe: ürün tek eşik taşısın; susturmadan sonra öbür kaynaklar 0,30-0,70 arasında ad yazamasın.
- **Asıl çözüm bu değil.** Planın istediği, adayların sona kadar taşınıp eşiğin ayrı bir son adımda uygulanmasıdır (`plan_v2_2.md:57`). Bu, c_namer'ın metne yazmayı bırakmasını gerektirir ve G26'nın işidir (`plan_v2_2.md:152`).

**Geliştirme setindeki etkisi** (§1.3 sayımı): fonksiyon adlarında 0 değişiklik; 9 217 `DAT_` adı düşer.

### 4.5 Veri adları (`DAT_`)

| Seçenek | Sonuç |
|---|---|
| A (öneri) | Genel eşik `DAT_` anahtarlarına da uygulanır; `global_<dört hane>` adları yazılmaz, Ghidra'nın `DAT_<adres>` adı kalır |
| B | Adlar kalır; güven 0,30 ve "doğrulanmadı" ile gösterilir |
| C | Veri adları için ayrı, daha düşük eşik |

**[seçim 13]** Öneri A. Gerekçe: `global_7ae0` bir ad değil, adresin kısaltılmış hâli; çakışma ekiyle (`global_7ae0_2`) adres de okunamaz olur. "Yanlış ad vermektense `FUN_` bırak" ilkesinin veri karşılığı `DAT_` bırakmaktır.
- Yan etki: README'deki "Names Recovered" sayısı düşer (`output_formatter.py:826`); tmux Mac'te 1 369 → ≈ 1 100.
- Fonksiyon adı ölçümlerini etkilemez; puanlayıcılar yalnız fonksiyon adına bakar.

### 4.6 Geriye dönük uyumluluk

| Tüketici | Okuduğu | Etki |
|---|---|---|
| `function_f1.load_naming_map` (`:382-397`), `macho_f1` | `global` ya da `mappings[*].new_name` | Yok |
| `alt_kanal.py kayitlari_kur` (`:684-726`) | Köken alanları adıyla; şema sürümü 1 | Yok (şema 1 kalır) |
| `alt_kanal.py ters_eslesme` (`:737-738`) | `mappings[*].source == "c_namer"` | Yok (`source` korunur) |
| `tests/test_c_namer_provenance.py:259-312` | Üst düzey anahtar kümesi, `summary` anahtarları, kayıt alanlarının izinli kümesi | **Güncellenir:** izinli kümeye yeni alanlar, üst düzeye `silencing` ve `global_min_confidence`, `summary`'ye iki sayı |
| `tests/test_c_namer_provenance.py:444-456` | Künyesiz ön ad → `binary_extract`, temizlenmiş ad | Yok (künyesiz davranış aynı) |
| `tests/test_alt_kanal.py:413-459` | c_namer'ın klasik yolu, şema sürümü, yapısal süzgeç metni | Yok (§3.3 kısıtlarıyla) |
| `tests/test_main_gnulib_seed_ordering.py:81-128` | `_seed_recovery_pre_names(extracted_names, static_dir, context, stats)` | Yok (yeni argümanlar isteğe bağlı) |
| `tests/test_output_formatter.py` | Ürün haritasının varlığı ve biçimi | `1.0`'a bağlı doğrulama bulunmadı (`grep`); yeni testler eklenir |
| `tests/test_function_f1.py:302` | Sentetik `{"source": "c_namer"}` | Yok |
| `ui/server.py:572`, `ui/index.html:1195-1199` | `source`, `confidence`, `library` | `confidence` artık `null` olabilir; `index.html:1199` bunu zaten denetliyor |
| `ui/server.py:1648` | `naming_high_confidence` | Anahtar kalır; gösterim değişir |
| `core/report_generator.py:711-738` | `binary_names`, `signature_matches` | Yok |

Arayüz kökenini sınayan test yok (`grep "provenance" tests/`: yalnız c_namer ve alt kanal testleri). Yeni test gerekir.

## 5. Uygulama planı

### 5.1 Dokunulmayacak dosyalar

| Dosya | Neden |
|---|---|
| `karadul/reconstruction/tarif/kesin.py`, `scripts/measurement/ks1_olc.py`, `function_f1.py`, `macho_f1.py`, `macho_measure.py`, `tests/benchmark/metrics.py`, `tests/test_tarif_kesin.py`, `tests/test_ks1_olc.py`, `scripts/measurement/mutation_specs_ks1.json` | KS-1 ön kaydıyla sha256'ları sabit (`docs/arge/2026-10-21_g11_n1/ks1_sabitler.json`, `ks1_sapma_1_sabitler.json`); değişirse `olc` ölçmez. Değişiklik ancak sapma kaydıyla |
| `scripts/measurement/alt_kanal.py`, `alt_kanal_olc.py` | N0b ve N2 sha256 denetimi |
| `karadul/core/target.py`, `karadul/ghidra/headless.py` | Bu adımda gerek yok; tip izinin dosyaları |

### 5.2 Commit sırası

Her commit tek başına yeşildir. 1-8 arasında bayraklar kapalıdır; ürünün ad haritası HEAD ile aynıdır (1. commit'in bilerek değiştirdiği `confidence` alanı dışında).

| # | Commit | Dosyalar | Üretim / test satırı | Tehlikeli dosya |
|---|---|---|---|---|
| 1 | Biçimlendirici gerçek güveni ve etiketi taşır; `1.0` kalkar | `karadul/core/output_formatter.py`; `tests/test_output_formatter.py` | ≈ 55 / 130 | evet (1.) |
| 2 | Ürün alt kanal modülü ve karar tablosu | `karadul/reconstruction/tarif/alt_kanal.py` (yeni); `tests/test_tarif_alt_kanal.py` (yeni); mutant belirtimi | ≈ 190 / 260 | hayır |
| 3 | KS-1 bağlama modülü | `karadul/reconstruction/tarif/baglama.py` (yeni); `tests/test_tarif_baglama.py` (yeni); mutant belirtimi | ≈ 230 / 330 | hayır |
| 4 | Yapılandırma bayrakları (kapalı) | `karadul/config.py`; yapılandırma testi | ≈ 15 / 30 | evet (2.) |
| 5 | c_namer: künyeli ön ad, süzgeç, genel eşik, etiket, köken alanları | `karadul/reconstruction/c_namer.py`; `tests/test_c_namer_susturma.py` (yeni); `tests/test_c_namer_provenance.py` (güncelleme); mutant belirtimi | ≈ 170 / 380 | evet (3.) |
| 6 | Hat bağlantısı | `karadul/pipeline/steps/kesin_anchors.py` (yeni), `steps/__init__.py`, `feedback_loop.py`, `_feedback_naming.py`, `_feedback_naming_merger.py`; testler | ≈ 150 / 200 | hayır |
| 7 | Adım listesi, tohum sırası, künye | `karadul/stages.py`; `tests/test_main_gnulib_seed_ordering.py` (ek) | ≈ 45 / 150 | evet (4.) |
| 8 | Arayüz: etiket ve gerçek puan | `ui/server.py`, `ui/index.html`; `tests/test_ui_etiket.py` (yeni) | ≈ 45 / 90 | hayır |
| 9 | Aç: bayrak öntanımlıları ve KS-1 satır tablosu | `karadul/config.py` (3 satır), `tarif/baglama.py` (tablo); belge | ≈ 10 / 20 | evet |
| | **Toplam** | | **≈ 910 / 1 590** | |

- Tehlikeli dosya sırası: `output_formatter.py` → `config.py` → `c_namer.py` → `stages.py` → `config.py` (aç). Tip izi bu günlerde bu dosyalara dokunmaz (`plan_v2_2.md:62`).
- 1. commit öbürlerinden bağımsızdır ve hemen değer üretir; tek başına da alınabilir.
- 9. commit adım 2'nin sonucu ve §6.4'ün GT'siz kapıları geçmeden atılmaz. **[seçim 20]**
- Sürüm: yeni özellik ve hata düzeltme birlikte; `Y` +1 ve `Z` +1.

### 5.3 Dosya başına değişiklik noktaları

| Dosya | Yer | Değişiklik |
|---|---|---|
| `output_formatter.py` | `:633-658` | Kardeş köken kaydını oku; girişi gerçek güven, etiket, kanal, kanıtla yaz; kayıt yoksa `null` |
| `config.py` | `:442-472` (`BinaryReconstructionConfig`) | `enable_ks1_anchors`, `enable_subchannel_silencing`, `apply_global_naming_threshold`. YAML'dan var olan döngüyle okunur (`_from_dict`, `binary_reconstruction` bloğu) |
| `c_namer.py` | `:74-104` | `CNamingResult`: `label_map`, `silenced_counts` |
| | `:205-369` | Kaydedici: iki yeni neden, `silencing` bloğu, `labels_global`, kayıtlara ek alan |
| | `:1654-1662` | Kurucu: `silenced_subchannels` (boş), `global_min_confidence` (`None`); yalnız anahtar sözcükle |
| | `:1687-1696` | `analyze_and_rename(..., pre_name_meta=None)` |
| | `:1912` sonrası | Susturma süzgeci |
| | `:1915-1936` | Ön adlar: öncelik sırası, `exact`, künyeden strateji ve etiket, düşen ön adın sayımı |
| | `:1986` ile `:1988` arası | Genel eşik |
| | `:2003-2021` | `label_map`; kayda `label` ve `sub_channel` |
| | `:1975-1977` | **Dokunulmaz** |
| `feedback_loop.py` | `:260-263` | c_namer'ı bayraklara göre kur |
| `_feedback_naming.py` | `:284-293` | `pre_name_meta` geçir; iki yeni istatistik |
| `_feedback_naming_merger.py` | `:107-122` | Genel anahtarlara ürün eşiği |
| `stages.py` | `:2574-2603` | İmza (`kesin=None`, `meta=None`), tür işaretleme, KS-1 işleme çağrısı |
| | `:3074-3104` | Listeye `"kesin_anchors"` |
| | `:3146` sonrası, `:3172`, `:3189-3192`, `:3293` | Yapıtı oku; iki çağrıya geçir; künyeyi Faz 2 tohumuna ekle |
| `ui/server.py` | `:212-250`, `:569-574`, `:1648-1650` | Liste etiketi, köken alanları ve bayat kayıt koruması, özet satırı |
| `ui/index.html` | `:1189-1199`, liste satırı, biçem | Rozet |

`stages.py`'deki KS-1 mantığı `tarif/baglama.py`'dedir; `stages.py` yalnız çağırır. Böylece tehlikeli dosyadaki fark ≈ 45 satırda kalır ve mantık `ReconstructionStage` kurulmadan sınanır.

### 5.4 Test ve mutant planı

| Commit | Kilitlenen davranışlar (test) | Mutantlar (hepsi gerçek test başarısızlığıyla ölmeli) |
|---|---|---|
| 1 | Kayıt varsa güven kayıttaki değer; yoksa `null`; hiçbir yolda `1.0`; ad ve köken aynı yinelemeden; `source` hâlâ `c_namer`; etiket yoksa "doğrulanmadı" | Sabit `1.0` geri gelir; köken yanlış yinelemeden okunur; eksik kayıtta `label` "kesin" olur |
| 2 | §3.2'deki beş eşitlik; her alt kanalın sınır durumları | Yüklem sırası değişir; `oz_ad` susan kümeye girer; `agresif` kümeden çıkar; `%%` belirteç sayılır; büyük harf dışlaması kalkar |
| 3 | Satır tanımı `gorunum` ile aynı; etiket kuralı; C++ işareti ölçüm betiğiyle aynı; `FUN_` dışı anahtar atlanır; parça ad almaz; `main` korunur; Faz 1 adı ezilir ve sayılır; ikinci çağrı değişiklik yapmaz; girdi eksikse durum kodu; geçiş kuralının dört satırı ve sınırları | "En az bir satır" → "hepsi"; C++'ta "kesin" verilir; `sus` satır ad verir; `main` ezilir; parça ad alır; Wilson sınırı `≥` olur; Mach-O'da `_` soyulmaz |
| 4 | Öntanımlılar kapalı; YAML'dan okunur | — (öntanımlı çevirme testle) |
| 5 | **Öntanımlı kurucuyla `naming_map.json` ve `.c` çıktıları bayt bayt aynı** (HEAD çıktısının dondurulmuş özetiyle); süzgeç yalnız `string_context` ve yalnız genel anahtar; susan aday yoksa çıktı aynı; ikinci dizgiye geçilmez (iki dizgili fonksiyon: birincisi susan, ikincisi kalan kanal → ad yok); agresif ≥ 0,75 susunca klasik aday doğmaz; halef (`api_param_reverse`) geçer; yapısal halef ad almaz; `exact` ad olduğu gibi; künye adı uyuşmazsa yok sayılır; öncelik sırası; genel eşik yalnız genel anahtar; köken değişmezi; belirlenimcilik (iki tohum) | Süzgeç yerel anahtara da uygulanır; süzgeç bütün stratejilere uygulanır; `scored[1]`'e geçilir; `exact` adı temizlenir; etiket künyesiz ada "kesin" yazılır; eşik yerel ada uygulanır; eşik `<=` olur; düşen ön ad sayılmaz |
| 6 | Bayrak kapalıyken adım iş yapmaz; yapıt biçimi; c_namer bayraklara göre kurulur; `naming_flags` raporda; NameMerger eşiği | Bayrak yok sayılır; `static/` yerine `deobfuscated/` okunur; eşik uygulanmaz |
| 7 | Sıra: elle > main > KS-1 > Faz 1 > gnulib > önyük; tür işaretleri; iki çağrı; künye Faz 2'ye ulaşır; KS-1 yapıtı yokken bugünkü davranış | KS-1 `main`'den önce çağrılır; KS-1 gnulib'den sonra çağrılır; künye tohuma eklenmez |
| 8 | Etiket ve kanal geçer; bayat kayıtta etiket yok; etiket yoksa rozet verisi yok | Bayat kayıt koruması kalkar |
| 9 | Tablo = geçiş kuralı(adım 2 sayıları); öntanımlılar açık | Tabloda bir satır elle "kesin" yapılır |

- Mutant koşusu: `PYTHONDONTWRITEBYTECODE=1`; mutant uzunluğu özgününden farklı olmalı (`.pyc` tuzağı).
- Worktree'de testler `python -m pytest` ile koşulur; `karadul.__file__` denetlenir.
- Her tehlikeli dosya commit'inden sonra tam takım (bugün ≈ 6 400 test).

### 5.5 Önce ölç

Hepsi GT'sizdir; uygulamadan ya da "aç" commit'inden önce yapılır.

| # | Ölçüm | Neden | Ne zaman |
|---|---|---|---|
| Ö1 | KS-1 çıkarım süresi, en büyük geliştirme ikilisinde | Faz 1'e eklenen süre bilinmiyor; saf Python veri akışı | 6. commit'ten önce (`say` koşusunun süresinden okunabilir) |
| Ö2 | Bayraklar kapalıyken `reconstructed/src/naming_map.json` ve `.c` dosyaları HEAD ile bayt bayt aynı (tmux, htop) | 5-7. commit'lerin sessiz etkisi olmadığının kanıtı | 7. commit'ten sonra |
| Ö3 | Susturma açıkken `merged/` ile `src/` farkı: c_namer dışı kaynaklardan kaç `FUN_` adı geliyor | Ölçülmemiş kanalların açılması riski (§3.4) | 9. commit'ten önce |
| Ö4 | Adı temizlemeyle değişecek KS-1 çapası sayısı | §2.4 tuzak 1'in boyutu | 3. commit'te, test verisi olarak |
| Ö5 | KS-1 ile `main` ve gnulib'in aynı anahtarda ayrı ad önerdiği durum sayısı | Öncelik sırasının fiilî etkisi | 7. commit'ten sonra |
| Ö6 | Anahtarı `FUN_` olmayan çapa sayısı | [seçim 5]'in bedeli | 3. commit'te |
| Ö7 | `FUN_` anahtarlı, güveni 0,7'nin altında kayıt sayısı | Genel eşiğin fonksiyon adlarına etkisi | **Yapıldı:** 119 çalışma alanında 0 |
| Ö8 | Yeni modüllerin uygulama paketine girdiği | Uygulama bu adımdan sonra derlenecek | Derlemeden önce |

### 5.6 Riskler

1. **Takvim.** G12 bir gün; bu iş 2-3 gün. Kesilebilecekler, öncelik sırasıyla: liste rozeti ([seçim 19]), NameMerger eşiği ([seçim 14]), öbür ön ad türlerinin künyesi (yalnız `ks1` ve `elle` kalır). Kesilemeyecekler: 1, 2, 3, 5, 7 ve 9. commit'ler.
2. **N4 ile çakışma.** Fiil adımının ürüne bağlanması G14'te (`plan_v2_2.md:217`) ve aynı dosyalara dokunur (`c_namer.py`, `stages.py`). Tarif adları da `pre_names` ve `pre_name_meta` (`kind: "tarif"`) kanalını kullanmalı; ikinci bir kanal açılmamalı. İki bağlama aynı güne konmaz.
3. **İki kopya tanım.** Ürün sınıflayıcısı ile donuk betik ayrışırsa susturma ölçülenden farklı bir kümeye uygulanır. Koruma: §3.2 eşitlik testi ve §6.4 K-C.
4. **KS-1 süresi ve büyük ikili.** 100 000 fonksiyonlu ikilide çıkarım süresi ölçülmedi. Gerekirse fonksiyon sayısına üst sınır; aşılırsa `ks1_status = atlandi_buyuk` (bu adımda eklenmesi önerilmiyor; Ö1'e bağlı).
5. **x86-64.** KS-1 yok, susturma var; ürün çok az ad verir. Sürüm notunda yazılmalı; KS-1'in x86-64 çağrı kuralı ayrı iş.
6. **`extracted_names`'i sonradan ezenler.** BinDiff ve referans farkı sözlüğü günceller (`_feedback_naming_bindiff.py:69`, `_feedback_naming_refdiff.py:75`); yalnız referans ikili verilirse çalışır. Künye ad uyuşmazlığında yok sayıldığı için "kesin" etiketi yanlış ada geçmez.
7. **Yineleme tutarsızlığı.** Biçimlendirici son yinelemenin haritasını, puanlayıcı ilkini okur (§1.3 K6). Bu adım düzeltmez; köken ile adı aynı dosyadan okuyarak etiketin yanlış ada yapışmasını önler.
8. **Geliştirme setine uyum.** KS-1 kuralları ve N0b kararı aynı programlarda (tmux, htop ve Debian 8 programı) kuruldu. Üründeki "kesin" iddiasının bağımsız sınaması Kapı 1 ve Kapı 2'dedir.
9. **Elle adın koşulsuz zorlanması ölü** (`stages.py:4262-4267`). Step yolunda elle ad yalnız ön ad olarak etkilidir; §2.4'teki öncelik sırası bunu sağlamlaştırır, ama BinDiff sonrası ezilme olasılığı sürer (6. madde).

## 6. Ablasyon ön kaydı taslağı

> Bu bölüm ayrı bir ön kayıt belgesine (`ablasyon_onkayit.md`) dönüşecek. Kollar GT'ye bakılarak okunmadan önce commit'lenir.

### 6.1 Amaç ve sınır

- **Amaç:** KS-1'in ve susturmanın ürünün fonksiyon adlarına etkisini ayrı ayrı ve birlikte ölçmek; bağlamanın doğru çalıştığını göstermek.
- **Ne değildir:**
  - KS-1 kesinliğinin bağımsız sınaması değil (aynı geliştirme seti; adım 2 ile aynı çapalar).
  - Susturma kararının yeniden açılması değil. N0b kararı G4 verisiyle değişmez (`alt_kanal_onkayit.md:256`); ablasyon da değiştirmez.
  - Rubrikli (kör etiketli) yanlış oranı değil. O ölçüm N2'dedir (`plan_v2_2.md:71`).

### 6.2 Kollar

| Kol | KS-1 | Susturma | Anlamı |
|---|---|---|---|
| A0 | kapalı | kapalı | Taban |
| A1 | açık | kapalı | Yalnız KS-1 |
| A2 | kapalı | açık | Yalnız susturma |
| A3 | açık | açık | Ürün |

- Genel eşik dört kolda da açıktır (ürün ayarı); fonksiyon adlarını değiştirmediği K-A'da ayrıca gösterilir.
- Kollar `karadul.yaml` ile seçilir (çalışma dizininde; `config.py:940-944`). Depo kökünde bugün böyle bir dosya yok.
- **Kol kimliği çıktıdan okunur:** okuyucu `report.json`'daki `naming_flags`'i kolun beklenen değerleriyle karşılaştırır; uyuşmazsa durur. Yapılandırma dosyasının unutulması böylece sessiz kalmaz.
- **Girdi:** dört kol aynı Ghidra çıktısını kullanır. **[seçim A3]**
  - Öneri: dondurulmuş `static/` dizinleri üzerinde yalnız adlandırma hattını koşturan bir koşum betiği (tohumlar + KS-1 + c_namer; N0b `uret` ile aynı yaklaşım, `alt_kanal.py:567-632`). 119 ikili × 4 kol Ghidra'sız koşar.
  - Koşum betiğinin hatla eşdeğerliği K-E'de sınanır.
  - Alternatif: dört kol için tam koşu (Ghidra dahil); Debian'da 468 koşu demektir.

### 6.3 Nüfus ve ölçüler

**Nüfus:** KS-1 ön kaydının geliştirme seti, 10 birim, 119 ikili (`ks1_onkayit.md` §7). **[seçim A2]**
- Mac: tmux, htop (`workspaces/olcum_mac/runs/ol7-c-b7faeac`; Ghidra 12.1.2).
- Debian 13 arm64: tmux, htop, tree, zstd (2), redis-tools (4), sqlite3, openssl, coreutils (106) (`~/karadul_olcum/n1_debian13`).
- C++ ikili (pzstd) fonksiyon adı ölçülerinin dışındadır; GT'siz sayaçlarda kalır.
- Doğrulama ve test setlerine bakılmaz.

**GT'li ölçüler** (birim başına; yanında program düzeyinde makro ve havuz):

| Ölçü | Tanım |
|---|---|
| P, R, F1 (strict) | Var olan puanlayıcıların katı eşleşmesi (`function_f1.py`, `macho_f1.py`; değiştirilmeden) |
| Yanlış oranı (otomatik) | Ad verilen ve katı eşleşmeyen / ad verilen; Wilson %95 |
| Kapsam | Ad verilen / ad bekleyen nüfus |
| Tam ad kapsamı | Katı doğru / ad bekleyen nüfus |
| KS-1 payı | `ks1` kanallı ad / bütün adlar; ayrıca katı doğru adlar içindeki payı |
| Kanal tablosu | Kanal başına n, katı doğru, katı yanlış: `ks1:<satır>`, `oz_ad`, `kebap_ad`, `api_param_reverse`, `on_ad:<tür>` |
| Doğru ad kaybı | A0'da katı doğru olup A2'de adı silinen / A0'daki katı doğru |
| Proje normalleştirmesi | Aynı ölçüler `match_strict` ile (duyarlılık; karar dışı) |

- Kanal, adın köken kaydındaki `strategy`, `sub_channel` ve `pre_name_kind` alanlarından okunur.
- Çok ikilili birimlerde sayım örnek düzeyindedir (ikili başına ad); KS-1 ön kaydının kapsam tanımıyla aynı (`ks1_onkayit.md` §9).
- Çıktıda öğe düzeyinde ad yoktur; yalnız sayılar ve oranlar (`ks1_olc.py` ile aynı kural).

**GT'siz ölçüler** (N2'nin sınıflarıyla aynı adlar; `n2_onkayit_taslak.md:232-241`):

| Sınıf | Tanım (A0'a göre) |
|---|---|
| `korunan` | Aynı taban ad, aynı strateji ya da alt kanal |
| `ks1` | KS-1 kanalından ad |
| `halef` | A0 adı susan bir alt kanaldandı, şimdi başka stratejiden |
| `yeni_diger` | A0'da adsızdı, şimdi KS-1 dışından ad aldı |
| `degisen` | Aynı strateji, farklı taban ad (0 beklenir) |
| `silinen` | Adı `FUN_`'a döndü |

### 6.4 Kapılar (GT'siz; "aç" commit'inden ve derlemeden önce)

| Kapı | Ölçüt | Tutmazsa |
|---|---|---|
| K-A regresyon | Bayraklar kapalıyken `reconstructed/src/naming_map.json` HEAD ile bayt bayt aynı. Genel eşik açılınca `FUN_` girişleri yine aynı; fark yalnız `DAT_` girişlerinde | Dur. Fark açıklanmadan hiçbir kol koşmaz |
| K-B KS-1 bütünlüğü | A1 ve A3'te ad veren her çapa (`kesin_capalar.json`) haritada aynı anahtarla ve harfi harfine aynı adla var; eksikler yalnız kayıtlı atlama nedenleriyle | Dur. Bağlama hatası |
| K-C susturma bütünlüğü | A2 ve A3'ün köken kaydı donuk `alt_kanal.py sinifla` ile yeniden sınıflanınca susan dokuz alt kanaldan gelen ad sayısı 0 (N2 ön koşulu 2 ile aynı denetim). Ürünün yazdığı `sub_channel` donuk sınıflayıcıyla her kayıtta aynı | Dur. Sınıflayıcı kopyası ayrışmış |
| K-D beklenmeyen kaynak | A2 ve A3'te c_namer haritasında olmayıp `merged/`'de ad alan `FUN_` sayısı 0 | Kaynak başına listelenir; bu kaynaklar ad yazmayacak biçimde kapatılır (aday olarak kalır); derleme ondan sonra |
| K-E koşum eşdeğerliği | Koşum betiğinin A3 haritası, tam hat koşusunun A3 `reconstructed/src/naming_map.json`'ı ile bayt bayt aynı (Mac tmux, htop; Debian tmux) | Koşum betiği kullanılmaz; kollar tam koşuyla ölçülür |
| K-F halef öngörüsü | A2'deki `halef` ve `silinen` kümeleri, A0'ın köken kaydından donuk `halef()` ile öngörülenle aynı (Mac geliştirme setinde beklenen 16 halef) | Fark öğe öğe açıklanır; açıklanamayan fark hata sayılır |
| K-G belirlenimcilik | A3 iki ayrı `PYTHONHASHSEED` ile aynı haritayı verir | Dur (ÖL-7 koşulu) |

### 6.5 Kararlar ve önceden yazılmış dallar

| # | Soru | Dal |
|---|---|---|
| D1 | Kapılardan biri tutmadı mı | Evet → ölçüm okunmaz, "aç" commit'i atılmaz, uygulama derlenmez |
| D2 | Üründeki KS-1 adlarının satır başına katı kesinliği adım 2'ninkiyle aynı mı | Aynı çapalar olduğu için eşitlik beklenir. Fark varsa her farklı öğe nedeniyle sayılır (temizleme, ezilme, atlama); açıklanamayan fark bağlama hatasıdır, D1 gibi işlenir |
| D3 | A3'ün otomatik yanlış oranı A0'ınkinden düşük mü (n ≥ 10 olan her birimde) | Evet → beklenen. Hayır → o birim için kanal tablosu okunur ve kayda geçer; ürün kararı değişmez (karar N0b ve adım 2'dedir), ama sonuç Kapı 1 öncesi risk olarak plana yazılır |
| D4 | Doğru ad kaybı beklenenden çok mu | N0b örnekleminden beklenti ≈ %6,5 (susan kanalların 3 tam adı / 46 tam ad; `kesinlik_tablosu.md:14-23`). > %15 ise sınıflayıcı taşıması ve süzgeç incelenir; N0b kararı değişmez **[seçim A4]** |
| D5 | KS-1 hiç ad vermeyen birimler | Sayılır ve program sınıfı eş değişkeniyle raporlanır (htop, sqlite3, tree'de dizgi türü yuvası yok; `ks1_say.md`). Karar yok |
| D6 | `api_param_reverse` ve halefleri | Yalnız sayılır. Otomatik katı eşleşme bu kanalı yargılayamaz (rol adları tam ad değildir); karar N2'de |
| D7 | Var olan ön ad türleri (`main_giris`, `gnulib`, `elf_onyuk`) | Kanal tablosunda ilk kez ayrı ayrı görünürler. Yalnız rapor; bir tür n ≥ 35 ve Wilson alt sınırı > %10 yanlış gösterirse ayrı bir ön kayıtla ele alınır |
| D8 | F1 düştü mü | Raporlanır; ürün kararı değildir. Ürün duruşu kesinlik önceliklidir; susturma kapsamı bilerek düşürür |

**Önceden bilinenler** (GT'siz, karar değil):
- `assert_ust` ve `func_aktarma` "kesin" etiketi taşımayacak (`ks1_onkayit.md:331-336`).
- Mac tmux'ta susan dokuz kanaldan 588 ad var (`alt_kanal_onkayit.md:148-158`, tmux 0,7 sütunu); 16'sının yerine `api_param_reverse` geçer, kalanı KS-1 almazsa `FUN_` olur. Kalan `string_context` adları `oz_ad` 126 ve `kebap_ad` 147 (`n2_onkayit_taslak.md:327`).
- Mac htop'ta susturmadan sonra `string_context` adı kalmaz (`alt_kanal_onkayit.md:151, 154`); KS-1 de yuva bulamıyor. Ürün htop'ta yalnız ön adlarla ad verir.

### 6.6 Çıktılar ve bütünlük

- `docs/arge/2026-11-10_n1_adim3/ablasyon_sonuc.json` ve `.md`: kol × birim tabloları, kapı sonuçları, künye (commit, bayraklar, girdi sha256'ları, Ghidra sürümü).
- Ölçüm betiği yeni bir dosyadır (ör. `scripts/measurement/ablasyon_olc.py`); sabit dosyaları içe aktarır, değiştirmez. Testli ve mutant kanıtlı.
- Eksiksizlik: her kolda beklenen ikili sayısı (Mac 2, Debian 117) birim başına denetlenir; eksik varsa ölçüm durur.
- GT yalnız bu betikte, yalnız ön kayıt commit'inden sonra okunur. GT'siz kapılar (§6.4) ön kayıttan önce de koşulabilir.

## 7. [seçim] maddeleri (özet)

| # | Madde | Öneri | Gerekçe | Yer |
|---|---|---|---|---|
| 1 | Susturma süzgecinin yeri | Ana süreçte, seçimden önce | Strateji değişmediği için ikinci dizgiye geçmek yapısal olarak imkânsız; donuk testler korunur | §3.3 |
| 2 | Alt kanal tanımının kaynağı | Ürün kopyası + eşitlik testi | Donuk betiğin sha256'sı ve ölçülen nüfus korunur | §3.2 |
| 3 | Köken şeması | Sürüm 1, yalnız alan eklenir | N2 ön koşulu donuk betiği yeni kayıt üzerinde koşturuyor | §4.2 |
| 4 | KS-1 çıkarımı | Ayrı adım (`kesin_anchors`) | Tohum iki kez çağrılıyor; çıkarım bir kez yapılmalı | §2.1 |
| 5 | KS-1 anahtarı | Yalnız `FUN_<onaltılık>` | `entry` gibi sözcüklerin genel değişimi dizgi literallerini bozar | §2.2 |
| 6 | Parça çapaları | Ad yok, yalnız kayıt | Aynı ad iki fonksiyona verilemez; parçalar kesinliğe girmiyor | §2.6 |
| 7 | `kesin` çıkmayan satır | Wilson kuralı: L > %10 susar, değilse "doğrulanmadı" | N0b ile aynı ölçüt; `oz_ad` kalırken daha iyi bir satır susmasın | §2.5 |
| 8 | Çok satırlı çapanın etiketi | En iyi satır | Ölçüm de çapayı her satırında sayıyor; ek kanıt güveni düşürmez | §2.5 |
| 9 | C++ ikilide KS-1 | Ad verir, "doğrulanmadı" | Verilen karar yalnız "kesin" etiketini yasaklıyor | §2.5 |
| 10 | Öncelik sırası | elle > main > KS-1 > Faz 1 > gnulib > önyük | Yükleyici bilgisi yapısal kanıttan, yapısal kanıt parmak izinden önce gelir | §2.8 |
| 11 | Künyeli ön adın yazımı | Olduğu gibi (`ks1` ve `elle`) | Temizleme tam adı bozuyor (`Vector_add` → `vector_add`) | §2.4 |
| 12 | Genel eşik | 0,7, c_namer'ın seçiminde, yalnız genel anahtar | Ad metne orada yazılıyor; eşik bugün hiçbir yerde uygulanmıyor | §4.4 |
| 13 | `DAT_` adları | Eşik altında kalır, `DAT_` bırakılır | `global_7ae0` ad değil, kısaltılmış adres | §4.5 |
| 14 | NameMerger'a aynı eşik | Evet | Susturmadan sonra öbür kaynaklar 0,30-0,70 arasında ad yazamasın | §4.4 |
| 15 | `api_param_reverse` halefi | Kalır, "doğrulanmadı"; karar N2'de | N0b bu kanal için karar yazmadı; G4'te n = 5 | §3.4 |
| 16 | KS-1 adının güven değeri | 0,95 (bütün ön adlar gibi) | Etiket anlamı taşıyor; yeni sayı uydurulmaz, kalibrasyon N6'da | §2.3 |
| 17 | Öbür ön ad türlerinin etiketi | "doğrulanmadı"; `elle` etiketsiz | Kanal başına ön kayıtlı ölçümleri yok | §2.8 |
| 18 | `export` çapaları | Ad atanmaz, etiket verilmez | Ad zaten Ghidra'nın; ön kayıtta karar satırı değil | §2.7 |
| 19 | Arayüzde etiket | Kanıt kartı ve liste rozeti | Kullanıcı adı listede görüyor; etiket orada olmalı | §4.3 |
| 20 | Davranışın açılması | Tek "aç" commit'i; adım 2 sonucu ve kapılardan sonra | Ondan önceki her commit geri alınmadan durabilir | §5.2 |
| 21 | Etiket değerlerinin yazımı | "kesin", "doğrulanmadı" (N0b ile aynı) | Tek sözlük; ikinci bir kod adı tutulmaz | §4.1 |
| 22 | Yapılandırma | Üç bayrak `BinaryReconstructionConfig`'te; susan küme ve satır tablosu ürün modülünde sabit | Bayraklar ablasyon için gerekli; kararlar kullanıcı ayarı olmamalı | §5.3 |
| A1 | Ablasyon kolları | 2 × 2 (KS-1 × susturma) | Etkiler ayrı ayrı ve birlikte görülür | §6.2 |
| A2 | Ablasyon nüfusu | Geliştirme setinin 10 birimi | KS-1'in ölçüldüğü küme; doğrulama setine bakılmaz | §6.3 |
| A3 | Kolların koşulması | Dondurulmuş Ghidra çıktısında yalnız adlandırma; eşdeğerlik kapısıyla | 468 tam koşu yerine dakikalar; kollar arasında Ghidra farkı olmaz | §6.2 |
| A4 | Doğru ad kaybı için inceleme sınırı | > %15 | N0b örneklemindeki beklentinin (≈ %6,5) iki katından fazlası hata işaretidir | §6.5 |

## 8. Önceki bulgularla ayrışanlar

| Önceki bilgi | Bulunan | Kanıt |
|---|---|---|
| "0,7 eşiğini NameMerger uyguluyor" | Uygulamıyor. `min_confidence` yalnız saklanıyor; fiilî eşik 0,30. c_namer adlarında fiilî eşik 0,15 | `name_merger.py:199-207, 237`; 9 217 `DAT_` adı 0,30 ile üründe |
| N0b: "rakip 0,7'nin altında: c_namer ad verir, NameMerger düşürür" (`alt_kanal_onkayit.md:181`) | NameMerger düşürse de ad `src/`'ye yazılmış olur | §1.1 satır 9 ve 13. Geliştirme setinde sonuç değişmiyor: bu rakiplerin hepsi agresif adaydır ve o kanal zaten susuyor (`kapsam.json` `halef_urun`) |
| Arayüz `karadul/ui/index.html`, gösterim "%100" | Dosya `ui/index.html`; gösterim `1.00` | `ui/index.html:1168, 1199` |
| Ön kayıt §10: "KS-1 çapaları `run_tarif`'in `kesin` girdisi olur ve NameMerger'da öncelik alır" (`ks1_onkayit.md:360`) | NameMerger önceliği metne ulaşmıyor; bağlama `pre_names`'ten | §1.2. Aynı bölüm bağlama biçimini adım 3'e bırakıyor (`:362`); sapma değil, belirleme |
| "`pre_names` adı olduğu gibi taşır" (örtük varsayım) | Küçültür, alt çizgi atar, yinelenen adı sessizce düşürür | `c_namer.py:474-493, 1920-1922` |

## 9. Doğrulanmayanlar

- Adım 2'nin sonucu: bilerek görülmedi. Sapma kaydı 1'in çapa kümesini ya da satır tanımlarını değiştirip değiştirmediği de okunmadı; §2.5'teki satır tablosu `ks1_olc.gorunum`'un 0da58cf'deki hâline göre yazıldı.
- KS-1 çıkarım süresi (Ö1).
- `kesinlik_tablosu.json`'ın şeması: açılmadı; §3.2 madde 5 uygulamada doğrulanır.
- `kayitlar_*.jsonl` alan adları: dosyalar açılmadı; alanlar `tests/test_alt_kanal.py:471-489`'dan okundu.
- `return_type` alanının `undefined` olması: 5 ikilide bakıldı (Mac tmux, htop; Debian cat, tmux, htop), 119'unda değil.
- `stages.py:4961-5037`'nin `struct_recovery` adımıyla çift koşup koşmadığı.
- `Config._from_dict`'in `binary_reconstruction` bloğundaki yeni alanları okuduğu: döngü `hasattr` ile genel; yeni alanlarla denenmedi.
- Yeni modüllerin uygulama paketine (Nuitka) girdiği (Ö8).
- x86-64 ve Mach-O dışı, ELF dışı ikililerde hattın uçtan uca davranışı.
- Koşum betiğinin (seçim A3) hatla eşdeğerliği: K-E ile sınanacak; bugün yalnız N0b `uret`'in benzer yaklaşımı var.
- N4'ün (fiil) bağlama tasarımı: `docs/arge/2026-11-10_n4/` okunmadı.

## 10. Bütünlük kaydı

**Bakılmadı:**
- GT: dbgsym `.debug` dosyaları, `*.gt.json`, `macho_score.json`, dSYM, `nm` çıktıları.
- `docs/arge/dogrulama_seti*`, `test_seti*`; G4 etiket verisi (`docs/arge/2026-10-19_g4_etiketleme/veri/`).
- N0b `kayitlar_*.jsonl`, `ters_eslesme_*.json`, `kesinlik_tablosu.json`.
- Adım 2'nin çıktıları: `ks1_olcum.json` ve `ks1_olcum.md` bu belge biterken ağaçta belirdi (commit'siz); açılmadı. §2.5'teki geçiş kuralı ve §6 onlardan önce yazıldı.
- `ks1_sapma_1.md` (yalnız commit başlığı görüldü: ELF ofsetinin kanıtlanma biçimi).

**Bakıldı:**
- Plan v2.2; KS-1 ön kaydı ve taslağı, `ks1_say.md`, `ks1_sabitler.json`; N0b ön kaydı, `kesinlik_tablosu.md`, `kapsam.json`; N2 taslağının susturma, yeni ad payı ve sıra bölümleri.
- Kod: `stages.py`, `c_namer.py`, `name_merger.py`, `aho_replacer.py`, `config.py`, `core/output_formatter.py`, `core/report_generator.py`, `pipeline/` (koşucu, bağlam, adlandırma adımları), `tarif/`, `ui/server.py`, `ui/index.html`, `scripts/measurement/alt_kanal.py`, `ks1_olc.py` (tanımlar), `function_f1.py` ve `macho_f1.py` (yalnız harita yükleme satırları).
- Karadul çıktıları (GT değil): 119 çalışma alanının `naming_provenance.json` ve `naming_map.json` dosyaları, beş ikilinin `ghidra_functions.json`'ı, üç koşunun `report.json` istatistikleri ve ürün `naming_map.json`'ı; tmux Mac'te ara dizinlerin dosya özetleri.

**Çalıştırılan:** yalnız salt okur sayım betikleri (JSON okuyup sayan Python; oturumun geçici dizininde). Karadul, Ghidra, ölçüm betiği ya da test koşulmadı; depodan modül içe aktarılmadı.

**Kazara görülen:**
- Koşu dizini listelerinde `macho_score.json` dosya adı (açılmadı).
- Sayım çıktılarında birkaç fonksiyon adı: Debian htop'ta Ghidra'nın dinamik simge tablosundan verdiği üç ad ve coreutils `cat`'te iki içe aktarım adı (`ghidra_functions.json`'dan; ürün girdisi), bir redis ön ad anahtarı. Hiçbiri gerçek adlarla karşılaştırılmadı.
- N0b ve N2 belgelerinde geçen örnek adlar (`close_stdout`, `fatal`).

**Tasarımı yazan:** bir LLM ajanı (Claude). Kararlar bu belgedeki [seçim] maddeleriyle açık bırakıldı; hiçbiri uygulanmadı.
