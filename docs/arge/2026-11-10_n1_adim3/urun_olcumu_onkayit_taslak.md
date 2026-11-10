# N1 adım 3: ürün adlarının GT'ye karşı ölçümü — ön kayıt taslağı

- **Tarih:** 2026-11-10.
- **Durum:** TASLAK. Yeni kol (kanıtlı adlandırma açık) henüz koşulmadı ve ölçülmedi. Bu belge, yeni kol GT'ye karşı okunmadan önce kesinleşip commit'lenmelidir. Taban kolun (eski ürün) sayıları bu taslakta açıktır; görülmesi serbestti.
- **[seçim] maddeleri:** 13 madde (§11). Her biri önerilen değer ve tek cümlelik gerekçeyle yazıldı; hiçbiri karara bağlanmadı.
- **Plan:** v2.2 §3 N1 ("bitince üründe susturma açılır") ve Kapı 1 ölçütü (`2026-10-21_plan_v2_2.md:70-72`); tasarım `baglama_tasarimi_taslak.md` §6 (ablasyon taslağı; D3, D4).
- **Dayanak:** KS-1 adım 2 (`../2026-10-21_g11_n1/ks1_sonuc.md`): `func_kalibi` kesin, `assert` kesin değil. N0b (`../2026-10-21_g10_n0b/kesinlik_tablosu.md`): dokuz alt kanal susar, `oz_ad` ve `kebap_ad` "doğrulanmadı" etiketiyle kalır.
- **Bu belgenin yapmadığı:**
  - Rubrikli (kör etiketli) yanlış oranı ölçümü. O ölçüm N2'dedir; burada LLM vekil etiketi yoktur.
  - KS-1 kesinliğinin bağımsız sınaması (aynı geliştirme seti).
  - N0b susturma kararının yeniden açılması.
- Bu belgede fonksiyon adı geçmez.

**Dosyalar** (sha256'ların ilk 16 hanesi, taslağın yazıldığı andaki hâl; kesin ön kayıtta tam değerler sabitlenmeli):

| Dosya | İçerik | sha256 (ilk 16) |
|---|---|---|
| `scripts/measurement/urun_olc.py` | `olc`, `karsilastir` | `06131cdc55f752bc` |
| `tests/test_urun_olc.py` | 32 test (sentetik çalışma alanı, sentetik GT) | `7ea45ab6417e096c` |
| `scripts/measurement/mutation_specs_urun_olc.json` | 65 mutant | `a68ad11acec14635` |
| `scripts/measurement/ks1_olc.py` | GT, adres eşlemesi, hüküm, Wilson, program sınıfı (içe aktarılır; değişmedi) | `975c4d1265d8610e` |
| `scripts/measurement/function_f1.py`, `macho_f1.py`, `macho_measure.py`, `tests/benchmark/metrics.py` | `ks1_olc.py`'nin yardımcıları (değişmedi) | `edc782981f98abc6`, `bc48eac6fe1f2879`, `d4d517fd43e835ea`, `114456c29af17fb9` |
| `karadul/core/naming_labels.py` | etiket sözlüğü, kanal adı (`provenance_channel`) | `f9c2e1d5e4b826ed` |
| `karadul/reconstruction/tarif/alt_kanal.py` | alt kanal sınıflayıcısı, susan küme | `d222c812f4be1805` |
| `urun_olcumu_taban.json`, `urun_olcumu_taban.md` | taban kolun ölçümü (§5) | `4f7dbe9927f0b0bf`, `36d6b46f223162c9` |

## 1. Amaç ve hipotezler

**Soru:** kanıtlı adlandırma (KS-1 çapaları, zayıf alt kanalların susturulması, ürün eşiği) açıldıktan sonra
1. ürünün verdiği fonksiyon adlarının ne kadarı yanlış,
2. "kesin" etiketli adlar ne kadar doğru,
3. ürün ad bekleyen fonksiyonların ne kadarına ad veriyor ve ne kadarına doğru ad veriyor,
4. eski ürüne göre kaç doğru ad kaybedildi, kaç doğru ad kazanıldı?

Cevap program ve boyut tabakası başına, tek koşuyla verilir ve eski ürünle (bayraklar kapalı) yan yana konur.

**Hipotezler** (yeni kol için; geliştirme seti, tam eşitlik):

| # | Hipotez | Beklenti (ölçümden önce) |
|---|---|---|
| H1 | "kesin" etiketli adların kesinliği, program düzeyi makro, ≥ %95 | Tutması beklenir: adım 2'de `func_kalibi` makrosu %97,3 çıktı ve "kesin" etiketini yalnız o satır veriyor. Sınırda: adım 2'de tmux'un program kesinliği %94,57 idi |
| H2 | Yanlış ad oranı, iki kolda da en az 10 ad verilen her birimde, tabandakinden düşük | Tutması beklenir: susan dokuz alt kanalın tabandaki tam ad kesinliği 14 / 4 321 (§5.4) |
| H3 | Yanlış ad oranı, program düzeyi makro, ≤ %10 | **Tutmaması beklenir** (§6): tam eşitlik gevşek rubrikten katıdır ve kalan kanalların tabandaki yanlış oranı makroda %68,6 |
| H4 | Kaybedilen doğru ad, tabandaki doğru adların %15'ini aşmaz | Tutması beklenir: susan kanallardaki doğru ad 14 / 1 184 (%1,2) |

H3'ün tutmaması bu ölçümün başarısızlığı değildir; ne anlama geldiği §7 (a) ve (d)'de önceden yazıldı.

## 2. Kollar ve girdi

| Kol | Ürün | Koşu kökü |
|---|---|---|
| taban | Eski ürün (KS-1, susturma ve genel eşik yok) | Debian `~/karadul_olcum/n1_debian13` (117 ELF, a10fde3); Mac `workspaces/olcum_mac/runs/ol7-a-9a36142` (tmux, htop) |
| yeni | Kanıtlı adlandırma açık (9. commit'ten sonraki ürün) | Aynı ikililerin yeni ürünle koşusu; kök komut satırından verilir; dizin yerleşimi tabanla aynı |

- **Okunan ürün çıktısı** (ikili başına): `reconstructed/src/naming_map.json`'ın `global` sözlüğü ve yanındaki `naming_provenance.json` (`urun_olc.haritayi_oku`); `static/ghidra_functions.json` (Ghidra adı ve adres).
  - **[seçim 5]** Ad haritası ilk yinelemeninkidir (`src/`, `src_iter1/` değil). Gerekçe: var olan puanlayıcılar da bu dosyayı okuyor (`function_f1.find_run_artifacts`); bütün ölçümler aynı haritaya bakar.
- **Kol kimliği çıktıdan okunur:** köken kaydının üst düzey `silencing.enabled` ve `global_min_confidence` alanları ikili başına sayılır (`kol_kimligi`). Taban kolda ikisi de yok: `{"genel_esik": null, "koken_var": true, "susturma": null}` × 118.
- **İki kol aynı dosyaları ölçmelidir:** `karsilastir`, ikili başına analiz edilen dosyanın sha256'sını (`raw/target_info.json`) iki kolda karşılaştırır; farklıysa ya da ikili yalnız bir koldaysa durur.
- **[seçim 7] Mac taban koşusu.** Verilen kök `ol7-a-9a36142`: belirlenimsizlik düzeltmesinden (b7faeac) önceki commit. Öneri: yeni kol ölçülmeden önce Mac tabanı `ol7-c-b7faeac` ile değiştirilsin. Gerekçe: düzeltme öncesi koşuda çakışma ekleri (`_2`) koşudan koşuya değişiyordu ve tam eşitlik eke duyarlıdır.
  - Boyutu: aynı betikle `ol7-a` ile `ol7-c` karşılaştırıldı (çıktı depoya yazılmadı). mac/tmux'ta 875 addan 3'ünün hükmü değişiyor (1 doğru → yanlış, 2 yanlış → doğru); mac/htop'ta 0. Kararları etkileyecek büyüklükte değil, ama yeni kolun farkına karışır.

## 3. Nüfus ve birimler

KS-1 ön kaydının geliştirme seti, aynı tanımlarla (`ks1_onkayit.md` §7): 8 açık kaynak program, 10 birim, 119 ikili.

- Debian 13 arm64: tmux, htop, tree, sqlite3, openssl (birer ELF), zstd (2), redis-tools (4), coreutils (106).
- Mac arm64: tmux, htop.
- Birim = platform/program (`ks1_olc.birim_anahtari`). Program düzeyinde aynı programın iki platformu tek programdır (tmux, htop).
- **C++ ikili** ölçülerin dışındadır (`ks1_olc.cpp_ikili_mi`): `pzstd`. Geriye 118 ikili kalır.
- **Eksiksizlik:** birim başına ikili sayısı `ks1_olc.BEKLENEN_ELF` ile denetlenir (`ks1_olc.nufus_denetle`). Eksik birim, `BITTI` dosyası olmayan Debian koşusu ya da ad haritası yazılmamış koşu (`urun_olc.haritasizlari_isaretle`) varsa ölçüm durur. `--eksik-izinli` ile sürer ve eksikleri listeler; böyle bir çıktıyla karar okunmaz.
- **Ad bekleyen nüfus** (kapsam paydası): `ks1_olc.GtBirimi.nufus`. GT fonksiyonu; o adreste Ghidra'nın thunk olmayan, jenerik adlı bir fonksiyonu var; CRT, export ya da klon değil (Mac'te sınıfı `program`). Toplam 21 371.
- **Program sınıfı** (eş değişken, GT'siz; `ks1_olc.sinif`): boyut tabakası (birimdeki ELF'lerin iç fonksiyon ortancası: < 500 küçük, < 2 000 orta, ≥ 2 000 büyük) ve dizgi zenginliği sınıfı (eşik 0,05). Sınıf başına hedef yoktur.
- Doğrulama ve test setlerine bakılmaz.

## 4. Ölçüler ve tanımlar

**Neyin adı ölçülür** (`urun_olc.degerlendir_elf`, `anahtar_sinifi`):
- Fonksiyon adı: `global` sözlüğünde anahtarı `FUN_<onaltılık>` olan giriş; adres anahtardan okunur.
- Veri adı (`DAT_`, `PTR_`, `UNK_` önekli anahtar) ve öbür anahtarlar yalnız sayılır; karar ölçülerine girmez.
- **[seçim 6]** Ölçüye girmeyen `FUN_` girişleri sayılır ve raporlanır: yeni ad anahtarın kendisi (`ozdes`); o adreste Ghidra fonksiyonu yok (`ghidra_yok`); Ghidra fonksiyonu zaten adlandırmış (`ghidra_adli`); ürünün adı adres etiketi (`jenerik_ad`; `function_f1.is_generic_name`). Gerekçe: soru "Ghidra'nın jenerik bıraktığı fonksiyonlara verilen adlar"dır; taban kolda bu girişler 6 394 ölçülen ada karşı 6 tanedir (hepsi `ghidra_adli`).

**Hüküm** (`ks1_olc.capa_degerlendir`; KS-1 ile aynı kural):
- GT adlarından en az biri eksiz (ana satır): ürün adı bir GT adına tam eşitse doğru. Mach-O'da GT adının baştaki tek `_`'ı soyulur. Büyük/küçük harf, önek ya da ek yok sayılmaz.
- GT adlarının hepsi derleyici ekli (klon satırı: `.isra`, `.constprop`, `.part`, `.cold`, `.lto_priv` …): ek soyulunca bulunan tabana tam eşitse doğru.
- GT'de o adreste fonksiyon yok (eşlenemedi): **yanlış**. Ürün o fonksiyona ad yazmıştır.
- **[seçim 1]** Karar ölçüleri tam eşitlikledir; proje normalleştirmesi (`function_f1.match_strict`: baştaki `_`, harf biçimi, sondaki `_<rakam>` eki yok sayılır) yalnız duyarlılık satırıdır. Gerekçe: KS-1 adım 2 ile aynı ölçüt; "kesin" iddiası tam ad iddiasıdır.

**Ölçüler** (`urun_olc.olcu`; örnek düzeyi):

| Ölçü | Tanım |
|---|---|
| Ad verilen | Ölçüye giren fonksiyon adı sayısı |
| Kesinlik (tam ad) | doğru / ad verilen |
| Yanlış ad oranı | yanlış / ad verilen |
| Kapsam | ad bekleyen nüfusta ad verilen / nüfus |
| Tam ad kapsamı | ad bekleyen nüfusta doğru / nüfus |

- **[seçim 2]** Kesinliğin ve yanlış oranının paydası ad verilen **bütün** fonksiyonlardır; nüfus dışındakiler de girer (CRT fonksiyonları, klonlar, GT'de karşılığı olmayanlar). Gerekçe: kullanıcı o adları da görür. Yalnız nüfustaki adların kesinliği duyarlılık satırıdır (`nufus_ici_kesinlik`).
- **[seçim 3]** Sayım örnek düzeyindedir (ikili başına ad). Gerekçe: üründeki karşılığı ikili başına ad almaktır; tasarım §6.3 ile aynı. Birim içinde aynı adı tek öğe sayan görünüm (bütün örnekleri doğruysa doğru) duyarlılık satırıdır (`tekil_kesinlik`).
- Birim başına her oran Wilson %95 aralığıyla verilir (`ks1_olc.oran`).
- **Havuz:** pay ve paydaların birimler üzerinden toplamı (`urun_olc.havuz`).
- **[seçim 4] Program düzeyi makro** (`urun_olc.makro_kesri`): paydası ≥ N_MIN = 10 olan birimler girer; aynı programın giren platform birimleri önce ortalanır, sonra programlar eşit ağırlıkla ortalanır. Karar için en az EN_AZ_PROGRAM = 2 farklı program girmelidir; girmezse `yetersiz`. Gerekçe: KS-1 karar kuralıyla aynı sayılar (`ks1_olc.N_MIN`, `EN_AZ_PROGRAM`); 106 ELF'li coreutils havuzu tek başına belirlemesin.

**Kırılımlar** (`urun_olc.birim_ozeti`, `toplam_ozeti`, `tabaka_ozeti`):
- Birim; boyut tabakası; zenginlik sınıfı.
- **Etiket** (`urun_olc.etiket_oku`): köken kaydındaki `label` ("kesin", "doğrulanmadı"); alan yoksa `etiketsiz`. Eski koşularda alan yoktur: taban kolun bütün adları `etiketsiz`.
- **Kanal** (`urun_olc.kanal_oku`; ürünün `provenance_channel` kuralı): `ks1:<satırlar>`, `on_ad:<tür>`, `string_context/<alt kanal>` ya da strateji adı.
  - Alt kanalı yazılmamış `string_context` kaydı (eski koşu) ürünün sınıflayıcısıyla sınıflanır (`alt_kanal.classify_record`). Yazılmışsa sınıflayıcıyla karşılaştırılır; uyuşmayan kayıt sayılır.
- **Kanal grubu** (`urun_olc.kanal_grubu`): `susan` = ürünün karar tablosunda susan dokuz `string_context` alt kanalı (`alt_kanal.SILENCED_SUBCHANNELS`); `kalan` = öbür bütün kanallar.

**Karşılaştırma** (`urun_olc.karsilastir`, `birim_farki`): öğeler birim, ikili ve adresle eşlenir; her adresin iki koldaki durumu `adsiz`, `dogru` ya da `yanlis`'tır.

| Fark | Tanım |
|---|---|
| Kaybedilen doğru ad | Tabanda doğru, yenide doğru değil (adı silinen + yanlışa dönen) |
| Kazanılan doğru ad | Yenide doğru, tabanda doğru değil |
| Giderilen yanlış | Tabanda yanlış, yenide yanlış değil |
| Yeni yanlış | Yenide yanlış, tabanda yanlış değil |
| Kayıp oranı | kaybedilen doğru / tabandaki doğru |

Kaybedilen adlar tabandaki kanallarıyla, kazanılanlar yenideki kanallarıyla sayılır.

**Çıktı:** JSON ve Markdown. Fonksiyon adı (ne ürünün adı ne GT adı) yazılmaz; yalnız sayılar ve, `karsilastir` eşleyebilsin diye, adres başına hüküm kodu (`ogeler`: durum, satır, nüfusta mı, etiket, kanal). Aynı girdi aynı çıktıyı verir (iki ayrı `PYTHONHASHSEED` ile bayt bayt aynı).

## 5. Taban kolun sayıları

Kaynak: `urun_olcumu_taban.json` ve `.md` (bu commit; betik `06131cdc55f752bc`, HEAD b0c972c, Ghidra 12.1.2, 119 ikili bitti, sorun yok). Bu sayılar eski ürünündür.

### 5.1 Toplam

| | Ad verilen | Doğru | Yanlış | Kesinlik | Yanlış oranı | Kapsam | Tam ad kapsamı |
|---|---|---|---|---|---|---|---|
| Havuz | 6 394 | 1 184 | 5 210 | %18,5 | %81,5 | 5 381 / 21 371 (%25,2) | 944 / 21 371 (%4,4) |
| Program düzeyi makro (8 program) | | | | %7,8 | %92,2 | %37,6 | %1,5 |

- Duyarlılık (havuz): nüfus içi kesinlik 944 / 5 381 (%17,5); proje normalleştirmesiyle doğru 1 423 / 6 394 (%22,3); tekil adla 233 / 3 599 (%6,5).
- Karar (a) taban kolda: makro yanlış %92,2 → `tutmuyor`. Karar (b): "kesin" etiketli ad yok → `yetersiz`.
- Veri adları: ölçülen 118 ikilide 9 118 veri anahtarının hepsine ad verilmiş (ölçülmez). Fonksiyon ya da veri olmayan anahtar 2.

### 5.2 Birim başına (küçükten büyüğe)

| Birim | İkili | Boyut | Zenginlik | Ad bekleyen | Ad verilen | Doğru | Yanlış | Yanlış oranı (Wilson %95) | Kapsam | Tam ad kapsamı |
|---|---|---|---|---|---|---|---|---|---|---|
| debian/coreutils | 106 | küçük | yoksul | 12 717 | 2 652 | 967 | 1 685 | %63,5 (%61,7-%65,3) | %17,1 | %5,9 |
| debian/tree | 1 | küçük | yoksul | 110 | 50 | 3 | 47 | %94,0 (%83,8-%97,9) | %40,9 | %0,9 |
| debian/sqlite3 | 1 | küçük | zengin | 389 | 151 | 3 | 148 | %98,0 (%94,3-%99,3) | %34,4 | %0,3 |
| debian/openssl | 1 | orta | zengin | 563 | 372 | 7 | 365 | %98,1 (%96,2-%99,1) | %62,7 | %0,9 |
| mac/htop | 1 | orta | zengin | 597 | 101 | 0 | 101 | %100,0 (%96,3-%100,0) | %16,9 | %0,0 |
| debian/htop | 1 | orta | zengin | 222 | 72 | 2 | 70 | %97,2 (%90,4-%99,2) | %27,5 | %0,0 |
| debian/zstd | 1 (+1 C++) | orta | yoksul | 919 | 594 | 5 | 589 | %99,2 (%98,0-%99,6) | %49,2 | %0,2 |
| debian/tmux | 1 | orta | zengin | 1 851 | 636 | 88 | 548 | %86,2 (%83,3-%88,6) | %33,2 | %4,4 |
| mac/tmux | 1 | büyük | zengin | 2 545 | 875 | 101 | 774 | %88,5 (%86,2-%90,4) | %33,7 | %3,9 |
| debian/redis-tools | 4 | büyük | yoksul | 1 458 | 891 | 8 | 883 | %99,1 (%98,2-%99,5) | %40,6 | %0,0 |

- Eşlenemeyen ad (GT'de karşılığı yok): mac/tmux 4, debian/redis-tools 2; öbür birimlerde 0.
- Klon satırındaki adlar (doğru / n): coreutils 1/58, tree 0/1, sqlite3 0/13, openssl 0/15, debian/htop 0/8, zstd 1/138, debian/tmux 5/17, mac/tmux 1/14, redis-tools 0/285.

### 5.3 Boyut tabakası ve zenginlik sınıfı

| Tabaka | Birimler | Ad verilen | Doğru | Yanlış oranı (havuz) | Makro yanlış | Kapsam (havuz) | Tam ad kapsamı (havuz) |
|---|---|---|---|---|---|---|---|
| küçük | coreutils, sqlite3, tree | 2 853 | 973 | %65,9 | %85,2 | %17,8 | %5,7 |
| orta | debian/htop, openssl, debian/tmux, zstd, mac/htop | 1 775 | 102 | %94,3 | %95,5 | %38,1 | %2,1 |
| büyük | redis-tools, mac/tmux | 1 766 | 109 | %93,8 | %93,8 | %36,2 | %2,5 |
| yoksul | coreutils, redis-tools, tree, zstd | 4 187 | 983 | %76,5 | %88,9 | %21,4 | %5,0 |
| zengin | iki htop, openssl, sqlite3, iki tmux | 2 207 | 201 | %90,9 | %95,5 | %34,4 | %3,0 |

Boyutla düzenli bir ilişki yok. Küçük tabakanın havuzdaki farkı coreutils'ten geliyor: doğru adlarının 937'si ön ad kanalındandır (§5.4).

### 5.4 Kanal başına (havuz)

| Kanal | Ad verilen | Doğru | Yanlış oranı | Üründeki kararı |
|---|---|---|---|---|
| `binary_extract` (ön adlar: `main`, CRT, gnulib parmak izi) | 1 420 | 963 | %32,2 | kalır |
| `string_context/oz_ad` | 332 | 207 | %37,7 | kalır, "doğrulanmadı" |
| `string_context/kebap_ad` | 266 | 0 | %100,0 | kalır, "doğrulanmadı" |
| `api_param_reverse` | 55 | 0 | %100,0 | kalır, "doğrulanmadı" |
| `string_context/tek_sozcuk` | 1 147 | 10 | %99,1 | susar |
| `string_context/hata_iletisi` | 789 | 1 | %99,9 | susar |
| `string_context/bicim_dizgisi` | 714 | 2 | %99,7 | susar |
| `string_context/duz_metin` | 658 | 0 | %100,0 | susar |
| `string_context/diger` | 437 | 0 | %100,0 | susar |
| `string_context/tanimlayici` | 303 | 1 | %99,7 | susar |
| `string_context/kod_parcasi` | 196 | 0 | %100,0 | susar |
| `string_context/bicim_parcasi` | 60 | 0 | %100,0 | susar |
| `string_context/agresif` | 17 | 0 | %100,0 | susar |

| Kanal grubu | Ad verilen | Doğru | Yanlış oranı (havuz) | Makro yanlış | Kapsam (havuz) | Tam ad kapsamı (havuz) |
|---|---|---|---|---|---|---|
| `susan` | 4 321 | 14 | %99,7 | %99,8 | 3 801 / 21 371 (%17,8) | 14 / 21 371 (%0,1) |
| `kalan` | 2 073 | 1 170 | %43,6 | %68,6 | 1 580 / 21 371 (%7,4) | 930 / 21 371 (%4,4) |

- 4 919 `string_context` adının hepsinde alt kanal sonradan sınıflandı (eski koşu; kayıtta alan yok); kayıtla uyuşmazlık tanımsız.
- GT'siz çapraz denetim: mac/tmux'ta susan gruptaki ad sayısı 588, `oz_ad` 126; N0b'nin ve tasarımın GT'siz sayımlarıyla aynı (`baglama_tasarimi_taslak.md` §6.5).
- `oz_ad` birim başına (doğru / ad verilen; `urun_olcumu_taban.json`, `birimler.*.ozet.kanal`): mac/tmux 96/126, debian/tmux 80/96, coreutils 27/40, zstd 1/52, openssl 3/7, sqlite3 0/7, redis-tools 0/3, debian/htop 0/1. tmux dışında kanalın tam ad kesinliği düşük; N0b'nin kararı tmux ve htop örneklemine dayanıyordu.

### 5.5 Rubrikli ölçümle ilişkisi

G4'ün kör etiketli (rubrik sürüm 2) yanlış oranı eski üründe tmux'ta %45,5, htop'ta %81,4 idi (`../2026-10-19_g4_etiketleme/sonuc.md` §1; Mac, koşu `taban-v2-62ad154`, payda nüfustaki adlar). Aynı programların buradaki tam eşitlikli yanlış oranı: mac/tmux %88,5, mac/htop %100,0. Fark, rubriğin "yanlış" saymadığı ama tam ad da olmayan adlardır (doğru tarif, yalnız alan). İki sayı aynı şeyi ölçmez; birbirinin yerine kullanılmaz.

## 6. Yeni kol için ölçümden önce bilinenler

Hepsi taban kolun sayılarından ve GT'siz belgelerden; yeni kolun çıktısına bakılmadı (yok).

1. **Susturmanın tek başına bırakacağı adlar** `kalan` grubudur (§5.4): 2 073 ad, yanlış oranı havuzda %43,6, program düzeyi makroda %68,6. KS-1'in ekleyeceği adlar ve halefler (susan adayın yerine geçen `api_param_reverse`) bu sayıda yok.
2. **Makroya girecek birimler azalır.** `kalan` grubunda 10'dan az adı olan birimler: debian/tree (5), debian/htop (5), mac/htop (0). KS-1 bu programlarda yuva bulamıyor (`ks1_sonuc.md` §2); yeni kolda htop ve tree karar (a)'nın makrosuna girmeyebilir.
3. **"kesin" etiketi** yalnız `func_kalibi` satırından gelir. Adım 2'de bu satırın tekil çapa sayısı: mac/tmux 150, debian/tmux 97, debian/openssl 15. Karar (b)'ye girebilecek programlar: tmux ve openssl (2 program; alt sınırda).
4. **Tam eşitlikte doğru olamayacak kanallar:** `kebap_ad` (ad dizgiden türetilir, fonksiyon adı değildir; 0 / 266) ve `api_param_reverse` (rol adı; 0 / 55). Bu iki kanal üründe kalıyor; yeni kolun tam eşitlikli yanlış oranını yukarı çeker. Rubrikte `kebap_ad`'ın yanlış oranı %10,8 idi (N0b; tam %0,0).
5. **Ön adların yazımı:** `binary_extract` adları temizlenerek yazılıyor (baştaki alt çizgiler atılıyor); CRT fonksiyonlarının bir bölümü bu yüzden tam eşitlikte yanlış. Proje normalleştirmesi satırı bunu gösterir (taban havuzda %18,5 → %22,3).
6. **Veri adları:** genel eşik `DAT_` adlarını düşürür (tasarım [seçim 13]); yeni kolda veri adı sayısının 9 118'den 0'a inmesi beklenir.
7. **Kapsam düşer.** Taban kapsamı %25,2'nin 17,8 puanı susan gruptan; tam ad kapsamı %4,4'ün 0,1 puanı.

## 7. Önceden yazılmış kararlar

Kararlar yeni kol ölçüldükten sonra `urun_olc.py`'nin çıktısından mekanik okunur (`kol_kararlari`, `karsilastir`). Eşikler betiğin başındaki sabitlerdir.

### (a) Fonksiyon adlarının yanlış oranı

- **[seçim 8]** Hedef: yeni kolda yanlış ad oranı, program düzeyi makro, **≤ %10** (`YANLIS_HEDEFI`). Gerekçe: plan Kapı 1'in sayısı; ikinci bir sayı uydurulmaz.
- **Bu ölçüt Kapı 1'in ölçütünden katıdır.** Kapı 1 "yanlış"ı rubrikle sayar: doğru tarif ve yalnız alan adları yanlış değildir. Burada tam ad olmayan her ad yanlıştır. Tam eşleşen ad rubrikte yanlış sayılmadığı için tam eşitlikli yanlış oranı, aynı adların rubrikli yanlış oranı için üst sınır niteliğindedir:
  - `tutuyor` (≤ %10): geliştirme setinde rubrikli yanlış oranı da ≤ %10 olur. Yeterli koşul.
  - `tutmuyor` (> %10): rubrikli oran hakkında bir şey söylemez. Karar N2'nin rubrikli ölçümüne kalır.
- **Beklenti:** `tutmuyor` (§6). Bu, H3'ün tutmaması demektir ve §7 (d) dalı 2 ile işlenir.
- **[seçim 9] Yön koşulu** (tasarım D3): iki kolda da en az 10 ad verilen her birimde yeni kolun yanlış oranı tabanınkinden düşük olmalı (eşit oran düşmüş sayılmaz). Gerekçe: susturma ve KS-1'in işe yaradığının en zayıf, eşiksiz göstergesi. Tutmayan birim için kanal tablosu okunur ve kayda geçer.
- Alternatif (önerilmiyor): hedefi yalnız "kesin" etiketli adlara uygulamak. O soru zaten (b)'dir.

### (b) "kesin" etiketli adların kesinliği

- **[seçim 10]** Yeni kolda "kesin" etiketli adların tam ad kesinliği, program düzeyi makro, **≥ %95** (`KESIN_ETIKET_ESIGI` = `ks1_olc.KESINLIK_ESIGI`). Giren birim: en az 10 "kesin" etiketli ad; en az 2 farklı program. Gerekçe: etiketin anlamı bu eşiktir (`naming_labels.py`); KS-1 adım 2 ile aynı sayı.
- Wilson üst sınırı %95'in altında kalan giren birimler listelenir (`wilson_ihlali`); bu taslakta karara girmez. Alternatif: KS-1 kuralındaki gibi karara katmak (o zaman tek bir kötü birim kararı düşürür).
- Adım 2 ile fark (tasarım D2): üründeki "kesin" adlar adım 2'nin `func_kalibi` çapalarıdır. Sayı ya da kesinlik farkı varsa her farklı öğe nedeniyle sayılır (temizleme, ezilme, atlama, örnek düzeyi ile tekil sayım farkı). Açıklanamayan fark bağlama hatasıdır.

### (c) Kaybedilen doğru ad

- **[seçim 11]** İnceleme sınırı: kayıp oranı **> %15** (`KAYIP_INCELEME_SINIRI`; tasarım [seçim A4]). Havuzda aşılırsa ya da tabanda en az 10 doğru adı olan bir birimde aşılırsa sonuç `incele`. Gerekçe: susan kanallardaki doğru ad tabanda 14 / 1 184 (%1,2); %15 bunun çok üstündedir ve ancak bir taşıma ya da süzgeç hatası açıklar. Birim koşulu, tabandaki doğru adların %82'sini taşıyan coreutils (967 / 1 184) öbür birimleri örtmesin diyedir.
- Tabanda en az 10 doğru adı olan birimler: coreutils (967), mac/tmux (101), debian/tmux (88). Susan gruptaki doğru adları: 3, 5, 5.
- `incele` çıkarsa: kaybedilen adların taban kanalı okunur (`kayip_kanali`). Kayıp susan kanallardansa beklenen bedeldir ve kayda geçer. Kalan kanallardan (`binary_extract`, `oz_ad`) doğru ad kaybı varsa sınıflayıcı taşıması, ön ad önceliği ve süzgeç incelenir. N0b kararı değişmez.

### (d) Tutmazsa ne olur

**[seçim 12]** Dallar, öncelik sırasıyla:

| # | Durum | Derleme | Ürün ve kayıt |
|---|---|---|---|
| 1 | Ölçüm durdu ya da bütünlük koşullarından biri tutmadı (aşağıda) | Yapılmaz | Ölçüm okunmaz. Neden giderilir, yeni kol yeniden koşulur |
| 2 | (b) `tutmuyor` ya da `yetersiz` | Yapılmaz | "kesin" etiketi gösterilemez. Önce (b)'deki adım 2 farkı açıklanır. Açıklanamazsa ya da kesinlik gerçekten < %95 ise `func_kalibi` satırı "doğrulanmadı"ya indirilir (KS-1 satır tablosu) ve ölçüm yinelenir |
| 3 | (c) `incele` ve kayıp kalan kanallardan | Bekler | İnceleme bitene kadar derleme yok; hata bulunursa düzeltilip yeniden ölçülür |
| 4 | (a) `tutmuyor`, (b) `tutuyor` (beklenen durum) | Yapılır | Adlar etiketleriyle gösterilir. Sürüm notunda ve arayüzde "ürün yanlış ad vermiyor" denmez. Yazılabilecek iddia: "kesin" etiketli adların ölçülen kesinliği ve kapsamı. "doğrulanmadı" adlar için ölçülen tam ad kesinliği sayıyla yazılır. Sonuç Kapı 1 öncesi risk olarak plana işlenir |
| 5 | Yön koşulu tutmadı | Yapılır | O birimin kanal tablosu okunur, kayda geçer. Ürün kararı değişmez (karar N0b ve adım 2'dedir) |
| 6 | (a), (b) `tutuyor`, (c) `beklenen_aralikta` | Yapılır | İddia: geliştirme setinde tam eşitlikle yanlış ad ≤ %10. Kapı 1'in yerini tutmaz (doğrulama seti, rubrik) |

Gerekçe: üründeki tek güçlü iddia "kesin" etiketidir; o tutmuyorsa derleme yanlış bir iddia taşır. "doğrulanmadı" adlar iddia taşımaz; hangi kanalların kalacağı rubrikli ölçümle (N0b) verildi ve bu ölçüm o kararı açmaz.

Dal 4 için Berke'nin ayrıca karar vermesi gereken soru (bu taslak önermiyor, yalnız işaretliyor): "doğrulanmadı" adların üründe öntanımlı olarak gösterilip gösterilmeyeceği. Taban sayılarında üründe kalacak kanalların tam ad kesinliği kanala göre %0 ile %68 arasında (`kebap_ad` ve `api_param_reverse` %0; `oz_ad` %62,3; ön adlar %67,8).

### Bütünlük koşulları (GT'siz; yeni kolun çıktısından okunur)

**[seçim 13]** Biri tutmazsa ölçüm geçersizdir (dal 1). Gerekçe: bunlar kolun gerçekten yeni ürün olduğunu gösterir; tutmuyorsa ölçülen şey sorulan şey değildir.

| # | Koşul | Çıktıdaki yeri |
|---|---|---|
| B1 | 119 ikili bitti, sorun yok; `--eksik-izinli` kullanılmadı | `nufus` |
| B2 | Kol kimliği 118 ikilide aynı: susturma açık, genel eşik 0,7 | `kol_kimligi` |
| B3 | Susan grupta ad yok (`susan` grubu: 0 ad) | `toplam.kanal_grubu` |
| B4 | Kayıttaki alt kanal ürün sınıflayıcısıyla her kayıtta aynı (uyuşmayan 0); alt kanalı sonradan sınıflanan kayıt 0 | `anahtar_sayaci` |
| B5 | "kesin" etiketli her adın kanalı `ks1:` ile başlıyor ve satırları arasında `func_kalibi` var | `etiket_kanal` (etiket × kanal çapraz sayımı) |
| B6 | İki kol aynı dosyaları ölçtü; Ghidra sürümleri aynı | `karsilastir`: `sorunlar`, `ghidra_ayni` |

Betik bu koşulları hesaplayıp yazar, ama kendisi "geçti / kaldı" demez; okuyan oturum tabloyu çıktıyla karşılaştırıp kayda geçirir.

## 8. Koşum

```
# yeni kol (ana ağaçtan; worktree'den koşulursa --mac-veri verilmeli)
python scripts/measurement/urun_olc.py olc --kok-debian <yeni kök>/debian --kok-mac <yeni kök>/mac \
    --kol yeni --json docs/arge/2026-11-10_n1_adim3/urun_olcumu_yeni.json \
    --md docs/arge/2026-11-10_n1_adim3/urun_olcumu_yeni.md
python scripts/measurement/urun_olc.py karsilastir \
    --taban docs/arge/2026-11-10_n1_adim3/urun_olcumu_taban.json \
    --yeni docs/arge/2026-11-10_n1_adim3/urun_olcumu_yeni.json \
    --json docs/arge/2026-11-10_n1_adim3/urun_olcumu_fark.json \
    --md docs/arge/2026-11-10_n1_adim3/urun_olcumu_fark.md
```

- Taban kol şu komutla ölçüldü: `olc --kok-debian ~/karadul_olcum/n1_debian13 --kok-mac /Users/apple/Black_Widow/workspaces/olcum_mac/runs/ol7-a-9a36142 --mac-veri /Users/apple/Black_Widow/workspaces/olcum_mac --kol taban`. Süre ≈ 7 sn.
- GT yolları: Mac `--mac-veri` (öntanımlı `<depo>/workspaces/olcum_mac`), Debian `--debian-indir` (öntanımlı `~/karadul_olcum/downloads/debian13`).
- Betik `karadul` paketinin kendi deposundan yüklendiğini denetler; değilse içe aktarmada durur (worktree ve editable kurulum tuzağı).
- **Betik ön kayıt commit'ini ve sha256'ları kendisi denetlemiyor** (`ks1_olc.py olc` denetliyordu). Kesin ön kayıtta bu ya betiğe eklenmeli ya da ölçümü yapan oturum sha256'ları elle karşılaştırıp kayda yazmalıdır.
- Testler: `python -m pytest tests/test_urun_olc.py -q -p no:cacheprovider` → 32 geçti. Mutantlar: `PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec scripts/measurement/mutation_specs_urun_olc.json` → 65 mutant, 65'i öldü; 58'i doğrulama (assert) başarısızlığıyla, 7'si beklenen istisnanın atılmamasıyla ("DID NOT RAISE"). Mutant uzunlukları özgününden farklı.

## 9. Bilinen sınırlar

1. **LLM vekil etiketi yok.** Ölçüm yalnız tam eşitliktir. "Yakın" ad, doğru tarif ya da doğru fiil sayılmaz. Bu yüzden (a) Kapı 1'in ölçütü değildir (§7 a) ve ürünün gevşek moddaki başarısını ölçmez.
2. **Tam eşitlik katıdır.** Çakışma eki (`_2`), temizlenmiş ön ad (baştaki alt çizgi), harf biçimi farkı yanlıştır. Proje normalleştirmesi satırı bunun boyutunu gösterir; karar dışıdır.
3. **Klonlar.** GT'nin bütün adları derleyici ekliyse taban eşitliği doğru sayılır; ürün klona özgün fonksiyonun adını verirse doğrudur. Klonlar ad bekleyen nüfusta değildir: kapsamı artırmaz, kesinliğe girer. Taban kolda klon satırında 549 ad var, 8'i doğru; 285'i redis-tools'ta (`.lto_priv`).
4. **Aynı dosya olan iki redis ikilisi.** `redis-check-aof` ve `redis-check-rdb` bayt bayt aynı dosya; KS-1 ön kaydındaki gibi ayrı ikili sayılıyor (yeni bir seçim değil; KS-1 kuralı aynen). Betik bunları `ayni_dosyalar` altında listeler. redis-tools'un sayıları bu yüzden bir ikiliyi iki kez içerir.
5. **Aynı iki ikili libstdc++'a bağlı** ama C++ işaretini taşımıyor (`ks1_sonuc.md` §4); ölçüde kalıyorlar.
6. **coreutils.** 106 ELF aynı gnulib fonksiyonlarını paylaşır; örnek düzeyinde aynı ad 106 kez sayılabilir. Program düzeyi makro bunu tek programa indirir; havuz indirmez. Tekil satır duyarlılıktır.
7. **Geliştirme setine uyum.** KS-1 kuralları ve N0b kararı bu programlarda kuruldu. Buradaki "kesin" kesinliği bağımsız bir sınama değildir; o sınama Kapı 1 ve Kapı 2'dedir.
8. **Yineleme.** Ölçülen harita ilk yinelemeninkidir; temiz çıktıyı yazan biçimlendirici son yinelemeyi okur (tasarım §5.6 madde 7). İki harita arasındaki fark bu ölçümde görünmez.
9. **c_namer dışı kaynaklar.** `merged/` altında başka kaynaklardan gelen fonksiyon adı varsa (tasarım K-D) bu ölçüm onları görmez.
10. **Ad bekleyen nüfus GT'ye bağlıdır.** Ghidra'nın bulamadığı fonksiyonlar nüfusta değildir; kapsam "Ghidra'nın bulduğu ve jenerik bıraktığı" fonksiyonlara göredir.
11. **Kanal kırılımı tabanda sonradan sınıflamaya dayanır.** Taban kolun alt kanalları bugünkü ürün sınıflayıcısıyla hesaplandı; sınıflayıcı değişirse taban kırılımı da değişir. Karar ölçüleri kanala bağlı değildir.
12. **Mac tabanı düzeltme öncesi commit'ten** (§2, [seçim 7]).
13. **Wilson aralıkları** örnek düzeyinde bağımsızlık varsayar; coreutils'te öğeler bağımsız değildir. Aralıklar orada iyimserdir.

## 10. Bütünlük kaydı

**Bakıldı:**
- Geliştirme setinin GT'si (dbgsym, Mac GT dosyaları), yalnız betik aracılığıyla; taban kolun 119 çalışma alanı (`naming_map.json`, `naming_provenance.json`, `ghidra_functions.json`, `report.json`).
- Elle denetim: beş ikilide (debian tree, htop, redis-cli, cat; mac htop) hükümler ürün adı ve GT adı yan yana, uçbirimde okundu; dosyaya yazılmadı. Hükümler kurala uygundu.
- Çapraz sayım: Mac'te var olan puanlayıcının çıktısı (`macho_score.json`, koşu `ol7-a`). tmux: nüfus 2 545, nüfusta ad verilen 857, soğuk ve dışlanmış parçalarda 14 ad; betiğin sayılarıyla aynı. Proje normalleştirmesiyle doğru 105 (puanlayıcı: 104 + 1); tam eşitlikle 101.
- Belgeler: plan v2.2, KS-1 ön kaydı ve sonucu, tasarım taslağı §4-§10, G4 sonucu §1, N0b kesinlik tablosunun `oz_ad` ve `kebap_ad` satırları.

**Bakılmadı:**
- `docs/arge/dogrulama_seti*`, `test_seti*`, `dogrulama_seti_kanit/`, `targets/`.
- Yeni kolun çıktısı (yok). G4 etiket verisi (`veri/`), N0b kayıt dosyaları.

**Çalıştırılan:** `urun_olc.py` (taban kol; iki kez, çıktılar aynı), `ol7-a` ile `ol7-c` karşılaştırması (çıktı depoya yazılmadı), testler, mutant koşusu. Karadul ve Ghidra koşturulmadı.

**Yazan:** bir LLM ajanı (Claude). Eşikler ve dallar öneridir; karar ana oturumun ve Berke'nindir.

## 11. [seçim] maddeleri (özet)

| # | Madde | Öneri | Gerekçe | Yer |
|---|---|---|---|---|
| 1 | Hüküm | Tam eşitlik; proje normalleştirmesi yalnız duyarlılık | KS-1 adım 2 ile aynı ölçüt | §4 |
| 2 | Kesinliğin paydası | Ad verilen bütün fonksiyonlar (nüfus dışı dahil) | Kullanıcı o adları da görür | §4 |
| 3 | Sayım düzeyi | Örnek düzeyi (ikili başına ad); tekil duyarlılık | Üründeki karşılığı ikili başına ad | §4 |
| 4 | Makro | Program düzeyi; N_MIN = 10; en az 2 program | KS-1 karar kuralıyla aynı sayılar | §4 |
| 5 | Ad haritası | İlk yineleme (`reconstructed/src`) | Var olan puanlayıcılarla aynı dosya | §2 |
| 6 | Ölçüye girmeyen girişler | `ozdes`, `ghidra_yok`, `ghidra_adli`, `jenerik_ad` sayılır, ölçülmez | Soru Ghidra'nın jenerik bıraktığı fonksiyonlar | §4 |
| 7 | Mac taban koşusu | `ol7-c-b7faeac` ile değiştir | Düzeltme öncesi koşuda ekler belirlenimsiz; tam eşitlik eke duyarlı | §2 |
| 8 | (a) yanlış oranı hedefi | Makro ≤ %10; tutması beklenmiyor | Kapı 1'in sayısı; tam eşitlikte yeterli koşul | §7 a |
| 9 | (a) yön koşulu | Her n ≥ 10 birimde tabandan düşük | Eşiksiz, en zayıf etki göstergesi | §7 a |
| 10 | (b) "kesin" kesinliği | Makro ≥ %95; Wilson ihlali yalnız rapor | Etiketin anlamı bu eşik | §7 b |
| 11 | (c) kayıp sınırı | > %15, havuzda ya da n ≥ 10 birimde | Beklenti %1,2; aşan ancak hatayla açıklanır | §7 c |
| 12 | (d) dallar | (b) tutmazsa derleme yok; (a) tutmazsa derleme var, iddia yok | Tek güçlü iddia "kesin" etiketi | §7 d |
| 13 | Bütünlük koşulları | B1-B6; biri tutmazsa ölçüm geçersiz | Kolun gerçekten yeni ürün olduğunun kanıtı | §7 |
