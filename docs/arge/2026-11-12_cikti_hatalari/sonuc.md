# Çıktı dürüstlüğü ve sağlamlığı: dün görülüp dokunulmayan beş hata (2026-11-12)

> Girdi: `docs/arge/2026-11-11_cikti_kucuk_hatalar/sonuc.md` (dünkü onarım) ve
> `docs/arge/2026-11-10_cikti_saglamligi/yeni_urun_karsilastirma.md` (süren kusurlar). Beş kalemin
> dördü yeniden üretildi ve onarıldı (her biri ayrı commit); beşincisi (`$` taşıyan ad) bugünkü kodda
> yeniden üretilemedi (§1.5). Bu belgedeki her sayı aşağıdaki komutların çıktısıdır; GT ve kör
> setlere bakılmadı.

"Önce" kodu `2be12ed` (sürüm 1.22.2), "sonra" kodu `fe8dcfb` (bu dalın son kod commit'i; ardından
yalnız test sıkılaştırması `3723d2a` ve bu belge). Commit'ler: `964e0d8` (kalem 2), `f339422`
(kalem 1), `59146e8` (kalem 3), `fe8dcfb` (kalem 4).
Ölçüm kökü `R = ~/karadul_olcum/runs/cikti-hatalari-2026-11-12`, betikler `$R/betikler/`.
Satır numaraları "önce" kodundadır.

## 1. Kalemler

### 1.1 Strateji bölümünde "Signature Database (FLIRT)" (commit `f339422`)

- **Belirti:** temiz çıktının `report.html` strateji bölümü: "Signature Database (FLIRT) — 133
  functions matched — Known library functions identified via byte signatures."
- **Sayı nereden:** `pipeline/steps/ghidra_metadata.py:218` `ctx.stats["signature_matches"] =
  len(sig_matches)`; liste `SignatureDB.match_all`'ın dönüşü. (Aynı kayıt `stages.py:1651`'de de
  yazılıyor ama o yol emekli: `stages.py:3085-3098` `use_step_registry=False`'u adım yoluna çeviriyor.)
- **Neyi sayıyor:** `match_all` her Ghidra fonksiyonu için `match_function`'ı `func_bytes=None` ile
  çağırır (`analyzers/signature_db.py:2739`): bayt imzası hiç karşılaştırılmaz, FLIRT kullanılmaz
  (FLIRT yalnız ayrı `byte_pattern` adımında). Kalan yollar: `symbol` (fonksiyonun Ghidra'daki var
  olan adı veritabanında aranır, `:1939-2074`; aday ad = aynı ad, baştaki `_` soyulmuş), `string_ref`,
  `call_pattern`. `$R/betikler/imza_yontem.py` aynı girdilerle `match_all`'ı yeniden koşup yöntemleri
  saydı; yeniden hesaplanan çoklu küme kayıttakiyle aynı (`$R/imza_yontem_tree_once.txt`):

  | Debian tree | sayı |
  |---|---|
  | kayıt | 133 |
  | `symbol` (var olan adın aranması; aday = özgün ad, `_` soyulmuş) | 128 |
  | `string_ref` (`FUN_0010d1a8 → parse_xml`, `FUN_0010e4c4 → parse_html`) | 2 |
  | `call_pattern` (üç `FUN_… → copy_buffer`) | 3 |
  | tekil (özgün, aday) / tekil adres | 70 / 133 |

- **Düzeltme:** `report_generator.py` satır adı "Signature Database Lookup"; etki "N matches"
  ve kayıtlar yöntem taşıyorsa yönteme göre döküm; açıklama bayt karşılaştırılmadığını ve
  eşleşmenin koda uygulanmasının denetlenmediğini söyler. Döküm için kayda `method` alanı eklendi
  (`ghidra_metadata.py` ve eşlik için `stages.py`). Döküm yalnız kayıt sayısı aşamanın sayısıyla
  aynıysa ve her kayıt yöntem taşıyorsa yazılır; eski kayıtta yalnız sayı (uydurulmaz).
  Aynı bölümdeki "Binary Name Extraction — N names recovered" da aday sayısıydı
  (`reconstructed/binary_names.json`'daki çıkarılan ad sayısı): "N name candidates".

### 1.2 `signature_matches.json` adres taşımıyordu (commit `964e0d8`)

- **Yeniden üretim:** tree, `2be12ed`: 133 kayıt, 63'ü bir başkasıyla bayt bayt özdeş, 70 tekil
  (`$R/tree_once_a`). Örnek: Ghidra `getcwd` için iki thunk veriyor (`00103d00` PLT, `00135010` dış
  blok), ikisi aynı kayıt.
- **Kök neden:** `SignatureMatch.address` zaten var ve `match_all` dolduruyor
  (`signature_db.py:2746`); kaydı yazan iki yer alanı yazmıyordu: etkin yol
  `pipeline/steps/ghidra_metadata.py:224-232` ve emekli monolit yolu `stages.py:1656-1660`.
  **Not:** görevde gösterilen yer (`stages.py` ≈1645–1660) emekli yoldur; yalnız orayı düzeltmek
  gerçek koşuyu değiştirmezdi. İkisi de düzeltildi (eşlik testi `tests/test_stages_split_parity.py`
  monolit yöntemini hâlâ çağırıyor). `analyzers/` değişmedi.
- **Düzeltme:** kayıt `address` (ve 1.1 için `method`) taşır.
- **Okuyucular** (`grep -rn signature_matches` — `karadul`, `ui`, `scripts`, `docs`, `tests`):

  | Okuyucu | Okuduğu alan | Durum |
  |---|---|---|
  | `core/output_formatter.py:604-615` (`_build_naming_map`) | `original`, `matched`, `confidence`, `library` | değişmedi; test: harita adresli/adressiz kayıtla aynı |
  | `core/report_generator.py:743-751` (`_collect_naming_data`, HTML aday tablosu) | aynı dört alan | değişmedi; tablo özdeş satırı yine teke indirir (tabloda adres sütunu yok; yorum güncellendi) |
  | `ui/server.py:653-677` (`_signature_candidates`) | yalnız `original` | **dokunulmadı**; test: aday kümesi aynı |
  | `docs/arge/2026-11-10_cikti_saglamligi/denetle.py:693` | `total`, `len(matches)` | etkilenmez |
  | `docs/arge/2026-11-11_fonksiyon_karti/envanter_sayim.py:365` | `original` | etkilenmez |
  | `reporting/html_report.py:570`, `reporting/markdown_report.py:708` | `static/signature_matches.json` (başka dosya) | ilgisiz; bu dosyayı yazan yok (yan bulgu §6) |

### 1.3 Genel dal C++'ta dosyaları eziyordu (commit `59146e8`)

- **Yeniden üretim** (`$R/betikler/genel_dal_cakisma.py`, ürün koşusunun pzstd'si, salt okunur):
  `~/karadul_olcum/runs/urun-yeni-93a2956/debian/zstd/pzstd` — `identify.language = "cpp"`.
  `reconstructed/` altında 12 757 kaynak dosyası, 1 201 tekil ad; `out/src` 1 201 dosya. 1 158 adın
  birden çok kaynağı var ve hepsinin içerikleri farklı; 11 556 kopya üstüne yazıldı. Kazanan
  (sıralı kopyada son gelen) 1 157 adda `typed_iter1`, 1'inde `project`. Örnek:
  `FUN_00103050.c` 11 kaynaktan (`annotated/`, `commented/`, `merged/`, `merged_iter1/`,
  `project/src/subsystem_misc/`, `semantic_named/`, `src/`, `struct_recovered/`,
  `struct_recovered/originals/`, `typed/`, `typed_iter1/`) gelir; kalan `typed_iter1` kopyası.
  119 ikililik ürün kümesinde dili `cpp` olan tek ikili pzstd (öbürleri `unknown` → C dalı).
- **Koşul:** `output_formatter.py:193-200`: dil `c`, `javascript`, `swift` değilse genel dal;
  `:556-559` her dosyayı `src_dir / f.name`'e kopyalar. Ghidra her ikiliden C ürettiği için
  C++ (Rust, Go …) ikilinin kaynağı da C'dir ve C dalının olgun proje ağacı (`reconstructed/project`)
  kullanıcıya hiç gitmiyordu.
- **Düzeltme:** `reconstructed/` altındaki kaynaklar yalnız C ise (en az bir `.c`, başka dil yok) C
  dalı; başka dilden kaynak da varsa genel dal kalır ve artık göreli yolu korur (iki `__init__.py`
  ezilmez). "Kaynak yazılamadı → başarısız" kuralı C dalının her kullanımında geçerli.
  `tests/test_temiz_harita.py::test_source_files_diskten_sayaci_sisik_olsa_da` sayaç farkını eski
  ezmeyle üretiyordu; fark artık biçimlendirici yerine konarak üretiliyor (testin kilitlediği README
  davranışı aynı; `mutation_specs_temiz_harita.json`'un `readme_kaynak_sayisi_sayactan` mutantı
  hâlâ ölüyor).
- **Uçtan uca:** §2.3.

### 1.4 `types.h` yapı sırası koşudan koşuya değişiyordu (commit `fe8dcfb`)

- **Kaynak:** `reconstruction/c_type_recoverer.py:1131-1148`, **`c_project_builder.py` değil**
  (o, `reconstructed/typed/types.h`'yi `_build_types_h` içinde olduğu gibi kopyalar). `recover()`
  dosyaları işçi havuzunda ayrıştırır ve sonuçları `as_completed` sırasıyla, yani işçilerin
  **bitiş sırasıyla** `_merge_parse_result`'a verir. Birleştirme sıraya bağlıdır:
  `_field_accesses` / `_switch_vars` / `_vtable_entries` sözlüklerine ilk görülme sırasıyla girilir
  ve `_synthesize_structs` / `_synthesize_enums` bu sırayla numara verir (`recovered_struct_NNN`,
  `recovered_enum_NNN`); aynı alana iki tip gelirse ilk görülen kalır. `PYTHONHASHSEED`'in payı yok
  (aşağıda).
- **Yeniden üretim** (`$R/betikler/types_h_tekrar.py`: aynı girdiyle — tree çalışma alanının
  `reconstructed/src`'si ve `static/` JSON'ları — `recover()`'ı tek süreçte koşar):

  | koşu | önce (`2be12ed`) | sonra (`fe8dcfb`) |
  |---|---|---|
  | doğal 1 / 2 / 3 | `76a4c4ea…` / `6050e07c…` / `3c96d30c…` | `9870d0ab…` (üçü) |
  | zorlanmış bitiş sırası: yol sırası / ters / karışık (tohum 7) | `9870d0ab…` / `9cf5e21a…` / `d4722b80…` | `9870d0ab…` (üçü) |
  | ayrı süreçlerde `PYTHONHASHSEED` 1 / 2 / 3 (doğal + yol sırası) | — | `9870d0ab…` (altısı) |

  Çıktılar: `$R/types_h_once.txt`, `$R/types_h_sonra.txt`, `$R/types_h_sonra_hashseed.txt`.
  Ters sırayla yol sırası arasında 174 satır farklı (enum değerleri ve yapı `Sources` satırları yer
  değiştiriyor). Tam hatta da görülmüştü: `~/karadul_olcum/runs/rapor-sayaclari-2026-11-11/{once,sonra}`
  `out/src/include/types.h` 16 satır farklı (`recovered_struct_003…006`'nın `Sources:
  FUN_00109600` ↔ `FUN_00109460`). Bugünkü iki "önce" tree koşusu (`tree_once_a/b`) rastlantıyla aynı
  `types.h`'yi verdi (ikisi de yol sırasının sonucu `9870d0ab…`); doğal sıra yük altında
  çoğunlukla gönderim sırasına yakın.
- **Düzeltme:** sonuçlar bitiş sırasıyla toplanır, dosya yolu sırasıyla (`c_files` sıralı)
  birleştirilir. Hata ve zaman aşımı yolları aynı (zaman aşımında biten dosyalar yine birleştirilir).
- **Kodda da iz vardı (Mac htop):** §2.2.

### 1.5 Mach-O'da `$` taşıyan ad: bugünkü kodda yeniden üretilemedi (kod değişmedi)

- **Ürün koşusunda (93a2956, ad haritası 1.0):** Mac htop'ta 4, tmux'ta 3 `signature_db` kaydı
  `mappings`'te: `_fdopen$DARWIN_EXTSN → fdopen$DARWIN_EXTSN` (ve `fopen`, `realpath`, `select`)
  (`$R/dolar_ad_93a2956_mac.txt`). Kodda (yorum ve dizgi atılmış `out/src`) `$`'lı tanımlayıcı **0**;
  17 / 23 geçiş yalnız yorumda: Ghidra'nın gerçek Mach-O simge adı (`// Function:
  _fdopen$DARWIN_EXTSN`, `@calls …`). Kodda Ghidra adı zaten `_fdopen_DARWIN_EXTSN`.
- **Bugünkü kodda (`2be12ed`, harita 1.1, a726692):** Mac htop tam koşusu (`$R/htop_once`):
  `mappings` 0, dört `$`'lı ad `candidates`'te gerekçe `invalid_c_identifier` ile; kodda 0, yorumda 17;
  HTML aday tablosunda yok (`$R/dolar_ad_htop_once.txt`). Aynı kodla 93a2956'nın htop ve tmux
  çalışma alanlarından harita bellekte yeniden kurulunca (`$R/betikler/harita_bellekte.py`,
  `$R/harita_bellekte_93a2956_mac.txt`) dört ve üç ad `candidates`'te, `invalid_c_identifier`.
- **Sonuç:** sağlamlık belgesindeki kusur (`gecersiz_c_adi:gecersiz_karakter`: `mappings`'te `$`'lı ad)
  temiz harita onarımıyla (a726692, `output_formatter._candidate_reason` →
  `name_validity.lexical_reject_reason`) giderilmiş; mevcut ad geçerliliği kuralı zaten bu yolda
  uygulanıyor. Ad hiçbir zaman koda girmemiş. Kalan tek yer `reconstructed/signature_matches.json`
  (aday kaydı; 4 `$`'lı aday adı) — bu bir aday listesi ve okuyucuları adı geçersiz diye ayırıyor.
  Kaynakta süzmek (eşleşmeyi atmak ya da adı dönüştürmek) yeni bir kural olurdu ve eşleşme bilgisini
  ("bu fonksiyon libSystem `fdopen`") kaybettirirdi; yapılmadı. Bu yüzden 5. kalemde ad haritası
  değişmedi (§3).

## 2. Uçtan uca

Komut (worktree kökünden; `$R/betikler/kos.sh` commit'i, girdi sha256'sını ve `karadul.__file__`'ı
koşu dizinine yazar, en çok bir koşu aynı anda):

```
GHIDRA_INSTALL_DIR=~/Library/BlackWidowBuild/ghidra_12.1.2_PUBLIC PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=$PWD \
  python -m karadul analyze <girdi> --skip-dynamic --output-dir $R/<koşu>/ws --output $R/<koşu>/out
python $R/betikler/once_sonra.py $R/<koşu> ...        # ölçüler (salt okunur)
```

Girdiler (salt okunur): tree `~/karadul_olcum/n1_debian13/tree/tree/ws/workspaces/tree/20261021_092848/raw/tree`
(sha256 `62810aca…49f00c0`); Mac htop
`~/Black_Widow/workspaces/olcum_mac/runs/ol7-c-b7faeac/htop/ws/workspaces/htop/20261021_085005/raw/htop`;
pzstd `~/karadul_olcum/n1_debian13/zstd/pzstd/ws/workspaces/pzstd/20261021_092948/raw/pzstd`.
Hepsinin `rc=0`; `karadul.__file__` worktree (`pzstd_once` dışında, §2.3).

### 2.1 Debian tree (`tree_once_a`, `tree_once_b` @ 2be12ed; `tree_sonra_a` @ fe8dcfb)

| Ölçü | önce | sonra |
|---|---|---|
| `report.html` imza satırı | `Signature Database (FLIRT)` · `133 functions matched` · `Known library functions identified via byte signatures.` | `Signature Database Lookup` · `133 matches: 128 by the function's existing name, 2 by referenced strings, 3 by callees` · açıklama: bayt karşılaştırılmaz, uygulama denetlenmez |
| `signature_matches.json` kayıt / özdeş fazlası / tekil adres | 133 / 63 / — (alan yok) | 133 / 0 / 133 |
| kayıt alanları | original, matched, library, confidence, purpose | + address, method |
| `reconstructed/typed/types.h` | `9870d0ab…` (a ve b) | `9870d0ab…` |
| `out/src/include/types.h` | `1f3573ac…` (a ve b) | `1f3573ac…` |
| `out/src` dosya | 275 | 275 |

`diff -rq önce/out sonra/out`: `README.md`, `report.html`, `report.json`, `src/compile_commands.json`
farklı — iki "önce" koşusu arasında da aynı dört dosya farklı (süre, yol, aşama istatistiklerinin
sırası). `report.html`'in görünür metin farkı (`$R/report_html_fark_tree.txt`): süreler, çalışma
alanı yolu, paralel adım istatistiklerinin sırası ve imza satırı.

### 2.2 Mac htop (`htop_once` @ 2be12ed, `htop_sonra` @ fe8dcfb)

| Ölçü | önce | sonra |
|---|---|---|
| `report.html` imza satırı | `Signature Database (FLIRT)` · `196 functions matched` | `Signature Database Lookup` · `196 matches: 186 by the function's existing name, 7 by referenced strings, 3 by callees` |
| `signature_matches.json` kayıt / özdeş fazlası / tekil adres | 196 / 0 / — | 196 / 0 / 196 |
| `$`'lı ad: `mappings` / `candidates` / kod / yorum | 0 / 4 / 0 / 17 | 0 / 4 / 0 / 17 |
| `reconstructed/typed/types.h` | `4cb60cc2…` | `a020a390…` |
| `out/src` dosya | 845 | 845 |

`types.h` farklı (2 266 satır): yapı/enum numaraları sıralı farklı; numaralar normalize edilip
satırlar sıralanınca iki dosya aynı (yalnız sıra ve numara farkı). `diff -rq önce/out sonra/out`
ayrıca iki C dosyası gösteriyor:
`src/subsystem_group_0/FUN_100003438.c` ve `src/subsystem_group_5/FUN_100002c34.c`, ikisinde de tek
satır: `uVar1`'in tipi `uint32_t` ↔ `uint64_t` iki fonksiyon arasında yer değiştirmiş. Bu da 1.4'ün
sıra bağımlılığıdır: `types_h_tekrar.py` htop'un "önce" çalışma alanında (`reconstructed/src`) eski
ve yeni `CTypeRecoverer`'la koşuldu (`$R/types_h_htop.txt`; eski modül `git show
2be12ed:karadul/reconstruction/c_type_recoverer.py` kopyası):

| koşu | önce kodu: types.h · yazılan .c (birlikte) | sonra kodu |
|---|---|---|
| doğal 1 / 2 | `9f729f5b…` · `e7dfc1f0…` / `570d947a…` · `e7dfc1f0…` | `a020a390…` · `e7dfc1f0…` (ikisi) |
| zorlanmış: yol sırası | `a020a390…` · `e7dfc1f0…` | aynı |
| zorlanmış: ters | `dc90ad69…` · `ca672a9a…` | aynı |
| zorlanmış: karışık (tohum 7) | `632a1422…` · `bd147f7d…` | aynı |

Eski kodda ters sıra 13 `.c` dosyasında yerel değişken tipini değiştiriyor (ör. `FUN_100002c34`
`uint32_t uVar1` → `uint64_t`, `FUN_100001a6c` `uint32_t uVar5` → `int32_t`). Yeni kodun tek
sonucu `a020a390…`, `htop_sonra`'nın `typed/types.h`'siyle aynı. "Önce" koşusunun bitiş sırası
yeniden üretilemez; ama `types.h` ve iki `.c` farkı bu mekanizmanın ürettiği türden (sıra ve
numara, yerel tip) ve ad haritasına yansımadı (§3).

### 2.3 Debian pzstd, dil `cpp` (`pzstd_once` @ 2be12ed, `pzstd_sonra` @ fe8dcfb)

"Önce" koşusu `2be12ed`'in `git archive` kopyasından (`$R/kod_2be12ed`, `$R/betikler/kos_kod.sh`;
`karadul.__file__` o kopya). Worktree'de git dışı dosya yok (`git status --ignored`: yalnız
`__pycache__`), yani kopya worktree'nin 2be12ed hâliyle aynı kodu koşar.

| Ölçü | önce | sonra |
|---|---|---|
| `out/src` | 1 201 dosya, düz (`FUN_….c`) | 1 201 dosya, proje ağacı (`src/subsystem_*/`, `include/`, `analysis/`, `CMakeLists.txt`, `Makefile`, `README.md`, `compile_commands.json`) |
| `out/src` = `reconstructed/project` | hayır | **birebir** (1 201 dosya, içerik özeti) |
| ezilen kopya (`genel_dal_cakisma.py`) | 12 757 kaynak → 1 201 ad; 1 158 adın kaynakları farklı içerikli; kazanan `typed_iter1` 1 157, `project` 1 | — |
| `report.html` imza satırı | `229 functions matched` (FLIRT) | `229 matches: 222 by the function's existing name, 1 by referenced strings, 6 by callees` |
| `signature_matches.json` kayıt / özdeş fazlası / tekil adres | 229 / **147** / — | 229 / 0 / 229 |

Kalem 3'ü yalnız başına ölçmek için aynı ("sonra") çalışma alanı eski (`git show
2be12ed:karadul/core/output_formatter.py`) ve yeni biçimlendiriciyle bellekte yeniden yazıldı
(`$R/betikler/bicim_eski_yeni.py`, `$R/pzstd_bicim_eski_yeni.txt`): eski — sayaç 12 757, diskte
1 201; dosyaların 1 157'si `typed_iter1`, 44'ü yalnız `project`'te bulunan içerik; proje ağacının
içeriğiyle aynı olan 209 / 1 201. Yeni — sayaç 1 201, diskte 1 201, proje ağacıyla birebir. İki
biçimlendiricinin `naming_map.json`'u bayt bayt aynı (`aebfcc16…`; 4 eşleme: `main`,
`deregister_tm_clones`, `register_tm_clones`, `compare_func`; 84 aday).

`reconstructed/typed/types.h` önce `f2bfb8ef…`, sonra `331da0c7…`; numaralar normalize edilip
sıralanınca 12 satır farklı (aynı alanda ilk görülen tip `int` ↔ `undefined4`, güven 0.90 ↔ 0.80),
proje ağacında 3 `.c` dosyasında yapı numarası (`recovered_struct_007 *` ↔ `_010 *`) ve yerel tip
farkı. `types_h_tekrar.py` "önce" çalışma alanında (`$R/types_h_pzstd.txt`): eski kodun doğal koşusu
`4233a70d…` (hattaki `f2bfb8ef…`'den de farklı), zorlanmış üç sıra üç ayrı `types.h` ve üç ayrı `.c`
kümesi; yeni kodun dört koşusu tek `331da0c7…` (= "sonra" hattı).

## 3. Ad haritası (`out/naming_map.json`)

| İkili | önce sha256 | sonra sha256 | `mappings` |
|---|---|---|---|
| tree | `7c49aebbc27c…` (a ve b) | `7c49aebbc27c…` | bayt bayt aynı (3 eşleme, 71 aday) |
| Mac htop | `c1319aa1dda4…` | `c1319aa1dda4…` | bayt bayt aynı (0 eşleme, 196 aday) |
| pzstd | `aebfcc16a95d…` | `aebfcc16a95d…` | bayt bayt aynı (4 eşleme, 84 aday); kalem 3 yalnız başına da değiştirmiyor (§2.3) |

`ws/reconstructed/src/naming_map.json` ve `src_iter1/naming_map.json` (c_namer) üç ikilide de
önce/sonra aynı (tree `79a3ddbd…` / `94cffe6c…`, htop `6b9b2238…` / `320a3bac…`, pzstd `ee8dcf77…`
/ `ee8dcf77…`). Kalem 5 kod değiştirmediği için haritayı değiştirmedi (görevde beklenen "5. kalem
haritayı değiştirir" olmadı).

## 4. Testler ve mutantlar

Yeni: `tests/test_cikti_hatalari.py` (20 test). Değişen: `tests/test_temiz_harita.py` (bir test, §1.3).

- Kalem 1: satır adı, açıklama, "recover" geçmez; yöntem dökümü (tree dağılımı 128/2/3); bilinmeyen
  yöntem adıyla; yöntem alanı yoksa ya da bir kayıtta eksikse ya da sayı tutmazsa döküm yok; kayıt
  yoksa yalnız sayı; ikili ad satırı "name candidates"; tam `generate_html`; iki yazıcının `method`
  alanı (etkin adım yolu ve monolit yolu, gerçek `SignatureDB` ile).
- Kalem 2: iki yazıcı adres yazar (aynı adlı iki thunk ayrı kayıt, gerçek `SignatureDB`); okuyucular
  (ad haritası, HTML aday tablosu, `ui.server._signature_candidates`) adresli ve adressiz kayıtta aynı.
- Kalem 3: `cpp` ve yalnız C → proje ağacı (ara aşamalar gelmez); genel dal aynı adlı iki dosyayı
  korur; C ile `.py` birlikte → genel dal ikisini de korur; `cpp`'de kaynak yazılamazsa başarısız.
- Kalem 4: `recover()` iş parçacığı havuzu ve zorlanmış bitiş sırasıyla: düz ve ters sıra aynı
  `types.h`; yapı numaraları ve ilk alan tipi dosya yolu sırasındaki ilk görülme.

Mutasyon: `docs/arge/2026-11-12_cikti_hatalari/mutation_specs.json` (`scripts/measurement/` bu işin
yetkisi dışında olduğu için tanımlar burada).

```
PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec docs/arge/2026-11-12_cikti_hatalari/mutation_specs.json
== ozet: 25 killed, 0 survived, 0 error ==
python ~/karadul_olcum/runs/temiz-harita-2026-11-11/betikler/olum_nedeni.py <worktree> docs/arge/2026-11-12_cikti_hatalari/mutation_specs.json
```

25 mutant (kalem 1: 12, kalem 2: 5, kalem 3: 4, kalem 4: 4); 25'i de `AssertionError`/`assert` ile
öldü (`$R/olum_nedeni.txt`; ilk koşuda 4 mutant alanın yokluğundan `KeyError` ile düşüyordu, testler
alanın varlığını önce `assert` edecek biçimde sıkılaştırıldı). Her mutanttan sonra kaynak baytları
geri yazıldı. Var olan iki mutasyon takımı değişikliklerden sonra da tam öldü:
`scripts/measurement/mutation_specs_temiz_harita.json` 25/25, `mutation_specs_cikti_kucuk_hatalar.json`
27/27. Depodaki mutant tanımlarının değişen dosyalardaki `find` metinleri hâlâ tek eşleşme
(bir istisna, önceden de öyleydi: §6).

Dokunulan modüllerin testleri (tam takım koşulmadı):

```
PYTHONDONTWRITEBYTECODE=1 python -m pytest tests/test_cikti_hatalari.py tests/test_step_ghidra_metadata.py \
  tests/test_stages_split_parity.py tests/test_cikti_kucuk_hatalar.py tests/test_output_formatter.py \
  tests/test_temiz_harita.py tests/test_ui_cagri_kenari.py tests/test_ui_temiz_harita.py \
  tests/test_report_v113_sections.py tests/test_skipped_stage_display.py tests/test_surum_oncesi_hatalar.py \
  tests/test_output_formatter_guven.py tests/test_saglamlik_onlemleri.py tests/test_step_tip_guvence_sayaci.py \
  tests/test_binary_reconstruction.py tests/test_typeforge_adapter.py tests/test_mutation_gap_closures.py \
  tests/test_tip_degisimi_metin_sadakati.py tests/test_v157_fixes.py tests/test_c_type_recoverer_bloat.py -q
→ 744 passed, 1 skipped
```

## 5. Sınırlar ve doğrulanmayanlar

- Kalem 1'in yöntem dökümü yalnız bu sürümden sonra yazılan kayıtlarda çıkar; eski çalışma alanında
  satır yalnız "N matches" der.
- Kalem 2: HTML aday tablosu adres sütunu taşımıyor; aynı adlı iki thunk tabloda yine tek satır
  (dünkü tekilleştirme duruyor, yorumu güncellendi).
- Kalem 3: tam koşu yalnız pzstd'de (ürün kümesinde dili `cpp` olan tek ikili). Rust/Go ikilisi ve
  `.py` ile C'nin birlikte olduğu bir hedef (PyInstaller) tam koşuda denenmedi; bu yollar birim
  testiyle sınandı. Genel dal artık iç içe dizin yazar: JS/Swift dışı, C olmayan hedeflerde
  `out/src` düz değil, `reconstructed/`'in yapısında.
- Kalem 4: belirlenimlilik `CTypeRecoverer` için gösterildi. Tam hatta `types.h` dışında başka sıra
  bağımlılığı aranmadı; tree'de iki "sonra" koşusu yapılmadı (sıra bağımlılığı yük altında nadiren
  görünüyor, kanıt §1.4'teki zorlanmış sıra).
- Kalem 5: tmux tam koşusu yapılmadı (951 sn); bugünkü kodla tmux haritası yalnız bellekte, 93a2956
  çalışma alanından kuruldu.

## 6. Yan bulgular (dokunulmadı)

1. **Görevdeki yer emekli kod:** `stages._run_signature_matching` (görevin işaret ettiği ≈1645–1660)
   gerçek koşuda çalışmıyor; `use_step_registry=False` `stages.py:3085-3098`'de adım yoluna
   çevriliyor. Etkin yazıcı `pipeline/steps/ghidra_metadata.py`. Aynı ikilik (monolit metot +
   adım) başka kayıtlarda da olabilir; bir düzeltme yalnız monolite yapılırsa koşuyu değiştirmez.
2. **Malware IOC bölümü hiç dolmuyor olabilir:** `reporting/html_report.py:570` ve
   `reporting/markdown_report.py:708` `static/signature_matches.json`'ı okuyor; bu dosyayı yazan kod
   yok (`grep`: `save_json("static", "signature_matches")` ve `save_matches(` çağrısı yok). Yedek yol
   `stages["static"].stats["signature_matches"]`'ı liste bekliyor; sayaç `reconstruct` aşamasında ve
   tamsayı. Kayıtlar `family`/`tier` da taşımıyor. Gerçek koşuda denenmedi, yalnız kod okundu.
3. **Aynı strateji bölümünde doğrulanmamış iddialar:** "Context-Aware Renaming (NSA-grade) — 513
   variables renamed — 300+ rules, 3-level data flow tracking" (JS aracının açıklaması; tree gibi bir
   ikilide de yazılıyor), "Source Matching — N names recovered from original source" (JS; aday mı
   uygulanmış mı denetlenmiyor). Bu işin kapsamı dışında bırakıldı.
4. **C dalının yedek yolu (proje ağacı yokken) `types/types.h`'yi iki kez yazıyor:** önce kaynak
   dizinindeki `types.h`, sonra `reconstructed/types.h` (`output_formatter.py`, `_format_binary_sources`);
   `_clean_filename` eşlemesi de iki adı aynı dosyaya düşürebilir. Yalnız proje ağacı boşken çalışır;
   düzeltilmedi.
5. **Yerel tip çıkarımı değişken adına göre havuzlanıyor gibi:** htop'ta birleştirme sırası 13
   fonksiyonda `uVar1`/`uVar5` tipini değiştiriyor; `CTypeRecoverer._type_usage` değişken adıyla
   (fonksiyon ayırmadan) anahtarlanıyor. Bugünkü düzeltme sonucu belirlenimli yapar ama havuzlamayı
   değiştirmez. Doğrulanmadı (hipotez).
6. **Mac htop'ta temiz haritada uygulanmış ad yok:** `mappings` 0, `candidates` 196 (hepsi
   `signature_db`: 191 `not_in_code` — kod Ghidra'nın `_fopen` adını taşıyor, aday `fopen`; 4
   `invalid_c_identifier`; 1 `same_as_original`); c_namer genel yeniden adlandırma 0. Bu işin
   değişikliğinden bağımsız (önce/sonra aynı).
7. **Bayat mutant tanımı:** `docs/mutation_specs.json` `t2_gnulib_call_removed_from_seed`'in `find`
   metni `stages.py`'de iki kez geçiyor (2be12ed'de de); `mutation_probe` bu mutantı "error" verir.
