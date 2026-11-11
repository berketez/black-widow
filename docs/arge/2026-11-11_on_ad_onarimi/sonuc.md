# Ön ad kanalı onarımı: ELF önyük adları ve dört gnulib girdisi (2026-11-11)

> Girdi: `docs/arge/2026-11-10_n1_adim3/kalan_kanal_dokumu.md` (7b19ffe; geliştirme seti, KEŞİF).
> Bu belgedeki her sayı aşağıdaki komutların çıktısıdır. Kör setlere (doğrulama/test setleri,
> `targets/`) bakılmadı. Geliştirme seti dışındaki korpuslar: Debian 9.4-3 ve Ubuntu 9.4-3ubuntu6
> coreutils (`~/karadul_olcum/corpus`, 5'er ikili), aynı Ubuntu paketinden iki ek ikili (od, pr) ve
> `tests/fixtures/coreutils`. Geliştirme seti ikililerinin GT adları bu belgede geçmez; açıklama
> için geçen GT adları (`xstrtol_fatal`, `version_etc_arn` …) geliştirme seti dışındaki 9.4
> korpuslarındandır.

## 0. Özet

| Onarım | Kök neden | Değişiklik | Sonuç |
|---|---|---|---|
| 1. ELF önyük adı | Tür künyesi doğru yazılıyordu (`stages.py:2632-2633`, `elf_onyuk`), ama `baglama.EXACT_KINDS` yalnız KS-1 ve elle adı içeriyordu; c_namer önyük adını `_sanitize_c_name`'den geçirdi (`c_namer.py:2243-2251`; temizleyici `c_namer.py:610` baştaki/sondaki `_`'yi atar) | `karadul/reconstruction/tarif/baglama.py:74`: `EXACT_KINDS`'e `KIND_ELF_BOILERPLATE` eklendi | Geliştirme seti dışında önyük adları temizlenmeden 48/48, temizlenince 24/48 doğru; tree ve cat'te ad haritasında yalnız 2'şer önyük anahtarı değişti |
| 2. gnulib girdileri | Dört girdi geliştirme setinde hep yanlış | Karar kuralıyla yalnız `GNULIB_FINGERPRINTS[4]` (`xstrtol_error`) çıkarıldı | Öbür üçü LTO'lu Ubuntu yapısında doğru ad veriyor (kural: çıkarılmaz); yapıya bağlı oldukları yazıldı |

Ön ad türünün atandığı yer `karadul/reconstruction/binary_name_extractor.py` DEĞİL: tür,
`stages.py:2631-2633`'te tohumun önceki ve sonraki sözlüğü karşılaştırılarak (`baglama.mark_changed`)
yazılıyor ve `make_meta` `exact` alanını `EXACT_KINDS`'ten türetiyor. Bu yüzden onarım tek satır
(`baglama.py`); `stages.py` ve `c_namer.py`'ye dokunulmadı.

## 1. Onarım 1: ELF önyük adları temizlenmeden yazılır

- Katalog (`karadul/analyzers/elf_boilerplate.py:64-87`): `register_tm_clones`,
  `deregister_tm_clones`, `__do_global_dtors_aux`, `_start`. Temizleyici son ikisini `do_global_dtors_aux`
  ve `start` yapıyordu; ilk ikisini değiştirmez.
- Değişiklikten sonra önyük künyesi `{"kind": "elf_onyuk", "exact": true}`; c_namer KS-1 ve elle ad
  için var olan tam ad yolunu kullanır. Etiket ("doğrulanmadı"), strateji (`binary_extract`) ve güven
  (0,95) değişmedi. gnulib, `main` ve Faz 1 adları eskisi gibi temizlenir.
- **Ad geçerliliği süzgeci (93a2956) temizlenmemiş adı reddetmiyor:** `_start` ve
  `__do_global_dtors_aux` geçerli C tanımlayıcısı; anahtar sözcük ya da tip adı değil. Gerçek hatta
  reddedilen ön ad 0 (tree, cat; §3).
- **Çakışma (madde 3):** temizlenmemiş ad ikilide başka bir fonksiyonun adıysa ya da ithal bir
  fonksiyonun baştaki tek `_` soyulmuş adıysa ön ad reddedilir (`collides_with_existing_function`),
  `_start_2` gibi ek verilmez, anahtar aday listesine kalır; köken kaydına `pre_name_kind: elf_onyuk`
  ve sahibinin adresiyle girer. Simgeli ikilide anahtarın gösterdiği fonksiyonun Ghidra adı zaten
  `_start` ise çakışma sayılmaz. Üç durum testle kilitli (`tests/test_on_ad_onarimi.py`). Gerçek
  hatta (tree, cat) çakışma yok: iki ikilide de `_start` ve `__do_global_dtors_aux` anahtarları,
  Ghidra'nın `entry` ve `_FINI_0` adını verdiği fonksiyonların adresten kurulmuş `FUN_` anahtarıdır
  (tree `FUN_00105dc0` / `FUN_00105e8c`, cat `FUN_00103340` / `FUN_0010340c`; `ghidra_functions.json`).
  Bu anahtarlar C metninde geçmez; değişen ad haritası, köken kaydı ve ölçümdür, `.c` metni değil.

Geliştirme seti dışında (tohumlar saklı `static/` üzerinde bu ağacın koduyla yeniden çağrıldı; hüküm
`ks1_olc.capa_degerlendir`, tam eşitlik; `on_ad_kanit.py`):

| Katalog girdisi | Debian 9.4 (5) | Ubuntu 9.4 (5) | Ubuntu 9.4 ek (od, pr) | Temizlenince doğru |
|---|---|---|---|---|
| `ELF_BOILERPLATE_SHAPES[0]` `register_tm_clones` | 5/5 | 5/5 | 2/2 | 12/12 |
| `ELF_BOILERPLATE_SHAPES[1]` `deregister_tm_clones` | 5/5 | 5/5 | 2/2 | 12/12 |
| `ELF_BOILERPLATE_SHAPES[2]` `__do_global_dtors_aux` | 5/5 | 5/5 | 2/2 | 0/12 |
| `ELF_BOILERPLATE_SHAPES[3]` `_start` | 5/5 | 5/5 | 2/2 | 0/12 |
| Toplam | 20/20 | 20/20 | 8/8 | 24/48 |

## 2. Onarım 2: dört gnulib girdisi (kanıt şartlı)

Karar kuralı (görevde önceden yazılı): bir girdi bakılan HER korpusta 0 doğru veriyorsa çıkarılır;
herhangi birinde doğru ad veriyorsa çıkarılmaz.

| Girdi | Ad | Geliştirme seti (7b19ffe) | Debian 9.4 (5 ikili) | Ubuntu 9.4 (5 ikili) | Ubuntu 9.4 ek (od, pr) | Karar |
|---|---|---|---|---|---|---|
| `GNULIB_FINGERPRINTS[0]` | `version_etc` | 0/104 | 0/5 | 4/4 | 2/2 | tutuldu |
| `GNULIB_FINGERPRINTS[4]` | `xstrtol_error` | 0/9 | ateşlenmedi | ateşlenmedi | 0/2 | **çıkarıldı** |
| `GNULIB_CALL_SHAPES[1]` | `hard_locale` | 0/104 | 0/5 | 5/5 | 2/2 | tutuldu |
| `GNULIB_CALL_SHAPES[2]` | `full_write` | 0/11 | 0/1 | 1/1 | ateşlenmedi | tutuldu |

Hücre: doğru / ateşlenme (tohumun yazdığı ad). Proje normalleştirmesiyle (`function_f1.match_strict`)
hükümler aynı. Yanlışların sınıfı: Debian 9.4'te 11'inin hepsi `baska_fonksiyonun_adi/cagiran`
(ad, bu fonksiyonu doğrudan çağıran fonksiyonun GT adı); od/pr'de `xstrtol_error`'ın 2'si
`katalog_adi` (ad GT'de hiçbir adreste yok; ateşlendiği fonksiyonun GT adı `xstrtol_fatal`'ın klonu).

- **`xstrtol_error` çıkarıldı.** Beş ikililik iki korpusta hiç ateşlenmediği için ("0 doğru" boş
  kalmasın diye) aynı Ubuntu paketinde bu adı simge olarak taşıyan ikililer arandı (`sembol_tara.py`,
  `xstrtol_ikilileri.py`): Debian 9.4 paketinin 106 simgeli debug dosyasında 0, Ubuntu paketinde
  eki soyulmuş adla 8 (`vdir`, `df`, `du`, `od`, `pr`, `dir`, `sort`, `ls`). En küçük ikisi (od, pr;
  cat boyutunda) yalnız static aşamasına kadar koşturuldu: girdi ikisinde de ateşlendi, ikisinde de
  yanlış. Fixture (`tests/fixtures/coreutils`) bu soruya cevap veremez: GT'si `nm -D` (yalnız dinamik
  simgeler; gnulib iç fonksiyonları yok) ve BuildID'leri korpus ikililerinden farklı (ör. cat
  `5d7650c2…` / korpus `3592cdb0…`); Ghidra çıktısı saklı değil, koşturulmadı.
- **Tutulan üç girdi yapıya bağlı:** Ubuntu 9.4 LTO'lu, Debian 9.4 LTO'suz
  (`scripts/measurement/README.md:44, 61-62`: Ubuntu DWARF'ında `<artificial>` LTRANS CU'su var);
  geliştirme setindeki (Debian 13) sonuç Debian 9.4'ünkiyle aynı yönde, derleme bayrağı bu çalışmada
  ayrıca denetlenmedi. Aynı üç yer değiştirme 2026-09-25 ölçüm zemini notunda da yazılı
  (`version_etc_arn ← version_etc`, `setlocale_null_r ← hard_locale`, `safe_write ← full_write`).
  LTO'lu yapıda iç fonksiyon (`version_etc_arn`, `setlocale_null_r`, `safe_write`)
  dışarıdakine satır içine alınıyor ve dizgi / çağrı şekli doğru fonksiyonda kalıyor; LTO'suz yapıda
  dizgiyi ya da `setlocale` / `write` çağrısını taşıyan iç fonksiyon, ad ise onu çağıranın. Debian 9.4
  GT'sinde `version_etc_arn` ve `setlocale_null_r` 5 ikilinin 5'inde, `safe_write` `full_write`'ın
  ateşlendiği tek ikilide (cat) ayrı fonksiyon; Ubuntu 9.4 GT'sinde üçü de hiçbir ikilide yok.
- **Öneri (doğrulanmadı):** (a) platform koşulu: LTO'suz yapıda bu üç girdi ad vermesin ya da
  (b) daraltma: LTO'suz yapıda ad dizgiyi taşıyan fonksiyona değil, onu çağıran ince sarmalayıcıya
  verilsin, dizgiyi taşıyana iç adı (`version_etc_arn` …) verilsin. GT'siz bir yapı özelliği keşif
  olarak bakıldı (`yapi_ozellik.py`; geliştirme seti dışındaki 25 ateşleme): yanlış 11 ateşlemenin
  hepsinde fonksiyonun bütün çağıranları en çok 2 fonksiyon çağırıyor; doğru 14 ateşlemenin
  12'sinde bütün çağıranlar 12-54 fonksiyon çağırıyor, 2'sinde (Ubuntu expr ve pr, `hard_locale`)
  çağıranlardan biri 2 çağırıyor. "Bütün çağıranlar ince (≤ 2)" koşulu bu veride 11 yanlışın 11'ini,
  14 doğrunun 1'ini (expr) susturur. Aynı veride bulunduğu için iyimser; taze veride sınanmadan
  kural yapılmamalı. `xstrtol_error` yerine `xstrtol_fatal` adı da ancak ayrı ölçümle düşünülebilir.
- Geliştirme setindeki sonucu (keşif, aynı veri): yalnız `xstrtol_error` çıkınca gnulib adları
  621/852'den 621/843'e (9 yanlış ad düşer). Belgenin "621/633" satırı üç girdinin daha çıkmasını
  varsayıyordu; kural onları tutturdu.
- `xstrtol_error` satırı silindiği için sonraki girdilerin sıra numarası bir azaldı:
  `GNULIB_FINGERPRINTS[5]` `close_stdin` → `[4]`, `[6]` `usage` → `[5]`. 2026-11-10 dökümündeki
  numaralar eski sıradır.
- Yan gözlem (kapsam dışı, dokunulmadı): pr'de `GNULIB_CALL_SHAPES[6]` `mbslen` 0/1 (ateşlendiği
  fonksiyonun GT adı `mbsnwidth` klonu).
- Değişiklikten sonra aynı korpuslarda tohumlar yeniden çağrıldı: 5+5 ikilide fark 0, od/pr'de
  yalnız `xstrtol_error`'ın 2 yanlış adı düştü; boşalan fonksiyona başka bir tohum ad yazmadı.

## 3. Gerçek hat: tree ve cat

Debian 13 `tree` ve `cat` (`~/karadul_olcum/n1_debian13/...`, salt okunur), tam hat, sırayla. Önce
koşusu HEAD 93a2956, sonra koşuları onarımlı ağaç. Karşılaştırılan: `reconstructed/src/naming_map.json`.

Decompile özeti: `static/ghidra_output/decompiled/*.c` metninin sha256'sı (ilk 8 hane).

| Karşılaştırma | İkili | Decompile özeti (önce / sonra) | Değişen global anahtar | Önyük | gnulib | Başka | Değişen yerel ad |
|---|---|---|---|---|---|---|---|
| önce ↔ önce2 (aynı kod) | tree | 934dd12e / 934dd12e | 0 | 0 | 0 | 0 | 0 |
| önce ↔ önce2 (aynı kod) | cat | 170b0970 / c384f21f | 0 | 0 | 0 | 0 | 31 |
| önce ↔ sonra1 (onarım 1) | tree | 934dd12e / 934dd12e | 2 | 2 | 0 | 0 | 0 |
| önce2 ↔ sonra1 (onarım 1) | cat | c384f21f / c384f21f | 2 | 2 | 0 | 0 | 0 |
| önce ↔ sonra2 (iki onarım) | tree | 934dd12e / 934dd12e | 2 | 2 | 0 | 0 | 0 |
| önce2 ↔ sonra2 (iki onarım) | cat | c384f21f / b8dee34d | 2 | 2 | 0 | 0 | 32 |
| önce ↔ sonra2b (iki onarım, yineleme) | tree | 934dd12e / 934dd12e | 2 | 2 | 0 | 0 | 0 |
| önce2 ↔ sonra2b (iki onarım, yineleme) | cat | c384f21f / 1a61227c | 2 | 2 | 0 | 0 | 31 |

- Değişen anahtarlar: tree `FUN_00105dc0` `start` → `_start`, `FUN_00105e8c` `do_global_dtors_aux`
  → `__do_global_dtors_aux`; cat `FUN_00103340` ve `FUN_0010340c` aynı biçimde. Temiz çıktının
  `out/naming_map.json`'ında (tree 74, cat 79 eşleme) bütün sonra koşularında fark yalnız bu 2 anahtar.
- **Yerel ad farkları gürültüdür, onarımla ilgisi yok:** aynı kodla iki koşu (önce ↔ önce2) arasında
  cat'in decompile çıktısı ayrıştı: aynı ithal fonksiyonun thunk'ı ile dış kaydından hangisinin dosya
  adını aldığı koşudan koşuya değişiyor (`__overflow_00121158.c` ↔ `__overflow_00101e90.c`,
  `fileno_00121070.c` ↔ `fileno_00101c38.c`; dosya sayısı hep 296). Bir thunk'a yerel ad düşünce
  yerel adların `result_<n>` sayacı kayıyor. Decompile çıktısı birebir aynı olan çiftte (önce2 ↔
  sonra1, cat) yerel fark 0; tree'nin decompile çıktısı beş koşuda aynı ve yerel fark hep 0. İki
  onarımlı iki cat koşusunda Ghidra yine farklı çıktı verdi (b8dee34d, 1a61227c); makine yükü altında
  üçüncü kez denenmedi.
- Onarım 2 bu iki ikilide etkisizdir ve bu ayrıca gösterildi: `invalid suffix in` dizgisi tree ve
  cat'in decompile çıktısında 0 kez geçiyor (`grep -rn "invalid suffix in" .../decompiled | wc -l`).
  Onarım 1 ile 2 arasındaki tek kod farkı bu katalog girdisi.
- Reddedilen ön ad: bütün koşularda 0; ön ad verilen/uygulanan tree 5/5, cat 14/14 (köken kaydı
  `name_validity.rejected_counts`, `summary.pre_names_given/applied`).
- Bazı koşularda BSim yerel veritabanı başka bir süreçte açık olduğu için "lite"a düştü (önce ve
  önce2'de düşmedi; sonra1 ve sonra2'de iki ikilide, sonra2b'de yalnız tree'de düştü). Ad haritasına
  etkisi görülmedi (yukarıdaki satırlar).

## 4. Testler ve mutantlar

- Yeni: `tests/test_on_ad_onarimi.py` (6 test: tohum künyesi, tam yazım, künyesiz/uyuşmayan
  künyede eski davranış, başka fonksiyonla çakışma, ithal adıyla çakışma, simgeli ikilide kendi
  adı), `tests/test_gnulib_fingerprints.py::TestXstrtolErrorRemoved` (3 test).
- Güncellenen: `tests/test_tarif_baglama.py` (tam ad türleri kümesi, `make_meta`), 
  `tests/test_main_gnulib_seed_ordering.py` (tam ad anahtarları; `xstrtol_error` dizgisiyle kurulan
  "gnulib > önyük" öncelik sınaması `close_stdin` dizgisine taşındı — test silinmedi).
- Mutantlar: `scripts/measurement/mutation_specs_on_ad_onarimi.json`, 15 mutant (onarım 1: 11,
  onarım 2: 4), 15 / 15 gerçek test başarısızlığıyla öldü ("1 failed"; toplama hatası yok).
  c_namer.py, name_validity.py ve elf_boilerplate.py mutantları yalnız yeni testlerin o
  davranışları kilitlediğini sınar; bu dosyalar değişmedi. Onarım 1 commit'indeki tanımda bir
  mutantın (`oa_make_meta_yalniz_elle`) find/replace uzunluğu eşitti; onarım 2 commit'inde
  düzeltildi (`.pyc` tuzağı; koşum zaten `PYTHONDONTWRITEBYTECODE=1` ile).
- Seçili takım: `pytest tests -k "baglama or gnulib or name_valid or c_namer or kesin or on_ad or
  ad_gecerliligi"`: onarım 1'den sonra 581 geçti, 1 atlandı, 0 kaldı; iki onarımla (ve
  `scripts/node_modules` bağlıyken) 584 geçti, 0 kaldı.
- Tam takım (iki onarımla): 7 818 geçti, 4 kaldı, 31 atlandı (153 `integration`/`benchmark`
  seçilmedi). Kalan 4'ü (`test_deobfuscator.py` 3, `test_pipeline.py::...::test_identify_and_static`)
  worktree'de `scripts/node_modules` olmadığı için (`@babel/parser` bulunamadı); ana ağacın
  `scripts/node_modules`'ı bağlanınca dördü de geçti (aynı komut, iki dosya: 19 geçti / 0).

## 5. Komutlar

Betikler ve çıktılar `~/karadul_olcum/runs/on-ad-onarimi-2026-11-11/` altında (sha256 ilk 16 hane):
`on_ad_kanit.py` 9cd34345d466ba45, `sembol_tara.py` 03a7f507885f4fda, `xstrtol_ikilileri.py`
562b5d53ca5fd057, `ek_hazirla.py` 4b3bd9dd641e3d37, `ek_kos.sh` 107a6021a4c2f368, `kos.sh`
cb58183fd06a976a, `harita_farki.py` dad40fb61cc62e13, `yapi_ozellik.py` b7c8ce578bdea825.
`W` = worktree kökü; her Python komutu `PYTHONPATH=$W PYTHONDONTWRITEBYTECODE=1` ile.

```
# §1-§2 kanıt (saklı koşu aday-f893d72: Ghidra 12.1.2, 2026-10-14)
python on_ad_kanit.py --kosu ~/karadul_olcum/runs/aday-f893d72 --korpus ~/karadul_olcum/corpus \
    --cikti on_ad_kanit_aday-f893d72.json
python sembol_tara.py ~/karadul_olcum/downloads/x_coreutils-dbgsym_9.4-3_arm64 \
    ~/karadul_olcum/downloads/x_coreutils-dbgsym_9.4-3ubuntu6_arm64            # > sembol_tara.txt
python xstrtol_ikilileri.py ~/karadul_olcum/downloads/x_coreutils_9.4-3ubuntu6_arm64 \
    ~/karadul_olcum/downloads/x_coreutils-dbgsym_9.4-3ubuntu6_arm64 xstrtol_error
python ek_hazirla.py ~/karadul_olcum/runs/on-ad-onarimi-2026-11-11/ek_korpus od pr
./ek_kos.sh                                       # od, pr: --stage static, sırayla
python on_ad_kanit.py --kosu $PWD/ek_kosu --korpus $PWD/ek_korpus --cikti on_ad_kanit_ek_od_pr.json
python yapi_ozellik.py ~/karadul_olcum/runs/aday-f893d72 ~/karadul_olcum/corpus \
    $PWD/ek_kosu $PWD/ek_korpus                                                 # > yapi_ozellik.txt
# onarımdan sonra aynı iki kanıt komutu: on_ad_kanit_SONRA_*.json

# §3 gerçek hat (tree, cat sırayla; çıktı <etiket>/{tree,cat}/{ws,out}; kod.txt: HEAD + diff özeti)
./kos.sh once ; ./kos.sh once2 ; ./kos.sh sonra1 ; ./kos.sh sonra2 ; ./kos.sh sonra2b
python harita_farki.py once  once2  tree ; python harita_farki.py once once2 cat --goster
python harita_farki.py once  sonra1 tree --goster ; python harita_farki.py once2 sonra1 cat --goster
python harita_farki.py once  sonra2 tree --goster ; python harita_farki.py once2 sonra2 cat --goster
python harita_farki.py once  sonra2b tree --goster; python harita_farki.py once2 sonra2b cat --goster
cat <etiket>/<ikili>/ws/workspaces/*/*/static/ghidra_output/decompiled/*.c | shasum -a 256
grep -rn "invalid suffix in" once/tree/ws/workspaces/*/*/static/ghidra_output/decompiled \
    once2/cat/ws/workspaces/*/*/static/ghidra_output/decompiled | wc -l                  # 0

# §4
PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py \
    --spec scripts/measurement/mutation_specs_on_ad_onarimi.json --verbose
python -m pytest tests -q -p no:cacheprovider -x \
    -k "baglama or gnulib or name_valid or c_namer or kesin or on_ad or ad_gecerliligi"
python -m pytest tests -q -p no:cacheprovider
```

## 6. Sınırlar ve doğrulanmayanlar

- Korpus kanıtı saklı static çıktısında tohumların yeniden çağrılmasıdır; KS-1 bu çağrıda yok
  (ürün hattında KS-1, gnulib'den önce boş yuvayı alabilir). Soru "girdi doğru ad veriyor mu"
  olduğu için ateşlenme tohumun yazdığı addır.
- Korpuslar küçük: geliştirme seti dışında 12 ikili, hepsi coreutils 9.4. Tutulan üç girdinin
  "LTO'lu yapıda doğru" sonucu tek programın tek LTO'lu paketinden.
- Önyük adının C metnine etkisi bu iki ikilide yok (anahtarlar `entry` / `_FINI_0`). Ghidra'nın
  önyük fonksiyonunu `FUN_` bıraktığı bir ikilide `_start` / `__do_global_dtors_aux` C metnine
  girer; orada başka bir fonksiyon ya da ithal adla çakışma süzgeçle reddedilir (testle kilitli,
  gerçek hatta görülmedi).
- c_namer.py:2245'teki yorum hâlâ "Tam ad iddiası (KS-1, elle)" diyor; dosya bu görevde
  değiştirilemezdi. `baglama_tasarimi_taslak.md` §2.4 de yalnız KS-1 ve elle adı sayıyor.
- Daha büyük ikililerde (tmux, openssl) koşu yapılmadı (makine yükü).
