> **Not (ana oturum, 2026-10-21):** Bu dosya taslağın kopyasıdır ve bilerek `ks1_onkayit.md` adıyla commit'lenmedi.
> - `ks1_olc.py olc`, `ks1_onkayit.md`'yi ilk ekleyen commit'i resmî ön kayıt sayar.
> - Kesin ön kayıt, [seçim] maddeleri karara bağlandıktan sonra `ks1_onkayit.md` ve `ks1_sabitler.json` olarak **aynı commit'te** girer.
> - `ks1_sabitler_taslak.json` yalnız bugünkü sha256'ları gösterir.

# G11 / N1: KS-1 kesin çapalar — ön kayıt

- **Tarih:** 2026-10-21.
- **Durum:** Ön kayıt taslağı (adım 1/3). GT'ye bakılmadan yazıldı. Ana oturum bu belgeyi ve sabitlenen dosyaları (§11) inceleyip commit'lemeden GT'ye bakılmaz. Ölçüm adım 2'de `ks1_olc.py olc` ile yapılır; betik ön koşulları kendisi denetler.
- **Karar bekleyen maddeler:** **[seçim]** diye işaretli. Her birinin yanında önerilen varsayılan ve tek cümlelik gerekçe var; kararı Berke verir. Özet listesi §15'te.
- **Plan:**
  - v2.2 §3 N1 (satır 70);
  - §5 program sınıfı (satır 119-122);
  - §0 karar 4: sınıf başına ayrı eşik yok;
  - v2.1 3.2: KS-1 tanımı ve ölçütü.
- **Dayanak:** N0b (`2026-10-21_g10_n0b/`). `oz_ad` alt kanalında (dizgi tek tanımlayıcı, ad ona eşit) yanlış %7,7 (Wilson %3,0-%18,2), karar `belirsiz` çıktı. O tanım dizginin bu fonksiyona ait olduğunu denetlemiyordu. KS-1 sahipliği yapısal olarak kurar: ad yuvası (§3) ve inline koruması (§5).
- **Bu adımda yapılmayan:**
  - GT'ye karşı ölçüm (adım 2);
  - ürüne bağlama (`tarif/__init__.py`), susturma ve güven etiketi (adım 3).

**Dosyalar** (tam sha256'lar `ks1_sabitler.json`'da):

| Dosya | İçerik | sha256 (ilk 16) |
|---|---|---|
| `karadul/reconstruction/tarif/kesin.py` | çıkarıcı: veri akışı, türler, parçalar, K0-K5 | `cd77947252ed9514` |
| `scripts/measurement/ks1_olc.py` | `say`, `sinif`, `olc`, `sabitle` | `26feb9b0be52dc97` |
| `tests/test_tarif_kesin.py` | çıkarıcı testleri (sentetik `static/`) | `f92823b4f49e202b` |
| `tests/test_ks1_olc.py` | ölçüm testleri (sentetik GT, geçici git deposu) | `52237e25253bbdbf` |
| `scripts/measurement/mutation_specs_ks1.json` | 30 mutant | `d69dfad026755dda` |
| `docs/arge/2026-10-21_g11_n1/ks1_sabitler.json` | yukarıdaki beş dosyanın tam sha256'ları | — |

## 1. Amaç ve hipotez

KS-1, fonksiyonun tam adını ikilinin kendisinden okuyan kaynaklardır. "Kesin" iddiası, adın ikilide fonksiyona yapısal olarak bağlı bir yuvada durduğu anlamına gelir. Bu yuva bir assert çağrısının fonksiyon argümanı ya da bir günlük çağrısının `__func__` hizası olabilir.

**Hipotez H-KS1:** Her karar satırında (§8) tam ad kesinliğinin program başına makro ortalaması geliştirme setinde ≥ %95'tir.

**Ölçü ve kapsam:**
- Tam ad şarttır. KS-1 "kesin" iddia ettiği için yakın ad (gevşek mod) başarı sayılmaz.
- Kapsam (çapalanan / ad bekleyen) program sınıfı eş değişkeniyle raporlanır (§9).
- Ürün adlandırmasında KS-1'in tek başına ablasyonu adım 2-3'te koşulur (§10).

## 2. Girdi ve veri akışı

**Girdi:** yalnız Karadul'un `static/` çıktısı:
- `ghidra_functions.json`, `ghidra_strings.json`, `ghidra_xrefs.json`;
- `ghidra_combined_results.json` (işlemci, dosya biçimi);
- `ghidra_output/decompiled/*.c`: başlıktaki `// Address:` satırı ve dosya sonundaki gömülü disassembly.

GT, `raw/` ve ikilinin kendisi okunmaz. Adres biçimi taşımayan dizgi kayıtları (ELF'te yüklenmeyen bölümler: `.shstrtab::00000001`) atlanır.

**Neden disassembly:** Darwin arm64'te değişken sayılı argümanlar yığında geçer. Kaynaktaki `günlük("%s: …", __func__)` biçimli bir çağrıyı Ghidra'nın C çıktısı `FUN_x("%s: …")` diye gösterir, `__func__` argümanı görünmez (tmux Mac'te gözlendi). ELF'te argümanlar C'de görünse de iki platform aynı yoldan okunur.

**Çağrı kuralı:**
- Yalnız AArch64 desteklenir.
- Mach-O → Darwin: değişken argümanlar çağrı anında `[sp, #0]`'dan başlar.
- ELF → AAPCS64: değişken argümanlar sabit argümanlar gibi x0-x7'dedir.
- Başka işlemci ya da biçimde dizgi türleri çıkarılmaz (`desteklenmeyen_platform` sayacı).

**Fonksiyon içi ileri veri akışı:**
- **Değerler:**
  - sayfa: `adrp`;
  - adres sabiti: `adrp` + `add`, `adr`, ayrıca sabit + `add #imm` (GCC'nin bölüm çapası: `add x1, x19, #0x18`);
  - parametre: girişte x0-x7.
- **Kopya ve yığın:**
  - `mov xD, xS` değeri kopyalar.
  - `[sp, #ofset]` yuvalarına saklama (`str`, `stur`, `stp`) ve oradan geri yükleme (`ldr`, `ldur`, `ldp`) izlenir.
  - sp değişince (`sub sp`, geri yazmalı adresleme) ya da yazmaç ofsetli saklamada yığın haritası silinir.
- **Birleşme:** yalnız bütün gelen yollarda aynı olan değer kalır. Yuvanın "taze"liği VE ile birleşir.
- **Çağrı** (`bl`, `blr`, işlev dışına `b`):
  - x0-x18 ve x30 ölür.
  - Yığın yuvaları bayatlar: değer geri yüklemeler için korunur, ama "taze" değildir.
  - Darwin'de değişken argüman yalnız taze yuvadan, yani son çağrıdan sonra yazılmış yuvadan okunur.
- **Yükleyici özeti:**
  - Yükleyici: çağrı yapmayan, dönen fonksiyon. Özeti, bütün `ret`'lerde ortak olan x0-x7 adres sabitleridir; çağrıdan sonra çağıranda bu yazmaçlara konur.
  - Darwin'de makine dışlayıcısı (MachineOutliner) assert'in fonksiyon ve dosya argümanlarını böyle bir yardımcıda yüklüyor (tmux Mac'te 14 assert çağrı yerinin 10'u).
  - **[seçim] Yükleyiciden gelen değer yalnız assert yuvasında geçerli** (öneri: evet). Gerekçe: sabit döndüren sıradan bir fonksiyon (`get_name()`) günlük önekinde başka bir şeyin adını taşır.
- **Tanınmayan komut:** ilk işleneni yazmaçsa öldürülür.
- **Güvenlik sınırı:** blok başına 64 değişiklik aşılırsa blok "hiçbir değer bilinmiyor" durumuna iner (tutucu).

**Ad yuvası dizgisi** (bütün dizgi türlerinde ortak koşul):
- Değer, `ghidra_strings.json`'da (ya da xrefs'te) tanımlı bir dizginin adresidir.
- Dizgi `^[A-Za-z_][A-Za-z0-9_]+$` biçimindedir: ASCII tanımlayıcı, en az iki karakter.
- Dizgi ikilinin adına eşit değildir (`ghidra_functions.json` `program`).
- **[seçim] Alt çizgi zorunlu değil** (öneri: zorunlu değil). Gerekçe: yuva sahipliği yapısal olarak veriyor; `main`, `usage` gibi tek sözcüklü adlar kaybolmasın.
- **[seçim] Program adı dışlanır** (öneri: evet). Gerekçe: `"%s: …"` öneki programın kendi adını da sık taşır.

## 3. Çapa türleri

### 3.1 `assert`

- **Çağrılan:** baştaki alt çizgiler atılmış adı aşağıdakilerden biri olan Ghidra fonksiyonu (thunk). Ad yuvası:
  - Darwin `assert_rtn`: 1. argüman, x0;
  - glibc `assert_fail` ve `assert_perror_fail`: 4. argüman, x3.
- **Dosya argümanı:** üçünde de x1. K0'da kullanılır (§5).
- **Parça:** çağrı bir assert parçasındaysa yuva üst fonksiyona kaldırılır (§4).

### 3.2 `func_kalibi` (`__func__` kalıbı)

Bir çağrı yeri (`bl` ya da işlev dışına `b`) yuvadır, şu koşullarla:
- x0-x7'den **tam olarak biri**, `^%s(?::|\(\))` ile başlayan sabit bir dizgi taşır: biçim dizgisi, k. yazmaçta.
  - Birden çok yazmaç uyuyorsa yuva yok.
  - Çağrılanın kim olduğu aranmaz: printf ailesi, `fprintf`/`__fprintf_chk`, programın günlük fonksiyonları.
- Bu ilk `%s`'e hizalı argüman, biçimden sonraki ilk değişken argümandır:
  - Darwin'de taze `[sp, #0]`;
  - AAPCS64'te x(k+1); k = 7 ise taze `[sp, #0]`.
- Hizalı değer bir adres sabitidir (yükleyiciden gelmemiş) ve ad yuvası koşulunu (§2) sağlar.
- **[seçim] Ayraçlar: `%s:` ve `%s()`** (öneri: yalnız bu ikisi).
  - Gerekçe: `%s:` C günlük önekinin yerleşik biçimi. Geliştirme setinin 119 çalışma alanında `%s` ile başlayan 2 185 dizginin 1 380'inde `%s`'i `:` izliyor.
  - `%s ` (563), ` - ` (4) ve `(` (5) dosya ya da komut adı önekinde de kullanılır.
  - `%s()` geliştirme setinde hiç yok; genellik için tutuldu.

### 3.3 `func_aktarma`

- **Aktarıcı:** fonksiyon F'nin bir çağrı yerinde (§3.2 koşullarıyla) hizalı değer F'nin j. parametresiyse F, j'nin aktarıcısıdır.
  - Örnek (tmux Mac, `FUN_10000b350`): x0'daki parametre x19'a, oradan `[sp]`'ye gidiyor; biçim dizgisi `"%s: s=none"`. Çağıranlar x0'da tanımlayıcı biçimli bir dizgi geçiriyor.
- **Sabit nokta:** G, aktarıcı F'yi j. parametrede kendi i. parametresiyle çağırıyorsa G, i'nin aktarıcısıdır.
- **Yuva:** aktarıcı F'ye j. parametrede tanımlayıcı biçimli sabit dizgi geçiren çağrı yeri (yükleyiciden gelmemiş).
- Aktarıcının kendisi bu yoldan çapa almaz.
- **[seçim] Ayrı tür** (öneri: evet). Gerekçe: aktarılan parametre bir ileti de olabilir; kesinliği `func_kalibi`'den ayrı ölçülmeli. Örnek: Debian htop'ta Ghidra'nın dinamik simge tablosundan `CRT_fatalError` diye adlandırdığı fonksiyon parametresini `__fprintf_chk(stderr, 1, "%s: %s\n", param_1, …)` çağrısına geçiriyor.

### 3.4 `export`

- **Tanım:** thunk ve dış olmayan, `source == IMPORTED`, adı jenerik olmayan Ghidra fonksiyonu.
- **Dışarıda kalan adlar:** `entry`, `_start`, `_init`, `_fini`, `_DT_INIT`, `_DT_FINI`, `__libc_csu_init`, `__libc_csu_fini`, `__mh_execute_header`, `_INIT_N`, `_FINI_N`.
- **Kaynak:** ikilinin dinamik simge tablosu.
  - ELF: `.dynsym` ve `-rdynamic` (Debian htop 366, redis-tools 8 394, coreutils 211).
  - Mach-O: export trie. Apple strip'li Mac kopyasında `macho_measure prepare` boş olduğunu doğruluyor; beklenen 0.
- KS-1 yalnız işaretler. Kesinlik ölçüsünü şişirmemesi için ayrı türdür ve karar satırı değildir (§8).

### 3.5 Dışarıda bırakılanlar

- **FLIRT ve imza DB'si.**
  - Ad ikilinin kendisinden değil, dış bir katalogdan gelir.
  - Bugünkü DB seçici değil (2026-09-25, commit 93dc480). Sembollü ikililerde redis-server 162 ad / 0 doğru, jxl_from_tree 104 / 0 verdi. 22 277 bayt imzasının 3 921'i birden çok ada gidiyor. İmzalar yalnız 32 baytlık fonksiyon başını kapsıyor.
  - Karadul'da `--output-dir` ile bilerek kapalı.
  - DB yeniden kurulup ölçülürse ayrı bir ön kayıtla KS-1'e aday olabilir.
- **Gövdede geçen herhangi bir tanımlayıcı dizgi** (N0b `oz_ad`).
  - Ad yuvası olmadan sahiplik kurulamaz: biçim değişkeni adları (`window_index`), seçenek ya da komut adları da tanımlayıcıdır.
  - N0b'nin kararına uyar; KS-1'e girmez.
  - **Değerlendirilen ve seçilmeyen:** "tek fonksiyonun başvurduğu tanımlayıcı dizgi" (K1 + K2 yuvasız). Aynı nedenle seçilmedi.
- **Tanımlayıcı olmayanlar:** C++ `__PRETTY_FUNCTION__` imzaları (`void Foo::bar(int)`), `Class::method` biçimleri.
- **Yükleyiciden gelen değerler:** `func_kalibi` ve `func_aktarma` yuvalarında sayılmaz.

## 4. Assert parçaları ve kaldırma

**Assert parçası:** aşağıdaki iki koşulu sağlayan Ghidra fonksiyonu.
- `ret` ya da dolaylı dallanma (`br`) yok. Tuzak komutları (`brk`, `udf`, `hlt`) dönüş sayılmaz.
- `bl` ve kuyruk çağrısı hedeflerinin hepsi assert işlevi ya da yükleyici; en az biri assert.

**Kaldırma:**
- Bir fonksiyonun girişleri: xrefs çağıranları ∪ disassembly'de onun başına dallanan fonksiyonlar (`b`, `b.cond`, `cbz`, `tbz` …).
- `lift(F)`:
  - F parça değilse F'nin kendisi;
  - parçaysa ve girişlerinin `lift`'leri tek bir fonksiyona iniyorsa o fonksiyon;
  - yoksa (sıfır ya da birden çok) **sahipsiz**.
- Özyinelidir: makine dışlayıcısının assert'e kuyruk çağrısı yapan parçası, parçalar üstünden kaldırılır.

**Roller:**
- `kendi`: en az bir yuva sahibin kendi gövdesinde;
- `ust`: bütün yuvalar parçalardan kaldırılmış;
- `parca`: tek girişli parçanın kendisi. Üstü çapalanırsa üstün adını taşır; ayrı raporlanır, kesinliğe girmez (§6).

**Gerekçe:**
- Darwin clang `-Os` assert'leri soğuk parçalara (`.cold.N`) koyuyor; parça `bl` ile çağrılıyor.
- GCC'nin kısmi inline'ı (ipa-split, `.part.N`) assert yolunu, fonksiyonun inline edildiği her yerden çağrılan bir parçaya koyuyor. Debian zstd'de 52 parça var: 35'i iki ya da daha çok fonksiyondan çağrılıyor, 3'ünün girişi yok, 14'ünün tek çağıranı var. İlk 38'i, çağıranları tek bir fonksiyona inmedikçe kaldırılmaz.

**Risk:** parçanın tek üstü, assert'i yazan fonksiyonu inline eden fonksiyon olabilir.
- **[seçim] Kaldırılmış çapalar ayrı karar satırı (`assert_ust`)** (öneri: evet). Gerekçe: zayıf çıkarsa doğrudan assert çapalarını da düşürmesin.

## 5. İnline koruması (K0-K5)

-O2'de (ve Darwin -Os'ta) bir fonksiyonun gövdesi, içine inline edilmiş başka bir fonksiyonun adını taşıyan assert ya da `__func__` dizgisi içerebilir. Kurallar aşağıdaki sırayla uygulanır. K0-K2 dizgi başına, K3-K5 sahip fonksiyon başına sayılır; her tür ayrı huni tutar (`kesin.FUNNEL`).

| Kural | Birim | Tanım | Eleme nedeni |
|---|---|---|---|
| K0 başlık dosyası | dizgi | Assert yuvasının dosya argümanı (x1) sabit bir dizgi ve `.h`, `.hh`, `.hpp`, `.hxx`, `.h++`, `.inl`, `.inc`, `.def` ya da `.tcc` ile bitiyor (büyük/küçük harf duyarsız). Böyle bir yuvası olan dizgi çapa vermez | `K0_baslik_dosyasi` |
| K1 saf başvuru | dizgi | Dizgiye kod içinden başvuran (xrefs `strings_used`) her fonksiyon ya dizginin yuva kullanıcısıdır ya da bütün çağıranları yuva kullanıcısı olan bir yükleyicidir | `K1_yuva_disi_basvuru` |
| K2 tek sahip | dizgi | Yuva kullanıcılarının `lift`'leri tam olarak bir fonksiyona iner | `K2_sahipsiz` (bir kullanıcı sahipsiz), `K2_cok_sahip` (≥ 2 sahip) |
| K3 gövdede tek ad | fonksiyon | Sahibin gövdesindeki yuva adları (kaldırılmış parçalar dahil) tek bir değere iner. Türler arası çelişki (assert X, `__func__` Y) buraya düşer | `K3_govdede_cok_ad` |
| K4 ad tekliği | fonksiyon | K3'ten geçen sahipler arasında aynı ad (ayrı dizgi nesneleri) birden çok fonksiyonda değil | `K4_ad_cok_fonksiyonda` |
| K5 zaten adlı | fonksiyon | Sahibin Ghidra adı jenerik (`FUN_`, `thunk_FUN_`, `LAB_`, `SUB_`, `sub_`, `entry`, `_INIT_N`, `_FINI_N`) | `K5_zaten_adli` |

**K0:**
- Başlıkta tanımlı fonksiyon (`static inline`) başka gövdelere inline edilmiş olabilir. Assert'i yazanın başlık fonksiyonu olduğu dosya argümanından bilinir.
- Geliştirme setinde Debian zstd'de 96 dizgiyi düşürdü (§12).
- **[seçim] K0 açık** (öneri: evet). Gerekçe: inline edilen başlık yardımcısının adı, onu içeren fonksiyona yanlış çapa olur; tersine bir kanıt yok.
- **[seçim] K0 adları K3'te gövde adı sayılmaz** (öneri: sayılmaz). Gerekçe: başlık adının gövdenin kendi adı olmadığı zaten biliniyor; sayılsa, kendi assert'i olan fonksiyonun doğru çapası da düşerdi (zstd'de K3 elemesi 118'den 88'e indi).
- **[seçim] Uzantı listesi** (öneri: yukarıdaki dokuz). Gerekçe: C ve C++ başlıkları ile içerilen (`#include`) kaynaklar.

**K1:**
- Sınır: xrefs yalnız kod içi başvuruları taşır. Veri bölümündeki işaretçi tablolarından gelen başvurular görünmez, bu yüzden K1 o durumda zayıftır (§13).
- Yuva kullanıcısının aynı dizgiyi gövdesinde yuva dışında da kullanması fonksiyon düzeyinde ayırt edilmez.

**K2:** aynı `__func__` nesnesi iki fonksiyonun yuvasında geçiyorsa, sahibi inline edilmiş bir fonksiyondur (ya da biri onun kopyası).

**K3:**
- **[seçim] Gövde adlarına K1 ve K2'de elenmiş dizgiler dahil** (öneri: dahil). Gerekçe: birden çok yerde inline edilen Y'nin (K2'de elenen) izini taşıyan gövde X'e "Z" çapası verilmesin; gövdede kendi adından başka ad olduğu biliniyor.

**K4:**
- **[seçim] K4 açık** (öneri: evet). Gerekçe: aynı adın ayrı nesneleri çoğunlukla başlık fonksiyonunun çeviri birimi kopyalarıdır. Bedeli: farklı dosyalarda aynı adlı `static` fonksiyonların ikisi de çapasız kalır.

**K5:**
- Ad export türünden gelebilir (§3.4). Dizgi türleri, Ghidra'nın zaten adlandırdığı fonksiyona çapa yazmaz.
- **[seçim] K5, K4'ten sonra** (öneri: evet). Gerekçe: adlı bir fonksiyonun gövdesindeki ad da ad tekliğine sayılsın (tutucu).
- `entry` (Mac'te `main`) jeneriktir, çapa alabilir (`macho_f1` ile aynı).

**Hepsi tutucu:** bir kural tutmazsa ad yazılmaz. Çıktı adrese göre sıralıdır; bütün küme dolaşımları sıralıdır. Girdi sırasından ve `PYTHONHASHSEED`'den bağımsızlık testle kilitli.

## 6. Doğruluk ölçütü (adım 2)

**GT:**
- **Mac:** `macho_measure prepare`'in nm GT'si: `workspaces/olcum_mac/corpus/<p>/gt/<p>.gt.json` (`macho_measure.gt_path`). Koşunun `raw/target_info.json` sha256'sı GT'deki strip'li kopyanın sha256'sıyla aynı olmalı.
- **ELF:** dbgsym `.debug` dosyasının `.symtab`'ı: `function_f1.extract_gt`. Build-id eşleşmesi ve strip denetimi bu işlevde yapılır. Hata ayıklama dosyası `x_*-dbgsym_*/usr/lib/debug/.build-id/` altında build-id'yle bulunur; tam bir tane olmalı.

**Adres eşleme:**
- Mac: Ghidra adresi = VM adresi.
- ELF: Ghidra adresi − ofset; ofset `function_f1.derive_image_offset`'ten gelir (Ghidra `entry` − `e_entry`; PIE'de 0x100000).
- Çapanın adresinde GT fonksiyonu yoksa **eşlenemeyen** satırına düşer, kesinliğe girmez.

**Ad karşılaştırması: tam eşitlik.**
- Çapa adı, GT fonksiyonunun takma adlarından birine eşittir.
- Mach-O GT adlarının baştaki tek `_`'ı soyulur.
- Büyük/küçük harf, `m_`/`g_` gibi önekler ve `_N` ekleri yok sayılmaz.

**Klon satırı:**
- GT'nin bütün takma adları derleyici ekli ise çapa **klon** satırına düşer: `.isra`, `.constprop`, `.part`, `.cold`, `.lto_priv`, `.clone`, `.llvm`, `.__uniq`, zincirleri dahil.
- Eki soyulmuş tabana tam eşitlik doğru sayılır. `OUTLINED_FUNCTION_N`'nin tabanı yoktur (yanlış).
- Klon satırı kesinliğe girmez, ayrı raporlanır.

**Parça çapaları:** `assert_ust` satırının ayrı sayımında. GT'leri büyük olasılıkla `X.cold.N` ya da `X.part.N`'dir.

**Duyarlılık satırları** (karar dışı):
- proje normalleştirmesi: `function_f1.match_strict`; büyük/küçük harf, önek ve `_N` ekini yok sayar;
- örnek düzeyi: tekilleştirmesiz (§7).
- **[seçim] Proje normalleştirmesi satırı raporlanır** (öneri: evet). Gerekçe: tarihsel F1 ölçümleriyle kıyas; karar tam eşitlikle.

**Çıktı:** `olc` çıktısında öğe düzeyinde ad yoktur; yalnız sayılar ve oranlar.

## 7. Nüfus

**Birim:** (platform, program); 10 birim.
- **Mac** (`workspaces/olcum_mac/runs/ol7-a-9a36142`): tmux, htop.
  - Karadul commit 9a36142, Ghidra 12.1.2.
  - Analiz edilen dosya Apple strip'li kopya.
- **Debian 13 arm64** (`~/karadul_olcum/n1_debian13`): 8 program, 117 ELF.
  - tmux 1, htop 1, tree 1;
  - zstd 2: `zstd`, `pzstd`;
  - redis-tools 4: `redis-benchmark`, `redis-check-aof`, `redis-check-rdb`, `redis-cli`;
  - sqlite3 1, openssl 1, coreutils 106.
  - Karadul commit a10fde3; `karadul/` dizini 1f69b35 ile aynı (`git diff 1f69b35 a10fde3 -- karadul/` boş).
  - Ghidra sürümü çıktıda kayıtlı değil; koşu, Karadul'un sabitlediği kurulumla (`GHIDRA_PINNED_VERSION = "12.1.2"`) yapıldı. Adım 2'de doğrulanmalı.
- **[seçim] tmux Mac ve tmux Debian ayrı birim** (öneri: ayrı). Gerekçe: derleyici, nesne biçimi ve çağrı kuralı farklı; platform başına okunabilsin.

**Eksiksizlik:**
- `olc`, bulunan ELF sayısını beklenenle (Mac 2, Debian 117) karşılaştırır.
- Bitmemiş ya da hatalı (`BITTI`'siz) ELF varsa ölçüm durur. `--eksik-izinli` ile sürer; o zaman eksikler çıktıda listelenir.

**C++ ikililer:**
- İçe aktarılan adlardan biri `_Z`, `__gxx_personality`, `__cxa_begin_catch`, `__cxa_end_catch`, `__cxa_throw` ya da `__cxa_rethrow` ile başlıyorsa ikili C++ sayılır. Ghidra mangled adları açtığı için `_Z` tek başına yetmez; `__cxa_finalize` ve `__cxa_atexit` C ikililerinde de var.
- Geliştirme setinde yalnız pzstd.
- **[seçim] C++ ikililer kesinlik dışı, GT'siz sayılır** (öneri: evet). Gerekçe: GT adları mangled, `__func__` niteliksiz ad verir; tam eşitlik tanımsız. Açma yolu ayrı ön kayıtla: açılmış GT'nin niteliksiz adıyla karşılaştırma.

**coreutils ve çok ELF'li programlar:**
- **[seçim] Birim programdır; tekil öğe (karar satırı, ad)'dır; öğe, bütün örnekleri doğruysa doğrudur** (öneri: evet).
  - Gerekçe: gnulib fonksiyonları 106 ELF'te yineleniyor. Örnek başına saymak aynı iddiayı 106 kez sayar.
  - "Hepsi doğru" kuralı, inline kararının ELF'e göre değiştiği durumda tutucudur.
- Örnek düzeyi (tekilleştirmesiz) duyarlılık satırı olarak raporlanır.

**Ad bekleyen nüfus** (kapsam paydası):
- **Mac:** GT fonksiyonu, o adreste thunk olmayan ve adı jenerik olan bir Ghidra fonksiyonu var, sınıfı `program` (`macho_f1.fragment_class`; `cold` ve `outlined` dışarıda).
- **ELF:** GT fonksiyonu CRT ya da export değil; o adreste Ghidra'nın `code` sınıfında, thunk olmayan, adı jenerik bir fonksiyonu var; takma adlarının hepsi derleyici ekli değil (klon değil).

## 8. Karar kuralı

**Karar satırları:**
- `assert`: rolü `kendi`;
- `assert_ust`;
- `func_kalibi`;
- `func_aktarma`.

Bir çapa birden çok türü taşıyabilir. Örnek: aynı ad hem assert'ten hem `__func__` kalıbından geldiyse her iki satırda sayılır.

**Yalnız raporlananlar:**
- `export`: beklenen kesinlik ≈ %100, KS-1 iddiası değil;
- `dizgi_turleri`: bütün dizgi türleri birleşik, çapa başına bir.
- **[seçim]** (öneri: bu ikisi karar satırı değil). Gerekçe: export ad üretmiyor, Ghidra'nın adını işaretliyor; birleşik satır karar satırlarının toplamı.

**Kural:**
1. Birim kesinliği: tekil öğelerde doğru / n, Wilson %95 aralığıyla (z = 1,96).
2. Makro ortalama: n ≥ N_MIN olan birimlerin kesinlik ortalaması.
   - **[seçim] N_MIN = 10** (öneri). Gerekçe: daha az çapalı birimin tek bir yanlışı ortalamayı %10 oynatır.
3. En az EN_AZ_BIRIM birim N_MIN'i geçmeli; geçmezse karar `yetersiz` olur ve satır üründe kesin sayılmaz.
   - **[seçim] EN_AZ_BIRIM = 2** (öneri). Gerekçe: tek programın kesinliği programa özgü olabilir; iddia ölçülen kadar.
4. Makro ≥ %95 → `kesin`; < %95 → `kesin_degil`.
   - **[seçim] Eşik nokta tahminine uygulanır** (öneri: evet).
   - Gerekçe: plan v2.1 3.2 "çapa kesinliği ≥ %95" diyor. Wilson alt sınırı ≥ %95, ≥ 73 öğenin hepsinin doğru olmasını ister; geliştirme setinde birim başına bu sayı yok.
   - Doğrulama setindeki tek okuma (Kapı 2: "kesin kanallarda kesinlik ≥ %95") ayrıca sınar.
5. N_MIN altındaki birimler "küçük" diye listelenir. Havuzlanmış (mikro) kesinlik ve Wilson aralığı raporlanır, kararı değiştirmez.
6. `kesin` çıkmayan satır üründe kesin olmaz. Aday olarak mı kalacağı, susacak mı ve hangi güven etiketini taşıyacağı adım 3'ün kararıdır.

**Nokta tahminiyle ≥ %95 için izin verilen en çok yanlış:**

| n | 10 | 20 | 40 | 60 | 100 | 150 |
|---|---|---|---|---|---|---|
| en çok yanlış | 0 | 1 | 2 | 3 | 5 | 7 |

## 9. Kapsam ve program sınıfı eş değişkeni

**Kapsam:** karar satırı ve birim başına, Wilson aralığıyla.
- kapsam = nüfusta çapalanan / nüfus;
- tam ad kapsamı = nüfusta doğru çapalanan / nüfus.
- coreutils'te örnek düzeyinde: Σ çapalanan / Σ nüfus.
- **[seçim]** (öneri: örnek düzeyi). Gerekçe: üründeki karşılığı ELF başına ad almak.

**Program sınıfı** (GT'siz, `ks1_olc.py sinif`):
- **Dizgi zenginliği:** Σ snake_case dizgi / Σ iç fonksiyon, birimin ELF'leri üzerinden.
  - snake_case: `ghidra_strings.json` girdisi (adres başına), `^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$`.
  - İç fonksiyon: thunk ve dış olmayan Ghidra fonksiyonu.
- **[seçim] Zenginlik sınıfı:** platform içindeki birimlerin ortancasına göre zengin / yoksul (öneri). Gerekçe: yalnız eş değişken; Mac'te iki birim var, mutlak eşik keyfi olurdu.
- **[seçim] Boyut tabakası:** birimdeki ELF'lerin iç fonksiyon sayısı ortancası; < 500 küçük, < 2000 orta, ≥ 2000 büyük (öneri). Gerekçe: coreutils'in tek ELF'i küçük bir programdır; toplam boyut onu büyük gösterirdi.
- Değerler koşu bitince platform başına kilitlenir (Berke). Ara değerler §12'de.
- Kapsam ve kesinlik sınıf başına raporlanır. Sınıf başına hedef yoktur (v2.2 §0 karar 4).

## 10. Ablasyon (adım 2-3)

**Plan:**
- Ürün adlandırması KS-1'li ve KS-1'siz koşulur: aynı Ghidra çıktısı, aynı c_namer/tarif.
- Fark: KS-1 çapaları `run_tarif`'in `kesin` girdisi olur (`kesin.kesin_mapping`) ve NameMerger'da öncelik alır.
- Ölçü: tam ad F1 (strict), yanlış oranı, kapsam; ayrıca KS-1'in sağladığı adların payı.
- Bu belge ablasyonun yapılacağını kaydeder. Bağlama biçimi ve ölçüsü adım 3'ün ön kaydında yazılır.

**N0b ile ilişki** (`alt_kanal_onkayit.md` §6):
- KS-1'in adlandırdığı fonksiyonlar KS-1 kökeniyle ad alır, `string_context`'ten çıkar.
- KS-1'in almadığı fonksiyonlarda `oz_ad` ve öbür alt kanallar N0b'nin kararına uyar.

## 11. Ön koşullar ve sabitlenen dosyalar

`ks1_olc.py olc` koşu başında aşağıdakileri denetler; biri tutmazsa durur:
1. bu belgeyi depoya ilk ekleyen commit HEAD'in atası;
2. o commit'teki `ks1_sabitler.json`'da yazan sha256'lar ile bugünkü `kesin.py` ve `ks1_olc.py` aynı;
3. nüfus eksiksiz (§7).

- Sabitler, sonradan güncellenen dosyadan değil ön kayıt commit'indeki hâlinden okunur: sonradan güncellemek kodu aklamaz (testle kilitli).
- Bu yüzden bu belge ile `ks1_sabitler.json` **aynı commit'te** depoya girmelidir.
- `ks1_olc.py sabitle` dosyayı bugünkü sha256'larla yazar; ön kayıt commit'inden önce koşulur.
- Kod ön kayıttan sonra değişirse betik ölçmez; değişiklik ancak yeni bir ön kayıtla (sapma kaydı) açılabilir.

| Dosya | sha256 |
|---|---|
| `karadul/reconstruction/tarif/kesin.py` | `cd77947252ed9514cf6664c87a45837c513ef7aa7f15bf82abaa3243f541bcc9` |
| `scripts/measurement/ks1_olc.py` | `26feb9b0be52dc978ab39ed1398aa3c8099041d90d690e6a55265cd8827b15d7` |
| `tests/test_tarif_kesin.py` | `f92823b4f49e202b137aa3b1a404bb187560db796d25b099de7dacea53431f84` |
| `tests/test_ks1_olc.py` | `52237e25253bbdbfc9020ae1df853d46b8a72db6521e8060aa657c62641da9eb` |
| `scripts/measurement/mutation_specs_ks1.json` | `d69dfad026755ddaba204876cd16dc2f52ea9a7e980636019dd2db0e560b4665` |

**Testler ve mutasyon:**
- `python -m pytest tests/test_tarif_kesin.py tests/test_ks1_olc.py -q -p no:cacheprovider`: 101 test geçti.
- `PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec scripts/measurement/mutation_specs_ks1.json`: 30 mutant, 30'u öldü (0 hayatta, 0 hata).
- Mutantların uzunluğu özgününden farklıdır (`.pyc` tuzağı). Hepsi gerçek test başarısızlığıyla öldü, sözdizimi hatasıyla değil.

## 12. GT'siz sayım (bütün geliştirme ELF'leri bitti)

Komut: `python scripts/measurement/ks1_olc.py say --mac-kosu workspaces/olcum_mac/runs/ol7-a-9a36142 --debian-kosu ~/karadul_olcum/n1_debian13 --json … --md …`

Sayım anı: 2026-10-21 13:46 (bütün ELF'ler bitti). `kesin.py` sha256 `cd77947252ed9514…`.

**Biten ELF'ler:**
- `mac/tmux`: 1/1
- `mac/htop`: 1/1
- `debian/tmux`: 1/1
- `debian/htop`: 1/1
- `debian/tree`: 1/1
- `debian/zstd`: 2/2
- `debian/redis-tools`: 4/4
- `debian/sqlite3`: 1/1
- `debian/openssl`: 1/1
- `debian/coreutils`: 106/106
- Toplam: 119/119 bitti; 0 ELF koşuyor (`BITTI` yok), 0 ELF henüz başlamadı.

**Koruma hunisi** (yalnız sıfır olmayan satırlar). K0-K2 sütunları dizgi, sonrakiler fonksiyon sayar:

| Birim | Tür | Yuva | Dizgi | K0 | K1 | K2 | Aday fonksiyon | K3 | K4 | Çapa (K5) |
|---|---|---|---|---|---|---|---|---|---|---|
| `debian/coreutils` | `assert` | 120 | 86 | 86 | 84 | 83 | 74 | 65 | 65 | 65 |
| `debian/openssl` | `func_kalibi` | 209 | 30 | 30 | 30 | 30 | 18 | 16 | 16 | 16 |
| `debian/openssl` | `func_aktarma` | 2 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
| `debian/redis-tools` | `assert` | 217 | 140 | 140 | 140 | 140 | 130 | 122 | 122 | 60 |
| `debian/tmux` | `func_kalibi` | 284 | 138 | 138 | 136 | 130 | 111 | 97 | 97 | 97 |
| `debian/tmux` | `func_aktarma` | 28 | 19 | 19 | 18 | 17 | 17 | 15 | 15 | 15 |
| `debian/zstd` | `assert` | 2423 | 461 | 365 | 362 | 316 | 256 | 168 | 168 | 168 |
| `mac/tmux` | `assert` | 14 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 |
| `mac/tmux` | `func_kalibi` | 283 | 186 | 186 | 185 | 182 | 163 | 150 | 150 | 150 |
| `mac/tmux` | `func_aktarma` | 71 | 23 | 23 | 23 | 23 | 22 | 21 | 21 | 21 |

Sıfır satırlı birimler (hiçbir dizgi türünde yuva yok): `debian/htop`, `debian/sqlite3`, `debian/tree`, `mac/htop`.

**Rol, export ve elemeler:**

| Birim | ELF | C++ ELF | Çapa: kendi / üst / parça | Export | Aktarıcı fonksiyon | K0 | K1 | K2 sahipsiz | K2 çok sahip | K3 | K4 | K5 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `debian/coreutils` | 106 | 0 | 65 / 0 / 0 | 211 | 39 | 0 | 2 | 1 | 0 | 9 | 0 | 0 |
| `debian/htop` | 1 | 0 | 0 / 0 / 0 | 366 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `debian/openssl` | 1 | 0 | 16 / 0 / 0 | 0 | 3 | 0 | 1 | 0 | 0 | 2 | 0 | 0 |
| `debian/redis-tools` | 4 | 0 | 60 / 0 / 0 | 8394 | 4 | 0 | 0 | 0 | 0 | 8 | 0 | 62 |
| `debian/sqlite3` | 1 | 0 | 0 / 0 / 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `debian/tmux` | 1 | 0 | 111 / 0 / 0 | 0 | 4 | 0 | 3 | 0 | 7 | 16 | 0 | 0 |
| `debian/tree` | 1 | 0 | 0 / 0 / 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `debian/zstd` | 2 | 1 | 164 / 4 / 4 | 0 | 2 | 96 | 3 | 19 | 27 | 88 | 0 | 0 |
| `mac/htop` | 1 | 0 | 0 / 0 / 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `mac/tmux` | 1 | 0 | 169 / 3 / 14 | 0 | 7 | 0 | 1 | 0 | 3 | 14 | 0 | 0 |

Eleme sütunları türlerin toplamıdır; bir dizgi ya da fonksiyon birden çok türü taşıyorsa her türde sayılır.

**Program sınıfı eş değişkeni (ara, kilitlenmedi):**

| Birim | ELF | İç fonksiyon | snake_case dizgi | Dizgi zenginliği | Zenginlik sınıfı (platform ortancası) | ELF ortancası | Boyut tabakası |
|---|---|---|---|---|---|---|---|
| `debian/coreutils` | 106 | 14120 | 97 | 0,007 | `yoksul` (0,103) | 112 | `kucuk` |
| `debian/htop` | 1 | 609 | 113 | 0,186 | `zengin` (0,103) | 609 | `orta` |
| `debian/openssl` | 1 | 592 | 404 | 0,682 | `zengin` (0,103) | 592 | `orta` |
| `debian/redis-tools` | 4 | 10531 | 225 | 0,021 | `yoksul` (0,103) | 2672 | `buyuk` |
| `debian/sqlite3` | 1 | 429 | 85 | 0,198 | `zengin` (0,103) | 429 | `kucuk` |
| `debian/tmux` | 1 | 1920 | 496 | 0,258 | `zengin` (0,103) | 1920 | `orta` |
| `debian/tree` | 1 | 119 | 0 | 0,000 | `yoksul` (0,103) | 119 | `kucuk` |
| `debian/zstd` | 2 | 1931 | 6 | 0,003 | `yoksul` (0,103) | 965,5 | `orta` |
| `mac/htop` | 1 | 597 | 58 | 0,097 | `yoksul` (0,239) | 597 | `orta` |
| `mac/tmux` | 1 | 2588 | 986 | 0,381 | `zengin` (0,239) | 2588 | `buyuk` |

**Tekil aday sayısı** (karar satırı × birim; farklı ad sayısı, parantezde örnek sayısı; C++ ve parça dışarıda). Kararda N_MIN bu sayıyla karşılaştırılır; GT eşlemesinden sonra eşlenemeyen ve klon satırları düşeceği için ölçümdeki n bundan küçük olabilir:

| Birim | `assert` | `assert_ust` | `func_kalibi` | `func_aktarma` | `dizgi_turleri` | `export` |
|---|---|---|---|---|---|---|
| `debian/coreutils` | 32 (65) | 0 | 0 | 0 | 32 (65) | 3 (211) |
| `debian/htop` | 0 | 0 | 0 | 0 | 0 | 366 (366) |
| `debian/openssl` | 0 | 0 | 16 (16) | 0 | 16 (16) | 0 |
| `debian/redis-tools` | 31 (60) | 0 | 0 | 0 | 31 (60) | 3855 (8394) |
| `debian/tmux` | 0 | 0 | 97 (97) | 15 (15) | 111 (111) | 0 |
| `debian/zstd` | 164 (164) | 4 (4) | 0 | 0 | 168 (168) | 0 |
| `mac/tmux` | 0 | 3 (3) | 150 (150) | 21 (21) | 172 (172) | 0 |

## 13. Bilinen sınırlar ve riskler

1. **Tek yerde inline edilen fonksiyon.**
   - Tek çağrılı `static` bir fonksiyon inline edilince adı tek bir gövdede kalır; yapısal olarak görünmez.
   - K3 bunu ancak gövdenin kendi adı da bir yuvadaysa yakalar.
   - Beklenen başlıca yanlış kaynağı budur. Ölçümde yanlışlar bu yüzden tür ve rol başına okunur.
2. **Kaldırma.**
   - Parçanın tek üstü inline eden fonksiyon olabilir (§4).
   - Yalnız `assert(0)` içeren, inline edilmemiş tek çağıranlı bir fonksiyon da (`unreachable()`) parça gibi görünür; adı çağırana kaldırılır.
   - Kaldırılmış çapalar bu yüzden ayrı satırdadır.
3. **Aktarıcı parametresi.** Parametre bir ileti ya da alt sistem adı olabilir (Debian htop `CRT_fatalError`). Çağıranlar orada tanımlayıcı olmayan ileti geçtiği için çapa çıkmadı; tanımlayıcı biçimli bir ileti çapa olurdu.
4. **Alt komut ya da alt sistem öneki.**
   - `"%s: …"` önekindeki sabit, fonksiyonun adı yerine bir alt komutun ya da alt sistemin adı olabilir.
   - Debian openssl'de `func_kalibi`'nin 209 yuvası 30 dizgiye düşüyor: dizgi başına yaklaşık 7 kullanım. tmux'ta bu oran 2'nin altında (Mac 283 / 186, Debian 284 / 138).
   - Böyle bir dizgi tek fonksiyonda kalırsa K1-K5'ten geçer. Adlara bakılmadı; ölçüm bunu tür ve birim başına gösterecek.
5. **Export.**
   - Ad dinamik simge tablosundan gelir; `-rdynamic` programlarında çok sayıdadır.
   - K5 nedeniyle dizgi türleri bu fonksiyonlara çapa vermez. Bu yüzden htop ve redis gibi programlarda dizgi kapsamının paydası küçüktür.
   - Mac'te export yok. Mach-O dylib ya da strip'siz Mac ikilisinde Ghidra'nın simge adının baştaki `_`'ı nasıl verdiği denenmedi.
6. **Darwin'de sabit argümanlı çağrı.** Değişken argümansız bir fonksiyona `(fmt, ad)` geçilirse ad x1'dedir, `[sp]`'de değil; yakalanmaz. Kapsam kaybıdır, yanlış değil.
7. **xrefs yalnız kod başvurularını taşır.** Veri bölümündeki işaretçi tabloları K1'e görünmez; böyle bir dizgi saf görünür.
8. **Ghidra fonksiyon sınırları.** Bölünmüş ya da birleşmiş fonksiyonlar "eşlenemeyen" ya da yanlış satırına düşer. Sınır hatası ayrıca raporlanmaz.
9. **Mimari.** Yalnız AArch64. Doğrulama ve test setleri aynı mimaride (plan v2.2 §1).
10. **Veri akışı yaklaşıktır.**
    - Fonksiyon içidir. Yükleyici özeti tek düzeydir; çağrılar dışında fonksiyonlar arası akış yoktur.
    - Döngüde değişen değer birleşmede düşer.
    - Tanınmayan komutlar yalnız ilk işlenenlerini öldürür. Yanlış bir yazmaç değerini canlı tutan nadir komutlar bir yuvayı yanlış dizgiye bağlayabilir. Tanınan saklama ve atomik biçimler dışında bunun ölçüsü yok.
11. **Küçük ve bağımlı örneklem.**
    - Birim başına çapa sayıları onlarla yüzler arasında.
    - Aynı programdan ve aynı dosyadan gelen çapalar bağımsız değildir; Wilson aralıkları iyimserdir (N0b §7 madde 4).
12. **Tanımları yazanın bilgisi.**
    - Tanımları bir LLM ajanı (Claude Opus 5.5) yazdı.
    - Geliştirme setinin Ghidra çıktılarını (dizgiler, disassembly, C) etiketsiz gördü.
    - tmux, htop, zstd ve coreutils kaynaklarını eğitiminden tanıyor olabilir; örtük bir ayar tümüyle dışlanamaz.
    - Önlemler:
      - kurallar yalnız yapıya (çağrı kuralı, yuva, sahiplik, dosya uzantısı) dayanır;
      - hiçbir kural belirli bir ada ya da ad listesine başvurmaz;
      - kurallar ve atamalar GT'den önce bu belgeyle sabitlenir.

## 14. Bütünlük kaydı: neye bakıldı, neye bakılmadı

**Bakılmadı:**
- GT: `nm` çıktısı, `*.gt.json`, `macho_score.json`, dbgsym `.debug` dosyalarının içeriği (`.symtab`, DWARF), dSYM'ler;
- G4 etiket ve anahtar dosyaları (`docs/arge/2026-10-19_g4_etiketleme/veri/`), `kesinlik_tablosu.json`, `kayitlar_*.jsonl`;
- doğrulama ve test setleri (`targets/`, `docs/arge/dogrulama_seti*`, `docs/arge/test_seti*`).

GT yükleyicileri (`function_f1`, `macho_f1`) bu adımda hiç çalıştırılmadı; sayım kipinde de çalıştırılmadı.

**Bakıldı:**
- plan v2.2 ve v2.1'in ilgili bölümleri; N0b ön kaydı (`alt_kanal_onkayit.md`) ve toplu sonucu (`kesinlik_tablosu.md`);
- `tarif/`, `string_intelligence.py`, `headless.py` (disassembly ve xrefs yazımı), `function_f1.py`, `macho_f1.py`, `macho_measure.py` (yol işlevleri), `alt_kanal_olc.py`, `mutation_probe.py`;
- Mac `ol7-a-9a36142` ve Debian `n1_debian13` çalışma alanlarının `static/` çıktıları: fonksiyon listesi, dizgiler, xrefs, decompile C ve disassembly;
- `raw/target_info.json` (yol, sha256), `run.json` ve `session.json` (künye), Debian `manifest.json` (paket listesi);
- literatür taraması (`2026-10-21_literatur/yontem_taramasi.md`, a10fde3; yalnız okundu);
- proje hafızasındaki FLIRT ölçüm notu (2026-09-25).

**Kazara görülen:**
- `test_seti_kura.py`'de içe aktarma yan etkisi ararken çalıştırılan `grep`, test seti stres adaylarının listesini taşıyan satırı bastı (beş program adı). Dosya açılmadı, başka satırı okunmadı.
- `macho_f1.py` belge dizgisinde GT'den bir örnek ad geçiyor (`_grid_check_is_clear.cold.1`).
- Keşifte disassembly ve dizgi örneklerinde birkaç fonksiyon adı dizgisi görüldü. Bunlar çapa kanıtıdır, GT değil. Çapalar hiçbir yerde gerçek adlarla karşılaştırılmadı.

**Tasarım geçmişi** (hepsi GT'siz):
- İlk taslakta GCC bölüm çapası (`add xD, xS, #imm`, xS sabit) ve yığından geri yükleme yoktu. Debian tmux'ta `func_kalibi` yuvası 42'de kalınca C çıktısıyla karşılaştırıldı ve eklendi. Sonra 284 yuva çıktı (Mac'te 283).
- K0, zstd'nin assert parçalarının çağrı yapısı incelenince eklendi: başlık fonksiyonunun kısmi inline parçası birden çok fonksiyondan çağrılıyordu.
- C++ işareti ilk sürümde `__cxa_` önekiydi; glibc'nin `__cxa_finalize`'ı yüzünden bütün Debian ELF'leri C++ çıktı ve düzeltildi.
- Hiçbir değişiklik bir doğruluk ya da GT sayısına bakılarak yapılmadı; değişikliklerin dayanağı sayaçlar ve kod yapısıdır.

## 15. [seçim] maddeleri (özet)

| # | Madde | Öneri | Yer |
|---|---|---|---|
| 1 | Yükleyici değeri yalnız assert yuvasında | evet | §2 |
| 2 | Ad yuvası dizgisinde alt çizgi zorunlu | hayır | §2 |
| 3 | Program adı dışlanır | evet | §2 |
| 4 | Biçim ayraçları | `%s:`, `%s()` | §3.2 |
| 5 | `func_aktarma` ayrı tür | evet | §3.3 |
| 6 | Kaldırılmış assert ayrı karar satırı (`assert_ust`) | evet | §4 |
| 7 | K0 açık | evet | §5 |
| 8 | K0 adları K3'te sayılmaz | evet | §5 |
| 9 | K0 uzantı listesi | dokuz uzantı | §5 |
| 10 | K3'te elenmiş dizgiler dahil | evet | §5 |
| 11 | K4 açık | evet | §5 |
| 12 | K5, K4'ten sonra | evet | §5 |
| 13 | Proje normalleştirmesi satırı | evet (karar dışı) | §6 |
| 14 | tmux Mac ve Debian ayrı birim | evet | §7 |
| 15 | C++ ikililer kesinlik dışı | evet | §7 |
| 16 | Çok ELF'li programda birim = program; (satır, ad) tekil, hepsi doğruysa doğru | evet | §7 |
| 17 | `export` ve birleşik satır karar dışı | evet | §8 |
| 18 | N_MIN | 10 | §8 |
| 19 | EN_AZ_BIRIM | 2 | §8 |
| 20 | Eşik nokta tahminine | evet | §8 |
| 21 | Kapsam örnek düzeyinde | evet | §9 |
| 22 | Zenginlik sınıfı: platform içi ortanca | evet | §9 |
| 23 | Boyut tabakası sınırları (ELF ortancası) | 500 / 2000 | §9 |
