# G11 / N1: KS-1 kesin çapalar — ön kayıt

- **Tarih:** 2026-11-10 (taslak 2026-10-21, kararlar 2026-10-22, koda işlenmesi 2026-10-22 ve 2026-11-10).
- **Durum:** Kesin ön kayıt (adım 1/3). GT'ye bakılmadan yazıldı. Bu belge ve `ks1_sabitler.json` aynı commit'te depoya girer; `ks1_olc.py olc` o commit'i resmî ön kayıt sayar ve ön koşulları kendisi denetler (§11). Ölçüm adım 2'dir.
- **[seçim] maddeleri:** 23 maddenin hepsi karara bağlandı (§15). Metinde **[seçim]** diye kalan maddelerde yazılı öneri kabul edilen karardır. Kararı öneriden farklı çıkan sekiz madde yeniden yazıldı ve **[karar N]** diye işaretlendi (N, §15'teki madde numarası). Taslakta işaretlenmemiş kararlar ve taslaktan bu yana yapılan bütün değişiklikler §16'da.
- **Kararların dayanağı:** maddelerin bağımsız değerlendirmesi (GPT-6 Astra, GT'siz; depo dışında `workspaces/2026-10-22_ks1_secim/codex_degerlendirme.md`) ve ana oturumun incelemesi. Berke mikro kararları ana oturuma bıraktı.
- **Taslak:** `ks1_onkayit_taslak.md` (10d69cd) tarihsel kayıt olarak duruyor; geçerli olan bu belgedir.
- **Plan:**
  - v2.2 §3 N1 (satır 70);
  - §5 program sınıfı (satır 119-122);
  - §0 karar 4: sınıf başına ayrı eşik yok;
  - v2.1 3.2: KS-1 tanımı ve ölçütü.
- **Dayanak:** N0b (`2026-10-21_g10_n0b/`). `oz_ad` alt kanalında (dizgi tek tanımlayıcı, ad ona eşit) yanlış %7,7 (Wilson %3,0-%18,2), karar `belirsiz` çıktı. O tanım dizginin bu fonksiyona ait olduğunu denetlemiyordu. KS-1 sahipliği yapısal olarak kurar: ad yuvası (§3) ve inline koruması (§5).
- **Bu adımda yapılmayan:**
  - GT'ye karşı ölçüm (adım 2);
  - ürüne bağlama (`tarif/__init__.py`), susturma ve güven etiketi (adım 3).

**Dosyalar** (tam sha256'lar `ks1_sabitler.json`'da ve §11'de):

| Dosya | İçerik | Ölçümden önce denetlenir | sha256 (ilk 16) |
|---|---|---|---|
| `karadul/reconstruction/tarif/kesin.py` | çıkarıcı: veri akışı, türler, parçalar, K0-K5 (`KS1_VERSION = 2`) | evet | `2a412e8a4467cff1` |
| `scripts/measurement/ks1_olc.py` | `say`, `sinif`, `olc`, `sabitle` | evet | `33156644d6c0c87c` |
| `scripts/measurement/function_f1.py` | ELF GT'si, ofset, sınıflama (ölçüm yardımcısı) | evet | `edc782981f98abc6` |
| `scripts/measurement/macho_f1.py` | Mac GT'si, parça sınıfı, Wilson aralığı (ölçüm yardımcısı) | evet | `bc48eac6fe1f2879` |
| `scripts/measurement/macho_measure.py` | Mac GT yolu (ölçüm yardımcısı) | evet | `d4d517fd43e835ea` |
| `tests/benchmark/metrics.py` | `function_f1`'in içe aktardığı ölçüt modülü | evet | `114456c29af17fb9` |
| `tests/test_tarif_kesin.py` | çıkarıcı testleri (sentetik `static/`) | hayır | `02c716c633ba4d8b` |
| `tests/test_ks1_olc.py` | ölçüm testleri (sentetik GT, geçici git deposu) | hayır | `d9236ed798b331f7` |
| `scripts/measurement/mutation_specs_ks1.json` | mutant belirtimi | hayır | `faa9054f73c80675` |
| `docs/arge/2026-10-21_g11_n1/ks1_sabitler.json` | yukarıdaki dokuz dosyanın tam sha256'ları | — | — |
| `docs/arge/2026-10-21_g11_n1/ks1_say.json`, `ks1_say.md` | GT'siz sayım (§12); ad içermez | — | — |
| `docs/arge/2026-10-21_g11_n1/ks1_sinif.json` | program sınıfı kilidi (§9, §12) | — | — |

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
- **Güvenlik sınırı:** bir bloğun giriş durumu 64 kezden çok değişirse giriş durumu boşaltılır ("hiçbir değer bilinmiyor") ve blok bu boş durumla yeniden yürütülür (tutucu).

**Ad yuvası dizgisi:**
- Bütün dizgi türlerinde ortak koşul:
  - Değer, `ghidra_strings.json`'da (ya da xrefs'te) tanımlı bir dizginin adresidir.
  - Dizginin tamamı `[A-Za-z_][A-Za-z0-9_]+` biçimindedir: ASCII tanımlayıcı, en az iki karakter. Eşleşme bütün dizgiyedir; sondaki satır sonu kabul edilmez.
- Günlük türlerinde (`func_kalibi`, `func_aktarma`) ek koşullar; assert yuvasında bunlar aranmaz:
  - **[karar 2] Ad en az iki parçalıdır ve en az bir küçük harf taşır.** İki parça: harf ya da rakamlar arasında bir alt çizgi (`oturum_ac`) ya da küçükten büyüğe geçiş (`oturumAc`). Gerekçe: `%s:` yuvası yapısal değil, alışkanlıktır; tek sözcüklü ya da tamamı büyük harf sabitler orada çoğunlukla program, alt komut, modül ya da düzey adıdır (`ERROR`, `server`). Assert'in ad argümanı ise yapı gereği `__func__`'tır; `main` gibi tek sözcüklü adlar orada kalır.
  - **[karar 3] Ad, ikilinin adı ya da adının bir biçimi değildir** (harf duyarsız). Biçimler: adın kendisi, `-` ve `.` yerine `_` konmuş hâli ve `-` ya da `.` ile ayrılan parçaları (`redis-cli` → `redis-cli`, `redis_cli`, `redis`, `cli`). Gerekçe: `"%s: …"` öneki programın kendi adını da sık taşır; assert yuvasında program adına eşit dizgi ise gerçek bir addır.
  - Bu koşullarla elenen yuvalar tür başına sayılır (`ad_bicimi_eleme:<tür>`).

## 3. Çapa türleri

### 3.1 `assert`

- **Çağrılan:** baştaki alt çizgiler atılmış adı aşağıdakilerden biri olan Ghidra fonksiyonu (thunk olması aranmaz; ad yeter). Ad yuvası:
  - Darwin `assert_rtn`: 1. argüman, x0;
  - glibc `assert_fail` ve `assert_perror_fail`: 4. argüman, x3.
- **Dosya argümanı:** üçünde de x1. K0'da kullanılır (§5).
- **Parça:** çağrı bir assert parçasındaysa yuva üst fonksiyona kaldırılır (§4).

### 3.2 `func_kalibi` (`__func__` kalıbı)

Bir çağrı yeri (`bl` ya da işlev dışına `b`) yuvadır, şu koşullarla:
- x0-x7'den **tam olarak biri**, `%s:` ile başlayan sabit bir dizgi taşır: biçim dizgisi, k. yazmaçta.
  - Birden çok yazmaç uyuyorsa yuva yok.
  - Çağrılanın kim olduğu aranmaz: printf ailesi, `fprintf`/`__fprintf_chk`, programın günlük fonksiyonları.
- Bu ilk `%s`'e hizalı argüman, biçimden sonraki ilk değişken argümandır:
  - Darwin'de taze `[sp, #0]`;
  - AAPCS64'te x(k+1); k = 7 ise taze `[sp, #0]`.
- Hizalı değer bir adres sabitidir (yükleyiciden gelmemiş) ve ad yuvası koşullarını (§2; günlük türü koşulları dahil) sağlar.
- **[karar 4] Ayraç: yalnız `%s:`.**
  - Gerekçe: `%s:` C günlük önekinin yerleşik biçimi. Geliştirme setinin 119 çalışma alanında `%s` ile başlayan 2 185 dizginin 1 380'inde `%s`'i `:` izliyor.
  - `%s ` (563), ` - ` (4) ve `(` (5) dosya ya da komut adı önekinde de kullanılır.
  - `%s()` geliştirme setinde hiç geçmiyor; ölçülmemiş bir biçim "kesin" etiketi taşımaz. Ayrı bir ön kayıtla açılabilir.

### 3.3 `func_aktarma`

- **Aktarıcı:** fonksiyon F'nin bir çağrı yerinde (§3.2 koşullarıyla) hizalı değer F'nin j. parametresiyse F, j'nin aktarıcısıdır.
  - Örnek (tmux Mac, `FUN_10000b350`): x0'daki parametre x19'a, oradan `[sp]`'ye gidiyor; biçim dizgisi `"%s: s=none"`. Çağıranlar x0'da tanımlayıcı biçimli bir dizgi geçiriyor.
- **Sabit nokta:** G, aktarıcı F'yi j. parametrede kendi i. parametresiyle çağırıyorsa G, i'nin aktarıcısıdır.
- **Yuva:** aktarıcı F'ye j. parametrede tanımlayıcı biçimli sabit dizgi geçiren çağrı yeri (yükleyiciden gelmemiş). Ad, günlük türü koşullarını (§2) sağlar.
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

**Assert parçası:** aşağıdaki koşulların hepsini sağlayan Ghidra fonksiyonu.
- `ret` ya da dolaylı dallanma (`br`) yok. Tuzak komutları (`brk`, `udf`, `hlt`) dönüş sayılmaz.
- Dolaylı çağrı (`blr`) yok.
- `bl`, kuyruk çağrısı ve işlev dışına koşullu dallanma (`b.cond`, `cbz`, `tbz` …) hedeflerinin hepsi assert işlevi, yükleyici ya da başka bir parça; en az biri assert ya da parça.
- Tanım sabit noktayla hesaplanır: parçaya kuyruk çağrısı yapan parça da parçadır.

Gerekçe (taslaktan fark): koşullu kuyruk çağrısı ya da dolaylı çağrı yapan gerçek bir fonksiyon parça sayılıp adı çağırana kaldırılabiliyordu; parçayı kuyruk çağrısıyla çağıran parça ise tanınmıyordu.

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
| K0 dosya bilinmiyor | dizgi | Assert yuvasının dosya argümanı sabit bir dizgiye çözülemiyor: K0 değerlendirilemez. Böyle bir yuvası olan dizgi çapa vermez; adı K3'te gövde adı sayılır | `K0_dosya_bilinmiyor` |
| K1 saf başvuru | dizgi | Dizgiye kod içinden başvuran (xrefs `strings_used`) her fonksiyon ya dizginin yuva kullanıcısıdır ya da o dizgiyi bir yuvaya taşıyan ve bütün çağıranları yuva kullanıcısı olan bir yükleyicidir | `K1_yuva_disi_basvuru` |
| K2 tek sahip | dizgi | Yuva kullanıcılarının `lift`'leri tam olarak bir fonksiyona iner | `K2_sahipsiz` (bir kullanıcı sahipsiz), `K2_cok_sahip` (≥ 2 sahip) |
| K3 gövdede tek ad | fonksiyon | Sahibin gövdesindeki yuva adları (kaldırılmış parçalar dahil) tek bir değere iner. Türler arası çelişki (assert X, `__func__` Y) buraya düşer | `K3_govdede_cok_ad` |
| K4 ad tekliği | fonksiyon | K3'ten geçen sahipler arasında aynı ad (ayrı dizgi nesneleri) birden çok fonksiyonda değil | `K4_ad_cok_fonksiyonda` |
| K4 Ghidra adı | fonksiyon | Ad, Ghidra'nın başka bir adresteki fonksiyona verdiği jenerik olmayan ada eşit değil (Mach-O'da Ghidra adının baştaki tek `_`'ı soyulur) | `K4_ghidra_adi_dolu` |
| K5 zaten adlı | fonksiyon | Sahibin Ghidra adı jenerik (`FUN_`, `thunk_FUN_`, `LAB_`, `SUB_`, `sub_`, `entry`, `_INIT_N`, `_FINI_N`) | `K5_zaten_adli` |

**K0:**
- Başlıkta tanımlı fonksiyon (`static inline`) başka gövdelere inline edilmiş olabilir. Assert'i yazanın başlık fonksiyonu olduğu dosya argümanından bilinir.
- Geliştirme setinde Debian zstd'de 96 dizgiyi düşürdü (§12).
- **[seçim] K0 açık** (öneri: evet). Gerekçe: inline edilen başlık yardımcısının adı, onu içeren fonksiyona yanlış çapa olur; tersine bir kanıt yok.
- **[seçim] K0 adları K3'te gövde adı sayılmaz** (öneri: sayılmaz). Gerekçe: başlık adının gövdenin kendi adı olmadığı zaten biliniyor; sayılsa, kendi assert'i olan fonksiyonun doğru çapası da düşerdi (zstd'de K3 elemesi 118'den 88'e indi).
- **[seçim] Uzantı listesi** (öneri: yukarıdaki dokuz). Gerekçe: C ve C++ başlıkları ile içerilen (`#include`) kaynaklar.
- **Dosya bilinmiyorsa çapa yok** (taslakta işaretlenmemiş karar, §16). Dosya argümanı sabit bir dizgiye çözülemeyen assert yuvasında başlık olup olmadığı bilinemez; "hepsi tutucu" ilkesi gereği dizgi çapa vermez. Başlık olduğu bilinen adların tersine bu ad K3'te gövde adı sayılır: gövdede başka bir ad daha varsa ikisi de düşer.

**K1:**
- Sınır: xrefs yalnız kod içi başvuruları taşır. Veri bölümündeki işaretçi tablolarından gelen başvurular görünmez, bu yüzden K1 o durumda zayıftır (§13).
- Yuva kullanıcısının aynı dizgiyi gövdesinde yuva dışında da kullanması fonksiyon düzeyinde ayırt edilmez.

**K2:** aynı `__func__` nesnesi iki fonksiyonun yuvasında geçiyorsa, sahibi inline edilmiş bir fonksiyondur (ya da biri onun kopyası).

**K3:**
- **[seçim] Gövde adlarına K1 ve K2'de elenmiş dizgiler dahil** (öneri: dahil). Gerekçe: birden çok yerde inline edilen Y'nin (K2'de elenen) izini taşıyan gövde X'e "Z" çapası verilmesin; gövdede kendi adından başka ad olduğu biliniyor.

**K4:**
- **[seçim] K4 açık** (öneri: evet). Gerekçe: aynı adın ayrı nesneleri çoğunlukla başlık fonksiyonunun çeviri birimi kopyalarıdır. Bedeli: farklı dosyalarda aynı adlı `static` fonksiyonların ikisi de çapasız kalır.
- **Ghidra'nın adlarıyla çakışma** (taslakta işaretlenmemiş karar, §16). Ad tekliği Ghidra'nın zaten verdiği adları da görür: `"%s: %s"` kalıbında çağrılan kütüphane işlevinin adı (`setsockopt`) ya da inline edilmiş, dışa aktarılan bir fonksiyonun assert adı, o ad başka bir fonksiyonda (thunk, dış, export) duruyorsa çapa olmaz.

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
- ELF'te ofsetin kaynağı Ghidra'nın `entry` fonksiyonu olmalıdır; yardımcı varsayılan tabana düşerse adres eşlemesi kanıtsız kalır ve ölçüm durur.
- Çapanın adresinde GT fonksiyonu yoksa çapa **eşlenemeyen** satırına düşer ve **yanlış** sayılır: ürün ona da ad yazar.

**Ad karşılaştırması: tam eşitlik.**
- Çapa adı, GT fonksiyonunun takma adlarından birine eşittir.
- Mach-O GT adlarının baştaki tek `_`'ı soyulur.
- Büyük/küçük harf, `m_`/`g_` gibi önekler ve `_N` ekleri yok sayılmaz.

**Klon satırı:**
- GT'nin bütün takma adları derleyici ekli ise çapa **klon** satırına düşer: `.isra`, `.constprop`, `.part`, `.cold`, `.lto_priv`, `.clone`, `.llvm`, `.__uniq`, zincirleri dahil.
- Eki soyulmuş tabana tam eşitlik doğru sayılır. `OUTLINED_FUNCTION_N`'nin tabanı yoktur (yanlış).
- Klon satırı kesinliğe **girer** (taban eşitliğiyle) ve ayrıca dökülür. Gerekçe: taslakta klon ve eşlenemeyen satırlarındaki yanlışlar kararı hiç etkilemiyordu; ürün ise hepsine ad yazar.

**Parça çapaları:** `assert_ust` satırının ayrı sayımında; kesinliğe girmez. GT'leri büyük olasılıkla `X.cold.N` ya da `X.part.N`'dir. Ürün eşlemesi (`kesin.kesin_mapping`) varsayılan olarak parçalara ad yazmaz.

**Duyarlılık satırları** (karar dışı):
- proje normalleştirmesi: `function_f1.match_strict`; büyük/küçük harf, önek ve `_N` ekini yok sayar;
- yalnız ana satır: klon ve eşlenemeyen çapalar dışarıda (taslaktaki tanım);
- tek türlü: yalnız bir türü taşıyan çapalar (türün tek başına kesinliği).
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
  - Ghidra sürümü her çalışma alanının `reports/report.json` dosyasında kayıtlı (`environment.ghidra`): 117 ELF'in ve iki Mac ikilisinin hepsinde 12.1.2, `matches_pinned` doğru (2026-11-10'da sayıldı; taslaktaki "kayıtlı değil" cümlesi yanlıştı). `olc` bunu koşu başında denetler (§11).
- **[karar 14] Rapor birimi (platform, program)'dır; karar kaynak program düzeyindedir.** tmux Mac ve tmux Debian ayrı raporlanır (derleyici, nesne biçimi ve çağrı kuralı farklı), ama kararda tek programdır: aynı kaynak iki bağımsız kanıt sayılmaz (§8).

**Eksiksizlik:**
- `olc`, bulunan ELF sayısını birim başına beklenenle karşılaştırır (yukarıdaki sayılar; Mac 2, Debian 117). Beklenmeyen birim de sorundur.
- Bitmemiş ya da hatalı (`BITTI`'siz) ELF varsa ölçüm durur. `--eksik-izinli` ile sürer; o zaman eksikler çıktıda listelenir.

**C++ ikililer:**
- İçe aktarılan adlardan biri `_Z`, `__gxx_personality`, `__cxa_begin_catch`, `__cxa_end_catch`, `__cxa_throw` ya da `__cxa_rethrow` ile başlıyorsa ikili C++ sayılır. Ghidra mangled adları açtığı için `_Z` tek başına yetmez; `__cxa_finalize` ve `__cxa_atexit` C ikililerinde de var.
- Mach-O'da Ghidra içe aktarılan adı baştaki `_` ile verir (`___assert_rtn`); işaret, tek `_` soyulduktan sonra aranır. Soyulmadan aransaydı `_ZSTD_…` gibi C adları `_Z` sayılırdı.
- Geliştirme setinde yalnız pzstd.
- **[seçim] C++ ikililer kesinlik dışı, GT'siz sayılır** (öneri: evet). Gerekçe: GT adları mangled, `__func__` niteliksiz ad verir; tam eşitlik tanımsız. Açma yolu ayrı ön kayıtla: açılmış GT'nin niteliksiz adıyla karşılaştırma.

**coreutils ve çok ELF'li programlar:**
- **[karar 16] Birim programdır; tekil öğe (karar satırı, ad)'dır; öğe, bütün örnekleri doğruysa doğrudur. Karar, tekil ve örnek düzeyi makrolarının küçüğüyle verilir (§8).**
  - Gerekçe: gnulib fonksiyonları 106 ELF'te yineleniyor. Örnek başına saymak aynı iddiayı 106 kez sayar.
  - "Hepsi doğru" kuralı, inline kararının ELF'e göre değiştiği durumda tutucudur.
  - Tekil kuralın etkisinin yönü veriye bağlıdır: yinelenen bir adın yanlışlarını tek öğeye indirir. Örnek düzeyi bunu dengeler; bu yüzden ikinci karar görünümüdür.

**Ad bekleyen nüfus** (kapsam paydası):
- **Mac:** GT fonksiyonu, o adreste thunk olmayan ve adı jenerik olan bir Ghidra fonksiyonu var, sınıfı `program` (`macho_f1.fragment_class`; `cold` ve `outlined` dışarıda); takma adlarının hepsi derleyici ekli değil (klon değil; ELF ile aynı kural).
- **ELF:** GT fonksiyonu CRT ya da export değil; o adreste Ghidra'nın `code` sınıfında, thunk olmayan, adı jenerik bir fonksiyonu var; takma adlarının hepsi derleyici ekli değil (klon değil).

## 8. Karar kuralı

**Karar satırları:**
- `assert`: rolü `kendi`;
- `assert_ust`;
- `func_kalibi`;
- `func_aktarma`.

Bir çapa birden çok türü taşıyabilir. Örnek: aynı ad hem assert'ten hem `__func__` kalıbından geldiyse her iki satırda sayılır. Yalnız bir türü taşıyan çapaların kesinliği duyarlılık satırıdır (`tek_turlu`).

**Yalnız raporlananlar** (bunlar için karar hesaplanmaz):
- `export`: beklenen kesinlik ≈ %100, KS-1 iddiası değil. Kapsamının payı ve paydası dışa aktarılan GT fonksiyonlarıdır (ad bekleyen nüfus değil);
- `dizgi_turleri`: bütün dizgi türleri birleşik, çapa başına bir.
- **[seçim]** (öneri: bu ikisi karar satırı değil). Gerekçe: export ad üretmiyor, Ghidra'nın adını işaretliyor; birleşik satır karar satırlarının toplamıdır ve başarısız bir satırı örtebilir.

**Kesinliğe giren öğeler:** parça dışındaki bütün çapalar (§6): ana satır (tam eşitlik), klon satırı (taban eşitliği), eşlenemeyen (yanlış).

**Kural** (her karar satırı için):
1. Birim kesinliği iki görünümde hesaplanır, Wilson %95 aralığıyla (z = 1,96):
   - tekil: aynı ad bir öğe, bütün örnekleri doğruysa doğru;
   - örnek düzeyi: her çapa bir öğe.
2. Giren birim: tekil öğe sayısı n ≥ N_MIN.
   - **[seçim] N_MIN = 10** (öneri). Gerekçe: daha az öğeli birimin tek bir yanlışı oranı %10 oynatır.
3. **[karar 14, 19] Program düzeyi.** Aynı kaynak programın giren platform birimlerinin kesinliği ortalanır (program kesinliği). En az EN_AZ_PROGRAM = 2 **farklı** kaynak program girmelidir; girmezse karar `yetersiz` olur ve satır üründe kesin sayılmaz.
   - Gerekçe: tek programın kesinliği programa özgü olabilir; iddia ölçülen kadar. tmux'un iki platformu iki bağımsız kanıt değildir. Taslaktaki kuralla (`EN_AZ_BIRIM = 2`, birim düzeyi) `func_aktarma` yalnız tmux'la `kesin` çıkabilirdi.
4. Makro: program kesinliklerinin eşit ağırlıklı ortalaması; iki görünüm için ayrı hesaplanır.
5. **[karar 16, 20] `kesin`** ancak şu ikisi birlikte tutarsa verilir; tutmazsa `kesin_degil`:
   - karar makrosu = min(tekil makro, örnek düzeyi makro) ≥ %95. Nokta tahminidir; karşılaştırma kesirlerle, yuvarlamasız yapılır.
   - İki görünümün hiçbirinde, giren hiçbir birimin Wilson üst sınırı %95'in altında değildir.
   - Gerekçe (nokta tahmini): plan v2.1 3.2 "çapa kesinliği ≥ %95" diyor. Wilson alt sınırı ≥ %95, ≥ 73 öğenin hepsinin doğru olmasını ister; geliştirme setinde birim başına bu sayı yok.
   - Gerekçe (Wilson üst sınırı): makro tek bir kötü birimi örtebilir (%100 ve %90 → %95). Üst sınırı bile %95'e ulaşmayan birim, eşiğin altında kaldığı örneklem gürültüsüyle açıklanamayan birimdir. Yeni bir sayı gerektirmez. Örnek düzeyinde öğeler bağımsız değildir (aynı ad birçok ELF'te); orada bu koşul istatistiksel bir sınama değil, tutucu bir güvencedir.
   - Doğrulama setindeki tek okuma (Kapı 2: "kesin kanallarda kesinlik ≥ %95") ayrıca sınar.
6. N_MIN altındaki birimler "küçük" diye listelenir. Havuzlanmış (mikro) kesinlik ve Wilson aralığı raporlanır, kararı değiştirmez.
7. `kesin` çıkmayan satır üründe kesin olmaz. Aday olarak mı kalacağı, susacak mı ve hangi güven etiketini taşıyacağı adım 3'ün kararıdır.

**Nokta tahminiyle ≥ %95 için izin verilen en çok yanlış** (tek birim için; makro, programların ortalamasıdır):

| n | 10 | 20 | 40 | 60 | 100 | 150 |
|---|---|---|---|---|---|---|
| en çok yanlış | 0 | 1 | 2 | 3 | 5 | 7 |

**Ölçümden önce bilinenler** (GT'siz; §12'deki tekil aday sayılarından):

- `assert`: giren birimler `debian/coreutils`, `debian/redis-tools`, `debian/zstd` → karar verilebilir (3 program: coreutils, redis-tools, zstd).
- `assert_ust`: giren birimler yok; küçük birimler `debian/zstd`, `mac/tmux` → **`yetersiz` çıkacak** (N_MIN'i geçen 0 program).
- `func_kalibi`: giren birimler `debian/openssl`, `debian/tmux`, `mac/tmux` → karar verilebilir (2 program: openssl, tmux).
- `func_aktarma`: giren birimler `debian/tmux`, `mac/tmux` → **`yetersiz` çıkacak** (N_MIN'i geçen 1 program: tmux).
- Yani bu ölçümde `kesin` çıkabilecek satırlar yalnız yukarıda "karar verilebilir" denenlerdir. `yetersiz` çıkacak satırların kesinliği yine raporlanır; üründe "kesin" etiketi taşımazlar (adım 3).

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
- **[karar 22] Zenginlik sınıfı:** iki platformda ortak, önceden yazılmış mutlak eşik: dizgi zenginliği ≥ 0,05 zengin, altı yoksul. Gerekçe: platform içi ortanca, iki birimli Mac'te sınıfları zorunlu olarak birine bir böler ve aynı program platform değişince sınıf değiştirir (taslakta htop Mac'te yoksul, Debian'da zengin çıkıyordu). 0,05, taslaktaki değerlerde 0,021 ile 0,097 arasındaki boşluğa düşer.
- **[seçim] Boyut tabakası:** birimdeki ELF'lerin iç fonksiyon sayısı ortancası; < 500 küçük, < 2000 orta, ≥ 2000 büyük (öneri). Gerekçe: coreutils'in tek ELF'i küçük bir programdır; toplam boyut onu büyük gösterirdi.
- Değerler kilitlidir: `ks1_sinif.json` (bu commit'te), tablo §12'de. `olc` sınıfları yeniden hesaplayıp çıktısına yazar.
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
2. o commit'teki `ks1_sabitler.json`'da yazan sha256'lar ile ölçümü belirleyen altı dosyanın bugünkü hâli aynı: `kesin.py`, `ks1_olc.py` ve GT'yi, ofseti ve nüfusu üreten yardımcılar (`function_f1.py`, `macho_f1.py`, `macho_measure.py`, `tests/benchmark/metrics.py`);
3. nüfus eksiksiz: birim başına ELF sayısı beklenenle aynı ve hepsi bitmiş (§7);
4. biten bütün ELF'ler aynı, sabitlenmiş Ghidra sürümüyle analiz edilmiş (`reports/report.json`).

Ölçüm sırasında ayrıca denetlenir:
- Mac: analiz edilen dosyanın sha256'sı GT'deki strip'li kopyanınkiyle aynı;
- ELF: analiz edilen dosyanın sha256'sı değişmemiş, build-id için tam bir hata ayıklama dosyası var, ofset Ghidra'nın `entry`'sinden türetilmiş.

Kurallar:
- Sabitler, sonradan güncellenen dosyadan değil ön kayıt commit'indeki hâlinden okunur: sonradan güncellemek kodu aklamaz (testle kilitli).
- Bu yüzden bu belge ile `ks1_sabitler.json` **aynı commit'te** depoya girer.
- `ks1_olc.py sabitle` dosyayı bugünkü sha256'larla yazar; ön kayıt commit'inden önce koşulur.
- Kod ön kayıttan sonra değişirse betik ölçmez; değişiklik ancak yeni bir ön kayıtla (sapma kaydı) açılabilir.

| Dosya | sha256 |
|---|---|
| `karadul/reconstruction/tarif/kesin.py` | `2a412e8a4467cff152a8ed271d0216a5fcb3038f1299ca6e8927e3319838cc48` |
| `scripts/measurement/ks1_olc.py` | `33156644d6c0c87cdce95b0b4abf7337616bb5a8511ab780e16f9a8d8cc49bce` |
| `scripts/measurement/function_f1.py` | `edc782981f98abc6683dec0ee948c7caafcbeaf01759fdc8ddc14dd8586c4bdc` |
| `scripts/measurement/macho_f1.py` | `bc48eac6fe1f2879374f17a5ba198672718f43e648df0b84d18b3e21e7705f43` |
| `scripts/measurement/macho_measure.py` | `d4d517fd43e835ea1546f51186e7167b732d7b4551826ef3353e6009916667d8` |
| `tests/benchmark/metrics.py` | `114456c29af17fb9451a23ede4a2bf071cb02295372b91c25d46878c8240fd09` |
| `tests/test_tarif_kesin.py` | `02c716c633ba4d8b99cfe9e4ece1fbd5459e6482eb4fdc6464bd1ea074d9c76a` |
| `tests/test_ks1_olc.py` | `d9236ed798b331f72937e2c33e46f56b9712de8300d0b28a51dfe2f31d047c8d` |
| `scripts/measurement/mutation_specs_ks1.json` | `faa9054f73c806757d45bcb453ec12c82067f878907b6378b247dfe48ead798d` |

**Testler ve mutasyon:**
- `python -m pytest tests/test_tarif_kesin.py tests/test_ks1_olc.py -q -p no:cacheprovider`: 139 test geçti.
- `PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec scripts/measurement/mutation_specs_ks1.json`: 60 mutant, 60'ı öldü (0 hayatta, 0 hata).
- Mutantların uzunluğu özgününden farklıdır (`.pyc` tuzağı). Mutasyon, çalışan başka okuyucular geçici mutant görmesin diye deponun yalıtılmış bir kopyasında koşuldu; kopyadaki dosyaların sha256'ları yukarıdakilerle aynıdır.

## 12. GT'siz sayım (bütün geliştirme ELF'leri bitti)

Komut: `python scripts/measurement/ks1_olc.py say --mac-kosu workspaces/olcum_mac/runs/ol7-a-9a36142 --debian-kosu ~/karadul_olcum/n1_debian13 --json … --md …` (`sinif` aynı girdilerle).

Sayım anı: 2026-11-10 13:43. `kesin.py` sha256 `2a412e8a4467cff1…` (`KS1_VERSION = 2`). Çıktılar: `ks1_say.json`, `ks1_say.md`, `ks1_sinif.json`.

**Biten ELF'ler:**
- `debian/coreutils`: 106/106
- `debian/htop`: 1/1
- `debian/openssl`: 1/1
- `debian/redis-tools`: 4/4
- `debian/sqlite3`: 1/1
- `debian/tmux`: 1/1
- `debian/tree`: 1/1
- `debian/zstd`: 2/2
- `mac/htop`: 1/1
- `mac/tmux`: 1/1
- Toplam: 119/119 bitti; bekleyen 0.

**Koruma hunisi** (yalnız sıfır olmayan satırlar). K0-K2 sütunları dizgi, sonrakiler fonksiyon sayar. K0 sütunu iki K0 kuralından (başlık dosyası, dosya bilinmiyor) sonrasıdır; K4 sütunu iki K4 kuralından sonrası:

| Birim | Tür | Yuva | Dizgi | K0 | K1 | K2 | Aday fonksiyon | K3 | K4 | Çapa (K5) |
|---|---|---|---|---|---|---|---|---|---|---|
| `debian/coreutils` | `assert` | 122 | 88 | 88 | 86 | 85 | 76 | 67 | 67 | 67 |
| `debian/openssl` | `func_kalibi` | 208 | 29 | 29 | 29 | 29 | 17 | 15 | 15 | 15 |
| `debian/redis-tools` | `assert` | 217 | 140 | 140 | 140 | 140 | 130 | 122 | 118 | 56 |
| `debian/tmux` | `func_kalibi` | 284 | 138 | 138 | 136 | 130 | 111 | 97 | 97 | 97 |
| `debian/tmux` | `func_aktarma` | 28 | 19 | 19 | 18 | 17 | 17 | 15 | 15 | 15 |
| `debian/zstd` | `assert` | 2423 | 461 | 365 | 362 | 316 | 256 | 168 | 168 | 168 |
| `mac/tmux` | `assert` | 14 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 |
| `mac/tmux` | `func_kalibi` | 283 | 186 | 186 | 185 | 182 | 163 | 150 | 150 | 150 |
| `mac/tmux` | `func_aktarma` | 71 | 23 | 23 | 23 | 23 | 22 | 21 | 21 | 21 |

Sıfır satırlı birimler (hiçbir dizgi türünde yuva yok): `debian/htop`, `debian/sqlite3`, `debian/tree`, `mac/htop`.

**Rol, export ve elemeler:**

| Birim | ELF | C++ ELF | Çapa: kendi / üst / parça | Export | Aktarıcı fonksiyon | Assert parçası | Ad biçimi | K0 başlık | K0 dosya | K1 | K2 sahipsiz | K2 çok sahip | K3 | K4 ad | K4 Ghidra adı | K5 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `debian/coreutils` | 106 | 0 | 67 / 0 / 0 | 211 | 39 | 4 | 0 | 0 | 0 | 2 | 1 | 0 | 9 | 0 | 0 | 0 |
| `debian/htop` | 1 | 0 | 0 / 0 / 0 | 366 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `debian/openssl` | 1 | 0 | 15 / 0 / 0 | 0 | 3 | 0 | 3 | 0 | 0 | 0 | 0 | 0 | 2 | 0 | 0 | 0 |
| `debian/redis-tools` | 4 | 0 | 56 / 0 / 0 | 8394 | 4 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 8 | 0 | 4 | 62 |
| `debian/sqlite3` | 1 | 0 | 0 / 0 / 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `debian/tmux` | 1 | 0 | 111 / 0 / 0 | 0 | 4 | 0 | 0 | 0 | 0 | 3 | 0 | 7 | 16 | 0 | 0 | 0 |
| `debian/tree` | 1 | 0 | 0 / 0 / 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `debian/zstd` | 2 | 1 | 164 / 4 / 4 | 0 | 2 | 52 | 0 | 96 | 0 | 3 | 19 | 27 | 88 | 0 | 0 | 0 |
| `mac/htop` | 1 | 0 | 0 / 0 / 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `mac/tmux` | 1 | 0 | 169 / 3 / 14 | 0 | 7 | 14 | 0 | 0 | 0 | 1 | 0 | 3 | 14 | 0 | 0 | 0 |

Eleme sütunları türlerin toplamıdır; bir dizgi ya da fonksiyon birden çok türü taşıyorsa her türde sayılır. "Ad biçimi", günlük türlerinde [karar 2-3] koşullarıyla elenen yuva sayısıdır.

**Taslağa göre değişen çapa sayıları** (`KS1_VERSION` 1 → 2; öbür birimlerde sayı aynı):

| Birim | Tür | Taslak | Bu belge | GT'siz açıklama |
|---|---|---|---|---|
| `debian/coreutils` | `assert` | 65 | 67 | program adı dışlaması assert'te kalktı [karar 3]: adı ELF adının bir biçimine eşit 2 çapa var |
| `debian/openssl` | `func_kalibi` | 16 | 15 | ad biçimi koşulu [karar 2]: elenen yuvalar "Ad biçimi" sütununda |
| `debian/redis-tools` | `assert` | 60 | 56 | K4 Ghidra adı: 4 fonksiyon |

**Program sınıfı eş değişkeni (kilitli; `ks1_sinif.json`):**

| Birim | ELF | İç fonksiyon | snake_case dizgi | Dizgi zenginliği | Zenginlik sınıfı (eşik 0,05) | ELF ortancası | Boyut tabakası |
|---|---|---|---|---|---|---|---|
| `debian/coreutils` | 106 | 14120 | 97 | 0,007 | `yoksul` | 112 | `kucuk` |
| `debian/htop` | 1 | 609 | 113 | 0,186 | `zengin` | 609 | `orta` |
| `debian/openssl` | 1 | 592 | 404 | 0,682 | `zengin` | 592 | `orta` |
| `debian/redis-tools` | 4 | 10531 | 225 | 0,021 | `yoksul` | 2672 | `buyuk` |
| `debian/sqlite3` | 1 | 429 | 85 | 0,198 | `zengin` | 429 | `kucuk` |
| `debian/tmux` | 1 | 1920 | 496 | 0,258 | `zengin` | 1920 | `orta` |
| `debian/tree` | 1 | 119 | 0 | 0,000 | `yoksul` | 119 | `kucuk` |
| `debian/zstd` | 2 | 1931 | 6 | 0,003 | `yoksul` | 965,5 | `orta` |
| `mac/htop` | 1 | 597 | 58 | 0,097 | `zengin` | 597 | `orta` |
| `mac/tmux` | 1 | 2588 | 986 | 0,381 | `zengin` | 2588 | `buyuk` |

**Tekil aday sayısı** (satır × birim; farklı ad sayısı, parantezde örnek sayısı; C++ ve parça dışarıda). Kararda N_MIN bu sayıyla karşılaştırılır: klon ve eşlenemeyen çapalar da öğe olduğu için ölçümdeki tekil n bu tablodaki sayıya eşittir.

| Birim | `assert` | `assert_ust` | `func_kalibi` | `func_aktarma` | `dizgi_turleri` | `export` |
|---|---|---|---|---|---|---|
| `debian/coreutils` | 34 (67) | 0 | 0 | 0 | 34 (67) | 3 (211) |
| `debian/htop` | 0 | 0 | 0 | 0 | 0 | 366 (366) |
| `debian/openssl` | 0 | 0 | 15 (15) | 0 | 15 (15) | 0 |
| `debian/redis-tools` | 30 (56) | 0 | 0 | 0 | 30 (56) | 3855 (8394) |
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
6. **Darwin'de sabit argümanlı çağrı.** Değişken argümansız bir fonksiyona `(fmt, ad)` geçilirse ad x1'dedir, `[sp]`'de değil; yakalanmaz. Çoğunlukla kapsam kaybıdır. Ancak aynı çağrıdan önce ilgisiz bir değer taze bir `[sp, #0]` yuvasına yazılmışsa o değer hizalı argüman sayılır ve yanlış çapa verebilir.
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

**Kararlar ve koda işlenmesi (2026-10-22, 2026-11-10; hepsi GT'siz):**
- Bağımsız değerlendirme GT'ye, kör veriye ve kilitli setlere erişmeden yapıldı (29 kabuk komutu denetlendi). Kararlar o rapor ve ana oturumun incelemesiyle verildi; hiçbiri bir doğruluk ya da GT sayısına dayanmıyor.
- GT yükleyicileri (`function_f1.extract_gt`, `macho_f1.gt_from_json`, `macho_measure`) bu tarihlerde de gerçek veride çalıştırılmadı; yalnız sentetik testlerde çağrıldılar.
- 2026-11-10'da bakılanlar: Mac ikililerinin içe aktarılan (thunk) adlarının yazımı, çalışma alanlarındaki `reports/report.json` dosyalarının `environment.ghidra` alanı, yeniden koşulan `say` ve `sinif` çıktıları (ad içermez).
- Aynı gün ana ağaçta başka işler için çalışan ajanlara (kripto etiketi, bağlama tasarımı, N4 taslağı, belgeler, paketleme) GT ve kilitli veri açıkça yasaklandı.
- Karar kuralı değişikliklerinin bazı satırları `yetersiz` yapacağı ölçümden önce biliniyordu (§8 "Ölçümden önce bilinenler"); bu bilgi GT'den değil aday sayılarından gelir.

**Tasarım geçmişi** (hepsi GT'siz):
- İlk taslakta GCC bölüm çapası (`add xD, xS, #imm`, xS sabit) ve yığından geri yükleme yoktu. Debian tmux'ta `func_kalibi` yuvası 42'de kalınca C çıktısıyla karşılaştırıldı ve eklendi. Sonra 284 yuva çıktı (Mac'te 283).
- K0, zstd'nin assert parçalarının çağrı yapısı incelenince eklendi: başlık fonksiyonunun kısmi inline parçası birden çok fonksiyondan çağrılıyordu.
- C++ işareti ilk sürümde `__cxa_` önekiydi; glibc'nin `__cxa_finalize`'ı yüzünden bütün Debian ELF'leri C++ çıktı ve düzeltildi.
- Hiçbir değişiklik bir doğruluk ya da GT sayısına bakılarak yapılmadı; değişikliklerin dayanağı sayaçlar ve kod yapısıdır.

## 15. [seçim] maddeleri: kararlar

| # | Madde | Taslaktaki öneri | Karar | Yer |
|---|---|---|---|---|
| 1 | Yükleyici değeri yalnız assert yuvasında | evet | öneri | §2 |
| 2 | Ad yuvası dizgisinde alt çizgi zorunlu | hayır | **değişti:** assert'te şart yok; günlük türlerinde ad en az iki parçalı ve en az bir küçük harfli | §2 |
| 3 | Program adı dışlanır | evet | **değişti:** yalnız günlük türlerinde; harf duyarsız; adın parçaları ve alt çizgili biçimi de | §2 |
| 4 | Biçim ayraçları | `%s:`, `%s()` | **değişti:** yalnız `%s:` | §3.2 |
| 5 | `func_aktarma` ayrı tür | evet | öneri | §3.3 |
| 6 | Kaldırılmış assert ayrı karar satırı (`assert_ust`) | evet | öneri | §4 |
| 7 | K0 açık | evet | öneri | §5 |
| 8 | K0 adları K3'te sayılmaz | evet | öneri | §5 |
| 9 | K0 uzantı listesi | dokuz uzantı | öneri | §5 |
| 10 | K3'te elenmiş dizgiler dahil | evet | öneri | §5 |
| 11 | K4 açık | evet | öneri | §5 |
| 12 | K5, K4'ten sonra | evet | öneri | §5 |
| 13 | Proje normalleştirmesi satırı | evet (karar dışı) | öneri | §6 |
| 14 | tmux Mac ve Debian ayrı birim | evet | **değişti:** rapor birimi ayrı; karar kaynak program düzeyinde (platformlar önce ortalanır) | §7, §8 |
| 15 | C++ ikililer kesinlik dışı | evet | öneri | §7 |
| 16 | Çok ELF'li programda birim = program; (satır, ad) tekil, hepsi doğruysa doğru | evet | **değişti:** tekil kural kalır; karar tekil ve örnek düzeyi makrolarının küçüğüyle | §7, §8 |
| 17 | `export` ve birleşik satır karar dışı | evet | öneri (kod da uyduruldu: bunlar için karar hesaplanmaz) | §8 |
| 18 | N_MIN | 10 | öneri | §8 |
| 19 | EN_AZ_BIRIM | 2 | **değişti:** N_MIN'i geçen en az iki FARKLI kaynak program (EN_AZ_PROGRAM = 2) | §8 |
| 20 | Eşik nokta tahminine | evet | **değişti:** nokta tahmini ≥ %95 kalır; ek koşul: giren hiçbir birimin Wilson üst sınırı %95'in altında olamaz | §8 |
| 21 | Kapsam örnek düzeyinde | evet | öneri | §9 |
| 22 | Zenginlik sınıfı: platform içi ortanca | evet | **değişti:** iki platformda ortak mutlak eşik 0,05 | §9 |
| 23 | Boyut tabakası sınırları (ELF ortancası) | 500 / 2000 | öneri | §9 |

## 16. Taslaktan bu yana değişiklikler

Taslak: `ks1_onkayit_taslak.md` ve 10d69cd'deki kod (`KS1_VERSION = 1`). Bu belge `KS1_VERSION = 2` ile yazıldı. Hepsi GT'ye bakılmadan yapıldı.

**Taslakta işaretlenmemiş kararlar:**

| # | Konu | Taslaktaki davranış | Karar |
|---|---|---|---|
| G1 | Klon ve eşlenemeyen çapalar | karar dışı, ayrı satır | Klon satırı taban eşitliğiyle kesinliğe girer; eşlenemeyen yanlış sayılır. Eski tanım duyarlılık satırı (`yalniz_ana`) |
| G2 | K4 ve Ghidra'nın adları | K4 yalnız dizgi çapalarına bakıyordu | Ghidra'nın başka fonksiyona verdiği jenerik olmayan adla çakışan çapa düşer (`K4_ghidra_adi_dolu`) |
| G3 | K0 değerlendirilemeyince | dosya argümanı çözülemeyen assert yuvası çapa veriyordu | Çapa yok (`K0_dosya_bilinmiyor`); ad K3'te gövde adı sayılır |
| G4 | Tür satırı ve çok türlü çapa | her satırda sayılır | Aynen; ek olarak `tek_turlu` duyarlılık satırı |
| G5 | Ölçüm yardımcıları | sha256 denetimi dışında | `function_f1.py`, `macho_f1.py`, `macho_measure.py`, `tests/benchmark/metrics.py` sabitlenir ve ölçümden önce denetlenir; ofset `entry`'den türetilemezse ölçüm durur |

**Belge ↔ kod uyumsuzluklarının giderilmesi:**

| # | Uyumsuzluk | Düzeltme |
|---|---|---|
| D1 | `export` ve `dizgi_turleri` için karar hesaplanıyordu | Kod: yalnız rapor satırı (havuz) |
| D2 | Export kapsamının payı ad bekleyen nüfustan sayılıyordu (hep ≈ 0) | Kod: pay ve payda dışa aktarılan GT |
| D3 | Parça tanımı `blr`'yi ve işlev dışına koşullu dallanmayı saymıyordu; tek geçişti | Kod ve §4: ikisi de parça olmayı engeller; tespit sabit noktayla |
| D4 | K0 değerlendirilemeyince çapa veriliyordu | G3 |
| D5 | C++ işaretleri ELF yazımındaydı | Kod ve §7: Mach-O'da tek `_` soyulup aranır |
| D6 | Tanımlayıcı deseni sondaki satır sonunu kabul ediyordu | Kod ve §2: bütün dizgiye eşleşme |
| D7 | §13.6 "yanlış değil" diyordu | Belge düzeltildi |
| D8 | K1'in yükleyici istisnası belgeden dardı (tutucu yönde) | Belge koda uyduruldu (§5) |
| D9 | §3.1 "(thunk)" diyordu; kod thunk aramıyor | Belge düzeltildi |
| D10 | §2'de 64 sınırının anlatımı | Belge düzeltildi: giriş durumu boşaltılır |
| D11 | Mac nüfusunda derleyici ekli klonlar kalıyordu | Kod ve §7: klon nüfus dışı (ELF ile aynı) |
| D12 | Eksiksizlik yalnız platform toplamıyla denetleniyordu | Kod ve §7: birim başına |
| D13 | Ghidra sürümü denetlenmiyordu; belge "kayıtlı değil" diyordu | Kod ve §7, §11: `reports/report.json`'dan denetlenir |
| D14 | Oranlar eşikten önce yuvarlanıyordu | Kod: karar kesirlerle |
| D15 | `olc` çıktısında sınıf alanı ve sınıf kilidi yoktu | `ks1_sinif.json` bu commit'te; `olc` sınıfları çıktısına yazar |
| D16 | §12'deki N_MIN cümlesi ile kod farklı şey söylüyordu | G1 ile ikisi aynı oldu: tekil aday sayısı ölçümdeki n'dir |

**Yapılmayanlar** (değerlendirmede önerilip bu ön kayda alınmayanlar):
- K0'ın K3'te saymadığı başlık adları için ayrı duyarlılık satırı (≈ 30 zstd çapası): çıkarıcıda yeni bir kip gerektirir.
- Günlük türlerinde tek parçalı adlar için ayrı alt satır: elenen yuva sayısı `ad_bicimi_eleme` sayacında; kesinlikleri ölçülmez.
