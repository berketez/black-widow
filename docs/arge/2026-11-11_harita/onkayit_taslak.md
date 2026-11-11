# Harita ölçümü: ürünün modül ataması ↔ kaynak dosya yapısı — ön kayıt taslağı

- **Tarih:** 2026-11-11.
- **Durum:** TASLAK. Ölçüm yapılmadı. Gerçek veride ürün modülü ile GT etiketi hiç çaprazlanmadı; tek bir uyum sayısı hesaplanmadı (§11). Bu belge ana oturumda kesinleşip `onkayit.md` adıyla, `harita_sabitler.json` ile aynı commit'te depoya girmeden `harita_olc.py olc` koşmaz (betik bunu kendi denetler).
- **[seçim] maddeleri:** 17 madde (§12). Her biri önerilen değer ve tek cümlelik gerekçeyle yazıldı; hiçbiri karara bağlanmadı.
- **Dayanak:** yerleşimin her koşuda aynı çıkması 32f18e3 ile sağlandı; doğruluğu hiç ölçülmedi. Kullanıcının gözlemi ("haritalandırmamız iyi gibi") sınanabilir bir soruya çevriliyor.
- **Bu belgenin yapmadığı:**
  - Ürünün yerleşim yöntemini değiştirmek ya da yeni bir yöntem önermek. Burada yalnız bugünkü ürün ölçülür.
  - Mach-O ikililerini ölçmek: GT'leri derleme birimi taşımıyor (§3.3).
  - Bağımsız doğrulama: nüfus geliştirme setidir.
- Bu belgede fonksiyon adı ve kaynak dosya adı geçmez.

**Dosyalar** (sha256'ların ilk 16 hanesi, taslağın yazıldığı andaki hâl; kesin ön kayıtta tam değerler `harita_olc.py sabitle` ile sabitlenir):

| Dosya | İçerik | sha256 (ilk 16) |
|---|---|---|
| `scripts/measurement/harita_olc.py` | `kuru`, `olc`, `sabitle` | `1a205ca42d4d9e3d` |
| `tests/test_harita_olc.py` | 50 test (sentetik çalışma alanı, sentetik DWARF, sentetik GT) | `67fd764cc2a6bd25` |
| `scripts/measurement/mutation_specs_harita_olc.json` | 113 mutant | `8a18c9957bc8fb1e` |
| `scripts/measurement/ks1_olc.py` | birimler, nüfus denetimi, GT fonksiyon evreni, ofset kanıtı, sabitler (içe aktarılır; değişmedi) | `975c4d1265d8610e` |
| `scripts/measurement/dwarf_tip.py` | dwz farkında DWARF okuyucu, köken zinciri, satır tablosu yolları (içe aktarılır; değişmedi) | `b62d496be4ac8610` |
| `scripts/measurement/function_f1.py`, `tests/benchmark/metrics.py` | `ks1_olc.py`'nin ELF yardımcıları (değişmedi) | `edc782981f98abc6`, `114456c29af17fb9` |
| `kuru_kosu.json`, `kuru_kosu.md` | GT'siz kuru koşu (§9) | `900e0245336ad049`, `7a34b2f9cef9479c` |

## 1. Soru ve hipotezler

**Soru:** ürünün modül ataması (proje ağacındaki `subsystem_…` dizinleri), fonksiyonların gerçek kaynak dosyası yapısıyla ne kadar örtüşüyor ve basit tabanları geçiyor mu?

- "Gerçek kaynak dosyası": fonksiyonun derlendiği derleme biriminin kaynak dosyası (DWARF; §3.2).
- "Örtüşme": aynı modüle konan iki fonksiyon aynı kaynak dosyadan mı, aynı kaynak dosyanın iki fonksiyonu aynı modülde mi (§5).
- "Basit tabanlar": rastgele atama, adres sırasına göre bitişik bölme, yozlaşmış sınırlar (§6).

**Aykırı öncül (bilerek):** bağlayıcı, aynı derleme biriminin fonksiyonlarını çoğunlukla adres sırasında yan yana bırakır. Öyleyse hiçbir çözümleme yapmayan "adres sırasına diz, eşit parçalara böl" tabanı, ürünün çağrı grafı topluluklarını ve API kurallarını geçebilir. Ölçüm bunu sınar; aşağıdaki beklentiler ölçümden önce yazıldı.

**Hipotezler ve beklentiler** (geliştirme seti, Debian ELF'leri, dosya düzeyi):

| # | Hipotez | Ölçü | Beklenti (ölçümden önce) |
|---|---|---|---|
| H1 | Ürün rastgele atamadan ayırt edilir. | Program başına ürün ARI'si ↔ B0'ın 95. yüzdeliği | Tutar: çağrı grafında birbirini çağıran fonksiyonlar bir ölçüde aynı dosyadandır. Makro ARI küçük ve pozitif: 0,02 – 0,15. |
| H2 | Ürün adres sırası tabanını (B1) geçer. | Program başına ARI farkı (ürün − B1) | **Tutmaz.** B1 makro ARI 0,15 – 0,50; fark negatif; karar `taban_gecer`. |
| H3 | LTO'lu programda (redis-tools) B1'in üstünlüğü küçülür ya da tersine döner. | redis-tools'un farkı ↔ öbür programların farkı | Tutar: LTO'da gövdeler parçalara çağrı yakınlığına göre dağılır, kaynak dosya bitişikliği bozulur. |
| H4 | Dizin düzeyinde sonuç dosya düzeyiyle aynı yöndedir. | Dizin düzeyi ARI farkı | Aynı yön; ama ölçülebilen program azdır (tek dizinli programlar düşer), karar çıkmayabilir. |
| H5 | `subsystem_misc` ürünün uyumunu düşürür. | `urun_misc_tekil` ↔ `urun` çift kesinliği | Kesinlik artar, duyarlılık düşer; ARI'nin yönü belirsiz. |

Beklentinin gerekçesi (H2):
1. Kural modülleri (`subsystem_file_io`, `subsystem_memory`, …) fonksiyonun çağırdığı içe aktarılmış API'ye göre verilir; bu ayrım kaynak dosyaları keser (her dosyada bellek ayıran ve dosya okuyan fonksiyon vardır).
2. Etiket yayılımı, çağıranı çağrılanla birleştirir. Yardımcı dosyaların (ör. ortak kitaplık kodu) fonksiyonları her yerden çağrılır ve çağıranların topluluğuna dağılır.
3. `subsystem_misc` büyük bir yığındır; içindeki her çift "aynı modülde" sayılır.
4. Adres sırası, LTO'suz derlemede derleme birimini neredeyse bölmeden korur.

Beklentinin zayıf yeri (H2; güven: orta):
- B1 eşit parçalara böler. Tek büyük kaynak dosyanın baskın olduğu ikilide (coreutils'in çoğu) büyük dosyayı birkaç parçaya ayırır ve duyarlılık kaybeder. Ürünün en büyük topluluğu o dosyayı bir arada tutuyorsa coreutils'te fark pozitif çıkabilir.
- Bu yüzden beklenti program sayısıyla yazılır: farkın 7 programın en az 5'inde negatif olması beklenir; coreutils belirsizdir.

Bu beklenti yanlış çıkarsa (ürün B1'i geçerse) çağrı grafı topluluklarının adres sırasında olmayan bir bilgiyi taşıdığı gösterilmiş olur; §7'deki cümle yazılabilir.

**Ön çalışma:** ikiliyi bileşenlere ayıran BCD (Karande ve ark., ASIA CCS 2018) üç sinyal kullanır: kod yakınlığı (adres sırası), veri başvuruları ve fonksiyon çağrıları. Adres yakınlığının bu alanda birincil sinyallerden sayılması aykırı öncülle uyumludur. Kaynak: [dblp kaydı](https://dblp.dagstuhl.de/rec/conf/ccs/KarandeCLCKH18.html), [makale](https://personal.utdallas.edu/~hamlen/karande18asiaccs.pdf); 2026-11-11'de arama sonucundan okundu, makalenin tam metni bu oturumda okunmadı (güven: orta).

## 2. Kol ve girdi

| | |
|---|---|
| Ölçülen kol | yeni ürün koşusu, commit 93a2956 (yerleşim belirlenimli) |
| Koşu kökü | `~/karadul_olcum/runs/urun-yeni-93a2956/` (`debian/<program>/<ikili>/ws/…`, `mac/<ikili>/ws/…`); künye `kosu_kunyesi.json` |
| Ürün çıktısı | çalışma alanında `reconstructed/project/src/` |
| GT | Debian 13 dbgsym: `~/karadul_olcum/downloads/debian13/x_*-dbgsym_*/usr/lib/debug/.build-id/` |
| Saklı taban koşuları | eski ürün (a10fde3); yerleşimi tohuma bağlıydı. Yalnız ayrıştırıcıyı geliştirmek için ürün tarafı okundu; ölçülmez. |

## 3. İki tarafın okunuşu

### 3.1 Ürün tarafı (adrese anahtarlı)

- Kaynak: `reconstructed/project/src` altındaki her `.c` dosyası.
- Anahtar: fonksiyon başlığındaki `// Address:  <onaltılık>` satırı (satırın tamamı). Ad kullanılmaz; aynı adlı birden çok fonksiyon ayrı adresleriyle ayrı okunur.
- Modül: dosyanın `src`'ye göre ilk dizini (`subsystem_<ad>`). `src` kökündeki dosya (`main.c`: giriş noktaları) `.` modülüdür.
- Birleşik dosyada (`thunks_and_stubs*.c`) her başlık ayrı fonksiyondur.
- Modül türü (yalnız döküm için): `subsystem_group_<sayı>` topluluk, `subsystem_misc` misc, öbür `subsystem_…` kural, `.` giriş.
- Ölçüye girmeyen ve sayılan durumlar:
  - `atanamayan`: Ghidra'nın fonksiyon listesinde olup projede başlığı geçmeyen fonksiyon;
  - `coklu_modul`: başlığı birden çok modülde geçen fonksiyon;
  - `ghidra_disi`: başlıktaki adres Ghidra'nın fonksiyon listesinde yok;
  - `basliksiz_dosya`: adres başlığı taşımayan `.c` dosyası.
- Sınama: ürünün kendi kurucusu (`CProjectBuilder`) sentetik girdiyle çalıştırılır, çıktısı bu okuyucuyla okunur (`test_urun_oku_urunun_kurucusuyla`). Ürünün yerleşim biçimi değişirse test kırılır.

### 3.2 GT tarafı (ELF, dbgsym)

- **Fonksiyon evreni ve adres eşlemesi:** `ks1_olc.gt_elf` (içe aktarılır).
  - Hata ayıklama dosyası build-id ile bulunur; tam bir dosya olmalıdır.
  - Evren: hata ayıklama dosyasının `.symtab`'ındaki fonksiyonlar.
  - Ofset: Ghidra'nın görüntü tabanı − ELF'in en düşük `PT_LOAD` adresi; `entry` ve giriş adresiyle çapraz denetlenir (KS-1 sapma kaydı 1). Kanıtlanamazsa ölçüm durur.
- **Etiket:** o adreste başlayan DWARF somut gövdesinin (`DW_AT_low_pc`'li `DW_TAG_subprogram`) kaynak derleme birimi.
  - Birim seçimi `dwarf_tip.Cozucu`'nun kuralıdır: köken zincirinde (`DW_AT_abstract_origin`, `DW_AT_specification`) en derinden başlanır; adı olan ve `<artificial>` olmayan ilk `DW_TAG_compile_unit` alınır.
  - LTO'da somut gövde yapay (LTRANS) birimdedir; kaynak dosya kökenin birimidir.
  - dwz kısmi birimleri (`DW_TAG_partial_unit`) kaynak birim sayılmaz.
  - Yalnız yapay ya da adsız birime varan gövde etiketsizdir.
- **Etiketin değeri (dosya düzeyi):** birimin kaynak dosyasının yolu.
  - DWARF 5 satır tablosunun 0. dosyası (derleme diziniyle birleşik, sadeleşmiş; `dwarf_tip.dosya_yollari`).
  - Tablo yoksa, DWARF 5 değilse ya da 0. dosyanın adı `DW_AT_name` ile uyuşmuyorsa sadeleşmiş `DW_AT_name` (`yol_ad` sayılır).
  - Gerekçe: özyinelemeli derlemede her dizin kendi derleme diziniyle derlenir; `DW_AT_name` tek başına iki ayrı dizindeki aynı adlı dosyayı ayırmaz. Geliştirme setinde böyle bir çift görüldü (§9).
- **Dizin düzeyi etiketi:** yolun dizini; kökteki dosya için `.`.
- **Dışarıda kalan ve sayılan durumlar:**
  - `crt`: bütün adları CRT adı olan fonksiyon (`function_f1.is_crt_name`);
  - `govdesiz`: o adreste somut gövde yok;
  - `etiketsiz`: gövde var, birim seçilemedi;
  - `celiskili`: aynı adreste farklı kaynak dosyalı gövdeler.
- Sınama: bellekte kurulan sentetik DWARF ile (`dwarf_tip.Die`, `DwarfDosyasi`); seçilen birimin adı `dwarf_tip.Cozucu.fonksiyon`'un `birim` alanıyla karşılaştırılır.

### 3.3 Mach-O: GT derleme birimi taşımıyor

Geliştirme setinin iki Mach-O ikilisinin (tmux, htop) GT'si `nm` çıktısıdır: ad, adres, sınıf. Özgün ikililerde kaynak dosya bilgisi yok:

| Komut (özgün ikili: `workspaces/olcum_mac/corpus/<p>/orig/<p>`) | tmux | htop |
|---|---|---|
| `/usr/bin/nm -a <p> \| grep -c ' SO '` (kaynak dosya stab'ı) | 0 | 0 |
| `/usr/bin/nm -a <p> \| grep -c ' OSO '` (nesne dosyası stab'ı) | 0 | 0 |
| `/usr/bin/nm -a <p> \| grep -c ' FUN '` | 0 | 0 |
| `/usr/bin/xcrun dwarfdump --debug-info <p> \| grep -c DW_TAG_compile_unit` | 0 | 0 |
| `/usr/bin/otool -l <p> \| grep -c "segname __DWARF"` | 0 | 0 |
| `/usr/bin/nm <p> \| grep -c ' [Tt] '` (fonksiyon simgesi) | 2584 | 606 |

- GT kaydının alanları kuru koşuda okundu: `addr`, `names`, `sinif` (§9). Derleme birimi ya da kaynak dosya alanı yok.
- Homebrew sürümleri Debian'dakilerle aynı değil (`corpus/manifest.json`: htop 3.5.3, tmux 3.8; Debian paketleri htop 3.4.1-5, tmux 3.5a-3). Ad üzerinden Debian DWARF'ına köprü kurmak farklı sürümleri eşlerdi; önerilmez.
- Sonuç: Mach-O ikilileri ölçülmez, `gt_etiketsiz` listesinde nedeniyle yazılır. Ürün tarafları kuru koşuda okunur.

## 4. Nüfus ve birimler

- **İkililer:** geliştirme seti, `ks1_olc.BEKLENEN_ELF`: 119 ikili (Debian 117, Mac 2).
  - C++ ikili `ks1_olc.cpp_ikili_mi` kuralıyla dışarıda (pzstd).
  - Mach-O 2 ikili GT etiketi olmadığı için ölçülmez (§3.3).
  - Ölçülen: Debian 116 ikili, 8 program.
- **Fonksiyon nüfusu (ikili başına):** ürün modülü ve GT etiketi birlikte okunan fonksiyonlar.
  - PLT thunk'ları ve içe aktarılan fonksiyonlar GT etiketi taşımaz; nüfusa girmez.
  - Ghidra'nın bulamadığı GT fonksiyonları nüfusa girmez; oran raporlanır.
- **Giriş kuralı (ikili, düzey başına):** nüfus ≥ `ks1_olc.N_MIN` (10) ve GT'de en az iki sınıf ve aynı sınıfta en az bir çift. Tutmayan ikili nedeniyle sayılır (`kucuk`, `gt_tek_sinif`, `gt_hepsi_ayri`, `yol_kaynagi_ad`).
- **Birim:** platform/program (`ks1_olc.birim_anahtari`). Birimin değeri, giren ikililerinin eşit ağırlıklı ortalamasıdır.
- **Program:** aynı programın platform birimleri ortalanır (burada yalnız Debian). Makro: programlar eşit ağırlıkla.
- **Karar için en az program:** `ks1_olc.EN_AZ_PROGRAM` (2).
- Kuru koşudan bilinenler §9'da.

## 5. Ölçüler

İkili başına, iki düzeyde (dosya, dizin). U ürünün bölmesi (modüller), V GT'nin bölmesi (sınıflar).

| Ölçü | Tanım | Ne söyler |
|---|---|---|
| Çift kesinliği | aynı modüldeki fonksiyon çiftlerinden aynı sınıfta olanların payı | Modülü açan kullanıcı, yan yana gördüğü iki fonksiyonun aynı kaynak dosyadan olduğuna ne kadar güvenebilir. |
| Çift duyarlılığı | aynı sınıftaki çiftlerden aynı modülde olanların payı | Bir kaynak dosyanın fonksiyonları ne kadar bir arada kalıyor. |
| Çift F1 | ikisinin harmonik ortalaması | |
| **Düzeltilmiş Rand indeksi (ARI)** | (ortak − beklenen) / ((aynı modül + aynı sınıf) / 2 − beklenen); beklenen = aynı modül · aynı sınıf / bütün çiftler | Çift uyumunun, boyutlar korunarak yapılan rastgele atamanın üstündeki kısmı. Rastgele 0, tam uyum 1. |
| Türdeşlik | 1 − H(sınıf \| modül) / H(sınıf) | Modül tek kaynak dosyadan mı. |
| Tamlık | 1 − H(modül \| sınıf) / H(modül) | Kaynak dosya tek modülde mi. |
| V-ölçüsü | türdeşlik ile tamlığın harmonik ortalaması | |

**Karar ölçüsü ARI'dir.** Gerekçe:
- Modül sayısı ile kaynak dosya sayısı farklıdır ve ürün bire bir eşleme iddia etmez. Kesinlik ve türdeşlik çok küçük modülleri, duyarlılık ve tamlık tek büyük modülü ödüllendirir.
- ARI iki yozlaşmış sınırda da 0'dır (tek modül, her fonksiyon ayrı) ve B0'ın beklenen değeri kapalı biçimde 0'dır.
- V-ölçüsü şansa göre düzeltilmez: her fonksiyonun ayrı modül olduğu bölmede türdeşlik 1'dir ve V sıfırdan büyüktür (`test_olculer_yozlasmis_sinirlar`: 12 fonksiyon, üç eşit sınıfta V > 0,5). Bu yüzden V yalnız yön bilgisidir.

Hesap kesirle yapılır (`fractions.Fraction`); eşik karşılaştırmalarında yuvarlama yoktur. V-ölçüsü kayan noktadır.

**Elle hesaplanmış örnek** (`test_cift_olculeri_elle_hesap`, `test_v_olcusu_elle_hesap`): 6 fonksiyon; iki modül (3 + 3), üç sınıf (2 + 2 + 2); ilk modülde birinci sınıfın ikisi ve ikinci sınıfın biri.
- Çiftler: toplam 15, aynı modülde 6, aynı sınıfta 3, ikisi de 2.
- Kesinlik 2/6 = 0,333; duyarlılık 2/3 = 0,667; F1 4/9 = 0,444.
- Beklenen = 6 · 3 / 15 = 1,2; ARI = (2 − 1,2) / (4,5 − 1,2) = 8/33 = 0,242.
- Türdeşlik 0,421; tamlık 0,667; V 0,516.
- Formüller ayrıca, çiftleri tek tek sayan bağımsız bir hesapla 40 rastgele sentetik bölmede karşılaştırılır (`test_olculer_kaba_kuvvetle_ayni`).

**Değerlendirilip seçilmeyenler:**
- MoJoFM (yazılım mimarisi kurtarma yazınının taşıma-birleştirme uzaklığı): şansa göre düzeltilmez, yönlüdür, doğru uygulanması ayrı bir iş.
- Düzeltilmiş karşılıklı bilgi (AMI): ARI ile aynı soruyu sorar; ikinci bir düzeltilmiş ölçü karar yollarını çoğaltır.

**Yalnız rapor edilen ek sayılar:**
- GT bitişikliği: adres sırasında aynı sınıftan ardışık fonksiyon öbeği sayısı; sınıf / öbek oranı (1: her kaynak dosya tek öbek). Aykırı öncülün doğrudan sınaması.
- Modül türü dökümü: tür başına (giriş, kural, topluluk, misc) modül, fonksiyon, aynı modüldeki çift ve bunlardan aynı sınıfta olanlar.

## 6. Tabanlar

Hepsi aynı nüfusta, aynı GT'ye karşı, aynı ölçülerle.

| Satır | Tanım | Rol |
|---|---|---|
| `b0` | Ürünün modül etiketleri fonksiyonlar arasında karılır; modül boyutları korunur. 200 karma; tohum = SHA-256(`karadul-harita-b0-2026-11-11\|<birim>/<ikili>`)'in ilk 16 hanesi. Ölçü başına ortalama; ARI'nin 95. yüzdeliği (en yakın sıra) ve permütasyon p değeri ((1 + ürününkine eşit ya da büyük karma) / 201). Kapalı biçim beklenen değerler de yazılır: ARI 0, kesinlik = GT çift yoğunluğu, duyarlılık = ürün çift yoğunluğu. | karar (H1) |
| `b1` | Fonksiyonlar adres sırasına dizilir; ürünün o ikilideki modül sayısı kadar bitişik parçaya bölünür. Parça boyutları en çok bir farklı; fazlalık baştaki parçalarda. | karar (H2) |
| `b1_gt` | Aynı bölme; parça sayısı GT sınıf sayısı. Ürünün bilemeyeceği bilgiyi kullanır. | yalnız rapor: adres sırasının erişebileceği düzey |
| `tek_modul` | Bütün fonksiyonlar tek modülde. | sınır: ARI 0, duyarlılık 1, kesinlik = GT çift yoğunluğu |
| `hepsi_ayri` | Her fonksiyon ayrı modül. | sınır: ARI 0, duyarlılık 0, türdeşlik 1 |
| `urun_misc_tekil` | Ürünün bölmesi; `subsystem_misc` üyeleri tek başına modül. | yalnız rapor (H5) |

## 7. Önceden yazılmış kararlar

Kararlar dosya düzeyinde, program başına ARI ile verilir. P: iki tarafta da değeri olan program sayısı; gerekli = ⌈2/3 · P⌉.

### (a) Rastgeleye karşı (H1)

| Sonuç | Koşul |
|---|---|
| `rastgeleden_iyi` | en az "gerekli" programda ürünün ARI'si B0'ın 95. yüzdeliğinin (programın ikililerinin ortalaması) üstünde |
| `rastgeleden_ayirt_edilemiyor` | öbür durum |
| `yetersiz` | P < 2 |

### (b) Adres sırasına karşı (H2)

Program başına fark = ürün ARI − B1 ARI; makro fark = programların ortalaması.

| Sonuç | Koşul |
|---|---|
| `urun_gecer` | makro fark ≥ +0,05 ve fark en az "gerekli" programda pozitif |
| `taban_gecer` | makro fark ≤ −0,05 ve fark en az "gerekli" programda negatif |
| `ayrismiyor` | öbür durum |
| `yetersiz` | P < 2 |

### (c) Sonuca göre ne olur

| (a) | (b) | Ne yazılabilir, ne yapılır |
|---|---|---|
| `rastgeleden_iyi` | `urun_gecer` | README'ye şu cümle yazılabilir (sayılar ölçümden): "Karadul fonksiyonları alt sistem dizinlerine ayırır. Geliştirme setinde (N program) bu ayrım kaynak dosya yapısını rastgele atamadan ve adres sırasına göre bölmeden daha iyi yansıtır (düzeltilmiş Rand indeksi: X; adres sırası: Y)." Nitelik ("geliştirme seti", N, X, Y) atılamaz. |
| `rastgeleden_iyi` | `ayrismiyor` | README'de yalnız yöntem anlatılır: "fonksiyonları çağrı grafına ve kullandıkları API'lere göre gruplar". Kaynak yapısını yansıttığı yazılmaz. Sonuç kayda girer. |
| `rastgeleden_iyi` | `taban_gecer` | Yukarıdakiyle aynı README kuralı. Ek olarak plan'a iş kalemi açılır: yerleşimde adres sırasının kullanılması (tek başına ya da çağrı grafıyla birlikte). Bu ölçüm o işin tabanıdır. |
| `rastgeleden_ayirt_edilemiyor` | herhangi | README'de harita için kalite cümlesi yazılmaz; "alt sistem" dizinlerinin kaynak yapısını yansıtmadığı kayda girer. Aynı iş kalemi açılır. |
| `yetersiz` | — | Karar yok; neden yazılır. |

- Yeni bir yerleşim yöntemi bu geliştirme setinde geliştirilirse sonucu "geliştirme setinde ayarlanmış" sayılır; bağımsız iddia için doğrulama seti ve yeni bir ön kayıt gerekir.
- "Harita iyi" cümlesi (a) ve (b)'nin ilk satırı dışında hiçbir sonuçla yazılmaz.
- Dizin düzeyi yalnız raporlanır; karar değiştirmez (§12, seçim 2).
- H3 (LTO) ve H5 (misc) yalnız raporlanır.

### Bütünlük koşulları (GT'siz; ölçümden önce ve ölçüm sırasında denetlenir)

1. Ön kayıt commit'i HEAD'in atası; ölçümü belirleyen beş dosyanın sha256'sı o commit'teki `harita_sabitler.json` ile aynı. Tutmazsa ölçüm durur.
2. Birim başına ikili sayısı `ks1_olc.BEKLENEN_ELF` ile aynı; hepsi bitmiş; proje ağacı yazılmış. Tutmazsa ölçüm durur.
3. Bütün ikililer aynı, sabitlenmiş Ghidra sürümüyle analiz edilmiş (`ks1_olc.ghidra_denetle`). Tutmazsa ölçüm durur.
4. Ofset kanıtı her ELF'te tutar (`ks1_olc.elf_ofseti`); dwz ek dosyası bulunur. Tutmazsa ölçüm durur.
5. Etiket yolu her ikilide satır tablosundan okunur (`yol_ad` = 0). Tutmayan ikili iki düzeyde de ölçüye girmez ve sayılır.
6. Ürün okuması: `atanamayan`, `coklu_modul`, `ghidra_disi`, `basliksiz_dosya` sayıları raporlanır. Kuru koşudaki değerler §9'da; ölçümde farklı çıkarsa ölçüm sonuçla birlikte bunu yazar.
7. Koşu künyesi: `kosu_kunyesi.json`'daki commit 93a2956 ve çalışma ağacı temiz. Ana oturum ölçümden önce okur.

## 8. Koşum

```bash
# GT'siz kuru koşu (bu taslakta koşuldu; §9)
python scripts/measurement/harita_olc.py kuru \
    --debian-kosu ~/karadul_olcum/runs/urun-yeni-93a2956/debian \
    --mac-kosu ~/karadul_olcum/runs/urun-yeni-93a2956/mac \
    --mac-veri /Users/apple/Black_Widow/workspaces/olcum_mac \
    --json docs/arge/2026-11-11_harita/kuru_kosu.json --md docs/arge/2026-11-11_harita/kuru_kosu.md

# ön kayıt kesinleşince: sabitler, sonra onkayit.md ile aynı commit
python scripts/measurement/harita_olc.py sabitle

# ölçüm (ön kayıt commit'inden sonra; önce koşmaz)
python scripts/measurement/harita_olc.py olc \
    --debian-kosu ~/karadul_olcum/runs/urun-yeni-93a2956/debian \
    --mac-kosu ~/karadul_olcum/runs/urun-yeni-93a2956/mac \
    --json docs/arge/2026-11-11_harita/harita_olcumu.json --md docs/arge/2026-11-11_harita/harita_olcumu.md

# testler ve mutasyon
python -m pytest tests/test_harita_olc.py -q -p no:cacheprovider
PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec scripts/measurement/mutation_specs_harita_olc.json
```

- `kuru` worktree'den koşulursa `--mac-veri` verilmelidir (varsayılan, betiğin bulunduğu ağaca göredir). `olc` Mach-O GT'sini okumaz.
- `olc` süresi: kuru koşu 119 ikilide 82 saniye sürdü (iki tarafın okunması); ölçüm buna B0 karmalarını ekler.
- Seçimler betikte sabittir (`FARK_ESIGI`, `COGUNLUK`, `B0_PERMUTASYON`, `B0_TOHUM_METNI`, `KARAR_DUZEYI`, `KARAR_OLCUSU`). Bir seçim değişirse betik, test ve mutant tanımı birlikte güncellenir; `sabitle` en son koşulur.
- `olc` iki koşu kökünü de ister: nüfus `ks1_olc.BEKLENEN_ELF`'in 119 ikilisiyle denetlenir (Mach-O ikilileri sayılır, ölçülmez).

## 9. Ölçümden önce bilinenler (GT'siz kuru koşu)

Komut §8'deki `kuru`; çıktı `kuru_kosu.json` ve `kuru_kosu.md`. Bu bölümdeki her sayı o çıktıdan okunur. Hiçbiri uyum sayısı değildir: iki taraf ayrı ayrı okundu, modül ile GT etiketi çaprazlanmadı.

- Nüfus: bulunan 119 ikili, biten 119; sorunlar: yok.
- Koşu künyesi: ürün commit'i `93a29569e4c3b61123b322af70b8c32e4d48e520`, kirli dosya 0.
- Ghidra sürümü denetimi (`ks1_olc.ghidra_denetle`): tamam, sürüm 12.1.2, 119 ikili.

| | Sonuç |
|---|---|
| Debian ikili (C++ dışında) | 116 (C++: 1) |
| Ürün tarafı okunan ikili | 116 / 116 |
| GT tarafı okunan ikili | 116 / 116 (okunamayan: 0) |
| İki taraf da okunan ikili | 116 / 116 |
| Ürün: Ghidra fonksiyonu (thunk dahil) | 62216 (thunk: 32810) |
| Ürün: modüle atanan | 62216 |
| Ürün: atanamayan; çoklu modül; Ghidra dışı adres; başlıksız dosya | 0; 0; 0; 0 |
| GT: `.symtab` fonksiyonu | 29958 |
| GT: CRT; gövdesiz; etiketsiz; çelişkili | 1034; 298; 6; 0 |
| GT: etiketli fonksiyon | 28620 |
| Adres eşleme: etiketli fonksiyonlardan Ghidra'da fonksiyon başı olan | 28620 / 28620 (oranı 1'in altında olan ikili: 0) |
| Adres eşleme: CRT dışı GT fonksiyonlarından Ghidra'da olan | 28924 / 28924 |
| Etiketin yolu yalnız addan gelen (`yol_ad`) | 0 |
| LTO'lu ikili (yapay birimde gövde taşıyan); etiketi köken biriminden gelen fonksiyon | 4; 8491 |
| Aynı adı taşıyan ayrı kaynak dosya (ikililerin toplamı) | 2 |
| Yalnız `DW_AT_ranges` taşıyan gövde | 0 |
| Ofset kanıtı: görüntü tabanı + `entry`; yalnız görüntü tabanı | 110; 6 |
| dwz ek dosyası: bağla bulunan; bağ yok | 111; 5 |
| Ortak nüfus (ürün modülü ve GT etiketi olan fonksiyon) | 28620 |
| Dosya düzeyine girecek ikili | 114 (girmeyen: gt_tek_sinif 1, kucuk 1) |
| Dizin düzeyine girecek ikili | 113 (girmeyen: gt_tek_sinif 2, kucuk 1) |
| Dosya düzeyine girecek program | 7: coreutils, htop, openssl, redis-tools, tmux, tree, zstd |
| Dizin düzeyine girecek program | 6: coreutils, htop, openssl, redis-tools, tmux, zstd |

Birim başına (üçlü değerler: en küçük – ortanca – en büyük; ortak nüfusta):

| Birim | İkili | Ortak nüfus | Modül | Kaynak dosya | Dizin | Dosya düzeyine girer | Dizin düzeyine girer | LTO'lu ikili |
|---|---|---|---|---|---|---|---|---|
| debian/coreutils | 106 | 2 – 105.5 – 309 | 2 – 16 – 32 | 1 – 28 – 91 | 1 – 2 – 3 | 105 | 105 | 0 |
| debian/htop | 1 | 608 | 34 | 85 | 4 | 1 | 1 | 0 |
| debian/openssl | 1 | 596 | 22 | 74 | 2 | 1 | 1 | 0 |
| debian/redis-tools | 4 | 479 – 2656 – 4675 | 25 – 37.5 – 48 | 25 – 86 – 145 | 3 – 5.5 – 7 | 4 | 4 | 4 |
| debian/sqlite3 | 1 | 418 | 10 | 1 | 1 | 0 | 0 | 0 |
| debian/tmux | 1 | 1911 | 15 | 147 | 2 | 1 | 1 | 0 |
| debian/tree | 1 | 110 | 10 | 11 | 1 | 1 | 0 | 0 |
| debian/zstd | 1 | 1079 | 16 | 43 | 6 | 1 | 1 | 0 |

Mach-O (ölçülmez; §3.3):
- `mac/htop`: ürün tarafı okundu (Ghidra fonksiyonu 790, atanan 790, modül 48). GT 605 fonksiyon; kayıt alanları `addr`, `names`, `sinif`: derleme birimi yok.
- `mac/tmux`: ürün tarafı okundu (Ghidra fonksiyonu 2821, atanan 2821, modül 31). GT 2572 fonksiyon; kayıt alanları `addr`, `names`, `sinif`: derleme birimi yok.

**Okuma:**

- **İki taraf 116 Debian ikilisinin hepsinde ayrı ayrı okundu.** Ölçümü durduracak GT'siz ön koşulların hepsi tuttu: nüfus eksiksiz, Ghidra sürümü tek, ofset kanıtı 116/116, dwz ek dosyası 111/111, `yol_ad` 0.
- **Ürün her Ghidra fonksiyonunu tam bir modüle koymuş:** atanamayan, çoklu modül, Ghidra dışı adres ve başlıksız dosya 0. Bütünlük koşulu 6'nın kuru koşudaki değeri budur.
- **Adres eşlemesi tam:** etiketli 28 620 GT fonksiyonunun hepsi Ghidra'da fonksiyon başı. Nüfusa girmeyen GT fonksiyonları Ghidra yüzünden değil, GT'nin kendisinden: CRT 1 034, gövdesiz 298, etiketsiz 6.
- **Ayrıntı düzeyi farkı.** Ürünün modül sayısı çoğu programda kaynak dosya sayısının altında: tmux 15'e 147, htop 34'e 85, openssl 22'ye 74, zstd 16'ya 43, coreutils'te ortanca 16'ya 28. tree'de sayılar yakın (10'a 11).
  - Bu modül sayısıyla hiçbir bölme tam uyuma (ARI 1) erişemez; mutlak değerler düşük çıkar.
  - Ürün ile B1 aynı modül sayısıyla çalışır; karşılaştırma bundan etkilenmez.
- **LTO yalnız redis-tools'ta:** 4 ikilinin 4'ü. Bu programda etiketli 10 466 fonksiyonun 8 491'i etiketini köken biriminden alıyor. H3 tek programa dayanır.
- **Aynı adı taşıyan ayrı kaynak dosya** 2 kez görüldü (redis-tools'un iki ikilisinde birer). Etiket yalnız `DW_AT_name`'den alınsaydı bu dosyalar birleşirdi.
- **Dışarıda kalacak ikililer:** `libstdbuf.so` (ortak nüfus 2; iki düzeyde), `sqlite3` (tek kaynak dosya; iki düzeyde), `tree` (tek dizin; yalnız dizin düzeyinde).
- **Karara girecek program:** dosya düzeyinde 7, dizin düzeyinde 6. Çoğunluk için gereken sayı 5 (dosya) ve 4 (dizin).
- **GT tarafı koldan bağımsız.** Aynı kuru koşu saklı taban koşularında (eski ürün) da koşuldu: GT sayaçları ve adres eşlemesi 116 ikilinin 116'sında aynı. O çıktı depoya girmedi (`~/karadul_olcum/runs/harita-2026-11-11/kuru_taban.json`).
- **Süre:** 119 ikilide 82 saniye.

## 10. Bilinen sınırlar

- **Etiket derleme birimidir, bildirim dosyası değil.** Başlıkta tanımlı bir fonksiyon satır dışı derlenmişse, onu içeren `.c` dosyasının etiketini alır.
- **Satır içine alınan fonksiyonlar görünmez.** İkilide ayrı fonksiyon değildirler; nüfusa girmezler. Bir fonksiyonun gövdesi başka dosyaların satır içine alınmış kodunu taşıyabilir; etiket yalnız dış fonksiyonun birimini söyler.
- **LTO.** LTO'lu ikilide etiket kökenin birimidir. Bağlama zamanında yeniden bölünen gövdelerin adres sırası kaynak dosyayı izlemez; B1 için koşullar LTO'suz ikiliden farklıdır. Geliştirme setinde LTO'lu ikililer tek programdadır (§9); H3 tek programa dayanır.
- **Ghidra'nın bulamadığı fonksiyonlar** nüfusa girmez. Ölçü, ürünün gördüğü fonksiyonlardaki yerleşimi ölçer; fonksiyon bulma başarımı ayrı bir sorudur. Oran §9'da.
- **CRT ve gövdesiz adresler** dışarıdadır (derleyici ve C kitaplığı başlangıç kodu; klon parçaları).
- **Mach-O ölçülmedi.** Sonuç Debian 13, AArch64, GCC derlemeleri içindir. Mach-O bağlayıcısının sırası ve Clang'in bölümlemesi farklı olabilir.
- **Kaynak dosya, "alt sistem" değildir.** Dosya düzeyi katı bir ölçüttür: iki yakın dosyayı birleştiren bir modül duyarlılıkta ödül, kesinlikte ceza alır. Dizin düzeyi daha gevşektir ama düz dizinli programlarda tanımsızdır.
- **Thunk'lar ve içe aktarılan fonksiyonlar** ürünün dizinlerinde yer alır ve kullanıcı onları görür; GT etiketleri olmadığı için ölçülmez.
- **ARI çiftleri eşit sayar.** Büyük kaynak dosyalar (çok fonksiyonlu) sonucu belirler.
- **B1 tek bir basit tabandır.** Eşit parçalı bölme, adres sırasından çıkarılabilecek en iyi bölme değildir (ör. hizalama boşluklarından kesmek). `b1_gt` üst düzeyi gösterir ama GT bilgisi kullanır.
- **Az program.** Karar en çok 8 programa dayanır (dosya düzeyinde girenler §9'da). İşaret sayımı kaba bir ölçüttür; aralık verilmez.
- **coreutils'in 106 ikilisi** ortak kitaplık kodunu paylaşır; program düzeyi makro bunu tek oya indirir, ama programın değeri bağımsız 106 gözlem değildir.
- **Aynı dosya iki ikili.** `redis-check-aof` ile `redis-check-rdb` aynı dosyadır (`raw/target_info.json`: sha256'nın ilk 16 hanesi iki ikilide `65846e52d7bbebe8`). `ks1_olc` nüfusunda ayrı ikili sayılırlar; redis-tools'un dört ikililik ortalamasına iki kez girerler.
- **Geliştirme seti.** Bağımsız doğrulama değildir.

## 11. Bütünlük kaydı

Bu taslak yazılırken:

- **Hesaplanmayan:** gerçek bir ikilide ürün modülü ile GT etiketi arasında hiçbir çapraz tablo, çift sayısı, ARI, V-ölçüsü ya da taban değeri. `olc` gerçek veride çalıştırılmadı. B1'in GT'ye uyumu ve GT bitişikliği de hesaplanmadı (ikisi de ölçümün sonucudur).
- **Okunan (ürün tarafı, tek başına):** yeni koşunun ve saklı taban koşularının proje ağaçları ve `ghidra_functions.json` dosyaları: fonksiyon, modül ve dosya sayıları, modül boyutları.
- **Okunan (GT tarafı, tek başına):** dbgsym dosyalarının DWARF birim yapısı: birim sayıları, DWARF sürümü, satır tablosu yolları, yapay birimler, aynı adlı birimler. Geliştirme sırasında uçbirimde birkaç derleme birimi adı görüldü; hiçbiri ürün modülüyle yan yana konmadı.
- **Okunan (adres eşlemesi):** GT fonksiyon adreslerinin Ghidra fonksiyon başlangıçlarıyla kesişimi ve ortak nüfusun büyüklüğü (modül sayısı ve kaynak dosya sayısı ayrı ayrı). Bunlar uyum sayısı değildir.
- **Mekanik güvenceler:**
  - `kuru`, çapraz tablo kuran hiçbir fonksiyonu çağırmaz; test bu fonksiyonları patlayan sahteleriyle değiştirip `kuru`'yu koşar (`test_kuru_caprazlamaz`).
  - `olc`, ön kayıt commit'i yokken hiçbir veri okumadan durur (`test_olc_on_kosul_once_denetlenir`); komut satırından denetim kapatılamaz (`test_main_olc_on_kosulsuz_kosmaz`).
- **Uçtan uca doğrulama** yalnız sentetik veriyle yapıldı (`test_olc_uctan_uca`: üç program, bilinen cevap; `test_main_olc_ciktilari_yazar`: komutun JSON ve Markdown yazımı).
- **Testler ve mutasyon** (baştaki tabloda sha256'ı yazılı dosyalarla; worktree'de):
  - `python -m pytest tests/test_harita_olc.py -q -p no:cacheprovider`: 50 test geçti.
  - `PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec scripts/measurement/mutation_specs_harita_olc.json`: 113 mutant, 113'ü öldü (0 hayatta, 0 hata).
- **Kör setler** (`docs/arge/dogrulama_seti*`, `docs/arge/test_seti*`, `targets/`, `scripts/measurement/*seti*`) okunmadı. `ks1_olc.gt_mac`, `macho_measure` üzerinden `test_seti_kura` modülünü içe aktarır (kilit denetimi için); bu betik o modülü okumaz ve kullanmaz.

## 12. [seçim] maddeleri (özet)

| # | Madde | Önerilen | Gerekçe |
|---|---|---|---|
| 1 | Karar ölçüsü | ARI | Şansa göre düzeltilmiş; iki yozlaşmış sınırda 0; modül sayısı farkına dayanıklı. |
| 2 | Karar düzeyi | dosya; dizin yalnız rapor | GT'nin doğrudan verdiği düzey dosya; dizin düzeyi birçok programda tanımsız (§9). |
| 3 | Dosya etiketi | derleme biriminin kaynak dosyasının yolu (satır tablosunun 0. dosyası) | `DW_AT_name` tek başına aynı adlı dosyaları birleştirir; bildirim dosyası başlık fonksiyonlarını başlığa atardı. |
| 4 | LTO'lu program | karara girer; etiket köken birimi | Ürün LTO'lu ikiliyle de karşılaşır. Duyarlılık: redis-tools'suz makro, program tablosundan elle. |
| 5 | İkilinin girişi | nüfus ≥ 10 (`ks1_olc.N_MIN`), GT'de ≥ 2 sınıf ve ≥ 1 çift | Küçük nüfusta ARI gürültülü; tek sınıfta ayrım ölçülemez. |
| 6 | Birimin değeri | giren ikililerin eşit ağırlıklı ortalaması | Bölme ikiliye özgüdür; çift havuzu büyük ikiliyi baskın kılar. |
| 7 | B1'in parça sayısı ve boyutu | ürünün modül sayısı; eşit parçalar | Ürünle aynı ayrıntı düzeyi; "hiç çözümleme yapmayan" en basit taban. |
| 8 | B0 | 200 karma; ikiliye bağlı sabit tohum; 95. yüzdelik | Görev tanımındaki alt sınır; yüzdelik tek ikilide kararlı. |
| 9 | Fark eşiği | 0,05 ARI | B0'ın 95. yüzdeliği düzeyindeki farkı karar saymamak için; değer keyfidir. |
| 10 | Çoğunluk | programların 2/3'ü | Tek programın makroyu taşımasını engeller; 7 programda 5. |
| 11 | `subsystem_misc` | olduğu gibi modül; tekil görünüm yalnız rapor | Kullanıcı onu bir dizin olarak görür. |
| 12 | Mach-O | kapsam dışı | GT derleme birimi taşımıyor (§3.3). Seçenek: dSYM'li yerel derlemeyle ayrı GT (ayrı iş). |
| 13 | C++ ikili | dışarıda (`ks1_olc.cpp_ikili_mi`) | Geliştirme setinin öbür ölçümleriyle aynı nüfus. Etiket açısından engel yok; içeri alınabilir. |
| 14 | Thunk, CRT, gövdesiz | nüfus dışı | Kaynak dosyaları yok. |
| 15 | Yolu satır tablosundan okunamayan etiket | ikili iki düzeyde dışarıda | Karışık yol kaynakları dizin etiketini bozar. Seçenek: ölçümü durdurmak. |
| 16 | Adres eşleme alt sınırı | yok; oran raporlanır | Kuru koşuda oran §9'da; eşik gerekirse buradan seçilir. |
| 17 | Tek kaynak dosyalı ikili | dosya düzeyinde dışarıda | Ayrım tanımsız (ARI'nin paydası anlamını yitirir). |
