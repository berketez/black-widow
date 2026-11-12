# Yerleşim doğrulama ölçümü: adres yerleşimi (S2) ↔ adres tabanı (B1) — ön kayıt TASLAĞI

- **Tarih:** 2026-11-12.
- **Durum: TASLAK.** Kesinleştirme ana oturumun ve Berke'nin işidir. Doğrulama ölçümü yapılmadı; doğrulama seti seçilmedi, indirilmedi, derlenmedi; hiçbir doğrulama ikilisinin GT'sine bakılmadı.
- **Dayanak:**
  - `docs/arge/2026-11-11_harita/harita_sonuc.md`: ön kayıtlı ölçüm; ürün 0,097, adres tabanı B1 0,424; karar `taban_gecer`.
  - `docs/arge/2026-11-11_harita/yerlesim_kesfi.md`: ön kayıtsız keşif; S2 (`s2_dolgu16`) 0,705.
  - `uygulama.md` (bu dizin): S2 ürüne bayrak arkasında girdi; geliştirme setinde ürün çıktısı 0,705'i yeniden üretti.
- **[seçim] maddeleri:** 11 madde (§10). Her biri önerilen değerle yazıldı; hiçbiri karara bağlanmadı.
- Bu belgede fonksiyon adı ve kaynak dosya adı geçmez.

## 1. Soru ve hipotezler

**Soru:** bayrak açıkken ürünün yerleşimi (adres sırasında bitişik dilimler; sınır, dolgu ≥ 16 baytken), geliştirme setinde görülmemiş programlarda fonksiyonların kaynak dosya yapısını basit adres tabanından (B1: eşit bölme) daha iyi yansıtıyor mu?

**Aykırı öncül (bilerek):** geliştirme setindeki 0,705, yöntemin değil araç zincirinin sonucudur. Eşik 16, GCC 14'ün AArch64 öntanımlı ayarının (`function_align` "32:16") parmak izidir (`uygulama.md` §5). Öyleyse:

- aynı araç zincirinde yeni programlarda S2 tutar;
- başka derleyici sürümünde ya da hedefte sinyal yoktur; S2 orada B1'e yenilir.

Ölçüm iki cümleyi ayrı ayrı sınar. Aşağıdaki beklentiler ölçümden önce yazıldı.

| # | Hipotez | Ölçü | Beklenti (ölçümden önce) |
|---|---|---|---|
| H1 | Kol A'da (aynı araç zinciri, yeni programlar) S2, B1'i geçer. | Program başına ARI farkı (S2 − B1) | Tutar. Makro S2 0,55–0,80 (geliştirme: 0,705; LTO'suz altı program 0,605–0,911). Karar `s2_gecer`. |
| H2 | Kol B'de (GCC 13 ve öncesi, AArch64) S2, B1'i geçemez. | Aynı | Tutar. İkililerin çoğu "sinyal yok" ile eski yerleşime döner; kalanında 1–2 başıboş dolgu vardır. Karar `taban_gecer` ya da `ayrismiyor`. |
| H3 | Kol B'de (x86-64, GCC 14) hiçbir ikilide sinyal yoktur. | Sinyalsiz ikili payı (GT'siz) | Tutar: GCC'nin x86 genel ayarında fonksiyon hizalaması "16"dır (en çok atlama sınırı yok); dolgu 15 baytı geçmez. Pay ≥ 0,9. |
| H4 | LTO'lu programlarda S2'nin B1'e üstünlüğü LTO'suzlardan küçüktür. | LTO'lu ↔ LTO'suz programların farkı | Tutar (geliştirme: redis-tools +0,031; öbür altı program +0,135 ile +0,465 arası). |
| H5 | Mekanizma: Kol A ikililerinde pozitif dolgudan sonra gelen başlangıç 32'nin katıdır. | GT'siz oran (ana kod bloğu) | ≥ 0,95 (geliştirme: program başına 0,981–1,000). |
| H6 | S2, gerçek sınırların yaklaşık yarısını yakalar. | Sınıf değişimlerinden dolgu sınırına düşenlerin payı | 0,35–0,65. Gerekçe: bağlayıcının dolgusu 0–28 bayt arasında dağılır; yalnız ≥ 16 olanı görünür (`uygulama.md` §5). |

Beklentinin zayıf yeri (H1; güven: orta):

- Geliştirme setinin yedi programı da aynı dağıtımın paketleridir; derleme bayrakları birbirine benzer. Paket bakımcısı `-Os`, `-falign-functions` ya da başka bir `-mtune` kullandıysa sinyal o programda kaybolur.
- Tek büyük kaynak dosyalı program (ör. birleştirilmiş tek dosya) S2'de de B1'de de az sınıf taşır; ölçüye girmeyebilir.
- LTO'lu program Kol A'ya düşerse farkı küçültür (H4).

## 2. Dondurulanlar

Doğrulama setinde hiçbiri yeniden ayarlanmaz.

| Dondurulan | Değer | Nerede |
|---|---|---|
| Dolgu eşiği | 16 bayt | `karadul/config.py` → `address_placement_padding_threshold` |
| Hizalama (sinyal bandının üst ucu, dışında) | 32 bayt | `karadul/config.py` → `address_placement_alignment` |
| Dilimleme kuralı | sınır: bellek bloğu değişimi, ya da yürütülebilir blokta dolgu ≥ eşik | `c_project_builder.slice_by_padding` |
| "Sinyal yok" kuralı | [16, 32) bandında hiç dolgu yok → eski yerleşim | `AddressLayout.has_padding_signal`; §6 |
| Giriş noktaları | iki yerleşimde de `main.c` (modül `.`) | `c_project_builder.build` |
| B1 | ürünün (bayrak kapalı) modül sayısı kadar eşit, bitişik parça | `harita_olc.b1_bolme`; [seçim 4] |
| Ölçü ve toplama | dosya düzeyi ARI; ikili → birim → program → makro | `harita_olc.py` (2026-11-11 ön kaydındaki dosya) |
| Fark eşiği ve çoğunluk | 0,05 ARI; programların 2/3'ü | `harita_olc.FARK_ESIGI`, `COGUNLUK` |

- Ürün kodu: `uygulama.md` §9'daki commit. Kesin ön kayıtta `c_project_builder.py`, `config.py` ve ölçüm betiklerinin sha256'ları sabitlenir (2026-11-11'deki `harita_sabitler.json` düzeni).
- `tests/test_yerlesim_adres.py::test_dondurulmus_sayilar` eşik ya da hizalama değişirse düşer.

## 3. Kollar ve doğrulama seti ÖNERİSİ

Seçim ana oturumundur. Hiçbir paket indirilmedi; aşağıdaki sürüm ve derleyici bilgileri öneridir, kesinleşmeden önce doğrulanmalıdır.

### Kol A: aynı araç zinciri, yeni programlar (karar kolu)

- **Araç zinciri:** Debian 13 (trixie), arm64, GCC 14.2 (geliştirme setiyle aynı).
- **Programlar:** geliştirme setinde olmayan 8–10 C programı. İki seçenek:
  - **A1: kilitli doğrulama seti** (`docs/arge/dogrulama_seti_kilidi.md`; 10 program). Bu set yalnız kapı günlerinde analiz edilir ve her bakış kayda geçer. Harita ölçümü ad kullanmaz, ama Karadul'u bu programlarda koşturmak kilidin 1. kuralına girer. Kullanılacaksa karar Berke'nindir ve bir kapı gününe bağlanır.
  - **A2: yeni çekiliş** [seçim 1, öneri]. Debian 13 arm64 deposundan, geliştirme / test / doğrulama kümelerinde ve yedeklerinde olmayan, `-dbgsym` paketi bulunan C programları; tohumlu kura (`dogrulama_seti_kura.py`'nin düzeni: havuz, tabaka, aile kısıtı önce commit edilir, sonra çekilir). Kilitli seti adlandırma kapılarına saklar.
- **GT:** `-dbgsym` paketindeki DWARF; fonksiyonun somut gövdesinin derleme biriminin kaynak dosyası (`harita_olc.gt_oku`; 2026-11-11 ön kaydının §3.2'si aynen).
- **Koşu:** ikili başına bir Karadul koşusu (bayrak kapalı, öntanımlı). Bayrak açık ağaç, aynı çalışma alanından kurucu yeniden çalıştırılarak üretilir (`yerlesim_urun_olc.py`'nin yaptığı). Geliştirme setinde bu yol, tam koşuyla aynı bölmeyi verdi (`uygulama.md` §4.3); doğrulama koşusunda da en az bir ikilide tam koşuyla karşılaştırılır.

### Kol B: farklı araç zinciri (ayrı satır; karar (b))

Amaç S2'nin tutacağını göstermek değil, araç zinciri sınırını önceden yazılmış bir öngörüyle ölçmektir.

| Kol | Araç zinciri | Kaynak | Öngörü (mekanizmadan) | Not |
|---|---|---|---|---|
| B-1 | Debian 12 (bookworm), arm64, GCC 12 | Kol A programlarının Debian 12 paketleri ve `-dbgsym` paketleri | `function_align` "16:12": dolgu ≤ 12; bant boş. "Sinyal yok" baskın. | LTO'suz; yalnız derleyici sürümü değişir. En temiz karşılaştırma. |
| B-2 | Debian 13, amd64, GCC 14 | Kol A programlarının amd64 paketleri | Fonksiyon hizalaması "16", atlama sınırı yok: dolgu ≤ 15; bant boş. | Hedef mimari değişir. `ks1_olc.gt_elf` ve ofset kanıtı x86-64'te sınanmadı. |
| B-3 | Ubuntu 24.04, arm64, GCC 13, LTO | `~/karadul_olcum/corpus/ubuntu-9.4-3ubuntu6` (5 ikili, hata ayıklama dosyalarıyla; elde) | Bant neredeyse boş; LTO ile karışık. | Tek paket (coreutils); 5 ikili bağımsız 5 gözlem değildir. Yalnız rapor. |
| B-4 | clang (Linux arm64 ya da Mach-O) | Kol A'dan 2–3 programın kaynaktan derlenmesi | Mach-O'da dolgu yok (elde iki ikili: `uygulama.md` §3). Linux'ta clang için öngörü yok. | Derleme işi gerekir. Mach-O'da GT için derleme birimi gerekir: hata ayıklama haritası (`N_OSO`) ya da `.dSYM`. Yöntem sınanmadı. |

- [seçim 2, öneri]: B-1 ve B-2 ölçülür; B-3 yalnız raporlanır; B-4 ertelenir.
- Kol B'nin ön koşulu GT'siz sayımdır (`yerlesim_dolgu_say.py`): bant dağılımı ve sinyalsiz ikili sayısı, ölçümden önce ve GT'ye bakılmadan yazılır.

## 4. Nüfus ve ölçüler

2026-11-11 ön kaydı (`docs/arge/2026-11-11_harita/onkayit.md`) ile aynıdır:

- Nüfus: ürün modülü ve GT etiketi birlikte okunan fonksiyonlar; ikili, nüfus ≥ 10, GT'de en az iki sınıf ve bir çift varsa girer.
- C++ ikili, CRT, thunk, gövdesiz adres dışarıdadır; hepsi sayılır.
- Karar ölçüsü ARI, karar düzeyi dosya. Çift kesinliği, duyarlılığı ve V-ölçüsü raporlanır.
- Satırlar: `urun_eski` (bayrak kapalı), `b1`, `s2` (bayrak açık ürün çıktısı), `b0` (rastgele; yalnız rapor), `tavan` (GT'li bitişik üst sınır; yalnız rapor).

## 5. Önceden yazılan kararlar

P: iki tarafta da değeri olan program sayısı; gerekli = ⌈2/3 · P⌉. Program başına fark = S2 ARI − B1 ARI.

### (a) Kol A: S2 ↔ B1

| Sonuç | Koşul |
|---|---|
| `s2_gecer` | makro fark ≥ +0,05 ve fark en az "gerekli" programda pozitif |
| `taban_gecer` | makro fark ≤ −0,05 ve fark en az "gerekli" programda negatif |
| `ayrismiyor` | öbür durum |
| `yetersiz` | P < 5 [seçim 3] |

### (b) Kol B: araç zinciri başına aynı kural, ayrı satır

- Her alt kol (B-1, B-2) kendi satırında okunur; (a)'nın kararını değiştirmez.
- Sinyalsiz ikili payı alt kol başına yazılır (H2, H3).

### (c) LTO

- LTO'lu program (GT'de yapay derleme birimi taşıyan) (a)'ya girer [seçim 5; dünkü ön kaydın seçim 4'ü ile tutarlı].
- Ayrıca ayrı satırda raporlanır: LTO'lu programların farkı, LTO'suz programların farkı (H4).
- Kol A'da LTO'lu program yoksa H4 sınanamaz ve öyle yazılır.

### (d) Sonuca göre ne olur

| (a) | (b) | Ne yazılabilir, ne yapılır |
|---|---|---|
| `s2_gecer` | H2 ve H3 tutar (Kol B'de `taban_gecer` ya da `ayrismiyor`) | Nitelikli cümle yazılabilir: "Debian 13 / AArch64 / GCC 14 ile derlenmiş N programda adres yerleşimi kaynak dosya yapısını adres tabanından daha iyi yansıtır (ARI X ↔ Y)". Bayrağın öntanımlı açılması ayrı karardır: araç zinciri tanınmadan açılmaz [seçim 9]. |
| `s2_gecer` | Kol B'de de `s2_gecer` | Aykırı öncül yanlış çıkmıştır: mekanizma açıklaması eksiktir. Sonuç kayda girer; cümle araç zinciri niteliği olmadan yazılmaz, önce neden araştırılır. |
| `ayrismiyor` | herhangi | Bayrak kapalı kalır. README'de yalnız yöntem anlatılır. Sonuç kayda girer. |
| `taban_gecer` | herhangi | Bayrak kapalı kalır. Geliştirme setindeki 0,705'in o sete özgü olduğu yazılır. |
| `yetersiz` | — | Karar yok; neden yazılır. |

- "Kaynak dosya yapısını yansıtır" cümlesi ilk satır dışında hiçbir sonuçla yazılmaz.
- H5 ve H6 yalnız raporlanır.

## 6. "Sinyal yok" kuralı

- **Tanım (dondurulmuş; GT'siz):** yürütülebilir bellek bloklarında, aynı bloktaki ardışık iki fonksiyon arasında 16 ≤ dolgu < 32 olan hiç çift yoksa ikilide sinyal yoktur. Ürün o ikilide eski yerleşime döner; karar README'ye, `analysis/placement.json`'a ve günlüğe yazılır.
- **Ölçümde:** sinyalsiz ikili S2 satırına ürünün verdiği çıktıyla (eski yerleşim) girer. Sayısı kol başına raporlanır. "Yalnız sinyalli ikililer" görünümü ayrıca raporlanır; karar değildir.
- **Bilinen zayıflık:** tanım, bantta tek bir başıboş dolguyu sinyal sayar. Eldeki GT'siz sayımda rejimi farklı 12 ikiliden 5'i bu yüzden adres yerleşimine giriyor ve kod bloğunun neredeyse tamamı tek gruba düşüyor (`uygulama.md` §3.3). Bu, Kol B'de S2'nin ARI'sini düşürür; H2'nin beklentisi bunu içerir.
- **[seçim 6]: rejim kapısı eklensin mi?** Aday (GT'siz): ana kod bloğunda "yasak kalanlı" başlangıç payı (kalanı 16'dan büyük olan başlangıç; varsayılan rejimde derleyici orada durmaz) < 1/16 ise sinyal geçerli sayılır. Eldeki değerler: Debian 13 / GCC 14 ikililerinde 0,000–0,029 (117 ikili); GCC 13 ikililerinde 0,100–0,167 (10 ikili); Mach-O'da 0,345–0,367 (2 ikili). Kapı geliştirme setinin hiçbir sonucunu değiştirmez. Uygulanmadı: yeni bir sayı getirir ve seçim ana oturumundur. Eklenecekse ön kayıttan ÖNCE ürüne girer ve dondurulur.

## 7. Bütünlük koşulları (GT'siz; ölçümden önce ve ölçüm sırasında)

1. Ön kayıt commit'i HEAD'in atası; ürün ve ölçüm dosyalarının sha256'ları o commit'teki sabitlerle aynı. Tutmazsa ölçüm durur.
2. Kol başına bütün ikililer bitmiş; proje ağacı yazılmış; aynı, sabitlenmiş Ghidra sürümü.
3. Her ikilide bayrak kapalı yeniden kurulum, koşunun yazdığı proje ağacıyla bayt bayt aynı (`yerlesim_urun_olc.girdiyi_bul`). Tutmayan ikili ölçüye girmez ve sayılır. Geliştirme setinde 119 / 119 tuttu.
4. Bayrak açık kurulumda kurucunun değişmezi tutar: eksik 0, çift 0. Adressiz birim sayısı raporlanır.
5. GT'siz sayım (`yerlesim_dolgu_say.py`) ve kuru koşu (`harita_olc.py kuru`) ölçümden önce koşar; çıktıları ön kayıtla aynı commit'e girer. Ürün modülü ile GT etiketi ölçümden önce çaprazlanmaz.
6. Ofset kanıtı ve etiket yolu koşulları 2026-11-11 ön kaydındaki gibidir. Kol B-2 (amd64) için bu koşulların tutup tutmadığı kuru koşuda görülür; tutmuyorsa kol ölçülmez ve öyle yazılır.

## 8. Ölçümden önce bilinenler (GT'siz; geliştirme seti ve eldeki eski derlemeler)

Kaynak: `dolgu_sayimi.md`, `kurulum_denetimi.md` (bu dizin). Bu sayılar doğrulama setine ait değildir.

| Grup | Derleyici | İkili | [16, 32) bandında dolgu | Sinyalsiz ikili | Pozitif dolgudan sonra 32'ye hizalı başlangıç | Yasak kalanlı başlangıç payı |
|---|---|---|---|---|---|---|
| Debian 13 arm64 (geliştirme seti) | GCC 14.2 | 117 | 2336 | 0 | 0,981–1,000 (program başına) | 0,000–0,029 |
| Debian coreutils 9.4-3, arm64 | GCC 13.2 | 5 | 2 | 3 | 0,510 | 0,124–0,146 |
| Ubuntu 24.04 coreutils, arm64, LTO | GCC 13.2 | 5 | 2 | 3 | 0,468 | 0,100–0,167 |
| Mach-O arm64 (htop, tmux) | clang (sürüm okunmadı) | 2 | 2 | 1 | 0,211 | 0,345–0,367 |

## 9. Bilinen sınırlar

- Kol A geliştirme setiyle aynı araç zincirindedir: orada tutması, başka derlemede tutacağını göstermez. Bunu Kol B ölçer.
- Dağıtım paketleri, kullanıcıların analiz ettiği ikililerin temsilî örneği değildir (soyulmuş ticari ikili, statik bağlı ikili, oyun, gömülü yazılım yok).
- GT derleme birimidir. Başlık dosyasındaki `static inline` fonksiyon, gövdesinin çıktığı birimin dosyasıyla etiketlenir; LTO'da köken birimiyle.
- ARI çift sayımına dayanır; büyük kaynak dosyalar ağırlıklıdır.
- Eşikler (0,05; 2/3) keyfidir. Sonuç eşiğe yakın çıkarsa `ayrismiyor` okunur.
- Mach-O için GT yöntemi yoktur; B-4 bu yüzden ertelenmiştir.
- Dizin düzeyi ölçülmez (2026-11-11'de iki yöntem de dizin yapısını yansıtmadı).
- Seçim bir insan uzmanın işidir (yaratıcılık protokolü, kural 4): "kaynak dosya yapısına benzeyen yerleşim tersine mühendis için daha mı kullanışlı?" sorusunu bu ölçüm cevaplamaz.

## 10. [seçim] maddeleri (özet)

| # | Madde | Öneri | Gerekçe |
|---|---|---|---|
| 1 | Kol A'nın programları | A2: yeni tohumlu çekiliş, 8–10 program | Kilitli doğrulama setini adlandırma kapılarına saklar |
| 2 | Kol B'nin alt kolları | B-1 ve B-2 ölçülür; B-3 rapor; B-4 ertelenir | B-1 yalnız derleyici sürümünü, B-2 yalnız hedefi değiştirir |
| 3 | Karar için en az program | 5 | 2 programla 2/3 çoğunluk anlamsız |
| 4 | B1'in parça sayısı | Bayrak kapalı ürünün modül sayısı (dünkü tanım) | Dünkü ölçümle karşılaştırılabilir; S2'nin parça sayısıyla B1 yalnız raporlanır |
| 5 | LTO'lu program | (a)'ya girer; ayrıca ayrı satır | Dünkü ön kayıtla tutarlı |
| 6 | Rejim kapısı | Karar ana oturumun (§6) | Yeni sayı getirir; eklenirse ön kayıttan önce dondurulur |
| 7 | Sinyalsiz ikili | S2 satırına ürünün çıktısıyla girer | Ürünün gerçek davranışı ölçülür |
| 8 | Sinyalsiz ikilide geri düşüş | Eski yerleşim (uygulanan) | Görev tanımı; seçenek: B1 benzeri eşit bölme (dün 0,424 ↔ 0,097), ama parça sayısı kuralı gerekir |
| 9 | Bayrağın öntanımlı açılması | Bu ölçümün kararı değil | Araç zinciri tanınmadan açılırsa rejimi farklı ikilide zarar verir |
| 10 | Tam koşu ↔ yeniden kurulum | Bir koşu + yeniden kurulum; bir ikilide tam koşuyla karşılaştırma | Koşu sayısını yarıya indirir; geliştirme setinde aynı bölmeyi verdi |
| 11 | Eşiğin ikiliden kestirilmesi | Bu ölçümün dışında | Yeni yöntemdir; ayrı keşif ve ayrı ön kayıt ister (`uygulama.md` §7) |
