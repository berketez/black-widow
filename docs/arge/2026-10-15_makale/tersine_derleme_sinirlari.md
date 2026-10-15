# Derlenmiş Koddan Kaynağa Ne Kadar Dönülebilir?

**Kuramsal sınırlar, derleyici aşaması başına bilgi kaybı ve Karadul'un isimlendirme tasarımı için çıkarımlar**

- Hazırlanma ve kaynak kontrol tarihi: 2026-10-15
- Amaç: makalenin arka plan bölümü ve Karadul'un "tarif" katmanının kuramsal dayanağı.
- Doğrulama işaretleri:
  - **(D)**: Künye resmî ya da birincil kaynakta (yayıncı, konferans, yazar sayfası, arXiv) görüldü.
  - **(K)**: Kısmen doğrulandı, ya da yalnız ikincil kaynakta (başka makalenin atfı, kütüphane kaydı) görüldü.
  - **(DY)**: Doğrulanmadı.
- Köşeli parantezli sayılar (ör. [17]) Bölüm 7'deki kaynakçaya gönderir.
- Kaynaklardan doğrudan alıntı yapılmadı. Bütün aktarımlar özetlemedir.
- Bu belgede "biz" diye işaretlenen gerekçeler ve çerçeveler literatürden alıntı değildir. Bunlar bu çalışmanın önerisidir ve makalede öyle sunulmalıdır.

---

## 1. Kısa cevap

1. Derleme çoğa-bir (çok-bire) bir eşlemedir. Aynı ikiliyi üreten çok sayıda kaynak program vardır. Bu yüzden "özgün kaynağı geri almak" iyi tanımlı bir problem değildir. Yapılabilecek olan, bu eşdeğerlik sınıfından okunabilir bir temsilci üretmektir.
2. İki ayrı türde imkânsızlık vardır:
   - **Hesaplanabilirlik sınırı:** Bilgi ikilide durur ama genel durumda hesaplanamaz. Kod/veri ayrımı, dolaylı atlama hedefleri ve takma ad (alias) bu türdendir [1][2][3][4].
   - **Bilgi yokluğu:** Bilgi ikilide hiç yoktur. Yorumlar, yerel değişken adları, makro adları ve elenmiş kod bu türdendir.
3. Birinci türün kararsız olması en kötü durumla ilgili bir sonuçtur. Derleyicinin ürettiği, gizlenmemiş kodda pratikte büyük ölçüde aşılır: komut kurtarma doğruluğu %100'e yaklaşır. Pratikteki en zayıf halka fonksiyon sınırlarıdır [35][36].
4. İkinci tür hiçbir algoritmayla, LLM dahil, *kanıtlanarak* geri kazanılamaz. Yapılabilecek iki şey vardır: ikilide kalan dış kanıtı (string, dinamik semboller, RTTI, kütüphane imzası) kullanmak, ya da korpus önsel bilgisiyle *tahmin* etmek.
5. Derleyici yalnız gözlemlenebilir davranışı korumakla yükümlüdür [6]:
   - İç yapı, değişkenler, fonksiyon sınırları ve hatta fonksiyon imzaları değişebilir [8].
   - Tanımsız davranış (UB) içeren programlar için hiçbir koruma yoktur.
   - Biçimsel olarak doğrulanmış derleyicide bile garanti eşdeğerlik değil, iyileştirmedir (refinement) [7].
6. Ölçümler isim tahmin modellerinin şunu yaptığını gösteriyor: eğitimde gövdesi görülen fonksiyonlarda tam eşleşme %85–87, görülmeyenlerde ~%35–37 [26][27]. "Kurtarmanın" büyük bölümü aynı kodun ezberlenmesidir. Ama görülmemiş kodda da isabet sıfır değildir.
7. Karadul için sonuç: Davranış korunur. Bu yüzden davranışı anlatan "tarif" isimleri, korunan bilgiden hesaplanabilir. Özgün isim ise yalnız ikilide kanıt varsa iddia edilebilir. Değerlendirme bu iki sınıfı ayrı ölçmelidir.

### Ne kurtarılabilir, ne kurtarılamaz

| Bilgi | Kurtarılabilirlik | Gerekçe / kanıt |
|---|---|---|
| Makine düzeyi davranış (semantik) | Tamamen | Komut semantiği ISA belgelerinde tanımlıdır; ikili kendisi bir programdır (lifting). |
| Komutlar (disassembly) | Pratikte neredeyse tamamen | Genel durumda kararsız [1]; gizlenmemiş GCC/Clang/MSVC ikililerinde %100'e yakın [35]. |
| Fonksiyon sınırları | Çoğunlukla, hatalı | Makine düzeyinde "fonksiyon" kavramı yoktur; tespit sezgiseldir, hatalar yaygındır [35][36]. |
| Kontrol akışı yapısı (if/while/switch) | Eşdeğer bir yapı her zaman; özgün biçim kısmen | Yapılandırma algoritmaları [17][18][20]; optimizasyonlar özgün biçimi bozar [20]. |
| İlkel tipler, işaretçi/tamsayı ayrımı | Çoğunlukla | İşlemlerin semantiği ve ABI ile çıkarılır [22][23][24]. |
| Struct düzeni (alan ofsetleri, boyut) | Kısmen | Yalnız erişilen alanlar görünür; kullanılmayan alanlar iz bırakmaz. |
| Tip, struct, alan ve enum adları | Kanıt yoksa hayır | C++ RTTI'da sınıf adları kalır [11]; geri kalanı yalnız hata ayıklama bilgisiyle gelir. |
| İçe/dışa aktarılan fonksiyon adları | Evet | Dinamik bağlama için gerekir; `strip` bunları silmez [9]. |
| İç (static) fonksiyon adları | Yalnız kanıtla | Kütüphane imzası, `assert`/log string'leri, isimli komşulardan yayılım. |
| Yerel değişken ve parametre adları | Hayır (yalnız tahmin) | İkilide sıfır bit; korpus önseliyle tahmin edilir [26][27][28]. |
| Yorumlar, biçim, makro adları | Hayır | Önişlemcide ya da derleme başında silinir. |
| Sabit ifadelerin özgün biçimi | Hayır (yalnız değer) | Sabit katlama ifadeyi değere indirger. |
| Elenmiş (ölü) kod | Hayır | İkilide yoktur. |
| Satır içine alınmış fonksiyonun ayrı varlığı | Kısmen | Kopyalar benzerlikle bulunabilir; sınırları ve adı kaybolur [37]. |
| String literal'ler | Evet | Veri olarak olduğu gibi kalır. |
| Davranışın tarifi (fonksiyon "ne yapıyor") | İlke olarak evet | Korunan semantikten hesaplanır. Kesin doğrulaması genel durumda yine kararsızdır (Rice) [2]. |

---

## 2. Kuramsal sonuçlar

### 2.1 Kararsızlık sonuçları

**Rice teoremi (1953) [2] (D).** Programların davranışına ilişkin önemsiz olmayan her özellik kararsızdır. Önemsiz olmayan özellik, bazı programlarda doğru, bazılarında yanlış olan özelliktir. Bu, tersine derlemedeki "X'e ulaşılır mı / X çalıştırılır mı" türü bütün soruların genel durumda algoritmik olarak yanıtlanamayacağı anlamına gelir.

**Horspool ve Marovac (1980) [1] (D).** Çalışma The Computer Journal 23(3):223–229'da yayımlandı (DOI 10.1093/comjnl/23.3.223). Özetinde şu söylenir:
- Ayrıştırmanın (detranslation) temel güçlüğü, komutları veriden ayırmaktır.
- Bu problem çoğu mimari için durma problemine (Halting Problem) eşdeğerdir, yani genel çözümü yoktur.
- Yazarlar yine de çoğu durumda doğru sonuç veren bir algoritma önerirler.

Çalışma, "genel durumda imkânsız, pratikte çoğunlukla yapılabilir" ikiliğini ilk kez açıkça ortaya koyan kaynaktır. Görev tanımındaki atıf (Horspool & Marovac 1980) doğrudur. Tam metin yayıncıda ücretlidir; doğrulama yayıncı özetiyle yapıldı.

**Takma ad (alias) analizi: Landi (1992) [3] (K), Ramalingam (1994) [4] (D).** Bu iki çalışma koşullu dallanma, döngü, dinamik bellek ve özyinelemeli veri yapıları olan dillerde şunu gösterir:
- Kesin "may-alias" bilgisi hesaplanabilir (recursive) değildir.
- Kesin "must-alias" bilgisi özyinelemeli sayılabilir bile değildir.

Ramalingam bu sonuçlara daha basit ispatlar verir (TOPLAS 16(5):1467–1471).

İkili analize etkisi doğrudandır. Tip kurtarma, struct kurtarma ve yığın değişkeni kurtarma, hangi bellek erişiminin hangi nesneye gittiğini bilmeye dayanır. Bu yüzden bu analizler zorunlu olarak yaklaşıktır. Balakrishnan ve Reps'in değer kümesi analizi (VSA) ve CodeSurfer/x86 çalışması [5] böyle bir yaklaştırma ailesidir.

**Dolaylı atlama ve çağrı hedefleri (biz; Rice'tan doğrudan sonuç).** "J'deki dolaylı atlama T adresine gidebilir mi?" sorusu da davranışsal bir özelliktir, dolayısıyla genel durumda kararsızdır. Pratikteki yaklaşımlar şunlardır:
- Aşırı yaklaştırma (sound over-approximation): VSA [5], Jakstab [42].
- Derleyici deyimlerini tanıma: `switch` için atlama tablosu kalıpları.

**Fonksiyon sınırları (biz; standart indirgeme).** Keyfi bir P programı ve x girdisi için şöyle bir ikili kurulabilir: önce P(x) çalıştırılır, sonra A adresine çağrı yapılır. Bu ikilide:
- A adresindeki baytlar ancak P(x) durursa çalıştırılır.
- A ancak P(x) durursa bir fonksiyon girişi olur.

Dolayısıyla "A kod mudur?", "A bir fonksiyon girişi midir?" ve "A'ya çağrı yapılır mı?" soruları durma problemine indirgenir. Andriesse ve ark. de makine düzeyinde fonksiyon ve döngü gibi üst düzey kavramların gerçek bir karşılığı olmadığını vurgular [35].

### 2.2 Bu sonuçlar ne söylüyor, ne söylemiyor?

**Söyledikleri:**
- Her programda doğru çalışan bir disassembler, CFG kurucu ya da tip çıkarıcı yoktur. Her araç ya aşırı yaklaştırır, ya eksik kalır, ya da bazı girdilerde yanılır.
- Kasıtlı gizleme (obfuscation), kuramsal olarak en kötü duruma ulaşabilir.

**Söylemedikleri:**
1. **Ortalama ya da tipik durum hakkında bir şey söylemezler.** Derleyici çıktısı düşmanca değildir, sınırlı sayıda kalıptan oluşur. Andriesse ve ark. [35] dokuz disassembler'ı 981 gerçek ikilide ölçtü:
   - Komut kurtarma doğruluğu doğrusal taramayla bile çoğu zaman %100'e yaklaşıyor.
   - Literatürün kaygı duyduğu satır içi veri ve üst üste binen kod, optimize ikililerde bile çok nadir.
   - Buna karşılık fonksiyon başlangıçlarını kurtarmak literatürün varsaydığından zor. Makale, fonksiyon bilgisine dayanan Windows hedefli çalışmaları tartışırken fonksiyon tespiti doğruluğunun sıklıkla %80'e ya da altına düştüğünü belirtiyor.
   - Pang ve ark. [36] 3.788 ikiliyle aynı tabloyu genişletti. Araçlar ilkeli algoritmaların üstüne sezgiseller ekliyor, bu da kapsama ile doğruluk arasında ödünleşime yol açıyor.
2. **İsimler hakkında hiçbir şey söylemezler.** Bir yerel değişkenin adı, programın davranışına ilişkin bir özellik değildir: adı değiştirmek davranışı değiştirmez. Bu yüzden isim kurtarmanın sınırı "kararsızlık" değil, **bilginin yokluğudur** (bkz. 2.3).
3. **Sağlam yaklaştırmayı yasaklamazlar.** "Ya her zaman doğru ama bazen 'bilmiyorum' diyen" ya da "her zaman cevap veren ama bazen yanılan" araçlar mümkündür. Karadul için önemli olan, bu tercihin bilinçli yapılmasıdır.
4. **Olasılıksal sınır vermezler.** "Hangi oranda doğru olunabilir?" sorusu kararsızlık sonuçlarının kapsamı dışındadır. Bu soru yalnız ölçümle (bkz. 4.7) ya da bilgi kuramsal bir çerçeveyle (bkz. 2.3) ele alınabilir.

### 2.3 Çok-bire eşleme ve bilgi kuramı açısından kayıp

**Biçimsel çerçeve (biz).** Derlemeyi B = C_θ(S) diye yazalım:
- S: kaynak program.
- θ = (derleyici, sürüm, bayraklar, hedef mimari).
- B: ikili.

Belli bir θ için C_θ bir fonksiyondur ama birebir değildir. Örnekler:
- Yerel bir değişkenin adını değiştirmek ya da yorum eklemek aynı ikiliyi üretir.
- `for` ile `while` çoğu zaman aynı ikiliyi üretir.
- Özdeş iki fonksiyon katlanabilir: GCC `-fipa-icf`, belgeye göre `-O2` ve `-Os`'ta açıktır [8].

Bu yüzden ters görüntü C_θ⁻¹(B), bir program kümesidir. Ayrıca θ çoğu zaman bilinmez, bu da belirsizliği artırır.

İki farklı hedef tanımlanabilir:
- **Sözdizimsel hedef:** C_θ(S') = B olan herhangi bir S'. Bu hedef için "özgün" kaynağı seçmenin kanıtı yoktur.
- **Semantik hedef:** B ile gözlemsel olarak eşdeğer herhangi bir S'.

Semantik hedef dar anlamda her zaman ulaşılabilirdir: ikiliyi C'de taklit eden bir yorumlayıcı da eşdeğerdir. Bu yüzden decompilation'ın asıl problemi doğruluk değil, **soyutlama ve okunabilirliktir**: eşdeğer programlar arasından kaynağa "yakın" olanı seçmek. SAILR'in başarı ölçütünü "goto sıfırlamak" yerine "özgün kaynağa yakınlık" diye yeniden tanımlaması [20] bu görüşle örtüşür. İki programın eşdeğer olup olmadığını genel durumda *doğrulamak* ise yine Rice'a takılır [2].

**Bilgi kuramsal ölçü (biz).** Kaynağın bir bileşenine X diyelim (örneğin yerel değişken adları). Derlemenin bu bileşende bıraktığı belirsizlik H(X | B), yani ikili verildiğinde X'in koşullu entropisidir. Buradan iki sonuç çıkar:
- H(X | B) = H(X) ise ikili X hakkında hiçbir şey söylemez.
- Yerel isimler davranışla korelasyonludur: bir döngü sayacına sık sık `i` denir. Bu yüzden H(X | B) < H(X) olabilir. İkili ismi *belirlemez*, ama isim üzerindeki dağılımı daraltır.

Tam eşleşme isabeti için Bayes-optimal tavan şudur:

> A* = E_B [ max_x P(x | B) ]

Aynı veri dağılımında hiçbir yöntem, LLM dahil, beklenen değerde A*'ı aşamaz. Bunun ölçümle ilişkisi şöyledir:
- Bir yöntemin ölçtüğü isabet, o dağılım ve metrik için A*'ın **alt sınırıdır**. Örneğin DIRE görülmemiş fonksiyonlarda %35,3 [26], DIRTY %36,9 [27] ölçmüştür.
- A*'ın kendisini ya da H(X | B)'yi doğrudan ölçen bir çalışma bu taramada bulunamadı (bkz. 4.7).

### 2.4 İki tür sınır: özet

| Tür | Bilgi ikilide var mı? | Örnekler | Ne yapılabilir |
|---|---|---|---|
| Hesaplanabilirlik sınırı | Var | Kod/veri ayrımı, dolaylı hedefler, alias, fonksiyon sınırları, davranış sınıflandırması ("bu CRC32 mi?") | Sağlam yaklaştırma, sezgisel tanıma, derleyici deyimi bilgisi; hata oranı ölçülür |
| Bilgi yokluğu | Yok | Yorumlar, yerel isimler, makro adları, elenmiş kod, katlanmış fonksiyonların ayrı adları | Yalnız dış kanıt (string, sembol, imza) ya da korpus önseliyle tahmin; tahmin "kanıt" diye sunulamaz |

---

## 3. Derleyici aşaması başına kayıp

### 3.1 Tablo

Sütunlardaki durum sınıfları:
- **Kalıcı:** Bilgi ikilide yoktur.
- **Kısmen:** Bilginin bir kısmı ya da bir eşdeğeri kurtarılır.
- **Tamamen:** Anlam olarak tam kurtarılır.

| Aşama | Ne silinir / değişir | Durum | Kurtarma kanıtı | Not / kaynak |
|---|---|---|---|---|
| Önişlemci | Yorumlar, biçim, makro adları, seçilmeyen `#if` dalları, `#define` sabit adları | Yorum ve seçilmeyen dal: kalıcı. Makro ve sabit adı: kısmen | Tekrarlayan kod kalıbı (makro adayı); bilinen API'lerin argüman konumu sabitin sembolik adını verir (ör. `open` bayrakları); `__FILE__`/`__LINE__`/`__func__` string olarak kalır | `assert` başarısız olduğunda dosya ve fonksiyon adını yazdırır [10]. Bu yüzden `NDEBUG` tanımlı değilse fonksiyon adı ikilide string olarak durur (çıkarım, biz) |
| İsimler | Yerel değişken, parametre, static fonksiyon, global, tip adları | Kanıt yoksa kalıcı; kanıt varsa kısmen ya da tamamen | `.dynsym` içe/dışa aktarımları [9]; string'ler; RTTI [11]; ObjC seçicileri [12]; Go sembol tabloları [13]; Rust panik konumları [14]; kütüphane imzası | Bkz. 3.4 ve 5.5 |
| Tipler ve struct düzeni | Tip adları, typedef'ler, alan adları, kullanılmayan alanlar, union/cast ayrımı | Adlar kalıcı; düzen ve ilkel tipler kısmen | İşlem semantiği (işaretli/işaretsiz karşılaştırma, kayan nokta), taban+ofset erişim kalıpları, `malloc` boyutları, kütüphane prototipleri, ABI | TIE: derleme soyutlamaları yazmaç ve düz belleğe indirger [22]; Retypd [23]; OSPREY [24] |
| Kontrol akışı yapıları | `if`/`for`/`while`/`switch`/`break` dalları; özgün biçim | Eşdeğer yapı: tamamen. Özgün biçim: kısmen | CFG yapılandırma; atlama tablosu deyimi; derleyiciye duyarlı tersine dönüşüm | Phoenix [17], DREAM [18], SAILR [20] |
| Satır içine alma (inlining) | Çağrı sınırı, çağrılanın adı ve ayrı varlığı; kısmi inlining fonksiyonu böler | Kısmen; her çağrı yeri inline edilmişse kalıcı | Çağıranlar arasında tekrarlanan gövde parçaları; inline edilmiş bilinen kütüphane kodu kalıpları | `-finline-functions`, `-finline-small-functions`, `-fpartial-inlining` `-O2`'de açık [8]. Inlining oranı %70'e yaklaşabiliyor [37] |
| LTO | Çeviri birimi sınırları; modüller arası inlining; içselleştirilen semboller; klonlar | Modül sınırları kalıcı; geri kalanı inlining gibi | Aynı kanıtlar; statik bağlı kütüphanede imza eşleşmesi zorlaşır | `-flto` bağlama anında nesne dosyaları arası optimizasyon yapar [8]. Ölçüm deneylerinde LTO ayrı koşul olarak ele alınmalı [35] |
| Sabit katlama / yayılım | Sabit ifadenin özgün biçimi (`N*2+1`, `sizeof(T)*n`) | İfade biçimi kalıcı; değer tamamen | Değerin kendisi; bilinen sabitler (sayfa boyutu, hash başlangıç değerleri, CRC tabloları) algoritmayı ele verir | Sabitle bölme çarpma ve kaydırmaya dönüşür. Bu yaygın deyim anlam olarak tamamen tersine çevrilebilir (künye verilmedi) |
| Ölü kod eleme | Erişilemeyen ya da sonucu kullanılmayan kod; kullanılmayan fonksiyonlar | Kalıcı | Yok (ikili dışı kaynak gerekir) | `-fdce`, `-ftree-dce` `-O1`'den itibaren açık [8]. Standart buna izin verir [6] |
| Döngü dönüşümleri | Açma (unrolling), vektörleştirme, döndürme, değişmez kodu dışarı alma, sürümleme | Semantik tamamen; özgün döngü biçimi kısmen | Tekrarlayan gövde (yeniden sarma), vektör deyimleri, prolog/epilog kalıpları | `-ftree-loop-vectorize` GCC'de `-O2`'de varsayılan açık [8] |
| Kuyruk çağrıları | `call`+`ret` yerine `jmp`; çağıran yığında görünmez; kuyruk özyinelemesi döngüye döner | Kısmen | Bilinen fonksiyon girişine `jmp` bir kuyruk çağrısıdır; sınırlar başka kanıtla bilinmelidir | `-foptimize-sibling-calls` `-O2`'de açık [8]. Fonksiyon sınırı hatalarının kaynaklarından biri |
| Yazmaç atama | Değişken kimliği: bir yazmaç birden çok değişkeni taşır, bir değişken bölünür, değerler yığına taşar | Kısmen (değişken sınırları yaklaşık) | Veri akışı, SSA yeniden kurma, yaşam aralıkları | `-fomit-frame-pointer` `-O1`'den itibaren açık; yığın değişkeni kurtarmayı zorlaştırır [8]. Debin değişkenleri yazmaç ya da bellek değişkeni diye sınıflar [25] |
| SSA | Derleyici içi φ düğümleri; SSA'dan çıkışta kopya ve birleştirme | SSA formu tamamen yeniden kurulur; kaynak değişken eşlemesi kısmen | Veri akışından SSA yeniden inşası | SSA kaynakta olan bir bilgi değil, derleyicinin ara biçimidir. Van Emmerik SSA'yı decompile için yeniden kurar [16] |
| Komut seçimi | İfadenin kaynak biçimi; `lea`/`cmov`/SIMD/sihirli sayı deyimleri; inline edilmiş `memcpy`/`strlen` | Semantik tamamen; kaynak biçimi kısmen | ISA semantiği; deyim tanıma | Derleyici ders kitaplarının "kod biçimi" ve komut seçimi bölümleri (Bölüm 6.2) |
| Sembol tablosunun strip edilmesi | `.symtab` (iç semboller), DWARF (tipler, değişken adları, satır bilgisi) | Silinen kısım kalıcı | Kalanlar: `.dynsym` [9], string'ler, RTTI [11], dil çalışma zamanı üst verisi [12][13][14], istisna tabloları | Bkz. 3.4 |

### 3.2 Aşama notları: kaynakta karşılığı olmayan ya da ayrışan fonksiyonlar

Ground truth tasarımı için en kritik nokta şudur: derleyici, kaynak fonksiyonlarla ikili fonksiyonlar arasındaki eşlemeyi birebir olmaktan çıkarır. GCC belgesine göre [8]:

| Seçenek | Ne yapar | Etkin olduğu düzey | Eşleme türü |
|---|---|---|---|
| `-fipa-icf` | Özdeş fonksiyonları tek kopyaya katlar | `-O2`, `-Os` | Çok kaynak → bir ikili |
| `-fipa-cp-clone` | Sabit argümanlar için fonksiyon klonlar | `-O3` | Bir kaynak → çok ikili |
| `-fipa-sra` | Kullanılmayan parametreleri siler, bazı başvuru parametrelerini değerle geçirir | `-O2` ve üstü | İkilideki imza kaynaktaki imzadan farklı |
| `-fpartial-inlining` | Fonksiyonun bir kısmını satır içine alır, kalanı ayrı bir parça olur | `-O2` ve üstü | Bir kaynak → parçalar |
| `-freorder-blocks-and-partition` | Sıcak ve soğuk blokları ayrı bölümlere koyar | x86'da `-O2` ve üstü | Bir fonksiyon bellekte bölünür |

Sembollü ikililerde bu klonlar ve parçalar sonekli adlarla görünür. Sonek biçimi bu belgede resmî kaynaktan doğrulanmadı.

Jia ve ark. [37] bu yüzden ikili-kaynak eşlemesinin bire-bir değil "bire-çok" olduğunu ölçtü:
- Inlining oranı %70'e yaklaşabiliyor.
- Eşleme hatası kod aramada yaklaşık %30, zafiyet tespitinde yaklaşık %40 performans kaybına yol açıyor.
- Mevcut inlining benzetim stratejileri inline edilmiş fonksiyonların yalnız yaklaşık %60'ını yakalıyor.

### 3.3 Semantik koruma yükümlülüğü: ne garanti edilir, ne edilmez

**C standardı (C11, N1570 §5.1.2.3) [6] (D).**
- Standardın semantiği, optimizasyonu yok sayan soyut bir makineyi tanımlar (p1).
- Bir gerçekleştirim, değeri kullanılmayan ve gerekli yan etkisi olmayan ifade parçalarını hiç değerlendirmeyebilir (p4).
- Uyumlu bir gerçekleştirimin en az yükümlülükleri şunlardır (p6). Standart bunların toplamına programın *gözlemlenebilir davranışı* der.
  - `volatile` erişimler soyut makinenin kurallarına sıkı sıkıya uyar.
  - Program bittiğinde dosyalara yazılmış veri, soyut yürütmenin üreteceğiyle aynıdır.
  - Etkileşimli cihaz giriş-çıkışı 7.21.3'teki gibi davranır.

**Garanti edilenler:**
- UB içermeyen bir program için ikilinin gözlemlenebilir davranışı, kaynağın izin verdiği davranışlardan biridir.

**Garanti edilmeyenler (tersine derleme için asıl önemli kısım):**
- Değişkenlerin varlığı, sayısı ve yeri.
- Fonksiyon sınırları, fonksiyon sayısı ve imzaları. IPA-SRA ve klonlama bunları değiştirir [8].
- Gözlemlenmeyen hesaplamaların sırası ve biçimi.
- Kontrol akışının şekli ve veri yapılarının iç düzeni (`volatile` olmayan yerel bellek).
- Zamanlama.
- UB içeren programın herhangi bir davranışı. Derleyici UB'nin olmayacağını varsayabilir. Bu durumda kaynağın "niyeti" ikiliden hiçbir şekilde okunamaz.

**Biçimsel doğrulanmış derleyici, CompCert [7] (D).** CompCert'in semantik koruma teoremi eşdeğerlik değil, **iyileştirme** (refinement) ilişkisidir:
- Derlenmiş kodun davranışı, kaynağın izin verdiği davranışlardan birini "iyileştirir". Örneğin derleyici, optimizasyonla sıfıra bölme gibi bir çalışma zamanı hatasını ortadan kaldırabilir.
- Standardın açık bıraktığı değerlendirme sırasında derleyici bir sırayı seçer.
- Kaynakta çalışma zamanı hatası olmadığı biliniyorsa, kod kaynağın izin verdiği davranışlardan birini birebir sergiler.

**Tersine derleme için sonucu (biz):**
- Decompile edilmiş program, kaynağın değil, *ikilinin* semantiğini anlatır. Bu semantik, kaynağınkinin bir alt kümesidir.
- Kaynağın izin verdiği öbür davranışlar (belirlenmemiş sıra, UB) ikiliden geri kazanılamaz.
- En iyi decompiler bile kaynağın bir iyileştirmesini üretir.

### 3.4 Strip neyi siler, neyi bırakır?

| Ne | Durum | Kaynak |
|---|---|---|
| `.symtab` | Siler. Dosyayı tanımlayan bütün sembolleri tutar, genelde süreç belleğine yüklenmez | Oracle bağlayıcı kılavuzu [9] (D, Solaris ELF; kavram genel ELF için de geçerli) |
| `.dynsym` | Silinemez. Dinamik bağlama için gereken alt küme, belleğe yüklenir; içe ve dışa aktarılan adlar kalır | [9] |
| DWARF hata ayıklama bilgisi | Siler: tipler, değişken adları, satır bilgisi | |

Strip'ten sonra da kalan kanıt kaynakları:

| Kanıt | Ne taşır | Kaynak |
|---|---|---|
| String literal'ler | Hata ve log mesajları, `assert` metinleri | Linux'ta `assert` mesajı dosya adı, fonksiyon adı, satır ve ifade metnini içerir [10] (D). macOS libc'nin `assert`'ü için doğrulama yapılmadı (DY) |
| C++ RTTI | Çok biçimli sınıflar için karışık (mangled) tip adı string'i; vtable ile birlikte üretilir | Itanium C++ ABI §2.9 [11] (D) |
| Objective-C | Mesaj gönderimi çalışma zamanında seçiciyle (selector) çözülür; sınıfların gönderim tabloları seçicileri gerçekleştirim adreslerine bağlar. Bu yüzden seçicilerin ikilide bulunması gerekir | [12] (D). Seçicilerin metin olarak saklandığı ayrıntısı bu belgede doğrulanmadı (DY) |
| Go | gc derleyicisinin ürettiği ikililer sembol ve satır numarası tablolarını gömer | `debug/gosym` [13] (D) |
| Rust | Panik konumu kaynak dosya adı, satır ve sütunu taşır; `'static` bir konumdur | [14] (D) |
| İstisna/unwind tabloları (`.eh_frame`) | Fonksiyon aralıklarını taşır, x86-64 ELF'te strip'ten sonra kalır | Yaygın bilgi; bu belgede birincil kaynaktan doğrulanmadı (DY) |

---

## 4. Kilometre taşları

### 4.1 Temeller

- **Horspool & Marovac (1980) [1] (D).** Kod/veri ayrımının durma problemine eşdeğer olduğunu söyler ve pratikte çalışan bir algoritma önerir (bkz. 2.1).
- **Cifuentes (1994), "Reverse Compilation Techniques", doktora tezi [15] (D).**
  - Queensland University of Technology'nin resmî deposunda (QUT ePrints 36820) doktora tezi olarak kayıtlıdır. Tam metin depoda yalnız belge teslim hizmetiyle sunuluyor.
  - Bazı ders notları tezi "University of Queensland" diye anıyor. Resmî kayıt QUT'tur.
  - Yazarın kendi anlatımına göre tez 4 Temmuz 1994'te teslim edildi ve 80286 DOS ikililerini yüksek düzey dile çevirmeyi hedefledi. Veri akışı analizi, parametre geçirme ve kontrol akışı grafikleri tezin merkezindedir. dcc decompiler'ının dayanağıdır.
- **Van Emmerik (2007), "Static Single Assignment for Decompilation", doktora tezi, University of Queensland [16] (K).**
  - DBLP kaydı var. Tam metin yalnız üçüncü taraf bir aynada bulundu: tez kapağına göre 3 Mayıs 2007'de teslim edilmiş, danışmanları Paul Bailes ve Cristina Cifuentes. UQ eSpace kaydı bulunamadı.
  - Tez, SSA'nın decompile'da üç işi kolaylaştırdığını savunur: parametre ve dönüş değerlerinin belirlenmesi, tip yeniden inşası, dolaylı atlama ve çağrıların doğru çevrilmesi. Boomerang decompiler'ının dayanağıdır.

### 4.2 Kontrol akışı yapılandırma

- **Phoenix: Schwartz, Lee, Woo, Brumley, USENIX Security 2013 [17] (D).**
  - Mevcut yapılandırma algoritmalarının semantiği korumadığını ve yapı kurtarma fırsatlarını kaçırdığını gösterdi.
  - Semantiği koruyan yapısal analiz ve yinelemeli yapılandırma önerdi.
  - GNU coreutils'ten 107 programda Hex-Rays'e göre %114 daha fazla doğruluk, önceki yöntemlere göre 30 kat daha fazla kurtarılmış yapı bildirdi.
  - Schwartz'ın doktora tezi bu çalışmayı "soyutlama kurtarma" çerçevesine yerleştirir [43].
- **No More Gotos / DREAM: Yakdan, Eschweiler, Gerhards-Padilla, Smith, NDSS 2015 [18] (D).**
  - Kalıplara bağlı olmayan bir yapılandırma algoritması ve semantiği koruyan dönüşümlerle goto'suz çıktı üretti.
  - coreutils'te Hex-Rays'e göre fonksiyonların %72,7'sinde, Phoenix'e göre %98,8'inde daha kısa kod üretti.
- **DREAM++: Yakdan, Dechand, Gerhards-Padilla, Smith, "Helping Johnny to Analyze Malware", IEEE S&P 2016, s. 158–177, DOI 10.1109/SP.2016.18 [19] (D).**
  - Okunabilirliğe yönelik dönüşümler ekledi: ifade sadeleştirme, kontrol akışı sadeleştirme, anlama duyarlı isimlendirme.
  - Gerçek kötü amaçlı yazılım örnekleriyle 6 görevli bir kullanıcı çalışması yaptı. Katılımcılar Hex-Rays'e göre 3 kat, DREAM'e göre 2 kat daha fazla görevi çözdü.
  - Karadul'un "aylar → saatler" iddiası için örnek alınacak deney tasarımı budur. Yakdan'ın tezi: [21] (D).
- **SAILR: Basque ve ark., USENIX Security 2024 [20] (D).**
  - Başarı ölçütünün goto'ları sıfırlamak değil, özgün kaynağa yaklaşmak olduğunu savunur. Örneğin Linux 6.1 kaynağında 3.754 goto var.
  - Sahte goto'ların kök nedeni, her optimizasyon düzeyinde görülen derleyici dönüşümleridir. Makale optimizasyonsuz derlemede bile %17'lik bir pay veriyor; paydanın tanımı makalede.
  - SAILR, GCC'nin hattını taklit ederek bu dönüşümleri tersine çevirir.
  - Karadul için ders: **derleyiciye duyarlı** tersine dönüşüm.

### 4.3 Tip kurtarma

- **TIE: Lee, Avgerinos, Brumley, NDSS 2011 [22] (D).** Derlemenin tip soyutlamalarını yazmaç ve düz bellek işlemlerine indirdiğini çıkış noktası alır. İlkeli bir tip çıkarımı önerir; statik ve dinamik analizde kullanılabilir. Değerlendirmesi 87 programdadır.
- **Retypd: Noonan, Loginov, Cok, PLDI 2016 [23] (D, arXiv tam sürüm).** Özyinelemeli kısıtlı çok biçimli tipler ve alt tiplemeyle bir tip sistemi kurar. `const` işaretçi açıklamalarında %98 recall bildirir ve yüksek kaliteli points-to bilgisine ihtiyaç duymaz.
- **OSPREY: Zhang ve ark., IEEE S&P 2021, s. 813–832 [24] (D).** Belirsizliği derlemedeki bilgi kaybına bağlar. Değişken ve struct kurtarmayı olasılıksal kısıtlarla çözer; Ghidra, IDA ve angr ile karşılaştırır. Sayısal sonuçlar bu taramada okunmadı.

### 4.4 İsim kurtarma

| Çalışma | Yöntem | Bildirilen sonuç | Kaynak |
|---|---|---|---|
| **Debin**: He, Ivanov, Tsankov, Raychev, Vechev, CCS 2018 | Koşullu rastgele alanlar (CRF); önce değişkenleri yazmaç/bellek diye sınıflar, sonra isim ve tip tahmin eder; x86, x64, ARM | — | [25] (D, depo BibTeX'i; ACM sayfasına erişilemedi) |
| **DIRE**: Lacomis ve ark., ASE 2019 | Sözcüksel ve yapısal bilgiyle olasılıksal isim tahmini | 164.632 benzersiz x86-64 ikili. Tam eşleşme: genel %74,3; gövdesi eğitimde görülen %85,5; görülmeyen %35,3 | [26] (D) |
| **DIRTY**: Chen ve ark., USENIX Security 2022 | Transformer ile isim ve tip tahmini | İsim %66,4 (görülen %87,1 / görülmeyen %36,9); tip %75,8 (%89,9 / %56,4) | [27] (D) |
| **VarBERT**: Pal ve ark., IEEE S&P 2024 | İnsan kaynak koduyla ön eğitim, sonra ince ayar | O2 ikililerde özgün isim isabeti %54,43 (IDA) ve %54,49 (Ghidra). DIRE ve DIRTY'nin eğitimde görülmeyen fonksiyonlara zayıf genelleştiğini vurgular | [28] (D, yazar sayfası) |
| **DIRE and its Data**: Dramko ve ark., TOSEM | Eğitim verisi seçiminin etkisi: popüler projelerle eğitmek genellemeyi artırıyor; alana özgü uyarlama alana özgü isimleri %23 daha sık tahmin ediyor | — | [29] (K; yıl 2022/2023 kaynaklar arasında tutarsız) |
| **Punstrip**: Patrick-Evans, Cavallaro, Kinder, ACSAC 2020, s. 373–385 | Olasılıksal parmak izi + grafiksel model; derleyiciler ve optimizasyon düzeyleri arasında Debian C ikilileri | — | [30] (D) |
| **XFL**: Patrick-Evans, Dannehl, Kinder, IEEE S&P 2023, s. 2375–2390 | İsimleri token'lara bölüp çok etiketli sınıflandırma | 10.047 Debian ikilisinde %83,5 kesinlik (precision) | [31] (D; erken sürüm %82,5) |

**Metrik uyarısı.**
- DIRE, DIRTY ve VarBERT değişken başına tam eşleşme ölçer.
- XFL token düzeyinde kesinlik ölçer.
- Karadul isim düzeyinde F1 ölçüyor.

Bu sayılar birbirleriyle ve Karadul'la doğrudan karşılaştırılamaz. Makalede hem token düzeyi hem isim düzeyi raporlanmalıdır.

### 4.5 Decompiler doğruluğunu test eden çalışmalar

- **Liu & Wang, ISSTA 2020, DOI 10.1145/3395363.3397370 [32] (D).**
  - Dört yaygın decompiler'da hata tetikleyen 1.423 girdi buldu.
  - İki açık kaynak decompiler'da 13 hata tespit etti.
  - Sonuç: decompiler'lar akademinin sandığından yetenekli, ama tip kurtarma ve optimizasyon hâlâ sorun.
- **Dramko, Lacomis, Schwartz, Vasilescu, Le Goues, USENIX Security 2024, s. 379–396 [33] (D).** Dört decompiler'ın çıktısını açık kodlama ve tematik analizle inceledi. İsim ve tip dışındaki sadakat (fidelity) kusurları için bir sınıflandırma üretti.
- **Kline & Kulkarni, ICISSP 2023, s. 228–239 [34] (D).** Fonksiyon, değişken ve tip çıkarımının isabetini DWARF'a karşı ölçen bir çerçeve kurdu ve bütün GNU coreutils programlarında Ghidra'ya uyguladı. Karadul'un ölçüm düzeneğine en yakın örnek budur.
- **Disassembly ölçümleri.**
  - Andriesse ve ark., USENIX Security 2016 [35] (D): 9 araç, 981 ikili; ayrıntı 2.2'de.
  - Pang ve ark., "SoK", IEEE S&P 2021, s. 833–851 [36] (D): 9 açık kaynak araç, 3.788 ikili.

### 4.6 LLM tabanlı decompile (yalnız bağlam)

- **LLM4Decompile: Tan, Luo, Li, Zhang, EMNLP 2024 [39] (D).**
  - 1,3B–33B parametreli açık modeller.
  - HumanEval ve ExeBench'te yeniden çalıştırılabilirlik oranında GPT-4o ve Ghidra'ya göre %100'ün üzerinde göreli iyileşme bildirir.
  - Ghidra çıktısını iyileştiren "Ref" sürümü ek %16,2 kazanç bildirir.
- **ReSym: Xie ve ark., CCS 2024, s. 4554–4568 [40] (D).** LLM tahminlerini Prolog tabanlı bir akıl yürütmeyle birleştirerek yerel değişken ve kullanıcı tanımlı struct isim ve tiplerini kurtarır. Uydurmayı azaltmak için çapraz denetim yapar.
- **Tarama: Abusabha & Hwang, arXiv 2608.24955, Ağustos 2026 [41] (D).** Alanda güvenilir ground truth ve standart kıyas setlerinin eksik olduğunu, bunun karşılaştırmayı zorlaştırdığını söyler.
- **Kuramsal yer (biz).** LLM'ler bilgi yokluğu sınırını aşmaz. Yaptıkları şey, korpus önselini çok güçlü biçimde kullanmaktır (bkz. 2.3'teki A*). Karadul'un LLM kullanmama kararıyla çelişmez. Makalede LLM yalnız kıyas için koşturulmalıdır.

**Değişebilecek bilgi kutusu:**
- İddia: LLM tabanlı decompile hızla değişen bir alan; bu bölümdeki sonuçlar 2024–2026 yayınlarına dayanıyor.
- Kanıt: [39][40][41].
- Güven: orta. Yayın sayısı hızla artıyor, kıyas setleri standart değil.
- Kontrol tarihi: 2026-10-15.
- Ne değişebilir: SOTA sayıları, kıyas setleri, model boyutları.

### 4.7 Ölçülmüş sınırlar (Soru 4)

**Doğrudan bir ölçüm bulunamadı.** Derlemenin sildiği bilgiyi bit cinsinden ölçen ya da isim kurtarmanın kuramsal tavanını (2.3'teki A*) doğrudan kestiren bir çalışma bu taramada bulunamadı. Bu, makale için açık bir boşluktur. Mevcut ölçümler dolaylıdır:

1. **Görülen ve görülmeyen kod ayrımı (en önemli bulgu).** DIRE ve DIRTY'de, gövdesi eğitimde görülen fonksiyonlarla görülmeyenler arasında isim isabeti yaklaşık 50 puan düşüyor: %85,5 → %35,3 ve %87,1 → %36,9 [26][27]. VarBERT bu genelleme sorununu ayrıca vurguluyor [28]. Yorumu şudur:
   - Yüksek isabetin büyük kısmı *aynı kodun başka yerde görülmüş olmasından* gelir. Bu, işlev olarak imza eşleştirmeye denktir.
   - Görülmemiş kodda isabet o dağılım ve metrik için A*'ın alt sınırıdır. ~%35–37 gibi sıfırdan anlamlı ölçüde büyük bir değerdir. Not: veri setlerinde `i`, `buf`, `len` gibi sık isimlerin payı bu oranı şişirebilir; bu ayrıca incelenmeli.
2. **Disassembly.** Komutlarda %100'e yakın, fonksiyon tespitinde sıklıkla %80'e ya da altına düşen doğruluk [35]. İkinci değer makalede Windows hedefli çalışmalar bağlamında veriliyor. Araç tercihine göre kapsama-doğruluk ödünleşimi [36].
3. **Yapı.** Sahte goto'ların kökü derleyici optimizasyonlarıdır ve optimizasyonsuz derlemede bile görülür [20].
4. **Decompiler doğruluğu.** 1.423 hata tetikleyen girdi [32]. Ghidra'nın fonksiyon, değişken ve tip çıkarımının DWARF'a karşı ölçümü [34].
5. **Bire-çok eşleme.** Inlining oranı %70'e yaklaşabiliyor [37]. Bu, "ikili fonksiyon başına bir özgün isim" varsayımını bozar.
6. **Korunan "kaynak düzeyi" bilgi.** Caliskan ve ark. [38] (D; NDSS 2018, DOI 10.14722/ndss.2018.23304) programcı üslubunun derlemeden sağ çıktığını gösterdi:
   - Derlenmiş ikililerden programcı kimliği 100 aday arasında %96'ya, 600 aday arasında %83'e varan isabetle bulunabiliyor.
   - Yöntem temel gizlemeye, optimizasyon ayarlarına ve strip edilmiş sembol tablosuna karşı dayanıklı.
   - Sonuç: ikili, isimler dışında kaynağın üslubuna dair ölçülebilir bilgi taşır.

---

## 5. Karadul için çıkarımlar (isim kurtarma ve tarif yaklaşımı)

### 5.1 İsimlerin üç epistemik statüsü

Kuramsal ayrım (2.4), Karadul'un üç sınıflı modelini (kesin / tarif / bilinmiyor) doğrudan destekler. Dördüncü bir statü de açıkça adlandırılmalıdır:

| Statü | Tanım | Kanıt türü | Doğrulanabilirlik |
|---|---|---|---|
| **Kesin (kanıtlı özgün isim)** | İkilideki bir kanıt özgün ismi belirler | `.dynsym`, `assert`/log string'i, RTTI, ObjC seçicisi, Go/Rust üst verisi, birebir kütüphane imzası, isimli komşulardan tutarlı yayılım | Kanıt zinciri gösterilebilir |
| **Tahmin (korpus önseli)** | İsim kanıtla değil, istatistikle seçilir | DIRE/DIRTY/LLM türü; deterministik kural tabanlı önseller de bu sınıftadır (ör. döngü sayacına `i`) | Yalnız istatistiksel; kanıt diye sunulamaz |
| **Tarif** | Özgün ismi iddia etmeden fonksiyonun ne yaptığını anlatır | Korunan semantik: kütüphane ve sistem çağrıları, sabitler, veri akışı, döngü deyimleri, ABI arayüzü | Davranışa karşı test edilebilir ve yanlışlanabilir |
| **Bilinmiyor** | Yeterli kanıt yok | — | — |

### 5.2 Tarif katmanının kuramsal dayanağı

Makalede savunulabilecek ana tez (biz):

1. **Özgün isim ile tarif farklı türden problemlerdir.**
   - Özgün isim çoğu zaman bir *bilgi yokluğu* problemidir: H(isim | B) büyüktür. Kanıt yoksa yalnız tahmin mümkündür.
   - Tarif ise korunan bilginin bir fonksiyonudur: gözlemlenebilir davranış korunur [6][7]. Bu yüzden bir *hesaplanabilirlik* problemidir.
2. **Tarifin de bir sınırı vardır.** Fonksiyon "CRC32 hesaplar" gibi davranışsal bir yüklemin kesin doğrulaması genel durumda yine kararsızdır [2]. Ama bu, disassembly gibi pratikte büyük ölçüde aşılabilen türden bir sınırdır: kalıp tanıma, sabit kanıtı, test girdisiyle sınama yeterlidir. Bilgi yokluğu sınırı ise hiçbir hesaplamayla aşılamaz.
3. **Sonuç: kanıt yoksa dürüst çıktı tariftir.** DIRE ve DIRTY'nin görülmemiş kodda ~%35–37'de kalması [26][27] bunun ampirik karşılığıdır.

Hafıza notundaki "lokal isim recall'ü bilgisel olarak ~0" ifadesi bu çerçevede düzeltilmeli. İkili özgün ismi *belirlemez*, kesin iddia imkânsızdır. Ama koşullu dağılım düz değildir, A* > 0'dır: istatistiksel tahmin sıfırın anlamlı ölçüde üstüne çıkar. Karadul'un LLM'siz ve kanıtlı tutumu bu yüzden "imkânsızlık" değil, **"iddia edilebilirlik"** gerekçesiyle savunulmalıdır.

### 5.3 Tarif tasarım ilkeleri (öneri)

1. **Yalnız korunan bilgiden türet.** Gözlemlenebilir etkiler (dosya, ağ, süreç, bellek ayırma çağrıları), veri dönüşümleri (bilinen sabitler ve tablolar), arayüz (ABI'den arite ve tipler), döngü ve karşılaştırma deyimleri. Kaynağa özgü biçimi (`for` mu `while` mı, makro mu fonksiyon mu) olgu diye sunma. Bu bilgiler 3.1'e göre kalıcı olarak kayıptır.
2. **Niyet değil davranış söyle.** Örneğin `compute_crc32_over_buffer` gibi bir isim davranışı anlatır. `validate_license` ise niyet iddiasıdır; kanıt (ilgili string'ler) yoksa verilmemelidir. Örnekler açıklama amaçlıdır.
3. **Her isme kanıt künyesi ve statü etiketi ekle.** Ör. `statü=tarif; kanıt=[crc32 sabit tablosu @0x..., döngü deyimi]; güven=...`. Hafıza notlarına göre 2026-10-14 denetiminde her ismin güveni 1.0 gösteriliyordu. Bu, 5.1'deki ayrımın çıktıda kaybolması demektir ve makale açısından da kusurdur.
4. **Derleyiciye duyarlı ol (SAILR dersi [20]):**
   - ICF ile katlanmış bir fonksiyon için tek isim değil, aday isim kümesi ver.
   - Klon ve parçaları (`ipa-cp`, `ipa-sra`, kısmi inlining, sıcak/soğuk bölme [8]) aynı kaynak fonksiyonuna bağla.
   - IPA-SRA nedeniyle ikilideki parametre listesinin kaynaktakinden farklı olabileceğini parametre isimlendirmesinde hesaba kat.
5. **Kesin ve tarif ayrı yarışsın.** Tarif hiçbir zaman özgün isim yerine sayılmamalı ve özgün isim metriğine katılmamalıdır.

### 5.4 Değerlendirme ve ground truth için sonuçlar

- **Bire-çok eşleme [37].** Ground truth, ikili fonksiyon ile kaynak fonksiyon arasında bire-çok ve çoğa-bir eşlemeyi temsil etmelidir: inlining, ICF, klonlar. Aksi halde doğru bir isim "yanlış", katlanmış bir fonksiyon "eksik" sayılır.
- **İki ayrı eğri raporlanmalı (Berke'nin makale hedefiyle uyumlu):**
  - Kesin isimler için isim düzeyi ve token düzeyi kesinlik-kapsama.
  - Tarif için insan değerlendirmesiyle doğruluk ve iki değerlendirici arası uyum.
  - Ana gösterge: sabit bir kesinlikte (ör. %90) fonksiyonların yüzde kaçına isim verildiği.
- **Görülen/görülmeyen ayrımı Karadul'a da uygulanmalı.** İmza veritabanında aynı kodun bulunduğu fonksiyonlar ile bulunmadığı fonksiyonlar ayrı raporlanmalı. Bu, DIRE ve DIRTY'nin "Body in Train" ayrımının deterministik karşılığıdır [26][27] ve sonuçların ezber mi genelleme mi olduğunu gösterir.
- **LTO ve optimizasyon düzeyi deney değişkeni olmalı.** Andriesse [35] LTO'yu ayrı koşul olarak test etti. Karadul'un iç ölçüm notlarında da LTO'lu ve LTO'suz ikililer arasında büyük fark kaydı var; bu belge onu ayrıca doğrulamadı.
- **Ölçüm düzeneği örneği.** Kline & Kulkarni'nin DWARF'a karşı karşılaştırma çerçevesi [34] ve Phoenix ile DREAM'in coreutils kullanımı [17][18], hakemlerin tanıdığı bir zemindir. Ama coreutils, Karadul için artık geliştirme setidir; dondurulmuş test seti şartı bunu gerektirir.

### 5.5 Kanıt envanteri (platforma göre, strip sonrası)

| Kanıt | Linux ELF | macOS Mach-O | Kaynak |
|---|---|---|---|
| Dinamik içe/dışa aktarma adları | `.dynsym` kalır | Dinamik bağlama adları kalır (DY) | [9] |
| `assert` string'leri | Fonksiyon ve dosya adı | Benzer olması beklenir (DY) | [10] |
| C++ RTTI tip adları | Var | Var (aynı Itanium ABI) | [11] |
| ObjC sınıf ve seçici bilgisi | — | Çalışma zamanı gönderimi için gerekli | [12] |
| Go sembol ve satır tabloları | Var | Var | [13] |
| Rust panik dosya yolları | Var | Var | [14] |
| Kütüphane imzası (birebir kod) | Statik bağlı kütüphanede güçlü; LTO ve inlining ile zayıflar (biz) | Aynı | [8][37] |

### 5.6 Makale için önerilen iddialar (ölçülebilir biçimde)

1. Karadul, kanıt gerektiren özgün isim ile korunan semantikten türetilen tarifi ayıran, LLM'siz ve kanıt künyeli bir isimlendirme sunar.
2. Ölçüm: dondurulmuş test setinde, sabit kesinlikte kapsama. Kesin isimler için DIRE/DIRTY/VarBERT türü yöntemlere ve LLM'e karşı token ve isim düzeyinde. Tarif için insan değerlendirmesiyle.
3. Kuramsal katkı (arka plan bölümü):
   - Hesaplanabilirlik sınırı ile bilgi yokluğu sınırının ayrımı (2.4).
   - Bayes tavanı A* çerçevesi (2.3).
   - Ölçülmüş isabetlerin tavanın üst sınırı değil, alt sınırı olduğu gözlemi.
   - Literatürde H(isim | B)'yi doğrudan ölçen bir çalışmanın bulunamaması, açık bir araştırma sorusu olarak işaretlenebilir.

---

## 6. Ücretsiz yasal kaynaklar ve telifli kitaplar

### 6.1 Ücretsiz ve yasal kaynaklar (yazar ya da yayıncı tarafından açık)

**Kitaplar ve ders notları**

| Kaynak | Erişim ve lisans | İlgili konular |
|---|---|---|
| Møller & Schwartzbach, *Static Program Analysis*, Aarhus Üniversitesi [46] | https://cs.au.dk/~amoeller/spa/ — CC BY-NC-ND 4.0, son revizyon Eylül 2026 (D) | Giriş bölümü: davranışsal özelliklerin kararsızlığı (Turing/Rice). Sayfadaki konu listesinde kafesler ve sabit nokta çözücüler, tip analizi, soyut yorumlama var. İşaretçi analizi bölümü olduğu biliniyor ama bu belgede doğrulanmadı (DY) |
| Mogensen, *Basics of Compiler Design*, 2010 baskısı, DIKU [47] | http://hjemmesider.diku.dk/~torbenm/Basics/ — kişisel kullanım için kopyalama ve basma izni (D) | Analiz ve optimizasyon bölümü (2008 baskısında eklendi), bellek yönetimi bölümü (2010). Tam bölüm listesi doğrulanmadı |
| Wirth, *Compiler Construction* [48] | https://people.inf.ethz.ch/wirth/CompilerConstruction/index.html — yazarın ETH sayfasında iki PDF ve kaynak dosyaları; sayfada lisans belirtilmiyor (K) | Küçük bir derleyicinin uçtan uca kod üretimi |
| Sampson, Cornell CS 6120 *Advanced Compilers* (kendi kendine çevrimiçi ders) [49] | https://www.cs.cornell.edu/courses/cs6120/2020fa/self-guided/ — açık kaynak (D) | Yerel optimizasyon ve DCE, veri akışı, SSA, LLVM, döngü optimizasyonu, prosedürler arası analiz, alias analizi |
| Yurichev, *Reverse Engineering for Beginners* [50] | https://beginners.re/ — yazar ücretsiz yayımlıyor, CC BY-SA 4.0 (D) | Derleyici çıktısını assembly üzerinden okuma; bölüm listesi bu belgede doğrulanmadı |

**Tezler**

| Tez | Erişim |
|---|---|
| Cifuentes 1994, QUT [15] | https://eprints.qut.edu.au/36820/ — resmî kayıt; tam metin yalnız belge teslimiyle. Çevrimiçi kopyalar üçüncü taraf aynalarda, yasal durumları doğrulanmadı |
| Van Emmerik 2007, UQ [16] | Resmî depo kaydı bulunamadı. Tam metin üçüncü taraf aynada: https://yurichev.com/mirrors/vanEmmerik_ssa.pdf (yasal durumu DY) |
| Kinder 2010, *Static Analysis of x86 Executables*, TU Darmstadt [42] | TUprints kaydı https://tuprints.ulb.tu-darmstadt.de/view/person/Kinder=3AJohannes=3A=3A.html ; PDF yazarın kürsü sayfasında https://www.plai.ifi.lmu.de/publications/phdthesis-kinder.pdf (D). Dolaylı atlamalar varlığında CFG yeniden inşası, Jakstab |
| Schwartz 2014, *Abstraction Recovery for Scalable Static Binary Analysis*, CMU [43] | https://kilthub.cmu.edu/articles/thesis/Abstraction_Recovery_for_Scalable_Static_Binary_Analysis/6714434 (D). Phoenix'in tez bağlamı |
| Andriesse 2017, *Analyzing and Securing Binaries Through Static Disassembly*, VU Amsterdam [44] | https://danielandriesse.com/theses/phd-thesis.pdf — yazar sitesi (D) |
| Yakdan 2018, *A Human-Centric Approach For Binary Code Decompilation*, Bonn [21] | https://bonndoc.ulb.uni-bonn.de/xmlui/handle/20.500.11811/7517 — açık erişim üniversite deposu (D) |
| Balakrishnan 2007, *WYSINWYX*, UW–Madison [45] | Yalnız künye doğrulandı (Math Genealogy); tam metin bağlantısı doğrulanmadı |

**Açık erişimli makaleler**
- USENIX bildirileri açık erişimlidir: [17][20][27][33][35].
- NDSS bildirileri açık erişimlidir: [18][22].
- arXiv sürümleri: [23][26][31][36][37][38][39][41].
- Yazar ve kurum kopyaları: [24][28][29][30][40].

**Standartlar ve resmî belgeler**
- C11 taslağı N1570 [6]: https://www.open-std.org/jtc1/sc22/wg14/www/docs/n1570.pdf. Bu taramada aynı metnin HTML kopyasından okundu.
- GCC optimizasyon seçenekleri [8].
- CompCert kılavuzu [7].
- Itanium C++ ABI [11].
- Oracle bağlayıcı kılavuzu [9].
- Go `debug/gosym` [13], Rust `Location` [14], Apple Objective-C çalışma zamanı kılavuzu [12].

### 6.2 Telifli ders kitapları: künye ve ilgili bölümler

Bu kitapların yalnız künyesi ve içindekileri incelendi. Korsan kopyalara bakılmadı.

**Aho, Lam, Sethi, Ullman, *Compilers: Principles, Techniques, and Tools*, 2. baskı, Pearson/Addison-Wesley, ISBN 978-0-321-48681-3 [51].** İlk basım yılı yaygın olarak 2006 diye anılır; yayıncı sayfası 2011/2012 tarihli bir basımı gösteriyor (yıl: K). İlgili bölümler (bölüm numaraları Pearson ve British Library kaydından, K):

| Bölüm | Bu soruyla ilgisi |
|---|---|
| 8. Code Generation | Komut seçimi, yazmaç atama |
| 9. Machine-Independent Optimizations | Veri akışı, sabit yayılımı, ölü kod, döngüler |
| 10. Instruction-Level Parallelism | Komut çizelgeleme |
| 11. Optimizing for Parallelism and Locality | Döngü dönüşümleri |
| 12. Interprocedural Analysis | Prosedürler arası ve işaretçi analizi |

**Cooper & Torczon, *Engineering a Compiler*, 3. baskı, Elsevier (Morgan Kaufmann), 2022 [52] (D, yayıncı içindekiler sayfası).**

| Bölüm | Bu soruyla ilgisi |
|---|---|
| 4. Intermediate Representations | SSA dahil ara biçimler |
| 6. Implementing Procedures | Çağrı kuralları ve ABI |
| 7. Code Shape | Kaynak yapıların koda nasıl indiği. Decompile deyimleri için en doğrudan bölüm |
| 8. Introduction to Optimization | |
| 9. Data-Flow Analysis | |
| 10. Scalar Optimization | DCE, sabit yayılımı |
| 11. Instruction Selection | |
| 12. Instruction Scheduling | |
| 13. Register Allocation | |

**Muchnick, *Advanced Compiler Design and Implementation*, Morgan Kaufmann, 1997, ISBN 1-55860-320-4 [53] (künye: K, kütüphane kaydı ve yayıncı sayfası).** Yayıncı tanımına göre çok geniş bir optimizasyon yelpazesini ve bunların göreli önemini ele alır. Prosedür optimizasyonları (kuyruk çağrısı, inlining), yazmaç atama ve prosedürler arası analiz bölümleri olduğu hatırlanıyor. Bölüm numaraları ve adları doğrulanmadı (DY); kullanmadan önce içindekilerden kontrol edilmeli.

**Appel, *Modern Compiler Implementation in C* (ayrıca ML ve Java sürümleri), Cambridge University Press, 1998 [54] (D).** Yazar sayfası 1998 telif ve 1997 ön baskıları gösteriyor. Bölüm numaraları CUP'un 2004 basım sayfasından (K):

| Bölüm | Konu |
|---|---|
| 9 | Instruction Selection |
| 10 | Liveness Analysis |
| 11 | Register Allocation |
| 18 | Loop Optimizations |
| 19 | Static Single-Assignment Form |

---

## 7. Kaynakça

**Kuram, standartlar ve resmî belgeler**

1. R. N. Horspool, N. Marovac. An Approach to the Problem of Detranslation of Computer Programs. *The Computer Journal* 23(3):223–229, Ağustos 1980. DOI 10.1093/comjnl/23.3.223. https://academic.oup.com/comjnl/article-lookup/doi/10.1093/comjnl/23.3.223 (D; yayıncı özeti okundu, tam metin ücretli)
2. H. G. Rice. Classes of Recursively Enumerable Sets and Their Decision Problems. *Transactions of the American Mathematical Society* 74:358–366, 1953. https://doi.org/10.1090/S0002-9947-1953-0053041-6 (D)
3. W. Landi. Undecidability of Static Analysis. *ACM Letters on Programming Languages and Systems* 1(4), Aralık 1992. (K: Ramalingam'ın özetindeki ve atıf listesindeki bilgiden; sayfa ve DOI doğrulanmadı)
4. G. Ramalingam. The Undecidability of Aliasing. *ACM TOPLAS* 16(5):1467–1471, 1994. https://www.microsoft.com/en-us/research/?p=324470 (D)
5. G. Balakrishnan, T. Reps. WYSINWYX: What You See Is Not What You eXecute. *ACM TOPLAS*, 2010. DOI 10.1145/1749608.1749612. https://pages.cs.wisc.edu/~bgogul/Research/Journal/toplas10.html (K: yazar sayfası ve DOI; cilt/sayı doğrulanmadı)
6. ISO/IEC 9899:2011 (C11) taslağı N1570, §5.1.2.3 Program execution. https://www.open-std.org/jtc1/sc22/wg14/www/docs/n1570.pdf ; okunan HTML kopyası: http://port70.net/~nsz/c/c11/n1570.html (D)
7. CompCert C kullanıcı kılavuzu, Bölüm 1 (semantik koruma). https://compcert.org/man/manual001.html (D). Ayrıca X. Leroy, Formal Verification of a Realistic Compiler, *Communications of the ACM*, 2009 (DY: yayıncı sayfası erişimi engelledi)
8. GCC Manual: Options That Control Optimization. https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html (D, 2026-10-15'te okunan sürüm)
9. Oracle Solaris Linkers and Libraries Guide, sembol tablosu bölümleri. https://docs.oracle.com/en/operating-systems/solaris/oracle-solaris/11.4/linkers-libraries/symbol-table-layout-conventions.html ve https://docs.oracle.com/cd/E36784_01/html/E36857/chapter2-13.html (D, arama sonucundaki resmî sayfa metinleriyle)
10. Linux man-pages, assert(3). https://man7.org/linux/man-pages/man3/assert.3.html (D)
11. Itanium C++ ABI, §2.9 RTTI. https://itanium-cxx-abi.github.io/cxx-abi/abi.html (D)
12. Apple, Objective-C Runtime Programming Guide: Messaging. https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/ObjCRuntimeGuide/Articles/ocrtHowMessagingWorks.html (D)
13. Go standart kütüphanesi, `debug/gosym` paketi. https://pkg.go.dev/debug/gosym (D)
14. Rust standart kütüphanesi, `std::panic::Location`. https://doc.rust-lang.org/std/panic/struct.Location.html (D)

**Klasik decompile ve yapılandırma**

15. C. Cifuentes. Reverse Compilation Techniques. Doktora tezi, Queensland University of Technology, 1994. https://eprints.qut.edu.au/36820/ (D)
16. M. J. Van Emmerik. Static Single Assignment for Decompilation. Doktora tezi, University of Queensland, 2007. DBLP: https://dblp.org/pid/24/1405.html ; ayna: https://yurichev.com/mirrors/vanEmmerik_ssa.pdf (K)
17. E. J. Schwartz, J. Lee, M. Woo, D. Brumley. Native x86 Decompilation Using Semantics-Preserving Structural Analysis and Iterative Control-Flow Structuring. USENIX Security 2013. https://www.usenix.org/conference/usenixsecurity13/technical-sessions/presentation/schwartz (D)
18. K. Yakdan, S. Eschweiler, E. Gerhards-Padilla, M. Smith. No More Gotos: Decompilation Using Pattern-Independent Control-Flow Structuring and Semantics-Preserving Transformations. NDSS 2015. https://www.ndss-symposium.org/ndss2015/ndss-2015-programme/no-more-gotos-decompilation-using-pattern-independent-control-flow-structuring-and-semantics/ (D)
19. K. Yakdan, S. Dechand, E. Gerhards-Padilla, M. Smith. Helping Johnny to Analyze Malware: A Usability-Optimized Decompiler and Malware Analysis User Study. IEEE S&P 2016, s. 158–177. https://doi.org/10.1109/SP.2016.18 ; slaytlar: https://www.ieee-security.org/TC/SP2016/slides/yakdan.pdf (D)
20. Z. L. Basque, A. P. Bajaj, W. Gibbs, J. O'Kain, D. Miao, T. Bao, A. Doupé, Y. Shoshitaishvili, R. Wang. Ahoy SAILR! There is No Need to DREAM of C: A Compiler-Aware Structuring Algorithm for Binary Decompilation. USENIX Security 2024, s. 361–378. https://www.usenix.org/conference/usenixsecurity24/presentation/basque (D)
21. K. Yakdan. A Human-Centric Approach For Binary Code Decompilation. Doktora tezi, Universität Bonn, 2018. https://bonndoc.ulb.uni-bonn.de/xmlui/handle/20.500.11811/7517 (D)

**Tip kurtarma**

22. J. Lee, T. Avgerinos, D. Brumley. TIE: Principled Reverse Engineering of Types in Binary Programs. NDSS 2011. https://www.ndss-symposium.org/?p=2424 (D)
23. M. Noonan, A. Loginov, D. Cok. Polymorphic Type Inference for Machine Code. PLDI 2016. https://arxiv.org/abs/1603.05495 (D)
24. Z. Zhang, Y. Ye, W. You, G. Tao, W.-C. Lee, Y. Kwon, Y. Aafer, X. Zhang. OSPREY: Recovery of Variable and Data Structure via Probabilistic Analysis for Stripped Binary. IEEE S&P 2021, s. 813–832. https://par.nsf.gov/biblio/10296833 ; https://www.cs.purdue.edu/homes/zhan3299/res/SP21a.pdf (D)

**İsim kurtarma**

25. J. He, P. Ivanov, P. Tsankov, V. Raychev, M. Vechev. Debin: Predicting Debug Information in Stripped Binaries. ACM CCS 2018. https://github.com/eth-sri/debin (D, depo BibTeX'i)
26. J. Lacomis, P. Yin, E. J. Schwartz, M. Allamanis, C. Le Goues, G. Neubig, B. Vasilescu. DIRE: A Neural Approach to Decompiled Identifier Naming. ASE 2019. https://arxiv.org/abs/1909.09029 ; tablolar: https://ar5iv.labs.arxiv.org/html/1909.09029 (D)
27. Q. Chen, J. Lacomis, E. J. Schwartz, C. Le Goues, G. Neubig, B. Vasilescu. Augmenting Decompiler Output with Learned Variable Names and Types. USENIX Security 2022, s. 4327–4343. https://www.usenix.org/conference/usenixsecurity22/presentation/chen-qibin ; tablolar: https://ar5iv.labs.arxiv.org/html/2108.06363 (D)
28. K. K. Pal, A. P. Bajaj ve ark. "Len or index or count, anything but v1": Predicting Variable Names in Decompilation Output with Transfer Learning. IEEE S&P 2024. https://adamdoupe.com/publications/varbert-oakland2024.md ; https://par.nsf.gov//servlets/purl/10536794 (D, yazar sayfası)
29. L. Dramko, J. Lacomis, P. Yin, E. J. Schwartz, M. Allamanis, G. Neubig, B. Vasilescu, C. Le Goues. DIRE and its Data: Neural Decompiled Variable Renamings with Respect to Software Class. *ACM TOSEM*. https://clairelegoues.com/assets/papers/dramko22dire.pdf (K; yıl ve cilt kaynaklar arasında tutarsız: 2022 yazar kopyası, DBLP'ye göre 2023, 32(2))
30. J. Patrick-Evans, L. Cavallaro, J. Kinder. Probabilistic Naming of Functions in Stripped Binaries. ACSAC 2020, s. 373–385. DOI 10.1145/3427228.3427265. https://acsac.org/2020/program/final/s207.html (D)
31. J. Patrick-Evans, M. Dannehl, J. Kinder. XFL: Naming Functions in Binaries with Extreme Multi-label Learning. IEEE S&P 2023, s. 2375–2390. DOI 10.1109/SP46215.2023.00096. https://arxiv.org/abs/2107.13404 (D)

**Doğruluk, disassembly ve ölçüm**

32. Z. Liu, S. Wang. How Far We Have Come: Testing Decompilation Correctness of C Decompilers. ISSTA 2020. DOI 10.1145/3395363.3397370. https://conf.researchr.org/details/issta-2020/issta-2020-papers/26/How-Far-We-Have-Come-Testing-Decompilation-Correctness-of-C-Decompilers (D)
33. L. Dramko, J. Lacomis, E. J. Schwartz, B. Vasilescu, C. Le Goues. A Taxonomy of C Decompiler Fidelity Issues. USENIX Security 2024, s. 379–396. https://www.usenix.org/conference/usenixsecurity24/presentation/dramko (D)
34. J. Kline, P. Kulkarni. A Framework for Assessing Decompiler Inference Accuracy of Source-Level Program Constructs. ICISSP 2023, s. 228–239. DOI 10.5220/0011872600003405. https://www.scitepress.org/DigitalLibrary/Link.aspx?doi=10.5220/0011872600003405 (D)
35. D. Andriesse, X. Chen, V. van der Veen, A. Slowinska, H. Bos. An In-Depth Analysis of Disassembly on Full-Scale x86/x64 Binaries. USENIX Security 2016, s. 583–600. https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/andriesse (D)
36. C. Pang, R. Yu, Y. Chen, E. Koskinen, G. Portokalidis, B. Mao, J. Xu. SoK: All You Ever Wanted to Know About x86/x64 Binary Disassembly But Were Afraid to Ask. IEEE S&P 2021, s. 833–851. https://arxiv.org/abs/2007.14266 (D)
37. A. Jia, M. Fan, W. Jin, X. Xu, Z. Zhou, Q. Tang, S. Nie, S. Wu, T. Liu. 1-to-1 or 1-to-n? Investigating the Effect of Function Inlining on Binary Similarity Analysis. ICSE 2023 dergi-öncelikli (journal-first) sunumu. https://arxiv.org/abs/2112.12928 (K: dergi künyesi, muhtemelen ACM TOSEM, doğrulanmadı)
38. A. Caliskan, F. Yamaguchi, E. Dauber, R. Harang, K. Rieck, R. Greenstadt, A. Narayanan. When Coding Style Survives Compilation: De-anonymizing Programmers from Executable Binaries. NDSS 2018. DOI 10.14722/ndss.2018.23304. https://arxiv.org/abs/1512.08546 (D)

**LLM bağlamı ve tarama**

39. H. Tan, Q. Luo, J. Li, Y. Zhang. LLM4Decompile: Decompiling Binary Code with Large Language Models. EMNLP 2024. https://arxiv.org/abs/2403.05286 (D)
40. D. Xie, Z. Zhang, N. Jiang, X. Xu, L. Tan, X. Zhang. ReSym: Harnessing LLMs to Recover Variable and Data Structure Symbols from Stripped Binaries. ACM CCS 2024, s. 4554–4568. https://www.cs.purdue.edu/homes/lintan/publications/resym-ccs24.pdf (D)
41. O. Abusabha, S. Hwang. The Evolution of Binary Decompilation in the Modern Era: A Taxonomy, Literature Review, and Future Perspectives. arXiv 2608.24955, 2026. https://arxiv.org/abs/2608.24955 (D)

**Tezler**

42. J. Kinder. Static Analysis of x86 Executables. Doktora tezi, TU Darmstadt, 2010. https://www.plai.ifi.lmu.de/publications/phdthesis-kinder.pdf (D)
43. E. J. Schwartz. Abstraction Recovery for Scalable Static Binary Analysis. Doktora tezi, Carnegie Mellon University, 2014. https://kilthub.cmu.edu/articles/thesis/Abstraction_Recovery_for_Scalable_Static_Binary_Analysis/6714434 (D)
44. D. A. Andriesse. Analyzing and Securing Binaries Through Static Disassembly. Doktora tezi, Vrije Universiteit Amsterdam, 2017. https://danielandriesse.com/theses/phd-thesis.pdf (D)
45. G. Balakrishnan. WYSINWYX: What You See Is Not What You eXecute. Doktora tezi, University of Wisconsin–Madison, 2007. https://mathgenealogy.org/id.php?id=166536 (K: yalnız künye)

**Ücretsiz kitaplar ve dersler**

46. A. Møller, M. I. Schwartzbach. Static Program Analysis. Aarhus Üniversitesi. https://cs.au.dk/~amoeller/spa/ (D)
47. T. Æ. Mogensen. Basics of Compiler Design, 2010 baskısı. DIKU. http://hjemmesider.diku.dk/~torbenm/Basics/ (D)
48. N. Wirth. Compiler Construction. ETH Zürich, yazar sayfası. https://people.inf.ethz.ch/wirth/CompilerConstruction/index.html (K: sayfada yazar adı ve lisans yazmıyor; yazarın kişisel ETH dizininde)
49. A. Sampson. CS 6120: Advanced Compilers, The Self-Guided Online Course. Cornell University. https://www.cs.cornell.edu/courses/cs6120/2020fa/self-guided/ (D)
50. D. Yurichev. Reverse Engineering for Beginners. https://beginners.re/ (D)

**Telifli kitaplar (yalnız künye)**

51. A. V. Aho, M. S. Lam, R. Sethi, J. D. Ullman. Compilers: Principles, Techniques, and Tools, 2. baskı. Pearson/Addison-Wesley. ISBN 978-0-321-48681-3. https://www.pearson.com/store/p/compilers-principles-techniques-and-tools/P100000772496/9780321486813 (K: yıl)
52. K. D. Cooper, L. Torczon. Engineering a Compiler, 3. baskı. Elsevier (Morgan Kaufmann), 2022. https://shop.elsevier.com/books/engineering-a-compiler/cooper/978-0-12-815412-0 (D)
53. S. S. Muchnick. Advanced Compiler Design and Implementation. Morgan Kaufmann, 1997. ISBN 1-55860-320-4. https://shop.elsevier.com/books/advanced-compiler-design-and-implementation/muchnick/978-0-08-049871-3 (K: bölüm adları doğrulanmadı)
54. A. W. Appel. Modern Compiler Implementation in C / ML / Java. Cambridge University Press, 1998. https://www.cs.princeton.edu/~appel/modern/ ; C sürümü: https://www.cambridge.org/us/universitypress/subjects/computer-science/programming-languages-and-applied-logic/modern-compiler-implementation-c (D)

---

### Ek: Bu taramada doğrulanamayan ya da açık kalanlar

- Landi 1992'nin sayfa numaraları ve DOI'si (ACM sayfası erişimi engelledi).
- WYSINWYX TOPLAS makalesinin cilt ve sayısı (yalnız DOI doğrulandı).
- Jia ve ark.'nın dergi künyesi (ICSE 2023 journal-first olarak doğrulandı).
- Dragon Book 2. baskının ilk basım yılı; Muchnick'in bölüm adları ve numaraları.
- Van Emmerik tezinin resmî depo kaydı; Balakrishnan tezinin tam metin bağlantısı.
- macOS'ta `assert`'ün fonksiyon adını string olarak gömdüğü, ObjC seçicilerinin metin olarak tutulduğu, Mach-O dinamik bağlama adları ve `.eh_frame`'in strip sonrası fonksiyon aralığı verdiği. Bunlar yaygın bilgidir ama bu belgede birincil kaynaktan doğrulanmadı.
- GCC klon sonek biçimleri.
- Derlemedeki bilgi kaybını bit cinsinden ölçen ya da isim kurtarmanın Bayes tavanını kestiren bir çalışma bulunamadı. Bu bir "yokluk kanıtı" değildir; daha geniş bir tarama (ör. "mutual information", "rate–distortion" ve "decompilation" birlikte) önerilir.
