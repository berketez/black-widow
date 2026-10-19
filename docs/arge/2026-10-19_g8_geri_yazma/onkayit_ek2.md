# G8 ek 2: ürün kuralı adayı, ön kayıt

- **Yazıldığı an:** 2026-10-19 13:12 (+0300). K4 ve K4' koşulmadı, hiçbir yeni decompile yapılmadı, hiçbir yeni sonuç ölçütü görülmedi.
- **Bağlam:** G8 ek koşullarında (`onkayit_ek.md`, `rapor.md` §10; commit d6c4bcf) yerleşimsiz işaretçi tipleri tip dönüşümünü artırdı: C2'de opak yapı işaretçisi +%27, K2'de `void *` +%70. Ana oturum (karar 3) ürün kuralı adayının ölçülmesini istedi.
- **Değişmeyenler:**
  - Ölçütler `olcut.py` (SHA-256 `67afd3dd…eede2005c`).
  - Eşli analiz ve "anlamlı kazanç" tanımı `ozet.py` (SHA-256 `981caaa0…4e194bf182`): tohum `18419053266058711754`, 10 000 yeniden örnekleme, göreli eşik %25.
  - Decompile ayarları, Ghidra 12.1.2 ve taban projesi.
  - Aynı 20 hedef ve 49 doğrudan çağıran (`secim.json`).
- **Künye:** depo HEAD `3d2365d`.
- **Değişiklik kuralı:** Bu belge ölçümden sonra değiştirilmez. Sapmalar `onkayit_ek2_notlari.md`'ye yazılır.

## 1. Hipotez

Yapının yerleşimi bilinmiyorsa, yalnız fonksiyon ve parametre adı yazmak (Ghidra'nın tiplerine dokunmadan) tip dönüşümünü artırmadan okunurluğu artırır. Yerleşimi bilinen yapı için tip de yazılırsa ("bilinen yerleşimde tip yaz, bilinmeyende yazma"), kazanç C3'e yakın olur ama C3'ten daha az dönüşüm üretir.

## 2. Koşullar

Her koşul taban projenin ayrı bir kopyasında koşulur. Yeniden analiz yapılmaz.

### K4: yalnız ad, Ghidra tipleri korunur

1. 20 hedefe `Function.setName` ile gerçek ad yazılır (C1 ile aynı).
2. **Parametre adları.**
   - Hedef, koşulun kendi kopyasında decompile edilir.
   - `HighFunction`'ın parametre sembolleri, kaynaktaki parametrelere ABI konumuyla eşlenir:
     - `x0`-`x7` / `w0`-`w7` yazmaçları → kaynak parametresi 0-7
     - yığın parametreleri ofset sırasıyla → 8, 9, …
   - Gerçek ad yalnız adı değiştirerek yazılır: `HighFunctionDBUtil.updateDBVariable(sembol, ad, null, SourceType.USER_DEFINED)`.
     - Bu, Ghidra arayüzündeki "parametreyi yeniden adlandır" yoludur.
     - Parametreleri decompiler'ın kendi tipleriyle veritabanına kaydeder: `commitParamsToDatabase(useDataTypes=true, ReturnCommitOption.NO_COMMIT, SourceType.ANALYSIS)`.
     - Dönüş tipini kaydetmez.
   - Kaynak parametre adları, G8'de C2/C3 için ayrıştırılan kaynak prototiplerinden alınır.
3. **Adlandırılmayanlar.** Konumu eşlenemeyen parametre (ör. kayan nokta yazmacı) ya da kaynakta karşılığı olmayan parametre adlandırılmaz; ayrıca sayılır.
4. **Değişmeyenler.** Parametre tipleri, dönüş tipi ve yerel değişkenler değiştirilmez.

### K4': K4 + yalnız yerleşimi bilinen yapı için tip

1. K4'teki her şey uygulanır.
2. Kaynak tipi `struct window_pane *` olan parametrelere, aynı `updateDBVariable` çağrısıyla ad ve `window_pane *` tipi birlikte yazılır.
3. Kaynak dönüş tipi `struct window_pane *` olan fonksiyonlara `Function.setReturnType` ile `window_pane *` dönüş tipi yazılır.
4. `window_pane` tipi C3'teki gibi kurulur: `window_pane` ve değerle gömdüğü yapılar tam yerleşimle; yalnız işaretçiyle erişilen yapılar boş yer tutucu.
5. Öbür parametre ve dönüş tipleri (öbür yapılara işaretçiler dahil) Ghidra'nın tipi olarak kalır.

### Isınma

Süreçte koşullardan önce taban proje açılır, bütün küme bir kez decompile edilir ve sonuçlar atılır. Sonra K4 ve K4' koşulur. Her koşulda G8'deki ısınma ve çift koşu düzeni aynen uygulanır.

## 3. Ölçütler ve yeni tanımlayıcı

Ölçütler ve "anlamlı kazanç" kuralı G8'deki gibidir (`ozet.py`).

**Fonksiyon başına ortalama göreli değişim** (ana oturumun kararı, tanımlayıcı):
- Her ölçüt için, taban oranı 0'dan büyük olan fonksiyonlarda `(sonra − önce) / önce` hesaplanır; bunların ortalaması alınır.
- Kullanılan fonksiyon sayısı yazılır.
- A'da taban 0 olduğundan bu değer tanımsızdır; yerine "sonra"daki fonksiyon başına ortalama oran verilir.

Bu değer havuzlanmış oranın yanında raporlanır; karar kuralını değiştirmez.

## 4. Karşılaştırmalar

- **K4 ↔ C0**, **K4 ↔ C2**, **K4 ↔ K2**
- **K4' ↔ C0**, **K4' ↔ C3**
- K4' ↔ K4 yalnız tanımlayıcı

C0, C2, C3 ve K2 ölçümleri önceki dosyalardan gelir (`olcum_C0/C2/C3/K2.json`); bunlar belirlenimci olarak doğrulandı.

## 5. Karar okuması

Okumalar hedefler üzerinde yapılır; çağıranlar ikincildir. "Havuz oranı" ifadesi, toplam sayının toplam satıra oranının 100 katıdır.

| Okuma | Koşul | Tutarsa |
|---|---|---|
| R1 | K4 ↔ C0'da C/100 havuz oranının göreli değişimi ≤ 0 | "Yalnız ad tip dönüşümünü artırmıyor" |
| R2a | K4'ün C/100 havuz oranı hem C2'ninkinden hem K2'ninkinden küçük | "Yerleşim yoksa yalnız ad, yerleşimsiz tip yazmaktan iyi" |
| R2b | K4'ün D/100 havuz oranı C2'ninkinden en çok 5,0 büyük (100 satırda) | "Ad kazancı aynı" |
| R3 | K4' ↔ C0'da 5 birincil ölçütün en az 2'sinde anlamlı kazanç, ve K4'ün C/100 havuz oranı ≤ C3'ünki | "Bilinen yerleşimde tip yaz, bilinmeyende yazma" kuralı, C3 düzeyinde kazancı daha az dönüşümle veriyor |

**Ürün kuralı önerisi:**
- R1, R2a ve R2b tutarsa: "Yerleşim yoksa yalnız ad yaz, tipe dokunma."
- R3 de tutarsa: "Yerleşimi doğrulanmış yapılar için tip de yaz."
- Tutmayan okuma, önerinin o parçasını düşürür. Sonuç olduğu gibi raporlanır.

## 6. Bilinen sınırlamalar

- Aynı tek program, tek yapı ve n = 20.
- Ad ve tip bilgisi kaynaktan geliyor, yani bu bir üst sınırdır.
- Parametreleri kaydetmek, çağıranlarda decompiler'ın prototip çıkarımını sabitler. Bu, ad yazmanın Ghidra'daki kaçınılmaz yan etkisidir ve ölçüme dahildir.
