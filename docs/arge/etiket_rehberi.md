# Etiketleme rehberi: isim, fonksiyonun amacını anlatıyor mu?

- **Sürüm:** 2 (2026-10-19)
- **Değişiklik notu (2026-10-19):**
  - Yanlış fiil artık `yanlis` sayılıyor; sürüm 1'de `yalniz_alan` grubundaydı. Kapsam: getter/setter, tahsis/serbest bırakma ve hazırla/uygula karışmaları. Karar Berke'nin (plan v2 §9 madde 1; Onuncu Adam İ5).
  - Bu yüzden değişenler: tanım tablosunda `yalniz_alan` ve `yanlis` satırları, kural 3'e eklenen cümle, kural 4, `window_size` örneği. İki yeni örnek eklendi.
  - Değerlendirme sırası yazıldı: önce amaç cümlesi, sonra aday.
  - Kör pakette yalnız fonksiyonun kendi adı karartılır; başka fonksiyonların adları gövdelerde görünür kalır (ana oturum kararı, 2026-10-19).
  - Kural 7 değişmedi.
- **Sürüm 1:** 2026-10-15 (1bc05ec). Kural 7, 2026-10-17'de eklendi (52a34dc).
- **Yordam:** `docs/arge/etiket_protokolu_v2.md`. Sürüm 1 ile verilmiş etiketler sürüm 2 sayılarıyla birleştirilmez.

Karadul'un ölçütü "gevşek mod". İsim özgün adla aynı olmak zorunda değil. Okuyan, fonksiyonun amacını isimden yakın bir doğrulukla anlayabiliyorsa isim başarılıdır. Benzetme: seramik duvara "fayans duvar" demek doğru, "pencere" demek yanlış.

## Değerlendirme sırası

1. **Amaç cümlesi.** Fonksiyonun kaynak kodunu oku. Ana işini tek cümleyle yaz. Bu aşamada adayı görmezsin.
2. **Aday.** Bütün amaç cümlelerini teslim ettikten sonra adayları alırsın. Her adayı kendi amaç cümlenle karşılaştır ve aşağıdaki dört gruptan birine koy. Amaç cümlesi bu aşamada değiştirilmez.

Kör pakette:
- Fonksiyonun kendi adı gövdede `FONKSIYON` olarak geçer. Kaynak dosyanın adı fonksiyonun adıyla aynıysa dosya adında da `FONKSIYON` görünür (ör. `FONKSIYON.c`).
- Gizlenen adı tahmin etmeye çalışma. Kodu tanıdığını düşünsen bile ezberindeki adı kullanma.
- Gövdelerde başka fonksiyonların adları geçer; hangi gövdenin hangi ada ait olduğunu tahmin etmeye çalışma.
- Özgün adı bilmediğin için `tam` etiketini kullanma. Aday amacı doğru anlatıyorsa `dogru_tarif` yaz. Özgün adla aynı olan adaylara `tam` etiketini puanlayıcı verir; bunun için anahtardaki otomatik tam eşleşmeye bakar.

Gerçek adın gösterildiği pakette (cömertlik deneyi) aday gerçek adın kendisiyse `tam` yaz.

## Etiketler

| Etiket | Tanım |
|---|---|
| `tam` | Özgün adın kendisi; yalnız biçim farkı olabilir (alt çizgi, büyük/küçük harf, `_2` gibi çakışma eki). |
| `dogru_tarif` | Fiil ve nesne fonksiyonun ana işini doğru anlatıyor (eş anlamlı da olur). Okuyan, fonksiyonun ne yaptığını isimden tahmin edebilir. |
| `yalniz_alan` | İsim doğru alanı ya da nesneyi söylüyor ama ana işi söylemiyor. Ya fiil yok ya da isim fonksiyonun yalnız bir yan ayrıntısını anlatıyor. Fiil varsa ama yanlışsa isim bu gruba değil `yanlis` grubuna girer (kural 4). |
| `yanlis` | İsim ana işle ilgisiz ya da okuyanı yanıltıyor. Yanlış fiil de bu gruptadır (kural 4). Örnekler: tek bir string'den alınmış alakasız kelime, Ghidra değişken parçası (`else_pcvar`), ters eylem, getter/setter ya da tahsis/serbest bırakma karışması, başka bir kütüphane fonksiyonunun adı. |

## Karar kuralları
1. Ölçüt amaç. İsmin gerçek adla harf benzerliği tek başına bir şey kanıtlamaz.
2. `_2`, `_3` gibi çakışma eklerini yok say.
3. Fiili olmayan, yalnız nesne adı olan bir isim (ör. `available_columns`) en fazla `yalniz_alan` olur. Tek istisna: nesne adı amacı zaten tam olarak söylüyorsa (ör. bir getter). Nesne adı bir değerin getter'ı gibi okunuyor ama fonksiyon o değeri değiştiriyorsa isim örtük bir yanlış fiil taşır: `yanlis` (kural 4). Örnek: boyutu değiştiren fonksiyona `window_size`.
4. **Yanlış fiil `yanlis` olur** (sürüm 2). Okuyanı yanıltan fiil karışmaları:
   - **getter/setter:** değer döndüren fonksiyona değeri değiştiren ad verilmesi ya da tersi;
   - **tahsis/serbest bırakma:** `alloc` ile `free`, `create` ile `destroy` karışması;
   - **hazırla/uygula:** fonksiyon bir işin hazırlık ya da yardımcı adımıyken isim işin kendisini söylüyor (ör. bir şeyi hazırlayan fonksiyona "yap" denmesi) ya da tersi.

   Genel fiiller (`handle`, `process`, `do`, `run`) yanlış fiil sayılmaz; modül + rol isimlerinde kural 7 geçerlidir. Fiil fonksiyonun gerçekten yaptığı ama ana olmayan bir işi söylüyorsa isim yan ayrıntıdır: `yalniz_alan`.
5. Kütüphane fonksiyonu adıyla çakışan isim (ör. sinyal yöneticisine `sigaction`) okuyanı yanıltır: `yanlis`.
6. Tek, genel bir kelime (ör. `missing`, `small`, `line`) neredeyse her zaman `yanlis` olur.
7. **Modül + rol isimleri** (ör. veri tablosu yuvasından gelen `Modul_rol`; Berke kararı, 2026-10-17):
   - Rol, fonksiyonun asıl işiyse `dogru_tarif` olur. Örnek: yuvası "çiz" ve fonksiyon gerçekten çiziyor.
   - Rol genel bir fiilse `yalniz_alan` olur: `handle`, `helper`, `process`, `do`, `run`.
   - Modül yanlışsa isim `yanlis` olur.

## Örnekler (değerlendirme kümesinden değildir)
| Gerçek ad | Verilen isim | Etiket | Neden |
|---|---|---|---|
| `buffer_append` | `buffer_append` | `tam` | aynı ad |
| `config_load_file` | `read_config` | `dogru_tarif` | yapılandırmayı dosyadan okuyor |
| `session_destroy` | `session_free` | `dogru_tarif` | eş anlamlı fiil |
| `config_load_file` | `config` | `yalniz_alan` | nesne doğru, fiil yok (kural 3) |
| `window_resize` | `window_size` | `yanlis` | getter sanılır, fonksiyon ise boyutu değiştiriyor: getter/setter karışması (kural 3 ve 4; sürüm 1'de `yalniz_alan`) |
| `cache_entry_free` | `cache_entry_alloc` | `yanlis` | tahsis/serbest bırakma karışması (kural 4) |
| `query_prepare` | `query_execute` | `yanlis` | hazırlayan fonksiyona "uygula" denmiş: hazırla/uygula karışması (kural 4) |
| `config_load_file` | `parse_error` | `yanlis` | yalnız hata mesajından |
| `session_destroy` | `session_create` | `yanlis` | ters eylem |
| `list_sort` | `qsort` | `yanlis` | kütüphane adı, yanıltır |
| `List_draw` | `List_display` | `dogru_tarif` | modül doğru, rol asıl işi anlatıyor (kural 7) |
| `Widget_onKey` | `Widget_handle` | `yalniz_alan` | modül doğru, rol genel fiil (kural 7) |
