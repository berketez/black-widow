# Etiketleme rehberi: isim, fonksiyonun amacını anlatıyor mu?

Karadul'un ölçütü "gevşek mod". İsim özgün adla aynı olmak zorunda değil. Okuyan, fonksiyonun amacını isimden yakın bir doğrulukla anlayabiliyorsa isim başarılıdır. Benzetme: seramik duvara "fayans duvar" demek doğru, "pencere" demek yanlış.

Her isim için fonksiyonun kaynak kodunu oku. Önce ana işini bir cümleyle belirle, sonra ismi şu dört gruptan birine koy:

| Etiket | Tanım |
|---|---|
| `tam` | Özgün adın kendisi; yalnız biçim farkı olabilir (alt çizgi, büyük/küçük harf, `_2` gibi çakışma eki). |
| `dogru_tarif` | Fiil ve nesne fonksiyonun ana işini doğru anlatıyor (eş anlamlı da olur). Okuyan, fonksiyonun ne yaptığını isimden tahmin edebilir. |
| `yalniz_alan` | İsim doğru alanı ya da nesneyi söylüyor ama ana işi söylemiyor: fiil yok, fiil yanlış, ya da isim fonksiyonun yalnız bir yan ayrıntısını anlatıyor. |
| `yanlis` | İsim ana işle ilgisiz ya da okuyanı yanıltıyor. Örnekler: tek bir string'den alınmış alakasız kelime, Ghidra değişken parçası (`else_pcvar`), ters eylem, başka bir kütüphane fonksiyonunun adı. |

## Karar kuralları
1. Ölçüt amaç. İsmin gerçek adla harf benzerliği tek başına bir şey kanıtlamaz.
2. `_2`, `_3` gibi çakışma eklerini yok say.
3. Fiili olmayan, yalnız nesne adı olan bir isim (ör. `available_columns`) en fazla `yalniz_alan` olur. Tek istisna: nesne adı amacı zaten tam olarak söylüyorsa (ör. bir getter).
4. Fonksiyon bir işin hazırlık ya da yardımcı adımıysa ama isim işin kendisini söylüyorsa (ör. bir şeyi hazırlayan fonksiyona "yap" denmesi): `yalniz_alan`.
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
| `config_load_file` | `config` | `yalniz_alan` | nesne doğru, fiil yok |
| `window_resize` | `window_size` | `yalniz_alan` | getter sanılır, yeniden boyutlandırma söylenmiyor |
| `config_load_file` | `parse_error` | `yanlis` | yalnız hata mesajından |
| `session_destroy` | `session_create` | `yanlis` | ters eylem |
| `list_sort` | `qsort` | `yanlis` | kütüphane adı, yanıltır |
| `List_draw` | `List_display` | `dogru_tarif` | modül doğru, rol asıl işi anlatıyor (kural 7) |
| `Widget_onKey` | `Widget_handle` | `yalniz_alan` | modül doğru, rol genel fiil (kural 7) |
