# OL10A — ön kayıt (ölçümden önce; 2026-11-23 20:3x)

Kaynak: `olcek/OL10_TASARIM.md` §7.1 "Ön kayıt". Öngörü metinleri ve eşikler oradan aynen alındı; bu commit'ten sonra değişmez. Tutmayan beklenti silinmez.

## Öngörüler

- **H-A1 (Ollama dilimi, gösteri çalışma alanı):** sınıf `KENDI` 1 406, `BILINMIYOR` 2 619, `BAGIMLILIK` 594, `STANDART` 8 541, `TASLAK` 399; basamak B1 36 (+ giriş taslağı `entry`), B2 1 373, B3 1 236, B4a 547, B4b 836, B5 591, B6 398. Fark çıkarsa kural metniyle hangisinin uyuştuğu yazılır (bu sayılar tasarım turunun kuru sayımıdır: `OL10_TASARIM.md` Ek B-1).
- **H-A2 (belirlenimcilik):** S8 tabanının 8 çalışma alanı + gösteri: 20 permütasyonda seçim sha256'sı değişmez (9 / 9). S8 tabanı ↔ A/A tekrarı (`s8_taban_b6aceb9` ↔ `s8_taban_b6aceb9_AA`) seçim sha256'sı aynı (8 / 8): çağıran sırası farkı seçimi etkilemez.
- **H-A3 (xref türetme):** 9 çalışma alanında türetilen `function_xrefs` dökülenle JSON-eşit (`called_by` sıra-normal karşılaştırılır; tabanlar P16e'den önce üretildi); `statistics.total_functions` ve `total_strings_with_xrefs` eşit. Eşit olmayan her fonksiyon alan türüyle sayılır.
- **H-A4 (C ikilileri, S8; kural adlı olacak fonksiyonu öne alıyor mu):** `ust_sinir` = bütün fonksiyonların yarısı iken, tam kipte ad verilen fonksiyonların (taban `naming_map.json` `global`, `FUN_` anahtarları) ≥ %60'ı seçili kümededir (rastgele seçimde beklenen %50). Dayanağı zayıf bir öngörüdür (tek dayanak: gösteride 17 adın 10'u B3'te); sonuç ne çıkarsa kayda geçer. `ust_sinir = 0` iken C ikilisinde seçili küme bütün fonksiyonlardır (`STANDART` sınıfı yok): bu bir testtir, öngörü değil.
- **H-A5 (hedef seti, keşif, K0):** terminal-notifier'da 32 ObjC yöntem adresinin 32'si `KENDI`; docker-cli'de Go sınıf dağılımı raporlanır (ilk ölçüm, öngörü yok).
- **H-A6 (SINAMA; dondurma commit'inden sonra bir kez):** docker-compose, iTerm2, llama-server K0 sınıf sayımı raporlanır. Öngörü: docker-compose'da `STANDART` payı ≥ %50 (dayanak: Go adlarının %72,3–%93,6'sı kitaplık, `ustveri/BULGULAR.md` satır 374).
- **H-A7 (süre, kaba sınır; yük altında):** `sec` gösteri girdisinde (13 160 fonksiyon) ≤ 5 sn; 163 141 fonksiyonluk sentetik girdide ≤ 60 sn.

## Ölçüm tanımları (uygulayanın; öngörüleri değiştirmez)

- **Seçim sha256'sı:** `sec` çıktısındaki sıralı listenin her öğesi için `"<adres onaltılık, küçük harf, 0x'siz> <basamak> <sınıf>"` satırları `\n` ile birleştirilir, UTF-8 baytlarının sha256'sı. Sınırlar (kesim) uygulanmadan önceki tam listenin sha256'sı raporlanır.
- **Permütasyon (H-A2):** fonksiyon listesi, dizgi listesi ve dizgi başına başvuran listesi, çağrı grafiği düğüm sırası ve düğüm başına çağıran / çağrılan listeleri `random.Random(tohum)` ile karıştırılır (tohum 0 … 19); girdi karıştırılmış belgelerden yeniden kurulur.
- **H-A3 karşılaştırması:** belge JSON olarak ayrıştırılıp karşılaştırılır (sözlük anahtar sırası sayılmaz; liste sırası sayılır). `called_by` S8 tabanında ve gösteride (ikisi de P16e'den önce üretildi) iki biçimde raporlanır: ham ve `(adres, ad)` ile sıralanmış (sıra-normal). Hüküm sıra-normal karşılaştırmayla verilir. Alan türleri: `name`, `strings_used` (küme farkı / yalnız sıra farkı / yalnız `value` farkı ayrı), `functions_called`, `called_by`, anahtar kümesi.
- **H-A4:** birincil kesim `ust_sinir = ⌊P / 2⌋`, P = program fonksiyonu sayısı (taslak ve dış fonksiyon hariç). Gerekçe: `FUN_` anahtarlı adların hepsi program fonksiyonudur; "rastgele seçimde beklenen %50" ancak aynı nüfusun yarısı seçilince geçerlidir. Taslaklar dahil `⌊N / 2⌋` (N = `ghidra_functions.json`'daki bütün fonksiyonlar) ikincil satır olarak ayrıca yazılır (C ikilisinde taslaklar B6'da sonda olduğu için o kesim öngörüyü kolaylaştırır; hüküm birincilden verilir). Pay: `naming_map.json` `global`'deki `FUN_` anahtarlarından Ghidra program fonksiyonuna eşlenenlerin seçili kümede olanları; payda eşlenenlerin hepsi; ikilileri toplayan oran ve ikili başına oran ayrı yazılır (hüküm toplam orandan).
- **H-A5 / H-A6:** K0 sayımı Ghidra'sız: `goruntu.ac` → `go_pclntab.oku` / `objc.oku`; sınıf haritası `tembel_girdi`'nin eşlemesiyle (`TASLAK` K0'da yoktur: Ghidra fonksiyon listesi gerekir). Sınıf payı üst veride adı olan fonksiyonlar üstündendir.
- **Belirsiz kural noktalarında uygulanan okuma** (kural metni → kod; ölçümden önce yazıldı):
  1. Genişleme `STANDART` ve `TASLAK` fonksiyona girmez ve onlardan geçmez; E üyesi `STANDART` / `TASLAK` olsa da seçilir (sınıf istisnası) ama genişleme ondan da ilerlemez (metin "onlardan geçmez" diyor; Ek B-1'in betiği E üyelerinden sınıfa bakmadan ilerliyordu. Ollama'da E = {`main.main` (`KENDI`), `entry` taslağı}; taslaktan ilerleme `STANDART` çalışma zamanına girmeyeceği için iki okuma aynı B1'i verir).
  2. B1'in 256 sınırı, B0'da sayılmamış B1 adayları (derinlik, adres) sırasıyla dizildikten sonra uygulanır.
  3. B0'da fonksiyon listesinde olmayan istek adresi seçilmez, `istek_bulunamayan` olarak sayılır; yinelenen istek ilk konumunda kalır.
  4. "Ana modül bulunamadı" yalnız Go üst verisi okunduysa (en az bir Go fonksiyonu bir Ghidra fonksiyonuna eşlendiyse) ve `ana_modul_bul` `None` döndüyse geçerlidir.
  5. `kanıt` yalnız programın fonksiyonları için sıralama anahtarıdır; `TASLAK` fonksiyonun kanıtı da hesaplanır ama B6'da anahtar yalnız adrestir.
