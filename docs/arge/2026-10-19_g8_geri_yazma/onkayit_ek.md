# G8 ek koşullar: ön kayıt

- **Yazıldığı an:** 2026-10-19 12:55 (+0300). Yeni koşulların hiçbiri koşulmadı, hiçbir yeni fonksiyon decompile edilmedi, hiçbir yeni sonuç ölçütü görülmedi.
- **Bağlam:** G8 deneyi (`onkayit.md`, `rapor.md`; commit 6dc79bd) bir üst sınır ölçtü. Ana oturum (2026-10-19) üç ek koşul istedi: K1 "Karadul bugün", K2 "void *", K3 `struct client` tekrarı.
- **Değişmeyenler:**
  - Ölçütler: `olcut.py` (SHA-256 `67afd3dd…eede2005c`).
  - Eşli analiz ve "anlamlı kazanç" tanımı: `ozet.py`'deki işlevler (SHA-256 `981caaa0…4e194bf182`). Bootstrap tohumu `18419053266058711754`, 10 000 yeniden örnekleme, göreli eşik %25.
  - Decompile ayarları: `DecompileOptions()`, 30 sn, ısınma, iki koşu.
  - Ghidra 12.1.2 ve taban projesi `workspaces/2026-10-19_g8/projeler/taban`. Her koşul bu projenin ayrı bir kopyasında koşulur.
- **Künye:** depo HEAD `4325a60`. Karadul çıktısı `workspaces/olcum_mac/runs/taban-v2-62ad154/tmux/` (Karadul 62ad154, aynı strip'li ikili, sha256 `10fa0411…c9997b7`).
- **Değişiklik kuralı:** Bu belge ölçümden sonra değiştirilmez. Sapmalar `onkayit_ek_notlari.md`'ye yazılır.

## 0. Yazmadan önce bakılanlar (şeffaflık)

Bu belge yazılmadan önce Karadul çıktısının biçimine bakıldı ve şu bulundu. Hedeflerin decompile sonucuna bakılmadı.

- **İsim.** `out/naming_map.json`'da 1369 eşleme var (c_namer 1145, imza DB 224). Hedeflerin 10/20'sine ad verilmiş.
- **Tip.** Karadul'un tip aşaması (`reconstructed/typed/`) Ghidra C metninde `undefined4` → `int32_t`, `undefined8` → `uint64_t` gibi düz değiştirmeler yapıyor.
  - Son çıktıdaki imzalar (`out/src/src/**`) Karadul'un parametre adlarını ve bu tipleri taşıyor.
  - `struct_recovered/struct_recovery.json` yalnız Ghidra'nın zaten bildiği 45 SDK/Mach-O yapısını zenginleştiriyor.
- **Yapı.**
  - `types.h`'de 1398 `recovered_struct_NNN` var.
  - **Hiçbiri hiçbir fonksiyonun imzasında ya da gövdesinde kullanılmıyor.** Bütün `.c` çıktılarında 0 dosyada geçiyor.
  - Yapıların "Sources" alanında 371 yapı `if` adlı sahte bir kaynağı listeliyor. Bu, Karadul'un fonksiyon tanımı düzenli ifadesinin `if (` satırlarını tanım sanmasından geliyor.
  - Hedeflerin 10/20'si en az bir yapının kaynak listesinde geçiyor.
- **Yapı ile değişken bağı.** `CTypeRecoverer` alan erişimlerini **değişken adına göre, bütün dosyalar boyunca** birleştiriyor; anahtar fonksiyonla sınırlanmıyor. Hangi yapının hangi değişkenden üretildiği çıktıya yazılmıyor.
  - Bu bağ, Karadul'un kendi işlevleriyle (`_parse_c_file_worker`, `_merge_parse_result`, `_synthesize_structs`; karadul koduna dokunmadan) `reconstructed/merged/` girdisi üzerinde yeniden üretilebiliyor.
  - Sınama: 1398 yapının 1391'i boyut, alan ofsetleri ve kaynak listesiyle birebir yeniden üretildi.

## 1. Koşullar

Her koşulda 20 hedefe ve 49 çağırana aynı ayarlarla decompile ve ölçüm uygulanır. Hedefler ve çağıranlar G8'in `secim.json`'ındakiler; K3'te bunlar yeniden seçilir.

### K1 "Karadul bugün" (yalnız Karadul'un açık çıktısı)

Her hedef için yalnız Karadul'un çıktısında açıkça bulunan bilgi yazılır.

1. **Ad.** `naming_map.json` `mappings["FUN_<adres>"].new_name` varsa `setName` uygulanır.
2. **Prototip.**
   - Kaynak: Karadul'un son çıktısında bu adresin dosyasındaki imza satırı. Dosya `out/src/src/**/*.c` altında `// Address:  <adres>` başlığıyla bulunur. Dönüş tipi, parametre tipleri ve parametre adları yorumlar (`/* was: … */`) atılarak alınır.
   - Ayrıştırma: Ghidra'nın C ayrıştırıcısıyla. Tip adları şu sırayla çözülür:
     1. Karadul'un `types.h` başındaki tanımlar (`undefined1..8`, `code`, `addr`, `uaddr`)
     2. `stdint`/`stddef`/`stdbool` tanımları
     3. Ghidra'nın yerleşik adları (`uint`, `ulong`, `byte` vb.)
     4. programda zaten var olan tipler
     5. bunlarda olmayan bir yapı adı içi boş yer tutucu olur
   - **Karadul'un bilgisi yoksa yazılmaz.** İmza, C0'da Ghidra'nın verdiği imzayla parametre adı ve tip yazımı bakımından aynıysa prototip yazılmaz. Ayrıştırılamayan imza da yazılmaz; ikisi de ayrıca sayılır.
   - Uygulama: `ApplyFunctionSignatureCmd`, G8'deki ayarlarla.
3. **Yapı.** Karadul hiçbir yapıyı bir fonksiyona ya da parametreye bağlamıyor (§0), bu yüzden K1'de yapı yazılmaz. Kapsam olarak "0 bağlı yapı" raporlanır.

**Sayılacak kapsam:** ad verilen hedef sayısı; prototip yazılan hedef sayısı (parametre adı değişen ve tip yazımı değişen ayrı ayrı); ayrıştırma hatası.

### K1y "Karadul'un yapısı bağlansaydı" (ek)

K1'e ek olarak, her hedefin **ilk parametresine** Karadul'un o değişken için ürettiği yapı bağlanır.

- **Bağlama kuralı.**
  1. Hedefin `reconstructed/merged/` dosyasındaki ilk parametre adı V alınır.
  2. Karadul'un sentez işlevleri yeniden koşulur.
  3. V anahtarından bir yapı çıkıyorsa, onunla birebir aynı olan (boyut + alan ofsetleri + kaynak listesi) `types.h` yapısı bağlanır.
  4. Yapı yoksa ya da birebir eşleşme yoksa bağlanmaz.
- **Ghidra'ya yazım.** Yapı, Karadul'un ofset ve tipleriyle `StructureDataType` olarak kurulur; dolgu alanları `char[n]` olur. Bir alan öncekiyle çakışıyorsa yerleştirilmez, "yerleştirilemeyen alan" olarak sayılır. Hedefin K1 prototipindeki (yoksa C0 imzasındaki) ilk parametre tipi `<yapı> *` yapılır.
- Bağlanabilen hedef yoksa K1y koşulmaz ve bu raporlanır.

### Karadul yerleşiminin doğruluğu (decompile'dan bağımsız ölçüm)

**Gerçek yerleşim.** G8'de DWARF'la doğrulanan `struct window_pane` (1760 bayt) yaprak alanlara açılır:
- Değerle gömülü yapı ve birlikler özyinelemeli olarak açılır.
- Sayıl dizilerin her elemanı bir yapraktır.

**Karadul'un bir alanı** (dolgu hariç; ofset o, boyut s) üç sınıftan birine girer:
- **doğru:** o'da başlayan ve boyutu s olan bir yaprak var.
- **ofset doğru, boyut yanlış:** o'da başlayan bir yaprak var ama boyutu farklı.
- **yanlış:** o bir yaprağın başlangıcı değil ya da yapının dışında.

**Raporlanacaklar:**
- K1y'de bağlanan her yapı için (aynı yapı birden çok hedefe bağlanırsa bir kez sayılır) üç sınıfın sayısı, toplam boyut ve 1760 ile kıyası.
- Hedeflerden en az birini kaynak listesinde taşıyan bütün yapılar için aynı sayılar, tanımlayıcı olarak. Bu yapıların bir kısmı başka değişkenlerden üretildiği için bu sayı yalnız bağlam verir.

### K2 "void *"

C2'nin aynısıdır (gerçek ad + kaynaktan gerçek prototip), tek farkla: **yerleşimi bilinmeyen yapıya giden her işaretçi `void`'e giden işaretçi olur.**
- İşaretçi derinliği korunur: `struct X *` → `void *`, `struct X **` → `void **`.
- Kural, prototiplerde geçen fonksiyon işaretçisi tiplerinin içinde de uygulanır.
- Tabanda zaten bulunan tam yapılar (`timeval`, `termios`) yerleşimi bilinen sayılır ve değişmez.
- Değerle geçirilen yapı (varsa) C2'deki gibi içi boş yer tutucu kalır.

### K3 `struct client` tekrarı

- **Seçim.** G8 ön kaydının §3 kuralları aynen uygulanır, yalnız yapı `client`:
  - (a)-(f) koşulları ve aynı tohum (`8691180542497554626`); karışık sıradaki ilk 20 hedef.
  - Doğrudan çağıranlar taban programdan.
  - Isınma: ölçülen kümede olmayan, adrese göre ilk 5 `FUN_`.
- **Koşullar.**
  - **K3-C0:** taban.
  - **K3-C3:** C3'ün eşdeğeri. Gerçek ad + gerçek prototip + `struct client` ve değerle gömdüğü yapılar tam yerleşimle; yalnız işaretçiyle erişilen yapılar boş yer tutucu.
- **Yerleşim doğrulaması (ön koşul).** G8 ile aynı:
  1. `client` kapanışındaki her adlı yapının boyutu ve adlı alan ofsetleri, `-g` derlemenin DWARF'ıyla eşit olmalı.
  2. İkilide `sizeof(struct client)` kanıtı aranır (`xcalloc` argümanı) ve raporlanır.
  3. Hedeflerin ofset kümeleri şişe ile kendi derlememiz arasında karşılaştırılır.
  
  (1) tutmazsa K3-C3 koşulmaz ve bu raporlanır.

## 2. Hipotezler

- **H-K1.**
  - Karadul'un bugünkü bilgisi C3 tavanının küçük bir kısmını verir: K1 ↔ C0'da 5 birincil ölçütün en çok 1'inde anlamlı kazanç.
  - A sıfır kalır, çünkü yapı yok.
  - D'de düşüş Karadul'un parametre adı kapsamı kadardır.
  - U'daki değişim yön belirsizdir: `undefined8` yerine `uint64_t` U'yu düşürür ama işaretçi çıkarımını engelleyip dönüşüm ekleyebilir.
- **H-K1y.** Bağlanan yapılar sözdizimsel ölçütleri (A, P1) iyileştirebilir, ama Karadul yapı alanlarının yarıdan azı "doğru" sınıfındadır. Sözdizimsel kazanç burada yanlış alan adıyla gelir.
- **H-K2.** C2'deki tip dönüşümü artışı opak yapı işaretçisinden gelir. K2'de C/100'ün havuz oranı C0'dan büyük değildir; C2'deki +%27 kaybolur. P1 C0'dan anlamlı farklı değildir.
- **H-K3.** Tek yapı bulgusu `client`'ta tekrarlanır: K3-C3 ↔ K3-C0'da 5 birincil ölçütün en az 2'sinde anlamlı kazanç.

## 3. Analiz ve karar okuması

**Karşılaştırmalar** (her biri hedefler ve çağıranlar için ayrı; `ozet.py`'deki `olcut_ozeti` ve `tanimlayici` aynen kullanılır):
- K1 ↔ C0
- K1y ↔ C0
- K2 ↔ C0
- K2 ↔ C2 (void * etkisini opak işaretçiden ayırır)
- K3-C3 ↔ K3-C0

C0 ve C2 ölçümleri G8'in `olcum_C0.json` ve `olcum_C2.json` dosyalarından gelir; bu ölçümler belirlenimcidir. Belirlenimciliği sınamak için C0 bu turda yeniden decompile edilir: metinler `olcum_C0.json`'la birebir aynı olmalı. Süre karşılaştırmaları aynı süreç içinde ölçülen C0 tekrarıyla yapılır.

**Tavan payı.** Her birincil ölçüt için havuzlanmış oranla (K1 − C0) / (C3 − C0) hesaplanır ve tanımlayıcı olarak raporlanır.

**Karar okuması:**

| Sonuç | Okuma |
|---|---|
| K1 ↔ C0: en az 2/5 anlamlı kazanç | Karadul'un bugünkü bilgisiyle de geri yazma kazancı var; G14-G15 öne alınabilir |
| K1 ↔ C0: 2/5'ten az | Kazanç bugün erişilebilir değil. Önce tip ve yapı kurtarma gelir (G16-G17, G19); geri yazma hattı yerinde kalır, öne alınmaz |
| K1y'de anlamlı sözdizimsel kazanç var ve alan doğruluğu < %50 | Sözdizimsel ölçütler yanlış yerleşimi ödüllendiriyor. G14-G15'in kapısına alan doğruluğu (DWARF'a karşı) eklenmeli |
| K2: C/100 havuz oranı C0'dan büyük değil | C2'deki artış opak yapı işaretçisinden. Ürün kuralı: yerleşimi bilinmeyen yapıya `void *` |
| K2: C/100 havuz oranı C0'dan büyük | Artışın kaynağı başka; kural yeniden düşünülür |
| K3: en az 2/5 anlamlı kazanç | Tek yapı bulgusu `client`'ta tekrarlandı |
| K3: 2/5'ten az | Bulgu `window_pane`'e özgü olabilir; genellenmez |

**Eksik veri.** G8'deki kuralla aynı: 30 sn'de bitmeyen decompile o koşulun eşli analizinden çıkar ve sayılır.

## 4. Bilinen sınırlamalar

- K1, Karadul'un tek bir koşusunu (62ad154, taban v2) yansıtır.
- K1y'deki bağ, Karadul'un yapmadığı bir işlemdir. Karadul'un kendi anahtarıyla yeniden üretilir ama bir "bugün" ölçümü değildir, "bağlansaydı" ölçümüdür.
- K3 de tek program ve tek derlemedir. İki yapı (`window_pane`, `client`) genelleme için yine azdır.
