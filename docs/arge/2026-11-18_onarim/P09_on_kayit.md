# P09 — ön kayıt (tip ve yapı kurtarma)

Bu belge kod değişmeden ÖNCE yazıldı ve commit'lendi. Taban sayıları ölçüm betiğinin değişmemiş kodla (ddf8b19; kodun dondurulmuş kopyası ölçülen ağaç olarak kullanılır) ürettiği değerlerdir ve `P09.md`'ye yazılır; "sonra" sayıları her kalemden sonra aynı betikle, aynı girdilerle alınır. Bir beklenti tutmazsa "tutmadı" yazılır, eşik sonradan gevşetilmez.

Ön deneme (2 ikili, taban kodu) bilgisi: hizalanmış parametrelerde tip kurtarmanın öntanım dışı değişimi neredeyse yok (tmux'ta 400 "çıkarım" değişiminin hemen hepsi `undefined8 *` → `uint64_t *` öntanımıydı; öntanım sınıflaması bu yüzden `undefinedN` sözcüğü bazında yapılır). TIP-06'nın asıl alanı yerel değişkenler; onlar için DWARF eşlemesi yok, aşağıdaki öz-tutarlılık sayacı kullanılır.

## 1. Araç ve girdiler
- Betik: `scripts/measurement/p09_olc.py kos` (tanımlar betiğin başında). Kayıtlı ürün koşusunun `reconstructed/merged/` dizinini ölçülen ağacın `CTypeRecoverer.recover`'ına, ardından çıktıyı XTRIDE adımına (`run_xtride_typing`) verir; Ghidra koşmaz.
- **Yeniden oynatma doğrulaması (koşul):** değişmemiş kodla yeniden oynatılan `typed/` (C dosyaları + `types.h`) kayıtlı `typed/` ile bayt bayt aynı olmalı. G setinde aynı değilse ölçüm geçersizdir.
- **G seti:** `~/karadul_olcum/runs/genel-tarama-2026-11-18` (14 ikili; 1.23.1 = e9d2d08 çıktısı; tip kodu bugünküyle aynı).
- **D seti:** `~/karadul_olcum/runs/urun-yeni2-f30ac9a` içinden T0b hizalama belgesi olan 22 ikili (`~/karadul_olcum/runs/t0b-1acba60/hizalama`; ikili sha256'sı hizalamadaki `ghidra_ikili_sha256` ile denetlenir) + `debian/redis-tools/redis-check-rdb` (TIP-06'nın `lolwutUnstableCommand` örneği; hizalaması yok). Bu koşu 1.22.1 kodunun çıktısıdır; `types.h` belirlenimsizlik onarımından (e9d2d08) önce olduğu için D'de doğrulama tam tutmayabilir; DWARF ölçüsü yeniden oynatmanın kendi önce/sonrasını karşılaştırır.
- Çıktı: `~/karadul_olcum/runs/onarim-2026-11-18/P09/{G,D}/<etiket>/ozet.json`.

## 2. Ölçüler
- **Yapı (TIP-07, ARAYUZ-18):** `types.h`'deki `recovered_struct` tanımı, koda bağlı olanı (adı bir `.c` dosyasının kodunda geçen), sabit `confidence: 0.80` satırı, üst üste binen alanlı yapı, aday dosyasındaki tanım (`typed/types_candidates.txt`).
- **Bildirim değişimi (TIP-06, TIP-11):** `merged/` → `typed/` arasında tipi değişen (fonksiyon, değişken). `ontanim` (tipteki her `undefinedN` sözcüğü `uint8_t/uint16_t/int32_t/uint64_t` öntanımına çevrilince yeni tip çıkıyor; `undefined8 *` → `uint64_t *` dahil; bu paket değiştirmiyor) ve `cikarim` (geri kalanı) ayrı. `cikarim` içinde: `double_yeni`, `genislik_bozan` (eski ve yeni tipin boyutu bilinir ve farklı), `somut_ezilen` (Ghidra'nın `undefined*` olmayan tipi işaretçi olmayan bir tiple değişti), `kanitsiz` (öz-tutarlılık, doğruluk ölçüsü DEĞİL: yeni tip `char *` / `void *` / `double` iken değişkenin KENDİ fonksiyonunun dizgi ve yorumu örtülmüş kodunda betikteki en basit kanıt deseni (`OZ_KANIT`) yok; kanıtı başka fonksiyondan ya da dizgiden gelen tip burada görünür).
- **"Ghidra'dan daha kötü tip" (kapı ölçüsü, D seti):** hizalanmış parametrelerde (`eslesme == "tam"`), tip değiştiğinde Karadul'un tipi DWARF'la çelişirken Ghidra'nınki çelişmiyorsa `kotulesen`; tersine `iyilesen`. Tür ekseni işaretçi / kayan / tamsayı; tamsayıda iki boyut biliniyorsa boyut. `undefined*` hüküm vermez (`bilgisiz`). Ayrı satır: `kotulesen_cikarim`, `iyilesen_cikarim` (öntanım değişimleri hariç).
- Parametre dışı yerel değişkenler için DWARF eşlemesi yok: yerellerde yalnız yukarıdaki örüntü sayaçları ve tek tek örnekler.

## 3. Beklentiler (kalem başına)
**Kalem 1 — bekletme (K-1).**
- `types.h`'deki `recovered_struct` sayısı = koda bağlı sayısı (G ve D). Bağlanmayanların hepsi `types_candidates.txt`'de; `types.h` + aday toplamı tabandaki `types.h` sayısına eşit.
- `confidence: 0.80` satırı 0 (her ikili).
- C dosyaları tabanla bayt bayt aynı (bağlama davranışı bu kalemde değişmiyor).
- Tutmadı sayılır: bağlanmamış tek bir yapı `types.h`'de kalırsa, ya da tek bir `.c` dosyası değişirse.

**Kalem 2 — TIP-07 onarımı (anahtar, ölçek, örtüşme).**
- Üst üste binen alanlı yapı 0 (G ve D; tabanda sayılır).
- Aday yapılar tek bir (fonksiyon, değişken)'den kurulur; aday dosyasında her yapının kaynağı tek fonksiyon.
- Ölçek: `uint64_t *p; *(int *)(p + 1)` → ofset 8 (birim testi; gerçek çıktıda kaynak satırla örnek denetimi).
- Bağlama: değişkenin bildirim tipi yapı işaretçisine çevrilirken erişim metni (`*(T *)(p + N)`) değişmiyorsa C anlamı değişir (tamsayı aritmetiği → işaretçi aritmetiği). Bu durumda bağlama yazılmaz. Beklenen: koda bağlı yapı sayısı tabandan büyük OLMAZ; bağlanan her yapıda değişkenin koddaki her geçişi yapı alanı erişimine çevrilmiş olur ya da hiç bağlama olmaz.
- Tutmadı: örtüşen alanlı yapı > 0, ya da bağlanan bir yapının değişkeni bağlamadan sonra kodda tamsayı aritmetiğiyle (`p + N`) kalırsa.

**Kalem 3 — TIP-06 / TIP-11 (anahtar `(fonksiyon, değişken)`, dizgi/yorum örtme, Ghidra somut tipini koruma).**
- `double_yeni` içinde dizgi sabitinden doğan değişim 0 (örnekler tek tek okunur); `redis-check-rdb` `lolwutUnstableCommand`'da `double sdsnewlen_ret_*` yok.
- `genislik_bozan` = 0 ve `somut_ezilen` = 0 (`cikarim` içinde; G ve D).
- `kanitsiz` G'de ve D'de tabana göre en az %50 düşer (kalan her örnek okunup nedeni yazılır: betiğin kanıt deseninin dar olması mı, kusur mu).
- DWARF (D): `kotulesen_cikarim` artmaz; `karadul_yanlis` artmaz; `iyilesen_cikarim` tabandan en çok tabanın yarısı kadar düşer (taban küçükse sayı yazılır).
- Tutmadı: yukarıdakilerden biri sağlanmazsa. İyileşme düşerse onarım "doğruyu da düşürdü" diye kaydedilir; eşik gevşetilmez.

**Kalem 4 — AD-10 (n-gram kanalı).**
- Veritabanı dizini yokken adım istatistiğe durum yazar (`ngram_naming_durum: veri_yok` + aranan yol); sessiz dönüş yok. Birim testiyle kilitlenir (koşulu kayıtlı çıktıda ölçülemez: ürün koşuları `--output-dir` ile çalıştı, kanal hiç koşmadı).
- Veritabanı varken yeniden adlandırma yalnız kodda (dizgi ve yorum değişmez), ad geçerlilik süzgecinden geçer ve fonksiyonda zaten kullanılan adla çakışmaz (birim testi).

## 4. Kapsam dışı (bilerek)
- `undefinedN` → `uintN_t`/`int32_t` öntanımı (`_UNDEFINED_DEFAULTS`) bu pakette değişmiyor; D'deki etkisi ayrıca raporlanır.
- Mühendislik yapı hattı (`engineering/struct_recovery.py`, TIP-04/05: P04a/P10), `c_project_builder.py` (P18), veri kökü (`data_root`, P15).
- `masum_kapi_esik.json`'a yazılmaz; öneri `P09.md`'de.
