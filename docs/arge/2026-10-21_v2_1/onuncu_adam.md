# Onuncu Adam: plan v2.1'e ve Berke'nin beş kararına itirazlar

- **Tarih:** 2026-10-21
- **Rol:** Zorunlu muhalif. Konsensüsün yanlış olduğunu varsayar; dengeli değerlendirme değildir.
- **Saldırılan konsensüs:** `docs/arge/2026-10-19_plan_v2_1.md` (0a392e7; "P") ve §8'deki beş karar. Dayanakları: `2026-10-19_g8_karar/karar_taslagi.md` ve plan v2 (`2026-10-17_plan_v2.md`; "V").
- **Yöntem:**
  - Belge ve kod salt okumayla incelendi; kod iddiaları `grep`/`sed` ile doğrulandı.
  - Küçük hesaplar (Ghidra, pytest, ölçüm koşusu yok): taban v2 `naming_by_strategy`; G8 yerleşiminde şans tabanı; G7 kümelerinde tip dağılımı; Debian coreutils 9.4 arm64 dbgsym'de (`~/karadul_olcum`) DWARF sayımı.
  - Codex: `gpt-6-astra`, `xhigh`, salt okuma, 451 sn, çıkış 0. Atıfları elle doğrulandı (§Codex).
- **Ham kayıt:** `workspaces/2026-10-21_v2_1/codex_onuncu_adam/` (depo dışı; hesap betikleri `hesap_betikleri/` altında).
- **İşaretler:**
  - **[kod]** depoda doğrulandı
  - **[belge]** depo belgesinde yazılı
  - **[hafıza]** hafızada, yeniden doğrulanmadı
  - **[hesap]** bu raporda yapılan hesap
  - **[doğrulanmadı]** kaynağından bakılmadı
  - **[tahmin]** gerekçeli kestirim

## Özet

1. **K0 fonksiyon adlarının hemen hepsini susturur (karar 2).** Adların %98,5'i (tmux) ve %100'ü (htop) tek kanaldan, `string_context`'ten geliyor. "Kanal başına kesinlik" fiilen tek bir sayı.
2. **Sıranın "→ isim" ayağını Faz 0 verisi desteklemiyor (karar 1).**
   - Tip kümesinden nesne adı, kâhin çapayla bile isim bekleyenlerin %1,6'sında doğru (%36,7 kesinlik).
   - KS-1 gerekçesiz G23'e kaydı.
   - Kapı 1 ya süs ya isim kurallarını erken donduruyor.
3. **K1 tip doğruluğunu değil, anonim küme saflığını ölçüyor (karar 3).**
   - Kural (a) neredeyse totolojik.
   - `void *` doğru birleştirmeyi cezalandırıyor, yanlışını ödüllendiriyor.
   - Kapsam alt sınırı yok.
   - Başarısızlık dalı doğrulama setinin ön kaydını çiğniyor.
4. **K1'in veri hattı yok; G16 tutmaz (karar 1, 3).** Debian dbgsym dwz'li: örnekte parametre tiplerinin %75,5'i ek dosyada ve kod bunları çözmüyor. Parametre hizalaması (ÖL-4) G28'de.
5. **K2'nin "doğru" tanımı ve şans tabanı yazılı değil; kazanç kanıtı tek yapı (karar 3).** `client` tekrarı 1/5 ile tutmadı, §0 bunu yazmıyor.
6. **Program sınıfı isim kanalının girdisiyle tanımlanıyor; platforma göre değişiyor (karar 4).**
7. **G6 okunmadan plan onaylandı (karar 5, 1).** Ana iddia fiilen tip ve yapıya kaydı; orada kıyas tabanı ve doğruluk ölçüsü yok.

## İtirazlar

### İ1. K0 "hızlı kazanç" değil, fonksiyon adlarının kapatılması

**İtiraz.** K0, kanallar arasında kesinlik farkı olduğunu varsayıyor. Oysa adlar tek kanaldan geliyor; eşik ne olursa olsun ya hepsi susar ya hiçbiri.

**Gerekçe ve kanıt.**
- **Kanal dağılımı [kod][hesap].** `report.json` → `naming_by_strategy` (tmux `…/20261019_090738/reports/report.json:184-193`):
  - tmux'ta fonksiyon adı üreten stratejiler `string_context` 863, `api_param_reverse` 12, `binary_extract` 1 (%98,5).
  - htop'ta `string_context` 101 = adlandırılan 101.
  - Öbür stratejiler değişken adı üretiyor. Codex de aynısını buldu.
- **Etki [hesap].** Yakın kapsam bugün tmux'ta P'nin %6,6'sı (0,197 × 857/2545), htop'ta %0,7. Susturma sonrası ikisi de ≈ 0. Ürün G9-G26 arası neredeyse adsız kalır.
- **Alt kanallar.** Kurtarma yolu `string_context`'i dizgi türüne bölmek. Tanımlar etiketler görülerek yazılırsa çatallanan yollar sorunu çıkar. En iyi mevcut alt kanal (G7 Ç-K) bile tam kesinlikte %73,4 [%65,2; %80,3] (`g7/rapor.md:68`).
- **Örneklem [hesap: Wilson].** "Yanlış ≤ %10" için en az 35 hatasız etiket, "kesinlik ≥ %95" için 73 hatasız etiket gerekir (codex).
- **Örneklem içi ölçüm.** Seçim ve "G4 etiketleriyle yeniden ölçüm" aynı 482 öğede (P:112). V:71 ise kural geliştirmeyle eşik seçiminin ayrı kümelerde yapılmasını istiyor.
- **"Yeniden etiketleme gerekmez" (P:51) tutmayabilir [kod].**
  - `c_namer.py:1665` en güçlü adayı alıyor.
  - `api_param_reverse` adayı 0,75 güvenle 0,7 eşiğini geçiyor (`c_namer.py:3147-3155`, `config.py:472`). `string_context` silinince fonksiyon yeni, etiketsiz bir ad alabilir (codex).
  - Ad birleştirici (1145 ad, 1144 çakışma) da ad koyabilir **[doğrulanmadı]**.
- **Önkoşullar.**
  - G4 anahtarında kanal alanı yok [kod]. Köken, 62ad154'ü yeniden koşarak çıkarılmalı; bu da ÖL-7'ye bağlı, ÖL-7 bekliyor.
  - Berke'nin 2026-10-15 kuralı "eleme en sonda" diyor [hafıza: `feedback_no_llm.md`]; K0 elemeyi en başa koyuyor.

**Karşı öneri.**
- G9'da K0 yalnız ölçüm olsun: köken kaydı ve alt kanal tablosu. Alt kanal tanımları etiketlere bakmadan ön kayda yazılsın.
- Üründe susturma KS-1 ile birlikte açılsın.
- Etki taze bir örneklemde ölçülsün.

**Kapatmak için.**
- ÖL-7.
- 482 öğenin kökenle eşlenme oranı.
- Susturma sonrası `naming_map` farkının yalnız silmeden oluştuğu.
- Taze örneklemde yanlış oranı.

**Etkilediği karar:** 2.

### İ2. İsim katmanı tipe bağımlı değil; KS-1'in kayması ve Kapı 1'in yeri gerekçesiz

**İtiraz.** "Tip → yapı" makul. "Yapı → isim" bağımlılığını ise Faz 0'ın kendi ölçümleri çürütüyor.

**Gerekçe ve kanıt [belge].**
- **Mekanizma G7'de ölçüldü.** V1 kümeleri, oybirliği, çelişkide sus.
  - Kâhin çapayla nesne düzeyinde (Ö2): öneri %4,3, kesinlik %36,7, doğru %1,6 (`g7/rapor.md:80, 85`).
  - Modül düzeyinde (Ö1): kesinlik %83,5 [%78,5; %87,4] (`:77`). Kâhin çapayla bile "yanlış ≤ %10" tutmuyor.
  - P:17 kendisi "adlar tipi değil modülü izliyor" diyor, yine de 3.3 ve 3.5'i tip sınıfına bağlıyor (P:96).
- **P:24'te etiket hatası (codex).** "%39 → %68 → %84" çapa kesinliği değil, yayılan önekin kesinliği (`g7/rapor.md:77-79`). Çapa kesinliği %73,4.
- **KS-1 iç çelişkili yerleştirilmiş.**
  - Karar taslağı ve G7, KS-1'in G11-G12'de, yayılımdan önce kalmasını istiyor (`karar_taslagi.md:34`, `g7/rapor.md:213`).
  - v2.1 KS-1'i G23'e koyuyor (P:121), ama "paralel yürüyebilir" de diyor (P:129).
- **Kapı 1 ya süs ya zararlı.**
  - G16'da yalnız K0'dan geçmiş, susturulmuş bir sistemi ölçer; tasarım gereği tutmaz.
  - Önceden yazılmış dal: "Kapsam düşükse isim kuralları o hâliyle dondurulur, emek … tip izine kayar" (V:212).
  - Emek zaten tipte. Dal ya hiçbir şey değiştirmez ya da isim kurallarını KS-1'den önce dondurur (codex).
- **Takvim dayanaksız.**
  - Faz 1 +%58 uzuyor (12 → 19 gün [hesap]); kalem başına kestirim yok.
  - Faz 0'ın planlı kalemleri sessizce düştü: G6, G7b, ÖL-7 ve G8'in Debian ofset P/R kalemi (`g8_geri_yazma/onkayit.md:141`).
  - Takvimde hiç olmayan işler:
    - Kapı 1 ve 2 için doğrulama etiketleme, sınıf başına ~385 öğe (`etiket_protokolu_v2.md:261`);
    - kanıt tavanı;
    - 3.6 kalibrasyonu için yeni adların etiketleri.
  - G27'de "Kapı 2 + bilinen hatalar" aynı gün (P:124). Kapı donmuş kodu ölçmeli.

**Karşı öneri.**
- **İki bağımsız iz.**
  - İsim: K0 (ölçüm) → KS-1 (G10-G11) → G7b → Kapı 1 (G12-G13). Dalı gerçek bir karar olsun, örneğin tutmazsa isim birincil iddia olmaz.
  - Tip: 1.1-1.3 → K1 → 2.x → K2.
- **Bağ.** İsim katmanı tip kümesinden ancak ön kayıtlı küçük bir deney (DWARF tip kümesi + kâhin çapa) nesne kesinliğini ≥ %90 gösterirse girdi alır.
- **Takvim.** Etiketleme günleri yazılsın; hata günü kapıdan öne alınsın.

**Kapatmak için.**
- G7 yayılım benzetiminin DWARF kümeleriyle tekrarı.
- KS-1'in tip ve yapı olmadan ablasyonu (codex).
- Kalem başına kestirim.

**Etkilediği karar:** 1.

### İ3. K1 yanlış şeyi ölçüyor ve oyunlanabilir

**İtiraz.** K1 tutsa bile çıktıda tek bir doğru, adlı tip olmayabilir. Başarısızlık dalı da doğrulama setini ikinci bir geliştirme setine çeviriyor.

**Gerekçe ve kanıt.**
- **Saflık tip doğruluğu değildir [belge].**
  - V §4 tip hedefi: "DWARF'a karşı tip doğruluğu … taban Faz 0'da, hedef G8'de; Hex-Rays (%35-50) kıyas çizgisi" (V:101). Bu taban ölçülmedi (`onkayit.md:141`).
  - Anonim küme saflığı Hex-Rays'e ya da literatüre (TypeForge, OSPREY, ReSym [hafıza: `karadul-2026-literatur.md:34`]) kıyaslanamaz.
- **Kural (a) totolojiye yakın.**
  - Değişmeden geçen argümanın tip uyumunu C derleyicisi zaten denetliyor (G7 `rapor.md` §6 sonu). %99,1 yalnız bunu gösteriyor; (b)-(f) hiç ölçülmedi.
  - V1 üyelerinin %92,2'si yapı işaretçisi, %4,7'si `char *` [hesap, tmux]. (b) skaler parametreleri de birleştirir ve saflığı ucuzdan şişirir.
- **Bağlamdan bağımsız birleştirme [kod][belge].**
  - tmux'ta `window_pane` ve `client` ikisi de iç `xcalloc`'un dönüşüyle kuruluyor (G8: `#0x6e0` / `#0xca8` + `bl _xcalloc`). (c) kuralı iki tipi `xcalloc.ret` üstünden birleştirir.
  - Çatışma denetimi ortak ofset ve genişlikte kurtarmaz (codex) ve birleştirme sırasına bağlı.
  - (c)'nin içe aktarmalara uygulanıp uygulanmayacağı yazılı değil.
- **DWARF tipi her zaman "gerçek" değil.**
  - Bağlam parametresi DWARF'ta `void *`: (e) doğru birleştirirse saflık düşer ve P:69 kuralı kapattırır. Farklı nesneleri "aynı `void *`" üstünden birleştirmek ise %100 alır (codex).
  - Adres alınması, hangi çağrı yerinin hangi bağlamla çağırdığını söylemez (codex).
  - htop'ta kalıtım yüzünden saflık %87,1 (`rapor.md:142`).
  - typedef, `const` ve klonlar için tanım yok; G7 `const`'u atmıştı (`rapor.md:126`).
- **Oyun alanı.**
  - Tekilleri atmak yetmez: yalnız bir doğru ikiliyi tutan sistem %100 alır (codex). tmux'taki 135 kümenin 63'ü zaten iki üyeli (`rapor.md:110`).
  - Kapsam yalnız "raporlanır".
  - Medyan saflık önek ölçüsünde bile %100 (`rapor.md:51`).
  - Negatif kontrolün geçme ölçütü yok.
- **Ön kayıt ihlali [belge].**
  - P:69'daki dal ("kural kapatılır, saf kurallarla devam") doğrulamaya bakarak kural ayarıdır.
  - `dogrulama_seti_onkayit.md` §2 madde 2-4'e aykırı ("düzeltme geliştirme setinde yapılır").
  - DWARF'taki adlar aynı programların Mac isim kapısına sızar.

**Karşı öneri.**
- **Ölçü:** çiftler üzerinden kesinlik ve duyarlılık; yalnız yapı işaretçileri. `void *`, `char *` ve skalerler ayrı.
- **Ön kayıt:** kapsam alt sınırı ve negatif kontrol ölçütü.
- **"Aynı tip":** typedef soyulur, `const` atılır, `void *` joker, kalıtım ailesi önceden tanımlı, klonlar dışarıda.
- **Birleştirme:** ayırıcı, kap ve kimlik fonksiyonlarında çağrı yeri başına tip değişkeni; sıra bağımsızlığı testi.
- **Ablasyon:** yalnız geliştirmede; doğrulamada tek okuma.
- **Ayrıca:** GDT prototipleriyle adlı tip doğruluğu, tabanı çıplak Ghidra.

**Kapatmak için.**
- K1 ön kaydı.
- Geliştirmede kural başına saflık ve kapsam tablosu.
- `xcalloc` sınaması: (c) açıkken `window_pane` ile `client` aynı sınıfa düşüyor mu?

**Etkilediği karar:** 3, 1.

### İ4. K1'in gerçek veri hattı yok: dwz, hizalama, klonlar

**İtiraz.** G14-G15'in iki günü, var olmayan bir ölçüm hattını varsayıyor.

**Gerekçe ve kanıt.**
- **dwz [hesap].**
  - Debian coreutils 9.4 arm64 dbgsym'in 9 `.debug` dosyasında `formal_parameter` `DW_AT_type` başvurularının %75,5'i (7921/10493) `<alt …>`; ek dosya `.dwz/aarch64-linux-gnu/coreutils.debug`.
  - Apple `dwarfdump` (LLVM 21) bunları çözmüyor.
  - pyelftools 0.32 `DW_FORM_GNU_ref_alt`'ta `NotImplementedError` veriyor.
- **Bilinen ama planlanmamış [belge][kod].**
  - Derleyici sentezi "dwz alt dosyası da okunmalı" diyor (`2026-10-15_makale/derleyici/gcc_elf.md:164, 278`).
  - Kodda karşılığı yok (`karadul/`, `scripts/`, `tests/` altında grep 0). `dwarf_extractor.py` `dwarfdump` metnini ayrıştırıyor.
  - Doğrulama paketlerinin hangilerinde ek dosya olduğu **[doğrulanmadı]**.
- **Klonlar.** Sentez "parametre/tip ölçümünde klon imzası kaynak imzayla kıyaslanmamalı" diyor (`gcc_elf.md:120`). Örnekte `.isra/.constprop/.part` payı %1,1 (225/20324) [hesap].
- **Hizalama.**
  - `param_N` ↔ DWARF eşlemesi ÖL-4'ün işi; ÖL-4 Faz 2'de (V:156).
  - AAPCS64'te tamsayı ve kayan nokta parametreleri ayrı yazmaçlarda **[tahmin: sıra sapabilir]**.
- **Faz 0'da hiçbir Debian DWARF tip ölçümü koşmadı** (`onkayit.md:141`); risk bu yüzden görülmedi.

**Karşı öneri.** K1'den önce bir "tip gerçeği hattı":
- dwz farkında okuyucu;
- ÖL-4'ün parametre kısmı;
- çıplak Ghidra ↔ DWARF tabanı.

**Kapatmak için.**
- 8 Debian geliştirme ikilisinde çözülen tip payı ≥ %99.
- Elle denetlenmiş 50 hizalama.

**Etkilediği karar:** 1, 3.

### İ5. K2: "doğru" tanımı ve şans tabanı yok; kanıt tek yapı

**Gerekçe ve kanıt.**
- **Şans tabanı [hesap].**
  - `window_pane`: 1760 bayt, 75 üst düzey bileşen; baytların %80,5'i 21 bileşik ya da dizi bileşenin içinde.
  - Rastgele 8 hizalı ofsetin üst düzey bir bileşen başına denk gelme olasılığı %27,7; ofset ve genişlikle birlikte %11,4.
  - Yaprak düzeyinde (566 alan) şans oranı çok daha yüksek **[tahmin]**.
  - Hangi tanımın geçerli olduğu yazılı değil.
- **Mevcut kanıt zayıf.**
  - "11/11 doğru" yaprak alanların %1,77'sini kapsıyor, boyutlar da yanlış (`g8/rapor.md:543-549`; codex).
  - Boyut son erişimden tamamlanıyor (`c_type_recoverer.py:1537-1538`).
  - Paketli yapıda CParser 23 bayt yerine 24 veriyor (`rapor.md:93-98`).
- **Ofset doğru, tip yanlış.** Yerleşimsiz tip dönüşümü +%27 / +%70 artırıyor (be8f7eb). K2 alan tipini ölçmüyor; "dönüşüm artmaz" koşulunun hangi kümede ölçüleceği yazılı değil.
- **Seçilmiş kanıt.**
  - Hedefler yapıyı ilk parametre olarak alan fonksiyonlar.
  - `client` tekrarı 1/5 (`rapor.md:477, 565`). P:18 bunu atlayıp "okunurluğu ikiye katlıyor" diyor.
  - Program geneline seyrelince %25 havuz eşiği tutmayabilir **[tahmin]**.
- **Ölçüt ve P/R aynı gün.** G19'da ikisi birlikte (P:118); k'yı sonuca bakarak ayarlama yolu açık.

**Karşı öneri.**
- Ölçü: (ofset, genişlik, işaretçi/skaler) üçlüsü, yaprak alana karşı.
- Yanında:
  - şans tabanı;
  - yanlış yapı kimliği ve "yalnız ofset 0" kontrolleri (codex);
  - alan kapsamı ve sizeof.
- Okunurluk program genelinde ve rastgele örneklemde ölçülür.
- Ölçüt P/R'den önce mühürlenir.

**Etkilediği karar:** 3.

### İ6. 1.2 SSA dışa aktarımı: kolay kısmı saatlik, zor kısmı ve maliyeti takvimde yok

**Gerekçe ve kanıt [kod].**
- **Engel yapılandırmada.**
  - p-code aynı decompile içinde `HighFunction`'dan alınıyor (`headless.py:1198`).
  - MULTIEQUAL, INDIRECT, CAST ve PTRSUB'ı seçici liste dışarıda bırakıyor (`config.py:500-506`).
  - Varnode yalnız [uzay, ofset, boyut] olarak yazılıyor (`headless.py:1205-1225`).
  - Ghidra 12.1.2 `VarnodeAST`'te `getUniqueId()`, `def` ve `descend` var (`SoftwareModeling-src.zip`; codex, elle doğrulandı).
  - "SSA kimliği yok" doğru; ekleme ise saatlik iş.
- **Zor kısım takvimde yok.** Taban + gerçek ofset zinciri (INT_ADD/PTRSUB/CAST/MULTIEQUAL), takma ad ve MaxSMT tüketicisinin yeniden yazımı (`computation_struct_recovery.py:92-116`); hepsi mutant kanıtlı testlerle aynı iki günde.
- **Maliyet ölçülmedi.**
  - tmux'ta seçici dışa aktarım 132 155 op, 9,5 MB [hesap].
  - Bütün sonuçlar bellekte tutuluyor (`headless.py:1063-1064`); eski tam dışa aktarım 4,7 GB (`config.py:499`).
  - alpine ve gnome-builder 13-15 MB.
- **Decompile kuralıyla çelişki yok; iki gri bölge var.**
  - (a) Kuyruk çağrısı, Ghidra başvurusu olarak yazılırsa V:236'nın neresine düşer?
  - (b) Geri yazmadan sonraki p-code Karadul'un kendi yapısını yansıtır. K2 geri yazma öncesi p-code'la ölçülmeli.

**Karşı öneri.**
- Geliştirme setinin en büyük ikilisinde tam op listesiyle tek koşu; op, boyut, bellek ve süre ölçülür.
- V:236'ya gri bölgeler için bir satır eklensin.

**Etkilediği karar:** 1.

### İ7. Program sınıfı yöntemin girdisiyle tanımlanmış

**Gerekçe ve kanıt.**
- **Döngüsellik.**
  - snake_case dizgi `string_context`'in yakıtı ve Karadul'un çapa süzgeciyle aynı biçim (`[a-z][a-z0-9]*(_[a-z0-9]+)+`, `g7/onkayit.md:86`; codex). Totoloji kapı yapısına gömülüyor.
  - "Hedef sınıf başına konur" (P:135), V:208'deki "eşikler düşürülmez" kuralına arka kapı açar.
- **Biçim zenginlik değildir.** htop'un adları karışık harfli; tmux'un snake_case dizgilerinin bir kısmı fonksiyon adı değil **[tahmin]**.
- **Platform.** sqlite3 Mac'te SQLite'ı gömüyor, Debian'da dinamik bağlı (`dogrulama_seti_onkayit.md:450`); sınıf platforma göre değişebilir.
- **Eşik uydurma.**
  - Eşik, "htop ve tmux ayrı sınıfa düşmeli" beklentisiyle seçiliyor (`karar_taslagi.md:39`).
  - 8 programda tek program %12,5 ağırlık taşıyor; kararlılık gösterilmedi (codex).
- **C++ ve ObjC.** Yöntem adları snake_case değil **[tahmin]**.

**Karşı öneri.**
- Yöntemden bağımsız bir sınıf değişkeni (boyut tabakası, "assert/`__func__` var mı") ya da eş değişkenli rapor.
- Sınıflar ilk koşudan önce, platform başına kilitlensin.
- Bir "belirsiz" bandı ve program dışarıda bırakma kararlılık testi.

**Etkilediği karar:** 4.

### İ8. Ön kayıtlı karar usulü askıya alındı; LLM riski tip tarafına taşındı

**Gerekçe ve kanıt [belge].**
- **Durum.** Taslak "G6 bitince tamamlanacak" diyor (`karar_taslagi.md:3`); kural 1 "BEKLİYOR" (`:11`). G6 durdu (P:44). Harness sonradan commit'lendi (f9d01f1, f9d375b), ama kuru koşu yarıda ve pilot koşmadı. Plan yine de onaylandı; sapma kaydı yok. Durdurma yetkisi "kural okundu" kanıtı değildir (codex).
- **Kuralın işlevi.** Yönü yatırımdan önce seçmekti (V:134). v2.1 "tip ve yapı" dalını okumadan seçti. Ama bu dalın gerektirdiği iki şey yok:
  - kıyas tabanı: çıplak Ghidra, Hex-Rays, LLM'li tip kurtarma **[doğrulanmadı]**;
  - tip doğruluğu ölçüsü (İ3).
- **Kapı 1'in eksik girdisi.** G6 sonucu G13 kapısına girdi olacaktı (`g6_pilot/pilot_protokolu.md` §11.6).
- **Geri dönüşsüz sıra.** Kıyaslar G38-G42'de (P:126), öncü model kararı açık (V:238).

**Karşı öneri.** İki yoldan biri:
- Faz 1'den önce küçük bir G6: (a) ve (b), 2 × 100 fonksiyon.
- Ya da yazılı sapma kaydı + "ana sonuç tip ve yapıdır" kararı; tip doğruluğu tabanı G9-G10'da ölçülür.

**Etkilediği karar:** 5, 1.

### İ9. Platform: kurallar Debian'da ölçülüp Mac'te kullanılıyor

**Gerekçe ve kanıt.**
- **[ÇELİŞKİ — görev metniyle]** Görev "Debian x86-64" diyor; kilitler "Debian 13 arm64" diyor (`dogrulama_seti_kilidi.md:40`; codex aynısını buldu). Asimetri şunlarda:
  - gcc `-O2 -mbranch-protection=standard` / clang `-Os` (`gcc_elf.md:205-214`);
  - ELF / Mach-O;
  - dwz;
  - sürüm: 10 doğrulama programının 6'sında farklı (`dogrulama_seti_kilidi.md:42-51`).
- **Görünmez klonlar.** gcc klonları sonek taşıyor, ayıklanabilir. Apple clang'da IPSCCP ve DeadArgElim sonek eklemiyor; parametre sayısı sessizce azalıyor (`2026-10-15_makale/derleyici/llvm_arm64.md:21`). Debian K1'i bunu göremez.
- **Adım 1.1 yalnız Mach-O biçimiyle yazılmış** (rebase fixup, `adrp+add`). ELF tablo yuvası tanımsız.
- **Çöküş senaryosu.** K1 Debian'da (e) kapatılarak geçer. Mac'te chained fixup kenarları, sessiz imza değişimi ve yığından geçen değişken argümanlar (`g7/onkayit.md:184`) saflığı düşürür. K2 Mac'te yanlış yerleşim yazar.
- **Kullanılmayan Mac gerçeği.** newlisp ve nagios kaynaktan `-g` ile derlendi, dSYM UUID'leri eşleşti (`dogrulama_seti_kilidi.md` §4.5).

**Karşı öneri.**
- K1 ve K2 Mac'te newlisp ve nagios dSYM'iyle de okunsun.
- 1.1 ELF ve Mach-O için ayrı yazılsın.

**Etkilediği karar:** 3, 1.

### İ10. "Kesinlik önce" çarpımsal süzgeçtir; son kapsam tek haneye iner

**Gerekçe ve kanıt [hesap; tmux, P = 2545; `g7/rapor.md:59, 77, 80`].**
- **Tip kümesi zinciri.**
  - Kümeye düşen %40,4 → kâhin çapalı kümede %24,8 → nesne düzeyinde oybirliği %4,3 → doğru %1,6.
  - Kesinlik %36,7 olduğu için "kesinlik önce" bu kanalı da susturur.
  - Modül öneki kâhinle %8,7 doğru, %16,5 yanlış.
- **KS-1 tavanı.** tmux'ta %10,7 (272/2545), htop'ta 0.
- **Kapı 2.**
  - Kapı: yakın ≥ tavanın %70'i, yanlış ≤ %10. Tavan ölçülmedi.
  - V §12'deki %36-59 varsayımıyla hedef P'nin ≥ %25'i.
  - KS-1 en çok %10,7 getirir; kalan ≈ %15 yalnız modül + fiilden gelebilir.
  - Modül kapsamı ~%22-25 (`g7/rapor.md:200`, V:20) ve rubrik kural 7 genel fiili "yalnız alan" sayıyor.
  - Tahmin: tmux türünde sınırda, htop türünde yapı gereği tutmaz **[tahmin]**.
- **Tip tarafı.** K1 kapsamı tekiller atılınca ≤ %40 (V1) / %46 (V2); K2 bunu bir kez daha süzer.

**Karşı öneri.**
- Katman başına kapsam taban çizgisi ve kesinlik-kapsam eğrisi.
- Ara katmanlar adayları güvenleriyle taşısın; eşik son çıktıda uygulansın ("eleme en sonda" [hafıza]).

**Kapatmak için.** Faz 1'den önce kanıt tavanı ve hangi kanıt paketi sürümüyle tanımlandığı.

**Etkilediği karar:** 1, 2, 3.

### İ11. Doğrulama setinin bakış bütçesi delindi

**Gerekçe ve kanıt [belge].**
- Ön kayıt kapı günlerini G13, G20, G28-G30 diye sabitliyor (`dogrulama_seti_onkayit.md` §2 madde 1).
- v2.1 bakışları beşe çıkarıyor ve günleri değiştiriyor; ön kayda değişiklik girişi yok.
- Aradaki her düzeltme bir sonraki bakışı uyarlamalı kılar; kestirimler iyimserleşir.

**Karşı öneri.**
- Ön kayda tarihli bir değişiklik girişi.
- K1 ve K2'de doğrulamada tek okuma.
- DWARF teşhisi isim etiketlemesinden ayrı oturumda yapılsın ve bakış kaydına yazılsın.

**Etkilediği karar:** 1, 3.

## Codex

- **Çalıştırma:** `gpt-6-astra`, `xhigh`, 451 sn, çıkış 0, yanıt 10 KB.
- **Doğrulama:** Atıfların hepsi elle denetlendi. Dosyayla çelişen iddia yok. Tek fark yuvarlamada: Codex %8,8 hesapladı, belgede %8,7.
- **Bağımsız katkılar** (metinde "(codex)" diye işaretli):
  - `api_param_reverse` yedeği;
  - P:24'teki etiket hatası;
  - Kapı 1'in dondurma dalı;
  - `void *` ödülü;
  - Ç-K biçimiyle sınıf tanımının aynılığı;
  - %95 kesinlik için 73 etiket;
  - `VarnodeAST` kaynağı;
  - K2 negatif kontrolleri.
- Debian'ın arm64 olduğunu o da buldu.

## Önceki Onuncu Adam'dan açık kalanlar (2026-10-17)

| İtiraz | Durum | Neden |
|---|---|---|
| İ3 LLM kıyası | **açık, büyüdü** | G6 koşulmadı; öncü model kararı açık (V:238); tip iddiası için kıyas yok |
| İ4 kanıt tavanı | **açık** | G7b koşulmadı; Kapı 1 ve 2 tanımsız |
| İ5 insan değerlendirici | **açık** | Etiketlerin hepsi Claude Opus 5.5'ten (G4 `sonuc.md` §8) |
| İ9 ÖL-4 önce | **ters döndü** | Parametre tipi kapısı (G16) hizalamadan (G28) önce |
| İ2 / İ7 SDK GDT | **sessizce düştü** | v2.1'de yok; `ghidra_data_type_archives` boş (`config.py:486`). Kütüphane prototipleri K1'e adlı tip çapası verirdi |
| İ1 kontrol akışı | **açık** | Faz 1'de 0 gün |
| V §4 tip tabanı | **yapılmadı** | "Taban Faz 0'da, hedef G8'de" uygulanmadı |

## Korunması gerekenler

1. Ön kayıt, mühür ve olumsuz sonuç kaydı. v2.1'in sorunu bu disiplinden sapması.
2. "Yerleşim yoksa yalnız ad" ürün kuralı (be8f7eb).
3. Kör protokol v2 (yakın/değil kappa 0,95; cömertlik +1 puan).
4. "Çelişkide sus" kuralı (G7'de 213 yanlış öneriyi kesti).
5. Tip ve yapı izinin kendisi. Ama isim bahanesiyle değil, kendi okunurluk kazancıyla gerekçelendirilmeli.
6. 433 ofset teşhisi ve "MaxSMT gerekmezse emekliye" kararı.
7. ÖL-3 erişim sınıfları ve talimat ağırlığı.

## Premortem: 6 ay sonra başarısız olduysa

1. K0 adları susturdu.
2. Kapı 1 boşa geçti ya da isim kurallarını dondurdu.
3. dwz, hizalama ve Debian koşuları takvimi 6-8 gün kaydırdı.
4. K1, (c) ve (e) kapatılınca %30 kapsamla geçti; Mac'te ölçülmedi.
5. K2 cömert bir tanımla geçti; kazanç seyreldi.
6. Kapı 2 tutmadı; htop türünün hedefi düşürüldü.
7. Test seti açıldığında LLM tabanı isimde öndeydi; tip iddiası için kıyas yoktu.

**En olası tek sebep:** ana iddia, ön kayıtlı karar okunmadan isimden tip ve yapıya kaydı. Yeni iddianın doğruluk ölçüsü ve kıyas tabanı hiç kurulmadı.

## En büyük tek risk

**Ölçütün hedefin yerini alması, bu kez tip tarafında.**
- K1 (anonim küme saflığı) ve K2 (doğrulanmış yerleşimde ofset kesinliği), Karadul tek bir değişkene doğru adlı tip vermeden de geçilebilir.
- İkisinde de kapsam alt sınırı ve şans tabanı yok. Biri doğrulama setinde kural ayarına izin veriyor.
- G6 okunmadığı için ana sonuç belirsiz. 19 iş günü bu belirsizliğin tek dalına yatırılıyor.

**Faz 1'den önce istenen en küçük kanıt seti:**
1. Ön kayıtlı alt kanallarla K0 tablosu ve taze örneklemde etkisi (İ1).
2. Kanıt tavanı (İ2, İ10).
3. dwz farkında DWARF hattı ve çıplak Ghidra tip tabanı (İ3, İ4).
4. K1 ve K2 ön kaydı: tanım, kapsam alt sınırı, şans tabanı, doğrulamada tek okuma (İ3, İ5, İ11).
5. Küçük bir G6 ya da yazılı sapma kaydıyla ana sonuç kararı (İ8).
