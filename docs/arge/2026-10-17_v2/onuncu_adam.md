# Onuncu Adam: plan v1 ve derleyici sentezine itirazlar

- **Tarih:** 2026-10-17
- **Rol:** Zorunlu muhalif. Bu belge konsensüsün yanlış olduğunu varsayar. Amaç, plan v2 yazılmadan kör noktaları bulmak; dengeli bir değerlendirme değildir.
- **Saldırılan konsensüs:**
  - plan v1: `docs/arge/2026-10-15_isimlendirme_plani.md`
  - derleyici sentezi §4–§6: `docs/arge/2026-10-15_makale/derleyici_sentez.md`, satır 231–450
  - makale çerçevesi ve Berke'nin kuralları (hafıza)
- **Yöntem:**
  1. Belgeler ve depo kodu salt okumayla incelendi. Her kod iddiası `grep`/`sed` ile doğrulandı.
  2. Codex (`-c model_reasoning_effort=xhigh`, salt okuma, 10 dakikalık sınırın içinde bitti) bağımsız bir karşı argüman üretti.
  3. Codex'in görüşü danışman görüşüdür. Dosya atıflarının hepsi elle doğrulandı. Dosyayla çelişen iddialar **[ÇELİŞKİ]** diye işaretlendi.
  4. Codex literatür künyelerini web aramasıyla kontrol ettiğini söyledi; bağlantılar codex yanıtında, ben açmadım.
  5. Ham kayıt: `/tmp/codex-54406-1792232201-21080/` (`prompt.txt`, `response.txt`, `meta.json`, `codex.log`). `/tmp` geçicidir; kalıcı kopyası `workspaces/2026-10-17_v2/codex_onuncu_adam/` (depo dışı). Model `gpt-6-astra`, düzey `xhigh` (ana oturum notu).
- **İşaretler:**
  - **[kod]** depoda doğrulandı
  - **[belge]** depo belgesinde yazılı
  - **[hafıza]** hafıza kaydında yazılı, bu raporda yeniden doğrulanmadı
  - **[hesap]** bu raporda yapılan aritmetik
  - **[doğrulanmadı]** künye ya da iddia birincil kaynaktan kontrol edilmedi
  - **[tahmin]** gerekçeli kestirim

## Özet

1. **Ölçü:** Plan, "kodun tamamı okunur" hedefinin beş boyutundan yalnız fonksiyon adını ölçüyor. Mimari de öbür dördünü engelliyor: Karadul Ghidra'nın C metninde ad değiştiriyor, tip ve yapıyı decompiler'a hiç geri vermiyor. TRex adımı ölü, yapı çözücüdeki ofset çıkarımı da hatalı görünüyor.
2. **En büyük risk:** Makalenin ana ölçütü (ünlü açık kaynakta gevşek isim) LLM'in en güçlü olduğu alan. Planda aynı rubrikle koşan bir LLM tabanı yok. Bu risk ancak G33'te, test seti açıldıktan sonra görülür.
3. **Kapılar sayısal olarak yanlış ve bağlayıcı değil:** G20'nin %10 tam isim eşiği, Mac geliştirme setinde ölçülmüş literal tavanın (%8,6) üstünde; kapı tutmazsa hedef aşağı çekiliyor; G30 ise makaleye girmeyen modeli ölçüyor.
4. **Etiketleme:** Etiket paketi gerçek adı ve özgün gövdeyi içeriyor, yani gerçeğe kör değil. Rubrik, yanlış fiilli isimleri "yanlış" sayacının dışında tutuyor. "29/30 uyum" Claude'un Claude'la uyumu.
5. **Zaman:** 40 iş gününün yaklaşık 14,5'i (%36) ana test setinde getirisi sıfıra yakın işlere ayrılmış: gnulib, C++/ObjC, model ve arayüz. Tip geri yazma, SDK tip arşivi, alıcı tip kümeleri, öykünme ve yeniden derleme kâhini planda yok.
6. **Codex:** Bağımsız olarak aynı ana sonuca vardı. Ek **[ÇELİŞKİ]**'ler buldu: yerel isimler, p-code erişimi, "kesin" tip kanıtları, G30, rubrik kararı. Benim iki abartımı da düzeltti: gnulib işinin stres kümesinde karşılığı var; FID ve Lumina bilinen koda isim verir.

## İtirazlar

### Konsensüsün sorgulanmamış varsayımları

1. İyi isim, okunur kod demektir. Oysa yanlış tip ya da yapı üstüne konan güzel bir isim, hatayı daha inandırıcı kılar.
2. Ghidra'nın ilk geçiş çıktısı sabit bir tabandır; Karadul onun üstüne yalnız metin ekler.
3. %36–59 "tavan" ölçülmüş bir sayıdır. Oysa katman kesinlikleri varsayımdır (sentez:363).
4. Asıl rakip Ghidra ve IDA'dır, LLM ise yalnız bir ürün eklentisidir. Oysa makale şartı LLM kıyasıdır (`karadul-makale-hedefi.md:24`).
5. İki Mac programında seçilen kurallar 15 programa genellenir.
6. Kaynağı ve gerçek adı gören bir LLM etiketleyici, kaynağı görmeyen okuyucunun vekilidir.

---

### İ1. Plan yanlış problemi optimize ediyor: isim, okunur kodun ilk değil son katmanı

**İtiraz.**
- Berke'nin yeni hedefi beş boyutlu: fonksiyon adı, değişkenler, tipler ve yapılar, kontrol akışı. Plan bunlardan yalnız fonksiyon adını ölçüyor.
- Bütün kapılar geçilse bile çıktıda yanlış yapı alanları, bozuk değişken eşlemeleri ve yanıltıcı kontrol akışı kalabilir.
- Codex'in ifadesiyle: `FUN_123` adını `session_update` yapmak, `*(long *)(param_1 + 0x28)` ifadesinin hangi nesnenin hangi alanını değiştirdiğini açıklamaz.

**Gerekçe ve kanıt.**
- **Plan [belge]:**
  - Değişkenlere 1 gün (G16, plan:92), tiplere 1 gün (G17, plan:93), kontrol akışına 0 gün ayrılmış.
  - Kapıların hepsi yalnız fonksiyon adını ölçüyor (plan:136–140).
- **Sentez [belge]:**
  - §4'teki 44 kalemin hiçbiri kontrol akışını hedeflemiyor.
  - Oysa Ek A iki şeyi not etmiş: SAILR'ın "O0'da bile %17 sahte goto" bulgusu (sentez:572) ve "goto/etiket sayısı okunabilirlik metriği" önerisi (sentez:729). İkisi de §4'e taşınmamış.
- **Sentez:390 "Yerel isimler bu hedefin dışında tutulmalı."** **[ÇELİŞKİ — yeni hedefle]** Codex de aynı yeri işaretledi.
- **Projenin kendi raporu:** Decompilation'ın asıl problemi soyutlama ve okunabilirlik (`tersine_derleme_sinirlari.md:120`). [belge]
- **Tip çıkarımında rakipler zayıf** [hafıza: `karadul-ida-level-zorunluluk.md:33`; birincil kaynak burada yeniden doğrulanmadı]:
  - Hex-Rays %35 (-O0) / %50 (-O2).
  - Hesaplamanın "en iyi" olabileceği ve nesnel gerçeği (DWARF) bulunan alan boş bırakılıyor.

**Karşı öneri.**
- **Kritik yol bağımlılık sırasına göre kurulsun:**
  1. Fonksiyon sınırı ve çağrı grafiği
  2. Değer ve bellek temsili (alan erişimleri)
  3. Tip ve yapı
  4. Kontrol akışı
  5. Bunların üstüne isim

  İsim, tek başarı kapısı olmaktan çıkar.
- **İki iz:**
  - **Makale izi (8 hafta):** LLM'siz isim, kanıt künyesi, kalibre kesinlik.
  - **Ürün izi:** tip/yapı geri yazma ve kontrol akışı. Bu izin ölçüm altyapısı şimdi kurulur ki sonraki "en iyi" iddiaları ölçülebilsin.

**Sınayacak ölçüm.**
- **Dört koşullu ablasyon** (codex). Ortam: Debian dbgsym'li geliştirme programları. Koşullar:
  1. Çıplak Ghidra
  2. Yalnız isim
  3. Yalnız tip, yapı ve akış
  4. Birleşik
- **Nesnel ölçütler:**
  - DWARF'a karşı parametre ve yerel tip doğruluğu
  - Yapı alanı ofsetinde P/R
  - 100 satırdaki `*(T *)(p + 0x..)` ifadesi sayısı
  - 100 satırdaki goto sayısı ve iç içe derinlik (`karadul/quality/metrics/code_structure.py` bunu zaten sayıyor ama plan kullanmıyor)
  - Derlenebilirlik oranı
- **Küçük analist deneyi** (DREAM++ şablonu, sentez:572):
  - 6–10 katılımcı, kaynağı görmeden.
  - Sorular: "ne yapar", "hangi alanı değiştirir".
  - Süre ve doğruluk ölçülür.
- **Karar kuralı:** 3. koşul 2. koşulu geçiyorsa isim merkezli strateji elenir.

---

### İ2. Mimari tavan: Karadul bildiğini decompiler'a geri vermiyor; tip ve yapı bileşenleri ölü ya da kanıtsız

**İtiraz.**
- Karadul, Ghidra'nın tek seferlik C çıktısında metin değiştiriyor.
- Bulunan isim, prototip ve yapı decompiler'a dönmüyor, bu yüzden tip yayılımı hiç çalışmıyor. Örnekler:
  - `xmalloc` olduğu anlaşılan fonksiyonun çağıranlarındaki değişkenler `undefined8` kalıyor.
  - `*(long *)(param_1 + 0x28)` hiçbir zaman `s->field` olmuyor.
- Sonuç: plandaki her isim kazanımının okunurluğa dönüşmesi baştan sınırlı.

**Gerekçe ve kanıt.**
- **İsim uygulama [kod]:**
  - `karadul/reconstruction/c_namer.py:1760-1777`, Ghidra'nın fonksiyon başına ürettiği `.c` dosyalarında Aho-Corasick ile metin değiştiriyor.
  - `karadul/` altında `setName`, `HighFunctionDBUtil` ve `ApplyFunctionSignatureCmd` yok.
  - Yeniden decompile döngüsü yok.
- **TRex [kod]:**
  - `karadul/pipeline/steps/trex_struct_recovery.py:116-126`, `ghidra_lifted_il_path` artefaktını bekliyor.
  - Bu artefaktı üreten kod depoda yok, yani adım her koşuda `no_lifted_il` ile atlanıyor.
  - Testler sahte süreç çıktısıyla çalışıyor (`tests/test_trex_adapter.py:1-4`).
- **TypeForge [kod]:**
  - İsteğe bağlı ve kapalı.
  - Entegrasyon testi boş sonucu kabul ediyor (`tests/test_typeforge_adapter_integration.py:176-180`).
- **TypeForge'un LLM durumu** **[ÇELİŞKİ]**:
  - `feedback_no_llm.md:26` TypeForge'u "LLM değil" sayıyor.
  - Depodaki `docs/typeforge_setup.md:187`: "LLM-assisted faz (TypeForge Phase 2) entegre edilmedi."
  - `docs/BLACKHAT-BLACK-WIDOW-RESEARCH-REPORT.md:125`: "Type Flow Graph + LLM refinement."
  - Yayımlanmış yöntemin bir aşaması LLM'li görünüyor. Makalede "LLM'siz tip çıkarımı" diye anılmadan önce birincil kaynaktan doğrulanmalı.
  - Aynı belge Mach-O desteğinin sınırlı olduğunu da yazıyor (`typeforge_setup.md:180-181`).
- **MaxSMT yapı çözücüsü [kod]:**
  - Varsayılan olarak kapalı, CLI bayrağıyla açılıyor.
  - `karadul/pipeline/steps/computation_struct_recovery.py:92-99`, girdiler arasında 4096'dan küçük ilk sabiti ofset alıyor.
  - Oysa p-code'da LOAD/STORE'un 0. girdisi adres uzayı kimliğini taşıyan bir sabittir. STORE'un değer girdisi de sabit olabilir. Gerçek ofset, LOAD'ı besleyen `INT_ADD`/`PTRSUB` işlemindedir.
  - Dışa aktarma bütün girdileri yazıyor (`karadul/ghidra/scripts/pcode_analysis.py:157-173`).
  - Bulgu codex'in; ben kodda doğruladım. Çalıştırılarak hata oranı ölçülmedi.
- **Tip arşivi [kod]:** `karadul/config.py:437`'de `ghidra_data_type_archives` varsayılanı boş. Güncel macOS SDK'dan ya da Homebrew kütüphane başlıklarından üretilmiş bir arşiv yok.
- **Unutulan plan [hafıza + kod]:**
  - Mayıs 2026 yol haritasında bir madde vardı: "Type back-injection döngüsü: TRex/PDB JSON'u `DataTypeManager.addDataType` ile geri yaz, re-decompile" (`karadul-computation-fusion-roadmap.md:47`).
  - Yapılmadı. Plan v1 ve sentez bundan hiç söz etmiyor.
- **Açık soru zaten kapalı** **[ÇELİŞKİ — kodla]:**
  - Sentezin 11. açık sorusu, Karadul'un `HighFunction`/p-code erişimi olup olmadığını soruyor (sentez:449).
  - `pcode_analysis.py:25, 97` zaten `DecompInterface` ve `HighFunction` kullanıyor.
  - Asıl soru erişim değil, çıkan temsilden doğru kısıt üretebilmek (codex).
- **"Kesin" tip kanıtları kesin değil** **[ÇELİŞKİ — TP-1'in "kesin" nitelemesiyle, codex; sentez:284]:**
  - FORTIFY `_chk` boyutu nesnenin boyudur; `char[N]` olduğunu kanıtlamaz.
  - Debian'ın varsayılan `-fstack-protector-strong` ayarı, adresi alınan yerelleri de korur. Yani kanarya char dizisi kanıtı değildir.
  - Mac'teki varsayılan düzey [doğrulanmadı].
  - Bunlar kesin kanıt değil, güven değeri taşıyan kısıtlar olarak ele alınmalı.

**Karşı öneri.**
- **Geri yaz ve yeniden decompile et:**
  - İsimler `Function.setName` ile yazılır.
  - Prototipler `ApplyFunctionSignatureCmd` ile uygulanır.
  - Parametre ve yerel tipler `HighFunctionDBUtil` ile yazılır.
  - Güncel SDK GDT'si uygulanır, sonra yeniden decompile edilir.
  - Metin değiştirme yalnız son çare olur.
- **TRex:** Ya lifted IL üretilir ya da adım açıkça emekliye ayrılır. Ölü kod "tip çıkarımı var" izlenimi vermemeli.
- **Ofset çıkarımı:** LOAD/STORE'un 1. girdisini besleyen işlemden (taban + sabit) alınır. Çözücü, doğru erişimlerin elle verildiği bir teşhis koşuluyla ayrıca sınanır (codex).

**Sınayacak ölçüm.**
- **Geri yazma prototipi:** Geliştirme setindeki tmux'ta 1 yapı ve 20 prototip geri yazılır. Öncesi ve sonrası karşılaştırılır:
  - `undefined*` tip oranı (`karadul/quality/metrics/type_quality.py` bunu zaten sayıyor)
  - 100 satırdaki işaretçi aritmetiği ifadesi
  - DWARF'a karşı alan ofseti P/R (Debian coreutils dbgsym)
- **Ofset hatası:** Çözücü çıktısındaki farklı ofset değerlerinin dağılımına bakılır. Hata gerçekse tek bir değer baskın çıkar.

---

### İ3. Makalenin ana kıyası planda yok; gevşek rubrik LLM'in ev sahası

**İtiraz.**
- Makale şartı, LLM tabanlı yöntemlerle kıyas (`karadul-makale-hedefi.md:24`).
- Plan G33 yalnız IDA Free, Ghidra ve SymGen alt örneklemini öngörüyor (plan:123).
- Aynı test setinde, aynı rubrikle koşan bir "Ghidra çıktısı + hazır LLM" tabanı yok. En güçlü rakip, en iyi oynadığı oyunda planın dışında kalmış.

**Gerekçe ve kanıt.**
- **Rubrik LLM'in işini ölçüyor:** Gevşek rubrik "fiil ve nesne ana işi anlatıyor mu?" diye soruyor (rehber:10). Akıcı bir fiil-nesne tarifi üretmek, dil modelinin doğrudan yaptığı iş (codex).
- **Ezber Karadul'u geride bırakır:**
  - 15 programın hepsi ünlü açık kaynak (kilit:16–34).
  - İsim tahmininde görülen ve görülmeyen kod arasındaki fark yaklaşık 50 puan: %85–87'ye karşı %35–37 (`tersine_derleme_sinirlari.md:29`).
  - Yinelenenler ayıklanınca SymLM'in F1'i 0,73'ten 0,105'e düşüyor (`veri_setleri.md:125`).
  - LLM tabanı bu test setinde ezberle şişer, Karadul şişmez. Ham tablo Karadul'un aleyhine çıkar. [tahmin, mekanizması belgeli]
- **Ghidra/IDA kıyası anlamsız biçimde kazanılır:**
  - İkisi de programa özgü fonksiyonlara betimleyici isim üretmez. Projenin kendi taraması bunu "IDA naming F1 baseline'ı yok, kategori hatası" diye kaydetmiş (`karadul-ida-level-zorunluluk.md:35`) [hafıza].
  - Codex'in **[ÇELİŞKİ]** notu: FID, FLIRT ve Lumina bilinen kod için isim verir. Adil kıyasta bu mekanizmalar eşit katalog erişimiyle açık olmalı.

**Karşı öneri.**
- **Pilot (1–2 gün, G3'ten önce, yalnız geliştirme setinde):**
  - Örneklem: htop ve tmux'tan rastgele 150'şer isim bekleyen fonksiyon.
  - Koşullar:
    - (a) Karadul
    - (b) Ghidra C'si + öncü bir LLM, sıfır atış
    - (c) Aynı LLM + Karadul'un kanıt paketi
    - (d) Yerel 20–30B model
  - Hepsi aynı rubrikle değerlendirilir; sistem kimliği gizlenir.
  - LLM'ler yalnız kıyas için koşar; Berke'nin kuralı bunu açıkça izinli kılıyor.
- **"Görülmemiş" dilim (şimdi ön kayıtla):**
  - LLM tabanının eğitim kesim tarihinden sonra ilk sürümü çıkmış, insan yazımı C projeleri. Kaynaktan `-g` ile derlenir.
  - LLM yardımıyla yazılmış kod seçilmez; LLM'e tipik isimler LLM lehine yanlılık yaratır.
- **Ana iddia hesaplamanın kazandığı yere taşınır:**
  - sabit kesinlikte (≥ %90) kapsam
  - kanıt künyesi
  - determinizm
  - görülmemiş kodda dayanıklılık
  - tip ve yapı doğruluğu
  - süre ve maliyet

**Sınayacak ölçüm.**
- Pilotta (LLM − Karadul) yakın isim farkı ve risk–kapsam eğrileri. LLM için çekimser kalabildiği bir istem sürümü de koşulur.
- **Karar kuralı:** Fark ≥ 15 puansa ve görülmemiş dilimde de sürüyorsa, makalenin ana sonucu "gevşek isim oranı" olamaz.

---

### İ4. Kapılar sayısal olarak yanlış ve bağlayıcı değil

**İtiraz.** Eşikler, ölçülmüş tabana ve ölçülmüş tavana göre değil, bir tahmine göre konmuş. Tutmadıklarında da hedef aşağı çekiliyor.

**Gerekçe ve kanıt.** Sayılar [hesap]; codex aynı sonuçları bağımsız olarak buldu.
- **Bugünkü yakın isim oranı (v0):**
  - htop 21/597 = %3,52
  - tmux ≥ 192/2561 = %7,50
  - mikro %6,74, makro %5,51
- **G10 ve G20 için gereken sıçrama:**
  - G10 (mikro %25) için 790 yakın isim gerekiyor: bugünkünün 577 fazlası, yani 3,7 katı. Arada yalnız 7 iş günü var (G3–G9).
  - G20 (%35) için 893 ek isim gerekiyor, 5,2 kat.
  - M4'ün kaç fonksiyonu kapsayacağı bile henüz ölçülmedi (sentez:259).
- **G20'nin tam isim eşiği (%10):**
  - tmux'ta adı literal duran 272/2561 (%10,62), htop'ta 0/597.
  - Literal kanal kusursuz çalışsa bile mikro tavan %8,61, makro tavan %5,31.
  - Mac geliştirme setinde eşik ancak başka kanallardan en az 44 tam isimle geçilebilir.
  - coreutils eklenirse gnulib kanalıyla geçilir. Ama gnulib kullanan programlar ana test setinden çıkarılıp stres kümesine alınmış (kilit:41–49).
  - Sonuç: kapı ya Mac'te geçilemez ya da test setini temsil etmeyen bir aileyle geçilir.
- **"Sorun kesinlikte değil, kapsamda" (sentez:327) yanlış ölçüyü öne çıkarıyor** (ajan etiketleri):
  - htop'ta verilen 43 ismin 21'i yakın, 20'si yalnız alan.
  - tmux tariflerinde 171 ismin 96'sı yakın, 64'ü yalnız alan.
  - Yani verilen isimlerin yaklaşık yarısı amacı anlatmıyor.
- **"< %10 yanlış" henüz kurulmuş değil.** Wilson %95 aralıkları (codex):
  - htop 2/43 → %1,3–15,5
  - tmux 11/171 → %3,6–11,2
- **Tavan bir varsayım:** %36–59 tavanı varsayım (sentez:363). G20'nin %35 eşiği bu varsayımın alt ucuna denk geliyor.
- **"Tutmazsa" sütunu yanlışlanamaz:**
  - G20: "hedef ölçülen değere çekilir ve model katmanına ağırlık verilir" (plan:139).
  - G30: "hedef yeniden konuşulur" (plan:140).
- **G30:** Modeli de katarak ölçüyor. **[ÇELİŞKİ]** Makalede yalnız LLM'siz sonuçlar yer alacak (`feedback_no_llm.md:65`). G30, araştırma planının içinde bir ürün kapısı.
- **Kapılar geliştirme setinde ölçülüyor:**
  - Kurallar zaten o setin etiketlemesiyle seçildi (`karadul/reconstruction/tarif/propagate.py:3`: "ölçümle seçildi, 2026-10-15 tmux kör etiketleme").
  - Bu, genellemeyi değil uyumu ölçer.
- **Ortalama türü belirsiz** (plan:9). tmux mikro ortalamanın %81,1'ini taşıyor (codex).

**Karşı öneri.**
- **Üç katmanlı veri:**
  - geliştirme: kurallar burada yazılır
  - doğrulama: 8–10 program, farklı yazılım aileleri, test yedekleriyle çakışmaz; kapılar burada ölçülür
  - test: kilitli kalır
- **Kapıların biçimi:**
  - Makro ortalama, program sınıfı başına.
  - Risk–kapsam biçiminde: "yanlış oranı (yanıltıcı isimler dahil) ≤ %10 iken yakın isim kapsamı ≥ X".
- **X'in belirlenmesi:** "Kanıt tavanı deneyi" ile.
  - Bir insan yalnız Karadul'un kanıt paketini görüp isim verir. Başarı oranı, kanalın bilgi tavanıdır.
  - Kapı bu tavanın bir oranı olarak konur: G10'da ≥ %50, G20'de ≥ %70.
- **Mac'te tam isim kapısı:** "Kesin kanalın kesinliği ≥ %95 ve kapsamı literal tavanının ≥ %80'i."
- **G20'ye tip/yapı kapısı eklenir:** Debian'da DWARF'a karşı ölçülür.
- **G30:** Araştırma planından çıkar, ürün izinde ayrı izlenir.
- **Kapı tutmazsa:**
  - Sonuç "başarısız" diye kaydedilir.
  - Önceden yazılmış yön değişikliği uygulanır (örneğin kaynak tip/yapı izine aktarılır).
  - Eşik düşürülmez.

**Sınayacak ölçüm.**
- Doğrulama setinde, program bazında bootstrap güven aralıklarıyla kapı sayıları.
- Kanıt tavanı deneyinde iki insanın uyumu.

---

### İ5. Etiketleme okuyucunun anlamasını ölçmüyor; yanıltıcı isimler sayacın dışında kalıyor

**İtiraz.** Bugünkü etiketleme, kaynağı ve gerçek adı bilen bir LLM'in cömertliğini ölçüyor; okuyucunun isimden doğru davranışı çıkarıp çıkaramadığını ölçmüyor.

**Gerekçe ve kanıt.**
- **"Kör" paket gerçeğe kör değil [kod]:**
  - `workspaces/2026-10-15_oturum_scratchpad/tarif/kor_tmux.jsonl` her kayıtta `gt` (gerçek ad) ve özgün gövdeyi veriyor.
  - Gövdenin imza satırında özgün ad da yazıyor. Örnek: `gt: alerts_reset`, `pred: alerts_timer_reset`.
- **Kaynağı bilen değerlendirici okuyucunun vekili değil:** Rehber önce kaynağı okumayı söylüyor (rehber:5). Kaynağı zaten bilen biri, ismi bilmeyen okuyucunun yerine geçemez (codex).
- **Rubrik açığı (codex; dosyada doğrulandı):**
  - `yalniz_alan` sınıfı "fiil yanlış" durumunu da kapsıyor (rehber:11).
  - Rehberin kendi örneği: `window_resize → window_size` "getter sanılır" diye yalnız alan sayılıyor (rehber:29).
  - Okuyanı yanıltan bu isimler "yanlış ≤ %10" sayacına girmiyor.
- **"29/30 ajan–Claude uyumu" (plan:30):**
  - Aynı model ailesinin kendisiyle uyumu; doğruluk değil.
  - Wilson %95 aralığı %83,3–99,4 (codex).
- **Ön etiket:** Testte ajan ön etiketi kullanılacak (kilit:66), ama insanlara gösterilip gösterilmeyeceği yazılı değil. Gösterilirse çapa etkisi yaratır.
- **Örneklem büyüklüğü yazılı değil** [hesap]. %95 güvende, kümelenme düzeltmesinden önce:
  - ±5 puan için yaklaşık 385 öğe
  - ±3 puan için yaklaşık 1068 öğe
- **Rubrik kararı hâlâ açık** **[ÇELİŞKİ — bilim kuralıyla, codex]:**
  - "Modül + rol" isimlerinin yakın sayılıp sayılmayacağı açık soru olarak duruyor (sentez:448). Tavan bu karara çok duyarlı (sentez:377).
  - Başarı tanımı ölçümden önce yazılıp dondurulmalı (`feedback-karadul-bilim.md:16-17`).

**Karşı öneri.**
- **Paket ve sıra:** Paketten `gt` çıkarılır, gövdede fonksiyonun kendi adı karartılır. Değerlendirici önce amaç cümlesini yazar, sonra adayı görür.
- **Yanlış fiil yanlış sayılır:** Getter/setter, tahsis/serbest bırakma, hazırla/uygula karışmaları `yanlis` olur.
- **Yem isimler:** Örneklemin %10'una aynı modülden başka bir fonksiyonun adı karıştırılır. Yemlerin kabul oranı rubriğin cömertliğini ölçer.
- **Okuyucu testi:** Okuyucuya isim ve aynı modülden 5 gövde verilir (kaynak adları karartılmış); doğru gövdeyi seçmesi beklenir.
- **İnsan değerlendiriciler:**
  - Ön etiketi görmezler.
  - Bağımsız ilk kararları kilitlenir, anlaşmazlık ondan sonra çözülür.
  - Örneklem büyüklüğü ve ikili (yakın/değil) karardaki kappa ön kayıtla sabitlenir.
  - LLM yargıcın insanlarla uyumu ayrı raporlanır.

**Sınayacak ölçüm.**
- Aynı 200 öğe hem `gt`'li hem `gt`'siz protokolle etiketlenir. Yakın oranındaki fark, cömertlik yanlılığının ölçüsüdür.
- Yemlerin kabul oranı için hedef ≤ %5.
- Okuyucu testinde şans düzeyi %20.

---

### İ6. Emek dağılımı: 40 günün yaklaşık 14,5'i ana test setinde getirisi sıfıra yakın işlere gidiyor

**Gerekçe ve kanıt.**
- **Hafta 3 (G11–G14, 4 gün):** gnulib D1–D9, FLIRT DB ve bağlayıcı simülasyonu.
  - D1–D9 kazançları (Debian F1 0,123 → 0,903) coreutils'te elde edilmiş, örneklem içi bir simülasyon (sentez:245, 250, 346).
  - Ana test setinde gnulib yok; gnulib kullanan wget ve nano stres kümesinde (kilit:41–49).
  - Codex'in düzeltmesi: "hiçbir karşılığı yok" demek **[ÇELİŞKİ]** olur, çünkü stres kümesinde karşılığı var.
  - Asıl itiraz: bu işler ana test setine genellenen bir kazanç göstermeden kritik yolda yer alıyor.
- **G4(c) ve G4(d), yarım gün:** C++ RTTI ve ObjC/Swift metaverisi (plan:66).
  - Ana test setindeki 15 programın hepsi C (kilit:16–34).
  - Sentezin KS-7'sine göre C programlarında getirisi yaklaşık 0 (sentez:248).
- **Hafta 5–6 (G21–G30, 10 gün):** Model seçimi, istem, arayüz, paketleme ve animasyon.
  - Hiçbiri makaleye girmiyor (`feedback_no_llm.md:65`).
  - Sentez model katmanını "deterministik katman dondurulduktan sonra" koyuyor (sentez:321). Plan ise onu test seti açılmadan önceye yerleştirmiş.
- **G8 isim biçimi:** Amaç yanlışsa düzenli bir `modül_fiil_nesne` biçimi yalnız kozmetiktir (codex).
- **Toplam:** 4 + 0,5 + 10 = 14,5 gün, 40 günün %36'sı [hesap].

**Karşı öneri.** Bu 14,5 gün şöyle yeniden dağıtılsın:

| İş | Gün |
|---|---|
| Geri yazma ve yeniden decompile + SDK GDT | 3 |
| Alıcı tip kümeleri | 3 |
| Doğrulama seti + kanıt tavanı deneyi + LLM pilotu | 3 |
| Etiket protokolü | 1 |
| Ofset düzeltmesi ve tip ölçüm altyapısı (ÖL-4'ün ilk adımı) | 2–3 |

- Model ve arayüz G35'ten sonraya kalır.
- gnulib işi stres kümesi için tek bir kalem olarak, daha sonra yapılır.

**Sınayacak ölçüm.**
- Her kalem yazılmadan önce doğrulama setinde "kaç fonksiyonda tetikleniyor?" diye sayılır.
- Kalem bitince kazanç/emek oranı ölçülür.
- Aynı fonksiyonda örtüşen kazanımlar iki kez sayılmaz (codex).

---

### İ7. Eksik yüksek değerli hesaplama yöntemleri

**İtiraz.** Aynı veriden ters bir sonuç da çıkarılabilir:
- v0, isim verdiği yerde büyük ölçüde haklı ama kanıtı seyrek.
- Plan bundan "kapsamı büyüt" sonucunu çıkarıyor. Ters okuma şu: kapsamı zayıf kurallarla büyütmek yerine kesin çapaları daha güçlü bir taşıyıcıyla yaymak gerekir.
- En güçlü taşıyıcı, tip kimliği.

| Yöntem | Neden | Tavan nasıl ölçülür |
|---|---|---|
| **1. Alıcı tip denklik kümeleri → isimdeki nesne** | **Fikir:** Nesne yönelimli C'de aynı yapıyı ilk parametre olarak alan fonksiyonlar bir aile oluşturur. Ailede tek bir çapa isim (`__func__`, log) bütün ailenin nesnesini verir. Örnek aileler [tahmin]: tmux'ta `window_*`, `session_*`; git'te `strbuf_*`. <br>**Sentezde durumu:** TP-5/TK-13 olarak var, ama "L" ve araştırma grubunda (sentez:288, 320). <br>**Plana bağı:** Plan §4.1'deki "alan → doğru tarif" kaldıracının eksik nesne kaynağı bu. | Geliştirme setinde, ilk parametre tipine göre Steensgaard tarzı birleştirmeyle kümeler kurulur. İki şey ölçülür: <br>• GT ad önekine göre küme saflığı <br>• En az bir çapası olan kümelere düşen isim bekleyen fonksiyonların oranı |
| **2. Güncel SDK ve kütüphane tip arşivi** | **Kaynaklar:** macOS SDK; Homebrew ncurses, libevent ve openssl başlıkları; Debian'da glibc. <br>**Durum:** Varsayılan arşiv listesi boş (`config.py:437`). <br>**Getirisi:** Her içe aktarılan çağrıda prototip, enum ve yapı gelir; bunlar çağıranın değişkenlerine tip ve rol adı olarak yayılır (DG-2). Ucuz, deterministik ve sızıntısızdır, çünkü kaynak test programı değil kütüphane başlığıdır. | • Tam prototipli içe aktarma çağrı yeri oranı <br>• Enum'a dönüşen sihirli sabit oranı <br>• Üç koşulun kıyası: arşivli, arşivsiz, doğru prototiplerin elle verildiği (codex) |
| **3. Öykünmeyle G/Ç parmak izi** | **Yöntem:** Ghidra PcodeEmulator ile yaprak fonksiyonlar ve yan etkisi modellenebilen fonksiyonlar çalıştırılır. Derleyiciden ve -O düzeyinden bağımsızdır. <br>**Literatür:** BLEX (Egele vd., USENIX Security 2014), Multi-MH (Pewny vd., IEEE S&P 2015) [künyeler doğrulanmadı]. <br>**Sentezde durumu:** TR-12, "D–O, L" ve son sırada (sentez:267). | Önce tavan ölçülür: isim bekleyenlerin yüzde kaçı öykünülebilir (sistem çağrısı yok, dolaylı çağrı yok, sınırlı bellek). %5'in altındaysa ertelenir. <br>Sonlu G/Ç eşleşmesi eşdeğerlik kanıtı sayılmaz (codex). |
| **4. Yeniden derleyip karşılaştırma kâhini** | **Yöntem:** Karadul'un tipleriyle birlikte ürettiği C, çıkarılan derleme profiliyle derlenir; özgün fonksiyonla aynı girdilerde davranış karşılaştırılır. <br>**İki kullanım:** tip, yapı ve imza hipotezleri arasında seçim yapmak; metin değiştirmenin kodu bozmadığını denetlemek. <br>**Literatür:** <br>• LLM4Decompile'ın yeniden çalıştırılabilirlik ölçütü (Tan vd., EMNLP 2024) <br>• Liu ve Wang, ISSTA 2020 (sentez kaynakçası [32]) <br>• Schulte vd., "Evolving Exact Decompilation", BAR 2018 [künye doğrulanmadı]. Hedef yer de BAR. | Derlenen/toplam ve testi geçen/toplam ayrı ayrı verilir. Yalnız başarıyla derlenenleri paydaya almak yasaktır (codex). |
| **5. Biçim dizesinden alan adı, dize tablosundan enum** | **Örnekler:** `log("... flags=%x", c->flags)` → `flags` alanı. Değer → dize tabloları ve `switch` → enum. <br>**Sentezde durumu:** TP-2 yalnız argüman tiplerini öngörüyor (sentez:285). | Debian dbgsym'li geliştirme programlarında log argümanı olarak görünen yapı alanlarının oranı kanalın tavanıdır. Alan adı kesinliği DWARF'a karşı ölçülür. |
| **6. Dinamik izleme** | **Durum:** Frida altyapısı zaten var (`karadul/frida/collectors/function_tracer.py`). <br>**Getirisi:** htop gibi tablolu programlarda dolaylı çağrı hedeflerini ve argüman değerlerini doğrudan verir. <br>**Rapor:** Ayrı bir kanal olarak raporlanır. | • İş yükü arttıkça bulunan yeni hedeflerin eğrisi <br>• Çözülen dolaylı çağrı yeri oranı <br>Hiç çalışmamış dallar "çözüldü" sayılmaz (codex). |

---

### İ8. Sızıntı ve geliştirme setine aşırı uyum

**Gerekçe ve kanıt.**
- **Dar geliştirme tabanı:**
  - Kurallar tmux etiketlemesiyle seçildi (`propagate.py:3`).
  - M4 htop'a dayanıyor.
  - Mac geliştirme seti yalnız iki program.
- **Geçmiş:** Karadul daha önce "unique-in-binary" yoluyla gizli aşırı uyum yaşadı (R-2, sentez:427).
- **Katalog yoklaması bir örneklem:** Aday başına 2–10 adla yapıldı (`test_seti_adaylari.md:23`). 9,2M kayıtla örtüşme olmadığını göstermez (codex).
- **DB açık/kapalı koşu:** Kilit belgesinde yalnız SymGen kıyası için yazılı (kilit:67).
- **Tasarım sızıntısı:**
  - Kuralları ve sözlükleri tasarlayan model (Claude), vim, git, ssh gibi programların kaynağını büyük olasılıkla eğitimde görmüştür.
  - Çalışma anında LLM bulunmaması, tasarım sızıntısına bağışıklık sağlamaz (codex).
  - Bu kanıtlanamaz, ama sınanabilir.

**Karşı öneri.**
- Her kural ve sözlük girdisi için köken kaydı tutulur: hangi geliştirme fonksiyonundan ya da etiketinden türetildi.
- Kurallar ve sözlükler G31'den önce hash'le dondurulur.
- Ana test setinde DB açık, DB kapalı ve "hedef aile dışlanmış" koşulları koşulur.
- Geliştirme seti, G10'dan önce farklı yazar ve stillerden en az 8 programa genişletilir.
- Kural geliştirme ile eşik seçimi ayrı kümelerde yapılır.

**Sınayacak ölçüm.**
- Aile dışarıda bırakma deneyinde düşüş.
- Sözlüklerin yalnız geliştirme setinden yeniden türetildiği sürümle ablasyon.
- DB açıkken ve kapalıyken fark.

---

### İ9. Test setinin Mac yarısı yeni hedefin gerçeğini taşımıyor; değişken ölçütü yanlış değişkene verilen doğru adı ödüllendiriyor

**Gerekçe ve kanıt.**
- **Mac'te yalnız isim var:**
  - Gerçek isimler yalnız `nm` çıktısından geliyor (kilit:53–56). DWARF ya da dSYM yok.
  - Bu yüzden Mac'te değişken, tip, yapı ve kontrol akışı ölçülemiyor.
- **Eksik şişeler:**
  - unzip, ssh ve vim şişeleri sembolsüz; zsh'de yerel sembol yok (kilit:131–147).
  - Karar hâlâ bekliyor.
- **Değişken ölçütü:**
  - `scripts/varname_f1_eval.py:292` `setwise_local_prf` küme bazlı eşleştiriyor.
  - `karadul/analyzers/dwarf_extractor.py:517-522` ad ve tipi alıyor, konumu almıyor (sentez:59 da not etmiş).
  - Sonuç: `len` ile `capacity` yer değiştirse bile puan doğru görünür (codex).

**Karşı öneri.**
- **Mac gerçeği için:**
  - Aynı formül aynı bayraklarla `-g` kullanılarak derlenir; dSYM gerçek olarak saklanır.
  - Analiz `/usr/bin/strip` ile soyulmuş kopya üzerinde yapılır; yeni hash alınır.
  - Değişiklik gerekçesiyle kilit belgesine yazılır. Program listesi değişmez.
- **Seçenek:** Yeni hedefin değişken, tip ve akış boyutları yalnız Debian'da raporlanır.
- **Sıra:** ÖL-4 (konum hizalaması), herhangi bir değişken kapısından önce gelir.

**Sınayacak ölçüm.**
- Gerçeği bulunan fonksiyon ve değişken oranı.
- **Negatif kontrol** (codex): Fonksiyon içindeki yerel adlar kendi aralarında karıştırılır. Puan belirgin düşmüyorsa ölçüt geçersizdir.
- Kaynaktan derlenen ikili ile şişe arasındaki fonksiyon kümesi örtüşmesi.

---

### İ10. Ölçü birimi: ağırlıksız fonksiyon sayısı okunurluğu temsil etmiyor

**İtiraz.**
- İsim bekleyen fonksiyonların çoğu küçük yardımcılar olabilir [tahmin]. Bu durumda yarısına isim vermek, kodun hacimce küçük bir kısmını okunur yapar.
- Payda "Ghidra'nın adlandıramadıkları"dır. Karadul fonksiyon sınırlarını değiştirirse payda da değişir.

**Karşı öneri.**
- Talimat sayısıyla ağırlıklı kapsam da raporlanır.
- Sınır F1'i, isim F1'inden ayrı raporlanır (ÖL-3 zaten öneriyor).

**Sınayacak ölçüm.** Ağırlıklı ve ağırlıksız oranlar arasındaki fark. Fark büyükse ana ölçü ağırlıklı olur.

## Korunması gerekenler

1. **Test seti ön kaydı.** Bu, makalenin en sağlam parçası:
   - Kura betiği sonuç görülmeden commit edildi (337c4d5), sonuç ayrı bir commit (1bc05ec).
   - Dosyalar sha256 ve BuildID ile sabitlendi (ee0c34f).
   - Değiştirme kuralı yazılı (kilit:13).
2. **LLM'siz çekirdek.** Model katmanı ayrı statüde kalıyor. Kesin, tarif, alan ipucu ve model önerisinin kökenleri ayrılıyor (MD-1). Model kimlik iddia etmiyor.
3. **Kesinlik önceliği ve yanlış isim üst sınırı.** v0, yanlış oranını mevcut Karadul'un %41–64'ünden %5–6'ya indirdi (sentez:329). Korunmalı, ama İ5'teki rubrik açığı kapatılarak.
4. **Kafesli, sıradan bağımsız iki fazlı yayılım.** Çelişkide isim verilmiyor ve ÖL-7 determinizm testi var.
5. **M4: veri tablosu yuvaları ve işaretçi haritası (TR-4).** Dolaylı çağrılan fonksiyonlar için tek statik yol. Test setinde tablo güdümlü yorumlayıcılar var: dash, mawk, zsh, nasm [tahmin: genel bilgi, test programlarına bakılmadı].
6. **Kanıt yönü ve hata yolu budaması (TR-2).** Simülasyonda yanlış pozitif düşüşü ölçülmüş (Ubuntu FP 16 → 0).
7. **Derleme kökeni profili (KS-5).** Kip belirsizse kural susuyor.
8. **Raporlama ilkeleri:**
   - eş anlamlı tarif kabulü (gevşek mod)
   - ünlü ve az bilinen programların ayrı raporu
   - DB açık/kapalı koşu
   - program sınıfı başına rapor (sentez:413)
9. **Bilim disiplini.** Hipotez → deney → ölçüm döngüsü, olumsuz sonuçların kaydı ve iddiaların ölçülenle sınırlı tutulması.

## En büyük tek risk

**Risk: Ölçütün hedefin yerini alması.**
- Karadul, kendi gevşek rubriğinin beğendiği isimleri çoğaltır ama kodu daha doğru anlaşılır kılmaz.
- Test seti açıldığında, aynı rubrikle koşan "Ghidra + hazır LLM" tabanı bu ölçütte de onu geçer.
- Codex'in cümlesiyle: "Karadul'un kodu daha doğru anlaşılır kılmadan, kendi rubriğinin beğendiği isimleri çoğaltarak 'dünyanın en iyisi' olduğuna inanması."

**Neden tek ve en büyük risk bu:**
- **İki hedefi birden vurur.** "Dünyanın en iyisi" iddiası makalenin kendi tablosunda çürür; makale "LLM'siz, ama daha kötü" diye okunur.
- **Geri dönüşü yok.** Test seti tek kullanımlık. Sorun G31–G33'te, kilit açıldıktan sonra görülür. O noktada ölçütü ya da kıyası değiştirmek ön kaydı bozar.
- **Hiçbir kapı onu erken yakalamıyor.** LLM tabanı G33'e kadar hiç koşmuyor; kapılar yalnız LLM'siz isim oranını ölçüyor.
- **Karadul'un üstünlüğü ana ölçütte görünmüyor.** Hesaplamanın üstün olabileceği alanlar şunlar: değer akışı, alan yerleşimi, çağrı hedefi, kalibre kesinlik ve görülmemiş kodda dayanıklılık.

**Erken sınama (2 gün, yalnız geliştirme seti):**
- İ3'teki LLM pilotu.
- İ5'teki `gt`'siz etiket protokolü ve yem isimler.
- **Karar kuralı:**
  - LLM tabanı geliştirme setinde ≥ 15 puan önde ve fark küçük bir görülmemiş dilimde de sürüyorsa, makalenin ana sonucu şunlar olur: sabit kesinlikte kapsam, tip ve yapı doğruluğu, görülmemiş kodda dayanıklılık.
  - Bu durumda "en iyi" iddiası gevşek isim oranı üzerinden kurulmaz.

**Premortem: 6 ay sonra başarısız olduysa, en olası senaryo:**
1. G31'de test seti açıldı. LLM tabanı aynı rubrikle 20 puandan fazla öndeydi.
2. Mac'te dört programda gerçek eksikti; değişken ve tip boyutu ölçülemedi.
3. İnsan değerlendiriciler geç bulundu ve kappa düşük çıktı.
4. Hafta 3 ve Hafta 5–6'ya giden zaman ana sonuca bir şey katmadı.
5. Ürün tarafında okunurluk değişmedi, çünkü tipler hiçbir zaman decompiler'a geri yazılmadı.

**Konsensüs kapatılmadan (plan v2'den önce) istenen kanıt:**
1. LLM pilotu ve karar kuralı (İ3).
2. Etiket protokolü A/B: `gt`'li ve `gt`'siz etiketleme, yem kabul oranı (İ5).
3. Kanıt tavanı deneyi (İ4).
4. Geri yazma ve yeniden decompile prototipi: tmux'ta 1 yapı ve 20 prototip, öncesi ve sonrası ölçümleriyle (İ2).
5. Ofset hatasının doğrulanması: çözücü çıktısındaki ofset dağılımı (İ2).
6. Doğrulama setinin seçimi ve ön kaydı (İ4, İ8).
7. Mac test gerçeği kararı: kaynaktan `-g` ile derleme ya da Mac'teki değişken, tip ve akış boyutlarını Debian'a bırakma (İ9).
8. Alıcı tip kümesi saflık deneyi (İ7).
