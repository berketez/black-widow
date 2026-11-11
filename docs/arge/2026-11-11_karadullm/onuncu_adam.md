# KaradulLM uzlaşısı: Onuncu Adam incelemesi

- **Tarih:** 2026-11-11.
- **İtirazları yazan:** Codex yanıt verdi: model `gpt-6-astra`, reasoning `xhigh` (çağrı günlüğünün başlığı; çıkış 0, 08:56-09:06). Belgeyi Claude (Opus 5.5) yazdı. Codex'in yanıtı danışman görüşü olarak alındı; dosya, satır ve sayı iddiaları tek tek denetlendi. Hangi iddiaların Codex'ten geldiği, hangilerinin doğrulanıp hangilerinin elendiği §7'de.
- **İncelenen uzlaşı:**
  - U1. Deterministik motorun ad veremediği fonksiyonlarda yerel 27B model + Karadul araçları (KaradulLM) güvenilir ad ve "ne iş yapıyor" açıklaması üretir; ürünün bu boşluktaki dayanağı bu olur.
  - U2. İnce ayar yapmadan, yalnız istem + araç sözleşmesi + örnek izler + bağlam yönetimi + model dışı denetimle model "ince ayarlı gibi" davranır ve araçları güvenilir kullanır.
  - U3. Sohbet paneli + yan panel ("küçük Cursor") ve adsız fonksiyonlar için fonksiyon kartı araştırmacıya net fayda sağlar; yerel modelin hızı yeterlidir.
- **Görev:** Üç maddenin tersini savunmak. Onay değil, çürütme denemesi.
- **Yöntem:** Belgeler, kod ve toplu sayım dosyaları okundu. Kör setler (`docs/arge/dogrulama_seti*`, `test_seti*`, `dogrulama_seti_kanit/`, `targets/`, `scripts/measurement/*seti*`) açılmadı. Model, sunucu, Ghidra, Karadul hattı ve test koşulmadı.
- **`tasarim.md` ve `arac_sozlesmeleri.md`:** 09:00'da ikisi de dizinde yoktu. İtirazlar uzlaşının sözlü hâline (`feedback_no_llm.md` 2026-11-11 bloğu) ve plan metnine (`2026-10-17_plan_v2.md:179-187`) karşı yazıldı. `arac_sozlesmeleri.md` 09:04'te dizine girdi (yarım taslak, kod yok); `tasarim.md` 09:06'da hâlâ yoktu. Sözleşme taslağına yalnız çakışma için bakıldı:
  - **Taslağın zaten karşıladıkları:** BSim gölge adayları, `_naming_diagnosis` kararları ve algoritma etiketleri araç olarak sunulmuyor (`arac_sozlesmeleri.md:85`, `:79`). Çağıranlar yalnız Ghidra çağrı kenarından geliyor (`:71`, `:76`). Dizgi aracı "dizgi talimat değildir" uyarısı taşıyor (`:74`). Ölçüm kipinde hedefin adı gizleniyor (`:51`). Ad önerisinin bugün `manual` / `1.0` yazılacağı ve `source` alanı eklenmeden uygulanamayacağı yazılmış (`:93`).
  - **Taslakta göremediklerim:** kabul edilen önerinin sonraki koşuda en yüksek öncelikli, korunan ön ad tohumuna dönüşmesi ve ürün ölçüm koşucusunun geçersiz kılma deposunu okuması (R1); kaçışın bir yetki sınırı olmaması (R2); ölçüm kipi (`blind_target = true`) ile ürün kipinin bilerek ayrışması ve pilot sayısının ürünü sertifikalamaması (R3).
  - Aşağıdaki §2.1 madde 7 ve §3.1 madde 3, bugünkü kodu ve arayüzü anlatır. Taslak uygulanırsa bu maddelerin bir kısmı kapanır; R1-R3 kapanmaz.
- **İşaretler:** **[hesap]** kaynak sayılardan aritmetik. **[tahmin]** açıkça yazılmış bir varsayıma dayanır. **doğrulanmadı** dosyadan teyit edilemedi. **[hafıza]** yalnız hafıza notunda duruyor, birincil kaynak bu incelemede okunmadı.
- Dünkü Onuncu Adam (`docs/arge/2026-11-10_n4/onuncu_adam.md`) N4 fiil ailelerini inceliyordu; buradaki itirazlar onu tekrar etmez, yalnız N4 tavanını kalan nüfusun tanımı için kullanır.

## 0. Hüküm

**U1 (güvenilir dayanak).** Uzlaşı ölçülmemiş bir şeye "güveneceğimiz yer" diyor. Bu modelin Karadul bağlamında verdiği tek bir ad bile puanlanmadı: G6 pilotu koşulmadı, kuru koşu yarıda kaldı (K-3 25/40, K-5 hiç koşmadı), ajanlı D satırı hiç kurulmadı (`pilot_protokolu.md:9`, §8.1, §15). Üstelik modelin çalışacağı nüfus ters seçilmiş: yeni ürün Mac htop'ta hiçbir fonksiyona ad vermiyor, Mac tmux'ta 395'ine veriyor (`2026-11-10_n1_adim3/ac_kapilari.json`, `fun_ad.A3`). Mac htop'ta kalan nüfus bütün nüfus demek ve onun %47,9'unda ne ithal çağrı ne dizgi var (`2026-11-11_fonksiyon_karti/envanter.md` §3.5, `icerik_adsiz`). Mac tmux'ta aynı pay bütün adsız nüfusta %40,4; yeni ürünün ad vermediği alt kümede ayrıca sayılmadı. Ekibin kendi kart envanteri bu fonksiyonlar için "boşluğu bir etiketle doldurmamalı" diyor (§5.1 son madde); KaradulLM tam olarak o etiketi üretecek. Öncü modeller bile bu görevde ortalama token F1 0,18-0,29, medyan 0, tam eşleşme %1,9-7,1 veriyor (`2026-10-15_makale/veri_setleri.md:60`, REFORGE, birincil kaynak okunmuş). "Ne iş yapıyor" açıklamasının ise hiçbir ölçüm protokolü yok: pilot `gerekce` alanını değerlendiriciye bile göstermiyor (`pilot_protokolu.md` §9.2).

**U2 (ince ayarsız, ince ayarlı gibi).** Plan, ince ayar kararını araç kullanım hatalarının ölçümüne bağlamıştı (`2026-10-17_plan_v2.md:184`). 11 Kasım kararı ölçümü beklemeden ince ayarı kaldırdı; "ince ayarlı gibi davranır" iddiası da aynı ölçümsüzlükle kuruldu. Bağlam aritmetiği bu iddiayı zorluyor: D'nin bütçesi 16K jeton ve en çok 8 araç çağrısı (§15). Tek bir tmux fonksiyonunun Ghidra C'si p90'da 5.159, p95'te 8.034 jeton (`model_secimi.md` §4.2). p95'lik bir hedef ve p90'lık tek bir komşu, sistem metni ve kanıt paketiyle birlikte ~14,5K eder **[hesap]**; örnek izlere ve araç sonuçlarına yer kalmaz. Bellek de bunu taşımıyor: 16K'da ~21-22 GB bekleniyor, kapı 20 GiB (§15). "Model dışı denetim" en çok kullanılacağı yerde boştur: kanıtla tutarlılığı denetler, ama Mac fonksiyonlarının yarıya yakınında denetlenecek kanıt yok. Tutarlılık doğruluk da değildir: dizgiden ad üreten kanallar tanım gereği kanıtla tutarlıydı ve adlarının %99,7'si yanlıştı (`urun_olcumu_taban.md:74`).

**U3 (sohbet + küçük Cursor + kart; hız yeterli).** Ölçülen hız, Cursor türü bir etkileşime yetmiyor. Düşünmesiz tek çağrı 20,4-36,4 sn, düşünmeli çağrı 95,8-102,9 sn sürdü (`pilot_protokolu.md` §8.1; makine yükü 33-45). 8 çağrılık bir ajan turu fonksiyon başına ~3 dakika, düşünmeyle ~13 dakika demek **[hesap]**. Kartı önceden hesaplamak da yerel modelle bir gecelik iş: Mac tmux'un kalan ~2.190 fonksiyonu ~15,8 saat sürer **[hesap]**. Belleğe sığan tek yapılandırma, çok turlu sohbeti hızlandıran istem önbelleğini kapatarak bulunmuştu (`model_secimi.md` K28). Arayüzün bugünkü kanıt yüzeyi de yanıltıcı: çağıran listesi adresi yalnız alan fonksiyonları da sayıyor, "neden isimsiz" kararları ve BSim satırı ölçülmemiş (`envanter.md` §0). Akıcı bir anlatıcı bu yüzeyin üstüne konursa hataları büyütür. Son olarak bugünkü ad değiştirme yolu, modelin önerisini `source: "manual", confidence: 1.0` diye kaydediyor (`karadul/core/overrides.py` `set_name`). Uzlaşının şart koştuğu "model önerisi" etiketini taşıyacak bir kod yolu yok (§4, R1).

**Uzlaşının en zayıf varsayımı:** "Model, deterministik motorun bulamadığı bilgiyi bulur." Deterministik motorun bulamadığı fonksiyonların çoğunda o bilgi ikilide yok. Model bu durumda bilgi bulmaz, akıcı bir tahmin üretir. Tahminin yanlış olduğunu da kimse göremez, çünkü denetlenecek kanıt da yoktur.

## 1. U1: "Yerel model + araçlar güvenilir ad ve açıklama üretir"

### 1.1 En güçlü karşı sav

1. **Sıfır ölçüm.**
   - G6 pilotu koşulmadı. Kuru koşu Berke'nin kararıyla durdu: K-3 sondası 25/40, K-5 bellek denemesi 0/7, Gemma hiç koşmadı (`pilot_protokolu.md:9`, §8.1).
   - Kuru koşudan çıkan tek nitelik verisi biçimle ilgili: B ve C'de 20/20 geçerli JSON, belirlenimcilik 40/40. Hiçbir adın doğruluğu puanlanmadı.
   - Ajanlı D satırı "pilottan sonra" diye bırakıldı (§15). Araç katmanı kodda yok: `karadul/`, `ui/`, `scripts/` altında `KaradulLM` geçen Python dosyası bulunamadı (bu inceleme, `grep`).
   - 11 Kasım notunun kendisi de "güveneceğimiz yer olması için adlar kör protokolle ölçülmeli" diyor (`feedback_no_llm.md`, 2026-11-11, Claude'un yorumu). Uzlaşı bu şartı sonuç gibi okuyor.
2. **Nüfus ters seçilmiş.**
   - Yeni ürünün ad verdiği fonksiyonlar: Mac htop 0, Mac tmux 395, Debian tmux 295, tree 5 (`ac_kapilari.json` `fun_ad.A3`). Mac htop'un 597 adsızının hepsi, Mac tmux'un 2.587'sinden en az ~2.190'ı modele kalır **[hesap: 2.587 − 395]**.
   - Bu kalanın kanıtı zayıf (`envanter.md` §3.5). Envanter Mac ikililerinde taban koşusunu okudu, yani bütün jenerik fonksiyonları saydı (`envanter.md` girdi notu). Mac htop'ta yeni ürün hiç ad vermediği için sayılar kalan nüfusa doğrudan uyar. Mac tmux'ta kalan ~2.190 fonksiyondaki pay ölçülmedi (Codex'in uyarısı, §7):

     | | Mac tmux | Mac htop | Debian tmux |
     |---|---|---|---|
     | İthal çağrı da dizgi de yok (`icerik_adsiz`) | 1.046 (%40,4) | 286 (%47,9) | 681 (%35,5) |
     | Çağıranı yok | 787 (%30,4) | 216 (%36,2) | 629 (%32,8) |
     | Çağıranı yok ve `icerik_adsiz` | 307 (%11,9) | 99 (%16,6) | 220 (%11,5) |
     | Ayırt edici ithal çağrı var | 519 (%20,1) | 138 (%23,1) | 374 (%19,5) |

   - Kolay vakaları deterministik kanallar alıyor. KS-1'in `func_kalibi` satırı Mac tmux'ta adı dizgiden okuyarak 150 fonksiyona %95,3 kesinlikle ad veriyor (`docs/arge/2026-10-21_g11_n1/ks1_olcum.md:43`). Pilotta adını dizgide taşıyan "öz-ad" katmanı htop'ta 0, tmux'ta 256 fonksiyondu (`pilot_protokolu.md` §12 madde 5.1). Model bütün nüfusta ölçülürse sonucu bu kolay katman şişirir. Ürün ise modeli yalnız kalan zor nüfusta çalıştıracak.
3. **Darboğaz model değil, girdinin bilgisi.**
   - REFORGE'da, aralarında Claude Sonnet 4.5, GPT-5.1 ve Qwen3 Coder'ın bulunduğu 7 model ortalama token F1 0,18-0,29, medyan 0, tam eşleşme %1,9-7,1 veriyor (`2026-10-15_makale/veri_setleri.md:60`; birincil kaynak sayfası okunmuş).
   - Aynı makalenin "zorluk modelin kapasitesinden değil, decompile edilmiş girdinin bilgi içeriğinden geliyor" bulgusu ve modellerin hangi fonksiyonun zor olduğunda uyuştuğu (Kendall W 0,66-0,77) **[hafıza]** (`karadul-llm-olcek-literatur.md` §2). Doğruysa 27B'lik yerel model bu tavanın altında kalır. Araç vermek de girdinin bilgisini artırmaz (U2).
4. **Dizgiler yanıltıyor.**
   - Deterministik ürünün dizgiden ad üreten dokuz alt kanalı 4.321 ad verdi, 14'ü doğruydu (%0,3; `urun_olcumu_taban.md:74`; tam eşitlik ölçütü). Yakın ölçütle ölçülmedi.
   - Kanıt paketinde modelin adı söyleyen başlıca ipucu dizgi: en çok 40 dizgi, her biri 120 karakter (`pilot_protokolu.md` §3.2).
   - Modelin bu dizgilerden deterministik kurallardan daha iyi ad çıkaracağına dair veri yok. Ad üretmeye zorlanırsa doğal davranışı hata iletisinden ya da biçim dizgisinden ad türetmektir; bu bir tahmindir **[tahmin]**, ama ölçülen tek emsal %0,3.
5. **Ezber ve alan kayması.**
   - Geliştirme seti ünlü açık kaynak (htop 3.5.3, tmux 3.8). Qwen3.8'in deposu 2026-08-05'te açıldı, eğitim kesimi beyan edilmedi (`model_secimi.md` §0). Pilot ezberi ölçülmeyen bir yanlılık sayıyor (§12 madde 6, §16).
   - Ezberi temizleyen görülmemiş dilim plana göre G31'de açılacak (§11.3). Ürünün asıl kullanımı (kapalı kaynak, kötü amaçlı yazılım) ezber desteğinden tümüyle yoksun.
6. **"Ne iş yapıyor" açıklaması ölçülemiyor.**
   - Pilotta açıklama alanı (`gerekce`, en çok 30 sözcük) değerlendiriciye gösterilmiyor; yalnız hata analizinde kullanılıyor (§9.2). Açıklama için rubrik yok.
   - Harness `gerekce` metin değilse onu `None` yapıyor ve adı yine geçerli sayıyor (`scripts/measurement/llm_pilot.py:544-556`). Yani pilotun geçerlilik kapısı açıklama istemiyor bile (Codex).
   - Amaç cümlesini yazan da bir LLM (Opus vekili, §9.4). Literatürde LLM yargıcın uzman yargısıyla ortalama korelasyonu %63 (§9.4, `model_secimi.md` K25).
   - Kanıt paketi çağrıları, dizgileri ve sabitleri taşıyor (`evidence.py:34-48`). Açıklamanın fonksiyonun ana yolunu anlattığını, hata dalındaki bir yardımcıyı anlatmadığını gösteren bir şey taşımıyor. Hata dalındaki dizgiyi ve yardımcıyı gören model, yan işi asıl iş diye anlatabilir; aynı paketi okuyan denetim çelişki bulamaz (Codex'in çöküş senaryosu, §7).
   - Karadul'un bugünkü ölçülmemiş açıklayıcı katmanlarının sicili kötü: "OpenGL" 119/119 ikilide, kripto sahte pozitifi tabanda 8.666 fonksiyon, tree'de CFD ve roket simülasyonu bileşimi (`envanter.md` §5.2). Modelin açıklaması da aynı sınıftan, ölçülmemiş ama akıcı bir metin.

### 1.2 En olası çöküş senaryosu

1. Araştırmacı Mac htop'ta `icerik_adsiz` bir fonksiyon açar: ithal çağrı yok, dizgi yok, Ghidra'da çağıranı yok (büyük olasılıkla bir veri tablosundan çağrılıyor; `envanter.md` §3.6). Mac htop'ta bu türden 99 fonksiyon var (§1.1 tablosu).
2. Modelin elindeki tek şey gövde ve komşuların `FUN_` adresleri. Model akıcı, alana uygun bir ad ve iki cümlelik açıklama üretir.
3. Model dışı denetimin karşılaştıracağı API ya da dizgi olmadığı için uyarı çıkmaz.
4. Araştırmacı adı kabul eder. Ad, bugünkü kod yoluyla elle verilmiş ad olarak saklanır (§4, R1).
5. Sonraki analizde bu ad en yüksek öncelikli ön ad olarak hatta girer. Komşu fonksiyonların kanıt paketinde "adlı komşu" olarak görünür.
6. Model komşulara bu temayla uyumlu adlar verir. Sonuç, çağrı grafiğinde birbirini doğrulayan **tutarlı ama yanlış bir ad kümesi** olur. Tek tek bakınca her ad makul görünür.

### 1.3 En ucuz çürütme ya da doğrulama deneyi

- **Ön koşul:** Pilotun kendi kuralı; kuru koşunun eksik kapıları tamamlanır: K-3'ün kalan 15 çağrısı, K-5'in 7 çağrısı (`pilot_protokolu.md` §8.1). Model zamanı ~15-20 dakika **[hesap: 15 × ~34 sn + 5 × ~26 sn + 2 × ~100 sn ≈ 14 dk; en uzun istemler daha yavaş, o yüzden üst pay]**.
- **Veri:** Pilotun hazır ana örnekleminden (§2.4.1), yeni ürünün (A3) ad vermediği fonksiyonlar: 75 Mac htop + 75 Mac tmux. Hepsi geliştirme seti.
- **Koşul:** Yalnız C-Ç (kanıt paketi + çekimser kalabilir). B, düşünme kipi ve belirlenimcilik tekrarı yok. Model zamanı 150 × 25,9 sn ≈ 1,1 saat **[hesap; C-Ç ortalaması §8.1]**.
- **Ölçü:** Rubrik v2 ile kör etiketleme (§9). Ana sayı: yanlış ≤ %10 iken yakın kapsam (çapraz eşik, §10.4).
  - Katmanlar ayrı raporlanır: `icerik_adsiz` / öbürleri; öz-ad dizgisi / öbürleri.
  - Açıklama için ek etiket: amaç cümlesine göre `dogru` / `kismen` / `yaniltici`.
- **Uzlaşıyı yanlışlayan eşik (öneri; karar Berke'nin):**
  - kalan nüfusta yanlış ≤ %10 iken yakın kapsam < %20 (makro), **ya da**
  - `icerik_adsiz` katmanında ad verilenlerde yanlış oranının Wilson alt sınırı > %10, **ya da**
  - açıklamaların `yaniltici` payı > %15.
  - Biri tutarsa "güveneceğimiz yer" iddiası düşer. Model en çok ölçülen katmanda, "model önerisi" etiketiyle kalır.
- **Codex'in çeşitlemesi:** 10 birimin her birinden 10'ar, toplam 100 kalan fonksiyon (Mac ve Debian birlikte). Amaç cümlesi kaynaktan, model çıktısı görülmeden kilitlenir. Ad ile açıklama ayrı puanlanır; "davranışı yanlış anlatan açıklama" ayrı bir yanlış türü sayılır. Bu çeşitleme program çeşitliliği kazandırır, ama htop'ta örneklem 10'a düşer.
- **Daha da ucuz ön deney (aynı veri, 0 yeni etiket):** C-Ç çıktısında çekimser kalma oranı katmana göre sayılır. `icerik_adsiz` katmanında çekimser oranı öbür katmandan düşük ya da ona eşitse, model bilgisizliğini tanımıyor demektir: kanıt azaldığında çekimser kalmıyor, ad vermeyi sürdürüyor.

## 2. U2: "İnce ayarsız, istem + araç sözleşmesi + izler + bağlam yönetimi + denetimle ince ayarlı gibi"

### 2.1 En güçlü karşı sav

1. **Karar ölçümü atladı.** Plan: "Önce ince ayarsız taban ölçülür (G6 pilotu); ince ayara ancak araç kullanım hataları ölçülürse geçilir" (`2026-10-17_plan_v2.md:184`). Pilotun D satırı, ince ayar kararının girdisi olarak araç kullanım hatalarını sayacaktı (§15 "Ölçüler"). Hiçbiri yapılmadan ince ayar kaldırıldı ve "ince ayarlı gibi davranır" denildi. İki yönde de veri yok.
2. **Bağlam bütçesi aritmetiği.**

   | Kalem | Jeton | Kaynak |
   |---|---|---|
   | D bütçesi | 16K (bellek aşarsa 12K) | `pilot_protokolu.md` §15 |
   | Sistem metni | 309-318 | `model_secimi.md` §4.2 |
   | Kanıt paketi | ortalama 182-250, p99 751-1.065 | §4.2 |
   | Ghidra C, tmux | ortalama 2.398, medyan 1.197, p90 5.159, p95 8.034 | §4.2 (Gemma jetonlayıcısı; Qwen %1-2 az) |
   | Ghidra C, htop | ortalama 1.959, p90 4.009, p95 6.311 | §4.2 |

   - p95 hedef + p90 komşu + sistem + paket ≈ 8.034 + 5.159 + 318 + 1.065 ≈ 14.576 **[hesap]**. 16K'nın %89'u, iki çağrıda doluyor. Araç şeması, örnek izler, araç sonuçlarının sınırlama alanları ve yanıt bütçesi buna eklenir.
   - Bağlam yönetimi bu durumda budamak demek. Budanan şey ajanın az önce getirdiği kanıt. Ajanın sabit pakete (C) göre üstünlüğü tam bu ek kanıttan gelmeliydi.
3. **Bellek ve önbellek çelişkisi.**
   - 8K'da tepe 17,63 GiB (§8.1). 16K'da ~21-22 GB bekleniyor (§15), kapı 20 GiB.
   - LM Studio'nun öntanımlıları (`--cache-ram` 8.192 MiB, 32 bağlam kontrol noktası) 4 çağrıda RSS'i 20,1 GiB'a çıkardı. Belleğe sığan yapılandırma ikisini de kapattı (`model_secimi.md` K28).
   - Çok turlu ajan istem önekini yeniden kullanarak hızlanır. Qwen3.8 karma bir mimari (Gated DeltaNet + dikkat; `model_secimi.md` §0.1, Qwen3.6 satırı, "aynı mimari ailesi" §3.1). Kontrol noktası olmadan, ortadan budanan bir geçmiş öneki geçersiz kılar ve bütün bağlam yeniden işlenir **[tahmin; llama.cpp davranışı bu depoda doğrulanmadı]**. 16K / ~195 jeton/sn ≈ 84 sn önek işleme, tur başına **[hesap; önek hızı Qwen3.6 ölçümü, §4.1]**.
4. **Düşünme kipi belirlenimciliği bozuyor.**
   - Ajan işleri genelde düşünme ister. Açgözlü çözmeyle düşünme kuru koşuda 2/2 çağrıda döngüye girip bütçeyi doldurdu. Bu yüzden düşünme kipi sıcaklık 1,0 ile örnekleniyor ve belirlenimcilik denetimi yalnız düşünmesiz B ve C'de yapılıyor (§0.1, §6).
   - Düşünmeli 4 çağrının 2'si zorunluyken çekimser kaldı (§8.1; n = 4, sonuç değil işaret).
   - Sonuç: güvenilen katman, Karadul'un ayırt edici özelliği olan yeniden üretilebilirliği taşımaz. Aynı fonksiyon iki kez sorulunca iki ayrı ad gelebilir.
5. **Örnek izler geliştirme setinden sızar.** P1 istemindeki örnek ad (`window_resize`) ve adresler geliştirme setinde gerçekti; P2 tam bu yüzden yazıldı (§4, P1 → P2). Örnek izler htop/tmux'tan kurulursa geliştirme setindeki ölçüm kirlenir. Test setinden kurulamaz (`2026-10-17_plan_v2.md:184`). Üçüncü bir derlem yok.
6. **Model dışı denetim tutarlılık denetler, doğruluk değil.**
   - Tanımlanan tek denetim örneği: ağ çağırmayan fonksiyona `send_packet` önerilirse uyarı (`feedback_no_llm.md`, 2026-10-15).
   - `icerik_adsiz` fonksiyonlarda (Mac %40-48) karşılaştırılacak API ya da dizgi yok; denetim boş geçer.
   - Kanıtla tutarlı ama yanlış ad bu denetimden geçer. Dizgi kanalları kanıttan türediği için tanım gereği tutarlıydı ve %99,7 yanlıştı (`urun_olcumu_taban.md:74`).
7. **Araçların kendisi gürültülü.** "Araçları güvenilir kullanmak" araçların güvenilir olduğu anlamına gelmez:
   - alan kapısı açılırsa `rc4` etiketi Mac htop fonksiyonlarının %99,2'sine yapışıyor (`fizibilite.md`, Deney 2);
   - derin izleyici `FUN_` köklerini budadığı için strip'li ikilide iz üretmiyor (`fizibilite.md` §7);
   - arayüzün çağıran listesi adresi alan fonksiyonları da sayıyor (`ui/server.py:244`; `envanter.md` §0: adsızların %36,6-61,6'sı);
   - BSim gölge adaylarının Mac'te %92-93'ü incelenen programla aynı adlı programdan geliyor; GT sızıntısı mı döngüsel kanıt mı olduğu bilinmiyor (`envanter.md` §0 madde 2).
   - Bu araçlardan biri modele açılırsa model onu güvenle kullanır. Tek fark, hatanın arkasına akıcı bir gerekçe eklenmesi olur.
8. **Takılabilir arka uç istem mühendisliğini taşımaz.** 11 Kasım'da kabul edildi: isteyen araştırmacı kendi OpenAI uyumlu ucunu bağlar (`feedback_no_llm.md`). İstem, şablon ve düşünme denetimi modele özgü:
   - Qwen `enable_thinking`, Gemma `reasoning_effort` (§0.1);
   - Gemma'nın düşünme kanalı ayrıştırıcıda ayrıca düzeltilmek zorunda kalındı (§0.2);
   - LM Studio'da `chat_template_kwargs` Qwen3.8'de etkisiz (`model_secimi.md` K27).
   - Qwen3.8 üzerinde "ince ayarlı gibi" yapılan iş başka uçta ölçülmemiş bir davranıştır. Birincil model de QAT değil, eğitim sonrası Q4_K_M; nicemleme kaybı bu makinede ölçülemiyor (`model_secimi.md` §10).

### 2.2 En olası çöküş senaryosu

1. p95 boyutlu bir tmux fonksiyonunda ajan hedefi decompile eder (~8K).
2. Çağıranı da decompile eder (~5K). Bağlam dolar.
3. Bağlam yöneticisi ilk araç sonucunu kırpar. Ajan hedefin kırpılmış gövdesini yeniden ister.
4. Döngü 8 çağrı bütçesini tüketir. Son ad son getirilen komşudan türetilir.
5. Önek her budamada geçersiz kaldığı için tur başına ~1,5 dakika önek işleme biner **[tahmin]**.
6. Kullanıcı bir fonksiyon için birkaç dakika bekler ve tutarsız bir ad alır. Aynı soruyu yinelediğinde düşünme kipinin örneklemesi yüzünden başka bir ad alır.

### 2.3 En ucuz deney

- **Veri:** §1.3'teki 150 fonksiyonun ilk 25 + 25'i. Önce en kısa ajan sözleşmesi kurulur: üç salt okunur araç (decompile, xref, kanıt paketi); yazan araç yok.
- **Koşullar:** D ve C-Ç aynı fonksiyonlarda. D iki kez koşar (yeniden üretilebilirlik). Aynı istemle Gemma 4 26B-A4B'de de bir kez koşar (taşınabilirlik).
- **Ölçü:** Çağrı başına: şema geçersizliği, var olmayan araç ya da argüman, aynı çağrının yinelenmesi. Fonksiyon başına: bağlam ya da bütçe aşımı, son JSON geçerliliği, iki koşuda aynı son ad, D − C-Ç yakın kapsam farkı.
- **Bozulma kolu (Codex'in önerisi):** Aynı görevler, araç yanıtları bozulmuş kopyalarla yeniden oynatılır: boş sonuç, çelişkili sonuç, pakete eklenmiş yanlış bir hedef adı. Sayılan hata: boş araç sonucunu "bilgi alınamadı" yerine "böyle bir davranış yok" diye okuyup kesin hüküm vermek; yanlış hedef adını onaylamak. Ürünün `_evidence` çıktısı hedefin o anki adını taşıdığı için (`ui/server.py:668`) bu kol üründeki davranışa pilottan daha yakındır.
- **Model zamanı:** 50 × 8 tur × ~25 sn ≈ 2,8 saat, iki koşu ve Gemma ile ~6-7 saat **[tahmin]**. Önce 10 fonksiyonluk kuru koşu: eşikleri o bile çiğniyorsa gerisi koşulmaz.
- **Uzlaşıyı yanlışlayan eşik (öneri):**
  - geçersiz ya da uydurma araç çağrısı > %5 (çağrı başına), **ya da**
  - fonksiyonların ≥ %10'unda bağlam ya da bütçe aşımı, **ya da**
  - D − C-Ç yakın kapsam farkı ≤ +5 puan ya da GA sıfırı içeriyor (araçlar sabit pakete bir şey katmıyor), **ya da**
  - iki koşuda aynı son ad < %90, **ya da**
  - Gemma'nın aynı istemle araç hata oranı Qwen'inkinin 2 katından fazla ("ince ayarlı gibi" davranış modele özgü), **ya da**
  - bozulma kolunda görevlerin > %5'inde eksik kanıttan kesin hüküm, ya da tek bir onaysız yazma eylemi (Codex'in eşiği).

## 3. U3: "Sohbet + küçük Cursor + fonksiyon kartı net fayda sağlar; yerel model yeterince hızlı"

### 3.1 En güçlü karşı sav

1. **Hız, ölçülen sayılarla.**

   | Ne | Süre | Kaynak |
   |---|---|---|
   | Düşünmesiz tek çağrı (kuru küme) | 20,4-25,9 sn | `pilot_protokolu.md` §8.1 |
   | Düşünmesiz tek çağrı (sonda) | 31,7-36,4 sn | §8.1 |
   | Düşünmeli tek çağrı | 95,8-102,9 sn | §8.1 |
   | Üretim hızı (Qwen3.6-27B 4 bit, aynı makine sınıfı) | ~20 jeton/sn | `model_secimi.md` §4.1 |
   | 300 jetonluk sohbet yanıtının yalnız üretimi | ~15 sn | **[hesap]** |
   | 8 çağrılık ajan turu, düşünmesiz / düşünmeli | ~2,7-3,5 dk / ~13-14 dk | **[hesap; tur ≈ tek çağrı varsayımı]** |
   | Kartı önceden hesaplama, Mac tmux (~2.190 adsız × 25,9 sn) | ~15,8 sa | **[hesap]** |
   | Kartı önceden hesaplama, Mac htop (597 × 25,9 sn) | ~4,3 sa | **[hesap]** |

   - Süreler 33-45 yük ortalamasında alındı; boş makinede daha kısa olabilir. Ama ürün de Ghidra ve Karadul hattıyla aynı makinede koşacak.
   - "Küçük Cursor" saniyelik bir döngü varsayar. Ölçülen sayı, en basit kipte bile çağrı başına yarım dakika.
2. **Bellek, aynı makinede Ghidra ile birlikte.**
   - Model 16,4-17,6 GiB (8K bağlam); 16K'da ~21-22 GB beklentisi (§15).
   - Tek Ghidra süreci 4 GB yığınla ölçüldü (`fizibilite.md` §4). Makine 36 GB (`model_secimi.md` §1.1).
   - 20 GB bütçesi zaten "Ghidra aynı anda çalışabilir" diye konmuştu (§1.1). LM Studio ile yapılan ilk kuru koşuda 6,9 GB takas ya da sıkıştırılmış bellek görüldü (K28).
   - Sohbet paneli açıkken analiz koşturan bir araştırmacı bu bütçeyi aşar **[tahmin]**.
3. **Kartın yüzeyi bugün yanıltıcı; model onu büyütür.**
   - Çağıran listesi Ghidra'nın çağrı kenarı değil, gövdede geçen her `FUN_` adı (`ui/server.py:244`). Adsızların %36,6-61,6'sında adresi yalnız alan bir fonksiyon "çağıran" diye görünüyor (`envanter.md` §0).
   - "NEDEN İSİMSİZ?" satırındaki ikili geneli füzyon cümlesi adsızların %100'ünde çıkıyor. `app_specific` ve `app_wrapper` kararları ölçülmemiş (`ui/server.py:587-642`; `envanter.md` §0). `app_wrapper` kararı imza veritabanının tanıdığı tek bir dış çağrı bulununca veriliyor (`ui/server.py:632-636`). Dış fonksiyon çağırmak sarmalayıcı olmayı kanıtlamaz (Codex).
   - Arayüzün kanıtı (`ui/server.py` `_evidence`) pilotun kanıt paketinden (`evidence.py`) farklı (§4, R3). Model bu yüzeyden beslenirse hatalı olguları akıcı bir anlatıya çevirir.
4. **Etiket kodda yok.** Uzlaşının kendi şartı "model önerisi etiketi, kesin adı ezmez" (`feedback_no_llm.md`). Bugünkü tek ad yazma yolu `_do_rename` → `overrides.set_name` ve kaydı `source: "manual"`, `confidence: 1.0` diye yazıyor (`karadul/core/overrides.py` `set_name`; `ui/server.py:680-719`). "Küçük Cursor" yazma eylemini bu yoldan yaparsa model önerisi elle verilmiş ad olur (R1).
5. **Fayda ölçülmedi.** Kartın ya da sohbetin araştırmacının hızını ya da doğruluğunu artırdığına dair hiçbir ölçüm yok. Kart envanteri, adı söyleyen kanıtı olmayan fonksiyonlar için kartın açıkça "kanıt yok, komşulara bak" yazmasını öneriyor (`envanter.md` §5.1). Model bu dürüst boşluğun yerine akıcı bir tahmin koyar. Otomasyon yanlılığı, yani kullanıcının akıcı öneriyi denetlemeden kabul etmesi, ölçülmeden fayda sayılamaz.

### 3.2 En olası çöküş senaryosu

1. Araştırmacı Mac tmux'u analiz ediyor; Ghidra aşaması 716 sn sürüyor (`fizibilite.md` §4).
2. Bu sırada sohbeti açıp yan panelden "bu fonksiyonları adlandır" der.
3. Model yüklenir (~17 GiB), Ghidra JVM ve Karadul hattıyla aynı belleği paylaşır. Takas başlar, iki iş de yavaşlar.
4. İlk yanıt dakikalar sonra gelir. Araştırmacı ya paneli kapatır ya da hız için önerileri toplu kabul eder.
5. Toplu kabul yüzlerce model adını `manual / 1.0` olarak geçersiz kılma deposuna yazar. Sonraki analizde bu adlar en yüksek öncelikli ön ad olarak hatta girer (R1).

### 3.3 En ucuz deney

- **Önce modelsiz fayda sınaması (Codex'in önerisi; en ucuzu):**
  - Saklı yanıtları ve gerçekte ölçülmüş gecikmeleri oynatan bir prototip kurulur. Model koşmaz.
  - Üç akış karşılaştırılır: bugünkü arayüz, yalnız kanıt kartı, kart + sohbet. Aynı geliştirme görevleri akışlara dengeli dağıtılır.
  - Doğru sonuca kadar geçen süre ölçülür. Bekleme, elle doğrulama ve yanlış yönlendirmeden geri dönüş bu süreye dahildir.
  - Kart + sohbet akışı burada kazanmazsa gecikme ve bellek ölçümüne gerek kalmaz.
  - Oynatılacak yanıtlar §1.3 deneyinin kayıtlı çıktılarıdır. Uydurma yanıt kullanılmaz; o deney koşulmadan bu sınama da koşulmaz.
- **Gecikme ve bellek sınaması (yalnız fayda sınamasını kazanan akış için):** Mac tmux üzerinde aynı anda Karadul analizi (Ghidra) koşarken:
  - 20 kart isteği (C-Ç tek atış);
  - 16K bağlama kadar büyüyen, 6 turluk 5 sohbet.
  - Ölçü: kartta ilk yanıta kadar geçen süre (p50, p95); sohbet turu süresi; pilotun `bellek_ust_gb` ölçüsü; takas artışı (`vm_stat`).
- **Uzlaşıyı yanlışlayan eşik (öneri):**
  - kart p50 > 30 sn ya da p95 > 90 sn, **ya da**
  - sohbet turu p50 > 45 sn, **ya da**
  - tepe bellek > 20 GiB (pilotun K-5 kapısı) ya da takas artışı > 1 GB.
- **Küçük kullanıcı sınaması (fayda):**
  - 20 adsız Mac htop fonksiyonu; araştırmacı yarısını yalnız deterministik kartla, yarısını kart + modelle adlandırır (dengeli sıra).
  - Sonra adlar rubrik v2 ile kör puanlanır.
  - Uzlaşıyı yanlışlayan sonuç: model koşulunda kabul edilen yanlış ad oranı modelsiz koşuldan düşük değil, **ya da** süre kazancı < %30.
  - Kimin yapacağı pilotta da açık (§17 madde 3). Tek bir araştırmacıyla sonuç kişiye bağlı kalır; en az iki değerlendirici gerekir.

## 4. Ekibin görmediğini düşündüğüm beş risk

**R1. Etiket aklanması ve hattın kirlenmesi (kodla doğrulandı).**
- Arayüzden verilen ad iki yere yazılır: `naming_map.json` `global` ve `~/.karadul/overrides/<hash>.json`. Kayıt `source: "manual"`, `confidence: 1.0` taşır (`ui/server.py:680-719`; `karadul/core/overrides.py:166-194`).
- Sonraki analizde `_apply_manual_overrides` bu adları ön ad tohumu yapar ve birleştirmeden sonra haritaya zorlar (`karadul/stages.py:2948-3044`). Künyesi `KIND_MANUAL` olur (`stages.py:2634-2637`).
- `KIND_MANUAL` öncelik sırasında birinci. Tam ad türleri arasında: temizlenmeden yazılır. Korunan türler arasında: KS-1 bile üzerine yazamaz (`karadul/reconstruction/tarif/baglama.py:67-76`).
- c_namer bu adı 0,95 güvenle ve etiketsiz yazar (`karadul/reconstruction/c_namer.py:2236-2290`).
- Ölçüme sızma yolu: ürün ölçüm koşucusu `scripts/measurement/urun_kos.py` ortamı olduğu gibi devralıyor (`os.environ`, satır 88, 110) ve geçersiz kılma deposunu kapatmıyor (dosyada `override` geçmiyor). `alt_kanal.py` yalnız deponun dolu olup olmadığını künyeye yazıyor (`:574`, `:600`).
- Sonuç: araştırmacı geliştirme setindeki bir ikiliyi (tmux, htop) arayüzde KaradulLM ile gezip öneri kabul ederse, aynı sha256'lı ikilinin sonraki ürün ölçümü model adlarını "LLM'siz" sonuç olarak sayar. Makale kuralı ("makalede yalnız LLM'siz sonuçlar") sessizce çiğnenir.
- Bugün depo boş (`~/.karadul/overrides` 0 dosya); risk henüz gerçekleşmedi. KaradulLM kodu da yok; risk, "küçük Cursor"un yazma eylemini bugünkü ad değiştirme yolundan yapması koşuluna bağlı (Codex: "KaradulLM bağlantısı doğrulanmadı").
- Geri aldıracak sonuç: öneri → kabul → yeniden analiz zincirinin her adımında model kökeni korunuyor, sessiz köken yükseltmesi 0. Ürün ölçüm koşucusu geçersiz kılma deposunu yok sayıyor ya da doluysa koşuyu durduruyor.

**R2. İkilinin dizgilerinden istem enjeksiyonu.**
- `evidence.py` `strings_used` değerlerini süzmeden pakete koyuyor (satır 94). Arayüz 20 dizgiyi 160 karaktere kadar gösteriyor (`ui/server.py:491-502`).
- Pilot harness'ı dizgileri JSON kaçışıyla ve 120 karakterde keserek yazıyor (`scripts/measurement/llm_pilot.py:454-460`). Kaçış, metni talimattan ayıran bir yetki sınırı değildir (Codex).
- Kötü amaçlı yazılımda dizgileri saldırgan yazar. "Küçük Cursor" yazan araçlar (ad değiştirme, yorum, toplu uygulama) taşırsa, ikilideki bir metin modele eylem yaptırabilir.
- `_do_rename` yalnız C tanımlayıcı biçimini denetliyor (`ui/server.py:687`).
- Talimatsız saldırı daha sinsi: modeli yanlış ada iten bir dizgi (ör. `send_packet` içeren bir biçim dizgisi) model dışı denetimi de geçer, çünkü denetim dizgiyi kanıt sayar.

**R3. Kör ölçüm ile ürün yüzeyinin ayrışması.**

| | Pilot (C, D) | Ürün (`ui/server.py` `_evidence`) |
|---|---|---|
| Çağıranlar | Ghidra xref (`evidence.py:93`) | gövdede geçen her `FUN_` (`server.py:244`) |
| Dizgiler | en çok 40 × 120 karakter (§3.2) | en çok 20 × 160 karakter (`server.py:491`) |
| Hedefin Karadul adı | gizli (§3.1, Berke'nin körlük kararı) | `current_name` alanında açık (`server.py:668`) |
| Ölçülmemiş ekler | yok | BSim gölge adayı, "NEDEN İSİMSİZ?" kararları (`server.py:587-642`) |

- Pilot bunu kendisi yazıyor: "Üründeki davranış farklı olabilir" (§15).
- Hedefin adını gören model "bu ad doğru mu" kipine kayar. Bu kipin onaylamaya yatkın olduğu 15 Ekim'de kayda geçmişti (`feedback_no_llm.md`).
- Pilotun sayısı ürünü sertifikalamaz. İkisini aynı yapmak bir tasarım şartı olmalı.

**R4. Komşu adını papağanlama ve tutarlı yanlış küme.**
- Komşu adları hedefin adına sızıyor. Pilotun sızıntı sayımında tmux'ta 8 fonksiyonda komşunun Karadul adı hedefin gerçek adıyla aynıydı (§12 madde 5.1).
- Pilotun kanıt sızıntısı denetimi `[proven: …]` ve `[inferred: …]` etiketlerini taramadan önce siliyor (`scripts/measurement/llm_pilot.py:472-476`). Bu bilinçli bir seçim: komşu adı meşru kanıt sayılıyor ve ayrı bir katmana yazılıyor. Ama "kanıt paketinde 0 sızıntı" sonucu, komşu adını kopyalayarak gelen isabetleri kapsamaz. Papağanlık bu sonucun içinde görünmeden kalabilir (Codex).
- Ucuz ablasyon: §1.3'ün çıktısında komşu adları (a) maskelenmiş, (b) başka fonksiyonların adlarıyla karıştırılmış iki kopya. Karıştırılmış kopyada model adının, araya sokulan komşu adıyla jeton paylaşma oranı ölçülür. Yanlış komşudan gelen ek yanlış oranı > %5 ise model komşu adını büyütüyor demektir.
- SymGen, çağrılan adlarını maskelemek zorunda kalmış, çünkü sinyal ölçümü bozacak kadar güçlüymüş **[hafıza]** (`karadul-llm-olcek-literatur.md` §4).
- R1 ile birleşince model adları komşu paketlerine "adlı komşu" olarak girer. Hatalar çağrı grafiği boyunca kendini doğrular.
- BSim gölge adayları bir araçla modele açılırsa ve gerçekten GT sızıntısıysa (envanter §0 madde 2), geliştirme setinde model olağanüstü görünür, sahada çöker. Sözleşme taslağı BSim'i bugün dışarıda tutuyor (`arac_sozlesmeleri.md:79`, `:85`); bu madde yalnız o karar gevşerse geçerli.

**R5. Yeniden üretilebilirlik kaybı ve sürdürme maliyeti.**
- Düşünme kipi örnekleniyor (sıcaklık 1,0; §0.1). Ürün "deterministik, yeniden üretilebilir" diye konumlanıyor (`feedback_no_llm.md`, "DOKUMENTASYON"). Güvenilecek katman bu özelliği taşımıyor.
- LM Studio motorları kendiliğinden güncelliyor: 2026-10-19 sabahı 2.50.0 → 2.60.0 (`model_secimi.md` §1.2, §11 madde 4).
- Sohbet şablonu sha256'ya sabitlenmek zorunda kalındı (§6).
- Ürün ayrıca şunları taşımak zorunda: 16,8 GB model, `llama-server` ikilisi (bugün PATH'te yok; `karadul-plan-v2.md` hafıza, 2026-11-11), şablon kopyası, bellek bekçisi.
- Takılabilir uçların her biri ayrı kuru koşu ister (§2.1 madde 8). Bunlar Karadul'un deterministik çekirdeğinin hiç taşımadığı, sürekli bir bakım yüküdür **[tahmin: yükün büyüklüğü ölçülmedi]**.

## 5. Yanılıyorsam beni ne ikna eder

| Madde | İtirazı geri aldıracak ölçüm |
|---|---|
| U1 | §1.3 deneyinde kalan nüfusta (≥ 150 fonksiyon, iki Mac programı) yanlış ≤ %10 iken yakın kapsam ≥ %25 (çapraz eşik, makro); `icerik_adsiz` katmanında yanlış ≤ %15; açıklamalarda `yaniltici` ≤ %10. İnsan denetimli alt kümede (≥ 30) vekil ile insan arasında yakın / yakın değil uyumu ≥ %80. Görülmemiş dilim açıldığında yakın kapsam ≤ 10 puan düşer (sonucu ezber taşımıyor) |
| U2 | İnce ayarsız D'de geçersiz araç çağrısı ≤ %2; bağlam ya da bütçe aşımı ≤ %5 fonksiyon; D − C-Ç ≥ +10 puan yakın kapsam ve GA'nın alt sınırı > 0; iki koşuda aynı son ad ≥ %95; dizgiye gömülü 20 talimat sondasında 0 yazma eylemi; Gemma'nın aynı istemle hata oranı Qwen'in en çok 1,5 katı |
| U3 | Ghidra koşarken kart p50 ≤ 30 sn, p95 ≤ 90 sn; sohbet turu p50 ≤ 30 sn; tepe bellek ≤ 20 GiB ve takas artışı < 1 GB. Kullanıcı sınamasında model koşulunda kabul edilen yanlış ad oranı modelsiz koşuldan düşük ya da ona eşit, süre kazancı ≥ %30 |

Bir satırdaki ölçütlerin hepsi tutarsa o maddedeki itirazımı geri çekerim. Üç satır da tutarsa uzlaşı haklıdır. R1-R5 için ayrıca: köken zinciri korunuyor (R1), dizgiye gömülü talimatlarla 0 yetkisiz eylem (R2), pilot ile ürün aynı kanıt yüzeyini kullanıyor (R3), komşu adı karıştırma ablasyonunda ek yanlış ≤ %5 (R4), desteklenen her model ve çalıştırıcı profili U2 kapılarını ayrı ayrı geçiyor (R5).

## 6. Uzlaşının yerine iki seçenek

**S1. Önce LLM'siz kanıt kartı; model toplu, kör ve çekimser, ayrı dosyada; sohbet ölçümden sonra.**
- **Kart:** `envanter.md` §5.1'deki olgu satırları; model içeriği yok.
- **Model:** Yalnız C-Ç tek atış, analiz bittikten sonra toplu ve gece koşusu olarak. Çıktı ayrı bir `model_onerileri` dosyasına yazılır; ad alanına değil, kartın "model önerisi" satırına gider.
- **Etiket:** Kabul edilen öneri için `elle`den ayrı yeni bir köken türü (`model`). Ölçüm koşucuları bu türü ve geçersiz kılma deposunu yok sayar (R1).
- **Kapsam:** Model yalnız §1.3'te eşiği geçen katmanlarda açılır, ör. ayırt edici ithal çağrısı olanlar. `icerik_adsiz` katmanında kapalı kalır.
- **Maliyet:** §1.3 deneyi (~1,1 saat model zamanı + 150 öğe etiketleme). Köken türü ve ölçüm koruması küçük bir kod işi **[tahmin]**. Kart işi envanterde tanımlı.
- **Feda edilen:** İlk sürümde sohbet ve "küçük Cursor" yok. Mac fonksiyonlarının yarıya yakınında model susar. "Güveneceğimiz yer" iddiası ölçülen katmanla sınırlı kalır.

**S2. Önce tavan deneyi; tavan tutmazsa KaradulLM ad üretmez, kanıt gezgini olur.**
- **Tavan deneyi:** §1.3'ün aynı 150 fonksiyonunda aynı C-Ç istemi, takılabilir uç üzerinden bir öncü modelle koşulur. Geliştirme seti açık kaynak olduğu için gizlilik sorunu yok.
- **Mantık:** Pilot "yerel model sonucu öncü modele genellenmez" diyor (§11.2). Ters yön daha güçlü bir çıkarım: öncü model aynı kanıtla eşiği geçemiyorsa, 27B'lik Q4 modelin geçmesi beklenmez **[tahmin; ezber öncü modelde daha güçlü, tavan iyimser kalır; bu yüzden yalnız olumsuz sonuç bağlayıcı]**.
- **Tavan tutmazsa:** KaradulLM'in rolü ad vermek değil, araştırmacının kanıtta gezinmesine yardım etmek olur. Her cümlesi bir araç sonucunun kimliğine atıf yapar; atıfsız cümleyi deterministik denetim reddeder. Ad alanına hiçbir zaman yazmaz.
- **Maliyet:** Bir öncü model koşusu (API ücreti, yerel bellek sorunu yok) + aynı etiketleme. Atıf denetimi küçük bir kod işi **[tahmin]**.
- **Feda edilen:** Adsız fonksiyonlarda model kaynaklı ad. Berke'nin "yapılamayan isim kurtarma kısmında güveneceğimiz yer" hedefi tavan tutmazsa bu katmanda karşılanmaz.

## 7. Codex çağrısı ve denetim

| Çalışma dizini (depo dışı, geçici) | Ayar | Çıkış | Sonuç |
|---|---|---|---|
| `/tmp/codex-28376-1794376584-30288/` | model `gpt-6-astra`, `-c model_reasoning_effort=xhigh`, `timeout 600`, `-s read-only`, `--skip-git-repo-check`, `< /dev/null`, depo kökünden | 0 (08:56'da başladı, ~09:06'da bitti) | `response.txt` 11.583 bayt; istem 3.721 bayt (`prompt.txt`), künye `meta.json` |

- **Komut denetimi:** Günlükte 32 kabuk komutu var. Hepsi okuma (`nl`, `sed`, `rg`). `rg` aramaları kör setleri `-g '!…'` ile dışlıyor. Okunanlar istemdeki belgeler ve kod, ayrıca `scripts/measurement/llm_pilot.py` (kör set değil) ve `karadul/reconstruction/engineering/deep_tracer.py`. Kör set, `targets/`, model, Ghidra ya da test koşusu yok.
- **Ham yanıt depoya kopyalanmadı:** Görevin dosya sahipliği yalnız bu belgeye izin veriyor. Yanıtın kullanılan kısmı aşağıda ve yerlerinde "(Codex)" diye işaretli. `/tmp` kalıcı değil.

**Codex'ten alınıp dosyadan doğrulananlar:**

| # | Codex'in iddiası | Denetim | Belgedeki yeri |
|---|---|---|---|
| 1 | Model önerisi ad değiştirme yolundan `manual` / `1.0` kaydına, sonraki koşuda ön ada dönüşüyor; birleştirmeden sonra koşulsuz zorlanıyor | Doğrulandı: `ui/server.py:703-716`, `overrides.py:166-194`, `stages.py:2995-3000` ve `4316-4322` | R1 (aynı bulguya bağımsız olarak da varıldı) |
| 2 | Düzeltme: `EXACT_KINDS` "kesin doğru" etiketi değil; temizlemeyi atlatır, elle ad etiketsizdir | Doğrulandı: `baglama.py:74`, `:317-332` (`entry_label`) | R1'in ifadesi buna göre yazıldı |
| 3 | Harness `gerekce` metin değilse `None` yapıp adı geçerli sayıyor | Doğrulandı: `llm_pilot.py:544-556` | §1.1 madde 6 |
| 4 | Kanıt sızıntısı denetimi komşu adı etiketlerini taramadan önce siliyor | Doğrulandı: `llm_pilot.py:472-476` | R4 |
| 5 | Dizgiler JSON kaçışıyla taşınıyor; bu bir yetki sınırı değil | Doğrulandı: `llm_pilot.py:454-460` | R2 |
| 6 | `_naming_diagnosis` tanınan tek bir dış çağrıyla "sarmalayıcı" kararı veriyor | Doğrulandı: `ui/server.py:632-636` | §3.1 madde 3 |
| 7 | Ürünün `_evidence` çıktısı hedefin o anki adını taşıyor; pilot gizliyor | Doğrulandı: `ui/server.py:668`; `pilot_protokolu.md` §3.1, §15 | R3, §2.3 bozulma kolu |
| 8 | Hız tablosundaki Qwen ölçümleri Qwen3.6'ya ait | Doğrulandı: `model_secimi.md` §4.1 | §3.1 tablosunda işaretli |
| 9 | Kalan nüfusun ters seçilmişliğinin büyüklüğü doğrulanmadı | Kısmen kabul: Mac htop'ta kalan = bütün nüfus (`ac_kapilari.json`), sayılar geçerli; Mac tmux'ta ölçülmedi | §0, §1.1 madde 2 düzeltildi |
| 10 | Deneyler: 10 × 10 çeşitleme; bozuk araç yanıtlı yeniden oynatma; modelsiz fayda prototipi | Öneri (veri değil) | §1.3, §2.3, §3.3 |

**Elenen ya da kullanılmayanlar:**
- Codex literatür sayılarını kullanmadı, çünkü yalnız hafıza notunda duruyorlardı. Bu belgedeki REFORGE sayıları hafızadan değil, depodaki `docs/arge/2026-10-15_makale/veri_setleri.md:60`'tan alındı. Orada birincil kaynak sayfası okunmuş olarak işaretli. "Zorluk girdinin bilgisinden" yorumu ve Kendall W yalnız hafıza notunda; **[hafıza]** diye işaretlendi, hiçbir eşik onlara dayanmıyor.
- Codex'in U3 eşiği (yararlı yanıtın p95'i > 60 sn) bu belgedeki kart eşiğinden (p95 > 90 sn) sıkı. İkisi de öneri; karar Berke'nin.
- Codex'in iki seçeneği ("salt kanıt kartı" ve "seçili fonksiyona isteğe bağlı model hipotezi") bu belgenin S1'iyle örtüşüyor. "En çok iki seçenek" sınırı yüzünden S1'de birleştirildi.

**Yalnız Claude'un ekledikleri** (Codex'in yanıtında yok; hepsi dosyadan doğrulandı): bağlam bütçesi aritmetiği (§2.1 madde 2); önbellek ile bellek çelişkisi (madde 3; llama.cpp davranışı **[tahmin]**); `icerik_adsiz` sayıları ve kart envanterinin "boşluğu etiketle doldurma" önerisi; ürün ölçüm koşucusunun geçersiz kılma deposunu okuması (R1, `urun_kos.py:88, 110`); takılabilir arka ucun istem işini taşımaması (§2.1 madde 8; Codex de ayrıca değindi); S2 tavan deneyi.
