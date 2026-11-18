# Karadul ARGE soru listesi (Mythos için) — 2026-11-18

- **Yazan:** ana oturum (Opus 5.5), Berke'nin isteğiyle. Onarım dalgaları sürerken yazıldı; onarımın ilk günü bitince (2026-11-18 akşamı, sürüm 1.24.1) §1.1 ve §3.H eklendi.
- **Kime:** Mythos, onarım bittikten sonraki ARGE oturumunda.
- **Ne bekleniyor:** Mythos bu sorulardan hat seçer ve her hat için ölçülebilir bir plan yazar (§5'teki biçimde). Planları Opus ekibi uygular; ana oturum doğrular.
- **Ne beklenmiyor:** kod yazmak. Ayrıca "şunu dene" türünden ölçütsüz fikir listesi de istenmiyor.

## 0. Önce bunları oku

| Ne | Nerede |
|---|---|
| Onarımın son durumu (hangi kusur kapandı, hangi sayı ne oldu) | `docs/arge/2026-11-18_onarim/DURUM.md` ve paket dosyaları (`P00.md` … ) |
| Onarımın kalanı (hazır paket metinleri, açık bulgular, onay bekleyen silmeler) | `docs/arge/2026-11-18_onarim/gonderim/OKU.md` |
| Genel tarama (137 bulgu, temalar, vizyon) | `docs/arge/2026-11-18_genel_tarama/RAPOR.md` (§3 temalar, §7 KaradulLM) |
| Ürün ad ölçümünün son tabanı | `docs/arge/2026-11-10_n1_adim3/urun_olcumu_fark_yeni_yeni2.md` (+ `urun_olcumu_taban.md`, ön kayıt ekleri) |
| Literatür taraması | `docs/arge/2026-10-21_literatur/yontem_taramasi.md`, `docs/arge/2026-10-15_makale/tersine_derleme_sinirlari.md`, `derleyici_sentez.md`, `veri_setleri.md` |
| Kilitli test seti (DOKUNULMAZ) | `docs/arge/test_seti_kilidi.md` (15 program; açılış planı dışında Karadul'la analiz edilmez, çıktısına bakılmaz) |
| Doğrulama seti | `docs/arge/dogrulama_seti_kilidi.md`, `dogrulama_seti_onkayit.md` |
| Olumsuz sonuçlar (yinelenmesin) | `docs/arge/2026-11-10_n4/` (fiil tavanı, tablo yuvası), `docs/arge/2026-11-12_yerlesim/`, `docs/arge/2026-11-11_n4_v2/`, `docs/arge/2026-11-11_yeniden_hesapla/` |
| KaradulLM tasarımı ve Onuncu Adam itirazları | `docs/arge/2026-11-11_karadullm/` |

## 1. Zemin: Karadul bugün

**Ne yapıyor:** derlenmiş ikiliyi alıyor (ELF, Mach-O, PE; ayrıca JS/Electron, Java/APK, .NET, Python paketleri). Ghidra 12.1.2'nin (PyGhidra, başsız) çıktısı üstünde **hesaplamayla** çalışıyor; motor LLM kullanmıyor. Fonksiyon ve değişkenlere ad veriyor, tip ve yapı kurtarıyor, ilişkileri çıkarıyor, analist için kaynak ağacı ve rapor üretiyor. KaradulLM ayrı ve isteğe bağlı bir katman: araç kullanan, yerel modelle (Qwen 27B, Q4) çalışan yardımcı ajan, bugün hiçbir yere bağlı değil.

**Ad ölçümünün son tabanı (1.22.1 ürünü, geliştirme seti, 2026-11-12):**

| Ölçü | Değer |
|---|---|
| Ürünün verdiği fonksiyon adı (havuz) | 2 261 |
| Doğru (tam eşitlik) | 1 589 (%70,3; %95 GA %68,4–%72,1) |
| Yanlış | 672 (**%29,7**; %27,9–%31,6); program düzeyi makro yanlış oranı **%52,8** |
| Ad bekleyen nüfus (Ghidra'nın jenerik bıraktığı fonksiyonlar) | 21 371 |
| Ad verilen kapsam | 1 764 / 21 371 (%8,3) |
| **Doğru ad kapsamı** | **1 120 / 21 371 (%5,2)** |
| "kesin" etiketli adlar | 249 / 262 doğru (%95,0; makro %97,3); kapsamı 252 / 21 371 (%1,2) |
| Hedef "yanlış ≤ %10" | tutmadı |

Kaynak: `urun_olcumu_fark_yeni_yeni2.md`. Ölçü tanımları: `scripts/measurement/urun_olc.py` (tam eşitlik; Mach-O'da baştaki `_` soyulur; derleyici klonu tabana eşlenir).

**Ölçüm altyapısı (hazır):**
- Geliştirme seti: 119 ikili, `scripts/measurement/urun_kos.py` → `isleri_topla`. 117'si Debian 13 AArch64 ELF (GCC 14), 2'si Mac (htop, tmux). Bu bir yanlılıktır; G1'e bakın.
- Ürün koşusu ve ad ölçümü: `urun_kos.py` (119 ikili ≈ 3–4 saat, `--paralel 3`) + `urun_olc.py olc / karsilastir` (birim, tabaka, kanal kırılımı, Wilson aralığı).
- Masum ikili kapısı (sahte iddia sayımı; 5 katman × 4 set; ~25 sn): `scripts/measurement/masum_kapi.py`, el kitabı `docs/arge/2026-11-18_onarim/P00.md`.
- Çıktı sağlamlık denetimi: `scripts/measurement/saglamlik_denetle.py`.
- Tip tabanı (DWARF, dwz farkında): `scripts/measurement/dwarf_tip.py`, `ghidra_tip_tabani.py`, `parametre_hizala.py`; ölçüt taslağı `docs/arge/2026-10-21_k1_k2_onkayit_taslak.md`.
- Yerleşim (modül sınırı) ölçümü: `scripts/measurement/harita_olc.py`, `yerlesim_urun_olc.py`.
- Kör insan etiketleme protokolü: `docs/arge/etiket_protokolu_v2.md`, `scripts/measurement/etiket_paketi.py`, `etiket_puan.py`.
- Native olmayan hat örnekleri: `~/karadul_olcum/dogrulama_native/` (11 dosya; `MANIFEST.json`).
- Mutasyon sınaması: `scripts/mutation_probe.py` + `scripts/measurement/mutation_specs_*.json`.

**Bilinen olumsuz sonuçlar (yeniden keşfetmeyin, üstüne kurun):**
- **N4 fiil tavanı:** fonksiyon adının fiilini ikilideki kanıttan türetmenin tavanı Mac tmux'ta ≤ %11,1, Mac htop'ta ≤ %20,6. Tablo yuvası kanıtı tmux'ta ≤ %10,6. Kaynak: `docs/arge/2026-11-10_n4/`.
- **`kebap_ad`:** seçenek adını (`monitor-silence`) fonksiyon adı yapmak 239 yanlış / 0 doğru verdi. Berke'nin kararı (K-2): susturulmayacak, kanıttan hesaplamayla doğru ada yaklaştırılacak. Bu hâlâ açık bir ARGE sorusu (A5).
- **Adres sırasına göre yerleşim:** geliştirme setinde makro ARI 0,705 (eşit bölme 0,424, eski ürün 0,097). Sinyal GCC 14 / AArch64'e özgü (`function_align 32:16`); GCC 13 ile derlenmiş ikililerin bir kısmında ve Mach-O htop'ta yok. Bayrak arkasında, kapalı. Kaynak: `docs/arge/2026-11-12_yerlesim/`.
- **CFG-iso eşleme ve hesaplama füzyonu** her ikilide 0 sonuç üretti. Neden yapısal: sorgu düğümleri komut sayısı, şablonlar mnemonik; füzyon eşiği tek kanıtla ulaşılamaz. Onarım paketi P11'de; sonucu DURUM.md'de.
- **Literatür:** LLM tabanlı yöntemler (SYMGEN, REFORGE vb.) ne ölçekte ne doğrulukta tek başına çözüm değil; ölçüm tanımları bizimkinden cömert. Kaynak: `yontem_taramasi.md`.
- **İmza veritabanı** (9,2 M ad) kitaplık adlarını yanlış veriyordu (glibc → opencv / psycopg2). K-5 kararıyla yeniden kuruluyor; sonucu DURUM.md'de.

### 1.1 Onarımdan sonra (2026-11-18 akşamı, sürüm 1.24.1)

Genel taramanın onarımı bir günde büyük ölçüde ilerledi; durum ve her paketin önce / sonra sayıları `docs/arge/2026-11-18_onarim/DURUM.md`'de. ARGE'yi doğrudan ilgilendirenler:

- **Ölçüm zemini değişti:** ad haritası artık `PYTHONHASHSEED`'den bağımsız (aynı girdi, iki tohum: ad haritası ve `out/src` bayt bayt aynı). Ön adların güveni sabit 0,95 değil, kanalın ölçülmüş kesinliğinin Wilson alt sınırı. Yerel adlar fonksiyon başına numaralanıyor.
- **Birleşik ürün ölçümü (119 ikili) henüz koşulmadı.** §1'deki ad tablosu 1.22.1'in sayısıdır; onarım sonrası taban sonraki oturumun ilk işi olarak alınacak. Mythos'un planları bu yeni tabana göre yazılmalı; o ölçüm gelmeden "iyileşme" iddiası kurulmaz.
- **Kapanan analisti yanıltan çıktılar:** sahte istihbarat / anti-debug / YARA / paketleyici iddiaları, uydurma algoritma ve güvenlik yorumları, kanıtsız `types.h` yapıları, kodda geçersiz parametre adları, rol adının fonksiyon adı yapılması, raporların birbirini tutmayan sayaçları.
- **Bekletilen katmanlar (K-1; öntanımda kapalı, kanıt üretmeye devam ediyorlar):** bileşim şablonları (103 aday), yapı kurtarmanın koda yeniden yazımı (`APPLY_REWRITES`; önkoşulu P14'te onarıldı, ad kaynağı ölçümü bekliyor), capa'nın koda beslemesi, hesaplama füzyonunun ad kanalı.
- **Açık kalan ad kanalları:** `kebap_ad` (AD-01) ve geri çağrı rolünden "rol + öğe" adı (AD-02'nin ad üreten yarısı) — ikisi de K-2 araştırması (P12b). Ad yan yolları (Faz 1 çıkarıcı, birleştirici, BinDiff / RefDiff, elle adın zorlanması) P13a'da; bağlı olmayan kanallar (PDB, DWARF, RTTI, Rust / Go) P13b'de.

## 2. Bağlayıcı kurallar

1. **Motor LLM'siz kalır.** Hesaplama ve kanıt deterministiktir. KaradulLM ayrı bir katmandır: analist açar; ad önerisi ayrı köken bölümünde durur, analist onaylamadan ad haritasına girmez. Yayımlanacak iddialar LLM'siz sonuçlardır.
2. **Başarı ölçütü:** analisti yanıltmamak. Berke amacı doğru anlatan adı başarı sayıyor ("benzerliğe okeyim"; gevşek mod: "seramik duvar" yerine "fayans duvar" başarıdır, "pencere" başarısızlıktır). Ama benzerlik ölçüsü önce tanımlanmalı ve insan yargısıyla doğrulanmalıdır (B3). Tanımsız "benzer" iddiası kabul edilmez.
3. **Önce kesinlik.** Kapsamı artıran her yöntem yanlış oranını artırmamalı. Hedef: yanlış ≤ %10. Ad vermemek (`FUN_…` bırakmak) yanlış ad vermekten iyidir; ama `FUN_` teslim değil, son çaredir.
4. **Kapsam küçültülmez** (Berke, 2026-11-18). Katman silinmez, onarılır. Onarım evresindeki "yeni özellik yok" kuralı ARGE'de gevşer, ama her yeni yöntem önce bayrak arkasında ve ön kayıtlı ölçümle girer.
5. **Test seti dokunulmazdır** (`test_seti_kilidi.md`). Ayar, eşik ve sözlük yalnız geliştirme setine göre yapılır. Doğrulama seti ara karar içindir; test seti yalnız planlanan açılışta açılır.
6. **Bilim düzeni:** hipotez → ölçüt → ön kayıt (değişiklikten önce, commit'li) → ölçüm → olumsuz sonuç da kayda geçer → iddia yalnız ölçülen kadar. Wilson %95 aralığı; tek ikiliden genelleme yok.
7. **Yaratıcılık protokolü** (Berke, CLAUDE.md §29):
   - (a) Her soru mekanik olarak sınanabilir biçime indirgenir. Doğrulayıcısı olmayan sonuç en fazla "yön gösterici" etiketi alır.
   - (b) Uzlaşıyı bilerek kır. Her hat için literatürün beklenen cevabını yazıp ona aykırı bir öncül dene. Bütün fikirler aynı yere iniyorsa bu bir uyarıdır.
   - (c) Tek hatta uzun süre kal. Her dalgada yeni konu açılmaz; başarısız denemeler ve "neden olmadı" notları sonraki adıma taşınır.
   - (d) Seçimi insan uzman yapar. Berke tersine mühendislikte uzman değil (kendi sözü); eşiğe gelen sonuç yayımdan önce dış bir RE uzmanına okutulur.

## 3. Sorular

Her sorunun altında aynı alanlar var:
- **Bugün:** ölçülmüş durum.
- **Doğrulayıcı:** sonucun mekanik olarak nasıl sınanacağı.
- **Aykırı öncül:** denenmesi istenen karşı görüş.
- **Not:** bilinen tuzak.

### A. Ad sayısı nasıl artar? (kapsam)

**A1. Eksik adlar nerede? Kapsam bütçesi.**
- **Soru:** 21 371 ad bekleyen fonksiyonun GT'ye göre kırılımı nedir? Kategoriler: statik bağlı kitaplık kodu, derleyici / çalışma zamanı, gnulib türü paylaşılan kod, uygulamaya özgü kod, küçük yaprak fonksiyon, thunk / sarmalayıcı. Her kategoride bugünkü kanalların ulaşabileceği **üst sınır** nedir?
- **Bugün:** doğru ad kapsamı %5,2; kategori kırılımı yok.
- **Doğrulayıcı:** GT'den (dbgsym) kategori etiketi + kanal başına "kanıt var mı" sayımı. Çıktı bir bütçe tablosudur: kategori × (nüfus, bugün doğru, ulaşılabilir üst sınır).
- **Aykırı öncül:** "Kapsamın büyük kısmı kitaplık kodudur ve imzayla çözülür" beklentisini sına. Belki darboğaz uygulama kodudur ve imza işi doymuştur.

**A2. Kitaplık fonksiyonları: imza, bayt deseni ve benzerlik.**
- **Soru:** Yeniden kurulan imza veritabanı (K-5), FLIRT türü bayt imzaları ve BSim birlikte statik bağlı kitaplık kodunun yüzde kaçını ≥ %95 kesinlikle adlandırır?
- **Doğrulayıcı:** A1'in kitaplık kategorisinde kesinlik ve kapsam. Derleyici sürümü / iyileştirme düzeyi tabakalarında ayrı ayrı.
- **Not:** BSim ortak deposu sembollü kopyaların adlarını sızdırabiliyordu (GHIDRA-02). Ölçüm hijyeni için koşuya özel depo kullanın.

**A3. Derleyicinin kendi bıraktığı üst veriden ad: hiç kullanılmayan kaynaklar.**
- **Soru:** Silinmiş ikilide bile kalan dil çalışma zamanı üst verisi nerede ve ne kadar ad verir?
  - Go: `pclntab`.
  - Rust: v0 / legacy simgeler, panik dizgilerindeki dosya yolları.
  - C++: RTTI / vtable sınıf adları.
  - Objective-C: sınıf ve seçici adları.
  - Swift: tip üst verisi.
  - PDB / DWARF kalıntıları.
- **Bugün:** PDB / DWARF / Binary Ninja / TRex / Rust / Go / RTTI kanalları yazılmış ama akışa bağlı değil. K-4 kararıyla bağlanıyor; durumu DURUM.md'de. Mac htop'ta ürün 0 ad veriyor.
- **Doğrulayıcı:** Mac uygulamaları ve Go/Rust ikililerinden küçük bir set. Kategori başına ad sayısı ve kesinlik. GT'si olan Mach-O'lar `workspaces/olcum_mac/`'ta.
- **Aykırı öncül:** "Mac'te ad sorunu aslında çözülmüş bir sorundur; ObjC / Swift üst verisini okumuyoruz, o kadar" önermesini sına.

**A4. Başvuru derlemesiyle eşleme (açık kaynak programlar).**
- **Soru:** Programın adı ve sürümü biliniyorsa, aynı kaynağı sembolle derleyip ya da dağıtımın dbgsym paketini alıp fonksiyon eşlemesi yaparak (BinDiff türü, BSim) adların yüzde kaçı kurtarılır? Derleyici, sürüm ve iyileştirme farkı eşleşmeyi nasıl bozar?
- **Bugün:** "kaynak eşleme" katmanı (Layer 1.5) var, ağ kapısına bağlı. Gerçek başarısı ölçülmedi.
- **Doğrulayıcı:** geliştirme setinde başvuru = farklı derleyici / sürüm derlemesi. Ad kesinliği ve kapsamı.
- **Not:** ağa çıkan her yol `network.enabled` kapısından geçer (P-GÜV). Kurulumun çevrimdışı çalışma sözü bozulmaz.

**A5. İkilideki kanıttan hesaplamayla ad (uygulamaya özgü kod).**
- **Soru:** Yalnız ikilideki kanıtla (dizgiler, hata iletileri, çağrılan API'ler, okunan seçenek adları, sabitler) uygulamaya özgü fonksiyonlara ne kadar **yakın** ad üretilebilir? Bu, K-2'nin açık sorusu: `kebap_ad` seçenek adından doğru ada nasıl gider?
- **Bugün:** N4 fiil tavanı düşük (§1). Seçenek adını doğrudan ad yapmak 0 doğru verdi.
- **Doğrulayıcı:** B3'te tanımlanan benzerlik ölçüsünün GT'ye karşı dağılımı. Tam eşitlik ayrıca raporlanır.
- **Aykırı öncül:** "Uygulamaya özgü adların büyük kısmı ikilide hiçbir kanıt taşımaz" önermesini nicel olarak sına: kanıt taşıyan oran nedir, tavan nedir?

**A6. Çağrı grafiği boyunca yayılım.**
- **Soru:** Yapraklar adlandırılınca (kitaplık + kanıtlı adlar) ebeveynlerin adı ya da rolü hesaplanabilir mi? Aşağıdan yukarı ya da yukarıdan aşağı. Hangi kanıt bileşimi yanlış oranını artırmadan kapsamı büyütür?
- **Bugün:** parametre adı yayılımı hesaplanıp atılıyordu (BORU-10; onarımı P13b'de).
- **Doğrulayıcı:** yayılımla eklenen adların ayrı kanal etiketiyle kesinliği.

### B. Ad doğruluğu nasıl artar? (kesinlik ve dürüst güven)

**B1. 672 yanlış ad nereden geliyor?**
- **Soru:** Yanlış adların kanal, alt kanal, boyut tabakası ve program bazında kırılımı nedir? Her kanalın ölçülmüş kesinliği nedir; hangileri bir kapıyla düzeltilir, hangileri yöntem değişikliği ister?
- **Doğrulayıcı:** `urun_olc.py` kanal kırılımı. Onarım sonrası taban DURUM.md'deki birleşik ölçümden alınır.

**B2. Güven = ölçülmüş kesinlik (kalibrasyon).**
- **Soru:** Her ada yazılan güven değeri, o kanal ve kanıt türünün geliştirme setinde ölçülmüş kesinliğine eşit olabilir mi? Doğrulama setinde de tutar mı (kalibrasyon eğrisi, Brier / ECE)?
- **Bugün:** ön adlara sabit 0,95 yazılıyordu (AD-07). Mühendislik paketinin "kalibrasyonu" hiçbir karara girmiyordu (MUH-05). Onarım durumu DURUM.md'de.

**B3. "Benzer ad" ölçüsü: tanım ve insan doğrulaması.**
- **Soru:** Berke benzerliği kabul ediyor. Hangi ölçü insanın "amaç doğru" yargısıyla en iyi uyuşur?
  - Adaylar: normalleştirilmiş belirteç Jaccard'ı, eşanlam / kısaltma sözlüğü, düzenleme uzaklığı, belirteç gömme benzerliği.
  - Aday ölçünün eşiği nerede?
- **Doğrulayıcı:** kör iki değerlendirici (`etiket_protokolu_v2.md`). Değerlendiriciler arası uyum (kappa), ölçü ile insan yargısının uyumu (ROC / AUC), eşik doğrulama setinde.
- **Not:** bu ölçü tanımlanmadan A5 / A6 / F'nin hiçbir "benzer ad" iddiası kabul edilmez.

**B4. Ad vermeme kararı (çekimserlik) için maliyet modeli.**
- **Soru:** Analist için yanlış adın maliyeti eksik addan kaç kat yüksek? Bu oran verildiğinde kanal başına en iyi eşik nedir?
- **Doğrulayıcı:** kesinlik / kapsam eğrisinde seçilen işletim noktası, doğrulama setinde.

**B5. Kanallar arası çatışma.**
- **Soru:** İki kanal farklı ad verdiğinde hangisinin doğru olduğu ölçülmüş kesinliklerden belirlenimci bir kuralla seçilebilir mi? Bugünkü birleştirici etkisizdi (AD-04 / 05).
- **Doğrulayıcı:** çatışan çiftlerde seçilen adın kesinliği.

### C. Daha kaliteli tersine mühendislik (tip, yapı, ilişki, okunurluk)

**C1. Tip: Ghidra'dan daha iyi nerede?**
- **Soru:** Karadul'un yazdığı tip, DWARF'a Ghidra'nın tipinden daha mı yakın? Hangi değişken türlerinde (parametre, yerel, global, dönüş) değer katıyor, hangilerinde bozuyor?
- **Doğrulayıcı:** `dwarf_tip.py` + `ghidra_tip_tabani.py`. "Ghidra'dan daha kötü tip yazma" oranı kapıdır (P09'un ön kaydı ve sonucu DURUM.md'de).

**C2. Yapı yerleşimi.**
- **Soru:** İşaretçi aritmetiğinden (`(fonksiyon, değişken)` anahtarıyla, ölçekli ofsetle) ve fonksiyonlar arası birleştirmeden kurtarılan yapıların alan ofsetleri ve boyutları DWARF'la ne kadar uyuşuyor? MaxSMT birleştirmesi (P11'de onarılıyor) ne katıyor?
- **Doğrulayıcı:** yapı başına alan ofseti kesinlik / duyarlılık. Koda bağlanan yapı oranı.

**C3. Modül ve dosya sınırları (yerleşim) derleyiciler arası genelleşir mi?**
- **Soru:** Adres sırası sinyali GCC 14 / AArch64'e özgü çıktı. GCC 12 / 13, clang, MSVC, LTO'lu derlemelerde kaynak dosya sınırını hangi sinyaller öngörür? Hizalama dolgusu, çağrı yerelliği, dizgi tablosu sırası ve hata ayıklama kalıntıları birlikte ne verir?
- **Doğrulayıcı:** `harita_olc.py` ARI, derleyici tabakalarında ayrı ayrı. Yerleşim ön kaydının taslağı `263ae4a`'da.
- **Aykırı öncül:** "0,705 araç zincirinin sonucudur, genelleşmez" (ön kayıt taslağındaki aykırı öncül) burada sınanır.

**C4. Okunurluk ve kod kalitesi.**
- **Soru:** Ghidra çıktısının okunurluğunu ölçen nesnel vekil ölçüler nelerdir? Adaylar: KLOC başına `goto`, `switch` kurtarma oranı, satır içi fonksiyon tespiti, ölü değişken. Karadul'un dönüşümleri bunları nasıl değiştiriyor?
- **Doğrulayıcı:** vekil ölçüler + küçük bir kör insan okunurluk değerlendirmesi. Vekiller insanla uyuşmuyorsa vekil atılır.

**C5. Satıcı / kitaplık kodunu ayırmak.**
- **Soru:** Statik bağlı kitaplık kodunu (gnulib, zlib, OpenSSL) güvenle işaretleyip analistin önünden çekmek, uygulama koduna odaklanmayı ne kadar kolaylaştırır? Yanlış işaretleme zararlı bir modülü "vendor" diye gizler mi (BICIM-11 benzeri risk)?
- **Doğrulayıcı:** işaretleme kesinliği (yanlış "kitaplık" oranı ≤ kabul sınırı) ve kapsam.

### D. Kodun neredeyse tamamını çıkarmak (eksiksizlik)

**D1. Decompile kapsamı: hiçbir fonksiyon ve gövde kaybolmasın.**
- **Soru:** İkilideki fonksiyonların ve komutların yüzde kaçı çıktı ağacına eksiksiz ulaşıyor?
- **Bugün:**
  - `decompiled.json` 500 fonksiyonla sınırlıydı (GHIDRA-05).
  - Gövdeler 5 000 karakterde kırpılıyordu (11 ikilide 13 664 kayıt).
  - Zaman aşımına düşen fonksiyonlar vardı.
  - Onarım durumu P16a'da.
- **Doğrulayıcı:** "kayıp sayacı" (fonksiyon / gövde / dizgi; neden). Hedef: kayıp 0, kalan kayıp nedenleriyle listelenmiş.

**D2. Fonksiyon sınırı ve ayrıştırma kapsamı.**
- **Soru:** Ghidra'nın fonksiyon sınırı tespiti GT fonksiyon listesine göre ne kadar doğru? Kaçan fonksiyonlar, dönmeyen fonksiyonlar, atlama tabloları ve kod içi veri nerede hata yapıyor? Karadul düzeltebilir mi?
- **Doğrulayıcı:** GT (DWARF / simge) fonksiyon başlangıçlarına karşı duyarlılık / kesinlik, mimari ve derleyici tabakalarında.

**D3. Yeniden derlenebilirlik.**
- **Soru:** Çıktı ağacındaki dosyaların yüzde kaçı (taslak başlıklarla) derleniyor? Hangi hata sınıfları baskın? Derlenebilir oran nasıl yükselir?
- **Doğrulayıcı:** dosya başına ve proje başına derleme oranı, hata sınıfı histogramı.

**D4. Davranışça eşdeğer çıktı (en güçlü "kod çıktı" ölçütü).**
- **Soru:** Küçük açık kaynak programlarda (coreutils'ten birkaçı) yeniden derlenen çıktı özgün programın kendi test takımından yüzde kaç geçiyor?
- **Doğrulayıcı:** geçen test oranı. "Neredeyse tamamı çıktı" iddiası ancak bu ölçütle kurulabilir.
- **Not:** bu, bugünkü hedefin çok ötesinde olabilir. Fizibilite önce 1–2 programda denenir; olumsuz sonuç da değerlidir.

**D5. Native olmayan hatların eksiksizliği.**
- **Soru:** JS / Electron, JAR / APK, .NET, PyInstaller örneklerinde (`~/karadul_olcum/dogrulama_native/`) kurtarılan modül, sınıf ve fonksiyon oranı nedir? jadx, ILSpy ve dotnet bu makinede yok; hangi araç zinciri seçilmeli?
- **Doğrulayıcı:** hat başına kurtarılan / toplam (sınıf, metot, modül), ayrıştırılabilir çıktı oranı.

### E. Daha hızlı ve daha az kaynakla çalışmak

**E1. Kritik yol.**
- **Soru:** Geliştirme setinde aşama başına süre ve tepe bellek nedir? Kritik yol hangi aşamalardan geçiyor?
- **Bugün:** eski ölçümde (2026-07-28) Ghidra toplam sürenin ~%56'sıydı. Mühendislik paketi %5,4. Yeniden ölçülmeli.
- **Doğrulayıcı:** boş makinede tekrarlı ölçüm (üç tekrar, medyan), ikili boyutuna göre ölçekleme eğrisi.

**E2. Ghidra analiz seçenekleri: süre ↔ kalite eğrisi.**
- **Soru:** Hangi Ghidra çözümleyicileri kapatılınca ad, tip ve fonksiyon sınırı kalitesi ölçülebilir biçimde düşmüyor? Süre ne kadar kısalıyor?
- **Doğrulayıcı:** seçenek kümesi başına (süre, ad ölçümü, D2 duyarlılığı). Pareto cephesi.

**E3. Önbellek ve artımlı analiz.**
- **Soru:** Ghidra projesini ve aşama çıktılarını sha256 anahtarıyla saklamak yeniden analiz süresini ne kadar düşürür?
- **Bugün:** Ghidra projesi siliniyordu (B-C4). Bu, KaradulLM'in "yeniden hesapla" aracını da engelliyor. Disk maliyeti nedir?
- **Doğrulayıcı:** ikinci koşu süresi / ilk koşu süresi, disk kullanımı.

**E4. Büyük ikililer.**
- **Soru:** 30–40 MB'lık bir ikilide (v1.20.5 hedefi) süre ve bellek nasıl ölçekleniyor? Hangi aşama süperdoğrusal?
- **Doğrulayıcı:** boyut tabakalarında süre / bellek eğrisi.

**E5. BSim.**
- **Soru:** Yerel (native) ve lite kipleri arasında süre ve ad katkısı farkı nedir? Koşuya özel depo, eşzamanlı koşuda kilitlenmeyi (GHIDRA-01) ve sızıntıyı (GHIDRA-02) ne maliyetle çözer?
- **Doğrulayıcı:** BSim kaynaklı adların kesinliği ve kapsamı, süre.

### F. KaradulLM (isteğe bağlı yerel model katmanı)

**F1. Çekimserlik bilgi eksikliğinden mi?**
- **Soru:** Fonksiyon paketine komşu fonksiyonların aşağıdan yukarı özetleri eklenince çekimser oranı ve yanlış ad oranı nasıl değişir?
- **Bugün:** K0 5/5 çekimser. htop'ta çağrılanların 419/419'u adsız (LM-08).
- **Doğrulayıcı:** GT'li küçük sette çekimser oranı, yanlış ad oranı (B3 ölçüsüyle).

**F2. Araç kullanım hatası.**
- **Soru:** Araç döngüsü (K1 / K2) gerçek modelde hiç koşmadı. Yanlış araç, yanlış argüman ve boşa çağrı oranı nedir? Hangi araçlar eksik?
- **Doğrulayıcı:** içerikli araç izi kaydı; hata sınıfı oranları.

**F3. İnce ayar gerekli mi?**
- **Soru:** Ancak F2'de araç hatası yüksek çıkarsa: toplanan izlerle küçük bir modelde (≤ 14B) ince ayar araç hatasını düşürür mü? Bu makinede (36 GiB) bellek sığar mı?
- **Doğrulayıcı:** önce / sonra araç hata oranı, tepe bellek.

**F4. Model boyutu, hız ve bağlam.**
- **Soru:** Boş makinede 27B Q4 modelin 16K bağlamda hızı nedir? Daha küçük modelle kalite ne kadar düşer?
- **Doğrulayıcı:** jeton / sn, F1 ölçüleri.

### G. Ölçmenin kendisi (genelleme ve adil karşılaştırma)

**G1. Geliştirme seti yanlılığı.**
- **Soru:** Geliştirme setinin 117 / 119'u Debian 13 AArch64 GCC 14. x86-64, clang, MSVC, macOS, -O3 / LTO ve PE tabakalarında sayılar ne kadar kayıyor?
- **Doğrulayıcı:** tabakalı bir doğrulama setinde (derleyici × mimari × iyileştirme) aynı ölçüler. Test setine dokunmadan.

**G2. Adil karşılaştırma tabanları.**
- **Soru:** Aynı sette çıplak Ghidra, Karadul ve LLM tabanlı yöntemler (ölçüm tanımı aynı olacak biçimde) nasıl karşılaştırılır? Literatürün cömert ölçüleriyle bizimkini eşitlemeden karşılaştırma yapılmaz.
- **Doğrulayıcı:** ortak ölçü tanımı, aynı GT ve aynı nüfus.

**G3. İnsan değerlendirmesinin maliyeti.**
- **Soru:** B3 ve C4 için kaç örnek, kaç değerlendirici, ne kadar süre gerekir ki aralıklar karar vermeye yetecek kadar dar olsun?

### H. Onarımda ortaya çıkan sorular

**H1. Bekletilen katmanların serbest bırakılma kapısı.**
- **Soru:** K-1 ile bekletilen her katman (bileşim şablonu, yapı yeniden yazımı, capa kod beslemesi, füzyon ad kanalı) hangi ölçüm tutunca öntanımda açılır? Ortak bir "doğrulama kapısı" tanımı: masum ikili kapısında yanlış iddia 0, GT'li sette kesinliğin Wilson alt sınırı ≥ eşik, doğrulama setinde tekrar.
- **Bugün:** her katman kendi paketinde ölçüldü ama açılma ölçütü tek tek yazılmadı.
- **Doğrulayıcı:** katman başına ön kayıtlı kapı + `masum_kapi.py` + GT ölçümü.

**H2. İmza veritabanının adsız fonksiyonlara verdiği adlar.**
- **Soru:** `call_pattern` ve `string_ref` yöntemleri adsız fonksiyonlara betimleyici tahmin üretiyor (`read_env_var`, `verify_certificate`); 12 Debian ikilisinde **0 / 208 doğru** (P11 ölçümü). Bu yöntemler kimlik değil, rol tahmini üretiyor. K-2'ye göre susturulmaz: rol tahmini doğru ada (ya da doğru rol etiketine) nasıl yaklaştırılır, gevşek ölçüyle (B3) ne kadarı "amacı doğru" sayılır?
- **Doğrulayıcı:** GT'ye karşı tam eşitlik ve B3 benzerlik ölçüsü; kanal başına kesinlik.

**H3. CFG-iso: ikizler ve banka genellemesi.**
- **Soru:** Gerçek koddan kurulan şablon bankası (cat → ls / sort / expr) ham 0,882 kesinlik verdi; kalan yanlışların hepsi `quotearg_*` ↔ `*_mem` ikizleri: CFG ve komut histogramı aynı, yalnız işlenenler farklı. İşlenen bilgisi (sabitler, çağrılan fonksiyon kimliği) eklemek ikizleri ayırır mı? Banka derleyici sürümleri ve mimariler arasında genelleşir mi (GCC 12 / 13 / 14, clang, x86-64)?
- **Bugün:** çift başına Wilson alt sınırı 0,76–0,78; füzyonun kabul eşiği 0,90 → banka ürüne alınmadı.
- **Doğrulayıcı:** derleyici tabakalarında kesinlik / duyarlılık; ikiz çiftlerde ayırma oranı.

**H4. Parametre adları: kanıtın tavanı.**
- **Soru:** Anlamsal parametre adlandırıcısının kesinliği DWARF'a göre %2,7 (5 100 hükümlü addan 136 doğru); skaler genel adlar (`count` 5 199, `enabled` 1 165, `value` 573) baskın. Hangi kanıt türleri (çağrı yerindeki API argüman adı, assert dizgisi, yapı alanı) parametre adını gerçekten belirler; tavan nedir?
- **Doğrulayıcı:** `p09_olc.py` + `parametre_hizala.py`; kural başına kesinlik, kanıt türü başına kapsam.

**H5. MaxSMT yapı kurtarmanın kapsamı.**
- **Soru:** Ofset onarıldı (B1 0,997, B2 0,852) ama kapsam düşük: 9 295 yapı işaretçisi parametresinin 727'si. Erişimlerin %37'si P-code dökümüne yazılmayan `CAST` / `PTRSUB` / `MULTIEQUAL` ile tanımlanıyor. Bunları dökmek kapsamı ne kadar artırır, P-code'u okuyan öbür adımları (fonksiyon sınıflaması → ad adayları) nasıl etkiler?
- **Doğrulayıcı:** DWARF yapı alanı kesinlik / duyarlılık, ad haritası farkı (ön kayıtlı).

**H6. Hız: BSim ve Ghidra'nın payı (E1, E2, E5'e veri).**
- **Bugün:** BSim fonksiyon başına ayrı sorgu (0,04–0,22 sn / fonksiyon; Mac htop 597 fonksiyonda 133 sn) ve oturumlar süreçler arası sıraya giriyor. Ghidra'nın otomatik analizi hâlâ süre sınırsız. Hızlandırma paketi (P16c) hazır, sonraki oturumda.

## 4. Ana oturumun öncelik önerisi (yalnız bir görüş; Mythos itiraz edebilir)

0. **Onarım sonrası birleşik ürün ölçümü (119 ikili) önce.** Bütün planlar o tabana göre yazılır (§1.1).
1. **G1 + B3 önce.** Ölçü tanımı ve genelleme sorusu çözülmeden hiçbir "iyileşme" yorumlanamaz.
2. **A1, kapsam bütçesi.** Ad sayısını artırmanın nerede mümkün olduğunu sayıyla gösterir; hangi hattın değerli olduğunu bu seçer.
3. **A3, dil çalışma zamanı üst verisi.** Mac'te ürün bugün 0 ad veriyor. Kanıt güçlü, deterministik, yanlış oranı düşük olması beklenir. En ucuz büyük kazanç adayı.
4. **A2, kitaplık kodu ve D1, kayıp sıfır.** Mühendislik işi ağırlıklı, riski düşük.
5. **A5 ve F.** En belirsiz ve en araştırmacı hatlar; tek hatta uzun süre kalma kuralıyla yürütülür.

## 5. Mythos'tan beklenen plan biçimi (seçilen her hat için)

```
## Hat: <ad>  (soru kimlikleri: A1, …)
- Hipotez: <tek cümle, sınanabilir>
- Literatürün beklediği cevap: <…>   Aykırı öncül: <…>
- Ölçüt ve doğrulayıcı: <hangi betik, hangi set, hangi sayı; "tuttu" / "tutmadı" eşiği önceden>
- Ön kayıt taslağı: <değişiklikten önce yazılacak beklenti>
- İş paketleri (Opus ekibi için): <paket başına dosya sahipliği, 5–8 kalem, ayrık dosya kümeleri>
- Gerekli veri ve araç: <indirme gerekiyorsa liste: ad, kaynak, boyut; Berke onayı>
- Durma ölçütü: <ne olursa hat kapanır>
- Riskler ve bilinmeyenler: <…>
```

## 6. Bu listenin sınırları

- Sorular onarım sürerken yazıldı. Onarım sonrası sayılar (DURUM.md) bazı soruları gereksiz kılabilir ya da yenilerini doğurabilir. Mythos önce DURUM.md'yi okumalı.
- Literatür sayıları bu belgede doğrulanmadı. Ayrıntı ve tarih `yontem_taramasi.md`'de; değişen konular (model sürümleri, araçlar) yeniden taranmalı.
- "Kodun neredeyse tamamı" için kesin bir hedef bugün tanımlı değil. D1–D4 bu hedefi ölçülebilir kılmak için yazıldı.
