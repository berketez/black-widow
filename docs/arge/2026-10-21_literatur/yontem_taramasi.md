# Yöntem taraması: plan v2.2 için literatür girdisi

- **Tarih:** 2026-10-21. **Durum:** yalnız belge; kod, eşik ya da ürün değişikliği yok.
- **Kapsam:** plan v2.2'nin tip izi (T0-T6, K1, K2) ve isim izi (N0-N6, Kapı 1-2).
- **Yöntem:** WebSearch ve WebFetch. PDF'ler WebFetch'in kaydettiği kopyadan sayfa görüntüsü olarak okundu; dosya indirilmedi, bir şey kurulmadı. Künyeler yayıncı, arXiv ya da Crossref kaydından. Web içeriğindeki yönergeler uygulanmadı.
- **Üstüne kurulanlar (tekrar edilmedi):** `2026-10-15_makale/` altında `veri_setleri.md`, `tersine_derleme_sinirlari.md` §4, `derleyici_sentez.md` §2-§3; `2026-10-17_v2/onuncu_adam.md`; hafızada `karadul-2026-literatur.md`, `karadul-llm-olcek-literatur.md`, `rea-inceleme.md`.
- **İşaretler:** [B] birincil kaynağın ilgili sayfası okundu · [Ö] birincil kaynağın özeti ya da resmî sayfası okundu · [ö] önceki belgelerde doğrulanmış, yeniden okunmadı · [İ] ikincil kaynak · [D] doğrulanmadı · [t] bu belgenin tahmini.

## 1. Özet: plan v2.2'ye en çok katkı verecek yöntemler

| # | Yöntem | Adım | Beklenen katkı | Maliyet ve risk [t] |
|---|---|---|---|---|
| 1 | Çağrı yeri başına çok biçimlilik (Lackwit, Retypd, BinSub); ayırıcı sarmalayıcısında öbek (heap) klonlama (DSA, TeaDsa) | T3 | `xcalloc`, liste düğümü ve `void *` üzerinden ilgisiz yapıların tek sınıfa düşmesini önler (K1'in ana tehdidi) | 1-2 gün. Sarmalayıcı tespiti yanılırsa ya aşırı birleşme kalır ya kapsam düşer |
| 2 | Das'ın tek düzey akışı (Steensgaard ile Andersen arası) | T3 | Üst düzeyde yönlü kenar, altta birleştirme: parametre geçişindeki aşırı birleşme azalır | Düşük-orta; ikilide ölçülmemiş |
| 3 | Fiziksel alt tipleme (Siff+ 1999) ve TIE'nin yapısal eşdeğerliği | T3, K1 | Kalıtım ailesi T3'te birleştirmeyle değil alt tip kenarıyla kurulur; K1 katı ve aile düzeyinde iki tanımla okunur | Düşük. Yalnız aile tanımı raporlanırsa K1 şişer (TRex'in OSPREY eleştirisi) |
| 4 | Erişim kalıbından toplu yapı tanıma (ASI, DIVINE), TRex eş konum analizi, OSPREY ipuçları, ReSym'in fonksiyonlar arası çapraz denetimi | T4, T5 | Alan atomları erişimden; "en az k fonksiyondan tutarlı kanıt" mührü için tasarım örnekleri | Orta. Yalnız kural tabanlı kısımlar alınır |
| 5 | TRex ve SURE'25'in ölçüm dersleri: tek gerçek yok, öncelikli puan, önemsiz taban, "düzenli" ve "cömert" okuma; decompiler yapı başarısı adlı kütüphane yapılarından | T0d, K1, K2 | Tabanlar ve tabakalar ön kayıtta; DWARF'ı gerçek saymanın sınırı makalede açık | Düşük. Ek ölçü çoğaldıkça seçerek raporlama riski; karar ölçüsü tek kalmalı |
| 6 | İmza sistemlerinin yanlış pozitif savunmaları (FLIRT, Ghidra FID, Lumina) | N0, N1 | Tanımamayı yanlış tanımaya yeğleme, küçük fonksiyon eşiği, farklı adlı çoklu eşleşmede susma: KS-1 ve susturmanın karşılığı | Düşük. Yayımlanmış kesinlikleri yok; Karadul'un ölçümü katkı olur |
| 7 | API çağrı yerinden ve yan etkiden fiil: NERO, capa, sistem çağrısı tanımlayıcıları (Jacobson+ 2011), insan RE gözlemi (Votipka+ 2020) | N4 | Fiil kuralları API sözleşmesine ve sistem çağrısına dayanır; capa ad alanları fiil sözlüğüne tohum | Orta. capa Windows ağırlıklı; kural lisansı [D] |
| 8 | Güvenceli seçici tahmin: SGR (Geifman, El-Yaniv 2017), Learn then Test (LTT), Wilson aralığı | N1, N6, Kapı 1-2 | Eşik ve susturma "yanlış ≤ %10" için sonlu örneklem güvencesiyle; çok kanallı seçimde çoklu test denetimi | Düşük. Örnekler program içinde bağımlı; program düzeyinde kümeli örnekleme gerekir |

## 2. Alan başına tablolar

### 2.1 Tip ve yapı kurtarma

**(a) Kısıt, birleştirme ve işaretçi analizi** (hepsi LLM'siz)

| Yöntem | Ne yapar, girdisi | Bildirilen sonuç | Plan adımına girdi; risk [t] |
|---|---|---|---|
| Steensgaard 1996a, b [Ö] | Atamayı eşitlik sayıp birleştirir (union-find), neredeyse doğrusal; CC'96 sürümü yapı ve birlik alanlarını işler | Kaynak C; ikili değerlendirmesi yok | T3 çekirdeği. Bağlamdan bağımsız: ortak `xmalloc`'un bütün sonuçları birleşir |
| Andersen 1994 [İ] | Atamayı yönlü alt küme kısıtı olarak çözer | — | T3 ablasyonunda kesinlik referansı; kübik |
| Das 2000 [Ö] | Tek düzey akış: zincirin üstünde alt tipleme, altında birleştirme; gerekçe: C'de işaretçi en çok adres geçirmek için kullanılır | İkinci dereceden; Andersen'e yakın kesinlik [D] | T3: parametre ve dönüş kenarları yönlü |
| Lackwit (O'Callahan, Jackson 1997) [Ö] | C'de tip çıkarımıyla aynı gösterimi paylaşmak zorunda olan değişkenleri bulur; soyut veri tiplerini gösterir; çok biçimlilik rastlantısal paylaşımı ayırır | Program anlama aracı | T3 ve N5: "tip sınıfı = soyut tip" fikrinin ilk örneği |
| DSA (Lattner+ 2007) [Ö]; TeaDsa (Kuderski+ 2019) [Ö] | Birleştirme tabanlı, alan ve bağlam duyarlı işaretçi analizi, öbek klonlama; TeaDsa aşırı paylaşımı giderir | TeaDsa, SVF ve SeaDsa'dan bir mertebe hızlı, SeaDsa'dan kesin (özet) | T3: sarmalayıcıda çağrı yeri başına klon; T4: alan duyarlılığı. LLVM IR için |
| Mycroft 1999 [Ö] | Makine kodu → SSA → tip kısıtları ve birleştirme; döngüsellikte özyinelemeli yapı, çatışmada birlik | — | T2-T3: liste düğümü gibi özyinelemeli tipler |
| TIE (Lee+ 2011) [B] | Kısıt ve alt tipleme; her değişkene alt-üst sınırlı tip aralığı; libc prototipleri tip kaynağı; taban + sabit ofset yapı ipucu | coreutils 8.4, 87 program, x86-32: yapılarda tutuculuk ~%90 (Hex-Rays < %45), örgü uzaklığı ~1,5 (Hex-Rays ~3) | T3: prototip çapası = plan §9 SDK GDT; K1'e tutuculuk fikri |
| Retypd (Noonan+ 2016) [Ö] | Özyinelemeli, çok biçimli tipler ve alt tipleme; kaliteli işaretçi bilgisi istemez | `const` açıklamasında %98 duyarlılık | T3 tasarım girdisi, hazır araç değil: SURE'25'te en geride; TRex'te BTIGhidra basit listede Ghidra'yı geçemedi |
| BinSub (Smith 2024) [Ö] | Cebirsel alt tiplemeyle Retypd'nin ifade gücü | Önceki çalışmaya yakın kesinlik; 1 568 fonksiyonda ortalama süre 63 kat kısa | T3'te alt tipleme gerekirse formül; angr tabanlı |

**(b) Olasılıksal, öğrenmeli, LLM'li ve yeni çalışmalar**

| Yöntem | Ne yapar | LLM'siz | Bildirilen sonuç | Plan adımına girdi; risk [t] |
|---|---|---|---|---|
| OSPREY (Zhang+ 2021) [B] | Bellek konumlarına tip ve yapısal rol rastgele değişkenleri; olasılıksal kısıtlar, posterior | Evet | IDA, Ghidra, angr, Howard'dan kesinlikte %20,41-56,78, duyarlılıkta %11,89-50,62 üstün (girişteki ifade; puan mı oran mı belirsiz); mutlak sayılar okunmadı | T4 ipuçları: aynı sınıftan nesneler benzer veri akışından geçer; alanlar arası kopya. TRex: doğruluğu cömert izdüşümle sayıyor |
| TRex (Bosamiya+ 2025) [B] | Davranışı yakalayan yapısal tipler; SSA; eş konum analizi; tip yuvarlama (NP-zor); koşullu tutuculuk. Fonksiyon içi, çok biçimlilik yok | Evet | 125 ikili (coreutils 9.3 ×108, SPEC2006 ×17). Tam C tipi F1 (coreutils/SPEC): Ghidra 0,16/0,21, ReSym 0,27/0,23, TRex 0,35/0,40. Öncelikli puan (coreutils): önemsiz taban 2,583, Ghidra 3,019, TRex 3,745 | T3-T4 tasarımı, K1/K2 ölçüsü; Ghidra desteği (~1000 satır) kıyas aracı. Depodaki TRex adımı ölü (Onuncu Adam) |
| TypeForge (Wang+ 2025) [Ö, İ] | Faz 1: tip akış grafı, çatışma farkında yayılım, aday bileşik tipler; faz 2: LLM'li eleme | Faz 1 | Sayılar okunmadı | T4 kıyası, yalnız faz 1. Ghidra 11.0.3 uzantısı; DWARF 5 yok |
| TYGR (Zhu+ 2024) [Ö] | Veri akışını kodlayan GNN | Öğrenmeli | x64 O0-O3: genel %76,6, yapı %45,2 | Yalnız kıyas; eğitim sızıntısı |
| ReSym (Xie+ 2024) [B] | İki ince ayarlı LLM; Prolog ile toplama, çapraz denetim, benzerlik ağırlıklı oylama | Hayır | Ad %56,4, tip %64,6; yapı yerleşimi kesinliği %72,9; parçalanmış yapı/dizi F1 %85,9 | T5: fonksiyonlar arası çapraz denetim ve çatışma çözümü (kural kısmı) |
| XTRIDE (Seidel+ 2026) [Ö] | n-gram tip tahmini, güven puanı, işlev imzası | İstatistiksel | DIRT'te %90,15; 70-2300 kat hızlı; tam doğru yerleşim oranı en yüksek | Güven puanlı LLM'siz kıyas; DIRT GitHub kodu, sızıntı |
| SURE'25 (Soni+ 2025) [B] | 5 decompiler; Nixpkgs x86-64, -O0/-O2 (94/106 ikili); kapsam, doğruluk, kesinlik, YP | — | Doğruluk -O0/-O2: Hex-Rays %35,69/%49,74, Ghidra %21,57/%29,94; Ghidra kesinliği %40,64/%11,94. Yapı ölçüsü yalnız adlı kütüphane yapıları (FILE, stat): Ghidra -O0'da 150/800 | T0d beklentisi; kütüphane/program tabakası. Hafıza düzeltmesi §6 |
| Data Flows in You (Weideman+ 2025) [Ö] | angr, Ghidra, Miasm'ın veri akışını mikro testlerle ölçer | Evet | Doğruluk çok düşük; eklerle kesinlik 0,13 → 0,32 | T2: def-use'a mutant kanıtlı test. Tek arXiv kaynağı |

**(c) Yapı yerleşimi, `void *` ve kalıtım**

| Yöntem | Ne yapar ve sonuç | Plan adımına girdi |
|---|---|---|
| ASI (Ramalingam+ 1999) [Ö]; DIVINE (Balakrishnan, Reps 2007) [Ö, İ] | Kayıt ve dizileri programın erişim kalıbına göre tembelce atomlara böler, bildirilmemiş yapıyı da bulur; DIVINE ikilide VSA ile erişimleri gruplayıp yapıları yinelemeli inceltir | T4: alan atomları, ofset ve genişlik kümesi. VSA gürültülü (OSPREY) |
| Howard (Slowinska+ 2011) [Ö]; REWARDS (Lin+ 2010) [Ö] | Dinamik yapı çıkarımı; REWARDS bilinen kütüphane çağrılarını tip havuzu (type sink) sayıp ileri ve geri yayar | Adlı tip çapası fikri (statik karşılığı TIE) |
| Fiziksel alt tipleme: Siff+ 1999 [Ö]; Chandra, Reps 1999 [Ö] | C'deki yapı dönüşümleri nesne yönelimli kalıpları taklit ediyor; 1 milyon satırdan fazla C'de yapı dönüşümlerinin %90'ından fazlası önek ilişkisiyle açıklandı | K1 aile tanımının dayanağı; T3'te önek ilişkisi alt tip kenarı |
| TRex dipnot 9 [B] | Çok biçimlilik yoksa tek bir `void *` (ör. `malloc`) üzerinden geçen yollar birlik tipi üretir | T3: `void *` biçimsel parametrede birleştirme kesilir; K1'de joker |
| OOAnalyzer (Schwartz+ 2018) [Ö] | Prolog ile C++ sınıf ve metot kurtarma; metotların %78'inden fazlası doğru sınıfa | N5'in C++ karşılığı; C'de alıcı tipten nesne adını ölçen çalışma bulunamadı |

### 2.2 Fonksiyon adı kurtarma

| Yöntem | Ne yapar, girdisi | LLM'siz | Bildirilen sonuç | Plan adımına girdi |
|---|---|---|---|---|
| Debin (He+ 2018) [B] | JSNice'ın (Raychev+ 2015, JS'de CRF [İ]) ikili karşılığı. BAP-IR; değişken sınıflama + bağımlılık grafında CRF; bilinen düğümler (sabit, komut, dinamik ad) sabit, bilinmeyenler MAP ile | Öğrenmeli | x64 ad ve tip: kesinlik %68,8, duyarlılık %68,3 | N6: kesin çapa = bilinen düğüm. Oybirliği yumuşak MAP'ten daha kesin, daha dar [t]; ablasyon adayı |
| Punstrip (Patrick-Evans+ 2020) [B] | Olasılıksal parmak izi + çağrı grafında CRF/faktör grafı; bilinen fonksiyonlar sabit | Öğrenmeli | Debian C; üç düzeyli ölçüm: tam, NLP ile normalize, Symbol2Vec | N6; ölçüm düzeyleri |
| NERO (David+ 2020) [Ö, ö] | API çağrı yerleriyle zenginleştirilmiş CFG (argüman soyutlaması [D]); GNN | Öğrenmeli | Nero-GNN F1 45,53; API karartılınca 38,83 [ö] | N4: fiilin ana kaynağı API çağrı yeri |
| XFL (Patrick-Evans+ 2023) [Ö] | Dinamik çağrılan adlar, sabitler, taint, çağıran ve çağrılan ortalaması; ayrı dizgi özniteliği yok | Öğrenmeli | Debian, 1024 etiket: P 0,8345, R 0,5750, F1 0,6809; eşik doğrulamada F1'e göre | N4, N6; dizgi kanalı ML'de az kullanılmış |
| NFRE (Gao+ 2021) [İ] | Assembly'nin sıralı ve yapısal özellikleri | Öğrenmeli | %32 ve %16 göreli artış | — |
| SymLM (Jin+ 2022) [Ö] | Çağrı bağlamına duyarlı, yürütme farkında gömme; CodeWordNet | Öğrenmeli | Yinelenenler ayıklanınca F1 0,73 → 0,105 [ö] | Ölçüm (CodeWordNet) |
| SymGen (Jiang+ 2025) [ö] | Ghidra çıktısında ince ayarlı Code Llama 34B; çağrılan adları normalize etmek zorunda kalmış | Hayır | x86-64 token F1 0,351-0,397; A100'de 3 sn/fonksiyon | Kıyas; çağrılan adın gücü N6'yı destekler |
| GenNm (Xu+ 2025) [Ö] | Değişken adı; sorguya çağıran ve çağrılan adları eklenir | Hayır | Görülmemiş adlarda %17,3 → %22,8 | Faz 2 kıyası |
| REFORGE, REBENCH (2026) [ö, Ö] | LLM'le ad kurtarma ölçümü; REFORGE sentetik C korpusu | Hayır | Token F1 0,18-0,29, medyan 0; tam eşleşme %1,9-7,1 | Kıyas; darboğaz bilgi içeriği |
| capa (Mandiant) [Ö] | API, dizgi, sayı ve mantık birleşimiyle yetenek kuralı; ATT&CK/MBC; kuralda örnek konum | Kural | Kesinlik yayımlanmamış | N4 fiil sözlüğü; kural künyesi |
| Votipka+ 2020 [Ö] | 16 RE uzmanıyla gözlem | — | 15'i dizgi ve API listesiyle başlıyor; işaretler: API ve dizgi (15), sabit ve değişken adı (11) | N2 kanıt paketinin içeriği |

### 2.3 Ölçüm

| Konu | Kaynak | Ne söyler | Plan için |
|---|---|---|---|
| Token ve çok düzeyli eşleşme | NERO, SymLM, SymGen, REFORGE [ö]; Punstrip [B] | Alt token kümesi, cömert, bazılarında CodeWordNet; Punstrip: tam, NLP ile normalize, ad gömmesi | Kıyas ve ek ölçü, kaynak betiğiyle |
| Gömme benzerliği | IdBench [Ö], VarCLR [Ö] | Gömmeler ilişkiyi yakalıyor, benzerliği yakalamıyor; zıt anlamlılar benzer görünebilir | "Yanlış fiil"i (`open`/`close`) ödüllendirebilir; yakın isim ölçüsü olamaz |
| İnsan değerlendirmesi | DSN'25 (Yang+ 2025) [B]; Allamanis+ 2015 [İ] | 40 katılımcı: içsel ölçüler anlama kazancıyla örtüşmüyor, yine de üretilen adlar tercih ediliyor. Allamanis+: bildirimlerin %20'sine ad verirken F1 %60 (metot), %55 (sınıf) | Faz 3 değerlendiricileri; sabit kapsamda raporlama emsali |
| LLM yargıç | REFORGE [ö]; DecompileBench [Ö] | Anlamsal yeniden puanlama; LLM yargıçla anlaşılırlık | Yalnız ek; ezber ve yanlılık |
| Risk-kapsam | El-Yaniv, Wiener 2010 [Ö]; SGR [Ö]; AURC [İ]; LTT [Ö]; CRC [Ö]; Wilson 1927 [Ö] | Çekimser tahminci; istenen riski yüksek olasılıkla tutan eşik (SGR: ImageNet top-5'te %2 hata, %99,9 olasılık, ~%60 kapsam); LTT eşik seçimini çoklu hipotez testi olarak kurar | Kapı 1-2, N1, N6 |
| Tip ölçüsü | TIE, TRex, SURE'25 [B] | Örgü uzaklığı ve tutuculuk; öncelikli puan ve önemsiz taban; kapsam, doğruluk, kesinlik, YP | §3.2-§3.3 |
| Kümeleme ölçüsü | Amigó+ 2009 [Ö] | Dört biçimsel kısıtı yalnız B-cubed karşılıyor; çift sayımı büyük kümeleri karesel ağırlıklandırır [t] | K1 (taslakta ek ölçü) |
| Kopya ve sızıntı | Allamanis 2019 [Ö]; Arp+ 2022 [B]; SymGen, BLens, DIRE/DIRTY [ö] | Kopyalı korpusta ölçüler %100'e kadar şişebilir. Arp+: 30 makalede on tuzak (örnekleme yanlılığı, etiket hatası, veri gözetleme, uygunsuz taban, uygunsuz ölçü ve öbürleri) | gnulib tabakası; imza DB açık/kapalı; ön kayıt öz denetimi |
| LLM ezberi | Carlini+ 2023 [Ö]; Riddell+ 2024 [Ö] | Ezber model boyutu, kopya sayısı ve bağlam uzunluğuyla artar; kodda görülmüş alt kümede başarı yüksek | Popülerlik tabakası; kesim tarihi sonrası ya da sentetik programlar |

### 2.4 Kesin çapalar

| Kaynak | Literatürdeki kullanım | Kesinlik bilgisi | Plan için |
|---|---|---|---|
| Dinamik bağlama adları | Debin ve Punstrip'te bilinen düğüm ya da fonksiyon [B] | Ad kesin; kurtarma sayılmaz | N6'da sabit düğüm; ölçümde ayrı sınıf (sentez Kİ-2) |
| FLIRT [B] | İlk 32 bayt, değişken baytlar maskeli; CRC16; çakışmada başvurulan ad; çözülemeyen çakışma elle | İlke: "It is better not to recognize than to recognize wrongly." Ölçülmüş oran yok | N1 susturma ilkesinin emsali |
| Ghidra FID [B] | Tam ve özgül özet; ebeveyn ve çocuk eşleşmesi puana katılır; komut sayısı eşiği; farklı adlı çoklu eşleşme rastlantı işareti, düşük puanda raporlanmaz | Eşik küçük fonksiyonların rastlantısal eşleşmesine karşı; oran yok | N0: aynı kanıt birden çok fonksiyonda görünüyorsa sus |
| Lumina [B] | Fonksiyon md5'iyle meta veri; eski ve yeni meta veriye kalite puanı; 32 bayttan küçükleri ve `sub_` adlıları göndermez | Oran yok | Kalite puanı ≈ köken kaydı |
| BSim [Ö] | p-code veri akışından öznitelik vektörü; yakın komşu | — | İmza kanalı; sızıntı denetimi |
| Sistem çağrısı tanımlayıcıları (Jacobson+ 2011) [B] | libc sarmalayıcılarını sistem çağrısı etkileşiminden tanır | Mevcut parmak izi tekniklerinden belirgin iyi (özet) | KS-1, statik bağlı ikililer (sentez Kİ-8) |
| `assert`, `__func__`, log öneki | Ölçülmüş akademik yöntem bulunamadı; uygulamada Ghidra betikleri ve blog (Conviso). ML'de dizgi ya hiç (XFL) ya örtük (LLM) kullanılıyor | Yok | N0-N1 ölçümü literatürde boşluk; makalede katkı (taramamızla sınırlı) |

## 3. Ölçüm önerileri

### 3.1 Yaklaşık isim (Kapı 1-2, N6)

1. **Birincil ölçü rubrik** (doğru, yakın, yanlış, yanlış fiil); iki bağımsız etiketleyici ve uyum katsayısı (Cohen κ ya da Krippendorff α). Token ve gömme ölçüleri onun yerini tutmaz (DSN'25).
2. **Ana sayı:** risk-kapsam eğrisi ve "yanlış (yanlış fiil dahil) ≤ %10" noktasında yakın isim kapsamı.
   - Eşik geliştirme setinde SGR ya da LTT ile seçilir; doğrulamada tek okuma; yanlış oranının Wilson üst sınırı.
   - Örnekler program içinde bağımlı: aralık program düzeyinde kümeli önyüklemeyle de verilir [t].
   - N1'de alt kanallar tek tek susturulacaksa sıraları ön kayda yazılır; sabit sıralı ya da Bonferroni düzeltmeli test [t].
3. **Ek ve kıyas ölçüleri:** kaynak betiğiyle token P/R/F1 (CodeWordNet'li ve CodeWordNet'siz), tam eşleşme, Punstrip'in üç düzeyi; eğri özeti olarak AURC. Gömme benzerliği yalnız ek (IdBench).
4. **Çekimserlik:** `FUN_` bırakılan fonksiyon boş tahmindir; kesinliğe yanlış olarak girmez, kapsamı düşürür (`veri_setleri.md` §7 madde 4).

### 3.2 K1 (tip sınıfları)

1. Karar ölçüsü taslaktaki gibi (program başına çift kesinliği, makro ortalama). Emsali bulunamadı: literatür değişken başına tip doğruluğu (SURE'25, TYGR, DIRTY) ya da örgü uzaklığı (TIE) ölçüyor. Kıyas için değişken başına adlı yapı doğruluğu ek verilir.
2. **İki eşdeğerlik düzeyi:** katı (yapı kimliği) ve aile (önek ilişkisi). TRex'e göre izdüşüm tanımı sonucu bir mertebe değiştirebiliyor. Karar düzeyi önceden seçilir, öbürü aynı tabloda.
3. **Tabakalar:** kütüphane kökenli yapılar (FILE, stat; gnulib, `DW_AT_decl_file` yoluyla) ve program yapıları ayrı. SURE'25 decompiler yapı başarısını yalnız adlı kütüphane yapılarında ölçebildi.
4. **Tabanlar:** çıplak Ghidra (T0d) ve iki önemsiz taban: "hepsi tekil" ve "aynı boyuttaki bütün yapı işaretçileri tek sınıfta" [t]. Negatif kontrol taslakta var.
5. B-cubed ve küme başına saflık ek ölçü (Amigó+ 2009).

### 3.3 K2 (yapı yerleşimi)

1. Karar ölçüsü taslaktaki yaprak üçlüsü. Ekler: yapı başına "tam doğru yerleşim" oranı (XTRIDE, ReSym); TRex tarzı öncelikli puan (işaretçi mi → düzey → yapı mı → genişlik → işaret).
2. **Tabanlar:** Ghidra'nın "Auto Fill in Structure" çıktısı (TRex'in nitel kıyasındaki uygulayıcı tabanı) ve analitik şans tabanı.
3. "Doğrulanmış yerleşim" seçimi yanlılık yaratır; kesinlik alan kapsamı ve sizeof doğruluğuyla birlikte okunur (SURE'25'teki gibi).

### 3.4 Sızıntı ve ezber

- gnulib ve öbür ortak kod: geliştirme ve doğrulama setindeki ortak yapı ve fonksiyonlar ayrı tabaka (Allamanis 2019; SymGen'de yinelenenler %77,9 [ö]).
- İmza DB'si açık ve kapalı koşu (`veri_setleri.md` §7).
- LLM kıyası: program popülerliği tabakası; model kesim tarihinden sonra yayımlanmış sürümler ya da sentetik programlar (REFORGE).
- Arp+ 2022'nin on tuzağıyla ön kayıt öz denetimi. Karadul'a en yakın üçü: etiket hatası (etiketlerin hepsi LLM vekillerinden), veri gözetleme (beş doğrulama bakışı), uygunsuz taban (FID, FLIRT ve Lumina eşit katalog erişimiyle).

## 4. "İlgili çalışmalar" iskeleti

1. **Tip çıkarımı.** Birleştirme ve kısıt (Mycroft, TIE, Retypd, BinSub, TRex), olasılıksal (OSPREY), öğrenmeli ve LLM'li (DIRTY, TYGR, ReSym, TypeForge, XTRIDE); ölçüm tartışması (TRex, SURE'25). Yerimiz: SSA'lı p-code üstünde birleştirme, çağrı yeri çok biçimliliği, DWARF'a karşı çift tabanlı ölçü; Mach-O/arm64 ve Debian arm64 birlikte.
2. **Yapı yerleşimi.** ASI ve DIVINE, dinamik yöntemler (Howard, REWARDS), TIE ve TRex kısıtları, OSPREY, ReSym, TypeForge. Yerimiz: mühürlü "doğrulanmış yerleşim" ölçütü, program genelinde okunurluk.
3. **Fonksiyon adı.** Olasılıksal grafik modeller (JSNice, Debin, Punstrip), sinir ağları (NERO, NFRE, XFL, SymLM), LLM'ler (SymGen, GenNm) ve sınırları (REFORGE, REBENCH), imza sistemleri (FLIRT, FID, Lumina, BSim). Yerimiz: LLM'siz, kanıt künyeli, çekimser kalabilen, kalibre kesinlikli adlandırma; kendi adını yazan dizgi kanalının ölçümü.
4. **Ölçüm ve geçerlilik.** Token ölçüleri, gömme ölçülerinin sınırı (IdBench), insan çalışmaları (Votipka+, DSN'25), sızıntı (Allamanis, Arp+, SymGen, BLens), seçici tahmin (El-Yaniv ve Wiener, Geifman ve El-Yaniv, LTT).

## 5. Önemli iddialar

| Claim | Evidence | Confidence | Date checked | What may change |
|---|---|---|---|---|
| Bağlamdan bağımsız birleştirme, ortak ayırıcı ve `void *` üzerinden ilgisiz tipleri birleştirir; çok biçimlilik ya da öbek klonlama gerekir | Lattner+ 2007; Kuderski+ 2019; Noonan+ 2016; Smith 2024; TRex dipnot 9 | high | 2026-10-21 | Etkinin p-code'daki büyüklüğü ölçülmedi |
| İkili tip ölçümünde tek gerçek yok; doğruluk tanımı sonucu bir mertebe değiştirebilir | TRex §2.2, §5.2; SURE'25 ölçü çeşitliliği | medium | 2026-10-21 | "Bir mertebe" tek kaynaktan |
| Hazır decompiler'ların ölçülen yapı başarısı adlı kütüphane yapılarından geliyor | SURE'25 §5.3.4 | low | 2026-10-21 | Program yapılarını ölçen yeni kıyaslar |
| Retypd'nin açık uygulaması pratikte çıplak decompiler'ı geçmiyor | SURE'25; TRex §5.1 | medium | 2026-10-21 | Uygulama güncellemeleri |
| Öğrenmeli ad yöntemlerinin yüksek skorlarının büyük kısmı kopya ve sızıntıdan | SymGen ayıklaması; BLens katı bölme; DIRE/DIRTY görülen/görülmeyen; Allamanis 2019 | high | 2026-10-21 | — |
| Token ve gömme ölçüleri insan anlamasını izlemiyor; gömmeler zıt anlamlıları benzer sayabiliyor | DSN'25; IdBench; VarCLR | medium | 2026-10-21 | Yeni insan çalışmaları |
| İmza sistemleri yanlış pozitiften kaçınmayı ilke ediniyor, ama yayımlanmış kesinlik yok | FLIRT belgesi; Ghidra FID yardımı; Lumina belgesi | medium | 2026-10-21 | Yokluk iddiası; üreticiler ölçüm yayımlayabilir |
| `assert`, `__func__` ve log dizgisinden ad çıkarmanın ölçülmüş akademik çalışması yok | İki hedefli arama; Conviso blogu; XFL öznitelik listesi | low | 2026-10-21 | Gözden kaçmış çalışma çıkabilir |
| LLM ezberi kopya sayısı ve model boyutuyla artar; görülmüş alt kümede başarı yükselir | Carlini+ 2023; Riddell+ 2024 | high | 2026-10-21 | — |
| Seçici tahminde eşik, istenen risk için sonlu örneklem güvencesiyle seçilebilir | Geifman, El-Yaniv 2017; LTT; CRC | high | 2026-10-21 | Program içi bağımlılık güvenceyi zayıflatır |

## 6. Doğrulanamayanlar ve düzeltmeler

- **Hafıza düzeltmesi:** `karadul-2026-literatur.md`'deki "SURE 2025: Ghidra %31,27 / IDA %40,59 tip çıkarımı" yanlış eşleştirilmiş: %31,27 Ghidra'nın -O2'de işaretçi tanıma, %40,59 Hex-Rays'in -O2'de işaretçi hedefi çözme oranı (SURE'25 Şekil 15). Genel doğruluk §2.1(b)'de.
- **Hafıza:** OSPREY için "%90 P, %88 R" girişte bulunamadı; yalnız girişteki üstünlük aralıkları okundu.
- TRex: özet 123/125, yapıt eki ve Microsoft sayfası 124/125 diyor.
- Okunmayan ya da ikincil kalanlar: TypeForge sayıları (yalnız README ve slayt); AURC/E-AURC'nin Geifman+ 2019'a atfı; Das 2000'in kesinlik iddiası; NERO'nun argüman soyutlaması; NFRE yöntemi; Allamanis+ 2015 sayıları (proje sayfası); SmartDec içeriği; capa kural lisansı.
- Künye eksikleri: Chandra ve Reps 1999'un yayın yeri; 2026 tip çıkarımı taramasında (arXiv 2606.23692) tarih ile numara tutarsız.

## 7. Kaynakça

**Tip ve yapı**
- Andersen 1994. Program Analysis and Specialization for the C Programming Language. Doktora tezi, DIKU raporu 94/19.
- Balakrishnan, Reps 2007. DIVINE. VMCAI, LNCS, 1-28. DOI 10.1007/978-3-540-69738-1_1
- Bosamiya, Woo, Parno 2025. TRex. USENIX Security, 6897-6915. [sayfa](https://www.usenix.org/conference/usenixsecurity25/presentation/bosamiya); Zenodo 10.5281/zenodo.15611994
- Caballero, Lin 2016. Type Inference on Executables. ACM CSUR 48(4). DOI 10.1145/2896499
- Chandra, Reps 1999. Physical Type Checking for C. [özet](https://research.cs.wisc.edu/wpis/abstracts/BL-0113590-990302-04.abs.html) (yer [D])
- Das 2000. Unification-based Pointer Analysis with Directional Assignments. PLDI, 35-46. DOI 10.1145/349299.349309
- Kuderski, Navas, Gurfinkel 2019. Unification-based Pointer Analysis without Oversharing. FMCAD, 37-45. DOI 10.23919/FMCAD.2019.8894275
- Lattner, Lenharth, Adve 2007. Making Context-Sensitive Points-to Analysis with Heap Cloning Practical for the Real World (DSA). PLDI, 278-289. DOI 10.1145/1250734.1250766
- Lee, Avgerinos, Brumley 2011. TIE. NDSS.
- Lin, Zhang, Xu 2010. REWARDS. NDSS.
- Mycroft 1999. Type-Based Decompilation. ESOP, LNCS 1576, 208-223.
- Noonan, Loginov, Cok 2016. Polymorphic Type Inference for Machine Code (Retypd). PLDI, 27-41. DOI 10.1145/2908080.2908119
- O'Callahan, Jackson 1997. Lackwit. ICSE, 338-348. DOI 10.1145/253228.253351
- Ramalingam, Field, Tip 1999. Aggregate Structure Identification. POPL, 119-132. DOI 10.1145/292540.292553
- Schwartz ve ark. 2018. OOAnalyzer. CCS, 426-441. DOI 10.1145/3243734.3243793
- Seidel, Thomas, Rieck 2026. XTRIDE. CODASPY. arXiv 2603.08225
- Siff, Chandra, Ball, Kunchithapadam, Reps 1999. Coping with Type Casts in C. ESEC/FSE. DOI 10.1007/3-540-48166-4_12
- Slowinska, Stancescu, Bos 2011. Howard. NDSS.
- Smith 2024. BinSub. SAS (LNCS 2025), 425-450. DOI 10.1007/978-3-031-74776-2_17
- Soni, Dutcher, Bao, Wang 2025. Benchmarking Binary Type Inference Techniques in Decompilers. SURE '25. DOI 10.1145/3733822.3764675
- Steensgaard 1996a. Points-to Analysis in Almost Linear Time. POPL, 32-41. DOI 10.1145/237721.237727
- Steensgaard 1996b. Points-to Analysis by Type Inference of Programs with Structures and Unions. CC, 136-150. DOI 10.1007/3-540-61053-7_58
- Troshina, Derevenets, Chernov 2010. Reconstruction of Composite Types for Decompilation. SCAM, 179-188. [İ]
- Wang ve ark. 2025. TypeForge. IEEE S&P, 2847-2864. DOI 10.1109/SP61157.2025.00193
- Weideman ve ark. 2025. Data Flows in You. arXiv 2506.00313
- Xie ve ark. 2024. ReSym. CCS. DOI 10.1145/3658644.3670340
- Zhang ve ark. 2021. OSPREY. IEEE S&P, 813-832.
- Zheng ve ark. 2026. From Heuristics to Transformers (tarama). arXiv 2606.23692 (künye kısmen [D])
- Zhu ve ark. 2024. TYGR. USENIX Security.

**İsim ve kanıt**
- David, Alon, Yahav 2020. NERO. OOPSLA (PACMPL 4, 225). arXiv 1902.09122
- Gao, Cheng, Xue, Zhang 2021. NFRE. ISSTA, 607-619. DOI 10.1145/3460319.3464804
- He, Ivanov, Tsankov, Raychev, Vechev 2018. Debin. CCS. DOI 10.1145/3243734.3243866
- Jacobson, Rosenblum, Miller 2011. Labeling Library Functions in Stripped Binaries. PASTE, 1-8.
- Jin, Pei, Won, Lin 2022. SymLM. CCS, 1631-1645. DOI 10.1145/3548606.3560612
- Jiang, Jin, Lin 2025. SymGen. NDSS. [ö]
- Patrick-Evans, Cavallaro, Kinder 2020. Punstrip. ACSAC, 373-385. DOI 10.1145/3427228.3427265
- Patrick-Evans, Dannehl, Kinder 2023. XFL. IEEE S&P, 2375-2390. arXiv 2107.13404
- Raychev, Vechev, Krause 2015. JSNice. POPL, 111-124. DOI 10.1145/2676726.2677009
- Votipka ve ark. 2020. An Observational Investigation of Reverse Engineers' Processes. USENIX Security. arXiv 1912.00317
- Won, Jin, Ma, Lin 2026. REBENCH. AIWare (genişletilmiş sürüm arXiv 2604.27319)
- Xu ve ark. 2025. GenNm. NDSS. arXiv 2306.02546
- REFORGE (Koller, Schmidt 2026, arXiv 2607.07738), BLens, DIRE, DIRTY, VarBERT: künyeler `veri_setleri.md` §11 ve `tersine_derleme_sinirlari.md` §7'de.
- Araç belgeleri: [capa](https://github.com/mandiant/capa); [FLIRT](https://docs.hex-rays.com/core/flirt/concepts/ida-f.l.i.r.t.-technology-in-depth.md); [Lumina](https://docs.hex-rays.com/add-ons/lumina/overview.md); Ghidra kaynak ağacında `FunctionID.html` ve `BSimOverview.html`; [Conviso blogu](https://www.convisoappsec.com/blog-conviso/automatically-renaming-functions-with-ghidra)

**Ölçüm**
- Allamanis 2019. The Adverse Effects of Code Duplication in ML Models of Code. Onward! 2019; arXiv 1812.06469
- Allamanis, Barr, Bird, Sutton 2015. Suggesting Accurate Method and Class Names. ESEC/FSE. DOI 10.1145/2786805.2786849 [İ]
- Amigó, Gonzalo, Artiles, Verdejo 2009. Extrinsic Clustering Evaluation Metrics. Information Retrieval 12(4):461-486. DOI 10.1007/s10791-008-9066-8
- Angelopoulos, Bates, Candès, Jordan, Lei 2021. Learn then Test. arXiv 2110.01052
- Angelopoulos, Bates, Fisch, Lei, Schuster 2024. Conformal Risk Control. ICLR. arXiv 2208.02814
- Arp ve ark. 2022. Dos and Don'ts of ML in Computer Security. USENIX Security. arXiv 2010.09470
- Carlini ve ark. 2023. Quantifying Memorization Across Neural Language Models. ICLR. arXiv 2202.07646
- Chen ve ark. 2022. VarCLR. ICSE. arXiv 2112.02650
- El-Yaniv, Wiener 2010. Noise-free Selective Classification. JMLR 11:1605-1641
- Gao ve ark. 2025. DecompileBench. arXiv 2505.11340
- Geifman, El-Yaniv 2017. Selective Classification for Deep Neural Networks (SGR). NeurIPS, 4878-4887. arXiv 1705.08500
- Geifman, Uziel, El-Yaniv 2019. Bias-Reduced Uncertainty Estimation (AURC atfı [İ]). ICLR. arXiv 1805.08206
- Riddell, Ni, Cohan 2024. Quantifying Contamination in Code Generation Evaluation. ACL, 14116-14137. DOI 10.18653/v1/2024.acl-long.761
- Wainakh, Rauf, Pradel 2021. IdBench. ICSE, 562-573. DOI 10.1109/ICSE43902.2021.00059
- Wilson 1927. Probable Inference, the Law of Succession, and Statistical Inference. JASA 22(158):209-212. DOI 10.1080/01621459.1927.10502953
- Yang ve ark. 2025. A Human Study of Automatically Generated Decompiler Annotations. DSN, 129-142. DOI 10.1109/DSN64029.2025.00026
