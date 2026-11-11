# Yerleşim keşfi: adres sırasına dayalı bölme seçenekleri

- **Tarih:** 2026-11-11.
- **Durum: ÖN KAYITSIZ KEŞİF, GELİŞTİRME SETİ. Bu belge bir tasarım girdisidir; içindeki hiçbir sayı ürün iddiası değildir.** Seçenekler, eşikler ve ızgaralar bu sette, sonuçlara bakılarak denendi. Bağımsız iddia için doğrulama seti ve yeni ön kayıt gerekir (§6).
- **Dayanak:** `harita_sonuc.md` (ön kayıtlı ölçüm; ürün 0,097, adres tabanı B1 0,424) ve onun açtığı iş kalemi: yerleşimde adres sırasının kullanılması.
- **Ürün kodu değişmedi.** Yalnız çevrimdışı hesap: betik `yerlesim_kesfi.py`, çıktı `yerlesim_kesfi.json`.
- Bu belgede fonksiyon adı ve kaynak dosya adı geçmez. "Sınıf" = fonksiyonun gerçek kaynak dosyası (GT).

## 1. Sağlama

| Denetim | Sonuç |
|---|---|
| B1 makro ARI, `harita_olc.py`'den içe aktarılan `b1_bolme` + `olculer` + `makro` ile | 0,423659; ölçümdeki 0,423659 ile aynı; yedi programın değeri de aynı |
| Ürün satırı | 0,097077 = 0,097077 |
| `b1_gt` satırı | 0,299268 = 0,299268 |
| GT'nin `harita_olc.gt_oku` + `urun_oku` ile YENİDEN okunması, ölçüm JSON'undaki öğelerle karşılaştırma | 115 ikilinin 115'inde nüfus adresleri ve iki bölme (modül, dosya sınıfı) aynı |

Sağlama tuttu. Betik tutmazsa 2 ile çıkar.

## 2. Veri ve kurallar

- Nüfus, ürün modülü ve GT sınıf kodları ön kayıtlı ölçümün çıktısından (`harita_olcumu.json`, `ogeler`) okunur: 114 ikili, 7 program, 28 200 fonksiyon. GT yalnız değerlendirmede kullanılır.
- Yöntemlerin girdisi GT'sizdir: çalışma alanındaki `ghidra_functions.json` (adres, boyut, thunk) ve `ghidra_call_graph.json`.
- **Evren:** adres sırasında, hedefsiz thunk olmayan Ghidra fonksiyonları (40 218; 29 626'sı "çekirdek"). Kitaplık geçitleri (PLT girişleri ve dış fonksiyona atlayan sarmalayıcılar) evrende kalır ama kenarları atılır ve sayıya dayalı kurallarda sayılmaz. PLT girişi ile metin içi sarmalayıcı GT'siz ayrılamadı; iki deneme başarısız oldu (§7).
- Her yöntem evrende çalışır; etiketler nüfusa indirgenir; ölçü ve toplama `harita_olc.py`'nin kuralıdır (ikili → program → makro).
- Sabitler (`N_MIN`, `EN_AZ_PROGRAM`, `ONDALIK`, karar düzeyi) `harita_olc.py` / `ks1_olc.py`'den içe aktarılır.
- `b1_evren`: B1 kuralının evrende uygulanmış hâli (0,428). Nüfus ile evren arasındaki fark sonucu değiştirmiyor.
- `tavan` yöntem değildir: GT sınıfının her değişiminde kesen bitişik bölme. Bitişik bir yöntemin ulaşabileceği üst sınırdır.

## 3. Seçenekler ve sonuçlar

Dosya düzeyi, program düzeyi makro. "Parça / GT sınıf": 1'in altı az bölme, üstü aşırı bölme.

| Satır | Makro ARI | Çift kesinliği | Çift duyarlılığı | Parça / GT sınıf | coreutils | htop | openssl | redis-tools (LTO) | tmux | tree | zstd |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `urun` | 0,097 | 0,153 | 0,418 | 0,469 | 0,335 | 0,019 | 0,083 | 0,078 | 0,009 | 0,077 | 0,079 |
| `b1` | 0,424 | 0,538 | 0,447 | 0,469 | 0,296 | 0,515 | 0,412 | 0,354 | 0,432 | 0,492 | 0,464 |
| `tavan` (GT kullanır) | 0,945 | 1,000 | 0,918 | 1,359 | 1,000 | 1,000 | 1,000 | 0,677 | 1,000 | 1,000 | 0,941 |
| S1 `s1_karekok` | 0,402 | 0,572 | 0,379 | 0,546 | 0,355 | 0,479 | 0,379 | 0,349 | 0,448 | 0,419 | 0,383 |
| S2 `s2_dolgu16` | 0,705 | 0,621 | 0,948 | 0,554 | 0,605 | 0,650 | 0,877 | 0,385 | 0,793 | 0,911 | 0,710 |
| S3 `s3_g1` | 0,421 | 0,412 | 0,726 | 1,029 | 0,706 | 0,080 | 0,513 | 0,318 | 0,370 | 0,394 | 0,567 |
| S3 `s3_g2` | 0,519 | 0,622 | 0,539 | 2,013 | 0,837 | 0,256 | 0,517 | 0,444 | 0,512 | 0,422 | 0,643 |
| S4 `s4_g1` | 0,461 | 0,446 | 0,733 | 1,181 | 0,473 | 0,138 | 0,633 | 0,412 | 0,476 | 0,443 | 0,654 |
| S4 `s4_g2` | 0,569 | 0,690 | 0,581 | 2,058 | 0,646 | 0,360 | 0,580 | 0,500 | 0,804 | 0,388 | 0,705 |
| S2+S4 `s4c_hiza32_g1` | 0,673 | 0,757 | 0,690 | 1,495 | 0,604 | 0,522 | 0,719 | 0,478 | 0,858 | 0,756 | 0,775 |
| S2+S3 `s3e_sifir_gecis_bagli` | 0,697 | 0,651 | 0,886 | 0,684 | 0,616 | 0,611 | 0,863 | 0,393 | 0,815 | 0,813 | 0,766 |
| S5 `s5_s4_birlesik` | 0,327 | 0,290 | 0,775 | 0,243 | 0,403 | 0,095 | 0,469 | 0,332 | 0,161 | 0,325 | 0,502 |
| S5 `s5_kapili_s2_g1` | 0,708 | 0,625 | 0,930 | 0,631 | 0,605 | 0,650 | 0,877 | 0,412 | 0,793 | 0,911 | 0,710 |
| S5 `s5_kapili_s2_g2` | 0,721 | 0,658 | 0,915 | 0,840 | 0,605 | 0,650 | 0,877 | 0,500 | 0,793 | 0,911 | 0,710 |

Bütün satırlar (ızgaraların tamamı) `yerlesim_kesfi.json` → `ozet` altındadır.

### S1: eşit parça, parça sayısı modül sayısından bağımsız

- Kural: `⌈√N⌉` parça (N: çekirdek fonksiyon sayısı). Makro 0,402; B1'in (0,424) altında.
- Duyarlılık eğrisi (sabit ortalama parça boyu → makro ARI): 2 → 0,056; 3 → 0,101; 4 → 0,140; 6 → 0,208; 8 → 0,255; 12 → 0,321; 16 → 0,351; 24 → 0,381; 32 → 0,376; 48 → 0,359.
- **Sonuç: kazanç yok.** Denenen on bir eşit bölme kuralının hiçbiri B1'i geçmiyor. Sorun parça sayısı değil, sınırın yeri.

### S2: sınır, fonksiyonlar arasındaki dolguya göre

- Kural: ardışık iki fonksiyon arasındaki boşluk ≥ 16 bayt ise yeni parça.
- Makro 0,705; yedi programın yedisinde B1'in üstünde. İkili düzeyinde B1'i geçen: coreutils 105/105, htop, openssl, tmux, tree, zstd 1/1, redis-tools 2/4.
- Eşik eğrisi (bayt → makro ARI): 1 → 0,145; 4 → 0,145; 8 → 0,207; 12 → 0,331; **16 → 0,705**; 20 → 0,622; 24 → 0,465; 28 → 0,313; 32 → 0,039. Eşik bıçak sırtıdır: 12'de ve 32'de yöntem çöker.

Neden çalıştığını gösteren döküm (ardışık çiftler; hücre: sınıf aynı / sınıf değişti):

| Program | negatif | 0 | 1–11 | 12–15 | 16–31 | ≥ 32 |
|---|---|---|---|---|---|---|
| coreutils | 21 / 105 | 7103 / 467 | 1498 / 558 | 1136 / 475 | 3 / 1718 | 117 / 8 |
| htop | 0 / 0 | 314 / 8 | 139 / 23 | 69 / 8 | 0 / 43 | 0 / 1 |
| openssl | 8 / 0 | 311 / 7 | 134 / 18 | 68 / 8 | 0 / 40 | 0 / 0 |
| redis-tools (LTO) | 3 / 0 | 5637 / 646 | 2398 / 288 | 1157 / 140 | 24 / 60 | 8 / 1 |
| tmux | 0 / 0 | 1082 / 18 | 436 / 47 | 243 / 15 | 0 / 65 | 0 / 1 |
| tree | 0 / 0 | 60 / 1 | 23 / 1 | 14 / 0 | 0 / 8 | 0 / 0 |
| zstd | 1 / 0 | 604 / 22 | 271 / 8 | 129 / 8 | 0 / 20 | 0 / 0 |

- LTO'suz altı programda 16–31 baytlık dolgu 1897 kez görüldü; 1894'ünde sınıf değişiyor (sınır kesinliği 0,998 **[hesap]**). Bu dolgu gerçek sınırların yaklaşık yarısını yakalıyor (0,512 **[hesap]**; program başına 0,345–0,800). Kalan yarı dolgudan görünmüyor.
- İkinci gözlem (hizalama): LTO'suz programlarda sınıf, yalnız başlangıç adresi 32'nin katı olan fonksiyonda değişiyor. Katı olmayan 7082 başlangıcın 18'inde sınıf değişti (coreutils 3, zstd 15, öbür dördünde 0). Bu bir dışlama kuralıdır: aday sınırların yaklaşık yarısını eler. Tek başına bölme olarak işe yaramaz (`s2_hiza32` 0,096: aşırı bölme).
- LTO'lu redis-tools'ta iki gözlem de bozulur: 16–31 dolgusunda 24 / 60; 32'nin katı olmayan başlangıçların 501'inde sınıf değişiyor.
- **Mekanizma (varsayım; derleyici kaynağından doğrulanmadı):** derleyici dosya içinde hizalama için en çok 15 bayt atlıyor; bağlayıcı ise her nesne dosyasının kod bölümünü 32'ye hizalıyor. Öyleyse 16–31 baytlık boşluk yalnız nesne dosyası sınırında oluşur. Gözlenen dağılım bununla tutarlı (dosya içinde 16–31 neredeyse hiç yok; ≥ 32 neredeyse hiç yok).
- **En zayıf yeri:** araç zincirine özgü. Yedi programın hepsi aynı dağıtım, aynı mimari, aynı derleyici ailesi (Debian 13, AArch64, GCC). Programlar arası tutarlılık, araç zincirleri arası genellemeyi göstermez. Başka hizalama kuralı kullanan derlemede (x86-64, Clang, Mach-O) sinyal hiç olmayabilir. LTO'da "nesne dosyası" kaynak dosya değil LTO bölümüdür; sinyal anlamını yitirir.

### S3: bitişik modülerlik dilimlemesi (çağrı grafı)

- Kural: adres sırasındaki dizi bitişik dilimlere bölünür; çağrı grafının modülerliği dinamik programlamayla en büyüklenir. Parça sayısı çıktıdır. γ = 1 standart tanımdır (ayar yok).
- γ = 1: makro 0,421; B1 ile aynı düzeyde. htop'ta 0,080; nedeni incelenmedi (yalıtık fonksiyonlar kural gereği önceki dilime katılır; dolaylı çağrısı çok olan programda bu büyük dilim üretir: varsayım).
- γ eğrisi (makro; parantezde redis-tools): 0,25 → 0,030; 0,5 → 0,180; 1 → 0,421 (0,318); 2 → 0,519 (0,444); 4 → 0,496 (0,422); 8 → 0,317; 16 → 0,173; 32 → 0,114. Tepe γ = 2'de; bu sette ayarlanmış olur.

### S4: S3 + statik fonksiyon ipucu

- Kural: kenar ağırlığı 1 / (çağrılanın farklı çağıran sayısı). Tek yerden çağrılan fonksiyon büyük olasılıkla çağıranının dosyasındadır; çok yerden çağrılan ortak yardımcıdır. Ek parametre yok.
- γ = 1: makro 0,461 (S3'ün 0,040 üstünde **[hesap]**); γ = 2: 0,569. Yedi programın altısında S3'ten iyi; coreutils'te belirgin kötü (0,473 ↔ 0,706).
- LTO'lu redis-tools'ta yalnız çağrı grafı kullanan seçeneklerin en iyisi bu ailede: γ = 1'de 0,412, γ = 2'de 0,500 (B1 0,354; S2 0,385; tavan 0,677).

### S2 + çağrı grafı: ikinci aşama denemeleri

S2 sınırların yarısını kaçırıyor. Kalan yarıyı çağrı grafıyla bulma denemeleri:

| Deneme | Makro ARI | Not |
|---|---|---|
| `s4b_dolgu16`: S2 sınırları zorunlu + S4 dilimlemesi | γ 0,125 → 0,648; 0,25 → 0,653; 0,5 → 0,634; 1 → 0,613; 2 → 0,592 | hepsi S2'nin altında |
| `s4c_hiza32`: ayrıca dilim yalnız 32'nin katında başlar | γ 0,125 → 0,666; 0,25 → 0,674; 0,5 → 0,678; 1 → 0,673; 2 → 0,630 | hizalama kısıtı her γ'da iyileştiriyor; yine S2'nin altında |
| `s3d_sifir_gecis`: S2 parçası içinde hiçbir çağrının aşmadığı izinli sıralardan kes | 0,641 | parametresiz |
| `s3e_sifir_gecis_bagli`: aynısı, çağrı kanıtı olmayan blok ayrılmaz | 0,697 | parametresiz; S2 ile aynı düzeyde |

- **Sonuç: bu sette çağrı grafı, dolgu sinyalinin üstüne LTO'suz programlarda kazanç getirmedi.** İkinci aşama kesinliği artırıyor ama duyarlılığı daha çok düşürüyor: S2'de 0,621 / 0,948; `s3e_sifir_gecis_bagli`'da 0,651 / 0,886; `s4c_hiza32_g1`'de 0,757 / 0,690. Yani yanlış yerden kesiyor.
- LTO'lu redis-tools'ta durum terstir: γ = 1 ve 2 olan birleşimler S2'den iyidir (0,473–0,532 ↔ 0,385; γ = 4'te 0,434–0,468); γ < 1 olanlar ve sıfır geçişli kurallar S2 ile aynı düzeydedir (0,384–0,423).

### S5: LTO'ya dayanıklılık

- **Çağrı yerelliği LTO'yu ayırt ETMİYOR.** Çağrı kenarlarının ortalama sıra uzaklığı: LTO'lu dört ikili 0,114–0,175; LTO'suz 110 ikili 0,090–0,209; aralıklar iç içe. GT bitişikliğiyle sıra korelasyonu −0,096 (n = 114). En iyi bitişik modülerlik (Q) de ayırt etmiyor (0,287).
- **Bitişik olmayan dilimleri birleştirmek zarar veriyor.** `s5_s4_birlesik` 0,327 (S4 γ = 1: 0,461); redis-tools'ta da kötü (0,332 ↔ 0,412).
- **Ayırt eden gösterge: kesin sınır yoğunluğu** (16–31 baytlık dolgu sayısı / çekirdek fonksiyon sayısı). LTO'lu dört ikili 0,0102–0,0155; LTO'suz 110 ikili 0,0216–0,2132. Aralıklar ayrık ama dar; en yakın LTO'suz ikili 0,0216.
- Kapılı seçenek: yoğunluk ≥ 0,018 ise S2, değilse S4. `s5_kapili_s2_g1` 0,708; `s5_kapili_s2_g2` 0,721. Kazancın tamamı redis-tools'tan gelir (0,385 → 0,412 / 0,500).
- **En zayıf yeri:** tek LTO'lu program, dört ikili (ikisinin fonksiyon ve kenar sayısı aynı: 5075 ve 14 498; bağımsız iki gözlem sayılmamalı). Eşik bu sette seçildi ve keşif sırasında bir kez taşındı (yoğunluğun paydası değişince 0,015 → 0,018). Gösterge LTO'yu değil "fonksiyon başına az nesne sınırı"nı ölçer; çok büyük kaynak dosyalı LTO'suz bir programı da LTO sayar.

## 4. Parametre sayımı ve aşırı uyum

| Seçenek | Ayarlanabilir parametre | Bu sette ayarlandı mı |
|---|---|---|
| S1 `s1_karekok` | 0 (kural seçimi: karekök) | Hayır; eğriye bakıldı, kazanç yok |
| S2 `s2_dolgu16` | 1 (dolgu eşiği) | **Evet.** On değerlik ızgaradan seçildi; mekanizma sonradan önerildi |
| Hizalama kısıtı | 1 (32) | **Evet.** Gözlemden seçildi |
| S3 γ = 1 | 0 | Hayır |
| S3 / S4 γ = 2 | 1 (γ) | **Evet.** Sekiz değerlik ızgaranın tepesi |
| S4 γ = 1 | 0 (ağırlık kuralı sabit) | Hayır; ama kural sonuç görülmeden önce tek biçimde yazıldı, başka biçim denenmedi |
| `s3e_sifir_gecis_bagli` | 0 ek (S2'nin 2 parametresini devralır) | Kuralın kendisi sonuçlara bakılarak eklendi |
| `s5_kapili_s2_*` | 3–4 (dolgu eşiği, yoğunluk eşiği, γ, hizalama) | **Evet, hepsi.** En yüksek aşırı uyum riski |

- Bu keşifte 70 yöntem satırı denendi (ızgaralar dahil). En iyi satırı seçip "sonuç" diye okumak çoklu karşılaştırma hatasıdır.
- coreutils'in 105 ikilisi ortak kitaplık kodunu paylaşır; ikili sayıları bağımsız gözlem sayısı değildir. Program düzeyi makro bunu kısmen dengeler; yine de yalnız 7 program var.

## 5. Ürüne nasıl girer (tarif; kod yazılmadı)

Dosya: `karadul/reconstruction/c_project_builder.py`.

- **Değişen adım:** `build()` içindeki alt sistem sınıflandırması (satır 281–301). Bugün modülü `_classify_subsystem` (satır 690) belirliyor; `misc` kalanlar `_detect_communities` (satır 735) ile topluluğa gidiyor (satır 296–301). Yeni düzende yerleşim anahtarı adres dilimi olur: fonksiyonlar adrese göre dizilir, dilimleme `func_subsystem` yerine bir "fonksiyon → dilim" eşlemesi üretir. Küçük / normal ayrımı (satır 310–324) ve dizin yazımı (satır 352–374, dizin adı satır 359) bu eşlemeyi kullanır.
- **Gereken yeni girdi:** fonksiyon boyutu. Yapıcı bugün yalnız `ghidra_call_graph.json` okuyor (`_load_call_graph`, satır 669); `ghidra_functions.json` (aynı `static` dizini) okunmuyor. Adres zaten var: düğümler adresle anahtarlı (satır 285) ve her birimin başlığında adres satırı bulunuyor.
- **Kural modülleri dosya içi etiket olarak korunur:** `_classify_subsystem` çalışmaya devam eder ama dizini belirlemez. Sonucu üç yere yazılır: (a) fonksiyon başlığına bir yorum satırı; (b) `analysis/subsystem_map.md`'ye sütun (`_build_subsystem_map`, satır 1168); (c) istenirse dilim dizininin adına, dilimdeki çoğunluk etiketi (eşitlikte `_SUBSYSTEM_ORDER`). Böylece "bu fonksiyon dosya G/Ç yapıyor" bilgisi kaybolmaz, yalnız yerleşimi belirlemez.
- **Topluluk tespiti:** adres yöntemi devreye girdiğinde `_detect_communities` yerleşimden çıkar; kapı adres yöntemini kapatırsa (LTO) geri düşüş olarak kalabilir. Hangisinin geri düşüş olacağı ölçümle seçilir (§6).
- **Belirlenimlilik:** sıralama tam sayı adrese göre (onaltılık dizgiye göre değil); dilim numarası başlangıç adresi sırasıyla; dinamik programlamada eşitlikte en küçük sıra; küme dolaşımına ve karma tohumuna bağlı hiçbir adım yok. S4'ün kesirli ağırlıkları üründe tam sayıya ölçeklenmelidir (bu betik kayan nokta kullanıyor; eşitlikler aynı makinede kararlı, makineler arası güvence yok). `_check_placement` (satır 602) değişmeden kalır: her birim tam bir dosyada.
- **Sabitler:** dolgu eşiği, hizalama ve kapı eşiği `karadul/config.py`'de tek yerde tanımlanır; araç zincirine göre değişebileceği için ikiliden kestirilmesi ayrı bir iş kalemidir.
- **README:** `_build_readme` (satır 1203; metin satır 1244–1246) yöntemi anlatır. "Kaynak dosya yapısını yansıtır" cümlesi doğrulama ölçümünden önce yazılmaz.

## 6. Sıradaki ölçüm için öneri

Seçim ana oturumundur. Seçenekler kazanç, karmaşıklık ve aşırı uyum riskiyle sıralandı:

| Sıra | Seçenek | Bu setteki kazanç (B1'e göre) | Karmaşıklık | Aşırı uyum riski |
|---|---|---|---|---|
| 1 | S2 `s2_dolgu16` | +0,281 (0,705) | Çok düşük: tek geçiş, tek eşik | Orta: eşik bu sette seçildi; araç zincirine özgü; LTO'da zayıf |
| 2 | S4 γ = 1 | +0,037 (0,461) | Orta: O(N²) dinamik programlama | Düşük: ayarlanan parametre yok; kazanç küçük |
| 3 | `s5_kapili_s2_g1` (S2, yoğunluk düşükse S4 γ = 1) | +0,284 (0,708) | Orta | Yüksek: kapı eşiği tek LTO programına dayanıyor |
| 4 | `s3e_sifir_gecis_bagli` | +0,273 (0,697) | Orta | Yüksek: kural sonuçlara bakılarak eklendi; S2'yi geçmiyor |
| 5 | S3 / S4 γ = 2 | +0,095 / +0,145 | Orta | Yüksek: γ bu sette ayarlandı |
| — | S1 | −0,022 | — | Önerilmez |
| — | S5 birleştirme, çağrı yerelliği göstergesi | negatif | — | Önerilmez |

Ön kayıt için öneriler:

- **Veri:** doğrulama seti gerekir. Bu keşifte doğrulama setine bakılmadı; içeriği bilinmiyor.
- **Asıl soru araç zinciri.** Doğrulama seti de Debian / AArch64 / GCC ise S2'nin orada tutması, başka derleyicide tutacağını göstermez. Ön kayıtta bu sınır açık yazılmalı ya da ölçüme farklı araç zinciriyle derlenmiş en az bir program eklenmelidir. Mach-O ikililerinde kaynak dosya GT'si yok; Mac için sonuç üretilemez.
- **Dondurulacaklar:** dolgu eşiği 16, hizalama 32, γ = 1, yoğunluk eşiği; hiçbiri doğrulama setinde yeniden ayarlanmaz.
- **Önceden yazılacak kararlar:** (a) S2 ↔ B1 (program başına eşli fark, aynı 0,05 eşiği ve 2/3 çoğunluk); (b) S4 γ = 1 ↔ B1 (parametresiz karşılaştırma kolu); (c) kapılı seçenek ↔ S2; (d) LTO'lu programlar ayrı satır. Doğrulama setinde LTO'lu program yoksa (c) sınanamaz ve öyle yazılır.
- **Mekanizma denetimi (GT'siz, ölçümden önce yapılabilir):** dolgu dağılımının 16–31 aralığında kütle taşıyıp taşımadığı her ikilide sayılabilir. Taşımıyorsa S2 o ikilide sınır üretmez; ön kayıt bu durumu "sinyal yok" diye ayrı sayabilir.

## 7. Sınırlar ve yapılmayanlar

- Yalnız Debian 13, AArch64, GCC; 7 program; tek LTO'lu program. Mac ölçülmedi (GT yok).
- Dolgu mekanizması derleyici ve bağlayıcı belgelerinden doğrulanmadı; yalnız dağılımla tutarlılığı gösterildi.
- Veri ve dizgi başvuruları kullanılmadı. Çalışma alanında fonksiyon başına yalnız dizgi başvurusu var; genel veri başvurusu fonksiyon düzeyinde yok.
- PLT girişleri evrenden GT'siz ayıklanamadı: "bütün hedefleri dış" ve "en uzun kesintisiz dizi" kuralları, nüfustaki gerçek fonksiyonları da dışladı (LTO'lu bir ikilide 4 ve 3 adres). Çözüm: evrende bırakıp kenarlarını atmak. Ürüne girerken bu ayrım yeniden ele alınmalı.
- İkinci aşama için yalnız dört kural denendi. "Çağrı grafı dolgunun üstüne kazanç getirmiyor" bulgusu bu dört kuralla sınırlıdır.
- Dizin düzeyi ölçülmedi. Yerleşimin dizin yapısına etkisi bilinmiyor.
- Rastgele taban (B0) yeniden koşulmadı; ön kayıtlı ölçümdeki değer geçerlidir.
- Ürün kodu, testler, ön kayıt ve sonuç belgeleri değişmedi. Kör setlere bakılmadı. Ghidra ve Karadul hattı koşturulmadı.

## 8. Komutlar

```
K=~/karadul_olcum/runs/urun-yeni-93a2956
D=~/karadul_olcum/runs/yerlesim-kesfi-2026-11-11

# Bu belgedeki bütün sayılar (çıktı: yerlesim_kesfi.json; tablo: $D/kosu.txt)
python3 docs/arge/2026-11-11_harita/yerlesim_kesfi.py --debian-kosu $K/debian \
    --olcum docs/arge/2026-11-11_harita/harita_olcumu.json \
    --json docs/arge/2026-11-11_harita/yerlesim_kesfi.json --gt-sagla htop tree > $D/kosu.txt

# GT'nin bütün programlarda yeniden okunması (§1'in son satırı; çıktı: $D/tam_gt_saglama.json)
python3 docs/arge/2026-11-11_harita/yerlesim_kesfi.py --debian-kosu $K/debian \
    --olcum docs/arge/2026-11-11_harita/harita_olcumu.json --json $D/tam_gt_saglama.json \
    --gt-sagla coreutils htop openssl redis-tools tmux tree zstd > $D/kosu_gt.txt
```

- `yerlesim_kesfi.py` sha256 `a4d4c2cae9446c99…`; `yerlesim_kesfi.json` sha256 `7df4a65ed8df0e78…`; `harita_olc.py` sha256 `1a205ca42d4d9e3d…` (ön kayıttaki ile aynı dosya, değişmedi).
- Tam GT sağlaması betiğin daha erken bir sürümüyle koştu; o sürümle son sürüm arasında GT okuma ve karşılaştırma kodu (`gt_sagla`, `ogeleri_ac`) değişmedi, yalnız seçenekler değişti. O koşunun seçenek tablosu geçersizdir, kullanılmadı.
- **[hesap]** işaretli sayılar JSON'daki sayılardan elle türetildi: sınır kesinliği 1894 / 1897; yakalanan pay = 16–31 kutusundaki sınıf değişimi / bütün sınıf değişimleri (`dolgu_dokumu`); farklar iki satırın çıkarması.
- İkili düzeyi "B1'i geçen" sayıları ve yoğunluk aralıkları: `yerlesim_kesfi.json` → `ikili_ari`, `gostergeler`, `gosterge_ozeti`.
