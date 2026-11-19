# ARGE yön kararı (2026-11-19, ana oturum: Mythos)

- **Taban:** birleşik ölçüm a62f15e (`docs/arge/2026-11-19_birlesik_olcum/sonuc.md`). main bugün fc3c5c6 (tabandan sonra P02b, P16d, P-S4, P12c, P05c, P22c, P22h, P20b, P18 girdi; ad etkileri bu tabanda yok).
- **Soru listesi:** `docs/arge/2026-11-18_arge_soru_listesi.md` (SON SÜRÜM).
- **Düzen (Berke, 2026-11-19):** en çok 3 Mythos ajanı, yalnız araştırma için; ölçüm, veri hazırlığı ve uygulama Opus ajanlarına.
- Bu belge yön kararıdır; Onuncu Adam itirazı aynı anda istendi (`onuncu_adam.md`), ikinci dalgadan önce işlenir.

## 1. Zeminin okunuşu

1. Yanlış ad sorunu büyük ölçüde kapandı: havuzda %6,6. Kalan 119 yanlışın 104'ü tek kanaldan (`string_context/oz_ad`, kesinlik %47,2).
2. Asıl açık kapsam: doğru ad 1 212 / 21 371 (%5,7).
3. Doğru adların dağılımı tek mekanizmaya yaslanıyor. 1 681 doğru adın 733'ü gnulib ön ad kanalından (kuralları bu setin GT'sine bakılarak kuruldu), 458'i ELF önyük kalıbından, 110'u `main` girişinden. Coreutils dışındaki sekiz birimde doğru ad toplamı 410 (tmux iki platformda 353).
4. Bu yüzden iki şey bilinmiyor:
   - ad bekleyen 21 371 fonksiyonun ne kadarı başka bir yerde kaynağı bulunan kod (kitaplık kopyası, aynı programın başka derlemesi), ne kadarı programın yalnız kendi kodu;
   - set dışında (başka program, derleyici, platform) bu sayıların ne kadarı ayakta kalır.
5. "Yakın ad" iddialarının hiçbiri bugün kabul edilemiyor, çünkü benzerlik ölçüsü tanımlı değil (B3).

## 2. Seçilen hatlar ve neden

| Hat | Sorular | Neden | İlk turun doğrulayıcısı |
|---|---|---|---|
| **KİMLİK** | A2, A4, H3, C5, E5; Berke'nin hipotezinin 1. kolu | Kapsamı büyük adımla artırabilecek tek kanıtlanmış yol kimlik eşlemesi. Bugün yalnız gnulib'de ve set içi kurallarla çalışıyor. Genel biçimi (başka derlemeden tanıma) ölçülmedi. | Geliştirme setinde aynı kaynağın iki derlemesi iki tarafta da GT'li: tmux ve htop (Debian GCC / AArch64 ELF ↔ Mac clang / arm64 Mach-O), coreutils (Debian ↔ Homebrew), 106 coreutils ikilisi arasındaki gnulib kopyaları. Eşleme kesinliği ve kapsamı doğrudan sayılır. |
| **ÖZ KOD** | A5, I1, A6, H2, B1 (`oz_ad`); Berke'nin hipotezinin 2. ve 3. kolu | Programın kendi kodu hiçbir kitaplıkta yok. Bugüne kadarki denemeler (fiil tavanı, kebap adı, benzer imzalı ad) olumsuz. Tavan belirteç düzeyinde hiç sayılmadı; "kanıt adlandırılan fonksiyonun içinde değil, onu kaydeden yerde" öncülü hiç sınanmadı. | GT adının belirteçlerinin kanıt kaynağı başına bulunma oranı (tavan); kayıt çiftlerinden (dizgi + fonksiyon işaretçisi) kuralla üretilen adın tam eşitliği; keşif / sınama birimi ayrımı. |
| **ÖLÇÜ** | B3, B4, B2, B5, G1, G2 | Öbür iki hattın "yakın ad" ve "genelleşir" iddiaları bu hat olmadan yorumlanamaz. | Var olan insan etiketleriyle ölçünün uyumu (ROC / AUC; bir etiket kümesinde ayar, öbüründe sınama). |

Opus desteği (ilk dalga): **OLGU** — 119 ikilinin bütün fonksiyonları için fonksiyon başına olgu tablosu (GT adı, derleme birimi, ürünün verdiği ad, dizgiler, çağrı komşuları, kayıt çiftleri). A1 kapsam bütçesi bu tablodan çıkar; üç hat da onu kullanır.

## 3. Öncelik önerisine itiraz (liste §4)

- Liste A3 + I2 + I4'ü (üst veri, Mach-O) üçüncü sıraya koyuyor. Geliştirme setinde ObjC / Swift / Go / Rust nüfusu yok; bu soruların doğrulayıcısı yeni veri ister. I2'nin aykırı öncülü doğruysa iş bir pakettir. Bu yüzden A3 hattı ÖLÇÜ'nün önereceği tabakalı sete bağlandı.
- A1 ayrı hat değil: OLGU tablosunun ilk çıktısı.

## 4. Seçilmeyenler ve neden

| Soru | Neden şimdi değil | Ne olacak |
|---|---|---|
| A3, I4 (üst veri, düşman girdi) | Geliştirme setinde nüfusu yok | ÖLÇÜ hattının set önerisi + Berke'nin indirme onayından sonra |
| I2 (Mach-O `main`) | Aykırı öncül doğruysa paket | Opus ölçüm paketi, sonraki dalga |
| I3 (dizgi kaçışı), I5 (parametre yayılımı), H4 | Küçük ölçüm işleri, araştırma değil | Opus paketleri, sonraki dalga |
| C1, C2, H5, I6 (tip, yapı) | P10b ve P18 yamasına bağlı | Onarımın kalanından sonra |
| C3 (yerleşim) | Olumsuz sonuç; derleyici tabakası ister | Tabakalı set gelince |
| C4, D3, D4 (okunurluk, yeniden derleme) | D3'ün ilk ölçümü ucuz ama ad hattından bağımsız | D3 için Opus ölçüm paketi, sonraki dalga |
| E1–E5 (hız) | Boş makine ister; ARGE ajanları çalışırken ölçülemez | Makine boşken |
| F1–F4 (KaradulLM) | Önce gerçek model duman listeleri | Ana oturum, makine boşken |
| H1 (serbest bırakma kapısı) | ÖLÇÜ'nün karar kuralına bağlı | ÖLÇÜ'nün ikinci turu |

## 5. Yaratıcılık protokolü (CLAUDE.md §29) nasıl uygulanıyor

1. **Denetlenebilir soru:** her hattın ilk turu bir sayım; doğrulayıcı yukarıdaki tabloda.
2. **Uzlaşıyı kır:** her hat metninde literatürün beklenen cevabı yasak cevap olarak yazılı, aykırı öncül verildi. Onuncu Adam (Astra, xhigh) yön kararına karşı aynı anda çalışıyor.
3. **Tek hatta kal:** üç hat sabit; sonraki dalgalar aynı hatların devamıdır. Her hat `DEFTER.md` tutar ("neden olmadı" notları dahil).
4. **İnsan uzman:** eşiğe gelen sonuç yayımdan önce dış bir tersine mühendislik uzmanına okutulur; Berke'ye teknik yol ayrımı sorulmaz.

## 6. Onarımdan kalan (ARGE'yi kesmiyor, ama kayıtlı)

`gonderim/OKU.md` başı: tam takım (kapanışta koşulmadı; bu oturumda koşuluyor), son doğrulama mutasyonları, push (Berke'ye sorulur), 9 bayat mutasyon tanımı, P18 yaması + 78 test, P12d (`oz_ad` erken dönüşü), parametre adı yeniden ölçümü, P10b, P08b, P03b, P23, kapanış denetimi.
