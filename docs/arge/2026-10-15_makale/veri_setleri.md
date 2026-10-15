# Strip edilmiş binary'lerde fonksiyon adı tahmini: açık veri setleri ve Karadul için uygunluk

Hazırlanma: 2026-10-15. Yalnız WebSearch ve WebFetch kullanıldı; hiçbir veri seti indirilmedi. Birincil kaynak önceliklidir.

**Doğrulama işaretleri**

| İşaret | Anlamı |
|---|---|
| **[B]** | Birincil kaynağın sayfası ya da tablosu doğrudan okundu (makale PDF'inin sayfa görüntüsü). |
| **[Ö]** | Birincil kaynak (makale HTML'i, README, Zenodo sayfası), ama WebFetch özetleyicisi üzerinden okundu. Bağımsız bir kaynakla çapraz denetlendiyse yanında yazıyor. |
| **[İ]** | İkincil kaynak: başka bir makalenin aktarımı ya da arama özeti. |
| **[D]** | Doğrulanmadı. Bu sayıyı makalede kullanmadan önce kaynağından elle okuyun. |

---

## 1. Kısa sonuç

1. **Doğrudan kıyas için önerilen iki veri seti:**
   - **SymGen veri seti** (NDSS 2025). SymGen'in kendi (LLM tabanlı) sonucunu ve aynı x86-64 test kümesinde yeniden eğitilmiş XFL, SymLM, AsmDepictor sayılarını veriyor. Girdisi Ghidra decompile çıktısı. Yinelenen fonksiyonlar ayıklanmış. Binary'ler, kaynak kodu ve decompile çıktısı Zenodo'da (CC BY 4.0).
   - **NERO veri seti** (OOPSLA 2020). Test bölmesi arşivin içinde hazır (TEST dizini) ve paket düzeyinde ayrılmış. Arşiv küçük (36 MB). Tüm test kümesi Karadul'un süre bütçesine sığar; bölmeyi biz seçmediğimiz için "dondurulmuş test seti" şartını da kendiliğinden karşılar.
2. **Mach-O içeren fonksiyon adı veri seti bulunamadı.** AArch64 (arm64) yalnız BinKit'te var; BinKit'te adlandırma için yayımlanmış sayı yok. SymLM, SymGen ve Epitome'deki "ARM" büyük olasılıkla 32-bit (REBench için [Ö], diğerleri [D]).
3. **Ölçütler birbirinin aynısı değil.** Hangi veri setiyle kıyas yapılacaksa o makalenin ölçütü ve değerlendirme betiği kullanılmalı (bkz. §7). Karadul'un bugünkü isim düzeyi ölçütü hepsinden sıkı; makalede ikisi birlikte raporlanmalı.
4. **Karadul'a özgü sızıntı riski var.** SymGen'in 9.842 binary'sinin 1.848'i coreutils-8.32. coreutils Karadul'un geliştirme setinde. Ayrıca Karadul'un gnulib parmak izleri, bu GNU projelerinin (coreutils, grep, tar, diffutils, gzip…) ortak kullandığı gnulib'den geliyor. Test kümesinden çıkarılmalı ya da ayrı raporlanmalı (bkz. §7, madde 5).

---

## 2. Fonksiyon adı veri setleri: özellikler

| # | Veri seti (çalışma) | Kullananlar | Platform / mimari | Derleyici / optimizasyon | Boyut | Ground truth | Erişim / lisans |
|---|---|---|---|---|---|---|---|
| 1 | **Debin veri seti** (Debin, CCS 2018) | Debin | ELF; x86, x64, ARM [B] | Her paketin varsayılan derleme ayarı, "-O0 ile -O3 arası" karışık [B] | 9.000 binary (mimari başına 3.000); 830 Debian debug-sembol paketinden. Mimari başına rastgele 2.700 eğitim / 300 test. Binary başına ortalama 79 "bilinmeyen" fonksiyon düğümü (Tablo 2) [B] | Debug'lı binary'deki DWARF (pyelftools); `.dynsym`'deki adlar "bilinen" sayılıyor [B] | Veri seti yayımlanmamış. Yalnız eğitilmiş modeller var; kod Apache-2.0 [Ö] |
| 2 | **NERO veri seti** (NERO, OOPSLA 2020) | NERO. NERO makalesi Debin ve DIRE'yi de bu sette koşuyor. | ELF x86-64, Linux [Ö] | Makalede yazmıyor [Ö] | Filtrelemeden sonra 67.246 prosedür: 60.403 eğitim / 2.034 doğrulama / 4.809 test. Bölme paket düzeyinde, 8:1:1. Binary sayısı verilmemiş [Ö] | Debug bilgisiyle derlenmiş binary'ler; etiket prosedür adı [Ö] | Zenodo (DOI 10.5281/zenodo.4081641): `nero_dataset_binaries.tar.gz` 36,0 MB, CC BY 4.0. Arşivde TRAIN, VALIDATE ve TEST dizinleri var. Kod GPL-3.0 [Ö] |
| 3 | **Punstrip/XFL Debian veri seti** (Punstrip ACSAC 2020; XFL S&P 2023) | Punstrip, XFL, BLens (USENIX Sec 2025) | ELF x86-64 [Ö] | Debian bakıcılarının seçtiği derleyici, sürüm ve optimizasyon; sabit değil [Ö] | 10.047 C binary, 741.724 fonksiyon, 3.000'den fazla Debian paketi [Ö] | ELF sembol tablosundaki global semboller [Ö] | XFL deney verisi ve logları: github.com/unibw-patch/xfl (depo GPL-3.0). BLens artefaktı: Zenodo 10.5281/zenodo.14732394. BLens, binary'leri "GPLv3 kısıtı nedeniyle" paylaşmadığını yazıyor; Debian arşivinden yeniden kurulmaları gerekir [Ö] |
| 4 | **SymLM veri seti** (SymLM, CCS 2022) | SymLM; Epitome yeniden koşmuş; REBench'in kaynakları arasında | ELF; x64, x86, ARM, MIPS [Ö] | O0–O3 ve 4 karartma (obfuscation) [İ]; derleyici [D] | 27 proje, 1.431.169 fonksiyon [İ, makale özeti üzerinden] | [D] | Zenodo 8306055: toplam 9,4 GB (x64 4,4 GB, x86 3,8 GB, ARM 606,9 MB, MIPS 548,8 MB), CC BY 4.0. Kod MIT. README'de bölme tanımı yok [Ö] |
| 5 | **AsmDepictor veri seti** (AsiaCCS 2023) | AsmDepictor | [D] | [D] | Zenodo 7978756: `train_source.txt` 656,2 MB, `test_source.txt` 163,3 MB, hedef dosyaları ve model; toplam 987 MB. Dosya adlarına bakılırsa binary değil, metin [Ö/D] | [D] | CC BY 4.0 [Ö] |
| 6 | **Epitome veri seti** (Epitome, FSE 2024) | Epitome | ELF (Buildroot ile çapraz derleme); x86, x64, ARM, MIPS [Ö] | O0, O1, O2, O3, Os. Derleyici adı geçmiyor, yalnız GCC kılavuzuna atıf var [Ö] | 174 proje, 36.275 binary, 2.597.346 fonksiyon (Tablo 2). Kaynak koda göre 8:1:1 bölme ve 5 katlı çapraz doğrulama [Ö] | [D] | Kod: github.com/Xiaolinger-Z/Epitome. Veri setinin yayımlandığına dair beyan bulunamadı [Ö] |
| 7 | **SymGen veri seti** (SymGen, NDSS 2025) | SymGen. XFL, SymLM ve AsmDepictor aynı sette yeniden eğitilip ölçülmüş. | ELF; x86-32, x86-64, ARM, MIPS [B] | GCC-9.4.0; O0–O3 [B] | 33 açık kaynak C projesi, 9.842 benzersiz binary, 2.237.915 fonksiyon. Yinelenenler (%77,9, yani 1.742.421 fonksiyon) atılınca 495.494 benzersiz fonksiyon kalıyor. Binary düzeyinde rastgele 8:1:1 bölme [B]. En büyük projeler: openssl-3.0.6 (2.128 binary), coreutils-8.32 (1.848), ncurses-6.3 (1.440) (Tablo VI, s. 17) [B] | Debug'lı eş binary'nin DWARF kayıtları; fonksiyonlar adres üzerinden eşleniyor. Girdi Ghidra decompile çıktısı [B] | Zenodo 15530083: toplam 7,5 GB (binary'ler 4,9 GB; kaynak 223,1 MB; stripped ve unstripped decompile çıktısı 1,2 + 1,2 GB), CC BY 4.0. Kod Apache-2.0. Bölme `divide_dataset.py` betiğiyle yapılıyor [Ö] |
| 8 | **"How Far" kıyaslaması** (Shang vd., arXiv 2404.09836; genişletilmiş sürüm 2504.21803) | Aynı makale: LLM'ler, SymLM, HexT5 | x86-64 (v3). Genişletilmiş sürüm çoklu mimari ve optimizasyon içeriyor [Ö] | Her projenin varsayılan derleme yapılandırması [Ö] | 12 C projesi (FFmpeg, Redis, Curl, OpenSSL, zstd, ImageMagick…), 28 binary, 81.185 fonksiyon; bunlardan 2.000'i örneklenmiş (Tablo I) [Ö] | Kaynak koddan regex ile ad [Ö] | Yayın bağlantısı bulunamadı [D]. Yayın yeri (ICSME 2024) doğrulanmadı [D] |
| 9 | **REBench** (Won, Jin, Ma, Lin; arXiv 2604.27319, Nisan 2026) | REBench (LLM değerlendirmesi) | x64, x86, ARM 32-bit, MIPS 32-bit [Ö] | O0–O3; derleyici belirtilmemiş [Ö] | 96 C/C++ projesi; mimari×optimizasyon hücresi başına milyonlarca fonksiyon (ör. x64 O0 için 2,87 M) [Ö] | Debug sembollerinden kurulan bilgi tabanı (bayt düzeyinde yığın eşlemesi); Ghidra [Ö] | github.com/OSUSecLab/REBench, Zenodo 19899116; lisans belirtilmemiş [Ö] |
| 10 | **REFORGE** (Koller & Schmidt; arXiv 2607.07738, Temmuz 2026) | REFORGE (7 LLM) | Tek mimari, tek derleyici, Ghidra. Mimarinin adı okunan sayfalarda geçmiyor [B] | O0–O3 [B] | Sentetik C mikro-korpusu. Değerlendirilebilir fonksiyon sayısı O0'da 220, O3'te 132. Toplam 4.837 puanlanmış tahmin [B] | DWARF ve sözdizimsel hizalama; 8 kapılı güven hunisi (GOLD, SILVER, BRONZE katmanları) [B] | github.com/NicolasKol/reforge [B] |

---

## 3. Ölçütler ve raporlanan sayılar

P / R / F1 sırasıyla verilmiştir. Kaynağın kendi yazımı korunmuştur: bazı makaleler yüzde, bazıları 0–1 aralığında raporluyor.

| Veri seti | Ölçüt | Raporlanan sayılar | Referans | Doğrulama |
|---|---|---|---|---|
| **NERO** | Alt-token P/R/F1. Büyük-küçük harfe, sıraya ve tekrara duyarsız; alfabetik olmayan karakterler yok sayılıyor. | Nero-GNN 48,61 / 42,82 / 45,53 · Nero-Transformer 41,54 / 38,64 / 40,04 · DIRE 38,02 / 33,33 / 35,52 · Debin 34,86 / 32,54 / 33,66. API çağrıları karartıldığında Nero-GNN F1 38,83. | Tablo 2 | [Ö]. README'deki tahmin logunun adı (`predictions_iter495_F1_45.5.txt`) 45,53 ile tutarlı. |
| **Debin** | Tam eşleşme P/R/F1. Fonksiyon ve değişken adları birlikte sayılıyor ("Name" satırı); yalnız fonksiyon adı için ayrı sonuç yok. | x64 63,5 / 63,1 / 63,3 · x86 62,6 / 62,5 / 62,5 · ARM 61,6 / 61,3 / 61,5 | Tablo 3, s. 10 | [B] |
| **XFL Debian** | 1024 etiketlik sözlükte mikro-ortalamalı etiket P/R/F1. Debin ve Punstrip çıktıları kanonikleştirilip bu etiket uzayına izdüşürülmüş. | XFL 0,8345 / 0,5750 / 0,6809 · Punstrip 0,6336 / 0,6350 / 0,6343 · Debin 0,1564 / 0,1081 / 0,1279 · Nero 0,1600 / 0,0622 / 0,0896. Hiç görülmemiş adlarda XFL F1 0,2416. | Tablo III, Tablo V | [Ö]. Özetteki "%83,5 precision" ve SymGen'in aktardığı "XFL 0,68" ile tutarlı. |
| **BLens** (aynı Debian seti, yeniden bölünmüş) | Kelime kümesi üzerinde mikro-ortalama P/R/F1; yanında RougeL, BLEU ve VarCLR. | Yalnız F1. Binary'ler arası bölme: BL-s 0,789 · BLens 0,772 · SymLM 0,704 · XFL 0,625 · AsmDepictor 0,407. Projeler arası: BLens 0,460 · XFL 0,295 · SymLM 0,277 · AsmDepictor 0,200. Katı bölme (projeler arası ortak bileşenler ayıklanmış): BL-a 0,321 · SymLM 0,195 · AsmDepictor 0,090 · XFL 0,085. | Tablo 1, 3, 5 (arXiv v2) | [Ö]. USENIX özetindeki 0,79/0,70, 0,46/0,29 ve 0,32/0,19 çiftleriyle tutarlı. |
| **SymLM** | Token P/R/F1 ve CodeWordNet eşanlamlı eşlemesi. | Özgün tablo okunamadı. Özet: önceki çalışmalara göre "en fazla" P'de %15,4, R'de %59,6, F1'de %35,0 iyileşme [İ]. SymGen'in aktarımıyla SymLM kendi veri setinde ortalama F1 0,73 [B; ikincil aktarım]. Epitome'nin yeniden koşumu: SymLM 0,780 / 0,766 / 0,773, Epitome 0,890 / 0,884 / 0,887 [Ö]. | — | SymGen'e göre SymLM'in test kümesinde eğitimden sızan yinelenen fonksiyonlar var. |
| **AsmDepictor** | [D] | README: F1 %80,85, Jaccard doğruluğu %81,63. Hangi veri setinde ölçüldüğü yazmıyor. | README'deki Şekil 2 ve 3 başlıkları | [Ö]; ayrıntılar [D] |
| **Epitome** | Kelime düzeyinde P/R/F1. | Ortalama 73,13 / 70,84 / 71,96 (metin). Tablo 3'te mimari×optimizasyon kırılımı var, ör. x64 O2 0,7339 / 0,7094 / 0,7214. | Tablo 3 (arXiv v1) | [Ö]. FSE sürümüyle karşılaştırılmadı. |
| **SymGen** | Token P/R/F1 ve SymLM'in CodeWordNet eşanlamlı eşlemesi. | x86-64'te SymGen F1: O0 0,351 · O1 0,381 · O2 0,392 · O3 0,397 (ortalama 0,373 / 0,388 / 0,380). Aynı x86-64 testinde XFL F1 0,153 / 0,156 / 0,186 / 0,188; SymLM 0,100 / 0,102 / 0,098 / 0,101; AsmDepictor 0,050 / 0,060 / 0,052 / 0,067. Dört mimarinin ortalaması: SymGen 0,275 / 0,281 / 0,277. SymGen F1 aralıkları: ARM 0,239–0,280, MIPS 0,130–0,146, x86-32 0,306–0,349. | Tablo I s. 10; metin s. 9 | [B] |
| **How Far** | Token P/R/F1 (NERO tarzı: harfe, sıraya ve tekrara duyarsız). | En iyi LLM CodeLlama-34b-Instruct 28,96 / 28,44 / 27,59. Tablodaki "NER" satırının F1'i 13,33; bunun NERO olması muhtemel [D]. SymLM F1 7,72; HexT5 F1 3,28. | Tablo III | [Ö] |
| **REBench** | P/R/F1 ve CodeWordNet. | LLM sonuçları var (Tablo 3 ve 6), ancak sayılar özetleyiciden geldi ve tutarsız görünüyor (x86 sonuçları x64'ten yüksek). | — | [D] |
| **REFORGE** | Token F1 (küçük harfli alt-token kümesi), normalize edilmiş tam eşleşme ve top-K oracle. | 7 LLM: Claude Sonnet 4.5, GPT-5.1, GPT-4o mini, DeepSeek R1, DeepSeek V3, Qwen3 Coder, Llama-3.1 70B. Ortalama Token F1 yaklaşık 0,18–0,29, medyan 0. Tam eşleşme %1,9–7,1. GOLD katmanında Token F1 0,20–0,32. | §4.3, s. 7 | [B] |

Not: SymGen tahmin başına 3 saniye sürüyor (A100); eğitimi 41 saat (s. 14) [B].

---

## 4. Diğer adlandırma çalışmaları

Bu çalışmaların veri seti ayrıntıları doğrulanamadı.

- **NFRE** (Gao, Cheng, Xue, Zhang; ISSTA 2021, s. 607–619). "Büyük ölçekli" bir veri seti ve iki ön işleme yöntemi tanıtıyor. İki tekniğe göre %32 ve %16 göreli iyileşme bildiriyor [İ, özet]. Epitome'ye göre kodu GitHub'da yok [Ö]. Platform, boyut ve mutlak sayılar [D].
- **HexT5** (ASE 2023). Decompile sözde-kodu üzerinde ön-eğitim yapıyor. Dört alt görevi var: özetleme, değişken adı, fonksiyon adı, benzerlik [Ö, özet]. Veri seti ve özgün sayılar [D]. "How Far" makalesinin kendi kıyaslamasında HexT5'in F1'i 3,28 [Ö].
- **BETAC** (Breyton, Saqib, Fung, Charland; DRCN 2024). Assembly'den ad üreten bir transformer; iyi huylu ve zararlı binary'ler üzerinde değerlendirilmiş [İ]. Veri seti [D].
- **Ge vd. 2026** (FITEE 27(8)). Açık LLM'leri fonksiyon adı tahmininde kıyaslıyor ve "büyük ölçekli çok projeli bir binary veri seti" kullanıyor. Ayrıntı [D].
- **Valenzuela & Kinder 2026** (arXiv 2608.02084, "Pretraining on Call Graphs"). Arama özetine göre XFL'yi alt görev olarak kullanıyor [İ]. Özet sayfasında adlandırmaya ilişkin sayı yok [D].
- **In Nomine Function** (Artuso vd.; NLP4Prog 2021, arXiv 1912.07946). 22 binden fazla yazılımdan yaklaşık 9 milyon fonksiyon kullanıyor [İ]. Ayrıntı [D].

## 5. Değişken adı çalışmaları

Bunlar fonksiyon adı kıyası için doğrudan uygun değil.

- **GenNm** (Xu vd.; NDSS 2025). Değişken adı kurtarıyor. "Yaygın kullanılan iki veri setinde" precision'da 5,6–11,4 puan iyileşme bildiriyor. Görülmemiş adlarda doğruluk %17,3'ten %22,8'e çıkıyor [Ö, özet]. Veri setlerinin adı [D]; DIRT ve VarCorpus olması muhtemel.
- **ReSym** (Xie vd.; CCS 2024, ayırt edici makale ödülü). Yerel değişkenlerin ve kullanıcı tanımlı yapıların adını ve tipini kurtarıyor; LLM'i Prolog tabanlı bir tutarlılık denetimiyle birleştiriyor [Ö, özet]. Veri seti [D].

## 6. Genel amaçlı binary veri setleri

Bu setlerde adlandırma için yayımlanmış sayı yok. Mimari ve format kapsamını genişletmek için kullanılabilirler.

- **BinKit** (TSE 2022; SoftSec-KAIST).
  - BinKit 2.0: 371.928 binary [Ö]. Özgün makale: 51 GNU paketi, 243.128 binary [İ].
  - 8 mimari: x86_32, x86_64, arm_32, **arm_64**, mips_32, mips_64, mipseb_32, mipseb_64 [Ö].
  - Derleyiciler: GCC 4.9.4–11.2.0, Clang 4.0.0–13.0.0, ayrıca Obfuscator-LLVM [Ö].
  - Optimizasyon: O0, O1, O2, O3, Os, Ofast. PIE, noinline, LTO ve karartma alt kümeleri var [Ö].
  - Lisans MIT; dağıtım Google Drive üzerinden [Ö]. Binary'lerin debug bilgisi taşıyıp taşımadığı README'de yazmıyor [D].
  - **AArch64 içeren tek veri seti bu.**
- **ALLSTAR** (JHU/APL, 2019).
  - 30.000'den fazla Debian jessie paketi için "x86, amd64, ARM, MIPS, PPC, s390x" derleme denemesi [Ö].
  - Sembollü ELF'ler, DWARF, kaynak kodu ve ara derleyici dosyaları saklanmış; rsync ile çekiliyor [Ö].
  - Lisans: sitedeki "Legal Notice" sayfası okunmadı [D]. Hangi ARM alt mimarilerinin (armel, armhf, arm64) olduğu [D].
- **Assemblage** (NeurIPS 2024, Datasets & Benchmarks).
  - 890 bin Windows PE (847.856 .exe ve 43.507 .dll) ile 428.884 Linux ELF; 29 yapılandırma [Ö].
  - Derleyiciler: MSVC v140–v143 (VS 2015–2022), GCC 11.4.0, Clang 14.0.0. Mimariler x86 ve x64 [Ö].
  - Ground truth: PDB dosyaları ve SQLite veritabanı (`functions`, `rvas`, `lines`; kaynak satırından bayt adresine eşleme) [Ö].
  - Dağıtım Hugging Face ve S3 üzerinden. Kod MIT; veri lisansı her deponun kendi lisansı [Ö].
  - Adlandırma deneyi yok; Tablo 1'de yalnız "FN" görevine uygun diye işaretli [Ö]. **PE için tek seçenek bu.**
- **Mach-O:** Adlandırma için veri seti bulunamadı. Arama özetinde MOTIF-Bench adlı bir kaynak geçiyor: 2026 tarihli bir yüksek lisans tezi (MBZUAI); dyld shared cache arm64 binary'lerini Xcode SDK başlıklarıyla eşleyip tip ve imza kurtarmayı ölçüyor. Sayfası 403 döndü [D].

---

## 7. Ölçüt farkları: kıyas için zorunlu notlar

1. **Ölçüm birimi farklı.**
   - NERO, SymLM, SymGen, How Far ve REFORGE alt-token kümesiyle ölçüyor.
   - XFL sabit 1024 etiketlik bir sözlük kullanıyor.
   - Debin tam adı ölçüyor ve değişken adlarını da aynı sayıya katıyor.
2. **Toplama biçimi farklı.**
   - XFL ve BLens mikro ortalama kullanıyor.
   - SymLM tarzı değerlendirmenin örnek başına ortalama (makro) olduğunu ikincil bir kaynak yazıyor [İ]. NERO'nun toplama biçimi [D].
   - Aynı tahminler mikro ve makro ortalamada farklı F1 verir. Bu yüzden hedef makalenin kendi betiği kullanılmalı: NERO için `gnn.py --test` yolu, SymGen ve SymLM için depo betikleri.
3. **Eşanlamlı eşleme farklı.** SymLM, SymGen ve REBench CodeWordNet ile eşanlamlıları eşliyor. NERO ve REFORGE eşlemiyor. BLens bilerek eşlemiyor.
4. **Çekimser kalma (`FUN_xxx`) ve fonksiyon eşleme.**
   - Karadul'un `FUN_xxx` bıraktığı fonksiyon "boş tahmin" sayılmalı: precision'a yanlış pozitif eklemez, recall'u düşürür. Debin'in ölçütü bunu açıkça böyle tanımlıyor (NP yalnız tahmin yapılan düğümler).
   - Değerlendirilen fonksiyonlar test listesindeki adreslerle birebir eşlenmeli. Karadul'un hiç bulamadığı fonksiyon da boş tahmin sayılmalı.
   - Karadul'un üç sınıflı çıktısı (kesin / tarif / bilinmiyor) "isabet–kapsama" eğrisi olarak da verilebilir.
5. **Sızıntı.**
   - SymGen, SymLM ve XFL setlerinde eğitimden teste sızan yinelenen fonksiyonlar olduğunu gösteriyor. SymGen'in yinelenenleri ayıklanmış setinde SymLM'in F1'i 0,105'e (kendi setinde 0,73), XFL'nin F1'i 0,16'ya (Debian setinde 0,68) düşüyor. SymGen bu farkı büyük ölçüde sızıntıya bağlıyor (s. 9) [B].
   - Karadul'daki karşılığı **imza veritabanı sızıntısı**. 9,2 M imza ve gnulib parmak izleri test projeleriyle (coreutils, binutils, bash, OpenSSL, grep, tar…) çakışırsa sonuç, eğitim kümesinde test yapılmış gibi şişer.
   - Makalede imza DB'si açık ve kapalı olarak, ya da test projelerinden arındırılmış bir DB ile ayrı ayrı sonuç verilmeli.
   - coreutils hem SymGen'in en büyük ikinci projesi hem de Karadul'un geliştirme setinde. Dondurulmuş test kümesinden çıkarılmalı.
6. **Optimizasyon seviyesi kıyası.**
   - REFORGE, seviyeler arasında eşleştirilmemiş ortalamaların hayatta kalma yanlılığı taşıdığını gösteriyor: değerlendirilebilir fonksiyon sayısı O0'dan O3'e 220'den 132'ye iniyor [B].
   - Karadul'un O0–O3 tablosuna aynı kaynak fonksiyonu üzerinden eşleştirilmiş bir analiz de eklenmeli.

---

## 8. Karadul için değerlendirme (binary başına 10–25 dakika)

| Veri seti | Test kümesi | Tam testin süresi | Alt örneklem | Yayımlanmış sayıyla doğrudan kıyas |
|---|---|---|---|---|
| **NERO** | Paketlerin yaklaşık %10'u, 4.809 prosedür. Binary sayısı makalede yok; arşiv açılınca sayılmalı. | Arşiv 36 MB olduğuna göre test kısmı küçük. Kaba tahmin: onlarca binary, yani birkaç saat ile 1–2 gün arası [tahmin] | Gerekmez | **Evet.** Bölme arşivde hazır, ölçüt tanımlı. Kısıtları: yalnız x86-64; referanslar eski (Nero-GNN F1 45,53). |
| **SymGen, x86-64** | 9.842 binary / 16 hücre ≈ hücre başına 615 binary; %10 test ≈ hücre başına 61. x86-64'ün O0–O3'ü ≈ 246 binary [tahmin, eşit dağılım varsayımıyla]. coreutils çıkarılırsa ≈ 200. | 41–103 saat | Evet: proje×optimizasyon katmanlı, seed'i önceden yazılmış 40 binary ≈ 7–17 saat | **Kısmen.** Ölçüt ve binary havuzu aynı. Bölme `divide_dataset.py` ile birebir üretilebilirse doğrudan kıyas olur; alt örneklemde "yaklaşık kıyas" denmeli ve bootstrap güven aralığı verilmeli. |
| **XFL/BLens Debian** | Testin payı %5 (XFL) ya da %10 (BLens); 500–1.000 binary | 83–419 saat | Zorunlu | **Zor.** Binary'ler dağıtılmıyor. Paket sürümleri BLens'in Zenodo kaydından çıkarılıp Debian arşivinden yeniden kurulmalı. XFL ölçütü 1024 etiketlik sözlüğe bağlı. |
| **SymLM** | Zenodo'da binary var ama bölme tanımı yok [Ö] | — | Evet | **Hayır.** Bölme yok; SymGen'e göre test kümesi sızıntılı. |
| **Debin, Epitome, How Far** | Veri yok ya da bulunamadı | — | — | **Hayır** |
| **AsmDepictor** | Yalnız metin dosyaları; binary yok gibi görünüyor [D] | — | — | **Hayır** |
| **REBench** | Çok büyük ve yeni | — | Evet | Sayılar doğrulanmadı. Makalenin hakemli sürümü çıkınca yeniden bakılmalı. |
| **REFORGE** | 220 fonksiyonluk sentetik korpus | Dakikalar | Gerekmez | Yalnız 7 LLM'e karşı kıyas verir. Asıl değeri yöntemde: hizalama verimi ve eşleştirilmiş analiz. |
| **BinKit, ALLSTAR, Assemblage** | Çok büyük | — | Zorunlu | **Hayır.** Adlandırma referansı yok; yalnız kendi ölçümümüz için alt örneklem (arm64, PE). |

---

## 9. Öneri

### Öneri 1: SymGen veri seti, x86-64 O0–O3 (ana kıyas tablosu)

**Neden:**
- NDSS 2025'te yayımlanan LLM tabanlı bir yöntemin sonucu (SymGen, x86-64 F1 0,351–0,397) ve üç klasik yöntem (XFL, SymLM, AsmDepictor) aynı test kümesinde, aynı ölçütle ve optimizasyon seviyesine göre ayrılmış olarak raporlanmış (Tablo I).
- Yinelenen fonksiyonlar ayıklanmış. Hakem gözünde "sızıntısız" sayılan güncel bir set.
- Girdisi Ghidra decompile çıktısı; Karadul da Ghidra 12.1.2 kullanıyor, yani iki taraf aynı bilgiden başlıyor.
- Binary'ler, kaynak kodu ve decompile çıktısı CC BY 4.0 ile açık.
- ARM ve MIPS tabloları da var; ikincil bir mimari kıyası mümkün.

**Nasıl uygulanır:**
1. İndirmeden sonra ilk iş: `divide_dataset.py`'nin bölmeyi sabit bir seed'le üretip üretmediğine bakın. Üretiyorsa SymGen'in test listesi birebir kurulabilir; üretmiyorsa bu [D].
2. coreutils'i (ve Karadul'un geliştirme setinde kalan diğer projeleri) çıkarın. Seçim kuralını sonuçlara bakmadan yazıya geçirip kilitleyin.
3. SymLM'in CodeWordNet'li token P/R/F1 betiğini kullanın. Ayrıca CodeWordNet'siz token F1 ve isim düzeyinde tam eşleşme raporlayın.
4. İmza DB'si açık ve kapalı iki koşu yapın.

### Öneri 2: NERO veri seti, TEST paketleri (tam test kümesi, birebir kıyas)

**Neden:**
- Test bölmesi veri setinin kendisinde tanımlı ve paket düzeyinde ayrılmış (projeler arası duruma en yakın kurgu). Bölmeyi biz seçmediğimiz için "dondurulmuş test seti" şartı kendiliğinden sağlanıyor.
- Arşiv küçük (36 MB), lisansı CC BY 4.0. Test kümesinin tamamı Karadul'un süre bütçesine sığar, alt örnekleme gerekmez.
- Ölçüt açıkça tanımlı. Aynı test kümesinde Nero-GNN, DIRE ve Debin sayıları var.

**Kısıtları:**
- Yalnız x86-64.
- Referanslar 2020'den.
- GNU paketleri Karadul'un gnulib parmak izleriyle çakışabilir; imza DB'siyle ilgili ablasyon burada da şart.

### Üçüncü seçenek: XFL/BLens Debian (gerçekçi, ama emek ister)

Projeler arası bölme ve gerçek Debian derlemeleri hakem gözünde en inandırıcı kurgu. Karadul'un mevcut Debian ölçüm altyapısıyla (Docker, dbgsym) de uyumlu. Ancak binary'ler yeniden kurulmalı ve test kümesi büyük; bu yüzden ancak alt örneklemle "yaklaşık kıyas" verilebilir.

### Mach-O / arm64 uzantısı

Literatürde bu platform için kıyaslanacak sayı yok. Bir yol: SymGen'in `source_projects.tar.gz` arşivindeki (223,1 MB) 33 projeyi macOS arm64'te clang ile O0–O3 ve `-g` (dsymutil) kullanarak yeniden derleyip aynı ölçütle ölçmek. Bu, "aynı projeler, farklı platform" tablosu verir. Yayımlanmış sayılarla doğrudan kıyas değildir; makalede ayrı başlık altında sunulmalı. Linux arm64 için BinKit'in arm_64 alt kümesi kullanılabilir.

---

## 10. Doğrulanamayanlar (makaleye girmeden önce elle okunmalı)

- SymLM'in özgün P/R/F1 tablosu, derleyicisi ve bölme biçimi (yalnız özetteki "en fazla" yüzdeleri ve ikincil aktarımlar var).
- NFRE ve HexT5'in veri setleri ve özgün sayıları.
- AsmDepictor'ın veri setleri (DS_N ve DS_A), mimarisi ve README'deki %80,85 F1'in hangi sete ait olduğu.
- REBench'in tablo sayıları.
- How Far'ın yayın yeri ve veri bağlantısı; tablodaki "NER" satırının NERO olup olmadığı.
- NERO test kümesindeki binary sayısı ve paket listesi (arşiv açılınca görülür).
- SymGen bölmesinin seed'le birebir üretilip üretilemeyeceği.
- SymLM, SymGen ve Epitome'deki "ARM"ın 32-bit olup olmadığı.
- BinKit binary'lerinin debug bilgisi taşıyıp taşımadığı.
- ALLSTAR'ın lisansı ve hangi ARM alt mimarilerini içerdiği.
- MOTIF-Bench (Mach-O) ayrıntıları.
- Ge vd. 2026 ve Valenzuela & Kinder 2026'nın veri setleri.

---

## 11. Kaynaklar

**Fonksiyon adı çalışmaları**
- Debin (He, Ivanov, Tsankov, Raychev, Vechev; CCS 2018, s. 1667–1680): [makale PDF](https://files.sri.inf.ethz.ch/website/papers/ccs18-debin.pdf) · [GitHub eth-sri/debin](https://github.com/eth-sri/debin)
- NERO (David, Alon, Yahav; OOPSLA 2020): [arXiv 1902.09122](https://arxiv.org/abs/1902.09122) · [ar5iv HTML](https://ar5iv.labs.arxiv.org/html/1902.09122) · [GitHub tech-srl/Nero](https://github.com/tech-srl/Nero) · [Zenodo 10.5281/zenodo.4081641](https://doi.org/10.5281/zenodo.4081641)
- NFRE (Gao, Cheng, Xue, Zhang; ISSTA 2021, s. 607–619): [ISSTA sayfası](https://conf.researchr.org/details/issta-2021/issta-2021-technical-papers/13/A-Lightweight-Framework-for-Function-Name-Reassignment-Based-on-Large-Scale-Stripped-) · DOI 10.1145/3460319.3464804
- Punstrip (Patrick-Evans, Cavallaro, Kinder; ACSAC 2020, s. 373–385): künye SymGen kaynakçasından [51]
- SymLM (Jin, Pei, Won, Lin; CCS 2022, s. 1631–1645): [GitHub OSUSecLab/SymLM](https://github.com/OSUSecLab/SymLM) · [Zenodo 8306055](https://zenodo.org/records/8306055)
- XFL (Patrick-Evans, Dannehl, Kinder; IEEE S&P 2023, s. 2375–2390): [arXiv 2107.13404](https://arxiv.org/abs/2107.13404) · [ar5iv HTML](https://ar5iv.labs.arxiv.org/html/2107.13404) · [GitHub unibw-patch/xfl](https://github.com/unibw-patch/xfl)
- HexT5 (ASE 2023): [ASE sayfası](https://conf.researchr.org/details/ase-2023/ase-2023-papers/96/HexT5-Unified-Pre-training-for-Stripped-Binary-Code-Information-Inference)
- AsmDepictor (Kim, Bak, Cho, Koo; AsiaCCS 2023, s. 951–965): [GitHub agwaBom/AsmDepictor](https://github.com/agwaBom/AsmDepictor) · [Zenodo 7978756](https://zenodo.org/record/7978756)
- Epitome (FSE 2024): [arXiv 2405.09112](https://arxiv.org/abs/2405.09112) · [FSE sayfası](https://2024.esec-fse.org/details/fse-2024-research-papers/30/Enhancing-Function-Name-Prediction-using-Votes-Based-Name-Tokenization-and-Multi-Task) · [GitHub Xiaolinger-Z/Epitome](https://github.com/Xiaolinger-Z/Epitome)
- BLens (Benoit, Wang, Dannehl, Kinder; USENIX Security 2025, s. 6877–6896): [USENIX sayfası](https://www.usenix.org/conference/usenixsecurity25/presentation/benoit) · [arXiv 2409.07889 v2](https://arxiv.org/html/2409.07889v2) · Zenodo 10.5281/zenodo.14732394
- SymGen (Jiang, Jin, Lin; NDSS 2025): [makale PDF](https://ndss-symposium.org/wp-content/uploads/2025-797-paper.pdf) · [NDSS sayfası](https://ndss-symposium.org/ndss-paper/beyond-classification-inferring-function-names-in-stripped-binaries-via-domain-adapted-llms) · [GitHub OSUSecLab/SymGen](https://github.com/OSUSecLab/SymGen) · [Zenodo 15530083](https://zenodo.org/records/15530083)
- How Far (Shang vd.): [arXiv 2404.09836 v3](https://arxiv.org/html/2404.09836v3) · [genişletilmiş sürüm arXiv 2504.21803](https://arxiv.org/abs/2504.21803)
- REBench (Won, Jin, Ma, Lin; 2026): [arXiv 2604.27319](https://arxiv.org/abs/2604.27319) · GitHub OSUSecLab/REBench · Zenodo 19899116
- REFORGE (Koller, Schmidt; 2026): [arXiv 2607.07738](https://arxiv.org/abs/2607.07738) · [GitHub NicolasKol/reforge](https://github.com/NicolasKol/reforge)
- BETAC (DRCN 2024): [ön baskı PDF](https://dmas.lab.mcgill.ca/fung/pub/BSFC24drcn_preprint.pdf)
- Ge vd. (FITEE 2026): [dergi sayfası](https://journal.hep.com.cn/fitee/EN/10.1631/ENG.ITEE.2026.0017)
- Valenzuela & Kinder (2026): [arXiv 2608.02084](https://arxiv.org/abs/2608.02084)
- In Nomine Function (Artuso vd.): [arXiv 1912.07946](https://arxiv.org/abs/1912.07946)

**Değişken adı çalışmaları**
- GenNm (NDSS 2025): [arXiv 2306.02546](https://arxiv.org/abs/2306.02546) · [NDSS sayfası](https://ndss-symposium.org/ndss-paper/unleashing-the-power-of-generative-model-in-recovering-variable-names-from-stripped-binary)
- ReSym (CCS 2024): [makale PDF](https://www.cs.purdue.edu/homes/lintan/publications/resym-ccs24.pdf)

**Genel amaçlı veri setleri**
- BinKit: [GitHub SoftSec-KAIST/BinKit](https://github.com/SoftSec-KAIST/BinKit)
- ALLSTAR: [allstar.jhuapl.edu](https://allstar.jhuapl.edu/)
- Assemblage: [arXiv 2405.03991 v2](https://arxiv.org/html/2405.03991v2) · [NeurIPS 2024 bildirisi](https://proceedings.neurips.cc/paper_files/paper/2024/hash/6bbefc73a187dd42e0dc065b4e7a0615-Abstract-Datasets_and_Benchmarks_Track.html) · [assemblage-dataset.net](https://assemblage-dataset.net/) · [belgeler](https://assemblagedocs.readthedocs.io)
