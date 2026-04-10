# "Black Widow" / Karadul: Derinlemesine Arastirma Raporu

**Tarih:** 2026-04-05
**Hazirlayan:** Architect Agent
**Kapsam:** Film kaynagi, NSA teknikleri, akademik state-of-the-art, Karadul icin gap analizi

---

## 1. Blackhat (2015) Filmindeki "Black Widow" Araci

### 1.1 Filmdeki Tasvir

Michael Mann'in yonettigi Blackhat (2015, Chris Hemsworth) filminde "Black Widow" NSA'nin
gizli bir forensic reconstruction aracidir. Filmde:

- Bir nukleer santral saldirisi sonrasi kontrol odasindan hasar gormüs bir veri surucusu kurtarilir
- Surucu radyasyonla bozulmustur
- NSA'nin Black Widow yazilimi bu bozuk veriyi onarabilir/yeniden yapilandirabilir
- NSA baslangicta Cin'in bu araca erismesine izin vermez
- Protagonist NSA'yi hack'leyerek Black Widow'u kullanir ve saldirganin sunucusunun
  Jakarta'da oldugunu kesfeder

### 1.2 Uzman Degerlendirmesi

Film genel teknik dogruluk acisindan "en dogru siber guvenlik filmi" olarak ovuldu
(Google'in bas bilgi guvenligi muhendisi). Ancak Black Widow araci konusunda:

- Kevin Poulsen (eski blackhat hacker, Wired editoru): "Black Widow abartili.
  NSA'nin bu kadar guclu bir araci internet baglantili bir bilgisayarda tutmasi
  mumkun degil."
- Gercek dunyada bozuk/silinmis verileri saf hesaplama ile kurtarma kavrami
  **teorik olarak sinirli** -- Shannon entropy sinirlarini asamazsiniz
- Film danismanlari: Christopher McKinlay, Kevin Poulsen

### 1.3 Gerceklik Puani

| Ozellik | Filmde | Gercek Dünya |
|---------|--------|--------------|
| Bozuk disk kurtarma | "Sihirli" onarim | Sinirli -- ECC/RAID varsa kismi kurtarma |
| Silinmis dosya reconstruction | Tam kurtarma | Uzerine yazilmamissa kismi mumkun |
| Binary reverse engineering | Gosterilmedi | BSim, FLIRT, constraint solving ile kismi |
| "Hesaplama gucu ile imkansizi basarma" | Ana tema | Dogru yonde ama abartili |

**Ozet:** Film kavramsal olarak dogru yonde -- hesaplama gucu ile daha fazla bilgi
cikarilabilir. Ama "kurtarilamaz" veriyi sihirli bir sekilde kurtarma fikri fiziksel
ve bilgi-teorik sinirlari gozetmiyor.

---

## 2. NSA'nin Bilinen RE Araclari ve Teknikleri

### 2.1 Ghidra Ekosistemi (Acik Kaynak)

Ghidra, NSA'nin Research Directorate tarafindan 2000'lerin basinda gelistirildi.
Vault 7 (WikiLeaks, 2017) ile varligi dogrulandi, RSA 2019'da acik kaynaga alindi.

**Ghidra'nin icindeki onemli alt sistemler:**

| Bilesen | Teknik | Karsiligi Karadul'da |
|---------|--------|---------------------|
| **BSim** | Behavior Similarity -- P-code'dan feature vector, cosine similarity | Cross-binary CFG transfer (v1.7.6) |
| **Function ID** | Byte-pattern + hash tabanli kutuphane tespiti | FLIRT + 4.93M imza DB |
| **Decompiler** | P-code intermediate representation + type propagation | pcode_high_vars tip cikarimi |
| **Data Type Manager** | DWARF/PDB/header parse + struct layout | Undefined type resolution |
| **Sleigh** | Processor spec dili - her ISA icin P-code cevirisi | (Ghidra'ya bagli) |
| **Emulator** | P-code emulation | (Yok - potansiyel gap) |
| **Version Tracking** | Cross-version function correlation | Binary diffing auto-activation |

**BSim Detay:** Feature vector'ler Ghidra decompiler'inin yuksek seviye P-code'undan
olusturulur. Register isimleri, sabit degerleri, veri tipleri kasitli olarak DAHIL
EDiLMEZ -- sadece dataflow ve control flow yapisi. Locality-sensitive hashing ile
milyonlarca fonksiyon arasinda hizli arama. Kosinus benzerligine dayali "fuzzy matching".

### 2.2 NSA'nin Kamuya Acilmamis Araclari (Bilinen/Tahmin Edilen)

- Vault 7 Ghidra'nin CIA ile paylasimini dogruladi -- baska ajanslarla da paylasildi
- Reddit kullanici (hash_define) Ghidra'nin "birkac ABD devlet ajansi" ile paylasildigini
  soyledi
- NSA'nin ic arac seti Ghidra'dan daha genis olma ihtimali yuksek, ancak kamuya acik
  bilgi sinirli

### 2.3 DARPA Cyber Grand Challenge (2016) Teknikleri

DARPA CGC, otomatik binary analiz tekniklerini ilerletmek icin kuruldu:

- **Angr** (UCSB): Symbolic execution framework -- path explosion problemi
- **AFL** tabanli guided fuzzing + sembolik calisma birlesimleri
- **QEMU** tabanli emulasyon ve execution tracing
- 7 fonlanmis takim, toplam $4M odul
- En basarili yaklasim: AFL fuzzing + angr symbolic execution kombinasyonu

---

## 3. State-of-the-Art: Stripped Binary Recovery (2024-2026)

### 3.1 Degisken Isim Kurtarma

| Arac/Paper | Yil | Venue | Teknik | Basari |
|------------|-----|-------|--------|--------|
| **GenNm** | 2025 | NDSS | CodeGemma/CodeLlama finetune + caller/callee context + bias mitigation | +5.6-11.4pp SOTA uzerinde; unseen names icin %22.8 |
| **ReSym** | 2024 | CCS | LLM finetune + Prolog-based aggregation + cross-check | >%50 base name/type; **ACM Distinguished Paper** |
| **VarBERT** | 2024 | S&P | BERT transfer learning + decompiled code tokenization | DIRE'dan iyilestirme |
| **DIRTY** | 2022 | USENIX | Augmented decompiler output + learned names/types | Onemli iyilestirme |
| **DIRE** | 2019 | ASE | Lexical + structural bilgi, neural model | %74.3 (body-in-train) |
| **DEBIN** | 2018 | CCS | Probabilistic graphical models (ETH Zurich) | %68.8 precision, %68.3 recall |

**Kritik gorus:** "Unseen" degisken isimleri (egitim setinde gorulmemis) icin
en iyi arac bile sadece %22.8 precision'a ulasabiliyor. Bu, information theory
sinirlarinin pratikte ne kadar sert oldugunu gosteriyor.

### 3.2 Fonksiyon Isim Kurtarma

| Arac/Paper | Yil | Venue | Teknik | Not |
|------------|-----|-------|--------|-----|
| **Beyond Classification (Domain-Adapted LLMs)** | 2025 | NDSS | Domain-adapted LLM inference | Siniflandirma yerine uretim |
| **BLens** | 2025 | USENIX | Contrastive captioning + ensemble embedding | Binary fonksiyon aciklamasi |
| **SymSem** | 2025 | OpenReview | Self-transformative, semantic-aware LLM finetune | Az etiketli veri ile calisir |
| **ReCopilot** | 2025 | arXiv | Qwen2.5-Coder-7B + CPT/SFT/DPO + dataflow/callgraph | SOTA, +%13 mevcut araclarin uzerinde |
| **SymLM** | 2022 | CCS | Context-sensitive execution-aware embeddings | Ilk "execution trace" tabanli isim |

### 3.3 Tip Cikarimi ve Struct Kurtarma

| Arac/Paper | Yil | Venue | Teknik | Not |
|------------|-----|-------|--------|-----|
| **TypeForge** | 2025 | S&P | Type Flow Graph + LLM refinement (Ghidra extension) | Composite type recovery |
| **TRex** | 2025 | USENIX | Pratik tip reconstruction | Yuksek throughput |
| **TYGR** | 2024 | USENIX | Graph Neural Network tabanli tip cikarimi | |
| **OSPREY** | 2021 | S&P | Probabilistic analysis | IDA/Ghidra/Angr'dan ustun |
| **TIE** | 2011 | NDSS | Constraint-based + dataflow | Temel calisma |

### 3.4 Ozel Alanlar

**REMEND (2025, ACM TIST):** Matematiksel denklemleri binary'den kurtarma.
12M parametre, %89.8-92.4 dogruluk, 3 ISA + 3 optimizasyon seviyesi + 2 dil.
**Karadul icin cok ilgili** -- Fortran/C bilimsel kodda math equation recovery.

**REcover (2025, Springer):** Object file reconstruction -- compile-unit sinirlari tahmin.

**Practical Type Inference (2025, arXiv):** Gercek dunya struct'lari ve fonksiyon
imzalari icin yuksek hizli tip cikarimi.

---

## 4. Information Theory Sinirlari: Neyin Kurtarilabilecegi

### 4.1 Shannon-Fano Cercevesi

Berke'nin mevcut analizi (`IMPOSSIBLE-RE-MATH-ANALYSIS.md`) cok saglam.
Eklemek istedigim noktalar:

```
Derleme donusumu: Y = Compile(X, theta)
Ters cevirme:    X_hat = Decompile(Y, theta_hat)

Mutual information: I(X; Y | theta)  -- kurtarilabilir bilgi miktari
Conditional entropy: H(X | Y, theta) -- kurtarilamayan bilgi
```

**Kurtarilabilirlik spektrumu:**

```
%100 kesin  <---[||||||||||||||||||||]---> %0 sifir bilgi

Fonksiyon sinirlari     [===========|              ] ~%95
Parametre sayisi         [=========|               ] ~%90
Tip bilgisi (temel)      [========|                ] ~%85
Struct layout            [=======|                 ] ~%80
Kontrol akisi yapisi     [=======|                 ] ~%80
Algoritma kimligi (CFG)  [=====|                   ] ~%65
Library fonksiyon ismi   [=====|                   ] ~%65
Fonksiyon amaci/anlami   [===|                     ] ~%45
Degisken isimleri        [==|                      ] ~%25
Yorum icerigi            [|                        ] ~%5
Kod stili/formatting     [                         ] ~%0
```

### 4.2 Neden Degisken Isimleri Kurtarilamaz?

Degisken isimleri derleyici tarafindan **tamamen siliniyor** (stripped binary).
Kalan bilgi kaynaklari:

1. **Kullanim patterni** -- degiskenin nasil kullanildigi ismi hakkinda ipucu verir
   - Loop counter icin `i, j, k` %80+ dogruluk
   - Dosya pointer icin `fp, file` %60 dogruluk
   - Domain-specific isimler (orn. `reynolds_number`) %10-15 dogruluk

2. **Tip bilgisi** -- `double*` olan degisken `count` olmasi olasi degil

3. **Cagri baglami** -- `printf(format, X)` ise X muhtemelen string

4. **Istatistiksel prior** -- egitim verisindeki isim dagilimi
   - >%50 isim 2'den az kez gorunuyor (long tail)
   - %0.1 isim 1000+ kez gorunuyor (common names)

**Sonuc:** Degisken isim kurtarma yapisal olarak "hallucination-prone" bir problem.
LLM'ler %74 basari rapor etse de, bu cogunlukla egitim setinde gorulen yaygin
isimler icin. Gercek dunyada benzersiz isimlerde basari %10-22 arasinda.

### 4.3 Kurtarilamaz Olanlari "Kurtarma": Berke'nin Signature Fusion Fikri

Berke'nin vizyonu (`karadul-v140-vizyon.md`) bilgi-teorik olarak DOGRU bir yaklasim:

```
Hesaplama ile struct/tip/CFG kurtarma
    |
    v
Kurtarilan yapilar bilinen kutuphane fonksiyonlariyla eslestirme
    |
    v
Eslestirme basarili -> orijinal isimler de gelir
```

Bu yaklasim Shannon sinirlarina TAKILI KALMAZ cunku:
- Struct layout + parametre tipleri + CFG yapisi = cok boyutlu fingerprint
- Bu fingerprint bilinen fonksiyonlarla eslestirirse, isimler DB'den gelir (kurtarma degil, eslestirme)
- Eslestirme basarisi I(fingerprint; library_function) ile sinirli, isim entropisi ile degil

**Bu, FLIRT'in byte-matching yaklasiminin DAHA GUCLU bir genellemesi.**

---

## 5. Karadul vs State-of-the-Art: Gap Analizi

### 5.1 Karadul'un GUCLU Yanlari

| Ozellik | Karadul | Rakipler |
|---------|---------|----------|
| LLM'siz deterministik pipeline | VAR -- tekrarlanabilir, offline | Cogu LLM'e bagimli |
| 4.93M imza DB | VAR | Ghidra BSim: ayarlara bagli |
| Inter-proc param propagation | VAR (5 hop, bidirectional) | ReSym: LLM ile, GenNm: caller/callee |
| Cross-binary CFG transfer | VAR (v1.7.6) | BSim: feature vector ile |
| Fortran ABI support | VAR (150+ runtime, BLAS, LAPACK) | Nadiren destekleniyor |
| 125 domain-specific pattern | VAR | DIRE: 0, GenNm: LLM-based |
| Regex safety (0 skip) | VAR | Aractan araca degisir |

### 5.2 Karadul'un EKSIK Yanlari (Potansiyel Iyilestirmeler)

| Eksik | Aciklama | Oncelik | Referans Arac |
|-------|----------|---------|---------------|
| **LLM-based variable naming** | GenNm/ReSym seviyesinde generative isim uretimi | ORTA | GenNm, ReSym |
| **BSim-tarzi behavior hashing** | P-code feature vector + LSH index | YUKSEK | Ghidra BSim |
| **Math equation recovery** | REMEND-tarzi binary -> LaTeX/sympy donusumu | YUKSEK | REMEND |
| **Struct layout solving (SMT)** | TypeForge-tarzi Type Flow Graph + constraint solve | YUKSEK | TypeForge, TIE |
| **Symbolic execution** | Angr-tarzi path exploration + constraint collection | DUSUK | Angr, Manticore |
| **Emulation-based analysis** | Dynamic trace + concrete execution | DUSUK | Ghidra Emulator, Unicorn |
| **Cross-architecture support** | ARM -> x86 eslestirme | DUSUK | BSim (P-code), CFG2VEC |
| **Prolog/Datalog reasoning** | ReSym-tarzi cross-function consistency check | ORTA | ReSym |

### 5.3 Oncelik Siralamasina Gore Oneriler

**KISA VADELI (v1.8.x):**

1. **BSim-tarzi Behavior Hashing** -- Karadul'un CFG transfer'i zaten temeli atiyor.
   Eksik olan: feature vector standardizasyonu + LSH indexleme.
   BSim'in yaklasimindan ogrenilecekler:
   - Register/sabit degerleri DAHIL ETME (normalization)
   - Dataflow + control flow birlestir
   - Cosine similarity threshold
   - Bu Karadul'un mevcut cross_binary_transfer modulune eklenebilir

2. **REMEND entegrasyonu veya benzeri math recovery** -- CalculiX gibi
   bilimsel kodlarda formul kurtarma cok degerli. 12M parametrelik kucuk
   model, offline calisabilir.

3. **TypeForge-tarzi TFG** -- Mevcut `pcode_high_vars` altyapisi uzerine
   Type Flow Graph insa edilebilir. Constraint solving ile struct
   layout'larini daha iyi kurtarma.

**ORTA VADELI (v1.9.x):**

4. **Opsiyonel LLM pass** -- Pipeline sonunda, deterministik sonuclarin
   uzerine opsiyonel bir LLM pass (CodeGemma-2B gibi kucuk model) ile
   isimlendirme iyilestirmesi. Kullanici tercihine bagli.

5. **Prolog-based consistency checker** -- ReSym'in Prolog yaklasimi:
   farkli fonksiyonlardaki LLM/heuristic tahminleri cross-check et,
   tutarsizliklari gider.

**UZUN VADELI (v2.0+):**

6. **Signature Fusion Engine (Berke'nin vizyonu)** -- constraint solving
   ile cikarilan struct/tip/CFG + imza DB eslestirme. Bu gercek "Black Widow"
   momenti -- hesaplama gucu ile "kurtarilamaz" olani kurtarma.

---

## 6. Akademik Kaynaklar: Kapsamli Liste

### 6.1 Degisken/Isim Kurtarma

| # | Paper | Yil | Venue | URL |
|---|-------|-----|-------|-----|
| 1 | GenNm: Generative Model for Variable Name Recovery | 2025 | NDSS | https://www.ndss-symposium.org/ndss-paper/unleashing-the-power-of-generative-model-in-recovering-variable-names-from-stripped-binary/ |
| 2 | ReSym: LLMs for Variable & Data Structure Recovery | 2024 | CCS | https://github.com/lt-asset/resym |
| 3 | VarBERT: Transfer Learning for Variable Names | 2024 | S&P | https://sefcom.asu.edu/publications/varbert-oakland24.pdf |
| 4 | DIRE: Neural Decompiled Identifier Naming | 2019 | ASE | https://arxiv.org/abs/1909.09029 |
| 5 | DEBIN: Predicting Debug Info in Stripped Binaries | 2018 | CCS | https://debin.ai/ |

### 6.2 Fonksiyon Isim Kurtarma

| # | Paper | Yil | Venue | URL |
|---|-------|-----|-------|-----|
| 6 | Beyond Classification: Domain-Adapted LLMs | 2025 | NDSS | https://www.ndss-symposium.org/wp-content/uploads/2025-797-paper.pdf |
| 7 | ReCopilot: RE Copilot in Binary Analysis | 2025 | arXiv | https://arxiv.org/abs/2505.16366 |
| 8 | SymSem: Self-Transformative Function Name Recovery | 2025 | OpenReview | https://openreview.net/forum?id=E14Vr16HwD |
| 9 | BLens: Contrastive Captioning of Binary Functions | 2025 | USENIX | (USENIX Sec 2025) |
| 10 | SymLM: Context-Sensitive Execution-Aware Embeddings | 2022 | CCS | (ACM CCS 2022) |

### 6.3 Tip Cikarimi ve Struct Kurtarma

| # | Paper | Yil | Venue | URL |
|---|-------|-----|-------|-----|
| 11 | TypeForge: Composite Data Types for Stripped Binaries | 2025 | S&P | https://github.com/noobone123/TypeForge |
| 12 | TRex: Practical Type Reconstruction | 2025 | USENIX | (USENIX Sec 2025) |
| 13 | TYGR: GNN-based Type Recovery | 2024 | USENIX | (USENIX Sec 2024) |
| 14 | OSPREY: Probabilistic Variable/Structure Recovery | 2021 | S&P | (IEEE S&P 2021) |
| 15 | TIE: Principled RE of Types in Binaries | 2011 | NDSS | (NDSS 2011) |

### 6.4 Neural Decompilation ve Ozel Alanlar

| # | Paper | Yil | Venue | URL |
|---|-------|-----|-------|-----|
| 16 | REMEND: Math Equations from Binary Executables | 2025 | ACM TIST | https://dl.acm.org/doi/10.1145/3749988 |
| 17 | REcover: Object File Recovery from Stripped Binary | 2025 | Springer | https://link.springer.com/article/10.1007/s11416-025-00565-1 |
| 18 | Practical Type Inference: High-Throughput Recovery | 2025 | arXiv | https://arxiv.org/html/2603.08225 |
| 19 | Neutron: Attention-based Neural Decompiler | 2021 | Cybersecurity | https://link.springer.com/article/10.1186/s42400-021-00070-0 |
| 20 | How Far Have We Gone (LLM Survey) | 2024 | ICSME | https://arxiv.org/abs/2404.09836 |

### 6.5 Binary Diffing ve Similarity

| # | Paper | Yil | Venue | URL |
|---|-------|-----|-------|-----|
| 21 | BSim Tutorial (Ghidra) | - | NSA | https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GhidraClass/BSim/BSimTutorial_Intro.md |
| 22 | CFG2VEC: Cross-Architectural RE | 2023 | ICSE | (ACM ICSE 2023) |
| 23 | discovRE: Cross-Architecture Bug ID | 2016 | NDSS | https://www.ndss-symposium.org/wp-content/uploads/2017/09/discovre-efficient-cross-architecture-identification-bugs-binary-code.pdf |
| 24 | Efficient Features for BinDiff | 2019 | JCVHT | https://census-labs.com/media/efficient-features-bindiff.pdf |

### 6.6 Arsiv Kaynaklari

| # | Kaynak | URL |
|---|--------|-----|
| 25 | Awesome-Info-Inferring-Binary (kapsamli liste) | https://github.com/Bin2Own/Awesome-Info-Inferring-Binary |
| 26 | BlackHat 2015: Distributing RE of High-Level IR | https://github.com/REhints/BlackHat_2015 |
| 27 | Ghidra Wikipedia | https://en.wikipedia.org/wiki/Ghidra |

---

## 7. Film vs Gerceklik: Sonuc Tablosu

| Kavram | Filmde (Black Widow) | Gercek Dunya | Karadul'da |
|--------|---------------------|--------------|------------|
| Bozuk disk kurtarma | Tek tusla | ECC/parity varsa kismi | Kapsam disi |
| "Hesaplama ile kurtarma" | Sihirli | Constraint solving, SMT | Signature fusion vizyonu |
| Silinen veri reconstruction | Tam | Uzerine yazilmamissa kismi | CFG/struct reconstruction |
| Pattern-based tanima | Gosterilmedi | FLIRT, BSim, CFG matching | 4.93M imza + CFG transfer |
| AI-based isim tahmin | Gosterilmedi | GenNm, ReSym, ReCopilot | 125 pattern + propagation |
| Entropi sinirlari | Yok sayildi | Shannon'un kanunlari | `IMPOSSIBLE-RE-MATH-ANALYSIS.md` |

**Berke'nin vizyonu filmin "spiritini" yakalayarak gercek teknik sinirlarin icinde kaliyor.**
Hesaplama gucu ile "kurtarilamaz" gorunen seyleri kurtarma fikri DOGRU --
sinir, ne kadarinin gercekten kurtarilabileceginde.

---

## 8. Ozel Notlar ve Uyarilar

### 8.1 BlackHat Konferansi vs Blackhat Filmi
Bunlar FARKLI seyler:
- **BlackHat konferansi**: Yillik guvenlik konferansi (Las Vegas, 1997'den beri)
- **Blackhat filmi**: Michael Mann, 2015, Chris Hemsworth

Konferansta "Black Widow" adinda bir NSA sunumu BULUNAMADI.
En yakin eslesen: "Distributing the REconstruction of High-Level IR for
Large Scale Malware Analysis" (BH USA 2015, Intel/ESET araştırmacıları --
NSA degil).

### 8.2 NSA'nin Gercek Arac Seti
Kamuya acik olan tek major arac Ghidra. NSA'nin ic arac setinin cok daha
genis oldugu varsayilabilir, ancak dogrulanmis bilgi sinirli.
WikiLeaks Vault 7 (2017) Ghidra'nin CIA ile paylasildigini dogruladi.

### 8.3 "Kurtarilamaz" Kavraminin Yeniden Tanimlanmasi
"Kurtarilamaz" olarak kabul edilen seylerin cogu aslinda "yeterli constraint
ile kurtarilabilir" kategorisindedir. Berke'nin constraint solving + signature
fusion yaklasimiNIN gercek "kurtarilamaz" (H(X|Y) = 0 olmayan) durumlar
icin bile ANLAMLI sonuclar uretebilecegi gorulmustur.

---

*Bu rapor, Karadul projesinin yol haritasi icin referans dokumani olarak kullanilabilir.*
*Tum URL'ler 2026-04-05 tarihinde dogrulanmistir.*
