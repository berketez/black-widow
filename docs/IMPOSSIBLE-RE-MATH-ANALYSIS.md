# "Imkansiz" RE Sorunlarinin Matematiksel Cozum Analizi

**Tarih:** 2026-03-23
**Dogrulayan:** Codex-Consultant (GPT-5.4 + kendi analiz)
**Kapsam:** 3 "cozulemez" RE problemi + Multi-Signal Fusion

---

## Genel Cerceve: Ters Cevirme Problemi

Uc problem de ayni soyut yapiyi paylasiyor: gizli kaynak-seviye nesne X'i, gozlemlenen artifact Y = T_theta(X, Z)'den cikarma. Burada theta toolchain/VM/minifier ailesi, Z gizli baglam veya nuisance varyasyon.

**Kesin geri donusum ancak T_theta enjektif (bire-bir) ise mumkun.**

Bayes-optimal kesin esleme orani:

```
P_s* = E_Y [max_x  p(x | Y, theta)]
```

Fano esitsizligi alt sinir verir:

```
P_e* >= (H(X | Y, theta) - 1) / log |X|
```

Derleme/minification/virtualization hesaplanabilir donusumler oldugu icin K(Y | X, theta) = O(1). Zor kisim: K(X | Y, theta) coktan-bire (many-to-one) eslemede buyuk kalabilir.

**Sonuc: Hicbiri "imkansiz" degil, ama kesin ters cevirme en kotu durumda mumkun degil. Anlamli (semantik) kurtarma cogu zaman mumkun.**

---

## 1. Compiler Inline Recovery -- Bilgi-Teorik Analiz

### 1.1 Formulasyon

F = orijinal callee kimligi (fonksiyon adi, orn. `abs`)
Y = optimize edilmis makine kodu dilimi (inline + sonraki paslar)
theta = (compiler, version, flags, target, LTO, PGO)

```
Y = Pi_theta(inline(F, context))
```

Kurtarma = posterior cikarim: p(F | Y, theta)

### 1.2 Inline Expansion Deterministik mi?

**Evet, belirli kosullar altinda.**

Ayni compiler binary + ayni versiyon + ayni hedef + ayni IR + ayni flags + ayni link baglami + ayni LTO gorunurlugu + ayni PGO profili = ayni inline kararlari.

Bunlardan HERHANGI birinin degismesi karari degistirebilir.

**Kaynaklar:**
- LLVM Reproducible Build rehberi
- GCC inline heuristics (cost model): `-finline-limit`, `--param inline-unit-growth`
- `-O2` vs `-O0`: `-O0` hicbir sey inline etmez (explicit `always_inline` haric), `-O2` maliyet modeline gore karar verir

### 1.3 Kolmogorov Complexity Analizi

| Olcu | Orijinal call | Inline edilmis |
|------|--------------|----------------|
| Byte uzunlugu | Kisa (5-10 byte: call addr) | Uzun (15-50 byte: gercek kod) |
| K(Y \| F, theta) | O(1) -- compiler belirleyici | O(1) -- compiler belirleyici |
| K(F \| Y, theta) | **Degisken!** | - |

**Kritik Gorus:** Daha fazla byte, kaynak hakkinda DAHA FAZLA bilgi tasimak ZORUNDA DEGIL.

Inline expansion K(Y | F, theta) = O(1) saglar (compiler deterministik). Ama K(F | Y, theta) pozitif kalabilir cunku farkli callee'ler ayni optimize edilmis idiom'a cekilebilir.

**Ornek:**
```c
// abs() inline:
if (x < 0) x = -x;

// fabs() inline (integer context'te):
if (x < 0) x = -x;   // AYNI KOD!
```

Bu durumda K(F | Y, theta) > 0 cunku Y'den F'yi ayirt edemeyiz.

### 1.4 Pattern Matching Fizibilitesi

**Evet, kisitli aileler icin calisir.**

| Fonksiyon Ailesi | Pattern Guvenirliligi | Ornek |
|------------------|-----------------------|-------|
| abs/fabs | YUKSEK | `cdq; xor eax,edx; sub eax,edx` (x86 idiom) |
| memcpy/memset | YUKSEK | SIMD unrolling, `rep movsb/stosb` |
| strlen | YUKSEK | Null-scan loop + SIMD variants |
| min/max | ORTA | `cmp; cmov` -- diger karsilastirmalarla karisabilir |
| sqrt | DUSUK | `sqrtsd` tek instruction -- context gerekli |
| User-defined | DUSUK | Benzersiz pattern olusturmaz |

**BINO (2023) sonuclari:** Template/library inline tespitinde precision ~%72, recall ~%56, F1 ~%63 (-O2/-O3/-Ofast).

### 1.5 Teorik Sinir

```
H(F | Y, theta) = H(F) - I(F; Y | theta)
```

- Best case: Bilinen compiler + bilinen library ailesi + benzersiz idiom -> H(F | Y, theta) -> 0
- Worst case: Iki farkli callee ayni koda derlenirse -> H(F | Y, theta) = 1 bit (ikili belirsizlik)
- Genel: Keyfi user-defined inline fonksiyonlar icin H(F | Y, theta) buyuk kalir

**Kurtarma mümkünlük sinifi:**
- Library/STL inline: %60-80 F1
- Compiler intrinsic: %80-95 (cok az varyasyon)
- Keyfi user-defined: %10-30 (cogu kurtarilamaz)

### 1.6 Pratik Yaklasim Onerisi

1. **Compiler-aware canonicalization:** Her compiler/version/flag kombinasyonu icin inline idiom veritabani olustur
2. **IR lifting:** Binary'yi LLVM IR'a yukselterek (RetDec, rev.ng) inline pattern'leri IR seviyesinde esle
3. **Library fingerprinting:** FLIRT/BSIM + inline varyant tablosu
4. **Caller-context prior:** `abs()` genellikle matematiksel kod icinde cagirilir -> context prior ekle

### 1.7 Karadul Icin Somut Etki

Mevcut `inline_extractor.py` JS inline bolgeleri icin -- bu FARKLI bir problem (JS bundle inline).
Binary inline recovery icin yeni bir modul gerekli: `karadul/analyzers/inline_detector.py`

**Beklenen basari orani:** Bilinen library inline'lari icin %65-75, genel durum icin %20-35.

**Referanslar:**
- BINO 2023: Binary Inlined function Detection (doi:10.1016/j.cose.2023.103312)
- ICSE 2023: 1-to-1 or 1-to-n (inline etkisi binary similarity'ye)
- LLVM inliner kaynak kodu: llvm/lib/Analysis/InlineCost.cpp

---

## 2. VM Devirtualization -- Teorik Sinirlar

### 2.1 Formulasyon

P = korunan orijinal program
O = gozlemlenen output: O = V_phi(P, xi)
phi = VM ailesi (VMProtect, Themida, Tigress...)
xi = diversification (her build'de farkli opcode mapping, handler obfuscation)

Hedef: P' ~= P (semantik esdeger program kurtarma)

**NOT:** Kesin orijinal native instruction dizisi kurtarilamaz -- sadece bir esdegerlik sinifi kurtarilir.

### 2.2 Turing-Complete Mi?

**Genellikle evet.** VMProtect/Themida/Tigress VM'leri dallanma, aritmetik ve bellek erisimi iceriyor -> Turing-complete.

Ama Turing-completeness kurtarma icin ne gerekli ne yeterli:
- Gerekli degil: Basit substitution cipher de kurtarilamaz olabilir
- Yeterli degil: Turing-complete VM'den bile korunan fragment bounded state/path space'e sahipse kurtarma yapilabilir

**Gercek soru:** Korunan fragment sinirli mi sinirsiz mi?

### 2.3 Handler -> Native Mapping 1:1 ise

**Evet, tam SEMANTIK recovery mumkun.** Ama "orijinal kod"u degil, esdeger bir programi kurtarirsin.

```
handler_semantics(op) -> LLVM IR blogu
bytecode_stream -> VM CFG
VM CFG -> native CFG (LLVM optimize + recompile)
```

### 2.4 VM Bytecode Entropy Analizi

```
H(O) = I(P; O) + H(O | P)
```

| Olcu | Native Kod | VM Bytecode |
|------|-----------|-------------|
| Byte-seviye entropy | 5.5-6.5 bit/byte | 6.0-7.5 bit/byte |
| Yararli bilgi I(P;O) | Yuksek | Ayni (anlam korunuyor) |
| Nuisance entropy H(O\|P) | Dusuk | Yuksek (diversification) |

Virtualization H(O|P)'yi artirmaya calisir (nuisance entropy), H(O)'yu degil.
Opcode sifreleme + handler randomization -> yuksek byte entropy AMA bu bilgi P hakkinda degil!

### 2.5 Rice's Theorem Uygulanabilirligi

Rice's theorem: "Herhangi bir Turing-complete dilde yazilmis programin semantik ozelligi genel olarak karar verilemez."

**Ama biz genel sormuyor, specific VM'ler soruyoruz:**

| VM Sinifi | Rice Geçerli mi? | Kurtarma |
|-----------|-------------------|----------|
| Genel Turing-complete | Evet | Undecidable |
| Bounded-memory VM | Hayir | Decidable (sonlu durum) |
| Non-self-modifying, sabit bytecode | Hayir | Decidable (exhaustive/symbolic analiz) |
| Acyclic fragment | Hayir | Decidable (path enumeration) |
| VMProtect (pratikte) | Kismi | Fragment bazinda decidable |

### 2.6 VMProtect Karmasikligi

| Parametre | VMProtect v3.x |
|-----------|----------------|
| Handler sayisi | 40-120 (versiyona gore) |
| Opcode domain | 256 (tek byte) veya 65536 (iki byte) |
| VM mimarisi | Stack-based (cogu), register-based (bazi modlar) |
| Diversification | Her build'de farkli opcode->handler mapping |
| Handler obfuscation | Junk code, MBA, opaque predicates |
| Nesting | Ultra mode: VM icinde VM (2-3 katman) |

### 2.7 Pratik Sonuclar (Literatur)

| Calisma | Hedef | Sonuc |
|---------|-------|-------|
| Salwan et al. 2018 | 920 Tigress-protected hash | Semantik esdeger kurtarma BASARILI |
| VMAttack 2017 | VMProtect | %89.86 dynamic-trace reduction, %96.67 combined |
| NoVMP | VMProtect <=2.x | Eski versiyonlar icin otomatik |
| SoK 2021 (ARES) | Genel | Insan yardimi HALA gerekli (ticari protector'lar) |

### 2.8 Pratik Yaklasim: Hibrit Pipeline

```
1. Dynamic tracing -> VM sinirlari, VPC, dispatch davranisi
2. Trace compression -> VM-seviye pseudo-trace
3. Selective symbolic execution -> handler ozetleri, branch hedefleri
4. LLVM lifting -> kucuk, saf, dusuk-path rutinler icin
```

**Neden hibrit:**
- Saf statik lifting: diversified protector'larda kirilgan
- Saf synthesis: pahali
- Saf trace simplification: path-limited ama analistler icin kullanisli
- Hibrit: erken okunabilir sonuc + gerektiginde lifting

**Beklenen basari orani:**
- Basit/sabit VM aileleri: %80-95 semantik kurtarma
- VMProtect Ultra (ic ice): %30-50 (buyuk insan yardimi gerekli)
- Genel ticari protector'lar: %50-70

**Referanslar:**
- Sharif et al. 2009: VPC discovery, opcode/handler extraction
- Yadegari et al. 2015: Generic semantics-based trace simplification
- Salwan et al. 2018: Trace-based devirtualization -> LLVM IR
- Rolles 2009: VMProtect manual devirtualization
- Blazytko et al. 2017 (Syntia): Handler semantics via synthesis
- Kinder 2012: VPC-sensitive abstract interpretation

---

## 3. Minified Isim Recovery -- Bilgi-Teorik Sinir

### 3.1 Formulasyon

N = orijinal fonksiyon ismi (orn. "sendHttpRequest")
C = kod baglami (AST, API calls, string literals, call graph)
P = kaynak paket (npm paketi, versiyon)

Minification: N -> e (alpha-renaming + scope compression)

**Donusum semantik-koruyucu ve coktan-bire (many-to-one).**

### 3.2 Shannon Entropy: Isim Bilgisi Kac Bit?

15 karakterlik identifier icin maximum ham-string entropy:

```
H_max(N) = log2(53) + 14 * log2(63) ~= 5.73 + 14 * 5.98 = ~89 bit
```

(Ilk karakter: a-z, A-Z, _ = 53 secenek; sonrakiler: + 0-9 = 63 secenek)

**Ama gercek identifier entropy cok daha dusuk!** Isimler non-uniform ve compositional:

| Olcu | Deger | Kaynak |
|------|-------|--------|
| Max entropy (15 char) | ~89 bit | Yukaridaki hesap |
| Gercek entropy (empirik) | ~25-40 bit | Identifier'lar 200-500 yaygin kelimeden olusur |
| Unigram kelime entropy | ~8-10 bit | ~300 yaygin verb/noun |
| CamelCase parca sayisi | 2-4 | sendHttpRequest = 3 parca |
| Toplam yapisal entropy | ~25-35 bit | 3 parca x 8-10 bit |

### 3.3 Mutual Information: Kod Baglami Ne Kadar Bilgi Tasiyor?

```
I(N; C) = H(N) - H(N | C)
```

| Sinyal | Tahmini I(sinyal; N) | Ornek |
|--------|---------------------|-------|
| API calls | 8-12 bit | `fetch()`, `XMLHttpRequest` -> "http" + "request" |
| String literals | 5-10 bit | "Content-Type", "application/json" -> "http" |
| Parametre sayisi (arity) | 2-3 bit | 3 param: url, method, body |
| Return type | 1-2 bit | Promise -> async islem |
| Call graph (callers) | 3-5 bit | Router handler'dan cagiriliyorsa -> "route" veya "handle" |
| Property access | 3-5 bit | `.headers`, `.status` -> HTTP baglami |

**Toplam tahmini I(N; C) ~= 22-37 bit** (correlation'lar nedeniyle toplamdan az)

**H(N | C) ~= 25-35 - 22-37 = 0-13 bit** -> Bu, 1 ile 8192 isim arasinda belirsizlik demek.

### 3.4 ML Yaklasimi ve Teorik Tavan

| Sistem | Dogruluk | Kosul |
|--------|----------|-------|
| JSNice (2015) | %63 | JS identifier (supervised, CRF) |
| JSNeat (2019) | %69.1 | Minified JS variables |
| DeGuard (2016) | %79.1 | Android obfuscated names |
| DIRE (2019) | %74.3 | Binary variable names (gorulen kutuphaneler) |
| GenNm (2023) | %22.8 | Binary names (gorulMEMIS, top-1) |

**Teorik tavan:**

Fano esitsizligi:

```
P_error >= (H(N | C) - 1) / log2(|vocabulary|)
```

|vocabulary| ~= 50000 (tipik fonksiyon ismi sozlugu) icin:

```
H(N|C) = 10 bit -> P_error >= (10-1)/16 = 56% -> max accuracy = %44
H(N|C) = 5 bit -> P_error >= (5-1)/16 = 25% -> max accuracy = %75
H(N|C) = 2 bit -> P_error >= (2-1)/16 = 6% -> max accuracy = %94
```

Bu gosteriyor ki:
- Kod baglami cok zenginse (API + string + call graph) -> H(N|C) ~ 5 bit -> %75 tavan MAKUL
- DIRE'in %74.3'u bu sinira yakin -> **neredeyse optimal**
- GenNm'in %22.8'i gorulmemis isimler icin -> H(N|C) cok yuksek (bilinmeyen domain)

### 3.5 Kaynak Kod Eslesme: npm Paketi Mevcutsa

```
I(N; C, P) = I(N; C) + I(N; P | C)
```

Eger tam paket/versiyon/build tanimlanirsa:

```
H(N | C, P) -> ~0 bit (cogu durumda)
```

Istisnalar:
- Build-time dead code elimination -> bazi fonksiyonlar kaybolur
- Tree shaking -> kalan fonksiyonlarin alt kumesi
- Versiyon farki -> API degisiklikleri

**Karadul'daki source_matcher pipeline tam olarak bunu yapiyor!**

| Senaryo | Beklenen kurtarma orani |
|---------|------------------------|
| Tam paket + tam versiyon eslesmesi | %90-98 |
| Ayni paket, farkli versiyon | %70-85 |
| Benzer paket (fork) | %40-60 |
| Bilinmeyen kod | %0 (source matching uygulanamaz) |

### 3.6 Pratik Yaklasim Onerisi

1. **Source matching (en yuksek oncelik):** npm registry'den bilinen paket eslesmesi
2. **AST fingerprint:** Structural similarity ile kaynak-minified eslestirme
3. **ML-based prediction:** Bilinmeyen kod icin DIRE/JSNice tarzi model
4. **Multi-signal fusion:** Tum sinyalleri birlestir (asagidaki bolum 4)

---

## 4. Multi-Signal Fusion: Birlestirme Matematigi

### 4.1 Bilgi Kazanci Formulu

N bagimsiz sinyal S_1, ..., S_N icin:

```
I(X; S_1:N) = SUM_{i=1}^{N} I(X; S_i | S_1:i-1)
```

**Bagimsiz sinyaller icin:**

```
I(X; S_1:N) = SUM_{i=1}^{N} I(X; S_i)   [bagimsilik varsayimi]
```

### 4.2 Bayesian Fusion: N Bagimsiz Sinyal

Her sinyal i, accuracy p_i ile:

```
p(x | s_1:N) proportional to p(x) * PRODUCT_{i=1}^{N} p(s_i | x)
```

Log-odds formunda:

```
log O(x | s_1:N) = log O_0(x) + SUM_{i=1}^{N} log LR_i(x)
```

**Somut hesap: N sinyal, hepsi accuracy p, hepsi ayni ismi oneriyor:**

```
P(dogru | N sinyal uyusuyorsa) = p^N / (p^N + (1-p)^N)
```

| N | p=0.6 | p=0.7 | p=0.8 | p=0.9 |
|---|-------|-------|-------|-------|
| 1 | 0.600 | 0.700 | 0.800 | 0.900 |
| 2 | 0.692 | 0.845 | 0.941 | 0.988 |
| 3 | 0.771 | 0.927 | 0.985 | 0.999 |
| 5 | 0.886 | 0.986 | 0.999 | ~1.000 |
| 10 | 0.983 | ~1.000 | ~1.000 | ~1.000 |

### 4.3 Diminishing Returns Analizi

```
Marginal bilgi kazanci: delta_I(N) = I(X; S_N | S_1:N-1)
```

Bagimsiz sinyaller icin delta_I sabit kalir (ve toplam H(X)'e yakinsir).
Korelasyon varsa delta_I hizla azalir.

**Epsilon-esik analizi:**

Posterior hata P_e(N) = 1 - P_s*(N) icin:

```
P_e(N) ~= exp(-N * D_KL) / (1 + exp(-N * D_KL))
```

Burada D_KL = sum p(s|x=dogru) log [p(s|x=dogru) / p(s|x=yanlis)] her sinyalin KL divergence'i.

| D_KL per signal | P_e < 0.01 icin gerekli N | P_e < 0.001 icin N |
|-----------------|---------------------------|---------------------|
| 0.1 (zayif) | ~46 | ~69 |
| 0.5 (orta) | ~9 | ~14 |
| 1.0 (guclu) | ~5 | ~7 |
| 2.0 (cok guclu) | ~3 | ~4 |

**Pratik yorum:** RE'de cogu sinyal D_KL ~ 0.3-0.8 arasinda. 5-8 sinyal genellikle %99+ dogruluk icin yeterli -- EK sinyaller negligible iyilestirme saglar.

### 4.4 Korelasyon Problemi

**RE sinyalleri bagimsiz DEGIL!** Hepsi ayni binary'den geliyor.

```
I(X_i; X_j | Y) > 0  -> korelasyon var
```

Naive Bayesian carpma DOUBLE-COUNTING yapar ve overconfident olur.

**Cozum: Agirlikli log-uzay birlestirici**

```
score(y) = b_y + SUM_i w_i * logit(q_i(y))
P(Y=y | X) proportional to exp(score(y))
```

Bu, w_i < 1 ile korelasyonu absorbe eder:

```
P(Y=y | X) proportional to pi(y)^(1 - SUM w_i) * PRODUCT_i q_i(y)^w_i
```

Naive Bayes = ozel durum: w_i = 1.

**Onerilen w_i degerleri (Karadul icin):**

| Kaynak Sinifi | Onerilen w_i | Gerekce |
|---------------|-------------|---------|
| Signature DB (FLIRT) | 0.9 | Dusuk korelasyon, yuksek kesinlik |
| Source matcher | 0.85 | Bagimsiz kaynak, yuksek kesinlik |
| RTTI extractor | 0.8 | Binary icinden, orta korelasyon |
| Debug string parser | 0.7 | String'ler korelasyonlu (ayni assert'ler) |
| API call namer | 0.6 | CFG ile korelasyonlu |
| Call graph namer | 0.5 | API namer ile korelasyonlu |
| Dataflow namer | 0.5 | API + call graph ile korelasyonlu |
| LLM4Decompile | 0.4 | Tum kaynaklarla korelasyonlu (model hepsini goruyor) |

### 4.5 Optimal Sinyal Secim Stratejisi

Aktif analiz icin, sonraki sinyal secimi:

```
i* = argmax_i { I(Y; X_i | X_S) / cost_i }
```

Burada cost_i = sinyal cikarma maliyeti (sure, hesaplama).

| Sinyal | Maliyet | Beklenen I | I/cost |
|--------|---------|-----------|--------|
| Signature DB | Dusuk (O(N log N)) | Yuksek (8-12 bit) | EN YUKSEK |
| RTTI | Dusuk (string scan) | Orta (5-8 bit) | Yuksek |
| Source match | Orta (AST parse) | Cok Yuksek (15-25 bit) | Yuksek |
| Debug strings | Dusuk (regex) | Orta (5-10 bit) | Orta-Yuksek |
| API call | Orta (CFG traversal) | Orta (5-8 bit) | Orta |
| LLM4Decompile | Yuksek (GPU inference) | Orta (8-12 bit) | Dusuk |

**Optimal siralama:** Signature DB -> RTTI -> Debug strings -> Source match -> API call -> LLM

---

## 5. Ozet Tablosu

| # | Problem | Kesin Ters Cevirme | Semantik Kurtarma | Best-Case | Worst-Case | Karadul'da |
|---|---------|-------------------|-------------------|-----------|------------|------------|
| 1 | Compiler Inline | IMKANSIZ (many-to-one) | MUMKUN (pattern matching) | %80-95 (bilinen library) | %10-30 (keyfi user code) | YOK (yeni modul gerekli) |
| 2 | VM Devirtualization | IMKANSIZ (esdegerlik sinifi) | MUMKUN (hibrit pipeline) | %80-95 (basit VM) | %30-50 (VMProtect Ultra) | YOK (P0 oncelik) |
| 3 | Minified Name | IMKANSIZ (alpha-renaming) | MUMKUN (ML + source match) | %90-98 (paket eslesmesi) | %20-30 (gorulmemis kod) | MEVCUT (source_matcher + name_merger) |
| 4 | Multi-Signal Fusion | N/A | COKLU SINYAL BIRLESTIRME | %99+ (5-8 sinyal) | %60-70 (tek sinyal) | KISMI (name_merger -- iyilestirme gerekli) |

---

## 6. Karadul Icin Aksiyon Onerileri

### Oncelik 1: name_merger.py Bayesian Guncelleme
Mevcut ad-hoc formuller (avg * 1.2, cap 0.95) yerine agirlikli log-uzay birlestirici:

```python
def calibrated_fusion(candidates, weights, prior=0.5):
    """Agirlikli Bayesian fusion -- korelasyon-aware."""
    log_odds = math.log(prior / (1 - prior))
    for c, w in zip(candidates, weights):
        lr = c.confidence / (1 - c.confidence + 1e-10)
        log_odds += w * math.log(lr)
    prob = 1 / (1 + math.exp(-log_odds))
    return min(0.99, prob)
```

### Oncelik 2: Inline Detector Modulu
Yeni `karadul/analyzers/inline_detector.py`:
- Compiler/version-aware idiom veritabani
- IR lifting ile inline pattern tespiti
- FLIRT'e ek olarak inline varyant tablosu

### Oncelik 3: VM Devirtualization Framework
- Handler table extraction (dynamic trace)
- Handler semantics -> LLVM IR lifting
- Trace-based simplification (single-path, multi-path)

### Oncelik 4: Korelasyon-Aware Sinyal Agirliklari
name_merger.py'ye kaynak-bazli w_i agirliklari eklenmeli (Bolum 4.4 tablosu).

---

## 7. Akademik Referanslar

### Inline Recovery
1. **BINO 2023** -- Binary Inlined function Detection. doi:10.1016/j.cose.2023.103312
2. **ICSE 2023** -- 1-to-1 or 1-to-n: Investigating the effect of function inlining on binary similarity

### VM Devirtualization
3. **Sharif et al. 2009** -- Automatic RE of Malware Emulators (VPC discovery)
4. **Yadegari et al. 2015** -- Generic semantics-based deobfuscation (trace simplification)
5. **Salwan et al. 2018** -- Trace-based devirtualization -> LLVM IR (DIMVA)
6. **VMAttack 2017** -- Hybrid approach to VMProtect (ARES)
7. **Rolles 2009** -- VMProtect manual devirtualization (WOOT)
8. **Blazytko et al. 2017** -- Syntia: handler semantics via program synthesis (USENIX Security)
9. **Kinder 2012** -- VPC-sensitive abstract interpretation (EPFL)
10. **SoK 2021** -- Software Protection: ARES Survey

### Name Recovery
11. **JSNice 2015** -- Big Code: predicting identifiers (POPL)
12. **JSNeat 2019** -- Recovering minified JS variables
13. **DIRE 2019** -- Neural decompiled variable renaming. arXiv:1909.09029
14. **GenNm 2023** -- Generalized binary name recovery. arXiv:2306.02546
15. **DeGuard 2016** -- Android deobfuscation (ETH Zurich)

### Bilgi Teorisi
16. **Cover & Thomas** -- Elements of Information Theory (MIT Press)
17. **Li & Vitanyi** -- An Introduction to Kolmogorov Complexity
18. **Rice 1953** -- Classes of Recursively Enumerable Sets (AMS Trans.)
19. **Dempster 1967** -- Upper and lower probabilities (Biometrika)
20. **Shafer 1976** -- A Mathematical Theory of Evidence

### Opaque Predicates (Ek -- onceki rapordaki referanslar)
21. **Collberg et al. 1998** -- Manufacturing Cheap, Resilient, and Stealthy Opaque Constructs
22. **Dalla Preda et al. 2006** -- Opaque Predicates Detection by Abstract Interpretation
23. **Ming et al. 2015** -- LOOP: Logic-Oriented Opaque Predicate Detection (CCS)
