# Karadul v1.0 - Matematiksel ve Algoritmik Dogrulama Raporu

**Tarih:** 2026-03-22
**Dogrulayan:** Codex-Consultant (GPT-5.4 + kendi analiz)
**Kapsam:** 5 kritik algoritma

---

## 1. FLIRT Byte Pattern Matching

**Dosya:** `karadul/analyzers/flirt_parser.py`, satir 663-721
**Verdict: DOGRU**

### Mask Mekanizmasi
Kod `mask[i] == 0xFF` icin kesin karsilastirma, `mask[i] == 0x00` icin wildcard (atlama) yapiyor.
Bu klasik FLIRT implementasyonu ve **dogru**.

### False Positive Analizi

N byte pattern, F = (0xFF mask olan byte sayisi), M = (0x00 wildcard sayisi), F + M = N

Her sabit byte'in rasgele bir byte ile eslesmeme olasiligi: 255/256
Tek bir aday pozisyonda false positive olasiligi:

```
P_fp = (1/256)^F = 2^(-8F)
```

| F (sabit byte) | P_fp (tek aday)    | K=10^6 adayda en az 1 FP |
|----------------|--------------------|--------------------------|
| 4              | 2.33 x 10^-10      | 2.33 x 10^-4             |
| 6              | 3.55 x 10^-15      | 3.55 x 10^-9             |
| 8              | 5.42 x 10^-20      | 5.42 x 10^-14            |
| 16 (tipik)     | 2.94 x 10^-39      | ihmal edilebilir          |

### Confidence Hesabinda Bug

Satir 712-714'te:
```python
conf = min(0.98, sig.confidence * (fixed_bytes / plen))
```

Bu formul sabit byte oranini confidence'a ceviriyor. Ama bu yanlislik orani ile dogruluk
oranini karistiriyor. Ornegin 16 byte pattern'de 8 wildcard varsa: `fixed_bytes/plen = 0.5`,
confidence 0.95 * 0.5 = 0.475 olur. Oysa 8 sabit byte ile false positive olasiligi
5.42 x 10^-20 -- bu son derece guvenilir bir eslesmedir.

**Oneri:** Confidence'i sabit byte SAYISINA gore hesapla, oranina gore degil:
```python
if fixed_bytes >= 8:
    conf = 0.98
elif fixed_bytes >= 6:
    conf = 0.95
elif fixed_bytes >= 4:
    conf = 0.85
else:
    conf = max(0.5, sig.confidence * (fixed_bytes / plen))
```

### Minimum Guvenilir Eslestirme
- F >= 6 byte: P_fp < 3.55 x 10^-15 (cok guvenilir)
- F >= 4 byte: P_fp < 2.33 x 10^-10 (kabul edilebilir, CRC16 ile desteklenmeli)
- F < 4 byte: Guvenilmez, ek dogrulama gerekli

**Risk: DUSUK** - Tipik FLIRT pattern'leri 16-32 byte, wildcard orani %10-30. Gercek
kullanim senaryosunda false positive olasiligi ihmal edilebilir.

---

## 2. Name Merger Confidence Birlestirme

**Dosya:** `karadul/reconstruction/name_merger.py`, satir 146-198
**Verdict: KISMI DOGRU -- ad-hoc formuller UNDERCONFIDENT**

### Mevcut Formuller vs Bayesian

Bagimsiz n kaynak, her biri p confidence ile ayni ismi veriyor:

```
P(dogru | hepsi ayni) = p^n / (p^n + (1-p)^n)    [esit prior varsayimi]
```

| n | p   | Bayesian | exact_multi | semantic | voting  | Sapma         |
|---|-----|----------|-------------|----------|---------|---------------|
| 2 | 0.5 | 0.500   | 0.600       | 0.550    | -       | OVERCONFIDENT |
| 2 | 0.7 | 0.845   | 0.840       | 0.770    | -       | yaklasik      |
| 2 | 0.9 | 0.988   | 0.950(cap)  | 0.900(cap)| -      | UNDERCONF     |
| 3 | 0.7 | 0.927   | -           | -        | 0.805   | UNDERCONF 12% |
| 3 | 0.8 | 0.985   | -           | -        | 0.920   | UNDERCONF 6%  |
| 4 | 0.7 | 0.967   | -           | -        | 0.805   | UNDERCONF 16% |
| 5 | 0.7 | 0.986   | -           | -        | 0.805   | UNDERCONF 18% |

**Analiz:**
- p < 0.6 bolgesi: Ad-hoc formuller OVERCONFIDENT (dusuk kaliteli kaynaklari sisirir)
- p = 0.7 bolgesi: exact_multi yaklasik, voting underconfident
- p > 0.8 bolgesi: 0.95 cap gereksiz yere kisitlayici -- 3+ yuksek kaliteli kaynak
  0.99+ dogruluk verebilir ama 0.95'te takilir

**Dempster-Shafer Alternatifi:**

Dempster-Shafer teorisi her kaynagi bir "belief function" olarak modelleyip
Dempster kurali ile birlestirir. Avantaji: kaynaklarin kismen bagimsiz olmasina izin verir
(Bayesian'in tam bagimsilik varsayimi gercekci degildir). Dezavantaji: hesaplama karmasikligi
ve "Zadeh paradoksu" (cok cakisan kaynaklar bos kumeye yuksek kutle atayabilir).

**Oneri:** Bayesian formulu dogru priorlarda kullan:
```python
def bayesian_merge(confidences: list[float], prior_correct: float = 0.5) -> float:
    """Bagimsiz kaynak varsayimiyla Bayesian birlestirme."""
    p_correct = prior_correct
    for conf in confidences:
        # Likelihood ratio guncelleme
        lr = conf / (1 - conf + 1e-10)
        odds = (p_correct / (1 - p_correct + 1e-10)) * lr
        p_correct = odds / (1 + odds)
    return min(0.99, p_correct)  # Tam kesinlik verme
```

**Risk: ORTA** - Dusuk kaliteli kaynaklarda overconfident, yuksek kaliteli kaynaklarda
underconfident. Pratikte cok buyuk hata yaratmaz cunku isim kalitesi zaten binary olarak
(dogru/yanlis) degerlendirilir, confidence esik degeri uzerinden.

---

## 3. Opaque Predicate Detection

**Dosya:** `karadul/deobfuscators/opaque_predicate.py`, satir 58-102
**Verdict: 2 HATALI pattern var**

### Pattern-by-Pattern Dogrulama

#### x * (x+1) % 2 == 0: DOGRU (overflow dahil)
**Matematiksel kanit:** n ve n+1 ardisik tamsayilar. Biri her zaman cifttir.
Cift sayi * herhangi sayi = cift sayi. mod 2 = 0.

**Overflow durumu:** Modular aritmetikte bile gecerli.
n*(n+1) mod 2^32 mod 2 = n*(n+1) mod 2 = 0 (cunku 2 | 2^32).
Bu, hem unsigned hem signed wraparound icin dogru.

C dilinde signed overflow UB'dir, ama pratikte derleyiciler ya (a) wrapping yapar
ya da (b) UB oldugu icin "her zaman true" varsayar. Her iki durumda da
opaque predicate tespiti dogru calisir.

**Verdict: DOGRU**

#### x*x >= 0 (square_nonnegative): HATALI!
**Matematiksel olarak:** Tum x icin x^2 >= 0 dogru.
**C signed int32'de:** x = 46341 icin x*x = 2147488281, int32 olarak -2147479015. Negatif!

```
x = 46341:  46341^2 = 2147488281
int32 wrap: 2147488281 - 2^32 = -2147479015
-2147479015 >= 0?  FALSE!
```

Bu bir gercek BUG. Signed integer overflow nedeniyle x*x negatif olabilir.
Decompile edilen kodda signed int kullaniliyorsa bu pattern false positive uretir.

**Fix:** Bu pattern'i sadece `unsigned` olarak bilinen degiskenler icin veya
cok kucuk deger araligindaki (|x| < 46340) durumlar icin kullanin.
Alternatif olarak, bu pattern'i "MEDIUM confidence" ile isaretleyin.

#### (x | 1) != 0: DOGRU
**Kanit:** x | 1 en az bit 0'i 1 yapar. Sonuc >= 1. 1 != 0 her zaman true.
Her signed/unsigned integer icin gecerli. Overflow yok (bitwise OR tasma yapmaz).

**Verdict: DOGRU**

#### x == x: KISMI DOGRU (NaN sorunu)
**Integer icin:** Her zaman true. Dogru.
**Float/double icin:** IEEE 754'te NaN != NaN. Yani `x == x` false olabilir.

Decompile edilen C kodunda degisken tipi bilinmeyebilir.
Eger degisken `float` veya `double` ise, `x == x` bir opaque predicate DEGILDIR,
gecerli bir NaN kontroludur! Bu pattern'i opaque predicate olarak isaretlemek
GERCEK kodu bozabilir.

Ornek:
```c
float x = some_calculation();
if (x == x) {  // Bu NaN kontrolu! Opaque predicate degil!
    // x NaN degilse buraya gir
}
```

**Fix:** Bu pattern'i sadece `int/long/unsigned` tip bilgisi mevcutsa kullanin.
Float turlerinde bu pattern'i ATLATIN.

**Verdict: HATALI float/double bolgesi icin**

#### 2 * (x / 2) <= x: DOGRU
Integer division floor ozelligi. 2*(x/2) her zaman <= x cunku
x/2 asagi yuvarlanir (pozitif x icin) veya uste yuvarlanir (negatif x icin).
Her iki durumda 2*(x/2) <= x saglanir.

Istisnai durum: x = INT32_MIN = -2147483648. x/2 = -1073741824.
2*(-1073741824) = -2147483648 = x. -2147483648 <= -2147483648? Evet.

**Verdict: DOGRU**

### Eksik Yaygin Opaque Predicate Pattern'leri

Kodda eksik olanlar:
1. `(x & (x-1)) >= 0` -- 2'nin kuvveti kontrolu maskelemesi (her zaman negatif olmayan sonuc uretmez; bu YANLIS bir opaque predicate, dahil etmemek dogru)
2. `x + 1 > x` -- signed overflow haric her zaman true
3. `(x * x + x) % 2 == 0` -- x*(x+1) ile ayni, farkli yazim
4. `(x | x) == x` -- OR kendisiyle her zaman kendisi
5. `(x & 0) == 0` -- AND 0 her zaman 0
6. `(x ^ x) == 0` -- XOR kendisiyle her zaman 0

---

## 4. CFF Deflattening Topological Sort

**Dosya:** `karadul/deobfuscators/cff_deflattener.py`, satir 278-309
**Verdict: KISMI DOGRU -- isimlendirme YANLIS, davranis KABUL EDILEBILIR**

### Analiz

Kod "topological sort" diyor ama aslinda **BFS traversal** yapiyor.
Gercek topological sort sadece DAG (Directed Acyclic Graph) icin tanimlidir.
CFF state graph'lari cycle icerebilir (while loop = bir state kendisine veya
onceki bir state'e geri doner).

### Cycle Davranisi
```python
while queue:
    state = queue.pop(0)
    if state in visited:
        continue       # <-- Cycle'i engeller
    visited.add(state)
    order.append(state)
```

`visited` seti sonsuz donguyu ONLER. Ama cycle icerisindeki state'ler sadece
ILK ziyarette siraya eklenir, geri kenarlar (back edge) ATLANIR.

### Bu Sorun Mu?

CFF deflattening baglami icin: **Cogunlukla KABUL EDILEBILIR.**

Neden: CFF obfuscation'da state graph genellikle "yaklasik-seri" bir yapidadir.
Obfuscator orijinal linear kodu state'lere bolerek dispatcher'a cevirir.
Cycle'lar genellikle orijinal while/for loop'larindan gelir. BFS traversal
entry'den baslayip "breadth-first" gezinerek makul bir lineer siralama uretir.

### Sorunlu Senaryolar

1. **Ic ice loop'lar:** Dis loop body'si ile ic loop body'si BFS'te ayni seviyeye
   dusebilir, siralama hatali olabilir.

2. **If-else diamond:** entry -> A, entry -> B, A -> exit, B -> exit. BFS A ve B'yi
   ayni seviyede ziyaret eder ve ikisini de exit'ten once koyar. Bu DOGRU.

3. **Birden fazla entry point:** Kod sadece `blocks[0]`'i entry kabul ediyor (satir 288).
   Gercek CFF'de birden fazla giris noktasi olabilir (exception handler, signal handler).
   Bu durumda bazi state'ler "ziyaret edilmemis" kalip sona atilir (satir 304-308).

### Iyilestirme Onerisi

BFS yerine **Reverse Post-Order DFS** kullanin. Bu, cycle icerisindeki back edge'leri
dogal olarak ayirir ve compiler'lardaki kontrol akisi analizi ile uyumludur.

```python
def _reverse_postorder(self, graph, blocks):
    order = []
    visited = set()

    def dfs(state):
        if state in visited:
            return
        visited.add(state)
        for ns in graph.get(state, []):
            dfs(ns)
        order.append(state)  # Post-order

    entry = blocks[0].state_value
    dfs(entry)

    # Ziyaret edilmemisler
    for block in blocks:
        if block.state_value not in visited:
            dfs(block.state_value)

    return list(reversed(order))  # Reverse post-order
```

**Risk: ORTA** - Basit CFF'ler icin BFS yeterli. Karmasik ic ice loop'lu CFF'lerde
hatali siralama uretebilir. Pratik etkisi: deobfuscate edilen kod okunabilirlik
acisindan bozulabilir ama semantik olarak (state machine logic) dogru kalir.

---

## 5. Benchmark Accuracy Metrikleri

**Dosya:** `tests/benchmark/metrics.py`
**Verdict: KISMI DOGRU -- agirliklar makul ama Jaccard'da ince sorunlar var**

### Agirlik Analizi

| Tip      | Agirlik | Bilgi-teorik yorum |
|----------|---------|-------------------|
| Exact    | 1.0     | Tam bilgi: H(X)=0 bit belirsizlik |
| Semantic | 0.8     | Yaklasik bilgi: ~0.3 bit belirsizlik (5 synonym arasinda biri) |
| Partial  | 0.5     | Kismi bilgi: ~1 bit belirsizlik |
| Wrong    | 0.0     | Bilgi yok |

Exact = 1.0 ve Wrong = 0.0 kesin dogru. Semantic icin 0.8 makul bir tercih.
Partial icin 0.5 biraz cömert olabilir (ornegin sadece "send" kelimesi dogru ama
fonksiyonun ne gonderdigini bilmiyorsak, asil bilginin %30-40'i kadar).

**Oneri:** Partial agirligini 0.3-0.4 araligina dusurmeyi dusun. Veya partial match
icindeki overlap oranina gore dinamik agirlik ver:
```python
partial_score = overlap_ratio * 0.6  # 0.4 overlap = 0.24, 0.8 overlap = 0.48
```

### Jaccard >= 0.5 Threshold

**Testlerim:**
- Gercek semantic eslesmeler (send_data vs transmit_buffer): Jaccard = 1.0 (synonym gruplari tam eslesiyor)
- Yanlis eslesmeler (send_data vs parse_data): Jaccard = 0.06 (dogru sekilde reddediliyor)
- Zit anlamlar (get_config vs set_config): Jaccard = 0.045 (dogru sekilde reddediliyor)

**Sorun:** Synonym expansion nedeniyle Jaccard ya cok yuksek (1.0) ya cok dusuk (<0.1)
cikiyor. 0.5 threshold'u pratikte nadiren "sinirlarda" bir karar veriyor.
Bu, threshold'un islevsel oldugu ama ayrimci gucunun dusuk oldugu anlamina gelir --
esasen "synonym grubunda mi degil mi" ikili bir karar.

**Transitive kapisma riski:** `write` kelimesi hem `send` grubunda hem `serialize`
grubunda. Bu nedenle `write` iceren bir isim her iki grupla da baglantilanir.
Ancak full Jaccard hesabinda bu sorunlu bir false positive uretmiyor cunku
diger kelimeler (data vs msg vs config) farkli gruplardan geliyor.

### BLEU/ROUGE/Cosine Alternatifi

- **BLEU:** N-gram bazli, ceviri kalitesi icin tasarlanmis. Fonksiyon isimleri genelde
  2-4 kelime, BLEU'nun unigram/bigram hassasiyeti cok kaba kalir.
- **ROUGE:** Recall-oriented, ozet kalitesi icin. Ayni sorun.
- **Cosine Similarity (embedding-based):** En iyi alternatif. CodeBERT/UniXcoder
  embedding'lerini kullanarak semantik benzerlik hesaplanabilir. Ama bu LLM
  bagimliligi ekler, lightweight benchmark icin agir.

**Oneri:** Mevcut Jaccard yaklasiminizi tutun ama agirlikli Jaccard kullanin:
```python
def weighted_jaccard(parts1, parts2, equiv_map):
    """Her kelimenin grupta nerede durduğuna gore agirlik ver."""
    # Dogrudan eslesen kelimeler: agirlik 1.0
    # Synonym uzerinden eslesen: agirlik 0.7
    # Bu, transitive kapismayi azaltir
```

**Risk: DUSUK** - Mevcut sistem pratikte iyi calisiyor. Jaccard'in bimodal davranisi
(1.0 veya <0.1) esasen sorun degil, dogru sekilde "eslesiyor veya eslesmiyor" ayrimi yapiyor.

---

## OZET TABLOSU

| # | Algoritma | Verdict | Risk | Aksiyon |
|---|-----------|---------|------|---------|
| 1 | FLIRT Byte Matching | DOGRU | DUSUK | Confidence hesabini duzelt (oran -> sayi bazli) |
| 2 | Name Merger Confidence | KISMI DOGRU | ORTA | Bayesian guncellemeye gec veya caps'leri kaldir |
| 3a | x*(x+1)%2==0 | DOGRU | - | - |
| 3b | x*x>=0 | **HATALI** | **YUKSEK** | Signed overflow false positive! Fix gerekli |
| 3c | (x\|1)!=0 | DOGRU | - | - |
| 3d | x==x | **HATALI** (float) | **YUKSEK** | NaN false positive! Tip kontrolu ekle |
| 4 | CFF Topological Sort | KISMI DOGRU | ORTA | BFS yerine reverse post-order DFS onerisi |
| 5 | Benchmark Metrics | KISMI DOGRU | DUSUK | Partial agirligini dusur, weighted Jaccard dusun |

**En kritik bug'lar:**
1. `x*x >= 0` signed int32 overflow'da false positive (opaque_predicate.py satir 63)
2. `x == x` float/double NaN'da false positive (opaque_predicate.py satir 72)

Bu iki bug, gercek deobfuscation senaryosunda kodu bozabilir: gercek NaN kontrollerini
veya overflow-sensitive kosullari yanlistikla "opaque predicate" olarak isaretleyip
dead code olarak kaldirmak, programin mantigini degistirir.
