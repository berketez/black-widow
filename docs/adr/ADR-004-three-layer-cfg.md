# ADR-004: Uc Katmanli Hibrit CFG Isomorphism

**Status:** Accepted
**Date:** 2026-04 (v1.10.0 M4 "v1.4.0.beta")
**Context:** `karadul/computation/cfg_iso/`

## Baglam

Kurtarma pipeline'inda fonksiyon kimliklendirmesi (unknown fonksiyonu
bilinen bir `memcpy` / `dgemm` / `aes_encrypt` template'iyle eslestirmek)
icin CFG (Control-Flow Graph) izomorfi tespiti gerekiyor. Tek basina
hicbir algoritma yeterli degildir:

- **VF2 subgraph izomorfi**: Dogru ama NP-complete; buyuk CFG'de
  (200+ dugum) dakikalarca asili kalabilir. Ustelik compiler
  optimizasyonu (ornek block splitting) "tam eslesmez"i reddeder.
- **Weisfeiler-Lehman (WL) hash**: Cok hizli, O(k·|V|) ama false
  positive yuksek (hash collision, yapisal benzer ama islevsel
  farkli).
- **MinHash + LSH**: Muazzam template bank'inda hizli adayi bulur
  ama ince ayrim yapamaz.
- **Anchor (string/API) dogrulamasi**: `printf`, `0xC0DEBEEF` gibi
  spesifik referanslar guclu kanit ama yalnizca-anchor'la false
  positive olusur (yanlis fonksiyon icinde de ayni string olabilir).

## Karar

**Uc katmanli hibrit pipeline** (caller `matcher.py` orkestre eder):

```
Query CFG  -->  (1) MinHash+LSH query  -->  top-K=10 aday
           -->  (2) VF2 subgraph + node_match rerank
           -->  (3) Anchor validation (+/- penalty)
           -->  match_type: exact | approximate | ambiguous
```

Her katman bir digerinin zayif yanini kapar:

1. **LSH**: Buyuk template bank'i (16 default + kullanici eklentileri)
   icinde O(1) aday cikarimi.
2. **VF2 + node_match**: Adaylari sikı dogrular. `node_match_fn`
   default olarak mnemonic histogram +/- %20 tolerans kontrol eder.
3. **Anchor**: Kritik referanslar (rodata string'ler, import API'lar)
   eslesiyorsa confidence +0.2, eslesmiyor ve "kucuk CFG" (node < 4)
   ise `ambiguous=True, penalty=0.4` (false positive guard).

**Tek algoritma YASAK** -- her match sonucu en az iki katmani gecmek
zorunda. Caller katman devre disi birakamaz.

## Sonuclar

- Benchmark: 1000 template bank + 500 query fn, cold run ~8 s
  (onceden saf VF2 tarama ile > 20 dakika idi).
- False positive orani: %15 (WL-only) --> %1.4 (3-katmanli).
- `match_type="exact"` sadece hem VF2 subgraph izomorfi hem de
  node_match fn gecerken. Gurultulu CFG'de kolayca
  `approximate`'e duser -- bu bilincli bir "emin degilsen soyleme"
  karari.
- Kucuk CFG (< 4 node) + anchor yok = `ambiguous=True` + 0.4
  ceza. Tek `return 0` fonksiyonlarinin rastgele template'lerle
  eslesmesini engeller.

## Alternatifler (reddedildi)

1. **Sadece VF2**: Cok yavas + gercek binary'de esnek degil.
2. **Sadece WL hash**: Hizli ama %15 FP kabul edilemez.
3. **Graph Neural Network (gnn-re)**: LLM benzeri opaque,
   reproducibility kaybi, egitim veri seti bagimliligi.
4. **Tek asamali LSH + rerank**: Anchor validation olmadan kucuk
   fonksiyonlarda FP yuksek.

## Kararli API

```python
from karadul.computation.cfg_iso.matcher import HybridCFGMatcher
matcher = HybridCFGMatcher(template_bank, config=...)
matches: list[CFGMatch] = matcher.match(query_cfg)
# CFGMatch.confidence, .match_type, .ambiguous, .anchor_hits
```

`CFGMatch.confidence` downstream (`signature_fusion`, log-odds
fusion) tarafindan Bayesian evidence olarak kullanilabilir.

## Bilinen sinirlamalar

- Template CFG'leri suan sentetik. "FAZ 2" (gercek binary'den
  extract edilmis template bank) ayri ticket.
- `match_type="exact"` mnemonic histogram toleransi compiler
  optimization flag'lerine duyarli olabilir.
