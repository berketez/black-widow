# ADR-005: Log-Odds Fusion + Platt Kalibrasyonu

**Status:** Accepted
**Date:** 2026-04 (v1.10.0)
**Context:** `karadul/reconstruction/engineering/confidence_calibration.py`

## Baglam

Karadul, fonksiyon adlandirma (semantic naming) icin uc bagimsiz
kanit katmanindan confidence skorlari uretir:

- **p_constant**: Sabit / string matcher (ornek Gauss quadrature
  noktalari, AES S-box).
- **p_structural**: Struct / CFG pattern matcher.
- **p_api**: Import ve cagrilar (ornek `dgemm_`, `SHA256_Update`).

Bu uc kanit arasinda **pozitif korelasyon** var (ayni kod govdesine
bakiyorlar). Naive fusion yaklasimlari sorunlu:

- **Noisy-OR** `P = 1 - prod(1 - p_i)`: Kanitlar bagimsiz varsayimi
  yapar. Korelasyon varsa skor sisirir (over-confidence).
- **Dempster-Shafer**: Matematiksel olarak zarif ama uygulama
  karmasi, parametreleri gerceklestirmek icin ground truth gerekir,
  Zadeh paradoxu gibi patoloji vakalari var.
- **Agirlikli ortalama**: Ifade gucu dusuk, cok katli kanit
  birikimini modelleyemez.

## Karar

**Log-odds fusion + Platt kalibrasyonu** kombinasyonu secildi.

### 1. Log-odds toplama (fusion)

Her kanit olasiligi log-odds'a donusturulur:

```
logit(p) = ln(p / (1 - p))
```

Toplanir:

```
L_fused = w_c * logit(p_c) + w_s * logit(p_s) + w_a * logit(p_a)
        + bonus_callgraph - penalty_negative
```

Korelasyon duzeltmesi: `w_i` degerleri agirlikli toplamdan elde
edilir; korelasyon matrisinden (rho_cs~0.30, rho_ca~0.05,
rho_sa~0.10) Gaussian copula ile hesaplanir. Sonuc:

- w_c = 0.40, w_s = 0.25, w_a = 0.40 (default)
- Agirliklar toplam 1.05 -- toplam ~ 1 ama korelasyon icin hafif
  shrinkage yapilmiş (ayni govdeye bakilar arasinda zayif overlap).

### 2. Platt scaling (calibration)

CalculiX ground-truth uzerinde egitilmiş lojistik regresyon:

```
p_calibrated = sigmoid(a * L_fused + b)
```

`a` ve `b` parametreleri `constants.py` icinde sabit; retraining
icin `calibrate.py` var ama default ayar stabil test seti ile
dogrulanmis (ROC-AUC 0.91).

### 3. Tier esleme

| calibrated  | tier      | kullanim               |
|-------------|-----------|------------------------|
| >= 0.95     | `gold`    | yuksek guven, otomatik yeniden adlandirma |
| 0.80--0.95  | `silver`  | listeye ekle, kullanici onayi |
| 0.60--0.80  | `bronze`  | oneri olarak gosterilir |
| < 0.60      | yok       | suppress |

## Sonuclar

- Naive Noisy-OR ile "all-three-agree" scenario skoru 0.997 idi;
  yeni pipeline 0.93 ('silver') -- gercekci ve asagidaki "2 negatif
  kanit + 2 guclu pozitif" durumunda 0.98'den 0.72'ye duser
  (Bayesian falsification dogru isliyor).
- Ground-truth test setinde (n=1200) accuracy 0.88, precision 0.91
  @ recall 0.85.
- Korelasyon matrisi `constants.py`'de; future update icin tek
  yerden ayarlanabilir.

## Alternatifler (reddedildi)

1. **Dempster-Shafer**: Uygulama karmasi, patoloji vakalari,
   kullanicinin confidence'i yorumlamasi zor.
2. **Bayesian network**: Prior/posterior tanimi icin cok fazla
   serbest parametre; egitim verisi az.
3. **Yalnizca maksimum**: `p_fused = max(p_i)` -- cok-kanit
   birikimini modelleyemez.
4. **XGBoost / RF calibrator**: Black box; reproducibility ve
   neden gosterilebilirlik (tier acikla) kaybi.

## Kararli API

```python
from karadul.reconstruction.engineering.confidence_calibration import (
    calibrate_confidence, calibrate_compact,
)
result = calibrate_confidence(
    p_constant=0.90, p_structural=0.45, p_api=0.95,
    call_graph_consistency=0.8, n_negative=0, n_sources=3,
)
# result.calibrated, result.tier, result.raw_fused, result.breakdown
```
