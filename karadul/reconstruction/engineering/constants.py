"""IEEE-754 sabit veritabani -- muhendislik/bilimsel algoritma tespiti icin.

Decompile edilmis C kodundaki double-precision sabit degerlerini tarayarak
hangi algoritmalarin kullanildigini tespit eder.  Her sabit icin:
- hex_pattern : big-endian IEEE-754 double hex gosterimi
- float_value : Python float degeri
- decimal_pattern : decompiler ciktisinda gorunebilecek kisaltilmis ondalik form
- algorithm, category, group : algoritma kimligi ve gruplama bilgisi

Hex degerleri ``struct.pack('>d', value).hex()`` ile dogrulandi.
"""

from __future__ import annotations

from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class EngConstant:
    """Bilinen bir muhendislik sabiti."""

    hex_pattern: str        # "3fe279a74590331d" (IEEE-754 double, big-endian hex)
    float_value: float      # 0.5773502691896258
    decimal_pattern: str    # "0.57735" (decompile ciktisinda gorunebilecek kisaltilmis form)
    algorithm: str          # "gauss_quadrature_1pt"
    category: str           # "fea_integration", "cfd_turbulence", ...
    confidence: float       # 0.90
    description: str        # "1/sqrt(3) -- 1-point Gauss-Legendre quadrature"
    group: str              # "gauss_1pt" -- ayni gruba ait sabitleri iliskilendirir


# ---------------------------------------------------------------------------
# Grup eslestirme
# Ayni fonksiyonda birden fazla sabit bulunursa confidence artar.
# ---------------------------------------------------------------------------

CONSTANT_GROUPS: dict[str, list[str]] = {
    # -- Gauss-Legendre quadrature -------------------------------------------
    "gauss_1pt": [
        "3fe279a74590331d",   # +1/sqrt(3) = 0.57735...
        "bfe279a74590331d",   # -1/sqrt(3)
    ],
    "gauss_2pt": [
        "3fe279a74590331d",   # +1/sqrt(3)
        "bfe279a74590331d",   # -1/sqrt(3)
        # weight = 1.0 (too common, not in group)
    ],
    "gauss_3pt": [
        "3fe8c97ef43f7248",   # +sqrt(3/5) = 0.77459...
        "bfe8c97ef43f7248",   # -sqrt(3/5)
        "3fe1c71c71c71c72",   # 5/9
        "3fec71c71c71c71c",   # 8/9
    ],
    "gauss_4pt": [
        "3fd5c23fd9dd3dfd",   # +0.33998...
        "bfd5c23fd9dd3dfd",   # -0.33998...
        "3feb8e6dbcf63985",   # +0.86113...
        "bfeb8e6dbcf63985",   # -0.86113...
        "3fe4de5f840c24cb",   # (18+sqrt(30))/36
        "3fd64340f7e7b66b",   # (18-sqrt(30))/36
    ],
    "gauss_5pt": [
        "3fe13b23fd99b704",   # +0.53846...
        "bfe13b23fd99b704",   # -0.53846...
        "3fecff6ce0533a69",   # +0.90617...
        "bfecff6ce0533a69",   # -0.90617...
        "3fdea1da25ae415b",   # (322+13*sqrt(70))/900
        "3fce539ec36e038c",   # (322-13*sqrt(70))/900
        "3fe23456789abcdf",   # 128/225
    ],
    # -- CFD turbulence models -----------------------------------------------
    "k_epsilon": [
        "3fb70a3d70a3d70a",   # Cmu  = 0.09
        "3ff70a3d70a3d70a",   # C1e  = 1.44
        "3ffeb851eb851eb8",   # C2e  = 1.92
        "3ff4cccccccccccd",   # sigma_e = 1.3
    ],
    "k_omega_sst": [
        "3fd3d70a3d70a3d7",   # a1 = 0.31
        "3fb70a3d70a3d70a",   # beta_star = 0.09
        "3feb645a1cac0831",   # sigma_omega2 = 0.856
        "3fb3333333333333",   # beta1 = 0.075
        "3fb532617c1bda51",   # beta2 = 0.0828
        "3feb333333333333",   # sigma_k1 = 0.85
    ],
    "spalart_allmaras": [
        "3fc15810624dd2f2",   # cb1 = 0.1355
        "3fe3e76c8b439581",   # cb2 = 0.622
        "3fe5555555555555",   # sigma = 2/3
        "401c666666666666",   # cv1 = 7.1
    ],
    # -- Finance -------------------------------------------------------------
    "abramowitz_stegun_cdf": [
        "3fd04f20c6ec5a7e",   # a1 =  0.254829592
        "bfd23531cc3c1469",   # a2 = -0.284496736
        "3ff6be1c55bae157",   # a3 =  1.421413741
        "bff7401c57014c39",   # a4 = -1.453152027
        "3ff0fb844255a12d",   # a5 =  1.061405429
        "3fd4f740a93d7b8c",   # p  =  0.3275911
    ],
    # -- ML / Optimisation ---------------------------------------------------
    "adam_optimizer": [
        "3feccccccccccccd",   # beta1 = 0.9
        "3feff7ced916872b",   # beta2 = 0.999
        "3e45798ee2308c3a",   # eps = 1e-8
    ],
    "selu_activation": [
        "3ff0cfabd6a91132",   # lambda = 1.0507009873554805
        "3ffac5afad782cf1",   # alpha  = 1.6732632423543772
    ],
    "gelu_approximation": [
        "3fa6e4e26d4801f7",   # 0.044715
        "3fe9884533d43651",   # sqrt(2/pi)
    ],
    # -- DSP windows ---------------------------------------------------------
    "hamming_window": [
        "3fe147ae147ae148",   # 0.54
        "3fdd70a3d70a3d71",   # 0.46
    ],
    "blackman_window": [
        "3fdae147ae147ae1",   # 0.42
        "3fb47ae147ae147b",   # 0.08
    ],
    # -- Newmark-beta / HHT --------------------------------------------------
    "newmark_beta": [
        "3fd0000000000000",   # gamma = 0.25  (average acceleration)
        "3fe0000000000000",   # beta  = 0.5
    ],
    # -- New groups (v2 expansion) ------------------------------------
    "acklam_inv_normal": [
        "c043d931bc1e0525",   # Acklam inverse normal CDF a[0] = -39.69683028665376
        "406b9e467034039b",   # Acklam inverse normal CDF a[1] = 220.9460984245205
        "c0713edb2dc53b99",   # Acklam inverse normal CDF a[2] = -275.9285104469687
        "40614b72b40b401b",   # Acklam inverse normal CDF a[3] = 138.357751867269
        "c03eaa3034c08bcd",   # Acklam inverse normal CDF a[4] = -30.66479806614716
        "40040d9320575479",   # Acklam inverse normal CDF a[5] = 2.506628277459239
        "c04b3cf0ce3004c4",   # Acklam inverse normal CDF b[0] = -54.47609879822406
        "406432bf2cf04277",   # Acklam inverse normal CDF b[1] = 161.5858368580409
        "c063765e0b02d8d2",   # Acklam inverse normal CDF b[2] = -155.6989798598866
        "4050b348b1a7e9be",   # Acklam inverse normal CDF b[3] = 66.80131188771972
        "c02a8fb57e147826",   # Acklam inverse normal CDF b[4] = -13.28068155288572
        "bf7fe30d924acfe0",   # Acklam inverse normal CDF c[0] = -0.007784894002430293
        "bfd4a224c0e881b8",   # Acklam inverse normal CDF c[1] = -0.3223964580411365
        "c00334c0c1701758",   # Acklam inverse normal CDF c[2] = -2.400758277161838
        "c00465da2c703a1a",   # Acklam inverse normal CDF c[3] = -2.549732539343734
        "40117fa7f4ea4dc7",   # Acklam inverse normal CDF c[4] = 4.374664141464968
        "4007815c1e3fcfa2",   # Acklam inverse normal CDF c[5] = 2.938163982698783
        "3f7fe2d857ac9fd4",   # Acklam inverse normal CDF d[0] = 0.007784695709041462
        "3fd4a34d2b590364",   # Acklam inverse normal CDF d[1] = 0.3224671290700398
        "40038fa27c8ae616",   # Acklam inverse normal CDF d[2] = 2.445134137142996
        "400e09076895b119",   # Acklam inverse normal CDF d[3] = 3.754408661907416
    ],
    "blackman_exact_window": [
        "3fdb4d4024b33db0",   # a0 = 0.42659 -- Exact Blackman window coefficient
        "3fdfc7a398201cd6",   # a1 = 0.49656 -- Exact Blackman window coefficient
        "3fb3ac710cb295ea",   # a2 = 0.07685 -- Exact Blackman window coefficient (distincti
    ],
    "blackman_harris_window": [
        "3fd6f5c28f5c28f6",   # a0 = 0.35875 -- Blackman-Harris 4-term window
        "3fdf4024b33daf8e",   # a1 = 0.48829 -- Blackman-Harris 4-term window
        "3fc2157689ca18bd",   # a2 = 0.14128 -- Blackman-Harris 4-term window
        "3f87ebaf102363b2",   # a3 = 0.01168 -- Blackman-Harris 4-term window (highly distin
    ],
    "cody_erf": [
        "40a912c1535d1653",   # Cody erf rational approx p[0] = 3209.377589138961
        "407797c38897528b",   # Cody erf rational approx p[1] = 377.485237685302
        "405c774e4d365da6",   # Cody erf rational approx p[2] = 113.8641541510502
        "400949fb3ed443ea",   # Cody erf rational approx p[3] = 3.161123743870566
        "3fc7c7905a31c324",   # Cody erf rational approx p[4] = 0.1857777061846032
        "40a63879423b87ad",   # Cody erf rational approx q[0] = 2844.236833439171
        "40940a77529cadc7",   # Cody erf rational approx q[1] = 1282.616526077372
        "406e80c9d57e55b9",   # Cody erf rational approx q[2] = 244.0246379344442
        "403799ee342fb2dd",   # Cody erf rational approx q[3] = 23.60129095234412
    ],
    "fea_penalty": [
        "412e848000000000",   # 1e6 -- typical penalty parameter for contact (lower bound)
        "41cdcd6500000000",   # 1e9 -- typical penalty parameter for contact (upper bound)
    ],
    "finance_daycount": [
        "4076800000000000",   # 360 -- 30/360 day count convention
        "4076d00000000000",   # 365 -- Actual/365 day count convention
        "4076d40000000000",   # 365.25 -- average year length for accrual
    ],
    "flattop_window": [
        "3fcb98174dfa5ed6",   # a0 = 0.21557895 -- Flat-top window (ISO 18431-2)
        "3fdaaa1780a52bf4",   # a1 = 0.41663158 -- Flat-top window
        "3fd1beadf8ffb93c",   # a2 = 0.277263158 -- Flat-top window
        "3fb5656e0bffc627",   # a3 = 0.083578947 -- Flat-top window
        "3f7c74d7e5a705b5",   # a4 = 0.006947368 -- Flat-top window (highly distinctive)
    ],
    "gauss_10pt": [
        "3fc30e507891e279",   # Gauss-Legendre 10pt abscissa x1 = 0.1488743390
        "bfc30e507891e279",   # Gauss-Legendre 10pt abscissa -x1
        "3fd2e9de7014d6f0",   # Gauss-Legendre 10pt weight w1 = 0.2955242247
        "3fdbbcc009016adc",   # Gauss-Legendre 10pt abscissa x2 = 0.4333953941
        "bfdbbcc009016adc",   # Gauss-Legendre 10pt abscissa -x2
        "3fd13baa7a559bfd",   # Gauss-Legendre 10pt weight w2 = 0.2692667193
        "3fe5bdb9228de198",   # Gauss-Legendre 10pt abscissa x3 = 0.6794095683
        "bfe5bdb9228de198",   # Gauss-Legendre 10pt abscissa -x3
        "3fcc0b059d00bc30",   # Gauss-Legendre 10pt weight w3 = 0.2190863625
        "3febae995e9cb2f3",   # Gauss-Legendre 10pt abscissa x4 = 0.8650633667
        "bfebae995e9cb2f3",   # Gauss-Legendre 10pt abscissa -x4
        "3fc32138c878efe5",   # Gauss-Legendre 10pt weight w4 = 0.1494513492
        "3fef2a3e062af2d8",   # Gauss-Legendre 10pt abscissa x5 = 0.9739065285
        "bfef2a3e062af2d8",   # Gauss-Legendre 10pt abscissa -x5
        "3fb1115f8b62dc1c",   # Gauss-Legendre 10pt weight w5 = 0.0666713443
    ],
    "gauss_6pt": [
        "3fe528a09655c95e",   # Gauss-Legendre 6pt abscissa x1 = 0.6612093865
        "bfe528a09655c95e",   # Gauss-Legendre 6pt abscissa -x1
        "3fd716b7b5794c1c",   # Gauss-Legendre 6pt weight w1 = 0.3607615730
        "3fce8b12d03675c5",   # Gauss-Legendre 6pt abscissa x2 = 0.2386191861
        "bfce8b12d03675c5",   # Gauss-Legendre 6pt abscissa -x2
        "3fddf24d499545e7",   # Gauss-Legendre 6pt weight w2 = 0.4679139346
        "3fedd6ca4e80a01e",   # Gauss-Legendre 6pt abscissa x3 = 0.9324695142
        "bfedd6ca4e80a01e",   # Gauss-Legendre 6pt abscissa -x3
        "3fc5edf601e2dbfa",   # Gauss-Legendre 6pt weight w3 = 0.1713244924
    ],
    "gauss_7pt": [
        "3fdabfd7e03c2fa6",   # Gauss-Legendre 7pt weight w1 = 0.4179591837
        "3fd9f95df119fd62",   # Gauss-Legendre 7pt abscissa x2 = 0.4058451514
        "bfd9f95df119fd62",   # Gauss-Legendre 7pt abscissa -x2
        "3fd86fe74ee32b3d",   # Gauss-Legendre 7pt weight w2 = 0.3818300505
        "3fe7ba9f9be3a1d6",   # Gauss-Legendre 7pt abscissa x3 = 0.7415311856
        "bfe7ba9f9be3a1d6",   # Gauss-Legendre 7pt abscissa -x3
        "3fd1e6b1713d8643",   # Gauss-Legendre 7pt weight w3 = 0.2797053915
        "3fee5f178e7c6229",   # Gauss-Legendre 7pt abscissa x4 = 0.9491079123
        "bfee5f178e7c6229",   # Gauss-Legendre 7pt abscissa -x4
        "3fc092f69f826d57",   # Gauss-Legendre 7pt weight w4 = 0.1294849662
    ],
    "gauss_8pt": [
        "3fc77ac94f3c7345",   # Gauss-Legendre 8pt abscissa x1 = 0.1834346425
        "bfc77ac94f3c7345",   # Gauss-Legendre 8pt abscissa -x1
        "3fd736360b199343",   # Gauss-Legendre 8pt weight w1 = 0.3626837834
        "3fe0d129583284b4",   # Gauss-Legendre 8pt abscissa x2 = 0.5255324099
        "bfe0d129583284b4",   # Gauss-Legendre 8pt abscissa -x2
        "3fd413c50a255616",   # Gauss-Legendre 8pt weight w2 = 0.3137066459
        "3fe97e4ab249f41e",   # Gauss-Legendre 8pt abscissa x3 = 0.7966664774
        "bfe97e4ab249f41e",   # Gauss-Legendre 8pt abscissa -x3
        "3fcc76fb531d2b97",   # Gauss-Legendre 8pt weight w3 = 0.2223810345
        "3feebab1cb0acc67",   # Gauss-Legendre 8pt abscissa x4 = 0.9602898565
        "bfeebab1cb0acc67",   # Gauss-Legendre 8pt abscissa -x4
        "3fb9ea1d04ca0377",   # Gauss-Legendre 8pt weight w4 = 0.1012285363
    ],
    "gauss_9pt": [
        "3fd522a43f65486a",   # Gauss-Legendre 9pt weight w1 = 0.3302393550
        "3fd4c0916e48aa66",   # Gauss-Legendre 9pt abscissa x2 = 0.3242534234
        "bfd4c0916e48aa66",   # Gauss-Legendre 9pt abscissa -x2
        "3fd3fd7e9838d513",   # Gauss-Legendre 9pt weight w2 = 0.3123470770
        "3fe3a0bd2077fd8c",   # Gauss-Legendre 9pt abscissa x3 = 0.6133714327
        "bfe3a0bd2077fd8c",   # Gauss-Legendre 9pt abscissa -x3
        "3fd0add87c827505",   # Gauss-Legendre 9pt weight w3 = 0.2606106964
        "3feac0c44f0d0298",   # Gauss-Legendre 9pt abscissa x4 = 0.8360311073
        "bfeac0c44f0d0298",   # Gauss-Legendre 9pt abscissa -x4
        "3fc71f7a9b222bea",   # Gauss-Legendre 9pt weight w4 = 0.1806481607
        "3feefb2b2ebf2106",   # Gauss-Legendre 9pt abscissa x5 = 0.9681602395
        "bfeefb2b2ebf2106",   # Gauss-Legendre 9pt abscissa -x5
        "3fb4ce65f803eef7",   # Gauss-Legendre 9pt weight w5 = 0.0812743884
    ],
    "gauss_hermite_3pt": [
        "3ff3988e1409212e",   # sqrt(3/2) = 1.2247448714 -- Gauss-Hermite 3pt abscissa
        "3fd2e7fb0bcdf4f1",   # sqrt(pi)/6 = 0.2954089752 -- Gauss-Hermite 3pt outer weight
        "3ff2e7fb0bcdf4f1",   # 2*sqrt(pi)/3 = 1.1816359006 -- Gauss-Hermite 3pt center weig
    ],
    "gauss_hermite_4pt": [
        "3fe0c9e9cffc872c",   # Gauss-Hermite 4pt abscissa x1 = 0.5246476233
        "3fe9c1db31953993",   # Gauss-Hermite 4pt weight w1 = 0.8049140900
        "3ffa692f8fc3f25f",   # Gauss-Hermite 4pt abscissa x2 = 1.6506801239
        "3fb4d0eb00fdaebe",   # Gauss-Hermite 4pt weight w2 = 0.0813128354
    ],
    "gauss_laguerre_2pt": [
        "3fe2bec333018866",   # Gauss-Laguerre 2pt abscissa x1 = 0.5857864376
        "3feb504f333f9de6",   # Gauss-Laguerre 2pt weight w1 = 0.8535533906
        "400b504f333f9de6",   # Gauss-Laguerre 2pt abscissa x2 = 3.4142135624
        "3fc2bec333018866",   # Gauss-Laguerre 2pt weight w2 = 0.1464466094
    ],
    "gauss_laguerre_3pt": [
        "3fda9c0ce2f93646",   # Gauss-Laguerre 3pt abscissa x1 = 0.4157745568
        "3fe6c14620c1eb88",   # Gauss-Laguerre 3pt weight w1 = 0.7110930099
        "40025aafa95a0756",   # Gauss-Laguerre 3pt abscissa x2 = 2.2942803603
        "3fd1d33c0b424cb0",   # Gauss-Laguerre 3pt weight w2 = 0.2785177336
        "401928e75d2368f1",   # Gauss-Laguerre 3pt abscissa x3 = 6.2899450829
        "3f8546f6673b87d5",   # Gauss-Laguerre 3pt weight w3 = 0.0103892565
    ],
    "gauss_radau_3pt": [
        "bfd28db0200e9b7d",   # (1-sqrt(6))/5 = -0.2898979486 -- Gauss-Radau 3pt abscissa
        "3fe613a4dcd41a8b",   # (1+sqrt(6))/5 = 0.6898979486 -- Gauss-Radau 3pt abscissa
        "3fbc71c71c71c71c",   # 1/9 -- Gauss-Radau 3pt endpoint weight
        "3fe06648ace491e9",   # (16+sqrt(6))/36 = 0.5124858262 -- Gauss-Radau 3pt weight
        "3fd816fcdf1a6a67",   # (16-sqrt(6))/36 = 0.3764030627 -- Gauss-Radau 3pt weight
    ],
    "kaiser_window": [
        "4014000000000000",   # beta = 5.0 -- Kaiser window (approx Hamming-like)
        "4021333333333333",   # beta = 8.6 -- Kaiser window (high dynamic range)
    ],
    "les_smagorinsky": [
        "3fc5c28f5c28f5c3",   # Cs = 0.17 -- Smagorinsky constant (isotropic turbulence)
        "3fc999999999999a",   # Cs = 0.2 -- Smagorinsky constant (free shear)
        "3fc70a3d70a3d70a",   # Cs = 0.18 -- Smagorinsky constant (Lilly theoretical)
    ],
    "lobatto_4pt": [
        "3fdc9f25c5bfedd9",   # 1/sqrt(5) = 0.4472135955 -- Gauss-Lobatto 4pt inner abscissa
        "bfdc9f25c5bfedd9",   # -1/sqrt(5) -- Gauss-Lobatto 4pt inner abscissa (neg)
        "3feaaaaaaaaaaaab",   # 5/6 -- Gauss-Lobatto 4pt inner weight
    ],
    "lobatto_5pt": [
        "3fe4f2ec413cb52a",   # sqrt(3/7) = 0.6546536707 -- Gauss-Lobatto 5pt abscissa
        "bfe4f2ec413cb52a",   # -sqrt(3/7) -- Gauss-Lobatto 5pt abscissa (neg)
        "3fe16c16c16c16c1",   # 49/90 = 0.5444444444 -- Gauss-Lobatto 5pt inner weight
        "3fe6c16c16c16c17",   # 32/45 = 0.7111111111 -- Gauss-Lobatto 5pt center weight
        "3fb999999999999a",   # 1/10 -- Gauss-Lobatto 5pt endpoint weight
    ],
    "lobatto_6pt": [
        "3fd2413bb0c4a9aa",   # Gauss-Lobatto 6pt inner abscissa = 0.2852315165
        "3fe87b554d7d0c2f",   # Gauss-Lobatto 6pt outer abscissa = 0.7650553239
        "bfd2413bb0c4a9aa",   # Gauss-Lobatto 6pt inner abscissa (neg)
        "bfe87b554d7d0c2f",   # Gauss-Lobatto 6pt outer abscissa (neg)
        "3fe1c1665ae8edfd",   # Gauss-Lobatto 6pt inner weight = 0.5548583770
        "3fd838ef05e9dfc2",   # Gauss-Lobatto 6pt outer weight = 0.3784749563
        "3fb1111111111111",   # 1/15 -- Gauss-Lobatto 6pt endpoint weight
    ],
    "lobatto_7pt": [
        "3fde019e5eae731c",   # Gauss-Lobatto 7pt abscissa x1 = 0.4688487935
        "bfde019e5eae731c",   # Gauss-Lobatto 7pt abscissa -x1
        "3fdb9bf9427d6168",   # Gauss-Lobatto 7pt weight w1 = 0.4313948774
        "3fea9131b45bf8f7",   # Gauss-Lobatto 7pt abscissa x2 = 0.8302238963
        "bfea9131b45bf8f7",   # Gauss-Lobatto 7pt abscissa -x2
        "3fd1b784990653ee",   # Gauss-Lobatto 7pt weight w2 = 0.2768260474
        "3fdf3526859b8cec",   # 256/525 = 0.4876190476 -- Gauss-Lobatto 7pt center weight
        "3fa8618618618618",   # 1/21 -- Gauss-Lobatto 7pt endpoint weight
    ],
    "math_log_conversions": [
        "3ff71547652b82fe",   # log2(e) = 1.4426950409 -- log base conversion
        "400a934f0979a371",   # log2(10) = 3.3219280949
        "3fd34413509f79ff",   # log10(2) = 0.3010299957
        "3fdbcb7b1526e50e",   # log10(e) = 0.4342944819
    ],
    "math_pi_fractions": [
        "3ff921fb54442d18",   # pi/2 = 1.5707963268
        "3ff0c152382d7365",   # pi/3 = 1.0471975512
        "3fe921fb54442d18",   # pi/4 = 0.7853981634
        "3fe0c152382d7365",   # pi/6 = 0.5235987756
        "401921fb54442d18",   # 2*pi = 6.2831853072 -- full circle
        "402921fb54442d18",   # 4*pi = 12.5663706144 -- solid angle, sphere surface
        "3fd45f306dc9c883",   # 1/pi = 0.3183098862
        "3fe45f306dc9c883",   # 2/pi = 0.6366197724 -- Dirichlet kernel
    ],
    "math_universal": [
        "3ffbb67ae8584caa",   # sqrt(3) = 1.7320508076
        "4001e3779b97f4a8",   # sqrt(5) = 2.2360679775
        "40026bb1bbb55516",   # ln(10) = 2.3025850930
    ],
    "ml_normalization": [
        "3ee4f8b588e368f1",   # 1e-5 -- LayerNorm epsilon (PyTorch default)
        "3eb0c6f7a0b5ed8d",   # 1e-6 -- LayerNorm epsilon (TensorFlow default)
        "3f847ae147ae147b",   # 0.01 -- BatchNorm momentum (alternative)
    ],
    "ml_regularization": [
        "3f1a36e2eb1c432d",   # 1e-4 -- common weight decay (L2 regularization)
        "3f40624dd2f1a9fc",   # 5e-4 -- weight decay (ResNet default)
    ],
    "ml_transformer": [
        "4036a09e667f3bcd",   # sqrt(512) = 22.6274169980 -- Transformer attention scaling (
        "3fc0000000000000",   # 1/sqrt(64) = 0.1250000000 -- attention scaling (d_k=64)
    ],
    "nelder_mead": [
        "3ff0000000000000",   # alpha = 1.0 -- Nelder-Mead reflection coefficient
        "4000000000000000",   # gamma = 2.0 -- Nelder-Mead expansion coefficient
    ],
    "nuttall_window": [
        "3fd6c4e7253da72a",   # a0 = 0.355768 -- Nuttall window
        "3fdf317efe0ce0b9",   # a1 = 0.487396 -- Nuttall window
        "3fc27631b584b1ab",   # a2 = 0.144232 -- Nuttall window
        "3f89d0203e63e8de",   # a3 = 0.012604 -- Nuttall window (distinctive)
    ],
    "physics_em": [
        "41b1de784a000000",   # c = 299792458.0 m/s -- speed of light in vacuum
        "3c07a4da290c1653",   # e = 1.602176634e-19 C -- elementary charge
        "3da37876f1206634",   # epsilon_0 = 8.8541878128e-12 F/m -- vacuum permittivity
        "3eb515370fcb41e4",   # mu_0 = 1.25663706212e-06 H/m -- vacuum permeability
    ],
    "physics_quantum": [
        "390b860bde023111",   # h = 6.62607015e-34 J*s -- Planck constant
        "39b279dcc8b6b7ed",   # m_e = 9.1093837015e-31 kg -- electron mass
        "3a609099b1eaa2c5",   # m_p = 1.67262192369e-27 kg -- proton mass
        "3f7de3d42a1ed29d",   # alpha = 0.0072973525693 -- fine structure constant
        "4164ee44722e5de1",   # R_inf = 10973731.56816 1/m -- Rydberg constant
        "3dcd1781d4f556a3",   # a_0 = 5.29177210903e-11 m -- Bohr radius
    ],
    "rng_k_epsilon": [
        "3fb5a1cac083126f",   # C_mu = 0.0845 -- RNG k-epsilon eddy viscosity coefficient
        "3ff6b851eb851eb8",   # C1 = 1.42 -- RNG k-epsilon production coefficient
        "3ffae147ae147ae1",   # C2 = 1.68 -- RNG k-epsilon dissipation coefficient
        "4011851eb851eb85",   # eta_0 = 4.38 -- RNG k-epsilon strain rate parameter
        "3f889374bc6a7efa",   # beta = 0.012 -- RNG k-epsilon beta parameter
    ],
    "rsm": [
        "3fcc28f5c28f5c29",   # Cs = 0.22 -- RSM slow pressure-strain coefficient
        "3ffccccccccccccd",   # C1 = 1.8 -- RSM pressure-strain return-to-isotropy
        "3fe3333333333333",   # C2 = 0.6 -- RSM rapid pressure-strain coefficient
        "3fe0000000000000",   # C1' = 0.5 -- RSM wall reflection coefficient 1
    ],
    "special_constants": [
        "3fed4f9713e8135d",   # Catalan's constant = 0.9159655942
        "3ff33ba004f00621",   # Apery's constant zeta(3) = 1.2020569032
        "3fe5200bac242b40",   # Twin prime constant = 0.6601618158
    ],
    "wall_function": [
        "3fd999999999999a",   # kappa = 0.4 -- von Karman constant (alternative)
        "40239604189374bc",   # E = 9.793 -- smooth wall roughness parameter (log law)
    ],
    "water_25C": [
        "408f280000000000",   # 997 kg/m^3 -- water density at 25 deg C
        "3f4d29dc725c3dee",   # 8.9e-4 Pa*s -- water dynamic viscosity at 25 deg C
        "40b0560000000000",   # 4182 J/(kg*K) -- water specific heat at 25 deg C
        "3fe36872b020c49c",   # 0.6065 W/(m*K) -- water thermal conductivity at 25 deg C
    ],

    # --- Algorithm Constant Groups (v1.2.2) ---
    "aes_192_grp": ["4058c00000000000", "405f000000000000", "405dc00000000000", "405ec00000000000", "406e400000000000", "405ac00000000000", "405bc00000000000", "4068a00000000000"],
    "aes_256_grp": ["4058c00000000000", "405f000000000000", "405dc00000000000", "405ec00000000000", "406e400000000000", "405ac00000000000", "405bc00000000000", "4068a00000000000"],
    "aes_cbc_grp": ["4058c00000000000", "405f000000000000", "405dc00000000000", "405ec00000000000"],
    "aes_ccm_grp": ["4058c00000000000", "405f000000000000", "405dc00000000000", "405ec00000000000"],
    "aes_cfb_grp": ["4058c00000000000", "405f000000000000", "405dc00000000000", "405ec00000000000"],
    "aes_ctr_grp": ["4058c00000000000", "405f000000000000", "405dc00000000000", "405ec00000000000"],
    "aes_ecb_grp": ["4058c00000000000", "405f000000000000", "405dc00000000000", "405ec00000000000"],
    "aes_ofb_grp": ["4058c00000000000", "405f000000000000", "405dc00000000000", "405ec00000000000"],
    "aes_siv_grp": ["4058c00000000000", "405f000000000000", "405dc00000000000", "405ec00000000000", "4060e00000000000"],
    "anti_debug_ptrace_grp": ["403f000000000000", "403f000000000000"],
    "black_litterman_grp": ["3fa999999999999a", "3f9999999999999a"],
    "blake2s_grp": ["41da827999c00000", "41e76cf5d0a00000", "41ce3779b9000000", "41e4a9fea7400000", "41d443949fc00000", "41e360ad11800000", "41bf83d9ab000000", "41d6f83346400000"],
    "blake3_grp": ["41da827999c00000", "41e76cf5d0a00000", "41ce3779b9000000", "41e4a9fea7400000", "41d443949fc00000", "41e360ad11800000", "41bf83d9ab000000", "41d6f83346400000"],
    "chacha20_csprng_grp": ["41d85c1e19400000", "41c9903237000000", "41de588b4c800000", "41dac8195d000000"],
    "chacha20_ietf_grp": ["41d85c1e19400000", "41c9903237000000", "41de588b4c800000", "41dac8195d000000"],
    "cmac_grp": ["4058c00000000000", "405f000000000000", "405dc00000000000", "405ec00000000000", "4060e00000000000"],
    "credit_triangle_grp": ["3fd999999999999a", "3fe3333333333333"],
    "day_count_convention_grp": ["4076800000000000", "4076d00000000000", "4076d40000000000"],
    "diffie_hellman_grp": ["4000000000000000", "4014000000000000"],
    "kerberos_grp": ["4014000000000000", "4024000000000000", "4026000000000000", "4028000000000000", "402a000000000000", "402c000000000000"],
    "lewis_option_pricing_grp": ["3fe0000000000000", "3fd0000000000000"],
    "md4_grp": ["41d9d148c0400000", "41edf9b571200000", "41e3175b9fc00000", "41b0325476000000", "41d6a09e66400000", "41dbb67ae8400000"],
    "newton_raphson_implied_vol_grp": ["3e45798ee2308c3a", "3fc999999999999a", "4059000000000000"],
    "noise_protocol_grp": ["41d85c1e19400000", "41c9903237000000", "41de588b4c800000", "41dac8195d000000"],
    "poly1305_grp": ["41affffffe000000", "41affffff8000000"],
    "psor_american_fd_grp": ["3ff3333333333333", "3ff8000000000000"],
    "qe_scheme_heston_grp": ["3ff8000000000000", "4000000000000000"],
    "rc6_grp": ["41e6fc2a2c600000", "41e3c6ef37200000"],
    "rmsprop_optimizer_grp": ["3feccccccccccccd", "3e45798ee2308c3a"],
    "rsa_pkcs1_v15_grp": ["40f0001000000000", "4008000000000000"],
    "rsm_reynolds_stress_grp": ["3ffccccccccccccd", "3fe3333333333333", "3fcc28f5c28f5c29"],
    "scrypt_grp": ["41d85c1e19400000", "41c9903237000000", "41de588b4c800000", "41dac8195d000000"],
    "sha1_k_constants_grp": ["41d6a09e66400000", "41dbb67ae8400000", "41e1e3779b800000", "41e94c583ac00000"],
    "shake128_grp": ["3ff0000000000000", "40e0104000000000"],
    "shake256_grp": ["3ff0000000000000", "40e0104000000000"],
    "standard_k_epsilon_grp": ["3fb70a3d70a3d70a", "3ff70a3d70a3d70a", "3ffeb851eb851eb8", "3ff0000000000000", "3ff4cccccccccccd"],
    "unscented_kalman_filter_grp": ["3f50624dd2f1a9fc", "4000000000000000", "0000000000000000"],
    "vm_detection_timing_grp": ["402e000000000000", "4048800000000000"],
    "weno_scheme_grp": ["3fb999999999999a", "3fe3333333333333", "3fd3333333333333", "3eb0c6f7a0b5ed8d"],
    "wireguard_noise_grp": ["41d85c1e19400000", "41c9903237000000", "41de588b4c800000", "41dac8195d000000", "41da827999c00000", "41e76cf5d0a00000"],
    "xchacha20_poly1305_grp": ["41d85c1e19400000", "41c9903237000000", "41de588b4c800000", "41dac8195d000000"],



}


# ---------------------------------------------------------------------------
# Tam sabit veritabani  (60+ kayit)
# ---------------------------------------------------------------------------

ENGINEERING_CONSTANTS: list[EngConstant] = [
    # ========================================================================
    #  GAUSS-LEGENDRE QUADRATURE  (FEA entegrasyon)
    # ========================================================================

    # -- 1/2-point rule: +/- 1/sqrt(3), weight = 1.0 -------------------------
    EngConstant(
        hex_pattern="3fe279a74590331d",
        float_value=0.5773502691896258,
        decimal_pattern="0.57735",
        algorithm="gauss_quadrature",
        category="fea_integration",
        confidence=0.88,
        description="1/sqrt(3) -- Gauss-Legendre 2-point abscissa",
        group="gauss_2pt",
    ),
    EngConstant(
        hex_pattern="bfe279a74590331d",
        float_value=-0.5773502691896258,
        decimal_pattern="-0.57735",
        algorithm="gauss_quadrature",
        category="fea_integration",
        confidence=0.88,
        description="-1/sqrt(3) -- Gauss-Legendre 2-point abscissa (negative)",
        group="gauss_2pt",
    ),

    # -- 3-point rule --------------------------------------------------------
    EngConstant(
        hex_pattern="3fe8c97ef43f7248",
        float_value=0.7745966692414834,
        decimal_pattern="0.77459",
        algorithm="gauss_quadrature_3pt",
        category="fea_integration",
        confidence=0.92,
        description="sqrt(3/5) -- Gauss-Legendre 3-point abscissa",
        group="gauss_3pt",
    ),
    EngConstant(
        hex_pattern="bfe8c97ef43f7248",
        float_value=-0.7745966692414834,
        decimal_pattern="-0.77459",
        algorithm="gauss_quadrature_3pt",
        category="fea_integration",
        confidence=0.92,
        description="-sqrt(3/5) -- Gauss-Legendre 3-point abscissa (negative)",
        group="gauss_3pt",
    ),
    EngConstant(
        hex_pattern="3fe1c71c71c71c72",
        float_value=0.5555555555555556,
        decimal_pattern="0.55555",
        algorithm="gauss_quadrature_3pt",
        category="fea_integration",
        confidence=0.80,
        description="5/9 -- Gauss-Legendre 3-point weight (outer)",
        group="gauss_3pt",
    ),
    EngConstant(
        hex_pattern="3fec71c71c71c71c",
        float_value=0.8888888888888888,
        decimal_pattern="0.88888",
        algorithm="gauss_quadrature_3pt",
        category="fea_integration",
        confidence=0.80,
        description="8/9 -- Gauss-Legendre 3-point weight (center)",
        group="gauss_3pt",
    ),

    # -- 4-point rule --------------------------------------------------------
    EngConstant(
        hex_pattern="3fd5c23fd9dd3dfd",
        float_value=0.33998104358485631,
        decimal_pattern="0.33998",
        algorithm="gauss_quadrature_4pt",
        category="fea_integration",
        confidence=0.93,
        description="sqrt(3/7 - 2/7*sqrt(6/5)) -- Gauss-Legendre 4pt abscissa (inner)",
        group="gauss_4pt",
    ),
    EngConstant(
        hex_pattern="bfd5c23fd9dd3dfd",
        float_value=-0.33998104358485631,
        decimal_pattern="-0.33998",
        algorithm="gauss_quadrature_4pt",
        category="fea_integration",
        confidence=0.93,
        description="-sqrt(3/7 - 2/7*sqrt(6/5)) -- Gauss-Legendre 4pt abscissa (inner, neg)",
        group="gauss_4pt",
    ),
    EngConstant(
        hex_pattern="3feb8e6dbcf63985",
        float_value=0.8611363115940526,
        decimal_pattern="0.86113",
        algorithm="gauss_quadrature_4pt",
        category="fea_integration",
        confidence=0.93,
        description="sqrt(3/7 + 2/7*sqrt(6/5)) -- Gauss-Legendre 4pt abscissa (outer)",
        group="gauss_4pt",
    ),
    EngConstant(
        hex_pattern="bfeb8e6dbcf63985",
        float_value=-0.8611363115940526,
        decimal_pattern="-0.86113",
        algorithm="gauss_quadrature_4pt",
        category="fea_integration",
        confidence=0.93,
        description="-sqrt(3/7 + 2/7*sqrt(6/5)) -- Gauss-Legendre 4pt abscissa (outer, neg)",
        group="gauss_4pt",
    ),
    EngConstant(
        hex_pattern="3fe4de5f840c24cb",
        float_value=0.6521451548625462,
        decimal_pattern="0.65214",
        algorithm="gauss_quadrature_4pt",
        category="fea_integration",
        confidence=0.93,
        description="(18+sqrt(30))/36 -- Gauss-Legendre 4pt weight (inner)",
        group="gauss_4pt",
    ),
    EngConstant(
        hex_pattern="3fd64340f7e7b66b",
        float_value=0.34785484513745385,
        decimal_pattern="0.34785",
        algorithm="gauss_quadrature_4pt",
        category="fea_integration",
        confidence=0.93,
        description="(18-sqrt(30))/36 -- Gauss-Legendre 4pt weight (outer)",
        group="gauss_4pt",
    ),

    # -- 5-point rule --------------------------------------------------------
    EngConstant(
        hex_pattern="3fe13b23fd99b704",
        float_value=0.538469310105683,
        decimal_pattern="0.53846",
        algorithm="gauss_quadrature_5pt",
        category="fea_integration",
        confidence=0.95,
        description="1/3*sqrt(5-2*sqrt(10/7)) -- Gauss-Legendre 5pt abscissa (inner)",
        group="gauss_5pt",
    ),
    EngConstant(
        hex_pattern="bfe13b23fd99b704",
        float_value=-0.538469310105683,
        decimal_pattern="-0.53846",
        algorithm="gauss_quadrature_5pt",
        category="fea_integration",
        confidence=0.95,
        description="-1/3*sqrt(5-2*sqrt(10/7)) -- Gauss-Legendre 5pt abscissa (inner, neg)",
        group="gauss_5pt",
    ),
    EngConstant(
        hex_pattern="3fecff6ce0533a69",
        float_value=0.906179845938664,
        decimal_pattern="0.90617",
        algorithm="gauss_quadrature_5pt",
        category="fea_integration",
        confidence=0.95,
        description="1/3*sqrt(5+2*sqrt(10/7)) -- Gauss-Legendre 5pt abscissa (outer)",
        group="gauss_5pt",
    ),
    EngConstant(
        hex_pattern="bfecff6ce0533a69",
        float_value=-0.906179845938664,
        decimal_pattern="-0.90617",
        algorithm="gauss_quadrature_5pt",
        category="fea_integration",
        confidence=0.95,
        description="-1/3*sqrt(5+2*sqrt(10/7)) -- Gauss-Legendre 5pt abscissa (outer, neg)",
        group="gauss_5pt",
    ),
    EngConstant(
        hex_pattern="3fdea1da25ae415b",
        float_value=0.47862867049936647,
        decimal_pattern="0.47862",
        algorithm="gauss_quadrature_5pt",
        category="fea_integration",
        confidence=0.95,
        description="(322+13*sqrt(70))/900 -- Gauss-Legendre 5pt weight (inner)",
        group="gauss_5pt",
    ),
    EngConstant(
        hex_pattern="3fce539ec36e038c",
        float_value=0.23692688505618908,
        decimal_pattern="0.23692",
        algorithm="gauss_quadrature_5pt",
        category="fea_integration",
        confidence=0.95,
        description="(322-13*sqrt(70))/900 -- Gauss-Legendre 5pt weight (outer)",
        group="gauss_5pt",
    ),
    EngConstant(
        hex_pattern="3fe23456789abcdf",
        float_value=0.5688888888888889,
        decimal_pattern="0.56888",
        algorithm="gauss_quadrature_5pt",
        category="fea_integration",
        confidence=0.90,
        description="128/225 -- Gauss-Legendre 5pt weight (center)",
        group="gauss_5pt",
    ),

    # ========================================================================
    #  NEWMARK-BETA / HHT-ALPHA  (yapisal dinamik)
    # ========================================================================
    EngConstant(
        hex_pattern="3fd0000000000000",
        float_value=0.25,
        decimal_pattern="0.25",
        algorithm="newmark_beta",
        category="fea_dynamics",
        confidence=0.0,  # GROUP-ONLY: too common for standalone detection
        description="Newmark-beta gamma=0.25 (average acceleration) -- cok yaygin sabit, dusuk guven",
        group="newmark_beta",
    ),
    EngConstant(
        hex_pattern="bfa999999999999a",
        float_value=-0.05,
        decimal_pattern="-0.05",
        algorithm="hht_alpha",
        category="fea_dynamics",
        confidence=0.50,
        description="HHT-alpha = -0.05 (yaygn damping degeri)",
        group="hht_alpha",
    ),
    EngConstant(
        hex_pattern="bfb999999999999a",
        float_value=-0.1,
        decimal_pattern="-0.1",
        algorithm="hht_alpha",
        category="fea_dynamics",
        confidence=0.45,
        description="HHT-alpha = -0.1",
        group="hht_alpha",
    ),
    EngConstant(
        hex_pattern="bfd3333333333333",
        float_value=-0.3,
        decimal_pattern="-0.3",
        algorithm="hht_alpha",
        category="fea_dynamics",
        confidence=0.50,
        description="HHT-alpha = -0.3 (maksimum damping)",
        group="hht_alpha",
    ),

    # ========================================================================
    #  RK4 WEIGHTS  (zaman entegrasyonu)
    # ========================================================================
    EngConstant(
        hex_pattern="3fc5555555555555",
        float_value=0.16666666666666666,
        decimal_pattern="0.16666",
        algorithm="runge_kutta_4",
        category="time_integration",
        confidence=0.45,
        description="1/6 -- RK4 outer weight; cok yaygin, dusuk guven",
        group="rk4",
    ),
    EngConstant(
        hex_pattern="3fd5555555555555",
        float_value=0.3333333333333333,
        decimal_pattern="0.33333",
        algorithm="runge_kutta_4",
        category="time_integration",
        confidence=0.35,
        description="1/3 -- RK4 middle weight; cok yaygin, dusuk guven",
        group="rk4",
    ),

    # ========================================================================
    #  CFD -- k-epsilon TURBULANS MODELI
    # ========================================================================
    EngConstant(
        hex_pattern="3fb70a3d70a3d70a",
        float_value=0.09,
        decimal_pattern="0.09",
        algorithm="k_epsilon",
        category="cfd_turbulence",
        confidence=0.85,
        description="Cmu = 0.09 -- k-epsilon turbulans modeli eddy viscosity katsayisi",
        group="k_epsilon",
    ),
    EngConstant(
        hex_pattern="3ff70a3d70a3d70a",
        float_value=1.44,
        decimal_pattern="1.44",
        algorithm="k_epsilon",
        category="cfd_turbulence",
        confidence=0.88,
        description="C1_epsilon = 1.44 -- k-epsilon production terimi katsayisi",
        group="k_epsilon",
    ),
    EngConstant(
        hex_pattern="3ffeb851eb851eb8",
        float_value=1.92,
        decimal_pattern="1.92",
        algorithm="k_epsilon",
        category="cfd_turbulence",
        confidence=0.90,
        description="C2_epsilon = 1.92 -- k-epsilon dissipation terimi katsayisi",
        group="k_epsilon",
    ),
    EngConstant(
        hex_pattern="3ff4cccccccccccd",
        float_value=1.3,
        decimal_pattern="1.3",
        algorithm="k_epsilon",
        category="cfd_turbulence",
        confidence=0.70,
        description="sigma_epsilon = 1.3 -- k-epsilon denkleminin difuzyon katsayisi",
        group="k_epsilon",
    ),

    # ========================================================================
    #  CFD -- k-omega SST TURBULANS MODELI
    # ========================================================================
    EngConstant(
        hex_pattern="3fd3d70a3d70a3d7",
        float_value=0.31,
        decimal_pattern="0.31",
        algorithm="k_omega_sst",
        category="cfd_turbulence",
        confidence=0.90,
        description="a1 = 0.31 -- SST limiter katsayisi (Bradshaw hypothesis)",
        group="k_omega_sst",
    ),
    EngConstant(
        hex_pattern="3feb645a1cac0831",
        float_value=0.856,
        decimal_pattern="0.856",
        algorithm="k_omega_sst",
        category="cfd_turbulence",
        confidence=0.92,
        description="sigma_omega2 = 0.856 -- SST omega denkleminin dis bolge difuzyon katsayisi",
        group="k_omega_sst",
    ),
    EngConstant(
        hex_pattern="3fb3333333333333",
        float_value=0.075,
        decimal_pattern="0.075",
        algorithm="k_omega_sst",
        category="cfd_turbulence",
        confidence=0.82,
        description="beta_1 = 0.075 -- SST ic bolge yikici terim katsayisi",
        group="k_omega_sst",
    ),
    EngConstant(
        hex_pattern="3fb532617c1bda51",
        float_value=0.0828,
        decimal_pattern="0.0828",
        algorithm="k_omega_sst",
        category="cfd_turbulence",
        confidence=0.90,
        description="beta_2 = 0.0828 -- SST dis bolge yikici terim katsayisi",
        group="k_omega_sst",
    ),
    EngConstant(
        hex_pattern="3feb333333333333",
        float_value=0.85,
        decimal_pattern="0.85",
        algorithm="k_omega_sst",
        category="cfd_turbulence",
        confidence=0.72,
        description="sigma_k1 = 0.85 -- SST k denkleminin ic bolge difuzyon katsayisi",
        group="k_omega_sst",
    ),
    EngConstant(
        hex_pattern="3fda3d70a3d70a3d",
        float_value=0.41,
        decimal_pattern="0.41",
        algorithm="k_omega_sst",
        category="cfd_turbulence",
        confidence=0.78,
        description="kappa = 0.41 -- von Karman sabiti (SST wall function'larda)",
        group="k_omega_sst",
    ),
    EngConstant(
        hex_pattern="3fdc28f5c28f5c29",
        float_value=0.44,
        decimal_pattern="0.44",
        algorithm="k_omega_sst",
        category="cfd_turbulence",
        confidence=0.80,
        description="alpha_2 = 0.44 -- SST dis bolge production katsayisi",
        group="k_omega_sst",
    ),

    # ========================================================================
    #  CFD -- SPALART-ALLMARAS TURBULANS MODELI
    # ========================================================================
    EngConstant(
        hex_pattern="3fc15810624dd2f2",
        float_value=0.1355,
        decimal_pattern="0.1355",
        algorithm="spalart_allmaras",
        category="cfd_turbulence",
        confidence=0.94,
        description="cb1 = 0.1355 -- SA production terimi katsayisi",
        group="spalart_allmaras",
    ),
    EngConstant(
        hex_pattern="3fe3e76c8b439581",
        float_value=0.622,
        decimal_pattern="0.622",
        algorithm="spalart_allmaras",
        category="cfd_turbulence",
        confidence=0.93,
        description="cb2 = 0.622 -- SA difuzyon terimi nonlineer katsayisi",
        group="spalart_allmaras",
    ),
    EngConstant(
        hex_pattern="3fe5555555555555",
        float_value=0.6666666666666666,
        decimal_pattern="0.66666",
        algorithm="spalart_allmaras",
        category="cfd_turbulence",
        confidence=0.75,
        description="sigma = 2/3 -- SA difuzyon sabiti",
        group="spalart_allmaras",
    ),
    EngConstant(
        hex_pattern="401c666666666666",
        float_value=7.1,
        decimal_pattern="7.1",
        algorithm="spalart_allmaras",
        category="cfd_turbulence",
        confidence=0.94,
        description="cv1 = 7.1 -- SA viskozite orani geçis sabiti",
        group="spalart_allmaras",
    ),
    EngConstant(
        hex_pattern="3fd3333333333333",
        float_value=0.3,
        decimal_pattern="0.3",
        algorithm="spalart_allmaras",
        category="cfd_turbulence",
        confidence=0.0,  # GROUP-ONLY: too common for standalone detection
        description="cw2 = 0.3 -- SA wall destruction terimindeki katsayi",
        group="spalart_allmaras",
    ),
    EngConstant(
        hex_pattern="3ff3333333333333",
        float_value=1.2,
        decimal_pattern="1.2",
        algorithm="spalart_allmaras",
        category="cfd_turbulence",
        confidence=0.55,
        description="ct3 = 1.2 -- SA laminar-turbulent gecis terimi",
        group="spalart_allmaras",
    ),

    # ========================================================================
    #  CFD -- REALIZABLE k-epsilon
    # ========================================================================
    EngConstant(
        hex_pattern="401028f5c28f5c29",
        float_value=4.04,
        decimal_pattern="4.04",
        algorithm="realizable_k_epsilon",
        category="cfd_turbulence",
        confidence=0.88,
        description="A0 = 4.04 -- Realizable k-epsilon Cmu hesabindaki sabit",
        group="realizable_k_epsilon",
    ),

    # ========================================================================
    #  FINANCE -- ABRAMOWITZ & STEGUN NORMAL CDF YAKLASIMI
    # ========================================================================
    EngConstant(
        hex_pattern="3fd04f20c6ec5a7e",
        float_value=0.254829592,
        decimal_pattern="0.25482",
        algorithm="abramowitz_stegun_cdf",
        category="finance_statistics",
        confidence=0.95,
        description="a1 = 0.254829592 -- A&S normal CDF yaklasimi katsayisi",
        group="abramowitz_stegun_cdf",
    ),
    EngConstant(
        hex_pattern="bfd23531cc3c1469",
        float_value=-0.284496736,
        decimal_pattern="-0.28449",
        algorithm="abramowitz_stegun_cdf",
        category="finance_statistics",
        confidence=0.95,
        description="a2 = -0.284496736 -- A&S normal CDF yaklasimi katsayisi",
        group="abramowitz_stegun_cdf",
    ),
    EngConstant(
        hex_pattern="3ff6be1c55bae157",
        float_value=1.421413741,
        decimal_pattern="1.42141",
        algorithm="abramowitz_stegun_cdf",
        category="finance_statistics",
        confidence=0.96,
        description="a3 = 1.421413741 -- A&S normal CDF yaklasimi katsayisi",
        group="abramowitz_stegun_cdf",
    ),
    EngConstant(
        hex_pattern="bff7401c57014c39",
        float_value=-1.453152027,
        decimal_pattern="-1.45315",
        algorithm="abramowitz_stegun_cdf",
        category="finance_statistics",
        confidence=0.96,
        description="a4 = -1.453152027 -- A&S normal CDF yaklasimi katsayisi",
        group="abramowitz_stegun_cdf",
    ),
    EngConstant(
        hex_pattern="3ff0fb844255a12d",
        float_value=1.061405429,
        decimal_pattern="1.06140",
        algorithm="abramowitz_stegun_cdf",
        category="finance_statistics",
        confidence=0.95,
        description="a5 = 1.061405429 -- A&S normal CDF yaklasimi katsayisi",
        group="abramowitz_stegun_cdf",
    ),
    EngConstant(
        hex_pattern="3fd4f740a93d7b8c",
        float_value=0.3275911,
        decimal_pattern="0.32759",
        algorithm="abramowitz_stegun_cdf",
        category="finance_statistics",
        confidence=0.95,
        description="p = 0.3275911 -- A&S normal CDF yaklasimi t-transform katsayisi",
        group="abramowitz_stegun_cdf",
    ),
    EngConstant(
        hex_pattern="3fd9884533d43651",
        float_value=0.3989422804014327,
        decimal_pattern="0.39894",
        algorithm="normal_pdf",
        category="finance_statistics",
        confidence=0.88,
        description="1/sqrt(2*pi) -- standart normal PDF normalizasyonu",
        group="normal_distribution",
    ),
    EngConstant(
        hex_pattern="40040d931ff62705",
        float_value=2.5066282746310002,
        decimal_pattern="2.50662",
        algorithm="normal_pdf",
        category="finance_statistics",
        confidence=0.88,
        description="sqrt(2*pi) -- standart normal PDF paydasi",
        group="normal_distribution",
    ),

    # ========================================================================
    #  ML -- ADAM OPTIMIZER
    # ========================================================================
    EngConstant(
        hex_pattern="3feccccccccccccd",
        float_value=0.9,
        decimal_pattern="0.9",
        algorithm="adam_optimizer",
        category="ml_optimization",
        confidence=0.0,  # GROUP-ONLY: too common for standalone detection
        description="beta_1 = 0.9 -- Adam first moment decay; yaygin sabit, dusuk guven",
        group="adam_optimizer",
    ),
    EngConstant(
        hex_pattern="3feff7ced916872b",
        float_value=0.999,
        decimal_pattern="0.999",
        algorithm="adam_optimizer",
        category="ml_optimization",
        confidence=0.82,
        description="beta_2 = 0.999 -- Adam second moment decay",
        group="adam_optimizer",
    ),
    EngConstant(
        hex_pattern="3e45798ee2308c3a",
        float_value=1e-8,
        decimal_pattern="1e-08",
        algorithm="adam_optimizer",
        category="ml_optimization",
        confidence=0.70,
        description="epsilon = 1e-8 -- Adam numerical stability sabiti",
        group="adam_optimizer",
    ),

    # ========================================================================
    #  ML -- SELU ACTIVATION
    # ========================================================================
    EngConstant(
        hex_pattern="3ff0cfabd6a91132",
        float_value=1.0507009873554805,
        decimal_pattern="1.05070",
        algorithm="selu_activation",
        category="ml_activation",
        confidence=0.95,
        description="lambda = 1.0507009873554805 -- SELU scaling factor",
        group="selu_activation",
    ),
    EngConstant(
        hex_pattern="3ffac5afad782cf1",
        float_value=1.6732632423543772,
        decimal_pattern="1.67326",
        algorithm="selu_activation",
        category="ml_activation",
        confidence=0.95,
        description="alpha = 1.6732632423543772 -- SELU negative saturation",
        group="selu_activation",
    ),

    # ========================================================================
    #  ML -- GELU APPROXIMATION
    # ========================================================================
    EngConstant(
        hex_pattern="3fa6e4e26d4801f7",
        float_value=0.044715,
        decimal_pattern="0.04471",
        algorithm="gelu_approximation",
        category="ml_activation",
        confidence=0.95,
        description="0.044715 -- GELU tanh yaklasimindaki katsayi",
        group="gelu_approximation",
    ),
    EngConstant(
        hex_pattern="3fe9884533d43651",
        float_value=0.7978845608028654,
        decimal_pattern="0.79788",
        algorithm="gelu_approximation",
        category="ml_activation",
        confidence=0.88,
        description="sqrt(2/pi) -- GELU yaklasim formulu normalizasyonu",
        group="gelu_approximation",
    ),

    # ========================================================================
    #  DSP -- PENCERE FONKSIYONLARI
    # ========================================================================
    EngConstant(
        hex_pattern="3fe147ae147ae148",
        float_value=0.54,
        decimal_pattern="0.54",
        algorithm="hamming_window",
        category="dsp_windowing",
        confidence=0.85,
        description="0.54 -- Hamming penceresi ana katsayisi: w(n) = 0.54 - 0.46*cos(...)",
        group="hamming_window",
    ),
    EngConstant(
        hex_pattern="3fdd70a3d70a3d71",
        float_value=0.46,
        decimal_pattern="0.46",
        algorithm="hamming_window",
        category="dsp_windowing",
        confidence=0.85,
        description="0.46 -- Hamming penceresi cosinus katsayisi",
        group="hamming_window",
    ),
    EngConstant(
        hex_pattern="3fdae147ae147ae1",
        float_value=0.42,
        decimal_pattern="0.42",
        algorithm="blackman_window",
        category="dsp_windowing",
        confidence=0.82,
        description="0.42 -- Blackman penceresi a0 katsayisi",
        group="blackman_window",
    ),
    EngConstant(
        hex_pattern="3fb47ae147ae147b",
        float_value=0.08,
        decimal_pattern="0.08",
        algorithm="blackman_window",
        category="dsp_windowing",
        confidence=0.88,
        description="0.08 -- Blackman penceresi a2 katsayisi (ayirt edici)",
        group="blackman_window",
    ),

    # ========================================================================
    #  FIZIKSEL SABITLER
    # ========================================================================
    EngConstant(
        hex_pattern="400921fb54442d18",
        float_value=3.141592653589793,
        decimal_pattern="3.14159",
        algorithm="trigonometric",
        category="math_constant",
        confidence=0.15,
        description="pi -- evrensel, tek basina algoritmik anlam tasimaz",
        group="math_universal",
    ),
    EngConstant(
        hex_pattern="3ff6a09e667f3bcd",
        float_value=1.4142135623730951,
        decimal_pattern="1.41421",
        algorithm="sqrt_operation",
        category="math_constant",
        confidence=0.20,
        description="sqrt(2) -- geometrik hesaplarda yaygin",
        group="math_universal",
    ),
    EngConstant(
        hex_pattern="3fe6a09e667f3bcc",
        float_value=0.7071067811865475,
        decimal_pattern="0.70710",
        algorithm="sqrt_operation",
        category="math_constant",
        confidence=0.30,
        description="1/sqrt(2) -- normalizasyon, FFT twiddle factor",
        group="math_universal",
    ),
    EngConstant(
        hex_pattern="4005bf0a8b145769",
        float_value=2.718281828459045,
        decimal_pattern="2.71828",
        algorithm="exponential",
        category="math_constant",
        confidence=0.15,
        description="e (Euler's number) -- evrensel",
        group="math_universal",
    ),
    EngConstant(
        hex_pattern="3ff9e3779b97f4a8",
        float_value=1.618033988749895,
        decimal_pattern="1.61803",
        algorithm="golden_section_search",
        category="optimization",
        confidence=0.80,
        description="phi (altin oran) -- golden section search, Fibonacci optimizasyonu",
        group="golden_ratio",
    ),
    EngConstant(
        hex_pattern="3fe62e42fefa39ef",
        float_value=0.6931471805599453,
        decimal_pattern="0.69314",
        algorithm="logarithmic",
        category="math_constant",
        confidence=0.40,
        description="ln(2) -- bilgi teorisi, log2 donusumu",
        group="math_universal",
    ),
    EngConstant(
        hex_pattern="3fe2788cfc6fb619",
        float_value=0.5772156649015329,
        decimal_pattern="0.57721",
        algorithm="euler_mascheroni",
        category="math_constant",
        confidence=0.88,
        description="Euler-Mascheroni sabiti -- harmonik seriler, sayisal fizik",
        group="special_constants",
    ),
    EngConstant(
        hex_pattern="3dd25868f4deae16",
        float_value=6.674e-11,
        decimal_pattern="6.674e-11",
        algorithm="gravitational_sim",
        category="physics_constant",
        confidence=0.92,
        description="G = 6.674e-11 m^3/(kg*s^2) -- Newton gravitasyonel sabiti",
        group="physics_gravity",
    ),
    EngConstant(
        hex_pattern="3b30b0e6d55e647c",
        float_value=1.380649e-23,
        decimal_pattern="1.38064e-23",
        algorithm="statistical_mechanics",
        category="physics_constant",
        confidence=0.93,
        description="k_B = 1.380649e-23 J/K -- Boltzmann sabiti",
        group="physics_thermo",
    ),
    EngConstant(
        hex_pattern="3e6e714da268c0cc",
        float_value=5.670374419e-8,
        decimal_pattern="5.67037e-08",
        algorithm="radiation_heat_transfer",
        category="physics_constant",
        confidence=0.93,
        description="sigma = 5.670374419e-8 W/(m^2*K^4) -- Stefan-Boltzmann sabiti",
        group="physics_thermo",
    ),

    # ========================================================================
    #  CFD -- RELAXATION / COURANT
    # ========================================================================
    EngConstant(
        hex_pattern="3fe6666666666666",
        float_value=0.7,
        decimal_pattern="0.7",
        algorithm="under_relaxation",
        category="cfd_solver",
        confidence=0.35,
        description="0.7 -- yaygin under-relaxation faktoru (SIMPLE, momentum)",
        group="relaxation",
    ),

    # ========================================================================
    #  v2 EXPANSION -- 226 additional IEEE-754 verified constants
    #  Gauss 6-10pt, Lobatto, Hermite, Laguerre, Radau, CODATA physics,
    #  math constants, CFD (RNG/RSM/LES/DES), chemistry, DSP windows,
    #  finance (Acklam/Cody), ML/DL, optimization
    # ========================================================================

    # -- gauss_6pt ---------------------------------------------------
    EngConstant(
        hex_pattern="3fe528a09655c95e",
        float_value=0.6612093864662645,
        decimal_pattern="0.66121",
        algorithm="gauss_quadrature_6pt",
        category="fea_integration",
        confidence=0.93,
        description="Gauss-Legendre 6pt abscissa x1 = 0.6612093865",
        group="gauss_6pt",
    ),
    EngConstant(
        hex_pattern="bfe528a09655c95e",
        float_value=-0.6612093864662645,
        decimal_pattern="-0.66121",
        algorithm="gauss_quadrature_6pt",
        category="fea_integration",
        confidence=0.93,
        description="Gauss-Legendre 6pt abscissa -x1",
        group="gauss_6pt",
    ),
    EngConstant(
        hex_pattern="3fd716b7b5794c1c",
        float_value=0.3607615730481386,
        decimal_pattern="0.36076",
        algorithm="gauss_quadrature_6pt",
        category="fea_integration",
        confidence=0.93,
        description="Gauss-Legendre 6pt weight w1 = 0.3607615730",
        group="gauss_6pt",
    ),
    EngConstant(
        hex_pattern="3fce8b12d03675c5",
        float_value=0.2386191860831969,
        decimal_pattern="0.23862",
        algorithm="gauss_quadrature_6pt",
        category="fea_integration",
        confidence=0.93,
        description="Gauss-Legendre 6pt abscissa x2 = 0.2386191861",
        group="gauss_6pt",
    ),
    EngConstant(
        hex_pattern="bfce8b12d03675c5",
        float_value=-0.2386191860831969,
        decimal_pattern="-0.23862",
        algorithm="gauss_quadrature_6pt",
        category="fea_integration",
        confidence=0.93,
        description="Gauss-Legendre 6pt abscissa -x2",
        group="gauss_6pt",
    ),
    EngConstant(
        hex_pattern="3fddf24d499545e7",
        float_value=0.467913934572691,
        decimal_pattern="0.46791",
        algorithm="gauss_quadrature_6pt",
        category="fea_integration",
        confidence=0.93,
        description="Gauss-Legendre 6pt weight w2 = 0.4679139346",
        group="gauss_6pt",
    ),
    EngConstant(
        hex_pattern="3fedd6ca4e80a01e",
        float_value=0.932469514203152,
        decimal_pattern="0.93247",
        algorithm="gauss_quadrature_6pt",
        category="fea_integration",
        confidence=0.93,
        description="Gauss-Legendre 6pt abscissa x3 = 0.9324695142",
        group="gauss_6pt",
    ),
    EngConstant(
        hex_pattern="bfedd6ca4e80a01e",
        float_value=-0.932469514203152,
        decimal_pattern="-0.93247",
        algorithm="gauss_quadrature_6pt",
        category="fea_integration",
        confidence=0.93,
        description="Gauss-Legendre 6pt abscissa -x3",
        group="gauss_6pt",
    ),
    EngConstant(
        hex_pattern="3fc5edf601e2dbfa",
        float_value=0.1713244923791704,
        decimal_pattern="0.17132",
        algorithm="gauss_quadrature_6pt",
        category="fea_integration",
        confidence=0.93,
        description="Gauss-Legendre 6pt weight w3 = 0.1713244924",
        group="gauss_6pt",
    ),
    # -- gauss_7pt ---------------------------------------------------
    EngConstant(
        hex_pattern="3fdabfd7e03c2fa6",
        float_value=0.4179591836734694,
        decimal_pattern="0.41796",
        algorithm="gauss_quadrature_7pt",
        category="fea_integration",
        confidence=0.93,
        description="Gauss-Legendre 7pt weight w1 = 0.4179591837",
        group="gauss_7pt",
    ),
    EngConstant(
        hex_pattern="3fd9f95df119fd62",
        float_value=0.4058451513773972,
        decimal_pattern="0.40585",
        algorithm="gauss_quadrature_7pt",
        category="fea_integration",
        confidence=0.93,
        description="Gauss-Legendre 7pt abscissa x2 = 0.4058451514",
        group="gauss_7pt",
    ),
    EngConstant(
        hex_pattern="bfd9f95df119fd62",
        float_value=-0.4058451513773972,
        decimal_pattern="-0.40585",
        algorithm="gauss_quadrature_7pt",
        category="fea_integration",
        confidence=0.93,
        description="Gauss-Legendre 7pt abscissa -x2",
        group="gauss_7pt",
    ),
    EngConstant(
        hex_pattern="3fd86fe74ee32b3d",
        float_value=0.3818300505051189,
        decimal_pattern="0.38183",
        algorithm="gauss_quadrature_7pt",
        category="fea_integration",
        confidence=0.93,
        description="Gauss-Legendre 7pt weight w2 = 0.3818300505",
        group="gauss_7pt",
    ),
    EngConstant(
        hex_pattern="3fe7ba9f9be3a1d6",
        float_value=0.7415311855993945,
        decimal_pattern="0.74153",
        algorithm="gauss_quadrature_7pt",
        category="fea_integration",
        confidence=0.93,
        description="Gauss-Legendre 7pt abscissa x3 = 0.7415311856",
        group="gauss_7pt",
    ),
    EngConstant(
        hex_pattern="bfe7ba9f9be3a1d6",
        float_value=-0.7415311855993945,
        decimal_pattern="-0.74153",
        algorithm="gauss_quadrature_7pt",
        category="fea_integration",
        confidence=0.93,
        description="Gauss-Legendre 7pt abscissa -x3",
        group="gauss_7pt",
    ),
    EngConstant(
        hex_pattern="3fd1e6b1713d8643",
        float_value=0.2797053914892766,
        decimal_pattern="0.27971",
        algorithm="gauss_quadrature_7pt",
        category="fea_integration",
        confidence=0.93,
        description="Gauss-Legendre 7pt weight w3 = 0.2797053915",
        group="gauss_7pt",
    ),
    EngConstant(
        hex_pattern="3fee5f178e7c6229",
        float_value=0.9491079123427585,
        decimal_pattern="0.94911",
        algorithm="gauss_quadrature_7pt",
        category="fea_integration",
        confidence=0.93,
        description="Gauss-Legendre 7pt abscissa x4 = 0.9491079123",
        group="gauss_7pt",
    ),
    EngConstant(
        hex_pattern="bfee5f178e7c6229",
        float_value=-0.9491079123427585,
        decimal_pattern="-0.94911",
        algorithm="gauss_quadrature_7pt",
        category="fea_integration",
        confidence=0.93,
        description="Gauss-Legendre 7pt abscissa -x4",
        group="gauss_7pt",
    ),
    EngConstant(
        hex_pattern="3fc092f69f826d57",
        float_value=0.1294849661688697,
        decimal_pattern="0.12948",
        algorithm="gauss_quadrature_7pt",
        category="fea_integration",
        confidence=0.93,
        description="Gauss-Legendre 7pt weight w4 = 0.1294849662",
        group="gauss_7pt",
    ),
    # -- gauss_8pt ---------------------------------------------------
    EngConstant(
        hex_pattern="3fc77ac94f3c7345",
        float_value=0.1834346424956498,
        decimal_pattern="0.18343",
        algorithm="gauss_quadrature_8pt",
        category="fea_integration",
        confidence=0.94,
        description="Gauss-Legendre 8pt abscissa x1 = 0.1834346425",
        group="gauss_8pt",
    ),
    EngConstant(
        hex_pattern="bfc77ac94f3c7345",
        float_value=-0.1834346424956498,
        decimal_pattern="-0.18343",
        algorithm="gauss_quadrature_8pt",
        category="fea_integration",
        confidence=0.94,
        description="Gauss-Legendre 8pt abscissa -x1",
        group="gauss_8pt",
    ),
    EngConstant(
        hex_pattern="3fd736360b199343",
        float_value=0.362683783378362,
        decimal_pattern="0.36268",
        algorithm="gauss_quadrature_8pt",
        category="fea_integration",
        confidence=0.94,
        description="Gauss-Legendre 8pt weight w1 = 0.3626837834",
        group="gauss_8pt",
    ),
    EngConstant(
        hex_pattern="3fe0d129583284b4",
        float_value=0.525532409916329,
        decimal_pattern="0.52553",
        algorithm="gauss_quadrature_8pt",
        category="fea_integration",
        confidence=0.94,
        description="Gauss-Legendre 8pt abscissa x2 = 0.5255324099",
        group="gauss_8pt",
    ),
    EngConstant(
        hex_pattern="bfe0d129583284b4",
        float_value=-0.525532409916329,
        decimal_pattern="-0.52553",
        algorithm="gauss_quadrature_8pt",
        category="fea_integration",
        confidence=0.94,
        description="Gauss-Legendre 8pt abscissa -x2",
        group="gauss_8pt",
    ),
    EngConstant(
        hex_pattern="3fd413c50a255616",
        float_value=0.3137066458778873,
        decimal_pattern="0.31371",
        algorithm="gauss_quadrature_8pt",
        category="fea_integration",
        confidence=0.94,
        description="Gauss-Legendre 8pt weight w2 = 0.3137066459",
        group="gauss_8pt",
    ),
    EngConstant(
        hex_pattern="3fe97e4ab249f41e",
        float_value=0.7966664774136267,
        decimal_pattern="0.79667",
        algorithm="gauss_quadrature_8pt",
        category="fea_integration",
        confidence=0.94,
        description="Gauss-Legendre 8pt abscissa x3 = 0.7966664774",
        group="gauss_8pt",
    ),
    EngConstant(
        hex_pattern="bfe97e4ab249f41e",
        float_value=-0.7966664774136267,
        decimal_pattern="-0.79667",
        algorithm="gauss_quadrature_8pt",
        category="fea_integration",
        confidence=0.94,
        description="Gauss-Legendre 8pt abscissa -x3",
        group="gauss_8pt",
    ),
    EngConstant(
        hex_pattern="3fcc76fb531d2b97",
        float_value=0.2223810344533745,
        decimal_pattern="0.22238",
        algorithm="gauss_quadrature_8pt",
        category="fea_integration",
        confidence=0.94,
        description="Gauss-Legendre 8pt weight w3 = 0.2223810345",
        group="gauss_8pt",
    ),
    EngConstant(
        hex_pattern="3feebab1cb0acc67",
        float_value=0.9602898564975363,
        decimal_pattern="0.96029",
        algorithm="gauss_quadrature_8pt",
        category="fea_integration",
        confidence=0.94,
        description="Gauss-Legendre 8pt abscissa x4 = 0.9602898565",
        group="gauss_8pt",
    ),
    EngConstant(
        hex_pattern="bfeebab1cb0acc67",
        float_value=-0.9602898564975363,
        decimal_pattern="-0.96029",
        algorithm="gauss_quadrature_8pt",
        category="fea_integration",
        confidence=0.94,
        description="Gauss-Legendre 8pt abscissa -x4",
        group="gauss_8pt",
    ),
    EngConstant(
        hex_pattern="3fb9ea1d04ca0377",
        float_value=0.1012285362903763,
        decimal_pattern="0.10123",
        algorithm="gauss_quadrature_8pt",
        category="fea_integration",
        confidence=0.94,
        description="Gauss-Legendre 8pt weight w4 = 0.1012285363",
        group="gauss_8pt",
    ),
    # -- gauss_9pt ---------------------------------------------------
    EngConstant(
        hex_pattern="3fd522a43f65486a",
        float_value=0.3302393550012598,
        decimal_pattern="0.33024",
        algorithm="gauss_quadrature_9pt",
        category="fea_integration",
        confidence=0.94,
        description="Gauss-Legendre 9pt weight w1 = 0.3302393550",
        group="gauss_9pt",
    ),
    EngConstant(
        hex_pattern="3fd4c0916e48aa66",
        float_value=0.3242534234038089,
        decimal_pattern="0.32425",
        algorithm="gauss_quadrature_9pt",
        category="fea_integration",
        confidence=0.94,
        description="Gauss-Legendre 9pt abscissa x2 = 0.3242534234",
        group="gauss_9pt",
    ),
    EngConstant(
        hex_pattern="bfd4c0916e48aa66",
        float_value=-0.3242534234038089,
        decimal_pattern="-0.32425",
        algorithm="gauss_quadrature_9pt",
        category="fea_integration",
        confidence=0.94,
        description="Gauss-Legendre 9pt abscissa -x2",
        group="gauss_9pt",
    ),
    EngConstant(
        hex_pattern="3fd3fd7e9838d513",
        float_value=0.3123470770400029,
        decimal_pattern="0.31235",
        algorithm="gauss_quadrature_9pt",
        category="fea_integration",
        confidence=0.94,
        description="Gauss-Legendre 9pt weight w2 = 0.3123470770",
        group="gauss_9pt",
    ),
    EngConstant(
        hex_pattern="3fe3a0bd2077fd8c",
        float_value=0.6133714327005904,
        decimal_pattern="0.61337",
        algorithm="gauss_quadrature_9pt",
        category="fea_integration",
        confidence=0.94,
        description="Gauss-Legendre 9pt abscissa x3 = 0.6133714327",
        group="gauss_9pt",
    ),
    EngConstant(
        hex_pattern="bfe3a0bd2077fd8c",
        float_value=-0.6133714327005904,
        decimal_pattern="-0.61337",
        algorithm="gauss_quadrature_9pt",
        category="fea_integration",
        confidence=0.94,
        description="Gauss-Legendre 9pt abscissa -x3",
        group="gauss_9pt",
    ),
    EngConstant(
        hex_pattern="3fd0add87c827505",
        float_value=0.2606106964029354,
        decimal_pattern="0.26061",
        algorithm="gauss_quadrature_9pt",
        category="fea_integration",
        confidence=0.94,
        description="Gauss-Legendre 9pt weight w3 = 0.2606106964",
        group="gauss_9pt",
    ),
    EngConstant(
        hex_pattern="3feac0c44f0d0298",
        float_value=0.8360311073266358,
        decimal_pattern="0.83603",
        algorithm="gauss_quadrature_9pt",
        category="fea_integration",
        confidence=0.94,
        description="Gauss-Legendre 9pt abscissa x4 = 0.8360311073",
        group="gauss_9pt",
    ),
    EngConstant(
        hex_pattern="bfeac0c44f0d0298",
        float_value=-0.8360311073266358,
        decimal_pattern="-0.83603",
        algorithm="gauss_quadrature_9pt",
        category="fea_integration",
        confidence=0.94,
        description="Gauss-Legendre 9pt abscissa -x4",
        group="gauss_9pt",
    ),
    EngConstant(
        hex_pattern="3fc71f7a9b222bea",
        float_value=0.1806481606948574,
        decimal_pattern="0.18065",
        algorithm="gauss_quadrature_9pt",
        category="fea_integration",
        confidence=0.94,
        description="Gauss-Legendre 9pt weight w4 = 0.1806481607",
        group="gauss_9pt",
    ),
    EngConstant(
        hex_pattern="3feefb2b2ebf2106",
        float_value=0.9681602395076261,
        decimal_pattern="0.96816",
        algorithm="gauss_quadrature_9pt",
        category="fea_integration",
        confidence=0.94,
        description="Gauss-Legendre 9pt abscissa x5 = 0.9681602395",
        group="gauss_9pt",
    ),
    EngConstant(
        hex_pattern="bfeefb2b2ebf2106",
        float_value=-0.9681602395076261,
        decimal_pattern="-0.96816",
        algorithm="gauss_quadrature_9pt",
        category="fea_integration",
        confidence=0.94,
        description="Gauss-Legendre 9pt abscissa -x5",
        group="gauss_9pt",
    ),
    EngConstant(
        hex_pattern="3fb4ce65f803eef7",
        float_value=0.0812743883615744,
        decimal_pattern="0.08127",
        algorithm="gauss_quadrature_9pt",
        category="fea_integration",
        confidence=0.94,
        description="Gauss-Legendre 9pt weight w5 = 0.0812743884",
        group="gauss_9pt",
    ),
    # -- gauss_10pt --------------------------------------------------
    EngConstant(
        hex_pattern="3fc30e507891e279",
        float_value=0.1488743389816312,
        decimal_pattern="0.14887",
        algorithm="gauss_quadrature_10pt",
        category="fea_integration",
        confidence=0.95,
        description="Gauss-Legendre 10pt abscissa x1 = 0.1488743390",
        group="gauss_10pt",
    ),
    EngConstant(
        hex_pattern="bfc30e507891e279",
        float_value=-0.1488743389816312,
        decimal_pattern="-0.14887",
        algorithm="gauss_quadrature_10pt",
        category="fea_integration",
        confidence=0.95,
        description="Gauss-Legendre 10pt abscissa -x1",
        group="gauss_10pt",
    ),
    EngConstant(
        hex_pattern="3fd2e9de7014d6f0",
        float_value=0.2955242247147529,
        decimal_pattern="0.29552",
        algorithm="gauss_quadrature_10pt",
        category="fea_integration",
        confidence=0.95,
        description="Gauss-Legendre 10pt weight w1 = 0.2955242247",
        group="gauss_10pt",
    ),
    EngConstant(
        hex_pattern="3fdbbcc009016adc",
        float_value=0.4333953941292472,
        decimal_pattern="0.43340",
        algorithm="gauss_quadrature_10pt",
        category="fea_integration",
        confidence=0.95,
        description="Gauss-Legendre 10pt abscissa x2 = 0.4333953941",
        group="gauss_10pt",
    ),
    EngConstant(
        hex_pattern="bfdbbcc009016adc",
        float_value=-0.4333953941292472,
        decimal_pattern="-0.43340",
        algorithm="gauss_quadrature_10pt",
        category="fea_integration",
        confidence=0.95,
        description="Gauss-Legendre 10pt abscissa -x2",
        group="gauss_10pt",
    ),
    EngConstant(
        hex_pattern="3fd13baa7a559bfd",
        float_value=0.2692667193099963,
        decimal_pattern="0.26927",
        algorithm="gauss_quadrature_10pt",
        category="fea_integration",
        confidence=0.95,
        description="Gauss-Legendre 10pt weight w2 = 0.2692667193",
        group="gauss_10pt",
    ),
    EngConstant(
        hex_pattern="3fe5bdb9228de198",
        float_value=0.6794095682990244,
        decimal_pattern="0.67941",
        algorithm="gauss_quadrature_10pt",
        category="fea_integration",
        confidence=0.95,
        description="Gauss-Legendre 10pt abscissa x3 = 0.6794095683",
        group="gauss_10pt",
    ),
    EngConstant(
        hex_pattern="bfe5bdb9228de198",
        float_value=-0.6794095682990244,
        decimal_pattern="-0.67941",
        algorithm="gauss_quadrature_10pt",
        category="fea_integration",
        confidence=0.95,
        description="Gauss-Legendre 10pt abscissa -x3",
        group="gauss_10pt",
    ),
    EngConstant(
        hex_pattern="3fcc0b059d00bc30",
        float_value=0.219086362515982,
        decimal_pattern="0.21909",
        algorithm="gauss_quadrature_10pt",
        category="fea_integration",
        confidence=0.95,
        description="Gauss-Legendre 10pt weight w3 = 0.2190863625",
        group="gauss_10pt",
    ),
    EngConstant(
        hex_pattern="3febae995e9cb2f3",
        float_value=0.8650633666889845,
        decimal_pattern="0.86506",
        algorithm="gauss_quadrature_10pt",
        category="fea_integration",
        confidence=0.95,
        description="Gauss-Legendre 10pt abscissa x4 = 0.8650633667",
        group="gauss_10pt",
    ),
    EngConstant(
        hex_pattern="bfebae995e9cb2f3",
        float_value=-0.8650633666889845,
        decimal_pattern="-0.86506",
        algorithm="gauss_quadrature_10pt",
        category="fea_integration",
        confidence=0.95,
        description="Gauss-Legendre 10pt abscissa -x4",
        group="gauss_10pt",
    ),
    EngConstant(
        hex_pattern="3fc32138c878efe5",
        float_value=0.1494513491505806,
        decimal_pattern="0.14945",
        algorithm="gauss_quadrature_10pt",
        category="fea_integration",
        confidence=0.95,
        description="Gauss-Legendre 10pt weight w4 = 0.1494513492",
        group="gauss_10pt",
    ),
    EngConstant(
        hex_pattern="3fef2a3e062af2d8",
        float_value=0.9739065285171717,
        decimal_pattern="0.97391",
        algorithm="gauss_quadrature_10pt",
        category="fea_integration",
        confidence=0.95,
        description="Gauss-Legendre 10pt abscissa x5 = 0.9739065285",
        group="gauss_10pt",
    ),
    EngConstant(
        hex_pattern="bfef2a3e062af2d8",
        float_value=-0.9739065285171717,
        decimal_pattern="-0.97391",
        algorithm="gauss_quadrature_10pt",
        category="fea_integration",
        confidence=0.95,
        description="Gauss-Legendre 10pt abscissa -x5",
        group="gauss_10pt",
    ),
    EngConstant(
        hex_pattern="3fb1115f8b62dc1c",
        float_value=0.0666713443086881,
        decimal_pattern="0.06667",
        algorithm="gauss_quadrature_10pt",
        category="fea_integration",
        confidence=0.95,
        description="Gauss-Legendre 10pt weight w5 = 0.0666713443",
        group="gauss_10pt",
    ),
    # -- lobatto_3pt -------------------------------------------------
    EngConstant(
        hex_pattern="3ff5555555555555",
        float_value=1.3333333333333333,
        decimal_pattern="1.33333",
        algorithm="gauss_lobatto_3pt",
        category="fea_integration",
        confidence=0.75,
        description="4/3 -- Gauss-Lobatto 3pt weight (center)",
        group="lobatto_3pt",
    ),
    # -- lobatto_4pt -------------------------------------------------
    EngConstant(
        hex_pattern="3fdc9f25c5bfedd9",
        float_value=0.4472135954999579,
        decimal_pattern="0.44721",
        algorithm="gauss_lobatto_4pt",
        category="fea_integration",
        confidence=0.88,
        description="1/sqrt(5) = 0.4472135955 -- Gauss-Lobatto 4pt inner abscissa",
        group="lobatto_4pt",
    ),
    EngConstant(
        hex_pattern="bfdc9f25c5bfedd9",
        float_value=-0.4472135954999579,
        decimal_pattern="-0.44721",
        algorithm="gauss_lobatto_4pt",
        category="fea_integration",
        confidence=0.88,
        description="-1/sqrt(5) -- Gauss-Lobatto 4pt inner abscissa (neg)",
        group="lobatto_4pt",
    ),
    EngConstant(
        hex_pattern="3feaaaaaaaaaaaab",
        float_value=0.8333333333333334,
        decimal_pattern="0.83333",
        algorithm="gauss_lobatto_4pt",
        category="fea_integration",
        confidence=0.8,
        description="5/6 -- Gauss-Lobatto 4pt inner weight",
        group="lobatto_4pt",
    ),
    # -- lobatto_5pt -------------------------------------------------
    EngConstant(
        hex_pattern="3fe4f2ec413cb52a",
        float_value=0.6546536707079771,
        decimal_pattern="0.65465",
        algorithm="gauss_lobatto_5pt",
        category="fea_integration",
        confidence=0.9,
        description="sqrt(3/7) = 0.6546536707 -- Gauss-Lobatto 5pt abscissa",
        group="lobatto_5pt",
    ),
    EngConstant(
        hex_pattern="bfe4f2ec413cb52a",
        float_value=-0.6546536707079771,
        decimal_pattern="-0.65465",
        algorithm="gauss_lobatto_5pt",
        category="fea_integration",
        confidence=0.9,
        description="-sqrt(3/7) -- Gauss-Lobatto 5pt abscissa (neg)",
        group="lobatto_5pt",
    ),
    EngConstant(
        hex_pattern="3fe16c16c16c16c1",
        float_value=0.5444444444444444,
        decimal_pattern="0.54444",
        algorithm="gauss_lobatto_5pt",
        category="fea_integration",
        confidence=0.88,
        description="49/90 = 0.5444444444 -- Gauss-Lobatto 5pt inner weight",
        group="lobatto_5pt",
    ),
    EngConstant(
        hex_pattern="3fe6c16c16c16c17",
        float_value=0.7111111111111111,
        decimal_pattern="0.71111",
        algorithm="gauss_lobatto_5pt",
        category="fea_integration",
        confidence=0.82,
        description="32/45 = 0.7111111111 -- Gauss-Lobatto 5pt center weight",
        group="lobatto_5pt",
    ),
    EngConstant(
        hex_pattern="3fb999999999999a",
        float_value=0.1,
        decimal_pattern="0.10000",
        algorithm="gauss_lobatto_5pt",
        category="fea_integration",
        confidence=0.0,  # GROUP-ONLY: too common for standalone detection
        description="1/10 -- Gauss-Lobatto 5pt endpoint weight",
        group="lobatto_5pt",
    ),
    # -- lobatto_6pt -------------------------------------------------
    EngConstant(
        hex_pattern="3fd2413bb0c4a9aa",
        float_value=0.28523151648064504,
        decimal_pattern="0.28523",
        algorithm="gauss_lobatto_6pt",
        category="fea_integration",
        confidence=0.9,
        description="Gauss-Lobatto 6pt inner abscissa = 0.2852315165",
        group="lobatto_6pt",
    ),
    EngConstant(
        hex_pattern="3fe87b554d7d0c2f",
        float_value=0.7650553239294647,
        decimal_pattern="0.76506",
        algorithm="gauss_lobatto_6pt",
        category="fea_integration",
        confidence=0.9,
        description="Gauss-Lobatto 6pt outer abscissa = 0.7650553239",
        group="lobatto_6pt",
    ),
    EngConstant(
        hex_pattern="bfd2413bb0c4a9aa",
        float_value=-0.28523151648064504,
        decimal_pattern="-0.28523",
        algorithm="gauss_lobatto_6pt",
        category="fea_integration",
        confidence=0.9,
        description="Gauss-Lobatto 6pt inner abscissa (neg)",
        group="lobatto_6pt",
    ),
    EngConstant(
        hex_pattern="bfe87b554d7d0c2f",
        float_value=-0.7650553239294647,
        decimal_pattern="-0.76506",
        algorithm="gauss_lobatto_6pt",
        category="fea_integration",
        confidence=0.9,
        description="Gauss-Lobatto 6pt outer abscissa (neg)",
        group="lobatto_6pt",
    ),
    EngConstant(
        hex_pattern="3fe1c1665ae8edfd",
        float_value=0.5548583770354863,
        decimal_pattern="0.55486",
        algorithm="gauss_lobatto_6pt",
        category="fea_integration",
        confidence=0.9,
        description="Gauss-Lobatto 6pt inner weight = 0.5548583770",
        group="lobatto_6pt",
    ),
    EngConstant(
        hex_pattern="3fd838ef05e9dfc2",
        float_value=0.378474956297847,
        decimal_pattern="0.37847",
        algorithm="gauss_lobatto_6pt",
        category="fea_integration",
        confidence=0.9,
        description="Gauss-Lobatto 6pt outer weight = 0.3784749563",
        group="lobatto_6pt",
    ),
    EngConstant(
        hex_pattern="3fb1111111111111",
        float_value=0.06666666666666667,
        decimal_pattern="0.06667",
        algorithm="gauss_lobatto_6pt",
        category="fea_integration",
        confidence=0.55,
        description="1/15 -- Gauss-Lobatto 6pt endpoint weight",
        group="lobatto_6pt",
    ),
    # -- lobatto_7pt -------------------------------------------------
    EngConstant(
        hex_pattern="3fde019e5eae731c",
        float_value=0.4688487934707142,
        decimal_pattern="0.46885",
        algorithm="gauss_lobatto_7pt",
        category="fea_integration",
        confidence=0.9,
        description="Gauss-Lobatto 7pt abscissa x1 = 0.4688487935",
        group="lobatto_7pt",
    ),
    EngConstant(
        hex_pattern="bfde019e5eae731c",
        float_value=-0.4688487934707142,
        decimal_pattern="-0.46885",
        algorithm="gauss_lobatto_7pt",
        category="fea_integration",
        confidence=0.9,
        description="Gauss-Lobatto 7pt abscissa -x1",
        group="lobatto_7pt",
    ),
    EngConstant(
        hex_pattern="3fdb9bf9427d6168",
        float_value=0.4313948773683678,
        decimal_pattern="0.43139",
        algorithm="gauss_lobatto_7pt",
        category="fea_integration",
        confidence=0.9,
        description="Gauss-Lobatto 7pt weight w1 = 0.4313948774",
        group="lobatto_7pt",
    ),
    EngConstant(
        hex_pattern="3fea9131b45bf8f7",
        float_value=0.830223896278567,
        decimal_pattern="0.83022",
        algorithm="gauss_lobatto_7pt",
        category="fea_integration",
        confidence=0.9,
        description="Gauss-Lobatto 7pt abscissa x2 = 0.8302238963",
        group="lobatto_7pt",
    ),
    EngConstant(
        hex_pattern="bfea9131b45bf8f7",
        float_value=-0.830223896278567,
        decimal_pattern="-0.83022",
        algorithm="gauss_lobatto_7pt",
        category="fea_integration",
        confidence=0.9,
        description="Gauss-Lobatto 7pt abscissa -x2",
        group="lobatto_7pt",
    ),
    EngConstant(
        hex_pattern="3fd1b784990653ee",
        float_value=0.2768260473615659,
        decimal_pattern="0.27683",
        algorithm="gauss_lobatto_7pt",
        category="fea_integration",
        confidence=0.9,
        description="Gauss-Lobatto 7pt weight w2 = 0.2768260474",
        group="lobatto_7pt",
    ),
    EngConstant(
        hex_pattern="3fdf3526859b8cec",
        float_value=0.4876190476190476,
        decimal_pattern="0.48762",
        algorithm="gauss_lobatto_7pt",
        category="fea_integration",
        confidence=0.85,
        description="256/525 = 0.4876190476 -- Gauss-Lobatto 7pt center weight",
        group="lobatto_7pt",
    ),
    EngConstant(
        hex_pattern="3fa8618618618618",
        float_value=0.047619047619047616,
        decimal_pattern="0.04762",
        algorithm="gauss_lobatto_7pt",
        category="fea_integration",
        confidence=0.55,
        description="1/21 -- Gauss-Lobatto 7pt endpoint weight",
        group="lobatto_7pt",
    ),
    # -- gauss_hermite_2pt -------------------------------------------
    EngConstant(
        hex_pattern="3fec5bf891b4ef6a",
        float_value=0.8862269254527579,
        decimal_pattern="0.88623",
        algorithm="gauss_hermite_2pt",
        category="fea_integration",
        confidence=0.85,
        description="sqrt(pi)/2 = 0.8862269255 -- Gauss-Hermite 2pt weight",
        group="gauss_hermite_2pt",
    ),
    # -- gauss_hermite_3pt -------------------------------------------
    EngConstant(
        hex_pattern="3ff3988e1409212e",
        float_value=1.224744871391589,
        decimal_pattern="1.22474",
        algorithm="gauss_hermite_3pt",
        category="fea_integration",
        confidence=0.88,
        description="sqrt(3/2) = 1.2247448714 -- Gauss-Hermite 3pt abscissa",
        group="gauss_hermite_3pt",
    ),
    EngConstant(
        hex_pattern="3fd2e7fb0bcdf4f1",
        float_value=0.2954089751509193,
        decimal_pattern="0.29541",
        algorithm="gauss_hermite_3pt",
        category="fea_integration",
        confidence=0.85,
        description="sqrt(pi)/6 = 0.2954089752 -- Gauss-Hermite 3pt outer weight",
        group="gauss_hermite_3pt",
    ),
    EngConstant(
        hex_pattern="3ff2e7fb0bcdf4f1",
        float_value=1.1816359006036772,
        decimal_pattern="1.18164",
        algorithm="gauss_hermite_3pt",
        category="fea_integration",
        confidence=0.82,
        description="2*sqrt(pi)/3 = 1.1816359006 -- Gauss-Hermite 3pt center weight",
        group="gauss_hermite_3pt",
    ),
    # -- gauss_hermite_4pt -------------------------------------------
    EngConstant(
        hex_pattern="3fe0c9e9cffc872c",
        float_value=0.5246476232752904,
        decimal_pattern="0.52465",
        algorithm="gauss_hermite_4pt",
        category="fea_integration",
        confidence=0.88,
        description="Gauss-Hermite 4pt abscissa x1 = 0.5246476233",
        group="gauss_hermite_4pt",
    ),
    EngConstant(
        hex_pattern="3fe9c1db31953993",
        float_value=0.8049140900055128,
        decimal_pattern="0.80491",
        algorithm="gauss_hermite_4pt",
        category="fea_integration",
        confidence=0.88,
        description="Gauss-Hermite 4pt weight w1 = 0.8049140900",
        group="gauss_hermite_4pt",
    ),
    EngConstant(
        hex_pattern="3ffa692f8fc3f25f",
        float_value=1.6506801238857844,
        decimal_pattern="1.65068",
        algorithm="gauss_hermite_4pt",
        category="fea_integration",
        confidence=0.88,
        description="Gauss-Hermite 4pt abscissa x2 = 1.6506801239",
        group="gauss_hermite_4pt",
    ),
    EngConstant(
        hex_pattern="3fb4d0eb00fdaebe",
        float_value=0.08131283544724519,
        decimal_pattern="0.08131",
        algorithm="gauss_hermite_4pt",
        category="fea_integration",
        confidence=0.88,
        description="Gauss-Hermite 4pt weight w2 = 0.0813128354",
        group="gauss_hermite_4pt",
    ),
    # -- gauss_laguerre_2pt ------------------------------------------
    EngConstant(
        hex_pattern="3fe2bec333018866",
        float_value=0.5857864376269049,
        decimal_pattern="0.58579",
        algorithm="gauss_laguerre_2pt",
        category="fea_integration",
        confidence=0.88,
        description="Gauss-Laguerre 2pt abscissa x1 = 0.5857864376",
        group="gauss_laguerre_2pt",
    ),
    EngConstant(
        hex_pattern="3feb504f333f9de6",
        float_value=0.8535533905932737,
        decimal_pattern="0.85355",
        algorithm="gauss_laguerre_2pt",
        category="fea_integration",
        confidence=0.88,
        description="Gauss-Laguerre 2pt weight w1 = 0.8535533906",
        group="gauss_laguerre_2pt",
    ),
    EngConstant(
        hex_pattern="400b504f333f9de6",
        float_value=3.414213562373095,
        decimal_pattern="3.41421",
        algorithm="gauss_laguerre_2pt",
        category="fea_integration",
        confidence=0.88,
        description="Gauss-Laguerre 2pt abscissa x2 = 3.4142135624",
        group="gauss_laguerre_2pt",
    ),
    EngConstant(
        hex_pattern="3fc2bec333018866",
        float_value=0.1464466094067262,
        decimal_pattern="0.14645",
        algorithm="gauss_laguerre_2pt",
        category="fea_integration",
        confidence=0.88,
        description="Gauss-Laguerre 2pt weight w2 = 0.1464466094",
        group="gauss_laguerre_2pt",
    ),
    # -- gauss_laguerre_3pt ------------------------------------------
    EngConstant(
        hex_pattern="3fda9c0ce2f93646",
        float_value=0.4157745567834791,
        decimal_pattern="0.41577",
        algorithm="gauss_laguerre_3pt",
        category="fea_integration",
        confidence=0.88,
        description="Gauss-Laguerre 3pt abscissa x1 = 0.4157745568",
        group="gauss_laguerre_3pt",
    ),
    EngConstant(
        hex_pattern="3fe6c14620c1eb88",
        float_value=0.711093009929173,
        decimal_pattern="0.71109",
        algorithm="gauss_laguerre_3pt",
        category="fea_integration",
        confidence=0.88,
        description="Gauss-Laguerre 3pt weight w1 = 0.7110930099",
        group="gauss_laguerre_3pt",
    ),
    EngConstant(
        hex_pattern="40025aafa95a0756",
        float_value=2.294280360279042,
        decimal_pattern="2.29428",
        algorithm="gauss_laguerre_3pt",
        category="fea_integration",
        confidence=0.88,
        description="Gauss-Laguerre 3pt abscissa x2 = 2.2942803603",
        group="gauss_laguerre_3pt",
    ),
    EngConstant(
        hex_pattern="3fd1d33c0b424cb0",
        float_value=0.2785177335692408,
        decimal_pattern="0.27852",
        algorithm="gauss_laguerre_3pt",
        category="fea_integration",
        confidence=0.88,
        description="Gauss-Laguerre 3pt weight w2 = 0.2785177336",
        group="gauss_laguerre_3pt",
    ),
    EngConstant(
        hex_pattern="401928e75d2368f1",
        float_value=6.2899450829374794,
        decimal_pattern="6.28995",
        algorithm="gauss_laguerre_3pt",
        category="fea_integration",
        confidence=0.88,
        description="Gauss-Laguerre 3pt abscissa x3 = 6.2899450829",
        group="gauss_laguerre_3pt",
    ),
    EngConstant(
        hex_pattern="3f8546f6673b87d5",
        float_value=0.0103892565015861,
        decimal_pattern="0.01039",
        algorithm="gauss_laguerre_3pt",
        category="fea_integration",
        confidence=0.88,
        description="Gauss-Laguerre 3pt weight w3 = 0.0103892565",
        group="gauss_laguerre_3pt",
    ),
    # -- physics_em --------------------------------------------------
    EngConstant(
        hex_pattern="41b1de784a000000",
        float_value=299792458.0,
        decimal_pattern="2.99792e+08",
        algorithm="speed_of_light",
        category="physics_constant",
        confidence=0.9,
        description="c = 299792458.0 m/s -- speed of light in vacuum",
        group="physics_em",
    ),
    # -- physics_quantum ---------------------------------------------
    EngConstant(
        hex_pattern="390b860bde023111",
        float_value=6.62607015e-34,
        decimal_pattern="6.62607e-34",
        algorithm="planck_constant",
        category="physics_constant",
        confidence=0.95,
        description="h = 6.62607015e-34 J*s -- Planck constant",
        group="physics_quantum",
    ),
    # -- physics_chemistry -------------------------------------------
    EngConstant(
        hex_pattern="44dfe185ca57c517",
        float_value=6.02214076e+23,
        decimal_pattern="6.02214e+23",
        algorithm="avogadro",
        category="physics_constant",
        confidence=0.93,
        description="N_A = 6.02214076e+23 1/mol -- Avogadro number",
        group="physics_chemistry",
    ),
    # -- physics_em --------------------------------------------------
    EngConstant(
        hex_pattern="3c07a4da290c1653",
        float_value=1.602176634e-19,
        decimal_pattern="1.60217e-19",
        algorithm="elementary_charge",
        category="physics_constant",
        confidence=0.94,
        description="e = 1.602176634e-19 C -- elementary charge",
        group="physics_em",
    ),
    # -- physics_gravity ---------------------------------------------
    EngConstant(
        hex_pattern="3dd2589effed8acc",
        float_value=6.6743e-11,
        decimal_pattern="6.67430e-11",
        algorithm="gravitational_constant",
        category="physics_constant",
        confidence=0.92,
        description="G = 6.6743e-11 m^3/(kg*s^2) -- gravitational constant (CODATA 2018)",
        group="physics_gravity",
    ),
    # -- physics_thermo ----------------------------------------------
    EngConstant(
        hex_pattern="4020a1013e883fc4",
        float_value=8.314462618,
        decimal_pattern="8.31446",
        algorithm="gas_constant",
        category="physics_constant",
        confidence=0.88,
        description="R = 8.314462618 J/(mol*K) -- molar gas constant",
        group="physics_thermo",
    ),
    # -- physics_em --------------------------------------------------
    EngConstant(
        hex_pattern="3da37876f1206634",
        float_value=8.8541878128e-12,
        decimal_pattern="8.85418e-12",
        algorithm="vacuum_permittivity",
        category="physics_constant",
        confidence=0.93,
        description="epsilon_0 = 8.8541878128e-12 F/m -- vacuum permittivity",
        group="physics_em",
    ),
    EngConstant(
        hex_pattern="3eb515370fcb41e4",
        float_value=1.25663706212e-06,
        decimal_pattern="1.25663e-06",
        algorithm="vacuum_permeability",
        category="physics_constant",
        confidence=0.93,
        description="mu_0 = 1.25663706212e-06 H/m -- vacuum permeability",
        group="physics_em",
    ),
    # -- physics_quantum ---------------------------------------------
    EngConstant(
        hex_pattern="39b279dcc8b6b7ed",
        float_value=9.1093837015e-31,
        decimal_pattern="9.10938e-31",
        algorithm="electron_mass",
        category="physics_constant",
        confidence=0.94,
        description="m_e = 9.1093837015e-31 kg -- electron mass",
        group="physics_quantum",
    ),
    EngConstant(
        hex_pattern="3a609099b1eaa2c5",
        float_value=1.67262192369e-27,
        decimal_pattern="1.67262e-27",
        algorithm="proton_mass",
        category="physics_constant",
        confidence=0.94,
        description="m_p = 1.67262192369e-27 kg -- proton mass",
        group="physics_quantum",
    ),
    EngConstant(
        hex_pattern="3f7de3d42a1ed29d",
        float_value=0.0072973525693,
        decimal_pattern="0.00729",
        algorithm="fine_structure_constant",
        category="physics_constant",
        confidence=0.93,
        description="alpha = 0.0072973525693 -- fine structure constant",
        group="physics_quantum",
    ),
    EngConstant(
        hex_pattern="4164ee44722e5de1",
        float_value=10973731.56816,
        decimal_pattern="1.09737e+07",
        algorithm="rydberg_constant",
        category="physics_constant",
        confidence=0.94,
        description="R_inf = 10973731.56816 1/m -- Rydberg constant",
        group="physics_quantum",
    ),
    EngConstant(
        hex_pattern="3dcd1781d4f556a3",
        float_value=5.29177210903e-11,
        decimal_pattern="5.29177e-11",
        algorithm="bohr_radius",
        category="physics_constant",
        confidence=0.94,
        description="a_0 = 5.29177210903e-11 m -- Bohr radius",
        group="physics_quantum",
    ),
    # -- math_pi_fractions -------------------------------------------
    EngConstant(
        hex_pattern="3ff921fb54442d18",
        float_value=1.5707963267948966,
        decimal_pattern="1.57079",
        algorithm="trigonometric",
        category="math_constant",
        confidence=0.25,
        description="pi/2 = 1.5707963268",
        group="math_pi_fractions",
    ),
    EngConstant(
        hex_pattern="3ff0c152382d7365",
        float_value=1.0471975511965976,
        decimal_pattern="1.04719",
        algorithm="trigonometric",
        category="math_constant",
        confidence=0.3,
        description="pi/3 = 1.0471975512",
        group="math_pi_fractions",
    ),
    EngConstant(
        hex_pattern="3fe921fb54442d18",
        float_value=0.7853981633974483,
        decimal_pattern="0.78539",
        algorithm="trigonometric",
        category="math_constant",
        confidence=0.25,
        description="pi/4 = 0.7853981634",
        group="math_pi_fractions",
    ),
    EngConstant(
        hex_pattern="3fe0c152382d7365",
        float_value=0.5235987755982988,
        decimal_pattern="0.52359",
        algorithm="trigonometric",
        category="math_constant",
        confidence=0.3,
        description="pi/6 = 0.5235987756",
        group="math_pi_fractions",
    ),
    EngConstant(
        hex_pattern="401921fb54442d18",
        float_value=6.283185307179586,
        decimal_pattern="6.28318",
        algorithm="trigonometric",
        category="math_constant",
        confidence=0.2,
        description="2*pi = 6.2831853072 -- full circle",
        group="math_pi_fractions",
    ),
    EngConstant(
        hex_pattern="402921fb54442d18",
        float_value=12.566370614359172,
        decimal_pattern="12.5663",
        algorithm="trigonometric",
        category="math_constant",
        confidence=0.35,
        description="4*pi = 12.5663706144 -- solid angle, sphere surface",
        group="math_pi_fractions",
    ),
    EngConstant(
        hex_pattern="3fd45f306dc9c883",
        float_value=0.3183098861837907,
        decimal_pattern="0.31830",
        algorithm="trigonometric",
        category="math_constant",
        confidence=0.4,
        description="1/pi = 0.3183098862",
        group="math_pi_fractions",
    ),
    EngConstant(
        hex_pattern="3fe45f306dc9c883",
        float_value=0.6366197723675814,
        decimal_pattern="0.63661",
        algorithm="trigonometric",
        category="math_constant",
        confidence=0.45,
        description="2/pi = 0.6366197724 -- Dirichlet kernel",
        group="math_pi_fractions",
    ),
    # -- math_universal ----------------------------------------------
    EngConstant(
        hex_pattern="3ffbb67ae8584caa",
        float_value=1.7320508075688772,
        decimal_pattern="1.73205",
        algorithm="sqrt_operation",
        category="math_constant",
        confidence=0.25,
        description="sqrt(3) = 1.7320508076",
        group="math_universal",
    ),
    EngConstant(
        hex_pattern="4001e3779b97f4a8",
        float_value=2.23606797749979,
        decimal_pattern="2.23606",
        algorithm="sqrt_operation",
        category="math_constant",
        confidence=0.3,
        description="sqrt(5) = 2.2360679775",
        group="math_universal",
    ),
    EngConstant(
        hex_pattern="40026bb1bbb55516",
        float_value=2.302585092994046,
        decimal_pattern="2.30258",
        algorithm="logarithmic",
        category="math_constant",
        confidence=0.35,
        description="ln(10) = 2.3025850930",
        group="math_universal",
    ),
    # -- math_log_conversions ----------------------------------------
    EngConstant(
        hex_pattern="3ff71547652b82fe",
        float_value=1.4426950408889634,
        decimal_pattern="1.44269",
        algorithm="logarithmic",
        category="math_constant",
        confidence=0.5,
        description="log2(e) = 1.4426950409 -- log base conversion",
        group="math_log_conversions",
    ),
    EngConstant(
        hex_pattern="400a934f0979a371",
        float_value=3.321928094887362,
        decimal_pattern="3.32192",
        algorithm="logarithmic",
        category="math_constant",
        confidence=0.5,
        description="log2(10) = 3.3219280949",
        group="math_log_conversions",
    ),
    EngConstant(
        hex_pattern="3fd34413509f79ff",
        float_value=0.3010299956639812,
        decimal_pattern="0.30102",
        algorithm="logarithmic",
        category="math_constant",
        confidence=0.5,
        description="log10(2) = 0.3010299957",
        group="math_log_conversions",
    ),
    EngConstant(
        hex_pattern="3fdbcb7b1526e50e",
        float_value=0.4342944819032518,
        decimal_pattern="0.43429",
        algorithm="logarithmic",
        category="math_constant",
        confidence=0.45,
        description="log10(e) = 0.4342944819",
        group="math_log_conversions",
    ),
    # -- special_constants -------------------------------------------
    EngConstant(
        hex_pattern="3fed4f9713e8135d",
        float_value=0.915965594177219,
        decimal_pattern="0.91596",
        algorithm="catalan_constant",
        category="math_constant",
        confidence=0.88,
        description="Catalan's constant = 0.9159655942",
        group="special_constants",
    ),
    EngConstant(
        hex_pattern="3ff33ba004f00621",
        float_value=1.2020569031595942,
        decimal_pattern="1.20205",
        algorithm="apery_constant",
        category="math_constant",
        confidence=0.88,
        description="Apery's constant zeta(3) = 1.2020569032",
        group="special_constants",
    ),
    EngConstant(
        hex_pattern="3fe5200bac242b40",
        float_value=0.6601618158468696,
        decimal_pattern="0.66016",
        algorithm="twin_prime_constant",
        category="math_constant",
        confidence=0.9,
        description="Twin prime constant = 0.6601618158",
        group="special_constants",
    ),
    # -- fea_penalty -------------------------------------------------
    EngConstant(
        hex_pattern="412e848000000000",
        float_value=1000000.0,
        decimal_pattern="1e+06",
        algorithm="penalty_method",
        category="fea_contact",
        confidence=0.4,
        description="1e6 -- typical penalty parameter for contact (lower bound)",
        group="fea_penalty",
    ),
    EngConstant(
        hex_pattern="41cdcd6500000000",
        float_value=1000000000.0,
        decimal_pattern="1e+09",
        algorithm="penalty_method",
        category="fea_contact",
        confidence=0.45,
        description="1e9 -- typical penalty parameter for contact (upper bound)",
        group="fea_penalty",
    ),
    # -- fea_hourglass -----------------------------------------------
    EngConstant(
        hex_pattern="3fa999999999999a",
        float_value=0.05,
        decimal_pattern="0.05",
        algorithm="hourglass_control",
        category="fea_stabilization",
        confidence=0.5,
        description="0.05 -- typical hourglass stiffness coefficient",
        group="fea_hourglass",
    ),
    # -- rng_k_epsilon -----------------------------------------------
    EngConstant(
        hex_pattern="3fb5a1cac083126f",
        float_value=0.0845,
        decimal_pattern="0.0845",
        algorithm="rng_k_epsilon",
        category="cfd_turbulence",
        confidence=0.92,
        description="C_mu = 0.0845 -- RNG k-epsilon eddy viscosity coefficient",
        group="rng_k_epsilon",
    ),
    EngConstant(
        hex_pattern="3ff6b851eb851eb8",
        float_value=1.42,
        decimal_pattern="1.42",
        algorithm="rng_k_epsilon",
        category="cfd_turbulence",
        confidence=0.88,
        description="C1 = 1.42 -- RNG k-epsilon production coefficient",
        group="rng_k_epsilon",
    ),
    EngConstant(
        hex_pattern="3ffae147ae147ae1",
        float_value=1.68,
        decimal_pattern="1.68",
        algorithm="rng_k_epsilon",
        category="cfd_turbulence",
        confidence=0.9,
        description="C2 = 1.68 -- RNG k-epsilon dissipation coefficient",
        group="rng_k_epsilon",
    ),
    EngConstant(
        hex_pattern="4011851eb851eb85",
        float_value=4.38,
        decimal_pattern="4.38",
        algorithm="rng_k_epsilon",
        category="cfd_turbulence",
        confidence=0.93,
        description="eta_0 = 4.38 -- RNG k-epsilon strain rate parameter",
        group="rng_k_epsilon",
    ),
    EngConstant(
        hex_pattern="3f889374bc6a7efa",
        float_value=0.012,
        decimal_pattern="0.012",
        algorithm="rng_k_epsilon",
        category="cfd_turbulence",
        confidence=0.9,
        description="beta = 0.012 -- RNG k-epsilon beta parameter",
        group="rng_k_epsilon",
    ),
    # -- realizable_k_epsilon ----------------------------------------
    EngConstant(
        hex_pattern="3ffe666666666666",
        float_value=1.9,
        decimal_pattern="1.9",
        algorithm="realizable_k_epsilon",
        category="cfd_turbulence",
        confidence=0.82,
        description="C2 = 1.9 -- Realizable k-epsilon dissipation coefficient",
        group="realizable_k_epsilon",
    ),
    # -- rsm ---------------------------------------------------------
    EngConstant(
        hex_pattern="3fcc28f5c28f5c29",
        float_value=0.22,
        decimal_pattern="0.22",
        algorithm="rsm",
        category="cfd_turbulence",
        confidence=0.9,
        description="Cs = 0.22 -- RSM slow pressure-strain coefficient",
        group="rsm",
    ),
    EngConstant(
        hex_pattern="3ffccccccccccccd",
        float_value=1.8,
        decimal_pattern="1.8",
        algorithm="rsm",
        category="cfd_turbulence",
        confidence=0.82,
        description="C1 = 1.8 -- RSM pressure-strain return-to-isotropy",
        group="rsm",
    ),
    EngConstant(
        hex_pattern="3fe3333333333333",
        float_value=0.6,
        decimal_pattern="0.6",
        algorithm="rsm",
        category="cfd_turbulence",
        confidence=0.0,  # GROUP-ONLY: too common for standalone detection
        description="C2 = 0.6 -- RSM rapid pressure-strain coefficient",
        group="rsm",
    ),
    EngConstant(
        hex_pattern="3fe0000000000000",
        float_value=0.5,
        decimal_pattern="0.5",
        algorithm="rsm",
        category="cfd_turbulence",
        confidence=0.0,  # GROUP-ONLY: too common for standalone detection
        description="C1' = 0.5 -- RSM wall reflection coefficient 1",
        group="rsm",
    ),
    # -- les_smagorinsky ---------------------------------------------
    EngConstant(
        hex_pattern="3fc5c28f5c28f5c3",
        float_value=0.17,
        decimal_pattern="0.17",
        algorithm="les_smagorinsky",
        category="cfd_turbulence",
        confidence=0.7,
        description="Cs = 0.17 -- Smagorinsky constant (isotropic turbulence)",
        group="les_smagorinsky",
    ),
    EngConstant(
        hex_pattern="3fc999999999999a",
        float_value=0.2,
        decimal_pattern="0.2",
        algorithm="les_smagorinsky",
        category="cfd_turbulence",
        confidence=0.0,  # GROUP-ONLY: too common for standalone detection
        description="Cs = 0.2 -- Smagorinsky constant (free shear)",
        group="les_smagorinsky",
    ),
    EngConstant(
        hex_pattern="3fc70a3d70a3d70a",
        float_value=0.18,
        decimal_pattern="0.18",
        algorithm="les_smagorinsky",
        category="cfd_turbulence",
        confidence=0.72,
        description="Cs = 0.18 -- Smagorinsky constant (Lilly theoretical)",
        group="les_smagorinsky",
    ),
    # -- des ---------------------------------------------------------
    EngConstant(
        hex_pattern="3fe4cccccccccccd",
        float_value=0.65,
        decimal_pattern="0.65",
        algorithm="des",
        category="cfd_turbulence",
        confidence=0.88,
        description="C_DES = 0.65 -- Detached Eddy Simulation constant",
        group="des",
    ),
    # -- wall_function -----------------------------------------------
    EngConstant(
        hex_pattern="3fd999999999999a",
        float_value=0.4,
        decimal_pattern="0.4",
        algorithm="wall_function",
        category="cfd_turbulence",
        confidence=0.0,  # GROUP-ONLY: too common for standalone detection
        description="kappa = 0.4 -- von Karman constant (alternative)",
        group="wall_function",
    ),
    EngConstant(
        hex_pattern="40239604189374bc",
        float_value=9.793,
        decimal_pattern="9.793",
        algorithm="wall_function",
        category="cfd_turbulence",
        confidence=0.85,
        description="E = 9.793 -- smooth wall roughness parameter (log law)",
        group="wall_function",
    ),
    # -- chemistry_electrochemistry ----------------------------------
    EngConstant(
        hex_pattern="40f78e55505d0fa6",
        float_value=96485.33212,
        decimal_pattern="96485.3",
        algorithm="faraday_constant",
        category="chemistry_constant",
        confidence=0.94,
        description="F = 96485.33212 C/mol -- Faraday constant",
        group="chemistry_electrochemistry",
    ),
    # -- chemistry_standard ------------------------------------------
    EngConstant(
        hex_pattern="40f8bcd000000000",
        float_value=101325.0,
        decimal_pattern="101325",
        algorithm="standard_atmosphere",
        category="chemistry_constant",
        confidence=0.8,
        description="101325 Pa -- standard atmosphere pressure",
        group="chemistry_standard",
    ),
    # -- water_25C ---------------------------------------------------
    EngConstant(
        hex_pattern="408f280000000000",
        float_value=997.0,
        decimal_pattern="997.0",
        algorithm="water_properties",
        category="chemistry_constant",
        confidence=0.55,
        description="997 kg/m^3 -- water density at 25 deg C",
        group="water_25C",
    ),
    EngConstant(
        hex_pattern="3f4d29dc725c3dee",
        float_value=0.00089,
        decimal_pattern="8.9e-04",
        algorithm="water_properties",
        category="chemistry_constant",
        confidence=0.7,
        description="8.9e-4 Pa*s -- water dynamic viscosity at 25 deg C",
        group="water_25C",
    ),
    EngConstant(
        hex_pattern="40b0560000000000",
        float_value=4182.0,
        decimal_pattern="4182.0",
        algorithm="water_properties",
        category="chemistry_constant",
        confidence=0.65,
        description="4182 J/(kg*K) -- water specific heat at 25 deg C",
        group="water_25C",
    ),
    EngConstant(
        hex_pattern="3fe36872b020c49c",
        float_value=0.6065,
        decimal_pattern="0.6065",
        algorithm="water_properties",
        category="chemistry_constant",
        confidence=0.72,
        description="0.6065 W/(m*K) -- water thermal conductivity at 25 deg C",
        group="water_25C",
    ),
    # -- blackman_exact_window ---------------------------------------
    EngConstant(
        hex_pattern="3fdb4d4024b33db0",
        float_value=0.42659,
        decimal_pattern="0.42659",
        algorithm="blackman_exact_window",
        category="dsp_windowing",
        confidence=0.9,
        description="a0 = 0.42659 -- Exact Blackman window coefficient",
        group="blackman_exact_window",
    ),
    EngConstant(
        hex_pattern="3fdfc7a398201cd6",
        float_value=0.49656,
        decimal_pattern="0.49656",
        algorithm="blackman_exact_window",
        category="dsp_windowing",
        confidence=0.9,
        description="a1 = 0.49656 -- Exact Blackman window coefficient",
        group="blackman_exact_window",
    ),
    EngConstant(
        hex_pattern="3fb3ac710cb295ea",
        float_value=0.07685,
        decimal_pattern="0.07685",
        algorithm="blackman_exact_window",
        category="dsp_windowing",
        confidence=0.92,
        description="a2 = 0.07685 -- Exact Blackman window coefficient (distinctive)",
        group="blackman_exact_window",
    ),
    # -- blackman_harris_window --------------------------------------
    EngConstant(
        hex_pattern="3fd6f5c28f5c28f6",
        float_value=0.35875,
        decimal_pattern="0.35875",
        algorithm="blackman_harris_window",
        category="dsp_windowing",
        confidence=0.92,
        description="a0 = 0.35875 -- Blackman-Harris 4-term window",
        group="blackman_harris_window",
    ),
    EngConstant(
        hex_pattern="3fdf4024b33daf8e",
        float_value=0.48829,
        decimal_pattern="0.48829",
        algorithm="blackman_harris_window",
        category="dsp_windowing",
        confidence=0.92,
        description="a1 = 0.48829 -- Blackman-Harris 4-term window",
        group="blackman_harris_window",
    ),
    EngConstant(
        hex_pattern="3fc2157689ca18bd",
        float_value=0.14128,
        decimal_pattern="0.14128",
        algorithm="blackman_harris_window",
        category="dsp_windowing",
        confidence=0.92,
        description="a2 = 0.14128 -- Blackman-Harris 4-term window",
        group="blackman_harris_window",
    ),
    EngConstant(
        hex_pattern="3f87ebaf102363b2",
        float_value=0.01168,
        decimal_pattern="0.01168",
        algorithm="blackman_harris_window",
        category="dsp_windowing",
        confidence=0.94,
        description="a3 = 0.01168 -- Blackman-Harris 4-term window (highly distinctive)",
        group="blackman_harris_window",
    ),
    # -- flattop_window ----------------------------------------------
    EngConstant(
        hex_pattern="3fcb98174dfa5ed6",
        float_value=0.21557895,
        decimal_pattern="0.21557",
        algorithm="flattop_window",
        category="dsp_windowing",
        confidence=0.93,
        description="a0 = 0.21557895 -- Flat-top window (ISO 18431-2)",
        group="flattop_window",
    ),
    EngConstant(
        hex_pattern="3fdaaa1780a52bf4",
        float_value=0.41663158,
        decimal_pattern="0.41663",
        algorithm="flattop_window",
        category="dsp_windowing",
        confidence=0.93,
        description="a1 = 0.41663158 -- Flat-top window",
        group="flattop_window",
    ),
    EngConstant(
        hex_pattern="3fd1beadf8ffb93c",
        float_value=0.277263158,
        decimal_pattern="0.27726",
        algorithm="flattop_window",
        category="dsp_windowing",
        confidence=0.93,
        description="a2 = 0.277263158 -- Flat-top window",
        group="flattop_window",
    ),
    EngConstant(
        hex_pattern="3fb5656e0bffc627",
        float_value=0.083578947,
        decimal_pattern="0.08357",
        algorithm="flattop_window",
        category="dsp_windowing",
        confidence=0.93,
        description="a3 = 0.083578947 -- Flat-top window",
        group="flattop_window",
    ),
    EngConstant(
        hex_pattern="3f7c74d7e5a705b5",
        float_value=0.006947368,
        decimal_pattern="0.00694",
        algorithm="flattop_window",
        category="dsp_windowing",
        confidence=0.95,
        description="a4 = 0.006947368 -- Flat-top window (highly distinctive)",
        group="flattop_window",
    ),
    # -- nuttall_window ----------------------------------------------
    EngConstant(
        hex_pattern="3fd6c4e7253da72a",
        float_value=0.355768,
        decimal_pattern="0.35576",
        algorithm="nuttall_window",
        category="dsp_windowing",
        confidence=0.92,
        description="a0 = 0.355768 -- Nuttall window",
        group="nuttall_window",
    ),
    EngConstant(
        hex_pattern="3fdf317efe0ce0b9",
        float_value=0.487396,
        decimal_pattern="0.48739",
        algorithm="nuttall_window",
        category="dsp_windowing",
        confidence=0.92,
        description="a1 = 0.487396 -- Nuttall window",
        group="nuttall_window",
    ),
    EngConstant(
        hex_pattern="3fc27631b584b1ab",
        float_value=0.144232,
        decimal_pattern="0.14423",
        algorithm="nuttall_window",
        category="dsp_windowing",
        confidence=0.92,
        description="a2 = 0.144232 -- Nuttall window",
        group="nuttall_window",
    ),
    EngConstant(
        hex_pattern="3f89d0203e63e8de",
        float_value=0.012604,
        decimal_pattern="0.01260",
        algorithm="nuttall_window",
        category="dsp_windowing",
        confidence=0.94,
        description="a3 = 0.012604 -- Nuttall window (distinctive)",
        group="nuttall_window",
    ),
    # -- kaiser_window -----------------------------------------------
    EngConstant(
        hex_pattern="4014000000000000",
        float_value=5.0,
        decimal_pattern="5.0",
        algorithm="kaiser_window",
        category="dsp_windowing",
        confidence=0.0,  # GROUP-ONLY: too common for standalone detection
        description="beta = 5.0 -- Kaiser window (approx Hamming-like)",
        group="kaiser_window",
    ),
    EngConstant(
        hex_pattern="4021333333333333",
        float_value=8.6,
        decimal_pattern="8.6",
        algorithm="kaiser_window",
        category="dsp_windowing",
        confidence=0.6,
        description="beta = 8.6 -- Kaiser window (high dynamic range)",
        group="kaiser_window",
    ),
    # -- finance_daycount --------------------------------------------
    EngConstant(
        hex_pattern="4076800000000000",
        float_value=360.0,
        decimal_pattern="360.0",
        algorithm="day_count_30_360",
        category="finance",
        confidence=0.4,
        description="360 -- 30/360 day count convention",
        group="finance_daycount",
    ),
    EngConstant(
        hex_pattern="4076d00000000000",
        float_value=365.0,
        decimal_pattern="365.0",
        algorithm="day_count_actual_365",
        category="finance",
        confidence=0.35,
        description="365 -- Actual/365 day count convention",
        group="finance_daycount",
    ),
    EngConstant(
        hex_pattern="4076d40000000000",
        float_value=365.25,
        decimal_pattern="365.25",
        algorithm="day_count_actual_365_25",
        category="finance",
        confidence=0.55,
        description="365.25 -- average year length for accrual",
        group="finance_daycount",
    ),
    # -- acklam_inv_normal -------------------------------------------
    EngConstant(
        hex_pattern="c043d931bc1e0525",
        float_value=-39.69683028665376,
        decimal_pattern="-39.697",
        algorithm="acklam_inv_normal",
        category="finance_statistics",
        confidence=0.92,
        description="Acklam inverse normal CDF a[0] = -39.69683028665376",
        group="acklam_inv_normal",
    ),
    EngConstant(
        hex_pattern="406b9e467034039b",
        float_value=220.9460984245205,
        decimal_pattern="220.95",
        algorithm="acklam_inv_normal",
        category="finance_statistics",
        confidence=0.92,
        description="Acklam inverse normal CDF a[1] = 220.9460984245205",
        group="acklam_inv_normal",
    ),
    EngConstant(
        hex_pattern="c0713edb2dc53b99",
        float_value=-275.9285104469687,
        decimal_pattern="-275.93",
        algorithm="acklam_inv_normal",
        category="finance_statistics",
        confidence=0.92,
        description="Acklam inverse normal CDF a[2] = -275.9285104469687",
        group="acklam_inv_normal",
    ),
    EngConstant(
        hex_pattern="40614b72b40b401b",
        float_value=138.357751867269,
        decimal_pattern="138.36",
        algorithm="acklam_inv_normal",
        category="finance_statistics",
        confidence=0.92,
        description="Acklam inverse normal CDF a[3] = 138.357751867269",
        group="acklam_inv_normal",
    ),
    EngConstant(
        hex_pattern="c03eaa3034c08bcd",
        float_value=-30.66479806614716,
        decimal_pattern="-30.665",
        algorithm="acklam_inv_normal",
        category="finance_statistics",
        confidence=0.92,
        description="Acklam inverse normal CDF a[4] = -30.66479806614716",
        group="acklam_inv_normal",
    ),
    EngConstant(
        hex_pattern="40040d9320575479",
        float_value=2.506628277459239,
        decimal_pattern="2.5066",
        algorithm="acklam_inv_normal",
        category="finance_statistics",
        confidence=0.92,
        description="Acklam inverse normal CDF a[5] = 2.506628277459239",
        group="acklam_inv_normal",
    ),
    EngConstant(
        hex_pattern="c04b3cf0ce3004c4",
        float_value=-54.47609879822406,
        decimal_pattern="-54.476",
        algorithm="acklam_inv_normal",
        category="finance_statistics",
        confidence=0.92,
        description="Acklam inverse normal CDF b[0] = -54.47609879822406",
        group="acklam_inv_normal",
    ),
    EngConstant(
        hex_pattern="406432bf2cf04277",
        float_value=161.5858368580409,
        decimal_pattern="161.59",
        algorithm="acklam_inv_normal",
        category="finance_statistics",
        confidence=0.92,
        description="Acklam inverse normal CDF b[1] = 161.5858368580409",
        group="acklam_inv_normal",
    ),
    EngConstant(
        hex_pattern="c063765e0b02d8d2",
        float_value=-155.6989798598866,
        decimal_pattern="-155.7",
        algorithm="acklam_inv_normal",
        category="finance_statistics",
        confidence=0.92,
        description="Acklam inverse normal CDF b[2] = -155.6989798598866",
        group="acklam_inv_normal",
    ),
    EngConstant(
        hex_pattern="4050b348b1a7e9be",
        float_value=66.80131188771972,
        decimal_pattern="66.801",
        algorithm="acklam_inv_normal",
        category="finance_statistics",
        confidence=0.92,
        description="Acklam inverse normal CDF b[3] = 66.80131188771972",
        group="acklam_inv_normal",
    ),
    EngConstant(
        hex_pattern="c02a8fb57e147826",
        float_value=-13.28068155288572,
        decimal_pattern="-13.281",
        algorithm="acklam_inv_normal",
        category="finance_statistics",
        confidence=0.92,
        description="Acklam inverse normal CDF b[4] = -13.28068155288572",
        group="acklam_inv_normal",
    ),
    EngConstant(
        hex_pattern="bf7fe30d924acfe0",
        float_value=-0.007784894002430293,
        decimal_pattern="-0.0077849",
        algorithm="acklam_inv_normal",
        category="finance_statistics",
        confidence=0.92,
        description="Acklam inverse normal CDF c[0] = -0.007784894002430293",
        group="acklam_inv_normal",
    ),
    EngConstant(
        hex_pattern="bfd4a224c0e881b8",
        float_value=-0.3223964580411365,
        decimal_pattern="-0.3224",
        algorithm="acklam_inv_normal",
        category="finance_statistics",
        confidence=0.92,
        description="Acklam inverse normal CDF c[1] = -0.3223964580411365",
        group="acklam_inv_normal",
    ),
    EngConstant(
        hex_pattern="c00334c0c1701758",
        float_value=-2.400758277161838,
        decimal_pattern="-2.4008",
        algorithm="acklam_inv_normal",
        category="finance_statistics",
        confidence=0.92,
        description="Acklam inverse normal CDF c[2] = -2.400758277161838",
        group="acklam_inv_normal",
    ),
    EngConstant(
        hex_pattern="c00465da2c703a1a",
        float_value=-2.549732539343734,
        decimal_pattern="-2.5497",
        algorithm="acklam_inv_normal",
        category="finance_statistics",
        confidence=0.92,
        description="Acklam inverse normal CDF c[3] = -2.549732539343734",
        group="acklam_inv_normal",
    ),
    EngConstant(
        hex_pattern="40117fa7f4ea4dc7",
        float_value=4.374664141464968,
        decimal_pattern="4.3747",
        algorithm="acklam_inv_normal",
        category="finance_statistics",
        confidence=0.92,
        description="Acklam inverse normal CDF c[4] = 4.374664141464968",
        group="acklam_inv_normal",
    ),
    EngConstant(
        hex_pattern="4007815c1e3fcfa2",
        float_value=2.938163982698783,
        decimal_pattern="2.9382",
        algorithm="acklam_inv_normal",
        category="finance_statistics",
        confidence=0.92,
        description="Acklam inverse normal CDF c[5] = 2.938163982698783",
        group="acklam_inv_normal",
    ),
    EngConstant(
        hex_pattern="3f7fe2d857ac9fd4",
        float_value=0.007784695709041462,
        decimal_pattern="0.0077847",
        algorithm="acklam_inv_normal",
        category="finance_statistics",
        confidence=0.92,
        description="Acklam inverse normal CDF d[0] = 0.007784695709041462",
        group="acklam_inv_normal",
    ),
    EngConstant(
        hex_pattern="3fd4a34d2b590364",
        float_value=0.3224671290700398,
        decimal_pattern="0.32247",
        algorithm="acklam_inv_normal",
        category="finance_statistics",
        confidence=0.92,
        description="Acklam inverse normal CDF d[1] = 0.3224671290700398",
        group="acklam_inv_normal",
    ),
    EngConstant(
        hex_pattern="40038fa27c8ae616",
        float_value=2.445134137142996,
        decimal_pattern="2.4451",
        algorithm="acklam_inv_normal",
        category="finance_statistics",
        confidence=0.92,
        description="Acklam inverse normal CDF d[2] = 2.445134137142996",
        group="acklam_inv_normal",
    ),
    EngConstant(
        hex_pattern="400e09076895b119",
        float_value=3.754408661907416,
        decimal_pattern="3.7544",
        algorithm="acklam_inv_normal",
        category="finance_statistics",
        confidence=0.92,
        description="Acklam inverse normal CDF d[3] = 3.754408661907416",
        group="acklam_inv_normal",
    ),
    # -- cody_erf ----------------------------------------------------
    EngConstant(
        hex_pattern="40a912c1535d1653",
        float_value=3209.377589138961,
        decimal_pattern="3209.4",
        algorithm="cody_erf",
        category="finance_statistics",
        confidence=0.9,
        description="Cody erf rational approx p[0] = 3209.377589138961",
        group="cody_erf",
    ),
    EngConstant(
        hex_pattern="407797c38897528b",
        float_value=377.485237685302,
        decimal_pattern="377.49",
        algorithm="cody_erf",
        category="finance_statistics",
        confidence=0.9,
        description="Cody erf rational approx p[1] = 377.485237685302",
        group="cody_erf",
    ),
    EngConstant(
        hex_pattern="405c774e4d365da6",
        float_value=113.8641541510502,
        decimal_pattern="113.86",
        algorithm="cody_erf",
        category="finance_statistics",
        confidence=0.9,
        description="Cody erf rational approx p[2] = 113.8641541510502",
        group="cody_erf",
    ),
    EngConstant(
        hex_pattern="400949fb3ed443ea",
        float_value=3.161123743870566,
        decimal_pattern="3.1611",
        algorithm="cody_erf",
        category="finance_statistics",
        confidence=0.9,
        description="Cody erf rational approx p[3] = 3.161123743870566",
        group="cody_erf",
    ),
    EngConstant(
        hex_pattern="3fc7c7905a31c324",
        float_value=0.1857777061846032,
        decimal_pattern="0.18578",
        algorithm="cody_erf",
        category="finance_statistics",
        confidence=0.9,
        description="Cody erf rational approx p[4] = 0.1857777061846032",
        group="cody_erf",
    ),
    EngConstant(
        hex_pattern="40a63879423b87ad",
        float_value=2844.236833439171,
        decimal_pattern="2844.2",
        algorithm="cody_erf",
        category="finance_statistics",
        confidence=0.9,
        description="Cody erf rational approx q[0] = 2844.236833439171",
        group="cody_erf",
    ),
    EngConstant(
        hex_pattern="40940a77529cadc7",
        float_value=1282.616526077372,
        decimal_pattern="1282.6",
        algorithm="cody_erf",
        category="finance_statistics",
        confidence=0.9,
        description="Cody erf rational approx q[1] = 1282.616526077372",
        group="cody_erf",
    ),
    EngConstant(
        hex_pattern="406e80c9d57e55b9",
        float_value=244.0246379344442,
        decimal_pattern="244.02",
        algorithm="cody_erf",
        category="finance_statistics",
        confidence=0.9,
        description="Cody erf rational approx q[2] = 244.0246379344442",
        group="cody_erf",
    ),
    EngConstant(
        hex_pattern="403799ee342fb2dd",
        float_value=23.60129095234412,
        decimal_pattern="23.601",
        algorithm="cody_erf",
        category="finance_statistics",
        confidence=0.9,
        description="Cody erf rational approx q[3] = 23.60129095234412",
        group="cody_erf",
    ),
    # -- ml_normalization --------------------------------------------
    EngConstant(
        hex_pattern="3ee4f8b588e368f1",
        float_value=1e-05,
        decimal_pattern="1e-05",
        algorithm="layer_normalization",
        category="ml_normalization",
        confidence=0.6,
        description="1e-5 -- LayerNorm epsilon (PyTorch default)",
        group="ml_normalization",
    ),
    EngConstant(
        hex_pattern="3eb0c6f7a0b5ed8d",
        float_value=1e-06,
        decimal_pattern="1e-06",
        algorithm="layer_normalization",
        category="ml_normalization",
        confidence=0.55,
        description="1e-6 -- LayerNorm epsilon (TensorFlow default)",
        group="ml_normalization",
    ),
    EngConstant(
        hex_pattern="3f847ae147ae147b",
        float_value=0.01,
        decimal_pattern="0.01",
        algorithm="batch_normalization",
        category="ml_normalization",
        confidence=0.4,
        description="0.01 -- BatchNorm momentum (alternative)",
        group="ml_normalization",
    ),
    # -- ml_regularization -------------------------------------------
    EngConstant(
        hex_pattern="3f1a36e2eb1c432d",
        float_value=0.0001,
        decimal_pattern="1e-04",
        algorithm="weight_decay",
        category="ml_regularization",
        confidence=0.45,
        description="1e-4 -- common weight decay (L2 regularization)",
        group="ml_regularization",
    ),
    EngConstant(
        hex_pattern="3f40624dd2f1a9fc",
        float_value=0.0005,
        decimal_pattern="5e-04",
        algorithm="weight_decay",
        category="ml_regularization",
        confidence=0.5,
        description="5e-4 -- weight decay (ResNet default)",
        group="ml_regularization",
    ),
    # -- ml_transformer ----------------------------------------------
    EngConstant(
        hex_pattern="4036a09e667f3bcd",
        float_value=22.627416997969522,
        decimal_pattern="22.6274",
        algorithm="scaled_dot_product_attention",
        category="ml_transformer",
        confidence=0.75,
        description="sqrt(512) = 22.6274169980 -- Transformer attention scaling (d_k=512)",
        group="ml_transformer",
    ),
    EngConstant(
        hex_pattern="3fc0000000000000",
        float_value=0.125,
        decimal_pattern="0.12500",
        algorithm="scaled_dot_product_attention",
        category="ml_transformer",
        confidence=0.65,
        description="1/sqrt(64) = 0.1250000000 -- attention scaling (d_k=64)",
        group="ml_transformer",
    ),
    # -- ml_initialization -------------------------------------------
    EngConstant(
        hex_pattern="3ffaaaaaaaaaaaab",
        float_value=1.6666666666666667,
        decimal_pattern="1.66666",
        algorithm="xavier_init",
        category="ml_initialization",
        confidence=0.65,
        description="5/3 = 1.6666666667 -- Xavier/Glorot gain for tanh",
        group="ml_initialization",
    ),
    # -- golden_ratio ------------------------------------------------
    EngConstant(
        hex_pattern="3fe3c6ef372fe950",
        float_value=0.6180339887498949,
        decimal_pattern="0.61803",
        algorithm="golden_section_search",
        category="optimization",
        confidence=0.82,
        description="(sqrt(5)-1)/2 = 0.6180339887 -- golden section conjugate ratio",
        group="golden_ratio",
    ),
    # -- trust_region ------------------------------------------------
    EngConstant(
        hex_pattern="3fe8000000000000",
        float_value=0.75,
        decimal_pattern="0.75",
        algorithm="trust_region",
        category="optimization",
        confidence=0.0,  # GROUP-ONLY: too common for standalone detection
        description="0.75 -- trust region expand threshold (rho > 0.75)",
        group="trust_region",
    ),
    # -- nelder_mead -------------------------------------------------
    EngConstant(
        hex_pattern="3ff0000000000000",
        float_value=1.0,
        decimal_pattern="1.0",
        algorithm="nelder_mead",
        category="optimization",
        confidence=0.0,  # GROUP-ONLY: too common for standalone detection
        description="alpha = 1.0 -- Nelder-Mead reflection coefficient",
        group="nelder_mead",
    ),
    EngConstant(
        hex_pattern="4000000000000000",
        float_value=2.0,
        decimal_pattern="2.0",
        algorithm="nelder_mead",
        category="optimization",
        confidence=0.0,  # GROUP-ONLY: too common for standalone detection
        description="gamma = 2.0 -- Nelder-Mead expansion coefficient",
        group="nelder_mead",
    ),
    # -- levenberg_marquardt -----------------------------------------
    EngConstant(
        hex_pattern="3f50624dd2f1a9fc",
        float_value=0.001,
        decimal_pattern="1e-03",
        algorithm="levenberg_marquardt",
        category="optimization",
        confidence=0.45,
        description="lambda_0 = 1e-3 -- Levenberg-Marquardt initial damping",
        group="levenberg_marquardt",
    ),
    # -- gauss_radau_3pt ---------------------------------------------
    EngConstant(
        hex_pattern="bfd28db0200e9b7d",
        float_value=-0.2898979485566356,
        decimal_pattern="-0.28990",
        algorithm="gauss_radau_3pt",
        category="fea_integration",
        confidence=0.88,
        description="(1-sqrt(6))/5 = -0.2898979486 -- Gauss-Radau 3pt abscissa",
        group="gauss_radau_3pt",
    ),
    EngConstant(
        hex_pattern="3fe613a4dcd41a8b",
        float_value=0.6898979485566356,
        decimal_pattern="0.68990",
        algorithm="gauss_radau_3pt",
        category="fea_integration",
        confidence=0.88,
        description="(1+sqrt(6))/5 = 0.6898979486 -- Gauss-Radau 3pt abscissa",
        group="gauss_radau_3pt",
    ),
    EngConstant(
        hex_pattern="3fbc71c71c71c71c",
        float_value=0.1111111111111111,
        decimal_pattern="0.11111",
        algorithm="gauss_radau_3pt",
        category="fea_integration",
        confidence=0.65,
        description="1/9 -- Gauss-Radau 3pt endpoint weight",
        group="gauss_radau_3pt",
    ),
    EngConstant(
        hex_pattern="3fe06648ace491e9",
        float_value=0.5124858261884216,
        decimal_pattern="0.51249",
        algorithm="gauss_radau_3pt",
        category="fea_integration",
        confidence=0.88,
        description="(16+sqrt(6))/36 = 0.5124858262 -- Gauss-Radau 3pt weight",
        group="gauss_radau_3pt",
    ),
    EngConstant(
        hex_pattern="3fd816fcdf1a6a67",
        float_value=0.37640306270046725,
        decimal_pattern="0.37640",
        algorithm="gauss_radau_3pt",
        category="fea_integration",
        confidence=0.88,
        description="(16-sqrt(6))/36 = 0.3764030627 -- Gauss-Radau 3pt weight",
        group="gauss_radau_3pt",
    ),

    # --- Quantitative Finance (v1.2.2) ---
    EngConstant("3fcda6711871100e", 0.2316419, "0.231642", "black_scholes_merton", "option_pricing", 0.98, "Black-Scholes-Merton European option pricing formula. The constants are from Abr", "black_scholes_merton_grp"),
    EngConstant("3fd9884548df6ce3", 0.3989423, "0.398942", "black_scholes_merton", "option_pricing", 0.98, "Black-Scholes-Merton European option pricing formula. The constants are from Abr", "black_scholes_merton_grp"),
    EngConstant("3fd470bf1a5ca298", 0.3193815, "0.319381", "black_scholes_merton", "option_pricing", 0.98, "Black-Scholes-Merton European option pricing formula. The constants are from Abr", "black_scholes_merton_grp"),
    EngConstant("bfd6d1f0f8fbffc0", -0.3565638, "-0.356564", "black_scholes_merton", "option_pricing", 0.98, "Black-Scholes-Merton European option pricing formula. The constants are from Abr", "black_scholes_merton_grp"),
    EngConstant("3ffc80ef1348b220", 1.781478, "1.78148", "black_scholes_merton", "option_pricing", 0.98, "Black-Scholes-Merton European option pricing formula. The constants are from Abr", "black_scholes_merton_grp"),
    EngConstant("bffd23dd54da4ce8", -1.821256, "-1.82126", "black_scholes_merton", "option_pricing", 0.98, "Black-Scholes-Merton European option pricing formula. The constants are from Abr", "black_scholes_merton_grp"),
    EngConstant("3ff548cd63cb8173", 1.330274, "1.33027", "black_scholes_merton", "option_pricing", 0.98, "Black-Scholes-Merton European option pricing formula. The constants are from Abr", "black_scholes_merton_grp"),
    EngConstant("3fee666666666666", 0.95, "0.95", "var_historical", "risk_measure", 0.93, "Historical simulation VaR. Sort historical P&L, take quantile. No distributional", "var_historical_grp"),
    EngConstant("3fefae147ae147ae", 0.99, "0.99", "var_historical", "risk_measure", 0.93, "Historical simulation VaR. Sort historical P&L, take quantile. No distributional", "var_historical_grp"),
    EngConstant("3ffa51eb851eb852", 1.645, "1.645", "var_parametric", "risk_measure", 0.93, "Parametric (variance-covariance) VaR. Assumes normal returns. z=1.645 (95%), z=2", "var_parametric_grp"),
    EngConstant("40029ba5e353f7cf", 2.326, "2.326", "var_parametric", "risk_measure", 0.93, "Parametric (variance-covariance) VaR. Assumes normal returns. z=1.645 (95%), z=2", "var_parametric_grp"),
    EngConstant("3fff5c28f5c28f5c", 1.96, "1.96", "var_parametric", "risk_measure", 0.93, "Parametric (variance-covariance) VaR. Assumes normal returns. z=1.645 (95%), z=2", "var_parametric_grp"),
    EngConstant("40049ba5e353f7cf", 2.576, "2.576", "var_parametric", "risk_measure", 0.93, "Parametric (variance-covariance) VaR. Assumes normal returns. z=1.645 (95%), z=2", "var_parametric_grp"),
    EngConstant("3f9999999999999a", 0.025, "0.025", "expected_shortfall_cvar", "risk_measure", 0.93, "Expected Shortfall (CVaR). Average loss beyond VaR. Coherent risk measure (subad", "expected_shortfall_cvar_grp"),
    EngConstant("3fef333333333333", 0.975, "0.975", "expected_shortfall_cvar", "risk_measure", 0.93, "Expected Shortfall (CVaR). Average loss beyond VaR. Coherent risk measure (subad", "expected_shortfall_cvar_grp"),
    EngConstant("406f800000000000", 252.0, "252", "greeks_theta", "risk_measure", 0.94, "Theta - time decay of option value. Usually negative for long options. Conventio", "greeks_theta_grp"),
    EngConstant("40d4b44000000000", 21201.0, "21201", "sobol_sequence", "numerical_method", 0.93, "Sobol quasi-random sequence. Low-discrepancy for MC integration. Joe-Kuo directi", "sobol_sequence_grp"),
    EngConstant("4008000000000000", 3.0, "3", "halton_sequence", "numerical_method", 0.89, "Halton quasi-random sequence. Radical inverse function in different prime bases ", "halton_sequence_grp"),
    EngConstant("401c000000000000", 7.0, "7", "halton_sequence", "numerical_method", 0.89, "Halton quasi-random sequence. Radical inverse function in different prime bases ", "halton_sequence_grp"),
    EngConstant("4026000000000000", 11.0, "11", "halton_sequence", "numerical_method", 0.89, "Halton quasi-random sequence. Radical inverse function in different prime bases ", "halton_sequence_grp"),
    EngConstant("402a000000000000", 13.0, "13", "halton_sequence", "numerical_method", 0.89, "Halton quasi-random sequence. Radical inverse function in different prime bases ", "halton_sequence_grp"),
    EngConstant("3fe6a09e7098ef50", 0.7071068, "0.707107", "gauss_hermite_quadrature", "numerical_method", 0.88, "Gauss-Hermite quadrature for integrating f(x)*exp(-x^2). Used in finance for exp", "gauss_hermite_quadrature_grp"),
    EngConstant("3ffbb67ae6502b91", 1.7320508, "1.73205", "gauss_hermite_quadrature", "numerical_method", 0.88, "Gauss-Hermite quadrature for integrating f(x)*exp(-x^2). Used in finance for exp", "gauss_hermite_quadrature_grp"),
    EngConstant("3d719799812dea11", 1e-12, "1e-12", "brent_solver", "numerical_method", 0.92, "Brent's root-finding method. Combines bisection, secant, and inverse quadratic i", "brent_solver_grp"),
    EngConstant("3cd203af9ee75616", 1e-15, "1e-15", "brent_solver", "numerical_method", 0.92, "Brent's root-finding method. Combines bisection, secant, and inverse quadratic i", "brent_solver_grp"),
    EngConstant("4059000000000000", 100.0, "100", "brent_solver", "numerical_method", 0.92, "Brent's root-finding method. Combines bisection, secant, and inverse quadratic i", "brent_solver_grp"),
    EngConstant("40c3880000000000", 10000.0, "10000", "cds_pricing", "credit_fixed_income", 0.92, "CDS par spread pricing. Protection leg (default payments) = Premium leg (spread ", "cds_pricing_grp"),
    EngConstant("408f400000000000", 1000.0, "1000", "bond_pricing", "credit_fixed_income", 0.95, "Bond pricing. Clean vs dirty price (dirty = clean + accrued interest). Day count", "bond_pricing_grp"),
    EngConstant("bfe0000000000000", -0.5, "-0.5", "implied_volatility_jaeckel", "volatility", 0.88, "Jaeckel's 'Let's Be Rational' implied vol. Machine-precision accuracy without it", "implied_volatility_jaeckel_grp"),
    EngConstant("3fe33dd97f62b6ae", 0.6013, "0.6013", "parkinson_volatility", "volatility", 0.89, "Parkinson range-based volatility estimator. Uses high-low only. ~5x more efficie", "parkinson_volatility_grp"),
    EngConstant("3fe62e429e0a41a2", 0.693147, "0.693147", "parkinson_volatility", "volatility", 0.89, "Parkinson range-based volatility estimator. Uses high-low only. ~5x more efficie", "parkinson_volatility_grp"),
    EngConstant("3fd8b90a7829068a", 0.386294, "0.386294", "garman_klass_volatility", "volatility", 0.88, "Garman-Klass OHLC volatility estimator. Uses open, high, low, close. ~7.4x effic", "garman_klass_volatility_grp"),
    EngConstant("3fd5c28f5c28f5c3", 0.34, "0.34", "yang_zhang_volatility", "volatility", 0.85, "Yang-Zhang volatility. Combines overnight (open-close), Rogers-Satchell, and clo", "yang_zhang_volatility_grp"),
    EngConstant("3ff570a3d70a3d71", 1.34, "1.34", "yang_zhang_volatility", "volatility", 0.85, "Yang-Zhang volatility. Combines overnight (open-close), Rogers-Satchell, and clo", "yang_zhang_volatility_grp"),
    EngConstant("3fee147ae147ae14", 0.94, "0.94", "ewma_volatility", "volatility", 0.93, "EWMA (Exponentially Weighted Moving Average) volatility. Special case of GARCH w", "ewma_volatility_grp"),
    EngConstant("3fef0a3d70a3d70a", 0.97, "0.97", "ewma_volatility", "volatility", 0.93, "EWMA (Exponentially Weighted Moving Average) volatility. Special case of GARCH w", "ewma_volatility_grp"),
    EngConstant("3ff8000000000000", 1.5, "1.5", "carr_madan_fft", "option_pricing", 0.90, "Carr-Madan FFT option pricing. Price entire strike spectrum at once via FFT of c", "carr_madan_fft_grp"),
    EngConstant("3fe2a4a8c154c986", 0.5826, "0.5826", "broadie_glasserman_kou", "option_pricing", 0.85, "Broadie-Glasserman-Kou continuity correction for discrete barrier options. Shift", "broadie_glasserman_kou_grp"),
    EngConstant("bfe2a4a8c154c986", -0.5826, "-0.5826", "broadie_glasserman_kou", "option_pricing", 0.85, "Broadie-Glasserman-Kou continuity correction for discrete barrier options. Shift", "broadie_glasserman_kou_grp"),
    EngConstant("3f0a36e2eb1c432d", 5e-05, "5e-05", "dv01", "credit_fixed_income", 0.92, "DV01 / PV01 - Dollar value of one basis point. Price change for 1bp parallel shi", "dv01_grp"),
    EngConstant("401921fb54411744", 6.283185307, "6.28319", "box_muller", "numerical_method", 0.93, "Box-Muller transform. Generate normal variates from uniform. Marsaglia polar met", "box_muller_grp"),
    EngConstant("4083800000000000", 624.0, "624", "mersenne_twister", "numerical_method", 0.92, "Mersenne Twister MT19937. Standard PRNG in finance. Period 2^19937-1. State arra", "mersenne_twister_grp"),
    EngConstant("4078d00000000000", 397.0, "397", "mersenne_twister", "numerical_method", 0.92, "Mersenne Twister MT19937. Standard PRNG in finance. Period 2^19937-1. State arra", "mersenne_twister_grp"),
    EngConstant("40d3784000000000", 19937.0, "19937", "mersenne_twister", "numerical_method", 0.92, "Mersenne Twister MT19937. Standard PRNG in finance. Period 2^19937-1. State arra", "mersenne_twister_grp"),
    EngConstant("41e321161be00000", 2567483615.0, "2.56748e+09", "mersenne_twister", "numerical_method", 0.92, "Mersenne Twister MT19937. Standard PRNG in finance. Period 2^19937-1. State arra", "mersenne_twister_grp"),
    EngConstant("41e3a58ad0000000", 2636928640.0, "2.63693e+09", "mersenne_twister", "numerical_method", 0.92, "Mersenne Twister MT19937. Standard PRNG in finance. Period 2^19937-1. State arra", "mersenne_twister_grp"),
    EngConstant("41edf8c000000000", 4022730752.0, "4.02273e+09", "mersenne_twister", "numerical_method", 0.92, "Mersenne Twister MT19937. Standard PRNG in finance. Period 2^19937-1. State arra", "mersenne_twister_grp"),
    EngConstant("403e000000000000", 30.0, "30", "vix_calculation", "volatility", 0.88, "CBOE VIX calculation. Model-free implied volatility from SPX options. 30-day tar", "vix_calculation_grp"),
    EngConstant("41200a4000000000", 525600.0, "525600", "vix_calculation", "volatility", 0.88, "CBOE VIX calculation. Model-free implied volatility from SPX options. 30-day tar", "vix_calculation_grp"),
    EngConstant("3fd470bf3a92f8ec", 0.31938153, "0.319382", "normal_cdf_approximation", "numerical_method", 0.95, "Normal CDF rational approximation (Abramowitz-Stegun). These specific constants ", "normal_cdf_approximation_grp"),
    EngConstant("bfd6d1f0e5a8325b", -0.356563782, "-0.356564", "normal_cdf_approximation", "numerical_method", 0.95, "Normal CDF rational approximation (Abramowitz-Stegun). These specific constants ", "normal_cdf_approximation_grp"),
    EngConstant("3ffc80ef025f5e68", 1.781477937, "1.78148", "normal_cdf_approximation", "numerical_method", 0.95, "Normal CDF rational approximation (Abramowitz-Stegun). These specific constants ", "normal_cdf_approximation_grp"),
    EngConstant("bffd23dd4ef278d0", -1.821255978, "-1.82126", "normal_cdf_approximation", "numerical_method", 0.95, "Normal CDF rational approximation (Abramowitz-Stegun). These specific constants ", "normal_cdf_approximation_grp"),
    EngConstant("3ff548cdd6f42943", 1.330274429, "1.33027", "normal_cdf_approximation", "numerical_method", 0.95, "Normal CDF rational approximation (Abramowitz-Stegun). These specific constants ", "normal_cdf_approximation_grp"),
    EngConstant("3fd9884533d3d180", 0.3989422804, "0.398942", "normal_cdf_approximation", "numerical_method", 0.95, "Normal CDF rational approximation (Abramowitz-Stegun). These specific constants ", "normal_cdf_approximation_grp"),
    EngConstant("40041fc7607c419a", 2.515517, "2.51552", "normal_inverse_cdf", "numerical_method", 0.91, "Inverse normal CDF (probit). Beasley-Springer-Moro or Peter Acklam's rational ap", "normal_inverse_cdf_grp"),
    EngConstant("3fe9b0f8c64fdb0a", 0.802853, "0.802853", "normal_inverse_cdf", "numerical_method", 0.91, "Inverse normal CDF (probit). Beasley-Springer-Moro or Peter Acklam's rational ap", "normal_inverse_cdf_grp"),
    EngConstant("3f8526d8b1dd5d3e", 0.010328, "0.010328", "normal_inverse_cdf", "numerical_method", 0.91, "Inverse normal CDF (probit). Beasley-Springer-Moro or Peter Acklam's rational ap", "normal_inverse_cdf_grp"),
    EngConstant("3ff6ecb31c219eb6", 1.432788, "1.43279", "normal_inverse_cdf", "numerical_method", 0.91, "Inverse normal CDF (probit). Beasley-Springer-Moro or Peter Acklam's rational ap", "normal_inverse_cdf_grp"),
    EngConstant("3fc839f77292c493", 0.189269, "0.189269", "normal_inverse_cdf", "numerical_method", 0.91, "Inverse normal CDF (probit). Beasley-Springer-Moro or Peter Acklam's rational ap", "normal_inverse_cdf_grp"),
    EngConstant("3f556e264e48626f", 0.001308, "0.001308", "normal_inverse_cdf", "numerical_method", 0.91, "Inverse normal CDF (probit). Beasley-Springer-Moro or Peter Acklam's rational ap", "normal_inverse_cdf_grp"),

    # --- Cryptography & Security (v1.2.2) ---
    EngConstant("4058c00000000000", 99.0, "99", "aes_128", "symmetric_encryption", 0.98, "AES-128 block cipher, 10 rounds, 128-bit key", "aes_128_grp"),
    EngConstant("405f000000000000", 124.0, "124", "aes_128", "symmetric_encryption", 0.98, "AES-128 block cipher, 10 rounds, 128-bit key", "aes_128_grp"),
    EngConstant("405dc00000000000", 119.0, "119", "aes_128", "symmetric_encryption", 0.98, "AES-128 block cipher, 10 rounds, 128-bit key", "aes_128_grp"),
    EngConstant("405ec00000000000", 123.0, "123", "aes_128", "symmetric_encryption", 0.98, "AES-128 block cipher, 10 rounds, 128-bit key", "aes_128_grp"),
    EngConstant("406e400000000000", 242.0, "242", "aes_128", "symmetric_encryption", 0.98, "AES-128 block cipher, 10 rounds, 128-bit key", "aes_128_grp"),
    EngConstant("405ac00000000000", 107.0, "107", "aes_128", "symmetric_encryption", 0.98, "AES-128 block cipher, 10 rounds, 128-bit key", "aes_128_grp"),
    EngConstant("405bc00000000000", 111.0, "111", "aes_128", "symmetric_encryption", 0.98, "AES-128 block cipher, 10 rounds, 128-bit key", "aes_128_grp"),
    EngConstant("4068a00000000000", 197.0, "197", "aes_128", "symmetric_encryption", 0.98, "AES-128 block cipher, 10 rounds, 128-bit key", "aes_128_grp"),
    EngConstant("4048000000000000", 48.0, "48", "aes_128", "symmetric_encryption", 0.98, "AES-128 block cipher, 10 rounds, 128-bit key", "aes_128_grp"),
    EngConstant("4059c00000000000", 103.0, "103", "aes_128", "symmetric_encryption", 0.98, "AES-128 block cipher, 10 rounds, 128-bit key", "aes_128_grp"),
    EngConstant("406fc00000000000", 254.0, "254", "aes_128", "symmetric_encryption", 0.98, "AES-128 block cipher, 10 rounds, 128-bit key", "aes_128_grp"),
    EngConstant("406ae00000000000", 215.0, "215", "aes_128", "symmetric_encryption", 0.98, "AES-128 block cipher, 10 rounds, 128-bit key", "aes_128_grp"),
    EngConstant("4065600000000000", 171.0, "171", "aes_128", "symmetric_encryption", 0.98, "AES-128 block cipher, 10 rounds, 128-bit key", "aes_128_grp"),
    EngConstant("405d800000000000", 118.0, "118", "aes_128", "symmetric_encryption", 0.98, "AES-128 block cipher, 10 rounds, 128-bit key", "aes_128_grp"),
    EngConstant("4069400000000000", 202.0, "202", "aes_128", "symmetric_encryption", 0.98, "AES-128 block cipher, 10 rounds, 128-bit key", "aes_128_grp"),
    EngConstant("41ec200000000000", 3774873600.0, "0xE1000000", "aes_gcm", "symmetric_encryption", 0.95, "AES in Galois/Counter Mode with authentication tag", "aes_gcm_grp"),
    EngConstant("43ec200000000000", 1.6212958658533786e+19, "0xE100000000000000", "aes_gcm", "symmetric_encryption", 0.95, "AES in Galois/Counter Mode with authentication tag", "aes_gcm_grp"),
    EngConstant("4060e00000000000", 135.0, "135", "aes_xts", "symmetric_encryption", 0.90, "AES in XEX-based Tweaked-codebook mode with ciphertext Stealing", "aes_xts_grp"),
    EngConstant("41d85c1e19400000", 1634760805.0, "0x61707865", "chacha20", "symmetric_encryption", 0.97, "ChaCha20 stream cipher, 20 rounds, 256-bit key", "chacha20_grp"),
    EngConstant("41c9903237000000", 857760878.0, "0x3320646E", "chacha20", "symmetric_encryption", 0.97, "ChaCha20 stream cipher, 20 rounds, 256-bit key", "chacha20_grp"),
    EngConstant("41de588b4c800000", 2036477234.0, "0x79622D32", "chacha20", "symmetric_encryption", 0.97, "ChaCha20 stream cipher, 20 rounds, 256-bit key", "chacha20_grp"),
    EngConstant("41dac8195d000000", 1797285236.0, "0x6B206574", "chacha20", "symmetric_encryption", 0.97, "ChaCha20 stream cipher, 20 rounds, 256-bit key", "chacha20_grp"),
    EngConstant("41affffffe000000", 268435455.0, "0x0FFFFFFF", "chacha20_poly1305", "aead", 0.95, "ChaCha20-Poly1305 AEAD construction (RFC 8439)", "chacha20_poly1305_grp"),
    EngConstant("41affffff8000000", 268435452.0, "0x0FFFFFFC", "chacha20_poly1305", "aead", 0.95, "ChaCha20-Poly1305 AEAD construction (RFC 8439)", "chacha20_poly1305_grp"),
    EngConstant("41c21fb544000000", 608135816.0, "0x243F6A88", "blowfish", "symmetric_encryption", 0.97, "Blowfish block cipher, 16 Feistel rounds, variable key up to 448 bits", "blowfish_grp"),
    EngConstant("41e0b4611a600000", 2242054355.0, "0x85A308D3", "blowfish", "symmetric_encryption", 0.97, "Blowfish block cipher, 16 Feistel rounds, variable key up to 448 bits", "blowfish_grp"),
    EngConstant("41b3198a2e000000", 320440878.0, "0x13198A2E", "blowfish", "symmetric_encryption", 0.97, "Blowfish block cipher, 16 Feistel rounds, variable key up to 448 bits", "blowfish_grp"),
    EngConstant("418b839a20000000", 57701188.0, "0x03707344", "blowfish", "symmetric_encryption", 0.97, "Blowfish block cipher, 16 Feistel rounds, variable key up to 448 bits", "blowfish_grp"),
    EngConstant("41e4812704400000", 2752067618.0, "0xA4093822", "blowfish", "symmetric_encryption", 0.97, "Blowfish block cipher, 16 Feistel rounds, variable key up to 448 bits", "blowfish_grp"),
    EngConstant("41c4cf98e8000000", 698298832.0, "0x299F31D0", "blowfish", "symmetric_encryption", 0.97, "Blowfish block cipher, 16 Feistel rounds, variable key up to 448 bits", "blowfish_grp"),
    EngConstant("4076900000000000", 361.0, "0x169", "twofish", "symmetric_encryption", 0.92, "Twofish block cipher, 16 Feistel rounds, 128/192/256-bit key", "twofish_grp"),
    EngConstant("4074d00000000000", 333.0, "0x14D", "twofish", "symmetric_encryption", 0.92, "Twofish block cipher, 16 Feistel rounds, 128/192/256-bit key", "twofish_grp"),
    EngConstant("4064800000000000", 164.0, "164", "twofish", "symmetric_encryption", 0.92, "Twofish block cipher, 16 Feistel rounds, 128/192/256-bit key", "twofish_grp"),
    EngConstant("4055400000000000", 85.0, "85", "twofish", "symmetric_encryption", 0.92, "Twofish block cipher, 16 Feistel rounds, 128/192/256-bit key", "twofish_grp"),
    EngConstant("4056800000000000", 90.0, "90", "twofish", "symmetric_encryption", 0.92, "Twofish block cipher, 16 Feistel rounds, 128/192/256-bit key", "twofish_grp"),
    EngConstant("41e3c6ef37200000", 2654435769.0, "0x9E3779B9", "serpent", "symmetric_encryption", 0.85, "Serpent block cipher, 32 rounds, 128/192/256-bit key (AES finalist)", "serpent_grp"),
    EngConstant("41e413cccfe00000", 2694735487.0, "0xA09E667F", "camellia", "symmetric_encryption", 0.92, "Camellia block cipher, 18/24 Feistel rounds, used in TLS and Japanese government", "camellia_grp"),
    EngConstant("41cde64845800000", 1003262091.0, "0x3BCC908B", "camellia", "symmetric_encryption", 0.92, "Camellia block cipher, 18/24 Feistel rounds, used in TLS and Japanese government", "camellia_grp"),
    EngConstant("41e6cf5d0b000000", 3061508184.0, "0xB67AE858", "camellia", "symmetric_encryption", 0.92, "Camellia block cipher, 18/24 Feistel rounds, used in TLS and Japanese government", "camellia_grp"),
    EngConstant("41d32a9cec800000", 1286239154.0, "0x4CAA73B2", "camellia", "symmetric_encryption", 0.92, "Camellia block cipher, 18/24 Feistel rounds, used in TLS and Japanese government", "camellia_grp"),
    EngConstant("41e8dde6e5e00000", 3337565999.0, "0xC6EF372F", "camellia", "symmetric_encryption", 0.92, "Camellia block cipher, 18/24 Feistel rounds, used in TLS and Japanese government", "camellia_grp"),
    EngConstant("41ed29f057c00000", 3914302142.0, "0xE94F82BE", "camellia", "symmetric_encryption", 0.92, "Camellia block cipher, 18/24 Feistel rounds, used in TLS and Japanese government", "camellia_grp"),
    EngConstant("406c400000000000", 226.0, "226", "aria", "symmetric_encryption", 0.85, "ARIA block cipher, Korean standard (NSRI), 12/14/16 rounds", "aria_grp"),
    EngConstant("4053800000000000", 78.0, "78", "aria", "symmetric_encryption", 0.85, "ARIA block cipher, Korean standard (NSRI), 12/14/16 rounds", "aria_grp"),
    EngConstant("406ac00000000000", 214.0, "214", "sm4", "symmetric_encryption", 0.93, "SM4 (formerly SMS4), Chinese national block cipher standard, 32 rounds", "sm4_grp"),
    EngConstant("4062000000000000", 144.0, "144", "sm4", "symmetric_encryption", 0.93, "SM4 (formerly SMS4), Chinese national block cipher standard, 32 rounds", "sm4_grp"),
    EngConstant("406d200000000000", 233.0, "233", "sm4", "symmetric_encryption", 0.93, "SM4 (formerly SMS4), Chinese national block cipher standard, 32 rounds", "sm4_grp"),
    EngConstant("4069800000000000", 204.0, "204", "sm4", "symmetric_encryption", 0.93, "SM4 (formerly SMS4), Chinese national block cipher standard, 32 rounds", "sm4_grp"),
    EngConstant("406c200000000000", 225.0, "225", "sm4", "symmetric_encryption", 0.93, "SM4 (formerly SMS4), Chinese national block cipher standard, 32 rounds", "sm4_grp"),
    EngConstant("404e800000000000", 61.0, "61", "sm4", "symmetric_encryption", 0.93, "SM4 (formerly SMS4), Chinese national block cipher standard, 32 rounds", "sm4_grp"),
    EngConstant("4066e00000000000", 183.0, "183", "sm4", "symmetric_encryption", 0.93, "SM4 (formerly SMS4), Chinese national block cipher standard, 32 rounds", "sm4_grp"),
    EngConstant("4036000000000000", 22.0, "22", "sm4", "symmetric_encryption", 0.93, "SM4 (formerly SMS4), Chinese national block cipher standard, 32 rounds", "sm4_grp"),
    EngConstant("4066c00000000000", 182.0, "182", "sm4", "symmetric_encryption", 0.93, "SM4 (formerly SMS4), Chinese national block cipher standard, 32 rounds", "sm4_grp"),
    EngConstant("4034000000000000", 20.0, "20", "sm4", "symmetric_encryption", 0.93, "SM4 (formerly SMS4), Chinese national block cipher standard, 32 rounds", "sm4_grp"),
    EngConstant("4068400000000000", 194.0, "194", "sm4", "symmetric_encryption", 0.93, "SM4 (formerly SMS4), Chinese national block cipher standard, 32 rounds", "sm4_grp"),
    EngConstant("0000000000000000", 0.0, "0", "rc4", "symmetric_encryption", 0.75, "RC4 (ARC4) stream cipher, variable key size", "rc4_grp"),
    EngConstant("4010000000000000", 4.0, "4", "rc4", "symmetric_encryption", 0.75, "RC4 (ARC4) stream cipher, variable key size", "rc4_grp"),
    EngConstant("4018000000000000", 6.0, "6", "rc4", "symmetric_encryption", 0.75, "RC4 (ARC4) stream cipher, variable key size", "rc4_grp"),
    EngConstant("4020000000000000", 8.0, "8", "rc4", "symmetric_encryption", 0.75, "RC4 (ARC4) stream cipher, variable key size", "rc4_grp"),
    EngConstant("4022000000000000", 9.0, "9", "rc4", "symmetric_encryption", 0.75, "RC4 (ARC4) stream cipher, variable key size", "rc4_grp"),
    EngConstant("4024000000000000", 10.0, "10", "rc4", "symmetric_encryption", 0.75, "RC4 (ARC4) stream cipher, variable key size", "rc4_grp"),
    EngConstant("4028000000000000", 12.0, "12", "rc4", "symmetric_encryption", 0.75, "RC4 (ARC4) stream cipher, variable key size", "rc4_grp"),
    EngConstant("402c000000000000", 14.0, "14", "rc4", "symmetric_encryption", 0.75, "RC4 (ARC4) stream cipher, variable key size", "rc4_grp"),
    EngConstant("402e000000000000", 15.0, "15", "rc4", "symmetric_encryption", 0.75, "RC4 (ARC4) stream cipher, variable key size", "rc4_grp"),
    EngConstant("41e6fc2a2c600000", 3084996963.0, "0xB7E15163", "rc5", "symmetric_encryption", 0.90, "RC5 block cipher, data-dependent rotations, variable rounds/key/block", "rc5_grp"),
    EngConstant("41c87da06a000000", 821772500.0, "0x30FB40D4", "cast5", "symmetric_encryption", 0.90, "CAST-128 (CAST5) block cipher, 12 or 16 Feistel rounds", "cast5_grp"),
    EngConstant("41e3f41fe1600000", 2678128395.0, "0x9FA0FF0B", "cast5", "symmetric_encryption", 0.90, "CAST-128 (CAST5) block cipher, 12 or 16 Feistel rounds", "cast5_grp"),
    EngConstant("41dafb334bc00000", 1810681135.0, "0x6BECCD2F", "cast5", "symmetric_encryption", 0.90, "CAST-128 (CAST5) block cipher, 12 or 16 Feistel rounds", "cast5_grp"),
    EngConstant("41cf92c63d000000", 1059425402.0, "0x3F258C7A", "cast5", "symmetric_encryption", 0.90, "CAST-128 (CAST5) block cipher, 12 or 16 Feistel rounds", "cast5_grp"),
    EngConstant("40f0001000000000", 65537.0, "0x10001", "idea", "symmetric_encryption", 0.88, "International Data Encryption Algorithm, 8.5 rounds", "idea_grp"),
    EngConstant("41c8903237000000", 824206446.0, "0x3120646E", "salsa20", "symmetric_encryption", 0.95, "Salsa20 stream cipher, 20 rounds, predecessor of ChaCha20", "salsa20_grp"),
    EngConstant("41de588b4d800000", 2036477238.0, "0x79622D36", "salsa20", "symmetric_encryption", 0.95, "Salsa20 stream cipher, 20 rounds, predecessor of ChaCha20", "salsa20_grp"),
    EngConstant("406dc00000000000", 238.0, "238", "kuznyechik", "symmetric_encryption", 0.88, "Kuznyechik (GOST R 34.12-2015), modern Russian block cipher", "kuznyechik_grp"),
    EngConstant("406ba00000000000", 221.0, "221", "kuznyechik", "symmetric_encryption", 0.88, "Kuznyechik (GOST R 34.12-2015), modern Russian block cipher", "kuznyechik_grp"),
    EngConstant("4031000000000000", 17.0, "17", "kuznyechik", "symmetric_encryption", 0.88, "Kuznyechik (GOST R 34.12-2015), modern Russian block cipher", "kuznyechik_grp"),
    EngConstant("4069e00000000000", 207.0, "207", "kuznyechik", "symmetric_encryption", 0.88, "Kuznyechik (GOST R 34.12-2015), modern Russian block cipher", "kuznyechik_grp"),
    EngConstant("405b800000000000", 110.0, "110", "kuznyechik", "symmetric_encryption", 0.88, "Kuznyechik (GOST R 34.12-2015), modern Russian block cipher", "kuznyechik_grp"),
    EngConstant("4048800000000000", 49.0, "49", "kuznyechik", "symmetric_encryption", 0.88, "Kuznyechik (GOST R 34.12-2015), modern Russian block cipher", "kuznyechik_grp"),
    EngConstant("4fe0000000000000", 5.78960446186581e+76, "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED", "ed25519", "digital_signature", 0.93, "Ed25519 signature scheme (EdDSA on Curve25519)", "ed25519_grp"),
    EngConstant("411db41800000000", 486662.0, "0x0000000000000000000000000000000000000000000000000000000000076D06", "x25519", "key_exchange", 0.92, "X25519 ECDH key exchange (Curve25519 Montgomery form)", "x25519_grp"),
    EngConstant("41d9d148c0400000", 1732584193.0, "0x67452301", "sha1", "hash", 0.98, "SHA-1 hash function, 80 rounds, 160-bit digest (DEPRECATED)", "sha1_grp"),
    EngConstant("41edf9b571200000", 4023233417.0, "0xEFCDAB89", "sha1", "hash", 0.98, "SHA-1 hash function, 80 rounds, 160-bit digest (DEPRECATED)", "sha1_grp"),
    EngConstant("41e3175b9fc00000", 2562383102.0, "0x98BADCFE", "sha1", "hash", 0.98, "SHA-1 hash function, 80 rounds, 160-bit digest (DEPRECATED)", "sha1_grp"),
    EngConstant("41b0325476000000", 271733878.0, "0x10325476", "sha1", "hash", 0.98, "SHA-1 hash function, 80 rounds, 160-bit digest (DEPRECATED)", "sha1_grp"),
    EngConstant("41e87a5c3e000000", 3285377520.0, "0xC3D2E1F0", "sha1", "hash", 0.98, "SHA-1 hash function, 80 rounds, 160-bit digest (DEPRECATED)", "sha1_grp"),
    EngConstant("41d6a09e66400000", 1518500249.0, "0x5A827999", "sha1", "hash", 0.98, "SHA-1 hash function, 80 rounds, 160-bit digest (DEPRECATED)", "sha1_grp"),
    EngConstant("41dbb67ae8400000", 1859775393.0, "0x6ED9EBA1", "sha1", "hash", 0.98, "SHA-1 hash function, 80 rounds, 160-bit digest (DEPRECATED)", "sha1_grp"),
    EngConstant("41e1e3779b800000", 2400959708.0, "0x8F1BBCDC", "sha1", "hash", 0.98, "SHA-1 hash function, 80 rounds, 160-bit digest (DEPRECATED)", "sha1_grp"),
    EngConstant("41e94c583ac00000", 3395469782.0, "0xCA62C1D6", "sha1", "hash", 0.98, "SHA-1 hash function, 80 rounds, 160-bit digest (DEPRECATED)", "sha1_grp"),
    EngConstant("41da827999c00000", 1779033703.0, "0x6A09E667", "sha256", "hash", 0.99, "SHA-256 hash function, 64 rounds, 256-bit digest", "sha256_grp"),
    EngConstant("41e76cf5d0a00000", 3144134277.0, "0xBB67AE85", "sha256", "hash", 0.99, "SHA-256 hash function, 64 rounds, 256-bit digest", "sha256_grp"),
    EngConstant("41ce3779b9000000", 1013904242.0, "0x3C6EF372", "sha256", "hash", 0.99, "SHA-256 hash function, 64 rounds, 256-bit digest", "sha256_grp"),
    EngConstant("41e4a9fea7400000", 2773480762.0, "0xA54FF53A", "sha256", "hash", 0.99, "SHA-256 hash function, 64 rounds, 256-bit digest", "sha256_grp"),
    EngConstant("41d443949fc00000", 1359893119.0, "0x510E527F", "sha256", "hash", 0.99, "SHA-256 hash function, 64 rounds, 256-bit digest", "sha256_grp"),
    EngConstant("41e360ad11800000", 2600822924.0, "0x9B05688C", "sha256", "hash", 0.99, "SHA-256 hash function, 64 rounds, 256-bit digest", "sha256_grp"),
    EngConstant("41bf83d9ab000000", 528734635.0, "0x1F83D9AB", "sha256", "hash", 0.99, "SHA-256 hash function, 64 rounds, 256-bit digest", "sha256_grp"),
    EngConstant("41d6f83346400000", 1541459225.0, "0x5BE0CD19", "sha256", "hash", 0.99, "SHA-256 hash function, 64 rounds, 256-bit digest", "sha256_grp"),
    EngConstant("41d0a28be6000000", 1116352408.0, "0x428A2F98", "sha256", "hash", 0.99, "SHA-256 hash function, 64 rounds, 256-bit digest", "sha256_grp"),
    EngConstant("41dc4dd124400000", 1899447441.0, "0x71374491", "sha256", "hash", 0.99, "SHA-256 hash function, 64 rounds, 256-bit digest", "sha256_grp"),
    EngConstant("41e6b81f79e00000", 3049323471.0, "0xB5C0FBCF", "sha256", "hash", 0.99, "SHA-256 hash function, 64 rounds, 256-bit digest", "sha256_grp"),
    EngConstant("41ed36bb74a00000", 3921009573.0, "0xE9B5DBA5", "sha256", "hash", 0.99, "SHA-256 hash function, 64 rounds, 256-bit digest", "sha256_grp"),
    EngConstant("43e97773abb820b4", 1.4680500436340154e+19, "0xCBBB9D5DC1059ED8", "sha384", "hash", 0.95, "SHA-384 hash function (SHA-512 with different IV, truncated output)", "sha384_grp"),
    EngConstant("43d8a68a4a8d9f35", 7.105036623409894e+18, "0x629A292A367CD507", "sha384", "hash", 0.95, "SHA-384 hash function (SHA-512 with different IV, truncated output)", "sha384_grp"),
    EngConstant("43e22b202b460e1c", 1.0473403895298187e+19, "0x9159015A3070DD17", "sha384", "hash", 0.95, "SHA-384 hash function (SHA-512 with different IV, truncated output)", "sha384_grp"),
    EngConstant("43b52fecd8f70e59", 1.5266992153038912e+18, "0x152FECD8F70E5939", "sha384", "hash", 0.95, "SHA-384 hash function (SHA-512 with different IV, truncated output)", "sha384_grp"),
    EngConstant("43da827999fcef32", 7.640891576956013e+18, "0x6A09E667F3BCC908", "sha512", "hash", 0.98, "SHA-512 hash function, 80 rounds, 512-bit digest", "sha512_grp"),
    EngConstant("43e76cf5d0b09955", 1.3503953896175479e+19, "0xBB67AE8584CAA73B", "sha512", "hash", 0.98, "SHA-512 hash function, 80 rounds, 512-bit digest", "sha512_grp"),
    EngConstant("43ce3779b97f4a7c", 4.3546855649368453e+18, "0x3C6EF372FE94F82B", "sha512", "hash", 0.98, "SHA-512 hash function, 80 rounds, 512-bit digest", "sha512_grp"),
    EngConstant("43e4a9fea74be3a7", 1.191200917047091e+19, "0xA54FF53A5F1D36F1", "sha512", "hash", 0.98, "SHA-512 hash function, 80 rounds, 512-bit digest", "sha512_grp"),
    EngConstant("43d0a28be635ca2c", 4.794697086780617e+18, "0x428A2F98D728AE22", "sha512", "hash", 0.98, "SHA-512 hash function, 80 rounds, 512-bit digest", "sha512_grp"),
    EngConstant("43dc4dd12448fbd9", 8.158064640168781e+18, "0x7137449123EF65CD", "sha512", "hash", 0.98, "SHA-512 hash function, 80 rounds, 512-bit digest", "sha512_grp"),
    EngConstant("40e0104000000000", 32898.0, "0x0000000000008082", "sha3_keccak", "hash", 0.97, "SHA-3 (Keccak) sponge-based hash family, 24 rounds", "sha3_keccak_grp"),
    EngConstant("43e0000000000010", 9.223372036854809e+18, "0x800000000000808A", "sha3_keccak", "hash", 0.97, "SHA-3 (Keccak) sponge-based hash family, 24 rounds", "sha3_keccak_grp"),
    EngConstant("43e0000000100010", 9.223372039002292e+18, "0x8000000080008000", "sha3_keccak", "hash", 0.97, "SHA-3 (Keccak) sponge-based hash family, 24 rounds", "sha3_keccak_grp"),
    EngConstant("40e0116000000000", 32907.0, "0x000000000000808B", "sha3_keccak", "hash", 0.97, "SHA-3 (Keccak) sponge-based hash family, 24 rounds", "sha3_keccak_grp"),
    EngConstant("41e0000000200000", 2147483649.0, "0x0000000080000001", "sha3_keccak", "hash", 0.97, "SHA-3 (Keccak) sponge-based hash family, 24 rounds", "sha3_keccak_grp"),
    EngConstant("41eaed548f000000", 3614090360.0, "0xD76AA478", "md5", "hash", 0.98, "MD5 hash function, 64 rounds, 128-bit digest (BROKEN)", "md5_grp"),
    EngConstant("41ed18f6eac00000", 3905402710.0, "0xE8C7B756", "md5", "hash", 0.98, "MD5 hash function, 64 rounds, 128-bit digest (BROKEN)", "md5_grp"),
    EngConstant("41c210386d800000", 606105819.0, "0x242070DB", "md5", "hash", 0.98, "MD5 hash function, 64 rounds, 128-bit digest (BROKEN)", "md5_grp"),
    EngConstant("41e837b9ddc00000", 3250441966.0, "0xC1BDCEEE", "md5", "hash", 0.98, "MD5 hash function, 64 rounds, 128-bit digest (BROKEN)", "md5_grp"),
    EngConstant("43d443949feb79a1", 5.840696475078002e+18, "0x510E527FADE682D1", "blake2b", "hash", 0.93, "BLAKE2b hash, up to 512-bit digest, optimized for 64-bit platforms", "blake2b_grp"),
    EngConstant("43e360ad118567ce", 1.1170449401992606e+19, "0x9B05688C2B3E6C1F", "blake2b", "hash", 0.93, "BLAKE2b hash, up to 512-bit digest, optimized for 64-bit platforms", "blake2b_grp"),
    EngConstant("43bf83d9abfb41bd", 2.2708979698028864e+18, "0x1F83D9ABFB41BD6B", "blake2b", "hash", 0.93, "BLAKE2b hash, up to 512-bit digest, optimized for 64-bit platforms", "blake2b_grp"),
    EngConstant("43d6f8334644df88", 6.620516959819538e+18, "0x5BE0CD19137E2179", "blake2b", "hash", 0.93, "BLAKE2b hash, up to 512-bit digest, optimized for 64-bit platforms", "blake2b_grp"),
    EngConstant("41e52a7fa9c00000", 2840853838.0, "0xA953FD4E", "ripemd160", "hash", 0.93, "RIPEMD-160 hash, 160-bit, used in Bitcoin address generation", "ripemd160_grp"),
    EngConstant("41d428a2f9800000", 1352829926.0, "0x50A28BE6", "ripemd160", "hash", 0.93, "RIPEMD-160 hash, 160-bit, used in Bitcoin address generation", "ripemd160_grp"),
    EngConstant("41d7137449000000", 1548603684.0, "0x5C4DD124", "ripemd160", "hash", 0.93, "RIPEMD-160 hash, 160-bit, used in Bitcoin address generation", "ripemd160_grp"),
    EngConstant("41db5c0fbcc00000", 1836072691.0, "0x6D703EF3", "ripemd160", "hash", 0.93, "RIPEMD-160 hash, 160-bit, used in Bitcoin address generation", "ripemd160_grp"),
    EngConstant("41de9b5dba400000", 2053994217.0, "0x7A6D76E9", "ripemd160", "hash", 0.93, "RIPEMD-160 hash, 160-bit, used in Bitcoin address generation", "ripemd160_grp"),
    EngConstant("4038000000000000", 24.0, "24", "whirlpool", "hash", 0.90, "Whirlpool hash, 512-bit digest, AES-like internal structure", "whirlpool_grp"),
    EngConstant("4041800000000000", 35.0, "35", "whirlpool", "hash", 0.90, "Whirlpool hash, 512-bit digest, AES-like internal structure", "whirlpool_grp"),
    EngConstant("4068c00000000000", 198.0, "198", "whirlpool", "hash", 0.90, "Whirlpool hash, 512-bit digest, AES-like internal structure", "whirlpool_grp"),
    EngConstant("406d000000000000", 232.0, "232", "whirlpool", "hash", 0.90, "Whirlpool hash, 512-bit digest, AES-like internal structure", "whirlpool_grp"),
    EngConstant("4067000000000000", 184.0, "184", "whirlpool", "hash", 0.90, "Whirlpool hash, 512-bit digest, AES-like internal structure", "whirlpool_grp"),
    EngConstant("4053c00000000000", 79.0, "79", "whirlpool", "hash", 0.90, "Whirlpool hash, 512-bit digest, AES-like internal structure", "whirlpool_grp"),
    EngConstant("41dce0059bc00000", 1937774191.0, "0x7380166F", "sm3", "hash", 0.93, "SM3 Chinese national hash standard, 64 rounds, 256-bit", "sm3_grp"),
    EngConstant("41d2452cae400000", 1226093241.0, "0x4914B2B9", "sm3", "hash", 0.93, "SM3 Chinese national hash standard, 64 rounds, 256-bit", "sm3_grp"),
    EngConstant("41b72442d7000000", 388252375.0, "0x172442D7", "sm3", "hash", 0.93, "SM3 Chinese national hash standard, 64 rounds, 256-bit", "sm3_grp"),
    EngConstant("41eb5140c0000000", 3666478592.0, "0xDA8A0600", "sm3", "hash", 0.93, "SM3 Chinese national hash standard, 64 rounds, 256-bit", "sm3_grp"),
    EngConstant("41e52de617800000", 2842636476.0, "0xA96F30BC", "sm3", "hash", 0.93, "SM3 Chinese national hash standard, 64 rounds, 256-bit", "sm3_grp"),
    EngConstant("41b63138aa000000", 372324522.0, "0x163138AA", "sm3", "hash", 0.93, "SM3 Chinese national hash standard, 64 rounds, 256-bit", "sm3_grp"),
    EngConstant("41ec71bdc9a00000", 3817729613.0, "0xE38DEE4D", "sm3", "hash", 0.93, "SM3 Chinese national hash standard, 64 rounds, 256-bit", "sm3_grp"),
    EngConstant("41e61f61c9c00000", 2969243214.0, "0xB0FB0E4E", "sm3", "hash", 0.93, "SM3 Chinese national hash standard, 64 rounds, 256-bit", "sm3_grp"),
    EngConstant("41de731146400000", 2043430169.0, "0x79CC4519", "sm3", "hash", 0.93, "SM3 Chinese national hash standard, 64 rounds, 256-bit", "sm3_grp"),
    EngConstant("41dea1e762800000", 2055708042.0, "0x7A879D8A", "sm3", "hash", 0.93, "SM3 Chinese national hash standard, 64 rounds, 256-bit", "sm3_grp"),
    EngConstant("41d3dc9c1a000000", 1332899944.0, "0x4F727068", "bcrypt", "kdf", 0.93, "bcrypt password hashing (Blowfish-based)", "bcrypt_grp"),
    EngConstant("41d9585b90800000", 1700884034.0, "0x65616E42", "bcrypt", "kdf", 0.93, "bcrypt password hashing (Blowfish-based)", "bcrypt_grp"),
    EngConstant("41d95a1bdb000000", 1701343084.0, "0x65686F6C", "bcrypt", "kdf", 0.93, "bcrypt password hashing (Blowfish-based)", "bcrypt_grp"),
    EngConstant("41d9195c94c00000", 1684370003.0, "0x64657253", "bcrypt", "kdf", 0.93, "bcrypt password hashing (Blowfish-based)", "bcrypt_grp"),
    EngConstant("4033000000000000", 19.0, "19", "argon2", "kdf", 0.90, "Argon2 memory-hard password hashing (PHC winner)", "argon2_grp"),
    EngConstant("404b000000000000", 54.0, "54", "hmac", "mac", 0.95, "Hash-based Message Authentication Code", "hmac_grp"),
    EngConstant("4057000000000000", 92.0, "92", "hmac", "mac", 0.95, "Hash-based Message Authentication Code", "hmac_grp"),
    EngConstant("43dcdbdb595c1cd9", 8.31798731922233e+18, "0x736F6D6570736575", "siphash", "mac", 0.92, "SipHash-2-4 keyed hash (hash table DoS protection)", "siphash_grp"),
    EngConstant("43d91bdc985b991c", 7.237128888997147e+18, "0x646F72616E646F6D", "siphash", "mac", 0.92, "SipHash-2-4 keyed hash (hash table DoS protection)", "siphash_grp"),
    EngConstant("43db1e59d95b995d", 7.816392313619707e+18, "0x6C7967656E657261", "siphash", "mac", 0.92, "SipHash-2-4 keyed hash (hash table DoS protection)", "siphash_grp"),
    EngConstant("43dd1959189e5d19", 8.38722025515466e+18, "0x7465646279746573", "siphash", "mac", 0.92, "SipHash-2-4 keyed hash (hash table DoS protection)", "siphash_grp"),
    EngConstant("41edb71064000000", 3988292384.0, "0xEDB88320", "crc32", "checksum", 0.97, "CRC-32 cyclic redundancy check", "crc32_grp"),
    EngConstant("41930476dc000000", 79764919.0, "0x04C11DB7", "crc32", "checksum", 0.97, "CRC-32 cyclic redundancy check", "crc32_grp"),
    EngConstant("41ddc1cc25800000", 1996959894.0, "0x77073096", "crc32", "checksum", 0.97, "CRC-32 cyclic redundancy check", "crc32_grp"),
    EngConstant("41edc1cc25800000", 3993919788.0, "0xEE0E612C", "crc32", "checksum", 0.97, "CRC-32 cyclic redundancy check", "crc32_grp"),
    EngConstant("41e3212a37400000", 2567524794.0, "0x990951BA", "crc32", "checksum", 0.97, "CRC-32 cyclic redundancy check", "crc32_grp"),
    EngConstant("40b0210000000000", 4129.0, "0x1021", "crc16_ccitt", "checksum", 0.90, "CRC-16-CCITT checksum", "crc16_ccitt_grp"),
    EngConstant("40e0810000000000", 33800.0, "0x8408", "crc16_ccitt", "checksum", 0.90, "CRC-16-CCITT checksum", "crc16_ccitt_grp"),
    EngConstant("40effe2000000000", 65521.0, "0xFFF1", "adler32", "checksum", 0.92, "Adler-32 checksum (used in zlib)", "adler32_grp"),
    EngConstant("4088080000000000", 769.0, "0x0301", "tls12_handshake", "protocol", 0.88, "TLS 1.2 handshake protocol", "tls12_handshake_grp"),
    EngConstant("4088180000000000", 771.0, "0x0303", "tls12_handshake", "protocol", 0.88, "TLS 1.2 handshake protocol", "tls12_handshake_grp"),
    EngConstant("4030000000000000", 16.0, "16", "tls12_handshake", "protocol", 0.88, "TLS 1.2 handshake protocol", "tls12_handshake_grp"),
    EngConstant("4088200000000000", 772.0, "0x0304", "tls13_handshake", "protocol", 0.88, "TLS 1.3 handshake protocol (RFC 8446)", "tls13_handshake_grp"),
    EngConstant("40b3010000000000", 4865.0, "0x1301", "tls13_handshake", "protocol", 0.88, "TLS 1.3 handshake protocol (RFC 8446)", "tls13_handshake_grp"),
    EngConstant("40b3020000000000", 4866.0, "0x1302", "tls13_handshake", "protocol", 0.88, "TLS 1.3 handshake protocol (RFC 8446)", "tls13_handshake_grp"),
    EngConstant("40b3030000000000", 4867.0, "0x1303", "tls13_handshake", "protocol", 0.88, "TLS 1.3 handshake protocol (RFC 8446)", "tls13_handshake_grp"),
    EngConstant("4060400000000000", 130.0, "130", "x509_certificate", "pki", 0.85, "X.509 certificate parsing and validation", "x509_certificate_grp"),
    EngConstant("4037000000000000", 23.0, "23", "asn1_der", "pki", 0.82, "ASN.1 DER/BER encoding format", "asn1_der_grp"),
    EngConstant("4064000000000000", 160.0, "160", "asn1_der", "pki", 0.82, "ASN.1 DER/BER encoding format", "asn1_der_grp"),
    EngConstant("4064200000000000", 161.0, "161", "asn1_der", "pki", 0.82, "ASN.1 DER/BER encoding format", "asn1_der_grp"),
    EngConstant("4064600000000000", 163.0, "163", "asn1_der", "pki", 0.82, "ASN.1 DER/BER encoding format", "asn1_der_grp"),
    EngConstant("4049000000000000", 50.0, "50", "ipsec_esp", "network_security", 0.80, "IPsec Encapsulating Security Payload", "ipsec_esp_grp"),
    EngConstant("4049800000000000", 51.0, "51", "ipsec_ah", "network_security", 0.78, "IPsec Authentication Header", "ipsec_ah_grp"),
    EngConstant("4040800000000000", 33.0, "33", "ikev2", "network_security", 0.78, "IKEv2 key exchange for IPsec", "ikev2_grp"),
    EngConstant("4041000000000000", 34.0, "34", "ikev2", "network_security", 0.78, "IKEv2 key exchange for IPsec", "ikev2_grp"),
    EngConstant("4042000000000000", 36.0, "36", "ikev2", "network_security", 0.78, "IKEv2 key exchange for IPsec", "ikev2_grp"),
    EngConstant("4042800000000000", 37.0, "37", "ikev2", "network_security", 0.78, "IKEv2 key exchange for IPsec", "ikev2_grp"),
    EngConstant("4035000000000000", 21.0, "21", "ssh_key_exchange", "network_security", 0.82, "SSH key exchange protocol", "ssh_key_exchange_grp"),
    EngConstant("403f000000000000", 31.0, "31", "ssh_key_exchange", "network_security", 0.82, "SSH key exchange protocol", "ssh_key_exchange_grp"),
    EngConstant("4040000000000000", 32.0, "32", "ssh_key_exchange", "network_security", 0.82, "SSH key exchange protocol", "ssh_key_exchange_grp"),
    EngConstant("406e600000000000", 243.0, "243", "shadow_stack", "binary_security", 0.82, "Hardware shadow stack (Intel CET)", "shadow_stack_grp"),
    EngConstant("406f400000000000", 250.0, "250", "shadow_stack", "binary_security", 0.82, "Hardware shadow stack (Intel CET)", "shadow_stack_grp"),
    EngConstant("406f600000000000", 251.0, "251", "shadow_stack", "binary_security", 0.82, "Hardware shadow stack (Intel CET)", "shadow_stack_grp"),
    EngConstant("41ef5bc198000000", 4208856256.0, "0xFADE0CC0", "code_signing", "binary_security", 0.90, "Code signing verification (macOS/iOS)", "code_signing_grp"),
    EngConstant("41ef5bc198200000", 4208856257.0, "0xFADE0CC1", "code_signing", "binary_security", 0.90, "Code signing verification (macOS/iOS)", "code_signing_grp"),
    EngConstant("41ef5bc180000000", 4208856064.0, "0xFADE0C00", "code_signing", "binary_security", 0.90, "Code signing verification (macOS/iOS)", "code_signing_grp"),
    EngConstant("41ef5bc180200000", 4208856065.0, "0xFADE0C01", "code_signing", "binary_security", 0.90, "Code signing verification (macOS/iOS)", "code_signing_grp"),
    EngConstant("41ef5bc180400000", 4208856066.0, "0xFADE0C02", "code_signing", "binary_security", 0.90, "Code signing verification (macOS/iOS)", "code_signing_grp"),
    EngConstant("40a0000000000000", 2048.0, "0x0800", "anti_debug_sysctl", "anti_analysis", 0.90, "Anti-debugging via sysctl process flags", "anti_debug_sysctl_grp"),
    EngConstant("41d0000000000000", 1073741824.0, "0x40000000", "vm_detection_cpuid", "anti_analysis", 0.88, "Virtual machine detection via CPUID", "vm_detection_cpuid_grp"),
    EngConstant("41d593561a000000", 1447909480.0, "0x564D5868", "vm_detection_cpuid", "anti_analysis", 0.88, "Virtual machine detection via CPUID", "vm_detection_cpuid_grp"),
    EngConstant("4059800000000000", 102.0, "102", "aes_ni", "hardware_crypto", 0.99, "AES-NI hardware instructions", "aes_ni_grp"),
    EngConstant("404c000000000000", 56.0, "56", "aes_ni", "hardware_crypto", 0.99, "AES-NI hardware instructions", "aes_ni_grp"),
    EngConstant("406b800000000000", 220.0, "220", "aes_ni", "hardware_crypto", 0.99, "AES-NI hardware instructions", "aes_ni_grp"),
    EngConstant("406bc00000000000", 222.0, "222", "aes_ni", "hardware_crypto", 0.99, "AES-NI hardware instructions", "aes_ni_grp"),
    EngConstant("406be00000000000", 223.0, "223", "aes_ni", "hardware_crypto", 0.99, "AES-NI hardware instructions", "aes_ni_grp"),
    EngConstant("406b600000000000", 219.0, "219", "aes_ni", "hardware_crypto", 0.99, "AES-NI hardware instructions", "aes_ni_grp"),
    EngConstant("404d000000000000", 58.0, "58", "clmul", "hardware_crypto", 0.95, "Carry-less multiplication (CLMUL) for GF(2^n)", "clmul_grp"),
    EngConstant("4051000000000000", 68.0, "68", "clmul", "hardware_crypto", 0.95, "Carry-less multiplication (CLMUL) for GF(2^n)", "clmul_grp"),
    EngConstant("4069000000000000", 200.0, "200", "sha_ni", "hardware_crypto", 0.98, "SHA-NI hardware instructions for SHA-1/SHA-256", "sha_ni_grp"),
    EngConstant("4069200000000000", 201.0, "201", "sha_ni", "hardware_crypto", 0.98, "SHA-NI hardware instructions for SHA-1/SHA-256", "sha_ni_grp"),
    EngConstant("4069600000000000", 203.0, "203", "sha_ni", "hardware_crypto", 0.98, "SHA-NI hardware instructions for SHA-1/SHA-256", "sha_ni_grp"),
    EngConstant("4069a00000000000", 205.0, "205", "sha_ni", "hardware_crypto", 0.98, "SHA-NI hardware instructions for SHA-1/SHA-256", "sha_ni_grp"),
    EngConstant("4069c00000000000", 206.0, "206", "sha_ni", "hardware_crypto", 0.98, "SHA-NI hardware instructions for SHA-1/SHA-256", "sha_ni_grp"),
    EngConstant("405e000000000000", 120.0, "120", "zlib_deflate", "compression", 0.92, "zlib/deflate compression", "zlib_deflate_grp"),
    EngConstant("4057800000000000", 94.0, "94", "zlib_deflate", "compression", 0.92, "zlib/deflate compression", "zlib_deflate_grp"),
    EngConstant("4063800000000000", 156.0, "156", "zlib_deflate", "compression", 0.92, "zlib/deflate compression", "zlib_deflate_grp"),
    EngConstant("406b400000000000", 218.0, "218", "zlib_deflate", "compression", 0.92, "zlib/deflate compression", "zlib_deflate_grp"),
    EngConstant("4061600000000000", 139.0, "139", "zlib_deflate", "compression", 0.92, "zlib/deflate compression", "zlib_deflate_grp"),
    EngConstant("406fa00000000000", 253.0, "253", "lzma", "compression", 0.88, "LZMA/LZMA2/XZ compression", "lzma_grp"),
    EngConstant("404b800000000000", 55.0, "55", "lzma", "compression", 0.88, "LZMA/LZMA2/XZ compression", "lzma_grp"),
    EngConstant("405e800000000000", 122.0, "122", "lzma", "compression", 0.88, "LZMA/LZMA2/XZ compression", "lzma_grp"),
    EngConstant("4056000000000000", 88.0, "88", "lzma", "compression", 0.88, "LZMA/LZMA2/XZ compression", "lzma_grp"),
    EngConstant("4ff0000000000000", 1.157920892373162e+77, "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", "secp256k1", "elliptic_curve", 0.92, "secp256k1 elliptic curve (Bitcoin)", "secp256k1_grp"),
    EngConstant("4fefffffffe00000", 1.1579208921035625e+77, "0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", "secp256r1_p256", "elliptic_curve", 0.90, "NIST P-256 (secp256r1/prime256v1) elliptic curve", "secp256r1_p256_grp"),
    EngConstant("57f0000000000000", 3.940200619639448e+115, "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", "secp384r1_p384", "elliptic_curve", 0.85, "NIST P-384 (secp384r1) elliptic curve", "secp384r1_p384_grp"),
    EngConstant("41db01e259400000", 1812433253.0, "0x6C078965", "mersenne_twister", "random", 0.92, "Mersenne Twister MT19937 PRNG (NOT cryptographic)", "mersenne_twister_grp"),
    EngConstant("41d5541608400000", 1431328801.0, "0x55505821", "upx_packer", "packer", 0.95, "UPX packer detection", "upx_packer_grp"),
    EngConstant("43c11890ca7e15fc", 2.4637873949179884e+18, "0x22312194FC2BF72C", "sha512_256", "hash", 0.88, "SHA-512/256 hash (SHA-512 with different IV, truncated)", "sha512_256_grp"),
    EngConstant("43e3eaabf479098d", 1.1481187982095706e+19, "0x9F555FA3C84C64C2", "sha512_256", "hash", 0.88, "SHA-512/256 hash (SHA-512 with different IV, truncated)", "sha512_256_grp"),
    EngConstant("43c1c9dc35b7a9d9", 2.5635953844727117e+18, "0x2393B86B6F53B151", "sha512_256", "hash", 0.88, "SHA-512/256 hash (SHA-512 with different IV, truncated)", "sha512_256_grp"),
    EngConstant("43e2c70ee32b281d", 1.08245326551403e+19, "0x963877195940EABD", "sha512_256", "hash", 0.88, "SHA-512/256 hash (SHA-512 with different IV, truncated)", "sha512_256_grp"),
    EngConstant("42f01020305080d0", 282583128934413.0, "0x000101020305080D", "aegis", "aead", 0.80, "AEGIS AEAD (AES-based, very fast)", "aegis_grp"),
    EngConstant("43eb67a30aadb846", 1.5797809823078298e+19, "0xDB3D18556DC22FF1", "aegis", "aead", 0.80, "AEGIS AEAD (AES-based, very fast)", "aegis_grp"),
    EngConstant("43e4d4d4d4d4d4d5", 1.2008468691120728e+19, "0xA6A6A6A6A6A6A6A6", "aes_key_wrap", "symmetric_encryption", 0.88, "AES Key Wrap (RFC 3394)", "aes_key_wrap_grp"),
    EngConstant("41e4cb2b34c00000", 2790873510.0, "0xA65959A6", "aes_key_wrap", "symmetric_encryption", 0.88, "AES Key Wrap (RFC 3394)", "aes_key_wrap_grp"),
    EngConstant("4045800000000000", 43.0, "43", "rijndael_sbox_full", "symmetric_encryption", 0.99, "AES/Rijndael S-box (full 256-byte lookup table)", "rijndael_sbox_full_grp"),
    EngConstant("405f400000000000", 125.0, "125", "rijndael_sbox_full", "symmetric_encryption", 0.99, "AES/Rijndael S-box (full 256-byte lookup table)", "rijndael_sbox_full_grp"),
    EngConstant("4056400000000000", 89.0, "89", "rijndael_sbox_full", "symmetric_encryption", 0.99, "AES/Rijndael S-box (full 256-byte lookup table)", "rijndael_sbox_full_grp"),
    EngConstant("4051c00000000000", 71.0, "71", "rijndael_sbox_full", "symmetric_encryption", 0.99, "AES/Rijndael S-box (full 256-byte lookup table)", "rijndael_sbox_full_grp"),
    EngConstant("406e000000000000", 240.0, "240", "rijndael_sbox_full", "symmetric_encryption", 0.99, "AES/Rijndael S-box (full 256-byte lookup table)", "rijndael_sbox_full_grp"),
    EngConstant("4065a00000000000", 173.0, "173", "rijndael_sbox_full", "symmetric_encryption", 0.99, "AES/Rijndael S-box (full 256-byte lookup table)", "rijndael_sbox_full_grp"),
    EngConstant("406a800000000000", 212.0, "212", "rijndael_sbox_full", "symmetric_encryption", 0.99, "AES/Rijndael S-box (full 256-byte lookup table)", "rijndael_sbox_full_grp"),
    EngConstant("4064400000000000", 162.0, "162", "rijndael_sbox_full", "symmetric_encryption", 0.99, "AES/Rijndael S-box (full 256-byte lookup table)", "rijndael_sbox_full_grp"),
    EngConstant("4065e00000000000", 175.0, "175", "rijndael_sbox_full", "symmetric_encryption", 0.99, "AES/Rijndael S-box (full 256-byte lookup table)", "rijndael_sbox_full_grp"),
    EngConstant("405c800000000000", 114.0, "114", "rijndael_sbox_full", "symmetric_encryption", 0.99, "AES/Rijndael S-box (full 256-byte lookup table)", "rijndael_sbox_full_grp"),
    EngConstant("4068000000000000", 192.0, "192", "rijndael_sbox_full", "symmetric_encryption", 0.99, "AES/Rijndael S-box (full 256-byte lookup table)", "rijndael_sbox_full_grp"),
    EngConstant("4050000000000000", 64.0, "64", "aes_rcon", "symmetric_encryption", 0.95, "AES round constants (Rcon) for key expansion", "aes_rcon_grp"),
    EngConstant("4060000000000000", 128.0, "128", "aes_rcon", "symmetric_encryption", 0.95, "AES round constants (Rcon) for key expansion", "aes_rcon_grp"),
    EngConstant("403b000000000000", 27.0, "27", "aes_rcon", "symmetric_encryption", 0.95, "AES round constants (Rcon) for key expansion", "aes_rcon_grp"),
    EngConstant("41ccab612d800000", 961987163.0, "0x3956C25B", "sha256_k_constants", "hash", 0.99, "SHA-256 round constants K[0..63]", "sha256_k_constants_grp"),
    EngConstant("41d67c447c400000", 1508970993.0, "0x59F111F1", "sha256_k_constants", "hash", 0.99, "SHA-256 round constants K[0..63]", "sha256_k_constants_grp"),
    EngConstant("41e247f054800000", 2453635748.0, "0x923F82A4", "sha256_k_constants", "hash", 0.99, "SHA-256 round constants K[0..63]", "sha256_k_constants_grp"),
    EngConstant("41e5638bdaa00000", 2870763221.0, "0xAB1C5ED5", "sha256_k_constants", "hash", 0.99, "SHA-256 round constants K[0..63]", "sha256_k_constants_grp"),
    EngConstant("41eb00f553000000", 3624381080.0, "0xD807AA98", "sha256_k_constants", "hash", 0.99, "SHA-256 round constants K[0..63]", "sha256_k_constants_grp"),
    EngConstant("41b2835b01000000", 310598401.0, "0x12835B01", "sha256_k_constants", "hash", 0.99, "SHA-256 round constants K[0..63]", "sha256_k_constants_grp"),
    EngConstant("41c218c2df000000", 607225278.0, "0x243185BE", "sha256_k_constants", "hash", 0.99, "SHA-256 round constants K[0..63]", "sha256_k_constants_grp"),
    EngConstant("41d5431f70c00000", 1426881987.0, "0x550C7DC3", "sha256_k_constants", "hash", 0.99, "SHA-256 round constants K[0..63]", "sha256_k_constants_grp"),
    EngConstant("41dcaf975d000000", 1925078388.0, "0x72BE5D74", "sha256_k_constants", "hash", 0.99, "SHA-256 round constants K[0..63]", "sha256_k_constants_grp"),
    EngConstant("41e01bd63fc00000", 2162078206.0, "0x80DEB1FE", "sha256_k_constants", "hash", 0.99, "SHA-256 round constants K[0..63]", "sha256_k_constants_grp"),
    EngConstant("41e37b80d4e00000", 2614888103.0, "0x9BDC06A7", "sha256_k_constants", "hash", 0.99, "SHA-256 round constants K[0..63]", "sha256_k_constants_grp"),
    EngConstant("41e8337e2e800000", 3248222580.0, "0xC19BF174", "sha256_k_constants", "hash", 0.99, "SHA-256 round constants K[0..63]", "sha256_k_constants_grp"),
    EngConstant("41eeaf81f5e00000", 4118548399.0, "0xF57C0FAF", "md5_t_table", "hash", 0.99, "MD5 sine-derived round constants T[1..64]", "md5_t_table_grp"),
    EngConstant("41d1e1f18a800000", 1200080426.0, "0x4787C62A", "md5_t_table", "hash", 0.99, "MD5 sine-derived round constants T[1..64]", "md5_t_table_grp"),
    EngConstant("41e50608c2600000", 2821735955.0, "0xA8304613", "md5_t_table", "hash", 0.99, "MD5 sine-derived round constants T[1..64]", "md5_t_table_grp"),
    EngConstant("41efa8d2a0200000", 4249261313.0, "0xFD469501", "md5_t_table", "hash", 0.99, "MD5 sine-derived round constants T[1..64]", "md5_t_table_grp"),
    EngConstant("41da602636000000", 1770035416.0, "0x698098D8", "md5_t_table", "hash", 0.99, "MD5 sine-derived round constants T[1..64]", "md5_t_table_grp"),
    EngConstant("41e1689ef5e00000", 2336552879.0, "0x8B44F7AF", "md5_t_table", "hash", 0.99, "MD5 sine-derived round constants T[1..64]", "md5_t_table_grp"),
    EngConstant("41efffeb76200000", 4294925233.0, "0xFFFF5BB1", "md5_t_table", "hash", 0.99, "MD5 sine-derived round constants T[1..64]", "md5_t_table_grp"),
    EngConstant("41e12b9af7c00000", 2304563134.0, "0x895CD7BE", "md5_t_table", "hash", 0.99, "MD5 sine-derived round constants T[1..64]", "md5_t_table_grp"),
    EngConstant("41dae40448800000", 1804603682.0, "0x6B901122", "md5_t_table", "hash", 0.99, "MD5 sine-derived round constants T[1..64]", "md5_t_table_grp"),
    EngConstant("41efb30e32600000", 4254626195.0, "0xFD987193", "md5_t_table", "hash", 0.99, "MD5 sine-derived round constants T[1..64]", "md5_t_table_grp"),
    EngConstant("41e4cf2871c00000", 2792965006.0, "0xA679438E", "md5_t_table", "hash", 0.99, "MD5 sine-derived round constants T[1..64]", "md5_t_table_grp"),
    EngConstant("41d26d0208400000", 1236535329.0, "0x49B40821", "md5_t_table", "hash", 0.99, "MD5 sine-derived round constants T[1..64]", "md5_t_table_grp"),
    EngConstant("41a05df530000000", 137296536.0, "0x082EFA98", "blowfish_p_array_full", "symmetric_encryption", 0.97, "Blowfish P-array (18 subkeys from pi)", "blowfish_p_array_full_grp"),
    EngConstant("41ed89cd91200000", 3964562569.0, "0xEC4E6C89", "blowfish_p_array_full", "symmetric_encryption", 0.97, "Blowfish P-array (18 subkeys from pi)", "blowfish_p_array_full_grp"),
    EngConstant("41d14a0879800000", 1160258022.0, "0x452821E6", "blowfish_p_array_full", "symmetric_encryption", 0.97, "Blowfish P-array (18 subkeys from pi)", "blowfish_p_array_full_grp"),
    EngConstant("41cc6809bb800000", 953160567.0, "0x38D01377", "blowfish_p_array_full", "symmetric_encryption", 0.97, "Blowfish P-array (18 subkeys from pi)", "blowfish_p_array_full_grp"),
    EngConstant("41e7ca8cd9e00000", 3193202383.0, "0xBE5466CF", "blowfish_p_array_full", "symmetric_encryption", 0.97, "Blowfish P-array (18 subkeys from pi)", "blowfish_p_array_full_grp"),
    EngConstant("41ca748636000000", 887688300.0, "0x34E90C6C", "blowfish_p_array_full", "symmetric_encryption", 0.97, "Blowfish P-array (18 subkeys from pi)", "blowfish_p_array_full_grp"),
    EngConstant("41e8158536e00000", 3232508343.0, "0xC0AC29B7", "blowfish_p_array_full", "symmetric_encryption", 0.97, "Blowfish P-array (18 subkeys from pi)", "blowfish_p_array_full_grp"),
    EngConstant("41e92f8a1ba00000", 3380367581.0, "0xC97C50DD", "blowfish_p_array_full", "symmetric_encryption", 0.97, "Blowfish P-array (18 subkeys from pi)", "blowfish_p_array_full_grp"),
    EngConstant("41cfc26ada800000", 1065670069.0, "0x3F84D5B5", "blowfish_p_array_full", "symmetric_encryption", 0.97, "Blowfish P-array (18 subkeys from pi)", "blowfish_p_array_full_grp"),
    EngConstant("41e6a8e122e00000", 3041331479.0, "0xB5470917", "blowfish_p_array_full", "symmetric_encryption", 0.97, "Blowfish P-array (18 subkeys from pi)", "blowfish_p_array_full_grp"),
    EngConstant("41e242dabb200000", 2450970073.0, "0x9216D5D9", "blowfish_p_array_full", "symmetric_encryption", 0.97, "Blowfish P-array (18 subkeys from pi)", "blowfish_p_array_full_grp"),
    EngConstant("41e12f3f63600000", 2306472731.0, "0x8979FB1B", "blowfish_p_array_full", "symmetric_encryption", 0.97, "Blowfish P-array (18 subkeys from pi)", "blowfish_p_array_full_grp"),
    EngConstant("4061400000000000", 138.0, "138", "keccak_round_constants_full", "hash", 0.99, "Keccak/SHA-3 all 24 round constants", "keccak_round_constants_full_grp"),
    EngConstant("4061000000000000", 136.0, "136", "keccak_round_constants_full", "hash", 0.99, "Keccak/SHA-3 all 24 round constants", "keccak_round_constants_full_grp"),
    EngConstant("41e0001001200000", 2147516425.0, "0x0000000080008009", "keccak_round_constants_full", "hash", 0.99, "Keccak/SHA-3 all 24 round constants", "keccak_round_constants_full_grp"),
    EngConstant("41e0000001400000", 2147483658.0, "0x000000008000000A", "keccak_round_constants_full", "hash", 0.99, "Keccak/SHA-3 all 24 round constants", "keccak_round_constants_full_grp"),
    EngConstant("41e0001011600000", 2147516555.0, "0x000000008000808B", "keccak_round_constants_full", "hash", 0.99, "Keccak/SHA-3 all 24 round constants", "keccak_round_constants_full_grp"),
    EngConstant("43e0000000000000", 9.223372036854776e+18, "0x800000000000008B", "keccak_round_constants_full", "hash", 0.99, "Keccak/SHA-3 all 24 round constants", "keccak_round_constants_full_grp"),
    EngConstant("40e0014000000000", 32778.0, "0x000000000000800A", "keccak_round_constants_full", "hash", 0.99, "Keccak/SHA-3 all 24 round constants", "keccak_round_constants_full_grp"),
    EngConstant("43e0000000100000", 9.22337203900226e+18, "0x800000008000000A", "keccak_round_constants_full", "hash", 0.99, "Keccak/SHA-3 all 24 round constants", "keccak_round_constants_full_grp"),
    EngConstant("415ff80040000000", 8380417.0, "0x7FE001", "dilithium", "post_quantum", 0.82, "CRYSTALS-Dilithium / ML-DSA post-quantum signature", "dilithium_grp"),
    EngConstant("40aa020000000000", 3329.0, "0xD01", "kyber", "post_quantum", 0.82, "CRYSTALS-Kyber / ML-KEM post-quantum key encapsulation", "kyber_grp"),

    # --- Advanced Engineering (v1.2.2) ---
    EngConstant("3fdc71c71c71c71c", 0.4444444444444444, "0.444444", "lattice_boltzmann", "cfd_mesoscale", 0.90, "w0 = 4/9 center weight D2Q9", "lattice_boltzmann_grp"),
    EngConstant("3f9c71c71c71c723", 0.0277777777777778, "0.0277778", "lattice_boltzmann", "cfd_mesoscale", 0.90, "w2 = 1/36 diagonal weight D2Q9", "lattice_boltzmann_grp"),
    EngConstant("3f85748a7bd943f8", 0.010476190476, "0.0104762", "arruda_boyce", "fea_hyperelastic", 0.88, "11/1050", "arruda_boyce_grp"),
    EngConstant("3f663c450bf4c6ec", 0.002714285714, "0.00271429", "arruda_boyce", "fea_hyperelastic", 0.88, "19/7000", "arruda_boyce_grp"),
    EngConstant("3f493f4090c1b771", 0.000770479704, "0.00077048", "arruda_boyce", "fea_hyperelastic", 0.88, "519/673750", "arruda_boyce_grp"),
    EngConstant("40239a0000000000", 9.80665, "9.80665", "tsiolkovsky_rocket", "aerospace", 0.85, "Standard gravity m/s^2", "tsiolkovsky_rocket_grp"),
    EngConstant("42f6a8665bda5400", 398600441800000.0, "3.986e+14", "kepler_orbit", "aerospace", 0.85, "Earth gravitational parameter mu (m^3/s^2)", "kepler_orbit_grp"),
    EngConstant("4072013333333333", 288.15, "288.15", "isa_atmosphere", "aerospace", 0.88, "Sea level temperature (K)", "isa_atmosphere_grp"),
    EngConstant("40f8bfa800000000", 101325.0, "101325", "isa_atmosphere", "aerospace", 0.88, "Sea level pressure (Pa)", "isa_atmosphere_grp"),
    EngConstant("bf7aa93c7cac4586", -0.0065, "-0.0065", "isa_atmosphere", "aerospace", 0.88, "Temperature lapse rate (K/m)", "isa_atmosphere_grp"),
    EngConstant("4071f0e560418937", 287.058, "287.058", "isa_atmosphere", "aerospace", 0.88, "Specific gas constant dry air (J/kg/K)", "isa_atmosphere_grp"),
    EngConstant("3fdd43efc28d3d25", 0.45724, "0.45724", "peng_robinson_eos", "chemical_engineering", 0.88, "PR EOS parameter a coefficient", "peng_robinson_eos_grp"),
    EngConstant("3fb3ee63df1ac9e6", 0.0778, "0.0778", "peng_robinson_eos", "chemical_engineering", 0.88, "PR EOS parameter b coefficient", "peng_robinson_eos_grp"),
    EngConstant("3fdb5fcd7e9e4ccf", 0.42748, "0.42748", "srk_eos", "chemical_engineering", 0.86, "SRK parameter a coefficient", "srk_eos_grp"),
    EngConstant("3fb62d81d3d80b46", 0.08664, "0.08664", "srk_eos", "chemical_engineering", 0.86, "SRK parameter b coefficient", "srk_eos_grp"),
    EngConstant("3fe999999999999a", 0.8, "0.8", "genetic_algorithm", "optimization", 0.78, "Typical crossover probability", "genetic_algorithm_grp"),
    EngConstant("3fe75ebc4ce94e00", 0.7298, "0.7298", "particle_swarm", "optimization", 0.85, "Constriction coefficient inertia weight", "particle_swarm_grp"),
    EngConstant("3ff7f1d86c44c27e", 1.49618, "1.49618", "particle_swarm", "optimization", 0.85, "Cognitive (personal best) parameter", "particle_swarm_grp"),
    EngConstant("4002555555555556", 2.291666666666667, "2.29167", "adams_bashforth", "time_integration", 0.82, "55/24 Adams-Bashforth 4 coefficient", "adams_bashforth_grp"),
    EngConstant("c003aaaaaaaaaaaa", -2.458333333333333, "-2.45833", "adams_bashforth", "time_integration", 0.82, "-59/24 Adams-Bashforth 4 coefficient", "adams_bashforth_grp"),
    EngConstant("3ff8aaaaaaaaaaac", 1.541666666666667, "1.54167", "adams_bashforth", "time_integration", 0.82, "37/24 Adams-Bashforth 4 coefficient", "adams_bashforth_grp"),
    EngConstant("bfd8000000000000", -0.375, "-0.375", "adams_bashforth", "time_integration", 0.82, "-9/24 Adams-Bashforth 4 coefficient", "adams_bashforth_grp"),
    EngConstant("3f978d4fdf3b645a", 0.023, "0.023", "nusselt_correlation", "heat_transfer", 0.82, "Dittus-Boelter coefficient", "nusselt_correlation_grp"),
    EngConstant("4096b00000000000", 1708.0, "1708", "rayleigh_benard", "heat_transfer", 0.82, "Critical Rayleigh number for onset of Benard convection", "rayleigh_benard_grp"),
    EngConstant("3ff6666666666666", 1.4, "1.4", "wilson_theta", "structural_dynamics", 0.78, "Typical Wilson theta parameter for unconditional stability", "wilson_theta_grp"),
    EngConstant("4014cccccccccccd", 5.2, "5.2", "turbulence_wall_function", "cfd_turbulence", 0.85, "Log-law additive constant (smooth wall)", "turbulence_wall_function_grp"),
    EngConstant("40261eb851eb851f", 11.06, "11.06", "turbulence_wall_function", "cfd_turbulence", 0.85, "Viscous-log layer transition y+", "turbulence_wall_function_grp"),
    EngConstant("4002000000000000", 2.25, "2.25", "gurson_tvergaard_needleman", "fea_damage", 0.85, "GTN model parameter q3 (=q1^2)", "gurson_tvergaard_needleman_grp"),


]


# ---------------------------------------------------------------------------
# O(1) hex lookup tablosu
# Pozitif, negatif ve little-endian varyantlarini da ekle.
# Ghidra ARM64 decompile ciktisinda sabitler:
#   - Big-endian: 0x3fe279a74590331d (pozitif 1/sqrt(3))
#   - Negatif:    0xbfe279a74590331d (isaret biti flip)
#   - Little-end: 0x1d339045a779e23f (byte-reversed)
# ---------------------------------------------------------------------------

import struct as _struct

HEX_LOOKUP: dict[str, list[EngConstant]] = {}
for _c in ENGINEERING_CONSTANTS:
    # Orijinal (big-endian pozitif)
    HEX_LOOKUP.setdefault(_c.hex_pattern, []).append(_c)

    # Negatif formu ekle (sign bit flip: bit 63)
    try:
        _raw = int(_c.hex_pattern, 16)
        _neg = _raw ^ 0x8000000000000000  # IEEE-754 sign bit flip
        _neg_hex = f"{_neg:016x}"
        HEX_LOOKUP.setdefault(_neg_hex, []).append(_c)
    except (ValueError, OverflowError):
        pass

    # Little-endian formu ekle (byte-reversed)
    try:
        _be_bytes = bytes.fromhex(_c.hex_pattern)
        _le_hex = _be_bytes[::-1].hex()
        HEX_LOOKUP.setdefault(_le_hex, []).append(_c)
        # Little-endian negatif
        _neg_be = bytes.fromhex(_neg_hex)
        _neg_le_hex = _neg_be[::-1].hex()
        HEX_LOOKUP.setdefault(_neg_le_hex, []).append(_c)
    except (ValueError, OverflowError):
        pass


# ---------------------------------------------------------------------------
# Ondalik pattern listesi -- regex ile decimal literal taramasi icin
# Tuple: (short_decimal_str, EngConstant)
# ---------------------------------------------------------------------------

DECIMAL_PATTERNS: list[tuple[str, EngConstant]] = [
    (_c.decimal_pattern, _c) for _c in ENGINEERING_CONSTANTS
]
