"""Decompile edilmis C kodunda algoritma tespiti -- sabit, yapi ve API bazli.

Ghidra decompile ciktisindaki C kaynak kodunu analiz ederek kullanilan
kriptografik algoritmalari, hash fonksiyonlarini ve diger bilinen
algoritmalari tespit eder.

Uc katmanli tespit:
1. Constant-Based: Bilinen kriptografik sabitleri (S-box, init vectors) arar
2. Structure-Based: Kod yapisindan algoritma pattern'lerini tanir
3. API Correlation: Bilinen crypto API cagrilarini eslestirir

String matching'den farkli olarak gercek kod yapisina ve sabit degerlerine bakar.
"""

from __future__ import annotations

import json
import logging
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from karadul.config import CPU_PERF_CORES, Config

logger = logging.getLogger(__name__)

# v1.4.2+: BLAS/LAPACK/ML kutuphane indicator'leri.
# Binary'deki fonksiyon isimlerinde bunlardan biri varsa numeric library olarak
# isaretlenir.  stages.py de ayni listeyi kullanir -- TEK YERDE tanimla.
BLAS_ML_INDICATORS: frozenset[str] = frozenset({
    "cblas_", "sgemm", "dgemm", "dsyev", "dgesv", "dgetrf",
    "faiss", "openblas", "lapack", "mkl_", "blas_",
    "cublas", "cusolver", "cusparse", "cufft",
    "aten_", "torch_", "caffe_", "onnx_",
    "vdsp_", "accelerate_", "veclib_",
    "eigen_", "armadillo_",
})


# ---------------------------------------------------------------------------
# Sabit-tabanlı tespit kuralları (2026-11-10 düzeltmesi)
# ---------------------------------------------------------------------------
# Eski kural sabiti gövdede alt dize olarak arıyordu ("0x1", her "0x1..." sayısının
# içinde bulunuyordu; "0xfffffff", her 0xffffffff'in içinde) ve büyük sabitli bir
# grubun yarısını yeterli sayıyordu. Sonuç: kripto içermeyen Mac tmux'ta 1901,
# htop'ta 355 sabit-tabanlı etiket (çoğu Keccak/SHA-3 ve Poly1305).
#
# Yeni kural:
#   1. Sabit yalnız bütün bir sayı belirteci (token) olarak eşleşir; yorum ve dizge
#      içindekiler sayılmaz. Belirteç onaltılık ya da ondalık, U/L/UL/LL/ULL ekli olabilir.
#      Her belirteç ikiye tümleyen eşiyle (32 ve 64 bit) de denenir: Ghidra 0xd76aa478'i
#      "-0x28955b88" diye, "sum -= 0x9e3779b9" satırını "sum + 0x61c88647" diye basabilir.
#   2. 64 bitlik bir belirtecin iki 32 bitlik yarısı da aynı algoritmanın ayırt edici
#      sabitiyse iki sabit de bulunmuş sayılır: Ghidra yan yana iki 32 bitlik alana
#      yazmayı tek sabite birleştirir (SHA1Init: 0xefcdab8967452301). Yarılar tek tek
#      kanıt sayılmaz (SHA-512'nin 0x6a09e667f3bcc908'i SHA-256 H0 vermez).
#   3. Zayıf sabitler (küçük değerler, 2'nin kuvvetleri, maskeler, tekrar desenleri)
#      hiçbir zaman kanıt değildir.
#   4. Etiket için aynı fonksiyonda algoritmaya ait en az CONST_MIN_DISTINCT farklı
#      ayırt edici sabit gerekir.
#   5. Küçük değerli tablolar (S-kutusu, permütasyon) yalnız listedeki sıranın
#      tamamı kesintisiz bir sayı dizisi olarak geçerse kanıttır.
#   6. Birden çok algoritmanın ortak sabitleri (SHA-512 H = BLAKE2b IV, MD5 init =
#      SHA-1 H0-H3) tek başına bir algoritma seçtirmez: başka bir algoritmanın kendine
#      özgü sabiti yoksa etiket "BLAKE2/SHA-512" gibi ortak ad taşır.

#: Bu değere kadar (dahil) olan sabitler tek başına hiçbir zaman kanıt sayılmaz
#: (0x36, 0x5c, 0xff, 0x1021, tablo indisleri, kaydırma miktarları).
CONST_WEAK_MAX: int = 0xFFFF
#: 1 bitlerinin (ya da 0 bitlerinin) sayısı bu değere eşit ya da küçükse sabit zayıftır:
#: 2'nin kuvvetleri, 0x80000001, 0xfffffffe, 0x7fffffff.
CONST_WEAK_MAX_POPCOUNT: int = 2
#: Bu periyotlarla (bit) kendini tekrar eden sabitler zayıftır: 0x01010101, 0xff00ff00, 0x55555555.
CONST_WEAK_PERIODS_BITS: tuple[int, ...] = (4, 8, 16)
#: Bir algoritmanın etiketi için aynı fonksiyonda gereken farklı ayırt edici sabit sayısı.
CONST_MIN_DISTINCT: int = 2
#: Algoritmaya özgü istisnalar.
CONST_MIN_DISTINCT_OVERRIDES: dict[str, int] = {
    # Bit bit CRC32 gerçeklemesinin tek tanımlayıcı sabiti polinomdur (0xEDB88320,
    # 32 bit, yüksek entropi); tablo .rodata'da olduğundan başka sabit görünmez.
    "CRC32": 1,
    # Keccak tur sabitleri seyrek bitli desenlerdir; tek tek bayrak değerlerine
    # benzedikleri için üç farklı sabit istenir.
    "Keccak/SHA-3": 3,
}
#: Küçük değerli bir tablonun (bütün değerleri <= CONST_WEAK_MAX) kanıt sayılması için
#: listedeki dizinin en az bu kadar öğesi olmalı ve dizinin tamamı sırayla görünmeli.
CONST_SEQUENCE_MIN_LEN: int = 8
#: Sabit taraması bu uzunluktan kısa fonksiyon gövdelerini atlar. Eski 500 sınırı
#: alt dize eşleşmesinin yanlışlarını bastırmak içindi; SHA1Init gibi gerçek başlatma
#: fonksiyonları ~130 karakterdir. Kanıt artık ayırt edici sabit kümesine dayandığı
#: için sınır kaldırıldı (0).
CONST_SCAN_MIN_BODY_CHARS: int = 0
#: 32 ve 64 bitlik değer maskeleri.
_MASK32: int = (1 << 32) - 1
_MASK64: int = (1 << 64) - 1


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class AlgorithmMatch:
    """Tespit edilen tek bir algoritma eslesmesi.

    Attributes:
        name: Algoritma adi (orn. "AES-256-CBC").
        category: Kategori -- symmetric_cipher, hash, mac, asymmetric, kdf, checksum.
        confidence: Guven skoru 0.0-1.0.
        detection_method: Tespit yontemi -- constant, structural, api.
        evidence: Tespit kaniti olan string/deger listesi.
        function_name: Hangi fonksiyonda bulundu.
        address: Fonksiyon adresi (0x...).
    """

    name: str
    category: str
    confidence: float
    detection_method: str
    evidence: list[str]
    function_name: str
    address: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "confidence": self.confidence,
            "detection_method": self.detection_method,
            "evidence": self.evidence,
            "function_name": self.function_name,
            "address": self.address,
        }


@dataclass
class CAlgorithmResult:
    """Algoritma tespit sonucu.

    Attributes:
        success: Islem basarili mi.
        algorithms: Tespit edilen algoritma listesi.
        total_detected: Toplam tespit sayisi.
        by_category: Kategoriye gore dagilim.
        by_confidence: Guven seviyesine gore dagilim (high/medium/low).
        errors: Hata mesajlari.
    """

    success: bool
    algorithms: list[AlgorithmMatch] = field(default_factory=list)
    total_detected: int = 0
    by_category: dict[str, int] = field(default_factory=dict)
    by_confidence: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    # v1.6.5: GPU domain classification -- per-function domain probability vectors.
    # {func_name: [(domain_name, probability), ...]} or None if not computed.
    domain_classification: dict[str, list[tuple[str, float]]] | None = None

    def to_dict(self) -> dict[str, Any]:
        result = {
            "success": self.success,
            "algorithms": [a.to_dict() for a in self.algorithms],
            "total_detected": self.total_detected,
            "by_category": self.by_category,
            "by_confidence": self.by_confidence,
            "errors": self.errors,
        }
        # v1.6.5: include domain classification if available
        if self.domain_classification is not None:
            result["domain_classification"] = self.domain_classification
        return result


# ---------------------------------------------------------------------------
# Yaklasim 1: Sabit-bazli tanimlar (Constant-Based Identification)
# ---------------------------------------------------------------------------

# Tablolar matematiksel tanımlarından üretilip testte yeniden hesaplanarak denetlenir
# (tests/test_c_algorithm_id_sabit.py): SHA-2 K/H asal köklerinin kesirleri, MD5 T
# sinüs değerleri, Keccak RC LFSR çıktısı, Camellia Σ karekök kesirleri.
# Küçük ya da zayıf değerler listede kalabilir; kanıt olarak süzülürler (bkz. kurallar).
ALGORITHM_SIGNATURES: dict[str, dict[str, list[int]]] = {
    "AES": {
        # Küçük değerli tablolar: yalnız sıralı ve kesintisiz dizi olarak kanıt.
        "sbox": [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5],
        # rcon 2'nin kuvvetleridir; zayıf dizi, hiçbir zaman kanıt değil.
        "rcon": [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80],
        "inv_sbox": [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38],
    },
    "SHA-256": {
        "k_constants": [
            0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
            0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
            0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
            0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
            0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
            0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
            0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
            0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
        ],
        "h_init": [
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
        ],
    },
    "SHA-512": {
        "k_constants": [
            0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
            0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
            0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
            0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
            0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
            0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
            0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
            0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
            0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
            0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
            0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
            0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
            0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
            0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
            0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
            0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
            0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
            0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
            0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
            0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817,
        ],
        # BLAKE2b IV ile aynı; yalnız bunlarla eşleşen fonksiyon "BLAKE2/SHA-512" olur.
        "h_init": [
            0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
            0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
        ],
    },
    "SHA-1": {
        # H0-H3 MD5 init ile ortak; H4 (0xC3D2E1F0) SHA-1'e özgü.
        "h_init": [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
        "k_constants": [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6],
    },
    "MD5": {
        "t_values": [
            0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE, 0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
            0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE, 0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
            0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA, 0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
            0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED, 0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
            0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C, 0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
            0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05, 0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
            0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039, 0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
            0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1, 0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
        ],
        "init": [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476],
    },
    "CRC32": {
        "polynomial": [0xEDB88320],
        "table_start": [0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA],
    },
    "CRC16-CCITT": {
        # 0x1021 zayıf (<= CONST_WEAK_MAX): sabitle etiket veremez, kayıt uyumluluk için duruyor.
        "polynomial": [0x1021],
    },
    "DES": {
        # ip_table: 16+ eleman -- kisa diziler her yerde bulunur, uzun tablo benzersiz.
        # Küçük değerli tablo: yalnız 32 öğenin tamamı sırayla ve kesintisiz geçerse kanıt.
        "ip_table": [
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
        ],
        # sbox1 SILINDI: 0-15 arasi sayilar her yerde FP uretiyor
    },
    # 3DES SILINDI: DES ile birebir ayni sabitler, ayri entry gereksiz
    # RSA SILINDI: Tek sabit (65537) ile tespit guvenilmez, structural+API ile yapiliyor
    # HMAC SILINDI: ipad/opad (0x36/0x5C tekrarlari) her yerde bulunur, API ile tespit ediliyor
    # RC4 SILINDI: identity_permutation (0-15) en yaygin FP kaynagi
    "ChaCha20/Salsa20": {
        # sigma: "expand 32-byte k" -- ChaCha20 ve Salsa20 ortak sabiti
        "sigma": [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574],
        # tau: "expand 16-byte k" -- sadece Salsa20 128-bit key
        "tau": [0x61707865, 0x3120646E, 0x79622D36, 0x6B206574],
    },
    "Blowfish": {
        "p_array_start": [0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344],
    },
    "Twofish": {
        # 0x169 ve 0x14D zayıf: sabitle etiket veremez, kayıt uyumluluk için duruyor.
        "mds_poly": [0x169],
        "rs_poly": [0x14D],
    },
    "Poly1305": {
        # RFC 7539 kenetleme maskesinin 32 bitlik sözcükleri (0x0FFFFFFF, 0x0FFFFFFC) tek
        # parça maskedir, her yerde geçer ve kanıt sayılmaz (eski kuralda 0x0FFFFFFF,
        # 0xFFFFFFFF'in alt dizesi olarak her fonksiyonda bulunuyordu). Kanıt olarak
        # kenetlemenin 64 bitlik biçimleri ve poly1305-donna sınır maskeleri kullanılır.
        "clamp": [0x0FFFFFFC0FFFFFFF, 0x0FFFFFFC0FFFFFFC],
        "donna_masks": [
            0x3FFFF03, 0x3FFC0FF, 0x3F03FFF,             # donna-32: r1..r3
            0xFFC0FFFFFFF, 0xFFFFFC0FFFF, 0xFFFFFFC0F,  # donna-64: r0..r2
        ],
    },
    "GOST": {
        "sbox1": [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
    },
    "Keccak/SHA-3": {
        # 24 tur sabitinin hepsi; <= 0xFFFF olanlar ve 2 bitli olanlar (0x80000001,
        # 0x8000000000000080) zayıf sayılıp süzülür, geriye 14 ayırt edici değer kalır.
        "round_constants": [
            0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
            0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
            0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
            0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
            0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
            0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
        ],
    },
    "BLAKE2": {
        # BLAKE2b IV = SHA-512 H; yalnız bunlarla eşleşen fonksiyon "BLAKE2/SHA-512" olur.
        "iv": [
            0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
            0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
        ],
        # sigma_first_row SILINDI: [0,1,2,...,7] her yerde FP uretiyor
    },
    "Whirlpool": {
        "sbox": [0x18, 0x23, 0xC6, 0xE8, 0x87, 0xB8, 0x01, 0x4F],
    },
    "CAST5": {
        "sbox1_start": [0x30FB40D4, 0x9FA0FF0B, 0x6BECCD2F, 0x3F258C7A],
    },
    "IDEA": {
        # 2^16 + 1 (aynı zamanda RSA üssü 65537): zayıf, sabitle etiket veremez.
        "mul_mod": [0x10001],
    },
    "Serpent/TEA/XTEA": {
        # Altın oran sabiti karma fonksiyonlarında da yaygın (Fibonacci karması, zstd);
        # tek başına yetmez. TEA/XTEA şifre çözmesinin başlangıç toplamı 32*delta ile
        # birlikte görülürse etiket verilir.
        "golden_ratio": [0x9E3779B9],
        "decrypt_sum": [0xC6EF3720],
    },
    "Camellia": {
        "sigma1": [0xA09E667F, 0x3BCC908B],
        # Σ1..Σ6 64 bitlik biçimleri (2, 3, 5, 7, 11, 13'ün karekök kesirleri).
        "sigma64": [
            0xA09E667F3BCC908B, 0xB67AE8584CAA73B2, 0xC6EF372FE94F82BE,
            0x54FF53A5F1D36F1C, 0x10E527FADE682D1D, 0xB05688C2B3E6C1FD,
        ],
    },
}

# Sabit -> algoritma kategorisi eslestirmesi
_ALGO_CATEGORIES: dict[str, str] = {
    "AES": "symmetric_cipher",
    "DES": "symmetric_cipher",
    "Blowfish": "symmetric_cipher",
    "Twofish": "symmetric_cipher",
    "ChaCha20/Salsa20": "symmetric_cipher",
    "GOST": "symmetric_cipher",
    "CAST5": "symmetric_cipher",
    "IDEA": "symmetric_cipher",
    "Serpent/TEA/XTEA": "symmetric_cipher",
    "Camellia": "symmetric_cipher",
    "SHA-256": "hash",
    "SHA-512": "hash",
    "SHA-1": "hash",
    "MD5": "hash",
    "Keccak/SHA-3": "hash",
    "BLAKE2": "hash",
    "Whirlpool": "hash",
    "CRC32": "checksum",
    "CRC16-CCITT": "checksum",
    "Poly1305": "mac",
}


# ---------------------------------------------------------------------------
# Sabit-tabanlı tespit yardımcıları
# ---------------------------------------------------------------------------

# Bütün bir sayı belirteci: önünde harf/rakam/_/. yok, arkasında da yok (DAT_00123456,
# FUN_0010b340 ve 1.5e10 içindeki rakamlar sayılmaz). Onaltılık ya da ondalık gövde,
# C tamsayı ekleri (U, L, UL, LL, ULL, LU, LLU; büyük/küçük harf). Eksi işareti belirtece
# katılmaz; her belirteç ikiye tümleyen eşiyle de denendiği için gerekmez.
_NUM_TOKEN_RE = re.compile(
    r"(?<![\w.])(?P<num>0[xX][0-9a-fA-F]+|\d+)"
    r"(?:[uU](?:ll|LL|[lL])?|(?:ll|LL|[lL])[uU]?)?(?![\w.])"
)
# Yorumlar ve dizge/karakter sabitleri; soldan sağa ilk gelen kazanır, böylece
# dizge içindeki "/*" ya da yorum içindeki tırnak öbürünü bozmaz.
_COMMENT_OR_STRING_RE = re.compile(
    r"/\*.*?\*/|//[^\n]*|\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'",
    re.DOTALL,
)
# Bir dizi (ilklendirme listesi) içinde iki belirteç arasında yalnız virgül ve boşluk olur.
_RUN_SEPARATOR_RE = re.compile(r"\s*,\s*")


def _is_weak_constant(value: int) -> bool:
    """Sabit tek başına kanıt olamayacak kadar yaygın mı?

    Zayıf: CONST_WEAK_MAX'a kadar her değer; 1 ya da 0 bitleri en çok
    CONST_WEAK_MAX_POPCOUNT olan değerler; tek kesintisiz 1 bloğu olan maskeler
    (0x0fffffff, 0xfffffff0); CONST_WEAK_PERIODS_BITS periyotlarıyla tekrar eden desenler.
    """
    if value <= CONST_WEAK_MAX:
        return True
    width = 32 if value <= _MASK32 else 64
    width_mask = (1 << width) - 1
    if bin(value).count("1") <= CONST_WEAK_MAX_POPCOUNT:
        return True
    if bin(~value & width_mask).count("1") <= CONST_WEAK_MAX_POPCOUNT:
        return True
    shifted = value >> ((value & -value).bit_length() - 1)
    if shifted & (shifted + 1) == 0:
        return True
    for period in CONST_WEAK_PERIODS_BITS:
        unit = value & ((1 << period) - 1)
        repeated = 0
        for i in range(width // period):
            repeated |= unit << (i * period)
        if repeated == value:
            return True
    return False


def _is_weak_sequence(values: list[int]) -> bool:
    """Küçük değerli bir tablo sıralı dizi olarak bile kanıt olamayacak kadar sıradan mı?

    Zayıf: CONST_SEQUENCE_MIN_LEN'den az farklı değer; yalnız 0 ve 2'nin kuvvetleri
    (AES rcon, bayrak tabloları); sabit adımlı aritmetik dizi (0,1,2,...; 56,48,40,...).
    """
    if len(set(values)) < CONST_SEQUENCE_MIN_LEN:
        return True
    if all(v == 0 or v & (v - 1) == 0 for v in values):
        return True
    steps = {b - a for a, b in zip(values, values[1:])}
    return len(steps) == 1


@dataclass(frozen=True)
class _ConstGroup:
    """Bir imza grubunun kanıt olarak kullanılabilir hali.

    Attributes:
        label: Grup adı (ALGORITHM_SIGNATURES anahtarı).
        values: Ayırt edici skaler değerler; zayıflar süzülmüş, liste sırası korunmuş.
        sequence: Küçük değerli tablo kanıtı olarak aranacak sıralı dizi ya da None.
    """

    label: str
    values: tuple[int, ...]
    sequence: tuple[int, ...] | None


def _build_const_index(
    signatures: dict[str, dict[str, list[int]]],
) -> tuple[dict[str, list[_ConstGroup]], dict[int, frozenset[str]]]:
    """İmza tablosundan grup kanıt tanımlarını ve değer -> sahip algoritmalar dizinini kur."""
    groups_by_algo: dict[str, list[_ConstGroup]] = {}
    owners: dict[int, set[str]] = {}
    for algo, groups in signatures.items():
        specs: list[_ConstGroup] = []
        for label, constants in groups.items():
            unique = tuple(dict.fromkeys(constants))
            if all(c <= CONST_WEAK_MAX for c in unique):
                is_table = (
                    len(constants) >= CONST_SEQUENCE_MIN_LEN
                    and not _is_weak_sequence(list(constants))
                )
                specs.append(_ConstGroup(label, (), tuple(constants) if is_table else None))
                continue
            values = tuple(c for c in unique if not _is_weak_constant(c))
            specs.append(_ConstGroup(label, values, None))
            for v in values:
                owners.setdefault(v, set()).add(algo)
        groups_by_algo[algo] = specs
    return groups_by_algo, {v: frozenset(a) for v, a in owners.items()}


def _collect_constant_tokens(body: str) -> tuple[set[int], list[int], list[list[set[int]]]]:
    """Gövdedeki sayı belirteçlerini topla (yorum ve dizgeler atılarak).

    Returns:
        (değerler, 64 bitlik değerler, diziler):
        - değerler: her belirtecin olası değerleri: kendisi ve 32/64 bitlik ikiye tümleyen
          eşi. Toplanan sabit Ghidra'da üç biçimde görünebilir: "x + 0xd76aa478",
          "x + -0x28955b88", "x - 0x28955b88"; TEA'nın "sum -= 0x9e3779b9" satırı da
          "sum + 0x61c88647" olarak basılır.
        - 64 bitlik değerler: 32 bitlik yarılara bölünmeye aday (> 0xFFFFFFFF) değerler.
        - diziler: yalnız virgülle ayrılmış ardışık belirteçlerin değer kümeleri listesi
          (ilklendirme listesi ya da argüman listesi); küçük tablo dizisi araması için.
    """
    clean = _COMMENT_OR_STRING_RE.sub(" ", body)
    values: set[int] = set()
    wide: list[int] = []
    runs: list[list[set[int]]] = []
    current: list[set[int]] = []
    prev_end = -1
    for m in _NUM_TOKEN_RE.finditer(clean):
        num = m.group("num")
        mag = int(num, 16) if num[:2] in ("0x", "0X") else int(num)
        cands = {mag & _MASK64, (-mag) & _MASK64}
        if mag <= (1 << 32):
            cands.add((-mag) & _MASK32)
        values |= cands
        wide.extend(c for c in cands if c > _MASK32)
        if prev_end >= 0 and _RUN_SEPARATOR_RE.fullmatch(clean, prev_end, m.start()):
            current.append(cands)
        else:
            if len(current) >= CONST_SEQUENCE_MIN_LEN:
                runs.append(current)
            current = [cands]
        prev_end = m.end()
    if len(current) >= CONST_SEQUENCE_MIN_LEN:
        runs.append(current)
    return values, wide, runs


def _contains_sequence(runs: list[list[set[int]]], sequence: tuple[int, ...]) -> bool:
    """Dizi, belirteç dizilerinden birinde kesintisiz ve sırayla geçiyor mu?"""
    n = len(sequence)
    for run in runs:
        for start in range(len(run) - n + 1):
            if all(sequence[i] in run[start + i] for i in range(n)):
                return True
    return False


# ---------------------------------------------------------------------------
# Yaklasim 2: Yapi-bazli tanimlar (Structure-Based Identification)
# ---------------------------------------------------------------------------

STRUCTURAL_PATTERNS: dict[str, dict[str, Any]] = {
    "feistel_network": {
        "description": "Feistel cipher (DES, Blowfish, etc.)",
        "patterns": [
            re.compile(r"(\w+)\s*=\s*(\w+)\s*\^\s*\w+\(.+\)"),
            re.compile(r"(\w+)\s*=\s*(\w+);.*\n.*\2\s*="),
        ],
        "min_matches": 16,
        "category": "symmetric_cipher",
        "confidence": 0.4,
        "context_keywords": ["round", "left", "right", "feistel", "block", "half", "swap"],
        "suppress_if_blas": True,
    },
    "sbox_lookup": {
        "description": "S-box substitution (AES, DES)",
        "patterns": [
            re.compile(r"\w+\[.+\s*&\s*0x[fF]{1,2}\]"),
            re.compile(r"\w+\[.+>>\s*\d+\s*&\s*0x[fF]+\]"),
        ],
        "min_matches": 2,
        "category": "symmetric_cipher",
        "confidence": 0.5,
    },
    "xor_encrypt_loop": {
        "description": "XOR-based encryption/decryption",
        "patterns": [
            # v1.7.x: .+ -> [^)]+ -- DOTALL'da .+ tum inputu tuketir, backtracking yapar
            re.compile(r"for\s*\([^)]+\)\s*\{[^}]*\^=", re.DOTALL),
            re.compile(r"while\s*\([^)]+\)\s*\{[^}]*\^=", re.DOTALL),
        ],
        "min_matches": 1,
        "category": "symmetric_cipher",
        "confidence": 0.3,
    },
    "hash_rounds": {
        "description": "Hash function rounds (SHA, MD5)",
        "patterns": [
            re.compile(r">>>\s*\d+|<<<\s*\d+|ROTR|ROTL"),
            re.compile(r">>\s*\d+\s*\|\s*<<\s*\d+"),  # rotate via shift+or
        ],
        "min_matches": 16,
        "category": "hash",
        "confidence": 0.5,
    },
    "galois_field": {
        "description": "Galois field operations (ECC, AES-GF)",
        "patterns": [
            re.compile(r"\*\s*\w+\s*%\s*\w+"),
            re.compile(r"mod\s*\w+|%\s*0x[0-9a-fA-F]+"),
        ],
        "min_matches": 3,
        "category": "asymmetric",
        "confidence": 0.4,
    },
    "key_schedule": {
        "description": "Key expansion / key schedule",
        "patterns": [
            re.compile(r"round.?key|key.?schedule|expand.?key", re.IGNORECASE),
            re.compile(r"for\s*\([^)]*(?:Nk|Nr|round)[^)]*\)", re.IGNORECASE),
        ],
        "min_matches": 1,
        "category": "symmetric_cipher",
        "confidence": 0.4,
    },
    "modular_exponentiation": {
        "description": "Modular exponentiation (RSA, DH)",
        "patterns": [
            re.compile(r"pow\s*\(.*,.*,.*\)"),
            re.compile(r"mod_exp|modpow|montgomery", re.IGNORECASE),
        ],
        "min_matches": 1,
        "category": "asymmetric",
        "confidence": 0.5,
    },
    "block_cipher_mode": {
        "description": "Block cipher mode of operation (CBC, CTR, GCM)",
        "patterns": [
            re.compile(r"iv\s*\^|xor.*iv|prev.*block\s*\^", re.IGNORECASE),
            re.compile(r"counter\s*\+\+|nonce.*counter", re.IGNORECASE),
            re.compile(r"cbc|ctr|gcm|ecb|cfb|ofb", re.IGNORECASE),
        ],
        "min_matches": 12,
        "category": "symmetric_cipher",
        "confidence": 0.4,
        "context_keywords": ["cbc", "ctr", "gcm", "ecb", "block", "cipher", "encrypt", "decrypt", "iv", "nonce"],
        "suppress_if_blas": True,
    },
    "pbkdf_loop": {
        "description": "Password-based key derivation (PBKDF2, scrypt)",
        "patterns": [
            re.compile(r"iteration|iter.?count|rounds", re.IGNORECASE),
            re.compile(r"salt.*hash|hash.*salt|derive.*key", re.IGNORECASE),
        ],
        "min_matches": 2,
        "category": "kdf",
        "confidence": 0.5,
    },
    "elliptic_curve": {
        "description": "Elliptic curve operations (ECDSA, ECDH)",
        "patterns": [
            re.compile(r"point_add|point_mul|scalar_mul", re.IGNORECASE),
            re.compile(r"curve.?point|ec.?point|affine", re.IGNORECASE),
            re.compile(r"secp256|curve25519|ed25519|p384|p521", re.IGNORECASE),
        ],
        "min_matches": 1,
        "category": "asymmetric",
        "confidence": 0.6,
    },
    "compression_lz": {
        "description": "LZ-family compression (LZ77, LZW, zlib)",
        "patterns": [
            re.compile(r"match.?len|match.?dist|back.?ref", re.IGNORECASE),
            re.compile(r"sliding.?window|look.?ahead", re.IGNORECASE),
            re.compile(r"deflate|inflate|z_stream", re.IGNORECASE),
        ],
        "min_matches": 2,
        "category": "compression",
        "confidence": 0.5,
    },
    "huffman": {
        "description": "Huffman coding",
        "patterns": [
            re.compile(r"huffman|huff.?tree|code.?len", re.IGNORECASE),
            re.compile(r"bit.?length|freq.?table", re.IGNORECASE),
        ],
        "min_matches": 2,
        "category": "compression",
        "confidence": 0.5,
    },
    "base64_encoding": {
        "description": "Base64 encoding/decoding",
        "patterns": [
            re.compile(
                r"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\+/"
            ),
            re.compile(r"base64|b64.?encode|b64.?decode", re.IGNORECASE),
        ],
        "min_matches": 1,
        "category": "encoding",
        "confidence": 0.7,
    },
}


# ---------------------------------------------------------------------------
# Yaklasim 3: API korelasyonu (bilinen crypto API cagrilari)
# ---------------------------------------------------------------------------

CRYPTO_APIS: dict[str, dict[str, Any]] = {
    # Apple CommonCrypto
    "CCCrypt": {"algorithm": "AES/DES/3DES", "category": "symmetric_cipher"},
    "CCCryptorCreate": {"algorithm": "AES/DES/3DES", "category": "symmetric_cipher"},
    "CCCryptorUpdate": {"algorithm": "AES/DES/3DES", "category": "symmetric_cipher"},
    "CCCryptorFinal": {"algorithm": "AES/DES/3DES", "category": "symmetric_cipher"},
    "CCHmac": {"algorithm": "HMAC (SHA1/SHA256/SHA512)", "category": "mac"},
    "CCHmacInit": {"algorithm": "HMAC", "category": "mac"},
    "CCHmacUpdate": {"algorithm": "HMAC", "category": "mac"},
    "CCHmacFinal": {"algorithm": "HMAC", "category": "mac"},
    "CCKeyDerivationPBKDF": {"algorithm": "PBKDF2", "category": "kdf"},
    "CC_SHA1_Init": {"algorithm": "SHA-1", "category": "hash"},
    "CC_SHA1_Update": {"algorithm": "SHA-1", "category": "hash"},
    "CC_SHA1_Final": {"algorithm": "SHA-1", "category": "hash"},
    "CC_SHA1": {"algorithm": "SHA-1", "category": "hash"},
    "CC_SHA256_Init": {"algorithm": "SHA-256", "category": "hash"},
    "CC_SHA256_Update": {"algorithm": "SHA-256", "category": "hash"},
    "CC_SHA256_Final": {"algorithm": "SHA-256", "category": "hash"},
    "CC_SHA256": {"algorithm": "SHA-256", "category": "hash"},
    "CC_SHA384": {"algorithm": "SHA-384", "category": "hash"},
    "CC_SHA512": {"algorithm": "SHA-512", "category": "hash"},
    "CC_MD5_Init": {"algorithm": "MD5", "category": "hash"},
    "CC_MD5_Update": {"algorithm": "MD5", "category": "hash"},
    "CC_MD5_Final": {"algorithm": "MD5", "category": "hash"},
    "CC_MD5": {"algorithm": "MD5", "category": "hash"},
    # Apple Security framework
    "SecKeyCreateSignature": {"algorithm": "RSA/ECDSA signing", "category": "asymmetric"},
    "SecKeyVerifySignature": {"algorithm": "RSA/ECDSA verification", "category": "asymmetric"},
    "SecKeyCreateEncryptedData": {"algorithm": "RSA encryption", "category": "asymmetric"},
    "SecKeyCreateDecryptedData": {"algorithm": "RSA decryption", "category": "asymmetric"},
    "SecKeyGeneratePair": {"algorithm": "RSA/EC key generation", "category": "asymmetric"},
    "SecCertificateCreateWithData": {"algorithm": "X.509 certificate", "category": "asymmetric"},
    "SecTrustEvaluate": {"algorithm": "Certificate chain validation", "category": "asymmetric"},
    "SecItemAdd": {"algorithm": "Keychain storage", "category": "key_management"},
    "SecItemCopyMatching": {"algorithm": "Keychain retrieval", "category": "key_management"},
    "SecItemUpdate": {"algorithm": "Keychain update", "category": "key_management"},
    "SecItemDelete": {"algorithm": "Keychain deletion", "category": "key_management"},
    "SecRandomCopyBytes": {"algorithm": "CSPRNG", "category": "random"},
    # OpenSSL / BoringSSL / LibreSSL
    "SSL_CTX_new": {"algorithm": "TLS context", "category": "protocol"},
    "SSL_new": {"algorithm": "TLS session", "category": "protocol"},
    "SSL_connect": {"algorithm": "TLS handshake (client)", "category": "protocol"},
    "SSL_accept": {"algorithm": "TLS handshake (server)", "category": "protocol"},
    "SSL_read": {"algorithm": "TLS encrypted read", "category": "protocol"},
    "SSL_write": {"algorithm": "TLS encrypted write", "category": "protocol"},
    "SSL_set_verify": {"algorithm": "TLS certificate verification", "category": "protocol"},
    "EVP_EncryptInit": {"algorithm": "OpenSSL symmetric encryption", "category": "symmetric_cipher"},
    "EVP_EncryptInit_ex": {"algorithm": "OpenSSL symmetric encryption", "category": "symmetric_cipher"},
    "EVP_EncryptUpdate": {"algorithm": "OpenSSL symmetric encryption", "category": "symmetric_cipher"},
    "EVP_EncryptFinal": {"algorithm": "OpenSSL symmetric encryption", "category": "symmetric_cipher"},
    "EVP_DecryptInit": {"algorithm": "OpenSSL symmetric decryption", "category": "symmetric_cipher"},
    "EVP_DecryptInit_ex": {"algorithm": "OpenSSL symmetric decryption", "category": "symmetric_cipher"},
    "EVP_DecryptUpdate": {"algorithm": "OpenSSL symmetric decryption", "category": "symmetric_cipher"},
    "EVP_DecryptFinal": {"algorithm": "OpenSSL symmetric decryption", "category": "symmetric_cipher"},
    "EVP_DigestInit": {"algorithm": "OpenSSL hash", "category": "hash"},
    "EVP_DigestInit_ex": {"algorithm": "OpenSSL hash", "category": "hash"},
    "EVP_DigestUpdate": {"algorithm": "OpenSSL hash", "category": "hash"},
    "EVP_DigestFinal": {"algorithm": "OpenSSL hash", "category": "hash"},
    "EVP_SignInit": {"algorithm": "OpenSSL signing", "category": "asymmetric"},
    "EVP_SignFinal": {"algorithm": "OpenSSL signing", "category": "asymmetric"},
    "EVP_VerifyInit": {"algorithm": "OpenSSL verification", "category": "asymmetric"},
    "EVP_VerifyFinal": {"algorithm": "OpenSSL verification", "category": "asymmetric"},
    "EVP_PKEY_CTX_new": {"algorithm": "OpenSSL key context", "category": "asymmetric"},
    "RSA_generate_key": {"algorithm": "RSA key generation", "category": "asymmetric"},
    "RSA_public_encrypt": {"algorithm": "RSA encryption", "category": "asymmetric"},
    "RSA_private_decrypt": {"algorithm": "RSA decryption", "category": "asymmetric"},
    "EC_KEY_new_by_curve_name": {"algorithm": "EC key generation", "category": "asymmetric"},
    "ECDSA_sign": {"algorithm": "ECDSA signing", "category": "asymmetric"},
    "ECDSA_verify": {"algorithm": "ECDSA verification", "category": "asymmetric"},
    "DH_generate_parameters": {"algorithm": "Diffie-Hellman", "category": "asymmetric"},
    "DH_generate_key": {"algorithm": "Diffie-Hellman", "category": "asymmetric"},
    "RAND_bytes": {"algorithm": "CSPRNG (OpenSSL)", "category": "random"},
    "RAND_seed": {"algorithm": "RNG seeding", "category": "random"},
    "AES_encrypt": {"algorithm": "AES (low-level)", "category": "symmetric_cipher"},
    "AES_decrypt": {"algorithm": "AES (low-level)", "category": "symmetric_cipher"},
    "AES_set_encrypt_key": {"algorithm": "AES key setup", "category": "symmetric_cipher"},
    "AES_set_decrypt_key": {"algorithm": "AES key setup", "category": "symmetric_cipher"},
    "BF_encrypt": {"algorithm": "Blowfish", "category": "symmetric_cipher"},
    "BF_set_key": {"algorithm": "Blowfish key setup", "category": "symmetric_cipher"},
    "DES_ecb_encrypt": {"algorithm": "DES", "category": "symmetric_cipher"},
    "DES_set_key": {"algorithm": "DES key setup", "category": "symmetric_cipher"},
    "SHA1": {"algorithm": "SHA-1 (OpenSSL)", "category": "hash"},
    "SHA256": {"algorithm": "SHA-256 (OpenSSL)", "category": "hash"},
    "SHA512": {"algorithm": "SHA-512 (OpenSSL)", "category": "hash"},
    "MD5": {"algorithm": "MD5 (OpenSSL)", "category": "hash"},
    "HMAC": {"algorithm": "HMAC (OpenSSL)", "category": "mac"},
    "HMAC_Init": {"algorithm": "HMAC (OpenSSL)", "category": "mac"},
    "HMAC_Update": {"algorithm": "HMAC (OpenSSL)", "category": "mac"},
    "HMAC_Final": {"algorithm": "HMAC (OpenSSL)", "category": "mac"},
    "PKCS5_PBKDF2_HMAC": {"algorithm": "PBKDF2", "category": "kdf"},
    "PKCS5_PBKDF2_HMAC_SHA1": {"algorithm": "PBKDF2-SHA1", "category": "kdf"},
    # OpenSSL RC4
    "RC4": {"algorithm": "RC4", "category": "symmetric_cipher", "confidence": 0.85},
    "RC4_set_key": {"algorithm": "RC4 Key Setup", "category": "symmetric_cipher", "confidence": 0.90},
    "RC4_options": {"algorithm": "RC4", "category": "symmetric_cipher", "confidence": 0.80},
    "EVP_rc4": {"algorithm": "RC4 (EVP)", "category": "symmetric_cipher", "confidence": 0.85},
    # libsodium / NaCl
    "crypto_secretbox": {"algorithm": "XSalsa20-Poly1305", "category": "symmetric_cipher"},
    "crypto_secretbox_open": {"algorithm": "XSalsa20-Poly1305", "category": "symmetric_cipher"},
    "crypto_box": {"algorithm": "Curve25519-XSalsa20-Poly1305", "category": "asymmetric"},
    "crypto_box_open": {"algorithm": "Curve25519-XSalsa20-Poly1305", "category": "asymmetric"},
    "crypto_sign": {"algorithm": "Ed25519 signing", "category": "asymmetric"},
    "crypto_sign_open": {"algorithm": "Ed25519 verification", "category": "asymmetric"},
    "crypto_hash_sha256": {"algorithm": "SHA-256 (libsodium)", "category": "hash"},
    "crypto_hash_sha512": {"algorithm": "SHA-512 (libsodium)", "category": "hash"},
    "crypto_aead_chacha20poly1305_encrypt": {
        "algorithm": "ChaCha20-Poly1305",
        "category": "symmetric_cipher",
    },
    "crypto_aead_xchacha20poly1305_ietf_encrypt": {
        "algorithm": "XChaCha20-Poly1305",
        "category": "symmetric_cipher",
    },
    "crypto_pwhash": {"algorithm": "Argon2id", "category": "kdf"},
    "crypto_pwhash_scryptsalsa208sha256": {"algorithm": "scrypt", "category": "kdf"},
    # Windows CryptoAPI (Ghidra bazen Windows binary de decompile eder)
    "CryptEncrypt": {"algorithm": "Windows CryptoAPI encryption", "category": "symmetric_cipher"},
    "CryptDecrypt": {"algorithm": "Windows CryptoAPI decryption", "category": "symmetric_cipher"},
    "CryptHashData": {"algorithm": "Windows CryptoAPI hash", "category": "hash"},
    "BCryptEncrypt": {"algorithm": "Windows BCrypt encryption", "category": "symmetric_cipher"},
    "BCryptDecrypt": {"algorithm": "Windows BCrypt decryption", "category": "symmetric_cipher"},
    "BCryptHash": {"algorithm": "Windows BCrypt hash", "category": "hash"},
    # zlib / compression
    "deflateInit": {"algorithm": "zlib deflate", "category": "compression"},
    "deflate": {"algorithm": "zlib deflate", "category": "compression"},
    "inflateInit": {"algorithm": "zlib inflate", "category": "compression"},
    "inflate": {"algorithm": "zlib inflate", "category": "compression"},
    "compress2": {"algorithm": "zlib compression", "category": "compression"},
    "uncompress": {"algorithm": "zlib decompression", "category": "compression"},
    "BZ2_bzCompressInit": {"algorithm": "bzip2 compression", "category": "compression"},
    "BZ2_bzDecompressInit": {"algorithm": "bzip2 decompression", "category": "compression"},
    "LZ4_compress_default": {"algorithm": "LZ4 compression", "category": "compression"},
    "LZ4_decompress_safe": {"algorithm": "LZ4 decompression", "category": "compression"},
    "ZSTD_compress": {"algorithm": "Zstandard compression", "category": "compression"},
    "ZSTD_decompress": {"algorithm": "Zstandard decompression", "category": "compression"},
}


# ---------------------------------------------------------------------------
# Ana sinif
# ---------------------------------------------------------------------------

class CAlgorithmIdentifier:
    """Decompile edilmis C kodunda algoritma tespiti.

    Uc katmanli analiz:
    1. Bilinen kriptografik sabitleri kaynak kodda arar
    2. Kod yapisindan (loop, XOR, rotate, S-box) algoritma pattern'i tanir
    3. Bilinen crypto API fonksiyon cagrilarini eslestirir

    Args:
        config: Merkezi konfigurasyon. None ise varsayilan kullanilir.
    """

    def __init__(self, config: Config | None = None) -> None:
        self.config = config or Config()
        self._signatures = ALGORITHM_SIGNATURES
        self._const_groups, self._const_owners = _build_const_index(self._signatures)
        self._structural = STRUCTURAL_PATTERNS
        self._crypto_apis = CRYPTO_APIS
        # Onceden compile: tek combined regex ile tum API'leri tek geciste ara
        api_names = sorted(CRYPTO_APIS.keys(), key=len, reverse=True)
        self._combined_api_re = re.compile(
            r"\b(" + "|".join(re.escape(n) for n in api_names) + r")\s*\("
        ) if api_names else None
        # v1.4.2: False positive azaltma -- numeric library tespiti
        # identify() basinda set edilir, _scan_constants'da okunur (read-only, thread-safe)
        self._is_numeric_library: bool = False

    def identify(
        self,
        decompiled_dir: Path,
        functions_json: Path | None = None,
        strings_json: Path | None = None,
    ) -> CAlgorithmResult:
        """Ana tespit fonksiyonu.

        Args:
            decompiled_dir: Decompile edilmis C dosyalarinin bulundugu dizin.
            functions_json: Fonksiyon metadata (Ghidra ciktisi). Opsiyonel.
            strings_json: String referanslari. Opsiyonel.

        Returns:
            CAlgorithmResult: Tespit sonuclari.
        """
        errors: list[str] = []
        all_matches: list[AlgorithmMatch] = []

        # Fonksiyon metadata yukle
        func_meta = self._load_json(functions_json, errors)

        # v1.4.2 Fix A: Domain-aware pre-filter
        # Binary'deki fonksiyon isimlerinden BLAS/LAPACK/ML kutuphane tespiti.
        # Bu flag True ise constant-based crypto tespiti cok dusuk confidence alir.
        # v1.4.3: Indicator listesi module-level BLAS_ML_INDICATORS'a tasinmistir.
        self._is_numeric_library = False
        if func_meta:
            for fn_name in func_meta:
                fn_lower = fn_name.lower()
                if any(ind in fn_lower for ind in BLAS_ML_INDICATORS):
                    self._is_numeric_library = True
                    logger.info(
                        "Numeric library detected (indicator in '%s') -- "
                        "constant-based crypto confidence will be suppressed",
                        fn_name,
                    )
                    break

        # Kaynak 2: strings_json'dan ML/BLAS gostergeleri
        # Stripped binary'lerde fonksiyon isimleri FUN_xxx olur, tespit yapilamaz.
        # String tablosu ise strip'ten etkilenmez -- kutuphane isimlerini icerir.
        if not self._is_numeric_library and strings_json:
            _ML_STRING_INDICATORS = frozenset({
                "openblas", "libopenblas", "mkl", "lapack", "atlas", "blas",
                "faiss", "torch", "tensorflow", "onnx", "caffe", "cublas",
                "eigen", "armadillo", "accelerate", "veclib", "numpy", "scipy",
                "sgemm", "dgemm", "cblas", "product_quantizer", "index_factory",
            })
            try:
                strings_data = (
                    json.loads(strings_json.read_text(encoding="utf-8"))
                    if strings_json.exists()
                    else {}
                )
                # Format: {"strings": [...]} veya list[str] veya {addr: str}
                all_strings: list = []
                if isinstance(strings_data, dict):
                    all_strings = strings_data.get("strings", [])
                    if not all_strings:
                        all_strings = list(strings_data.values())
                elif isinstance(strings_data, list):
                    all_strings = strings_data

                for s in all_strings[:500000]:  # limit -- cok buyuk JSON'larda OOM onlemi
                    s_lower = str(s).lower()
                    if any(ind in s_lower for ind in _ML_STRING_INDICATORS):
                        self._is_numeric_library = True
                        logger.info(
                            "Numeric library detected from strings: %s",
                            s_lower[:60],
                        )
                        break
            except Exception:
                logger.debug("Numeric library string tespiti basarisiz, atlaniyor", exc_info=True)

        # C dosyalarini topla
        c_files = self._collect_c_files(decompiled_dir, errors)
        if not c_files:
            return CAlgorithmResult(
                success=False,
                errors=errors or ["No C files found in decompiled directory"],
            )

        # Her C dosyasini paralel analiz et
        matches_lock = threading.Lock()
        errors_lock = threading.Lock()
        processed_count = 0
        total_files = len(c_files)

        def _analyze_file(c_file: Path) -> list[AlgorithmMatch]:
            """Tek C dosyasini analiz et, eslesmeler dondur."""
            file_matches: list[AlgorithmMatch] = []
            try:
                content = c_file.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                with errors_lock:
                    errors.append(f"Cannot read {c_file.name}: {exc}")
                return file_matches

            functions = self._extract_functions(content, func_meta, c_file.stem)

            for func_name, func_body, func_addr in functions:
                try:
                    const_matches = self._scan_constants(func_body, func_name, func_addr)
                    file_matches.extend(const_matches)

                    struct_matches = self._scan_structural(func_body, func_name, func_addr)
                    file_matches.extend(struct_matches)

                    api_matches = self._scan_apis(func_body, func_name, func_addr)
                    file_matches.extend(api_matches)
                except Exception as exc:
                    logger.debug("Algorithm scan hatasi (%s in %s): %s", func_name, c_file.name, exc)

            return file_matches

        logger.info("Paralel algoritma taramasi: %d dosya, %d worker", total_files, CPU_PERF_CORES)

        with ThreadPoolExecutor(max_workers=CPU_PERF_CORES) as pool:
            futures = {pool.submit(_analyze_file, f): f for f in c_files}
            for future in as_completed(futures):
                processed_count += 1
                try:
                    file_matches = future.result()
                    with matches_lock:
                        all_matches.extend(file_matches)
                except Exception as exc:
                    c_file = futures[future]
                    with errors_lock:
                        errors.append(f"Algorithm analysis failed for {c_file.name}: {exc}")
                if processed_count % 100 == 0:
                    logger.info(
                        "  Algorithm ID ilerleme: %d/%d dosya (%.0f%%)",
                        processed_count, total_files, 100.0 * processed_count / total_files,
                    )

        # Sonuclari birlestirilmis ve tekillestirilmis olarak dondur
        merged = self._merge_matches(all_matches)

        # v1.4.2 Fix C: Post-filter -- numeric library + constant-based => suppress
        # Eger binary BLAS/ML kutuphanesi ise VE constant-based tespit varsa,
        # constant-based olanlarin confidence'ini ek olarak 0.3x ile carp.
        # (Fix A zaten 0.2x yapti, bu fazladan guvenlik kati.)
        if self._is_numeric_library:
            before = len(merged)
            merged = [m for m in merged if "constant" not in m.detection_method]
            suppressed = before - len(merged)
            if suppressed:
                logger.info(
                    "Post-filter: %d constant-based match REMOVED (numeric library)",
                    suppressed,
                )

        # v1.4.3: Match budget -- cok fazla eslesme memory/zaman israfi
        MAX_ALGO_MATCHES = self.config.binary_reconstruction.max_algo_matches
        if MAX_ALGO_MATCHES > 0 and len(merged) > MAX_ALGO_MATCHES:
            merged.sort(key=lambda m: m.confidence, reverse=True)
            merged = merged[:MAX_ALGO_MATCHES]
            logger.warning(
                "Match budget exceeded: truncated to %d (from %d+)",
                MAX_ALGO_MATCHES, MAX_ALGO_MATCHES,
            )

        # Istatistik hesapla
        by_category: dict[str, int] = {}
        by_confidence: dict[str, int] = {"high": 0, "medium": 0, "low": 0}

        for m in merged:
            by_category[m.category] = by_category.get(m.category, 0) + 1
            if m.confidence >= 0.7:
                by_confidence["high"] += 1
            elif m.confidence >= 0.4:
                by_confidence["medium"] += 1
            else:
                by_confidence["low"] += 1

        logger.info(
            "Algorithm identification: %d detected (%d high, %d medium, %d low)",
            len(merged),
            by_confidence["high"],
            by_confidence["medium"],
            by_confidence["low"],
        )

        return CAlgorithmResult(
            success=True,
            algorithms=merged,
            total_detected=len(merged),
            by_category=by_category,
            by_confidence=by_confidence,
            errors=errors,
        )

    # ------------------------------------------------------------------
    # Yardimci: dosya toplama
    # ------------------------------------------------------------------

    @staticmethod
    def _collect_c_files(directory: Path, errors: list[str]) -> list[Path]:
        """Dizindeki C/H dosyalarini topla."""
        if not directory.exists():
            errors.append(f"Directory does not exist: {directory}")
            return []
        files: list[Path] = []
        for ext in ("*.c", "*.h", "*.cpp", "*.cc"):
            files.extend(directory.glob(ext))
        # Alt dizinleri de tara
        for ext in ("**/*.c", "**/*.h", "**/*.cpp", "**/*.cc"):
            for f in directory.glob(ext):
                if f not in files:
                    files.append(f)
        return sorted(files)

    @staticmethod
    def _load_json(
        path: Path | None, errors: list[str],
    ) -> dict[str, Any]:
        """JSON dosyasini yukle, hata olursa bos dict dondur."""
        if path is None or not path.exists():
            return {}
        try:
            with open(path) as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, OSError) as exc:
            errors.append(f"Cannot load {path.name}: {exc}")
            return {}

    # ------------------------------------------------------------------
    # Fonksiyon cikarma
    # ------------------------------------------------------------------

    # Ghidra decompile ciktisi fonksiyon baslangic pattern'i
    _FUNC_RE = re.compile(
        r"^(?:(?:void|int|uint|long|ulong|char|uchar|short|ushort|byte|bool|float|double|"
        r"size_t|ssize_t|undefined\d?|code\s*\*|undefined\s*\*|"
        r"\w+\s*\*+)\s+)"
        r"(\w+)\s*\(([^)]*)\)\s*\{",
        re.MULTILINE,
    )

    def _extract_functions(
        self,
        content: str,
        func_meta: dict[str, Any],
        file_stem: str,
    ) -> list[tuple[str, str, str]]:
        """C iceriginden fonksiyon adi, body ve adres cikart.

        Returns:
            list of (func_name, func_body, address) tuples.
        """
        results: list[tuple[str, str, str]] = []

        for match in self._FUNC_RE.finditer(content):
            func_name = match.group(1)
            start = match.start()

            # Body'yi bul: { ... } eslestirmesi
            body = self._extract_body(content, match.end() - 1)

            # Adres: func_meta'dan veya fonksiyon adindan cikar
            address = "unknown"
            if func_name in func_meta:
                address = func_meta[func_name].get("address", "unknown")
            elif func_name.startswith("FUN_"):
                # Ghidra FUN_XXXXXXXX formatinda adres verir
                address = "0x" + func_name[4:]

            results.append((func_name, body, address))

        # Eger hicbir fonksiyon bulunamadiysa tum icerigi tek fonksiyon olarak al
        if not results and content.strip():
            results.append((file_stem, content, "unknown"))

        return results

    @staticmethod
    def _extract_body(content: str, brace_pos: int) -> str:
        """Suslu parantez eslestirme ile fonksiyon body'sini cikart.

        Args:
            content: Tam dosya icerigi.
            brace_pos: Acilis { pozisyonu.

        Returns:
            Fonksiyon body string'i (maksimum 5000 karakter).
        """
        if brace_pos >= len(content) or content[brace_pos] != "{":
            return ""

        depth = 0
        limit = min(brace_pos + 5000, len(content))  # max 5000 char body

        for i in range(brace_pos, limit):
            ch = content[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return content[brace_pos:i + 1]

        # Kapanmamis parantez -- mevcut kismi dondur
        return content[brace_pos:limit]

    # ------------------------------------------------------------------
    # Katman 1: Sabit tarama
    # ------------------------------------------------------------------

    def _scan_constants(
        self, body: str, func_name: str, address: str,
    ) -> list[AlgorithmMatch]:
        """Fonksiyon gövdesinde bilinen kriptografik sabitleri ara.

        Kurallar dosya başındaki "Sabit-tabanlı tespit kuralları" bölümündedir:
        tam belirteç eşleşmesi, zayıf sabit süzgeci, algoritma başına en az
        CONST_MIN_DISTINCT farklı ayırt edici sabit, küçük tablolar için kesintisiz
        sıralı dizi, yalnız ortak sabitlerle eşleşmede ortak ad.
        """
        if len(body) < CONST_SCAN_MIN_BODY_CHARS:
            return []

        values, wide, runs = _collect_constant_tokens(body)
        owners = self._const_owners

        # 64 bitlik belirtecin iki yarısı da aynı algoritmanın ayırt edici sabitiyse
        # (iki 32 bitlik alana birleştirilmiş yazım) iki yarı o algoritma için bulunmuş sayılır.
        halves: dict[str, set[int]] = {}
        for wide_value in wide:
            lo, hi = wide_value & _MASK32, wide_value >> 32
            common = owners.get(lo, frozenset()) & owners.get(hi, frozenset())
            for algo_name in common:
                halves.setdefault(algo_name, set()).update((lo, hi))

        # algo -> (eşleşen değerler, güven, kanıt)
        definite: dict[str, tuple[set[int], float, list[str]]] = {}
        shared_only: dict[str, tuple[set[int], float, list[str]]] = {}

        for algo_name, groups in self._const_groups.items():
            present = values | halves.get(algo_name, set())
            matched: set[int] = set()
            evidence: list[str] = []
            matched_groups = 0
            sequence_hit = False
            for group in groups:
                group_hits = [v for v in group.values if v in present]
                sequence = group.sequence
                group_seq = sequence is not None and _contains_sequence(runs, sequence)
                if group_hits or group_seq:
                    matched_groups += 1
                matched.update(group_hits)
                evidence.extend(f"{group.label}: {hex(v)}" for v in group_hits)
                if sequence is not None and group_seq:
                    sequence_hit = True
                    evidence.append(f"{group.label}: ordered table ({len(sequence)} items)")

            need = CONST_MIN_DISTINCT_OVERRIDES.get(algo_name, CONST_MIN_DISTINCT)
            if not sequence_hit and len(matched) < need:
                continue

            # Güven: eşleşen grup oranı; birden çok grup eşleştiyse ek güven
            confidence = min(0.95, 0.4 + 0.3 * (matched_groups / len(groups)))
            if matched_groups >= 2:
                confidence = min(0.95, confidence + 0.2)

            entry = (matched, confidence, evidence)
            if sequence_hit or any(owners[v] == {algo_name} for v in matched):
                definite[algo_name] = entry
            else:
                shared_only[algo_name] = entry

        # Yalnız ortak sabitlerle eşleşen aday: ortak sahiplerden biri kendine özgü bir
        # sabitle kesin eşleştiyse sabitleri o açıklar ve aday düşer; yoksa sahiplerin
        # hepsinin adıyla tek bir ortak etiket verilir ("BLAKE2/SHA-512", "MD5/SHA-1").
        combined: dict[str, tuple[list[str], float, list[str]]] = {}
        for algo_name, (matched, confidence, evidence) in shared_only.items():
            co_owners: set[str] = set().union(*(owners[v] for v in matched))
            if co_owners & definite.keys():
                continue
            members = sorted(co_owners)
            label = "/".join(members)
            previous = combined.get(label)
            if previous is None:
                combined[label] = (members, confidence, list(evidence))
            else:
                merged_evidence = previous[2] + [e for e in evidence if e not in previous[2]]
                combined[label] = (members, min(previous[1], confidence), merged_evidence)

        def _make(name: str, category: str, confidence: float, evidence: list[str]) -> AlgorithmMatch:
            # v1.4.2: Numeric library ise constant-based confidence dusur
            if self._is_numeric_library:
                confidence *= 0.2
            return AlgorithmMatch(
                name=name,
                category=category,
                confidence=round(confidence, 2),
                detection_method="constant",
                evidence=evidence[:10],  # max 10 evidence
                function_name=func_name,
                address=address,
            )

        matches: list[AlgorithmMatch] = []
        for algo_name, (_matched, confidence, evidence) in definite.items():
            category = _ALGO_CATEGORIES.get(algo_name, "unknown")
            matches.append(_make(algo_name, category, confidence, evidence))
        for label, (members, confidence, evidence) in combined.items():
            categories = {_ALGO_CATEGORIES.get(m, "unknown") for m in members}
            category = categories.pop() if len(categories) == 1 else "unknown"
            matches.append(_make(label, category, confidence, evidence))
        return matches

    # ------------------------------------------------------------------
    # Katman 2: Yapisal pattern tarama
    # ------------------------------------------------------------------

    def _scan_structural(
        self, body: str, func_name: str, address: str,
    ) -> list[AlgorithmMatch]:
        """Fonksiyon body'sinde yapisal pattern'leri ara."""
        matches: list[AlgorithmMatch] = []

        for pattern_name, spec in self._structural.items():
            total_hits = 0
            evidence: list[str] = []

            for regex in spec["patterns"]:
                hits = regex.findall(body)
                if hits:
                    total_hits += len(hits)
                    # Eslesen ilk birini evidence olarak kaydet
                    sample = hits[0] if isinstance(hits[0], str) else str(hits[0])
                    evidence.append(f"{pattern_name}: matched '{sample[:80]}'")

            min_needed = spec.get("min_matches", 1)
            if total_hits >= min_needed and evidence:
                # Context keyword verification — pattern icin tanimliysa,
                # body'de en az 1 keyword yoksa bu tespit false positive'dir.
                context_kws = spec.get("context_keywords")
                if context_kws:
                    body_lower = body.lower()
                    if not any(kw.lower() in body_lower for kw in context_kws):
                        continue  # No context keywords → skip this detection

                # BLAS/ML suppression — feistel/xor pattern'leri BLAS fonksiyonlarinda
                # da tetiklenir. suppress_if_blas True ise ve BLAS indikatoru varsa atla.
                if spec.get("suppress_if_blas"):
                    combined = (func_name + " " + body).lower()
                    blas_indicators = [
                        "blas", "lapack", "dgemm", "sgemm", "dtrsm", "openblas",
                        "cblas", "matmul", "dot_product", "mkl", "accelerate",
                    ]
                    if any(ind in combined for ind in blas_indicators):
                        continue

                # Confidence: esleme sayisina gore artir
                base_conf = spec.get("confidence", 0.3)
                bonus = min(0.3, 0.05 * (total_hits - min_needed))
                confidence = min(0.85, base_conf + bonus)

                matches.append(AlgorithmMatch(
                    name=spec["description"],
                    category=spec.get("category", "unknown"),
                    confidence=round(confidence, 2),
                    detection_method="structural",
                    evidence=evidence[:5],
                    function_name=func_name,
                    address=address,
                ))

        return matches

    # ------------------------------------------------------------------
    # Katman 3: API cagri tarama
    # ------------------------------------------------------------------

    def _scan_apis(
        self, body: str, func_name: str, address: str,
    ) -> list[AlgorithmMatch]:
        """Fonksiyon body'sinde bilinen crypto API cagrilarini ara."""
        matches: list[AlgorithmMatch] = []
        seen_algos: set[str] = set()

        # Tek combined regex ile tum API'leri tek geciste bul
        if not self._combined_api_re:
            return matches

        for m in self._combined_api_re.finditer(body):
            api_name = m.group(1)
            info = self._crypto_apis.get(api_name)
            if not info:
                continue
            algo = info["algorithm"]
            key = f"{algo}:{func_name}"
            if key in seen_algos:
                continue
            seen_algos.add(key)

            matches.append(AlgorithmMatch(
                name=algo,
                category=info["category"],
                confidence=info.get("confidence", 0.9),
                detection_method="api",
                evidence=[f"API call: {api_name}()"],
                function_name=func_name,
                address=address,
            ))

        return matches

    # ------------------------------------------------------------------
    # Sonuc birlestirme
    # ------------------------------------------------------------------

    # v1.4.3: Alias tablosu -- eski/tekil isimler kanonize edilir
    _ALGO_ALIASES: dict[str, str] = {
        "3des": "des",
        "salsa20": "chacha20/salsa20",
        "chacha20": "chacha20/salsa20",
    }

    @classmethod
    def _merge_matches(cls, matches: list[AlgorithmMatch]) -> list[AlgorithmMatch]:
        """Ayni fonksiyonda ayni algoritmadan birden fazla eslesme varsa birlestirir.

        En yuksek confidence'i alir, tum evidence'i birlestirir.
        v1.4.3: Alias tablosu ile 3DES->DES, Salsa20/ChaCha20 birlestirmesi.
        """
        # Key: (algorithm_name_normalized, function_name)
        merged: dict[tuple[str, str], AlgorithmMatch] = {}

        for m in matches:
            # Normalize: alias tablosundan kanonik ada cevir
            norm_name = m.name.lower().strip()
            norm_name = cls._ALGO_ALIASES.get(norm_name, norm_name)
            key = (norm_name, m.function_name)

            if key in merged:
                existing = merged[key]
                # Yuksek confidence'i al
                if m.confidence > existing.confidence:
                    existing.confidence = m.confidence
                # Detection method'lari biriktir
                if m.detection_method not in existing.detection_method:
                    existing.detection_method += f"+{m.detection_method}"
                    # Multi-method tespit confidence'i arttirir
                    existing.confidence = min(0.98, existing.confidence + 0.1)
                # Evidence'lari birlestirir
                for ev in m.evidence:
                    if ev not in existing.evidence:
                        existing.evidence.append(ev)
            else:
                # Kopya olustur ki orijinali bozmasin
                merged[key] = AlgorithmMatch(
                    name=m.name,
                    category=m.category,
                    confidence=m.confidence,
                    detection_method=m.detection_method,
                    evidence=list(m.evidence),
                    function_name=m.function_name,
                    address=m.address,
                )

        # Confidence'a gore sirala (yuksekten dusuge)
        result = sorted(merged.values(), key=lambda x: -x.confidence)
        return result
