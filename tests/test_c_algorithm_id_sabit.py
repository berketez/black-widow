"""Sabit-tabanlı kripto algoritma tespitinin kesinlik kuralları (2026-11-10 düzeltmesi).

Eski kural sabitleri alt dize olarak arıyor ve bir grubun yarısını yeterli sayıyordu:
"0x1" her "0x10", "0x1f" içinde; "0xfffffff" her "0xffffffff" içinde bulunuyordu.
Kripto içermeyen Mac tmux'ta 1901, htop'ta 355 sahte etiket çıkıyordu (çoğu
Keccak/SHA-3 ve Poly1305). Bu dosya yeni kuralları sentetik C metniyle kilitler:

- sabit yalnız bütün bir sayı belirteci olarak eşleşir (onaltılık, ondalık, eksi işaretli,
  U/L ekli; yorum, dizge ve tanımlayıcı içindekiler sayılmaz);
- 64 bitlik birleştirilmiş yazımın iki yarısı ancak ikisi de aynı algoritmanın sabitiyse sayılır;
- zayıf sabitler (küçük, 2'nin kuvveti, maske, tekrar deseni) kanıt değildir;
- etiket için aynı fonksiyonda en az CONST_MIN_DISTINCT farklı ayırt edici sabit gerekir
  (CRC32: 1, Keccak: 3);
- küçük değerli tablolar yalnız kesintisiz ve sıralı dizi olarak kanıttır;
- yalnız ortak sabitlerle eşleşme ortak ad taşır (BLAKE2/SHA-512, MD5/SHA-1).

Testler gerçek ikili çıktısına bağlı değildir.
"""

from __future__ import annotations

import math
from pathlib import Path

import pytest

from karadul.reconstruction.c_algorithm_id import (
    ALGORITHM_SIGNATURES,
    CONST_MIN_DISTINCT,
    CONST_MIN_DISTINCT_OVERRIDES,
    CAlgorithmIdentifier,
    _is_weak_constant,
    _is_weak_sequence,
)

M32 = (1 << 32) - 1
M64 = (1 << 64) - 1


# ---------------------------------------------------------------------------
# Yardımcılar
# ---------------------------------------------------------------------------


def _fn(lines: list[str], name: str = "FUN_00101000") -> str:
    """Ghidra biçiminde bir fonksiyon metni üret."""
    body = "\n".join(f"  {line}" for line in lines)
    return f"void {name}(long *param_1)\n\n{{\n{body}\n  return;\n}}\n"


def _names(text: str) -> set[str]:
    """_scan_constants'ın verdiği algoritma adları."""
    ident = CAlgorithmIdentifier()
    return {m.name for m in ident._scan_constants(text, "FUN_00101000", "0x101000")}


def _neg32(value: int) -> str:
    """Ghidra'nın işaretli 32 bit yazımı: 0xd76aa478 -> -0x28955b88."""
    return f"-0x{(1 << 32) - value:x}"


def _neg64(value: int) -> str:
    return f"-0x{(1 << 64) - value:x}"


SHA256_H = ALGORITHM_SIGNATURES["SHA-256"]["h_init"]
SHA256_K = ALGORITHM_SIGNATURES["SHA-256"]["k_constants"]
SHA512_H = ALGORITHM_SIGNATURES["SHA-512"]["h_init"]
SHA512_K = ALGORITHM_SIGNATURES["SHA-512"]["k_constants"]
MD5_T = ALGORITHM_SIGNATURES["MD5"]["t_values"]
MD5_INIT = ALGORITHM_SIGNATURES["MD5"]["init"]
KECCAK_RC = ALGORITHM_SIGNATURES["Keccak/SHA-3"]["round_constants"]

# Kripto içermeyen tipik decompile gövdesi: eski kuralın alt dize ile Keccak, Poly1305,
# AES, GOST, IDEA ürettiği yazımlar (0x1 önekli sayılar, 0xffffffff, 2'nin kuvvetleri,
# 0..15 arası küçük değerler, bayt çevirme maskeleri, karma çarpanı).
NON_CRYPTO_LINES = [
    "uVar1 = param_1[0x10];",
    "uVar2 = param_1[0x1f] + 0x100;",
    "if (uVar1 == 0xffffffff) { uVar1 = 0x7fffffff; }",
    "uVar3 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;",
    "uVar4 = uVar3 * 0x9e3779b9 >> 0x1c;",
    "param_1[1] = 0x100010000;",
    "param_1[2] = 0x80000000;",
    "param_1[3] = 0x0fffffff & uVar4;",
    "param_1[4] = 0xfffffffc;",
    "local_10 = 1; local_14 = 2; local_18 = 4; local_1c = 8;",
    "local_20 = 0x10; local_24 = 0x20; local_28 = 0x40; local_2c = 0x80;",
    "for (i = 0; i < 0xf; i = i + 1) { tbl[i] = i * 3 + 5 + 6 + 7 + 9 + 10 + 11 + 12 + 13 + 14; }",
    "uVar5 = 0x8082; uVar6 = 0x1021; uVar7 = 0x169; uVar8 = 0x10001;",
    "uVar9 = 0x63 ^ 0x7c ^ 0x36 ^ 0x5c;",
]


# ---------------------------------------------------------------------------
# 1. Bütün belirteç eşleşmesi
# ---------------------------------------------------------------------------


class TestTamBelirtec:
    def test_kripto_icermeyen_govde_etiket_vermez(self) -> None:
        """Eski kuralın sahte Keccak/Poly1305/AES/GOST/IDEA ürettiği gövde: hiç etiket yok."""
        assert _names(_fn(NON_CRYPTO_LINES)) == set()

    def test_uzun_sayinin_icindeki_sabit_sayilmaz(self) -> None:
        """0x6a09e667 ve 0xbb67ae85, daha uzun sayıların başında geçiyor: eşleşme yok."""
        text = _fn([
            "uVar1 = 0x6a09e6670;",
            "uVar2 = 0xbb67ae851;",
            "uVar3 = 0x3c6ef3720000;",
        ])
        assert _names(text) == set()

    def test_tanimlayici_ve_ondalik_kesir_icindeki_rakam_sayilmaz(self) -> None:
        """DAT_1779033703 (0x6a09e667) ve 3144134277.0 (0xbb67ae85) belirteç değil."""
        text = _fn([
            "uVar1 = DAT_1779033703;",
            "uVar2 = LAB_3144134277 + 1;",
            "dVar3 = 1013904242.0 * 2773480762.5;",
        ])
        assert _names(text) == set()

    def test_onaltilik_tam_belirtec_eslesir(self) -> None:
        text = _fn([f"param_1[{i}] = 0x{v:x};" for i, v in enumerate(SHA256_H)])
        assert _names(text) == {"SHA-256"}

    def test_isaretli_onaltilik_ikiye_tumleyen_ile_eslesir(self) -> None:
        """Ghidra MD5 T değerlerini işaretli basar: 0xd76aa478 -> -0x28955b88."""
        text = _fn([
            f"uVar1 = uVar1 + {_neg32(MD5_T[0])} + param_1[0];",
            f"uVar2 = uVar2 + {_neg32(MD5_T[1])} + param_1[1];",
            f"uVar3 = uVar3 + 0x{MD5_T[2]:x} + param_1[2];",
        ])
        assert _names(text) == {"MD5"}

    def test_isaretli_64bit_eslesir(self) -> None:
        """SHA-512 K değerleri işaretli 64 bit yazımla da bulunur."""
        text = _fn([
            f"uVar1 = uVar1 + {_neg64(SHA512_K[2])};",
            f"uVar2 = uVar2 + {_neg64(SHA512_K[3])};",
        ])
        assert SHA512_K[2] > 1 << 63 and SHA512_K[3] > 1 << 63
        assert _names(text) == {"SHA-512"}

    @pytest.mark.parametrize("suffix", ["U", "u", "L", "UL", "ul", "LL", "ULL", "LU", "LLU"])
    def test_c_tamsayi_ekleri_kabul(self, suffix: str) -> None:
        text = _fn([
            f"param_1[0] = 0x{SHA256_H[0]:x}{suffix};",
            f"param_1[1] = 0x{SHA256_H[1]:X}{suffix};",
        ])
        assert _names(text) == {"SHA-256"}

    def test_ondalik_yazim_eslesir(self) -> None:
        text = _fn([f"param_1[0] = {SHA256_H[0]};", f"param_1[1] = {SHA256_H[1]}U;"])
        assert _names(text) == {"SHA-256"}

    def test_yorum_ve_dizge_icindeki_sabit_sayilmaz(self) -> None:
        text = _fn([
            f"/* 0x{SHA256_H[0]:x} 0x{SHA256_H[1]:x} */",
            f"// 0x{SHA256_H[2]:x} 0x{SHA256_H[3]:x}",
            f'puts("0x{SHA256_H[4]:x} 0x{SHA256_H[5]:x}");',
        ])
        assert _names(text) == set()


# ---------------------------------------------------------------------------
# 2. 64 bitlik birleştirilmiş yazım
# ---------------------------------------------------------------------------


class TestBirlesik64:
    def test_sha1init_ghidra_bicimi(self) -> None:
        """SHA1Init: H0|H1 ve H2|H3 tek 64 bit sabit; H4 ayrı. Sonuç SHA-1 (MD5 değil)."""
        text = _fn([
            "*(undefined4 *)(param_1 + 3) = 0;",
            "param_1[2] = 0xc3d2e1f0;",
            "*param_1 = 0xefcdab8967452301;",
            "param_1[1] = 0x1032547698badcfe;",
        ], name="SHA1Init")
        assert _names(text) == {"SHA-1"}

    def test_sha256_init_birlesik(self) -> None:
        text = _fn([
            f"*(undefined8 *)(param_1 + 0x50) = 0x{SHA256_H[1]:08x}{SHA256_H[0]:08x};",
            f"*(undefined8 *)(param_1 + 0x58) = 0x{SHA256_H[3]:08x}{SHA256_H[2]:08x};",
        ])
        assert _names(text) == {"SHA-256"}

    def test_yari_tek_basina_kanit_degil(self) -> None:
        """SHA-512 H'nin üst yarıları SHA-256 H'dir; SHA-256 etiketi çıkmamalı."""
        assert all((v >> 32) == SHA256_H[i] for i, v in enumerate(SHA512_H))
        text = _fn([f"param_1[{i}] = 0x{v:x};" for i, v in enumerate(SHA512_H)])
        names = _names(text)
        assert "SHA-256" not in names
        assert names == {"BLAKE2/SHA-512"}

    def test_farkli_algoritmalarin_yarilari_birlesmez(self) -> None:
        """Bir yarı SHA-256 K, öbür yarı MD5 T: ikisi de sayılmaz."""
        text = _fn([f"uVar1 = 0x{SHA256_K[0]:08x}{MD5_T[0]:08x};"])
        assert _names(text) == set()


# ---------------------------------------------------------------------------
# 3. Zayıf sabitler ve en az farklı sabit sayısı
# ---------------------------------------------------------------------------


class TestZayifVeSayi:
    @pytest.mark.parametrize("value", [
        0x1, 0x36, 0x5C, 0xFF, 0x100, 0x1021, 0x8082, 0xFFFF,
        0x10001, 0x80000000, 0x80000001, 0x7FFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE,
        0x0FFFFFFF, 0x0FFFFFFC, 0xFFFFFFF0, 0xFF00FF00, 0x00FF00FF,
        0x01010101, 0x55555555, 0x8000000000000000, 0x8000000000000080,
        0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFF,
    ])
    def test_zayif_sabit(self, value: int) -> None:
        assert _is_weak_constant(value)

    @pytest.mark.parametrize("value", [
        0x428A2F98, 0x6A09E667, 0xC3D2E1F0, 0xEDB88320, 0x9E3779B9, 0xD76AA478,
        0x800000000000808A, 0x8000000A, 0x0FFFFFFC0FFFFFFF, 0x3FFFF03,
    ])
    def test_ayirt_edici_sabit(self, value: int) -> None:
        assert not _is_weak_constant(value)

    def test_esik_degerleri(self) -> None:
        assert CONST_MIN_DISTINCT == 2
        assert CONST_MIN_DISTINCT_OVERRIDES == {"CRC32": 1, "Keccak/SHA-3": 3}

    def test_tek_ayirt_edici_sabit_yetmez(self) -> None:
        assert _names(_fn([f"uVar1 = uVar1 + 0x{SHA256_K[5]:x};"])) == set()

    def test_iki_farkli_sabit_yeter(self) -> None:
        text = _fn([f"uVar1 = uVar1 + 0x{SHA256_K[5]:x};", f"uVar2 = uVar2 + 0x{SHA256_K[9]:x};"])
        assert _names(text) == {"SHA-256"}

    def test_ayni_sabitin_tekrari_tek_sayilir(self) -> None:
        text = _fn([f"uVar{i} = uVar{i} + 0x{SHA256_K[5]:x};" for i in range(6)])
        assert _names(text) == set()

    def test_altin_oran_tek_basina_tea_degil(self) -> None:
        assert _names(_fn(["uVar1 = uVar1 * 0x9e3779b9;", "uVar2 = uVar2 - 0x61c88647;"])) == set()

    def test_tea_cozme_toplamiyla_etiket(self) -> None:
        text = _fn(["uVar1 = 0xc6ef3720;", "uVar1 = uVar1 + 0x61c88647;"])
        assert _names(text) == {"Serpent/TEA/XTEA"}

    def test_keccak_uc_farkli_tur_sabiti_ister(self) -> None:
        strong = [v for v in KECCAK_RC if not _is_weak_constant(v)]
        two = _fn([f"uVar{i} = uVar{i} ^ 0x{v:x};" for i, v in enumerate(strong[:2])])
        three = _fn([f"uVar{i} = uVar{i} ^ 0x{v:x};" for i, v in enumerate(strong[:3])])
        assert _names(two) == set()
        assert _names(three) == {"Keccak/SHA-3"}

    def test_keccak_zayif_tur_sabitleri_sayilmaz(self) -> None:
        weak = [v for v in KECCAK_RC if _is_weak_constant(v)]
        assert len(set(weak)) == 8
        assert _names(_fn([f"uVar{i} = uVar{i} ^ 0x{v:x};" for i, v in enumerate(weak)])) == set()

    def test_crc32_tek_polinom_yeter(self) -> None:
        assert _names(_fn(["uVar1 = uVar1 >> 1 ^ 0xedb88320;"])) == {"CRC32"}
        assert _names(_fn([f"uVar1 = uVar1 >> 1 ^ {_neg32(0xEDB88320)};"])) == {"CRC32"}

    def test_poly1305_maskeleri_yetmez(self) -> None:
        text = _fn(["uVar1 = uVar1 & 0x0fffffff;", "uVar2 = uVar2 & 0x0ffffffc;",
                    "uVar3 = uVar3 & 0xffffffff;"])
        assert _names(text) == set()

    def test_poly1305_donna_maskeleri(self) -> None:
        text = _fn(["uVar1 = uVar1 >> 2 & 0x3ffff03;", "uVar2 = uVar2 >> 4 & 0x3ffc0ff;",
                    "uVar3 = uVar3 >> 6 & 0x3f03fff;"])
        assert _names(text) == {"Poly1305"}


# ---------------------------------------------------------------------------
# 4. Küçük değerli tablolar: yalnız sıralı ve kesintisiz dizi
# ---------------------------------------------------------------------------


class TestSiraliTablo:
    AES_SBOX = ALGORITHM_SIGNATURES["AES"]["sbox"]
    AES_RCON = ALGORITHM_SIGNATURES["AES"]["rcon"]

    def test_sirali_sbox_dizisi_aes(self) -> None:
        items = ", ".join(f"0x{v:02x}" for v in self.AES_SBOX)
        assert _names(_fn([f"unsigned char sbox[] = {{{items}, 0x30, 0x01}};"])) == {"AES"}

    def test_karisik_sira_aes_degil(self) -> None:
        items = ", ".join(f"0x{v:02x}" for v in reversed(self.AES_SBOX))
        assert _names(_fn([f"unsigned char sbox[] = {{{items}}};"])) == set()

    def test_kesintili_dizi_aes_degil(self) -> None:
        """Değerler sırayla ama ayrı deyimlerde: kanıt değil."""
        letters = "abcdefgh"
        text = _fn([f"{letters[i]} = 0x{v:02x};" for i, v in enumerate(self.AES_SBOX)])
        assert _names(text) == set()

    def test_rcon_dizisi_zayif(self) -> None:
        items = ", ".join(f"0x{v:02x}" for v in self.AES_RCON)
        assert _names(_fn([f"unsigned char rcon[] = {{{items}}};"])) == set()

    def test_gost_ve_des_tam_dizi(self) -> None:
        gost = ", ".join(str(v) for v in ALGORITHM_SIGNATURES["GOST"]["sbox1"])
        des = ", ".join(str(v) for v in ALGORITHM_SIGNATURES["DES"]["ip_table"])
        assert _names(_fn([f"int s[] = {{{gost}}};"])) == {"GOST"}
        assert _names(_fn([f"int ip[] = {{{des}}};"])) == {"DES"}

    @pytest.mark.parametrize("seq", [
        list(range(8)),                      # özdeşlik permütasyonu
        [56, 48, 40, 32, 24, 16, 8, 0],      # kaydırma miktarları
        [1, 2, 4, 8, 16, 32, 64, 128],       # bayrak tablosu / AES rcon
        [7, 7, 7, 7, 7, 7, 7, 7],            # tekrar
        [3, 1, 4, 1, 5, 9, 2, 6],            # 8'den az farklı değer
    ])
    def test_zayif_dizi(self, seq: list[int]) -> None:
        assert _is_weak_sequence(seq)

    def test_ayirt_edici_dizi(self) -> None:
        assert not _is_weak_sequence(ALGORITHM_SIGNATURES["AES"]["sbox"])
        assert not _is_weak_sequence(ALGORITHM_SIGNATURES["DES"]["ip_table"])

    def test_des_ilk_sekiz_aritmetik_dizi_yetmez(self) -> None:
        part = ", ".join(str(v) for v in ALGORITHM_SIGNATURES["DES"]["ip_table"][:8])
        assert _names(_fn([f"int ip[] = {{{part}}};"])) == set()


# ---------------------------------------------------------------------------
# 5. Ortak sabitler
# ---------------------------------------------------------------------------


class TestOrtakSabit:
    def test_md5_init_yalniz_ortak_ad(self) -> None:
        """MD5 init = SHA-1 H0-H3: hangisi olduğu belirsiz, ortak ad."""
        text = _fn([f"param_1[{i}] = 0x{v:x};" for i, v in enumerate(MD5_INIT)])
        assert _names(text) == {"MD5/SHA-1"}

    def test_md5_t_degerleri_ortak_adi_bastirir(self) -> None:
        lines = [f"param_1[{i}] = 0x{v:x};" for i, v in enumerate(MD5_INIT)]
        lines += [f"uVar{i} = uVar{i} + 0x{v:x};" for i, v in enumerate(MD5_T[:4])]
        assert _names(_fn(lines)) == {"MD5"}

    def test_sha512_k_ile_kesin(self) -> None:
        lines = [f"param_1[{i}] = 0x{v:x};" for i, v in enumerate(SHA512_H)]
        lines += [f"uVar{i} = uVar{i} + 0x{v:x};" for i, v in enumerate(SHA512_K[:2])]
        assert _names(_fn(lines)) == {"SHA-512"}

    def test_ortak_ad_kategorisi(self) -> None:
        ident = CAlgorithmIdentifier()
        text = _fn([f"param_1[{i}] = 0x{v:x};" for i, v in enumerate(SHA512_H)])
        (match,) = ident._scan_constants(text, "f", "0x1")
        assert match.name == "BLAKE2/SHA-512"
        assert match.category == "hash"
        assert match.detection_method == "constant"
        assert match.evidence[0] == f"h_init: 0x{SHA512_H[0]:x}"


# ---------------------------------------------------------------------------
# 6. identify() üzerinden uçtan uca
# ---------------------------------------------------------------------------


class TestIdentify:
    def test_kisa_baslatma_fonksiyonu_tespit_edilir(self, tmp_path: Path) -> None:
        """Eski 500 karakter sınırı SHA1Init gibi gerçek başlatma fonksiyonlarını atıyordu."""
        d = tmp_path / "decompiled"
        d.mkdir()
        text = _fn([
            "param_1[2] = 0xc3d2e1f0;",
            "*param_1 = 0xefcdab8967452301;",
            "param_1[1] = 0x1032547698badcfe;",
        ], name="FUN_001a9dc0")
        assert len(text) < 500
        (d / "FUN_001a9dc0.c").write_text(text)
        result = CAlgorithmIdentifier().identify(d)
        consts = [(m.name, m.function_name) for m in result.algorithms
                  if "constant" in m.detection_method]
        assert consts == [("SHA-1", "FUN_001a9dc0")]

    def test_kripto_icermeyen_program_sabit_etiketi_yok(self, tmp_path: Path) -> None:
        d = tmp_path / "decompiled"
        d.mkdir()
        for i in range(5):
            name = f"FUN_0010{i}000"
            (d / f"{name}.c").write_text(_fn(NON_CRYPTO_LINES * 3, name=name))
        result = CAlgorithmIdentifier().identify(d)
        assert result.success
        assert [m for m in result.algorithms if "constant" in m.detection_method] == []


# ---------------------------------------------------------------------------
# 7. İmza tabloları tanımlarıyla tutarlı
# ---------------------------------------------------------------------------


def _primes(n: int) -> list[int]:
    out: list[int] = []
    k = 2
    while len(out) < n:
        if all(k % p for p in out if p * p <= k):
            out.append(k)
        k += 1
    return out


def _icbrt(x: int) -> int:
    lo, hi = 0, 1 << (x.bit_length() // 3 + 2)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** 3 <= x:
            lo = mid
        else:
            hi = mid - 1
    return lo


def _keccak_rc() -> list[int]:
    def rc_bit(t: int) -> int:
        r = 1
        for _ in range(t % 255):
            r <<= 1
            if r & 0x100:
                r ^= 0x171
        return r & 1

    out = []
    for i in range(24):
        v = 0
        for j in range(7):
            if rc_bit(j + 7 * i):
                v |= 1 << ((1 << j) - 1)
        out.append(v)
    return out


class TestImzaTablolari:
    P = _primes(80)

    def test_sha256(self) -> None:
        assert SHA256_K == [_icbrt(p << 96) & M32 for p in self.P[:64]]
        assert SHA256_H == [math.isqrt(p << 64) & M32 for p in self.P[:8]]

    def test_sha512(self) -> None:
        assert SHA512_K == [_icbrt(p << 192) & M64 for p in self.P[:80]]
        assert SHA512_H == [math.isqrt(p << 128) & M64 for p in self.P[:8]]
        assert ALGORITHM_SIGNATURES["BLAKE2"]["iv"] == SHA512_H

    def test_md5(self) -> None:
        assert MD5_T == [int(abs(math.sin(i + 1)) * 2 ** 32) & M32 for i in range(64)]
        assert (MD5_T[0], MD5_T[63]) == (0xD76AA478, 0xEB86D391)  # RFC 1321
        assert MD5_INIT == ALGORITHM_SIGNATURES["SHA-1"]["h_init"][:4]

    def test_sha1_k(self) -> None:
        assert ALGORITHM_SIGNATURES["SHA-1"]["k_constants"] == [
            math.isqrt(k << 60) & M32 for k in (2, 3, 5, 10)
        ]

    def test_keccak(self) -> None:
        assert KECCAK_RC == _keccak_rc()

    def test_camellia_sigma(self) -> None:
        assert ALGORITHM_SIGNATURES["Camellia"]["sigma64"] == [
            math.isqrt(p << 136) & M64 for p in (2, 3, 5, 7, 11, 13)
        ]

    def test_chacha_sigma_ascii(self) -> None:
        sigma = [int.from_bytes(b"expand 32-byte k"[i:i + 4], "little") for i in range(0, 16, 4)]
        assert ALGORITHM_SIGNATURES["ChaCha20/Salsa20"]["sigma"] == sigma

    def test_ortak_sabitler_yalniz_bilinen_ciftler(self) -> None:
        """Birden çok algoritmaya ait ayırt edici değerler yalnız iki bilinen çiftte."""
        ident = CAlgorithmIdentifier()
        shared = {tuple(sorted(o)) for o in ident._const_owners.values() if len(o) > 1}
        assert shared == {("BLAKE2", "SHA-512"), ("MD5", "SHA-1")}

    def test_dizindeki_her_deger_ayirt_edici(self) -> None:
        ident = CAlgorithmIdentifier()
        assert ident._const_owners
        assert not [v for v in ident._const_owners if _is_weak_constant(v)]
