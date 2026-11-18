"""TIP-09: yapısal algoritma etiketinin kanıt kuralları (2026-11-18 onarımı, P06).

Eski katman desenleri gövdenin tamamında (dizgi sabitleri, tanımlayıcılar dahil) sözcük sınırı
olmadan arıyor, anahtar sözcükleri kanıt sayıyor ve çoğu algoritmayı tek eşleşmeyle
etiketliyordu: coreutils ``chmod`` / ``mkfifo`` / ``md5sum``'da ``mode`` / ``mode_t`` →
"Galois field operations (ECC, AES-GF)", ``tail`` yardım metnindeki "iterations" → "PBKDF2",
onaltılık yazdırma tablosu → "S-box". Ölçüm (119 ikililik geliştirme seti, yeniden oynatma):
yapısal etiket 36 ikilide 216 → 2 ikilide 2 (ikisi de GT'ye göre doğru).

Bu dosya gerçek decompile çıktısından alınmış parçalarla kuralları kilitler:
- desenler dizgi ve yorumları örtülmüş kod metninde çalışır;
- etiket için en az iki FARKLI kanıt türü ve ``required`` türler gerekir;
- bağlam sözcükleri yalnız ek koşuldur, kod tanımlayıcılarında tam sözcük olarak aranır.
"""

from __future__ import annotations

import pytest

from karadul.reconstruction.c_algorithm_id import (
    STRUCT_MIN_DISTINCT_KINDS,
    STRUCTURAL_PATTERNS,
    CAlgorithmIdentifier,
    _code_only,
    _identifier_words,
)

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _labels(body: str, name: str = "FUN_00101000") -> set[str]:
    ident = CAlgorithmIdentifier()
    return {m.name for m in ident._scan_structural(body, name, "0x101000")}


def _wrap(lines: list[str]) -> str:
    return "{\n" + "\n".join(f"  {line}" for line in lines) + "\n}\n"


# ---------------------------------------------------------------------------
# Masum gövdeler: gerçek çıktıda sahte etiket alanlar (önce → hiç)
# ---------------------------------------------------------------------------


class TestMasumGovdeler:
    def test_chmod_mode_degiskeni_galois_degil(self) -> None:
        # debian/coreutils/chmod FUN_00102f00: yalnız "uint __mode;" ve "%s" biçim dizgileri
        body = _wrap([
            "uint __mode;",
            "__mode = (uint)param_2 & 0xfff;",
            'printf("%s: mode of %s changed", pcVar1, pcVar2);',
            "iVar3 = FUN_00104c00(param_1,__mode);",
            "uVar4 = mode_to_text(__mode, 0x1ff);",
        ])
        assert _labels(body) == set()

    def test_mkfifo_mode_t_galois_degil(self) -> None:
        body = _wrap([
            "mode_t mVar1;",
            "mVar1 = umask(0);",
            "umask(mVar1);",
            "mode_t __mode = ~mVar1 & 0x1b6;",
            "iVar2 = mkfifo(__path, __mode);",
        ])
        assert _labels(body, "umask") == set()

    def test_saat_bicimleme_modulo_galois_degil(self) -> None:
        # debian/htop Row_printTime: "% 0x3c" (mod 60) ve çarpım-modülo
        body = _wrap([
            "uVar8 = uVar9 / 0x3c;",
            "uVar6 = uVar8 / 0x3c;",
            'uVar5 = xSnprintf(auStack_68,10,"%2u:%02u.%02u ",uVar8,uVar9 % 0x3c,uVar7);',
            'uVar5 = xSnprintf(auStack_68,10,"%02u:%02u ",uVar8 % 0x3c,uVar9 % 0x3c);',
            "uVar3 = uVar1 * uVar2 % 0x18;",
            "uVar4 = uVar3 * uVar2 % param_2;",
        ])
        assert _labels(body) == set()

    def test_yardim_metnindeki_iteration_pbkdf_degil(self) -> None:
        # debian/coreutils/tail usage(): "... (default %d) iterations ..." dizgisi
        body = _wrap([
            'fputs_unlocked("      --max-unchanged-stats=N\\n  changed size after N '
            '(default %d) iterations\\n",stdout);',
            'fputs_unlocked("  -s, --sleep-interval=N   (default 1.0) between iterations;\\n",stdout);',
            "/* salt hash derive key rounds */",
        ])
        assert _labels(body) == set()

    def test_onaltilik_yazdirma_tablosu_sbox_degil(self) -> None:
        # debian/openssl print_verify_detail: "0123456789abcdef"[x & 0xf]
        body = _wrap([
            'pcVar6[1] = "0123456789abcdef"[(ulong)*pbVar10 & 0xf];',
            'pcVar6[0] = "0123456789abcdef"[(ulong)(*pbVar10 >> 4)];',
            "auStack_858[uVar1 & 0xff] = auStack_858[uVar1 & 0xff] + 1;",
        ])
        assert _labels(body) == set()

    def test_tek_xor_dongusu_sifreleme_degil(self) -> None:
        # debian/htop Platform_Battery_getSysData: "^=" içeren sıradan bir döngü
        body = _wrap([
            "while( true ) {",
            "  iVar2 = dirfd(__dirp);",
            "  uVar3 ^= uVar4;",
            "}",
        ])
        assert _labels(body) == set()

    def test_thunk_icindeki_nk_anahtar_cizelgesi_degil(self) -> None:
        # mac/tmux: "thunk_FUN_..." içindeki "nk" eski IGNORECASE deseni Nk sayıyordu
        body = _wrap([
            "for (; lVar1 != 0; lVar1 = thunk_FUN_10009c0c8(lVar1)) {",
            "  FUN_100070000(lVar1);",
            "}",
        ])
        assert _labels(body) == set()

    def test_dizgideki_lz_ve_egri_adlari_etiket_degil(self) -> None:
        body = _wrap([
            '__assert_fail("matchLength < matchLenLowerBound","zstd_compress.c",0x19d9);',
            'BIO_printf(param_1,"Supported Elliptic Curve Point Formats: P384 secp256r1");',
            'puts("huffman bit length deflate inflate base64 b64_decode");',
        ])
        assert _labels(body) == set()

    def test_isaretci_aritmetigindeki_alfabe_base64_degil(self) -> None:
        # debian/coreutils/cksum crc32_update_no_xor: Ghidra CRC tablosunu "..." + ofset yazmış
        body = _wrap([
            f'uVar3 = *(uint *)("{ALPHABET}" + (ulong)(uVar3 & 0xff) * 4 + 0x400);',
            f'uVar4 = *(uint *)("{ALPHABET}" + (ulong)(uVar4 >> 0x18) * 4);',
            "uVar5 = (uVar3 >> 2) & 0x3f;",
        ])
        assert _labels(body) == set()

    def test_utf8_bicimi_base64_degil(self) -> None:
        # alfabesiz 6 bit maskesi ve kaydırma: UTF-8 kodlamasıyla aynı biçim
        body = _wrap([
            "pcVar1[0] = (char)(uVar2 >> 6) | 0xc0;",
            "pcVar1[1] = (byte)uVar2 & 0x3f | 0x80;",
            "pcVar1[2] = (char)(uVar2 >> 2) & 0x3f;",
        ])
        assert _labels(body) == set()

    def test_varint_kaydirma_galois_degil(self) -> None:
        # indirgeme polinomu olmadan yüksek bit sınaması ve ikiyle çarpma (varint, bit akışı)
        body = _wrap([
            "while ((bVar1 & 0x80) != 0) {",
            "  uVar2 = uVar2 << 1 | (ulong)(bVar1 >> 7);",
            "  uVar3 = uVar3 * 2;",
            "}",
        ])
        assert _labels(body) == set()

    def test_feistel_baglam_sozcugu_alt_dizge_degil(self) -> None:
        # 16+ "x = y ^ f()" ve takas var; "background", "copyright" içinde "round"/"right"
        # tam sözcük değildir, dizgi/yorumdaki "left" sayılmaz.
        xor_lines = [f"uVar{i} = uVar{i + 1} ^ FUN_0010{i:04d}(uVar{i + 2});" for i in range(18)]
        body = _wrap([
            "lVar1 = lVar2;",
            "lVar2 = background_copyright;",
            *xor_lines,
            '/* left right half */ puts("left right half");',
        ])
        assert _labels(body) == set()


# ---------------------------------------------------------------------------
# Gerçek pozitifler: korunmalı
# ---------------------------------------------------------------------------


class TestGercekPozitifler:
    def test_base64_kodlayici_alfabe_ve_maske(self) -> None:
        # debian/coreutils/cksum FUN_00108aa0 = base64_encode (GT), Ghidra çıktısı
        body = _wrap([
            "do {",
            f'  cVar4 = "{ALPHABET}"',
            "          [(int)(pbVar9[2] & 0x3f)];",
            f'  cVar5 = "{ALPHABET}"',
            "          [(int)((uint)(pbVar9[2] >> 6) + (uint)pbVar9[1] * 4 & 0x3f)];",
            f'  *param_3 = "{ALPHABET}"',
            "             [(int)(uint)(*pbVar9 >> 2)];",
            "} while (pbVar9 != pbVar1);",
        ])
        assert _labels(body) == {"Base64 encoding/decoding"}

    def test_keccak_dondurme_ve_secim(self) -> None:
        # debian/sqlite3 FUN_0010b340 = KeccakF1600Step (GT): theta döndürmeleri + chi
        lines = [f"uVar{i} = uVar{i + 1} ^ (uVar{i + 2} >> 0x3f | uVar{i + 2} << 1);" for i in range(12)]
        lines += [
            f"uVar{20 + i} = ~(uVar{i} >> 0x13 | uVar{i} << 0x2d) & (uVar{i + 1} >> 3 | uVar{i + 1} << 0x3d) ^ uVar{i + 2};"
            for i in range(5)
        ]
        assert _labels(_wrap(lines)) == {"Hash function rounds (SHA, MD5)"}

    def test_aes_xtime_galois(self) -> None:
        body = _wrap([
            "bVar2 = (byte)(bVar1 << 1) ^ (byte)(-(bVar1 >> 7) & 0x1b);",
            "bVar3 = (byte)(bVar2 << 1) ^ (byte)(-(bVar2 >> 7) & 0x1b);",
        ])
        assert _labels(body) == {"Galois field operations (ECC, AES-GF)"}

    def test_kare_al_carp_modular_us(self) -> None:
        body = _wrap([
            "while (uVar3 != 0) {",
            "  if ((uVar3 & 1) != 0) { uVar1 = uVar1 * uVar2 % param_3; }",
            "  uVar2 = uVar2 * uVar2 % param_3;",
            "  uVar3 = uVar3 >> 1;",
            "}",
        ])
        assert _labels(body) == {"Modular exponentiation (RSA, DH)"}

    def test_des_turu_bagla_sozcukleri_kodda(self) -> None:
        xor_lines = [f"left = right ^ sbox_func(round_key{i});" for i in range(20)]
        body = _wrap(["temp = right;", *xor_lines, "right = left;", "left = temp;"])
        assert "Feistel cipher (DES, Blowfish, etc.)" in _labels(body, "des_round")

    def test_xor_sifreleme_dongusel_anahtar(self) -> None:
        body = _wrap([
            "for (lVar2 = 0; lVar2 < param_2; lVar2 = lVar2 + 1) {",
            "  pbVar1[lVar2] = pbVar1[lVar2] ^ param_3[lVar2 % param_4];",
            "}",
        ])
        assert _labels(body) == {"XOR-based encryption/decryption"}


# ---------------------------------------------------------------------------
# Kural kilitleri
# ---------------------------------------------------------------------------


class TestKurallar:
    def test_iki_tur_esigi(self) -> None:
        assert STRUCT_MIN_DISTINCT_KINDS == 2
        for name, spec in STRUCTURAL_PATTERNS.items():
            kinds = len(spec["evidence"]) + len(spec.get("data_evidence", {}))
            assert spec.get("min_kinds", STRUCT_MIN_DISTINCT_KINDS) >= 2, name
            assert kinds >= spec.get("min_kinds", STRUCT_MIN_DISTINCT_KINDS), name

    def test_tek_tur_cok_eslesme_yetmez(self) -> None:
        # 40 kez aynı tür (indirgeme polinomu) — ikinci tür yok
        body = _wrap([f"uVar{i} = uVar{i} ^ 0x1b;" for i in range(40)])
        assert _labels(body) == set()

    def test_zorunlu_tur_olmadan_etiket_yok(self) -> None:
        # Galois'in iki yan türü var (yüksek bit + ikiyle çarpma) ama indirgeme polinomu yok
        body = _wrap(["uVar1 = (uVar2 & 0x80) << 1;", "uVar3 = uVar2 * 2 >> 7;"])
        assert _labels(body) == set()

    def test_az_eslesme_yetmez(self) -> None:
        # iki tür var (döndürme + seçim) ama toplam eşleşme hash_rounds eşiğinin (16) altında
        body = _wrap([
            "uVar1 = uVar2 ^ (uVar3 >> 0x3f | uVar3 << 1);",
            "uVar4 = ~uVar5 & uVar6 ^ uVar7;",
        ])
        assert _labels(body) == set()

    def test_dizgi_ve_yorumdaki_kod_bicimi_kanit_degil(self) -> None:
        # Galois türleri yalnız dizgi ve yorumda: kod metninde hiçbiri yok
        body = _wrap([
            'puts("x = (x << 1) ^ 0x1b; y = x & 0x80; z = z * 2 ^ 0x87");',
            "/* b = (b << 1) ^ (-(b >> 7) & 0x1b); */",
            "uVar1 = FUN_00102000(param_1);",
        ])
        assert _labels(body) == set()

    def test_sabit_tam_belirtec(self) -> None:
        # 0x1b8 ve 0x87654321 indirgeme polinomu değildir
        body = _wrap(["uVar1 = (uVar2 << 1) ^ 0x1b8;", "uVar3 = uVar4 & 0x87654321 >> 7;"])
        assert _labels(body) == set()

    def test_dizgi_ve_yorum_kod_degil(self) -> None:
        code = _code_only('x = 1; /* a ^ 0x1b\n b */ puts("y << 1 ^ 0x1b"); c = \'^\';')
        assert "0x1b" not in code and "<<" not in code and "^" not in code
        assert code.count("\n") == 1

    def test_tanimlayici_sozcukleri(self) -> None:
        words = _identifier_words(_code_only('roundKey = left_half; s = "block"; // cipher'))
        assert {"round", "key", "left", "half"} <= words
        assert "block" not in words and "cipher" not in words
        assert "round" not in _identifier_words("background = 1;")

    @pytest.mark.parametrize("anahtar", ["mod", "mode", "iteration", "ctr", "affine", "rounds"])
    def test_anahtar_sozcuk_tek_basina_kanit_degil(self, anahtar: str) -> None:
        body = _wrap([f"{anahtar} = {anahtar}_x % 0x10;", f'puts("{anahtar}");'] * 10)
        assert _labels(body) == set()
