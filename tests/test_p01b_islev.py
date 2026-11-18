"""P01b kalem 3: ``analyze_decompiled`` fonksiyon başına etiketler dosya düzeyiyle aynı kanıt kuralında.

Kayıtlı decompile çıktısında (genel tarama, 14 ikili, ``static/ghidra_output/decompiled``) önce:
algoritma etiketi 2 110, zafiyet etiketi 140. Zafiyetlerin çoğu tanımlayıcı içi alt dizgiydi:
``fgets`` / ``BIO_gets`` → "gets", ``sqlite3_exec`` / ``regexec`` → "exec", ``_vasprintf`` →
"sprintf", ``EVP_RAND_CTX_get0_rand`` → "rand"; içe aktarma thunk'ı (``strcpy`` içinde
``strcpy(...)``) kendi adıyla "Buffer Overflow" alıyordu. Algoritma etiketi tek eşleşmeyle
veriliyordu. Girdiler bu çıktıdaki gerçek satırlardır.
"""

from __future__ import annotations

import pytest

from karadul.analyzers.binary_intelligence import BinaryIntelligence, _analyze_single_file
from karadul.config import Config

# _analyze_single_file 50 karakterden kısa kodu atlar; yorum kanıt sayılmadığı için dolgu yorum.
DOLGU = "\n// " + "-" * 60 + "\n"

THUNK_STRCPY = """// Function: strcpy
// Address:  001041f4
// Callees:  1 (strcpy)

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

char * strcpy(char *__dest,char *__src)

{
  char *pcVar1;

  pcVar1 = strcpy(__dest,__src);
  return pcVar1;
}
"""


def _vuln(code: str, stem: str = "FUN_00100000") -> list[str]:
    out = _analyze_single_file((stem, code + DOLGU))
    assert out is not None
    return out["vulnerabilities"]


def _algo(code: str) -> list[str]:
    out = _analyze_single_file(("FUN_00100000", code + DOLGU))
    assert out is not None
    return out["algorithms"]


@pytest.fixture
def bi() -> BinaryIntelligence:
    return BinaryIntelligence(Config())


class TestZafiyetTamAd:
    @pytest.mark.parametrize("satir", [
        "while (pcVar2 = fgets(acStack_248,0x200,__stream), pcVar2 != (char *)0x0) {",
        "iVar1 = BIO_gets(DAT_0021c3d8,acStack_438,0x400);",
        "sqlite3_exec(*param_1,lVar6,0,0,0);",
        "iVar4 = _regexec(auStack_130,param_3 + lVar9,10,&local_110,0);",
        "anetCloexec();",
        "iVar1 = _vasprintf(param_1,param_2,&stack0x00000000);",
        "xAsprintf(param_1, fmt, a, b);",
        "EVP_RAND_CTX_get0_rand();",
    ])
    def test_alt_dizgi_zafiyet_degil(self, satir) -> None:
        code = "void FUN_00100000(void)\n{\n  " + satir + "\n  return;\n}\n"
        assert _vuln(code) == []

    def test_thunk_kendi_adi_sayilmaz(self) -> None:
        assert _vuln(THUNK_STRCPY, "strcpy_001041f4") == []
        assert _vuln(THUNK_STRCPY.replace("strcpy", "_system"), "_system") == []

    def test_yorum_ve_dizgi_sabiti_sayilmaz(self) -> None:
        code = ('void FUN_00100000(void)\n{\n  /* strcpy(a,b) */\n  // system("x")\n'
                '  puts("call system(cmd) here");\n}\n')
        assert _vuln(code) == []

    def test_gercek_cagrilar_kalir(self) -> None:
        code = ("void FUN_00104100(char *param_1)\n{\n  pcVar4 = strcpy(pcVar4,param_1);\n"
                "  iVar1 = rand();\n  _system(cmd);\n  execl(\"/bin/sh\",\"sh\",p,0);\n}\n")
        v = " ".join(_vuln(code))
        assert "Buffer Overflow: strcpy" in v
        assert "Weak Randomness" in v
        assert "Command Injection: system()" in v
        assert "Command Injection: exec" in v  # exec ailesi paralel yolda artık çalışıyor

    def test_isoc99_scanf_takma_adi(self) -> None:
        code = 'void FUN_1(void)\n{\n  __isoc99_scanf("%s", buf);\n}\n'
        assert any("scanf" in v for v in _vuln(code))

    def test_ornek_yol_ayni(self, bi) -> None:
        code = "void FUN_00100000(void)\n{\n  fgets(b, 10, f);\n  strcpy(a, b);\n}\n"
        assert bi._find_vulnerabilities(code) == _vuln(code)


class TestAlgoritmaIkiKanit:
    def test_tek_cagri_etiketlemez(self) -> None:
        assert "RSA" not in _algo("void f(void)\n{\n  RSA_sign(key);\n}\n")
        assert "AES" not in _algo("void f(void)\n{\n  AES_encrypt(in, out, k);\n}\n")

    def test_iki_ayri_api_etiketler(self) -> None:
        code = ("void f(void)\n{\n  AES_set_encrypt_key(k, 128, &ks);\n"
                "  AES_encrypt(in, out, &ks);\n}\n")
        assert "AES" in _algo(code)

    def test_yorumdaki_ad_kanit_degil(self) -> None:
        code = ("// Function: AES_encrypt_wrapper\n// Callees: 1 (AES_set_encrypt_key)\n"
                "void f(void)\n{\n  AES_encrypt(in, out, k);\n}\n")
        assert "AES" not in _algo(code)

    def test_ornek_yol_ayni(self, bi) -> None:
        code = ("void f(void)\n{\n  RSA_sign(key);\n  RSA_verify(key);\n"
                "  AES_encrypt(in, out, k);\n}\n")
        assert bi._find_algorithms_in_code(code) == _algo(code)
        assert "RSA" in _algo(code) and "AES" not in _algo(code)
