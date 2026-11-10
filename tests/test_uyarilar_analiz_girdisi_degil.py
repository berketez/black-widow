"""Korunan Ghidra uyarıları analiz girdisi değildir (2026-11-10).

Uyarı yorumları (``/* WARNING: … */``) artık çıktıda korunuyor. İki adım kod metnini sözcük
arayarak okuyor; uyarı metni onların kararını değiştirmemeli:

- Algoritma tanıyıcı: "Removing unreachable block" içindeki "block" sözcüğü bir şifre
  kalıbının bağlam anahtarını tek başına sağlıyordu (openssl'de 1 sahte etiket).
- Yorum üretici: araya giren uyarı satırı ileri bakış penceresini kaydırıyor, sonraki
  ``exit(`` / ``return`` görülmüyordu.
"""
from __future__ import annotations

import re

from karadul.config import Config
from karadul.reconstruction import c_algorithm_id as algo
from karadul.reconstruction import c_comment_generator as cg

UYARI = "/* WARNING: Removing unreachable block (ram,0x00104100) */"


# ---------------------------------------------------------------------------
# Algoritma tanıyıcı
# ---------------------------------------------------------------------------


def test_uyari_yorumu_analiz_metninden_cikar():
    metin = f"void f(void)\n{{\n  {UYARI}\n  g();\n}}\n"
    temiz = algo._strip_ghidra_warnings(metin)
    assert "WARNING" not in temiz and "block" not in temiz
    assert "g();" in temiz and temiz.count("\n") == metin.count("\n")


def test_dizgi_icindeki_uyari_gorunumlu_metne_dokunulmaz():
    metin = 'puts("/* WARNING: Script requires that X be disabled */\\n");\n'
    assert algo._strip_ghidra_warnings(metin) == metin


def test_uyari_olmayan_yorum_ve_uyarisiz_metin_aynen_kalir():
    metin = "/* block cipher round */\nint x; // WARNING: elle yazılmış not\n"
    assert algo._strip_ghidra_warnings(metin) == metin
    duz = "int f(void) { return 1; }\n"
    assert algo._strip_ghidra_warnings(duz) is duz


def test_display_warning_ve_cok_satirli_uyari_da_cikar():
    metin = "/* DISPLAY WARNING: Type casts are NOT being printed */\n/* WARNING: a\n   b */\nint x;\n"
    temiz = algo._strip_ghidra_warnings(metin)
    assert "WARNING" not in temiz and "int x;" in temiz


def test_tanimlayici_fonksiyonlari_uyarisiz_metinle_calisir(tmp_path, monkeypatch):
    """identify, dosya metnini fonksiyonlara ayırmadan önce uyarıları çıkarır."""
    (tmp_path / "FUN_00104100.c").write_text(
        f"void FUN_00104100(void)\n{{\n  {UYARI}\n  puts(\"/* WARNING: dizgi */\");\n  return;\n}}\n",
        encoding="utf-8",
    )
    gorulen: list[str] = []
    asil = algo.CAlgorithmIdentifier._extract_functions

    def kaydet(self, content, func_meta, file_stem):
        gorulen.append(content)
        return asil(self, content, func_meta, file_stem)

    monkeypatch.setattr(algo.CAlgorithmIdentifier, "_extract_functions", kaydet)
    algo.CAlgorithmIdentifier(Config()).identify(tmp_path)
    assert len(gorulen) == 1
    assert "Removing unreachable block" not in gorulen[0]
    assert '"/* WARNING: dizgi */"' in gorulen[0]          # dizgi sabiti yerinde


# ---------------------------------------------------------------------------
# Yorum üretici: ileri bakış
# ---------------------------------------------------------------------------


def test_ileri_bakis_uyariyi_saymaz():
    ctx = f"if (p == NULL) {{\n  {UYARI}\n  exit(1);\n}}\n"
    bas = ctx.index("{")
    pencere = cg._lookahead(ctx, bas, 40)
    assert "WARNING" not in pencere and "exit(1)" in pencere
    assert len(pencere) <= 40


def test_ileri_bakis_uyarisiz_metinde_dilimle_ayni():
    ctx = "if (p == NULL) {\n  exit(1);\n}\nint y = 2;\n" * 20
    for bas, genislik in ((0, 150), (17, 200), (40, 500), (len(ctx) - 5, 200)):
        assert cg._lookahead(ctx, bas, genislik) == ctx[bas:][:genislik]


def test_null_denetimi_yorumu_uyaridan_etkilenmez():
    """Araya uzun uyarılar girse de karar uyarısız metindekiyle aynı."""
    desen = re.compile(r"if\s*\(\s*(\w+)\s*==\s*NULL\s*\)")
    uyarisiz = "if (ptr == NULL) {\n  exit(1);\n}\n"
    uyarili = "if (ptr == NULL) {\n" + "".join(
        f"  /* WARNING: Removing unreachable block (ram,0x{i:08x}) */\n" for i in range(6)
    ) + "  exit(1);\n}\n"
    beklenen = cg._logic_null_check(desen.search(uyarisiz), uyarisiz)
    assert beklenen == "null check: ptr -- abort/cleanup"
    assert cg._logic_null_check(desen.search(uyarili), uyarili) == beklenen


def test_hata_donusu_yorumu_uyaridan_etkilenmez():
    desen = re.compile(r"if\s*\(\s*(\w+)\s*<\s*0\s*\)")
    uyarisiz = "if (rc < 0) {\n  return -1;\n}\n"
    uyarili = "if (rc < 0) {\n" + "".join(
        f"  /* WARNING: Could not recover jumptable at 0x{i:08x}. Too many branches */\n" for i in range(5)
    ) + "  return -1;\n}\n"
    beklenen = cg._logic_error_return(desen.search(uyarisiz), uyarisiz)
    assert beklenen == "error check: return on rc failure"
    assert cg._logic_error_return(desen.search(uyarili), uyarili) == beklenen
