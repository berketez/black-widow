"""P04a kalem 4 — "Row-major matrix access" blok yorumu (MUH-07).

Olumsuz örnek gerçek çıktıdan: ``debian/coreutils/cat`` ``FUN_00105b70`` (gnulib
quotearg yuvası, ``struct {size; ptr;}[]``): ``strided_array[idx_2 * 2 + 1]``.
"""
from __future__ import annotations

from pathlib import Path

from karadul.reconstruction.engineering.block_annotator import (
    ASSEMBLY_BODY_PATTERNS,
    ASSEMBLY_PATTERNS,
    CodeBlockAnnotator,
)


def _yorumlar(satirlar: list[str], domain=None) -> list:
    an = CodeBlockAnnotator(None)
    return an._detect_assembly_ops(satirlar, "f", domain, 10)


def _rowmajor(anns) -> list:
    return [a for a in anns if "Row-major matrix access" in a.text]


def test_yapi_ici_erisim_matris_degil():
    satirlar = [
        "  buf_9 = (uint64_t *)strided_array[idx_2 * 2 + 1];",
        "    strided_array[idx_2 * 2 + 1] = buf_9;",
        "  x = a[2*idx + 1];",
        "  y = strided_array[idx_2 * 2 + field_ofs];",  # sabit çarpan, değişken ek
    ]
    assert _rowmajor(_yorumlar(satirlar)) == []


def test_sabit_carpan_ya_da_sabit_ek_matris_degil():
    assert _rowmajor(_yorumlar(["  y = M[i * 6 + j];"])) == []
    assert _rowmajor(_yorumlar(["  y = M[i * n + 1];"])) == []


def test_gercek_satir_sutun_erisimi():
    anns = _rowmajor(_yorumlar(["    c = A[row * ncols + col] * x[col];"]))
    assert len(anns) == 1
    assert "A[row*ncols + col]" in anns[0].text
    assert anns[0].line_number == 10


def test_dof_cift_dongusu_govdeye_uygulanir():
    govde = [
        "void assemble(int ndof)",
        "{",
        "  for (i = 0; i < ndof; i = i + 1) {",
        "    for (j = 0; j < ndof; j = j + 1) {",
        "      K[i] = K[i] + Ke[j];",
        "    }",
        "  }",
        "}",
    ]
    anns = [a for a in _yorumlar(govde, "structural") if "DOF-DOF" in a.text]
    assert len(anns) == 1
    assert anns[0].line_number == 10 + 2  # dıştaki for satırı
    assert anns[0].text.startswith("  // --- Global assembly: DOF-DOF")


def test_dof_deseni_satir_listesinde_degil():
    """Çok satırlı desen satır satır denenirse hiç eşleşemez (eski ölü desen)."""
    assert all("DOF" not in t for _p, t, _c in ASSEMBLY_PATTERNS)
    assert any("DOF" in t for _p, t, _c in ASSEMBLY_BODY_PATTERNS)


def test_annotate_ucundan_uca(tmp_path: Path):
    """Ürünün çağırdığı ``annotate``: yapı içi erişime yorum yok, gerçek matrise var."""
    dec = tmp_path / "dec"
    dec.mkdir()
    (dec / "FUN_00105b70.c").write_text(
        "void FUN_00105b70(long strided_array, long idx_2)\n{\n"
        "  buf_9 = (uint64_t *)strided_array[idx_2 * 2 + 1];\n}\n", encoding="utf-8")
    (dec / "matvec.c").write_text(
        "void matvec(double *A, double *x, long ncols)\n{\n"
        "  c = A[row * ncols + col] * x[col];\n}\n", encoding="utf-8")
    out = tmp_path / "out"
    res = CodeBlockAnnotator(None).annotate(dec, tmp_path / "yok.json", tmp_path / "yok2.json", out)
    assert res.success
    yazilan = {p.name: p.read_text() for p in out.glob("*.c")}
    assert "Row-major" not in yazilan.get("FUN_00105b70.c", "")
    assert "Row-major matrix access" in yazilan.get("matvec.c", "")
