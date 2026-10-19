"""scripts/measurement/csrc_index.py — C kaynak dizinleyicisinin birim testleri.

Dizinleyici etiket paketinin gövde kaynağıdır (plan v2 G4). Kilitlenen davranışlar:
  (a) BSD biçiminde (dönüş tipi bir üst satırda) tanım: ad, satır, gövde sınırları,
  (b) yorum, string ve char sabitlerindeki süslü parantez eşleştirmeyi bozmaz,
  (c) önişlemci satırları ve ``#ifdef``/``#if 0`` dalları,
  (d) yapı ve dizi başlatıcıları fonksiyon sayılmaz, kontrol sözcükleri ad olmaz,
  (e) aynı adın birden çok tanımı dosya sırasıyla listelenir.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_PATH = Path(__file__).resolve().parents[1] / "scripts" / "measurement" / "csrc_index.py"
_spec = importlib.util.spec_from_file_location("csrc_index_under_test", _PATH)
csrc = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = csrc
_spec.loader.exec_module(csrc)


def _write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def test_bsd_style_definition_includes_return_type_line(tmp_path):
    src = (
        "#include <stdio.h>\n"
        "\n"
        "static void\n"
        "alerts_reset(struct window *w)\n"
        "{\n"
        "\tw->flags = 0;\n"
        "}\n"
        "\n"
        "int helper(int a) { return a + 1; }\n"
    )
    funcs = csrc.functions_in_file(_write(tmp_path, "a.c", src))
    assert [f["name"] for f in funcs] == ["alerts_reset", "helper"]
    first = funcs[0]
    # Ad sütun 0'daysa bir üst satırdaki dönüş tipi de gövdeye girer.
    assert first["text"] == "static void\nalerts_reset(struct window *w)\n{\n\tw->flags = 0;\n}"
    assert first["line"] == 5  # açılan süslü parantezin satırı
    assert funcs[1]["text"] == "int helper(int a) { return a + 1; }"


def test_braces_in_comments_strings_and_chars_are_ignored(tmp_path):
    src = (
        "void\n"
        "f(void)\n"
        "{\n"
        "\tputs(\"} not the end {\");\n"
        "\tchar c = '}';\n"
        "\tchar *q = \"esc \\\" }\";\n"
        "\t/* } yorum { */\n"
        "\t// } satır yorumu\n"
        "\treturn;\n"
        "}\n"
        "void\n"
        "g(void)\n"
        "{\n"
        "}\n"
    )
    funcs = csrc.functions_in_file(_write(tmp_path, "b.c", src))
    assert [f["name"] for f in funcs] == ["f", "g"]
    assert funcs[0]["text"].endswith("\treturn;\n}")
    assert "} not the end {" in funcs[0]["text"]  # metin özgün kaynaktan gelir


def test_preprocessor_lines_and_alternative_branches(tmp_path):
    src = (
        "#define OPEN {\n"
        "int\n"
        "h(int a)\n"
        "{\n"
        "#ifdef X\n"
        "\tif (a) {\n"
        "#else\n"
        "\tif (!a) {\n"
        "#endif\n"
        "\t\ta++;\n"
        "\t}\n"
        "\treturn a;\n"
        "}\n"
        "#if 0\n"
        "int dead(void) {\n"
        "#else\n"
        "int live(void) {\n"
        "#endif\n"
        "\treturn 0;\n"
        "}\n"
    )
    funcs = csrc.functions_in_file(_write(tmp_path, "c.c", src))
    assert [f["name"] for f in funcs] == ["h", "live"]
    assert funcs[0]["text"].endswith("\treturn a;\n}")


def test_initializers_and_keywords_are_not_functions(tmp_path):
    src = (
        "struct entry table[] = {\n"
        "\t{ \"a\", 1 },\n"
        "};\n"
        "struct point { int x; int y; };\n"
        "int\n"
        "k(void)\n"
        "{\n"
        "\treturn sizeof(struct point);\n"
        "}\n"
    )
    funcs = csrc.functions_in_file(_write(tmp_path, "d.c", src))
    assert [f["name"] for f in funcs] == ["k"]
    assert not any(f["name"] in {"if", "while", "for", "switch", "sizeof"} for f in funcs)


def test_index_tree_lists_every_definition_in_path_order(tmp_path):
    _write(tmp_path, "z.c", "int\ndup(void)\n{\n\treturn 2;\n}\n")
    _write(tmp_path, "a.c", "int\ndup(void)\n{\n\treturn 1;\n}\n")
    _write(tmp_path, "sub/x.h", "static inline int\nonly_in_header(void)\n{\n\treturn 3;\n}\n")
    _write(tmp_path, "notes.txt", "int\nnot_c(void)\n{\n}\n")
    idx = csrc.index_tree(tmp_path)
    assert set(idx) == {"dup", "only_in_header"}
    assert [Path(d["file"]).name for d in idx["dup"]] == ["a.c", "z.c"]
    assert "return 1;" in idx["dup"][0]["text"]
    assert Path(idx["only_in_header"][0]["file"]).name == "x.h"
