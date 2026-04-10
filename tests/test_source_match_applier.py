"""SourceMatchApplier birim testleri.

Minified isimleri orijinale cevirme isleminin dogrulugunu test eder.

Onemli test senaryolari:
- Basit identifier rename
- String literal koruma (string icerisindeki isimler degismemeli)
- Property access koruma (.e, .t degismemeli)
- JS keyword koruması
- Bos mapping
- Coklu replacement
- Template literal koruma
- Comment icindeki isimler (degismeli -- identifier olabilir)
- Scope-safe rename: kisa isimler daha uzun isimlerin parcasi degil

Calistirma:
    pytest tests/test_source_match_applier.py -v
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from karadul.reconstruction.source_matcher.applier import (
    SourceMatchApplier,
    _build_identifier_pattern,
    _should_skip,
)


# ---------------------------------------------------------------------------
# _should_skip testleri
# ---------------------------------------------------------------------------

class TestShouldSkip:
    """Filtreleme fonksiyonu testleri."""

    def test_empty_old_name(self):
        assert _should_skip("", "element") is True

    def test_empty_new_name(self):
        assert _should_skip("e", "") is True

    def test_same_names(self):
        assert _should_skip("foo", "foo") is True

    def test_js_keyword_old(self):
        assert _should_skip("return", "myReturn") is True

    def test_js_keyword_new(self):
        assert _should_skip("e", "class") is True

    def test_global_name(self):
        assert _should_skip("console", "logger") is True

    def test_webpack_require(self):
        assert _should_skip("__webpack_require__", "importModule") is True

    def test_valid_rename(self):
        assert _should_skip("e", "element") is False

    def test_valid_rename_two_char(self):
        assert _should_skip("fn", "callback") is False


# ---------------------------------------------------------------------------
# _build_identifier_pattern testleri
# ---------------------------------------------------------------------------

class TestIdentifierPattern:
    """Regex pattern testleri."""

    def test_simple_identifier(self):
        pat = _build_identifier_pattern("e")
        assert pat.search("var e = 5") is not None

    def test_no_match_property(self):
        """Property access (.e) eslesmemeli."""
        pat = _build_identifier_pattern("e")
        assert pat.search("obj.e") is None

    def test_no_match_part_of_word(self):
        """Daha uzun kelimenin parcasi eslesmemeli."""
        pat = _build_identifier_pattern("e")
        assert pat.search("element") is None

    def test_match_after_paren(self):
        pat = _build_identifier_pattern("e")
        m = pat.search("(e)")
        assert m is not None

    def test_match_after_comma(self):
        pat = _build_identifier_pattern("t")
        m = pat.search("function(e, t)")
        assert m is not None

    def test_no_match_after_dollar(self):
        """$ ile biten isimden sonra eslesmemeli."""
        pat = _build_identifier_pattern("e")
        assert pat.search("$e") is None

    def test_match_beginning_of_line(self):
        pat = _build_identifier_pattern("e")
        m = pat.search("e = 5")
        assert m is not None

    def test_no_match_underscore_prefix(self):
        """_e gibi isimler eslesmemeli (e pattern'i icin)."""
        pat = _build_identifier_pattern("e")
        assert pat.search("_e") is None


# ---------------------------------------------------------------------------
# SourceMatchApplier -- apply_to_file testleri
# ---------------------------------------------------------------------------

class TestApplyToFile:
    """Dosya bazli rename testleri."""

    def _apply(self, code: str, mapping: dict[str, str]) -> str:
        """Yardimci: gecici dosya olustur, rename uygula, sonucu oku."""
        applier = SourceMatchApplier()
        with tempfile.NamedTemporaryFile(
            suffix=".js", mode="w", delete=False,
        ) as f:
            f.write(code)
            src = Path(f.name)

        out = src.with_suffix(".renamed.js")
        try:
            applier.apply_to_file(src, mapping, out)
            return out.read_text()
        finally:
            src.unlink(missing_ok=True)
            out.unlink(missing_ok=True)

    def test_simple_rename(self):
        code = "var e = 5; console.log(e);"
        result = self._apply(code, {"e": "element"})
        assert "var element = 5" in result
        assert "console.log(element)" in result
        # "var e " (boslukla) artik olmamali -- "var element" oldu
        assert "var e " not in result

    def test_multiple_variables(self):
        code = "function(e, t, n) { return e + t + n; }"
        result = self._apply(code, {
            "e": "element",
            "t": "type",
            "n": "name",
        })
        assert "element" in result
        assert "type" in result
        assert "name" in result

    def test_string_literal_protected(self):
        """String icerisindeki isimler degismemeli."""
        code = 'var e = "e is a variable"; console.log(e);'
        result = self._apply(code, {"e": "element"})
        assert '"e is a variable"' in result  # string korunmali
        assert "var element" in result

    def test_single_quote_protected(self):
        code = "var e = 'e'; console.log(e);"
        result = self._apply(code, {"e": "element"})
        assert "'e'" in result  # tek tirnak string korunmali
        assert "console.log(element)" in result

    def test_template_literal_protected(self):
        code = "var e = `e is ${e}`;"
        result = self._apply(code, {"e": "element"})
        # Template literal icerisindeki e korunmali
        assert "`e is ${e}`" in result or "`e is ${element}`" in result
        assert "var element" in result

    def test_property_access_not_renamed(self):
        """obj.e seklindeki property access degismemeli."""
        code = "var e = obj.e; e.push(1);"
        result = self._apply(code, {"e": "element"})
        assert "obj.e" in result  # property access korunmali
        assert "var element" in result

    def test_js_keyword_skipped(self):
        """return gibi keyword'ler rename edilmemeli."""
        code = "return e;"
        result = self._apply(code, {"return": "myReturn", "e": "element"})
        assert "return element" in result

    def test_empty_mapping(self):
        code = "var e = 5;"
        result = self._apply(code, {})
        assert result == code

    def test_no_match_in_code(self):
        """Mapping'deki isim kodda yoksa degisiklik olmamali."""
        code = "var x = 5;"
        result = self._apply(code, {"e": "element"})
        assert result == code

    def test_preserves_line_breaks(self):
        code = "var e = 5;\nvar t = 10;\nreturn e + t;\n"
        result = self._apply(code, {"e": "element", "t": "type"})
        lines = result.split("\n")
        assert len(lines) == 4  # 3 satir + son bos satir

    def test_escaped_string(self):
        """Escape character icerisindeki string korunmali."""
        code = r'var e = "e\"s"; console.log(e);'
        result = self._apply(code, {"e": "element"})
        assert "console.log(element)" in result

    def test_block_comment_preserved(self):
        code = "/* e is important */ var e = 5;"
        result = self._apply(code, {"e": "element"})
        assert "var element" in result

    def test_line_comment_preserved(self):
        code = "// e is a variable\nvar e = 5;"
        result = self._apply(code, {"e": "element"})
        assert "var element" in result


# ---------------------------------------------------------------------------
# SourceMatchApplier -- apply_to_directory testleri
# ---------------------------------------------------------------------------

class TestApplyToDirectory:
    """Dizin bazli toplu rename testleri."""

    def test_multiple_modules(self, tmp_path):
        """Birden fazla modulu rename et."""
        modules_dir = tmp_path / "modules"
        modules_dir.mkdir()

        (modules_dir / "module_1.js").write_text(
            "function(e, t) { return e + t; }"
        )
        (modules_dir / "module_2.js").write_text(
            "var n = require('fs'); n.readFile('test');"
        )

        output_dir = tmp_path / "output"
        applier = SourceMatchApplier()
        stats = applier.apply_to_directory(
            modules_dir, output_dir,
            {
                "module_1": {"e": "left", "t": "right"},
                "module_2": {"n": "fileSystem"},
            },
        )

        # module_1 rename olmus olmali
        assert "module_1" in stats
        out1 = (output_dir / "module_1.js").read_text()
        assert "left" in out1
        assert "right" in out1

        # module_2 rename olmus olmali
        assert "module_2" in stats
        out2 = (output_dir / "module_2.js").read_text()
        assert "fileSystem" in out2

    def test_missing_module(self, tmp_path):
        """Mevcut olmayan modul atlanmali."""
        modules_dir = tmp_path / "modules"
        modules_dir.mkdir()

        output_dir = tmp_path / "output"
        applier = SourceMatchApplier()
        stats = applier.apply_to_directory(
            modules_dir, output_dir,
            {"nonexistent": {"e": "element"}},
        )
        assert len(stats) == 0

    def test_inplace_rename(self, tmp_path):
        """Output dir == modules dir ise yerinde degistir."""
        modules_dir = tmp_path / "modules"
        modules_dir.mkdir()
        (modules_dir / "mod.js").write_text("var e = 1;")

        applier = SourceMatchApplier()
        stats = applier.apply_to_directory(
            modules_dir, modules_dir,
            {"mod": {"e": "value"}},
        )

        content = (modules_dir / "mod.js").read_text()
        assert "var value" in content


# ---------------------------------------------------------------------------
# SourceMatchApplier -- dry_run modu
# ---------------------------------------------------------------------------

class TestDryRun:
    """Dry run modu: dosya degistirmez."""

    def test_dry_run_no_write(self, tmp_path):
        src = tmp_path / "test.js"
        src.write_text("var e = 1;")

        applier = SourceMatchApplier(dry_run=True)
        count = applier.apply_to_file(src, {"e": "element"})

        # Count donmeli ama dosya degismemis olmali
        assert count > 0
        assert src.read_text() == "var e = 1;"


# ---------------------------------------------------------------------------
# Edge case'ler
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Ozel durumlar ve sinir kosullari."""

    def test_regex_special_chars_in_name(self):
        """Orijinal isimde regex ozel karakter olmamasini kontrol et.
        (pratikte olmaz ama guvenlik icin)."""
        applier = SourceMatchApplier()
        with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False) as f:
            f.write("var $e = 1;")
            src = Path(f.name)
        out = src.with_suffix(".out.js")
        try:
            count = applier.apply_to_file(src, {"$e": "dollarElement"}, out)
            result = out.read_text()
            assert "dollarElement" in result
        finally:
            src.unlink(missing_ok=True)
            out.unlink(missing_ok=True)

    def test_large_mapping(self):
        """26 harflik mapping (a-z) uygulanabilmeli."""
        import string
        mapping = {c: f"var_{c}" for c in string.ascii_lowercase}
        code = "; ".join(f"var {c} = {i}" for i, c in enumerate(string.ascii_lowercase))
        code += ";"

        applier = SourceMatchApplier()
        with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False) as f:
            f.write(code)
            src = Path(f.name)
        out = src.with_suffix(".out.js")
        try:
            count = applier.apply_to_file(src, mapping, out)
            result = out.read_text()
            # a-z'nin hepsi rename edilmis olmali (return, var gibi keyword'ler haric)
            # "a" -> "var_a" kontrol edelim
            assert "var_a" in result
            assert "var_z" in result
        finally:
            src.unlink(missing_ok=True)
            out.unlink(missing_ok=True)

    def test_adjacent_identifiers(self):
        """Yanyana identifierlar dogru rename edilmeli."""
        applier = SourceMatchApplier()
        code = "e+t"  # iki identifier arasinda +

        with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False) as f:
            f.write(code)
            src = Path(f.name)
        out = src.with_suffix(".out.js")
        try:
            applier.apply_to_file(src, {"e": "left", "t": "right"}, out)
            result = out.read_text()
            assert result == "left+right"
        finally:
            src.unlink(missing_ok=True)
            out.unlink(missing_ok=True)

    def test_nested_strings(self):
        """Ic ice string: "it's a 'test'" korunmali."""
        applier = SourceMatchApplier()
        code = '''var e = "it's e"; e;'''

        with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False) as f:
            f.write(code)
            src = Path(f.name)
        out = src.with_suffix(".out.js")
        try:
            applier.apply_to_file(src, {"e": "element"}, out)
            result = out.read_text()
            assert '''"it's e"''' in result  # string korunmali
            assert result.endswith("element;")  # identifier degismeli
        finally:
            src.unlink(missing_ok=True)
            out.unlink(missing_ok=True)
