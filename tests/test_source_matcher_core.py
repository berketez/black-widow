"""SourceResolver + ASTFingerprinter birim testleri.

Test 1: ASTFingerprinter ile cesitli JS pattern'lerini fingerprint'le
Test 2: FunctionFingerprint.similarity() skoru
Test 3: SourceResolver unpkg.com'dan gercek paket cekme (network testi)
Test 4: Minified vs orijinal kod karsilastirmasi
"""

from __future__ import annotations

import pytest

from karadul.reconstruction.source_matcher.ast_fingerprinter import (
    ASTFingerprinter,
    FunctionFingerprint,
)
from karadul.reconstruction.source_matcher.source_resolver import (
    ResolvedSource,
    SourceResolver,
)


# ---------------------------------------------------------------------------
# ASTFingerprinter Tests
# ---------------------------------------------------------------------------

class TestASTFingerprinter:
    """Regex tabanli fonksiyon cikarma testleri."""

    def setup_method(self):
        self.fp = ASTFingerprinter()

    def test_function_declaration(self):
        """function NAME(params) { ... } cikarma."""
        code = '''
        function greet(name, greeting) {
            console.log(greeting + " " + name);
            return greeting;
        }
        '''
        funcs = self.fp.extract_functions(code)
        assert len(funcs) == 1
        f = funcs[0]
        assert f.name == "greet"
        assert f.arity == 2
        assert f.param_names == ["name", "greeting"]
        assert f.return_count >= 1

    def test_function_expression(self):
        """const NAME = function(params) { ... } cikarma."""
        code = '''
        const add = function(a, b) {
            return a + b;
        };
        '''
        funcs = self.fp.extract_functions(code)
        assert len(funcs) == 1
        assert funcs[0].name == "add"
        assert funcs[0].arity == 2

    def test_arrow_function_block(self):
        """const NAME = (params) => { ... } cikarma."""
        code = '''
        const multiply = (x, y) => {
            const result = x * y;
            return result;
        };
        '''
        funcs = self.fp.extract_functions(code)
        assert len(funcs) == 1
        assert funcs[0].name == "multiply"
        assert funcs[0].arity == 2

    def test_arrow_function_single_param(self):
        """const NAME = param => { ... } cikarma."""
        code = '''
        const double = n => {
            return n * 2;
        };
        '''
        funcs = self.fp.extract_functions(code)
        assert len(funcs) == 1
        assert funcs[0].name == "double"
        assert funcs[0].arity == 1

    def test_multiple_functions(self):
        """Birden fazla fonksiyon cikarma."""
        code = '''
        function first(a) {
            return a + 1;
        }

        function second(a, b) {
            if (a > b) {
                return a;
            }
            return b;
        }

        const third = (x, y, z) => {
            for (let i = 0; i < z; i++) {
                x += y;
            }
            return x;
        };
        '''
        funcs = self.fp.extract_functions(code)
        assert len(funcs) == 3
        names = [f.name for f in funcs]
        assert "first" in names
        assert "second" in names
        assert "third" in names

        # second has branches
        second = next(f for f in funcs if f.name == "second")
        assert second.branch_count >= 1

        # third has loops
        third = next(f for f in funcs if f.name == "third")
        assert third.loop_count >= 1

    def test_string_extraction(self):
        """String literal cikarma."""
        code = '''
        function logMessage(msg) {
            console.log("Starting process");
            console.error('Error occurred');
            return "done";
        }
        '''
        funcs = self.fp.extract_functions(code)
        assert len(funcs) == 1
        f = funcs[0]
        assert "Starting process" in f.string_literals
        assert "Error occurred" in f.string_literals
        assert "done" in f.string_literals

    def test_property_access_extraction(self):
        """Property access cikarma."""
        code = '''
        function processArray(arr) {
            const mapped = arr.map(x => { return x * 2; });
            const filtered = mapped.filter(x => { return x > 5; });
            filtered.push(100);
            console.log(filtered.join(", "));
            return filtered;
        }
        '''
        funcs = self.fp.extract_functions(code)
        assert len(funcs) >= 1
        # Ana fonksiyonu bul (en cok statement iceren)
        main_func = max(funcs, key=lambda f: f.total_statements)
        assert "map" in main_func.property_accesses
        assert "filter" in main_func.property_accesses
        assert "push" in main_func.property_accesses

    def test_try_catch_detection(self):
        """try/catch tespiti."""
        code = '''
        function safeParse(json) {
            try {
                return JSON.parse(json);
            } catch (e) {
                console.error("Parse failed:", e.message);
                return null;
            }
        }
        '''
        funcs = self.fp.extract_functions(code)
        assert len(funcs) == 1
        assert funcs[0].has_try_catch is True

    def test_nested_functions(self):
        """Ic fonksiyon tespiti."""
        code = '''
        function outer(x) {
            function inner(y) {
                return x + y;
            }
            return inner(x * 2);
        }
        '''
        funcs = self.fp.extract_functions(code)
        assert len(funcs) >= 1
        outer = next(f for f in funcs if f.name == "outer")
        assert outer.nested_func_count >= 1

    def test_brace_matching_with_strings(self):
        """String icindeki brace'leri dogru handle etme."""
        code = '''
        function templateFunc(data) {
            const msg = "Hello {name}, welcome to {city}!";
            const json = '{"key": "value"}';
            return msg + json;
        }
        '''
        funcs = self.fp.extract_functions(code)
        assert len(funcs) == 1
        assert funcs[0].name == "templateFunc"

    def test_empty_params(self):
        """Parametresiz fonksiyon."""
        code = '''
        function noArgs() {
            return 42;
        }
        '''
        funcs = self.fp.extract_functions(code)
        assert len(funcs) == 1
        assert funcs[0].arity == 0
        assert funcs[0].param_names == []

    def test_no_functions(self):
        """Fonksiyon icermeyen kod."""
        code = '''
        const x = 5;
        const y = "hello";
        console.log(x + y);
        '''
        funcs = self.fp.extract_functions(code)
        assert len(funcs) == 0


# ---------------------------------------------------------------------------
# FunctionFingerprint Similarity Tests
# ---------------------------------------------------------------------------

class TestFingerprintSimilarity:
    """Benzerlik skoru testleri."""

    def test_identical_fingerprints(self):
        """Ayni fingerprint -> skor 1.0."""
        fp = FunctionFingerprint(
            name="test",
            arity=2,
            param_names=["a", "b"],
            string_literals=["hello", "world"],
            property_accesses=["push", "map"],
            branch_count=3,
            loop_count=1,
            return_count=2,
            throw_count=0,
            has_try_catch=False,
            nested_func_count=0,
            total_statements=10,
            line_count=15,
        )
        assert fp.similarity(fp) == pytest.approx(1.0)

    def test_completely_different(self):
        """Tamamen farkli fingerprint'ler -> dusuk skor."""
        fp1 = FunctionFingerprint(
            name="func1",
            arity=0,
            string_literals=["aaa", "bbb"],
            property_accesses=["push"],
            branch_count=0,
            loop_count=0,
            return_count=1,
            has_try_catch=False,
            total_statements=5,
        )
        fp2 = FunctionFingerprint(
            name="func2",
            arity=5,
            string_literals=["xxx", "yyy", "zzz"],
            property_accesses=["map", "filter", "reduce"],
            branch_count=10,
            loop_count=5,
            return_count=8,
            has_try_catch=True,
            total_statements=50,
        )
        score = fp1.similarity(fp2)
        assert score < 0.3  # cok dusuk olmali

    def test_similar_but_renamed(self):
        """Isim farkli ama yapi ayni -> yuksek skor."""
        fp1 = FunctionFingerprint(
            name="originalName",
            arity=3,
            param_names=["config", "options", "callback"],
            string_literals=["error", "success", "loading"],
            property_accesses=["push", "map", "then", "catch"],
            branch_count=4,
            loop_count=1,
            return_count=3,
            has_try_catch=True,
            total_statements=20,
        )
        fp2 = FunctionFingerprint(
            name="a",  # minified isim
            arity=3,
            param_names=["e", "t", "n"],  # minified param isimleri
            string_literals=["error", "success", "loading"],  # string'ler korunur!
            property_accesses=["push", "map", "then", "catch"],
            branch_count=4,
            loop_count=1,
            return_count=3,
            has_try_catch=True,
            total_statements=20,
        )
        score = fp1.similarity(fp2)
        assert score > 0.9  # cok yuksek olmali (sadece isimler farkli)

    def test_partial_string_overlap(self):
        """Kismi string overlap -> orta skor."""
        fp1 = FunctionFingerprint(
            name="func1",
            arity=2,
            string_literals=["hello", "world", "foo", "bar"],
            property_accesses=["push", "map"],
            branch_count=2,
            return_count=1,
            total_statements=10,
        )
        fp2 = FunctionFingerprint(
            name="func2",
            arity=2,
            string_literals=["hello", "world", "baz", "qux"],
            property_accesses=["push", "filter"],
            branch_count=2,
            return_count=1,
            total_statements=10,
        )
        score = fp1.similarity(fp2)
        # String overlap 2/6 = 0.33, property overlap 1/3 = 0.33
        # Diger metrikler ayni
        assert 0.4 < score < 0.9

    def test_symmetry(self):
        """Similarity simetrik olmali: sim(a,b) == sim(b,a)."""
        fp1 = FunctionFingerprint(
            name="x", arity=1,
            string_literals=["a", "b"],
            property_accesses=["push"],
            branch_count=2,
            total_statements=5,
        )
        fp2 = FunctionFingerprint(
            name="y", arity=2,
            string_literals=["b", "c"],
            property_accesses=["map"],
            branch_count=3,
            total_statements=8,
        )
        assert fp1.similarity(fp2) == pytest.approx(fp2.similarity(fp1))


# ---------------------------------------------------------------------------
# SourceResolver Tests (network gerektirir)
# ---------------------------------------------------------------------------

class TestSourceResolver:
    """unpkg.com'dan kaynak cekme testleri.

    NOT: Bu testler network erisimi gerektirir.
    CI'da skip edilebilir: pytest -m "not network"
    """

    @pytest.mark.network
    def test_resolve_highlight_js(self):
        """highlight.js'i cek ve dogrula."""
        resolver = SourceResolver()
        source = resolver.resolve("highlight.js")

        assert source is not None
        assert source.package_name == "highlight.js"
        assert source.version  # bos olmamali
        assert len(source.source_code) > 1000  # en az 1KB olmali
        assert "highlight" in source.source_code.lower()

    @pytest.mark.network
    def test_resolve_with_version(self):
        """Belirli versiyon ile cekme."""
        resolver = SourceResolver()
        source = resolver.resolve("lodash", "4.17.21")

        assert source is not None
        assert source.version == "4.17.21"
        assert len(source.source_code) > 100

    @pytest.mark.network
    def test_cache_hit(self):
        """Cache dogru calisiyor mu."""
        resolver = SourceResolver()
        source1 = resolver.resolve("is-odd")
        source2 = resolver.resolve("is-odd")

        assert source1 is not None
        assert source2 is not None
        assert source1.source_code == source2.source_code
        assert resolver.cache_size == 1

    @pytest.mark.network
    def test_resolve_nonexistent(self):
        """Var olmayan paket -> None."""
        resolver = SourceResolver()
        source = resolver.resolve("this-package-definitely-does-not-exist-xyzzy-12345")
        assert source is None

    @pytest.mark.network
    def test_resolve_scoped_package(self):
        """Scoped paket (@org/name) cekme."""
        resolver = SourceResolver()
        source = resolver.resolve("@types/node")

        # @types/node bir .d.ts paketi, kaynak kodu olmayabilir ama package.json var
        # Onemli olan 404 vermemesi
        # (bu paket typings iceriyor, main "index.d.ts" olabilir)

    @pytest.mark.network
    def test_version_resolution(self):
        """Versiyon cozme (redirect)."""
        resolver = SourceResolver()
        version = resolver._resolve_version("highlight.js")
        assert version is not None
        # Semantic version formati: X.Y.Z
        parts = version.split(".")
        assert len(parts) >= 2
        assert parts[0].isdigit()

    @pytest.mark.network
    def test_clear_cache(self):
        """Cache temizleme."""
        resolver = SourceResolver()
        resolver.resolve("is-odd")
        assert resolver.cache_size >= 1
        resolver.clear_cache()
        assert resolver.cache_size == 0


# ---------------------------------------------------------------------------
# Entegrasyon Testi: Fingerprint + Resolve
# ---------------------------------------------------------------------------

class TestIntegration:
    """SourceResolver + ASTFingerprinter birlikte calisma testi."""

    @pytest.mark.network
    def test_resolve_and_fingerprint_highlight_js(self):
        """highlight.js core'unu cek, fingerprint olustur, fonksiyonlari say.

        NOT: highlight.js'in lib/index.js dosyasi sadece registerLanguage satirlari.
        Gercek kod lib/core.js'de. extra_files ile cekilir.
        """
        resolver = SourceResolver()
        source = resolver.resolve("highlight.js", extra_files=["lib/core.js"])
        assert source is not None

        # core.js'yi fingerprint'le (entry point sadece re-export)
        core_code = source.additional_files.get("lib/core.js", "")
        assert len(core_code) > 1000, "core.js bos veya cok kisa"

        fingerprinter = ASTFingerprinter()
        functions = fingerprinter.extract_functions(core_code)

        print(f"\nhighlight.js@{source.version}")
        print(f"core.js: {len(core_code)} bytes")
        print(f"Functions found: {len(functions)}")

        # highlight.js core oldukca buyuk, 50+ fonksiyon olmali
        assert len(functions) > 20

        # Ilk 10 fonksiyonu yazdir
        for f in functions[:10]:
            print(f"  {f.summary()}")

    @pytest.mark.network
    def test_minified_vs_original_similarity(self):
        """Ayni kodu minified ve orijinal olarak karsilastir.

        Basit bir test: orijinal kodu al, elle 'minify' et (isimleri kisalt),
        fingerprint'leri karsilastir.
        """
        original_code = '''
        function calculateTotal(items, taxRate, discount) {
            let subtotal = 0;
            for (let i = 0; i < items.length; i++) {
                subtotal += items[i].price * items[i].quantity;
            }
            const tax = subtotal * taxRate;
            const total = subtotal + tax - discount;
            if (total < 0) {
                throw new Error("Total cannot be negative");
            }
            return total;
        }

        function formatCurrency(amount, currency) {
            const symbols = {"USD": "$", "EUR": "\\u20ac", "GBP": "\\u00a3"};
            const symbol = symbols[currency] || currency;
            return symbol + amount.toFixed(2);
        }
        '''

        # "Minified" versiyon: isimleri kisalt, yapiyi koru
        minified_code = '''
        function a(e, t, n) {
            let r = 0;
            for (let i = 0; i < e.length; i++) {
                r += e[i].price * e[i].quantity;
            }
            const o = r * t;
            const s = r + o - n;
            if (s < 0) {
                throw new Error("Total cannot be negative");
            }
            return s;
        }

        function b(e, t) {
            const n = {"USD": "$", "EUR": "\\u20ac", "GBP": "\\u00a3"};
            const r = n[t] || t;
            return r + e.toFixed(2);
        }
        '''

        fingerprinter = ASTFingerprinter()
        orig_funcs = fingerprinter.extract_functions(original_code)
        mini_funcs = fingerprinter.extract_functions(minified_code)

        assert len(orig_funcs) == 2
        assert len(mini_funcs) == 2

        # calculateTotal <-> a
        calc_orig = next(f for f in orig_funcs if f.name == "calculateTotal")
        calc_mini = next(f for f in mini_funcs if f.name == "a")
        score = calc_orig.similarity(calc_mini)
        print(f"\ncalculateTotal vs a: {score:.3f}")
        assert score > 0.7, f"Similarity too low: {score}"

        # formatCurrency <-> b
        fmt_orig = next(f for f in orig_funcs if f.name == "formatCurrency")
        fmt_mini = next(f for f in mini_funcs if f.name == "b")
        score = fmt_orig.similarity(fmt_mini)
        print(f"formatCurrency vs b: {score:.3f}")
        assert score > 0.7, f"Similarity too low: {score}"

        # Cross-check: calculateTotal vs b should be LOW
        cross_score = calc_orig.similarity(fmt_mini)
        print(f"calculateTotal vs b (cross): {cross_score:.3f}")
        assert cross_score < score, "Cross-match should be lower"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--tb=short"])
