"""N-gram namer unit testleri (v1.8.7)."""

import hashlib
import struct
from pathlib import Path

import pytest

from karadul.reconstruction.ngram_namer import (
    NgramDB,
    NgramNamer,
    NgramNamerResult,
    NgramPrediction,
    NgramVocab,
    NGRAM_SIZES,
    TOP_K,
    _GENERIC_VAR_RE,
    _mark_variables,
    ngram_hash,
    normalize_token,
    normalize_tokens,
    tokenize_c,
)


# ========================================================================
# Token normalizasyonu testleri
# ========================================================================


class TestTokenizeC:
    def test_simple_function(self):
        code = "int foo(int a) { return a + 1; }"
        tokens = tokenize_c(code)
        assert "int" in tokens
        assert "foo" in tokens
        assert "return" in tokens
        assert "+" in tokens
        assert "1" in tokens

    def test_hex_numbers(self):
        tokens = tokenize_c("x = 0xDEAD;")
        assert "0xDEAD" in tokens

    def test_pointers(self):
        tokens = tokenize_c("char *ptr;")
        assert "*" in tokens
        assert "ptr" in tokens

    def test_empty_code(self):
        assert tokenize_c("") == []

    def test_ghidra_decompiled(self):
        code = "void FUN_00401000(undefined8 param_1, int local_10) {"
        tokens = tokenize_c(code)
        assert "FUN_00401000" in tokens
        assert "undefined8" in tokens
        assert "param_1" in tokens
        assert "local_10" in tokens


class TestNormalizeToken:
    def test_compiler_prefix_fun(self):
        assert normalize_token("FUN_00401000") == "FUN_XXX"

    def test_compiler_prefix_dat(self):
        assert normalize_token("DAT_00403000") == "DAT_XXX"

    def test_compiler_prefix_lab(self):
        assert normalize_token("LAB_00401050") == "LAB_XXX"

    def test_compiler_prefix_sub(self):
        assert normalize_token("sub_401000") == "sub_XXX"

    def test_compiler_prefix_thunk(self):
        assert normalize_token("thunk_FUN_00401000") == "thunk_FUN_XXX"

    def test_string_literal(self):
        assert normalize_token('"hello world"') == "<STRING>"

    def test_ghidra_stack(self):
        assert normalize_token("Stack_0") == "<ghidra_stack>"
        assert normalize_token("auStack_18") == "<ghidra_stack>"

    def test_ghidra_var(self):
        assert normalize_token("Var123") == "<ghidra_var>"
        assert normalize_token("iVar5") == "<ghidra_var>"

    def test_hex_large(self):
        assert normalize_token("0xDEADBEEF") == "<NUM_8>"

    def test_hex_small(self):
        assert normalize_token("0x10") == "0x10"
        assert normalize_token("0xff") == "0xff"

    def test_decimal_large(self):
        assert normalize_token("65536") == "<NUM_5>"

    def test_decimal_small(self):
        assert normalize_token("42") == "0x2a"
        assert normalize_token("0") == "0x0"
        assert normalize_token("255") == "0xff"

    def test_keyword_unchanged(self):
        assert normalize_token("int") == "int"
        assert normalize_token("return") == "return"
        assert normalize_token("void") == "void"

    def test_normal_identifier(self):
        assert normalize_token("strlen") == "strlen"
        assert normalize_token("my_func") == "my_func"


class TestNormalizeTokens:
    def test_batch(self):
        tokens = ["FUN_00401000", "0xDEAD", "int", "param_1"]
        result = normalize_tokens(tokens)
        assert result[0] == "FUN_XXX"
        assert result[1] == "<NUM_4>"
        assert result[2] == "int"
        assert result[3] == "param_1"  # degisken normalizasyonu _mark_variables'da


# ========================================================================
# Degisken marker testleri
# ========================================================================


class TestMarkVariables:
    def test_params_marked(self):
        tokens = ["int", "param_1", "+", "param_2"]
        marked, positions = _mark_variables(tokens)
        assert marked[1] == "@@var_0@@"
        assert marked[3] == "@@var_1@@"
        assert positions[1] == "param_1"
        assert positions[3] == "param_2"

    def test_locals_marked(self):
        tokens = ["local_10", "=", "local_20"]
        marked, positions = _mark_variables(tokens)
        assert "@@var_0@@" in marked
        assert "@@var_1@@" in marked

    def test_ivar_marked(self):
        tokens = ["iVar1", "=", "0"]
        marked, positions = _mark_variables(tokens)
        assert marked[0] == "@@var_0@@"

    def test_non_generic_unchanged(self):
        tokens = ["strlen", "buffer", "count"]
        marked, positions = _mark_variables(tokens)
        assert marked == tokens
        assert positions == {}

    def test_same_var_same_id(self):
        tokens = ["param_1", "+", "param_1"]
        marked, _ = _mark_variables(tokens)
        assert marked[0] == marked[2] == "@@var_0@@"

    def test_empty(self):
        marked, positions = _mark_variables([])
        assert marked == []
        assert positions == {}


class TestGenericVarRegex:
    def test_params(self):
        assert _GENERIC_VAR_RE.match("param_1")
        assert _GENERIC_VAR_RE.match("param_42")

    def test_locals(self):
        assert _GENERIC_VAR_RE.match("local_10")
        assert _GENERIC_VAR_RE.match("local_ff")

    def test_ivars(self):
        assert _GENERIC_VAR_RE.match("iVar1")
        assert _GENERIC_VAR_RE.match("uVar3")
        assert _GENERIC_VAR_RE.match("lVar5")

    def test_non_generic(self):
        assert not _GENERIC_VAR_RE.match("strlen")
        assert not _GENERIC_VAR_RE.match("buffer")
        assert not _GENERIC_VAR_RE.match("count")

    def test_in_stack(self):
        assert _GENERIC_VAR_RE.match("in_x0")

    def test_austack(self):
        assert _GENERIC_VAR_RE.match("auStack_38")

    def test_extraout(self):
        assert _GENERIC_VAR_RE.match("extraout_x0")


# ========================================================================
# N-gram hash testleri
# ========================================================================


class TestNgramHash:
    def test_deterministic(self):
        tokens = ["int", "@@var_0@@", "+", "1"]
        h1 = ngram_hash(tokens)
        h2 = ngram_hash(tokens)
        assert h1 == h2

    def test_length(self):
        h = ngram_hash(["a", "b", "c"])
        assert len(h) == 12

    def test_different_tokens_different_hash(self):
        h1 = ngram_hash(["int", "@@var_0@@"])
        h2 = ngram_hash(["char", "@@var_0@@"])
        assert h1 != h2

    def test_discriminator_matters(self):
        tokens = ["int", "x"]
        h1 = ngram_hash(tokens, b"left")
        h2 = ngram_hash(tokens, b"right")
        h3 = ngram_hash(tokens)
        assert h1 != h2
        assert h1 != h3

    def test_sha256_based(self):
        tokens = ["a", "b"]
        raw = b"a\xffb"
        expected = hashlib.sha256(raw).digest()[:12]
        assert ngram_hash(tokens) == expected


# ========================================================================
# NgramVocab testleri
# ========================================================================


class TestNgramVocab:
    def test_add_and_lookup(self):
        v = NgramVocab()
        vid = v.add("buffer", 10)
        assert vid == 0
        assert v.lookup("buffer") == 0
        assert v.reverse(0) == "buffer"
        assert v.count_by_id(0) == 10

    def test_unknown_lookup(self):
        v = NgramVocab()
        assert v.lookup("nonexistent") == -1

    def test_unknown_reverse(self):
        v = NgramVocab()
        assert v.reverse(999) == ""

    def test_add_increments(self):
        v = NgramVocab()
        v.add("buf", 5)
        v.add("buf", 3)
        assert v.count_by_id(0) == 8

    def test_save_load(self, tmp_path):
        """v1.10.0 Fix-9 C5 (sahte test duzeltmesi):
        Onceki test `assert v2.lookup("buffer") >= 0` tarzi kullaniyordu.
        Bu zayif -- test `lookup` miss durumunda -1 donuyor (>= 0 cakismaz)
        ama farkli ID'lerin UNIQUE oldugunu, orijinal count'larin KORUNDUGUNU,
        VE reverse()/count_by_id()'in persistance'tan sonra dogru cevap
        verdigini dogrulamiyordu. Simdi round-trip invariant'lari test edilir.
        """
        v = NgramVocab()
        v.add("buffer", 100)
        v.add("counter", 50)
        v.add("pointer", 75)

        path = tmp_path / "vocab.txt"
        v.save(path)

        v2 = NgramVocab.load(path)
        assert len(v2) == 3

        # 3 ismin ID'si bulunmali ve birbirinden farkli olmali
        id_buf = v2.lookup("buffer")
        id_cnt = v2.lookup("counter")
        id_ptr = v2.lookup("pointer")
        assert id_buf != -1, "buffer ID bulunamadi"
        assert id_cnt != -1, "counter ID bulunamadi"
        assert id_ptr != -1, "pointer ID bulunamadi"
        assert len({id_buf, id_cnt, id_ptr}) == 3, (
            f"ID'ler unique olmali: buf={id_buf}, cnt={id_cnt}, ptr={id_ptr}"
        )

        # Round-trip: reverse(id) orijinal ismi vermeli
        assert v2.reverse(id_buf) == "buffer"
        assert v2.reverse(id_cnt) == "counter"
        assert v2.reverse(id_ptr) == "pointer"

        # Count korundu mu (frequency persistance)
        assert v2.count_by_id(id_buf) == 100
        assert v2.count_by_id(id_cnt) == 50
        assert v2.count_by_id(id_ptr) == 75

        # Olmayan isim -1 donmeli (negatif dogrulama)
        assert v2.lookup("nonexistent_word") == -1

    def test_save_sorted_by_frequency(self, tmp_path):
        v = NgramVocab()
        v.add("rare", 1)
        v.add("common", 1000)
        v.add("medium", 50)

        path = tmp_path / "vocab.txt"
        v.save(path)

        lines = path.read_text().strip().split("\n")
        assert lines[0].startswith("common\t")
        assert lines[1].startswith("medium\t")
        assert lines[2].startswith("rare\t")

    def test_len(self):
        v = NgramVocab()
        assert len(v) == 0
        v.add("a", 1)
        v.add("b", 1)
        assert len(v) == 2


# ========================================================================
# NgramDB testleri
# ========================================================================


class TestNgramDB:
    def _make_db(self):
        """Test icin kucuk bir DB olustur."""
        entries = {}
        # 3 farkli n-gram hash'i
        h1 = ngram_hash(["int", "@@var_0@@", ";"])
        h2 = ngram_hash(["char", "*", "@@var_0@@"])
        h3 = ngram_hash(["for", "(", "@@var_0@@"])

        entries[h1] = {0: 50, 1: 10}  # "buffer": 50, "data": 10
        entries[h2] = {2: 30, 3: 5}   # "str": 30, "ptr": 5
        entries[h3] = {4: 100}         # "i": 100

        return NgramDB.build(entries, size=4, topk=TOP_K)

    def test_build_and_lookup(self):
        db = self._make_db()
        h1 = ngram_hash(["int", "@@var_0@@", ";"])
        result = db.lookup(h1)
        assert result is not None
        total, preds = result
        assert total == 60  # 50 + 10
        assert len(preds) >= 1

    def test_lookup_miss(self):
        db = self._make_db()
        h = ngram_hash(["nonexistent", "context", "here"])
        assert db.lookup(h) is None

    def test_save_load(self, tmp_path):
        db = self._make_db()
        path = tmp_path / "db_4.ngdb"
        db.save(path)

        db2 = NgramDB.load(path)
        assert len(db2) == len(db)
        assert db2.size == 4

        # Ayni lookup sonucu
        h1 = ngram_hash(["int", "@@var_0@@", ";"])
        r1 = db.lookup(h1)
        r2 = db2.lookup(h1)
        assert r1 is not None and r2 is not None
        assert r1[0] == r2[0]  # total

    def test_sorted_hashes(self):
        db = self._make_db()
        for i in range(len(db._hashes) - 1):
            assert db._hashes[i] <= db._hashes[i + 1]

    def test_build_empty(self):
        db = NgramDB.build({}, size=2)
        assert len(db) == 0

    def test_topk_limit(self):
        entries = {}
        h = ngram_hash(["test"])
        entries[h] = {i: 100 - i for i in range(20)}
        db = NgramDB.build(entries, size=2, topk=5)
        result = db.lookup(h)
        assert result is not None
        _, preds = result
        assert len(preds) == 5


# ========================================================================
# NgramNamer testleri
# ========================================================================


class TestNgramNamer:
    @pytest.fixture
    def db_dir(self, tmp_path):
        """Kucuk bir test DB olustur."""
        db_dir = tmp_path / "ngram_name_db"
        db_dir.mkdir()

        # Vocab
        vocab = NgramVocab()
        vocab.add("buffer", 100)
        vocab.add("count", 80)
        vocab.add("pointer", 60)
        vocab.add("length", 50)
        vocab.add("index", 40)
        vocab.save(db_dir / "vocab.txt")

        # DB: size 4 icin bazi n-gram'lar
        entries = {}

        # "strlen ( @@var_0@@ )" -> buffer (vid=0)
        tok_ctx = ["strlen", "(", "@@var_0@@", ")"]
        h = ngram_hash(["??"] * 2 + tok_ctx + ["??"] * 2)  # centered, half=4 (full size needs padding)
        # Aslinda centered n-gram tam olarak boyle calismaz, ama mantigi test eder
        entries[ngram_hash(tok_ctx)] = {0: 50, 3: 5}

        # "for ( @@var_0@@ =" -> index (vid=4)
        tok_for = ["for", "(", "@@var_0@@", "="]
        entries[ngram_hash(tok_for)] = {4: 80, 1: 10}

        db = NgramDB.build(entries, size=4, topk=TOP_K)
        db.save(db_dir / "db_4.ngdb")

        return db_dir

    def test_predict_no_db(self):
        namer = NgramNamer(db_dir=None)
        result = namer.predict("int foo(int param_1) { return param_1; }", "foo")
        assert isinstance(result, NgramNamerResult)
        assert result.total_predicted == 0

    def test_predict_missing_dir(self, tmp_path):
        namer = NgramNamer(db_dir=tmp_path / "nonexistent")
        result = namer.predict("int foo(int param_1) {}", "foo")
        assert result.total_predicted == 0

    def test_predict_empty_code(self, db_dir):
        namer = NgramNamer(db_dir=db_dir)
        result = namer.predict("", "empty")
        assert result.total_predicted == 0

    def test_predict_no_variables(self, db_dir):
        namer = NgramNamer(db_dir=db_dir)
        result = namer.predict("int foo(int a, int b) { return a + b; }", "foo")
        assert result.total_predicted == 0

    def test_db_loads(self, db_dir):
        namer = NgramNamer(db_dir=db_dir)
        assert namer.db_count == 1
        assert namer.vocab_size == 5

    def test_batch_predict(self, db_dir):
        namer = NgramNamer(db_dir=db_dir)
        functions = {
            "f1": "void f1(int param_1) {}",
            "f2": "void f2(int param_1, int param_2) {}",
        }
        results = namer.batch_predict(functions)
        assert len(results) == 2
        assert "f1" in results
        assert "f2" in results

    def test_stats_tracking(self, db_dir):
        namer = NgramNamer(db_dir=db_dir)
        namer.predict("void f(int param_1) {}", "f1")
        namer.predict("void g(int param_1) {}", "f2")
        assert namer.stats["total_functions"] == 2

    def test_result_structure(self, db_dir):
        namer = NgramNamer(db_dir=db_dir)
        result = namer.predict("void f(int param_1) {}", "f")
        assert isinstance(result, NgramNamerResult)
        assert result.func_name == "f"

    def test_prediction_fields(self):
        pred = NgramPrediction(
            var_name="param_1",
            predicted_name="buffer",
            confidence=0.85,
            ngram_size=8,
            evidence="test",
        )
        assert pred.var_name == "param_1"
        assert pred.predicted_name == "buffer"
        assert pred.confidence == 0.85

    def test_c_keyword_filtered(self):
        """C keyword'leri isim tahmini olarak donmemeli."""
        from karadul.reconstruction.ngram_namer import _C_KEYWORDS
        assert "int" in _C_KEYWORDS
        assert "return" in _C_KEYWORDS
        assert "buffer" not in _C_KEYWORDS

    def test_skip_names_filtered(self):
        """Cok kisa/generic isimler filtrelenmeli."""
        from karadul.reconstruction.ngram_namer import _SKIP_NAMES
        assert "a" in _SKIP_NAMES
        assert "tmp" in _SKIP_NAMES
        assert "buffer" not in _SKIP_NAMES


# ========================================================================
# Edge case testleri
# ========================================================================


class TestEdgeCases:
    def test_very_long_code(self):
        """1000+ token'lik kod tokenize edilmeli."""
        code = "int f() { " + " ".join(f"param_{i} = {i};" for i in range(500)) + " }"
        tokens = tokenize_c(code)
        assert len(tokens) > 1000

    def test_unicode_in_string(self):
        tokens = tokenize_c('printf("Türkçe karakter: ğüşöç");')
        assert len(tokens) > 0

    def test_multiline_code(self):
        code = """void foo(int param_1) {
            int local_10;
            local_10 = param_1 * 2;
            return local_10;
        }"""
        tokens = tokenize_c(code)
        assert "param_1" in tokens
        assert "local_10" in tokens

    def test_nested_pointers(self):
        tokens = tokenize_c("char **ppVar1;")
        assert "ppVar1" in tokens

    def test_cast_expression(self):
        tokens = tokenize_c("*(int *)(param_1 + 0x10)")
        assert "param_1" in tokens
        assert "0x10" in tokens

    def test_ngram_sizes_sorted(self):
        """NGRAM_SIZES buyukten kucuge siralanmali."""
        sizes = list(NGRAM_SIZES)
        assert sizes == sorted(sizes, reverse=True)
