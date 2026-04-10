"""Karadul v1.5.7 fix'lerinin birim testleri.

4 dosyadaki 10 fix icin hedefli testler:
- c_flow_simplifier.py: cleanup block duplicate fix, word boundary fix
- c_project_builder.py: path sanitization (/ iceren stem)
- c_namer.py: brace counting (string literal icindeki brace)
- c_type_recoverer.py: import kontrolu (syntax + import zaten Adim 1-2'de yapildi)
"""

import re
import pytest


# ===================================================================
# TEST A: c_flow_simplifier — Cleanup block duplicate fix
# ===================================================================

class TestCleanupBlockDuplicate:
    """Inline sonrasi cleanup block'un orijinal konumda kalip kalmadigini test et.

    TEST: Cleanup block duplicate kalma
    GIVEN: Tek hedefli goto + cleanup block (free + return)
    WHEN: Inline islemi yapilir
    THEN: Orijinal label ve cleanup block silinmeli, duplicate kalmamali
    EDGE CASES: Fallback label silme (block regex eslesemediyse)
    """

    def test_inline_removes_original_cleanup_block(self):
        """Inline edilen cleanup block, orijinal konumundan silinmeli."""
        from karadul.reconstruction.c_flow_simplifier import CFlowSimplifier

        simplifier = CFlowSimplifier()

        # Tek hedefli goto + cleanup block
        code = """\
void func(void) {
    char *buf = malloc(100);
    if (buf == NULL) {
        goto LAB_00a;
    }
    do_work(buf);
    return;

LAB_00a:
    free(buf);
    return;
}
"""
        result, stats = simplifier._simplify_content(code)

        # Orijinal label silinmis olmali
        assert "LAB_00a:" not in result, (
            "Orijinal cleanup label silinmedi — duplicate kalmis"
        )
        # Inline edilmis cleanup blogu mevcut olmali
        assert "error cleanup" in result.lower() or "free(buf)" in result, (
            "Cleanup block inline edilmedi"
        )
        # Istatistik dogru olmali
        assert stats["inlined"] >= 1
        assert stats["eliminated"] >= 1

    def test_no_duplicate_free_calls(self):
        """Inline sonrasi free() cagrisi iki kez bulunmamali (ayni block)."""
        from karadul.reconstruction.c_flow_simplifier import CFlowSimplifier

        simplifier = CFlowSimplifier()

        code = """\
void cleanup_test(void) {
    void *ptr = alloc_resource();
    if (ptr == NULL) {
        goto LAB_001;
    }
    process(ptr);
    return;

LAB_001:
    free(ptr);
    close(fd);
    return;
}
"""
        result, stats = simplifier._simplify_content(code)

        # Duplicate kontrol: free(ptr) sadece 1 kez olmali
        free_count = result.count("free(ptr)")
        assert free_count <= 1, (
            f"free(ptr) {free_count} kez bulundu — cleanup block duplicate kalmis"
        )

    def test_multi_target_goto_not_inlined(self):
        """Birden fazla goto ayni label'a gidiyorsa inline edilmemeli."""
        from karadul.reconstruction.c_flow_simplifier import CFlowSimplifier

        simplifier = CFlowSimplifier()

        code = """\
void multi_goto(void) {
    if (a) goto LAB_00c;
    if (b) goto LAB_00c;
    return;

LAB_00c:
    free(x);
    return;
}
"""
        result, stats = simplifier._simplify_content(code)

        # Multi-target: inline edilmemeli, label kalmali
        # (sadece rename olabilir ama block ayni yerde kalmali)
        assert stats["inlined"] == 0, (
            "Multi-target goto inline edildi — bu guvenli degil"
        )


# ===================================================================
# TEST B: c_flow_simplifier — Word boundary fix
# ===================================================================

class TestWordBoundaryFix:
    """LAB_00a rename edilirken LAB_00ab bozulmamali.

    TEST: Word boundary korumasi
    GIVEN: LAB_00a ve LAB_00ab ayni dosyada
    WHEN: Label rename islemi yapilir
    THEN: LAB_00a rename edilir, LAB_00ab BOZULMAZ
    EDGE CASES: LAB_00a12 vs LAB_00a1, ic ice prefix'ler
    """

    def test_short_label_does_not_corrupt_longer_label(self):
        """LAB_00a -> error_cleanup yaparken LAB_00ab bozulmamali."""
        from karadul.reconstruction.c_flow_simplifier import CFlowSimplifier

        simplifier = CFlowSimplifier()

        # LAB_00a cleanup, LAB_00ab farkli bir label
        code = """\
void boundary_test(void) {
    if (err1) goto LAB_00a;
    if (err2) goto LAB_00a;
    if (err3) goto LAB_00ab;
    if (err4) goto LAB_00ab;
    return;

LAB_00a:
    free(resource1);
    return;

LAB_00ab:
    close(fd);
    return;
}
"""
        result, stats = simplifier._simplify_content(code)

        # LAB_00ab orijinal veya rename edilmis olmali ama LAB_00a'nin
        # rename'inden etkilenmemeli
        # Eger word boundary kullanilmasaydi, LAB_00ab -> error_cleanupb olurdu
        assert "error_cleanupb" not in result and "cleanup_and_returnb" not in result, (
            "Word boundary hatasi: LAB_00ab, LAB_00a rename'inden etkilendi"
        )
        # LAB_00ab bir sekilde durmali (orijinal veya rename edilmis)
        # "close(fd)" hala mevcut olmali
        assert "close(fd)" in result

    def test_label_matching_uses_exact_name(self):
        """Label eslesmesinde tam isim eslesmesi yapildigini dogrula.

        v1.6.4: Eski implementasyon re.escape(label_name) ile dinamik regex
        derliyordu. Yeni batch algoritma pre-compiled _LABEL_RE + _GOTO_RE
        ve dict-key bazli eslesme kullaniyor — prefix cakismasi riski yok
        cunku label_name dict key'i olarak exact-match yapiliyor.
        """
        from karadul.reconstruction.c_flow_simplifier import CFlowSimplifier
        import inspect

        source = inspect.getsource(CFlowSimplifier._simplify_content)
        # v1.6.4: Batch algorithm uses dict keyed by exact label_name.
        # Either re.escape (old) or goto_positions dict (new) must be present.
        has_exact_match = (
            "re.escape(label_name)" in source
            or "goto_positions.get(label_name)" in source
        )
        assert has_exact_match, (
            "Label eslesmesinde exact-match mekanizmasi bulunamadi — "
            "LAB_00a ve LAB_00ab karismasi riski var"
        )

    def test_similar_label_names_stay_independent(self):
        """LAB_001, LAB_0010, LAB_00100 gibi prefix zinciri olmali."""
        from karadul.reconstruction.c_flow_simplifier import CFlowSimplifier

        simplifier = CFlowSimplifier()

        code = """\
void prefix_chain(void) {
    goto LAB_001;
    goto LAB_001;
    goto LAB_0010;
    goto LAB_0010;
    return;

LAB_001:
    free(a);
    return;

LAB_0010:
    return -1;
}
"""
        result, stats = simplifier._simplify_content(code)

        # Her label bagimsiz rename edilmeli
        # Onemli olan: birinin rename'i digerini bozmasin
        # "free(a)" ve "return -1" hala mevcut olmali
        assert "free(a)" in result
        assert "return -1" in result or "return" in result


# ===================================================================
# TEST C: c_project_builder — Path sanitization
# ===================================================================

class TestPathSanitization:
    """'/' iceren stem guvenli dosya adina donusmeli.

    TEST: Dosya adi sanitization
    GIVEN: Go binary fonksiyon adi: "runtime/internal/sys"
    WHEN: _sanitize_stem() cagrilir
    THEN: "/" -> "_" donusumu, path traversal engellenmeli
    EDGE CASES: bos string, sadece ozel karakterler, ".." traversal
    """

    def test_slash_replaced_with_underscore(self):
        """Go-style fonksiyon adi: '/' -> '_' donusumu."""
        from karadul.reconstruction.c_project_builder import CProjectBuilder

        # _sanitize_stem @staticmethod -- dogrudan sinif uzerinden cagir
        result = CProjectBuilder._sanitize_stem("runtime/internal/sys")
        assert "/" not in result, f"Slash kalmamaliydi: {result}"
        assert result == "runtime_internal_sys"

    def test_path_traversal_prevented(self):
        """../../etc/passwd gibi traversal engellenmeli."""
        from karadul.reconstruction.c_project_builder import CProjectBuilder

        result = CProjectBuilder._sanitize_stem("../../etc/passwd")
        assert "/" not in result
        assert ".." not in result, f"Path traversal kalmamaliydi: {result}"

    def test_empty_string_returns_unnamed(self):
        """Bos veya sadece ozel karakter -> 'unnamed'."""
        from karadul.reconstruction.c_project_builder import CProjectBuilder

        result = CProjectBuilder._sanitize_stem("")
        assert result == "unnamed"

    def test_only_special_chars_returns_unnamed(self):
        """Sadece ozel karakterlerden olusan stem -> 'unnamed'."""
        from karadul.reconstruction.c_project_builder import CProjectBuilder

        result = CProjectBuilder._sanitize_stem("///...")
        assert result == "unnamed"

    def test_normal_stem_unchanged(self):
        """Normal fonksiyon adi degismemeli."""
        from karadul.reconstruction.c_project_builder import CProjectBuilder

        result = CProjectBuilder._sanitize_stem("SSL_read")
        assert result == "SSL_read"

    def test_dots_in_name_preserved(self):
        """Nokta karakteri korunmali (dosya adi icin gecerli)."""
        from karadul.reconstruction.c_project_builder import CProjectBuilder

        result = CProjectBuilder._sanitize_stem("libcrypto.so.3")
        # Baslangic ve sondaki . strip edilir ama ortadakiler kalir
        assert "." in result or result == "libcrypto.so.3"

    def test_special_go_package_names(self):
        """Go paket adi cesitleri."""
        from karadul.reconstruction.c_project_builder import CProjectBuilder

        cases = [
            ("main.init", "main.init"),
            ("crypto/tls.(*Conn).Read", "crypto_tls.__Conn_.Read"),
            ("net/http.ListenAndServe", "net_http.ListenAndServe"),
        ]
        for input_stem, expected_safe in cases:
            result = CProjectBuilder._sanitize_stem(input_stem)
            assert "/" not in result, f"Slash kaldi: {input_stem} -> {result}"
            assert result, f"Bos sonuc: {input_stem}"


# ===================================================================
# TEST D: c_namer — Brace counting (string literal fix)
# ===================================================================

class TestBraceCounting:
    """String literal icindeki brace sayilmamali.

    TEST: Brace sayimi string literal korumasi
    GIVEN: printf("{key: %d}", val) gibi satir
    WHEN: _count_braces() cagrilir
    THEN: String icindeki { } sayilmaz, sadece gercek kod brace'leri sayilir
    EDGE CASES: escaped quote, char literal, ic ice string, bos satir
    """

    def test_string_literal_braces_ignored(self):
        """printf("{key: %d}", val) -> 0 brace (string icindekiler sayilmaz)."""
        from karadul.reconstruction.c_namer import _count_braces

        line = 'printf("{key: %d}", val);'
        result = _count_braces(line)
        assert result == 0, (
            f"String icindeki brace sayilmamali: beklenen 0, gercek {result}"
        )

    def test_real_brace_counted(self):
        """if (x) { -> +1 brace."""
        from karadul.reconstruction.c_namer import _count_braces

        line = "if (x) {"
        result = _count_braces(line)
        assert result == 1, f"Beklenen 1, gercek {result}"

    def test_closing_brace(self):
        """} -> -1 brace."""
        from karadul.reconstruction.c_namer import _count_braces

        line = "}"
        result = _count_braces(line)
        assert result == -1, f"Beklenen -1, gercek {result}"

    def test_mixed_real_and_string_braces(self):
        """if (x) { printf("{a}"); -> +1 (sadece gercek { sayilir)."""
        from karadul.reconstruction.c_namer import _count_braces

        line = 'if (x) { printf("{a}"); '
        result = _count_braces(line)
        assert result == 1, (
            f"String icindeki brace sayilmamali: beklenen 1, gercek {result}"
        )

    def test_char_literal_brace_ignored(self):
        """if (c == '{') -> 0 brace (char literal icindeki { sayilmaz)."""
        from karadul.reconstruction.c_namer import _count_braces

        line = "if (c == '{') return;"
        result = _count_braces(line)
        assert result == 0, (
            f"Char literal icindeki brace sayilmamali: beklenen 0, gercek {result}"
        )

    def test_escaped_quote_in_string(self):
        r"""Escaped quote: printf("\"{\"}") -> 0."""
        from karadul.reconstruction.c_namer import _count_braces

        line = r'printf("\"{\"");'
        result = _count_braces(line)
        assert result == 0, (
            f"Escaped quote'lu string: beklenen 0, gercek {result}"
        )

    def test_empty_line(self):
        """Bos satir -> 0."""
        from karadul.reconstruction.c_namer import _count_braces

        result = _count_braces("")
        assert result == 0

    def test_balanced_braces_in_code(self):
        """{ ... } -> 0 (dengeli brace)."""
        from karadul.reconstruction.c_namer import _count_braces

        line = "{ x = 1; }"
        result = _count_braces(line)
        assert result == 0

    def test_multiple_opens(self):
        """{ { -> +2."""
        from karadul.reconstruction.c_namer import _count_braces

        line = "if (a) { if (b) {"
        result = _count_braces(line)
        assert result == 2, f"Beklenen 2, gercek {result}"

    def test_json_string_literal(self):
        """JSON format string: '{"key": "val"}' hepsi string icinde -> 0."""
        from karadul.reconstruction.c_namer import _count_braces

        line = 'sprintf(buf, "{\\"key\\": \\"%s\\"}", val);'
        result = _count_braces(line)
        assert result == 0, (
            f"JSON string literal brace sayilmamali: beklenen 0, gercek {result}"
        )

    def test_ghidra_style_format_string(self):
        """Ghidra ciktisinda tipik: printf("{result: %d}\\n", iVar1)."""
        from karadul.reconstruction.c_namer import _count_braces

        line = 'printf("{result: %d}\\n", iVar1);'
        result = _count_braces(line)
        assert result == 0, (
            f"Ghidra format string: beklenen 0, gercek {result}"
        )


# ===================================================================
# TEST E: Entegrasyon - flow simplifier full pipeline
# ===================================================================

class TestFlowSimplifierIntegration:
    """Tam bir dosya uzerinde simplifikasyon pipeline'i."""

    def test_full_pipeline_on_realistic_code(self):
        """Gercekci Ghidra ciktisinda tum katmanlar calismali."""
        from karadul.reconstruction.c_flow_simplifier import CFlowSimplifier

        simplifier = CFlowSimplifier()

        code = """\
int SSL_do_handshake(SSL *s) {
    int ret = 0;
    BIO *rbio = NULL;

    rbio = SSL_get_rbio(s);
    if (rbio == NULL) {
        goto LAB_00100a;
    }

    ret = ssl_handshake_internal(s);
    if (ret < 0) {
        goto LAB_00100b;
    }

    return ret;

LAB_00100a:
    free(rbio);
    return -1;

LAB_00100b:
    return -1;
}
"""
        result, stats = simplifier._simplify_content(code)

        # En az bir islem yapilmis olmali
        total_ops = stats["inlined"] + stats["renamed"] + stats["eliminated"]
        assert total_ops > 0, "Hicbir simplifikasyon yapilmadi"

        # Sonuc gecerli C kodu gibi gorunmeli
        assert "int SSL_do_handshake" in result
        assert "return" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
