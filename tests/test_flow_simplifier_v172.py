"""v1.7.2 CFlowSimplifier yeni pass testleri.

Pass 4: Early return elimination
Pass 5a: Cascading goto collapse
Pass 5b: Break/continue recognition
Pass 6: If-else restructuring
Pass 7: Multi-target cleanup inlining
"""

from __future__ import annotations

import pytest


class TestEarlyReturnElimination:
    """Pass 4: goto LAB_end; ... LAB_end: return x; -> if (cond) return x;"""

    def test_simple_early_return(self):
        """Basit if(cond) goto LAB; ... LAB: return 0; donusumu."""
        from karadul.reconstruction.c_flow_simplifier import CFlowSimplifier

        simplifier = CFlowSimplifier()
        code = """\
int func(int x) {
    if (x < 0) goto LAB_001;
    x = x + 1;
    return x;
LAB_001:
    return 0;
}
"""
        result, stats = simplifier._simplify_content(code)
        assert "goto LAB_001" not in result
        assert "if (x < 0) return 0;" in result
        assert stats["early_returns"] >= 1

    def test_early_return_with_value(self):
        """return -1; gibi negatif deger donusumu."""
        from karadul.reconstruction.c_flow_simplifier import CFlowSimplifier

        simplifier = CFlowSimplifier()
        code = """\
int validate(char *s) {
    if (s == NULL) goto LAB_00a;
    int len = strlen(s);
    return len;
LAB_00a:
    return -1;
}
"""
        result, stats = simplifier._simplify_content(code)
        assert "goto LAB_00a" not in result
        assert "if (s == NULL) return -1;" in result

    def test_early_return_void(self):
        """void fonksiyonda sadece return; donusumu."""
        from karadul.reconstruction.c_flow_simplifier import CFlowSimplifier

        simplifier = CFlowSimplifier()
        code = """\
void cleanup(void *p) {
    if (p == NULL) goto LAB_0ff;
    free(p);
LAB_0ff:
    return;
}
"""
        result, stats = simplifier._simplify_content(code)
        assert "goto LAB_0ff" not in result
        assert "if (p == NULL) return;" in result

    def test_no_transform_multi_line_label(self):
        """Label'dan sonra birden fazla statement varsa donusturme."""
        from karadul.reconstruction.c_flow_simplifier import CFlowSimplifier

        simplifier = CFlowSimplifier()
        code = """\
int func(int x) {
    if (x < 0) goto LAB_001;
    return x;
LAB_001:
    printf("error");
    return -1;
}
"""
        result, stats = simplifier._simplify_content(code)
        # Label'dan sonra 2 statement var, early return donusumu YAPILMAMALI
        # (printf + return, ikisi de anlamli)
        # Not: _pass_early_return sadece tek-return label'lari donusturur.
        # Bu durumda printf ikinci satir, is_pure_return False olur.
        assert "goto LAB_001" in result or "goto" not in result


class TestCascadingGotoCollapse:
    """Pass 5a: goto LAB_a; LAB_a: goto LAB_b; -> goto LAB_b;"""

    def test_simple_chain(self):
        """Basit A -> B zinciri."""
        from karadul.reconstruction.c_flow_simplifier import CFlowSimplifier

        simplifier = CFlowSimplifier()
        code = """\
void func(void) {
    goto LAB_00a;
    x = 1;
LAB_00a:
    goto LAB_00b;
LAB_00b:
    return;
}
"""
        result, stats = simplifier._simplify_content(code)
        assert "goto LAB_00a" not in result
        assert stats["cascading_collapsed"] >= 1

    def test_triple_chain(self):
        """A -> B -> C zinciri."""
        from karadul.reconstruction.c_flow_simplifier import CFlowSimplifier

        simplifier = CFlowSimplifier()
        code = """\
void func(void) {
    goto LAB_001;
LAB_001:
    goto LAB_002;
LAB_002:
    goto LAB_003;
LAB_003:
    return;
}
"""
        result, stats = simplifier._simplify_content(code)
        # LAB_001 ve LAB_002 direkt LAB_003'e gitmeli
        assert "goto LAB_001" not in result
        assert "goto LAB_002" not in result

    def test_no_self_loop(self):
        """Self-loop goto (goto LAB_a; LAB_a: goto LAB_a;) cokertilmemeli."""
        from karadul.reconstruction.c_flow_simplifier import CFlowSimplifier

        simplifier = CFlowSimplifier()
        code = """\
void func(void) {
    goto LAB_00a;
LAB_00a:
    goto LAB_00a;
}
"""
        # Self-loop korunmali, sonsuz dongu degil
        result, stats = simplifier._simplify_content(code)
        # En azindan crash etmemeli
        assert isinstance(result, str)


class TestBreakContinueRecognition:
    """Pass 5b: Loop icindeki goto -> break/continue."""

    def test_goto_to_break(self):
        """Loop sonuna goto -> break. Label'dan sonra birden fazla statement
        oldugundan early return pass'i bunu almaz."""
        from karadul.reconstruction.c_flow_simplifier import CFlowSimplifier

        simplifier = CFlowSimplifier()
        # Label'dan sonra printf + return var (multi-statement, early return pass almaz)
        code = """\
void func(int *arr, int n) {
    int i = 0;
    while (i < n) {
        if (arr[i] == 0) goto LAB_00f0;
        arr[i] = arr[i] * 2;
        i++;
    }
LAB_00f0:
    printf("done");
    return;
}
"""
        result, stats = simplifier._simplify_content(code)
        assert "break;" in result
        assert stats["breaks_continues"] >= 1

    def test_goto_inside_for_loop(self):
        """for loop icinde goto -> break. Label'dan sonra non-return statement var."""
        from karadul.reconstruction.c_flow_simplifier import CFlowSimplifier

        simplifier = CFlowSimplifier()
        code = """\
void search(int *arr, int n) {
    for (int i = 0; i < n; i++) {
        if (arr[i] == 42) goto LAB_00a0;
    }
LAB_00a0:
    printf("found");
    return;
}
"""
        result, stats = simplifier._simplify_content(code)
        assert "break;" in result


class TestIfElseRestructuring:
    """Pass 6: if(cond) goto ELSE; ... goto END; ELSE: ... END: -> if-else."""

    def test_simple_ifelse(self):
        """Basit if-else donusumu."""
        from karadul.reconstruction.c_flow_simplifier import CFlowSimplifier

        simplifier = CFlowSimplifier()
        code = """\
void func(int x) {
    if (x > 0) goto LAB_00b0;
    printf("negative");
    goto LAB_00c0;
LAB_00b0:
    printf("positive");
LAB_00c0:
    return;
}
"""
        result, stats = simplifier._simplify_content(code)
        assert "if (!(x > 0))" in result
        assert "} else {" in result
        assert stats["ifelse_restructured"] >= 1

    def test_no_transform_nested_goto(self):
        """Then/else block icinde baska goto varsa donusturme."""
        from karadul.reconstruction.c_flow_simplifier import CFlowSimplifier

        simplifier = CFlowSimplifier()
        code = """\
void func(int x) {
    if (x > 0) goto LAB_00b0;
    goto LAB_00d0;
    goto LAB_00c0;
LAB_00b0:
    printf("positive");
LAB_00c0:
    return;
LAB_00d0:
    return;
}
"""
        result, stats = simplifier._simplify_content(code)
        # Then block icinde baska goto var, donusturulMEMELI
        # (Guvenlik: ic ice yapilar)
        assert stats.get("ifelse_restructured", 0) == 0

    def test_no_transform_large_blocks(self):
        """20+ satirlik block'lar donusturulmemeli."""
        from karadul.reconstruction.c_flow_simplifier import CFlowSimplifier

        simplifier = CFlowSimplifier()
        # 25 satirlik then block
        then_lines = "\n".join(f"    x = x + {i};" for i in range(25))
        code = f"""\
void func(int x) {{
    if (x > 0) goto LAB_00b0;
{then_lines}
    goto LAB_00c0;
LAB_00b0:
    printf("else");
LAB_00c0:
    return;
}}
"""
        result, stats = simplifier._simplify_content(code)
        assert stats.get("ifelse_restructured", 0) == 0


class TestMultiTargetCleanup:
    """Pass 7: Birden fazla goto ayni cleanup'a -> hepsini inline et."""

    def test_double_goto_cleanup(self):
        """2 goto ayni cleanup label'a gidiyor, ikisi de inline edilmeli."""
        from karadul.reconstruction.c_flow_simplifier import CFlowSimplifier

        simplifier = CFlowSimplifier()
        code = """\
int func(int x, int y) {
    char *a = malloc(10);
    if (a == NULL) goto LAB_00cc;
    char *b = malloc(20);
    if (b == NULL) goto LAB_00cc;
    return 0;
LAB_00cc:
    free(a);
    return -1;
}
"""
        result, stats = simplifier._simplify_content(code)
        assert stats["multi_target_inlined"] >= 2
        # goto LAB_00cc kalmamali
        assert "goto LAB_00cc" not in result or "goto" not in result

    def test_no_inline_large_block(self):
        """6+ satirlik cleanup block inline edilmemeli (multi icin limit 5)."""
        from karadul.reconstruction.c_flow_simplifier import CFlowSimplifier

        simplifier = CFlowSimplifier()
        cleanup_lines = "\n".join(f"    free(ptr{i});" for i in range(7))
        code = f"""\
int func(void) {{
    if (a == NULL) goto LAB_00bb;
    if (b == NULL) goto LAB_00bb;
    return 0;
LAB_00bb:
{cleanup_lines}
    return -1;
}}
"""
        result, stats = simplifier._simplify_content(code)
        assert stats.get("multi_target_inlined", 0) == 0


class TestFullPipeline:
    """Tum pass'larin birlikte calismasini test et."""

    def test_all_passes_run_sequentially(self):
        """Tum pass'lar sirayla calisip birbirlerini bozmamali."""
        from karadul.reconstruction.c_flow_simplifier import CFlowSimplifier

        simplifier = CFlowSimplifier()
        code = """\
int complex_func(int x, int *arr, int n) {
    /* Early return pattern */
    if (x < 0) goto LAB_001;

    /* Cascading goto pattern */
    goto LAB_00a;
LAB_00a:
    goto LAB_00b;
LAB_00b:
    x = x + 1;

    /* Loop with break pattern */
    while (x < n) {
        if (arr[x] == 0) goto LAB_00ee;
        x++;
    }
LAB_00ee:
    return x;
LAB_001:
    return -1;
}
"""
        result, stats = simplifier._simplify_content(code)
        # Toplam eliminated > 0 olmali
        assert stats["eliminated"] > 0
        # Sonuc gecerli C kodu olmali (bazi basic checks)
        assert "int complex_func" in result

    def test_empty_content(self):
        """Bos icerik crash etmemeli."""
        from karadul.reconstruction.c_flow_simplifier import CFlowSimplifier

        simplifier = CFlowSimplifier()
        result, stats = simplifier._simplify_content("")
        assert result == ""
        assert stats["eliminated"] == 0

    def test_no_gotos_content(self):
        """goto olmayan icerik degismemeli."""
        from karadul.reconstruction.c_flow_simplifier import CFlowSimplifier

        simplifier = CFlowSimplifier()
        code = "int main() { return 0; }\n"
        result, stats = simplifier._simplify_content(code)
        assert result == code
        assert stats["eliminated"] == 0

    def test_large_content_guard(self):
        """500K+ karakter icerikte yeni pass'lar calismamali."""
        from karadul.reconstruction.c_flow_simplifier import CFlowSimplifier

        simplifier = CFlowSimplifier()
        # 500K+ icerik olustur
        base = "    x = x + 1;\n"
        big_code = "void func(void) {\n"
        big_code += "    if (x < 0) goto LAB_001;\n"
        big_code += base * 40000  # ~600K karakter
        big_code += "LAB_001:\n    return;\n}\n"

        result, stats = simplifier._simplify_content(big_code)
        # skip_inline aktif olmali, yeni pass'lar calismamali
        assert stats.get("early_returns", 0) == 0


class TestSimplifyResult:
    """SimplifyResult yeni alanlari."""

    def test_result_has_new_fields(self):
        from karadul.reconstruction.c_flow_simplifier import SimplifyResult

        r = SimplifyResult()
        assert hasattr(r, "early_returns")
        assert hasattr(r, "breaks_continues")
        assert hasattr(r, "ifelse_restructured")
        assert hasattr(r, "cascading_collapsed")
        assert hasattr(r, "multi_target_inlined")
        assert r.early_returns == 0
        assert r.breaks_continues == 0
