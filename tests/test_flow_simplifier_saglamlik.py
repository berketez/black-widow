"""Akış sadeleştiricinin sağlamlık testleri (2026-11-10 onarımı).

Kaynak: docs/arge/2026-11-10_cikti_saglamligi/rapor.md, kusur 1. Eski sürüm
119 ikilinin 117'sinde decompile edilmiş C metnini bozuyordu.

Üç öbek:

1. **Kök nedenler** — her kök neden için en küçük sentetik örnek. Beklenen
   çıktı tam metin olarak yazılıdır (ürünün kendi denetleyicisine
   dayanmaz); eski sürümde hepsi düşer.
2. **Ard koşul denetimi** — elle bozulmuş dönüşümler tanınmalı; bozuk
   geçiş üreten fonksiyonun özgün metni yazılmalı ve sayaç artmalı.
3. **Bağımsız yorumlayıcıyla fark testi** — rastgele üretilen goto'lu
   programlar sadeleştirilir; özgün ve yeni metin bu dosyadaki küçük
   yorumlayıcıda aynı girdilerle çalıştırılır, olay izleri aynı olmalı.
   Aynı yorumlayıcı denetleyicinin kendisini de sınar: izi değiştiren bir
   bozma, ard koşul denetiminden geçmemeli.
"""

from __future__ import annotations

import random
import re
from collections import Counter

import pytest

from karadul.reconstruction import c_flow_simplifier as fs
from karadul.reconstruction.c_flow_simplifier import CFlowSimplifier, SimplifyResult


def simplify(code: str, passes: tuple[str, ...] | None = None):
    s = CFlowSimplifier()
    if passes is not None:
        s._passes = passes
    return s._simplify_content(code)


def body(code: str) -> str:
    """Dosya metninden fonksiyon gövdesini (``{`` … ``}``) alır."""
    return code[code.index("{"): code.rindex("}") + 1]


def assert_unchanged_by_choice(code: str, passes: tuple[str, ...] | None = None):
    """Metin değişmemeli ve bunu geçişin kendisi sağlamalı (güvenlik ağı değil)."""
    result, stats = simplify(code, passes)
    assert result == code
    assert stats["functions_reverted"] == 0
    assert stats["functions_skipped"] == 0


# ===========================================================================
# 1. Kök nedenler
# ===========================================================================


class TestInlineRootCauses:
    """Temizlik bloğunu goto yerine koyma (eski Pass 1 ve Pass 7)."""

    def test_braceless_if_gets_braces(self):
        """K2: ``if (k) goto L;`` tek deyimdi; blok ayraçsız konunca yalnız
        ilk deyim koşullu kalıyordu."""
        code = """\
int f(char *a) {
    if (a == NULL) goto LAB_00cc;
    use(a);
    return 0;
LAB_00cc:
    log_null();
    return -1;
}
"""
        result, stats = simplify(code)
        assert result == """\
int f(char *a) {
    if (a == NULL) {
        /* error cleanup (inlined from LAB_00cc) */
        log_null();
        return -1;
    }
    use(a);
    return 0;
}
"""
        assert stats["inlined"] == 1
        assert stats["functions_reverted"] == 0

    def test_else_goto_gets_braces(self):
        code = """\
int f(int a, char *p) {
    if (a > 0) use(p);
    else goto LAB_001;
    return 0;
LAB_001:
    free(p);
    return -1;
}
"""
        result, stats = simplify(code)
        assert result == """\
int f(int a, char *p) {
    if (a > 0) use(p);
    else {
        /* error cleanup (inlined from LAB_001) */
        free(p);
        return -1;
    }
    return 0;
}
"""
        assert stats["functions_reverted"] == 0

    def test_goto_on_its_own_line_under_if_gets_braces(self):
        code = """\
int f(char *a) {
    if (a == NULL)
        goto LAB_00cc;
    use(a);
    return 0;
LAB_00cc:
    log_null();
    return -1;
}
"""
        result, stats = simplify(code)
        assert result == """\
int f(char *a) {
    if (a == NULL) {
        /* error cleanup (inlined from LAB_00cc) */
        log_null();
        return -1;
    }
    use(a);
    return 0;
}
"""
        assert stats["functions_reverted"] == 0

    def test_goto_inside_one_line_braces_keeps_them(self):
        code = """\
int f(char *a) {
    if (a == NULL) { goto LAB_00cc; }
    use(a);
    return 0;
LAB_00cc:
    log_null();
    return -1;
}
"""
        result, stats = simplify(code)
        assert result == """\
int f(char *a) {
    if (a == NULL) { {
        /* error cleanup (inlined from LAB_00cc) */
        log_null();
        return -1;
    } }
    use(a);
    return 0;
}
"""
        assert stats["functions_reverted"] == 0

    def test_goto_to_next_line_label_is_not_inlined(self):
        """``goto L; L:`` — taşınacak blok yok; yalnız ad değişir."""
        code = """\
void f(char *x) {
    work(x);
    goto LAB_001;
LAB_001:
    free(x);
    return;
}
"""
        result, stats = simplify(code)
        assert result == code.replace("LAB_001", "cleanup_and_return")
        assert stats["inlined"] == 0
        assert stats["functions_reverted"] == 0

    def test_multi_target_conditional_sites_get_braces(self):
        code = """\
int f(char *a, char *b) {
    if (a == NULL) goto LAB_00cc;
    if (b == NULL) goto LAB_00cc;
    return 0;
LAB_00cc:
    free(a);
    return -1;
}
"""
        result, stats = simplify(code)
        assert result == """\
int f(char *a, char *b) {
    if (a == NULL) {
        /* cleanup (inlined from LAB_00cc) */
        free(a);
        return -1;
    }
    if (b == NULL) {
        /* cleanup (inlined from LAB_00cc) */
        free(a);
        return -1;
    }
    return 0;
}
"""
        assert stats["multi_target_inlined"] == 2
        assert stats["inlined"] == 0
        assert stats["functions_reverted"] == 0

    def test_fallthrough_label_block_is_not_moved(self):
        """K3: etikete düşerek de ulaşılıyor; blok silinirse o yol bloğu
        kaybeder. Blok yerinde kalmalı; yalnız etiket adı değişir."""
        code = """\
void f(char *p) {
    if (p == NULL) goto LAB_001;
    use(p);
LAB_001:
    free(p);
    return;
}
"""
        result, stats = simplify(code)
        assert result == """\
void f(char *p) {
    if (p == NULL) goto cleanup_and_return;
    use(p);
cleanup_and_return:
    free(p);
    return;
}
"""
        assert stats["inlined"] == 0
        assert stats["functions_reverted"] == 0

    def test_fallthrough_guard_is_in_the_pass(self):
        """Düşme koruması geçişin kendisinde; güvenlik ağına bırakılmıyor."""
        code = """\
void f(char *p) {
    if (p == NULL) goto LAB_001;
    use(p);
LAB_001:
    free(p);
    return;
}
"""
        an = fs._Analysis(body(code))
        edits, _stats, _delta = CFlowSimplifier()._pass_inline(an)
        assert edits == []

    def test_block_never_crosses_closing_brace(self):
        """K1: blok satır satır alınıyordu; ``}`` aşılıp sonraki kod da
        taşınıyordu. Etiketin bloğu atlamayla bitmiyorsa dokunulmaz."""
        assert_unchanged_by_choice("""\
int f(int a, char *p) {
    if (a == 1) goto LAB_0a0;
    if (a == 2) {
        log_it(a);
        return 2;
LAB_0a0:
        free(p);
    }
    done(a);
    return 0;
}
""")

    def test_blank_lines_inside_block_leave_no_tail(self):
        """K4: silinecek uzunluk boş satırsız bloktan hesaplanıyordu;
        ``return -1;`` deyiminin kuyruğu (``1;``) yerinde kalıyordu."""
        code = """\
int f(char *p) {
    if (p == NULL) {
        goto LAB_001;
    }
    return 0;
LAB_001:
    log_fail(p);

    free(p);
    return -1;
}
"""
        result, stats = simplify(code)
        assert result == """\
int f(char *p) {
    if (p == NULL) {
        /* error cleanup (inlined from LAB_001) */
        log_fail(p);
        free(p);
        return -1;
    }
    return 0;
}
"""
        assert stats["functions_reverted"] == 0

    def test_nested_return_does_not_end_block(self):
        """K1: iç içe bloktaki ``return`` bloğun sonu sayılıyordu."""
        code = """\
int f(char *p, char *q) {
    if (p == NULL) {
        goto LAB_001;
    }
    return 0;
LAB_001:
    if (q != NULL) {
        return 1;
    }
    free(p);
    return -1;
}
"""
        result, stats = simplify(code)
        assert result == """\
int f(char *p, char *q) {
    if (p == NULL) {
        /* error cleanup (inlined from LAB_001) */
        if (q != NULL) {
            return 1;
        }
        free(p);
        return -1;
    }
    return 0;
}
"""
        assert stats["functions_reverted"] == 0

    def test_block_ending_in_break_is_not_copied(self):
        """``break`` başka bir konuma taşınınca başka döngüye bağlanır."""
        code = """\
void f(int n, char *p) {
    if (n == 0) goto LAB_001;
    while (n > 0) {
        n = step(n);
        continue;
LAB_001:
        free(p);
        break;
    }
    done();
}
"""
        result, stats = simplify(code)
        assert result == code.replace("LAB_001", "error_cleanup")
        assert stats["inlined"] == 0
        assert stats["functions_reverted"] == 0

    @pytest.mark.parametrize("extra, block", [
        # içinde etiket var (kopyalanırsa iki kez tanımlanır)
        ("    if (n == 3) goto LAB_002;\n",
         "        log_it(p);\nLAB_002:\n        free(p);\n        return -1;\n"),
        # içinde bildirim var (kopyalanırsa kapsamı değişir)
        ("", "        int tmp = 1;\n        free(p);\n        return tmp;\n"),
        # iç içe break (taşınınca başka döngüye bağlanır)
        ("", "        if (p) {\n            break;\n        }\n        free(p);\n        return -1;\n"),
        # iç içe continue
        ("", "        if (p) {\n            continue;\n        }\n        free(p);\n        return -1;\n"),
    ])
    def test_unsafe_blocks_are_not_inlined(self, extra, block):
        code = (
            "int f(char *p, int n) {\n"
            "    if (p == NULL) goto LAB_001;\n" + extra +
            "    while (n > 0) {\n"
            "        n--;\n"
            "        continue;\n"
            "LAB_001:\n" + block +
            "    }\n"
            "    return 0;\n"
            "}\n"
        )
        an = fs._Analysis(body(code))
        edits, _stats, _delta = CFlowSimplifier()._pass_inline(an)
        assert edits == []
        _result, stats = simplify(code)
        assert stats["inlined"] == 0
        assert stats["functions_reverted"] == 0

    def test_late_declared_name_blocks_move(self):
        """Blok, goto'dan sonra bildirilen bir adı anıyorsa taşınmaz."""
        code = """\
int f(char *a) {
    if (a == NULL) goto LAB_001;
    char *late = dup(a);
    use(late);
    return 0;
LAB_001:
    free(late);
    return -1;
}
"""
        an = fs._Analysis(body(code))
        assert "late" in an.late_declared
        edits, _stats, _delta = CFlowSimplifier()._pass_inline(an)
        assert edits == []

    @pytest.mark.parametrize("stmt, expected", [
        ("int i = 0;", True),
        ("char *buf = malloc(100);", True),
        ("unsigned long uVar1;", True),
        ("undefined1 auVar5 [16];", True),
        ("int (*pfVar1)(int);", True),
        ("a * b;", True),                      # ihtiyatlı: çarpma da olabilir
        ("x = x + 1;", False),
        ("*param_3 = sVar2;", False),
        ("free(buf);", False),
        ("report (puVar3,*(long *)(param_1 + 8),param_2);", False),
        ("(*pcVar1)(a);", False),
        ("arr[i] = arr[i] * 2;", False),
        ("i++;", False),
    ])
    def test_declaration_heuristic(self, stmt, expected):
        assert fs._looks_like_decl(stmt) is expected

    def test_self_jumping_block_is_not_inlined(self):
        code = """\
int f(int n) {
    if (n == 0) goto LAB_001;
    return 0;
LAB_001:
    n = retry(n);
    if (n > 0) goto LAB_001;
    close(n);
    return -1;
}
"""
        an = fs._Analysis(body(code))
        edits, _stats, _delta = CFlowSimplifier()._pass_inline(an)
        assert edits == []

    def test_non_lab_labels_are_left_alone(self):
        """Yalnız ``LAB_`` etiketlerine dokunulur (Ghidra'nın ``code_r0x…``,
        ``joined_r0x…`` etiketleri ve fonksiyon dışına goto'lar kalır)."""
        assert_unchanged_by_choice("""\
void f(char *a) {
    if (a == NULL) goto joined_r0x00101234;
    if (*a == 0) goto code_r0x00105678;
    if (a[1] == 0) goto LAB_00101000;
    use(a);
LAB_00101000:
    more(a);
    return;
joined_r0x00101234:
    free(a);
    return;
}
""", passes=("cascade", "ifelse", "early_return", "break_continue", "inline"))


class TestEarlyReturnRootCauses:

    def test_fallthrough_return_is_kept(self):
        """E1: etikete düşerek de ulaşılıyor; eski sürüm goto'lar bitince
        ``return``'ü de siliyordu (fonksiyon değer döndürmeden bitiyordu)."""
        code = """\
int f(int x) {
    if (x < 0) goto LAB_001;
    x = work(x);
LAB_001:
    return x;
}
"""
        result, stats = simplify(code)
        assert result == """\
int f(int x) {
    if (x < 0) return x;
    x = work(x);
    return x;
}
"""
        assert stats["early_returns"] == 1
        assert stats["functions_reverted"] == 0

    def test_return_inside_block_is_kept(self):
        """E1: etiket bir bloğun ilk deyimi; ``return`` silinince blok
        boşalıyordu."""
        code = """\
int f(char *p, int n) {
    if (n == 0) goto LAB_001;
    if (*p == 0) {
LAB_001:
        return 1;
    }
    return 0;
}
"""
        result, stats = simplify(code)
        assert result == """\
int f(char *p, int n) {
    if (n == 0) return 1;
    if (*p == 0) {
        return 1;
    }
    return 0;
}
"""
        assert stats["functions_reverted"] == 0

    def test_unreachable_return_is_removed_only_after_jump(self):
        code = """\
int f(int x) {
    if (x < 0) goto LAB_001;
    return x;
LAB_001:
    return 0;
}
"""
        result, stats = simplify(code)
        assert result == """\
int f(int x) {
    if (x < 0) return 0;
    return x;
}
"""
        assert stats["functions_reverted"] == 0

    def test_nested_parentheses_and_else(self):
        code = """\
int f(int a) {
    if (check(a) != 0) goto LAB_001;
    if (a > 3) a = 3;
    else goto LAB_001;
    return a;
LAB_001:
    return -1;
}
"""
        result, stats = simplify(code)
        assert result == """\
int f(int a) {
    if (check(a) != 0) return -1;
    if (a > 3) a = 3;
    else return -1;
    return a;
}
"""
        assert stats["early_returns"] == 2
        assert stats["functions_reverted"] == 0

    def test_multiline_return_is_not_copied(self):
        assert_unchanged_by_choice("""\
int f(int a) {
    if (a) goto LAB_001;
    work(a);
LAB_001:
    return compute(a,
                   a + 1);
}
""", passes=("early_return",))


class TestBreakContinueRootCauses:

    def test_goto_out_of_nested_loop_is_not_break(self):
        """B1: ``break`` içteki döngüye bağlanır; goto dıştakinden çıkıyordu."""
        assert_unchanged_by_choice("""\
void f(int n, int m) {
    while (n > 0) {
        while (m > 0) {
            if (probe(m)) goto LAB_001;
            m--;
        }
        n--;
    }
LAB_001:
    done();
}
""")

    def test_label_not_immediately_after_loop_is_not_break(self):
        """Etiketle döngü arasında deyim var; ``break`` onu da çalıştırır."""
        assert_unchanged_by_choice("""\
void f(int n) {
    while (n > 0) {
        if (probe(n)) goto LAB_001;
        n--;
    }
    tail();
LAB_001:
    done();
}
""")

    def test_goto_inside_switch_is_not_break(self):
        """B1: ``break`` switch'e bağlanır; goto döngüden çıkıyordu."""
        assert_unchanged_by_choice("""\
void f(int n, int k) {
    while (n > 0) {
        switch (k) {
        case 1:
            goto LAB_001;
        default:
            n--;
        }
    }
LAB_001:
    done();
}
""")

    def test_goto_before_conditional_do_while_is_not_continue(self):
        """B2: ``continue`` koşulu sınar; goto koşulu sınamadan başa döner."""
        assert_unchanged_by_choice("""\
void f(int n) {
LAB_001:
    do {
        n = step(n);
        if (n == 7) goto LAB_001;
        n--;
    } while (n > 0);
    done();
}
""")

    def test_goto_before_for_is_not_continue(self):
        """B2: goto ``for``'un ilk deyimini yeniden çalıştırır."""
        assert_unchanged_by_choice("""\
void f(int n) {
    int i;
LAB_001:
    for (i = 0; i < n; i++) {
        if (probe(i)) goto LAB_001;
    }
    done();
}
""")

    def test_while_and_do_true_become_continue(self):
        code = """\
void f(int n) {
LAB_001:
    while (n > 0) {
        n = step(n);
        if (n == 7) goto LAB_001;
        n--;
    }
LAB_002:
    do {
        n = step(n);
        if (n == 7) goto LAB_002;
        if (n == 0) {
            return;
        }
    } while( true );
}
"""
        result, stats = simplify(code)
        assert result == """\
void f(int n) {
    while (n > 0) {
        n = step(n);
        if (n == 7) continue;
        n--;
    }
    do {
        n = step(n);
        if (n == 7) continue;
        if (n == 0) {
            return;
        }
    } while( true );
}
"""
        assert stats["breaks_continues"] == 2
        assert stats["functions_reverted"] == 0

    def test_break_with_brace_in_char_literal(self):
        """Sözcük düzeyi: ``'}'`` sabiti ayraç sayılmamalı."""
        code = """\
void f(char *s, int n) {
    while (n > 0) {
        if (*s == '}') goto LAB_001;
        n--;
    }
LAB_001:
    done();
}
"""
        result, stats = simplify(code)
        assert result == """\
void f(char *s, int n) {
    while (n > 0) {
        if (*s == '}') break;
        n--;
    }
    done();
}
"""
        assert stats["breaks_continues"] == 1

    def test_label_stays_when_other_goto_remains(self):
        code = """\
void f(int n, int m) {
    if (m) goto LAB_001;
    while (n > 0) {
        if (probe(n)) goto LAB_001;
        n--;
    }
LAB_001:
    done();
}
"""
        result, stats = simplify(code)
        assert "if (probe(n)) break;" in result
        assert "if (m) goto LAB_001;" in result
        assert "\nLAB_001:\n" in result
        assert stats["functions_reverted"] == 0


class TestIfElseRootCauses:

    def test_parts_must_be_siblings(self):
        """I1: ``if`` iç blokta, etiketler dışta. Eski sürüm ``}``'ı then
        bloğuna katıp ``else``'i dıştaki ``if``'e bağlıyordu (koşul tersine
        dönmüş, ayraçlar dengeli)."""
        assert_unchanged_by_choice("""\
void f(int c, int d) {
    if (d) {
        if (c) goto LAB_0b0;
        a();
    }
    goto LAB_0c0;
LAB_0b0:
    b();
LAB_0c0:
    done();
}
""")

    def test_else_label_in_outer_block_blocks_restructure(self):
        """I1: ELSE etiketi dış blokta, bitiş etiketi iç blokta."""
        assert_unchanged_by_choice("""\
void f(int c, int d) {
    pre1();
    if (d) {
        if (c) goto LAB_0b0;
        a();
        goto LAB_0c0;
        x1();
        x2();
LAB_0c0:
        y();
    }
    z();
LAB_0b0:
    b();
}
""")

    def test_end_label_in_outer_block_blocks_restructure(self):
        """I1: ELSE etiketi ``if`` ile kardeş, bitiş etiketi dış blokta."""
        assert_unchanged_by_choice("""\
void f(int c, int d) {
    if (d) {
        if (c) goto LAB_0b0;
        a();
        goto LAB_0c0;
LAB_0b0:
        b();
        b2();
    }
    z1();
    z2();
    z3();
    z4();
LAB_0c0:
    done();
}
""")

    def test_else_label_with_second_goto_is_kept(self):
        """I1: ELSE etiketine başka bir goto da gidiyor; etiket silinemez."""
        assert_unchanged_by_choice("""\
void f(int c, int d) {
    if (d) goto LAB_0b0;
    if (c) goto LAB_0b0;
    a();
    goto LAB_0c0;
LAB_0b0:
    b();
LAB_0c0:
    done();
}
""")

    def test_end_label_with_second_goto_is_kept(self):
        code = """\
void f(int c, int d) {
    if (d) goto LAB_0c0;
    if (c) goto LAB_0b0;
    a();
    goto LAB_0c0;
LAB_0b0:
    b();
LAB_0c0:
    done();
}
"""
        result, stats = simplify(code)
        assert result == """\
void f(int c, int d) {
    if (d) goto LAB_0c0;
    if (!(c)) {
        a();
    } else {
        b();
    }
LAB_0c0:
    done();
}
"""
        assert stats["ifelse_restructured"] == 1
        assert stats["functions_reverted"] == 0

    def test_label_inside_then_part_blocks_restructure(self):
        assert_unchanged_by_choice("""\
void f(int c, int d) {
    if (d) goto LAB_0aa;
    if (c) goto LAB_0b0;
    a();
LAB_0aa:
    a2();
    goto LAB_0c0;
LAB_0b0:
    b();
LAB_0c0:
    done();
}
""", passes=("ifelse",))

    def test_declaration_in_part_blocks_restructure(self):
        assert_unchanged_by_choice("""\
void f(int c) {
    if (c) goto LAB_0b0;
    int v = a();
    goto LAB_0c0;
LAB_0b0:
    b();
LAB_0c0:
    done(v);
}
""", passes=("ifelse",))


class TestCascadeRootCauses:

    def test_fallthrough_keeps_the_goto(self):
        """``A: goto C;`` satırına düşerek de ulaşılıyor; eski sürüm
        etiketle birlikte goto'yu da siliyordu (``first()`` sonrası
        ``second()`` çalışıyordu)."""
        code = """\
void f(int x) {
    if (x == 1) goto LAB_00a;
    if (x == 2) goto LAB_00b;
    first();
LAB_00a:
    goto LAB_00c;
LAB_00b:
    second();
LAB_00c:
    done();
}
"""
        result, stats = simplify(code, passes=("cascade",))
        assert result == """\
void f(int x) {
    if (x == 1) goto LAB_00c;
    if (x == 2) goto LAB_00b;
    first();
    goto LAB_00c;
LAB_00b:
    second();
LAB_00c:
    done();
}
"""
        assert stats["cascading_collapsed"] == 1
        assert stats["functions_reverted"] == 0

    def test_unreachable_relay_is_removed(self):
        code = """\
void f(int x) {
    if (x == 1) goto LAB_00a;
    first();
    goto LAB_00c;
LAB_00a:
    goto LAB_00c;
LAB_00c:
    done();
}
"""
        result, stats = simplify(code, passes=("cascade",))
        assert result == """\
void f(int x) {
    if (x == 1) goto LAB_00c;
    first();
    goto LAB_00c;
LAB_00c:
    done();
}
"""
        assert stats["functions_reverted"] == 0

    def test_goto_cycle_is_left_alone(self):
        assert_unchanged_by_choice("""\
void f(int x) {
    if (x) goto LAB_00a;
    return;
LAB_00a:
    goto LAB_00b;
LAB_00b:
    goto LAB_00a;
}
""", passes=("cascade",))


class TestLexing:

    def test_strings_comments_and_trailer_are_untouched(self):
        """Eski sürüm dizgi içindeki ``}`` ve ``LAB_`` sözcüklerini kod
        sayıyor, yeniden adlandırmayı yoruma ve DISASSEMBLY ekine de
        uyguluyordu."""
        code = """\
// Function: f
int f(char *p, char *q) {
    puts("LAB_001: goto LAB_001; }");
    /* see LAB_001 } */
    if (p == NULL) goto LAB_001;
    if (q == NULL) goto LAB_001;
    use(p);
LAB_001:
    free(p);
    free(q);
    return 0;
}
// --- DISASSEMBLY (2 instructions) ---
// 00001000  b LAB_001
"""
        result, stats = simplify(code)
        assert result == """\
// Function: f
int f(char *p, char *q) {
    puts("LAB_001: goto LAB_001; }");
    /* see LAB_001 } */
    if (p == NULL) goto cleanup_and_return;
    if (q == NULL) goto cleanup_and_return;
    use(p);
cleanup_and_return:
    free(p);
    free(q);
    return 0;
}
// --- DISASSEMBLY (2 instructions) ---
// 00001000  b LAB_001
"""
        assert stats["renamed"] == 1
        assert stats["functions_reverted"] == 0

    def test_mask_keeps_length_and_newlines(self):
        text = 'a = "x{y"; /* } \n } */ b = \'{\'; // }\nc;'
        code, nocomment = fs._mask(text)
        assert len(code) == len(text) == len(nocomment)
        assert [i for i, ch in enumerate(text) if ch == "\n"] == \
               [i for i, ch in enumerate(code) if ch == "\n"]
        assert "{" not in code and "}" not in code
        assert '"x{y"' in nocomment and "'{'" in nocomment
        assert "/*" not in nocomment and "//" not in nocomment

    @pytest.mark.parametrize("broken", [
        "void f(int x) {\n    if (x) goto LAB_001;\n    /* kapanmayan yorum\nLAB_001:\n    return;\n}\n",
        "void f(int x) {\n    if (x) goto LAB_001;\n    puts(\"kapanmayan);\nLAB_001:\n    return;\n}\n",
        "void f(int x) {\n    if (x) goto LAB_001;\n    {\nLAB_001:\n    return;\n}\n",
        # gövde içinde ön işlemci satırı: deyim sınırı bilinemez
        "int f(int x) {\n    if (x) goto LAB_001;\n#include <x.h>\n    use(x);\n    return 1;\nLAB_001:\n    return 0;\n}\n",
        # satır devamı
        "int f(int x) {\n    if (x) goto LAB_001;\n    x = 1 + \\\n        2;\n    return 1;\nLAB_001:\n    return 0;\n}\n",
        "void f(int x) {\n    if (x) goto LAB_001;\n    else else x = 1;\nLAB_001:\n    return;\n}\n",
        "void f(int x) {\n    if (x) goto LAB_001;\nLAB_001:\n    x = 1;\nLAB_001:\n    return;\n}\n",
    ])
    def test_unparseable_function_is_untouched(self, broken):
        result, stats = simplify(broken)
        assert result == broken
        assert stats["functions_reverted"] == 0

    def test_duplicate_label_function_is_untouched(self):
        """Ghidra nadiren aynı etiketi iki kez yazar; hangi tanımın hedef
        olduğu belirsizdir, fonksiyona dokunulmaz."""
        code = """\
int f(int x) {
    if (x) goto LAB_001;
    return 1;
LAB_001:
    return 2;
LAB_001:
    return 3;
}
"""
        result, stats = simplify(code)
        assert result == code
        assert stats["functions_skipped"] == 1
        assert stats["functions_reverted"] == 0

    def test_unparseable_function_is_counted(self):
        code = "void f(int x) {\n    if (x) goto LAB_001;\n    continue(x);\nLAB_001:\n    return;\n}\n"
        result, stats = simplify(code)
        assert result == code
        assert stats["functions_skipped"] == 1

    def test_only_the_bad_function_is_skipped(self):
        good = "int g(int x) {\n    if (x < 0) goto LAB_002;\n    return x;\nLAB_002:\n    return 0;\n}\n"
        bad = "void f(int x) {\n    if (x) goto LAB_001;\n    continue(x);\nLAB_001:\n    return;\n}\n"
        result, stats = simplify(bad + "\n" + good)
        assert result.startswith(bad)
        assert "if (x < 0) return 0;" in result
        assert stats["functions_skipped"] == 1
        assert stats["functions_changed"] == 1


class TestRename:

    def test_new_name_never_collides_with_identifier(self):
        code = """\
int f(int exit_function) {
    if (exit_function < 0) goto LAB_001;
    exit_function = work(exit_function);
LAB_001:
    log_it(exit_function);
    return exit_function;
}
"""
        result, stats = simplify(code)
        assert result == code.replace("LAB_001", "exit_function_2")
        assert stats["functions_reverted"] == 0

    def test_names_are_unique_across_functions_in_a_file(self):
        one = "int f(int x) {\n    if (x < 0) goto LAB_001;\n    x = work(x);\nLAB_001:\n    log_it(x);\n    return x;\n}\n"
        two = one.replace("int f", "int g").replace("LAB_001", "LAB_002")
        result, stats = simplify(one + two)
        assert result == one.replace("LAB_001", "exit_function") + two.replace("LAB_002", "exit_function_2")
        assert stats["renamed"] == 2

    @pytest.mark.parametrize("first_statement", ["n = step(n);", "free(p);"])
    def test_loop_head_label_gets_no_exit_name(self, first_statement):
        """Düz bloğu bir atlamayla bitmeyen etiket (döngü başı) adlandırılmaz;
        blokta temizlik çağrısı olsa da."""
        assert_unchanged_by_choice("""\
int f(int n, char *p) {
LAB_001:
    %s
    if (n > 3) {
        return 0;
    }
    if (n == 1) goto LAB_001;
    more(n);
    even_more(n);
}
""" % first_statement)

    def test_label_names_do_not_feed_the_heuristic(self):
        """``goto error_cleanup;`` ya da ``__stack_chk_fail`` kendi başına
        "cleanup"/"fail" sayılmaz (yoksa ad, uygulama sayısına bağlı olur)."""
        s = CFlowSimplifier()
        assert s._classify_label("LAB_1", "    log_it(x);\n    goto error_cleanup_2;") == "LAB_1"
        assert s._classify_label("LAB_1", "    __stack_chk_fail();\n    return;") == "LAB_1"
        assert s._classify_label("LAB_1", "    puts(\"free\");\n    return;") == "LAB_1"
        assert s._classify_label("LAB_1", "    xfree(p);\n    return;") == "cleanup_and_return"
        assert s._classify_label("LAB_1", "    report_error(p);\n    return;") == "error_exit"

    def test_simplification_is_idempotent_on_renamed_output(self):
        code = """\
int f(char *p, int n) {
    if (n == 1) goto LAB_001;
    if (n == 2) goto LAB_002;
    use(p);
LAB_002:
    log_it(n);
    goto LAB_001;
LAB_001:
    free(p);
    return 0;
}
"""
        once, _ = simplify(code)
        twice, stats = simplify(once)
        assert twice == once
        assert stats["functions_changed"] == 0


class TestExtractLabelBlock:

    def test_stops_at_enclosing_brace(self):
        s = CFlowSimplifier()
        content = "\n        free(p);\n    }\n    done(a);\n    return 0;\n}\n"
        assert s._extract_label_block(content, 0).strip() == "free(p);"
        assert s._label_block(content, 0)[1] == ""

    def test_nested_return_is_not_the_terminator(self):
        s = CFlowSimplifier()
        content = "\n    if (q) {\n        return 1;\n    }\n    free(p);\n    goto LAB_9;\n    other();\n"
        block, terminator = s._label_block(content, 0)
        assert terminator == "goto"
        assert block.split("\n")[-1].strip() == "goto LAB_9;"
        assert "other" not in block


# ===========================================================================
# 2. Ard koşul denetimi
# ===========================================================================

OLD_BODY = """{
    if (a == NULL) goto LAB_00cc;
    use(a);
    return 0;
LAB_00cc:
    log_null();
    return -1;
}"""

GOOD_BODY = """{
    if (a == NULL) {
        /* error cleanup (inlined from LAB_00cc) */
        log_null();
        return -1;
    }
    use(a);
    return 0;
}"""


class TestPostcondition:

    def test_correct_transformation_passes(self):
        assert fs._postcondition_violation(OLD_BODY, GOOD_BODY, Counter()) is None

    def test_identity_passes(self):
        assert fs._postcondition_violation(OLD_BODY, OLD_BODY, Counter()) is None

    @pytest.mark.parametrize("new_body, expected", [
        # kapanmayan ayraç
        (GOOD_BODY[:-1], "denge"),
        # fazladan kapanış
        (GOOD_BODY + "\n}", "denge"),
        # parantez dengesiz
        (GOOD_BODY.replace("use(a);", "use(a;"), "denge"),
        # köşeli ayraç dengesiz
        (GOOD_BODY.replace("use(a);", "use(a[0);"), "denge"),
        # ters sırada kapanış: sayılar tutuyor, iç içelik tutmuyor
        (GOOD_BODY.replace("use(a);", "use(a[0)];"), "denge"),
        # dengeli ama ayrışmıyor
        (GOOD_BODY.replace("use(a);", "use(a);\n    else use(a);"), "ayrıştırma"),
        # etiket iki kez
        (OLD_BODY.replace("    use(a);", "LAB_00cc:\n    use(a);"), "etiket"),
        # goto'nun etiketi yok
        (GOOD_BODY.replace("use(a);", "use(a);\n    goto LAB_00cc;"), "goto"),
        # çağrı kayboldu
        (GOOD_BODY.replace("    use(a);\n", ""), "çağrı"),
        # bildirilmemiş fazladan çağrı
        (GOOD_BODY.replace("use(a);", "use(a);\n    use(a);"), "çağrı"),
        # return değeri değişti
        (GOOD_BODY.replace("return -1;", "return 1;"), "return"),
        # artık parça (erişilemeyen yerde)
        (GOOD_BODY.replace("return 0;", "return 0;\n1;"), "deyim"),
        # koşul değişti
        (GOOD_BODY.replace("a == NULL", "a != NULL"), "deyim"),
        # ayraçsız koşul: return koşulsuz oldu (eski sürümün çıktısı)
        ("""{
    if (a == NULL)
 /* error cleanup (inlined from LAB_00cc) */
 log_null();
 return -1;
    use(a);
    return 0;
;
}""", "akış"),
        # deyim sırası değişti
        (GOOD_BODY.replace("    use(a);\n    return 0;", "    return 0;\n    use(a);"), "akış"),
        # koşul ters çevrildi ama kollar yer değiştirmedi
        (GOOD_BODY.replace("if (a == NULL) {", "if (!(a == NULL)) {"), "akış"),
    ])
    def test_broken_transformations_are_named(self, new_body, expected):
        assert fs._postcondition_violation(OLD_BODY, new_body, Counter()) == expected

    def test_declared_copies_are_accepted_and_required(self):
        old = """{
    if (a == NULL) goto LAB_1;
    if (b == NULL) goto LAB_1;
    return 0;
LAB_1:
    free(a);
    return -1;
}"""
        new = """{
    if (a == NULL) {
        free(a);
        return -1;
    }
    if (b == NULL) {
        free(a);
        return -1;
    }
    return 0;
}"""
        assert fs._postcondition_violation(old, new, Counter({"free": 1})) is None
        assert fs._postcondition_violation(old, new, Counter()) == "çağrı"
        assert fs._postcondition_violation(old, new, Counter({"free": 2})) == "çağrı"
        # sayım bilinmiyorsa (ölçüm betiği) yalnız kayıp aranır
        assert fs._postcondition_violation(old, new, None) is None
        assert fs._postcondition_violation(old, new.replace("        free(a);\n", ""), None) == "çağrı"

    def test_negated_condition_with_swapped_arms_is_equivalent(self):
        old = "{\n    if (c) {\n        a();\n    } else {\n        b();\n    }\n    return;\n}"
        new = "{\n    if (!(c)) {\n        b();\n    } else {\n        a();\n    }\n    return;\n}"
        assert fs._postcondition_violation(old, new, Counter()) is None
        partial = "{\n    if (!(c) && d) {\n        b();\n    } else {\n        a();\n    }\n    return;\n}"
        assert fs._postcondition_violation(old, partial, Counter()) == "deyim"

    def test_break_bound_to_wrong_loop_is_a_flow_violation(self):
        old = "{\n    while (n) {\n        while (m) {\n            if (p()) goto LAB_1;\n            m--;\n        }\n        n--;\n    }\nLAB_1:\n    done();\n}"
        new = old.replace("goto LAB_1;", "break;").replace("LAB_1:\n", "")
        assert fs._postcondition_violation(old, new, Counter()) == "akış"

    def test_break_bound_to_right_loop_is_equivalent(self):
        old = "{\n    while (n) {\n        if (p()) goto LAB_1;\n        n--;\n    }\nLAB_1:\n    done();\n}"
        new = old.replace("goto LAB_1;", "break;").replace("LAB_1:\n", "")
        assert fs._postcondition_violation(old, new, Counter()) is None

    def test_continue_in_conditional_do_while_is_a_flow_violation(self):
        old = "{\nLAB_1:\n    do {\n        if (p()) goto LAB_1;\n        n--;\n    } while (n > 0);\n    done();\n}"
        new = old.replace("goto LAB_1;", "continue;").replace("LAB_1:\n", "")
        assert fs._postcondition_violation(old, new, Counter()) == "akış"
        old_true = old.replace("while (n > 0)", "while( true )")
        new_true = new.replace("while (n > 0)", "while( true )")
        assert fs._postcondition_violation(old_true, new_true, Counter()) is None

    def test_lost_fallthrough_return_is_a_flow_violation(self):
        old = "{\n    if (x < 0) goto LAB_1;\n    x = work(x);\nLAB_1:\n    return x;\n}"
        new = "{\n    if (x < 0) return x;\n    x = work(x);\n}"
        assert fs._postcondition_violation(old, new, Counter()) == "akış"

    def test_switch_case_targets_are_compared(self):
        old = "{\n    switch (k) {\n    case 1:\n        a();\n        break;\n    case 2:\n        b();\n    default:\n        c();\n    }\n    return;\n}"
        assert fs._postcondition_violation(old, old.replace("        break;\n", "        break;\n        break;\n"), Counter()) is None
        swapped = old.replace("case 1:", "case 9:").replace("case 2:", "case 1:").replace("case 9:", "case 2:")
        assert fs._postcondition_violation(old, swapped, Counter()) == "akış"

    def test_cfg_compares_switch_case_values(self):
        """Akış grafı tek başına: case değeri değişirse graflar eşdeğer değil."""
        old = "{\n    switch (k) {\n    case 1:\n        a();\n        break;\n    default:\n        c();\n    }\n    return;\n}"

        def cfg(text):
            return fs._Cfg(fs._Analysis(text))

        assert fs._cfg_equivalent(cfg(old), cfg(old.replace("a();", "a();\n        ;")))
        assert not fs._cfg_equivalent(cfg(old), cfg(old.replace("case 1:", "case 3:")))
        assert not fs._cfg_equivalent(cfg(old), cfg(old.replace("a();", "b();")))

    def test_out_of_function_goto_is_tolerated_but_not_new_ones(self):
        old = "{\n    if (x) goto code_r0x00101234;\n    a();\n    return;\n}"
        assert fs._postcondition_violation(old, old.replace("a();", "a();\n    ;"), Counter()) is None
        new = old.replace("code_r0x00101234", "code_r0x00109999")
        assert fs._postcondition_violation(old, new, Counter()) == "goto"

    def test_comments_and_literals_are_skipped(self):
        old = "{\n    if (x) goto LAB_1;\n    puts(\"}\");\nLAB_1:\n    return;\n}"
        new = "{\n    /* { ( [ goto LAB_9; */\n    if (x) goto LAB_1;\n    puts(\"}\"); // }\nLAB_1:\n    return;\n}"
        assert fs._postcondition_violation(old, new, Counter()) is None
        changed_literal = new.replace('puts("}")', 'puts("{")')
        assert fs._postcondition_violation(old, changed_literal, Counter()) == "deyim"

    def test_brackets_balanced_helper(self):
        assert fs._brackets_balanced("{ ( [ ] ) }")
        assert not fs._brackets_balanced("{ ( } )")
        assert not fs._brackets_balanced("{ {")
        assert not fs._brackets_balanced("}")


def _drop_statement_pass(needle: str):
    """``needle`` geçen satırı silen (bozuk) bir geçiş üretir."""
    def bad_pass(self, an, file_ctx=None):
        pos = an.text.find(needle)
        if pos < 0:
            return [], {}, {}
        start = an.text.rfind("\n", 0, pos) + 1
        end = an.text.find("\n", pos) + 1
        return [(start, end, "")], {"early_returns": 1, "eliminated": 1}, {}
    return bad_pass


class TestRevertOnViolation:

    CODE = """\
int f(char *a) {
    if (a == NULL) goto LAB_00cc;
    use(a);
    return 0;
LAB_00cc:
    log_null();
    return -1;
}
"""

    def test_bad_pass_restores_original_text(self, monkeypatch):
        monkeypatch.setattr(CFlowSimplifier, "_pass_early_return", _drop_statement_pass("use(a);"))
        result, stats = simplify(self.CODE)
        assert result == self.CODE
        assert stats["functions_reverted"] == 1
        assert stats["reverted_çağrı"] == 1
        # geri alınan fonksiyonun dönüşüm sayaçları yazılmaz
        assert stats["functions_changed"] == 0
        assert stats["inlined"] == 0 and stats["eliminated"] == 0 and stats["early_returns"] == 0

    @pytest.mark.parametrize("edit, reason", [
        # ayraç siler
        (lambda t: [(len(t) - 1, len(t), "")], "ayrıştırma"),
        # parantez açar
        (lambda t: [(t.index("use(a)"), t.index("use(a)") + 6, "use((a)")], "ayrıştırma"),
        # etiketi siler, goto kalır
        (lambda t: [(t.index("LAB_00cc:"), t.index("LAB_00cc:") + 9, "")], "goto"),
        # return'ü değiştirir
        (lambda t: [(t.index("return -1;"), t.index("return -1;") + 10, "return 7;")], "return"),
        # koşulsuz return ekler (akış değişir, çağrılar ve return kümesi aynı)
        (lambda t: [(t.index("    use(a);"), t.index("    use(a);"), "    return 0;\n")], "akış"),
    ])
    def test_each_violation_reverts(self, monkeypatch, edit, reason):
        def bad_pass(self, an, file_ctx=None):
            return edit(an.text), {"eliminated": 1}, {}
        monkeypatch.setattr(CFlowSimplifier, "_pass_cascade", bad_pass)
        s = CFlowSimplifier()
        s._passes = ("cascade",)
        result, stats = s._simplify_content(self.CODE)
        assert result == self.CODE
        assert stats["functions_reverted"] == 1
        assert stats.get("reverted_" + reason) == 1

    def test_overlapping_edits_revert(self, monkeypatch):
        def bad_pass(self, an, file_ctx=None):
            return [(5, 20, "x"), (10, 30, "y")], {}, {}
        monkeypatch.setattr(CFlowSimplifier, "_pass_cascade", bad_pass)
        result, stats = simplify(self.CODE)
        assert result == self.CODE
        assert stats["functions_reverted"] == 1

    def test_other_functions_in_file_are_still_simplified(self, monkeypatch):
        other = "int g(int x) {\n    if (x < 0) goto LAB_002;\n    return x;\nLAB_002:\n    return 0;\n}\n"
        monkeypatch.setattr(CFlowSimplifier, "_pass_cascade", _drop_statement_pass("use(a);"))
        result, stats = simplify(self.CODE + "\n" + other)
        assert result.startswith(self.CODE)
        assert "if (x < 0) return 0;" in result
        assert stats["functions_reverted"] == 1
        assert stats["functions_changed"] == 1
        assert stats["early_returns"] == 1

    def test_directory_writes_only_verified_functions(self, monkeypatch, tmp_path):
        good = "int g(int x) {\n    if (x < 0) goto LAB_002;\n    return x;\nLAB_002:\n    return 0;\n}\n"
        (tmp_path / "bad.c").write_text(self.CODE, encoding="utf-8")
        (tmp_path / "good.c").write_text(good, encoding="utf-8")
        monkeypatch.setattr(CFlowSimplifier, "_pass_cascade", _drop_statement_pass("use(a);"))
        result = CFlowSimplifier().simplify_directory(tmp_path)
        assert isinstance(result, SimplifyResult)
        assert (tmp_path / "bad.c").read_text(encoding="utf-8") == self.CODE
        assert "if (x < 0) return 0;" in (tmp_path / "good.c").read_text(encoding="utf-8")
        assert result.functions_reverted == 1
        assert result.files_modified == 1
        assert result.early_returns == 1

    def test_directory_counts_failed_files_and_continues(self, monkeypatch, tmp_path):
        good = "int g(int x) {\n    if (x < 0) goto LAB_002;\n    return x;\nLAB_002:\n    return 0;\n}\n"
        (tmp_path / "a_boom.c").write_text(self.CODE, encoding="utf-8")
        (tmp_path / "b_good.c").write_text(good, encoding="utf-8")

        def boom(self, an, file_ctx=None):
            if "use(a)" in an.text:
                raise RuntimeError("beklenmeyen")
            return [], {}, {}
        monkeypatch.setattr(CFlowSimplifier, "_pass_cascade", boom)
        result = CFlowSimplifier().simplify_directory(tmp_path)
        assert result.files_failed == 1
        assert (tmp_path / "a_boom.c").read_text(encoding="utf-8") == self.CODE
        assert "if (x < 0) return 0;" in (tmp_path / "b_good.c").read_text(encoding="utf-8")

    def test_large_content_only_renames(self):
        filler = "    x = x + 1;\n" * 40000
        code = (
            "int f(int x) {\n    if (x < 0) goto LAB_001;\n" + filler
            + "    return x;\nLAB_001:\n    log_it(x);\n    return 0;\n}\n"
        )
        result, stats = simplify(code)
        assert stats["inlined"] == 0 and stats["early_returns"] == 0
        assert stats["renamed"] == 1
        assert "goto exit_function;" in result


class TestDeterminism:

    def test_same_input_same_output(self):
        code = TestRevertOnViolation.CODE + "\n" + """\
int g(char *p, int n) {
    if (n == 1) goto LAB_001;
    if (n == 2) goto LAB_002;
    if (n == 3) goto LAB_003;
    use(p);
LAB_003:
    log_it(n);
    return 1;
LAB_002:
    free(p);
    return 2;
LAB_001:
    close(n);
    return 3;
}
"""
        first = simplify(code)
        for _ in range(3):
            assert simplify(code) == first


# ===========================================================================
# 3. Bağımsız yorumlayıcıyla fark testi
# ===========================================================================
#
# Yorumlayıcı ürün kodunu kullanmaz: kendi sözcük çözücüsü ve ayrıştırıcısı
# vardır. Program düz bir komut listesine derlenir (goto bir bloğun içine de
# atlayabilir), sonra bir bit akışıyla çalıştırılır. ``c(K)`` her
# çağrıldığında akıştan bir değer çeker; ``a(K);`` ve ``return K;`` olay
# üretir. İki metin aynı akışla aynı olay izini vermelidir.

_TOKEN_RE = re.compile(r"/\*.*?\*/|//[^\n]*|[A-Za-z_]\w*|\d+|[(){};:!]", re.S)


def _tokens(text: str) -> list[str]:
    return [t for t in _TOKEN_RE.findall(text) if not t.startswith(("/*", "//"))]


class _Compiler:
    """Mini dil -> komut listesi. Komutlar:

    ("call", ad, n) | ("cond", n, yanlışsa_hedef) | ("sw", n, {değer: hedef}, varsayılan)
    | ("jmp", hedef) | ("goto", etiket) | ("ret", n)
    """

    def __init__(self, text: str):
        self.t = _tokens(text)
        self.i = 0
        self.code: list[list] = []
        self.labels: dict[str, int] = {}
        self.breaks: list[list[int]] = []
        self.continues: list[list[int]] = []
        self.switches: list[tuple[dict, list]] = []
        self.expect("{")
        self.block_items()
        self.code.append(["end"])

    def peek(self, k: int = 0) -> str:
        return self.t[self.i + k] if self.i + k < len(self.t) else ""

    def expect(self, tok: str) -> None:
        assert self.peek() == tok, (tok, self.t[self.i:self.i + 6])
        self.i += 1

    def emit(self, *ins) -> int:
        self.code.append(list(ins))
        return len(self.code) - 1

    def block_items(self) -> None:
        while self.peek() != "}":
            self.stmt()
        self.expect("}")

    def cond(self) -> int:
        """Koşulu derler; dönen: 'yanlışsa atla' komutunun sırası."""
        negate = False
        depth = 0
        while self.peek() in ("!", "("):
            if self.peek() == "!":
                negate = not negate
            else:
                depth += 1
            self.i += 1
        if self.peek() == "true":
            self.i += 1
            ins = self.emit("const", not negate, None)
        else:
            self.expect("c")
            self.expect("(")
            n = int(self.peek())
            self.i += 1
            self.expect(")")
            ins = self.emit("cond", n, None, negate)
        for _ in range(depth):
            self.expect(")")
        return ins

    def call(self) -> None:
        name = self.peek()
        self.i += 1
        self.expect("(")
        n = int(self.peek())
        self.i += 1
        self.expect(")")
        self.emit("call", name, n)

    def stmt(self) -> None:
        t = self.peek()
        if t == "{":
            self.i += 1
            self.block_items()
        elif t == ";":
            self.i += 1
        elif t == "if":
            self.i += 1
            self.expect("(")
            c = self.cond()
            self.expect(")")
            self.stmt()
            if self.peek() == "else":
                self.i += 1
                j = self.emit("jmp", None)
                self.code[c][2] = len(self.code)
                self.stmt()
                self.code[j][1] = len(self.code)
            else:
                self.code[c][2] = len(self.code)
        elif t == "while":
            self.i += 1
            top = len(self.code)
            self.expect("(")
            c = self.cond()
            self.expect(")")
            self.breaks.append([])
            self.continues.append([])
            self.stmt()
            self.emit("jmp", top)
            self.code[c][2] = len(self.code)
            self.patch(self.continues.pop(), top)
            self.patch(self.breaks.pop(), len(self.code))
        elif t == "do":
            self.i += 1
            top = len(self.code)
            self.breaks.append([])
            self.continues.append([])
            self.stmt()
            self.expect("while")
            test = len(self.code)
            self.expect("(")
            c = self.cond()
            self.expect(")")
            self.expect(";")
            self.emit("jmp", top)
            self.code[c][2] = len(self.code)
            self.patch(self.continues.pop(), test)
            self.patch(self.breaks.pop(), len(self.code))
        elif t == "for":
            self.i += 1
            self.expect("(")
            self.call()
            self.expect(";")
            top = len(self.code)
            c = self.cond()
            self.expect(";")
            # artırma deyimi gövdeden sonra çalışır: önce atla, sonra geri gel
            to_body = self.emit("jmp", None)
            step = len(self.code)
            self.call()
            self.emit("jmp", top)
            self.expect(")")
            self.code[to_body][1] = len(self.code)
            self.breaks.append([])
            self.continues.append([])
            self.stmt()
            self.emit("jmp", step)
            self.code[c][2] = len(self.code)
            self.patch(self.continues.pop(), step)
            self.patch(self.breaks.pop(), len(self.code))
        elif t == "switch":
            self.i += 1
            self.expect("(")
            self.expect("c")
            self.expect("(")
            n = int(self.peek())
            self.i += 1
            self.expect(")")
            self.expect(")")
            table: dict = {}
            sw = self.emit("sw", n, table, None)
            self.switches.append((table, self.code[sw]))
            self.breaks.append([])
            self.stmt()
            self.switches.pop()
            if self.code[sw][3] is None:
                self.code[sw][3] = len(self.code)
            self.patch(self.breaks.pop(), len(self.code))
        elif t == "case":
            self.i += 1
            value = int(self.peek())
            self.i += 1
            self.expect(":")
            self.switches[-1][0][value] = len(self.code)
        elif t == "default":
            self.i += 1
            self.expect(":")
            self.switches[-1][1][3] = len(self.code)
        elif t == "goto":
            self.i += 1
            self.emit("goto", self.peek())
            self.i += 1
            self.expect(";")
        elif t == "return":
            self.i += 1
            n = int(self.peek())
            self.i += 1
            self.expect(";")
            self.emit("ret", n)
        elif t == "break":
            self.i += 1
            self.expect(";")
            self.breaks[-1].append(self.emit("jmp", None))
        elif t == "continue":
            self.i += 1
            self.expect(";")
            self.continues[-1].append(self.emit("jmp", None))
        elif self.peek(1) == ":":
            assert t not in self.labels, "yinelenen etiket " + t
            self.labels[t] = len(self.code)
            self.i += 2
        else:
            self.call()
            self.expect(";")

    def patch(self, slots: list[int], target: int) -> None:
        for s in slots:
            self.code[s][1] = target


def run_program(text: str, seed: int, max_steps: int = 4000) -> tuple[list, bool]:
    """Fonksiyon gövdesini çalıştırır. Dönen: (olay izi, bitti_mi)."""
    comp = _Compiler(text)
    code, labels = comp.code, comp.labels
    rnd = random.Random(seed)
    trace: list = []
    pc = 0
    for _ in range(max_steps):
        ins = code[pc]
        op = ins[0]
        if op == "call":
            trace.append(("a", ins[1], ins[2]))
            pc += 1
        elif op == "cond":
            value = rnd.random() < 0.5
            trace.append(("c", ins[1], value))
            if ins[3]:
                value = not value
            pc = pc + 1 if value else ins[2]
        elif op == "const":
            pc = pc + 1 if ins[1] else ins[2]
        elif op == "sw":
            value = rnd.randrange(4)
            trace.append(("s", ins[1], value))
            pc = ins[2].get(value, ins[3])
        elif op == "jmp":
            pc = ins[1]
        elif op == "goto":
            pc = labels[ins[1]]
        elif op == "ret":
            trace.append(("ret", ins[1]))
            return trace, True
        else:
            trace.append(("end",))
            return trace, True
    return trace, False


def traces_agree(a: str, b: str, seeds=range(12)) -> bool:
    for seed in seeds:
        ta, done_a = run_program(a, seed)
        tb, done_b = run_program(b, seed)
        if done_a and done_b:
            if ta != tb:
                return False
        else:
            n = min(len(ta), len(tb))
            if ta[:n] != tb[:n]:
                return False
    return True


class _Generator:
    """Ghidra biçeminde rastgele goto'lu fonksiyon gövdesi üretir."""

    def __init__(self, rnd: random.Random):
        self.r = rnd
        self.k = 0
        n_labels = rnd.randint(1, 5)
        self.labels = ["LAB_%03x" % (i + 1) for i in range(n_labels)]
        self.undefined = list(self.labels)

    def num(self) -> int:
        self.k += 1
        return self.k

    def call(self) -> str:
        return "%s(%d);" % (self.r.choice(["a", "a", "free", "close"]), self.num())

    def label_here(self, out: list[str], chance: float) -> None:
        if self.undefined and self.r.random() < chance:
            out.append(self.undefined.pop(self.r.randrange(len(self.undefined))) + ":")

    def block(self, depth: int, loop: bool, sw: bool, ind: str, n_max: int = 4) -> list[str]:
        out: list[str] = []
        for _ in range(self.r.randint(1, n_max)):
            out.extend(self.stmt(depth, loop, sw, ind))
        return out

    def stmt(self, depth: int, loop: bool, sw: bool, ind: str) -> list[str]:
        r = self.r
        out: list[str] = []
        self.label_here(out, 0.25)
        p = r.random()
        inner = ind + "  "
        if p < 0.26:
            out.append(ind + self.call())
        elif p < 0.44:
            out.append("%sif (c(%d)) goto %s;" % (ind, self.num(), r.choice(self.labels)))
        elif p < 0.49:
            out.append("%sgoto %s;" % (ind, r.choice(self.labels)))
            self.label_here(out, 0.7)
        elif p < 0.57:
            out.append("%sreturn %d;" % (ind, self.num()))
            self.label_here(out, 0.8)
            if out[-1].endswith(":"):
                # atlamadan sonra gelen etiket: temizlik bloğu ya da return
                for _ in range(r.randint(0, 2)):
                    out.append(ind + self.call())
                out.append(ind + r.choice(["return %d;" % self.num(),
                                           "goto %s;" % r.choice(self.labels)]))
        elif p < 0.61 and (loop or sw):
            out.append(ind + ("break;" if sw and not loop else r.choice(["break;", "continue;"])))
        elif p < 0.65 and len(self.undefined) >= 2:
            # goto ile yazılmış if/else
            else_label = self.undefined.pop()
            end_label = self.undefined.pop()
            out.append("%sif (c(%d)) goto %s;" % (ind, self.num(), else_label))
            for _ in range(r.randint(1, 2)):
                out.append(ind + self.call())
            out.append("%sgoto %s;" % (ind, end_label))
            out.append(else_label + ":")
            for _ in range(r.randint(1, 2)):
                out.append(ind + self.call())
            out.append(end_label + ":")
            out.append(ind + self.call())
        elif depth >= 3:
            out.append(ind + self.call())
        elif p < 0.72:
            out.append("%sif (c(%d)) {" % (ind, self.num()))
            out.extend(self.block(depth + 1, loop, sw, inner))
            out.append(ind + "}")
            if r.random() < 0.4:
                out.append(ind + "else {")
                out.extend(self.block(depth + 1, loop, sw, inner))
                out.append(ind + "}")
        elif p < 0.76:
            out.append("%sif (c(%d)) %s" % (ind, self.num(), self.call()))
            if r.random() < 0.5:
                out.append("%selse goto %s;" % (ind, r.choice(self.labels)))
        elif p < 0.84:
            self.label_here(out, 0.4)
            out.append("%swhile (c(%d)) {" % (ind, self.num()))
            out.extend(self.block(depth + 1, True, False, inner))
            out.append(ind + "}")
            self.label_here(out, 0.6)
        elif p < 0.90:
            self.label_here(out, 0.4)
            out.append(ind + "do {")
            out.extend(self.block(depth + 1, True, False, inner))
            if r.random() < 0.5:
                out.append("%s} while( true );" % ind)
            else:
                out.append("%s} while (c(%d));" % (ind, self.num()))
            self.label_here(out, 0.6)
        elif p < 0.94:
            self.label_here(out, 0.4)
            out.append("%sfor (a(%d); c(%d); a(%d)) {" % (ind, self.num(), self.num(), self.num()))
            out.extend(self.block(depth + 1, True, False, inner))
            out.append(ind + "}")
            self.label_here(out, 0.6)
        else:
            out.append("%sswitch (c(%d)) {" % (ind, self.num()))
            for value in r.sample([0, 1, 2], r.randint(1, 3)):
                out.append("%scase %d:" % (ind, value))
                out.extend(self.block(depth + 1, loop, True, inner, 2))
                if r.random() < 0.6:
                    out.append(inner + "break;")
            if r.random() < 0.5:
                out.append(ind + "default:")
                out.extend(self.block(depth + 1, loop, True, inner, 2))
            out.append(ind + "}")
            self.label_here(out, 0.5)
        return out

    def function_body(self) -> str:
        out = ["{"]
        out.extend(self.block(0, False, False, "  ", 7))
        out.append("  return %d;" % self.num())
        while self.undefined:
            out.append(self.undefined.pop() + ":")
            for _ in range(self.r.randint(0, 2)):
                out.append("  " + self.call())
            out.append("  return %d;" % self.num())
        out.append("}")
        return "\n".join(out)


N_FUZZ = 400


def _fuzz_programs():
    for seed in range(N_FUZZ):
        yield seed, _Generator(random.Random(seed)).function_body()


class TestDifferentialExecution:

    def test_interpreter_distinguishes_programs(self):
        """Yorumlayıcının kendisi: bilinen eşdeğer/eşdeğer olmayan çiftler."""
        a = "{\n  if (c(1)) goto LAB_001;\n  a(2);\nLAB_001:\n  a(3);\n  return 4;\n}"
        same = "{\n  if (!(c(1))) {\n    a(2);\n  }\n  a(3);\n  return 4;\n}"
        different = "{\n  if (c(1)) {\n    a(2);\n  }\n  a(3);\n  return 4;\n}"
        assert traces_agree(a, same)
        assert not traces_agree(a, different)
        loop = "{\n  while (c(1)) {\n    while (c(2)) {\n      if (c(3)) goto LAB_001;\n      a(4);\n    }\n    a(5);\n  }\nLAB_001:\n  return 6;\n}"
        assert not traces_agree(loop, loop.replace("goto LAB_001;", "break;"))

    def test_simplified_programs_behave_like_originals(self):
        """Sadeleştirilen her program özgünüyle aynı olay izini verir."""
        s = CFlowSimplifier()
        changed = 0
        reverted = 0
        applied: Counter = Counter()
        for seed, text in _fuzz_programs():
            new, stats = s._simplify_function(text, fs._FileContext(text))
            reverted += stats.get("functions_reverted", 0)
            assert not stats.get("functions_skipped"), (seed, text)
            if new == text:
                continue
            changed += 1
            applied.update({k: 1 for k, v in stats.items() if v})
            assert fs._brackets_balanced(fs._mask(new)[0]), (seed, new)
            assert traces_agree(text, new), "tohum %d\n--- özgün\n%s\n--- yeni\n%s" % (seed, text, new)
        # üreteç dönüşümleri gerçekten tetikliyor olmalı
        assert changed >= N_FUZZ // 4
        for key in ("early_returns", "breaks_continues", "inlined",
                    "multi_target_inlined", "renamed", "cascading_collapsed",
                    "ifelse_restructured"):
            assert applied[key] >= 5, key
        # geçişler kendi başına doğru: güvenlik ağına hiç düşülmedi
        assert reverted == 0

    def test_checker_rejects_every_behaviour_changing_corruption(self):
        """Denetleyicinin sağlamlığı: izi değiştiren bozma ard koşuldan geçemez."""
        rnd = random.Random(20261110)
        caught = 0
        for seed, text in _fuzz_programs():
            lines = text.split("\n")
            for _ in range(4):
                mutated = _corrupt(lines, rnd)
                if mutated is None or mutated == text:
                    continue
                try:
                    differs = not traces_agree(text, mutated)
                except (AssertionError, KeyError, IndexError):
                    continue      # bozma mini dilin dışına çıktı
                if differs:
                    caught += 1
                    assert fs._postcondition_violation(text, mutated, None) is not None, \
                        "tohum %d\n--- özgün\n%s\n--- bozuk\n%s" % (seed, text, mutated)
        assert caught >= N_FUZZ


def _corrupt(lines: list[str], rnd: random.Random) -> str | None:
    """Metni, eski sürümün hatalarına benzer biçimde bozar."""
    out = list(lines)
    kind = rnd.randrange(7)
    idx = [i for i in range(1, len(out) - 1)]
    if kind == 0:                        # goto -> break
        cand = [i for i in idx if "goto LAB_" in out[i]]
        if not cand:
            return None
        i = rnd.choice(cand)
        out[i] = re.sub(r"goto LAB_\w+;", rnd.choice(["break;", "continue;"]), out[i])
    elif kind == 1:                      # goto hedefini değiştir
        cand = [i for i in idx if "goto LAB_" in out[i]]
        labels = sorted({m for ln in out for m in re.findall(r"^(LAB_\w+):", ln)})
        if not cand or len(labels) < 2:
            return None
        i = rnd.choice(cand)
        out[i] = re.sub(r"LAB_\w+", rnd.choice(labels), out[i])
    elif kind == 2:                      # koşulu ters çevir
        cand = [i for i in idx if re.search(r"\bif \(c\(\d+\)\)", out[i])]
        if not cand:
            return None
        i = rnd.choice(cand)
        out[i] = re.sub(r"if \((c\(\d+\))\)", r"if (!(\1))", out[i])
    elif kind == 3:                      # iki satırın yerini değiştir
        cand = [i for i in idx[:-1] if re.match(r"\s+(a|free|close)\(\d+\);$", out[i])
                and re.match(r"\s+(a|free|close)\(\d+\);$", out[i + 1])]
        if not cand:
            return None
        i = rnd.choice(cand)
        out[i], out[i + 1] = out[i + 1], out[i]
    elif kind == 4:                      # etiket satırını bir satır kaydır
        cand = [i for i in idx[:-1] if re.match(r"LAB_\w+:$", out[i])
                and not out[i + 1].lstrip().startswith(("}", "case", "default", "else"))]
        if not cand:
            return None
        i = rnd.choice(cand)
        out[i], out[i + 1] = out[i + 1], out[i]
    elif kind == 5:                      # "if (k) goto L;" altına ikinci deyim (ayraçsız)
        cand = [i for i in idx if re.match(r"\s+if \(c\(\d+\)\) goto LAB_\w+;$", out[i])]
        if not cand:
            return None
        i = rnd.choice(cand)
        out[i] = re.sub(r"goto (LAB_\w+);", r"a(999); goto \1;", out[i])
    else:                                # return'den sonraki etiketi sil (düşen yol)
        cand = [i for i in idx if re.match(r"LAB_\w+:$", out[i])]
        if not cand:
            return None
        i = rnd.choice(cand)
        name = out[i][:-1]
        if any(("goto " + name + ";") in ln for ln in out):
            out[i] = name + ":\n  return 998;"
        else:
            return None
    return "\n".join(out)
