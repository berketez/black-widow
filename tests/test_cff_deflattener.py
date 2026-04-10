"""CFF Deflattener testleri.

Control Flow Flattening (CFF) tespiti ve deflattening islemlerini test eder.

Test 1: Basit 4-state CFF detect + deflatten
Test 2: Hex state degerleri (case 0x1A:)
Test 3: Nested if iceren case block
Test 4: return ile cikan exit block
Test 5: CFF olmayan kod (false positive kontrolu)
Test 6: Bos kod
Test 7: JS CFF pattern (while(!0))
Test 8: Deflattened code dogrulama (blok sirasi)
Test 9: Multiline case block'lar
Test 10: deflatten_code() entegrasyon testi
Test 11: Birden fazla dispatcher
Test 12: for(;;) JS pattern
"""

from __future__ import annotations

import pytest

from karadul.deobfuscators.cff_deflattener import CFFDeflattener, CFFResult, CFFBlock


# --- Fixtures ---

@pytest.fixture
def deflattener() -> CFFDeflattener:
    return CFFDeflattener()


@pytest.fixture
def basic_cff_code() -> str:
    """4-state basit CFF kodu."""
    return """
int state = 0;
while(true) {
    switch(state) {
        case 0: init(); state = 2; break;
        case 1: cleanup(); return; break;
        case 2: process(); state = 3; break;
        case 3: validate(); state = 1; break;
    }
}
"""


@pytest.fixture
def hex_cff_code() -> str:
    """Hex state degerli CFF kodu."""
    return """
int s = 0;
while(1) {
    switch(s) {
        case 0x0: init(); s = 0x1A; break;
        case 0x1A: process(); s = 0xFF; break;
        case 0xFF: end(); return; break;
    }
}
"""


@pytest.fixture
def js_cff_code() -> str:
    """JavaScript CFF kodu (while(!0) pattern)."""
    return """
var _state = 0;
while(!0) {
    switch(_state) {
        case 0: setup(); _state = 2; break;
        case 1: teardown(); return; break;
        case 2: execute(); _state = 1; break;
    }
}
"""


# --- Test 1: Basit 4-state CFF detect + deflatten ---

class TestBasicCFFDetection:
    """Basit CFF pattern tespiti ve analizi."""

    def test_detect_cff_returns_true(self, deflattener, basic_cff_code):
        """CFF pattern dogru tespit edilmeli."""
        assert deflattener.detect_cff(basic_cff_code) is True

    def test_analyze_detected_true(self, deflattener, basic_cff_code):
        """analyze_cff detected=True donmeli."""
        result = deflattener.analyze_cff(basic_cff_code)
        assert result.detected is True

    def test_analyze_total_blocks(self, deflattener, basic_cff_code):
        """4 case blogu bulunmali."""
        result = deflattener.analyze_cff(basic_cff_code)
        assert result.total_blocks == 4

    def test_analyze_original_order(self, deflattener, basic_cff_code):
        """Topological sort dogru sira vermeli: 0 -> 2 -> 3 -> 1."""
        result = deflattener.analyze_cff(basic_cff_code)
        assert result.original_order == [0, 2, 3, 1]

    def test_analyze_state_graph(self, deflattener, basic_cff_code):
        """State graph dogru gecisleri icermeli."""
        result = deflattener.analyze_cff(basic_cff_code)
        assert result.state_graph == {0: [2], 1: [], 2: [3], 3: [1]}

    def test_analyze_dispatcher_count(self, deflattener, basic_cff_code):
        """Tek dispatcher bulunmali."""
        result = deflattener.analyze_cff(basic_cff_code)
        assert result.total_dispatchers == 1


# --- Test 2: Hex state degerleri ---

class TestHexStateValues:
    """Hex formatta state degerleri (case 0x1A:)."""

    def test_hex_detection(self, deflattener, hex_cff_code):
        """Hex state'li CFF tespit edilmeli."""
        assert deflattener.detect_cff(hex_cff_code) is True

    def test_hex_block_count(self, deflattener, hex_cff_code):
        """3 hex state blogu bulunmali."""
        result = deflattener.analyze_cff(hex_cff_code)
        assert result.total_blocks == 3

    def test_hex_state_values_parsed(self, deflattener, hex_cff_code):
        """Hex degerler integer'a donusturulmeli: 0x1A=26, 0xFF=255."""
        result = deflattener.analyze_cff(hex_cff_code)
        assert 0 in result.state_graph
        assert 26 in result.state_graph   # 0x1A
        assert 255 in result.state_graph  # 0xFF

    def test_hex_original_order(self, deflattener, hex_cff_code):
        """Sira: 0 -> 26 -> 255."""
        result = deflattener.analyze_cff(hex_cff_code)
        assert result.original_order == [0, 26, 255]


# --- Test 3: Nested if iceren case block ---

class TestNestedIfCaseBlock:
    """Case blogu icinde if-else yapisi."""

    def test_nested_if_block_count(self, deflattener):
        """Nested if iceren CFF'de bloklar dogru cikarilmali."""
        code = """
int state = 0;
while(true) {
    switch(state) {
        case 0:
            if (x > 0) {
                state = 1;
            } else {
                state = 2;
            }
            break;
        case 1: process_positive(); state = 3; break;
        case 2: process_negative(); state = 3; break;
        case 3: finish(); return; break;
    }
}
"""
        result = deflattener.analyze_cff(code)
        assert result.detected is True
        assert result.total_blocks == 4

    def test_nested_if_multiple_transitions(self, deflattener):
        """Nested if'te birden fazla state gecisi yakalanmali."""
        code = """
int state = 0;
while(true) {
    switch(state) {
        case 0:
            if (x > 0) {
                state = 1;
            } else {
                state = 2;
            }
            break;
        case 1: a(); state = 3; break;
        case 2: b(); state = 3; break;
        case 3: done(); return; break;
    }
}
"""
        result = deflattener.analyze_cff(code)
        # case 0: iki farkli state'e gecis yapiyor (1 ve 2)
        assert sorted(result.state_graph.get(0, [])) == [1, 2]


# --- Test 4: return ile cikan exit block ---

class TestExitBlock:
    """Return ile sonlanan exit state bloklari."""

    def test_exit_block_detected(self, deflattener, basic_cff_code):
        """Return iceren blok exit block olarak isaretlenmeli."""
        result = deflattener.analyze_cff(basic_cff_code)
        # state 1: cleanup(); return; -- bu exit block
        assert result.state_graph.get(1) == []  # no next states

    def test_exit_block_no_next_state(self, deflattener):
        """Exit block hicbir state'e gecis yapmamali."""
        code = """
int state = 0;
while(true) {
    switch(state) {
        case 0: work(); state = 1; break;
        case 1: return result; break;
    }
}
"""
        result = deflattener.analyze_cff(code)
        assert result.state_graph.get(1) == []


# --- Test 5: CFF olmayan kod (false positive kontrolu) ---

class TestFalsePositives:
    """CFF olmayan kodlarda false positive olmamali."""

    def test_normal_for_loop(self, deflattener):
        """Normal for dongusu CFF degil."""
        code = """
for(int i = 0; i < 10; i++) {
    printf("%d", i);
}
"""
        assert deflattener.detect_cff(code) is False
        result = deflattener.analyze_cff(code)
        assert result.detected is False
        assert result.total_blocks == 0

    def test_switch_without_while(self, deflattener):
        """While olmadan switch-case CFF degil."""
        code = """
switch(option) {
    case 1: do_a(); break;
    case 2: do_b(); break;
    case 3: do_c(); break;
}
"""
        assert deflattener.detect_cff(code) is False

    def test_while_without_switch(self, deflattener):
        """Switch olmadan while dongusu CFF degil."""
        code = """
while(true) {
    process();
    if (done) break;
}
"""
        assert deflattener.detect_cff(code) is False

    def test_normal_function_code(self, deflattener):
        """Siradan fonksiyon kodu CFF degil."""
        code = """
int main() {
    int x = calculate();
    if (x > 0) {
        printf("positive");
    } else {
        printf("negative");
    }
    return 0;
}
"""
        result = deflattener.analyze_cff(code)
        assert result.detected is False


# --- Test 6: Bos kod ---

class TestEmptyCode:
    """Bos veya gecersiz girdi."""

    def test_empty_string(self, deflattener):
        """Bos string hata vermemeli."""
        result = deflattener.analyze_cff("")
        assert result.detected is False
        assert result.total_blocks == 0
        assert result.original_order == []

    def test_whitespace_only(self, deflattener):
        """Sadece bosluk karakteri olan string."""
        result = deflattener.analyze_cff("   \n\t  \n  ")
        assert result.detected is False

    def test_none_like_empty(self, deflattener):
        """Cok kisa kod CFF olamaz."""
        result = deflattener.analyze_cff("x = 1;")
        assert result.detected is False


# --- Test 7: JS CFF pattern (while(!0)) ---

class TestJSCFFPattern:
    """JavaScript obfuscation patternleri."""

    def test_js_while_not_zero(self, deflattener, js_cff_code):
        """while(!0) JS pattern tespiti."""
        assert deflattener.detect_cff(js_cff_code) is True

    def test_js_block_count(self, deflattener, js_cff_code):
        """JS CFF'de 3 blok bulunmali."""
        result = deflattener.analyze_cff(js_cff_code)
        assert result.total_blocks == 3

    def test_js_original_order(self, deflattener, js_cff_code):
        """JS CFF sirasi: 0 -> 2 -> 1."""
        result = deflattener.analyze_cff(js_cff_code)
        assert result.original_order == [0, 2, 1]

    def test_js_for_infinite(self, deflattener):
        """for(;;) JS infinite loop pattern."""
        code = """
var s = 0;
for(;;) {
    switch(s) {
        case 0: a(); s = 1; break;
        case 1: b(); return; break;
    }
}
"""
        result = deflattener.analyze_cff(code)
        assert result.detected is True
        assert result.total_blocks == 2


# --- Test 8: Deflattened code dogrulama (blok sirasi) ---

class TestDeflattendCodeOrder:
    """Deflattened kodda bloklarin sirasi dogru olmali."""

    def test_block_order_in_output(self, deflattener, basic_cff_code):
        """Deflattened kodda bloklar topological sirayla gelmeli."""
        result = deflattener.analyze_cff(basic_cff_code)
        code = result.deflattened_code
        # order: 0, 2, 3, 1
        pos_0 = code.index("state 0")
        pos_2 = code.index("state 2")
        pos_3 = code.index("state 3")
        pos_1 = code.index("state 1")
        assert pos_0 < pos_2 < pos_3 < pos_1

    def test_cleaned_code_no_state_assignment(self, deflattener, basic_cff_code):
        """Deflattened kodda state assignment olmamali."""
        result = deflattener.analyze_cff(basic_cff_code)
        code = result.deflattened_code
        # "state = 2" gibi ifadeler temizlenmis olmali
        assert "state = 2" not in code
        assert "state = 3" not in code
        assert "state = 1" not in code

    def test_cleaned_code_no_break(self, deflattener, basic_cff_code):
        """Deflattened kodda break; olmamali."""
        result = deflattener.analyze_cff(basic_cff_code)
        code = result.deflattened_code
        assert "break;" not in code

    def test_original_function_calls_preserved(self, deflattener, basic_cff_code):
        """Orijinal fonksiyon cagrilari korunmali."""
        result = deflattener.analyze_cff(basic_cff_code)
        code = result.deflattened_code
        assert "init()" in code
        assert "process()" in code
        assert "validate()" in code
        assert "cleanup()" in code


# --- Test 9: Multiline case block'lar ---

class TestMultilineCaseBlocks:
    """Birden fazla satir iceren case bloklari."""

    def test_multiline_case_detection(self, deflattener):
        """Multiline case bloklar dogru parse edilmeli."""
        code = """
int state = 0;
while(true) {
    switch(state) {
        case 0:
            x = 10;
            y = 20;
            state = 1;
            break;
        case 1:
            result = x + y;
            state = 2;
            break;
        case 2:
            print(result);
            return;
            break;
    }
}
"""
        result = deflattener.analyze_cff(code)
        assert result.detected is True
        assert result.total_blocks == 3
        assert result.original_order == [0, 1, 2]


# --- Test 10: deflatten_code() entegrasyon testi ---

class TestDeflattenCodeIntegration:
    """deflatten_code() metodu entegrasyon testi."""

    def test_deflatten_replaces_dispatcher(self, deflattener, basic_cff_code):
        """deflatten_code() dispatcher'i deflattened kodla degistirmeli."""
        modified_code, result = deflattener.deflatten_code(basic_cff_code)
        assert result.detected is True
        # Orijinal while-switch kalmamali
        assert "while(true)" not in modified_code
        assert "switch(state)" not in modified_code
        # Deflattened isaret olmali
        assert "DEFLATTENED" in modified_code

    def test_deflatten_non_cff_returns_original(self, deflattener):
        """CFF olmayan kodda orijinal kod degismemeli."""
        original = "int x = 42;\nreturn x;\n"
        modified, result = deflattener.deflatten_code(original)
        assert modified == original
        assert result.detected is False


# --- Test 11: Birden fazla dispatcher ---

class TestMultipleDispatchers:
    """Tek kodda birden fazla CFF dispatcher."""

    def test_two_dispatchers_detected(self, deflattener):
        """Iki farkli CFF dispatcher sayilmali."""
        code = """
int s1 = 0;
while(true) {
    switch(s1) {
        case 0: a(); s1 = 1; break;
        case 1: b(); return; break;
    }
}
int s2 = 0;
while(true) {
    switch(s2) {
        case 0: c(); s2 = 1; break;
        case 1: d(); return; break;
    }
}
"""
        result = deflattener.analyze_cff(code)
        assert result.detected is True
        assert result.total_dispatchers == 2


# --- Test 12: for(;;) JS pattern ---

class TestForInfinitePattern:
    """for(;;) sonsuz dongu pattern'i."""

    def test_for_infinite_detect(self, deflattener):
        """for(;;) { switch... } CFF olarak tespit edilmeli."""
        code = """
var x = 0;
for(;;) {
    switch(x) {
        case 0: start(); x = 1; break;
        case 1: middle(); x = 2; break;
        case 2: end(); return; break;
    }
}
"""
        result = deflattener.analyze_cff(code)
        assert result.detected is True
        assert result.total_blocks == 3
        assert result.original_order == [0, 1, 2]
