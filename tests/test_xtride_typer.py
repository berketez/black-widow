"""XTRIDE N-gram tip cikarimi testleri.

Kategoriler:
    1. API parametre tipleri
    2. Donus tipi atamalari
    3. Operator kaliplari
    4. Dongu kaliplari
    5. Karsilastirma kaliplari
    6. Atama kaliplari
    7. Explicit cast
    8. String literal
    9. Float literal
    10. Mevcut tip birlestirme (merge_with_existing)
    11. Batch inference
    12. Confidence birlestirme (coklu kanit)
    13. Performance (< 1ms/fonksiyon)
"""

from __future__ import annotations

import time

import pytest

from karadul.reconstruction.xtride_typer import (
    CONFIDENCE_API_PARAM,
    CONFIDENCE_ASSIGNMENT,
    CONFIDENCE_COMPARISON,
    CONFIDENCE_LOOP,
    CONFIDENCE_OPERATOR,
    CONFIDENCE_RETURN_TYPE,
    TypeInference,
    XTrideResult,
    XTrideTyper,
)


@pytest.fixture
def typer() -> XTrideTyper:
    return XTrideTyper()


# =====================================================================
# 1. API Parametre Tipleri
# =====================================================================


class TestAPIParamTypes:
    """API cagrisi parametrelerinden tip cikarimi."""

    def test_memcpy_params(self, typer: XTrideTyper) -> None:
        code = """
void FUN_001000(undefined8 param_1, undefined8 param_2, undefined8 param_3) {
    memcpy(param_1, param_2, param_3);
}
"""
        result = typer.infer_types(code, "FUN_001000")
        assert result.inferences["param_1"].inferred_type == "void *"
        assert result.inferences["param_2"].inferred_type == "const void *"
        assert result.inferences["param_3"].inferred_type == "size_t"

    def test_fopen_params(self, typer: XTrideTyper) -> None:
        code = """
undefined8 FUN_002000(undefined8 param_1, undefined8 param_2) {
    fopen(param_1, param_2);
}
"""
        result = typer.infer_types(code, "FUN_002000")
        assert result.inferences["param_1"].inferred_type == "const char *"
        assert result.inferences["param_2"].inferred_type == "const char *"

    def test_read_params(self, typer: XTrideTyper) -> None:
        code = """
void FUN_003000(int param_1, undefined8 param_2, undefined8 param_3) {
    read(param_1, param_2, param_3);
}
"""
        result = typer.infer_types(code, "FUN_003000")
        assert result.inferences["param_1"].inferred_type == "int"
        assert result.inferences["param_2"].inferred_type == "void *"
        assert result.inferences["param_3"].inferred_type == "size_t"

    def test_printf_params(self, typer: XTrideTyper) -> None:
        code = """
void FUN_004000(undefined8 param_1) {
    printf(param_1);
}
"""
        result = typer.infer_types(code, "FUN_004000")
        assert result.inferences["param_1"].inferred_type == "const char *"

    def test_send_params(self, typer: XTrideTyper) -> None:
        code = """
void FUN_005000(int param_1, undefined8 param_2, undefined8 param_3, int param_4) {
    send(param_1, param_2, param_3, param_4);
}
"""
        result = typer.infer_types(code, "FUN_005000")
        assert result.inferences["param_1"].inferred_type == "int"
        assert result.inferences["param_2"].inferred_type == "const void *"
        assert result.inferences["param_3"].inferred_type == "size_t"
        assert result.inferences["param_4"].inferred_type == "int"

    def test_ssl_read_params(self, typer: XTrideTyper) -> None:
        code = """
void FUN_006000(undefined8 param_1, undefined8 param_2, int param_3) {
    SSL_read(param_1, param_2, param_3);
}
"""
        result = typer.infer_types(code, "FUN_006000")
        assert result.inferences["param_1"].inferred_type == "SSL *"
        assert result.inferences["param_2"].inferred_type == "void *"
        assert result.inferences["param_3"].inferred_type == "int"

    def test_sqlite3_exec(self, typer: XTrideTyper) -> None:
        code = """
void FUN_007000(undefined8 param_1, undefined8 param_2) {
    sqlite3_exec(param_1, param_2, 0, 0, 0);
}
"""
        result = typer.infer_types(code, "FUN_007000")
        assert result.inferences["param_1"].inferred_type == "sqlite3 *"
        assert result.inferences["param_2"].inferred_type == "const char *"

    def test_underscore_prefix(self, typer: XTrideTyper) -> None:
        """Mach-O _malloc gibi underscore-prefixed fonksiyonlar."""
        code = """
void FUN_008000(undefined8 param_1) {
    _malloc(param_1);
}
"""
        result = typer.infer_types(code, "FUN_008000")
        assert result.inferences["param_1"].inferred_type == "size_t"

    def test_address_of_param(self, typer: XTrideTyper) -> None:
        """&var ile adresi gecirilen parametreler."""
        code = """
void FUN_009000(undefined8 param_1) {
    pthread_mutex_lock(&param_1);
}
"""
        result = typer.infer_types(code, "FUN_009000")
        # &param_1 passed as pthread_mutex_t * -> param_1 is pthread_mutex_t
        assert "param_1" in result.inferences

    def test_api_confidence(self, typer: XTrideTyper) -> None:
        code = """
void FUN_010000(undefined8 param_1) {
    strlen(param_1);
}
"""
        result = typer.infer_types(code, "FUN_010000")
        assert result.inferences["param_1"].confidence >= CONFIDENCE_API_PARAM
        assert result.inferences["param_1"].source == "api_param"


# =====================================================================
# 2. Donus Tipi Atamalari
# =====================================================================


class TestReturnTypes:
    """var = known_func() donus tipi cikarimi."""

    def test_malloc_return(self, typer: XTrideTyper) -> None:
        code = """
void FUN_020000(void) {
    undefined8 local_10;
    local_10 = malloc(0x100);
}
"""
        result = typer.infer_types(code, "FUN_020000")
        assert result.inferences["local_10"].inferred_type == "void *"

    def test_fopen_return(self, typer: XTrideTyper) -> None:
        code = """
void FUN_021000(void) {
    undefined8 local_10;
    local_10 = fopen("/tmp/test", "r");
}
"""
        result = typer.infer_types(code, "FUN_021000")
        assert result.inferences["local_10"].inferred_type == "FILE *"

    def test_strdup_return(self, typer: XTrideTyper) -> None:
        code = """
void FUN_022000(void) {
    undefined8 local_10;
    local_10 = strdup(param_1);
}
"""
        result = typer.infer_types(code, "FUN_022000")
        assert result.inferences["local_10"].inferred_type == "char *"

    def test_socket_return(self, typer: XTrideTyper) -> None:
        code = """
void FUN_023000(void) {
    undefined4 local_10;
    local_10 = socket(2, 1, 0);
}
"""
        result = typer.infer_types(code, "FUN_023000")
        assert result.inferences["local_10"].inferred_type == "int"

    def test_strlen_return(self, typer: XTrideTyper) -> None:
        code = """
void FUN_024000(undefined8 param_1) {
    undefined8 local_10;
    local_10 = strlen(param_1);
}
"""
        result = typer.infer_types(code, "FUN_024000")
        assert result.inferences["local_10"].inferred_type == "size_t"

    def test_dlopen_return(self, typer: XTrideTyper) -> None:
        code = """
void FUN_025000(void) {
    undefined8 local_10;
    local_10 = dlopen("libtest.so", 1);
}
"""
        result = typer.infer_types(code, "FUN_025000")
        assert result.inferences["local_10"].inferred_type == "void *"

    def test_getenv_return(self, typer: XTrideTyper) -> None:
        code = """
void FUN_026000(void) {
    undefined8 local_10;
    local_10 = getenv("HOME");
}
"""
        result = typer.infer_types(code, "FUN_026000")
        assert result.inferences["local_10"].inferred_type == "char *"


# =====================================================================
# 3. Operator Kaliplari
# =====================================================================


class TestOperatorPatterns:
    """Operator kullanimindan tip cikarimi."""

    def test_increment(self, typer: XTrideTyper) -> None:
        code = """
void FUN_030000(void) {
    undefined4 local_10;
    local_10++;
}
"""
        result = typer.infer_types(code, "FUN_030000")
        assert result.inferences["local_10"].inferred_type == "int"

    def test_pre_increment(self, typer: XTrideTyper) -> None:
        code = """
void FUN_030100(void) {
    undefined4 local_10;
    ++local_10;
}
"""
        result = typer.infer_types(code, "FUN_030100")
        assert result.inferences["local_10"].inferred_type == "int"

    def test_dereference(self, typer: XTrideTyper) -> None:
        code = """
void FUN_031000(undefined8 param_1) {
    undefined8 local_10;
    local_10 = *param_1;
}
"""
        result = typer.infer_types(code, "FUN_031000")
        assert result.inferences["param_1"].inferred_type == "void *"

    def test_arrow_operator(self, typer: XTrideTyper) -> None:
        code = """
void FUN_032000(undefined8 param_1) {
    param_1->field = 42;
}
"""
        result = typer.infer_types(code, "FUN_032000")
        assert result.inferences["param_1"].inferred_type == "void *"

    def test_array_access(self, typer: XTrideTyper) -> None:
        code = """
void FUN_033000(undefined8 param_1) {
    local_10 = param_1[0];
}
"""
        result = typer.infer_types(code, "FUN_033000")
        assert result.inferences["param_1"].inferred_type == "void *"

    def test_bitwise_mask_byte(self, typer: XTrideTyper) -> None:
        code = """
void FUN_034000(undefined4 param_1) {
    local_10 = param_1 & 0xFF;
}
"""
        result = typer.infer_types(code, "FUN_034000")
        assert result.inferences["param_1"].inferred_type == "uint8_t"

    def test_bitwise_mask_word(self, typer: XTrideTyper) -> None:
        code = """
void FUN_034100(undefined4 param_1) {
    local_10 = param_1 & 0xFFFF;
}
"""
        result = typer.infer_types(code, "FUN_034100")
        assert result.inferences["param_1"].inferred_type == "uint16_t"

    def test_bitwise_mask_dword(self, typer: XTrideTyper) -> None:
        code = """
void FUN_034200(undefined8 param_1) {
    local_10 = param_1 & 0xFFFFFFFF;
}
"""
        result = typer.infer_types(code, "FUN_034200")
        assert result.inferences["param_1"].inferred_type == "uint32_t"

    def test_shift_left(self, typer: XTrideTyper) -> None:
        code = """
void FUN_035000(undefined4 param_1) {
    local_10 = param_1 << 8;
}
"""
        result = typer.infer_types(code, "FUN_035000")
        assert "uint" in result.inferences["param_1"].inferred_type


# =====================================================================
# 4. Dongu Kaliplari
# =====================================================================


class TestLoopPatterns:
    """Dongu pattern'lerinden tip cikarimi."""

    def test_for_loop_basic(self, typer: XTrideTyper) -> None:
        code = """
void FUN_040000(undefined8 param_1) {
    for (local_10 = 0; local_10 < param_1; local_10++) {
        // body
    }
}
"""
        result = typer.infer_types(code, "FUN_040000")
        assert result.inferences["local_10"].inferred_type == "int"
        assert result.inferences["param_1"].inferred_type == "size_t"

    def test_while_string_iteration(self, typer: XTrideTyper) -> None:
        code = """
void FUN_041000(undefined8 param_1) {
    while (*param_1) {
        param_1++;
    }
}
"""
        result = typer.infer_types(code, "FUN_041000")
        assert result.inferences["param_1"].inferred_type in ("char *", "int")

    def test_while_not_null(self, typer: XTrideTyper) -> None:
        code = """
void FUN_042000(undefined8 param_1) {
    while (param_1 != NULL) {
        param_1 = *(param_1 + 8);
    }
}
"""
        result = typer.infer_types(code, "FUN_042000")
        assert result.inferences["param_1"].inferred_type == "void *"


# =====================================================================
# 5. Karsilastirma Kaliplari
# =====================================================================


class TestComparisonPatterns:
    """Karsilastirma pattern'lerinden tip cikarimi."""

    def test_null_comparison(self, typer: XTrideTyper) -> None:
        code = """
void FUN_050000(undefined8 param_1) {
    if (param_1 == NULL) {
        return;
    }
}
"""
        result = typer.infer_types(code, "FUN_050000")
        assert result.inferences["param_1"].inferred_type == "void *"

    def test_not_null(self, typer: XTrideTyper) -> None:
        code = """
void FUN_051000(undefined8 param_1) {
    if (param_1 != NULL) {
        // use
    }
}
"""
        result = typer.infer_types(code, "FUN_051000")
        assert result.inferences["param_1"].inferred_type == "void *"

    def test_char_comparison(self, typer: XTrideTyper) -> None:
        code = """
void FUN_052000(undefined param_1) {
    if (param_1 == '\\0') {
        return;
    }
}
"""
        result = typer.infer_types(code, "FUN_052000")
        assert result.inferences["param_1"].inferred_type == "char"

    def test_negative_comparison(self, typer: XTrideTyper) -> None:
        code = """
void FUN_053000(undefined4 param_1) {
    if (param_1 < 0) {
        return;
    }
}
"""
        result = typer.infer_types(code, "FUN_053000")
        assert result.inferences["param_1"].inferred_type == "int"


# =====================================================================
# 6. Atama Kaliplari
# =====================================================================


class TestAssignmentPatterns:
    """Atama pattern'lerinden tip cikarimi."""

    def test_malloc_assign(self, typer: XTrideTyper) -> None:
        code = """
void FUN_060000(void) {
    undefined8 local_10;
    local_10 = malloc(100);
}
"""
        result = typer.infer_types(code, "FUN_060000")
        assert result.inferences["local_10"].inferred_type == "void *"

    def test_fopen_assign(self, typer: XTrideTyper) -> None:
        code = """
void FUN_061000(void) {
    undefined8 local_10;
    local_10 = fopen("test.txt", "w");
}
"""
        result = typer.infer_types(code, "FUN_061000")
        assert result.inferences["local_10"].inferred_type == "FILE *"

    def test_socket_assign(self, typer: XTrideTyper) -> None:
        code = """
void FUN_062000(void) {
    undefined4 local_10;
    local_10 = socket(2, 1, 0);
}
"""
        result = typer.infer_types(code, "FUN_062000")
        assert result.inferences["local_10"].inferred_type == "int"

    def test_cast_malloc_assign(self, typer: XTrideTyper) -> None:
        code = """
void FUN_063000(void) {
    undefined8 local_10;
    local_10 = (char *)malloc(100);
}
"""
        result = typer.infer_types(code, "FUN_063000")
        # malloc assign + cast + return_type hepsi etki eder
        assert "local_10" in result.inferences

    def test_opendir_assign(self, typer: XTrideTyper) -> None:
        code = """
void FUN_064000(void) {
    undefined8 local_10;
    local_10 = opendir("/tmp");
}
"""
        result = typer.infer_types(code, "FUN_064000")
        assert result.inferences["local_10"].inferred_type == "DIR *"

    def test_popen_assign(self, typer: XTrideTyper) -> None:
        code = """
void FUN_065000(void) {
    undefined8 local_10;
    local_10 = popen("ls", "r");
}
"""
        result = typer.infer_types(code, "FUN_065000")
        assert result.inferences["local_10"].inferred_type == "FILE *"


# =====================================================================
# 7. Explicit Cast
# =====================================================================


class TestExplicitCast:
    """Explicit cast pattern'lerinden tip cikarimi."""

    def test_cast_to_int(self, typer: XTrideTyper) -> None:
        code = """
void FUN_070000(void) {
    undefined8 local_10;
    local_10 = (int)local_20;
}
"""
        result = typer.infer_types(code, "FUN_070000")
        assert result.inferences["local_10"].inferred_type == "int"

    def test_cast_deref_base(self, typer: XTrideTyper) -> None:
        code = """
void FUN_071000(undefined8 param_1) {
    local_10 = *(long *)(param_1 + 0x10);
}
"""
        result = typer.infer_types(code, "FUN_071000")
        assert result.inferences["param_1"].inferred_type == "void *"


# =====================================================================
# 8. String Literal
# =====================================================================


class TestStringLiteral:
    """String literal atamasindan tip cikarimi."""

    def test_string_assign(self, typer: XTrideTyper) -> None:
        code = """
void FUN_080000(void) {
    undefined8 local_10;
    local_10 = "hello world";
}
"""
        result = typer.infer_types(code, "FUN_080000")
        assert result.inferences["local_10"].inferred_type == "char *"


# =====================================================================
# 9. Float Literal
# =====================================================================


class TestFloatLiteral:
    """Float literal atamasindan tip cikarimi."""

    def test_double_literal(self, typer: XTrideTyper) -> None:
        code = """
void FUN_090000(void) {
    undefined8 local_10;
    local_10 = 3.14159;
}
"""
        result = typer.infer_types(code, "FUN_090000")
        assert result.inferences["local_10"].inferred_type == "double"


# =====================================================================
# 10. Mevcut Tip Birlestirme
# =====================================================================


class TestMergeWithExisting:
    """XTRIDE sonuclarini mevcut tiplerle birlestirme."""

    def test_override_undefined(self, typer: XTrideTyper) -> None:
        code = """
void FUN_100000(undefined8 param_1) {
    strlen(param_1);
}
"""
        result = typer.infer_types(code, "FUN_100000")
        existing = {"param_1": "undefined8"}
        merged = typer.merge_with_existing(result, existing)
        assert merged["param_1"] == "const char *"

    def test_override_long(self, typer: XTrideTyper) -> None:
        code = """
void FUN_101000(long param_1) {
    memcpy(param_1, param_2, param_3);
}
"""
        result = typer.infer_types(code, "FUN_101000")
        existing = {"param_1": "long"}
        merged = typer.merge_with_existing(result, existing)
        assert merged["param_1"] == "void *"

    def test_keep_specific(self, typer: XTrideTyper) -> None:
        """Spesifik tip (FILE *) XTRIDE tarafindan override edilmemeli."""
        code = """
void FUN_102000(FILE *param_1) {
    fclose(param_1);
}
"""
        result = typer.infer_types(code, "FUN_102000")
        existing = {"param_1": "FILE *"}
        merged = typer.merge_with_existing(result, existing)
        assert merged["param_1"] == "FILE *"

    def test_add_new(self, typer: XTrideTyper) -> None:
        """Mevcut olmayan degiskenler icin XTRIDE tahmini eklenmeli."""
        code = """
void FUN_103000(void) {
    undefined8 local_10;
    local_10 = malloc(100);
}
"""
        result = typer.infer_types(code, "FUN_103000")
        existing = {}
        merged = typer.merge_with_existing(result, existing)
        assert "local_10" in merged
        assert merged["local_10"] == "void *"


# =====================================================================
# 11. Batch Inference
# =====================================================================


class TestBatchInference:
    """Batch tip cikarimi."""

    def test_batch(self, typer: XTrideTyper) -> None:
        funcs = {
            "func_a": "void func_a(undefined8 param_1) { strlen(param_1); }",
            "func_b": "void func_b(undefined8 param_1) { free(param_1); }",
        }
        results = typer.infer_types_batch(funcs)
        assert "func_a" in results
        assert "func_b" in results
        assert results["func_a"].inferences["param_1"].inferred_type == "const char *"
        assert results["func_b"].inferences["param_1"].inferred_type == "void *"


# =====================================================================
# 12. Confidence Birlestirme
# =====================================================================


class TestConfidenceMerging:
    """Coklu kanit birlestirme."""

    def test_multiple_evidence_boosts(self, typer: XTrideTyper) -> None:
        """Ayni degisken icin birden fazla kanit -> confidence artisi."""
        code = """
void FUN_120000(undefined8 param_1) {
    strlen(param_1);
    printf(param_1);
    strcmp(param_1, "test");
}
"""
        result = typer.infer_types(code, "FUN_120000")
        inf = result.inferences["param_1"]
        # 3 API cagrisi -> base 0.85 + 2 * 0.05 = 0.95
        assert inf.confidence > CONFIDENCE_API_PARAM

    def test_conflicting_types_highest_wins(self, typer: XTrideTyper) -> None:
        """Farkli tipler tahmin edildiginde en yuksek confidence kazanir."""
        code = """
void FUN_121000(undefined8 param_1) {
    param_1++;
    if (param_1 == NULL) { return; }
}
"""
        result = typer.infer_types(code, "FUN_121000")
        # Her iki tahmin de var ama birisi kazanir
        assert "param_1" in result.inferences


# =====================================================================
# 13. Non-generic degiskenler atlanmali
# =====================================================================


class TestNonGenericSkip:
    """Non-generic degiskenler icin tahmin yapilmamali."""

    def test_skip_named_variable(self, typer: XTrideTyper) -> None:
        code = """
void FUN_130000(void) {
    counter++;
}
"""
        result = typer.infer_types(code, "FUN_130000")
        assert "counter" not in result.inferences

    def test_skip_function_name(self, typer: XTrideTyper) -> None:
        code = """
void process_data(undefined8 param_1) {
    strlen(param_1);
}
"""
        result = typer.infer_types(code, "process_data")
        # "process_data" gibi isimlendirilmis fonksiyon adlari atlanmali
        assert "process_data" not in result.inferences
        # Ama param_1 tahmin edilmeli
        assert "param_1" in result.inferences


# =====================================================================
# 14. Performance
# =====================================================================


_BODY_BLOCK = """\
    undefined8 local_{a:x};
    undefined8 local_{b:x};
    undefined4 local_{c:x};

    local_{a:x} = malloc(0x100);
    if (local_{a:x} == NULL) {{
        return;
    }}
    memcpy(local_{a:x}, param_1, param_2);
    local_{b:x} = strlen(local_{a:x});
    for (local_{c:x} = 0; local_{c:x} < local_{b:x}; local_{c:x}++) {{
        if (local_{a:x}[local_{c:x}] == '\\0') {{
            break;
        }}
    }}
    free(local_{a:x});
    fclose(param_3);
"""


def _function_code(blocks: int) -> str:
    """Gövdesi ``blocks`` kez yinelenen Ghidra çıktısı; her blok kendi yerel değişkenleriyle.

    ``blocks=1`` bu sınıfın eski tek fonksiyon örneğidir (local_10 / local_18 / local_20).
    """
    body = "".join(
        _BODY_BLOCK.format(a=0x10 + 0x20 * i, b=0x18 + 0x20 * i, c=0x20 + 0x20 * i)
        for i in range(blocks)
    )
    return (
        "\nvoid FUN_140000(undefined8 param_1, undefined8 param_2, undefined8 param_3) {\n"
        + body + "}\n"
    )


def _best_infer_seconds(
    typer: XTrideTyper, cases: list[tuple[str, int]], rounds: int = 7,
) -> list[float]:
    """Her (kod, çağrı sayısı) çifti için ``infer_types``'ın çağrı başına en kısa CPU süresi.

    Saat ``time.process_time``: yalnız bu sürecin işlemci süresi (tek iş parçacıklı saf
    hesap ölçülüyor; duvar saati başka süreçler araya girdikçe uzar). Her turda bir çift art
    arda ``çağrı sayısı`` kez çağrılır; en kısa tur alınır, turlar çiftleri sırayla dolaşır.
    """
    best = [float("inf")] * len(cases)
    for _ in range(rounds):
        for i, (code, calls) in enumerate(cases):
            start = time.process_time()
            for _ in range(calls):
                typer.infer_types(code, "FUN_140000")
            best[i] = min(best[i], (time.process_time() - start) / calls)
    return best


class TestPerformance:
    """Performans testleri.

    ``test_performance_batch_100`` modülün mutlak hedefini (< 1 ms / fonksiyon) küçük
    fonksiyonlarda sınar. ``test_cost_linear_in_function_length`` eskiden 20 satırlık tek
    fonksiyonda aynı mutlak hedefi sınıyordu (``test_performance_single``); o ölçüm kodu
    değil makineyi ölçüyordu: geliştirme makinesinde 0,52 - 0,58 ms, GitHub koşucularında
    1,18 - 1,31 ms (koşu 42830613886; koşucu 2,1 - 2,5 kat yavaş, gürültü değil). Maliyet
    gövde uzunluğuyla doğrusal (~1 µs / karakter), yani "< 1 ms" o makinede ancak ~40
    satıra kadar tutar. Makineden bağımsız iddia doğrusallıktır; test onu sınar.
    """

    SHORT_BLOCKS = 1
    LONG_BLOCKS = 8
    # Gövde 8 katına çıkınca süre: doğrusal 8, karesel 64. Eşik ikisinin geometrik ortası.
    LIMIT = (LONG_BLOCKS * LONG_BLOCKS ** 2) ** 0.5     # 22,6

    def test_cost_linear_in_function_length(self, typer: XTrideTyper) -> None:
        """Gövde 8 kat uzayınca çağrı süresi ~8 kat artar (karesel değil).

        Ölçüm (2026-11-10; Apple Silicon, CPython 3.12.7; 10 bağımsız ölçüm): oran 6,3 - 6,6
        (çekirdek sayısının 1,5 katı meşgul süreç varken en çok 6,7); 1 blok ~0,5 ms, 8 blok
        ~3,2 ms; 64 blokta 53 kat (doğrusal 64).

        Yakalanan (bellek içi mutantla denendi): satır çiftlerini karşılaştıran karesel ek iş
        (oran 37,9). Yakalanmayan: sabit çarpanlı yavaşlama ve 8 blokta doğrusal terimin
        ~2,5 katından küçük kalan karesel terim.
        """
        short_code = _function_code(self.SHORT_BLOCKS)
        long_code = _function_code(self.LONG_BLOCKS)

        # İki girdi de gerçekten işleniyor: her bloğun malloc sonucu tiplenir
        short_result = typer.infer_types(short_code, "FUN_140000")
        long_result = typer.infer_types(long_code, "FUN_140000")
        assert "local_10" in short_result.inferences
        assert len(long_result.inferences) > len(short_result.inferences)

        # Tur başına ~20 ms: kısa kod 40, uzun kod 5 çağrı (ısınma yukarıdaki iki çağrı)
        t_short, t_long = _best_infer_seconds(typer, [(short_code, 40), (long_code, 5)])

        ratio = t_long / t_short
        assert ratio < self.LIMIT, (
            f"infer_types gövde uzunluğunda doğrusal değil: {self.SHORT_BLOCKS} blok "
            f"{t_short * 1000:.3f} ms, {self.LONG_BLOCKS} blok {t_long * 1000:.3f} ms, "
            f"oran {ratio:.1f} (doğrusal {self.LONG_BLOCKS}, "
            f"karesel {self.LONG_BLOCKS ** 2}, eşik {self.LIMIT:.1f})"
        )

    def test_performance_batch_100(self, typer: XTrideTyper) -> None:
        """100 fonksiyon batch < 100ms."""
        funcs = {}
        for i in range(100):
            funcs[f"FUN_{i:06x}"] = f"""
void FUN_{i:06x}(undefined8 param_1) {{
    undefined8 local_10;
    local_10 = malloc(param_1);
    if (local_10 == NULL) {{ return; }}
    memset(local_10, 0, param_1);
    free(local_10);
}}
"""
        start = time.perf_counter()
        results = typer.infer_types_batch(funcs)
        elapsed = time.perf_counter() - start
        assert elapsed < 0.1, f"Batch performance: {elapsed * 1000:.1f}ms > 100ms"
        assert len(results) == 100


# =====================================================================
# 15. Edge Cases
# =====================================================================


class TestEdgeCases:
    """Edge case testleri."""

    def test_empty_code(self, typer: XTrideTyper) -> None:
        result = typer.infer_types("", "empty")
        assert result.total_inferred == 0

    def test_no_generic_vars(self, typer: XTrideTyper) -> None:
        code = """
void process(int count, char *name) {
    printf(name);
}
"""
        result = typer.infer_types(code, "process")
        # count ve name generic degil -> atlanir
        assert "count" not in result.inferences
        assert "name" not in result.inferences

    def test_nested_calls(self, typer: XTrideTyper) -> None:
        """Nested cagriler -- strchr ic cagrisi ayri satirda infer edilir."""
        code = """
void FUN_150000(undefined8 param_1) {
    undefined8 local_10;
    local_10 = strchr(param_1, '/');
    strlen(local_10);
}
"""
        result = typer.infer_types(code, "FUN_150000")
        assert "param_1" in result.inferences
        assert result.inferences["param_1"].inferred_type == "const char *"

    def test_multiple_functions_in_code(self, typer: XTrideTyper) -> None:
        """Birden fazla fonksiyon taniminda ilki islenmeli."""
        code = """
void FUN_160000(undefined8 param_1) {
    memcpy(param_1, param_2, 10);
}
void FUN_160001(undefined8 param_1) {
    free(param_1);
}
"""
        result = typer.infer_types(code, "FUN_160000")
        assert "param_1" in result.inferences

    def test_pattern_count(self, typer: XTrideTyper) -> None:
        """Pattern sayisi > 200 olmali."""
        assert typer.pattern_count >= 200

    def test_stats_tracking(self, typer: XTrideTyper) -> None:
        code = """
void FUN_170000(undefined8 param_1, undefined8 param_2) {
    memcpy(param_1, param_2, 10);
    param_1++;
}
"""
        typer.infer_types(code, "FUN_170000")
        assert typer.stats["total_functions"] >= 1
        assert typer.stats["total_inferences"] >= 1
        assert typer.stats["api_param_inferences"] >= 1


# =====================================================================
# 16. Gercekci Fonksiyon Testleri
# =====================================================================


class TestRealisticFunctions:
    """Gercekci decompiled fonksiyon ornekleri."""

    def test_network_server(self, typer: XTrideTyper) -> None:
        code = """
int FUN_200000(undefined4 param_1)
{
    int iVar1;
    undefined8 local_28;
    undefined4 local_1c;
    undefined4 local_18;

    local_18 = sizeof(local_28);
    iVar1 = accept(param_1, &local_28, &local_18);
    if (iVar1 < 0) {
        perror("accept failed");
        return -1;
    }
    local_1c = recv(iVar1, local_38, 0x400, 0);
    if (local_1c < 0) {
        close(iVar1);
        return -1;
    }
    send(iVar1, "HTTP/1.1 200 OK", 0x10, 0);
    close(iVar1);
    return 0;
}
"""
        result = typer.infer_types(code, "FUN_200000")
        # param_1 = accept'in sockfd parametresi -> int
        assert result.inferences["param_1"].inferred_type == "int"
        # iVar1 = accept donusu -> int
        assert result.inferences["iVar1"].inferred_type == "int"

    def test_file_processor(self, typer: XTrideTyper) -> None:
        code = """
void FUN_201000(undefined8 param_1)
{
    undefined8 local_20;
    undefined8 local_18;
    undefined4 local_c;

    local_20 = fopen(param_1, "rb");
    if (local_20 == NULL) {
        fprintf(stderr, "Cannot open %s\\n", param_1);
        return;
    }
    local_18 = malloc(0x1000);
    if (local_18 == NULL) {
        fclose(local_20);
        return;
    }
    local_c = fread(local_18, 1, 0x1000, local_20);
    printf("Read %d bytes\\n", local_c);
    free(local_18);
    fclose(local_20);
}
"""
        result = typer.infer_types(code, "FUN_201000")
        assert result.inferences["param_1"].inferred_type == "const char *"
        assert result.inferences["local_20"].inferred_type == "FILE *"
        assert result.inferences["local_18"].inferred_type == "void *"

    def test_crypto_function(self, typer: XTrideTyper) -> None:
        code = """
void FUN_202000(undefined8 param_1, undefined8 param_2, undefined4 param_3)
{
    undefined8 local_18;
    undefined8 local_10;

    local_18 = EVP_CIPHER_CTX_new();
    local_10 = EVP_aes_256_cbc();
    EVP_EncryptInit_ex(local_18, local_10, 0, param_1, param_2);
    EVP_CIPHER_CTX_free(local_18);
}
"""
        result = typer.infer_types(code, "FUN_202000")
        assert result.inferences["local_18"].inferred_type == "EVP_CIPHER_CTX *"
        assert result.inferences["param_1"].inferred_type == "const unsigned char *"
        assert result.inferences["param_2"].inferred_type == "const unsigned char *"
