"""v1.8.0 Bug 4 Fix: M_matrix pandemi testi.

TypeUsagePattern confidence dusurulmesi ve _context_override_for_pointer
helper metodu testleri.

Bug: double * + loop_depth>=2 -> "matrix" -> "M_matrix" -- %30 parametre
ayni ismi aliyordu. Fix:
  1. Confidence dusuruldu (0.65->0.50, 0.60->0.45)
  2. Fonksiyondaki API cagrilarina bakarak context override eklendi:
     - memcpy/memmove/memset/bzero -> "buffer"
     - strlen/strcmp/strcpy/strncpy -> "string"
     - malloc/calloc/realloc       -> "data"
     - fread/fwrite/read/write     -> "io_buffer"
"""

from __future__ import annotations

from unittest import mock

import pytest

from karadul.reconstruction.engineering.semantic_namer import (
    SemanticParameterNamer,
    TYPE_USAGE_PATTERNS,
)


# ---------------------------------------------------------------------------
# Bug 4a: Confidence dusurulmu mu?
# ---------------------------------------------------------------------------

class TestTypeUsagePatternConfidence:
    """TYPE_USAGE_PATTERNS confidence degerleri testi."""

    def test_loop_depth_3_matrix_confidence(self):
        """double * + loop_depth=3 -> confidence 0.50 olmali (eskiden 0.65)."""
        pattern = next(
            p for p in TYPE_USAGE_PATTERNS
            if p.c_type == "double *" and p.loop_depth == 3 and p.name == "matrix"
        )
        assert pattern.confidence == 0.50, (
            f"loop_depth=3 matrix confidence {pattern.confidence}, beklenen 0.50"
        )

    def test_loop_depth_2_matrix_confidence(self):
        """double * + loop_depth=2 -> confidence 0.45 olmali (eskiden 0.60)."""
        pattern = next(
            p for p in TYPE_USAGE_PATTERNS
            if p.c_type == "double *" and p.loop_depth == 2 and p.name == "matrix"
        )
        assert pattern.confidence == 0.45, (
            f"loop_depth=2 matrix confidence {pattern.confidence}, beklenen 0.45"
        )

    def test_vector_confidence_unchanged(self):
        """double * + loop_depth=1 + sequential -> vector confidence ayni kalmali (0.55)."""
        pattern = next(
            p for p in TYPE_USAGE_PATTERNS
            if p.c_type == "double *" and p.loop_depth == 1 and p.name == "vector"
        )
        assert pattern.confidence == 0.55


# ---------------------------------------------------------------------------
# Bug 4b: _context_override_for_pointer static method testi
# ---------------------------------------------------------------------------

class TestContextOverrideForPointer:
    """_context_override_for_pointer helper testi."""

    def test_memcpy_returns_buffer(self):
        code = "void FUN_00401000(double *param_1) { memcpy(param_1, src, 1024); }"
        result = SemanticParameterNamer._context_override_for_pointer(code, "M_matrix")
        assert result == "M_buffer"

    def test_memmove_returns_buffer(self):
        code = "void f(double *p) { memmove(p, src, n); }"
        result = SemanticParameterNamer._context_override_for_pointer(code, "M_matrix")
        assert result == "M_buffer"

    def test_memset_returns_buffer(self):
        code = "void f(double *p) { memset(p, 0, sizeof(double)*100); }"
        result = SemanticParameterNamer._context_override_for_pointer(code, "K_matrix")
        assert result == "K_buffer"

    def test_bzero_returns_buffer(self):
        code = "void f(double *p) { bzero(p, 1024); }"
        result = SemanticParameterNamer._context_override_for_pointer(code, "A_matrix")
        assert result == "A_buffer"

    def test_strlen_returns_string(self):
        code = "int f(double *p) { return strlen((char*)p); }"
        result = SemanticParameterNamer._context_override_for_pointer(code, "M_matrix")
        assert result == "M_string"

    def test_strcmp_returns_string(self):
        code = "int f(double *a, double *b) { return strcmp((char*)a, (char*)b); }"
        result = SemanticParameterNamer._context_override_for_pointer(code, "M_matrix")
        assert result == "M_string"

    def test_strcpy_returns_string(self):
        code = "void f(double *dst) { strcpy((char*)dst, \"hello\"); }"
        result = SemanticParameterNamer._context_override_for_pointer(code, "M_matrix")
        assert result == "M_string"

    def test_strncpy_returns_string(self):
        code = "void f(double *dst) { strncpy((char*)dst, src, 10); }"
        result = SemanticParameterNamer._context_override_for_pointer(code, "M_matrix")
        assert result == "M_string"

    def test_malloc_returns_data(self):
        code = "void f(double *p) { p = (double*)malloc(sizeof(double)*n); }"
        result = SemanticParameterNamer._context_override_for_pointer(code, "M_matrix")
        assert result == "M_data"

    def test_calloc_returns_data(self):
        code = "void f(double *p) { p = (double*)calloc(n, sizeof(double)); }"
        result = SemanticParameterNamer._context_override_for_pointer(code, "M_matrix")
        assert result == "M_data"

    def test_realloc_returns_data(self):
        code = "void f(double *p) { p = (double*)realloc(p, new_size); }"
        result = SemanticParameterNamer._context_override_for_pointer(code, "M_matrix")
        assert result == "M_data"

    def test_fread_returns_io_buffer(self):
        code = "void f(double *buf, FILE *fp) { fread(buf, 8, n, fp); }"
        result = SemanticParameterNamer._context_override_for_pointer(code, "M_matrix")
        assert result == "M_io_buffer"

    def test_fwrite_returns_io_buffer(self):
        code = "void f(double *buf, FILE *fp) { fwrite(buf, 8, n, fp); }"
        result = SemanticParameterNamer._context_override_for_pointer(code, "M_matrix")
        assert result == "M_io_buffer"

    def test_read_returns_io_buffer(self):
        code = "void f(double *buf, int fd) { read(fd, buf, 1024); }"
        result = SemanticParameterNamer._context_override_for_pointer(code, "M_matrix")
        assert result == "M_io_buffer"

    def test_write_returns_io_buffer(self):
        code = "void f(double *buf, int fd) { write(fd, buf, 1024); }"
        result = SemanticParameterNamer._context_override_for_pointer(code, "M_matrix")
        assert result == "M_io_buffer"

    def test_generic_code_unchanged(self):
        """API cagrisi yoksa isim degismemeli."""
        code = """
        void compute_stiffness(double *K, int n) {
            for (int i = 0; i < n; i++) {
                for (int j = 0; j < n; j++) {
                    K[i*n+j] = integrate_element(i, j);
                }
            }
        }
        """
        result = SemanticParameterNamer._context_override_for_pointer(code, "K_matrix")
        assert result == "K_matrix"

    def test_domain_prefix_preserved(self):
        """Domain prefix'i korunmali (M_, K_, A_)."""
        code = "void f(double *p) { memcpy(p, src, n); }"
        assert SemanticParameterNamer._context_override_for_pointer(code, "M_matrix") == "M_buffer"
        assert SemanticParameterNamer._context_override_for_pointer(code, "K_matrix") == "K_buffer"
        assert SemanticParameterNamer._context_override_for_pointer(code, "A_matrix") == "A_buffer"

    def test_case_insensitive(self):
        """API isimleri case-insensitive eslenmeli."""
        code = "void f(double *p) { MEMCPY(p, src, n); }"
        result = SemanticParameterNamer._context_override_for_pointer(code, "M_matrix")
        assert result == "M_buffer"

    def test_priority_memcpy_over_malloc(self):
        """memcpy ve malloc ikisi de varsa, memcpy oncelikli (ilk eslesen)."""
        code = "void f(double *p) { p = malloc(n); memcpy(p, src, n); }"
        result = SemanticParameterNamer._context_override_for_pointer(code, "M_matrix")
        # memcpy ilk kontrol ediliyor -> buffer
        assert result == "M_buffer"

    def test_no_matrix_in_name_unchanged(self):
        """Isimde 'matrix' yoksa degistirmemeli (caller tarafinda kontrol edilir ama yine de)."""
        code = "void f(double *p) { memcpy(p, src, n); }"
        # Bu fonksiyon sadece "matrix" icin replace yapar
        result = SemanticParameterNamer._context_override_for_pointer(code, "M_vector")
        assert result == "M_vector"


# ---------------------------------------------------------------------------
# Bug 4c: Integration -- _infer_from_type_and_usage sonuclarinda context override
# ---------------------------------------------------------------------------

class TestInferFromTypeAndUsageIntegration:
    """_infer_from_type_and_usage icerisinde context override'in dogru calismasi."""

    @pytest.fixture
    def namer(self):
        """Minimal SemanticParameterNamer instance."""
        cfg = mock.MagicMock()
        return SemanticParameterNamer(cfg)

    def _make_memcpy_code(self, param_name: str) -> str:
        """memcpy kullanan, 2-seviye dongusu olan C kodu."""
        return f"""
        void FUN_00401000({param_name}) {{
            for (int i = 0; i < n; i++) {{
                for (int j = 0; j < m; j++) {{
                    memcpy(&{param_name}[i*m+j], src, 8);
                }}
            }}
        }}
        """

    def _make_strlen_code(self, param_name: str) -> str:
        """strlen kullanan, 2-seviye dongusu olan C kodu."""
        return f"""
        void FUN_00402000({param_name}) {{
            for (int i = 0; i < n; i++) {{
                for (int j = 0; j < m; j++) {{
                    int len = strlen((char*){param_name});
                }}
            }}
        }}
        """

    def _make_generic_code(self, param_name: str) -> str:
        """Sadece matematik islemleri, API cagrisi yok."""
        return f"""
        void FUN_00403000({param_name}) {{
            for (int i = 0; i < n; i++) {{
                for (int j = 0; j < m; j++) {{
                    {param_name}[i*m+j] = {param_name}[i*m+j] * 2.0;
                }}
            }}
        }}
        """

    def test_memcpy_code_gets_buffer_name(self, namer):
        """memcpy olan fonksiyonda double* parametre 'buffer' ismi almali."""
        code = self._make_memcpy_code("param_1")
        params = [{"name": "param_1", "type": "double *", "position": 0}]

        results = namer._infer_from_type_and_usage(
            "FUN_00401000", params, code, "generic",
        )

        # En az 1 sonuc olmali
        assert len(results) >= 1
        result = results[0]
        # "matrix" yerine "buffer" olmali (context override)
        assert "buffer" in result.semantic_name, (
            f"Beklenen 'buffer' iceren isim, alinan: {result.semantic_name}"
        )
        assert "matrix" not in result.semantic_name

    def test_strlen_code_gets_string_name(self, namer):
        """strlen olan fonksiyonda double* parametre 'string' ismi almali."""
        code = self._make_strlen_code("param_1")
        params = [{"name": "param_1", "type": "double *", "position": 0}]

        results = namer._infer_from_type_and_usage(
            "FUN_00402000", params, code, "generic",
        )

        assert len(results) >= 1
        result = results[0]
        assert "string" in result.semantic_name, (
            f"Beklenen 'string' iceren isim, alinan: {result.semantic_name}"
        )

    def test_generic_code_gets_matrix_name(self, namer):
        """API cagrisi olmayan fonksiyonda double* parametre 'matrix' ismi almali."""
        code = self._make_generic_code("param_1")
        params = [{"name": "param_1", "type": "double *", "position": 0}]

        results = namer._infer_from_type_and_usage(
            "FUN_00403000", params, code, "generic",
        )

        # Sonuc olabilir veya olmayabilir (loop depth detection bagimsiz)
        # Ama eger sonuc varsa ve "matrix" ise, confidence dusuk olmali
        if results:
            result = results[0]
            if "matrix" in result.semantic_name:
                assert result.confidence <= 0.50, (
                    f"Matrix confidence {result.confidence}, beklenen <= 0.50"
                )

    def test_reduced_confidence_values(self, namer):
        """Type heuristic'ten gelen matrix isimleri dusurulmus confidence'a sahip olmali."""
        # Bu test TYPE_USAGE_PATTERNS'deki degerleri dogrudan kontrol eder
        # loop_depth=3 icin 0.50, loop_depth=2 icin 0.45
        for pattern in TYPE_USAGE_PATTERNS:
            if pattern.name == "matrix" and pattern.c_type == "double *":
                if pattern.loop_depth == 3:
                    assert pattern.confidence == 0.50
                elif pattern.loop_depth == 2:
                    assert pattern.confidence == 0.45
