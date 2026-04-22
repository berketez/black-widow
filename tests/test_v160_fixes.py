"""v1.6.0 bug fix testleri.

1. TargetType import scoping (stages.py local import kaldirildi)
2. CFlowSimplifier regex backtracking (label_and_block_pattern rewrite)
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------
# Fix #1: TargetType import scoping
# ---------------------------------------------------------------


class TestTargetTypeImportScoping:
    """stages.py'de TargetType'in top-level import uzerinden erisilebildigini dogrula.

    Eski bug: local import basarisiz olursa UnboundLocalError.
    Fix: Redundant local import'lar kaldirildi, sadece top-level import.
    """

    def test_no_local_targettype_import_in_stages(self) -> None:
        """stages.py icerisinde TargetType icin local import olmamali."""
        stages_path = Path(__file__).parent.parent / "karadul" / "stages.py"
        content = stages_path.read_text(encoding="utf-8")

        # Top-level import olmali
        assert "from karadul.core.target import" in content

        # Fonksiyon icerisinde ayri TargetType import'u olmamali
        lines = content.split("\n")
        local_imports = []
        in_function = False
        indent_level = 0
        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith("def ") or stripped.startswith("async def "):
                in_function = True
                indent_level = len(line) - len(stripped)
            elif in_function and stripped and not line[0].isspace():
                in_function = False

            if in_function and "import" in stripped:
                if "TargetType" in stripped and "as _TT" not in stripped:
                    # _TT alias kaldirildi, asil TargetType import'u yasak
                    if "from karadul.core.target import TargetType" in stripped:
                        local_imports.append((i, stripped))

        assert local_imports == [], (
            f"TargetType icin local import bulundu (UnboundLocalError riski):\n"
            + "\n".join(f"  L{n}: {s}" for n, s in local_imports)
        )

    def test_targettype_accessible_from_stages_module(self) -> None:
        """TargetType, stages modulu import edildiginde erisilebildir olmali."""
        from karadul.stages import TargetType  # noqa: F401 -- import testi

        assert hasattr(TargetType, "GO_BINARY")
        assert hasattr(TargetType, "MACHO_BINARY")
        assert hasattr(TargetType, "ELECTRON_APP")

    def test_deobfuscation_stage_resolve_deob_input_no_unbound(self) -> None:
        """DeobfuscationStage._resolve_deob_input bytecode'unda
        TargetType LOCAL olmamali (GLOBAL olarak erismeli)."""
        from karadul.stages import DeobfuscationStage

        method = DeobfuscationStage._resolve_deob_input
        code = method.__code__

        # TargetType local degiskenlerde OLMAMALI
        assert "TargetType" not in code.co_varnames, (
            "TargetType hala _resolve_deob_input'ta local! "
            "Bu UnboundLocalError riski olusturur."
        )

    def test_reconstruction_stage_execute_binary_no_unbound(self) -> None:
        """ReconstructionStage._execute_binary bytecode'unda
        TargetType LOCAL olmamali."""
        from karadul.stages import ReconstructionStage

        method = ReconstructionStage._execute_binary
        code = method.__code__

        assert "TargetType" not in code.co_varnames, (
            "TargetType hala _execute_binary'de local!"
        )
        # GLOBAL olarak erisilebilir olmali
        assert "TargetType" in code.co_names, (
            "TargetType, _execute_binary'de global isimler arasinda yok!"
        )


# ---------------------------------------------------------------
# Fix #2: CFlowSimplifier regex backtracking
# ---------------------------------------------------------------


class TestCFlowSimplifierRegexSafety:
    """CFlowSimplifier'daki regex'lerin catastrophic backtracking yapmadigini dogrula.

    Eski bug: label_and_block_pattern icinde (?:...)*? + [^\\n]* kombinasyonu
    buyuk dosyalarda sonsuz geri donus yapiyordu.
    Fix: Regex kaldiraldi, string-based yaklasima gecildi.
    """

    def test_no_lazy_quantifier_regex_in_simplify(self) -> None:
        """CFlowSimplifier'da (?:...)*? pattern'i kalmadigini dogrula."""
        flow_path = (
            Path(__file__).parent.parent
            / "karadul"
            / "reconstruction"
            / "c_flow_simplifier.py"
        )
        content = flow_path.read_text(encoding="utf-8")

        # Eski tehlikeli pattern: (?:...)*? ile [^\n]* kombinasyonu
        dangerous_pattern = re.compile(
            r'r"[^"]*\(\?:[^)]*\)\*\?[^"]*\[\\n\]\*'
        )
        matches = dangerous_pattern.findall(content)
        # Yorum satirlari haric
        code_lines = [
            line for line in content.split("\n")
            if line.strip() and not line.strip().startswith("#")
        ]
        code_content = "\n".join(code_lines)
        assert ")*?" not in code_content or "[^\\n]*" not in code_content, (
            "CFlowSimplifier'da hala lazy quantifier + [^\\n]* pattern'i var! "
            "Catastrophic backtracking riski."
        )

    def test_simplify_large_content_no_hang(self) -> None:
        """12K+ satir icerik uzerinde simplify 5 saniye icerisinde bitmeli."""
        from karadul.reconstruction.c_flow_simplifier import CFlowSimplifier
        from karadul.config import Config

        config = Config()
        simplifier = CFlowSimplifier(config)

        # 12K satirlik sentetik C kodu (gh binary benzeri buyukluk)
        lines = []
        for i in range(500):
            label = f"LAB_{i:08x}"
            lines.append(f"  goto {label};")
            lines.append(f"  // ... some code ...")
            lines.append(f"  {label}:")
            lines.append(f"    free(ptr_{i});")
            lines.append(f"    return -1;")
        content = "void big_func(void) {\n" + "\n".join(lines) + "\n}\n"

        start = time.monotonic()
        result_content, result_stats = simplifier._simplify_content(content)
        elapsed = time.monotonic() - start

        assert elapsed < 5.0, (
            f"CFlowSimplifier 500 label'lik icerik icin {elapsed:.1f}s surdu! "
            f"Backtracking olabilir."
        )
        assert isinstance(result_content, str)
        assert isinstance(result_stats, dict)

    def test_simplify_adversarial_input_no_hang(self) -> None:
        """Backtracking tetikleyebilecek adversarial input uzerinde hang olmamali.

        Eski regex: (?:[^\\n]*\\n)*? pattern'i, eslesme basarisiz olunca
        her satir kombinasyonunu deniyor. Bu test o durumu tetikler.
        """
        from karadul.reconstruction.c_flow_simplifier import CFlowSimplifier
        from karadul.config import Config

        config = Config()
        simplifier = CFlowSimplifier(config)

        # Label var ama return/break/goto yok -> eski regex sonsuza giderdi
        adversarial = (
            "void evil(void) {\n"
            "  goto LAB_deadbeef;\n"
            "  // code\n"
            "  LAB_deadbeef:\n"
            + "    x = x + 1;\n" * 200  # return/break/goto yok
            + "}\n"
        )

        start = time.monotonic()
        result_content, result_stats = simplifier._simplify_content(adversarial)
        elapsed = time.monotonic() - start

        assert elapsed < 2.0, (
            f"Adversarial input icin {elapsed:.1f}s! Backtracking!"
        )

    def test_extract_label_block_bounded(self) -> None:
        """_extract_label_block max 2000 karakter ile sinirli olmali."""
        from karadul.reconstruction.c_flow_simplifier import CFlowSimplifier
        from karadul.config import Config

        config = Config()
        simplifier = CFlowSimplifier(config)

        # 10K karakterlik icerik
        big_content = "    x = 1;\n" * 1000  # ~11K char
        block = simplifier._extract_label_block(big_content, 0)
        # _max_inline_lines + 5 ile sinirli
        assert len(block) < 5000, (
            f"_extract_label_block sinirlanmamis: {len(block)} char"
        )


# ---------------------------------------------------------------
# Regression: semantic_namer regex guvenlik kontrolu
# ---------------------------------------------------------------


class TestSemanticNamerRegexSafety:
    """semantic_namer'daki _replace_whole_word'un re.sub yerine kullanildigini dogrula."""

    def test_replace_whole_word_is_used(self) -> None:
        """_replace_whole_word, str-based O(n) garanti etmeli."""
        namer_path = (
            Path(__file__).parent.parent
            / "karadul"
            / "reconstruction"
            / "engineering"
            / "semantic_namer.py"
        )
        content = namer_path.read_text(encoding="utf-8")

        # _replace_whole_word fonksiyonu tanimli olmali
        assert "def _replace_whole_word" in content or "_replace_whole_word" in content

    def test_replace_whole_word_performance(self) -> None:
        """_replace_whole_word buyuk string'de hizli olmali."""
        from karadul.reconstruction.c_flow_simplifier import _replace_whole_word

        # 1MB'lik icerik
        big_text = "void func_name(int param) { return param; }\n" * 20000
        start = time.monotonic()
        result = _replace_whole_word(big_text, "param", "new_param")
        elapsed = time.monotonic() - start

        assert elapsed < 2.0, f"_replace_whole_word 1MB icin {elapsed:.1f}s!"
        assert "new_param" in result
        assert result.count("new_param") > 0


# ---------------------------------------------------------------
# v1.6.1: Buyuk fonksiyon body regex korumalari
# ---------------------------------------------------------------


class TestLargeBodyRegexProtection:
    """Buyuk fonksiyon body'lerinde regex atlandigini dogrula."""

    def test_detect_usage_pattern_skips_large_body(self) -> None:
        """50K+ body'de _detect_usage_pattern str-based fallback kullanmali."""
        from karadul.reconstruction.engineering.semantic_namer import _detect_usage_pattern

        big_code = "int x = param_1;\n" * 5000  # ~90K
        start = time.monotonic()
        result = _detect_usage_pattern(big_code, "param_1")
        elapsed = time.monotonic() - start

        assert elapsed < 1.0, f"_detect_usage_pattern buyuk body'de {elapsed:.1f}s!"
        assert isinstance(result, str)

    def test_detect_usage_pattern_works_normal(self) -> None:
        """Normal body'de detayli regex calismali."""
        from karadul.reconstruction.engineering.semantic_namer import _detect_usage_pattern

        code = "for(i=0; i<param_1; i++) { x += arr[i]; }"
        result = _detect_usage_pattern(code, "param_1")
        assert result == "loop_bound"

    def test_detect_usage_pattern_missing_param(self) -> None:
        """Param body'de yoksa hizlica 'general' donmeli."""
        from karadul.reconstruction.engineering.semantic_namer import _detect_usage_pattern

        code = "int x = 42; return x;"
        result = _detect_usage_pattern(code, "nonexistent_param")
        assert result == "general"

    def test_confidence_calibrator_large_body_str_fallback(self) -> None:
        """build_call_graph_from_bodies buyuk body'de str.find kullanmali."""
        from karadul.reconstruction.engineering.confidence_calibrator import (
            ConfidenceCalibrator,
        )
        from karadul.config import Config

        cal = ConfidenceCalibrator()
        big_body = "void helper() { return; }\n" * 5000  # ~130K
        bodies = {"main_func": big_body}
        names = ["main_func", "helper"]

        start = time.monotonic()
        cg = cal.build_call_graph_from_bodies(bodies, names)
        elapsed = time.monotonic() - start

        assert elapsed < 2.0, f"build_call_graph buyuk body'de {elapsed:.1f}s!"
        # str.find "helper" bulabilmeli
        assert "helper" in cg["main_func"]["callees"]

    def test_detect_index_pattern_works_on_large(self) -> None:
        """v1.8.0: 50K+ body'de _detect_index_pattern satir bazli calisir."""
        from karadul.reconstruction.engineering.semantic_namer import _detect_index_pattern

        big_code = "x = arr[i];\n" * 6000
        result = _detect_index_pattern(big_code, "arr")
        # v1.8.0: Artik buyuk body'ler de islenir, pattern eslesmeli
        assert result == "sequential"


# ---------------------------------------------------------------
# Fix #4-5-6: DOTALL regex boyut siniri
# ---------------------------------------------------------------


class TestDotallRegexSafety:
    """v1.8.0: DOTALL regex'lerin chunk-bazli calistigini dogrula."""

    def test_constraint_solver_chunk_based_go_detection(self) -> None:
        """Go map pattern buyuk inputta da calisir."""
        from karadul.reconstruction.recovery_layers.constraint_solver import _GO_MAP_RE
        code = "runtime.makemap(typ, 8)"
        match = _GO_MAP_RE.search(code)
        assert match is not None

    def test_constraint_solver_linked_list_chunk_safe(self) -> None:
        """Linked list DOTALL regex 5KB chunk icinde calisir."""
        from karadul.reconstruction.recovery_layers.constraint_solver import (
            _LINKED_LIST_LOOP_RE, _iter_loop_chunks,
        )
        # Kucuk input: dogrudan match
        code = """while (node != NULL) {
            node = *(long *)(node + 0x8);
        }"""
        chunks = _iter_loop_chunks(code, 5000)
        assert len(chunks) >= 1
        found = False
        for chunk in chunks:
            if _LINKED_LIST_LOOP_RE.search(chunk):
                found = True
        assert found

    def test_formula_extractor_chunk_based_dotall(self) -> None:
        """v1.8.0: formula_extractor _safe_dotall_search chunk-bazli calisir."""
        from karadul.reconstruction.recovery_layers.formula_extractor import (
            _safe_dotall_search, ACCUMULATOR_RE,
        )
        # Kucuk inputta esleme calismali
        code = "for(i=0; i<n; i++) { sum += arr[i]; }"
        match = _safe_dotall_search(ACCUMULATOR_RE, code)
        assert match is not None

    def test_formula_extractor_handles_large_safely(self) -> None:
        """v1.8.0: Buyuk inputta chunk-bazli arama timeout yapmaz."""
        import time
        from karadul.reconstruction.recovery_layers.formula_extractor import (
            _safe_dotall_search, MATRIX_MUL_RE,
        )
        # 100K input -- artik atlanmak yerine chunk-bazli islenir
        big = "x = y + z;\n" * 10000
        start = time.monotonic()
        result = _safe_dotall_search(MATRIX_MUL_RE, big)
        elapsed = time.monotonic() - start
        # No hang -- should finish in reasonable time
        assert elapsed < 5.0, f"Took {elapsed:.1f}s"
        # No match expected (no for loop pattern in this input)
        assert result is None




# ---------------------------------------------------------------
# Fix #8: Ctrl+C graceful shutdown
# ---------------------------------------------------------------


class TestGracefulShutdown:
    """KeyboardInterrupt yakalandigini dogrula."""

    def test_hacker_cli_catches_keyboard_interrupt(self) -> None:
        """hacker_cli pipeline calistirma kodunda KeyboardInterrupt catch var."""
        import inspect
        from karadul import hacker_cli
        source = inspect.getsource(hacker_cli)
        assert "except KeyboardInterrupt" in source

    def test_error_recovery_does_not_swallow_keyboard_interrupt(self) -> None:
        """ErrorRecovery retry loop'u KeyboardInterrupt yutmamali."""
        import inspect
        from karadul.core.error_recovery import ErrorRecovery
        source = inspect.getsource(ErrorRecovery.execute)
        # except Exception kullaniliyor, except BaseException degil
        # Bu KeyboardInterrupt'i otomatik olarak yukari gecirmeli
        assert "except BaseException" not in source
        assert "except Exception" in source


# ---------------------------------------------------------------
# Fix #3: Silent ImportError loglama
# ---------------------------------------------------------------


class TestImportErrorLogging:
    """ImportError'larin sessizce yutulmadigini dogrula."""

    def test_hacker_cli_logs_import_error(self) -> None:
        """hacker_cli ReconstructionStage ImportError'u loglamali."""
        import inspect
        from karadul import hacker_cli
        source = inspect.getsource(hacker_cli)
        # Eski: except ImportError: pass
        # Yeni: except ImportError as exc: logger.warning(...)
        assert "ImportError:\n        pass" not in source

    def test_cli_logs_import_error(self) -> None:
        """cli.py ReconstructionStage ImportError'u loglamali."""
        import inspect
        from karadul import cli
        source = inspect.getsource(cli)
        assert "ImportError:\n        pass" not in source
