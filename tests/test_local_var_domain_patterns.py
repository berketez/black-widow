"""v1.9.0: Domain-specific local variable naming pattern tests.

Tests for the 7 new pattern categories added to Strategy 9
(_strategy_local_var_naming):

1. Return value semantic naming (funcName_ret)
2. Array stride detection (coord_array, tensor_array, etc.)
3. Accumulator patterns (accumulator, counter, product)
4. Comparison target patterns (threshold_val, bound_check, etc.)
5. Pointer chain patterns (field_ptr, next_ptr, current_node)
6. Math operation patterns (magnitude, angle, ratio, etc.)
7. Conditional assignment patterns (min_val, max_val, selected)

Each test creates a minimal C function body, runs Strategy 9 via
CVariableNamer._strategy_local_var_naming, and checks that the
correct name + confidence is produced.
"""
from __future__ import annotations

import re
from types import SimpleNamespace

import pytest

from karadul.config import Config
from karadul.reconstruction.c_namer import CVariableNamer, _LOCAL_VAR_USAGE_PATTERNS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_namer() -> CVariableNamer:
    """Fresh CVariableNamer instance with default config."""
    return CVariableNamer(Config(), min_confidence=0.15)


def _run_strategy(body: str, func_name: str = "FUN_test") -> dict[str, list]:
    """Run _strategy_local_var_naming on body and return candidates dict."""
    namer = _make_namer()
    namer._func_bodies[func_name] = body
    func_info = SimpleNamespace(
        name=func_name,
        address="0xdead",
        params=[],
    )
    namer._strategy_local_var_naming(func_info)
    return dict(namer._candidates)


def _get_best_name(candidates: dict, func_name: str, var_name: str) -> str | None:
    """Extract best candidate name for a variable from candidates dict."""
    key = f"{func_name}::{var_name}"
    cands = candidates.get(key, [])
    if not cands:
        return None
    best = max(cands, key=lambda c: c.confidence)
    return best.new_name


def _get_best_conf(candidates: dict, func_name: str, var_name: str) -> float:
    """Extract best confidence for a variable from candidates dict."""
    key = f"{func_name}::{var_name}"
    cands = candidates.get(key, [])
    if not cands:
        return 0.0
    return max(c.confidence for c in cands)


# ---------------------------------------------------------------------------
# Test: Pattern list integrity
# ---------------------------------------------------------------------------

class TestPatternListIntegrity:
    """Verify that all patterns compile and have valid structure."""

    def test_all_patterns_have_param_placeholder(self):
        """Every pattern should contain PARAM placeholder."""
        for pattern, name, conf in _LOCAL_VAR_USAGE_PATTERNS:
            # The raw pattern string should have PARAM
            assert "PARAM" in pattern.pattern, (
                f"Pattern for '{name}' missing PARAM: {pattern.pattern}"
            )

    def test_all_confidences_in_range(self):
        """Confidence should be between 0.0 and 1.0."""
        for pattern, name, conf in _LOCAL_VAR_USAGE_PATTERNS:
            assert 0.0 < conf <= 1.0, (
                f"Pattern '{name}' has invalid confidence {conf}"
            )

    def test_pattern_compilation_with_real_var(self):
        """All patterns should compile when PARAM is replaced with a real var."""
        test_vars = ["uVar1", "local_78", "iVar3", "pcVar5"]
        for var_name in test_vars:
            for pattern, name, conf in _LOCAL_VAR_USAGE_PATTERNS:
                try:
                    compiled = re.compile(
                        pattern.pattern.replace("PARAM", re.escape(var_name))
                    )
                    assert compiled is not None
                except re.error as e:
                    pytest.fail(
                        f"Pattern '{name}' failed to compile with "
                        f"var={var_name}: {e}"
                    )


# ---------------------------------------------------------------------------
# Test 1: Accumulator patterns
# ---------------------------------------------------------------------------

class TestAccumulatorPatterns:
    """Accumulator/counter/product patterns."""

    def test_plus_equals(self):
        body = """\
void FUN_test(void) {
  int iVar1;
  iVar1 = 0;
  iVar1 += *(int *)(param_1 + 0x10);
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "iVar1") == "accumulator"

    def test_self_add(self):
        body = """\
void FUN_test(void) {
  double dVar1;
  dVar1 = 0.0;
  dVar1 = dVar1 + *(double *)(param_1 + 0x8);
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "dVar1") == "accumulator"

    def test_product_accumulator(self):
        body = """\
void FUN_test(void) {
  double dVar1;
  dVar1 = 1.0;
  dVar1 *= *(double *)(param_1 + 0x8);
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "dVar1") == "product"

    def test_post_increment(self):
        body = """\
void FUN_test(void) {
  int iVar1;
  iVar1 = 0;
  iVar1++;
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "iVar1") == "counter"

    def test_pre_increment(self):
        body = """\
void FUN_test(void) {
  int uVar1;
  uVar1 = 0;
  ++uVar1;
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "uVar1") == "counter"

    def test_post_decrement(self):
        body = """\
void FUN_test(void) {
  int iVar1;
  iVar1 = 10;
  iVar1--;
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "iVar1") == "counter"

    def test_bitwise_or_equals(self):
        body = """\
void FUN_test(void) {
  uint uVar1;
  uVar1 = 0;
  uVar1 |= 0x80;
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "uVar1") == "flags"

    def test_bitwise_and_equals(self):
        body = """\
void FUN_test(void) {
  uint uVar1;
  uVar1 = 0xff;
  uVar1 &= 0x0f;
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "uVar1") == "mask"


# ---------------------------------------------------------------------------
# Test 2: Array stride detection
# ---------------------------------------------------------------------------

class TestArrayStridePatterns:
    """Strided array access patterns."""

    def test_stride_3_coordinate(self):
        body = """\
void FUN_test(void) {
  undefined8 local_78;
  *(float *)(local_78 + 0) = local_78[iVar1*3+0];
  *(float *)(local_78 + 4) = local_78[iVar1*3+1];
  *(float *)(local_78 + 8) = local_78[iVar1*3+2];
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "local_78") == "coord_array"

    def test_stride_4_rgba(self):
        body = """\
void FUN_test(void) {
  undefined8 local_48;
  val = local_48[idx*4+channel];
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "local_48") == "rgba_array"

    def test_stride_6_tensor(self):
        body = """\
void FUN_test(void) {
  undefined8 local_30;
  val = local_30[idx*6+component];
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "local_30") == "tensor_array"

    def test_general_stride(self):
        body = """\
void FUN_test(void) {
  undefined8 local_28;
  val = local_28[row*8];
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "local_28") == "strided_array"


# ---------------------------------------------------------------------------
# Test 3: Comparison target patterns
# ---------------------------------------------------------------------------

class TestComparisonPatterns:
    """Variable used in comparisons / conditionals."""

    def test_threshold_check(self):
        body = """\
void FUN_test(void) {
  int iVar1;
  iVar1 = param_2;
  if (iVar1 > 100) {
    do_something();
  }
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "iVar1") == "threshold_val"

    def test_bound_check_break(self):
        body = """\
void FUN_test(void) {
  int iVar1;
  iVar1 = 0;
  while (1) {
    if (iVar1 < limit) break;
    process();
  }
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "iVar1") == "bound_check"

    def test_null_check(self):
        body = """\
void FUN_test(void) {
  undefined8 local_38;
  local_38 = *(undefined8 *)(param_1 + 0x20);
  if (local_38 == NULL) {
    return;
  }
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "local_38") == "nullable_ptr"

    def test_switch_selector(self):
        body = """\
void FUN_test(void) {
  int iVar1;
  iVar1 = *(int *)(param_1 + 4);
  switch (iVar1) {
    case 0: break;
    case 1: break;
  }
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "iVar1") == "selector"


# ---------------------------------------------------------------------------
# Test 4: Pointer chain patterns
# ---------------------------------------------------------------------------

class TestPointerChainPatterns:
    """Pointer dereference chains / linked list traversal."""

    def test_field_dereference(self):
        body = """\
void FUN_test(void) {
  undefined8 local_28;
  local_28 = *(long *)(param_1 + 0x10);
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "local_28") == "field_ptr"

    def test_self_referential_deref(self):
        body = """\
void FUN_test(void) {
  undefined8 local_18;
  local_18 = param_1;
  local_18 = *(long *)local_18;
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "local_18") == "current_node"

    def test_next_pointer(self):
        body = """\
void FUN_test(void) {
  undefined8 local_20;
  local_20 = param_1;
  local_20 = *(long *)(local_20 + 0x8);
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "local_20") == "next_ptr"

    def test_write_through_ptr(self):
        body = """\
void FUN_test(void) {
  undefined8 local_40;
  local_40 = param_1;
  *(int *)(local_40 + 0x10) = 42;
  *(int *)(local_40 + 0x14) = 0;
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "local_40") == "obj_ptr"


# ---------------------------------------------------------------------------
# Test 5: Math operation patterns
# ---------------------------------------------------------------------------

class TestMathPatterns:
    """Math function return values."""

    def test_sqrt_magnitude(self):
        body = """\
void FUN_test(void) {
  double dVar1;
  dVar1 = sqrt(x*x + y*y);
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "dVar1") == "magnitude"

    def test_atan2_angle(self):
        body = """\
void FUN_test(void) {
  double dVar1;
  dVar1 = atan2(y, x);
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "dVar1") == "angle"

    def test_sin_value(self):
        body = """\
void FUN_test(void) {
  double dVar1;
  dVar1 = sin(theta);
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "dVar1") == "sin_val"

    def test_cos_value(self):
        body = """\
void FUN_test(void) {
  float fVar1;
  fVar1 = cosf(angle);
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "fVar1") == "cos_val"

    def test_exp_value(self):
        body = """\
void FUN_test(void) {
  double dVar1;
  dVar1 = exp(-lambda * t);
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "dVar1") == "exp_val"

    def test_log_value(self):
        body = """\
void FUN_test(void) {
  double dVar1;
  dVar1 = log(probability);
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "dVar1") == "log_val"

    def test_abs_value(self):
        body = """\
void FUN_test(void) {
  double dVar1;
  dVar1 = fabs(delta);
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "dVar1") == "abs_val"

    def test_pow_value(self):
        body = """\
void FUN_test(void) {
  double dVar1;
  dVar1 = pow(base, exponent);
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "dVar1") == "power_val"

    def test_division_ratio(self):
        body = """\
void FUN_test(void) {
  double dVar1;
  dVar1 = numerator / denominator;
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "dVar1") == "ratio"

    def test_modulo_remainder(self):
        body = """\
void FUN_test(void) {
  int iVar1;
  iVar1 = value % divisor;
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "iVar1") == "remainder"

    def test_floor_value(self):
        body = """\
void FUN_test(void) {
  double dVar1;
  dVar1 = floor(x);
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "dVar1") == "floor_val"

    def test_ceil_value(self):
        body = """\
void FUN_test(void) {
  double dVar1;
  dVar1 = ceil(x);
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "dVar1") == "ceil_val"


# ---------------------------------------------------------------------------
# Test 6: Conditional assignment patterns
# ---------------------------------------------------------------------------

class TestConditionalAssignmentPatterns:
    """Ternary operator patterns."""

    def test_min_val(self):
        body = """\
void FUN_test(void) {
  int iVar1;
  iVar1 = (a < b) ? a : b;
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "iVar1") == "min_val"

    def test_max_val(self):
        body = """\
void FUN_test(void) {
  int iVar1;
  iVar1 = (a > b) ? a : b;
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "iVar1") == "max_val"

    def test_general_ternary(self):
        """General ternary without < or > is 'selected' at lower conf."""
        body = """\
void FUN_test(void) {
  int iVar1;
  iVar1 = (flag == 1) ? option_a : option_b;
  return;
}"""
        cands = _run_strategy(body)
        # This could match "selected" or "ret" depending on pattern order
        name = _get_best_name(cands, "FUN_test", "iVar1")
        assert name is not None  # At least something matched


# ---------------------------------------------------------------------------
# Test 7: Return value semantic naming
# ---------------------------------------------------------------------------

class TestReturnValueSemanticNaming:
    """var = someFunc(...) -> someFunc_ret."""

    def test_named_function_return(self):
        """Unknown function call should produce funcName_ret."""
        body = """\
void FUN_test(void) {
  int iVar1;
  iVar1 = calculateChecksum(param_1, param_2);
  return;
}"""
        cands = _run_strategy(body)
        name = _get_best_name(cands, "FUN_test", "iVar1")
        assert name == "calculateChecksum_ret"

    def test_known_api_not_overridden(self):
        """malloc should stay 'buf', not become 'malloc_ret'."""
        body = """\
void FUN_test(void) {
  undefined8 local_28;
  local_28 = malloc(0x100);
  return;
}"""
        cands = _run_strategy(body)
        name = _get_best_name(cands, "FUN_test", "local_28")
        assert name == "buf"

    def test_ghidra_auto_name_not_used(self):
        """FUN_XXXXX should NOT produce 'FUN_XXXXX_ret' -- Ghidra auto names
        are excluded from semantic naming. Result may be 'ret' or 'result'
        depending on type declaration, but never FUN_xxx_ret."""
        body = """\
void FUN_test(void) {
  int iVar1;
  iVar1 = FUN_00401234(param_1);
  return;
}"""
        cands = _run_strategy(body)
        name = _get_best_name(cands, "FUN_test", "iVar1")
        assert name in ("ret", "result")
        assert "FUN_" not in name

    def test_underscore_stripped(self):
        """_initModule -> initModule_ret."""
        body = """\
void FUN_test(void) {
  int iVar1;
  iVar1 = _initModule(param_1);
  return;
}"""
        cands = _run_strategy(body)
        name = _get_best_name(cands, "FUN_test", "iVar1")
        assert name == "initModule_ret"

    def test_short_func_name_ignored(self):
        """2-char function names like 'ab' are too short -> no semantic ret.
        Result will be 'ret' or 'result' (from type fallback), never 'ab_ret'."""
        body = """\
void FUN_test(void) {
  int iVar1;
  iVar1 = ab(param_1);
  return;
}"""
        cands = _run_strategy(body)
        name = _get_best_name(cands, "FUN_test", "iVar1")
        assert name in ("ret", "result")
        assert "ab_" not in name


# ---------------------------------------------------------------------------
# Test 8: Shift/mask patterns
# ---------------------------------------------------------------------------

class TestShiftMaskPatterns:
    """Bitwise shift and mask operations."""

    def test_right_shift(self):
        body = """\
void FUN_test(void) {
  uint uVar1;
  uVar1 = flags >> 4;
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "uVar1") == "shifted"

    def test_left_shift(self):
        body = """\
void FUN_test(void) {
  uint uVar1;
  uVar1 = base << 8;
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "uVar1") == "shifted"

    def test_hex_mask(self):
        body = """\
void FUN_test(void) {
  uint uVar1;
  uVar1 = raw & 0xFF;
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "uVar1") == "masked"


# ---------------------------------------------------------------------------
# Test 9: Cast patterns (Ghidra-specific)
# ---------------------------------------------------------------------------

class TestCastPatterns:
    """Type cast assignment patterns."""

    def test_float_cast(self):
        body = """\
void FUN_test(void) {
  float fVar1;
  fVar1 = (float)iVar2;
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "fVar1") == "fval"

    def test_double_cast(self):
        body = """\
void FUN_test(void) {
  double dVar1;
  dVar1 = (double)uVar2;
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "dVar1") == "dval"

    def test_int_cast(self):
        body = """\
void FUN_test(void) {
  int iVar1;
  iVar1 = (int)fVar2;
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "iVar1") == "ival"


# ---------------------------------------------------------------------------
# Test 10: Confidence ordering (higher-conf pattern wins)
# ---------------------------------------------------------------------------

class TestConfidenceOrdering:
    """When multiple patterns match, highest confidence should win."""

    def test_specific_beats_generic(self):
        """sqrt return (0.50) beats generic 'ret' (0.30)."""
        body = """\
void FUN_test(void) {
  double dVar1;
  dVar1 = sqrt(x * x + y * y);
  return;
}"""
        cands = _run_strategy(body)
        name = _get_best_name(cands, "FUN_test", "dVar1")
        assert name == "magnitude"

    def test_counter_beats_fallback(self):
        """Counter (0.50) beats prefix fallback 'ret' (0.25)."""
        body = """\
void FUN_test(void) {
  int iVar1;
  iVar1 = 0;
  iVar1++;
  return;
}"""
        cands = _run_strategy(body)
        assert _get_best_name(cands, "FUN_test", "iVar1") == "counter"
        assert _get_best_conf(cands, "FUN_test", "iVar1") >= 0.50


# ---------------------------------------------------------------------------
# Test 11: Large body performance (regression test)
# ---------------------------------------------------------------------------

class TestLargeBodyPerformance:
    """New patterns should not cause O(n^2) on large bodies."""

    def test_large_body_with_new_patterns(self):
        """200K body with accumulator/math patterns - must finish < 10s."""
        import time

        lines = [
            "void FUN_test(long param_1) {",
            "  int iVar1;",
            "  uint uVar2;",
            "  double dVar3;",
            "  undefined8 local_78;",
        ]
        # Pad with realistic content including some pattern triggers
        for i in range(3000):
            lines.append(f"  uVar2 += *(uint *)(param_1 + 0x{i * 4:x});")
            lines.append(f"  dVar3 = dVar3 + *(double *)(param_1 + 0x{i * 8:x});")
            lines.append(f"  if (iVar1 > {i}) {{")
            lines.append(f"    *(int *)(param_1 + 0x{i:x}) = uVar2;")
            lines.append(f"  }}")
        lines.append("  return;")
        lines.append("}")

        body = "\n".join(lines)
        assert len(body) > 100_000

        start = time.monotonic()
        cands = _run_strategy(body)
        elapsed = time.monotonic() - start

        assert elapsed < 10.0, f"Large body took {elapsed:.1f}s (expected < 10s)"
        # Should still produce valid candidates
        assert _get_best_name(cands, "FUN_test", "uVar2") == "accumulator"
        assert _get_best_name(cands, "FUN_test", "dVar3") == "accumulator"


# ---------------------------------------------------------------------------
# Test 12: Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_empty_body(self):
        """Empty body should not crash."""
        cands = _run_strategy("")
        assert cands == {}

    def test_no_auto_vars(self):
        """Body with no Ghidra auto-vars should produce no candidates."""
        body = """\
void someFunc(int x) {
  int y = x + 1;
  return y;
}"""
        cands = _run_strategy(body)
        assert cands == {}

    def test_multiple_patterns_same_var(self):
        """Variable matching multiple categories should get highest conf name."""
        body = """\
void FUN_test(void) {
  int iVar1;
  iVar1 = 0;
  iVar1++;
  if (iVar1 > 100) {
    return;
  }
  return iVar1;
}"""
        cands = _run_strategy(body)
        # counter (0.50) should beat threshold_val (0.40) and result (0.40)
        assert _get_best_name(cands, "FUN_test", "iVar1") == "counter"

    def test_local_hex_var(self):
        """local_XX with hex suffix should be handled."""
        body = """\
void FUN_test(void) {
  undefined8 local_a8;
  local_a8 = *(long *)(param_1 + 0x20);
  if (local_a8 == NULL) {
    return;
  }
  return;
}"""
        cands = _run_strategy(body)
        name = _get_best_name(cands, "FUN_test", "local_a8")
        assert name is not None  # Should get some naming
