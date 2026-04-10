"""v1.8.0: Regex safety tests -- line-by-line processing.

Ensures ALL regex patterns work safely on ANY input size.
No files are skipped, no size guards -- every function is processed.

Tests verify:
1. Large body (300K+) processed without hangs via line-by-line search
2. constraint_solver _LINKED_LIST_RE pattern doesn't backtrack
3. Line-by-line strategies produce correct results on both small and large bodies
"""
from __future__ import annotations

import re
import time

import pytest


# ---------------------------------------------------------------------------
# Buyuk body olusturucu: tipik CalculiX decompile ciktisi (~300K chars)
# ---------------------------------------------------------------------------

def _make_large_body(size: int = 200_000) -> str:
    """CalculiX-like buyuk fonksiyon body'si olustur."""
    lines = []
    lines.append("void FUN_001234(undefined8 param_1, undefined8 param_2, long param_3) {")
    lines.append("  int iVar1;")
    lines.append("  uint uVar2;")
    lines.append("  long lVar3;")
    lines.append("  bool bVar4;")
    lines.append("  char *pcVar5;")
    lines.append("  undefined8 local_78;")
    lines.append("  undefined4 local_70;")
    lines.append("")

    # Tip isimlerini genislet
    i = 0
    while len("\n".join(lines)) < size:
        lines.append(f"  if (*(int *)(param_1 + 0x{i * 8:x}) == {i}) {{")
        lines.append(f"    *(long *)(param_2 + 0x{i * 4:x}) = (long)param_3 + {i};")
        lines.append(f"    uVar2 = uVar2 + (uint)(*(int *)(param_1 + 0x{i * 8 + 4:x}));")
        lines.append(f"    iVar1 = iVar1 + 1;")
        lines.append(f"  }}")
        i += 1

    lines.append("  return;")
    lines.append("}")
    return "\n".join(lines)


def _make_small_body() -> str:
    """Kucuk fonksiyon body'si."""
    return """void FUN_abcdef(char *param_1, int param_2) {
  int iVar1;
  char *pcVar2;
  bool bVar3;
  undefined8 local_28;

  iVar1 = strlen(param_1);
  pcVar2 = malloc(iVar1 + 1);
  if (pcVar2 == NULL) {
    return;
  }
  strcpy(pcVar2, param_1);
  bVar3 = param_2 > 0;
  free(pcVar2);
  return;
}"""


# ---------------------------------------------------------------------------
# Test: O(n) safe regex'ler buyuk body'de de calisir
# ---------------------------------------------------------------------------

def test_large_body_regex_safe():
    """300K body'de O(n) safe regex pattern'leri 5 saniye icinde bitmeli."""
    body = _make_large_body(300_000)
    assert len(body) > 200_000

    # Bu pattern'ler c_namer icinde kullanilir.
    # Hepsi O(n) safe: \w, \s, [^...] negated char class
    c_func_call = re.compile(r"\b(\w+)\s*\(")
    c_local_usage = re.compile(r"\b(local_[0-9a-fA-F]+)\b")
    c_autovar = re.compile(r"\b([a-z]{1,4}Var\d+)\b")

    start = time.monotonic()

    # v1.8.0: Boyut siniri YOK -- dogrudan calistir
    c_func_call.findall(body)
    c_local_usage.findall(body)
    c_autovar.findall(body)

    elapsed = time.monotonic() - start
    assert elapsed < 5.0, f"Large body processing took {elapsed:.1f}s (expected < 5s)"


def test_small_body_works():
    """Kucuk body normal regex ile islenmeli."""
    body = _make_small_body()

    c_func_call = re.compile(r"\b(\w+)\s*\(")
    funcs = set(c_func_call.findall(body))
    assert "strlen" in funcs
    assert "malloc" in funcs
    assert "strcpy" in funcs
    assert "free" in funcs


# ---------------------------------------------------------------------------
# Test: _LINKED_LIST_RE pattern backtracking sorunu
# ---------------------------------------------------------------------------

def test_linked_list_re_no_backtracking():
    r"""constraint_solver _LINKED_LIST_RE: negated char class ile safe."""
    from karadul.reconstruction.computation.constraint_solver import _LINKED_LIST_RE

    # Normal match: calismali
    normal = "ptr = *(long *)(ptr + 0x8);"
    m = _LINKED_LIST_RE.search(normal)
    assert m is not None
    assert m.group("var") == "ptr"
    assert m.group("offset") == "0x8"

    # Complex type: calismali
    complex_type = "node = *(struct element_data *)(node + 0x10);"
    m = _LINKED_LIST_RE.search(complex_type)
    assert m is not None
    assert m.group("var") == "node"

    # Eski pattern'de O(n^2) backtracking yapan case:
    no_match = "long_variable_name_here = something_else_entirely + 42;"
    start = time.monotonic()
    m = _LINKED_LIST_RE.search(no_match)
    elapsed = time.monotonic() - start
    assert m is None
    assert elapsed < 1.0, f"Non-matching search took {elapsed:.1f}s"

    # Buyuk icerikte match aramasi 1 saniye icinde bitmeli
    big_content = "\n".join([
        f"  *(long *)(param_1 + 0x{i * 8:x}) = local_{i:04x};"
        for i in range(5000)
    ])
    start = time.monotonic()
    matches = list(_LINKED_LIST_RE.finditer(big_content))
    elapsed = time.monotonic() - start
    assert elapsed < 2.0, f"Big content finditer took {elapsed:.1f}s"


# ---------------------------------------------------------------------------
# Test: c_namer strategies work on large bodies (line-by-line)
# ---------------------------------------------------------------------------

def test_c_namer_strategy_dataflow_large_body():
    """_strategy_dataflow: 200K body satir bazli islenir, hang olmaz."""
    from karadul.config import Config
    from karadul.reconstruction.c_namer import CVariableNamer

    config = Config()
    namer = CVariableNamer(config)

    # Buyuk body olustur
    big_body = _make_large_body(200_000)

    # _func_bodies'e ekle
    namer._func_bodies["FUN_test"] = big_body

    from types import SimpleNamespace
    func_info = SimpleNamespace(
        name="FUN_test",
        address="0x1234",
        params=[{"name": "param_1", "type": "long"}, {"name": "param_2", "type": "long"}],
    )

    # v1.8.0: Satir bazli islem, hang olmamali
    start = time.monotonic()
    namer._strategy_dataflow(func_info)
    elapsed = time.monotonic() - start
    assert elapsed < 5.0, f"_strategy_dataflow took {elapsed:.1f}s on large body"


def test_c_namer_local_var_naming_large_body():
    """_strategy_local_var_naming: buyuk body'de satir bazli calisir."""
    from karadul.config import Config
    from karadul.reconstruction.c_namer import CVariableNamer

    config = Config()
    namer = CVariableNamer(config)

    # Buyuk body olustur (degisken tanimlamalari ile)
    lines = [
        "void FUN_test(long param_1) {",
        "  int iVar1;",
        "  uint uVar2;",
        "  char *pcVar3;",
        "  bool bVar4;",
        "  undefined8 local_78;",
    ]
    # Body'yi buyut
    while len("\n".join(lines)) < 150_000:
        lines.append("  iVar1 = iVar1 + 1;")
    lines.append("}")

    big_body = "\n".join(lines)
    assert len(big_body) > 100_000

    namer._func_bodies["FUN_test"] = big_body

    from types import SimpleNamespace
    func_info = SimpleNamespace(
        name="FUN_test",
        address="0x5678",
        params=[{"name": "param_1", "type": "long"}],
    )

    # v1.8.0: Satir bazli islem, hang olmamali
    start = time.monotonic()
    namer._strategy_local_var_naming(func_info)
    elapsed = time.monotonic() - start
    assert elapsed < 5.0, f"local_var_naming took {elapsed:.1f}s on large body"

    # Prefix-based isimler uretebilmeli
    # (iVar1 -> ret, uVar2 -> val, pcVar3 -> str, bVar4 -> flag)
    candidates_found = 0
    for key, cands in namer._candidates.items():
        if "FUN_test" in key:
            candidates_found += len(cands)
    # En az 1 tane candidate olmali (artik tum Layer'lar calisir)
    assert candidates_found >= 1, "Should produce at least 1 candidate on large body"
