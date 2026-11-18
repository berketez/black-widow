"""P05b kalem 4: CALLER_NAME_HINTS tam belirteç eşleşmesiyle.

Eski kural iki yönlü alt dizgiydi (``hint in caller or caller in hint``, ``_`` atılmış küçük harf):
kısa adlı çağıran ``g`` ``assembleglobal``'in alt dizgisi olduğu için ``K_global`` ipucu alıyordu.
Yeni kural: ipucu adının belirteç dizisi çağıranın belirteç dizisinde ardışık geçmeli.
"""
from __future__ import annotations

from karadul.config import Config
from karadul.reconstruction.engineering.semantic_namer import (
    SemanticParameterNamer,
    _caller_matches_hint,
    _name_tokens,
)


def _yay(codes: dict[str, str], callee: str, callers: list[str]) -> dict[str, tuple[str, str]]:
    namer = SemanticParameterNamer(Config())
    namer._func_codes = dict(codes)
    namer._reverse_graph = {callee: list(callers)}
    params = namer._get_function_params(callee)
    return {s.original_name: (s.semantic_name, s.reason)
            for s in namer._propagate_from_callers(callee, params, {})}


# ---------------------------------------------------------------------------
# Kalem 4: CALLER_NAME_HINTS tam belirteç
# ---------------------------------------------------------------------------

def test_ad_belirtecleri():
    assert _name_tokens("my_assemble_global_v2") == ("my", "assemble", "global", "v2")
    assert _name_tokens("assembleGlobal") == ("assemble", "global")
    assert _name_tokens("_matvec") == ("matvec",)
    assert _name_tokens("FUN_00101000") == ("fun", "00101000")


def test_ipucu_tam_belirtec():
    assert _caller_matches_hint("my_assemble_global_v2", "assemble_global")
    assert _caller_matches_hint("assembleGlobal", "assemble_global")
    assert _caller_matches_hint("matvec_csr", "matvec")
    # Kısa adlı çağıran (eski kural: "g" ⊂ "assembleglobal")
    assert not _caller_matches_hint("g", "assemble_global")
    assert not _caller_matches_hint("FUN_00101000", "assemble_global")
    # Belirteç içi alt dizgi değil (eski kural: "matvec" ⊂ "matvecmul")
    assert not _caller_matches_hint("matvecmul", "matvec")
    assert not _caller_matches_hint("global_assemble", "assemble_global")


def test_ipucu_kisa_cagirana_ad_vermez():
    callee = "void FUN_x(long param_1,long param_2)\n{\n  return;\n}\n"
    caller = "void g(void)\n{\n  FUN_x(0,1);\n  return;\n}\n"
    assert _yay({"g": caller, "FUN_x": callee}, "FUN_x", ["g"]) == {}
    caller2 = "void my_assemble_global(void)\n{\n  FUN_x(0,1);\n  return;\n}\n"
    got = _yay({"my_assemble_global": caller2, "FUN_x": callee}, "FUN_x", ["my_assemble_global"])
    assert got["param_1"][0] == "K_global"
    assert got["param_1"][1].startswith("Caller hint")
