"""Mutasyon-oldurucu testler: _add_computation source-bazli conf esikleri.

Faz-1 mutasyon denetimi 1 GERCEK deligi (+ ikiz) buldu:

  D  _feedback_naming_candidates.py:518
       `if cand_src == "signature_fusion" and cand_conf < 0.40:`  -> `< 0.0:`
  D' (ikiz) satir 520
       `if cand_src == "callee_profile" and cand_conf < 0.30:`    -> `< 0.0:`

Bu kapilar dusuk-guvenli fusion/profile adaylarinin (gurultu) aday havuzuna
sizmasini engeller. Esik 0.0'a dusurulurse 0.35/0.25 gibi zayif adaylar
EKLENIR (FP). Test: esik ALTINDAKI aday EKLENMEMELI, esik USTUNDEKI eklenmeli.

Kanit (mutation_probe, TUM suite):
  python scripts/mutation_probe.py --spec docs/mutation_specs.json \
      --id d_signature_fusion_conf_gate,d_callee_profile_conf_gate
"""
from __future__ import annotations

from types import SimpleNamespace

from karadul.pipeline.steps._feedback_naming_candidates import _add_computation


def _comp_result(naming_candidates: list[dict]) -> SimpleNamespace:
    """_add_computation'un bekledigi minimal computation_result mock'u."""
    return SimpleNamespace(
        naming_candidates=naming_candidates,
        layer_results={},  # .get("cross_binary_matches", []) -> [] (cross yolu atlanir)
    )


def test_signature_fusion_low_confidence_gate() -> None:
    """signature_fusion conf<0.40 EKLENMEZ; conf>=0.40 eklenir.

    Mutant `< 0.0` -> 0.35'lik zayif aday da eklenir -> assert patlar (KILLED).
    """
    comp = _comp_result([
        {"function_name": "FUN_00000001", "candidate_name": "weak_fusion",
         "confidence": 0.35, "source": "signature_fusion"},
        {"function_name": "FUN_00000002", "candidate_name": "strong_fusion",
         "confidence": 0.45, "source": "signature_fusion"},
    ])
    candidates: dict[str, list] = {}

    _add_computation(comp, candidates, iter_index=0, stats={})

    assert "FUN_00000001" not in candidates, (
        "signature_fusion conf 0.35 < 0.40 esigi -> EKLENMEMELIYDI"
    )
    assert "FUN_00000002" in candidates, (
        "signature_fusion conf 0.45 >= 0.40 -> eklenmeliydi"
    )


def test_callee_profile_low_confidence_gate() -> None:
    """callee_profile conf<0.30 EKLENMEZ; conf>=0.30 eklenir.

    Mutant `< 0.0` -> 0.25'lik zayif aday da eklenir -> assert patlar (KILLED).
    """
    comp = _comp_result([
        {"function_name": "FUN_00000003", "candidate_name": "weak_profile",
         "confidence": 0.25, "source": "callee_profile"},
        {"function_name": "FUN_00000004", "candidate_name": "ok_profile",
         "confidence": 0.35, "source": "callee_profile"},
    ])
    candidates: dict[str, list] = {}

    _add_computation(comp, candidates, iter_index=0, stats={})

    assert "FUN_00000003" not in candidates, (
        "callee_profile conf 0.25 < 0.30 esigi -> EKLENMEMELIYDI"
    )
    assert "FUN_00000004" in candidates, (
        "callee_profile conf 0.35 >= 0.30 -> eklenmeliydi"
    )
