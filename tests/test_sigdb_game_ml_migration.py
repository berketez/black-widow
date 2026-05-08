"""sig_db game_ml migration testleri (Faz A-DELETE sonrasi).

v1.13 Dalga 2 A-DELETE: legacy ``_*_SIGNATURES`` inline literal bloklari
silindi, signature_db.py artik
``from sigdb_builtin.game_ml import SIGNATURES`` referansi uzerinden
dogrudan import yapiyor. AST parse parity testleri tautolojik hale geldigi
icin kaldirildi.

Korunan parity katmanlari:
1. Runtime identity (``is`` check)
2. Coverage count
3. Cross-dict overlap kontrolu
4. Bilinen sembol lookup
5. Post-A-DELETE: signature_db.py'da inline literal YOK + dogrudan
   ``_BUILTIN_GAME_ML_SIGS`` referansi VAR.

Kapsam (5 alt-kategori, 750 imza):
  - ml_compute_signatures        (74 entry)
  - game_engine_signatures       (73 entry)
  - anti_analysis_signatures     (14 entry)
  - mega_batch_1_signatures      (329 entry)
  - mega_batch_2_signatures      (260 entry)
"""
from __future__ import annotations

import pytest


_KEY_TO_ORIG: dict[str, str] = {
    "ml_compute_signatures": "_ML_COMPUTE_SIGNATURES",
    "game_engine_signatures": "_GAME_ENGINE_SIGNATURES",
    "anti_analysis_signatures": "_ANTI_ANALYSIS_SIGNATURES",
    "mega_batch_1_signatures": "_MEGA_BATCH_1_SIGNATURES",
    "mega_batch_2_signatures": "_MEGA_BATCH_2_SIGNATURES",
}

_EXPECTED_COUNTS: dict[str, int] = {
    "ml_compute_signatures": 74,
    "game_engine_signatures": 73,
    "anti_analysis_signatures": 14,
    "mega_batch_1_signatures": 329,
    "mega_batch_2_signatures": 260,
}


# ---------------------------------------------------------------------------
# 1. Modul yuklenebilirlik + ust seviye yapi
# ---------------------------------------------------------------------------

def test_sigdb_builtin_game_ml_importable() -> None:
    """sigdb_builtin.game_ml import edilebilir ve SIGNATURES dict'i var."""
    from karadul.analyzers.sigdb_builtin import game_ml as gm

    assert hasattr(gm, "SIGNATURES")
    assert isinstance(gm.SIGNATURES, dict)
    assert len(gm.SIGNATURES) == 5


def test_sigdb_builtin_game_ml_has_expected_keys() -> None:
    """SIGNATURES tam olarak 5 top-level alt-dict icerir."""
    from karadul.analyzers.sigdb_builtin import game_ml as gm

    assert set(gm.SIGNATURES.keys()) == set(_KEY_TO_ORIG.keys())


# ---------------------------------------------------------------------------
# 2. Coverage count
# ---------------------------------------------------------------------------

def test_coverage_count() -> None:
    """Her alt-dict beklenen entry sayisina sahip; toplam 750."""
    from karadul.analyzers.sigdb_builtin import game_ml as gm

    for key, count in _EXPECTED_COUNTS.items():
        actual = len(gm.SIGNATURES[key])
        assert actual == count, f"{key}: expected {count}, got {actual}"

    total = sum(len(v) for v in gm.SIGNATURES.values())
    assert total == 750, f"game_ml total: expected 750, got {total}"


# ---------------------------------------------------------------------------
# 3. Runtime identity
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("builtin_key,legacy_name", sorted(_KEY_TO_ORIG.items()))
def test_runtime_identity_each_dict(builtin_key: str, legacy_name: str) -> None:
    """signature_db._<NAME> ile builtin game_ml[<key>] AYNI obje (`is`)."""
    from karadul.analyzers import signature_db as sdb
    from karadul.analyzers.sigdb_builtin import game_ml as gm

    legacy = getattr(sdb, legacy_name)
    migrated = gm.SIGNATURES[builtin_key]
    assert legacy is migrated, (
        f"{legacy_name} <-> {builtin_key} runtime identity ihlali"
    )
    assert len(migrated) == _EXPECTED_COUNTS[builtin_key]


# ---------------------------------------------------------------------------
# 4. Anahtar kesismez (cross-dict overlap)
# ---------------------------------------------------------------------------

def test_no_duplicate_keys() -> None:
    """5 alt-dict arasinda anahtar kesişimi yok."""
    from karadul.analyzers.sigdb_builtin import game_ml as gm

    seen: dict[str, str] = {}
    collisions: list[tuple[str, str, str]] = []
    for sub_name, sub_dict in gm.SIGNATURES.items():
        for key in sub_dict:
            if key in seen:
                collisions.append((key, seen[key], sub_name))
            else:
                seen[key] = sub_name
    assert not collisions, (
        f"Cross-dict anahtar kesişimi tespit edildi (ilk 5): "
        f"{collisions[:5]}"
    )


# ---------------------------------------------------------------------------
# 5. Dispatcher (get_category) calisiyor mu?
# ---------------------------------------------------------------------------

def test_get_category_game_ml_returns_data() -> None:
    """sigdb_builtin.get_category('game_ml') 5 anahtarli dolu dict dondurur."""
    from karadul.analyzers.sigdb_builtin import get_category

    sigs = get_category("game_ml")
    assert isinstance(sigs, dict)
    assert len(sigs) == 5
    for key in _KEY_TO_ORIG:
        assert key in sigs


# ---------------------------------------------------------------------------
# 6. Bilinen sembol lookup'lari (smoke test)
# ---------------------------------------------------------------------------

def test_known_cuda_symbol() -> None:
    """CUDA temel API tasinmis ve dogru meta tasiyor."""
    from karadul.analyzers.sigdb_builtin import game_ml as gm

    ml = gm.SIGNATURES["ml_compute_signatures"]
    assert "cudaMalloc" in ml
    assert ml["cudaMalloc"]["lib"] == "cuda"
    assert ml["cudaMalloc"]["category"] == "gpu_compute"

    assert "cv::imread" in ml
    assert ml["cv::imread"]["category"] == "cv"


def test_known_unreal_godot_symbols() -> None:
    """Unreal + Godot + Box2D + GLFW + ImGui sembolleri mevcut."""
    from karadul.analyzers.sigdb_builtin import game_ml as gm

    ge = gm.SIGNATURES["game_engine_signatures"]
    assert "UObject::ProcessEvent" in ge
    assert ge["UObject::ProcessEvent"]["lib"] == "unreal"

    assert "godot_gdnative_init" in ge
    assert ge["godot_gdnative_init"]["lib"] == "godot"

    assert "b2World::Step" in ge
    assert ge["b2World::Step"]["category"] == "physics"

    assert "glfwCreateWindow" in ge
    assert ge["glfwCreateWindow"]["category"] == "windowing"

    assert "ImGui::Begin" in ge
    assert ge["ImGui::Begin"]["category"] == "gui"


def test_known_anti_analysis_symbol() -> None:
    """Anti-debug + anti-VM + packer sembolleri korunmus."""
    from karadul.analyzers.sigdb_builtin import game_ml as gm

    aa = gm.SIGNATURES["anti_analysis_signatures"]
    assert "ptrace_PTRACE_TRACEME" in aa
    assert aa["ptrace_PTRACE_TRACEME"]["category"] == "anti_debug"

    assert "cpuid_hypervisor_detect" in aa
    assert aa["cpuid_hypervisor_detect"]["category"] == "anti_vm"

    assert "vmprotect_entry" in aa
    assert aa["vmprotect_entry"]["category"] == "packer"


def test_known_mega_batch_1_symbol() -> None:
    """MEGA_BATCH_1: MSVC CRT + STL + math sembolleri korunmus."""
    from karadul.analyzers.sigdb_builtin import game_ml as gm

    mb1 = gm.SIGNATURES["mega_batch_1_signatures"]
    assert "_open" in mb1 and mb1["_open"]["lib"] == "msvcrt"
    assert "sprintf_s" in mb1 and mb1["sprintf_s"]["category"] == "win_crt"
    assert "std::string::c_str" in mb1
    assert mb1["std::string::c_str"]["category"] == "cpp_stl"
    assert "std::vector::push_back" in mb1
    assert "__cxa_throw" in mb1
    assert mb1["__cxa_throw"]["category"] == "cpp_exception"
    assert "sin" in mb1 and mb1["sin"]["lib"] == "libm"
    assert "sqrtf" in mb1 and mb1["sqrtf"]["category"] == "math"


def test_known_mega_batch_2_symbol() -> None:
    """MEGA_BATCH_2: ObjC runtime + Foundation + Swift + Swift concurrency."""
    from karadul.analyzers.sigdb_builtin import game_ml as gm

    mb2 = gm.SIGNATURES["mega_batch_2_signatures"]
    assert "_objc_msgSend" in mb2
    assert mb2["_objc_msgSend"]["category"] == "objc_runtime"
    assert "_NSLog" in mb2 and mb2["_NSLog"]["lib"] == "Foundation"
    assert "-[NSObject init]" in mb2
    assert mb2["-[NSObject init]"]["category"] == "foundation"
    assert "_swift_retain" in mb2
    assert mb2["_swift_retain"]["category"] == "swift"
    assert "_swift_task_create" in mb2
    assert mb2["_swift_task_create"]["category"] == "swift_concurrency"


# ---------------------------------------------------------------------------
# 7. Veri yapi tutarliligi
# ---------------------------------------------------------------------------

def test_entry_schema_consistency() -> None:
    """Tum entry'ler {'lib','purpose','category'} string alanlarina sahip."""
    from karadul.analyzers.sigdb_builtin import game_ml as gm

    required = {"lib", "purpose", "category"}
    for sub_name, sub_dict in gm.SIGNATURES.items():
        for key, info in sub_dict.items():
            assert isinstance(info, dict), (
                f"{sub_name}[{key!r}]: dict bekleniyor, {type(info).__name__}"
            )
            missing = required - set(info)
            assert not missing, (
                f"{sub_name}[{key!r}]: eksik alanlar {missing}"
            )
            for field in required:
                assert isinstance(info[field], str), (
                    f"{sub_name}[{key!r}][{field!r}]: str bekleniyor, "
                    f"{type(info[field]).__name__}"
                )


# ---------------------------------------------------------------------------
# 8. Post-A-DELETE: legacy literal silindi, dogrudan referans
# ---------------------------------------------------------------------------

def test_post_a_delete_no_inline_literal() -> None:
    """signature_db.py'da legacy ``_<KAT>_SIGNATURES = {...}`` literal'leri YOK."""
    from pathlib import Path

    text = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    assert (
        '_ML_COMPUTE_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_GAME_ML_SIGS["ml_compute_signatures"]'
    ) in text
    assert (
        '_MEGA_BATCH_1_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_GAME_ML_SIGS["mega_batch_1_signatures"]'
    ) in text
    assert (
        '_MEGA_BATCH_2_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_GAME_ML_SIGS["mega_batch_2_signatures"]'
    ) in text
    for legacy in _KEY_TO_ORIG.values():
        assert f'\n{legacy}: dict[str, dict[str, str]] = {{' not in text, (
            f"{legacy} hala inline literal olarak duruyor"
        )


def test_post_a_delete_direct_import() -> None:
    """signature_db.py game_ml SIGNATURES'i ``sigdb_builtin.game_ml``'dan dogrudan alir."""
    from pathlib import Path

    text = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    assert "_BUILTIN_GAME_ML_SIGS" in text
    assert "sigdb_builtin" in text and "game_ml" in text


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
