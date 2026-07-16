"""Cephe 1b — Alg 1 (cross-function pass-through param miras) testleri.

`_propagate_passthrough_params` caller'ın BOŞ param_N'lerine, çağrılan iç
fonksiyonun çözülmüş param adını miras ettirir. call-graph.json argüman
POZİSYONU içermediğinden pozisyon decompiled `.c` çağrı-site ifadesinden parse
edilir (copy-propagation alias'ıyla). Yüksek precision riski var → 7 guard.

Bu testler:
  1. temel miras (düz param + local_X alias),
  2. her guard'ın (conf eşiği, boş-hedef, variadik, arg-sayısı, çoklu-atama
     alias, karmaşık arg, tip çelişkisi, self-recursion) GERÇEKTEN koruduğunu,
  3. fixed-point (transitif zincir) + sönümleme,
  4. DİFERANSİYEL ENJEKSİYON: guard koşulunu tersine çevir → mirasın AÇILDIĞINI
     göster (guard'ın load-bearing olduğunu kanıtla — 'yeşil test kanıt değil').

Sentetik gövdeler — fixture/leakage bağımsız.
"""
from __future__ import annotations

import textwrap

import pytest

from karadul.config import Config
from karadul.reconstruction.c_namer import CVariableNamer, _NamingCandidate


def _make_namer(bodies: dict[str, str],
                seed: dict[str, list[tuple[str, str, float]]] | None = None,
                min_conf: float = 0.15) -> CVariableNamer:
    """func_bodies + önceden-çözülmüş adaylarla namer kur.

    seed: {"func::param_N": [(new_name, strategy, conf), ...]}
    """
    n = CVariableNamer(Config(), min_confidence=min_conf)
    n._func_bodies = {k: textwrap.dedent(v) for k, v in bodies.items()}
    n._candidates = {}
    for key, cands in (seed or {}).items():
        old = key.split("::", 1)[1]
        n._candidates[key] = [
            _NamingCandidate(old_name=old, new_name=nm, confidence=cf, strategy=st)
            for nm, st, cf in cands
        ]
    return n


def _passthrough_of(n: CVariableNamer, key: str) -> tuple[str, float] | None:
    """key için 'passthrough' stratejili adayı (name, conf) döndür (yoksa None)."""
    for c in n._candidates.get(key, []):
        if c.strategy == "passthrough":
            return (c.new_name, c.confidence)
    return None


# gnulib buffer-fonksiyon iskeleti: leaf process_bytes'ın imzası (param sayısı
# için gövde şart) + adayı seed'lenir; caller onu miras eder.
_LEAF_BODY = """\
    void _leaf(ulong param_1,ulong param_2)
    {
      x = param_1;
      y = param_2;
    }
"""


# ---------------------------------------------------------------------------
# 1. Temel miras
# ---------------------------------------------------------------------------
def test_inherit_direct_param_arg():
    """caller BOŞ param'ı, callee'nin adlandırdığı pozisyona DÜZ geçiyorsa miras."""
    n = _make_namer(
        {
            "_leaf": _LEAF_BODY,
            "_caller": "void _caller(ulong param_1)\n{\n  _leaf(param_1,0);\n}\n",
        },
        seed={"_leaf::param_1": [("len", "body_param", 0.42)]},
    )
    n._propagate_passthrough_params()
    got = _passthrough_of(n, "_caller::param_1")
    assert got is not None and got[0] == "len"
    assert got[1] == pytest.approx(0.42 * 0.85)  # sönümleme


def test_inherit_via_local_alias_copy_prop():
    """O0 stack-dökümü: local_X = param_N; callee(local_X) -> alias üzerinden miras."""
    n = _make_namer(
        {
            "_leaf": _LEAF_BODY,
            "_caller": ("void _caller(ulong param_1)\n{\n"
                        "  local_18 = param_1;\n  _leaf(local_18,0);\n}\n"),
        },
        seed={"_leaf::param_1": [("len", "body_param", 0.42)]},
    )
    n._propagate_passthrough_params()
    assert _passthrough_of(n, "_caller::param_1") == ("len", pytest.approx(0.42 * 0.85))


# ---------------------------------------------------------------------------
# 2. Guard'lar — miras YAPILMAMALI
# ---------------------------------------------------------------------------
def test_guard_source_conf_below_threshold():
    """GUARD #1: kaynak conf < 0.40 (gürültülü) -> miras YOK."""
    n = _make_namer(
        {"_leaf": _LEAF_BODY,
         "_caller": "void _caller(ulong param_1)\n{\n  _leaf(param_1,0);\n}\n"},
        seed={"_leaf::param_1": [("buf", "body_param", 0.35)]},  # < 0.40
    )
    n._propagate_passthrough_params()
    assert _passthrough_of(n, "_caller::param_1") is None


def test_guard_only_empty_target_not_overwritten():
    """GUARD #2: hedef param'ın zaten adayı varsa EZME."""
    n = _make_namer(
        {"_leaf": _LEAF_BODY,
         "_caller": "void _caller(ulong param_1)\n{\n  _leaf(param_1,0);\n}\n"},
        seed={
            "_leaf::param_1": [("len", "body_param", 0.42)],
            "_caller::param_1": [("count", "dataflow", 0.55)],  # zaten var
        },
    )
    n._propagate_passthrough_params()
    assert _passthrough_of(n, "_caller::param_1") is None  # passthrough EKLENMEDİ


def test_guard_variadic_callee_skipped():
    """GUARD #3: variadic callee (...) -> pozisyon güvensiz -> miras YOK."""
    n = _make_namer(
        {"_leaf": "void _leaf(ulong param_1,...)\n{\n  x = param_1;\n}\n",
         "_caller": "void _caller(ulong param_1)\n{\n  _leaf(param_1,0);\n}\n"},
        seed={"_leaf::param_1": [("len", "body_param", 0.42)]},
    )
    n._propagate_passthrough_params()
    assert _passthrough_of(n, "_caller::param_1") is None


def test_guard_arg_count_mismatch_skipped():
    """GUARD #3: çağrı arg sayısı != callee param sayısı -> miras YOK."""
    n = _make_namer(
        {"_leaf": _LEAF_BODY,  # 2 param
         "_caller": "void _caller(ulong param_1)\n{\n  _leaf(param_1);\n}\n"},  # 1 arg
        seed={"_leaf::param_1": [("len", "body_param", 0.42)]},
    )
    n._propagate_passthrough_params()
    assert _passthrough_of(n, "_caller::param_1") is None


def test_guard_multiassign_alias_untrusted():
    """GUARD #4: local_X birden fazla atanıyorsa (yeniden-kullanılan slot) alias
    güvensiz -> miras YOK."""
    n = _make_namer(
        {"_leaf": _LEAF_BODY,
         "_caller": ("void _caller(ulong param_1)\n{\n"
                     "  local_18 = param_1;\n  local_18 = other;\n"  # 2. atama
                     "  _leaf(local_18,0);\n}\n")},
        seed={"_leaf::param_1": [("len", "body_param", 0.42)]},
    )
    n._propagate_passthrough_params()
    assert _passthrough_of(n, "_caller::param_1") is None


def test_guard_impure_alias_rhs_not_trusted():
    """GUARD (alias saflığı): `local_X = param_N OP ...;` (aritmetik/deref/
    karşılaştırma) SAF KOPYA DEĞİL → local param'ın türevidir, kendisi değil →
    alias kurulmaz → miras YOK. Reviewer bulgusu (2026-07-16): eski regex
    `param_N\\b` trailing içeriği yoksayıp `param_1 + 4`'ü de param_1 sanıyordu."""
    for rhs in ("param_1 + 4", "param_1->field", "param_1 == 0", "param_1 << 3"):
        n = _make_namer(
            {"_leaf": _LEAF_BODY,
             "_caller": (f"void _caller(ulong param_1)\n{{\n"
                         f"  local_18 = {rhs};\n  _leaf(local_18,0);\n}}\n")},
            seed={"_leaf::param_1": [("len", "body_param", 0.42)]},
        )
        n._propagate_passthrough_params()
        assert _passthrough_of(n, "_caller::param_1") is None, f"rhs={rhs}"
    # DİFERANSİYEL: saf kopya (`local = param;`) -> alias güvenilir -> miras açılır.
    n2 = _make_namer(
        {"_leaf": _LEAF_BODY,
         "_caller": ("void _caller(ulong param_1)\n{\n"
                     "  local_18 = param_1;\n  _leaf(local_18,0);\n}\n")},
        seed={"_leaf::param_1": [("len", "body_param", 0.42)]},
    )
    n2._propagate_passthrough_params()
    assert _passthrough_of(n2, "_caller::param_1") == ("len", pytest.approx(0.42 * 0.85))


def test_guard_complex_arg_skipped():
    """GUARD (§6.3): karmaşık arg (param+off / &local / cast) -> miras YOK
    (o farklı bir değer, param'ın kendisi değil)."""
    for call in ("_leaf(param_1 + 4,0);", "_leaf(&local_18,0);",
                 "_leaf((long)param_1,0);"):
        n = _make_namer(
            {"_leaf": _LEAF_BODY,
             "_caller": f"void _caller(ulong param_1)\n{{\n  {call}\n}}\n"},
            seed={"_leaf::param_1": [("len", "body_param", 0.42)]},
        )
        n._propagate_passthrough_params()
        assert _passthrough_of(n, "_caller::param_1") is None, f"arg={call}"


def test_guard_type_mismatch_ptr_scalar_skipped():
    """GUARD #5: açık ptr↔scalar tip çelişkisi -> miras YOK."""
    n = _make_namer(
        {"_leaf": _LEAF_BODY,  # param_1 scalar (ulong)
         "_caller": "void _caller(uint *param_1)\n{\n  _leaf(param_1,0);\n}\n"},  # ptr
        seed={"_leaf::param_1": [("len", "body_param", 0.42)]},
    )
    n._propagate_passthrough_params()
    assert _passthrough_of(n, "_caller::param_1") is None


def test_guard_self_recursion_skipped():
    """GUARD #7: self-edge (fonksiyon kendini çağırıyor) -> miras YOK."""
    # _rec(param_1, param_2) kendini SWAP argümanla çağırır: self-edge guard
    # olmasa param_2, _rec pos0 (len) mirası alırdı.
    n = _make_namer(
        {"_rec": ("void _rec(ulong param_1,ulong param_2)\n{\n"
                  "  _rec(param_2,param_1);\n}\n")},
        seed={"_rec::param_1": [("len", "body_param", 0.42)]},
    )
    n._propagate_passthrough_params()
    assert _passthrough_of(n, "_rec::param_2") is None


# ---------------------------------------------------------------------------
# 3. Fixed-point (transitif zincir) + sönümleme
# ---------------------------------------------------------------------------
def test_fixed_point_transitive_two_hops():
    """Zincir X->Y->Z: Z leaf adlı, Y ve X boş. Y round1'de Z'den, X round2'de
    Y'den miras almalı (fixed-point 2 tur).

    Leaf conf 0.50: hop1=0.425 HÂLÂ ≥0.40 kaynak eşiği → 2. hop'a yeter. (Not:
    daha düşük leaf ör. 0.42 tek hop'ta ölür — sönümleme+eşik zinciri sınırlar,
    tasarım §6.2 #6 kasıtlı davranış.)"""
    n = _make_namer(
        {
            "_z": "void _z(ulong param_1)\n{\n  x = param_1;\n}\n",
            "_y": "void _y(ulong param_1)\n{\n  _z(param_1);\n}\n",
            "_x": "void _x(ulong param_1)\n{\n  _y(param_1);\n}\n",
        },
        seed={"_z::param_1": [("len", "body_param", 0.50)]},
    )
    n._propagate_passthrough_params()
    y = _passthrough_of(n, "_y::param_1")
    x = _passthrough_of(n, "_x::param_1")
    assert y is not None and y[0] == "len"
    assert x is not None and x[0] == "len"
    # sönümleme: Y = 0.50*0.85, X = Y*0.85 (iki hop)
    assert y[1] == pytest.approx(0.50 * 0.85)
    assert x[1] == pytest.approx(0.50 * 0.85 * 0.85)


# ---------------------------------------------------------------------------
# 4. DİFERANSİYEL ENJEKSİYON — guard koşulunu tersine çevir, miras AÇILIR
# ---------------------------------------------------------------------------
def test_injection_variadic_removed_reenables_inheritance():
    """MUTASYON: callee'den `...` kaldırılınca (arg sayısı = param sayısı olunca)
    AYNI kurulum miras ÜRETİR. Variadik guard'ı load-bearing."""
    base = {
        "_caller": "void _caller(ulong param_1)\n{\n  _leaf(param_1,0);\n}\n",
    }
    seed = {"_leaf::param_1": [("len", "body_param", 0.42)]}
    # variadic -> engellenir
    n1 = _make_namer({**base, "_leaf": "void _leaf(ulong param_1,...)\n{\n x=param_1;\n}\n"}, seed)
    n1._propagate_passthrough_params()
    assert _passthrough_of(n1, "_caller::param_1") is None
    # variadic YOK (2 gerçek param) -> miras açılır
    n2 = _make_namer({**base, "_leaf": _LEAF_BODY}, seed)
    n2._propagate_passthrough_params()
    assert _passthrough_of(n2, "_caller::param_1") == ("len", pytest.approx(0.42 * 0.85))


def test_injection_alias_singleassign_reenables_inheritance():
    """MUTASYON: local_X'in 2. atamasını kaldırınca (tek düz atama olunca) alias
    güvenilir olur, miras açılır. Çoklu-atama guard'ı load-bearing."""
    seed = {"_leaf::param_1": [("len", "body_param", 0.42)]}
    body_multi = ("void _caller(ulong param_1)\n{\n"
                  "  local_18 = param_1;\n  local_18 = other;\n  _leaf(local_18,0);\n}\n")
    body_single = ("void _caller(ulong param_1)\n{\n"
                   "  local_18 = param_1;\n  _leaf(local_18,0);\n}\n")
    n1 = _make_namer({"_leaf": _LEAF_BODY, "_caller": body_multi}, seed)
    n1._propagate_passthrough_params()
    assert _passthrough_of(n1, "_caller::param_1") is None
    n2 = _make_namer({"_leaf": _LEAF_BODY, "_caller": body_single}, seed)
    n2._propagate_passthrough_params()
    assert _passthrough_of(n2, "_caller::param_1") == ("len", pytest.approx(0.42 * 0.85))


def test_injection_typematch_reenables_inheritance():
    """MUTASYON: caller param tipini ptr'dan scalar'a çevirince tip uyar, miras
    açılır. Tip-uyumu guard'ı load-bearing."""
    seed = {"_leaf::param_1": [("len", "body_param", 0.42)]}
    n1 = _make_namer(
        {"_leaf": _LEAF_BODY, "_caller": "void _caller(uint *param_1)\n{\n _leaf(param_1,0);\n}\n"},
        seed)
    n1._propagate_passthrough_params()
    assert _passthrough_of(n1, "_caller::param_1") is None
    n2 = _make_namer(
        {"_leaf": _LEAF_BODY, "_caller": "void _caller(ulong param_1)\n{\n _leaf(param_1,0);\n}\n"},
        seed)
    n2._propagate_passthrough_params()
    assert _passthrough_of(n2, "_caller::param_1") == ("len", pytest.approx(0.42 * 0.85))


def test_injection_conf_threshold_reenables_inheritance():
    """MUTASYON: kaynak conf'unu 0.35'ten 0.42'ye çıkarınca eşiği geçer, miras
    açılır. Conf-eşiği guard'ı load-bearing."""
    base = {"_leaf": _LEAF_BODY,
            "_caller": "void _caller(ulong param_1)\n{\n _leaf(param_1,0);\n}\n"}
    n1 = _make_namer(base, seed={"_leaf::param_1": [("buf", "body_param", 0.35)]})
    n1._propagate_passthrough_params()
    assert _passthrough_of(n1, "_caller::param_1") is None
    n2 = _make_namer(base, seed={"_leaf::param_1": [("len", "body_param", 0.42)]})
    n2._propagate_passthrough_params()
    assert _passthrough_of(n2, "_caller::param_1") is not None
