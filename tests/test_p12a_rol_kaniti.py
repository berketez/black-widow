"""P12a kalem 4 — AD-02: geri çağrı ROLÜ fonksiyon adı değil, köken kaydında rol kanıtı.

Sorun (AD-02, ölçüldü): ``api_param_reverse`` bir ``FUN_`` başka bir API'ye geri çağrı olarak
geçince rol adını (``compare_func``, ``event_callback``) fonksiyon ADI yapıyordu; aynı API'ye
verilen her fonksiyon aynı adı ``_2``, ``_3`` … ekiyle alıyordu. Geliştirme setinde 85 adın 1'i
doğruydu. K-2 (Berke): susturma değil, kanıta dayalı onarım; öğe kanıtı yoksa ad yerine kanıt satırı.

Kural (P12a ön kaydı §1): rol adayı aday listesinden ayrılır, ``naming_provenance.json`` →
``role_evidence``'a ``{role, api, arg_index, caller}`` olarak yazılır; ad verilmez.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_ad_gecerliligi as G  # noqa: E402
import test_c_namer_determinism as T  # noqa: E402
import test_c_namer_susturma as S  # noqa: E402

from karadul.reconstruction import c_namer  # noqa: E402
from karadul.reconstruction.c_namer import _enclosing_call  # noqa: E402


@pytest.fixture
def seri(monkeypatch):
    monkeypatch.setattr(c_namer, "ProcessPoolExecutor", T._SerialExecutor)
    monkeypatch.setattr(c_namer, "_worker_namer", None)


def _alan(root: Path):
    cagiran = ("void FUN_00001000(long param_1,int param_2)\n{\n"
               "  qsort((void *)param_1,(long)param_2,0x10,FUN_00002000);\n"
               "  qsort((void *)param_1,(long)param_2,0x10,FUN_00003000);\n"
               "  signal(0xf,FUN_00004000);\n  return;\n}\n")
    return G._calisma_alani(root, [
        G._fonk("FUN_00001000", "00001000", govde=cagiran),
        G._fonk("FUN_00002000", "00002000"), G._fonk("FUN_00003000", "00003000"),
        G._fonk("FUN_00004000", "00004000"),
    ])


def test_rol_ad_olmaz_kanit_olarak_yazilir(tmp_path, seri):
    res, prov, harita = S._kos(_alan(tmp_path / "ws"), tmp_path / "out")
    for anahtar in ("FUN_00002000", "FUN_00003000", "FUN_00004000"):
        assert anahtar not in harita["global"], anahtar
        assert anahtar not in res.strategy_map, anahtar
    assert not any(v.startswith(("compare_func", "signal_handler")) for v in harita["global"].values())
    assert prov["role_evidence"] == {
        "FUN_00002000": [{"role": "compare_func", "api": "qsort", "arg_index": 3,
                          "caller": "FUN_00001000"}],
        "FUN_00003000": [{"role": "compare_func", "api": "qsort", "arg_index": 3,
                          "caller": "FUN_00001000"}],
        "FUN_00004000": [{"role": "signal_handler", "api": "signal", "arg_index": 1,
                          "caller": "FUN_00001000"}],
    }
    # rol adayı köken kaydında ne yeniden adlandırma ne elenme olarak sayılır
    assert all(r.get("strategy") != "api_param_reverse" for r in prov["global"].values())
    assert S._hesap_tutar(prov)


def test_enclosing_call_cagriyi_ve_arguman_sirasini_bulur():
    govde = ("void f(void){\n  qsort(local_28, (size_t)uVar3, 0x10, FUN_00101000);\n"
             "  event_set(param_1 + 0x48, *(int *)(param_1 + 4), 2, FUN_00102000, param_1);\n"
             "  x = FUN_00103000;\n  signal(0xf,FUN_00104000);\n}\n")
    assert _enclosing_call(govde, "FUN_00101000") == ("qsort", 3)
    assert _enclosing_call(govde, "FUN_00102000") == ("event_set", 3)
    assert _enclosing_call(govde, "FUN_00103000") == ("", -1)      # çağrı içinde değil
    assert _enclosing_call(govde, "FUN_00104000") == ("signal", 1)
    assert _enclosing_call(govde, "FUN_00109999") == ("", -1)      # gövdede yok
