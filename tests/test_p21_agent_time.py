"""P21 / LM-06 — iptal görev başınadır; süre bütçesi öntanımda uygulanır.

Kusur (``kulvar_LM.md`` LM-06): ``Agent.cancel`` ajan ömrünce tek bir olaydı ve hiç temizlenmiyordu:
bir kez "durdur"a basılınca sonraki her görev model çağrılmadan ``iptal`` bitiyordu. ``time_budget_sec``
ürün kodunda çağrılmıyordu; ``deadline_sec`` öntanımı ``None`` idi, K0'da süre denetimi hiç yoktu.
Burada sahte arka uç ve sahte saatle: model yok.

Mutasyon koruması: ``scripts/measurement/mutation_specs_p21.json``.
"""
from __future__ import annotations

import json

import karadul.lm as LM
from karadul.lm import agent as G
from karadul.lm import backend as B
from karadul.lm import tools as T
from karadul.lm.audit import AuditLog
from tests.test_lm_tools import A, CB, default_ws, fun

YOK = {"isim": None, "gerekce": "Kanıt yetersiz.", "cekimser": True, "kanit": []}


def _yok(**kw):
    return B.FakeReply(content=json.dumps(YOK), **kw)


def _son(**kw):
    return B.FakeReply(content=json.dumps({"kind": "final", **YOK}), **kw)


def _ajan(tmp_path, yanitlar, **kw):
    arka = B.FakeBackend(yanitlar, audit=AuditLog())
    return G.Agent(arka, T.Workspace(default_ws(tmp_path / "ws")), **kw), arka


def test_iptal_sonraki_gorevi_etkilemez(tmp_path):
    cagri = B.FakeReply(content=json.dumps({"kind": "call", "tool": "get_evidence", "args": {"addr": fun(CB)}}),
                        delay_sec=1)
    ajan, arka = _ajan(tmp_path, [cagri, _yok(), _yok()], enabled_modes=("K0", "K2"))
    arka._sleep = lambda s: ajan.cancel_current()                    # görev sürerken "durdur"
    assert ajan.run_loop(fun(A)).status == "iptal" and len(arka.calls) == 1
    sonraki = [ajan.suggest_name(fun(a)) for a in (A, CB)]
    assert [r.status for r in sonraki] == ["tamam", "tamam"] and len(arka.calls) == 3


def test_bosta_iptal_bir_sey_yapmaz(tmp_path):
    ajan, arka = _ajan(tmp_path, [_yok(delay_sec=1)])
    assert ajan.cancel_current() is False and not ajan.cancel.is_set()
    ajan.cancel.set()                                                 # dışarıdan, görev yokken kurulmuş
    assert ajan.suggest_name(fun(A)).status == "tamam" and len(arka.calls) == 1
    gorulen = []
    ajan2, arka2 = _ajan(tmp_path / "2", [B.FakeReply(content="json yok", delay_sec=1), _yok()], )
    ajan2.backend.level = "L2"                                        # onarım turu öncesi iptal bakılır
    arka2._sleep = lambda s: gorulen.append(ajan2.cancel_current())
    r = ajan2.suggest_name(fun(A))
    assert gorulen == [True] and (r.status, len(arka2.calls)) == ("iptal", 1)


def test_oentanimli_sure_butcesi(tmp_path):
    ajan, _ = _ajan(tmp_path, [_yok()], enabled_modes=("K0", "K1", "K2"))
    assert LM.TASK_TIME_BUDGET_FALLBACK_SEC == float(LM.REQUEST_TIMEOUT_SEC) == 900.0
    assert ajan.default_time_budget_sec("K0") == 900.0 == ajan.default_time_budget_sec("K2")
    r = ajan.suggest_name(fun(A))
    assert r.time_budget_sec == 900.0
    assert [k for k in ajan.audit.records if k["olay"] == "gorev"][0]["sure_butcesi_sn"] == 900.0
    ajan.expected_task_sec = 10.0                                     # hız ölçüldü: 4 × beklenen × tur
    assert ajan.default_time_budget_sec("K0") == 40.0
    assert ajan.default_time_budget_sec("K1") == 4 * 10.0 * (LM.MAX_TOOL_CALLS_K1 + 1) == 120.0
    assert ajan.default_time_budget_sec("K2") == 4 * 10.0 * (LM.MAX_TOOL_CALLS + 1) == 360.0
    for bozuk in (0, -1.0, True, None):
        ajan.expected_task_sec = bozuk
        assert ajan.default_time_budget_sec("K0") == 900.0


def test_k0_sure_dolunca_model_cagrilmaz_ve_onarim_turu_atilmaz(tmp_path):
    simdi = [0.0]
    ajan, arka = _ajan(tmp_path / "1", [_yok()], clock=lambda: simdi[0], expected_task_sec=1.0)
    asil = ajan.registry.call

    def yavas(*a, **k):
        simdi[0] += 3.0                                               # paket kurulumu bütçeyi (4 sn) aşar
        return asil(*a, **k)

    ajan.registry.call = yavas
    r = ajan.suggest_name(fun(A))
    assert (r.status, len(arka.calls), r.time_budget_sec) == ("sure_asimi", 0, 4.0)
    # L2 onarım turu: ilk cevap bütçeyi aşınca ikinci istek atılmaz
    simdi[0] = 0.0
    ajan, arka = _ajan(tmp_path / "2", [B.FakeReply(content="json yok", delay_sec=10), _yok()],
                       clock=lambda: simdi[0], expected_task_sec=1.0)
    arka.level = "L2"
    arka._sleep = lambda s: simdi.__setitem__(0, simdi[0] + s)
    r = ajan.suggest_name(fun(A))
    assert (r.status, len(arka.calls)) == ("sure_asimi", 1)
    # açık deadline_sec öntanımın önüne geçer
    simdi[0] = 0.0
    ajan, arka = _ajan(tmp_path / "3", [_yok(delay_sec=10)], clock=lambda: simdi[0], expected_task_sec=1.0)
    arka._sleep = lambda s: simdi.__setitem__(0, simdi[0] + s)
    assert ajan.suggest_name(fun(A), deadline_sec=100.0).status == "tamam"


def test_dongu_oentanimda_sure_asimi(tmp_path):
    simdi = [0.0]
    cagri = B.FakeReply(content=json.dumps({"kind": "call", "tool": "get_evidence", "args": {"addr": fun(CB)}}),
                        delay_sec=1000)
    ajan, arka = _ajan(tmp_path, [cagri, _son()], clock=lambda: simdi[0], enabled_modes=("K0", "K2"))
    arka._sleep = lambda s: simdi.__setitem__(0, simdi[0] + s)
    r = ajan.run_loop(fun(A))                                         # deadline_sec verilmedi
    assert (r.status, len(arka.calls), r.time_budget_sec) == ("sure_asimi", 1, 900.0)
