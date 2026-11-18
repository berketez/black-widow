"""P22e — KaradulLM oturumu: tekrar anahtarı, defter, oturum yaşam döngüsü, plan, iptal / devam.

Bölümler:
  (0) ``Agent._call_key``: ``find_path``'in ``to``'su da tek yazıma (P22d bulgusu; tekrar yakalanır).

Gerçek model yok: sahte arka uç (``FakeBackend``) ve sentetik çalışma alanı (``tests/test_lm_tools.py``).
Mutasyon koruması: ``scripts/measurement/mutation_specs_lm_oturum.json``.
"""
from __future__ import annotations

import json

from karadul.lm import agent as G
from karadul.lm import backend as B
from karadul.lm import tools as T
from tests.test_lm_tools import A, D, default_ws, fun


def _cagri(tool: str, **args) -> B.FakeReply:
    return B.FakeReply(content=json.dumps({"kind": "call", "tool": tool, "args": args}))


_CEKIMSER = B.FakeReply(content=json.dumps({"kind": "final", "isim": None, "gerekce": "Eksik.", "cekimser": True,
                                            "kanit": []}))


# --------------------------------------------------------------------------------------------
# (0) tekrar anahtarı: bütün adres argümanları tek yazıma


def test_tekrar_anahtari_find_path_hedefini_de_tek_yaziya_cevirir(tmp_path):
    ws = T.Workspace(default_ws(tmp_path / "ws"))
    arka = B.FakeBackend([
        _cagri("find_path", addr=fun(D), to="FUN_1000"),            # çalışır
        _cagri("find_path", addr=fun(D), to=fun(A)),                 # aynı çağrı, dolgulu yazım → tekrar
        _cagri("find_path", addr="FUN_4000", to="FUN_00001000"),     # iki uç da başka yazım → tekrar
        _cagri("find_path", addr=fun(D), to=fun(A), max_depth=2),    # başka argüman → yeni çağrı
        _CEKIMSER])
    ajan = G.Agent(arka, ws, registry=T.full_registry(), enabled_modes=("K0", "K2"))
    r = ajan.run_loop(fun(A))
    c = r.counters
    assert r.status == "tamam"
    assert (c.call_requests, c.tool_calls, c.repeats) == (4, 2, 2)
    # anahtar: iki adres alanı da ``FUN_<çalışma alanı yazımı>``; tanınmayan adres olduğu gibi kalır
    k1 = ajan._call_key("find_path", {"addr": "FUN_4000", "to": "FUN_1000"})
    k2 = ajan._call_key("find_path", {"addr": fun(D), "to": fun(A)})
    assert k1 == k2 and json.loads(k1[1])["to"] == fun(A)
    assert json.loads(ajan._call_key("find_path", {"addr": fun(D), "to": "FUN_fffff"})[1])["to"] == "FUN_fffff"
