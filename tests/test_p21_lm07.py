"""P21 / LM-07 — sınanmayan yollar: tamsayı değerli kayan nokta argümanı, K1 / K2 zarfının şema alt kümesi.

Kulvar (``kulvar_LM.md`` LM-07) altı boşluk sayıyor: (a) okurken kopma → ``tests/test_p21_backend.py``;
(b) yapışkan iptal → ``tests/test_p21_agent_time.py``; (c) ``2.0`` gibi argüman → burada, kusur onarıldı
(araç ``ic_hata`` dönüyordu); (d) K1 / K2 zarfının motorda derlenmesi → burada yalnız şemanın
desteklenen alt kümede kaldığı ve en büyük K1 adres listesiyle kurulabildiği sınanır; gerçek
``llama-server``'da derlenmesi gerçek modelle doğrulanacaklar listesinde (P21.md); (e), (f) gerçek model
ister (aynı liste). Model yok.

Mutasyon koruması: ``scripts/measurement/mutation_specs_p21.json``.
"""
from __future__ import annotations

import json

from karadul.lm import agent as G
from karadul.lm import backend as B
from karadul.lm import protocol as P
from karadul.lm import tools as T
from tests.test_lm_tools import A, HUB, HUB_CALLEES, HUB_CALLERS, call, default_ws, fun


def test_tamsayi_degerli_kayan_nokta_arguman(tmp_path):
    ws = T.Workspace(default_ws(tmp_path / "ws"))
    for arac, kayan, tam in (
            ("get_xrefs", {"addr": fun(A), "direction": "callers", "offset": 0.0, "limit": 30.0},
             {"addr": fun(A), "direction": "callers", "offset": 0, "limit": 30}),
            ("get_decompiled", {"addr": fun(A), "part": "aralik", "line_from": 2.0, "line_to": 5.0},
             {"addr": fun(A), "part": "aralik", "line_from": 2, "line_to": 5})):
        r1, r2 = call(ws, arac, kayan), call(ws, arac, tam)
        assert r1.ok and r1.envelope() == r2.envelope(), (arac, r1.error)
    # tamsayı olmayan kayan nokta şemaya uymaz: argüman hatası (araç çalışmaz)
    r = call(ws, "get_xrefs", {"addr": fun(A), "direction": "callers", "offset": 0.5})
    assert (r.ok, r.error, r.executed) == (False, "gecersiz_arguman", False)
    assert T.normalize_args({"offset": 3.0, "addr": "x", "limit": True}, {"properties": {
        "offset": {"type": "integer"}, "addr": {"type": "string"}, "limit": {"type": "integer"}}}) == {
        "offset": 3, "addr": "x", "limit": True}


def test_dongude_kayan_nokta_arguman_ve_tekrar(tmp_path):
    def cagri(**args):
        return B.FakeReply(content=json.dumps({"kind": "call", "tool": "get_xrefs", "args": args}))
    son = B.FakeReply(content=json.dumps({"kind": "final", "isim": None, "gerekce": "x", "cekimser": True,
                                          "kanit": []}))
    arka = B.FakeBackend([cagri(addr=fun(A), direction="callers", offset=0.0),
                          cagri(addr=fun(A), direction="callers", offset=0), son])
    ajan = G.Agent(arka, T.Workspace(default_ws(tmp_path / "ws")), enabled_modes=("K0", "K2"))
    r = ajan.run_loop(fun(A))
    c = r.counters
    assert r.status == "tamam" and (c.tool_calls, c.repeats, c.invalid_calls) == (1, 1, 0)
    ilk = json.loads(arka.calls[1]["messages"][-1]["content"].split("\n")[1])
    assert ilk["ok"] is True                                          # eskiden "ic_hata"


def _anahtar_sozcukler(sema) -> set[str]:
    out: set[str] = set()
    if isinstance(sema, dict):
        for k, v in sema.items():
            if k == "properties":
                for alt in v.values():
                    out |= _anahtar_sozcukler(alt)
            else:
                out.add(k)
                if k in ("items",):
                    out |= _anahtar_sozcukler(v)
                elif k == "anyOf":
                    for alt in v:
                        out |= _anahtar_sozcukler(alt)
    return out


def test_k1_k2_zarfi_desteklenen_alt_kumede(tmp_path):
    """En büyük K1 adres listesi (HUB: 35 çağıran + 45 çağrılan + kendisi) ve K2 zarfı kurulabilir, yalnız
    desteklenen anahtar sözcükleri kullanır ve L3 istek gövdesine girer. Motorda derlenmesi BURADA
    SINANMAZ (gerçek sunucu gerekir)."""
    ws = T.Workspace(default_ws(tmp_path / "ws"))
    ajan = G.Agent(B.FakeBackend([]), ws, enabled_modes=("K0", "K1", "K2"))
    komsu = ajan._neighbours(HUB)
    assert len(komsu) == 1 + len(HUB_CALLERS) + len(HUB_CALLEES) == 81
    finals = P.name_answer_branches([f"r{i}" for i in range(1, 11)])
    for kip, araclar in (("K1", ajan.registry.schemas(komsu)), ("K2", ajan.registry.schemas())):
        zarf = P.build_task_envelope(araclar, finals, P.NAME_ANSWER_REQUIRED)
        P.check_schema(zarf)
        assert _anahtar_sozcukler(zarf) <= P.SUPPORTED_KEYWORDS, kip
        rf = P.response_format_for("L3", zarf)
        assert rf["type"] == "json_schema" and rf["json_schema"]["strict"] is True
        dal = next(d for d in zarf["anyOf"] if d["properties"].get("tool", {}).get("const") == "get_xrefs")
        sayi = dal["properties"]["args"]["properties"]["offset"]
        assert sayi["type"] == "integer" and "minimum" in sayi and "maximum" in sayi
        if kip == "K1":
            assert dal["properties"]["args"]["properties"]["addr"]["enum"] == komsu
