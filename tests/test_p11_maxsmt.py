"""P11 / TIP-03: MaxSMT erişim çıkarımı ofseti doğru varnode'dan okur.

Ghidra P-code'unda LOAD/STORE'un ``input0``'ı adres alanının kimliğidir
(sabit; ``ram`` = 433). Ofset işaretçi girdisinin (``input1``) tanım
zincirindedir. Veriler gerçek ``pcode.jsonl`` biçiminde (``[alan, ofset,
boyut]``; alan 0 unique, 1 register, 2 const) kurulur ve ürünün JSONL
ayrıştırıcısından geçirilir.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from karadul.analyzers.pcode_analyzer import PcodeAnalysisResult, PcodeAnalyzer
from karadul.computation.kol_durumu import CALISTI, HATA, KAPALI, STAT_MAXSMT
from karadul.pipeline.steps import computation_struct_recovery as csr

RAM = [2, 433, 4]          # LOAD/STORE input0: adres alanı kimliği
X0 = [1, 0x4000, 8]        # AArch64 x0 (param_1)
X1 = [1, 0x4008, 8]


def _c(v: int, size: int = 8) -> list:
    return [2, v, size]


def _u(off: int, size: int = 8) -> list:
    return [0, off, size]


def _res(*fonksiyonlar: tuple[str, list, list | None]) -> PcodeAnalysisResult:
    an = PcodeAnalyzer()
    fns = []
    for i, (ad, ops, vars_) in enumerate(fonksiyonlar):
        fns.append(an._parse_jsonl_function(
            {"n": ad, "a": f"{0x101000 + 0x100 * i:08x}", "ops": ops, "vars": vars_ or []}))
    return PcodeAnalysisResult(total_functions=len(fns), functions=fns)


def _tek(res: PcodeAnalysisResult):
    ex = csr.extract_struct_accesses(res)
    erisimler = [a for v in ex.per_function.values() for a in v]
    return ex, erisimler


def test_input0_alan_kimligi_ofset_sayilmaz():
    # LOAD(ram, x0): param_1'in 0. baytı; eski kod 433 okuyordu.
    ex, er = _tek(_res(("f", [["LOAD", _u(0x100, 4), [RAM, X0]]], None)))
    assert [(a.offset, a.width, a.access_type) for a in er] == [(0, 4, "read")]
    assert all(a.offset != 433 for a in er)


def test_ptradd_sabit_indeks_ofset_ve_kok():
    ops = [
        ["PTRADD", _u(0x10), [X0, _c(2), _c(8)]],
        ["LOAD", _u(0x20, 8), [RAM, _u(0x10)]],
    ]
    ex, er = _tek(_res(("f", ops, [{"name": "param_1", "storage": "(register, 0x4000, 8)"}])))
    assert [(a.offset, a.width) for a in er] == [(16, 8)]
    b = ex.bases[er[0].var_name]
    assert (b["space"], b["offset"], b["definition"], b["high_name"]) == ("register", 0x4000, "in", "param_1")


def test_store_genisligi_yazilan_degerden():
    ops = [
        ["INT_ADD", _u(0x10), [X1, _c(0x18)]],
        ["STORE", None, [RAM, _u(0x10), _u(0x30, 2)]],
    ]
    _, er = _tek(_res(("f", ops, None)))
    assert [(a.offset, a.width, a.access_type) for a in er] == [(0x18, 2, "write")]


def test_ic_ice_ptradd_int_add_toplanir():
    ops = [
        ["PTRADD", _u(0x10), [X0, _c(3), _c(8)]],
        ["INT_ADD", _u(0x18), [_u(0x10), _c(4)]],
        ["COPY", _u(0x20), [_u(0x18)]],
        ["LOAD", _u(0x28, 4), [RAM, _u(0x20)]],
    ]
    _, er = _tek(_res(("f", ops, None)))
    assert [a.offset for a in er] == [28]


def test_ptradd_erisim_degil():
    ops = [["PTRADD", _u(0x10), [X0, _c(2), _c(8)]]]
    ex, er = _tek(_res(("f", ops, None)))
    assert er == [] and ex.counts.get("erisim", 0) == 0


def test_tanimsiz_gecici_ve_dizi_indeksi_atlanir():
    ops = [
        ["LOAD", _u(0x50, 8), [RAM, _u(0x40)]],                # CAST ile tanımlı (kayıtta yok)
        ["PTRADD", _u(0x10), [X0, X1, _c(8)]],                 # değişken indeks
        ["LOAD", _u(0x60, 8), [RAM, _u(0x10)]],
        ["INT_SUB", _u(0x18), [X0, _c(8)]],
        ["LOAD", _u(0x70, 8), [RAM, _u(0x18)]],                # negatif ofset
    ]
    ex, er = _tek(_res(("f", ops, None)))
    assert er == []
    assert ex.counts["tanimsiz_gecici"] == 1
    assert ex.counts["dizi_indeksi"] == 1
    assert ex.counts["negatif_ofset"] == 1


def test_en_yakin_onceki_tanim_kullanilir():
    # Aynı unique varnode iki kez tanımlanıyor; her LOAD kendinden önceki tanımı görür.
    ops = [
        ["INT_ADD", _u(0x10), [X0, _c(8)]],
        ["LOAD", _u(0x20, 8), [RAM, _u(0x10)]],
        ["INT_ADD", _u(0x10), [X0, _c(0x30)]],
        ["LOAD", _u(0x28, 8), [RAM, _u(0x10)]],
    ]
    _, er = _tek(_res(("f", ops, None)))
    assert [a.offset for a in er] == [8, 0x30]


def test_yalniz_sonraki_tanim_dongu_sayilir():
    ops = [
        ["LOAD", _u(0x20, 8), [RAM, X0]],
        ["CALL", X0, [[3, 0x1000, 8]]],                        # x0 sonradan yeniden tanımlanıyor
    ]
    ex, er = _tek(_res(("f", ops, None)))
    assert er == [] and ex.counts["dongu_tanimi"] == 1


def test_load_ile_gelen_isaretci_ayri_kok():
    ops = [
        ["LOAD", X1, [RAM, X0]],                               # p = *param_1
        ["INT_ADD", _u(0x10), [X1, _c(0x10)]],
        ["LOAD", _u(0x20, 4), [RAM, _u(0x10)]],                # p->0x10
    ]
    ex, er = _tek(_res(("f", ops, None)))
    kokler = {ex.bases[a.var_name]["definition"] for a in er}
    assert sorted((a.offset for a in er)) == [0, 0x10]
    assert kokler == {"in", 0}


def test_ayni_adli_iki_fonksiyon_birlesmez():
    ops = [["LOAD", _u(0x20, 8), [RAM, X0]]]
    ex, _ = _tek(_res(("f", ops, None), ("f", ops, None)))
    assert len(ex.per_function) == 2


def _ctx(flag: bool, pcode):
    comp = SimpleNamespace(
        enable_computation_struct_recovery=flag, struct_solver_timeout=5.0,
        enable_parallel_solve=False,
    )
    if flag:
        from karadul.computation.config import ComputationConfig
        comp = ComputationConfig(enable_computation_struct_recovery=True,
                                 enable_parallel_solve=False, struct_solver_timeout=5.0)
    pc = SimpleNamespace(config=SimpleNamespace(computation=comp))
    return SimpleNamespace(pipeline_context=pc, artifacts={"pcode_result": pcode},
                           stats={}, errors=[])


def test_adim_bayrak_kapali_durum():
    ctx = _ctx(False, None)
    out = csr.ComputationStructRecoveryStep().run(ctx)
    assert out["recovered_struct_candidates"] == []
    assert ctx.stats[STAT_MAXSMT]["durum"] == KAPALI


def test_adim_calisti_sayac_ve_aday():
    ops = [
        ["LOAD", _u(0x20, 8), [RAM, X0]],
        ["INT_ADD", _u(0x10), [X0, _c(8)]],
        ["LOAD", _u(0x28, 4), [RAM, _u(0x10)]],
    ]
    ctx = _ctx(True, _res(("f", ops, None)))
    out = csr.ComputationStructRecoveryStep().run(ctx)
    d = ctx.stats[STAT_MAXSMT]
    assert d["durum"] == CALISTI and d["cikti"] == "yapi_adayi"
    assert d["erisim"]["kabul"] == 2
    offs = sorted(f.offset for c in out["recovered_struct_candidates"] for f in c.fields)
    assert offs == [0, 8]


def test_adim_hata_sayac_yazmaz(monkeypatch):
    def _patla(_p):
        raise RuntimeError("bozuk")
    monkeypatch.setattr(csr, "extract_struct_accesses", _patla)
    ctx = _ctx(True, _res(("f", [], None)))
    csr.ComputationStructRecoveryStep().run(ctx)
    d = ctx.stats[STAT_MAXSMT]
    assert d["durum"] == HATA and "erisim" not in d and "aday" not in d


def test_ardisik_int_add_ofsetleri_toplanir():
    ops = [
        ["INT_ADD", _u(0x10), [X0, _c(8)]],
        ["INT_ADD", _u(0x18), [_u(0x10), _c(4)]],
        ["LOAD", _u(0x28, 4), [RAM, _u(0x18)]],
    ]
    _, er = _tek(_res(("f", ops, None)))
    assert [a.offset for a in er] == [12]


def test_ayni_yazmac_farkli_tanim_farkli_degisken():
    ops = [
        ["LOAD", X1, [RAM, X0]],                               # 0: p = param_1->0
        ["INT_ADD", _u(0x10), [X1, _c(0x10)]],
        ["LOAD", _u(0x20, 4), [RAM, _u(0x10)]],                # p->0x10
        ["INT_ADD", _u(0x30), [X0, _c(8)]],
        ["LOAD", X1, [RAM, _u(0x30)]],                         # 4: q = param_1->8 (aynı x1)
        ["INT_ADD", _u(0x40), [X1, _c(0x10)]],
        ["LOAD", _u(0x48, 4), [RAM, _u(0x40)]],                # q->0x10
    ]
    ex, er = _tek(_res(("f", ops, None)))
    degiskenler = {a.var_name for a in er}
    assert len(degiskenler) == 3
    assert sorted(ex.bases[v]["definition"] for v in degiskenler
                  if ex.bases[v]["offset"] == 0x4008) == [0, 4]


def test_kol_durumu_hatada_sayac_yok():
    from karadul.computation.kol_durumu import kol_durumu
    assert "erisim" not in kol_durumu(HATA, "x", erisim=5)
    assert kol_durumu(CALISTI, "", erisim=5)["erisim"] == 5
    with pytest.raises(ValueError):
        kol_durumu("calisti_0_sonuc")


@pytest.mark.parametrize("v,size,beklenen", [(0xfff8, 2, -8), (-8, 8, -8), (8, 8, 8), (0xff, 1, -1)])
def test_isaretli_sabit(v, size, beklenen):
    assert csr._signed_const(SimpleNamespace(offset=v, size=size)) == beklenen
