"""``scripts/measurement/ustveri_urun.py`` (P-ÜV8 kalem 5–6; P-ÜV6a): ürün düzeyi ölçü işlevleri.

Sentetik yapıtlarla; gerçek ikili ve Ghidra yok.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_KOK = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_KOK / "scripts" / "measurement"))

import ustveri_urun as uu  # noqa: E402
from karadul.core import naming_labels as nl  # noqa: E402


def _go(addr, ad, pcsp="tam"):
    return {"giris": hex(addr), "ad": ad, "pcsp_kapsama": pcsp}


def _oc(imp, tam, **kw):
    r = {"imp": imp, "tam_ad": tam, "secici": tam.split()[-1][:-1], "swift": False,
         "imp_paylasimli": False, "ad_yazilabilir": True}
    r.update(kw)
    return r


@pytest.fixture
def sahte_okuyucu(monkeypatch):
    go = [_go(0x10, "main.main"), _go(0x20, "a.F", "kisa"), _go(0x30, "a.G", "tasan"), _go(0x40, "")]
    oc = [_oc(0x100, "-[A b]"), _oc(0x110, "-[A c]", swift=True), _oc(0x120, "-[A d]", imp_paylasimli=True),
          _oc(0x130, "-[A e]", ad_yazilabilir=False), _oc(0, "-[P f]")]
    monkeypatch.setattr(uu, "go_kayitlari", lambda _p: (go, {"durum": "calisti", "neden": ""}))
    monkeypatch.setattr(uu, "objc_kayitlari", lambda _p: (oc, {"durum": "calisti", "neden": None}))


def test_aday_listesi_urun_suzgeclerini_uygular(sahte_okuyucu) -> None:
    liste = uu.aday_listesi(Path("x"))
    go, oc = liste[nl.SOURCE_GO_PCLNTAB], liste[nl.SOURCE_OBJC_METHOD]
    assert go["aday"] == {0x10: {"main.main"}}
    assert go["elenen"] == {"pcsp_kisa": 1, "pcsp_tasan": 1, "adsiz": 1}
    assert oc["aday"] == {0x100: {"-[A b]"}}
    assert oc["elenen"] == {"swift_kopru": 1, "imp_paylasimli": 1, "ad_yazilamaz": 1, "imp_yok": 1}


def test_aday_gt_sinama_ikilisini_reddeder() -> None:
    with pytest.raises(SystemExit):
        uu.aday_gt("docker-compose", Path("/yok"))
    with pytest.raises(SystemExit):
        uu.aday_gt("iTerm2", Path("/yok"))


def test_ustveri_adlari_adres_cozumu() -> None:
    gfonk = [{"addr": 0x10, "name": "FUN_00000010"}, {"addr": 0x20, "name": "printVersion"},
             {"addr": 0x30, "name": "init"}, {"addr": 0x40, "name": "init"},
             {"addr": 0x50, "name": "applicationDidFinishLaunching:"}]
    rec = {"label": nl.LABEL_METADATA, "new_name": "n", "ozgun_ad": "o", "source": nl.SOURCE_OBJC_METHOD,
           "confidence": 0.9998}
    harita = {"mappings": {"FUN_00000010": rec, "printVersion": rec, "init": rec,
                           "applicationDidFinishLaunching_": rec,
                           "A::sel_": {**rec, "address": "0x70"},
                           "FUN_00000060": {**rec, "label": nl.LABEL_UNVERIFIED}}}
    out = {r["anahtar"]: r for r in uu.ustveri_adlari(harita, gfonk)}
    assert set(out) == {"FUN_00000010", "printVersion", "init", "applicationDidFinishLaunching_", "A::sel_"}
    assert out["A::sel_"]["adres"] == 0x70 and out["A::sel_"]["a28"]
    assert out["FUN_00000010"]["adres"] == 0x10 and not out["FUN_00000010"]["a28"]
    assert out["printVersion"]["adres"] == 0x20 and out["printVersion"]["a28"]
    assert out["applicationDidFinishLaunching_"]["adres"] == 0x50
    assert out["init"]["adres"] is None                       # iki fonksiyon: adres belirsiz


def test_goruntu_tabani_onaltilik_ve_tamsayi(tmp_path) -> None:
    st = tmp_path / "static"
    st.mkdir()
    (st / "ghidra_combined_results.json").write_text('{"program_info": {"image_base": "100000000"}}')
    assert uu.goruntu_tabani(tmp_path) == 0x100000000
    (st / "ghidra_combined_results.json").write_text('{"program_info": {"image_base": 4096}}')
    assert uu.goruntu_tabani(tmp_path) == 4096
    (st / "ghidra_combined_results.json").write_text("{}")
    assert uu.goruntu_tabani(tmp_path) is None
