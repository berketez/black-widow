"""P-ÜV1 — ``go_metadata_recovery`` üretici adımı.

Görüntü açıcı (``_goruntu_ac``) testte sentetik ``BellekGoruntu``'ya bağlanır
(``tests/test_puv1_go_pclntab.py`` kurucusu); gerçek ikili yok.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from karadul.analyzers.ustveri import go_pclntab as G
from karadul.config import Config
from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step
from karadul.pipeline.steps import go_metadata_recovery as A
from tests.test_puv1_go_pclntab import BellekGoruntu, Modul, kur


class _Hata(Exception):
    def __init__(self, neden: str, durum: str) -> None:
        super().__init__(neden)
        self.neden = neden
        self.durum = durum


def _baglam(tmp_path: Path, bayrak: object = True, ikili: bool = True) -> StepContext:
    hedef = tmp_path / "ikili"
    if ikili:
        hedef.write_bytes(b"\xcf\xfa\xed\xfe" + b"\0" * 60)
    pc = MagicMock()
    pc.config = Config()
    pc.config.binary_reconstruction.enable_go_metadata_recovery = bayrak
    pc.workspace.save_json = MagicMock(return_value=tmp_path / "static" / "go_functions.json")
    ctx = StepContext(pipeline_context=pc)
    ctx._write_artifacts({"binary_for_byte_match": hedef})
    return ctx


@pytest.fixture
def go_goruntu(monkeypatch: pytest.MonkeyPatch):
    def kur_ve_bagla(m: Modul | None = None):
        g, bilgi = kur(m)
        monkeypatch.setattr(A, "_goruntu_ac", lambda yol: g)
        return bilgi
    return kur_ve_bagla


def test_kayit_requires_produces() -> None:
    spec = get_step("go_metadata_recovery")
    assert spec.requires == ("binary_for_byte_match",)
    assert set(spec.produces) == {"go_functions", "go_buildinfo", "go_integrity", "go_status",
                                  "go_functions_path"}


def test_oentanim_bayrak_kapali() -> None:
    """Bağlanan alanın tür / öntanım kilidi (bayrak ön paketi testi bağlanınca atlar)."""
    from karadul import config as config_mod

    deger = Config().binary_reconstruction.enable_go_metadata_recovery
    assert deger is False
    hints = config_mod._field_type_hints(type(Config().binary_reconstruction))
    assert hints["enable_go_metadata_recovery"] is bool


@pytest.mark.parametrize("bayrak", [False, 1, "true", "True", None])
def test_bayrak_gercek_true_degilse_kapali(tmp_path: Path, go_goruntu, bayrak: object) -> None:
    go_goruntu()
    ctx = _baglam(tmp_path, bayrak=bayrak)
    out = A.GoMetadataRecoveryStep().run(ctx)
    assert out["go_status"]["durum"] == G.DURUM_KAPALI
    assert out["go_functions"] == [] and out["go_functions_path"] is None
    assert out["go_buildinfo"] is None and out["go_integrity"] == {}
    ctx.pipeline_context.workspace.save_json.assert_not_called()


def test_sahte_nesne_bayragi_acmaz(tmp_path: Path, go_goruntu) -> None:
    go_goruntu()
    ctx = _baglam(tmp_path)
    ctx.pipeline_context.config = MagicMock()   # getattr her şeye doğru-değerli nesne döner
    out = A.GoMetadataRecoveryStep().run(ctx)
    assert out["go_status"]["durum"] == G.DURUM_KAPALI


def test_calisti_fonksiyon_listesi_ve_yapit(tmp_path: Path, go_goruntu) -> None:
    bilgi = go_goruntu()
    ctx = _baglam(tmp_path)
    out = A.GoMetadataRecoveryStep().run(ctx)
    assert out["go_status"] == {"durum": G.DURUM_CALISTI, "neden": ""}
    assert [f["giris"] for f in out["go_functions"]] == [hex(a) for a in bilgi["girisler"]]
    assert out["go_functions"][2]["ad"] == "main.main"
    assert out["go_buildinfo"]["surum"] == "go1.27.4"
    assert out["go_integrity"]["K1_artan"]["ihlal"] == 0
    assert out["go_functions_path"] == tmp_path / "static" / "go_functions.json"
    asama, ad, payload = ctx.pipeline_context.workspace.save_json.call_args.args
    assert (asama, ad) == ("static", "go_functions")
    assert payload["fonksiyon_sayisi"] == 4 and len(payload["fonksiyonlar"]) == 4
    assert payload["durum"]["durum"] == G.DURUM_CALISTI
    assert payload["pclntab"]["metin_tabani_kaynagi"] == "moduledata.text"
    assert ctx.stats["go_status"] == G.DURUM_CALISTI and ctx.stats["go_function_count"] == 4


def test_tutarsiz_ad_listesi_yok_kanit_var(tmp_path: Path, go_goruntu) -> None:
    go_goruntu(Modul(findfunctab_bozuk=True))
    ctx = _baglam(tmp_path)
    out = A.GoMetadataRecoveryStep().run(ctx)
    assert out["go_status"]["durum"] == G.DURUM_TUTARSIZ
    assert "K5" in out["go_status"]["neden"]
    assert out["go_functions"] == []
    assert out["go_integrity"]["K5_findfunctab"]["ihlal"] > 0
    payload = ctx.pipeline_context.workspace.save_json.call_args.args[2]
    assert payload["fonksiyonlar"] == [] and payload["sayim"]["fonksiyon_girisi"] == 4


def test_go_degil_veri_yok(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    g = BellekGoruntu([("__text", 0x1000, b"\0" * 64, True), ("__data", 0x2000, b"\0" * 64)])
    monkeypatch.setattr(A, "_goruntu_ac", lambda yol: g)
    ctx = _baglam(tmp_path)
    out = A.GoMetadataRecoveryStep().run(ctx)
    assert out["go_status"]["durum"] == G.DURUM_VERI_YOK
    assert out["go_functions"] == [] and ctx.errors == []


@pytest.mark.parametrize("durum", [G.DURUM_DESTEKLENMIYOR, G.DURUM_VERI_YOK])
def test_goruntu_hatasi_durumu_tasinir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                       durum: str) -> None:
    def ac(yol):
        raise _Hata("biçim tanınmadı", durum)
    monkeypatch.setattr(A, "_goruntu_ac", ac)
    ctx = _baglam(tmp_path)
    out = A.GoMetadataRecoveryStep().run(ctx)
    assert out["go_status"]["durum"] == durum
    assert "biçim tanınmadı" in out["go_status"]["neden"]
    assert ctx.errors == []


def test_beklenmedik_istisna_hata(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def ac(yol):
        raise OSError("okunamadı")
    monkeypatch.setattr(A, "_goruntu_ac", ac)
    ctx = _baglam(tmp_path)
    out = A.GoMetadataRecoveryStep().run(ctx)
    assert out["go_status"]["durum"] == G.DURUM_HATA
    assert "OSError" in out["go_status"]["neden"]
    assert ctx.errors and "go_metadata_recovery" in ctx.errors[0]


def test_ikili_yoksa_hata(tmp_path: Path, go_goruntu) -> None:
    go_goruntu()
    ctx = _baglam(tmp_path, ikili=False)
    out = A.GoMetadataRecoveryStep().run(ctx)
    assert out["go_status"]["durum"] == G.DURUM_HATA
    assert out["go_functions"] == []


def test_yapit_yazilamazsa_adim_dusmez(tmp_path: Path, go_goruntu) -> None:
    go_goruntu()
    ctx = _baglam(tmp_path)
    ctx.pipeline_context.workspace.save_json.side_effect = OSError("disk dolu")
    out = A.GoMetadataRecoveryStep().run(ctx)
    assert out["go_status"]["durum"] == G.DURUM_CALISTI
    assert out["go_functions_path"] is None
    assert any("yapıt yazımı" in e for e in ctx.errors)


def test_goruntu_ac_urunun_dilimini_secer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from karadul.analyzers.ustveri import goruntu

    yol = tmp_path / "evrensel"
    yol.write_bytes(b"\xca\xfe\xba\xbe" + b"\0" * 60)
    cagri = {}
    monkeypatch.setattr(goruntu, "urun_dilimi", lambda veri: "arm64")

    def baytlardan(veri, dilim=None, kaynak=""):
        cagri.update(dilim=dilim, kaynak=kaynak, boy=len(veri))
        return "goruntu"

    monkeypatch.setattr(goruntu, "baytlardan", baytlardan)
    assert A._goruntu_ac(yol) == "goruntu"
    assert cagri == {"dilim": "arm64", "kaynak": str(yol), "boy": 64}
