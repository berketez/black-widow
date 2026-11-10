"""KesinAnchorsStep: KS-1 çapalarının Faz 1'de bir kez çıkarılması (plan v2.2 N1 adım 3, 6. commit).

Kilitlenen davranışlar (tasarım §2.1, §5.4 satır 6):
  - bayrak kapalıyken adım iş yapmaz: dizin çözülmez, dosya yazılmaz, yapıt ``kapali`` bağlamasıdır;
  - girdi ``static/`` dizinidir (``deobfuscated/`` değil);
  - yapıt ``baglama.Binding``'dir; yan çıktı ``reconstructed/kesin_capalar.json`` onun dökümüdür;
  - girdi eksikse, platform desteklenmiyorsa ya da çıkarım hata verirse hat düşmez, durum kodu yazılır;
  - tohumun girdileri (``seed_inputs``) ve Faz 2 tohumu (``with_pre_name_meta``).

Mutasyon koruması: ``scripts/measurement/mutation_specs_adim3_hat.json``.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from unittest.mock import MagicMock

import pytest

from karadul.config import Config
from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step
from karadul.pipeline.runner import PipelineRunner
from karadul.pipeline.steps import kesin_anchors as KA
from karadul.reconstruction.tarif import baglama as B

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_tarif_baglama import F_FUNC, TABLO, karma  # noqa: E402
from test_tarif_kesin import ELF, Ikili, temel  # noqa: E402


class _Workspace:
    """Aşama dizinlerini ``kok/<aşama>`` altında çözen ve çağrıları kaydeden çalışma alanı."""

    def __init__(self, kok: Path) -> None:
        self.kok = kok
        self.istenen: list[str] = []
        self.yazilan: list[str] = []

    def get_stage_dir(self, stage: str) -> Path:
        self.istenen.append(stage)
        d = self.kok / stage
        d.mkdir(parents=True, exist_ok=True)
        return d

    def save_artifact(self, stage: str, name: str, data: str) -> Path:
        self.yazilan.append(f"{stage}/{name}")
        p = self.get_stage_dir(stage) / name
        p.write_text(data, encoding="utf-8")
        return p


def _ctx(tmp_path: Path, *, acik: bool, workspace=None) -> tuple[StepContext, _Workspace]:
    cfg = Config()
    cfg.binary_reconstruction.enable_ks1_anchors = acik
    ws = workspace or _Workspace(tmp_path)
    pc = SimpleNamespace(config=cfg, workspace=ws, metadata={})
    ctx = StepContext(pipeline_context=pc)
    ctx._write_artifacts({"functions_json_path": tmp_path / "static" / "ghidra_functions.json"})
    return ctx, ws


@pytest.fixture
def ad_veren_tablo(monkeypatch):
    """Ürün tablosu "aç" commit'ine kadar susar; ad veren durumu sınamak için sınama tablosu."""
    ozgun = B.bind_static
    monkeypatch.setattr(B, "bind_static", lambda d: ozgun(d, row_status=TABLO))


# --------------------------------------------------------------------------------------------
# Kayıt


def test_kayit_ve_sira():
    import karadul.pipeline  # noqa: F401
    spec = get_step("kesin_anchors")
    assert spec.cls is KA.KesinAnchorsStep
    assert spec.requires == ("functions_json_path",)   # ghidra_metadata'dan sonra
    assert spec.produces == ("kesin_anchors",)
    assert KA.KS1_ARTIFACT_KEY == "kesin_anchors" and KA.PRE_NAME_META_KEY == "pre_name_meta"


def test_ontanimli_yapilandirmada_acik():
    assert KA.ks1_enabled(Config()) is True


# --------------------------------------------------------------------------------------------
# Bayrak kapalı: iş yok


def test_bayrak_kapaliyken_is_yapmaz(tmp_path):
    karma().yaz(tmp_path)   # girdi hazır olsa da okunmamalı
    ctx, ws = _ctx(tmp_path, acik=False)
    cikti = KA.KesinAnchorsStep().run(ctx)
    assert set(cikti) == {"kesin_anchors"}
    b = cikti["kesin_anchors"]
    assert isinstance(b, B.Binding) and b.status == "kapali" and b.anchors == []
    assert b.as_dict()["durum"] == "kapali"
    assert ctx.stats == {"ks1_status": "kapali"}      # sayı uydurulmaz: yalnız durum
    assert ws.istenen == [] and ws.yazilan == []      # dizin çözülmedi, dosya yazılmadı
    assert not (tmp_path / "reconstructed").exists()
    assert ctx.errors == [] and dict(ctx.stage_artifacts) == {}


@pytest.mark.parametrize("deger", [None, 1, "true", "evet"])
def test_dogru_benzeri_deger_bayragi_acmaz(tmp_path, deger):
    ctx, ws = _ctx(tmp_path, acik=False)
    ctx.pipeline_context.config.binary_reconstruction.enable_ks1_anchors = deger
    assert KA.KesinAnchorsStep().run(ctx)["kesin_anchors"].status == "kapali"
    assert ws.istenen == []


def test_sahte_yapilandirma_bayragi_acmaz(tmp_path):
    """MagicMock yapılandırma her özniteliğe doğru benzeri değer döndürür; adım yine kapalıdır."""
    ws = _Workspace(tmp_path)
    ctx = StepContext(pipeline_context=SimpleNamespace(config=MagicMock(), workspace=ws))
    assert KA.KesinAnchorsStep().run(ctx)["kesin_anchors"].status == "kapali"
    ctx = StepContext(pipeline_context=SimpleNamespace(config=None, workspace=ws))
    assert KA.KesinAnchorsStep().run(ctx)["kesin_anchors"].status == "kapali"
    assert ws.istenen == []


# --------------------------------------------------------------------------------------------
# Bayrak açık


def test_bayrak_acikken_yapit_ve_yan_cikti(tmp_path, ad_veren_tablo):
    karma().yaz(tmp_path)
    ctx, ws = _ctx(tmp_path, acik=True)
    b = KA.KesinAnchorsStep().run(ctx)["kesin_anchors"]
    assert isinstance(b, B.Binding) and b.status == "ok"
    assert len(b.anchors) == 7 and len(b.named()) == 4 and b.export_count == 1
    assert ctx.stats["ks1_status"] == "ok" and "ks1_detail" not in ctx.stats
    assert isinstance(ctx.stats["timing_kesin_anchors"], float)
    # ad sayaçlarını adım yazmaz: onları tohum, adları sözlüğe yazarken doldurur
    assert set(ctx.stats) == {"ks1_status", "timing_kesin_anchors"}
    # yan çıktı: reconstructed/kesin_capalar.json, bağlamanın dökümü, UTF-8
    yol = tmp_path / "reconstructed" / "kesin_capalar.json"
    assert ws.yazilan == ["reconstructed/kesin_capalar.json"]
    metin = yol.read_text(encoding="utf-8")
    assert json.loads(metin) == json.loads(json.dumps(b.as_dict()))
    assert "doğrulanmadı" in metin                     # etiket okunur yazılır (\\u kaçışı yok)
    belge = json.loads(metin)
    assert belge["sema"] == "karadul.ks1_baglama" and belge["durum"] == "ok"
    assert belge["ad_veren"] == 4 and len(belge["capalar"]) == 6 and len(belge["parcalar"]) == 1
    assert dict(ctx.stage_artifacts) == {"kesin_capalar": yol}
    assert ctx.errors == []


def test_urun_tablosuyla_ad_veren_capalar(tmp_path):
    """Ürün tablosu ("aç"tan beri ölçümden türer): yalnız assert'e dayanan çapa susar."""
    karma().yaz(tmp_path)
    ctx, _ = _ctx(tmp_path, acik=True)
    b = KA.KesinAnchorsStep().run(ctx)["kesin_anchors"]
    assert b.status == "ok" and len(b.anchors) == 7
    assert sorted((a.rows, a.label) for a in b.named()) == [
        (("assert", "func_kalibi"), "kesin"), (("assert_ust",), "doğrulanmadı"),
        (("func_aktarma",), "doğrulanmadı"), (("func_kalibi",), "kesin"),
    ]
    assert b.skipped() == {"anahtar_fun_degil": 1, "parca": 1, "satir_sus": 1}
    belge = json.loads((tmp_path / "reconstructed" / "kesin_capalar.json").read_text("utf-8"))
    assert belge["ad_veren"] == 4 and belge["satir_durumu"] == dict(B.ROW_STATUS) == TABLO


def test_hepsi_susan_tabloyla_capalar_kayda_gecer_ad_veren_yok(tmp_path, monkeypatch):
    """Tablo dört satırda da sussa çapalar yine yan çıktıya yazılır, hiçbiri ad vermez."""
    sus = {r: B.STATUS_SILENT for r in B.DECISION_ROWS}
    ozgun = B.bind_static
    monkeypatch.setattr(B, "bind_static", lambda d: ozgun(d, row_status=sus))
    karma().yaz(tmp_path)
    ctx, _ = _ctx(tmp_path, acik=True)
    b = KA.KesinAnchorsStep().run(ctx)["kesin_anchors"]
    assert b.status == "ok" and len(b.anchors) == 7 and b.named() == []
    belge = json.loads((tmp_path / "reconstructed" / "kesin_capalar.json").read_text("utf-8"))
    assert belge["ad_veren"] == 0 and belge["satir_durumu"] == sus


def test_girdi_static_dizinidir_deobfuscated_degil(tmp_path, ad_veren_tablo):
    # geçerli girdi yalnız static/'te; deobfuscated/ boş
    karma().yaz(tmp_path)
    (tmp_path / "deobfuscated").mkdir()
    ctx, ws = _ctx(tmp_path, acik=True)
    assert KA.KesinAnchorsStep().run(ctx)["kesin_anchors"].status == "ok"
    assert ws.istenen[0] == "static" and "deobfuscated" not in ws.istenen

    # tersi: girdi yalnız deobfuscated/'te → static/ boş, çıkarım yapılamaz
    ters = tmp_path / "ters"
    ters.mkdir()
    karma().yaz(ters)
    (ters / "static").rename(ters / "deobfuscated")
    ctx, _ = _ctx(ters, acik=True)
    b = KA.KesinAnchorsStep().run(ctx)["kesin_anchors"]
    assert b.status == "girdi_eksik" and b.anchors == []


def test_girdi_eksikse_hat_dusmez(tmp_path):
    ctx, _ = _ctx(tmp_path, acik=True)
    b = KA.KesinAnchorsStep().run(ctx)["kesin_anchors"]
    assert b.status == "girdi_eksik"
    assert ctx.stats["ks1_status"] == "girdi_eksik"
    assert ctx.stats["ks1_detail"].startswith("eksik dosya: ghidra_functions.json")
    belge = json.loads((tmp_path / "reconstructed" / "kesin_capalar.json").read_text("utf-8"))
    assert belge["durum"] == "girdi_eksik" and belge["capalar"] == []
    assert ctx.errors == []


def test_desteklenmeyen_platform(tmp_path):
    ik = Ikili(ELF, islemci="x86")
    ik.fonksiyon(0x1000, ["ret"])
    ik.yaz(tmp_path)
    ctx, _ = _ctx(tmp_path, acik=True)
    b = KA.KesinAnchorsStep().run(ctx)["kesin_anchors"]
    assert b.status == "desteklenmeyen_platform"
    assert ctx.stats["ks1_status"] == "desteklenmeyen_platform"


def test_bozuk_girdi_hata_koduna_cevrilir(tmp_path):
    st = temel(ELF).yaz(tmp_path)
    (st / "ghidra_strings.json").write_text("{bozuk", encoding="utf-8")
    ctx, _ = _ctx(tmp_path, acik=True)
    b = KA.KesinAnchorsStep().run(ctx)["kesin_anchors"]
    assert b.status == "hata" and "JSONDecodeError" in b.detail
    assert ctx.stats["ks1_status"] == "hata" and "JSONDecodeError" in ctx.stats["ks1_detail"]


def test_dizin_cozulemezse_hat_dusmez(tmp_path):
    class Patlayan(_Workspace):
        def get_stage_dir(self, stage):
            if stage == "static":
                raise OSError("disk yok")
            return super().get_stage_dir(stage)

    ctx, _ = _ctx(tmp_path, acik=True, workspace=Patlayan(tmp_path))
    b = KA.KesinAnchorsStep().run(ctx)["kesin_anchors"]
    assert b.status == "hata" and b.detail == "OSError: disk yok"
    assert ctx.stats["ks1_status"] == "hata"


def test_yan_cikti_yazilamazsa_yapit_yine_doner(tmp_path, ad_veren_tablo):
    class Yazamayan(_Workspace):
        def save_artifact(self, stage, name, data):
            raise OSError("salt okur")

    karma().yaz(tmp_path)
    ctx, _ = _ctx(tmp_path, acik=True, workspace=Yazamayan(tmp_path))
    b = KA.KesinAnchorsStep().run(ctx)["kesin_anchors"]
    assert b.status == "ok" and len(b.named()) == 4
    assert ctx.errors == ["kesin_anchors: kesin_capalar.json yazılamadı: salt okur"]
    assert dict(ctx.stage_artifacts) == {}


def test_kosucuyla_calisir(tmp_path, ad_veren_tablo):
    """PipelineRunner sözleşmesi: requires tohumdan gelir, produces dışına çıkılmaz."""
    karma().yaz(tmp_path)
    ctx, ws = _ctx(tmp_path, acik=True)
    pc = ctx.pipeline_context
    sonuc = PipelineRunner(steps=["kesin_anchors"]).run(
        pc, seed_artifacts={"functions_json_path": tmp_path / "static" / "ghidra_functions.json"})
    assert sonuc.artifacts["kesin_anchors"].status == "ok"
    assert sonuc.stats["ks1_status"] == "ok" and "kesin_anchors_duration_s" in sonuc.stats
    with pytest.raises(RuntimeError, match="eksik girdi"):
        PipelineRunner(steps=["kesin_anchors"]).run(pc)


# --------------------------------------------------------------------------------------------
# Tohumun girdileri ve Faz 2 tohumu


def test_tohum_girdileri(tmp_path, ad_veren_tablo):
    assert KA.seed_inputs(None) == (None, None)                 # adım hiç koşmadı
    assert KA.seed_inputs(B.disabled()) == (None, None)         # bayrak kapalı
    assert KA.seed_inputs({"durum": "ok"}) == (None, None)      # bağlama değil
    b = B.bind_static(karma().yaz(tmp_path))
    assert KA.seed_inputs(b) == (b, {})
    # çıkarım başarısız olsa da adım koştu: durum sayaçlara yazılsın diye bağlama tohuma gider
    eksik = B.bind_static(tmp_path / "yok")
    assert eksik.status == "girdi_eksik" and KA.seed_inputs(eksik) == (eksik, {})
    # her çağrı yeni bir sözlük verir
    assert KA.seed_inputs(b)[1] is not KA.seed_inputs(b)[1]


def test_faz2_tohumu():
    yapitlar = MappingProxyType({"extracted_names": {"FUN_1": "a"}, "c_files": []})
    kunyesiz = KA.with_pre_name_meta(yapitlar, None)
    assert kunyesiz == dict(yapitlar) and "pre_name_meta" not in kunyesiz
    kunye = {"FUN_1": B.make_meta(B.KIND_MAIN, "a")}
    tohum = KA.with_pre_name_meta(yapitlar, kunye)
    assert tohum["pre_name_meta"] is kunye                      # aynı nesne: tohum sonradan doldurur
    assert {k: v for k, v in tohum.items() if k != "pre_name_meta"} == dict(yapitlar)
    assert "pre_name_meta" not in yapitlar                      # salt okur yapıtlara yazılmadı
    assert KA.with_pre_name_meta(yapitlar, {})["pre_name_meta"] == {}   # boş künye de taşınır


def test_ad_veren_capa_anahtari_fikstur():
    """Sınama tablosuyla ``F_FUNC`` ad verir (öbür testlerin dayandığı fikstür varsayımı)."""
    assert TABLO[B.ROW_FUNC] == B.STATUS_KESIN and F_FUNC == 0x100001000
