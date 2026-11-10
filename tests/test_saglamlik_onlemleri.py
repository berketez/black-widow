"""Çıktı sağlamlığı denetiminin (2026-11-10) iki acil önlemi.

1. Akış sadeleştirme öntanımlı kapalı: goto içeren fonksiyonların çoğunda C metnini bozuyordu.
2. Başvuru kaynağı ağdan yalnız ağ açıkça açılmışsa indirilir: analiz eskiden koşulsuz
   indirmeyi ve derlemeyi deniyordu.
"""
from __future__ import annotations

import inspect

import pytest

from karadul.config import Config
from karadul.pipeline.steps import _feedback_naming_refdiff as refdiff


def test_akis_sadelestirme_ontanimli_kapali():
    assert Config().binary_reconstruction.enable_flow_simplification is False


def test_akis_sadelestirme_yamldan_acilabilir(tmp_path):
    yol = tmp_path / "karadul.yaml"
    yol.write_text("binary_reconstruction:\n  enable_flow_simplification: true\n", encoding="utf-8")
    assert Config.load(yol).binary_reconstruction.enable_flow_simplification is True


def test_kapaliyken_sadelestirici_metne_dokunmaz(tmp_path):
    from karadul.reconstruction.c_flow_simplifier import CFlowSimplifier
    kaynak = (
        "void FUN_00001000(int param_1)\n{\n  if (param_1 == 0) goto LAB_00001010;\n"
        "  puts(\"a\");\nLAB_00001010:\n  return;\n}\n"
    )
    girdi, cikti = tmp_path / "girdi", tmp_path / "cikti"
    girdi.mkdir()
    (girdi / "FUN_00001000.c").write_text(kaynak, encoding="utf-8")
    sade = CFlowSimplifier(Config())
    assert sade._enabled is False
    sonuc = sade.simplify_directory(girdi, cikti)
    yazilan = cikti / "FUN_00001000.c"
    # kapalıyken ya hiç yazmaz ya da metni aynen kopyalar; içerik değişmemeli
    assert not yazilan.exists() or yazilan.read_text(encoding="utf-8") == kaynak
    assert getattr(sonuc, "gotos_eliminated", 0) == 0


@pytest.mark.parametrize("ag, izin, beklenen", [
    (False, False, False), (True, False, False), (False, True, False), (True, True, True),
])
def test_kaynak_indirme_yalniz_iki_anahtar_acikken(ag, izin, beklenen):
    cfg = Config()
    cfg.network.enabled = ag
    cfg.network.allow_reference_download = izin
    assert refdiff.reference_download_allowed(cfg) is beklenen


def test_ontanimli_yapilandirmada_indirme_kapali_ve_cagri_ayara_bagli():
    assert refdiff.reference_download_allowed(Config()) is False
    assert refdiff.reference_download_allowed(object()) is False      # ağ ayarı yoksa kapalı
    kaynak = inspect.getsource(refdiff._match_against_db)
    assert "auto_populate=True" not in kaynak
    assert "auto_populate=reference_download_allowed(pc.config)" in kaynak



def test_hicbir_cagri_kosulsuz_indirme_acmaz():
    """karadul/ altında ReferenceDiffer'a sabit auto_populate=True veren çağrı kalmamalı."""
    from pathlib import Path

    import karadul
    kok = Path(karadul.__file__).parent
    bulunan = [
        f"{yol.relative_to(kok)}:{i}"
        for yol in sorted(kok.rglob("*.py"))
        for i, satir in enumerate(yol.read_text(encoding="utf-8", errors="replace").splitlines(), 1)
        if "auto_populate=True" in satir.replace(" ", "") and not satir.lstrip().startswith("#")
    ]
    assert bulunan == []
    # eski hat (stages.py) da aynı kuralı kullanır
    stages = (kok / "stages.py").read_text(encoding="utf-8")
    assert "auto_populate=_ref_dl_allowed(context.config)" in stages

# --------------------------------------------------------------------------------------------
# 3. Boş proje ağacı: temiz çıktı boş kalmaz, kalırsa "başarılı" denmez


def _bicimlendirici(tmp_path, asamalar=("identify", "static", "reconstruct")):
    from karadul.core.output_formatter import OutputFormatter
    from karadul.core.result import PipelineResult, StageResult
    from karadul.core.workspace import Workspace
    ws = Workspace(base_dir=tmp_path / "workspaces", target_name="ornek")
    ws.create()
    sonuc = PipelineResult(target_name="ornek", target_hash="0" * 16, workspace_path=ws.path)
    for ad in asamalar:
        sonuc.add_stage_result(StageResult(stage_name=ad, success=True, duration_seconds=0.1,
                                           stats={"language": "c"} if ad == "identify" else {}))
    return ws, OutputFormatter(ws, sonuc)


def _c_yaz(dizin, n=3):
    dizin.mkdir(parents=True, exist_ok=True)
    for i in range(n):
        (dizin / f"FUN_{i:04x}.c").write_text(f"void FUN_{i:04x}(void)\n{{\n  return;\n}}\n", encoding="utf-8")


def test_bos_proje_agaci_yerine_dolu_asamaya_dusulur(tmp_path):
    ws, bic = _bicimlendirici(tmp_path)
    rec = ws.get_stage_dir("reconstructed")
    (rec / "project").mkdir(parents=True)          # var ama boş: son aşamalar çıktı üretmemiş
    (rec / "commented").mkdir()
    _c_yaz(rec / "typed", n=3)
    src = tmp_path / "out" / "src"
    src.mkdir(parents=True)
    yazilan, hatalar = bic._format_binary_sources(src)
    assert yazilan == 3 and hatalar == []
    assert len(list(src.rglob("*.c"))) == 3
    assert any("boş" in u for u in bic._warnings)


def test_dolu_proje_agaci_onceliklidir(tmp_path):
    ws, bic = _bicimlendirici(tmp_path)
    rec = ws.get_stage_dir("reconstructed")
    _c_yaz(rec / "project" / "altsistem_a", n=2)
    _c_yaz(rec / "typed", n=5)
    src = tmp_path / "out" / "src"
    src.mkdir(parents=True)
    yazilan, _ = bic._format_binary_sources(src)
    assert yazilan == 2 and (src / "altsistem_a").is_dir() and bic._warnings == []


def test_kaynak_yazilamazsa_sonuc_basarili_sayilmaz(tmp_path, monkeypatch):
    from karadul.core.output_formatter import OutputFormatter
    ws, bic = _bicimlendirici(tmp_path)
    monkeypatch.setattr(OutputFormatter, "_detect_language", lambda self: "c")
    monkeypatch.setattr(OutputFormatter, "_format_binary_sources", lambda self, src: (0, []))
    sonuc = bic._format_clean(tmp_path / "out")
    assert sonuc.src_files == 0 and sonuc.reports_generated > 0
    assert sonuc.success is False
    assert any("kaynak dosyası yazılamadı" in h for h in sonuc.errors)
    # reconstruct koşmadıysa (ör. --stage static) kaynaksız çıktı olağandır
    ws2, bic2 = _bicimlendirici(tmp_path / "b", asamalar=("identify", "static"))
    monkeypatch.setattr(OutputFormatter, "_format_binary_sources", lambda self, src: (0, []))
    assert bic2._format_clean(tmp_path / "b" / "out").success is True


def test_uyari_sonuca_ve_komut_satirina_tasinir(tmp_path, monkeypatch):
    """Boş proje ağacından geri düşüldüğünde uyarı FormatResult.warnings'e geçer."""
    from karadul.core.output_formatter import OutputFormatter
    monkeypatch.setattr(OutputFormatter, "_detect_language", lambda self: "c")
    ws, bic = _bicimlendirici(tmp_path)
    rec = ws.get_stage_dir("reconstructed")
    (rec / "project").mkdir(parents=True)
    _c_yaz(rec / "typed", n=2)
    sonuc = bic._format_clean(tmp_path / "out")
    assert sonuc.success is True and sonuc.src_files == 2
    assert len(sonuc.warnings) == 1 and "boş" in sonuc.warnings[0]
    # dolu proje ağacında uyarı yok; ikinci çağrı öncekinin uyarısını taşımaz
    ws2, bic2 = _bicimlendirici(tmp_path / "b")
    _c_yaz(ws2.get_stage_dir("reconstructed") / "project" / "alt", n=2)
    assert bic2._format_clean(tmp_path / "b" / "out").warnings == []
    _c_yaz(rec / "project" / "alt", n=2)
    assert bic._format_clean(tmp_path / "out2").warnings == []
