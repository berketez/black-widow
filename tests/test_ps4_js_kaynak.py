"""P-S4 kalem 1 + 2: JS yeniden kurmanın kaynağı ve modül dizini.

BICIM-02: ``ReconstructionStage._execute_js`` ``deobfuscated/`` altındaki EN BÜYÜK
``.js``'yi işliyordu (``00_original.js`` ya da yalnız güzelleştirilmiş dosya); ayrıca
Electron hedefinde çıkarılmış JS yoksa ikili ``.asar`` derin hatta veriliyordu.
(BICIM-13 testleri: ``test_ps4_modul_dizini.py``.)

Adım sınıfları (ContextNamer, ParamRecovery …) burada kayıt tutan / hata veren
yer tutucularla değiştirilir: sınanan şey seçim ve yönlendirme, adımların işi değil.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from karadul.config import Config
from karadul.core.pipeline import PipelineContext
from karadul.core.result import StageResult
from karadul.core.target import Language, TargetInfo, TargetType
from karadul.core.workspace import Workspace
from karadul.stages import DeobfuscationStage, ReconstructionStage

_DEPO = Path(__file__).resolve().parents[1]


def _ctx(tmp_path: Path, target_type=TargetType.JS_BUNDLE, path: Path | None = None):
    if path is None:
        path = tmp_path / "girdi.js"
        path.write_text("var a=1;\n", encoding="utf-8")
    ws = Workspace(base_dir=tmp_path / "ws", target_name="ornek")
    ws.create()
    target = TargetInfo(
        path=path, name="ornek", target_type=target_type, language=Language.JAVASCRIPT,
        file_size=path.stat().st_size if path.is_file() else 0, file_hash="0" * 64,
    )
    return PipelineContext(target=target, workspace=ws, config=Config())


@pytest.fixture
def adimlar_bos(monkeypatch):
    """JS hattının adımlarını iş yapmayan yer tutucularla değiştir; çağrıları kaydet."""
    kayit: dict[str, list] = {"context_namer": [], "split": [], "reconstructor": []}

    def _patla(*_a, **_k):
        raise RuntimeError("test: adım koşmaz")

    import karadul.reconstruction.context_namer as cn
    import karadul.reconstruction.variable_renamer as vr
    import karadul.reconstruction.param_recovery as pr
    import karadul.reconstruction.type_inferrer as ti
    import karadul.reconstruction.comment_generator as cg
    import karadul.reconstruction.gap_filler as gf
    import karadul.reconstruction.project_builder as pb
    import karadul.reconstruction.module_splitter as ms
    import karadul.reconstruction.naming as nm

    def _cn(self, src, out):
        kayit["context_namer"].append(Path(src))
        raise RuntimeError("test: ad adımı koşmaz")

    def _split(self, mdir, out):
        kayit["split"].append(Path(mdir))
        raise RuntimeError("test: ayırma koşmaz")

    monkeypatch.setattr(cn.ContextNamer, "analyze_and_rename", _cn)
    monkeypatch.setattr(vr.VariableRenamer, "rename", _patla)
    monkeypatch.setattr(pr.ParamRecovery, "recover", _patla)
    monkeypatch.setattr(ti.TypeInferrer, "infer", _patla)
    monkeypatch.setattr(cg.CommentGenerator, "generate", _patla)
    monkeypatch.setattr(gf.GapFiller, "fill", _patla)
    monkeypatch.setattr(pb.ProjectBuilder, "build", _patla)
    monkeypatch.setattr(ms.ModuleSplitter, "split", _split)
    monkeypatch.setattr(nm.NamingPipeline, "run", _patla)
    return kayit


def _deob_dosyalari(ctx, boyutlar: dict[str, int]) -> Path:
    deob = ctx.workspace.get_stage_dir("deobfuscated")
    for ad, n in boyutlar.items():
        p = deob / ad
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x" * n, encoding="utf-8")
    return deob


# --- BICIM-02: kaynak seçimi -------------------------------------------------

def test_kaynak_deobfuscation_ciktisi_en_buyuk_degil(tmp_path, adimlar_bos):
    """Derin dönüşüm kodu küçülttüğünde de kaynak zincirin gerçek çıktısıdır."""
    ctx = _ctx(tmp_path)
    deob = _deob_dosyalari(ctx, {
        "00_original.js": 1457, "01_beautified.js": 1322,
        "02_deep_deobfuscated.js": 1428, "03_enhanced_renamed.js": 1300,
        "stream_chunks/block_0.js": 9000,
    })
    ctx.results["deobfuscate"] = StageResult(
        stage_name="deobfuscate", success=True, duration_seconds=0.0,
        artifacts={"output_file": deob / "03_enhanced_renamed.js"},
        stats={"status": "ok"},
    )
    res = ReconstructionStage(use_project_reconstructor=False)._execute_js(ctx, 0.0)
    assert res.stats["source_file"] == "03_enhanced_renamed.js"
    assert res.stats["source_selection"] == "deobfuscate_output"
    assert adimlar_bos["context_namer"] == [deob / "03_enhanced_renamed.js"]


def test_deobfuscation_basarisizsa_kayitta_soylenir(tmp_path, adimlar_bos):
    """Derin adım başarısız (fallback kopyası): kaynak beautify çıktısı ve uyarı var."""
    ctx = _ctx(tmp_path)
    deob = _deob_dosyalari(ctx, {
        "00_original.js": 5000, "01_beautified.js": 6000,
        "02_deep_deobfuscated.js": 6000,
    })
    ctx.results["deobfuscate"] = StageResult(
        stage_name="deobfuscate", success=False, duration_seconds=0.0,
        artifacts={"output_file": deob / "01_beautified.js"},
        stats={"status": "failed", "deep_deob_fallback_copy": True},
    )
    res = ReconstructionStage(use_project_reconstructor=False)._execute_js(ctx, 0.0)
    assert res.stats["source_file"] == "01_beautified.js"
    assert res.stats["deobfuscation_status"] == "failed"
    assert any("Deobfuscation durumu 'failed'" in e for e in res.errors)


def test_deobfuscation_cikti_uretmediyse_ozgun_kod_kurulmaz(tmp_path, adimlar_bos):
    """Aşama koştu, çıktı yok: 00_original 'yeniden kurulmuş' diye sunulmaz (atlandı)."""
    ctx = _ctx(tmp_path)
    _deob_dosyalari(ctx, {"00_original.js": 5000, "02_deep_deobfuscated.js": 5000})
    ctx.results["deobfuscate"] = StageResult(
        stage_name="deobfuscate", success=False, duration_seconds=0.0,
        stats={"status": "failed", "deep_deob_fallback_copy": True},
        errors=["Babel parse basarisiz"],
    )
    res = ReconstructionStage(use_project_reconstructor=False)._execute_js(ctx, 0.0)
    assert res.skipped is True and res.success is False
    assert "özgün girdi" in res.stats["skip_reason"]
    assert adimlar_bos["context_namer"] == []


def test_asama_sonucu_yoksa_adim_sirasi_ozgun_asla(tmp_path, adimlar_bos):
    """``--stage reconstruct`` gibi: sıra 03 > 02 > 01b > 01; 00_original asla."""
    ctx = _ctx(tmp_path)
    _deob_dosyalari(ctx, {"00_original.js": 9999, "01_beautified.js": 100})
    res = ReconstructionStage(use_project_reconstructor=False)._execute_js(ctx, 0.0)
    assert res.stats["source_file"] == "01_beautified.js"
    assert res.stats["source_selection"] == "adim_dosyasi"


def test_electron_js_yoksa_asar_derin_hatta_girmez(tmp_path, monkeypatch):
    """Çıkarılmış JS yoksa ikili .asar beautify'a verilmez; aşama 'atlandı'."""
    asar = tmp_path / "app.asar"
    asar.write_bytes(b"\x04\x00\x00\x00binary-asar")
    ctx = _ctx(tmp_path, TargetType.ELECTRON_APP, asar)
    ctx.results["static"] = StageResult(stage_name="static", success=False,
                                        duration_seconds=0.0, stats={"js_file_count": 0})
    (ctx.workspace.get_stage_dir("raw") / "asar_extracted").mkdir(parents=True)
    cagri: list[Path] = []
    import karadul.deobfuscators.deep_pipeline as dp

    def _run(self, input_file, workspace, **_k):
        cagri.append(Path(input_file))
        raise RuntimeError("test")

    monkeypatch.setattr(dp.DeepDeobfuscationPipeline, "run", _run)
    res = DeobfuscationStage().execute(ctx)
    assert cagri == []
    assert res.skipped is True
    assert "JS" in res.stats["skip_reason"]
