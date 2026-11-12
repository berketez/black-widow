"""Çıktı dürüstlüğü ve sağlamlığı: 2026-11-11'de görülüp dokunulmayan hatalar (2026-11-12).

Kanıt ve önce/sonra sayıları: ``docs/arge/2026-11-12_cikti_hatalari/sonuc.md``.

1. Temiz çıktının ``report.html`` strateji bölümü imza veritabanı adımını "Signature Database
   (FLIRT) — N functions matched / Known library functions identified via byte signatures"
   diye anlatıyordu. Adım (``SignatureDB.match_all``) bayt karşılaştırmaz (``func_bytes=None``)
   ve FLIRT değildir: fonksiyonun var olan adını, dizgilerini ve çağırdıklarını arar (Debian
   tree: 133 eşleşmenin 128'i ``symbol``, yani ithal/simge adının aranması). Satır artık
   "Signature Database Lookup — N matches: … by the function's existing name, …" der; döküm
   kayda eklenen ``method`` alanından sayılır, alan yoksa yalnız sayı yazılır. "Binary Name
   Extraction — N names recovered" de aday sayısıdır: "N name candidates".
2. ``reconstructed/signature_matches.json`` kaydı fonksiyonun adresini taşımıyordu: aynı adlı iki
   thunk (Debian ``tree``'de ``getcwd`` 00103d00 PLT ve 00135010 dış blok) iki özdeş kayıt
   üretiyordu (133 kaydın 63'ü). ``SignatureMatch.address`` zaten doluydu (``match_all``);
   kaydı yazan iki yer (etkin ``pipeline/steps/ghidra_metadata.py`` ve emekli monolit yolunun
   ``stages._run_signature_matching``'i) alanı yazmıyordu. Kayıt artık ``address`` taşır;
   okuyucular anahtarla okuduğu için davranışları değişmez.
3. Temiz çıktının biçimlendiricisi dili C, JS ya da Swift olmayan hedefi genel dala gönderiyordu;
   genel dal ``reconstructed/`` altındaki bütün kaynakları düz ``src/<dosya adı>`` yoluna
   kopyaladığı için aynı adlı dosyalar birbirini eziyordu (Debian ``pzstd``, dil ``cpp``:
   12 757 dosyadan 1 201'i kaldı; kalan ``typed_iter1`` kopyasıydı, proje ağacı kayboldu).
   Kaynak yalnız C ise C dalı kullanılır; genel dal göreli yolu korur.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from karadul.config import Config
from karadul.core.result import PipelineResult, StageResult
from karadul.core.workspace import Workspace


def _workspace(tmp_path: Path) -> Workspace:
    ws = Workspace(base_dir=tmp_path / "workspaces", target_name="ikili")
    ws.create()
    return ws


def _result(ws: Workspace, stages: dict[str, dict]) -> PipelineResult:
    result = PipelineResult(target_name="ikili", target_hash="0" * 64, workspace_path=ws.path)
    for name, stats in stages.items():
        result.add_stage_result(StageResult(
            stage_name=name, success=True, duration_seconds=1.0, stats=stats,
        ))
    return result


# Debian tree'deki gibi: aynı adlı iki thunk (PLT ve dış blok) ve adsız bir fonksiyon
_FUNCTIONS = {"functions": [
    {"name": "getcwd", "address": "00103d00", "size": 16},
    {"name": "getcwd", "address": "00135010", "size": 1},
    {"name": "strlen", "address": "00103e00", "size": 16},
    {"name": "FUN_00104000", "address": "00104000", "size": 64},
]}


def _ghidra_inputs(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    d = tmp_path / "girdi"
    (d / "decompiled").mkdir(parents=True)
    funcs = d / "ghidra_functions.json"
    funcs.write_text(json.dumps(_FUNCTIONS), encoding="utf-8")
    strings = d / "ghidra_strings.json"
    strings.write_text("[]", encoding="utf-8")
    cg = d / "ghidra_call_graph.json"
    cg.write_text(json.dumps({"edges": []}), encoding="utf-8")
    return funcs, strings, cg, d / "decompiled"


def _pipeline_context(ws: Workspace) -> SimpleNamespace:
    return SimpleNamespace(config=Config(), workspace=ws,
                           report_progress=lambda *a, **k: None)


def _records(ws: Workspace) -> list[dict]:
    data = ws.load_json("reconstructed", "signature_matches")
    assert data is not None
    return data["matches"]


# ---------------------------------------------------------------------------
# 2. signature_matches.json kaydı adres taşır
# ---------------------------------------------------------------------------


class TestImzaKaydiAdres:
    def test_adim_yolu_adres_yazar(self, tmp_path) -> None:
        """Etkin yol (step registry): ghidra_metadata kaydı adres taşır; aynı adlı thunk'lar ayrılır."""
        from karadul.core.target import TargetType
        from karadul.pipeline.context import StepContext
        from karadul.pipeline.steps.ghidra_metadata import GhidraMetadataStep

        ws = _workspace(tmp_path)
        funcs, strings, cg, dec = _ghidra_inputs(tmp_path)
        pc = _pipeline_context(ws)
        ctx = StepContext(pipeline_context=pc)
        GhidraMetadataStep._run_signature_db(
            pc=pc, target=SimpleNamespace(target_type=TargetType.ELF_BINARY),
            functions_json=funcs, strings_json=strings, call_graph_json=cg,
            decompiled_dir=dec, ctx=ctx,
        )
        rec = _records(ws)
        getcwd = [r for r in rec if r["original"] == "getcwd"]
        assert sorted(r["address"] for r in getcwd) == ["00103d00", "00135010"]
        # İki kayıt artık özdeş değil
        assert len({json.dumps(r, sort_keys=True) for r in rec}) == len(rec)
        assert all(r["address"] for r in rec)
        assert ctx.stats["signature_matches"] == len(rec)

    def test_monolit_yolu_adres_yazar(self, tmp_path) -> None:
        """Emekli monolit yolu (``_run_signature_matching``) aynı kaydı yazar (eşlik testi)."""
        from karadul.core.target import TargetType
        from karadul.pipeline.reconstruction_context import ReconstructionContext
        from karadul.stages import ReconstructionStage

        ws = _workspace(tmp_path)
        funcs, strings, cg, dec = _ghidra_inputs(tmp_path)
        context = SimpleNamespace(
            config=Config(), workspace=ws, report_progress=lambda *a, **k: None,
            target=SimpleNamespace(target_type=TargetType.ELF_BINARY),
        )
        rc = ReconstructionContext()
        rc.ph1_artifacts.update({
            "functions_json_path": funcs, "strings_json_path": strings,
            "call_graph_json_path": cg, "decompiled_dir": dec,
        })
        ReconstructionStage()._run_signature_matching(context, rc)
        rec = _records(ws)
        assert sorted(r["address"] for r in rec if r["original"] == "getcwd") == [
            "00103d00", "00135010"]
        assert [r["address"] for r in rec] == [m.address for m in rc.sig_matches]

    def test_okuyucular_adres_alanindan_etkilenmez(self, tmp_path) -> None:
        """Adres alanı eklenince ad haritası, HTML aday tablosu ve arayüz aday kümesi aynı kalır."""
        from karadul.core.output_formatter import OutputFormatter
        from karadul.core.report_generator import ReportGenerator

        eski = [
            {"original": "getcwd", "matched": "getcwd", "library": "libc", "confidence": 0.98,
             "purpose": "cwd"},
            {"original": "getcwd", "matched": "getcwd", "library": "libc", "confidence": 0.98,
             "purpose": "cwd"},
            {"original": "FUN_00104000", "matched": "copy_buffer", "library": "libc",
             "confidence": 0.56, "purpose": "copy"},
        ]
        yeni = [{**r, "address": a} for r, a in zip(eski, ("00103d00", "00135010", "00104000"))]

        def oku(kayit: list[dict], alt: str):
            ws = Workspace(base_dir=tmp_path / alt, target_name="ikili")
            ws.create()
            ws.save_json("reconstructed", "signature_matches",
                         {"total": len(kayit), "matches": kayit})
            res = _result(ws, {})
            harita = OutputFormatter(ws, res)._build_naming_map()
            tablo = ReportGenerator(res, ws)._naming_table()
            return harita, tablo, ws

        h_eski, t_eski, _ = oku(eski, "eski")
        h_yeni, t_yeni, ws_yeni = oku(yeni, "yeni")
        assert h_yeni == h_eski
        assert t_yeni == t_eski

        ui = pytest.importorskip("ui.server")
        old_ws = ui.WS
        try:
            ui._CACHE.clear()
            ui.WS = str(ws_yeni.path)
            assert ui._signature_candidates() == {"getcwd", "FUN_00104000"}
        finally:
            ui.WS = old_ws
            ui._CACHE.clear()


# ---------------------------------------------------------------------------
# 1. HTML raporunun strateji bölümü: imza veritabanı satırı
# ---------------------------------------------------------------------------


def _strategies_html(tmp_path: Path, stats: dict, matches: list[dict] | None = None) -> str:
    from karadul.core.report_generator import ReportGenerator

    ws = _workspace(tmp_path)
    if matches is not None:
        ws.save_json("reconstructed", "signature_matches",
                     {"total": len(matches), "matches": matches})
    return ReportGenerator(_result(ws, {"reconstruct": stats}), ws)._strategies_section()


def _sig(method: str | None, i: int) -> dict:
    rec = {"original": f"fn{i}", "matched": f"fn{i}", "library": "libc", "confidence": 0.98,
           "purpose": "", "address": f"{0x1000 + i:08x}"}
    if method is not None:
        rec["method"] = method
    return rec


def _impact(html: str, name: str) -> str:
    import re as _re

    m = _re.search(rf'<span class="name">{_re.escape(name)}</span> '
                   r'<span class="impact">(.*?)</span>', html)
    assert m, html
    return m.group(1)


_TREE_METHODS = ["symbol"] * 128 + ["string_ref"] * 2 + ["call_pattern"] * 3


class TestStratejiImzaSatiri:
    def test_flirt_bayt_kurtarma_denmez(self, tmp_path) -> None:
        """Eşleşmeler FLIRT değil, bayt imzası değil, koda uygulanması denetlenmiyor."""
        html = _strategies_html(tmp_path, {"signature_matches": 133},
                                [_sig(m, i) for i, m in enumerate(_TREE_METHODS)])
        assert "FLIRT" not in html
        assert "identified via byte signatures" not in html
        assert "this step compares no byte signatures" in html
        assert "Signature Database Lookup" in html
        assert "does not check whether a match was applied to the code" in html
        assert "recover" not in html.lower()

    def test_yonteme_gore_dokum(self, tmp_path) -> None:
        """Debian tree: 133 eşleşmenin 128'i fonksiyonun var olan adının aranması."""
        html = _strategies_html(tmp_path, {"signature_matches": 133},
                                [_sig(m, i) for i, m in enumerate(_TREE_METHODS)])
        assert _impact(html, "Signature Database Lookup") == (
            "133 matches: 128 by the function&#x27;s existing name, 2 by referenced strings, "
            "3 by callees")

    def test_bilinmeyen_yontem_adiyla_yazilir(self, tmp_path) -> None:
        html = _strategies_html(tmp_path, {"signature_matches": 3},
                                [_sig("symbol", 0), _sig("byte_pattern", 1), _sig("yeni", 2)])
        assert _impact(html, "Signature Database Lookup") == (
            "3 matches: 1 by the function&#x27;s existing name, 1 by bytes, 1 by yeni")

    def test_yontem_yoksa_dokum_yok(self, tmp_path) -> None:
        """Eski kayıt (yöntem alanı yok): yalnız sayı; döküm uydurulmaz."""
        html = _strategies_html(tmp_path, {"signature_matches": 5},
                                [_sig(None, i) for i in range(5)])
        assert _impact(html, "Signature Database Lookup") == "5 matches"

    def test_bir_kayitta_yontem_eksikse_dokum_yok(self, tmp_path) -> None:
        html = _strategies_html(tmp_path, {"signature_matches": 3},
                                [_sig("symbol", 0), _sig("symbol", 1), _sig(None, 2)])
        assert _impact(html, "Signature Database Lookup") == "3 matches"

    def test_sayi_tutmazsa_dokum_yok(self, tmp_path) -> None:
        """Aşama sayısı ile kayıt sayısı farklıysa döküm sayıya eklenmez."""
        html = _strategies_html(tmp_path, {"signature_matches": 6},
                                [_sig("symbol", i) for i in range(5)])
        assert _impact(html, "Signature Database Lookup") == "6 matches"

    def test_kayit_yoksa_yalniz_sayi(self, tmp_path) -> None:
        html = _strategies_html(tmp_path, {"signature_matches": 133})
        assert _impact(html, "Signature Database Lookup") == "133 matches"

    def test_ikili_dizgi_adlari_aday(self, tmp_path) -> None:
        html = _strategies_html(tmp_path, {"binary_names_extracted": 12})
        assert _impact(html, "Binary Name Extraction") == "12 name candidates"
        assert "recover" not in html.lower()
        assert "does not check whether a name was applied to the code" in html

    def test_tam_rapor(self, tmp_path) -> None:
        from karadul.core.report_generator import ReportGenerator

        ws = _workspace(tmp_path)
        ws.save_json("reconstructed", "signature_matches", {
            "total": 2, "matches": [_sig("symbol", 0), _sig("call_pattern", 1)]})
        html = ReportGenerator(
            _result(ws, {"reconstruct": {"signature_matches": 2}}), ws).generate_html()
        assert "Signature Database (FLIRT)" not in html
        assert "2 matches: 1 by the function&#x27;s existing name, 1 by callees" in html


class TestImzaKaydiYontem:
    def test_adim_yolu_yontem_yazar(self, tmp_path) -> None:
        from karadul.core.target import TargetType
        from karadul.pipeline.context import StepContext
        from karadul.pipeline.steps.ghidra_metadata import GhidraMetadataStep

        ws = _workspace(tmp_path)
        funcs, strings, cg, dec = _ghidra_inputs(tmp_path)
        pc = _pipeline_context(ws)
        GhidraMetadataStep._run_signature_db(
            pc=pc, target=SimpleNamespace(target_type=TargetType.ELF_BINARY),
            functions_json=funcs, strings_json=strings, call_graph_json=cg,
            decompiled_dir=dec, ctx=StepContext(pipeline_context=pc),
        )
        rec = _records(ws)
        assert {r["original"]: r["method"] for r in rec}["getcwd"] == "symbol"
        assert all(r["method"] for r in rec)

    def test_monolit_yolu_yontem_yazar(self, tmp_path) -> None:
        from karadul.core.target import TargetType
        from karadul.pipeline.reconstruction_context import ReconstructionContext
        from karadul.stages import ReconstructionStage

        ws = _workspace(tmp_path)
        funcs, strings, cg, dec = _ghidra_inputs(tmp_path)
        context = SimpleNamespace(
            config=Config(), workspace=ws, report_progress=lambda *a, **k: None,
            target=SimpleNamespace(target_type=TargetType.ELF_BINARY),
        )
        rc = ReconstructionContext()
        rc.ph1_artifacts.update({
            "functions_json_path": funcs, "strings_json_path": strings,
            "call_graph_json_path": cg, "decompiled_dir": dec,
        })
        ReconstructionStage()._run_signature_matching(context, rc)
        assert [r["method"] for r in _records(ws)] == [m.match_method for m in rc.sig_matches]


# ---------------------------------------------------------------------------
# 3. Temiz çıktı: C dışı dil etiketli ikilinin kaynakları ezilmez
# ---------------------------------------------------------------------------


def _bicimle(tmp_path: Path, language: str, files: dict[str, str], reconstruct: bool = True):
    from karadul.core.output_formatter import OutputFormatter

    ws = _workspace(tmp_path)
    rec = ws.get_stage_dir("reconstructed")
    for rel, text in files.items():
        p = rec / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    stages = {"identify": {"language": language}}
    if reconstruct:
        stages["reconstruct"] = {}
    out = tmp_path / "out"
    fr = OutputFormatter(ws, _result(ws, stages)).format_output(out, fmt="clean")
    src = out / "src"
    disk = {str(p.relative_to(src)): p.read_text(encoding="utf-8")
            for p in sorted(src.rglob("*")) if p.is_file()}
    return fr, disk


class TestGenelDalEzmez:
    def test_cpp_ikilisi_proje_agacini_alir(self, tmp_path) -> None:
        """pzstd gibi: dil "cpp", kaynak yalnız C. Olgun proje ağacı gelir, ara aşamalar gelmez."""
        fr, disk = _bicimle(tmp_path, "cpp", {
            "project/src/subsystem_misc/FUN_00001000.c": "olgun",
            "project/include/types.h": "tipler",
            "annotated/FUN_00001000.c": "ara0",
            "typed_iter1/FUN_00001000.c": "ara1",
        })
        assert disk == {"src/subsystem_misc/FUN_00001000.c": "olgun", "include/types.h": "tipler"}
        assert fr.success

    def test_genel_dal_ayni_adli_dosyalari_ezmez(self, tmp_path) -> None:
        fr, disk = _bicimle(tmp_path, "python", {
            "pkg_a/__init__.py": "A",
            "pkg_b/__init__.py": "B",
        })
        assert disk == {"pkg_a/__init__.py": "A", "pkg_b/__init__.py": "B"}
        assert fr.src_files == 2

    def test_karisik_kaynak_genel_dalda_kalir(self, tmp_path) -> None:
        """C ile başka dil birlikteyse C dalı öbür dili almazdı: genel dal hepsini korur."""
        fr, disk = _bicimle(tmp_path, "cpp", {
            "project/src/a.c": "c",
            "pyc/mod.py": "py",
        })
        assert disk == {"project/src/a.c": "c", "pyc/mod.py": "py"}

    def test_cpp_kaynak_yazilamazsa_basarisiz(self, tmp_path) -> None:
        """C dalındaki kural C++ için de geçerli: yeniden kurma koştu ama kaynak yazılamadı."""
        fr, disk = _bicimle(tmp_path, "cpp", {"annotated/FUN_00001000.c": "ara0"})
        assert disk == {}
        assert not fr.success
