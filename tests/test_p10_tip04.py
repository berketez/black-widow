"""P10 kalem 3 (TIP-04 + K-1): mühendislik yapı kurtarması.

Eski motor Ghidra'nın sistem yapılarını (``_IO_FILE``, ``Elf64_Ehdr`` …) taban alıyordu: her ELF'te
taban dolu olduğu için koddan çıkarma hiç çalışmıyor, yapıların GERÇEK alan adları sezgisel adlarla
eziliyordu (G: 4 722 / 4 722; D: 21 888 / 21 888), bağlanamayan yapılar ``structs_enriched``
olarak "kurtarıldı" sayılıyordu (G: 712). K-1: onarım ölçülene kadar yapılar koda ve ``types.h``'ye
iddia olarak girmez; motor koşar, öneriler ayrı dizinde.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

from karadul.config import Config
from karadul.pipeline.context import StepContext
from karadul.pipeline.steps.struct_recovery import StructRecoveryStep
from karadul.reconstruction.engineering.struct_recovery import (
    STRUCT_CANDIDATES_FILENAME,
    StructRecoveryEngine,
)

_GHIDRA = {"structures": [{
    "name": "Elf64_Ehdr", "size": 64, "fields": [
        {"name": "e_ident_magic_num", "type": "byte", "offset": 0, "size": 1},
        {"name": "e_ident_magic_str", "type": "char[3]", "offset": 1, "size": 3},
        {"name": "e_type", "type": "word", "offset": 16, "size": 2},
        {"name": "e_entry", "type": "qword", "offset": 24, "size": 8}]}]}

_KOD = """long FUN_00101000(long param_1)

{
  long lVar1;
  lVar1 = *(long *)(param_1 + 8);
  *(long *)param_1 = lVar1;
  return lVar1;
}
"""


def _hazirla(tmp_path: Path, ghidra: bool = True) -> tuple[Path, Path]:
    src = tmp_path / "typed"
    src.mkdir()
    (src / "FUN_00101000.c").write_text(_KOD, encoding="utf-8")
    gt = tmp_path / "ghidra_types.json"
    if ghidra:
        gt.write_text(json.dumps(_GHIDRA), encoding="utf-8")
    return src, gt


def _recover(src: Path, gt: Path, out: Path, esik: float | None = None, **kw):
    eng = StructRecoveryEngine(Config())
    if esik is not None:
        eng._REWRITE_MIN_CONFIDENCE = esik  # bekletme mantığını eşikten ayırmak için
    return eng.recover(
        decompiled_dir=src, functions_json=src.parent / "yok.json",
        ghidra_types_json=gt, call_graph_json=src.parent / "yok.json",
        output_dir=out, **kw,
    )


class TestGhidraYapilari:
    def test_ghidra_field_names_kept_and_not_counted(self, tmp_path: Path) -> None:
        src, gt = _hazirla(tmp_path)
        out = tmp_path / "struct_recovered"
        res = _recover(src, gt, out)
        assert [s.name for s in res.reference_structs] == ["Elf64_Ehdr"]
        assert [f.name for f in res.reference_structs[0].fields] == [
            "e_ident_magic_num", "e_ident_magic_str", "e_type", "e_entry"]
        # Ghidra yapısı ne bağlı ne aday (Karadul iddiası değil)
        hepsi = res.enriched_structs + res.candidate_structs
        assert all(s.raw_name != "Elf64_Ehdr" for s in hepsi)
        assert {s.origin for s in hepsi} <= {"code"}
        rapor = json.loads((out / "struct_recovery.json").read_text(encoding="utf-8"))
        ref = rapor["reference_structs"][0]
        assert ref["origin"] == "ghidra"
        assert [f["name"] for f in ref["fields"]] == [
            "e_ident_magic_num", "e_ident_magic_str", "e_type", "e_entry"]
        # sezgisel ad hiçbir yerde Ghidra alanının yerine geçmedi
        assert "field_0x0" not in json.dumps(ref)
        assert "Elf64_Ehdr" not in (out / "types.h").read_text(encoding="utf-8")


class TestKoddanCikarma:
    def test_code_extraction_runs_with_ghidra_structs_present(self, tmp_path: Path) -> None:
        src, gt = _hazirla(tmp_path)
        res = _recover(src, gt, tmp_path / "struct_recovered")
        aday = {s.name: s for s in res.candidate_structs}
        assert "struct_FUN_00101000_param_1" in aday
        s = aday["struct_FUN_00101000_param_1"]
        assert s.origin == "code" and s.base_var == "param_1"
        assert s.source_functions == ["FUN_00101000"]
        assert [f.offset for f in s.fields] == [0, 8]

    def test_unbound_structs_not_counted_as_recovered(self, tmp_path: Path) -> None:
        src, gt = _hazirla(tmp_path)
        res = _recover(src, gt, tmp_path / "struct_recovered")
        assert res.total_structs == 0
        assert res.enriched_structs == []
        assert res.field_access_rewrites == 0


class TestBekletme:
    def test_hold_keeps_source_tree_and_writes_proposals_aside(self, tmp_path: Path) -> None:
        src, gt = _hazirla(tmp_path)
        out = tmp_path / "struct_recovered"
        res = _recover(src, gt, out, esik=0.0)
        # öneri hesaplandı …
        assert res.proposed_field_access_rewrites == 2
        assert res.rewrites_applied is False
        # … ama Faz 3'ün kaynak ağacına girmedi
        assert (out / "FUN_00101000.c").read_text(encoding="utf-8") == _KOD
        assert res.rewritten_files == [] and res.field_access_rewrites == 0
        assert res.total_structs == 0
        assert "typedef struct" not in (out / "types.h").read_text(encoding="utf-8")
        # öneri ve aday dosyası kaynak ağacın DIŞINDA; aday dosyası .h değil
        cand = tmp_path / "struct_recovered_candidates"
        assert "((struct_FUN_00101000_param_1 *)param_1)->" in (
            cand / "FUN_00101000.c").read_text(encoding="utf-8")
        assert (cand / STRUCT_CANDIDATES_FILENAME).exists()
        assert not STRUCT_CANDIDATES_FILENAME.endswith(".h")
        assert [p.name for p in out.iterdir() if p.is_dir()] == []
        assert not (tmp_path / "struct_recovered_originals").exists()

    def test_apply_binds_and_backs_up_outside_tree(self, tmp_path: Path) -> None:
        src, gt = _hazirla(tmp_path)
        out = tmp_path / "struct_recovered"
        res = _recover(src, gt, out, esik=0.0, apply_rewrites=True)
        assert res.rewrites_applied is True
        assert res.field_access_rewrites == 2
        assert [s.name for s in res.enriched_structs] == ["struct_FUN_00101000_param_1"]
        assert res.total_structs == 1
        assert "((struct_FUN_00101000_param_1 *)param_1)->" in (
            out / "FUN_00101000.c").read_text(encoding="utf-8")
        assert "typedef struct struct_FUN_00101000_param_1" in (
            out / "types.h").read_text(encoding="utf-8")
        # BORU-02: yedek kardeş dizinde, özgün içerikle; kaynak ağacında alt dizin yok
        orj = tmp_path / "struct_recovered_originals" / "FUN_00101000.c"
        assert orj.read_text(encoding="utf-8") == _KOD
        assert [p.name for p in out.iterdir() if p.is_dir()] == []

    def test_engine_default_is_hold(self) -> None:
        assert StructRecoveryEngine.APPLY_REWRITES is False


class TestKaynakAgaci:
    def test_output_tree_written_even_without_any_struct(self, tmp_path: Path) -> None:
        src = tmp_path / "typed"
        src.mkdir()
        (src / "FUN_1.c").write_text("void FUN_1(void)\n\n{\n  return;\n}\n", encoding="utf-8")
        out = tmp_path / "struct_recovered"
        res = _recover(src, tmp_path / "yok.json", out)
        assert res.success
        assert [p.name for p in res.output_files] == ["FUN_1.c"]
        assert (out / "FUN_1.c").read_bytes() == (src / "FUN_1.c").read_bytes()
        assert (out / "struct_recovery.json").exists()


class TestAdimIstatistikleri:
    def test_step_stats_separate_candidates_and_reference(self, tmp_path: Path) -> None:
        src, gt = _hazirla(tmp_path)
        rec = tmp_path / "reconstructed"
        rec.mkdir()
        pc = MagicMock()
        pc.metadata = {}
        pc.config = SimpleNamespace(
            binary_reconstruction=SimpleNamespace(enable_struct_recovery=True))
        pc.workspace.get_stage_dir = MagicMock(return_value=rec)
        ctx = StepContext(pipeline_context=pc)
        ctx._write_artifacts({
            "final_decompiled_dir": src,
            "functions_json_path": tmp_path / "yok.json",
            "ghidra_types_json_path": gt,
            "call_graph_json_path": tmp_path / "yok.json",
            "updated_algo_result": None,
            "updated_eng_result": SimpleNamespace(success=True, algorithms=[]),
            "computation_result": None,
            "recovered_struct_candidates": [],
            "computation_struct_result": None,
        })
        StructRecoveryStep().run(ctx)
        assert ctx.stats["structs_enriched"] == 0
        assert ctx.stats["struct_candidates"] == 1
        assert ctx.stats["struct_reference_ghidra"] == 1
        assert ctx.stats["struct_rewrites_proposed"] == 0  # ürün eşiği: sezgisel ad yazılmaz
