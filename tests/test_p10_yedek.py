"""P10 kalem 2 (BORU-02, BORU-01): yedek kaynak ağacın dışında, yalnız kaynak dosyalar işlenir.

Önceden ``StructRecoveryEngine`` özgünleri çıktı dizininin içine (``struct_recovered/originals/``)
yazıyordu; çıktı dizini Faz 3'ün kaynak ağacı olduğundan ``inline_detection`` (``rglob``) yedekleri
de işliyor, ``inline_patterns_detected`` iki katı sayılıyordu (G: 788 / ağaçta 394). ``stages.py``'deki
ikinci çağrı (girdi = çıktı) motoru kendi çıktısı üstünde koşturuyor, ``rewritten_files`` dosya
sayısının iki katı oluyordu (G: 40 016 / 20 008) ve "yeniden yazıldı" listesi değişmemiş kopyaları
da sayıyordu.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from karadul.config import Config
from karadul.pipeline.context import StepContext
from karadul.pipeline.steps.inline_detection import InlineDetectionStep
from karadul.reconstruction.engineering.struct_recovery import StructRecoveryEngine

_KOD = """void FUN_00101000(long param_1)

{
  long lVar1;
  lVar1 = strlen_like(param_1);
  return;
}
"""
_INLINE_KOD = """int FUN_00102000(char *param_1)

{
  int iVar1;
  char *pcVar2;
  iVar1 = 0;
  for (pcVar2 = param_1; *pcVar2 != '\\0'; pcVar2 = pcVar2 + 1) {
    iVar1 = iVar1 + 1;
  }
  if (iVar1 < 0) iVar1 = -iVar1;
  return iVar1;
}
"""


def _recover(src: Path, out: Path):
    # Ghidra'nın verdiği bir sistem yapısı (her ELF'te olduğu gibi) — motor bir şey bulsun.
    gt = src.parent / "ghidra_types.json"
    if not gt.exists():
        gt.write_text(json.dumps({"structures": [{
            "name": "_IO_marker", "size": 24, "fields": [
                {"name": "_next", "type": "_IO_marker *", "offset": 0, "size": 8},
                {"name": "_sbuf", "type": "_IO_FILE *", "offset": 8, "size": 8},
                {"name": "_pos", "type": "int", "offset": 16, "size": 4}]}]}),
            encoding="utf-8")
    eng = StructRecoveryEngine(Config())
    return eng.recover(
        decompiled_dir=src, functions_json=src.parent / "yok.json",
        ghidra_types_json=gt, call_graph_json=src.parent / "yok.json",
        output_dir=out,
    )


def _src(tmp_path: Path) -> Path:
    src = tmp_path / "typed"
    src.mkdir()
    (src / "FUN_00101000.c").write_text(_KOD, encoding="utf-8")
    (src / "FUN_00102000.c").write_text(_INLINE_KOD, encoding="utf-8")
    return src


class TestYedek:
    def test_originals_not_inside_output_tree(self, tmp_path: Path) -> None:
        src = _src(tmp_path)
        out = tmp_path / "struct_recovered"
        _recover(src, out)
        assert not (out / "originals").exists()
        assert list(out.rglob("*.c")) == list(out.glob("*.c"))

    def test_unchanged_copies_are_not_rewritten_files(self, tmp_path: Path) -> None:
        src = _src(tmp_path)
        out = tmp_path / "struct_recovered"
        res = _recover(src, out)
        assert res.success
        assert sorted(p.name for p in res.output_files) == [
            "FUN_00101000.c", "FUN_00102000.c"]
        assert res.rewritten_files == []
        assert res.field_access_rewrites == 0
        # hiçbir dosya değişmediyse yedek dizini hiç açılmaz
        assert not (tmp_path / "struct_recovered_originals").exists()
        rapor = json.loads((out / "struct_recovery.json").read_text(encoding="utf-8"))
        assert rapor["rewritten_files"] == []
        assert len(rapor["output_files"]) == 2
        # kaynak ağacı girdinin kopyası
        for p in src.glob("*.c"):
            assert (out / p.name).read_bytes() == p.read_bytes()

    def test_in_place_call_refused(self, tmp_path: Path) -> None:
        src = _src(tmp_path)
        out = tmp_path / "struct_recovered"
        _recover(src, out)
        rapor_once = (out / "struct_recovery.json").read_bytes()
        icerik_once = {p.name: p.read_bytes() for p in out.iterdir() if p.is_file()}
        res2 = _recover(out, out)  # stages.py'deki ikinci çağrının biçimi
        assert res2.success is False
        assert any("aynı" in e for e in res2.errors)
        # ilk çağrının raporu ve dosyaları ezilmedi
        assert (out / "struct_recovery.json").read_bytes() == rapor_once
        assert {p.name: p.read_bytes() for p in out.iterdir() if p.is_file()} == icerik_once

    def test_nested_c_files_are_not_sources(self, tmp_path: Path) -> None:
        src = _src(tmp_path)
        (src / "originals").mkdir()
        (src / "originals" / "FUN_00101000.c").write_text("/* eski yedek */\n" + _KOD,
                                                          encoding="utf-8")
        out = tmp_path / "struct_recovered"
        res = _recover(src, out)
        assert len(res.output_files) == 2
        assert (out / "FUN_00101000.c").read_text(encoding="utf-8") == _KOD


class TestInlineYalnizKaynak:
    def _run(self, d: Path, cache: dict[str, str]) -> tuple[dict, StepContext]:
        pc = MagicMock()
        pc.metadata = {}
        ctx = StepContext(pipeline_context=pc)
        ctx._write_artifacts({"final_decompiled_dir": d, "file_cache": cache})
        return InlineDetectionStep().run(ctx), ctx

    def test_backup_subdir_not_annotated_or_counted(self, tmp_path: Path) -> None:
        d = tmp_path / "struct_recovered"
        (d / "originals").mkdir(parents=True)
        (d / "FUN_00102000.c").write_text(_INLINE_KOD, encoding="utf-8")
        (d / "originals" / "FUN_00102000.c").write_text(_INLINE_KOD, encoding="utf-8")
        out, ctx = self._run(d, {"FUN_00102000.c": _INLINE_KOD})
        yorum = (d / "FUN_00102000.c").read_text(encoding="utf-8").count("/* INLINE:")
        assert yorum >= 1
        # sayaç = kaynak ağaçtaki yorum sayısı (eskiden 2 katı)
        assert out["inline_patterns_detected"] == yorum
        # yedek dokunulmadı
        assert (d / "originals" / "FUN_00102000.c").read_text(encoding="utf-8") == _INLINE_KOD
        assert ctx.stats["inline_detection_nested_skipped"] == 1


class TestAdimKaynakAgaci:
    def test_step_routes_phase3_to_output_tree_without_rewrites(self, tmp_path: Path) -> None:
        """Yeniden yazım olmasa da Faz 3 kaynağı çıktı ağacıdır (girdi dizini yerinde
        yazılmasın); ``rewritten_files`` artık boş olduğu için karar ``output_files``'tan."""
        from types import SimpleNamespace

        from karadul.pipeline.steps.struct_recovery import StructRecoveryStep

        src = _src(tmp_path)
        _recover(src, tmp_path / "hazirlik")  # ghidra_types.json'u yazar
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
            "ghidra_types_json_path": tmp_path / "ghidra_types.json",
            "call_graph_json_path": tmp_path / "yok.json",
            "updated_algo_result": None,
            "updated_eng_result": SimpleNamespace(success=True, algorithms=[]),
            "computation_result": None,
            "recovered_struct_candidates": [],
            "computation_struct_result": None,
        })
        out = StructRecoveryStep().run(ctx)
        assert out["struct_recovery_decompiled_dir"] == rec / "struct_recovered"
        assert out["struct_recovery_result"].rewritten_files == []
