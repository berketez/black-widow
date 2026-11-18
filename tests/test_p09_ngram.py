"""P09 Kalem 4 — AD-10: n-gram yerel ad kanalı.

Taban: veritabanı yolu ``project_root/sigs/ngram_name_db``; ``--output-dir`` verilince
project_root çıktı dizini olur ve adım SESSİZCE döner (istatistik yok, uyarı yok). Çalıştığında
``re.subn(r"\\bvar\\b", ad, kod)`` bütün dosyaya uygulanıyordu: dizgi ve yorum da değişiyor,
geçersiz ad (``int``) ve dosyada zaten kullanılan ad süzülmüyordu.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from karadul.config import Config
from karadul.pipeline.steps import _feedback_typing_extras as fte
from karadul.reconstruction import ngram_namer as nn


def _ctx(root: Path) -> SimpleNamespace:
    cfg = Config()
    cfg.project_root = root
    cfg.data_root = root  # GHIDRA-14 (P15b): veritabanı yalnız veri kökünde aranır
    return SimpleNamespace(pipeline_context=SimpleNamespace(config=cfg))


def test_veri_yoksa_durum_yazilir(tmp_path: Path) -> None:
    d = tmp_path / "typed"
    d.mkdir()
    (d / "FUN_1.c").write_text("void FUN_1(void)\n{\n  return;\n}\n", encoding="utf-8")
    stats: dict = {}
    fte.run_ngram_naming(ctx=_ctx(tmp_path / "ws"), iter_index=0, decompiled_dir=d,
                         incremental_files=None, stats=stats, errors=[])
    assert stats["ngram_naming_durum"] == "veri_yok"
    assert stats["ngram_db_aranan"] == [str(tmp_path / "ws" / "sigs" / "ngram_name_db")]


def test_data_root_once_aranir(tmp_path: Path) -> None:
    # GHIDRA-14 (P15b): çıktı kökü (project_root) artık hiç aranmaz.
    cfg = SimpleNamespace(project_root=tmp_path / "ws", data_root=tmp_path / "veri")
    assert fte.ngram_db_dirs(cfg) == [
        tmp_path / "veri" / "sigs" / "ngram_name_db",
    ]


class _SahteNamer:
    def __init__(self, db_dir: Path | None = None) -> None:
        self.db_dir = db_dir

    def predict(self, code: str, func_name: str = "") -> nn.NgramNamerResult:
        tahmin = {"local_10": "buffer", "uVar1": "int", "uVar2": "count", "uVar3": "buffer"}
        return nn.NgramNamerResult(func_name=func_name, predictions={
            v: nn.NgramPrediction(var_name=v, predicted_name=a, confidence=0.9)
            for v, a in tahmin.items()
        })


def test_ad_yalniz_kodda_suzgecli_ve_cakismasiz(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "sigs" / "ngram_name_db").mkdir(parents=True)
    monkeypatch.setattr(nn, "NgramNamer", _SahteNamer)
    d = tmp_path / "typed"
    d.mkdir()
    kaynak = (
        "void FUN_1(void)\n{\n"
        "  char local_10 [16];\n"
        "  int uVar1;\n"
        "  int uVar2;\n"
        "  int uVar3;\n"
        "  int count;\n"
        "  /* local_10 burada */\n"
        "  FUN_2(local_10, \"local_10 dizgide\");\n"
        "  FUN_3(uVar1, uVar2, uVar3, count);\n"
        "  return;\n}\n"
    )
    (d / "FUN_1.c").write_text(kaynak, encoding="utf-8")
    stats: dict = {}
    fte.run_ngram_naming(ctx=_ctx(tmp_path), iter_index=0, decompiled_dir=d,
                         incremental_files=None, stats=stats, errors=[])
    metin = (d / "FUN_1.c").read_text(encoding="utf-8")
    assert stats["ngram_naming_durum"] == "calisti"
    # kodda değişti, yorum ve dizgide değişmedi
    assert "  char buffer [16];" in metin
    assert "FUN_2(buffer, \"local_10 dizgide\");" in metin
    assert "/* local_10 burada */" in metin
    # ``int`` geçersiz ad; ``count`` dosyada zaten var; ``buffer`` ikinci kez verilmez
    assert "  int uVar1;" in metin
    assert "  int uVar2;" in metin
    assert "  int uVar3;" in metin
    assert stats["ngram_names_applied"] == 1
    assert stats["ngram_rejected_invalid"] == 1
    assert stats["ngram_rejected_collision"] == 2


@pytest.mark.parametrize("ad", ["while", "123abc", "a-b"])
def test_gecersiz_adlar_uygulanmaz(ad: str) -> None:
    kod, uygulanan, gecersiz, cakisma = fte.apply_local_renames("  x = local_8;\n", {"local_8": ad})
    assert (kod, uygulanan, gecersiz, cakisma) == ("  x = local_8;\n", 0, 1, 0)
