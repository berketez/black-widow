"""P05c Kalem 5 — n-gram yerel adlarının köken kaydı.

Taban: n-gram kanalı (``run_ngram_naming``) adları ``typed/*.c``'ye yazıyor, yalnız sayaç
tutuyordu (``ngram_names_applied``); hangi değişkenin hangi adı hangi güvenle aldığı hiçbir
kayıtta yoktu (P15b: Mac htop'ta 15 ad kökensiz). Şimdi her uygulanan ad köken kaydına girer
(``naming_provenance.json`` → ``ngram_locals``; c_namer kaydı yoksa
``ngram_provenance[_iterN].json``).
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from karadul.config import Config
from karadul.pipeline.steps import _feedback_typing_extras as fte
from karadul.reconstruction import ngram_namer as nn


def _ctx(root: Path) -> SimpleNamespace:
    cfg = Config()
    cfg.project_root = root
    cfg.data_root = root
    return SimpleNamespace(pipeline_context=SimpleNamespace(config=cfg))


class _SahteNamer:
    def __init__(self, db_dir: Path | None = None) -> None:
        self.db_dir = db_dir

    def predict(self, code: str, func_name: str = "") -> nn.NgramNamerResult:
        tahmin = {
            "local_10": ("buffer", 0.9, "score=1.80, occurrences=2"),
            "uVar1": ("length", 0.3, "score=0.60, occurrences=2"),  # eşiğin altında
            "uVar2": ("int", 0.9, "score=0.90, occurrences=1"),      # geçersiz ad
        }
        return nn.NgramNamerResult(func_name=func_name, predictions={
            v: nn.NgramPrediction(var_name=v, predicted_name=a, confidence=g, evidence=k)
            for v, (a, g, k) in tahmin.items()
        })


_KAYNAK = (
    "// Address: 00101000\n"
    "void FUN_00101000(void)\n{\n"
    "  char local_10 [16];\n"
    "  int uVar1;\n"
    "  int uVar2;\n"
    "  FUN_2(local_10, uVar1, uVar2);\n"
    "  return;\n}\n"
)


def _hazirla(tmp_path: Path, monkeypatch) -> Path:
    (tmp_path / "sigs" / "ngram_name_db").mkdir(parents=True)
    monkeypatch.setattr(nn, "NgramNamer", _SahteNamer)
    rec = tmp_path / "ws" / "reconstructed"
    typed = rec / "typed"
    typed.mkdir(parents=True)
    (typed / "FUN_00101000.c").write_text(_KAYNAK, encoding="utf-8")
    return typed


def test_uygulanan_ad_koken_kaydina_yazilir(tmp_path: Path, monkeypatch) -> None:
    # Yazma yolu (ölçümle yeniden açılırsa): her uygulanan ad köken kaydında
    typed = _hazirla(tmp_path, monkeypatch)
    monkeypatch.setattr(fte, "NGRAM_APPLY_NAMES", True)
    stats: dict = {}
    fte.run_ngram_naming(ctx=_ctx(tmp_path), iter_index=0, decompiled_dir=typed,
                         incremental_files=None, stats=stats, errors=[])
    assert stats["ngram_names_applied"] == 1
    assert stats["ngram_provenance"] == "yazildi:ngram_provenance.json"
    kayit = json.loads((typed.parent / "ngram_provenance.json").read_text(encoding="utf-8"))
    bolum = kayit[fte.NGRAM_PROVENANCE_SECTION]
    assert bolum["source"] == "ngram"
    assert bolum["applied"] == [{
        "file": "FUN_00101000.c", "var": "local_10", "name": "buffer", "source": "ngram",
        "confidence": 0.9, "evidence": "score=1.80, occurrences=2",
    }]
    assert bolum["rejected"] == {"below_min_confidence": 1, "invalid_name": 1, "collision": 0}
    assert bolum["predictions"] == 3
    assert bolum["candidates"] == []
    # kodda yalnız eşiği ve kapıyı geçen ad
    metin = (typed / "FUN_00101000.c").read_text(encoding="utf-8")
    assert "char buffer [16];" in metin and "int uVar1;" in metin and "int uVar2;" in metin


def test_ontanim_aday_kaydi_kod_degismez(tmp_path: Path, monkeypatch) -> None:
    # P05c: ölçülen kesinlik eşiğin altında → ad koda yazılmaz, aday olarak köken kaydında
    typed = _hazirla(tmp_path, monkeypatch)
    assert fte.NGRAM_APPLY_NAMES is False
    stats: dict = {}
    fte.run_ngram_naming(ctx=_ctx(tmp_path), iter_index=0, decompiled_dir=typed,
                         incremental_files=None, stats=stats, errors=[])
    assert (typed / "FUN_00101000.c").read_text(encoding="utf-8") == _KAYNAK
    assert stats["ngram_names_applied"] == 0
    assert stats["ngram_candidates"] == 1
    bolum = json.loads((typed.parent / "ngram_provenance.json").read_text(
        encoding="utf-8"))[fte.NGRAM_PROVENANCE_SECTION]
    assert bolum["applied"] == []
    assert bolum["apply_names"] is False
    assert bolum["candidates"] == [{
        "file": "FUN_00101000.c", "var": "local_10", "name": "buffer", "source": "ngram",
        "confidence": 0.9, "evidence": "score=1.80, occurrences=2",
        "rejected": fte.NGRAM_REJECT_PRECISION,
    }]
    olcum = bolum["measured_precision"]
    assert olcum["threshold"] == 0.06
    assert olcum["D"] is not None and olcum["D"]["kesinlik"] < 0.06


def test_c_namer_kaydina_bolum_eklenir(tmp_path: Path, monkeypatch) -> None:
    typed = _hazirla(tmp_path, monkeypatch)
    monkeypatch.setattr(fte, "NGRAM_APPLY_NAMES", True)
    src = typed.parent / "src_iter1"
    src.mkdir()
    (src / "naming_provenance.json").write_text(
        json.dumps({"schema": "karadul.naming_provenance", "records": {"x": 1}}),
        encoding="utf-8")
    typed1 = typed.parent / "typed_iter1"
    typed.rename(typed1)
    stats: dict = {}
    fte.run_ngram_naming(ctx=_ctx(tmp_path), iter_index=1, decompiled_dir=typed1,
                         incremental_files=None, stats=stats, errors=[])
    assert stats["ngram_provenance"] == "yazildi:src_iter1/naming_provenance.json"
    kayit = json.loads((src / "naming_provenance.json").read_text(encoding="utf-8"))
    assert kayit["records"] == {"x": 1}  # c_namer'ın kaydı korunur
    assert kayit[fte.NGRAM_PROVENANCE_SECTION]["iteration"] == 1
    assert [r["name"] for r in kayit[fte.NGRAM_PROVENANCE_SECTION]["applied"]] == ["buffer"]


def test_apply_local_renames_plan_doner() -> None:
    plan: dict[str, str] = {}
    kod, n, bad, clash = fte.apply_local_renames(
        "  x = local_8 + local_c;\n", {"local_8": "size", "local_c": "x"}, applied_out=plan)
    assert (n, bad, clash) == (1, 0, 1)
    assert plan == {"local_8": "size"}
    assert kod == "  x = size + local_c;\n"


def test_sayac_yinelemeler_boyunca_toplanir(tmp_path: Path, monkeypatch) -> None:
    # Eskiden ikinci yineleme sayaçların üstüne yazıyordu: ilk yinelemenin adları rapordan
    # siliniyordu (birleşik koşu dir: rapor 0, koda yazılan 138).
    typed = _hazirla(tmp_path, monkeypatch)
    monkeypatch.setattr(fte, "NGRAM_APPLY_NAMES", True)
    stats: dict = {}
    fte.run_ngram_naming(ctx=_ctx(tmp_path), iter_index=0, decompiled_dir=typed,
                         incremental_files=None, stats=stats, errors=[])
    typed1 = typed.parent / "typed_iter1"
    typed1.mkdir()
    (typed1 / "FUN_00101000.c").write_text(_KAYNAK, encoding="utf-8")
    fte.run_ngram_naming(ctx=_ctx(tmp_path), iter_index=1, decompiled_dir=typed1,
                         incremental_files=[typed1 / "FUN_00101000.c"], stats=stats, errors=[])
    assert stats["ngram_names_applied"] == 2
    assert stats["ngram_names_applied_iter0"] == 1
    assert stats["ngram_names_applied_iter1"] == 1
    assert stats["ngram_total_predictions"] == 6
    assert stats["ngram_provenance_iter1"] == "yazildi:ngram_provenance_iter1.json"
