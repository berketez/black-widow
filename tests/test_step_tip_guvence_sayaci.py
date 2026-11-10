"""Tip kurtarmanın son koşul sayacı rapora ulaşır (2026-11-10).

``CTypeRecoverer`` tip değişimi dizgi ya da yorum metnini değiştirirse dosyayı özgün metniyle
yazar ve ``type_recovery_reverted`` sayar. Sayaç eskiden adımda okunmuyordu.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from karadul.pipeline.steps import _feedback_typing as ft


def _sonuc(**alanlar):
    taban = dict(success=True, structs=[], enums=[], total_types_recovered=0, types_header=None,
                 output_files=[], errors=[])
    taban.update(alanlar)
    return SimpleNamespace(**taban)


def _kos(tmp_path: Path, sonuc, stats=None, iter_index=0):
    stats = {} if stats is None else stats
    errors: list[str] = []
    ctx = SimpleNamespace(pipeline_context=SimpleNamespace(
        config=SimpleNamespace(binary_reconstruction=SimpleNamespace(enable_type_recovery=True)),
    ))
    girdi = tmp_path / "girdi"
    girdi.mkdir(exist_ok=True)
    ft._run_type_recovery(
        ctx=ctx, iter_index=iter_index, decompiled_dir=girdi, reconstructed_dir=tmp_path,
        incremental_files=None, rglob_c_files=[],
        type_recoverer=SimpleNamespace(recover=lambda *a, **k: sonuc),
        functions_json=tmp_path / "f.json", strings_json=tmp_path / "s.json",
        ghidra_types_json=tmp_path / "t.json", call_graph_json=tmp_path / "cg.json",
        decompiled_json=tmp_path / "d.json", computation_result=None,
        stats=stats, errors=errors, artifacts={}, func_count=0,
    )
    return stats, errors


def test_temiz_kosuda_sayac_sifir_ve_hata_yok(tmp_path):
    stats, errors = _kos(tmp_path, _sonuc(type_recovery_reverted=0))
    assert stats["type_recovery_reverted"] == 0
    assert errors == []


def test_geri_alinan_dosya_sayilir_ve_uyari_olur(tmp_path):
    stats, errors = _kos(tmp_path, _sonuc(type_recovery_reverted=3))
    assert stats["type_recovery_reverted"] == 3
    assert len(errors) == 1 and "3 dosyada" in errors[0] and "geri alındı" in errors[0]


def test_yinelemeler_arasinda_toplanir(tmp_path):
    stats, errors = _kos(tmp_path, _sonuc(type_recovery_reverted=2))
    stats, errors2 = _kos(tmp_path, _sonuc(type_recovery_reverted=1), stats=stats, iter_index=1)
    assert stats["type_recovery_reverted"] == 3
    assert len(errors) == 1 and len(errors2) == 1 and "1 dosyada" in errors2[0]


def test_basarisiz_sonucta_da_sayac_okunur(tmp_path):
    stats, errors = _kos(tmp_path, _sonuc(success=False, errors=["x"], type_recovery_reverted=1))
    assert stats["type_recovery_reverted"] == 1
    assert errors[0] == "x" and "geri alındı" in errors[1]


def test_alan_yoksa_ya_da_sayi_degilse_sayac_uydurulmaz(tmp_path):
    stats, errors = _kos(tmp_path, _sonuc())
    assert "type_recovery_reverted" not in stats and errors == []
    stats, errors = _kos(tmp_path, _sonuc(type_recovery_reverted=True))
    assert "type_recovery_reverted" not in stats and errors == []
    stats, errors = _kos(tmp_path, _sonuc(type_recovery_reverted="2"))
    assert "type_recovery_reverted" not in stats and errors == []
