"""P15b kalem 4 — kısmi (3) çıkış kodunu başarısız sayan ölçüm betikleri.

P15a'dan beri `karadul analyze` 0 = tam, 1 = başarısız, 3 = kısmi (çıktı var, en az
bir alt adım düştü) döndürüyor. Taban: ``measure.py``, ``adim3_kapilar.py``,
``coverage_matrix.py`` ve ``karadul/scripts/multi_binary_runner.py`` 0 dışı her kodu
başarısız / çökme sayıyordu: kısmi koşunun çıktısı ölçümden düşüyordu.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

DEPO = Path(__file__).resolve().parents[1]


def _yukle(ad: str, yol: Path):
    spec = importlib.util.spec_from_file_location(ad, yol)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[ad] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def measure():
    sys.path.insert(0, str(DEPO / "scripts" / "measurement"))
    return _yukle("p15b_measure", DEPO / "scripts" / "measurement" / "measure.py")


def test_measure_cikis_kodu_durumu(measure) -> None:
    assert measure.run_status_for_exit(0) == "ok"
    assert measure.run_status_for_exit(3) == "partial"
    assert measure.run_status_for_exit(1) == "failed"
    assert measure.run_status_for_exit(None) == "failed"


def test_measure_kismi_kosu_puanlanabilir_kalir(measure, tmp_path: Path, monkeypatch) -> None:
    data = tmp_path / "veri"
    hedef = data / "corpus" / "c" / "bin" / "ikili"
    hedef.parent.mkdir(parents=True)
    hedef.write_bytes(b"\x7fELF")

    class _Surec:
        pid = 0

        def __init__(self, *a, **k) -> None:
            pass

        def wait(self, timeout=None) -> int:
            return 3

    monkeypatch.setattr(measure.subprocess, "Popen", _Surec)
    monkeypatch.setattr(measure.f1, "find_run_artifacts",
                        lambda run_dir: {"ghidra_functions": run_dir / "x.json"})
    monkeypatch.setattr(measure, "cfg_cache_snapshot", lambda: {})
    meta = measure._run_one(tmp_path, tmp_path, data, "etiket", "c", "ikili", 10, True)
    assert meta["status"] == "partial"
    assert meta["exit_code"] == 3


def test_coverage_matrix_kismi_cokme_degil(tmp_path: Path, monkeypatch) -> None:
    cm = _yukle("p15b_coverage_matrix", DEPO / "scripts" / "coverage_matrix.py")
    monkeypatch.setattr(cm, "RUNS", tmp_path)
    monkeypatch.setattr(cm, "label", lambda row: "ikili")
    monkeypatch.setattr(cm.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=3))
    monkeypatch.setattr(cm, "_count_functions", lambda ws: (10, 4))
    monkeypatch.setattr(cm, "_last_error", lambda log: "")
    r = cm.robustness({"path": "/yok"}, 10)
    assert r["status"] == "PARTIAL"
    monkeypatch.setattr(cm.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=1))
    assert cm.robustness({"path": "/yok"}, 10)["status"] == "CRASH"


def test_adim3_kismi_kosu_bitti_yazilir(tmp_path: Path, monkeypatch) -> None:
    sys.path.insert(0, str(DEPO / "scripts" / "measurement"))
    ak = _yukle("p15b_adim3", DEPO / "scripts" / "measurement" / "adim3_kapilar.py")
    monkeypatch.setattr(ak, "ikililer", lambda: {"tek": {"girdi": tmp_path / "g"}})
    monkeypatch.setattr(ak.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=3))
    assert ak.kos(tmp_path / "kok", 1) == 0
    bitti = sorted((tmp_path / "kok").glob("tek/*/BITTI"))
    assert bitti and all(p.read_text().strip() == "3" for p in bitti)


def test_multi_binary_runner_kismi_ayri(tmp_path: Path, monkeypatch) -> None:
    from karadul.scripts import multi_binary_runner as mbr

    ikili = tmp_path / "ikili"
    ikili.write_bytes(b"\x7fELF")
    monkeypatch.setattr(mbr.subprocess, "run",
                        lambda *a, **k: SimpleNamespace(returncode=3, stdout="", stderr=""))
    r = mbr.run_one(ikili, tmp_path / "ws")
    assert r.success is True and r.partial is True
    assert mbr._status_label(r) == "PARTIAL"
    suite = mbr.SuiteResult(suite_name="s", binary_count=1, total_duration_seconds=0.0,
                            binaries=[r])
    assert suite.partial_count == 1
