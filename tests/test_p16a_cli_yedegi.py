"""P16a / GHIDRA-08: analyzeHeadless (CLI) yedeği çıkış koduna değil çıktıya göre başarı verir.

Eski davranış (kulvar GHIDRA-08, kod): ``success = result.success`` (yalnız çıkış kodu). Ghidra
12.1.2'de Jython yok; Python 3 betikleri analyzeHeadless ile koşmaz, Ghidra yine 0 ile çıkar →
"Ghidra başarılı, 0 fonksiyon". CFG / P-Code betikleri ``ghidra_cfg.json`` / ``ghidra_pcode.json``
yazdığı için anahtar ``ghidra_cfg`` oluyor, static'te ``ghidra_ghidra_cfg.json``'a gidiyordu.

Ghidra yok: süreç koşucusu sahte; betik çıktıları elle yazılır.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from karadul.config import Config
from karadul.ghidra.headless import GhidraHeadless


def _gh(tmp_path, rc=0, stdout="INFO  REPORT: Import succeeded\n", yaz=None):
    gh = GhidraHeadless.__new__(GhidraHeadless)
    cfg = Config()
    cfg.binary_reconstruction.ghidra_data_type_archives = []
    gh.config = cfg
    gh.analyze_headless = tmp_path / "support" / "analyzeHeadless"

    class _Runner:
        def run_command(self, cmd, timeout=None, env=None):
            if yaz:
                yaz(Path(env["KARADUL_OUTPUT"]))
            return SimpleNamespace(success=rc == 0, returncode=rc, stdout=stdout, stderr="")

    gh.runner = _Runner()
    return gh


def _kos(gh, tmp_path):
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    return gh._analyze_cli(tmp_path / "ikili", tmp_path / "proj", "p", [], 60, out)


def test_cikis_sifir_ama_betik_ciktisi_yoksa_basarisiz(tmp_path):
    r = _kos(_gh(tmp_path, stdout="ERROR Python is not available\n"), tmp_path)
    assert r["success"] is False
    assert "betik çıktısı yok" in r["error"]
    assert "Python is not available" in r["error"]
    assert "functions" in r["missing_outputs"]


def test_cikis_kodu_hatasi_nedenle(tmp_path):
    r = _kos(_gh(tmp_path, rc=1, stdout="java.lang.OutOfMemoryError\n"), tmp_path)
    assert r["success"] is False
    assert "çıkış kodu 1" in r["error"] and "OutOfMemoryError" in r["error"]


def test_betikler_yazdiysa_basarili_ve_anahtarlar_pyghidra_ile_ayni(tmp_path):
    def yaz(d: Path):
        (d / "functions.json").write_text(json.dumps({"total": 2, "functions": []}))
        (d / "decompiled.json").write_text(json.dumps({"success": 2, "total_attempted": 2, "functions": []}))
        (d / "strings.json").write_text(json.dumps({"total": 0, "strings": []}))
        (d / "call_graph.json").write_text(json.dumps({}))
        (d / "xrefs.json").write_text(json.dumps({}))
        (d / "ghidra_cfg.json").write_text(json.dumps({"total_functions": 2}))
        (d / "ghidra_pcode.json").write_text(json.dumps({"total_functions": 2}))

    r = _kos(_gh(tmp_path, yaz=yaz), tmp_path)
    assert r["success"] is True and r["error"] is None
    assert "cfg" in r["scripts_output"] and "pcode" in r["scripts_output"]
    assert "ghidra_cfg" not in r["scripts_output"]
    assert r["missing_outputs"] == []
