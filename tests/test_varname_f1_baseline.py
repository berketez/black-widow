"""Regresyon guard'ı: varname_bench değişken-adı F1 baseline'ının altına düşmesin.

`tests/fixtures/varname_bench/baseline.json` (commit 15f83f1, karadul 1.20.0-pre)
referans değerleri tutar. İki katman test var:

1. `test_baseline_json_wellformed` (MARKER YOK → default suitte koşar, hızlı):
   baseline.json'un iyi biçimli ve iç-tutarlı (F1 = 2PR/(P+R), recall = TP/(TP+FN),
   precision = TP/(TP+FP)) olduğunu doğrular. Dosyanın kazara bozulmasını yakalar.
   Ghidra/pipeline GEREKTİRMEZ.

2. `test_no_regression_vs_baseline` (@pytest.mark.benchmark → default suitten hariç):
   fixture `.stripped` binary'yi karadul pipeline'ı (Ghidra) ile yeniden analiz
   eder, `scripts/varname_f1_eval.py` ile DWARF GT'ye karşı ölçer ve SIZINTISIZ
   metriklerin (param recall + değişken(P+L) F1) baseline − EPS altına inmediğini
   doğrular. Fonksiyon F1 gnulib imza sızıntısı yüzünden GÜVENİLMEZ → guard EDİLMEZ.

Ölçüm ~dakikalar sürer (Ghidra decompile) → benchmark marker'ı default `addopts`
(`-m 'not integration and not benchmark'`) tarafından atlanır. Çalıştırmak için:

    pytest tests/test_varname_f1_baseline.py -m benchmark

Reconstruction kaynağı (öncelik sırası):
  1. Env `KARADUL_VARNAME_RECON_O0` / `_O2` → hazır bir `<clean>/src` (veya `<clean>`)
     dizini; pipeline koşturmadan onu ölçer (hızlı tekrar için).
  2. Bundle Ghidra (veya `GHIDRA_INSTALL_DIR` env) → pipeline'ı geçici dizine koşar.
  3. Hiçbiri yoksa → SKIP.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "varname_bench"
BASELINE_PATH = FIXTURE / "baseline.json"

# Baseline'ın altına inmeye izin verilen tolerans (gürültü payı).
EPS = 0.02

# Guard edilen SIZINTISIZ metrikler: (blok, alan). Fonksiyon F1 KASITEN yok
# (gnulib imza sızıntısı → güvenilmez).
GUARDED = [
    ("param", "recall"),
    ("variable", "f1"),
]


def _load_baseline() -> dict:
    assert BASELINE_PATH.is_file(), f"baseline.json yok: {BASELINE_PATH}"
    return json.loads(BASELINE_PATH.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# 1) Hızlı tutarlılık testi (marker YOK → default suit)
# ---------------------------------------------------------------------------
def test_baseline_json_wellformed():
    """baseline.json iyi biçimli ve iç-tutarlı (metrik ↔ ham sayım)."""
    data = _load_baseline()
    assert "_meta" in data
    assert data["_meta"]["measured_date"], "measured_date meta alanı boş"
    assert data["_meta"]["commit"], "commit meta alanı boş"
    assert data["_meta"]["karadul_version"], "karadul_version meta alanı boş"

    for opt in ("O0", "O2"):
        assert opt in data, f"{opt} baseline'da yok"
        block = data[opt]
        # Fonksiyon F1 sızıntı damgası korunmuş olmalı.
        note = block["function"].get("function_f1_note", "")
        assert "leakage" in note and "NOT trustworthy" in note, (
            f"{opt}: fonksiyon F1 sızıntı damgası eksik/bozuk: {note!r}"
        )
        for metric in ("function", "param", "local", "variable"):
            m = block[metric]
            tp, fp, fn = m["tp"], m["fp"], m["fn"]
            exp_p = tp / (tp + fp) if (tp + fp) else 0.0
            exp_r = tp / (tp + fn) if (tp + fn) else 0.0
            exp_f1 = (2 * exp_p * exp_r / (exp_p + exp_r)) if (exp_p + exp_r) else 0.0
            assert m["precision"] == pytest.approx(exp_p, abs=1e-9), (
                f"{opt}/{metric}: precision TP/FP/FN ile tutarsız")
            assert m["recall"] == pytest.approx(exp_r, abs=1e-9), (
                f"{opt}/{metric}: recall TP/FP/FN ile tutarsız")
            assert m["f1"] == pytest.approx(exp_f1, abs=1e-9), (
                f"{opt}/{metric}: F1 = 2PR/(P+R) tutmuyor")

    # Bilinen değerler (transkripsiyon nöbetçisi): param recall ARTIK 0.000 DEĞİL.
    assert data["O0"]["param"]["recall"] > 0.30, (
        "O0 param recall bayat 0.000'a geri dönmüş görünüyor")
    assert data["O2"]["param"]["recall"] > 0.30, (
        "O2 param recall bayat 0.000'a geri dönmüş görünüyor")


# ---------------------------------------------------------------------------
# 2) Gerçek regresyon guard'ı (pipeline koşar → @benchmark, default'ta atlanır)
# ---------------------------------------------------------------------------
def _bundle_resources() -> Path | None:
    p = Path.home() / "Library" / "BlackWidowBuild" / "Black Widow.app" / "Contents" / "Resources"
    return p if p.is_dir() else None


def _pipeline_env() -> dict | None:
    """karadul analyze için ortam. Ghidra bulunamazsa None."""
    env = os.environ.copy()
    if env.get("GHIDRA_INSTALL_DIR"):
        return env
    res = _bundle_resources()
    if res is None:
        return None
    jdk_home = res / "jdk" / "Contents" / "Home"
    env["GHIDRA_INSTALL_DIR"] = str(res / "ghidra")
    env["JAVA_HOME"] = str(jdk_home)
    env["PATH"] = str(jdk_home / "bin") + os.pathsep + env.get("PATH", "")
    env.setdefault("KARADUL_SIG_LMDB_PATH", str(res / "signatures.lmdb"))
    return env


def _resolve_recon_src(opt: str, tmp_path: Path) -> Path:
    """opt ('O0'/'O2') için reconstructed `<clean>/src` dizinini döndür.

    Env cache → yoksa pipeline koşumu. Ne bulunur ne koşturulabilirse SKIP.
    """
    env_key = f"KARADUL_VARNAME_RECON_{opt}"
    env_val = os.environ.get(env_key)
    if env_val:
        p = Path(env_val)
        src = p / "src" if (p / "src").is_dir() else p
        if not src.is_dir():
            pytest.skip(f"{env_key} geçersiz dizin: {env_val}")
        return src

    stripped = FIXTURE / "build" / f"hashbench_{opt}.stripped"
    if not stripped.is_file():
        pytest.skip(f"fixture yok: {stripped} (önce gen_fixture.sh çalıştır)")

    env = _pipeline_env()
    if env is None:
        pytest.skip(
            "Ghidra bulunamadı (GHIDRA_INSTALL_DIR set değil, bundle yok) ve "
            f"{env_key} cache verilmedi → pipeline koşturulamıyor")

    ws = tmp_path / f"ws_{opt}"
    clean = tmp_path / f"clean_{opt}"
    cmd = [
        sys.executable, "-m", "karadul", "analyze", str(stripped),
        "--skip-dynamic", "--lmdb-sigdb",
        "--output-dir", str(ws), "--output", str(clean),
    ]
    proc = subprocess.run(cmd, cwd=str(ROOT), env=env,
                          capture_output=True, text=True, timeout=1800)
    if proc.returncode != 0:
        pytest.fail(
            f"karadul analyze başarısız (rc={proc.returncode})\n"
            f"STDERR (son):\n{proc.stderr[-2000:]}")
    src = clean / "src"
    assert src.is_dir(), f"pipeline src üretmedi: {src}"
    return src


@pytest.mark.benchmark
@pytest.mark.parametrize("opt", ["O0", "O2"])
def test_no_regression_vs_baseline(opt: str, tmp_path: Path):
    """Sızıntısız F1 metrikleri baseline − EPS altına inmemeli."""
    sys.path.insert(0, str(ROOT / "scripts"))
    import varname_f1_eval as vfe  # noqa: E402

    baseline = _load_baseline()[opt]
    debug = FIXTURE / "build" / f"hashbench_{opt}"
    if not debug.is_file():
        pytest.skip(f"debug binary yok: {debug}")

    recon_src = _resolve_recon_src(opt, tmp_path)

    dwarf_gt, recon = vfe.build_gt_and_recon(debug, recon_src)
    assert dwarf_gt, "DWARF GT boş — dSYM/debug info okunamadı"
    assert recon, "reconstructed fonksiyon yok — src ayrıştırılamadı"

    calc = vfe.AccuracyCalculator()
    res = vfe.evaluate(dwarf_gt, recon, calc)
    measured = {
        "param": res["param_prf"],
        "variable": res["var_prf"],
        "local": res["local_prf"],
        "function": res["func_prf"],
    }

    failures = []
    for block, field in GUARDED:
        got = getattr(measured[block], field)
        base = baseline[block][field]
        if got < base - EPS:
            failures.append(
                f"{opt}/{block}.{field}: {got:.3f} < baseline {base:.3f} − {EPS} "
                f"= {base - EPS:.3f}  (REGRESYON)")
    assert not failures, "F1 regresyonu:\n" + "\n".join(failures)
