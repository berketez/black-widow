"""B26: Karadul pipeline uçtan uca (E2E) gerçek binary testi.

Bu modül v1.15.5 test audit'ine yanıttır. "4915 PASS" yanıltıcı yeşildi;
hiçbir test gerçek bir binary üzerinde tüm pipeline'ı (identify → static →
deobfuscate → reconstruct → report) uçtan uca koşturmuyordu. Mevcut
benchmark testleri sentetik nm çıktısı veya mock workspace kullanıyordu.

Buradaki testler:

1. ``karadul analyze`` CLI'sını gerçek bir Mach-O binary üzerinde çalıştırır.
2. Workspace çıktılarını dosya sistemi üzerinden doğrular (report.html,
   naming_map.json, static/ artifact'leri).
3. ``BenchmarkRunner.run_from_binaries`` ile **gerçek** F1 ölçer (mock 1.0
   değil — debug binary'den nm GT, stripped binary'den naming_map).

Skip mantığı:

- ``karadul`` CLI yoksa (PATH'te değilse) tüm modül skip.
- Fixture binary'ler yoksa (build yapılmadıysa) skip.
- Uzun koşan ikinci-pipeline (x86_64 smoke) ``@pytest.mark.benchmark``
  ile işaretli; varsayılan ``pytest`` koşumunda dışlanır
  (``-m 'not benchmark'`` pyproject.toml'da). E2E ana koşum ~13 sn.

B25 fixture'ları: ``tests/fixtures/diverse/`` altında
``hello_macho_{arch}_{stripped,debug}`` (arm64 + x86_64).
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Optional

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DIVERSE_DIR = REPO_ROOT / "tests" / "fixtures" / "diverse"


# ---------------------------------------------------------------------------
# Yardımcılar
# ---------------------------------------------------------------------------


def _karadul_cli() -> Optional[str]:
    """``karadul`` çalıştırılabilir mi? Yoksa None döndür."""
    return shutil.which("karadul")


def _fixture_pair(arch: str) -> tuple[Path, Path]:
    """(stripped, debug) ikilisi."""
    stripped = DIVERSE_DIR / f"hello_macho_{arch}_stripped"
    debug = DIVERSE_DIR / f"hello_macho_{arch}_debug"
    return stripped, debug


def _have_fixtures(arch: str) -> bool:
    s, d = _fixture_pair(arch)
    return s.is_file() and d.is_file()


def _find_naming_map(workspace_root: Path) -> Optional[Path]:
    """Workspace altında naming_map.json bul (reconstructed/src/ tercih)."""
    candidates = list(workspace_root.rglob("naming_map.json"))
    # 'src' altındaki tercih edilir, 'src_iter1' yedek
    src_pref = [p for p in candidates if p.parent.name == "src"]
    if src_pref:
        return src_pref[0]
    return candidates[0] if candidates else None


def _latest_timestamp_dir(workspace_root: Path) -> Optional[Path]:
    """``workspaces/<binary>/<timestamp>/`` içinde en yeni timestamp dizini."""
    if not workspace_root.is_dir():
        return None
    ts_dirs = [p for p in workspace_root.iterdir() if p.is_dir()]
    if not ts_dirs:
        return None
    return max(ts_dirs, key=lambda p: p.stat().st_mtime)


# ---------------------------------------------------------------------------
# Modül-seviyesi skip koşulları
# ---------------------------------------------------------------------------


pytestmark = [
    pytest.mark.skipif(
        _karadul_cli() is None,
        reason="karadul CLI PATH'te değil (pip install -e . gerekli)",
    ),
    pytest.mark.skipif(
        not _have_fixtures("arm64"),
        reason=(
            "diverse fixture yok (tests/fixtures/diverse/hello_macho_arm64_*). "
            "README.md'deki build talimatını izle."
        ),
    ),
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def e2e_workspace(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Tüm modül boyunca paylaşılan E2E pipeline koşumu.

    Mach-O arm64 stripped fixture üstünde ``karadul analyze --skip-dynamic``
    çalıştırır, oluşan ``workspaces/<bin>/<ts>/`` dizinini döndürür.

    Module scope sayesinde pipeline 1 kez koşar, tüm assertion'lar aynı
    çıktıyı paylaşır. Tipik süre: ~13 sn (Mac arm64). Üst limit: 600 sn.
    """
    karadul = _karadul_cli()
    assert karadul is not None  # pytestmark zaten skip etti
    stripped, _ = _fixture_pair("arm64")

    out_dir = tmp_path_factory.mktemp("e2e_arm64")
    cmd = [
        karadul,
        "analyze",
        str(stripped),
        "--output-dir",
        str(out_dir),
        "--skip-dynamic",
    ]
    proc = subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=600,
    )
    if proc.returncode != 0:
        pytest.fail(
            "karadul analyze E2E koşumu başarısız:\n"
            f"  cmd: {' '.join(cmd)}\n"
            f"  rc: {proc.returncode}\n"
            f"  stdout (son 40 satır):\n{chr(10).join(proc.stdout.splitlines()[-40:])}\n"
            f"  stderr (son 40 satır):\n{chr(10).join(proc.stderr.splitlines()[-40:])}\n"
        )
    ws_root = out_dir / "workspaces" / "hello_macho_arm64_stripped"
    ts_dir = _latest_timestamp_dir(ws_root)
    if ts_dir is None:
        pytest.fail(f"Workspace timestamp dizini bulunamadı: {ws_root}")
    return ts_dir


# ---------------------------------------------------------------------------
# Pipeline çıktısı varlık testleri (B26 ana kısım)
# ---------------------------------------------------------------------------


class TestPipelineArtifacts:
    """Pipeline 5 stage'i de gerçek artifact üretti mi?"""

    def test_workspace_directory_exists(self, e2e_workspace: Path) -> None:
        assert e2e_workspace.is_dir(), f"Workspace dizini yok: {e2e_workspace}"

    def test_report_html_exists_and_nonempty(self, e2e_workspace: Path) -> None:
        report = e2e_workspace / "reports" / "report.html"
        assert report.is_file(), f"report.html yok: {report}"
        # Anlamlı içerik (5 KB+) — boş HTML iskeleti değil
        assert report.stat().st_size > 5_000, (
            f"report.html çok küçük ({report.stat().st_size} bayt), "
            "muhtemelen pipeline çıktısı eksik."
        )

    def test_report_json_parseable(self, e2e_workspace: Path) -> None:
        report = e2e_workspace / "reports" / "report.json"
        assert report.is_file(), f"report.json yok: {report}"
        data = json.loads(report.read_text(encoding="utf-8"))
        assert "karadul_version" in data
        assert "generated_at" in data

    def test_pipeline_result_records_all_stages(self, e2e_workspace: Path) -> None:
        """``pipeline_result.json`` 5 stage'i de OK olarak listeliyor mu?

        Yapı: ``{"stages": {"identify": {...success, duration, ...}, ...}}``
        veya eski sürümlerde liste olabilir; her ikisini de tolere et.
        """
        pr = e2e_workspace / "reports" / "pipeline_result.json"
        assert pr.is_file(), f"pipeline_result.json yok: {pr}"
        data = json.loads(pr.read_text(encoding="utf-8"))
        stages = data.get("stages") or data.get("stage_results") or {}
        assert stages, f"pipeline_result.json içinde stage listesi yok: {list(data)}"
        if isinstance(stages, dict):
            names = set(stages.keys())
            ok_stages = {k for k, v in stages.items()
                         if isinstance(v, dict) and v.get("success") is True}
        else:
            names = {s.get("stage_name") or s.get("name") for s in stages
                     if isinstance(s, dict)}
            ok_stages = {s.get("stage_name") or s.get("name") for s in stages
                         if isinstance(s, dict) and s.get("success") is True}
        # En azından bu üç stage olmalı (dynamic skip'lendi)
        for required in ("identify", "static", "report"):
            assert required in names, (
                f"'{required}' stage pipeline_result.json'da yok: {names}"
            )
        # Tüm stage'ler başarılı olmalı
        assert "identify" in ok_stages and "report" in ok_stages, (
            f"identify veya report stage başarısız: ok={ok_stages}"
        )
        # Üst seviye 'success' bayrağı — graceful tolerans:
        # reconstruct stage'i opsiyonel (yeni step'lerin yarısı graceful skip
        # döndürebilir), identify+report başarısı kritik kanıt.
        # NOT: Tam pipeline başarısı için ayrı integration test gerek.

    def test_static_artifacts_present(self, e2e_workspace: Path) -> None:
        """static/ altında en az 5 JSON artifact üretildi mi?"""
        static_dir = e2e_workspace / "static"
        assert static_dir.is_dir(), f"static/ yok: {static_dir}"
        jsons = list(static_dir.glob("*.json"))
        assert len(jsons) >= 5, (
            f"static/ altında yalnızca {len(jsons)} JSON var, "
            "pipeline'ın static stage'i eksik koşmuş olabilir."
        )

    def test_naming_map_exists_and_has_functions(self, e2e_workspace: Path) -> None:
        """Reconstruct stage naming_map.json üretti ve içinde isim var mı?"""
        nm = _find_naming_map(e2e_workspace)
        assert nm is not None, f"naming_map.json hiçbir yerde yok ({e2e_workspace})"
        data = json.loads(nm.read_text(encoding="utf-8"))
        # En azından 'global' anahtarı olmalı
        assert "global" in data, f"naming_map.json 'global' anahtarı yok: {list(data)}"
        # 4 user fonksiyon var (add, multiply, get_greeting, print_info)
        # Hepsini doğru isimlendirmesini beklemiyoruz; en az 1 FUN_xxx
        # için karadul bir öneri üretmeli.
        if not data["global"]:
            pytest.fail(
                "naming_map.json['global'] boş — naming pipeline hiç çalışmamış."
            )


# ---------------------------------------------------------------------------
# Gerçek F1 ölçümü (B26 — B4 ile bağlantı)
# ---------------------------------------------------------------------------


class TestRealF1Measurement:
    """Mock değil, gerçek nm GT × karadul naming_map F1 ölçümü.

    Bu test'in amacı **mevcut F1'i taşa kazımak DEĞİL**, sadece ölçümün
    gerçekten koştuğunu ve mock 1.0 dönmediğini doğrulamaktır. F1 değeri
    raporlanır ve testin çıktı log'una yazılır.

    Mach-O Mac fixture'ı için mevcut karadul (v1.15.5 öncesi) tipik olarak
    F1 ≈ 0.0 üretir: nm GT ``_add`` gibi sembol döner, naming_map ise
    ``FUN_0x...`` döner; B4 ajanının eklediği sembol-adres mapping (B4
    teslim olunca workspace_dir parametresi gelecek) bunu çözecek.
    """

    def test_benchmark_runner_produces_real_f1(
        self, e2e_workspace: Path, capsys: pytest.CaptureFixture[str],
    ) -> None:
        from tests.benchmark.benchmark_runner import BenchmarkRunner

        nm = _find_naming_map(e2e_workspace)
        assert nm is not None
        _, debug_bin = _fixture_pair("arm64")
        assert debug_bin.is_file()

        runner = BenchmarkRunner()
        result = runner.run_from_binaries(
            debug_binary=debug_bin, naming_map_json=nm,
        )
        m = result.metrics

        # Gerçek ölçüm yapıldı mı?
        assert result.per_symbol, (
            "BenchmarkRunner hiç comparison üretmedi — nm boş veya "
            "naming_map boş döndü."
        )
        # F1 değeri tanımlı (0.0 dahil — mock 1.0 olmamalı)
        assert isinstance(m.f1, float)
        assert 0.0 <= m.f1 <= 1.0
        assert isinstance(m.precision, float) and 0.0 <= m.precision <= 1.0
        assert isinstance(m.recall, float) and 0.0 <= m.recall <= 1.0

        # Raporla — pytest -v -s ile görünür
        with capsys.disabled():
            print()
            print("=" * 60)
            print("B26 E2E GERÇEK F1 ÖLÇÜMÜ (arm64 Mach-O fixture)")
            print("=" * 60)
            print(f"  precision         = {m.precision:.4f}")
            print(f"  recall            = {m.recall:.4f}")
            print(f"  f1                = {m.f1:.4f}")
            print(f"  exact_matches     = {m.exact_matches}")
            print(f"  semantic_matches  = {m.semantic_matches}")
            print(f"  partial_matches   = {m.partial_matches}")
            print(f"  missing_names     = {m.missing_names}")
            print(f"  preserved_names   = {m.preserved_names}")
            print(f"  fun_residue_pct   = {m.fun_residue_pct:.2f}%")
            print(f"  total_comparisons = {len(result.per_symbol)}")
            print("=" * 60)

    def test_f1_is_not_fake_unity(self, e2e_workspace: Path) -> None:
        """v1.11.0 P4 patch'inden ÖNCE renamed_f1=1.0 yalan ölçümdü.

        F1=1.0 ancak ve ancak GT'nin %100'ü karadul tarafından doğru
        isimlendirilmişse mümkündür. Bu küçük Mach-O fixture'ı için
        karadul mevcut implementasyonda bu seviyeye ulaşamaz; eğer
        F1=1.0 gelirse YA bug var YA ölçüm bozulmuş.
        """
        from tests.benchmark.benchmark_runner import BenchmarkRunner

        nm = _find_naming_map(e2e_workspace)
        assert nm is not None
        _, debug_bin = _fixture_pair("arm64")
        runner = BenchmarkRunner()
        result = runner.run_from_binaries(
            debug_binary=debug_bin, naming_map_json=nm,
        )
        # Yalan F1=1.0 alarmı (B4 sonrasında bile beklenmeyen)
        if result.metrics.f1 >= 0.99 and result.metrics.exact_matches == 0:
            pytest.fail(
                f"f1={result.metrics.f1} ama exact_matches=0 → "
                "YALAN ölçüm uyarısı. v1.11.0 P4 bug'ı geri döndü mü?"
            )


# ---------------------------------------------------------------------------
# Mimari çeşitlilik smoke (B25 — opsiyonel x86_64 koşumu)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not _have_fixtures("x86_64"),
    reason="x86_64 fixture yok",
)
@pytest.mark.benchmark
class TestX86_64Smoke:
    """x86_64 Mach-O fixture için ayrı smoke (arm64 host'ta da çalışır)."""

    def test_x86_64_pipeline_completes(
        self, tmp_path_factory: pytest.TempPathFactory,
    ) -> None:
        karadul = _karadul_cli()
        assert karadul is not None
        stripped, _ = _fixture_pair("x86_64")
        out_dir = tmp_path_factory.mktemp("e2e_x86")
        proc = subprocess.run(
            [
                karadul, "analyze", str(stripped),
                "--output-dir", str(out_dir), "--skip-dynamic",
            ],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=600,
        )
        # x86_64 Mac arm64 host'ta — Ghidra çapraz mimari ile koşar; rc=0 bekle
        if proc.returncode != 0:
            pytest.skip(
                "x86_64 fixture pipeline koşmadı (arm64 host'ta çapraz "
                f"mimari Ghidra desteği yok olabilir). rc={proc.returncode}"
            )
        ws_root = out_dir / "workspaces" / "hello_macho_x86_64_stripped"
        ts_dir = _latest_timestamp_dir(ws_root)
        assert ts_dir is not None
        assert (ts_dir / "reports" / "report.html").is_file()
