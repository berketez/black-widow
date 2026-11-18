"""P-GÜV / GHIDRA-13: ``karadul run`` analiz edilen kodu yerelde çalıştırır.

Eski davranış: kapıya ve ağ ayarına bakmadan ``npm install`` (kayıt
deposundan indirme) + ``npm start``; uyarı "güvenilmeyen kaynaktan
gelebilir" diyordu; hedef adında ``..`` denetimi yoktu; çalışma alanı yoksa
yığın izi basılıyordu.

Bu testler HİÇBİR ŞEY çalıştırmaz: ``safe_run`` ve ``resolve_tool`` sahte
nesnelerle değiştirilir, yalnız kurulacak komut satırları kaydedilir.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from karadul.cli import main as karadul_main


@pytest.fixture
def fake_exec(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    import karadul.core.safe_subprocess as ss

    calls: list[list[str]] = []

    def _fake_run(cmd, *args, **kwargs):
        calls.append([str(c) for c in cmd])
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(ss, "safe_run", _fake_run)
    monkeypatch.setattr(ss, "resolve_tool", lambda name: f"/sahte/{name}")
    return calls


def _workspace(tmp_path: Path, with_package_json: bool = True) -> Path:
    ws = tmp_path / "workspaces"
    rec = ws / "hedef" / "reconstructed"
    rec.mkdir(parents=True)
    if with_package_json:
        (rec / "package.json").write_text('{"name": "x", "scripts": {"start": "node index.js"}}')
    (rec / "index.js").write_text("// analiz edilen kod\n")
    return ws


def _yaml(tmp_path: Path, *, allow: bool, network: bool) -> str:
    p = tmp_path / "k.yaml"
    p.write_text(
        f"security:\n  allow_target_execution: {str(allow).lower()}\n"
        f"network:\n  enabled: {str(network).lower()}\n",
        encoding="utf-8",
    )
    return str(p)


def _flat(text: str) -> str:
    """rich satır kaydırmasını yok say (boşlukları tekle)."""
    return " ".join(text.split())


def _invoke(args: list[str], cwd: Path):
    runner = CliRunner(env={"KARADUL_NONINTERACTIVE": "1"})
    with runner.isolated_filesystem(temp_dir=cwd):
        return runner.invoke(karadul_main, ["run", *args])


class TestRunGate:
    def test_gate_closed_by_default_runs_nothing(self, fake_exec, tmp_path: Path) -> None:
        ws = _workspace(tmp_path)
        res = _invoke(["hedef", "--workspace-dir", str(ws), "--yes"], tmp_path)
        assert res.exit_code == 2
        assert fake_exec == []
        assert "allow_target_execution" in _flat(res.output)

    def test_gate_closed_in_yaml_runs_nothing(self, fake_exec, tmp_path: Path) -> None:
        ws = _workspace(tmp_path)
        cfg = _yaml(tmp_path, allow=False, network=True)
        res = _invoke(["hedef", "--workspace-dir", str(ws), "--config", cfg, "--yes"], tmp_path)
        assert res.exit_code == 2
        assert fake_exec == []
        assert "kapısı kapalı" in _flat(res.output)

    def test_network_off_installs_offline(self, fake_exec, tmp_path: Path) -> None:
        ws = _workspace(tmp_path)
        cfg = _yaml(tmp_path, allow=True, network=False)
        res = _invoke(["hedef", "--workspace-dir", str(ws), "--config", cfg, "--yes"], tmp_path)
        assert res.exit_code == 0, res.output
        install = fake_exec[0]
        assert install[:2] == ["/sahte/npm", "install"]
        assert "--offline" in install
        assert "--ignore-scripts" in install

    def test_network_on_installs_with_ignore_scripts(self, fake_exec, tmp_path: Path) -> None:
        ws = _workspace(tmp_path)
        cfg = _yaml(tmp_path, allow=True, network=True)
        res = _invoke(["hedef", "--workspace-dir", str(ws), "--config", cfg, "--yes"], tmp_path)
        assert res.exit_code == 0, res.output
        install = fake_exec[0]
        assert "--offline" not in install
        assert "--ignore-scripts" in install

    def test_warning_names_the_risk_even_with_yes(self, fake_exec, tmp_path: Path) -> None:
        ws = _workspace(tmp_path)
        cfg = _yaml(tmp_path, allow=True, network=False)
        res = _invoke(["hedef", "--workspace-dir", str(ws), "--config", cfg, "--yes"], tmp_path)
        assert "analiz edilen kodun kendisidir" in _flat(res.output)

    def test_noninteractive_without_yes_runs_nothing(self, fake_exec, tmp_path: Path) -> None:
        ws = _workspace(tmp_path)
        cfg = _yaml(tmp_path, allow=True, network=False)
        res = _invoke(["hedef", "--workspace-dir", str(ws), "--config", cfg], tmp_path)
        assert res.exit_code == 2
        assert fake_exec == []
        assert "--yes" in _flat(res.output)
        assert "analiz edilen kodun kendisidir" in _flat(res.output)


class TestRunTargetResolution:
    def test_dotdot_target_rejected(self, fake_exec, tmp_path: Path) -> None:
        ws = _workspace(tmp_path)
        outside = tmp_path / "disari" / "reconstructed"
        outside.mkdir(parents=True)
        (outside / "index.js").write_text("// çalışma alanı dışı\n")
        cfg = _yaml(tmp_path, allow=True, network=False)
        res = _invoke(["../disari", "--workspace-dir", str(ws), "--config", cfg, "--yes"], tmp_path)
        assert res.exit_code == 1
        assert fake_exec == []
        assert "path traversal" in _flat(res.output)

    def test_workspace_root_itself_rejected(self, fake_exec, tmp_path: Path) -> None:
        ws = _workspace(tmp_path)
        cfg = _yaml(tmp_path, allow=True, network=False)
        res = _invoke([".", "--workspace-dir", str(ws), "--config", cfg, "--yes"], tmp_path)
        assert res.exit_code == 1
        assert fake_exec == []

    def test_missing_workspace_is_clean_error(self, fake_exec, tmp_path: Path) -> None:
        cfg = _yaml(tmp_path, allow=True, network=False)
        res = _invoke(
            ["yokhedef", "--workspace-dir", str(tmp_path / "yok"), "--config", cfg, "--yes"],
            tmp_path,
        )
        assert res.exit_code == 1
        assert isinstance(res.exception, SystemExit)
        assert "Traceback" not in res.output
        assert "Çalışma alanı" in _flat(res.output)
        assert fake_exec == []
