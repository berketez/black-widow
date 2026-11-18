"""P-GÜV / GHIDRA-07: hedef çalıştırma kapısı ve YAML'da katı bool dönüşümü.

Eski davranış: ``security.allow_target_execution: "false"`` (tırnaklı dizgi)
Python doğruluğuyla değerlendirildiği için kapıyı AÇIYORDU; YAML'dan açılan
kapı için hiçbir uyarı basılmıyordu; bilinmeyen tipteki hedef de doğrudan
spawn ediliyordu.

Bu testler hedef çalıştırmaz: aşama testinde ``FridaSession`` kayıt tutan
sahte bir sınıfla değiştirilir, CLI testinde ``build_pipeline`` yakalanıp koşu
durdurulur.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from karadul.cli import main as karadul_main
from karadul.config import Config, ConfigValueError
from karadul.core.pipeline import PipelineContext
from karadul.core.target import Language, TargetInfo, TargetType
from karadul.core.workspace import Workspace


def _load_yaml(tmp_path: Path, text: str) -> Config:
    p = tmp_path / "karadul.yaml"
    p.write_text(text, encoding="utf-8")
    return Config.load(p)


# ---------------------------------------------------------------------------
# Config: katı bool dönüşümü
# ---------------------------------------------------------------------------

class TestStrictBool:
    @pytest.mark.parametrize("raw", ['"false"', '"no"', '"0"', '"off"', '"False"', "' NO '", "0", "false", "no"])
    def test_false_spellings_close_the_gate(self, tmp_path: Path, raw: str) -> None:
        cfg = _load_yaml(tmp_path, f"security:\n  allow_target_execution: {raw}\n")
        assert cfg.security.allow_target_execution is False

    @pytest.mark.parametrize("raw", ['"true"', '"yes"', '"1"', '"on"', "1", "true", "TRUE"])
    def test_true_spellings_open_the_gate(self, tmp_path: Path, raw: str) -> None:
        cfg = _load_yaml(tmp_path, f"security:\n  allow_target_execution: {raw}\n")
        assert cfg.security.allow_target_execution is True

    @pytest.mark.parametrize("raw", ['"kapalı"', '"evet"', "2", "1.0", '""', "[]"])
    def test_unknown_values_are_rejected_loudly(self, tmp_path: Path, raw: str) -> None:
        with pytest.raises(ConfigValueError, match="security.allow_target_execution"):
            _load_yaml(tmp_path, f"security:\n  allow_target_execution: {raw}\n")

    def test_empty_value_is_rejected(self, tmp_path: Path) -> None:
        # `anahtar:` (değersiz) YAML'da None olur; bool alana sessizce yazılmaz.
        with pytest.raises(ConfigValueError):
            _load_yaml(tmp_path, "security:\n  allow_target_execution:\n")

    def test_same_path_for_every_section(self, tmp_path: Path) -> None:
        cfg = _load_yaml(
            tmp_path,
            "bsim:\n  enabled: \"false\"\n"
            "network:\n  enabled: \"no\"\n  allow_dts_fetch: \"off\"\n"
            "binary_reconstruction:\n  enable_address_placement: \"yes\"\n"
            "computation_recovery:\n  enabled: \"0\"\n",
        )
        assert cfg.bsim.enabled is False
        assert cfg.network.enabled is False
        assert cfg.network.allow_dts_fetch is False
        assert cfg.binary_reconstruction.enable_address_placement is True
        assert cfg.computation_recovery.enabled is False

    def test_non_bool_fields_untouched(self, tmp_path: Path) -> None:
        cfg = _load_yaml(tmp_path, "timeouts:\n  frida_attach: 12\nbsim:\n  enabled: true\n")
        assert cfg.timeouts.frida_attach == 12
        assert cfg.bsim.enabled is True


# ---------------------------------------------------------------------------
# Aşama kapısı: yalnız gerçek True açar; bilinmeyen tip asla spawn edilmez
# ---------------------------------------------------------------------------

class _RecordingSession:
    instances: list = []

    def __init__(self, config) -> None:
        self.calls: list[str] = []
        _RecordingSession.instances.append(self)

    def spawn(self, program, args=None, env=None) -> int:
        self.calls.append("spawn")
        return 1

    def load_script(self, path) -> None:
        self.calls.append("load_script")

    def resume(self) -> None:
        self.calls.append("resume")

    def wait(self, timeout=None) -> float:
        return 0.0

    def kill(self) -> bool:
        self.calls.append("kill")
        return True

    def detach(self) -> None:
        self.calls.append("detach")

    detach_reason = None
    messages: list = []
    errors: list = []


@pytest.fixture
def recording_session(monkeypatch: pytest.MonkeyPatch):
    import karadul.frida.session as fs

    _RecordingSession.instances = []
    monkeypatch.setattr(fs, "FridaSession", _RecordingSession)
    return _RecordingSession


def _ctx(tmp_path: Path, target_type: TargetType, allow) -> PipelineContext:
    cfg = Config()
    cfg.project_root = tmp_path
    cfg.security.allow_target_execution = allow
    f = tmp_path / "hedef.bin"
    f.write_bytes(b"\0" * 64)
    tinfo = TargetInfo(
        path=f, name="hedef", target_type=target_type, language=Language.C,
        file_size=64, file_hash="0" * 64,
    )
    ws = Workspace(base_dir=tmp_path / "ws", target_name="hedef")
    ws.create()
    return PipelineContext(target=tinfo, workspace=ws, config=cfg)


class TestStageGate:
    @pytest.mark.parametrize("allow", ["false", "no", "0", 1, "true"])
    def test_only_real_true_opens_gate(self, recording_session, tmp_path: Path, allow) -> None:
        from karadul.stages import DynamicAnalysisStage

        sr = DynamicAnalysisStage().execute(_ctx(tmp_path, TargetType.ELF_BINARY, allow))
        assert recording_session.instances == []
        assert sr.skipped is True
        assert "--dynamic" in sr.stats["skip_reason"]

    def test_real_true_reaches_session(self, recording_session, tmp_path: Path) -> None:
        from karadul.stages import DynamicAnalysisStage

        DynamicAnalysisStage().execute(_ctx(tmp_path, TargetType.ELF_BINARY, True))
        assert len(recording_session.instances) == 1

    def test_unknown_type_is_never_spawned(self, recording_session, tmp_path: Path) -> None:
        from karadul.stages import DynamicAnalysisStage

        sr = DynamicAnalysisStage().execute(_ctx(tmp_path, TargetType.UNKNOWN, True))
        assert recording_session.instances == []
        assert sr.skipped is True
        assert "bilinmeyen tip" in sr.stats["skip_reason"]

    def test_known_native_types_keep_spawn_path(self, recording_session, tmp_path: Path) -> None:
        # Kapsam küçültülmez: tanınan yerel tip (ör. PyInstaller paketi) eskisi gibi
        # izinle çalıştırılabilir; yalnız UNKNOWN kapandı.
        from karadul.stages import DynamicAnalysisStage

        sr = DynamicAnalysisStage().execute(_ctx(tmp_path, TargetType.PYTHON_PACKED, True))
        assert len(recording_session.instances) == 1
        assert sr.stats["spawn_method"] == "generic_spawn"


# ---------------------------------------------------------------------------
# CLI: kapı hangi kaynaktan açılırsa açılsın uyarı; YAML'dan açıksa onay
# ---------------------------------------------------------------------------

def _invoke_analyze(monkeypatch, tmp_path: Path, extra: list[str], *, interactive=False,
                    input_text: str | None = None):
    import karadul.cli as cli_mod

    captured: dict = {}

    class _Stop(Exception):
        pass

    def _fake_build_pipeline(cfg, **kwargs):
        captured["cfg"] = cfg
        raise _Stop()

    monkeypatch.setattr(cli_mod, "build_pipeline", _fake_build_pipeline)
    monkeypatch.setattr(cli_mod, "_is_noninteractive", lambda: not interactive)
    exe = tmp_path / "tiny_macho"
    exe.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 64)
    runner = CliRunner()
    result = runner.invoke(
        karadul_main,
        ["analyze", str(exe), "--output-dir", str(tmp_path / "ws"),
         "--compute", "off", *extra],
        input=input_text,
    )
    assert "cfg" in captured, f"build_pipeline'a ulaşılmadı: {result.output}"
    return captured["cfg"], result


def _yaml_open(tmp_path: Path) -> str:
    p = tmp_path / "acik.yaml"
    p.write_text("security:\n  allow_target_execution: true\n", encoding="utf-8")
    return str(p)


class TestCliGateWarning:
    def test_dynamic_flag_warns_even_in_json_mode(self, monkeypatch, tmp_path: Path) -> None:
        cfg, res = _invoke_analyze(monkeypatch, tmp_path, ["--dynamic", "--json"])
        assert cfg.security.allow_target_execution is True
        assert "ÇALIŞTIRILACAK" in res.stderr
        assert "--dynamic" in res.stderr

    def test_yaml_open_noninteractive_does_not_run(self, monkeypatch, tmp_path: Path) -> None:
        cfg, res = _invoke_analyze(
            monkeypatch, tmp_path, ["--config", _yaml_open(tmp_path)], interactive=False,
        )
        assert cfg.security.allow_target_execution is False
        assert "ÇALIŞTIRILMAYACAK" in res.stderr

    def test_yaml_open_interactive_refused(self, monkeypatch, tmp_path: Path) -> None:
        cfg, res = _invoke_analyze(
            monkeypatch, tmp_path, ["--config", _yaml_open(tmp_path)],
            interactive=True, input_text="n\n",
        )
        assert cfg.security.allow_target_execution is False

    def test_yaml_open_interactive_confirmed_warns(self, monkeypatch, tmp_path: Path) -> None:
        cfg, res = _invoke_analyze(
            monkeypatch, tmp_path, ["--config", _yaml_open(tmp_path)],
            interactive=True, input_text="y\n",
        )
        assert cfg.security.allow_target_execution is True
        assert "ÇALIŞTIRILACAK" in res.stderr
        assert "ayar dosyası" in res.stderr

    def test_yaml_open_but_dynamic_skipped_no_prompt(self, monkeypatch, tmp_path: Path) -> None:
        # --skip-dynamic: dinamik aşama yok, hedef zaten çalışmaz; soru da sorulmaz.
        cfg, res = _invoke_analyze(
            monkeypatch, tmp_path, ["--config", _yaml_open(tmp_path), "--skip-dynamic"],
            interactive=True, input_text="",
        )
        assert "çalıştırılsın mı" not in res.output
        assert "ÇALIŞTIRILACAK" not in res.stderr
