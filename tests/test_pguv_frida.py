"""P-GÜV / GHIDRA-11: dinamik analizde hedef sürecin yaşam döngüsü.

Eski davranış: ``FridaSession.spawn`` süreci kanca yüklenmeden sürdürüyordu
(``resume`` -> ``create_script``) ve analiz bitince süreç hiç öldürülmüyordu;
attach başarısız olursa askıdaki süreç yetim kalıyordu.

Bu testler GERÇEK süreç başlatmaz: ``karadul.frida.session.frida`` sahte bir
modülle değiştirilir (aygıt yalnız çağrıları kaydeder), aşama testinde de
``FridaSession`` sahte bir oturumla değiştirilir.
"""

from __future__ import annotations

import types
from pathlib import Path

import pytest

from karadul.config import Config
from karadul.core.pipeline import PipelineContext
from karadul.core.target import Language, TargetInfo, TargetType
from karadul.core.workspace import Workspace


# ---------------------------------------------------------------------------
# Sahte Frida modülü (session düzeyi)
# ---------------------------------------------------------------------------

class _ProcessNotFound(Exception):
    pass


class _ExecNotFound(Exception):
    pass


def _fake_frida_module() -> types.SimpleNamespace:
    return types.SimpleNamespace(
        get_local_device=lambda: pytest.fail("gerçek aygıt istenmemeli"),
        ExecutableNotFoundError=_ExecNotFound,
        ProcessNotFoundError=_ProcessNotFound,
        PermissionDeniedError=type("PermissionDenied", (Exception,), {}),
        TransportError=type("TransportError", (Exception,), {}),
    )


class _FakeScript:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def on(self, *_a, **_k) -> None:
        pass

    def load(self) -> None:
        self.calls.append("script.load")

    def unload(self) -> None:
        self.calls.append("script.unload")


class _FakeFridaSession:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls
        self.handlers: dict = {}

    def on(self, event, handler) -> None:
        self.handlers[event] = handler

    def create_script(self, _source: str) -> _FakeScript:
        self.calls.append("create_script")
        return _FakeScript(self.calls)

    def detach(self) -> None:
        self.calls.append("session.detach")


class _FakeDevice:
    def __init__(self, *, attach_fails: bool = False, kill_exc: Exception | None = None) -> None:
        self.calls: list[str] = []
        self.attach_fails = attach_fails
        self.kill_exc = kill_exc
        self.sessions: list[_FakeFridaSession] = []

    def spawn(self, argv, **_kw) -> int:
        self.calls.append("spawn")
        return 4242

    def attach(self, pid):
        self.calls.append("attach")
        if self.attach_fails:
            raise RuntimeError("sahte attach hatası")
        s = _FakeFridaSession(self.calls)
        self.sessions.append(s)
        return s

    def resume(self, pid) -> None:
        self.calls.append("resume")

    def kill(self, pid) -> None:
        self.calls.append("kill")
        if self.kill_exc is not None:
            raise self.kill_exc


@pytest.fixture
def fake_frida(monkeypatch: pytest.MonkeyPatch):
    import karadul.frida.session as fs

    monkeypatch.setattr(fs, "frida", _fake_frida_module())
    monkeypatch.setattr(fs, "FRIDA_AVAILABLE", True)
    return fs


def _session(fs, device: _FakeDevice):
    cfg = Config()
    s = fs.FridaSession(cfg)
    s._device = device
    return s


class TestSessionLifecycle:
    def test_spawn_does_not_resume(self, fake_frida) -> None:
        dev = _FakeDevice()
        s = _session(fake_frida, dev)
        pid = s.spawn("/hedef/ikili")
        assert pid == 4242
        assert dev.calls == ["spawn", "attach"]
        assert "resume" not in dev.calls

    def test_resume_after_hooks_then_kill_before_detach(self, fake_frida) -> None:
        dev = _FakeDevice()
        s = _session(fake_frida, dev)
        s.spawn("/hedef/ikili")
        s.load_script_source("send(1);")
        s.resume()
        s.detach()
        c = dev.calls
        assert c.index("script.load") < c.index("resume")
        assert c.count("kill") == 1
        assert c.index("kill") < c.index("session.detach")
        assert s.spawned_pid is None

    def test_explicit_kill_is_idempotent_with_detach(self, fake_frida) -> None:
        dev = _FakeDevice()
        s = _session(fake_frida, dev)
        s.spawn("/hedef/ikili")
        s.load_script_source("send(1);")
        s.resume()
        assert s.kill() is True
        s.detach()
        assert dev.calls.count("kill") == 1

    def test_attach_failure_kills_suspended_process(self, fake_frida) -> None:
        dev = _FakeDevice(attach_fails=True)
        s = _session(fake_frida, dev)
        with pytest.raises(fake_frida.FridaAttachError):
            s.spawn("/hedef/ikili")
        assert dev.calls == ["spawn", "attach", "kill"]
        assert s.spawned_pid is None

    def test_already_exited_process_counts_as_terminated(self, fake_frida) -> None:
        dev = _FakeDevice(kill_exc=_ProcessNotFound("bitti"))
        s = _session(fake_frida, dev)
        s.spawn("/hedef/ikili")
        s.resume()
        assert s.kill() is True
        assert s.spawned_pid is None

    def test_kill_failure_is_not_swallowed(self, fake_frida) -> None:
        dev = _FakeDevice(kill_exc=PermissionError("izin yok"))
        s = _session(fake_frida, dev)
        s.spawn("/hedef/ikili")
        s.resume()
        with pytest.raises(RuntimeError, match="öldürülemedi"):
            s.detach()
        # Oturum yine de kapatıldı
        assert "session.detach" in dev.calls
        assert not s.is_attached

    def test_attach_to_foreign_pid_is_never_killed(self, fake_frida) -> None:
        dev = _FakeDevice()
        s = _session(fake_frida, dev)
        s.attach(999)
        s.detach()
        assert "kill" not in dev.calls

    def test_wait_returns_early_on_process_exit(self, fake_frida) -> None:
        dev = _FakeDevice()
        s = _session(fake_frida, dev)
        s.spawn("/hedef/ikili")
        s.resume()
        # Frida "detached" olayı: süreç kendiliğinden bitti
        dev.sessions[0].handlers["detached"]("process-terminated", None)
        elapsed = s.wait(timeout=3.0)
        assert elapsed < 1.5
        assert s.detach_reason == "process-terminated"
        s.detach()


# ---------------------------------------------------------------------------
# Aşama düzeyi: DynamicAnalysisStage çağrı sırası (sahte oturum)
# ---------------------------------------------------------------------------

class _RecordingSession:
    """FridaSession yerine geçer; yalnız çağrı sırasını kaydeder."""

    instances: list["_RecordingSession"] = []

    def __init__(self, config) -> None:
        self.calls: list[tuple] = []
        self.detach_reason = None
        self._spawned = False
        _RecordingSession.instances.append(self)

    def spawn(self, program, args=None, env=None) -> int:
        self.calls.append(("spawn", program, tuple(args or ())))
        self._spawned = True
        return 4242

    def load_script(self, path) -> None:
        self.calls.append(("load_script", Path(path).name))

    def resume(self) -> None:
        self.calls.append(("resume",))

    def wait(self, timeout=None) -> float:
        self.calls.append(("wait", timeout))
        return 0.25

    def kill(self) -> bool:
        self.calls.append(("kill",))
        self._spawned = False
        return True

    def detach(self) -> None:
        self.calls.append(("detach",))

    @property
    def messages(self) -> list:
        return []

    @property
    def errors(self) -> list:
        return []

    def names(self) -> list[str]:
        return [c[0] for c in self.calls]


def _ctx(tmp_path: Path, target_type: TargetType, *, allow=True) -> PipelineContext:
    cfg = Config()
    cfg.project_root = tmp_path
    cfg.security.allow_target_execution = allow
    cfg.timeouts.frida_attach = 7
    target_file = tmp_path / "hedef.bin"
    target_file.write_bytes(b"\x7fELF" + b"\0" * 60)
    tinfo = TargetInfo(
        path=target_file, name="hedef", target_type=target_type,
        language=Language.C, file_size=64, file_hash="0" * 64,
    )
    ws = Workspace(base_dir=tmp_path / "ws", target_name="hedef")
    ws.create()
    return PipelineContext(target=tinfo, workspace=ws, config=cfg)


@pytest.fixture
def recording_session(monkeypatch: pytest.MonkeyPatch):
    import karadul.frida.session as fs

    _RecordingSession.instances = []
    monkeypatch.setattr(fs, "FridaSession", _RecordingSession)
    return _RecordingSession


class TestDynamicStageOrder:
    def test_hooks_loaded_before_resume_and_target_killed(
        self, recording_session, tmp_path: Path,
    ) -> None:
        from karadul.stages import DynamicAnalysisStage

        sr = DynamicAnalysisStage().execute(_ctx(tmp_path, TargetType.ELF_BINARY))
        assert len(recording_session.instances) == 1
        names = recording_session.instances[0].names()
        assert names[0] == "spawn"
        assert "resume" in names, "hedef hiç sürdürülmedi (ya da spawn içinde sürdürüldü)"
        assert names.index("load_script") < names.index("resume")
        assert names.index("resume") < names.index("wait")
        assert "kill" in names, "toplama bitince hedef süreç öldürülmedi"
        assert names.index("wait") < names.index("kill")
        assert sr.success is True, sr.errors
        assert sr.stats["target_terminated"] is True

    def test_collect_duration_is_real_elapsed(
        self, recording_session, tmp_path: Path,
    ) -> None:
        from karadul.stages import DynamicAnalysisStage

        sr = DynamicAnalysisStage().execute(_ctx(tmp_path, TargetType.ELF_BINARY))
        assert sr.stats["collect_duration"] == 0.25
        assert sr.stats["collect_timeout"] == 7.0

    def test_exception_after_spawn_still_cleans_up(
        self, recording_session, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    ) -> None:
        from karadul.stages import DynamicAnalysisStage

        def _boom(self, timeout=None):
            self.calls.append(("wait", timeout))
            raise ValueError("toplama sırasında hata")

        monkeypatch.setattr(_RecordingSession, "wait", _boom)
        sr = DynamicAnalysisStage().execute(_ctx(tmp_path, TargetType.ELF_BINARY))
        names = recording_session.instances[0].names()
        assert names[-1] == "detach"
        assert sr.success is False
        assert any("toplama sırasında hata" in e for e in sr.errors)

    def test_hook_load_failure_never_resumes(
        self, recording_session, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    ) -> None:
        from karadul.stages import DynamicAnalysisStage

        def _fail(self, path):
            self.calls.append(("load_script", Path(path).name))
            raise RuntimeError("kanca yüklenemedi")

        monkeypatch.setattr(_RecordingSession, "load_script", _fail)
        sr = DynamicAnalysisStage().execute(_ctx(tmp_path, TargetType.ELF_BINARY))
        names = recording_session.instances[0].names()
        assert "resume" not in names
        assert names[-1] == "detach"
        assert sr.success is False
