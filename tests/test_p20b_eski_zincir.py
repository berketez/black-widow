"""P20b kalem 3 — eski deobfuscation zincirinin `beautify` / `babel_transforms` adımları silindi.

Berke kararı (2026-11-19, A seçeneği): iki adım `DeobfuscationManager`'dan ve
`BabelPipeline` modülüyle birlikte silindi; `synchrony` kalır (derin hatta P20'nin
bayrağı arkasında). Önce (39aca9c), gerçek Electron Fiddle 0.39.0 `app.asar`'ında
`ElectronAnalyzer.deobfuscate()`: tamamlanan ["beautify"], başarısız
["synchrony", "babel_transforms"], aşama BAŞARILI, hata satırı 0 — ama çıktı
(`01_beautify.js`) `node --check`'ten geçmiyordu. Beautify betiği düşerse girdi
kopyalanıp adım yine "başarılı" sayılıyordu.

Sonra: zincir tanımında kalan silinmiş adım koşmaz, `steps_skipped` +
`stats["skipped_reasons"]`'ta nedeniyle görünür; Electron yolu bunu ve "hiçbir
adım tamamlanmadı"yı aşama hatalarına yazar.
"""

from __future__ import annotations

import importlib
import json
import struct
from pathlib import Path

import pytest

from karadul.analyzers.electron import ElectronAnalyzer
from karadul.config import Config
from karadul.core.target import Language, TargetInfo, TargetType
from karadul.core.workspace import Workspace
from karadul.deobfuscators import manager as manager_mod
from karadul.deobfuscators.manager import DeobfuscationManager
from karadul.deobfuscators.synchrony_wrapper import SynchronyWrapper

_OLD_CHAIN = ["beautify", "synchrony", "babel_transforms"]


def _asar(tree: dict[str, bytes]) -> bytes:
    body = bytearray()
    files = {}
    for name, data in tree.items():
        files[name] = {"size": len(data), "offset": str(len(body))}
        body.extend(data)
    js = json.dumps({"files": files}).encode()
    payload = struct.pack("<I", len(js)) + js + b"\x00" * ((-len(js)) % 4)
    pickle = struct.pack("<I", len(payload)) + payload
    return struct.pack("<II", 4, len(pickle)) + pickle + bytes(body)


def _fake_synchrony(monkeypatch, *, available: bool) -> list[Path]:
    """synchrony'yi taklit et: varsa girdiye bir satır ekleyip yazar (dış süreç yok)."""
    calls: list[Path] = []
    monkeypatch.setattr(SynchronyWrapper, "is_available", lambda self: available)

    def deob(self, inp: Path, out: Path) -> bool:
        calls.append(inp)
        out.write_text(inp.read_text(encoding="utf-8") + "\n// synchrony\n", encoding="utf-8")
        return True

    monkeypatch.setattr(SynchronyWrapper, "deobfuscate", deob)
    return calls


def _no_node(monkeypatch) -> list:
    """Silinen adımlar node betiği çağırırdı (beautify.mjs / deobfuscate.mjs)."""
    calls: list = []

    def boom(self, *a, **k):
        calls.append(a)
        raise AssertionError(f"silinmiş adım node çağırdı: {a!r}")

    monkeypatch.setattr(manager_mod.SubprocessRunner, "run_node_script", boom)
    return calls


@pytest.fixture
def ws(tmp_path: Path) -> Workspace:
    w = Workspace(tmp_path / "ws", "p20b")
    w.create()
    return w


@pytest.fixture
def js_file(tmp_path: Path) -> Path:
    p = tmp_path / "main.js"
    p.write_text("var a=1;function f(b){return a+b}console.log(f(2));\n", encoding="utf-8")
    return p


def test_removed_steps_are_gone_from_manager_and_package():
    assert "beautify" not in manager_mod._KNOWN_STEPS
    assert "babel_transforms" not in manager_mod._KNOWN_STEPS
    assert not hasattr(DeobfuscationManager, "_step_beautify")
    assert not hasattr(DeobfuscationManager, "_step_babel_transforms")
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("karadul.deobfuscators.babel_pipeline")


def test_old_chain_runs_remaining_step_and_reports_removed_ones(monkeypatch, ws, js_file):
    calls = _fake_synchrony(monkeypatch, available=True)
    node_calls = _no_node(monkeypatch)
    res = DeobfuscationManager(Config()).run_chain(js_file, ws, chain=list(_OLD_CHAIN))
    assert node_calls == []
    assert res.steps_completed == ["synchrony"]
    assert res.steps_failed == []
    assert res.steps_skipped == ["beautify", "babel_transforms"]
    reasons = res.stats["skipped_reasons"]
    assert set(reasons) == {"beautify", "babel_transforms"}
    assert all("kaldırıldı" in r for r in reasons.values())
    # synchrony özgün girdiyi aldı (araya güzelleştirme girmedi), çıktı onun.
    assert calls and calls[0].name == "00_original.js"
    assert res.success is True and res.output_file.name == "01_synchrony.js"
    deob = ws.get_stage_dir("deobfuscated")
    assert sorted(p.name for p in deob.iterdir()) == ["00_original.js", "01_synchrony.js"]


def test_only_removed_steps_is_not_success(monkeypatch, ws, js_file):
    _no_node(monkeypatch)
    res = DeobfuscationManager(Config()).run_chain(js_file, ws, chain=["beautify"])
    assert res.success is False
    assert res.output_file is None
    assert res.steps_completed == []
    assert res.steps_skipped == ["beautify"]


def _electron(tmp_path: Path, ws: Workspace):
    js = b"function main(){ return 42; }\n" * 50
    asar = tmp_path / "app.asar"
    asar.write_bytes(_asar({"package.json": b'{"main": "main.js"}', "main.js": js}))
    ti = TargetInfo(path=asar, name="app", target_type=TargetType.ELECTRON_APP,
                    language=Language.JAVASCRIPT, file_size=asar.stat().st_size, file_hash="x")
    an = ElectronAnalyzer(Config())
    assert an.analyze_static(ti, ws).success is True
    return an, ti


def test_electron_path_runs_remaining_chain(monkeypatch, tmp_path, ws):
    an, ti = _electron(tmp_path, ws)
    _fake_synchrony(monkeypatch, available=True)
    _no_node(monkeypatch)
    # Config'in öntanımlı zinciri (yama uygulanana dek eski üç adım).
    monkeypatch.setattr(an.config.analysis, "deobfuscation_chain", list(_OLD_CHAIN))
    res = an.deobfuscate(ti, ws)
    assert res.success is True
    assert res.stats["deob_steps_completed"] == ["synchrony"]
    assert res.stats["deob_steps_skipped"] == ["beautify", "babel_transforms"]
    assert res.artifacts["deobfuscated_main"].name == "01_synchrony.js"
    assert len(res.errors) == 2
    assert all(e.startswith("Deobfuscation adimi kosmadi: ") and "kaldırıldı" in e for e in res.errors)


def test_electron_path_without_synchrony_is_honest_failure(monkeypatch, tmp_path, ws):
    an, ti = _electron(tmp_path, ws)
    _fake_synchrony(monkeypatch, available=False)
    _no_node(monkeypatch)
    monkeypatch.setattr(an.config.analysis, "deobfuscation_chain", list(_OLD_CHAIN))
    res = an.deobfuscate(ti, ws)
    # Eskiden beautify "tamamlandı" sayılıp aşama başarılıydı.
    assert res.success is False
    assert "deobfuscated_main" not in res.artifacts
    assert res.stats["deob_steps_completed"] == []
    assert res.stats["deob_steps_failed"] == ["synchrony"]
    assert any(e.startswith("Deobfuscation basarisiz: hicbir adim tamamlanmadi") for e in res.errors)
