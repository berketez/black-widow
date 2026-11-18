"""P15a / MEK-05 ve BORU-13: etkisiz ayarlar.

Eski davranış: `config.py`'deki ~50 alan hiçbir kod yolunda okunmuyordu (değiştirmek
hiçbir şeyi değiştirmiyordu) ve bunun için hiçbir uyarı yoktu; `MinConfidencePresets`'in
16 eşiğinin 12'si kodda ayrıca sabit yazılıydı; `--deep` hiç okunmayan dört
`deep_trace.enable_*` alanını açıyordu; `karadul rtti` ayar dosyasını hiç yüklemiyordu
(`rtti_abi`, `rtti_max_vtable_entries` etkisiz); capa bayrağının ayar alanı yoktu.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from click.testing import CliRunner

from karadul.cli import main as karadul_main
from karadul.config import INERT_SETTINGS, Config

ROOT = Path(__file__).resolve().parents[1]


def _yaml(tmp_path: Path, text: str, name: str = "karadul.yaml") -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def _load(tmp_path: Path, text: str) -> Config:
    return Config.load(_yaml(tmp_path, text))


def test_sub_permission_without_master_warns(tmp_path: Path) -> None:
    cfg = _load(tmp_path, "network:\n  allow_dts_fetch: true\n")
    assert any("network.allow_dts_fetch açık ama network.enabled kapalı" in w
               for w in cfg.inert_setting_warnings())


def test_validate_warns_inert_settings(tmp_path: Path) -> None:
    p = _yaml(tmp_path, "min_confidence:\n  bindiff_match: 0.123\n"
                        "timeouts:\n  frida_spawn_wait: 1.0\n")
    res = CliRunner().invoke(karadul_main, ["config", "validate", "--config", str(p)])
    assert res.exit_code == 0, res.output
    assert "min_confidence.bindiff_match etkisiz" in res.stdout
    assert "timeouts.frida_spawn_wait etkisiz" in res.stdout


def test_config_show_marks_inert_knob(tmp_path: Path) -> None:
    p = _yaml(tmp_path, "binary_reconstruction:\n  max_functions_to_process: 10\n")
    res = CliRunner().invoke(karadul_main, ["config", "show", "--config", str(p)])
    assert res.exit_code == 0, res.output
    assert "etkisiz" in res.stdout


def _code_texts() -> list[tuple[str, str]]:
    out = []
    for d in ("karadul", "ui"):
        for p in (ROOT / d).rglob("*.py"):
            if "__pycache__" in p.parts:
                continue
            rel = p.relative_to(ROOT).as_posix()
            if rel in ("karadul/config.py", "karadul/computation/config.py"):
                continue
            out.append((rel, p.read_text(encoding="utf-8", errors="replace")))
    return out


def _reads(name: str, texts: list[tuple[str, str]], skip: tuple[str, ...] = ()) -> list[str]:
    """`name` alanını OKUYAN dosyalar: `.name` (atama değil) ya da getattr/hasattr dizesi."""
    attr = re.compile(r"\.%s\b(?!\s*=[^=])" % re.escape(name))
    getattr_s = re.compile(r"(getattr|hasattr|config_flag|_get)\([^)]*[\"']%s[\"']" % re.escape(name))
    return [rel for rel, txt in texts
            if rel not in skip and (attr.search(txt) or getattr_s.search(txt))]


def _all_fields() -> list[tuple[str, str]]:
    from karadul.config import _config_sections

    import dataclasses

    out = []
    for section, cls in _config_sections().items():
        for f in dataclasses.fields(cls):
            out.append((section, f.name))
    return out


def test_inert_registry_keys_exist() -> None:
    fields = {f"{s}.{n}" for s, n in _all_fields()}
    assert set(INERT_SETTINGS) <= fields, set(INERT_SETTINGS) - fields


def test_inert_registry_is_accurate() -> None:
    """Kayıttaki hiçbir alan analiz kodunda okunmuyor (CLI / arayüz yalnız gösteriyor).

    Bir alan bağlanınca bu test kırmızı olur: kayıttan çıkarılmalı.
    """
    texts = _code_texts()
    display_only = ("karadul/cli.py", "ui/server.py")
    stale = {k: _reads(k.split(".", 1)[1], texts, skip=display_only) for k in INERT_SETTINGS}
    stale = {k: v for k, v in stale.items() if v}
    assert not stale, f"kayıtta ama okunuyor: {stale}"


def test_every_unread_field_is_registered() -> None:
    """Okuması hiç olmayan her alan kayıtta (ortak adlar — `enabled` vb. — başka
    nesnelerle karıştığı için bu bir alt sınırdır)."""
    texts = _code_texts()
    literal_anywhere = "\n".join(t for _, t in texts)
    unread = []
    for section, name in _all_fields():
        if _reads(name, texts):
            continue
        # Sabit üstünden getattr (ör. capa_annotation.CAPA_CODE_FEED_FLAG) da okumadır.
        if re.search(r"[\"']%s[\"']" % re.escape(name), literal_anywhere):
            continue
        unread.append(f"{section}.{name}")
    missing = sorted(set(unread) - set(INERT_SETTINGS))
    assert not missing, f"okunmayan ama kayıtta olmayan: {missing}"


def test_rtti_command_reads_abi_from_config(tmp_path: Path) -> None:
    binary = tmp_path / "b.bin"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
    p = _yaml(tmp_path, "binary_reconstruction:\n  rtti_abi: msvc\n")
    res = CliRunner().invoke(karadul_main, ["rtti", str(binary), "--config", str(p)])
    assert res.exit_code == 2, res.output
    assert "MSVC ABI" in res.stderr


def test_rtti_command_passes_vtable_limit(tmp_path: Path,
                                          monkeypatch: pytest.MonkeyPatch) -> None:
    import karadul.analyzers.cpp_rtti as rtti_mod

    seen: dict = {}

    class _Parser:
        def __init__(self, config=None) -> None:
            seen["limit"] = getattr(config, "rtti_max_vtable_entries", None)

        def parse_itanium(self, path):
            class _H:
                classes: list = []
            return _H()

    monkeypatch.setattr(rtti_mod, "RTTIParser", _Parser)
    binary = tmp_path / "b.bin"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
    p = _yaml(tmp_path, "binary_reconstruction:\n  rtti_max_vtable_entries: 7\n")
    res = CliRunner().invoke(karadul_main, ["rtti", str(binary), "--json", "--config", str(p)])
    assert res.exit_code == 0, res.output
    assert seen["limit"] == 7


def test_deep_flag_help_does_not_promise_deep_trace() -> None:
    res = CliRunner().invoke(karadul_main, ["analyze", "--help"], terminal_width=200)
    assert "Derin çağrı izlemeyi değiştirmez" in res.output
    assert "Etkisiz (geriye uyum)" in res.output


def test_capa_code_feed_field_reaches_reader(tmp_path: Path) -> None:
    from karadul.pipeline.steps.capa_annotation import capa_code_feed_enabled

    assert Config().binary_reconstruction.enable_capa_code_feed is False
    assert capa_code_feed_enabled(Config()) is False
    cfg = _load(tmp_path, "binary_reconstruction:\n  enable_capa_code_feed: true\n")
    assert capa_code_feed_enabled(cfg) is True


def test_analyze_warns_inert_setting_on_stderr(tmp_path: Path,
                                              monkeypatch: pytest.MonkeyPatch) -> None:
    import karadul.cli as cli_mod

    class _Stop(Exception):
        pass

    def _fake_build(cfg, **kwargs):
        raise _Stop

    monkeypatch.setattr(cli_mod, "build_pipeline", _fake_build)
    target = tmp_path / "a.js"
    target.write_text("var a=1;\n", encoding="utf-8")
    p = _yaml(tmp_path, "deep_trace:\n  max_trace_depth: 3\n")
    res = CliRunner().invoke(karadul_main, [
        "analyze", str(target), "--skip-dynamic", "--config", str(p),
        "--output-dir", str(tmp_path / "ws"),
    ])
    assert "deep_trace.max_trace_depth etkisiz" in res.stderr
