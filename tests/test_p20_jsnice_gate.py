"""P20 kalem 5 — JS ad yardımcıları: JSNiceRenamer ağ izni olmadan süreç başlatmaz.

Bulgu (kaynak okunarak): kurulu ``jsnice`` komutu (npm jsnice 0.2.0) yerel
değil; girdinin tamamını ``http://www.jsnice.org/beautify``'a düz HTTP ile POST
ediyor. Modülün eski açıklaması "lokal çalışır" diyordu; sınıf ``jsnice``
PATH'te varsa doğrudan çağırıyordu ve "yeniden adlandırılan değişken" sayısını
anahtar sözcükleri de sayan bir sözcük farkıyla uyduruyordu.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import karadul.reconstruction.jsnice_renamer as jr


@pytest.fixture
def fake_jsnice(monkeypatch, tmp_path: Path):
    """PATH'te jsnice varmış gibi yap; subprocess.run çağrılarını kaydet."""
    calls: list[list[str]] = []

    def _run(cmd, *a, **k):
        calls.append([str(c) for c in cmd])
        return subprocess.CompletedProcess(
            cmd, 0, stdout="function main(request) { return request; }\n", stderr="",
        )

    monkeypatch.setattr(jr.shutil, "which", lambda _n: "/usr/local/bin/jsnice")
    monkeypatch.setattr(jr.subprocess, "run", _run)
    src = tmp_path / "in.js"
    src.write_text("function a(b){return b}\n", encoding="utf-8")
    return calls, src


def test_default_refuses_without_network_permission(fake_jsnice, tmp_path):
    calls, src = fake_jsnice
    renamer = jr.JSNiceRenamer()
    assert renamer.is_available is False
    res = renamer.rename(src, tmp_path / "out.js")
    assert res.success is False
    assert "www.jsnice.org" in res.errors[0]
    assert renamer.rename_chunk("var a = 1;") is None
    assert calls == []  # hiçbir süreç başlatılmadı (kod dışarı gitmedi)


def test_explicit_permission_runs_and_does_not_invent_rename_count(fake_jsnice, tmp_path):
    calls, src = fake_jsnice
    renamer = jr.JSNiceRenamer(allow_network=True)
    assert renamer.is_available is True
    res = renamer.rename(src, tmp_path / "out.js")
    assert res.success is True and len(calls) == 1
    # Eski sezgi "function", "return", "main", "request" → 4 "değişken" derdi.
    assert res.variables_renamed is None
