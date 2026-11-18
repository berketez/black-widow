"""P17 / ARAYUZ-14: arayüzden ad düzeltme kalıcıdır ya da hiç yapılmaz; doğru ikiliye bağlanır;
anahtar sözcük, tip adı ve çakışan ad reddedilir.

Eskiden: (1) ikili özeti bulunamazsa ya da kalıcı kayıt patlarsa naming_map güncellenip
{"ok": true} dönüyordu (ad sonraki analizde kayboluyordu); (2) özet çalışma alanının ikilisinden
değil ADA göre aranıyordu (`ls` → `/bin/ls`): HEAD koşusunun 14 çalışma alanının 14'ünde başka
bir ikilinin özetine yazılıyordu; (3) `int`, `return` ya da başka fonksiyonun adı kabul ediliyordu.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from karadul.core import overrides

_ROOT = Path(__file__).resolve().parent.parent
_SERVER_PY = _ROOT / "ui" / "server.py"
_HASH = "0d5a5dd543ed8d31220320eb513e4680ab303e48cb22a5edbf27a5a91561a71e"
A1, A2 = "FUN_00101000", "FUN_00102000"


@pytest.fixture()
def srv(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("bw_ui_server_p17_ad", _SERVER_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    ov = tmp_path / "overrides"
    ov.mkdir()
    monkeypatch.setattr(overrides, "overrides_dir", lambda: ov)

    def _no_name_lookup(*a, **k):
        raise AssertionError("ikili ADA göre aranmamalı")

    monkeypatch.setattr(mod, "resolve_binary", _no_name_lookup)
    mod._ov_dir = ov
    yield mod
    mod.activate_workspace(None)


def _ws(root: Path, *, report=True, target_info=False, raw_bytes=None, names=None) -> Path:
    ws = root / "ws" / "workspaces" / "ls" / "20261118_000000"
    src = ws / "reconstructed" / "src"
    src.mkdir(parents=True)
    (src / "naming_map.json").write_text(json.dumps({"global": names or {A2: "parse_args"}}))
    dec = ws / "deobfuscated" / "decompiled"
    dec.mkdir(parents=True)
    for a in (A1, A2):
        (dec / f"{a}.c").write_text(f"// Function: {a}\n// Address:  {a[4:]}\nvoid {a}(void){{}}\n")
    (ws / "static").mkdir()
    (ws / "static" / "ghidra_functions.json").write_text(json.dumps({"functions": [
        {"name": A1, "address": A1[4:]}, {"name": A2, "address": A2[4:]},
        {"name": "memcpy", "address": "00101b30", "is_thunk": True},
    ]}))
    if report:
        (ws / "reports").mkdir()
        (ws / "reports" / "report.json").write_text(json.dumps({"target": {"hash": _HASH}}))
    raw = ws / "raw"
    raw.mkdir()
    if target_info:
        (raw / "target_info.json").write_text(json.dumps({"file_hash": _HASH}))
    if raw_bytes is not None:
        (raw / "ls").write_bytes(raw_bytes)
    return ws


def _map(ws: Path) -> dict:
    return json.loads((ws / "reconstructed/src/naming_map.json").read_text())["global"]


# -- (2) özet çalışma alanının kendi kaydından -------------------------------------------------

def test_hash_from_workspace_report(srv, tmp_path):
    ws = _ws(tmp_path)
    assert srv._active_binary_hash(str(ws)) == _HASH


def test_hash_from_target_info(srv, tmp_path):
    ws = _ws(tmp_path, report=False, target_info=True)
    assert srv._active_binary_hash(str(ws)) == _HASH


def test_hash_from_raw_copy(srv, tmp_path):
    body = b"\x7fELF fake"
    ws = _ws(tmp_path, report=False, raw_bytes=body)
    assert srv._active_binary_hash(str(ws)) == hashlib.sha256(body).hexdigest()


def test_no_hash_no_rename(srv, tmp_path):
    ws = _ws(tmp_path, report=False)
    srv.activate_workspace(str(ws))
    before = _map(ws)
    r = srv._do_rename(A1, "read_config")
    assert r["__code"] == 409 and "kalıcı" in r["error"]
    assert _map(ws) == before
    assert list(srv._ov_dir.iterdir()) == []


# -- (1) kalıcı kayıt yazılamazsa ad verilmez ----------------------------------------------------

def test_override_write_failure_changes_nothing(srv, tmp_path, monkeypatch):
    ws = _ws(tmp_path)
    srv.activate_workspace(str(ws))
    before = _map(ws)

    def _boom(*a, **k):
        raise OSError("salt okunur")

    monkeypatch.setattr(overrides, "set_name", _boom)
    r = srv._do_rename(A1, "read_config")
    assert r["__code"] == 500 and "kalıcı kayda yazılamadı" in r["error"]
    assert _map(ws) == before


def test_success_persists_under_workspace_hash(srv, tmp_path):
    ws = _ws(tmp_path)
    srv.activate_workspace(str(ws))
    r = srv._do_rename(A1, "read_config")
    assert r.get("ok") is True and r["persisted"] is True and r["binary_hash"] == _HASH
    assert _map(ws)[A1] == "read_config"
    assert overrides.all_names(_HASH) == {A1: "read_config"}


# -- (3) anahtar sözcük, tip adı, çakışma ---------------------------------------------------------

@pytest.mark.parametrize("bad,kod", [("int", 400), ("return", 400), ("uint8_t", 400),
                                     ("undefined4", 400), ("parse_args", 409), ("memcpy", 409)])
def test_rejected_names(srv, tmp_path, bad, kod):
    ws = _ws(tmp_path)
    srv.activate_workspace(str(ws))
    before = _map(ws)
    r = srv._do_rename(A1, bad)
    assert r.get("__code") == kod, r
    assert _map(ws) == before
    assert overrides.all_names(_HASH) == {}


def test_own_name_is_not_a_collision(srv, tmp_path):
    ws = _ws(tmp_path)
    srv.activate_workspace(str(ws))
    r = srv._do_rename(A2, "parse_args")
    assert r.get("ok") is True


def test_overrides_module_rejects_keywords_and_types():
    for bad in ("int", "return", "uint32_t", "undefined8"):
        with pytest.raises(ValueError):
            overrides._validate_name(bad)
    assert overrides._validate_name("read_config") == "read_config"
    # parametre adı: dosya düzeyi typedef (addr) olabilir, gövde tip sözcüğü olamaz
    assert overrides._validate_name("addr", local=True) == "addr"
    with pytest.raises(ValueError):
        overrides._validate_name("addr")
    with pytest.raises(ValueError):
        overrides._validate_name("int", local=True)


def test_set_param_allows_addr_param(tmp_path, monkeypatch):
    monkeypatch.setattr(overrides, "overrides_dir", lambda: tmp_path)
    assert overrides.set_param("ab" * 4, A1, "param_1", "addr") == {"param_1": "addr"}
    with pytest.raises(ValueError):
        overrides.set_param("ab" * 4, A1, "param_1", "while")
