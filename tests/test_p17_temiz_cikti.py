"""P17 / ARAYUZ-09 (arayüz tarafı): arayüz temiz çıktıyı (etiketler, köken) yalnız AYNI ikilinin
çıktısından okur ve ad haritası ile decompile dizinini aynı çalışma alanından alır.

Eskiden temiz çıktı yalnız ``clean/report.json`` adıyla aranıyordu (üst dizinlerde köke kadar):
CLI'ın ``--output out`` koşusunda etiketler hiç okunmuyordu (HEAD Mac tmux: 395 adın 395'i
"etiketsiz" görünüyordu; temiz haritada 150 kesin + 245 doğrulanmadı), başka bir koşunun
``clean/``'ı da seçilebiliyordu. ``find_ws`` ilk rastlanan haritayı ve ilk rastlanan decompile
dizinini ayrı ayrı alıyordu.
"""
from __future__ import annotations

import importlib.util
import json
import os
import time
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_SERVER_PY = _ROOT / "ui" / "server.py"
H1, H2 = "11" * 32, "22" * 32


@pytest.fixture()
def srv():
    spec = importlib.util.spec_from_file_location("bw_ui_server_p17_temiz", _SERVER_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    yield mod
    mod.activate_workspace(None)


def _ws(run: Path, h: str, ts: str = "20261118_000000", out_name: str = "out",
        out_hash: str | None = None, adlar=None) -> Path:
    ws = run / "ws" / "workspaces" / "tmux" / ts
    (ws / "reconstructed" / "src").mkdir(parents=True)
    (ws / "reconstructed" / "src" / "naming_map.json").write_text(
        json.dumps({"global": adlar or {"FUN_1": "spawn_pane"}}))
    dec = ws / "deobfuscated" / "decompiled"
    dec.mkdir(parents=True)
    for a in ("FUN_1", "FUN_2"):
        (dec / f"{a}.c").write_text(f"void {a}(void){{}}\n")
    (ws / "reports").mkdir()
    (ws / "reports" / "report.json").write_text(json.dumps({"target": {"hash": h}}))
    out = run / out_name
    out.mkdir(exist_ok=True)
    (out / "report.json").write_text(json.dumps({"target": {"hash": out_hash or h}}))
    (out / "naming_map.json").write_text(json.dumps({"version": "1.1", "mappings": {
        "FUN_1": {"new_name": "spawn_pane", "label": "kesin", "source": "x"}}}))
    return ws


def test_cli_output_dir_is_found_by_hash(srv, tmp_path):
    ws = _ws(tmp_path / "kosu", H1)
    assert srv._clean_output_dir(str(ws)) == (tmp_path / "kosu" / "out").resolve()
    srv.activate_workspace(str(ws))
    model = srv.build_model()
    labels = {f["addr"]: f["label"] for f in model["functions"]}
    assert labels["FUN_1"] == "kesin"


def test_other_binarys_output_is_not_used(srv, tmp_path):
    ws = _ws(tmp_path / "kosu", H1, out_hash=H2)
    assert srv._clean_output_dir(str(ws)) is None
    srv.activate_workspace(str(ws))
    labels = {f["addr"]: f["label"] for f in srv.build_model()["functions"]}
    assert labels["FUN_1"] is None


def test_unknown_hash_reads_no_output(srv, tmp_path):
    ws = _ws(tmp_path / "kosu", H1)
    (ws / "reports" / "report.json").unlink()
    assert srv._clean_output_dir(str(ws)) is None


def test_ui_run_layout_clean_dir(srv, tmp_path):
    run = tmp_path / "ui" / "_runs" / "abc123"
    ws = _ws(run, H1, out_name="clean")
    assert srv._clean_output_dir(str(ws)) == (run / "clean").resolve()


def test_far_ancestor_clean_is_not_used(srv, tmp_path):
    """Çalışma alanının çok üstündeki (arama derinliği dışında) bir clean/ seçilmez."""
    far = tmp_path / "clean"
    far.mkdir()
    (far / "report.json").write_text(json.dumps({"target": {"hash": H1}}))
    (far / "naming_map.json").write_text("{}")
    deep = tmp_path / "a" / "b" / "c" / "d"
    ws = _ws(deep, H1, out_name="baska_ad")
    (deep / "baska_ad" / "report.json").unlink()      # yakındaki çıktı yok
    assert srv._clean_output_dir(str(ws)) is None


def test_find_ws_takes_map_and_decompile_from_same_run(srv, tmp_path):
    run = tmp_path / "kosu"
    # yeni koşunun adı sözlük sırasında önce gelir: "son rastlanan" ya da "ilk rastlanan"
    # dizin seçimi iki yönde de yanlış çalışma alanını verir
    old = _ws(run, H1, ts="20261118_010000", adlar={"FUN_1": "eski"})
    new = _ws(run, H1, ts="20261118_000000", adlar={"FUN_1": "yeni"})
    t = time.time()
    os.utime(old / "reconstructed/src/naming_map.json", (t - 100, t - 100))
    os.utime(new / "reconstructed/src/naming_map.json", (t, t))
    # eski koşunun decompile dizinine fazladan dosya: karışırsa görünür
    (old / "deobfuscated" / "decompiled" / "FUN_3.c").write_text("void FUN_3(void){}\n")
    nm, dec = srv.find_ws(str(run / "ws"))
    assert nm == new / "reconstructed/src/naming_map.json"
    assert dec == new / "deobfuscated" / "decompiled"
