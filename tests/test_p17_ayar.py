"""P17 / ARAYUZ-04, 05, 06: ayar paneli dosyayı birleştirerek yazar, etkisiz düğme yok, ağ düğmesi
gerçek etkisini söyler.

- ARAYUZ-06: "Kaydet" karadul.yaml'ı baştan yazıyordu; paneldeki 7 anahtar dışındaki her şey
  (Ghidra yolu, deney bayrakları, network.allow_reference_download ...) siliniyordu.
- ARAYUZ-04: "Maks. fonksiyon" (binary_reconstruction.max_functions_to_process) hiçbir yerde
  okunmuyor (config.INERT_SETTINGS); panel dosyaya yazdığı için her analizde "etkisiz" uyarısı.
- ARAYUZ-05: ağ düğmesinin açtığı izinler yükleyicinin kuracağı yapılandırmadan gösterilir.
"""
from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from karadul.config import Config

_ROOT = Path(__file__).resolve().parent.parent
_SERVER_PY = _ROOT / "ui" / "server.py"
_INDEX = _ROOT / "ui" / "index.html"

_PANEL = {
    "min_naming_confidence": 0.8, "unk_threshold": 0.25, "pipeline_iterations": 2,
    "computation_recovery_enabled": True, "network_enabled": True,
    "signature_paths": ["/a/b.json", "/c/d.gdt"],
}


@pytest.fixture()
def srv(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("bw_ui_server_p17_ayar", _SERVER_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "_SETTINGS_YAML", tmp_path / "karadul.yaml")
    return mod


def _write(srv, text: str) -> Path:
    srv._SETTINGS_YAML.write_text(text, encoding="utf-8")
    return srv._SETTINGS_YAML


_USER_YAML = (
    "tools:\n  ghidra_headless: /opt/ghidra/support/analyzeHeadless\n"
    "binary_reconstruction:\n  enable_address_placement: true\n  min_naming_confidence: 0.5\n"
    "  max_functions_to_process: 0\n"
    "network:\n  enabled: false\n  allow_reference_download: true\n"
    "timeouts:\n  ghidra: 1200\n"
)


def test_save_keeps_the_rest_of_the_file(srv):
    target = _write(srv, _USER_YAML)
    out = srv._write_settings(dict(_PANEL))
    assert out.get("ok") is True, out
    data = yaml.safe_load(target.read_text(encoding="utf-8"))
    assert data["tools"]["ghidra_headless"] == "/opt/ghidra/support/analyzeHeadless"
    assert data["binary_reconstruction"]["enable_address_placement"] is True
    assert data["network"]["allow_reference_download"] is True
    assert data["timeouts"]["ghidra"] == 1200
    # panelin anahtarları değişti
    assert data["binary_reconstruction"]["min_naming_confidence"] == 0.8
    assert data["network"]["enabled"] is True
    assert data["name_merger"]["unk_threshold"] == 0.25
    assert data["binary_reconstruction"]["external_signature_paths"] == ["/a/b.json"]
    assert data["binary_reconstruction"]["ghidra_data_type_archives"] == ["/c/d.gdt"]
    # katı yükleyiciden geçer ve elle eklenen ayarlar etkin
    cfg = Config.load(target)
    assert str(cfg.tools.ghidra_headless) == "/opt/ghidra/support/analyzeHeadless"
    assert cfg.binary_reconstruction.enable_address_placement is True
    assert cfg.network.allow_reference_download is True


def test_inert_max_functions_removed_and_reported(srv):
    target = _write(srv, _USER_YAML)
    out = srv._write_settings(dict(_PANEL))
    data = yaml.safe_load(target.read_text(encoding="utf-8"))
    assert "max_functions_to_process" not in data["binary_reconstruction"]
    assert any("max_functions_to_process" in w and "kaldırıldı" in w for w in out["warnings"])
    assert Config.load(target).inert_setting_warnings() == []


def test_panel_never_writes_max_functions(srv):
    target = srv._SETTINGS_YAML
    out = srv._write_settings({**_PANEL, "max_functions_to_process": 10})
    assert out.get("ok") is True
    text = target.read_text(encoding="utf-8")
    assert "max_functions_to_process" not in text
    assert "max_functions_to_process" not in out["knobs"]
    assert not any("max_functions_to_process" in w for w in out["warnings"])
    assert Config.load(target).inert_setting_warnings() == []


def test_html_has_no_max_functions_control():
    html = _INDEX.read_text(encoding="utf-8")
    assert "cfgMaxF" not in html
    assert "Maks. fonksiyon" not in html
    assert "max_functions_to_process" not in html


@pytest.mark.parametrize("bad", ["a: [1, 2\n", "- yalniz\n- liste\n", "network: 5\n"])
def test_unreadable_file_is_not_overwritten(srv, bad):
    target = _write(srv, bad)
    before = target.read_bytes()
    out = srv._write_settings(dict(_PANEL))
    assert out.get("__code") == 409, out
    assert "değiştirilmedi" in out["error"]
    assert target.read_bytes() == before


def test_read_settings_reports_loader_problems(srv):
    _write(srv, "binary_reconstrution:\n  enable_address_placement: true\n")
    out = srv._read_settings()
    assert out["errors"], out
    assert any("binary_reconstrution" in e for e in out["errors"])
    assert out["knobs"]["min_naming_confidence"] == Config().binary_reconstruction.min_naming_confidence


def test_read_settings_without_file_uses_defaults(srv, tmp_path, monkeypatch):
    # cwd'de başka bir karadul.yaml olsa da analizin dosyası yoksa öntanımlar gösterilir
    (tmp_path / "cwd").mkdir()
    (tmp_path / "cwd" / "karadul.yaml").write_text("network:\n  enabled: true\n")
    monkeypatch.chdir(tmp_path / "cwd")
    out = srv._read_settings()
    assert out["exists"] is False
    assert out["knobs"]["network_enabled"] is False
    assert out["errors"] == []


def test_start_analysis_refuses_when_loader_rejects(srv, tmp_path, monkeypatch):
    binary = tmp_path / "hedef"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
    monkeypatch.setattr(srv, "HOME", tmp_path)
    monkeypatch.setattr(srv, "_DATA_ROOT", tmp_path / "data")
    _write(srv, "timeouts:\n  ghidra: abc\n")
    called = []
    monkeypatch.setattr(srv.subprocess, "Popen", lambda *a, **k: called.append(a))
    out = srv.start_analysis(str(binary))
    assert "error" in out and "ayar dosyası" in out["error"], out
    assert called == []


# -- ARAYUZ-05: ağ düğmesinin etkisi ----------------------------------------------------------

def test_network_effect_off(srv):
    out = srv._write_settings({**_PANEL, "network_enabled": False})
    assert out["knobs"]["network_enabled"] is False
    assert out["network_effect"] == {"enabled": False, "dts_fetch": False,
                                     "source_match": False, "reference_download": False}


def test_network_effect_on_default_permissions(srv):
    out = srv._write_settings(dict(_PANEL))
    assert out["network_effect"] == {"enabled": True, "dts_fetch": True,
                                     "source_match": True, "reference_download": False}


def test_network_effect_keeps_explicit_permissions(srv):
    _write(srv, "network:\n  allow_reference_download: true\n  allow_dts_fetch: false\n")
    out = srv._write_settings(dict(_PANEL))
    eff = out["network_effect"]
    assert eff["reference_download"] is True     # elle eklenen izin silinmedi ve etkili
    assert eff["dts_fetch"] is False             # açıkça kapatılan izin ana anahtarı izlemez


def test_network_effect_mirrors_cli_enable_network():
    """Panelin gösterdiği etki CLI'ın --enable-network bloğunun aynısıdır."""
    cli = (_ROOT / "karadul" / "cli.py").read_text(encoding="utf-8")
    block = re.search(r"    if enable_network:\n(.*?)\n\n", cli, re.S)
    assert block, "cli.py --enable-network bloğu bulunamadı"
    assert "cfg.network.enable(" in block.group(1)
    assert "cfg.source_match.enabled = True" in block.group(1)


def test_network_effect_matches_reference_download_reader(srv):
    from karadul.pipeline.steps._feedback_naming_refdiff import reference_download_allowed
    for yaml_text, expected in (("", False), ("network:\n  allow_reference_download: true\n", True)):
        _write(srv, yaml_text) if yaml_text else None
        out = srv._write_settings(dict(_PANEL))
        cfg = Config.load(srv._SETTINGS_YAML)
        cfg.network.enable(explicit_keys={k.split(".", 1)[1] for k in cfg.yaml_keys
                                          if k.startswith("network.")})
        assert reference_download_allowed(cfg) is expected
        assert out["network_effect"]["reference_download"] is expected


def test_html_network_text_is_truthful():
    html = _INDEX.read_text(encoding="utf-8")
    assert "İnternetten kaynak/paket indirip eşleştir" not in html
    assert "network.allow_reference_download" in html
    assert 'id="cfgNetEff"' in html
    assert "daha doğru tip çıkarımı" not in html


_NODE = shutil.which("node")


@pytest.mark.skipif(_NODE is None, reason="node yok")
def test_settings_js_helpers(tmp_path):
    html = _INDEX.read_text(encoding="utf-8")
    m = re.search(r"/\* P17-AYAR-BASLA:.*?\*/(.*?)/\* P17-AYAR-BITIS \*/", html, re.S)
    assert m
    script = m.group(1) + r"""
console.log(JSON.stringify({
  off: netEffectText({enabled:false,dts_fetch:true}),
  on: netEffectText({enabled:true,dts_fetch:true,source_match:false,reference_download:false}),
  none: [null, undefined, 5].map(netEffectText),
  notes: settingsNotes({errors:['a: x'], warnings:['b etkisiz']}),
  empty: settingsNotes({}),
}));
"""
    p = tmp_path / "ayar.js"
    p.write_text(script, encoding="utf-8")
    proc = subprocess.run([_NODE, str(p)], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out["off"] == "Şu an: ağ kapalı — analiz ağa çıkmaz."
    assert out["on"] == ("Şu an: .d.ts indirme açık · kaynak eşleme kapalı · "
                         "başvuru kaynağı indirip derleme kapalı.")
    assert out["none"] == ["", "", ""]
    assert out["notes"][0]["cls"] == "err" and "a: x" in out["notes"][0]["text"]
    assert out["notes"][1] == {"cls": "warn", "text": "b etkisiz"}
    assert out["empty"] == []
