"""P17 / MEK-08, ARAYUZ-12, ARAYUZ-13, ARAYUZ-15: sonuç ekranındaki adlar ve sayaçlar veriyle aynı.

- MEK-08: adsız fonksiyon `'FUN_'+addr.slice(-6)` ile gösteriliyordu (FUN_1000052f4 → FUN_0052f4;
  ikilide olmayan ad; ad kutusu bu uydurma etiketle doluyordu).
- ARAYUZ-12: liste 600 satırda sessizce kesiliyor, sayaç kesilmiş sayıyı "toplam" gibi gösteriyordu.
- ARAYUZ-13: "X / Y çözüldü" ve "RECONSTRUCTED %" doğrulanmamış adları da sayıyordu.
- ARAYUZ-15: teşhis metni arayüzde olmayan "İmzalar → BSim" ayarına yönlendiriyordu.
İşlevler index.html'den çıkarılıp node ile çalıştırılır (P17-GOSTERIM bloğu).
"""
from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_INDEX = _ROOT / "ui" / "index.html"
_SERVER_PY = _ROOT / "ui" / "server.py"
_NODE = shutil.which("node")


def _html() -> str:
    return _INDEX.read_text(encoding="utf-8")


def _block() -> str:
    m = re.search(r"/\* P17-GOSTERIM-BASLA:.*?\*/(.*?)/\* P17-GOSTERIM-BITIS \*/", _html(), re.S)
    assert m, "P17-GOSTERIM bloğu yok"
    return m.group(1)


def _run(tmp_path, body: str):
    p = tmp_path / "g.js"
    p.write_text(_block() + body, encoding="utf-8")
    proc = subprocess.run([_NODE, str(p)], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def test_no_shortened_fun_labels_in_html():
    html = _html()
    assert "slice(-6)" not in html and "slice(-5)" not in html
    assert "'FUN_'+" not in html


def test_no_resolved_wording():
    html = _html()
    assert "' çözüldü'" not in html and "çözüldü</span>" not in html
    assert ">RECONSTRUCTED<" not in html
    assert "+'.stripped'" not in html


@pytest.mark.skipif(_NODE is None, reason="node yok")
def test_shown_name_and_seed(tmp_path):
    out = _run(tmp_path, r"""
const u={addr:'FUN_1000052f4',name:'FUN_1000052f4',cls:'unnamed'};
const n={addr:'FUN_00101000',name:'read_config',cls:'named'};
console.log(JSON.stringify({su:shownName(u), sn:shownName(n), ru:renameSeed(u), rn:renameSeed(n)}));
""")
    assert out == {"su": "FUN_1000052f4", "sn": "read_config", "ru": "", "rn": "read_config"}


@pytest.mark.skipif(_NODE is None, reason="node yok")
def test_list_cut_is_reported(tmp_path):
    out = _run(tmp_path, r"""
console.log(JSON.stringify({
  cut: listCountText(LIST_MAX, 2587), full: listCountText(42, 42),
  more: moreRowText(LIST_MAX, 2587), none: moreRowText(42, 42), max: LIST_MAX}));
""")
    assert out["cut"] == "600 / 2587"
    assert out["full"] == "42"
    assert out["more"].startswith("1987 fonksiyon daha listelenmedi")
    assert out["none"] == ""
    assert out["max"] == 600


@pytest.mark.skipif(_NODE is None, reason="node yok")
def test_counters_split_by_label(tmp_path):
    out = _run(tmp_path, r"""
const F=[
 {addr:'FUN_1',name:'a',cls:'named',label:'kesin'},
 {addr:'FUN_2',name:'b',cls:'named',label:'doğrulanmadı'},
 {addr:'FUN_3',name:'c_00401000',cls:'weak',label:null},
 {addr:'FUN_4',name:'FUN_4',cls:'unnamed',label:null},
 {addr:'FUN_5',name:'d',cls:'named',label:'doğrulandı'},
 {addr:'FUN_6',name:'elle_ad',cls:'named',label:null},
 {addr:'memcpy',name:'memcpy',cls:'ghidra',label:null},
];
const c=nameCounts(F,new Set(['FUN_6']));
console.log(JSON.stringify({c, t:queueTexts(c)}));
""")
    c = out["c"]
    assert c == {"total": 6, "assigned": 5, "unnamed": 1, "kesin": 1, "dogrulandi": 1,
                 "dogrulanmadi": 1, "etiketsiz": 1, "elle": 1}
    assert out["t"]["head"] == "5 / 6 ad atandı"
    assert out["t"]["lab"] == ("kesin 1 · doğrulandı 1 · doğrulanmadı 1 · etiketsiz 1 · elle 1")


def test_list_uses_helpers():
    html = _html()
    assert "listCountText(rows.length,matched.length)" in html
    assert "moreRowText(rows.length,matched.length)" in html
    assert "inp.value = renameSeed(f);" in html


def test_bsim_diagnosis_is_factual(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("bw_ui_server_p17_g", _SERVER_PY)
    srv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(srv)
    monkeypatch.setattr(srv, "_signature_candidates", lambda: None)
    monkeypatch.setattr(srv, "_bsim_shadow", lambda: {"00101000": {"name": "xmalloc",
                                                                   "similarity": 0.93}})
    monkeypatch.setattr(srv, "_recon_stats", lambda: {})
    d = srv._naming_diagnosis("FUN_00101000", "", {}, "unnamed")
    assert d["verdict"] == "bsim_shadow"
    assert "İmzalar" not in d["reason"] and "otomatik isimlenebilir" not in d["reason"]
    assert "'xmalloc'" in d["reason"] and "%93" in d["reason"]
    assert "ölçülmedi" in d["reason"]
