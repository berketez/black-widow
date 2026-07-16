"""ui/server.py build_model() güvenlik (packer/anti-debug) bloğu testleri.

KAPSAM: yalnızca saf artifact-okuma mantığı. Ghidra ÇAĞIRMAZ, ağ KULLANMAZ,
subprocess YOK. Sahte bir workspace kurulur (reconstructed/src/naming_map.json +
decompiled/FUN_*.c + static/*.json); build_model'in mevcut alanları BOZULMADAN
`security` bloğunu ürettiği doğrulanır.

TUZAK: ui/server.py paket modülü değil (ui/__init__.py yok) -> importlib ile
dosya yolundan yüklenir; __main__ guard server'ı başlatmaz. WS global'i test
başına set edilip cache temizlenir (activate_workspace) -> testler birbirini
kirletmez.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_SERVER_PY = Path(__file__).resolve().parent.parent / "ui" / "server.py"


@pytest.fixture(scope="module")
def srv():
    """ui/server.py'yi izole modül olarak yükle (server başlatmadan)."""
    spec = importlib.util.spec_from_file_location("bw_ui_server_sec", _SERVER_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _make_ws(root: Path, *, packer: dict | None = None,
             anti_debug: dict | None = None) -> Path:
    """En küçük geçerli workspace: naming_map + tek decompiled FUN + opsiyonel static/."""
    src = root / "reconstructed" / "src"
    src.mkdir(parents=True)
    (src / "naming_map.json").write_text(
        json.dumps({"global": {"FUN_00401000": "main"}}), encoding="utf-8")
    dec = root / "reconstructed" / "ghidra" / "decompiled"
    dec.mkdir(parents=True)
    (dec / "FUN_00401000.c").write_text(
        "void FUN_00401000(void){ return; }\n", encoding="utf-8")
    static = root / "static"
    static.mkdir(parents=True)
    if packer is not None:
        (static / "packer_fingerprints.json").write_text(
            json.dumps(packer), encoding="utf-8")
    if anti_debug is not None:
        (static / "anti_debug_findings.json").write_text(
            json.dumps(anti_debug), encoding="utf-8")
    return root


def test_build_model_security_packed(srv, tmp_path):
    """Paketli workspace -> security.packer dolu (packer_name == UPX)."""
    ws = _make_ws(
        tmp_path / "packed",
        packer={
            "total_fingerprints": 1,
            "fingerprints": [{
                "packer_name": "UPX", "version": "3.96", "confidence": 0.99,
                "evidence": ["UPX! magic", "section .UPX0"],
                "category": "packer", "platform": "elf", "layers_matched": 3,
            }],
        },
        anti_debug={"total_findings": 2, "findings": [],
                    "summary": {"anti_debug_score": 0.4}},
    )
    srv.activate_workspace(str(ws))
    m = srv.build_model()
    assert m is not None
    # mevcut alanlar BOZULMAMIŞ
    assert m["functions"] and m["total"] == 1
    assert "calls" in m and "names" in m
    # security bloğu
    sec = m["security"]
    assert sec["packer"] is not None
    assert sec["packer"]["packer_name"] == "UPX"   # curl/kanıt anahtarı
    assert sec["packer"]["name"] == "UPX"          # UI anahtarı
    assert sec["packer"]["version"] == "3.96"
    assert sec["packer"]["confidence"] == 0.99
    assert sec["packer"]["layers"] == 3
    assert "UPX! magic" in sec["packer"]["evidence"]
    assert sec["anti_debug"] == {"count": 2, "score": 0.4}


def test_build_model_security_clean(srv, tmp_path):
    """Temiz workspace (total_fingerprints=0) -> security.packer None (banner yok)."""
    ws = _make_ws(
        tmp_path / "clean",
        packer={"total_fingerprints": 0, "fingerprints": []},
        anti_debug={"total_findings": 0, "findings": [],
                    "summary": {"anti_debug_score": 0.0}},
    )
    srv.activate_workspace(str(ws))
    m = srv.build_model()
    assert m is not None
    assert m["total"] == 1  # model yine dolu
    assert m["security"]["packer"] is None
    assert m["security"]["anti_debug"] is None  # count=0 -> None


def test_build_model_security_missing_artifacts(srv, tmp_path):
    """static/ artifact'ları HİÇ yoksa -> security {packer:None, anti_debug:None}.

    build_model BOZULMAZ; eski davranış (functions/calls/names) aynen döner.
    """
    ws = _make_ws(tmp_path / "noartifacts")  # packer=None -> dosya yazılmaz
    srv.activate_workspace(str(ws))
    m = srv.build_model()
    assert m is not None
    assert m["total"] == 1
    assert m["security"] == {"packer": None, "anti_debug": None}


def test_security_info_corrupt_json_is_none(srv, tmp_path):
    """Bozuk JSON -> None (exception yayılmaz, build_model çökmez)."""
    ws = tmp_path / "corrupt"
    static = ws / "static"
    static.mkdir(parents=True)
    (static / "packer_fingerprints.json").write_text("{bozuk json", encoding="utf-8")
    sec = srv._security_info(str(ws))
    assert sec == {"packer": None, "anti_debug": None}
