"""Biçimlendirici c_namer adlarını gerçek güven, etiket ve kanalla yazar (plan v2.2 N1 adım 3).

Eskiden her c_namer adına ``confidence: 1.0`` yazılıyordu ve arayüz bunu gösteriyordu. Kilitlenen
davranışlar:
  - kayıt varsa güven, etiket, kanal ve kanıt kardeş köken kaydından gelir;
  - kayıt yoksa ya da başka bir adı anlatıyorsa güven ``None``, etiket "doğrulanmadı";
  - hiçbir yolda sabit ``1.0`` yazılmaz;
  - ad ve köken aynı yinelemeden okunur (son yineleme kazanır, kökeni de onunki olur);
  - ``source`` değeri ``c_namer`` kalır (ölçüm betikleri ve arayüz bunu okuyor).

Mutasyon koruması: ``scripts/measurement/mutation_specs_adim3_bicimlendirici.json``.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from karadul.core import naming_labels as nl
from karadul.core.output_formatter import OutputFormatter
from karadul.core.workspace import Workspace

_KOK = Path(__file__).resolve().parents[1]


def _kayit(ad, guven, strateji="string_context", **ek):
    return {"key": "", "new_name": ad, "confidence": guven, "strategy": strateji, "source": "candidate",
            "n_candidates": 1, "runners_up": [], **ek}


def _yaz(dizin: Path, adlar: dict, kayitlar: dict | None) -> None:
    dizin.mkdir(parents=True, exist_ok=True)
    (dizin / "naming_map.json").write_text(json.dumps({"global": adlar, "per_function": {}}), encoding="utf-8")
    if kayitlar is not None:
        (dizin / nl.NAMING_PROVENANCE_FILE).write_text(json.dumps({
            "schema": "karadul.naming_provenance", "schema_version": 1, "global": kayitlar,
            "per_function": {}}), encoding="utf-8")


@pytest.fixture
def ws(tmp_path: Path) -> Workspace:
    w = Workspace(base_dir=tmp_path / "workspaces", target_name="ornek")
    w.create()
    return w


def _harita(ws: Workspace) -> dict:
    return OutputFormatter(ws, SimpleNamespace(target_name="ornek"))._build_naming_map()["mappings"]


def test_guven_etiket_kanal_koken_kaydindan(ws):
    src = ws.get_stage_dir("reconstructed") / "src"
    _yaz(src, {"FUN_1000": "oturum_ac", "FUN_2000": "pencere_bul", "DAT_3000": "global_3000",
               "FUN_4000": "elle_verilen"},
         {"FUN_1000": _kayit("oturum_ac", 0.75, evidence="oturum_ac", sub_channel="oz_ad"),
          "FUN_2000": _kayit("pencere_bul", 0.95, strateji="ks1", label="kesin",
                             ks1={"satirlar": ["func_kalibi"], "rol": "kendi", "kanitlar": [{}, {}]}),
          "DAT_3000": _kayit("global_3000", 0.3, strateji="dataflow"),
          "FUN_4000": _kayit("elle_verilen", 0.95, strateji="pre_name", pre_name_kind="elle")})
    m = _harita(ws)
    assert m["FUN_1000"] == {"new_name": "oturum_ac", "source": "c_namer", "confidence": 0.75,
                             "label": "doğrulanmadı", "channel": "string_context/oz_ad",
                             "evidence": "oturum_ac"}
    assert m["FUN_2000"]["confidence"] == 0.95 and m["FUN_2000"]["label"] == "kesin"
    assert m["FUN_2000"]["channel"] == "ks1:func_kalibi"
    assert m["FUN_2000"]["evidence"] == {"rol": "kendi", "kanit_sayisi": 2}
    assert m["DAT_3000"]["confidence"] == 0.3 and m["DAT_3000"]["channel"] == "dataflow"
    # elle verilen ad etiket taşımaz; kanalı ön ad türüdür
    assert m["FUN_4000"]["label"] is None and m["FUN_4000"]["channel"] == "on_ad:elle"


def test_kayit_yoksa_guven_bilinmiyor_ve_asla_sabit_bir(ws):
    src = ws.get_stage_dir("reconstructed") / "src"
    _yaz(src, {"FUN_1000": "oturum_ac", "FUN_2000": "baska_ad"}, None)        # köken dosyası hiç yok
    m = _harita(ws)
    assert m["FUN_1000"] == {"new_name": "oturum_ac", "source": "c_namer", "confidence": None,
                             "label": "doğrulanmadı", "channel": None, "evidence": None}
    # dosya var ama anahtar yok / kayıt başka bir adı anlatıyor / güven sayı değil
    _yaz(src, {"FUN_1000": "oturum_ac", "FUN_2000": "baska_ad", "FUN_3000": "ucuncu"},
         {"FUN_2000": _kayit("eski_ad", 0.9, label="kesin"),
          "FUN_3000": _kayit("ucuncu", "yuksek", label="uydurma")})
    m = _harita(ws)
    assert m["FUN_1000"]["confidence"] is None and m["FUN_1000"]["label"] == "doğrulanmadı"
    assert m["FUN_2000"]["confidence"] is None and m["FUN_2000"]["label"] == "doğrulanmadı"
    assert m["FUN_2000"]["channel"] is None
    assert m["FUN_3000"]["confidence"] is None and m["FUN_3000"]["label"] == "doğrulanmadı"
    assert all(g["confidence"] != 1.0 for g in m.values())
    # bozuk köken dosyası adları düşürmez
    (src / nl.NAMING_PROVENANCE_FILE).write_text("{bozuk", encoding="utf-8")
    assert _harita(ws)["FUN_1000"]["confidence"] is None


def test_ad_ve_koken_ayni_yinelemeden(ws):
    """Son yineleme kazanır; kökeni de o yinelemenin kaydından gelir, taban kaydından değil."""
    rec = ws.get_stage_dir("reconstructed")
    _yaz(rec / "src", {"FUN_1000": "ilk_ad", "FUN_2000": "degismeyen"},
         {"FUN_1000": _kayit("ilk_ad", 0.4), "FUN_2000": _kayit("degismeyen", 0.8)})
    _yaz(rec / "src_iter1", {"FUN_1000": "son_ad"}, {"FUN_1000": _kayit("son_ad", 0.9, label="kesin")})
    m = _harita(ws)
    assert (m["FUN_1000"]["new_name"], m["FUN_1000"]["confidence"], m["FUN_1000"]["label"]) == \
        ("son_ad", 0.9, "kesin")
    assert m["FUN_2000"]["confidence"] == 0.8
    # son yinelemenin kökeni yoksa taban yinelemenin güveni devralınmaz
    (rec / "src_iter1" / nl.NAMING_PROVENANCE_FILE).unlink()
    m = _harita(ws)
    assert m["FUN_1000"]["new_name"] == "son_ad" and m["FUN_1000"]["confidence"] is None


@pytest.mark.parametrize("kayit, etiket", [
    (None, "doğrulanmadı"), ({}, "doğrulanmadı"), ({"label": "kesin"}, "kesin"),
    ({"label": "doğrulandı"}, "doğrulandı"), ({"label": "KESİN"}, "doğrulanmadı"),
    ({"pre_name_kind": "elle"}, None), ({"pre_name_kind": "ks1"}, "doğrulanmadı"),
    ({"pre_name_kind": "elle", "label": "kesin"}, "kesin"),
])
def test_etiket_kurali(kayit, etiket):
    assert nl.provenance_label(kayit) == etiket


def test_guven_ve_kanal_yardimcilari():
    assert nl.provenance_confidence({"confidence": 0}) == 0.0
    assert nl.provenance_confidence({"confidence": True}) is None       # bool sayı sayılmaz
    assert nl.provenance_confidence({"confidence": None}) is None and nl.provenance_confidence(None) is None
    assert nl.provenance_channel({"strategy": "ks1"}) == "ks1"
    assert nl.provenance_channel({"strategy": "ks1", "ks1": {"satirlar": ["assert_ust", "func_aktarma"]}}) == \
        "ks1:assert_ust+func_aktarma"
    assert nl.provenance_channel({"strategy": "string_context"}) == "string_context"
    assert nl.provenance_channel({"strategy": "api_param_reverse", "sub_channel": "x"}) == "api_param_reverse"
    assert nl.provenance_channel({}) is None and nl.provenance_channel(None) is None
    assert nl.provenance_evidence({"strategy": "dataflow", "evidence": ""}) is None


def test_sozluk_n0b_ve_c_namer_ile_ayni():
    """Etiket yazımı N0b'nin sözlüğüyle, köken dosyasının adı c_namer'ınkiyle aynı (tek sözlük)."""
    spec = importlib.util.spec_from_file_location("alt_kanal_sozluk", _KOK / "scripts" / "measurement" / "alt_kanal.py")
    ak = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = ak
    spec.loader.exec_module(ak)
    assert set(ak.GUVEN_ETIKETLERI.values()) == {nl.LABEL_VERIFIED, nl.LABEL_UNVERIFIED}
    assert nl.NAME_LABELS == ("kesin", "doğrulandı", "doğrulanmadı")
    from karadul.reconstruction import c_namer
    assert c_namer.NAMING_PROVENANCE_FILE == nl.NAMING_PROVENANCE_FILE
