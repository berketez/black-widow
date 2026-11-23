"""P-ÜV6a: Go ``pclntab`` ve Objective-C yöntem adları ad kanallarına bağlandı (KARARLAR A-10, A-27, A-28).

Önce: üretici adımlar (``go_metadata_recovery``, ``objc_metadata_recovery``) Faz 1 listesinde değildi,
ad kanalı yoktu → hedef setinde terminal-notifier 0 / 40, Ollama 13 160 fonksiyonda 17 ad. Şimdi:
- iki kanal ``K4_CHANNEL_FLAGS``'ta (bayrak öntanımda kapalı; A-14: 3 bağımsız program yok);
- aday yalnız Ghidra'nın adsız bıraktığı fonksiyona; A-28: ObjC'de Ghidra adı = seçici ise tam ad;
- Go ``pcsp_kapsama`` ``kisa`` / ``tasan``, ObjC ``ad_yazilabilir = False`` / ``swift`` /
  ``imp_paylasimli`` → ad değil kanıt satırı (her nedenin ayrı sayacı);
- etiket ``üst veriden`` (hiçbir zaman ``kesin``), ``ozgun_ad`` korunur, güven ölçülmüş tablodan.
Testler sahte yapıtlarla (``tests/test_p13b_kanallar.py`` düzeni); gerçek ikili yok.
"""
from __future__ import annotations

import importlib.util
import json
import math
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from karadul.config import Config
from karadul.core import naming_labels as nl
from karadul.pipeline.steps import _feedback_naming_candidates as FC
from karadul.pipeline.steps import _feedback_naming_merger as FM

_KOK = Path(__file__).resolve().parents[1]
GO = nl.SOURCE_GO_PCLNTAB
OBJC = nl.SOURCE_OBJC_METHOD
RAN_STATUS = {"durum": "calisti", "neden": ""}


def _index(*addrs: int, named: dict[int, str] | None = None) -> FC.GhidraFunctionIndex:
    by_addr = {a: f"FUN_{a:08x}" for a in addrs}
    by_addr.update(named or {})
    counts: dict[str, int] = {}
    for n in by_addr.values():
        cn = FC.code_name(n)
        counts[cn] = counts.get(cn, 0) + 1
    return FC.GhidraFunctionIndex(by_addr=by_addr, names=frozenset(by_addr.values()),
                                  code_name_counts=counts)


def _flags(**on: bool) -> dict[str, bool]:
    return {src: bool(on.get(src)) for src in FC.K4_CHANNEL_FLAGS}


def _k4(index, **kw):
    base = dict(flags=_flags(), index=index, binary_path=None, pdb_symbols=[], pdb_status=None,
                bn_functions=[], bn_status=None, trex_structs=[], trex_status=None)
    base.update(kw)
    return base


def _go(addr: int, ad: str, pcsp: str = "tam") -> dict:
    return {"giris": hex(addr), "bitis": hex(addr + 0x40), "ad": ad, "paket": ad.split(".")[0],
            "pcsp_kapsama": pcsp}


def _objc(imp: int, sinif: str, secici: str, **kw) -> dict:
    rec = {"imp": imp, "adres": hex(imp), "tur": "-", "sinif": sinif, "kategori": None,
           "secici": secici, "tam_ad": f"-[{sinif} {secici}]", "swift": False,
           "imp_paylasimli": False, "ad_yazilabilir": True}
    rec.update(kw)
    return rec


def _run(index, *, go=None, objc=None, flags=None, go_status=RAN_STATUS, objc_status=RAN_STATUS, **kw):
    cands: dict = {}
    stats: dict = {}
    recs: dict = {}
    ev: list = []
    FC.add_k4_channels(**_k4(index, flags=flags or _flags(**{GO: True, OBJC: True}),
                             go_functions=go or [], go_status=go_status, objc_methods=objc or [],
                             objc_status=objc_status, metadata_records=recs,
                             metadata_evidence=ev, **kw),
                       candidates=cands, stats=stats)
    return SimpleNamespace(cands=cands, stats=stats, ch=stats["naming_channels"], recs=recs, ev=ev)


# --- 1. kanal kapalı / açık ------------------------------------------------------------------

def test_flags_off_metadata_channels_do_nothing() -> None:
    r = _run(_index(0x1000), go=[_go(0x1000, "main.main")],
             objc=[_objc(0x1000, "A", "b")], flags=_flags())
    assert r.cands == {} and r.recs == {} and r.ev == []
    assert r.ch[GO]["durum"] == "kapali" and r.ch[OBJC]["durum"] == "kapali"
    assert "enable_go_pclntab_naming" in r.ch[GO]["neden"]


def test_go_channel_on_names_unnamed_function_with_table_confidence() -> None:
    r = _run(_index(0x1000), go=[_go(0x1000, "runtime.mapaccess1")])
    (c,) = r.cands["FUN_00001000"]
    assert (c.name, c.source) == ("runtime_mapaccess1", GO)
    assert c.confidence == nl.MEASURED_METADATA_PRECISION[GO][2]
    assert r.recs["FUN_00001000"]["ozgun_ad"] == "runtime.mapaccess1"     # özgün ad korunur
    assert r.ch[GO]["durum"] == "calisti" and r.ch[GO]["tuttu"] == 1 and r.ch[GO]["aday"] == 1


def test_ghidra_named_function_gets_no_go_candidate() -> None:
    r = _run(_index(named={0x2000: "_rt0_arm64_darwin"}), go=[_go(0x2000, "_rt0_arm64_darwin")])
    assert r.cands == {}
    assert r.ch[GO]["ghidra_adli"] == 1


@pytest.mark.parametrize("pcsp", ["kisa", "tasan"])
def test_go_pcsp_mismatch_becomes_evidence_row(pcsp: str) -> None:
    r = _run(_index(0x1000, 0x1100), go=[_go(0x1000, "a.F", pcsp), _go(0x1100, "a.G")])
    assert list(r.cands) == ["FUN_00001100"]
    assert r.ch[GO]["pcsp_elendi"] == 1
    assert r.ev == [{"kaynak": GO, "adres": "0x1000", "ozgun_ad": "a.F", "nedenler": [f"pcsp_{pcsp}"]}]


# --- 2. ObjC: A-28 ve kanıt satırı -----------------------------------------------------------

def test_objc_a28_selector_named_function_gets_full_name() -> None:
    sel = "applicationDidFinishLaunching:"
    r = _run(_index(named={0x3000: sel}), objc=[_objc(0x3000, "AppDelegate", sel)])
    key = "applicationDidFinishLaunching_"            # Ghidra'nın C çıktısındaki yazım
    (c,) = r.cands[key]
    assert c.name == "AppDelegate_applicationDidFinishLaunching"
    assert r.recs[key]["ozgun_ad"] == "-[AppDelegate applicationDidFinishLaunching:]"
    assert r.recs[key]["secici_yerine"] is True and r.ch[OBJC]["secici_yerine"] == 1


def test_objc_unnamed_function_uses_address_key() -> None:
    r = _run(_index(0x3100), objc=[_objc(0x3100, "Kedi", "miyav")])
    assert [c.name for c in r.cands["FUN_00003100"]] == ["Kedi_miyav"]
    assert r.recs["FUN_00003100"]["secici_yerine"] is False


def test_objc_ghidra_name_differs_from_selector_is_untouched() -> None:
    r = _run(_index(named={0x3200: "kendi_adim"}), objc=[_objc(0x3200, "Kedi", "miyav")])
    assert r.cands == {} and r.ch[OBJC]["ghidra_adli"] == 1


def test_objc_selector_name_shared_by_two_functions_is_not_used() -> None:
    """``init`` iki sınıfta: Ghidra'nın ad listesi ad alanını yazmaz, koddaki ``init`` ayırmaz."""
    r = _run(_index(named={0x4000: "init", 0x4100: "init"}),
             objc=[_objc(0x4000, "A", "init"), _objc(0x4100, "B", "init")])
    assert r.cands == {} and r.ch[OBJC]["secici_tekil_degil"] == 2


@pytest.mark.parametrize("alan,deger,neden", [
    ("ad_yazilabilir", False, FC.OBJC_NOT_WRITABLE),
    ("swift", True, FC.OBJC_SWIFT_BRIDGE),
    ("imp_paylasimli", True, FC.OBJC_SHARED_IMP),
])
def test_objc_rejected_records_become_evidence_rows(alan: str, deger: bool, neden: str) -> None:
    r = _run(_index(0x5000, 0x5100), objc=[_objc(0x5000, "S", "x", **{alan: deger}),
                                          _objc(0x5100, "S", "y")])
    assert list(r.cands) == ["FUN_00005100"]
    assert r.ch[OBJC][neden] == 1 and r.ch[OBJC]["kanit_satiri"] == 1
    assert r.ev[0]["nedenler"] == [neden] and r.ev[0]["ozgun_ad"] == "-[S x]"


def test_objc_protocol_record_without_imp_is_counted_not_named() -> None:
    r = _run(_index(0x5000), objc=[_objc(0, "P", "z")])
    assert r.cands == {} and r.ch[OBJC]["imp_yok"] == 1


# --- 3. üretici durumu, çift aday ----------------------------------------------------------

def test_producer_statuses_are_reported_not_invented() -> None:
    r = _run(_index(0x1000), go_status=None, objc_status={"durum": "kapali", "neden": "x"})
    assert r.ch[GO]["durum"] == "desteklenmiyor"         # adım koşmadı (yapıt yok)
    assert r.ch[OBJC]["durum"] == "kapali"
    r2 = _run(_index(0x1000), go_status={"durum": "veri_yok", "neden": "Go değil"},
              objc_status={"durum": "veri_yok", "neden": "ObjC yok"})
    assert r2.ch[GO]["durum"] == "veri_yok" and r2.ch[OBJC]["durum"] == "veri_yok"


def test_old_go_channel_does_not_add_second_candidate(monkeypatch) -> None:
    monkeypatch.setattr(FC, "_extract_binary_symbols", lambda _p: [("main.main", 0x1000)])
    r = _run(_index(0x1000), go=[_go(0x1000, "main.main")],
             flags=_flags(**{GO: True, "go_demangler": True}), binary_path=Path("x"))
    assert [c.source for c in r.cands["FUN_00001000"]] == [GO]
    assert r.ch["go_demangler"]["ust_veri_onde"] == 1


# --- 4. birleştirici: köken kaydı, etiket, güven ------------------------------------------

def _ctx(flags: dict[str, bool], artifacts: dict) -> SimpleNamespace:
    cfg = Config()
    for src, on in flags.items():
        setattr(cfg.binary_reconstruction, FC.K4_CHANNEL_FLAGS[src], on)
    return SimpleNamespace(
        pipeline_context=SimpleNamespace(config=cfg, metadata={}, target=None, workspace=None),
        artifacts=artifacts)


def _merge(tmp_path: Path, ctx, naming_result=None) -> SimpleNamespace:
    dec = tmp_path / "src"
    dec.mkdir()
    (dec / "a.c").write_text("void FUN_00002000(void){ FUN_00001000(); FUN_00001100(); }\n")
    (dec / nl.NAMING_PROVENANCE_FILE).write_text(json.dumps({"schema": "x", "global": {}}))
    fj = tmp_path / "ghidra_functions.json"
    fj.write_text(json.dumps({"functions": [
        {"name": f"FUN_{a:08x}", "address": f"{a:x}"} for a in (0x1000, 0x1100, 0x2000)]}))
    rec = tmp_path / "rec"
    rec.mkdir()
    stats: dict = {}
    errors: list[str] = []
    harita, _adli, dizin = FM.run_name_merger(
        ctx=ctx, iter_index=0, decompiled_dir=dec, reconstructed_dir=rec,
        incremental_files=None, extracted_names={}, naming_result=naming_result,
        bindiff_confidence_map={}, refdiff_naming={}, fid_json=tmp_path / "fid.json",
        computation_result=None, pcode_naming_candidates=[], stats=stats, errors=errors,
        artifacts={}, functions_json=fj)
    assert errors == []
    prov = json.loads((dec / nl.NAMING_PROVENANCE_FILE).read_text())
    return SimpleNamespace(harita=harita, stats=stats, dizin=dizin, prov=prov.get("name_merger"))


GO_ARTS = {
    "binary_for_byte_match": Path("hedef"),
    "go_functions": [_go(0x1000, "main.main"), _go(0x1100, "a.F", "tasan")],
    "go_status": RAN_STATUS,
}


def test_merger_writes_go_name_with_metadata_label(tmp_path) -> None:
    k = _merge(tmp_path, _ctx({GO: True}, dict(GO_ARTS)))
    assert k.harita == {"FUN_00001000": "main_main"}
    assert "main_main();" in (k.dizin / "a.c").read_text()
    karar = k.prov["decisions"]["FUN_00001000"]
    assert karar["label"] == nl.LABEL_METADATA != nl.LABEL_CERTAIN
    assert karar["ozgun_ad"] == "main.main"
    assert karar["ust_veri_kanali"] == GO and karar["ust_veri_dogrulama"] == "olculmedi"
    assert karar["confidence"] == nl.MEASURED_METADATA_PRECISION[GO][2]
    assert nl.provenance_channel(karar) == "ust_veri:go_pclntab"
    # pcsp tasan: ad yok, kanıt satırı köken kaydında
    assert k.prov["ust_veri_kanit"] == [{"kaynak": GO, "adres": "0x1100", "ozgun_ad": "a.F",
                                         "nedenler": ["pcsp_tasan"]}]
    assert k.stats["name_merger_by_label"] == {nl.LABEL_METADATA: 1}


def test_merger_flag_off_provenance_has_no_metadata_fields(tmp_path) -> None:
    k = _merge(tmp_path, _ctx({GO: False}, dict(GO_ARTS)))
    assert not k.harita
    assert k.prov is None or "ust_veri_kanit" not in k.prov
    assert "name_merger_by_label" not in k.stats


def test_c_namer_decided_key_keeps_c_namer_name_metadata_becomes_evidence(tmp_path) -> None:
    nr = SimpleNamespace(success=True, naming_map={"FUN_00001000": "c_namer_adi"})
    k = _merge(tmp_path, _ctx({GO: True}, dict(GO_ARTS)), naming_result=nr)
    assert k.harita["FUN_00001000"] == "c_namer_adi"
    assert k.stats["naming_channels"][GO]["c_namer_adlandirdi"] == 1
    assert any(r["nedenler"] == ["c_namer_adlandirdi"] for r in k.prov["ust_veri_kanit"])


def test_metadata_decision_never_certain_and_loser_is_evidence() -> None:
    meta = {"kaynak": OBJC, "adres": "0x10", "ozgun_ad": "-[A b]", "ad": "A_b", "secici_yerine": True,
            "ghidra_adi": "b"}
    won = FM.metadata_decision(meta, "A_b")
    assert won["label"] == nl.LABEL_METADATA and won["ozgun_ad"] == "-[A b]"
    assert won["secici_yerine"] is True and won["ghidra_adi"] == "b"
    lost = FM.metadata_decision(meta, "baska_ad")
    assert "label" not in lost and lost["ust_veri_adayi"]["ozgun_ad"] == "-[A b]"


# --- 5. sözlük, tablo, gösterim ----------------------------------------------------------

def test_label_dictionary_equality() -> None:
    spec = importlib.util.spec_from_file_location(
        "alt_kanal_puv6a", _KOK / "scripts" / "measurement" / "alt_kanal.py")
    ak = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = ak
    spec.loader.exec_module(ak)
    assert nl.NAME_LABELS == (nl.LABEL_CERTAIN, *sorted(set(ak.GUVEN_ETIKETLERI.values()),
                                                        key=nl.NAME_LABELS.index),
                              nl.LABEL_METADATA)
    assert nl.LABEL_METADATA == "üst veriden"
    assert nl.provenance_label({"label": nl.LABEL_METADATA}) == nl.LABEL_METADATA
    from karadul.lm import tools as T
    assert T.LABEL_TAGS[nl.LABEL_METADATA] == T.TAG_METADATA != T.TAG_PROVEN


def test_measured_metadata_table_is_wilson_floor_and_above_threshold() -> None:
    from karadul.reconstruction.tarif import baglama
    for src, (k, n, alt) in nl.MEASURED_METADATA_PRECISION.items():
        assert alt == math.floor(baglama.wilson(k, n)[0] * 1e4) / 1e4
        assert alt < 1.0 and alt >= nl.AD_ESIGI and nl.metadata_writes_names(src)
        assert src not in FC.UNMEASURED_SOURCES
        assert len(nl.METADATA_MEASURED_PROGRAMS[src]) < 3     # A-14: öntanımda açılmaz
    assert FC.K4_CHANNEL_FLAGS[GO] == "enable_go_pclntab_naming"
    assert FC.K4_CHANNEL_FLAGS[OBJC] == "enable_objc_metadata_naming"
    cfg = Config().binary_reconstruction
    assert cfg.enable_go_pclntab_naming is False and cfg.enable_objc_metadata_naming is False


def test_output_formatter_carries_metadata_decision_into_naming_map(tmp_path) -> None:
    from karadul.core.output_formatter import OutputFormatter
    src = tmp_path / "src"
    src.mkdir()
    (src / "naming_map.json").write_text(json.dumps({"global": {}}))
    dec = FM.metadata_decision({"kaynak": GO, "adres": "0x1000", "ozgun_ad": "main.main",
                                "ad": "main_main"}, "main_main")
    (src / nl.NAMING_PROVENANCE_FILE).write_text(json.dumps({"name_merger": {"decisions": {
        "FUN_00001000": {"name": "main_main", "applied_name": "main_main", **dec},
        "FUN_00002000": {"name": "x", "applied_name": "x", "confidence": 0.9},
        "FUN_00003000": {"name": "y", "applied_name": None, **dec}}}}))
    out = OutputFormatter._merger_metadata_records(tmp_path, [src / "naming_map.json"])
    assert list(out) == ["FUN_00001000"]
    rec = out["FUN_00001000"]
    assert rec["new_name"] == "main_main" and rec["label"] == nl.LABEL_METADATA
    assert rec["ozgun_ad"] == "main.main" and rec["source"] == GO
    assert rec["confidence"] == nl.MEASURED_METADATA_PRECISION[GO][2]


def test_report_counts_metadata_names_separately() -> None:
    from karadul.reporting import report_data as rd
    res = SimpleNamespace(stages={"reconstruct": SimpleNamespace(stats={
        "naming_by_label": {nl.LABEL_CERTAIN: 2}, "name_merger_by_label": {nl.LABEL_METADATA: 5}})})
    sec = rd._naming_labels(res, None)
    assert sec.extra["function_names_metadata"] == 5
    assert sec.extra["function_names_unverified"] == 0
    assert nl.LABEL_METADATA in sec.summary


# --- 6. adım sırası ------------------------------------------------------------------------

def test_producer_steps_registered_and_before_consumer() -> None:
    from karadul.pipeline.registry import get_step
    import karadul.pipeline.steps  # noqa: F401  (kayıt)
    assert get_step("go_metadata_recovery") is not None
    assert get_step("objc_metadata_recovery") is not None
    text = (_KOK / "karadul" / "stages.py").read_text(encoding="utf-8")
    m = re.search(r'runner = PipelineRunner\(steps=\[(.*?)\]\)', text, re.S)
    assert m and '"kesin_anchors"' in m.group(1)                  # Faz 1 listesi
    steps = re.findall(r'"([a-z_0-9]+)"', m.group(1))
    i = steps.index
    assert i("binaryninja_analysis") < i("go_metadata_recovery") < i("type_recovery_consumer")
    assert i("binaryninja_analysis") < i("objc_metadata_recovery") < i("type_recovery_consumer")
    assert "feedback_loop" not in steps                            # tüketici Faz 2'de
