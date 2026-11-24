"""P-ÜV6b: Swift tip üst verisi ad kanalına, C++ RTTI kanıt satırına bağlandı (KARARLAR A-10, A-27, A-32).

Önce: ``swift_metadata_recovery`` ve ``rtti_recovery`` main'de ama Faz 1 listesinde yoktu; Swift adları hiçbir
ada dönüşmüyordu; ``_add_rtti`` vtable yuvasından ``Sınıf_vfunc_N`` ADI üretiyordu (güven 0,6; tam eşitlikte
doğruluğu 0). Şimdi:
- Swift (``swift_type_accessor``): ``ad_yazilabilir is True`` tipin erişim fonksiyonu → ad adayı (yalnız
  Ghidra'nın adsız bıraktığı fonksiyona), özgün ad ``type metadata accessor for <nitelikli_ad>``, etiket
  ``üst veriden``, güven tablodan; tablo satırı yoksa ya da alt sınır ``AD_ESIGI``'nin altındaysa kanıt satırı;
  ad verilemeyen tip ve bütün yuvalar kanıt satırı;
- RTTI: ``islevler[]`` → kanıt satırı (``sinif`` / ``karar`` / ``yerler``; ``belirsiz``'de ``siniflar``), ad 0;
- iki adım Faz 1'de ``objc_metadata_recovery``'den sonra, ``type_recovery_consumer``'dan önce;
- ObjC güven satırı ürün düzeyi aday ölçümünden (33 611 / 33 885);
- ``DURUM_TUTARSIZ`` / ``DURUM_KAPALI`` tek tanım (``goruntu.py``).
Testler sahte yapıtlarla (``tests/test_puv6a_baglama.py`` düzeni); gerçek ikili yok.
"""
from __future__ import annotations

import json
import math
import re
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from karadul.config import Config
from karadul.core import naming_labels as nl
from karadul.pipeline.steps import _feedback_naming_candidates as FC
from karadul.pipeline.steps import _feedback_naming_merger as FM

_KOK = Path(__file__).resolve().parents[1]
SW = nl.SOURCE_SWIFT_TYPE
RT = nl.SOURCE_RTTI
RAN = {"durum": "calisti", "neden": None}
SW_ROW = (2627, 2627, 0.9985)          # test satırı (gerçek satır ölçümle girer; testler ona bağlı değil)


@pytest.fixture
def swift_olculdu(monkeypatch):
    monkeypatch.setitem(nl.MEASURED_METADATA_PRECISION, SW, SW_ROW)


@pytest.fixture
def swift_olculmedi(monkeypatch):
    monkeypatch.delitem(nl.MEASURED_METADATA_PRECISION, SW, raising=False)


def _index(*addrs: int, named: dict[int, str] | None = None) -> FC.GhidraFunctionIndex:
    by_addr = {a: f"FUN_{a:08x}" for a in addrs}
    by_addr.update(named or {})
    return FC.GhidraFunctionIndex(by_addr=by_addr, names=frozenset(by_addr.values()))


def _flags(**on: bool) -> dict[str, bool]:
    return {src: bool(on.get(src)) for src in FC.K4_CHANNEL_FLAGS}


def _tip(addr: int, nitelikli: str | None = "Uyg.Pencere", **kw) -> dict:
    rec = {"tip_adresi": hex(addr + 0x9000), "tur": "class", "genel": False, "kisa_ad": "Pencere",
           "nitelikli_ad": nitelikli, "ad_neden": None, "alt_kume": "diger", "erisim": addr,
           "adres": hex(addr), "ad": (f"type metadata accessor for {nitelikli}" if nitelikli else None),
           "erisim_kodda": True, "erisim_baslangic": True, "erisim_paylasimli": False,
           "ad_yazilabilir": nitelikli is not None}
    rec.update(kw)
    return rec


def _yuva(addr: int | None, tur: str = "vtable", **kw) -> dict:
    rec = {"tur": tur, "tip": "Uyg.Pencere", "tip_adresi": 0x9000, "yontem_turu": "method", "sira": 2,
           "ornek": True, "dinamik": False, "zaman_uyumsuz": False, "adres": addr, "kodda": True}
    rec.update(kw)
    return rec


def _islev(addr: int, karar: str = "tek_sinif", sinif: str | None = "llama::Model",
           siniflar: list[str] | None = None) -> dict:
    return {"adres": addr, "karar": karar, "sinif": sinif, "sinif_typeinfo": 0x7000 if sinif else None,
            "siniflar": siniflar if siniflar is not None else ([sinif] if sinif else []),
            "yerler": [{"vtable": 0x8000, "sira": 3}]}


def _rtti_json(tmp_path: Path, islevler: list[dict]) -> Path:
    p = tmp_path / "rtti_classes.json"
    p.write_text(json.dumps({"schema": "karadul.rtti_classes.v1", "durum": "calisti",
                             "siniflar": [{"name": "llama::Model", "methods": [a["adres"] for a in islevler]}],
                             "islevler": islevler}))
    return p


def _run(index, *, flags=None, swift=None, slots=None, swift_status=RAN, rtti_path=None,
         rtti_status=("calisti", None), rtti_classes=None):
    cands: dict = {}
    stats: dict = {}
    recs: dict = {}
    ev: list = []
    FC.add_k4_channels(
        flags=flags or _flags(**{SW: True, RT: True}), index=index, binary_path=None, pdb_symbols=[],
        pdb_status=None, bn_functions=[], bn_status=None, trex_structs=[], trex_status=None,
        rtti_classes=rtti_classes, rtti_status=rtti_status, swift_types=swift or [],
        swift_slots=slots or [], swift_status=swift_status, rtti_classes_path=rtti_path,
        metadata_records=recs, metadata_evidence=ev, candidates=cands, stats=stats)
    return SimpleNamespace(cands=cands, stats=stats, ch=stats["naming_channels"], recs=recs, ev=ev)


# --- 1. bayraklar ---------------------------------------------------------------------------

def test_flags_off_swift_and_rtti_do_nothing(tmp_path, swift_olculdu) -> None:
    r = _run(_index(0x1000), flags=_flags(), swift=[_tip(0x1000)], slots=[_yuva(0x1000)],
             rtti_path=_rtti_json(tmp_path, [_islev(0x1000)]))
    assert r.cands == {} and r.recs == {} and r.ev == []
    assert r.ch[SW]["durum"] == "kapali" and "enable_swift_metadata_naming" in r.ch[SW]["neden"]
    assert r.ch[RT]["durum"] == "kapali" and "enable_rtti_naming" in r.ch[RT]["neden"]


def test_other_channel_on_does_not_open_swift_or_rtti(tmp_path, swift_olculdu) -> None:
    """Başka bir kanal açıkken (Go) Swift ve RTTI kendi bayrakları kapalıysa iş yapmaz."""
    r = _run(_index(0x1000), flags=_flags(**{nl.SOURCE_GO_PCLNTAB: True}), swift=[_tip(0x1000)],
             slots=[_yuva(0x1000)], rtti_path=_rtti_json(tmp_path, [_islev(0x1000)]))
    assert r.cands == {} and r.recs == {} and r.ev == []
    assert r.ch[SW]["durum"] == "kapali" and r.ch[RT]["durum"] == "kapali"


def test_flag_names_and_defaults_are_off() -> None:
    assert FC.K4_CHANNEL_FLAGS[SW] == "enable_swift_metadata_naming"
    assert FC.K4_CHANNEL_FLAGS[RT] == "enable_rtti_naming"
    br = Config().binary_reconstruction
    assert br.enable_swift_metadata_naming is False and br.enable_swift_metadata_recovery is False
    assert br.enable_rtti_naming is False and br.enable_rtti_recovery is False


# --- 2. Swift ad kanalı ----------------------------------------------------------------------

def test_swift_writable_type_names_unnamed_accessor(swift_olculdu) -> None:
    r = _run(_index(0x1000), swift=[_tip(0x1000, "Uyg.Pencere")])
    (c,) = r.cands["FUN_00001000"]
    ozgun = "type metadata accessor for Uyg.Pencere"
    assert (c.name, c.source) == (FC.c_identifier(ozgun), SW)       # Go / ObjC ile aynı dönüştürücü
    assert c.name == "type_metadata_accessor_for_Uyg_Pencere"
    assert c.confidence == SW_ROW[2]                                 # güven tablodan
    rec = r.recs["FUN_00001000"]
    assert rec["ozgun_ad"] == ozgun and rec["nitelikli_ad"] == "Uyg.Pencere" and rec["kaynak"] == SW
    assert r.ch[SW]["durum"] == "calisti" and r.ch[SW]["tuttu"] == 1 and r.ch[SW]["aday"] == 1


def test_swift_ghidra_named_accessor_gets_no_candidate(swift_olculdu) -> None:
    r = _run(_index(named={0x1000: "kendi_adi"}), swift=[_tip(0x1000)])
    assert r.cands == {} and r.recs == {} and r.ch[SW]["ghidra_adli"] == 1


@pytest.mark.parametrize("kw", [
    {"nitelikli": None, "alt_kume": "adsiz", "ad_neden": "ayrac_yok"},          # özel tip, ayraç yok
    {"erisim_kodda": False, "ad_yazilabilir": False},                            # erişim kodda değil
    {"erisim_paylasimli": True, "ad_yazilabilir": False},                        # paylaşımlı
    {"alt_kume": "uzanti", "ad_yazilabilir": False},                             # kısıtlı uzantı
])
def test_swift_not_writable_types_are_evidence_not_names(swift_olculdu, kw) -> None:
    r = _run(_index(0x1000, 0x1100), swift=[_tip(0x1000, **kw), _tip(0x1100, "Uyg.Diger")])
    assert list(r.cands) == ["FUN_00001100"]
    assert r.ch[SW]["ad_yazilamaz"] == 1 and r.ch[SW]["kanit_satiri"] == 1
    (row,) = [e for e in r.ev if e["adres"] == "0x1000"]
    assert row["kaynak"] == SW and row["nedenler"] == [FC.SWIFT_NOT_WRITABLE]
    assert row["kisa_ad"] == "Pencere"                                # kısa ad yalnız kanıtta


def test_swift_slots_are_evidence_never_candidates(swift_olculdu) -> None:
    r = _run(_index(0x2000, 0x2100, 0x2200),
             swift=[_tip(0x2200)],
             slots=[_yuva(0x2000), _yuva(0x2100, "tanik", protokol="Swift.Hashable"), _yuva(None)])
    assert list(r.cands) == ["FUN_00002200"]                         # yalnız erişim fonksiyonu
    rows = [e for e in r.ev if e["nedenler"] == [FC.SWIFT_SLOT_EVIDENCE]]
    assert [e["adres"] for e in rows] == ["0x2000", "0x2100"]
    assert rows[0]["yuva"] == "vtable" and rows[0]["sira"] == 2 and "ad" not in rows[0]
    assert rows[1]["protokol"] == "Swift.Hashable"
    assert r.ch[SW]["yuva_kanit"] == 2 and r.ch[SW]["yuva_adressiz"] == 1


def test_swift_without_table_row_writes_evidence_only(swift_olculmedi) -> None:
    r = _run(_index(0x1000), swift=[_tip(0x1000)])
    assert r.cands == {} and r.recs == {}
    assert r.ev[0]["nedenler"] == ["esik_alti"] and r.ev[0]["ozgun_ad"].startswith("type metadata")
    assert "ölçülmedi" in r.ch[SW]["neden"]


def test_swift_row_below_threshold_reads_table_and_writes_evidence(monkeypatch) -> None:
    """Hüküm 6: alt sınır < AD_ESIGI ise kanal ad yazmaz; kod bunu tablodan okur (elle dal yok)."""
    monkeypatch.setitem(nl.MEASURED_METADATA_PRECISION, SW, (90, 100, 0.8256))
    assert nl.metadata_writes_names(SW) is False
    r = _run(_index(0x1000), swift=[_tip(0x1000)])
    assert r.cands == {} and r.ev[0]["nedenler"] == ["esik_alti"]
    assert "eşiğinin altında" in r.ch[SW]["neden"]


def test_swift_producer_status_is_reported_not_invented(swift_olculdu) -> None:
    assert _run(_index(0x1000), swift_status=None).ch[SW]["durum"] == "desteklenmiyor"
    assert _run(_index(0x1000), swift_status={"durum": "kapali", "neden": "x"}).ch[SW]["durum"] == "kapali"
    r = _run(_index(0x1000), swift=[_tip(0x1000)], swift_status={"durum": "tutarsiz", "neden": "yapı"})
    assert r.ch[SW]["durum"] == "tutarsiz" and r.cands == {}
    assert _run(_index(0x1000), swift=[]).ch[SW]["durum"] == "veri_yok"


# --- 3. RTTI kanıt satırı ----------------------------------------------------------------------

def test_rtti_writes_evidence_rows_not_names(tmp_path) -> None:
    p = _rtti_json(tmp_path, [_islev(0x3000), _islev(0x3100, "en_taban_sinif", "llama::Taban")])
    r = _run(_index(0x3000, 0x3100), rtti_path=p, flags=_flags(**{RT: True}))
    assert r.cands == {} and r.recs == {}                           # RTTI kaynaklı ad 0
    rows = [e for e in r.ev if e["kaynak"] == RT]
    assert [e["adres"] for e in rows] == ["0x3000", "0x3100"]
    assert rows[0] == {"kaynak": RT, "adres": "0x3000", "nedenler": [FC.RTTI_SLOT_EVIDENCE],
                       "karar": "tek_sinif", "sinif": "llama::Model",
                       "yerler": [{"vtable": "0x8000", "sira": 3}], "ghidra_adi": "FUN_00003000"}
    ch = r.ch[RT]
    assert ch["durum"] == "calisti" and ch["kayit"] == 2 and ch["kanit_satiri"] == 2 and ch["aday"] == 0
    assert ch["tek_sinif"] == 1 and ch["en_taban_sinif"] == 1


def test_rtti_ambiguous_decision_writes_class_list_not_class_name(tmp_path) -> None:
    amb = _islev(0x3200, "belirsiz", None, siniflar=["A", "B"])
    amb["sinif"] = "A"                     # üretici yazsa bile belirsizde sınıf adı yazılmaz
    r = _run(_index(0x3200), rtti_path=_rtti_json(tmp_path, [amb]), flags=_flags(**{RT: True}))
    (row,) = r.ev
    assert "sinif" not in row and row["siniflar"] == ["A", "B"] and row["karar"] == FC.RTTI_AMBIGUOUS
    assert r.ch[RT]["belirsiz"] == 1


def test_rtti_old_vfunc_names_never_produced(tmp_path) -> None:
    """Eski yol: ``rtti_classes`` yuvalarından ``Sınıf_vfunc_N`` adayı. Artık hiçbir aday yok."""
    classes = [{"name": "llama::Model", "methods": [0x3000, 0x3100]}]
    r = _run(_index(0x3000, 0x3100), rtti_classes=classes, flags=_flags(**{RT: True}),
             rtti_path=_rtti_json(tmp_path, [_islev(0x3000), _islev(0x3100)]))
    assert r.cands == {}
    assert not any("vfunc" in json.dumps(e) for e in r.ev)


def test_rtti_producer_status_tuple_and_missing_producer(tmp_path) -> None:
    f = _flags(**{RT: True})
    assert _run(_index(0x1), flags=f, rtti_status=None).ch[RT]["durum"] == "desteklenmiyor"
    r = _run(_index(0x1), flags=f, rtti_status=("kapali", "bayrak kapalı"))
    assert r.ch[RT]["durum"] == "kapali" and "enable_rtti_recovery" in r.ch[RT]["neden"]
    r = _run(_index(0x1), flags=f, rtti_status=("veri_yok", "Itanium typeinfo nesnesi bulunamadı"))
    assert r.ch[RT]["durum"] == "veri_yok" and "typeinfo" in r.ch[RT]["neden"]
    r = _run(_index(0x1), flags=f, rtti_path=_rtti_json(tmp_path, []))
    assert r.ch[RT]["durum"] == "veri_yok" and r.ev == []


def test_rtti_is_not_unmeasured_name_channel_and_swift_is_metadata() -> None:
    assert SW in nl.METADATA_SOURCES and RT not in nl.METADATA_SOURCES
    assert RT in nl.METADATA_EVIDENCE_SOURCES
    assert RT not in FC.UNMEASURED_SOURCES and SW not in FC.UNMEASURED_SOURCES
    assert FC.UNMEASURED_SOURCES == frozenset(
        {"pdb", "dwarf", "rust_demangler", "go_demangler", "bn_symbol", "trex_struct"})


# --- 4. tablo ------------------------------------------------------------------------------

def test_objc_row_is_product_level_candidate_measurement_and_wilson_recomputed() -> None:
    from karadul.reconstruction.tarif import baglama
    assert nl.MEASURED_METADATA_PRECISION[nl.SOURCE_OBJC_METHOD][:2] == (33611, 33885)
    # Swift satırı: H3 (iTerm2, dondurmadan sonra bir kez); A-14 için 1 program → öntanımda kapalı
    assert nl.MEASURED_METADATA_PRECISION[SW][:2] == (2627, 2627)
    assert nl.METADATA_MEASURED_PROGRAMS[SW] == ("iTerm2",)
    for src, (k, n, alt) in nl.MEASURED_METADATA_PRECISION.items():
        assert alt == math.floor(baglama.wilson(k, n)[0] * 1e4) / 1e4     # elle yazılmadı
        assert nl.metadata_writes_names(src) is (alt >= nl.AD_ESIGI)
    assert nl.AD_ESIGI == nl.MALIYET_ORANI_L / (nl.MALIYET_ORANI_L + 1)
    src = (_KOK / "karadul" / "pipeline" / "steps" / "_feedback_naming_candidates.py").read_text()
    assert "0.909" not in src                                        # eşik içe aktarılır


# --- 5. birleştirici, köken kaydı, biçimlendirici ---------------------------------------------

def _ctx(flags: dict[str, bool], artifacts: dict) -> SimpleNamespace:
    cfg = Config()
    for src, on in flags.items():
        setattr(cfg.binary_reconstruction, FC.K4_CHANNEL_FLAGS[src], on)
    return SimpleNamespace(
        pipeline_context=SimpleNamespace(config=cfg, metadata={}, target=None, workspace=None),
        artifacts=artifacts)


def _merge(tmp_path: Path, ctx) -> SimpleNamespace:
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
    nr = SimpleNamespace(success=True, naming_map={"FUN_00002000": "c_namer_adi"})
    harita, _adli, dizin = FM.run_name_merger(
        ctx=ctx, iter_index=0, decompiled_dir=dec, reconstructed_dir=rec,
        incremental_files=None, extracted_names={}, naming_result=nr,
        bindiff_confidence_map={}, refdiff_naming={}, fid_json=tmp_path / "fid.json",
        computation_result=None, pcode_naming_candidates=[], stats=stats, errors=errors,
        artifacts={}, functions_json=fj)
    assert errors == []
    prov = json.loads((dec / nl.NAMING_PROVENANCE_FILE).read_text())
    return SimpleNamespace(harita=harita, stats=stats, dizin=dizin, prov=prov.get("name_merger"))


def test_merger_writes_swift_name_with_metadata_label(tmp_path, swift_olculdu) -> None:
    arts = {"binary_for_byte_match": Path("hedef"), "swift_status": RAN,
            "swift_types": [_tip(0x1000, "Uyg.Pencere"), _tip(0x1100, None)],
            "swift_slots": [_yuva(0x1100)]}
    k = _merge(tmp_path, _ctx({SW: True}, arts))
    ad = "type_metadata_accessor_for_Uyg_Pencere"
    assert k.harita["FUN_00001000"] == ad and "FUN_00001100" not in k.harita
    assert f"{ad}();" in (k.dizin / "a.c").read_text()
    karar = k.prov["decisions"]["FUN_00001000"]
    assert karar["label"] == nl.LABEL_METADATA != nl.LABEL_CERTAIN
    assert karar["ozgun_ad"] == "type metadata accessor for Uyg.Pencere"
    assert karar["ust_veri_kanali"] == SW and karar["confidence"] == SW_ROW[2]
    nedenler = sorted(n for r in k.prov["ust_veri_kanit"] for n in r["nedenler"])
    assert nedenler == [FC.SWIFT_NOT_WRITABLE, FC.SWIFT_SLOT_EVIDENCE]
    assert k.stats["name_merger_by_label"] == {nl.LABEL_METADATA: 1}


def test_merger_rtti_evidence_in_provenance_and_no_names(tmp_path) -> None:
    p = _rtti_json(tmp_path, [_islev(0x1000), _islev(0x1100, "belirsiz", None, ["A", "B"])])
    arts = {"binary_for_byte_match": Path("hedef"), "rtti_status": ("calisti", None),
            "rtti_classes": [{"name": "llama::Model", "methods": [0x1000, 0x1100]}],
            "rtti_classes_path": p}
    k = _merge(tmp_path, _ctx({RT: True}, arts))
    assert k.harita == {"FUN_00002000": "c_namer_adi"}                # RTTI kaynaklı ad 0
    rows = k.prov["ust_veri_kanit"]
    assert [r["kaynak"] for r in rows] == [RT, RT] and rows[1]["siniflar"] == ["A", "B"]
    assert "unmeasured_sources" not in json.dumps(k.prov)


def test_output_formatter_recognizes_swift_source(tmp_path) -> None:
    from karadul.core.output_formatter import OutputFormatter
    src = tmp_path / "src"
    src.mkdir()
    (src / "naming_map.json").write_text(json.dumps({"global": {}}))
    meta = {"kaynak": SW, "adres": "0x1000", "ozgun_ad": "type metadata accessor for A.B",
            "ad": "type_metadata_accessor_for_A_B"}
    dec = FM.metadata_decision(meta, meta["ad"])
    (src / nl.NAMING_PROVENANCE_FILE).write_text(json.dumps({"name_merger": {"decisions": {
        "FUN_00001000": {"name": meta["ad"], "applied_name": meta["ad"], **dec}}}}))
    rec = OutputFormatter._merger_metadata_records(tmp_path, [src / "naming_map.json"])["FUN_00001000"]
    assert rec["source"] == SW and rec["label"] == nl.LABEL_METADATA
    assert rec["ozgun_ad"] == meta["ozgun_ad"] and rec["channel"] == f"ust_veri:{SW}"


# --- 6. adım sırası, kapalı adımın süresi, durum sabitleri ------------------------------------

def test_producer_steps_registered_and_between_objc_and_consumer() -> None:
    from karadul.pipeline.registry import get_step
    import karadul.pipeline.steps  # noqa: F401  (kayıt)
    assert get_step("swift_metadata_recovery") is not None and get_step("rtti_recovery") is not None
    text = (_KOK / "karadul" / "stages.py").read_text(encoding="utf-8")
    m = re.search(r'runner = PipelineRunner\(steps=\[(.*?)\]\)', text, re.S)
    assert m and '"kesin_anchors"' in m.group(1)
    steps = re.findall(r'"([a-z_0-9]+)"', m.group(1))
    i = steps.index
    assert i("objc_metadata_recovery") < i("swift_metadata_recovery") < i("type_recovery_consumer")
    assert i("objc_metadata_recovery") < i("rtti_recovery") < i("type_recovery_consumer")


def test_steps_flag_off_write_kapali_quickly(tmp_path) -> None:
    from karadul.pipeline.steps.rtti_recovery import RttiRecoveryStep
    from karadul.pipeline.steps.swift_metadata_recovery import SwiftMetadataRecoveryStep
    cfg = Config()
    for cls, key in ((SwiftMetadataRecoveryStep, "swift_status"), (RttiRecoveryStep, "rtti_status")):
        ctx = SimpleNamespace(pipeline_context=SimpleNamespace(config=cfg, target=None, workspace=None),
                              artifacts={"binary_for_byte_match": tmp_path / "yok"}, stats={}, errors=[])
        t0 = time.monotonic()
        out = cls().run(ctx)
        assert time.monotonic() - t0 <= 0.1
        durum = out[key]["durum"] if isinstance(out[key], dict) else out[key][0]
        assert durum == "kapali" and ctx.stats[key] == "kapali" and ctx.errors == []


def test_durum_constants_have_single_definition() -> None:
    from karadul.analyzers.ustveri import cpp_rtti_tara, go_pclntab, goruntu, objc, swift
    assert (goruntu.DURUM_TUTARSIZ, goruntu.DURUM_KAPALI) == ("tutarsiz", "kapali")
    for mod in (objc, swift, go_pclntab):
        assert mod.DURUM_TUTARSIZ is goruntu.DURUM_TUTARSIZ and mod.DURUM_KAPALI is goruntu.DURUM_KAPALI
    assert cpp_rtti_tara.DURUM_KAPALI is goruntu.DURUM_KAPALI
    for mod in (objc, swift, go_pclntab, cpp_rtti_tara):
        text = Path(mod.__file__).read_text(encoding="utf-8")
        assert not re.search(r"^DURUM_(TUTARSIZ|KAPALI)\s*=", text, re.M), mod.__name__
