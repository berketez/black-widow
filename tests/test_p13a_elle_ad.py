"""P13a / AD-11 + B-C6: BinDiff / ReferenceDiffer elle, ``main`` ve KS-1 ön adını ezmez; elle ad
birleştirmeden sonra koda giden haritaya zorlanır.

Uçtan uca: arayüzün ad düzeltme yolu (``core/overrides.set_name``) → kurtarma tohumu
(``_seed_recovery_pre_names``, künyede ``elle``) → BinDiff eşleşmesi aynı anahtara başka ad
önerir → iki yineleme (gerçek c_namer + birleştirici) sonunda ad ve künye korunur.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import test_c_namer_determinism as T  # noqa: E402

from karadul.config import Config  # noqa: E402
from karadul.core import overrides  # noqa: E402
from karadul.pipeline.steps import _feedback_naming_bindiff as FB  # noqa: E402
from karadul.pipeline.steps import _feedback_naming_merger as FM  # noqa: E402
from karadul.pipeline.steps import _feedback_naming_refdiff as FR  # noqa: E402
from karadul.reconstruction import c_namer  # noqa: E402
from karadul.reconstruction.c_namer import CVariableNamer  # noqa: E402
from karadul.reconstruction.tarif import baglama  # noqa: E402
from karadul.stages import ReconstructionStage  # noqa: E402

HASH = "a" * 64
ELLE_ANAHTAR = "FUN_00007000"
ELLE_AD = "analist_adi"


@pytest.fixture
def seri(monkeypatch):
    monkeypatch.setattr(c_namer, "ProcessPoolExecutor", T._SerialExecutor)
    monkeypatch.setattr(c_namer, "_worker_namer", None)


def test_korunan_tur_ezilmez_digerleri_yazilir() -> None:
    adlar = {"FUN_1": "elle_ad", "FUN_2": "main", "FUN_3": "ks1_ad", "FUN_4": "faz1_ad"}
    kunye = {"FUN_1": baglama.make_meta(baglama.KIND_MANUAL, "elle_ad"),
             "FUN_2": baglama.make_meta(baglama.KIND_MAIN, "main"),
             "FUN_3": {"kind": baglama.KIND_KS1, "name": "ks1_ad"},
             "FUN_4": baglama.make_meta(baglama.KIND_PHASE1, "faz1_ad")}
    korunan = FB.update_unprotected(
        adlar, {k: "ref_" + k for k in ("FUN_1", "FUN_2", "FUN_3", "FUN_4", "FUN_5")}, kunye)
    assert korunan == ["FUN_1", "FUN_2", "FUN_3"]
    assert adlar == {"FUN_1": "elle_ad", "FUN_2": "main", "FUN_3": "ks1_ad",
                     "FUN_4": "ref_FUN_4", "FUN_5": "ref_FUN_5"}


def test_kunyesi_bayat_ad_korunmaz() -> None:
    # künye başka adı anlatıyorsa (ad başka kaynakça ezilmiş) koruma yok
    adlar = {"FUN_1": "baska"}
    kunye = {"FUN_1": baglama.make_meta(baglama.KIND_MANUAL, "elle_ad")}
    assert FB.update_unprotected(adlar, {"FUN_1": "ref"}, kunye) == []
    assert adlar["FUN_1"] == "ref"


def _bindiff_kos(ctx, adlar, stats, monkeypatch, eslesme):
    def sahte_kaynak(*, bindiff_names, bindiff_confidence_map, **_kw):
        bindiff_names.update(eslesme)
        bindiff_confidence_map.update({k: (v, 0.95, "string") for k, v in eslesme.items()})

    monkeypatch.setattr(FB, "_config_source", sahte_kaynak)
    monkeypatch.setattr(FB, "_refdb_source", lambda **_kw: None)
    harita: dict = {}
    FB.run_bindiff(ctx=ctx, func_data={"functions": []}, string_data={"strings": []},
                   functions_json=Path("/yok"), strings_json=Path("/yok"),
                   call_graph_json=Path("/yok"), bindiff_confidence_map=harita,
                   bindiff_names={}, extracted_names=adlar, stats=stats, errors=[])
    return harita


def test_uctan_uca_overrides_bindiff_iki_yineleme(tmp_path, monkeypatch, seri) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "ev"))
    overrides.set_name(HASH, ELLE_ANAHTAR, ELLE_AD)

    # Kurtarma tohumu: elle ad ön ad olur, künyesi "elle"
    cfg = Config()
    context = SimpleNamespace(target=SimpleNamespace(file_hash=HASH), config=cfg)
    adlar: dict[str, str] = {}
    kunye: dict = {}
    ReconstructionStage()._seed_recovery_pre_names(adlar, None, context, {}, meta=kunye)
    assert adlar == {ELLE_ANAHTAR: ELLE_AD}
    assert kunye[ELLE_ANAHTAR]["kind"] == baglama.KIND_MANUAL

    ctx = SimpleNamespace(pipeline_context=SimpleNamespace(config=cfg, metadata={}),
                          artifacts={"pre_name_meta": kunye})
    stats: dict = {}
    # BinDiff aynı anahtara başka ad, başka bir anahtara da ad öneriyor (yineleme 0)
    bd = _bindiff_kos(ctx, adlar, stats, monkeypatch,
                      {ELLE_ANAHTAR: "referans_adi", "FUN_00005000": "ref_bes"})
    assert adlar[ELLE_ANAHTAR] == ELLE_AD and adlar["FUN_00005000"] == "ref_bes"
    assert stats["bindiff_protected_pre_names"] == 1
    assert baglama.meta_for(kunye, ELLE_ANAHTAR, adlar[ELLE_ANAHTAR])["kind"] == "elle"

    ws = T.build_workspace(tmp_path / "ws")
    for yineleme in (0, 1):
        out = tmp_path / f"out{yineleme}"
        sonuc = CVariableNamer(Config(), min_confidence=0.15).analyze_and_rename(
            ws["decompiled"], ws["functions"], ws["strings"], ws["call_graph"], out,
            pre_names=dict(adlar), pre_name_meta=kunye)
        assert sonuc.success, sonuc.errors
        assert sonuc.naming_map[ELLE_ANAHTAR] == ELLE_AD
        koken = json.loads((out / c_namer.NAMING_PROVENANCE_FILE).read_text())
        assert koken["global"][ELLE_ANAHTAR]["pre_name_kind"] == baglama.KIND_MANUAL
        harita, _, _ = FM.run_name_merger(
            ctx=ctx, iter_index=yineleme, decompiled_dir=out, reconstructed_dir=tmp_path / "rec",
            incremental_files=None, extracted_names=adlar, naming_result=sonuc,
            bindiff_confidence_map=bd, refdiff_naming={}, fid_json=tmp_path / "fid.json",
            computation_result=None, pcode_naming_candidates=[], stats=stats, errors=[],
            artifacts={}, functions_json=ws["functions"])
        assert harita[ELLE_ANAHTAR] == ELLE_AD


def test_birlestirmeden_sonra_elle_ad_zorlanir(tmp_path) -> None:
    kunye = {"FUN_00007000": baglama.make_meta(baglama.KIND_MANUAL, "analist_adi"),
             "FUN_00008000": baglama.make_meta(baglama.KIND_MANUAL, "int")}
    harita = {"FUN_00007000": "baska_ad"}
    zorlanan, reddedilen = FM.force_manual_names(harita, FM.manual_names(kunye), None)
    assert harita == {"FUN_00007000": "analist_adi"}
    assert zorlanan == 1 and reddedilen == {"FUN_00008000": "invalid_c_keyword"}


def test_refdiff_de_korur(monkeypatch) -> None:
    kunye = {"FUN_1": baglama.make_meta(baglama.KIND_MAIN, "main")}
    ctx = SimpleNamespace(
        pipeline_context=SimpleNamespace(config=Config(), metadata={}),
        artifacts={"pre_name_meta": kunye})

    def sahte_eslestir(*, refdiff_naming, **_kw):
        refdiff_naming.update({"FUN_1": "ref_main", "FUN_2": "ref_iki"})

    class _Det:
        def detect_from_strings(self, _s):
            return [SimpleNamespace(library="zlib", version="1.3", confidence=0.9)]

    import karadul.reconstruction.reference_differ as rd
    monkeypatch.setattr(rd, "VersionDetector", _Det)
    monkeypatch.setattr(FR, "_match_against_db", sahte_eslestir)
    monkeypatch.setattr(FR, "reference_download_allowed", lambda _c: True, raising=False)
    adlar = {"FUN_1": "main"}
    stats: dict = {}
    FR.run_reference_differ(
        ctx=ctx, iter_index=0, func_data={"functions": []}, string_data={"strings": [1]},
        functions_json=Path("/yok"), strings_json=Path("/yok"), call_graph_json=Path("/yok"),
        cfg_json=Path("/yok"), refdiff_naming={}, extracted_names=adlar, stats=stats, errors=[])
    assert adlar == {"FUN_1": "main", "FUN_2": "ref_iki"}
    assert stats["refdiff_protected_pre_names"] == 1
