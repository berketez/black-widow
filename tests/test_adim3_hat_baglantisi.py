"""Adlandırma hattının bayraklara bağlanması (plan v2.2 N1 adım 3, 6. commit).

Kilitlenen davranışlar (tasarım §2.3, §4.3, §4.4, §5.4 satır 6):
  - bayraklar kapalıyken c_namer öntanımlı kurulur ve hattın çıktısı (``naming_map.json`` ve
    ``.c`` dosyaları) değişiklik öncesiyle bayt bayt aynıdır;
  - susturma ve ürün eşiği c_namer kurucusuna bayraklara göre verilir; susan küme ürün
    modülünün sabitidir, eşik ``min_naming_confidence``'tır;
  - ön ad künyesi Faz 2 tohumundan (``ctx.artifacts["pre_name_meta"]``) c_namer'a ulaşır;
    künye yoksa c_namer bugünkü çağrıyla çalışır;
  - ``naming_flags``, ``naming_by_label`` ve ``naming_silenced`` istatistiklere gerçek sayılarla
    yazılır;
  - NameMerger çıktısına aynı ürün eşiği uygulanır (yalnız bayrak açıkken, yalnız genel anahtar).

Mutasyon koruması: ``scripts/measurement/mutation_specs_adim3_hat.json``.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_c_namer_determinism as T  # noqa: E402
from test_c_namer_susturma import DIZGI_ADLI, ONCEKI_CIKTI_OZETI, _ozet  # noqa: E402

from karadul.config import Config  # noqa: E402
from karadul.core import naming_labels as nl  # noqa: E402
from karadul.pipeline.context import StepContext  # noqa: E402
from karadul.pipeline.steps import _feedback_naming as FN  # noqa: E402
from karadul.pipeline.steps import _feedback_naming_merger as FM  # noqa: E402
from karadul.pipeline.steps import feedback_loop as FL  # noqa: E402
from karadul.reconstruction import c_namer  # noqa: E402
from karadul.reconstruction.tarif import alt_kanal, baglama  # noqa: E402

BAYRAKLAR = ("enable_ks1_anchors", "enable_subchannel_silencing", "apply_global_naming_threshold")


@pytest.fixture
def seri(monkeypatch):
    monkeypatch.setattr(c_namer, "ProcessPoolExecutor", T._SerialExecutor)
    monkeypatch.setattr(c_namer, "_worker_namer", None)


def _config(**bayraklar) -> Config:
    """Üç adlandırma bayrağı açıkça kapalı başlar (öntanımlıya bağlı değil: "aç" commit'i
    öntanımlıları çevirince bu sınamalar anlamını korur); verilenler üstüne yazılır."""
    cfg = Config()
    cfg.computation_recovery.enabled = False
    cfg.binary_reconstruction.enable_type_recovery = False
    for ad, deger in {**dict.fromkeys(BAYRAKLAR, False), **bayraklar}.items():
        assert hasattr(cfg.binary_reconstruction, ad), ad
        setattr(cfg.binary_reconstruction, ad, deger)
    return cfg


def _pc(**bayraklar) -> SimpleNamespace:
    return SimpleNamespace(config=_config(**bayraklar), metadata={})


def _adlandir(tmp_path: Path, pc, *, pre_names=None, kunye=None, namer=None):
    """Hattın c_namer adımını gerçek c_namer'la koştur: ``_pre_instantiate`` + ``_run_c_namer``."""
    ws = T.build_workspace(tmp_path / "ws")
    out = tmp_path / "out"
    ctx = StepContext(pipeline_context=pc)
    if kunye is not None:
        ctx._write_artifacts({"pre_name_meta": kunye})
    if namer is None:
        _, namer, _ = FL.FeedbackLoopStep._pre_instantiate(pc)
    stats: dict = {}
    errors: list[str] = []
    sonuc = FN._run_c_namer(
        ctx=ctx, iter_index=0, decompiled_dir=ws["decompiled"],
        reconstructed_dir=tmp_path / "rec", output_dir=out, incremental_files=None,
        rglob_c_files=[], c_namer=namer, functions_json=ws["functions"],
        strings_json=ws["strings"], call_graph_json=ws["call_graph"],
        xrefs_json=tmp_path / "yok.json", extracted_names=dict(pre_names or {}),
        stats=stats, errors=errors, artifacts={}, func_count=len(T._FUNCS),
    )
    assert errors == []
    return SimpleNamespace(sonuc=sonuc, stats=stats, out=out, namer=namer)


def _harita(out: Path) -> dict:
    return json.loads((out / "naming_map.json").read_text(encoding="utf-8"))


def _koken(out: Path) -> dict:
    return json.loads((out / c_namer.NAMING_PROVENANCE_FILE).read_text(encoding="utf-8"))


# --------------------------------------------------------------------------------------------
# Bayrak okuma


def test_ontanimli_bayraklar_acik():
    """Öntanımlılar "aç" commit'inden (9.) beri açıktır: c_namer susturma ve ürün eşiğiyle kurulur."""
    from karadul.reconstruction.tarif import alt_kanal
    br = Config().binary_reconstruction
    assert [getattr(br, b) for b in BAYRAKLAR] == [True, True, True]
    assert FL.c_namer_options(br) == {
        "silenced_subchannels": alt_kanal.SILENCED_SUBCHANNELS,
        "global_min_confidence": 0.7,
    }
    assert FM.global_naming_threshold(br) == 0.7


@pytest.mark.parametrize("deger", [None, 0, 1, "true", MagicMock()])
def test_bayrak_yalniz_gercek_true_ile_acilir(deger):
    br = SimpleNamespace(enable_subchannel_silencing=deger, apply_global_naming_threshold=deger,
                         min_naming_confidence=0.7)
    assert FM.config_flag(br, "enable_subchannel_silencing") is False
    assert FL.c_namer_options(br) == {}
    assert FM.config_flag(SimpleNamespace(), "enable_subchannel_silencing") is False   # öznitelik yok
    assert FM.config_flag(SimpleNamespace(x=True), "x") is True


def test_sahte_yapilandirma_c_nameri_degistirmez():
    """MagicMock yapılandırma (var olan testlerin çoğu) bayrakları açmış sayılmaz."""
    assert FL.c_namer_options(MagicMock()) == {}
    assert FL.c_namer_options(None) == {}
    bayraklar = FL.naming_flags(MagicMock())
    assert (bayraklar["ks1"], bayraklar["silencing"], bayraklar["global_threshold"]) == (
        False, False, None)


def test_c_namer_secenekleri_bayraklara_gore():
    assert FL.c_namer_options(_config(enable_subchannel_silencing=True).binary_reconstruction) == {
        "silenced_subchannels": alt_kanal.SILENCED_SUBCHANNELS}
    assert FL.c_namer_options(
        _config(apply_global_naming_threshold=True).binary_reconstruction) == {
        "global_min_confidence": 0.7}
    ikisi = _config(enable_subchannel_silencing=True, apply_global_naming_threshold=True,
                    min_naming_confidence=0.55).binary_reconstruction
    assert FL.c_namer_options(ikisi) == {"silenced_subchannels": alt_kanal.SILENCED_SUBCHANNELS,
                                         "global_min_confidence": 0.55}
    # KS-1 bayrağı c_namer kurucusunu etkilemez (KS-1 ön ad kanalından girer)
    assert FL.c_namer_options(_config(enable_ks1_anchors=True).binary_reconstruction) == {}


@pytest.mark.parametrize("deger, beklenen", [
    (0.7, 0.7), (0.5, 0.5), (1, 1.0), (0.0, 0.0), (None, None), ("0.7", None), (True, None)])
def test_urun_esigi_degeri(deger, beklenen):
    br = SimpleNamespace(apply_global_naming_threshold=True, min_naming_confidence=deger)
    assert FM.global_naming_threshold(br) == beklenen
    if beklenen is not None:
        assert isinstance(FM.global_naming_threshold(br), float)
    br.apply_global_naming_threshold = False
    assert FM.global_naming_threshold(br) is None
    assert FM.global_naming_threshold(SimpleNamespace(apply_global_naming_threshold=True)) is None


def test_kol_kimligi():
    kapali = FL.naming_flags(_config().binary_reconstruction)
    assert kapali == {"ks1": False, "silencing": False, "global_threshold": None,
                      "ks1_row_status": dict(baglama.ROW_STATUS),
                      "definition_version": alt_kanal.DEFINITION_VERSION}
    assert set(kapali["ks1_row_status"]) == set(baglama.DECISION_ROWS)
    json.dumps(kapali)   # rapora yazılabilir
    assert kapali["ks1_row_status"] is not baglama.ROW_STATUS   # kopya; ürün tablosu değişmez
    acik = FL.naming_flags(_config(**dict.fromkeys(BAYRAKLAR, True)).binary_reconstruction)
    assert (acik["ks1"], acik["silencing"], acik["global_threshold"]) == (True, True, 0.7)
    for bayrak, alan in zip(BAYRAKLAR, ("ks1", "silencing", "global_threshold")):
        tek = FL.naming_flags(_config(**{bayrak: True}).binary_reconstruction)
        acik_alanlar = {a for a in ("ks1", "silencing", "global_threshold") if tek[a]}
        assert acik_alanlar == {alan}, bayrak


# --------------------------------------------------------------------------------------------
# c_namer bayraklara göre kurulur


def test_on_kurulum_bayraklar_kapaliyken_ontanimli():
    _, namer, _ = FL.FeedbackLoopStep._pre_instantiate(_pc())
    assert isinstance(namer, c_namer.CVariableNamer)
    assert namer._silenced_subchannels == frozenset() and namer._global_min_confidence is None
    assert namer._min_confidence == 0.15


def test_on_kurulum_bayraklar_acikken():
    _, namer, _ = FL.FeedbackLoopStep._pre_instantiate(
        _pc(enable_subchannel_silencing=True, apply_global_naming_threshold=True))
    assert namer._silenced_subchannels == alt_kanal.SILENCED_SUBCHANNELS
    assert namer._global_min_confidence == 0.7
    assert namer._min_confidence == 0.15            # yerel adların eşiği değişmez
    _, yalniz_esik, _ = FL.FeedbackLoopStep._pre_instantiate(
        _pc(apply_global_naming_threshold=True))
    assert yalniz_esik._silenced_subchannels == frozenset()
    assert yalniz_esik._global_min_confidence == 0.7


def test_c_naming_kapaliysa_c_namer_kurulmaz():
    _, namer, _ = FL.FeedbackLoopStep._pre_instantiate(
        _pc(enable_c_naming=False, enable_subchannel_silencing=True))
    assert namer is None


# --------------------------------------------------------------------------------------------
# Hat: c_namer adımı


def test_bayraklar_kapaliyken_hat_ciktisi_bayt_bayt_ayni(tmp_path, seri):
    """Regresyon kilidi: bayraklar kapalıyken ad haritası ve .c dosyaları değişiklik öncesiyle aynı."""
    k = _adlandir(tmp_path, _pc())
    assert k.sonuc.success
    assert _ozet(k.out) == ONCEKI_CIKTI_OZETI
    harita = _harita(k.out)
    assert k.stats["naming_by_label"] == {nl.LABEL_UNVERIFIED: len(harita["global"])}
    assert k.stats["naming_silenced"] == {}
    assert k.stats["naming_by_strategy"]["string_context"] == len(DIZGI_ADLI)
    koken = _koken(k.out)
    assert koken["silencing"]["enabled"] is False and koken["global_min_confidence"] is None


def test_susturma_bayragi_hatta_etkili(tmp_path, seri):
    k = _adlandir(tmp_path, _pc(enable_subchannel_silencing=True))
    harita = _harita(k.out)["global"]
    assert not set(DIZGI_ADLI) & set(harita)
    assert k.stats["naming_silenced"] == {"duz_metin": len(DIZGI_ADLI)}
    assert "string_context" not in k.stats["naming_by_strategy"]
    assert k.stats["naming_by_label"] == {nl.LABEL_UNVERIFIED: len(harita)}
    assert any(a.startswith("DAT_") for a in harita)          # eşik kapalı: veri adları duruyor
    assert _koken(k.out)["silencing"]["silenced"] == sorted(alt_kanal.SILENCED_SUBCHANNELS)


def test_esik_bayragi_hatta_etkili(tmp_path, seri):
    taban = _adlandir(tmp_path / "taban", _pc())
    k = _adlandir(tmp_path / "esik", _pc(apply_global_naming_threshold=True))
    once, sonra = _harita(taban.out), _harita(k.out)
    dusen = set(once["global"]) - set(sonra["global"])
    # düşenler tam olarak tabanda güveni 0,7'nin altında olan genel adlardır
    guven = {a: k_["confidence"] for a, k_ in _koken(taban.out)["global"].items()}
    assert dusen == {a for a in once["global"] if guven[a] < 0.7}
    assert {a for a in dusen if a.startswith("DAT_")} and "FUN_00007000" in dusen
    assert not any(a.startswith("DAT_") for a in sonra["global"])   # 0,30 güvenli global_<4 hane>
    assert set(DIZGI_ADLI) <= set(sonra["global"])              # 0,7 üstü fonksiyon adları duruyor
    assert sonra["per_function"] == once["per_function"]        # yerel adlar etkilenmez
    assert _koken(k.out)["global_min_confidence"] == 0.7
    assert k.stats["naming_silenced"] == {}
    assert k.stats["naming_by_label"] == {nl.LABEL_UNVERIFIED: len(sonra["global"])}


def test_esik_degeri_yapilandirmadan(tmp_path, seri):
    """Eşik sabit 0,7 değil, ``min_naming_confidence``: 0,2 ile 0,30 güvenli veri adları kalır."""
    k = _adlandir(tmp_path, _pc(apply_global_naming_threshold=True, min_naming_confidence=0.2))
    assert any(a.startswith("DAT_") for a in _harita(k.out)["global"])
    assert _koken(k.out)["global_min_confidence"] == 0.2


def _ks1_kunyesi(ad: str, etiket: str = nl.LABEL_CERTAIN) -> dict:
    return {"kind": baglama.KIND_KS1, "name": ad, "exact": True, "label": etiket,
            "ks1": {"adres": "5000", "turler": ["func_kalibi"], "rol": "kendi",
                    "satirlar": ["func_kalibi"], "kanitlar": []}}


def test_kunye_faz2_tohumundan_c_namera_ulasir(tmp_path, seri):
    on_adlar = {"FUN_00005000": "Vector_add", "FUN_00006000": "Eski_ad"}
    kunye = {"FUN_00005000": _ks1_kunyesi("Vector_add")}
    k = _adlandir(tmp_path / "kunyeli", _pc(), pre_names=on_adlar, kunye=kunye)
    harita = _harita(k.out)["global"]
    assert harita["FUN_00005000"] == "Vector_add"        # tam ad: temizlenmedi
    assert harita["FUN_00006000"] == "eski_ad"           # künyesiz ön ad bugünkü gibi
    kayit = _koken(k.out)["global"]["FUN_00005000"]
    assert kayit["strategy"] == "ks1" and kayit["label"] == nl.LABEL_CERTAIN
    assert kayit["pre_name_kind"] == "ks1" and kayit["ks1"]["satirlar"] == ["func_kalibi"]
    assert k.stats["naming_by_label"][nl.LABEL_CERTAIN] == 1
    assert k.stats["naming_by_label"][nl.LABEL_UNVERIFIED] == len(harita) - 1
    assert k.stats["naming_by_strategy"]["ks1"] == 1

    # aynı ön adlar, künye tohumda yok: KS-1 adı sıradan ön ad gibi işlenir
    k2 = _adlandir(tmp_path / "kunyesiz", _pc(), pre_names=on_adlar)
    assert _harita(k2.out)["global"]["FUN_00005000"] == "vector_add"
    assert nl.LABEL_CERTAIN not in k2.stats["naming_by_label"]
    assert "ks1" not in k2.stats["naming_by_strategy"]


class _KatiNamer:
    """Künye parametresini tanımayan (adım 3 öncesi imzalı) c_namer vekili."""

    def __init__(self) -> None:
        self.cagrilar: list[dict] = []

    def analyze_and_rename(self, decompiled_dir, functions_json, strings_json, call_graph_json,
                           output_dir, pre_names=None, xrefs_json=None):
        self.cagrilar.append({"pre_names": pre_names, "xrefs_json": xrefs_json})
        return SimpleNamespace(success=True, total_renamed=0, by_strategy={}, high_confidence=0,
                               errors=[], output_files=[])


class _KayitNamer(_KatiNamer):
    def analyze_and_rename(self, *a, **kw):   # type: ignore[override]
        self.cagrilar.append(kw)
        return SimpleNamespace(success=True, total_renamed=0, by_strategy={}, high_confidence=0,
                               errors=[], output_files=[])


def test_kunye_yokken_c_namer_bugunku_cagriyla(tmp_path):
    namer = _KatiNamer()
    k = _adlandir(tmp_path, _pc(), pre_names={"FUN_00005000": "a"}, namer=namer)
    assert namer.cagrilar == [{"pre_names": {"FUN_00005000": "a"}, "xrefs_json": None}]
    # sonuç etiket ve susturma alanı taşımıyorsa istatistik uydurulmaz
    assert "naming_by_label" not in k.stats and "naming_silenced" not in k.stats
    assert k.stats["variables_renamed"] == 0


@pytest.mark.parametrize("yapit", [["FUN_1"], "kunye", 0, MagicMock()])
def test_sozluk_olmayan_kunye_gecirilmez(tmp_path, yapit):
    namer = _KatiNamer()
    _adlandir(tmp_path, _pc(), kunye=yapit, namer=namer)
    assert len(namer.cagrilar) == 1        # TypeError yok: pre_name_meta verilmedi


def test_kunye_varken_anahtar_sozcukle_gecer(tmp_path):
    namer = _KayitNamer()
    kunye = {"FUN_00005000": _ks1_kunyesi("a")}
    _adlandir(tmp_path, _pc(), pre_names={"FUN_00005000": "a"}, kunye=kunye, namer=namer)
    assert namer.cagrilar[0]["pre_name_meta"] is kunye
    bos = _KayitNamer()
    _adlandir(tmp_path / "bos", _pc(), kunye={}, namer=bos)
    assert bos.cagrilar[0]["pre_name_meta"] == {}       # boş künye de künyedir


def test_kunye_okuyucu_baglamsiz_calisir():
    assert FN._pre_name_meta(SimpleNamespace()) is None
    assert FN._pre_name_meta(SimpleNamespace(artifacts=None)) is None
    assert FN._pre_name_meta(SimpleNamespace(artifacts={"pre_name_meta": {"a": {}}})) == {"a": {}}

    class Patlayan:
        def get(self, _):
            raise RuntimeError("okunamaz")

    assert FN._pre_name_meta(SimpleNamespace(artifacts=Patlayan())) is None


def test_etiket_sayaclari_gercek_sayilardan():
    stats: dict = {}
    FN._record_label_stats(SimpleNamespace(
        label_map={"FUN_1": "kesin", "FUN_2": "doğrulanmadı", "DAT_1": "doğrulanmadı"},
        silenced_counts={"agresif": 3}), stats)
    assert stats == {"naming_by_label": {"doğrulanmadı": 2, "kesin": 1},
                     "naming_silenced": {"agresif": 3}}
    assert list(stats["naming_by_label"]) == ["doğrulanmadı", "kesin"]    # sıralı: belirlenimci
    bos: dict = {}
    FN._record_label_stats(SimpleNamespace(label_map={}, silenced_counts={}), bos)
    assert bos == {"naming_by_label": {}, "naming_silenced": {}}
    sahte: dict = {}
    FN._record_label_stats(MagicMock(), sahte)       # sözlük olmayan alan yazılmaz
    assert sahte == {}


def test_reddedilen_ad_sayaci_rapora_yazilir():
    """Ad geçerliliği süzgecinin sayaçları (neden → adet) stats'a taşınır; alan yoksa yazılmaz."""
    stats: dict = {}
    reddedilen = {"collides_with_existing_function": 4, "invalid_c_keyword": 1}
    FN._record_label_stats(SimpleNamespace(label_map={}, silenced_counts={},
                                           rejected_name_counts=reddedilen), stats)
    assert stats["naming_rejected"] == reddedilen
    assert stats["naming_rejected"] is not reddedilen          # kopya; sonuç nesnesi değişmez
    eski: dict = {}
    FN._record_label_stats(SimpleNamespace(label_map={}, silenced_counts={}), eski)
    assert "naming_rejected" not in eski
    bos: dict = {}
    FN._record_label_stats(SimpleNamespace(label_map={}, silenced_counts={}, rejected_name_counts={}), bos)
    assert bos["naming_rejected"] == {}


# --------------------------------------------------------------------------------------------
# FeedbackLoopStep: kol kimliği istatistiklerde


def _dongu_baglami(tmp_path: Path, **bayraklar) -> StepContext:
    cfg = _config(enable_c_naming=False, enable_struct_recovery=False, pipeline_iterations=1,
                  **bayraklar)
    pc = MagicMock()
    pc.config = cfg
    pc.workspace.get_stage_dir = MagicMock(return_value=tmp_path / "reconstructed")
    (tmp_path / "reconstructed").mkdir(parents=True)
    pc.metadata = {}
    pc.target.file_hash = "abc" * 22
    pc.target.target_type = None
    dec = tmp_path / "decompiled"
    dec.mkdir()
    (dec / "FUN_1.c").write_text("int a(void){return 1;}", encoding="utf-8")
    (tmp_path / "src_out").mkdir()
    ctx = StepContext(pipeline_context=pc)
    ctx._write_artifacts({
        "c_files": [dec / "FUN_1.c"], "file_cache": {}, "decompiled_dir": dec,
        "output_dir": tmp_path / "src_out",
        **{f"{ad}_json_path": tmp_path / f"{ad}.json" for ad in (
            "functions", "strings", "call_graph", "ghidra_types", "xrefs", "cfg", "fid",
            "decompiled")},
        "functions_data": None, "strings_data": None, "call_graph_data": {},
        "sig_matches": None, "algo_result_filtered": None, "eng_result_filtered": None,
        "extracted_names": {}, "pcode_naming_candidates": [],
    })
    return ctx


def test_dongu_kol_kimligini_istatistiklere_yazar(tmp_path):
    ctx = _dongu_baglami(tmp_path / "kapali")
    FL.FeedbackLoopStep().run(ctx)
    assert ctx.stats["naming_flags"] == FL.naming_flags(_config().binary_reconstruction)
    assert ctx.stats["naming_flags"]["ks1"] is False

    ctx = _dongu_baglami(tmp_path / "acik", **dict.fromkeys(BAYRAKLAR, True))
    FL.FeedbackLoopStep().run(ctx)
    bayraklar = ctx.stats["naming_flags"]
    assert (bayraklar["ks1"], bayraklar["silencing"], bayraklar["global_threshold"]) == (
        True, True, 0.7)
    assert bayraklar["definition_version"] == alt_kanal.DEFINITION_VERSION
    assert bayraklar["ks1_row_status"] == dict(baglama.ROW_STATUS)


def _faz2_kos(tmp_path: Path, *, tohum_eki: dict, **bayraklar):
    """Faz 2'yi gerçek koşucu, gerçek adım ve gerçek c_namer ile koştur (tek yineleme)."""
    from karadul.pipeline.runner import PipelineRunner

    ws = T.build_workspace(tmp_path / "ws")
    rec = tmp_path / "reconstructed"
    rec.mkdir()
    out = rec / "src"
    out.mkdir()
    pc = MagicMock()
    pc.config = _config(pipeline_iterations=1, enable_struct_recovery=False, **bayraklar)
    pc.workspace.get_stage_dir = MagicMock(return_value=rec)
    pc.metadata = {}
    pc.target.file_hash = "abc" * 22
    pc.target.target_type = None
    c_files = sorted(ws["decompiled"].glob("*.c"))
    tohum = {
        "c_files": c_files, "file_cache": {}, "decompiled_dir": ws["decompiled"],
        "output_dir": out, "functions_json_path": ws["functions"],
        "strings_json_path": ws["strings"], "call_graph_json_path": ws["call_graph"],
        **{f"{ad}_json_path": tmp_path / f"yok_{ad}.json" for ad in (
            "ghidra_types", "xrefs", "cfg", "fid", "decompiled")},
        "functions_data": None, "strings_data": None, "call_graph_data": {},
        "sig_matches": None, "algo_result_filtered": None, "eng_result_filtered": None,
        "pcode_naming_candidates": [], **tohum_eki,
    }
    sonuc = PipelineRunner(steps=["feedback_loop"]).run(pc, seed_artifacts=tohum)
    return SimpleNamespace(stats=sonuc.stats, errors=sonuc.errors, out=out)


def test_kunye_gercek_kosucuyla_faz2den_ad_haritasina(tmp_path, seri):
    """Uçtan uca: Faz 2 tohumundaki künye → koşucu → döngü → c_namer → ``naming_map.json``."""
    on_adlar = {"FUN_00005000": "Vector_add", "FUN_00006000": "Eski_ad"}
    k = _faz2_kos(tmp_path / "kunyeli", tohum_eki={
        "extracted_names": dict(on_adlar),
        "pre_name_meta": {"FUN_00005000": _ks1_kunyesi("Vector_add")}})
    assert k.errors == []
    harita = _harita(k.out)["global"]
    assert harita["FUN_00005000"] == "Vector_add" and harita["FUN_00006000"] == "eski_ad"
    assert _koken(k.out)["global"]["FUN_00005000"]["strategy"] == "ks1"
    assert k.stats["naming_by_label"][nl.LABEL_CERTAIN] == 1
    assert k.stats["naming_flags"]["ks1"] is False        # künye bayraktan bağımsız taşınır

    # künye tohumda yoksa (KS-1 kapalı): aynı ön adlar bugünkü gibi işlenir
    k2 = _faz2_kos(tmp_path / "kunyesiz", tohum_eki={"extracted_names": dict(on_adlar)})
    assert k2.errors == []
    assert _harita(k2.out)["global"]["FUN_00005000"] == "vector_add"
    assert nl.LABEL_CERTAIN not in k2.stats["naming_by_label"]


def test_gercek_kosucuyla_bayraklar_kapaliyken_cikti_bayt_bayt_ayni(tmp_path, seri):
    """Faz 2 adımının tamamı (c_namer + birleştirici) bayraklar kapalıyken ``src/``'yi değiştirmez;
    bayraklar açıkken susturma ve eşik aynı koşuda etkilidir."""
    k = _faz2_kos(tmp_path / "kapali", tohum_eki={"extracted_names": {}})
    assert k.errors == []
    assert _ozet(k.out) == ONCEKI_CIKTI_OZETI
    assert k.stats["naming_silenced"] == {} and "name_merger_below_global_min" not in k.stats

    acik = _faz2_kos(tmp_path / "acik", tohum_eki={"extracted_names": {}},
                     enable_subchannel_silencing=True, apply_global_naming_threshold=True)
    assert acik.errors == []
    harita = _harita(acik.out)["global"]
    assert not set(DIZGI_ADLI) & set(harita) and not any(a.startswith("DAT_") for a in harita)
    assert acik.stats["naming_silenced"] == {"duz_metin": len(DIZGI_ADLI)}
    assert acik.stats["naming_flags"]["silencing"] is True
    assert acik.stats["naming_flags"]["global_threshold"] == 0.7
    assert acik.stats["name_merger_below_global_min"] == 0


# --------------------------------------------------------------------------------------------
# NameMerger: ürün eşiği


def _birlesik(**guvenler: float) -> dict:
    return {k: SimpleNamespace(final_confidence=v) for k, v in guvenler.items()}


def test_esik_yokken_harita_aynen_doner():
    harita = {"FUN_1": "a", "DAT_1": "b"}
    sonuc, dusen = FM.drop_below_threshold(harita, _birlesik(FUN_1=0.31, DAT_1=0.30), None)
    assert sonuc is harita and dusen == 0


def test_esik_genel_anahtarlari_dusurur():
    harita = {"FUN_1": "alt", "FUN_2": "sinir", "FUN_3": "ust", "DAT_1": "veri",
              "f::local_8": "yerel", "FUN_4": "bilinmeyen"}
    birlesik = _birlesik(FUN_1=0.69, FUN_2=0.7, FUN_3=0.95, DAT_1=0.30)
    birlesik["f::local_8"] = SimpleNamespace(final_confidence=0.2)
    sonuc, dusen = FM.drop_below_threshold(harita, birlesik, 0.7)
    # eşiğe eşit güven geçer (c_namer'daki ``<`` ile aynı); yerel anahtar etkilenmez;
    # güveni okunamayan giriş düşürülmez
    assert sonuc == {"FUN_2": "sinir", "FUN_3": "ust", "f::local_8": "yerel", "FUN_4": "bilinmeyen"}
    assert dusen == 2
    assert list(sonuc) == ["FUN_2", "FUN_3", "f::local_8", "FUN_4"]    # sıra korunur
    assert harita["FUN_1"] == "alt"                                    # girdi değişmedi


def _birlestir(tmp_path: Path, **bayraklar):
    """``run_name_merger``'ı gerçek NameMerger ile koştur: biri eşik altı, biri üstü iki c_namer adı."""
    dec = tmp_path / "dec"
    dec.mkdir(parents=True)
    (dec / "a.c").write_text("void FUN_00001000(void){ FUN_00002000(); }\n", encoding="utf-8")
    rec = tmp_path / "rec"
    rec.mkdir()
    adlandirma = SimpleNamespace(
        naming_map={"FUN_00001000": "dusuk_guvenli_ad", "FUN_00002000": "yuksek_guvenli_ad"},
        confidence_map={"FUN_00001000": 0.5, "FUN_00002000": 0.9},
        strategy_map={"FUN_00001000": "string_context", "FUN_00002000": "string_context"})
    ctx = SimpleNamespace(pipeline_context=_pc(**bayraklar), artifacts={})
    stats: dict = {}
    errors: list[str] = []
    harita, adli, dizin = FM.run_name_merger(
        ctx=ctx, iter_index=0, decompiled_dir=dec, reconstructed_dir=rec,
        incremental_files=None, extracted_names={}, naming_result=adlandirma,
        bindiff_confidence_map={}, refdiff_naming={}, fid_json=tmp_path / "fid.json",
        computation_result=None, pcode_naming_candidates=[], stats=stats, errors=errors,
        artifacts={}, functions_json=None)
    assert errors == []
    return SimpleNamespace(harita=harita, adli=adli, stats=stats,
                           metin=(dizin / "a.c").read_text(encoding="utf-8"))


def test_name_merger_esigi_bayrak_kapaliyken_uygulanmaz(tmp_path):
    k = _birlestir(tmp_path)
    assert k.harita == {"FUN_00001000": "dusuk_guvenli_ad", "FUN_00002000": "yuksek_guvenli_ad"}
    assert "name_merger_below_global_min" not in k.stats
    assert k.stats["name_merger_total"] == 2
    assert k.metin == "void dusuk_guvenli_ad(void){ yuksek_guvenli_ad(); }\n"


def test_name_merger_esigi_bayrak_acikken(tmp_path):
    k = _birlestir(tmp_path, apply_global_naming_threshold=True)
    assert k.harita == {"FUN_00002000": "yuksek_guvenli_ad"}
    assert k.adli == {"FUN_00002000"}
    assert k.stats["name_merger_below_global_min"] == 1
    assert k.stats["name_merger_total"] == 2          # birleştiricinin kendi sayacı değişmez
    assert k.metin == "void FUN_00001000(void){ yuksek_guvenli_ad(); }\n"


def test_name_merger_esigi_dusen_yoksa_sifir_yazar(tmp_path):
    """Bayrak açıkken sayaç her zaman yazılır: 0 da ölçülmüş bir sayıdır."""
    k = _birlestir(tmp_path, apply_global_naming_threshold=True, min_naming_confidence=0.4)
    assert set(k.harita) == {"FUN_00001000", "FUN_00002000"}
    assert k.stats["name_merger_below_global_min"] == 0
