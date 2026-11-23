"""P13a / AD-04 + AD-05: NameMerger aynı kanıtı iki kaynak saymaz, c_namer'ın süzgecini atlamaz.

- AD-04: ön ad hem ``binary_extractor`` (0,85) hem ``c_namer`` adayı olarak girip 0,99 ve sahte
  ``exact_multi`` veriyordu. c_namer koştuysa ad verdiği anahtarın kararı onundur.
- AD-05: c_namer'ın reddettiği ön ad (var olan fonksiyonla çakışma, geçersiz tanımlayıcı)
  birleştiriciden süzgeçsiz koda geri geliyordu; karar hiçbir yere kaydedilmiyordu.
- ``_add_c_namer`` güveni olmayan anahtara 0,70 uyduruyordu (P12a notu).
- Aynı mühendislik eşleşmesi sabit + formül olarak iki kaynak sayılıyordu (kulvar "Küçükler").
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from karadul.config import Config
from karadul.core.naming_labels import NAMING_PROVENANCE_FILE
from karadul.pipeline.steps import _feedback_naming_candidates as FC
from karadul.pipeline.steps import _feedback_naming_merger as FM


def _ctx(pre_name_meta=None) -> SimpleNamespace:
    cfg = Config()
    cfg.binary_reconstruction.apply_global_naming_threshold = True
    artifacts = {} if pre_name_meta is None else {"pre_name_meta": pre_name_meta}
    return SimpleNamespace(pipeline_context=SimpleNamespace(config=cfg, metadata={}),
                           artifacts=artifacts)


def _gnulib_kunyesi(extracted) -> dict:
    # P12c kalem 5: c_namer koşmadığında ön adın güveni kanalının ölçülmüş kesinliği; künyesiz
    # ön ad birleştiriciye girmez. Bu testler birleştiricinin süzgecini sınar: ölçülmüş kanal.
    return {k: {"kind": "gnulib", "name": v} for k, v in extracted.items()}


def _functions(tmp_path: Path) -> Path:
    p = tmp_path / "ghidra_functions.json"
    p.write_text(json.dumps({"functions": [
        {"name": "free", "address": "00109000", "is_thunk": True},
        {"name": "FUN_00101000", "address": "00101000"},
        {"name": "FUN_00102000", "address": "00102000"},
        {"name": "FUN_00103000", "address": "00103000"},
        {"name": "FUN_00104000", "address": "00104000"},
    ]}))
    return p


def _kos(tmp_path: Path, *, extracted, naming_result, refdiff=None, provenance=True, meta=None):
    dec = tmp_path / "src"
    dec.mkdir(parents=True)
    (dec / "a.c").write_text(
        "void FUN_00102000(void){ FUN_00103000(); FUN_00104000(); }\n", encoding="utf-8")
    if provenance:
        (dec / NAMING_PROVENANCE_FILE).write_text(json.dumps({"schema": "x", "global": {}}))
    rec = tmp_path / "rec"
    rec.mkdir()
    stats: dict = {}
    errors: list[str] = []
    harita, adli, dizin = FM.run_name_merger(
        ctx=_ctx(meta), iter_index=0, decompiled_dir=dec, reconstructed_dir=rec,
        incremental_files=None, extracted_names=dict(extracted), naming_result=naming_result,
        bindiff_confidence_map={}, refdiff_naming=dict(refdiff or {}),
        fid_json=tmp_path / "fid.json", computation_result=None, pcode_naming_candidates=[],
        stats=stats, errors=errors, artifacts={}, functions_json=_functions(tmp_path))
    assert errors == []
    metin = (dizin / "a.c").read_text(encoding="utf-8") if harita else None
    return SimpleNamespace(harita=harita, adli=adli, stats=stats, metin=metin, dec=dec, rec=rec)


def _cnamer(naming_map, confidence_map=None, strategy_map=None):
    return SimpleNamespace(success=True, naming_map=dict(naming_map),
                           confidence_map=dict(confidence_map or {}),
                           strategy_map=dict(strategy_map or {}))


def test_ad04_on_ad_iki_kaynak_sayilmaz(tmp_path) -> None:
    k = _kos(tmp_path, extracted={"FUN_00101000": "close_stdout"},
             naming_result=_cnamer({"FUN_00101000": "close_stdout"},
                                   {"FUN_00101000": 0.706}, {"FUN_00101000": "binary_extract"}))
    assert k.stats["name_merger_exact_multi"] == 0
    assert k.stats["name_merger_total"] == 0          # c_namer'ın kararı yeniden puanlanmadı
    assert k.stats["name_merger_c_namer_decided"] == 1
    assert k.harita == {"FUN_00101000": "close_stdout"}


def test_ad05_c_namerin_reddettigi_on_ad_geri_gelmez(tmp_path) -> None:
    # c_namer koştu ve iki ön adı reddetti (ithal 'free' ile çakışma; geçersiz tanımlayıcı)
    k = _kos(tmp_path, extracted={"FUN_00102000": "free", "FUN_00103000": "_$s4main3FooV"},
             naming_result=_cnamer({}))
    assert "FUN_00102000" not in (k.harita or {}) and "FUN_00103000" not in (k.harita or {})
    assert k.stats["name_merger_excluded_rejected_pre_names"] == 2


def test_ad05_c_namer_kosmadiysa_birlestirici_ad_gecerliligi_uygular(tmp_path) -> None:
    on_ad = {"FUN_00102000": "free", "FUN_00103000": "_$s4main3FooV",
             "FUN_00104000": "parse_header"}
    k = _kos(tmp_path, extracted=on_ad, naming_result=None, meta=_gnulib_kunyesi(on_ad))
    assert k.harita == {"FUN_00104000": "parse_header"}
    assert k.stats["name_merger_rejected"] == {
        "collides_with_existing_function": 1, "invalid_c_identifier": 1}
    assert k.metin == "void FUN_00102000(void){ FUN_00103000(); parse_header(); }\n"


def test_birlestiricinin_karari_koken_kaydina_yazilir(tmp_path) -> None:
    # c_namer FUN_00101000'a ad verdi; FUN_00104000'a vermedi, ReferenceDiffer önerdi
    k = _kos(tmp_path, extracted={},
             naming_result=_cnamer({"FUN_00101000": "x_ad"}, {"FUN_00101000": 0.9}),
             refdiff={"FUN_00104000": "inflate_block"})
    assert k.harita == {"FUN_00101000": "x_ad", "FUN_00104000": "inflate_block"}
    kayit = json.loads((k.dec / NAMING_PROVENANCE_FILE).read_text())["name_merger"]
    assert kayit["c_namer_decided"] == 1
    karar = kayit["decisions"]["FUN_00104000"]
    assert karar["sources"] == ["reference_differ"] and karar["applied_name"] == "inflate_block"
    assert karar["dropped"] is None
    assert "FUN_00101000" not in kayit["decisions"]
    assert k.metin == "void FUN_00102000(void){ FUN_00103000(); inflate_block(); }\n"


def test_koken_kaydi_yoksa_ayri_dosyaya_yazilir(tmp_path) -> None:
    on_ad = {"FUN_00104000": "parse_header"}
    k = _kos(tmp_path, extracted=on_ad, naming_result=None, provenance=False,
             meta=_gnulib_kunyesi(on_ad))
    kayit = json.loads((k.rec / "name_merger_provenance.json").read_text())["name_merger"]
    assert kayit["decisions"]["FUN_00104000"]["applied_name"] == "parse_header"


def test_add_c_namer_guveni_olmayan_ada_sayi_uydurmaz() -> None:
    adaylar: dict = {}
    stats: dict = {}
    FC._add_c_namer(_cnamer({"FUN_1": "a", "FUN_2": "b"}, {"FUN_2": 0.9}), adaylar, stats)
    assert list(adaylar) == ["FUN_2"] and adaylar["FUN_2"][0].confidence == 0.9
    assert stats["name_merger_c_namer_unmeasured"] == 1


def test_ayni_eslesme_formul_ve_sabit_iki_kaynak_sayilmaz() -> None:
    m = SimpleNamespace(name="FFT", function_name="FUN_5", confidence=0.6,
                        detection_method="constant")
    formul = SimpleNamespace(detected_as=["fft"], functions=["FUN_5"], algorithm="FFT")
    adaylar: dict = {}
    FC._add_engineering_constant_naming(algorithms=[m], candidates=adaylar)
    eklenen = FC._add_engineering_formula_naming(algorithms=[m], formulas=[formul],
                                                 candidates=adaylar)
    assert eklenen == 0
    assert [c.source for c in adaylar["FUN_5"]] == ["engineering_constant"]


def _kos_adaylarla(tmp_path: Path, monkeypatch, *, extracted, naming_result, ek_adaylar,
                   bindiff=None):
    """``collect_candidates``'in döndürdüğüne ek aday enjekte ederek birleştiriciyi koştur."""
    gercek = FM.collect_candidates

    def sahte(**kw):
        adaylar = gercek(**kw)
        for anahtar, liste in ek_adaylar.items():
            adaylar.setdefault(anahtar, []).extend(liste)
        return adaylar

    monkeypatch.setattr(FM, "collect_candidates", sahte)
    dec = tmp_path / "src"
    dec.mkdir(parents=True)
    (dec / "a.c").write_text("void FUN_00104000(void){}\n", encoding="utf-8")
    stats: dict = {}
    harita, _, _ = FM.run_name_merger(
        ctx=_ctx(), iter_index=0, decompiled_dir=dec, reconstructed_dir=tmp_path,
        incremental_files=None, extracted_names=dict(extracted), naming_result=naming_result,
        bindiff_confidence_map=dict(bindiff or {}), refdiff_naming={},
        fid_json=tmp_path / "fid.json", computation_result=None, pcode_naming_candidates=[],
        stats=stats, errors=[], artifacts={}, functions_json=_functions(tmp_path))
    return harita or {}, stats


def test_ad05_reddedilen_ad_baska_kaynaktan_da_donmez(tmp_path, monkeypatch) -> None:
    from karadul.reconstruction.name_merger import NamingCandidate

    # c_namer ön adı 'dup_ad'ı vermedi (aynı ad daha öncelikli ön adda); FID aynı adı öneriyor
    harita, _ = _kos_adaylarla(
        tmp_path, monkeypatch, extracted={"FUN_00104000": "dup_ad"}, naming_result=_cnamer({}),
        ek_adaylar={"FUN_00104000": [NamingCandidate("dup_ad", 0.9, "function_id")]})
    assert "FUN_00104000" not in harita


def test_ad05_reddedilen_anahtara_baska_ad_yarisir(tmp_path, monkeypatch) -> None:
    from karadul.reconstruction.name_merger import NamingCandidate

    harita, _ = _kos_adaylarla(
        tmp_path, monkeypatch, extracted={"FUN_00104000": "dup_ad"}, naming_result=_cnamer({}),
        ek_adaylar={"FUN_00104000": [NamingCandidate("inflate_fast", 0.9, "function_id")]})
    assert harita == {"FUN_00104000": "inflate_fast"}


def test_ad04_bindiff_adi_on_ad_olarak_ikinci_kez_sayilmaz(tmp_path, monkeypatch) -> None:
    # BinDiff c_namer'dan SONRA ön ad sözlüğüne yazdı; aynı eşleşme bir kez sayılır
    harita, stats = _kos_adaylarla(
        tmp_path, monkeypatch, extracted={"FUN_00104000": "ref_ad"}, naming_result=_cnamer({}),
        ek_adaylar={}, bindiff={"FUN_00104000": ("ref_ad", 0.8, "string_refs")})
    assert stats["name_merger_exact_multi"] == 0
    assert harita == {"FUN_00104000": "ref_ad"}
