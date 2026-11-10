"""İkinci tur tam kipte koşunca isimlendirici çıktısının silinmesi (2026-11-10).

Kök neden: run_naming_phase, isimlendirici yazdıktan SONRA _compute_namer_output'u bir kez daha
çağırıyordu; o fonksiyon iter > 0'da dizini silip yeniden kurar. Sonuç: src_iter1 boş kalıyor,
sonraki bütün adımlar (tip, yorum, proje ağacı) boş dizinle çalışıyor ve temiz çıktı kaynaksız
çıkıyordu. Artımlı kipte yönlendirme yapılmadığı için hata yalnız tam kipte (küçük ikililer)
görülüyordu: tests/fixtures/varname_bench/build/hashbench_O2.
"""
from __future__ import annotations

import pytest


def test_namer_output_path_diske_dokunmaz(tmp_path):
    from karadul.pipeline.steps import _feedback_naming as fn
    rec = tmp_path / "reconstructed"
    eski = rec / "src_iter1"
    eski.mkdir(parents=True)
    (eski / "f.c").write_text("x", encoding="utf-8")
    assert fn._namer_output_path(rec, rec / "src", 1) == eski
    assert (eski / "f.c").read_text(encoding="utf-8") == "x"      # silinmedi
    assert fn._namer_output_path(rec, rec / "src", 0) == rec / "src"
    assert not (rec / "src").exists()                              # oluşturulmadı
    assert fn._namer_output_path(rec, rec / "src", 2) == rec / "src_iter2"


def test_compute_namer_output_yol_hesabiyla_ayni_yeri_verir(tmp_path):
    from karadul.pipeline.steps import _feedback_naming as fn
    rec = tmp_path / "reconstructed"
    for i in (0, 1, 3):
        assert fn._compute_namer_output(rec, rec / "src", i) == fn._namer_output_path(rec, rec / "src", i)


@pytest.mark.parametrize("iter_index", [1, 2])
def test_tam_kipte_sonraki_tur_isimlendirici_ciktisi_silinmez(tmp_path, monkeypatch, iter_index):
    """iter > 0 ve artımlı küme yokken (tam kip) çıktı dizini dolu kalmalı."""
    from types import SimpleNamespace

    from karadul.pipeline.steps import _feedback_naming as fn

    rec = tmp_path / "reconstructed"
    girdi = rec / "typed"
    girdi.mkdir(parents=True)
    adlar = ["FUN_00001000.c", "FUN_00001040.c", "main.c"]
    for ad in adlar:
        (girdi / ad).write_text(f"void {ad[:-2]}(void) {{}}\n", encoding="utf-8")

    def sahte_namer(**kw):
        # Gerçek _run_c_namer gibi: önce çıktı dizinini hazırlar, sonra yazar.
        hedef = fn._compute_namer_output(kw["reconstructed_dir"], kw["output_dir"], kw["iter_index"])
        yazilan = []
        for cf in sorted(kw["decompiled_dir"].glob("*.c")):
            (hedef / cf.name).write_text(cf.read_text(encoding="utf-8"), encoding="utf-8")
            yazilan.append(hedef / cf.name)
        return SimpleNamespace(success=True, output_files=yazilan, errors=[])

    def sahte_merger(**kw):
        return {}, set(), kw["decompiled_dir"]

    monkeypatch.setattr(fn, "_run_c_namer", sahte_namer)
    monkeypatch.setattr(fn, "run_name_merger", sahte_merger)

    sonuc = fn.run_naming_phase(
        ctx=SimpleNamespace(), iter_index=iter_index, decompiled_dir=girdi,
        reconstructed_dir=rec, output_dir=rec / "src", incremental_files=None,
        rglob_c_files=sorted(girdi.glob("*.c")), c_namer=object(),
        functions_json=tmp_path / "f.json", strings_json=tmp_path / "s.json",
        call_graph_json=tmp_path / "cg.json", xrefs_json=tmp_path / "x.json",
        fid_json=tmp_path / "fid.json", cfg_json=tmp_path / "cfg.json",
        extracted_names={}, func_data=None, string_data=None, sig_matches=None,
        algo_result=None, eng_result=None, pcode_naming_candidates=[],
        computation_result=None, bindiff_confidence_map={}, stats={}, errors=[],
        artifacts={}, func_count=len(adlar),
    )
    assert sonuc.decompiled_dir == rec / f"src_iter{iter_index}"
    assert sorted(p.name for p in sonuc.decompiled_dir.glob("*.c")) == sorted(adlar)


def test_artimli_kipte_girdi_dizini_degismez(tmp_path, monkeypatch):
    """Artımlı kipte isimlendirici yalnız alt kümeyi yazar; yönlendirme yapılmaz."""
    from types import SimpleNamespace

    from karadul.pipeline.steps import _feedback_naming as fn

    rec = tmp_path / "reconstructed"
    girdi = rec / "typed"
    girdi.mkdir(parents=True)
    (girdi / "a.c").write_text("a", encoding="utf-8")
    (girdi / "b.c").write_text("b", encoding="utf-8")

    def sahte_namer(**kw):
        hedef = fn._compute_namer_output(kw["reconstructed_dir"], kw["output_dir"], kw["iter_index"])
        (hedef / "a.c").write_text("a", encoding="utf-8")
        return SimpleNamespace(success=True, output_files=[hedef / "a.c"], errors=[])

    monkeypatch.setattr(fn, "_run_c_namer", sahte_namer)
    monkeypatch.setattr(fn, "run_name_merger", lambda **kw: ({}, set(), kw["decompiled_dir"]))

    sonuc = fn.run_naming_phase(
        ctx=SimpleNamespace(), iter_index=1, decompiled_dir=girdi,
        reconstructed_dir=rec, output_dir=rec / "src", incremental_files=[girdi / "a.c"],
        rglob_c_files=sorted(girdi.glob("*.c")), c_namer=object(),
        functions_json=tmp_path / "f.json", strings_json=tmp_path / "s.json",
        call_graph_json=tmp_path / "cg.json", xrefs_json=tmp_path / "x.json",
        fid_json=tmp_path / "fid.json", cfg_json=tmp_path / "cfg.json",
        extracted_names={}, func_data=None, string_data=None, sig_matches=None,
        algo_result=None, eng_result=None, pcode_naming_candidates=[],
        computation_result=None, bindiff_confidence_map={}, stats={}, errors=[],
        artifacts={}, func_count=2,
    )
    assert sonuc.decompiled_dir == girdi
    assert sorted(p.name for p in girdi.glob("*.c")) == ["a.c", "b.c"]
