"""Ön ad kanalı onarımı (2026-11-11): ELF önyük adları temizlenmeden yazılır.

Kanıt: ``docs/arge/2026-11-10_n1_adim3/kalan_kanal_dokumu.md`` §3 (geliştirme seti, keşif): ELF
önyük adlarının 226/458'i yalnız ad temizleyici (``_sanitize_c_name``: baştaki/sondaki alt
çizgiyi atar) yüzünden yanlıştı; temizlenmeden yazılsa 458/458. Sonuç belgesi:
``docs/arge/2026-11-11_on_ad_onarimi/sonuc.md``.

Kilitlenen davranışlar:
  - kurtarma tohumunun ELF önyük adı künyesinde ``exact`` taşır (tür ``elf_onyuk``);
  - c_namer bu adı olduğu gibi yazar (``_start``, ``__do_global_dtors_aux``); gnulib ve künyesiz
    ön adlar eskisi gibi temizlenir;
  - etiket yine "doğrulanmadı", strateji yine ``binary_extract`` (yalnız yazım değişti);
  - temizlenmemiş ad ikilide başka bir fonksiyonun ya da ithal bir fonksiyonun adıysa ön ad
    reddedilir (ad geçerliliği süzgeci, 93a2956): ek verilmez, anahtar aday listesine kalır;
  - anahtarın gösterdiği fonksiyonun Ghidra adı zaten bu adsa (simgeli ikili) çakışma değildir.

Mutasyon koruması: ``scripts/measurement/mutation_specs_on_ad_onarimi.json``.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_ad_gecerliligi as A  # noqa: E402
import test_c_namer_determinism as T  # noqa: E402
import test_c_namer_susturma as S  # noqa: E402

from karadul.core import naming_labels as nl  # noqa: E402
from karadul.reconstruction import c_namer  # noqa: E402
from karadul.reconstruction import name_validity as nv  # noqa: E402
from karadul.reconstruction.tarif import baglama  # noqa: E402
from karadul.stages import ReconstructionStage  # noqa: E402

ONYUK = baglama.KIND_ELF_BOILERPLATE


@pytest.fixture
def seri(monkeypatch):
    monkeypatch.setattr(c_namer, "ProcessPoolExecutor", T._SerialExecutor)
    monkeypatch.setattr(c_namer, "_worker_namer", None)


def _alan(kok: Path, *ekler: dict) -> dict[str, Path]:
    return A._calisma_alani(kok, [
        *ekler,
        A._fonk("FUN_00001000", "00001000"),
        A._fonk("FUN_00002000", "00002000"),
        A._fonk("FUN_00003000", "00003000"),
        A._fonk("FUN_00004000", "00004000"),
        A._fonk("FUN_00005000", "00005000"),
    ])


# --------------------------------------------------------------------------------------------
# Tohum: künye


def _onyuk_static(tmp_path: Path) -> Path:
    """Yalnız ELF önyük adaylarını taşıyan ``static/`` (çağrı çizgesi; decompile çıktısı yok)."""
    static_dir = tmp_path / "static"
    static_dir.mkdir(parents=True)

    def node(*callees: str) -> dict:
        return {"callees": [{"name": c} for c in callees], "callee_count": len(callees)}

    nodes = {
        "00001000": node("__libc_start_main", "abort"),        # _start şekli
        "00002000": node("__cxa_finalize", "FUN_00009000"),    # __do_global_dtors_aux şekli
        "00003000": node("_ITM_registerTMCloneTable"),         # register_tm_clones şekli
    }
    (static_dir / "call_graph.json").write_text(json.dumps({"nodes": nodes}), encoding="utf-8")
    return static_dir


def test_tohum_onyuk_kunyesi_tam_ad_der(tmp_path):
    names: dict[str, str] = {}
    meta: dict = {}
    stats: dict = {}
    context = SimpleNamespace(target=None, config=SimpleNamespace(
        binary_reconstruction=SimpleNamespace(overrides_path=str(tmp_path / "yok.json"))))
    ReconstructionStage()._seed_recovery_pre_names(
        names, _onyuk_static(tmp_path), context, stats, kesin=None, meta=meta)
    assert names == {"FUN_00001000": "_start", "FUN_00002000": "__do_global_dtors_aux",
                     "FUN_00003000": "register_tm_clones"}
    for key, name in names.items():
        assert meta[key] == {"kind": ONYUK, "name": name, "exact": True}
        assert baglama.is_exact(baglama.meta_for(meta, key, name))
    assert stats["elf_boilerplate_recovered"] == 3


# --------------------------------------------------------------------------------------------
# c_namer: yazım


def test_onyuk_adi_temizlenmeden_yazilir(tmp_path, seri):
    on = {"FUN_00001000": "_start", "FUN_00002000": "__do_global_dtors_aux",
          "FUN_00003000": "register_tm_clones", "FUN_00004000": "_gnulib__ic_",
          "FUN_00005000": "_faz1_adi"}
    meta = {"FUN_00001000": baglama.make_meta(ONYUK, "_start"),
            "FUN_00002000": baglama.make_meta(ONYUK, "__do_global_dtors_aux"),
            "FUN_00003000": baglama.make_meta(ONYUK, "register_tm_clones"),
            "FUN_00004000": baglama.make_meta(baglama.KIND_GNULIB, "_gnulib__ic_"),
            "FUN_00005000": baglama.make_meta(baglama.KIND_PHASE1, "_faz1_adi")}
    res, prov, harita = S._kos(_alan(tmp_path / "ws"), tmp_path / "out", pre_names=on, meta=meta)
    # önyük adı olduğu gibi; öbür türler eskisi gibi temizlenir
    assert harita["global"] == {"FUN_00001000": "_start", "FUN_00002000": "__do_global_dtors_aux",
                                "FUN_00003000": "register_tm_clones", "FUN_00004000": "gnulib_ic",
                                "FUN_00005000": "faz1_adi"}
    # yalnız yazım değişti: etiket "doğrulanmadı", strateji binary_extract, güven 0,95
    for key in on:
        assert res.label_map[key] == nl.LABEL_UNVERIFIED
        assert res.strategy_map[key] == "binary_extract"
        assert res.confidence_map[key] == 0.95
    kayit = prov["global"]["FUN_00002000"]
    assert (kayit["source"], kayit["pre_name_kind"], kayit["new_name"]) == (
        "pre_names", ONYUK, "__do_global_dtors_aux")
    assert "proposed_name" not in kayit                        # ham ad = yazılan ad
    assert prov["global"]["FUN_00004000"]["proposed_name"] == "_gnulib__ic_"
    assert res.rejected_name_counts == {} and prov["summary"]["pre_names_applied"] == 5
    assert S._hesap_tutar(prov)


def test_kunyesiz_onyuk_adi_eskisi_gibi_temizlenir(tmp_path, seri):
    """Künye yoksa (meta verilmedi) ya da künye başka adı anlatıyorsa ad temizlenir."""
    on = {"FUN_00001000": "_start", "FUN_00002000": "__do_global_dtors_aux"}
    _, _, duz = S._kos(_alan(tmp_path / "ws"), tmp_path / "duz", pre_names=on)
    assert duz["global"] == {"FUN_00001000": "start", "FUN_00002000": "do_global_dtors_aux"}
    meta = {"FUN_00001000": baglama.make_meta(ONYUK, "_baska_ad")}
    _, _, uyusmaz = S._kos(_alan(tmp_path / "ws2"), tmp_path / "uyusmaz", pre_names=on, meta=meta)
    assert uyusmaz["global"]["FUN_00001000"] == "start"


# --------------------------------------------------------------------------------------------
# c_namer: çakışma (ad geçerliliği süzgeci, 93a2956)


def test_temizlenmemis_onyuk_adi_baska_fonksiyonunsa_reddedilir(tmp_path, seri):
    """``_start`` ikilide başka bir fonksiyonun adı: ön ad verilmez, ``_start_2`` gibi ek de
    verilmez; anahtar aday listesine kalır (burada adayı yok, Ghidra adıyla kalır)."""
    ws = _alan(tmp_path / "ws", A._fonk("_start", "00000200"))
    on = {"FUN_00001000": "_start", "FUN_00002000": "__do_global_dtors_aux"}
    meta = {k: baglama.make_meta(ONYUK, v) for k, v in on.items()}
    res, prov, harita = S._kos(ws, tmp_path / "out", pre_names=on, meta=meta)
    assert harita["global"] == {"FUN_00002000": "__do_global_dtors_aux"}
    assert not any(str(v).startswith("_start") for v in harita["global"].values())
    assert res.rejected_name_counts == {nv.REASON_COLLISION: 1}
    kayitlar = {k["key"]: k for k in A._reddedilenler(prov)}
    assert kayitlar == {"FUN_00001000": {
        "key": "FUN_00001000", "scope": "global", "source": "pre_names",
        "reason": nv.REASON_COLLISION, "proposed_name": "_start", "strategy": "binary_extract",
        "pre_name_kind": ONYUK, "existing_address": "00000200"}}
    assert prov["summary"]["pre_names_applied"] == 1 and S._hesap_tutar(prov)


def test_temizlenmemis_onyuk_adi_ithal_adiyla_cakisirsa_reddedilir(tmp_path, seri):
    """İthal fonksiyon baştaki tek ``_`` soyulmuş adıyla da sayılır (Mach-O kuralı, ELF'te de
    uygulanır): ``___do_global_dtors_aux`` ithal ediliyorsa ``__do_global_dtors_aux`` verilmez."""
    ws = _alan(tmp_path / "ws", A._fonk("___do_global_dtors_aux", "00000300", thunk=True))
    on = {"FUN_00002000": "__do_global_dtors_aux"}
    res, prov, harita = S._kos(ws, tmp_path / "out", pre_names=on,
                               meta={"FUN_00002000": baglama.make_meta(ONYUK, on["FUN_00002000"])})
    assert "FUN_00002000" not in harita["global"]
    kayit = A._reddedilenler(prov, nv.REASON_COLLISION)
    assert len(kayit) == 1 and kayit[0]["existing_name"] == "___do_global_dtors_aux"
    assert kayit[0]["existing_address"] == "00000300" and kayit[0]["pre_name_kind"] == ONYUK


def test_simgeli_ikilide_onyuk_adi_kendi_adidir(tmp_path, seri):
    """Anahtar adresten kurulmuş (``FUN_<adres>``) ve o adresteki fonksiyonun Ghidra adı zaten
    ``_start``: ad fonksiyonun kendi adıdır, çakışma sayılmaz."""
    ws = _alan(tmp_path / "ws", A._fonk("_start", "00000400"))
    on = {"FUN_00000400": "_start"}
    res, _, harita = S._kos(ws, tmp_path / "out", pre_names=on,
                            meta={"FUN_00000400": baglama.make_meta(ONYUK, "_start")})
    assert harita["global"] == {"FUN_00000400": "_start"} and res.rejected_name_counts == {}
