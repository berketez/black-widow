"""P12a kalem 2 — AD-07: ön adların güveni kanalın ölçülmüş kesinliği (sabit 0,95 değil).

Sorun (AD-07): c_namer her ön ada (gnulib parmak izi, ELF önyükü, main, KS-1, Faz 1) kanıt
gücünden bağımsız 0,95 yazıyordu; ``naming_map.json`` bu sayıyı gösteriyordu. gnulib kanalının
ölçülmüş tam ad kesinliği 621/843 (%73,7).

Kural (P12a ön kaydı §1): güven = ``naming_labels.MEASURED_PRE_NAME_PRECISION``'daki Wilson %95 alt
sınırı; ölçülmemiş kanal → ``None`` (JSON ``null``). Ad seçimi değişmez.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_ad_gecerliligi as G  # noqa: E402
import test_c_namer_determinism as T  # noqa: E402
import test_c_namer_susturma as S  # noqa: E402

from karadul.core import naming_labels as nl  # noqa: E402
from karadul.core.output_formatter import OutputFormatter  # noqa: E402,F401  (içe aktarılabilir olmalı)
from karadul.reconstruction import c_namer  # noqa: E402
from karadul.reconstruction.tarif import baglama  # noqa: E402

# Ölçüm belgesinden (urun_olcumu_yeni2.md "Kanal başına") elle aktarılmış sayılar
BELGEDEKI = {
    "on_ad:gnulib": (621, 843), "on_ad:elf_onyuk": (458, 458), "on_ad:main_giris": (110, 110),
    "ks1:func_kalibi": (246, 259), "ks1:func_aktarma": (33, 33),
    "ks1:func_kalibi+func_aktarma": (3, 3), "ks1:assert_ust": (5, 7),
}


@pytest.fixture
def seri(monkeypatch):
    monkeypatch.setattr(c_namer, "ProcessPoolExecutor", T._SerialExecutor)
    monkeypatch.setattr(c_namer, "_worker_namer", None)


def test_tablo_olcum_belgesiyle_ve_wilson_alt_sinirla_ayni():
    assert {k: v[:2] for k, v in nl.MEASURED_PRE_NAME_PRECISION.items()} == BELGEDEKI
    for kanal, (k, n, alt) in nl.MEASURED_PRE_NAME_PRECISION.items():
        assert alt == round(baglama.wilson(k, n)[0], 3), kanal
        assert 0.0 < alt < 1.0, kanal
    belge = Path(__file__).resolve().parents[1] / nl.MEASURED_PRECISION_SOURCE.split("@")[0]
    metin = belge.read_text(encoding="utf-8")
    for kanal, (k, n) in BELGEDEKI.items():
        assert f"| `{kanal}` | {n} | {k} | {n - k} |" in metin, kanal


def test_olculmemis_kanal_guven_tasimaz():
    assert nl.measured_channel_confidence("on_ad:faz1") is None
    assert nl.measured_channel_confidence("on_ad:elle") is None
    assert nl.measured_channel_confidence(None) is None
    assert nl.measured_channel_confidence("on_ad:gnulib") == 0.706


def _alan(root: Path) -> dict[str, Path]:
    adlar = ["FUN_00001000", "FUN_00002000", "FUN_00003000", "FUN_00004000", "FUN_00005000",
             "FUN_00006000"]
    return G._calisma_alani(root, [G._fonk(a, a[4:]) for a in adlar])


def test_on_ad_turune_gore_guven_ve_ad_degismez(tmp_path, seri):
    on = {"FUN_00001000": "full_write", "FUN_00002000": "_start", "FUN_00003000": "main",
          "FUN_00004000": "faz1_adi", "FUN_00005000": "elle_adi", "FUN_00006000": "kunyesiz_ad"}
    meta = {"FUN_00001000": baglama.make_meta(baglama.KIND_GNULIB, "full_write"),
            "FUN_00002000": baglama.make_meta(baglama.KIND_ELF_BOILERPLATE, "_start"),
            "FUN_00003000": baglama.make_meta(baglama.KIND_MAIN, "main"),
            "FUN_00004000": baglama.make_meta(baglama.KIND_PHASE1, "faz1_adi"),
            "FUN_00005000": baglama.make_meta(baglama.KIND_MANUAL, "elle_adi")}
    res, prov, harita = S._kos(_alan(tmp_path / "ws"), tmp_path / "out", pre_names=on, meta=meta)
    beklenen = {"FUN_00001000": 0.706, "FUN_00002000": 0.992, "FUN_00003000": 0.966,
                "FUN_00004000": None, "FUN_00005000": None, "FUN_00006000": None}
    for anahtar, guven in beklenen.items():
        kayit = prov["global"][anahtar]
        assert kayit["source"] == "pre_names", anahtar
        assert kayit["confidence"] == guven, anahtar
        assert res.confidence_map.get(anahtar) == guven, anahtar
    # sabit 0,95 hiçbir kayıtta yok; adlar yine verildi
    assert all(r.get("confidence") != 0.95 for r in prov["global"].values())
    assert set(harita["global"]) == set(on)
    # köken kaydı JSON'da null yazılabiliyor
    ham = json.loads((tmp_path / "out" / nl.NAMING_PROVENANCE_FILE).read_text(encoding="utf-8"))
    assert ham["global"]["FUN_00004000"]["confidence"] is None
