"""Dalga 0, OLCUM paketi: ölçüm aracı kusurlarının onarım testleri (kalem 2–7).

Kaynak: ``docs/arge/2026-11-20_dalga0/gonderim/OLCUM.md``; ilerleme ``docs/arge/2026-11-20_dalga0/OLCUM.md``.
Her sınama sentetik veriyle koşar (gerçek koşu kökü, GT, Ghidra yok).

  - kalem 2: ``ks1_olc`` ``BITTI``'nin içeriğini okur; yalnız başarı işareti bitmiş sayılır, kısmi /
    hatalı / bekleyen ayrı sayılır ve özete girer; Mac birimi de ``BITTI``'ye bakılarak sınanır.

Mutasyon koruması: ``scripts/measurement/mutation_specs_olcum_araci.json``.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_KOK = Path(__file__).resolve().parents[1]
_OLCUM = _KOK / "scripts" / "measurement"


def _yukle(ad: str, dosya: str):
    spec = importlib.util.spec_from_file_location(ad, _OLCUM / dosya)
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


uo = _yukle("urun_olc_d0_under_test", "urun_olc.py")
ks1 = uo.ks1

ZAMAN = "20261110_000000"   # öbür ölçüm testlerinin sentetik çalışma alanı zamanıyla aynı


# --------------------------------------------------------------------------------------------
# Kalem 2 — ks1_olc BITTI


def _ikili(d: Path, bitti=None, gunluk=False, run_json=None, ad=None):
    """Bir ikili dizini (urun_kos ya da eski düzen): ``ws/workspaces/<ad>/<zaman>/static``."""
    ws = d / "ws" / "workspaces" / (ad or d.name) / ZAMAN
    st = ws / "static"
    st.mkdir(parents=True)
    (st / "ghidra_functions.json").write_text(json.dumps({"functions": []}))
    (st / "ghidra_strings.json").write_text(json.dumps({"strings": []}))
    (ws / "raw").mkdir()
    (ws / "raw" / "target_info.json").write_text(json.dumps({"file_hash": f"sha-{d.name}"}))
    (ws / "reports").mkdir()
    (ws / "reports" / "report.json").write_text(json.dumps(
        {"environment": {"ghidra": {"version": "12.1.2", "matches_pinned": True}}}))
    src = ws / "reconstructed" / "src"
    src.mkdir(parents=True)
    (src / "naming_map.json").write_text(json.dumps({"global": {}, "per_function": {}}))
    if bitti is not None:
        (d / "BITTI").write_text(bitti)
    if gunluk:
        (d / "kosu.log").write_text("…\n")
    if run_json is not None:
        (d / "run.json").write_text(json.dumps(run_json))
    return st


@pytest.mark.parametrize("icerik, beklenen", [
    ("0\n", ("tamam", "0")),
    ("ok 61\n", ("tamam", "ok")),
    ("3\n", ("kismi", "3")),
    ("1\n", ("hatali", "icerik:1")),
    ("zaman_asimi\n", ("hatali", "icerik:zaman_asimi")),
    ("", ("tamam", "bos")),
])
def test_bitti_durumu_icerik(tmp_path, icerik, beklenen):
    (tmp_path / "BITTI").write_text(icerik)
    assert ks1.bitti_durumu(tmp_path, "debian") == beklenen
    assert ks1.bitti_durumu(tmp_path, "mac") == beklenen


def test_bitti_durumu_dosyasiz(tmp_path):
    assert ks1.bitti_durumu(tmp_path, "debian") == ("bekliyor", "yok")
    # Mac: urun_kos düzeni (kosu.log var) ve BITTI yok → koşu bitmemiş
    (tmp_path / "kosu.log").write_text("")
    assert ks1.bitti_durumu(tmp_path, "mac") == ("bekliyor", "yok")
    # eski ol7 düzeni: run.json'dan
    eski = tmp_path / "eski"
    eski.mkdir()
    (eski / "run.json").write_text(json.dumps({"status": "ok", "exit_code": 0}))
    assert ks1.bitti_durumu(eski, "mac") == ("tamam", "run.json")
    (eski / "run.json").write_text(json.dumps({"status": "fail", "exit_code": 1}))
    assert ks1.bitti_durumu(eski, "mac") == ("hatali", "run.json")
    # hiçbir işaret yok (yalnız sentetik kök): bitmiş ama işareti ayrı
    yalin = tmp_path / "yalin"
    yalin.mkdir()
    assert ks1.bitti_durumu(yalin, "mac") == ("tamam", "isaretsiz")


def test_kismi_ve_hatali_bitmis_sayilmaz_ozete_girer(tmp_path):
    deb, mac = tmp_path / "debian", tmp_path / "mac"
    _ikili(deb / "zstd" / "zstd", bitti="0\n")
    _ikili(deb / "zstd" / "pzstd", bitti="3\n")              # kısmi: eskiden bitmiş sayılıyordu
    _ikili(deb / "tree" / "tree", bitti="zaman_asimi\n")     # hatalı içerik
    _ikili(deb / "htop" / "htop")                            # BITTI yok: bekliyor
    _ikili(mac / "tmux", bitti="3\n", gunluk=True)           # Mac kısmi: eskiden BITTI okunmuyordu
    _ikili(mac / "htop", gunluk=True)                        # Mac, urun_kos düzeni, BITTI yok
    elfler = ks1.elfleri_topla(mac, deb)
    durum = {f"{e.platform}/{e.ad}": (e.durum, e.static is not None) for e in elfler}
    assert durum == {"debian/zstd": ("tamam", True), "debian/pzstd": ("kismi", False),
                     "debian/tree": ("hatali", False), "debian/htop": ("bekliyor", False),
                     "mac/tmux": ("kismi", False), "mac/htop": ("bekliyor", False)}
    with pytest.raises(ks1.OnkosulHatasi, match=r"5 ELF bitmemiş ya da hatalı \(kısmi 2, hatalı 1, bekliyor 2\)"):
        ks1.nufus_denetle(elfler, None)
    k = ks1.nufus_denetle(elfler, None, eksik_izinli=True)
    assert k["durumlar"] == {"tamam": 1, "kismi": 2, "hatali": 1, "bekliyor": 2, "ciktisiz": 0}
    assert k["bitti_isareti"] == {"0": 1}
    assert k["biten"] == {"debian/zstd": 1}


def test_urun_olc_bitmislik_ozeti(tmp_path, monkeypatch):
    """``urun_olc olc`` kısmi ve hatalı ikiliyi ölçmez; JSON ve Markdown özetine sayıyla yazar."""
    deb = tmp_path / "debian"
    _ikili(deb / "zstd" / "zstd", bitti="0\n")
    _ikili(deb / "zstd" / "pzstd", bitti="3\n")
    _ikili(deb / "tree" / "tree", bitti="1\n")
    bos = ks1.GtBirimi(adlar={}, nufus=set(), export_gt=set(), kunye={"gt": "sentetik"})
    monkeypatch.setattr(ks1, "gt_elf", lambda e, indir: bos)
    beklenen = {"debian/zstd": 2, "debian/tree": 1}
    with pytest.raises(ks1.OnkosulHatasi, match="kısmi 1, hatalı 1"):
        uo.olc(ks1.elfleri_topla(None, deb), None, None, beklenen=beklenen)
    s = uo.olc(ks1.elfleri_topla(None, deb), None, None, beklenen=beklenen, eksik_izinli=True)
    assert s["nufus"]["durumlar"]["kismi"] == 1 and s["nufus"]["durumlar"]["hatali"] == 1
    assert list(s["birimler"]) == ["debian/zstd"] and list(s["birimler"]["debian/zstd"]["elfler"]) == ["zstd"]
    md = uo.olc_markdown(s)
    assert "tamam 1, kısmi 1, hatalı 1, bekliyor 0, çıktısız 0 (işaret: `0` × 1)" in md
    # ad haritası olmayan "bitmiş" ikili çıktısız sayılır (haritasizlari_isaretle)
    (next((deb / "zstd" / "zstd" / "ws").rglob("naming_map.json"))).unlink()
    s = uo.olc(ks1.elfleri_topla(None, deb), None, None, beklenen=beklenen, eksik_izinli=True)
    assert s["nufus"]["durumlar"]["ciktisiz"] == 1 and s["nufus"]["durumlar"]["tamam"] == 0
    assert "veri yok" in uo.bitmislik_cumlesi({})
