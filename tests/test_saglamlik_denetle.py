"""Sağlamlık denetiminin bugünkü sürümü (scripts/measurement/saglamlik_denetle.py).

2026-11-10 betiğinden değişen kalemler sentetik koşularla sınanır: ``urun_kos`` düzeni
(BITTI ``0`` + künye durumu), Mac'te ``kosu.log``, ad haritası 1.1 sözleşmesi (mappings +
gerekçeli candidates), README "Output Structure" ağacı. Gerçek koşu varsa tek ikilide koşar.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

_KOK = Path(__file__).resolve().parents[1]
_PATH = _KOK / "scripts" / "measurement" / "saglamlik_denetle.py"
_spec = importlib.util.spec_from_file_location("saglamlik_denetle_under_test", _PATH)
sd = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = sd
_spec.loader.exec_module(sd)

ZAMAN = "20261110_000000"      # sentetik çalışma alanı dizini; tests/test_urun_olc.py ile aynı değer
GUNLUK = """header
─────── Pipeline ───────
  [ok] static
                Results
│  Functions recovered  │   2   │
│  Strings found        │   0   │
│  Variables renamed    │   0   │
  OK 4 dosya yazildi (1 kaynak, 2 rapor)
"""


def _yaz(yol: Path, veri) -> None:
    yol.parent.mkdir(parents=True, exist_ok=True)
    yol.write_text(veri if isinstance(veri, str) else json.dumps(veri), encoding="utf-8")


def _readme(src_dosya: int) -> str:
    return f"""# Black Widow Analysis -- t

## Output Structure

```
out/
  src/                    # Reconstructed source code, {src_dosya} files
    src/                  # 1 files
    README.md
  naming_map.json         # Name mappings and candidates (see Summary)
  README.md               # This file
```

## Pipeline Stages
"""


def _kosu(kok: Path, anahtar: str, *, bitti="0", tur_haritasi=None, out_haritasi=None,
          readme=None) -> Path:
    d = kok / anahtar
    ws = d / "ws" / "workspaces" / "t" / ZAMAN
    _yaz(ws / "reports/report.json", {"pipeline": {"success": True, "stages": {}}, "summary": {}})
    _yaz(d / "kosu.log", GUNLUK)
    if bitti is not None:
        _yaz(d / "BITTI", bitti + "\n")
    _yaz(ws / "reconstructed/src/naming_map.json",
         tur_haritasi or {"global": {"FUN_1": "main", "FUN_2": "_start"}, "per_function": {}})
    _yaz(d / "out/naming_map.json", out_haritasi or {
        "version": "1.1", "mappings": {"FUN_1": {"new_name": "main", "source": "c_namer"}},
        "total_mappings": 1,
        "candidates": {"FUN_2": {"new_name": "_start", "source": "c_namer", "reason": "not_in_code"}}})
    _yaz(d / "out/src/src/main.c", "// Function: main\n// Address: 0x1\nint main(void) { return 0; }\n")
    _yaz(d / "out/src/README.md", "x")
    _yaz(d / "out/README.md", readme if readme is not None else _readme(2))
    return d


def _denetle(kok: Path, anahtar: str, kunye=None) -> dict:
    if kunye is not None:
        _yaz(kok / "kosu_kunyesi.json", kunye)
    kosu = next(k for k in sd.kosulari_bul(str(kok)) if k["kimlik"] == anahtar)
    s, _iz = sd.kosu_denetle_guvenli(kosu)
    assert "denetci_hatasi" not in s, s.get("iz")
    return s


# --------------------------------------------------------------------------------------------
# Koşu listesi
# --------------------------------------------------------------------------------------------
def test_kosulari_bul_urun_duzeni(tmp_path):
    _kosu(tmp_path, "debian/coreutils/ls")
    _kosu(tmp_path, "mac/htop")
    k = {x["kimlik"]: x for x in sd.kosulari_bul(str(tmp_path))}
    assert set(k) == {"debian/coreutils/ls", "mac/htop"}
    assert (k["debian/coreutils/ls"]["platform"], k["debian/coreutils/ls"]["program"]) == ("debian", "coreutils")
    assert (k["mac/htop"]["platform"], k["mac/htop"]["program"]) == ("mac", "htop")
    assert k["mac/htop"]["log"].endswith(os.path.join("mac", "htop", "kosu.log"))
    assert [x["kimlik"] for x in sd.kosulari_bul(str(tmp_path), ["mac/htop"])] == ["mac/htop"]
    with pytest.raises(SystemExit):
        sd.kosulari_bul(str(tmp_path), ["debian/yok/yok"])


# --------------------------------------------------------------------------------------------
# Tamamlanma ve günlük
# --------------------------------------------------------------------------------------------
def test_bitti_sifir_ve_kunye_tamam_bitmis_sayilir(tmp_path):
    _kosu(tmp_path, "mac/htop")
    s = _denetle(tmp_path, "mac/htop",
                 {"sonuclar": [{"anahtar": "mac/htop", "durum": "tamam", "sure_sn": 3.0}]})
    for kalem in ("bitmedi", "log_yok", "log_yazildi_satiri_yok", "log_yapisi_beklenmedik"):
        assert kalem not in s["kusur"], kalem
    assert s["k1"]["log"]["yazilan"] == 4 and s["k1"]["bitti_sure_s"] == 3.0


def test_bitti_yoksa_ya_da_kunye_basarisizsa_bitmedi(tmp_path):
    _kosu(tmp_path, "debian/p/a", bitti=None)
    _kosu(tmp_path, "debian/p/b")
    kunye = {"sonuclar": [{"anahtar": "debian/p/a", "durum": "tamam"},
                          {"anahtar": "debian/p/b", "durum": "cikis_1"}]}
    assert _denetle(tmp_path, "debian/p/a", kunye)["kusur"].get("bitmedi") == 1
    assert _denetle(tmp_path, "debian/p/b", kunye)["kusur"].get("bitmedi") == 1


def test_gunluk_yoksa_log_yok(tmp_path):
    d = _kosu(tmp_path, "mac/htop")
    (d / "kosu.log").unlink()
    assert _denetle(tmp_path, "mac/htop")["kusur"].get("log_yok") == 1


# --------------------------------------------------------------------------------------------
# Ad haritası 1.1 sözleşmesi
# --------------------------------------------------------------------------------------------
def test_harita_sozlesmesi_temiz(tmp_path):
    _kosu(tmp_path, "debian/p/a")
    s = _denetle(tmp_path, "debian/p/a")
    assert "out_harita_ws_haritadan_farkli" not in s["kusur"]
    assert s["k3"]["out_cnamer_aday_kodda_yok"] == 1


@pytest.mark.parametrize("out_haritasi, beklenen", [
    # kayıp: tur FUN_2'yi adlandırdı, out'ta ne mappings ne candidates
    ({"version": "1.1", "mappings": {"FUN_1": {"new_name": "main", "source": "c_namer"}},
      "candidates": {}}, "kayip"),
    # farklı ad
    ({"version": "1.1", "mappings": {"FUN_1": {"new_name": "baska", "source": "c_namer"}},
      "candidates": {"FUN_2": {"new_name": "_start", "source": "c_namer", "reason": "x"}}}, "farkli"),
    # fazla: out'ta turda olmayan c_namer eşlemesi
    ({"version": "1.1", "mappings": {"FUN_1": {"new_name": "main", "source": "c_namer"},
                                     "FUN_9": {"new_name": "uydurma", "source": "c_namer"}},
      "candidates": {"FUN_2": {"new_name": "_start", "source": "c_namer", "reason": "x"}}}, "fazla"),
    # gerekçesiz aday
    ({"version": "1.1", "mappings": {"FUN_1": {"new_name": "main", "source": "c_namer"}},
      "candidates": {"FUN_2": {"new_name": "_start", "source": "c_namer"}}}, "gerekcesiz"),
])
def test_harita_sozlesmesi_bozulunca_kusur(tmp_path, out_haritasi, beklenen):
    _kosu(tmp_path, "debian/p/a", out_haritasi=out_haritasi)
    s = _denetle(tmp_path, "debian/p/a")
    assert s["kusur"].get("out_harita_ws_haritadan_farkli", 0) >= 1, beklenen
    alan = {"kayip": "out_harita_ws_kayip", "farkli": "out_harita_ws_farkli_ad",
            "fazla": "out_harita_ws_fazla", "gerekcesiz": "out_aday_gerekcesiz"}[beklenen]
    assert s["k3"][alan] == 1


# --------------------------------------------------------------------------------------------
# README "Output Structure"
# --------------------------------------------------------------------------------------------
def test_readme_yapisi_tutuyor_ve_bozuluyor(tmp_path):
    d = _kosu(tmp_path, "debian/p/a")
    out = str(d / "out")
    assert sd.readme_yapisini_denetle(_readme(2), out) == []
    assert sd.readme_yapisini_denetle(_readme(3), out) == ["sayı: src README 3 / disk 2"]
    eksik = _readme(2).replace("    README.md\n", "    README.md\n    yok.c\n")
    assert sd.readme_yapisini_denetle(eksik, out) == ["yok: src/yok.c"]
    assert sd.readme_yapisini_denetle("# başlık yok\n", out) == ["yapı bloğu yok"]


def test_readme_kusuru_kosu_denetiminde(tmp_path):
    _kosu(tmp_path, "debian/p/a", readme=_readme(7))
    s = _denetle(tmp_path, "debian/p/a")
    assert s["kusur"].get("readme_yapi_uyusmuyor") == 1
    _kosu(tmp_path, "debian/p/b")
    assert "readme_yapi_uyusmuyor" not in _denetle(tmp_path, "debian/p/b")["kusur"]


# --------------------------------------------------------------------------------------------
# Tek gerçek örnek
# --------------------------------------------------------------------------------------------
GERCEK = Path.home() / "karadul_olcum/runs/genel-tarama-2026-11-18"


@pytest.mark.skipif(not (GERCEK / "debian/tree/tree/out").is_dir(), reason="HEAD koşusu yok")
def test_gercek_kosu_tree():
    kosu = next(k for k in sd.kosulari_bul(str(GERCEK), ["debian/tree/tree"]))
    s, _ = sd.kosu_denetle_guvenli(kosu)
    for kalem in ("bitmedi", "log_yok", "out_harita_ws_haritadan_farkli", "readme_yapi_uyusmuyor",
                  "denetci_hatasi"):
        assert kalem not in s["kusur"], kalem
    assert not [x["ad"] for x in s["k1"]["sayilar"] if x["ad"].startswith("log_") and not x["esit"]]
