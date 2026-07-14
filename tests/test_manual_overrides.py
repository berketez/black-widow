"""ReconstructionStage._apply_manual_overrides testleri (Faz 2, FIX-5).

Analistin arayuzden elle verdigi fonksiyon isimleri (kalici override deposu)
karadul deterministik hat bir binary'yi YENIDEN analiz ettiginde motordan
otomatik geri gelir. Bu testler seam'i (extracted_names mutasyonu) VE donen
manuel map kontratini (MAJOR-1 merge-sonrasi zorlamasi) izole dogrular.

Depo (`~/.karadul/overrides/<hash>.json`) kirlenmesin diye HOME monkeypatch ile
tmp dizine yonlendirilir.
"""
from __future__ import annotations

import json
import types
from pathlib import Path

import pytest

from karadul.config import Config
from karadul.core import overrides
from karadul.stages import ReconstructionStage


# 64 karakterlik gecerli sha256 hex (yalnizca [0-9a-f]) -- depo anahtari sozlesmesi.
TEST_HASH = "a" * 64


def _make_context(file_hash: str, *, overrides_path: str | None = None):
    """Sahte PipelineContext: yalnizca .target.file_hash + .config gerekli."""
    cfg = Config()
    cfg.binary_reconstruction.overrides_path = overrides_path
    target = types.SimpleNamespace(file_hash=file_hash)
    return types.SimpleNamespace(target=target, config=cfg)


@pytest.fixture()
def _tmp_home(tmp_path, monkeypatch):
    """~/.karadul depolamasini tmp HOME'a yonlendir (gercek depo kirlenmesin)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    # Path.home() POSIX'te HOME env'i okur; guvenlik icin expanduser'i da sabitle.
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    return tmp_path


# ---------------------------------------------------------------------------
# 1) Auto-discover: manuel isim deterministik ismi KOSULSUZ ezer
# ---------------------------------------------------------------------------
def test_manual_override_overwrites_and_preserves(_tmp_home):
    # Depoya manuel isim yaz (analistin rename'i).
    overrides.set_name(TEST_HASH, "FUN_00104df0", "my_custom_name")

    stage = ReconstructionStage()
    context = _make_context(TEST_HASH)
    # Deterministik hat bu iki ismi uretmis olsun.
    extracted_names = {
        "FUN_00104df0": "eski_det_isim",   # ezilmeli
        "FUN_00105000": "baska",           # dokunulmamali
    }
    stats: dict = {}

    stage._apply_manual_overrides(extracted_names, context, stats)

    assert extracted_names["FUN_00104df0"] == "my_custom_name"  # manuel ezdi
    assert extracted_names["FUN_00105000"] == "baska"           # dokunmadi
    assert stats["manual_overrides_applied"] == 1


# ---------------------------------------------------------------------------
# 2) Bos hash -> no-op (crash yok)
# ---------------------------------------------------------------------------
def test_empty_hash_is_noop(_tmp_home):
    stage = ReconstructionStage()
    context = _make_context("")  # file_hash bos
    extracted_names = {"FUN_00104df0": "det"}
    stats: dict = {}

    stage._apply_manual_overrides(extracted_names, context, stats)

    assert extracted_names == {"FUN_00104df0": "det"}   # degismedi
    assert "manual_overrides_applied" not in stats


# ---------------------------------------------------------------------------
# 3) Depo yok / bos -> no-op
# ---------------------------------------------------------------------------
def test_missing_store_is_noop(_tmp_home):
    stage = ReconstructionStage()
    context = _make_context(TEST_HASH)  # bu hash icin depo dosyasi hic yok
    extracted_names = {"FUN_00104df0": "det"}
    stats: dict = {}

    stage._apply_manual_overrides(extracted_names, context, stats)

    assert extracted_names == {"FUN_00104df0": "det"}
    assert "manual_overrides_applied" not in stats


# ---------------------------------------------------------------------------
# 4) Bozuk depo dosyasi -> no-op (savunmaci try/except)
# ---------------------------------------------------------------------------
def test_corrupt_store_is_noop(_tmp_home):
    fp = overrides.overrides_file(TEST_HASH)
    fp.write_text("{ bozuk json <<<", encoding="utf-8")  # gecersiz JSON

    stage = ReconstructionStage()
    context = _make_context(TEST_HASH)
    extracted_names = {"FUN_00104df0": "det"}
    stats: dict = {}

    stage._apply_manual_overrides(extracted_names, context, stats)

    assert extracted_names == {"FUN_00104df0": "det"}   # crash yok, degismedi
    assert "manual_overrides_applied" not in stats


# ---------------------------------------------------------------------------
# 5) context yerine None -> guvenli (getattr zinciri)
# ---------------------------------------------------------------------------
def test_none_target_is_noop(_tmp_home):
    stage = ReconstructionStage()
    context = types.SimpleNamespace(target=None, config=Config())
    extracted_names = {"FUN_00104df0": "det"}
    stats: dict = {}

    stage._apply_manual_overrides(extracted_names, context, stats)

    assert extracted_names == {"FUN_00104df0": "det"}
    assert "manual_overrides_applied" not in stats


# ---------------------------------------------------------------------------
# 6) Opsiyonel acik yol (config.overrides_path) -> EK ikinci kaynak
# ---------------------------------------------------------------------------
def test_explicit_overrides_path(_tmp_home, tmp_path):
    # Depo dosyasi (auto-discover) YOK; sadece acik yol ver.
    explicit = tmp_path / "custom_overrides.json"
    explicit.write_text(
        json.dumps(
            {"overrides": {"FUN_00200000": {"name": "from_explicit_file"}}}
        ),
        encoding="utf-8",
    )

    stage = ReconstructionStage()
    context = _make_context(TEST_HASH, overrides_path=str(explicit))
    extracted_names = {"FUN_00200000": "det", "FUN_00300000": "kalir"}
    stats: dict = {}

    stage._apply_manual_overrides(extracted_names, context, stats)

    assert extracted_names["FUN_00200000"] == "from_explicit_file"  # acik yol ezdi
    assert extracted_names["FUN_00300000"] == "kalir"
    assert stats["manual_overrides_applied"] == 1


# ---------------------------------------------------------------------------
# 7) extracted_names dict degil -> no-op
# ---------------------------------------------------------------------------
def test_non_dict_extracted_names_is_noop(_tmp_home):
    overrides.set_name(TEST_HASH, "FUN_00104df0", "x")
    stage = ReconstructionStage()
    context = _make_context(TEST_HASH)
    stats: dict = {}
    # None gecirilse bile crash olmamali.
    stage._apply_manual_overrides(None, context, stats)  # type: ignore[arg-type]
    assert "manual_overrides_applied" not in stats


# ---------------------------------------------------------------------------
# 8) GUVENLIK: acik yoldaki gecersiz/kotu-niyetli addr/name REDDEDILIR
#    (set_name WRITE-dogrulamasini bypass eden el-editli dosya senaryosu)
# ---------------------------------------------------------------------------
def test_explicit_path_rejects_invalid_entries(_tmp_home, tmp_path):
    evil = tmp_path / "evil.json"
    evil.write_text(
        json.dumps({"overrides": {
            # C tanimlayicisi DEGIL (bosluk/paranttez/noktalama) -> reddedilmeli
            "FUN_00104df0": {"name": 'x); do_bad(); //'},
            # path-traversal addr -> reddedilmeli
            "../../etc/passwd": {"name": "ok_name"},
            # gecerli -> uygulanmali
            "FUN_00200000": {"name": "legit_name"},
        }}),
        encoding="utf-8",
    )
    stage = ReconstructionStage()
    context = _make_context(TEST_HASH, overrides_path=str(evil))
    extracted_names: dict = {}
    stats: dict = {}

    stage._apply_manual_overrides(extracted_names, context, stats)

    # Yalnizca gecerli giris gecti; kirli iki giris atlandi.
    assert extracted_names == {"FUN_00200000": "legit_name"}
    assert stats["manual_overrides_applied"] == 1


# ---------------------------------------------------------------------------
# 9) GUVENLIK: auto-discover deposunda el-editli gecersiz name REDDEDILIR
#    (dosyayi dogrudan yazip set_name dogrulamasini atla)
# ---------------------------------------------------------------------------
def test_auto_discover_rejects_hand_edited_invalid_name(_tmp_home):
    # Once gecerli bir kayit yaz (dosyayi/dizini olustur), sonra elle kirlet.
    overrides.set_name(TEST_HASH, "FUN_00200000", "legit_name")
    fp = overrides.overrides_file(TEST_HASH)
    data = json.loads(fp.read_text(encoding="utf-8"))
    # El-editli kirli kayit: gecersiz C ismi.
    data["overrides"]["FUN_00104df0"] = {"name": "bad name with spaces",
                                          "source": "manual", "confidence": 1.0}
    fp.write_text(json.dumps(data), encoding="utf-8")

    stage = ReconstructionStage()
    context = _make_context(TEST_HASH)
    extracted_names: dict = {}
    stats: dict = {}

    stage._apply_manual_overrides(extracted_names, context, stats)

    assert extracted_names == {"FUN_00200000": "legit_name"}  # kirli atlandi
    assert stats["manual_overrides_applied"] == 1


# ---------------------------------------------------------------------------
# 10) MAJOR-1 kontrati: metot uyguladigi DOGRULANMIS map'i DONDURUR
#     (cagiran bu map'i merge SONRASI final_naming_map'e kosulsuz zorlar --
#     bindiff/refdiff clobber + Bayesian merge bypass).
# ---------------------------------------------------------------------------
def test_returns_validated_manual_map(_tmp_home, tmp_path):
    overrides.set_name(TEST_HASH, "FUN_00104df0", "auto_name")   # auto-discover
    mixed = tmp_path / "mixed.json"
    mixed.write_text(
        json.dumps({"overrides": {
            "FUN_00200000": {"name": "explicit_name"},   # gecerli
            "bad addr": {"name": "x"},                    # gecersiz addr -> haric
        }}),
        encoding="utf-8",
    )
    stage = ReconstructionStage()
    context = _make_context(TEST_HASH, overrides_path=str(mixed))
    extracted_names: dict = {}
    stats: dict = {}

    result = stage._apply_manual_overrides(extracted_names, context, stats)

    # Donen map = yalnizca dogrulanmis girisler (auto-discover + acik yol birlesik).
    assert result == {
        "FUN_00104df0": "auto_name",
        "FUN_00200000": "explicit_name",
    }
    assert "bad addr" not in result           # kirli ne map'te
    assert result == extracted_names          # tohum ile donen map tutarli


# ---------------------------------------------------------------------------
# 11) MAJOR-1 kontrati: override yoksa BOS DICT doner (None degil) ->
#     cagiran "(_map or {})" guvenli, zorlama no-op.
# ---------------------------------------------------------------------------
def test_returns_empty_dict_when_no_overrides(_tmp_home):
    stage = ReconstructionStage()
    context = _make_context(TEST_HASH)   # depo yok
    result = stage._apply_manual_overrides({}, context, {})
    assert result == {}                  # None DEGIL
