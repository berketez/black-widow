"""P15b kalem 1 — GHIDRA-14: veri kökü (``data_root``) çıktı kökünden (``project_root``) ayrı.

Taban: ``project_root`` hem çıktı hem veri köküydü. ``--output-dir`` onu çıktı dizinine
çekince dış imza JSON'ları, FLIRT bayt imzaları ve n-gram veritabanı sessizce
bulunmuyordu; depo kökünden ``--output-dir``'siz koşuda bulunuyordu (FLIRT dahil, B-D3
kararına rağmen). Sonuç giriş noktasına bağlıydı ve hiçbir istatistik ne yüklendiğini
söylemiyordu.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import karadul
from karadul.analyzers.signature_db import SignatureDB
from karadul.config import BinaryReconstructionConfig, Config, resolve_data_root
from karadul.pipeline.context import StepContext
from karadul.pipeline.steps import _feedback_typing_extras as fte
from karadul.pipeline.steps.byte_pattern import BytePatternStep

PAKET_KOKU = Path(karadul.__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _temiz_ortam(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KARADUL_SIG_DATA_DIR", raising=False)
    monkeypatch.delenv("KARADUL_DATA_DIR", raising=False)


# ---------------------------------------------------------------------------
# Config: veri kökü çalışma dizininden ve KARADUL_DATA_DIR'den bağımsız
# ---------------------------------------------------------------------------

def test_veri_koku_calisma_dizininden_bagimsiz(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    cfg = Config()
    assert cfg.project_root == tmp_path or cfg.project_root.resolve() == tmp_path.resolve()
    assert Path(cfg.data_root).resolve() == PAKET_KOKU
    assert cfg.data_root_info() == {"data_root": str(cfg.data_root), "data_root_source": "package"}


def test_ortam_degiskeni_ve_karadul_data_dir_ayrimi(tmp_path: Path, monkeypatch) -> None:
    # KARADUL_DATA_DIR yazılabilir veri dizini / önbellek yedeği: veri kökünü DEĞİŞTİRMEZ.
    monkeypatch.setenv("KARADUL_DATA_DIR", str(tmp_path / "yazma"))
    assert resolve_data_root() == (PAKET_KOKU, "package")
    monkeypatch.setenv("KARADUL_SIG_DATA_DIR", str(tmp_path / "veri"))
    assert resolve_data_root() == ((tmp_path / "veri").resolve(), "env:KARADUL_SIG_DATA_DIR")
    cfg = Config()
    assert cfg.data_root_info()["data_root_source"] == "env:KARADUL_SIG_DATA_DIR"
    cfg.data_root = tmp_path / "baska"
    assert cfg.data_root_info()["data_root_source"] == "config"


def test_veri_koku_yaml_bolumu_degil(tmp_path: Path) -> None:
    from karadul.config import ConfigValueError

    yml = tmp_path / "k.yaml"
    yml.write_text("data_root: /tmp\n", encoding="utf-8")
    with pytest.raises(ConfigValueError):
        Config.load(yml)


# ---------------------------------------------------------------------------
# SignatureDB: dış imza JSON'ları veri kökünden; istatistikte görünür
# ---------------------------------------------------------------------------

def _imza_dosyasi(kok: Path, ad: str) -> Path:
    kok.mkdir(parents=True, exist_ok=True)
    f = kok / "signatures_p15b.json"
    f.write_text(json.dumps({ad: {"lib": "p15blib", "purpose": "", "category": "misc"}}),
                 encoding="utf-8")
    return f


def _cfg(project_root: Path, data_root: Path) -> Config:
    cfg = Config()
    cfg.project_root = project_root
    cfg.data_root = data_root
    cfg.perf.use_lmdb_sigdb = False  # dış JSON yolu yalnız LMDB yokken koşar
    return cfg


def test_dis_imza_veri_kokunden_yuklenir_cikti_kokunden_degil(tmp_path: Path) -> None:
    veri, cikti = tmp_path / "veri", tmp_path / "cikti"
    cikti.mkdir()
    _imza_dosyasi(veri, "p15b_veri_kokunde")
    _imza_dosyasi(cikti, "p15b_cikti_kokunde")
    db = SignatureDB(_cfg(cikti, veri))
    assert db.lookup_symbol("p15b_veri_kokunde") is not None
    assert db.lookup_symbol("p15b_cikti_kokunde") is None
    info = db.backend_info()
    assert info["sigdb_data_root"] == str(veri)
    assert info["sigdb_data_root_source"] == "config"
    assert info["sigdb_external_status"] == "yüklendi"
    assert info["sigdb_external_files"] == 1
    assert info["sigdb_external_signatures"] == 1


def test_onbellek_anahtari_veri_koku(tmp_path: Path) -> None:
    """Aynı çıktı kökü, farklı veri kökü → farklı imza kümesi (IMZA-10 anahtarı)."""
    cikti = tmp_path / "cikti"
    cikti.mkdir()
    dolu, bos = tmp_path / "dolu", tmp_path / "bos"
    bos.mkdir()
    _imza_dosyasi(dolu, "p15b_anahtar_adi")
    a = SignatureDB(_cfg(cikti, dolu))
    b = SignatureDB(_cfg(cikti, bos))
    assert a.lookup_symbol("p15b_anahtar_adi") is not None
    assert b.lookup_symbol("p15b_anahtar_adi") is None
    assert b.backend_info()["sigdb_external_files"] == 0
    assert b.backend_info()["sigdb_external_status"].startswith("dosya yok")
    # Önbellekten gelen örnek de künyeyi taşır.
    a2 = SignatureDB(_cfg(tmp_path / "baska_cikti", dolu))
    assert a2.backend_info()["sigdb_external_files"] == 1


def test_lmdb_etkinken_dis_json_atlandi_yazilir(tmp_path: Path) -> None:
    lmdb = pytest.importorskip("lmdb")  # noqa: F841
    from karadul.analyzers.sigdb_lmdb import LMDBSignatureDB

    yol = tmp_path / "mini.lmdb"
    db = LMDBSignatureDB(yol, readonly=False, map_size=16 * 1024 * 1024)
    db.bulk_write_symbols([("p15b_lmdb", {"lib": "x", "purpose": "", "category": "x"})])
    db.close()
    cfg = _cfg(tmp_path, tmp_path)
    cfg.perf.use_lmdb_sigdb = True
    cfg.perf.sig_lmdb_path = yol
    info = SignatureDB(cfg).backend_info()
    assert info["sigdb_backend"] == "lmdb"
    assert info["sigdb_external_status"].startswith("atlandı: LMDB etkin")
    assert info["sigdb_external_files"] is None  # sayı uydurulmaz
    assert info["sigdb_external_signatures"] is None


# ---------------------------------------------------------------------------
# FLIRT: veri kökündeki bayt imzaları B-D3 kararıyla bekletilir — her girişte
# ---------------------------------------------------------------------------

PATTERN = bytes(range(0x40, 0x60))
GHIDRA_PIE_BASE = 0x100000
CODE_OFFSET = 0x1000


def _elf(path: Path, size: int = 0x2000) -> Path:
    data = bytearray(size)
    data[0:4] = b"\x7fELF"
    data[4], data[5], data[6] = 2, 1, 1
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 3, 183, 1, 0, 64, 0, 0, 64, 56, 1, 64, 0, 0)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0, 0, size, size, 0x1000)
    data[CODE_OFFSET:CODE_OFFSET + len(PATTERN)] = PATTERN
    path.write_bytes(bytes(data))
    return path


def _bytes_sigs(kok: Path) -> Path:
    kok.mkdir(parents=True, exist_ok=True)
    f = kok / "signatures_homebrew_bytes.json"
    f.write_text(json.dumps({"signatures": [
        {"name": "_p15b_flirt", "library": "zstd", "confidence": 0.9, "byte_pattern": PATTERN.hex()},
    ], "total": 1}), encoding="utf-8")
    return f


def _flirt_kos(tmp_path: Path, *, project_root: Path, data_root: Path) -> dict:
    from karadul.analyzers.flirt_parser import FLIRTParser

    binary = _elf(tmp_path / "bin")
    fj = tmp_path / "functions.json"
    fj.write_text(json.dumps({"functions": [
        {"name": f"FUN_{GHIDRA_PIE_BASE + CODE_OFFSET:08x}",
         "address": f"{GHIDRA_PIE_BASE + CODE_OFFSET:08x}", "size": 64},
    ]}), encoding="utf-8")
    pc = MagicMock()
    pc.config = SimpleNamespace(project_root=project_root, data_root=data_root,
                                binary_reconstruction=BinaryReconstructionConfig())
    pc.metadata = {}
    pc.workspace.save_json = MagicMock(return_value=tmp_path / "bp.json")
    pc.workspace.get_stage_dir = MagicMock(side_effect=lambda n: tmp_path / n)
    ctx = StepContext(pipeline_context=pc)
    ctx._write_artifacts({"binary_for_byte_match": binary, "functions_json_path": fj})
    orig = FLIRTParser.extract_from_binary
    FLIRTParser.extract_from_binary = lambda self, *a, **k: []  # type: ignore[method-assign]
    try:
        BytePatternStep().run(ctx)
    finally:
        FLIRTParser.extract_from_binary = orig  # type: ignore[method-assign]
    return dict(ctx.stats)


def test_flirt_veri_koku_bekletilir_depo_kokunden_kosuda_da(tmp_path: Path) -> None:
    """Depo kökünden ``--output-dir``'siz koşu: çıktı kökü = veri kökü, imza dosyası orada."""
    kok = tmp_path / "depo"
    _bytes_sigs(kok)
    st = _flirt_kos(tmp_path, project_root=kok, data_root=kok)
    assert st["flirt_signatures_loaded"] == 0
    assert st["flirt_functions_named"] == 0
    assert st["flirt_data_root"] == str(kok)
    assert st["flirt_data_root_status"].startswith("bekletildi (B-D3)")
    assert st["flirt_data_root_held_files"] == ["signatures_homebrew_bytes.json"]


def test_flirt_giris_noktasindan_bagimsiz(tmp_path: Path) -> None:
    veri = tmp_path / "veri"
    _bytes_sigs(veri)
    cikti_a = tmp_path / "a"
    _bytes_sigs(cikti_a)  # eski kodda çıktı kökündeki dosya yükleniyordu
    cikti_b = tmp_path / "b"
    cikti_b.mkdir()
    anahtarlar = ("flirt_signatures_loaded", "flirt_functions_named", "flirt_data_root",
                  "flirt_data_root_status", "flirt_data_root_held_files")
    sa = _flirt_kos(tmp_path, project_root=cikti_a, data_root=veri)
    sb = _flirt_kos(tmp_path, project_root=cikti_b, data_root=veri)
    assert {k: sa[k] for k in anahtarlar} == {k: sb[k] for k in anahtarlar}


# ---------------------------------------------------------------------------
# n-gram: yalnız veri kökü
# ---------------------------------------------------------------------------

def test_ngram_cikti_kokune_bakmaz(tmp_path: Path) -> None:
    cikti, veri = tmp_path / "ws", tmp_path / "veri"
    (cikti / "sigs" / "ngram_name_db").mkdir(parents=True)
    veri.mkdir()
    d = tmp_path / "typed"
    d.mkdir()
    (d / "FUN_1.c").write_text("void FUN_1(void)\n{\n  return;\n}\n", encoding="utf-8")
    cfg = Config()
    cfg.project_root, cfg.data_root = cikti, veri
    stats: dict = {}
    fte.run_ngram_naming(ctx=SimpleNamespace(pipeline_context=SimpleNamespace(config=cfg)),
                         iter_index=0, decompiled_dir=d, incremental_files=None,
                         stats=stats, errors=[])
    assert stats["ngram_naming_durum"] == "veri_yok"
    assert stats["ngram_db_aranan"] == [str(veri / "sigs" / "ngram_name_db")]


def test_hacker_cli_cikti_kokunu_paket_kokune_cekmez() -> None:
    import inspect

    from karadul import hacker_cli

    kaynak = inspect.getsource(hacker_cli.analyze_with_live_output)
    assert "project_root =" not in kaynak.replace("config.project_root ==", "")
