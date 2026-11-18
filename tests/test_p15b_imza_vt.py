"""P15b kalem 2 — K-5: yeni (şema 2) imza veritabanı kendiliğinden devreye girmiyordu.

Taban: ``resolve_lmdb_path`` sırası config → ``KARADUL_SIG_LMDB_PATH`` →
``~/.karadul/signatures.lmdb`` (eski, şema 1). Geliştirmede ve ölçümde şema 1
veritabanı sessizce açılıyordu; istatistikte uyarı yoktu. Paketleme betiği de eski
konumdan kopyalıyordu.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from karadul.analyzers.signature_db import SignatureDB
from karadul.config import Config, resolve_sig_lmdb_path

lmdb = pytest.importorskip("lmdb")

DEPO = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _temiz_ortam(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KARADUL_SIG_LMDB_PATH", raising=False)
    monkeypatch.delenv("KARADUL_SIG_DATA_DIR", raising=False)


def _mini_lmdb(path: Path, *, schema: str | None) -> Path:
    from karadul.analyzers.sigdb_lmdb import LMDBSignatureDB

    db = LMDBSignatureDB(path, readonly=False, map_size=16 * 1024 * 1024)
    db.bulk_write_symbols([("p15b_vt_adi", {"lib": "x", "purpose": "", "category": "x"})])
    if schema is not None:
        db.put_metadata("schema_version", schema.encode("ascii"))
    db.close()
    return path


def test_veri_koku_veritabani_eski_konumdan_once(tmp_path: Path, monkeypatch) -> None:
    veri = tmp_path / "veri"
    _mini_lmdb(veri / "signatures.lmdb", schema="2")
    assert resolve_sig_lmdb_path(None, veri) == (veri / "signatures.lmdb", "data_root:signatures.lmdb")
    # Veri kökünde veritabanı yoksa eski konum (kaynağı açıkça "default").
    bos = tmp_path / "bos"
    bos.mkdir()
    yol, kaynak = resolve_sig_lmdb_path(None, bos)
    assert kaynak == "default:~/.karadul/signatures.lmdb"
    assert yol == Path.home() / ".karadul" / "signatures.lmdb"
    # Ortam değişkeni ve config veri kökünden önce gelir.
    monkeypatch.setenv("KARADUL_SIG_LMDB_PATH", str(tmp_path / "ortam.lmdb"))
    assert resolve_sig_lmdb_path(None, veri)[1] == "env:KARADUL_SIG_LMDB_PATH"
    assert resolve_sig_lmdb_path(tmp_path / "cfg.lmdb", veri)[1] == "config:perf.sig_lmdb_path"


def _cfg(veri: Path) -> Config:
    cfg = Config()
    cfg.project_root = veri
    cfg.data_root = veri
    cfg.perf.use_lmdb_sigdb = True
    return cfg


def test_signature_db_veri_kokundeki_sema2_veritabanini_acar(tmp_path: Path) -> None:
    veri = tmp_path / "veri"
    _mini_lmdb(veri / "signatures.lmdb", schema="2")
    info = SignatureDB(_cfg(veri)).backend_info()
    assert info["sigdb_backend"] == "lmdb"
    assert info["sigdb_path"] == str(veri / "signatures.lmdb")
    assert info["sigdb_path_source"] == "data_root:signatures.lmdb"
    assert info["sigdb_schema_version"] == "2"
    assert info["sigdb_lmdb_symbol_count"] == 1
    assert info["sigdb_schema_warning"] is None


def test_sema1_sessizce_yeglenmez(tmp_path: Path) -> None:
    veri = tmp_path / "veri"
    _mini_lmdb(veri / "signatures.lmdb", schema=None)  # şema 1: künye kaydı yok
    info = SignatureDB(_cfg(veri)).backend_info()
    assert info["sigdb_backend"] == "lmdb"
    assert info["sigdb_schema_version"] is None
    assert info["sigdb_schema_warning"].startswith("eski şema (1 (künyesiz))")


def test_paketleme_betigi_sozdizimi_ve_kaynak() -> None:
    betik = DEPO / "packaging" / "macos" / "build_mac_app.sh"
    subprocess.run(["bash", "-n", str(betik)], check=True)
    metin = betik.read_text(encoding="utf-8")
    # Kaynak artık eski konum değil: veri kökündeki signatures.lmdb (ya da açık değişken).
    assert 'LMDB="$HOME/.karadul/signatures.lmdb"' not in metin
    assert 'LMDB_SRC="${KARADUL_SIG_LMDB_SRC:-$REPO/signatures.lmdb}"' in metin
    # Eski şema --full'de gömülmez; bağ çözülerek kopyalanır; künye build-info'da.
    assert 'if [ "$SIG_SCHEMA" = "2" ]; then' in metin
    assert 'cp -R "$SIG_REAL" "$RES/signatures.lmdb"' in metin
    assert '"signature_db": {' in metin
