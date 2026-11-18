"""P04b / MUH-09: başvuru karşılaştırmasında sürüm yalnız sürüm dizgisi bağlamından.

Eski kod sqlite3 kabuğundaki "generate_series() requires SQLite 3.8.12 or later"
dizgisinden sürümü 3.8.12 / güven 0,99 okuyordu; en yakın sürüm araması dizgi önekiyle
("3.8.12" ↔ "3.8.1") eşliyordu. Bu testler eski kodda kırmızıdır.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from karadul.reconstruction.reference_differ import ReferenceDB, VersionDetector

_SQLITE_SHELL = [
    "generate_series() requires SQLite 3.8.12 or later",
    "CREATE TABLE x(a)", "SELECT * FROM sqlite_master", "PRAGMA foreign_keys",
    "SQLite version %s %.19s\n",
]


def _detect(strings: list[str]):
    return {d.library: d for d in VersionDetector().detect_from_strings(strings)}


def test_gereksinim_dizgisi_surum_degil():
    d = _detect(_SQLITE_SHELL)["sqlite3"]
    assert d.version == "unknown"
    assert "3.8.12" in d.version_note and "bound" in d.version_note


def test_gercek_surum_dizgisi_korunur():
    d = _detect(_SQLITE_SHELL + ["SQLite 3.46.1 2024-08-13"])["sqlite3"]
    assert d.version == "3.46.1"
    assert d.version_note == "version string"


def test_sinir_dizgisi_once_gelse_de_gercek_surum_secilir():
    strings = ["needs OpenSSL 1.1.1 or newer", "OpenSSL 3.5.7 9 Jun 2026", "EVP_DigestInit", "SSL_CTX_new"]
    assert _detect(strings)["openssl"].version == "3.5.7"


@pytest.mark.parametrize("line", [
    "requires zlib 1.2.11", "zlib 1.2.0 or later is required", "at least zlib 1.2.3",
    "built for >= zlib 1.2.8",
])
def test_sinir_kaliplari(line):
    d = _detect([line, "inflate", "deflate", "adler32"])["zlib"]
    assert d.version == "unknown"


def test_surumsuz_tespit_guveni_surum_ekini_almaz():
    bound = _detect(_SQLITE_SHELL)["sqlite3"]
    real = _detect(_SQLITE_SHELL + ["SQLite 3.46.1"])["sqlite3"]
    assert bound.confidence < real.confidence


def _db(tmp_path: Path, versions: list[str]) -> ReferenceDB:
    for v in versions:
        d = tmp_path / "sqlite3" / v
        d.mkdir(parents=True)
        (d / "ghidra_functions.json").write_text("[]")
        (d / "ghidra_strings.json").write_text("[]")
    return ReferenceDB(tmp_path)


def test_en_yakin_surum_bilesen_karsilastirmasi(tmp_path: Path):
    db = _db(tmp_path, ["3.8.1", "3.8.12.1", "3.46.0"])
    assert db.libraries == ["sqlite3"]
    got = db.lookup_closest("sqlite3", "3.8.12")
    assert got is not None and got.version == "3.8.12.1"


def test_dizgi_oneki_eslesmez(tmp_path: Path):
    db = _db(tmp_path, ["3.8.1", "1.10.0"])
    assert db.libraries == ["sqlite3"]
    assert db.lookup_closest("sqlite3", "3.8.12") is None
    assert db.lookup_closest("sqlite3", "1.1") is None
    assert db.lookup_closest("sqlite3", "unknown") is None


def test_yama_duzeyi_iki_yonlu(tmp_path: Path):
    db = _db(tmp_path, ["3.46.0"])
    assert db.libraries == ["sqlite3"]
    assert db.lookup_closest("sqlite3", "3.46").version == "3.46.0"


def test_yalniz_major_ortakligi_yetmez(tmp_path: Path):
    db = _db(tmp_path, ["3.46.0"])
    assert db.libraries == ["sqlite3"]
    assert db.lookup_closest("sqlite3", "3") is None
