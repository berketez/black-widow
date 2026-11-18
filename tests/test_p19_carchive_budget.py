"""P19 / BICIM-14: PyInstaller CArchive açmada toplam bütçe ve ad çakışması.

Eskiden PYZ ve cx_Freeze için uygulanan toplam açılmış boyut bütçesi CArchive
girdilerine uygulanmıyordu (100 000 girdinin her biri 100 MB'a kadar), aynı
adlı ya da harf duyarsız eşit adlı girdiler aynı dosyaya `O_TRUNC` ile yazılıp
biri sessizce kayboluyordu, dosyanın tamamı boyut denetimsiz belleğe alınıyordu.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from karadul.analyzers.packed_binary import PyInstallerExtractor, _inflate_capped
from karadul.config import Config
from tests.test_packed_binary import _build_pyinstaller_blob


@pytest.fixture(autouse=True)
def _no_decompile(monkeypatch):
    monkeypatch.setattr(PyInstallerExtractor, "_try_decompile_pyc_files",
                        staticmethod(lambda files, out: []))


def _binary(tmp_path: Path, files, *, compressed: bool = True, name: str = "app.bin") -> Path:
    blob, _ = _build_pyinstaller_blob(files, compressed=compressed)
    p = tmp_path / name
    p.write_bytes(b"_MEIPASS\x00" + blob)
    return p


def _disk(root: Path) -> tuple[int, int]:
    files = [p for p in root.rglob("*") if p.is_file()]
    return len(files), sum(p.stat().st_size for p in files)


def test_total_budget_stops_extraction(tmp_path):
    binp = _binary(tmp_path, [(f"e{i:02d}.dat", b"\x00" * 200_000, ord("d")) for i in range(50)])
    cfg = Config()
    # 5 girdi sığar, 6'ncı kalan 100 000 bayta sığmaz -> çıkarma orada durur
    cfg.security.max_archive_extract_size = 1_100_000
    res = PyInstallerExtractor(cfg).extract(binp, tmp_path / "out")
    n, total = _disk(tmp_path / "out")
    assert total <= 1_100_000
    assert n == 5 and len(res.extracted_files) == 5
    assert res.report["budget_exceeded"] is True
    assert res.report["entries_not_extracted_budget"] == 45
    assert any("butcesi" in e and "45 girdi" in e for e in res.errors)


def test_uncompressed_entry_counts_against_budget(tmp_path):
    binp = _binary(tmp_path, [(f"u{i}.dat", b"u" * 400_000, ord("d")) for i in range(5)],
                   compressed=False)
    cfg = Config()
    cfg.security.max_archive_extract_size = 1_000_000
    res = PyInstallerExtractor(cfg).extract(binp, tmp_path / "out")
    assert _disk(tmp_path / "out")[1] <= 1_000_000
    assert len(res.extracted_files) == 2
    assert res.report["budget_exceeded"] is True


def test_per_entry_bomb_rejected_and_charged(tmp_path):
    """Girdi başı sınırı aşan bomba reddedilir; ürettiği bayt bütçeden düşer."""
    files = [(f"bomb{i:02d}.dat", b"\x00" * 1_000_000, ord("d")) for i in range(30)]
    files.append(("last.txt", b"son", ord("d")))
    binp = _binary(tmp_path, files)
    cfg = Config()
    cfg.security.max_decompress_bytes = 300_000
    cfg.security.max_archive_extract_size = 2_000_000
    res = PyInstallerExtractor(cfg).extract(binp, tmp_path / "out")
    assert res.extracted_files == []
    # Toplam açma işi bütçe + bir girdi sınırıyla sınırlı (eskiden 30 x sınır)
    assert res.report["carchive_bytes_inflated"] <= 2_000_000 + 300_001
    assert res.report["budget_exceeded"] is True
    assert res.report["entries_not_extracted_budget"] >= 20


def test_per_entry_cap_alone_is_not_budget_exceeded(tmp_path):
    binp = _binary(tmp_path, [("bomb.dat", b"\x00" * 1_000_000, ord("d")),
                              ("ok.txt", b"tamam", ord("d"))])
    cfg = Config()
    cfg.security.max_decompress_bytes = 300_000
    res = PyInstallerExtractor(cfg).extract(binp, tmp_path / "out")
    assert [ef.original_name for ef in res.extracted_files] == ["ok.txt"]
    assert res.report["budget_exceeded"] is False


def test_same_and_casefold_names_not_overwritten(tmp_path):
    binp = _binary(tmp_path, [
        ("dup.txt", b"AAAA", ord("d")), ("dup.txt", b"BBBB", ord("d")),
        ("Case.txt", b"CCCC", ord("d")), ("case.txt", b"DDDD", ord("d")),
        ("sub/X.so", b"EEEE", ord("b")), ("SUB/x.so", b"FFFF", ord("b")),
    ], compressed=False)
    res = PyInstallerExtractor(Config()).extract(binp, tmp_path / "out")
    on_disk = sorted(p.read_bytes() for p in (tmp_path / "out").rglob("*") if p.is_file())
    assert on_disk == [b"AAAA", b"BBBB", b"CCCC", b"DDDD", b"EEEE", b"FFFF"]
    assert len(res.extracted_files) == 6
    assert len({ef.path for ef in res.extracted_files}) == 6
    assert len(res.report["renamed"]) == 3
    renamed = [ef for ef in res.extracted_files if ef.metadata.get("renamed_due_to_collision")]
    assert sorted(ef.path.name for ef in renamed) == ["case~2.txt", "dup~2.txt", "x~2.so"]
    assert any("ad cakismasi" in e for e in res.errors)


def test_size_checked_before_reading(tmp_path):
    binp = _binary(tmp_path, [("a.txt", b"a", ord("d"))])
    cfg = Config()
    cfg.security.max_binary_size_bytes = 100
    res = PyInstallerExtractor(cfg).extract(binp, tmp_path / "out")
    assert res.success is False
    assert "max_binary_size_bytes" in res.errors[0]


def test_inflate_capped_reports_work():
    import zlib
    data, produced = _inflate_capped(zlib.compress(b"x" * 1000), 5000)
    assert data == b"x" * 1000 and produced == 1000
    data, produced = _inflate_capped(zlib.compress(b"x" * 10_000), 5000)
    assert data is None and produced == 5001
    assert _inflate_capped(b"not zlib", 100) == (None, 0)


def test_pyz_gets_only_what_carchive_left(tmp_path):
    """PYZ modülleri CArchive'in harcadığından kalan bütçeyi kullanır (ortak bütçe)."""
    from tests.test_pyz_archive import _build_pyz, _code, _z

    body = _code("S = '" + "c" * 3000 + "'\n")
    pyz1 = _build_pyz([("a1", 0, _z(body)), ("a2", 0, _z(body))])
    pyz2 = _build_pyz([("b1", 0, _z(body)), ("b2", 0, _z(body))])
    binp = _binary(tmp_path, [("PYZ-00.pyz", pyz1, ord("z")), ("PYZ-01.pyz", pyz2, ord("z"))],
                   compressed=False)
    cfg = Config()
    # CArchive iki PYZ blobunu yazar; PYZ'ye 3*body - 1 kalır -> yalnız a1, a2
    cfg.security.max_archive_extract_size = 3 * len(body) + len(pyz1) + len(pyz2) - 1
    res = PyInstallerExtractor(cfg).extract(binp, tmp_path / "out")
    names = sorted(ef.original_name for ef in res.extracted_files if ef.metadata.get("pyz_module"))
    assert names == ["a1", "a2"]
