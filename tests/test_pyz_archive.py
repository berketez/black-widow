"""PyInstaller PYZ (ZlibArchive) okuyucusu testleri (packed_binary PYZ bölümü).

Sentetik PYZ'ler PyInstaller 6.x yazıcısıyla aynı biçimde üretilir: 17 baytlık
başlık, ``zlib.compress(marshal.dumps(code), 6)`` gövdeler, TOC için CPython'un
kendi ``marshal.dumps``'ı. Kısıtlı TOC ayrıştırıcısı böylece gerçek yazıcı
çıktısına karşı sınanır. Her güvenlik korumasının testi mutation ile kanıtlandı
(koruma kaldırılınca ilgili test düşer).

Gerçek binary testi ``/private/tmp/pycdc_e2e/py312_mod/dist/app`` yoksa atlanır.
"""

from __future__ import annotations

import importlib.util
import json
import marshal
import os
import struct
import sys
import tracemalloc
import zlib
from pathlib import Path
from typing import Any

import pytest

from karadul.analyzers.packed_binary import (
    PYZ_ITEM_DATA,
    PYZ_ITEM_MODULE,
    PYZ_ITEM_NSPKG,
    PYZ_ITEM_PKG,
    PYZ_MAGIC,
    ExtractedFile,
    PyInstallerExtractor,
    PyzFormatError,
    _TocMarshalReader,
    _inflate_pyz_entry,
    classify_pyz_module,
    extract_pyz_modules,
    parse_pyz,
    unique_casefold_name,
)
from karadul.analyzers.pyc_decompiler import repair_pyc_header, version_from_pyc_bytes
from karadul.config import Config
from tests.test_packed_binary import _build_pyinstaller_blob

RUNNING = f"{sys.version_info.major}.{sys.version_info.minor}"
# Sabit, bilinen bir magic (3.12, 3531): başlık testleri çalışan yorumlayıcıdan bağımsız.
MAGIC_312 = struct.pack("<H", 3531) + b"\r\n"
BIG = 2 * 1024 ** 3

REAL_APP = Path("/private/tmp/pycdc_e2e/py312_mod/dist/app")


# ---------------------------------------------------------------------------
# Yardımcılar
# ---------------------------------------------------------------------------

def _code(src: str = "x = 1\n", name: str = "m") -> bytes:
    """Çalışan yorumlayıcıyla derlenmiş code nesnesinin marshal gövdesi."""
    return marshal.dumps(compile(src, name + ".py", "exec"))


def _z(body: bytes) -> bytes:
    return zlib.compress(body, 6)


def _build_pyz(
    entries: list[tuple[str, int, bytes]],
    *,
    as_dict: bool = False,
    crypt_flag: int = 0,
    pymagic: bytes = MAGIC_312,
    toc_bytes: bytes | None = None,
) -> bytes:
    """PyInstaller ZlibArchiveWriter düzeni: başlık(17) + gövdeler + marshal TOC.

    ``entries``: (ad, typecode, saklanan_gövde) -- gövde zaten sıkıştırılmış
    (ya da testin istediği bozuk bayt dizisi).
    """
    buf = bytearray(17)
    toc: list[tuple[str, tuple[int, int, int]]] = []
    for name, typecode, blob in entries:
        toc.append((name, (typecode, len(buf), len(blob))))
        buf += blob
    toc_offset = len(buf)
    if toc_bytes is None:
        toc_bytes = marshal.dumps(dict(toc) if as_dict else toc)
    buf += toc_bytes
    buf[0:4] = PYZ_MAGIC
    buf[4:8] = pymagic
    buf[8:12] = struct.pack("!i", toc_offset)
    buf[12] = crypt_flag
    return bytes(buf)


def _extract(data: bytes, out: Path, **kw: Any) -> tuple[list[ExtractedFile], dict[str, Any]]:
    kw.setdefault("max_total_size", BIG)
    return extract_pyz_modules(data, out, archive_name="PYZ.pyz", **kw)


def _i32(n: int) -> bytes:
    return struct.pack("<i", n)


# ---------------------------------------------------------------------------
# 1. Başlık + TOC okuma
# ---------------------------------------------------------------------------

class TestParsePyz:
    def test_liste_toc_okunur(self) -> None:
        mod, pkg, ns = _z(_code("a = 1\n")), _z(_code("b = 2\n")), _z(_code(""))
        data = _build_pyz([
            ("app.core", PYZ_ITEM_MODULE, mod),
            ("app", PYZ_ITEM_PKG, pkg),
            ("nsp", PYZ_ITEM_NSPKG, ns),
        ])
        arc = parse_pyz(data)
        assert [(e.name, e.typecode) for e in arc.entries] == [
            ("app.core", PYZ_ITEM_MODULE), ("app", PYZ_ITEM_PKG), ("nsp", PYZ_ITEM_NSPKG),
        ]
        # Ofset/uzunluk PYZ başına göre ve gövdeyi tam gösteriyor.
        first = arc.entries[0]
        assert (first.offset, first.length) == (17, len(mod))
        assert data[first.offset:first.offset + first.length] == mod
        assert arc.python_magic == MAGIC_312
        assert arc.python_version == "3.12"
        assert arc.crypt_flag == 0 and not arc.encrypted
        assert arc.rejected == {} and not arc.toc_truncated

    def test_eski_dict_toc_ayni_sonucu_verir(self) -> None:
        ents = [("a", PYZ_ITEM_MODULE, _z(_code())), ("b", PYZ_ITEM_PKG, _z(_code()))]
        lst = parse_pyz(_build_pyz(ents))
        dct = parse_pyz(_build_pyz(ents, as_dict=True))
        assert [(e.name, e.typecode, e.offset, e.length) for e in lst.entries] == \
               [(e.name, e.typecode, e.offset, e.length) for e in dct.entries]

    @pytest.mark.parametrize("obj", [
        [("a", (0, 17, 5)), ("b.c", (1, 22, 9))],
        {"a": (0, 17, 5), "modül": (3, 22, 1)},
        [("x", (0, 2 ** 31 + 5, 7)), ("y", (0, -(2 ** 40), 0))],   # TYPE_LONG
        [("ref", (0, 0, 0))] * 4,                                    # FLAG_REF / TYPE_REF
        [],
    ])
    def test_kisitli_okuyucu_marshal_loads_ile_ayni(self, obj: Any) -> None:
        """Zararsız TOC'lerde kısıtlı okuyucu CPython marshal.loads ile aynı sonucu verir."""
        raw = marshal.dumps(obj)
        got = _TocMarshalReader(raw, 0, 10 ** 6).read()
        want = marshal.loads(raw)
        if isinstance(want, dict):
            want = list(want.items())
        assert got == want

    def test_ayni_ad_sonraki_kazanir(self) -> None:
        a1, a2 = _z(_code("v = 1\n")), _z(_code("v = 2\n"))
        toc = marshal.dumps([("a", (0, 17, len(a1))), ("a", (0, 17 + len(a1), len(a2)))])
        data = _build_pyz([("a", 0, a1), ("a", 0, a2)], toc_bytes=toc)
        arc = parse_pyz(data)
        assert len(arc.entries) == 1
        assert arc.entries[0].offset == 17 + len(a1)   # dict(...) semantiği
        assert arc.rejected == {"duplicate_name": 1}

    def test_toc_ogesi_dogrulama_nedenleri(self) -> None:
        ok = _z(_code())
        toc = marshal.dumps([
            ("iyi", (PYZ_ITEM_MODULE, 17, len(ok))),
            ("veri", (PYZ_ITEM_DATA, 17, len(ok))),
            ("tip", (9, 17, len(ok))),
            ("tasma", (PYZ_ITEM_MODULE, 17, 10 ** 6)),
            ("negatif", (PYZ_ITEM_MODULE, -1, 3)),
            ("bool", (True, 17, 3)),
            ("eksik", (0, 17)),
            (5, (0, 17, 3)),
            "duz-dizge",
        ])
        arc = parse_pyz(_build_pyz([("iyi", 0, ok)], toc_bytes=toc))
        assert [e.name for e in arc.entries] == ["iyi"]
        assert arc.rejected == {
            "data_entry": 1, "unknown_typecode": 1, "bad_range": 2, "bad_toc_item": 4,
        }


# ---------------------------------------------------------------------------
# 2. Bozuk başlık / düşmanca TOC -> PyzFormatError (çökme yok)
# ---------------------------------------------------------------------------

class TestHostileToc:
    @pytest.mark.parametrize("data", [
        b"",
        b"PYZ",
        b"XYZ\x00" + MAGIC_312 + struct.pack("!i", 17) + b"\x00" * 10,
        b"PYZ\x00" + MAGIC_312 + struct.pack("!i", -5) + b"\x00" * 10,
        b"PYZ\x00" + MAGIC_312 + struct.pack("!i", 10 ** 6) + b"\x00" * 10,
        b"PYZ\x00" + MAGIC_312 + struct.pack("!i", 17) + b"\x00" * 5 + b"[" + _i32(3),
    ])
    def test_bozuk_baslik_ve_kesik_toc(self, data: bytes) -> None:
        with pytest.raises(PyzFormatError):
            parse_pyz(data)

    def test_toc_icinde_code_nesnesi_reddedilir(self) -> None:
        """TOC marshal.loads ile açılsaydı code nesnesi süreç içinde yaratılırdı."""
        toc = marshal.dumps([("a", (0, 17, 1)), compile("x = 1", "e", "exec")])
        with pytest.raises(PyzFormatError, match="izin verilmeyen"):
            parse_pyz(_build_pyz([("a", 0, b"x")], toc_bytes=toc))

    @pytest.mark.parametrize("raw,neden", [
        (b"\xdb" + _i32(1) + b"r" + _i32(0), "referans"),         # kendine dönen liste
        (b"[" + _i32(1) + b"r" + _i32(7), "referans"),             # olmayan referans
        (b"[" + _i32(-1), "boyut"),                                # negatif boyut
        (b"[" + _i32(0x7FFFFFFF) + b"N", "boyut"),                 # sahte dev boyut
        (b"u" + _i32(0x7FFFFFFF) + b"ab", "boyut"),                # sahte dev dizge
        ((b"[" + _i32(1)) * 20 + b"N", "derinlik"),               # derin iç içe
        (b"[" + _i32(1) + b"(" + _i32(50) + b"N" * 50, "iç öğe"),  # iç demet çok büyük
        (b"l" + _i32(40) + b"\x00\x00" * 40, "çok büyük"),         # dev tamsayı
        (b"[" + _i32(1) + b"{0", "iç içe dict"),
        (b"g" + b"\x00" * 8, "izin verilmeyen"),                   # float
    ])
    def test_dusmanca_marshal(self, raw: bytes, neden: str) -> None:
        with pytest.raises(PyzFormatError, match=neden):
            _TocMarshalReader(raw, 0, 100).read()

    def test_extract_bozuk_pyzde_cokmez_hata_raporlar(self, tmp_path: Path) -> None:
        files, rep = _extract(b"PYZ\x00" + MAGIC_312 + struct.pack("!i", -1), tmp_path / "o")
        assert files == []
        assert rep["error"] and "PYZ okunamadı" in rep["error"]


# ---------------------------------------------------------------------------
# 3. Sınırlar: girdi sayısı, tek girdi boyutu, toplam boyut (zip-bomb)
# ---------------------------------------------------------------------------

class TestLimits:
    def test_girdi_sayisi_siniri(self, tmp_path: Path) -> None:
        ents = [(f"m{i}", 0, _z(_code())) for i in range(5)]
        data = _build_pyz(ents)
        arc = parse_pyz(data, max_entries=3)
        assert [e.name for e in arc.entries] == ["m0", "m1", "m2"]
        assert arc.toc_truncated is True
        files, rep = _extract(data, tmp_path / "o", max_entries=3)
        assert len(files) == 3 and rep["toc_truncated"] is True

    def test_varsayilan_girdi_siniri_carchive_ile_ayni_sabit(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Aynı kavram için ikinci sabit yok: PYZ de MAX_TOC_ENTRIES kullanır."""
        data = _build_pyz([(f"m{i}", 0, _z(_code())) for i in range(3)])
        monkeypatch.setattr(PyInstallerExtractor, "MAX_TOC_ENTRIES", 2)
        assert len(parse_pyz(data).entries) == 2

    def test_tek_girdi_boyut_siniri(self, tmp_path: Path) -> None:
        big = _code("S = '" + "a" * 5000 + "'\n")      # açılmış > 4096
        small = _code("s = 1\n")
        data = _build_pyz([("big", 0, _z(big)), ("small", 0, _z(small))])
        files, rep = _extract(data, tmp_path / "o", max_entry_size=4096)
        assert [f.original_name for f in files] == ["small"]
        assert rep["rejected"] == {"too_large": 1}
        assert not (tmp_path / "o" / "big.pyc").exists()

    def test_toplam_boyut_siniri_kalanlari_atlar(self, tmp_path: Path) -> None:
        body = _code("S = '" + "b" * 3000 + "'\n")
        n = len(body)
        budget = 2 * n + n // 2
        data = _build_pyz([(f"m{i}", 0, _z(body)) for i in range(4)])
        files, rep = _extract(data, tmp_path / "o", max_total_size=budget)
        assert [f.original_name for f in files] == ["m0", "m1"]
        assert rep["rejected"] == {"total_limit": 2}
        # Üçüncü girdi kalan bütçe + 1 baytta kesildi; toplam iş bütçeyi 1 bayt aşar.
        assert rep["bytes_inflated"] == budget + 1

    def test_reddedilen_girdilerin_isi_de_butceden_duser(self, tmp_path: Path) -> None:
        """Her biri tek girdi sınırını aşan bombalar sonsuza dek açılmaz (CPU DoS)."""
        bomb = _z(b"c" + b"\x00" * 50_000)
        data = _build_pyz([(f"b{i}", 0, bomb) for i in range(50)])
        files, rep = _extract(data, tmp_path / "o", max_entry_size=10_000,
                              max_total_size=35_000)
        assert files == []
        # 3 girdi (3 x 10_001 bayt) açılıp reddedildi, 4.sü kalan bütçeye takıldı.
        assert rep["rejected"] == {"too_large": 3, "total_limit": 47}
        assert rep["bytes_inflated"] <= 35_000 + 1

    def test_zip_bomb_bellegi_sinirli(self) -> None:
        """64 MiB'a açılan ~64 KiB girdi: çıktı limit+1 baytla kesilir, bellek şişmez."""
        bomb = zlib.compress(b"\x00" * (64 * 1024 * 1024), 9)
        assert len(bomb) < 128 * 1024
        tracemalloc.start()
        try:
            body, reason, produced = _inflate_pyz_entry(bomb, 1024 * 1024)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert body is None and reason == "too_large"
        assert produced == 1024 * 1024 + 1
        assert peak < 8 * 1024 * 1024

    def test_extractor_butceyi_pyz_arsivleri_arasinda_paylasir(
        self, tmp_path: Path, config: Config,
    ) -> None:
        body = _code("S = '" + "c" * 3000 + "'\n")
        pyz1 = _build_pyz([("a1", 0, _z(body)), ("a2", 0, _z(body))])
        pyz2 = _build_pyz([("b1", 0, _z(body)), ("b2", 0, _z(body))])
        blob, _ = _build_pyinstaller_blob([
            ("PYZ-00.pyz", pyz1, ord("z")), ("PYZ-01.pyz", pyz2, ord("z")),
        ])
        binp = tmp_path / "app.bin"
        binp.write_bytes(blob)
        config.security.max_archive_extract_size = 3 * len(body)
        res = PyInstallerExtractor(config).extract(binp, tmp_path / "out")
        names = sorted(ef.original_name for ef in res.extracted_files
                       if ef.metadata.get("pyz_module"))
        assert names == ["a1", "a2", "b1"]


# ---------------------------------------------------------------------------
# 4. Bozuk girdiler atlanır ve sayılır
# ---------------------------------------------------------------------------

class TestCorruptEntries:
    def test_bozuk_zlib_atlanir_sayilir(self, tmp_path: Path) -> None:
        data = _build_pyz([
            ("iyi", 0, _z(_code())),
            ("bozuk", 0, b"\x78\x9cBOZUK-VERI"),
            ("kesik", 0, _z(_code())[:-6]),
        ])
        files, rep = _extract(data, tmp_path / "o")
        assert [f.original_name for f in files] == ["iyi"]
        assert rep["rejected"] == {"corrupt_zlib": 2}

    def test_code_olmayan_marshal_atlanir(self, tmp_path: Path) -> None:
        data = _build_pyz([
            ("veri", 0, _z(marshal.dumps({"not": "code"}))),
            ("bos", 0, _z(b"")),
            ("kod", 0, _z(_code())),
        ])
        files, rep = _extract(data, tmp_path / "o")
        assert [f.original_name for f in files] == ["kod"]
        assert rep["rejected"] == {"bad_marshal": 2}
        assert not (tmp_path / "o" / "veri.pyc").exists()


# ---------------------------------------------------------------------------
# 5. Modül adı -> dosya yolu: path traversal koruması
# ---------------------------------------------------------------------------

class TestPathSafety:
    BAD_NAMES = [
        "../kacis", "..", "a..b", "/mutlak/yol", "a/b", "a\\b", "x\x00y",
        ".gizli", "bitis.", "1rakam", "bo sluk", "CON", "aux.util", "a" * 300,
    ]

    def test_guvensiz_adlar_yazilmaz(self, tmp_path: Path) -> None:
        ents = [(n, 0, _z(_code())) for n in self.BAD_NAMES]
        ents.append(("iyi.alt", 0, _z(_code())))
        out = tmp_path / "work" / "PYZ.pyz_extracted"
        files, rep = _extract(_build_pyz(ents), out)
        assert [f.original_name for f in files] == ["iyi.alt"]
        assert rep["rejected"] == {"unsafe_name": len(self.BAD_NAMES)}
        # Çıktı dizininde yalnız iyi dosya; üst dizinlere hiçbir şey sızmadı.
        assert sorted(p.name for p in out.iterdir()) == ["iyi.alt.pyc"]
        assert sorted(p.name for p in (tmp_path / "work").iterdir()) == ["PYZ.pyz_extracted"]
        assert sorted(p.name for p in tmp_path.iterdir()) == ["work"]

    def test_traversal_adi_cikti_kokunden_kacamaz(self, tmp_path: Path) -> None:
        """'../../x' ve mutlak yol: dosya members_dir dışına yazılmaz (NUL'suz, tek başına)."""
        out = tmp_path / "work" / "PYZ.pyz_extracted"
        files, rep = _extract(_build_pyz([
            ("../../kacis", 0, _z(_code())),
            (str(tmp_path / "mutlak"), 0, _z(_code())),
        ]), out)
        assert files == [] and rep["rejected"] == {"unsafe_name": 2}
        assert not (tmp_path / "kacis.pyc").exists()
        assert not (tmp_path / "mutlak.pyc").exists()
        assert list(out.iterdir()) == []

    def test_unicode_tanimlayici_ad_kabul(self, tmp_path: Path) -> None:
        files, _ = _extract(_build_pyz([("modül.çekirdek", 0, _z(_code()))]), tmp_path / "o")
        assert [f.path.name for f in files] == ["modül.çekirdek.pyc"]

    def test_harf_duyarsiz_cakisma_eki(self, tmp_path: Path) -> None:
        data = _build_pyz([("Foo", 0, _z(_code("a = 1\n"))), ("foo", 0, _z(_code("b = 2\n")))])
        files, _ = _extract(data, tmp_path / "o")
        assert [f.path.name for f in files] == ["Foo.pyc", "foo~2.pyc"]
        assert files[0].path.read_bytes() != files[1].path.read_bytes()

    def test_unique_casefold_name(self) -> None:
        used: set[str] = set()
        assert [unique_casefold_name(n, used) for n in ("a", "A", "a", "b")] == \
               ["a", "A~2", "a~3", "b"]

    def test_cikti_dizini_symlink_ise_yazmaz(self, tmp_path: Path) -> None:
        outside = tmp_path / "disari"
        outside.mkdir()
        link = tmp_path / "PYZ.pyz_extracted"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("symlink desteklenmiyor")
        files, rep = _extract(_build_pyz([("m", 0, _z(_code()))]), link)
        assert files == [] and "symlink" in (rep["error"] or "")
        assert list(outside.iterdir()) == []

    def test_dosya_symlink_ise_izlenmez(self, tmp_path: Path) -> None:
        out = tmp_path / "o"
        out.mkdir()
        target = tmp_path / "hedef.txt"
        target.write_bytes(b"ORIJINAL")
        try:
            (out / "m.pyc").symlink_to(target)
        except (OSError, NotImplementedError):
            pytest.skip("symlink desteklenmiyor")
        files, rep = _extract(_build_pyz([("m", 0, _z(_code()))]), out)
        assert files == [] and rep["rejected"] == {"write_failed": 1}
        assert target.read_bytes() == b"ORIJINAL"


# ---------------------------------------------------------------------------
# 6. Şifreli PYZ (PyInstaller < 6.0) tespiti
# ---------------------------------------------------------------------------

class TestEncrypted:
    @staticmethod
    def _sifreli_girdi() -> bytes:
        # 5.x yazıcısı: IV(16) + AES-CTR(zlib gövdesi) -- burada rastgele bayt.
        return os.urandom(16) + os.urandom(64)

    def test_baslik_bayragi_sifreli(self, tmp_path: Path) -> None:
        data = _build_pyz(
            [("gizli", 0, self._sifreli_girdi()), ("paket.alt", 0, self._sifreli_girdi())],
            crypt_flag=1,
        )
        assert parse_pyz(data).encrypted is True
        files, rep = _extract(data, tmp_path / "o")
        assert files == []
        assert rep["encrypted"] is True
        assert rep["encrypted_module_names"] == ["gizli", "paket.alt"]   # TOC şifresiz
        assert rep["rejected"] == {"encrypted": 2}
        assert not (tmp_path / "o").exists()

    def test_bayraksiz_ama_anahtar_modulu_varsa_cikarim(self, tmp_path: Path) -> None:
        data = _build_pyz([("gizli", 0, self._sifreli_girdi())], crypt_flag=0)
        files, rep = _extract(data, tmp_path / "o", crypto_key_present=True)
        assert files == [] and rep["encrypted"] is True
        assert rep["rejected"] == {"corrupt_zlib": 1}
        assert any("pyimod00_crypto_key" in e for e in rep["encryption_evidence"])

    def test_carchive_anahtar_modulu_ve_bayrak(self, tmp_path: Path, config: Config) -> None:
        pyz = _build_pyz([("gizli", 0, self._sifreli_girdi())], crypt_flag=1)
        blob, _ = _build_pyinstaller_blob([
            ("pyimod00_crypto_key", _code("key = '0123456789abcdef'\n"), ord("m")),
            ("PYZ-00.pyz", pyz, ord("z")),
        ])
        binp = tmp_path / "enc.bin"
        binp.write_bytes(blob)
        res = PyInstallerExtractor(config).extract(binp, tmp_path / "out")
        pyz_ef = next(ef for ef in res.extracted_files if ef.original_name == "PYZ-00.pyz")
        rep = pyz_ef.metadata["pyz"]
        assert rep["encrypted"] is True and len(rep["encryption_evidence"]) == 2
        assert any("PYZ şifreli" in e for e in res.errors)


# ---------------------------------------------------------------------------
# 7. .pyc yazımı (başlık onarımı) + politika sınıflandırması
# ---------------------------------------------------------------------------

class TestPycOutput:
    def test_bilinen_magic_ile_baslik_onarilir(self, tmp_path: Path) -> None:
        body = _code("def f():\n    return 42\n")
        files, rep = _extract(_build_pyz([("helper", 0, _z(body))]), tmp_path / "o")
        pyc = files[0].path.read_bytes()
        assert pyc == repair_pyc_header(body, "3.12")
        assert version_from_pyc_bytes(pyc) == "3.12"
        assert pyc[16:] == body                       # gövde değişmeden
        assert files[0].metadata["pyc_header"] == "pyz_magic"
        assert rep["python_version"] == "3.12"

    def test_bilinmeyen_magic_gövde_basliksiz_yazilir(self, tmp_path: Path) -> None:
        body = _code()
        unknown = struct.pack("<H", 3999) + b"\r\n"
        files, rep = _extract(_build_pyz([("m", 0, _z(body))], pymagic=unknown), tmp_path / "o")
        assert files[0].path.read_bytes() == body     # onarım aşağı akışta (static sürüm)
        assert files[0].metadata["pyc_header"] == "none"
        assert rep["python_version"] is None and rep["python_magic"] == unknown.hex()

    def test_metadata_kategori_ve_paket(self, tmp_path: Path) -> None:
        data = _build_pyz([
            ("helper", PYZ_ITEM_MODULE, _z(_code())),
            ("email.utils", PYZ_ITEM_MODULE, _z(_code())),
            ("_pyi_rth_utils", PYZ_ITEM_PKG, _z(_code())),
        ])
        files, _ = _extract(data, tmp_path / "o")
        meta = {f.original_name: f.metadata for f in files}
        assert meta["helper"]["module_category"] == "user"
        assert meta["email.utils"]["module_category"] == "stdlib"
        assert meta["_pyi_rth_utils"]["module_category"] == "pyinstaller"
        assert meta["_pyi_rth_utils"]["is_package"] is True
        assert all(f.file_type == "pyc" for f in files)

    @pytest.mark.parametrize("name,version,beklenen", [
        ("os", "3.12", "stdlib"),
        ("xml.etree.ElementTree", "3.12", "stdlib"),
        ("helper", "3.12", "user"),
        ("requests.adapters", "3.12", "user"),
        ("pyimod01_archive", "3.12", "pyinstaller"),
        ("pyi_splash", "3.12", "pyinstaller"),
        ("_pyi_rth_utils.qt", "3.12", "pyinstaller"),
        # Sürüm farkı tablosu: hedef sürüme göre karar.
        ("tomllib", "3.10", "user"), ("tomllib", "3.11", "stdlib"),
        ("parser", "3.9", "stdlib"), ("parser", "3.12", "user"),
        ("distutils.core", "3.11", "stdlib"), ("distutils.core", "3.12", "user"),
        ("cgi", "3.12", "stdlib"), ("cgi", "3.13", "user"),
        ("compression.zstd", "3.12", "user"), ("compression.zstd", "3.14", "stdlib"),
        ("_pyrepl", "3.12", "user"), ("_pyrepl", "3.13", "stdlib"),
    ])
    def test_siniflandirma(self, name: str, version: str, beklenen: str) -> None:
        assert classify_pyz_module(name, version) == beklenen

    def test_surum_yoksa_calisan_yorumlayici(self) -> None:
        assert classify_pyz_module("json", None) == "stdlib"
        assert classify_pyz_module("helper", None) == "user"


# ---------------------------------------------------------------------------
# 8. PyInstallerExtractor + python_binary entegrasyonu
# ---------------------------------------------------------------------------

def _pyinstaller_binary(tmp_path: Path, *, with_user: bool = True) -> Path:
    """CArchive: betik 's' + PYZ 'z' (user + stdlib + PyInstaller modülü)."""
    magic = importlib.util.MAGIC_NUMBER
    members = [
        ("json", PYZ_ITEM_PKG, _z(_code("", "json"))),
        ("_pyi_rth_utils", PYZ_ITEM_PKG, _z(_code("", "_pyi_rth_utils"))),
    ]
    if with_user:
        members.insert(0, ("helper", PYZ_ITEM_MODULE,
                           _z(_code("def yardim(x):\n    return x * 2\n", "helper"))))
    pyz = _build_pyz(members, pymagic=magic)
    blob, _ = _build_pyinstaller_blob([
        ("app", _code("import helper\n", "app"), ord("s")),
        ("PYZ.pyz", pyz, ord("z")),
    ])
    # static aşamanın PyInstaller'ı tanıması için bootloader işareti
    binp = tmp_path / "app"
    binp.write_bytes(b"_MEIPASS\x00" + blob)
    return binp


class TestIntegration:
    def test_extractor_pyz_modullerini_cikarir(
        self, tmp_path: Path, config: Config, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        seen: list[str] = []

        def fake_try(pyc_files: list[ExtractedFile], out: Path) -> list[ExtractedFile]:
            seen.extend(ef.original_name for ef in pyc_files)
            return []

        monkeypatch.setattr(PyInstallerExtractor, "_try_decompile_pyc_files",
                            staticmethod(fake_try))
        res = PyInstallerExtractor(config).extract(_pyinstaller_binary(tmp_path), tmp_path / "out")
        members = {ef.original_name: ef for ef in res.extracted_files
                   if ef.metadata.get("pyz_module")}
        assert set(members) == {"helper", "json", "_pyi_rth_utils"}
        assert members["helper"].path.parent == tmp_path / "out" / "PYZ.pyz_extracted"
        pyz_ef = next(ef for ef in res.extracted_files if ef.original_name == "PYZ.pyz")
        assert pyz_ef.metadata["pyz"]["modules_extracted"] == 3
        # Eski uncompyle6 yoluna da yalnız CArchive .pyc'leri + kullanıcı modülleri gider.
        assert sorted(seen) == ["app", "helper"]

    def test_reconstruct_manifest_pyz_politikasi(self, tmp_path: Path, config: Config,
                                                 monkeypatch: pytest.MonkeyPatch) -> None:
        from karadul.analyzers import pyc_decompiler as pd
        from karadul.analyzers.python_binary import PythonBinaryAnalyzer
        from karadul.core.target import Language, TargetInfo, TargetType
        from karadul.core.workspace import Workspace

        monkeypatch.setattr(pd, "resolve_tool", lambda name, **k: None)   # pycdc yok
        binp = _pyinstaller_binary(tmp_path)
        target = TargetInfo(
            path=binp, name="app", target_type=TargetType.PYTHON_PACKED,
            language=Language.PYTHON, file_size=binp.stat().st_size, file_hash="x",
        )
        ws = Workspace(tmp_path / "ws", "pyz")
        ws.create()
        an = PythonBinaryAnalyzer(config)
        an.analyze_static(target, ws)
        res = an.reconstruct(target, ws)
        assert res is not None and res.success
        proj = res.artifacts["python_project"]
        manifest = json.loads((proj / "manifest.json").read_text())
        pyz = manifest["pyz"]
        assert (pyz["modules_extracted"], pyz["decompile_chain"],
                pyz["skipped_stdlib"], pyz["skipped_pyinstaller"]) == (3, 1, 1, 1)
        # Zincire: CArchive betiği "app" + PYZ kullanıcı modülü "helper" (stdlib/PyInstaller değil).
        assert manifest["decompile"]["total_pyc"] == 2
        assert "PYZ: 3 modül çıkarıldı" in manifest["note"]
        listing = json.loads((proj / "pyz_modules.json").read_text())
        assert {m["name"]: m["category"] for m in listing["modules"]} == {
            "helper": "user", "json": "stdlib", "_pyi_rth_utils": "pyinstaller",
        }
        src = sorted(p.name for p in (proj / "source").iterdir())
        assert any(n.startswith("helper.") for n in src)
        assert not any(n.startswith("json.") for n in src)

    def test_pyz_surumu_static_tahminden_once_gelir(self, tmp_path: Path, config: Config,
                                                    monkeypatch: pytest.MonkeyPatch) -> None:
        """Başlıksız CArchive betiği, static tahmin yanlış olsa da PYZ sürümüyle onarılır."""
        from karadul.analyzers import pyc_decompiler as pd
        from karadul.analyzers.python_binary import PythonBinaryAnalyzer
        from karadul.core.target import Language, TargetInfo, TargetType
        from karadul.core.workspace import Workspace

        monkeypatch.setattr(pd, "resolve_tool", lambda name, **k: None)   # yalnız stdlib dis
        binp = _pyinstaller_binary(tmp_path, with_user=False)   # zincirde başlıklı .pyc yok
        target = TargetInfo(
            path=binp, name="app", target_type=TargetType.PYTHON_PACKED,
            language=Language.PYTHON, file_size=binp.stat().st_size, file_hash="x",
        )
        ws = Workspace(tmp_path / "ws", "pyzv")
        ws.create()
        an = PythonBinaryAnalyzer(config)
        an.analyze_static(target, ws)
        wrong = "3.8" if RUNNING != "3.8" else "3.9"
        ws.save_json("static", "python_version", {"version": wrong})   # yanlış sezgi
        res = an.reconstruct(target, ws)
        manifest = json.loads((res.artifacts["python_project"] / "manifest.json").read_text())
        if manifest["pyz"]["python_version"] != RUNNING:
            pytest.skip("çalışan yorumlayıcının magic'i tabloda yok")
        # Tek .pyc (betik "app") PYZ'nin sürümüyle onarıldı -> aynı sürüm dis çalıştı.
        assert manifest["decompile"]["total_pyc"] == 1
        assert manifest["decompile"]["disasm"] == 1
        assert manifest["decompile"]["failed"] == 0


class TestManifestNotes:
    def test_not_bos_sifreli_okunamayan(self) -> None:
        from karadul.analyzers.python_binary import _pyz_note
        assert _pyz_note({}) == ""
        assert "şifreli" in _pyz_note({"encrypted": True, "archives": [{}]})
        assert "okunamadı" in _pyz_note({"encrypted": False, "archives": [{"error": "x"}]})

    def test_reconstruct_sifreli_pyz_adlari_listeler(self, tmp_path: Path, config: Config,
                                                     monkeypatch: pytest.MonkeyPatch) -> None:
        from karadul.analyzers import pyc_decompiler as pd
        from karadul.analyzers.python_binary import PythonBinaryAnalyzer
        from karadul.core.target import Language, TargetInfo, TargetType
        from karadul.core.workspace import Workspace

        monkeypatch.setattr(pd, "resolve_tool", lambda name, **k: None)
        pyz = _build_pyz([("gizli.cekirdek", 0, os.urandom(80))], crypt_flag=1,
                         pymagic=importlib.util.MAGIC_NUMBER)
        blob, _ = _build_pyinstaller_blob([
            ("pyimod00_crypto_key", _code("key = 'k'\n"), ord("m")),
            ("PYZ-00.pyz", pyz, ord("z")),
        ])
        binp = tmp_path / "enc"
        binp.write_bytes(b"_MEIPASS\x00" + blob)
        target = TargetInfo(
            path=binp, name="enc", target_type=TargetType.PYTHON_PACKED,
            language=Language.PYTHON, file_size=binp.stat().st_size, file_hash="x",
        )
        ws = Workspace(tmp_path / "ws", "enc")
        ws.create()
        an = PythonBinaryAnalyzer(config)
        an.analyze_static(target, ws)
        res = an.reconstruct(target, ws)
        proj = res.artifacts["python_project"]
        manifest = json.loads((proj / "manifest.json").read_text())
        assert manifest["pyz"]["encrypted"] is True
        assert manifest["pyz"]["modules_extracted"] == 0
        assert "şifreli" in manifest["note"]
        assert "encrypted_module_names" not in manifest["pyz"]["archives"][0]
        listing = json.loads((proj / "pyz_modules.json").read_text())
        assert listing["archives"][0]["encrypted_module_names"] == ["gizli.cekirdek"]


@pytest.mark.skipif(not REAL_APP.is_file(), reason=f"gerçek binary yok: {REAL_APP}")
def test_gercek_pyinstaller_612_helper_pyz_icinden_cikar(tmp_path: Path, config: Config) -> None:
    """PyInstaller 6.15 + Python 3.12.7 binary'si: 'helper' yalnız PYZ'de durur."""
    res = PyInstallerExtractor(config).extract(REAL_APP, tmp_path / "out")
    members = {ef.original_name: ef for ef in res.extracted_files
               if ef.metadata.get("pyz_module")}
    assert "helper" in members
    helper = members["helper"]
    assert helper.metadata["module_category"] == "user"
    assert version_from_pyc_bytes(helper.path.read_bytes()) == "3.12"
    users = [n for n, ef in members.items() if ef.metadata["module_category"] == "user"]
    assert users == ["helper"]
    pyz_ef = next(ef for ef in res.extracted_files if ef.original_name == "PYZ.pyz")
    assert pyz_ef.metadata["pyz"]["rejected"] == {}
    assert pyz_ef.metadata["pyz"]["modules_extracted"] == len(members)
