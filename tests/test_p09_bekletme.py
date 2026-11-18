"""P09 Kalem 1 — yapı kurtarmada bekletme (K-1, TIP-07 / ARAYUZ-18).

K-1 (Berke, 2026-11-18): yapı kurtarma onarılıp ölçülene kadar iddiası koda ve ``types.h``'ye
yazılmaz; katman koşar, sonucu ayrı yere yazılır.

Taban (ddf8b19, G seti 14 ikili): ``types.h``'de binlerce ``recovered_struct``, koda bağlanan
yok denecek kadar az, her alanda sabit ``confidence: 0.80``. Bu testler:

- koda bağlanmayan yapının ``types.h``'ye girmediğini, ``types_candidates.txt``'ye "doğrulanmamış
  aday" başlığıyla yazıldığını;
- ``types.h``'de ve aday dosyasında sabit 0,80 güvenin olmadığını;
- sonuç nesnesinin (rapor sayacı ``structs_recovered`` buradan okunur) bağlanmamış yapıları
  saymadığını
kilitler.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from karadul.config import Config
from karadul.reconstruction import c_type_recoverer as ctr
from karadul.reconstruction.c_type_recoverer import CTypeRecoverer


def _yaz(d: Path, ad: str, govde: str) -> None:
    (d / f"{ad}.c").write_text(govde, encoding="utf-8")


def _kos(tmp_path: Path, dosyalar: dict[str, str]):
    dec = tmp_path / "dec"
    dec.mkdir()
    for ad, govde in dosyalar.items():
        _yaz(dec, ad, govde)
    fj = tmp_path / "functions.json"
    fj.write_text(json.dumps({"functions": []}), encoding="utf-8")
    out = tmp_path / "out"
    sonuc = CTypeRecoverer(Config()).recover(dec, fj, out)
    assert sonuc.success, sonuc.errors
    return sonuc, out


# Taban: ``long param_1`` bildirimi bağlanmaz (``_apply_struct_types`` yalnız ``undefined8``'i
# değiştirir); iki ofsetteki erişim yine de yapı sentezler.
BAGSIZ = (
    "long FUN_00001000(long param_1)\n"
    "{\n"
    "  *(int *)(param_1 + 8) = 1;\n"
    "  *(long *)(param_1 + 0x10) = 2;\n"
    "  return param_1;\n"
    "}\n"
)


def test_bagsiz_yapi_types_h_ye_girmez(tmp_path: Path) -> None:
    sonuc, out = _kos(tmp_path, {"FUN_00001000": BAGSIZ})
    th = (out / "types.h").read_text(encoding="utf-8")
    assert "recovered_struct" not in th
    aday = out / ctr.STRUCT_CANDIDATES_FILENAME
    assert aday.exists()
    metin = aday.read_text(encoding="utf-8")
    assert "doğrulanmamış aday, koda bağlanmadı" in metin.split("\n", 3)[1] + metin[:200]
    assert "struct recovered_struct_001 {" in metin
    # Sonuç nesnesi bağlanmamış yapıyı saymaz; aday listesinde taşır.
    assert [s.name for s in sonuc.structs] == []
    assert [s.name for s in sonuc.struct_candidates] == ["recovered_struct_001"]
    assert sonuc.total_types_recovered == 0
    assert sonuc.struct_candidates_file == aday


def test_aday_dosyasi_kod_disinda(tmp_path: Path) -> None:
    _, out = _kos(tmp_path, {"FUN_00001000": BAGSIZ})
    ad = ctr.STRUCT_CANDIDATES_FILENAME
    # Sonraki adımlar ``*.c``/``*.h`` tarar (c_comment_generator, output_formatter): aday
    # dosyası bu uzantıları taşımaz ve hiçbir C dosyası onu içermez.
    assert not ad.endswith((".c", ".h"))
    for c in out.glob("*.c"):
        assert ad not in c.read_text(encoding="utf-8")


def test_sabit_080_guven_yok(tmp_path: Path) -> None:
    _, out = _kos(tmp_path, {"FUN_00001000": BAGSIZ})
    for f in (out / "types.h", out / ctr.STRUCT_CANDIDATES_FILENAME):
        metin = f.read_text(encoding="utf-8")
        assert "confidence: 0.80" not in metin
        assert "confidence: 0.30" not in metin
        assert "confidence: 0.20" not in metin


def test_aday_alani_kanit_sayisini_yazar(tmp_path: Path) -> None:
    # Aynı ofsete iki erişim: kanıt sayısı 2.
    govde = BAGSIZ.replace(
        "  return param_1;", "  *(int *)(param_1 + 8) = 3;\n  return param_1;")
    _, out = _kos(tmp_path, {"FUN_00001000": govde})
    metin = (out / ctr.STRUCT_CANDIDATES_FILENAME).read_text(encoding="utf-8")
    satir = next(s for s in metin.split("\n") if "/* 0x08 */" in s)
    assert "erişim: 2" in satir
    satir = next(s for s in metin.split("\n") if "/* 0x10 */" in s)
    assert "erişim: 1" in satir


def test_yapi_yoksa_aday_dosyasi_yazilmaz(tmp_path: Path) -> None:
    sonuc, out = _kos(tmp_path, {"FUN_00001000": "int FUN_00001000(void)\n{\n  return 0;\n}\n"})
    assert not (out / ctr.STRUCT_CANDIDATES_FILENAME).exists()
    assert sonuc.struct_candidates == []
    assert sonuc.struct_candidates_file is None


@pytest.mark.parametrize("ghidra_alan_sayisi", [2])
def test_ghidra_yapilari_types_h_de_kalir(tmp_path: Path, ghidra_alan_sayisi: int) -> None:
    """Ghidra'nın kendi yapıları (ghidra_types.json) Karadul iddiası değil; types.h'de kalır."""
    dec = tmp_path / "dec"
    dec.mkdir()
    _yaz(dec, "FUN_00001000", BAGSIZ)
    fj = tmp_path / "functions.json"
    fj.write_text(json.dumps({"functions": []}), encoding="utf-8")
    gt = tmp_path / "types.json"
    gt.write_text(json.dumps({"structures": [{"name": "stat", "size": 16, "fields": [
        {"name": "st_dev", "type": "ulong", "offset": 0, "size": 8},
        {"name": "st_ino", "type": "ulong", "offset": 8, "size": 8},
    ][:ghidra_alan_sayisi]}]}), encoding="utf-8")
    out = tmp_path / "out"
    sonuc = CTypeRecoverer(Config()).recover(dec, fj, out, ghidra_types_json=gt)
    th = (out / "types.h").read_text(encoding="utf-8")
    assert "struct stat {" in th
    assert "recovered_struct" not in th
    assert [s.name for s in sonuc.structs] == ["stat"]


def test_types_h_deki_her_kurtarilan_yapi_kodda_kullanilir(tmp_path: Path) -> None:
    """Değişmez: types.h'deki her ``recovered_struct`` en az bir C dosyasının KODUNDA geçer.

    İki fonksiyon: biri bağlanabilir bildirimle (``undefined8``), biri bağlanamaz (``long``).
    Hangi yapının bağlandığından bağımsız olarak types.h yalnız kullanılanları taşır.
    """
    import re as _re

    bagli = (
        "void FUN_00002000(undefined8 param_9)\n"
        "{\n"
        "  *(int *)(param_9 + 8) = 1;\n"
        "  *(long *)(param_9 + 0x10) = 2;\n"
        "  return;\n"
        "}\n"
    )
    sonuc, out = _kos(tmp_path, {"FUN_00001000": BAGSIZ, "FUN_00002000": bagli})
    th = (out / "types.h").read_text(encoding="utf-8")
    tanimli = set(_re.findall(r"^struct (recovered_struct_\d+) \{", th, _re.M))
    kodda: set[str] = set()
    for c in out.glob("*.c"):
        kod = ctr._C_NONCODE_TOKEN.sub(" ", c.read_text(encoding="utf-8"))
        kodda.update(_re.findall(r"recovered_struct_\d+", kod))
    assert tanimli <= kodda
    assert {s.name for s in sonuc.structs} == tanimli
    # Bağlanamayan (long param_1) yapı her durumda adaydır.
    assert any("FUN_00001000" in s.source_functions for s in sonuc.struct_candidates)
