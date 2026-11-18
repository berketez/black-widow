"""P09 Kalem 2 — TIP-07 onarımı: yapı kurtarmada anahtar, ölçek, örtüşme, bağlama.

Taban (ddf8b19): erişimler yalnız değişken ADIYLA birleşiyordu (ilgisiz fonksiyonların
``param_1``'leri tek yapı), ofset tabanın işaretçi tipine göre ölçeklenmiyordu
(``uint64_t *p; *(int *)(p + 1)`` → ofset 1), üst üste binen alanlar denetlenmiyordu
(G setinde 4 109 yapının 582'si) ve bağlama ``undefined8 p`` → ``recovered_struct_N * p``
yapıp erişim metnini bırakıyordu (C'de tamsayı aritmetiği işaretçi aritmetiğine döner).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from karadul.config import Config
from karadul.reconstruction import c_type_recoverer as ctr
from karadul.reconstruction.c_type_recoverer import CTypeRecoverer, _parse_c_file_worker


def _kos(tmp_path: Path, dosyalar: dict[str, str]):
    dec = tmp_path / "dec"
    dec.mkdir()
    for ad, govde in dosyalar.items():
        (dec / f"{ad}.c").write_text(govde, encoding="utf-8")
    fj = tmp_path / "functions.json"
    fj.write_text(json.dumps({"functions": []}), encoding="utf-8")
    out = tmp_path / "out"
    sonuc = CTypeRecoverer(Config()).recover(dec, fj, out)
    assert sonuc.success, sonuc.errors
    return sonuc, out


def _alanlar(struct) -> dict[int, str]:
    return {f.offset: f.type for f in struct.fields if not f.name.startswith("padding_")}


def test_ofset_isaretci_tipine_gore_olceklenir(tmp_path: Path) -> None:
    govde = (
        "uint64_t FUN_0010ce08(uint64_t *param_1,int param_2)\n"
        "{\n"
        "  *(int *)(param_1 + 1) = param_2;\n"
        "  *(long *)(param_1 + 2) = 0;\n"
        "  return 0;\n"
        "}\n"
    )
    sonuc, _ = _kos(tmp_path, {"FUN_0010ce08": govde})
    [s] = sonuc.struct_candidates
    assert _alanlar(s) == {8: "int", 16: "long"}


def test_bayt_tabani_olceklenmez(tmp_path: Path) -> None:
    govde = (
        "void FUN_00001000(long param_1)\n"
        "{\n"
        "  *(int *)(param_1 + 8) = 1;\n"
        "  *(long *)(param_1 + 0x10) = 2;\n"
        "  return;\n"
        "}\n"
    )
    sonuc, _ = _kos(tmp_path, {"FUN_00001000": govde})
    [s] = sonuc.struct_candidates
    assert _alanlar(s) == {8: "int", 16: "long"}


def test_bildirimi_bilinmeyen_taban_kanit_sayilmaz(tmp_path: Path) -> None:
    # ``struct foo *`` öğe boyutu bilinmiyor: ``p + 1`` kaç bayt, söylenemez.
    govde = (
        "void FUN_00001000(struct foo *param_1)\n"
        "{\n"
        "  *(int *)(param_1 + 1) = 1;\n"
        "  *(int *)(param_1 + 2) = 2;\n"
        "  return;\n"
        "}\n"
    )
    sonuc, _ = _kos(tmp_path, {"FUN_00001000": govde})
    assert sonuc.struct_candidates == []
    assert sonuc.struct_unscaled_accesses == 2


def test_farkli_fonksiyonlarin_ayni_adli_degiskeni_birlesmez(tmp_path: Path) -> None:
    a = (
        "void FUN_00001000(long param_1)\n{\n"
        "  *(int *)(param_1 + 8) = 1;\n"
        "  *(int *)(param_1 + 0xc) = 1;\n"
        "  return;\n}\n"
    )
    b = (
        "void FUN_00002000(long param_1)\n{\n"
        "  *(long *)(param_1 + 0x40) = 1;\n"
        "  *(long *)(param_1 + 0x48) = 1;\n"
        "  return;\n}\n"
    )
    sonuc, _ = _kos(tmp_path, {"FUN_00001000": a, "FUN_00002000": b})
    yapilar = {tuple(s.source_functions): _alanlar(s) for s in sonuc.struct_candidates}
    assert yapilar == {
        ("FUN_00001000",): {8: "int", 12: "int"},
        ("FUN_00002000",): {64: "long", 72: "long"},
    }
    assert all(s.source_variable == "param_1" for s in sonuc.struct_candidates)


def test_ortusen_alanlar_yapi_uretmez(tmp_path: Path) -> None:
    # 1, 2, 3'te int: dört baytlık alanlar üst üste biner (zstd örneği, TIP-07).
    govde = (
        "void FUN_00001000(long param_1)\n{\n"
        "  *(int *)(param_1 + 1) = 1;\n"
        "  *(int *)(param_1 + 2) = 1;\n"
        "  *(int *)(param_1 + 3) = 1;\n"
        "  return;\n}\n"
    )
    sonuc, out = _kos(tmp_path, {"FUN_00001000": govde})
    assert sonuc.struct_candidates == []
    assert sonuc.struct_conflicts == 1


def test_ayni_ofsete_farkli_genislik_yapi_uretmez(tmp_path: Path) -> None:
    govde = (
        "void FUN_00001000(long param_1)\n{\n"
        "  *(int *)(param_1 + 8) = 1;\n"
        "  *(long *)(param_1 + 8) = 1;\n"
        "  *(long *)(param_1 + 0x10) = 1;\n"
        "  return;\n}\n"
    )
    sonuc, _ = _kos(tmp_path, {"FUN_00001000": govde})
    assert sonuc.struct_candidates == []
    assert sonuc.struct_conflicts == 1


def test_bagalama_bildirimi_degistirmez(tmp_path: Path) -> None:
    """Eski bağlama ``undefined8 param_1`` → ``recovered_struct_001 * param_1`` yazıyor,
    ``*(int *)(param_1 + 8)``'i bırakıyordu (C'de ``param_1 + 8`` = 8 * sizeof(yapı) bayt)."""
    govde = (
        "void FUN_00001000(undefined8 param_1)\n{\n"
        "  *(int *)(param_1 + 8) = 1;\n"
        "  *(long *)(param_1 + 0x10) = 2;\n"
        "  return;\n}\n"
    )
    sonuc, out = _kos(tmp_path, {"FUN_00001000": govde})
    kod = (out / "FUN_00001000.c").read_text(encoding="utf-8")
    assert "recovered_struct" not in kod
    assert "recovered_struct" not in (out / "types.h").read_text(encoding="utf-8")
    [s] = sonuc.struct_candidates
    aday = (out / ctr.STRUCT_CANDIDATES_FILENAME).read_text(encoding="utf-8")
    assert "Kaynak: FUN_00001000 / param_1 (bildirim: undefined8)" in aday


def test_fonksiyon_tanimi_sutun_sifirdan(tmp_path: Path) -> None:
    """``  return foo(x);``, ``else if (x)`` ve girintili yerel prototip tanım sayılmaz.

    Eski kod girintisi atılmış satıra bakıyordu: ``return foo(x);`` -> fonksiyon ``foo``;
    sonraki erişim ve etiketler yanlış fonksiyona yazılıyordu.
    """
    f = tmp_path / "FUN_00001000.c"
    f.write_text(
        "long FUN_00001000(long param_1)\n{\n"
        "  int FUN_00007777(long x);\n"
        "  if (param_1 == 0) {\n    return FUN_00009999(param_1);\n  }\n"
        "  else if (param_1 == 1) {\n    return 2;\n  }\n"
        "  *(int *)(param_1 + 8) = 1;\n"
        "return FUN_00008888(param_1);\n"
        "  *(int *)(param_1 + 0xc) = 1;\n"
        "}\n",
        encoding="utf-8",
    )
    r = _parse_c_file_worker(str(f))
    assert {acc[3] for acc in r["field_accesses"]} == {"FUN_00001000"}
    assert r["declared_types"] == {"FUN_00001000": {"param_1": "long"}}


def test_bildirimsiz_taban_kanit_sayilmaz(tmp_path: Path) -> None:
    """Fonksiyonda bildirimi olmayan taban (``unaff_x19``, genel ``DAT_``) ölçeklenemez."""
    govde = (
        "void FUN_00001000(void)\n{\n"
        "  *(int *)(unaff_x19 + 8) = 1;\n"
        "  *(long *)(unaff_x19 + 0x10) = 2;\n"
        "  return;\n}\n"
    )
    sonuc, _ = _kos(tmp_path, {"FUN_00001000": govde})
    assert sonuc.struct_candidates == []
    assert sonuc.struct_unscaled_accesses == 2


def test_aday_dosyasinda_ortusen_yapi_yok_gercekci(tmp_path: Path) -> None:
    """Karışık girdi: aday dosyasındaki her yapının alanları üst üste binmez."""
    govde = (
        "void FUN_00001000(uint32_t *param_1,long param_2)\n{\n"
        "  uint64_t *puVar1;\n"
        "  *(int *)(param_1 + 1) = 1;\n"
        "  *(int *)(param_1 + 2) = 1;\n"
        "  *(int *)(param_2 + 1) = 1;\n"
        "  *(int *)(param_2 + 2) = 1;\n"
        "  *(char *)(puVar1 + 1) = 1;\n"
        "  *(long *)(puVar1 + 2) = 1;\n"
        "  return;\n}\n"
    )
    sonuc, out = _kos(tmp_path, {"FUN_00001000": govde})
    for s in sonuc.struct_candidates:
        alanlar = sorted((f.offset, f.size) for f in s.fields)
        for (o1, b1), (o2, _) in zip(alanlar, alanlar[1:]):
            assert o2 >= o1 + b1, (s.source_variable, alanlar)
    assert {s.source_variable for s in sonuc.struct_candidates} == {"param_1", "puVar1"}
    assert sonuc.struct_conflicts == 1  # param_2: 1 ve 2'de int
    assert re.search(r"Kaynak: FUN_00001000 / puVar1 \(bildirim: uint64_t \*\)",
                     (out / ctr.STRUCT_CANDIDATES_FILENAME).read_text(encoding="utf-8"))
