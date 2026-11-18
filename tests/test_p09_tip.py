"""P09 Kalem 3 — TIP-06 / TIP-11: tip etiketleri (fonksiyon, değişken) ile, desenler dizgi ve
yorum örtüldükten sonra, Ghidra'nın somut tipi yalnız aynı genişlikte ve daha bilgili tiple.

Taban (ddf8b19): etiketler yalnız ADA göre birleşiyordu (A'daki ``strlen(uVar1)`` B'nin
``uVar1``'ini ``char *`` yapıyordu); ``x = f(x, "8.0.2", 5)`` satırı ``x``'i ``double``
yapıyordu (redis ``double sdsnewlen_ret_164``); XTRIDE ``long lVar1``'i ``"version 2.5"``
yüzünden ``double``'a, ``& 0xffffffff`` yüzünden ``uint32_t``'ye çeviriyordu.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from karadul.config import Config
from karadul.pipeline.steps._feedback_typing_extras import (
    run_xtride_typing,
    xtride_replacement_ok,
)
from karadul.reconstruction.c_type_recoverer import (
    CTypeRecoverer,
    float_literal_target,
    mask_noncode,
)
from karadul.reconstruction.xtride_typer import XTrideTyper


def _kos(tmp_path: Path, dosyalar: dict[str, str]) -> dict[str, str]:
    dec = tmp_path / "dec"
    dec.mkdir()
    for ad, govde in dosyalar.items():
        (dec / f"{ad}.c").write_text(govde, encoding="utf-8")
    fj = tmp_path / "functions.json"
    fj.write_text(json.dumps({"functions": []}), encoding="utf-8")
    out = tmp_path / "out"
    sonuc = CTypeRecoverer(Config()).recover(dec, fj, out)
    assert sonuc.success, sonuc.errors
    return {ad: (out / f"{ad}.c").read_text(encoding="utf-8") for ad in dosyalar}


def _bildirim(metin: str, var: str) -> str:
    m = re.search(r"^\s+(.+?)\s*\b" + re.escape(var) + r";", metin, re.M)
    assert m, (var, metin)
    return m.group(1).strip()


# kulvar_TIP.md TIP-06 "Kanıt": üç küçük dosya
UC_DOSYA = {
    "FUN_00001000": (
        "undefined8 FUN_00001000(undefined8 param_1)\n{\n"
        "  undefined8 uVar1;\n\n"
        "  uVar1 = FUN_00003000(param_1);\n"
        "  return uVar1;\n}\n"
    ),
    "FUN_00002000": (
        "void FUN_00002000(undefined8 param_1)\n{\n"
        "  undefined8 uVar1;\n\n"
        "  uVar1 = FUN_00004000(param_1);\n"
        "  strlen(uVar1);\n"
        "  return;\n}\n"
    ),
    "FUN_00005000": (
        "void FUN_00005000(void)\n{\n"
        "  undefined8 uVar2;\n\n"
        "  uVar2 = FUN_00006000(\"libfoo 1.2 ready\");\n"
        "  FUN_00007000(uVar2);\n"
        "  return;\n}\n"
    ),
}


def test_kanit_kendi_fonksiyonuna_yazilir(tmp_path: Path) -> None:
    out = _kos(tmp_path, UC_DOSYA)
    assert _bildirim(out["FUN_00002000"], "uVar1") == "char *"
    assert _bildirim(out["FUN_00001000"], "uVar1") != "char *"


def test_dizgideki_surum_metni_double_yapmaz(tmp_path: Path) -> None:
    out = _kos(tmp_path, UC_DOSYA)
    assert "double" not in _bildirim(out["FUN_00005000"], "uVar2")


def test_redis_sds_ornegi(tmp_path: Path) -> None:
    """``lolwutUnstableCommand``: sds dizgisi ``"8.0.2"`` yüzünden ``double`` oluyordu."""
    govde = (
        "void lolwutUnstableCommand(undefined8 param_1)\n{\n"
        "  undefined8 sdsnewlen_ret_164;\n\n"
        "  sdsnewlen_ret_164 = _sdsnewlen(\"Redis ver. \",0xb,0);\n"
        "  sdsnewlen_ret_164 = sdscatlen(sdsnewlen_ret_164,\"8.0.2\",5);\n"
        "  addReplyVerbatim(param_1,sdsnewlen_ret_164);\n"
        "  return;\n}\n"
    )
    out = _kos(tmp_path, {"lolwutUnstableCommand": govde})
    assert "double" not in _bildirim(out["lolwutUnstableCommand"], "sdsnewlen_ret_164")


def test_dizgideki_cagri_metni_kanit_degil(tmp_path: Path) -> None:
    """Dizgi içindeki ``strlen(uVar2)`` metni ``string_func_arg`` kanıtı değildir."""
    govde = (
        "void FUN_00001000(void)\n{\n"
        "  undefined8 uVar2;\n\n"
        "  uVar2 = FUN_00003000();\n"
        "  FUN_00002000(\"strlen(uVar2) failed\");\n"
        "  return;\n}\n"
    )
    out = _kos(tmp_path, {"FUN_00001000": govde})
    assert _bildirim(out["FUN_00001000"], "uVar2") != "char *"


def test_genislik_uyumsuz_tip_yazilmaz(tmp_path: Path) -> None:
    govde = (
        "void FUN_00001000(void)\n{\n"
        "  undefined4 uVar1;\n\n"
        "  uVar1 = FUN_00002000();\n"
        "  strlen(uVar1);\n"
        "  return;\n}\n"
    )
    out = _kos(tmp_path, {"FUN_00001000": govde})
    # 4 baytlık bilinmeyene 8 baytlık işaretçi yazılmaz (öntanım int32_t kalır).
    assert _bildirim(out["FUN_00001000"], "uVar1") == "int32_t"


def test_ghidra_yuksek_degisken_tipi_genislige_uyar(tmp_path: Path) -> None:
    """Katman 2e: ``undefined8 uVar22`` bildirimine Ghidra'nın ``uint``'i (4 bayt) yazılmaz;
    ``undefined4``'e işaretçi yazılmaz; aynı genişlikteki ``size_t`` yazılır (G setinde ls,
    sort, pzstd'de 3 örnek)."""
    dec = tmp_path / "dec"
    dec.mkdir()
    (dec / "FUN_00001000.c").write_text(
        "void FUN_00001000(void)\n{\n"
        "  undefined8 uVar22;\n  undefined4 uVar5;\n  undefined8 uVar7;\n\n"
        "  uVar22 = FUN_2();\n  uVar5 = FUN_3();\n  uVar7 = FUN_4();\n"
        "  FUN_5(uVar22, uVar5, uVar7);\n  return;\n}\n", encoding="utf-8")
    fj = tmp_path / "functions.json"
    fj.write_text(json.dumps({"functions": []}), encoding="utf-8")
    dj = tmp_path / "decompiled.json"
    dj.write_text(json.dumps({"functions": [{"name": "FUN_00001000", "pcode_high_vars": [
        {"name": "uVar22", "type": "uint"},
        {"name": "uVar5", "type": "char *"},
        {"name": "uVar7", "type": "size_t"},
    ]}]}), encoding="utf-8")
    out = tmp_path / "out"
    CTypeRecoverer(Config()).recover(dec, fj, out, decompiled_json=dj)
    metin = (out / "FUN_00001000.c").read_text(encoding="utf-8")
    assert _bildirim(metin, "uVar22") == "uint64_t"
    assert _bildirim(metin, "uVar5") == "int32_t"
    assert _bildirim(metin, "uVar7") == "size_t"


def test_gercek_kayan_nokta_korunur(tmp_path: Path) -> None:
    govde = (
        "void FUN_00001000(void)\n{\n"
        "  undefined8 dVar1;\n\n"
        "  dVar1 = 2.5;\n"
        "  FUN_00002000(dVar1);\n"
        "  return;\n}\n"
    )
    out = _kos(tmp_path, {"FUN_00001000": govde})
    assert _bildirim(out["FUN_00001000"], "dVar1") == "double"


@pytest.mark.parametrize(
    ("satir", "hedef"),
    [
        ("x = 2.5;", "x"),
        ("dVar1 = (double)lVar2 * 0.5;", "dVar1"),
        ("x = f(y, 2.5);", None),
        ("if (a == 1.5) {", None),
        ("x = f(x, \"8.0.2\", 5);", None),
        ("x = 1.0e-5;", "x"),
        ("x = y + 0x10;", None),
    ],
)
def test_float_literal_target(satir: str, hedef: str | None) -> None:
    assert float_literal_target(mask_noncode(satir)) == hedef


def test_mask_noncode_uzunluk_ve_karakter_sabiti() -> None:
    metin = 'a = "8.0.2"; /* 1.5 */ c = \'.\'; // 2.5\nb = 1;'
    ort = mask_noncode(metin)
    assert len(ort) == len(metin)
    assert ort.count("\n") == 1
    assert "8.0.2" not in ort and "1.5" not in ort and "2.5" not in ort
    assert "'.'" in ort and '"     "' in ort


# --- XTRIDE (TIP-11) ---

def test_xtride_dizgideki_kayan_nokta_kanit_degil() -> None:
    kod = (
        "long FUN_00001000(undefined8 param_1)\n{\n"
        "  long lVar1;\n"
        "  lVar1 = FUN_00002000(param_1,\"version 2.5\");\n"
        "  return lVar1;\n}\n"
    )
    inf = XTrideTyper().infer_types(kod).inferences
    assert "lVar1" not in inf or inf["lVar1"].inferred_type != "double"


def test_xtride_dizgideki_cagri_kanit_degil() -> None:
    """Dizgi içindeki ``strlen(uVar4)`` metni API parametre kanıtı değildir."""
    kod = (
        "void FUN_00001000(void)\n{\n"
        "  undefined8 uVar4;\n"
        "  local_10 = \"strlen(uVar4)\";\n"
        "  return;\n}\n"
    )
    assert "uVar4" not in XTrideTyper().infer_types(kod).inferences


def test_xtride_gercek_kayan_nokta() -> None:
    kod = "void FUN_1(void)\n{\n  undefined8 dVar1;\n  dVar1 = 2.5;\n  return;\n}\n"
    assert XTrideTyper().infer_types(kod).inferences["dVar1"].inferred_type == "double"


@pytest.mark.parametrize(
    ("eski", "yeni", "beklenen"),
    [
        ("long", "double", False),
        ("long", "uint32_t", False),
        ("ulong", "uint32_t", False),
        ("long", "char *", True),
        ("ulong", "void *", True),
        ("undefined4", "int", True),
        ("undefined4", "char *", False),
        ("undefined8", "uint32_t", False),
        ("undefined8", "FILE *", True),
        ("undefined8", "struct", False),
        ("undefined", "char *", False),
    ],
)
def test_xtride_degisim_kurali(eski: str, yeni: str, beklenen: bool) -> None:
    assert xtride_replacement_ok(eski, yeni) is beklenen


def test_xtride_uygulayici_somut_tipi_ezmez(tmp_path: Path) -> None:
    d = tmp_path / "typed"
    d.mkdir()
    (d / "FUN_00001000.c").write_text(
        "long FUN_00001000(undefined8 param_1)\n{\n"
        "  long lVar1;\n"
        "  ulong uVar2;\n"
        "  undefined8 uVar3;\n"
        "  lVar1 = FUN_00002000(param_1,\"version 2.5\");\n"
        "  uVar2 = (ulong)(param_1 & 0xffffffff);\n"
        "  uVar2 = uVar2 & 0xffffffff;\n"
        "  uVar3 = strdup(\"a\");\n"
        "  return lVar1 + uVar2;\n}\n",
        encoding="utf-8",
    )
    ctx = SimpleNamespace(pipeline_context=SimpleNamespace(config=Config()))
    stats: dict = {}
    run_xtride_typing(ctx=ctx, iter_index=0, decompiled_dir=d, incremental_files=None,
                      stats=stats, errors=[])
    metin = (d / "FUN_00001000.c").read_text(encoding="utf-8")
    assert "  long lVar1;" in metin
    assert "  ulong uVar2;" in metin
    assert "  char * uVar3;" in metin or "  char *uVar3;" in metin
    assert stats["xtride_rejected_width_or_concrete"] >= 1


def test_in_stack_c_fonksiyonunda_kanitsiz_isaretci_olmaz(tmp_path: Path) -> None:
    c = (
        "void FUN_00001000(void)\n{\n"
        "  undefined8 in_stack_00000010;\n"
        "  FUN_00002000(in_stack_00000010);\n"
        "  return;\n}\n"
    )
    f = (
        "void solve_(void)\n{\n"
        "  undefined8 in_stack_00000010;\n"
        "  FUN_00002000(in_stack_00000010);\n"
        "  return;\n}\n"
    )
    out = _kos(tmp_path, {"FUN_00001000": c, "solve_": f})
    assert _bildirim(out["FUN_00001000"], "in_stack_00000010") == "uint64_t"
    assert _bildirim(out["solve_"], "in_stack_00000010") == "void *"
