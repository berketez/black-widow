"""P18 — çıktı ağacı: alt sistem başlıkları, içe aktarım taslakları, tip öntanımı.

B-B1: ``include/subsystem_*.h`` bildirimleri tanımın kendisinden kurulur. Eski başlık
çağrı grafındaki Ghidra adından ``void ad(void);`` yazıyordu: yeniden adlandırılan
fonksiyonda eski ad, C++ adında geçersiz C adı (``operator.new``), her fonksiyonda
tanımdan farklı imza (birleşik 119 koşu: 66 860 bildirimin 36 083'ü imza farklı,
22 976'sı tanımsız ad, 11'i geçersiz C adı).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from karadul.reconstruction.c_project_builder import CProjectBuilder, definition_signatures


class _Alan:
    def __init__(self, kok: Path) -> None:
        self._kok = kok

    def get_stage_dir(self, ad: str) -> Path:
        return self._kok / ad


def _birim(baslik_ad: str, adres: str, govde_imza: str, satir: int = 12) -> str:
    return (
        f'#include "types.h"\n\n// Function: {baslik_ad}\n// Address:  {adres}\n\n'
        f"/* WARNING: yorum {{ ayraç }} içeriyor */\n"
        f"{govde_imza}\n\n{{\n" + "  puts(\"{ dizgide ayraç }\");\n" * satir + "}\n"
    )


def _kur(tmp_path: Path, birimler: dict[str, str], dugumler: dict[str, str]) -> Path:
    kaynak = tmp_path / "kaynak"
    kaynak.mkdir()
    for ad, icerik in birimler.items():
        (kaynak / f"{ad}.c").write_text(icerik)
    (tmp_path / "static").mkdir()
    (tmp_path / "static" / "ghidra_call_graph.json").write_text(json.dumps({
        "program": "deneme",
        "nodes": {a: {"name": n, "address": a, "callees": [], "callers": []}
                  for a, n in dugumler.items()},
        "edges": [],
    }))
    sonuc = CProjectBuilder(None).build(kaynak, tmp_path / "proje", workspace=_Alan(tmp_path))
    assert sonuc.success, sonuc.errors
    return tmp_path / "proje"


def _bildirimler(proje: Path) -> list[str]:
    satirlar = []
    for h in sorted((proje / "include").glob("subsystem_*.h")):
        for s in h.read_text().splitlines():
            if s and not s.startswith(("#", "//")):
                satirlar.append(s)
    return satirlar


def test_baslik_bildirimi_tanimin_adi_ve_imzasi(tmp_path):
    """Yeniden adlanan ve C++ adlı fonksiyonda başlık tanımla aynı ad ve imzayı söyler."""
    proje = _kur(tmp_path, {
        "FUN_00001000": _birim("parse_args", "00001000", "int parse_args(char **argv,int argc)"),
        "operator.new": _birim("operator.new", "00002000", "void * operator_new(ulong param_1)"),
    }, {"00001000": "FUN_00001000", "00002000": "operator.new"})
    bildirim = _bildirimler(proje)
    assert "int parse_args(char **argv,int argc);  // @00001000" in bildirim
    assert "void * operator_new(ulong param_1);  // @00002000" in bildirim
    metin = "\n".join(bildirim)
    assert "FUN_00001000" not in metin
    assert "operator.new" not in metin
    assert "(void);" not in metin


def test_her_bildirim_bir_tanima_denk(tmp_path):
    """Başlıktaki her bildirim src/ altındaki bir tanımın imzasıdır (ad + tip)."""
    proje = _kur(tmp_path, {
        f"FUN_0000{i}000": _birim(f"islev_{i}", f"0000{i}000", f"long islev_{i}(long param_1)")
        for i in range(1, 6)
    }, {f"0000{i}000": f"FUN_0000{i}000" for i in range(1, 6)})
    tanimlar = set()
    for c in (proje / "src").rglob("*.c"):
        tanimlar.update(imza for _ad, imza in definition_signatures(c.read_text()))
    bildirim = [re.sub(r";\s*//.*$|;$", "", s) for s in _bildirimler(proje)]
    assert len(bildirim) == 5
    assert set(bildirim) <= tanimlar


def test_tanim_imzasi_yorum_dizgi_onislemci_atlanir():
    kod = (
        '#include "types.h"\n// Function: f\n/* { */\n'
        "uint\nf(code *cb,\n  int (*g)(int))\n\n{\n  if (x) {\n    puts(\"}\");\n  }\n}\n"
        "int g(void) { return 0; }\n"
    )
    assert definition_signatures(kod) == [
        ("f", "uint f(code *cb, int (*g)(int))"), ("g", "int g(void)")]


def test_tanimi_okunamayan_birim_bildirilmez(tmp_path):
    proje = _kur(tmp_path, {
        "FUN_00003000": "// Function: FUN_00003000\n// Address:  00003000\n" + "// x\n" * 12,
    }, {"00003000": "FUN_00003000"})
    assert _bildirimler(proje) == []
    metin = "\n".join(h.read_text() for h in (proje / "include").glob("subsystem_*.h"))
    assert "FUN_00003000: no C-declarable function definition found in source; not declared" in metin


def test_nitelikli_cpp_adi_c_bildirimi_olmaz(tmp_path):
    """Ghidra'nın nitelikli C++ adı (`std::x`, `A::~A`) başlıkta yalnız yorum olarak durur."""
    proje = _kur(tmp_path, {
        "now": _birim("std::chrono::now", "00004000",
                      "void std::chrono::_V2::system_clock::now(void)"),
        "_State": _birim("~_State", "00005000",
                         "void __thiscall std::thread::_State::~_State(_State *this)"),
    }, {"00004000": "now", "00005000": "~_State"})
    assert _bildirimler(proje) == []
    metin = "\n".join(h.read_text() for h in (proje / "include").glob("subsystem_*.h"))
    assert metin.count("// qualified C++ name, not a C declaration:") == 2


def test_ayni_ad_farkli_imza_bir_kez_bildirilir(tmp_path):
    """Aynı ad iki birimde farklı imzayla: tek bildirim (adres sırasında ilki), öbürü yorum."""
    proje = _kur(tmp_path, {
        "dup": _birim("dup", "00006000", "int dup(int param_1)"),
        "dup_00007000": _birim("dup", "00007000", "long dup(long param_1)"),
    }, {"00006000": "dup", "00007000": "dup"})
    assert _bildirimler(proje) == ["int dup(int param_1);  // @00006000"]
    metin = "\n".join(h.read_text() for h in (proje / "include").glob("subsystem_*.h"))
    assert ("// also defined with another signature (not declared twice): "
            "long dup(long param_1);  // @00007000") in metin
