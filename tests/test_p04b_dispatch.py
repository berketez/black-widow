"""P04b / MUH-06: sanal çağrı çözücüsü Ghidra'nın gerçek biçimini tanır, doğrulanamayan
yuva tahmini yapmaz, seçici haritasını yalnız ObjC izi olan ikilide kurar.

Eski desen yalnız ``(*(code **)(*(long *)X + 0x..))`` biçimini tanıyordu: 119 ikilide 0
çağrı yeri (C++ pzstd'de 178 ``(**(code **)`` dahil). Bu testler eski kodda kırmızıdır.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from karadul.reconstruction.engineering import dispatch_resolver as D
from karadul.reconstruction.engineering.dispatch_resolver import VirtualDispatchResolver


@pytest.mark.parametrize("line", [
    "  (**(code **)(*param_1 + 0x10))(param_1);",
    "  (*(code **)(*(long *)param_1 + 0x10))(param_1);",
    "  (**(code **)(*(long *)this + 0x18))(this);",
    "  (**(code **)(*local_70 + 8))();",
])
def test_ghidra_vtable_bicimleri(line):
    assert D._RE_VTABLE.search(line)


def test_ilk_yuva():
    assert D._RE_VTABLE_SLOT0.search("  (**(code **)*param_1)(param_1);")


@pytest.mark.parametrize("line", [
    "  (**(code **)(param_1 + 0xe2))(uVar7);",          # yapı alanındaki işlev göstericisi
    "  (*(code *)param_1[0x12])(param_1[0x13]);",
    "  if (*(code **)(param_1 + 0x388) == (code *)0x0) {",
])
def test_yapi_alani_gostericisi_vtable_degil(line):
    assert not D._RE_VTABLE.search(line) and not D._RE_VTABLE_SLOT0.search(line)


def _ws(tmp_path: Path, names: list[str], body: str) -> tuple[Path, Path, Path]:
    dec = tmp_path / "decompiled"
    dec.mkdir()
    (dec / "Foo__bar.c").write_text(
        "// Function: Foo::bar\n// Address: 0x1000\n"
        "void Foo::bar(Foo *this) {\n" + body + "\n}\n")
    fj = tmp_path / "functions.json"
    fj.write_text(json.dumps({"total": len(names), "program": "x",
                              "functions": [{"name": n, "address": hex(0x1000 + i)}
                                            for i, n in enumerate(names)]}))
    cg = tmp_path / "cg.json"
    cg.write_text(json.dumps({"nodes": {}, "edges": []}))
    return dec, fj, cg


def test_yer_sayilir_hedef_ve_kenar_uretilmez(tmp_path: Path):
    names = ["_ZTV3Foo", "_ZN3Foo3barEv", "_ZN3Foo3bazEv", "_ZN3Foo3quxEv", "main"]
    dec, fj, cg = _ws(tmp_path, names, "  (**(code **)(*(long *)this + 0x18))(this);")
    r = VirtualDispatchResolver().resolve(dec, fj, cg)
    assert r.total_dispatch_sites == 1
    site = r.dispatch_sites[0]
    assert site.resolved_targets == []
    assert site.resolution_method == D.VTABLE_UNSUPPORTED_METHOD
    assert r.augmented_edges == []
    assert r.resolved_count == 0 and r.candidate_count == 0


def test_secici_haritasi_objc_izi_olmadan_kurulmaz(tmp_path: Path):
    dec, fj, cg = _ws(tmp_path, ["main", "dictAdd", "redisCommand", "processInput"], "  x = 1;")
    r = VirtualDispatchResolver().resolve(dec, fj, cg)
    assert r.selector_map_size == 0


def test_secici_haritasi_objc_ikilisinde_kurulur(tmp_path: Path):
    dec, fj, cg = _ws(tmp_path, ["-[AppDelegate applicationDidFinishLaunching:]",
                                 "initWithFrame:", "_objc_msgSend"], "  x = 1;")
    r = VirtualDispatchResolver().resolve(dec, fj, cg)
    assert r.selector_map_size >= 2
