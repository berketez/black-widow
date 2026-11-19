"""P16d: ``pcode_high_vars`` sırası koşudan koşuya değişmesin; tüketici sıraya bağlı olmasın.

Bulgu (P16c yan bulgusu; P16d.md'de ölçüldü): aynı kod, aynı girdi, ``PYTHONHASHSEED=0``:
``decompiled.json`` / ``pcode.jsonl``'de ``pcode_high_vars`` listesinin SIRASI bazı fonksiyonlarda
koşudan koşuya değişiyordu (küme aynı). Kaynak Ghidra'nın ``LocalSymbolMap.getSymbols()``
yinelemesi (simge kimliğiyle anahtarlanmış eşlem). Tüketici (``c_type_recoverer``) listeyi
``{ad: tip}`` sözlüğüne döküyordu: aynı ad iki kez geçerse sonuncu kazanıyordu.

Ghidra yok: ``ghidra.*`` modülleri ve decompile sonuçları sahte; ``getSymbols()`` iki koşuda
bilerek farklı sırada döner.
"""
from __future__ import annotations

import ast
import itertools
import json
import sys
import types
from pathlib import Path

import pytest

import karadul.ghidra.headless as headless_mod
from karadul.ghidra.headless import GhidraHeadless

SCRIPT = Path(__file__).resolve().parents[1] / "karadul" / "ghidra" / "scripts" / "pcode_analysis.py"
XREF = {"caller_count": 0, "callee_count": 0, "callers": [], "callees": []}

# (ad, tip, boyut, depolama alanı, ofset) — ofsetler sayısal sıra ile metin sırası farklı
# olacak biçimde seçildi (0x8 < 0x10 ama "0x10" < "0x8").
SEMBOLLER = [
    ("param_1", "char *", 8, "register", 0x4000),
    ("param_2", "int", 4, "register", 0x4008),
    ("local_10", "long", 8, "stack", 0xFFFFFFFFFFFFFFF0),
    ("uVar1", "uint", 4, "unique", 0x10),
    ("iVar2", "int", 4, "unique", 0x8),
    ("pcVar3", "char *", 8, "register", 0x8),
    ("extraout_x0", "ulong", 8, None, 0),  # depolama yok -> "unknown"
]


class _Varnode:
    def __init__(self, alan, ofset, boyut):
        self.alan, self.ofset, self.boyut = alan, ofset, boyut

    def __str__(self):  # Ghidra Varnode.toString() biçimi
        return "(%s, 0x%x, %d)" % (self.alan, self.ofset, self.boyut)

    def getAddress(self):
        alan = self.alan

        class _Uzay:
            def getName(self):
                return alan

        class _Adres:
            def getAddressSpace(self):
                return _Uzay()

        return _Adres()

    def getOffset(self):
        return self.ofset


class _HighVar:
    def __init__(self, vn):
        self.vn = vn

    def getRepresentative(self):
        return self.vn


class _Sembol:
    def __init__(self, ad, tip, boyut, alan, ofset):
        self.ad, self.tip, self.boyut = ad, tip, boyut
        self.hv = _HighVar(_Varnode(alan, ofset, boyut)) if alan else None

    def getName(self):
        return self.ad

    def getDataType(self):
        return self.tip

    def getSize(self):
        return self.boyut

    def getHighVariable(self):
        return self.hv

    def isParameter(self):
        return self.ad.startswith("param_")


class _Iter:
    def __init__(self, xs):
        self.xs = list(xs)
        self.i = 0

    def hasNext(self):
        return self.i < len(self.xs)

    def next(self):
        self.i += 1
        return self.xs[self.i - 1]

    def __iter__(self):  # JPype Java Iterator'ı Python'da dolaşılabilir yapar
        return iter(self.xs)


class _LocalMap:
    def __init__(self, semboller):
        self.semboller = semboller

    def getSymbols(self):
        return _Iter(self.semboller)


class _HighFunc:
    def __init__(self, semboller):
        self.semboller = semboller

    def getPcodeOps(self):
        return _Iter([])

    def getLocalSymbolMap(self):
        return _LocalMap(self.semboller)


class _CFonk:
    def getC(self):
        return "void f(void) {}\n"


class _Sonuc:
    def __init__(self, semboller):
        self.semboller = semboller

    def getDecompiledFunction(self):
        return _CFonk()

    def getHighFunction(self):
        return _HighFunc(self.semboller)

    def decompileCompleted(self):
        return True


class _Decomp:
    def __init__(self, semboller):
        self.semboller = semboller

    def decompileFunction(self, func, timeout, monitor):
        return _Sonuc(self.semboller)

    def setOptions(self, o):
        pass

    def openProgram(self, p):
        pass

    def dispose(self):
        pass


class _Govde:
    def getNumAddresses(self):
        return 4


class _Fonk:
    def getName(self):
        return "f"

    def getEntryPoint(self):
        return "00101000"

    def getBody(self):
        return _Govde()


def _semboller(sira):
    return [_Sembol(*s) for s in sira]


def _tek_fonksiyon(tmp_path, monkeypatch, sira, alt):
    monkeypatch.setattr(GhidraHeadless, "_extract_disassembly", staticmethod(lambda p, f: []))
    monkeypatch.setattr(GhidraHeadless, "_extract_stack_frame", staticmethod(lambda f: None))
    monkeypatch.setattr(GhidraHeadless, "_extract_func_xrefs", staticmethod(lambda p, f: dict(XREF)))
    hedef = tmp_path / alt
    hedef.mkdir()
    r = GhidraHeadless._decompile_single_function(
        _Decomp(_semboller(sira)), _Fonk(), None, hedef, 30, None, selective_ops={"LOAD"},
    )
    return r["pcode_high_vars"]


def test_decompile_yolu_iki_sirada_ayni_liste(tmp_path, monkeypatch):
    a = _tek_fonksiyon(tmp_path, monkeypatch, SEMBOLLER, "a")
    b = _tek_fonksiyon(tmp_path, monkeypatch, list(reversed(SEMBOLLER)), "b")
    assert a == b
    assert len(a) == len(SEMBOLLER)
    # depolama yerine göre: alan adı, SAYISAL ofset; tanınmayan depolama en sonda
    assert [h["name"] for h in a] == [
        "pcVar3", "param_1", "param_2", "local_10", "iVar2", "uVar1", "extraout_x0",
    ]
    assert a[-1]["storage"] == "unknown"


def test_pcode_jsonl_iki_sirada_ayni(tmp_path, monkeypatch):
    a = _tek_fonksiyon(tmp_path, monkeypatch, SEMBOLLER, "a")
    b = _tek_fonksiyon(tmp_path, monkeypatch, SEMBOLLER[3:] + SEMBOLLER[:3], "b")
    satirlar = []
    for alt, hv in (("ja", a), ("jb", b)):
        d = tmp_path / alt
        d.mkdir()
        GhidraHeadless._write_pcode_jsonl(d, {"functions": [
            {"name": "f", "address": "00101000", "pcode_ops": [["LOAD", None, []]], "pcode_high_vars": hv},
        ]})
        satirlar.append((d / "pcode.jsonl").read_bytes())
    assert satirlar[0] == satirlar[1]


def test_tam_pcode_yolu_iki_sirada_ayni(monkeypatch):
    sonuclar = []
    for sira in (SEMBOLLER, list(reversed(SEMBOLLER))):
        dec = types.ModuleType("ghidra.app.decompiler")
        dec.DecompInterface = lambda s=sira: _Decomp(_semboller(s))
        dec.DecompileOptions = object
        task = types.ModuleType("ghidra.util.task")

        class _Monitor:
            def isCancelled(self):
                return False

        task.ConsoleTaskMonitor = _Monitor
        for ad, mod in (("ghidra", types.ModuleType("ghidra")), ("ghidra.app", types.ModuleType("ghidra.app")),
                        ("ghidra.util", types.ModuleType("ghidra.util")),
                        ("ghidra.app.decompiler", dec), ("ghidra.util.task", task)):
            monkeypatch.setitem(sys.modules, ad, mod)

        class _FM:
            def getFunctions(self, ileri):
                return [_Fonk()]

        class _Program:
            def getFunctionManager(self):
                return _FM()

            def getName(self):
                return "p"

        sonuclar.append(GhidraHeadless._extract_pcode(_Program())["functions"][0]["high_variables"])
    assert sonuclar[0] == sonuclar[1]
    assert [h["name"] for h in sonuclar[0]][0] == "pcVar3"


def test_sira_anahtari_her_permutasyonda_ayni_sonuc():
    high_var_sort_key = headless_mod.high_var_sort_key
    kayitlar = [
        {"name": n, "type": t, "size": s,
         "storage": str(_Varnode(a, o, s)) if a else "unknown"}
        for n, t, s, a, o in SEMBOLLER
    ]
    beklenen = sorted(kayitlar, key=high_var_sort_key)
    for perm in itertools.islice(itertools.permutations(kayitlar), 0, 5040, 37):
        assert sorted(perm, key=high_var_sort_key) == beklenen


def test_sira_anahtari_ayni_depolamada_ad_ve_tip_belirler():
    high_var_sort_key = headless_mod.high_var_sort_key
    ortak = "(register, 0x4000, 8)"
    kayitlar = [{"name": "b", "type": "long", "size": 8, "storage": ortak},
                {"name": "a", "type": "long", "size": 8, "storage": ortak},
                {"name": "a", "type": "char *", "size": 8, "storage": ortak}]
    for perm in itertools.permutations(kayitlar):
        assert [(k["name"], k["type"]) for k in sorted(perm, key=high_var_sort_key)] == [
            ("a", "char *"), ("a", "long"), ("b", "long")]


def test_sira_anahtari_bozuk_girdide_istisna_atmaz():
    high_var_sort_key = headless_mod.high_var_sort_key
    kotu = [{}, {"storage": None, "size": "8"}, {"storage": "(ram, 0xzz, 4)", "name": 3},
            {"storage": "(register, 0x10, 8)", "size": True}]
    assert len(sorted(kotu, key=high_var_sort_key)) == 4


def _betik_yukle(monkeypatch):
    dec = types.ModuleType("ghidra.app.decompiler")
    dec.DecompInterface = object
    dec.DecompileOptions = object
    task = types.ModuleType("ghidra.util.task")
    task.ConsoleTaskMonitor = object
    for ad, mod in (("ghidra", types.ModuleType("ghidra")), ("ghidra.app", types.ModuleType("ghidra.app")),
                    ("ghidra.util", types.ModuleType("ghidra.util")),
                    ("ghidra.app.decompiler", dec), ("ghidra.util.task", task)):
        monkeypatch.setitem(sys.modules, ad, mod)
    # Betik içe aktarılırken en sonda ``main()``'i koşar; yalnız tanımlar yüklenir.
    agac = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    agac.body = [d for d in agac.body
                 if not (isinstance(d, ast.Expr) and isinstance(d.value, ast.Call)
                         and getattr(d.value.func, "id", "") == "main")]
    mod = types.ModuleType("p16d_pcode_analysis")
    exec(compile(agac, str(SCRIPT), "exec"), mod.__dict__)
    return mod


def test_cli_betigi_iki_sirada_ayni_liste(monkeypatch):
    mod = _betik_yukle(monkeypatch)
    a = mod.extract_high_variables(_HighFunc(_semboller(SEMBOLLER)))
    b = mod.extract_high_variables(_HighFunc(_semboller(list(reversed(SEMBOLLER)))))
    assert a == b
    assert [v["name"] for v in a][:3] == ["pcVar3", "param_1", "param_2"]


# --------------------------------------------------------------------------
# Tüketici: c_type_recoverer._load_ghidra_high_vars
# --------------------------------------------------------------------------

def _yukle(tmp_path, hv, ad="decompiled.json"):
    from karadul.config import Config
    from karadul.reconstruction.c_type_recoverer import CTypeRecoverer

    p = tmp_path / ad
    p.write_text(json.dumps({"functions": [{"name": "FUN_00001000", "pcode_high_vars": hv}]}),
                 encoding="utf-8")
    r = CTypeRecoverer(Config())
    r._load_ghidra_high_vars(p, [])
    return r


YINELENEN = [
    {"name": "uVar1", "type": "uint", "size": 4, "storage": "(register, 0x4008, 4)"},
    {"name": "uVar1", "type": "char *", "size": 8, "storage": "(register, 0x4000, 8)"},
    {"name": "uVar12", "type": "long", "size": 8, "storage": "(stack, 0x10, 8)"},
    {"name": "local_8", "type": "undefined8", "size": 8, "storage": "(stack, 0x8, 8)"},
]


def test_tuketici_yinelenen_adda_depolama_sirasinda_ilk_kazanir(tmp_path):
    a = _yukle(tmp_path, YINELENEN, "a.json")
    b = _yukle(tmp_path, list(reversed(YINELENEN)), "b.json")
    # (register, 0x4000) depolama sırasında (register, 0x4008)'den önce: "char *" seçilir
    assert a._ghidra_high_vars == {"FUN_00001000": {"uVar1": "char *", "uVar12": "long"}}
    assert list(a._ghidra_high_vars["FUN_00001000"].items()) == \
        list(b._ghidra_high_vars["FUN_00001000"].items())
    assert a.ghidra_high_var_duplicates == b.ghidra_high_var_duplicates == [{
        "function": "FUN_00001000", "name": "uVar1", "chosen_type": "char *",
        "dropped_type": "uint", "dropped_storage": "(register, 0x4008, 4)",
    }]


def test_tuketici_sozluk_sirasi_girdi_sirasindan_bagimsiz(tmp_path):
    kayitlar = [
        {"name": n, "type": t, "size": s, "storage": str(_Varnode(a, o, s)) if a else "unknown"}
        for n, t, s, a, o in SEMBOLLER
    ]
    a = _yukle(tmp_path, kayitlar, "a.json")
    b = _yukle(tmp_path, list(reversed(kayitlar)), "b.json")
    assert list(a._ghidra_high_vars["FUN_00001000"]) == list(b._ghidra_high_vars["FUN_00001000"])
    assert a.ghidra_high_var_duplicates == []


def test_tuketici_ayni_tipli_yineleme_kayda_girmez(tmp_path):
    hv = [{"name": "x", "type": "int", "size": 4, "storage": "(register, 0x0, 4)"},
          {"name": "x", "type": "int", "size": 4, "storage": "(stack, 0x4, 4)"}]
    r = _yukle(tmp_path, hv)
    assert r._ghidra_high_vars == {"FUN_00001000": {"x": "int"}}
    assert r.ghidra_high_var_duplicates == []


@pytest.mark.parametrize("bozuk", [None, "x", {"a": 1}, 5])
def test_tuketici_liste_olmayan_alani_atlar(tmp_path, bozuk):
    r = _yukle(tmp_path, bozuk)
    assert r._ghidra_high_vars == {}
