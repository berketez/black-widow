"""P16a / GHIDRA-05 + B-B4: decompile listesi belirlenimci, kırpma ve kayıplar yazılı.

Eski davranış (ölçüldü, ``P16a.md``): ``decompiled.json``'daki 500 kayıt iş parçacıklarının bitiş
sırasıyla seçiliyordu (119 ikilinin 116'sında adres sırası kırık); kırpılan sayı hiçbir alanda
yoktu (21 ikili / 25 640 kayıt); istisna veren parçanın fonksiyonları listeden adsız düşüyordu;
aynı adlı fonksiyonlardan eksiz ``ad.c`` adını hangisinin aldığı zamanlamaya bağlıydı
(10 938 grubun 4 695'inde adres sırasında ilk olmayan almıştı).

Ghidra yok: ``ghidra.*`` modülleri sahte, decompile sahte nesnelerle; parça bitiş sırası
gecikmeyle bilerek ters çevrilir.
"""
from __future__ import annotations

import sys
import threading
import time
import types

import pytest

from karadul.ghidra.headless import GhidraHeadless

XREF = {"caller_count": 0, "callee_count": 0, "callers": [], "callees": []}


class _Govde:
    def getNumAddresses(self):
        return 4


class _Fonk:
    def __init__(self, ad, adres):
        self._ad, self._adres = ad, adres

    def getName(self):
        return self._ad

    def getEntryPoint(self):
        return self._adres

    def getBody(self):
        return _Govde()


class _CFonk:
    def __init__(self, f):
        self.f = f

    def getC(self):
        return "void %s(void) {} /* %s */\n" % (self.f.getName(), self.f.getEntryPoint())


class _Sonuc:
    def __init__(self, f):
        self.f = f

    def getDecompiledFunction(self):
        return _CFonk(self.f)


class _Iter:
    def __init__(self, xs):
        self.xs, self.i = list(xs), 0

    def hasNext(self):
        return self.i < len(self.xs)

    def next(self):
        self.i += 1
        return self.xs[self.i - 1]


class _FM:
    def __init__(self, fonklar):
        self.fonklar = fonklar

    def getFunctions(self, ileri):
        return _Iter(self.fonklar)

    def getFunctionCount(self):
        return len(self.fonklar)


class _Program:
    def __init__(self, fonklar):
        self.fm = _FM(fonklar)

    def getFunctionManager(self):
        return self.fm


@pytest.fixture
def sahte_ghidra(monkeypatch):
    """``ghidra.app.decompiler`` / ``ghidra.util.task`` sahteleri; davranış ``ayar`` ile seçilir."""
    ayar = {"gecikme": None, "patlayan_parca_ilk_adres": None, "acilis": 0}
    kilit = threading.Lock()

    class DecompInterface:
        def setOptions(self, o):
            pass

        def openProgram(self, p):
            with kilit:
                ayar["acilis"] += 1

        def decompileFunction(self, func, timeout, monitor):
            if ayar["gecikme"]:
                time.sleep(ayar["gecikme"](func))
            return _Sonuc(func)

        def dispose(self):
            pass

    class DecompileOptions:
        pass

    class ConsoleTaskMonitor:
        pass

    dec = types.ModuleType("ghidra.app.decompiler")
    dec.DecompInterface = DecompInterface
    dec.DecompileOptions = DecompileOptions
    task = types.ModuleType("ghidra.util.task")
    task.ConsoleTaskMonitor = ConsoleTaskMonitor
    for ad, mod in (("ghidra", types.ModuleType("ghidra")), ("ghidra.app", types.ModuleType("ghidra.app")),
                    ("ghidra.util", types.ModuleType("ghidra.util")),
                    ("ghidra.app.decompiler", dec), ("ghidra.util.task", task)):
        monkeypatch.setitem(sys.modules, ad, mod)
    monkeypatch.setattr(GhidraHeadless, "_extract_disassembly", staticmethod(lambda p, f: []))
    monkeypatch.setattr(GhidraHeadless, "_extract_stack_frame", staticmethod(lambda f: None))
    monkeypatch.setattr(GhidraHeadless, "_extract_func_xrefs", staticmethod(lambda p, f: dict(XREF)))
    return ayar


def _fonklar(n, ad=lambda i: "FUN_%08x" % (0x100000 + 16 * i)):
    return [_Fonk(ad(i), "%08x" % (0x100000 + 16 * i)) for i in range(n)]


def _kos(tmp_path, fonklar, n_threads=4, total_timeout=0, alt="d"):
    hedef = tmp_path / alt
    hedef.mkdir()
    return GhidraHeadless._parallel_decompile_java_threads(
        _Program(fonklar), hedef, len(fonklar), 30, total_timeout, n_threads,
    ), hedef


def test_liste_adres_sirasinda_ve_kirpma_yazili(tmp_path, sahte_ghidra):
    fonklar = _fonklar(600)
    # son parça önce bitsin: eski kodda liste son parçanın adresleriyle başlıyordu
    sahte_ghidra["gecikme"] = lambda f: 0.004 if int(f.getEntryPoint(), 16) < 0x100000 + 16 * 450 else 0.0
    r, _ = _kos(tmp_path, fonklar)
    adresler = [x["address"] for x in r["functions"]]
    assert adresler == [f.getEntryPoint() for f in fonklar[:500]]
    assert r["functions_order"] == "address"
    assert r["functions_total"] == 600
    assert r["functions_written"] == 500
    assert r["functions_truncated"] == 100
    assert r["losses"]["decompiled_json_truncated"]["count"] == 100
    assert r["losses"]["body_truncated"] == 0
    assert r["success"] == 600 and r["failed"] == 0 and r["skipped"] == 0


def test_iki_kosu_ayni_liste_ve_dosya_adlari(tmp_path, sahte_ghidra):
    ad = lambda i: "dup" if i % 3 == 0 else "f%d" % i  # noqa: E731
    fonklar = _fonklar(90, ad=ad)
    sahte_ghidra["gecikme"] = lambda f: 0.003 if int(f.getEntryPoint(), 16) % 64 == 0 else 0.0
    r1, _ = _kos(tmp_path, fonklar, n_threads=6, alt="k1")
    sahte_ghidra["gecikme"] = lambda f: 0.003 if int(f.getEntryPoint(), 16) % 64 != 0 else 0.0
    r2, _ = _kos(tmp_path, fonklar, n_threads=6, alt="k2")
    e1 = [(x["address"], x["file"]) for x in r1["functions"]]
    e2 = [(x["address"], x["file"]) for x in r2["functions"]]
    assert e1 == e2
    # aynı adlıların ilki (adres sırasında) eksiz adı alır
    dup = [x for x in r1["functions"] if x["name"] == "dup"]
    assert dup[0]["file"] == "dup.c"
    assert all(x["file"] == "dup_%s.c" % x["address"][-8:] for x in dup[1:])


def test_dosya_adi_plani_buyuk_kucuk_harf_duyarsiz_ve_adres_sirasinda():
    plan = GhidraHeadless._plan_decompile_filenames([
        ("fputs", "00103d40"), ("Foo", "00104000"), ("foo", "00104100"),
        ("fputs", "00135030"), ("a/b", "00136000"),
    ])
    assert plan == {
        "00103d40": "fputs.c", "00104000": "Foo.c", "00104100": "foo_00104100.c",
        "00135030": "fputs_00135030.c", "00136000": "a_b.c",
    }


def test_dusen_parcanin_fonksiyonlari_adiyla_kalir(tmp_path, sahte_ghidra, monkeypatch):
    fonklar = _fonklar(40)
    asil = GhidraHeadless._decompile_single_function

    def patlayan(decomp, func, *a, **kw):
        if func.getEntryPoint() == fonklar[10].getEntryPoint():
            raise RuntimeError("JVM parca hatasi")
        return asil(decomp, func, *a, **kw)

    monkeypatch.setattr(GhidraHeadless, "_decompile_single_function", staticmethod(patlayan))
    r, _ = _kos(tmp_path, fonklar, n_threads=4)
    assert r["total_attempted"] == 40
    assert len(r["functions"]) == 40
    kayip = [x for x in r["functions"] if not x["success"]]
    assert len(kayip) == 10                        # 40 // 4 = 10'luk parçanın tamamı
    assert all("JVM parca hatasi" in x["error"] and x["name"] for x in kayip)
    assert r["failed"] == 10
    assert r["losses"]["chunk_errors"][0]["functions"] == 10
    assert [x["address"] for x in r["functions"]] == [f.getEntryPoint() for f in fonklar]


def test_toplam_sure_dolunca_kalanlar_atlandi_diye_kaydedilir(tmp_path, sahte_ghidra):
    fonklar = _fonklar(20)
    sahte_ghidra["gecikme"] = lambda f: 0.6
    r, _ = _kos(tmp_path, fonklar, n_threads=2, total_timeout=1)
    assert r["skipped"] > 0
    assert r["success"] + r["failed"] + r["skipped"] == 20
    atlanan = [x for x in r["functions"] if x.get("skipped")]
    assert len(atlanan) == r["skipped"]
    assert all("süresi" in x["error"] for x in atlanan)


def test_seri_yedek_ayni_sayaclari_yazar(tmp_path, sahte_ghidra):
    fonklar = _fonklar(510)
    hedef = tmp_path / "seri"
    hedef.mkdir()
    r = GhidraHeadless._serial_decompile_fallback(_Program(fonklar), hedef, 510, 30, 0)
    assert r["parallel"] is False
    assert r["functions_truncated"] == 10
    assert [x["address"] for x in r["functions"]] == [f.getEntryPoint() for f in fonklar[:500]]


def test_seri_yedekte_sure_dolunca_atlanan_sayilir(tmp_path, sahte_ghidra):
    fonklar = _fonklar(6)
    sahte_ghidra["gecikme"] = lambda f: 0.6
    hedef = tmp_path / "seri2"
    hedef.mkdir()
    r = GhidraHeadless._serial_decompile_fallback(_Program(fonklar), hedef, 6, 30, 1)
    assert r["skipped"] > 0
    assert r["total_attempted"] == 6
    assert r["success"] + r["failed"] + r["skipped"] == 6


def test_strings_raw_kirpmasi_yazili(monkeypatch, tmp_path):
    import json

    from tests.test_p16a_ghidra_sonuc import _static_kos

    dizgiler = ["dizgi_%05d" % i for i in range(10_007)]
    sonuc, static = _static_kos(monkeypatch, tmp_path, None, dizgiler=dizgiler)
    d = json.loads((static / "strings_raw.json").read_text(encoding="utf-8"))
    assert d["total"] == 10_007
    assert d["written"] == 10_000 == len(d["strings"])
    assert d["truncated"] == 7
    assert "10000" in d["truncated_reason"]
    assert sonuc.stats["strings_raw_truncated"] == 7


def test_fonksiyon_basi_sure_ayardan_gecer(tmp_path, monkeypatch):
    gorulen = {}

    def paralel(program, d, n, func_timeout, total_timeout, threads, selective_ops=None):
        gorulen["func_timeout"] = func_timeout
        return {"success": 0}

    monkeypatch.setattr(GhidraHeadless, "_parallel_decompile_java_threads", staticmethod(paralel))
    GhidraHeadless._decompile_functions(_Program([]), tmp_path, 100, func_timeout=7)
    assert gorulen["func_timeout"] == 7
