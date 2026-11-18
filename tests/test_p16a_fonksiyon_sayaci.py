"""P16a / GHIDRA-10: "kurtarılan fonksiyon" sayacı içe aktarım taslaklarını (thunk) saymaz.

Eski davranış (ölçüldü, ``P16a.md``): 119 ikilide sayılan 66 983 fonksiyonun 33 547'si thunk
idi; ELF'te her içe aktarım iki kez (PLT girişi + EXTERNAL taslak) "fonksiyon" sayılıyordu.
"""
from __future__ import annotations

from karadul.ghidra.headless import GhidraHeadless


class _Tip:
    def __init__(self, ad):
        self.ad = ad

    def __str__(self):
        return self.ad


class _Sembol:
    def getSource(self):
        return "IMPORTED"


class _Govde:
    def __init__(self, n):
        self.n = n

    def getNumAddresses(self):
        return self.n


class _Fonk:
    def __init__(self, ad, adres, boyut, thunk=False, dis=False):
        self.ad, self.adres, self.boyut, self.thunk, self.dis = ad, adres, boyut, thunk, dis

    def getName(self):
        return self.ad

    def getEntryPoint(self):
        return self.adres

    def getBody(self):
        return _Govde(self.boyut)

    def getParameterCount(self):
        return 0

    def getReturnType(self):
        return _Tip("int")

    def isThunk(self):
        return self.thunk

    def getCallingConventionName(self):
        return "__cdecl"

    def isExternal(self):
        return self.dis

    def getSymbol(self):
        return _Sembol()


class _FM:
    def __init__(self, fonklar):
        self.fonklar = fonklar

    def getFunctions(self, ileri):
        return iter(self.fonklar)


class _Program:
    def __init__(self, fonklar):
        self.fm = _FM(fonklar)

    def getFunctionManager(self):
        return self.fm

    def getName(self):
        return "tree"


# tree'deki gerçek örüntü: fputs için PLT thunk'ı (16 bayt) + EXTERNAL bloktaki taslak (1 bayt).
FONKLAR = [
    _Fonk("fputs", "00103d40", 16, thunk=True),
    _Fonk("FUN_00104000", "00104000", 120),
    _Fonk("main", "00104100", 300),
    _Fonk("fputs", "00135030", 1, thunk=True),
    _Fonk("dlopen", "EXTERNAL:00000001", 0, dis=True),
]


def test_fonksiyon_listesi_tur_sayaclarini_tasir():
    d = GhidraHeadless._extract_functions(_Program(FONKLAR))
    assert d["total"] == 5
    assert d["program_function_count"] == 2
    assert d["thunk_count"] == 2
    assert d["external_count"] == 1
    # liste değişmedi: tüketiciler (ölçüm, ad haritası) bütün kayıtları görmeye devam eder
    assert len(d["functions"]) == 5


def test_tur_sayaclari_toplami_tutar():
    funcs = [{"is_thunk": True, "is_external": True}, {"is_thunk": False, "is_external": False}]
    c = GhidraHeadless._function_kind_counts(funcs)
    assert c == {"program_function_count": 1, "thunk_count": 1, "external_count": 0}
    assert sum(c.values()) == len(funcs)


def test_static_istatistigi_program_fonksiyonunu_sayar(monkeypatch, tmp_path):
    from tests.test_p16a_ghidra_sonuc import _static_kos

    sonuc, _ = _static_kos(monkeypatch, tmp_path, {
        "success": True, "error": None, "step_errors": {}, "mode": "pyghidra",
        "returncode": None, "scripts_output": {"combined_results": {"summary": {
            "function_count": 119, "function_total": 250, "thunk_count": 131,
            "external_count": 0, "decompiled_success": 250,
        }}},
    })
    st = sonuc.stats
    assert st["ghidra_function_count"] == 119
    assert st["ghidra_function_total"] == 250
    assert st["ghidra_thunk_count"] == 131
    assert st["ghidra_external_count"] == 0


from tests.test_p16a_ghidra_sonuc import _yamala_adimlar, sahte_pyghidra  # noqa: E402,F401


def test_birlesik_ozet_program_fonksiyonunu_sayar(sahte_pyghidra, monkeypatch, tmp_path):
    gh, _ = sahte_pyghidra
    gercek = GhidraHeadless.__dict__["_extract_functions"]
    _yamala_adimlar(monkeypatch, dusen=set())
    monkeypatch.setattr(GhidraHeadless, "_extract_functions", staticmethod(
        lambda program: gercek.__func__(_Program(FONKLAR))))
    sonuc = gh._analyze_pyghidra(tmp_path / "x", tmp_path / "p", "p", 10, tmp_path)
    ozet = sonuc["scripts_output"]["combined_results"]["summary"]
    assert ozet["function_count"] == 2
    assert ozet["function_total"] == 5
    assert ozet["thunk_count"] == 2
    assert ozet["external_count"] == 1
