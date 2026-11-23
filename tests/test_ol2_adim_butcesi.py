"""ÖL-2: Ghidra köprüsünün döküm adımlarında süre bütçesi ve adım içi ilerleme olayı.

Ghidra / JVM gerekmez: sahte program nesneleri ve elle ilerleyen saat (``headless_mod.time``).
Sözleşme (``docs/arge/2026-11-19_mythos/olcek/PLAN.md`` "ÖL-2" + gönderim hükümleri):
- bütçe dolunca döngü birim sınırında biter, çıktı geçerli JSON'dur ve ``kismi / islenen /
  [toplam] / neden`` taşır; bütçe dolmadıysa bu alanlar YAZILMAZ (çıktı bayt bayt aynı);
- adım hatası ``step_errors[<adım>]`` = neden; bitiş olayı ``durum=kismi`` gerçek sayaçlarla;
- adım içi ``durum=suruyor`` olayı yalnız denetim noktasında, adımın son olayından beri
  ``analysis.bekci_aralik_sn`` geçtiyse; sayaçlar gerçek döngü sayaçları.
"""

from __future__ import annotations

import json
import logging
import shlex
import sys
import types

import pytest

import karadul.ghidra.headless as headless_mod
from karadul.ghidra.headless import (
    GhidraHeadless,
    KUCUK_BIRIM_DENETIM_ADIMI,
    _AdimDenetcisi,
    _AdimSaati,
    _en_kucuk_butce,
)
from tests.test_hz1_olcum_kancasi import SURE, _BSim, kopru  # noqa: F401


class _Saat:
    """``headless_mod.time`` yerine: ``monotonic`` elle ilerler."""

    def __init__(self) -> None:
        self.t = 100.0

    def monotonic(self) -> float:
        return self.t

    def ilerle(self, sn: float) -> None:
        self.t += sn

    @staticmethod
    def time() -> float:
        return 0.0


@pytest.fixture
def saat(monkeypatch):
    s = _Saat()
    monkeypatch.setattr(headless_mod, "time", s)
    return s


@pytest.fixture
def olay_kaydi(caplog):
    caplog.set_level(logging.INFO, logger="karadul.ilerleme")
    return caplog


def _olaylar(caplog) -> list[dict[str, str]]:
    out = []
    for r in caplog.records:
        if r.name != "karadul.ilerleme":
            continue
        parca = shlex.split(r.getMessage())
        assert parca[0] == "ILERLEME"
        out.append(dict(p.split("=", 1) for p in parca[1:]))
    return out


# ---------------------------------------------------------------------------
# _AdimDenetcisi
# ---------------------------------------------------------------------------

def test_denetci_butce_dolunca_true_ve_sayaclari_saklar(saat) -> None:
    d = _AdimDenetcisi("ghidra.cfg", 2.0, 0, saat.t, toplam=10)
    assert d.denetle(0) is False
    saat.ilerle(2.0)
    assert d.denetle(3) is False          # sınırda (eşit) dolmadı
    saat.ilerle(0.001)
    assert d.denetle(4) is True
    assert d.doldu and d.sayac() == {"islenen": 4, "toplam": 10}
    assert d.kismi_alanlari() == {"kismi": True, "islenen": 4, "toplam": 10,
                                  "neden": "adım bütçesi (2 sn) doldu"}


def test_denetci_butce_sifir_hic_dolmaz_ve_alan_yok(saat) -> None:
    d = _AdimDenetcisi("ghidra.cfg", 0, 0, saat.t)
    saat.ilerle(10 ** 6)
    assert d.denetle(5) is False
    assert not d.doldu and d.kismi_alanlari() == {} and d.sayac() == {}


def test_denetci_toplam_bilinmiyorsa_yazilmaz(saat) -> None:
    d = _AdimDenetcisi("ghidra.strings", 1, 0, saat.t)
    saat.ilerle(5)
    assert d.denetle(7) is True
    assert d.kismi_alanlari() == {"kismi": True, "islenen": 7,
                                  "neden": "adım bütçesi (1 sn) doldu"}


def test_denetci_suruyor_olayi_aralikta_gercek_sayacla(saat, olay_kaydi) -> None:
    d = _AdimDenetcisi("ghidra.xref", 0, 15, saat.t, toplam=100)
    saat.ilerle(14.9)
    d.denetle(10)                          # aralık dolmadı: olay yok
    saat.ilerle(0.1)
    d.denetle(11)                          # 15 sn: olay
    saat.ilerle(1)
    d.denetle(12)                          # son olaydan 1 sn: olay yok
    saat.ilerle(15)
    d.denetle(40, 50)                      # toplam çağrıda verilirse o yazılır
    ol = _olaylar(olay_kaydi)
    assert ol == [
        {"asama": "static", "adim": "ghidra.xref", "durum": "suruyor", "islenen": "11",
         "toplam": "100", "gecen_sn": "15.0"},
        {"asama": "static", "adim": "ghidra.xref", "durum": "suruyor", "islenen": "40",
         "toplam": "50", "gecen_sn": "31.0"},
    ]
    assert d.olay == 2


def test_denetci_aralik_sifirsa_olay_yok(saat, olay_kaydi) -> None:
    d = _AdimDenetcisi("ghidra.xref", 0, 0, saat.t)
    for i in range(5):
        saat.ilerle(100)
        d.denetle(i)
    assert _olaylar(olay_kaydi) == []


def test_denetci_dolunca_olay_basmaz(saat, olay_kaydi) -> None:
    d = _AdimDenetcisi("ghidra.cfg", 5, 1, saat.t)
    saat.ilerle(6)
    assert d.denetle(3) is True
    assert _olaylar(olay_kaydi) == []


def test_en_kucuk_butce() -> None:
    assert _en_kucuk_butce(3600, 900) == 900
    assert _en_kucuk_butce(2, 900) == 2
    assert _en_kucuk_butce(0, 900) == 900
    assert _en_kucuk_butce(0, 0) == 0


def test_adim_saati_denetcisi_baslangici_saatten_alir_ve_kismi_olaya_sayac(saat, olay_kaydi):
    hatalar: dict[str, str] = {}
    s = _AdimSaati(hatalar)
    with pytest.raises(ValueError):
        s.denetci("ghidra.cfg", 1, 0)        # başlamamış adım
    s.basla("ghidra.cfg")
    saat.ilerle(0.5)
    d = s.denetci("ghidra.cfg", 1, 0, toplam=9)
    saat.ilerle(0.6)                          # adım başından 1,1 sn
    assert d.denetle(4) is True
    hatalar["cfg"] = d.neden()
    s.bitti("ghidra.cfg")
    son = _olaylar(olay_kaydi)[-1]
    assert son == {"asama": "static", "adim": "ghidra.cfg", "durum": "kismi", "islenen": "4",
                   "toplam": "9", "gecen_sn": "1.1",
                   "neden": "cfg: adım bütçesi (1 sn) doldu"}


def test_adim_saati_dolmayan_denetci_bitis_olayina_alan_eklemez(saat, olay_kaydi) -> None:
    s = _AdimSaati({})
    s.basla("ghidra.cfg")
    d = s.denetci("ghidra.cfg", 100, 0, toplam=9)
    d.denetle(1)
    s.bitti("ghidra.cfg")
    assert _olaylar(olay_kaydi)[-1] == {"asama": "static", "adim": "ghidra.cfg",
                                        "durum": "bitti", "gecen_sn": "0.0"}


# ---------------------------------------------------------------------------
# Sahte Ghidra program nesneleri (her yinelenen birim saati 1 sn ilerletir)
# ---------------------------------------------------------------------------

class _Adres:
    def __init__(self, off: int) -> None:
        self.off = off

    def __str__(self) -> str:
        return "%08x" % self.off


class _Yineleyici:
    """Java yineleyicisi (``hasNext`` / ``next``) ve Python yinelemesi; her öğe saati ilerletir."""

    def __init__(self, ogeler, saat: _Saat | None, adim: float = 1.0) -> None:
        self._ogeler = list(ogeler)
        self._i = 0
        self._saat = saat
        self._adim = adim

    def hasNext(self) -> bool:  # noqa: N802
        return self._i < len(self._ogeler)

    def next(self):
        o = self._ogeler[self._i]
        self._i += 1
        if self._saat is not None:
            self._saat.ilerle(self._adim)
        return o

    def __iter__(self):
        # Python ``for`` döngüsünde öğe önce alınır, iş gövdede yapılır: saat öğenin işi
        # bittikten sonra (bir sonraki öğe istenince) ilerler.
        for o in self._ogeler:
            yield o
            if self._saat is not None:
                self._saat.ilerle(self._adim)


class _Govde:
    def getAddresses(self, ileri):  # noqa: N802
        return _Yineleyici([], None)


class _Sembol:
    def __init__(self, tur) -> None:
        self._tur = tur

    def getSource(self):  # noqa: N802
        return self._tur

    def getSymbolType(self):  # noqa: N802
        return self._tur

    def getAddress(self):  # noqa: N802
        return _Adres(0x9000)


class _Fonk:
    def __init__(self, ad: str, off: int, kaynak="ANALYSIS") -> None:
        self._ad, self._adr, self._kaynak = ad, _Adres(off), kaynak

    def getName(self):  # noqa: N802
        return self._ad

    def getEntryPoint(self):  # noqa: N802
        return self._adr

    def getBody(self):  # noqa: N802
        return _Govde()

    def getSymbol(self):  # noqa: N802
        return _Sembol(self._kaynak)

    def getComment(self):  # noqa: N802
        return "libc"


class _Veri:
    def __init__(self, off: int, tip: str = "string") -> None:
        self._off, self._tip = off, tip

    def getDataType(self):  # noqa: N802
        return types.SimpleNamespace(getName=lambda: self._tip)

    def getAddress(self):  # noqa: N802
        return _Adres(self._off)

    def getDefaultValueRepresentation(self):  # noqa: N802
        return '"s%x"' % self._off

    def getLength(self):  # noqa: N802
        return 4


class _Tipdef:
    def __init__(self, ad: str) -> None:
        self._ad = ad

    def getName(self):  # noqa: N802
        return self._ad

    def getCategoryPath(self):  # noqa: N802
        return "/k"

    def getBaseDataType(self):  # noqa: N802
        return "int"

    def getLength(self):  # noqa: N802
        return 4


class _Program:
    """N fonksiyon, N dizgi verisi, N tip, N komut, N genel sembol."""

    def __init__(self, saat: _Saat | None, n: int = 10) -> None:
        self.saat = saat
        self.n = n
        self.fonklar = [_Fonk("f%d" % i if i % 2 else "FUN_%d" % i, 0x1000 + 0x10 * i)
                        for i in range(n)]

    def getName(self):  # noqa: N802
        return "sahte"

    def getFunctionManager(self):  # noqa: N802
        p = self
        return types.SimpleNamespace(
            getFunctions=lambda ileri: _Yineleyici(p.fonklar, p.saat),
            getFunctionContaining=lambda a: None,
            getFunctionAt=lambda a: None,
            getFunctionCount=lambda: p.n,
        )

    def getReferenceManager(self):  # noqa: N802
        return types.SimpleNamespace(getReferencesTo=lambda a: [],
                                     getReferencesFrom=lambda a: [])

    def getListing(self):  # noqa: N802
        p = self
        return types.SimpleNamespace(
            getDefinedData=lambda ileri: _Yineleyici(
                [_Veri(0x5000 + i, "string" if i % 3 else "dword") for i in range(p.n)], p.saat),
            getInstructions=lambda *a: _Yineleyici(range(p.n), p.saat, 0.001),
            getDefinedDataAt=lambda a: None,
        )

    def getDataTypeManager(self):  # noqa: N802
        p = self
        return types.SimpleNamespace(
            getAllDataTypes=lambda: _Yineleyici([_Tipdef("t%d" % i) for i in range(p.n)],
                                                p.saat))

    def getSymbolTable(self):  # noqa: N802
        p = self
        return types.SimpleNamespace(
            getAllSymbols=lambda ileri: _Yineleyici([_Sembol("LABEL") for _ in range(p.n)],
                                                    p.saat, 0.001))


@pytest.fixture
def ghidra_sahte(monkeypatch):
    """Döküm işlevlerinin içe aktardığı Ghidra sınıfları (yalnız ad / tür denetimi için)."""
    class Structure:
        pass

    class Union:
        pass

    class Enum:
        pass

    class _Blok:
        def __init__(self, program) -> None:
            pass

        def getCodeBlocksContaining(self, govde, izleyici):  # noqa: N802
            return _Yineleyici([], None)

    adlar = ["ghidra", "ghidra.program", "ghidra.program.model", "ghidra.program.model.data",
             "ghidra.program.model.symbol", "ghidra.program.model.block", "ghidra.util",
             "ghidra.util.task"]
    mods = {}
    for ad in adlar:
        mods[ad] = types.ModuleType(ad)
        monkeypatch.setitem(sys.modules, ad, mods[ad])
    veri = mods["ghidra.program.model.data"]
    veri.Structure, veri.Union, veri.Enum, veri.TypeDef = Structure, Union, Enum, _Tipdef
    mods["ghidra.program.model.symbol"].SymbolType = types.SimpleNamespace(
        FUNCTION="FUNCTION", PARAMETER="PARAMETER", LOCAL_VAR="LOCAL_VAR")
    mods["ghidra.program.model.symbol"].SourceType = types.SimpleNamespace(ANALYSIS="ANALYSIS")
    mods["ghidra.program.model.block"].BasicBlockModel = _Blok
    mods["ghidra.util.task"].ConsoleTaskMonitor = lambda: types.SimpleNamespace(
        isCancelled=lambda: False)
    return mods


# Adım → (işlev, birim sayısını veren anahtar). Fonksiyon döngülerinde toplam bilinir.
ISLEVLER = {
    "ghidra.strings": GhidraHeadless._extract_strings,
    "ghidra.call_graph": GhidraHeadless._extract_call_graph,
    "ghidra.types": GhidraHeadless._extract_types,
    "ghidra.xref": GhidraHeadless._extract_xrefs,
    "ghidra.cfg": GhidraHeadless._extract_cfg,
    "ghidra.function_id": GhidraHeadless._extract_function_id_matches,
}
TOPLAMLI = {"ghidra.call_graph", "ghidra.xref", "ghidra.cfg", "ghidra.function_id"}


@pytest.mark.parametrize("adim", sorted(ISLEVLER))
def test_denetcisiz_ve_butcesiz_cikti_bayt_bayt_ayni(adim, saat, ghidra_sahte) -> None:
    taban = ISLEVLER[adim](_Program(saat))
    d = _AdimDenetcisi(adim, 0, 15, saat.t, toplam=10)  # bütçe yok, olay açık
    sonra = ISLEVLER[adim](_Program(saat), denetci=d)
    assert json.dumps(sonra) == json.dumps(taban)
    assert not any(k in sonra for k in ("kismi", "islenen", "toplam", "neden"))


@pytest.mark.parametrize("adim", sorted(ISLEVLER))
def test_butce_dolunca_birim_sinirinda_kismi_gecerli_json(adim, saat, ghidra_sahte) -> None:
    # her birim 1 sn; bütçe 3,5 sn → 4 birim biter (0, 1, 2, 3 sn'de denetim geçer)
    toplam = 10 if adim in TOPLAMLI else None
    d = _AdimDenetcisi(adim, 3.5, 0, saat.t, toplam=toplam)
    out = ISLEVLER[adim](_Program(saat), denetci=d)
    json.loads(json.dumps(out))
    assert out["kismi"] is True
    assert out["islenen"] == 4
    assert out["neden"].startswith("adım bütçesi (3.5 sn) doldu")
    if toplam is None:
        assert "toplam" not in out
    else:
        assert out["toplam"] == 10


def test_kismi_cikti_birim_sayilari_tutarli(saat, ghidra_sahte) -> None:
    d = _AdimDenetcisi("ghidra.call_graph", 3.5, 0, saat.t, toplam=10)
    out = GhidraHeadless._extract_call_graph(_Program(saat), denetci=d)
    assert out["total_functions"] == 4 == len(out["nodes"])
    assert list(out["nodes"]) == ["00001000", "00001010", "00001020", "00001030"]
    d = _AdimDenetcisi("ghidra.cfg", 3.5, 0, saat.t, toplam=10)
    out = GhidraHeadless._extract_cfg(_Program(saat), denetci=d)
    assert out["total_functions"] == 4
    d = _AdimDenetcisi("ghidra.function_id", 3.5, 0, saat.t, toplam=10)
    out = GhidraHeadless._extract_function_id_matches(_Program(saat), denetci=d)
    assert [m["name"] for m in out["matches"]] == ["f1", "f3"]
    d = _AdimDenetcisi("ghidra.strings", 3.5, 0, saat.t)
    out = GhidraHeadless._extract_strings(_Program(saat), denetci=d)
    assert [s["address"] for s in out["strings"]] == ["00005001", "00005002"]  # 4 veri, 2 dizgi


def test_xref_butce_fonksiyonlarda_dolunca_sembol_sayimi_yapilmaz(saat, ghidra_sahte) -> None:
    d = _AdimDenetcisi("ghidra.xref", 3.5, 0, saat.t, toplam=10)
    out = GhidraHeadless._extract_xrefs(_Program(saat), denetci=d)
    assert out["statistics"]["total_functions"] == 4
    assert out["statistics"]["total_globals_with_xrefs"] == 0
    assert out["neden"] == "adım bütçesi (3.5 sn) doldu; genel sembol sayımı yapılmadı"


def test_xref_butce_sembol_sayiminda_dolarsa_neden_soyler(saat, ghidra_sahte, monkeypatch):
    # 10 fonksiyon 10 sn; semboller 0,001 sn; bütçe 10,5 sn → semboller adımlı denetimde kesilir
    n = KUCUK_BIRIM_DENETIM_ADIMI * 3
    p = _Program(saat, n=10)
    p.getSymbolTable = lambda: types.SimpleNamespace(  # type: ignore[method-assign]
        getAllSymbols=lambda ileri: _Yineleyici([_Sembol("LABEL") for _ in range(n)], saat, 0.4))
    d = _AdimDenetcisi("ghidra.xref", 10.5, 0, saat.t, toplam=10)
    out = GhidraHeadless._extract_xrefs(p, denetci=d)
    assert out["kismi"] is True and out["islenen"] == 10 and out["toplam"] == 10
    assert out["neden"] == ("adım bütçesi (10.5 sn) doldu; genel sembol sayımı yarıda (%d sembol)"
                            % KUCUK_BIRIM_DENETIM_ADIMI)


def test_pcode_istatistik_kucuk_birim_adimli_denetim(saat) -> None:
    n = KUCUK_BIRIM_DENETIM_ADIMI * 3
    p = _Program(saat, n=n)
    p.getListing = lambda: types.SimpleNamespace(  # type: ignore[method-assign]
        getInstructions=lambda *a: _Yineleyici(range(n), saat, 1.0))
    taban = GhidraHeadless._extract_pcode_stats_only(_Program(None, n=n))
    d = _AdimDenetcisi("ghidra.pcode", 1.5, 0, saat.t)
    out = GhidraHeadless._extract_pcode_stats_only(p, denetci=d)
    # 0. komutta denetim geçer (0 sn), 1024. komutta 1024 sn > 1,5: kesilir
    assert out["total_pcode_ops"] == KUCUK_BIRIM_DENETIM_ADIMI
    assert out["kismi"] is True and out["islenen"] == KUCUK_BIRIM_DENETIM_ADIMI
    assert taban["total_pcode_ops"] == n and "kismi" not in taban


def test_dongu_ici_suruyor_olayi_gercek_sayac(saat, ghidra_sahte, olay_kaydi) -> None:
    d = _AdimDenetcisi("ghidra.cfg", 0, 3, saat.t, toplam=10)
    GhidraHeadless._extract_cfg(_Program(saat), denetci=d)
    ol = [o for o in _olaylar(olay_kaydi) if o["durum"] == "suruyor"]
    # denetim her fonksiyonun başında; 3., 6., 9. sn'de olay (islenen o ana kadar biten)
    assert [(o["islenen"], o["toplam"], o["gecen_sn"]) for o in ol] == [
        ("3", "10", "3.0"), ("6", "10", "6.0"), ("9", "10", "9.0")]


# ---------------------------------------------------------------------------
# Köprü (_analyze_pyghidra) — HZ-1'in sahte köprüsüyle
# ---------------------------------------------------------------------------

def _kos(gh, tmp_path):
    return gh._analyze_pyghidra(tmp_path / "x", tmp_path / "p", "p", 60, tmp_path)


def _denetci_kaydeden(monkeypatch, saat, ad: str, adim_adi: str, cikti: dict, birim: int):
    """``ad`` işlevini denetçiyi kaydeden ve ``birim`` kez 1 sn ilerleyip denetleyen sahteyle değiştir."""
    gorulen: dict = {}

    def f(program, denetci=None):
        gorulen["denetci"] = denetci
        out = json.loads(json.dumps(cikti))
        for i in range(birim):
            if denetci is not None and denetci.denetle(i):
                break
            saat.ilerle(1.0)
        if denetci is not None:
            out.update(denetci.kismi_alanlari())
        return out

    monkeypatch.setattr(GhidraHeadless, ad, staticmethod(f))
    return gorulen


CFG_CIKTI = {"total_functions": 0, "total_blocks": 0, "total_edges": 0, "functions": []}


def test_kopru_butce_ayardan_toplam_fonksiyon_adimindan(kopru, tmp_path, monkeypatch) -> None:
    gh, saat, kayit = kopru
    gh.config.timeouts.ghidra_adim = 7
    gh.config.analysis.bekci_aralik_sn = 4
    gorulen = _denetci_kaydeden(monkeypatch, saat, "_extract_cfg", "ghidra.cfg", CFG_CIKTI, 3)
    sonuc = _kos(gh, tmp_path)
    d = gorulen["denetci"]
    assert d.butce_sn == 7 and d.aralik_sn == 4 and d.adim == "ghidra.cfg"
    assert d.toplam == 2                     # sahte functions adımının total'ı
    assert "cfg" not in sonuc["step_errors"]
    assert "kismi" not in kayit["kaydedilen"]["cfg.json"]


def test_kopru_butce_dolunca_adim_hatasi_kismi_olay_ve_kismi_json(kopru, tmp_path, monkeypatch,
                                                                  olay_kaydi) -> None:
    gh, saat, kayit = kopru
    gh.config.timeouts.ghidra_adim = 2
    _denetci_kaydeden(monkeypatch, saat, "_extract_cfg", "ghidra.cfg", CFG_CIKTI, 10)
    sonuc = _kos(gh, tmp_path)
    assert sonuc["step_errors"]["cfg"] == "adım bütçesi (2 sn) doldu"
    assert sonuc["success"] is True          # bütçe aşımı başarıyı bozmaz, kısmi sayılır
    yazilan = kayit["kaydedilen"]["cfg.json"]
    assert yazilan["kismi"] is True and yazilan["islenen"] == 3 and yazilan["toplam"] == 2
    son = [o for o in _olaylar(olay_kaydi) if o["adim"] == "ghidra.cfg"][-1]
    assert son["durum"] == "kismi" and son["islenen"] == "3" and son["toplam"] == "2"
    assert son["neden"] == "cfg: adım bütçesi (2 sn) doldu"
    assert "WARN: cfg: adım bütçesi (2 sn) doldu" in sonuc["ghidra_log"]


@pytest.mark.parametrize("ad,adim_adi,anahtar,cikti", [
    ("_extract_strings", "ghidra.strings", "strings", {"total": 0, "strings": []}),
    ("_extract_call_graph", "ghidra.call_graph", "call_graph",
     {"total_functions": 0, "total_edges": 0}),
    ("_extract_types", "ghidra.types", "types",
     {"total_structures": 0, "total_enums": 0, "total_typedefs": 0}),
    ("_extract_xrefs", "ghidra.xref", "xrefs", {"statistics": {
        "total_functions": 0, "total_strings_with_xrefs": 0, "total_globals_with_xrefs": 0}}),
    ("_extract_function_id_matches", "ghidra.function_id", "function_id", {"total_matches": 0}),
    ("_extract_pcode_stats_only", "ghidra.pcode", "pcode",
     {"total_functions": 0, "mode": "stats_only"}),
])
def test_kopru_her_dokum_adimi_bagli(kopru, tmp_path, monkeypatch, ad, adim_adi, anahtar,
                                     cikti) -> None:
    gh, saat, _ = kopru
    gh.config.timeouts.ghidra_adim = 2
    if anahtar == "pcode":
        gh.config.binary_reconstruction.enable_pcode_extraction = False
    gorulen = _denetci_kaydeden(monkeypatch, saat, ad, adim_adi, cikti, 10)
    sonuc = _kos(gh, tmp_path)
    assert gorulen["denetci"].adim == adim_adi
    assert sonuc["step_errors"][anahtar] == "adım bütçesi (2 sn) doldu"


def test_kopru_bsim_ingest_ve_sorgu_denetcisi(kopru, tmp_path) -> None:
    gh, _, _ = kopru
    gh.config.timeouts.ghidra_adim = 3600
    gh.config.bsim.ingest_butcesi_sn = 900
    gh.config.analysis.bekci_aralik_sn = 15
    gorulen: dict = {}
    eski_ingest, eski_sorgu = _BSim.ingest_program, _BSim.query_all_functions

    def ingest(self, program, db):
        gorulen["ingest"] = self.denetci
        return eski_ingest(self, program, db)

    def sorgu(self, program, sim, db_name=None):
        gorulen["sorgu"] = self.denetci
        return eski_sorgu(self, program, sim, db_name=db_name)

    _BSim.ingest_program, _BSim.query_all_functions = ingest, sorgu
    try:
        _kos(gh, tmp_path)
    finally:
        _BSim.ingest_program, _BSim.query_all_functions = eski_ingest, eski_sorgu
    assert gorulen["ingest"].adim == "ghidra.bsim.ingest" and gorulen["ingest"].butce_sn == 900
    assert gorulen["ingest"].toplam == 2     # functions adımının program_function_count'u
    assert gorulen["sorgu"].adim == "ghidra.bsim.query" and gorulen["sorgu"].butce_sn == 3600
    assert gorulen["sorgu"].aralik_sn == 15


def test_kopru_bsim_ingest_butcesi_adim_butcesinden_kucukse(kopru, tmp_path) -> None:
    gh, _, _ = kopru
    gh.config.timeouts.ghidra_adim = 2
    gh.config.bsim.ingest_butcesi_sn = 900
    gorulen: dict = {}
    eski = _BSim.ingest_program

    def ingest(self, program, db):
        gorulen["ingest"] = self.denetci
        return eski(self, program, db)

    _BSim.ingest_program = ingest
    try:
        _kos(gh, tmp_path)
    finally:
        _BSim.ingest_program = eski
    assert gorulen["ingest"].butce_sn == 2


def test_kopru_bsim_ingest_dolunca_adim_hatasi(kopru, tmp_path, olay_kaydi) -> None:
    gh, saat, _ = kopru
    gh.config.timeouts.ghidra_adim = 0
    gh.config.bsim.ingest_butcesi_sn = 1
    eski = _BSim.ingest_program

    def ingest(self, program, db):
        out = eski(self, program, db)        # saati 2,5 sn ilerletir
        assert self.denetci.denetle(1, 2) is True
        return out

    _BSim.ingest_program = ingest
    try:
        sonuc = _kos(gh, tmp_path)
    finally:
        _BSim.ingest_program = eski
    assert sonuc["step_errors"]["bsim_ingest"] == "adım bütçesi (1 sn) doldu"
    assert "bsim_query" not in sonuc["step_errors"]
    son = [o for o in _olaylar(olay_kaydi) if o["adim"] == "ghidra.bsim.ingest"][-1]
    assert son["durum"] == "kismi" and son["islenen"] == "1" and son["toplam"] == "2"


def test_kopru_bsim_sorgu_atlandi_olayi_adim_hatasi_degil(kopru, tmp_path, olay_kaydi) -> None:
    gh, _, kayit = kopru
    eski = _BSim.query_all_functions
    detay = {"status": "atlandi", "sorgu_atlandi": True, "neden": "depoda başka program yok"}

    def sorgu(self, program, sim, db_name=None):
        eski(self, program, sim, db_name=db_name)
        return types.SimpleNamespace(total_matches=0, to_payload=lambda: {
            "total_matches": 0, "total_queries": 0, "matches": [], "bsim_mode": "native",
            "bsim_status": "atlandi", "bsim_detail": detay})

    _BSim.query_all_functions = sorgu
    try:
        sonuc = _kos(gh, tmp_path)
    finally:
        _BSim.query_all_functions = eski
    assert not any(k.startswith("bsim") for k in sonuc["step_errors"])
    ol = [o for o in _olaylar(olay_kaydi) if o["adim"] == "ghidra.bsim.query"]
    assert [o["durum"] for o in ol] == ["basladi", "atlandi", "bitti"]
    assert ol[1]["neden"] == "depoda başka program yok"
    assert kayit["kaydedilen"]["bsim_matches.json"]["bsim_status"] == "atlandi"


def test_kopru_ontanimli_butcede_cikti_alanlari_yok(kopru, tmp_path, monkeypatch) -> None:
    """Bütçe öntanımında (yamanın 3 600 sn'si) hiçbir adım kesilmez, çıktıya alan eklenmez."""
    gh, saat, kayit = kopru
    gh.config.timeouts.ghidra_adim = 3600
    gh.config.bsim.ingest_butcesi_sn = 900
    sonuc = _kos(gh, tmp_path)
    assert sonuc["step_errors"] == {}
    for ad, veri in kayit["kaydedilen"].items():
        assert "kismi" not in veri and "neden" not in veri, ad
    assert sonuc["adim_sureleri"] == SURE
