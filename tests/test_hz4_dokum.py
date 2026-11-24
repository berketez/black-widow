"""HZ-4a: döküm adımlarında tek başvuru geçişi — eski ve yeni yol aynı çıktıyı verir.

Çağrı grafiği ve xref dökümü ``_BasvuruTablosu`` üstünden (yalnız başvurusu olan adresler,
fonksiyon başına tek geçiş, iki adım ortak kayıt) kurulur; CFG dökümü bu pakette değişmedi
(ölçümde Python tarafında kazanç yolu çıkmadı). Sözleşme: çıktı eski döngülerle bayt bayt aynı (``json.dumps`` metni), ÖL-2'nin bütçe /
``suruyor`` / kısmi çıktı davranışı aynı, Java çağrısı sayısı düşer.

Ghidra yok: program, başvuru yöneticisi, liste, simge tablosu ve blok modeli sahte. Sahte
nesneler çağrı sayar; ``getReferencesTo`` isteğe bağlı karışık sırada, ``getReferenceSourceIterator``
isteğe bağlı BOZUK sırada döner (sıra güvencesinin sınaması).
"""
from __future__ import annotations

import json
import logging
import sys
import types
from collections import Counter

import pytest

from karadul.ghidra import headless as headless_mod
from karadul.ghidra.headless import (
    KUCUK_BIRIM_DENETIM_ADIMI,
    GhidraHeadless,
    _AdimDenetcisi,
    _BasvuruTablosu,
)

# ---------------------------------------------------------------------------
# Sahte Ghidra nesneleri
# ---------------------------------------------------------------------------


class _Adr:
    def __init__(self, off: int, alan: str = "") -> None:
        self.off, self.alan = off, alan

    def __str__(self) -> str:
        return ("%s:" % self.alan if self.alan else "") + "%08x" % self.off

    def __eq__(self, other) -> bool:
        return isinstance(other, _Adr) and (other.alan, other.off) == (self.alan, self.off)

    def __hash__(self) -> int:
        return hash((self.alan, self.off))

    def compareTo(self, other) -> int:  # noqa: N802
        a, b = (self.alan, self.off), (other.alan, other.off)
        return (a > b) - (a < b)

    def getOffset(self) -> int:  # noqa: N802
        return self.off


class _Iter:
    """Java yineleyicisi (``hasNext`` / ``next``) ve Python yinelemesi."""

    def __init__(self, xs, saat=None, adim: float = 0.0) -> None:
        self.xs, self.i, self.saat, self.adim = list(xs), 0, saat, adim

    def hasNext(self) -> bool:  # noqa: N802
        return self.i < len(self.xs)

    def next(self):
        self.i += 1
        if self.saat is not None:
            self.saat.ilerle(self.adim)
        return self.xs[self.i - 1]

    def __iter__(self):
        # Python ``for`` döngüsünde öğe önce alınır, iş gövdede yapılır: saat öğenin işi
        # bittikten sonra (bir sonraki öğe istenince) ilerler.
        for x in self.xs:
            yield x
            if self.saat is not None:
                self.saat.ilerle(self.adim)


class _Tur:
    def __init__(self, ad: str) -> None:
        self.ad = ad

    def isCall(self) -> bool:  # noqa: N802
        return self.ad == "cagri"

    def isData(self) -> bool:  # noqa: N802
        return self.ad == "veri"


class _Ref:
    def __init__(self, kaynak: int, hedef, tur: str = "cagri") -> None:
        self.kaynak = _Adr(kaynak)
        self.hedef = hedef if isinstance(hedef, _Adr) else _Adr(hedef)
        self.tur = tur

    def getFromAddress(self):  # noqa: N802
        return self.kaynak

    def getToAddress(self):  # noqa: N802
        return self.hedef

    def getReferenceType(self):  # noqa: N802
        return _Tur(self.tur)

    def __repr__(self) -> str:
        return "Ref(%s→%s,%s)" % (self.kaynak, self.hedef, self.tur)


class _Kume:
    """Adres kümesi (gövde ya da blok): kapalı aralıklar listesi."""

    def __init__(self, *araliklar) -> None:
        self.araliklar = sorted(araliklar)

    def icerir(self, off: int) -> bool:
        return any(a <= off <= b for a, b in self.araliklar)

    def offlar(self) -> list[int]:
        return [o for a, b in self.araliklar for o in range(a, b + 1)]

    def getAddresses(self, ileri):  # noqa: N802
        assert ileri is True
        return _Iter(_Adr(o) for o in self.offlar())

    def getNumAddresses(self) -> int:  # noqa: N802
        return len(self.offlar())


class _Fonk:
    def __init__(self, ad: str, bas: int, boy: int = 0x40, govde: _Kume | None = None) -> None:
        self.ad, self.bas = ad, bas
        self.govde = govde if govde is not None else (
            _Kume((bas, bas + boy - 1)) if boy else _Kume())

    def getName(self) -> str:  # noqa: N802
        return self.ad

    def getEntryPoint(self):  # noqa: N802
        return _Adr(self.bas)

    def getBody(self):  # noqa: N802
        return self.govde


class _DisFonk:
    """Dış (EXTERNAL) fonksiyon: ``getFunctions(True)``'da yok, ``getFunctionAt`` ile bulunur."""

    def __init__(self, ad: str, off: int) -> None:
        self.ad, self.adr = ad, _Adr(off, "EXTERNAL")

    def getName(self) -> str:  # noqa: N802
        return self.ad

    def getEntryPoint(self):  # noqa: N802
        return self.adr


class _FM:
    def __init__(self, fonklar, dis, sayac: Counter, saat=None) -> None:
        self.fonklar = sorted(fonklar, key=lambda f: f.bas)
        self.dis, self.sayac, self.saat = list(dis), sayac, saat

    def getFunctions(self, ileri):  # noqa: N802
        return _Iter(self.fonklar, self.saat, 1.0)

    def getFunctionAt(self, adr):  # noqa: N802
        self.sayac["getFunctionAt"] += 1
        for f in self.dis:
            if f.adr == adr:
                return f
        for f in self.fonklar:
            if _Adr(f.bas) == adr:
                return f
        return None

    def getFunctionContaining(self, adr):  # noqa: N802
        self.sayac["getFunctionContaining"] += 1
        if adr.alan:
            return None
        for f in self.fonklar:
            if f.govde.icerir(adr.off):
                return f
        return None


class _RM:
    def __init__(self, refs, sayac: Counter, to_sira=None, kaynak_sira=None) -> None:
        self.refs, self.sayac = list(refs), sayac
        self.to_sira = to_sira or (lambda xs: xs)
        self.kaynak_sira = kaynak_sira or (lambda xs: xs)

    def getReferencesFrom(self, adr):  # noqa: N802
        self.sayac["getReferencesFrom"] += 1
        return [r for r in self.refs if r.kaynak == adr]

    def getReferencesTo(self, adr):  # noqa: N802
        self.sayac["getReferencesTo"] += 1
        return _Iter(self.to_sira([r for r in self.refs if r.hedef == adr]))

    def hasReferencesTo(self, adr) -> bool:  # noqa: N802
        self.sayac["hasReferencesTo"] += 1
        return any(r.hedef == adr for r in self.refs)

    def getReferenceSourceIterator(self, kume, ileri):  # noqa: N802
        assert ileri is True
        self.sayac["getReferenceSourceIterator"] += 1
        offlar = sorted({r.kaynak.off for r in self.refs if kume.icerir(r.kaynak.off)})
        return _Iter(_Adr(o) for o in self.kaynak_sira(offlar))


class _RMEski:
    """``getReferenceSourceIterator`` / ``hasReferencesTo`` OLMAYAN başvuru yöneticisi."""

    def __init__(self, rm: _RM) -> None:
        self.getReferencesFrom = rm.getReferencesFrom
        self.getReferencesTo = rm.getReferencesTo


class _Veri:
    def __init__(self, tip: str, deger) -> None:
        self.tip, self.deger = tip, deger

    def getDataType(self):  # noqa: N802
        return types.SimpleNamespace(getName=lambda: self.tip)

    def getDefaultValueRepresentation(self):  # noqa: N802
        return self.deger


class _Komut:
    def __init__(self, off: int, ad: str) -> None:
        self.off, self.ad = off, ad

    def getMnemonicString(self) -> str:  # noqa: N802
        return self.ad


class _Listing:
    def __init__(self, veriler: dict, komutlar, sayac: Counter) -> None:
        self.veriler, self.komutlar, self.sayac = veriler, list(komutlar), sayac

    def getDefinedDataAt(self, adr):  # noqa: N802
        self.sayac["getDefinedDataAt"] += 1
        return self.veriler.get(adr.off) if not adr.alan else None

    def getInstructions(self, kume, ileri):  # noqa: N802
        assert ileri is True
        self.sayac["getInstructions"] += 1
        return _Iter(k for k in self.komutlar if kume.icerir(k.off))


class _SimgeTuru:
    def __init__(self, kimlik: int) -> None:
        self.kimlik = kimlik

    def getID(self) -> int:  # noqa: N802
        return self.kimlik


SIMGE_TURLERI = types.SimpleNamespace(
    LABEL=_SimgeTuru(0), LIBRARY=_SimgeTuru(1), NAMESPACE=_SimgeTuru(3), CLASS=_SimgeTuru(4),
    FUNCTION=_SimgeTuru(5), PARAMETER=_SimgeTuru(6), LOCAL_VAR=_SimgeTuru(7),
    GLOBAL_VAR=_SimgeTuru(8))


class _Simge:
    def __init__(self, tur: _SimgeTuru, off: int) -> None:
        self.tur, self.adr = tur, _Adr(off)

    def getSymbolType(self):  # noqa: N802
        return self.tur

    def getAddress(self):  # noqa: N802
        return self.adr


class _Akis:
    def __init__(self, ad: str) -> None:
        self.ad = ad

    def isCall(self) -> bool:  # noqa: N802
        return self.ad == "cagri"

    def isFallthrough(self) -> bool:  # noqa: N802
        return self.ad == "dusme"

    def isConditional(self) -> bool:  # noqa: N802
        return self.ad == "kosullu"

    def isUnConditional(self) -> bool:  # noqa: N802
        return self.ad == "kosulsuz"


class _Blok(_Kume):
    def __init__(self, bas: int, son: int, hedefler=()) -> None:
        super().__init__((bas, son))
        self.bas, self.son, self.hedefler = bas, son, list(hedefler)
        self.model = None

    def getFirstStartAddress(self):  # noqa: N802
        return _Adr(self.bas)

    def getMaxAddress(self):  # noqa: N802
        return _Adr(self.son)

    def getDestinations(self, izleyici):  # noqa: N802
        self.model.sayac["getDestinations"] += 1
        out = []
        for hedef_bas, akis in self.hedefler:
            hedef = self.model.blok(hedef_bas) if hedef_bas is not None else None
            out.append(types.SimpleNamespace(
                getDestinationBlock=lambda h=hedef: h, getFlowType=lambda a=akis: _Akis(a)))
        return _Iter(out)


class _BlokModeli:
    """Sahte ``BasicBlockModel``: bulunan blokları ``bulunan``'da biriktirir (gerçeğin
    ``foundBlockMap``'i gibi); kaç model kurulduğu ve en büyük birikim sayılır."""

    kurulan = 0
    en_buyuk_birikim = 0
    program = None

    def __init__(self, program) -> None:
        type(self).kurulan += 1
        self.p = program
        self.sayac = program.sayac
        self.bulunan: set[int] = set()

    def blok(self, bas: int):
        b = next(b for b in self.p.bloklar if b.bas == bas)
        b.model = self
        self.bulunan.add(bas)
        type(self).en_buyuk_birikim = max(type(self).en_buyuk_birikim, len(self.bulunan))
        return b

    def getCodeBlocksContaining(self, govde, izleyici):  # noqa: N802
        self.sayac["getCodeBlocksContaining"] += 1
        return _Iter(self.blok(b.bas) for b in sorted(self.p.bloklar, key=lambda b: b.bas)
                     if any(govde.icerir(o) for o in (b.bas, b.son)))


class _Program:
    def __init__(self, fonklar, refs, *, dis=(), veriler=None, simgeler=(), bloklar=(),
                 komutlar=(), to_sira=None, kaynak_sira=None, eski_api=False, saat=None) -> None:
        self.sayac: Counter = Counter()
        self.fm = _FM(fonklar, dis, self.sayac, saat)
        self.rm = _RM(refs, self.sayac, to_sira, kaynak_sira)
        self.eski_api = eski_api
        self.listing = _Listing(veriler or {}, komutlar, self.sayac)
        self.simgeler, self.bloklar, self.saat = list(simgeler), list(bloklar), saat
        self.degisiklik = 7

    def getName(self) -> str:  # noqa: N802
        return "sahte"

    def getFunctionManager(self):  # noqa: N802
        return self.fm

    def getReferenceManager(self):  # noqa: N802
        return _RMEski(self.rm) if self.eski_api else self.rm

    def getListing(self):  # noqa: N802
        return self.listing

    def getSymbolTable(self):  # noqa: N802
        return types.SimpleNamespace(
            getAllSymbols=lambda ileri: _Iter(self.simgeler, self.saat, 0.001))

    def getModificationNumber(self) -> int:  # noqa: N802
        return self.degisiklik


@pytest.fixture
def ghidra_sahte(monkeypatch):
    """Döküm işlevlerinin içeride içe aktardığı Ghidra sınıfları."""
    _BlokModeli.kurulan = 0
    _BlokModeli.en_buyuk_birikim = 0
    mods = {}
    for ad in ("ghidra", "ghidra.program", "ghidra.program.model", "ghidra.program.model.symbol",
               "ghidra.program.model.block", "ghidra.util", "ghidra.util.task"):
        mods[ad] = types.ModuleType(ad)
        monkeypatch.setitem(sys.modules, ad, mods[ad])
    mods["ghidra.program.model.symbol"].SymbolType = SIMGE_TURLERI
    mods["ghidra.program.model.block"].BasicBlockModel = _BlokModeli
    mods["ghidra.util.task"].ConsoleTaskMonitor = lambda: types.SimpleNamespace(
        isCancelled=lambda: False)
    return mods


# ---------------------------------------------------------------------------
# Senaryo
#
#   ana   00001000..3f  çağırır: orta (2 yerden), yaprak, orta'nın İÇİNE (00002008 → orta),
#                        dış fonksiyon puts, kendini (özyineleme: sayılmaz), fonksiyonsuz adres
#                        veri: "merhaba" (2 yerden), dword (dizgi değil), tek tırnaklı, tırnaksız,
#                              None değerli dizgi; bir dizgiye veri OLMAYAN başvuru (atlama)
#   orta  00002000..3f  çağırır: yaprak; veri: "merhaba" (ana ile ortak dizgi)
#   yaprak 00003000..3f başvurusu yok; giriş adresine ana ve orta'dan çağrı + bir veri başvurusu
#                        (işlev göstericisi) + bir atlama
#   bos   00004000      gövdesi boş
#   parcali 00005000..0f + 00005020..2f  iki aralıklı gövde; aradaki 00005018 başka kimsenin
# ---------------------------------------------------------------------------

PUTS = _DisFonk("puts", 0x12)


def _senaryo(**kw) -> _Program:
    fonklar = [
        _Fonk("orta", 0x2000), _Fonk("ana", 0x1000), _Fonk("yaprak", 0x3000),
        _Fonk("bos", 0x4000, boy=0),
        _Fonk("parcali", 0x5000, govde=_Kume((0x5000, 0x500F), (0x5020, 0x502F))),
    ]
    refs = [
        _Ref(0x1030, 0x3000),                 # ana → yaprak (gövdede SONRA)
        _Ref(0x1004, 0x2000),                 # ana → orta
        _Ref(0x1004, 0x9000, "veri"),         # aynı adresten ikinci başvuru: "merhaba"
        _Ref(0x1008, 0x9010, "veri"),         # dword: dizgi değil
        _Ref(0x100C, 0x2008),                 # ana → orta'nın içi (getFunctionContaining)
        _Ref(0x1010, PUTS.adr),               # ana → dış fonksiyon
        _Ref(0x1014, 0x1000),                 # özyineleme
        _Ref(0x1018, 0x7777),                 # fonksiyonsuz hedef
        _Ref(0x101C, 0x9000, "veri"),         # "merhaba" ikinci kez (tekil)
        _Ref(0x1020, 0x9020, "veri"),         # tek tırnaklı
        _Ref(0x1024, 0x9030, "veri"),         # tırnaksız
        _Ref(0x1028, 0x9040, "veri"),         # None değerli dizgi
        _Ref(0x102C, 0x2000),                 # ana → orta (ikinci çağrı yeri)
        _Ref(0x1034, 0x9050, "veri"),         # tanımlı veri yok
        _Ref(0x1038, 0x9010, "atlama"),       # ne çağrı ne veri
        _Ref(0x103C, 0x9060, "atlama"),       # ne çağrı ne veri; hedefi DİZGİ (yine sayılmaz)
        _Ref(0x2010, 0x3000),                 # orta → yaprak
        _Ref(0x2014, 0x9000, "veri"),         # orta → "merhaba"
        _Ref(0x8000, 0x3000, "veri"),         # yaprak'ın adresi alınıyor (fonksiyon dışı veri)
        _Ref(0x2020, 0x3000, "atlama"),       # yaprak'a atlama (çağrı değil)
        _Ref(0x6000, 0x3000),                 # fonksiyon dışından çağrı (arayan yok sayılır)
        _Ref(0x5004, 0x1000),                 # parcali → ana (ilk aralık)
        _Ref(0x5018, 0x2000),                 # aralıkların ARASI: parcali'nin değil
        _Ref(0x5024, 0x3000),                 # parcali → yaprak (ikinci aralık)
    ]
    veriler = {
        0x9000: _Veri("string", '"merhaba"'), 0x9010: _Veri("dword", "0x10"),
        0x9020: _Veri("TerminatedCString", "'tek'"), 0x9030: _Veri("unicode string", "ham"),
        0x9040: _Veri("string", None), 0x9060: _Veri("string", '"gizli"'),
    }
    T = SIMGE_TURLERI
    simgeler = [
        _Simge(T.FUNCTION, 0x3000),           # işlev: sayılmaz (başvurusu olsa da)
        _Simge(T.LABEL, 0x9000),              # başvurulu etiket: sayılır
        _Simge(T.LABEL, 0x9000),              # aynı adreste ikinci simge: yine sayılır
        _Simge(T.LABEL, 0xAAAA),              # başvurusuz
        _Simge(T.PARAMETER, 0x9010), _Simge(T.LOCAL_VAR, 0x9010),
        _Simge(T.GLOBAL_VAR, 0x9010),         # başvurulu genel değişken: sayılır
        _Simge(T.NAMESPACE, 0xBBBB), _Simge(T.CLASS, 0x2000),  # sınıf simgesi başvurulu adreste
    ]
    bloklar = [
        _Blok(0x1000, 0x100F, [(0x1010, "dusme"), (0x1020, "kosullu"), (0x2000, "cagri")]),
        _Blok(0x1010, 0x101F, [(0x1000, "kosulsuz")]),          # geri kenar
        _Blok(0x1020, 0x103F, [(None, "kosulsuz"), (0x1020, "baska")]),  # hedefsiz + bilinmeyen
        _Blok(0x2000, 0x203F, [(0x3000, "kosulsuz")]),          # fonksiyon dışına atlama
        _Blok(0x3000, 0x303F, []),
        _Blok(0x5000, 0x500F, [(0x5020, "kosulsuz")]),
        _Blok(0x5020, 0x502F, [(0x5000, "kosullu")]),
    ]
    komutlar = [_Komut(o, "MOV" if o % 8 else "Bl") for o in range(0x1000, 0x1040, 4)]
    komutlar += [_Komut(0x2000, "RET"), _Komut(0x3000, "NOP"), _Komut(0x5000, "ADD"),
                 _Komut(0x5018, "UDF"), _Komut(0x5020, "SUB")]
    return _Program(fonklar, refs, dis=[PUTS], veriler=veriler, simgeler=simgeler,
                    bloklar=bloklar, komutlar=komutlar, **kw)


def _metin(veri) -> str:
    """``_save_output`` ile aynı serileştirme."""
    return json.dumps(veri, indent=2, ensure_ascii=False, default=str)


def _eski(**kw):
    p = _senaryo(**kw)
    return (GhidraHeadless._extract_call_graph(p), GhidraHeadless._extract_xrefs(p),
            GhidraHeadless._extract_cfg(p), p)


def _yeni(**kw):
    p = _senaryo(**kw)
    t = _BasvuruTablosu.kur(p)
    assert t is not None
    return (GhidraHeadless._extract_call_graph(p, tablo=t),
            GhidraHeadless._extract_xrefs(p, tablo=t, tek_gecis=True),
            GhidraHeadless._extract_cfg(p), p, t)


# ---------------------------------------------------------------------------
# Eşitlik (asıl kabul)
# ---------------------------------------------------------------------------

def test_uc_dokum_eski_ve_yeni_yolda_bayt_bayt_ayni(ghidra_sahte) -> None:
    cg0, xr0, cf0, _ = _eski()
    cg1, xr1, cf1, _, _ = _yeni()
    assert _metin(cg1) == _metin(cg0)
    assert _metin(xr1) == _metin(xr0)
    assert _metin(cf1) == _metin(cf0)


def test_senaryo_bos_degil_beklenen_icerik(ghidra_sahte) -> None:
    """Eşitlik testi boş çıktıların eşitliği olmasın: yeni yolun çıktısı elle beklenenle aynı."""
    cg, xr, cf, _, _ = _yeni()
    ana = cg["nodes"]["00001000"]
    # gövde adres sırası: orta (1004), [1008 veri], orta'nın içi → orta (tekil), puts, yaprak
    assert ana["callees"] == [
        {"name": "orta", "address": "00002000"},
        {"name": "puts", "address": "EXTERNAL:00000012"},
        {"name": "yaprak", "address": "00003000"},
    ]
    assert ana["callers"] == [{"name": "parcali", "address": "00005000"}]
    assert ana["callee_count"] == 3 and ana["caller_count"] == 1
    yaprak = cg["nodes"]["00003000"]
    assert yaprak["callees"] == []
    assert yaprak["callers"] == [
        {"name": "ana", "address": "00001000"}, {"name": "orta", "address": "00002000"},
        {"name": "parcali", "address": "00005000"}]
    assert cg["nodes"]["00004000"] == {
        "name": "bos", "address": "00004000", "caller_count": 0, "callee_count": 0,
        "callers": [], "callees": []}
    # aralıkların arasındaki 00005018 parcali'nin değil: orta'yı çağırmıyor
    assert cg["nodes"]["00005000"]["callees"] == [
        {"name": "ana", "address": "00001000"}, {"name": "yaprak", "address": "00003000"}]
    assert cg["total_functions"] == 5 and cg["total_edges"] == 6
    assert [(e["from"], e["to"]) for e in cg["edges"]] == [
        ("00001000", "00002000"), ("00001000", "EXTERNAL:00000012"), ("00001000", "00003000"),
        ("00002000", "00003000"), ("00005000", "00001000"), ("00005000", "00003000")]
    assert cg["edges"][1] == {"from": "00001000", "to": "EXTERNAL:00000012",
                              "from_name": "ana", "to_name": "puts"}

    x = xr["function_xrefs"]["00001000"]
    assert x["strings_used"] == [
        {"address": "00009000", "value": "merhaba"}, {"address": "00009020", "value": "tek"},
        {"address": "00009030", "value": "ham"}, {"address": "00009040", "value": None}]
    assert x["functions_called"] == ana["callees"] and x["called_by"] == ana["callers"]
    assert xr["function_xrefs"]["00002000"]["strings_used"] == [
        {"address": "00009000", "value": "merhaba"}]
    # 4 ayrı dizgi adresi; simgeler: 2 etiket (9000) + genel değişken (9010) + sınıf (2000)
    assert xr["statistics"] == {"total_functions": 5, "total_strings_with_xrefs": 4,
                                "total_globals_with_xrefs": 4}

    f = {x["address"]: x for x in cf["functions"]}
    assert set(f) == {"00001000", "00002000", "00003000", "00004000", "00005000"}
    assert f["00001000"]["block_count"] == 3 and f["00001000"]["edge_count"] == 4
    assert f["00001000"]["blocks"][0] == {
        "start_address": "00001000", "end_address": "0000100f", "size": 16,
        "instruction_count": 4, "mnemonics": ["bl", "mov", "bl", "mov"]}
    assert f["00001000"]["edges"] == [
        {"from_block": "00001000", "to_block": "00001010", "edge_type": "fall_through"},
        {"from_block": "00001000", "to_block": "00001020", "edge_type": "conditional_jump"},
        {"from_block": "00001010", "to_block": "00001000", "edge_type": "unconditional_jump"},
        {"from_block": "00001020", "to_block": "00001020", "edge_type": "unknown"}]
    assert f["00001000"]["back_edges"] == [["00001010", "00001000"]]
    assert f["00001000"]["loop_headers"] == ["00001000"]
    assert f["00001000"]["cyclomatic_complexity"] == 4 - 3 + 2
    assert f["00004000"]["block_count"] == 0 and f["00004000"]["cyclomatic_complexity"] == 0
    assert [b["mnemonics"] for b in f["00005000"]["blocks"]] == [["add"], ["sub"]]
    assert cf["total_functions"] == 5 and cf["total_blocks"] == 7 and cf["total_edges"] == 7


def test_cikti_listeleri_iki_adim_arasinda_ortak_nesne_degil(ghidra_sahte) -> None:
    """Çağrı grafiği ve xref aynı kayıttan kurulur ama çıktıları birbirinin takma adı olmaz."""
    cg, xr, _, p, t = _yeni()
    xr["function_xrefs"]["00003000"]["called_by"][0]["name"] = "DEĞİŞTİ"
    xr["function_xrefs"]["00001000"]["functions_called"][0]["name"] = "DEĞİŞTİ"
    xr["function_xrefs"]["00001000"]["strings_used"][0]["value"] = "DEĞİŞTİ"
    assert cg["nodes"]["00003000"]["callers"][0]["name"] == "ana"
    assert cg["nodes"]["00001000"]["callees"][0]["name"] == "orta"
    cg["nodes"]["00003000"]["callers"][0]["name"] = "DEĞİŞTİ"
    cg["nodes"]["00001000"]["callees"][0]["name"] = "DEĞİŞTİ"
    # çıktılar değiştirilse de tablodaki kayıt bozulmaz: aynı tablodan yeniden döküm eskiyle aynı
    cg0, xr0, _, _ = _eski()
    assert _metin(GhidraHeadless._extract_xrefs(p, tablo=t, tek_gecis=True)) == _metin(xr0)
    assert _metin(GhidraHeadless._extract_call_graph(p, tablo=t)) == _metin(cg0)


# ---------------------------------------------------------------------------
# Tek geçiş: çağrı sayıları
# ---------------------------------------------------------------------------

def test_yalniz_basvurusu_olan_adresler_gezilir_ve_iki_adim_tek_gecis(ghidra_sahte) -> None:
    *_, p0 = _eski()
    *_, p1, _ = _yeni()
    govde_adresi = 0x40 * 3 + 0x20
    # eski: iki adım × gövdedeki her adres
    assert p0.sayac["getReferencesFrom"] == 2 * govde_adresi
    assert p0.sayac["getReferenceSourceIterator"] == 0
    # yeni: fonksiyon başına bir yineleyici, yalnız başvurusu olan 20 adres (ana 15, orta 3,
    # parcali 2), iki adımda BİR kez
    assert p1.sayac["getReferenceSourceIterator"] == 5
    assert p1.sayac["getReferencesFrom"] == 20
    assert p1.sayac["getReferencesTo"] == 5          # eski: 2 × 5 + başvurulu simge sayımı
    assert p0.sayac["getReferencesTo"] == 2 * 5 + 6
    assert p1.sayac["hasReferencesTo"] == 6 and p0.sayac["hasReferencesTo"] == 0


def test_cagri_hedefi_ve_dizgi_cozumlemesi_program_boyunca_bir_kez(ghidra_sahte) -> None:
    *_, p, _ = _yeni()
    # ayrı çağrı hedefi adresi: 2000, 2008, EXTERNAL:12, 1000, 7777, 3000 = 6 (9 çağrı başvurusu)
    assert p.sayac["getFunctionAt"] == 6
    # ayrı veri hedefi: 9000, 9010, 9020, 9030, 9040, 9050 = 6 (8 veri başvurusu)
    assert p.sayac["getDefinedDataAt"] == 6


def test_xref_tek_basina_da_tabloyu_kendisi_doldurur(ghidra_sahte) -> None:
    """Çağrı grafiği adımı koşmadıysa (düştüyse) xref kayıtları kendisi hesaplar."""
    _, xr0, _, _ = _eski()
    p = _senaryo()
    xr1 = GhidraHeadless._extract_xrefs(p, tablo=_BasvuruTablosu.kur(p), tek_gecis=True)
    assert _metin(xr1) == _metin(xr0)


# ---------------------------------------------------------------------------
# Sıra güvencesi
# ---------------------------------------------------------------------------

def test_kaynak_yineleyicisi_bozuk_siradaysa_eski_yuruyuse_duser(ghidra_sahte) -> None:
    cg0, xr0, _, _ = _eski()
    cg1, xr1, _, p, t = _yeni(kaynak_sira=lambda offlar: list(reversed(offlar)))
    assert _metin(cg1) == _metin(cg0) and _metin(xr1) == _metin(xr0)
    # birden çok kaynak adresi olan üç fonksiyon (ana, orta, parcali) eski yürüyüşe düştü
    assert t.eski_yuruyus == 3
    assert p.sayac["getReferencesFrom"] == 0x40 * 2 + 0x20 + 0  # yaprak / bos: kaynak yok


def test_kaynak_yineleyicisi_yinelenen_adres_verirse_eski_yuruyus(ghidra_sahte) -> None:
    cg0, xr0, _, _ = _eski()
    cg1, xr1, _, _, t = _yeni(kaynak_sira=lambda offlar: offlar + offlar[-1:])
    assert _metin(cg1) == _metin(cg0) and _metin(xr1) == _metin(xr0)
    assert t.eski_yuruyus == 3


def test_cagiran_sirasi_getreferencesto_sirasindan_bagimsiz(ghidra_sahte) -> None:
    """P16e korunur: ``getReferencesTo`` ters sırada dönse de çıktı aynı."""
    duz = _yeni()
    ters = _yeni(to_sira=lambda xs: list(reversed(xs)))
    assert _metin(ters[0]) == _metin(duz[0]) and _metin(ters[1]) == _metin(duz[1])
    assert _metin(ters[0]) == _metin(_eski(to_sira=lambda xs: list(reversed(xs)))[0])


# ---------------------------------------------------------------------------
# Bayatlama ve API yokluğu
# ---------------------------------------------------------------------------

def test_program_adimlar_arasinda_degisirse_tablo_bosaltilir(ghidra_sahte) -> None:
    p = _senaryo()
    t = _BasvuruTablosu.kur(p)
    GhidraHeadless._extract_call_graph(p, tablo=t)
    # iki adım arasında program değişti: orta yeniden adlandırıldı, yeni bir çağrı eklendi
    next(f for f in p.fm.fonklar if f.ad == "orta").ad = "orta_yeni"
    p.rm.refs.append(_Ref(0x3004, 0x1000))
    p.degisiklik += 1
    xr1 = GhidraHeadless._extract_xrefs(p, tablo=t, tek_gecis=True)
    xr0 = GhidraHeadless._extract_xrefs(p)
    assert t.bosaltma == 1
    assert _metin(xr1) == _metin(xr0)
    assert xr1["function_xrefs"]["00001000"]["functions_called"][0]["name"] == "orta_yeni"
    assert xr1["function_xrefs"]["00003000"]["functions_called"] == [
        {"name": "ana", "address": "00001000"}]


def test_tazele_her_iki_adimin_basinda(ghidra_sahte) -> None:
    """Tabloyu önce xref doldurduysa ve program değiştiyse çağrı grafiği de bayat kaydı kullanmaz."""
    p = _senaryo()
    t = _BasvuruTablosu.kur(p)
    GhidraHeadless._extract_xrefs(p, tablo=t, tek_gecis=True)
    p.rm.refs.append(_Ref(0x3004, 0x2000))
    p.degisiklik += 1
    cg1 = GhidraHeadless._extract_call_graph(p, tablo=t)
    assert t.bosaltma == 1
    assert _metin(cg1) == _metin(GhidraHeadless._extract_call_graph(p))
    assert cg1["nodes"]["00003000"]["callees"] == [{"name": "orta", "address": "00002000"}]


def test_program_degismediyse_tablo_bosaltilmaz(ghidra_sahte) -> None:
    *_, t = _yeni()
    assert t.bosaltma == 0 and t.eski_yuruyus == 0


def test_kur_gereken_api_yoksa_none(ghidra_sahte) -> None:
    assert _BasvuruTablosu.kur(_senaryo(eski_api=True)) is None
    assert _BasvuruTablosu.kur(types.SimpleNamespace(getName=lambda: "x")) is None
    yarim = types.SimpleNamespace(getReferenceManager=lambda: _senaryo().rm)
    assert _BasvuruTablosu.kur(yarim) is None      # getFunctionManager yok


# ---------------------------------------------------------------------------
# PK-8 için iç tablo (JSON'a yazılmaz)
# ---------------------------------------------------------------------------

def test_giris_adresine_cagri_olmayan_basvurular_ic_tabloda(ghidra_sahte) -> None:
    cg, xr, _, p, t = _yeni()
    yaprak = next(f for f in p.fm.fonklar if f.ad == "yaprak")
    k = t.kayit(yaprak, "00003000")
    assert [(str(r.getFromAddress()), r.tur) for r in k.giris_cagri_disi] == [
        ("00008000", "veri"), ("00002020", "atlama")]
    assert t.kayit(next(f for f in p.fm.fonklar if f.ad == "ana"), "00001000").giris_cagri_disi == []
    assert "giris_cagri_disi" not in _metin(cg) + _metin(xr)
    assert "address_taken_by" not in _metin(xr)


# ---------------------------------------------------------------------------
# Genel simge sayımı
# ---------------------------------------------------------------------------

def test_simge_sayimi_hasreferencesto_ile_ayni_sayi(ghidra_sahte) -> None:
    p0, p1 = _senaryo(), _senaryo()
    eski = GhidraHeadless._extract_xrefs(p0)
    yeni = GhidraHeadless._extract_xrefs(p1, tek_gecis=True)     # tablosuz: yalnız simge yolu
    assert _metin(yeni) == _metin(eski)
    assert yeni["statistics"]["total_globals_with_xrefs"] == 4
    # işlev / parametre / yerel simgeler için başvuru sorulmaz
    assert p1.sayac["hasReferencesTo"] == 6
    assert p1.sayac["getReferencesTo"] == 5                       # yalnız fonksiyon girişleri


# ---------------------------------------------------------------------------
# CFG: bu pakette değişmedi (program boyunca tek blok modeli); köprü ek argüman vermez
# ---------------------------------------------------------------------------

def test_cfg_dokumu_degismedi_tek_blok_modeli(ghidra_sahte) -> None:
    p = _senaryo()
    GhidraHeadless._extract_cfg(p)
    assert _BlokModeli.kurulan == 1 and _BlokModeli.en_buyuk_birikim == 7
    with pytest.raises(TypeError):
        GhidraHeadless._extract_cfg(_senaryo(), tek_gecis=True)


# ---------------------------------------------------------------------------
# ÖL-2 sözleşmesi: bütçe, kısmi çıktı, suruyor olayı
# ---------------------------------------------------------------------------

class _Saat:
    def __init__(self) -> None:
        self.t = 1000.0

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


def _kos(ad: str, p: _Program, d, yeni: bool):
    t = _BasvuruTablosu.kur(p) if yeni else None
    if ad == "call_graph":
        return GhidraHeadless._extract_call_graph(p, denetci=d, **({"tablo": t} if yeni else {}))
    if ad == "xref":
        return GhidraHeadless._extract_xrefs(
            p, denetci=d, **({"tablo": t, "tek_gecis": True} if yeni else {}))
    return GhidraHeadless._extract_cfg(p, denetci=d)


@pytest.mark.parametrize("ad", ["call_graph", "xref", "cfg"])
def test_butce_dolunca_kismi_cikti_iki_yolda_ayni(ad, saat, ghidra_sahte) -> None:
    # her fonksiyon 1 sn; bütçe 2,5 sn → 3 fonksiyon biter (0, 1, 2. sn'de denetim geçer)
    cikti = []
    for yeni in (False, True):
        saat.t = 1000.0
        d = _AdimDenetcisi("ghidra." + ad, 2.5, 0, saat.t, toplam=5)
        out = _kos(ad, _senaryo(saat=saat), d, yeni)
        json.loads(json.dumps(out))
        assert out["kismi"] is True and out["islenen"] == 3 and out["toplam"] == 5
        assert out["islenen"] <= out["toplam"]
        assert out["neden"].startswith("adım bütçesi (2.5 sn) doldu")
        cikti.append(_metin(out))
    assert cikti[0] == cikti[1]
    if ad == "xref":
        assert json.loads(cikti[1])["neden"].endswith("genel sembol sayımı yapılmadı")
        assert json.loads(cikti[1])["statistics"]["total_globals_with_xrefs"] == 0


@pytest.mark.parametrize("ad", ["call_graph", "xref", "cfg"])
def test_butce_dolmazsa_kismi_alan_yok_ve_cikti_denetcisizle_ayni(ad, saat, ghidra_sahte) -> None:
    taban = _kos(ad, _senaryo(), None, True)
    d = _AdimDenetcisi("ghidra." + ad, 0, 15, saat.t, toplam=5)
    out = _kos(ad, _senaryo(saat=saat), d, True)
    assert _metin(out) == _metin(taban)
    assert not any(k in out for k in ("kismi", "islenen", "toplam", "neden"))


def test_cagri_grafigi_kesilirse_xref_kalan_fonksiyonlari_kendisi_hesaplar(saat,
                                                                           ghidra_sahte) -> None:
    """Tablo yarım kalsa da xref adımı kendi bütçesiyle bütün fonksiyonları döker."""
    _, xr0, _, _ = _eski()
    p = _senaryo(saat=saat)
    t = _BasvuruTablosu.kur(p)
    d = _AdimDenetcisi("ghidra.call_graph", 1.5, 0, saat.t, toplam=5)
    cg = GhidraHeadless._extract_call_graph(p, denetci=d, tablo=t)
    assert cg["kismi"] is True and cg["islenen"] == 2 and len(cg["nodes"]) == 2
    xr = GhidraHeadless._extract_xrefs(p, tablo=t, tek_gecis=True)
    assert _metin(xr) == _metin(xr0)


def test_xref_butce_simge_sayiminda_dolarsa_neden_soyler(saat, ghidra_sahte) -> None:
    n = KUCUK_BIRIM_DENETIM_ADIMI * 3
    cikti = []
    for yeni in (False, True):
        saat.t = 1000.0
        p = _senaryo(saat=saat)
        p.simgeler = [_Simge(SIMGE_TURLERI.LABEL, 0x9000) for _ in range(n)]
        p.getSymbolTable = lambda p=p: types.SimpleNamespace(  # type: ignore[method-assign]
            getAllSymbols=lambda ileri: _Iter(p.simgeler, saat, 0.4))
        # 5 fonksiyon 5 sn; simge başına 0,4 sn; bütçe 5,5 sn → 1024. simgede kesilir
        d = _AdimDenetcisi("ghidra.xref", 5.5, 0, saat.t, toplam=5)
        out = _kos("xref", p, d, yeni)
        assert out["kismi"] is True and out["islenen"] == 5 and out["toplam"] == 5
        assert out["neden"] == ("adım bütçesi (5.5 sn) doldu; genel sembol sayımı yarıda "
                                "(%d sembol)" % KUCUK_BIRIM_DENETIM_ADIMI)
        assert out["statistics"]["total_globals_with_xrefs"] == KUCUK_BIRIM_DENETIM_ADIMI
        cikti.append(_metin(out))
    assert cikti[0] == cikti[1]


@pytest.mark.parametrize("ad", ["call_graph", "xref", "cfg"])
def test_suruyor_olayi_yeni_dongulerde_gercek_sayacla(ad, saat, ghidra_sahte, caplog) -> None:
    caplog.set_level(logging.INFO, logger="karadul.ilerleme")
    d = _AdimDenetcisi("ghidra." + ad, 0, 2, saat.t, toplam=5)
    _kos(ad, _senaryo(saat=saat), d, True)
    olaylar = [r.getMessage() for r in caplog.records
               if r.name == "karadul.ilerleme" and "durum=suruyor" in r.getMessage()]
    # denetim her fonksiyonun başında; 2. ve 4. sn'de olay (o ana kadar biten fonksiyon sayısı)
    assert len(olaylar) == 2
    assert "islenen=2" in olaylar[0] and "toplam=5" in olaylar[0]
    assert "islenen=4" in olaylar[1] and "adim=ghidra.%s" % ad in olaylar[1]


# ---------------------------------------------------------------------------
# Köprü (_analyze_pyghidra): bayrak ve argümanlar
# ---------------------------------------------------------------------------

@pytest.fixture
def kopru_hz4(monkeypatch, tmp_path, request):
    """Sahte köprü: üç döküm işlevi gerçek, öbür adımlar boş; dönüş (gh, program, görülen)."""
    from karadul.config import Config

    program = _senaryo(**getattr(request, "param", {}))
    gorulen: dict = {}

    class _Ctx:
        def __enter__(self):
            return types.SimpleNamespace(getCurrentProgram=lambda: program)

        def __exit__(self, *a):
            return False

    pg = types.ModuleType("pyghidra")
    pg.open_program = lambda **kw: _Ctx()
    monkeypatch.setitem(sys.modules, "pyghidra", pg)
    monkeypatch.setattr(headless_mod, "_ensure_pyghidra_started", lambda install, **kw: None)

    def sabit(deger):
        return staticmethod(lambda *a, **kw: json.loads(json.dumps(deger)))

    monkeypatch.setattr(GhidraHeadless, "_run_auto_analysis",
                        lambda self, p, t: {"status": "ok", "timeout_s": t, "duration_s": 0.0})
    monkeypatch.setattr(GhidraHeadless, "_extract_functions", sabit(
        {"total": 5, "program_function_count": 5, "thunk_count": 0, "external_count": 0,
         "functions": []}))
    monkeypatch.setattr(GhidraHeadless, "_extract_strings", sabit({"total": 0, "strings": []}))
    monkeypatch.setattr(GhidraHeadless, "_decompile_functions", sabit(
        {"success": 0, "failed": 0, "total_attempted": 0, "functions": []}))
    monkeypatch.setattr(GhidraHeadless, "_extract_types", sabit(
        {"total_structures": 0, "total_enums": 0, "total_typedefs": 0}))
    monkeypatch.setattr(GhidraHeadless, "_extract_pcode_stats_only", sabit(
        {"total_functions": 0, "mode": "stats_only"}))
    monkeypatch.setattr(GhidraHeadless, "_write_pcode_jsonl", sabit({"total_functions": 0}))
    monkeypatch.setattr(GhidraHeadless, "_extract_function_id_matches", sabit(
        {"total_matches": 0}))
    monkeypatch.setattr(GhidraHeadless, "_get_program_info", sabit({}))
    kaydedilen: dict = {}
    monkeypatch.setattr(GhidraHeadless, "_save_output", staticmethod(
        lambda d, ad, veri: kaydedilen.__setitem__(ad, _metin(veri))))
    for ad in ("_extract_call_graph", "_extract_xrefs", "_extract_cfg"):
        gercek = getattr(GhidraHeadless, ad)

        def sar(*a, _ad=ad, _g=gercek, **kw):
            gorulen[_ad] = dict(kw)
            return _g(*a, **kw)

        monkeypatch.setattr(GhidraHeadless, ad, staticmethod(sar))

    cfg = Config()
    cfg.bsim.enabled = False
    cfg.binary_reconstruction.enable_function_id = False
    cfg.binary_reconstruction.pdb_auto_load = False
    gh = GhidraHeadless(cfg)
    gh.analyze_headless = tmp_path / "ghidra" / "support" / "analyzeHeadless"
    return gh, program, gorulen, kaydedilen


def _kopru_kos(gh, tmp_path):
    return gh._analyze_pyghidra(tmp_path / "x", tmp_path / "p", "p", 60, tmp_path)


def test_kopru_bayrak_kapaliyken_ek_arguman_verilmez(kopru_hz4, tmp_path, ghidra_sahte) -> None:
    gh, program, gorulen, _ = kopru_hz4
    gh.config.analysis.dokum_tek_gecis = False
    sonuc = _kopru_kos(gh, tmp_path)
    assert sonuc["step_errors"] == {}
    for ad in ("_extract_call_graph", "_extract_xrefs", "_extract_cfg"):
        assert set(gorulen[ad]) == {"denetci"}
    assert program.sayac["getReferenceSourceIterator"] == 0


def test_kopru_bayrak_acikken_ortak_tablo_ve_ayni_cikti(kopru_hz4, tmp_path, ghidra_sahte) -> None:
    gh, program, gorulen, kaydedilen = kopru_hz4
    gh.config.analysis.dokum_tek_gecis = True
    sonuc = _kopru_kos(gh, tmp_path)
    assert sonuc["step_errors"] == {}
    tablo = gorulen["_extract_call_graph"]["tablo"]
    assert isinstance(tablo, _BasvuruTablosu)
    assert gorulen["_extract_xrefs"]["tablo"] is tablo        # iki adım AYNI tablo
    assert gorulen["_extract_xrefs"]["tek_gecis"] is True
    assert set(gorulen["_extract_cfg"]) == {"denetci"}        # CFG'ye ek argüman verilmez
    assert program.sayac["getReferenceSourceIterator"] == 5   # iki adımda tek geçiş
    cg0, xr0, cf0, _ = _eski()
    assert kaydedilen["call_graph.json"] == _metin(cg0)
    assert kaydedilen["xrefs.json"] == _metin(xr0)
    assert kaydedilen["cfg.json"] == _metin(cf0)


@pytest.mark.parametrize("kopru_hz4", [{"eski_api": True}], indirect=True)
def test_kopru_bayrak_acik_ama_api_yoksa_eski_donguler(kopru_hz4, tmp_path, ghidra_sahte,
                                                       caplog) -> None:
    gh, program, gorulen, kaydedilen = kopru_hz4
    gh.config.analysis.dokum_tek_gecis = True
    caplog.set_level(logging.WARNING, logger="karadul.ghidra.headless")
    sonuc = _kopru_kos(gh, tmp_path)
    assert sonuc["step_errors"] == {}
    for ad in ("_extract_call_graph", "_extract_xrefs", "_extract_cfg"):
        assert set(gorulen[ad]) == {"denetci"}
    assert any("Döküm tek geçişi kurulamadı" in r.getMessage() for r in caplog.records)
    assert kaydedilen["cfg.json"] == _metin(_eski()[2])

