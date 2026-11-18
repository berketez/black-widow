"""P16a / GHIDRA-16: PyGhidra dizgi kaydında fonksiyon bağı başvurulardan kurulur.

Eski davranış (ölçüldü, ``P16a.md``): 119 koşunun ``ghidra_strings.json``'unda ``function`` dolu
0 / 80 545; ``xrefs`` alanı hiç yoktu. Kök: ``getFunctionContaining(dizgi adresi)``; dizgi
``.rodata``'da, hiçbir fonksiyon gövdesinde değil.
"""
from __future__ import annotations

from karadul.ghidra.headless import GhidraHeadless, _address_sort_key


class _Adr:
    def __init__(self, a):
        self.a = a

    def __str__(self):
        return self.a


class _Tip:
    def __init__(self, ad):
        self.ad = ad

    def getName(self):
        return self.ad


class _Veri:
    def __init__(self, adres, deger, tip="string"):
        self.adres, self.deger, self.tip = _Adr(adres), deger, tip

    def getDataType(self):
        return _Tip(self.tip)

    def getAddress(self):
        return self.adres

    def getDefaultValueRepresentation(self):
        return '"%s"' % self.deger

    def getLength(self):
        return len(self.deger) + 1


class _Iter:
    def __init__(self, xs):
        self.xs, self.i = list(xs), 0

    def hasNext(self):
        return self.i < len(self.xs)

    def next(self):
        self.i += 1
        return self.xs[self.i - 1]


class _Fonk:
    def __init__(self, ad, giris):
        self.ad, self.giris = ad, giris

    def getName(self):
        return self.ad

    def getEntryPoint(self):
        return _Adr(self.giris)


class _Ref:
    def __init__(self, kaynak):
        self.kaynak = _Adr(kaynak)

    def getFromAddress(self):
        return self.kaynak


# .text: main 00101000-001010ff, yardimci 00102000-001020ff; dizgiler .rodata'da (00200000+)
METIN_BOLUMU = [(0x101000, 0x101100, _Fonk("main", "00101000")),
           (0x102000, 0x102100, _Fonk("yardimci", "00102000"))]
REFS = {
    "00200000": ["00102010", "00101020"],  # iki fonksiyondan; sıra bilerek ters
    "00200010": ["00300000"],              # fonksiyon dışından (veri tablosu)
    "00200020": [],                        # başvurusuz
}


class _FM:
    def getFunctionContaining(self, adr):
        a = int(str(adr), 16)
        for bas, son, f in METIN_BOLUMU:
            if bas <= a < son:
                return f
        return None


class _RM:
    def getReferencesTo(self, adr):
        return [_Ref(x) for x in REFS.get(str(adr), [])]


class _Listing:
    def getDefinedData(self, ileri):
        return _Iter([_Veri("00200000", "usage: %s"), _Veri("00200010", "tablo"),
                      _Veri("00200020", "yalniz"), _Veri("00200030", "x", tip="int")])


class _Program:
    def getListing(self):
        return _Listing()

    def getFunctionManager(self):
        return _FM()

    def getReferenceManager(self):
        return _RM()

    def getName(self):
        return "deneme"


def test_dizgi_fonksiyon_bagi_baslananlardan():
    d = GhidraHeadless._extract_strings(_Program())
    assert d["total"] == 3
    s0, s1, s2 = d["strings"]
    assert s0["value"] == "usage: %s"
    assert [x["from_address"] for x in s0["xrefs"]] == ["00101020", "00102010"]  # adres sırası
    assert s0["xref_count"] == 2
    assert s0["function"] == "main" and s0["function_addr"] == "00101000"
    assert s0["xrefs"][1] == {"from_address": "00102010", "from_function": "yardimci",
                              "from_func_addr": "00102000"}
    # fonksiyon dışından başvuru: xref var, fonksiyon yok
    assert s1["xref_count"] == 1 and s1["function"] is None and s1["function_addr"] is None
    # başvurusuz dizgi: alanlar boş ve sayısı 0 (neden boş olduğu kayıttan okunur)
    assert s2["xrefs"] == [] and s2["xref_count"] == 0 and s2["function"] is None


def test_adres_siralama_anahtari():
    assert sorted(["ram:0010", "ram:0002", "0001"], key=_address_sort_key) == ["0001", "ram:0002", "ram:0010"]
    assert _address_sort_key("EXTERNAL:zz")[1] == -1
