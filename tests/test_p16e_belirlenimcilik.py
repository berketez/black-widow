"""P16e: Ghidra dökümünde çağıran listeleri kararlı sırada.

Bulgu (HZ1, 2026-11-20): aynı ürün, aynı ikili, iki koşu: çağıran listelerinin SIRASI farklı
(küme aynı). Kaynak ``ReferenceManager.getReferencesTo(giriş)`` yinelemesi; etkilenen alanlar
``call_graph.json`` ``nodes.<adr>.callers``, ``xrefs.json`` ``called_by``, ``decompiled.json``
``xrefs.callers`` ve ``.c`` başlığındaki ``// Callers:`` satırı (ilk 5 çağıran: 5'ten fazla
çağıranda analist koşudan koşuya farklı alt küme görüyordu).

Ghidra yok: program, fonksiyon yöneticisi ve başvuru yöneticisi sahte; ``getReferencesTo`` iki
koşuda bilerek farklı sırada döner. Çağrılan listeleri bu paketin dışında: gövde adres sırasıyla
kalır (test bunu da kilitler).
"""
from __future__ import annotations

import json
import sys
import types

import pytest

from karadul.ghidra.headless import GhidraHeadless, caller_sort_key


# ---------------------------------------------------------------------------
# Sahte Ghidra nesneleri
# ---------------------------------------------------------------------------


class _Adr:
    def __init__(self, s: str):
        self.s = s

    def __str__(self):
        return self.s

    def __eq__(self, other):
        return isinstance(other, _Adr) and other.s == self.s

    def __hash__(self):
        return hash(self.s)


class _Iter:
    def __init__(self, xs):
        self.xs, self.i = list(xs), 0

    def hasNext(self):
        return self.i < len(self.xs)

    def next(self):
        self.i += 1
        return self.xs[self.i - 1]


class _Tur:
    def __init__(self, cagri: bool):
        self.cagri = cagri

    def isCall(self):
        return self.cagri

    def isData(self):
        return not self.cagri


class _Ref:
    def __init__(self, kaynak: str, hedef: str, cagri: bool = True):
        self.kaynak, self.hedef, self.cagri = _Adr(kaynak), _Adr(hedef), cagri

    def getFromAddress(self):
        return self.kaynak

    def getToAddress(self):
        return self.hedef

    def getReferenceType(self):
        return _Tur(self.cagri)


class _Govde:
    def __init__(self, bas: int, boy: int):
        self.bas, self.boy = bas, boy

    def adresler(self):
        return ["%08x" % (self.bas + i) for i in range(self.boy)]

    def getAddresses(self, ileri):
        assert ileri is True
        return _Iter(_Adr(a) for a in self.adresler())

    def getNumAddresses(self):
        return self.boy


class _Fonk:
    def __init__(self, ad: str, bas: int, boy: int = 0x40):
        self.ad, self.bas, self.govde = ad, bas, _Govde(bas, boy)

    def getName(self):
        return self.ad

    def getEntryPoint(self):
        return _Adr("%08x" % self.bas)

    def getBody(self):
        return self.govde


class _FM:
    def __init__(self, fonklar):
        self.fonklar = sorted(fonklar, key=lambda f: f.bas)

    def getFunctions(self, ileri):
        return list(self.fonklar)

    def getFunctionContaining(self, adr):
        a = int(str(adr), 16)
        for f in self.fonklar:
            if f.bas <= a < f.bas + f.govde.boy:
                return f
        return None

    def getFunctionAt(self, adr):
        for f in self.fonklar:
            if "%08x" % f.bas == str(adr):
                return f
        return None


class _RM:
    """``getReferencesTo`` başvuruları ``sira`` işleviyle dizilmiş döndürür (Ghidra'nın kararsız
    yineleme sırasının yerine)."""

    def __init__(self, refs, sira):
        self.refs, self.sira = list(refs), sira

    def getReferencesTo(self, adr):
        return self.sira([r for r in self.refs if r.hedef == adr])

    def getReferencesFrom(self, adr):
        return [r for r in self.refs if r.kaynak == adr]


class _Listing:
    def getDefinedDataAt(self, adr):
        return None


class _SembolTablosu:
    def getAllSymbols(self, ileri):
        return _Iter([])


class _Program:
    def __init__(self, fonklar, refs, sira):
        self.fm, self.rm = _FM(fonklar), _RM(refs, sira)

    def getFunctionManager(self):
        return self.fm

    def getReferenceManager(self):
        return self.rm

    def getListing(self):
        return _Listing()

    def getSymbolTable(self):
        return _SembolTablosu()

    def getName(self):
        return "sahte"


# ---------------------------------------------------------------------------
# Senaryo: hedef H (00001000); 7 çağıran, adresleri ad sırasıyla uyuşmuyor. "ikiz" iki yerden
# çağırıyor (tekilleştirme); "veri" çağırmıyor, veri başvurusu; H kendini de çağırıyor (özyineleme).
# ---------------------------------------------------------------------------

H = _Fonk("hedef", 0x1000)
P16E_FONKLAR = [
    _Fonk("zeta", 0x5000), _Fonk("ikiz", 0x2000), _Fonk("delta", 0x4000), _Fonk("beta", 0x3000),
    _Fonk("eta", 0x7000), _Fonk("alfa", 0x6000), _Fonk("gama", 0x8000), _Fonk("veri", 0x9000),
]
REFS = [
    _Ref("00005010", "00001000"),
    _Ref("00002010", "00001000"),
    _Ref("00004010", "00001000"),
    _Ref("00002030", "00001000"),          # ikiz, ikinci çağrı yeri
    _Ref("00003010", "00001000"),
    _Ref("00007010", "00001000"),
    _Ref("00009010", "00001000", cagri=False),  # veri başvurusu
    _Ref("00006010", "00001000"),
    _Ref("00001020", "00001000"),          # özyineleme
    _Ref("00008010", "00001000"),
    # H'nin çağrıları: gövde sırası 0x1008 → gama, 0x1010 → beta (adres sırasının tersi)
    _Ref("00001008", "00008000"),
    _Ref("00001010", "00003000"),
]
BEKLENEN_ADRESLER = ["00002000", "00003000", "00004000", "00005000", "00006000", "00007000",
                     "00008000"]
BEKLENEN_ADLAR = ["ikiz", "beta", "delta", "zeta", "alfa", "eta", "gama"]


def _duz(xs):
    return list(xs)


def _ters(xs):
    return list(reversed(xs))


def _harman(xs):
    """İkiz'in iki başvurusunun göreli sırasını koruyan başka bir dizilim (Ghidra'da bir
    çağıranın başvuruları gövde akışı sırasıyla eklenir; koşudan koşuya değişen, çağıranlar
    arası sıradır — taban / A/A / HZ1'de call_site 8 ikilide 0 kez farklı)."""
    ikiz = [r for r in xs if r.kaynak.s.startswith("00002")]
    diger = [r for r in xs if not r.kaynak.s.startswith("00002")]
    diger = diger[3:] + diger[:3]
    return diger[:2] + ikiz[:1] + diger[2:5] + ikiz[1:] + diger[5:]


def _program(sira):
    return _Program([H, *P16E_FONKLAR], REFS, sira)


@pytest.fixture
def sahte_ghidra_modulu(monkeypatch):
    """``_extract_xrefs`` içindeki ``from ghidra.program.model.symbol import SymbolType``."""
    sembol = types.ModuleType("ghidra.program.model.symbol")
    sembol.SymbolType = types.SimpleNamespace(FUNCTION="F", PARAMETER="P", LOCAL_VAR="L")
    for ad in ("ghidra", "ghidra.program", "ghidra.program.model"):
        monkeypatch.setitem(sys.modules, ad, types.ModuleType(ad))
    monkeypatch.setitem(sys.modules, "ghidra.program.model.symbol", sembol)


# ---------------------------------------------------------------------------
# Anahtar
# ---------------------------------------------------------------------------


def test_anahtar_adres_tam_sayi_degeriyle():
    """Metin sırası ("10000" < "fff0") değil tam sayı sırası (0xfff0 < 0x10000)."""
    xs = [{"name": "b", "address": "00010000"}, {"name": "a", "address": "0000fff0"},
          {"name": "c", "address": "10000"}, {"name": "d", "address": "fff0"}]
    assert [x["address"] for x in sorted(xs, key=caller_sort_key)] == [
        "0000fff0", "fff0", "00010000", "10000"]


def test_anahtar_ayni_adresli_iki_ad_ada_gore():
    a = {"name": "beta", "address": "00002000"}
    b = {"name": "alfa", "address": "00002000"}
    assert sorted([a, b], key=caller_sort_key) == sorted([b, a], key=caller_sort_key) == [b, a]


def test_anahtar_adres_addan_once_gelir():
    xs = [{"name": "alfa", "address": "00003000"}, {"name": "zeta", "address": "00002000"}]
    assert [x["name"] for x in sorted(xs, key=caller_sort_key)] == ["zeta", "alfa"]


def test_anahtar_istisna_atmaz_ve_kararli():
    # Alanı olmayan ya da None olan kayıt aynı anahtarı alır (eşit kayıt sayılır).
    assert caller_sort_key({}) == caller_sort_key({"address": None, "name": None})
    xs = [{}, {"address": "EXTERNAL:00000010", "name": "x"}, {"address": "zzz", "name": "y"},
          {"address": "00001000", "name": "z", "call_site": "q"},
          {"address": "00001000", "name": "z", "call_site": "00001004"}]
    once = sorted(xs, key=caller_sort_key)
    assert sorted(list(reversed(xs)), key=caller_sort_key) == once
    assert once[0] == {}  # adres yok: boş alan adı, -1 (öntanımlı alan önce gelir)
    assert once[-1]["address"] == "EXTERNAL:00000010"


# ---------------------------------------------------------------------------
# Üç döküm işlevi: iki farklı yineleme sırası → aynı çıktı
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("sira", [_ters, _harman])
def test_cagri_grafigi_yineleme_sirasindan_bagimsiz(sira):
    a = GhidraHeadless._extract_call_graph(_program(_duz))
    b = GhidraHeadless._extract_call_graph(_program(sira))
    assert json.dumps(a, sort_keys=False) == json.dumps(b, sort_keys=False)
    dugum = a["nodes"]["00001000"]
    assert [c["address"] for c in dugum["callers"]] == BEKLENEN_ADRESLER
    assert dugum["caller_count"] == 7


@pytest.mark.parametrize("sira", [_ters, _harman])
def test_xrefs_yineleme_sirasindan_bagimsiz(sira, sahte_ghidra_modulu):
    a = GhidraHeadless._extract_xrefs(_program(_duz))
    b = GhidraHeadless._extract_xrefs(_program(sira))
    assert json.dumps(a) == json.dumps(b)
    assert [c["address"] for c in a["function_xrefs"]["00001000"]["called_by"]] == BEKLENEN_ADRESLER


def test_fonksiyon_xrefs_yineleme_sirasindan_bagimsiz():
    """Çağıranlar arası sıra değişir (ikiz'in iki başvurusunun göreli sırası korunur)."""
    a = GhidraHeadless._extract_func_xrefs(_program(_duz), H)
    b = GhidraHeadless._extract_func_xrefs(_program(_harman), H)
    assert json.dumps(a) == json.dumps(b)
    assert [c["address"] for c in a["callers"]] == BEKLENEN_ADRESLER
    assert [c["name"] for c in a["callers"]] == BEKLENEN_ADLAR


def test_uc_dokum_ayni_cagiran_sirasi(sahte_ghidra_modulu):
    p = _program(_ters)
    cg = [c["address"] for c in GhidraHeadless._extract_call_graph(p)["nodes"]["00001000"]["callers"]]
    fx = [c["address"] for c in GhidraHeadless._extract_func_xrefs(p, H)["callers"]]
    xr = [c["address"] for c in GhidraHeadless._extract_xrefs(p)["function_xrefs"]["00001000"]["called_by"]]
    assert cg == fx == xr == BEKLENEN_ADRESLER


def test_tekillestirme_korunur_kume_ayni():
    """Sıralama öğe eklemez / düşürmez: ikiz bir kez; veri başvurusu ve özyineleme dışarıda."""
    for sira in (_duz, _ters, _harman):
        fx = GhidraHeadless._extract_func_xrefs(_program(sira), H)
        adresler = [c["address"] for c in fx["callers"]]
        assert len(adresler) == len(set(adresler)) == fx["caller_count"] == 7
        assert set(adresler) == set(BEKLENEN_ADRESLER)
        cg = GhidraHeadless._extract_call_graph(_program(sira))["nodes"]["00001000"]
        assert [c["address"] for c in cg["callers"]] == adresler


def test_call_site_ilk_gorulen_basvuru():
    """Bu paket çağrı yerini değiştirmez: çağıranın ilk görülen başvurusu (ikiz → 00002010)."""
    fx = GhidraHeadless._extract_func_xrefs(_program(_duz), H)
    ikiz = [c for c in fx["callers"] if c["name"] == "ikiz"]
    assert ikiz == [{"name": "ikiz", "address": "00002000", "call_site": "00002010"}]


def test_cagrilan_listesi_govde_sirasinda_kalir(sahte_ghidra_modulu):
    """Çağrılanlar adres sırasına göre DEĞİL gövde sırasına göre (ilk çağrı yeri) kalır."""
    p = _program(_ters)
    fx = GhidraHeadless._extract_func_xrefs(p, H)
    assert [c["name"] for c in fx["callees"]] == ["gama", "beta"]
    cg = GhidraHeadless._extract_call_graph(p)
    assert [c["name"] for c in cg["nodes"]["00001000"]["callees"]] == ["gama", "beta"]
    assert [(e["from"], e["to"]) for e in cg["edges"] if e["from"] == "00001000"] == [
        ("00001000", "00008000"), ("00001000", "00003000")]
    xr = GhidraHeadless._extract_xrefs(p)
    assert [c["name"] for c in xr["function_xrefs"]["00001000"]["functions_called"]] == ["gama", "beta"]


def test_bos_ve_tek_ogeli_liste(sahte_ghidra_modulu):
    yalniz = _Fonk("yalniz", 0xA000)
    tek = _Fonk("tek", 0xB000)
    p = _Program([yalniz, tek, P16E_FONKLAR[0]], [_Ref("00005010", "0000b000")], _ters)
    assert GhidraHeadless._extract_func_xrefs(p, yalniz)["callers"] == []
    assert GhidraHeadless._extract_call_graph(p)["nodes"]["0000a000"]["callers"] == []
    assert GhidraHeadless._extract_xrefs(p)["function_xrefs"]["0000a000"]["called_by"] == []
    assert GhidraHeadless._extract_func_xrefs(p, tek)["callers"] == [
        {"name": "zeta", "address": "00005000", "call_site": "00005010"}]
    assert GhidraHeadless._extract_call_graph(p)["nodes"]["0000b000"]["callers"] == [
        {"name": "zeta", "address": "00005000"}]


# ---------------------------------------------------------------------------
# .c başlığı: "// Callers:" satırı
# ---------------------------------------------------------------------------


class _Decomp:
    def __init__(self, c_kodu: str = "void f(void) {}\n"):
        self.c_kodu = c_kodu

    def decompileFunction(self, func, timeout, monitor):
        c_kodu = self.c_kodu

        class _Df:
            def getC(self):
                return c_kodu

        class _Sonuc:
            def getDecompiledFunction(self):
                return _Df()

        return _Sonuc()


def _callers_satiri(tmp_path, program, func):
    sonuc = GhidraHeadless._decompile_single_function(_Decomp(), func, program, tmp_path, 30, None)
    assert sonuc["success"] is True
    satirlar = (tmp_path / sonuc["file"]).read_text(encoding="utf-8").splitlines()
    return [s for s in satirlar if s.startswith("// Callers:")], sonuc


@pytest.mark.parametrize("sira", [_duz, _ters, _harman])
def test_callers_satiri_en_kucuk_adresli_bes(tmp_path, sira):
    satir, sonuc = _callers_satiri(tmp_path, _program(sira), H)
    assert satir == ["// Callers:  7 (ikiz, beta, delta, zeta, alfa, ...)"]
    assert [c["address"] for c in sonuc["xrefs"]["callers"]] == BEKLENEN_ADRESLER


def test_callers_satiri_bes_ve_az_cagiranda_bicim_ayni(tmp_path):
    besli = REFS[:6]  # zeta, ikiz (2 yer), delta, beta, eta → 5 çağıran
    satir, _ = _callers_satiri(tmp_path, _Program([H, *P16E_FONKLAR], besli, _ters), H)
    assert satir == ["// Callers:  5 (ikiz, beta, delta, zeta, eta)"]


def test_callers_satiri_cagiransiz(tmp_path):
    satir, sonuc = _callers_satiri(tmp_path, _Program([H], [], _ters), H)
    assert satir == ["// Callers:  0"]
    assert sonuc["xrefs"]["callers"] == []


# ---------------------------------------------------------------------------
# scripts/arge/hiz/s8_esitlik.py --sira-normal (ön kayıt H3)
# ---------------------------------------------------------------------------


def _s8_modulu():
    import importlib.util
    from pathlib import Path

    yol = Path(__file__).resolve().parents[1] / "scripts" / "arge" / "hiz" / "s8_esitlik.py"
    spec = importlib.util.spec_from_file_location("s8_esitlik_p16e", yol)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _s8_kosu(kok, zaman, *, cagiranlar, cagrilanlar, c_govde):
    ikili = kok / "debian" / "coreutils" / "cat"
    st = ikili / "ws" / "workspaces" / "cat" / zaman / "static"
    (st / "ghidra_output" / "decompiled").mkdir(parents=True)
    cg = {"nodes": {"00001000": {"callers": [{"name": n, "address": a} for n, a in cagiranlar],
                                 "callees": [{"name": n, "address": a} for n, a in cagrilanlar]}}}
    (st / "ghidra_output" / "call_graph.json").write_text(json.dumps(cg), encoding="utf-8")
    (st / "ghidra_output" / "decompiled" / "f.c").write_text(c_govde, encoding="utf-8")
    (st / "ghidra_status.json").write_text(json.dumps({"success": True}), encoding="utf-8")
    (ikili / "out").mkdir()
    (ikili / "out" / "naming_map.json").write_text('{"a": 1}', encoding="utf-8")
    (ikili / "BITTI").write_text("0\n", encoding="utf-8")


C_A = "// Function: f\n// Callers:  2 (b, a)\n// Callees:  0\n\nvoid f(void) {}\n"
C_B = "// Function: f\n// Callers:  2 (a, b)\n// Callees:  0\n\nvoid f(void) {}\n"


def test_s8_sira_normal_cagiran_sirasini_ve_callers_satirini_yok_sayar_ham_saymaz(tmp_path):
    m = _s8_modulu()
    _s8_kosu(tmp_path / "once", "1", cagiranlar=[("b", "00003000"), ("a", "00002000")],
             cagrilanlar=[("x", "00005000")], c_govde=C_A)
    _s8_kosu(tmp_path / "sonra", "2", cagiranlar=[("a", "00002000"), ("b", "00003000")],
             cagrilanlar=[("x", "00005000")], c_govde=C_B)
    ham = m.kos(tmp_path / "once", tmp_path / "sonra", None)["ikililer"]["debian/coreutils/cat"]
    assert ham["sonra"]["ozet"]["json_farkli_dosya"] == 1 and ham["sonra"]["ozet"]["c_farkli"] == 1
    assert "c_callers_satiri_farkli" not in ham["sonra"]["ozet"]  # ham kıyas eskisi gibi
    sn = m.kos(tmp_path / "once", tmp_path / "sonra", None, True)
    s = sn["ikililer"]["debian/coreutils/cat"]
    assert s["cikti_esit"] is True
    assert s["sonra"]["ozet"]["c_callers_satiri_farkli"] == 1
    assert sn["sira_normal"]["listeler"] == ["callers", "called_by"]
    assert "sıra-normal" in m.markdown(sn)


def test_s8_sira_normal_baska_listeyi_ve_baska_satiri_saymaya_devam_eder(tmp_path):
    m = _s8_modulu()
    _s8_kosu(tmp_path / "once", "1", cagiranlar=[("a", "00002000")],
             cagrilanlar=[("x", "00005000"), ("y", "00004000")], c_govde=C_A)
    _s8_kosu(tmp_path / "sonra", "2", cagiranlar=[("a", "00002000")],
             cagrilanlar=[("y", "00004000"), ("x", "00005000")],
             c_govde=C_B.replace("void f(void) {}", "int f(void) {}"))
    s = m.kos(tmp_path / "once", tmp_path / "sonra", None, True)["ikililer"]["debian/coreutils/cat"]
    assert s["cikti_esit"] is False
    assert "json:ghidra_output/call_graph.json:nodes.00001000.callees[].name" in s["sonraya_yuklenebilir"]
    assert "c:f.c" in s["sonraya_yuklenebilir"]


def test_s8_sira_normal_kume_farkini_gizlemez(tmp_path):
    m = _s8_modulu()
    _s8_kosu(tmp_path / "once", "1", cagiranlar=[("a", "00002000"), ("b", "00003000")],
             cagrilanlar=[], c_govde=C_A)
    _s8_kosu(tmp_path / "sonra", "2", cagiranlar=[("a", "00002000")], cagrilanlar=[], c_govde=C_A)
    s = m.kos(tmp_path / "once", tmp_path / "sonra", None, True)["ikililer"]["debian/coreutils/cat"]
    assert s["cikti_esit"] is False
    assert any("callers[]" in b for b in s["sonraya_yuklenebilir"])
