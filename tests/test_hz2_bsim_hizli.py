"""HZ-2: BSim hızlı yol (paralel tarama; çıktıyı değiştirmez).

Ghidra / JVM gerekmez: sahte ``GenSignatures`` hem tekli (``scanFunction``) hem paralel
(``scanFunctions(yineleyici, n, izleyici)``) taramayı taklit eder; izleyici sahte (sayaç +
saatle bütçe + iptal). Sözleşme (gönderim hükümleri 1–7):
- paralel yol tekli yolla aynı fonksiyon kümesini aynı sırada tarar, aynı kümeyi ekler, aynı
  eşleşmeleri verir; durum alanlarında fark yalnız ``scan_mode``;
- sorgu, aynı oturumda tam ingest edildiyse ingest'in yöneticisini kullanır (yeni tarama yok);
- bütçe izleyicide: dolunca kısmi, ``islenen`` yöneticide imzası olan fonksiyon sayısı;
  ``QueryNearest`` öncesi denetim korunur;
- adım içi ``suruyor`` olayı yalnız gerçek okunan sayaçla; okunamıyorsa olay yok;
- paralel tarama istisna atarsa tekli yol, ``scan_mode: serial_fallback`` ve neden;
- kısmi ingest köken kaydında işaretli, sonraki koşuda durumda görünür.
"""

from __future__ import annotations

import sys
import time as _gercek_time
import types
from typing import Any

import pytest

import karadul.ghidra.bsim as bsim_mod
import karadul.ghidra.headless as headless_mod
from karadul.config import Config
from karadul.ghidra.bsim import (
    SCAN_PARALLEL,
    SCAN_SERIAL_FALLBACK,
    BSimDatabase,
    ExeIdentity,
    _BSimNativeWrapper,
    _java_iterator,
    _kalan_butce_sn,
    _ProvenanceStore,
    _TaramaIzleyicisi,
)
from karadul.ghidra.headless import _AdimDenetcisi
from tests.test_p16c_bsim_toplu import (
    BUILD_OWN,
    CANDIDATES,
    FUNCS,
    MD5_OWN,
    SHA_OWN,
    _exclusion,
    _Fdesc,
    _FakeNative,
    _Func,
    _Note,
    _Prog,
    _SimResult,
)

DBN = "karadul_bsim"
ZAMAN_ALANLARI = ("ingest_s", "query_s", "lock_wait_s")


class _Saat:
    def __init__(self) -> None:
        self.t = 50.0

    def monotonic(self) -> float:
        return self.t

    def ilerle(self, sn: float) -> None:
        self.t += sn

    @staticmethod
    def time() -> float:
        return 0.0

    @staticmethod
    def sleep(_sn: float) -> None:
        return None


@pytest.fixture
def saat(monkeypatch):
    s = _Saat()
    monkeypatch.setattr(headless_mod, "time", s)
    monkeypatch.setattr(bsim_mod, "time", s)
    return s


class _Thunk(_Func):
    def isThunk(self) -> bool:  # noqa: N802
        return True


class _Dis(_Func):
    def isExternal(self) -> bool:  # noqa: N802
        return True


# Programın bütün fonksiyonları: thunk ve dış fonksiyon _iter_real_functions'ta elenir.
TUM = [FUNCS[0], _Thunk("thunk_a", 0x1800), FUNCS[1], FUNCS[2], _Dis("ext_b", 0x7000),
       FUNCS[3], FUNCS[4]]


class _Fm:
    def __init__(self, funcs) -> None:
        self._f = list(funcs)

    def getFunctions(self, _ileri):  # noqa: N802
        it = iter(self._f)
        nxt: list[Any] = [None]

        class J:
            def hasNext(self_):  # noqa: N802, N805
                try:
                    nxt[0] = next(it)
                    return True
                except StopIteration:
                    return False

            def next(self_):  # noqa: N805
                return nxt[0]
        return J()


class _Program(_Prog):
    def getFunctionManager(self):  # noqa: N802
        return _Fm(TUM)


class _Mon:
    """Sahte izleyici: ConcurrentQ gibi biten iş sayısını ``setProgress``'le tutar; bütçe saatle."""

    def __init__(self, saat: _Saat | None, son_an: float | None, sayac: bool = True) -> None:
        self.saat, self.son_an, self.sayac = saat, son_an, sayac
        self.progress = 0
        self.cancelled = False
        self.cancel_cagri = 0
        if son_an is not None:
            self.didTimeout = lambda: self.saat.t > self.son_an  # noqa: N815 (TimeoutTaskMonitor)

    def isCancelled(self) -> bool:  # noqa: N802
        if self.son_an is not None and self.saat is not None and self.saat.t > self.son_an:
            self.cancelled = True
        return self.cancelled

    def cancel(self) -> None:
        self.cancel_cagri += 1
        self.cancelled = True

    def getProgress(self) -> int:  # noqa: N802
        if self.sayac is None:
            raise RuntimeError("sayaç yok")
        return self.progress if self.sayac else -1


class _Dunya:
    """Sahte Ghidra BSim (tekli + paralel tarama, ekleme, toplu sorgu)."""

    def __init__(self, saat: _Saat | None = None, adim_sn: float = 0.0,
                 scan_error: Exception | None = None, imzasiz: set[int] | None = None) -> None:
        self.saat, self.adim_sn, self.scan_error = saat, adim_sn, scan_error
        self.imzasiz = imzasiz or set()
        self.gens: list[Any] = []
        self.taranan: list[tuple[str, str]] = []
        self.paralel_cagri: list[int] = []
        self.eklenen: list[list[str]] = []
        self.sorgular: list[Any] = []
        self.monitorler: list[_Mon] = []

    def kur(self, monkeypatch) -> None:
        d = self

        class Fd:
            def __init__(self, f, imza: bool) -> None:
                self.f, self.imza = f, imza

            def getSignatureRecord(self):  # noqa: N802
                return object() if self.imza else None

            def sortCallgraph(self):  # noqa: N802
                pass

        class Manager:
            def __init__(self) -> None:
                self.funcs: list = []
                self.fds: list = []
                self.ayar = True    # sürüm / ayar bilgisi (clear() sıfırlar)

            def listAllFunctions(self):  # noqa: N802
                return list(self.fds)

        class Gen:
            def __init__(self, _b) -> None:
                self.m = Manager()
                self.disposed = False
                d.gens.append(self)

            def setVectorFactory(self, _f):  # noqa: N802
                pass

            def openProgram(self, *a):  # noqa: N802
                pass

            def _yaz(self, f) -> None:
                self.m.funcs.append(f)
                self.m.fds.append(Fd(f, f.getEntryPoint().getOffset() not in d.imzasiz))

            def scanFunction(self, f):  # noqa: N802
                if d.saat is not None:
                    d.saat.ilerle(d.adim_sn)
                d.taranan.append(("tekli", f.getName()))
                self._yaz(f)

            def scanFunctions(self, it, n, mon):  # noqa: N802
                d.paralel_cagri.append(n)
                if d.scan_error is not None:
                    raise d.scan_error
                for f in it:
                    if mon.isCancelled():
                        break
                    if d.saat is not None:
                        d.saat.ilerle(d.adim_sn)
                    if mon.isCancelled():       # iptal edilen iş yöneticiye yazılmaz
                        break
                    d.taranan.append(("paralel", f.getName()))
                    self._yaz(f)
                    mon.progress += 1

            def getDescriptionManager(self):  # noqa: N802
                return self.m

            def dispose(self):
                # Gerçek GenSignatures.dispose → clear() → manager.clear(): fonksiyonlar ve
                # sürüm / ayarlar sıfırlanır (2026-11-24 S8'de yakalandı).
                self.disposed = True
                self.m.funcs, self.m.fds, self.m.ayar = [], [], False

        class InsertRequest:
            def __init__(self) -> None:
                self.manage = None

            def execute(self, db):
                d.eklenen.append([f.getName() for f in self.manage.funcs])
                return object()

        class QueryNearest:
            def __init__(self) -> None:
                self.max = None
                self.manage = None
                d.sorgular.append(self)

            def execute(self, db):
                if not self.manage.ayar:
                    return None     # "Query signature data has no setting information"
                results = []
                for f in self.manage.funcs:
                    off = f.getEntryPoint().getOffset()
                    base = _Fdesc(MD5_OWN, "prog", f.getName(), off)
                    notes = [_Note(_Fdesc(m, p, nm, 0x9000 + i), s, 10.0 + i)
                             for i, (m, p, nm, s) in enumerate(CANDIDATES.get(off, []))]
                    results.append(_SimResult(base, notes[: self.max]))
                results.reverse()
                return types.SimpleNamespace(result=results)

        for ad in ("ghidra", "ghidra.features", "ghidra.features.bsim",
                   "ghidra.features.bsim.query", "ghidra.features.bsim.query.protocol"):
            monkeypatch.setitem(sys.modules, ad, types.ModuleType(ad))
        sys.modules["ghidra.features.bsim.query"].GenSignatures = Gen
        sys.modules["ghidra.features.bsim.query.protocol"].InsertRequest = InsertRequest
        sys.modules["ghidra.features.bsim.query.protocol"].QueryNearest = QueryNearest

    def izleyici(self, sayac: bool | None = True, neden: str = ""):
        """``_izleyici_olustur`` yerine: kalan bütçeyle sahte izleyici."""
        def kur(kalan):
            mon = _Mon(self.saat, None if kalan is None else self.saat.t + kalan, sayac)
            self.monitorler.append(mon)
            return mon, neden
        return kur


CLIENT = types.SimpleNamespace(getLSHVectorFactory=lambda: object(), getLastError=lambda: None,
                               close=lambda: None)


def _wrapper(tmp_path, dunya: _Dunya, paralel: bool, **izl) -> _BSimNativeWrapper:
    w = _BSimNativeWrapper(tmp_path)
    w.paralel_tarama = paralel
    w._izleyici_olustur = dunya.izleyici(**izl)  # type: ignore[method-assign]
    return w


# ---------------------------------------------------------------------------
# Ingest: küme, sıra, sayaç
# ---------------------------------------------------------------------------

def test_paralel_ingest_tekli_yolla_ayni_kume_sira_ve_ekleme(tmp_path, monkeypatch, saat) -> None:
    tekli = _Dunya(saat)
    tekli.kur(monkeypatch)
    n1 = _wrapper(tmp_path, tekli, False).ingest_program(_Program(), DBN, database=CLIENT)
    paralel = _Dunya(saat)
    paralel.kur(monkeypatch)
    w = _wrapper(tmp_path, paralel, True)
    n2 = w.ingest_program(_Program(), DBN, database=CLIENT)
    assert n1 == n2 == len(FUNCS)
    assert [a for _, a in tekli.taranan] == [a for _, a in paralel.taranan] == [
        f.getName() for f in FUNCS]                     # thunk / dış fonksiyon yok, aynı sıra
    assert tekli.eklenen == paralel.eklenen
    assert paralel.paralel_cagri == [len(FUNCS)]        # tek scanFunctions, n = toplam
    assert {k for k, _ in paralel.taranan} == {"paralel"}
    assert w.last_scan_mode == SCAN_PARALLEL and w.last_ingest_kismi is None


def test_bayrak_kapaliyken_tekli_yol_scan_mode_yok(tmp_path, monkeypatch, saat) -> None:
    d = _Dunya(saat)
    d.kur(monkeypatch)
    w = _wrapper(tmp_path, d, False)
    w.ingest_program(_Program(), DBN, database=CLIENT)
    assert d.paralel_cagri == [] and d.monitorler == []
    assert w.last_scan_mode is None and w._ingest_yoneticisi is None


def test_ingest_butcesi_izleyicide_kismi_ve_taranan_kisim_eklenir(tmp_path, monkeypatch,
                                                                   saat) -> None:
    d = _Dunya(saat, adim_sn=1.0)
    d.kur(monkeypatch)
    w = _wrapper(tmp_path, d, True)
    w.denetci = _AdimDenetcisi("ghidra.bsim.ingest", 2.5, 0, saat.t)
    n = w.ingest_program(_Program(), DBN, database=CLIENT)
    # 51 ve 52 sn'de iki iş biter; üçüncü 53 sn'de bütçeyi (52,5) aşar ve yazılmaz
    assert n == 2 and d.eklenen == [["FUN_1000", "FUN_2000"]]
    assert w.last_ingest_kismi == {"islenen": 2, "toplam": len(FUNCS)}
    assert w.denetci.doldu and w.denetci.sayac() == {"islenen": 2, "toplam": len(FUNCS)}
    assert "adım bütçesi (2.5 sn) doldu" in w.denetci.neden()
    assert d.monitorler[0].son_an == pytest.approx(52.5)   # kalan süre izleyiciye verildi
    assert w._ingest_yoneticisi is None                     # kısmi yönetici sorguya verilmez


def test_ingest_islenen_imzasi_olan_fonksiyon_sayisi(tmp_path, monkeypatch, saat) -> None:
    d = _Dunya(saat, adim_sn=1.0, imzasiz={0x2000})
    d.kur(monkeypatch)
    w = _wrapper(tmp_path, d, True)
    w.denetci = _AdimDenetcisi("ghidra.bsim.ingest", 3.5, 0, saat.t)
    w.ingest_program(_Program(), DBN, database=CLIENT)
    # 3 iş bitti, biri imzasız: depoya giren imzalı iş 2
    assert len(d.taranan) == 3 and w.last_ingest_kismi == {"islenen": 2, "toplam": 5}


def test_ingest_butcesi_taramadan_once_dolmussa_tarama_yok(tmp_path, monkeypatch, saat) -> None:
    d = _Dunya(saat)
    d.kur(monkeypatch)
    w = _wrapper(tmp_path, d, True)
    w.denetci = _AdimDenetcisi("ghidra.bsim.ingest", 1.0, 0, saat.t)
    saat.ilerle(2.0)
    assert w.ingest_program(_Program(), DBN, database=CLIENT) == 0
    assert d.paralel_cagri == [] and d.eklenen == []
    assert w.last_ingest_kismi == {"islenen": 0, "toplam": len(FUNCS)}
    assert w.denetci.sayac() == {"islenen": 0, "toplam": len(FUNCS)}


def test_butcesiz_izleyici_zaman_asimsiz(tmp_path, monkeypatch, saat) -> None:
    d = _Dunya(saat, adim_sn=100.0)
    d.kur(monkeypatch)
    w = _wrapper(tmp_path, d, True)
    w.denetci = _AdimDenetcisi("ghidra.bsim.ingest", 0, 0, saat.t)
    assert w.ingest_program(_Program(), DBN, database=CLIENT) == len(FUNCS)
    assert d.monitorler[0].son_an is None and w.last_ingest_kismi is None


# ---------------------------------------------------------------------------
# Yedek yol (H6)
# ---------------------------------------------------------------------------

def test_paralel_tarama_dusunce_tekli_yol_ayni_ekleme(tmp_path, monkeypatch, saat) -> None:
    tekli = _Dunya(saat)
    tekli.kur(monkeypatch)
    _wrapper(tmp_path, tekli, False).ingest_program(_Program(), DBN, database=CLIENT)
    d = _Dunya(saat, scan_error=RuntimeError("DecompileException: execution"))
    d.kur(monkeypatch)
    w = _wrapper(tmp_path, d, True)
    n = w.ingest_program(_Program(), DBN, database=CLIENT)
    assert n == len(FUNCS) and d.eklenen == tekli.eklenen
    assert {k for k, _ in d.taranan} == {"tekli"}
    assert w.last_scan_mode == SCAN_SERIAL_FALLBACK
    assert "RuntimeError" in w.last_scan_hatasi and "execution" in w.last_scan_hatasi
    assert len(d.gens) == 2 and d.gens[0].disposed       # düşen gen bırakıldı, yenisi kuruldu


# ---------------------------------------------------------------------------
# Sorgu
# ---------------------------------------------------------------------------

def _anahtar(m) -> tuple:
    return tuple(sorted(m.to_dict().items()))


def test_sorgu_ingest_yoneticisini_kullanir_yeni_tarama_yok(tmp_path, monkeypatch, saat) -> None:
    d = _Dunya(saat)
    d.kur(monkeypatch)
    w = _wrapper(tmp_path, d, True)
    prog = _Program()
    w.ingest_program(prog, DBN, database=CLIENT)
    ingest_yoneticisi = d.gens[0].m
    ex = _exclusion()
    out, failed = w.query_functions(CLIENT, prog, list(FUNCS), 0.7, 5, 0.0, ex,
                                    ex.extra_slots())
    assert len(d.gens) == 1 and len(d.taranan) == len(FUNCS)    # sorgu yeniden taramadı
    assert d.sorgular[0].manage is ingest_yoneticisi and failed == 0
    # tekli yolla (yeni GenSignatures + scanFunction) aynı eşleşmeler ve dışlama sayaçları
    t = _Dunya(saat)
    t.kur(monkeypatch)
    ex2 = _exclusion()
    out2, _ = _wrapper(tmp_path, t, False).query_functions(
        CLIENT, prog, list(FUNCS), 0.7, 5, 0.0, ex2, ex2.extra_slots())
    assert [m.to_dict() for m in out] == [m.to_dict() for m in out2] and len(out) > 0
    assert ex.counts == ex2.counts and ex.unrecorded_candidates == ex2.unrecorded_candidates
    assert w._ingest_yoneticisi is None and d.gens[0].disposed   # bir kez kullanıldı, bırakıldı


def test_tam_ingest_taramasi_sorguya_kadar_birakilmaz(tmp_path, monkeypatch, saat) -> None:
    """GenSignatures.dispose yöneticiyi temizler: ingest onu sorgudan önce bırakmamalı."""
    d = _Dunya(saat)
    d.kur(monkeypatch)
    w = _wrapper(tmp_path, d, True)
    w.ingest_program(_Program(), DBN, database=CLIENT)
    assert not d.gens[0].disposed and len(d.gens[0].m.fds) == len(FUNCS)
    w.close()                                   # kullanılmadan oturum kapanırsa bırakılır
    assert d.gens[0].disposed and w._ingest_yoneticisi is None


def test_kullanilmayan_ingest_taramasi_yeni_ingestte_birakilir(tmp_path, monkeypatch,
                                                               saat) -> None:
    d = _Dunya(saat)
    d.kur(monkeypatch)
    w = _wrapper(tmp_path, d, True)
    w.ingest_program(_Program(), DBN, database=CLIENT)
    w.ingest_program(_Program(), DBN, database=CLIENT)
    assert d.gens[0].disposed and not d.gens[1].disposed


def test_sorgu_baska_program_ya_da_kisim_icin_yoneticiyi_kullanmaz(tmp_path, monkeypatch,
                                                                    saat) -> None:
    d = _Dunya(saat)
    d.kur(monkeypatch)
    w = _wrapper(tmp_path, d, True)
    w.ingest_program(_Program(), DBN, database=CLIENT)
    assert w.hazir_yonetici(_Program(), list(FUNCS)) is None      # başka program nesnesi
    assert d.gens[0].disposed                                     # eşleşmeyen kayıt bırakıldı
    prog = _Program()
    w.ingest_program(prog, DBN, database=CLIENT)
    assert w.hazir_yonetici(prog, list(FUNCS[:3])) is None        # farklı fonksiyon sayısı
    prog2 = _Program()
    w.ingest_program(prog2, DBN, database=CLIENT)
    assert w.hazir_yonetici(prog2, list(FUNCS)) is d.gens[-1]     # sahiplik çağırana geçer
    assert w._ingest_yoneticisi is None and not d.gens[-1].disposed


def test_sorgu_zaten_ingestte_paralel_tarar_ayni_eslesme(tmp_path, monkeypatch, saat) -> None:
    d = _Dunya(saat)
    d.kur(monkeypatch)
    w = _wrapper(tmp_path, d, True)
    ex = _exclusion()
    out, failed = w.query_functions(CLIENT, object(), list(FUNCS), 0.7, 5, 0.0, ex,
                                    ex.extra_slots())
    assert d.paralel_cagri == [len(FUNCS)] and failed == 0 and w.last_scan_mode == SCAN_PARALLEL
    t = _Dunya(saat)
    t.kur(monkeypatch)
    ex2 = _exclusion()
    out2, _ = _wrapper(tmp_path, t, False).query_functions(
        CLIENT, object(), list(FUNCS), 0.7, 5, 0.0, ex2, ex2.extra_slots())
    assert [_anahtar(m) for m in out] == [_anahtar(m) for m in out2]


def test_sorgu_paralel_taramada_butce_dolarsa_cagri_yok(tmp_path, monkeypatch, saat) -> None:
    d = _Dunya(saat, adim_sn=1.0)
    d.kur(monkeypatch)
    w = _wrapper(tmp_path, d, True)
    w.denetci = _AdimDenetcisi("ghidra.bsim.query", 2.5, 0, saat.t)
    ex = _exclusion()
    out, _ = w.query_functions(CLIENT, object(), list(FUNCS), 0.7, 5, 0.0, ex, ex.extra_slots())
    assert out == [] and d.sorgular == []
    assert "toplu sorgu çağrılmadı (2 / 5 fonksiyon tarandı)" in w.denetci.neden()
    assert w.last_query_kismi == {"islenen": 0, "toplam": 5}


def test_sorgu_yoneticiyle_de_cagri_oncesi_butce_denetlenir(tmp_path, monkeypatch, saat) -> None:
    d = _Dunya(saat)
    d.kur(monkeypatch)
    w = _wrapper(tmp_path, d, True)
    prog = _Program()
    w.ingest_program(prog, DBN, database=CLIENT)
    w.denetci = _AdimDenetcisi("ghidra.bsim.query", 1.0, 0, saat.t)
    saat.ilerle(2.0)
    ex = _exclusion()
    out, _ = w.query_functions(CLIENT, prog, list(FUNCS), 0.7, 5, 0.0, ex, ex.extra_slots())
    assert out == [] and d.sorgular == []
    assert "(5 / 5 fonksiyon tarandı)" in w.denetci.neden()


def test_sorgu_paralel_duserse_tekli_tarama(tmp_path, monkeypatch, saat) -> None:
    d = _Dunya(saat, scan_error=RuntimeError("havuz"))
    d.kur(monkeypatch)
    w = _wrapper(tmp_path, d, True)
    ex = _exclusion()
    out, _ = w.query_functions(CLIENT, object(), list(FUNCS), 0.7, 5, 0.0, ex, ex.extra_slots())
    assert {k for k, _ in d.taranan} == {"tekli"} and len(out) > 0
    assert w.last_scan_mode == SCAN_SERIAL_FALLBACK and len(d.sorgular) == 1


# ---------------------------------------------------------------------------
# Veritabanı düzeyi: çıktı eşitliği, scan_mode, yedek yol durumu
# ---------------------------------------------------------------------------

def _veritabani(tmp_path, monkeypatch, dunya: _Dunya, paralel: bool | None) -> BSimDatabase:
    monkeypatch.setattr(bsim_mod, "_BSIM_AVAILABLE", True)
    cfg = Config()
    cfg.bsim.db_path = str(tmp_path / "bsim")
    cfg.bsim.lock_timeout_s = 0.3
    cfg.bsim.bos_depoda_sorgu_atla = False     # sorgu koşsun (eşleşme listesi karşılaştırılır)
    if paralel is not None:
        cfg.bsim.paralel_tarama = paralel
    db = BSimDatabase(cfg)
    db._native.open_client = lambda name: CLIENT                 # type: ignore[union-attr]
    db._native._izleyici_olustur = dunya.izleyici()              # type: ignore[union-attr]
    return db


def _kos(tmp_path, monkeypatch, paralel: bool | None, **dunya_kw):
    d = _Dunya(_Saat(), **dunya_kw)
    d.kur(monkeypatch)
    db = _veritabani(tmp_path, monkeypatch, d, paralel)
    prog = _Program()
    n = db.ingest_program(prog, DBN)
    res = db.query_all_functions(prog, 0.7, db_name=DBN)
    db.close()
    return n, res.to_payload(), d


def _zamansiz(p: dict) -> dict:
    p = dict(p)
    p.pop("query_duration", None)
    det = dict(p["bsim_detail"])
    for k in ZAMAN_ALANLARI:
        det.pop(k, None)
    p["bsim_detail"] = det
    return p


def test_veritabani_paralel_cikti_tekli_ile_ayni_yalniz_scan_mode(tmp_path, monkeypatch) -> None:
    n1, p1, d1 = _kos(tmp_path / "a", monkeypatch, False)
    n2, p2, d2 = _kos(tmp_path / "b", monkeypatch, True)
    assert "scan_mode" not in p1["bsim_detail"]                  # bayrak kapalı: alan yok
    assert p2["bsim_detail"]["scan_mode"] == SCAN_PARALLEL
    q2 = _zamansiz(p2)
    q2["bsim_detail"].pop("scan_mode")
    q1 = _zamansiz(p1)
    q1["bsim_detail"]["own_identity"] = q2["bsim_detail"]["own_identity"]
    assert n1 == n2 and q1 == q2 and p1["total_matches"] > 0
    assert list(_zamansiz(p1)["bsim_detail"]) == [k for k in q2["bsim_detail"]]  # anahtar sırası
    assert len(d1.gens) == 2 and len(d2.gens) == 1               # sorgu ikinci kez taramadı
    assert d1.eklenen == d2.eklenen


def test_veritabani_bayrak_yokken_tekli_yol(tmp_path, monkeypatch) -> None:
    _, p, d = _kos(tmp_path, monkeypatch, None)
    assert Config().bsim.paralel_tarama in (False, True)          # alan var
    if not Config().bsim.paralel_tarama:
        assert d.paralel_cagri == [] and "scan_mode" not in p["bsim_detail"]


def test_veritabani_yedek_yolda_durum_alani_ve_ayni_eslesme(tmp_path, monkeypatch) -> None:
    _, p1, _ = _kos(tmp_path / "a", monkeypatch, False)
    _, p2, d2 = _kos(tmp_path / "b", monkeypatch, True, scan_error=RuntimeError("kuyruk"))
    det = p2["bsim_detail"]
    assert det["scan_mode"] == SCAN_SERIAL_FALLBACK
    assert "RuntimeError: kuyruk" in det["scan_fallback_error"]
    assert p2["matches"] == p1["matches"] and p2["total_queries"] == p1["total_queries"]
    assert {k for k, _ in d2.taranan} == {"tekli"}


def test_veritabani_sayac_okunamazsa_durumda_yazilir(tmp_path, monkeypatch) -> None:
    d = _Dunya(_Saat())
    d.kur(monkeypatch)
    db = _veritabani(tmp_path, monkeypatch, d, True)
    db._native._izleyici_olustur = d.izleyici(neden="sayaçlı izleyici kurulamadı (X: y)")
    db.ingest_program(_Program(), DBN)
    assert db.status["scan_sayac"] == "okunamadı: sayaçlı izleyici kurulamadı (X: y)"
    assert db.status["scan_mode"] == SCAN_PARALLEL
    db.close()


# ---------------------------------------------------------------------------
# Adım içi olay (okuyucu)
# ---------------------------------------------------------------------------

@pytest.fixture
def olaylar(monkeypatch):
    toplanan: list[tuple[str, str, dict]] = []
    monkeypatch.setattr(headless_mod, "_ilerleme",
                        lambda adim, durum, **al: toplanan.append((adim, durum, al)))
    return toplanan


def test_okuyucu_gercek_sayacla_suruyor_olayi(saat, olaylar) -> None:
    mon = _Mon(saat, None)
    den = _AdimDenetcisi("ghidra.bsim.ingest", 0, 15, saat.t)
    oku = _TaramaIzleyicisi(mon, den, 13, True)
    mon.progress = 7
    saat.ilerle(15.0)
    assert oku.oku() is False
    assert olaylar == [("ghidra.bsim.ingest", "suruyor",
                        {"islenen": 7, "toplam": 13, "gecen_sn": 15.0})]
    mon.progress = 9
    saat.ilerle(5.0)                      # aralık dolmadı: olay yok
    assert oku.oku() is False and len(olaylar) == 1
    assert oku.okuma == 2


def test_okuyucu_sayac_okunamazsa_olay_yok(saat, olaylar) -> None:
    den = _AdimDenetcisi("ghidra.bsim.ingest", 0, 15, saat.t)
    for sayac in (False, None):           # -1 (NO_PROGRESS_VALUE) ya da okuma istisnası
        oku = _TaramaIzleyicisi(_Mon(saat, None, sayac), den, 13, True)
        saat.ilerle(20.0)
        assert oku.oku() is False and oku.okunamayan == 1 and oku.okuma == 0
    assert olaylar == []
    assert _TaramaIzleyicisi(_Mon(saat, None), den, 13, False).baslat() is False
    assert _TaramaIzleyicisi(_Mon(saat, None), None, 13, True).baslat() is False
    sifir = _AdimDenetcisi("ghidra.bsim.ingest", 0, 0, saat.t)
    assert _TaramaIzleyicisi(_Mon(saat, None), sifir, 13, True).baslat() is False


def test_okuyucu_butce_dolunca_izleyiciyi_iptal_eder(saat, olaylar) -> None:
    mon = _Mon(saat, None)
    den = _AdimDenetcisi("ghidra.bsim.ingest", 10, 15, saat.t)
    mon.progress = 4
    saat.ilerle(11.0)
    assert _TaramaIzleyicisi(mon, den, 13, True).oku() is True
    assert mon.cancel_cagri == 1 and den.doldu and olaylar == []


def test_okuyucu_is_parcacigi_gercek_zamanla(monkeypatch, olaylar) -> None:
    mon = _Mon(None, None)
    mon.progress = 3
    den = _AdimDenetcisi("ghidra.bsim.ingest", 0, 0.02, _gercek_time.monotonic(), toplam=None)
    oku = _TaramaIzleyicisi(mon, den, 13, True)
    assert oku.baslat() is True
    bitis = _gercek_time.monotonic() + 2.0
    while not olaylar and _gercek_time.monotonic() < bitis:
        _gercek_time.sleep(0.01)
    oku.durdur()
    assert olaylar and all(o[1] == "suruyor" and o[2]["islenen"] == 3 and o[2]["toplam"] == 13
                           for o in olaylar)
    assert oku._is is not None and not oku._is.is_alive()


def test_paralel_taramada_okuyucu_sayac_okunamazsa_baslamaz(tmp_path, monkeypatch, saat,
                                                            olaylar) -> None:
    d = _Dunya(saat, adim_sn=20.0)
    d.kur(monkeypatch)
    w = _wrapper(tmp_path, d, True, neden="sayaçlı izleyici kurulamadı (E: x)")
    w.denetci = _AdimDenetcisi("ghidra.bsim.ingest", 0, 15, saat.t)
    w.ingest_program(_Program(), DBN, database=CLIENT)
    assert olaylar == [] and w.last_scan_sayac.startswith("sayaçlı izleyici kurulamadı")


# ---------------------------------------------------------------------------
# Kısmi ingest'in kalıcılığı (hüküm 5)
# ---------------------------------------------------------------------------

OWN = ExeIdentity(MD5_OWN, SHA_OWN, BUILD_OWN, "prog")


def test_koken_kaydi_kismi_isareti(tmp_path) -> None:
    st = _ProvenanceStore(tmp_path, DBN)
    st.record(OWN, "native")
    assert "kismi" not in st.load()[MD5_OWN]
    st.record(OWN, "native", {"islenen": 2, "toplam": 5})
    assert st.load()[MD5_OWN]["kismi"] == {"islenen": 2, "toplam": 5}
    st.record(OWN, "native")                         # depoda zaten var: işaret kalır
    assert st.load()[MD5_OWN]["kismi"] == {"islenen": 2, "toplam": 5}
    st.record(OWN, "native", tam=True)               # tam ingest: işaret kalkar
    assert "kismi" not in st.load()[MD5_OWN]


class _KismiNative(_FakeNative):
    def __init__(self, already: bool) -> None:
        super().__init__()
        self.already = already

    def ingest_program(self, program, db_name, database=None):
        self.last_ingest_already = self.already
        self.last_ingest_kismi = None if self.already else {"islenen": 2, "toplam": 5}
        return 5 if self.already else 2


def test_kismi_ingest_sonraki_kosuda_durumda_gorunur(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(bsim_mod, "_BSIM_AVAILABLE", True)
    cfg = Config()
    cfg.bsim.db_path = str(tmp_path / "bsim")
    cfg.bsim.lock_timeout_s = 0.3
    db = BSimDatabase(cfg)
    db._native = _KismiNative(False)  # type: ignore[assignment]
    db.ingest_program(_Program(), DBN)
    db.close()
    kayit = _ProvenanceStore(db.db_path, DBN).load()[MD5_OWN]
    assert kayit["kismi"] == {"islenen": 2, "toplam": 5}
    db2 = BSimDatabase(cfg)
    db2._native = _KismiNative(True)  # type: ignore[assignment]
    db2.ingest_program(_Program(), DBN)
    assert db2.status["onceki_ingest_kismi"] == "2 / 5"
    db2.close()
    assert _ProvenanceStore(db.db_path, DBN).load()[MD5_OWN]["kismi"] == {"islenen": 2,
                                                                         "toplam": 5}
    db3 = BSimDatabase(cfg)                     # tam ingest değilse alan yazılmaz
    db3._native = _KismiNative(False)  # type: ignore[assignment]
    db3._native.ingest_program = lambda p, n, database=None: 5  # type: ignore[method-assign]
    db3._native.last_ingest_kismi = None
    db3.ingest_program(_Program(), DBN)
    assert "onceki_ingest_kismi" not in db3.status
    db3.close()
    assert "kismi" not in _ProvenanceStore(db.db_path, DBN).load()[MD5_OWN]


# ---------------------------------------------------------------------------
# Küçük yardımcılar
# ---------------------------------------------------------------------------

def test_kalan_butce(saat) -> None:
    assert _kalan_butce_sn(None) is None
    assert _kalan_butce_sn(_AdimDenetcisi("ghidra.bsim.ingest", 0, 15, saat.t)) is None
    den = _AdimDenetcisi("ghidra.bsim.ingest", 10, 15, saat.t)
    saat.ilerle(4.0)
    assert _kalan_butce_sn(den) == pytest.approx(6.0)


def test_java_yineleyici_jvm_yokken_ayni_sira(monkeypatch) -> None:
    sahte = types.ModuleType("jpype")
    sahte.isJVMStarted = lambda: False  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "jpype", sahte)
    assert list(_java_iterator(list(FUNCS))) == list(FUNCS)


def test_java_yineleyici_jvm_varken_java_olmayan_oge(monkeypatch) -> None:
    """Tam takımda başka bir test JVM'i başlatmış olabilir: sahte öğe ArrayList'e girmez."""
    class _Liste:
        def __init__(self, _n) -> None:
            pass

        def add(self, _x):
            raise TypeError("No matching overloads found for java.util.ArrayList.add")

    sahte = types.ModuleType("jpype")
    sahte.isJVMStarted = lambda: True  # type: ignore[attr-defined]
    sahte.JClass = lambda _ad: _Liste  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "jpype", sahte)
    assert list(_java_iterator(list(FUNCS))) == list(FUNCS)


def test_java_yineleyici_jvm_varken_ayni_sira(monkeypatch) -> None:
    eklenen: list = []

    class _Liste:
        def __init__(self, n) -> None:
            assert n == len(FUNCS)

        def add(self, x):
            eklenen.append(x)

        def iterator(self):
            return iter(list(eklenen))

    sahte = types.ModuleType("jpype")
    sahte.isJVMStarted = lambda: True  # type: ignore[attr-defined]
    sahte.JClass = lambda ad: _Liste if ad == "java.util.ArrayList" else None  # type: ignore
    monkeypatch.setitem(sys.modules, "jpype", sahte)
    assert list(_java_iterator(list(FUNCS))) == list(FUNCS) and eklenen == list(FUNCS)
