"""ÖL-1: Ghidra köprüsünde takılan çözümleyici bekçisi ve ilerleme olayları.

- ``_CozumleyiciBekcisi``: aynı görev ``analysis.cozumleyici_takilma_sn`` boyunca tepedeyse
  izleyiciyi iptal eder; ``_run_auto_analysis`` çözümleyiciyi kapatır ve ``analyzeAll``'ı kalan
  bütçeyle BİR kez daha çağırır (ikinci takılmada yeniden deneme yok); bekçi kapalıyken
  (eşik 0, bugünkü öntanım) davranış bugünküyle aynı.
- İlerleme olayları (``olcek/PLAN.md`` §1 sözleşmesi): günlükçü ``karadul.ilerleme``, INFO, tek
  satır ``ILERLEME asama=static adim=… durum=…``; adım başı / sonu HZ-1'in ``_AdimSaati``
  noktalarında, bitişin ``gecen_sn``'si ``adim_sureleri``'ndeki süreyle aynı.

Ghidra / JVM gerekmez: sahte modüller (``tests/test_p16c_analiz_suresi.py`` kalıbı) ve HZ-1'in
sahte köprüsü (``tests/test_hz1_olcum_kancasi.py::kopru``).
"""

from __future__ import annotations

import logging
import shlex
import sys
import threading
import time
import types
from pathlib import Path

import pytest

import karadul.ghidra.headless as headless_mod
from karadul.config import Config
from karadul.ghidra.headless import (
    ANALIZ_COZUMLEYICI_KAPATILDI,
    GHIDRA_ADIMLARI,
    OLAY_ISTEGE_BAGLI_ALANLAR,
    GhidraHeadless,
    _AdimSaati,
    _CozumleyiciBekcisi,
    ilerleme_satiri,
)
from tests.test_hz1_olcum_kancasi import SURE, kopru  # noqa: F401
from tests.test_p16a_decompile_sirasi import _fonklar, _Program, sahte_ghidra  # noqa: F401

OBJC = "Objective-C Message"


def _olaylar(caplog) -> list[dict[str, str]]:
    """``karadul.ilerleme`` kayıtları → alan sözlükleri (``shlex`` ile; biçim de denetlenir)."""
    out = []
    for r in caplog.records:
        if r.name != "karadul.ilerleme":
            continue
        assert r.levelno == logging.INFO
        parcalar = shlex.split(r.getMessage())
        assert parcalar[0] == "ILERLEME"
        alanlar = dict(p.split("=", 1) for p in parcalar[1:])
        assert list(alanlar)[:3] == ["asama", "adim", "durum"]
        assert alanlar["asama"] == "static"
        out.append(alanlar)
    return out


@pytest.fixture
def olay_kaydi(caplog):
    caplog.set_level(logging.INFO, logger="karadul.ilerleme")
    return caplog


# ---------------------------------------------------------------------------
# Satır biçimi
# ---------------------------------------------------------------------------

def test_satir_bicimi_sozlesmedeki_sira_ve_tirnak() -> None:
    s = ilerleme_satiri("ghidra.otomatik_analiz", "suruyor", neden='a "b" = c',
                        cozumleyici=OBJC, gecen_sn=12.5, islenen=None)
    assert s == ('ILERLEME asama=static adim=ghidra.otomatik_analiz durum=suruyor gecen_sn=12.5 '
                 'cozumleyici="Objective-C Message" neden="a \\"b\\" = c"')
    alanlar = dict(p.split("=", 1) for p in shlex.split(s)[1:])
    assert alanlar["cozumleyici"] == OBJC and alanlar["neden"] == 'a "b" = c'
    assert "islenen" not in alanlar            # None değerli alan yazılmaz


def test_satir_tek_satir_ve_bos_deger_tirnakli() -> None:
    s = ilerleme_satiri("ghidra.strings", "kismi", neden="iki\nsatır", bilesen="")
    assert "\n" not in s
    alanlar = dict(p.split("=", 1) for p in shlex.split(s)[1:])
    assert alanlar["neden"] == "iki satır" and alanlar["bilesen"] == ""


def test_satir_bilinmeyen_alan_ve_durum_reddedilir() -> None:
    with pytest.raises(ValueError):
        ilerleme_satiri("ghidra.cfg", "bitti", hiz=3)
    with pytest.raises(ValueError):
        ilerleme_satiri("ghidra.cfg", "tamam")
    assert OLAY_ISTEGE_BAGLI_ALANLAR == (
        "islenen", "toplam", "gecen_sn", "cozumleyici", "bilesen", "neden")


# ---------------------------------------------------------------------------
# Bekçi (sahte saat ve okuyucu; iş parçacığı yok)
# ---------------------------------------------------------------------------

class _Saat:
    def __init__(self) -> None:
        self.t = 100.0

    def __call__(self) -> float:
        return self.t


def _bekci(okuyucu, esik=600, aralik=15, saat=None):
    iptal = []
    saat = saat or _Saat()
    b = _CozumleyiciBekcisi(okuyucu, lambda: iptal.append(saat()), esik, aralik,
                            baslangic=saat.t, saat=saat)
    return b, iptal, saat


def test_bekci_esikte_tetikler_iptal_eder_ve_durur(olay_kaydi) -> None:
    gorev = object()
    b, iptal, saat = _bekci(lambda: (gorev, OBJC))
    tetik = []
    for _ in range(45):                      # 0, 15, …, 660 sn
        tetik.append(b.oku())
        saat.t += 15
    assert tetik.index(True) == 40           # 40 × 15 = 600 sn: eşiğe eşit olunca
    assert iptal == [700.0] and b.takilan == OBJC and b.tepede_sn == 600.0
    assert b.okuma == 41                      # tetiklendikten sonra okumaz
    ol = _olaylar(olay_kaydi)
    assert len(ol) == 41 and all(o["durum"] == "suruyor" for o in ol)
    assert all(o["adim"] == "ghidra.otomatik_analiz" and o["cozumleyici"] == OBJC for o in ol)
    assert ol[0]["gecen_sn"] == "0.0" and ol[-1]["gecen_sn"] == "600.0"
    assert "neden" not in ol[-2] and "kapatılıyor" in ol[-1]["neden"]


def test_bekci_esik_altinda_tetiklemez() -> None:
    gorev = object()
    b, iptal, saat = _bekci(lambda: (gorev, OBJC))
    for _ in range(40):                      # 0 … 585 sn
        assert b.oku() is False
        saat.t += 15
    assert iptal == [] and b.takilan is None


def test_bekci_gorev_degisince_sayac_sifirlanir() -> None:
    # Aynı çözümleyici art arda yeniden kuyruğa girip her seferinde bitiyor: takılma değil.
    sayac = iter(range(10_000))
    b, iptal, saat = _bekci(lambda: (next(sayac), OBJC))
    for _ in range(100):
        assert b.oku() is False
        saat.t += 15
    assert iptal == []


def test_bekci_cozumleyici_olmayan_gorevi_kapatmaz(olay_kaydi) -> None:
    gorev = object()
    b, iptal, saat = _bekci(lambda: (gorev, None))
    for _ in range(60):
        assert b.oku() is False
        saat.t += 15
    assert iptal == [] and b.takilan is None
    assert all("cozumleyici" not in o for o in _olaylar(olay_kaydi))


def test_bekci_okuma_dusunce_sayar_olay_uretmez_ad_uydurmaz(olay_kaydi) -> None:
    def patla():
        raise RuntimeError("alan yok")

    b, iptal, saat = _bekci(patla)
    for _ in range(50):
        assert b.oku() is False
        saat.t += 15
    assert (b.okunamayan, b.okuma, b.takilan, iptal) == (50, 0, None, [])
    assert "alan yok" in b.son_hata
    assert _olaylar(olay_kaydi) == []


def test_bekci_bos_tepe_olay_uretmez_ve_sayaci_sifirlar(olay_kaydi) -> None:
    gorev = object()
    sira = [(gorev, OBJC)] * 30 + [None] + [(gorev, OBJC)] * 30
    it = iter(sira)
    b, iptal, saat = _bekci(lambda: next(it))
    for _ in range(len(sira)):
        b.oku()
        saat.t += 15
    assert iptal == []                        # 29 × 15 < 600; boşluktan sonra yeniden sayar
    assert len(_olaylar(olay_kaydi)) == 60


def _bitmesini_bekle(b: _CozumleyiciBekcisi) -> None:
    son = time.monotonic() + 5
    while b._is.is_alive() and time.monotonic() < son:
        time.sleep(0.01)
    assert not b._is.is_alive(), "bekçi iş parçacığı durmadı"


def test_bekci_is_parcacigi_gercek_zamanla_tetikler_ve_durur() -> None:
    iptal = threading.Event()
    gorev = object()
    b = _CozumleyiciBekcisi(lambda: (gorev, OBJC), iptal.set, 0.05, 0.01,
                            baslangic=time.monotonic())
    b.baslat()
    assert iptal.wait(5), "bekçi iş parçacığı tetiklemedi"
    assert b.durdur() is True and b.takilan == OBJC
    _bitmesini_bekle(b)


def test_bekci_is_parcacigi_durdurulunca_okumayi_birakir() -> None:
    gorev = object()
    sayilan = []

    def oku():
        sayilan.append(1)
        return (gorev, OBJC)

    b = _CozumleyiciBekcisi(oku, lambda: None, 3600, 0.01, baslangic=time.monotonic())
    b.baslat()
    time.sleep(0.1)
    assert b.durdur() is False
    n = len(sayilan)
    _bitmesini_bekle(b)
    assert n > 0 and len(sayilan) == n


# ---------------------------------------------------------------------------
# _run_auto_analysis: iptal → kapatma → ikinci tur (sahte Ghidra)
# ---------------------------------------------------------------------------

class _Kontrollu:
    """``headless_mod.time`` yerine: gerçek ``monotonic`` + elle eklenen kayma."""

    def __init__(self) -> None:
        self.kayma = 0.0

    def monotonic(self) -> float:
        return time.monotonic() + self.kayma

    @staticmethod
    def time() -> float:
        return time.time()


class _Analiz:
    """Sahte Ghidra: ``turlar[i]`` = i. ``analyzeAll`` turunda tepede takılan çözümleyici (ya da
    ``None``: tur hemen biter). Takılan tur izleyici iptal edilene kadar bekler."""

    def __init__(self, monkeypatch, turlar, kayma=0.0) -> None:
        self.calls: list[str] = []
        self.timeouts: list[int] = []
        self.turlar = list(turlar)
        self.tepe = None
        self.kapatilan: list[tuple[str, bool]] = []
        self.okuyucu_kuruldu = 0
        self.secenek_var = True
        saat = _Kontrollu()
        monkeypatch.setattr(headless_mod, "time", saat)
        g = self

        class TimeUnit:
            SECONDS = "SECONDS"

        class Monitor:
            def __init__(self, t) -> None:
                self.iptal = threading.Event()
                g.timeouts.append(t)

            def cancel(self):
                g.calls.append("cancel")
                self.iptal.set()

            def didTimeout(self):  # noqa: N802
                return False

            def finished(self):
                g.calls.append("finished")

        class TimeoutTaskMonitor:
            @staticmethod
            def timeoutIn(t, unit):  # noqa: N802
                return Monitor(t)

        class FlatProgramAPI:
            def __init__(self, program, monitor) -> None:
                self.monitor = monitor
                g.calls.append("flat_api")

            def analyzeAll(self, program):  # noqa: N802
                g.calls.append("analyzeAll")
                ad = g.turlar.pop(0) if g.turlar else None
                if ad is None:
                    return
                g.tepe = (object(), ad)
                assert self.monitor.iptal.wait(5), "bekçi iptal etmedi"
                g.tepe = None
                saat.kayma += kayma

        class GhidraProgramUtilities:
            @staticmethod
            def shouldAskToAnalyze(program):  # noqa: N802
                return True

            @staticmethod
            def markProgramAnalyzed(program):  # noqa: N802
                g.calls.append("mark")

        class GhidraScriptUtil:
            @staticmethod
            def acquireBundleHostReference():  # noqa: N802
                g.calls.append("acquire")

            @staticmethod
            def releaseBundleHostReference():  # noqa: N802
                g.calls.append("release")

        class AutoAnalysisManager:
            @staticmethod
            def getAnalysisManager(program):  # noqa: N802
                return types.SimpleNamespace(
                    getTaskTimesString=lambda: "    Stack   0.500 secs\n",
                    initializeOptions=lambda: g.calls.append("initializeOptions"))

        class Program:
            ANALYSIS_PROPERTIES = "Analyzers"

        mods = {}
        for name in ("java", "java.util", "java.util.concurrent", "ghidra", "ghidra.app",
                     "ghidra.app.script", "ghidra.app.plugin", "ghidra.app.plugin.core",
                     "ghidra.app.plugin.core.analysis", "ghidra.program",
                     "ghidra.program.flatapi", "ghidra.program.util", "ghidra.util",
                     "ghidra.util.task", "ghidra.program.model", "ghidra.program.model.listing"):
            mods[name] = types.ModuleType(name)
            monkeypatch.setitem(sys.modules, name, mods[name])
        mods["java.util.concurrent"].TimeUnit = TimeUnit
        mods["ghidra.util.task"].TimeoutTaskMonitor = TimeoutTaskMonitor
        mods["ghidra.program.flatapi"].FlatProgramAPI = FlatProgramAPI
        mods["ghidra.program.util"].GhidraProgramUtilities = GhidraProgramUtilities
        mods["ghidra.app.script"].GhidraScriptUtil = GhidraScriptUtil
        mods["ghidra.app.plugin.core.analysis"].AutoAnalysisManager = AutoAnalysisManager
        mods["ghidra.program.model.listing"].Program = Program

        def okuyucu_kur(program):
            g.okuyucu_kuruldu += 1
            return lambda: g.tepe

        monkeypatch.setattr(GhidraHeadless, "_cozumleyici_okuyucu", staticmethod(okuyucu_kur))

    def program(self):
        g = self
        return types.SimpleNamespace(
            startTransaction=lambda ad: 1, endTransaction=lambda tx, ok: None,
            getOptions=lambda ad: g._opts())

    def _opts(self):
        g = self

        class Opts:
            def contains(self, name):
                return g.secenek_var

            def setBoolean(self, name, value):  # noqa: N802
                g.kapatilan.append((name, value))

        return Opts()


def _gh(esik=0.05, aralik=0.01) -> GhidraHeadless:
    gh = GhidraHeadless.__new__(GhidraHeadless)
    gh.config = Config()
    gh.config.analysis.cozumleyici_takilma_sn = esik
    gh.config.analysis.bekci_aralik_sn = aralik
    gh.analyze_headless = Path("/yok/support/analyzeHeadless")
    return gh


def _kur(monkeypatch, turlar, secenek_var=True, kayma=0.0) -> _Analiz:
    a = _Analiz(monkeypatch, turlar, kayma=kayma)
    a.secenek_var = secenek_var
    return a


def test_takilan_cozumleyici_kapatilir_ikinci_tur_bir_kez(monkeypatch) -> None:
    a = _kur(monkeypatch, [OBJC, None])
    info = _gh()._run_auto_analysis(a.program(), 120)
    assert info["status"] == ANALIZ_COZUMLEYICI_KAPATILDI
    assert info["takilan_cozumleyici"] == OBJC
    assert [t["cozumleyici"] for t in info["takilmalar"]] == [OBJC]
    assert a.kapatilan == [(OBJC, False)]
    assert a.calls == [
        "flat_api", "acquire", "analyzeAll", "cancel", "release", "finished",
        "initializeOptions",
        "flat_api", "acquire", "analyzeAll", "mark", "release", "finished",
    ]
    assert info["kapatilan_cozumleyiciler"] == {OBJC: True}
    assert info["ilk_tur"]["analyzer_times"] == {"Stack": 0.5}
    assert info["bekci"]["okuma"] >= 1 and info["bekci"]["esik_sn"] == 0.05
    assert "neden" not in info


def test_ikinci_turda_yeniden_takilirsa_yeniden_deneme_yok(monkeypatch) -> None:
    a = _kur(monkeypatch, [OBJC, "Stack", None])
    info = _gh()._run_auto_analysis(a.program(), 120)
    assert a.calls.count("analyzeAll") == 2 and "mark" not in a.calls
    assert info["status"] == "timeout"
    assert [t["cozumleyici"] for t in info["takilmalar"]] == [OBJC, "Stack"]
    assert [t["tur"] for t in info["takilmalar"]] == [1, 2]
    assert info["takilan_cozumleyici"] == OBJC and "ikinci turda" in info["neden"]
    assert a.kapatilan == [(OBJC, False)]     # ikinci takılan kapatılmaz


def test_kapatilamayan_adla_ikinci_tur_yok(monkeypatch) -> None:
    a = _kur(monkeypatch, [OBJC, None], secenek_var=False)
    info = _gh()._run_auto_analysis(a.program(), 120)
    assert a.calls.count("analyzeAll") == 1 and "mark" not in a.calls
    assert info["status"] == "timeout" and "kapatılamadı" in info["neden"]
    assert info["kapatilan_cozumleyiciler"] == {OBJC: False}


def test_ikinci_tur_kalan_butceyle(monkeypatch) -> None:
    a = _kur(monkeypatch, [OBJC, None], kayma=100.0)
    info = _gh()._run_auto_analysis(a.program(), 120)
    assert info["status"] == ANALIZ_COZUMLEYICI_KAPATILDI
    assert a.timeouts == [120, 20]           # 120 − 100 (birinci tur) = 20


def test_butce_bitince_ikinci_tur_yok(monkeypatch) -> None:
    a = _kur(monkeypatch, [OBJC, None], kayma=200.0)
    info = _gh()._run_auto_analysis(a.program(), 120)
    assert a.calls.count("analyzeAll") == 1 and a.timeouts == [120]
    assert info["status"] == "timeout" and "bütçe" in info["neden"]


@pytest.mark.parametrize("esik,aralik", [(0, 15), (600, 0)])
def test_bekci_kapaliyken_davranis_bugunku_gibi(monkeypatch, esik, aralik) -> None:
    a = _kur(monkeypatch, [None])
    info = _gh(esik, aralik)._run_auto_analysis(a.program(), 120)
    assert a.okuyucu_kuruldu == 0
    assert a.calls == ["flat_api", "acquire", "analyzeAll", "mark", "release", "finished"]
    assert info["status"] == "ok"
    assert not {"bekci", "bekci_hatasi", "takilan_cozumleyici", "takilmalar", "ilk_tur",
                "kapatilan_cozumleyiciler", "neden"} & set(info)


def test_bekci_acik_takilmasiz_davranis_ayni(monkeypatch) -> None:
    # Yamalı öntanım (600 / 15): takılma yoksa çağrı dizisi ve durum bugünküyle aynı.
    a = _kur(monkeypatch, [None])
    info = _gh(600, 15)._run_auto_analysis(a.program(), 120)
    assert a.okuyucu_kuruldu == 1
    assert a.calls == ["flat_api", "acquire", "analyzeAll", "mark", "release", "finished"]
    assert info["status"] == "ok" and "takilan_cozumleyici" not in info
    assert info["bekci"] == {"esik_sn": 600.0, "aralik_sn": 15.0, "okuma": 0, "okunamayan": 0}


def test_okuyucu_kurulamazsa_bekcisiz_kosar(monkeypatch) -> None:
    a = _kur(monkeypatch, [None])

    def patla(program):
        raise RuntimeError("activeTask yok")

    monkeypatch.setattr(GhidraHeadless, "_cozumleyici_okuyucu", staticmethod(patla))
    info = _gh(600, 15)._run_auto_analysis(a.program(), 120)
    assert a.calls == ["flat_api", "acquire", "analyzeAll", "mark", "release", "finished"]
    assert info["status"] == "ok" and "activeTask yok" in info["bekci_hatasi"]
    assert "bekci" not in info


# ---------------------------------------------------------------------------
# Gerçek okuyucu (yansıma) sahte Java nesneleriyle
# ---------------------------------------------------------------------------

class _Alan:
    def __init__(self, ad, kayit) -> None:
        self.ad = ad
        self.kayit = kayit

    def setAccessible(self, v):  # noqa: N802
        self.kayit.append(("erisim", self.ad, v))

    def get(self, nesne):
        return getattr(nesne, "_" + self.ad)


class _Sinif:
    def __init__(self, kayit) -> None:
        self.kayit = kayit

    def getDeclaredField(self, ad):  # noqa: N802
        return _Alan(ad, self.kayit)


def test_gercek_okuyucu_yalniz_analysistask_adini_verir(monkeypatch) -> None:
    kayit: list = []

    class AnalysisTask:
        def __init__(self, ad) -> None:
            self.ad = ad

        def getName(self):  # noqa: N802
            return self.ad

    class Komut:
        def getName(self):  # noqa: N802
            return "Disassemble"

    class Sarmal:
        def __init__(self, gorev) -> None:
            self._task = gorev

        def getClass(self):  # noqa: N802
            return _Sinif(kayit)

    mgr = types.SimpleNamespace(_activeTask=None, getClass=lambda: _Sinif(kayit))

    class AutoAnalysisManager:
        @staticmethod
        def getAnalysisManager(program):  # noqa: N802
            return mgr

    for name in ("ghidra", "ghidra.app", "ghidra.app.plugin", "ghidra.app.plugin.core",
                 "ghidra.app.plugin.core.analysis"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    sys.modules["ghidra.app.plugin.core.analysis"].AutoAnalysisManager = AutoAnalysisManager
    sys.modules["ghidra.app.plugin.core.analysis"].AnalysisTask = AnalysisTask

    oku = GhidraHeadless._cozumleyici_okuyucu(object())
    assert ("erisim", "activeTask", True) in kayit
    assert oku() is None                                     # tepede görev yok
    s1 = Sarmal(AnalysisTask(OBJC))
    mgr._activeTask = s1
    assert oku() == (s1, OBJC)
    assert ("erisim", "task", True) in kayit
    s2 = Sarmal(Komut())
    mgr._activeTask = s2
    assert oku() == (s2, None)                               # çözümleyici değil: ad yok
    mgr._activeTask = Sarmal(None)
    assert oku() is None


# ---------------------------------------------------------------------------
# Köprü: adım olayları ve analiz durumu (HZ-1'in sahte köprüsü)
# ---------------------------------------------------------------------------

def _kos(gh, tmp_path):
    return gh._analyze_pyghidra(tmp_path / "x", tmp_path / "p", "p", 60, tmp_path)


def test_her_adimin_basladi_bitti_olayi_ayni_saatle(kopru, tmp_path, olay_kaydi) -> None:
    gh, _, _ = kopru
    sonuc = _kos(gh, tmp_path)
    ol = _olaylar(olay_kaydi)
    basladi = [o["adim"] for o in ol if o["durum"] == "basladi"]
    bitti = [o for o in ol if o["durum"] == "bitti"]
    assert basladi == list(GHIDRA_ADIMLARI) == [o["adim"] for o in bitti]
    # tek zamanlayıcı: bitiş olayının süresi adim_sureleri'ndekiyle aynı
    assert {o["adim"]: float(o["gecen_sn"]) for o in bitti} == sonuc["adim_sureleri"] == SURE
    # her bitiş kendi başlangıcından sonra, sonraki adımın başlangıcından önce
    sira = [(o["adim"], o["durum"]) for o in ol if o["durum"] in ("basladi", "bitti")]
    assert sira[:4] == [("ghidra.jvm_baslatma", "basladi"), ("ghidra.jvm_baslatma", "bitti"),
                        ("ghidra.ice_aktarma", "basladi"), ("ghidra.ice_aktarma", "bitti")]


def test_kapali_adimlar_atlandi_olayi(kopru, tmp_path, olay_kaydi) -> None:
    gh, _, _ = kopru
    gh.config.binary_reconstruction.ghidra_data_type_archives = []
    gh.config.binary_reconstruction.pdb_auto_load = False
    gh.config.binary_reconstruction.enable_function_id = False
    gh.config.bsim.enabled = False
    _kos(gh, tmp_path)
    atlandi = {o["adim"]: o["neden"] for o in _olaylar(olay_kaydi) if o["durum"] == "atlandi"}
    assert set(atlandi) == {"ghidra.gdt", "ghidra.pdb", "ghidra.function_id",
                            "ghidra.bsim.ingest"}


def test_dusen_adim_kismi_olay_nedeniyle(kopru, tmp_path, olay_kaydi) -> None:
    gh, _, kayit = kopru
    kayit["dusen"] = {"ghidra.strings"}
    _kos(gh, tmp_path)
    ol = [o for o in _olaylar(olay_kaydi) if o["adim"] == "ghidra.strings"]
    assert [o["durum"] for o in ol] == ["basladi", "kismi"]
    assert ol[1]["neden"].startswith("strings: RuntimeError") and ol[1]["gecen_sn"] == "2.0"
    sonraki = [o for o in _olaylar(olay_kaydi) if o["adim"] == "ghidra.call_graph"]
    assert [o["durum"] for o in sonraki] == ["basladi", "bitti"]   # önceki hata taşınmaz


def test_decompile_bitis_olayi_islenen_toplam(kopru, tmp_path, olay_kaydi, monkeypatch) -> None:
    gh, saat, _ = kopru

    def dec(*a, **kw):
        saat.ilerle(SURE["ghidra.decompile"])
        return {"success": 5, "failed": 2, "skipped": 1, "total_attempted": 8, "functions": []}

    monkeypatch.setattr(GhidraHeadless, "_decompile_functions", staticmethod(dec))
    _kos(gh, tmp_path)
    o = [o for o in _olaylar(olay_kaydi)
         if o["adim"] == "ghidra.decompile" and o["durum"] == "bitti"]
    assert len(o) == 1 and (o[0]["islenen"], o[0]["toplam"]) == ("7", "8")


def test_cozumleyici_kapatildi_adim_hatasi_ve_kismi(kopru, tmp_path, olay_kaydi,
                                                    monkeypatch) -> None:
    gh, _, _ = kopru
    info = {"status": ANALIZ_COZUMLEYICI_KAPATILDI, "timeout_s": 60, "duration_s": 700.0,
            "takilan_cozumleyici": OBJC, "bekci": {"esik_sn": 600.0},
            "takilmalar": [{"tur": 1, "cozumleyici": OBJC, "tepede_sn": 600.0}]}
    monkeypatch.setattr(GhidraHeadless, "_run_auto_analysis", lambda self, p, t: dict(info))
    sonuc = _kos(gh, tmp_path)
    hata = sonuc["step_errors"]["analysis"]
    assert OBJC in hata and "kapatıldı" in hata and "600" in hata and "bitti" in hata
    assert "WARN: analysis" in sonuc["ghidra_log"]
    assert sonuc["success"] is True and sonuc["analysis"]["takilan_cozumleyici"] == OBJC
    o = [o for o in _olaylar(olay_kaydi) if o["adim"] == "ghidra.otomatik_analiz"]
    assert [x["durum"] for x in o] == ["basladi", "kismi"] and OBJC in o[1]["neden"]


def test_bekci_zaman_asimi_metni_nedeni_soyler(kopru, tmp_path, monkeypatch) -> None:
    gh, _, _ = kopru
    info = {"status": "timeout", "timeout_s": 60, "takilan_cozumleyici": OBJC,
            "bekci": {"esik_sn": 600.0}, "neden": "ikinci turda yeniden takıldı (Stack)",
            "takilmalar": [{"tur": 1, "cozumleyici": OBJC, "tepede_sn": 601.0},
                           {"tur": 2, "cozumleyici": "Stack", "tepede_sn": 600.0}]}
    monkeypatch.setattr(GhidraHeadless, "_run_auto_analysis", lambda self, p, t: dict(info))
    hata = _kos(gh, tmp_path)["step_errors"]["analysis"]
    assert OBJC in hata and "ikinci turda" in hata and "60 sn'de durduruldu" not in hata


def test_duz_zaman_asimi_metni_degismedi(kopru, tmp_path, monkeypatch) -> None:
    gh, _, _ = kopru
    monkeypatch.setattr(GhidraHeadless, "_run_auto_analysis",
                        lambda self, p, t: {"status": "timeout", "timeout_s": t})
    hata = _kos(gh, tmp_path)["step_errors"]["analysis"]
    assert hata.startswith("zaman aşımı: Ghidra otomatik analizi 60 sn'de durduruldu")


def test_adim_saati_hatasiz_kullanimda_olay_bitti() -> None:
    hatalar: dict = {"onceki": "x"}
    s = _AdimSaati(hatalar)
    s.basla("ghidra.cfg")
    s.bitti("ghidra.cfg")
    assert "ghidra.cfg" in s.sozluk()


# ---------------------------------------------------------------------------
# Decompile parçaları bittikçe ``suruyor`` olayı (gerçek paralel yol, sahte decompiler)
# ---------------------------------------------------------------------------

def test_decompile_parca_olaylari_biten_fonksiyon_sayisi(tmp_path, sahte_ghidra,  # noqa: F811
                                                         olay_kaydi) -> None:
    fonklar = _fonklar(22)                     # 22 // 4 = 5'lik parçalar: 5 parça (son parça 2)
    hedef = tmp_path / "d"
    hedef.mkdir()
    GhidraHeadless._parallel_decompile_java_threads(_Program(fonklar), hedef, 22, 30, 0, 4)
    ol = [o for o in _olaylar(olay_kaydi) if o["adim"] == "ghidra.decompile"]
    assert [o["durum"] for o in ol] == ["suruyor"] * 5
    islenen = [int(o["islenen"]) for o in ol]
    assert islenen == sorted(islenen) and islenen[-1] == 22
    assert {o["toplam"] for o in ol} == {"22"}
    assert set(islenen) <= {2, 5, 7, 10, 12, 15, 17, 20, 22}
