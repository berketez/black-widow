"""Ghidra headless analiz wrapper.

Iki calisma modu destekler:
1. PyGhidra API (tercih edilen) -- pyghidra.open_program ile Ghidra JVM
   baslatilir ve analiz dogrudan Python 3 icinde yapilir.
2. CLI fallback -- analyzeHeadless komutu ile subprocess olarak
   calistirilir (Jython gerektirir, Ghidra 12.0'da sinirlidir).
"""

from __future__ import annotations

import json
import logging
import os
import re
import statistics
import threading
import time
from pathlib import Path
from typing import Any

from karadul.config import Config, CPU_PERF_CORES, warn_if_ghidra_unpinned
from karadul.core.subprocess_runner import SubprocessRunner

logger = logging.getLogger(__name__)

# AutoAnalysisManager.getTaskTimesString() satırı: "<çözümleyici>   1.234 secs" (P16c).
_TASK_TIME_LINE = re.compile(r"^\s*(.+?)\s+([0-9]+(?:\.[0-9]+)?)\s+secs?\s*$")

# HZ-1: Ghidra köprüsünün (``_analyze_pyghidra``) adımları. Her adımın süresi (``time.monotonic``;
# çıkarım + JSON yazımı, düşen adımda düşene kadar) ``adim_sureleri`` sözlüğüne bu adlarla girer
# ve ``static/ghidra_status.json``'a yazılır. Adlar ilerleme olayı sözleşmesiyle aynıdır
# (``docs/arge/2026-11-19_mythos/olcek/PLAN.md`` §1: ``adim=ghidra.<adım>``); ÖL-1 olaylarını bu
# listeden üretir, ikinci bir liste ya da zamanlayıcı tanımlanmaz. Çıktı dosyası üreten adım
# dosyanın adını, öbürleri sözleşmenin Türkçe adlandırmasını taşır; ``xref`` ve ``bsim``
# sözleşmedeki gibi. Sıra köprüdeki çalışma sırasıdır. Koşmayan adım (ayarı kapalı ya da köprü
# daha önce düştü) sözlükte yer almaz; yarıda düşen köprünün yarım adımı yazılmaz.
ADIM_JVM = "ghidra.jvm_baslatma"
ADIM_ICE_AKTARMA = "ghidra.ice_aktarma"
ADIM_OTOMATIK_ANALIZ = "ghidra.otomatik_analiz"
ADIM_GDT = "ghidra.gdt"
ADIM_PDB = "ghidra.pdb"
ADIM_FUNCTIONS = "ghidra.functions"
ADIM_STRINGS = "ghidra.strings"
ADIM_CALL_GRAPH = "ghidra.call_graph"
ADIM_DECOMPILE = "ghidra.decompile"
ADIM_TYPES = "ghidra.types"
ADIM_XREF = "ghidra.xref"
ADIM_PCODE = "ghidra.pcode"
ADIM_CFG = "ghidra.cfg"
ADIM_FUNCTION_ID = "ghidra.function_id"
ADIM_BSIM_INGEST = "ghidra.bsim.ingest"
ADIM_BSIM_QUERY = "ghidra.bsim.query"
ADIM_COMBINED = "ghidra.combined"
ADIM_KAPATMA = "ghidra.kapatma"
GHIDRA_ADIMLARI: tuple[str, ...] = (
    ADIM_JVM, ADIM_ICE_AKTARMA, ADIM_OTOMATIK_ANALIZ, ADIM_GDT, ADIM_PDB,
    ADIM_FUNCTIONS, ADIM_STRINGS, ADIM_CALL_GRAPH, ADIM_DECOMPILE, ADIM_TYPES, ADIM_XREF,
    ADIM_PCODE, ADIM_CFG, ADIM_FUNCTION_ID, ADIM_BSIM_INGEST, ADIM_BSIM_QUERY, ADIM_COMBINED,
    ADIM_KAPATMA,
)
# HZ-1: köprü sonucundan ``static/ghidra_status.json``'a aynen geçen süre alanları
# (``MachOAnalyzer._record_ghidra_outcome``). ``analysis``: otomatik analizin durumu, süresi,
# sınırı, çözümleyici başına süreleri, kapatılan çözümleyiciler (P16c). ``adim_sureleri``:
# yukarıdaki adımların süresi. ``decompile_parcalari``: decompile parçalarının süre özeti.
DURUM_SURE_ALANLARI: tuple[str, ...] = ("analysis", "adim_sureleri", "decompile_parcalari")

# ÖL-1: ilerleme olayı sözleşmesi (``docs/arge/2026-11-19_mythos/olcek/PLAN.md`` §1; SABİT, ÖL-4
# gösterir). Günlükçü ``karadul.ilerleme``, düzey INFO, tek satır ``ILERLEME alan=değer …``.
# Olay yalnız gerçek bir adım geçişinde ya da gerçek bir okumada üretilir; "canlı görünsün" diye
# zamanlayıcıyla boş olay basılmaz. Boşluk içeren değer çift tırnakta (``"``, ``=`` ve ters bölü
# içeren değer de); tırnak içinde ``"`` ve ``\`` ters bölüyle kaçırılır, satır sonu boşluğa
# çevrilir: satır ``shlex.split`` ile ayrıştırılır. ``None`` değerli alan yazılmaz.
ILERLEME_GUNLUKCU = "karadul.ilerleme"
ILERLEME_ONEKI = "ILERLEME"
ILERLEME_ASAMA = "static"  # Ghidra köprüsü ``static`` aşamasında koşar
OLAY_BASLADI = "basladi"
OLAY_SURUYOR = "suruyor"
OLAY_BITTI = "bitti"
OLAY_KISMI = "kismi"
OLAY_ATLANDI = "atlandi"
OLAY_DURUMLARI: tuple[str, ...] = (OLAY_BASLADI, OLAY_SURUYOR, OLAY_BITTI, OLAY_KISMI, OLAY_ATLANDI)
OLAY_ISTEGE_BAGLI_ALANLAR: tuple[str, ...] = (
    "islenen", "toplam", "gecen_sn", "cozumleyici", "bilesen", "neden",
)
_ilerleme_logger = logging.getLogger(ILERLEME_GUNLUKCU)

# ÖL-1: bekçi takılan çözümleyiciyi kapatıp otomatik analizi ikinci turda bitirdiyse
# ``analysis.status`` (``static`` aşaması kısmi sayar: ``step_errors["analysis"]``).
ANALIZ_COZUMLEYICI_KAPATILDI = "ok_cozumleyici_kapatildi"


def _olay_degeri(deger: Any) -> str:
    metin = re.sub(r"[\r\n]+", " ", str(deger))
    if metin == "" or re.search(r'[\s"=\\]', metin):
        return '"%s"' % metin.replace("\\", "\\\\").replace('"', '\\"')
    return metin


def ilerleme_satiri(adim: str, durum: str, **alanlar: Any) -> str:
    """ÖL-1: sözleşme biçiminde tek ``ILERLEME`` satırı (alan sırası sözleşmedeki sıra)."""
    if durum not in OLAY_DURUMLARI:
        raise ValueError("bilinmeyen ilerleme durumu: %r" % (durum,))
    bilinmeyen = sorted(set(alanlar) - set(OLAY_ISTEGE_BAGLI_ALANLAR))
    if bilinmeyen:
        raise ValueError("sözleşmede olmayan ilerleme alanı: %s" % bilinmeyen)
    parcalar = [ILERLEME_ONEKI, "asama=" + ILERLEME_ASAMA, "adim=" + _olay_degeri(adim),
                "durum=" + durum]
    for ad in OLAY_ISTEGE_BAGLI_ALANLAR:
        if alanlar.get(ad) is not None:
            parcalar.append("%s=%s" % (ad, _olay_degeri(alanlar[ad])))
    return " ".join(parcalar)


def _ilerleme(adim: str, durum: str, **alanlar: Any) -> None:
    """ÖL-1: olayı ``karadul.ilerleme`` günlükçüsüne INFO düzeyinde yaz."""
    _ilerleme_logger.info("%s", ilerleme_satiri(adim, durum, **alanlar))


def _takilma_metni(info: dict[str, Any]) -> str:
    """ÖL-1: bekçi tetiklendiğinde ``step_errors["analysis"]`` metni (ad + süre + sonuç)."""
    ilk = (info.get("takilmalar") or [{}])[0]
    esik = (info.get("bekci") or {}).get("esik_sn")
    metin = "takılan çözümleyici kapatıldı: %r %s sn tepede kaldı (eşik %s sn)" % (
        ilk.get("cozumleyici"), ilk.get("tepede_sn"), "%g" % esik if esik is not None else "?")
    if info.get("status") == ANALIZ_COZUMLEYICI_KAPATILDI:
        return metin + "; otomatik analiz onsuz yeniden koşuldu ve bitti; analiz kısmi"
    return metin + "; %s; analiz kısmi (sonraki adımlar kısmi programla koştu)" % (
        info.get("neden") or "otomatik analiz bitmedi")


class _AdimSaati:
    """HZ-1: köprü adımlarının süresi; yalnız ``GHIDRA_ADIMLARI``'ndaki adlar kabul edilir.

    ÖL-1: adım başı ve sonu aynı noktada ilerleme olayı üretir (ikinci zamanlayıcı yok):
    ``basla`` → ``durum=basladi``; ``bitti`` → ``durum=bitti gecen_sn=<bu kaydın süresi>``.
    ``hatalar`` (köprünün ``step_errors``'ı) verilmişse adım sürerken eklenen hata ``durum=kismi
    neden="<adım>: <hata>"`` yazdırır.
    """

    def __init__(self, hatalar: dict[str, str] | None = None) -> None:
        self._baslangic: dict[str, float] = {}
        self._sureler: dict[str, float] = {}
        self._hatalar = hatalar
        self._onceki_hatalar: dict[str, frozenset[str]] = {}
        self._denetciler: dict[str, _AdimDenetcisi] = {}

    def basla(self, adim: str) -> None:
        if adim not in GHIDRA_ADIMLARI:
            raise ValueError("bilinmeyen Ghidra adımı: %r" % (adim,))
        self._baslangic[adim] = time.monotonic()
        self._onceki_hatalar[adim] = frozenset(self._hatalar or ())
        _ilerleme(adim, OLAY_BASLADI)

    def denetci(self, adim: str, butce_sn: float, aralik_sn: float,
                toplam: int | None = None) -> _AdimDenetcisi:
        """ÖL-2: başlamış adımın bütçe / adım içi olay denetçisi (başlangıcı bu saatten alır)."""
        t0 = self._baslangic.get(adim)
        if t0 is None:
            raise ValueError("başlamamış adıma denetçi kurulamaz: %r" % (adim,))
        den = _AdimDenetcisi(adim, butce_sn, aralik_sn, t0, toplam)
        self._denetciler[adim] = den
        return den

    def bitti(self, adim: str, **alanlar: Any) -> None:
        """Başlamış adımın süresini yaz; başlamamış ya da bitmiş adımda bir şey yapmaz."""
        t0 = self._baslangic.pop(adim, None)
        den = self._denetciler.pop(adim, None)
        if t0 is not None:
            self._sureler[adim] = round(time.monotonic() - t0, 3)
            onceki = self._onceki_hatalar.pop(adim, frozenset())
            yeni = [k for k in (self._hatalar or {}) if k not in onceki]
            if yeni and den is not None and den.doldu:
                # ÖL-2: bütçesi dolan adımın kısmi olayı gerçek sayaçları taşır.
                alanlar = {**den.sayac(), **alanlar}
            if yeni:
                _ilerleme(adim, OLAY_KISMI, gecen_sn=self._sureler[adim],
                          neden="%s: %s" % (yeni[0], self._hatalar[yeni[0]]), **alanlar)
            else:
                _ilerleme(adim, OLAY_BITTI, gecen_sn=self._sureler[adim], **alanlar)

    def sozluk(self) -> dict[str, float]:
        """Biten adımlar, ``GHIDRA_ADIMLARI`` sırasında."""
        return {a: self._sureler[a] for a in GHIDRA_ADIMLARI if a in self._sureler}


# ÖL-2: küçük birimli döngülerde (komut, sembol) saat her birimde değil bu kadar birimde bir
# okunur; fonksiyon / veri / tip döngülerinde her birimde (birim başına birkaç Java çağrısı var,
# saat okuması onların yanında ihmal edilir).
KUCUK_BIRIM_DENETIM_ADIMI = 1024


def _ayar_sn(config: Any, bolum: str, alan: str) -> float:
    """ÖL-2: ``config.<bolum>.<alan>`` saniye değeri; yok / geçersiz / negatif → 0 (kapalı)."""
    try:
        deger = float(getattr(getattr(config, bolum, None), alan, 0) or 0)
    except (TypeError, ValueError):
        return 0.0
    return deger if deger > 0 else 0.0


def _en_kucuk_butce(*butceler: float) -> float:
    """ÖL-2: sıfırdan büyük bütçelerin küçüğü; hepsi 0 ise 0 (bütçe yok)."""
    olan = [b for b in butceler if b and b > 0]
    return min(olan) if olan else 0.0


class _AdimDenetcisi:
    """ÖL-2: bir köprü adımının döngüsündeki tek denetim noktası (bütçe + adım içi olay).

    Döngü her birimin başında ``denetle(islenen)`` çağırır (``islenen`` = biten birim sayısı,
    gerçek döngü sayacı). Adımın başlangıcı (``_AdimSaati.basla`` anı) + ``butce_sn`` geçildiyse
    ``True`` döner (döngüden çık) ve kesildiği andaki sayaçları saklar. Geçilmediyse ve adımın son
    olayından beri ``aralik_sn`` geçtiyse aynı noktada ``durum=suruyor islenen=… toplam=…
    gecen_sn=…`` olayı üretilir. Zamanlayıcıyla olay basılmaz: olay yalnız döngü buraya
    geldiğinde. ``butce_sn = 0`` → bütçe yok; ``aralik_sn = 0`` → olay yok. ``toplam`` bilinmiyorsa
    (``None``) olayda ve kısmi çıktıda yazılmaz.
    """

    def __init__(self, adim: str, butce_sn: float, aralik_sn: float, baslangic: float,
                 toplam: int | None = None) -> None:
        self.adim = adim
        self.butce_sn = float(butce_sn) if butce_sn and butce_sn > 0 else 0.0
        self.aralik_sn = float(aralik_sn) if aralik_sn and aralik_sn > 0 else 0.0
        self.toplam = toplam
        self._baslangic = baslangic
        self._son_an = baslangic + self.butce_sn if self.butce_sn > 0 else None
        self._son_olay = baslangic
        self.doldu = False
        self.islenen: int | None = None
        self.olay = 0
        self.ek_neden = ""

    def denetle(self, islenen: int, toplam: int | None = None) -> bool:
        if toplam is None:
            toplam = self.toplam
        simdi = time.monotonic()
        if self._son_an is not None and simdi > self._son_an:
            self.doldu = True
            self.islenen = int(islenen)
            self.toplam = toplam
            return True
        if self.aralik_sn > 0 and simdi - self._son_olay >= self.aralik_sn:
            self._son_olay = simdi
            self.olay += 1
            _ilerleme(self.adim, OLAY_SURUYOR, islenen=int(islenen), toplam=toplam,
                      gecen_sn=round(simdi - self._baslangic, 1))
        return False

    def neden(self) -> str:
        metin = "adım bütçesi (%g sn) doldu" % self.butce_sn
        return metin + ("; " + self.ek_neden if self.ek_neden else "")

    def sayac(self) -> dict[str, int]:
        """Kesildiği andaki sayaçlar (toplam bilinmiyorsa yalnız ``islenen``)."""
        if not self.doldu:
            return {}
        out = {"islenen": int(self.islenen or 0)}
        if self.toplam is not None:
            out["toplam"] = int(self.toplam)
        return out

    def kismi_alanlari(self) -> dict[str, Any]:
        """Kısmi çıktıya eklenecek alanlar; bütçe dolmadıysa boş (çıktı bayt bayt aynı kalır)."""
        if not self.doldu:
            return {}
        return {"kismi": True, **self.sayac(), "neden": self.neden()}


def _jvm_den_ayril() -> None:
    """Bu Python iş parçacığı JVM'e bağlandıysa ayır (JPype onu kendiliğinden ayırmaz)."""
    try:
        import jpype

        if jpype.isJVMStarted() and jpype.isThreadAttachedToJVM():
            jpype.JClass("java.lang.Thread").detach()
    except Exception:  # noqa: BLE001
        logger.debug("bekçi iş parçacığı JVM'den ayrılamadı", exc_info=True)


class _CozumleyiciBekcisi:
    """ÖL-1: otomatik analizde tepedeki Ghidra görevini aralıkla okuyan bekçi (daemon iş parçacığı).

    ``okuyucu() -> (anahtar, ad) | None``: ``None`` = tepede görev yok; ``anahtar`` görevin
    kimliği (Ghidra'da görev sarmalayıcısı; ``==`` Java ``equals`` = kimlik); ``ad`` görev bir
    çözümleyiciyse onun seçenek adı, değilse ``None`` (kapatılamaz, olayda ad yazılmaz).

    Her başarılı okumada ``adim=ghidra.otomatik_analiz durum=suruyor`` olayı (``gecen_sn`` =
    otomatik analizin başından beri). Aynı görev ``esik_sn`` boyunca tepede kalır ve bir
    çözümleyiciyse ``iptal`` çağrılır (izleyicinin ``cancel()``'ı), ad ``takilan``'a yazılır ve
    bekçi durur. Okuma düşerse sayılır, olay üretilmez, ad uydurulmaz. Eşik ve aralık yalnız
    ayardan gelir (``analysis.cozumleyici_takilma_sn``, ``analysis.bekci_aralik_sn``; A-9).
    """

    def __init__(self, okuyucu, iptal, esik_sn: float, aralik_sn: float,
                 baslangic: float, saat=None) -> None:
        self._okuyucu = okuyucu
        self._iptal = iptal
        self._esik = float(esik_sn)
        self._aralik = float(aralik_sn)
        self._baslangic = baslangic
        self._saat = saat if saat is not None else time.monotonic
        self._onceki: Any = None
        self._ilk_gorulme = 0.0
        self._dur = threading.Event()
        self._is: threading.Thread | None = None
        self.takilan: str | None = None
        self.tepede_sn: float | None = None
        self.okuma = 0
        self.okunamayan = 0
        self.son_hata: str | None = None

    def oku(self) -> bool:
        """Tek okuma; bekçi tetiklendiyse (bu ya da önceki okumada) ``True``."""
        if self.takilan is not None:
            return True
        try:
            okunan = self._okuyucu()
        except Exception as exc:  # noqa: BLE001
            self.okunamayan += 1
            self.son_hata = "%s: %s" % (type(exc).__name__, exc)
            self._onceki = None
            return False
        simdi = self._saat()
        if okunan is None:
            self._onceki = None
            return False
        anahtar, ad = okunan
        self.okuma += 1
        if self._onceki is None or not (anahtar == self._onceki):
            self._onceki = anahtar
            self._ilk_gorulme = simdi
        tepede = simdi - self._ilk_gorulme
        gecen = round(simdi - self._baslangic, 1)
        if ad is not None and tepede >= self._esik:
            self.takilan = ad
            self.tepede_sn = round(tepede, 1)
            neden = "%.0f sn tepede (eşik %g sn); kapatılıyor" % (tepede, self._esik)
            _ilerleme(ADIM_OTOMATIK_ANALIZ, OLAY_SURUYOR, gecen_sn=gecen, cozumleyici=ad,
                      neden=neden)
            logger.warning("Ghidra çözümleyicisi takıldı: %s %s", ad, neden)
            self._iptal()
            return True
        _ilerleme(ADIM_OTOMATIK_ANALIZ, OLAY_SURUYOR, gecen_sn=gecen, cozumleyici=ad)
        return False

    def _dongu(self) -> None:
        try:
            while not self._dur.wait(self._aralik):
                if self.oku():
                    break
        finally:
            _jvm_den_ayril()

    def baslat(self) -> None:
        self._is = threading.Thread(target=self._dongu, name="karadul-cozumleyici-bekcisi",
                                    daemon=True)
        self._is.start()

    def durdur(self) -> bool:
        """İş parçacığını durdur; bekçi tetiklendiyse ``True``."""
        self._dur.set()
        if self._is is not None:
            self._is.join(self._aralik)
        return self.takilan is not None

# PyGhidra kontrol
_PYGHIDRA_AVAILABLE: bool | None = None
_PYGHIDRA_STARTED: bool = False


def _check_pyghidra() -> bool:
    """PyGhidra modulu mevcut mu kontrol et (lazy, tek seferlik)."""
    global _PYGHIDRA_AVAILABLE
    if _PYGHIDRA_AVAILABLE is None:
        try:
            import pyghidra  # noqa: F401
            _PYGHIDRA_AVAILABLE = True
        except ImportError:
            _PYGHIDRA_AVAILABLE = False
    return _PYGHIDRA_AVAILABLE


def _ensure_pyghidra_started(ghidra_install: Path, heap_mb: int | None = None) -> None:
    """PyGhidra JVM'i baslat (lazy, tek seferlik).

    JVM crash/kill sonrasi recovery: JVM zaten olmus ama flag hala True ise
    sifirla ve tekrar dene. JVM ayni process'te yeniden baslatilamazsa
    anlamli hata mesaji ver.

    ``heap_mb``: JVM yığını (``analysis.ghidra_max_heap_mb``; P16c). Verilmezse
    ``GHIDRA_HEAP_MB`` (ayarın öntanımı da odur). JVM zaten başlamışsa etkisizdir.
    """
    global _PYGHIDRA_STARTED
    if _PYGHIDRA_STARTED:
        return

    import pyghidra
    if pyghidra.started():
        _PYGHIDRA_STARTED = True
        return

    from pyghidra.launcher import HeadlessPyGhidraLauncher
    from karadul.config import CPU_PERF_CORES, GHIDRA_HEAP_MB
    warn_if_ghidra_unpinned(ghidra_install)
    launcher = HeadlessPyGhidraLauncher(install_dir=ghidra_install)
    gc_threads = max(2, CPU_PERF_CORES)
    conc_threads = max(1, CPU_PERF_CORES // 2)
    launcher.add_vmargs(
        # HeadlessPyGhidraLauncher bunu KENDİSİ vermiyor (VM argümanlarını yalnız
        # launch.properties'ten okur, orada da yok). Olmazsa AWT'ye dokunan herhangi
        # bir Java kodu macOS'ta LWCToolkit.initAppkit ile AppKit'in ana thread'de
        # başlamasını bekler; ana thread Python'da bir kilitte beklediği için süreç
        # kalıcı olarak kilitlenir (2026-09-25, .app hedefinde ölçüldü).
        "-Djava.awt.headless=true",
        "-XX:+UseG1GC",
        f"-XX:ParallelGCThreads={gc_threads}",
        f"-XX:ConcGCThreads={conc_threads}",
        "-XX:+UseCompressedOops",
        f"-XX:ActiveProcessorCount={gc_threads}",
        f"-Xmx{int(heap_mb) if heap_mb else GHIDRA_HEAP_MB}m",
    )
    try:
        launcher.start()
    except Exception as exc:
        err_msg = str(exc)
        if "not running" in err_msg.lower() or "already" in err_msg.lower():
            logger.warning(
                "JVM baslatilamadi (%s) -- onceki session'dan kirli state olabilir. "
                "Yeni karadul process'i ile tekrar deneyin.",
                err_msg,
            )
        raise RuntimeError(
            f"Ghidra JVM baslatilamadi: {exc}. "
            f"Karadul'u yeniden calistirin (JVM ayni process'te tekrar baslatilamaz)."
        ) from exc
    _PYGHIDRA_STARTED = True
    _release_jvm_creator_thread()
    logger.info("PyGhidra JVM baslatildi (Ghidra: %s)", ghidra_install)


def _release_jvm_creator_thread() -> None:
    """JVM'i ana olmayan bir thread başlattıysa o thread'i JVM'den ayır.

    JNI_CreateJavaVM'i çağıran thread JVM'de daemon OLMAYAN "main" Java
    thread'i olarak kayıtlı kalır. Bu bir Python işçi thread'iyse
    (ThreadPoolExecutor) thread bittiğinde JVM'den ayrılmaz — JPype otomatik
    ayırmaz. Çıkışta ana thread'deki JPype atexit kancası DestroyJavaVM'i
    çağırır; o da daemon olmayan thread sayısının 1'e inmesini bekler ve ölü
    "main" yüzünden SONSUZA kadar bekler.

    Ölçüm (2026-09-25, .app analizi): analiz bitip sonuç tablosu basıldıktan
    sonra süreç asılı kaldı (timeout 300 -> rc=124). jstack: daemon olmayan
    yalnız iki Java thread'i vardı — "main" #1 (OS thread'i ölü, cpu=-0.00ms)
    ve Monitor::wait'te bekleyen "DestroyJavaVM". H2/MVStore/GTimer
    thread'leri daemon'dı, çıkışı engellemiyordu. İzole deney (yalnız JPype):
    JVM ana thread'de başlarsa rc=0; işçi thread'de başlarsa asılı (rc=124);
    işçi thread başlattıktan sonra detach ederse rc=0.

    Ayrılan thread sonraki Java çağrısında JPype tarafından DAEMON olarak
    yeniden bağlanır (JPype'ın otomatik bağlama davranışı), çıkışı bloke
    etmez. Ana thread'e dokunulmaz: DestroyJavaVM'i zaten o çağırır.
    """
    import threading

    if threading.current_thread() is threading.main_thread():
        return
    try:
        import jpype

        jpype.JClass("java.lang.Thread").detach()
        logger.debug(
            "JVM ana olmayan thread'de başlatıldı (%s); thread JVM'den ayrıldı",
            threading.current_thread().name,
        )
    except Exception:
        logger.warning(
            "JVM'i başlatan thread JVM'den ayrılamadı; süreç çıkışta "
            "DestroyJavaVM'de asılı kalabilir",
            exc_info=True,
        )


def _address_sort_key(addr: str) -> tuple[str, int, str]:
    """Ghidra adres dizgisi için sıralama anahtarı (``ram:0010`` ya da ``00100010``)."""
    space, _, offset = addr.rpartition(":")
    try:
        return (space, int(offset, 16), "")
    except ValueError:
        return (space, -1, addr)


# Varnode.toString(): "(register, 0x4000, 8)", "(stack, 0xfffffffffffffff0, 8)".
_VARNODE_TEXT = re.compile(r"^\((?P<space>[^,()]+), 0x(?P<offset>[0-9a-fA-F]+), (?P<size>\d+)\)$")


def high_var_sort_key(entry: dict) -> tuple:
    """``pcode_high_vars`` kaydı için kararlı sıralama anahtarı (P16d).

    Ghidra'nın ``LocalSymbolMap.getSymbols()`` yinelemesi simge kimliğiyle anahtarlanmış bir
    eşlemin değerleridir; aynı girdide sırası koşudan koşuya değişiyordu (küme aynı). Liste
    üretim noktasında depolama yerine göre sıralanır: biçimi tanınan depolama (alan adı, sayısal
    ofset, genişlik) önce, tanınmayan (``unknown`` vb.) metniyle sonra; eşitlikte ad, tip,
    boyut. 119 ikilinin dökümünde (depolama, ad, tip, boyut) dörtlüsü fonksiyon içinde hiç
    yinelenmiyor, yani sıra tam belirlidir. Anahtar hiçbir girdide istisna atmaz.
    """
    storage = str(entry.get("storage", "") or "")
    m = _VARNODE_TEXT.match(storage)
    if m:
        where: tuple = (0, m.group("space"), int(m.group("offset"), 16), int(m.group("size")), "")
    else:
        where = (1, "", 0, 0, storage)
    size = entry.get("size")
    return (
        where,
        str(entry.get("name", "") or ""),
        str(entry.get("type", "") or ""),
        size if isinstance(size, int) and not isinstance(size, bool) else -1,
    )


def caller_sort_key(entry: dict) -> tuple:
    """Çağıran listesi kaydı için kararlı sıralama anahtarı (P16e).

    Çağıranlar ``ReferenceManager.getReferencesTo(giriş)`` yinelemesiyle toplanıyor; o sıra
    koşudan koşuya değişiyordu (küme aynı; HZ1, 2026-11-20: htop 6 koşuda 4 farklı sıra), ``.c``
    başlığındaki ``// Callers:`` satırı da ilk 5'i gösterdiği için farklı alt küme gösteriyordu.
    Liste tekilleştirildikten sonra, yazılmadan önce bu anahtarla sıralanır: çağıranın giriş
    adresi (tam sayı değeri), eşitlikte ad, sonra çağrı yeri. Anahtar hiçbir girdide istisna atmaz.
    """
    return (
        _address_sort_key(str(entry.get("address", "") or "")),
        str(entry.get("name", "") or ""),
        _address_sort_key(str(entry.get("call_site", "") or "")),
    )


_DIZGI_DEGIL = object()  # HZ-4a: "bu adreste dizgi verisi yok" (değer None da olabildiği için ayrı)


class _BasvuruKaydi:
    """HZ-4a: bir fonksiyonun tek başvuru geçişinden çıkan kayıt (çağrı grafiği + xref ortak).

    ``cagrilanlar``: gövdeden çıkan çağrı başvurularının hedef fonksiyonları, ``(ad, giriş)``;
    giriş adresine göre tekil, ilk görülme sırasıyla (kaynak adresi artan, adres içinde
    ``getReferencesFrom`` dizi sırası). ``cagiranlar``: giriş adresine gelen çağrı başvurularının
    kaynak fonksiyonları, ``{"name", "address"}``; tekil ve ``caller_sort_key`` sıralı (P16e).
    ``dizgiler``: gövdeden çıkan veri başvurularının gösterdiği dizgi verileri, ``(adres, değer)``;
    adrese göre tekil, ilk görülme sırasıyla (A-38: komut içi sıra bu listenin sırasıdır).
    ``giris_cagri_disi``: giriş adresine gelen ve çağrı OLMAYAN başvurular (Java ``Reference``
    nesneleri, yineleme sırasıyla; JSON'a yazılmaz — PK-8'in ``address_taken_by`` alanı için).
    """

    __slots__ = ("cagrilanlar", "cagiranlar", "dizgiler", "giris_cagri_disi")

    def __init__(self, cagrilanlar: list, cagiranlar: list, dizgiler: list,
                 giris_cagri_disi: list) -> None:
        self.cagrilanlar = cagrilanlar
        self.cagiranlar = cagiranlar
        self.dizgiler = dizgiler
        self.giris_cagri_disi = giris_cagri_disi


class _BasvuruTablosu:
    """HZ-4a: çağrı grafiği ve xref dökümünün ortak başvuru tablosu (fonksiyon başına tek geçiş).

    Eski döngüler aynı başvuru verisini iki adımda ayrı ayrı, gövdedeki HER adres için
    ``getReferencesFrom`` çağırarak geziyordu. Tablo fonksiyon başına bir kez, yalnız başvurusu
    olan adresleri (``ReferenceManager.getReferenceSourceIterator(gövde, True)``) gezer; kaydı ilk
    isteyen adım hesaplar, ikincisi hazır bulur. Çağrı hedefi → fonksiyon ve veri adresi → dizgi
    çözümlemeleri program boyunca bir kez yapılır (aynı adres için sonuç değişmez).

    Çıktı eski döngülerle bayt bayt aynıdır; iki güvence:

    - **Sıra:** yineleyicinin artan adres sırası Ghidra belgesinde yazılı değil ("forward
      direction"). Ardışık kaynak adresleri ``Address.compareTo`` ile denetlenir; artan değilse o
      fonksiyon eski yürüyüşle (gövdenin bütün adresleri) hesaplanır (``eski_yuruyus`` sayacı).
    - **Bayatlama:** adımlar arasında program değişirse (``Program.getModificationNumber``)
      tablo boşaltılır ve kayıtlar yeniden hesaplanır (``bosaltma`` sayacı).
    """

    def __init__(self, program: Any) -> None:
        self.program = program
        self.fm = program.getFunctionManager()
        self.ref_mgr = program.getReferenceManager()
        self.listing = program.getListing()
        self._kayitlar: dict[str, _BasvuruKaydi] = {}
        self._hedefler: dict[str, tuple[str, str] | None] = {}
        self._veriler: dict[str, Any] = {}
        self._surum = self._degisiklik_no()
        self.eski_yuruyus = 0
        self.bosaltma = 0

    @classmethod
    def kur(cls, program: Any) -> "_BasvuruTablosu | None":
        """Tabloyu kur; başvuru yöneticisinde gereken API yoksa ``None`` (eski döngüler koşar)."""
        try:
            ref_mgr = program.getReferenceManager()
        except AttributeError:
            return None
        for ad in ("getReferenceSourceIterator", "getReferencesFrom", "getReferencesTo",
                   "hasReferencesTo"):
            if not hasattr(ref_mgr, ad):
                return None
        try:
            return cls(program)
        except AttributeError:
            return None

    def _degisiklik_no(self) -> Any:
        oku = getattr(self.program, "getModificationNumber", None)
        return oku() if oku is not None else None

    def tazele(self) -> None:
        """Adım başında: program tablo kurulduktan sonra değiştiyse kayıtları at."""
        simdi = self._degisiklik_no()
        if simdi != self._surum:
            self._kayitlar.clear()
            self._hedefler.clear()
            self._veriler.clear()
            self._surum = simdi
            self.bosaltma += 1

    def kayit(self, func: Any, func_addr: str) -> _BasvuruKaydi:
        k = self._kayitlar.get(func_addr)
        if k is None:
            k = self._kayitlar[func_addr] = self._hesapla(func, func_addr)
        return k

    def _kaynak_adresleri(self, body: Any) -> list:
        """Gövdede başvurusu olan adresler, artan sırada; sıra tutmuyorsa gövdenin bütün adresleri."""
        adresler = []
        onceki = None
        it = self.ref_mgr.getReferenceSourceIterator(body, True)
        while it.hasNext():
            addr = it.next()
            if onceki is not None and onceki.compareTo(addr) >= 0:
                self.eski_yuruyus += 1
                adresler = []
                tum = body.getAddresses(True)
                while tum.hasNext():
                    adresler.append(tum.next())
                return adresler
            onceki = addr
            adresler.append(addr)
        return adresler

    def _cagri_hedefi(self, to_addr: Any) -> tuple[str, str] | None:
        anahtar = str(to_addr)
        try:
            return self._hedefler[anahtar]
        except KeyError:
            pass
        callee = self.fm.getFunctionAt(to_addr)
        if callee is None:
            callee = self.fm.getFunctionContaining(to_addr)
        hedef = None if callee is None else (callee.getName(), str(callee.getEntryPoint()))
        self._hedefler[anahtar] = hedef
        return hedef

    def _dizgi_degeri(self, to_addr: Any, ta: str) -> Any:
        try:
            return self._veriler[ta]
        except KeyError:
            pass
        val: Any = _DIZGI_DEGIL
        data = self.listing.getDefinedDataAt(to_addr)
        if data is not None:
            dtn = str(data.getDataType().getName()).lower()
            if "string" in dtn or "cstring" in dtn:
                val = data.getDefaultValueRepresentation()
                if val and len(val) >= 2 and val[0] in ('"', "'") and val[-1] in ('"', "'"):
                    val = val[1:-1]
        self._veriler[ta] = val
        return val

    def _hesapla(self, func: Any, func_addr: str) -> _BasvuruKaydi:
        ref_mgr = self.ref_mgr
        cagrilanlar: list[tuple[str, str]] = []
        gorulen_c: set = set()
        dizgiler: list[tuple[str, Any]] = []
        gorulen_s: set = set()

        # Giden başvurular: yalnız başvurusu olan adresler, artan sırada.
        for addr in self._kaynak_adresleri(func.getBody()):
            for ref in ref_mgr.getReferencesFrom(addr):
                rt = ref.getReferenceType()
                if rt.isCall():
                    hedef = self._cagri_hedefi(ref.getToAddress())
                    if hedef is not None and hedef[1] != func_addr and hedef[1] not in gorulen_c:
                        gorulen_c.add(hedef[1])
                        cagrilanlar.append(hedef)
                elif rt.isData():
                    to_addr = ref.getToAddress()
                    ta = str(to_addr)
                    if ta not in gorulen_s:
                        val = self._dizgi_degeri(to_addr, ta)
                        if val is not _DIZGI_DEGIL:
                            gorulen_s.add(ta)
                            dizgiler.append((ta, val))

        # Gelen başvurular (giriş adresine): çağrılar arayan listesine, öbürleri PK-8 tablosuna.
        cagiranlar: list[dict[str, Any]] = []
        gorulen_a: set = set()
        giris_cagri_disi: list = []
        for ref in ref_mgr.getReferencesTo(func.getEntryPoint()):
            if ref.getReferenceType().isCall():
                caller = self.fm.getFunctionContaining(ref.getFromAddress())
                if caller is not None:
                    ca = str(caller.getEntryPoint())
                    if ca != func_addr and ca not in gorulen_a:
                        gorulen_a.add(ca)
                        cagiranlar.append({"name": caller.getName(), "address": ca})
            else:
                giris_cagri_disi.append(ref)
        cagiranlar.sort(key=caller_sort_key)  # P16e: getReferencesTo sırası kararsız
        return _BasvuruKaydi(cagrilanlar, cagiranlar, dizgiler, giris_cagri_disi)

    def cagri_dugumu(self, func: Any, func_name: str, func_addr: str,
                     edges: list) -> dict[str, Any]:
        """``_extract_call_graph`` düğümü; fonksiyonun kenarlarını ``edges``'e ekler."""
        k = self.kayit(func, func_addr)
        unique_callees = []
        for ad, ca in k.cagrilanlar:
            unique_callees.append({"name": ad, "address": ca})
            edges.append({
                "from": func_addr,
                "to": ca,
                "from_name": func_name,
                "to_name": ad,
            })
        unique_callers = [dict(c) for c in k.cagiranlar]
        return {
            "name": func_name,
            "address": func_addr,
            "caller_count": len(unique_callers),
            "callee_count": len(unique_callees),
            "callers": unique_callers,
            "callees": unique_callees,
        }

    def xref_kaydi(self, func: Any, func_name: str, func_addr: str,
                   string_ref_counts: dict[str, int]) -> dict[str, Any]:
        """``_extract_xrefs`` fonksiyon kaydı; dizgi adreslerini ``string_ref_counts``'a sayar."""
        k = self.kayit(func, func_addr)
        strings_used = []
        for ta, val in k.dizgiler:
            strings_used.append({"address": ta, "value": val})
            string_ref_counts[ta] = string_ref_counts.get(ta, 0) + 1
        return {
            "name": func_name,
            "address": func_addr,
            "strings_used": strings_used,
            "functions_called": [{"name": ad, "address": ca} for ad, ca in k.cagrilanlar],
            "called_by": [dict(c) for c in k.cagiranlar],
        }


class GhidraHeadless:
    """Ghidra headless analiz wrapper.

    Config'den gelen Ghidra path'ini kullanarak binary dosyalari
    uzerinde headless analiz calistirir.

    PyGhidra mevcut ise dogrudan Python 3 icinden Ghidra API
    kullanilir. Aksi halde CLI fallback kullanilir.

    Args:
        config: Merkezi konfigurasyon (tool path'leri ve timeout'lar).
    """

    def __init__(self, config: Config) -> None:
        self.config = config
        self.runner = SubprocessRunner(config)
        self.analyze_headless = config.tools.ghidra_headless
        warn_if_ghidra_unpinned(Path(self.analyze_headless).parent.parent)

    def analyze(
        self,
        binary_path: Path,
        project_dir: Path,
        project_name: str = "karadul_analysis",
        scripts: list[Path] | None = None,
        timeout: int | None = None,
        output_dir: Path | None = None,
    ) -> dict[str, Any]:
        """Ghidra headless analiz calistir.

        PyGhidra mevcutsa dogrudan API uzerinden, degilse
        analyzeHeadless CLI ile calistirir.

        Args:
            binary_path: Analiz edilecek binary dosyasi.
            project_dir: Ghidra proje dizini.
            project_name: Ghidra proje adi.
            scripts: Calistirilacak Ghidra Python scriptleri (CLI modu icin).
            timeout: Dosya basina analiz zaman asimi (saniye).
            output_dir: Script ciktilarinin yazilacagi dizin.

        Returns:
            dict: {
                "success": bool,
                "scripts_output": dict -- script adi -> JSON icerik,
                "ghidra_log": str,
                "duration_seconds": float,
                "mode": "pyghidra" | "cli",
            }
        """
        binary_path = Path(binary_path).resolve()
        project_dir = Path(project_dir).resolve()
        project_dir.mkdir(parents=True, exist_ok=True)

        effective_timeout = timeout or self.config.timeouts.ghidra
        effective_output = output_dir or (project_dir / "output")
        effective_output.mkdir(parents=True, exist_ok=True)

        # Buyuk binary icin timeout'u otomatik artir
        threshold_bytes = (
            self.config.binary_reconstruction.large_binary_threshold_mb
            * 1024 * 1024
        )
        if binary_path.stat().st_size > threshold_bytes:
            multiplier = self.config.binary_reconstruction.large_binary_timeout_multiplier
            effective_timeout = int(effective_timeout * multiplier)
            logger.info(
                "Buyuk binary tespit edildi (%.0f MB): timeout %.0fx artirildi -> %ds",
                binary_path.stat().st_size / (1024 * 1024),
                multiplier,
                effective_timeout,
            )

        if _check_pyghidra():
            return self._analyze_pyghidra(
                binary_path, project_dir, project_name,
                effective_timeout, effective_output,
            )
        else:
            return self._analyze_cli(
                binary_path, project_dir, project_name,
                scripts, effective_timeout, effective_output,
            )

    def _analyze_pyghidra(
        self,
        binary_path: Path,
        project_dir: Path,
        project_name: str,
        timeout: int,
        output_dir: Path,
    ) -> dict[str, Any]:
        """PyGhidra API ile analiz.

        pyghidra.open_program ile Ghidra JVM icinde programi acar
        ve dogrudan Ghidra API'sini kullanarak analiz yapar.
        """
        import pyghidra

        ghidra_install = self.analyze_headless.parent.parent
        start = time.monotonic()
        # HZ-1: adım süreleri (yalnız ölçüm; adımların gövdesi ve çıktısı değişmez).
        decompile_parcalari: dict[str, Any] | None = None
        log_lines: list[str] = []
        scripts_output: dict[str, Any] = {}
        # Adım adı -> hata metni. Bir adımın düşmesi analizi durdurmaz ama sessiz de kalmaz:
        # sonuç sözlüğüyle çağırana gider, ``static`` aşaması istatistiğe ve
        # ``static/ghidra_status.json``'a yazar (GHIDRA-09).
        step_errors: dict[str, str] = {}
        # ÖL-1: adım saati ilerleme olaylarını da üretir; adım sürerken eklenen hata ``kismi``.
        saat = _AdimSaati(step_errors)

        def _step_failed(step: str, exc: BaseException, level: str = "WARN") -> None:
            msg = "%s: %s" % (type(exc).__name__, exc)
            step_errors[step] = msg
            log_lines.append("%s: %s: %s" % (level, step, msg))
            logger.warning("Ghidra adimi basarisiz (%s): %s", step, msg)

        # ÖL-2: döküm adımlarının bütçesi (``timeouts.ghidra_adim``; 0 = yok) ve adım içi olay
        # aralığı (``analysis.bekci_aralik_sn``; 0 = olay yok). Denetçi adımın başlangıcını
        # ``saat``ten alır (tek zamanlayıcı); kısmi olay ``saat.bitti``'de gerçek sayaçlarla.
        adim_butcesi = _ayar_sn(self.config, "timeouts", "ghidra_adim")
        olay_araligi = _ayar_sn(self.config, "analysis", "bekci_aralik_sn")

        def _denetci(adim: str, butce: float | None = None,
                     toplam: int | None = None) -> _AdimDenetcisi:
            return saat.denetci(adim, adim_butcesi if butce is None else butce, olay_araligi,
                                toplam)

        def _fonksiyon_toplami() -> int | None:
            # ``fm.getFunctions(True)`` yinelemesinin uzunluğu = ``functions`` adımının ``total``ı.
            toplam = (scripts_output.get("functions") or {}).get("total")
            return int(toplam) if isinstance(toplam, int) else None

        def _butce_doldu(step: str, den: _AdimDenetcisi) -> None:
            if den.doldu:
                step_errors[step] = den.neden()
                log_lines.append("WARN: %s: %s" % (step, step_errors[step]))
                logger.warning("Ghidra adımı bütçeyi aştı (%s): %s", step, step_errors[step])

        logger.info("Ghidra (PyGhidra) baslatiliyor: %s", binary_path.name)

        analysis_info: dict[str, Any] = {"status": "not_run", "timeout_s": int(timeout)}

        try:
            saat.basla(ADIM_JVM)
            _ensure_pyghidra_started(
                ghidra_install,
                heap_mb=getattr(getattr(self.config, "analysis", None), "ghidra_max_heap_mb", None),
            )
            saat.bitti(ADIM_JVM)

            # P16c (GHIDRA-06 kalanı): otomatik analiz artık süreli. open_program(analyze=True)
            # süresizdi; analiz Karadul tarafında TimeoutTaskMonitor ile koşar.
            saat.basla(ADIM_ICE_AKTARMA)
            with pyghidra.open_program(
                binary_path=str(binary_path),
                project_location=str(project_dir),
                project_name=project_name,
                analyze=False,
            ) as flat_api:
                saat.bitti(ADIM_ICE_AKTARMA)
                program = flat_api.getCurrentProgram()
                log_lines.append("Program acildi: %s" % program.getName())

                saat.basla(ADIM_OTOMATIK_ANALIZ)
                try:
                    analysis_info = self._run_auto_analysis(program, timeout)
                except Exception as exc:
                    analysis_info = {"status": "failed", "timeout_s": int(timeout),
                                     "error": "%s: %s" % (type(exc).__name__, exc)}
                    _step_failed("analysis", exc)
                if analysis_info.get("status") == "timeout":
                    msg = (
                        "zaman aşımı: Ghidra otomatik analizi %d sn'de durduruldu; "
                        "analiz kısmi (sonraki adımlar kısmi programla koştu)"
                        % int(timeout)
                    )
                    if analysis_info.get("takilmalar"):  # ÖL-1: bekçi durdurdu
                        msg = _takilma_metni(analysis_info)
                    step_errors["analysis"] = msg
                    log_lines.append("WARN: analysis: %s" % msg)
                    logger.warning("Ghidra otomatik analizi zaman aşımı (%d sn): kısmi", int(timeout))
                elif analysis_info.get("status") == ANALIZ_COZUMLEYICI_KAPATILDI:
                    msg = _takilma_metni(analysis_info)
                    step_errors["analysis"] = msg
                    log_lines.append("WARN: analysis: %s" % msg)
                    logger.warning("Ghidra otomatik analizi: %s", msg)
                elif analysis_info.get("status") == "ok":
                    log_lines.append(
                        "Otomatik analiz: %.1f sn" % float(analysis_info.get("duration_s", 0.0))
                    )
                # ÖL-1: bitiş olayı adım hatasını görsün diye durum işlendikten sonra.
                saat.bitti(ADIM_OTOMATIK_ANALIZ)

                # GDT Data Type Archive yukleme
                gdt_paths = self.config.binary_reconstruction.ghidra_data_type_archives
                if gdt_paths:
                    saat.basla(ADIM_GDT)
                    loaded = self._load_gdt_archives_pyghidra(
                        program, ghidra_install, gdt_paths,
                    )
                    saat.bitti(ADIM_GDT)
                    log_lines.append("GDT arsivleri: %d yuklendi" % loaded)
                else:
                    _ilerleme(ADIM_GDT, OLAY_ATLANDI, neden="ayar boş")

                # PDB otomatik yukleme (Windows PE icin)
                if self.config.binary_reconstruction.pdb_auto_load:
                    saat.basla(ADIM_PDB)
                    try:
                        pdb_loaded = self._load_pdb_if_available(
                            program, binary_path,
                        )
                        if pdb_loaded:
                            log_lines.append(
                                "PDB yuklendi: tip/isim recovery iyilestirildi"
                            )
                    except Exception as exc:
                        _step_failed("pdb", exc)
                    saat.bitti(ADIM_PDB)
                else:
                    _ilerleme(ADIM_PDB, OLAY_ATLANDI, neden="ayar kapalı")

                # 1. Fonksiyon listesi
                saat.basla(ADIM_FUNCTIONS)
                try:
                    func_data = self._extract_functions(program)
                    scripts_output["functions"] = func_data
                    self._save_output(output_dir, "functions.json", func_data)
                    log_lines.append(
                        "Fonksiyonlar: %d" % func_data["total"]
                    )
                except Exception as exc:
                    _step_failed("functions", exc, "FAIL")
                saat.bitti(ADIM_FUNCTIONS)

                # 2. String extraction (basarisizlik analizi durdurmaz)
                saat.basla(ADIM_STRINGS)
                try:
                    den = _denetci(ADIM_STRINGS)
                    str_data = self._extract_strings(program, denetci=den)
                    scripts_output["strings"] = str_data
                    self._save_output(output_dir, "strings.json", str_data)
                    log_lines.append("String'ler: %d" % str_data["total"])
                    _butce_doldu("strings", den)
                except Exception as exc:
                    _step_failed("strings", exc)
                saat.bitti(ADIM_STRINGS)

                # HZ-4a: ``analysis.dokum_tek_gecis`` açıkken çağrı grafiği ve xref dökümü ortak
                # başvuru tablosundan kurulur (CFG dökümü değişmedi: ölçümde Python tarafında kazanç
                # yolu çıkmadı). Kapalıyken (ya da programın başvuru yöneticisinde gereken API
                # yoksa) bugünkü döngüler koşar ve işlevlere ek argüman verilmez. Çıktı iki yolda
                # aynıdır.
                basvuru_tablosu = None
                if bool(getattr(getattr(self.config, "analysis", None),
                                "dokum_tek_gecis", False)):
                    basvuru_tablosu = _BasvuruTablosu.kur(program)
                    if basvuru_tablosu is None:
                        logger.warning("Döküm tek geçişi kurulamadı (başvuru yöneticisinde "
                                       "gereken API yok); eski döngüler koşuyor")
                tek_gecis = basvuru_tablosu is not None
                logger.info("Döküm kipi: %s", "tek geçiş" if tek_gecis else "eski döngüler")

                # 3. Call graph
                saat.basla(ADIM_CALL_GRAPH)
                try:
                    den = _denetci(ADIM_CALL_GRAPH, toplam=_fonksiyon_toplami())
                    cg_data = self._extract_call_graph(
                        program, denetci=den,
                        **({"tablo": basvuru_tablosu} if tek_gecis else {}))
                    scripts_output["call_graph"] = cg_data
                    self._save_output(output_dir, "call_graph.json", cg_data)
                    log_lines.append(
                        "Call graph: %d node, %d edge" % (
                            cg_data["total_functions"],
                            cg_data["total_edges"],
                        )
                    )
                    _butce_doldu("call_graph", den)
                except Exception as exc:
                    _step_failed("call_graph", exc, "FAIL")
                saat.bitti(ADIM_CALL_GRAPH)

                # 4. Decompilation (basarisizlik analizi durdurmaz)
                saat.basla(ADIM_DECOMPILE)
                try:
                    # v1.5: JSONL pcode enabled ise decompile sirasinda selective pcode topla
                    _br_cfg = self.config.binary_reconstruction
                    _pcode_sel = None
                    if _br_cfg.enable_pcode_extraction and getattr(_br_cfg, 'pcode_format', 'jsonl') == 'jsonl':
                        _pcode_sel = set(getattr(_br_cfg, 'pcode_selective_ops', None) or [])
                        if not _pcode_sel:
                            _pcode_sel = None  # Bos set ise pcode toplama

                    decomp_data = self._decompile_functions(
                        program, output_dir, timeout,
                        selective_ops=_pcode_sel,
                        func_timeout=int(
                            self.config.binary_reconstruction.max_decompile_timeout_per_func
                        ),
                    )
                    # _all_functions buyuk olabilir, decompiled.json'a yazmadan once ayir
                    _all_funcs_for_pcode = decomp_data.pop("_all_functions", None)
                    # HZ-1: parça süre özeti decompiled.json'a girmez (çıktı aynı kalır);
                    # ghidra_status.json'a gider.
                    decompile_parcalari = decomp_data.pop("_decompile_parcalari", None)
                    scripts_output["decompiled"] = decomp_data
                    self._save_output(output_dir, "decompiled.json", decomp_data)
                    log_lines.append(
                        "Decompile: %d/%d basarili" % (
                            decomp_data["success"],
                            decomp_data["total_attempted"],
                        )
                    )
                    # ÖL-1: bitiş olayında işlenen (başarılı + başarısız) / toplam.
                    dec_sayac = {
                        "islenen": int(decomp_data.get("success") or 0)
                        + int(decomp_data.get("failed") or 0),
                        "toplam": decomp_data.get("total_attempted"),
                    }
                except Exception as exc:
                    _all_funcs_for_pcode = None
                    dec_sayac = {}
                    _step_failed("decompile", exc, "FAIL")
                saat.bitti(ADIM_DECOMPILE, **dec_sayac)

                # 5. Type recovery (basarisizlik analizi durdurmaz)
                saat.basla(ADIM_TYPES)
                try:
                    den = _denetci(ADIM_TYPES)
                    type_data = self._extract_types(program, denetci=den)
                    scripts_output["types"] = type_data
                    self._save_output(output_dir, "types.json", type_data)
                    log_lines.append(
                        "Types: %d structs, %d enums, %d typedefs" % (
                            type_data["total_structures"],
                            type_data["total_enums"],
                            type_data["total_typedefs"],
                        )
                    )
                    _butce_doldu("types", den)
                except Exception as exc:
                    _step_failed("types", exc)
                saat.bitti(ADIM_TYPES)

                # 6. Cross-reference analysis (basarisizlik analizi durdurmaz)
                saat.basla(ADIM_XREF)
                try:
                    den = _denetci(ADIM_XREF, toplam=_fonksiyon_toplami())
                    xref_data = self._extract_xrefs(
                        program, denetci=den,
                        **({"tablo": basvuru_tablosu, "tek_gecis": True} if tek_gecis else {}))
                    scripts_output["xrefs"] = xref_data
                    self._save_output(output_dir, "xrefs.json", xref_data)
                    log_lines.append(
                        "Xrefs: %d functions, %d strings, %d globals" % (
                            xref_data["statistics"]["total_functions"],
                            xref_data["statistics"]["total_strings_with_xrefs"],
                            xref_data["statistics"]["total_globals_with_xrefs"],
                        )
                    )
                    _butce_doldu("xrefs", den)
                except Exception as exc:
                    _step_failed("xrefs", exc)
                basvuru_tablosu = None  # HZ-4a: tablo xref'ten sonra gerekmez (bellek)
                saat.bitti(ADIM_XREF)

                # 8. P-Code (v1.5: decompile icinde toplandiysa JSONL yaz)
                saat.basla(ADIM_PCODE)
                den = None
                try:
                    _br_cfg2 = getattr(getattr(self, 'config', None), 'binary_reconstruction', None)
                    _pcode_enabled = getattr(_br_cfg2, 'enable_pcode_extraction', False) if _br_cfg2 else False
                    _pcode_format = getattr(_br_cfg2, 'pcode_format', 'jsonl') if _br_cfg2 else 'jsonl'

                    if _pcode_enabled and _pcode_format == "jsonl":
                        # v1.5: decompile_results'tan JSONL yaz
                        _jsonl_input = {"functions": _all_funcs_for_pcode or []}
                        pcode_data = self._write_pcode_jsonl(output_dir, _jsonl_input)
                        # Bellek temizligi: buyuk listeyi serbest birak
                        _all_funcs_for_pcode = None
                    elif _pcode_enabled and _pcode_format == "legacy":
                        # Eski davranis: tam extraction
                        den = _denetci(ADIM_PCODE, toplam=_fonksiyon_toplami())
                        pcode_data = self._extract_pcode(program, denetci=den)
                    else:
                        # stats_only
                        den = _denetci(ADIM_PCODE)
                        pcode_data = self._extract_pcode_stats_only(program, denetci=den)

                    scripts_output["pcode"] = pcode_data
                    self._save_output(output_dir, "pcode.json", pcode_data)
                    log_lines.append(
                        "P-Code: %d fonksiyon, %d op%s" % (
                            pcode_data["total_functions"],
                            pcode_data.get("total_pcode_ops", 0),
                            " (JSONL)" if _pcode_format == "jsonl" and _pcode_enabled else
                            " (stats-only)" if pcode_data.get("mode") == "stats_only" else "",
                        )
                    )
                    if den is not None:
                        _butce_doldu("pcode", den)
                except Exception as exc:
                    _step_failed("pcode", exc)
                saat.bitti(ADIM_PCODE)

                # 9. CFG extraction (basarisizlik analizi durdurmaz)
                saat.basla(ADIM_CFG)
                try:
                    den = _denetci(ADIM_CFG, toplam=_fonksiyon_toplami())
                    cfg_data = self._extract_cfg(program, denetci=den)
                    scripts_output["cfg"] = cfg_data
                    self._save_output(output_dir, "cfg.json", cfg_data)
                    log_lines.append(
                        "CFG: %d fonksiyon, %d blok, %d edge" % (
                            cfg_data["total_functions"],
                            cfg_data["total_blocks"],
                            cfg_data["total_edges"],
                        )
                    )
                    _butce_doldu("cfg", den)
                except Exception as exc:
                    _step_failed("cfg", exc)
                saat.bitti(ADIM_CFG)

                # 11. FunctionID matches (basarisizlik analizi durdurmaz)
                if self.config.binary_reconstruction.enable_function_id:
                    saat.basla(ADIM_FUNCTION_ID)
                    try:
                        den = _denetci(ADIM_FUNCTION_ID, toplam=_fonksiyon_toplami())
                        fid_data = self._extract_function_id_matches(program, denetci=den)
                        scripts_output["function_id"] = fid_data
                        self._save_output(
                            output_dir, "function_id.json", fid_data,
                        )
                        log_lines.append(
                            "FunctionID: %d esleme"
                            % fid_data["total_matches"]
                        )
                        _butce_doldu("function_id", den)
                    except Exception as exc:
                        _step_failed("function_id", exc)
                    saat.bitti(ADIM_FUNCTION_ID)
                else:
                    _ilerleme(ADIM_FUNCTION_ID, OLAY_ATLANDI, neden="ayar kapalı")

                # 11.5 BSim ingest + sorgu (opsiyonel)
                if self.config.bsim.enabled:
                    # HZ-1: ingest = depo açılışı + hash'leme; query = sorgu + shadow dökümü +
                    # depo kapanışı. Düşen alt adımın süresi düştüğü ana kadar yazılır.
                    saat.basla(ADIM_BSIM_INGEST)
                    try:
                        from karadul.ghidra.bsim import BSimDatabase
                        bsim_db = BSimDatabase(self.config)
                        # ÖL-2: ingest bütçesi = ``bsim.ingest_butcesi_sn`` ile adım bütçesinin
                        # küçüğü (0 = yok); denetçi BSim'in tarama döngüsünde (öznitelikle).
                        ingest_den = _denetci(ADIM_BSIM_INGEST, butce=_en_kucuk_butce(
                            adim_butcesi, _ayar_sn(self.config, "bsim", "ingest_butcesi_sn")),
                            toplam=(scripts_output.get("functions") or {}).get(
                                "program_function_count"))
                        bsim_db.denetci = ingest_den
                        ingested = bsim_db.ingest_program(program, self.config.bsim.default_database)
                        # P16b (GHIDRA-01): kip ve durum günlükte ve bsim_matches.json'da;
                        # kilit / meşgul durumunda BSim atlanır, sessizce lite'a düşülmez.
                        log_lines.append(
                            "BSim: %d fonksiyon hash'lendi (kip: %s, durum: %s)"
                            % (ingested, bsim_db.status.get("mode"), bsim_db.status.get("status"))
                        )
                        _butce_doldu("bsim_ingest", ingest_den)
                        saat.bitti(ADIM_BSIM_INGEST)
                        if self.config.bsim.auto_query:
                            saat.basla(ADIM_BSIM_QUERY)
                            # ÖL-2: sorgu da adım bütçesiyle sınırlı (parça sınırında denetim).
                            sorgu_den = _denetci(ADIM_BSIM_QUERY)
                            bsim_db.denetci = sorgu_den
                            bsim_result = bsim_db.query_all_functions(
                                program, self.config.bsim.min_similarity,
                                db_name=self.config.bsim.default_database,
                            )
                            # Eski beş alan + aday kaynağı (GHIDRA-02) + bsim_mode /
                            # bsim_status / bsim_detail (GHIDRA-01).
                            bsim_data = bsim_result.to_payload()
                            scripts_output["bsim"] = bsim_data
                            self._save_output(output_dir, "bsim_matches.json", bsim_data)
                            log_lines.append(
                                "BSim query: %d esleme (kip: %s, durum: %s)"
                                % (bsim_result.total_matches, bsim_data.get("bsim_mode"),
                                   bsim_data.get("bsim_status"))
                            )
                            if (bsim_data.get("bsim_detail") or {}).get("sorgu_atlandi"):
                                # ÖL-2: boş depoda sorgu koşmadı (bilinen sonuç; kısmi değil).
                                _ilerleme(ADIM_BSIM_QUERY, OLAY_ATLANDI,
                                          neden=bsim_data["bsim_detail"].get("neden"))
                            _butce_doldu("bsim_query", sorgu_den)
                            # v1.11.0 Hafta 2: legacy yolda da shadow dump
                            # uretilsin ki use_step_registry=False olan
                            # kosumlarda bsim_shadow.json eksik kalmasin
                            # (BSim wiring bulgusu #1, ADR 0008 sonrasi).
                            try:
                                from karadul.ghidra._bsim_shadow import (
                                    build_shadow_payload,
                                )
                                shadow_mode = bool(
                                    getattr(self.config.bsim, "shadow_mode", True)
                                )
                                shadow_payload = build_shadow_payload(
                                    raw_data=bsim_data,
                                    shadow_mode=shadow_mode,
                                )
                                self._save_output(
                                    output_dir,
                                    "bsim_shadow.json",
                                    shadow_payload,
                                )
                                log_lines.append(
                                    "BSim shadow dump: %d fonksiyon"
                                    % len(shadow_payload["matches"])
                                )
                            except Exception as exc:  # pragma: no cover
                                logger.warning(
                                    "BSim shadow dump basarisiz (legacy yol): %s",
                                    exc,
                                )
                        bsim_db.close()
                    except Exception as exc:
                        _step_failed("bsim", exc)
                    saat.bitti(ADIM_BSIM_INGEST)
                    saat.bitti(ADIM_BSIM_QUERY)
                else:
                    _ilerleme(ADIM_BSIM_INGEST, OLAY_ATLANDI, neden="ayar kapalı")

                # 10. Program bilgileri + birlesik sonuc
                saat.basla(ADIM_COMBINED)
                try:
                    prog_info = self._get_program_info(program)
                    combined = {
                        "summary": {
                            "program": prog_info,
                            # "Kurtarılan fonksiyon" = programın kendi fonksiyonları; içe aktarım
                            # taslakları (thunk) ayrı sayılır (GHIDRA-10).
                            "function_count": scripts_output.get("functions", {}).get("program_function_count", 0),
                            "function_total": scripts_output.get("functions", {}).get("total", 0),
                            "thunk_count": scripts_output.get("functions", {}).get("thunk_count", 0),
                            "external_count": scripts_output.get("functions", {}).get("external_count", 0),
                            "string_count": scripts_output.get("strings", {}).get("total", 0),
                            "call_graph_nodes": scripts_output.get("call_graph", {}).get("total_functions", 0),
                            "call_graph_edges": scripts_output.get("call_graph", {}).get("total_edges", 0),
                            "decompiled_success": scripts_output.get("decompiled", {}).get("success", 0),
                            "decompiled_failed": scripts_output.get("decompiled", {}).get("failed", 0),
                            "type_count": scripts_output.get("types", {}).get("total_types", 0),
                            "xref_functions": scripts_output.get("xrefs", {}).get("statistics", {}).get("total_functions", 0),
                            "pcode_functions": scripts_output.get("pcode", {}).get("total_functions", 0),
                            "cfg_functions": scripts_output.get("cfg", {}).get("total_functions", 0),
                            "cfg_blocks": scripts_output.get("cfg", {}).get("total_blocks", 0),
                            "function_id_matches": scripts_output.get("function_id", {}).get("total_matches", 0),
                            "bsim_matches": scripts_output.get("bsim", {}).get("total_matches", 0),
                        },
                        "program_info": prog_info,
                    }
                    scripts_output["combined_results"] = combined
                    self._save_output(output_dir, "combined_results.json", combined)
                except Exception as exc:
                    _step_failed("combined_results", exc, "FAIL")
                saat.bitti(ADIM_COMBINED)
                # HZ-1: ``open_program`` bağlamının çıkışı (programın kaydı, projenin kapanışı).
                saat.basla(ADIM_KAPATMA)
            saat.bitti(ADIM_KAPATMA)

        except Exception as exc:
            _step_failed("fatal", exc, "FATAL")
            logger.error("PyGhidra analiz hatasi: %s", step_errors["fatal"])

        duration = time.monotonic() - start
        success, error = self._judge_outcome(scripts_output, step_errors)
        if error:
            log_lines.append("SONUC: basarisiz: %s" % error)

        sonuc: dict[str, Any] = {
            "success": success,
            "error": error,
            "step_errors": step_errors,
            "scripts_output": scripts_output,
            "ghidra_log": "\n".join(log_lines),
            "duration_seconds": round(duration, 3),
            "mode": "pyghidra",
            # PyGhidra yolunda süreç yok, çıkış kodu da yok (eski kod 0/1 uyduruyordu).
            "returncode": None,
            # P16c: otomatik analizin durumu (ok / timeout / already_analyzed / failed /
            # not_run), süresi, sınırı ve Ghidra'nın çözümleyici başına süreleri.
            "analysis": analysis_info,
            # HZ-1: biten köprü adımlarının süresi (``GHIDRA_ADIMLARI`` adlarıyla, sn).
            "adim_sureleri": saat.sozluk(),
        }
        # HZ-1: decompile parçalarının süre özeti; decompile hiç sonuç vermediyse alan yok.
        if decompile_parcalari is not None:
            sonuc["decompile_parcalari"] = decompile_parcalari
        return sonuc

    @staticmethod
    def _analyzer_task_times(program) -> dict[str, float]:
        """``AutoAnalysisManager.getTaskTimesString()`` → {çözümleyici: sn} (toplam satırı hariç)."""
        from ghidra.app.plugin.core.analysis import AutoAnalysisManager

        text = str(AutoAnalysisManager.getAnalysisManager(program).getTaskTimesString())
        times: dict[str, float] = {}
        for line in text.splitlines():
            m = _TASK_TIME_LINE.match(line)
            if m and "total" not in m.group(1).lower():
                times[m.group(1).strip()] = float(m.group(2))
        return times

    @staticmethod
    def _disable_analyzers(program, names: list[str]) -> dict[str, bool]:
        """Verilen Ghidra çözümleyicilerini analizden önce kapat (P16c kalem 2; ayar).

        ``analysis.ghidra_disabled_analyzers`` (config yaması; öntanım boş = Ghidra'nın
        öntanımı). Dönüş: ad -> seçenek programda var mıydı (yanlış yazılan ad görünür kalsın).
        Kapatmak decompile çıktısını değiştirebilir: ölçüm `P16c.md` kalem 2.
        """
        from ghidra.app.plugin.core.analysis import AutoAnalysisManager
        from ghidra.program.model.listing import Program

        found: dict[str, bool] = {}
        tx = program.startTransaction("karadul: kapali cozumleyiciler")
        try:
            opts = program.getOptions(Program.ANALYSIS_PROPERTIES)
            for name in names:
                found[name] = bool(opts.contains(name))
                if found[name]:
                    opts.setBoolean(name, False)
        finally:
            program.endTransaction(tx, True)
        AutoAnalysisManager.getAnalysisManager(program).initializeOptions()
        unknown = [n for n, ok in found.items() if not ok]
        if unknown:
            logger.warning("Ghidra'da bulunmayan çözümleyici adı (kapatılamadı): %s", unknown)
        return found

    @staticmethod
    def _cozumleyici_okuyucu(program):
        """ÖL-1: o an tepedeki otomatik analiz görevini okuyan işlev (fizibilite: yol a).

        ``AutoAnalysisManager.activeTask`` özel alanı (Java yansıması) → görev sarmalayıcısı;
        sarmalayıcının ``task`` alanı ``AnalysisTask`` ise adı çözümleyicinin seçenek adıdır
        (``AnalysisTask`` kurucusu ``analyzer.getName()``; ``_disable_analyzers`` bu adı kullanır).
        Ghidra 12.1.2'nin iç alanlarına bağlıdır: alan yoksa istisna çağırana gider, bekçi
        kurulmaz. Okuma yalnız alan okur; Java'ya geri çağrı (``JProxy``) yok.
        """
        from ghidra.app.plugin.core.analysis import AnalysisTask, AutoAnalysisManager

        mgr = AutoAnalysisManager.getAnalysisManager(program)
        etkin = mgr.getClass().getDeclaredField("activeTask")
        etkin.setAccessible(True)
        gorev_alani: list = []

        def oku():
            sarmal = etkin.get(mgr)
            if sarmal is None:
                return None
            if not gorev_alani:
                alan = sarmal.getClass().getDeclaredField("task")
                alan.setAccessible(True)
                gorev_alani.append(alan)
            gorev = gorev_alani[0].get(sarmal)
            if gorev is None:
                return None
            return sarmal, (str(gorev.getName()) if isinstance(gorev, AnalysisTask) else None)

        return oku

    def _bekci_ayari(self) -> tuple[float, float]:
        """ÖL-1: (takılma eşiği sn, okuma aralığı sn); biri 0 ise bekçi kapalı."""
        analysis = getattr(self.config, "analysis", None)
        esik = getattr(analysis, "cozumleyici_takilma_sn", 0) or 0
        aralik = getattr(analysis, "bekci_aralik_sn", 0) or 0
        return float(esik), float(aralik)

    def _run_auto_analysis(self, program, timeout_s: int) -> dict[str, Any]:
        """Ghidra otomatik analizini süre sınırıyla koş (P16c, GHIDRA-06 kalanı).

        pyghidra 3.0.0 ``core._analyze_program`` ile aynı adımlar (``shouldAskToAnalyze``,
        ``acquireBundleHostReference``, ``analyzeAll``, ``markProgramAnalyzed``); tek fark
        ``FlatProgramAPI``'nin izleyicisi ``TimeoutTaskMonitor``: süre dolunca analiz
        iptal edilir ve sonuç ``status = "timeout"`` olur (program kısmi çözümlenmiş
        kalır, ``markProgramAnalyzed`` çağrılmaz). Öntanımlı sınırla çıktı eskisiyle aynı.

        ÖL-1: ``analysis.cozumleyici_takilma_sn`` > 0 iken analiz boyunca ``_CozumleyiciBekcisi``
        koşar. Aynı çözümleyici eşik kadar tepede kalırsa izleyici iptal edilir, çözümleyici
        kapatılır (``_disable_analyzers``) ve ``analyzeAll`` kalan süre bütçesiyle BİR kez daha
        çağrılır; ikinci tur biterse ``status = "ok_cozumleyici_kapatildi"``. İkinci turda yeniden
        takılma, ikinci tur zaman aşımı, kapatılamayan ad ya da bitmiş bütçe → ``"timeout"``
        (bugünkü kısmi yol; yeniden deneme yok). Bekçi kapalıyken davranış bugünküyle aynı.
        """
        from java.util.concurrent import TimeUnit
        from ghidra.app.script import GhidraScriptUtil
        from ghidra.program.flatapi import FlatProgramAPI
        from ghidra.program.util import GhidraProgramUtilities
        from ghidra.util.task import TimeoutTaskMonitor

        info: dict[str, Any] = {"status": "not_run", "timeout_s": int(timeout_s)}
        if not GhidraProgramUtilities.shouldAskToAnalyze(program):
            info["status"] = "already_analyzed"
            return info
        disabled = list(getattr(getattr(self.config, "analysis", None),
                                "ghidra_disabled_analyzers", None) or [])
        if disabled:
            info["disabled_analyzers"] = self._disable_analyzers(program, disabled)
        esik_sn, aralik_sn = self._bekci_ayari()
        okuyucu = None
        if esik_sn > 0 and aralik_sn > 0:
            try:
                okuyucu = self._cozumleyici_okuyucu(program)
            except Exception as exc:  # noqa: BLE001
                info["bekci_hatasi"] = "%s: %s" % (type(exc).__name__, exc)
                logger.warning("Çözümleyici bekçisi kurulamadı (%s); otomatik analiz bekçisiz",
                               info["bekci_hatasi"])
        butce_s = int(timeout_s)
        takilmalar: list[dict[str, Any]] = []
        bekci_kaydi = {"esik_sn": esik_sn, "aralik_sn": aralik_sn, "okuma": 0, "okunamayan": 0}
        durma_nedeni: str | None = None
        t0 = time.monotonic()
        tur = 1
        while True:
            monitor = TimeoutTaskMonitor.timeoutIn(max(1, int(timeout_s)), TimeUnit.SECONDS)
            api = FlatProgramAPI(program, monitor)
            bekci = None
            if okuyucu is not None:
                bekci = _CozumleyiciBekcisi(okuyucu, monitor.cancel, esik_sn, aralik_sn, t0)
            GhidraScriptUtil.acquireBundleHostReference()
            try:
                if bekci is not None:
                    bekci.baslat()
                api.analyzeAll(program)
                timed_out = bool(monitor.didTimeout())
                takildi = bekci is not None and bekci.durdur()
                if not timed_out:
                    if not takildi:
                        GhidraProgramUtilities.markProgramAnalyzed(program)
            finally:
                if bekci is not None:
                    bekci.durdur()
                    bekci_kaydi["okuma"] += bekci.okuma
                    bekci_kaydi["okunamayan"] += bekci.okunamayan
                    if bekci.son_hata:
                        bekci_kaydi["son_hata"] = bekci.son_hata
                GhidraScriptUtil.releaseBundleHostReference()
                try:
                    monitor.finished()
                except Exception:  # noqa: BLE001
                    logger.debug("TimeoutTaskMonitor.finished basarisiz", exc_info=True)
            if not takildi:
                break
            takilmalar.append({"tur": tur, "cozumleyici": bekci.takilan,
                               "tepede_sn": bekci.tepede_sn,
                               "an_sn": round(time.monotonic() - t0, 3)})
            if tur == 2:
                durma_nedeni = "ikinci turda yeniden takıldı (%s); yeniden deneme yok" % (
                    bekci.takilan,)
                break
            info["ilk_tur"] = {"duration_s": round(time.monotonic() - t0, 3)}
            try:
                info["ilk_tur"]["analyzer_times"] = self._analyzer_task_times(program)
            except Exception as exc:  # noqa: BLE001
                info["ilk_tur"]["analyzer_times_error"] = "%s: %s" % (type(exc).__name__, exc)
            kapatildi = self._disable_analyzers(program, [bekci.takilan])
            info["kapatilan_cozumleyiciler"] = kapatildi
            # İkinci tur kalan süre bütçesiyle (ÖL-1 adım 3): izleyici aynı satırdan kurulur.
            timeout_s = butce_s - int(time.monotonic() - t0)
            if not kapatildi.get(bekci.takilan):
                durma_nedeni = "çözümleyici seçeneği programda yok, kapatılamadı"
                break
            if timeout_s < 1:
                durma_nedeni = "süre bütçesi (%d sn) bitti, ikinci tur koşulmadı" % butce_s
                break
            tur = 2
        info["duration_s"] = round(time.monotonic() - t0, 3)
        info["status"] = "timeout" if timed_out else "ok"
        if okuyucu is not None:
            info["bekci"] = bekci_kaydi
        if takilmalar:
            info["takilan_cozumleyici"] = takilmalar[0]["cozumleyici"]
            info["takilmalar"] = takilmalar
            if durma_nedeni is not None:
                info["status"] = "timeout"
                info["neden"] = durma_nedeni
            elif timed_out:
                info["neden"] = "ikinci tur süre sınırına (%d sn) ulaştı" % butce_s
            else:
                info["status"] = ANALIZ_COZUMLEYICI_KAPATILDI
        try:
            info["analyzer_times"] = self._analyzer_task_times(program)
        except Exception as exc:  # noqa: BLE001
            info["analyzer_times_error"] = "%s: %s" % (type(exc).__name__, exc)
        return info

    @staticmethod
    def _judge_outcome(
        scripts_output: dict[str, Any], step_errors: dict[str, str],
    ) -> tuple[bool, str | None]:
        """Ghidra koşusu başarılı mı; değilse neden (GHIDRA-09).

        Başarı = Ghidra en az bir fonksiyon döndürdü VE en az biri decompile edildi. Ürünün
        aşağı akışı decompile edilmiş C'ye dayanır; fonksiyon listesi dolu ama hiçbir fonksiyon
        decompile edilmemişse çıktı "başarılı görünen boş çıktı" olurdu. Öbür adımların
        (dizgi, tip, xref, CFG, BSim …) düşmesi başarıyı bozmaz ama ``step_errors``'ta kalır.
        """
        if "fatal" in step_errors:
            return False, "Ghidra analizi düştü: %s" % step_errors["fatal"]
        if "functions" in step_errors:
            return False, "fonksiyon listesi çıkarılamadı: %s" % step_errors["functions"]
        funcs = scripts_output.get("functions") or {}
        if not funcs.get("total"):
            return False, "Ghidra hiç fonksiyon bulmadı (fonksiyon listesi boş)"
        if "decompile" in step_errors:
            return False, "decompile düştü: %s" % step_errors["decompile"]
        dec = scripts_output.get("decompiled") or {}
        if not dec.get("success"):
            first = next(
                (f.get("error") for f in dec.get("functions") or [] if f.get("error")), None,
            )
            return False, (
                "decompile hiçbir fonksiyonda başarılı olmadı (%d denendi%s)"
                % (dec.get("total_attempted") or 0, "; ilk hata: %s" % first if first else "")
            )
        return True, None

    # ------------------------------------------------------------------
    # PyGhidra analiz metodlari
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_functions(program) -> dict[str, Any]:
        """Tum fonksiyonlari meta verileriyle cikar."""
        fm = program.getFunctionManager()
        functions = []

        for func in fm.getFunctions(True):
            entry = {
                "name": func.getName(),
                "address": str(func.getEntryPoint()),
                "size": int(func.getBody().getNumAddresses()),
                "param_count": func.getParameterCount(),
                "return_type": str(func.getReturnType()),
                "is_thunk": func.isThunk(),
                "calling_convention": str(func.getCallingConventionName()),
                "is_external": func.isExternal(),
            }

            params = []
            for i in range(func.getParameterCount()):
                param = func.getParameter(i)
                params.append({
                    "name": param.getName(),
                    "type": str(param.getDataType()),
                    "ordinal": param.getOrdinal(),
                })
            entry["parameters"] = params

            source = func.getSymbol().getSource()
            entry["source"] = str(source)

            functions.append(entry)

        return {
            "total": len(functions),
            **GhidraHeadless._function_kind_counts(functions),
            "program": str(program.getName()),
            "functions": functions,
        }

    @staticmethod
    def _function_kind_counts(functions: list[dict[str, Any]]) -> dict[str, int]:
        """Ghidra fonksiyon nesnelerini türe ayır (GHIDRA-10).

        Ghidra her içe aktarılan fonksiyon için taslak üretir (ELF'te PLT girişi + EXTERNAL
        bloktaki 1 baytlık taslak; ikisi de ``is_thunk``). Bunlar programın fonksiyonu değildir;
        "kurtarılan fonksiyon" sayacına girmemelidir. ``program_function_count`` = thunk da dış
        da olmayan fonksiyonlar; ``thunk_count`` = thunk'lar; ``external_count`` = thunk olmayan
        dış fonksiyonlar. Üçünün toplamı ``total``.
        """
        thunk = sum(1 for f in functions if f.get("is_thunk"))
        external = sum(1 for f in functions if f.get("is_external") and not f.get("is_thunk"))
        return {
            "program_function_count": len(functions) - thunk - external,
            "thunk_count": thunk,
            "external_count": external,
        }

    @staticmethod
    def _extract_strings(program, denetci: _AdimDenetcisi | None = None) -> dict[str, Any]:
        """Tanimli string'leri cikar.

        Ghidra 12.0'da DefinedDataIterator.definedStrings kaldirildi.
        Yerine Listing.getDefinedData ile tum data'lar taranarak
        string tipindekiler filtrelenir.

        ÖL-2: ``denetci`` verilirse her tanımlı veri biriminde bütçe / olay denetimi; bütçe
        dolunca döngü biter, çıktıya ``kismi / islenen / neden`` eklenir (birim = taranan veri).
        """
        listing = program.getListing()
        fm = program.getFunctionManager()
        ref_mgr = program.getReferenceManager()
        strings = []
        seen_addrs = set()

        data_iter = listing.getDefinedData(True)
        taranan = 0
        while data_iter.hasNext():
            if denetci is not None and denetci.denetle(taranan):
                break
            taranan += 1
            data = data_iter.next()
            dt_name = str(data.getDataType().getName()).lower()

            # String tipleri: string, TerminatedCString, UnicodeString vb.
            if "string" not in dt_name and "cstring" not in dt_name:
                continue

            addr = str(data.getAddress())
            if addr in seen_addrs:
                continue
            seen_addrs.add(addr)

            value = data.getDefaultValueRepresentation()
            if value and len(value) >= 2:
                if (value[0] == '"' and value[-1] == '"') or \
                   (value[0] == "'" and value[-1] == "'"):
                    value = value[1:-1]

            entry = {
                "address": addr,
                "value": value,
                "length": data.getLength(),
                "type": str(data.getDataType().getName()),
            }

            # GHIDRA-16: dizgi veri bölümünde durur; "onu içeren fonksiyon" hiç yoktur
            # (eski kod getFunctionContaining(dizgi adresi) yüzünden 80 545 kaydın 0'ında
            # dolu). Bağ dizgiye başvuran komutlardan kurulur (string_extractor.py ile
            # aynı şema): xrefs = başvuranlar (adres sırasında), function = ilk başvuranın
            # fonksiyonu. Başvuran yoksa alanlar boş kalır ve xref_count 0 bunu söyler.
            xrefs = []
            for ref in ref_mgr.getReferencesTo(data.getAddress()):
                from_addr = ref.getFromAddress()
                from_func = fm.getFunctionContaining(from_addr)
                xrefs.append({
                    "from_address": str(from_addr),
                    "from_function": str(from_func.getName()) if from_func else None,
                    "from_func_addr": str(from_func.getEntryPoint()) if from_func else None,
                })
            xrefs.sort(key=lambda x: _address_sort_key(x["from_address"]))
            entry["xrefs"] = xrefs
            entry["xref_count"] = len(xrefs)
            first = next((x for x in xrefs if x["from_function"]), None)
            entry["function"] = first["from_function"] if first else None
            entry["function_addr"] = first["from_func_addr"] if first else None

            strings.append(entry)

        out = {
            "total": len(strings),
            "program": str(program.getName()),
            "strings": strings,
        }
        if denetci is not None:
            out.update(denetci.kismi_alanlari())
        return out

    @staticmethod
    def _extract_call_graph(program, denetci: _AdimDenetcisi | None = None,
                            tablo: _BasvuruTablosu | None = None) -> dict[str, Any]:
        """Call graph cikar (ÖL-2: ``denetci`` ile fonksiyon başına bütçe / olay denetimi).

        HZ-4a: ``tablo`` verilirse düğümler ortak başvuru tablosundan kurulur (fonksiyon başına
        tek geçiş, yalnız başvurusu olan adresler); verilmezse aşağıdaki eski döngü koşar. Çıktı
        iki yolda bayt bayt aynıdır.
        """
        fm = program.getFunctionManager()
        ref_mgr = program.getReferenceManager()

        nodes = {}
        edges = []
        if tablo is not None:
            tablo.tazele()

        islenen = 0
        for func in fm.getFunctions(True):
            if denetci is not None and denetci.denetle(islenen):
                break
            islenen += 1
            func_name = func.getName()
            func_addr = str(func.getEntryPoint())
            if tablo is not None:  # HZ-4a: tek geçiş
                nodes[func_addr] = tablo.cagri_dugumu(func, func_name, func_addr, edges)
                continue

            callers = []
            callees = []

            # Callers
            refs_to = ref_mgr.getReferencesTo(func.getEntryPoint())
            for ref in refs_to:
                if ref.getReferenceType().isCall():
                    caller_func = fm.getFunctionContaining(ref.getFromAddress())
                    if caller_func and str(caller_func.getEntryPoint()) != func_addr:
                        callers.append({
                            "name": caller_func.getName(),
                            "address": str(caller_func.getEntryPoint()),
                        })

            # Callees
            body = func.getBody()
            addr_iter = body.getAddresses(True)
            while addr_iter.hasNext():
                addr = addr_iter.next()
                refs_from = ref_mgr.getReferencesFrom(addr)
                for ref in refs_from:
                    if ref.getReferenceType().isCall():
                        callee = fm.getFunctionAt(ref.getToAddress())
                        if not callee:
                            callee = fm.getFunctionContaining(ref.getToAddress())
                        if callee and str(callee.getEntryPoint()) != func_addr:
                            callee_addr = str(callee.getEntryPoint())
                            callees.append({
                                "name": callee.getName(),
                                "address": callee_addr,
                            })
                            edges.append({
                                "from": func_addr,
                                "to": callee_addr,
                                "from_name": func_name,
                                "to_name": callee.getName(),
                            })

            # Deduplicate (set.add None döner, comprehension trick yerine açık döngü)
            seen_c: set = set()
            unique_callers = []
            for c in callers:
                if c["address"] not in seen_c:
                    seen_c.add(c["address"])
                    unique_callers.append(c)
            unique_callers.sort(key=caller_sort_key)  # P16e: getReferencesTo sırası kararsız
            seen_e: set = set()
            unique_callees = []
            for c in callees:
                if c["address"] not in seen_e:
                    seen_e.add(c["address"])
                    unique_callees.append(c)

            nodes[func_addr] = {
                "name": func_name,
                "address": func_addr,
                "caller_count": len(unique_callers),
                "callee_count": len(unique_callees),
                "callers": unique_callers,
                "callees": unique_callees,
            }

        # Deduplicate edges
        seen_edges = set()
        unique_edges = []
        for e in edges:
            key = (e["from"], e["to"])
            if key not in seen_edges:
                seen_edges.add(key)
                unique_edges.append(e)

        out = {
            "program": str(program.getName()),
            "total_functions": len(nodes),
            "total_edges": len(unique_edges),
            "nodes": nodes,
            "edges": unique_edges,
        }
        if denetci is not None:
            out.update(denetci.kismi_alanlari())
        return out

    @staticmethod
    def _extract_disassembly(program, func) -> list[dict[str, Any]]:
        """Fonksiyonun disassembly'sini cikar (PyGhidra modu).

        Args:
            program: Ghidra program nesnesi.
            func: Ghidra Function nesnesi.

        Returns:
            list: instruction bilgileri listesi.
        """
        listing = program.getListing()
        instructions = []

        code_units = listing.getCodeUnits(func.getBody(), True)
        while code_units.hasNext():
            cu = code_units.next()
            try:
                mnemonic = cu.getMnemonicString()
            except Exception:
                logger.debug("Instruction mnemonic okuma basarisiz, atlaniyor", exc_info=True)
                continue

            instr_entry = {
                "address": str(cu.getAddress()),
                "mnemonic": mnemonic,
            }

            # KISIT: getDefaultOperandRepresentation YALNIZCA Instruction'da var. PLT/thunk
            # bolgesinde (ornegin gnu_ifunc GOT slotlari) Ghidra code unit'i Data (DataDB)
            # olarak siniflandirir -> AttributeError. Duck-typing tercih edildi: kod tabaninda
            # Ghidra tipleri icin isinstance konvansiyonu YOK (headless.py:2010 zaten hasattr
            # kullaniyor) ve JPype/Jython koprusunde Java arayuz isinstance'i koprue bagimli;
            # getattr her iki koprude de ayni davranir ve kendisi exception atamaz.
            op_repr = getattr(cu, "getDefaultOperandRepresentation", None)
            operands = []
            if op_repr is not None:
                for i in range(cu.getNumOperands()):
                    op_str = op_repr(i)
                    if op_str:
                        operands.append(op_str)
            else:
                # Data code unit: operand yok ama SESSIZCE ATMA -- degeri kaydet.
                instr_entry["is_data"] = True
                val_repr = getattr(cu, "getDefaultValueRepresentation", None)
                if val_repr is not None:
                    val = val_repr()
                    if val:
                        operands.append(str(val))
            instr_entry["operands"] = operands
            instr_entry["text"] = str(cu)

            instructions.append(instr_entry)

        return instructions

    @staticmethod
    def _extract_func_xrefs(program, func) -> dict[str, Any]:
        """Fonksiyonun cross-reference bilgisini cikar (PyGhidra modu).

        Args:
            program: Ghidra program nesnesi.
            func: Ghidra Function nesnesi.

        Returns:
            dict: callers ve callees listeleri.
        """
        fm = program.getFunctionManager()
        ref_mgr = program.getReferenceManager()
        func_addr = str(func.getEntryPoint())

        callers = []
        seen_callers: set[str] = set()
        refs_to = ref_mgr.getReferencesTo(func.getEntryPoint())
        for ref in refs_to:
            if ref.getReferenceType().isCall():
                caller = fm.getFunctionContaining(ref.getFromAddress())
                if caller is not None:
                    ca = str(caller.getEntryPoint())
                    if ca != func_addr and ca not in seen_callers:
                        seen_callers.add(ca)
                        callers.append({
                            "name": caller.getName(),
                            "address": ca,
                            "call_site": str(ref.getFromAddress()),
                        })
        # P16e: sıralı liste → "// Callers:" satırı en küçük adresli 5 çağıranı gösterir.
        callers.sort(key=caller_sort_key)

        callees = []
        seen_callees: set[str] = set()
        body = func.getBody()
        addr_iter = body.getAddresses(True)
        while addr_iter.hasNext():
            addr = addr_iter.next()
            refs_from = ref_mgr.getReferencesFrom(addr)
            for ref in refs_from:
                if ref.getReferenceType().isCall():
                    callee = fm.getFunctionAt(ref.getToAddress())
                    if callee is None:
                        callee = fm.getFunctionContaining(ref.getToAddress())
                    if callee is not None:
                        ca = str(callee.getEntryPoint())
                        if ca != func_addr and ca not in seen_callees:
                            seen_callees.add(ca)
                            callees.append({
                                "name": callee.getName(),
                                "address": ca,
                                "call_site": str(addr),
                            })

        return {
            "caller_count": len(callers),
            "callee_count": len(callees),
            "callers": callers,
            "callees": callees,
        }

    @staticmethod
    def _extract_stack_frame(func) -> dict[str, Any] | None:
        """Fonksiyonun stack frame layout'unu cikar (PyGhidra modu).

        Args:
            func: Ghidra Function nesnesi.

        Returns:
            dict: stack frame bilgileri veya None.
        """
        frame = func.getStackFrame()
        if frame is None:
            return None

        variables = []
        for var in frame.getStackVariables():
            var_entry = {
                "name": var.getName(),
                "offset": var.getStackOffset(),
                "size": var.getLength(),
                "type": str(var.getDataType()),
                "kind": "parameter" if var.getStackOffset() >= 0 else "local",
            }
            comment = var.getComment()
            if comment:
                var_entry["comment"] = comment
            variables.append(var_entry)

        variables.sort(key=lambda v: v["offset"], reverse=True)

        return {
            "frame_size": frame.getFrameSize(),
            "local_size": frame.getLocalSize(),
            "parameter_offset": frame.getParameterOffset(),
            "parameter_size": frame.getParameterSize(),
            "return_address_offset": frame.getReturnAddressOffset(),
            "variable_count": len(variables),
            "variables": variables,
        }

    @staticmethod
    def _decompile_functions(
        program, output_dir: Path, timeout: int,
        selective_ops: set[str] | None = None,
        func_timeout: int = 30,
    ) -> dict[str, Any]:
        """Fonksiyonlari PARALEL decompile et, disassembly/xref/stack frame ile zenginlestir.

        Ghidra'nin ParallelDecompiler API'sini kullanir -- Java thread pool ile
        birden fazla DecompInterface instance'i esanli calisir. M4 Max'te 10
        P-core tam yuk altinda kullanilir.

        Args:
            program: Ghidra program nesnesi.
            output_dir: Cikti dizini.
            timeout: Toplam zaman asimi (saniye).
            (P16c: eski ``batch_size`` parametresi gövdede hiç kullanılmıyordu, kaldırıldı;
            parça boyu işçi sayısından: fonksiyon sayısı / ``CPU_PERF_CORES``.)
            selective_ops: Verilirse decompile sirasinda bu mnemonic'lere
                sahip P-Code op'lari compact formatta toplanir (v1.5 JSONL).
            func_timeout: Fonksiyon başına decompile süresi (saniye);
                ``binary_reconstruction.max_decompile_timeout_per_func``'tan gelir.
        """
        from karadul.config import CPU_PERF_CORES

        FUNC_TIMEOUT = max(1, int(func_timeout))

        decompiled_dir = output_dir / "decompiled"
        decompiled_dir.mkdir(parents=True, exist_ok=True)

        fm = program.getFunctionManager()
        total_func_count = fm.getFunctionCount()

        logger.info(
            "Paralel decompile basliyor: %d fonksiyon (%d thread)",
            total_func_count, CPU_PERF_CORES,
        )

        try:
            parallel_results = GhidraHeadless._parallel_decompile_java_threads(
                program, decompiled_dir, total_func_count,
                FUNC_TIMEOUT, timeout, CPU_PERF_CORES,
                selective_ops=selective_ops,
            )
        except Exception as exc:
            logger.warning(
                "Paralel decompile hatasi (%s), seri fallback'e geciliyor", exc,
            )
            parallel_results = GhidraHeadless._serial_decompile_fallback(
                program, decompiled_dir, total_func_count,
                FUNC_TIMEOUT, timeout,
                selective_ops=selective_ops,
            )

        return parallel_results

    @staticmethod
    def _parallel_decompile_java_threads(
        program, decompiled_dir: Path, total_func_count: int,
        func_timeout: int, total_timeout: int, n_threads: int,
        selective_ops: set[str] | None = None,
    ) -> dict[str, Any]:
        """Python ThreadPoolExecutor ile paralel decompile.

        Her thread kendi DecompInterface + ConsoleTaskMonitor instance'ini
        acar. JPype JNI cagrisi (decompileFunction) sirasinda GIL serbest
        birakilir, gercek paralellik saglanir. Java thread pool yerine
        Python thread pool kullanilir -- JPype JProxy uyumsuzlugu nedeniyle.

        Args:
            selective_ops: set[str] | None -- Verilirse decompile sirasinda
                bu mnemonic'lere sahip P-Code op'lari compact toplanir (v1.5).
        """
        from ghidra.app.decompiler import DecompInterface, DecompileOptions
        from ghidra.util.task import ConsoleTaskMonitor
        from concurrent.futures import ThreadPoolExecutor, as_completed

        fm = program.getFunctionManager()
        start_time = time.time()
        deadline = start_time + total_timeout if total_timeout and total_timeout > 0 else None

        # Tum fonksiyonlari Python listesine topla. FunctionManager.getFunctions(True) adres
        # sirasinda (ileri) yineler; sonuclar bu sirayla birlestirilir (GHIDRA-05).
        all_funcs = []
        func_iter = fm.getFunctions(True)
        while func_iter.hasNext():
            all_funcs.append(func_iter.next())

        actual_count = len(all_funcs)
        logger.info("Fonksiyonlar toplandi: %d", actual_count)

        # Ayni adli fonksiyonlarin dosya adi decompile oncesi, adres sirasiyla belirlenir:
        # eskiden eksiz ``ad.c`` adini hangi is parcacigi once yazarsa o aliyordu.
        planned_files = GhidraHeadless._plan_decompile_filenames(
            (f.getName(), str(f.getEntryPoint())) for f in all_funcs
        )

        # Chunk'lara bol -- her thread kendi DecompInterface'ini kullanacak
        chunk_size = max(1, actual_count // n_threads)
        chunks = []
        for i in range(0, actual_count, chunk_size):
            chunks.append(all_funcs[i:i + chunk_size])

        def _process_chunk(chunk_funcs):
            """Bir chunk fonksiyonu decompile et. Her thread kendi decomp'unu acar."""
            decomp = DecompInterface()
            decomp.setOptions(DecompileOptions())
            decomp.openProgram(program)
            monitor = ConsoleTaskMonitor()

            chunk_results = []
            try:
                for func in chunk_funcs:
                    if deadline is not None and time.time() > deadline:
                        # Toplam sure doldu: kalanlar decompile edilmeden, nedeniyle kaydedilir.
                        chunk_results.append(GhidraHeadless._lost_entry(
                            func, "toplam decompile süresi (%d sn) doldu" % total_timeout,
                            skipped=True,
                        ))
                        continue
                    chunk_results.append(GhidraHeadless._decompile_single_function(
                        decomp, func, program, decompiled_dir,
                        func_timeout, monitor,
                        selective_ops=selective_ops,
                        file_name=planned_files.get(str(func.getEntryPoint())),
                    ))
            finally:
                decomp.dispose()
            return chunk_results

        # HZ-1: parça başına duvar süresi (iş parçacığında koştuğu süre; kuyrukta bekleme hariç).
        chunk_seconds: list[float | None] = [None] * len(chunks)

        def _timed_chunk(chunk_idx, chunk_funcs):
            t_chunk = time.monotonic()
            try:
                return _process_chunk(chunk_funcs)
            finally:
                chunk_seconds[chunk_idx] = round(time.monotonic() - t_chunk, 3)

        chunk_outputs: list[list[dict[str, Any]] | None] = [None] * len(chunks)
        chunk_errors: list[dict[str, Any]] = []
        biten_fonksiyon = 0  # ÖL-1: biten parçaların fonksiyon sayısı (ilerleme olayı)
        with ThreadPoolExecutor(max_workers=n_threads) as executor:
            futures = {
                executor.submit(_timed_chunk, i, chunk): i
                for i, chunk in enumerate(chunks)
            }

            for future in as_completed(futures):
                chunk_idx = futures[future]
                biten_fonksiyon += len(chunks[chunk_idx])
                _ilerleme(ADIM_DECOMPILE, OLAY_SURUYOR, islenen=biten_fonksiyon,
                          toplam=actual_count, gecen_sn=round(time.time() - start_time, 1))
                try:
                    chunk_outputs[chunk_idx] = future.result()
                    logger.info(
                        "Chunk %d/%d tamamlandi", chunk_idx + 1, len(chunks),
                    )
                except Exception as exc:
                    # Eskiden bu parcadaki fonksiyonlar listeden adsiz dusuyordu; artik her biri
                    # nedeniyle basarisiz kaydedilir (kayip sayaci).
                    logger.warning("Decompile chunk %d hatasi: %s", chunk_idx, exc)
                    chunk_errors.append({
                        "chunk": chunk_idx, "functions": len(chunks[chunk_idx]),
                        "error": "%s: %s" % (type(exc).__name__, exc),
                    })
                    chunk_outputs[chunk_idx] = [
                        GhidraHeadless._lost_entry(
                            f, "decompile parçası düştü: %s: %s" % (type(exc).__name__, exc),
                        )
                        for f in chunks[chunk_idx]
                    ]

        results = [entry for out in chunk_outputs for entry in (out or [])]
        total_time = time.time() - start_time

        result_dict = GhidraHeadless._finalize_decompile_result(
            results, decompiled_dir, total_time,
            batch_size=chunk_size, total_batches=len(chunks),
            chunk_errors=chunk_errors,
        )
        result_dict["parallel"] = True
        result_dict["threads"] = n_threads
        logger.info(
            "Decompile tamamlandi: %d/%d basarili, %d basarisiz, %d atlandi (%.1fs, %d thread)",
            result_dict["success"], actual_count, result_dict["failed"],
            result_dict["skipped"], total_time, n_threads,
        )
        # v1.5: JSONL pcode icin tum fonksiyon sonuclarina erisim gerekiyor
        # (functions key'i decompiled.json icin sinirla kesilir, _all_functions tam liste)
        if selective_ops is not None:
            result_dict["_all_functions"] = results
        # HZ-1: _analyze_pyghidra bunu decompiled.json'a yazmadan önce ayırır (ghidra_status.json).
        result_dict["_decompile_parcalari"] = GhidraHeadless._chunk_time_summary(
            chunk_seconds, path="paralel", threads=n_threads, chunk_size=chunk_size,
        )
        return result_dict

    @staticmethod
    def _chunk_time_summary(
        chunk_seconds: list[float | None], path: str, threads: int, chunk_size: int,
    ) -> dict[str, Any]:
        """HZ-1: decompile parçalarının süre özeti (``ghidra_status.json`` → ``decompile_parcalari``).

        ``parca_sn`` parça sırasındadır (parçalar adres sırasında kesilir). ``sure_sn`` ölçülen
        parçaların en küçüğü / ortancası / en büyüğü; ölçülen parça yoksa alan yazılmaz.
        """
        olculen = [s for s in chunk_seconds if s is not None]
        ozet: dict[str, Any] = {
            "yol": path,
            "parca_sayisi": len(chunk_seconds),
            "is_parcacigi": threads,
            "parca_boyu": chunk_size,
            "parca_sn": list(chunk_seconds),
        }
        if olculen:
            ozet["sure_sn"] = {
                "en_kucuk": min(olculen),
                "ortanca": round(statistics.median(olculen), 3),
                "en_buyuk": max(olculen),
            }
        return ozet

    # decompiled.json'a yazilan fonksiyon kaydi siniri (dosya boyutu). Kayitlar adres sirasinda;
    # kesilen sayi ``functions_truncated`` ile yazilir (B-B4). Tam liste pcode.jsonl'dedir.
    DECOMPILED_JSON_LIMIT = 500

    @staticmethod
    def _plan_decompile_filenames(funcs) -> dict[str, str]:
        """(ad, adres) dizisinden adres -> dosya adı; aynı ada sahip olanlardan ilki eksiz ad alır.

        Dizi Ghidra'nın adres sırasında verilir. Anahtar büyük/küçük harf duyarsızdır (macOS'un
        öntanımlı dosya sistemi ``Foo.c`` ile ``foo.c``'yi aynı dosya sayar). Sonuç iş
        parçacığı zamanlamasından bağımsızdır.
        """
        planned: dict[str, str] = {}
        taken: set[str] = set()
        for name, addr in funcs:
            safe = re.sub(r'[^\w\-.]', '_', name)[:200] or "unnamed"
            fname = safe + ".c"
            if fname.casefold() in taken:
                fname = "%s_%s.c" % (safe, addr.replace(":", "_")[-8:])
            taken.add(fname.casefold())
            planned[addr] = fname
        return planned

    @staticmethod
    def _lost_entry(func, error: str, skipped: bool = False) -> dict[str, Any]:
        """Decompile edilmeden kalan fonksiyonun kaydı (adı, adresi, nedeni)."""
        entry = {
            "name": func.getName(), "address": str(func.getEntryPoint()),
            "success": False, "error": error,
        }
        if skipped:
            entry["skipped"] = True
        return entry

    @staticmethod
    def _finalize_decompile_result(
        results: list[dict[str, Any]], decompiled_dir: Path, total_time: float,
        batch_size: int, total_batches: int,
        chunk_errors: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Decompile sonucunun sayaçları ve kayıp kaydı (B-B4, GHIDRA-05).

        ``results`` adres sırasındadır. ``functions`` ilk ``DECOMPILED_JSON_LIMIT`` kayıttır;
        kesilen sayı ve neden ``losses``'ta. Başarısız ya da atlanan her fonksiyon listede
        kendi kaydıyla durur (adsız düşme yok).
        """
        limit = GhidraHeadless.DECOMPILED_JSON_LIMIT
        success = sum(1 for r in results if r.get("success"))
        skipped = sum(1 for r in results if r.get("skipped"))
        failed = len(results) - success - skipped
        written = min(limit, len(results))
        truncated = len(results) - written
        losses: dict[str, Any] = {
            "decompiled_json_truncated": {
                "count": truncated,
                "reason": "decompiled.json yalnız adres sırasında ilk %d kaydı taşır" % limit,
            },
            "decompile_failed": failed,
            "decompile_skipped": skipped,
            "body_truncated": 0,
        }
        if chunk_errors:
            losses["chunk_errors"] = chunk_errors
        return {
            "total_attempted": len(results),
            "success": success,
            "failed": failed,
            "skipped": skipped,
            "duration_seconds": round(total_time, 2),
            "decompiled_dir": str(decompiled_dir),
            "functions_order": "address",
            "functions_total": len(results),
            "functions_written": written,
            "functions_truncated": truncated,
            "functions": results[:limit],
            "losses": losses,
            "batch_size": batch_size,
            "total_batches": total_batches,
        }

    @staticmethod
    def _decompile_single_function(decomp, func, program, decompiled_dir, func_timeout, monitor, selective_ops=None, file_name=None):
        """Tek bir fonksiyonu decompile et + dosyaya yaz. Thread-safe.

        Args:
            selective_ops: set[str] | None -- Verilirse decompile sonucundan
                bu mnemonic'lere sahip P-Code op'lari compact formatta toplanir.
                None ise pcode toplanmaz (v1.4 davranisi).
        """
        func_name = func.getName()
        func_addr = str(func.getEntryPoint())
        func_size = int(func.getBody().getNumAddresses())

        try:
            decomp_result = decomp.decompileFunction(func, func_timeout, monitor)
            decomp_func = decomp_result.getDecompiledFunction() if decomp_result else None
            if decomp_func:
                c_code = decomp_func.getC()
                if c_code:
                    # KISIT: decompile BASARILI oldugu halde metadata cikarimindaki bir hata
                    # disaridaki genis "except Exception"a dusup fonksiyonun TAMAMINI
                    # success=False isaretliyordu -> saglam C kodu cope gidiyordu (61/146).
                    # Metadata artik ayri ayri korunuyor: hata olursa fallback + SESLI kayit,
                    # C kodu her zaman yazilir. Fallback sekilleri asagida kullanilan
                    # anahtarlarla (caller_count/callees...) birebir uyumlu olmak ZORUNDA.
                    metadata_errors: dict[str, str] = {}

                    try:
                        disasm = GhidraHeadless._extract_disassembly(program, func)
                    except Exception as md_exc:
                        disasm = []
                        metadata_errors["disassembly"] = str(md_exc)
                        logger.warning(
                            "Disassembly cikarimi basarisiz (%s @ %s): %s -- C kodu yine de yazilyor",
                            func_name, func_addr, md_exc, exc_info=True,
                        )

                    try:
                        xrefs = GhidraHeadless._extract_func_xrefs(program, func)
                    except Exception as md_exc:
                        xrefs = {"caller_count": 0, "callee_count": 0, "callers": [], "callees": []}
                        metadata_errors["xrefs"] = str(md_exc)
                        logger.warning(
                            "Xref cikarimi basarisiz (%s @ %s): %s -- C kodu yine de yazilyor",
                            func_name, func_addr, md_exc, exc_info=True,
                        )

                    try:
                        stack_frame = GhidraHeadless._extract_stack_frame(func)
                    except Exception as md_exc:
                        stack_frame = None
                        metadata_errors["stack_frame"] = str(md_exc)
                        logger.warning(
                            "Stack frame cikarimi basarisiz (%s @ %s): %s -- C kodu yine de yazilyor",
                            func_name, func_addr, md_exc, exc_info=True,
                        )

                    safe_name = re.sub(r'[^\w\-.]', '_', func_name)[:200] or "unnamed"
                    # Adres suffix'i ile cakismayi onle (C++ overload, thunk vb.)
                    addr_suffix = func_addr.replace(":", "_")[-8:]
                    # Paralel yolda dosya adı önceden, adres sırasıyla planlanır (file_name);
                    # O_EXCL aşağıda yine son güvencedir.
                    filepath = decompiled_dir / (file_name or (safe_name + ".c"))

                    header_lines = [
                        "// Function: %s" % func_name,
                        "// Address:  %s" % func_addr,
                        "// Size:     %d bytes" % func_size,
                    ]

                    caller_line = "// Callers:  %d" % xrefs["caller_count"]
                    if xrefs["callers"]:
                        names = [c["name"] for c in xrefs["callers"][:5]]
                        caller_line += " (%s" % ", ".join(names)
                        if xrefs["caller_count"] > 5:
                            caller_line += ", ..."
                        caller_line += ")"
                    header_lines.append(caller_line)

                    callee_line = "// Callees:  %d" % xrefs["callee_count"]
                    if xrefs["callees"]:
                        names = [c["name"] for c in xrefs["callees"][:5]]
                        callee_line += " (%s" % ", ".join(names)
                        if xrefs["callee_count"] > 5:
                            callee_line += ", ..."
                        callee_line += ")"
                    header_lines.append(callee_line)

                    if stack_frame is not None:
                        header_lines.append(
                            "// Stack:    frame=%d, locals=%d, params=%d" % (
                                stack_frame["frame_size"],
                                stack_frame["local_size"],
                                stack_frame["parameter_size"],
                            )
                        )

                    file_content = "\n".join(header_lines) + "\n\n" + c_code
                    if disasm:
                        file_content += "\n\n// --- DISASSEMBLY (%d instructions) ---\n" % len(disasm)
                        for instr in disasm:
                            file_content += "// %s  %s\n" % (instr["address"], instr["text"])

                    # "Yoksa oluştur" tek adımda (O_EXCL). Eski kod önce exists() ile
                    # bakıp sonra yazıyordu; paralel decompile'da aynı adlı iki fonksiyon
                    # (ör. iki PLT thunk'ı) denetimi birlikte geçip aynı dosyaya yazıyor,
                    # biri kayboluyordu. Hangisinin eksiz adı alacağı zamanlamaya bağlıdır;
                    # dosyanın kimliği başlıktaki adrestir.
                    try:
                        with filepath.open("x", encoding="utf-8") as fh:
                            fh.write(file_content)
                    except FileExistsError:
                        filepath = decompiled_dir / (f"{safe_name}_{addr_suffix}.c")
                        filepath.write_text(file_content, encoding="utf-8")

                    result_entry = {
                        "name": func_name, "address": func_addr,
                        "file": filepath.name, "lines": c_code.count("\n") + 1,
                        "size": func_size, "success": True,
                        "instruction_count": len(disasm), "xrefs": xrefs,
                    }
                    # Kismi basari sessiz kalmasin: C kodu var ama metadata eksikse raporla.
                    if metadata_errors:
                        result_entry["metadata_errors"] = metadata_errors
                    if stack_frame is not None:
                        result_entry["stack_frame"] = {
                            "frame_size": stack_frame["frame_size"],
                            "local_size": stack_frame["local_size"],
                            "parameter_size": stack_frame["parameter_size"],
                            "variable_count": stack_frame["variable_count"],
                        }

                    # --- Selective P-Code extraction (v1.5) ---
                    if selective_ops is not None:
                        pcode_ops_selective = []
                        pcode_high_vars = []
                        try:
                            high_func = decomp_result.getHighFunction() if decomp_result else None
                            if high_func is not None:
                                _SPACE_MAP = {"unique": 0, "register": 1, "const": 2, "ram": 3, "stack": 4}

                                pcode_iter = high_func.getPcodeOps()
                                while pcode_iter.hasNext():
                                    op = pcode_iter.next()
                                    mnemonic = op.getMnemonic()
                                    if mnemonic not in selective_ops:
                                        continue

                                    output_vn = op.getOutput()
                                    out_compact = None
                                    if output_vn is not None:
                                        space_name = str(output_vn.getAddress().getAddressSpace().getName())
                                        out_compact = [
                                            _SPACE_MAP.get(space_name, 5),
                                            int(output_vn.getOffset()),
                                            output_vn.getSize(),
                                        ]

                                    inputs_compact = []
                                    for i in range(op.getNumInputs()):
                                        inp = op.getInput(i)
                                        if inp is not None:
                                            space_name = str(inp.getAddress().getAddressSpace().getName())
                                            inputs_compact.append([
                                                _SPACE_MAP.get(space_name, 5),
                                                int(inp.getOffset()),
                                                inp.getSize(),
                                            ])

                                    pcode_ops_selective.append([mnemonic, out_compact, inputs_compact])

                                # High-level variables
                                local_map = high_func.getLocalSymbolMap()
                                if local_map is not None:
                                    for sym in local_map.getSymbols():
                                        hv = sym.getHighVariable()
                                        pcode_high_vars.append({
                                            "name": sym.getName(),
                                            "type": str(sym.getDataType()) if sym.getDataType() else "undefined",
                                            "size": sym.getSize(),
                                            "storage": str(hv.getRepresentative()) if hv and hv.getRepresentative() else "unknown",
                                        })
                        except Exception:
                            logger.debug("Pcode variable extraction basarisiz, atlaniyor", exc_info=True)

                        # P16d: getSymbols() sırası koşudan koşuya değişiyor; liste kararlı sırada.
                        pcode_high_vars.sort(key=high_var_sort_key)
                        result_entry["pcode_ops"] = pcode_ops_selective
                        result_entry["pcode_high_vars"] = pcode_high_vars

                    return result_entry
                else:
                    return {"name": func_name, "address": func_addr,
                            "success": False, "error": "Empty result"}
            else:
                error_msg = "None result"
                if decomp_result:
                    error_msg = str(decomp_result.getErrorMessage() or "Unknown")
                return {"name": func_name, "address": func_addr,
                        "success": False, "error": error_msg}
        except Exception as exc:
            return {"name": func_name, "address": func_addr,
                    "success": False, "error": str(exc)}

    @staticmethod
    def _serial_decompile_fallback(
        program, decompiled_dir: Path, total_func_count: int,
        func_timeout: int, total_timeout: int,
        selective_ops: set[str] | None = None,
    ) -> dict[str, Any]:
        """Seri decompile -- paralel basarisiz olursa fallback."""
        from ghidra.app.decompiler import DecompInterface, DecompileOptions
        from ghidra.util.task import ConsoleTaskMonitor

        decomp = DecompInterface()
        decomp.setOptions(DecompileOptions())
        decomp.openProgram(program)
        monitor = ConsoleTaskMonitor()

        fm = program.getFunctionManager()
        func_iter = fm.getFunctions(True)
        results = []
        func_index = 0
        start_time = time.time()
        timed_out = False

        while func_iter.hasNext():
            func = func_iter.next()
            func_index += 1

            if not timed_out and total_timeout > 0 and time.time() - start_time > total_timeout:
                timed_out = True
                logger.warning("Zaman asimi: %d islendi, kalanlar atlaniyor", func_index - 1)
            if timed_out:
                # Atlanan fonksiyon adsız düşmez; nedeniyle kaydedilir (kayıp sayacı).
                results.append(GhidraHeadless._lost_entry(
                    func, "toplam decompile süresi (%d sn) doldu" % total_timeout, skipped=True,
                ))
                continue

            results.append(GhidraHeadless._decompile_single_function(
                decomp, func, program, decompiled_dir, func_timeout, monitor,
                selective_ops=selective_ops,
            ))

            if func_index % 500 == 0:
                logger.info("Seri decompile: %d/%d", func_index, total_func_count)

        decomp.dispose()
        total_time = time.time() - start_time
        result_dict = GhidraHeadless._finalize_decompile_result(
            results, decompiled_dir, total_time, batch_size=func_index, total_batches=1,
        )
        result_dict["parallel"] = False
        logger.info(
            "Decompile tamamlandi (seri): %d/%d basarili, %d basarisiz, %d atlandi (%.1fs)",
            result_dict["success"], func_index, result_dict["failed"],
            result_dict["skipped"], total_time,
        )
        # v1.5: JSONL pcode icin tum fonksiyon sonuclarina erisim
        if selective_ops is not None:
            result_dict["_all_functions"] = results
        # HZ-1: seri yolda tek parça; süresi decompile'ın kendi ölçtüğü toplam süre.
        result_dict["_decompile_parcalari"] = GhidraHeadless._chunk_time_summary(
            [round(total_time, 3)], path="seri", threads=1, chunk_size=func_index,
        )
        return result_dict

    @staticmethod
    def _extract_types(program, denetci: _AdimDenetcisi | None = None) -> dict[str, Any]:
        """DataTypeManager'dan struct/enum/typedef bilgilerini cikar.

        ÖL-2: ``denetci`` ile veri tipi başına bütçe / olay denetimi (toplam bilinmiyor).
        """
        from ghidra.program.model.data import Structure, Union, Enum, TypeDef

        dtm = program.getDataTypeManager()
        structures = []
        enums = []
        typedefs = []

        taranan = 0
        for dt in dtm.getAllDataTypes():
            if denetci is not None and denetci.denetle(taranan):
                break
            taranan += 1
            if isinstance(dt, (Structure, Union)):
                entry = {
                    "name": dt.getName(),
                    "category": str(dt.getCategoryPath()),
                    "kind": "union" if isinstance(dt, Union) else "struct",
                    "size": dt.getLength(),
                    "field_count": dt.getNumComponents(),
                    "fields": [],
                }
                for comp in dt.getComponents():
                    entry["fields"].append({
                        "name": comp.getFieldName() or "(unnamed)",
                        "type": str(comp.getDataType()),
                        "offset": comp.getOffset(),
                        "size": comp.getLength(),
                    })
                structures.append(entry)

            elif isinstance(dt, Enum):
                entry = {
                    "name": dt.getName(),
                    "category": str(dt.getCategoryPath()),
                    "size": dt.getLength(),
                    "value_count": dt.getCount(),
                    "values": [],
                }
                for name in dt.getNames():
                    entry["values"].append({
                        "name": name,
                        "value": int(dt.getValue(name)),
                    })
                enums.append(entry)

            elif isinstance(dt, TypeDef):
                typedefs.append({
                    "name": dt.getName(),
                    "category": str(dt.getCategoryPath()),
                    "base_type": str(dt.getBaseDataType()),
                    "size": dt.getLength(),
                })

        out = {
            "total_structures": len(structures),
            "total_enums": len(enums),
            "total_typedefs": len(typedefs),
            "total_types": len(structures) + len(enums) + len(typedefs),
            "program": str(program.getName()),
            "structures": structures,
            "enums": enums,
            "typedefs": typedefs,
        }
        if denetci is not None:
            out.update(denetci.kismi_alanlari())
        return out

    @staticmethod
    def _extract_xrefs(program, denetci: _AdimDenetcisi | None = None,
                       tablo: _BasvuruTablosu | None = None,
                       tek_gecis: bool = False) -> dict[str, Any]:
        """Cross-reference haritasi cikar: fonksiyon -> string/global/fonksiyon.

        ÖL-2: ``denetci`` ile fonksiyon başına (ikinci bölümde, genel sembol sayımında,
        ``KUCUK_BIRIM_DENETIM_ADIMI`` sembolde bir) bütçe / olay denetimi. Sayaç birimi
        fonksiyondur; bütçe genel sembol sayımında dolarsa neden bunu söyler.

        HZ-4a: ``tablo`` verilirse fonksiyon kayıtları ortak başvuru tablosundan kurulur (çağrı
        grafiği adımı hesapladıysa hazır bulunur). ``tek_gecis`` (ya da ``tablo``) genel sembol
        sayımında ``getReferencesTo`` yineleyicisi yerine ``hasReferencesTo`` kullanır. Çıktı
        eski döngülerle bayt bayt aynıdır.
        """
        fm = program.getFunctionManager()
        ref_mgr = program.getReferenceManager()
        listing = program.getListing()

        func_xrefs: dict = {}
        string_ref_counts: dict[str, int] = {}  # addr -> ref count
        if tablo is not None:
            tablo.tazele()

        islenen = 0
        for func in fm.getFunctions(True):
            if denetci is not None and denetci.denetle(islenen):
                break
            islenen += 1
            func_name = func.getName()
            func_addr = str(func.getEntryPoint())
            if tablo is not None:  # HZ-4a: tek geçiş
                func_xrefs[func_addr] = tablo.xref_kaydi(func, func_name, func_addr,
                                                         string_ref_counts)
                continue

            strings_used = []
            funcs_called = []
            called_by = []
            seen_s = set()
            seen_c = set()

            # Outgoing refs
            body = func.getBody()
            addr_iter = body.getAddresses(True)
            while addr_iter.hasNext():
                addr = addr_iter.next()
                for ref in ref_mgr.getReferencesFrom(addr):
                    to_addr = ref.getToAddress()
                    rt = ref.getReferenceType()

                    if rt.isCall():
                        callee = fm.getFunctionAt(to_addr)
                        if callee is None:
                            callee = fm.getFunctionContaining(to_addr)
                        if callee is not None:
                            ca = str(callee.getEntryPoint())
                            if ca not in seen_c and ca != func_addr:
                                seen_c.add(ca)
                                funcs_called.append({"name": callee.getName(), "address": ca})
                    elif rt.isData():
                        data = listing.getDefinedDataAt(to_addr)
                        if data is not None:
                            dtn = str(data.getDataType().getName()).lower()
                            ta = str(to_addr)
                            if ("string" in dtn or "cstring" in dtn) and ta not in seen_s:
                                seen_s.add(ta)
                                val = data.getDefaultValueRepresentation()
                                if val and len(val) >= 2 and val[0] in ('"', "'") and val[-1] in ('"', "'"):
                                    val = val[1:-1]
                                strings_used.append({"address": ta, "value": val})
                                string_ref_counts[ta] = string_ref_counts.get(ta, 0) + 1

            # Incoming refs (callers)
            seen_callers = set()
            for ref in ref_mgr.getReferencesTo(func.getEntryPoint()):
                if ref.getReferenceType().isCall():
                    caller = fm.getFunctionContaining(ref.getFromAddress())
                    if caller is not None:
                        ca = str(caller.getEntryPoint())
                        if ca != func_addr and ca not in seen_callers:
                            seen_callers.add(ca)
                            called_by.append({"name": caller.getName(), "address": ca})
            called_by.sort(key=caller_sort_key)  # P16e

            func_xrefs[func_addr] = {
                "name": func_name,
                "address": func_addr,
                "strings_used": strings_used,
                "functions_called": funcs_called,
                "called_by": called_by,
            }

        # String xref ozeti
        total_strings = len(string_ref_counts)

        # Global xref (symbol table'dan non-function label'lar)
        from ghidra.program.model.symbol import SymbolType
        global_count = 0
        sym_iter = program.getSymbolTable().getAllSymbols(True)
        semboller = 0
        # ÖL-2: bütçe fonksiyon bölümünde dolduysa genel sembol sayımı koşmaz (sayı 0 kalır;
        # neden bunu söyler, ``kismi`` çıktıda).
        ikinci_bolum = not (denetci is not None and denetci.doldu)
        if not ikinci_bolum:
            denetci.ek_neden = "genel sembol sayımı yapılmadı"
        # HZ-4a: tür süzgeci kimlik baytıyla (``SymbolType.getID``), başvuru hükmü
        # ``hasReferencesTo`` ile (yineleyici kurmadan).
        sayilmayan_turler = None
        if (tek_gecis or tablo is not None) and ikinci_bolum:
            sayilmayan_turler = frozenset(
                int(t.getID())
                for t in (SymbolType.FUNCTION, SymbolType.PARAMETER, SymbolType.LOCAL_VAR))
        while ikinci_bolum and sym_iter.hasNext():
            if (denetci is not None and semboller % KUCUK_BIRIM_DENETIM_ADIMI == 0
                    and denetci.denetle(islenen)):
                denetci.ek_neden = "genel sembol sayımı yarıda (%d sembol)" % semboller
                break
            semboller += 1
            sym = sym_iter.next()
            if sayilmayan_turler is not None:  # HZ-4a
                if (int(sym.getSymbolType().getID()) not in sayilmayan_turler
                        and ref_mgr.hasReferencesTo(sym.getAddress())):
                    global_count += 1
                continue
            st = sym.getSymbolType()
            if st != SymbolType.FUNCTION and st != SymbolType.PARAMETER and st != SymbolType.LOCAL_VAR:
                refs = ref_mgr.getReferencesTo(sym.getAddress())
                has_ref = False
                for _ in refs:
                    has_ref = True
                    break
                if has_ref:
                    global_count += 1

        out = {
            "program": str(program.getName()),
            "statistics": {
                "total_functions": len(func_xrefs),
                "total_strings_with_xrefs": total_strings,
                "total_globals_with_xrefs": global_count,
            },
            "function_xrefs": func_xrefs,
        }
        if denetci is not None:
            out.update(denetci.kismi_alanlari())
        return out

    @staticmethod
    def _extract_pcode(program, denetci: _AdimDenetcisi | None = None) -> dict[str, Any]:
        """P-Code intermediate representation cikar.

        Her fonksiyon icin Ghidra decompiler'i kullanarak
        P-Code op'larini ve high-level degiskenleri toplar.
        Dataflow analizi icin kritik veri kaynagi.

        ÖL-2: ``denetci`` ile fonksiyon başına bütçe / olay denetimi.
        """
        from ghidra.app.decompiler import DecompInterface, DecompileOptions
        from ghidra.util.task import ConsoleTaskMonitor

        monitor = ConsoleTaskMonitor()
        decomp = DecompInterface()
        opts = DecompileOptions()
        decomp.setOptions(opts)
        decomp.openProgram(program)

        fm = program.getFunctionManager()
        functions_data = []
        total_ops = 0
        mnemonic_dist: dict[str, int] = {}
        BATCH_SIZE = 5000
        DECOMPILE_TIMEOUT = 30
        func_count = 0

        for func in fm.getFunctions(True):
            if monitor.isCancelled():
                break
            if denetci is not None and denetci.denetle(func_count):
                break
            func_count += 1

            try:
                result = decomp.decompileFunction(func, DECOMPILE_TIMEOUT, monitor)
                if result is None or not result.decompileCompleted():
                    continue

                high_func = result.getHighFunction()
                if high_func is None:
                    continue

                ops_data = []
                pcode_iter = high_func.getPcodeOps()
                while pcode_iter.hasNext():
                    op = pcode_iter.next()
                    mnemonic = op.getMnemonic()
                    mnemonic_dist[mnemonic] = mnemonic_dist.get(mnemonic, 0) + 1

                    output_vn = op.getOutput()
                    output_info = None
                    if output_vn is not None:
                        output_info = {
                            "space": str(output_vn.getAddress().getAddressSpace().getName()),
                            "offset": int(output_vn.getOffset()),
                            "size": output_vn.getSize(),
                            "is_constant": output_vn.isConstant(),
                            "is_register": output_vn.isRegister(),
                            "is_unique": output_vn.isUnique(),
                        }

                    inputs_data = []
                    for i in range(op.getNumInputs()):
                        inp = op.getInput(i)
                        if inp is not None:
                            inputs_data.append({
                                "space": str(inp.getAddress().getAddressSpace().getName()),
                                "offset": int(inp.getOffset()),
                                "size": inp.getSize(),
                                "is_constant": inp.isConstant(),
                                "is_register": inp.isRegister(),
                                "is_unique": inp.isUnique(),
                            })

                    ops_data.append({
                        "seq_num": int(op.getSeqnum().getTime()),
                        "mnemonic": mnemonic,
                        "address": str(op.getSeqnum().getTarget()),
                        "output": output_info,
                        "inputs": inputs_data,
                    })

                # High variable'lar
                high_vars = []
                local_map = high_func.getLocalSymbolMap()
                if local_map is not None:
                    for sym in local_map.getSymbols():
                        hv = sym.getHighVariable()
                        high_vars.append({
                            "name": sym.getName(),
                            "type": str(sym.getDataType()) if sym.getDataType() else "undefined",
                            "size": sym.getSize(),
                            "storage": str(hv.getRepresentative()) if hv and hv.getRepresentative() else "unknown",
                        })
                high_vars.sort(key=high_var_sort_key)  # P16d: getSymbols() sırası kararsız

                total_ops += len(ops_data)
                functions_data.append({
                    "name": func.getName(),
                    "address": str(func.getEntryPoint()),
                    "total_ops": len(ops_data),
                    "ops": ops_data,
                    "high_variables": high_vars,
                })

            except Exception:
                logger.debug("Pcode extraction basarisiz, atlaniyor", exc_info=True)
                continue

            if func_count % BATCH_SIZE == 0:
                logger.info("P-Code: %d fonksiyon islendi", func_count)

        decomp.dispose()

        out = {
            "program": program.getName(),
            "total_functions": len(functions_data),
            "total_pcode_ops": total_ops,
            "mnemonic_distribution": mnemonic_dist,
            "functions": functions_data,
        }
        if denetci is not None:
            out.update(denetci.kismi_alanlari())
        return out

    @staticmethod
    def _extract_pcode_stats_only(program, denetci: _AdimDenetcisi | None = None) -> dict[str, Any]:
        """P-Code istatistiklerini tam extraction yapmadan topla.

        DecompInterface acmaz, sadece FunctionManager'dan fonksiyon sayisini
        ve Listing'den instruction sayisini alir. 4.7GB pcode.json yerine
        ~200 byte uretir.

        ÖL-2: ``denetci`` ile ``KUCUK_BIRIM_DENETIM_ADIMI`` komutta bir bütçe / olay denetimi
        (sayaç birimi komut; toplam bilinmiyor).
        """
        fm = program.getFunctionManager()
        func_count = fm.getFunctionCount()

        # Instruction sayisi: pcode op sayisi icin proxy
        listing = program.getListing()
        instruction_count = 0
        inst_iter = listing.getInstructions(True)
        while inst_iter.hasNext():
            if (denetci is not None and instruction_count % KUCUK_BIRIM_DENETIM_ADIMI == 0
                    and denetci.denetle(instruction_count)):
                break
            inst_iter.next()
            instruction_count += 1

        out = {
            "program": str(program.getName()),
            "total_functions": func_count,
            "total_pcode_ops": instruction_count,  # proxy: 1 instruction ~= 2-5 pcode ops
            "mode": "stats_only",
            "functions": [],
            "stats": {
                "mnemonic_distribution": {},
            },
        }
        if denetci is not None:
            out.update(denetci.kismi_alanlari())
        return out

    @staticmethod
    def _write_pcode_jsonl(output_dir: Path, decompile_results: dict) -> dict:
        """Decompile sonuclarindan selective P-Code JSONL dosyasi yaz.

        Her satir bir fonksiyonun compact pcode verisi:
        {"n": "func_name", "a": "addr", "ops": [[mnemonic, out, ins], ...], "vars": [...]}

        v1.5: Tek decompile'dan toplanan selective ops, ~200x kucuk.
        """
        import json as _json_mod

        jsonl_path = output_dir / "pcode.jsonl"
        total_functions = 0
        total_ops = 0
        mnemonic_dist: dict[str, int] = {}

        with open(jsonl_path, "w", encoding="utf-8") as f:
            # decompile_results'tan fonksiyonlari topla
            func_results = decompile_results.get("functions", [])
            if not func_results:
                # Alternatif: decompile_results dogrudan liste olabilir
                func_results = decompile_results if isinstance(decompile_results, list) else []

            for func_data in func_results:
                if not isinstance(func_data, dict):
                    continue
                pcode_ops = func_data.get("pcode_ops", [])
                pcode_vars = func_data.get("pcode_high_vars", [])

                if not pcode_ops and not pcode_vars:
                    continue

                # Mnemonic distribution
                for op in pcode_ops:
                    if isinstance(op, (list, tuple)) and len(op) >= 1:
                        mn = op[0]
                        mnemonic_dist[mn] = mnemonic_dist.get(mn, 0) + 1

                total_functions += 1
                total_ops += len(pcode_ops)

                line = _json_mod.dumps({
                    "n": func_data.get("name", "unknown"),
                    "a": func_data.get("address", "0x0"),
                    "ops": pcode_ops,
                    "vars": pcode_vars,
                }, ensure_ascii=False)
                f.write(line + "\n")

        return {
            "program": str(output_dir.parent.name),
            "total_functions": total_functions,
            "total_pcode_ops": total_ops,
            "mode": "jsonl",
            "format": "jsonl",
            "jsonl_path": str(jsonl_path),
            "functions": [],  # Fonksiyonlar JSONL dosyasinda, burada bos
            "stats": {"mnemonic_distribution": mnemonic_dist},
        }

    @staticmethod
    def _extract_cfg(program, denetci: _AdimDenetcisi | None = None) -> dict[str, Any]:
        """Control flow graph (basic block + edge) cikar.

        Her fonksiyon icin basic block'lari ve aralarindaki
        akis kenarlarini toplar. Loop detection ve complexity
        analizi icin temel veri kaynagi.

        ÖL-2: ``denetci`` ile fonksiyon başına bütçe / olay denetimi.
        """
        from ghidra.program.model.block import BasicBlockModel
        from ghidra.util.task import ConsoleTaskMonitor

        monitor = ConsoleTaskMonitor()
        block_model = BasicBlockModel(program)
        fm = program.getFunctionManager()

        functions_data = []
        total_blocks = 0
        total_edges = 0
        BATCH_SIZE = 5000
        func_count = 0

        for func in fm.getFunctions(True):
            if monitor.isCancelled():
                break
            if denetci is not None and denetci.denetle(func_count):
                break
            func_count += 1

            try:
                body = func.getBody()
                blocks_iter = block_model.getCodeBlocksContaining(body, monitor)

                blocks_data = []
                edges_data = []
                block_addrs = set()
                listing = program.getListing()

                while blocks_iter.hasNext():
                    block = blocks_iter.next()
                    start = str(block.getFirstStartAddress())
                    end = str(block.getMaxAddress())
                    size = int(block.getNumAddresses())
                    block_addrs.add(start)

                    # Instruction sayisi + blok basina komut adlari (P11 / TIP-01:
                    # CFG-iso dugum histogrami gercek komut adlarindan kurulur).
                    instr_count = 0
                    mnemonics = []
                    instr_iter = listing.getInstructions(block, True)
                    while instr_iter.hasNext():
                        instr = instr_iter.next()
                        instr_count += 1
                        mnemonics.append(str(instr.getMnemonicString()).lower())

                    blocks_data.append({
                        "start_address": start,
                        "end_address": end,
                        "size": size,
                        "instruction_count": instr_count,
                        "mnemonics": mnemonics,
                    })

                    # Edge'ler
                    dests = block.getDestinations(monitor)
                    while dests.hasNext():
                        dest_ref = dests.next()
                        dest_block = dest_ref.getDestinationBlock()
                        if dest_block is None:
                            continue

                        dest_start = str(dest_block.getFirstStartAddress())
                        flow = dest_ref.getFlowType()

                        if flow.isCall():
                            continue

                        if flow.isFallthrough():
                            edge_type = "fall_through"
                        elif flow.isConditional():
                            edge_type = "conditional_jump"
                        elif flow.isUnConditional():
                            edge_type = "unconditional_jump"
                        else:
                            edge_type = "unknown"

                        edges_data.append({
                            "from_block": start,
                            "to_block": dest_start,
                            "edge_type": edge_type,
                        })

                n_blocks = len(blocks_data)
                n_edges = len(edges_data)
                complexity = n_edges - n_blocks + 2 if n_blocks > 0 else 0

                # Back edge heuristigi (adres-bazli: to < from ise back-edge adayi)
                back_edges = []
                loop_headers = []
                for e in edges_data:
                    to_addr = e["to_block"]
                    from_addr = e["from_block"]
                    # Hex adres karsilastirmasi icin normalize et
                    # Ghidra adresleri "00401000" gibi sabit uzunlukta hex string
                    try:
                        to_int = int(to_addr, 16)
                        from_int = int(from_addr, 16)
                    except (ValueError, TypeError):
                        continue
                    if to_int < from_int:
                        # Tuple format -- cfg_analyzer tuple(be) ile parse eder
                        back_edges.append([from_addr, to_addr])
                        if to_addr not in loop_headers:
                            loop_headers.append(to_addr)

                total_blocks += n_blocks
                total_edges += n_edges

                functions_data.append({
                    "name": func.getName(),
                    "address": str(func.getEntryPoint()),
                    "block_count": n_blocks,
                    "edge_count": n_edges,
                    "cyclomatic_complexity": complexity,
                    "blocks": blocks_data,
                    "edges": edges_data,
                    "back_edges": back_edges,
                    "loop_headers": loop_headers,
                })

            except Exception:
                logger.debug("CFG extraction basarisiz, atlaniyor", exc_info=True)
                continue

            if func_count % BATCH_SIZE == 0:
                logger.info("CFG: %d fonksiyon islendi", func_count)

        out = {
            "program": program.getName(),
            "total_functions": len(functions_data),
            "total_blocks": total_blocks,
            "total_edges": total_edges,
            "functions": functions_data,
        }
        if denetci is not None:
            out.update(denetci.kismi_alanlari())
        return out

    @staticmethod
    def _get_program_info(program) -> dict[str, Any]:
        """Program meta bilgilerini topla."""
        lang = program.getLanguage()
        compiler = program.getCompilerSpec()

        info = {
            "name": str(program.getName()),
            "language": str(lang.getLanguageID()),
            "processor": str(lang.getProcessor()),
            "endian": "big" if lang.isBigEndian() else "little",
            "address_size": lang.getDefaultSpace().getSize(),
            "compiler": str(compiler.getCompilerSpecID()),
            "executable_format": str(program.getExecutableFormat()),
            "image_base": str(program.getImageBase()),
        }

        # Memory bloklari
        memory = program.getMemory()
        blocks = []
        for block in memory.getBlocks():
            blocks.append({
                "name": block.getName(),
                "start": str(block.getStart()),
                "end": str(block.getEnd()),
                "size": block.getSize(),
                "permissions": "%s%s%s" % (
                    "r" if block.isRead() else "-",
                    "w" if block.isWrite() else "-",
                    "x" if block.isExecute() else "-",
                ),
            })
        info["memory_blocks"] = blocks

        return info

    @staticmethod
    def _resolve_gdt_path(ghidra_install: Path, gdt_name: str) -> Path | None:
        """GDT dosyasini coz: tam yolsa dogrudan, kisa isimse Ghidra typeinfo'da ara.

        Ghidra GDT arsivleri genellikle su dizinde bulunur:
          <ghidra_install>/Ghidra/Features/Base/data/typeinfo/

        Bilinen arsivler: generic_clib.gdt, generic_clib_64.gdt,
        mac_osx.gdt, windows_vs12_32.gdt, windows_vs12_64.gdt vb.

        Args:
            ghidra_install: Ghidra kurulum dizini.
            gdt_name: GDT dosya adi veya tam yolu.

        Returns:
            Path: Bulunan GDT dosya yolu, bulunamazsa None.
        """
        gdt_path = Path(gdt_name)
        if gdt_path.is_absolute() and gdt_path.exists():
            return gdt_path

        # Ghidra typeinfo dizininde ara
        typeinfo_dir = ghidra_install / "Ghidra" / "Features" / "Base" / "data" / "typeinfo"
        if typeinfo_dir.exists():
            # Direkt isimle dene
            candidate = typeinfo_dir / gdt_name
            if candidate.exists():
                return candidate
            # .gdt uzantisi yoksa ekle
            if not gdt_name.endswith(".gdt"):
                candidate = typeinfo_dir / (gdt_name + ".gdt")
                if candidate.exists():
                    return candidate
            # Alt dizinlerde recursive ara (win, mac vb.)
            for found in typeinfo_dir.rglob(gdt_name if gdt_name.endswith(".gdt") else gdt_name + ".gdt"):
                return found

        return None

    @staticmethod
    def _load_gdt_archives_pyghidra(
        program, ghidra_install: Path, gdt_paths: list[str],
    ) -> int:
        """PyGhidra modunda GDT arsivlerini programa yukle.

        DataTypeManager.openDataTypeArchive ile GDT dosyasini acar
        ve icerigini programin DataTypeManager'ina uygular.

        Args:
            program: Ghidra program nesnesi.
            ghidra_install: Ghidra kurulum dizini.
            gdt_paths: GDT dosya adi veya yollarinin listesi.

        Returns:
            int: Basariyla yuklenen arsiv sayisi.
        """
        from ghidra.program.model.data import FileDataTypeManager

        loaded = 0
        dtm = program.getDataTypeManager()

        for gdt_name in gdt_paths:
            resolved = GhidraHeadless._resolve_gdt_path(ghidra_install, gdt_name)
            if resolved is None:
                logger.warning("GDT arsivi bulunamadi: %s", gdt_name)
                continue

            try:
                # Java File nesnesi olustur
                from java.io import File as JavaFile
                gdt_file = JavaFile(str(resolved))
                archive_dtm = FileDataTypeManager.openFileArchive(gdt_file, False)

                # Arsivdeki tum tipleri programin DTM'ine kopyala
                txn_id = program.startTransaction("Apply GDT: %s" % resolved.name)
                try:
                    for dt in archive_dtm.getAllDataTypes():
                        cat_path = dt.getCategoryPath()
                        dtm.addDataType(dt, None)  # None = default handler (keep existing)
                finally:
                    program.endTransaction(txn_id, True)

                archive_dtm.close()
                loaded += 1
                logger.info("GDT arsivi yuklendi: %s (%s)", resolved.name, resolved)
            except Exception as exc:
                logger.warning("GDT arsivi yuklenemedi: %s: %s", gdt_name, exc)

        return loaded

    def _load_pdb_if_available(self, program, binary_path: Path) -> bool:
        """Windows PE icin PDB dosyasini otomatik yukle.

        binary_path ile ayni dizinde veya config.binary_reconstruction.pdb_search_paths
        icinde .pdb dosyasi arar. Bulursa Ghidra program options'a PDB yolunu
        set eder, boylece PDB analyzer yeniden analiz sirasinda kullabilir.

        Args:
            program: Ghidra Program nesnesi.
            binary_path: Analiz edilen binary'nin yolu.

        Returns:
            True: PDB bulundu ve yuklendi. False: PDB bulunamadi veya hata.
        """
        pdb_path = None
        stem = binary_path.stem

        # 1. Binary ile ayni dizinde ara
        candidate = binary_path.with_suffix(".pdb")
        if candidate.exists():
            pdb_path = candidate

        # 2. Config'deki ek arama dizinlerinde ara
        if pdb_path is None:
            for search_dir in self.config.binary_reconstruction.pdb_search_paths:
                candidate = Path(search_dir) / (stem + ".pdb")
                if candidate.exists():
                    pdb_path = candidate
                    break

        if pdb_path is None:
            logger.debug("PDB dosyasi bulunamadi: %s.pdb", stem)
            return False

        logger.info("PDB bulundu: %s", pdb_path)

        try:
            # Ghidra program options'a PDB yolunu set et.
            # PdbUniversalAnalyzer bu opsiyonu okuyarak PDB'yi yukler.
            opts = program.getOptions("Program Information")
            txn_id = program.startTransaction("Set PDB path")
            try:
                opts.setString("PDB File", str(pdb_path.resolve()))
                program.endTransaction(txn_id, True)
            except Exception:
                program.endTransaction(txn_id, False)
                raise

            # Opsiyonel: PdbUniversalAnalyzer'i programatik calistir
            try:
                from ghidra.app.plugin.core.analysis import (
                    PdbUniversalAnalyzer,
                )
                from ghidra.app.util.importer import MessageLog
                from ghidra.util.task import TaskMonitor

                analyzer = PdbUniversalAnalyzer()
                msg_log = MessageLog()
                monitor = TaskMonitor.DUMMY

                # Analyzer'in programi kabul edip etmedigini kontrol et
                if analyzer.canAnalyze(program):
                    txn_id = program.startTransaction("PDB Analysis")
                    try:
                        analyzer.added(
                            program,
                            program.getMemory().getLoadedAndInitializedAddressSet(),
                            monitor,
                            msg_log,
                        )
                        program.endTransaction(txn_id, True)
                        logger.info(
                            "PDB analyzer calistirildi: %s", pdb_path.name,
                        )
                    except Exception:
                        program.endTransaction(txn_id, False)
                        raise
            except ImportError:
                # PdbUniversalAnalyzer import edilemezse sadece path set edilmis
                # olur, AutoAnalysis sirasinda kullanilir
                logger.debug(
                    "PdbUniversalAnalyzer import edilemedi, "
                    "sadece PDB path set edildi"
                )

            return True

        except Exception as exc:
            logger.warning("PDB yukleme hatasi (%s): %s", pdb_path, exc)
            return False

    @staticmethod
    def _extract_function_id_matches(
        program, denetci: _AdimDenetcisi | None = None,
    ) -> dict[str, Any]:
        """Ghidra FunctionID eslesmelerini topla (ÖL-2: ``denetci`` ile fonksiyon başına denetim).

        Ghidra'nin otomatik FunctionID analizinden sonra, FUN_ ile baslamayan
        ve source'u ANALYSIS olan fonksiyonlari toplar. Bu fonksiyonlar
        Ghidra'nin FunctionID veritabanindaki bilinen kutuphane fonksiyonlariyla
        eslesmistir.

        Args:
            program: Ghidra Program nesnesi.

        Returns:
            dict: {"total_matches": N, "matches": [...]}
        """
        try:
            from ghidra.program.model.symbol import SourceType
        except ImportError:
            # Ghidra JVM baslatilmamissa (test ortami vb.)
            return {"total_matches": 0, "matches": [], "error": "SourceType import edilemedi"}

        fm = program.getFunctionManager()
        matches = []

        islenen = 0
        for func in fm.getFunctions(True):
            if denetci is not None and denetci.denetle(islenen):
                break
            islenen += 1
            name = func.getName()

            # FUN_ ile baslayan isimler Ghidra default -- FunctionID tarafindan
            # tanINMAMIS demektir, bunlari atla
            if name.startswith("FUN_"):
                continue

            sym = func.getSymbol()
            if sym is None:
                continue

            source = sym.getSource()

            # SourceType.ANALYSIS: Ghidra analiz asamasinda atanmis isim
            # (FunctionID, DWARF, PDB vb.)
            if source != SourceType.ANALYSIS:
                continue

            entry = {
                "name": name,
                "address": str(func.getEntryPoint()),
                "library": "",
            }

            # Library bilgisini comment veya plate comment'ten cikar (varsa)
            comment = func.getComment()
            if comment:
                entry["library"] = comment
            else:
                plate = func.getCommentAsArray(
                    func.PLATE_COMMENT
                ) if hasattr(func, "PLATE_COMMENT") else None
                if plate:
                    entry["library"] = "\n".join(str(line) for line in plate)

            matches.append(entry)

        out: dict[str, Any] = {
            "total_matches": len(matches),
            "matches": matches,
        }
        if denetci is not None:
            out.update(denetci.kismi_alanlari())
        return out

    @staticmethod
    def _save_output(output_dir: Path, filename: str, data: dict) -> None:
        """JSON sonucunu dosyaya kaydet."""
        filepath = output_dir / filename
        filepath.write_text(
            json.dumps(data, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )

    # ------------------------------------------------------------------
    # CLI fallback
    # ------------------------------------------------------------------

    def _analyze_cli(
        self,
        binary_path: Path,
        project_dir: Path,
        project_name: str,
        scripts: list[Path] | None,
        timeout: int,
        output_dir: Path,
    ) -> dict[str, Any]:
        """analyzeHeadless CLI ile analiz (fallback)."""
        cmd: list[str] = [
            str(self.analyze_headless),
            str(project_dir),
            project_name,
            "-import", str(binary_path),
            "-max-cpu", str(CPU_PERF_CORES),
            "-analysisTimeoutPerFile", str(timeout),
            "-deleteProject",
        ]

        ghidra_scripts_dir = self.config.ghidra_scripts_dir
        if ghidra_scripts_dir.exists():
            cmd.extend(["-scriptPath", str(ghidra_scripts_dir)])

        # GDT Data Type Archive'lari -- preScript olarak yukle
        ghidra_install = self.analyze_headless.parent.parent
        gdt_paths = self.config.binary_reconstruction.ghidra_data_type_archives
        for gdt_name in gdt_paths:
            resolved = self._resolve_gdt_path(ghidra_install, gdt_name)
            if resolved is not None:
                # Ghidra CLI: -preScript ile GDT yuklenir.
                # ApplyDataTypeArchive.py Ghidra built-in script'i GDT dosyasini alir.
                cmd.extend(["-preScript", "ApplyDataTypeArchive.py", str(resolved)])
                logger.info("CLI GDT arsivi eklendi: %s", resolved)
            else:
                logger.warning("CLI GDT arsivi bulunamadi: %s", gdt_name)

        if scripts:
            for script in scripts:
                cmd.extend(["-postScript", str(script)])

        # v1.10.0 Batch 5B HIGH-10: Ghidra scripts'i icinde path traversal
        # koruma. KARADUL_WORKSPACE_ROOT env'i script'lere hangi dizinin
        # disina cikilamayacagini soyler; script'ler get_output_dir icinde
        # Path.relative_to(workspace_root) check yapar.
        workspace_root = str(Path(output_dir).resolve().parent)
        env = {
            "KARADUL_OUTPUT": str(output_dir),
            "KARADUL_WORKSPACE_ROOT": workspace_root,
            "_JAVA_OPTIONS": (
                f"-Xmx{self.config.analysis.ghidra_max_heap_mb}m "
                f"-XX:+UseG1GC -XX:ParallelGCThreads={CPU_PERF_CORES} "
                f"-XX:ConcGCThreads={max(1, CPU_PERF_CORES // 2)} "
                f"-XX:+UseCompressedOops"
            ),
        }

        logger.info(
            "Ghidra headless (CLI) baslatiliyor: %s (timeout=%ds)",
            binary_path.name, timeout,
        )

        start = time.monotonic()
        result = self.runner.run_command(
            cmd, timeout=timeout + 60, env=env,
        )
        duration = time.monotonic() - start

        scripts_output = self._collect_outputs(output_dir)
        ghidra_log = result.stdout + "\n" + result.stderr

        # GHIDRA-08: analyzeHeadless betik hatasında ya da Python betiği hiç koşmadığında da
        # (Ghidra 12'de Python 3 betikleri yalnız PyGhidra ile koşar) 0 ile çıkabilir. Başarı
        # çıkış koduyla değil, PyGhidra yoluyla aynı kuralla (_judge_outcome) ölçülür.
        step_errors: dict[str, str] = {}
        if not result.success:
            step_errors["fatal"] = "analyzeHeadless çıkış kodu %s; son satır: %s" % (
                result.returncode, self._last_log_line(ghidra_log),
            )
        missing = [k for k in self.CLI_EXPECTED_OUTPUTS if k not in scripts_output]
        if result.success and "functions" in missing:
            step_errors["functions"] = (
                "betik çıktısı yok (%s); Ghidra 12'de analyzeHeadless Python 3 betiklerini "
                "yalnız PyGhidra ile çalıştırır (pyghidra içe aktarılamadı). Son satır: %s"
                % (", ".join(missing), self._last_log_line(ghidra_log))
            )
        if missing:
            logger.warning("analyzeHeadless beklenen ciktilari uretmedi: %s", ", ".join(missing))
        success, error = self._judge_outcome(scripts_output, step_errors)

        return {
            "success": success,
            "error": error,
            "step_errors": step_errors,
            "missing_outputs": missing,
            "scripts_output": scripts_output,
            "ghidra_log": ghidra_log,
            "duration_seconds": round(duration, 3),
            "mode": "cli",
            "returncode": result.returncode,
        }

    # analyzeHeadless yolunda varlığı beklenen betik çıktıları (PyGhidra yolunun anahtarları).
    CLI_EXPECTED_OUTPUTS = ("functions", "strings", "call_graph", "decompiled", "xrefs")

    @staticmethod
    def _last_log_line(log: str) -> str:
        lines = [ln.strip() for ln in (log or "").splitlines() if ln.strip()]
        return lines[-1][:300] if lines else "(günlük boş)"

    @staticmethod
    def _collect_outputs(output_dir: Path) -> dict[str, Any]:
        """Script cikti dizinindeki JSON dosyalarini topla."""
        result: dict[str, Any] = {}
        if output_dir.exists():
            for json_file in sorted(output_dir.glob("*.json")):
                # GHIDRA-08: cfg_extraction / pcode_analysis betikleri ghidra_cfg.json /
                # ghidra_pcode.json yazar; PyGhidra yolunun anahtarı cfg / pcode. Önek
                # soyulmazsa static'te ghidra_ghidra_cfg.json olur ve aşağı akış bulamaz.
                key = json_file.stem
                if key.startswith("ghidra_"):
                    key = key[len("ghidra_"):]
                try:
                    data = json.loads(json_file.read_text(encoding="utf-8"))
                    result[key] = data
                except (json.JSONDecodeError, OSError) as exc:
                    logger.warning(
                        "Script ciktisi okunamadi: %s: %s", json_file.name, exc,
                    )
                    result[key] = {"error": str(exc)}
        return result

    # ------------------------------------------------------------------
    # Utility metodlar
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Ghidra mevcut mu kontrol et."""
        return self.analyze_headless.exists() or _check_pyghidra()

    def get_version(self) -> str | None:
        """Ghidra versiyonunu al."""
        try:
            ghidra_root = self.analyze_headless.parent.parent
            dir_name = ghidra_root.name
            match = re.search(r"ghidra_(\d+\.\d+(?:\.\d+)?)", dir_name)
            if match:
                return match.group(1)
        except (AttributeError, IndexError):
            pass
        return None

    def get_default_scripts(self) -> list[Path]:
        """Varsayilan Ghidra betiklerinin listesini dondur (yalnız analyzeHeadless yolu).

        Betikler PyGhidra 3 / Python 3'tür. Jython 2.7 yedekleri (``scripts/legacy/``)
        2026-11-18'de silindi (K-3 A2): sabitlenen Ghidra 12.1.2'de Jython yok, betik
        yükleyici o dizini yalnız ``perf.use_legacy_jython_scripts`` açıkken okuyordu.
        Bayrak açık bırakılmışsa etkisizdir ve uyarı yazılır.
        """
        scripts_dir = self.config.ghidra_scripts_dir
        if getattr(self.config.perf, "use_legacy_jython_scripts", False):
            logger.warning(
                "perf.use_legacy_jython_scripts etkisiz: Jython yedekleri kaldirildi "
                "(Ghidra 12.1.2'de Jython yok); Python 3 betikleri kullaniliyor",
            )

        ordered_names = [
            "function_lister.py",
            "string_extractor.py",
            "call_graph.py",
            "decompile_all.py",
            "type_recovery.py",
            "xref_analysis.py",
            "pcode_analysis.py",
            "cfg_extraction.py",
            "function_id_extractor.py",
            "export_results.py",
        ]
        return [scripts_dir / n for n in ordered_names if (scripts_dir / n).exists()]

    @staticmethod
    def pyghidra_available() -> bool:
        """PyGhidra mevcut mu?"""
        return _check_pyghidra()
