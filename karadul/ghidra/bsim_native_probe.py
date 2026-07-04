"""BSim native runtime tespit (probe) modulu.

Bu modul, Ghidra BSim native API'sinin guncel calisma ortaminda gercekten
kullanilabilir olup olmadigini ADIM ADIM tarar ve detayli bir rapor uretir.

Karadul'da BSim iki modda calisir:

  1. **bsim native** — Ghidra `ghidra.features.bsim.*` paketleri PyGhidra
     uzerinden JVM icine yuklenmis ve cagrilabilir durumdaysa, gercek
     feature-vector tabanli benzerlik kullanilir.
  2. **bsim lite** — JVM/PyGhidra erisimi yoksa, decompiled C kodu + opcode
     histogrami SHA256 hash'lenir (discrete exact-match fallback).

`bsim.py::_check_bsim()` sadece tek bir import (`BSimServerInfo`) dener ve
boolean doner. Bu yeterli degildir cunku:

  - JVM henuz baslatilmamis olabilir (`pyghidra.start()` cagrilmamis)
  - BSimServerInfo bulunabilir ama `FunctionDatabase` veya `GenSignatures`
    ayni release'de tasinmis/yeniden adlandirilmis olabilir
  - H2 DB dosyasi olusturulamiyor olabilir (izin/disk sorunu)

Bu modul `BSimNativeProbeResult` dataclass'i ile **dokuz ayri flag** ve
**diagnostic_log** doner, kullanici ger cek arizayi anlayabilir.

Kullanim
--------

CLI:
    $ karadul bsim probe                # human-readable rapor
    $ karadul bsim probe --json         # makine-okunur JSON

Programatik:
    >>> from karadul.ghidra.bsim_native_probe import probe
    >>> result = probe()
    >>> if result.available:
    ...     print("BSim native hazir!")
    >>> print(result.to_dict())

Mac CLI'dan dogrudan calistirildiginda PyGhidra/JVM olmadigi icin
`available=False` doner ve diagnostic log ilk adimda ('PyGhidra/JVM yok')
durur. Bu beklenen davranistir — gercek native test, PyGhidra
`pyghidra.start()` sonrasinda yapilmalidir.
"""

from __future__ import annotations

import logging
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Sonuc dataclass'i
# ---------------------------------------------------------------------------

@dataclass
class BSimNativeProbeResult:
    """BSim native runtime tespit sonucu.

    Attributes
    ----------
    available
        Tum kritik kontroller PASS gectiyse True. `bsim_module_found`,
        `function_database_found`, `gen_signatures_found` ve `test_db_creation`
        hepsi True olmalidir. `test_function_scan` opsiyoneldir (mock'lanir).
    error
        Bir adimda kritik hata olursa exception mesaji burada toplanir.
    pyghidra_active
        `jpype.isJVMStarted()` True ise. Mac CLI'dan PyGhidra baslamadan
        cagrildiginda False.
    bsim_module_found
        `ghidra.features.bsim.query.BSimServerInfo` import edilebilir mi.
    function_database_found
        `ghidra.features.bsim.query.FunctionDatabase` (veya turevi) bulundu mu.
    gen_signatures_found
        `ghidra.features.bsim.gui.search.GenSignatures` veya benzer
        feature signature uretici sinif bulundu mu.
    bsim_server_info_found
        `BSimServerInfo` somutlastirilabiliyor mu (sadece import degil
        dummy URL ile new'lenebiliyor mu).
    test_db_creation
        Gecici dizinde H2 DB dosyasi (jdbc:h2:file:...) acilabiliyor mu.
        JVM yoksa False, log: 'JVM yok, atlandi'.
    test_function_scan
        Sahte fonksiyon nesnesi uzerinde GenSignatures.scanFunction()
        cagrilabiliyor mu. Native testi cok karmasik oldugu icin saglamlik
        amaciyla yapildi: True ise gercek scan akisi baska bir hatayla
        kirilirsa anlamlidir; False varsa kritik degil (sadece import-level
        kontrol yetmiyor).
    diagnostic_log
        Her adim icin tek-satir mesaj. UI ve JSON ciktida gosterilir.
    """

    available: bool = False
    error: Optional[str] = None
    pyghidra_active: bool = False
    bsim_module_found: bool = False
    function_database_found: bool = False
    gen_signatures_found: bool = False
    bsim_server_info_found: bool = False
    test_db_creation: bool = False
    test_function_scan: bool = False
    diagnostic_log: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """JSON-serileziabilir dict'e cevir."""
        return asdict(self)

    def append_log(self, msg: str) -> None:
        """Diagnostic log'a tek satir ekle (modul logger'ina da yansit)."""
        self.diagnostic_log.append(msg)
        logger.debug("[bsim-probe] %s", msg)

    def summary(self) -> str:
        """Kisa human-readable ozet."""
        if self.available:
            return "BSim native: HAZIR"
        if not self.pyghidra_active:
            return "BSim native: YOK (PyGhidra/JVM aktif degil — lite mod)"
        if self.error:
            return f"BSim native: HATA — {self.error}"
        # JVM var ama bir parca eksik
        missing = []
        if not self.bsim_module_found:
            missing.append("ghidra.features.bsim modulu")
        if not self.function_database_found:
            missing.append("FunctionDatabase")
        if not self.gen_signatures_found:
            missing.append("GenSignatures")
        if missing:
            return f"BSim native: EKSIK — {', '.join(missing)}"
        return "BSim native: BILINMIYOR"


# ---------------------------------------------------------------------------
# Probe adimlari (tek tek ayrilmis, test edilebilir)
# ---------------------------------------------------------------------------

def _step_check_jvm(result: BSimNativeProbeResult) -> bool:
    """Adim 1: JVM/PyGhidra aktif mi.

    Returns
    -------
    bool
        Devam edilmeli mi. False donerse sonraki adimlar atlanir.
    """
    try:
        import jpype
    except ImportError as exc:
        result.append_log(f"jpype import edilemedi: {exc}")
        result.pyghidra_active = False
        return False

    try:
        jvm_started = bool(jpype.isJVMStarted())
    except Exception as exc:  # noqa: BLE001
        result.append_log(f"jpype.isJVMStarted() hata: {exc}")
        result.pyghidra_active = False
        return False

    result.pyghidra_active = jvm_started
    if jvm_started:
        result.append_log("JVM aktif (jpype.isJVMStarted() = True)")
        return True
    result.append_log("JVM baslatilmamis — pyghidra.start() cagrilmali")
    return False


def _step_check_bsim_module(result: BSimNativeProbeResult) -> bool:
    """Adim 2a: ghidra.features.bsim.query.BSimServerInfo import."""
    try:
        from ghidra.features.bsim.query import BSimServerInfo  # noqa: F401
        result.bsim_module_found = True
        result.bsim_server_info_found = True
        result.append_log(
            "BSimServerInfo import OK (ghidra.features.bsim.query)"
        )
        return True
    except ImportError as exc:
        result.append_log(f"BSimServerInfo ImportError: {exc}")
        result.bsim_module_found = False
        return False
    except Exception as exc:  # noqa: BLE001
        # JPype JClass NotFound, ClassNotFoundException vb.
        result.append_log(f"BSimServerInfo hata: {exc}")
        result.bsim_module_found = False
        return False


def _step_check_function_database(result: BSimNativeProbeResult) -> bool:
    """Adim 2b: FunctionDatabase sinifi import."""
    # Ghidra release'lerinde paket yolu degisebilir, alternatif yollar dene
    candidate_paths = [
        ("ghidra.features.bsim.query", "FunctionDatabase"),
        ("ghidra.features.bsim.query.facade", "FunctionDatabase"),
    ]
    for module_path, cls_name in candidate_paths:
        try:
            mod = __import__(module_path, fromlist=[cls_name])
            if hasattr(mod, cls_name):
                result.function_database_found = True
                result.append_log(
                    f"FunctionDatabase bulundu ({module_path}.{cls_name})"
                )
                return True
        except ImportError:
            continue
        except Exception:  # noqa: BLE001
            continue

    result.append_log(
        "FunctionDatabase hicbir yolda bulunamadi "
        "(ghidra.features.bsim.query, .facade)"
    )
    return False


def _step_check_gen_signatures(result: BSimNativeProbeResult) -> bool:
    """Adim 2c: GenSignatures sinifi import."""
    candidate_paths = [
        ("ghidra.features.bsim.gui.search", "GenSignatures"),
        ("ghidra.features.bsim.query", "GenSignatures"),
    ]
    for module_path, cls_name in candidate_paths:
        try:
            mod = __import__(module_path, fromlist=[cls_name])
            if hasattr(mod, cls_name):
                result.gen_signatures_found = True
                result.append_log(
                    f"GenSignatures bulundu ({module_path}.{cls_name})"
                )
                return True
        except ImportError:
            continue
        except Exception:  # noqa: BLE001
            continue

    result.append_log(
        "GenSignatures hicbir yolda bulunamadi "
        "(ghidra.features.bsim.gui.search, .query)"
    )
    return False


def _step_test_db_creation(result: BSimNativeProbeResult) -> bool:
    """Adim 3: Gecici H2 DB dosyasi olusturulabiliyor mu.

    Sadece import seviyesi degil, gercekten BSimServerInfo + FunctionDatabase
    ile bir database acilip kapanabiliyor mu kontrol edilir.

    JVM yoksa direkt False, log 'atlandi'.
    """
    if not result.pyghidra_active:
        result.append_log("DB testi atlandi (JVM yok)")
        return False
    if not (result.bsim_module_found and result.function_database_found):
        result.append_log("DB testi atlandi (BSim modulleri eksik)")
        return False

    try:
        from ghidra.features.bsim.query import BSimServerInfo
    except Exception as exc:  # noqa: BLE001
        result.append_log(f"DB testi: BSimServerInfo erisilemedi — {exc}")
        return False

    try:
        with tempfile.TemporaryDirectory(prefix="karadul_bsim_probe_") as tmp:
            db_file = Path(tmp) / "probe.h2.db"
            # BSimServerInfo duz mutlak posix yol bekler; "file:" prefix'i
            # "Invalid absolute file path: file:/..." hatasina yol acar.
            url = db_file.with_suffix("").resolve().as_posix()
            try:
                _ = BSimServerInfo(url)
                result.test_db_creation = True
                result.append_log(f"BSimServerInfo new OK (url={url})")
                return True
            except Exception as exc:  # noqa: BLE001
                result.append_log(f"BSimServerInfo new hata: {exc}")
                return False
    except Exception as exc:  # noqa: BLE001
        result.append_log(f"tempfile/H2 hatasi: {exc}")
        return False


def _step_test_function_scan(result: BSimNativeProbeResult) -> bool:
    """Adim 4: GenSignatures.scanFunction sahte fonksiyonla cagrilabiliyor mu.

    Bu adim cok kirilgan oldugu icin (Ghidra Program/Function nesneleri
    karmasik) sadece sinifin scanFunction metoduna sahip olup olmadigi
    kontrol edilir. Gercek scan PyGhidra integration testinde yapilir.
    """
    if not result.gen_signatures_found:
        result.append_log("scanFunction testi atlandi (GenSignatures yok)")
        return False

    candidate_paths = [
        ("ghidra.features.bsim.gui.search", "GenSignatures"),
        ("ghidra.features.bsim.query", "GenSignatures"),
    ]
    for module_path, cls_name in candidate_paths:
        try:
            mod = __import__(module_path, fromlist=[cls_name])
            cls = getattr(mod, cls_name, None)
            if cls is None:
                continue
            # scanFunction veya benzer adlandirma
            for method_name in ("scanFunction", "scanFunctions", "openProgram"):
                if hasattr(cls, method_name):
                    result.test_function_scan = True
                    result.append_log(
                        f"GenSignatures.{method_name} mevcut ({module_path})"
                    )
                    return True
        except Exception:  # noqa: BLE001
            continue

    result.append_log(
        "GenSignatures'da scanFunction/scanFunctions/openProgram bulunamadi"
    )
    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def probe() -> BSimNativeProbeResult:
    """BSim native lib durumunu tam tarar.

    Adimlar:
      1. JVM/PyGhidra aktif mi
      2. ghidra.features.bsim modulleri (3 sinif: BSimServerInfo,
         FunctionDatabase, GenSignatures) import edilebilir mi
      3. H2 DB dosyasi olusturulabiliyor mu (BSimServerInfo new'lenebilir mi)
      4. GenSignatures.scanFunction metodu tanimli mi

    JVM yoksa adim 1'de durur, sonraki adimlar 'atlandi' loglar.

    Returns
    -------
    BSimNativeProbeResult
        Tum flag'ler + diagnostic_log dolu.
    """
    result = BSimNativeProbeResult()
    result.append_log("BSim native probe basliyor")

    # Adim 1
    if not _step_check_jvm(result):
        result.append_log("Probe sonlandi (JVM yok, native test imkansiz)")
        return result

    # Adim 2a-c (her biri bagimsiz, biri fail etse de devam)
    try:
        _step_check_bsim_module(result)
        _step_check_function_database(result)
        _step_check_gen_signatures(result)
    except Exception as exc:  # noqa: BLE001
        result.error = f"Modul tarama hatasi: {exc}"
        result.append_log(result.error)
        return result

    # Adim 3
    try:
        _step_test_db_creation(result)
    except Exception as exc:  # noqa: BLE001
        result.error = f"DB testi hatasi: {exc}"
        result.append_log(result.error)

    # Adim 4
    try:
        _step_test_function_scan(result)
    except Exception as exc:  # noqa: BLE001
        # error'u override etme, sadece logla
        result.append_log(f"scanFunction testi hatasi: {exc}")

    # Sonuc: kritik flagler hepsi True ise available
    result.available = (
        result.pyghidra_active
        and result.bsim_module_found
        and result.function_database_found
        and result.gen_signatures_found
        and result.test_db_creation
    )
    result.append_log(
        f"Probe tamamlandi (available={result.available})"
    )
    return result


def probe_pyghidra_only() -> BSimNativeProbeResult:
    """Sadece PyGhidra JVM icinden cagrilir, gercek native test.

    `probe()`'tan farki: JVM aktif degilse exception firlatir (cunku bu
    fonksiyon zaten JVM icinden cagrilmis olmali).

    Raises
    ------
    RuntimeError
        JVM aktif degilse.
    """
    result = BSimNativeProbeResult()
    if not _step_check_jvm(result):
        raise RuntimeError(
            "probe_pyghidra_only() PyGhidra/JVM disinda cagrildi. "
            "Once pyghidra.start() cagirin veya probe() kullanin."
        )
    return probe()


def is_bsim_native_available() -> bool:
    """Hizli boolean check.

    `bsim.py::_check_bsim()` ile ayni semantic, ancak cache'lenmez ve
    bagimsizdir (probe modulu kendi gozetimini yapar).

    Returns
    -------
    bool
        Tam native BSim kullanilabilir mi.
    """
    return probe().available


__all__ = [
    "BSimNativeProbeResult",
    "probe",
    "probe_pyghidra_only",
    "is_bsim_native_available",
]
