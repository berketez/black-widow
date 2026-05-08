"""BSim native probe modulu testleri.

PyGhidra ve Ghidra import'lari yok — tum jpype/ghidra cagrilari mock'lanir.
Mac CLI ortaminda probe()'un dogru sekilde 'JVM yok' raporu uretmesi
ve mock'lu senaryolarda her flag'i dogru ayarlamasi test edilir.
"""

from __future__ import annotations

import sys
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

from karadul.ghidra.bsim_native_probe import (
    BSimNativeProbeResult,
    _step_check_bsim_module,
    _step_check_function_database,
    _step_check_gen_signatures,
    _step_check_jvm,
    _step_test_db_creation,
    _step_test_function_scan,
    is_bsim_native_available,
    probe,
    probe_pyghidra_only,
)


# ---------------------------------------------------------------------------
# Yardimci: sahte ghidra.* modullerini sys.modules'a enjekte et
# ---------------------------------------------------------------------------

def _install_fake_ghidra_modules(
    *,
    bsim_query: bool = True,
    function_database: bool = True,
    gen_signatures: bool = True,
    server_info_constructor_ok: bool = True,
    scan_function_method: bool = True,
) -> dict[str, ModuleType]:
    """Sahte ghidra.features.bsim.* modullerini sys.modules'a yerlestir.

    Returns: enjekte edilen modul adlarinin map'i (cleanup icin).
    """
    installed: dict[str, ModuleType] = {}

    # ghidra paketi (boyutu sirala)
    for pkg in [
        "ghidra",
        "ghidra.features",
        "ghidra.features.bsim",
        "ghidra.features.bsim.query",
        "ghidra.features.bsim.gui",
        "ghidra.features.bsim.gui.search",
    ]:
        if pkg not in sys.modules:
            mod = ModuleType(pkg)
            sys.modules[pkg] = mod
            installed[pkg] = mod

    if bsim_query:
        query_mod = sys.modules["ghidra.features.bsim.query"]

        if server_info_constructor_ok:
            class FakeBSimServerInfo:
                def __init__(self, url: str) -> None:
                    self.url = url
        else:
            class FakeBSimServerInfo:  # type: ignore[no-redef]
                def __init__(self, url: str) -> None:
                    raise RuntimeError("URL olusturulamadi (mock fail)")

        query_mod.BSimServerInfo = FakeBSimServerInfo  # type: ignore[attr-defined]

        if function_database:
            class FakeFunctionDatabase:
                pass

            query_mod.FunctionDatabase = FakeFunctionDatabase  # type: ignore[attr-defined]

    if gen_signatures:
        search_mod = sys.modules["ghidra.features.bsim.gui.search"]

        if scan_function_method:
            class FakeGenSignatures:
                def scanFunction(self) -> None:
                    pass
        else:
            class FakeGenSignatures:  # type: ignore[no-redef]
                pass

        search_mod.GenSignatures = FakeGenSignatures  # type: ignore[attr-defined]

    return installed


def _cleanup_fake_modules() -> None:
    """Test sonrasi enjekte edilen modulleri temizle."""
    for pkg in [
        "ghidra.features.bsim.gui.search",
        "ghidra.features.bsim.gui",
        "ghidra.features.bsim.query",
        "ghidra.features.bsim",
        "ghidra.features",
        "ghidra",
    ]:
        sys.modules.pop(pkg, None)


@pytest.fixture
def cleanup_ghidra():
    """Test sonrasi sahte modulleri her durumda temizle."""
    yield
    _cleanup_fake_modules()


# ---------------------------------------------------------------------------
# Test 1: smoke — probe() cagrilabilir, dataclass doner
# ---------------------------------------------------------------------------

def test_probe_smoke_returns_dataclass() -> None:
    """probe() cagrilabilir ve BSimNativeProbeResult doner."""
    result = probe()
    assert isinstance(result, BSimNativeProbeResult)
    assert isinstance(result.diagnostic_log, list)
    assert len(result.diagnostic_log) >= 1, "Diagnostic log bos olmamali"
    # to_dict serialize edilebilir
    d = result.to_dict()
    assert isinstance(d, dict)
    assert "available" in d
    assert "diagnostic_log" in d


# ---------------------------------------------------------------------------
# Test 2: PyGhidra/JVM yok senaryosu (Mac CLI gercegi)
# ---------------------------------------------------------------------------

def test_probe_no_jvm() -> None:
    """jpype yoksa veya JVM baslatilmamissa available=False."""
    fake_jpype = MagicMock()
    fake_jpype.isJVMStarted.return_value = False

    with patch.dict(sys.modules, {"jpype": fake_jpype}):
        result = probe()

    assert result.available is False
    assert result.pyghidra_active is False
    # JVM yoksa sonraki adimlar False olmali
    assert result.bsim_module_found is False
    assert result.function_database_found is False
    assert result.gen_signatures_found is False
    assert result.test_db_creation is False
    # Diagnostic log JVM yoksa duruyor
    log_text = " | ".join(result.diagnostic_log)
    assert "JVM" in log_text or "jpype" in log_text


def test_probe_jpype_import_error() -> None:
    """jpype paketi yuklu degilse available=False, pyghidra_active=False."""
    # jpype'i ImportError'a zorla
    real_import = __import__

    def fake_import(name, *args, **kwargs):
        if name == "jpype":
            raise ImportError("Mock: jpype not installed")
        return real_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=fake_import):
        result = probe()

    assert result.available is False
    assert result.pyghidra_active is False
    log_text = " | ".join(result.diagnostic_log)
    assert "jpype" in log_text.lower()


# ---------------------------------------------------------------------------
# Test 3: JVM var ama BSim modulu yok
# ---------------------------------------------------------------------------

def test_probe_jvm_active_no_bsim_module(cleanup_ghidra: None) -> None:
    """JVM var ama ghidra.features.bsim import edilemiyor."""
    fake_jpype = MagicMock()
    fake_jpype.isJVMStarted.return_value = True
    # ghidra modullerini hic enjekte etme — import ImportError firlatacak

    with patch.dict(sys.modules, {"jpype": fake_jpype}):
        result = probe()

    assert result.pyghidra_active is True
    assert result.bsim_module_found is False
    assert result.available is False
    log_text = " | ".join(result.diagnostic_log)
    assert "BSimServerInfo" in log_text or "ImportError" in log_text


# ---------------------------------------------------------------------------
# Test 4: Tum modullerle TAM BASARI senaryosu
# ---------------------------------------------------------------------------

def test_probe_all_modules_available(cleanup_ghidra: None) -> None:
    """JVM + tum BSim modulleri mevcut → available=True."""
    fake_jpype = MagicMock()
    fake_jpype.isJVMStarted.return_value = True
    _install_fake_ghidra_modules(
        bsim_query=True,
        function_database=True,
        gen_signatures=True,
        server_info_constructor_ok=True,
        scan_function_method=True,
    )

    with patch.dict(sys.modules, {"jpype": fake_jpype}):
        result = probe()

    assert result.pyghidra_active is True
    assert result.bsim_module_found is True
    assert result.function_database_found is True
    assert result.gen_signatures_found is True
    assert result.bsim_server_info_found is True
    assert result.test_db_creation is True
    assert result.test_function_scan is True
    assert result.available is True
    assert result.error is None


# ---------------------------------------------------------------------------
# Test 5: GenSignatures eksik → kismi basari
# ---------------------------------------------------------------------------

def test_probe_gen_signatures_missing(cleanup_ghidra: None) -> None:
    """BSim ve FunctionDatabase var ama GenSignatures yok."""
    fake_jpype = MagicMock()
    fake_jpype.isJVMStarted.return_value = True
    _install_fake_ghidra_modules(
        bsim_query=True,
        function_database=True,
        gen_signatures=False,  # bu yok
    )

    with patch.dict(sys.modules, {"jpype": fake_jpype}):
        result = probe()

    assert result.pyghidra_active is True
    assert result.bsim_module_found is True
    assert result.function_database_found is True
    assert result.gen_signatures_found is False
    # available False cunku GenSignatures kritik
    assert result.available is False


# ---------------------------------------------------------------------------
# Test 6: BSimServerInfo new() exception → test_db_creation False
# ---------------------------------------------------------------------------

def test_probe_db_creation_fails(cleanup_ghidra: None) -> None:
    """BSimServerInfo somutlastirma fail olursa test_db_creation False."""
    fake_jpype = MagicMock()
    fake_jpype.isJVMStarted.return_value = True
    _install_fake_ghidra_modules(
        bsim_query=True,
        function_database=True,
        gen_signatures=True,
        server_info_constructor_ok=False,  # constructor exception firlatacak
    )

    with patch.dict(sys.modules, {"jpype": fake_jpype}):
        result = probe()

    assert result.pyghidra_active is True
    assert result.bsim_module_found is True
    # constructor fail oldu
    assert result.test_db_creation is False
    assert result.available is False


# ---------------------------------------------------------------------------
# Test 7: Diagnostic log her adim icin entry icermeli
# ---------------------------------------------------------------------------

def test_probe_diagnostic_log_populated(cleanup_ghidra: None) -> None:
    """Probe sonrasi diagnostic_log birden fazla entry icermeli."""
    fake_jpype = MagicMock()
    fake_jpype.isJVMStarted.return_value = True
    _install_fake_ghidra_modules()

    with patch.dict(sys.modules, {"jpype": fake_jpype}):
        result = probe()

    # En az 5 satir log: basla, JVM OK, BSim OK, FunctionDatabase OK,
    # GenSignatures OK, DB testi, scanFunction, tamam
    assert len(result.diagnostic_log) >= 5
    log_text = "\n".join(result.diagnostic_log)
    assert "basliyor" in log_text.lower() or "probe" in log_text.lower()
    assert "tamamlandi" in log_text.lower()


# ---------------------------------------------------------------------------
# Test 8: to_dict() JSON-serileziabilir
# ---------------------------------------------------------------------------

def test_result_to_dict_json_serializable() -> None:
    """to_dict() ciktisi json.dumps ile serialize edilebilmeli."""
    import json
    result = probe()
    d = result.to_dict()
    serialized = json.dumps(d)
    assert isinstance(serialized, str)
    # Round-trip
    parsed = json.loads(serialized)
    assert parsed["available"] == result.available
    assert parsed["pyghidra_active"] == result.pyghidra_active
    assert isinstance(parsed["diagnostic_log"], list)


# ---------------------------------------------------------------------------
# Test 9: probe_pyghidra_only — JVM yoksa RuntimeError
# ---------------------------------------------------------------------------

def test_probe_pyghidra_only_raises_without_jvm() -> None:
    """probe_pyghidra_only() JVM yokken RuntimeError firlatir."""
    fake_jpype = MagicMock()
    fake_jpype.isJVMStarted.return_value = False

    with patch.dict(sys.modules, {"jpype": fake_jpype}):
        with pytest.raises(RuntimeError, match="PyGhidra/JVM disinda"):
            probe_pyghidra_only()


def test_probe_pyghidra_only_works_with_jvm(cleanup_ghidra: None) -> None:
    """probe_pyghidra_only() JVM aktifken normal probe sonucu doner."""
    fake_jpype = MagicMock()
    fake_jpype.isJVMStarted.return_value = True
    _install_fake_ghidra_modules()

    with patch.dict(sys.modules, {"jpype": fake_jpype}):
        result = probe_pyghidra_only()

    assert isinstance(result, BSimNativeProbeResult)
    assert result.pyghidra_active is True


# ---------------------------------------------------------------------------
# Test 10: is_bsim_native_available() — hizli boolean
# ---------------------------------------------------------------------------

def test_is_bsim_native_available_returns_bool() -> None:
    """is_bsim_native_available() bool doner."""
    val = is_bsim_native_available()
    assert isinstance(val, bool)
    # Mac CLI'da False olmali (PyGhidra yok)
    # Bu test Mac dev/CI ortaminda gecerli, gercek pyghidra ortaminda
    # True olabilir — sadece tip kontrol et


def test_is_bsim_native_available_false_without_jvm() -> None:
    """JVM yokken is_bsim_native_available() False doner."""
    fake_jpype = MagicMock()
    fake_jpype.isJVMStarted.return_value = False

    with patch.dict(sys.modules, {"jpype": fake_jpype}):
        assert is_bsim_native_available() is False


# ---------------------------------------------------------------------------
# Test 11: summary() string uretimi
# ---------------------------------------------------------------------------

def test_summary_no_jvm() -> None:
    """summary() JVM yokken aciklayici mesaj uretir."""
    result = BSimNativeProbeResult()
    result.pyghidra_active = False
    s = result.summary()
    assert "PyGhidra" in s or "JVM" in s
    assert "lite" in s.lower() or "yok" in s.lower()


def test_summary_available() -> None:
    """summary() available=True iken HAZIR mesaji uretir."""
    result = BSimNativeProbeResult(available=True, pyghidra_active=True)
    s = result.summary()
    assert "HAZIR" in s


def test_summary_partial_missing() -> None:
    """summary() bazi modullerin eksik oldugunu raporlar."""
    result = BSimNativeProbeResult(
        pyghidra_active=True,
        bsim_module_found=True,
        function_database_found=True,
        gen_signatures_found=False,
    )
    s = result.summary()
    assert "EKSIK" in s
    assert "GenSignatures" in s


# ---------------------------------------------------------------------------
# Test 12: append_log() helper
# ---------------------------------------------------------------------------

def test_append_log() -> None:
    """append_log() diagnostic_log'a satir ekler."""
    result = BSimNativeProbeResult()
    assert len(result.diagnostic_log) == 0
    result.append_log("test mesaji")
    assert len(result.diagnostic_log) == 1
    assert result.diagnostic_log[0] == "test mesaji"
    result.append_log("ikinci")
    assert len(result.diagnostic_log) == 2
