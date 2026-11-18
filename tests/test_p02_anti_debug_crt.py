"""P02 / IMZA-03: PE'de derleyici çalışma zamanı ithalleri ve 0xCC dolgusu anti-debug sayılmaz;
zayıf kanıtlar toplanarak hükme yükselmez.

Eski davranış (taban e9d2d08): MSVC ile derlenen her PE'nin CRT ithalleri
(IsDebuggerPresent, QueryPerformanceCounter, GetTickCount) ve fonksiyonlar
arası 0xCC dolgusu ayrı "teknik" sayılıyor, puan "en yüksek + 0,05 × (teknik
sayısı − 1)" ile şişiyordu: pip'in ``w32.exe``'si 0,7 → "[HIGH]"; masum 39
PE'nin 14'ü HIGH, 7'si MED.

Buradaki sınamaların her biri eski kodda KIRMIZI, yeni kodda yeşildir; doğru
pozitifleri koruyan sınamalar (ör. CRT kümesine rağmen CheckRemoteDebuggerPresent)
iki kodda da yeşildir.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from karadul.analyzers.anti_debug_detector import AntiDebugDetector, AntiDebugFinding
from scripts.measurement.p02_pozitif.pe_sentetik import pe_kur
from tests.test_p02_anti_debug_mimari import pe, teknikler, yaz

pytest.importorskip("lief")

# MSVC (VS2015+) CRT'nin olağan ithal kümesi (ölçülen masum PE'lerle aynı)
CRT_KUMESI = ["IsDebuggerPresent", "QueryPerformanceCounter", "GetCurrentProcessId",
              "GetCurrentThreadId", "GetSystemTimeAsFileTime", "UnhandledExceptionFilter",
              "GetTickCount", "ExitProcess"]


def _puan(p: Path) -> tuple[float, dict]:
    det = AntiDebugDetector(binary_path=p)
    bul = det.detect()
    return det.summary(bul)["anti_debug_score"], teknikler(bul)


class TestCRTKumesi:
    def test_crt_kumesi_hukum_degil(self, tmp_path):
        """Yalnız CRT ithalleri: puan < 0,4 (eski: 0,55 + 0,05×2 = 0,65 [MED])."""
        p = yaz(tmp_path, "crt.exe", pe("x86_64", b"\xc3", ithaller={"KERNEL32.dll": CRT_KUMESI}))
        puan, bul = _puan(p)
        assert puan < 0.4
        assert bul["IsDebuggerPresent"].category == "compiler_runtime"
        assert bul["QueryPerformanceCounter"].category == "compiler_runtime"
        assert bul["GetTickCount"].category == "compiler_runtime"
        assert "MSVC CRT ithal kumesi" in bul["IsDebuggerPresent"].evidence

    def test_crt_kumesine_ragmen_gercek_api_kalir(self, tmp_path):
        p = yaz(tmp_path, "crt_ad.exe", pe("x86_64", b"\xc3", ithaller={
            "KERNEL32.dll": CRT_KUMESI + ["CheckRemoteDebuggerPresent"],
            "ntdll.dll": ["NtQueryInformationProcess"]}))
        puan, bul = _puan(p)
        assert puan >= 0.7
        assert bul["CheckRemoteDebuggerPresent"].category == "windows_api"
        assert bul["IsDebuggerPresent"].category == "compiler_runtime"

    def test_crt_disi_isdebuggerpresent_hukum(self, tmp_path):
        """CRT kümesi yokken IsDebuggerPresent → ExitProcess dalı: puan ≥ 0,4 (kulvar ölçütü)."""
        p = yaz(tmp_path, "ad.exe", pe_kur("x86_64"))
        puan, bul = _puan(p)
        assert puan >= 0.4
        assert bul["IsDebuggerPresent"].category == "windows_api"
        assert bul["IsDebuggerPresent"].confidence >= 0.55

    def test_fastfail_esi_yoksa_isdebuggerpresent_aciklanmaz(self, tmp_path):
        """Çerez kümesi var, UnhandledExceptionFilter yok: QPC CRT'nin, IsDebuggerPresent değil."""
        adlar = [a for a in CRT_KUMESI if a != "UnhandledExceptionFilter"]
        p = yaz(tmp_path, "yarim.exe", pe("x86_64", b"\xc3", ithaller={"KERNEL32.dll": adlar}))
        _puan_, bul = _puan(p)
        assert bul["QueryPerformanceCounter"].category == "compiler_runtime"
        assert bul["IsDebuggerPresent"].category == "windows_api"

    def test_cerez_kumesi_eksikse_aciklanmaz(self, tmp_path):
        """GetCurrentProcessId / GetCurrentThreadId / zaman API'si yok: CRT kümesi değil."""
        p = yaz(tmp_path, "eksik.exe", pe("x86_64", b"\xc3", ithaller={"KERNEL32.dll": [
            "IsDebuggerPresent", "UnhandledExceptionFilter", "QueryPerformanceCounter"]}))
        _puan_, bul = _puan(p)
        assert bul["IsDebuggerPresent"].category == "windows_api"
        assert bul["QueryPerformanceCounter"].category == "windows_api"

    def test_outputdebugstring_tek_basina_zayif(self, tmp_path):
        p = yaz(tmp_path, "ods.exe", pe("x86_64", b"\xc3",
                                         ithaller={"KERNEL32.dll": ["OutputDebugStringW"]}))
        puan, bul = _puan(p)
        assert bul["OutputDebugString"].confidence <= 0.30
        assert puan < 0.4


# x86-64 .text içinde INT3 koşuları (RVA 0x1000'den başlar)
def _hizali_dolgu() -> bytes:
    # dönmeyen call (5 bayt), 0x1010'a dek CC (11 bayt), sonra hizalı fonksiyon.
    # Öncesinde ret/jmp yok: yalnız hizalama kuralı dolguyu tanımalı.
    return b"\xe8\x00\x00\x00\x00" + b"\xcc" * 11 + b"\x31\xc0\xc3"


def _ret_sonrasi_hizasiz() -> bytes:
    # ret'ten sonra 20 CC; hizasız biter (ardından jmp [thunk])
    return b"\x90" * 3 + b"\xc3" + b"\xcc" * 20 + b"\xff\x25\x00\x00\x00\x00"


def _nop_ile_hizalanan() -> bytes:
    # call (dönmeyen) ; CC x 17 ; 10 baytlık NOP ; 0x1020 hizalı fonksiyon
    return (b"\xe8\x00\x00\x00\x00" + b"\xcc" * 17
            + b"\x66\x66\x0f\x1f\x84\x00\x00\x00\x00\x00" + b"\x31\xc0\xc3")


def _fonksiyon_ici_kume() -> bytes:
    # akışın ortasında 12 CC (öncesi nop, sonrası hizasız mov) — sayılmalı
    return b"\x90" * 7 + b"\xcc" * 12 + b"\x89\xc8\xc3"


class TestINT3Dolgusu:
    @pytest.mark.parametrize("kod", [_hizali_dolgu(), _ret_sonrasi_hizasiz(), _nop_ile_hizalanan()],
                             ids=["hizali", "ret_sonrasi", "nop_ile_hizalanan"])
    def test_dolgu_sayilmaz(self, tmp_path, kod):
        p = yaz(tmp_path, "pad.exe", pe("x86_64", kod))
        bul = teknikler(AntiDebugDetector(binary_path=p).detect_by_bytes())
        assert "INT3_Cluster" not in bul

    def test_fonksiyon_ici_kume_sayilir(self, tmp_path):
        p = yaz(tmp_path, "ic.exe", pe("x86_64", _fonksiyon_ici_kume()))
        f = teknikler(AntiDebugDetector(binary_path=p).detect_by_bytes())["INT3_Cluster"]
        assert f.evidence.startswith("INT3 (0xCC) x12")
        assert f.confidence <= 0.30


def _bulgu(teknik: str, kategori: str, guven: float) -> AntiDebugFinding:
    return AntiDebugFinding(teknik, kategori, guven, "k", "windows", "d")


class TestPuan:
    def _det(self, tmp_path) -> AntiDebugDetector:
        return AntiDebugDetector(binary_path=yaz(tmp_path, "x.bin", b"x"))

    def test_zayif_kanitlar_toplanmaz(self, tmp_path):
        """Beş zayıf teknik (≤ 0,30): puan 0,30 (eski: 0,30 + 0,05×4 = 0,50 [MED])."""
        bul = [_bulgu("INT3_Cluster", "timing", 0.25), _bulgu("RDTSC_Timing", "timing", 0.30),
               _bulgu("CreateToolhelp32Snapshot", "windows_api", 0.30),
               _bulgu("Process32First", "windows_api", 0.30),
               _bulgu("Process32Next", "windows_api", 0.30)]
        assert self._det(tmp_path).summary(bul)["anti_debug_score"] == pytest.approx(0.30)

    def test_crt_bulgulari_puana_girmez(self, tmp_path):
        bul = [_bulgu("IsDebuggerPresent", "compiler_runtime", 0.10),
               _bulgu("CheckRemoteDebuggerPresent", "windows_api", 0.60)]
        assert self._det(tmp_path).summary(bul)["anti_debug_score"] == pytest.approx(0.60)

    def test_guclu_kanitlar_toplanir(self, tmp_path):
        bul = [_bulgu("CheckRemoteDebuggerPresent", "windows_api", 0.60),
               _bulgu("NtQueryInformationProcess", "windows_api", 0.75),
               _bulgu("INT3_Cluster", "timing", 0.25)]
        assert self._det(tmp_path).summary(bul)["anti_debug_score"] == pytest.approx(0.80)

    def test_cok_katman_artirimi_zayiflara_uygulanmaz(self, tmp_path):
        bul = [_bulgu("X", "string", 0.25), _bulgu("X", "timing", 0.30)]
        sonuc = self._det(tmp_path)._apply_multilayer_boost(bul)
        assert [b.confidence for b in sonuc] == [0.25, 0.30]


# ---------------------------------------------------------------------------
# Gerçek masum PE'ler (varsa) — kulvar IMZA-03 "Nasıl sınanır"
# ---------------------------------------------------------------------------

DISTLIB = Path("/opt/anaconda3/lib/python3.12/site-packages/pip/_vendor/distlib")
NSIS = Path("/opt/homebrew/Cellar/makensis/3.13/share/nsis/Bin")
MASUM = [DISTLIB / "w32.exe", DISTLIB / "t64.exe", DISTLIB / "w64.exe",
         NSIS / "GenPat.exe", NSIS / "zip2exe.exe", NSIS / "MakeLangId.exe"]


@pytest.mark.parametrize("yol", MASUM, ids=[p.name for p in MASUM])
def test_gercek_masum_pe_puani_dusuk(yol):
    if not yol.is_file():
        pytest.skip(f"{yol} yerelde yok")
    puan, bul = _puan(yol)
    assert puan < 0.4, (puan, {k: (v.category, v.confidence) for k, v in bul.items()})
    assert "INT3_Cluster" not in bul
