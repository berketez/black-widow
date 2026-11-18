"""P01b kalem 1: ikili inceleme araçlarının girdisi sessizce kaybolmaz.

Kusur (2026-11-18 ölçümü): PATH'teki conda cctools ``strings`` / ``nm`` yeni arm64e Mach-O'da
"malformed object (unknown load command N)" deyip çıkış 1 veriyor ama çıktının çoğunu basıyordu;
``SubprocessRunner.run_strings`` sıfırdan farklı çıkışta her şeyi atıp ``[]`` döndürüyordu.
Ayrıca ``text=True`` katı UTF-8 çözdüğü için geçersiz baytlı dizgi çıktısı (macOS nfcd x86_64
dilimi) ``UnicodeDecodeError`` ile çağıran adımı düşürüyordu.

Testler sahte araç betiği kullanır (gerçek araç sürümüne bağlı değil); son sınıf yalnız macOS'ta
gerçek sistem ikilisiyle koşar.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from karadul.config import Config
from karadul.core import subprocess_runner as sr
from karadul.core.safe_subprocess import resolve_tool
from karadul.core.subprocess_runner import SubprocessRunner


def _betik(dizin: Path, ad: str, govde: str) -> Path:
    yol = dizin / ad
    yol.write_text(f"#!{sys.executable}\nimport sys\n{govde}\n", encoding="utf-8")
    yol.chmod(yol.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return yol


@pytest.fixture
def runner() -> SubprocessRunner:
    return SubprocessRunner(Config())


class TestKismiCikti:
    def test_cikis_1_ama_cikti_var_kullanilir(self, runner, tmp_path) -> None:
        sahte = _betik(tmp_path, "strings", (
            "sys.stdout.write('CBCentralManager\\nBluetoothDaemon\\n')\n"
            "sys.stderr.write('strings: for architecture arm64e object: x malformed object "
            "(unknown load command 7)\\n')\n"
            "sys.exit(1)"))
        runner._config.tools.strings = sahte  # açık yol: beyaz liste çözümü uygulanmaz
        satirlar = runner.run_strings(tmp_path / "ikili")
        assert satirlar == ["CBCentralManager", "BluetoothDaemon"]
        durum = runner.tool_status["strings"]
        assert durum["durum"] == "kismi"
        assert durum["cikis_kodu"] == 1
        assert durum["satir"] == 2
        assert "unknown load command 7" in durum["hata"]

    def test_cikti_yoksa_hata_istatistikte(self, runner, tmp_path) -> None:
        sahte = _betik(tmp_path, "strings", (
            "sys.stderr.write('malformed object\\n')\nsys.exit(1)"))
        runner._config.tools.strings = sahte
        assert runner.run_strings(tmp_path / "ikili") == []
        durum = runner.tool_status["strings"]
        assert durum["durum"] == "hata"
        assert durum["satir"] == 0

    def test_tam_cikti(self, runner, tmp_path) -> None:
        sahte = _betik(tmp_path, "strings", "print('abcd')")
        runner._config.tools.strings = sahte
        assert runner.run_strings(tmp_path / "ikili") == ["abcd"]
        assert runner.tool_status["strings"]["durum"] == "tam"

    def test_otool_kismi_cikti(self, runner, tmp_path) -> None:
        sahte = _betik(tmp_path, "otool", (
            "print('x:')\nprint('\\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)')\n"
            "sys.exit(1)"))
        runner._config.tools.otool = sahte
        cikti = runner.run_otool(tmp_path / "ikili", flags=["-L"])
        assert "libSystem.B.dylib" in cikti
        assert runner.tool_status["otool"]["durum"] == "kismi"

    def test_nm_durumu_run_command_ile_yazilir(self, runner, tmp_path) -> None:
        # macho._run_nm run_command'ı doğrudan çağırır; durum yine kayda geçer.
        sahte = _betik(tmp_path, "nm", "print('U _ptrace')\nsys.exit(1)")
        r = runner.run_command([str(sahte), "-g", str(tmp_path / "ikili")])
        assert r.stdout.strip() == "U _ptrace"
        assert runner.tool_status["nm"]["durum"] == "kismi"


class TestGecersizUtf8:
    def test_gecersiz_bayt_dusurmez(self, runner, tmp_path) -> None:
        sahte = _betik(tmp_path, "strings", (
            "sys.stdout.buffer.write(b'PQRSVWAPAQH\\nAYAX_^[ZYX]\\xc3(\\nok12\\n')"))
        runner._config.tools.strings = sahte
        satirlar = runner.run_strings(tmp_path / "ikili")
        assert len(satirlar) == 3
        assert satirlar[0] == "PQRSVWAPAQH"
        assert satirlar[2] == "ok12"
        assert runner.tool_status["strings"]["durum"] == "tam"


class TestAracCozumu:
    def test_ciplak_ad_beyaz_listeden(self, monkeypatch, tmp_path) -> None:
        # PATH'in önünde bozuk bir "strings" olsa da (conda cctools gibi) beyaz listedeki
        # araç (safe_subprocess.resolve_tool) kullanılır.
        sahte_dizin = tmp_path / "bin"
        sahte_dizin.mkdir()
        _betik(sahte_dizin, "strings", "print('SAHTE_PATH_ARACI')\nsys.exit(1)")
        hedef = _betik(tmp_path, "beyaz_strings", "print('BEYAZ_LISTE')")
        monkeypatch.setenv("PATH", f"{sahte_dizin}{os.pathsep}{os.environ.get('PATH', '')}")
        cagrilan = []

        def _resolve(ad, **kw):
            cagrilan.append(ad)
            return str(hedef)

        monkeypatch.setattr(sr, "resolve_tool", _resolve)
        runner = SubprocessRunner(Config())
        assert str(runner._config.tools.strings) == "strings"  # öntanımlı çıplak ad
        assert runner.run_strings(tmp_path / "ikili") == ["BEYAZ_LISTE"]
        assert cagrilan == ["strings"]
        assert runner.tool_status["strings"]["yol"] == str(hedef)

    def test_acik_yol_korunur(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setattr(sr, "resolve_tool", lambda ad, **kw: pytest.fail("çağrılmamalı"))
        sahte = _betik(tmp_path, "strings", "print('ACIK')")
        runner = SubprocessRunner(Config())
        runner._config.tools.strings = sahte
        assert runner.run_strings(tmp_path / "ikili") == ["ACIK"]

    def test_obur_komutlar_cozulmez(self, monkeypatch) -> None:
        monkeypatch.setattr(sr, "resolve_tool", lambda ad, **kw: pytest.fail("çağrılmamalı"))
        assert sr._resolve_binary_tool("python3") == "python3"
        assert sr._resolve_binary_tool("node") == "node"


@pytest.mark.skipif(sys.platform != "darwin", reason="yalnız macOS sistem ikilisi")
class TestGercekSistemIkilisi:
    @pytest.mark.parametrize("yol", ["/usr/libexec/nsurlsessiond", "/usr/libexec/xpcproxy"])
    def test_arm64e_girdisi_bos_degil(self, yol) -> None:
        if not Path(yol).is_file() or resolve_tool("strings") is None:
            pytest.skip("ikili ya da araç yok")
        runner = SubprocessRunner(Config())
        assert len(runner.run_strings(Path(yol))) > 100
        assert runner.tool_status["strings"]["durum"] == "tam"
        r = runner.run_command(["nm", "-g", yol], timeout=60)
        assert len(r.stdout.splitlines()) > 50
        assert runner.tool_status["nm"]["durum"] == "tam"
