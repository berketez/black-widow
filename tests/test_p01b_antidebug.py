"""P01b kalem 0: masum kapının zorunlu gerçek pozitifi ``antidebug_x86_64`` → ``Anti-Debugging``.

Girdiler gerçek ikililerden alındı (``/usr/bin/nm -g`` ve ``strings -n 4``):
- örnek: ``scripts/measurement/masum_kapi_pozitif/antidebug.c`` derlemesi (x86-64 Mach-O),
- ssh-agent / sftp-server / sshd-session: ``ptrace(PT_DENY_ATTACH)`` + hata iletisi,
- sc_usage: izleyici; ``ptrace(PT_CONTINUE)`` + ``sysctl`` (anti-debug DEĞİL).

P01'in iki kanıt kuralı ``_ptrace`` simgesini tek kanıt sayıp iddiayı düşürmüştü. Onarım: ikilinin
kendi tespit metni ikinci bağımsız gösterge; ``ptrace`` yalnız başına (ya da ``sysctl`` ile) yine
iddia kurmaz.
"""

from __future__ import annotations

import pytest

from karadul.analyzers.binary_intelligence import BinaryIntelligence
from karadul.config import Config

ORNEK_DIZGI = ["debugger detected", "ok"]
ORNEK_SIMGE = [
    "___stack_chk_fail", "___stack_chk_guard", "__mh_execute_header", "_getpid", "_main",
    "_ptrace", "_puts", "_sysctl",
]


@pytest.fixture
def bi() -> BinaryIntelligence:
    return BinaryIntelligence(Config())


def _guvenlik(bi: BinaryIntelligence, dizgi, simge, kitaplik=()) -> dict:
    r = bi.analyze(list(dizgi), list(simge), list(kitaplik), "x")
    return {m.name: m for m in r.architecture.security}


class TestAntiDebugGercekPozitif:
    def test_masum_kapi_ornegi(self, bi: BinaryIntelligence) -> None:
        g = _guvenlik(bi, ORNEK_DIZGI, ORNEK_SIMGE,
                      ["/usr/lib/libSystem.B.dylib"])
        assert "Anti-Debugging" in g
        m = g["Anti-Debugging"]
        assert m.risk_level == "elevated"
        assert m.evidence[:2] == ["_ptrace", "debugger detected"]
        assert m.evidence_kinds[:2] == ["symbol", "string"]

    def test_openssh_pt_deny_attach(self, bi: BinaryIntelligence) -> None:
        g = _guvenlik(bi, ["unable to set PT_DENY_ATTACH: %s"],
                      ["_ptrace", "_getppid", "_isatty"])
        assert "Anti-Debugging" in g

    def test_qa1361_islev_adi(self, bi: BinaryIntelligence) -> None:
        g = _guvenlik(bi, [], ["_ptrace", "_AmIBeingDebugged"])
        assert "Anti-Debugging" in g


class TestAntiDebugSahteIddiaYok:
    def test_izleyici_ptrace_sysctl(self, bi: BinaryIntelligence) -> None:
        # sc_usage: ptrace(PT_CONTINUE) — izleyici; sysctl ikinci kanıt sayılmaz.
        assert "Anti-Debugging" not in _guvenlik(bi, [], ["_ptrace", "_sysctl", "_sysctlbyname"])

    def test_yalniz_ptrace(self, bi: BinaryIntelligence) -> None:
        assert "Anti-Debugging" not in _guvenlik(bi, [], ["_ptrace"])

    def test_yalniz_dizgi_guclu_kanit_yok(self, bi: BinaryIntelligence) -> None:
        # yükseltilmiş risk düzeyi en az bir simge / kitaplık kanıtı ister
        assert "Anti-Debugging" not in _guvenlik(
            bi, ["debugger detected", "being debugged", "ptrace"], [])

    def test_msvc_crt_isdebuggerpresent(self, bi: BinaryIntelligence) -> None:
        # her MSVC PE'sinde CRT içe aktarımı; "debugger present" gösterge değil
        assert "Anti-Debugging" not in _guvenlik(
            bi, ["IsDebuggerPresent", "UnhandledExceptionFilter"], ["_ptrace"])
