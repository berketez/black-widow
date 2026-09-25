"""Python (PyInstaller/cx_Freeze) hattının sertleştirme testleri (2026-09-25).

Her sınıf bir maddeyi kilitler; her korumanın testi mutation ile kanıtlandı
(koruma geri alınınca ilgili test düşer). Sentetik girdiler zararsızdır: hiçbir
test yorumlayıcıyı çökertmeye yönelik veri üretmez.
"""

from __future__ import annotations

import marshal
import os
import sys
import time
from pathlib import Path

import pytest

from karadul.analyzers import pyc_decompiler as pd
from karadul.analyzers.pyc_decompiler import repair_pyc_header

RUNNING = f"{sys.version_info.major}.{sys.version_info.minor}"


def _pyc(path: Path, src: str = "def f():\n    return 1\n") -> Path:
    """Çalışan yorumlayıcı sürümünde, başlığı geçerli .pyc."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(repair_pyc_header(marshal.dumps(compile(src, "m.py", "exec")), RUNNING))
    return path


@pytest.fixture
def ana_surec_unmarshal_yasak(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Ana süreçte marshal.loads çağrılırsa kaydet ve patlat."""
    calls: list[int] = []

    def _yasak(*_a: object, **_k: object) -> object:
        calls.append(os.getpid())
        raise AssertionError("güvenilmeyen .pyc ana süreçte unmarshal edildi")

    monkeypatch.setattr(marshal, "loads", _yasak)
    return calls


# ---------------------------------------------------------------------------
# Madde 1: stdlib dis yedeği güvenilmeyen .pyc'yi süreç içinde açmıyor
# ---------------------------------------------------------------------------

class TestMadde1StdlibDisAyriSurecte:
    def test_yedek_ana_surecte_unmarshal_etmez(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        ana_surec_unmarshal_yasak: list[int],
    ) -> None:
        monkeypatch.setattr(pd, "resolve_tool", lambda name, **k: None)  # pycdas yok
        p = _pyc(tmp_path / "m.pyc")
        res = pd._disassemble(p, RUNNING, timeout=30)
        assert res is not None and res[1] == "disasm"
        assert "RETURN_CONST" in res[0] or "RETURN_VALUE" in res[0]
        assert ana_surec_unmarshal_yasak == []

    def test_pycdas_dokemeyince_de_ana_surecte_acmaz(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        ana_surec_unmarshal_yasak: list[int],
    ) -> None:
        """pycdas kurulu ama içeriği dökemedi -> yedek yine alt süreçte (kod değil -> None)."""
        import subprocess
        monkeypatch.setattr(
            pd, "resolve_tool", lambda name, **k: "/fake/pycdas" if name == "pycdas" else None,
        )
        monkeypatch.setattr(pd, "safe_run", lambda *a, **k: subprocess.CompletedProcess(
            args=[], returncode=0, stdout=b"x (Python 3.12)\n", stderr=b""))
        p = tmp_path / "int.pyc"
        p.write_bytes(repair_pyc_header(bytes([ord("i")]) + (42).to_bytes(4, "little"), RUNNING))
        assert pd._disassemble(p, RUNNING, timeout=30) is None
        assert pd._stdlib_dis_isolated(p, timeout=30) == (None, "not_code")
        assert ana_surec_unmarshal_yasak == []

    def test_zaman_asimi_alt_sureci_oldurur(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(pd, "_DIS_CHILD_SCRIPT", "import time\ntime.sleep(30)\n")
        t0 = time.monotonic()
        assert pd._stdlib_dis_isolated(_pyc(tmp_path / "m.pyc"), timeout=0.5) == (None, "timeout")
        assert time.monotonic() - t0 < 10

    def test_cagiranin_uzun_zaman_asimi_alt_surec_tavanini_asmaz(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """config.timeouts.subprocess (7200 sn) dosya başına tavanı büyütmez."""
        monkeypatch.setattr(pd, "_DIS_CHILD_SCRIPT", "import time\ntime.sleep(30)\n")
        monkeypatch.setattr(pd, "_DIS_CHILD_TIMEOUT", 0.5)
        t0 = time.monotonic()
        assert pd._stdlib_dis_isolated(_pyc(tmp_path / "m.pyc"), timeout=7200) == (None, "timeout")
        assert time.monotonic() - t0 < 10

    @pytest.mark.skipif(pd._process_memory_bytes(os.getpid()) is None,
                        reason="bu platformda süreç belleği ölçülemiyor")
    def test_bellek_bekcisi_alt_sureci_oldurur(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Tavanı aşan alt süreç (sıradan bytearray) bekçi tarafından öldürülür."""
        monkeypatch.setattr(pd, "_DIS_MAX_MEMORY_BYTES", 64 * 1024 ** 2)
        monkeypatch.setattr(pd, "_DIS_CHILD_SCRIPT", (
            "import time\n"
            "b = bytearray(256 * 1024 * 1024)\n"
            "for i in range(0, len(b), 4096):\n"
            "    b[i] = 1\n"
            "time.sleep(30)\n"
        ))
        t0 = time.monotonic()
        assert pd._stdlib_dis_isolated(_pyc(tmp_path / "m.pyc"), timeout=30) == (None, "memory")
        assert time.monotonic() - t0 < 20

    def test_cikti_tavaninda_kesilir_ve_isaretlenir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(pd, "_DIS_MAX_OUTPUT_BYTES", 120)
        text, status = pd._stdlib_dis_isolated(_pyc(tmp_path / "m.pyc"), timeout=30)
        assert status == "truncated"
        assert text is not None and text.rstrip().endswith(pd._DIS_TRUNCATED_MARKER)
        assert len(text.encode("utf-8")) <= 120 + len(pd._DIS_TRUNCATED_MARKER.encode()) + 4

    def test_donmus_uygulamada_surec_ici_yedege_donmez(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        ana_surec_unmarshal_yasak: list[int],
    ) -> None:
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        assert pd._stdlib_dis_isolated(_pyc(tmp_path / "m.pyc"), timeout=30) == (
            None, "no_interpreter")
        assert ana_surec_unmarshal_yasak == []

    def test_cikti_tekrarlanabilir(self, tmp_path: Path) -> None:
        """Hash tohumu sabit + adres yok: iki ayrı alt süreç aynı metni üretir."""
        # 12 öğeli küme: rastgele tohumla iki sürecin aynı sırayı tutturması olası değil
        src = "def f():\n    return 1\nT = {%s}\n" % ", ".join(repr(("k%d" % i, "v")) for i in range(12))
        p = _pyc(tmp_path / "m.pyc", src)
        a, st_a = pd._stdlib_dis_isolated(p, timeout=30)
        b, st_b = pd._stdlib_dis_isolated(p, timeout=30)
        assert st_a == st_b == "ok" and a == b
        assert "<code object f, file" in a and " at 0x" not in a
        assert "frozenset" in a

    def test_surum_farkliysa_alt_surec_bile_acilmaz(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(pd, "resolve_tool", lambda name, **k: None)
        spawned: list[object] = []
        monkeypatch.setattr(pd, "_stdlib_dis_isolated",
                            lambda *a, **k: spawned.append(a) or (None, "x"))
        other = "3.8" if RUNNING != "3.8" else "3.9"
        assert pd._disassemble(_pyc(tmp_path / "m.pyc"), other, timeout=30) is None
        assert spawned == []
