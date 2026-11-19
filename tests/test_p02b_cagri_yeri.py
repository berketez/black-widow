"""P02b kalem 1-2: ithal tabanlı anti-debug bulguları çağrı yerine ve argümana bağlanır.

Eski davranış (taban 0984090): ithal tablosundaki ad tek başına bulgu kuruyordu;
``ptrace`` ithali 0,65 / 0,70 hüküm, ``sysctl`` / ``prctl`` ithali bilgi (0,15),
API hiç çağrılmasa bile. Çağrı yeri ve argüman görülmüyordu.

Şimdi Ghidra çağrı çizgesi + decompile metni verilirse (``GhidraCallSites``):
- hiç çağrılmayan / yalnız CRT başlangıcından çağrılan API hüküm üretmez (0,10);
- çağıran fonksiyon + adres kanıt satırına girer;
- ptrace isteği (PT_DENY_ATTACH / PTRACE_TRACEME), prctl seçeneği
  (PR_SET_DUMPABLE, 0) ve sysctl mib'i (CTL_KERN, KERN_PROC, KERN_PROC_PID,
  getpid()) + P_TRACED denetimi okunur.

Gerçek Ghidra çıktısı sınamaları (``urun-yeni2-f30ac9a``, salt okur) dosya yoksa
atlanır. Ghidra biçiminde ELLE yazılmış decompile metinleri birim sınamasıdır,
gerçek örnek kanıtı değildir: gerçek bir anti-debug ikilisinin Ghidra çıktısı
yerelde yok (Ghidra koşusu bu pakette yapılmadı).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from karadul.analyzers.anti_debug_detector import (
    AntiDebugDetector,
    AntiDebugFinding,
    GhidraCallSites,
    _sysctl_mib,
)

KOSU = Path.home() / "karadul_olcum/runs/urun-yeni2-f30ac9a"


def _gd(anahtar: str) -> Path | None:
    adaylar = sorted((KOSU / anahtar / "ws" / "workspaces").glob("*/*/static/ghidra_output"))
    return adaylar[-1] if adaylar else None


def _cs(tmp_path: Path, cagiranlar: dict[str, list[tuple[str, str]]],
        metinler: dict[str, str]) -> GhidraCallSites:
    """Ghidra biçiminde çağrı çizgesi (thunk → EXTERNAL zinciri dahil) + decompile dizini."""
    dec = tmp_path / "decompiled"
    dec.mkdir()
    for ad, metin in metinler.items():
        (dec / f"{ad}.c").write_text(metin, encoding="utf-8")
    nodes = {}
    for i, (api, cs) in enumerate(cagiranlar.items()):
        nodes[f"thunk{i}"] = {"name": api, "callers": [{"name": n, "address": a} for n, a in cs]}
        nodes[f"ext{i}"] = {"name": api, "callers": [{"name": api, "address": f"thunk{i}"}]}
    return GhidraCallSites({"nodes": nodes}, dec)


def _ithal(teknik: str, sembol: str, platform: str, guven: float,
           kategori: str = "macos") -> AntiDebugFinding:
    return AntiDebugFinding(teknik, kategori, guven, f"import: {sembol}", platform, "aciklama")


def _uygula(cs: GhidraCallSites, bulgular: list[AntiDebugFinding]) -> dict[str, AntiDebugFinding]:
    d = AntiDebugDetector(binary_path=Path("/dev/null"), callsites=cs)
    return {f.technique: f for f in d._apply_callsites(bulgular)}


# Ghidra'nın -O0 x86-64 Mach-O'da üreteceği biçim (antidebug.c traced_check / main)
TRACED_CHECK = """
bool _traced_check(void)
{
  int iVar1;
  size_t local_2a8;
  undefined local_2a0 [32];
  uint local_280;
  int local_18;
  undefined4 local_14;
  undefined4 local_10;
  int local_c;

  local_18 = 1;
  local_14 = 0xe;
  local_10 = 1;
  iVar1 = _getpid();
  local_c = iVar1;
  local_2a8 = 0x288;
  local_280 = 0;
  iVar1 = _sysctl(&local_18,4,local_2a0,&local_2a8,(void *)0x0,0);
  if (iVar1 != 0) {
    return false;
  }
  return (local_280 & 0x800) != 0;
}
"""
MAIN_DENY = """
int _main(void)
{
  _ptrace(0x1f,0,(caddr_t)0x0,0);
  _puts("ok");
  return 0;
}
"""
SC_USAGE = """
void FUN_100003a00(int param_1)
{
  _ptrace(7,param_1,(caddr_t)0x1,0);
  return;
}
"""


class TestCagriYeri:
    def test_cagrilmayan_ithal_hukum_degil(self, tmp_path):
        cs = _cs(tmp_path, {"IsDebuggerPresent": []}, {})
        f = _uygula(cs, [_ithal("IsDebuggerPresent", "IsDebuggerPresent", "windows", 0.55,
                                "windows_api")])["IsDebuggerPresent"]
        assert f.confidence == pytest.approx(0.10)
        assert "cagri yeri yok" in f.evidence

    def test_yalniz_crt_cagiriyor(self, tmp_path):
        cs = _cs(tmp_path, {"CheckRemoteDebuggerPresent": [("__scrt_fastfail", "401000")]}, {})
        f = _uygula(cs, [_ithal("CheckRemoteDebuggerPresent", "CheckRemoteDebuggerPresent",
                                "windows", 0.60, "windows_api")])["CheckRemoteDebuggerPresent"]
        assert f.confidence == pytest.approx(0.10)
        assert "derleyici calisma zamani" in f.evidence

    def test_cagiran_kanitta(self, tmp_path):
        cs = _cs(tmp_path, {"CheckRemoteDebuggerPresent": [("FUN_00401200", "00401200")]}, {})
        f = _uygula(cs, [_ithal("CheckRemoteDebuggerPresent", "CheckRemoteDebuggerPresent",
                                "windows", 0.60, "windows_api")])["CheckRemoteDebuggerPresent"]
        assert f.confidence == pytest.approx(0.60)
        assert "cagri: FUN_00401200@0x00401200" in f.evidence

    def test_katman_yoksa_eski_davranis(self, tmp_path):
        f = _ithal("ptrace_pt_deny_attach", "_ptrace", "macos", 0.70)
        d = AntiDebugDetector(binary_path=Path("/dev/null"))
        assert d._apply_callsites([f]) == [f]


class TestArguman:
    def test_pt_deny_attach_dogrulandi(self, tmp_path):
        cs = _cs(tmp_path, {"_ptrace": [("_main", "100003f00")]}, {"_main": MAIN_DENY})
        f = _uygula(cs, [_ithal("ptrace_pt_deny_attach", "_ptrace", "macos", 0.70)])[
            "ptrace_pt_deny_attach"]
        assert f.confidence == pytest.approx(0.70)
        assert "arguman dogrulandi: ptrace(PT_DENY_ATTACH=31)" in f.evidence
        assert "_main@0x100003f00" in f.evidence

    def test_izleyici_ptrace_hukum_degil(self, tmp_path):
        """sc_usage biçimi: ptrace(PT_CONTINUE=7) — izleyici, anti-debug değil (eski: 0,70)."""
        cs = _cs(tmp_path, {"_ptrace": [("FUN_100003a00", "100003a00")]},
                 {"FUN_100003a00": SC_USAGE})
        f = _uygula(cs, [_ithal("ptrace_pt_deny_attach", "_ptrace", "macos", 0.70)])[
            "ptrace_pt_deny_attach"]
        assert f.confidence == pytest.approx(0.10)
        assert "[7]" in f.evidence

    def test_linux_traceme(self, tmp_path):
        metin = "void FUN_1(void)\n{\n  lVar1 = ptrace(PTRACE_TRACEME,0,0,0);\n  lVar1 = ptrace(0,0,0,0);\n}\n"
        cs = _cs(tmp_path, {"ptrace": [("FUN_1", "1000")]}, {"FUN_1": metin})
        f = _uygula(cs, [_ithal("ptrace_traceme", "ptrace", "linux", 0.65, "ptrace")])[
            "ptrace_traceme"]
        assert f.confidence == pytest.approx(0.65)
        assert "PTRACE_TRACEME=0" in f.evidence

    def test_ptrace_istegi_okunamadi_zayif(self, tmp_path):
        metin = "void FUN_1(int r)\n{\n  ptrace(r,0,0,0);\n}\n"
        cs = _cs(tmp_path, {"ptrace": [("FUN_1", "1000")]}, {"FUN_1": metin})
        f = _uygula(cs, [_ithal("ptrace_traceme", "ptrace", "linux", 0.65, "ptrace")])[
            "ptrace_traceme"]
        assert f.confidence == pytest.approx(0.30)

    def test_sysctl_p_traced_hukum(self, tmp_path):
        cs = _cs(tmp_path, {"_sysctl": [("_traced_check", "100003e00")]},
                 {"_traced_check": TRACED_CHECK})
        out = _uygula(cs, [_ithal("sysctl_import", "_sysctl", "macos", 0.15)])
        f = out["sysctl_kinfo_proc"]
        assert f.confidence == pytest.approx(0.55)
        assert "KERN_PROC_PID, getpid()" in f.evidence and "P_TRACED" in f.evidence

    def test_sysctl_p_traced_denetimi_yoksa_bilgi(self, tmp_path):
        metin = TRACED_CHECK.replace("(local_280 & 0x800) != 0", "local_280 != 0")
        cs = _cs(tmp_path, {"_sysctl": [("_traced_check", "100003e00")]},
                 {"_traced_check": metin})
        out = _uygula(cs, [_ithal("sysctl_import", "_sysctl", "macos", 0.15)])
        assert set(out) == {"sysctl_import"}
        assert "KERN_PROC_PID + getpid(): 1" in out["sysctl_import"].evidence

    def test_sysctl_baska_pid_hukum_degil(self, tmp_path):
        """ps biçimi: KERN_PROC_PID + kullanıcının verdiği pid (getpid değil) + P_TRACED."""
        metin = TRACED_CHECK.replace("  iVar1 = _getpid();\n  local_c = iVar1;",
                                     "  local_c = param_1;")
        cs = _cs(tmp_path, {"_sysctl": [("_traced_check", "100003e00")]},
                 {"_traced_check": metin})
        assert "sysctl_kinfo_proc" not in _uygula(
            cs, [_ithal("sysctl_import", "_sysctl", "macos", 0.15)])

    def test_sysctl_paket_atama_ve_dizi(self, tmp_path):
        metin = ("int FUN_1(void)\n{\n  local_68 = 0xe00000001;\n  iVar2 = _getpid();\n"
                 "  local_60 = CONCAT44(iVar2,1);\n  _sysctl((int *)&local_68,4,auStack_300,&local_70,"
                 "(void *)0x0,0);\n  return (uint)(local_2e0 >> 0xb & 1);\n}\n")
        cs = _cs(tmp_path, {"_sysctl": [("FUN_1", "1000")]}, {"FUN_1": metin})
        site = cs.call_sites("_sysctl")[0]
        assert _sysctl_mib(site, metin) == [1, 14, 1, "getpid"]
        assert "sysctl_kinfo_proc" in _uygula(
            cs, [_ithal("sysctl_import", "_sysctl", "macos", 0.15)])

    def test_sysctl_kern_proc_yoksa_iddia_yok(self, tmp_path):
        metin = ("void FUN_1(void)\n{\n  local_20[0] = 1;\n  local_20[1] = 0x15;\n"
                 "  _sysctl(local_20,2,local_30,&local_48,(void *)0x0,0);\n}\n")
        cs = _cs(tmp_path, {"_sysctl": [("FUN_1", "1000")]}, {"FUN_1": metin})
        assert _uygula(cs, [_ithal("sysctl_import", "_sysctl", "macos", 0.15)]) == {}

    def test_prctl_set_name_iddia_yok(self, tmp_path):
        metin = "void FUN_1(void)\n{\n  prctl(0xf,acStack_f8);\n}\n"
        cs = _cs(tmp_path, {"prctl": [("FUN_1", "1000")]}, {"FUN_1": metin})
        assert _uygula(cs, [_ithal("prctl_import", "prctl", "linux", 0.15, "ptrace")]) == {}


@pytest.mark.skipif(not KOSU.exists(), reason="hazır Ghidra çıktısı (urun-yeni2-f30ac9a) yok")
class TestGercekGhidraCiktisi:
    """Masum geliştirme setinin gerçek Ghidra çıktıları (salt okur)."""

    def _tara(self, anahtar: str, ham: Path):
        gd = _gd(anahtar)
        if gd is None or not ham.exists():
            pytest.skip(f"{anahtar}: Ghidra çıktısı ya da ikili yok")
        return AntiDebugDetector(binary_path=ham,
                                 callsites=GhidraCallSites.from_ghidra_output(gd)).scan()

    def test_coreutils_timeout_set_dumpable_zayif(self):
        ham = Path.home() / "karadul_olcum/n1_debian13/coreutils/timeout"
        adaylar = sorted(ham.glob("ws/workspaces/*/*/raw/timeout"))
        r = self._tara("debian/coreutils/timeout", adaylar[0] if adaylar else ham)
        f = {x.technique: x for x in r.findings}["prctl_set_dumpable"]
        assert f.confidence == pytest.approx(0.30)
        assert "FUN_001029a0" in f.evidence
        assert r.layers["callsites"]["status"] == "calisti"
        assert AntiDebugDetector(binary_path=Path("/dev/null")).summary(
            r.findings)["anti_debug_score"] < 0.4

    def test_tmux_prctl_set_name_iddia_yok(self):
        ham = Path.home() / "karadul_olcum/n1_debian13/tmux/tmux"
        adaylar = sorted(ham.glob("ws/workspaces/*/*/raw/tmux"))
        r = self._tara("debian/tmux/tmux", adaylar[0] if adaylar else ham)
        assert not any(x.technique.startswith("prctl") for x in r.findings)


def test_adim_ghidra_ciktisini_dedektore_verir(tmp_path):
    """Adım ``call_graph_json_path`` + ``decompiled_dir`` varsa çağrı yeri katmanını açar."""
    import json
    from unittest.mock import MagicMock

    from karadul.pipeline.context import StepContext
    from karadul.pipeline.steps.anti_debug import AntiDebugStep

    ikili = tmp_path / "b.bin"
    ikili.write_bytes(b"\x00" * 64)
    cg = tmp_path / "call_graph.json"
    cg.write_text(json.dumps({"nodes": {}}), encoding="utf-8")
    dec = tmp_path / "decompiled"
    dec.mkdir()
    pc = MagicMock()
    pc.config.binary_reconstruction.enable_anti_debug_detection = True
    pc.workspace.save_json.return_value = tmp_path / "o.json"
    ctx = StepContext(pipeline_context=pc)
    ctx._write_artifacts({"binary_for_byte_match": ikili, "call_graph_json_path": cg,
                          "decompiled_dir": dec})
    AntiDebugStep().run(ctx)
    assert pc.workspace.save_json.call_args[0][2]["layers"]["callsites"]["status"] == "calisti"

    ctx2 = StepContext(pipeline_context=pc)
    ctx2._write_artifacts({"binary_for_byte_match": ikili})
    AntiDebugStep().run(ctx2)
    assert (pc.workspace.save_json.call_args[0][2]["layers"]["callsites"]["status"]
            == "desteklenmiyor")
