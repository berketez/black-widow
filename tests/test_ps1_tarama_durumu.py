"""P-S1 kalem 1 (IMZA-15 + P03 yaması): taramalarda dürüst durum.

"Taranamadı" ile "tarandı, temiz" ayrılmalı. Anti-debug ve paketleyici adımları
JSON'a her koşulda ``status`` (+ neden, dosya boyutu, taranan bayt) yazar; hata
ya da kısmi taramada ``total_*`` 0 değil ``None`` olur. Statik aşamanın YARA ve
capa blokları ``yara_status`` / ``capa_status`` yazar; YARA hata verirse
``yara_matches`` 0 değil ``None`` olur.

Hatalar gerçek dedektöre ENJEKTE edilir (katman yöntemi istisna atar); dedektörün
kendisi taklit edilmez.
"""

from __future__ import annotations

import functools
import json
import os
import struct
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from karadul.analyzers import anti_debug_detector as ad_mod
from karadul.analyzers import packer_fingerprint as pf_mod
from karadul.pipeline.context import StepContext
from karadul.pipeline.steps import anti_debug as ad_step_mod
from karadul.pipeline.steps import packer_fingerprint as pf_step_mod
from karadul.pipeline.steps.anti_debug import AntiDebugStep
from karadul.pipeline.steps.packer_fingerprint import PackerFingerprintStep

W32 = Path(sys.prefix) / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" \
    / "site-packages" / "pip" / "_vendor" / "distlib" / "w32.exe"
_DEB_TRUE = sorted((Path.home() / "karadul_olcum" / "n1_debian13" / "coreutils" / "true")
                   .glob("ws/workspaces/*/*/raw/true"))


# ---------------------------------------------------------------------------
# Ortak kurulum
# ---------------------------------------------------------------------------

def _pc(target_path: Path | None) -> MagicMock:
    pc = MagicMock()
    pc.config = MagicMock()
    pc.config.binary_reconstruction.enable_anti_debug_detection = True
    pc.config.binary_reconstruction.enable_packer_fingerprint = True
    pc.target = MagicMock()
    pc.target.path = target_path
    pc.workspace.save_json = MagicMock(side_effect=lambda st, ad, data: Path(f"/x/{st}/{ad}.json"))
    pc.metadata = {}
    return pc


def _ctx(binary: Path | None) -> StepContext:
    ctx = StepContext(pipeline_context=_pc(binary))
    if binary is not None:
        ctx._write_artifacts({"binary_for_byte_match": binary})
    return ctx


def _payload(ctx: StepContext, name: str) -> dict:
    calls = [c for c in ctx.pipeline_context.workspace.save_json.call_args_list
             if c.args[1] == name]
    assert len(calls) == 1, f"{name} {len(calls)} kez yazildi"
    data = calls[0].args[2]
    json.dumps(data)  # JSON'a yazilabilir olmali
    return data


@pytest.fixture
def unknown_bin(tmp_path: Path) -> Path:
    """Bicimi taninmayan kucuk dosya (bayt katmani icin x86 degil)."""
    p = tmp_path / "veri.bin"
    p.write_bytes(b"\x00\x11\x22\x33" * 128)
    return p


# ---------------------------------------------------------------------------
# Durum sozlugu: P03'un tarayici durumlariyla ayni dizgiler
# ---------------------------------------------------------------------------

def test_status_vocabulary_matches_p03_scanners() -> None:
    from karadul.analyzers import capa_scanner, yara_scanner
    m = ad_step_mod
    assert m.SCAN_RAN == yara_scanner.STATUS_RAN == capa_scanner.STATUS_RAN == "calisti"
    assert m.SCAN_ERROR == yara_scanner.STATUS_ERROR == capa_scanner.STATUS_ERROR == "hata"
    assert m.SCAN_NO_TOOL == capa_scanner.STATUS_NO_TOOL == "arac_yok"
    assert m.SCAN_UNSUPPORTED == capa_scanner.STATUS_UNSUPPORTED == "desteklenmiyor"
    assert m.SCAN_PARTIAL == "kismi"
    assert m.SCAN_DISABLED == "kapali"
    # Paketleyici adimi ayni sozlugu kullanir (kopya degil)
    assert pf_step_mod.SCAN_RAN is m.SCAN_RAN and pf_step_mod.SCAN_PARTIAL is m.SCAN_PARTIAL


# ---------------------------------------------------------------------------
# Anti-debug adimi
# ---------------------------------------------------------------------------

class TestAntiDebugStatus:
    def test_clean_scan_reports_ran_and_full_coverage(self, unknown_bin: Path) -> None:
        ctx = _ctx(unknown_bin)
        AntiDebugStep().run(ctx)
        p = _payload(ctx, "anti_debug_findings")
        assert p["status"] == "calisti"
        assert p["status_reason"] == ""
        assert p["file_size"] == unknown_bin.stat().st_size
        assert p["scanned_bytes"] == p["file_size"]
        assert p["total_findings"] == 0  # tarandi, temiz
        assert p["layers"]["imports"]["status"] == "calisti"
        assert p["layers"]["strings"]["status"] == "calisti"
        # Bicimi taninmayan dosyada x86 islem kodu taramasi uygulanmaz
        assert p["layers"]["bytes"]["status"] == "desteklenmiyor"
        assert p["layers"]["bytes"]["reason"]
        assert ctx.stats["anti_debug_status"] == "calisti"

    @pytest.mark.skipif(not _DEB_TRUE, reason="Debian AArch64 true yok")
    def test_aarch64_bytes_layer_unsupported(self) -> None:
        ctx = _ctx(_DEB_TRUE[0])
        AntiDebugStep().run(ctx)
        p = _payload(ctx, "anti_debug_findings")
        assert p["status"] == "calisti"
        assert p["layers"]["bytes"]["status"] == "desteklenmiyor"
        assert "arm64" in p["layers"]["bytes"]["reason"]

    def test_one_layer_error_is_partial_not_zero(self, unknown_bin: Path, monkeypatch) -> None:
        def boom(self):
            raise RuntimeError("bozuk dizgi tablosu")
        monkeypatch.setattr(ad_mod.AntiDebugDetector, "detect_by_strings", boom)
        ctx = _ctx(unknown_bin)
        out = AntiDebugStep().run(ctx)
        p = _payload(ctx, "anti_debug_findings")
        assert p["status"] == "kismi"
        assert p["total_findings"] is None  # "0 bulgu" YAZILMAZ
        assert p["layers"]["strings"]["status"] == "hata"
        assert "bozuk dizgi tablosu" in p["layers"]["strings"]["reason"]
        assert "bozuk dizgi tablosu" in p["status_reason"]
        assert p["layers"]["imports"]["status"] == "calisti"
        assert ctx.stats["anti_debug_status"] == "kismi"
        assert "anti_debug_total" not in ctx.stats
        assert any("bozuk dizgi tablosu" in e for e in ctx.errors)
        assert out["anti_debug_findings"] == []

    def test_all_layers_error_is_error(self, unknown_bin: Path, monkeypatch) -> None:
        def boom(self):
            raise RuntimeError("lief patladi")
        for meth in ("detect_by_imports", "detect_by_strings", "detect_by_bytes"):
            monkeypatch.setattr(ad_mod.AntiDebugDetector, meth, boom)
        ctx = _ctx(unknown_bin)
        AntiDebugStep().run(ctx)
        p = _payload(ctx, "anti_debug_findings")
        assert p["status"] == "hata"
        assert p["total_findings"] is None
        assert ctx.stats["anti_debug_status"] == "hata"

    def test_findings_kept_when_other_layer_fails(self, tmp_path: Path, monkeypatch) -> None:
        """Calisan katmanin bulgusu kaybolmaz; durum yine 'kismi'."""
        p_bin = tmp_path / "adb.bin"
        p_bin.write_bytes(b"\x00" * 64 + b"/proc/self/status" + b"\x00" * 64)

        def boom(self):
            raise RuntimeError("katman dustu")
        monkeypatch.setattr(ad_mod.AntiDebugDetector, "detect_by_imports", boom)
        ctx = _ctx(p_bin)
        AntiDebugStep().run(ctx)
        p = _payload(ctx, "anti_debug_findings")
        assert p["status"] == "kismi"
        assert p["total_findings"] is None
        assert [f["technique"] for f in p["findings"]] == ["Linux_ProcStatus"]

    def test_truncated_scan_is_partial(self, unknown_bin: Path, monkeypatch) -> None:
        monkeypatch.setattr(
            ad_mod, "AntiDebugDetector",
            functools.partial(ad_mod.AntiDebugDetector, max_bytes_scan=100),
        )
        ctx = _ctx(unknown_bin)
        AntiDebugStep().run(ctx)
        p = _payload(ctx, "anti_debug_findings")
        assert p["status"] == "kismi"
        assert p["scanned_bytes"] == 100
        assert p["file_size"] == 512
        assert p["total_findings"] is None
        assert "100" in p["status_reason"] and "512" in p["status_reason"]

    def test_module_missing_is_no_tool(self, unknown_bin: Path, monkeypatch) -> None:
        monkeypatch.setitem(sys.modules, "karadul.analyzers.anti_debug_detector", None)
        ctx = _ctx(unknown_bin)
        AntiDebugStep().run(ctx)
        p = _payload(ctx, "anti_debug_findings")
        assert p["status"] == "arac_yok"
        assert p["status_reason"]
        assert p["total_findings"] is None
        assert ctx.stats["anti_debug_status"] == "arac_yok"

    @pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root her dosyayi okur")
    def test_unreadable_file_is_error(self, unknown_bin: Path) -> None:
        unknown_bin.chmod(0)
        try:
            ctx = _ctx(unknown_bin)
            AntiDebugStep().run(ctx)
            p = _payload(ctx, "anti_debug_findings")
        finally:
            unknown_bin.chmod(0o644)
        assert p["status"] == "hata"
        assert "okunamadi" in p["status_reason"]
        assert p["total_findings"] is None

    def test_disabled_writes_status(self, unknown_bin: Path) -> None:
        ctx = _ctx(unknown_bin)
        ctx.pipeline_context.config.binary_reconstruction.enable_anti_debug_detection = False
        AntiDebugStep().run(ctx)
        p = _payload(ctx, "anti_debug_findings")
        assert p["status"] == "kapali"
        assert p["total_findings"] is None
        assert ctx.stats["anti_debug_status"] == "kapali"

    def test_missing_binary_writes_status(self, tmp_path: Path) -> None:
        ctx = _ctx(None)
        ctx.pipeline_context.target.path = tmp_path / "yok.bin"
        AntiDebugStep().run(ctx)
        p = _payload(ctx, "anti_debug_findings")
        assert p["status"] == "hata"
        assert "ikili" in p["status_reason"]
        assert p["total_findings"] is None

    @pytest.mark.parametrize("path", [p for p in [W32, Path("/bin/ls"), Path("/usr/bin/true"),
                                                    *(_DEB_TRUE[:1])] if p.is_file()],
                             ids=lambda p: p.name)
    def test_same_findings_as_detector_detect(self, path: Path) -> None:
        """Adim katmanlari gozler ama bulgu kumesi dedektorun detect()'iyle ayni."""
        ctx = _ctx(path)
        AntiDebugStep().run(ctx)
        p = _payload(ctx, "anti_debug_findings")
        beklenen = [f.to_dict() for f in ad_mod.AntiDebugDetector(binary_path=path).detect()]
        assert p["findings"] == beklenen
        assert p["status"] == "calisti"
        assert p["total_findings"] == len(beklenen)


# ---------------------------------------------------------------------------
# Paketleyici adimi
# ---------------------------------------------------------------------------

class TestPackerStatus:
    def test_clean_scan_reports_ran(self, unknown_bin: Path) -> None:
        ctx = _ctx(unknown_bin)
        PackerFingerprintStep().run(ctx)
        p = _payload(ctx, "packer_fingerprints")
        assert p["status"] == "calisti"
        assert p["status_reason"] == ""
        assert p["file_size"] == 512
        assert p["scanned_bytes"] == 512
        assert p["string_scan_bytes"] == 512
        assert p["total_fingerprints"] == 0
        assert ctx.stats["packer_fingerprint_status"] == "calisti"

    def test_string_window_smaller_than_file_is_partial(self, unknown_bin: Path,
                                                        monkeypatch) -> None:
        monkeypatch.setattr(pf_mod.PackerFingerprintDetector, "MAX_STRING_SCAN_BYTES", 16)
        ctx = _ctx(unknown_bin)
        PackerFingerprintStep().run(ctx)
        p = _payload(ctx, "packer_fingerprints")
        assert p["status"] == "kismi"
        assert p["string_scan_bytes"] == 16
        assert p["total_fingerprints"] is None
        assert "16" in p["status_reason"] and "512" in p["status_reason"]

    def test_detector_error_is_not_zero(self, unknown_bin: Path, monkeypatch) -> None:
        def boom(self):
            raise RuntimeError("bolum tablosu bozuk")
        monkeypatch.setattr(pf_mod.PackerFingerprintDetector, "detect_by_sections", boom)
        ctx = _ctx(unknown_bin)
        PackerFingerprintStep().run(ctx)
        p = _payload(ctx, "packer_fingerprints")
        assert p["status"] == "hata"
        assert "bolum tablosu bozuk" in p["status_reason"]
        assert p["total_fingerprints"] is None
        assert ctx.stats["packer_fingerprint_status"] == "hata"
        assert "packer_total" not in ctx.stats

    def test_module_missing_is_no_tool(self, unknown_bin: Path, monkeypatch) -> None:
        monkeypatch.setitem(sys.modules, "karadul.analyzers.packer_fingerprint", None)
        ctx = _ctx(unknown_bin)
        PackerFingerprintStep().run(ctx)
        p = _payload(ctx, "packer_fingerprints")
        assert p["status"] == "arac_yok"
        assert p["total_fingerprints"] is None

    @pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root her dosyayi okur")
    def test_unreadable_file_is_error(self, unknown_bin: Path) -> None:
        unknown_bin.chmod(0)
        try:
            ctx = _ctx(unknown_bin)
            PackerFingerprintStep().run(ctx)
            p = _payload(ctx, "packer_fingerprints")
        finally:
            unknown_bin.chmod(0o644)
        assert p["status"] == "hata"
        assert p["total_fingerprints"] is None

    def test_disabled_writes_status(self, unknown_bin: Path) -> None:
        ctx = _ctx(unknown_bin)
        ctx.pipeline_context.config.binary_reconstruction.enable_packer_fingerprint = False
        PackerFingerprintStep().run(ctx)
        p = _payload(ctx, "packer_fingerprints")
        assert p["status"] == "kapali"
        assert p["total_fingerprints"] is None


# ---------------------------------------------------------------------------
# Statik asama: YARA blogu
# ---------------------------------------------------------------------------

def _upx_pe() -> bytes:
    """UPX'in iki bagimsiz kaniti (UPX! + UPX0/UPX1 bolumleri) olan asgari PE."""
    e_lfanew = 0x80
    dos = (b"MZ" + b"\x00" * 0x3A + struct.pack("<I", e_lfanew)).ljust(e_lfanew, b"\x00")
    sections = [(b"UPX0", b"\x00" * 16), (b"UPX1", b"UPX!" + b"\x00" * 12)]
    opt_size = 224
    fh = struct.pack("<HHIIIHH", 0x14C, len(sections), 0, 0, 0, opt_size, 0x0102)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x10B)
    hdr_end = e_lfanew + 4 + 20 + opt_size + 40 * len(sections)
    raw_base = (hdr_end + 0x1FF) & ~0x1FF
    hdrs, bodies, va = b"", b"", 0x1000
    for name, raw in sections:
        hdrs += struct.pack("<8sIIIIIIHHI", name.ljust(8, b"\x00"), len(raw), va, 0x200,
                            raw_base + len(bodies), 0, 0, 0, 0, 0x60000020)
        bodies += raw.ljust(0x200, b"\x00")
        va += 0x1000
    struct.pack_into("<I", opt, 16, 0x1000)
    head = dos + b"PE\x00\x00" + fh + bytes(opt) + hdrs
    return head.ljust(raw_base, b"\x00") + bodies


class TestYaraStageBlock:
    def test_hit_recorded_with_status(self, tmp_path: Path) -> None:
        from karadul.stages import _run_yara_scan
        p = tmp_path / "upx.exe"
        p.write_bytes(_upx_pe())
        stats: dict = {}
        _run_yara_scan(p, stats)
        json.dumps(stats)
        assert stats["yara_status"] == "calisti"
        assert stats["yara_status_reason"] == ""
        assert stats["yara_backend"] in ("yara-python", "regex-fallback")
        assert stats["yara_rules_loaded"] > 0
        assert stats["yara_matches"] == len(stats["detected_tech"]) >= 1
        assert any(t.startswith("UPX_Packed (") for t in stats["detected_tech"])

    def test_clean_scan_is_ran_with_zero(self, unknown_bin: Path) -> None:
        from karadul.stages import _run_yara_scan
        stats: dict = {}
        _run_yara_scan(unknown_bin, stats)
        assert stats["yara_status"] == "calisti"
        assert stats["yara_matches"] == 0  # tarandi, temiz
        assert "detected_tech" not in stats

    def test_scan_exception_is_error_not_zero(self, unknown_bin: Path, monkeypatch) -> None:
        from karadul.analyzers import yara_scanner
        from karadul.stages import _run_yara_scan

        def boom(self, path):
            raise MemoryError("kural derlenemedi")
        monkeypatch.setattr(yara_scanner.YaraScanner, "scan_file", boom)
        stats: dict = {}
        _run_yara_scan(unknown_bin, stats)
        assert stats["yara_status"] == "hata"
        assert "kural derlenemedi" in stats["yara_status_reason"]
        assert stats["yara_matches"] is None
        assert "detected_tech" not in stats

    def test_malformed_result_is_error_not_crash(self, unknown_bin: Path, monkeypatch) -> None:
        """Beklenmeyen bicimde sonuc (eksik alan) asamayi dusurmez, yarim sayac birakmaz."""
        from types import SimpleNamespace

        from karadul.analyzers import yara_scanner
        from karadul.stages import _run_yara_scan
        monkeypatch.setattr(yara_scanner.YaraScanner, "scan_file",
                            lambda self, p: SimpleNamespace(matches=[]))
        stats: dict = {}
        _run_yara_scan(unknown_bin, stats)
        assert stats["yara_status"] == "hata"
        assert "AttributeError" in stats["yara_status_reason"]
        assert stats["yara_matches"] is None
        assert "yara_backend" not in stats

    def test_scanner_error_result_is_error(self, tmp_path: Path) -> None:
        from karadul.stages import _run_yara_scan
        stats: dict = {}
        _run_yara_scan(tmp_path / "yok.bin", stats)
        assert stats["yara_status"] == "hata"
        assert stats["yara_status_reason"]
        assert stats["yara_matches"] is None

    def test_import_error_is_no_tool(self, unknown_bin: Path, monkeypatch) -> None:
        from karadul.stages import _run_yara_scan
        monkeypatch.setitem(sys.modules, "karadul.analyzers.yara_scanner", None)
        stats: dict = {}
        _run_yara_scan(unknown_bin, stats)
        assert stats["yara_status"] == "arac_yok"
        assert stats["yara_matches"] is None


# ---------------------------------------------------------------------------
# Statik asama: capa blogu durumu
# ---------------------------------------------------------------------------

def _capa_ctx(tmp_path: Path, target_type, *, enable_capa=True, feed=None):
    from karadul.core.workspace import Workspace
    ws = Workspace(tmp_path / "ws", "hedef")
    ws.create()
    ctx = MagicMock()
    ctx.workspace = ws
    br = ctx.config.binary_reconstruction
    br.enable_capa = enable_capa
    br.capa_rules_path = ""
    br.capa_timeout = 60
    if feed is None:
        del br.enable_capa_code_feed  # alan yok (config.py'de henuz tanimli degil)
    else:
        br.enable_capa_code_feed = feed
    target = MagicMock()
    target.target_type = target_type
    target.path = tmp_path / "hedef.bin"
    target.path.write_bytes(b"\x00" * 64)
    return ctx, target


class TestCapaStageStatus:
    def test_disabled_is_kapali(self, tmp_path: Path) -> None:
        from karadul.core.target import TargetType
        from karadul.stages import _run_capa_scan
        ctx, target = _capa_ctx(tmp_path, TargetType.PE_BINARY, enable_capa=False)
        stats: dict = {}
        _run_capa_scan(ctx, target, stats)
        assert stats["capa_status"] == "kapali"
        assert stats["capa_status_reason"] == "enable_capa=False"

    def test_non_binary_target_is_unsupported(self, tmp_path: Path) -> None:
        from karadul.core.target import TargetType
        from karadul.stages import _run_capa_scan
        ctx, target = _capa_ctx(tmp_path, TargetType.JS_BUNDLE)
        stats: dict = {}
        _run_capa_scan(ctx, target, stats)
        assert stats["capa_status"] == "desteklenmiyor"
        assert "js_bundle" in stats["capa_status_reason"]

    def test_scanner_exception_is_error(self, tmp_path: Path, monkeypatch) -> None:
        from karadul.analyzers import capa_scanner
        from karadul.core.target import TargetType
        from karadul.stages import _run_capa_scan

        def boom(self, path, **kw):
            raise RuntimeError("vivisect coktu")
        monkeypatch.setattr(capa_scanner.CAPAScanner, "scan", boom)
        ctx, target = _capa_ctx(tmp_path, TargetType.PE_BINARY)
        stats: dict = {}
        _run_capa_scan(ctx, target, stats)
        assert stats["capa_status"] == "hata"
        assert "vivisect coktu" in stats["capa_status_reason"]
        assert "capa_rules_matched" not in stats

    def test_unsupported_macho_status_from_scanner(self, tmp_path: Path) -> None:
        """Gercek tarayici: Mach-O capa kapsami disinda -> durum + neden, sessizlik yok."""
        from karadul.core.target import TargetType
        from karadul.stages import _run_capa_scan
        ctx, target = _capa_ctx(tmp_path, TargetType.MACHO_BINARY)
        target.path.write_bytes(struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 3, 2, 0, 0, 0, 0))
        stats: dict = {}
        _run_capa_scan(ctx, target, stats)
        assert stats["capa_status"] in ("desteklenmiyor", "arac_yok")
        assert stats["capa_status_reason"]
