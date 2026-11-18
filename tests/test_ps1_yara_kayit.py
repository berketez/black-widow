"""P-S1 kalem 2 (ARAYUZ-17, kayıt kısmı): YARA isabetleri yapılandırılmış kayıt.

Bugüne dek isabetler ``static.stats.detected_tech``'e yalnız düz dizgi
(``"<kural> (<etiketler>)"``) olarak yazılıyordu; meta, eşleşen dizgi ve ofset
kayboluyordu, SARIF dizgi dalında ``tech_type="unknown"`` atıyordu. Artık
``static.stats.yara_hits`` sözlük listesidir (şema ``docs/arge/2026-11-18_onarim/
P-S1.md`` kalem 2). Geçiş için ``detected_tech`` aynı isabetlerden yazılmaya
devam eder.
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

import pytest

from karadul.analyzers.yara_scanner import YaraMatch
from karadul.stages import (
    _YARA_HIT_MAX_DATA,
    _YARA_HIT_MAX_STRINGS,
    _run_yara_scan,
    _yara_hit_record,
)

W32 = Path(sys.prefix) / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" \
    / "site-packages" / "pip" / "_vendor" / "distlib" / "w32.exe"

HIT_KEYS = {"rule", "tags", "meta", "namespace", "strings", "strings_total"}
STRING_KEYS = {"offset", "identifier", "length", "data_hex", "data_text"}


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


class TestRecord:
    def test_fields_and_truncation(self) -> None:
        m = YaraMatch(
            rule="UPX_Packed", tags=["packer", "upx"],
            meta={"severity": "medium", "condition": "UPX! ve UPX0", "ham": b"\x01\x02"},
            strings=[(0x10 * i, f"$s{i}", b"UPX!" * 40) for i in range(12)],
            namespace="default",
        )
        r = _yara_hit_record(m)
        json.dumps(r)
        assert set(r) == HIT_KEYS
        assert r["rule"] == "UPX_Packed"
        assert r["tags"] == ["packer", "upx"]
        assert r["meta"]["condition"] == "UPX! ve UPX0"
        assert r["meta"]["ham"] == "0102"  # bytes -> onaltilik (JSON'a yazilabilir)
        assert r["strings_total"] == 12
        assert len(r["strings"]) == _YARA_HIT_MAX_STRINGS
        s0 = r["strings"][0]
        assert set(s0) == STRING_KEYS
        assert s0["length"] == 160
        assert len(bytes.fromhex(s0["data_hex"])) == _YARA_HIT_MAX_DATA
        assert s0["data_text"] == ("UPX!" * 40)[:_YARA_HIT_MAX_DATA]
        assert r["strings"][3]["offset"] == 0x30 and r["strings"][3]["identifier"] == "$s3"

    def test_binary_data_has_no_text(self) -> None:
        r = _yara_hit_record(YaraMatch(rule="R", strings=[(4, "$b0", b"\x60\xe8\x00\x00")]))
        assert r["strings"][0]["data_text"] is None
        assert r["strings"][0]["data_hex"] == "60e80000"


class TestStageStats:
    def test_hits_parallel_to_legacy_list(self, tmp_path: Path) -> None:
        p = tmp_path / "upx.exe"
        p.write_bytes(_upx_pe())
        stats: dict = {}
        _run_yara_scan(p, stats)
        json.dumps(stats)
        hits = stats["yara_hits"]
        assert stats["yara_matches"] == len(hits) >= 1
        assert all(set(h) == HIT_KEYS for h in hits)
        upx = next(h for h in hits if h["rule"] == "UPX_Packed")
        assert "packer" in upx["tags"]
        assert upx["strings"], "eslesen dizgi kayitta olmali"
        assert any(s["data_text"] == "UPX!" for s in upx["strings"])
        # Gecis: eski duz liste ayni isabetlerden, ayni sirayla
        assert stats["detected_tech"] == [
            f"{h['rule']} ({','.join(h['tags']) if h['tags'] else 'unknown'})" for h in hits]

    def test_clean_scan_empty_list(self, tmp_path: Path) -> None:
        p = tmp_path / "veri.bin"
        p.write_bytes(b"\x00" * 256)
        stats: dict = {}
        _run_yara_scan(p, stats)
        assert stats["yara_status"] == "calisti"
        assert stats["yara_hits"] == []  # tarandi, temiz
        assert "detected_tech" not in stats

    def test_error_has_no_hits(self, tmp_path: Path) -> None:
        stats: dict = {}
        _run_yara_scan(tmp_path / "yok.bin", stats)
        assert stats["yara_status"] == "hata"
        assert stats["yara_hits"] is None

    @pytest.mark.skipif(not W32.is_file(), reason="pip distlib w32.exe yok")
    def test_real_pe_hit_has_offsets(self) -> None:
        stats: dict = {}
        _run_yara_scan(W32, stats)
        hits = {h["rule"]: h for h in stats["yara_hits"]}
        assert "MSVC_Compiler" in hits
        h = hits["MSVC_Compiler"]
        assert h["meta"].get("condition")
        size = W32.stat().st_size
        assert all(0 <= s["offset"] < size for s in h["strings"])
