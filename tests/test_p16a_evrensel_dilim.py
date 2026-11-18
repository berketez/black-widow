"""P16a / evrensel ikili dilimi (P00 gözlemi): arm64e doğru seçilir, dilim adı gerçek mimariyi söyler.

Eski davranış (P00, ``docs/arge/2026-11-18_onarim/P00.md``): ``lipo -thin arm64`` macOS sistem
ikililerinde (arm64e) düşüyor, x86_64'e geçip dilimi ``raw/<ad>_arm64`` adıyla yazıyordu;
yalnız arm64e taşıyanlarda (``/usr/bin/ssh``, ``/usr/sbin/sshd``, ``/usr/sbin/ioreg``) iki deneme
de düşüp şişman dosya taranıyordu.
"""
from __future__ import annotations

import json
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from karadul.analyzers.macho import MachOAnalyzer, read_fat_slices, select_fat_slice
from karadul.core.workspace import Workspace

ARM64 = (0x0100000C, 0)
ARM64E = (0x0100000C, 0x80000002)       # PTRAUTH_ABI bayrağıyla (sistem ikilileri)
ARM64E_X1 = (0x0100000C, 0x8000000C)    # lipo: "unknown(16777228,12)"
X86_64 = (0x01000007, 3)


def _ince(etiket: bytes, boy: int = 64) -> bytes:
    return b"\xcf\xfa\xed\xfe" + etiket.ljust(boy - 4, b"\x00")


def _fat(dilimler: list[tuple[tuple[int, int], bytes]], magic64: bool = False) -> bytes:
    """Gerçek düzende fat dosyası: başlık + 0x1000 hizalı dilimler."""
    giris = 32 if magic64 else 20
    ofset = 0x1000
    tablo, govde = b"", b""
    for (ct, cs), veri in dilimler:
        if magic64:
            tablo += struct.pack(">iIQQII", ct, cs, ofset, len(veri), 12, 0)
        else:
            tablo += struct.pack(">iIIII", ct, cs, ofset, len(veri), 12)
        govde += veri.ljust(0x1000, b"\x00")
        ofset += 0x1000
    bas = struct.pack(">II", 0xCAFEBABF if magic64 else 0xCAFEBABE, len(dilimler)) + tablo
    assert len(bas) <= 0x1000 and giris
    return bas.ljust(0x1000, b"\x00") + govde


def _ws(tmp_path: Path) -> Workspace:
    ws = Workspace(tmp_path / "ws", "hedef")
    ws.create()
    return ws


def _cikar(tmp_path: Path, icerik: bytes):
    yol = tmp_path / "hedef"
    yol.write_bytes(icerik)
    ws = _ws(tmp_path)
    stats: dict = {}
    errors: list = []
    dilim = MachOAnalyzer._extract_universal_slice(yol, ws, "hedef", stats, errors)
    kayit = json.loads((ws.get_stage_dir("static") / "universal_slice.json").read_text())
    return dilim, stats, errors, kayit, ws


def test_x86_64_ve_arm64e_varken_arm64e_secilir_ve_adi_dogru(tmp_path):
    dilim, stats, errors, kayit, ws = _cikar(tmp_path, _fat([
        (X86_64, _ince(b"x86")), (ARM64E, _ince(b"arm64e")), (ARM64E_X1, _ince(b"x1")),
    ]))
    assert dilim is not None and dilim.name == "hedef_arm64e"
    assert dilim.parent == ws.get_stage_dir("raw")
    assert dilim.read_bytes() == _ince(b"arm64e")
    assert stats["universal_slice"] == "arm64e"
    assert stats["universal_slices"] == ["x86_64", "arm64e", "arm64_sub12"]
    assert kayit["selected"] == "arm64e" and kayit["path"] == "hedef_arm64e"
    assert errors == []


def test_duz_arm64_arm64eden_once_gelir(tmp_path):
    dilim, stats, _, _, _ = _cikar(tmp_path, _fat([(ARM64E, _ince(b"e")), (ARM64, _ince(b"duz"))]))
    assert stats["universal_slice"] == "arm64"
    assert dilim.read_bytes() == _ince(b"duz")


def test_yalniz_x86_64_varsa_adi_x86_64(tmp_path):
    dilim, stats, _, _, _ = _cikar(tmp_path, _fat([(X86_64, _ince(b"x"))], magic64=True))
    assert dilim.name == "hedef_x86_64"
    assert stats["universal_slice"] == "x86_64"


def test_bozuk_baslikta_durum_acik(tmp_path):
    dilim, stats, errors, kayit, _ = _cikar(tmp_path, b"\xca\xfe\xba\xbe" + struct.pack(">I", 9999))
    assert dilim is None
    assert stats["universal_slice"] is None
    assert "dilim sayısı geçersiz" in stats["universal_slice_error"]
    assert any("dilim seçilemedi" in e for e in errors)
    assert kayit["selected"] is None and kayit["error"]


def test_macho_olmayan_dilim_reddedilir(tmp_path):
    dilim, stats, errors, _, _ = _cikar(tmp_path, _fat([(ARM64E, b"\x00" * 64)]))
    assert dilim is None
    assert "Mach-O değil" in stats["universal_slice_error"]


def test_dosya_disina_tasan_dilim_reddedilir(tmp_path):
    p = tmp_path / "k"
    p.write_bytes(struct.pack(">II", 0xCAFEBABE, 1) + struct.pack(">iIIII", *ARM64, 0x1000, 0x5000, 12))
    with pytest.raises(ValueError, match="dosya dışına"):
        read_fat_slices(p)


def test_secim_belirlenimci():
    s = [{"rank": 1, "index": 1, "arch": "b"}, {"rank": 1, "index": 0, "arch": "a"}]
    assert select_fat_slice(s)["arch"] == "a"
    assert select_fat_slice([]) is None


@pytest.mark.parametrize("ikili", ["/usr/bin/ssh", "/bin/ls"])
def test_gercek_sistem_ikilisinde_arm64e_ve_lipo_ile_ayni_bayt(tmp_path, ikili):
    lipo = shutil.which("lipo") or "/usr/bin/lipo"
    if not Path(ikili).is_file() or not Path(lipo).exists():
        pytest.skip("macOS sistem ikilisi ya da lipo yok")
    if b"\xca\xfe\xba\xbe" != Path(ikili).read_bytes()[:4]:
        pytest.skip("evrensel değil")
    ws = _ws(tmp_path)
    stats: dict = {}
    dilim = MachOAnalyzer._extract_universal_slice(Path(ikili), ws, "hedef", stats, [])
    assert stats["universal_slice"] == "arm64e"
    assert dilim.name == "hedef_arm64e"
    lipo_cikti = tmp_path / "lipo_arm64e"
    r = subprocess.run([lipo, ikili, "-thin", "arm64e", "-output", str(lipo_cikti)],
                       capture_output=True)
    if r.returncode != 0:
        pytest.skip("lipo -thin arm64e çalışmadı: %s" % r.stderr[:200])
    assert dilim.read_bytes() == lipo_cikti.read_bytes()


def test_binary_prep_secilen_dilimi_kullanir(tmp_path):
    from types import SimpleNamespace

    from karadul.core.target import TargetType
    from karadul.pipeline.steps.binary_prep import BinaryPrepStep

    dilim, _, _, _, ws = _cikar(tmp_path, _fat([(X86_64, _ince(b"x")), (ARM64E, _ince(b"e"))]))
    hedef = SimpleNamespace(path=tmp_path / "hedef", name="hedef",
                            target_type=TargetType.UNIVERSAL_BINARY)
    ctx = SimpleNamespace(stats={})
    sonuc = BinaryPrepStep._resolve_byte_match_binary(hedef, ws, ctx)
    assert sonuc == dilim
    assert ctx.stats["byte_match_binary"] == "arm64e_slice"

    (ws.get_stage_dir("static") / "universal_slice.json").write_text(
        json.dumps({"selected": None, "path": None, "error": "dilim yok"}))
    ctx = SimpleNamespace(stats={})
    assert BinaryPrepStep._resolve_byte_match_binary(hedef, ws, ctx) == hedef.path
    assert ctx.stats["byte_match_binary"] == "fat"
    assert ctx.stats["byte_match_slice_error"] == "dilim yok"
