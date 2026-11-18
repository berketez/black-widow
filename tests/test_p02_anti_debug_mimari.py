"""P02 / IMZA-02: anti-debug işlem kodu taraması mimariye ve yürütülebilir bölüme bağlı.

Eski davranış (taban e9d2d08): ``detect_by_bytes`` dosyanın tamamını ham bayt
olarak tarıyor, AArch64 ikilide de "0F 31"i rdtsc sayıyordu (Debian coreutils
``pwd`` → "Anti-Debug [MED]"); PEB desenleri ELF / Mach-O'da da aranıyordu;
``sysctl`` / ``prctl`` tek ithali 0,55 / 0,30 güvenle hüküm oluyordu; ELF'te
``ptrace`` ithali macOS'un PT_DENY_ATTACH tekniği olarak da yazılıyordu.

Buradaki sınamaların her biri eski kodda KIRMIZI, yeni kodda yeşildir
(``scripts/measurement/mutation_specs_p02.json``).

İkili kurucular (ELF / Mach-O / evrensel Mach-O / PE) bu dosyada; öbür P02
test dosyaları da buradan içe aktarır.
"""

from __future__ import annotations

import os
import struct
import sys
from pathlib import Path
from unittest import mock

import pytest

from karadul.analyzers.anti_debug_detector import AntiDebugDetector, code_layout
from scripts.measurement.p02_pozitif.pe_sentetik import Kod, pe_olustur

# ---------------------------------------------------------------------------
# İkili kurucular
# ---------------------------------------------------------------------------

EM_X86_64 = 62
EM_AARCH64 = 183
CPU_X86_64 = 0x01000007
CPU_ARM64 = 0x0100000C

RDTSC = b"\x0f\x31"
# Kod dışı tuzak: 7 adet "0F 31" (salt okunur veri)
TUZAK_0F31 = RDTSC * 7
# Gerçek x86-64 kodu: rdtsc; mov r8d, eax; rdtsc; sub eax, r8d; ret
X64_RDTSC_IKILI = b"\x0f\x31\x41\x89\xc0\x0f\x31\x44\x29\xc0\xc3"
# "0F 31" baytları bir komutun İÇİNDE: mov eax, 0x00310f00 (B8 00 0F 31 00); ret
X64_ICINDE_0F31 = b"\xb8\x00\x0f\x31\x00\xc3" * 4


def elf64(machine: int, text: bytes, rodata: bytes = b"", *, shdr: bool = True) -> bytes:
    """Küçük ELF64 (LE): .text (SHF_ALLOC|SHF_EXECINSTR) + .rodata (SHF_ALLOC).

    ``shdr=False``: bölüm tablosu yok; kod yürütülebilir PT_LOAD'dan bulunur,
    .rodata ayrı salt okunur PT_LOAD'dadır.
    """
    ehdr_size, phent = 64, 56
    phnum = 2
    text_off = ehdr_size + phnum * phent
    ro_off = text_off + len(text)
    shstr = b"\0.text\0.rodata\0.shstrtab\0"
    shstr_off = ro_off + len(rodata)
    shoff = shstr_off + len(shstr) if shdr else 0
    shnum = 4 if shdr else 0
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
    ehdr = ident + struct.pack("<HHIQQQIHHHHHH", 2, machine, 1, 0x400000 + text_off,
                               ehdr_size, shoff, 0, ehdr_size, phent, phnum, 64, shnum,
                               3 if shdr else 0)
    # PT_LOAD R+X (yalnız .text) ve PT_LOAD R (yalnız .rodata)
    ph = struct.pack("<IIQQQQQQ", 1, 0x5, text_off, 0x400000 + text_off,
                     0x400000 + text_off, len(text), len(text), 0x1000)
    ph += struct.pack("<IIQQQQQQ", 1, 0x4, ro_off, 0x600000 + ro_off,
                      0x600000 + ro_off, len(rodata), len(rodata), 0x1000)
    body = ehdr + ph + text + rodata + shstr
    if not shdr:
        return body

    def sh(name: int, typ: int, flags: int, addr: int, off: int, size: int) -> bytes:
        return struct.pack("<IIQQQQIIQQ", name, typ, flags, addr, off, size, 0, 0, 1, 0)

    shdrs = (b"\0" * 64
             + sh(1, 1, 0x6, 0x400000 + text_off, text_off, len(text))
             + sh(7, 1, 0x2, 0x600000 + ro_off, ro_off, len(rodata))
             + sh(15, 3, 0, 0, shstr_off, len(shstr)))
    return body + shdrs


def macho64(cputype: int, text: bytes, const: bytes = b"") -> bytes:
    """Küçük Mach-O 64 (LE): __TEXT segmenti; __text (komut) + __const (veri)."""
    nsects = 2
    seg_size = 72 + 80 * nsects
    hdr = struct.pack("<IiiIIIII", 0xFEEDFACF, cputype, 3, 2, 1, seg_size, 0, 0)
    text_off = 32 + seg_size
    const_off = text_off + len(text)
    seg = struct.pack("<II16sQQQQiiII", 0x19, seg_size, b"__TEXT", 0x100000000,
                      0x4000, 0, const_off + len(const), 5, 5, nsects, 0)

    def sect(name: bytes, addr: int, size: int, off: int, flags: int) -> bytes:
        return struct.pack("<16s16sQQIIIIIIII", name, b"__TEXT", addr, size, off, 4,
                           0, 0, flags, 0, 0, 0)

    seg += sect(b"__text", 0x100000000 + text_off, len(text), text_off, 0x80000400)
    seg += sect(b"__const", 0x100000000 + const_off, len(const), const_off, 0x0)
    return hdr + seg + text + const


def fat(*slices: tuple[int, bytes]) -> bytes:
    """Evrensel Mach-O (FAT_MAGIC, büyük uçlu başlık); dilimler 0x1000'e hizalı."""
    hdr = struct.pack(">II", 0xCAFEBABE, len(slices))
    body = b""
    off = 0x1000
    ents = b""
    for cputype, blob in slices:
        ents += struct.pack(">iiIII", cputype, 3, off, len(blob), 12)
        pad = (-(off + len(blob))) % 0x1000
        body += blob + b"\0" * pad
        off += len(blob) + pad
    head = (hdr + ents).ljust(0x1000, b"\0")
    return head + body


def pe(mimari: str, text: bytes, rdata_tuzak: bytes = b"",
       ithaller: dict[str, list[str]] | None = None) -> bytes:
    """Gerçek bölüm tablolu küçük PE (.text yürütülebilir, .rdata değil)."""
    return pe_olustur(mimari, text, ithaller or {}, rdata_tuzak)


def yaz(tmp_path: Path, ad: str, veri: bytes) -> Path:
    p = tmp_path / ad
    p.write_bytes(veri)
    return p


def teknikler(bulgular) -> dict[str, object]:
    return {f.technique: f for f in bulgular}


# ---------------------------------------------------------------------------
# Kod yerleşimi
# ---------------------------------------------------------------------------

class TestKodYerlesimi:
    def test_elf_bolum_tablosundan(self):
        veri = elf64(EM_X86_64, b"\x90" * 16, b"\x00" * 8)
        lay = code_layout(veri)
        assert (lay.fmt, lay.arch) == ("elf", "x86_64")
        assert len(lay.regions) == 1
        r = lay.regions[0]
        assert veri[r.start:r.end] == b"\x90" * 16

    def test_elf_bolum_tablosu_yoksa_pt_load(self):
        veri = elf64(EM_AARCH64, b"\x1f\x20\x03\xd5" * 4, b"x" * 8, shdr=False)
        lay = code_layout(veri)
        assert (lay.fmt, lay.arch) == ("elf", "arm64")
        assert [veri[r.start:r.end] for r in lay.regions] == [b"\x1f\x20\x03\xd5" * 4]

    def test_macho_yalniz_komut_bolumu(self):
        veri = macho64(CPU_X86_64, b"\xc3" * 4, b"\x0f\x31" * 3)
        lay = code_layout(veri)
        assert (lay.fmt, lay.arch) == ("macho", "x86_64")
        assert [r.name for r in lay.regions] == ["__TEXT,__text"]

    def test_evrensel_macho_x86_64_dilimi_secilir(self):
        veri = fat((CPU_ARM64, macho64(CPU_ARM64, b"\x1f\x20\x03\xd5")),
                   (CPU_X86_64, macho64(CPU_X86_64, b"\x90\xc3")))
        lay = code_layout(veri)
        assert lay.arch == "x86_64"
        assert "x86_64 dilimi" in lay.note
        assert veri[lay.regions[0].start:lay.regions[0].end] == b"\x90\xc3"

    def test_pe_yalniz_yurutulebilir_bolum(self):
        veri = pe("x86_64", b"\x90\xc3", rdata_tuzak=b"\x0f\x31" * 4)
        lay = code_layout(veri)
        assert (lay.fmt, lay.arch) == ("pe", "x86_64")
        assert [r.name for r in lay.regions] == [".text"]

    def test_java_class_evrensel_sanilmaz(self):
        # CAFEBABE + sürüm 0x0000003d (61) -> evrensel Mach-O değil
        assert code_layout(b"\xca\xfe\xba\xbe\x00\x00\x00\x3d" + b"\0" * 64).fmt == "unknown"


# ---------------------------------------------------------------------------
# İşlem kodu taraması: mimari + bölüm
# ---------------------------------------------------------------------------

class TestIslemKoduMimari:
    def test_aarch64_elf_rdtsc_yok(self, tmp_path):
        """AArch64 ELF'in hem kodunda hem verisinde "0F 31" var: rdtsc DEĞİL."""
        p = yaz(tmp_path, "arm.elf", elf64(EM_AARCH64, RDTSC * 6 + b"\xcc" * 20, TUZAK_0F31))
        bul = teknikler(AntiDebugDetector(binary_path=p).detect_by_bytes())
        assert "RDTSC_Timing" not in bul
        assert "INT3_Cluster" not in bul
        assert bul == {}

    def test_x86_64_elf_yalniz_text_sayilir(self, tmp_path):
        """.text'te 2 gerçek rdtsc, .rodata'da 7 tuzak: sayı 2 olmalı."""
        p = yaz(tmp_path, "x64.elf", elf64(EM_X86_64, X64_RDTSC_IKILI, TUZAK_0F31))
        bul = teknikler(AntiDebugDetector(binary_path=p).detect_by_bytes())
        f = bul["RDTSC_Timing"]
        assert f.evidence.startswith("rdtsc x2, rdtscp x0")
        assert f.confidence <= 0.30

    def test_x86_64_elf_bolum_tablosuz_pt_load(self, tmp_path):
        p = yaz(tmp_path, "x64np.elf",
                elf64(EM_X86_64, X64_RDTSC_IKILI, TUZAK_0F31, shdr=False))
        f = teknikler(AntiDebugDetector(binary_path=p).detect_by_bytes())["RDTSC_Timing"]
        assert f.evidence.startswith("rdtsc x2,")

    def test_komut_icindeki_0f31_sayilmaz(self, tmp_path):
        """mov eax, 0x00310f00 komutunun baytları "0F 31" içerir; rdtsc değildir."""
        pytest.importorskip("capstone")
        p = yaz(tmp_path, "imm.elf", elf64(EM_X86_64, X64_ICINDE_0F31))
        bul = teknikler(AntiDebugDetector(binary_path=p).detect_by_bytes())
        assert "RDTSC_Timing" not in bul

    def test_rdtsc_sayisi_zayif_ustunu_gecmez(self, tmp_path):
        """Çok sayıda rdtsc tek tür zayıf kanıttır: güven 0,30'u aşmaz (eski: 5+ → 0,45)."""
        p = yaz(tmp_path, "cok.elf", elf64(EM_X86_64, (RDTSC + b"\x90") * 12 + b"\xc3"))
        f = teknikler(AntiDebugDetector(binary_path=p).detect_by_bytes())["RDTSC_Timing"]
        assert f.evidence.startswith("rdtsc x12,")
        assert f.confidence <= 0.30

    def test_macho_const_tuzagi_sayilmaz(self, tmp_path):
        p = yaz(tmp_path, "x.macho", macho64(CPU_X86_64, X64_RDTSC_IKILI, TUZAK_0F31))
        f = teknikler(AntiDebugDetector(binary_path=p).detect_by_bytes())["RDTSC_Timing"]
        assert f.evidence.startswith("rdtsc x2,")

    def test_arm64_macho_bulgu_yok(self, tmp_path):
        p = yaz(tmp_path, "a.macho", macho64(CPU_ARM64, RDTSC * 8, TUZAK_0F31))
        assert AntiDebugDetector(binary_path=p).detect_by_bytes() == []

    def test_evrensel_macho_yalniz_x86_64_dilimi(self, tmp_path):
        """arm64 diliminde 8 "0F 31" (kod + veri), x86_64 diliminde 2 gerçek rdtsc."""
        veri = fat((CPU_ARM64, macho64(CPU_ARM64, RDTSC * 8, TUZAK_0F31)),
                   (CPU_X86_64, macho64(CPU_X86_64, X64_RDTSC_IKILI, TUZAK_0F31)))
        p = yaz(tmp_path, "fat", veri)
        f = teknikler(AntiDebugDetector(binary_path=p).detect_by_bytes())["RDTSC_Timing"]
        assert f.evidence.startswith("rdtsc x2,")
        assert "x86_64 dilimi" in f.evidence

    def test_bicimi_bilinmeyen_dosyada_bulgu_yok(self, tmp_path):
        p = yaz(tmp_path, "ham.bin", b"\x90" * 64 + RDTSC * 9 + b"\xcc" * 32)
        assert AntiDebugDetector(binary_path=p).detect_by_bytes() == []

    def test_pe_rdata_tuzagi_sayilmaz(self, tmp_path):
        p = yaz(tmp_path, "t.exe", pe("x86_64", X64_RDTSC_IKILI, TUZAK_0F31))
        f = teknikler(AntiDebugDetector(binary_path=p).detect_by_bytes())["RDTSC_Timing"]
        assert f.evidence.startswith("rdtsc x2,")


# ---------------------------------------------------------------------------
# PEB: yalnız PE, yalnız kendi mimarisi, denetim komut düzeyinde
# ---------------------------------------------------------------------------

GS60_BEING_DEBUGGED = (b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00"  # mov rax, gs:[0x60]
                       b"\x0f\xb6\x40\x02"                       # movzx eax, byte [rax+2]
                       b"\x85\xc0\xc3")                          # test eax, eax; ret
# MSVC UCRT'nin olağan PEB okuması: NtGlobalFlag & 0x100 (app verifier), anti-debug değil
GS60_UCRT = (b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00"  # mov rax, gs:[0x60]
             b"\x8b\x90\xbc\x00\x00\x00"               # mov edx, [rax+0xbc]
             b"\xc1\xea\x08"                           # shr edx, 8
             b"\xf6\xc2\x01\xc3")                      # test dl, 1; ret
FS30_NTGLOBALFLAG = (b"\x64\xa1\x30\x00\x00\x00"  # mov eax, fs:[0x30]
                     b"\x8b\x40\x68"               # mov eax, [eax+0x68]
                     b"\x83\xe0\x70"               # and eax, 0x70
                     b"\xc3")


class TestPEB:
    def test_pe_x64_being_debugged_hukum(self, tmp_path):
        pytest.importorskip("capstone")
        p = yaz(tmp_path, "bd.exe", pe("x86_64", GS60_BEING_DEBUGGED))
        f = teknikler(AntiDebugDetector(binary_path=p).detect_by_bytes())["PEB_GS60_x64"]
        assert f.confidence >= 0.5
        assert "BeingDebugged" in f.evidence
        assert f.platform == "windows"

    def test_pe_x86_ntglobalflag_hukum(self, tmp_path):
        pytest.importorskip("capstone")
        p = yaz(tmp_path, "ngf.exe", pe("x86", FS30_NTGLOBALFLAG))
        f = teknikler(AntiDebugDetector(binary_path=p).detect_by_bytes())["PEB_FS30_x86"]
        assert "NtGlobalFlag & 0x70" in f.evidence

    def test_ucrt_peb_okumasi_hukum_degil(self, tmp_path):
        """UCRT'nin NtGlobalFlag & 0x100 okuması: yalnız bilgi (eski: PEB_GS60_x64 0,55)."""
        pytest.importorskip("capstone")
        p = yaz(tmp_path, "ucrt.exe", pe("x86_64", GS60_UCRT))
        bul = teknikler(AntiDebugDetector(binary_path=p).detect_by_bytes())
        assert "PEB_GS60_x64" not in bul
        assert bul["PEB_Read"].confidence < 0.4

    def test_elf_icinde_peb_deseni_aranmaz(self, tmp_path):
        p = yaz(tmp_path, "peb.elf", elf64(EM_X86_64, GS60_BEING_DEBUGGED))
        bul = teknikler(AntiDebugDetector(binary_path=p).detect_by_bytes())
        assert not any(t.startswith("PEB") for t in bul)

    def test_pe_rdata_icindeki_peb_deseni_aranmaz(self, tmp_path):
        p = yaz(tmp_path, "rd.exe", pe("x86_64", b"\x90\xc3", GS60_BEING_DEBUGGED))
        bul = teknikler(AntiDebugDetector(binary_path=p).detect_by_bytes())
        assert not any(t.startswith("PEB") for t in bul)

    def test_32_bit_pe_de_gs60_aranmaz(self, tmp_path):
        p = yaz(tmp_path, "w32.exe", pe("x86", GS60_BEING_DEBUGGED))
        bul = teknikler(AntiDebugDetector(binary_path=p).detect_by_bytes())
        assert "PEB_GS60_x64" not in bul


# ---------------------------------------------------------------------------
# capstone yoksa: bayt taraması yedeği, hüküm yok
# ---------------------------------------------------------------------------

class TestCapstoneYok:
    def test_bayt_yedegi_zayif_kalir(self, tmp_path):
        p = yaz(tmp_path, "x.elf", elf64(EM_X86_64, (RDTSC + b"\x90") * 3 + b"\xc3"))
        with mock.patch.dict(sys.modules, {"capstone": None}):
            f = teknikler(AntiDebugDetector(binary_path=p).detect_by_bytes())["RDTSC_Timing"]
        assert "bayt taramasi" in f.evidence
        assert f.confidence == pytest.approx(0.20)

    def test_bayt_yedeginde_peb_yalniz_okuma(self, tmp_path):
        p = yaz(tmp_path, "bd.exe", pe("x86_64", GS60_BEING_DEBUGGED))
        with mock.patch.dict(sys.modules, {"capstone": None}):
            bul = teknikler(AntiDebugDetector(binary_path=p).detect_by_bytes())
        assert "PEB_GS60_x64" not in bul
        assert bul["PEB_Read"].confidence < 0.4


# ---------------------------------------------------------------------------
# İthal katmanı: katalog biçime bağlı; sysctl / prctl yalnız bilgi
# ---------------------------------------------------------------------------

def _lief_sahte(fmt: str, adlar: list[str]):
    ikili = mock.MagicMock()
    ikili.format = fmt
    ikili.imports = []
    syms = []
    for a in adlar:
        s = mock.MagicMock()
        s.name = a
        s.is_function = True
        syms.append(s)
    ikili.dynamic_symbols = syms if fmt == "ELF" else []
    ikili.imported_symbols = []
    fns = []
    for a in adlar:
        fn = mock.MagicMock()
        fn.name = a
        fns.append(fn)
    ikili.imported_functions = fns if fmt == "MACHO" else []
    lief = mock.MagicMock()
    lief.parse.return_value = ikili
    return lief


class TestIthalKatalogu:
    def test_elf_ptrace_macos_teknigi_olmaz(self, tmp_path):
        p = yaz(tmp_path, "a.elf", elf64(EM_AARCH64, b"\xc0\x03\x5f\xd6"))
        with mock.patch.dict(sys.modules, {"lief": _lief_sahte("ELF", ["ptrace"])}):
            bul = teknikler(AntiDebugDetector(binary_path=p).detect_by_imports())
        assert set(bul) == {"ptrace_traceme"}
        assert bul["ptrace_traceme"].platform == "linux"

    def test_macho_ptrace_linux_teknigi_olmaz(self, tmp_path):
        p = yaz(tmp_path, "a.macho", macho64(CPU_ARM64, b"\xc0\x03\x5f\xd6"))
        with mock.patch.dict(sys.modules, {"lief": _lief_sahte("MACHO", ["_ptrace"])}):
            bul = teknikler(AntiDebugDetector(binary_path=p).detect_by_imports())
        assert set(bul) == {"ptrace_pt_deny_attach"}

    def test_macho_sysctl_yalniz_bilgi(self, tmp_path):
        """htop / top gibi süreç listeleyiciler sysctl ithal eder (eski: 0,55 MED)."""
        p = yaz(tmp_path, "top", macho64(CPU_ARM64, b"\xc0\x03\x5f\xd6"))
        with mock.patch.dict(sys.modules, {"lief": _lief_sahte("MACHO", ["_sysctl"])}):
            det = AntiDebugDetector(binary_path=p)
            bul = det.detect()
        f = teknikler(bul)["sysctl_import"]
        assert f.confidence < 0.4
        assert "argumani dogrulanmadi" in f.evidence
        assert det.summary(bul)["anti_debug_score"] < 0.4

    def test_elf_prctl_yalniz_bilgi(self, tmp_path):
        p = yaz(tmp_path, "timeout", elf64(EM_AARCH64, b"\xc0\x03\x5f\xd6"))
        with mock.patch.dict(sys.modules, {"lief": _lief_sahte("ELF", ["prctl"])}):
            f = teknikler(AntiDebugDetector(binary_path=p).detect_by_imports())["prctl_import"]
        assert f.confidence < 0.4
        assert "argumani dogrulanmadi" in f.evidence

    def test_pe_windows_katalogu_korunur(self, tmp_path):
        p = yaz(tmp_path, "a.exe", pe("x86_64", b"\xc3"))
        lief = mock.MagicMock()
        ikili = mock.MagicMock()
        ikili.format = "PE"
        giris = mock.MagicMock()
        giris.name = "CheckRemoteDebuggerPresent"
        kut = mock.MagicMock()
        kut.entries = [giris]
        ikili.imports = [kut]
        ikili.dynamic_symbols = []
        ikili.imported_symbols = []
        ikili.imported_functions = []
        lief.parse.return_value = ikili
        with mock.patch.dict(sys.modules, {"lief": lief}):
            bul = teknikler(AntiDebugDetector(binary_path=p).detect_by_imports())
        assert bul["CheckRemoteDebuggerPresent"].confidence >= 0.6


# ---------------------------------------------------------------------------
# Gerçek ikililer (varsa)
# ---------------------------------------------------------------------------

DEBIAN_PWD = Path.home() / (
    "karadul_olcum/n1_debian13/coreutils/pwd/ws/workspaces/pwd/20261021_103050/raw/pwd")
POZITIF = Path.home() / "karadul_olcum/runs/onarim-2026-11-18/P02/pozitif"


@pytest.mark.skipif(not DEBIAN_PWD.is_file(), reason="Debian coreutils pwd yerelde yok")
def test_gercek_debian_aarch64_pwd_rdtsc_yok():
    """Kulvar IMZA-02 kanıtı: bu ikili eskiden "RDTSC_Timing 0,45 → [MED]" alıyordu."""
    det = AntiDebugDetector(binary_path=DEBIAN_PWD)
    bul = det.detect()
    assert "RDTSC_Timing" not in teknikler(bul)
    assert det.summary(bul)["anti_debug_score"] < 0.4


@pytest.mark.skipif(not (POZITIF / "ad_macos_evrensel").is_file(),
                    reason="P02 pozitif seti üretilmemiş (scripts/measurement/p02_pozitif/uret.sh)")
def test_gercek_pozitif_evrensel_macos():
    """clang ile derlenmiş ptrace + sysctl + rdtsc örneği: x86-64 diliminde 2 rdtsc."""
    det = AntiDebugDetector(binary_path=POZITIF / "ad_macos_evrensel")
    bul = teknikler(det.detect())
    assert bul["RDTSC_Timing"].evidence.startswith("rdtsc x2,")
    assert bul["ptrace_pt_deny_attach"].confidence >= 0.7
    assert "ptrace_traceme" not in bul
