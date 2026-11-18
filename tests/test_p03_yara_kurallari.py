"""P03 / IMZA-05 -- yerlesik YARA kurallarinin hukum kosullari.

Eski kusur: her dizgi ``nocase`` ve her kural ``any of them``; coreutils ``ls``
("compress" icindeki "mpress") MPRESS ile paketli, redis (``tObject``) Delphi,
``tree`` (rastgele ``60 E8 00 00 00 00``) ASPack, her Linux ikilisi
(``clock_gettime``) AntiDebug_Timing, her macOS ikilisi (kod imzasindaki RSA
OID'i) RSA_Public_Key_Constants cikiyordu.

Bu dosya:
- sentetik PE / Mach-O / ELF ile her duzeltilen kuralin dogru pozitifini ve
  eski yanlis pozitifini sinar (eski kodda KIRMIZI, yeni kodda yesil);
- iki arka ucun (yara-python, regex yedegi) ayni hukmu verdigini sinar;
- tarama durumunu (status) sinar;
- gercek ikililer varsa (skipif) masum ikililerde sahte hukum olmadigini
  ve gercek pozitiflerin kaldigini sinar.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from karadul.analyzers.yara_scanner import (
    STATUS_ERROR,
    STATUS_RAN,
    YaraScanner,
    _builtin_rules,
    _rule_to_yara_source,
)

try:  # yara-python varsa iki arka ucu da sinariz
    import yara  # noqa: F401
    HAS_YARA = True
except ImportError:  # pragma: no cover
    HAS_YARA = False


# ---------------------------------------------------------------------------
# Sentetik ikili ureticiler
# ---------------------------------------------------------------------------

def make_pe(sections, ep_section=0, ep_offset=0, machine=0x14C, stub=b""):
    """Asgari PE32: ``sections`` = [(ad, ham_bayt), ...]; giris noktasi
    ``ep_section`` bolumunun ``ep_offset``'inde. ``stub`` DOS kokune yazilir
    (or. Rich basligi)."""
    e_lfanew = 0x80
    dos = bytearray(b"MZ" + b"\x00" * 0x3A + struct.pack("<I", e_lfanew))
    dos[0x40:0x40 + len(stub)] = stub
    dos = bytes(dos[:e_lfanew]).ljust(e_lfanew, b"\x00")
    nsec = len(sections)
    opt_size = 224
    fh = struct.pack("<HHIIIHH", machine, nsec, 0, 0, 0, opt_size, 0x0102)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x10B)
    hdr_end = e_lfanew + 4 + 20 + opt_size + 40 * nsec
    raw_base = (hdr_end + 0x1FF) & ~0x1FF
    sec_hdrs = b""
    bodies = b""
    va = 0x1000
    ep_rva = 0
    for i, (name, raw) in enumerate(sections):
        size = max(0x200, (len(raw) + 0x1FF) & ~0x1FF)
        sec_hdrs += struct.pack(
            "<8sIIIIIIHHI", name.ljust(8, b"\x00")[:8], len(raw) or 0x200, va,
            size, raw_base + len(bodies), 0, 0, 0, 0, 0x60000020)
        if i == ep_section:
            ep_rva = va + ep_offset
        bodies += raw.ljust(size, b"\x00")
        va += 0x1000
    struct.pack_into("<I", opt, 16, ep_rva)
    head = dos + b"PE\x00\x00" + fh + bytes(opt) + sec_hdrs
    return head.ljust(raw_base, b"\x00") + bodies


def make_macho(payload: bytes, cputype=0x0100000C, codesig: bytes = b""):
    """Ince 64-bit Mach-O: tek yuk + istege bagli LC_CODE_SIGNATURE bolgesi."""
    ncmds = 1 if codesig else 0
    sizeofcmds = 16 if codesig else 0
    hdr = struct.pack("<IiiIIIII", 0xFEEDFACF, cputype, 3, 2, ncmds, sizeofcmds, 0, 0)
    body_off = 32 + sizeofcmds
    sig_off = body_off + len(payload)
    lc = struct.pack("<IIII", 0x1D, 16, sig_off, len(codesig)) if codesig else b""
    return hdr + lc + payload + codesig


def make_elf(payload: bytes, machine=183):
    """Asgari ELF64 LE basligi (e_machine: 183 AArch64, 62 x86-64) + yuk."""
    hdr = bytearray(64)
    hdr[0:4] = b"\x7fELF"
    hdr[4] = 2
    hdr[5] = 1
    struct.pack_into("<H", hdr, 0x12, machine)
    return bytes(hdr) + payload


def _scanners():
    out = []
    if HAS_YARA:
        s = YaraScanner()
        s.load_builtin_rules()
        out.append(("yara-python", s))
    fb = YaraScanner()
    fb._yara_available = False
    fb._yara = None
    fb.load_builtin_rules()
    out.append(("regex-fallback", fb))
    return out


SCANNERS = _scanners()


@pytest.fixture(params=[n for n, _ in SCANNERS])
def scanner(request):
    return dict(SCANNERS)[request.param]


def rules_of(scanner, data):
    r = scanner.scan_bytes(data)
    assert r.status == STATUS_RAN
    return set(r.matched_rules)


# ---------------------------------------------------------------------------
# Paketleyiciler: bolum adi + bicim
# ---------------------------------------------------------------------------

class TestPackers:
    def test_mpress_section_in_pe(self, scanner):
        pe = make_pe([(b".MPRESS1", b"\x90" * 32), (b".MPRESS2", b"\xcc" * 32)])
        assert "MPRESS_Packed" in rules_of(scanner, pe)

    def test_mpress_word_in_compress_is_not_mpress(self, scanner):
        # coreutils ls: "compress" icindeki "mpress" (eski nocase eslesmesi)
        data = make_elf(b"\x00--compress-program=PROG\x00uncompress\x00MPRESS\x00", 183)
        assert "MPRESS_Packed" not in rules_of(scanner, data)

    def test_mpress_string_without_section_is_not_mpress(self, scanner):
        pe = make_pe([(b".text", b"\x00.MPRESS1 is a packer\x00")])
        assert "MPRESS_Packed" not in rules_of(scanner, pe)

    def test_aspack_section_and_entry(self, scanner):
        pe = make_pe([(b".text", b"\x00" * 64),
                      (b".aspack", b"\x60\xE8\x03\x00\x00\x00\xE9\xEB"),
                      (b".adata", b"\x00" * 16)], ep_section=1)
        assert "ASPack_Packed" in rules_of(scanner, pe)

    def test_aspack_section_without_entry_pattern(self, scanner):
        pe = make_pe([(b".text", b"\x55\x8B\xEC" + b"\x00" * 32),
                      (b".adata", b"\x60\xE8\x00\x00\x00\x00")], ep_section=0)
        assert "ASPack_Packed" not in rules_of(scanner, pe)

    def test_aspack_bytes_in_elf_are_not_aspack(self, scanner):
        # debian tree: AArch64'te rastgele 60 E8 00 00 00 00
        data = make_elf(b"\x00" * 100 + b"\x60\xE8\x00\x00\x00\x00" + b".adata", 183)
        assert "ASPack_Packed" not in rules_of(scanner, data)

    def test_upx_needs_two_evidences(self, scanner):
        assert "UPX_Packed" not in rules_of(scanner, b"\x00" * 64 + b"UPX!" + b"\x00" * 64)
        assert "UPX_Packed" not in rules_of(scanner, b"\x00uPX9\x00")  # libcrypto nocase
        pe = make_pe([(b"UPX0", b""), (b"UPX1", b"\x00" * 64 + b"UPX!")])
        assert "UPX_Packed" in rules_of(scanner, pe)
        elf = make_elf(b"UPX!\x00$Info: This file is packed with the UPX executable packer")
        assert "UPX_Packed" in rules_of(scanner, elf)

    def test_vmprotect_section(self, scanner):
        assert "VMProtect_Packed" in rules_of(
            scanner, make_pe([(b".text", b""), (b".vmp0", b""), (b".vmp1", b"")]))
        # dyld: "vmProtect" (eski nocase) / bolumsuz dizgi
        assert "VMProtect_Packed" not in rules_of(
            scanner, make_macho(b"\x00vmProtect\x00.vmp0\x00"))

    def test_themida_section(self, scanner):
        assert "Themida_Packed" in rules_of(
            scanner, make_pe([(b".text", b""), (b".themida", b"")]))
        assert "Themida_Packed" not in rules_of(
            scanner, make_pe([(b".text", b"\x00Themida\x00")]))


# ---------------------------------------------------------------------------
# Derleyiciler
# ---------------------------------------------------------------------------

class TestCompilers:
    def test_delphi_tobject_alone_is_not_delphi(self, scanner):
        # redis: createStringObject -> "tObject" (eski nocase), C++ TObject
        data = make_elf(b"\x00createStringObject\x00TObject::Class\x00", 183)
        assert "Delphi_Compiler" not in rules_of(scanner, data)

    def test_delphi_single_evidence_is_not_delphi(self, scanner):
        assert "Delphi_Compiler" not in rules_of(
            scanner, make_pe([(b"CODE", b"\x00System.SysUtils\x00")]))

    def test_case_sensitive_by_default(self, scanner):
        # yardim metnindeki kucuk harfli sozcukler (eski nocase) kanit degil
        data = make_elf(b"\x00run under virtualbox or vmware or qemu\x00", 183)
        assert "AntiVM_Detection" not in rules_of(scanner, data)

    def test_delphi_two_specific_evidences(self, scanner):
        pe = make_pe([(b"CODE", b"\x00\x07TObject\x00System.SysUtils\x00")])
        assert "Delphi_Compiler" in rules_of(scanner, pe)

    def test_msvc_rich_header_only_in_stub(self, scanner):
        assert "MSVC_Compiler" in rules_of(
            scanner, make_pe([(b".text", b"")], stub=b"DanS" + b"\x00" * 12 + b"Rich"))
        # Rich'in dosyanin baska bir yerinde gecmesi (or. "Richard") MSVC degil
        assert "MSVC_Compiler" not in rules_of(
            scanner, make_pe([(b".rdata", b"\x00Richard Stallman\x00MSVCRT.dll\x00")]))


# ---------------------------------------------------------------------------
# Anti-debug: olagan API'ler kanit degil
# ---------------------------------------------------------------------------

class TestAntiDebug:
    def test_clock_gettime_is_not_timing_antidebug(self, scanner):
        data = make_elf(b"\x00clock_gettime\x00rdtsc\x00", 183)
        assert "AntiDebug_Timing" not in rules_of(scanner, data)

    def test_crt_timing_apis_are_not_antidebug(self, scanner):
        pe = make_pe([(b".rdata", b"\x00QueryPerformanceCounter\x00GetTickCount\x00"
                                  b"IsDebuggerPresent\x00OutputDebugStringW\x00"
                                  b"UnhandledExceptionFilter\x00SetUnhandledExceptionFilter\x00")])
        got = rules_of(scanner, pe)
        assert not {"AntiDebug_Timing", "AntiDebug_IsDebuggerPresent",
                    "AntiDebug_ExceptionTricks"} & got

    def test_check_remote_debugger_present(self, scanner):
        pe = make_pe([(b".rdata", b"\x00CheckRemoteDebuggerPresent\x00")])
        assert "AntiDebug_IsDebuggerPresent" in rules_of(scanner, pe)

    def test_sysctl_word_is_not_antidebug(self, scanner):
        # redis: "sysctl vm.overcommit_memory" uyari metni; htop/ps: _sysctl ithali
        assert "AntiDebug_SysctlCheck" not in rules_of(
            scanner, make_elf(b"\x00sysctl vm.overcommit_memory=1\x00", 183))
        assert "AntiDebug_SysctlCheck" not in rules_of(
            scanner, make_macho(b"\x00_sysctl\x00_getpid\x00"))

    def test_sysctl_self_query(self, scanner):
        mib = (b"\xC7\x45\xE0\x01\x00\x00\x00\xC7\x45\xE4\x0E\x00\x00\x00"
               b"\xC7\x45\xE8\x01\x00\x00\x00")
        data = make_macho(b"\x00_sysctl\x00_getpid\x00" + mib, cputype=0x01000007)
        assert "AntiDebug_SysctlCheck" in rules_of(scanner, data)

    def test_sysctl_without_getpid(self, scanner):
        # netstat: _sysctl + {1,14,1} mib dizisi, ama kendi pid'ini sormuyor
        mib = b"\x01\x00\x00\x00\x0E\x00\x00\x00\x01\x00\x00\x00"
        assert "AntiDebug_SysctlCheck" not in rules_of(
            scanner, make_macho(b"\x00_sysctl\x00" + mib, cputype=0x01000007))

    def test_timing_rdtsc_pair_alone_is_not_antidebug(self, scanner):
        # vim/ssh/top: x86 dilimde rdtsc cifti var, anti-debug degil
        data = make_macho(b"\x00\x0F\x31\x48\x89\xC1\x0F\x31\x00", cputype=0x01000007)
        assert "AntiDebug_Timing" not in rules_of(scanner, data)

    def test_timing_with_strong_context(self, scanner):
        mib = (b"\xC7\x45\xE0\x01\x00\x00\x00\xC7\x45\xE4\x0E\x00\x00\x00"
               b"\xC7\x45\xE8\x01\x00\x00\x00")
        data = make_macho(b"\x00_sysctl\x00_getpid\x00" + mib
                          + b"\x00\x0F\x31\x48\x89\xC1\x0F\x31\x00", cputype=0x01000007)
        got = rules_of(scanner, data)
        assert {"AntiDebug_SysctlCheck", "AntiDebug_Timing"} <= got
        # ayni baytlar AArch64 diliminde x86 komutu degildir
        arm = make_macho(b"\x00_sysctl\x00_getpid\x00" + mib
                         + b"\x00\x0F\x31\x48\x89\xC1\x0F\x31\x00", cputype=0x0100000C)
        assert "AntiDebug_Timing" not in rules_of(scanner, arm)

    def test_ptrace_syscall_bytes_need_syscall(self, scanner):
        # bash: tek basina "mov eax, 0x200001A"
        assert "AntiDebug_Ptrace" not in rules_of(
            scanner, make_macho(b"\x00\xB8\x1A\x00\x00\x02\x00", cputype=0x01000007))
        assert "AntiDebug_Ptrace" in rules_of(
            scanner, make_macho(b"\x00\xB8\x1A\x00\x00\x02\x0F\x05", cputype=0x01000007))

    def test_antivm_single_name_is_not_antivm(self, scanner):
        assert "AntiVM_Detection" not in rules_of(scanner, b"\x00VirtualBox\x00")
        assert "AntiVM_Detection" in rules_of(scanner, b"\x00VirtualBox\x00VMware\x00")

    def test_process_enum_without_tool_names(self, scanner):
        pe = make_pe([(b".rdata", b"\x00CreateToolhelp32Snapshot\x00Process32FirstW\x00"
                                  b"Process32NextW\x00")])
        assert "AntiDebug_ProcessEnum" not in rules_of(scanner, pe)
        pe2 = make_pe([(b".rdata", b"\x00CreateToolhelp32Snapshot\x00Process32FirstW\x00"
                                   b"Process32NextW\x00x64dbg.exe\x00")])
        assert "AntiDebug_ProcessEnum" in rules_of(scanner, pe2)


# ---------------------------------------------------------------------------
# Iki baytlik / bolgeden bagimsiz desenler
# ---------------------------------------------------------------------------

class TestShortPatterns:
    def test_c6_45_alone_is_not_stack_string(self, scanner):
        assert "Stack_String_Construction" not in rules_of(
            scanner, make_elf(b"\x00\xC6\x45\x00" * 4, 62))

    def test_stack_string_x86_only(self, scanner):
        seq = b"".join(b"\xC6\x45" + bytes([0xE0 + i]) + c for i, c in
                       enumerate([b"c", b"m", b"d", b".", b"e", b"x"]))
        assert "Stack_String_Construction" in rules_of(scanner, make_elf(seq, 62))
        assert "Stack_String_Construction" not in rules_of(scanner, make_elf(seq, 183))

    def test_zlib_magic_alone_is_not_zlib(self, scanner):
        assert "Zlib_Library" not in rules_of(scanner, make_elf(b"\x00\x78\x9C\x00", 183))
        assert "Zlib_Library" in rules_of(scanner, make_elf(b"\x00libz.so.1\x00", 183))

    def test_frame_magic_alone_is_not_library(self, scanner):
        data = make_macho(b"\x00\x04\x22\x4D\x18\x00\x28\xB5\x2F\xFD\x00")  # `file` magic tablosu
        got = rules_of(scanner, data)
        assert "LZ4_Library" not in got and "Zstd_Library" not in got

    def test_rsa_oid_in_code_signature_is_excluded(self, scanner):
        oid = bytes.fromhex("06092A864886F70D010101")
        assert "RSA_Public_Key_Constants" not in rules_of(
            scanner, make_macho(b"\x00" * 64, codesig=b"\x00" * 16 + oid + b"\x00" * 16))
        assert "RSA_Public_Key_Constants" in rules_of(
            scanner, make_macho(b"\x00" * 16 + oid + b"\x00" * 16,
                                codesig=b"\x00" * 16 + oid))


# ---------------------------------------------------------------------------
# Uretec: nocase yalniz isteyende, kosul N of them
# ---------------------------------------------------------------------------

class TestGenerator:
    def test_nocase_only_where_requested(self):
        for rule in _builtin_rules():
            src = _rule_to_yara_source(rule)
            want = sum(1 for p in rule.string_patterns if p.startswith("(?i") or p.startswith("(?si"))
            assert src.count(" nocase") == want, rule.name

    def test_condition_threshold_emitted(self):
        rule = next(r for r in _builtin_rules() if r.name == "Go_Compiler")
        assert "2 of them" in _rule_to_yara_source(rule)

    @pytest.mark.skipif(not HAS_YARA, reason="yara-python yok")
    def test_builtin_rules_compile(self):
        import yara
        src = "\n\n".join(_rule_to_yara_source(r) for r in _builtin_rules())
        yara.compile(source=src)


# ---------------------------------------------------------------------------
# Iki arka uc ayni hukmu verir
# ---------------------------------------------------------------------------

_CORPUS = [
    make_pe([(b".MPRESS1", b""), (b".MPRESS2", b"")]),
    make_pe([(b".aspack", b"\x60\xE8\x03\x00\x00\x00"), (b".adata", b"")]),
    make_pe([(b".rdata", b"\x00CheckRemoteDebuggerPresent\x00\x0F\x31\x90\x0F\x31\x00")],
            stub=b"Rich", machine=0x8664),
    make_macho(b"\x00_sysctl\x00_getpid\x00\x01\x00\x00\x00\x0E\x00\x00\x00\x01\x00\x00\x00",
               cputype=0x01000007),
    make_elf(b"\x00compress\x00tObject\x00clock_gettime\x00\x78\x9C\xC6\x45", 183),
    b"UPX!\x00UPX0\x00UPX1\x00OpenSSL 3.0.13\x00VirtualBox\x00QEMU\x00",
]


@pytest.mark.skipif(not HAS_YARA, reason="yara-python yok")
@pytest.mark.parametrize("data", _CORPUS)
def test_backends_agree_on_synthetic(data):
    (_, native), (_, fallback) = SCANNERS
    a = native.scan_bytes(data)
    b = fallback.scan_bytes(data)
    assert a.backend == "yara-python" and b.backend == "regex-fallback"
    sig = lambda r: {m.rule: sorted({i for _, i, _ in m.strings}) for m in r.matches}  # noqa: E731
    assert sig(a) == sig(b)


# ---------------------------------------------------------------------------
# Durum
# ---------------------------------------------------------------------------

class TestStatus:
    def test_clean_scan_is_ran(self, scanner):
        r = scanner.scan_bytes(b"\x00" * 128)
        assert r.status == STATUS_RAN and r.matches == [] and r.status_reason == ""
        assert r.to_dict()["status"] == STATUS_RAN

    def test_missing_file_is_error(self, scanner, tmp_path):
        r = scanner.scan_file(tmp_path / "yok.bin")
        assert r.status == STATUS_ERROR and "bulunamadi" in r.status_reason

    def test_no_rules_is_error(self):
        r = YaraScanner().scan_bytes(b"abc")
        assert r.status == STATUS_ERROR and r.status_reason

    @pytest.mark.skipif(not HAS_YARA, reason="yara-python yok")
    def test_compile_failure_falls_back_and_says_so(self):
        s = YaraScanner()
        s.load_builtin_rules()

        class _Broken:
            @staticmethod
            def compile(**_kw):
                raise RuntimeError("bozuk kural")

        s._yara = _Broken()
        r = s.scan_bytes(make_pe([(b".MPRESS1", b"")]))
        assert r.status == STATUS_RAN
        assert r.backend == "regex-fallback"
        assert "bozuk kural" in r.fallback_reason
        assert "MPRESS_Packed" in r.matched_rules


# ---------------------------------------------------------------------------
# Gercek ikililer (varsa)
# ---------------------------------------------------------------------------

_OLCUM = Path.home() / "karadul_olcum"
_DEB = _OLCUM / "n1_debian13"
_POZ = _OLCUM / "masum_kapi" / "pozitif"
_FALSE_FAMILIES = ("MPRESS_Packed", "ASPack_Packed", "Delphi_Compiler", "AntiDebug_",
                   "Stack_String_Construction", "RSA_Public_Key_Constants", "UPX_Packed",
                   "VMProtect_Packed", "AntiVM_Detection", "LZ4_Library")


def _deb(prog: str, binary: str) -> Path | None:
    hits = sorted((_DEB / prog / binary).glob("ws/workspaces/*/*/raw/" + binary))
    return hits[0] if hits else None


_INNOCENT = [p for p in [
    _deb("coreutils", "ls"), _deb("coreutils", "sort"), _deb("redis-tools", "redis-check-rdb"),
    _deb("tree", "tree"), Path("/bin/ls"), Path("/usr/bin/true"), Path("/usr/lib/dyld"),
] if p is not None and p.is_file()]


@pytest.mark.parametrize("path", _INNOCENT, ids=lambda p: str(p))
def test_innocent_binaries_have_no_false_family(scanner, path):
    got = scanner.scan_file(path).matched_rules
    bad = [r for r in got if any(r.startswith(f) for f in _FALSE_FAMILIES)]
    assert bad == [], f"{path}: {bad}"


@pytest.mark.skipif(not (_POZ / "upx_t32.exe").is_file(), reason="pozitif ornek yok")
def test_real_positives_kept(scanner):
    assert "UPX_Packed" in scanner.scan_file(_POZ / "upx_t32.exe").matched_rules
    assert "UPX_Packed" in scanner.scan_file(_POZ / "upx_t64.exe").matched_rules
    assert "UPX_Packed" in scanner.scan_file(_POZ / "upx_debian_true").matched_rules
    assert "AntiDebug_SysctlCheck" in scanner.scan_file(_POZ / "antidebug_x86_64").matched_rules
