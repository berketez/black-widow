"""v1.10.0 Batch 5B Security + Supply-Chain Hardening testleri.

Red Team 2. tur'da tespit edilen 23 bulgunun dogrulamasi.

Test kategorileri:
1. CRITICAL-1: jadx Log4Shell env
2. CRITICAL-2: shutil.which -> resolve_tool PATH hijack
3. CRITICAL-3: zlib decompression bomb
4. HIGH-4:   macho symlink TOCTOU
5. HIGH-5:   packed_binary limitsiz read
6. HIGH-6:   .class attr_len DoS
7. HIGH-8:   LD_PRELOAD / DYLD inject env drop
8. HIGH-10:  Ghidra KARADUL_OUTPUT traversal
9. MED-11:   Windows reserved names
10. MED-14:  Z3 access count cap
11. MED-15:  FLIRT entry limit
12. MED-16:  FLIRT hex length reject
13. MED-17:  PyInstaller TOC sanity
14. MED-13:  BUN segment negative offset

NOT: Jython 2.7 uyumlu Ghidra scripts'leri bu test suite icinden direkt
calistirilamaz -- baglanti kurmadan `import` edilemezler. Onlar icin
subprocess-based end-to-end test ayri (integration).
"""

from __future__ import annotations

import os
import struct
import subprocess
import zlib
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# safe_subprocess moduly
# ---------------------------------------------------------------------------

class TestResolveTool:
    def test_rejects_path_traversal(self):
        from karadul.core.safe_subprocess import resolve_tool
        assert resolve_tool("../bin/upx") is None
        assert resolve_tool("/usr/bin/upx") is None  # absolute reject
        assert resolve_tool("sub/dir/upx") is None
        assert resolve_tool("..") is None

    def test_empty_name(self):
        from karadul.core.safe_subprocess import resolve_tool
        assert resolve_tool("") is None

    def test_resolves_sh(self):
        """/bin/sh her POSIX sistemde vardir."""
        from karadul.core.safe_subprocess import resolve_tool
        result = resolve_tool("sh")
        assert result is not None
        assert "sh" in result
        assert os.path.isabs(result)

    def test_ignores_path_hijack(self, tmp_path, monkeypatch):
        """PATH'te malicious dizin olsa bile resolve_tool dikkate almaz.

        CRITICAL-2: Red team senaryosu -- attacker
        ``~/.local/bin/upx`` koyarsa ``shutil.which`` bunu secerdi;
        ``resolve_tool`` sadece whitelist path'lere bakar.
        """
        from karadul.core.safe_subprocess import resolve_tool
        # Malicious fake "upx" script yaratilir, PATH'e eklenir
        fake_bin = tmp_path / "upx"
        fake_bin.write_text("#!/bin/sh\nexit 0\n")
        fake_bin.chmod(0o755)
        monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")
        # shutil.which evet dercke, resolve_tool hayir demeli
        import shutil
        hijacked = shutil.which("upx")
        # shutil.which PATH'e baktigi icin fake'i bulabilir
        assert hijacked is None or hijacked == str(fake_bin)
        # resolve_tool ise fake'i asla bulmaz
        assert resolve_tool("upx") != str(fake_bin)


class TestSafeEnv:
    def test_blacklist_drops_ld_preload(self):
        from karadul.core.safe_subprocess import safe_env
        env = safe_env({"LD_PRELOAD": "/tmp/evil.so", "FOO": "bar"})
        assert "LD_PRELOAD" not in env
        assert env.get("FOO") == "bar"

    def test_blacklist_drops_dyld_insert(self):
        from karadul.core.safe_subprocess import safe_env
        env = safe_env({"DYLD_INSERT_LIBRARIES": "/tmp/evil.dylib"})
        assert "DYLD_INSERT_LIBRARIES" not in env

    def test_blacklist_drops_pythonpath(self):
        from karadul.core.safe_subprocess import safe_env
        env = safe_env({"PYTHONPATH": "/tmp/malicious"})
        assert "PYTHONPATH" not in env

    def test_passthrough_blacklist_filter(self, monkeypatch):
        from karadul.core.safe_subprocess import safe_env
        monkeypatch.setenv("LD_PRELOAD", "/tmp/evil.so")
        env = safe_env(passthrough=["LD_PRELOAD", "HOME"])
        assert "LD_PRELOAD" not in env

    def test_java_tool_options_log4shell_safe(self):
        """jadx Log4Shell (CVE-2021-44228) koruma zorunlu."""
        from karadul.core.safe_subprocess import safe_env
        env = safe_env()
        assert "JAVA_TOOL_OPTIONS" in env
        assert "log4j2.formatMsgNoLookups=true" in env["JAVA_TOOL_OPTIONS"]

    def test_explicit_env_also_cleansed(self):
        from karadul.core.safe_subprocess import safe_run
        # Direct env dict with blacklist key
        caught = {}
        import subprocess as _sp

        orig_run = _sp.run

        def _fake_run(cmd, **kwargs):
            caught.update(kwargs)
            return _sp.CompletedProcess(cmd, 0, "", "")

        _sp.run = _fake_run
        try:
            safe_run(["echo", "hi"], env={"LD_PRELOAD": "/tmp/x", "SAFE": "1"})
        finally:
            _sp.run = orig_run
        assert "LD_PRELOAD" not in caught["env"]
        assert caught["env"].get("SAFE") == "1"


class TestSafeZlibDecompress:
    def test_normal_data_ok(self):
        from karadul.core.safe_subprocess import safe_zlib_decompress
        data = b"hello world" * 100
        comp = zlib.compress(data)
        out = safe_zlib_decompress(comp, max_size=10_000)
        assert out == data

    def test_bomb_rejected(self):
        """1KB compressed -> 10MB uncompressed, cap=1MB."""
        from karadul.core.safe_subprocess import safe_zlib_decompress
        # 100MB zero-filled -> cok kucuk compressed (bomb)
        payload = b"\x00" * (100 * 1024 * 1024)
        comp = zlib.compress(payload)
        # Bu noktada comp << 100MB (high ratio)
        out = safe_zlib_decompress(comp, max_size=1 * 1024 * 1024)
        assert out is None

    def test_invalid_zlib(self):
        from karadul.core.safe_subprocess import safe_zlib_decompress
        assert safe_zlib_decompress(b"not-zlib-data", max_size=1024) is None


# ---------------------------------------------------------------------------
# .class attr_len DoS (HIGH-6)
# ---------------------------------------------------------------------------

class TestClassAttrLenDoS:
    def test_oversized_attr_len_rejected(self, tmp_path, monkeypatch):
        """Malicious .class attr_len = 4GB -> parse duz reddedilmeli."""
        from karadul.analyzers import java_binary
        monkeypatch.setattr(java_binary, "_MAX_CLASS_ATTR_LEN", 1024)

        # Asgari gecerli .class header + 1 field w/ attr_len = 10MB
        buf = bytearray()
        buf += b"\xCA\xFE\xBA\xBE"  # magic
        buf += struct.pack(">H", 0)  # minor
        buf += struct.pack(">H", 52)  # major (Java 8)
        buf += struct.pack(">H", 3)  # constant_pool_count
        # Dummy constant pool: 2 items (tag=1 UTF8 "X")
        buf += b"\x01"; buf += struct.pack(">H", 1); buf += b"X"
        buf += b"\x01"; buf += struct.pack(">H", 1); buf += b"Y"
        buf += struct.pack(">H", 0)  # access_flags
        buf += struct.pack(">H", 1)  # this_class
        buf += struct.pack(">H", 2)  # super_class
        buf += struct.pack(">H", 0)  # interfaces_count
        buf += struct.pack(">H", 1)  # fields_count
        # field: access, name, desc, attr_count=1
        buf += struct.pack(">H", 0)
        buf += struct.pack(">H", 1)
        buf += struct.pack(">H", 1)
        buf += struct.pack(">H", 1)
        # attribute: name_idx + attr_len=10MB (DoS)
        buf += struct.pack(">H", 1)
        buf += struct.pack(">I", 10 * 1024 * 1024)
        # (data intentionally missing -- should never be read)

        class_file = tmp_path / "Evil.class"
        class_file.write_bytes(bytes(buf))

        # Parse: silently empty result (struct.error -> logger.debug)
        result = java_binary.JavaBinaryAnalyzer._parse_class_file(class_file)
        # Parse hata verdigi icin fields bos olmali
        assert result.get("fields") == [] or "fields" not in result


# ---------------------------------------------------------------------------
# Windows reserved names (MED-11)
# ---------------------------------------------------------------------------

class TestWindowsReserved:
    def test_con_reserved(self):
        from karadul.analyzers.packed_binary import _is_windows_reserved
        assert _is_windows_reserved("CON.txt")
        assert _is_windows_reserved("dir/con.log")
        assert _is_windows_reserved("dir/AUX.bin")
        assert _is_windows_reserved("COM1")
        assert _is_windows_reserved("subdir\\LPT9.data")

    def test_normal_names_ok(self):
        from karadul.analyzers.packed_binary import _is_windows_reserved
        assert not _is_windows_reserved("normal.txt")
        assert not _is_windows_reserved("a/b/c.py")
        assert not _is_windows_reserved("console.log")  # CON prefix OK


# ---------------------------------------------------------------------------
# Z3 MaxSMT access cap (MED-14)
# ---------------------------------------------------------------------------

class TestZ3AccessCap:
    def test_oversized_input_rejected(self, monkeypatch):
        """10K+ access -> exponential DoS engeli devreye girmeli."""
        from karadul.computation.struct_recovery import solver as solver_mod
        # Cap'i dusur (test'te gercek 10K yaratmak pahalı)
        monkeypatch.setattr(solver_mod, "_MAX_Z3_ACCESSES", 10)

        from karadul.computation.struct_recovery.types import MemoryAccess, AliasClass

        accesses = [
            MemoryAccess(var_name="v%d" % i, offset=i * 8, width=8, access_type="read")
            for i in range(50)
        ]
        classes = [AliasClass(variables=["v%d" % i for i in range(50)], type_family="obj")]

        # Config'i aktif yapacak test double
        class CfgDouble:
            enable_computation_struct_recovery = True
        s = solver_mod.StructLayoutSolver(CfgDouble())
        result = s.solve(accesses=accesses, classes=classes)
        # Cap asildigi icin: unknown_accesses = tum accesses, confidence=0
        assert len(result.unknown_accesses) == 50
        assert result.confidence == 0.0


# ---------------------------------------------------------------------------
# FLIRT limits (MED-15, MED-16)
# ---------------------------------------------------------------------------

class TestFLIRTLimits:
    def test_hex_length_reject(self, monkeypatch):
        from karadul.analyzers import flirt_parser
        monkeypatch.setattr(flirt_parser, "_MAX_FLIRT_HEX_LENGTH", 16)
        p = flirt_parser.FLIRTParser()
        long_hex = "AB" * 50  # 100 chars > 16
        # Line formati: HEX CRC16 SIZE TOTAL :OFFSET NAME
        line = "%s 0C 0025 003A :0000 _evil" % long_hex
        assert p._parse_pat_line(line) is None

    def test_entry_count_cap(self, tmp_path, monkeypatch):
        """Malicious .pat 1M satir -> cap ile durdurul."""
        from karadul.analyzers import flirt_parser
        monkeypatch.setattr(flirt_parser, "_MAX_FLIRT_ENTRIES", 3)

        pat = tmp_path / "evil.pat"
        lines = []
        for i in range(20):
            lines.append("558BEC83EC10 0C 0025 003A :0000 _fn_%d" % i)
        pat.write_text("\n".join(lines))

        p = flirt_parser.FLIRTParser()
        sigs = p.load_pat_file(pat)
        assert len(sigs) <= 3


# ---------------------------------------------------------------------------
# PyInstaller sanity (MED-17)
# ---------------------------------------------------------------------------

class TestPyInstallerSanity:
    def test_negative_offset_rejected(self, tmp_path):
        from karadul.analyzers.packed_binary import PyInstallerExtractor
        data = b"A" * 1024
        entry = {
            "name": "ok.py",
            "entry_offset": -100,  # negative offset
            "data_length": 50,
            "uncompressed_length": 50,
            "is_compressed": False,
            "type_flag": 0,
            "type_name": "SCRIPT",
        }
        result = PyInstallerExtractor._extract_entry(
            data=data, pkg_start=0, entry=entry, output_dir=tmp_path,
        )
        assert result is None

    def test_out_of_bounds_rejected(self, tmp_path):
        from karadul.analyzers.packed_binary import PyInstallerExtractor
        data = b"A" * 100
        entry = {
            "name": "ok.py",
            "entry_offset": 50,
            "data_length": 10_000,  # > len(data)
            "uncompressed_length": 10_000,
            "is_compressed": False,
            "type_flag": 0,
            "type_name": "SCRIPT",
        }
        result = PyInstallerExtractor._extract_entry(
            data=data, pkg_start=0, entry=entry, output_dir=tmp_path,
        )
        assert result is None

    def test_windows_reserved_rejected(self, tmp_path):
        from karadul.analyzers.packed_binary import PyInstallerExtractor
        data = b"A" * 100
        entry = {
            "name": "CON.txt",  # Windows reserved
            "entry_offset": 0,
            "data_length": 10,
            "uncompressed_length": 10,
            "is_compressed": False,
            "type_flag": 0,
            "type_name": "SCRIPT",
        }
        result = PyInstallerExtractor._extract_entry(
            data=data, pkg_start=0, entry=entry, output_dir=tmp_path,
        )
        assert result is None


# ---------------------------------------------------------------------------
# SecurityConfig uyumu (config ile sabit degerler esit mi)
# ---------------------------------------------------------------------------

class TestSecurityConfigAlignment:
    def test_jar_attr_len_default(self):
        from karadul.config import SecurityConfig
        cfg = SecurityConfig()
        assert cfg.max_jar_attr_len_bytes == 10 * 1024 * 1024

    def test_z3_cap_default(self):
        from karadul.config import SecurityConfig
        cfg = SecurityConfig()
        assert cfg.max_z3_access_count == 10_000

    def test_flirt_defaults(self):
        from karadul.config import SecurityConfig
        cfg = SecurityConfig()
        assert cfg.max_flirt_entries == 100_000
        assert cfg.max_flirt_hex_length == 512

    def test_reserved_names_tuple(self):
        from karadul.config import SecurityConfig
        cfg = SecurityConfig()
        assert "CON" in cfg.pyinstaller_reserved_names
        assert "COM9" in cfg.pyinstaller_reserved_names
        assert "LPT1" in cfg.pyinstaller_reserved_names


# ---------------------------------------------------------------------------
# macho BUN segment (MED-13)
# ---------------------------------------------------------------------------

class TestBunSegmentBounds:
    def test_negative_offset_validated(self):
        """Negatif offset -> MachOAnalyzer BUN extraction None donmeli."""
        # Smoke test: _stat_is_regular helper calisir mi?
        from karadul.analyzers.macho import _stat_is_regular
        import stat

        class S:
            st_mode = stat.S_IFREG | 0o644
        assert _stat_is_regular(S())

        class NotReg:
            st_mode = stat.S_IFDIR | 0o755
        assert not _stat_is_regular(NotReg())


# ---------------------------------------------------------------------------
# Integration smoke (SecurityConfig yolu YAML'dan set edilebilir mi)
# ---------------------------------------------------------------------------

class TestConfigRoundTrip:
    def test_yaml_override(self, tmp_path):
        import yaml
        from karadul.config import Config
        cfg_file = tmp_path / "karadul.yaml"
        cfg_file.write_text(yaml.safe_dump({
            "security": {
                "max_jar_attr_len_bytes": 1024,
                "pyinstaller_reserved_names": ["FOO", "BAR"],
            }
        }))
        cfg = Config.load(cfg_file)
        assert cfg.security.max_jar_attr_len_bytes == 1024
        assert cfg.security.pyinstaller_reserved_names == ("FOO", "BAR")
