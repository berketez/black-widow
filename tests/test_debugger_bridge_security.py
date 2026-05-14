"""Debugger Bridge guvenlik testleri (CWE-94 Python kod enjeksiyonu).

`debugger_bridge.py` LLDB/GDB icin Python script uretiyor.
Bu script'lere kullanici-kontrollu register/fonksiyon isimleri gomuluyor.
Kotu niyetli bir saldirgan, kacis karakterleri (', ", \\n, ;, #) iceren
isimlerle Python kod enjeksiyonu denemesi yapabilir.

Bu test dosyasi su savunma katmanlarini dogrular:

1. Whitelist katmani:
   `_is_safe_identifier` ve `_is_safe_address` ile gecersiz isimlerin
   uretim asamasinda reddedilmesi.

2. Veri-kod ayrimi katmani:
   Tum dinamik veri JSON string olarak gomulur, runtime'da `json.loads`
   ile parse edilir. Boylece veri asla Python kodu olarak yorumlanmaz.

3. Python string literal escape katmani:
   `repr()` JSON string'i bile bir Python string literal'i icinde
   guvenli sekilde gomer (defense-in-depth).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from karadul.config import Config
from karadul.ghidra.debugger_bridge import (
    BreakpointSpec,
    CaptureSpec,
    DebuggerBridge,
    _GDB_SCRIPT_TEMPLATE,
    _LLDB_SCRIPT_TEMPLATE,
    _is_safe_address,
    _is_safe_identifier,
)


# ---------------------------------------------------------------------------
# Whitelist fonksiyon testleri
# ---------------------------------------------------------------------------


class TestIsSafeIdentifier:
    """`_is_safe_identifier` katı whitelist davranisi."""

    @pytest.mark.parametrize(
        "name",
        [
            "rax", "rdi", "rsi", "rsp", "rbp", "r8", "r9",
            "x0", "x29", "sp", "pc",          # ARM64
            "eax", "ebx", "ecx",              # x86 32-bit
            "main", "myFunc", "_start",
            "process_data", "__libc_start_main",
            "f", "F", "_", "a_b_c_123",
            "A1B2C3", "snake_case_name",
        ],
    )
    def test_valid_identifiers_accepted(self, name: str) -> None:
        """Gecerli register/fonksiyon isimleri kabul edilmeli."""
        assert _is_safe_identifier(name), f"reddedildi: {name!r}"

    @pytest.mark.parametrize(
        "payload",
        [
            # Python kod enjeksiyonu denemeleri
            "foo')\nimport os;os.system('curl evil')\n#",
            "rax'); __import__('os').system('id'); ('",
            "foo\nimport os",
            "main';os.system('rm -rf /');#",
            'name"; eval("evil")',
            # Tek karakterli kacis denemeleri
            "foo'", 'foo"', "foo\n", "foo\r", "foo\t",
            "foo;", "foo#", "foo)", "foo(", "foo{", "foo}",
            "foo[", "foo]", "foo\\", "foo`", "foo$",
            # Bos / None / sayisal baslangic
            "", " ", "123abc", "0rax", "-rax", "+main",
            # Whitespace
            "foo bar", " foo", "foo ", "\tfoo",
            # Unicode kacis
            "rax'", "rax\x27",
            # Tehlikeli karakterler
            "rax.evil", "rax::evil", "rax-evil", "rax/evil",
            "rax*evil", "rax&evil", "rax|evil",
            # Cok uzun (DoS koruma)
            "a" * 256,
            "a" * 1000,
        ],
    )
    def test_malicious_payloads_rejected(self, payload: str) -> None:
        """Enjeksiyon denemeleri ve kacis karakterleri reddedilmeli."""
        assert not _is_safe_identifier(payload), (
            f"GUVENLIK KAYDI: payload kabul edildi: {payload!r}"
        )

    def test_non_string_rejected(self) -> None:
        """str olmayan girdiler reddedilmeli."""
        assert not _is_safe_identifier(None)  # type: ignore[arg-type]
        assert not _is_safe_identifier(123)  # type: ignore[arg-type]
        assert not _is_safe_identifier(["rax"])  # type: ignore[arg-type]
        assert not _is_safe_identifier(b"rax")  # type: ignore[arg-type]


class TestIsSafeAddress:
    """`_is_safe_address` hex veya identifier whitelist'i."""

    @pytest.mark.parametrize(
        "addr",
        [
            "0x100003f00", "0xdeadbeef", "0x0", "0xFFFFFFFF",
            "main", "process_data", "_start",
            "std::vector::push_back",   # C++ namespace
            "module.func",              # mangled
        ],
    )
    def test_valid_addresses_accepted(self, addr: str) -> None:
        assert _is_safe_address(addr), f"reddedildi: {addr!r}"

    @pytest.mark.parametrize(
        "payload",
        [
            # Inject denemeleri
            "0x100')\nimport os;",
            "main'; os.system('id'); #",
            "0xdeadbeef;evil",
            "main\nimport sys",
            # Bos / boslukli
            "", " ", "0x", "0xZZZ",
            "main bar",
            # Cok uzun
            "0x" + "f" * 300,
        ],
    )
    def test_malicious_addresses_rejected(self, payload: str) -> None:
        assert not _is_safe_address(payload), (
            f"GUVENLIK KAYDI: address kabul edildi: {payload!r}"
        )


# ---------------------------------------------------------------------------
# Script uretim katmanı testleri (uca-uca)
# ---------------------------------------------------------------------------


@pytest.fixture
def bridge(tmp_path: Path) -> DebuggerBridge:
    """Debugger aktif, mock'lanmamis DebuggerBridge."""
    cfg = Config()
    cfg.debugger.enabled = True
    return DebuggerBridge(cfg)


class TestScriptGenerationRejectsInjection:
    """`_generate_*_script` enjeksiyon denemelerini reddeder."""

    def test_lldb_rejects_evil_function_name(
        self, bridge: DebuggerBridge, tmp_path: Path,
    ) -> None:
        """Kotu fonksiyon adi ile script uretimi `ValueError` firlatmalı."""
        evil = "foo')\nimport os;os.system('curl evil')\n#"
        bps = [
            BreakpointSpec(
                address="0x100",
                function_name=evil,
                capture=CaptureSpec(registers=["rax"]),
            ),
        ]
        with pytest.raises(ValueError, match="fonksiyon adi"):
            bridge._generate_lldb_script(
                bps, Path("/bin/ls"), tmp_path / "out.json",
            )

    def test_gdb_rejects_evil_function_name(
        self, bridge: DebuggerBridge, tmp_path: Path,
    ) -> None:
        """GDB script icin de ayni guvenlik kontrolu."""
        evil = "foo')\nimport os;os.system('curl evil')\n#"
        bps = [
            BreakpointSpec(
                address="0x100",
                function_name=evil,
                capture=CaptureSpec(registers=["rax"]),
            ),
        ]
        with pytest.raises(ValueError, match="fonksiyon adi"):
            bridge._generate_gdb_script(
                bps, Path("/bin/ls"), tmp_path / "out.json",
            )

    def test_lldb_rejects_evil_register(
        self, bridge: DebuggerBridge, tmp_path: Path,
    ) -> None:
        """Kotu register adi reddedilmeli."""
        bps = [
            BreakpointSpec(
                address="0x100",
                function_name="main",
                capture=CaptureSpec(
                    registers=["rax", "foo');import os;os.system('id');#"],
                ),
            ),
        ]
        with pytest.raises(ValueError, match="register adi"):
            bridge._generate_lldb_script(
                bps, Path("/bin/ls"), tmp_path / "out.json",
            )

    def test_gdb_rejects_evil_register(
        self, bridge: DebuggerBridge, tmp_path: Path,
    ) -> None:
        bps = [
            BreakpointSpec(
                address="0x100",
                function_name="main",
                capture=CaptureSpec(registers=["rax\nevil"]),
            ),
        ]
        with pytest.raises(ValueError, match="register adi"):
            bridge._generate_gdb_script(
                bps, Path("/bin/ls"), tmp_path / "out.json",
            )

    def test_lldb_rejects_evil_address(
        self, bridge: DebuggerBridge, tmp_path: Path,
    ) -> None:
        bps = [
            BreakpointSpec(
                address="0x100')\nimport os;",
                function_name="main",
                capture=CaptureSpec(registers=["rax"]),
            ),
        ]
        with pytest.raises(ValueError, match="breakpoint adresi"):
            bridge._generate_lldb_script(
                bps, Path("/bin/ls"), tmp_path / "out.json",
            )

    @pytest.mark.parametrize(
        "escape_char",
        ["\n", "\r", "'", '"', ";", "#", "\\", "\t", "\0"],
    )
    def test_lldb_rejects_all_escape_chars_in_registers(
        self,
        bridge: DebuggerBridge,
        tmp_path: Path,
        escape_char: str,
    ) -> None:
        """Tum kacis karakterleri register adlarinda reddedilmeli."""
        bps = [
            BreakpointSpec(
                address="0x100",
                function_name="main",
                capture=CaptureSpec(registers=[f"rax{escape_char}evil"]),
            ),
        ]
        with pytest.raises(ValueError, match="register adi"):
            bridge._generate_lldb_script(
                bps, Path("/bin/ls"), tmp_path / "out.json",
            )

    @pytest.mark.parametrize(
        "escape_char",
        ["\n", "\r", "'", '"', ";", "#", "\\"],
    )
    def test_lldb_rejects_all_escape_chars_in_function_name(
        self,
        bridge: DebuggerBridge,
        tmp_path: Path,
        escape_char: str,
    ) -> None:
        bps = [
            BreakpointSpec(
                address="0x100",
                function_name=f"foo{escape_char}bar",
                capture=CaptureSpec(registers=["rax"]),
            ),
        ]
        with pytest.raises(ValueError, match="fonksiyon adi"):
            bridge._generate_lldb_script(
                bps, Path("/bin/ls"), tmp_path / "out.json",
            )


class TestScriptGenerationAcceptsValid:
    """Gecerli girdilerle script uretimi calismali ve gecerli Python uretmeli."""

    def test_lldb_accepts_valid_input_and_compiles(
        self, bridge: DebuggerBridge, tmp_path: Path,
    ) -> None:
        """Gecerli girdi -> derlenebilir Python script."""
        bps = [
            BreakpointSpec(
                address="0x100003f00",
                function_name="main",
                capture=CaptureSpec(registers=["rax", "rdi", "rsi"]),
            ),
            BreakpointSpec(
                address="process_data",
                function_name="process_data",
                capture=CaptureSpec(
                    registers=["rdi", "_secret"],
                    stack_depth=3,
                ),
            ),
        ]
        out = tmp_path / "out.json"
        script_path = bridge._generate_lldb_script(bps, Path("/bin/ls"), out)
        assert script_path.exists()
        src = script_path.read_text(encoding="utf-8")
        # Python olarak derlenebilmeli
        compile(src, str(script_path), "exec")
        # JSON config gomulmus olmali
        assert "_CONFIG_JSON =" in src
        assert "json.loads" in src
        script_path.unlink()

    def test_gdb_accepts_valid_input_and_compiles(
        self, bridge: DebuggerBridge, tmp_path: Path,
    ) -> None:
        bps = [
            BreakpointSpec(
                address="0xdeadbeef",
                function_name="myFunc",
                capture=CaptureSpec(registers=["rax"]),
            ),
        ]
        out = tmp_path / "out.json"
        script_path = bridge._generate_gdb_script(bps, Path("/bin/ls"), out)
        assert script_path.exists()
        src = script_path.read_text(encoding="utf-8")
        compile(src, str(script_path), "exec")
        assert "_CONFIG_JSON =" in src
        assert "json.loads" in src
        script_path.unlink()

    def test_lldb_no_function_name_accepted(
        self, bridge: DebuggerBridge, tmp_path: Path,
    ) -> None:
        """Bos/None function_name kabul edilmeli."""
        bps = [
            BreakpointSpec(
                address="0x100",
                function_name=None,
                capture=CaptureSpec(registers=["rax"]),
            ),
            BreakpointSpec(
                address="0x200",
                function_name="",
                capture=CaptureSpec(registers=["rax"]),
            ),
        ]
        out = tmp_path / "out.json"
        script_path = bridge._generate_lldb_script(bps, Path("/bin/ls"), out)
        compile(script_path.read_text(encoding="utf-8"), "x", "exec")
        script_path.unlink()


# ---------------------------------------------------------------------------
# Template-seviye contained-payload testleri (defense-in-depth dogrulamasi)
# ---------------------------------------------------------------------------


class TestPayloadContainedAsData:
    """Whitelist atlatildigini varsay: payload yine de Python kodu olmamali.

    `_generate_*_script` whitelist'i tetiklediginden bu testler template'i
    elle besler. Amac, ikinci savunma katmaninin (JSON + repr) dogru
    calistigini kanitlamak.
    """

    def test_lldb_template_contains_payload_as_string_literal(self) -> None:
        """Payload Python kod olarak DEGIL, JSON string literal olarak gomulmeli."""
        evil = "foo')\nimport os;os.system('pwned')\n#"
        cfg = json.dumps({
            "output_path": "/tmp/x.json",
            "max_captures": 10,
            "registers": [evil],
            "stack_depth": 0,
            "breakpoints": [],
        })
        rendered = _LLDB_SCRIPT_TEMPLATE.format(config_json=cfg)
        # Derlenebilir olmali
        compile(rendered, "<test>", "exec")

        # Payload _CONFIG_JSON satirinda olmali (sadece veri)
        config_lines = [
            l for l in rendered.splitlines() if l.startswith("_CONFIG_JSON =")
        ]
        assert len(config_lines) == 1, "exactly one config line expected"

        # Hicbir satir 'os.system' kodunu CALISIR sekilde icermemeli.
        # Yani 'os.system' sadece string literal icinde olmali, kod olarak degil.
        # Python repr ile gomuldugu icin newline'lar literal '\n' olarak yazilir.
        for line in rendered.splitlines():
            if line.startswith("_CONFIG_JSON ="):
                continue
            assert "os.system" not in line, (
                f"GUVENLIK KAYDI: payload kod satirina kacti: {line!r}"
            )
            assert "import os" not in line, (
                f"GUVENLIK KAYDI: 'import os' kod satirinda: {line!r}"
            )

    def test_gdb_template_contains_payload_as_string_literal(self) -> None:
        evil = "foo')\nimport os;os.system('pwned')\n#"
        cfg = json.dumps({
            "output_path": "/tmp/x.json",
            "max_captures": 10,
            "registers": [evil],
            "stack_depth": 0,
            "breakpoints": [{"address": "0x100", "function_name": evil}],
        })
        rendered = _GDB_SCRIPT_TEMPLATE.format(config_json=cfg)
        compile(rendered, "<test>", "exec")
        for line in rendered.splitlines():
            if line.startswith("_CONFIG_JSON ="):
                continue
            assert "os.system" not in line
            assert "import os" not in line

    def test_template_newline_in_payload_does_not_break_out(self) -> None:
        """Payload icindeki gercek newline character'i Python literal seviyesinde
        escape edilmeli (yani kod satirina cikamamali)."""
        # Bu payload literal newline iceriyor — JSON dumps + Python repr ile
        # iki kez escape edilmeli.
        evil = "a\nb\nc"
        cfg = json.dumps({
            "output_path": "/tmp/x.json",
            "max_captures": 10,
            "registers": [evil],
            "stack_depth": 0,
            "breakpoints": [],
        })
        rendered = _LLDB_SCRIPT_TEMPLATE.format(config_json=cfg)
        # `_CONFIG_JSON = ` atamasi TEK satir olmali (newline kacmamis).
        # Template'de iki yerde "_CONFIG_JSON" gecer (atama + json.loads cagrisi),
        # bu yuzden sadece atama satirini ariyoruz.
        lines = rendered.splitlines()
        cfg_lines = [i for i, l in enumerate(lines) if l.startswith("_CONFIG_JSON =")]
        assert len(cfg_lines) == 1
        # O satirda payload'in ham newline degil escape edilmis hali olmali
        cfg_line = lines[cfg_lines[0]]
        # JSON katmaninda \n var ama Python literal'da \\n olarak gorunur
        assert "\\n" in cfg_line  # escape edilmis
        # Derlenebilirlik son kontrol
        compile(rendered, "<test>", "exec")
