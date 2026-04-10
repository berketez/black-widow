"""Debugger Bridge testleri.

GDB/LLDB runtime deger yakalama modulunun unit testleri.
Gercek debugger calistirmaz -- shutil.which mock'lanir.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from karadul.config import Config, DebuggerConfig
from karadul.ghidra.debugger_bridge import (
    BreakpointSpec,
    CapturedValue,
    CaptureSpec,
    DebuggerBridge,
    TypeVerification,
    _infer_type_from_value,
    _types_compatible,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def config() -> Config:
    """Debugger aktif Config."""
    cfg = Config()
    cfg.debugger.enabled = True
    return cfg


@pytest.fixture
def bridge(config: Config) -> DebuggerBridge:
    """DebuggerBridge instance'i."""
    return DebuggerBridge(config)


@pytest.fixture
def sample_breakpoints() -> list[BreakpointSpec]:
    """Ornek breakpoint listesi."""
    return [
        BreakpointSpec(
            address="0x100003f00",
            function_name="main",
            capture=CaptureSpec(registers=["rdi", "rsi", "rax"]),
        ),
        BreakpointSpec(
            address="0x100003f80",
            function_name="process_data",
            capture=CaptureSpec(
                registers=["rdi", "rsi"],
                stack_depth=2,
            ),
        ),
    ]


@pytest.fixture
def sample_captured_values() -> list[CapturedValue]:
    """Ornek yakalanan degerler."""
    return [
        CapturedValue(
            address="0x100003f00",
            function_name="main",
            hit_count=1,
            register_values={"rdi": 1, "rsi": 0x7fff5fbff8a0, "rax": 65},
            stack_values={},
            timestamp=time.monotonic(),
        ),
        CapturedValue(
            address="0x100003f80",
            function_name="process_data",
            hit_count=1,
            register_values={"rdi": 0x7fff5fbff900, "rsi": 42},
            stack_values={"frame_0": {"pc": "0x100003f80", "function": "process_data"}},
            timestamp=time.monotonic(),
        ),
    ]


# ---------------------------------------------------------------------------
# Debugger tespiti testleri
# ---------------------------------------------------------------------------


class TestDetectDebugger:
    """detect_debugger() testleri."""

    def test_detect_debugger_lldb(self, bridge: DebuggerBridge, monkeypatch):
        """macOS'ta lldb bulunursa 'lldb' doner."""
        monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/lldb" if x == "lldb" else None)
        result = bridge.detect_debugger()
        assert result == "lldb"

    def test_detect_debugger_gdb(self, bridge: DebuggerBridge, monkeypatch):
        """lldb yoksa gdb'ye fallback yapar."""
        monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/gdb" if x == "gdb" else None)
        result = bridge.detect_debugger()
        assert result == "gdb"

    def test_detect_debugger_none(self, bridge: DebuggerBridge, monkeypatch):
        """Hicbir debugger yoksa None doner."""
        monkeypatch.setattr("shutil.which", lambda _: None)
        result = bridge.detect_debugger()
        assert result is None

    def test_detect_debugger_preferred_lldb(self, monkeypatch):
        """preferred_debugger='lldb' ise sadece lldb aranir."""
        cfg = Config()
        cfg.debugger.preferred_debugger = "lldb"
        bridge = DebuggerBridge(cfg)

        calls = []
        def mock_which(name):
            calls.append(name)
            return "/usr/bin/lldb" if name == "lldb" else "/usr/bin/gdb"

        monkeypatch.setattr("shutil.which", mock_which)
        result = bridge.detect_debugger()
        assert result == "lldb"
        # Sadece lldb arandi, gdb'ye bakilmadi
        assert calls == ["lldb"]

    def test_detect_debugger_preferred_gdb(self, monkeypatch):
        """preferred_debugger='gdb' ise sadece gdb aranir."""
        cfg = Config()
        cfg.debugger.preferred_debugger = "gdb"
        bridge = DebuggerBridge(cfg)

        calls = []
        def mock_which(name):
            calls.append(name)
            return "/usr/bin/gdb" if name == "gdb" else "/usr/bin/lldb"

        monkeypatch.setattr("shutil.which", mock_which)
        result = bridge.detect_debugger()
        assert result == "gdb"
        assert calls == ["gdb"]


# ---------------------------------------------------------------------------
# Dataclass olusturma testleri
# ---------------------------------------------------------------------------


class TestDataclasses:
    """Dataclass olusturma ve varsayilan deger testleri."""

    def test_breakpoint_spec_creation(self):
        """BreakpointSpec dogru olusturulur."""
        bp = BreakpointSpec(address="0x1000")
        assert bp.address == "0x1000"
        assert bp.function_name is None
        assert isinstance(bp.capture, CaptureSpec)
        assert "rdi" in bp.capture.registers

    def test_capture_spec_defaults(self):
        """CaptureSpec varsayilan degerleri dogru."""
        cs = CaptureSpec()
        assert cs.registers == ["rdi", "rsi", "rax"]
        assert cs.stack_depth == 0
        assert cs.memory_reads == []

    def test_captured_value_creation(self):
        """CapturedValue dogru olusturulur."""
        cv = CapturedValue(
            address="0xDEADBEEF",
            function_name="test_func",
            hit_count=3,
            register_values={"rax": 42},
            stack_values={},
            timestamp=123.456,
        )
        assert cv.address == "0xDEADBEEF"
        assert cv.function_name == "test_func"
        assert cv.hit_count == 3
        assert cv.register_values["rax"] == 42
        assert cv.timestamp == 123.456

    def test_type_verification_match(self):
        """TypeVerification match=True durumu."""
        tv = TypeVerification(
            function_name="main",
            variable_name="rdi",
            ghidra_type="int",
            runtime_value=42,
            inferred_type="uint32",
            match=True,
            confidence=0.8,
        )
        assert tv.match is True
        assert tv.confidence == 0.8
        assert tv.ghidra_type == "int"

    def test_type_verification_mismatch(self):
        """TypeVerification match=False durumu."""
        tv = TypeVerification(
            function_name="process",
            variable_name="rsi",
            ghidra_type="char *",
            runtime_value=42,
            inferred_type="uint32",
            match=False,
            confidence=0.35,
        )
        assert tv.match is False
        assert tv.confidence == 0.35


# ---------------------------------------------------------------------------
# Script uretimi testleri
# ---------------------------------------------------------------------------


class TestScriptGeneration:
    """LLDB/GDB script uretimi testleri."""

    def test_generate_lldb_script(self, bridge: DebuggerBridge, tmp_path, sample_breakpoints):
        """LLDB script'i dogru icerikle uretilir."""
        output_path = tmp_path / "output.json"
        script_path = bridge._generate_lldb_script(
            sample_breakpoints, Path("/tmp/test_binary"), output_path,
        )
        try:
            assert script_path.exists()
            content = script_path.read_text()
            # Script temel bilesenleri icermeli
            assert "lldb" in content
            assert "breakpoint_callback" in content
            assert "__lldb_init_module" in content
            assert str(output_path) in content
            assert "rdi" in content
            assert "rsi" in content
            assert "rax" in content
            # Breakpoint adresleri
            assert "0x100003f00" in content
            assert "0x100003f80" in content
        finally:
            script_path.unlink(missing_ok=True)

    def test_generate_gdb_script(self, bridge: DebuggerBridge, tmp_path, sample_breakpoints):
        """GDB script'i dogru icerikle uretilir."""
        output_path = tmp_path / "output.json"
        script_path = bridge._generate_gdb_script(
            sample_breakpoints, Path("/tmp/test_binary"), output_path,
        )
        try:
            assert script_path.exists()
            content = script_path.read_text()
            # Script temel bilesenleri icermeli
            assert "gdb" in content
            assert "KaradulBreakpoint" in content
            assert str(output_path) in content
            assert "rdi" in content
            assert "rsi" in content
            # Breakpoint adresleri
            assert "0x100003f00" in content
            assert "0x100003f80" in content
        finally:
            script_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Tip dogrulama testleri
# ---------------------------------------------------------------------------


class TestVerifyTypes:
    """verify_types() testleri."""

    def test_verify_types_char_range(self, bridge: DebuggerBridge):
        """0-255 arasindaki degerler uint8/char olarak cikarilir."""
        captured = [CapturedValue(
            address="0x1000",
            function_name="read_char",
            hit_count=1,
            register_values={"rdi": 65},  # 'A' = 65
            stack_values={},
            timestamp=0.0,
        )]
        ghidra_types = {"rdi": "char"}
        results = bridge.verify_types(captured, ghidra_types)

        assert len(results) == 1
        v = results[0]
        assert v.inferred_type == "uint8"
        assert v.match is True  # char ve uint8 uyumlu
        assert v.confidence > 0

    def test_verify_types_pointer(self, bridge: DebuggerBridge):
        """Buyuk degerler pointer olarak cikarilir."""
        captured = [CapturedValue(
            address="0x1000",
            function_name="alloc",
            hit_count=1,
            register_values={"rdi": 0x7FFF5FBFF900},
            stack_values={},
            timestamp=0.0,
        )]
        ghidra_types = {"rdi": "void *"}
        results = bridge.verify_types(captured, ghidra_types)

        assert len(results) == 1
        v = results[0]
        assert v.inferred_type == "pointer"
        assert v.match is True
        assert v.confidence > 0

    def test_verify_types_bool(self, bridge: DebuggerBridge):
        """0/1 degerleri bool olarak cikarilir."""
        captured = [CapturedValue(
            address="0x2000",
            function_name="is_valid",
            hit_count=1,
            register_values={"rax": 1},
            stack_values={},
            timestamp=0.0,
        )]
        ghidra_types = {"rax": "bool"}
        results = bridge.verify_types(captured, ghidra_types)

        assert len(results) == 1
        v = results[0]
        assert v.inferred_type == "bool"
        assert v.match is True

    def test_verify_types_empty_input(self, bridge: DebuggerBridge):
        """Bos girislerde bos liste doner."""
        assert bridge.verify_types([], {}) == []
        assert bridge.verify_types([], {"rdi": "int"}) == []

        captured = [CapturedValue(
            address="0x1000",
            function_name=None,
            hit_count=1,
            register_values={"rdi": 42},
            stack_values={},
            timestamp=0.0,
        )]
        assert bridge.verify_types(captured, {}) == []


# ---------------------------------------------------------------------------
# Config testleri
# ---------------------------------------------------------------------------


class TestDebuggerConfig:
    """DebuggerConfig testleri."""

    def test_config_defaults(self):
        """Varsayilan degerler: enabled=False, auto, 30s timeout."""
        cfg = DebuggerConfig()
        assert cfg.enabled is False
        assert cfg.preferred_debugger == "auto"
        assert cfg.capture_timeout == 30.0
        assert cfg.max_breakpoints == 50
        assert cfg.max_captures_per_bp == 10
        assert cfg.auto_type_verification is False

    def test_config_in_main_config(self):
        """Config icinde debugger field'i mevcut ve varsayilan KAPALI."""
        cfg = Config()
        assert hasattr(cfg, "debugger")
        assert isinstance(cfg.debugger, DebuggerConfig)
        assert cfg.debugger.enabled is False

    def test_config_from_dict(self):
        """YAML'dan debugger ayarlari yuklenebilir."""
        data = {
            "debugger": {
                "enabled": True,
                "preferred_debugger": "lldb",
                "capture_timeout": 60.0,
                "max_breakpoints": 100,
            }
        }
        cfg = Config._from_dict(data)
        assert cfg.debugger.enabled is True
        assert cfg.debugger.preferred_debugger == "lldb"
        assert cfg.debugger.capture_timeout == 60.0
        assert cfg.debugger.max_breakpoints == 100
        # Ayarlanmamis deger varsayilan kalir
        assert cfg.debugger.max_captures_per_bp == 10


# ---------------------------------------------------------------------------
# Parse output testleri
# ---------------------------------------------------------------------------


class TestParseOutput:
    """_parse_output() testleri."""

    def test_parse_valid_output(self, bridge: DebuggerBridge, tmp_path):
        """Gecerli JSON cikti dogru parse edilir."""
        output_file = tmp_path / "capture.json"
        data = [
            {
                "address": "0x100003f00",
                "function_name": "main",
                "hit_count": 1,
                "register_values": {"rdi": 1, "rsi": "0x7fff5fbff8a0"},
                "stack_values": {},
                "timestamp": 123.456,
            },
        ]
        output_file.write_text(json.dumps(data))

        result = bridge._parse_output(output_file)
        assert len(result) == 1
        assert result[0].address == "0x100003f00"
        assert result[0].function_name == "main"
        assert result[0].register_values["rdi"] == 1

    def test_parse_missing_file(self, bridge: DebuggerBridge, tmp_path):
        """Dosya yoksa bos liste doner."""
        result = bridge._parse_output(tmp_path / "nonexistent.json")
        assert result == []

    def test_parse_empty_file(self, bridge: DebuggerBridge, tmp_path):
        """Bos dosyada bos liste doner."""
        output_file = tmp_path / "empty.json"
        output_file.write_text("")
        result = bridge._parse_output(output_file)
        assert result == []

    def test_parse_invalid_json(self, bridge: DebuggerBridge, tmp_path):
        """Gecersiz JSON'da bos liste doner."""
        output_file = tmp_path / "bad.json"
        output_file.write_text("not json {{{")
        result = bridge._parse_output(output_file)
        assert result == []


# ---------------------------------------------------------------------------
# Tip cikarim yardimcilari testleri
# ---------------------------------------------------------------------------


class TestTypeInference:
    """_infer_type_from_value() ve _types_compatible() testleri."""

    def test_infer_bool(self):
        assert _infer_type_from_value(0) == ("bool", 0.3)
        assert _infer_type_from_value(1) == ("bool", 0.3)

    def test_infer_uint8(self):
        typ, conf = _infer_type_from_value(200)
        assert typ == "uint8"

    def test_infer_pointer(self):
        typ, conf = _infer_type_from_value(0x7FFF5FBFF900)
        assert typ == "pointer"
        assert conf >= 0.7

    def test_infer_string_value(self):
        typ, conf = _infer_type_from_value("not_a_hex")
        assert typ == "string"

    def test_types_compatible_exact(self):
        match, conf = _types_compatible("int", "int")
        assert match is True
        assert conf >= 0.9

    def test_types_compatible_pointer(self):
        match, conf = _types_compatible("void *", "pointer")
        assert match is True

    def test_types_compatible_mismatch(self):
        match, conf = _types_compatible("char *", "uint32")
        assert match is False
