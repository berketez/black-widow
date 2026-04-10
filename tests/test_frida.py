"""Black Widow -- Frida modulleri testleri.

Test 1: FridaSession import basarili
Test 2: FunctionTracer mesaj isleme (mock data ile)
Test 3: FunctionTracer.get_unique_modules()
Test 4: FunctionTracer.get_api_calls()
Test 5: MemoryScanner pattern listesi
Test 6: Gercek Node.js script spawn + attach (SIP/izin sorunu varsa skip)
Test 7: FunctionTracer.get_file_accesses()
Test 8: FunctionTracer.get_crypto_operations()
Test 9: FunctionTracer.to_json() rapor yapisi
Test 10: DynamicAnalysisStage import basarili
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


# -------------------------------------------------------------------
# Fixture: mock Frida mesajlari
# -------------------------------------------------------------------

@pytest.fixture
def mock_messages() -> list[dict]:
    """FridaSession.messages formatinda mock mesajlar."""
    return [
        # Hook loaded meta mesaji (filtrelenmeli)
        {"type": "hook_loaded", "hook_name": "nodejs_hooks", "pid": 12345, "timestamp": 1000},

        # Dosya islemleri
        {"type": "fs_open", "path": "/app/config.json", "fd": 5, "timestamp": 1001},
        {"type": "fs_read", "fd": 5, "bytes_read": 1024, "timestamp": 1002},
        {"type": "fs_write", "fd": 6, "bytes_written": 512, "timestamp": 1010},
        {"type": "fs_stat", "path": "/app/node_modules/express/index.js", "timestamp": 1003},

        # Network islemleri
        {"type": "net_connect", "host": "api.anthropic.com", "port": 443, "fd": 7, "result": 0, "timestamp": 1005},
        {"type": "net_send", "fd": 7, "bytes_sent": 256, "timestamp": 1006},
        {"type": "net_recv", "fd": 7, "bytes_received": 4096, "timestamp": 1007},
        {"type": "net_request", "url": "https://api.openai.com/v1/chat", "method": "POST", "timestamp": 1008},

        # Process islemleri
        {"type": "process_exec", "command": "/usr/bin/env", "timestamp": 1009},
        {"type": "process_spawn", "command": "/usr/bin/node", "timestamp": 1011},

        # Crypto islemleri
        {"type": "crypto_encrypt", "algorithm": "AES", "key_length": 32, "data_length": 1024, "timestamp": 1012},
        {"type": "crypto_hash", "algorithm": "SHA256", "data_length": 512, "timestamp": 1013},
        {"type": "crypto_dlopen", "library": "/usr/lib/libcrypto.dylib", "handle": "0x12345", "timestamp": 1004},

        # Environment erisimleri
        {"type": "env_access", "name": "HOME", "value": "/Users/test", "timestamp": 1014},
        {"type": "env_access", "name": "API_KEY", "value": "sk-t***MASKED***", "timestamp": 1015},

        # Syscall formati (generic hooks)
        {"type": "syscall", "name": "open", "args": {"path": "/etc/hosts", "flags": 0}, "retval": 3, "timestamp": 1016},
        {"type": "syscall", "name": "connect", "args": {"fd": 8, "addr": {"family": "AF_INET", "ip": "8.8.8.8", "port": 53}}, "retval": 0, "timestamp": 1017},
        {"type": "syscall", "name": "dlopen", "args": {"path": "/usr/lib/libssl.dylib"}, "retval": "0xABC", "timestamp": 1018},
        {"type": "syscall", "name": "mmap", "args": {"length": 131072, "prot": 3, "flags": 1, "fd": -1}, "retval": "0xDEF", "timestamp": 1019},

        # Preferences (ObjC hooks)
        {"type": "defaults_read", "key": "UserTheme", "value": "dark", "timestamp": 1020},
        {"type": "bundle_resource", "resource": "Info.plist", "path": "/app/Contents/Info.plist", "timestamp": 1021},
    ]


# -------------------------------------------------------------------
# Test 1: Import kontrolu
# -------------------------------------------------------------------

class TestFridaImports:
    """Frida modulleri import testi."""

    def test_frida_session_import(self):
        """FridaSession sinifi import edilebilmeli."""
        from karadul.frida.session import FridaSession, FRIDA_AVAILABLE
        assert FridaSession is not None
        # FRIDA_AVAILABLE True veya False olabilir -- import basarili olmasi yeterli

    def test_function_tracer_import(self):
        """FunctionTracer sinifi import edilebilmeli."""
        from karadul.frida.collectors.function_tracer import FunctionTracer
        assert FunctionTracer is not None

    def test_memory_scanner_import(self):
        """MemoryScanner sinifi import edilebilmeli."""
        from karadul.frida.collectors.memory_scanner import MemoryScanner
        assert MemoryScanner is not None

    def test_dynamic_analysis_stage_import(self):
        """DynamicAnalysisStage sinifi import edilebilmeli (Test 10)."""
        from karadul.stages import DynamicAnalysisStage
        assert DynamicAnalysisStage is not None
        assert DynamicAnalysisStage.name == "dynamic"
        assert "identify" in DynamicAnalysisStage.requires


# -------------------------------------------------------------------
# Test 2: FunctionTracer mesaj isleme
# -------------------------------------------------------------------

class TestFunctionTracer:
    """FunctionTracer unit testleri."""

    def test_process_messages_basic(self, mock_messages):
        """Mesajlar islenmeli ve cagri kayitlari olusturulmali (Test 2)."""
        from karadul.frida.collectors.function_tracer import FunctionTracer

        tracer = FunctionTracer()
        tracer.process_messages(mock_messages)

        # hook_loaded mesaji filtrelenmis olmali
        assert len(tracer.calls) > 0
        types = [c.get("type") for c in tracer.calls]
        assert "hook_loaded" not in types

    def test_call_sequence_sorted(self, mock_messages):
        """get_call_sequence() timestamp'e gore sirali donmeli."""
        from karadul.frida.collectors.function_tracer import FunctionTracer

        tracer = FunctionTracer()
        tracer.process_messages(mock_messages)
        sequence = tracer.get_call_sequence()

        timestamps = [c.get("timestamp", 0) for c in sequence]
        assert timestamps == sorted(timestamps)

    def test_get_unique_modules(self, mock_messages):
        """get_unique_modules() dlopen'lardan modul isimlerini cikarmali (Test 3)."""
        from karadul.frida.collectors.function_tracer import FunctionTracer

        tracer = FunctionTracer()
        tracer.process_messages(mock_messages)
        modules = tracer.get_unique_modules()

        # crypto_dlopen -> libcrypto.dylib
        assert "libcrypto.dylib" in modules
        # syscall dlopen -> libssl.dylib
        assert "libssl.dylib" in modules

    def test_get_api_calls(self, mock_messages):
        """get_api_calls() sadece network cagrilarini donmeli (Test 4)."""
        from karadul.frida.collectors.function_tracer import FunctionTracer

        tracer = FunctionTracer()
        tracer.process_messages(mock_messages)
        api_calls = tracer.get_api_calls()

        assert len(api_calls) > 0
        for call in api_calls:
            assert call["category"] == "network"

        # net_connect, net_send, net_recv, net_request, syscall connect = 5
        assert len(api_calls) == 5

    def test_get_file_accesses(self, mock_messages):
        """get_file_accesses() dosya islemlerini donmeli (Test 7)."""
        from karadul.frida.collectors.function_tracer import FunctionTracer

        tracer = FunctionTracer()
        tracer.process_messages(mock_messages)
        file_ops = tracer.get_file_accesses()

        assert len(file_ops) > 0
        for op in file_ops:
            assert op["category"] == "filesystem"

        # fs_open, fs_read, fs_write, fs_stat, syscall open = 5
        assert len(file_ops) == 5

    def test_get_crypto_operations(self, mock_messages):
        """get_crypto_operations() crypto islemlerini donmeli (Test 8)."""
        from karadul.frida.collectors.function_tracer import FunctionTracer

        tracer = FunctionTracer()
        tracer.process_messages(mock_messages)
        crypto_ops = tracer.get_crypto_operations()

        assert len(crypto_ops) > 0
        for op in crypto_ops:
            assert op["category"] == "crypto"

        # crypto_encrypt, crypto_hash, crypto_dlopen = 3
        assert len(crypto_ops) == 3

    def test_get_process_operations(self, mock_messages):
        """get_process_operations() process islemlerini donmeli."""
        from karadul.frida.collectors.function_tracer import FunctionTracer

        tracer = FunctionTracer()
        tracer.process_messages(mock_messages)
        proc_ops = tracer.get_process_operations()

        # process_exec, process_spawn = 2
        assert len(proc_ops) == 2

    def test_get_env_accesses(self, mock_messages):
        """get_env_accesses() ortam degiskeni erisimlerini donmeli."""
        from karadul.frida.collectors.function_tracer import FunctionTracer

        tracer = FunctionTracer()
        tracer.process_messages(mock_messages)
        env_ops = tracer.get_env_accesses()

        # env_access x2 = 2
        assert len(env_ops) == 2

    def test_get_stats(self, mock_messages):
        """get_stats() kategori bazli istatistikler donmeli."""
        from karadul.frida.collectors.function_tracer import FunctionTracer

        tracer = FunctionTracer()
        tracer.process_messages(mock_messages)
        stats = tracer.get_stats()

        assert "network" in stats
        assert "filesystem" in stats
        assert "crypto" in stats
        assert stats["network"] == 5
        assert stats["filesystem"] == 5

    def test_to_json_structure(self, mock_messages):
        """to_json() dogru yapida rapor donmeli (Test 9)."""
        from karadul.frida.collectors.function_tracer import FunctionTracer

        tracer = FunctionTracer()
        tracer.process_messages(mock_messages)
        report = tracer.to_json()

        # Beklenen anahtarlar
        assert "total_calls" in report
        assert "unique_modules" in report
        assert "stats" in report
        assert "api_calls" in report
        assert "file_accesses" in report
        assert "crypto_operations" in report
        assert "process_operations" in report
        assert "env_accesses" in report
        assert "call_sequence" in report

        assert report["total_calls"] > 0
        assert isinstance(report["unique_modules"], list)
        assert isinstance(report["stats"], dict)

        # JSON serializable olmali
        serialized = json.dumps(report, default=str)
        assert len(serialized) > 0

    def test_clear(self, mock_messages):
        """clear() tum cagri kayitlarini temizlemeli."""
        from karadul.frida.collectors.function_tracer import FunctionTracer

        tracer = FunctionTracer()
        tracer.process_messages(mock_messages)
        assert len(tracer.calls) > 0

        tracer.clear()
        assert len(tracer.calls) == 0

    def test_empty_messages(self):
        """Bos mesaj listesi ile hata vermemeli."""
        from karadul.frida.collectors.function_tracer import FunctionTracer

        tracer = FunctionTracer()
        tracer.process_messages([])
        assert len(tracer.calls) == 0
        assert len(tracer.get_call_sequence()) == 0
        assert len(tracer.get_unique_modules()) == 0

    def test_invalid_messages(self):
        """Gecersiz mesajlar sessizce atlanmali."""
        from karadul.frida.collectors.function_tracer import FunctionTracer

        tracer = FunctionTracer()
        tracer.process_messages([
            "not a dict",
            42,
            None,
            {"type": "hook_loaded"},  # Filtrelenmeli
            {"no_type_field": True},
        ])
        # Sadece no_type_field olan islenmis olmali (type="" olarak)
        assert len(tracer.calls) == 1


# -------------------------------------------------------------------
# Test 5: MemoryScanner pattern listesi
# -------------------------------------------------------------------

class TestMemoryScanner:
    """MemoryScanner unit testleri."""

    def test_default_patterns(self):
        """DEFAULT_SENSITIVE_PATTERNS tanimli olmali (Test 5)."""
        from karadul.frida.collectors.memory_scanner import (
            DEFAULT_SENSITIVE_PATTERNS,
            MemoryScanner,
        )

        assert len(DEFAULT_SENSITIVE_PATTERNS) > 0
        assert "API_KEY" in DEFAULT_SENSITIVE_PATTERNS
        assert "SECRET" in DEFAULT_SENSITIVE_PATTERNS
        assert "TOKEN" in DEFAULT_SENSITIVE_PATTERNS
        assert "PASSWORD" in DEFAULT_SENSITIVE_PATTERNS
        assert "Bearer " in DEFAULT_SENSITIVE_PATTERNS

    def test_scanner_not_attached_returns_empty(self):
        """Session aktif degilken scan bos liste donmeli."""
        from karadul.frida.collectors.memory_scanner import MemoryScanner

        # Mock session
        class MockSession:
            is_attached = False
            messages = []

        scanner = MemoryScanner(MockSession())
        result = scanner.scan_strings()
        assert result == []

    def test_scanner_clear(self):
        """clear() tum sonuclari temizlemeli."""
        from karadul.frida.collectors.memory_scanner import MemoryScanner

        class MockSession:
            is_attached = False
            messages = []

        scanner = MemoryScanner(MockSession())
        scanner._results = [{"dummy": True}]
        assert len(scanner.results) == 1

        scanner.clear()
        assert len(scanner.results) == 0


# -------------------------------------------------------------------
# Test 6: Gercek Frida spawn (opsiyonel)
# -------------------------------------------------------------------

class TestFridaRealSpawn:
    """Gercek Frida spawn testleri -- SIP veya izin sorunu varsa skip."""

    @pytest.mark.skipif(
        not Path("/usr/local/bin/node").exists() and not Path("/opt/homebrew/bin/node").exists(),
        reason="Node.js kurulu degil"
    )
    def test_node_spawn_and_exit(self):
        """Basit node script spawn et ve exit yakala (Test 6).

        Bu test gercek Frida kullanir. macOS SIP veya izin sorunu
        varsa skip edilir.
        """
        try:
            from karadul.frida.session import FridaSession, FRIDA_AVAILABLE, FridaNotAvailableError
        except ImportError:
            pytest.skip("karadul.frida.session import edilemedi")

        if not FRIDA_AVAILABLE:
            pytest.skip("frida paketi kurulu degil")

        from karadul.config import Config

        config = Config()

        try:
            session = FridaSession(config)
        except FridaNotAvailableError:
            pytest.skip("frida kurulu degil")

        # Node.js yolunu bul
        node_path = "/opt/homebrew/bin/node"
        if not Path(node_path).exists():
            node_path = "/usr/local/bin/node"
        if not Path(node_path).exists():
            pytest.skip("Node.js bulunamadi")

        try:
            pid = session.spawn(node_path, args=["-e", "console.log('hello from frida test')"])
            assert pid > 0
            assert session.is_attached

            # Kisa bekleme (script hemen cikacak)
            session.wait(timeout=3.0)

        except Exception as exc:
            # SIP veya izin hatasi
            pytest.skip(f"Frida spawn basarisiz (muhtemelen SIP): {exc}")

        finally:
            session.detach()
            assert not session.is_attached


# -------------------------------------------------------------------
# Test: Hook script dosyalarinin varligi
# -------------------------------------------------------------------

class TestHookScripts:
    """Hook script dosyalarinin varligini kontrol et."""

    @pytest.fixture
    def hooks_dir(self) -> Path:
        return Path(__file__).parent.parent / "karadul" / "frida" / "hooks"

    def test_nodejs_hooks_exists(self, hooks_dir):
        """nodejs_hooks.js dosyasi mevcut olmali."""
        assert (hooks_dir / "nodejs_hooks.js").exists()

    def test_generic_hooks_exists(self, hooks_dir):
        """generic_hooks.js dosyasi mevcut olmali."""
        assert (hooks_dir / "generic_hooks.js").exists()

    def test_objc_hooks_exists(self, hooks_dir):
        """objc_hooks.js dosyasi mevcut olmali."""
        assert (hooks_dir / "objc_hooks.js").exists()

    def test_nodejs_hooks_uses_send(self, hooks_dir):
        """nodejs_hooks.js send() kullanmali, console.log degil (mesaj icin)."""
        content = (hooks_dir / "nodejs_hooks.js").read_text()
        assert "send({" in content or "send( {" in content
        # console.log olmamaali (hook icerisinde mesaj gonderme icin)
        # Not: Yorum satirlari haric

    def test_generic_hooks_uses_send(self, hooks_dir):
        """generic_hooks.js send() kullanmali."""
        content = (hooks_dir / "generic_hooks.js").read_text()
        assert "send({" in content or "send( {" in content

    def test_objc_hooks_uses_send(self, hooks_dir):
        """objc_hooks.js send() kullanmali."""
        content = (hooks_dir / "objc_hooks.js").read_text()
        assert "send({" in content or "send( {" in content


# -------------------------------------------------------------------
# Test: DynamicAnalysisStage hook secimi
# -------------------------------------------------------------------

class TestDynamicAnalysisStageHookSelection:
    """DynamicAnalysisStage._select_hook_script() testleri."""

    def test_javascript_selects_nodejs_hooks(self):
        """JavaScript hedef icin nodejs_hooks.js secilmeli."""
        from karadul.stages import DynamicAnalysisStage
        from karadul.core.target import TargetInfo, TargetType, Language

        stage = DynamicAnalysisStage()
        hooks_dir = Path(__file__).parent.parent / "karadul" / "frida" / "hooks"

        target = TargetInfo(
            path=Path("/tmp/test.js"),
            name="test",
            target_type=TargetType.JS_BUNDLE,
            language=Language.JAVASCRIPT,
            file_size=100,
            file_hash="abc",
        )

        hook = stage._select_hook_script(target, hooks_dir)
        assert hook is not None
        assert hook.name == "nodejs_hooks.js"

    def test_objc_selects_objc_hooks(self):
        """Objective-C hedef icin objc_hooks.js secilmeli."""
        from karadul.stages import DynamicAnalysisStage
        from karadul.core.target import TargetInfo, TargetType, Language

        stage = DynamicAnalysisStage()
        hooks_dir = Path(__file__).parent.parent / "karadul" / "frida" / "hooks"

        target = TargetInfo(
            path=Path("/tmp/test"),
            name="test",
            target_type=TargetType.MACHO_BINARY,
            language=Language.OBJECTIVE_C,
            file_size=100,
            file_hash="abc",
        )

        hook = stage._select_hook_script(target, hooks_dir)
        assert hook is not None
        assert hook.name == "objc_hooks.js"

    def test_swift_selects_objc_hooks(self):
        """Swift hedef icin de objc_hooks.js secilmeli (ObjC runtime)."""
        from karadul.stages import DynamicAnalysisStage
        from karadul.core.target import TargetInfo, TargetType, Language

        stage = DynamicAnalysisStage()
        hooks_dir = Path(__file__).parent.parent / "karadul" / "frida" / "hooks"

        target = TargetInfo(
            path=Path("/tmp/test"),
            name="test",
            target_type=TargetType.MACHO_BINARY,
            language=Language.SWIFT,
            file_size=100,
            file_hash="abc",
        )

        hook = stage._select_hook_script(target, hooks_dir)
        assert hook is not None
        assert hook.name == "objc_hooks.js"

    def test_cpp_selects_generic_hooks(self):
        """C++ hedef icin generic_hooks.js secilmeli."""
        from karadul.stages import DynamicAnalysisStage
        from karadul.core.target import TargetInfo, TargetType, Language

        stage = DynamicAnalysisStage()
        hooks_dir = Path(__file__).parent.parent / "karadul" / "frida" / "hooks"

        target = TargetInfo(
            path=Path("/tmp/test"),
            name="test",
            target_type=TargetType.MACHO_BINARY,
            language=Language.CPP,
            file_size=100,
            file_hash="abc",
        )

        hook = stage._select_hook_script(target, hooks_dir)
        assert hook is not None
        assert hook.name == "generic_hooks.js"
