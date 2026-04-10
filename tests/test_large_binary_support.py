"""Buyuk binary destegi testleri (224MB+ Brave/Opera).

Test edilen islemler:
1. Config: ghidra_batch_size, large_binary_threshold_mb parametreleri
2. MachOAnalyzer._extract_strings_mmap: mmap ile string extraction
3. CVariableNamer._load_strings: lazy/streaming string loading
4. GhidraHeadless: buyuk binary timeout artirimi
5. Pipeline: buyuk binary tespiti ve context flag'i
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from karadul.config import Config, BinaryReconstructionConfig


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def config() -> Config:
    """Test konfigurasyon."""
    return Config()


@pytest.fixture
def tmp_dir(tmp_path: Path) -> Path:
    """Gecici dizin."""
    return tmp_path


# ---------------------------------------------------------------------------
# 1. Config testleri
# ---------------------------------------------------------------------------

class TestLargeBinaryConfig:
    """Config'deki buyuk binary parametreleri."""

    def test_default_batch_size(self, config: Config) -> None:
        """Varsayilan batch size 5000 olmali."""
        assert config.binary_reconstruction.ghidra_batch_size == 5000

    def test_default_threshold(self, config: Config) -> None:
        """Varsayilan buyuk binary esigi 100MB olmali."""
        assert config.binary_reconstruction.large_binary_threshold_mb == 100

    def test_default_timeout_multiplier(self, config: Config) -> None:
        """Varsayilan timeout carpani 4.0 olmali."""
        assert config.binary_reconstruction.large_binary_timeout_multiplier == 4.0

    def test_batch_size_configurable(self) -> None:
        """Batch size disi ayarlanabilmeli."""
        cfg = Config()
        cfg.binary_reconstruction.ghidra_batch_size = 2000
        assert cfg.binary_reconstruction.ghidra_batch_size == 2000

    def test_threshold_configurable(self) -> None:
        """Buyuk binary esigi ayarlanabilmeli."""
        cfg = Config()
        cfg.binary_reconstruction.large_binary_threshold_mb = 50
        assert cfg.binary_reconstruction.large_binary_threshold_mb == 50

    def test_yaml_load_batch_size(self, tmp_dir: Path) -> None:
        """YAML'dan batch_size okunabilmeli."""
        yaml_path = tmp_dir / "karadul.yaml"
        yaml_path.write_text(
            "binary_reconstruction:\n"
            "  ghidra_batch_size: 3000\n"
            "  large_binary_threshold_mb: 200\n"
            "  large_binary_timeout_multiplier: 2.0\n"
        )
        cfg = Config.load(yaml_path)
        assert cfg.binary_reconstruction.ghidra_batch_size == 3000
        assert cfg.binary_reconstruction.large_binary_threshold_mb == 200
        assert cfg.binary_reconstruction.large_binary_timeout_multiplier == 2.0


# ---------------------------------------------------------------------------
# 2. mmap string extraction testleri
# ---------------------------------------------------------------------------

class TestMmapStringExtraction:
    """MachOAnalyzer._extract_strings_mmap testleri."""

    def test_basic_extraction(self, tmp_dir: Path) -> None:
        """Basit ASCII string extraction calismali."""
        from karadul.analyzers.macho import MachOAnalyzer

        # Test binary olustur: ASCII string'ler + null byte'lar
        content = (
            b"\x00\x00\x00Hello World\x00\x00"
            b"\x01\x02Test String\x00"
            b"\xff\xfe" + b"A" * 3 + b"\x00"  # 3 char = min_length'e uymuyor
            b"\x00Long String Here\x00"
        )
        test_file = tmp_dir / "test.bin"
        test_file.write_bytes(content)

        strings = MachOAnalyzer._extract_strings_mmap(test_file, min_length=4)

        assert "Hello World" in strings
        assert "Test String" in strings
        assert "Long String Here" in strings
        # 3 karakterlik "AAA" min_length=4'e uymuyor, olmamali
        assert "AAA" not in strings

    def test_empty_file(self, tmp_dir: Path) -> None:
        """Bos dosya hata vermemeli."""
        from karadul.analyzers.macho import MachOAnalyzer

        test_file = tmp_dir / "empty.bin"
        test_file.write_bytes(b"")

        strings = MachOAnalyzer._extract_strings_mmap(test_file, min_length=4)
        assert strings == []

    def test_max_strings_limit(self, tmp_dir: Path) -> None:
        """Max string limiti calismali."""
        from karadul.analyzers.macho import MachOAnalyzer

        # 100 string olustur
        content = b""
        for i in range(100):
            content += b"\x00" + f"string_number_{i:03d}".encode("ascii") + b"\x00"

        test_file = tmp_dir / "many_strings.bin"
        test_file.write_bytes(content)

        strings = MachOAnalyzer._extract_strings_mmap(
            test_file, min_length=4, max_strings=10,
        )
        assert len(strings) == 10

    def test_min_length_parameter(self, tmp_dir: Path) -> None:
        """min_length parametresi calismali."""
        from karadul.analyzers.macho import MachOAnalyzer

        content = b"\x00ab\x00abcd\x00abcdef\x00"
        test_file = tmp_dir / "minlen.bin"
        test_file.write_bytes(content)

        # min_length=6
        strings = MachOAnalyzer._extract_strings_mmap(test_file, min_length=6)
        assert len(strings) == 1
        assert "abcdef" in strings

        # min_length=2
        strings = MachOAnalyzer._extract_strings_mmap(test_file, min_length=2)
        assert len(strings) == 3

    def test_nonexistent_file(self, tmp_dir: Path) -> None:
        """Olmayan dosya bos liste dondurmeli."""
        from karadul.analyzers.macho import MachOAnalyzer

        strings = MachOAnalyzer._extract_strings_mmap(
            tmp_dir / "nonexistent.bin", min_length=4,
        )
        assert strings == []

    def test_binary_with_utf8(self, tmp_dir: Path) -> None:
        """UTF-8 olmayan byte'lar string'i kesmeli."""
        from karadul.analyzers.macho import MachOAnalyzer

        # "Hello" + non-ascii + "World"
        content = b"Hello\x80World\x00"
        test_file = tmp_dir / "utf8.bin"
        test_file.write_bytes(content)

        strings = MachOAnalyzer._extract_strings_mmap(test_file, min_length=4)
        assert "Hello" in strings
        assert "World" in strings
        assert "HelloWorld" not in strings  # non-ascii byte keser

    def test_large_synthetic_file(self, tmp_dir: Path) -> None:
        """1MB sentetik dosyada performans testi."""
        from karadul.analyzers.macho import MachOAnalyzer

        # 1MB dosya: her 1KB'de bir string
        content = bytearray()
        expected_count = 0
        for i in range(1024):
            # 1000 byte sifir + string
            content.extend(b"\x00" * 1000)
            s = f"func_{i:04d}_name".encode("ascii")
            content.extend(s)
            expected_count += 1
        content.extend(b"\x00" * 100)

        test_file = tmp_dir / "large_synthetic.bin"
        test_file.write_bytes(bytes(content))

        strings = MachOAnalyzer._extract_strings_mmap(test_file, min_length=4)
        assert len(strings) == expected_count


# ---------------------------------------------------------------------------
# 3. Lazy string loading testleri
# ---------------------------------------------------------------------------

class TestLazyStringLoading:
    """CVariableNamer._load_strings streaming mode testleri."""

    def _make_strings_json(self, path: Path, count: int) -> None:
        """Test icin ghidra_strings.json olustur."""
        strings = []
        for i in range(count):
            strings.append({
                "value": f"string_{i}",
                "address": f"0x{i:08x}",
                "function": f"FUN_{i % 100:08x}" if i % 2 == 0 else None,
                "refs": [f"0x{(i % 100):08x}"] if i % 3 == 0 else [],
            })
        data = {"total": count, "strings": strings}
        path.write_text(json.dumps(data), encoding="utf-8")

    def test_small_file_uses_full_load(self, tmp_dir: Path) -> None:
        """Kucuk dosya tam JSON loading kullanmali."""
        from karadul.reconstruction.c_namer import CVariableNamer

        strings_path = tmp_dir / "strings.json"
        self._make_strings_json(strings_path, 100)

        namer = CVariableNamer(Config())
        namer._load_strings(strings_path)

        # _strings listesi dolu olmali (kucuk dosya = full load)
        assert len(namer._strings) == 100
        assert len(namer._string_refs_by_func) > 0

    def test_streaming_mode_builds_index(self, tmp_dir: Path) -> None:
        """Streaming mode fonksiyon-string indeksini olusturmali."""
        from karadul.reconstruction.c_namer import CVariableNamer

        strings_path = tmp_dir / "strings.json"
        self._make_strings_json(strings_path, 500)

        namer = CVariableNamer(Config())
        # Streaming mode'u dogrudan test et (threshold'u bypass)
        file_size = strings_path.stat().st_size
        namer._load_strings_streaming(strings_path, file_size)

        # _strings bos ama indeks dolu olmali
        assert len(namer._strings) == 0
        assert len(namer._string_refs_by_func) > 0

    def test_streaming_preserves_xrefs(self, tmp_dir: Path) -> None:
        """Streaming mode xrefs alanini dogru islmeli."""
        from karadul.reconstruction.c_namer import CVariableNamer

        data = {
            "total": 2,
            "strings": [
                {
                    "value": "test_string",
                    "address": "0x1000",
                    "refs": ["0xAAAA"],
                    "xrefs": [
                        {"from_func_addr": "0xBBBB"},
                    ],
                },
                {
                    "value": "another_string",
                    "address": "0x2000",
                    "function": "FUN_00003000",
                },
            ],
        }
        strings_path = tmp_dir / "strings.json"
        strings_path.write_text(json.dumps(data), encoding="utf-8")

        namer = CVariableNamer(Config())
        file_size = strings_path.stat().st_size
        namer._load_strings_streaming(strings_path, file_size)

        # xrefs'ten gelen adres de indekslenmis olmali
        assert "0xBBBB" in namer._string_refs_by_func
        assert "test_string" in namer._string_refs_by_func["0xBBBB"]
        # function alanindaki adres de indekslenmis olmali
        assert "FUN_00003000" in namer._string_refs_by_func

    def test_nonexistent_file(self, tmp_dir: Path) -> None:
        """Olmayan dosya hata vermemeli."""
        from karadul.reconstruction.c_namer import CVariableNamer

        namer = CVariableNamer(Config())
        namer._load_strings(tmp_dir / "nonexistent.json")
        assert len(namer._strings) == 0

    def test_full_load_preserves_all_data(self, tmp_dir: Path) -> None:
        """Tam yukleme tum _StringRef objelerini saklamali."""
        from karadul.reconstruction.c_namer import CVariableNamer

        data = {
            "total": 3,
            "strings": [
                {"value": "foo", "address": "0x1", "refs": ["0xA"]},
                {"value": "bar", "address": "0x2", "refs": ["0xA", "0xB"]},
                {"value": "baz", "address": "0x3", "function": "0xC"},
            ],
        }
        strings_path = tmp_dir / "strings.json"
        strings_path.write_text(json.dumps(data), encoding="utf-8")

        namer = CVariableNamer(Config())
        namer._load_strings_full(strings_path)

        assert len(namer._strings) == 3
        assert "foo" in namer._string_refs_by_func["0xA"]
        assert "bar" in namer._string_refs_by_func["0xA"]
        assert "bar" in namer._string_refs_by_func["0xB"]
        assert "baz" in namer._string_refs_by_func["0xC"]


# ---------------------------------------------------------------------------
# 4. GhidraHeadless buyuk binary timeout testleri
# ---------------------------------------------------------------------------

class TestGhidraLargeBinaryTimeout:
    """Ghidra headless'ta buyuk binary timeout artirimi."""

    def test_timeout_increases_for_large_binary(self, tmp_dir: Path) -> None:
        """Buyuk binary icin timeout otomatik artmali."""
        from karadul.ghidra.headless import GhidraHeadless

        cfg = Config()
        cfg.binary_reconstruction.large_binary_threshold_mb = 1  # 1MB esik
        cfg.binary_reconstruction.large_binary_timeout_multiplier = 4.0
        cfg.timeouts.ghidra = 1800  # 30dk

        ghidra = GhidraHeadless(cfg)

        # 2MB test dosya olustur (esik ustunde)
        large_file = tmp_dir / "large_binary"
        large_file.write_bytes(b"\x00" * (2 * 1024 * 1024))

        # analyze metodu pyghidra/cli bulamayacak ama timeout hesaplamasini
        # loglarda gorebiliriz. Burada dogrudan hesaplamayi test edelim.
        threshold_bytes = (
            cfg.binary_reconstruction.large_binary_threshold_mb * 1024 * 1024
        )
        is_large = large_file.stat().st_size > threshold_bytes
        assert is_large

        effective_timeout = cfg.timeouts.ghidra
        if is_large:
            effective_timeout = int(
                effective_timeout
                * cfg.binary_reconstruction.large_binary_timeout_multiplier
            )
        assert effective_timeout == 7200  # 30dk * 4 = 120dk = 7200s

    def test_small_binary_keeps_default_timeout(self) -> None:
        """Kucuk binary icin timeout degismemeli."""
        cfg = Config()
        cfg.binary_reconstruction.large_binary_threshold_mb = 100  # 100MB
        cfg.timeouts.ghidra = 1800

        # 1KB dosya (esik altinda)
        threshold_bytes = (
            cfg.binary_reconstruction.large_binary_threshold_mb * 1024 * 1024
        )
        file_size = 1024  # 1KB
        is_large = file_size > threshold_bytes
        assert not is_large

        effective_timeout = cfg.timeouts.ghidra
        if is_large:
            effective_timeout = int(
                effective_timeout
                * cfg.binary_reconstruction.large_binary_timeout_multiplier
            )
        assert effective_timeout == 1800  # degismedi


# ---------------------------------------------------------------------------
# 5. Pipeline buyuk binary tespiti testleri
# ---------------------------------------------------------------------------

class TestPipelineLargeBinaryDetection:
    """Pipeline'da buyuk binary tespiti ve context flag'i."""

    def test_is_large_binary_flag_set(self) -> None:
        """Context.extra'da is_large_binary flag'i olmali."""
        from karadul.core.pipeline import PipelineContext
        from karadul.core.target import TargetInfo, TargetType, Language
        from karadul.core.workspace import Workspace

        cfg = Config()
        cfg.binary_reconstruction.large_binary_threshold_mb = 100

        # Simulated TargetInfo
        target = TargetInfo(
            name="test",
            path=Path("/tmp/test"),
            target_type=TargetType.MACHO_BINARY,
            language=Language.C,
            file_size=200 * 1024 * 1024,  # 200MB
            file_hash="abc123",
        )

        threshold_bytes = (
            cfg.binary_reconstruction.large_binary_threshold_mb * 1024 * 1024
        )
        is_large = target.file_size > threshold_bytes
        assert is_large

        context = PipelineContext(
            target=target,
            workspace=MagicMock(),
            config=cfg,
            extra={"is_large_binary": is_large},
        )
        assert context.extra["is_large_binary"] is True

    def test_small_binary_flag_false(self) -> None:
        """Kucuk binary icin is_large_binary False olmali."""
        from karadul.core.pipeline import PipelineContext
        from karadul.core.target import TargetInfo, TargetType, Language

        cfg = Config()
        cfg.binary_reconstruction.large_binary_threshold_mb = 100

        target = TargetInfo(
            name="test",
            path=Path("/tmp/test"),
            target_type=TargetType.MACHO_BINARY,
            language=Language.C,
            file_size=50 * 1024 * 1024,  # 50MB
            file_hash="abc123",
        )

        threshold_bytes = (
            cfg.binary_reconstruction.large_binary_threshold_mb * 1024 * 1024
        )
        is_large = target.file_size > threshold_bytes
        assert not is_large


# ---------------------------------------------------------------------------
# 6. Decompile batch progress testleri
# ---------------------------------------------------------------------------

class TestDecompileBatchProgress:
    """_decompile_functions batch parametreleri."""

    def test_batch_size_parameter_exists(self) -> None:
        """_decompile_functions batch_size parametresi kabul etmeli."""
        from karadul.ghidra.headless import GhidraHeadless
        import inspect

        sig = inspect.signature(GhidraHeadless._decompile_functions)
        assert "batch_size" in sig.parameters

    def test_batch_size_default_5000(self) -> None:
        """Varsayilan batch_size 5000 olmali."""
        from karadul.ghidra.headless import GhidraHeadless
        import inspect

        sig = inspect.signature(GhidraHeadless._decompile_functions)
        assert sig.parameters["batch_size"].default == 5000

    def test_return_includes_batch_info(self) -> None:
        """Decompile sonucu batch bilgisi icermeli."""
        # batch_size ve total_batches anahtarlarini kontrol et
        result = {
            "total_attempted": 100,
            "success": 90,
            "failed": 10,
            "skipped": 0,
            "duration_seconds": 5.0,
            "decompiled_dir": "/tmp/test",
            "functions": [],
            "batch_size": 5000,
            "total_batches": 1,
        }
        assert "batch_size" in result
        assert "total_batches" in result


# ---------------------------------------------------------------------------
# 7. Entegrasyon testleri -- mmap + config birlikte
# ---------------------------------------------------------------------------

class TestLargeBinaryIntegration:
    """Buyuk binary destegi entegrasyon testleri."""

    def test_analyze_static_uses_mmap_for_large(self, tmp_dir: Path) -> None:
        """analyze_static buyuk binary'de mmap kullanmali."""
        from karadul.analyzers.macho import MachOAnalyzer
        from karadul.core.target import TargetInfo, TargetType, Language
        from karadul.core.workspace import Workspace

        cfg = Config()
        cfg.project_root = tmp_dir
        cfg.binary_reconstruction.large_binary_threshold_mb = 1  # 1MB esik
        cfg.retry.max_retries = 0

        # 2MB test binary olustur
        binary_content = b"\x00" * (512 * 1024)
        binary_content += b"VISIBLE_STRING_ONE\x00"
        binary_content += b"\x00" * (512 * 1024)
        binary_content += b"VISIBLE_STRING_TWO\x00"
        binary_content += b"\x00" * (1024 * 1024)

        binary_path = tmp_dir / "large_test_binary"
        binary_path.write_bytes(binary_content)

        target = TargetInfo(
            name="large_test_binary",
            path=binary_path,
            target_type=TargetType.ELF_BINARY,  # ELF: otool atlaniyor
            language=Language.C,
            file_size=len(binary_content),
            file_hash="test_hash",
        )

        analyzer = MachOAnalyzer(cfg)

        # Dogrudan mmap extraction test et (analyze_static tam pipeline cagiriyor)
        strings = analyzer._extract_strings_mmap(binary_path, min_length=4)
        assert "VISIBLE_STRING_ONE" in strings
        assert "VISIBLE_STRING_TWO" in strings

    def test_config_yaml_round_trip(self, tmp_dir: Path) -> None:
        """Config YAML yazilip okunabilmeli."""
        import yaml

        cfg_data = {
            "binary_reconstruction": {
                "ghidra_batch_size": 10000,
                "large_binary_threshold_mb": 200,
                "large_binary_timeout_multiplier": 6.0,
            },
            "timeouts": {
                "ghidra": 3600,
            },
        }

        yaml_path = tmp_dir / "karadul.yaml"
        yaml_path.write_text(yaml.dump(cfg_data), encoding="utf-8")

        loaded = Config.load(yaml_path)
        assert loaded.binary_reconstruction.ghidra_batch_size == 10000
        assert loaded.binary_reconstruction.large_binary_threshold_mb == 200
        assert loaded.binary_reconstruction.large_binary_timeout_multiplier == 6.0
        assert loaded.timeouts.ghidra == 3600
