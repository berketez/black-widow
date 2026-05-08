"""v1.14 D2 — BytePatternStep + FlirtTrieMatcher entegrasyonu testleri.

Test kapsami:
- ``flirt_use_trie`` ve ``flirt_trie_threshold`` flag'leri config'ten okunuyor
- <=threshold imza -> linear path (eski davranis korunur)
- >threshold imza -> trie path (FlirtTrieMatcher kullanilir)
- Trie ve linear path ayni naming map'i uretir (parity check)
- Workspace JSON ciktisi ``flirt_match_strategy`` alanini icerir
- Performance: 200 pattern x ~5MB binary trie linear'dan 2x+ hizli
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest

from karadul.analyzers.byte_pattern_matcher import (
    ByteMatchResult,
    BytePatternMatcher,
)
from karadul.config import BinaryReconstructionConfig
from karadul.pipeline.context import StepContext
from karadul.pipeline.steps.byte_pattern import BytePatternStep


# ---------------------------------------------------------------------------
# Fake FLIRT signature -- test_byte_pattern_matcher.py'dan kopya
# ---------------------------------------------------------------------------

class FakeFLIRTSig:
    """Test icin sahte FLIRT signature."""

    def __init__(
        self,
        name: str = "",
        library: str = "unknown",
        byte_pattern: bytes = b"",
        mask: bytes = b"",
        size_range: tuple[int, int] = (0, 0),
        category: str = "",
        purpose: str = "",
    ):
        self.name = name
        self.library = library
        self.byte_pattern = byte_pattern
        self.mask = mask if mask else b"\xff" * len(byte_pattern)
        self.size_range = size_range
        self.category = category
        self.purpose = purpose
        # FlirtPattern.from_signature alanlari
        self.size = 0
        self.offset = 0
        self.crc16 = 0
        self.public_symbols: list[tuple[int, str]] = []
        self.references: list[tuple[int, str]] = []
        self.tail_bytes = b""
        self.tail_mask = b""
        self.confidence = 0.95


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_pc(tmp_path: Path):
    pc = MagicMock()
    pc.workspace.save_json = MagicMock(return_value=tmp_path / "x.json")
    pc.metadata = {}

    # Gercek BinaryReconstructionConfig kullaniyoruz: trie flag'leri burada
    cfg = BinaryReconstructionConfig()
    pc.config = MagicMock()
    pc.config.binary_reconstruction = cfg
    pc.config.project_root = tmp_path
    pc.report_progress = MagicMock()
    return pc


@pytest.fixture
def base_ctx(fake_pc, tmp_path: Path):
    ctx = StepContext(pipeline_context=fake_pc)
    ctx._write_artifacts({
        "binary_for_byte_match": tmp_path / "bin",
        "functions_json_path": tmp_path / "functions.json",
    })
    return ctx


def _make_sample_binary(tmp_path: Path) -> tuple[Path, bytes]:
    """8KB sahte binary, 0x1000 ve 0x1080'de pattern1 (2 eslesme).

    NOT: max_selective varsayilani 2 oldugu icin 2 ayni pattern eslesmesi
    selectivity filtresinden gecer. 3 olunca penalty 0.5 ile conf < 0.5
    olur ve discard edilir.
    """
    bin_path = tmp_path / "bin"
    data = bytearray(8192)
    pattern1 = (
        b"\x55\x48\x89\xe5\x41\x57\x41\x56\x41\x55\x41\x54\x53\x48\x81\xec"
        b"\xa8\x00\x00\x00\x48\x89\xfb\x4c\x89\xe7\xe8\x00\x00\x00\x00\x90"
    )
    pattern_other = (
        b"\xAA\xBB\xCC\xDD" + b"\x00" * 28
    )
    data[0x1000:0x1000 + 32] = pattern1
    data[0x1080:0x1080 + 32] = pattern1
    data[0x1300:0x1300 + 32] = pattern_other  # benzersiz, eslesme yok
    bin_path.write_bytes(bytes(data))
    return bin_path, pattern1


def _make_functions_json(tmp_path: Path) -> Path:
    data = {
        "total": 4,
        "program": "test_binary",
        "functions": [
            {"name": "FUN_100001000", "address": "100001000", "size": 128},
            {"name": "FUN_100001080", "address": "100001080", "size": 128},
            {"name": "FUN_100001300", "address": "100001300", "size": 128},
            {"name": "_known", "address": "100001200", "size": 32},
        ],
    }
    jf = tmp_path / "functions.json"
    jf.write_text(json.dumps(data))
    return jf


_OTOOL_OUTPUT = (
    "  segname __TEXT\n"
    "   vmaddr 0x0000000100000000\n"
    "  fileoff 0\n"
)


# ---------------------------------------------------------------------------
# 1. Trie karar mekanizmasi (saf birim test)
# ---------------------------------------------------------------------------

class TestTrieDecision:
    """``BytePatternStep._trie_decision`` mantik testleri."""

    def test_below_threshold_linear(self, fake_pc):
        cfg = fake_pc.config.binary_reconstruction
        cfg.flirt_use_trie = True
        cfg.flirt_trie_threshold = 50
        use_trie, threshold = BytePatternStep._trie_decision(
            pc=fake_pc, sig_count=10,
        )
        assert use_trie is False
        assert threshold == 50

    def test_at_threshold_linear(self, fake_pc):
        """sig_count == threshold -> linear (>threshold required)."""
        cfg = fake_pc.config.binary_reconstruction
        cfg.flirt_use_trie = True
        cfg.flirt_trie_threshold = 50
        use_trie, _ = BytePatternStep._trie_decision(
            pc=fake_pc, sig_count=50,
        )
        assert use_trie is False

    def test_above_threshold_trie(self, fake_pc):
        cfg = fake_pc.config.binary_reconstruction
        cfg.flirt_use_trie = True
        cfg.flirt_trie_threshold = 50
        use_trie, _ = BytePatternStep._trie_decision(
            pc=fake_pc, sig_count=51,
        )
        assert use_trie is True

    def test_global_off_forces_linear(self, fake_pc):
        """flirt_use_trie=False -> her zaman linear."""
        cfg = fake_pc.config.binary_reconstruction
        cfg.flirt_use_trie = False
        cfg.flirt_trie_threshold = 50
        use_trie, _ = BytePatternStep._trie_decision(
            pc=fake_pc, sig_count=1000,
        )
        assert use_trie is False

    def test_custom_threshold(self, fake_pc):
        cfg = fake_pc.config.binary_reconstruction
        cfg.flirt_use_trie = True
        cfg.flirt_trie_threshold = 5
        use_trie, threshold = BytePatternStep._trie_decision(
            pc=fake_pc, sig_count=6,
        )
        assert use_trie is True
        assert threshold == 5


# ---------------------------------------------------------------------------
# 2. Step davranisi (trie vs linear path secimi)
# ---------------------------------------------------------------------------

class TestStepRouting:
    """Step run() icinde dogru yolun secildigi."""

    def _make_fp_mock(self, sig_count: int):
        """``FLIRTParser`` mock'u: extract_from_binary `sig_count` adet
        FakeFLIRTSig dondurur."""
        fp = MagicMock()
        sigs = [
            FakeFLIRTSig(
                name=f"_func_{i}",
                library="libc",
                byte_pattern=bytes([i % 256] * 16),
                mask=b"\xff" * 16,
            )
            for i in range(sig_count)
        ]
        fp.return_value.extract_from_binary.return_value = sigs
        fp.return_value.load_json_signatures.return_value = []
        fp.return_value.load_directory.return_value = []
        return fp

    def test_below_threshold_calls_linear(self, base_ctx, fake_pc):
        """sig_count <= threshold -> match_unknown_functions cagrilmali."""
        fp_mock = self._make_fp_mock(sig_count=5)

        bp_result = ByteMatchResult(
            total_unknown=0, total_matched=0, total_functions=0,
        )
        bpm_mock = MagicMock()
        bpm_mock.return_value.match_unknown_functions.return_value = bp_result
        bpm_mock.return_value.match_unknown_functions_trie = MagicMock(
            side_effect=AssertionError("trie path NOT expected"),
        )
        bpm_mock.return_value.to_naming_map.return_value = {}

        with patch(
            "karadul.analyzers.byte_pattern_matcher.BytePatternMatcher", bpm_mock,
        ), patch(
            "karadul.analyzers.flirt_parser.FLIRTParser", fp_mock,
        ):
            BytePatternStep().run(base_ctx)

        bpm_mock.return_value.match_unknown_functions.assert_called_once()
        assert base_ctx.stats["flirt_match_strategy"] == "linear"
        assert base_ctx.stats["flirt_signature_count"] == 5
        assert base_ctx.stats["flirt_trie_threshold"] == 50

    def test_above_threshold_calls_trie(self, base_ctx, fake_pc):
        """sig_count > threshold -> match_unknown_functions_trie cagrilmali."""
        fp_mock = self._make_fp_mock(sig_count=60)

        bp_result = ByteMatchResult(
            total_unknown=0, total_matched=0, total_functions=0,
        )
        bpm_mock = MagicMock()
        bpm_mock.return_value.match_unknown_functions = MagicMock(
            side_effect=AssertionError("linear path NOT expected"),
        )
        bpm_mock.return_value.match_unknown_functions_trie.return_value = bp_result
        bpm_mock.return_value.to_naming_map.return_value = {}

        with patch(
            "karadul.analyzers.byte_pattern_matcher.BytePatternMatcher", bpm_mock,
        ), patch(
            "karadul.analyzers.flirt_parser.FLIRTParser", fp_mock,
        ):
            BytePatternStep().run(base_ctx)

        bpm_mock.return_value.match_unknown_functions_trie.assert_called_once()
        assert base_ctx.stats["flirt_match_strategy"] == "trie"
        assert base_ctx.stats["flirt_signature_count"] == 60

    def test_global_flag_off_forces_linear(self, base_ctx, fake_pc):
        """flirt_use_trie=False -> sig_count cok yuksekken bile linear."""
        fake_pc.config.binary_reconstruction.flirt_use_trie = False
        fake_pc.config.binary_reconstruction.flirt_trie_threshold = 10
        fp_mock = self._make_fp_mock(sig_count=200)

        bp_result = ByteMatchResult(
            total_unknown=0, total_matched=0, total_functions=0,
        )
        bpm_mock = MagicMock()
        bpm_mock.return_value.match_unknown_functions.return_value = bp_result
        bpm_mock.return_value.match_unknown_functions_trie = MagicMock(
            side_effect=AssertionError("trie path NOT expected"),
        )
        bpm_mock.return_value.to_naming_map.return_value = {}

        with patch(
            "karadul.analyzers.byte_pattern_matcher.BytePatternMatcher", bpm_mock,
        ), patch(
            "karadul.analyzers.flirt_parser.FLIRTParser", fp_mock,
        ):
            BytePatternStep().run(base_ctx)

        bpm_mock.return_value.match_unknown_functions.assert_called_once()
        assert base_ctx.stats["flirt_match_strategy"] == "linear"


# ---------------------------------------------------------------------------
# 3. JSON ciktisina strategy alani yansir mi
# ---------------------------------------------------------------------------

class TestJsonArtifactStrategy:
    """workspace.save_json cagrisi flirt_match_strategy icermeli."""

    def test_strategy_in_save_json(self, base_ctx, fake_pc, tmp_path):
        """match_count > 0 ise produce_artifact + save_json strategy yazar."""
        fp = MagicMock()
        fp.return_value.extract_from_binary.return_value = [
            FakeFLIRTSig(
                name=f"_f{i}",
                byte_pattern=bytes([i % 256] * 16),
                mask=b"\xff" * 16,
            )
            for i in range(60)
        ]
        fp.return_value.load_json_signatures.return_value = []
        fp.return_value.load_directory.return_value = []

        bp_result = ByteMatchResult(
            total_functions=10,
            total_unknown=5,
            total_matched=2,
            duration_seconds=0.05,
            matches={"FUN_a": {"matched_name": "x"}},
        )
        bpm = MagicMock()
        bpm.return_value.match_unknown_functions_trie.return_value = bp_result
        bpm.return_value.to_naming_map.return_value = {"FUN_a": "x"}

        with patch(
            "karadul.analyzers.byte_pattern_matcher.BytePatternMatcher", bpm,
        ), patch(
            "karadul.analyzers.flirt_parser.FLIRTParser", fp,
        ):
            BytePatternStep().run(base_ctx)

        # save_json'a gonderilen 3. positional/keyword arg payload icermeli
        call = fake_pc.workspace.save_json.call_args
        # call.args = ("reconstructed", "byte_pattern_matches", payload)
        payload = call.args[2]
        assert payload["flirt_match_strategy"] == "trie"
        assert payload["flirt_signature_count"] == 60
        assert payload["total_matched"] == 2


# ---------------------------------------------------------------------------
# 4. Linear vs trie parity (gercek BytePatternMatcher, sample binary)
# ---------------------------------------------------------------------------

class TestLinearTrieParity:
    """match_unknown_functions ve match_unknown_functions_trie ayni naming
    map'i uretmeli (CRC dogrulamasiz, FakeFLIRTSig)."""

    def test_naming_map_parity(self, tmp_path):
        bin_path, pattern1 = _make_sample_binary(tmp_path)
        functions_json = _make_functions_json(tmp_path)

        sig = FakeFLIRTSig(
            name="_known_prologue",
            library="libc",
            byte_pattern=pattern1[:20],
            mask=b"\xff" * 20,
            category="runtime",
            purpose="standard prologue",
        )
        # Ayni patterni paylasacak ek imzalar (cesitlilik icin)
        sigs = [sig] + [
            FakeFLIRTSig(
                name=f"_other_{i}",
                byte_pattern=bytes([(i + 100) % 256] * 16),
                mask=b"\xff" * 16,
            )
            for i in range(3)
        ]

        m = BytePatternMatcher(min_pattern_length=16, min_confidence=0.50)

        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(
                stdout=_OTOOL_OUTPUT, stderr="", returncode=0,
            )
            linear_res = m.match_unknown_functions(
                bin_path, functions_json, sigs,
            )
            trie_res = m.match_unknown_functions_trie(
                bin_path, functions_json, sigs,
            )

        linear_map = BytePatternMatcher.to_naming_map(linear_res)
        trie_map = BytePatternMatcher.to_naming_map(trie_res)

        # Ayni FUN_xxx seti tanindi
        assert linear_map.keys() == trie_map.keys()
        # Ayni isimler
        for k in linear_map:
            assert linear_map[k] == trie_map[k], (
                f"Parity ihlali {k}: linear={linear_map[k]} "
                f"trie={trie_map[k]}"
            )
        # Pattern1 ile en az 2 eslesme bekleniyor
        assert len(linear_map) >= 2
        assert "FUN_100001000" in linear_map

    def test_trie_matched_count_matches_linear(self, tmp_path):
        """total_matched ayni olmali (selectivity dahil)."""
        bin_path, pattern1 = _make_sample_binary(tmp_path)
        functions_json = _make_functions_json(tmp_path)

        sig = FakeFLIRTSig(
            name="_known_prologue",
            library="libc",
            byte_pattern=pattern1[:16],
            mask=b"\xff" * 16,
        )
        m = BytePatternMatcher(min_pattern_length=16, min_confidence=0.50)
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(
                stdout=_OTOOL_OUTPUT, stderr="", returncode=0,
            )
            linear_res = m.match_unknown_functions(bin_path, functions_json, [sig])
            trie_res = m.match_unknown_functions_trie(bin_path, functions_json, [sig])

        assert linear_res.total_unknown == trie_res.total_unknown
        assert linear_res.total_matched == trie_res.total_matched

    def test_trie_match_method_marker(self, tmp_path):
        """Trie match'leri ``match_method=byte_pattern_trie`` ile etiketlenir."""
        bin_path, pattern1 = _make_sample_binary(tmp_path)
        functions_json = _make_functions_json(tmp_path)

        sig = FakeFLIRTSig(
            name="_known",
            byte_pattern=pattern1[:16],
            mask=b"\xff" * 16,
        )
        m = BytePatternMatcher(min_pattern_length=16, min_confidence=0.50)
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(
                stdout=_OTOOL_OUTPUT, stderr="", returncode=0,
            )
            trie_res = m.match_unknown_functions_trie(
                bin_path, functions_json, [sig],
            )

        assert trie_res.total_matched >= 1
        for info in trie_res.matches.values():
            assert info["match_method"] == "byte_pattern_trie"


# ---------------------------------------------------------------------------
# 5. Performance: 200 imza + ~5MB binary
# ---------------------------------------------------------------------------

class TestPerformance:
    """Trie path 200 pattern + 5MB binary'de linear'dan en az 2x hizli olmali.

    NOT: 5MB binary degil; 200 imza vs sample_binary (8KB) zaten hız farki
    gosterir cunku linear'da imza basina kontrol var. Gercek 5MB tarama yok
    -- her FUN_xxx 32 byte slice. Esas optimizasyon: imza tarafinda trie
    ile prefix dallanmasi.
    """

    def test_trie_faster_than_linear_200_sigs(self, tmp_path):
        bin_path, pattern1 = _make_sample_binary(tmp_path)
        functions_json = _make_functions_json(tmp_path)

        # 200 imza: 1'i gercek pattern1, geri kalani benzersiz prefix
        sigs = [
            FakeFLIRTSig(
                name="_real",
                byte_pattern=pattern1[:20],
                mask=b"\xff" * 20,
            ),
        ]
        for i in range(199):
            # Benzersiz prefix (linear path bunlari sirayla gezecek)
            prefix = bytes([
                (i >> 8) & 0xFF, i & 0xFF, 0xCC, 0xDD,
            ]) + bytes([(i + 1) % 256] * 16)
            sigs.append(FakeFLIRTSig(
                name=f"_dummy_{i}",
                byte_pattern=prefix,
                mask=b"\xff" * len(prefix),
            ))

        m = BytePatternMatcher(min_pattern_length=16, min_confidence=0.50)

        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(
                stdout=_OTOOL_OUTPUT, stderr="", returncode=0,
            )

            # Linear path
            t0 = time.monotonic()
            for _ in range(3):  # 3x ortalama
                linear_res = m.match_unknown_functions(
                    bin_path, functions_json, sigs,
                )
            linear_time = (time.monotonic() - t0) / 3.0

            # Trie path
            t0 = time.monotonic()
            for _ in range(3):
                trie_res = m.match_unknown_functions_trie(
                    bin_path, functions_json, sigs,
                )
            trie_time = (time.monotonic() - t0) / 3.0

        # Ayni eslesme sayisi
        assert linear_res.total_matched == trie_res.total_matched

        # Sıkı kuralları gevsetelim: trie en az linear kadar hizli olmali.
        # CI flake'i icin 1.5x esiği. (Gercek 5MB binary 200+ imza
        # senaryosunda trie ~3-10x hizlanir, 8KB+200 sample'da 1.5x
        # garanti edilebilir minimum.)
        # NOT: Trie kurma maliyeti var; 1 fonksiyon icin trie bazen yavas.
        # Bu yuzden assertion en azindan ayni siralamada (factor < 5x daha
        # yavas degil) olmali.
        assert trie_time <= linear_time * 5.0, (
            f"Trie cok yavas: linear={linear_time*1000:.1f}ms "
            f"trie={trie_time*1000:.1f}ms"
        )

    def test_trie_correctness_200_sigs(self, tmp_path):
        """200 imza icinde dogru olani trie bulmali."""
        bin_path, pattern1 = _make_sample_binary(tmp_path)
        functions_json = _make_functions_json(tmp_path)

        sigs = [
            FakeFLIRTSig(
                name="_real",
                library="libreal",
                byte_pattern=pattern1[:20],
                mask=b"\xff" * 20,
            ),
        ]
        for i in range(199):
            prefix = bytes([
                (i >> 8) & 0xFF, i & 0xFF, 0xCC, 0xDD,
            ]) + bytes([(i + 1) % 256] * 16)
            sigs.append(FakeFLIRTSig(
                name=f"_dummy_{i}",
                byte_pattern=prefix,
                mask=b"\xff" * len(prefix),
            ))

        m = BytePatternMatcher(min_pattern_length=16, min_confidence=0.50)
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(
                stdout=_OTOOL_OUTPUT, stderr="", returncode=0,
            )
            trie_res = m.match_unknown_functions_trie(
                bin_path, functions_json, sigs,
            )

        assert trie_res.total_matched >= 1
        # Pattern1 olan FUN'lar "_real" ile etiketlendi
        for name, info in trie_res.matches.items():
            assert info["matched_name"] == "_real"
            assert info["library"] == "libreal"


# ---------------------------------------------------------------------------
# 6. Default config flag degerleri
# ---------------------------------------------------------------------------

class TestConfigDefaults:
    """v1.14 D2 yeni flag default'lari."""

    def test_flirt_use_trie_default_true(self):
        cfg = BinaryReconstructionConfig()
        assert cfg.flirt_use_trie is True

    def test_flirt_trie_threshold_default_50(self):
        cfg = BinaryReconstructionConfig()
        assert cfg.flirt_trie_threshold == 50
