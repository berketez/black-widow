"""FLIRT yükleme bug'ı regresyon testleri (2026-09-25).

Gerçek coreutils cat analizinde ölçülen üç katman:

  1. ``karadul analyze --output-dir X`` ``Config.project_root``'u X yapar;
     FLIRT imzaları yalnız project_root altında aranır, bulunmaz.
     BİLİNÇLİ BEKLETİLİYOR: imza DB'si seçici değil (redis-server'da 162
     FLIRT ismi, 0 doğru). Bu dosya yalnız bu durumda sayaçların dürüst
     (0) yazıldığını kilitler.
  2. Sayaç StaticAnalysisStage'de yazılıyordu ve eşleşmeye hiç girmeyen,
     bayt deseni olmayan 2,46M isim imzasını sayıyordu. Artık FLIRT yalnız
     byte_pattern adımında yüklenir ve sayılır; sayaçlar 0 dahil hep yazılır.
  3. PIE ELF'te Ghidra adresleri image base (0x100000) kadar kayık; matcher
     dosya ofsetini kaymasız hesapladığı için HİÇBİR FUN_xxx taranmıyordu
     (cat: 22 FUN_, 0 taranan).

Her test 2. ya da 3. katmandan birini korur; ilgili düzeltme geri alınırsa
test patlar (mutation kanıtı raporda).
"""

from __future__ import annotations

import json
import struct
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from karadul.analyzers.byte_pattern_matcher import BytePatternMatcher
from karadul.analyzers.flirt_parser import FLIRTParser, FLIRTSignature
from karadul.config import BinaryReconstructionConfig, Config
from karadul.core.result import StageResult
from karadul.core.target import TargetType
from karadul.pipeline.context import StepContext
from karadul.pipeline.steps.byte_pattern import BytePatternStep

# 32 baytlık, birbirinden farklı iki imza deseni (homebrew_bytes biçiminde 32 bayt).
PATTERN = bytes(range(0x40, 0x60))
OTHER_PATTERN = bytes(range(0xA0, 0xC0))
CODE_OFFSET = 0x1000          # desenin dosyadaki yeri
GHIDRA_PIE_BASE = 0x100000    # Ghidra'nın aarch64/x86-64 PIE için seçtiği image base
BYTES_FILE = "signatures_homebrew_bytes.json"


# ---------------------------------------------------------------------------
# Yardımcılar
# ---------------------------------------------------------------------------

def _make_elf64(path: Path, *, e_type: int, load_vaddr: int, size: int = 0x2000) -> Path:
    """Minimal ELF64 LE (aarch64): tek PT_LOAD (R+X), dosya ofseti 0 -> load_vaddr.

    e_type: 2 = ET_EXEC, 3 = ET_DYN (PIE).
    """
    data = bytearray(size)
    data[0:4] = b"\x7fELF"
    data[4] = 2   # ELFCLASS64
    data[5] = 1   # little endian
    data[6] = 1   # EV_CURRENT
    e_phoff = 64
    struct.pack_into(
        "<HHIQQQIHHHHHH", data, 16,
        e_type, 0xB7, 1, load_vaddr + CODE_OFFSET, e_phoff, 0, 0,
        64, 56, 1, 64, 0, 0,
    )
    # PT_LOAD, PF_R|PF_X, offset 0, vaddr, paddr, filesz, memsz, align
    struct.pack_into(
        "<IIQQQQQQ", data, e_phoff,
        1, 5, 0, load_vaddr, load_vaddr, size, size, 0x1000,
    )
    data[CODE_OFFSET:CODE_OFFSET + len(PATTERN)] = PATTERN
    path.write_bytes(bytes(data))
    return path


def _make_functions_json(path: Path, ghidra_addr: int) -> Path:
    """Ghidra functions.json: bir FUN_xxx (desenin yeri) + bir isimli fonksiyon."""
    path.write_text(json.dumps({
        "total": 2,
        "program": "synthetic",
        "functions": [
            {"name": f"FUN_{ghidra_addr:08x}", "address": f"{ghidra_addr:08x}", "size": 64},
            {"name": "main", "address": f"{ghidra_addr + 0x100:08x}", "size": 32},
        ],
    }))
    return path


def _write_bytes_sigs(root: Path, entries: list[tuple[str, bytes]]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    f = root / BYTES_FILE
    f.write_text(json.dumps({
        "signatures": [
            {"name": n, "library": "zstd", "confidence": 0.9, "byte_pattern": p.hex()}
            for n, p in entries
        ],
        "total": len(entries),
    }))
    return f


def _sig(name: str, pattern: bytes) -> FLIRTSignature:
    return FLIRTSignature(name=name, library="zstd", byte_pattern=pattern, mask=b"\xff" * len(pattern))


@pytest.fixture
def no_binary_symbols(monkeypatch: pytest.MonkeyPatch) -> None:
    """nm bağımlılığını kaldır: hedef binary'den sembol çıkmaz (stripped)."""
    monkeypatch.setattr(FLIRTParser, "extract_from_binary", lambda self, *a, **k: [])


def _step_ctx(
    tmp_path: Path, *, project_root: Path, binary: Path, functions_json: Path,
    static_dir: Path, trie_threshold: int = 50,
) -> StepContext:
    cfg = BinaryReconstructionConfig()
    cfg.flirt_trie_threshold = trie_threshold
    pc = MagicMock()
    pc.config = MagicMock()
    pc.config.project_root = project_root
    pc.config.binary_reconstruction = cfg
    pc.metadata = {}
    pc.report_progress = MagicMock()
    pc.workspace.save_json = MagicMock(return_value=tmp_path / "bp.json")
    pc.workspace.get_stage_dir = MagicMock(
        side_effect=lambda name: static_dir if name == "static" else tmp_path / name,
    )
    ctx = StepContext(pipeline_context=pc)
    ctx._write_artifacts({
        "binary_for_byte_match": binary,
        "functions_json_path": functions_json,
    })
    return ctx


def _write_ghidra_image_base(static_dir: Path, image_base: int) -> None:
    static_dir.mkdir(parents=True, exist_ok=True)
    (static_dir / "ghidra_combined_results.json").write_text(
        json.dumps({"program_info": {"image_base": f"{image_base:08x}"}}))


# ---------------------------------------------------------------------------
# 1. Sayaçlar: FLIRT yalnız byte_pattern adımında yüklenir ve sayılır
# ---------------------------------------------------------------------------

class _FakeAnalyzer:
    def __init__(self, config: object) -> None:
        pass

    def analyze_static(self, target: object, workspace: object) -> StageResult:
        return StageResult(stage_name="static", success=True, duration_seconds=0.0)


class _NoYara:
    def load_builtin_rules(self) -> None:
        pass

    def scan_file(self, path: object) -> SimpleNamespace:
        return SimpleNamespace(matches=[])


class TestCounterSingleSource:
    def test_static_stage_does_not_load_or_count_flirt(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Statik aşama isim imzalarını (bayt deseni YOK) artık yüklemez ve saymaz."""
        import karadul.stages as stages_mod

        proj = tmp_path / "proj"
        (proj / "sigs").mkdir(parents=True)
        # Eski bloğun yükleyeceği isim tabanlı kaynaklar (bayt deseni yok)
        (proj / "signatures_homebrew.json").write_text(
            json.dumps({"signatures": [{"name": "_a", "library": "x"}]}))
        (proj / "sigs" / "names.json").write_text(
            json.dumps({"signatures": [{"name": "_b", "library": "y"}]}))

        calls: list[str] = []
        monkeypatch.setattr(FLIRTParser, "load_json_signatures",
                            lambda self, p: calls.append(f"json:{p}") or [])
        monkeypatch.setattr(FLIRTParser, "load_directory",
                            lambda self, p: calls.append(f"dir:{p}") or [])
        monkeypatch.setattr(stages_mod, "get_analyzer", lambda tt: _FakeAnalyzer)
        monkeypatch.setattr("karadul.analyzers.yara_scanner.YaraScanner", _NoYara)

        cfg = Config()
        cfg.project_root = proj
        cfg.binary_reconstruction.enable_capa = False
        context = MagicMock()
        context.config = cfg
        context.target.target_type = TargetType.ELF_BINARY
        context.target.path = _make_elf64(tmp_path / "bin", e_type=3, load_vaddr=0)

        result = stages_mod.StaticAnalysisStage().execute(context)

        assert result.success
        assert calls == []
        assert not [k for k in result.stats if k.startswith("flirt_")]

    def test_output_dir_project_root_keeps_flirt_off_with_zero_counters(
        self, tmp_path: Path, no_binary_symbols: None,
    ) -> None:
        """--output-dir durumu: project_root'ta imza yok -> FLIRT kapalı, sayaçlar 0 ve mevcut.

        FLIRT'ün kapalı kalması HEAD davranışıdır ve bilinçli bekletiliyor
        (imza DB'si seçici değil). Paket köküne düşme gibi bir yol eklenirse
        bu test patlar; o karar ölçüm zemininde verilirse test de güncellenmeli.
        """
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        binary = _make_elf64(tmp_path / "bin", e_type=3, load_vaddr=0)
        fj = _make_functions_json(tmp_path / "functions.json", GHIDRA_PIE_BASE + CODE_OFFSET)
        ctx = _step_ctx(tmp_path, project_root=out_dir, binary=binary,
                        functions_json=fj, static_dir=tmp_path / "static")

        out = BytePatternStep().run(ctx)

        assert ctx.stats["flirt_signatures_loaded"] == 0
        assert ctx.stats["flirt_signature_sources"] == {str(binary): 0}
        assert ctx.stats["flirt_signatures_matchable"] == 0
        assert ctx.stats["flirt_functions_scanned"] == 0
        assert ctx.stats["flirt_functions_named"] == 0
        assert "flirt_match_strategy" not in ctx.stats  # eşleştirici koşmadı
        assert out["byte_pattern_names"] == {}

    @pytest.mark.parametrize("trie_threshold", [0, 50], ids=["trie", "linear"])
    def test_step_counters_reflect_matching(
        self, tmp_path: Path, no_binary_symbols: None, trie_threshold: int,
    ) -> None:
        """İmzalar testin kendi project_root'unda: yüklenen, giren, taranan, isimlenen."""
        proj = tmp_path / "proj"
        sig_file = _write_bytes_sigs(proj, [("_zstd_like_func", PATTERN), ("_other_func", OTHER_PATTERN)])
        static_dir = tmp_path / "static"
        _write_ghidra_image_base(static_dir, GHIDRA_PIE_BASE)
        binary = _make_elf64(tmp_path / "bin", e_type=3, load_vaddr=0)
        fj = _make_functions_json(tmp_path / "functions.json", GHIDRA_PIE_BASE + CODE_OFFSET)
        ctx = _step_ctx(tmp_path, project_root=proj, binary=binary,
                        functions_json=fj, static_dir=static_dir,
                        trie_threshold=trie_threshold)

        out = BytePatternStep().run(ctx)

        assert ctx.stats["flirt_match_strategy"] == ("trie" if trie_threshold == 0 else "linear")
        assert ctx.stats["flirt_signatures_loaded"] == 2
        assert ctx.stats["flirt_signature_sources"] == {str(sig_file): 2, str(binary): 0}
        assert ctx.stats["flirt_signatures_matchable"] == 2
        assert ctx.stats["flirt_functions_scanned"] == 1
        assert ctx.stats["flirt_functions_named"] == 1
        assert out["byte_pattern_names"] == {
            f"FUN_{GHIDRA_PIE_BASE + CODE_OFFSET:08x}": "zstd_like_func",
        }


# ---------------------------------------------------------------------------
# 2. PIE ELF: Ghidra image base kayması geri alınır
# ---------------------------------------------------------------------------

class TestPieLoadBase:
    @pytest.mark.parametrize("method", ["match_unknown_functions", "match_unknown_functions_trie"])
    def test_pie_function_bytes_read_with_ghidra_load_base(self, tmp_path: Path, method: str) -> None:
        binary = _make_elf64(tmp_path / "pie", e_type=3, load_vaddr=0)
        fj = _make_functions_json(tmp_path / "functions.json", GHIDRA_PIE_BASE + CODE_OFFSET)
        sigs = [_sig("_zstd_like_func", PATTERN), _sig("_other_func", OTHER_PATTERN)]
        m = BytePatternMatcher(min_confidence=0.7)

        res = getattr(m, method)(binary, fj, sigs, load_base=GHIDRA_PIE_BASE)

        assert res.total_unknown == 1
        assert res.functions_scanned == 1
        assert res.total_matched == 1
        assert res.matches[f"FUN_{GHIDRA_PIE_BASE + CODE_OFFSET:08x}"]["matched_name"] == "_zstd_like_func"

    def test_pie_without_load_base_scans_nothing(self, tmp_path: Path) -> None:
        """Eski davranışın belgesi: image base bilinmezse PIE'de hiçbir FUN_ taranmaz."""
        binary = _make_elf64(tmp_path / "pie", e_type=3, load_vaddr=0)
        fj = _make_functions_json(tmp_path / "functions.json", GHIDRA_PIE_BASE + CODE_OFFSET)
        res = BytePatternMatcher(min_confidence=0.7).match_unknown_functions_trie(
            binary, fj, [_sig("_zstd_like_func", PATTERN)],
        )
        assert res.total_unknown == 1
        assert res.functions_scanned == 0
        assert res.total_matched == 0

    @pytest.mark.parametrize("load_base", [None, 0x400000])
    def test_et_exec_unchanged(self, tmp_path: Path, load_base: int | None) -> None:
        """ET_EXEC: Ghidra image base == link base -> kayma 0, davranış aynı."""
        binary = _make_elf64(tmp_path / "exec", e_type=2, load_vaddr=0x400000)
        fj = _make_functions_json(tmp_path / "functions.json", 0x400000 + CODE_OFFSET)
        res = BytePatternMatcher(min_confidence=0.7).match_unknown_functions_trie(
            binary, fj, [_sig("_zstd_like_func", PATTERN)], load_base=load_base,
        )
        assert res.functions_scanned == 1
        assert res.total_matched == 1

    def test_step_reads_image_base_from_ghidra_output(self, tmp_path: Path) -> None:
        static_dir = tmp_path / "static"
        (static_dir / "ghidra_output").mkdir(parents=True)
        pc = MagicMock()
        pc.workspace.get_stage_dir = MagicMock(return_value=static_dir)
        fj = tmp_path / "deobfuscated" / "ghidra_functions.json"

        assert BytePatternStep._ghidra_load_base(pc=pc, functions_json=fj) is None

        _write_ghidra_image_base(static_dir, GHIDRA_PIE_BASE)
        assert BytePatternStep._ghidra_load_base(pc=pc, functions_json=fj) == GHIDRA_PIE_BASE
