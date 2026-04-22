"""stages.py ``_execute_binary`` split parity testi — Faz 1 iskelet.

**Amac:** v1.12.0'da ``ReconstructionStage._execute_binary`` fonksiyonu
3173 satirdan ~25 satirlik bir koordinatore ayristirilacak (bkz.
``docs/migrations/stages_split_plan.md``). Davranis degisikligi YOK
kuralinin saglandigini dogrulamak icin bu test split'ten **once**
uretilen golden artifact'lari split sonrasi calistirma ciktilariyla
karsilastirir.

**Faz 1 (bu commit) kapsami:**

- Golden fixture (``tests/fixtures/golden/sample_macho/``) yuklenebilir.
- ``ReconstructionContext`` dataclass import edilip insa edilebilir.
- Normalize fonksiyonu temel alanlari kararli sekilde maskeler.
- Henuz SHA256 parity testi calismaz — ``stages.py`` degismedigi icin
  "beklenen pre-state" ile "gercek post-state" zaten ayni, testin anlami
  Faz 2 ile gelir.

**Faz 2'de eklenecek:** gercek ``karadul analyze`` cagirarak split
implementasyonun ciktisini golden ile karsilastirmak. Su anda iskelet
`@pytest.mark.skip` ile saklandi; Faz 2 developer'i ``skip`` kaldiracak.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

GOLDEN_DIR = Path(__file__).parent / "fixtures" / "golden" / "sample_macho"

# Normalize kurallari golden fixture'i olustururken ``build_golden.py``
# scriptinde uygulandi. Buradakiler "canli cikti"yi ayni forma
# getirmek icin kullanilir.
UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
ABS_PATH_RE = re.compile(
    r"(/tmp/[^\s\"',\]\}]+|/Users/[^\s\"',\]\}]+|"
    r"/private/[^\s\"',\]\}]+|/var/folders/[^\s\"',\]\}]+)"
)
TS_KEYS = {
    "timestamp",
    "created_at",
    "updated_at",
    "started_at",
    "completed_at",
    "start_time",
    "end_time",
    "duration",
    "duration_seconds",
    "elapsed",
    "elapsed_seconds",
    "elapsed_ms",
}
PATH_KEYS = {
    "workspace",
    "workspace_dir",
    "binary_path",
    "output_dir",
    "path",
    "source_path",
    "target",
    "abs_path",
}
UUID_KEYS = {"uuid", "session_id", "run_id"}


# ---------------------------------------------------------------------------
# Yardimcilar
# ---------------------------------------------------------------------------


def _load_golden(rel_path: str) -> Any:
    """Golden snapshot oku — dict veya list dondurur."""
    p = GOLDEN_DIR / rel_path
    return json.loads(p.read_text())


def _normalize_output(data: Any) -> Any:
    """Deterministik olmayan alanlari maskele.

    - ``TS_KEYS`` -> ``"<TIMESTAMP>"``
    - ``UUID_KEYS`` -> ``"<UUID>"``
    - ``PATH_KEYS`` -> ``"<RELATIVE_PATH>"``
    - Her string icinde gecen UUID/absolute path regex match'leri
      ayni sekilde maskelenir.
    """
    if isinstance(data, dict):
        out: dict[str, Any] = {}
        for k, v in data.items():
            if k in TS_KEYS:
                out[k] = "<TIMESTAMP>"
            elif k in UUID_KEYS:
                out[k] = "<UUID>"
            elif k in PATH_KEYS and isinstance(v, str):
                out[k] = "<RELATIVE_PATH>"
            else:
                out[k] = _normalize_output(v)
        return out
    if isinstance(data, list):
        return [_normalize_output(v) for v in data]
    if isinstance(data, str):
        s = UUID_RE.sub("<UUID>", data)
        s = ABS_PATH_RE.sub("<RELATIVE_PATH>", s)
        return s
    return data


# ---------------------------------------------------------------------------
# Faz 1 iskelet testleri
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not GOLDEN_DIR.exists(), reason="Golden fixture yok")
def test_golden_fixture_dir_exists() -> None:
    """Golden fixture dizini commit edilmis mi?"""
    assert GOLDEN_DIR.is_dir(), f"Golden dizin eksik: {GOLDEN_DIR}"
    # En azindan metadata + bir static + bir recon dosyasi olmali.
    assert (GOLDEN_DIR / "METADATA.json").exists()
    assert (GOLDEN_DIR / "static").is_dir()
    assert (GOLDEN_DIR / "reconstructed").is_dir()


@pytest.mark.skipif(not GOLDEN_DIR.exists(), reason="Golden fixture yok")
def test_golden_fixture_core_files_present() -> None:
    """Kritik Phase 1 + reconstruction ciktilari mevcut olmali."""
    expected = [
        "static/ghidra_functions.json",
        "static/ghidra_strings.json",
        "static/ghidra_cfg.json",
        "static/ghidra_call_graph.json",
        "static/ghidra_xrefs.json",
        "reconstructed/signature_matches.json",
        "reconstructed/param_naming_map.json",
    ]
    missing = [f for f in expected if not (GOLDEN_DIR / f).exists()]
    assert not missing, f"Golden fixture eksik dosyalar: {missing}"


@pytest.mark.skipif(not GOLDEN_DIR.exists(), reason="Golden fixture yok")
def test_golden_fixture_metadata_parseable() -> None:
    """Metadata JSON parse edilebiliyor ve anlamli alanlar iceriyor."""
    meta = _load_golden("METADATA.json")
    assert isinstance(meta, dict)
    for key in ("description", "created_from", "pipeline_version", "file_count"):
        assert key in meta, f"METADATA.json icinde {key} yok"
    assert meta["file_count"] >= 10, "En az 10 golden dosya beklenirdi"


@pytest.mark.skipif(not GOLDEN_DIR.exists(), reason="Golden fixture yok")
def test_golden_ghidra_functions_structure() -> None:
    """Ghidra functions.json beklenen yapida."""
    data = _load_golden("static/ghidra_functions.json")
    # Karadul bazen {"functions": [...]} bazen dogrudan [...] donduruyor.
    if isinstance(data, dict):
        assert "functions" in data or len(data) > 0, "Bos dict"
    else:
        assert isinstance(data, list), "list ya da dict beklendi"


@pytest.mark.skipif(not GOLDEN_DIR.exists(), reason="Golden fixture yok")
def test_golden_no_absolute_paths_leaked() -> None:
    """Normalize sonrasi hicbir golden dosyada /tmp veya /Users path'i kalmamali."""
    leaked: list[str] = []
    for path in GOLDEN_DIR.rglob("*.json"):
        text = path.read_text()
        # METADATA.json ``created_from`` alani kaynak yolu bilgi amacli tutar.
        if path.name == "METADATA.json":
            continue
        for match in ABS_PATH_RE.finditer(text):
            leaked.append(f"{path.relative_to(GOLDEN_DIR)}: {match.group()}")
    assert not leaked, f"Normalize edilmemis absolute path'ler: {leaked[:5]}"


# ---------------------------------------------------------------------------
# ReconstructionContext (Faz 1 altyapi)
# ---------------------------------------------------------------------------


def test_recon_context_dataclass_importable() -> None:
    """``ReconstructionContext`` modul seviyesinden import edilebiliyor."""
    from karadul.pipeline.reconstruction_context import (  # noqa: WPS433
        ReconstructionContext,
    )

    ctx = ReconstructionContext(
        start=0.0,
        stage_name="reconstruction",
        workspace_dir=Path("/tmp/fake_ws"),
        binary_path=Path("/tmp/fake_bin"),
        static_dir=Path("/tmp/fake_ws/static"),
        reconstructed_dir=Path("/tmp/fake_ws/reconstructed"),
    )
    assert ctx.iteration == 0
    assert ctx.converged is False
    assert ctx.used_step_registry is False
    assert ctx.phase1_short_circuit is False
    assert ctx.loop_state is None


def test_recon_context_default_collections_are_distinct() -> None:
    """Iki ayri instance default_factory sayesinde ayri liste/dict almali."""
    from karadul.pipeline.reconstruction_context import ReconstructionContext

    a = ReconstructionContext()
    b = ReconstructionContext()
    a.errors.append("x")
    a.artifacts["k"] = Path("/v")
    assert b.errors == []
    assert b.artifacts == {}


def test_recon_context_ensure_loop_state_creates_once() -> None:
    """``ensure_loop_state`` cagirildiginda loop_state insa edilmeli, tekrar
    cagirildiginda ayni objeyi dondurmeli."""
    from karadul.pipeline.reconstruction_context import ReconstructionContext

    ctx = ReconstructionContext(max_iterations=7)
    ls1 = ctx.ensure_loop_state()
    assert ls1 is not None
    assert ls1.max_iterations == 7
    ls2 = ctx.ensure_loop_state()
    assert ls1 is ls2  # ayni obje
    assert ctx.loop_state is ls1


def test_recon_loop_state_defaults() -> None:
    """Loop state default'lari plan §4 ile uyumlu."""
    from karadul.pipeline.reconstruction_context import ReconLoopState

    ls = ReconLoopState()
    assert ls.iter_idx == 0
    assert ls.prev_named_set == set()
    assert ls.iteration_stats == []
    assert ls.loop_decompiled_dir is None
    assert ls.incremental_files is None
    assert ls.converged is False


def test_recon_context_private_alias_matches() -> None:
    """``_ReconCtx`` takma adi ayni siniflara isaret eder (plan §4 uyumlu)."""
    from karadul.pipeline import reconstruction_context as rcmod

    assert rcmod._ReconCtx is rcmod.ReconstructionContext
    assert rcmod._ReconLoopState is rcmod.ReconLoopState


# ---------------------------------------------------------------------------
# Normalize fonksiyonu testleri
# ---------------------------------------------------------------------------


def test_normalize_replaces_timestamp_keys() -> None:
    data = {"timestamp": 1745250000.0, "started_at": "2026-04-22T17:57:29", "value": 42}
    out = _normalize_output(data)
    assert out["timestamp"] == "<TIMESTAMP>"
    assert out["started_at"] == "<TIMESTAMP>"
    assert out["value"] == 42


def test_normalize_replaces_uuid_in_strings() -> None:
    data = {"note": "run abc12345-1234-5678-9abc-def012345678 bitti"}
    out = _normalize_output(data)
    assert "<UUID>" in out["note"]
    assert "abc12345-1234" not in out["note"]


def test_normalize_replaces_absolute_paths_in_strings() -> None:
    data = {"note": "Created in /tmp/kd_ws_sample/x and /Users/apple/Desktop/y"}
    out = _normalize_output(data)
    assert "/tmp/" not in out["note"]
    assert "/Users/" not in out["note"]
    assert out["note"].count("<RELATIVE_PATH>") == 2


def test_normalize_preserves_unrelated_fields() -> None:
    data = {"functions": [{"name": "main", "addr": "0x100"}], "count": 1}
    out = _normalize_output(data)
    assert out["functions"][0]["name"] == "main"
    assert out["functions"][0]["addr"] == "0x100"
    assert out["count"] == 1


# ---------------------------------------------------------------------------
# Gercek parity testi — Faz 2'de aktiflestirilecek
# ---------------------------------------------------------------------------


@pytest.mark.skip(
    reason="Faz 2'de aktif olacak: split implementasyonu bittiginde "
    "golden ile live output SHA256 karsilastirilacak"
)
def test_execute_binary_artifact_parity_golden() -> None:
    """Split sonrasi ReconstructionStage ciktilari golden ile ayni mi?

    Faz 2 developer'i yapacak:
      1. Tmp workspace'de ``karadul analyze`` kos.
      2. Ciktiyi normalize et.
      3. Golden ile key-by-key karsilastir (list sirasinin onemli oldugu
         yerler dikkat — sira kararliligi stages.py guvencesi).
      4. Hash mismatch icinde ilk farkliligi readable formatta rapor et.
    """
    raise NotImplementedError("Faz 2 gorevi")


# ---------------------------------------------------------------------------
# Faz 2 — adim 1 parity: _prepare_workspace + _load_binary
# ---------------------------------------------------------------------------
# Bu testler v1.12.0 Faz 2'nin ilk split adimini dogrular:
#   - ``ReconstructionStage._prepare_workspace`` (plan §3 metot 1 Setup)
#   - ``ReconstructionStage._load_binary`` (plan §3 metot 1 Load)
# Golden fixture'daki static/ altindaki ghidra_*.json dosyalari tmp bir
# workspace'e kopyalanir, metotlar izole cagrilir, rc state'i beklenen
# alanlari icermeli.


def _build_context_and_stage_from_golden(tmp_path: Path):
    """Golden fixture'i tmp workspace'e kopyalayip bir context insa et."""
    import shutil
    from unittest.mock import MagicMock

    from karadul.core.pipeline import PipelineContext
    from karadul.core.target import Language, TargetInfo, TargetType
    from karadul.core.workspace import Workspace
    from karadul.stages import ReconstructionStage

    # Sahte binary dosyasi (MACH-O olmasi zorunlu degil; _load_binary
    # sadece path'i okur, icerige bakmaz).
    fake_bin = tmp_path / "sample_macho"
    fake_bin.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 16)

    # Workspace kurulumu — stage dizinleri otomatik olusur (create() cagirisinda).
    workspace = Workspace(base_dir=tmp_path / "ws", target_name="sample_macho")
    workspace.create()
    static_dir = workspace.get_stage_dir("static")
    _ = workspace.get_stage_dir("deobfuscated")

    # Golden static JSON'larini static_dir'e kopyala (monolith load bu
    # konumdan okumaya fallback eder — deob_dir bos kalsin).
    gs = GOLDEN_DIR / "static"
    for fn in (
        "ghidra_functions.json",
        "ghidra_strings.json",
        "ghidra_call_graph.json",
        "ghidra_types.json",
        "ghidra_xrefs.json",
        "ghidra_pcode.json",
        "ghidra_cfg.json",
        "ghidra_function_id.json",
    ):
        src = gs / fn
        if src.exists():
            shutil.copy(src, static_dir / fn)

    # Decompiled C dosyasi minimum 1 tane olmak zorunda — yoksa
    # _load_binary erken cikis yapar.
    decompiled_dir = static_dir / "ghidra_output" / "decompiled"
    decompiled_dir.mkdir(parents=True, exist_ok=True)
    (decompiled_dir / "FUN_00001000.c").write_text(
        "void FUN_00001000(void) { return; }\n",
        encoding="utf-8",
    )

    # Target + context kur.
    target = TargetInfo(
        path=fake_bin,
        name="sample_macho",
        target_type=TargetType.MACHO_BINARY,
        language=Language.C,
        file_size=fake_bin.stat().st_size,
        file_hash="0" * 64,
    )
    config = MagicMock()
    config.binary_reconstruction.enable_byte_pattern_matching = False
    context = PipelineContext(target=target, workspace=workspace, config=config)

    stage = ReconstructionStage()
    return stage, context


def test_prepare_workspace_parity(tmp_path: Path) -> None:
    """_prepare_workspace cagirisi ``rc`` state'ini plan §3 metot 1 ile uyumlu doldurur."""
    from karadul.pipeline.reconstruction_context import ReconstructionContext

    stage, context = _build_context_and_stage_from_golden(tmp_path)

    rc = ReconstructionContext(start=0.0, stage_name=stage.name)
    stage._prepare_workspace(context, rc)

    # Artifacts/stats/errors init
    assert rc.errors == []
    assert rc.artifacts == {}
    assert rc.stats == {}
    # Workspace dizinleri
    assert rc.static_dir is not None
    assert rc.static_dir.is_dir()
    assert rc.reconstructed_dir is not None
    assert rc.dirs["deobfuscated"].is_dir()
    assert rc.dirs["static"] == rc.static_dir
    assert rc.dirs["reconstructed"] == rc.reconstructed_dir
    # binary_path rc icine isaretlenmeli
    assert rc.binary_path is not None
    assert rc.binary_path.name == "sample_macho"
    # workspace_dir — Workspace.path
    assert rc.workspace_dir is not None
    assert rc.workspace_dir.is_dir()


def test_load_binary_parity(tmp_path: Path) -> None:
    """_load_binary cagirisi sonrasi rc.ph1_artifacts beklenen alanlari icerir."""
    from karadul.pipeline.reconstruction_context import ReconstructionContext

    stage, context = _build_context_and_stage_from_golden(tmp_path)

    rc = ReconstructionContext(start=0.0, stage_name=stage.name)
    stage._prepare_workspace(context, rc)
    loaded = stage._load_binary(context, rc)

    # Erken cikis yasanmamali
    assert rc.phase1_short_circuit is False
    assert rc.phase1_early_return is None

    # Dict donusu eski lokal isimlere bit-identik
    for key in (
        "binary_for_byte_match",
        "decompiled_dir",
        "c_files",
        "_file_cache",
        "functions_json",
        "strings_json",
        "call_graph_json",
        "ghidra_types_json",
        "xrefs_json",
        "pcode_json",
        "cfg_json",
        "fid_json",
        "decompiled_json",
        "output_dir",
        "_func_data",
        "_string_data",
        "_call_graph_data",
    ):
        assert key in loaded, f"_load_binary donusu eksik: {key}"

    # rc mirror'lari
    assert rc.file_cache is loaded["_file_cache"]
    assert rc.ph1_artifacts["functions_json_path"] == loaded["functions_json"]
    assert rc.ph1_artifacts["strings_json_path"] == loaded["strings_json"]
    assert rc.ph1_artifacts["call_graph_json_path"] == loaded["call_graph_json"]
    assert rc.ph1_artifacts["decompiled_dir"] == loaded["decompiled_dir"]

    # c_files gercekten Load edilmis mi? (asgari 1 dosya)
    assert len(loaded["c_files"]) >= 1
    # Golden JSON'lari parse edilmis mi?
    assert loaded["_func_data"] is not None, "functions_json parse edilmedi"
    # output_dir (reconstructed/src) olusturulmus olmali
    assert loaded["output_dir"].is_dir()
    # stats source_c_files sayisi
    assert rc.stats.get("source_c_files") == len(loaded["c_files"])
    # context.metadata["file_cache"] de yerlestirilmis olmali
    assert context.metadata.get("file_cache") is rc.file_cache


def test_load_binary_short_circuit_when_no_c_files(tmp_path: Path) -> None:
    """Decompiled C dosyasi yoksa _load_binary rc.phase1_short_circuit set eder."""
    import shutil

    from karadul.pipeline.reconstruction_context import ReconstructionContext

    stage, context = _build_context_and_stage_from_golden(tmp_path)
    # Tum decompiled dosyalarini sil.
    for d in (
        context.workspace.get_stage_dir("static") / "ghidra_output" / "decompiled",
        context.workspace.get_stage_dir("deobfuscated") / "decompiled",
    ):
        if d.exists():
            shutil.rmtree(d)

    rc = ReconstructionContext(start=0.0, stage_name=stage.name)
    stage._prepare_workspace(context, rc)
    result = stage._load_binary(context, rc)

    assert rc.phase1_short_circuit is True
    assert rc.phase1_early_return is not None
    assert rc.phase1_early_return.success is False
    assert any("C dosyasi" in e for e in rc.phase1_early_return.errors)
    assert result == {}
