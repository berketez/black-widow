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
