"""TypeForge adapter entegrasyon testleri (v1.11.0 Phase 1A).

Gercek TypeForge binary'si sistemde varsa smoke test yapilir.
Yoksa testler pytest.skip ile atlanir -- CI ortaminda guvenli.

Calistirma:
    pytest tests/test_typeforge_adapter_integration.py -x --tb=short -v

TypeForge kurulumu:
    bash scripts/setup_typeforge.sh
    export KARADUL_TYPEFORGE_PATH=~/.karadul/typeforge/typeforge

Marker: ``@pytest.mark.requires_typeforge`` -- sadece TypeForge kuruluysa calisir.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from karadul.analyzers.typeforge_adapter import TypeForgeAdapter, TypeForgeResult
from karadul.config import Config


# ---------------------------------------------------------------------------
# Yardimci: TypeForge kurulu mu?
# ---------------------------------------------------------------------------

def _typeforge_binary() -> str | None:
    """TypeForge wrapper'inin yolunu don -- env var > PATH."""
    env = os.environ.get("KARADUL_TYPEFORGE_PATH")
    if env and Path(env).is_file():
        return env
    return shutil.which("typeforge")


TYPEFORGE_PATH = _typeforge_binary()
TYPEFORGE_INSTALLED = TYPEFORGE_PATH is not None

requires_typeforge = pytest.mark.requires_typeforge
skip_if_missing = pytest.mark.skipif(
    not TYPEFORGE_INSTALLED,
    reason=(
        "TypeForge kurulu degil. Kurulum: "
        "'bash scripts/setup_typeforge.sh' ve "
        "'export KARADUL_TYPEFORGE_PATH=~/.karadul/typeforge/typeforge'"
    ),
)


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def cfg() -> Config:
    c = Config()
    c.binary_reconstruction.enable_typeforge = True
    if TYPEFORGE_PATH:
        c.binary_reconstruction.typeforge_path = TYPEFORGE_PATH
    return c


@pytest.fixture
def sample_elf(tmp_path: Path) -> Path:
    """tests/fixtures/typeforge_sample.bin varsa kullan, yoksa sahte ELF yaz.

    Gercek test icin: tests/fixtures/ altina ELF binary koy ve adini
    ``typeforge_sample.bin`` yap. Script onu otomatik alir.
    """
    fixture = Path(__file__).parent / "fixtures" / "typeforge_sample.bin"
    if fixture.exists():
        return fixture

    # Sahte ELF: 4-byte magic + minimal header (TypeForge Ghidra olmadan reject eder)
    fake = tmp_path / "sample.elf"
    elf_header = (
        b"\x7fELF"            # magic
        b"\x02"               # 64-bit
        b"\x01"               # little-endian
        b"\x01"               # ELF version
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # padding (9 bytes)
        b"\x02\x00"           # ET_EXEC
        b"\x3e\x00"           # x86-64
        b"\x01\x00\x00\x00"  # ELF version
        + b"\x00" * 200       # sahte header devami
    )
    fake.write_bytes(elf_header)
    return fake


# ---------------------------------------------------------------------------
# 1) is_available() -- env var onceligi
# ---------------------------------------------------------------------------

def test_is_available_respects_env_var(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """KARADUL_TYPEFORGE_PATH env var dogru dosyaya isaret ederse is_available True."""
    fake_bin = tmp_path / "typeforge"
    fake_bin.write_text("#!/bin/sh\necho '{}'")
    fake_bin.chmod(0o755)

    monkeypatch.setenv("KARADUL_TYPEFORGE_PATH", str(fake_bin))
    # PATH'te typeforge yok -- env var baskali olmali
    import karadul.analyzers.typeforge_adapter as mod
    monkeypatch.setattr(mod.shutil, "which", lambda _: None)

    adapter = TypeForgeAdapter(Config())
    assert adapter.is_available() is True
    assert adapter._typeforge_path == str(fake_bin)


def test_is_available_env_var_missing_file_warns(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """KARADUL_TYPEFORGE_PATH tanimli ama dosya yoksa is_available False (graceful)."""
    monkeypatch.setenv("KARADUL_TYPEFORGE_PATH", str(tmp_path / "nonexistent"))
    import karadul.analyzers.typeforge_adapter as mod
    monkeypatch.setattr(mod.shutil, "which", lambda _: None)

    adapter = TypeForgeAdapter(Config())
    assert adapter.is_available() is False


# ---------------------------------------------------------------------------
# 2) Graceful skip -- kurulu degil
# ---------------------------------------------------------------------------

def test_analyze_binary_skip_when_not_installed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """TypeForge kurulu degilse hata yok, bos result + onerici hata mesaji."""
    import karadul.analyzers.typeforge_adapter as mod
    monkeypatch.delenv("KARADUL_TYPEFORGE_PATH", raising=False)
    monkeypatch.setattr(mod.shutil, "which", lambda _: None)

    adapter = TypeForgeAdapter(Config())
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF")

    result = adapter.analyze_binary(binary)
    assert isinstance(result, TypeForgeResult)
    assert result.structs == []
    assert result.errors
    # Hata mesaji kurulum scriptini aciklamali
    combined = " ".join(result.errors)
    assert "setup_typeforge" in combined or "KARADUL_TYPEFORGE_PATH" in combined


# ---------------------------------------------------------------------------
# 3) Smoke test -- TypeForge gercekten kuruluysa calistir
# ---------------------------------------------------------------------------

@requires_typeforge
@skip_if_missing
def test_smoke_typeforge_version(cfg: Config) -> None:
    """TypeForge binary cevap veriyor mu? --help veya version flag kontrol et."""
    assert TYPEFORGE_PATH is not None
    try:
        proc = subprocess.run(
            [TYPEFORGE_PATH, "--help"],
            capture_output=True, text=True, timeout=30,
        )
        # Returncode 0 veya 1 kabul edilir (--help bazi araclarda 1 doner)
        assert proc.returncode in (0, 1), (
            f"--help unexpected exit {proc.returncode}: {proc.stderr[:300]}"
        )
    except subprocess.TimeoutExpired:
        pytest.skip("TypeForge --help 30s'de yanit vermedi -- Ghidra init süresi normal.")


@requires_typeforge
@skip_if_missing
def test_smoke_analyze_binary_integration(cfg: Config, sample_elf: Path) -> None:
    """Gercek TypeForge ile sample ELF analizi -- en az bos sonuc donmeli."""
    adapter = TypeForgeAdapter(cfg, timeout=120.0)
    assert adapter.is_available(), "TypeForge kurulu oldugu halde is_available False"

    result = adapter.analyze_binary(sample_elf)

    # TypeForge ya struct listesi ya da bos liste doner; hata olmamali
    # (sahte ELF ise Ghidra parse edemez, bos struct listesi kabul edilir)
    assert isinstance(result, TypeForgeResult)
    assert isinstance(result.structs, list)
    assert result.duration_seconds >= 0.0

    if result.errors:
        # Bilinen kabul edilebilir hata: Ghidra fake ELF'i parse edemedi
        combined = " ".join(result.errors)
        acceptable = ("parse" in combined.lower() or "ghidra" in combined.lower()
                      or "import" in combined.lower() or "format" in combined.lower())
        if not acceptable:
            pytest.fail(f"Beklenmez TypeForge hatalari: {result.errors}")


@requires_typeforge
@skip_if_missing
def test_smoke_typeforge_json_output_schema(cfg: Config, sample_elf: Path) -> None:
    """TypeForge JSON ciktisi dogru sema ile gelmeli: {'structs': [...]}."""
    adapter = TypeForgeAdapter(cfg, timeout=120.0)
    result = adapter.analyze_binary(sample_elf)

    # Struct varsa sema dogrula
    for s in result.structs:
        assert isinstance(s.name, str) and s.name, f"name bos: {s}"
        assert isinstance(s.size, int) and s.size >= 0, f"size gecersiz: {s}"
        assert isinstance(s.fields, list), f"fields list degil: {s}"
        assert 0.0 <= s.confidence <= 1.0, f"confidence aralik disi: {s}"
