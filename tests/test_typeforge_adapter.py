"""Tests -- TypeForge adapter + merge hook (v1.10.0 M3 T8).

Burada gercek TypeForge binary'si yok. Subprocess cagrilari ``monkeypatch``
ile mock'lanir. Tum test'ler hermetik.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from karadul.analyzers.typeforge_adapter import (
    TypeForgeAdapter,
    TypeForgeResult,
    TypeForgeStruct,
)
from karadul.config import Config
from karadul.reconstruction.c_type_recoverer import (
    CTypeRecoverer,
    RecoveredStruct,
    StructField,
)
from karadul.reconstruction.c_type_recoverer_ext import (
    TypeForgeMergeStats,
    merge_typeforge_structs,
    typeforge_to_recovered,
)


# ---------------------------------------------------------------------------
# Fixture'lar
# ---------------------------------------------------------------------------


@pytest.fixture
def base_config() -> Config:
    cfg = Config()
    # Adapter testleri icin flag'a dokunma -- bazi testlerde off, bazilarinda on
    return cfg


@pytest.fixture
def sample_payload() -> dict:
    """Gecerli TypeForge JSON ciktisi."""
    return {
        "structs": [
            {
                "name": "struct_0x4010a0",
                "size": 16,
                "fields": [
                    {"name": "count", "offset": 0, "type": "int32", "size": 4},
                    {"name": "ptr", "offset": 8, "type": "int64", "size": 8},
                ],
                "confidence": 0.91,
            },
            {
                "name": "struct_0x401200",
                "size": 32,
                "fields": [
                    {"name": "field_0", "offset": 0, "type": "int64"},
                    {"name": "field_1", "offset": 8, "type": "int64"},
                    {"name": "field_2", "offset": 16, "type": "int64"},
                    {"name": "field_3", "offset": 24, "type": "int64"},
                ],
                "confidence": 0.72,
            },
        ]
    }


# ---------------------------------------------------------------------------
# 1) Adapter init + dataclass'lar
# ---------------------------------------------------------------------------


def test_adapter_init(base_config: Config) -> None:
    """Adapter default timeout'u config'den okur."""
    adapter = TypeForgeAdapter(base_config)
    assert adapter.config is base_config
    assert adapter.timeout == 600.0  # config default


def test_adapter_init_custom_timeout(base_config: Config) -> None:
    """Kullanici custom timeout verebilir."""
    adapter = TypeForgeAdapter(base_config, timeout=42.0)
    assert adapter.timeout == 42.0


def test_typeforge_struct_dataclass() -> None:
    """TypeForgeStruct field'lari ve tipleri."""
    s = TypeForgeStruct(
        name="foo", size=8,
        fields=[{"name": "f0", "offset": 0, "type": "int32"}],
        confidence=0.9,
    )
    assert s.name == "foo"
    assert s.size == 8
    assert s.fields[0]["offset"] == 0
    assert s.confidence == 0.9


def test_typeforge_result_dataclass() -> None:
    """TypeForgeResult default field'lar + backend sabit."""
    r = TypeForgeResult()
    assert r.structs == []
    assert r.errors == []
    assert r.duration_seconds == 0.0
    assert r.backend == "typeforge"


# ---------------------------------------------------------------------------
# 2) Availability
# ---------------------------------------------------------------------------


def test_is_available_when_not_installed(
    base_config: Config, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TypeForge PATH'te yok ve config'de path yok -> False."""
    import karadul.analyzers.typeforge_adapter as mod
    monkeypatch.setattr(mod.shutil, "which", lambda _: None)
    # Config'de path None (default)
    adapter = TypeForgeAdapter(base_config)
    assert adapter.is_available() is False


def test_is_available_with_mock(
    base_config: Config, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PATH'te typeforge varmis gibi davran -> True."""
    import karadul.analyzers.typeforge_adapter as mod
    monkeypatch.setattr(mod.shutil, "which", lambda name: "/usr/local/bin/typeforge")
    adapter = TypeForgeAdapter(base_config)
    assert adapter.is_available() is True


def test_is_available_uses_configured_path(
    base_config: Config, tmp_path: Path,
) -> None:
    """Config'de typeforge_path varsa PATH aranmaz, o kullanilir."""
    fake_bin = tmp_path / "typeforge_fake"
    fake_bin.write_text("#!/bin/sh\necho {}")
    fake_bin.chmod(0o755)
    base_config.binary_reconstruction.typeforge_path = str(fake_bin)
    adapter = TypeForgeAdapter(base_config)
    assert adapter.is_available() is True
    assert adapter._typeforge_path == str(fake_bin)


# ---------------------------------------------------------------------------
# 3) JSON parse
# ---------------------------------------------------------------------------


def test_parse_typeforge_json_valid(
    base_config: Config, sample_payload: dict,
) -> None:
    adapter = TypeForgeAdapter(base_config)
    structs = adapter._parse_typeforge_json(sample_payload)
    assert len(structs) == 2
    assert structs[0].name == "struct_0x4010a0"
    assert structs[0].size == 16
    assert structs[0].confidence == pytest.approx(0.91)
    assert len(structs[0].fields) == 2
    assert structs[1].name == "struct_0x401200"


def test_parse_typeforge_json_empty_structs(base_config: Config) -> None:
    """structs anahtari yoksa bos liste doner."""
    adapter = TypeForgeAdapter(base_config)
    assert adapter._parse_typeforge_json({}) == []
    assert adapter._parse_typeforge_json({"structs": []}) == []


def test_parse_typeforge_json_malformed(base_config: Config) -> None:
    """Gecersiz yapilar silentliyen atlanir, gecerli olanlar dondurulur."""
    adapter = TypeForgeAdapter(base_config)
    payload = {
        "structs": [
            "not a dict",
            {"name": "", "size": 8, "fields": [], "confidence": 0.9},  # bos name
            {"name": "ok", "size": 8, "fields": [], "confidence": 0.9},
            {"name": "bad_size", "size": -1, "fields": [], "confidence": 0.9},
            {"name": "bad_fields", "size": 8, "fields": "oops", "confidence": 0.9},
        ]
    }
    structs = adapter._parse_typeforge_json(payload)
    assert len(structs) == 1
    assert structs[0].name == "ok"


def test_parse_typeforge_json_clamps_confidence(base_config: Config) -> None:
    """Confidence [0, 1] disina tasarsa clamp edilir."""
    adapter = TypeForgeAdapter(base_config)
    payload = {
        "structs": [
            {"name": "a", "size": 8, "fields": [], "confidence": 1.5},
            {"name": "b", "size": 8, "fields": [], "confidence": -0.3},
            {"name": "c", "size": 8, "fields": [], "confidence": "oops"},
        ]
    }
    structs = adapter._parse_typeforge_json(payload)
    assert structs[0].confidence == 1.0
    assert structs[1].confidence == 0.0
    assert structs[2].confidence == 0.0  # non-numeric -> default 0.0


def test_parse_typeforge_json_rejects_non_dict_root(base_config: Config) -> None:
    adapter = TypeForgeAdapter(base_config)
    with pytest.raises(ValueError):
        adapter._parse_typeforge_json(["not", "a", "dict"])  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 4) analyze_binary -- graceful yollar
# ---------------------------------------------------------------------------


def test_analyze_binary_graceful_skip(
    base_config: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TypeForge kurulu degilse analyze_binary bos sonuc ve hata doner."""
    import karadul.analyzers.typeforge_adapter as mod
    monkeypatch.setattr(mod.shutil, "which", lambda _: None)
    adapter = TypeForgeAdapter(base_config)
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF")

    result = adapter.analyze_binary(binary)
    assert isinstance(result, TypeForgeResult)
    assert result.structs == []
    assert any("kurulu degil" in e for e in result.errors)
    assert result.duration_seconds >= 0.0


def test_analyze_binary_missing_file(
    base_config: Config, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """Binary dosyasi yoksa error dondurulur."""
    import karadul.analyzers.typeforge_adapter as mod
    monkeypatch.setattr(mod.shutil, "which", lambda _: "/usr/bin/typeforge")
    adapter = TypeForgeAdapter(base_config)
    missing = tmp_path / "missing"
    result = adapter.analyze_binary(missing)
    assert result.structs == []
    assert any("bulunamadi" in e for e in result.errors)


def test_analyze_binary_mocked_subprocess_success(
    base_config: Config, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch, sample_payload: dict,
) -> None:
    """Subprocess basarili -> JSON parse edilir, struct listesi doner."""
    import karadul.analyzers.typeforge_adapter as mod
    monkeypatch.setattr(mod.shutil, "which", lambda _: "/usr/bin/typeforge")
    base_config.binary_reconstruction.enable_typeforge = True

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        return subprocess.CompletedProcess(
            args=cmd, returncode=0,
            stdout=json.dumps(sample_payload), stderr="",
        )

    monkeypatch.setattr(mod.subprocess, "run", fake_run)

    adapter = TypeForgeAdapter(base_config)
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF")
    result = adapter.analyze_binary(binary)
    assert len(result.structs) == 2
    assert result.errors == []


def test_analyze_binary_subprocess_timeout(
    base_config: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Subprocess timeout -> graceful error."""
    import karadul.analyzers.typeforge_adapter as mod
    monkeypatch.setattr(mod.shutil, "which", lambda _: "/usr/bin/typeforge")

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs.get("timeout", 1))

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    adapter = TypeForgeAdapter(base_config)
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF")
    result = adapter.analyze_binary(binary)
    assert result.structs == []
    assert any("timeout" in e.lower() for e in result.errors)


def test_analyze_binary_subprocess_non_zero_exit(
    base_config: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Subprocess non-zero -> stderr error'a dusurulur."""
    import karadul.analyzers.typeforge_adapter as mod
    monkeypatch.setattr(mod.shutil, "which", lambda _: "/usr/bin/typeforge")

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        raise subprocess.CalledProcessError(
            returncode=42, cmd=cmd, stderr="crash detayi",
        )

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    adapter = TypeForgeAdapter(base_config)
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF")
    result = adapter.analyze_binary(binary)
    assert result.structs == []
    assert any("42" in e or "crash" in e for e in result.errors)


def test_analyze_binary_malformed_json(
    base_config: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Subprocess gecerli ama stdout JSON degilse graceful hata."""
    import karadul.analyzers.typeforge_adapter as mod
    monkeypatch.setattr(mod.shutil, "which", lambda _: "/usr/bin/typeforge")

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        return subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout="not json at all", stderr="",
        )

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    adapter = TypeForgeAdapter(base_config)
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF")
    result = adapter.analyze_binary(binary)
    assert result.structs == []
    assert result.errors  # hata mesaji var


# ---------------------------------------------------------------------------
# 5) Merge -- ana kural setleri
# ---------------------------------------------------------------------------


def _mk_struct(name: str, conf: float, n_fields: int = 2) -> RecoveredStruct:
    fields = [
        StructField(
            offset=i * 8, name=f"f{i}", type="int64", size=8, confidence=conf,
        )
        for i in range(n_fields)
    ]
    return RecoveredStruct(
        name=name, fields=fields, total_size=n_fields * 8,
        source_functions=["FUN_1"], alignment=8,
    )


def test_typeforge_to_recovered_converts_fields() -> None:
    tf = TypeForgeStruct(
        name="s1", size=16,
        fields=[
            {"name": "a", "offset": 8, "type": "int64"},
            {"name": "b", "offset": 0, "type": "int32"},
        ],
        confidence=0.9,
    )
    rs = typeforge_to_recovered(tf)
    assert rs.name == "s1"
    assert rs.total_size == 16
    # Offset'e gore sirali olmali
    assert rs.fields[0].offset == 0
    assert rs.fields[1].offset == 8
    # Confidence her field'a yansiyor
    assert all(f.confidence == 0.9 for f in rs.fields)


def test_merge_adds_new_structs() -> None:
    existing = [_mk_struct("old_struct", 0.75)]
    tf_result = TypeForgeResult(
        structs=[TypeForgeStruct(
            name="new_struct", size=16,
            fields=[{"name": "x", "offset": 0, "type": "int64"}],
            confidence=0.95,
        )]
    )
    merged, stats = merge_typeforge_structs(existing, tf_result, 0.85)
    assert stats.added == 1
    assert stats.replaced == 0
    assert len(merged) == 2
    assert {s.name for s in merged} == {"old_struct", "new_struct"}


def test_merge_high_confidence_wins() -> None:
    """TypeForge conf=0.95 > mevcut avg=0.75 -> TypeForge kazanir."""
    existing = [_mk_struct("S", 0.75)]
    tf_result = TypeForgeResult(structs=[
        TypeForgeStruct(
            name="S", size=32,
            fields=[{"name": "a", "offset": 0, "type": "int32"}],
            confidence=0.95,
        )
    ])
    merged, stats = merge_typeforge_structs(existing, tf_result, 0.85)
    assert stats.replaced == 1
    assert stats.added == 0
    assert stats.kept_existing == 0
    # S'nin artik total_size=32 olmali (TypeForge'dan geldi)
    s = next(x for x in merged if x.name == "S")
    assert s.total_size == 32
    assert s.fields[0].confidence == 0.95


def test_merge_low_confidence_fallback() -> None:
    """TypeForge conf=0.40 < min_confidence=0.85 -> filtered, mevcut kalir."""
    existing = [_mk_struct("S", 0.75)]
    tf_result = TypeForgeResult(structs=[
        TypeForgeStruct(
            name="S", size=32, fields=[], confidence=0.40,
        )
    ])
    merged, stats = merge_typeforge_structs(existing, tf_result, 0.85)
    assert stats.filtered_low_conf == 1
    assert stats.replaced == 0
    # S degismedi -- mevcut kopyasi korundu
    s = next(x for x in merged if x.name == "S")
    assert s.total_size == 16  # eski


def test_merge_tie_goes_to_typeforge() -> None:
    """Conf eslesirse (tie) TypeForge kazanir (re-analyst karari)."""
    existing = [_mk_struct("S", 0.90)]
    tf_result = TypeForgeResult(structs=[
        TypeForgeStruct(
            name="S", size=64,
            fields=[{"name": "x", "offset": 0, "type": "int64"}],
            confidence=0.90,
        )
    ])
    merged, stats = merge_typeforge_structs(existing, tf_result, 0.85)
    assert stats.replaced == 1
    s = next(x for x in merged if x.name == "S")
    assert s.total_size == 64


def test_merge_lower_conf_keeps_existing() -> None:
    """TypeForge conf=0.85 (esige uyar) AMA mevcut avg=0.95 -> mevcut kalir."""
    existing = [_mk_struct("S", 0.95)]
    tf_result = TypeForgeResult(structs=[
        TypeForgeStruct(name="S", size=64, fields=[], confidence=0.85),
    ])
    merged, stats = merge_typeforge_structs(existing, tf_result, 0.85)
    assert stats.kept_existing == 1
    assert stats.replaced == 0
    s = next(x for x in merged if x.name == "S")
    assert s.total_size == 16  # mevcut korundu


def test_merge_does_not_mutate_input() -> None:
    """Saf fonksiyon: girdi listesi mutate edilmez."""
    existing = [_mk_struct("S", 0.75)]
    original_ids = [id(x) for x in existing]
    tf_result = TypeForgeResult(structs=[
        TypeForgeStruct(
            name="S", size=32,
            fields=[{"name": "x", "offset": 0, "type": "int64"}],
            confidence=0.95,
        ),
        TypeForgeStruct(name="NEW", size=8, fields=[], confidence=0.9),
    ])
    merged, _ = merge_typeforge_structs(existing, tf_result, 0.85)
    # Existing listesi hala ayni uzunlukta + ayni objeleri iceriyor
    assert len(existing) == 1
    assert [id(x) for x in existing] == original_ids
    assert len(merged) == 2


# ---------------------------------------------------------------------------
# 6) CTypeRecoverer merge hook (recover_types_with_typeforge)
# ---------------------------------------------------------------------------


def test_recover_types_with_typeforge_flag_off(
    base_config: Config, tmp_path: Path,
) -> None:
    """Feature flag off -> mevcut liste aynen doner."""
    base_config.binary_reconstruction.enable_typeforge = False
    recoverer = CTypeRecoverer(base_config)
    existing = [_mk_struct("S", 0.7)]
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF")
    out, stats = recoverer.recover_types_with_typeforge(binary, existing)
    assert out is existing
    assert stats["skipped_reason"] == "feature_flag_off"


def test_recover_types_with_typeforge_not_installed(
    base_config: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Flag on ama TypeForge kurulu degil -> skip."""
    import karadul.analyzers.typeforge_adapter as mod
    monkeypatch.setattr(mod.shutil, "which", lambda _: None)
    base_config.binary_reconstruction.enable_typeforge = True
    recoverer = CTypeRecoverer(base_config)
    existing = [_mk_struct("S", 0.7)]
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF")
    out, stats = recoverer.recover_types_with_typeforge(binary, existing)
    assert out is existing
    assert stats["skipped_reason"] == "typeforge_not_installed"


def test_recover_types_with_typeforge_success(
    base_config: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    sample_payload: dict,
) -> None:
    """Tam pipeline: flag on + subprocess mock + merge."""
    import karadul.analyzers.typeforge_adapter as mod
    monkeypatch.setattr(mod.shutil, "which", lambda _: "/usr/bin/typeforge")

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        return subprocess.CompletedProcess(
            args=cmd, returncode=0,
            stdout=json.dumps(sample_payload), stderr="",
        )

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    base_config.binary_reconstruction.enable_typeforge = True
    base_config.binary_reconstruction.typeforge_min_confidence = 0.8

    recoverer = CTypeRecoverer(base_config)
    existing: list[RecoveredStruct] = []
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF")
    out, stats = recoverer.recover_types_with_typeforge(binary, existing)
    # sample_payload: conf 0.91 ve 0.72 var. Esik 0.8 -> sadece 0.91 gecer.
    assert stats["skipped_reason"] == ""
    assert stats["added"] == 1
    assert stats["filtered_low_conf"] == 1
    assert len(out) == 1
    assert out[0].name == "struct_0x4010a0"


# ---------------------------------------------------------------------------
# 7) Stats dataclass
# ---------------------------------------------------------------------------


def test_merge_stats_default() -> None:
    s = TypeForgeMergeStats()
    assert s.added == 0
    assert s.replaced == 0
    assert s.kept_existing == 0
    assert s.filtered_low_conf == 0
    assert s.notes == []
