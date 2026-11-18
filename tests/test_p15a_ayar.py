"""P15a / GHIDRA-04, MEK-05 ve P-GÜV'ün bıraktığı ağ kararı: katı ayar yükleyicisi.

Eski davranış (`Config._from_dict`): yanlış yazılmış bölüm / anahtar sessizce
atlanıyor, değer tipine bakılmadan atanıyor (`timeouts.ghidra: "abc"`), `min_confidence`
bölümü hiç yüklenmiyor, boş bölüm `AttributeError` ile düşüyor, sözlük alan
öntanımın tamamını siliyor, `karadul config validate` bunların hepsine "OK" diyordu.
Okunmayan ~50 ayar için hiçbir uyarı yoktu.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from karadul.cli import main as karadul_main
from karadul.config import Config, ConfigValueError

ROOT = Path(__file__).resolve().parents[1]


def _yaml(tmp_path: Path, text: str, name: str = "karadul.yaml") -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def _load(tmp_path: Path, text: str) -> Config:
    return Config.load(_yaml(tmp_path, text))


# ---------------------------------------------------------------------------
# Bilinmeyen bölüm / anahtar
# ---------------------------------------------------------------------------

class TestUnknownNames:
    def test_unknown_section_is_error_with_suggestion(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigValueError) as ei:
            _load(tmp_path, "binary_reconstrution:\n  enable_address_placement: true\n")
        assert ei.value.problems == [
            "binary_reconstrution: bilinmeyen bölüm "
            "(bunu mu demek istediniz: 'binary_reconstruction'?)"
        ]

    def test_unknown_key_is_error_with_suggestion(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigValueError, match="enable_addres_placement: bilinmeyen anahtar"):
            _load(tmp_path, "binary_reconstruction:\n  enable_addres_placement: true\n")

    def test_all_problems_reported_together(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigValueError) as ei:
            _load(tmp_path, (
                "bsim:\n  enabled: \"false\"\n"
                "binary_reconstrution:\n  enable_address_placement: true\n"
                "timeouts:\n  ghidra: \"abc\"\n"
                "min_confidence:\n  bindiff_match: 0.123\n"
            ))
        assert len(ei.value.problems) == 2
        assert any("binary_reconstrution" in p for p in ei.value.problems)
        assert any("timeouts.ghidra" in p for p in ei.value.problems)

    def test_non_section_top_level_field_is_unknown(self, tmp_path: Path) -> None:
        # project_root / scripts_dir dataclass bölümü değil; YAML'dan yüklenmez.
        with pytest.raises(ConfigValueError, match="project_root: bilinmeyen bölüm"):
            _load(tmp_path, "project_root: /tmp\n")

    def test_root_must_be_mapping(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigValueError, match="kökü"):
            _load(tmp_path, "- a\n- b\n")

    def test_section_must_be_mapping(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigValueError, match="timeouts: bölüm"):
            _load(tmp_path, "timeouts: 30\n")

    def test_yaml_syntax_error_is_config_error(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigValueError, match="YAML ayrıştırılamadı"):
            _load(tmp_path, "tools: [unterminated\n")


# ---------------------------------------------------------------------------
# Tip dönüşümü
# ---------------------------------------------------------------------------

class TestTypes:
    @pytest.mark.parametrize("raw", ['"abc"', '"600"', "true", "1.5", "[1]"])
    def test_int_field_rejects(self, tmp_path: Path, raw: str) -> None:
        with pytest.raises(ConfigValueError, match="timeouts.ghidra"):
            _load(tmp_path, f"timeouts:\n  ghidra: {raw}\n")

    def test_int_field_accepts_whole_float(self, tmp_path: Path) -> None:
        cfg = _load(tmp_path, "timeouts:\n  ghidra: 600.0\n")
        assert cfg.timeouts.ghidra == 600 and isinstance(cfg.timeouts.ghidra, int)

    @pytest.mark.parametrize("raw", ['"yuksek"', "true", "[0.5]"])
    def test_float_field_rejects(self, tmp_path: Path, raw: str) -> None:
        with pytest.raises(ConfigValueError, match="min_naming_confidence"):
            _load(tmp_path, f"binary_reconstruction:\n  min_naming_confidence: {raw}\n")

    def test_float_field_accepts_int(self, tmp_path: Path) -> None:
        cfg = _load(tmp_path, "binary_reconstruction:\n  min_naming_confidence: 1\n")
        assert cfg.binary_reconstruction.min_naming_confidence == 1.0
        assert isinstance(cfg.binary_reconstruction.min_naming_confidence, float)

    def test_list_field_rejects_bare_string(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigValueError, match="bir liste değil"):
            _load(tmp_path, "binary_reconstruction:\n  external_signature_paths: /tek/dizgi\n")

    def test_list_items_typed(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigValueError, match=r"external_signature_paths\[1\]"):
            _load(tmp_path, "binary_reconstruction:\n  external_signature_paths: [/a, 3]\n")

    def test_str_field_rejects_number(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigValueError, match="rtti_abi"):
            _load(tmp_path, "binary_reconstruction:\n  rtti_abi: 3\n")

    def test_optional_accepts_none_and_value(self, tmp_path: Path) -> None:
        cfg = _load(tmp_path, "pipeline:\n  parallel_max_workers: null\n"
                              "perf:\n  sig_lmdb_path: /x/y.lmdb\n  naming_max_workers: 4\n")
        assert cfg.pipeline.parallel_max_workers is None
        assert cfg.perf.sig_lmdb_path == Path("/x/y.lmdb")
        assert cfg.perf.naming_max_workers == 4

    def test_path_field(self, tmp_path: Path) -> None:
        cfg = _load(tmp_path, "tools:\n  ghidra_headless: /opt/ghidra/support/analyzeHeadless\n")
        assert cfg.tools.ghidra_headless == Path("/opt/ghidra/support/analyzeHeadless")

    def test_tuple_field(self, tmp_path: Path) -> None:
        cfg = _load(tmp_path, "security:\n  allowed_download_schemes: [https, http]\n")
        assert cfg.security.allowed_download_schemes == ("https", "http")

    def test_bool_still_strict(self, tmp_path: Path) -> None:
        assert _load(tmp_path, "bsim:\n  enabled: \"false\"\n").bsim.enabled is False
        with pytest.raises(ConfigValueError):
            _load(tmp_path, "bsim:\n  enabled: \"kapalı\"\n")


# ---------------------------------------------------------------------------
# min_confidence, boş bölüm, sözlük birleştirme, bölüm aralık denetimi
# ---------------------------------------------------------------------------

def test_min_confidence_section_is_loaded(tmp_path: Path) -> None:
    cfg = _load(tmp_path, "min_confidence:\n  bindiff_match: 0.123\n")
    assert cfg.min_confidence.bindiff_match == 0.123


def test_min_confidence_range_is_checked(tmp_path: Path) -> None:
    with pytest.raises(ConfigValueError, match=r"bindiff_match \[0,1\]"):
        _load(tmp_path, "min_confidence:\n  bindiff_match: 1.5\n")


def test_computation_post_init_is_rerun(tmp_path: Path) -> None:
    with pytest.raises(ConfigValueError, match="struct_solver_timeout"):
        _load(tmp_path, "computation:\n  struct_solver_timeout: -1.0\n")


def test_empty_section_is_empty(tmp_path: Path) -> None:
    cfg = _load(tmp_path, "tools:\nbsim:\n")
    assert cfg.tools.ghidra_headless == Config().tools.ghidra_headless


def test_dict_field_merges_over_defaults(tmp_path: Path) -> None:
    cfg = _load(tmp_path, "name_merger:\n  source_weights:\n    bsim: 0.5\n")
    default = Config().name_merger.source_weights
    assert cfg.name_merger.source_weights["bsim"] == 0.5
    assert len(cfg.name_merger.source_weights) == len(default)
    assert cfg.name_merger.source_weights["dwarf"] == default["dwarf"]


def test_dict_values_typed(tmp_path: Path) -> None:
    with pytest.raises(ConfigValueError, match="source_weights.bsim"):
        _load(tmp_path, "name_merger:\n  source_weights:\n    bsim: yuksek\n")


def test_yaml_keys_recorded(tmp_path: Path) -> None:
    cfg = _load(tmp_path, "network:\n  enabled: true\nbsim:\n  enabled: false\n")
    assert cfg.yaml_keys == frozenset({"network.enabled", "bsim.enabled"})


def test_real_shapes_load(tmp_path: Path) -> None:
    """Depodaki ayar dosyası ve arayüzün yazdığı biçim yeni yükleyiciyle yüklenir."""
    Config.load(ROOT / "docker" / "measurement" / "karadul.yaml")
    cfg = _load(tmp_path, (
        "binary_reconstruction:\n  external_signature_paths: []\n"
        "  ghidra_data_type_archives: []\n  max_functions_to_process: 0\n"
        "  min_naming_confidence: 0.7\n  pipeline_iterations: 3\n"
        "computation_recovery:\n  enabled: true\nname_merger:\n  unk_threshold: 0.3\n"
        "network:\n  enabled: false\n"
    ))
    assert cfg.computation_recovery.enabled is True


def test_ui_write_settings_output_loads(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """ARAYUZ-06 ile aynı dosya: arayüzün `_write_settings`'i yazdığı her anahtar yüklenir."""
    ui = pytest.importorskip("ui.server")
    target = tmp_path / "karadul.yaml"
    monkeypatch.setattr(ui, "_SETTINGS_YAML", target)
    out = ui._write_settings({
        "min_naming_confidence": 0.8, "unk_threshold": 0.25, "pipeline_iterations": 2,
        "max_functions_to_process": 10, "computation_recovery_enabled": True,
        "network_enabled": True, "signature_paths": ["/a/b.json", "/c/d.gdt"],
    })
    assert out.get("ok") is True, out
    cfg = Config.load(target)
    assert cfg.binary_reconstruction.min_naming_confidence == 0.8
    assert cfg.network.enabled is True


# ---------------------------------------------------------------------------
# CLI: config validate / analyze
# ---------------------------------------------------------------------------

def test_validate_reports_each_problem_and_exits_1(tmp_path: Path) -> None:
    p = _yaml(tmp_path, (
        "binary_reconstrution:\n  enable_address_placement: true\n"
        "timeouts:\n  ghidra: \"abc\"\n"
    ))
    res = CliRunner().invoke(karadul_main, ["config", "validate", "--config", str(p)])
    assert res.exit_code == 1, res.output
    assert "2 sorun" in res.stderr
    assert "- binary_reconstrution: bilinmeyen bölüm" in res.stderr
    assert "- timeouts.ghidra: 'abc' bir tamsayı değil" in res.stderr
    assert "OK" not in res.stdout


def test_validate_empty_section_ok(tmp_path: Path) -> None:
    p = _yaml(tmp_path, "tools:\n")
    res = CliRunner().invoke(karadul_main, ["config", "validate", "--config", str(p)])
    assert res.exit_code == 0, res.output


def test_analyze_unknown_key_exits_2_before_running(tmp_path: Path) -> None:
    p = _yaml(tmp_path, "binary_reconstruction:\n  enable_addres_placement: true\n")
    target = tmp_path / "x.bin"
    target.write_bytes(b"\x00" * 16)
    res = CliRunner().invoke(karadul_main, [
        "analyze", str(target), "--skip-dynamic", "--config", str(p),
        "--output-dir", str(tmp_path / "ws"),
    ])
    assert res.exit_code == 2, res.output
    assert "enable_addres_placement: bilinmeyen anahtar" in res.stderr
    assert not (tmp_path / "ws").exists()


def test_config_show_bad_yaml_exits_2(tmp_path: Path) -> None:
    p = _yaml(tmp_path, "timeouts:\n  ghidra: \"abc\"\n")
    res = CliRunner().invoke(karadul_main, ["config", "show", "--config", str(p)])
    assert res.exit_code == 2
    assert "timeouts.ghidra" in res.stderr


# ---------------------------------------------------------------------------
# Ağ alt izinleri (P-GÜV'ün bıraktığı karar)
# ---------------------------------------------------------------------------

class TestNetworkSubPermissions:
    def test_default_all_closed(self) -> None:
        n = Config().network
        assert (n.enabled, n.allow_dts_fetch, n.allow_source_match,
                n.allow_reference_download) == (False, False, False, False)

    def test_yaml_master_on_opens_data_permissions(self, tmp_path: Path) -> None:
        n = _load(tmp_path, "network:\n  enabled: true\n").network
        assert n.allow_dts_fetch is True and n.allow_source_match is True
        assert n.allow_reference_download is False  # indirip derleyen izin izlemez

    def test_explicit_false_wins(self, tmp_path: Path) -> None:
        n = _load(tmp_path, "network:\n  enabled: true\n  allow_dts_fetch: false\n").network
        assert n.allow_dts_fetch is False and n.allow_source_match is True

    def test_master_off_keeps_data_permissions_off(self, tmp_path: Path) -> None:
        n = _load(tmp_path, "network:\n  enabled: false\n").network
        assert n.allow_dts_fetch is False

    def test_reference_download_only_explicit(self, tmp_path: Path) -> None:
        n = _load(tmp_path, "network:\n  enabled: true\n  allow_reference_download: true\n").network
        assert n.allow_reference_download is True

    def test_enable_respects_explicit(self) -> None:
        n = Config().network
        n.allow_source_match = False
        n.enable(explicit_keys={"allow_source_match"})
        assert n.enabled and n.allow_dts_fetch is True and n.allow_source_match is False
        assert n.allow_reference_download is False


    def test_cli_enable_network_opens_dts(self, tmp_path: Path,
                                          monkeypatch: pytest.MonkeyPatch) -> None:
        import karadul.cli as cli_mod

        captured: dict = {}

        class _Stop(Exception):
            pass

        def _fake_build(cfg, **kwargs):
            captured["cfg"] = cfg
            raise _Stop

        monkeypatch.setattr(cli_mod, "build_pipeline", _fake_build)
        target = tmp_path / "a.js"
        target.write_text("var a=1;\n", encoding="utf-8")
        p = _yaml(tmp_path, "network:\n  allow_source_match: false\n")
        CliRunner().invoke(karadul_main, [
            "analyze", str(target), "--skip-dynamic", "--enable-network",
            "--config", str(p), "--output-dir", str(tmp_path / "ws"),
        ])
        n = captured["cfg"].network
        assert n.enabled is True and n.allow_dts_fetch is True
        assert n.allow_source_match is False  # YAML'da açıkça kapalı
        assert n.allow_reference_download is False
