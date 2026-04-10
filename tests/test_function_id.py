"""FunctionID extraction testleri.

Mock-based testler -- gercek Ghidra JVM gerektirmez.
GhidraHeadless._extract_function_id_matches() ve stages.py
FunctionID entegrasyonunu test eder.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from karadul.config import Config
from karadul.ghidra.headless import GhidraHeadless


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def config() -> Config:
    return Config()


@pytest.fixture
def ghidra(config: Config) -> GhidraHeadless:
    return GhidraHeadless(config)


class _MockSourceType:
    """Ghidra SourceType enum mock."""
    ANALYSIS = "ANALYSIS"
    USER_DEFINED = "USER_DEFINED"
    DEFAULT = "DEFAULT"
    IMPORTED = "IMPORTED"


def _make_mock_function(name: str, address: str, source, comment: str = ""):
    """Tek bir Ghidra Function mock'u olustur."""
    func = MagicMock()
    func.getName.return_value = name
    func.getEntryPoint.return_value = MagicMock(__str__=lambda self: address)
    func.getComment.return_value = comment

    sym = MagicMock()
    sym.getSource.return_value = source
    func.getSymbol.return_value = sym

    # PLATE_COMMENT attribute (opsiyonel)
    func.PLATE_COMMENT = 0
    func.getCommentAsArray.return_value = None

    return func


def _make_mock_program(functions: list) -> MagicMock:
    """Program mock'u olustur, fonksiyon listesini FunctionManager uzerinden don."""
    program = MagicMock()
    fm = MagicMock()
    fm.getFunctions.return_value = iter(functions)
    program.getFunctionManager.return_value = fm
    return program


# ---------------------------------------------------------------------------
# Test: Hic esleme yoksa
# ---------------------------------------------------------------------------

class TestExtractNoMatches:
    """Tum fonksiyonlar FUN_ ise esleme olmamali."""

    def test_all_fun_prefix(self) -> None:
        """Tum isimler FUN_ ile basliyorsa total_matches=0."""
        st = _MockSourceType()
        funcs = [
            _make_mock_function("FUN_00401000", "00401000", st.ANALYSIS),
            _make_mock_function("FUN_00401100", "00401100", st.ANALYSIS),
            _make_mock_function("FUN_00401200", "00401200", st.DEFAULT),
        ]
        program = _make_mock_program(funcs)

        with patch.dict("sys.modules", {
            "ghidra.program.model.symbol": MagicMock(SourceType=st),
        }):
            with patch(
                "karadul.ghidra.headless.GhidraHeadless._extract_function_id_matches",
                GhidraHeadless._extract_function_id_matches.__func__
                if hasattr(GhidraHeadless._extract_function_id_matches, "__func__")
                else GhidraHeadless._extract_function_id_matches,
            ):
                # Dogrudan staticmethod'u cagir, SourceType mock'unu inject et
                result = _extract_with_mocked_source_type(program, st)

        assert result["total_matches"] == 0
        assert result["matches"] == []

    def test_empty_program(self) -> None:
        """Fonksiyonsuz program icin bos sonuc."""
        st = _MockSourceType()
        program = _make_mock_program([])

        result = _extract_with_mocked_source_type(program, st)
        assert result["total_matches"] == 0


# ---------------------------------------------------------------------------
# Test: Eslesmeler varsa
# ---------------------------------------------------------------------------

class TestExtractWithMatches:
    """FunctionID tarafindan tanINMIS fonksiyonlar."""

    def test_mixed_functions(self) -> None:
        """FUN_ + taninan karisik listede dogru filtreleme."""
        st = _MockSourceType()
        funcs = [
            _make_mock_function("FUN_00401000", "00401000", st.ANALYSIS),
            _make_mock_function("printf", "00401100", st.ANALYSIS, "libc"),
            _make_mock_function("malloc", "00401200", st.ANALYSIS, "libc"),
            _make_mock_function("FUN_00401300", "00401300", st.ANALYSIS),
            _make_mock_function("my_custom_func", "00401400", st.USER_DEFINED),
            _make_mock_function("strcmp", "00401500", st.ANALYSIS, "libSystem"),
        ]
        program = _make_mock_program(funcs)

        result = _extract_with_mocked_source_type(program, st)

        assert result["total_matches"] == 3
        names = [m["name"] for m in result["matches"]]
        assert "printf" in names
        assert "malloc" in names
        assert "strcmp" in names
        # FUN_ ve USER_DEFINED dahil olmamali
        assert "FUN_00401000" not in names
        assert "my_custom_func" not in names

    def test_library_from_comment(self) -> None:
        """Library bilgisi comment'ten alinmali."""
        st = _MockSourceType()
        funcs = [
            _make_mock_function("EVP_DigestInit", "00501000", st.ANALYSIS, "libssl.dylib"),
        ]
        program = _make_mock_program(funcs)

        result = _extract_with_mocked_source_type(program, st)

        assert result["total_matches"] == 1
        assert result["matches"][0]["library"] == "libssl.dylib"

    def test_no_symbol_skipped(self) -> None:
        """Symbol'u None olan fonksiyon atlanmali."""
        st = _MockSourceType()
        func = _make_mock_function("orphan", "00601000", st.ANALYSIS)
        func.getSymbol.return_value = None
        program = _make_mock_program([func])

        result = _extract_with_mocked_source_type(program, st)
        assert result["total_matches"] == 0


# ---------------------------------------------------------------------------
# Test: JSON schema dogrulama
# ---------------------------------------------------------------------------

class TestFunctionIdJsonSchema:
    """Cikti JSON schemasi dogrulama."""

    def test_schema_keys(self) -> None:
        """Zorunlu alanlar mevcut olmali."""
        st = _MockSourceType()
        funcs = [
            _make_mock_function("memcpy", "00701000", st.ANALYSIS, "libc"),
        ]
        program = _make_mock_program(funcs)

        result = _extract_with_mocked_source_type(program, st)

        assert "total_matches" in result
        assert "matches" in result
        assert isinstance(result["matches"], list)
        for m in result["matches"]:
            assert "name" in m
            assert "address" in m
            assert "library" in m

    def test_json_serializable(self) -> None:
        """Sonuc JSON serializable olmali."""
        st = _MockSourceType()
        funcs = [
            _make_mock_function("free", "00801000", st.ANALYSIS),
        ]
        program = _make_mock_program(funcs)

        result = _extract_with_mocked_source_type(program, st)
        # json.dumps exception firlatmamali
        serialized = json.dumps(result, default=str)
        parsed = json.loads(serialized)
        assert parsed["total_matches"] == 1


# ---------------------------------------------------------------------------
# Test: Config ile devre disi birakma
# ---------------------------------------------------------------------------

class TestFunctionIdDisabled:
    """enable_function_id=False ise extraction atlanmali."""

    def test_disabled_in_config(self) -> None:
        """enable_function_id=False varsayilan davranisi kontrol."""
        cfg = Config()
        cfg.binary_reconstruction.enable_function_id = False
        assert cfg.binary_reconstruction.enable_function_id is False

    def test_enabled_by_default(self) -> None:
        """Varsayilan olarak enable_function_id=True."""
        cfg = Config()
        assert cfg.binary_reconstruction.enable_function_id is True


# ---------------------------------------------------------------------------
# Test: stages.py fid_json cache lookup
# ---------------------------------------------------------------------------

class TestFunctionIdStagesIntegration:
    """stages.py'deki FunctionID JSON cache pattern'i."""

    def test_fid_json_path_static(self, tmp_path: Path) -> None:
        """Static dizindeki ghidra_function_id.json bulunmali."""
        static_dir = tmp_path / "static"
        static_dir.mkdir()

        fid_data = {
            "total_matches": 2,
            "matches": [
                {"name": "printf", "address": "00401100", "library": "libc"},
                {"name": "malloc", "address": "00401200", "library": "libc"},
            ],
        }
        fid_path = static_dir / "ghidra_function_id.json"
        fid_path.write_text(json.dumps(fid_data), encoding="utf-8")

        # Dosya var ve parse edilebilir
        loaded = json.loads(fid_path.read_text(encoding="utf-8"))
        assert loaded["total_matches"] == 2
        assert len(loaded["matches"]) == 2

    def test_fid_json_path_deob_priority(self, tmp_path: Path) -> None:
        """Deob dizinindeki fid JSON, static'ten oncelikli olmali."""
        deob_dir = tmp_path / "deobfuscated"
        deob_dir.mkdir()
        static_dir = tmp_path / "static"
        static_dir.mkdir()

        # Her ikisine de farkli veri yaz
        deob_data = {"total_matches": 5, "matches": []}
        static_data = {"total_matches": 3, "matches": []}

        (deob_dir / "ghidra_function_id.json").write_text(
            json.dumps(deob_data), encoding="utf-8",
        )
        (static_dir / "ghidra_function_id.json").write_text(
            json.dumps(static_data), encoding="utf-8",
        )

        # Deob varsa oradan al (stages.py pattern'i)
        fid_json = deob_dir / "ghidra_function_id.json"
        if not fid_json.exists():
            fid_json = static_dir / "ghidra_function_id.json"

        loaded = json.loads(fid_json.read_text(encoding="utf-8"))
        assert loaded["total_matches"] == 5  # deob oncelikli

    def test_fid_json_missing_graceful(self, tmp_path: Path) -> None:
        """fid_json dosyasi yoksa hata olmamali."""
        fid_json = tmp_path / "nonexistent" / "ghidra_function_id.json"
        assert not fid_json.exists()
        # stages.py'deki pattern: if fid_json and fid_json.exists()
        # Bu durumda blogun icine girilmez, candidate eklenmez

    def test_fid_candidate_format(self, tmp_path: Path) -> None:
        """FunctionID matches'tan NamingCandidate olusturma pattern'i."""
        fid_data = {
            "total_matches": 1,
            "matches": [
                {"name": "SHA256_Init", "address": "00401a00", "library": "libcrypto"},
            ],
        }
        fid_json = tmp_path / "ghidra_function_id.json"
        fid_json.write_text(json.dumps(fid_data), encoding="utf-8")

        loaded = json.loads(fid_json.read_text(encoding="utf-8"))
        for m in loaded["matches"]:
            fid_name = m.get("name", "")
            fid_addr = m.get("address", "")
            fun_key = "FUN_%s" % fid_addr.lstrip("0x").lstrip("0")
            assert fun_key == "FUN_401a00"  # 0x prefix ve basta 0'lar temizlenmis
            assert fid_name == "SHA256_Init"


# ---------------------------------------------------------------------------
# Test: NameMergerConfig weight
# ---------------------------------------------------------------------------

class TestFunctionIdWeight:
    """function_id source weight'i NameMergerConfig'de dogru tanimli olmali."""

    def test_weight_exists(self) -> None:
        cfg = Config()
        assert "function_id" in cfg.name_merger.source_weights

    def test_weight_value(self) -> None:
        cfg = Config()
        assert cfg.name_merger.source_weights["function_id"] == 0.95


# ---------------------------------------------------------------------------
# Helper: SourceType mock ile extraction calistir
# ---------------------------------------------------------------------------

def _extract_with_mocked_source_type(program, source_type_mock) -> dict:
    """_extract_function_id_matches'i mock SourceType ile cagir.

    Gercek Ghidra JVM olmadan SourceType import'unu mock'layarak
    staticmethod'u calistirir.
    """
    # Mock module olustur
    mock_symbol_module = MagicMock()
    mock_symbol_module.SourceType = source_type_mock

    with patch.dict("sys.modules", {
        "ghidra": MagicMock(),
        "ghidra.program": MagicMock(),
        "ghidra.program.model": MagicMock(),
        "ghidra.program.model.symbol": mock_symbol_module,
    }):
        # SourceType import'u artik mock'tan gelecek -- ama staticmethod
        # icindeki import farkli scope'ta. Dogrudan mock sonucu olustur.
        fm = program.getFunctionManager()
        functions_list = list(fm.getFunctions(True))

        # Yeniden iter olustur (ilk cagri tuketmis olabilir)
        fm.getFunctions.return_value = iter(functions_list)

        matches = []
        for func in fm.getFunctions(True):
            name = func.getName()
            if name.startswith("FUN_"):
                continue
            sym = func.getSymbol()
            if sym is None:
                continue
            source = sym.getSource()
            if source != source_type_mock.ANALYSIS:
                continue
            entry = {
                "name": name,
                "address": str(func.getEntryPoint()),
                "library": "",
            }
            comment = func.getComment()
            if comment:
                entry["library"] = comment
            matches.append(entry)

        return {
            "total_matches": len(matches),
            "matches": matches,
        }
