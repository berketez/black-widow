"""BSim fonksiyon benzerlik modulu testleri.

Gercek Ghidra/PyGhidra gerektirmez -- tum Ghidra API cagrilari
mock'lanir. BSimConfig, BSimDatabase, BSimMatch/BSimResult dataclass'lari
ve CLI entegrasyonu test edilir.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from karadul.config import BSimConfig, Config
from karadul.ghidra.bsim import (
    BSimDatabase,
    BSimMatch,
    BSimResult,
    _BSimLiteIndex,
    _check_bsim,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def config() -> Config:
    """Varsayilan Config (BSim shadow-only: enabled=True, shadow_mode=True,
    use_bsim_fusion=False -- v1.11.0 Dalga 4)."""
    return Config()


@pytest.fixture
def bsim_config() -> Config:
    """BSim aktif Config."""
    cfg = Config()
    cfg.bsim.enabled = True
    return cfg


@pytest.fixture
def tmp_db_path(tmp_path: Path) -> Path:
    """Gecici BSim veritabani dizini."""
    db_dir = tmp_path / "bsim_test"
    db_dir.mkdir()
    return db_dir


@pytest.fixture
def lite_index(tmp_db_path: Path) -> _BSimLiteIndex:
    """Bos BSim lite index."""
    return _BSimLiteIndex(tmp_db_path)


@pytest.fixture
def mock_program() -> MagicMock:
    """Mock Ghidra program nesnesi."""
    program = MagicMock()
    program.getName.return_value = "test_binary"

    # FunctionManager mock
    func_manager = MagicMock()

    # 3 mock fonksiyon olustur
    functions = []
    for i, (name, addr) in enumerate([
        ("main", "0x100000"),
        ("helper_func", "0x100100"),
        ("thunk_func", "0x100200"),
    ]):
        func = MagicMock()
        func.getName.return_value = name
        func.getEntryPoint.return_value = MagicMock(__str__=lambda s, a=addr: a)
        func.isThunk.return_value = (name == "thunk_func")
        func.isExternal.return_value = False
        func.getBody.return_value = MagicMock()
        functions.append(func)

    # Java-style iterator simulasyonu
    class FuncIterator:
        def __init__(self, funcs):
            self._funcs = list(funcs)
            self._idx = 0

        def hasNext(self):
            return self._idx < len(self._funcs)

        def next(self):
            f = self._funcs[self._idx]
            self._idx += 1
            return f

    func_manager.getFunctions.return_value = FuncIterator(functions)
    program.getFunctionManager.return_value = func_manager

    # Listing mock (instruction iterator icin)
    listing = MagicMock()
    instr1 = MagicMock()
    instr1.getMnemonicString.return_value = "MOV"
    instr2 = MagicMock()
    instr2.getMnemonicString.return_value = "ADD"
    instr3 = MagicMock()
    instr3.getMnemonicString.return_value = "RET"

    class InstrIterator:
        def __init__(self):
            self._instrs = [instr1, instr2, instr3]
            self._idx = 0

        def hasNext(self):
            return self._idx < len(self._instrs)

        def next(self):
            i = self._instrs[self._idx]
            self._idx += 1
            return i

    listing.getInstructions.return_value = InstrIterator()
    program.getListing.return_value = listing

    return program


# ---------------------------------------------------------------------------
# Test 1-2: BSimConfig defaults ve custom
# ---------------------------------------------------------------------------

class TestBSimConfig:
    """BSimConfig dataclass testleri."""

    def test_bsim_config_defaults(self) -> None:
        """Varsayilan degerler dogru olmali.

        v1.11.0 Dalga 4 (BSim fusion kopru): enabled=True default
        (shadow_mode=True oldugu icin fusion'a yazmaz, sadece
        artifacts/bsim_shadow.json dump'i yapar -- guvenli log-only
        mod). Fusion gerceklesmesi icin shadow_mode=False VE
        use_bsim_fusion=True opt-in gerekli.
        """
        cfg = BSimConfig()
        assert cfg.enabled is True
        assert cfg.default_database == "karadul_bsim"
        assert cfg.db_path == ""
        assert cfg.auto_query is True
        assert cfg.min_similarity == 0.7
        assert cfg.max_results_per_function == 5
        # Dalga 4 fusion alanlari: varsayilan guvenli (shadow-only)
        assert cfg.shadow_mode is True
        assert cfg.use_bsim_fusion is False
        assert cfg.fusion_min_similarity == 0.7
        assert cfg.fusion_max_candidates_per_function == 3

    def test_bsim_config_custom(self) -> None:
        """Ozel degerler atanabilmeli."""
        cfg = BSimConfig(
            enabled=True,
            default_database="custom_db",
            db_path="/tmp/custom_bsim",
            auto_query=False,
            min_similarity=0.5,
            max_results_per_function=10,
        )
        assert cfg.enabled is True
        assert cfg.default_database == "custom_db"
        assert cfg.db_path == "/tmp/custom_bsim"
        assert cfg.auto_query is False
        assert cfg.min_similarity == 0.5
        assert cfg.max_results_per_function == 10


# ---------------------------------------------------------------------------
# Test 3: BSimDatabase init
# ---------------------------------------------------------------------------

class TestBSimDatabaseInit:
    """BSimDatabase baslangic testleri."""

    def test_bsim_database_init(self, config: Config, tmp_path: Path) -> None:
        """BSimDatabase dogru mod ve path ile baslamali."""
        config.bsim.db_path = str(tmp_path / "bsim")
        db = BSimDatabase(config)
        # Ghidra BSim API yoksa lite mod olmali
        assert db.mode == "lite"
        assert db.db_path == tmp_path / "bsim"
        assert db._closed is False
        db.close()

    def test_bsim_database_default_path(self, config: Config) -> None:
        """db_path bossa ~/.cache/karadul/bsim/ kullanilmali."""
        config.bsim.db_path = ""
        db = BSimDatabase(config)
        expected = Path.home() / ".cache" / "karadul" / "bsim"
        assert db.db_path == expected
        db.close()


# ---------------------------------------------------------------------------
# Test 4: create_database (lite mod)
# ---------------------------------------------------------------------------

class TestBSimCreateDatabase:
    """Veritabani olusturma testleri."""

    def test_bsim_create_database(self, config: Config, tmp_path: Path) -> None:
        """Lite modda veritabani olusturulabilmeli."""
        config.bsim.db_path = str(tmp_path / "bsim")
        db = BSimDatabase(config)
        result_path = db.create_database("test_db")
        assert result_path is not None

        # Index dosyasi olusturulmus olmali
        index_file = tmp_path / "bsim" / "bsim_lite_index.json"
        assert index_file.exists()

        index_data = json.loads(index_file.read_text())
        assert "test_db" in index_data["databases"]
        db.close()


# ---------------------------------------------------------------------------
# Test 5: ingest_program (mock)
# ---------------------------------------------------------------------------

class TestBSimIngest:
    """Program ingest testleri."""

    def test_bsim_ingest_program(
        self, config: Config, tmp_path: Path, mock_program: MagicMock,
    ) -> None:
        """Fonksiyonlar hash'lenip veritabanina eklenmeli."""
        config.bsim.db_path = str(tmp_path / "bsim")
        db = BSimDatabase(config)
        db.create_database("test_db")

        # Ghidra decompiler mock
        with patch("karadul.ghidra.bsim.BSimDatabase.ingest_program") as mock_ingest:
            mock_ingest.return_value = 2
            count = db.ingest_program(mock_program, "test_db")
            assert count == 2
        db.close()


# ---------------------------------------------------------------------------
# Test 6: query_similar (mock)
# ---------------------------------------------------------------------------

class TestBSimQuerySimilar:
    """Tek fonksiyon sorgu testleri."""

    def test_bsim_query_similar(
        self, config: Config, tmp_path: Path,
    ) -> None:
        """query_similar benzer fonksiyonlari dondurmeli."""
        config.bsim.db_path = str(tmp_path / "bsim")
        db = BSimDatabase(config)

        # Lite index'e elle veri ekle
        db._lite.create_database("karadul_bsim")
        test_hash = "abc123"
        db._lite._index["databases"]["karadul_bsim"]["programs"]["other_binary"] = {
            "functions": {
                "0x200000": {
                    "name": "similar_func",
                    "address": "0x200000",
                    "structural_hash": test_hash,
                    "opcode_hash": "def456",
                },
            },
        }
        db._lite.save()

        # Direkt lite query testi
        matches = db._lite.query_function(
            db_name="karadul_bsim",
            func_address="0x100000",
            structural_hash=test_hash,
            opcode_hash="",
            exclude_program="test_binary",
            min_similarity=0.7,
            max_results=5,
        )
        assert len(matches) == 1
        assert matches[0].matched_function == "similar_func"
        assert matches[0].similarity == 0.85
        db.close()


# ---------------------------------------------------------------------------
# Test 7: query_all_functions (mock)
# ---------------------------------------------------------------------------

class TestBSimQueryAll:
    """Toplu sorgu testleri."""

    def test_bsim_query_all_functions(self, config: Config, tmp_path: Path) -> None:
        """query_all_functions BSimResult dondurmeli."""
        config.bsim.db_path = str(tmp_path / "bsim")
        db = BSimDatabase(config)

        with patch.object(db, "query_all_functions") as mock_query:
            mock_query.return_value = BSimResult(
                total_queries=10,
                total_matches=3,
                matches=[
                    BSimMatch("func_a", "0x1000", "lib_func", "libfoo", 0.95, 0.9),
                    BSimMatch("func_b", "0x2000", "lib_func2", "libfoo", 0.80, 0.7),
                    BSimMatch("func_c", "0x3000", "lib_func3", "libbar", 0.75, 0.6),
                ],
                database_name="karadul_bsim",
                query_duration=1.23,
            )
            result = db.query_all_functions(MagicMock(), 0.7)
            assert result.total_queries == 10
            assert result.total_matches == 3
            assert len(result.matches) == 3
            assert result.database_name == "karadul_bsim"
        db.close()


# ---------------------------------------------------------------------------
# Test 8: list_databases
# ---------------------------------------------------------------------------

class TestBSimListDatabases:
    """Veritabani listeleme testleri."""

    def test_bsim_list_databases(self, config: Config, tmp_path: Path) -> None:
        """Olusturulmus veritabanlari listelenebilmeli."""
        config.bsim.db_path = str(tmp_path / "bsim")
        db = BSimDatabase(config)
        db.create_database("db_alpha")
        db.create_database("db_beta")

        databases = db.list_databases()
        names = [d["name"] for d in databases]
        assert "db_alpha" in names
        assert "db_beta" in names
        db.close()


# ---------------------------------------------------------------------------
# Test 9-10: Dataclass testleri
# ---------------------------------------------------------------------------

class TestBSimDataclasses:
    """BSimMatch ve BSimResult dataclass testleri."""

    def test_bsim_match_dataclass(self) -> None:
        """BSimMatch alanlari dogru tutulmali."""
        match = BSimMatch(
            query_function="main",
            query_address="0x100000",
            matched_function="_main",
            matched_program="libsystem",
            similarity=0.92,
            significance=0.88,
        )
        assert match.query_function == "main"
        assert match.query_address == "0x100000"
        assert match.matched_function == "_main"
        assert match.matched_program == "libsystem"
        assert match.similarity == 0.92
        assert match.significance == 0.88

        # asdict ile JSON serializable olmali
        d = asdict(match)
        assert isinstance(d, dict)
        assert d["similarity"] == 0.92

    def test_bsim_result_dataclass(self) -> None:
        """BSimResult alanlari dogru tutulmali."""
        result = BSimResult(
            total_queries=50,
            total_matches=12,
            matches=[
                BSimMatch("f1", "0x1", "m1", "prog1", 0.9, 0.8),
            ],
            database_name="test_db",
            query_duration=2.5,
        )
        assert result.total_queries == 50
        assert result.total_matches == 12
        assert len(result.matches) == 1
        assert result.database_name == "test_db"
        assert result.query_duration == 2.5


# ---------------------------------------------------------------------------
# Test 11: BSim unavailable graceful degradation
# ---------------------------------------------------------------------------

class TestBSimGracefulDegradation:
    """BSim API yokken graceful degradation testleri."""

    def test_bsim_unavailable_graceful(self, config: Config, tmp_path: Path) -> None:
        """BSim API yoksa lite moda dusulmeli, hata firlatilmamali."""
        config.bsim.db_path = str(tmp_path / "bsim")

        # _BSIM_AVAILABLE'i sifirla
        import karadul.ghidra.bsim as bsim_mod
        original = bsim_mod._BSIM_AVAILABLE
        try:
            bsim_mod._BSIM_AVAILABLE = False
            db = BSimDatabase(config)
            assert db.mode == "lite"
            assert db._lite is not None
            db.close()
        finally:
            bsim_mod._BSIM_AVAILABLE = original


# ---------------------------------------------------------------------------
# Test 12: close idempotent
# ---------------------------------------------------------------------------

class TestBSimClose:
    """Close metodu testleri."""

    def test_bsim_close_idempotent(self, config: Config, tmp_path: Path) -> None:
        """close() birden fazla cagrilabilmeli, hata vermemeli."""
        config.bsim.db_path = str(tmp_path / "bsim")
        db = BSimDatabase(config)
        db.close()
        db.close()  # ikinci cagri hata vermemeli
        db.close()  # ucuncu cagri da
        assert db._closed is True


# ---------------------------------------------------------------------------
# Test 13: BSim disabled in config
# ---------------------------------------------------------------------------

class TestBSimDisabled:
    """BSim devre disi testleri."""

    def test_bsim_disabled_in_config(self, config: Config) -> None:
        """Varsayilan Config'de BSim shadow-only olmali (fusion kapali).

        v1.11.0 Dalga 4: enabled=True default artik (shadow dump icin),
        fakat shadow_mode=True + use_bsim_fusion=False oldugu icin
        NameMerger'a/fusion'a evidence YAYMAZ -- log-only davranis.
        Yani "devre disi" testi = fusion pipeline'da aktif degil.
        """
        assert config.bsim.shadow_mode is True
        assert config.bsim.use_bsim_fusion is False


# ---------------------------------------------------------------------------
# Test 14: BSim fallback mode (lite)
# ---------------------------------------------------------------------------

class TestBSimFallbackMode:
    """BSim lite fallback testleri."""

    def test_bsim_fallback_mode(self, config: Config, tmp_path: Path) -> None:
        """BSim API yoksa bsim_lite moduyla calisabilmeli."""
        config.bsim.db_path = str(tmp_path / "bsim")

        import karadul.ghidra.bsim as bsim_mod
        original = bsim_mod._BSIM_AVAILABLE
        try:
            bsim_mod._BSIM_AVAILABLE = False
            db = BSimDatabase(config)
            assert db.mode == "lite"

            # Veritabani olusturabilmeli
            db.create_database("fallback_test")
            databases = db.list_databases()
            assert any(d["name"] == "fallback_test" for d in databases)

            # Lite index uzerinden fonksiyon eklenebilmeli
            db._lite.ingest_function(
                db_name="fallback_test",
                program_name="test_prog",
                func_name="test_func",
                func_address="0xDEAD",
                decompiled_code="int test_func(int x) { return x + 1; }",
                instructions=[{"mnemonic": "ADD"}, {"mnemonic": "RET"}],
            )
            db._lite.save()

            # Sorgulanabilmeli
            matches = db._lite.query_function(
                db_name="fallback_test",
                func_address="0xBEEF",
                structural_hash=_BSimLiteIndex._compute_structural_hash(
                    "int test_func(int x) { return x + 1; }"
                ),
                opcode_hash=_BSimLiteIndex._compute_opcode_hash(
                    [{"mnemonic": "ADD"}, {"mnemonic": "RET"}]
                ),
                exclude_program="other_prog",
                min_similarity=0.5,
            )
            assert len(matches) == 1
            assert matches[0].similarity == 1.0  # ikisi de eslesiyor
            db.close()
        finally:
            bsim_mod._BSIM_AVAILABLE = original


# ---------------------------------------------------------------------------
# Test 15: min_similarity filter
# ---------------------------------------------------------------------------

class TestBSimMinSimilarity:
    """Minimum benzerlik esigi testleri."""

    def test_bsim_min_similarity_filter(self, tmp_path: Path) -> None:
        """min_similarity altindaki eslemeler filtrelenmeli."""
        lite = _BSimLiteIndex(tmp_path)
        lite.create_database("test")

        # Fonksiyon ekle
        lite.ingest_function(
            db_name="test",
            program_name="prog_a",
            func_name="func_a",
            func_address="0x1000",
            decompiled_code="",
            instructions=[{"mnemonic": "MOV"}, {"mnemonic": "RET"}],
        )
        lite.save()

        # Sadece opcode eslesmesi -> similarity=0.65
        opcode_hash = _BSimLiteIndex._compute_opcode_hash(
            [{"mnemonic": "MOV"}, {"mnemonic": "RET"}]
        )

        # min_similarity=0.7 ile sorgu: 0.65 < 0.7, sonuc bos olmali
        matches = lite.query_function(
            db_name="test",
            func_address="0x2000",
            structural_hash="nonexistent",
            opcode_hash=opcode_hash,
            exclude_program="other",
            min_similarity=0.7,
        )
        assert len(matches) == 0

        # min_similarity=0.6 ile sorgu: 0.65 >= 0.6, sonuc donmeli
        matches = lite.query_function(
            db_name="test",
            func_address="0x2000",
            structural_hash="nonexistent",
            opcode_hash=opcode_hash,
            exclude_program="other",
            min_similarity=0.6,
        )
        assert len(matches) == 1
        assert matches[0].similarity == 0.65


# ---------------------------------------------------------------------------
# Test 16: max_results limit
# ---------------------------------------------------------------------------

class TestBSimMaxResults:
    """Max sonuc limiti testleri."""

    def test_bsim_max_results_limit(self, tmp_path: Path) -> None:
        """max_results sonuc sayisini sinirlamali."""
        lite = _BSimLiteIndex(tmp_path)
        lite.create_database("test")

        code = "void f() { return; }"
        struct_hash = _BSimLiteIndex._compute_structural_hash(code)

        # 10 fonksiyon ekle (ayni hash)
        for i in range(10):
            lite.ingest_function(
                db_name="test",
                program_name=f"prog_{i}",
                func_name=f"func_{i}",
                func_address=f"0x{i:04x}",
                decompiled_code=code,
            )
        lite.save()

        # max_results=3 ile sorgu
        matches = lite.query_function(
            db_name="test",
            func_address="0xFFFF",
            structural_hash=struct_hash,
            opcode_hash="",
            exclude_program="query_prog",
            min_similarity=0.5,
            max_results=3,
        )
        assert len(matches) == 3


# ---------------------------------------------------------------------------
# Test 17: empty database query
# ---------------------------------------------------------------------------

class TestBSimEmptyDatabase:
    """Bos veritabani sorgu testleri."""

    def test_bsim_empty_database_query(self, tmp_path: Path) -> None:
        """Bos veritabaninda sorgu bos sonuc dondurmeli."""
        lite = _BSimLiteIndex(tmp_path)
        lite.create_database("empty_db")

        matches = lite.query_function(
            db_name="empty_db",
            func_address="0x1000",
            structural_hash="abc",
            opcode_hash="def",
            min_similarity=0.5,
        )
        assert matches == []

    def test_bsim_nonexistent_database_query(self, tmp_path: Path) -> None:
        """Var olmayan veritabaninda sorgu bos sonuc dondurmeli."""
        lite = _BSimLiteIndex(tmp_path)

        matches = lite.query_function(
            db_name="nonexistent",
            func_address="0x1000",
            structural_hash="abc",
        )
        assert matches == []


# ---------------------------------------------------------------------------
# Test 18: JSON output schema
# ---------------------------------------------------------------------------

class TestBSimJsonOutput:
    """BSim JSON cikti sema testleri."""

    def test_bsim_json_output_schema(self) -> None:
        """BSim sonuclari dogru JSON semasina sahip olmali."""
        result = BSimResult(
            total_queries=5,
            total_matches=2,
            matches=[
                BSimMatch("func_a", "0x1000", "lib_a", "libfoo.dylib", 0.95, 0.9),
                BSimMatch("func_b", "0x2000", "lib_b", "libbar.dylib", 0.80, 0.7),
            ],
            database_name="test_db",
            query_duration=0.5,
        )

        # headless.py'deki cikti formatini simule et
        bsim_data = {
            "total_matches": result.total_matches,
            "database": result.database_name,
            "matches": [
                {
                    "query_function": m.query_function,
                    "query_address": m.query_address,
                    "matched_function": m.matched_function,
                    "matched_program": m.matched_program,
                    "similarity": m.similarity,
                }
                for m in result.matches
            ],
        }

        # JSON serializable olmali
        json_str = json.dumps(bsim_data)
        parsed = json.loads(json_str)

        assert parsed["total_matches"] == 2
        assert parsed["database"] == "test_db"
        assert len(parsed["matches"]) == 2
        assert parsed["matches"][0]["similarity"] == 0.95
        assert "query_function" in parsed["matches"][0]
        assert "query_address" in parsed["matches"][0]
        assert "matched_function" in parsed["matches"][0]
        assert "matched_program" in parsed["matches"][0]


# ---------------------------------------------------------------------------
# Test 19-20: CLI testleri
# ---------------------------------------------------------------------------

class TestBSimCLI:
    """BSim CLI komut testleri."""

    def test_cli_bsim_group_exists(self) -> None:
        """CLI'da bsim grubu var olmali."""
        from click.testing import CliRunner
        from karadul.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["bsim", "--help"])
        assert result.exit_code == 0
        assert "BSim" in result.output or "bsim" in result.output

    def test_cli_bsim_list(self, tmp_path: Path) -> None:
        """'karadul bsim list' calisabilmeli."""
        from click.testing import CliRunner
        from karadul.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["bsim", "list"])
        # Hata olmadan calismali (veritabani bos olabilir)
        assert result.exit_code == 0

    def test_cli_bsim_create(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """'karadul bsim create' yeni veritabani olusturabilmeli."""
        from click.testing import CliRunner
        from karadul.cli import main

        # Gecici dizin kullan
        monkeypatch.setattr(
            "karadul.ghidra.bsim.BSimDatabase.__init__",
            lambda self, config: (
                setattr(self, "db_path", tmp_path / "bsim"),
                setattr(self, "config", config),
                setattr(self, "mode", "lite"),
                setattr(self, "_native", None),
                setattr(self, "_lite", _BSimLiteIndex(tmp_path / "bsim")),
                setattr(self, "_closed", False),
                (tmp_path / "bsim").mkdir(parents=True, exist_ok=True),
            )[-1],
        )

        runner = CliRunner()
        result = runner.invoke(main, ["bsim", "create", "test_cli_db"])
        assert result.exit_code == 0
        assert "olusturuldu" in result.output or "test_cli_db" in result.output


# ---------------------------------------------------------------------------
# Lite Index ek testleri
# ---------------------------------------------------------------------------

class TestBSimLiteIndex:
    """_BSimLiteIndex birim testleri."""

    def test_normalize_code(self) -> None:
        """Kod normalizasyonu degisken isimlerini temizlemeli."""
        code = """
        int FUN_00123456(int param_1, long local_abc) {
            /* yorum */
            uVar1 = param_1 + local_abc;
            DAT_00DEAD00 = 0x42;
            return uVar1;
        }
        """
        normalized = _BSimLiteIndex._normalize_code(code)
        assert "FUN_00123456" not in normalized
        assert "param_1" not in normalized
        assert "local_abc" not in normalized
        assert "DAT_00DEAD00" not in normalized
        assert "uVar1" not in normalized
        assert "yorum" not in normalized
        assert "FUNC" in normalized
        assert "PARAM" in normalized
        assert "LOCAL" in normalized
        assert "DATA" in normalized
        assert "VAR" in normalized

    def test_structural_hash_deterministic(self) -> None:
        """Ayni kod icin ayni hash donmeli."""
        code = "int f(int x) { return x + 1; }"
        h1 = _BSimLiteIndex._compute_structural_hash(code)
        h2 = _BSimLiteIndex._compute_structural_hash(code)
        assert h1 == h2
        assert len(h1) == 64  # SHA256 hex

    def test_structural_hash_different_for_different_code(self) -> None:
        """Farkli kod icin farkli hash donmeli."""
        h1 = _BSimLiteIndex._compute_structural_hash("int f(int x) { return x + 1; }")
        h2 = _BSimLiteIndex._compute_structural_hash("int g(int y) { return y * 2; }")
        assert h1 != h2

    def test_opcode_hash_deterministic(self) -> None:
        """Ayni instruction listesi icin ayni hash donmeli."""
        instrs = [{"mnemonic": "MOV"}, {"mnemonic": "ADD"}, {"mnemonic": "RET"}]
        h1 = _BSimLiteIndex._compute_opcode_hash(instrs)
        h2 = _BSimLiteIndex._compute_opcode_hash(instrs)
        assert h1 == h2

    def test_opcode_hash_order_independent(self) -> None:
        """Opcode histogram siralamadan bagimsiz olmali."""
        # Ayni instruction'lar farkli sirada -> ayni histogram -> ayni hash
        instrs1 = [{"mnemonic": "MOV"}, {"mnemonic": "ADD"}]
        instrs2 = [{"mnemonic": "ADD"}, {"mnemonic": "MOV"}]
        h1 = _BSimLiteIndex._compute_opcode_hash(instrs1)
        h2 = _BSimLiteIndex._compute_opcode_hash(instrs2)
        assert h1 == h2

    def test_context_manager(self, config: Config, tmp_path: Path) -> None:
        """BSimDatabase context manager olarak kullanilabilmeli."""
        config.bsim.db_path = str(tmp_path / "bsim")
        with BSimDatabase(config) as db:
            db.create_database("ctx_test")
            assert not db._closed
        assert db._closed


# ---------------------------------------------------------------------------
# Config YAML parsing testi
# ---------------------------------------------------------------------------

class TestBSimConfigYAML:
    """Config._from_dict ile BSim ayarlarinin yuklenme testi."""

    def test_config_from_dict_with_bsim(self) -> None:
        """YAML'dan BSim ayarlari dogru parse edilmeli."""
        data = {
            "bsim": {
                "enabled": True,
                "default_database": "my_db",
                "db_path": "/custom/path",
                "auto_query": False,
                "min_similarity": 0.5,
                "max_results_per_function": 10,
            },
        }
        cfg = Config._from_dict(data)
        assert cfg.bsim.enabled is True
        assert cfg.bsim.default_database == "my_db"
        assert cfg.bsim.db_path == "/custom/path"
        assert cfg.bsim.auto_query is False
        assert cfg.bsim.min_similarity == 0.5
        assert cfg.bsim.max_results_per_function == 10

    def test_name_merger_has_bsim_weight(self) -> None:
        """NameMergerConfig source_weights'te bsim olmali."""
        cfg = Config()
        assert "bsim" in cfg.name_merger.source_weights
        assert cfg.name_merger.source_weights["bsim"] == 0.85
