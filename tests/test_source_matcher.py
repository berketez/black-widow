"""Source matcher birim testleri.

StructuralMatcher ve NameMapper siniflarini test eder.
ASTFingerprinter ve SourceResolver'in gercek halini kullanmaz --
mock FunctionFingerprint nesneleri ile test eder.

Calistirma:
    pytest tests/test_source_matcher.py -v
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from karadul.reconstruction.source_matcher.structural_matcher import (
    FunctionMatch,
    ModuleMatchResult,
    StructuralMatcher,
)
from karadul.reconstruction.source_matcher.name_mapper import (
    NameMapper,
    NameMapping,
)
from karadul.reconstruction.source_matcher.pipeline import (
    SourceMatchingPipeline,
    SourceMatchResult,
)


# ---------------------------------------------------------------------------
# Mock FunctionFingerprint -- gercek ASTFingerprinter'a bagimsiz test
# ---------------------------------------------------------------------------

@dataclass
class MockFingerprint:
    """Test icin basit fingerprint nesnesi.

    Gercek FunctionFingerprint'in sadece name, param_names ve similarity
    metodunu saglar -- StructuralMatcher icin yeterli.
    """

    name: str
    param_names: list[str] = field(default_factory=list)
    _similarity_map: dict[str, float] = field(default_factory=dict, repr=False)

    def similarity(self, other: MockFingerprint) -> float:
        """Onceden tanimlanmis benzerlik skorunu dondur."""
        # Isim bazli lookup (test kolayligi icin)
        return self._similarity_map.get(other.name, 0.0)


class MockFingerprinter:
    """Mock ASTFingerprinter -- extract_functions metodu sabit sonuc dondurur."""

    def __init__(self, functions: list[MockFingerprint]) -> None:
        self._functions = functions

    def extract_functions(self, code: str) -> list[MockFingerprint]:
        return self._functions


# ---------------------------------------------------------------------------
# StructuralMatcher Testleri
# ---------------------------------------------------------------------------

class TestStructuralMatcher:
    """StructuralMatcher birim testleri."""

    def test_empty_inputs(self):
        """Bos girdi bos sonuc dondurmeli."""
        matcher = StructuralMatcher(min_similarity=0.65)
        assert matcher.match([], []) == []
        assert matcher.match([MockFingerprint(name="a")], []) == []
        assert matcher.match([], [MockFingerprint(name="a")]) == []

    def test_perfect_match(self):
        """Tam eslesen fonksiyonlar dogru eslesmeli."""
        orig_a = MockFingerprint(name="registerLanguage", param_names=["name", "lang"])
        orig_b = MockFingerprint(name="getLanguage", param_names=["name"])

        min_a = MockFingerprint(
            name="a",
            param_names=["b", "c"],
            _similarity_map={"registerLanguage": 0.92, "getLanguage": 0.3},
        )
        min_b = MockFingerprint(
            name="d",
            param_names=["e"],
            _similarity_map={"registerLanguage": 0.4, "getLanguage": 0.85},
        )

        matcher = StructuralMatcher(min_similarity=0.65)
        matches = matcher.match([min_a, min_b], [orig_a, orig_b])

        assert len(matches) == 2
        # En yuksek benzerlik ilk eslesmeli
        assert matches[0].minified.name == "a"
        assert matches[0].original.name == "registerLanguage"
        assert matches[0].similarity == 0.92
        assert matches[1].minified.name == "d"
        assert matches[1].original.name == "getLanguage"
        assert matches[1].similarity == 0.85

    def test_no_match_below_threshold(self):
        """Minimum benzerlik altindaki ciftler eslesmemeli."""
        orig = MockFingerprint(name="configure", param_names=["opts"])
        minified = MockFingerprint(
            name="x",
            param_names=["y"],
            _similarity_map={"configure": 0.3},  # 0.65 altinda
        )

        matcher = StructuralMatcher(min_similarity=0.65)
        matches = matcher.match([minified], [orig])
        assert len(matches) == 0

    def test_greedy_prevents_double_match(self):
        """Ayni orijinal fonksiyon iki minified fonksiyona eslesmemeli."""
        orig = MockFingerprint(name="highlight", param_names=["code", "lang"])

        min_a = MockFingerprint(
            name="a",
            param_names=["b", "c"],
            _similarity_map={"highlight": 0.9},
        )
        min_b = MockFingerprint(
            name="d",
            param_names=["e", "f"],
            _similarity_map={"highlight": 0.8},
        )

        matcher = StructuralMatcher(min_similarity=0.65)
        matches = matcher.match([min_a, min_b], [orig])

        # Sadece en yuksek benzerlik eslesmeli
        assert len(matches) == 1
        assert matches[0].minified.name == "a"
        assert matches[0].similarity == 0.9

    def test_consistency_check_rejects_low_ratio(self):
        """Eslesen oran cok dusukse tum sonuclar reddedilmeli.

        10 minified, 10 orijinal, sadece 1 eslesme -> 1/10 = 0.1 < 0.3 esik
        (>5 fonksiyon oldugu icin kucuk modul istisnasi uygulanmaz)
        """
        orig_funcs = [
            MockFingerprint(name=f"func_{i}", param_names=[])
            for i in range(10)
        ]

        min_funcs = [
            MockFingerprint(
                name=f"m{i}",
                param_names=[],
                _similarity_map={f"func_{i}": 0.7 if i == 0 else 0.1 for i in range(10)},
            )
            for i in range(10)
        ]
        # Sadece m0 func_0 ile eslesir (0.7 > 0.65), gerisi 0.1

        matcher = StructuralMatcher(min_similarity=0.65)
        matches = matcher.match(min_funcs, orig_funcs)

        # 1/10 = 0.1 < 0.3 consistency ratio -> tumu reddedilir
        assert len(matches) == 0

    def test_consistency_check_passes(self):
        """Eslesen oran yeterli ise sonuclar kabul edilmeli.

        3 minified, 3 orijinal, 2 eslesme -> 2/3 = 0.67 > 0.3
        """
        orig_funcs = [
            MockFingerprint(name=f"func_{i}", param_names=[])
            for i in range(3)
        ]

        min_funcs = []
        for i in range(3):
            sim_map = {}
            for j in range(3):
                if i == j and i < 2:
                    sim_map[f"func_{j}"] = 0.8
                else:
                    sim_map[f"func_{j}"] = 0.1
            min_funcs.append(MockFingerprint(
                name=f"m{i}",
                param_names=[],
                _similarity_map=sim_map,
            ))

        matcher = StructuralMatcher(min_similarity=0.65)
        matches = matcher.match(min_funcs, orig_funcs)

        # 2/3 = 0.67 > 0.3 -> kabul
        assert len(matches) == 2

    def test_invalid_min_similarity(self):
        """Gecersiz min_similarity deger hatasi vermeli."""
        with pytest.raises(ValueError):
            StructuralMatcher(min_similarity=0.0)
        with pytest.raises(ValueError):
            StructuralMatcher(min_similarity=1.5)

    def test_match_module(self):
        """match_module fingerprinter ile birlikte calismali."""
        orig_funcs = [
            MockFingerprint(name="registerLanguage", param_names=["name", "lang"]),
        ]
        min_funcs = [
            MockFingerprint(
                name="a",
                param_names=["b", "c"],
                _similarity_map={"registerLanguage": 0.88},
            ),
        ]

        min_fp = MockFingerprinter(min_funcs)
        # match_module icinde iki kez extract_functions cagirir -- biri minified, biri orijinal
        # Mock'u biraz akillica yapmamiz lazim
        call_count = {"n": 0}
        original_extract = min_fp.extract_functions

        def patched_extract(code: str) -> list:
            call_count["n"] += 1
            if call_count["n"] == 1:
                return min_funcs  # minified
            return orig_funcs  # original

        min_fp.extract_functions = patched_extract

        matcher = StructuralMatcher(min_similarity=0.65)
        result = matcher.match_module("minified code", "original code", min_fp)

        assert isinstance(result, ModuleMatchResult)
        assert result.total_minified == 1
        assert result.total_original == 1
        assert result.matched == 1
        assert result.coverage == 1.0


# ---------------------------------------------------------------------------
# NameMapper Testleri
# ---------------------------------------------------------------------------

class TestNameMapper:
    """NameMapper birim testleri."""

    def test_basic_mapping(self):
        """Fonksiyon ve parametre isimleri dogru map'lenmeli."""
        matches = [
            FunctionMatch(
                minified=MockFingerprint(name="a", param_names=["b", "c"]),
                original=MockFingerprint(name="registerLanguage", param_names=["name", "lang"]),
                similarity=0.92,
            ),
        ]
        result = ModuleMatchResult(
            total_minified=1,
            total_original=1,
            matched=1,
            matches=matches,
            coverage=1.0,
        )

        mapper = NameMapper()
        mapping = mapper.map_names(result)

        assert mapping["a"] == "registerLanguage"
        assert mapping["b"] == "name"
        assert mapping["c"] == "lang"

    def test_skip_long_minified_names(self):
        """3+ karakter minified isimler map'lenmemeli (zaten anlamli olabilir)."""
        matches = [
            FunctionMatch(
                minified=MockFingerprint(name="configure", param_names=["opts"]),
                original=MockFingerprint(name="setupConfig", param_names=["options"]),
                similarity=0.8,
            ),
        ]
        result = ModuleMatchResult(
            total_minified=1, total_original=1,
            matched=1, matches=matches, coverage=1.0,
        )

        mapper = NameMapper()
        mapping = mapper.map_names(result)

        # "configure" 3+ karakter, map'lenmemeli
        assert "configure" not in mapping
        # "opts" 4 karakter, map'lenmemeli
        assert "opts" not in mapping

    def test_skip_builtin_names(self):
        """JS builtin isimleri (module, exports, this) map'lenmemeli."""
        matches = [
            FunctionMatch(
                minified=MockFingerprint(name="a", param_names=["module", "exports"]),
                original=MockFingerprint(name="init", param_names=["mod", "exp"]),
                similarity=0.8,
            ),
        ]
        result = ModuleMatchResult(
            total_minified=1, total_original=1,
            matched=1, matches=matches, coverage=1.0,
        )

        mapper = NameMapper()
        mapping = mapper.map_names(result)

        assert mapping["a"] == "init"
        # "module" ve "exports" builtin -- map'lenmemeli
        assert "module" not in mapping
        assert "exports" not in mapping

    def test_skip_meaningless_original(self):
        """Orijinal isim de anlamsizsa (tek karakter) map'lenmemeli."""
        matches = [
            FunctionMatch(
                minified=MockFingerprint(name="a", param_names=["b"]),
                original=MockFingerprint(name="x", param_names=["y"]),
                similarity=0.8,
            ),
        ]
        result = ModuleMatchResult(
            total_minified=1, total_original=1,
            matched=1, matches=matches, coverage=1.0,
        )

        mapper = NameMapper()
        mapping = mapper.map_names(result)

        # Orijinal "x" tek karakter, anlamsiz
        assert "a" not in mapping
        assert "b" not in mapping

    def test_no_duplicates(self):
        """Ayni minified isim iki farkli eslesmede varsa ilk gelen kazanir."""
        matches = [
            FunctionMatch(
                minified=MockFingerprint(name="a", param_names=[]),
                original=MockFingerprint(name="highlightBlock", param_names=[]),
                similarity=0.9,
            ),
            FunctionMatch(
                minified=MockFingerprint(name="a", param_names=[]),
                original=MockFingerprint(name="autoHighlight", param_names=[]),
                similarity=0.7,
            ),
        ]
        result = ModuleMatchResult(
            total_minified=2, total_original=2,
            matched=2, matches=matches, coverage=1.0,
        )

        mapper = NameMapper()
        mapping = mapper.map_names(result)

        # Ilk eslesmeden gelen isim
        assert mapping["a"] == "highlightBlock"

    def test_map_all_modules(self):
        """map_all_modules birden fazla modulu islemeli."""
        matches1 = [
            FunctionMatch(
                minified=MockFingerprint(name="a", param_names=["b"]),
                original=MockFingerprint(name="setup", param_names=["config"]),
                similarity=0.85,
            ),
        ]
        matches2 = [
            FunctionMatch(
                minified=MockFingerprint(name="c", param_names=[]),
                original=MockFingerprint(name="teardown", param_names=[]),
                similarity=0.78,
            ),
        ]

        module_matches = {
            "mod_1": ModuleMatchResult(1, 1, 1, matches1, 1.0),
            "mod_2": ModuleMatchResult(1, 1, 1, matches2, 1.0),
            "mod_3": ModuleMatchResult(0, 0, 0, [], 0.0),  # eslesmesi yok
        }

        mapper = NameMapper()
        all_maps = mapper.map_all_modules(module_matches)

        assert "mod_1" in all_maps
        assert all_maps["mod_1"]["a"] == "setup"
        assert "mod_2" in all_maps
        assert all_maps["mod_2"]["c"] == "teardown"
        assert "mod_3" not in all_maps  # eslesmesi yok

    def test_esbuild_3char_minified_names(self):
        """esbuild 3 karakterli minified isimler (fn2, ym9, Q88) map'lenmeli."""
        matches = [
            FunctionMatch(
                minified=MockFingerprint(name="fn2", param_names=["a1"]),
                original=MockFingerprint(name="createServer", param_names=["options"]),
                similarity=0.8,
            ),
            FunctionMatch(
                minified=MockFingerprint(name="ym9", param_names=["b2"]),
                original=MockFingerprint(name="handleRequest", param_names=["request"]),
                similarity=0.85,
            ),
        ]
        result = ModuleMatchResult(
            total_minified=2, total_original=2,
            matched=2, matches=matches, coverage=1.0,
        )

        mapper = NameMapper()
        mapping = mapper.map_names(result)

        # esbuild 3-char names should be treated as minified
        assert mapping.get("fn2") == "createServer"
        assert mapping.get("ym9") == "handleRequest"
        assert mapping.get("a1") == "options"
        assert mapping.get("b2") == "request"

    def test_3char_meaningful_names_not_mapped(self):
        """3 karakterli anlamli isimler (Map, Set, URL) map'lenmemeli."""
        matches = [
            FunctionMatch(
                minified=MockFingerprint(name="Map", param_names=["key"]),
                original=MockFingerprint(name="createMap", param_names=["initialKey"]),
                similarity=0.8,
            ),
            FunctionMatch(
                minified=MockFingerprint(name="SDK", param_names=[]),
                original=MockFingerprint(name="initSDK", param_names=[]),
                similarity=0.8,
            ),
        ]
        result = ModuleMatchResult(
            total_minified=2, total_original=2,
            matched=2, matches=matches, coverage=1.0,
        )

        mapper = NameMapper()
        mapping = mapper.map_names(result)

        # All-uppercase 3-char names (SDK) are NOT minified (abbreviations)
        assert "SDK" not in mapping
        # "Map" is in _SKIP_NAMES
        assert "Map" not in mapping

    def test_detailed_mapping(self):
        """map_names_detailed NameMapping nesneleri dondurmeli."""
        matches = [
            FunctionMatch(
                minified=MockFingerprint(name="a", param_names=["b", "c"]),
                original=MockFingerprint(name="registerLanguage", param_names=["name", "lang"]),
                similarity=0.92,
            ),
        ]
        result = ModuleMatchResult(
            total_minified=1, total_original=1,
            matched=1, matches=matches, coverage=1.0,
        )

        mapper = NameMapper()
        detailed = mapper.map_names_detailed(result)

        assert len(detailed) == 3  # 1 fonksiyon + 2 parametre
        assert all(isinstance(d, NameMapping) for d in detailed)

        func_maps = [d for d in detailed if d.kind == "function"]
        param_maps = [d for d in detailed if d.kind == "parameter"]
        assert len(func_maps) == 1
        assert len(param_maps) == 2


# ---------------------------------------------------------------------------
# SourceMatchResult Testleri
# ---------------------------------------------------------------------------

class TestSourceMatchResult:
    """SourceMatchResult veri yapisi testleri."""

    def test_empty_result(self):
        """Bos sonuc is_empty olmali."""
        result = SourceMatchResult(mappings={})
        assert result.is_empty
        assert "0" in repr(result) or "modules=0" in repr(result)

    def test_non_empty_result(self):
        """Dolu sonuc is_empty olmamali."""
        result = SourceMatchResult(
            mappings={"mod_1": {"a": "setup"}},
            stats={
                "packages_resolved": 1,
                "modules_processed": 1,
                "functions_matched": 3,
                "names_recovered": 5,
            },
        )
        assert not result.is_empty
        assert result.stats["names_recovered"] == 5


# ---------------------------------------------------------------------------
# Pipeline Testleri (SourceResolver/ASTFingerprinter mock ile)
# ---------------------------------------------------------------------------

class TestSourceMatchingPipeline:
    """SourceMatchingPipeline entegrasyon testi (mock dependency'lerle)."""

    def test_pipeline_without_dependencies(self):
        """SourceResolver/ASTFingerprinter yoksa graceful degrade etmeli."""
        pipeline = SourceMatchingPipeline(
            config=None,
            resolver=None,
            fingerprinter=None,
        )
        # resolver None -> bos sonuc
        result = pipeline.run(
            modules_dir=None,  # type: ignore
            npm_results=[],
        )
        assert result.is_empty

    def test_pipeline_no_npm_results(self):
        """npm eslesmesi yoksa bos sonuc dondurmeli."""
        pipeline = SourceMatchingPipeline(
            config=None,
            resolver="dummy_resolver",  # None degil, kontrol gecsin
            fingerprinter="dummy_fp",
        )
        result = pipeline.run(
            modules_dir=None,  # type: ignore
            npm_results=[],  # bos
        )
        assert result.is_empty
