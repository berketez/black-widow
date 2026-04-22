"""Readability scorer testleri -- karadul.quality paketi.

6 boyut (fonksiyon, parametre, lokal, tip, yorum, kod yapisi)
ve ReadabilityScorer orchestration davranislari icin sureli testler.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from karadul.quality import (
    CompareResult,
    DwarfBaseline,
    ReadabilityScorer,
    ScoreResult,
    ScorerConfig,
)
from karadul.quality.dwarf_baseline import DwarfBaselineResult
from karadul.quality.metrics import (
    CodeStructureMetric,
    CommentsMetric,
    FunctionNamesMetric,
    LocalVarsMetric,
    ParamNamesMetric,
    TypeQualityMetric,
)


# ---------------------------------------------------------------------------
# Fixture yardimcilari
# ---------------------------------------------------------------------------

def _write(path: Path, content: str) -> Path:
    """Dizini garanti altina alip dosya yaz."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


@pytest.fixture
def mixed_names_src(tmp_path: Path) -> list[Path]:
    """10 fonksiyondan 5'i FUN_XXX, 5'i anlamli (ingilizce kokler)."""
    body = "\n".join([
        # Anlamli isimler -- COMMON_ENGLISH_ROOTS icinden kelimeler
        "int read_buffer(int count) { return count; }",
        "int write_data(char *data) { return 0; }",
        "void init_state(int flag) { return; }",
        "int parse_packet(char *buf) { return 1; }",
        "int compute_hash(int value) { return value; }",
        # Ghidra varsayilan isimler
        "int FUN_00401000(int a) { return a; }",
        "int FUN_00401020(int a) { return a; }",
        "int FUN_00401040(int a) { return a; }",
        "int FUN_00401060(int a) { return a; }",
        "int FUN_00401080(int a) { return a; }",
    ])
    file = _write(tmp_path / "mixed.c", body)
    return [file]


@pytest.fixture
def param_mixed_src(tmp_path: Path) -> list[Path]:
    """5 fonksiyon -- yari param_N, yari anlamli."""
    body = "\n".join([
        "int f1(int param_1, int param_2) { return param_1; }",
        "int f2(int param_1, int param_2) { return param_1; }",
        "int f3(int count, int buffer) { return count; }",
        "int f4(int size, int offset) { return size; }",
        "int f5(int value, int index) { return value; }",
    ])
    file = _write(tmp_path / "params.c", body)
    return [file]


@pytest.fixture
def local_vars_src(tmp_path: Path) -> list[Path]:
    """Lokal variable ornegi -- yari iVar/lVar, yari anlamli."""
    body = "int f(void) {\n"
    body += "    int iVar1;\n"
    body += "    long lVar2;\n"
    body += "    unsigned int uVar3;\n"
    body += "    char *pcVar4;\n"
    body += "    int local_10;\n"
    body += "    int user_count;\n"
    body += "    long buffer_size;\n"
    body += "    int packet_index;\n"
    body += "    char *data_ptr;\n"
    body += "    int result_code;\n"
    body += "    return 0;\n"
    body += "}\n"
    file = _write(tmp_path / "locals.c", body)
    return [file]


@pytest.fixture
def type_mixed_src(tmp_path: Path) -> list[Path]:
    """Tip cesitli -- undefined8 vs gercek tipler."""
    body = "\n".join([
        "int f1(int a) { int x; return x; }",
        "undefined8 f2(undefined8 b) { undefined4 y; return y; }",
        "char f3(char c) { char z; return z; }",
        "undefined8 f4(undefined8 d) { undefined8 w; return w; }",
    ])
    file = _write(tmp_path / "types.c", body)
    return [file]


@pytest.fixture
def commented_src(tmp_path: Path) -> list[Path]:
    """100 fonksiyon, 50 yorum satiri olan ornek."""
    lines: list[str] = []
    for i in range(100):
        if i % 2 == 0:
            lines.append(f"// Fonksiyon {i} -- yorum")
        lines.append(f"int f_{i}(void) {{ return {i}; }}")
    file = _write(tmp_path / "commented.c", "\n".join(lines))
    return [file]


@pytest.fixture
def structured_src(tmp_path: Path) -> list[Path]:
    """goto ve derin nesting iceren fonksiyon."""
    body = (
        "int work(int x) {\n"
        "    if (x > 0) {\n"
        "        if (x < 100) {\n"
        "            for (int i = 0; i < x; i++) {\n"
        "                if (i == 5) {\n"
        "                    goto end;\n"
        "                }\n"
        "            }\n"
        "        }\n"
        "    }\n"
        "    end:\n"
        "    return x;\n"
        "}\n"
    )
    file = _write(tmp_path / "structure.c", body)
    return [file]


@pytest.fixture
def clean_src(tmp_path: Path) -> list[Path]:
    """Temiz, anlamli, az nesting'li ornek -- yuksek skor almali."""
    body = (
        "// Iyi dokumante edilmis fonksiyon\n"
        "int read_file(char *path, int size) {\n"
        "    int result = 0;\n"
        "    int buffer_length = size;\n"
        "    return result;\n"
        "}\n"
        "\n"
        "// Init rutini\n"
        "int init_state(int flag_value) {\n"
        "    int state = flag_value;\n"
        "    return state;\n"
        "}\n"
    )
    file = _write(tmp_path / "clean.c", body)
    return [file]


# ---------------------------------------------------------------------------
# 1. Scorer init
# ---------------------------------------------------------------------------

def test_scorer_init():
    """ReadabilityScorer default config ile 6 metric kayitli baslatilmali."""
    scorer = ReadabilityScorer()
    assert scorer.config.total_weight() == pytest.approx(1.0, abs=1e-6)
    assert len(scorer._metrics) == 6
    expected_names = {
        "function_names", "param_names", "local_vars",
        "type_quality", "comments", "code_structure",
    }
    assert set(scorer._metrics.keys()) == expected_names


def test_scorer_config_validate_fail():
    """Bozuk config validate ile ValueError vermeli."""
    cfg = ScorerConfig(weight_function_names=0.99)
    with pytest.raises(ValueError):
        cfg.validate()


def test_scorer_repr():
    """__repr__ metric ve agirlik toplamini vermeli."""
    scorer = ReadabilityScorer()
    rep = repr(scorer)
    assert "ReadabilityScorer" in rep
    assert "function_names" in rep


# ---------------------------------------------------------------------------
# 2. Fonksiyon isimleri
# ---------------------------------------------------------------------------

def test_function_names_metric_mixed(mixed_names_src):
    """10 fonksiyonun 5'i FUN_ olursa base_score ~50 ve yuksek dict match."""
    metric = FunctionNamesMetric()
    result = metric.score(mixed_names_src)

    # 5 FUN_ + 5 anlamli (read, write, init, parse, compute -- hepsi common root)
    assert result.details["total"] == 10
    assert result.details["generic_count"] == 5
    assert result.details["base_score"] == pytest.approx(50.0, abs=5.0)
    # Dict similarity yuksek olmali (5/5 kok match)
    assert result.details["dict_similarity"] >= 0.8
    # Final skor ~40-50 aralisinda
    assert 35 < result.score <= 55


def test_function_names_all_generic(tmp_path: Path):
    """Hepsi FUN_ olursa skor 0 civari."""
    body = "\n".join(f"int FUN_{i:08x}(void) {{ return {i}; }}" for i in range(5))
    f = _write(tmp_path / "all_fun.c", body)
    metric = FunctionNamesMetric()
    result = metric.score([f])
    assert result.score == pytest.approx(0.0, abs=1e-6)
    assert result.details["generic_count"] == 5


def test_function_names_all_meaningful(tmp_path: Path):
    """Hepsi anlamli kokler iceriyor -- skor 100'e yakin."""
    body = "\n".join([
        "int read_data(void) { return 0; }",
        "int write_buffer(void) { return 0; }",
        "int init_state(void) { return 0; }",
        "int parse_input(void) { return 0; }",
        "int compute_hash(void) { return 0; }",
    ])
    f = _write(tmp_path / "clean.c", body)
    metric = FunctionNamesMetric()
    result = metric.score([f])
    # 0 generic, dict similarity 1.0, skor 100
    assert result.score == pytest.approx(100.0, abs=1.0)


# ---------------------------------------------------------------------------
# 3. Parametre isimleri
# ---------------------------------------------------------------------------

def test_param_names_metric(param_mixed_src):
    """Yari generic, yari anlamli parametreler -- skor ~50."""
    metric = ParamNamesMetric()
    result = metric.score(param_mixed_src)
    # Toplam 10 param, 4 tanesi param_1/param_2 (f1+f2)
    assert result.details["total"] == 10
    assert result.details["generic_count"] == 4
    assert 55 < result.score < 65


def test_param_names_all_generic(tmp_path: Path):
    """Hepsi param_N olursa skor 0."""
    body = "int f(int param_1, int param_2, int param_3) { return param_1; }"
    f = _write(tmp_path / "generic.c", body)
    metric = ParamNamesMetric()
    result = metric.score([f])
    assert result.score == pytest.approx(0.0, abs=1e-6)


# ---------------------------------------------------------------------------
# 4. Lokal degiskenler
# ---------------------------------------------------------------------------

def test_local_vars_metric(local_vars_src):
    """5 generic (iVar/lVar/uVar/pcVar/local_10) + 5 anlamli lokal."""
    metric = LocalVarsMetric()
    result = metric.score(local_vars_src)
    assert result.details["total"] == 10
    assert result.details["generic_count"] == 5
    assert result.score == pytest.approx(50.0, abs=1.0)


def test_local_vars_detects_all_variants(tmp_path: Path):
    """Ghidra pattern varyasyonlarini teker teker yakalamali."""
    body = (
        "int f(void) {\n"
        "    int iVar1;\n"
        "    long lVar2;\n"
        "    unsigned int uVar3;\n"
        "    int *piVar4;\n"
        "    long local_28;\n"
        "    int auStack_30;\n"
        "    return 0;\n"
        "}\n"
    )
    f = _write(tmp_path / "variants.c", body)
    metric = LocalVarsMetric()
    result = metric.score([f])
    # Hepsi generic -> skor 0
    assert result.score == pytest.approx(0.0, abs=1e-6)
    assert result.details["generic_count"] == 6


# ---------------------------------------------------------------------------
# 5. Tip kalitesi
# ---------------------------------------------------------------------------

def test_type_quality_metric(type_mixed_src):
    """undefined8/undefined4 oranina gore skor."""
    metric = TypeQualityMetric()
    result = metric.score(type_mixed_src)
    # Tipler icinde undefined sayisi >= 5 olmali (genellikle daha fazla)
    assert result.details["total"] > 0
    assert result.details["undefined_count"] > 0
    assert 0 < result.score < 100


def test_type_quality_all_undefined(tmp_path: Path):
    """Hepsi undefined -> skor 0."""
    body = (
        "undefined8 f1(undefined8 a) { undefined8 x; return x; }\n"
        "undefined4 f2(undefined4 b) { undefined4 y; return y; }\n"
    )
    f = _write(tmp_path / "all_undef.c", body)
    metric = TypeQualityMetric()
    result = metric.score([f])
    assert result.score == pytest.approx(0.0, abs=1e-6)


def test_type_quality_all_clean(tmp_path: Path):
    """Hic undefined yok -> skor 100."""
    body = (
        "int f1(int a) { int x; return x; }\n"
        "char f2(char b) { char y; return y; }\n"
    )
    f = _write(tmp_path / "clean_types.c", body)
    metric = TypeQualityMetric()
    result = metric.score([f])
    assert result.score == pytest.approx(100.0, abs=1e-6)


# ---------------------------------------------------------------------------
# 6. Yorumlar
# ---------------------------------------------------------------------------

def test_comments_metric(commented_src):
    """100 fonksiyon, 50 yorum -> ratio 0.5, ideal 2.0 -> skor 25."""
    metric = CommentsMetric()
    result = metric.score(commented_src)
    assert result.details["function_count"] == 100
    assert result.details["comment_lines"] == 50
    assert result.details["ratio_per_function"] == pytest.approx(0.5, abs=0.01)
    # 0.5 / 2.0 * 100 = 25
    assert result.score == pytest.approx(25.0, abs=1.0)


def test_comments_ideal(tmp_path: Path):
    """Ideal oran -- fonksiyon basina 2 yorum."""
    lines: list[str] = []
    for i in range(5):
        lines.append(f"// Aciklama {i}")
        lines.append(f"// Devam {i}")
        lines.append(f"int f{i}(void) {{ return {i}; }}")
    f = _write(tmp_path / "ideal.c", "\n".join(lines))
    metric = CommentsMetric()
    result = metric.score([f])
    assert result.score == pytest.approx(100.0, abs=1.0)


def test_comments_no_functions(tmp_path: Path):
    """Fonksiyon yoksa skor 0 (bolen)."""
    f = _write(tmp_path / "empty.c", "// sadece yorum\n")
    metric = CommentsMetric()
    result = metric.score([f])
    assert result.score == 0.0


# ---------------------------------------------------------------------------
# 7. Kod yapisi
# ---------------------------------------------------------------------------

def test_code_structure_metric(structured_src):
    """Derin nesting ve goto iceren fonksiyon -- skor 100'den dusuk."""
    metric = CodeStructureMetric()
    result = metric.score(structured_src)
    assert result.details["goto_count"] == 1
    # Nesting en az 4 (if->if->for->if)
    assert result.details["max_nesting"] >= 3
    # Ceza var -> skor < 100
    assert result.score < 100


def test_code_structure_clean(tmp_path: Path):
    """Temiz, sig fonksiyonlar -- yuksek skor."""
    body = (
        "int add(int a, int b) { return a + b; }\n"
        "int mul(int a, int b) { return a * b; }\n"
    )
    f = _write(tmp_path / "clean.c", body)
    metric = CodeStructureMetric()
    result = metric.score([f])
    # Cok sig (nesting 0), goto yok, kisa -> ceza yok
    assert result.score >= 95


def test_code_structure_long_function(tmp_path: Path):
    """Uzun fonksiyon ceza almali."""
    # 200 satirlik bir fonksiyon
    lines = ["int giant(int x) {"]
    for i in range(200):
        lines.append(f"    x += {i};")
    lines.append("    return x;")
    lines.append("}")
    f = _write(tmp_path / "long.c", "\n".join(lines))
    metric = CodeStructureMetric()
    result = metric.score([f])
    # Fonksiyon uzunlugu hard limit'i gectigi icin ceza var
    assert result.details["func_len_penalty"] > 0
    assert result.score < 100


# ---------------------------------------------------------------------------
# 8. Toplam agirlikli skor
# ---------------------------------------------------------------------------

def test_total_score_weighted(tmp_path: Path, monkeypatch):
    """Tum metric'ler 50 donerse toplam skor 50 olmali (agirliklar toplami 1.0)."""
    scorer = ReadabilityScorer()

    # Her metric'i monkeypatch ile 50 dondurmeye zorla
    from karadul.quality.metrics.function_names import FunctionNamesResult
    from karadul.quality.metrics.param_names import ParamNamesResult
    from karadul.quality.metrics.local_vars import LocalVarsResult
    from karadul.quality.metrics.type_quality import TypeQualityResult
    from karadul.quality.metrics.comments import CommentsResult
    from karadul.quality.metrics.code_structure import CodeStructureResult

    for name, (metric, _w) in scorer._metrics.items():
        if name == "function_names":
            fake = FunctionNamesResult(score=50.0, details={"total": 10})
        elif name == "param_names":
            fake = ParamNamesResult(score=50.0, details={"total": 10})
        elif name == "local_vars":
            fake = LocalVarsResult(score=50.0, details={"total": 10})
        elif name == "type_quality":
            fake = TypeQualityResult(score=50.0, details={"total": 10})
        elif name == "comments":
            fake = CommentsResult(score=50.0, details={"function_count": 10})
        else:  # code_structure
            fake = CodeStructureResult(score=50.0, details={"func_count": 10})
        metric.score = lambda files, _f=fake: _f  # type: ignore[assignment]

    f = _write(tmp_path / "any.c", "int f(void){return 0;}")
    result = scorer.score_directory(tmp_path)
    assert result.total_score == pytest.approx(50.0, abs=1e-3)


def test_score_directory_missing(tmp_path: Path):
    """Olmayan dizin -> error ama crash yok."""
    scorer = ReadabilityScorer()
    result = scorer.score_directory(tmp_path / "does_not_exist")
    assert result.total_score == 0.0
    assert "error" in result.details


def test_score_directory_empty(tmp_path: Path):
    """Bos dizin -> total 0 ama dimensions sozlugu mevcut."""
    scorer = ReadabilityScorer()
    result = scorer.score_directory(tmp_path)
    assert result.total_score == 0.0
    assert len(result.dimensions) == 6


# ---------------------------------------------------------------------------
# 9. DWARF baseline
# ---------------------------------------------------------------------------

def test_dwarf_baseline_missing(tmp_path: Path):
    """Debug info yoksa graceful skip -- available False."""
    # Rastgele bir dosya -- binary degil, DWARF yok
    f = _write(tmp_path / "not_a_binary.txt", "hello")
    baseline = DwarfBaseline(f)
    result = baseline.result()
    assert result.available is False
    assert result.score == 0.0


def test_dwarf_baseline_nonexistent_file(tmp_path: Path):
    """Dosya yoksa crash yok."""
    baseline = DwarfBaseline(tmp_path / "ghost")
    result = baseline.result()
    assert result.available is False


# ---------------------------------------------------------------------------
# 10. Karsilastirma (debug vs stripped)
# ---------------------------------------------------------------------------

def test_compare_debug_vs_stripped(clean_src, tmp_path: Path):
    """Baseline available ise karsilastirmada baseline_score=100."""
    scorer = ReadabilityScorer()
    recon = scorer.score_directory(clean_src[0].parent)

    # Mock baseline -- direk DwarfBaselineResult olustur
    baseline = DwarfBaselineResult(
        score=100.0,
        available=True,
        statistics={"function_count": 2, "param_count": 3, "local_count": 3},
    )
    cmp = scorer.compare(baseline, recon)
    assert isinstance(cmp, CompareResult)
    assert cmp.baseline_score == 100.0
    assert cmp.reconstructed_score == recon.total_score
    assert cmp.delta == pytest.approx(100.0 - recon.total_score, abs=1e-3)
    # Her boyut icin delta olmali
    assert len(cmp.dimension_deltas) == 6


def test_compare_no_baseline(clean_src):
    """Baseline yoksa baseline_score 0, delta negatif olabilir."""
    scorer = ReadabilityScorer()
    recon = scorer.score_directory(clean_src[0].parent)
    baseline = DwarfBaselineResult(
        score=0.0,
        available=False,
        statistics={"note": "yok"},
    )
    cmp = scorer.compare(baseline, recon)
    assert cmp.baseline_score == 0.0


# ---------------------------------------------------------------------------
# 11. Clean vs generic end-to-end
# ---------------------------------------------------------------------------

def test_clean_source_high_score(clean_src):
    """Temiz kaynak kod yuksek skor almali."""
    scorer = ReadabilityScorer()
    result = scorer.score_directory(clean_src[0].parent)
    # Anlamli isimler, az nesting, yorumlar -- skor yuksek
    assert result.total_score > 40, f"Cok dusuk: {result.total_score}"


def test_generic_source_low_score(tmp_path: Path):
    """Tumuyle Ghidra-jenerik kod cok dusuk skor almali."""
    body = (
        "undefined8 FUN_00401000(undefined8 param_1, undefined8 param_2) {\n"
        "    undefined8 uVar1;\n"
        "    undefined4 iVar2;\n"
        "    long local_10;\n"
        "    return uVar1;\n"
        "}\n"
        "undefined8 FUN_00401020(undefined8 param_1) {\n"
        "    undefined8 uVar1;\n"
        "    return uVar1;\n"
        "}\n"
    )
    f = _write(tmp_path / "generic.c", body)
    scorer = ReadabilityScorer()
    result = scorer.score_directory(tmp_path)
    # Cok dusuk skor bekleniyor
    assert result.total_score < 25, f"Beklenenden yuksek: {result.total_score}"
