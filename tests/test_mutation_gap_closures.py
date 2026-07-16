"""Mutation testing ile bulunan TEST DELIKLERINI kapatan testler (2026-07-16).

Bugun duzeltilen kritik fonksiyonlarda elle hedefli mutasyon calistirildi:
koda kasitli bug (mutant) enjekte edilip ilgili testlerin yakalayip yakalamadigi
olculdu. Asagidaki testlerin HER BIRI, mevcut testlerin YAKALAYAMADIGI (mutant
"hayatta kalan") gercek bir davranis-degisimini kilitler. Her testin docstring'i
oldurdugu mutant'i belirtir; mutant geri konursa test PATLAR (kanit disiplini).
"""
from __future__ import annotations

import textwrap

import pytest

from karadul.config import Config
from karadul.reconstruction.c_namer import (
    CVariableNamer,
    _FunctionInfo,
    _classify_body_param,
)
from karadul.reconstruction.c_type_recoverer import _apply_per_func_replacements


# ===========================================================================
# MODUL 1: c_namer._classify_body_param / _strategy_body_param_naming
# ===========================================================================

def _run_strategy(namer: CVariableNamer, fname: str, body: str) -> dict[str, str]:
    namer._func_bodies = {fname: body}
    namer._candidates = {}
    fi = _FunctionInfo(name=fname, address="0", params=[])
    namer._strategy_body_param_naming(fi)
    out: dict[str, str] = {}
    for key, cands in namer._candidates.items():
        out[key.split("::", 1)[1]] = cands[0].new_name
    return out


def test_ptr_two_offsets_is_buf_not_ctx():
    """MUTANT: `if len(offsets) >= 3` (ptr ctx) -> `>= 2` HAYATTA KALIYORDU.

    Mevcut testler ptr ctx'i 4 ve 3 offset ile deniyor ama ALT SINIRI (2 offset)
    hic pinlemiyor. 2 ayrik offset ctx icin YETERSIZ (tesadufi olabilir) -> buf
    olmali. Bu test `>=3` esigini alttan kilitler.
    """
    # tam 2 ayrik sabit offset: *param_1 (offset 0) + param_1[1]
    body = "*param_1 = 0; param_1[1] = 1;"
    verdict = _classify_body_param(body, "param_1", is_ptr=True)
    assert verdict is not None
    assert verdict[0] == "buf", "2 offset ctx sanildi -- alt sinir kaymis (>=2)"


def test_body_param_respects_min_confidence():
    """MUTANT: `if conf < self._min_confidence: continue` -> `pass` HAYATTA.

    Mevcut testlerde tum adaylarin guveni (>=0.35) esigin (0.15) uzerinde, bu
    yuzden filtre HIC devreye girmiyor -> kaldirilinca test degismiyordu. Yuksek
    esikle (0.50) len adayinin (0.42) ELENMESI gerektigini kilitler.
    """
    namer = CVariableNamer(Config(), min_confidence=0.50)
    body = "int _f(int param_1)\n{\n  for (i = 0; i < param_1; i++) { s += a[i]; }\n}"
    out = _run_strategy(namer, "_f", body)
    assert out == {}, "min_confidence filtresi kalkti -- 0.42 aday 0.50 esigi gecti"

    # Kalkan: esik dusukse AYNI aday GECMELI (filtre asiri kisitlamasin)
    namer2 = CVariableNamer(Config(), min_confidence=0.15)
    assert _run_strategy(namer2, "_f", body).get("param_1") == "len"


def test_named_param_with_usage_not_renamed():
    """MUTANT: `if not _GHIDRA_AUTO_PARAM.match(pname): continue` -> `pass` HAYATTA.

    Mevcut test (test_strategy_skips_already_named) zaten-isimli param'lari
    KULLANIM SINYALI OLMADAN veriyor -> siniflandirma None dondugu icin guard
    kalksa da aday cikmiyor (mutant yakalanmiyor). Burada zaten-isimli 'buf'
    param'i GERCEK struct-offset kullanimi tasiyor: guard olmadan yanlislikla
    'ctx' olarak yeniden adlandirilir. Guard bunu engellemeli.
    """
    namer = CVariableNamer(Config(), min_confidence=0.15)
    # NOT: strateji kapisi (`"param_" not in body -> return`) icin govdede bir
    # param_N bulunmali; param_1 sinyalsiz birakilir (aday uretmez), asil sinav
    # zaten-isimli 'buf'un struct-offset kullanimina RAGMEN dokunulmamasidir.
    body = textwrap.dedent("""\
        void _use(int *buf,int param_1)
        {
          *buf = 0; buf[1] = 1; buf[2] = 2; buf[3] = 3;
          local = param_1;
        }
    """)
    out = _run_strategy(namer, "_use", body)
    assert "buf" not in out, "zaten-isimli 'buf' (kullanim sinyalli) yeniden adlandirildi"
    assert out == {}


# ===========================================================================
# MODUL 2: c_type_recoverer._apply_per_func_replacements
# ===========================================================================

def test_col0_else_if_actually_exercises_keyword_guard():
    """MUTANT: `if fname in _C_CONTROL_KEYWORDS: continue` -> `pass` HAYATTA.

    Mevcut test (test_control_keyword_not_a_function_name) GIRINTILI `else if`
    kullaniyor -- regex sutun-0 rtype istedigi icin 'if' ZATEN hic eslesmiyor,
    yani guard test edilmeden geciyor (yanlis nedenle yesil). Burada `else if`
    SUTUN-0'da: 'if' fname olarak GERCEKTEN eslesir; guard olmazsa if-blogunda
    yanlis kapsamda replace yapilir.
    """
    content = (
        "void FUN_00001000(int p)\n\n{\n  int iVar10;\n  iVar10 = 1;\n}\n"
        "else if (p == 1)\n\n{\n  int q;\n  q = iVar10;\n}\n"
    )
    out = _apply_per_func_replacements(content, {"if": {"iVar10": "WRONG"}})
    assert "WRONG" not in out, "'if' fonksiyon sanildi -- yanlis kapsamda replace"
    assert out == content


def test_nested_col0_definition_overlap_no_bloat():
    """MUTANT: `if func_start < last_end: continue` (160x sisme kalkani) -> `pass`
    HAYATTA KALIYORDU -- yani 160x sisme fix'i ASLINDA regex tarafindan korunuyor,
    overlap guard'i HIC test edilmiyordu.

    Bu girdi guard'i dogrudan tetikler: FUN_00001000 govdesi (brace-matching)
    ic-ice sutun-0 `long FUN_00002000(...)` tanimini yutar; ikinci match
    func_start < last_end olur. Guard olmadan ayni metin ciktiya IKINCI kez girer
    (olculen: ratio 1.38x, FUN_00002000 iki kez). Guard tek gecisi garanti eder.
    """
    content = (
        "void FUN_00001000(int a)\n\n{\n  undefined8 x;\n"
        "long FUN_00002000(int b)\n\n{\n  undefined8 y;\n  y = 1;\n}\n"
        "  x = 2;\n}\n"
    )
    per_func = {
        "FUN_00001000": {"undefined8 x": "long x"},
        "FUN_00002000": {"undefined8 y": "char y"},
    }
    out = _apply_per_func_replacements(content, per_func)
    assert out.count("FUN_00002000(") == 1, "ic-ice tanim cogaltildi (overlap guard yok)"
    assert len(out) / len(content) < 1.10, "metin sismesi -- overlap guard devre disi"


# ===========================================================================
# MODUL 4: c_comment_generator._annotate_file satir-offset dizisi
# ===========================================================================

def test_real_annotate_file_uses_correct_line_offset():
    """MUTANT'LAR (3 adet) HAYATTA KALIYORDU: `_acc += len(_l) + 1` -> `+ 0`;
    `line_offsets.append(_acc)` -> `append(0)`; `content[line_offset:...]` ->
    `content[0:...]`.

    Neden yakalanmiyordu: mevcut testler offset mantiginin bir KOPYASINI
    (`_yeni_offsets` yerel fonksiyonu) test ediyor, GERCEK `_annotate_file`'i
    degil. Bu test gercek fonksiyonu cagirir ve offset'in dogru context'i
    besledigini davranistan dogrular: `if (ret < 0)` satirinin YORUMU, satirdan
    SONRAKI `return -1` gorulup gorulmedigine gore degisir. Offset bozulursa
    yanlis context taranir -> yorum "error check" yerine "check ... negative"
    olur.
    """
    from karadul.reconstruction.c_comment_generator import CCommentGenerator

    # 160 dolgu satiri: '+1 dusur' mutantinin driftini (>150 char) context
    # penceresinin disina itip yorumu ceviren esigi asar; 'hep 0' ve 'ctx basi 0'
    # mutantlari zaten herhangi bir dolguda cevrilir.
    filler = "\n".join("  ret = step_%03d(ret);" % i for i in range(160))
    content = (
        "int FUN_100004000(int ret)\n\n{\n"
        + filler + "\n"
        "  if (ret < 0) {\n"
        "    return -1;\n"
        "  }\n"
        "  return ret;\n"
        "}\n"
    )
    gen = CCommentGenerator()
    annotated, _ = gen._annotate_file(
        content=content, func_meta={}, string_refs={},
        call_graph={}, algo_index={}, filename="t.c",
    )
    # Dogru offset -> satirdan sonraki 'return -1' gorulur -> "error check"
    assert "error check: return on ret failure" in annotated, (
        "satir offset'i bozuk -- context yanlis yerden okundu"
    )
    assert "check ret for negative value" not in annotated


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
