"""Mutation-kill testleri -- quality/metrics/code_structure delikleri (TAM-SUITE).

Sonraki-kademe mutasyon denetiminde TAM suite'e karsi HAYATTA kalan iki gercek
delik:

  CS4  _compute_func_len_penalty LINEAR interpolasyon bolgesi:
       fraction = (avg_len - soft) / (hard - soft), penalty = max_penalty*fraction.
       Mevcut tek uzunluk testi (test_code_structure_long_function) 202 satirlik
       fonksiyon kullaniyor -> `avg_len >= hard` (tam ceza) dalina duser; soft<avg<hard
       LINEAR bolge hic olculmuyordu. Mutant fraction'i 0'a cekince bu bolgede ceza
       0 olur -> yakalanmazdi.

  CS1  _max_nesting_depth fonksiyon-seviyesi ofseti: `max(0, max_depth - 1)`.
       Ilk `{` fonksiyon govdesidir, nesting onun UZERINE sayilir (-1). Mutant
       `- 0` her fonksiyonun nesting'ini 1 sisirir. Mevcut testler ya cok-sig
       (nesting 0, -1 clamp ile ayni) ya da `>= 3` gibi gevsek esik kullaniyordu;
       TAM deger hicbir yerde pinlenmiyordu.

Iki mutant da mutation_probe --test tests/ (TUM suite) ile HAYATTA dogrulandi.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from karadul.quality.metrics import CodeStructureMetric


def _write(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# CS4: func-len cezasinin LINEAR (soft<avg<hard) bolgesi
# ---------------------------------------------------------------------------


def test_func_len_penalty_linear_region_is_nonzero(tmp_path: Path) -> None:
    """soft(50) < avg_len < hard(150) bolgesinde func_len_penalty > 0 olmali.

    ~90 satirlik tek fonksiyon linear bolgeye duser:
        penalty = 40 * (avg_len-50)/(150-50)  (0 ile 40 arasi, tam ceza DEGIL).
    Mutant (fraction*0) bu bolgede cezayi 0 yapar -> `> 0` KIRMIZI.
    Tek dala (>=hard) dusen 200+ satir testi bu bolgeyi olcemiyordu.
    """
    lines = ["int midlen(int x) {"]
    for i in range(90):
        lines.append(f"    x += {i};")
    lines.append("    return x;")
    lines.append("}")
    f = _write(tmp_path / "midlen.c", "\n".join(lines))

    result = CodeStructureMetric().score([f])
    avg_len = result.details["avg_func_len"]
    penalty = result.details["func_len_penalty"]

    # Linear bolgede oldugumuzu belgele (tam-ceza dalina dusmedik).
    assert 50 < avg_len < 150, f"avg_len={avg_len} linear bolgede degil"
    # Kritik: linear interpolasyon 0 DEGIL (mutant fraction*0 -> 0).
    assert penalty > 0, f"linear bolgede func_len_penalty={penalty} (mutant 0?)"
    # Tam ceza (40) de DEGIL -- gercekten interpolasyon.
    assert penalty < 40.0


# ---------------------------------------------------------------------------
# CS1: nesting fonksiyon-seviyesi ofseti (-1)
# ---------------------------------------------------------------------------


def test_max_nesting_excludes_function_level_brace(tmp_path: Path) -> None:
    """Tek if-blogu iceren fonksiyonun nesting'i TAM 1 olmali (fonksiyon `{` haric).

    Braceler: fonksiyon{ (1) -> if{ (2, max) -> } (1) -> } (0).
    `max(0, max_depth-1)` = max(0, 2-1) = 1. Mutant `-0` = 2 -> assertion KIRMIZI.
    """
    body = (
        "int nested(int x) {\n"
        "    if (x > 0) {\n"
        "        return x;\n"
        "    }\n"
        "    return 0;\n"
        "}\n"
    )
    f = _write(tmp_path / "nested.c", body)

    result = CodeStructureMetric().score([f])
    # Fonksiyon-seviyesi `{` sayilmaz -> tek ic-blok = nesting 1 (mutant: 2).
    assert result.details["max_nesting"] == 1, (
        f"max_nesting={result.details['max_nesting']} (fonksiyon-brace ofseti kaybolmus?)"
    )
