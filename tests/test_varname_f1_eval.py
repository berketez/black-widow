"""scripts/varname_f1_eval.py harness'inin birim testleri.

Ghidra GEREKMEZ — reconstructed C ayrıştırma, placeholder tespiti, pozisyonel
param eşleştirme, küme-bazlı lokal eşleştirme ve uçtan uca metrik sentetik
verilerle sınanır. (Fixture derleme + karadul analizi ayrı, ağır; bu test hızlı.)
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

# scripts/ bir paket değil; doğrudan dosyadan yükle.
_SPEC = importlib.util.spec_from_file_location(
    "varname_f1_eval", _ROOT / "scripts" / "varname_f1_eval.py"
)
V = importlib.util.module_from_spec(_SPEC)
# dataclass, cls.__module__'ü sys.modules'ta arar; exec ÖNCESİ kaydet.
sys.modules["varname_f1_eval"] = V
_SPEC.loader.exec_module(V)  # type: ignore[union-attr]

from tests.benchmark.metrics import AccuracyCalculator  # noqa: E402


# --------------------------------------------------------------------------
# Placeholder tespiti
# --------------------------------------------------------------------------
@pytest.mark.parametrize("name", [
    "param_1", "param_12", "local_28", "local_c8_1", "auStack_c8",
    "uStack_18", "aiStack_20", "uVar1", "iVar2", "pcVar3", "puVar4",
    "unaff_x19", "extraout_x0", "in_stack_ffff",
])
def test_ghidra_placeholder_positive(name):
    assert V.is_ghidra_placeholder(name)


@pytest.mark.parametrize("name", [
    # karadul'un hesapladığı jenerik adlar placeholder DEĞİL (gerçek çıktı)
    "accumulator_24", "val_38", "raw_value_18", "result_14", "i_6",
    # gerçek kaynak adları
    "buffer", "len", "ctx", "checksum", "words",
])
def test_ghidra_placeholder_negative(name):
    assert not V.is_ghidra_placeholder(name)


# --------------------------------------------------------------------------
# reconstructed C ayrıştırma — docstring tuzağı dahil
# --------------------------------------------------------------------------
_RECON_ENHANCED = """\
#include "types.h"

// Function: _sha1_init_ctx
// Address:  1000004b0
// Size:     120 bytes

/**
 * @brief Internal: sha1 init ctx
 * @param int32_t *param_1
 * @called_by _sha1_buffer (1 site)
 */
void _sha1_init_ctx(int32_t *param_1)

{
  int result_14;
  uint accumulator_24;
  uint8_t auStack_c8 [160];
  *param_1 = 0x67452301;
  return;
}
"""


def test_parse_skips_docstring_call_site_trap(tmp_path):
    # "@called_by _sha1_buffer (1 site)" imza sanılıp 'site' çıkarılmamalı.
    (tmp_path / "sha1_init_ctx.c").write_text(_RECON_ENHANCED, encoding="utf-8")
    rec = V.parse_reconstructed(tmp_path)
    addr = 0x1000004b0
    assert addr in rec
    fv = rec[addr]
    assert fv.params == ["param_1"]              # 'site' DEĞİL
    assert fv.locals == ["result_14", "accumulator_24", "auStack_c8"]


def test_parse_dedupe_same_address_prefers_richer(tmp_path):
    raw = """\
// Function: _f
// Address:  100000abc
void _f(int param_1)
{
  return;
}
"""
    rich = """\
// Function: _f
// Address:  100000abc
void _f(int count)
{
  int total;
  return;
}
"""
    (tmp_path / "_f.c").write_text(raw, encoding="utf-8")
    (tmp_path / "f.c").write_text(rich, encoding="utf-8")
    rec = V.parse_reconstructed(tmp_path)
    fv = rec[0x100000abc]
    # daha çok isim çıkan (count + total) sürüm tercih edilir
    assert fv.params == ["count"]
    assert fv.locals == ["total"]


# --------------------------------------------------------------------------
# Pozisyonel param eşleştirme
# --------------------------------------------------------------------------
def test_positional_param_placeholder_is_fn_not_fp():
    calc = AccuracyCalculator()
    prf, _ = V.positional_param_prf(["buffer", "len", "ctx"],
                                    ["param_1", "param_2", "param_3"], calc)
    # placeholder = kurtarma yok -> hepsi FN, FP YOK (yanlış isim üretilmedi)
    assert prf.tp == 0 and prf.fp == 0 and prf.fn == 3


def test_positional_param_exact_and_wrong():
    calc = AccuracyCalculator()
    prf, ex = V.positional_param_prf(["buffer", "len"], ["buffer", "site"], calc)
    assert prf.tp == 1        # buffer == buffer
    assert prf.fp == 1        # site: yanlış isim üretildi
    assert prf.fn == 1        # len kurtarılamadı
    assert ("len", "site", "wrong") in ex


# --------------------------------------------------------------------------
# Küme-bazlı lokal eşleştirme
# --------------------------------------------------------------------------
def test_setwise_local_semantic_match_and_placeholders():
    calc = AccuracyCalculator()
    # GT: length; karadul: len (semantic) + iVar1 (placeholder) + accumulator_2 (fp)
    prf, _ex, ph = V.setwise_local_prf(
        ["length"], ["len", "iVar1", "accumulator_2"], calc)
    assert ph == 1                       # iVar1 placeholder sayıldı
    assert prf.tp == 1                   # length ~ len
    assert prf.fn == 0
    assert prf.fp == 1                   # accumulator_2 hiçbir GT'ye uymadı


def test_setwise_local_all_missing():
    calc = AccuracyCalculator()
    prf, _ex, ph = V.setwise_local_prf(
        ["a", "b", "c"], ["param_1", "local_8", "uVar1"], calc)
    # karadul'un tüm lokalleri placeholder -> TP yok, FP yok, hepsi FN
    assert prf.tp == 0 and prf.fp == 0 and prf.fn == 3
    assert ph == 3


# --------------------------------------------------------------------------
# Uçtan uca değerlendirme (sentetik GT + recon)
# --------------------------------------------------------------------------
def test_evaluate_end_to_end():
    calc = AccuracyCalculator()
    FV = V.FuncVars
    gt = {
        0x100: FV("compute", 0x100, params=["buffer", "len"],
                  locals=["total", "i"]),
        0x200: FV("helper", 0x200, params=["ctx"], locals=[]),
    }
    recon = {
        0x100: FV("compute", 0x100, params=["param_1", "param_2"],
                  locals=["total", "i_3", "accumulator_9"]),
        # 0x200 hiç yok -> eşleşmeyen GT fonksiyonu
    }
    res = V.evaluate(gt, recon, calc)
    assert res["matched_funcs"] == 1
    assert res["total_gt_funcs"] == 2
    # compute fonksiyon adı exact -> func TP
    assert res["func_prf"].tp == 1
    # helper eşleşmedi -> func FN
    assert res["func_prf"].fn == 1
    # locals: total (exact) + i~i_3 (exact) -> 2 TP; accumulator_9 -> FP
    assert res["local_prf"].tp == 2
    # helper'ın 'ctx' param'ı eşleşmeyen fonksiyondan -> param FN'e eklenir
    assert res["param_prf"].fn >= 3  # compute'un 2 param + helper'ın 1'i


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
