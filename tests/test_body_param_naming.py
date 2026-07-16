"""Gövde-tabanlı parametre isimlendirme (Strateji 11) testleri.

KÖK SEBEP (2026-07-16): ARM64 stripped Mach-O'da Ghidra
ghidra_functions.json'a params=[] yazıyor → func_info.params BOŞ →
_strategy_dataflow/_strategy_type_based'in param döngüleri hiç ateşlenmiyor.
param_N yalnızca decompiled C GÖVDESİNDE yaşıyor. Bu testler:
  1. Yeni stratejinin gövdeden param_N'i çıkarıp ctx/buf/len ürettiğini,
  2. ENJEKSİYON KANITI: eski stratejilerin (dataflow) boş params ile HİÇBİR
     param adayı üretmediğini (yani kök sebebin gerçekliğini),
  3. sinyal yoksa uydurma isim üretilmediğini (savunmacılık)
doğrular. Sentetik gövdeler — fixture'a/leakage'a bağımlı DEĞİL.
"""
from __future__ import annotations

import textwrap

import pytest

from karadul.config import Config
from karadul.reconstruction.c_namer import (
    CVariableNamer,
    _FunctionInfo,
    _classify_body_param,
    _split_top_level_commas,
)


@pytest.fixture
def namer() -> CVariableNamer:
    return CVariableNamer(Config(), min_confidence=0.15)


def _run(namer: CVariableNamer, fname: str, body: str) -> dict[str, str]:
    """Stratejiyi tek gövde üstünde çalıştır, {param_N: yeni_ad} döndür."""
    namer._func_bodies = {fname: body}
    namer._candidates = {}
    fi = _FunctionInfo(name=fname, address="0", params=[])  # GERÇEK: BOŞ
    namer._strategy_body_param_naming(fi)
    out: dict[str, str] = {}
    for key, cands in namer._candidates.items():
        old = key.split("::", 1)[1]
        out[old] = cands[0].new_name
    return out


# ---------------------------------------------------------------------------
# 1. Çekirdek kullanım sınıflandırması
# ---------------------------------------------------------------------------
def test_pointer_multi_offset_is_ctx():
    """>=3 ayrık sabit-offset deref -> struct/context pointer'ı => ctx."""
    body = "*param_1 = 1; param_1[1] = 2; param_1[2] = 3; param_1[3] = 4;"
    assert _classify_body_param(body, "param_1", is_ptr=True)[0] == "ctx"


def test_pointer_offset_cast_deref_is_ctx():
    """*(T *)(param + 0xNN) deseninde çok offset -> ctx."""
    body = ("*(uint *)(param_1 + 0x14) = 0; *(int *)(param_1 + 0x18) = 1; "
            "x = *(uint *)(param_1 + 0x1c);")
    assert _classify_body_param(body, "param_1", is_ptr=True)[0] == "ctx"


def test_pointer_iterated_is_buf():
    """Değişken indeksli pointer erişimi -> veri tamponu => buf."""
    body = "for (i = 0; i < n; i++) { total += param_1[i]; }"
    assert _classify_body_param(body, "param_1", is_ptr=True)[0] == "buf"


def test_pointer_single_deref_is_buf():
    """Tek deref'li pointer (struct değil) -> buf."""
    body = "x = *param_1;"
    assert _classify_body_param(body, "param_1", is_ptr=True)[0] == "buf"


def test_scalar_loop_bound_is_len():
    """Döngü sınırı olan scalar -> len (klasik `for i<n`)."""
    body = "for (i = 0; i < param_2; i++) { s += a[i]; }"
    assert _classify_body_param(body, "param_2", is_ptr=False)[0] == "len"


def test_scalar_size_arithmetic_is_len():
    """Boyut aritmetiği (param/4, (uint)param, param>>0x20) -> len."""
    body = "end = base + param_2 / 4; hi = (uint)param_2; x = param_2 >> 0x20;"
    assert _classify_body_param(body, "param_2", is_ptr=False)[0] == "len"


def test_scalar_decrement_loop_is_len():
    """`n--` azaltma sayacı -> len."""
    body = "while (param_2 != 0) { param_2--; c = *p++; }"
    assert _classify_body_param(body, "param_2", is_ptr=False)[0] == "len"


def test_scalar_no_signal_is_none():
    """Sinyal yoksa UYDURMA yok (savunmacılık): tek atama -> None."""
    body = "local = param_2; return local;"
    assert _classify_body_param(body, "param_2", is_ptr=False) is None


def test_pointer_no_usage_is_none():
    """Hiç deref/iterasyon yoksa pointer için de None."""
    body = "other_func(param_1);"  # sadece pass-through, deref yok
    assert _classify_body_param(body, "param_1", is_ptr=True) is None


def test_scalar_plain_arithmetic_is_none_overfit_guard():
    """OVERFIT KORUMASI (2026-07-16): `return a + b;` scalar toplaması buf
    SAYILMAZ. `param + var` yalnız POINTER için iterasyondur; add(int a,int b)
    fixture'ında param_1'i buf sanma tuzağı bu testle kilitli."""
    body = "int _add(int param_1,int param_2)\n{\n  return param_1 + param_2;\n}"
    assert _classify_body_param(body, "param_1", is_ptr=False) is None
    assert _classify_body_param(body, "param_2", is_ptr=False) is None


def test_scalar_memcpy_src_is_buf():
    """Scalar (ulong) ama mem-kopyaya pointer arg olarak veriliyor -> buf."""
    body = "___memcpy_chk(dst + 0x10, param_1, n, 0xff);"
    assert _classify_body_param(body, "param_1", is_ptr=False)[0] == "buf"


def test_scalar_memcpy_size_arg_not_buf():
    """OVERFIT KORUMASI: mem-kopyanın BOYUT arg'ı (arg2+) buf DEĞİL —
    len'i buf sanma tuzağı. (size_usage yoksa None kalır, buf olmaz.)"""
    body = "___memcpy_chk(dst, src, param_1, 0xff);"
    assert _classify_body_param(body, "param_1", is_ptr=False) is None


# ---------------------------------------------------------------------------
# 2. Strateji entegrasyonu — gerçek imza + gövde
# ---------------------------------------------------------------------------
def test_strategy_names_three_params(namer):
    """process_block tarzı: buffer(buf) + len(len) + ctx(ctx)."""
    body = textwrap.dedent("""\
        void _proc_block(uint *param_1,ulong param_2,uint *param_3)
        {
          uint a;
          a = *param_3;
          param_3[1] = a; param_3[2] = a; param_3[5] = param_3[5] + (uint)param_2;
          p = param_1;
          while (p < param_1 + param_2 / 4) { p = p + 1; }
          return;
        }
    """)
    out = _run(namer, "_proc_block", body)
    assert out.get("param_1") == "buf"
    assert out.get("param_2") == "len"
    assert out.get("param_3") == "ctx"


def test_strategy_skips_already_named(namer):
    """param_N olmayan (library-sig'den gelmiş) parametrelere DOKUNMAZ."""
    body = textwrap.dedent("""\
        uint _crc32(uLong crc,Bytef *buf,uInt len)
        {
          uLong r;
          r = _crc32_update(0,crc,buf);
          return r;
        }
    """)
    out = _run(namer, "_crc32", body)
    assert out == {}  # crc/buf/len zaten anlamlı -> aday YOK


def test_strategy_void_params(namer):
    """void parametreli fonksiyon -> aday yok, çökmez."""
    body = "void _f(void)\n{\n  return;\n}\n"
    assert _run(namer, "_f", body) == {}


# ---------------------------------------------------------------------------
# 3. ENJEKSİYON KANITI — kök sebebin gerçekliği
# ---------------------------------------------------------------------------
def test_injection_dataflow_empty_params_produces_nothing(namer):
    """KÖK SEBEP KANITI: func_info.params BOŞ iken ESKİ _strategy_dataflow
    HİÇBİR param adayı üretmez (param_N gövdede olsa bile). Yeni stratejinin
    neden gerektiğini kanıtlar."""
    body = textwrap.dedent("""\
        void _proc(uint *param_1,ulong param_2)
        {
          param_1[0] = 1; param_1[1] = 2; param_1[2] = 3; param_1[3] = 4;
          x = param_2 / 4;
        }
    """)
    namer._func_bodies = {"_proc": body}
    namer._candidates = {}
    fi = _FunctionInfo(name="_proc", address="0", params=[])  # Ghidra gerçeği

    namer._strategy_dataflow(fi)
    param_keys_old = [k for k in namer._candidates if "::param_" in k]
    assert param_keys_old == [], (
        "Eski dataflow boş params ile param_N üretmemeli (kök sebep)"
    )

    # Yeni strateji AYNI girdi ile param üretir:
    namer._strategy_body_param_naming(fi)
    param_keys_new = [k for k in namer._candidates if "::param_" in k]
    assert len(param_keys_new) == 2


# ---------------------------------------------------------------------------
# 4. Yardımcı: fonksiyon-pointer parametresi virgülü bölünmesin
# ---------------------------------------------------------------------------
def test_split_top_level_commas_nested():
    blob = "int a, void (*cb)(int, char), char *b"
    parts = _split_top_level_commas(blob)
    assert len(parts) == 3
    assert parts[1].strip() == "void (*cb)(int, char)"
