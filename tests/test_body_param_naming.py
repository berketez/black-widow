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
    """>=3 ayrık sabit-offset (OKUMA-baskın) deref -> struct/context pointer'ı => ctx.

    Cephe 1b (2a): gerçek ctx state OKUNUR (rvalue). Saf-YAZMA aynı desen artık
    çıktı-tamponu sayılır (aşağıdaki 2a testlerine bak); bu test okuma-baskın
    gövdeyle ctx dalını doğrular."""
    body = "a = *param_1; b = param_1[1]; c = param_1[2]; d = param_1[3];"
    assert _classify_body_param(body, "param_1", is_ptr=True)[0] == "ctx"


def test_pointer_offset_cast_deref_is_ctx():
    """*(T *)(param + 0xNN) OKUMA deseninde çok offset -> ctx (state load)."""
    body = ("a = *(uint *)(param_1 + 0x14); b = *(int *)(param_1 + 0x18); "
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
          x = param_1[0] + param_1[1] + param_1[2] + param_1[3];
          y = param_2 / 4;
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


# ---------------------------------------------------------------------------
# 5. Cephe 1b — Katman 2a: WRITE/READ yön kapısı (output-tampon FP fix)
# ---------------------------------------------------------------------------
from karadul.reconstruction.c_namer import (  # noqa: E402
    _param_read_offsets,
    _param_write_offsets,
)


def test_write_read_offset_helpers_classify_store_vs_load():
    """Helper'lar store (lvalue) ile load (rvalue) offset'lerini ayırır."""
    body = ("*(uint *)(param_1 + 0x14) = x; y = *(uint *)(param_1 + 0x18); "
            "param_1[2] = z;")
    w = _param_write_offsets(body, "param_1")
    r = _param_read_offsets(body, "param_1")
    assert "0x14" in w and "2" in w      # iki store
    assert "0x18" in r and "0x18" not in w  # tek load, store değil


def test_write_detector_ignores_comparison():
    """`==` karşılaştırması YAZMA sayılmaz (yalnız düz `=` atama = store)."""
    body = "if (*(int *)(param_1 + 0x1c) == 0) { return; }"
    assert "0x1c" not in _param_write_offsets(body, "param_1")
    assert "0x1c" in _param_read_offsets(body, "param_1")


def test_write_dominant_ptr_is_none_2a():
    """2a: pointer'a baskın YAZMA (writes>=2, reads<=1) -> çıktı tamponu ->
    'ctx' DEME, None (param_N bırak). Belgelenmiş output->ctx FP'yi siler."""
    body = ("*(uint *)(param_1 + 0) = a; *(uint *)(param_1 + 4) = b; "
            "*(uint *)(param_1 + 8) = c;")
    assert _classify_body_param(body, "param_1", is_ptr=True) is None


def test_mixed_inout_ptr_is_ctx_safe_default():
    """2a: karışık kullanım (hem yaz hem oku = inout state) -> eski ctx
    davranışı (güvenli varsayılan; baskınlık yok)."""
    body = ("*(uint *)(param_1 + 0x14) = *(int *)(param_1 + 0x14) + 1; "
            "y = *(uint *)(param_1 + 0x18); z = *(uint *)(param_1 + 0x1c);")
    v = _classify_body_param(body, "param_1", is_ptr=True)
    assert v is not None and v[0] == "ctx"


def test_scalar_write_dominant_stays_ctx_pointer_only_guard():
    """GUARD (2a yalnız-pointer): scalar param'da output-yön çıkarımı YAPILMAZ
    (çok gürültülü). Baskın-yazma scalar bile ≥3 offset -> ctx kalır."""
    body = ("*(uint *)(param_1 + 4) = a; *(uint *)(param_1 + 8) = b; "
            "*(uint *)(param_1 + 0xc) = c;")
    v = _classify_body_param(body, "param_1", is_ptr=False)
    assert v is not None and v[0] == "ctx"


def test_constant_init_ptr_stays_ctx_not_suppressed():
    """REGRESYON KORUMASI: *_init_ctx tarzı SABİT-değer yazma (struct başlatma)
    baskın-yazma AMA çıktı tamponu DEĞİL -> ctx KALIR. Gerçek ctx (GT) kaybını
    önler; naif 2a bu 4 init_ctx TP'sini yanlışlıkla siliyordu."""
    body = ("*param_1 = 0x67452301; param_1[1] = 0xefcdab89; "
            "param_1[2] = 0x98badcfe; param_1[3] = 0x10325476;")
    v = _classify_body_param(body, "param_1", is_ptr=True)
    assert v is not None and v[0] == "ctx"


def test_injection_computed_vs_constant_write_flips_2a():
    """DİFERANSİYEL: AYNI yazma-baskın desende RHS SABİT -> ctx (init state),
    RHS HESAPLANMIŞ -> None (çıktı tamponu). Hesaplanmış-yazma diskriminatörü
    load-bearing (init-ctx regresyonunu önleyen tam bu ayrım)."""
    const_body = "*param_1 = 0x1; param_1[1] = 0x2; param_1[2] = 0x3;"
    comp_body = "*param_1 = uVar1; param_1[1] = uVar2; param_1[2] = uVar3;"
    assert _classify_body_param(const_body, "param_1", is_ptr=True)[0] == "ctx"
    assert _classify_body_param(comp_body, "param_1", is_ptr=True) is None


def test_injection_2a_gate_disabled_reintroduces_ctx_fp(monkeypatch):
    """MUTASYON KANITI: yön kapısının write-tespitini boşaltırsak (mutant),
    saf-yazma output pointer YİNE 'ctx' (FP) olur. Kapı gerçekten FP'yi siliyor.
    'Yeşil test kanıt değil' — kapıyı sabote et, FP'nin geri geldiğini gör."""
    import karadul.reconstruction.c_namer as cn
    body = ("*(uint *)(param_1 + 0) = a; *(uint *)(param_1 + 4) = b; "
            "*(uint *)(param_1 + 8) = c;")
    # Normal (kapı aktif): baskın yazma -> None (FP silinir).
    assert cn._classify_body_param(body, "param_1", is_ptr=True) is None
    # Ön-koşul: offset sinyali ≥3 (yani eski kural yolu GİRİLİYOR, None sinyalsizlikten
    # değil KAPIDAN geliyor).
    assert len(cn._param_fixed_offsets(body, "param_1")) >= 3
    # Mutant: write-offset tespitini boşalt -> gate ateşlenemez -> ESKİ ctx FP döner.
    monkeypatch.setattr(cn, "_param_write_offsets", lambda b, e: set())
    v = cn._classify_body_param(body, "param_1", is_ptr=True)
    assert v is not None and v[0] == "ctx"
