"""P21 / LM-04 + B-E2 — jeton kestirimi içerik türüne göre; kestirime oransal pay.

Kusur (``kulvar_LM.md`` LM-04): kod dışı her şey 4,294 bayt/jeton sayılıyordu; adres listeleri
(``FUN_10001d1fc, …``) ve ``0x`` sabitleri rakam yoğundur ve Qwen ön-jetonlayıcısı rakamları tek tek
böler. 2026-11-12 K0 dumanının 5 isteminde gerçek / kestirim 1,060-1,168 (ortanca 1,080) idi; 512'lik
sabit pay bunu karşılamıyordu (B-E2). Ölçüm: aynı 5 istem bayt bayt yeniden kuruldu (iletilerin sha256'sı
koşunun denetim günlüğüyle aynı), yeni kestirimle oran 1,027-1,068 (ortanca 1,039); ayrıntı P21.md.

Bu dosya ölçümü değil kuralı kilitler (gerçek jetonlayıcı yok).

Mutasyon koruması: ``scripts/measurement/mutation_specs_p21.json``.
"""
from __future__ import annotations

import math

import karadul.lm as LM
from karadul.lm import context as C

# 2026-11-12 K0 dumanının 5 istemi: (o günkü kestirim, bugünkü kestirim, ucun bildirdiği prompt_tokens).
# Kaynak: ~/karadul_olcum/runs/k0-duman-2026-11-12/k0_duman_sonuc.json + P21 yeniden kurma betiği
# (lm04_once.txt / lm04_sonra.txt); istemler sha256 ile aynı.
K0_DUMAN_JETON = ((4354, 4584, 4851), (2822, 2933, 3047), (1740, 1788, 1849), (5109, 5272, 5416), (1693, 1852, 1978))


def test_rakam_bir_jeton():
    assert LM.TOKENS_PER_DIGIT == 1.0
    assert C.estimate_tokens(0, 0, 7) == 7 and C.estimate_tokens(4294, 0, 10) == 1010
    metin = "FUN_10001d1fc"                                           # 6 rakam + 7 bayt
    assert C.estimate_text_tokens(metin) == math.ceil(7 / LM.BYTES_PER_TOKEN_TEXT + 6)
    assert C.estimate_text_tokens("ş" * 2147) == 1000                 # rakamsız metin değişmedi


def test_adres_listesi_rakamlari_sayilir():
    adresler = ", ".join(f"FUN_1000{0x2000 + 0x40 * i:05x}" for i in range(15))
    zarf = {"id": "r1", "tool": "get_evidence", "ok": True, "data": {"callers": adresler}}
    rakam = sum(ch.isdigit() for ch in C.wrap_result(zarf))
    eski = math.ceil(len(C.wrap_result(zarf).encode()) / LM.BYTES_PER_TOKEN_TEXT)
    yeni = C.estimate_result_tokens(zarf)
    assert yeni >= rakam > eski                                       # eski kural rakamları bile saymıyordu
    # kodun içindeki rakamlar kod oranında kalır (kod oranı ölçümle tutarlı: 1,48)
    kod = {"id": "r2", "tool": "get_decompiled", "ok": True, "data": {"code": "x = 1234567890;\n" * 10}}
    kodsuz = {"id": "r2", "tool": "get_decompiled", "ok": True, "data": {"code": ""}}
    fark = C.estimate_result_tokens(kod) - C.estimate_result_tokens(kodsuz)
    assert fark == math.ceil(len(C.escape_json("x = 1234567890;\n" * 10).encode()) / LM.BYTES_PER_TOKEN_CODE) \
        or abs(fark - len(C.escape_json("x = 1234567890;\n" * 10).encode()) / LM.BYTES_PER_TOKEN_CODE) < 2


def test_olcumdeki_oranlar_ve_pay():
    b = C.ContextBudget(LM.CONTEXT_TOKENS, LM.MAX_TOKENS_STEP)
    for eski, yeni, gercek in K0_DUMAN_JETON:
        assert gercek / yeni < gercek / eski                          # her istemde yaklaştı
        assert gercek / yeni <= 1.07 and yeni + b.margin_for(yeni) >= gercek   # pay en kötü durumu karşılıyor
    assert max(g / e for e, _, g in K0_DUMAN_JETON) > 1.16 and max(g / y for _, y, g in K0_DUMAN_JETON) < 1.07
