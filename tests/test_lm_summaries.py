"""KaradulLM v2 P22b: açıkla / özet alt görevi, aşağıdan yukarı özet zinciri ve özet deposu.

Tasarım: ``docs/arge/2026-11-18_karadullm_v2/TASARIM.md`` §3.2, §3.3, §3.6, §3.7, §3.10. Gerçek model,
sunucu ve ağ yok: sentetik çalışma alanı (``tests/test_lm_tools.py``) ve betikli sahte arka uç.

Kilitlenen davranışlar:
  (a) KL-1 istemi ve "açıkla" şeması: KL-0 (ad öner, pilot) bayt bayt değişmez; KL-1 = KL-0 + 9. kural;
      görev türü olay akışına ve görev kaydına doğru yazılır (P22a notu),
  (b) özet deposu (``summaries.py``) ve geçersiz kılma,
  (c) zincir: paketteki ``[model-özet]`` girişi, D0 kısa yolu, körlük, denetim (D8 / D9 / D13).

Mutasyon koruması: ``scripts/measurement/mutation_specs_lm_ozet.json``.
"""
from __future__ import annotations

import json

import pytest

from karadul.lm import RATIONALE_MAX_CHARS
from karadul.lm import agent as G
from karadul.lm import backend as B
from karadul.lm import context as C
from karadul.lm import protocol as P
from karadul.lm import tools as T
from tests.test_lm_events import esler_tutarli, ilk, olayli, turler, yanit
from tests.test_lm_tools import A, B as FB, CB, default_ws, fun

OZET = {"ozet": "Bir tabloyu ayrıştırıp sonucu döndürür.", "belirsiz": False, "kanit": ["r1", "r2"]}
BELIRSIZ = {"ozet": "Çağrılanların işlevi bilinmiyor.", "belirsiz": True, "kanit": []}


# --------------------------------------------------------------------------------------------
# (a) KL-1 istemi, "açıkla" şeması, görev türü

def test_kl0_degismez_kl1_dokuzuncu_kural_ekler():
    satirlar = T.default_registry().definition_lines()
    k0 = C.fixed_prefix(C.MODE_K0, satirlar)
    assert k0 == C.fixed_prefix(C.MODE_K0, satirlar, C.PROMPT_VERSION)
    assert k0.startswith(C.SYSTEM_PROMPT_KL0)            # ad öner öneki: pilotun KL-0 metni aynen
    assert C.SYSTEM_PROMPT_KL0.count("\n9. ") == 0
    kl1 = C.fixed_prefix(C.MODE_K0, satirlar, C.PROMPT_VERSION_KL1)
    assert kl1 != k0 and kl1.startswith(C.SYSTEM_PROMPT_KL1)
    # KL-1 = KL-0'ın 8. kuralına kadar aynısı + 9. kural + aynı kapanış paragrafı
    bas, son = C.SYSTEM_PROMPT_KL0.split("\nReply with exactly one JSON object")
    assert C.SYSTEM_PROMPT_KL1 == bas + C.SUMMARY_RULE_KL1 + "\nReply with exactly one JSON object" + son
    assert C.SUMMARY_RULE_KL1.startswith("9. ") and C.SUMMARY_RULE_KL1.endswith("\n")
    assert '"kaynak": "model-özet"' in C.SUMMARY_RULE_KL1 and "not evidence" in C.SUMMARY_RULE_KL1
    assert kl1 == C.fixed_prefix(C.MODE_K0, satirlar, "KL-1")   # K-B1: aynı girdi, aynı önek
    for kip in (C.MODE_K1, C.MODE_K2):
        with pytest.raises(ValueError):
            C.fixed_prefix(kip, satirlar, C.PROMPT_VERSION_KL1)
    with pytest.raises(ValueError):
        C.fixed_prefix(C.MODE_K0, satirlar, "KL-9")


def test_aciklama_semasi_ve_sorusu():
    s = P.build_explain_answer_schema(["r1", "r2"])
    verilen, belirsiz = s["anyOf"]
    for dal in (verilen, belirsiz):
        assert dal["required"] == ["ozet", "belirsiz", "kanit"] and dal["additionalProperties"] is False
        assert dal["properties"]["ozet"] == {"type": "string", "minLength": 1, "maxLength": RATIONALE_MAX_CHARS}
        assert dal["properties"]["kanit"] == {"type": "array", "items": {"type": "string", "enum": ["r1", "r2"]},
                                              "maxItems": 2}
    assert verilen["properties"]["belirsiz"] == {"const": False}
    assert belirsiz["properties"]["belirsiz"] == {"const": True}
    assert not P.validate(OZET, s) and not P.validate(BELIRSIZ, s)
    for bozuk in ({**OZET, "ozet": ""}, {**OZET, "ozet": "x" * (RATIONALE_MAX_CHARS + 1)},
                  {**OZET, "kanit": ["r9"]}, {**OZET, "isim": "f"}, {"ozet": "a", "kanit": []},
                  {**OZET, "belirsiz": "hayir"}):
        assert P.validate(bozuk, s), bozuk
    with pytest.raises(P.SchemaError):
        P.build_explain_answer_schema([])
    soru = C.explain_question("FUN_1234", ["r1", "r2"])
    assert soru.startswith("Task: explain what the function FUN_1234 does.")
    assert f"at most {RATIONALE_MAX_CHARS} characters" in soru and '"belirsiz": true' in soru
    assert soru.endswith('"kanit" may only contain these ids: r1, r2.\n')
    for bozuk_adres, kimlik in (("1234", ["r1"]), ("FUN_1234", []), ("FUN_1234", ["x1"])):
        with pytest.raises(ValueError):
            C.explain_question(bozuk_adres, kimlik)


def test_acikla_gorevi_kl1_ile_tek_cagri_ve_gorev_turu(tmp_path):
    ajan, arka, gunluk, akis = olayli(tmp_path, [yanit(OZET)])
    r = ajan.explain(fun(A))
    assert r.status == G.STATUS_DONE and r.task == "acikla" and r.prompt_version == "KL-1"
    assert r.answer == OZET
    assert r.summary["kaynak"] == "model" and r.summary["metin"] == OZET["ozet"] and not r.summary["belirsiz"]
    assert r.summary["kanit"] == ["r1", "r2"] and r.summary["depodan"] is False
    istek = arka.calls[0]
    assert istek["messages"][0]["content"] == ajan.prefix(C.MODE_K0, C.PROMPT_VERSION_KL1)
    assert istek["messages"][1]["content"].endswith(C.explain_question(fun(A), ["r1", "r2"]))
    assert istek["schema"] == P.build_explain_answer_schema(["r1", "r2"])
    assert len(arka.calls) == 1 and r.counters.model_calls == 1
    # Olaylar: gorev_turu "acikla" (sabit "ad_oner" değil); özet olayı görev sonundan önce
    assert ilk(akis, "gorev_basladi")["gorev_turu"] == "acikla"
    t = turler(akis)
    assert t.index("ozet") == len(t) - 2 and t[-1] == "gorev_bitti"
    oz = ilk(akis, "ozet")
    assert oz["metin"] == OZET["ozet"] and oz["kaynak"] == "model" and oz["kanit"] == ["r1", "r2"]
    assert oz["hedef"] == {"fn": fun(A), "adres": A}
    esler_tutarli(akis, gunluk)
    kayit = [k for k in gunluk.records if k["olay"] == "gorev"][-1]
    assert kayit["tur"] == "acikla" and kayit["istem_surumu"] == "KL-1"
    assert kayit["onek_sha256"] == ajan.prefix_sha256(C.MODE_K0, C.PROMPT_VERSION_KL1)
    assert kayit["ozet"] == {"kaynak": "model", "belirsiz": False, "pakete_girer": r.summary["pakete_girer"],
                             "depodan": False}
    assert OZET["ozet"] not in json.dumps(gunluk.records, ensure_ascii=False)   # kayıt içeriksiz


def test_ad_oner_kl0_ve_tur_degismez(tmp_path):
    ajan, arka, gunluk, akis = olayli(tmp_path, [yanit({"isim": "parse_table", "gerekce": "Ayrıştırır.",
                                                        "cekimser": False, "kanit": ["r1"]})])
    r = ajan.suggest_name(fun(A))
    assert r.task == "ad_oner" and r.prompt_version == "KL-0" and r.summary is None
    assert arka.calls[0]["messages"][0]["content"] == ajan.prefix(C.MODE_K0)
    assert ilk(akis, "gorev_basladi")["gorev_turu"] == "ad_oner" and "ozet" not in turler(akis)
    kayit = [k for k in gunluk.records if k["olay"] == "gorev"][-1]
    assert kayit["istem_surumu"] == "KL-0" and "ozet" not in kayit


def test_acikla_belirsiz_ve_gecersiz_cevap(tmp_path):
    ajan, arka, gunluk, akis = olayli(tmp_path, [yanit(BELIRSIZ)])
    r = ajan.explain(fun(A))
    assert r.status == G.STATUS_DONE and r.summary["belirsiz"] is True and r.summary["kanit"] == []
    assert ilk(akis, "ozet")["belirsiz"] is True
    # L2: şemaya uymayan cevap bir kez onarılır; ikincisi de bozuksa görev biter, özet yok
    ajan, arka, gunluk, akis = olayli(tmp_path / "b", [yanit({"ozet": "", "belirsiz": False, "kanit": []}),
                                                      yanit({"isim": "x"})], duzey="L2")
    r = ajan.explain(fun(A))
    assert r.status == "sema_ihlali" and r.summary is None and r.counters.repairs == 1 and len(arka.calls) == 2
    assert "ozet" not in turler(akis)
    # Bilinmeyen adres: model çağrılmaz
    ajan, arka, gunluk, akis = olayli(tmp_path / "c", [])
    r = ajan.explain("FUN_99999999")
    assert r.status == G.STATUS_UNKNOWN_ADDRESS and not arka.calls and r.task == "acikla"
