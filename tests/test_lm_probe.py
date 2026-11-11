"""karadul/lm/probe.py — hız yoklaması ve arayüz kipi kuralı.

Tasarım: ``docs/arge/2026-11-11_karadullm/tasarim.md`` §2.2 "Hız yoklaması", §8.3. Gerçek model
yoktur: istekler betikli sahte arka uçtan (``karadul.lm.backend.FakeBackend``) gelir. Tasarım
tablosundaki [hesap] değerleri (§8.3: A-yük 28,7 sn, A-boş 16,7 sn, ön işlemeyle 7,6 sn) aritmetik
denetimi olarak kullanılır; ölçüm iddiası değildir.

Kilitlenen davranışlar:
  (a) yoklama iki istektir; ikincisi birincinin konuşmasını bayt bayt taşır ve yalnız sona ekler
      ("ek" deseni); metin yapaydır ve her yoklamada etiketi değişir; üretim tavanları 1 ve 64,
  (b) ``timings`` yolu: P istek 1'den, G istek 2'den, ö istek 2'nin ``cache_n``'inden (≥ %95),
  (c) ``akis`` yolu: G akış zaman damgalarından, P ilk jeton sürelerinin farkından (işlenen jetonla);
      önbellek bilgisi yoksa P ve ö boş,
  (d) her hız yalnız geçerlilik koşulunda dolar (sınır değerleri); ölçülmeden önce bütün alanlar boş,
  (e) T̂ formülü ve kip kuralı (τ sınırında etkileşimli; bant ±%20; bilinmeyen önceki kip hata),
  (f) kayan medyan son 5 gözlem; ilk jeton göstergesi; yoklama denetim kaydı.

Mutasyon koruması: ``scripts/measurement/mutation_specs_lm_cekirdek.json``
(``PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec <o dosya>``).
"""
from __future__ import annotations

import math

import pytest

import karadul.lm as LM
from karadul.lm import audit as A
from karadul.lm import probe as P
from karadul.lm.backend import ChatResult, FakeBackend, FakeReply

ESIK = LM.PROBE_MIN_PREFILL_TOKENS
URET = LM.PROBE_MIN_GEN_TOKENS


def _sonuc(*, usage=None, timings=None, ilk=None, son=None, sure=1.0, icerik="OK"):
    return ChatResult(content=icerik, finish_reason="stop", usage=usage, timings=timings, duration_sec=sure,
                      first_token_sec=ilk, last_token_sec=son, content_events=1, stream=True, request_meta={},
                      messages_sha256="0" * 64, messages_bytes=0)


# --------------------------------------------------------------------------------------------
# (a) istekler


def test_yoklama_iki_istek_ve_ek_deseni():
    s = FakeBackend([FakeReply(content="OK"), FakeReply(content="0001. ...")])
    P.run_probe(s, nonce="n1")
    assert len(s.calls) == 2
    m1, m2 = s.calls[0]["messages"], s.calls[1]["messages"]
    assert m2[: len(m1)] == m1
    assert m2[len(m1)] == {"role": "assistant", "content": "OK"} and m2[-1]["role"] == "user"
    assert len(m2) == len(m1) + 2
    assert [c["max_tokens"] for c in s.calls] == [LM.PROBE_FIRST_MAX_TOKENS, LM.PROBE_GEN_TOKENS] == [1, 64]
    assert all(c["stream"] for c in s.calls) and all(c["schema"] is None for c in s.calls)
    assert P.probe_messages("n1") == m1
    assert P.probe_messages("n1") != P.probe_messages("n2")
    assert P.probe_text("n1").splitlines()[0] == "Probe n1."
    sozcukler = set(P._WORDS)
    for satir in P.probe_text("n1").splitlines()[1:]:
        no, *govde, onaltilik = satir.split()
        assert no.endswith(".") and set(govde) <= sozcukler and onaltilik.startswith("0x")
    assert sum(len(sat.split()) - 2 for sat in P.probe_text("n1").splitlines()[1:]) >= LM.PROBE_WORDS


# --------------------------------------------------------------------------------------------
# (b) timings yolu


def _timings_ciftleri(cache_n=1012, p1_n=1012):
    r1 = _sonuc(usage={"prompt_tokens": 1012, "completion_tokens": 1},
                timings={"prompt_n": p1_n, "cache_n": 0, "prompt_per_second": 117.3, "predicted_n": 1,
                         "predicted_per_second": 3.0})
    r2 = _sonuc(usage={"prompt_tokens": 1040, "completion_tokens": 64},
                timings={"prompt_n": 1040 - cache_n, "cache_n": cache_n, "prompt_per_second": 40.0,
                         "predicted_n": 64, "predicted_per_second": 10.9})
    return r1, r2


def test_timings_yolu():
    r = P.compute_probe(*_timings_ciftleri(), measured_at="2026-11-11T12:00:00+03:00")
    assert r.path == P.PATH_TIMINGS and r.measured_at == "2026-11-11T12:00:00+03:00"
    assert r.prefill_tps == 117.3 and r.gen_tps == 10.9
    assert r.cached_tokens == 1012 and r.common_prefix_tokens == 1012 and r.prefix_reuse == 1
    assert r.notes == [] and r.duration_sec == 2.0 and len(r.requests) == 2
    assert r.requests[1]["onbellek_jeton"] is None and r.requests[0]["timings_var"] is True
    r = P.compute_probe(*_timings_ciftleri(cache_n=0))
    assert r.prefix_reuse == 0 and r.prefill_tps == 117.3
    r = P.compute_probe(*_timings_ciftleri(p1_n=ESIK - 1))
    assert r.prefill_tps is None and any(n.startswith("P yok") for n in r.notes)
    r1, r2 = _timings_ciftleri()
    r1.usage = None
    r1.timings["cache_n"] = 12
    assert P.compute_probe(r1, r2).common_prefix_tokens == 1012 + 12


def test_timings_hiz_alanlari_sinir():
    assert P.prefill_from_timings({"prompt_n": ESIK, "prompt_per_second": 100.0}) == 100.0
    assert P.prefill_from_timings({"prompt_n": ESIK - 1, "prompt_per_second": 100.0}) is None
    for kotu in (0, -5.0, float("nan"), float("inf"), True, "100", None):
        assert P.prefill_from_timings({"prompt_n": 2000, "prompt_per_second": kotu}) is None, kotu
    assert P.prefill_from_timings(None) is None and P.prefill_from_timings({"prompt_n": True}) is None
    assert P.gen_from_timings({"predicted_n": URET, "predicted_per_second": 9.5}) == 9.5
    assert P.gen_from_timings({"predicted_n": URET - 1, "predicted_per_second": 9.5}) is None
    assert P.gen_from_timings({"predicted_n": 64}) is None and P.gen_from_timings([]) is None


# --------------------------------------------------------------------------------------------
# (c) akış yolu


def test_akis_yolu_onbellek_bildirilirse():
    r1 = _sonuc(usage={"prompt_tokens": 1000, "completion_tokens": 1, "prompt_tokens_details": {"cached_tokens": 0}},
                ilk=9.0, son=9.0)
    r2 = _sonuc(usage={"prompt_tokens": 1030, "completion_tokens": 64,
                       "prompt_tokens_details": {"cached_tokens": 1000}}, ilk=0.7, son=7.0)
    r = P.compute_probe(r1, r2)
    assert r.path == P.PATH_STREAM
    assert r.prefill_tps == pytest.approx((30 - 1000) / (0.7 - 9.0))
    assert r.gen_tps == pytest.approx(63 / 6.3)
    assert r.prefix_reuse == 1 and r.cached_tokens == 1000 and r.common_prefix_tokens == 1000
    yok = _sonuc(usage={"prompt_tokens": 1030, "completion_tokens": 64,
                        "prompt_tokens_details": {"cached_tokens": 0}}, ilk=9.3, son=15.6)
    r = P.compute_probe(r1, yok)
    assert r.prefix_reuse == 0 and r.prefill_tps is None
    assert any("farkı" in n for n in r.notes)


def test_akis_yolu_onbellek_bilgisi_yoksa_P_ve_o_bos():
    r1 = _sonuc(usage={"prompt_tokens": 1000, "completion_tokens": 1}, ilk=9.0, son=9.0)
    r2 = _sonuc(usage={"prompt_tokens": 1030, "completion_tokens": 64}, ilk=0.7, son=7.0)
    r = P.compute_probe(r1, r2)
    assert r.prefill_tps is None and r.prefix_reuse is None and r.gen_tps == pytest.approx(10.0)
    assert any("cached_tokens" in n for n in r.notes) and any(n.startswith("ö yok") for n in r.notes)
    r2.usage = {"prompt_tokens": 1030}
    r = P.compute_probe(r1, r2)
    assert r.gen_tps is None and any(n.startswith("G yok") for n in r.notes)


def test_akis_hiz_aritmetigi_sinir():
    assert P.gen_from_stream(64, 1.0, 7.3) == pytest.approx(10.0)
    assert P.gen_from_stream(URET, 0.0, 1.0) == URET - 1
    assert P.gen_from_stream(URET - 1, 0.0, 1.0) is None
    assert P.gen_from_stream(64, 2.0, 2.0) is None and P.gen_from_stream(64, 3.0, 2.0) is None
    assert P.gen_from_stream(64, None, 2.0) is None and P.gen_from_stream(True, 0.0, 1.0) is None
    assert P.prefill_from_first_token(0, 1.0, ESIK, 2.0) == ESIK
    assert P.prefill_from_first_token(0, 1.0, ESIK - 1, 2.0) is None
    assert P.prefill_from_first_token(1000, 9.0, 30, 0.7) == pytest.approx(970 / 8.3)
    assert P.prefill_from_first_token(1000, 9.0, 30, 9.5) is None
    assert P.prefill_from_first_token(30, 1.0, 1000, 1.0) is None
    assert P.prefill_from_first_token(None, 1.0, 1000, 2.0) is None


def test_onek_yeniden_kullanimi_esigi():
    assert P.reuse_flag(950, 1000) == 1
    assert P.reuse_flag(949, 1000) == 0
    assert P.reuse_flag(0, 1000) == 0
    assert P.reuse_flag(None, 1000) is None and P.reuse_flag(950, None) is None and P.reuse_flag(5, 0) is None
    assert LM.PROBE_REUSE_FRACTION == 0.95


# --------------------------------------------------------------------------------------------
# (d) ölçülmeden önce boş


def test_olculmeden_once_bos():
    r = P.ProbeResult()
    for alan in ("measured_at", "path", "prefill_tps", "gen_tps", "prefix_reuse", "cached_tokens",
                 "common_prefix_tokens", "duration_sec"):
        assert getattr(r, alan) is None, alan
    k = P.SpeedTracker().decide()
    assert k.mode is None and k.t_hat_sec is None and k.first_token_sec is None and k.first_token_ok is None
    assert P.expected_name_suggest_sec(None, 10.0) is None and P.expected_name_suggest_sec(100.0, None) is None
    assert P.expected_name_suggest_sec(0.0, 10.0) is None and P.first_token_sec(None) is None


# --------------------------------------------------------------------------------------------
# (e) T̂ ve kip


def test_beklenen_sure_tasarim_tablosu():
    assert P.expected_name_suggest_sec(117.3, 10.9) == pytest.approx(2500 / 117.3 + 80 / 10.9)
    assert round(P.expected_name_suggest_sec(117.3, 10.9), 1) == 28.7
    assert round(P.expected_name_suggest_sec(195, 20.5), 1) == 16.7
    assert round(P.expected_name_suggest_sec(117.3, 10.9, prefix_reuse=1, prefill_on_select=True), 1) == 7.6
    assert P.expected_name_suggest_sec(117.3, 10.9, 1, False) == P.expected_name_suggest_sec(117.3, 10.9)
    assert P.expected_name_suggest_sec(117.3, 10.9, 0, True) == P.expected_name_suggest_sec(117.3, 10.9)
    assert P.expected_name_suggest_sec(117.3, 10.9, None, True) == P.expected_name_suggest_sec(117.3, 10.9)
    assert (LM.REF_PROMPT_TOKENS, LM.REF_PROMPT_TOKENS_PREFILLED, LM.REF_OUTPUT_TOKENS) == (2500, 30, 80)


def test_kip_kurali_sinir():
    tau = LM.INTERACTIVE_TAU_SEC
    assert tau == 10.0
    assert P.decide_mode(tau) == P.MODE_INTERACTIVE
    assert P.decide_mode(math.nextafter(tau, math.inf)) == P.MODE_QUEUE
    assert P.decide_mode(0.5) == P.MODE_INTERACTIVE
    assert P.decide_mode(28.7) == P.MODE_QUEUE
    assert P.decide_mode(None) is None and P.decide_mode(None, P.MODE_QUEUE) is None


def test_kip_bandi():
    tau, bant = LM.INTERACTIVE_TAU_SEC, LM.MODE_BAND
    ust, alt = tau * (1 + bant), tau * (1 - bant)
    assert bant == 0.20
    assert P.decide_mode(ust, P.MODE_INTERACTIVE) == P.MODE_INTERACTIVE
    assert P.decide_mode(math.nextafter(ust, math.inf), P.MODE_INTERACTIVE) == P.MODE_QUEUE
    assert P.decide_mode(11.0, P.MODE_INTERACTIVE) == P.MODE_INTERACTIVE
    assert P.decide_mode(alt, P.MODE_QUEUE) == P.MODE_INTERACTIVE
    assert P.decide_mode(math.nextafter(alt, math.inf), P.MODE_QUEUE) == P.MODE_QUEUE
    assert P.decide_mode(9.0, P.MODE_QUEUE) == P.MODE_QUEUE
    with pytest.raises(ValueError):
        P.decide_mode(5.0, "elle")


# --------------------------------------------------------------------------------------------
# (f) kayan medyan, ilk jeton, kayıt


def test_kayan_medyan_ve_kip_durumu():
    t = P.SpeedTracker(window=LM.ROLLING_WINDOW)
    t.seed_from_probe(P.ProbeResult(prefill_tps=117.3, gen_tps=10.9, prefix_reuse=1))
    k = t.decide()
    assert (k.prefill_tps, k.gen_tps) == (117.3, 10.9) and k.mode == P.MODE_QUEUE and t.mode == P.MODE_QUEUE
    for p in (1000.0, 1100.0, 1200.0, 1300.0):
        t.observe(prefill_tps=p, gen_tps=None)
    assert t.current() == (1100.0, 10.9)
    t.observe(prefill_tps=900.0, gen_tps=float("nan"))
    assert t.current()[0] == 1100.0
    t.observe(prefill_tps=-1.0, gen_tps=40.0)
    assert t.current() == (1100.0, (10.9 + 40.0) / 2)
    k = t.decide()
    assert k.mode == P.MODE_INTERACTIVE and k.t_hat_sec == pytest.approx(2500 / 1100 + 80 / 25.45)
    assert LM.ROLLING_WINDOW == 5


def test_ilk_jeton_gostergesi():
    t = P.SpeedTracker()
    t.observe(1250.0, 20.0)
    k = t.decide()
    assert k.first_token_sec == pytest.approx(2.0) and k.first_token_ok is True
    t2 = P.SpeedTracker()
    t2.observe(625.0, 20.0)
    assert t2.decide().first_token_ok is False
    t3 = P.SpeedTracker()
    t3.seed_from_probe(P.ProbeResult(prefill_tps=117.3, gen_tps=10.9, prefix_reuse=1))
    k = t3.decide(prefill_on_select=True)
    assert k.first_token_sec == pytest.approx(30 / 117.3) and k.prefill_on_select is True
    assert LM.FIRST_TOKEN_TARGET_SEC == 3.0


def test_yoklama_denetim_kaydi():
    g = A.AuditLog()
    s = FakeBackend([FakeReply(content="OK", usage={"prompt_tokens": 1012, "completion_tokens": 1},
                               timings={"prompt_n": 1012, "prompt_per_second": 117.3}),
                     FakeReply(content="0001.", usage={"prompt_tokens": 1040, "completion_tokens": 64},
                               timings={"cache_n": 1012, "predicted_n": 64, "predicted_per_second": 10.9})],
                    audit=g)
    r = P.run_probe(s, nonce="kayit", audit=g)
    assert [k["olay"] for k in g.records] == ["model_istegi", "model_istegi", "yoklama"]
    assert [k.get("amac") for k in g.records[:2]] == ["yoklama-1", "yoklama-2"]
    assert g.records[2]["sonuc"]["prefill_tps"] == 117.3 and g.records[2]["sonuc"]["prefix_reuse"] == 1
    assert r.prefill_tps == 117.3 and r.gen_tps == 10.9
    import json
    assert "0001. register" not in json.dumps(g.records) and "Probe kayit" not in json.dumps(g.records)
