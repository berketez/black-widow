"""P22h kalem 2 — keşif isteminin bütçesi: önek dilimi, oturum bloğunun kısalma kuralı, sığmayan soru.

Kural (``context.session_room``; ``Agent._execute_question``):
  1. Önek sabittir ve ``BUDGET_PREFIX_TOKENS`` (2 200) dilimine sığar (iki motor); soru ve oturum bloğu önekte değil
     kullanıcı iletisindedir (önek bayt bayt sabit, K-B1).
  2. Soru ve anılan fonksiyonların paketleri KISALTILMAZ.
  3. Kısalan tek parça oturum bloğudur: payı en çok ``BUDGET_SESSION_TOKENS`` (600); döngüde araç sonuçları dilimi
     (``BUDGET_TOOL_RESULTS_TOKENS``) önce ayrılır. Sığmazsa en eski kayıtlar düşer, gerekirse blok hiç girmez;
     sonuç (``TaskResult.session_block``) ve terminal bunu söyler.
  4. Blok sıfırken de sabit parçalar sığmıyorsa görev başlamadan reddedilir (``baglam_asimi``; model çağrılmaz).

Gerçek model yok. Mutasyon: ``scripts/measurement/mutation_specs_lm_kesif.json`` (``bu_*``).
"""
from __future__ import annotations

import json

import pytest

from karadul.lm import BUDGET_PREFIX_TOKENS, BUDGET_SESSION_TOKENS, BUDGET_TOOL_RESULTS_TOKENS, MAX_TOKENS_STEP
from karadul.lm import agent as G
from karadul.lm import backend as B
from karadul.lm import context as C
from karadul.lm import modes as M
from karadul.lm import notebook as N
from karadul.lm import session as S
from karadul.lm import tools as T
from tests.test_lm_tools import A, default_ws, fun
from tests.test_p22h_oturum_blogu import Arka

SHA = "aa" * 32
BEKLE = 20.0


@pytest.fixture(autouse=True)
def _oturumu_kapat():
    yield
    s = S.current_session()
    if s is not None:
        s.close()


def test_onek_dilime_sigar_ve_sorudan_bagimsiz(tmp_path):
    for loop in (True, False):
        p = M.explore_prefix(loop)
        assert C.estimate_text_tokens(p) <= BUDGET_PREFIX_TOKENS
    assert C.estimate_text_tokens(M.explore_prefix(True)) == 2130          # P22e: 2 108 (blok yeniden yazıldı)
    ws = T.Workspace(default_ws(tmp_path / "ws"))
    sistem = []
    for q in ("ne yapıyor?", "ğ" * 1900):
        arka = Arka()
        G.Agent(arka, ws).ask(q, [fun(A)])
        sistem.append(arka.calls[0]["messages"][0]["content"])
    assert sistem[0] == sistem[1] == M.explore_prefix(False)               # soru önekte değil


def test_session_room_kurali():
    b = C.ContextBudget(16384, MAX_TOKENS_STEP)
    assert C.session_room(b, 3000) == BUDGET_SESSION_TOKENS == 600
    assert C.session_room(b, 3000, BUDGET_TOOL_RESULTS_TOKENS) == 600
    # sınır: dönen pay sığar, bir fazlası sığmaz
    for fixed, reserve in ((14300, 0), (8300, 6000), (8650, 6000)):
        s = C.session_room(b, fixed, reserve)
        assert 0 < s < 600 and b.fits(fixed + s + reserve)
        assert not b.fits(fixed + s + 1 + reserve)
    assert C.session_room(b, 9600, 6000) == 0                              # sabit + yedek bile sığmıyor
    assert C.session_room(b, 100, cap=50) == 50
    with pytest.raises(ValueError):
        C.session_room(b, -1)


def _defter(root, n=30):
    nb = N.Notebook(SHA, root=root)
    for i in range(n):
        nb.note("o1", f"{0x1000 + i:x}", f"not {i}: " + "uzun açıklama " * 12)
    return nb


def test_blok_kisalir_soru_ve_paket_kisalmaz(tmp_path):
    ws = T.Workspace(default_ws(tmp_path / "ws"))
    nb = _defter(tmp_path / "depo")
    q = "@FUN_00001000 neyi çağırıyor?"
    temel = G.Agent(Arka(), ws).ask(q, [fun(A)])
    sabit = temel.est_prompt_tokens
    # tek atış: bağlam sabit + 200 jetonluk pay bırakacak kadar (sabit + 200 ≤ 5 120 → pay 512)
    arka = Arka()
    r = G.Agent(arka, ws, context_tokens=sabit + 200 + 512 + MAX_TOKENS_STEP).ask(
        q, [fun(A)], session_block=lambda n: nb.session_block(max_tokens=n))
    assert r.status == "tamam" and r.session_block["pay"] == 200 and r.session_block["kisaldi"] is True
    assert 0 < r.session_block["kestirim"] <= 200
    user = arka.calls[0]["messages"][1]["content"]
    assert "older records not shown)" in user.splitlines()[1]
    assert user.endswith(C.explore_question(q, [fun(A)], ["r1", "r2"], max_chars=480, loop=False))
    assert r.est_prompt_tokens == sabit + r.session_block["kestirim"]
    # bol bağlam: tam blok, kısalma yok
    r2 = G.Agent(Arka(), ws).ask(q, [fun(A)], session_block=lambda n: nb.session_block(max_tokens=n))
    assert r2.session_block["kisaldi"] is False and r2.session_block["pay"] == 600
    # pay yok: blok hiç girmez; sabit parçalar sığıyor, görev sürer
    arka3 = Arka()
    r3 = G.Agent(arka3, ws, context_tokens=sabit + 512 + MAX_TOKENS_STEP).ask(
        q, [fun(A)], session_block=lambda n: nb.session_block(max_tokens=n))
    assert r3.status == "tamam" and r3.session_block == {"pay": 0, "kestirim": 0, "kisaldi": True}
    assert "Researcher notebook" not in arka3.calls[0]["messages"][1]["content"]
    # sabit parçalar sığmıyor: görev başlamadan ret, model çağrılmaz
    arka4 = Arka()
    r4 = G.Agent(arka4, ws, context_tokens=sabit).ask(q, [fun(A)])
    assert r4.status == G.STATUS_CONTEXT and arka4.calls == []


def test_dongude_arac_dilimi_once_ayrilir(tmp_path):
    ws = T.Workspace(default_ws(tmp_path / "ws"))
    nb = _defter(tmp_path / "depo")
    q = "@FUN_00001000 neyi çağırıyor?"
    temel = G.Agent(Arka(), ws, enabled_modes=("K0", "K2")).ask(q, [fun(A)])
    sabit = temel.est_prompt_tokens
    # bağlam: sabit + 6 000 araç dilimi + 300 + pay (oransal %10) ... yalnız bloğa ~300 kalsın
    b_ctx = 0
    for ctx in range(sabit + BUDGET_TOOL_RESULTS_TOKENS, sabit + BUDGET_TOOL_RESULTS_TOKENS + 4000):
        if C.session_room(C.ContextBudget(ctx, MAX_TOKENS_STEP), sabit, BUDGET_TOOL_RESULTS_TOKENS) == 300:
            b_ctx = ctx
            break
    assert b_ctx
    arka = Arka()
    r = G.Agent(arka, ws, enabled_modes=("K0", "K2"), loop_context_tokens=b_ctx).ask(
        q, [fun(A)], session_block=lambda n: nb.session_block(max_tokens=n))
    assert r.status == "tamam" and r.session_block["pay"] == 300 and r.session_block["kisaldi"] is True
    # yedek ayrılmasaydı tam blok sığardı
    assert C.session_room(C.ContextBudget(b_ctx, MAX_TOKENS_STEP), sabit) == 600


def test_oturum_kisalma_ve_sigmayan_soru_satirlari(tmp_path):
    root = tmp_path / "ws"
    default_ws(root)
    _defter(tmp_path / "depo")
    arka = Arka()
    s = S.open_session(root, backend=arka, binary_sha256=SHA, store_root=tmp_path / "depo")
    sabit = G.Agent(Arka(), T.Workspace(root)).ask("@FUN_00001000 ne?", [fun(A)]).est_prompt_tokens
    s.agent.context_tokens = sabit + 200 + 512 + MAX_TOKENS_STEP
    assert s.submit("@FUN_00001000 ne?")["kabul"] and s.wait_idle(BEKLE)
    satirlar = [e["metin"] for e in s.stream.since(0)["olaylar"] if e["tur"] == "satir"]
    assert any(x.startswith("oturum bloğu bağlama sığmadı: 200 jetonluk pay") for x in satirlar)
    s.agent.context_tokens = 900
    assert s.submit("@FUN_00001000 ne?")["kabul"] and s.wait_idle(BEKLE)
    satirlar = [e["metin"] for e in s.stream.since(0)["olaylar"] if e["tur"] == "satir"]
    assert satirlar[-1].startswith("soru ve anılan fonksiyonların paketi bağlama sığmıyor")
    biten = [e for e in s.stream.since(0)["olaylar"] if e["tur"] == "gorev_bitti"]
    assert biten[-1]["durum"] == "baglam_asimi" and len(arka.calls) == 1
    assert json.dumps(biten[-1], ensure_ascii=False)
