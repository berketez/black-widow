"""P21 / LM-02 — akış ya da gövde okunurken kopma / zaman aşımı ``LMError``'a sarılır; görev ve kuyruk düşmez.

Kusur (``kulvar_LM.md`` LM-02): istemci yalnız bağlantı kurulurken çıkan hatayı ``BackendError``'a
çeviriyordu; başlıklardan sonra akış satırları ya da gövde okunurken çıkan ``ConnectionResetError``,
``TimeoutError``, ``IncompleteRead`` olduğu gibi yükseliyordu. Ajan bunu "beklenmeyen hata" sayıp
sunucuyu kapatıyor ve istisnayı yükseltiyordu (kuyruk düşer). ``[DONE]`` gelmeden temiz kapanan akış
yarım metni "başarılı" döndürüyordu. Burada sahte taşıma ve sahte arka uçla: model, sunucu, ağ yok.

Mutasyon koruması: ``scripts/measurement/mutation_specs_p21.json``.
"""
from __future__ import annotations

import http.client
import json

import pytest

import karadul.lm as LM
from karadul.lm import agent as G
from karadul.lm import backend as B
from karadul.lm import tools as T
from karadul.lm.audit import AuditLog
from tests.test_lm_tools import A, CB, default_ws, fun

from tests.test_lm_backend import ANAHTAR  # noqa: E402  (aynı sahte anahtar)
PARCA = b'data: {"choices":[{"delta":{"content":"{\\"isim\\""}}]}\n'
YOK = {"isim": None, "gerekce": "Kanıt yetersiz.", "cekimser": True, "kanit": []}


def _satirlar(*parcalar, hata=None):
    yield from parcalar
    if hata is not None:
        raise hata


def _tasima(lines=None, read=None, kapanis_hatasi=None):
    def kapat():
        if kapanis_hatasi is not None:
            raise kapanis_hatasi

    def t(method, url, headers, body, timeout):
        return B.HttpResponse(200, lines if lines is not None else iter(()), read or (lambda: b"{}"), kapat)
    return t


def _istemci(t):
    return B._OpenAIClient("http://127.0.0.1:1/v1/chat/completions", ANAHTAR, "m", t,
                           lambda s: s.replace(ANAHTAR, "<gizli>"), thinking_control=False)


def _sohbet(t, akis):
    return _istemci(t).chat([{"role": "user", "content": "x"}], None, akis, 16, None, 5)


def _firlat(e):
    def f():
        raise e
    return f


# --------------------------------------------------------------------------------------------
# İstemci katmanı


@pytest.mark.parametrize("akis,tasima", [
    (True, _tasima(lines=_satirlar(PARCA, hata=ConnectionResetError(54, "reset " + ANAHTAR)))),
    (True, _tasima(lines=_satirlar(PARCA, hata=TimeoutError("timed out")))),
    (False, _tasima(read=_firlat(TimeoutError("timed out")))),
    (False, _tasima(read=_firlat(http.client.IncompleteRead(b"{\"cho")))),
    (False, _tasima(read=_firlat(ConnectionResetError(54, "reset")))),
])
def test_okurken_kopma_backend_error_olur(akis, tasima):
    with pytest.raises(B.BackendError) as ei:
        _sohbet(tasima, akis)
    assert ei.value.transient is True
    assert ANAHTAR not in str(ei.value) and ei.value.__context__ is None and ei.value.__cause__ is None


def test_bitis_isareti_gelmeden_kesilen_akis():
    with pytest.raises(B.BackendError) as ei:
        _sohbet(_tasima(lines=_satirlar(PARCA)), True)
    assert ei.value.transient is True and "kesildi" in str(ei.value)
    # bitiş nedeni geldiyse [DONE]'sız uç kabul edilir; [DONE] varsa elbette
    son = b'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}\n'
    r = _sohbet(_tasima(lines=_satirlar(PARCA, son)), True)
    assert (r.content, r.finish_reason) == ('{"isim"', "stop")
    r = _sohbet(_tasima(lines=_satirlar(PARCA, b"data: [DONE]\n")), True)
    assert r.content == '{"isim"' and r.finish_reason is None


def test_bozuk_choices_turu_lmerror_ya_da_bos_cevap():
    # nesne biçimli choices: KeyError değil
    r = _sohbet(_tasima(read=lambda: json.dumps({"choices": {"0": {}}}).encode()), False)
    assert (r.content, r.finish_reason) == ("", None)
    with pytest.raises(B.BackendError):
        _sohbet(_tasima(lines=_satirlar(b'data: {"choices": {"a": 1}}\n')), True)
    # HTTP hata kodu ve bozuk JSON geçici sayılmaz
    with pytest.raises(B.BackendError) as ei:
        _sohbet(_tasima(read=lambda: b"bozuk"), False)
    assert ei.value.transient is False


def test_kapanista_hata_sonucu_ortmez():
    r = _sohbet(_tasima(lines=_satirlar(PARCA, b"data: [DONE]\n"), kapanis_hatasi=OSError("kapanış")), True)
    assert r.content == '{"isim"'


def test_backend_chat_sarilmamis_gc_hatasini_sarar():
    gunluk = AuditLog()
    arka = B.FakeBackend([B.FakeReply(error=ConnectionResetError(54, "reset"))], audit=gunluk)
    with pytest.raises(B.BackendError) as ei:
        arka.chat([{"role": "user", "content": "x"}])
    assert ei.value.transient is True and ei.value.__context__ is None
    assert [k["olay"] for k in gunluk.records] == ["model_istegi"] and "ConnectionResetError" in gunluk.records[0]["hata"]
    # programlama hatası sarılmaz (beklenmeyen hata olarak kalır)
    arka2 = B.FakeBackend([B.FakeReply(error=KeyError("x"))])
    with pytest.raises(KeyError):
        arka2.chat([{"role": "user", "content": "x"}])


# --------------------------------------------------------------------------------------------
# Ajan katmanı: görev ve kuyruk düşmez


def _ajan(tmp_path, yanitlar, **kw):
    arka = B.FakeBackend(yanitlar, audit=AuditLog())
    return G.Agent(arka, T.Workspace(default_ws(tmp_path / "ws")), **kw), arka


def _yok(**kw):
    return B.FakeReply(content=json.dumps(YOK), **kw)


def test_kuyrukta_kopma_gorevi_ve_kuyrugu_dusurmez(tmp_path):
    kopma = ConnectionResetError(54, "reset")
    ajan, arka = _ajan(tmp_path, [_yok(), B.FakeReply(error=kopma), B.FakeReply(error=kopma), _yok()])
    sonuclar = [ajan.suggest_name(fun(a)) for a in (A, CB, A)]     # istisna yükselmez
    assert [r.status for r in sonuclar] == ["tamam", "arka_uc_hatasi", "tamam"]
    orta = sonuclar[1]
    assert (orta.counters.model_calls, orta.counters.retries) == (2, 1)
    assert "BackendError" in orta.error and "yineleme 1/1" in orta.error
    assert arka.stops == [] and arka.state == B.STATE_READY         # sunucu kapatılmadı
    assert LM.MODEL_RETRY_MAX == 1


def test_tek_kopma_yinelenir_gorev_tamamlanir(tmp_path):
    ajan, arka = _ajan(tmp_path, [B.FakeReply(error=TimeoutError("timed out")), _yok()])
    r = ajan.suggest_name(fun(A))
    assert (r.status, r.counters.model_calls, r.counters.retries, len(arka.calls)) == ("tamam", 2, 1, 2)
    amaclar = [k["amac"] for k in ajan.audit.records if k["olay"] == "model_istegi"]
    assert amaclar == ["k0", "k0_yineleme"]


def test_kalici_hata_ve_olmus_sunucu_yinelenmez(tmp_path):
    ajan, arka = _ajan(tmp_path / "1", [B.FakeReply(error=B.HttpStatusError(500, "x")), _yok()])
    r = ajan.suggest_name(fun(A))
    assert (r.status, r.counters.retries, len(arka.calls)) == ("arka_uc_hatasi", 0, 1)
    # sunucu hata nedeniyle durdu (ölmüş yerel sunucu): yeniden yüklenmez, istek yinelenmez
    ajan, arka = _ajan(tmp_path / "2", [B.FakeReply(error=ConnectionResetError(54, "x"), delay_sec=1), _yok()])
    arka._sleep = lambda s: arka.stop("hata")
    r = ajan.suggest_name(fun(A))
    assert (r.status, r.counters.retries, len(arka.calls)) == ("arka_uc_hatasi", 0, 1)


def test_iptal_ve_sure_doldugunda_yinelenmez(tmp_path):
    ajan, arka = _ajan(tmp_path / "1", [B.FakeReply(error=ConnectionResetError(54, "x"), delay_sec=1), _yok()])
    arka._sleep = lambda s: ajan.cancel.set()
    r = ajan.suggest_name(fun(A))
    assert (r.status, r.counters.retries, len(arka.calls)) == ("arka_uc_hatasi", 0, 1)
    simdi = [0.0]
    ajan, arka = _ajan(tmp_path / "2", [B.FakeReply(error=ConnectionResetError(54, "x"), delay_sec=100), _yok()],
                       clock=lambda: simdi[0], enabled_modes=("K0", "K2"))
    arka._sleep = lambda s: simdi.__setitem__(0, simdi[0] + s)
    r = ajan.run_loop(fun(A), deadline_sec=50.0)
    assert r.counters.retries == 0 and len(arka.calls) == 1 and r.status == "arka_uc_hatasi"
