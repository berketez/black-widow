"""karadul/lm/backend.py, memory_guard.py, audit.py — KaradulLM arka uç çekirdeği.

Tasarım: ``docs/arge/2026-11-11_karadullm/tasarim.md`` §2.2 (yerel sunucu, kullanıcı ucu, bellek
bekçisi), §5.4 (denetim günlüğü), §6 (güvenlik). Gerçek süreç başlatılmaz, ağ isteği atılmaz:
``Popen``, HTTP taşıyıcısı, ``ps``/``footprint`` ve saat sahteleriyle değiştirilir. Pilot harness'ı
(``scripts/measurement/llm_pilot.py``) dosya yolundan yüklenir; ürün kodu onu içe aktarmaz.

Kilitlenen davranışlar:
  (a) komut pilotun yalın bayraklarıyla birebir aynı + ``--api-key``; sunucu yalnız ``127.0.0.1``'de;
      çözme ayarları ve sabitler pilotla aynı,
  (b) süreç ``process_group=0`` ile açılır, ``start_new_session`` kullanılmaz; PID dosyası yazılır;
      künyede ikilinin ve şablonun sha256'sı,
  (c) her başlatma hatasında (hazır olmama, erken çıkış, ``Popen`` hatası, kesme) süreç kapatılır,
      PID dosyası silinir; terminate işlemezse kill; PID dosyasında kalan yetim süreç kapatılır,
      yabancı süreç kapatılmaz; boşta süre dolunca durdurulur,
  (d) anahtar hata iletisine, istisna bağlamına ve denetim günlüğüne sızmaz; iletiler günlüğe girmez,
  (e) loopback tanımı; loopback olmayan uca onaysız HİÇBİR istek atılmaz; onayla atılır,
  (f) yetenek düzeyi yoklaması L3 / L2 / L1; başka hatada düzey uydurulmaz; yoklanmadan şemalı istek
      atılmaz; ``response_format`` düzeye göre,
  (g) akış okuma: içerik, zaman damgaları, ``usage``/``timings``, hata parçası; yönlendirme izlenmez,
  (h) sahte arka uç betiği oynatır (cevap, gecikme, hata, bitiş); her istek tek denetim kaydı,
  (i) bellek ölçüsü pilotun tanımıyla aynı (RSS + footprint, 3 basamak); eşik sınırı; ölçülemeyen
      değer uydurulmaz; artalan bekçisi; aşımda arka uç ``bellek_durdu`` olur,
  (j) içe aktarma yan etkisiz; motor ``karadul.lm``'i içe aktarmaz; paket yalnız standart kitaplık.

Mutasyon koruması: ``scripts/measurement/mutation_specs_lm_cekirdek.json``
(``PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec <o dosya>``).
"""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
import signal
import subprocess
import sys
import threading
import time
import traceback
import urllib.error
import urllib.parse
from pathlib import Path
from types import SimpleNamespace

import pytest

import karadul.lm as LM
from karadul.lm import audit as A
from karadul.lm import backend as B
from karadul.lm import memory_guard as M

KOK = Path(__file__).resolve().parents[1]
_PILOT = KOK / "scripts" / "measurement" / "llm_pilot.py"
_spec = importlib.util.spec_from_file_location("llm_pilot_lm_arka_uc_kopyasi", _PILOT)
lp = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = lp
_spec.loader.exec_module(lp)

ANAHTAR = "a1b2c3d4" * 8
KAPI = 54321
IKILI_ICERIK = b"sahte-llama-server-ikilisi"


# --------------------------------------------------------------------------------------------
# Sahteler


class SahteSurec:
    def __init__(self, pid=4321, cikis=None, terminate_islemez=False):
        self.pid = pid
        self.returncode = cikis
        self.terminate_sayisi = 0
        self.kill_sayisi = 0
        self.terminate_islemez = terminate_islemez

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminate_sayisi += 1
        if not self.terminate_islemez:
            self.returncode = -15

    def kill(self):
        self.kill_sayisi += 1
        self.returncode = -9

    def wait(self, timeout=None):
        if self.returncode is None:
            raise subprocess.TimeoutExpired("llama-server", timeout)
        return self.returncode


class SahtePopen:
    def __init__(self, surec=None, hata=None):
        self.surec = surec or SahteSurec()
        self.hata = hata
        self.cagrilar = []

    def __call__(self, cmd, **kw):
        self.cagrilar.append((list(cmd), kw))
        if self.hata is not None:
            raise self.hata(cmd)
        return self.surec


class SahteTasiyici:
    """Yol sonuna göre cevap verir; ``saglik`` listesinin son öğesi tekrarlanır."""

    def __init__(self, saglik=(200,), sohbet=()):
        self.saglik = list(saglik)
        self.sohbet = list(sohbet)
        self.cagrilar = []

    def __call__(self, method, url, headers, body, timeout):
        self.cagrilar.append({"method": method, "url": url, "headers": dict(headers), "body": body,
                              "timeout": timeout})
        yol = urllib.parse.urlsplit(url).path
        if yol.endswith(("/health", "/models")):
            oge = self.saglik.pop(0) if len(self.saglik) > 1 else self.saglik[0]
        else:
            oge = self.sohbet.pop(0)
        if isinstance(oge, BaseException):
            raise oge
        durum, yuk = oge if isinstance(oge, tuple) else (oge, b"")
        satirlar = yuk if isinstance(yuk, list) else yuk.splitlines(keepends=True)
        veri = b"".join(yuk) if isinstance(yuk, list) else yuk
        return B.HttpResponse(status=durum, lines=iter(satirlar), read=lambda: veri, close=lambda: None)


class SahteCalistirici:
    """``ps -o args=``, ``ps -o rss=``, ``footprint`` ve ``--version`` için sahte ``subprocess.run``."""

    def __init__(self):
        self.ps_args: dict[int, str] = {}
        self.cagrilar = []

    def __call__(self, cmd, **kw):
        self.cagrilar.append(list(cmd))
        out = ""
        if cmd[:3] == ["ps", "-o", "args="]:
            out = self.ps_args.get(int(cmd[-1]), "")
        elif cmd[-1] == "--version":
            out = "version: 0.7.0-dev (build 1, commit 2a66703)\nbuilt with clang"
        return SimpleNamespace(stdout=out, stderr="", returncode=0)


class SahteOldurucu:
    def __init__(self, calistirici):
        self.calistirici = calistirici
        self.cagrilar = []

    def __call__(self, pid, sig):
        self.cagrilar.append((pid, sig))
        if sig in (signal.SIGTERM, signal.SIGKILL):
            self.calistirici.ps_args.pop(pid, None)


class Saat:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def uyu(self, s):
        self.t += s


def _cevap(icerik='{"kind": "final", "text": "ok"}', **ek):
    d = {"choices": [{"message": {"content": icerik}, "finish_reason": "stop"}],
         "usage": {"prompt_tokens": 120, "completion_tokens": 9}, "timings": {"prompt_n": 120}}
    d.update(ek)
    return 200, json.dumps(d).encode()


def _dosyalar(tmp_path):
    ikili = tmp_path / "motor" / "llama-server"
    ikili.parent.mkdir(parents=True)
    ikili.write_bytes(IKILI_ICERIK)
    model = tmp_path / "modeller" / "m.gguf"
    model.parent.mkdir(parents=True)
    model.write_bytes(b"GGUF")
    sablon = tmp_path / "sablon.jinja"
    sablon.write_text("{{ messages }}", encoding="utf-8")
    return ikili, model, sablon


def _arka_uc(tmp_path, *, popen=None, tasiyici=None, calistirici=None, gunluk=None, oldurucu=None,
             hazir_suresi=10.0, bosta=600.0):
    ikili, model, sablon = _dosyalar(tmp_path)
    saat = Saat()
    cal = calistirici or SahteCalistirici()
    b = B.LlamaServerBackend(ikili, model, tmp_path / "durum", template_path=sablon, audit=gunluk,
                             popen=popen or SahtePopen(), transport=tasiyici or SahteTasiyici(), run=cal,
                             kill=oldurucu or SahteOldurucu(cal), clock=saat, sleep=saat.uyu,
                             port_finder=lambda: KAPI, key_factory=lambda: ANAHTAR, ready_timeout=hazir_suresi,
                             idle_shutdown_sec=bosta)
    return b, saat


# --------------------------------------------------------------------------------------------
# (a) komut, sabitler, gövde


def test_komut_pilot_bayraklariyla_ayni(tmp_path):
    ikili, model, sablon = _dosyalar(tmp_path)
    urun = B.build_llama_command(ikili, model, KAPI, ANAHTAR, template_path=sablon)
    pilot = lp.LlamaSunucu(ikili=ikili, sablon=sablon, port=KAPI).komut({"dizin": model.parent, "gguf": model.name})
    assert urun[:-2] == pilot
    assert urun[-2:] == ["--api-key", ANAHTAR]
    sablonsuz = B.build_llama_command(ikili, model, KAPI, ANAHTAR)
    assert sablonsuz[:-2] == lp.LlamaSunucu(ikili=ikili, port=KAPI).komut({"dizin": model.parent, "gguf": model.name})


def test_komut_anahtarli_ve_yalniz_loopback(tmp_path):
    ikili, model, _ = _dosyalar(tmp_path)
    k = B.build_llama_command(ikili, model, KAPI, ANAHTAR)
    assert k.count("--api-key") == 1 and k[k.index("--api-key") + 1] == ANAHTAR
    assert k.count("--host") == 1 and k[k.index("--host") + 1] == "127.0.0.1"
    assert k[k.index("--port") + 1] == str(KAPI)
    a1, a2 = B.new_api_key(), B.new_api_key()
    assert a1 != a2 and len(a1) == 64 and int(a1, 16) >= 0
    p = B.find_free_port()
    assert 1024 <= p <= 65535
    assert B.redact_command(k, ANAHTAR).count(A.REDACTED) == 1 and ANAHTAR not in B.redact_command(k, ANAHTAR)


def test_sabitler_pilotla_ayni():
    assert LM.CONTEXT_TOKENS == lp.BAGLAM
    assert LM.MODEL_SEED == lp.MODEL_TOHUMU
    assert LM.MAX_TOKENS_STEP == lp.MAX_TOKENS
    assert LM.MEMORY_LIMIT_GIB == lp.BELLEK_ESIGI_GB
    assert LM.REQUEST_TIMEOUT_SEC == lp.CAGRI_ZAMAN_ASIMI


def test_istek_govdesi_pilotun_cozme_ayarlariyla_ayni():
    iletiler = [{"role": "user", "content": "x"}]
    istemci = B._OpenAIClient("http://127.0.0.1:1/v1/chat/completions", ANAHTAR, "m", SahteTasiyici(),
                              lambda s: s, thinking_control=True)
    urun = istemci.build_body(iletiler, None, False, LM.MAX_TOKENS_STEP)
    pilot = lp.LlamaSunucu().govde("m", iletiler, False)
    for k in ("messages", "temperature", "seed", "max_tokens", "stream", "chat_template_kwargs"):
        assert urun[k] == pilot[k], k
    assert set(urun) == {"model", "messages", "temperature", "seed", "max_tokens", "stream", "chat_template_kwargs"}
    akis = istemci.build_body(iletiler, {"type": "json_object"}, True, 64)
    assert akis["stream_options"] == {"include_usage": True} and akis["response_format"] == {"type": "json_object"}
    dusunmesiz = B._OpenAIClient("u", None, "m", SahteTasiyici(), lambda s: s, thinking_control=False)
    assert "chat_template_kwargs" not in dusunmesiz.build_body(iletiler, None, False, 8)
    assert "Authorization" not in dusunmesiz.headers()
    assert istemci.headers()["Authorization"] == f"Bearer {ANAHTAR}"


# --------------------------------------------------------------------------------------------
# (b) başlatma


def test_baslatma_surec_grubu_pid_dosyasi_ve_kunye(tmp_path):
    popen = SahtePopen()
    gunluk = A.AuditLog()
    b, _ = _arka_uc(tmp_path, popen=popen, gunluk=gunluk)
    b.start()
    cmd, kw = popen.cagrilar[0]
    assert kw["process_group"] == 0 and "start_new_session" not in kw
    assert kw["stdin"] == subprocess.DEVNULL
    assert cmd[-2:] == ["--api-key", ANAHTAR]
    kayit = json.loads(b.pid_file.read_text())
    assert kayit == {"pid": 4321, "port": KAPI, "ikili": str(b.binary)}
    k = b.identity()
    assert k["ikili_sha256"] == hashlib.sha256(IKILI_ICERIK).hexdigest()
    assert k["sablon_sha256"] == hashlib.sha256(b"{{ messages }}").hexdigest()
    assert k["model_sha256"] is None and k["surum"].startswith("version: 0.7.0-dev")
    assert A.REDACTED in k["bayraklar"] and ANAHTAR not in json.dumps(k)
    assert b.state == B.STATE_READY and b.pid == 4321 and b.port == KAPI
    assert [r["olay"] for r in gunluk.records] == ["kunye"]
    b.start()
    assert len(popen.cagrilar) == 1
    b.stop()
    assert b.state == B.STATE_OFF and not b.pid_file.exists() and popen.surec.terminate_sayisi == 1


def test_ikili_yoksa_surec_acilmaz(tmp_path):
    popen = SahtePopen()
    b, _ = _arka_uc(tmp_path, popen=popen)
    b.binary.unlink()
    with pytest.raises(B.BackendError, match="ikilisi yok"):
        b.start()
    assert popen.cagrilar == [] and b.state == B.STATE_ERROR


# --------------------------------------------------------------------------------------------
# (c) hata sonrası kapatma


def test_hazir_olmazsa_kapatir(tmp_path):
    popen = SahtePopen()
    b, saat = _arka_uc(tmp_path, popen=popen, tasiyici=SahteTasiyici(saglik=(503,)))
    with pytest.raises(B.BackendError, match="hazır olmadı") as ei:
        b.start()
    assert popen.surec.terminate_sayisi == 1
    assert not b.pid_file.exists() and b.state == B.STATE_ERROR and b.pid is None
    assert saat.t - 1000.0 >= 10.0
    assert ANAHTAR not in str(ei.value)


def test_saglik_hatasi_yutulur_sonra_hazir(tmp_path):
    hata = B.BackendError("bağlantı reddedildi")
    b, _ = _arka_uc(tmp_path, tasiyici=SahteTasiyici(saglik=(hata, 503, 200)))
    b.start()
    assert b.state == B.STATE_READY
    b.stop()


def test_erken_cikista_pid_dosyasi_silinir(tmp_path):
    popen = SahtePopen(surec=SahteSurec(cikis=1))
    b, _ = _arka_uc(tmp_path, popen=popen)
    with pytest.raises(B.BackendError, match="erken çıktı"):
        b.start()
    assert not b.pid_file.exists() and b.state == B.STATE_ERROR


def test_popen_hatasi_anahtari_sizdirmaz(tmp_path):
    gunluk = A.AuditLog(tmp_path / "gunluk.jsonl")
    popen = SahtePopen(hata=lambda cmd: OSError(f"başlatılamadı: {cmd}"))
    b, _ = _arka_uc(tmp_path, popen=popen, gunluk=gunluk)
    with pytest.raises(B.BackendError) as ei:
        b.start()
    metin = "".join(traceback.format_exception(ei.value))
    assert ANAHTAR not in metin and A.REDACTED in str(ei.value)
    assert ei.value.__context__ is None and ei.value.__cause__ is None
    assert ANAHTAR not in (tmp_path / "gunluk.jsonl").read_text()
    assert [r["olay"] for r in gunluk.read_records()] == ["baslatma_hatasi"]


def test_kesmede_de_kapatir(tmp_path):
    popen = SahtePopen()
    b, _ = _arka_uc(tmp_path, popen=popen, tasiyici=SahteTasiyici(saglik=(KeyboardInterrupt(),)))
    with pytest.raises(KeyboardInterrupt):
        b.start()
    assert popen.surec.terminate_sayisi == 1 and not b.pid_file.exists()


def test_terminate_islemezse_kill(tmp_path):
    popen = SahtePopen(surec=SahteSurec(terminate_islemez=True))
    b, _ = _arka_uc(tmp_path, popen=popen)
    b.start()
    b.stop()
    assert popen.surec.terminate_sayisi == 1 and popen.surec.kill_sayisi == 1
    assert not b.pid_file.exists() and b.state == B.STATE_OFF


def test_yetim_surec_kapatilir_yabanci_surec_kapatilmaz(tmp_path):
    cal = SahteCalistirici()
    oldurucu = SahteOldurucu(cal)
    b, _ = _arka_uc(tmp_path, calistirici=cal, oldurucu=oldurucu)
    b.state_dir.mkdir()
    b.pid_file.write_text(json.dumps({"pid": 777, "port": 9999, "ikili": str(b.binary)}))
    cal.ps_args[777] = f"{b.binary} --model m --port 9999 --api-key xyz"
    b.start()
    assert oldurucu.cagrilar == [(777, signal.SIGTERM)]
    assert json.loads(b.pid_file.read_text())["pid"] == 4321
    b.stop()

    b2, _ = _arka_uc(tmp_path / "iki", calistirici=cal, oldurucu=oldurucu)
    b2.state_dir.mkdir()
    b2.pid_file.write_text(json.dumps({"pid": 888, "port": 9999, "ikili": str(b2.binary)}))
    cal.ps_args[888] = "/usr/bin/baska-surec --port 9999"
    b2.start()
    assert (888, signal.SIGTERM) not in oldurucu.cagrilar
    b2.stop()


def test_yetim_terminate_ile_olmezse_kill(tmp_path):
    cal = SahteCalistirici()
    oldurulen = []

    def inatci(pid, sig):
        oldurulen.append((pid, sig))
        if sig == signal.SIGKILL:
            cal.ps_args.pop(pid, None)

    b, saat = _arka_uc(tmp_path, calistirici=cal, oldurucu=inatci)
    b.state_dir.mkdir()
    b.pid_file.write_text(json.dumps({"pid": 777, "port": 9999, "ikili": str(b.binary)}))
    cal.ps_args[777] = f"{b.binary} --port 9999"
    assert b.reap_recorded() is True
    assert oldurulen == [(777, signal.SIGTERM), (777, signal.SIGKILL)]
    assert saat.t - 1000.0 == LM.STOP_WAIT_SEC and not b.pid_file.exists()


def test_bosta_kalinca_durur(tmp_path):
    b, saat = _arka_uc(tmp_path, bosta=600.0)
    b.start()
    saat.t += 599.0
    assert b.stop_if_idle() is False and b.state == B.STATE_READY
    saat.t += 1.0
    assert b.stop_if_idle() is True and b.state == B.STATE_OFF
    assert b.stop_if_idle() is False


# --------------------------------------------------------------------------------------------
# (d) sohbet ve sızıntı


def test_sohbet_govdesi_ve_gunlukte_anahtar_yok(tmp_path):
    gunluk = A.AuditLog(tmp_path / "oturum.jsonl")
    tas = SahteTasiyici(sohbet=[_cevap()])
    b, _ = _arka_uc(tmp_path, tasiyici=tas, gunluk=gunluk)
    sema = {"type": "object", "properties": {"kind": {"const": "final"}, "text": {"type": "string"}},
            "required": ["kind", "text"], "additionalProperties": False}
    iletiler = [{"role": "user", "content": "GIZLI_DECOMPILE_PARCASI_42 ne yapar?"}]
    r = b.chat(iletiler, sema)
    istek = tas.cagrilar[-1]
    assert istek["url"] == f"http://127.0.0.1:{KAPI}/v1/chat/completions"
    assert istek["headers"]["Authorization"] == f"Bearer {ANAHTAR}"
    govde = json.loads(istek["body"])
    assert govde["response_format"]["type"] == "json_schema" and govde["response_format"]["json_schema"]["strict"]
    assert govde["chat_template_kwargs"] == {"enable_thinking": False}
    assert r.content == '{"kind": "final", "text": "ok"}' and r.prompt_tokens == 120 and r.completion_tokens == 9
    metin = (tmp_path / "oturum.jsonl").read_text()
    assert ANAHTAR not in metin and "GIZLI_DECOMPILE_PARCASI_42" not in metin and "Bearer" not in metin
    kayitlar = gunluk.read_records()
    assert [k["olay"] for k in kayitlar] == ["kunye", "model_istegi"]
    assert kayitlar[1]["iletiler_sha256"] == A.sha256_text(A.canonical_json(iletiler))
    assert "messages" not in kayitlar[1]["istek"]
    assert b.state == B.STATE_READY


def test_sohbet_ilk_istekte_baslatir_ve_surec_olurse_kapatir(tmp_path):
    popen = SahtePopen()
    b, _ = _arka_uc(tmp_path, popen=popen, tasiyici=SahteTasiyici(sohbet=[_cevap()]))
    assert b.state == B.STATE_OFF
    b.chat([{"role": "user", "content": "x"}])
    assert len(popen.cagrilar) == 1 and b.state == B.STATE_READY

    def coker(*a, **k):
        popen.surec.returncode = 139
        raise B.BackendError("bağlantı koptu")

    b._client.transport = coker
    with pytest.raises(B.BackendError):
        b.chat([{"role": "user", "content": "x"}])
    assert b.state == B.STATE_ERROR and not b.pid_file.exists() and b.pid is None

    b2, _ = _arka_uc(tmp_path / "iki")
    b2.start()

    def gecici(*a, **k):
        raise B.BackendError("geçici")

    b2._client.transport = gecici
    with pytest.raises(B.BackendError):
        b2.chat([{"role": "user", "content": "x"}])
    assert b2.state == B.STATE_READY and b2.pid == 4321 and b2.pid_file.exists()
    b2.stop()


def test_http_hata_iletisinde_anahtar_yok(tmp_path):
    tas = SahteTasiyici(sohbet=[B.HttpStatusError(401, f"geçersiz anahtar {ANAHTAR}")])
    gunluk = A.AuditLog()
    b, _ = _arka_uc(tmp_path, tasiyici=tas, gunluk=gunluk)
    with pytest.raises(B.HttpStatusError) as ei:
        b.chat([{"role": "user", "content": "x"}])
    assert ei.value.status == 401
    assert ANAHTAR not in str(ei.value) and ANAHTAR not in "".join(traceback.format_exception(ei.value))
    assert ei.value.__context__ is None
    assert ANAHTAR not in json.dumps(gunluk.records) and gunluk.records[-1]["hata"].startswith("HttpStatusError")


# --------------------------------------------------------------------------------------------
# (e) loopback ve ağ onayı


@pytest.mark.parametrize("makine,beklenen", [
    ("127.0.0.1", True), ("127.5.6.7", True), ("::1", True), ("[::1]", True), ("localhost", True),
    ("LOCALHOST", True), ("127.0.0.1.ornek.com", False), ("0.0.0.0", False), ("10.0.0.1", False),
    ("ornek.com", False), ("", False), (None, False), ("::ffff:8.8.8.8", False),
])
def test_loopback_tanimi(makine, beklenen):
    assert B.is_loopback_host(makine) is beklenen


def test_loopback_olmayan_uca_onaysiz_istek_atilmaz():
    tas = SahteTasiyici(sohbet=[_cevap()])
    u = B.OpenAIEndpointBackend("https://api.ornek.com/v1?key=" + ANAHTAR, model_name="m", api_key=ANAHTAR,
                                transport=tas)
    for cagri in (u.start, u.health, u.probe_level, lambda: u.chat([{"role": "user", "content": "x"}])):
        with pytest.raises(B.NetworkConsentRequired) as ei:
            cagri()
        assert ANAHTAR not in str(ei.value)
    assert tas.cagrilar == []
    assert u.capabilities().network is True and u.capabilities().memory_guard is False


def test_onayla_ve_loopbackte_istek_atilir():
    tas = SahteTasiyici(sohbet=[_cevap(), _cevap()])
    u = B.OpenAIEndpointBackend("https://api.ornek.com/v1", model_name="m", api_key=ANAHTAR,
                                allow_network=True, transport=tas)
    u.start()
    u.chat([{"role": "user", "content": "x"}])
    assert tas.cagrilar[-1]["url"] == "https://api.ornek.com/v1/chat/completions"
    yerel = B.OpenAIEndpointBackend("http://localhost:1234/v1", model_name="m", transport=tas)
    yerel.chat([{"role": "user", "content": "x"}])
    assert len(tas.cagrilar) == 2 and yerel.capabilities().network is False
    assert "Authorization" not in tas.cagrilar[-1]["headers"]


def test_uc_adresi_dogrulanir_ve_kunyede_gizli_yok():
    with pytest.raises(ValueError):
        B.OpenAIEndpointBackend("http://kullanici:sifre@127.0.0.1/v1", model_name="m")
    with pytest.raises(ValueError):
        B.OpenAIEndpointBackend("ftp://127.0.0.1/v1", model_name="m")
    u = B.OpenAIEndpointBackend("https://api.ornek.com:8443/v1?key=" + ANAHTAR + "#x", model_name="m",
                                api_key=ANAHTAR)
    k = u.identity()
    assert k["uc"] == "https://api.ornek.com:8443/v1" and k["anahtar_var"] is True
    assert ANAHTAR not in json.dumps(k)
    assert A.redact_url("http://u:p@[::1]:80/v1?x=1") == "http://[::1]:80/v1"


# --------------------------------------------------------------------------------------------
# (f) yetenek düzeyi


def _uc(tas, **kw):
    return B.OpenAIEndpointBackend("http://127.0.0.1:8080/v1", model_name="m", transport=tas, **kw)


def test_yetenek_duzeyi_L3():
    tas = SahteTasiyici(sohbet=[_cevap('{"kind": "probe", "n": 7}')])
    u = _uc(tas)
    assert u.probe_level() == "L3" and len(tas.cagrilar) == 1
    rf = json.loads(tas.cagrilar[0]["body"])["response_format"]
    assert rf["type"] == "json_schema" and rf["json_schema"]["strict"] is True
    assert "probe" not in json.loads(tas.cagrilar[0]["body"])["messages"][0]["content"]
    assert u.capabilities().level == "L3"


def test_yetenek_duzeyi_L2_ve_L1():
    tas = SahteTasiyici(sohbet=[B.HttpStatusError(400, "response_format desteklenmiyor"), _cevap('{"merhaba": 1}')])
    assert _uc(tas).probe_level() == "L2"
    assert json.loads(tas.cagrilar[1]["body"])["response_format"] == {"type": "json_object"}

    tas = SahteTasiyici(sohbet=[B.HttpStatusError(422, "x"), B.HttpStatusError(400, "y"), _cevap("Merhaba!")])
    u = _uc(tas)
    assert u.probe_level() == "L1" and len(tas.cagrilar) == 3
    assert "response_format" not in json.loads(tas.cagrilar[2]["body"])

    # Şema kabul edildi ama uygulanmadı (düz metin) → zorlamaya güvenilmez.
    tas = SahteTasiyici(sohbet=[_cevap("Merhaba!"), _cevap("Merhaba yine!")])
    assert _uc(tas).probe_level() == "L1" and len(tas.cagrilar) == 2


def test_yetenek_yoklamasi_baska_hatada_duzey_uydurmaz():
    u = _uc(SahteTasiyici(sohbet=[B.HttpStatusError(401, "yetkisiz")]))
    with pytest.raises(B.HttpStatusError):
        u.probe_level()
    assert u.capabilities().level is None
    u = _uc(SahteTasiyici(sohbet=[B.HttpStatusError(400, "a"), B.HttpStatusError(400, "b"),
                                  B.HttpStatusError(400, "c")]))
    with pytest.raises(B.BackendError, match="belirlenemedi"):
        u.probe_level()
    assert u.capabilities().level is None


def test_yoklanmadan_semali_istek_yok_ve_duzeye_gore_bicim():
    tas = SahteTasiyici(sohbet=[_cevap(), _cevap(), _cevap('{"kind": "probe", "n": 7}'), _cevap()])
    u = _uc(tas)
    sema = {"type": "object", "properties": {"a": {"type": "string"}}, "additionalProperties": False}
    with pytest.raises(B.CapabilityUnknown):
        u.chat([{"role": "user", "content": "x"}], sema)
    assert tas.cagrilar == []
    u._level = "L2"
    u.chat([{"role": "user", "content": "x"}], sema)
    assert json.loads(tas.cagrilar[-1]["body"])["response_format"] == {"type": "json_object"}
    u._level = "L1"
    u.chat([{"role": "user", "content": "x"}], sema)
    assert "response_format" not in json.loads(tas.cagrilar[-1]["body"])
    u._level = None
    u.probe_level()
    u.chat([{"role": "user", "content": "x"}], sema)
    assert json.loads(tas.cagrilar[-1]["body"])["response_format"]["json_schema"]["schema"] == sema


# --------------------------------------------------------------------------------------------
# (g) akış


def _sse(*parcalar):
    return [b"data: " + json.dumps(p).encode() + b"\n" for p in parcalar] + [b"data: [DONE]\n", b"data: {bozuk\n"]


def test_akis_okuma_icerik_ve_zaman_damgalari():
    saat = Saat()
    gelen = []
    satirlar = iter([b": yorum\n", b"\n",
                     *_sse({"choices": [{"delta": {"role": "assistant"}}]},
                           {"choices": [{"delta": {"content": "Mer"}}]},
                           {"choices": [{"delta": {"content": ""}}]},
                           {"choices": [{"delta": {"content": "haba"}, "finish_reason": "stop"}]},
                           {"choices": [], "usage": {"prompt_tokens": 5, "completion_tokens": 2},
                            "timings": {"predicted_n": 2}})])

    def sayac():
        saat.t += 0.5
        return saat.t

    out = B.read_sse(satirlar, sayac, 1000.0, gelen.append)
    assert out["content"] == "Merhaba" and gelen == ["Mer", "haba"]
    assert out["first"] == 0.5 and out["last"] == 1.0 and out["events"] == 2
    assert out["finish_reason"] == "stop"
    assert out["usage"] == {"prompt_tokens": 5, "completion_tokens": 2} and out["timings"] == {"predicted_n": 2}


def test_akista_hata_ve_bozuk_parca():
    with pytest.raises(B.BackendError, match="hata bildirdi"):
        B.read_sse(iter(_sse({"error": {"message": "x"}})), time.monotonic, 0.0)
    with pytest.raises(B.BackendError, match="çözülemedi"):
        B.read_sse(iter([b"data: {bozuk\n"]), time.monotonic, 0.0)
    with pytest.raises(B.BackendError):
        B.parse_completion(b'{"error": "kota"}')
    assert B.parse_completion(b'{"choices": []}')["content"] == ""


def test_akisli_sohbet_on_token_ve_sure(tmp_path):
    akis = _sse({"choices": [{"delta": {"content": "a"}}]}, {"choices": [{"delta": {"content": "b"}}]},
                {"choices": [{"delta": {}, "finish_reason": "length"}], "usage": {"completion_tokens": 2}})
    tas = SahteTasiyici(sohbet=[(200, akis)])
    b, _ = _arka_uc(tmp_path, tasiyici=tas)
    gelen = []
    r = b.chat([{"role": "user", "content": "x"}], stream=True, on_token=gelen.append)
    assert r.content == "ab" and gelen == ["a", "b"] and r.finish_reason == "length" and r.stream
    assert r.first_token_sec is not None and r.content_events == 2
    assert json.loads(tas.cagrilar[-1]["body"])["stream_options"] == {"include_usage": True}


def test_yonlendirme_izlenmez():
    req = urllib.request.Request("http://127.0.0.1:1/v1/chat/completions")
    with pytest.raises(urllib.error.HTTPError):
        B._NoRedirect().redirect_request(req, None, 302, "Found", {}, "https://kotu.ornek.com/")


# --------------------------------------------------------------------------------------------
# (h) sahte arka uç ve kayıt sayısı


def test_sahte_arka_uc_betigi_oynatir():
    uyunan = []
    s = B.FakeBackend([B.FakeReply(content="bir", delay_sec=0.25),
                       B.FakeReply(chunks=["i", "ki"], finish_reason="length", first_token_sec=1.0,
                                   last_token_sec=2.0),
                       B.FakeReply(error=B.BackendError("betikli hata"))], sleep=uyunan.append)
    assert s.chat([{"role": "user", "content": "1"}]).content == "bir"
    assert uyunan == [0.25]
    gelen = []
    r = s.chat([{"role": "user", "content": "2"}], stream=True, on_token=gelen.append, max_tokens=7)
    assert r.content == "iki" and gelen == ["i", "ki"] and r.finish_reason == "length"
    assert (r.first_token_sec, r.last_token_sec, r.content_events) == (1.0, 2.0, 2)
    with pytest.raises(B.BackendError, match="betikli hata"):
        s.chat([{"role": "user", "content": "3"}])
    with pytest.raises(B.BackendError, match="betik bitti"):
        s.chat([{"role": "user", "content": "4"}])
    assert [c["messages"][0]["content"] for c in s.calls] == ["1", "2", "3", "4"]
    assert s.calls[1]["max_tokens"] == 7 and s.starts == 1
    with pytest.raises(ValueError):
        s.chat([])
    hatali = B.FakeBackend(start_error="başlamadı")
    with pytest.raises(B.BackendError):
        hatali.chat([{"role": "user", "content": "x"}])
    assert hatali.state == B.STATE_ERROR


def test_her_model_istegi_tek_kayit():
    g = A.AuditLog()
    s = B.FakeBackend([B.FakeReply(content="a"), B.FakeReply(error=B.BackendError("x")), B.FakeReply(content="c")],
                      audit=g)
    s.chat([{"role": "user", "content": "1"}], purpose="yoklama-1")
    with pytest.raises(B.BackendError):
        s.chat([{"role": "user", "content": "2"}])
    s.chat([{"role": "user", "content": "3"}])
    assert [r["olay"] for r in g.records] == ["model_istegi"] * 3
    assert [r["amac"] for r in g.records] == ["yoklama-1", "gorev", "gorev"]
    assert "hata" in g.records[1] and "cevap_sha256" in g.records[2] and g.count == 3


# --------------------------------------------------------------------------------------------
# (i) bellek bekçisi


_FOOTPRINT_CIKTILARI = ["llama-server [4321]: 64-bit    Footprint: 1145 MB (16384 bytes per page)\n",
                        "Footprint: 1.12 GB\n", "Footprint: 2048 KB", "Footprint:\t0.5\tGB", "footprint yok",
                        ""]


def test_bellek_olcusu_pilotla_ayni(monkeypatch):
    for cikti in _FOOTPRINT_CIKTILARI:
        monkeypatch.setattr(lp.subprocess, "run", lambda *a, _c=cikti, **k: SimpleNamespace(stdout=_c))
        assert M.parse_footprint_gib(cikti) == lp._footprint_gb(1), cikti
    for rss, fp in [(16.47, 1.22), (16.0, None), (19.9995, 0.0), (0.0, 20.0004)]:
        pilot = lp.bellek_ust({"surec": "llama-server", "rss_gb": rss, "footprint_gb": fp})
        assert M.upper_bound_gib(rss, fp) == round(pilot, 3)

    rss_kib = 17_270_000

    def sahte_run(cmd, **kw):
        if cmd[:2] == ["ps", "-axo"]:
            return SimpleNamespace(stdout=f"  4321 {rss_kib} /Users/x/.lmstudio/extensions/backends/b/llama-server\n"
                                          "  12 900 /usr/bin/baska\n")
        if cmd[:3] == ["ps", "-o", "rss="]:
            return SimpleNamespace(stdout=f" {rss_kib}\n")
        return SimpleNamespace(stdout=_FOOTPRINT_CIKTILARI[0])

    monkeypatch.setattr(lp.subprocess, "run", sahte_run)
    pilot = lp.model_bellegi()
    urun = M.measure_process(4321, run=sahte_run)
    assert (urun.rss_gib, urun.footprint_gib, urun.upper_gib) == (
        pilot["rss_gb"], pilot["footprint_gb"], pilot["bellek_ust_gb"])
    assert urun.complete is True


def _ornek(ust, pid=4321):
    return M.MemorySample(pid=pid, rss_gib=ust, footprint_gib=0.0, upper_gib=ust, complete=True, at="t")


def test_bellek_esigi_sinirda():
    durdurulan = []
    g = A.AuditLog()
    degerler = iter([LM.MEMORY_LIMIT_GIB, LM.MEMORY_LIMIT_GIB + 0.001, LM.MEMORY_LIMIT_GIB + 5])
    b = M.MemoryGuard(lambda: 4321, durdurulan.append, measure=lambda pid: _ornek(next(degerler)), audit=g)
    assert b.check().upper_gib == LM.MEMORY_LIMIT_GIB and durdurulan == [] and b.tripped is None
    b.check()
    assert len(durdurulan) == 1 and b.tripped.upper_gib == LM.MEMORY_LIMIT_GIB + 0.001
    b.check()
    assert len(durdurulan) == 1 and b.peak.upper_gib == LM.MEMORY_LIMIT_GIB + 5
    assert [r["olay"] for r in g.records] == ["bellek_durdu"] and g.records[0]["esik_gib"] == LM.MEMORY_LIMIT_GIB


def test_bellek_olculemezse_karar_yok():
    durdurulan = []
    assert M.MemoryGuard(lambda: None, durdurulan.append, measure=lambda pid: _ornek(99)).check() is None
    assert M.MemoryGuard(lambda: 1, durdurulan.append, measure=lambda pid: None).check() is None
    assert durdurulan == []

    def run(cmd, **kw):
        if cmd[0] == "ps":
            return SimpleNamespace(stdout=" 1048576\n")
        raise OSError("footprint yok")

    o = M.measure_process(7, run=run)
    assert o.rss_gib == 1.0 and o.footprint_gib is None and o.complete is False and o.upper_gib == 1.0
    assert M.measure_process(7, run=lambda cmd, **kw: SimpleNamespace(stdout="")) is None
    assert M.parse_rss_gib("abc") is None


def test_bellek_bekcisi_artalan():
    durdu = threading.Event()
    sayac = iter(range(1000))
    b = M.MemoryGuard(lambda: 1, lambda s: durdu.set(),
                      measure=lambda pid: _ornek(25.0 if next(sayac) >= 2 else 10.0))
    b.start(interval=0.01)
    assert durdu.wait(5.0)
    b.stop(timeout=5.0)
    assert b.tripped is not None and b._thread is None


def test_bellek_asiminda_arka_uc_durur(tmp_path):
    popen = SahtePopen()
    b, _ = _arka_uc(tmp_path, popen=popen)
    b.start()
    bekci = M.MemoryGuard(lambda: b.pid, lambda s: b.stop("bellek"), measure=lambda pid: _ornek(21.0, pid))
    assert bekci.check().pid == 4321
    assert b.state == B.STATE_MEMORY_STOPPED and popen.surec.terminate_sayisi == 1 and not b.pid_file.exists()
    assert bekci.check() is None


# --------------------------------------------------------------------------------------------
# denetim günlüğü


def test_gunlukte_anahtar_ve_ham_veri_yok(tmp_path):
    yol = A.session_log_path("ab" * 32, "s1", root=tmp_path / "lm")
    assert not yol.parent.exists()
    g = A.AuditLog(yol)
    g.add_secret(ANAHTAR)
    g.add_secret("kisa")
    g.write("model_istegi", istek={"headers": {"Authorization": f"Bearer {ANAHTAR}"}, "not": f"x{ANAHTAR}y"},
            messages=[{"role": "user", "content": "HAM_DIZGI"}], ham=b"\x7fELF-ham-bayt", api_key=ANAHTAR,
            kume={"b", "a"}, nesne=object(), yol=Path("/tmp/x"), kisa="kisa")
    metin = yol.read_text(encoding="utf-8")
    assert ANAHTAR not in metin and "HAM_DIZGI" not in metin and "ELF-ham" not in metin
    k = json.loads(metin)
    assert k["olay"] == "model_istegi" and k["istek"]["headers"] == A.REDACTED and k["messages"] == A.REDACTED
    assert k["istek"]["not"] == f"x{A.REDACTED}y" and k["api_key"] == A.REDACTED
    assert k["ham"] == {"sha256": hashlib.sha256(b"\x7fELF-ham-bayt").hexdigest(), "bayt": 13}
    assert k["kume"] == ["a", "b"] and k["nesne"] == "<object>" and k["yol"] == "/tmp/x" and k["kisa"] == "kisa"
    assert (yol.stat().st_mode & 0o777) == 0o600 and (yol.parent.stat().st_mode & 0o777) == 0o700
    assert g.records == [] and g.count == 1


def test_oturum_yolu_dogrulamasi(tmp_path):
    with pytest.raises(ValueError):
        A.session_log_path("../" + "a" * 61, "s1")
    with pytest.raises(ValueError):
        A.session_log_path("AB" * 32, "s1")
    with pytest.raises(ValueError):
        A.session_log_path("ab" * 32, "../x")
    assert A.session_log_path("ab" * 32, "s-1_x", root=tmp_path) == tmp_path / ("ab" * 32) / "oturum-s-1_x.jsonl"
    assert A.session_log_path("ab" * 32, "s").parent.parent == Path.home() / ".karadul" / "lm"


# --------------------------------------------------------------------------------------------
# (j) içe aktarma ve bağımlılık


def test_ice_aktarma_yan_etkisiz(tmp_path):
    ev = tmp_path / "ev"
    kod = (
        "import socket, subprocess, threading\n"
        "def yasak(*a, **k):\n    raise AssertionError('yan etki')\n"
        "subprocess.Popen.__init__ = yasak\nsocket.socket.connect = yasak\nsocket.socket.bind = yasak\n"
        "import karadul.lm, karadul.lm.audit, karadul.lm.protocol, karadul.lm.memory_guard\n"
        "import karadul.lm.backend, karadul.lm.probe\n"
        "assert threading.active_count() == 1, threading.enumerate()\nprint('tamam')\n")
    env = {**os.environ, "HOME": str(ev), "PYTHONDONTWRITEBYTECODE": "1"}
    r = subprocess.run([sys.executable, "-c", kod], cwd=KOK, env=env, capture_output=True, text=True, timeout=300)
    assert r.returncode == 0 and "tamam" in r.stdout, r.stderr[-2000:]
    assert not (ev / ".karadul" / "lm").exists()


def _ice_aktarilanlar(yol: Path, paket: str) -> set[str]:
    agac = ast.parse(yol.read_text(encoding="utf-8"))
    out = set()
    for d in ast.walk(agac):
        if isinstance(d, ast.Import):
            out.update(a.name for a in d.names)
        elif isinstance(d, ast.ImportFrom):
            if d.level:
                taban = paket.split(".")[: len(paket.split(".")) - d.level + 1]
                mod = ".".join(taban + ([d.module] if d.module else []))
            else:
                mod = d.module or ""
            out.add(mod)
            out.update(f"{mod}.{a.name}" for a in d.names)
    return out


def test_motor_karadul_lm_paketini_ice_aktarmaz():
    kok = KOK / "karadul"
    ihlal = []
    for yol in sorted(kok.rglob("*.py")):
        if (kok / "lm") in yol.parents:
            continue
        paket = ".".join(yol.relative_to(KOK).with_suffix("").parts)
        if yol.name != "__init__.py":
            paket = paket.rsplit(".", 1)[0]
        for m in _ice_aktarilanlar(yol, paket):
            if m == "karadul.lm" or m.startswith("karadul.lm."):
                ihlal.append(f"{yol.relative_to(KOK)}: {m}")
    assert ihlal == []


def test_lm_yalniz_standart_kitaplik_ve_karadul():
    yabanci = []
    for yol in sorted((KOK / "karadul" / "lm").glob("*.py")):
        for m in _ice_aktarilanlar(yol, "karadul.lm"):
            ust = m.split(".")[0]
            if ust and ust != "karadul" and ust != "__future__" and ust not in sys.stdlib_module_names:
                yabanci.append(f"{yol.name}: {m}")
    assert yabanci == []
