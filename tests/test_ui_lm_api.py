"""P22c1 — KaradulLM kısıtlı terminalinin arayüz sunucusu uçları (``ui/server.py``; KaradulLM v2 tasarımı §4.2,
§4.3, §4.6, §4.7).

Bölümler:
  (3) tek komutluk izin listesi: ``POST /api/lm/terminal/komut`` yalnız tam ``karadullm``'i kabul eder; başka her
      girdi 400 + içeriksiz denetim kaydı; oturum açma süreç başlatmaz; tek oturum.

Gerçek model yok, Ghidra yok: arayüz sunucusu gerçek ``ThreadingHTTPServer`` olarak rastgele kapıda koşar;
çalışma alanı sentetik (``tests/test_lm_tools.py``); model işi gereken yerde sahte arka uç. Depolar (defter,
denetim, ad deposu) geçici dizinde: kullanıcının ``~/.karadul``'una yazılmaz.
Mutasyon koruması: ``scripts/measurement/mutation_specs_ui_lm_api.json``.
"""
from __future__ import annotations

import http.client
import importlib.util
import json
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from karadul.core import overrides
from karadul.lm import session as S
from tests.test_lm_repl import DUSMAN
from tests.test_lm_tools import default_ws

_SERVER_PY = Path(__file__).resolve().parent.parent / "ui" / "server.py"
_TOKEN = "t0ken-lm-test"
SHA = "c4" * 32


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, _SERVER_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _ws(root: Path, *, report: bool = True) -> Path:
    ws = default_ws(root / "ws")
    if report:
        (ws / "reports").mkdir()
        (ws / "reports" / "report.json").write_text(json.dumps({"target": {"hash": SHA}}), encoding="utf-8")
    return ws


@pytest.fixture()
def srv(tmp_path, monkeypatch):
    """Sunucu modülü + gerçek HTTP sunucusu; depolar geçici dizinde; çalışma alanı etkin."""
    for k in ("KARADUL_LLAMA_SERVER", "KARADUL_LM_MODEL", "KARADUL_LM_SABLON"):
        monkeypatch.delenv(k, raising=False)
    mod = _load("bw_ui_server_lm_api")
    ov = tmp_path / "overrides"
    ov.mkdir()
    monkeypatch.setattr(overrides, "overrides_dir", lambda: ov)
    mod._LM_STORE_ROOT = tmp_path / "lm"
    mod._ov_dir = ov
    mod._ws_path = _ws(tmp_path)
    mod.activate_workspace(str(mod._ws_path))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
    mod._PORT = httpd.server_address[1]
    mod._TOKEN = _TOKEN
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield mod
    s = S.current_session()
    if s is not None:
        s.close()
    mod.activate_workspace(None)
    httpd.shutdown()
    httpd.server_close()


def req(mod, method: str, path: str, body=None, *, token: str | None = _TOKEN, host: str | None = None,
        origin: str | None = None, raw: bytes | None = None, timeout: float = 30):
    """(durum, JSON gövde) döndürür."""
    conn = http.client.HTTPConnection("127.0.0.1", mod._PORT, timeout=timeout)
    h = {"Host": host or f"127.0.0.1:{mod._PORT}"}
    if token is not None:
        h["X-Karadul-Token"] = token
    if origin is not None:
        h["Origin"] = origin
    data = raw if raw is not None else (None if body is None else json.dumps(body).encode("utf-8"))
    if data is not None:
        h["Content-Type"] = "application/json"
    conn.request(method, path, body=data, headers=h)
    resp = conn.getresponse()
    out = resp.read()
    conn.close()
    try:
        return resp.status, json.loads(out)
    except ValueError:
        return resp.status, out


def komut(mod, k="karadullm"):
    return req(mod, "POST", "/api/lm/terminal/komut", {"komut": k})


# --------------------------------------------------------------------------------------------
# (3) tek komutluk izin listesi + oturum açma


def test_komut_izin_listesi_tek_oge_dusman_girdiler_reddedilir(srv):
    kotu = list(DUSMAN) + [None, 0, ["karadullm"], {"komut": "karadullm"}, "karadullm\u0000"]
    for k in kotu:
        st, b = komut(srv, k)
        assert (st, b.get("hata")) == (400, "izin verilmeyen komut"), k
        assert b["satir"] == "bu terminal yalnız `karadullm` çalıştırır"
    assert S.current_session() is None                                     # hiçbiri oturum açmadı
    # gövdesiz / bozuk JSON da komut değildir
    assert req(srv, "POST", "/api/lm/terminal/komut", raw=b"{bozuk")[0] == 400
    assert req(srv, "POST", "/api/lm/terminal/komut")[0] == 400
    # denetim kaydı içeriksiz: her ret bir satır, metin yok (yalnız uzunluk + sha256)
    kayit = (srv._LM_STORE_ROOT / "arayuz-komut.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(kayit) == len(kotu) + 2
    for satir_ in kayit:
        k = json.loads(satir_)
        assert k["olay"] == "komut_reddedildi" and set(k) == {"olay", "zaman", "uzunluk", "sha256"}
    metin = "\n".join(kayit)
    assert "ls" not in metin and "bash" not in metin and "--model" not in metin


def test_komut_karadullm_tek_oturum_acar_surec_baslatmaz(srv, monkeypatch):
    acilan = []
    monkeypatch.setattr(srv.subprocess, "Popen", lambda *a, **k: acilan.append(a) or (_ for _ in ()).throw(
        AssertionError("süreç açılmamalı")))
    st, b = komut(srv, "  karadullm ")                                    # yalnız U+0020 kırpılır
    assert st == 200 and set(b) == {"oturum"}
    s = S.current_session()
    assert s is not None and s.id == b["oturum"] and s.backend is None     # model yapılandırılmamış: modelsiz
    assert s.workspace_root == srv._ws_path and s.binary_sha256 == SHA
    ilk = s.stream.since(0)["olaylar"][0]
    assert ilk["tur"] == "oturum_basladi" and ilk["arka_uc"] == "yok"
    st, b2 = komut(srv)
    assert (st, b2["hata"]) == (400, "oturum zaten açık") and S.current_session() is s
    assert acilan == []
    # analiz sürüyorsa oturum model başlatmaz ve yazmaz (G6): oturum arayüzün süren işine bağlı
    monkeypatch.setattr(srv, "_running_job", lambda: "j1")
    assert s._analysis_running() is True


def test_komut_calisma_alani_ya_da_ozet_yoksa_acilmaz(srv, tmp_path):
    srv.activate_workspace(None)
    st, b = komut(srv)
    assert (st, b["hata"]) == (400, "çalışma alanı yok: önce bir analiz sonucu açın")
    ozetsiz = _ws(tmp_path / "b", report=False)
    srv.activate_workspace(str(ozetsiz))
    st, b = komut(srv)
    assert st == 400 and b["hata"].startswith("çalışma alanında ikilinin özeti yok")
    assert S.current_session() is None


def test_komut_model_ikilisi_denetlenir_surec_acilmaz(srv, tmp_path, monkeypatch):
    sahte = tmp_path / "bin" / "sunucu"
    sahte.parent.mkdir()
    sahte.write_text("#!/bin/sh\nexit 0\n")
    sahte.chmod(0o755)
    monkeypatch.setenv("KARADUL_LLAMA_SERVER", str(sahte))
    st, b = komut(srv)                                                     # model eksik
    assert st == 400 and "birlikte verilmeli" in b["hata"] and S.current_session() is None
    monkeypatch.setenv("KARADUL_LM_MODEL", str(tmp_path / "m.gguf"))
    st, b = komut(srv)                                                     # adı llama-server değil
    assert st == 400 and b["hata"].startswith("model başlatılmaz") and "llama-server" in b["hata"]
    hedef = srv._ws_path / "raw"
    hedef.mkdir()
    ici = hedef / "llama-server"                                           # çalışma alanının içinde
    ici.write_text("#!/bin/sh\nexit 0\n")
    ici.chmod(0o755)
    monkeypatch.setenv("KARADUL_LLAMA_SERVER", str(ici))
    st, b = komut(srv)
    assert st == 400 and "çalışma alanının içinde" in b["hata"] and S.current_session() is None
    # geçerli ad, çalışma alanı dışı: arka uç kurulur ama süreç açılmaz (ilk model isteğinde başlar)
    dogru = tmp_path / "bin" / "llama-server"
    dogru.write_text("#!/bin/sh\nexit 0\n")
    dogru.chmod(0o755)
    monkeypatch.setenv("KARADUL_LLAMA_SERVER", str(dogru))
    monkeypatch.setattr(srv.LlamaServerBackend, "start", lambda self: (_ for _ in ()).throw(
        AssertionError("açılışta sunucu başlamamalı")))
    st, b = komut(srv)
    assert st == 200
    s = S.current_session()
    assert s.backend.kind == "yerel_llama_server" and s.backend.pid is None
    assert s.backend.state_dir == srv._LM_STORE_ROOT / "sunucu"


# --------------------------------------------------------------------------------------------
# (1) §4.6 uçları: girdi, durdur, durum, sonuç, öneriler, ret, kapat

from karadul.lm import backend as B  # noqa: E402
from tests.test_lm_session import AdArka  # noqa: E402
from tests.test_lm_tools import A, fun  # noqa: E402

BEKLE = 20.0


def ac(mod, monkeypatch, arka=None) -> str:
    if arka is not None:
        monkeypatch.setattr(mod, "_lm_make_backend", lambda root, sha, sid: arka)
    st, b = komut(mod)
    assert st == 200, b
    return b["oturum"]


def girdi(mod, oturum, metin):
    return req(mod, "POST", "/api/lm/terminal/girdi", {"oturum": oturum, "metin": metin})


def olaylar(oturum):
    s = S.current_session()
    assert s is not None and s.id == oturum
    return s.stream.since(0)["olaylar"]


def test_girdi_durum_kapat(srv, monkeypatch):
    st, b = req(srv, "GET", "/api/lm/durum")
    assert (st, b) == (200, {"oturum": None, "model_ayari": None})
    monkeypatch.setenv("KARADUL_LM_MODEL", "/yok/model-q4.gguf")
    assert req(srv, "GET", "/api/lm/durum")[1]["model_ayari"] == "model-q4.gguf"
    monkeypatch.delenv("KARADUL_LM_MODEL")
    o = ac(srv, monkeypatch)
    # oturum kimliği zorunlu ve açık oturumunki olmalı
    assert girdi(srv, None, "/yardim")[0] == 400
    assert girdi(srv, "o" + "0" * 12, "/yardim") == (404, {"hata": "böyle bir açık oturum yok"})
    st, b = girdi(srv, o, "/yardim")
    assert (st, b) == (200, {"kabul": True, "is": None, "hata": None})
    assert any(e["tur"] == "satir" and "kabuk değildir" in e["metin"] for e in olaylar(o))
    st, b = girdi(srv, o, "/ls -la")
    assert st == 400 and b["kabul"] is False and b["hata"] == "bilinmeyen komut: /ls (/yardim)"
    assert olaylar(o)[-1]["tur"] == "satir" and olaylar(o)[-1]["duzey"] == "hata"
    for kotu in (None, 5, ["/yardim"], "a\x1b[2Jb", "x" * 2001):
        assert girdi(srv, o, kotu)[0] == 400, kotu
    st, d = req(srv, "GET", "/api/lm/durum")
    assert st == 200 and d["oturum"] == o and d["kip"] == "kesif" and d["kapali"] is False
    assert d["arka_uc"] is None and d["calisan"] is None and d["son_olay"] == olaylar(o)[-1]["seq"]
    # kapat: yalnız açık oturum; sonra girdi kabul edilmez
    assert req(srv, "POST", "/api/lm/terminal/kapat", {"oturum": "baska"})[0] == 404
    assert req(srv, "POST", "/api/lm/terminal/kapat", {"oturum": o}) == (200, {"tamam": True})
    assert S.current_session() is None
    assert srv._LM_LAST.stream.since(0)["olaylar"][-1]["tur"] == "oturum_bitti"
    assert girdi(srv, o, "/yardim")[0] == 404
    assert req(srv, "POST", "/api/lm/terminal/kapat", {"oturum": o})[0] == 404
    assert req(srv, "GET", "/api/lm/durum")[1]["oturum"] is None
    # yeniden açılabilir (yeni kimlik)
    assert ac(srv, monkeypatch) != o


def test_oneriler_denetim_ayrintisi_sonuc_ve_ret(srv, monkeypatch):
    arka = AdArka()
    o = ac(srv, monkeypatch, arka)
    assert girdi(srv, o, "/kip adlandir")[0] == 200
    assert girdi(srv, o, f"/ad {fun(A)}")[0] == 200
    assert S.current_session().wait_idle(BEKLE)
    st, b = req(srv, "GET", f"/api/lm/oneriler?oturum={o}")
    assert st == 200 and len(b["oneriler"]) == 1
    p = b["oneriler"][0]
    assert (p["oneri_kimligi"], p["oneri_turu"], p["deger"], p["durum"]) == ("p1", "ad", "open_connection",
                                                                            "bekleyen")
    assert p["fn"] == fun(A) and p["oturum"] == o
    den = p["denetim"]                                                    # bu oturumun akışındaki P21 raporu
    assert set(den) == {"hukum", "bulgular", "bayraklar", "toplu_kabul", "sinanan", "sinanmayan"}
    assert den["hukum"] == p["hukum"] and "D4" in den["sinanmayan"]        # koşmayan kurallar gizlenmez
    # sonuç içeriği: kanıttaki kimlik açılır; biçimsiz kimlik 400, olmayan 404
    st, r = req(srv, "GET", f"/api/lm/sonuc?oturum={o}&kimlik=r1")
    assert st == 200 and r["kimlik"] == "r1" and isinstance(r["sonuc"], dict)
    assert req(srv, "GET", f"/api/lm/sonuc?oturum={o}&kimlik=../x")[0] == 400
    assert req(srv, "GET", f"/api/lm/sonuc?oturum={o}&kimlik=r999")[0] == 404
    assert req(srv, "GET", "/api/lm/sonuc?kimlik=r1")[0] == 400
    # ret: neden zorunlu; D10'a girer; ikinci karar yok
    st, b = req(srv, "POST", "/api/lm/oneri/ret", {"oneri_kimligi": "p1"})
    assert (st, b["hata"]) == (400, "ret için neden zorunlu")
    assert req(srv, "POST", "/api/lm/oneri/ret", {"oneri_kimligi": "p9", "neden": "x"})[1]["hata"] == \
        "böyle bir öneri yok"
    st, b = req(srv, "POST", "/api/lm/oneri/ret", {"oneri_kimligi": "p1", "neden": "bağlantı açmıyor"})
    assert st == 200 and b["oneri"]["durum"] == "ret" and b["oneri"]["neden"] == "bağlantı açmıyor"
    assert "open_connection" in S.current_session().agent.rejected_names[A]
    assert req(srv, "POST", "/api/lm/oneri/ret", {"oneri_kimligi": "p1", "neden": "y"})[0] == 400
    # kapanmış oturumun önerileri hâlâ okunur (son oturum); denetim ayrıntısı kaybolmaz
    req(srv, "POST", "/api/lm/terminal/kapat", {"oturum": o})
    st, b = req(srv, "GET", f"/api/lm/oneriler?oturum={o}")
    assert st == 200 and b["oneriler"][0]["durum"] == "ret" and b["oneriler"][0]["denetim"] is not None
    assert req(srv, "POST", "/api/lm/oneri/ret", {"oneri_kimligi": "p1", "neden": "y"})[0] == 409
    # yeni oturum: eski oturumun önerisi listede, akışı yok → denetim None (uydurulmaz)
    o2 = ac(srv, monkeypatch, AdArka())
    b = req(srv, "GET", f"/api/lm/oneriler?oturum={o2}")[1]
    assert b["oneriler"][0]["oturum"] == o and b["oneriler"][0]["denetim"] is None


def test_durdur_suren_isi_iptal_eder(srv, monkeypatch):
    arka = B.FakeBackend([B.FakeReply(content="{}", delay_sec=3.0)])
    o = ac(srv, monkeypatch, arka)
    st, b = req(srv, "POST", "/api/lm/durdur", {"oturum": o})
    assert (st, b) == (200, {"tamam": True, "durduruldu": False})          # iş yok: olay yok
    assert not any(e["tur"] == "iptal" for e in olaylar(o))
    girdi(srv, o, "/kip adlandir")
    assert girdi(srv, o, f"/ad {fun(A)}")[0] == 200
    s = S.current_session()
    for _ in range(200):                                                    # iş başlayana kadar
        if s.status()["calisan"] is not None:
            break
        threading.Event().wait(0.01)
    st, b = req(srv, "POST", "/api/lm/durdur", {"oturum": o})
    assert (st, b) == (200, {"tamam": True, "durduruldu": True})
    assert [e["kaynak"] for e in olaylar(o) if e["tur"] == "iptal"] == ["analist"]
    assert req(srv, "POST", "/api/lm/durdur", {"oturum": "yok"})[0] == 404


# --------------------------------------------------------------------------------------------
# (2) uzun yoklama: seq, kaçırılan olay sayısı, bekleme

import random  # noqa: E402
import time  # noqa: E402

from karadul.lm.events import EventStream  # noqa: E402


def yokla(mod, oturum, sonra, bekle=0, timeout=30):
    return req(mod, "GET", f"/api/lm/olaylar?oturum={oturum}&sonra={sonra}&bekle={bekle}", timeout=timeout)


def test_olaylar_sira_bosluksuz_ve_parametre_denetimi(srv, monkeypatch):
    o = ac(srv, monkeypatch)
    girdi(srv, o, "/yardim")
    st, b = yokla(srv, o, 0)
    assert st == 200 and set(b) == {"olaylar", "son", "tasma", "kacan", "kapali"}
    seqs = [e["seq"] for e in b["olaylar"]]
    assert seqs == list(range(1, len(seqs) + 1)) and b["son"] == seqs[-1] and b["tasma"] is False
    assert b["olaylar"][0]["tur"] == "oturum_basladi" and all(e["oturum"] == o for e in b["olaylar"])
    st, b2 = yokla(srv, o, 3)                                              # sonradan sürdürme
    assert [e["seq"] for e in b2["olaylar"]] == seqs[3:]
    for kotu in ("-1", "1e3", "x", "", "0x10", "1.5", "9" * 13):
        assert req(srv, "GET", f"/api/lm/olaylar?oturum={o}&sonra={kotu}")[0] == 400, kotu
        assert req(srv, "GET", f"/api/lm/olaylar?oturum={o}&sonra=0&bekle={kotu}")[0] == 400, kotu
    st, b = yokla(srv, o, b["son"] + 5)                                    # akışın ilerisi (başka oturumun sırası)
    assert st == 400 and "ilerisinde" in b["hata"]
    assert yokla(srv, "yok", 0)[0] == 404 and req(srv, "GET", "/api/lm/olaylar?sonra=0")[0] == 400
    # bir cevapta en çok _LM_POLL_LIMIT olay; kalanı ``son``'dan sürer, kayıp yok
    s = S.current_session()
    for i in range(srv._LM_POLL_LIMIT + 7):
        s._line(f"satır {i}")
    toplam, son = [], 0
    while True:
        b = yokla(srv, o, son)[1]
        if not b["olaylar"]:
            break
        assert len(b["olaylar"]) <= srv._LM_POLL_LIMIT
        toplam += [e["seq"] for e in b["olaylar"]]
        son = b["son"]
    assert toplam == list(range(1, s.stream.last_seq + 1))


def test_olaylar_tasma_kacan_sayisi_yavas_istemci(srv, monkeypatch):
    """E-2: halka küçültülmüş akışta yavaş istemci: her seq ya bir kez verilir ya kaçan sayısına girer."""
    o = ac(srv, monkeypatch)
    s = S.current_session()
    s.stream = EventStream(o, capacity=5)
    for i in range(12):
        s._line(f"olay {i}")
    st, b = yokla(srv, o, 0)
    assert (st, b["tasma"], b["kacan"]) == (200, True, 7) and [e["seq"] for e in b["olaylar"]] == [8, 9, 10, 11, 12]
    assert yokla(srv, o, 7)[1]["kacan"] == 0                               # sınırda kayıp yok
    rnd = random.Random(20261119)
    verilen, kacan, son = [], 0, b["son"]
    for _ in range(60):
        for _ in range(rnd.randint(0, 9)):
            s._line("p")
        b = yokla(srv, o, son)[1]
        verilen += [e["seq"] for e in b["olaylar"]]
        kacan += b["kacan"]
        son = b["son"]
    b = yokla(srv, o, son)[1]
    verilen += [e["seq"] for e in b["olaylar"]]
    kacan += b["kacan"]
    assert len(verilen) == len(set(verilen)) and verilen == sorted(verilen)
    assert len(verilen) + kacan == s.stream.last_seq - 12                  # 12'den sonrakiler: verilen + kaçan


def test_olaylar_uzun_yoklama_olayla_hemen_doner_olaysiz_bekler(srv, monkeypatch):
    o = ac(srv, monkeypatch)
    s = S.current_session()
    son = s.stream.last_seq
    # olay yoksa: bekle süresi kadar bekler, boş döner, hiçbir şey üretmez
    t0 = time.monotonic()
    st, b = yokla(srv, o, son, bekle=1)
    gecen = time.monotonic() - t0
    assert st == 200 and b["olaylar"] == [] and b["son"] == son and 0.9 <= gecen < 5
    assert s.stream.last_seq == son
    # bekle tavanı: 999 istense de en çok _LM_POLL_MAX_SEC (burada olay 0,3 sn'de gelir)
    threading.Timer(0.3, lambda: s._line("geldi")).start()
    t0 = time.monotonic()
    st, b = yokla(srv, o, son, bekle=999)
    gecen = time.monotonic() - t0
    assert st == 200 and [e["metin"] for e in b["olaylar"]] == ["geldi"] and gecen < 2.5
    # kapanış bekleyen yoklamayı uyandırır; son olay oturum_bitti, kapali=true
    son = b["son"]
    threading.Timer(0.3, lambda: req(srv, "POST", "/api/lm/terminal/kapat", {"oturum": o})).start()
    t0 = time.monotonic()
    b = yokla(srv, o, son, bekle=20)[1]
    assert time.monotonic() - t0 < 5
    hepsi = list(b["olaylar"])
    while not b["kapali"]:
        b = yokla(srv, o, b["son"], bekle=2)[1]
        hepsi += b["olaylar"]
    assert hepsi[-1]["tur"] == "oturum_bitti" and hepsi[-1]["neden"] == "cik"


# --------------------------------------------------------------------------------------------
# (4) yaşam döngüsü: arayüz kapanınca oturum ve model sunucusu kapanır; yetim toplama; boşta kapatma

import signal  # noqa: E402
import subprocess  # noqa: E402


def _bitti(s, bekle=10.0):
    son = time.monotonic() + bekle
    while time.monotonic() < son:
        e = s.stream.since(0)["olaylar"]
        if e and e[-1]["tur"] == "oturum_bitti":
            return e[-1]
        time.sleep(0.02)
    raise AssertionError("oturum_bitti gelmedi")


def test_kill_jobs_ve_ebeveyn_bekcisi_oturumu_ve_arka_ucu_kapatir(srv, monkeypatch):
    arka = B.FakeBackend([])
    ac(srv, monkeypatch, arka)
    s = S.current_session()
    srv._kill_jobs()
    assert S.current_session() is None and _bitti(s)["neden"] == "arayuz_kapandi"
    assert arka.stops[0] == "cikis"                                        # arka uç oturumdan önce durur
    # SIGTERM / SIGINT işleyicisi: aynı yol, sonra çıkış
    arka2 = B.FakeBackend([])
    ac(srv, monkeypatch, arka2)
    s2 = S.current_session()
    with pytest.raises(SystemExit):
        srv._terminate_jobs(signal.SIGTERM, None)
    assert _bitti(s2)["neden"] == "arayuz_kapandi" and "cikis" in arka2.stops
    # ebeveyn öldü (ppid 1): bekçi oturumu kapatıp süreci bitirir
    arka3 = B.FakeBackend([])
    ac(srv, monkeypatch, arka3)
    s3 = S.current_session()

    class Cikis(Exception):
        pass

    monkeypatch.setattr(srv.os, "getppid", lambda: 1)
    monkeypatch.setattr(srv.os, "_exit", lambda code: (_ for _ in ()).throw(Cikis(code)))
    with pytest.raises(Cikis):
        srv._parent_watchdog()
    assert _bitti(s3)["neden"] == "arayuz_kapandi" and "cikis" in arka3.stops


def test_calisma_alani_degisince_oturum_kapanir_ayni_alan_kapatmaz(srv, monkeypatch, tmp_path):
    ac(srv, monkeypatch)
    s = S.current_session()
    srv.activate_workspace(str(srv._ws_path))                              # aynı alan: önbellek tazeleme
    assert S.current_session() is s and not s.closed
    srv.activate_workspace(str(_ws(tmp_path / "baska")))
    assert S.current_session() is None and _bitti(s)["neden"] == "calisma_alani_degisti"


def test_bosta_kapatma_ve_durum_olayi(srv, monkeypatch):
    class Bosta(B.FakeBackend):
        def stop_if_idle(self):
            self.stop("bosta")
            return True

    assert srv._lm_idle_tick() is False                                    # oturum yok
    ac(srv, monkeypatch)                                                    # modelsiz: arka uç yok
    assert srv._lm_idle_tick() is False
    S.current_session().close()
    arka = Bosta([])
    arka.start()
    o = ac(srv, monkeypatch, arka)
    s = S.current_session()
    s._backend_state_event()
    assert srv._lm_idle_tick() is True and arka.stops == ["bosta"]
    durumlar = [e["durum"] for e in olaylar(o) if e["tur"] == "arka_uc_durumu"]
    assert durumlar[-1] != "hazir" and len(durumlar) >= 2


class _Ps:
    """Sahte ``ps``: ``pid`` → (ppid, args). ``kill`` çağrısında süreç kaybolur."""

    def __init__(self, procs):
        self.procs = dict(procs)
        self.kills = []

    def run(self, cmd, **kw):
        pid = int(cmd[-1])
        ppid, args = self.procs.get(pid, ("", ""))
        out = ppid if cmd[2] == "ppid=" else args
        return subprocess.CompletedProcess(cmd, 0, stdout=out + "\n" if out else "", stderr="")

    def kill(self, pid, sig):
        self.kills.append((pid, sig))
        self.procs.pop(pid, None)


def test_acilista_yetim_model_sunucusu_toplanir(srv, tmp_path):
    durum = srv._LM_STORE_ROOT / "sunucu"
    pidf = durum / "llama_server.pid"
    ikili = "/opt/llama/bin/llama-server"
    args = f"{ikili} -m /m.gguf --port 4321 --host 127.0.0.1"
    assert srv._lm_reap_orphan(run=_Ps({}).run, kill=_Ps({}).kill) == "kayıt yok"
    durum.mkdir(parents=True)

    def kayit(ikili_=ikili, pid=777, port=4321):
        pidf.write_text(json.dumps({"pid": pid, "port": port, "ikili": ikili_}), encoding="utf-8")

    # kayıttaki ikili llama-server değil: dokunulmaz
    kayit("/bin/bash")
    ps = _Ps({777: ("1", "/bin/bash")})
    assert "dokunulmadı" in srv._lm_reap_orphan(run=ps.run, kill=ps.kill) and ps.kills == [] and pidf.exists()
    # ebeveyni yaşıyor (ör. açık bir CLI oturumu): dokunulmaz
    kayit()
    ps = _Ps({777: ("4242", args)})
    assert srv._lm_reap_orphan(run=ps.run, kill=ps.kill) == "ebeveyni yaşıyor: dokunulmadı"
    assert ps.kills == [] and pidf.exists()
    # yetim (ppid 1) ve satır eşleşiyor: SIGTERM, kayıt silinir
    ps = _Ps({777: ("1", args)})
    assert srv._lm_reap_orphan(run=ps.run, kill=ps.kill, sleep=lambda s: None) == "yetim sunucu kapatıldı"
    assert ps.kills == [(777, signal.SIGTERM)] and not pidf.exists()
    # PID başka bir sürece geçmiş (satır eşleşmiyor): öldürülmez, bayat kayıt silinir
    kayit()
    ps = _Ps({777: ("1", "/usr/bin/vim notlar.txt")})
    assert "eşleşmedi" in srv._lm_reap_orphan(run=ps.run, kill=ps.kill) and ps.kills == [] and not pidf.exists()
    # süreç yok: bayat kayıt silinir
    kayit()
    ps = _Ps({})
    assert "eşleşmedi" in srv._lm_reap_orphan(run=ps.run, kill=ps.kill) and ps.kills == [] and not pidf.exists()
