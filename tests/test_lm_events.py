"""karadul/lm/events.py ve ajanın olay geri çağrısı (P22a, KaradulLM v2 olay omurgası).

Tasarım: ``docs/arge/2026-11-18_karadullm_v2/TASARIM.md`` §3.3, §3.11, §4.1, §4.3 G9, §8.1 E-1 / E-2.
Gerçek model, sunucu ve ağ yok: sentetik çalışma alanı (``tests/test_lm_tools.py``) ve betikli sahte
arka uç (``FakeBackend``).

Kilitlenen davranışlar:
  (a) şema: türler ve alanları tasarımla aynı; eksik / fazla alan, kapalı küme dışı değer reddedilir,
  (b) görüntü arındırması: denetim / biçim karakterleri görünür kaçış, ANSI etkisiz, uzunluk tavanlı,
      JSON'dan geri çözülen metinde de yorumlanacak karakter yok,
  (c) halka: ``seq`` boşluksuz, taşmada en eski düşer, düşen sayılır, geride kalan istemciye
      ``tasma`` + ``kacan`` doğru (E-2); uzun yoklama olay gelince döner,
  (d) ``Workspace.ui_name``: arayüzün BYADDR anahtarıyla aynı yazım,
  (e) ajan olayları: görev / araç / model / denetim / görev sonu; her araç kaydı için bir başladı ve
      bir bitti (E-1); ``dokunulan`` yalnız Karadul'un yazdığı adres alanlarından,
  (f) akış: ``jeton`` olayları birleştirilir; olay yalnız gerçek parçadan; parça başına iptal / süre,
  (g) içerik deposu: dosya 0600, dizin 0700, yol aşımı yok, yazılamazsa olay bunu söyler.

Mutasyon koruması: ``scripts/measurement/mutation_specs_lm_olay.json``.
"""
from __future__ import annotations

import json
import unicodedata

import pytest

import karadul.lm as LM
from karadul.lm import agent as G
from karadul.lm import backend as B
from karadul.lm import events as E
from karadul.lm import memory_guard as M
from karadul.lm import tools as T
from karadul.lm.audit import AuditLog
from tests.test_lm_tools import (  # noqa: F401 — srv bir pytest fikstürü
    A, B as FB, CB, D, ENTRY, HUB, MALLOC, MANUAL, SIGNAL, build_ws, default_ws, fun, srv,
)

# Tasarım §4.1 tablosu (+ P22a eklemeleri, P22a.md "Şema"). Şemanın değişmesi bu testi kırar.
TASARIM_ALANLARI = {
    "oturum_basladi": ("kip", "model", "arka_uc", "baglam", "ag", "hiz"),
    "arka_uc_durumu": ("durum", "bellek_gib"),
    "gorev_basladi": ("gorev_turu", "kip", "hedef", "butce"),
    "arac_basladi": ("sonuc", "arac", "cagiran", "hedef", "arguman"),
    "arac_bitti": ("sonuc", "arac", "tamam", "hata", "calistirildi", "tur_kind", "bayt", "kirpma", "sure_ms",
                   "dokunulan", "dokunulan_toplam", "icerik_saklandi"),
    "model_istegi": ("amac", "istem_kestirim"),
    "jeton": ("parca", "karakter"),
    "model_cevabi": ("amac", "durum", "bitis_nedeni", "istem_jeton", "uretim_jeton", "onbellek_jeton", "sure_ms",
                     "niyet", "hata"),
    "denetim": ("nesne", "hukum", "bulgular", "bayraklar", "toplu_kabul", "sinanan", "sinanmayan"),
    "oneri": ("oneri_kimligi", "hedef", "oneri_turu", "deger", "gerekce", "kanit", "hukum"),
    "ozet": ("hedef", "metin", "belirsiz", "kanit", "hukum", "kaynak"),
    "butce": ("arac", "jeton", "sure"),
    "gorev_bitti": ("durum", "hata", "ad_durumu", "cevap", "hukum", "toplu_kabul", "sayaclar", "sure_ms"),
    "iptal": ("kaynak",),
    "satir": ("metin", "duzey"),
    "oturum_bitti": ("neden",),
}

# Görüntüde ham kalmaması gereken karakterler: ESC / ANSI, C0, DEL, C1 (CSI dahil), yön değiştiren biçim
# karakterleri, sıfır genişlikliler, BOM, satır / paragraf ayırıcısı.
GORUNTU_TUZAKLARI = ["\x1b[2J\x1b[31mKIRMIZI\x1b[0m", "\x1b]0;baslik\x07", "a\x00b", "\x7f", "\x9b31m", "\x85",
            "‮evil‬", "⁦x⁩", "​‍‎‏", "﻿", "satır ayır",
            "p q", "؜", "\U000e0041", "çok\nsatır\r\n\tsekme", "\ud800"]
YORUMLANAN_KATEGORILER = {"Cc", "Cf", "Cs", "Zl", "Zp"}


def alanlar(tur: str, **degisen) -> dict:
    out = {k: None for k in E.EVENT_FIELDS[tur]}
    out.update(degisen)
    return out


def kur(tur: str, gorev=None, seq=1, **degisen) -> dict:
    return E.build_event(tur, alanlar(tur, **degisen), seq=seq, t_ms=0, zaman="2026-11-18T12:00:00+03:00",
                         oturum="o1", gorev=gorev)


def yorumlanan_yok(metin: str) -> bool:
    return not any(unicodedata.category(ch) in YORUMLANAN_KATEGORILER for ch in metin)


# --------------------------------------------------------------------------------------------
# (a) şema


def test_sema_tasarimla_ayni_ve_zarf():
    assert E.EVENT_FIELDS == TASARIM_ALANLARI
    assert E.ENVELOPE_KEYS == ("seq", "t_ms", "zaman", "oturum", "gorev", "tur")
    olay = kur("gorev_basladi", gorev="g1", gorev_turu="ad_oner", kip="K0",
               hedef={"adres": "1000", "fn": "FUN_00001000"}, butce={"arac": 0, "jeton": 10240, "sure_sn": 900.0})
    assert list(olay) == [*E.ENVELOPE_KEYS, *TASARIM_ALANLARI["gorev_basladi"]]
    assert list(olay["hedef"]) == ["fn", "adres"]                  # alan sırası sabit
    assert json.loads(E.serialize(olay)) == olay


@pytest.mark.parametrize("bozuk", [
    lambda: E.build_event("bilinmeyen", {}, seq=1, t_ms=0, zaman="z", oturum="o", gorev=None),
    lambda: E.build_event("iptal", {}, seq=1, t_ms=0, zaman="z", oturum="o", gorev=None),          # eksik
    lambda: E.build_event("iptal", {"kaynak": "analist", "fazla": 1}, seq=1, t_ms=0, zaman="z", oturum="o",
                          gorev=None),                                                             # fazla
    lambda: kur("iptal", kaynak="kullanici"),                                                      # kapalı küme
    lambda: kur("arac_basladi", cagiran="saldirgan"),
    lambda: kur("gorev_basladi", gorev_turu="kabuk"),
    lambda: kur("satir", duzey="kirmizi"),
    lambda: kur("arac_basladi", cagiran="model", hedef={"fn": "FUN_1"}),                           # hedef biçimi
    lambda: kur("arac_basladi", cagiran="model", hedef={"fn": 5, "adres": None}),
    lambda: kur("iptal", seq=0, kaynak="analist"),
    lambda: E.build_event("iptal", {"kaynak": "analist"}, seq=1, t_ms=-1, zaman="z", oturum="o", gorev=None),
    lambda: E.build_event("iptal", {"kaynak": "analist"}, seq=1, t_ms=0, zaman="z", oturum="../x", gorev=None),
    lambda: E.build_event("iptal", {"kaynak": "analist"}, seq=1, t_ms=0, zaman="z", oturum="o", gorev="g 1"),
    lambda: kur("butce", arac=float("nan")),
    lambda: kur("butce", arac=object()),
    lambda: kur("butce", arac={1: "x"}),
])
def test_sema_disi_olay_reddedilir(bozuk):
    with pytest.raises(E.EventError):
        bozuk()


# --------------------------------------------------------------------------------------------
# (b) görüntü arındırması


@pytest.mark.parametrize("tuzak", GORUNTU_TUZAKLARI)
def test_arindirma_denetim_ve_bicim_karakterleri_gorunur_kacis(tuzak):
    olay = kur("satir", metin=tuzak, duzey="bilgi")
    assert yorumlanan_yok(olay["metin"]), repr(olay["metin"])
    # JSON'dan geri çözülen metinde de (arayüzün göreceği) yorumlanacak karakter kalmaz.
    geri = json.loads(E.serialize(olay))["metin"]
    assert geri == olay["metin"] and yorumlanan_yok(geri)
    assert "\\" in geri and geri != tuzak                          # kaçış görünür


def test_arindirma_ayrintilari():
    d = E.display_text
    assert d("\x1b[31m") == "\\x1b[31m" and d("‮") == "\\u202e" and d("\U000e0041") == "\\U000e0041"
    assert d("a\nb\tc\rd") == "a\\nb\\tc\\rd"
    # Ters bölü olduğu gibi kalır: Ghidra dizgileri C kaçışıyla yazıyor ("...%s\\n" metni), ikilemek onları
    # yanlış gösterirdi. Bedel: düz "\u202e" metni ile gerçek U+202E'nin kaçışı aynı görünür; ikisi de
    # yorumlanmaz.
    assert d("usage: %s\\n") == "usage: %s\\n" and d("C:\\yol") == "C:\\yol"
    assert d("\\u202e") == d("\u202e") == "\\u202e"
    # Türkçe ve öbür basılabilir Unicode değişmez.
    tr = "Çağrı ağacı: ığdır İŞÖÜ ğüşiöç — “alıntı” 東京 🕷"
    assert d(tr) == tr
    # Tavan kaçışlanmış metne uygulanır; kaçış ortadan bölünmez; kaçan özgün karakter sayısı yazılır.
    assert d("x" * 10, 5) == "xxxxx… [+5 karakter]"
    assert d("ab\x1bcd", 4) == "ab… [+3 karakter]"
    assert d("ab\x1bcd", 6) == "ab\\x1b… [+2 karakter]"
    uzun = "y" * (LM.DISPLAY_TEXT_MAX_CHARS + 7)
    assert d(uzun) == "y" * LM.DISPLAY_TEXT_MAX_CHARS + "… [+7 karakter]"
    assert d("y" * LM.DISPLAY_TEXT_MAX_CHARS) == "y" * LM.DISPLAY_TEXT_MAX_CHARS
    with pytest.raises(TypeError):
        d(b"bayt")


def test_arindirma_ic_ice_ve_anahtarlar():
    olay = kur("gorev_bitti", durum="tamam", cevap={"isim": "f\x1b", "gerekce": "‮ters", "kanit": ("r1", "r2")},
               sayaclar={"a b": 1}, sure_ms=5)
    assert olay["cevap"] == {"isim": "f\\x1b", "gerekce": "\\u202eters", "kanit": ["r1", "r2"]}
    assert olay["sayaclar"] == {"a\\u2028b": 1}
    assert E.sanitize((True, 1, 1.5, None)) == [True, 1, 1.5, None]


# --------------------------------------------------------------------------------------------
# (c) halka ve uzun yoklama


class SahteSaat:
    def __init__(self, t: float = 100.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


def akis(kapasite: int = LM.EVENT_RING_CAPACITY, saat=None) -> E.EventStream:
    return E.EventStream("o1", capacity=kapasite, clock=saat or SahteSaat(), wall=lambda: "2026-11-18T12:00:00+03:00")


def satir(a: E.EventStream, n: int) -> list[dict]:
    return [a.emit("satir", metin=f"s{i}", duzey="bilgi") for i in range(n)]


def test_seq_bosluksuz_t_ms_ve_sema_disi_olay_sira_tuketmez():
    saat = SahteSaat(100.0)
    a = akis(saat=saat)
    assert LM.EVENT_RING_CAPACITY == 10000 and a.capacity == 10000
    e1 = a.emit("satir", metin="ilk", duzey="bilgi")
    saat.t = 100.25
    with pytest.raises(E.EventError):
        a.emit("satir", metin="x", duzey="yanlis")            # sıra numarası tüketmez
    with pytest.raises(E.EventError):
        a.emit("satir", metin=float("nan"), duzey="bilgi")
    e2 = a.emit("iptal", gorev="g1", kaynak="analist")
    assert (e1["seq"], e1["t_ms"], e2["seq"], e2["t_ms"], e2["gorev"]) == (1, 0, 2, 250, "g1")
    cevap = a.since(0)
    assert [e["seq"] for e in cevap["olaylar"]] == [1, 2] and cevap["son"] == 2
    assert (cevap["tasma"], cevap["kacan"], cevap["kapali"]) == (False, 0, False)
    assert cevap["olaylar"][0] == e1 and cevap["olaylar"][0] is not e1      # kopya: okuyan değiştiremez
    cevap["olaylar"][0]["metin"] = "bozuldu"
    assert a.since(0)["olaylar"][0]["metin"] == "ilk"
    assert a.last_seq == 2 and a.dropped == 0


def test_halka_tasmasi_kacan_sayisi_dogru():
    """E-2: halka dolunca en eski düşer; geride kalan istemci tasma + doğru kaçan sayısı görür."""
    a = akis(kapasite=5)
    satir(a, 12)
    assert a.dropped == 7 and a.last_seq == 12
    c = a.since(0)
    assert [e["seq"] for e in c["olaylar"]] == [8, 9, 10, 11, 12]
    assert (c["tasma"], c["kacan"], c["son"]) == (True, 7, 12)
    c = a.since(3)
    assert (c["tasma"], c["kacan"], [e["seq"] for e in c["olaylar"]]) == (True, 4, [8, 9, 10, 11, 12])
    c = a.since(7)                                             # tam sınırda: kayıp yok
    assert (c["tasma"], c["kacan"], len(c["olaylar"])) == (False, 0, 5)
    c = a.since(10, limit=1)
    assert ([e["seq"] for e in c["olaylar"]], c["son"], c["tasma"]) == ([11], 11, False)
    c = a.since(12)
    assert (c["olaylar"], c["son"], c["tasma"], c["kacan"]) == ([], 12, False, 0)
    with pytest.raises(ValueError):
        a.since(13)                                            # başka oturumun sırası
    for bozuk in (-1, True, "3"):
        with pytest.raises(ValueError):
            a.since(bozuk)
    with pytest.raises(ValueError):
        a.since(0, limit=0)
    with pytest.raises(ValueError):
        E.EventStream("o1", capacity=0)
    with pytest.raises(ValueError):
        E.EventStream("../x")


def test_yavas_istemci_benzetimi_her_olay_ya_verilir_ya_kacan_sayilir():
    """E-2: üretici patlamalar hâlinde yayar, istemci küçük sayfalarla okur. Her sıra numarası ya bir
    kez verilir ya da kaçan sayısına girer; ikisi birden ya da hiçbiri olmaz."""
    import random
    rnd = random.Random(20261118)
    a = akis(kapasite=7)
    verilen: list[int] = []
    kacan_toplam = 0
    son = 0
    for _ in range(300):
        satir(a, rnd.randint(0, 6))
        c = a.since(son, limit=rnd.randint(1, 4))
        kacan_toplam += c["kacan"]
        verilen += [e["seq"] for e in c["olaylar"]]
        son = c["son"]
    while son < a.last_seq:
        c = a.since(son, limit=3)
        kacan_toplam += c["kacan"]
        verilen += [e["seq"] for e in c["olaylar"]]
        son = c["son"]
    assert verilen == sorted(set(verilen))                     # yinelenmez, sırayla
    assert len(verilen) + kacan_toplam == a.last_seq          # her olay ya verildi ya kaçan sayıldı
    assert kacan_toplam > 0 and a.dropped >= kacan_toplam


def test_uzun_yoklama_olay_gelince_doner_yoksa_bos_doner_kapaninca_doner():
    import threading
    import time as _t
    a = E.EventStream("o1", capacity=10)
    t0 = _t.monotonic()
    bos = a.since(0, timeout=0.05)
    assert bos["olaylar"] == [] and _t.monotonic() - t0 >= 0.04   # olay yokken üretilen bir şey yok
    sonuc: dict = {}

    def bekle():
        sonuc["c"] = a.since(0, timeout=10)
        sonuc["t"] = _t.monotonic()

    th = threading.Thread(target=bekle)
    th.start()
    _t.sleep(0.05)
    t_yay = _t.monotonic()
    a.emit("satir", metin="geldi", duzey="bilgi")
    th.join(5)
    assert not th.is_alive() and [e["metin"] for e in sonuc["c"]["olaylar"]] == ["geldi"]
    assert sonuc["t"] - t_yay < 2.0                            # olay gelince hemen döner (10 sn beklemez)
    sonuc.clear()
    th = threading.Thread(target=lambda: sonuc.update(c=a.since(1, timeout=10)))
    th.start()
    _t.sleep(0.05)
    a.close()                                                  # bekleyen yoklama hemen döner
    th.join(5)
    assert not th.is_alive() and sonuc["c"]["olaylar"] == [] and sonuc["c"]["kapali"] is True
    with pytest.raises(E.EventError):
        a.emit("satir", metin="kapandıktan sonra", duzey="bilgi")
    assert a.closed and a.since(0)["kapali"] is True
    # Kapalı ama verilecek olay kalmışsa (sayfalama) "kapali" henüz True değildir.
    b = E.EventStream("o2", capacity=10)
    satir(b, 3)
    b.close()
    assert b.since(0, limit=1)["kapali"] is False and b.since(2)["kapali"] is True


# --------------------------------------------------------------------------------------------
# (d) hedef.fn = arayüzün BYADDR anahtarı (Workspace.ui_name)


def _arayuz_anahtarlari(srv, kok) -> set[str]:
    srv._CACHE.clear()
    srv.activate_workspace(str(kok))
    return {f["addr"] for f in srv.build_model()["functions"]}


def test_ui_name_arayuzun_byaddr_anahtariyla_ayni(srv, tmp_path):
    kok = default_ws(tmp_path / "ws")
    w = T.Workspace(kok)
    anahtarlar = _arayuz_anahtarlari(srv, kok)
    dolu = {a: w.ui_name(a) for a in w._functions.values() if w.ui_name(a) is not None}
    assert set(dolu.values()) == anahtarlar                    # her düğüme ulaşılır, düğümü olmayan ad yok
    assert len(set(dolu.values())) == len(dolu)                 # iki adres aynı düğüme gitmez
    assert dolu[A] == fun(A) and w.ui_name("0x" + A.upper()) == fun(A) == w.ui_name(A.lstrip("0"))
    # Decompile dosyası olmayan (ithal thunk, Ghidra'nın adlandırdığı) ve çalışma alanında olmayan adres: None.
    for a in (MALLOC, SIGNAL, ENTRY, "00fff000", "zz", None, 4096):
        assert w.ui_name(a) is None, a


def test_ui_name_dosya_adindan_okunur_adres_yaziminden_kurulmaz(srv, tmp_path):
    """ghidra_functions.json dolgusuz adres yazıyor (``1000``), dosya ``FUN_00001000.c``: eski yol
    (``f"FUN_{adres}"``) arayüzde olmayan bir anahtar verirdi; ui_name dosya adını verir."""
    kok = build_ws(tmp_path / "ws", {A: {"calls": [FB]}, FB: {"calls": []}})
    yol = kok / "static" / "ghidra_functions.json"
    veri = json.loads(yol.read_text(encoding="utf-8"))
    for f in veri["functions"]:
        f["address"] = f["address"].lstrip("0")
    yol.write_text(json.dumps(veri), encoding="utf-8")
    w = T.Workspace(kok)
    anahtarlar = _arayuz_anahtarlari(srv, kok)
    a = w.resolve(fun(A))
    assert a == "1000" and f"FUN_{a}" not in anahtarlar        # eski yol: düğüm bulunamazdı
    assert w.ui_name(a) == fun(A) and w.ui_name(a) in anahtarlar
    assert {w.ui_name(x) for x in w._functions.values()} == anahtarlar


# --------------------------------------------------------------------------------------------
# (e) ajanın olayları

AD = {"isim": "parse_table", "gerekce": "Tabloyu ayrıştırır.", "cekimser": False, "kanit": ["r1"]}


def yanit(nesne, **kw) -> B.FakeReply:
    return B.FakeReply(content=nesne if isinstance(nesne, str) else json.dumps(nesne, ensure_ascii=False), **kw)


def cagri(tool: str, **args) -> B.FakeReply:
    return yanit({"kind": "call", "tool": tool, "args": args})


def son(**degisen) -> B.FakeReply:
    return yanit({"kind": "final", **AD, **degisen})


def olayli(tmp_path, yanitlar, *, ws=None, duzey="L3", **kw):
    gunluk = AuditLog()
    arka = B.FakeBackend(list(yanitlar), level=duzey, audit=gunluk)
    akis = E.EventStream("o1")
    alan = ws if ws is not None else T.Workspace(default_ws(tmp_path / "ws"))
    return G.Agent(arka, alan, on_event=akis.emit, **kw), arka, gunluk, akis


def turler(akis) -> list[str]:
    return [e["tur"] for e in akis.since(0)["olaylar"]]


def ilk(akis, tur, **kosul) -> dict:
    return next(e for e in akis.since(0)["olaylar"] if e["tur"] == tur and all(e[k] == v for k, v in kosul.items()))


def esler_tutarli(akis, gunluk) -> None:
    """E-1: her araç kaydı için bir arac_basladi ve bir arac_bitti (aynı sonuç kimliğiyle, bu sırayla);
    her model isteği için bir model_istegi ve bir model_cevabi; seq boşluksuz."""
    olay = akis.since(0)["olaylar"]
    assert [e["seq"] for e in olay] == list(range(1, len(olay) + 1))
    kayit = [k["kimlik"] for k in gunluk.records if k["olay"] == "arac_cagrisi"]
    bas = [e["sonuc"] for e in olay if e["tur"] == "arac_basladi"]
    bit = [e["sonuc"] for e in olay if e["tur"] == "arac_bitti"]
    assert bas == bit == kayit
    for r in bas:
        i = next(i for i, e in enumerate(olay) if e["tur"] == "arac_basladi" and e["sonuc"] == r)
        j = next(i for i, e in enumerate(olay) if e["tur"] == "arac_bitti" and e["sonuc"] == r)
        assert i < j
    istek = [e["amac"] for e in olay if e["tur"] == "model_istegi"]
    assert istek == [e["amac"] for e in olay if e["tur"] == "model_cevabi"]
    assert istek == [k["amac"] for k in gunluk.records if k["olay"] == "model_istegi"]
    gorevler = [e for e in olay if e["tur"] in ("gorev_basladi", "gorev_bitti")]
    assert [e["tur"] for e in gorevler] == ["gorev_basladi", "gorev_bitti"] * (len(gorevler) // 2)


class Tik:
    """Her okunuşta 0,25 sn ilerleyen saat: ölçülen süreler kesin bilinir (araç ve model 250 ms)."""

    def __init__(self):
        self.t = 0.0

    def __call__(self) -> float:
        self.t += 0.25
        return self.t


def test_k0_olay_sirasi_ve_alanlar(tmp_path):
    ajan, arka, gunluk, akis = olayli(tmp_path, [yanit(AD, usage={"prompt_tokens": 900, "completion_tokens": 30,
                                                                    "prompt_tokens_details": {"cached_tokens": 512}})],
                                      clock=Tik())
    r = ajan.suggest_name(fun(A))
    assert r.status == "tamam"
    assert turler(akis) == ["gorev_basladi", "arac_basladi", "arac_bitti", "arac_basladi", "arac_bitti",
                            "model_istegi", "model_cevabi", "denetim", "gorev_bitti"]
    olay = akis.since(0)["olaylar"]
    assert {e["gorev"] for e in olay} == {"g1"} and {e["oturum"] for e in olay} == {"o1"}
    hedef = {"fn": fun(A), "adres": A}
    gb = olay[0]
    assert (gb["gorev_turu"], gb["kip"], gb["hedef"]) == ("ad_oner", "K0", hedef)
    assert gb["butce"] == {"arac": 0, "jeton": LM.CONTEXT_TOKENS, "sure_sn": r.time_budget_sec}
    b1, s1, b2, s2 = olay[1:5]
    assert (b1["sonuc"], b1["arac"], b1["cagiran"], b1["hedef"], b1["arguman"]) == (
        "r1", "get_evidence", "sunucu", hedef, {"addr": fun(A)})
    assert (s1["sonuc"], s1["tamam"], s1["hata"], s1["calistirildi"], s1["tur_kind"]) == ("r1", True, None, True, "olgu+cikarim")
    # Kanıt: çağrılan B, çağıran D, geri çağrı olarak verilen CB; ithaller (malloc, signal) düğüm değil.
    assert sorted(s1["dokunulan"]) == sorted([fun(FB), fun(D), fun(CB)]) and s1["dokunulan_toplam"] == 3
    # Kod: metindeki sırayla CB (signal argümanı), B; kendisi (öz çağrı) dokunulan sayılmaz.
    assert s2["dokunulan"] == [fun(CB), fun(FB)] and b2["arguman"] == {"addr": fun(A), "part": "bas"}
    assert s1["bayt"] == ajan.registry.call(ajan.workspace, "get_evidence", {"addr": fun(A)}, result_id="r1",
                                            ctx=T.ToolContext(single_shot=True)).size_bytes()
    assert (s1["sure_ms"], s2["sure_ms"]) == (250, 250) and s1["kirpma"] is None and s1["icerik_saklandi"] is None
    mi, mc, de, bit = olay[5:]
    assert (mi["amac"], mi["istem_kestirim"]) == ("k0", r.est_prompt_tokens)
    assert (mc["amac"], mc["durum"], mc["bitis_nedeni"], mc["istem_jeton"], mc["uretim_jeton"], mc["onbellek_jeton"],
            mc["niyet"], mc["hata"], mc["sure_ms"]) == ("k0", "gecerli", "stop", 900, 30, 512, None, None, 250)
    # Denetim: dört değerli hüküm + koşmayan kurallar (D4, D5) arayüze ulaşır.
    assert (de["nesne"], de["hukum"], de["toplu_kabul"]) == ("g1", r.verdict, r.guard["toplu_kabul"])
    assert de["bulgular"] == r.guard["bulgular"] and set(de["sinanmayan"]) == {"D4", "D5"}
    assert (bit["durum"], bit["ad_durumu"], bit["cevap"], bit["hukum"], bit["hata"]) == (
        "tamam", "gecerli", AD, r.verdict, None)
    assert bit["sayaclar"] == r.as_dict()["counters"] and bit["sure_ms"] == int(round(r.duration_sec * 1000))
    esler_tutarli(akis, gunluk)


def test_olay_geri_cagrisi_davranisi_degistirmez(tmp_path):
    """Olaylı ve olaysız ajan aynı sonucu, aynı istekleri ve aynı denetim kayıtlarını üretir."""
    sonuc = []
    for olayli_mi in (False, True):
        gunluk = AuditLog()
        arka = B.FakeBackend([yanit(AD, usage={"prompt_tokens": 9, "completion_tokens": 3})], audit=gunluk)
        akis = E.EventStream("o1")
        ajan = G.Agent(arka, T.Workspace(default_ws(tmp_path / str(olayli_mi))),
                       on_event=akis.emit if olayli_mi else None)
        r = ajan.suggest_name(fun(A)).as_dict()
        r.pop("duration_sec")
        sonuc.append((r, [(c["messages"], c["schema"], c["max_tokens"]) for c in arka.calls],
                      [{k: v for k, v in x.items() if k not in ("zaman", "sure_sn")} for x in gunluk.records],
                      akis.last_seq))
    assert sonuc[0][:3] == sonuc[1][:3] and sonuc[0][3] == 0 and sonuc[1][3] == 9


def test_dongu_olaylari_model_cagrisi_ret_ve_kor(tmp_path):
    ajan, arka, gunluk, akis = olayli(tmp_path, [
        cagri("get_xrefs", addr=fun(A), direction="callers"),
        cagri("get_xrefs", addr=fun(A), direction="callers"),                 # tekrar: çalışmaz
        cagri("get_xrefs", addr="FUN_00fff000", direction="callers"),         # bilinmeyen adres
        son(kanit=["r3"])], enabled_modes=("K0", "K2"), duzey="L1")
    r = ajan.run_loop(fun(A))
    assert r.status == "tamam", r
    esler_tutarli(akis, gunluk)
    model = [e for e in akis.since(0)["olaylar"] if e["tur"] == "arac_basladi" and e["cagiran"] == "model"]
    bitti = {e["sonuc"]: e for e in akis.since(0)["olaylar"] if e["tur"] == "arac_bitti"}
    x, tekrar, yok = model[0], model[1], model[2]
    assert (x["arac"], x["hedef"], x["arguman"]) == ("get_xrefs", {"fn": fun(A), "adres": A},
                                                     {"addr": fun(A), "direction": "callers"})
    assert bitti[x["sonuc"]]["dokunulan"] == [fun(D)] and bitti[x["sonuc"]]["calistirildi"] is True
    # Çalıştırılmadan reddedilen çağrı: hedef yok (örümcek oynamaz), sonuç çalışmadı, süre ölçülmedi.
    assert tekrar["hedef"] is None and tekrar["arguman"] == {"addr": fun(A), "direction": "callers"}
    t = bitti[tekrar["sonuc"]]
    assert (t["tamam"], t["hata"], t["calistirildi"], t["sure_ms"], t["dokunulan"]) == (False, "tekrar", False, None, [])
    assert yok["hedef"] is None and bitti[yok["sonuc"]]["hata"] == "bilinmeyen_adres"
    # Şemaya uymayan argüman: olaya ham yazılmaz (zarf şeması onu araca hiç ulaştırmaz; yazım kuralı ayrıca).
    assert ajan._shown_args("get_xrefs", {"addr": fun(A), "direction": "yukari"}) is None
    assert ajan._args_target("get_xrefs", {"addr": fun(A), "direction": "yukari"}) is None
    cevaplar = [e for e in akis.since(0)["olaylar"] if e["tur"] == "model_cevabi"]
    assert {e["amac"] for e in cevaplar} == {"dongu"} and all(e["niyet"] is None for e in cevaplar)


def test_dongu_kor_ve_baglam_karari_olaya_son_haliyle_gecer(tmp_path):
    """Körlük kipinde hedefin adını taşıyan sonuç modele verilmez: arac_bitti bunu söyler
    (çalıştı ama verilmedi; dokunulan boş)."""
    # Hedef A'nın Karadul adı report_error; komşusu FB aynı adlı bir ithali çağırıyor (test_lm_agent.py kurgusu).
    kayit = {"new_name": "report_error", "label": "doğrulanmadı"}
    kok = build_ws(tmp_path / "ws", {A: {"calls": [FB]}, FB: {"calls": [MALLOC]}}, imports={MALLOC: "report_error"},
                   names={A: "report_error", FB: "report_error"}, provenance={A: kayit, FB: kayit})
    ajan, arka, gunluk, akis = olayli(tmp_path, [cagri("get_evidence", addr=fun(FB)), son(kanit=["r1"])],
                                      ws=T.Workspace(kok), enabled_modes=("K0", "K2"), blind_target=True)
    r = ajan.run_loop(fun(A))
    assert r.counters.blind_blocked == 1, r
    e = ilk(akis, "arac_bitti", sonuc="r3")
    assert (e["tamam"], e["hata"], e["calistirildi"], e["dokunulan"], e["dokunulan_toplam"]) == (
        False, "arac_kapali", True, [], 0)
    esler_tutarli(akis, gunluk)


def test_touched_refs_alan_kurallari():
    zarf = {"ok": True, "data": {
        "addr": "FUN_00001000",
        "apis": "FUN_00009999 x1",                                  # ithal adı: ikiliden, taranmaz
        "callees": "FUN_00002000 [verified: parse_header], FUN_00001000",   # kendisi sayılmaz
        "callers": "FUN_00004000 [manual: renamed_by_hand]",
        "callbacks_given": "signal(FUN_00003000)", "callback_of": "qsort by FUN_00005000",
        "strings": '"FUN_00006000"', "constants": "FUN_00007000", "ghidra_warnings": ["FUN_00008000"],
        "items": [{"addr": "FUN_0000a000", "name_tag": "[unverified: FUN_0000b000]"}, {"addr": "kotu"}, "x"],
        "code": 'FUN_0000c000(); s = "FUN_0000d000"; c = \'FUN_0000e000\'; FUN_00002000();',
    }}
    assert E.touched_refs(zarf) == ["FUN_00002000", "FUN_00004000", "FUN_00003000", "FUN_00005000",
                                    "FUN_0000a000", "FUN_0000c000"]
    assert E.touched_refs({"ok": False, "error": "tekrar"}) == [] and E.touched_refs({"ok": True, "data": None}) == []


def test_dokunulan_dosya_adi_yazimiyla_ve_kendisi_haric(tmp_path):
    """ghidra_functions.json dolgusuz (``1000``), dosya adları dolgulu: dokunulan arayüz anahtarıyla
    yazılır ve hedefin kendisi (koddaki öz çağrı) yazım farkına rağmen dokunulan sayılmaz."""
    kok = build_ws(tmp_path / "ws", {A: {"calls": [FB, A]}, FB: {"calls": []}})
    yol = kok / "static" / "ghidra_functions.json"
    veri = json.loads(yol.read_text(encoding="utf-8"))
    for f in veri["functions"]:
        f["address"] = f["address"].lstrip("0")
    yol.write_text(json.dumps(veri), encoding="utf-8")
    ajan, _, _, akis = olayli(tmp_path, [yanit({**AD, "kanit": []})], ws=T.Workspace(kok))
    ajan.suggest_name(fun(A))
    assert ilk(akis, "gorev_basladi")["hedef"] == {"fn": fun(A), "adres": "1000"}
    assert ilk(akis, "arac_bitti", sonuc="r2")["dokunulan"] == [fun(FB)]


def test_dokunulan_ikili_metninden_okunmaz_ve_tavanli(tmp_path):
    x, y, z = "00001100", "00001200", "00001300"
    # Dizgiler çağrı argümanı değil (çağrı argümanındaki dizgiyi evidence.py geri çağrı sayıyor: P22a.md
    # "Yan bulgu"; o kural bu paketin dosyası değil).
    kod = (f'void FUN_{x}(void)\n{{\n  p = "FUN_{y} cagir";\n  c = \'FUN_{z}\';\n'
           f"  /* FUN_{z} yorum */\n  q = FUN_{y}x;\n  return;\n}}\n")
    kok = build_ws(tmp_path / "ws", {x: {"calls": [], "strings": [f"FUN_{y}", f"run FUN_{z} now"], "code": kod},
                                     y: {"calls": []}, z: {"calls": []}})
    ajan, _, gunluk, akis = olayli(tmp_path, [yanit({**AD, "kanit": []})], ws=T.Workspace(kok))
    ajan.suggest_name(fun(x))
    kanit, kod_olayi = (e for e in akis.since(0)["olaylar"] if e["tur"] == "arac_bitti")
    # Dizgi, dizgi sabiti ve karakter sabiti içindeki "FUN_…" metni dokunulan değil. Yorumdaki ad Ghidra'nın
    # metnidir (sayılır); "FUN_y" + harf bir tanımlayıcının parçasıdır (sayılmaz).
    assert kanit["dokunulan"] == [] and kod_olayi["dokunulan"] == [fun(z)]
    # Tavan: HUB'ın kanıtında 40 çağrılan + 30 çağıran gösteriliyor; olay 40'ını taşır, toplamı söyler.
    ajan2, _, _, akis2 = olayli(tmp_path / "2", [yanit({**AD, "kanit": []})])
    ajan2.suggest_name(fun(HUB))
    hub = ilk(akis2, "arac_bitti", sonuc="r1")
    assert LM.EVENT_TOUCHED_MAX == 40 and len(hub["dokunulan"]) == 40 and hub["dokunulan_toplam"] == 70
    assert len(set(hub["dokunulan"])) == 40 and fun(HUB) not in hub["dokunulan"]


def test_model_cagrilmayan_gorevde_yalniz_gorev_olaylari(tmp_path):
    ajan, arka, gunluk, akis = olayli(tmp_path, [])
    assert akis.last_seq == 0                                   # görev yokken olay yok
    r = ajan.suggest_name("FUN_00fff000")
    assert r.status == "bilinmeyen_adres" and turler(akis) == ["gorev_basladi", "gorev_bitti"]
    assert ilk(akis, "gorev_basladi")["hedef"] == {"fn": None, "adres": None}
    r = ajan.suggest_name(fun(MANUAL))                          # D2: elle verilmiş ad, model çağrılmaz
    assert r.status == "korunan_ad" and turler(akis)[2:] == ["gorev_basladi", "denetim", "gorev_bitti"]
    de = ilk(akis, "denetim", gorev="g2")
    assert (de["hukum"], de["bulgular"][0]["kod"]) == ("ret", "elle_ad_ezilmez")
    assert ilk(akis, "gorev_bitti", gorev="g2")["cevap"] is None and arka.calls == []
    esler_tutarli(akis, gunluk)


def test_hata_yollarinda_istek_ve_cevap_eslesir(tmp_path):
    # Geçici kopma → bir yineleme → cevap: iki istek, iki cevap; ilki arka uç hatası.
    kopma = B.FakeReply(error=B.BackendError("bağlantı koptu", transient=True))
    ajan, arka, gunluk, akis = olayli(tmp_path, [kopma, yanit(AD)])
    assert ajan.suggest_name(fun(A)).status == "tamam"
    cev = [e for e in akis.since(0)["olaylar"] if e["tur"] == "model_cevabi"]
    assert [(e["amac"], e["durum"]) for e in cev] == [("k0", "arka_uc_hatasi"), ("k0_yineleme", "gecerli")]
    assert "bağlantı koptu" in cev[0]["hata"]
    esler_tutarli(akis, gunluk)
    # Kalıcı hata: tek istek, cevap arka uç hatası; görev de öyle biter.
    ajan, _, gunluk, akis = olayli(tmp_path / "2", [B.FakeReply(error=B.BackendError("500"))])
    assert ajan.suggest_name(fun(A)).status == "arka_uc_hatasi"
    assert ilk(akis, "model_cevabi")["durum"] == "arka_uc_hatasi" and ilk(akis, "gorev_bitti")["hata"]
    esler_tutarli(akis, gunluk)
    # Bellek bekçisi cevaptan sonra durdurdu: cevap ayrıştırılmaz, olay bunu söyler.
    ajan, arka, gunluk, akis = olayli(tmp_path / "3", [yanit(AD, usage={"prompt_tokens": 5, "completion_tokens": 2})])
    ornek = M.MemorySample(pid=7, rss_gib=21.0, footprint_gib=0.0, upper_gib=21.0, complete=True, at="t")
    ajan.memory_guard = M.MemoryGuard(lambda: 7, lambda s: arka.stop("bellek"), measure=lambda pid: ornek)
    assert ajan.suggest_name(fun(A)).status == "bellek_durdu"
    mc = ilk(akis, "model_cevabi")
    assert (mc["durum"], mc["istem_jeton"], mc["uretim_jeton"]) == ("bellek_durdu", 5, 2)
    esler_tutarli(akis, gunluk)
    # Beklenmeyen hata: istek eşsiz kalmaz, görev beklenmeyen_hata ile biter, hata yükselir.
    ajan, arka, gunluk, akis = olayli(tmp_path / "4", [B.FakeReply(error=RuntimeError("bozuk"))])
    with pytest.raises(RuntimeError):
        ajan.suggest_name(fun(A))
    assert ilk(akis, "model_cevabi")["durum"] == "beklenmeyen_hata" and arka.stops == ["hata"]
    assert ilk(akis, "gorev_bitti")["durum"] == "beklenmeyen_hata"
    esler_tutarli(akis, gunluk)


def test_olay_geri_cagrisinin_hatasi_gorevi_beklenmeyen_hatayla_bitirir(tmp_path):
    akis = E.EventStream("o1")

    def bozuk(tur, **kw):
        if tur == "arac_bitti":
            raise RuntimeError("arayüz hatası")
        return akis.emit(tur, **kw)

    gunluk = AuditLog()
    arka = B.FakeBackend([yanit(AD)], audit=gunluk)
    ajan = G.Agent(arka, T.Workspace(default_ws(tmp_path / "ws")), on_event=bozuk)
    with pytest.raises(RuntimeError):
        ajan.suggest_name(fun(A))
    assert arka.stops == ["hata"] and arka.calls == []
    assert [k["olay"] for k in gunluk.records][-1] == "gorev"
    assert ilk(akis, "gorev_bitti")["durum"] == "beklenmeyen_hata"
    # Kapanış olayının hatası: görev bitmiş ve denetim kayıtları yazılmıştır (olaylar kayıtlardan sonra);
    # hata yükselir.
    gunluk2 = AuditLog()

    def kapanista_bozuk(tur, **kw):
        if tur == "gorev_bitti":
            raise RuntimeError("arayüz hatası")

    ajan2 = G.Agent(B.FakeBackend([yanit(AD)], audit=gunluk2), T.Workspace(default_ws(tmp_path / "ws2")),
                    on_event=kapanista_bozuk)
    with pytest.raises(RuntimeError):
        ajan2.suggest_name(fun(A))
    assert [k["olay"] for k in gunluk2.records][-2:] == ["denetim", "gorev"]
    assert gunluk2.records[-1]["durum"] == "tamam"


def test_niyet_yalniz_semaya_uyan_arac_dalindan(tmp_path, monkeypatch):
    """Berke kararı 5 (b): araç dalında modelin "neden" notu terminale gider. Şemaya girmesi
    ``protocol.call_branch`` yamasını ister (``yamalar/P22a__protocol.py.patch``: isteğe bağlı ``niyet``,
    en çok ``INTENT_MAX_CHARS``); burada yama aynı biçimde benzetilir."""
    from karadul.lm import protocol as P
    ozgun = P.call_branch

    def niyetli(tool, args_schema):
        dal = ozgun(tool, args_schema)
        dal["properties"]["niyet"] = {"type": "string", "maxLength": LM.INTENT_MAX_CHARS}
        return dal

    monkeypatch.setattr(P, "call_branch", niyetli)
    neden = "Çağıranlar adı ‮ters‬ çevirebilir mi?"
    ajan, _, gunluk, akis = olayli(tmp_path, [
        yanit({"kind": "call", "tool": "get_xrefs", "args": {"addr": fun(A), "direction": "callers"}, "niyet": neden}),
        yanit({"kind": "call", "tool": "get_xrefs", "args": {"addr": fun(A), "direction": "callees"},
               "niyet": "x" * (LM.INTENT_MAX_CHARS + 1)}),                     # şema dışı (uzun): gösterilmez
        cagri("get_xrefs", addr=fun(A), direction="address_refs"),            # niyetsiz (isteğe bağlı)
        son(kanit=["r3"])], enabled_modes=("K0", "K2"), duzey="L2")
    assert ajan.run_loop(fun(A)).status == "tamam"
    cev = [e for e in akis.since(0)["olaylar"] if e["tur"] == "model_cevabi"]
    assert [e["durum"] for e in cev] == ["gecerli", "sema_ihlali", "gecerli", "gecerli"]
    assert cev[0]["niyet"] == "Çağıranlar adı \\u202eters\\u202c çevirebilir mi?"       # arındırılmış
    assert [e["niyet"] for e in cev[1:]] == [None, None, None]                       # şema dışı / yok / son cevap
    assert [e["amac"] for e in cev] == ["dongu", "dongu", "dongu_onarim", "dongu"]
    esler_tutarli(akis, gunluk)
