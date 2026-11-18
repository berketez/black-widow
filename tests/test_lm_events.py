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
from karadul.lm import events as E

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
