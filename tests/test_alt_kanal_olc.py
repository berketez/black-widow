"""scripts/measurement/alt_kanal_olc.py — N0b adım 2 ölçüm betiğinin testleri (plan v2.2 G10).

Hesap testleri sentetik paket ve etiketlerle koşar. Kilitlenen davranışlar:
  (a) ön koşullar: sha256 denetimi, ön kayıt commit'inin HEAD'in atası olması, donmuş kayıtların
      yeniden sınıflanması (uyuşmazlıkta koşu durur),
  (b) öğeler: yemler dışarıda; ``tam`` anahtardaki ``status == "tp"``'den, değerlendiricinin
      ``tam``'ı ``dogru_tarif`` sayılır (G4 puanlayıcısı),
  (c) eşleme: adres biçimi, taban ad denetimi, eşlenmeyenlerin yalnız adresle listelenmesi,
  (d) sayım: oranlar ve Wilson aralıkları ``alt_kanal.wilson``'dan, karar ``alt_kanal.karar``'dan;
      birleşik ve program başına tablolar, tek kanal okuması, ``hepsini_kapatir``,
  (e) depodaki gerçek veriyle: 482/482 eşlenme ve G4'ün yayımlanmış program toplamları.

Mutasyon koruması: ``scripts/measurement/mutation_specs_alt_kanal.json``.
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

_KOK = Path(__file__).resolve().parents[1]
_PATH = _KOK / "scripts" / "measurement" / "alt_kanal_olc.py"
_spec = importlib.util.spec_from_file_location("alt_kanal_olc_under_test", _PATH)
olc = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = olc
_spec.loader.exec_module(olc)

ak = olc.alt_kanal()      # sha256 denetimiyle yüklenir
PAKET_SEMASI = "karadul-etiket-paketi/2"


# --------------------------------------------------------------------------------------------
# Sentetik paket


def oge(addr, aday, status="wrong", yem=False, capraz=0):
    return {"addr": addr, "aday": aday, "pred": aday, "gt": ["x"], "status": status, "yem": yem,
            "capraz_atif": capraz}


def paket_yaz(dizin, paket, program, ogeler, ek, etiketler):
    anahtar = {"kunye": {"sema": PAKET_SEMASI, "kip": "kor", "program": program},
               "ogeler": ogeler}
    (dizin / f"anahtar_{paket}.json").write_text(json.dumps(anahtar), encoding="utf-8")
    with open(dizin / f"etiket_{ek}.jsonl", "w", encoding="utf-8") as f:
        for iid, etiket in etiketler.items():
            f.write(json.dumps({"id": iid, "amac": f"amaç {iid}", "etiket": etiket,
                                "gerekce": ""}) + "\n")


def kayit(ad, alt_kanal, strateji="string_context", kaynak="string_ref", k=2):
    return {"ad": ad, "strateji": strateji, "alt_kanal": alt_kanal, "kanit_kaynagi": kaynak, "k": k}


def eslenmis(nihai, alt_kanal, program="p", strateji="string_context", kaynak="string_ref", k=2):
    return {"nihai": nihai, "alt_kanal": alt_kanal, "program": program, "strateji": strateji,
            "kanit_kaynagi": kaynak, "k": k, "capraz": False}


# --------------------------------------------------------------------------------------------
# (a) ön koşullar


def test_sha256_denetimi(tmp_path):
    yol = tmp_path / "betik.py"
    yol.write_bytes(b"print(1)\n")
    dogru = olc.sha256_dosya(yol)
    assert olc.sha256_denetle(yol, dogru) == dogru
    with pytest.raises(olc.OnkosulHatasi):
        olc.sha256_denetle(yol, "0" * 64)


def test_onkayitli_surumler_belgedekiyle_ayni():
    belge = (olc.ONKAYIT_DIZINI / "alt_kanal_onkayit.md").read_text(encoding="utf-8")
    assert olc.ALT_KANAL_SHA256 in belge
    assert olc.ONKAYIT_COMMIT == "f23f4ea"
    for sha in olc.KAYIT_SHA256.values():
        assert sha[:16] in belge
    assert olc.sha256_dosya(olc.ALT_KANAL_YOLU) == olc.ALT_KANAL_SHA256


@pytest.mark.skipif(shutil.which("git") is None, reason="git yok")
def test_commit_atasi():
    assert olc.commit_atasi_mi(olc.ONKAYIT_COMMIT) is True
    with pytest.raises(olc.OnkosulHatasi):
        olc.commit_atasi_mi("0123456789abcdef0123456789abcdef01234567")


def test_kayitlari_oku_yeniden_siniflar_ve_durur(tmp_path):
    satir = {"anahtar": "FUN_1", "adres": "0x1", "strateji": "string_context",
             "ad": "cmdq_append", "onerilen_ad": "cmdq_append", "guven": 0.8,
             "kanit": "cmdq_append", "kod_yolu": "classic", "kural": "keywords",
             "kanit_kaynagi": "string_ref", "alt_kanal": "oz_ad", "k": 2}
    (tmp_path / "kayitlar_p.jsonl").write_text(json.dumps(satir) + "\n", encoding="utf-8")
    assert olc.kayitlari_oku(tmp_path, "p")["0x1"]["alt_kanal"] == "oz_ad"
    (tmp_path / "kayitlar_p.jsonl").write_text(
        json.dumps({**satir, "alt_kanal": "tek_sozcuk"}) + "\n", encoding="utf-8")
    with pytest.raises(olc.OnkosulHatasi):
        olc.kayitlari_oku(tmp_path, "p")
    (tmp_path / "kayitlar_p.jsonl").write_text((json.dumps(satir) + "\n") * 2, encoding="utf-8")
    with pytest.raises(olc.OnkosulHatasi):
        olc.kayitlari_oku(tmp_path, "p")


# --------------------------------------------------------------------------------------------
# (b) öğeler ve nihai etiket


def test_ogeler_yem_disarida_ve_tam_anahtardan(tmp_path):
    ogeler = {"a": oge("0x10", "foo", status="tp"), "b": oge("0x20", "bar"),
              "c": oge("0x30", "baz"), "y": oge("0x40", "yem_adi", yem=True)}
    etiketler = {"a": "yanlis", "b": "tam", "c": "yalniz_alan", "y": "dogru_tarif"}
    paket_yaz(tmp_path, "pk", "p", ogeler, "E", etiketler)
    sonuc = {o["id"]: o for o in olc.ogeleri_yukle(tmp_path, "pk", "E")}
    assert sorted(sonuc) == ["a", "b", "c"]            # yem dışarıda
    assert sonuc["a"]["nihai"] == "tam"                # tp: değerlendirici yanlış dese de tam
    assert sonuc["b"]["nihai"] == "dogru_tarif"        # tp olmayana verilen tam
    assert sonuc["c"]["nihai"] == "yalniz_alan"


def test_ogeler_capraz_atif_ve_adres(tmp_path):
    ogeler = {"a": oge("0X10AB", "foo", capraz=2), "b": oge("20cd", "bar")}
    paket_yaz(tmp_path, "pk", "p", ogeler, "E", {"a": "yanlis", "b": "yanlis"})
    sonuc = {o["id"]: o for o in olc.ogeleri_yukle(tmp_path, "pk", "E")}
    assert sonuc["a"]["capraz"] is True and sonuc["b"]["capraz"] is False
    assert sonuc["a"]["adres"] == "0x10ab" and sonuc["b"]["adres"] == "0x20cd"


# --------------------------------------------------------------------------------------------
# (c) eşleme


def test_esleme_taban_ad_ve_eslenmeyenler():
    ogeler = [{"id": "a", "adres": "0x10", "aday": "small_2", "nihai": "yanlis", "capraz": False},
              {"id": "b", "adres": "0x20", "aday": "other", "nihai": "yanlis", "capraz": False},
              {"id": "c", "adres": "0x30", "aday": "lost", "nihai": "yanlis", "capraz": False}]
    kayitlar = {"0x10": kayit("small", "tek_sozcuk"), "0x20": kayit("different", "tek_sozcuk")}
    eslenen, ozet = olc.esle(ogeler, kayitlar, "p")
    assert [o["id"] for o in eslenen] == ["a"]         # yalnız çakışma eki farklı: eşlenir
    assert eslenen[0]["alt_kanal"] == "tek_sozcuk" and eslenen[0]["program"] == "p"
    assert ozet["taban_ad_uyusmuyor"] == ["0x20"]
    assert ozet["kayit_yok"] == ["0x30"]
    assert (ozet["ana_oge"], ozet["eslenen"]) == (3, 1)
    assert ozet["oran"] == pytest.approx(1 / 3, abs=1e-6)
    assert "small" not in json.dumps(ozet) and "other" not in json.dumps(ozet)


# --------------------------------------------------------------------------------------------
# (d) sayım ve karar


def test_sayim_oranlar_ve_karar():
    ogeler = ([eslenmis("dogru_tarif", "oz_ad")] * 30 + [eslenmis("tam", "oz_ad")] * 5
              + [eslenmis("yanlis", "kebap_ad")] + [eslenmis("yalniz_alan", "kebap_ad")] * 19
              + [eslenmis("yanlis", "tek_sozcuk")] * 8 + [eslenmis("dogru_tarif", "tek_sozcuk")] * 2)
    t = olc.tablo(ogeler)
    oz, kb, ts = (t["alt_kanallar"][k] for k in ("oz_ad", "kebap_ad", "tek_sozcuk"))
    assert oz["n"] == 35 and oz["sayilar"]["yakin"] == 35 and oz["sayilar"]["tam"] == 5
    assert oz["karar"]["karar"] == "dogrulandi" and oz["karar"]["guven_etiketi"] == "doğrulandı"
    assert kb["karar"]["karar"] == "belirsiz" and kb["karar"]["urunde"] is True
    assert kb["karar"]["guven_etiketi"] == "doğrulanmadı"
    assert ts["karar"]["karar"] == "zayif" and ts["karar"]["urunde"] is False
    assert t["alt_kanallar"]["agresif"]["karar"]["karar"] == "olculemedi"
    alt, ust = ak.wilson(8, 10)
    assert ts["oranlar"]["yanlis"] == {"k": 8, "n": 10, "oran": 0.8, "alt": round(alt, 6),
                                       "ust": round(ust, 6)}
    assert ts["yanlis_olmayan"]["k"] == 2
    assert t["tek_kanal"]["n"] == 65 and t["tek_kanal"]["sayilar"]["yanlis"] == 9
    assert t["hepsini_kapatir"] is False


def test_hepsini_kapatir_ve_string_context_disi():
    ogeler = ([eslenmis("yanlis", "tek_sozcuk")] * 10
              + [eslenmis("yanlis", None, strateji="api_param_reverse")] * 2)
    t = olc.tablo(ogeler)
    assert t["hepsini_kapatir"] is True
    assert t["tek_kanal"]["n"] == 10
    assert t["string_context_disi"]["api_param_reverse"]["n"] == 2
    assert "karar" not in t["string_context_disi"]["api_param_reverse"]


def test_bolum_karar_birlesik_sayilarla():
    ogeler = ([eslenmis("dogru_tarif", "oz_ad", program="a")] * 20
              + [eslenmis("dogru_tarif", "oz_ad", program="b")] * 15)
    b = olc.bolum(ogeler)
    assert b["programlar"]["a"]["alt_kanallar"]["oz_ad"]["karar"]["karar"] == "belirsiz"
    assert b["programlar"]["b"]["alt_kanallar"]["oz_ad"]["karar"]["karar"] == "belirsiz"
    assert b["birlesik"]["alt_kanallar"]["oz_ad"]["n"] == 35
    assert olc.kararlar(b)["oz_ad"] == "dogrulandi"      # 0/35: birleşikte doğrulanır
    assert olc.karar_farki({"oz_ad": "dogrulandi", "x": "zayif"},
                           {"oz_ad": "belirsiz", "x": "zayif"}) == {
        "oz_ad": {"ana": "dogrulandi", "duyarlilik": "belirsiz"}}


def test_betimsel_karar_disi():
    ogeler = ([eslenmis("yanlis", "kod_parcasi", kaynak="body_literal", k=3)] * 4
              + [eslenmis("dogru_tarif", "oz_ad", k=2)] * 3)
    bt = olc.betimsel(ogeler)
    assert bt["kanit_kaynagi"]["body_literal"]["n"] == 4
    assert bt["k"]["2"]["sayilar"]["yakin"] == 3
    assert "karar" not in bt["k"]["3"]


def test_yuzde_bicimi():
    assert olc.yuzde(0.4545) == "%45,5"
    assert olc.yuzde(None) == "—"


# --------------------------------------------------------------------------------------------
# (e) depodaki veri


_GERCEK_VAR = (olc.G4_VERI / "anahtar_tmux_385_kor.json").exists() and \
    (olc.ONKAYIT_DIZINI / "kayitlar_tmux.jsonl").exists()


@pytest.mark.skipif(not _GERCEK_VAR, reason="G4 verisi ya da ön kayıt kayıtları yok")
def test_gercek_veri_eslenme_ve_g4_toplamlari():
    s = olc.olc()
    assert s["esleme"]["toplam"] == {"ana_oge": 482, "eslenen": 482, "oran": 1.0}
    assert s["esleme"]["tmux_385_kor"]["strateji"] == {
        "api_param_reverse": 5, "binary_extract": 1, "string_context": 379}
    toplam = {}
    for p, t in s["ana"]["programlar"].items():
        n = t["tek_kanal"]["n"] + sum(v["n"] for v in t["string_context_disi"].values())
        y = t["tek_kanal"]["sayilar"]["yanlis"] + sum(
            v["sayilar"]["yanlis"] for v in t["string_context_disi"].values())
        toplam[p] = (y, n)
    # G4'ün yayımlanmış program toplamları (plan v2.1 §1: tmux %45,5, htop %81,4)
    assert toplam == {"tmux": (175, 385), "htop": (79, 97)}
    sabit = olc.ONKAYIT_DIZINI / "kesinlik_tablosu.json"
    if sabit.exists():
        assert s["ana_kararlar"] == json.loads(sabit.read_text(encoding="utf-8"))["ana_kararlar"]
