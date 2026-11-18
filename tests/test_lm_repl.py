"""P22e kalem 4 — kısıtlı terminal: izin listesi, girdi sınırları, komut ayrıştırıcısı, satır biçimi.

  (a) izin listesi tek öğe: ``karadullm`` dışında 200+ düşman / rastgele girdinin hiçbiri kabul edilmez (T-2);
  (b) girdi sınırları: uzunluk, denetim / biçim / görünmez karakter, Türkçe metin geçer (T-3);
  (c) ayrıştırıcı: kapalı küme, argüman kuralları, Türkçe yazımlar, soru yalnız keşifte;
  (d) satır biçimi: olaylardan terminal satırları (gerçek alanlar; "düşünce" satırı yok).

Model yok. Mutasyon koruması: ``scripts/measurement/mutation_specs_lm_oturum.json``.
"""
from __future__ import annotations

import random

import pytest

from karadul.lm import events as E
from karadul.lm import repl as R


# --------------------------------------------------------------------------------------------
# (a) izin listesi


DUSMAN = [
    "karadullm; ls", "karadullm && id", "karadullm | sh", "karadullm --model x", "karadullm x", "KARADULLM",
    "Karadullm", "karadullM", "$(karadullm)", "`karadullm`", "\nkaradullm", "karadullm\n", "karadullm\r",
    "\tkaradullm", "karadullm\t", "karadul​lm", "karadullm​", "﻿karadullm", "karadullm‮",
    "‮karadullm", "kаradullm", "ｋａｒａｄｕｌｌｍ", "karadullm\x00", "karadullm\x1b[2J", "karadul lm",
    "karadullm karadullm", "/karadullm", "./karadullm", "karadullm&", "karadullm>x", "karadullm<x", "sh",
    "bash -c karadullm", "", " ", "karadull", "karadullmm", "karadullm ", " karadullm",
    "karadullm ", "karadullm　", "kara͏dullm", "karadullm️", "karadullm" + " " * 1995 + "x",
]


def test_izin_listesi_tek_oge_ve_dusman_girdiler():
    assert R.ALLOWED_COMMANDS == frozenset({"karadullm"})
    assert R.is_allowed_command("karadullm") and R.is_allowed_command("  karadullm ")
    assert not any(R.is_allowed_command(x) for x in DUSMAN), [x for x in DUSMAN if R.is_allowed_command(x)]
    rnd = random.Random(20261118)
    alfabe = "karduLM;|&$()`-_ /\\\n\t\x00​‮ аｋ" + "karadullm"
    rastgele = set()
    while len(rastgele) < 200:
        n = rnd.randint(1, 14)
        s = "".join(rnd.choice(alfabe) for _ in range(n))
        if s.strip(" ") != "karadullm":
            rastgele.add(s)
    # karadullm'e bir karakter eklenmiş / değiştirilmiş biçimler
    for i in range(len("karadullm") + 1):
        for ch in ";|&$ \n\t​X":
            v = "karadullm"[:i] + ch + "karadullm"[i:]
            if v.strip(" ") != "karadullm":
                rastgele.add(v)
    assert sum(R.is_allowed_command(x) for x in rastgele) == 0
    assert not R.is_allowed_command(None) and not R.is_allowed_command(b"karadullm")
    # ret denetim kaydı: metin yazılmaz
    alan = R.command_audit_fields("karadullm; rm -rf ~")
    assert set(alan) == {"uzunluk", "sha256"} and alan["uzunluk"] == 19 and "rm" not in str(alan)


# --------------------------------------------------------------------------------------------
# (b) girdi sınırları


@pytest.mark.parametrize("girdi", ["a\x00b", "a\x1bb", "a\nb", "a\tb", "a\x7fb", "a\x85b", "a​b", "a‍b",
                                    "a‮b", "a⁦b", "a﻿b", "a b", "a b", "a b", "a　b",
                                    "a͏b", "aㅤb", "a️b", "ab", "a\U000e0041b", "a\ud800b"])
def test_girdi_sinirlari_gorunmez_ve_denetim_karakteri_reddedilir(girdi):
    with pytest.raises(R.InputError, match="U\\+"):
        R.check_text(girdi)


def test_girdi_uzunlugu_ve_turkce_metin():
    assert R.INPUT_MAX_CHARS == 2000
    R.check_text("ç" * 2000)
    with pytest.raises(R.InputError, match="çok uzun"):
        R.check_text("a" * 2001)
    metin = "Bu fonksiyon ağ bağlantısını açıyor mu? İçinde şifre çözme var — “emin değilim” (ğüşıöçİ) %s 0x1f"
    assert R.check_text(metin) == metin
    with pytest.raises(R.InputError):
        R.check_text(42)


# --------------------------------------------------------------------------------------------
# (c) ayrıştırıcı


def test_komutlar_ve_argumanlar():
    p = R.parse
    assert p("/kip acikla", "kesif") == R.Command("kip", kip="acikla")
    assert p("/kip adlandır", "kesif").kip == "adlandir" and p("/kip keşif", "plan").kip == "kesif"
    assert p("/acikla FUN_00001000", "kesif") == R.Command("acikla", hedef="FUN_00001000", derinlik=2)
    assert p("/açıkla FUN_1000 0", "acikla").derinlik == 0
    assert p("/ozet FUN_1000 1", "kesif") == R.Command("ozet", hedef="FUN_1000", derinlik=1)
    assert p("  /ad   FUN_1000  ", "adlandir") == R.Command("ad", hedef="FUN_1000")
    assert p("/not FUN_1000 bu   bir not ", "kesif") == R.Command("not", hedef="FUN_1000", metin="bu   bir not")
    assert p("/ac r12", "kesif") == R.Command("ac", sonuc="r12")
    assert p("/takip aç", "kesif").takip is True and p("/takip kapat", "kesif").takip is False
    for ad in ("onayla", "durdur", "oneriler", "hiz", "yardim", "cik"):
        assert p(f"/{ad}", "kesif") == R.Command(ad)
    assert p("/yardım", "kesif").ad == "yardim" and p("/çık", "plan").ad == "cik" and p("/hız", "kesif").ad == "hiz"
    # plan dilbilgisi
    assert p("/plan ithal connect", "plan") == R.Command("plan", metin="connect", plan_turu="ithal",
                                                         plan_gorevi="acikla")
    assert p("/plan ad ithal _connect", "plan").plan_gorevi == "ad_oner"
    assert p("/plan dizgi http://%s:%d/  x", "plan") == R.Command("plan", metin="http://%s:%d/  x",
                                                                   plan_turu="dizgi", plan_gorevi="acikla")
    assert p("/plan açıkla dizgi abc", "plan").plan_gorevi == "acikla"


@pytest.mark.parametrize("satir,ileti", [
    ("", "boş"), ("   ", "boş"), ("/ls", "bilinmeyen komut"), ("/kip", "kullanım"), ("/kip kabuk", "kip:"),
    ("/acikla", "kullanım"), ("/acikla 1000", "FUN_"), ("/acikla FUN_zz", "FUN_"), ("/acikla FUN_1000 3", "derinlik"),
    ("/acikla FUN_1000 -1", "derinlik"), ("/acikla FUN_1000 ١", "derinlik"), ("/ad FUN_1000 FUN_2000", "kullanım"),
    ("/not FUN_1000", "kullanım"), ("/ac 12", "r<sayı>"), ("/takip belki", "kullanım"), ("/onayla şimdi", "argümansız"),
    ("/plan", "kullanım"), ("/plan ithal", "kullanım"), ("/plan ithal a b", "ithal adı"), ("/plan ithal a;b", "ithal adı"),
    ("/plan dizgi ab", "3-64"), ("/plan dizgi " + "x" * 65, "3-64"), ("/plan sil dizgi abc", "kullanım"),
    ("/KIP acikla", "bilinmeyen komut"), ("/" + "x" * 40, "…"),
])
def test_ayristirma_hatalari(satir, ileti):
    with pytest.raises(R.InputError, match=ileti):
        R.parse(satir, "kesif")


def test_soru_yalniz_kesifte_ve_anmalar():
    c = R.parse("FUN_00001000 ile @FUN_00002000 ne yapıyor? @FUN_00002000 ve @FUN_3000x", "kesif")
    assert c.ad == "soru" and c.anmalar == ("FUN_00002000",)
    for kip in ("acikla", "adlandir", "plan"):
        with pytest.raises(R.InputError, match="keşif"):
            R.parse("bu ne yapıyor?", kip)
    # kapalı küme: bilinmeyen komut hiçbir kipte geçmez; komut adı harf duyarlı
    assert set(R.COMMANDS) == {"kip", "acikla", "ad", "ozet", "plan", "onayla", "durdur", "oneriler", "ac", "not",
                               "hiz", "takip", "yardim", "cik"}
    yardim = "\n".join(R.HELP_LINES)
    for c in R.COMMANDS:
        assert f"/{c}" in yardim, c


# --------------------------------------------------------------------------------------------
# (d) satır biçimi


def test_satir_bicimi_olaylardan():
    s = E.EventStream("o1")
    hedef = {"fn": "FUN_00001000", "adres": "00001000"}
    ev = [
        s.emit("gorev_basladi", gorev="g1", gorev_turu="acikla", kip="K0", hedef=hedef,
               butce={"arac": 0, "jeton": 10240, "sure_sn": 900.0}),
        s.emit("arac_bitti", gorev="g1", sonuc="r1", arac="get_evidence", tamam=True, hata=None, calistirildi=True,
               tur_kind="olgu+cikarim", bayt=812, kirpma=None, sure_ms=3, dokunulan=[], dokunulan_toplam=0,
               icerik_saklandi=True),
        s.emit("model_cevabi", gorev="g1", amac="k0", durum="gecerli", bitis_nedeni="stop", istem_jeton=1500,
               uretim_jeton=40, onbellek_jeton=None, sure_ms=900, niyet=None, hata=None),
        s.emit("denetim", gorev="g1", nesne="g1", hukum="sinanamadi", bulgular=[], bayraklar=[], toplu_kabul=False,
               sinanan=["D0"], sinanmayan={"D4": "x", "D5": "y"}),
        s.emit("ozet", gorev="g1", hedef=hedef, metin="Ayrıştırır.\x1b[2J", belirsiz=False, kanit=["r1"],
               hukum="sinandi_celiski_yok", kaynak="model"),
        s.emit("jeton", gorev="g1", parca=3, karakter=12),
        s.emit("gorev_bitti", gorev="g1", durum="tamam", hata=None, ad_durumu=None, cevap=None, hukum=None,
               toplu_kabul=None, sayaclar={"tool_calls": 0, "model_calls": 1}, sure_ms=950),
        s.emit("iptal", kaynak="analist"),
        s.emit("satir", metin="uyarı metni", duzey="uyari"),
        s.emit("oturum_bitti", neden="cik"),
    ]
    satirlar = [R.render(e) for e in ev]
    assert satirlar[0] == ["● g1 açıkla FUN_00001000  bütçe: 0 araç · 10240 jeton · 900.0 sn"]
    assert satirlar[1] == ["  ⎿ r1 get_evidence  olgu+cikarim · 812 B · 3 ms"]
    assert satirlar[2] == ["  ◆ model: istem 1500 jeton · üretilen 40 jeton · gecerli"]
    assert satirlar[3][0] == "  denetim: SINANAMADI (kanıt yok)" and "D4, D5" in satirlar[3][1]
    assert "\x1b" not in satirlar[4][0] and "\\x1b" in satirlar[4][0] and "model önerisi · kanıt r1" in satirlar[4][0]
    assert satirlar[5] == []                                   # jeton: terminal satırı yok
    assert satirlar[6][0].startswith("● g1 bitti · tamam · 0 araç · 1 model çağrısı")
    assert satirlar[7] == ["■ iptal istendi (analist)"] and satirlar[8] == ["! uyarı metni"]
    assert satirlar[9] == ["oturum kapandı (cik)"]
    # ölçülmemiş değer uydurulmaz: "?" yazılır
    yok = s.emit("arac_bitti", gorev="g1", sonuc="r2", arac="get_xrefs", tamam=False, hata="tekrar",
                 calistirildi=False, tur_kind=None, bayt=None, kirpma=None, sure_ms=None, dokunulan=[],
                 dokunulan_toplam=0, icerik_saklandi=None)
    assert R.render(yok) == ["  ⎿ r2 get_xrefs  hata: tekrar · ? B · ? ms"]
    assert not any("düşün" in x for xs in satirlar for x in xs)


# --------------------------------------------------------------------------------------------
# (e) bağımsız CLI: python -m karadul.lm (karar 10 (b))


def test_cli_modelsiz_oturum_ve_acilis_hatalari(tmp_path):
    import io
    import os

    from karadul.lm import __main__ as CLI
    from karadul.lm import session as S
    from tests.test_lm_tools import default_ws
    ws = default_ws(tmp_path / "ws")
    out = io.StringIO()
    # ikili özeti çalışma alanında yok: uydurulmaz, istenir
    assert CLI.main(["--calisma-alani", str(ws)], stdin=io.StringIO(""), stdout=out) == 2
    assert "--ikili-sha256" in out.getvalue()
    # sunucu ikilisi reddedilir (adı yanlış) — süreç açılmaz
    kotu = tmp_path / "bin" / "sunucu"
    kotu.parent.mkdir()
    kotu.write_bytes(b"#!/bin/sh\n")
    os.chmod(kotu, 0o755)
    out = io.StringIO()
    assert CLI.main(["--calisma-alani", str(ws), "--ikili-sha256", "ab" * 32, "--llama-server", str(kotu),
                     "--model", "/m.gguf"], stdin=io.StringIO(""), stdout=out) == 2
    assert "llama-server" in out.getvalue() and S.current_session() is None
    # modelsiz oturum: yardım, plan, not, öneriler, çık
    girdi = io.StringIO("/yardim\n/acikla FUN_00001000\n/kip plan\n/plan ithal malloc\n/not FUN_00001000 deneme\n"
                        "karadullm; sh\n/oneriler\n/cik\n/yardim\n")
    out = io.StringIO()
    assert CLI.main(["--calisma-alani", str(ws), "--ikili-sha256", "AB" * 32, "--depo", str(tmp_path / "depo")],
                    stdin=girdi, stdout=out) == 0
    metin = out.getvalue()
    for beklenen in ("KaradulLM · yok · model bilinmiyor", "model yok (arka uç verilmedi)",
                     "karadullm> /acikla FUN_00001000", "plan: find_refs(import=malloc): 1 fonksiyon",
                     "not deftere yazıldı: FUN_00001000", "✗ serbest metin yalnız keşif kipinde", "öneri yok",
                     "oturum kapandı (cik)", "bağlam - ·"):
        assert beklenen in metin, (beklenen, metin)
    assert "karadullm> /yardim" in metin and metin.rstrip().endswith("oturum kapandı (cik)")
    assert metin.count("karadullm> ") == 8                                   # /cik'ten sonraki satır okunmaz
    assert (tmp_path / "depo" / ("ab" * 32) / "defter.jsonl").exists() and S.current_session() is None
