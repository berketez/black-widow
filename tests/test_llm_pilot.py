"""scripts/measurement/llm_pilot.py — G6 LLM pilotu harness'inin birim testleri (sentetik veri).

Kilitlenen davranışlar:
  (a) tohum yöntemi test seti kurasındakiyle aynı; örneklem girdinin sırasından bağımsız,
      belirlenimci; kümeler ayrık; gövdesi bulunamayan / belirsiz / C'si olmayan dışlanır,
  (b) Karadul başlığı silinir; kırpma bayt sınırına uyar, baştaki ve sondaki satırlar kalır,
  (c) sızıntı taraması: kodda tanımlayıcı olarak geçen gerçek ad (``_`` önekli biçim dahil)
      yakalanır; dizgi ve yorum içindeki geçiş sızıntı sayılmaz,
  (d) kanıt paketi hedefin kendi Karadul adını asla taşımaz; sınırlar ve ``none``,
  (e) ayrıştırma: ön kayıttaki durum sınıfları (zorunlu koşulda çekimserlik isim sayılmaz,
      jenerik ad isim sayılmaz); düşünme blokları (Qwen ``<think>``, Gemma 4 ``<|channel>``;
      kapanmamışı dahil) ayıklanır, konumlar ham içerikte kalır,
  (f) log-olasılık güveni bayt hizalı, cevabın jetonlarından hesaplanır,
  (g) koşu kaldığı yerden devam eder, bellek eşiğinde durur, sızıntılı istemi çalıştırmaz;
      pilot beklenmeyen hatada da modeli boşaltır,
  (h) aday listesi (id, kosul, aday, cekimser) gerçek ad taşımaz; belirlenimcilik sayımı;
      kapılar (K-1 eksiksizlik dahil); künyedeki çözme ayarları istemcinin gönderdiğiyle aynı.
Mutasyon koruması: ``scripts/measurement/mutation_specs_llm_pilot.json``
(``PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec <o dosya>``).
"""
from __future__ import annotations

import importlib.util
import json
import math
import random
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

_PATH = Path(__file__).resolve().parents[1] / "scripts" / "measurement" / "llm_pilot.py"
_spec = importlib.util.spec_from_file_location("llm_pilot_under_test", _PATH)
lp = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = lp
_spec.loader.exec_module(lp)


# --------------------------------------------------------------------------------------------
# (a) tohum ve örneklem


def test_tohum_yontemi_test_seti_kurasiyla_ayni():
    assert lp.tohum("karadul-test-seti-kura-2026-10-15") == 1357717698366421230
    assert lp.tohum(lp.TOHUM_ORNEKLEM_METNI) == 18166492616011533410


def _satir(addr, sinif="program", gt=("_f",)):
    return {"addr": f"0x{addr}", "sinif": sinif, "gt": list(gt), "status": "unnamed", "pred": None}


def test_uygun_populasyon_dislar_ve_siralar():
    rows = [_satir("100000300", gt=["_belirsiz_ad"]), _satir("100000100"), _satir("100000400", sinif="cold"),
            _satir("100000200", gt=["_yok_ad"]), _satir("100000500"), _satir("100000050")]
    durumlar = {"_belirsiz_ad": "belirsiz", "_yok_ad": "yok"}
    uygun, dis = lp.uygun_populasyon(
        list(reversed(rows)),
        c_var=lambda a: a != "100000500",
        govde_durumu=lambda g: durumlar.get(g[0], "tek"),
    )
    assert uygun == ["100000050", "100000100"]
    assert dis == {"govde_yok": ["100000200"], "govde_belirsiz": ["100000300"], "c_yok": ["100000500"]}


def _uygun_listeler():
    return {p: [f"{0x100000000 + 16 * i + k:x}" for i in range(220)] for k, p in enumerate(lp.PROGRAMLAR)}


def _c_metni(p, a):
    return "uVar1 = _getpwnam(param_1); // auth" if int(a, 16) % 3 == 0 else "return 0;"


def _c_metni_seyrek(p, a):
    return "uVar1 = _crypt(param_1);" if int(a, 16) % 23 == 0 else "return 0;"


def test_cekim_belirlenimci_sirasiz_ve_ayrik():
    uygun = _uygun_listeler()
    a = lp.cekim(uygun, _c_metni, 12345)
    karisik = {p: random.Random(9).sample(v, len(v)) for p, v in uygun.items()}
    b = lp.cekim(karisik, _c_metni, 12345)
    assert a == b
    for p in lp.PROGRAMLAR:
        assert len(a["ana"][p]) == lp.ANA_N
        assert len(set(a["ana"][p])) == lp.ANA_N
        kuru, sonda = set(a["kuru"][p]), set(a["sonda"][p])
        assert len(kuru) == lp.KURU_N and len(sonda) == lp.SONDA_N
        assert not (kuru & set(a["ana"][p])) and not (sonda & set(a["ana"][p])) and not (kuru & sonda)
        assert all(int(x, 16) % 3 == 0 for x in a["sonda"][p])  # anahtar sözcüklüler önce
        assert a["dusunme"][p] == a["ana"][p][: lp.DUSUNME_N]
        assert a["insan"][p] == a["ana"][p][: lp.INSAN_N]
    assert len(a["yem"]) == lp.YEM_N and set(a["yem"]) <= {f"{p}-{x}" for p in lp.PROGRAMLAR for x in a["ana"][p]}
    assert lp.cekim(uygun, _c_metni, 54321)["ana"] != a["ana"]
    # Anahtar sözcüklü aday yetmezse kalanların hepsi alınır, küme kalan popülasyondan tamamlanır.
    s = lp.cekim(uygun, _c_metni_seyrek, 12345)
    for p in lp.PROGRAMLAR:
        kalan = set(uygun[p]) - set(s["ana"][p]) - set(s["kuru"][p])
        anahtarli = {x for x in kalan if int(x, 16) % 23 == 0}
        assert len(anahtarli) < lp.SONDA_N
        assert anahtarli <= set(s["sonda"][p]) and len(s["sonda"][p]) == lp.SONDA_N


# --------------------------------------------------------------------------------------------
# (b) başlık ve kırpma


def test_baslik_silinir_govde_kalir():
    kod = ("// Function: FUN_100001000\n// Address:  100001000\n// Size:     8 bytes\n// Callers:  1 (FUN_1)\n"
           "// Callees:  0\n// Stack:    frame=0\n\n\nvoid FUN_100001000(void)\n\n{\n  // Ghidra yorumu\n  return;\n}\n")
    out = lp.baslik_sil(kod)
    assert out.startswith("void FUN_100001000(void)")
    assert "// Ghidra yorumu" in out
    assert lp.baslik_sil("int x;\n") == "int x;\n"


def test_kirpma_bayt_sinirina_uyar_bas_ve_son_kalir():
    satirlar = [f"  uVar{i} = FUN_10000{i:04x}(param_1, {i});\n" for i in range(600)]
    kod = "".join(satirlar)
    assert len(kod.encode()) > lp.KOD_SINIR
    out, kirpildi, atlanan = lp.kirp(kod)
    assert kirpildi and atlanan > 0
    bas, _, son = out.partition(f"/* [karadul-g6] {atlanan} lines omitted */\n")
    assert len(bas.encode()) <= lp.KOD_BAS and len(son.encode()) <= lp.KOD_SON
    assert bas.startswith(satirlar[0]) and son.endswith(satirlar[-1])
    assert bas.count("\n") + son.count("\n") + atlanan == len(satirlar)
    kisa = "int x;\n"
    assert lp.kirp(kisa) == (kisa, False, 0)


# --------------------------------------------------------------------------------------------
# (c) sızıntı taraması


def test_sizinti_taramasi_tanimlayicida_yakalar_dizgide_yakalamaz():
    adlar = {"gizli_islev", "baska_ad"}
    assert lp.tanimlayici_sizintisi("  gizli_islev(param_1);\n", adlar) == ["gizli_islev"]
    assert lp.tanimlayici_sizintisi("  _gizli_islev(param_1);\n", adlar) == ["gizli_islev"]
    dizgide = '  _log("gizli_islev: %d", x); /* baska_ad */ // baska_ad\n  c = \'"\';\n'
    assert lp.tanimlayici_sizintisi(dizgide, adlar) == []
    assert "gizli_islev: %d" in lp.dizgi_sabitleri(dizgide)
    assert lp.tanimlayici_sizintisi("gizli_islevx(); xgizli_islev();", adlar) == []


def test_sizinti_adlari_kopyada_olani_ve_kisalari_disarida_birakir():
    tanimli = {"_alpha_beta", "_main", "_xy", "ltmp0", "_present_sym", "__mh_execute_header", "_9bad"}
    kopyada = {"_present_sym", "__mh_execute_header", "_malloc"}
    assert lp.sizinti_adlari(tanimli, kopyada) == {"alpha_beta", "main"}


def test_sabit_metin_taramasi_yalniz_tanimlayici_benzeri_sozcuklere_bakar():
    adlar = {"window_resize", "name"}
    assert lp.sabit_metin_sizintisi("for example window_resize or the name", adlar) == ["window_resize"]
    assert lp.sabit_metin_sizintisi("".join(lp.ISTEM_DOSYALARI.values()), {"window_resize", "parse_config_line"}) == []


# --------------------------------------------------------------------------------------------
# (d) kanıt paketi


def _pack():
    return SimpleNamespace(
        api_counts={"strlen": 2, "malloc": 1},
        internal_callees=["100000a00", "100000b00", "100000c00"],
        callers=["100000c00"] + [f"{0x100002000 + i:x}" for i in range(35)],
        callback_registrations=[{"api": "event_set", "target": "100000a00"}],
        registered_as_callback=[{"api": "qsort", "registrar": "100000b00"}],
        strings=["usage: %s", "usage: %s", "x" * 200, ""],
        large_constants=["0x12345678"],
    )


def test_kanit_paketi_hedefin_kendi_adini_tasimaz():
    adlar = {"100000a00": ("hedef_kendi_adi", "proven"), "100000b00": ("komsu_ad", "inferred"),
             "100000c00": ("baska_komsu", "proven")}
    alanlar = lp.kanit_alanlari(_pack(), lambda a: adlar.get(a), "100000a00")
    metin = "\n".join(alanlar.values())
    assert "hedef_kendi_adi" not in metin
    assert "FUN_100000a00" in alanlar["CAGIRILANLAR"]
    assert "FUN_100000b00 [inferred: komsu_ad]" in alanlar["CAGIRILANLAR"]
    assert "FUN_100000c00 [proven: baska_komsu]" in alanlar["CAGIRANLAR"]
    assert alanlar["CAGIRANLAR"].endswith("... and 6 more")
    assert alanlar["APIS"] == "malloc x1, strlen x2"
    assert alanlar["DIZGILER"].count('"usage: %s"') == 1 and '"' + "x" * 120 + '"' in alanlar["DIZGILER"]
    assert alanlar["GERI_CAGRI_VERIR"] == "event_set(FUN_100000a00)"
    bos = lp.kanit_alanlari(SimpleNamespace(api_counts={}, internal_callees=[], callers=[], callback_registrations=[],
                                            registered_as_callback=[], strings=[], large_constants=[]),
                            lambda a: None, "1")
    assert set(bos.values()) == {"none"}


def test_kanit_hedef_sizintisi_dizgi_ve_etiket_disinda_arar():
    kanit = {k: "none" for k in ("APIS", "CAGIRILANLAR", "CAGIRANLAR", "GERI_CAGRI_VERIR", "GERI_CAGRI_OLUR",
                                 "DIZGILER", "SABITLER")}
    kanit["DIZGILER"] = '"gizli: hata"'
    kanit["CAGIRILANLAR"] = "FUN_1 [inferred: gizli]"
    assert lp.kanit_hedef_sizintisi(kanit, {"gizli"}) == []
    kanit["APIS"] = "gizli x1"
    assert lp.kanit_hedef_sizintisi(kanit, {"gizli"}) == ["gizli"]


def test_doldur_tek_gecis_ve_mesajlar():
    kayit = {"kod": 'puts("{KOD} {APIS}");', "kanit": {k: "none" for k in (
        "APIS", "CAGIRILANLAR", "CAGIRANLAR", "GERI_CAGRI_VERIR", "GERI_CAGRI_OLUR", "DIZGILER", "SABITLER")}}
    b = lp.mesajlar("B", kayit)
    assert b[1]["content"] == 'Decompiled function:\n```c\nputs("{KOD} {APIS}");\n```\n'
    assert "Facts about this function" not in b[1]["content"] and "You must give a name." in b[0]["content"]
    cc = lp.mesajlar("C-Ç", kayit)
    assert "Facts about this function" in cc[1]["content"] and "abstain instead" in cc[0]["content"]
    assert cc[0]["content"].startswith(lp.SISTEM_ORTAK)


# --------------------------------------------------------------------------------------------
# (e) ayrıştırma


@pytest.mark.parametrize("icerik,bitis,kosul,beklenen", [
    ('{"isim": "parse_header", "gerekce": "x", "cekimser": false}', "stop", "B", "gecerli"),
    ('Sure! {"isim": "parse_header", "gerekce": "x", "cekimser": false} done', "stop", "C", "gecerli"),
    ('<think>{"isim": "a"}</think>{"isim": "read_cfg", "gerekce": "x", "cekimser": false}', "stop", "B", "gecerli"),
    ('{"isim": "FUN_100000a00", "gerekce": "x", "cekimser": false}', "stop", "B", "jenerik"),
    ('{"isim": null, "gerekce": "x", "cekimser": true}', "stop", "B", "zorunluyken_cekimser"),
    ('{"isim": null, "gerekce": "x", "cekimser": true}', "stop", "B-Ç", "cekimser"),
    ('{"isim": "read_cfg", "gerekce": "x", "cekimser": true}', "stop", "C-Ç", "gecersiz"),
    ('{"isim": "parse_hea', "length", "B", "butce_asimi"),
    ("I cannot help with reverse engineering this.", "stop", "B", "ret"),
    ("hmm", "stop", "B", "gecersiz"),
    ('{"isim": "two words", "gerekce": "x", "cekimser": false}', "stop", "B", "gecersiz"),
    ('{"isim": "read_cfg", "cekimser": false}', "stop", "B", "gecersiz"),
])
def test_ayristirma_durum_siniflari(icerik, bitis, kosul, beklenen):
    sonuc = lp.ayristir(icerik, bitis, kosul, "100000a00")
    assert sonuc["durum"] == beklenen
    if beklenen not in ("gecerli", "jenerik"):
        assert sonuc["isim"] is None


def test_ayristirma_dusunme_bloklari_ham_konumla():
    # Gemma 4 düşünme kanalı (sohbet şablonundaki işaretler) ayıklanır; içindeki taslak cevap isim sayılmaz.
    gemma = ('<|channel>thought\n{"isim": "taslak_ad", "gerekce": "x", "cekimser": false}<channel|>'
             '{"isim": "read_cfg", "gerekce": "x", "cekimser": false}')
    s = lp.ayristir(gemma, "stop", "B", "100000a00")
    assert s["durum"] == "gecerli" and s["isim"] == "read_cfg"
    assert gemma[s["json_bas"]:s["json_son"]].startswith('{"isim": "read_cfg"')  # konum ham içerikte
    # Kapanmamış düşünme: bütçe model düşünürken bitti; içindeki taslak cevap sayılmaz.
    yarim = '<think>{"isim": "taslak_ad", "gerekce": "x", "cekimser": false} hmm, belki'
    assert lp.ayristir(yarim, "length", "B", "100000a00")["durum"] == "butce_asimi"
    yarim_g = yarim.replace("<think>", "<|channel>thought\n")
    assert lp.ayristir(yarim_g, "length", "B", "100000a00")["durum"] == "butce_asimi"
    # Düşünmede geçen ret kalıbı cevabı ret yapmaz.
    assert lp.ayristir("<think>I cannot decide yet</think>hmm", "stop", "B", "100000a00")["durum"] == "gecersiz"


# --------------------------------------------------------------------------------------------
# (f) güven


def test_isim_guveni_bayt_hizali():
    icerik = 'Ş {"isim": "read_cfg", "gerekce": "ölçü", "cekimser": false}'
    parcalar = ["Ş ", '{"', "is", 'im": "', "read", "_cfg", '", "', 'gerekce": "ölçü", "cekimser": false}']
    lps = [-0.1, -0.2, -0.3, -0.4, -1.0, -3.0, -0.5, -0.6]
    jetonlar = [{"token": t, "logprob": l, "bytes": list(t.encode())} for t, l in zip(parcalar, lps)]
    ayr = lp.ayristir(icerik, "stop", "B", "100000a00")
    ort, en_kucuk = lp.isim_guveni(icerik, jetonlar, ayr["json_bas"], ayr["isim"])
    assert ort == pytest.approx(-2.0) and en_kucuk == pytest.approx(math.exp(-3.0))
    bozuk = jetonlar[:-1]
    assert lp.isim_guveni(icerik, bozuk, ayr["json_bas"], ayr["isim"]) == (None, None)


def test_isim_guveni_dusunmeden_sonraki_cevabin_jetonlarindan():
    # Düşünmedeki taslak aynı adı taşısa da güven cevabın jetonlarından hesaplanır.
    icerik = '<think>{"isim": "read_cfg"}</think>{"isim": "read_cfg", "gerekce": "x", "cekimser": false}'
    bol = icerik.index("</think>") + len("</think>")
    parcalar = [icerik[:bol], '{"isim": "', "read_cfg", '", "gerekce": "x", "cekimser": false}']
    lps = [-5.0, -0.1, -0.7, -0.2]
    jetonlar = [{"token": t, "logprob": l, "bytes": list(t.encode())} for t, l in zip(parcalar, lps)]
    ayr = lp.ayristir(icerik, "stop", "B", "100000a00")
    ort, en_kucuk = lp.isim_guveni(icerik, jetonlar, ayr["json_bas"], ayr["isim"])
    assert ort == pytest.approx(-0.7) and en_kucuk == pytest.approx(math.exp(-0.7))


# --------------------------------------------------------------------------------------------
# (g) koşu: devam, bellek eşiği, sızıntı


class _SahteIstemci:
    def __init__(self):
        self.cagri = 0

    def sohbet(self, model_kimlik, mesaj, dusunme):
        self.cagri += 1
        icerik = '{"isim": "read_cfg", "gerekce": "x", "cekimser": false}'
        jeton = [{"token": icerik, "logprob": -0.5, "bytes": list(icerik.encode())}]
        return ({"choices": [{"message": {"content": icerik, "reasoning_content": ""}, "finish_reason": "stop",
                              "logprobs": {"content": jeton}}],
                 "usage": {"prompt_tokens": 100, "completion_tokens": 20}}, 0.01, {"temperature": 0})


def _kok(tmp_path, sizinti=False):
    kok = tmp_path / "kok"
    (kok / "istemler").mkdir(parents=True)
    ornek = {"ana": {"htop": ["100000a00", "100000b00"], "tmux": ["100000c00"]},
             "kuru": {"htop": [], "tmux": []}, "sonda": {"htop": [], "tmux": []},
             "dusunme": {"htop": ["100000a00", "100000b00"], "tmux": []}, "bellek": []}
    (kok / "orneklem.json").write_text(json.dumps(ornek))
    kanit = {k: "none" for k in ("APIS", "CAGIRILANLAR", "CAGIRANLAR", "GERI_CAGRI_VERIR", "GERI_CAGRI_OLUR",
                                 "DIZGILER", "SABITLER")}
    for p, adresler in (("htop", ["100000a00", "100000b00"]), ("tmux", ["100000c00"])):
        satirlar = [json.dumps({"program": p, "adres": a, "kod": "return 0;", "kanit": kanit, "kirpildi": False,
                                "a0": "eski_ad" if a.endswith("a00") else None, "a1": "tarif_adi", "a1_kaynak": "tarif",
                                "sizinti_kod_sayisi": 1 if (sizinti and a == "100000b00") else 0,
                                "sizinti_kanit_sayisi": 0}) for a in adresler]
        (kok / "istemler" / f"{p}.jsonl").write_text("\n".join(satirlar) + "\n")
    return kok


def test_kos_kaldigi_yerden_devam_eder(tmp_path):
    kok = _kok(tmp_path)
    istemci = _SahteIstemci()
    bellek = lambda: {"bellek_gb": 16.0}
    ozet = lp.kos(kok, "qwen38", "ana", ("B", "C"), 1, False, istemci, bellek_olc=bellek)
    assert ozet["yapilan"] == 6 and istemci.cagri == 6
    ozet2 = lp.kos(kok, "qwen38", "ana", ("B", "C"), 1, False, istemci, bellek_olc=bellek)
    assert ozet2 == {"yapilan": 0, "atlanan": 6, "en_yuksek_bellek_gb": 0.0, "sure_sn": 0.0}
    assert istemci.cagri == 6
    ham = json.loads(lp.ham_yolu(kok, "qwen38", "ana", "B", 1, "htop", "100000a00").read_text())
    assert ham["tamam"] and ham["ayristirma"]["durum"] == "gecerli" and ham["guven_ort_logprob"] == -0.5
    assert len((kok / "ilerleme.jsonl").read_text().splitlines()) == 6


def test_kos_bellek_esiginde_durur(tmp_path):
    kok = _kok(tmp_path)
    istemci = _SahteIstemci()
    with pytest.raises(lp.PilotHatasi):
        lp.kos(kok, "qwen38", "ana", ("B",), 1, False, istemci, bellek_olc=lambda: {"bellek_gb": 25.0})
    assert istemci.cagri == 1


def test_kos_sizintili_istemi_calistirmaz(tmp_path):
    kok = _kok(tmp_path, sizinti=True)
    istemci = _SahteIstemci()
    with pytest.raises(lp.PilotHatasi):
        lp.kos(kok, "qwen38", "ana", ("B",), 1, False, istemci, bellek_olc=lambda: {"bellek_gb": 1.0})
    assert istemci.cagri == 1  # ilk öğe çalıştı, sızıntılı ikinci öğede durdu


# --------------------------------------------------------------------------------------------
# (h) aday listesi ve belirlenimcilik


def test_aday_listesi_alanlari_ve_gercek_ad_yok(tmp_path):
    kok = _kok(tmp_path)
    lp.kos(kok, "qwen38", "ana", ("B", "C-Ç"), 1, False, _SahteIstemci(), bellek_olc=lambda: {"bellek_gb": 1.0})
    satirlar = lp.aday_listesi(kok)
    kosullar = {s["kosul"] for s in satirlar}
    assert kosullar == {"A0", "A1", "B", "C-Ç"}
    for s in satirlar:
        assert {"id", "kosul", "aday", "cekimser"} <= set(s)
        assert "gt" not in s
    a0 = {s["id"]: s for s in satirlar if s["kosul"] == "A0"}
    assert a0["htop-100000a00"]["aday"] == "eski_ad" and a0["htop-100000b00"]["durum"] == "isimsiz"
    assert all(s["aday"] == "read_cfg" for s in satirlar if s["kosul"] == "B")


def test_belirlenimcilik_sayimi(tmp_path):
    kok = _kok(tmp_path)
    lp.kos(kok, "qwen38", "ana", ("B",), 1, False, _SahteIstemci(), bellek_olc=lambda: {"bellek_gb": 1.0})
    lp.kos(kok, "qwen38", "ana", ("B",), 2, True, _SahteIstemci(), bellek_olc=lambda: {"bellek_gb": 1.0})
    yol = lp.ham_yolu(kok, "qwen38", "ana", "B", 2, "tmux", "100000c00")
    d = json.loads(yol.read_text())
    d["icerik_sha256"] = "farkli"
    yol.write_text(json.dumps(d))
    b = lp.belirlenimcilik(kok, "qwen38", "ana", ("B",))
    assert b["kosullar"]["B"]["cift"] == 3 and b["kosullar"]["B"]["ayni_ham"] == 2
    assert b["kosullar"]["B"]["farkli_idler"] == ["tmux-100000c00"]


# --------------------------------------------------------------------------------------------
# (i) arka plan pilotu: adımlar, kaldığı yerden devam, hata sonrası boşaltma


class _SahteLMStudio(_SahteIstemci):
    def __init__(self, hata_cagrisi=0):
        super().__init__()
        self.olaylar = []
        self.hata_cagrisi = hata_cagrisi

    def sohbet(self, model_kimlik, mesaj, dusunme):
        if self.hata_cagrisi and self.cagri + 1 == self.hata_cagrisi:
            self.cagri += 1
            raise lp.PilotHatasi("yapay hata")
        return super().sohbet(model_kimlik, mesaj, dusunme)

    def yukle(self, model):
        self.olaylar.append(("yukle", model["kimlik"]))
        return "yüklendi"

    def bosalt(self, model):
        self.olaylar.append(("bosalt", model["kimlik"]))


def test_pilot_adimlari_devam_ve_hata_sonrasi_bosaltma(tmp_path, monkeypatch):
    monkeypatch.setattr(lp, "kunye_uret", lambda *a, **k: {})
    monkeypatch.setattr(lp, "model_bellegi", lambda: {"bellek_gb": 1.0})
    kok = _kok(tmp_path)
    istemci = _SahteLMStudio()
    assert lp.pilot(kok, ["qwen38"], istemci, dusunme=True, dusunme_n=1) == 0
    # ana: 3 öğe x 4 koşul; belirlenimcilik: 3 x 2; düşünme: htop'tan 1 öğe x 2
    assert istemci.cagri == 12 + 6 + 2
    durum = json.loads((kok / "pilot_durumu.json").read_text())
    assert durum["durum"] == "bitti" and set(durum["adimlar"].values()) == {"tamam"}
    ozet = json.loads((kok / "ilerleme_ozeti.json").read_text())
    assert ozet["toplam_cagri"] == 20 and ozet["biten_cagri"] == 20
    yukle = [o for o in istemci.olaylar if o[0] == "yukle"]
    assert len(yukle) == 2  # ana ve belirlenimcilik ayrı süreçte
    assert lp.ham_tamam_mi(lp.ham_yolu(kok, "qwen38", "ana", "C", 2, "tmux", "100000c00"))
    assert not lp.ham_yolu(kok, "qwen38", "dusunme", "B-D", 1, "htop", "100000b00").exists()
    assert lp.pilot(kok, ["qwen38"], istemci, dusunme=True, dusunme_n=1) == 0
    assert istemci.cagri == 20

    kok2 = _kok(tmp_path / "ikinci")
    hatali = _SahteLMStudio(hata_cagrisi=3)
    assert lp.pilot(kok2, ["qwen38"], hatali, dusunme=False) == 3
    assert hatali.olaylar[-1] == ("bosalt", "g6-qwen38")
    durum2 = json.loads((kok2 / "pilot_durumu.json").read_text())
    assert durum2["durum"].startswith("durdu") and durum2["adimlar"]["qwen38:ana"] == "calisiyor"
    devam = _SahteLMStudio()
    assert lp.pilot(kok2, ["qwen38"], devam, dusunme=False) == 0
    assert devam.cagri == (12 - 2) + 6


def test_pilot_beklenmeyen_hatada_da_modeli_bosaltir(tmp_path, monkeypatch):
    # Ör. bozuk JSON yanıtı (ValueError): durum yazılır, model boşaltılır, hata yükselir.
    monkeypatch.setattr(lp, "kunye_uret", lambda *a, **k: {})
    monkeypatch.setattr(lp, "model_bellegi", lambda: {"bellek_gb": 1.0})
    kok = _kok(tmp_path)

    class _Bozuk(_SahteLMStudio):
        def sohbet(self, model_kimlik, mesaj, dusunme):
            if self.cagri == 2:
                self.cagri += 1
                raise ValueError("bozuk JSON yanıtı")
            return super().sohbet(model_kimlik, mesaj, dusunme)

    bozuk = _Bozuk()
    with pytest.raises(ValueError):
        lp.pilot(kok, ["qwen38"], bozuk, dusunme=False)
    assert bozuk.olaylar[-1] == ("bosalt", "g6-qwen38")
    durum = json.loads((kok / "pilot_durumu.json").read_text())
    assert durum["durum"].startswith("durdu (beklenmeyen): ValueError")


# --------------------------------------------------------------------------------------------
# (j) yalın llama-server istemcisi ve bellek üst sınırı


def test_yalin_llama_sunucu_bayraklari_ve_govde(tmp_path):
    sablon = tmp_path / "sablon.jinja"
    sablon.write_text("{{ messages }}")
    s = lp.LlamaSunucu(ikili=tmp_path / "llama-server", sablon=sablon, port=8137)
    komut = s.komut(lp.MODELLER["qwen38"])
    metin = " ".join(komut)
    assert "--cache-ram 0" in metin and "--ctx-checkpoints 0" in metin
    assert "--mmproj" not in metin
    assert f"--ctx-size {lp.BAGLAM}" in metin and "--parallel 1" in metin
    assert f"--chat-template-file {sablon}" in metin
    assert komut[2].endswith("Qwen3.8-27B-Q4_K_M.gguf")
    kapali = s.govde("g6-qwen38", [], dusunme=False)
    acik = s.govde("g6-qwen38", [], dusunme=True)
    assert kapali["chat_template_kwargs"] == {"enable_thinking": False} and kapali["max_tokens"] == lp.MAX_TOKENS
    assert acik["chat_template_kwargs"] == {"reasoning_effort": "low"} and acik["max_tokens"] == lp.MAX_TOKENS_DUSUNME
    assert (acik["temperature"], acik["top_p"], acik["top_k"]) == (1.0, 0.95, 20)  # düşünmede üretici örneklemesi
    assert kapali["temperature"] == 0 and kapali["seed"] == lp.MODEL_TOHUMU and kapali["logprobs"] is True
    lms = lp.LMStudio().govde("g6-qwen38", [], dusunme=False)
    assert lms["reasoning_effort"] == "none" and "reasoning_effort" not in lp.LMStudio().govde("x", [], True)
    gemma = lp.LMStudio().govde("g6-gemma4", [], True)
    assert gemma["temperature"] == 1.0 and gemma["top_k"] == 64 and "reasoning_effort" not in gemma
    assert lp.LMStudio().govde("g6-gemma4", [], False)["temperature"] == 0


def test_kunye_cozme_ayarlari_istemcinin_gonderdigiyle_ayni(tmp_path):
    s = lp.LlamaSunucu(ikili=tmp_path / "llama-server", port=8137)
    c = lp.cozme_ayarlari(s, "g6-qwen38")
    assert c["dusunmesiz"] == {k: v for k, v in s.govde("g6-qwen38", [], False).items() if k != "messages"}
    assert c["dusunme"]["chat_template_kwargs"] == {"reasoning_effort": "low"} and c["dusunme"]["temperature"] == 1.0
    assert "messages" not in c["dusunme"] and "--cache-ram 0" in c["onek_onbellegi"]
    g = lp.cozme_ayarlari(lp.LMStudio(), "g6-gemma4")
    assert g["dusunmesiz"]["reasoning_effort"] == "none" and g["dusunme"]["top_k"] == 64
    assert g["onek_onbellegi"].startswith("LM Studio")


def test_bellek_ust_siniri_llama_icin_toplam_mlx_icin_en_buyuk():
    assert lp.bellek_ust({"surec": "llama-server", "rss_gb": 16.3, "footprint_gb": 10.0, "bellek_gb": 16.3}) == pytest.approx(26.3)
    assert lp.bellek_ust({"surec": "node", "rss_gb": 8.5, "footprint_gb": 16.0, "bellek_gb": 16.0}) == pytest.approx(16.0)
    assert lp.bellek_ust({"bellek_ust_gb": 17.5, "surec": "llama-server", "rss_gb": 1.0}) == pytest.approx(17.5)


def test_kayitli_pid_yalniz_kendi_sunucumuzu_tanir(tmp_path):
    s = lp.LlamaSunucu(ikili=Path("/olmayan/llama-server"), port=8137, pid_yolu=tmp_path / "s.pid")
    assert s._kayitli_pid() is None
    (tmp_path / "s.pid").write_text(str(__import__("os").getpid()))  # bu süreç llama-server değil
    assert s._kayitli_pid() is None


def test_pilot_iki_model_adim_oncelikli_sira(tmp_path, monkeypatch):
    monkeypatch.setattr(lp, "kunye_uret", lambda *a, **k: {})
    monkeypatch.setattr(lp, "model_bellegi", lambda: {"bellek_gb": 1.0})
    kok = _kok(tmp_path)
    q, g = _SahteLMStudio(), _SahteLMStudio()
    assert lp.pilot(kok, ["qwen38", "gemma4"], {"qwen38": q, "gemma4": g}, dusunme=True, dusunme_n=1) == 0
    assert q.cagri == 20 and g.cagri == 20
    sira = [l for l in (kok / "gunluk.log").read_text().splitlines() if " tamam: " in l]
    assert [s.split()[1] for s in sira] == ["qwen38:ana", "gemma4:ana", "qwen38:belirlenimcilik",
                                            "gemma4:belirlenimcilik", "qwen38:dusunme", "gemma4:dusunme"]
    assert q.olaylar[-1] == ("bosalt", "g6-qwen38") and g.olaylar[-1] == ("bosalt", "g6-gemma4")


def test_kapilar_json_gecerliligi_cekimserligi_gecerli_sayar(tmp_path):
    kok = _kok(tmp_path)
    ornek = json.loads((kok / "orneklem.json").read_text())
    ornek["kuru"] = {"htop": ["100000a00", "100000b00"], "tmux": ["100000c00"]}
    ornek["sonda"] = {"htop": ["100000a00"], "tmux": []}
    (kok / "orneklem.json").write_text(json.dumps(ornek))

    class _Cekimser(_SahteIstemci):
        def sohbet(self, model_kimlik, mesaj, dusunme):
            yanit, sure, ayar = super().sohbet(model_kimlik, mesaj, dusunme)
            icerik = '{"isim": null, "gerekce": "x", "cekimser": true}'
            yanit["choices"][0]["message"]["content"] = icerik
            yanit["choices"][0]["logprobs"]["content"] = [{"token": icerik, "logprob": -0.1, "bytes": list(icerik.encode())}]
            return yanit, sure, ayar

    for t, ters in ((1, False), (2, True)):
        lp.kos(kok, "qwen38", "kuru", lp.ANA_KOSULLAR, t, ters, _Cekimser(), bellek_olc=lambda: {"bellek_gb": 1.0})
    lp.kos(kok, "qwen38", "sonda", ("B", "C"), 1, False, _SahteIstemci(), bellek_olc=lambda: {"bellek_gb": 1.0})
    k = lp.kapilar(kok, "qwen38")
    assert k["K-1"]["gecti"] and k["K-1"]["kuru_cagri"] == k["K-1"]["beklenen"] == 12
    assert k["K-2"]["gecerli"] == k["K-2"]["toplam"] == 6 and k["K-2"]["gecti"]
    assert k["K-4"]["ayni_ham"] == k["K-4"]["cift"] == 12 and k["K-4"]["gecti"]
    assert k["K-3"] == {"gecti": True, "ret": 0, "toplam": 2, "beklenen": 2}
    assert k["hepsi"]


def test_kapilar_k3_ve_k5_eksik_sonda_ve_bellek_denemesini_gecirmez(tmp_path):
    # Yarıda kalan reddetme sondası K-3'ten, koşulmamış bellek denemesi K-5'ten geçmez.
    kok = _kok(tmp_path)
    ornek = json.loads((kok / "orneklem.json").read_text())
    ornek["sonda"] = {"htop": ["100000a00", "100000b00"], "tmux": []}
    ornek["bellek"] = [["tmux", "100000c00"], ["htop", "100000a00"], ["htop", "100000b00"]]
    (kok / "orneklem.json").write_text(json.dumps(ornek))
    bel = lambda: {"bellek_gb": 1.0}
    lp.kos(kok, "qwen38", "sonda", ("B", "C"), 1, False, _SahteIstemci(), bellek_olc=bel,
           ogeler=[("htop", "100000a00")])
    lp.kos(kok, "qwen38", "bellek", ("C",), 1, False, _SahteIstemci(), bellek_olc=bel)
    k = lp.kapilar(kok, "qwen38")
    assert k["K-3"]["toplam"] == 2 and k["K-3"]["beklenen"] == 4 and not k["K-3"]["gecti"]
    assert k["K-5"]["bellek_denemesi"] == {"C": 3, "C-D": 0} and not k["K-5"]["gecti"]
    lp.kos(kok, "qwen38", "sonda", ("B", "C"), 1, False, _SahteIstemci(), bellek_olc=bel)
    lp.kos(kok, "qwen38", "bellek", ("C-D",), 1, False, _SahteIstemci(), bellek_olc=bel,
           ogeler=lp.kume_ogeleri(kok, "bellek")[: lp.BELLEK_DUSUNME_N])
    k = lp.kapilar(kok, "qwen38")
    assert k["K-3"]["gecti"] and k["K-5"]["gecti"] and k["K-5"]["bellek_denemesi"] == {"C": 3, "C-D": 2}


def test_kapilar_k1_eksik_kuru_kosuyu_gecirmez(tmp_path):
    # Ön kayıt "40 / 40 çağrı tamamlanıyor": yarıda kalan kuru koşu K-1'den geçmez.
    kok = _kok(tmp_path)
    ornek = json.loads((kok / "orneklem.json").read_text())
    ornek["kuru"] = {"htop": ["100000a00", "100000b00"], "tmux": ["100000c00"]}
    (kok / "orneklem.json").write_text(json.dumps(ornek))
    bel = lambda: {"bellek_gb": 1.0}
    lp.kos(kok, "qwen38", "kuru", lp.ANA_KOSULLAR, 1, False, _SahteIstemci(), bellek_olc=bel,
           ogeler=[("htop", "100000a00"), ("htop", "100000b00")])
    k = lp.kapilar(kok, "qwen38")
    assert k["K-1"]["kuru_cagri"] == 8 and k["K-1"]["beklenen"] == 12
    assert not k["K-1"]["gecti"] and not k["hepsi"]
    lp.kos(kok, "qwen38", "kuru", lp.ANA_KOSULLAR, 1, False, _SahteIstemci(), bellek_olc=bel)
    assert lp.kapilar(kok, "qwen38")["K-1"]["gecti"]
