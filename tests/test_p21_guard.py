"""P21 / LM-01 — KaradulLM model dışı denetim katmanı (``karadul/lm/guard.py``; tasarım §5.1-5.2).

Kusur (``docs/arge/2026-11-18_genel_tarama/kulvar_LM.md`` LM-01): ajan şemaya uyan her cevabı
``tamam`` ile kabul ediyordu; ``while``, ``main``, ``helper``, ``malloc`` kanıtsız olarak "geçerli"
görünüyordu ve ``kesin`` adlı hedefte de ad isteniyordu. Burada her kural için reddedilen (ya da
çelişki bulunan) ve kabul edilen bir örnek sınanır. Model yok: betikli sahte arka uç + sentetik
çalışma alanı (``tests/test_lm_tools.py``).

Mutasyon koruması: ``scripts/measurement/mutation_specs_p21.json``.
"""
from __future__ import annotations

import json

from karadul.lm import agent as G
from karadul.lm import backend as B
from karadul.lm import guard as GD
from karadul.lm import tools as T
from karadul.lm.audit import AuditLog
from tests.test_lm_tools import A, BIG, CB, D, MANUAL, B as FB, default_ws, fun


def _ajan(tmp_path, cevaplar, **kw):
    gunluk = AuditLog()
    arka = B.FakeBackend([B.FakeReply(content=json.dumps(c, ensure_ascii=False)) for c in cevaplar], audit=gunluk)
    return G.Agent(arka, T.Workspace(default_ws(tmp_path / "ws")), **kw), arka, gunluk


def _cevap(isim, kanit=("r1",), gerekce="Kanıta göre tabloyu ayrıştırır."):
    return {"isim": isim, "gerekce": gerekce, "cekimser": False, "kanit": list(kanit)}


def oner(tmp_path, isim, hedef=A, **kw):
    ajan_kw = {k: kw.pop(k) for k in ("rejected_names", "blind_target") if k in kw}
    ajan, arka, _ = _ajan(tmp_path, [_cevap(isim, **kw)], **ajan_kw)
    return ajan.suggest_name(fun(hedef)), arka


def kodlar(r) -> list[str]:
    return [b["kod"] for b in r.guard["bulgular"]]


# --------------------------------------------------------------------------------------------
# Kulvardaki dört örnek: hepsi ret ya da çelişki


def test_kulvar_ornekleri_artik_kabul_edilmez(tmp_path):
    # ``main``: Karadul başka bir fonksiyona vermiş; sentetik alanda A'nın adı run_main, D'ye main verelim
    beklenen = {"while": ("ret", "invalid_c_keyword"), "helper": ("ret", "yer_tutucu"),
                "malloc": ("ret", "collides_with_existing_function"),
                "parse_header": ("ret", "baska_fonksiyonun_adi")}
    for i, (isim, (hukum, kod)) in enumerate(beklenen.items()):
        r, _ = oner(tmp_path / str(i), isim, kanit=())
        assert r.status == "tamam" and r.verdict == hukum and kod in kodlar(r), (isim, r.guard)
        assert "kanitsiz_oneri" in kodlar(r)                       # kanıt dizisi boş: D8
        assert r.guard["toplu_kabul"] is False


# --------------------------------------------------------------------------------------------
# D1 ad geçerliliği


def test_d1_anahtar_sozcuk_tip_ithal_ve_atanmis_ad(tmp_path):
    for i, (isim, kod) in enumerate((("while", "invalid_c_keyword"), ("uint", "invalid_type_name"),
                                     ("malloc", "collides_with_existing_function"),
                                     ("parse_header", "baska_fonksiyonun_adi"))):
        r, _ = oner(tmp_path / str(i), isim)
        assert r.verdict == "ret" and kod in kodlar(r), isim
    # kabul: yeni, geçerli ad; hedefin kendi bugünkü adı da çakışma değildir
    for i, isim in enumerate(("parse_table", "run_main")):
        r, _ = oner(tmp_path / f"k{i}", isim)
        assert r.verdict == "sinandi_celiski_yok" and not [k for k in kodlar(r) if k != "kuskulu_decompile"], isim


def test_d1_ayrilmis_ve_bicimsiz_ad_dogrudan(tmp_path):
    ws = T.Workspace(default_ws(tmp_path / "ws"))
    kw = dict(target=A, target_tag=None, existing_functions=ws.existing_function_names(),
              own_ghidra_name=f"FUN_{A}", assigned_names=ws.assigned_names(), related=[], empty_content=False,
              use_library=False)
    for isim, kod in (("_Exit_now", "ayrilmis_ad"), ("__init_x", "ayrilmis_ad"), ("9abc", "gecersiz_tanimlayici"),
                      ("bad-name", "gecersiz_tanimlayici")):
        rep = GD.check_proposal(_cevap(isim), [], **kw)
        assert rep.verdict == "ret" and kod in rep.codes(), isim
    assert GD.check_proposal(_cevap("exit_now"), [], **kw).verdict != "ret"


# --------------------------------------------------------------------------------------------
# D2 kesin ve elle ad ezilmez


def test_d2_kesin_ve_elle_adli_hedefte_model_cagrilmaz(tmp_path):
    for i, (hedef, kod) in enumerate(((FB, "kesin_ad_ezilmez"), (MANUAL, "elle_ad_ezilmez"),
                                      (D, "elle_ad_ezilmez"))):
        r, arka = oner(tmp_path / str(i), "parse_table", hedef=hedef)
        assert (r.status, r.verdict, len(arka.calls), r.answer) == ("korunan_ad", "ret", 0, None), hedef
        assert kodlar(r) == [kod] and r.counters.model_calls == 0
    # kabul: doğrulanmamış adlı hedefte model çağrılır
    r, arka = oner(tmp_path / "cb", "install_signal_hook", hedef=CB)
    assert r.status == "tamam" and len(arka.calls) == 1 and r.verdict != "ret"
    # körlük kipinde (ölçüm) model çağrılır ama cevap yine D2 ile ret alır
    r, arka = oner(tmp_path / "kor", "parse_table", hedef=FB, blind_target=True)
    assert r.status == "tamam" and len(arka.calls) == 1 and r.verdict == "ret" and "kesin_ad_ezilmez" in kodlar(r)


# --------------------------------------------------------------------------------------------
# D3 yer tutucu


def test_d3_yer_tutucu(tmp_path):
    for i, isim in enumerate(("helper", "func_2", "handler", "FUN_00001000", "SUB_1234", "helper_func")):
        r, _ = oner(tmp_path / str(i), isim)
        assert r.verdict == "ret" and "yer_tutucu" in kodlar(r), isim
    r, _ = oner(tmp_path / "k", "install_handler_table")        # yer tutucu sözcüğü taşıyan ama ad olan
    assert "yer_tutucu" not in kodlar(r)


# --------------------------------------------------------------------------------------------
# D7 kütüphane adı


def test_d7_kutuphane_adi(tmp_path):
    lib = GD.library_names()
    assert lib is not None and {"malloc", "printf", "strtok", "sqrt", "pthread_create"} <= lib
    assert not {"while", "parse_table", "run_main"} & lib
    r, _ = oner(tmp_path / "1", "strtok")                          # ithal değil, libc adı
    assert r.verdict == "celiski" and "kutuphane_adi" in kodlar(r)
    r, _ = oner(tmp_path / "2", "tokenize_input")
    assert "kutuphane_adi" not in kodlar(r) and "D7" in r.guard["sinanan"]
    # sözlük okunamazsa kural koşmaz ve bu yazılır (uydurma "çelişki yok" değil)
    ws = T.Workspace(default_ws(tmp_path / "ws"))
    rep = GD.check_proposal(_cevap("strtok"), [], target=A, target_tag=None, existing_functions={},
                            own_ghidra_name="", assigned_names={}, related=[], empty_content=False,
                            use_library=False)
    assert "D7" not in rep.tested and "D7" in rep.not_tested and "kutuphane_adi" not in rep.codes()
    assert ws.function_count() > 0


# --------------------------------------------------------------------------------------------
# D8 kanıt atfı


def test_d8_kanitsiz_verilmemis_ve_ilgisiz_kanit(tmp_path):
    r, _ = oner(tmp_path / "1", "parse_table", kanit=())
    assert r.verdict == "celiski" and "kanitsiz_oneri" in kodlar(r)
    r, _ = oner(tmp_path / "2", "parse_table", kanit=("r1", "r2"))
    assert not {"kanitsiz_oneri", "verilmemis_kanit", "ilgisiz_kanit"} & set(kodlar(r))
    rep = GD.check_proposal(_cevap("parse_table", kanit=("r7",)), [], target=A, target_tag=None,
                            existing_functions={}, own_ghidra_name="", assigned_names={}, related=[],
                            empty_content=False, use_library=False)
    assert "verilmemis_kanit" in rep.codes()
    # döngüde ilgisiz fonksiyonun (BIG) koduna dayanan öneri: ilgisiz kanıt
    ajan, arka, _ = _ajan(tmp_path / "k2", [{"kind": "call", "tool": "get_decompiled",
                                             "args": {"addr": fun(BIG), "part": "bas"}},
                                            {"kind": "final", **_cevap("parse_table", kanit=("r3",))}],
                          enabled_modes=("K0", "K2"))
    r = ajan.run_loop(fun(A))
    assert r.status == "tamam" and "ilgisiz_kanit" in kodlar(r)
    ajan, _, _ = _ajan(tmp_path / "k2b", [{"kind": "call", "tool": "get_decompiled",
                                           "args": {"addr": fun(FB), "part": "bas"}},
                                          {"kind": "final", **_cevap("parse_table", kanit=("r3",))}],
                       enabled_modes=("K0", "K2"))
    assert "ilgisiz_kanit" not in kodlar(ajan.run_loop(fun(A)))      # FB, A'nın çağırdığı komşu


# --------------------------------------------------------------------------------------------
# D9 görülmemiş olgu


def test_d9_gorulmemis_olgu(tmp_path):
    for i, (gerekce, kod) in enumerate((("FUN_0000dead çağrısına dayanıyor.", "gorulmemis_adres"),
                                        ('"connection refused" iletisini basıyor.', "gorulmemis_dizgi"),
                                        ("socket() çağırıyor.", "gorulmemis_cagri"))):
        r, _ = oner(tmp_path / str(i), "parse_table", gerekce=gerekce)
        assert r.verdict == "celiski" and kod in kodlar(r), gerekce
    for i, gerekce in enumerate(("FUN_00002000 çağrısına dayanıyor.", '"usage: %s <file>" iletisini basıyor.',
                                 "malloc() çağırıyor.")):
        r, _ = oner(tmp_path / f"k{i}", "parse_table", gerekce=gerekce)
        assert not {"gorulmemis_adres", "gorulmemis_dizgi", "gorulmemis_cagri"} & set(kodlar(r)), gerekce


# --------------------------------------------------------------------------------------------
# D10 reddedilmiş ad, D11 oturum içi çakışma


def test_d10_reddedilmis_ad(tmp_path):
    r, _ = oner(tmp_path / "1", "parse_table", rejected_names={fun(A): ["Parse_Table"]})
    assert r.verdict == "ret" and "reddedilmis_ad" in kodlar(r)
    r, _ = oner(tmp_path / "2", "parse_table", rejected_names={fun(CB): ["parse_table"]})
    assert "reddedilmis_ad" not in kodlar(r)


def test_d11_oturum_ici_cakisma(tmp_path):
    # kimlikler görevden göreve değişir (r1, r3, r5): kimliksiz cevap her görevde şemaya uyar
    ajan, _, _ = _ajan(tmp_path, [_cevap("parse_table", kanit=())] * 3)
    assert "oturumda_baska_fonksiyona_onerildi" not in kodlar(ajan.suggest_name(fun(A)))
    assert "oturumda_baska_fonksiyona_onerildi" not in kodlar(ajan.suggest_name(fun(A)))   # aynı fonksiyon
    r = ajan.suggest_name(fun(CB))
    assert r.verdict == "celiski" and "oturumda_baska_fonksiyona_onerildi" in kodlar(r)


# --------------------------------------------------------------------------------------------
# D12, D14 bayrakları; D0; toplu kabul; denetim kaydı


def test_d12_kuskulu_decompile_bayragi(tmp_path):
    r, _ = oner(tmp_path / "1", "parse_table")                     # A'nın kodunda Ghidra uyarısı var
    assert "kuskulu_decompile" in r.guard["bayraklar"] and r.verdict == "sinandi_celiski_yok"
    r, _ = oner(tmp_path / "2", "install_signal_hook", hedef=CB)
    assert "kuskulu_decompile" not in r.guard["bayraklar"]


def test_d14_yalniz_model_adlarina_yaslanma():
    def zarf(etiketler):
        return {"id": "r1", "tool": "get_evidence", "ok": True,
                "data": {"addr": f"FUN_{A}", "callees": ", ".join(f"FUN_0000200{i} [{t}: ad_{i}]"
                                                                  for i, t in enumerate(etiketler))}}
    kw = dict(target=A, target_tag=None, existing_functions={}, own_ghidra_name="", assigned_names={},
              related=[], empty_content=False, use_library=False)
    assert "yalniz_model_adlari" in GD.check_proposal(_cevap("parse_table"), [zarf(["model", "model"])], **kw).flags
    assert "yalniz_model_adlari" not in GD.check_proposal(_cevap("parse_table"), [zarf(["model", "proven"])],
                                                          **kw).flags


def test_d0_sinanamadi_ve_toplu_kabul(tmp_path):
    r, _ = oner(tmp_path / "1", "install_signal_hook", hedef=CB)  # CB: ithal yok, dizgi yok
    assert r.empty_content and r.verdict == "sinanamadi" and r.guard["toplu_kabul"] is False
    r, _ = oner(tmp_path / "2", "parse_table")
    assert r.verdict == "sinandi_celiski_yok" and r.guard["toplu_kabul"] is True
    assert set(r.guard["sinanmayan"]) == {"D4", "D5"}             # kodlanmayan kurallar her raporda yazılı
    for kural in ("D0", "D1", "D2", "D3", "D6", "D7", "D8", "D9", "D10", "D11", "D12", "D13", "D14"):
        assert kural in r.guard["sinanan"], kural


def test_cekimser_cevap_denetlenir_ad_kurallari_kosmaz(tmp_path):
    ajan, _, _ = _ajan(tmp_path, [{"isim": None, "gerekce": "Kanıt yetersiz.", "cekimser": True, "kanit": []}])
    r = ajan.suggest_name(fun(A))
    assert r.status == "tamam" and r.verdict == "sinandi_celiski_yok"
    assert "D1" not in r.guard["sinanan"] and "kanitsiz_oneri" not in kodlar(r)


def test_denetim_kaydi_ad_ve_ikili_metni_tasimaz(tmp_path):
    ajan, _, gunluk = _ajan(tmp_path, [_cevap("parse_table", kanit=(), gerekce='"usage: %s" basıyor.')])
    r = ajan.suggest_name(fun(A))
    kayit = [k for k in gunluk.records if k["olay"] == "denetim"]
    assert len(kayit) == 1 and kayit[0]["hukum"] == r.verdict == "celiski" and kayit[0]["gorev"] == r.task_id
    assert {"kural": "D8", "kod": "kanitsiz_oneri", "etki": "celiski", "dayanak": None} in kayit[0]["bulgular"]
    gorev = [k for k in gunluk.records if k["olay"] == "gorev"][0]
    assert gorev["hukum"] == "celiski"
    metin = json.dumps(gunluk.records, ensure_ascii=False)
    for ham in ("parse_table", "usage: %s", "basıyor"):
        assert ham not in metin, ham
