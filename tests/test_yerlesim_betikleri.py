"""Yerleşim ölçüm betiklerinin testleri (2026-11-12).

  * ``yerlesim_dolgu_say.py``: GT'siz dolgu sayımı (kutular, ana kod bloğu, sinyal, çalışma alanı keşfi).
  * ``yerlesim_urun_olc.py``: geliştirme setinde yeniden üretim (bölme eşitliği, duyarlılık dilimi, ağaç
    özeti, kurucunun girdisinin bulunması).

Veriler sentetiktir. Mutasyon koruması: ``scripts/measurement/mutation_specs_yerlesim.json``.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

from karadul.config import Config
from karadul.reconstruction.c_project_builder import CProjectBuilder, MemoryBlock

_KOK = Path(__file__).resolve().parents[1]


def _yukle(ad: str):
    spec = importlib.util.spec_from_file_location(
        f"{ad}_under_test", _KOK / "scripts" / "measurement" / f"{ad}.py")
    modul = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = modul
    spec.loader.exec_module(modul)
    return modul


ds = _yukle("yerlesim_dolgu_say")
uo = _yukle("yerlesim_urun_olc")

ESIK = Config().binary_reconstruction.address_placement_padding_threshold
HIZA = Config().binary_reconstruction.address_placement_alignment
ZAMAN = "20261110_000000"      # sentetik çalışma alanı dizini; tests/test_urun_olc.py ile aynı değer
METIN = MemoryBlock(0x1000, 0x1FFF, ".text", True)
PLT = MemoryBlock(0x0800, 0x0FFF, ".plt", True)
DIS = MemoryBlock(0x9000, 0x9FFF, "EXTERNAL", False)


def _blok_kaydi(b: MemoryBlock) -> dict:
    return {"name": b.name, "start": f"{b.start:08x}", "end": f"{b.end:08x}",
            "permissions": "r-x" if b.executable else "rw-"}


def _static_yaz(static: Path, fonksiyonlar: list[tuple[int, int, bool]], bloklar=(PLT, METIN, DIS)) -> None:
    """``fonksiyonlar``: (adres, boyut, thunk mı)."""
    static.mkdir(parents=True, exist_ok=True)
    (static / "ghidra_functions.json").write_text(json.dumps({"functions": [
        {"name": f"FUN_{a:08x}", "address": f"{a:08x}", "size": b, "is_thunk": t}
        for a, b, t in fonksiyonlar]}))
    (static / "ghidra_combined_results.json").write_text(json.dumps({"program_info": {
        "executable_format": "sentetik", "language": "yok",
        "memory_blocks": [_blok_kaydi(b) for b in bloklar]}}))


# --------------------------------------------------------------------------------------------
# yerlesim_dolgu_say


def test_ayarlar_merkezi_yapilandirmadan():
    assert ds.ayarlar() == (ESIK, HIZA)


def test_kutu_sinirlari():
    adlar = ds.kutu_adlari(ESIK, HIZA)
    assert adlar == ("negatif", "0", f"1-{ESIK - 1}", f"{ESIK}-{HIZA - 1}", f">={HIZA}")
    beklenen = {-1: 0, 0: 1, 1: 2, ESIK - 1: 2, ESIK: 3, HIZA - 1: 3, HIZA: 4, HIZA + 100: 4}
    assert {d: adlar.index(ds.kutu(d, ESIK, HIZA)) for d in beklenen} == beklenen


def test_calisma_alanlari_anahtar_ve_en_yeni_kosu(tmp_path):
    for goreli in (f"debian/prog/ikili/ws/workspaces/ikili/{ZAMAN}/static",
                   "debian/prog/ikili/ws/workspaces/ikili/20270101_000000/static",
                   f"mac/tek/ws/workspaces/tek/{ZAMAN}/static",
                   f"mac/tek/ws/workspaces/tek/{ZAMAN}/deobfuscated",      # static değil: sayılmaz
                   "baska/static"):                                         # çalışma alanı değil
        (tmp_path / goreli).mkdir(parents=True)
        (tmp_path / goreli / "ghidra_functions.json").write_text("{}")
    bulunan = ds.calisma_alanlari(tmp_path)
    assert sorted(bulunan) == ["debian/prog/ikili", "mac/tek"]
    assert bulunan["debian/prog/ikili"].parent.name == "20270101_000000"


def test_ikili_sayimi_kutular_ana_blok_ve_sinyal(tmp_path):
    """PLT'de `.text`'ten çok fonksiyon olsa da ana kod bloğu `.text`'tir (thunk olmayan sayılır)."""
    fonksiyonlar = [(0x0800 + 0x10 * i, 0x10, True) for i in range(6)]          # PLT: 6 bitişik thunk
    fonksiyonlar += [
        (0x1000, 0x20, False),
        (0x1020, 0x1C, False),                 # dolgu 0
        (0x1040, 0x20, False),                 # dolgu 4
        (0x1060 + ESIK, 0x20, False),          # dolgu = eşik (sinyal bandı)
        (0x1080 + ESIK + HIZA, 0x20, True),    # dolgu = hizalama (bant dışı); metin içi thunk
        (0x1090 + ESIK + HIZA, 0x10, False),   # negatif dolgu (örtüşme)
        (0x9000, 1, True), (0x9400, 1, True),  # EXTERNAL: dolgu ölçülmez
    ]
    _static_yaz(tmp_path / "static", fonksiyonlar)
    s = ds.ikili_sayimi(tmp_path / "static", ESIK, HIZA)
    adlar = ds.kutu_adlari(ESIK, HIZA)
    assert (s["fonksiyon"], s["thunk"], s["blok_bilgisi"]) == (14, 9, True)
    assert (s["ana_kod_blogu"], s["ana_kod_fonksiyon"]) == (".text", 6)
    assert s["blok_fonksiyon"] == {".plt": 6, ".text": 6, "EXTERNAL": 2}
    assert s["ana_kutular"] == dict(zip(adlar, (1, 1, 1, 1, 1)))
    assert s["kutular"] == dict(zip(adlar, (1, 6, 1, 1, 1)))                   # + PLT'nin 5 sıfır dolgusu
    assert s["olculen_cift"] == 10
    assert (s["sinyal_dolgu"], s["sinyal_var"]) == (1, True)
    assert (s["dolgu_siniri"], s["blok_siniri"], s["dilim"]) == (2, 2, 5)
    assert s["thunk_yeri"] == {"ana_kod": 1, "yurutulebilir_diger": 6, "yurutulemez": 2}
    assert s["sinyal_yogunlugu"] == round(1 / 10, ds.ONDALIK)
    # pozitif dolgular: 4 (başlangıç 0x1040: hizalı), eşik (0x1070: hizasız), hizalama (hizasız)
    assert (s["pozitif_dolgu"], s["pozitif_dolgu_sonrasi_hizali"]) == (3, 1)
    assert s["ana_dolgu_degerleri"] == {"-16": 1, "0": 1, "4": 1, str(ESIK): 1, str(HIZA): 1}


def test_yasak_kalanli_baslangic_sayilir(tmp_path):
    """Kalanı (hizalama − eşik)'ten büyük başlangıç: varsayılan rejimde derleyici orada durmazdı."""
    fonksiyonlar = [(0x1000 + k, 4, False) for k in (0, 4, HIZA - ESIK, HIZA - ESIK + 4, HIZA - 4)]
    _static_yaz(tmp_path / "static", fonksiyonlar, bloklar=(METIN,))
    s = ds.ikili_sayimi(tmp_path / "static", ESIK, HIZA)
    assert s["yasak_kalanli_baslangic"] == 2
    assert s["ana_baslangic_kalani"] == {"0": 1, "4": 1, str(HIZA - ESIK): 1, str(HIZA - ESIK + 4): 1,
                                         str(HIZA - 4): 1}


def test_sinyalsiz_ikili_ve_grup_ozeti(tmp_path):
    sinyalli = tmp_path / "a" / "static"
    sinyalsiz = tmp_path / "b" / "static"
    _static_yaz(sinyalli, [(0x1000, 0x20, False), (0x1020 + ESIK, 0x20, False)], bloklar=(METIN,))
    _static_yaz(sinyalsiz, [(0x1000, 0x20, False), (0x1020, 0x20, False)], bloklar=(METIN,))
    ikililer = {"kok/grup/a": ds.ikili_sayimi(sinyalli, ESIK, HIZA),
                "kok/grup/b": ds.ikili_sayimi(sinyalsiz, ESIK, HIZA)}
    assert [i["sinyal_var"] for i in ikililer.values()] == [True, False]
    ozet = ds.grup_ozeti(ikililer, ESIK, HIZA)
    assert list(ozet) == ["kok/grup"]
    g = ozet["kok/grup"]
    assert (g["ikili"], g["fonksiyon"], g["olculen_cift"]) == (2, 4, 2)
    assert g["sinyalsiz_ikili"] == ["kok/grup/b"]
    assert g["kutular"][f"{ESIK}-{HIZA - 1}"] == 1 and g["kutular"]["0"] == 1
    assert g["sinyal_yogunlugu"] == {"en_az": 0.0, "ortanca": 0.5, "en_cok": 1.0}


def test_say_ve_markdown_ad_icermez(tmp_path):
    static = tmp_path / "kok" / "debian" / "p" / "i" / "ws" / "workspaces" / "i" / ZAMAN / "static"
    _static_yaz(static, [(0x1000, 0x20, False), (0x1020 + ESIK, 0x20, False)], bloklar=(METIN,))
    sonuc = ds.say({"etiket": tmp_path / "kok"})
    assert list(sonuc["ikililer"]) == ["etiket/debian/p/i"]
    assert (sonuc["esik"], sonuc["hizalama"]) == (ESIK, HIZA)
    metin = ds.markdown(sonuc) + json.dumps(sonuc)
    assert "FUN_" not in metin
    assert "| `etiket/debian/p/i` | 2 | 1 | 0 | 0 | 0 | 1 | 0 | var | 2 |" in ds.markdown(sonuc)


# --------------------------------------------------------------------------------------------
# yerlesim_urun_olc


def test_ayni_bolme_etiket_adindan_bagimsiz():
    assert uo.ayni_bolme(["a", "a", "b"], [7, 7, 9]) is True
    assert uo.ayni_bolme(["a", "a", "b"], [7, 9, 9]) is False
    assert uo.ayni_bolme(["a", "a", "b"], [7, 7, 7]) is False      # kaba bölme aynı değil
    assert uo.ayni_bolme(["a", "a", "a"], [7, 7, 9]) is False      # ince bölme aynı değil


def test_bant_dilimi_yalniz_bantta_ve_blok_degisiminde_keser():
    boyut = {0x0FF0: 0x10,                 # PLT
             0x1000: 0x20,                 # blok değişti: keser
             0x1020 + ESIK: 0x20,          # dolgu = eşik: keser
             0x1040 + ESIK + HIZA: 0x20,   # dolgu = hizalama: bant dışı, KESMEZ
             0x1060 + 2 * HIZA + ESIK - 1: 0x20}   # dolgu = hizalama − 1: keser
    adresler = sorted(boyut)
    dilim = uo.bant_dilimi(boyut, [PLT, METIN], ESIK, HIZA)
    assert [dilim[a] for a in adresler] == [0, 1, 2, 2, 3]


def test_agac_ozeti_kok_yolunu_cevirir_ve_algoritma_raporunu_atlar(tmp_path):
    for kok in ("a", "b"):
        (tmp_path / kok / "analysis").mkdir(parents=True)
        (tmp_path / kok / "compile_commands.json").write_text(f'{{"directory": "{tmp_path / kok}"}}')
        (tmp_path / kok / "README.md").write_text("ayni")
        (tmp_path / kok / "analysis" / "algorithms.md").write_text(f"farkli {kok}")
    a = uo.agac_ozeti(tmp_path / "a")
    b_ham = uo.agac_ozeti(tmp_path / "b")
    b_cevrili = uo.agac_ozeti(tmp_path / "b", (str(tmp_path / "b"), str(tmp_path / "a")))
    assert sorted(a) == ["README.md", "compile_commands.json"]
    assert a != b_ham and a == b_cevrili


def _sakli_alan(kok: Path, dolgu: int) -> Path:
    """Saklı koşu gibi: ``reconstructed/annotated`` girdisi ve bayrak kapalı kurulmuş proje ağacı."""
    static = kok / "static"
    _static_yaz(static, [(0x1000, 0x20, False), (0x1020 + dolgu, 0x20, False)], bloklar=(METIN,))
    for aday, ek in (("commented", "eski"), ("annotated", "son")):
        d = kok / "reconstructed" / aday
        d.mkdir(parents=True)
        for ad, adres in (("f1", 0x1000), ("f2", 0x1020 + dolgu)):
            (d / f"{ad}.c").write_text(
                f"// Function: {ad}\n// Address:  {adres:08x}\n\nvoid {ad}(void)\n{{\n"
                + f"  {ek}();\n" * 12 + "}\n")
    CProjectBuilder(None).build(kok / "reconstructed" / "annotated", kok / "reconstructed" / "project",
                                workspace=uo.SakliAlan(kok))
    return kok


def test_girdiyi_bul_sakli_agaci_veren_adayi_secer(tmp_path):
    kosu = _sakli_alan(tmp_path / "kosu", ESIK)
    girdi = uo.girdiyi_bul(kosu, tmp_path / "gecici")
    assert (girdi["kaynak"], girdi["ayni"], girdi["denenen"]) == ("annotated", True, ["annotated"])
    # saklı ağaç değişirse hiçbir aday tutmaz
    (kosu / "reconstructed" / "project" / "README.md").write_text("degisti")
    girdi = uo.girdiyi_bul(kosu, tmp_path / "gecici2")
    assert (girdi["kaynak"], girdi["ayni"]) == (None, False)
    assert girdi["denenen"] == ["annotated", "commented"]


def test_kur_bayragi_yapilandirmadan_acar(tmp_path):
    kosu = _sakli_alan(tmp_path / "kosu", ESIK)
    kapali = uo.kur(kosu / "reconstructed" / "annotated", kosu, tmp_path / "kapali", acik=False)
    acik = uo.kur(kosu / "reconstructed" / "annotated", kosu, tmp_path / "acik", acik=True)
    assert (kapali.placement_strategy, acik.placement_strategy) == ("api_community", "address_padding")
    assert uo.ayarli_config(False).binary_reconstruction.enable_address_placement is False


def test_algoritma_sonucu_yalniz_sakli_rapor_varsa(tmp_path):
    kosu = _sakli_alan(tmp_path / "kosu", ESIK)
    assert uo.algoritma_sonucu(kosu) is None
    (kosu / "reconstructed" / "algorithms.json").write_text(json.dumps({"algorithms": [
        {"name": "x", "category": "c", "confidence": 0.9, "function": "f1", "evidence": ["e"]}]}))
    assert uo.algoritma_sonucu(kosu) is None                       # saklı ağaçta algorithms.md yok
    (kosu / "reconstructed" / "project" / "analysis" / "algorithms.md").write_text("# x")
    sonuc = uo.algoritma_sonucu(kosu)
    assert [(a.name, a.function_name, a.confidence) for a in sonuc.algorithms] == [("x", "f1", 0.9)]
