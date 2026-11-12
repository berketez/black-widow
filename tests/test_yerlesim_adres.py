"""Adres sırasına dayalı yerleşim testleri (2026-11-12; bayrak arkasında, öntanımlı kapalı).

Kilitlenen davranışlar:

  * Bayrak kapalıyken (yapılandırma yok, öntanımlı yapılandırma, bayrak açıkça False) kurucunun
    çıktısı aynıdır; yerleşim raporu yazılmaz.
  * Bayrak açıkken fonksiyonlar adres sırasında bitişik dilimlere ayrılır: sınır, bellek bloğu
    değiştiğinde ya da yürütülebilir blokta dolgu eşiği bulduğunda konur (eşik dahil).
  * Dolgu sinyali ([eşik, hizalama) bandında dolgu) yoksa eski yerleşime dönülür; karar README'ye,
    `analysis/placement.json`'a, günlüğe ve sonuç nesnesine yazılır.
  * Eşik ve hizalama yalnız `karadul/config.py`'den okunur.
  * "Her fonksiyon çıktıda tam bir kez" değişmezi adres yerleşiminde de tutar.

Adresler ve boyutlar sentetiktir; gerçek ikiliden alınmış veri yoktur.
"""
from __future__ import annotations

import json
import logging
import random
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from karadul.config import Config
from karadul.reconstruction import c_project_builder as cpb
from karadul.reconstruction.c_project_builder import (
    CProjectBuilder,
    MemoryBlock,
    function_gaps,
    parse_memory_blocks,
    slice_by_padding,
)

# Öntanımlı yapılandırmanın sayıları: testler bunları yapılandırmadan okur, yeniden tanımlamaz.
ESIK = Config().binary_reconstruction.address_placement_padding_threshold
HIZA = Config().binary_reconstruction.address_placement_alignment

METIN = MemoryBlock(0x1000, 0x1FFF, ".text", True)
PLT = MemoryBlock(0x0800, 0x0FFF, ".plt", True)
DIS = MemoryBlock(0x9000, 0x9FFF, "EXTERNAL", False)


# ---------------------------------------------------------------------------
# Yardımcılar
# ---------------------------------------------------------------------------

def _kaynak(ad: str, adres: int | None, satir: int = 12) -> str:
    """Ghidra çıktısı biçiminde tek fonksiyonluk kaynak; `adres` None ise başlıkta adres yok."""
    baslik = f"// Function: {ad}\n" + (f"// Address:  {adres:08x}\n" if adres is not None else "")
    return baslik + f"\nvoid {ad}(void)\n{{\n" + f"  adim_{ad}();\n" * satir + "}\n"


class _CalismaAlani:
    def __init__(self, kok: Path) -> None:
        self._kok = kok

    def get_stage_dir(self, ad: str) -> Path:
        return self._kok / ad


def _blok_kaydi(b: MemoryBlock) -> dict:
    return {"name": b.name, "start": f"{b.start:08x}", "end": f"{b.end:08x}",
            "size": b.end - b.start + 1, "permissions": "r-x" if b.executable else "rw-"}


def _alan_yaz(kok: Path, fonksiyonlar: dict[str, tuple[int, int]], bloklar=(METIN,),
              birimsiz: tuple[str, ...] = (), adressiz: tuple[str, ...] = (),
              fonksiyon_listesi: bool = True, blok_listesi: bool = True) -> None:
    """Sentetik çalışma alanı. `fonksiyonlar`: ad -> (adres, boyut).

    `birimsiz` adların kaynak dosyası yazılmaz (Ghidra listesinde var, birimi yok); `adressiz`
    adların kaynak başlığında adres satırı olmaz.
    """
    kaynak = kok / "kaynak"
    kaynak.mkdir(parents=True, exist_ok=True)
    static = kok / "static"
    static.mkdir(parents=True, exist_ok=True)
    for ad, (adres, _boyut) in fonksiyonlar.items():
        if ad in birimsiz:
            continue
        (kaynak / f"{ad}.c").write_text(_kaynak(ad, None if ad in adressiz else adres))
    if fonksiyon_listesi:
        (static / "ghidra_functions.json").write_text(json.dumps({"functions": [
            {"name": ad, "address": f"{adres:08x}", "size": boyut, "is_thunk": False}
            for ad, (adres, boyut) in fonksiyonlar.items()]}))
    if blok_listesi:
        (static / "ghidra_combined_results.json").write_text(json.dumps(
            {"program_info": {"memory_blocks": [_blok_kaydi(b) for b in bloklar]}}))


def _config(acik: bool = True, esik: int | None = None, hiza: int | None = None) -> Config:
    cfg = Config()
    cfg.binary_reconstruction.enable_address_placement = acik
    if esik is not None:
        cfg.binary_reconstruction.address_placement_padding_threshold = esik
    if hiza is not None:
        cfg.binary_reconstruction.address_placement_alignment = hiza
    return cfg


def _kur(kok: Path, config, cikti: str = "proje"):
    sonuc = CProjectBuilder(config).build(
        kok / "kaynak", kok / cikti, workspace=_CalismaAlani(kok))
    return sonuc, kok / cikti


def _agac(proje: Path) -> dict[str, bytes]:
    """Göreli yol -> içerik. `compile_commands.json`'daki mutlak kök yolu silinir."""
    out = {}
    for yol in sorted(p for p in proje.rglob("*") if p.is_file()):
        out[yol.relative_to(proje).as_posix()] = yol.read_bytes().replace(str(proje).encode(), b"<kok>")
    return out


def _yerler(proje: Path) -> dict[str, str]:
    """Fonksiyon adı -> `src` altındaki dizini (kökteki dosya: `.`)."""
    out: dict[str, str] = {}
    for yol in sorted((proje / "src").rglob("*.c")):
        goreli = yol.relative_to(proje / "src")
        dizin = goreli.parts[0] if len(goreli.parts) > 1 else "."
        for satir in yol.read_text().splitlines():
            if satir.startswith("// Function: "):
                ad = satir.split(": ", 1)[1]
                assert ad not in out, f"{ad} iki yerde"
                out[ad] = dizin
    return out


def _rapor(proje: Path) -> dict:
    return json.loads((proje / "analysis" / "placement.json").read_text())


# İki nesne dosyası gibi: f1, f2 bitişik; f3'ün önünde tam eşik kadar dolgu; f4 ondan sonra bitişik.
_IKI_DILIM = {
    "f1": (0x1000, 0x20), "f2": (0x1020, 0x30), "f3": (0x1050 + ESIK, 0x20),
    "f4": (0x1070 + ESIK, 0x10),
}


# ---------------------------------------------------------------------------
# 1. Bellek blokları
# ---------------------------------------------------------------------------

def test_bellek_bloklari_ayrisir_ve_siralanir():
    ham = [
        {"name": ".text", "start": "00001000", "end": "00001fff", "permissions": "r-x"},
        {"name": "EXTERNAL", "start": "00009000", "end": "00009fff", "permissions": "rw-"},
        {"name": ".plt", "start": "00000800", "end": "00000fff", "permissions": "r-x"},
        {"name": ".shstrtab", "start": ".shstrtab::00000000", "end": ".shstrtab::0000010f",
         "permissions": "---"},                                    # yüklenmeyen blok: atlanır
        {"name": "ters", "start": "00002000", "end": "00001000", "permissions": "r-x"},
        {"name": "eksik", "start": "00003000"},
        "bozuk",
    ]
    assert parse_memory_blocks(ham) == [PLT, METIN, DIS]
    assert parse_memory_blocks(None) == []
    assert parse_memory_blocks({"name": ".text"}) == []


def test_izin_dizgisi_olmayan_blok_yurutulemez_sayilir():
    blok, = parse_memory_blocks([{"name": "b", "start": "10", "end": "1f", "permissions": None}])
    assert blok.executable is False


def test_blok_uclari_dahildir():
    """Bloğun ilk ve son adresi bloğun içindedir; bir bayt dışı değildir."""
    bosluklar = function_gaps(
        {0x0FFF: 1, 0x1000: 4, 0x1FFF: 1, 0x2000: 4}, [PLT, METIN])
    assert [g.block for g in bosluklar] == [0, 1, 1, None]


# ---------------------------------------------------------------------------
# 2. Dolgu ve dilimleme (saf işlevler)
# ---------------------------------------------------------------------------

def test_dolgu_onceki_bitisten_sonraki_basa():
    bosluklar = function_gaps({0x1000: 0x20, 0x1020: 0x1C, 0x1040: 0x10, 0x1048: 8}, [METIN])
    assert [g.gap for g in bosluklar] == [None, 0, 4, -8]      # örtüşen gövde: negatif
    assert [g.block_changed for g in bosluklar] == [False] * 4


def test_blok_degisince_dolgu_olculmez():
    bosluklar = function_gaps({0x0FF0: 0x10, 0x1000: 0x10}, [PLT, METIN])
    assert [(g.gap, g.block_changed) for g in bosluklar] == [(None, False), (None, True)]


def test_yurutulemez_blokta_dolgu_olculmez():
    bosluklar = function_gaps({0x9000: 1, 0x9100: 1}, [DIS])
    assert [g.gap for g in bosluklar] == [None, None]


def test_blok_bilgisi_yoksa_tek_yurutulebilir_blok():
    bosluklar = function_gaps({0x0FF0: 0x10, 0x1000: 0x10, 0x9000: 1}, [])
    assert [g.block for g in bosluklar] == [None, None, None]
    assert [g.gap for g in bosluklar] == [None, 0, 0x9000 - 0x1010]


def test_esik_dahil_sinirdir():
    """Dolgu tam eşik kadarsa sınır konur; bir bayt azında konmaz."""
    tam = slice_by_padding({0x1000: 0x20, 0x1020 + ESIK: 0x20}, [METIN], ESIK, HIZA)
    az = slice_by_padding({0x1000: 0x20, 0x1020 + ESIK - 1: 0x20}, [METIN], ESIK, HIZA)
    assert (len(tam.slices), tam.padding_cuts, tam.signal_gaps) == (2, 1, 1)
    assert (len(az.slices), az.padding_cuts, az.signal_gaps) == (1, 0, 0)
    assert (tam.measured_gaps, az.measured_gaps) == (1, 1)


def test_hizalama_ve_ustu_sinirdir_ama_sinyal_degildir():
    """Dolgu hizalamayı bulursa yine sınır konur, ama sinyal bandı dışındadır (üst uç dışında)."""
    alt = slice_by_padding({0x1000: 0x20, 0x1020 + HIZA - 1: 0x20}, [METIN], ESIK, HIZA)
    ust = slice_by_padding({0x1000: 0x20, 0x1020 + HIZA: 0x20}, [METIN], ESIK, HIZA)
    assert (alt.padding_cuts, alt.signal_gaps, alt.has_padding_signal) == (1, 1, True)
    assert (ust.padding_cuts, ust.signal_gaps, ust.has_padding_signal) == (1, 0, False)


def test_blok_siniri_dolgusuz_da_keser_ve_ayri_sayilir():
    duzen = slice_by_padding({0x0FF0: 0x10, 0x1000: 0x10, 0x1010: 0x10}, [PLT, METIN], ESIK, HIZA)
    assert (len(duzen.slices), duzen.block_cuts, duzen.padding_cuts) == (2, 1, 0)
    assert duzen.measured_gaps == 1                        # yalnız aynı bloktaki çift ölçülür
    assert [duzen.slice_of[a] for a in (0x0FF0, 0x1000, 0x1010)] == [0, 1, 1]
    assert [s.block for s in duzen.slices] == [0, 1]


def test_yurutulemez_blok_tek_dilimdir():
    """`EXTERNAL` yer tutucuları arasındaki aralık dolgu değildir: blok bölünmez."""
    duzen = slice_by_padding({0x1000: 0x10, 0x9000: 1, 0x9100: 1, 0x9800: 1}, [METIN, DIS], ESIK, HIZA)
    assert (len(duzen.slices), duzen.block_cuts, duzen.padding_cuts) == (2, 1, 0)
    assert duzen.slices[1].functions == 3


def test_dilim_ucu_ve_fonksiyon_sayisi():
    duzen = slice_by_padding({a: b for a, b in _IKI_DILIM.values()}, [METIN], ESIK, HIZA)
    ilk, ikinci = duzen.slices
    assert (ilk.start, ilk.end, ilk.functions) == (0x1000, 0x1050, 2)
    assert (ikinci.start, ikinci.end, ikinci.functions) == (0x1050 + ESIK, 0x1080 + ESIK, 2)
    assert duzen.slice_of == {0x1000: 0, 0x1020: 0, 0x1050 + ESIK: 1, 0x1070 + ESIK: 1}


def test_negatif_dolgu_sinir_degildir():
    duzen = slice_by_padding({0x1000: 0x40, 0x1020: 0x10}, [METIN], ESIK, HIZA)
    assert (len(duzen.slices), duzen.padding_cuts, duzen.measured_gaps) == (1, 0, 1)


def test_dilimleme_girdi_sirasindan_bagimsiz():
    ogeler = [(0x1000 + 0x40 * i, 0x40 - (ESIK if i % 3 == 0 else 0)) for i in range(30)]
    beklenen = slice_by_padding(dict(ogeler), [METIN], ESIK, HIZA)
    rastgele = random.Random(7)
    for _ in range(5):
        rastgele.shuffle(ogeler)
        assert slice_by_padding(dict(ogeler), [METIN], ESIK, HIZA) == beklenen
    # dolgu, boyutu kısaltılan her fonksiyondan (i = 0, 3, …, 27) SONRA gelir: 10 sınır, 11 dilim
    assert (beklenen.padding_cuts, len(beklenen.slices)) == (10, 11)


def test_bos_fonksiyon_listesi():
    duzen = slice_by_padding({}, [METIN], ESIK, HIZA)
    assert (duzen.slices, duzen.slice_of, duzen.has_padding_signal) == ([], {}, False)


# ---------------------------------------------------------------------------
# 3. Yapılandırma: bayrak ve sayılar tek yerde
# ---------------------------------------------------------------------------

def test_ontanimli_bayrak_kapali_ve_yaml_ile_acilir():
    br = Config().binary_reconstruction
    assert br.enable_address_placement is False
    assert 0 < br.address_placement_padding_threshold < br.address_placement_alignment
    acik = Config._from_dict({"binary_reconstruction": {
        "enable_address_placement": True, "address_placement_padding_threshold": 12}})
    assert acik.binary_reconstruction.enable_address_placement is True
    assert acik.binary_reconstruction.address_placement_padding_threshold == 12
    assert acik.binary_reconstruction.address_placement_alignment == br.address_placement_alignment


def test_dondurulmus_sayilar():
    """Eşik 16, hizalama 32: geliştirme setinde seçildi ve doğrulama ölçümü için DONDURULDU
    (docs/arge/2026-11-12_yerlesim/onkayit_taslak.md). Değişirse bu test bilerek düşer."""
    assert (ESIK, HIZA) == (16, 32)


@pytest.mark.parametrize("config", [None, Config(), _config(acik=False), MagicMock()],
                         ids=["yok", "ontanimli", "kapali", "sahte_nesne"])
def test_bayrak_kapaliyken_plan_kurulmaz(config):
    """Sahte yapılandırma nesnesinin (MagicMock) "doğru gibi" alanı bayrağı AÇMAZ."""
    assert CProjectBuilder(config)._address_placement_settings() is None


def test_ayarlar_yapilandirmadan_okunur():
    assert CProjectBuilder(_config())._address_placement_settings() == (ESIK, HIZA)
    assert CProjectBuilder(_config(esik=8, hiza=64))._address_placement_settings() == (8, 64)


# ---------------------------------------------------------------------------
# 4. Kurucu: bayrak kapalı
# ---------------------------------------------------------------------------

def test_bayrak_kapaliyken_cikti_ayni_ve_rapor_yok(tmp_path):
    _alan_yaz(tmp_path, _IKI_DILIM)
    agaclar = []
    for i, config in enumerate([None, Config(), _config(acik=False)]):
        sonuc, proje = _kur(tmp_path, config, cikti=f"proje{i}")
        assert sonuc.success is True
        assert (sonuc.placement_strategy, sonuc.placement_fallback_reason) == (
            cpb.PLACEMENT_API_COMMUNITY, "")
        assert not (proje / "analysis" / "placement.json").exists()
        assert "Placement" not in (proje / "README.md").read_text()
        assert not list((proje / "src").glob("subsystem_addr_*"))
        agaclar.append(_agac(proje))
    assert agaclar[0] == agaclar[1] == agaclar[2]


# ---------------------------------------------------------------------------
# 5. Kurucu: bayrak açık, sinyal var
# ---------------------------------------------------------------------------

def test_adres_yerlesimi_dilimleri_dizine_yazar(tmp_path, caplog):
    _alan_yaz(tmp_path, _IKI_DILIM)
    with caplog.at_level(logging.INFO, logger=cpb.logger.name):
        sonuc, proje = _kur(tmp_path, _config())
    ikinci = f"subsystem_addr_{0x1050 + ESIK:x}"
    assert _yerler(proje) == {"f1": "subsystem_addr_1000", "f2": "subsystem_addr_1000",
                              "f3": ikinci, "f4": ikinci}
    assert sonuc.success is True and sonuc.errors == []
    assert (sonuc.placement_strategy, sonuc.placement_fallback_reason) == (
        cpb.PLACEMENT_ADDRESS_PADDING, "")
    assert (sonuc.functions_total, sonuc.functions_placed) == (4, 4)
    assert (sonuc.functions_missing, sonuc.functions_duplicated) == (0, 0)
    assert sonuc.subsystems_found == 2
    assert sorted(p.name for p in (proje / "include").glob("subsystem_*.h")) == [
        "subsystem_addr_1000.h", f"{ikinci}.h"]
    assert any("Adres yerleşimi: 4 fonksiyon, 2 grup (1 dolgu sınırı, 0 blok sınırı"
               in k.getMessage() for k in caplog.records)


def test_yerlesim_raporu_sayilari_ve_gruplari(tmp_path):
    _alan_yaz(tmp_path, _IKI_DILIM)
    _, proje = _kur(tmp_path, _config())
    rapor = _rapor(proje)
    gruplar = rapor.pop("groups")
    assert rapor == {
        "schema": "karadul-placement/1", "requested": cpb.PLACEMENT_ADDRESS_PADDING,
        "strategy": cpb.PLACEMENT_ADDRESS_PADDING, "fallback_reason": None,
        "padding_threshold": ESIK, "alignment": HIZA, "units": 4, "entry_units": 0,
        "functions": 4, "memory_blocks_known": True, "units_placed_by_address": 4,
        "units_without_address": 0, "measured_gaps": 3, "signal_gaps": 1, "padding_cuts": 1,
        "block_cuts": 0,
    }
    assert gruplar == [
        {"name": "addr_1000", "memory_block": ".text", "start": "1000", "end": "1050",
         "functions": 2, "units": 2},
        {"name": f"addr_{0x1050 + ESIK:x}", "memory_block": ".text", "start": f"{0x1050 + ESIK:x}",
         "end": f"{0x1080 + ESIK:x}", "functions": 2, "units": 2},
    ]


def test_readme_ve_harita_yontemi_anlatir_iddia_etmez(tmp_path):
    _alan_yaz(tmp_path, _IKI_DILIM)
    _, proje = _kur(tmp_path, _config())
    readme = (proje / "README.md").read_text()
    assert "## Placement" in readme
    assert f"Strategy: `{cpb.PLACEMENT_ADDRESS_PADDING}`" in readme
    assert f">= {ESIK} bytes" in readme
    assert "- **Groups:** 2 (1 padding boundaries, 0 memory-block boundaries)" in readme
    assert "- **Functions without a usable address:** 0" in readme
    assert "not a verified" in readme
    assert "subsystem_addr_<a>/" in readme and "call-graph community (group_N)" not in readme
    harita = (proje / "analysis" / "subsystem_map.md").read_text()
    assert f"| addr_1000 | .text | 1000 | 1050 | 2 | - |" in harita
    assert f">= {ESIK} bytes" in harita


def test_blok_siniri_plt_ve_dis_yer_tutuculari_ayirir(tmp_path):
    """PLT girişleri `.text`'e bitişik olsa da (dolgu 0) ayrı gruptadır; `EXTERNAL` tek gruptur."""
    fonksiyonlar = {
        "plt_a": (0x0FE0, 0x10), "plt_b": (0x0FF0, 0x10),
        "f1": (0x1000, 0x20), "f2": (0x1020 + ESIK, 0x20),
        "dis_a": (0x9000, 1), "dis_b": (0x9400, 1),
    }
    _alan_yaz(tmp_path, fonksiyonlar, bloklar=(PLT, METIN, DIS))
    sonuc, proje = _kur(tmp_path, _config())
    assert _yerler(proje) == {
        "plt_a": "subsystem_addr_0fe0", "plt_b": "subsystem_addr_0fe0",
        "f1": "subsystem_addr_1000", "f2": f"subsystem_addr_{0x1020 + ESIK:x}",
        "dis_a": "subsystem_addr_9000", "dis_b": "subsystem_addr_9000",
    }
    rapor = _rapor(proje)
    assert (rapor["block_cuts"], rapor["padding_cuts"], rapor["signal_gaps"]) == (2, 1, 1)
    assert [g["memory_block"] for g in rapor["groups"]] == [".plt", ".text", ".text", "EXTERNAL"]
    assert sonuc.success is True


def test_grup_adi_esit_genislikte_ve_dilimin_ilk_fonksiyonundan(tmp_path):
    """Ad, dilimin ilk FONKSİYONUNUN adresidir (birimi olmasa da); genişlik en uzun adrese göre."""
    fonksiyonlar = {
        "ilk": (0x0800, 0x10), "f1": (0x0810, 0x10),              # `ilk`in birimi yok
        "g1": (0x10000, 0x20), "g2": (0x10020 + ESIK, 0x20),
    }
    _alan_yaz(tmp_path, fonksiyonlar, bloklar=(PLT, MemoryBlock(0x10000, 0x1FFFF, ".text", True)),
              birimsiz=("ilk",))
    _, proje = _kur(tmp_path, _config())
    assert _yerler(proje) == {"f1": "subsystem_addr_00800", "g1": "subsystem_addr_10000",
                              "g2": f"subsystem_addr_{0x10020 + ESIK:x}"}
    adlar = [g["name"] for g in _rapor(proje)["groups"]]
    assert adlar == sorted(adlar)
    assert _rapor(proje)["groups"][0]["functions"] == 2 and _rapor(proje)["groups"][0]["units"] == 1


def test_birimi_olmayan_fonksiyon_sirada_yerini_tutar(tmp_path):
    """Ortadaki fonksiyonun birimi yoksa komşuları arasındaki aralık dolgu SANILMAZ."""
    fonksiyonlar = {"a": (0x1000, 0x20), "orta": (0x1020, 0x60), "b": (0x1080, 0x20),
                    "c": (0x10A0 + ESIK, 0x20)}
    _alan_yaz(tmp_path, fonksiyonlar, birimsiz=("orta",))
    _, proje = _kur(tmp_path, _config())
    yerler = _yerler(proje)
    assert yerler["a"] == yerler["b"] == "subsystem_addr_1000"
    assert yerler["c"] != yerler["a"]
    assert _rapor(proje)["padding_cuts"] == 1


def test_giris_noktasi_main_c_de_kalir(tmp_path):
    fonksiyonlar = {"f1": (0x1000, 0x20), "main": (0x1020, 0x20), "f3": (0x1040 + ESIK, 0x20)}
    _alan_yaz(tmp_path, fonksiyonlar)
    sonuc, proje = _kur(tmp_path, _config())
    assert _yerler(proje) == {"main": ".", "f1": "subsystem_addr_1000",
                              "f3": f"subsystem_addr_{0x1040 + ESIK:x}"}
    rapor = _rapor(proje)
    assert (rapor["units"], rapor["entry_units"], rapor["units_placed_by_address"]) == (3, 1, 2)
    assert [g["units"] for g in rapor["groups"]] == [1, 1]
    assert [g["functions"] for g in rapor["groups"]] == [2, 1]
    assert sonuc.functions_placed == 3


def test_adresi_okunamayan_birimler_ayri_grupta(tmp_path, caplog):
    fonksiyonlar = dict(_IKI_DILIM, basliksiz=(0x1100, 0x10))
    _alan_yaz(tmp_path, fonksiyonlar, adressiz=("basliksiz",))
    (tmp_path / "kaynak" / "listede_yok.c").write_text(_kaynak("listede_yok", 0x7777))
    with caplog.at_level(logging.WARNING, logger=cpb.logger.name):
        sonuc, proje = _kur(tmp_path, _config())
    yerler = _yerler(proje)
    assert yerler["basliksiz"] == yerler["listede_yok"] == "subsystem_addr_unknown"
    assert yerler["f1"] == "subsystem_addr_1000"
    rapor = _rapor(proje)
    assert (rapor["units"], rapor["units_placed_by_address"], rapor["units_without_address"]) == (6, 4, 2)
    assert "- **Functions without a usable address:** 2 (in `subsystem_addr_unknown`)" in (
        proje / "README.md").read_text()
    assert "| addr_unknown | - | - | - | 2 | - |" in (proje / "analysis" / "subsystem_map.md").read_text()
    assert any("2 birimin adresi fonksiyon listesinde yok" in k.getMessage() for k in caplog.records)
    assert sonuc.success is True and sonuc.functions_placed == 6


def test_esik_ve_hizalama_yapilandirmadan_gelir(tmp_path):
    """Aynı girdi, yapılandırmadaki eşik değişince farklı dilimlenir (kurucuda gömülü sayı yok)."""
    fonksiyonlar = {"a": (0x1000, 0x20), "b": (0x1020 + 8, 0x20), "c": (0x1048 + ESIK, 0x20)}
    _alan_yaz(tmp_path, fonksiyonlar)
    _, ontanimli = _kur(tmp_path, _config(), cikti="p1")
    _, dusuk = _kur(tmp_path, _config(esik=8, hiza=16), cikti="p2")
    assert len(set(_yerler(ontanimli).values())) == 2
    assert len(set(_yerler(dusuk).values())) == 3
    assert (_rapor(dusuk)["padding_threshold"], _rapor(dusuk)["alignment"]) == (8, 16)
    assert (_rapor(dusuk)["padding_cuts"], _rapor(dusuk)["signal_gaps"]) == (2, 1)


def test_blok_bilgisi_yoksa_uyari_ve_yalniz_dolgu(tmp_path, caplog):
    fonksiyonlar = {"plt_a": (0x0FF0, 0x10), "f1": (0x1000, 0x20), "f2": (0x1020 + ESIK, 0x20)}
    _alan_yaz(tmp_path, fonksiyonlar, blok_listesi=False)
    with caplog.at_level(logging.WARNING, logger=cpb.logger.name):
        _, proje = _kur(tmp_path, _config())
    yerler = _yerler(proje)
    assert yerler["plt_a"] == yerler["f1"] != yerler["f2"]
    rapor = _rapor(proje)
    assert (rapor["memory_blocks_known"], rapor["block_cuts"]) == (False, 0)
    assert rapor["groups"][0]["memory_block"] is None
    assert any("bellek bloğu bilgisi yok" in k.getMessage() for k in caplog.records)


def test_api_etiketi_haritada_grup_basina_sayilir(tmp_path):
    """Etiketler çok olandan aza; eşitlikte kural tablosundaki sırayla (ada göre değil)."""
    ikinci = 0x1060 + ESIK
    fonksiyonlar = {"a": (0x1000, 0x20), "b": (0x1020, 0x20), "c": (0x1040, 0x20),
                    "d": (ikinci, 0x20), "e": (ikinci + 0x20, 0x20), "f": (ikinci + 0x40, 0x20)}
    cagrilanlar = {"a": ["malloc"], "b": ["calloc"], "c": ["fopen", "fread"],
                   "d": ["SSL_read"], "e": ["socket"], "f": []}
    _alan_yaz(tmp_path, fonksiyonlar)
    graf = {"program": "p", "edges": [], "nodes": {
        f"{adres:08x}": {"name": ad, "address": f"{adres:08x}",
                         "callees": [{"name": c} for c in cagrilanlar[ad]]}
        for ad, (adres, _boyut) in fonksiyonlar.items()}}
    (tmp_path / "static" / "ghidra_call_graph.json").write_text(json.dumps(graf))
    _, proje = _kur(tmp_path, _config())
    harita = (proje / "analysis" / "subsystem_map.md").read_text()
    assert "| addr_1000 | .text | 1000 | 1060 | 3 | memory 2, file_io 1 |" in harita
    assert f"| addr_{ikinci:x} | .text | {ikinci:x} | {ikinci + 0x60:x} | 3 | network 1, crypto 1 |" in harita
    # API etiketi dizini belirlemez
    assert set(_yerler(proje).values()) == {"subsystem_addr_1000", f"subsystem_addr_{ikinci:x}"}


def test_adres_yerlesimi_belirlenimci(tmp_path):
    fonksiyonlar = {f"f{i}": (0x1000 + 0x40 * i, 0x40 - (ESIK if i % 4 == 0 else 4)) for i in range(24)}
    _alan_yaz(tmp_path, fonksiyonlar)
    _, p1 = _kur(tmp_path, _config(), cikti="p1")
    _, p2 = _kur(tmp_path, _config(), cikti="p2")
    assert _agac(p1) == _agac(p2)
    # eşik kadar dolgu i = 0, 4, …, 20'den sonra: 6 sınır, 7 grup (4 baytlık dolgular sınır değil)
    assert len(set(_yerler(p1).values())) == 7
    assert (_rapor(p1)["padding_cuts"], _rapor(p1)["signal_gaps"]) == (6, 6)


# ---------------------------------------------------------------------------
# 6. Kurucu: bayrak açık, eski yerleşime dönüş
# ---------------------------------------------------------------------------

def _geri_dusus_denetle(kok: Path, config, neden: str, caplog) -> dict:
    """Bayrak açık kurulum eski yerleşime döndü mü; ağaç bayrak kapalı ağaçla yalnız README ve
    placement.json'da mı ayrışıyor? Dönen: yerleşim raporu."""
    _, kapali = _kur(kok, None, cikti="kapali")
    with caplog.at_level(logging.WARNING, logger=cpb.logger.name):
        sonuc, acik = _kur(kok, config, cikti="acik")
    assert (sonuc.placement_strategy, sonuc.placement_fallback_reason) == (
        cpb.PLACEMENT_API_COMMUNITY, neden)
    assert sonuc.success is True
    a, k = _agac(acik), _agac(kapali)
    assert set(a) - set(k) == {"analysis/placement.json"}
    assert set(k) - set(a) == set()
    assert {yol for yol in k if a[yol] != k[yol]} == {"README.md"}
    readme = (acik / "README.md").read_text()
    assert f"was requested but not applied: `{neden}`" in readme
    assert "call-graph community (group_N)" in readme          # eski dizin anlatımı duruyor
    assert any(f"uygulanamadı ({neden})" in kayit.getMessage() for kayit in caplog.records)
    rapor = _rapor(acik)
    assert (rapor["requested"], rapor["strategy"], rapor["fallback_reason"]) == (
        cpb.PLACEMENT_ADDRESS_PADDING, cpb.PLACEMENT_API_COMMUNITY, neden)
    assert "groups" not in rapor
    return rapor


def test_sinyal_yoksa_eski_yerlesim(tmp_path, caplog):
    """Bütün dolgular eşiğin altında (Mach-O / clang gibi): eski yerleşim, nedeni yazılı."""
    fonksiyonlar = {"a": (0x1000, 0x20), "b": (0x1020, 0x20), "c": (0x1040 + ESIK - 1, 0x20)}
    _alan_yaz(tmp_path, fonksiyonlar)
    rapor = _geri_dusus_denetle(tmp_path, _config(), cpb.FALLBACK_NO_PADDING_SIGNAL, caplog)
    assert (rapor["signal_gaps"], rapor["padding_cuts"], rapor["measured_gaps"]) == (0, 0, 2)


def test_yalniz_hizalama_ustu_dolgu_sinyal_degildir(tmp_path, caplog):
    """Tek büyük aralık (hizalama ve üstü) bantta değildir: sınır sayılır ama sinyal sayılmaz."""
    fonksiyonlar = {"a": (0x1000, 0x20), "b": (0x1020 + HIZA, 0x20)}
    _alan_yaz(tmp_path, fonksiyonlar)
    rapor = _geri_dusus_denetle(tmp_path, _config(), cpb.FALLBACK_NO_PADDING_SIGNAL, caplog)
    assert (rapor["signal_gaps"], rapor["padding_cuts"]) == (0, 1)


def test_fonksiyon_listesi_yoksa_eski_yerlesim(tmp_path, caplog):
    _alan_yaz(tmp_path, _IKI_DILIM, fonksiyon_listesi=False)
    rapor = _geri_dusus_denetle(tmp_path, _config(), cpb.FALLBACK_NO_FUNCTION_DATA, caplog)
    assert "functions" not in rapor


def test_hicbir_birim_adreslenemiyorsa_eski_yerlesim(tmp_path, caplog):
    _alan_yaz(tmp_path, _IKI_DILIM, adressiz=tuple(_IKI_DILIM))
    rapor = _geri_dusus_denetle(tmp_path, _config(), cpb.FALLBACK_NO_ADDRESSED_UNIT, caplog)
    assert (rapor["units_placed_by_address"], rapor["units_without_address"]) == (0, 4)


@pytest.mark.parametrize("esik,hiza", [(0, 32), (32, 32), (48, 32), (16.0, 32), (True, 32), (16, None)],
                         ids=["esik_sifir", "esit", "esik_buyuk", "kesirli", "mantiksal", "hiza_yok"])
def test_gecersiz_sayilarla_eski_yerlesim(tmp_path, caplog, esik, hiza):
    _alan_yaz(tmp_path, _IKI_DILIM)
    cfg = _config()
    cfg.binary_reconstruction.address_placement_padding_threshold = esik
    cfg.binary_reconstruction.address_placement_alignment = hiza
    _geri_dusus_denetle(tmp_path, cfg, cpb.FALLBACK_INVALID_PARAMETERS, caplog)


def test_calisma_alani_yoksa_eski_yerlesim(tmp_path):
    _alan_yaz(tmp_path, _IKI_DILIM)
    sonuc = CProjectBuilder(_config()).build(tmp_path / "kaynak", tmp_path / "proje", workspace=None)
    assert sonuc.placement_fallback_reason == cpb.FALLBACK_NO_FUNCTION_DATA
    assert sonuc.success is True


# ---------------------------------------------------------------------------
# 7. Girdi okuma sağlamlığı
# ---------------------------------------------------------------------------

def test_fonksiyon_boyutlari_bozuk_kayitlari_atlar(tmp_path):
    static = tmp_path / "static"
    static.mkdir()
    (static / "ghidra_functions.json").write_text(json.dumps({"functions": [
        {"address": "00001000", "size": 32}, {"address": "00001000", "size": 16},   # yinelenen: büyük
        {"address": "00001040", "size": 8}, {"address": "00001040", "size": 24},
        {"address": "zz", "size": 4}, {"address": "00002000", "size": "8"},
        {"address": "00003000", "size": -1}, {"address": "00004000", "size": True},
        {"address": 4096, "size": 4}, {"size": 4}, "bozuk",
        {"address": "00005000", "size": 0},
    ]}))
    boyut = CProjectBuilder(None)._load_function_sizes(_CalismaAlani(tmp_path))
    assert boyut == {0x1000: 32, 0x1040: 24, 0x5000: 0}


def test_fonksiyon_listesi_ikinci_konumdan_okunur(tmp_path):
    cikti = tmp_path / "static" / "ghidra_output"
    cikti.mkdir(parents=True)
    (cikti / "functions.json").write_text(json.dumps({"functions": [{"address": "10", "size": 4}]}))
    (cikti / "combined_results.json").write_text(json.dumps(
        {"program_info": {"memory_blocks": [_blok_kaydi(METIN)]}}))
    kurucu = CProjectBuilder(None)
    assert kurucu._load_function_sizes(_CalismaAlani(tmp_path)) == {0x10: 4}
    assert kurucu._load_memory_blocks(_CalismaAlani(tmp_path)) == [METIN]


def test_bozuk_json_bos_sonuc(tmp_path):
    static = tmp_path / "static"
    static.mkdir()
    (static / "ghidra_functions.json").write_text("{bozuk")
    (static / "ghidra_combined_results.json").write_text(json.dumps({"program_info": []}))
    kurucu = CProjectBuilder(None)
    assert kurucu._load_function_sizes(_CalismaAlani(tmp_path)) == {}
    assert kurucu._load_memory_blocks(_CalismaAlani(tmp_path)) == []
    assert kurucu._load_function_sizes(None) == {}


def test_birim_adresi_basliktan(tmp_path):
    assert CProjectBuilder._unit_address(_kaynak("f", 0x1A2B)) == 0x1A2B
    assert CProjectBuilder._unit_address(_kaynak("f", None)) is None
    assert CProjectBuilder._unit_address("// Address:  ram:0010\n") is None
