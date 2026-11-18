"""P12a kalem 3 — AD-08: yerel adlar fonksiyon başına tekilleştirilir.

Sorun (AD-08, ölçüldü): ``c_namer`` yerel anahtarları (``fonksiyon::param_1``) ikili genelindeki
``used_new_names`` kümesiyle tekilleştiriyordu. Debian htop'ta 2 626 yerel adın 2 442'si sayaç eki
taşıyordu (``buf_308``); fonksiyon içi çift 0. Ek, fonksiyonların sırasına bağlıydı: bir fonksiyon
eklenip çıkınca sonraki bütün fonksiyonların yerel adları kayıyordu.

Kural (P12a ön kaydı §1): yerel adın kullanılmış kümesi = kendi fonksiyonunun yerel adları ∪ bu
koşuda verilen genel adlar. Genel adlar önce karara bağlanır; genel adın eki yerel adlara bakmaz.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_ad_gecerliligi as G  # noqa: E402
import test_c_namer_determinism as T  # noqa: E402
import test_c_namer_susturma as S  # noqa: E402

from karadul.reconstruction import c_namer  # noqa: E402


@pytest.fixture
def seri(monkeypatch):
    monkeypatch.setattr(c_namer, "ProcessPoolExecutor", T._SerialExecutor)
    monkeypatch.setattr(c_namer, "_worker_namer", None)


def _govde(ad: str, yereller: int = 1) -> str:
    """``yereller`` kadar ``local_N = strlen(param_1)`` (her biri ``len`` adayı)."""
    adlar = [f"local_{8 + 4 * i:x}" for i in range(yereller)]
    bildirim = "".join(f"  int {a};\n" for a in adlar)
    atama = "".join(f"  {a} = strlen(param_1);\n" for a in adlar)
    return (f"int {ad}(char *param_1)\n{{\n{bildirim}{atama}"
            f"  return {' + '.join(adlar)};\n}}\n")


def _fonklar(adresler, yereller=None):
    yereller = yereller or {}
    return [G._fonk(f"FUN_{a}", a, govde=_govde(f"FUN_{a}", yereller.get(a, 1))) for a in adresler]


def test_farkli_fonksiyonlardaki_ayni_yerel_ad_eksiz(tmp_path, seri):
    """Dört fonksiyonun hepsinde ``param_1`` → ``s``, ``local_8`` → ``len``: hiçbirine ek yok."""
    adresler = ["00001000", "00002000", "00003000", "00004000"]
    _, prov, harita = S._kos(G._calisma_alani(tmp_path / "ws", _fonklar(adresler)), tmp_path / "out")
    for a in adresler:
        assert harita["per_function"][f"FUN_{a}"] == {"param_1": "s", "local_8": "len"}, a
    assert S._hesap_tutar(prov)


def test_ayni_fonksiyonda_ikinci_istek_ek_alir(tmp_path, seri):
    """Ek yalnız aynı fonksiyonda aynı ad ikinci kez istenince: ``len``, ``len_2``, ``len_3``."""
    fonklar = _fonklar(["00001000", "00002000"], {"00002000": 3})
    _, _, harita = S._kos(G._calisma_alani(tmp_path / "ws", fonklar), tmp_path / "out")
    assert harita["per_function"]["FUN_00001000"]["local_8"] == "len"
    ikinci = harita["per_function"]["FUN_00002000"]
    assert sorted(v for k, v in ikinci.items() if k.startswith("local_")) == ["len", "len_2", "len_3"]


def test_fonksiyon_cikarilinca_obur_yerel_adlar_degismez(tmp_path, seri):
    """İlk fonksiyon girdiden çıkarılınca kalan fonksiyonların yerel adları aynı kalır."""
    adresler = ["00001000", "00002000", "00003000"]
    yereller = {"00001000": 2, "00002000": 2, "00003000": 1}
    _, _, tam = S._kos(G._calisma_alani(tmp_path / "ws1", _fonklar(adresler, yereller)), tmp_path / "o1")
    _, _, eksik = S._kos(G._calisma_alani(tmp_path / "ws2", _fonklar(adresler[1:], yereller)),
                         tmp_path / "o2")
    for a in adresler[1:]:
        assert eksik["per_function"][f"FUN_{a}"] == tam["per_function"][f"FUN_{a}"], a


def test_yerel_ad_genel_adi_golgelemez_ve_genel_ad_eki_yerele_bakmaz(tmp_path, seri):
    """Ön ad ``len`` (genel) verilmişse yerel ``len`` adayı ``len_2`` olur; genel ad eksiz kalır.

    Fonksiyon sırası bilerek: yerel ad isteyen fonksiyonlar ön adlı fonksiyondan ÖNCE.
    """
    adresler = ["00001000", "00002000", "00009000"]
    fonklar = _fonklar(adresler[:2]) + [G._fonk("FUN_00009000", "00009000")]
    _, _, harita = S._kos(G._calisma_alani(tmp_path / "ws", fonklar), tmp_path / "out",
                          pre_names={"FUN_00009000": "len"})
    assert harita["global"]["FUN_00009000"] == "len"
    for a in adresler[:2]:
        assert harita["per_function"][f"FUN_{a}"]["local_8"] == "len_2", a


def test_belirlenimcilik_fiksturunde_yerel_ek_yalniz_fonksiyon_icinde(tmp_path, seri):
    """Belirlenimcilik fikstüründe (G9) her ekli yerel adın tabanı aynı fonksiyonda ya da genel
    adlarda kullanılmış olmalı ("açıklanamayan ek" 0; ön kayıt H2)."""
    ws = T.build_workspace(tmp_path / "ws")
    _, _, harita = S._kos(ws, tmp_path / "out")
    genel = set(harita["global"].values())
    for fonk, yereller in harita["per_function"].items():
        adlar = set(yereller.values())
        assert len(adlar) == len(yereller), f"{fonk}: fonksiyon içi çift ad"
        for ad in adlar:
            m = re.fullmatch(r"(.+)_(\d+)", ad)
            if m and int(m.group(2)) >= 2:
                taban = m.group(1)
                assert taban in adlar or taban in genel, f"{fonk}: {ad} açıklanamayan ek"
        assert not (adlar & genel), f"{fonk}: yerel ad genel adı gölgeliyor"
