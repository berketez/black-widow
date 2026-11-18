"""Hesaplama kollarının (CFG-iso, füzyon, MaxSMT) dürüst durum kaydı (P11).

Eskiden bu kollar her ikilide "çalıştı, 0 sonuç" yazıyordu; sıfırın nedeni
(biçim uyuşmazlığı, bayrak, desteklenmeyen girdi) görünmüyordu. Her kol artık
``ctx.stats[<kol anahtarı>]`` altına tek bir sözlük yazar:

``durum``
    ``kapali`` (bayrak kapalı), ``calisti`` (girdisiyle gerçekten koştu; sonuç 0
    olabilir), ``desteklenmiyor`` (gerekli girdi ya da şablon yok; koşmadı),
    ``hata`` (istisna; sayaçlar yazılmaz).
``neden``
    Durumun Türkçe gerekçesi (``calisti`` için boş olabilir).
``cikti``
    Sonucun nereye gittiği: ``bagli_degil`` (yalnız aday yapıtı; ad haritasına ve
    koda girmez — K-1), ``fuzyon_girdisi``, ``yapi_adayi`` (yapı motoruna aday;
    koda yazım P10 bayrağıyla kapalı), ``ad_adayi`` (bayrakla ad kanalına).
Sayaçlar
    Kola özgü; ``hata``'da yazılmaz (yalan sıfır olmasın).
"""

from __future__ import annotations

from typing import Any

KAPALI = "kapali"
CALISTI = "calisti"
DESTEKLENMIYOR = "desteklenmiyor"
HATA = "hata"
KOL_DURUMLARI = (KAPALI, CALISTI, DESTEKLENMIYOR, HATA)

BAGLI_DEGIL = "bagli_degil"
FUZYON_GIRDISI = "fuzyon_girdisi"
YAPI_ADAYI = "yapi_adayi"
AD_ADAYI = "ad_adayi"

STAT_CFG_ISO = "kol_cfg_iso"
STAT_FUZYON = "kol_fuzyon"
STAT_MAXSMT = "kol_maxsmt"


def kol_durumu(durum: str, neden: str = "", cikti: str = BAGLI_DEGIL,
               **sayaclar: Any) -> dict[str, Any]:
    """Durum sözlüğü kur; bilinmeyen durum değeri hata verir."""
    if durum not in KOL_DURUMLARI:
        raise ValueError(f"bilinmeyen kol durumu: {durum}")
    kayit: dict[str, Any] = {"durum": durum, "neden": neden, "cikti": cikti}
    if durum != HATA:
        kayit.update(sayaclar)
    return kayit
