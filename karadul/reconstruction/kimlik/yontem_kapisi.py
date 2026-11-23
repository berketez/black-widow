"""PK-1 — var olan başvuru yollarına yöntem kapısı (KARARLAR A-2, A-13, A-15, A-25, A-30).

Ürünün iki başvuru yolu (``BinaryDiffer``: ``reference_binary`` / ``ref_db``; ``ReferenceDiffer``:
sürüm tespiti + ``ref_db``) her eşleşmeye bir yöntem adı yazar. Yöntemlerin ölçülmüş tam ad kesinliği
çok farklı (``kimlik/BULGULAR.md`` §2.2): dizgi yöntemleri 0,94–0,96, boyut / CFG yöntemleri 0,18–0,76.
Karar kuralı: ölçülmüş kesinliğin Wilson %95 alt sınırı ≥ ``AD_ESIGI`` (= L / (L + 1), L = 10) olan
yöntem **ad** yazar; altındaki yöntem **kanıt satırı** yazar (susturma değil, K-2: ölçülmüş kural).
Tabloda olmayan yöntem ölçülmemiştir → ad yazmaz.

Tablo: ``kimlik/PK-1_on_kayit.md`` (plan PK-1 ön kaydı) "TÜM GRUPLAR" satırları — beş grubun havuzu
(``kesif_htop``, ``sinama_tmux``, ``sinama_cu_mac``, ``sinama_cu_ic``, ``surum``), nüfus içi, tam eşitlik,
yön başına; kaynak dizgisi ``~/karadul_olcum/runs/arge-2026-11-19/kimlik/urun_bindiff.txt`` (ürün a62f15e).
Alt sınır elle yazılmaz: ``baglama.wilson`` ile hesaplanır; ``tests/test_pk1_basvuru_yontem_kapisi.py``
ölçüm betiğinin Wilson'u ile yeniden hesaplayıp ön kayıttaki değerlerle karşılaştırır.

Yöntem adları iki yolda ayrıktır (``BinaryDiffer``: ``string_refs``, ``cfg_fingerprint``, ``size_params``,
``call_pattern``, ``decompiled_hash``; ``ReferenceDiffer``: ``string_fingerprint``, ``cfg_similarity``,
``size_constant``, ``call_propagation``); tablo tek sözlüktür.
"""

from __future__ import annotations

from typing import Optional

from karadul.core.naming_labels import AD_ESIGI, floor_confidence
from karadul.reconstruction.tarif.baglama import wilson

OLCUM_KAYNAGI = (
    "docs/arge/2026-11-19_mythos/kimlik/PK-1_on_kayit.md "
    "(K/urun_bindiff.txt TÜM GRUPLAR; ürün a62f15e)")

# Yöntem → (doğru, ad verilen). Beş grubun havuzu; ``config`` ve ``refdb`` kiplerinde aynı yöntemin
# sayıları aynıdır (``refdb`` yalnız ``call_pattern`` ekler).
OLCULMUS_SAYIM: dict[str, tuple[int, int]] = {
    # BinaryDiffer (karadul.analyzers.bindiff)
    "string_refs": (414, 438),
    "cfg_fingerprint": (445, 584),
    "size_params": (99, 540),
    "call_pattern": (222, 283),
    # ReferenceDiffer (karadul.reconstruction.reference_differ)
    "string_fingerprint": (476, 494),
    "cfg_similarity": (1529, 2748),
    "size_constant": (43, 157),
    "call_propagation": (8, 16),
}
# ``decompiled_hash`` (BinaryDiffer) ölçülmedi: tabloda yok → ad yazmaz.


def _ham_alt(dogru: int, verilen: int) -> float:
    return wilson(dogru, verilen)[0]


# Yöntem → (doğru, ad verilen, Wilson %95 alt sınırı; 4 basamağa aşağı yuvarlanmış).
OLCULMUS_YONTEM: dict[str, tuple[int, int, float]] = {
    yontem: (d, n, floor_confidence(_ham_alt(d, n)))
    for yontem, (d, n) in OLCULMUS_SAYIM.items()
}

NEDEN_YONTEM_KAPISI = "yontem_kapisi"
NEDEN_OLCULMEMIS = "olculmemis_yontem"


def olculmus_alt(yontem: Optional[str]) -> Optional[float]:
    """Yöntemin ölçülmüş kesinliğinin Wilson alt sınırı (4 basamak, aşağı); ölçülmemişse ``None``."""
    satir = OLCULMUS_YONTEM.get(yontem) if yontem else None
    return satir[2] if satir else None


def ad_verebilir(yontem: Optional[str]) -> bool:
    """Yöntem ad yazabilir mi: ölçülmüş Wilson alt sınırı ≥ ``AD_ESIGI`` (yuvarlamasız karşılaştırma).

    Tabloda olmayan (ölçülmemiş) yöntem ``False``.
    """
    sayim = OLCULMUS_SAYIM.get(yontem) if yontem else None
    if sayim is None:
        return False
    return _ham_alt(*sayim) >= AD_ESIGI


def red_nedeni(yontem: Optional[str]) -> str:
    """Kanıt satırının nedeni: ölçülmemiş yöntem ya da ölçülmüş ama eşiğin altında."""
    return NEDEN_YONTEM_KAPISI if yontem in OLCULMUS_SAYIM else NEDEN_OLCULMEMIS


def ad_veren_yontemler() -> tuple[str, ...]:
    """Kapıdan geçen yöntemler (sıralı)."""
    return tuple(sorted(y for y in OLCULMUS_SAYIM if ad_verebilir(y)))


def en_dusuk_alt(yontemler: tuple[str, ...]) -> Optional[float]:
    """Verilen yöntemlerden kapıdan geçenlerin en düşük ölçülmüş alt sınırı; hiçbiri geçmiyorsa ``None``.

    Yöntemi taşınmayan adın güveni için (``_add_refdiff``): adın yöntemi bilinmiyorsa, o yoldan ad
    yazabilen yöntemlerin en düşüğü yazılır (hiçbir ölçülmüş değerden yüksek değil).
    """
    degerler = [olculmus_alt(y) for y in yontemler if ad_verebilir(y)]
    degerler = [d for d in degerler if d is not None]
    return min(degerler) if degerler else None


# ReferenceDiffer'ın yöntemleri (``FunctionMatch.method``); ``_add_refdiff`` yöntem bilgisi yokken kullanır.
REFDIFF_YONTEMLERI: tuple[str, ...] = (
    "string_fingerprint", "cfg_similarity", "size_constant", "call_propagation")


def kanit_satiri(*, kaynak: str, anahtar: str, ad: str, yontem: Optional[str],
                 adres: Optional[str] = None, eslesme_guveni: Optional[float] = None,
                 basvuru: Optional[str] = None) -> dict:
    """Kapıdan düşen eşleşmenin kanıt satırı.

    Biçim P-ÜV6a'nın ``ust_veri_kanit`` satırıyla aynı alanlar (``kaynak``, ``adres``, ``ozgun_ad``,
    ``nedenler``); ek alanlar ``anahtar`` (Ghidra adı), ``yontem``, ``olculmus_alt`` (ölçülmemişse
    ``None``), ``eslesme_guveni`` (eşleyicinin kendi puanı; kalibre değil), ``basvuru`` (varsa).
    ``ozgun_ad`` = başvurudaki fonksiyon adı (önerilen ad; koda yazılmadı).
    """
    satir: dict = {
        "kaynak": kaynak,
        "adres": adres,
        "anahtar": anahtar,
        "ozgun_ad": ad,
        "yontem": yontem,
        "olculmus_alt": olculmus_alt(yontem),
        "nedenler": [red_nedeni(yontem)],
    }
    if eslesme_guveni is not None:
        satir["eslesme_guveni"] = round(float(eslesme_guveni), 4)
    if basvuru:
        satir["basvuru"] = basvuru
    return satir
