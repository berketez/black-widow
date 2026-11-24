"""ÖL-4: ``ILERLEME`` olay satırlarının tek ayrıştırıcısı (CLI ve arayüz sunucusu birlikte kullanır).

Olayı ÖL-1 üretir (``karadul/ghidra/headless.py``: ``ilerleme_satiri``); sözleşme
``docs/arge/2026-11-19_mythos/olcek/PLAN.md`` §1'de SABİT. Bu modül olay üretmez, yalnız okur:

- Satır nerede olursa olsun (``--verbose`` kök işleyicisinin ``SS:DD:ss INFO    [karadul.ilerleme]``
  öneki, ya da yalın ``ILERLEME …`` satırı) ``ILERLEME `` önekinden sonrası ``shlex.split`` ile
  ayrılır (çift tırnak, içte ``\\"`` ve ``\\\\`` kaçışı; üretici ``_olay_degeri``).
- Sözleşmeye uymayan satır (zorunlu alan yok, bilinmeyen ``durum``, ``=``'siz parça, kapanmamış
  tırnak, sayı olmayan sayaç) olay değildir: ``None`` döner. Alan uydurulmaz; satırda olmayan alan
  sözlükte de yoktur.

Sözleşme sabitleri (önek, durumlar, isteğe bağlı alanlar) üreticiden içe aktarılır: tek kaynak.
"""

from __future__ import annotations

import re
import shlex
from typing import Any, Optional

from karadul.ghidra.headless import (
    ILERLEME_GUNLUKCU,
    ILERLEME_ONEKI,
    OLAY_DURUMLARI,
    OLAY_ISTEGE_BAGLI_ALANLAR,
)

# Önek satır başında ya da boşluktan sonra (günlük öneki ``[karadul.ilerleme] ILERLEME …``); ardından
# sözleşmenin ilk alanı ``asama=``. Başka bir sözcüğün parçası olan "ILERLEME" eşleşmez.
_ONEK_RE = re.compile(r"(?:^|\s)" + re.escape(ILERLEME_ONEKI) + r" (asama=.*)$")
ZORUNLU_ALANLAR: tuple[str, ...] = ("asama", "adim", "durum")
_TAMSAYI_ALANLARI: tuple[str, ...] = ("islenen", "toplam")
_ONDALIK_ALANLARI: tuple[str, ...] = ("gecen_sn",)
# Arayüzün ``ilerleme`` alanında ve CLI çubuğunda gösterilen alanlar (gönderim hükmü 3).
GOSTERILEN_ALANLAR: tuple[str, ...] = (
    "adim", "durum", "islenen", "toplam", "gecen_sn", "cozumleyici", "neden",
)


def ilerleme_ayristir(satir: str) -> Optional[dict[str, Any]]:
    """Tek satırdan ``ILERLEME`` olayı; satır sözleşmeye uymuyorsa ``None``.

    Dönen sözlükte yalnız satırda geçen sözleşme alanları vardır; ``islenen`` / ``toplam`` ``int``,
    ``gecen_sn`` ``float``, öbürleri metin.
    """
    m = _ONEK_RE.search(satir.rstrip("\r\n"))
    if not m:
        return None
    try:
        parcalar = shlex.split(m.group(1))
    except ValueError:  # kapanmamış tırnak / yarım kaçış: yarım satır olay değildir
        return None
    olay: dict[str, Any] = {}
    gecerli = set(ZORUNLU_ALANLAR) | set(OLAY_ISTEGE_BAGLI_ALANLAR)
    for parca in parcalar:
        ad, esit, deger = parca.partition("=")
        if not esit or ad not in gecerli or ad in olay:
            return None
        olay[ad] = deger
    if any(ad not in olay for ad in ZORUNLU_ALANLAR) or olay["durum"] not in OLAY_DURUMLARI:
        return None
    try:
        for ad in _TAMSAYI_ALANLARI:
            if ad in olay:
                olay[ad] = int(olay[ad])
        for ad in _ONDALIK_ALANLARI:
            if ad in olay:
                olay[ad] = float(olay[ad])
    except ValueError:
        return None
    return olay


def gosterim_alanlari(olay: Optional[dict[str, Any]]) -> Optional[dict[str, Any]]:
    """Olaydan gösterilen alanlar (satırda olmayan alan ``None``); olay yoksa ``None``."""
    if olay is None:
        return None
    return {ad: olay.get(ad) for ad in GOSTERILEN_ALANLAR}


__all__ = [
    "ILERLEME_GUNLUKCU",
    "ILERLEME_ONEKI",
    "ZORUNLU_ALANLAR",
    "GOSTERILEN_ALANLAR",
    "ilerleme_ayristir",
    "gosterim_alanlari",
]
