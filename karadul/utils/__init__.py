"""Karadul yardimci moduller paketi.

Bu paket, projenin farkli yerlerinden paylasilan kucuk yardimci
fonksiyonlari barindirir. Native crash riski tasiyan kutuphaneleri
(ornegin lief) izole etmek icin subprocess sarmalayicilari da
buradadir.
"""

from karadul.utils.lief_subprocess import (
    LiefParseResult,
    parse_bytes_in_subprocess,
    parse_in_subprocess,
)

__all__ = [
    "LiefParseResult",
    "parse_bytes_in_subprocess",
    "parse_in_subprocess",
]
