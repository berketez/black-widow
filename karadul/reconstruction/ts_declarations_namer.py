"""TypeScript .d.ts declaration dosyalarindan export isim kurtarma.

Bu modul ``karadul.reconstruction.dts_namer``'in yeni/onerilen adidir.
Eski ``dts_namer`` adi embedded Linux Device Tree (DTS) dosyalariyla
karistirilmaya musaitti; asli is TypeScript declaration (.d.ts) parse
etme. Bu sebeple yeniden adlandirildi.

Backward compatibility:
    Eski isim ``karadul.reconstruction.dts_namer`` hala calisir ve ayni
    semboleri dondurur (tersine uyumluluk — import sirasinda uyari yok).

Yeni kodlar bu modulu kullanmali:
    from karadul.reconstruction.ts_declarations_namer import (
        DtsExport,              # (ileride: TsExport)
        DtsNamer,               # (ileride: TsDeclarationsNamer)
        DtsNamerResult,
    )

Not: Class/type isimleri (``DtsNamer`` vb.) simdilik korundu cunku
harici test suite ve naming pipeline onlara bagli. Ileride ayri bir
sprint'te class isimleri de degistirilebilir (deprecation notice ile).
"""

from __future__ import annotations

# Tum public sembolleri eski moduldan re-export et.
from karadul.reconstruction.dts_namer import (  # noqa: F401
    DtsExport,
    DtsNamer,
    DtsNamerResult,
)

__all__ = ["DtsExport", "DtsNamer", "DtsNamerResult"]
