"""P-S3b kalem 2 / 4: iç ad tablosu ve `usage` gelenek adı (ürün davranışı stages.py yamasıyla gelir).

Tablo GT'yle ölçüldü (lto_yerlesimi ile tutulan adaylar, katı eşitlik): version_etc -> version_etc_arn
113/113, full_write -> safe_write 9/9; hard_locale -> setlocale_null_r katı 5/110 (2024+ gnulib'de ad
setlocale_null_r_unlocked) olduğu için tabloda YOK. Ölçüm: docs/arge/2026-11-18_onarim/P-S3b.md.
"""

from __future__ import annotations

import re
from pathlib import Path

from karadul.analyzers.gnulib_fingerprints import (
    LAYOUT_DEPENDENT_NAMES,
    LTO_LESS_INNER_NAMES,
    USAGE_CONVENTION_NAME,
    lto_less_inner_name,
)

GNULIB_LIB = Path(__file__).resolve().parents[1] / "vendor" / "gnulib-ref" / "lib"


def test_ic_ad_tablosu():
    assert lto_less_inner_name("version_etc") == "version_etc_arn"
    assert lto_less_inner_name("full_write") == "safe_write"
    assert lto_less_inner_name("hard_locale") is None  # sürüme bağlı; ölçümde katı 5/110
    assert lto_less_inner_name("close_stdout") is None
    assert set(LTO_LESS_INNER_NAMES) <= LAYOUT_DEPENDENT_NAMES


def test_ic_adlar_upstream_kaynakta_tanimli():
    """İç ad gnulib kaynağında fonksiyon adı olarak (ya da safe_rw makrosuyla) tanımlı."""
    for dis, (ic, kaynak) in LTO_LESS_INNER_NAMES.items():
        metin = (GNULIB_LIB / kaynak).read_text(encoding="utf-8", errors="replace")
        assert re.search(rf"^{re.escape(ic)} \(|define \w+ {re.escape(ic)}\b", metin, re.M), (dis, ic)


def test_usage_gelenek_adi():
    assert USAGE_CONVENTION_NAME == "usage"
