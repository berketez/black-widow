"""P07 — B-B7 (doğrulanmamış tanıtım cümleleri) ve P08 çok kitaplıklı ad, temiz çıktı raporu.

Fikstürler ve yardımcılar: ``tests/test_p07_rapor_sozlesme.py``.
"""

from __future__ import annotations

from karadul.core.report_generator import ReportGenerator
from tests.test_p07_rapor_sozlesme import _kur, _uret


# ---------------------------------------------------------------------------
# B-B7 ve P08 (çok kitaplıklı ad)
# ---------------------------------------------------------------------------

def test_dogrulanmamis_tanitim_cumlesi_yok(tmp_path):
    sonuc, ws = _kur("urun_openssl", tmp_path)
    temiz = _uret(sonuc, ws)["temiz"]
    for ifade in ("NSA-grade", "300+ rules", "3-level data flow", "names recovered from original source"):
        assert ifade not in temiz
    assert "Identifier Renaming" in temiz
    assert "doğrulanmadı: 20, kesin: 15" in temiz


def test_cok_kitaplikli_ad_bos_parantez_basmaz(tmp_path):
    sonuc, ws = _kur("p08_cat", tmp_path)
    tablo = ReportGenerator(sonuc, ws)._naming_table()
    assert "signature_db ()" not in tablo
    assert "signature_db (one of: musl, glibc)" in tablo
