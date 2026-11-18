"""P07 — SARIF ve dört üreticinin tutarlılığı (ARAYUZ-17), gerçek koşu yapıtlarıyla.

Fikstürler ve yardımcılar: ``tests/test_p07_rapor_sozlesme.py``.
"""

from __future__ import annotations

import json

import pytest

from karadul.reporting.report_data import CRYPTO_CATEGORIES, SECTION_ORDER, status_label
from tests.test_p07_rapor_sozlesme import (
    FIX,
    _html_bolum,
    _kur,
    _md_bolum,
    _sarif_sonuc,
    _uret,
)

# ---------------------------------------------------------------------------
# ARAYUZ-17: SARIF
# ---------------------------------------------------------------------------

def test_sarif_openssl_kripto_bulgusu_algorithms_jsondan(tmp_path):
    """Eskiden static.stats.algorithms_detected LİSTESİ okunuyordu (hiç yazılmıyor): openssl'de
    KRDL001 = 0. Şimdi reconstructed/algorithms.json'daki kripto kategorileri."""
    sonuc, ws = _kur("urun_openssl", tmp_path)
    r = _uret(sonuc, ws)
    algos = json.loads((FIX / "urun_openssl/reconstructed/algorithms.json").read_text())["algorithms"]
    kripto = [a for a in algos if a["category"] in CRYPTO_CATEGORIES]
    assert len(kripto) == 52
    k1 = [x for x in _sarif_sonuc(r) if x["ruleId"] == "KRDL001"]
    alg_kaynakli = [x for x in k1 if x["properties"].get("source") == "reconstructed/algorithms.json"]
    assert len(alg_kaynakli) == 52
    # her biri fonksiyonuyla ve kanıtıyla
    assert all(x["locations"][0]["logicalLocations"][0]["name"] for x in alg_kaynakli)
    assert all(x["properties"]["evidence"] for x in alg_kaynakli)
    # YARA'nın kripto etiketli isabeti (OpenSSL_Library) de KRDL001
    assert any(x["properties"].get("yara_rule") == "OpenSSL_Library" for x in k1)


def test_sarif_eski_yara_dizgisi_dogru_kurala(tmp_path):
    """P-S1 öncesi 'Kural (etiket,...)' dizgisi: paketleyici etiketi KRDL004, derleyici /
    sıkıştırma KRDL007 (not); '(unknown)' iletisi yok."""
    sonuc, ws = _kur("head_openssl", tmp_path)
    sonuclar = _sarif_sonuc(_uret(sonuc, ws))
    kural = {x["properties"]["yara_rule"]: x for x in sonuclar if "yara_rule" in x.get("properties", {})}
    assert kural["MPRESS_Packed"]["ruleId"] == "KRDL004"
    assert kural["MPRESS_Packed"]["properties"]["tags"] == ["packer", "mpress"]
    assert kural["Zlib_Library"]["ruleId"] == "KRDL007"
    assert kural["Zlib_Library"]["level"] == "note"
    assert kural["Stack_String_Construction"]["ruleId"] == "KRDL005"
    assert kural["OpenSSL_Library"]["ruleId"] == "KRDL001"
    assert not any("(unknown)" in x["message"]["text"] for x in sonuclar)


def test_sarif_ps1_yara_kaydi_kanitla(tmp_path):
    """P-S1 yara_hits: kural, etiket, koşul, dosya ofseti iletide; derleyici izi şüpheli değil."""
    sonuc, ws = _kur("ps1_w32", tmp_path)
    r = _uret(sonuc, ws)
    msvc = [x for x in _sarif_sonuc(r) if x.get("properties", {}).get("yara_rule") == "MSVC_Compiler"]
    assert len(msvc) == 1
    assert msvc[0]["ruleId"] == "KRDL007" and msvc[0]["level"] == "note"
    assert "file offsets: 216" in msvc[0]["message"]["text"]
    assert "rich_header" in msvc[0]["message"]["text"]
    # detected_tech aynı isabeti taşıyor: iki kez sayılmaz
    assert sum(1 for x in _sarif_sonuc(r) if "MSVC_Compiler" in x["message"]["text"]) == 1


def test_sarif_ad_guvenilirligi_uyarisi(tmp_path):
    """Eskiden hiç üretilmeyen avg_naming_confidence okunuyordu: KRDL002 hiçbir koşuda yoktu."""
    sonuc, ws = _kur("urun_openssl", tmp_path)
    k2 = [x for x in _sarif_sonuc(_uret(sonuc, ws)) if x["ruleId"] == "KRDL002"]
    assert len(k2) == 1 and k2[0]["level"] == "warning"
    assert "20 of 35" in k2[0]["message"]["text"]
    assert k2[0]["properties"]["labels"] == {"doğrulanmadı": 20, "kesin": 15}


def test_sarif_anti_debug_bulgulari(tmp_path):
    """HTML / Markdown'daki anti-debug bulguları SARIF'te de var (eskiden yoktu)."""
    sonuc, ws = _kur("ps1_w32", tmp_path)
    k3 = [x for x in _sarif_sonuc(_uret(sonuc, ws)) if x.get("properties", {}).get("source") == "anti_debug_findings"]
    assert sorted(x["properties"]["technique"] for x in k3) == [
        "GetTickCount", "IsDebuggerPresent", "QueryPerformanceCounter"]
    assert all(x["level"] == "note" for x in k3)  # güven 0,1: bilgi düzeyi


def test_sarif_taranamayan_bolum_bildirimi(tmp_path):
    """'taranmadı' ile 'temiz' ayrılır: P-S1 öncesi YARA alanı yok -> uyarı bildirimi."""
    sonuc, ws = _kur("head_cat", tmp_path)
    run = _uret(sonuc, ws)["sarif"]["runs"][0]
    notlar = {n["properties"]["section"]: n for n in run["invocations"][0]["toolExecutionNotifications"]
              if "section" in n["properties"]}
    assert notlar["yara"]["level"] == "warning"
    assert notlar["yara"]["properties"]["status"] == "no_data"
    assert notlar["packer"]["properties"]["status"] == "status_unknown"


# ---------------------------------------------------------------------------
# Dört üretici aynı şeyi söyler
# ---------------------------------------------------------------------------

_BASLIK = {"packer": "Detected Packer", "anti_debug": "Anti-Debug Findings", "yara": "YARA Matches",
           "capa": "capa Capabilities", "ioc": "Malware IOC", "crypto": "Crypto Algorithms",
           "naming": "Name Reliability", "compositions": "Algorithm Compositions"}


@pytest.mark.parametrize("etiket", ["head_cat", "head_openssl", "urun_cat", "urun_openssl",
                                    "p08_cat", "ps1_true", "ps1_w32"])
def test_dort_uretici_ayni_durum(tmp_path, etiket):
    sonuc, ws = _kur(etiket, tmp_path)
    r = _uret(sonuc, ws)
    js = r["json"]["report_sections"]
    sarif = r["sarif"]["runs"][0]["properties"]["report_sections"]
    assert set(js) == set(SECTION_ORDER)
    for k in SECTION_ORDER:
        assert js[k]["status"] == sarif[k]["status"], k
        assert js[k]["summary"] == sarif[k]["summary"], k
        etiket_metni = status_label(js[k]["status"])
        assert etiket_metni in _md_bolum(r["md"], _BASLIK[k]), k
        assert etiket_metni in _html_bolum(r["html"], _BASLIK[k]), k
        assert etiket_metni in _html_bolum(r["temiz"], _BASLIK[k]), k


def test_sarif_ioc_bulgusu_krdl006(tmp_path):
    """Bilinen zararlı yazılım simgesi SARIF'te KRDL006 (HTML / Markdown ile aynı kayıt)."""
    from karadul.analyzers.sigdb_builtin.malware_tier1 import _SLIVER_SIGNATURES_DATA

    sonuc, ws = _kur("urun_cat", tmp_path)
    yol = ws.path / "reconstructed" / "signature_matches.json"
    veri = json.loads(yol.read_text())
    sembol, kayit = next(iter(_SLIVER_SIGNATURES_DATA.items()))
    veri["matches"].append({
        "original": sembol, "matched": sembol, "library": kayit["lib"], "libraries": None,
        "confidence": 0.9, "purpose": kayit["purpose"], "category": kayit["category"],
        "family": kayit["family"], "tier": kayit["tier"], "address": "00104000",
        "method": "string_ref"})
    yol.write_text(json.dumps(veri))
    k6 = [x for x in _sarif_sonuc(_uret(sonuc, ws)) if x["ruleId"] == "KRDL006"]
    assert len(k6) == 1 and k6[0]["level"] == "error"
    assert k6[0]["properties"]["family"] == "sliver"
