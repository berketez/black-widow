"""P07 — raporlar: veriyle sözleşme. Gerçek koşu yapıtlarıyla (sentetik şema değil).

Fikstürler (``tests/fixtures/p07_rapor``) gerçek koşulardan değiştirilmeden kopyalandı;
kaynak yolu ve sha256 ``MANIFEST.json``'da:
  - ``head_cat`` / ``head_openssl``: 1.23.1 ürün koşusu (``genel-tarama-2026-11-18``), P-S1
    öncesi tarama sözleşmesi, şema 1 imza kaydı.
  - ``urun_cat`` / ``urun_openssl``: 397ca3b ürün koşusu (P07 ölçümü), şema 2 imza kaydı,
    P04a bekletmesi, P06 algoritma kaydı.
  - ``p08_cat``: P08 koşusu (yeni imza veritabanı; çok kitaplıklı adda ``library`` boş).
  - ``ps1_true`` / ``ps1_w32``: P-S1 koşuları (``status`` / ``yara_hits`` / ``capa_scan.json``).
  - ``hata_enjekte``: P-S1'in gerçek dedektöre hata enjekte ettiği w32 koşusunun durum alanları.

Her test ürünün dört raporlayıcısını ve temiz çıktının ``ReportGenerator``'ını, ``ReportStage``'in
kurduğu ``PipelineResult`` ile (report aşaması yok) çağırır.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path

from karadul.core.report_generator import ReportGenerator
from karadul.core.result import PipelineResult
from karadul.core.workspace import Workspace
from karadul.reporting.html_report import HTMLReporter
from karadul.reporting.json_report import JSONReporter
from karadul.reporting.markdown_report import MarkdownReporter
from karadul.reporting.report_data import build_report_data
from karadul.reporting.sarif_report import SARIFReporter

FIX = Path(__file__).parent / "fixtures" / "p07_rapor"


def _kur(etiket: str, tmp_path: Path) -> tuple[PipelineResult, Workspace]:
    """Fikstürü çalışma alanına kopyala; ReportStage'in sonucunu kur."""
    src = FIX / etiket
    ws_dir = tmp_path / "ws" / etiket
    ws = Workspace(tmp_path / "ws", etiket, workspace_dir=ws_dir)
    ws.create()
    for f in src.rglob("*.json"):
        rel = f.relative_to(src)
        if rel.parts[0] == "reports":
            continue
        dst = ws.path / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(f, dst)
    tam = PipelineResult.from_dict(json.loads((src / "reports" / "pipeline_result.json").read_text()))
    sonuc = PipelineResult(target_name=tam.target_name, target_hash=tam.target_hash,
                           workspace_path=ws.path)
    for ad, sr in tam.stages.items():
        if ad != "report":
            sonuc.add_stage_result(sr)
    sonuc.total_duration = sum(sr.duration_seconds for sr in sonuc.stages.values())
    return sonuc, ws


def _uret(sonuc: PipelineResult, ws: Workspace) -> dict:
    return {
        "json": json.loads(JSONReporter().generate(sonuc, ws).read_text()),
        "md": MarkdownReporter().generate(sonuc, ws).read_text(),
        "html": HTMLReporter().generate(sonuc, ws).read_text(),
        "sarif": json.loads(SARIFReporter().generate(sonuc, ws).read_text()),
        "temiz": ReportGenerator(sonuc, ws).generate_html(),
    }


def _sarif_sonuc(r: dict) -> list[dict]:
    return r["sarif"]["runs"][0]["results"]


def _md_bolum(md: str, baslik: str) -> str:
    return md.split(f"## {baslik}")[1].split("\n## ")[0]


def _html_bolum(html: str, baslik: str) -> str:
    return html.split(f"<h2>{baslik}</h2>")[1].split("<h2>")[0]


# ---------------------------------------------------------------------------
# fikstürler gerçek ve değişmemiş
# ---------------------------------------------------------------------------

def test_fiksturler_gercek_kopyalarla_ayni():
    manifest = json.loads((FIX / "MANIFEST.json").read_text())
    assert len(manifest) >= 30
    for rel, kayit in manifest.items():
        assert hashlib.sha256((FIX / rel).read_bytes()).hexdigest() == kayit["sha256"], rel


# ---------------------------------------------------------------------------
# ARAYUZ-07: kaynağı olmayan sayaçlar
# ---------------------------------------------------------------------------

def test_kaynaksiz_sayac_yok(tmp_path):
    sonuc, ws = _kur("urun_cat", tmp_path)
    st = sonuc.stages["reconstruct"].stats
    assert "coverage_percent" not in st and "modules_extracted" not in st
    assert "steps_completed" not in sonuc.stages["deobfuscate"].stats
    r = _uret(sonuc, ws)
    ozet = r["json"]["summary"]
    assert ozet["coverage_percent"] is None
    assert ozet["total_modules"] is None
    assert ozet["deobfuscation_steps"] is None
    for metin in (r["html"], r["temiz"]):
        kutular = re.findall(r'<div class="value">([^<]*)</div><div class="label">([^<]*)</div>', metin)
        assert not [k for k in kutular if "N/A" in k[0]], kutular
    assert "N/A%" not in r["md"] + r["html"] + r["temiz"]
    assert not re.search(r"\*\*(Steps completed|Modules extracted|Coverage):\*\*", r["md"])


# ---------------------------------------------------------------------------
# ARAYUZ-08: temiz rapor güvenlik bölümleri
# ---------------------------------------------------------------------------

def test_temiz_rapor_guvenlik_bolumleri_durumuyla(tmp_path):
    sonuc, ws = _kur("urun_cat", tmp_path)
    temiz = _uret(sonuc, ws)["temiz"]
    for baslik in ("Detected Packer", "Anti-Debug Findings", "YARA Matches", "capa Capabilities",
                   "Malware IOC", "Crypto Algorithms", "Name Reliability"):
        assert f"<h2>{baslik}</h2>" in temiz, baslik
    assert "STATUS NOT RECORDED" in _html_bolum(temiz, "Detected Packer")
    assert "CLEAN" in _html_bolum(temiz, "Malware IOC")


def test_temiz_rapor_anti_debug_tablosu(tmp_path):
    sonuc, ws = _kur("ps1_w32", tmp_path)
    temiz = _uret(sonuc, ws)["temiz"]
    bolum = _html_bolum(temiz, "Anti-Debug Findings")
    assert "FINDINGS" in bolum and "GetTickCount" in bolum and "IsDebuggerPresent" in bolum


# ---------------------------------------------------------------------------
# ARAYUZ-02: IOC okuma yolu ve "veri yok" / "IOC yok" ayrımı
# ---------------------------------------------------------------------------

def test_ioc_sema2_temiz_sema1_veri_yok(tmp_path):
    sonuc, ws = _kur("urun_cat", tmp_path)
    r = _uret(sonuc, ws)
    assert r["json"]["report_sections"]["ioc"]["status"] == "clean"
    assert "none from a known-malware family" in _md_bolum(r["md"], "Malware IOC")
    sonuc2, ws2 = _kur("head_cat", tmp_path / "eski")
    r2 = _uret(sonuc2, ws2)
    assert r2["json"]["report_sections"]["ioc"]["status"] == "no_data"
    assert "schema 1" in _md_bolum(r2["md"], "Malware IOC")


def test_ioc_bulgusu_dort_uretecide(tmp_path):
    """Gerçek şema 2 kaydına ürünün yerleşik Sliver imzasından, yazıcının alanlarıyla bir kayıt."""
    from karadul.analyzers.sigdb_builtin.malware_tier1 import _SLIVER_SIGNATURES_DATA

    sonuc, ws = _kur("urun_cat", tmp_path)
    yol = ws.path / "reconstructed" / "signature_matches.json"
    veri = json.loads(yol.read_text())
    sembol, kayit = next(iter(_SLIVER_SIGNATURES_DATA.items()))
    yeni = {"original": sembol, "matched": sembol, "library": kayit["lib"], "libraries": None,
            "confidence": 0.9, "purpose": kayit["purpose"], "category": kayit["category"],
            "family": kayit["family"], "tier": kayit["tier"], "address": "00104000", "method": "string_ref"}
    assert set(yeni) == set(veri["matches"][0])  # yazıcının alan kümesi
    veri["matches"].append(yeni)
    yol.write_text(json.dumps(veri))
    r = _uret(sonuc, ws)
    assert r["json"]["report_sections"]["ioc"]["status"] == "findings"
    for metin in (_md_bolum(r["md"], "Malware IOC"), _html_bolum(r["html"], "Malware IOC"),
                  _html_bolum(r["temiz"], "Malware IOC")):
        assert sembol in metin and "sliver" in metin


# ---------------------------------------------------------------------------
# Tarama durumları (P-S1 sözleşmesi ve eski sözleşme)
# ---------------------------------------------------------------------------

def test_ps1_durumlari(tmp_path):
    sonuc, ws = _kur("ps1_true", tmp_path)
    data = build_report_data(sonuc, ws)
    ad = data.sections["anti_debug"]
    assert ad.status == "clean"
    assert "68,048 / 68,048 bytes" in ad.summary and "bytes layer desteklenmiyor" in ad.summary
    assert data.sections["capa"].status == "unsupported"
    assert "e_machine=183" in data.sections["capa"].summary
    assert data.sections["yara"].status == "clean"


def test_capa_k1_yetenek_adi_iddia_gibi_gosterilmez(tmp_path):
    sonuc, ws = _kur("ps1_w32", tmp_path)
    r = _uret(sonuc, ws)
    bolum = _html_bolum(r["html"], "capa Capabilities")
    assert "23 capa rule(s) matched in 35 function(s)" in bolum
    assert "Unverified candidates (decision K-1)" in bolum
    for metin in (r["html"], r["md"], r["temiz"], json.dumps(r["sarif"])):
        assert "link function at runtime" not in metin


def _ad_yapiti_degistir(ws: Workspace, kayit: dict) -> None:
    yol = ws.path / "static" / "anti_debug_findings.json"
    veri = json.loads(yol.read_text())
    veri.update(kayit)
    yol.write_text(json.dumps(veri))


def test_kismi_ve_hatali_tarama(tmp_path):
    """P-S1'in gerçek hata enjeksiyonu kayıtları: kısmi -> PARTIAL (bulgular alt sınır),
    hepsi düştü -> NOT SCANNED; eski 'ok' + 0 -> STATUS NOT RECORDED (temiz DEĞİL)."""
    enj = json.loads((FIX / "hata_enjekte/anti_debug_w32.json").read_text())
    alanlar = ("status", "status_reason", "layers", "total_findings")

    sonuc, ws = _kur("ps1_w32", tmp_path / "k")
    _ad_yapiti_degistir(ws, {k: enj["dizgi_katmani_duser/sonra"][0][k] for k in alanlar})
    sec = build_report_data(sonuc, ws).sections["anti_debug"]
    assert sec.status == "partial" and len(sec.items) == 3 and "lower bound" in sec.summary
    assert "strings katmani" in sec.summary

    sonuc, ws = _kur("ps1_w32", tmp_path / "h")
    kayit = {k: enj["hepsi_duser/sonra"][0][k] for k in alanlar}
    kayit["findings"] = []
    _ad_yapiti_degistir(ws, kayit)
    sec = build_report_data(sonuc, ws).sections["anti_debug"]
    assert sec.status == "not_scanned" and "imports katmani" in sec.summary

    sonuc, ws = _kur("head_cat", tmp_path / "e")
    sec = build_report_data(sonuc, ws).sections["anti_debug"]
    assert sonuc.stages["reconstruct"].stats["anti_debug_status"] == "ok"
    assert sec.status == "status_unknown"


# ---------------------------------------------------------------------------
# ARAYUZ-01: bileşim alanları ve K-1
# ---------------------------------------------------------------------------

def test_bilesim_alanlari_ve_bekleyen(tmp_path):
    sonuc, ws = _kur("urun_openssl", tmp_path)
    r = _uret(sonuc, ws)
    html = r["html"]
    assert "<td><code>?</code></td>" not in html
    bolum = _html_bolum(html, "Algorithm Compositions")
    assert "35 composition(s)" in bolum and "uncalibrated" in bolum
    assert "11 template match(es) held back" in bolum
    for ad in ("VPN Tunnel Setup Pipeline", "TLS Handshake Protocol"):  # bekleyen: iddia değil
        assert ad not in html and ad not in r["md"] and ad not in r["temiz"]
    # Aşama başına fonksiyonlar görünür (eskiden function_name okunuyordu -> '?')
    assert "FUN_0017452c: FUN_0017452c -&gt; FUN_00173fc0" in bolum
    assert "pipeline" in bolum


def test_bilesim_eski_kayitta_ithal_fonksiyonlar_gorunur(tmp_path):
    sonuc, ws = _kur("head_cat", tmp_path)
    bolum = _md_bolum(_uret(sonuc, ws)["md"], "Algorithm Compositions")
    assert "Matrix Solve Pipeline | pipeline" in bolum
    assert "Allocate: realloc, malloc -> Factor: fflush -> Free: free" in bolum


