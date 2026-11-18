"""P-S3b kalem 5: gnulib kanalının yazmadığı adaylar raporda görünür.

``static/gnulib_candidates.json`` (P-S3; K-2: aday kaybolmaz) şimdiye dek yalnız diskteydi. Rapor
verisinin "Name Reliability" bölümü artık tutulan aday sayısını, nedenlere göre kırılımı, varlık
kanıtı satırını ve adayları (anahtar, aday ad, kanal, neden, kanıt) taşıyor; JSON, Markdown, HTML ve
temiz çıktının raporu aynı veriden yazıyor. Yapıt yoksa (kanal koşmadı) bölüm aday iddia etmez.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from karadul.core.report_generator import ReportGenerator
from karadul.core.result import PipelineResult
from karadul.core.workspace import Workspace
from karadul.reporting.html_report import HTMLReporter
from karadul.reporting.json_report import JSONReporter
from karadul.reporting.markdown_report import MarkdownReporter
from karadul.reporting.report_data import build_report_data, gnulib_candidates

FIX = Path(__file__).parent / "fixtures" / "p07_rapor"

# Gerçek bir ürün koşusunun (P-S3 A, coreutils cat) aday kaydından kısaltılmış.
KAYIT = {
    "schema": "karadul.gnulib_candidates", "schema_version": 1,
    "presence": {"sufficient": True, "min_modules": 2, "found": [],
                 "evidence": "gnulib varlık kanıtı yeterli: 4 / 2 bağımsız modül — progname (progname.c, dizgi: '…')"},
    "layout_rule": {"names": ["full_write", "hard_locale", "version_etc"], "thin_caller_max_callees": 2},
    "decisions": [
        {"key": "FUN_00103568", "name": "usage", "channel": "dizgi_parmak_izi",
         "evidence": "dizgi parmak izi ['Usage: %s'] (argmatch.c); ikilide tek aday", "decision": "applied"},
        {"key": "FUN_00106bc0", "name": "version_etc", "channel": "dizgi_parmak_izi",
         "evidence": "dizgi parmak izi ['Written by'] (version-etc.c); ikilide tek aday",
         "decision": "withheld", "reason": "lto_yerlesimi", "caller_callee_counts": [2, 2, 1],
         "evidence_layout": "çağıranların hepsi ince sarmalayıcı (≤ 2 çağrı; çağrı sayıları [2, 2, 1])"},
        {"key": "FUN_00106b40", "name": "full_write", "channel": "cagri_bicimi",
         "evidence": "çağrı şekli: ['write'] çağırır, çağrı sayısı 2 (full-write.c); ikilide tek aday",
         "decision": "withheld", "reason": "lto_yerlesimi", "caller_callee_counts": [2],
         "evidence_layout": "çağıranların hepsi ince sarmalayıcı (≤ 2 çağrı; çağrı sayıları [2])"},
        {"key": "FUN_00101000", "name": "close_stdout", "channel": "dizgi_parmak_izi",
         "evidence": "dizgi parmak izi ['write error'] (closeout.c); ikilide tek aday",
         "decision": "withheld", "reason": "gnulib_kaniti_yetersiz",
         "evidence_presence": "gnulib varlık kanıtı yok (gereken 2 bağımsız modül)"},
    ],
    "ambiguous": {},
}


def _kur(tmp_path: Path, kayit: dict | None) -> tuple[PipelineResult, Workspace]:
    src = FIX / "urun_cat"
    ws = Workspace(tmp_path / "ws", "urun_cat", workspace_dir=tmp_path / "ws" / "urun_cat")
    ws.create()
    for f in src.rglob("*.json"):
        rel = f.relative_to(src)
        if rel.parts[0] == "reports":
            continue
        dst = ws.path / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(f, dst)
    if kayit is not None:
        (ws.path / "static").mkdir(parents=True, exist_ok=True)
        (ws.path / "static" / "gnulib_candidates.json").write_text(
            json.dumps(kayit, ensure_ascii=False), encoding="utf-8")
    tam = PipelineResult.from_dict(json.loads((src / "reports" / "pipeline_result.json").read_text()))
    sonuc = PipelineResult(target_name=tam.target_name, target_hash=tam.target_hash, workspace_path=ws.path)
    for ad, sr in tam.stages.items():
        if ad != "report":
            sonuc.add_stage_result(sr)
    return sonuc, ws


def test_aday_kaydi_rapor_verisinde(tmp_path):
    sonuc, ws = _kur(tmp_path, KAYIT)
    sec = build_report_data(sonuc, ws).section("naming")
    gc = sec.extra["gnulib_candidates"]
    assert gc["withheld"] == 3 and gc["applied"] == 1
    assert gc["by_reason"] == {"lto_yerlesimi": 2, "gnulib_kaniti_yetersiz": 1}
    assert [i["name"] for i in gc["items"]] == ["version_etc", "full_write", "close_stdout"]
    assert "ince sarmalayıcı" in gc["items"][0]["evidence"]
    assert "varlık kanıtı yok" in gc["items"][2]["evidence"]
    assert "3 candidate name(s) withheld, no name written" in sec.summary
    assert "gnulib_kaniti_yetersiz: 1" in sec.summary and "lto_yerlesimi: 2" in sec.summary


def test_aday_kaydi_dort_ciktida(tmp_path):
    sonuc, ws = _kur(tmp_path, KAYIT)
    js = json.loads(JSONReporter().generate(sonuc, ws).read_text())
    md = MarkdownReporter().generate(sonuc, ws).read_text()
    html = HTMLReporter().generate(sonuc, ws).read_text()
    temiz = ReportGenerator(sonuc, ws).generate_html()
    assert json.dumps(js, ensure_ascii=False).count("3 candidate name(s) withheld") >= 1
    for metin in (md, html, temiz):
        assert "gnulib candidates (no name written)" in metin
        assert "FUN_00106bc0" in metin and "lto_yerlesimi" in metin
        assert "3 candidate name(s) withheld" in metin


def test_aday_yoksa_sifir_yazilir_ama_iddia_yok(tmp_path):
    kayit = dict(KAYIT, decisions=[KAYIT["decisions"][0]])
    sonuc, ws = _kur(tmp_path, kayit)
    sec = build_report_data(sonuc, ws).section("naming")
    assert sec.extra["gnulib_candidates"]["withheld"] == 0
    assert "no candidate withheld" in sec.summary
    md = MarkdownReporter().generate(sonuc, ws).read_text()
    assert "gnulib candidates (no name written)" not in md


def test_yapit_yoksa_bolum_aday_iddia_etmez(tmp_path):
    """Kanal koşmadıysa (yapıt yok) 0 aday yazılmaz; bölüm eskisi gibi."""
    sonuc, ws = _kur(tmp_path, None)
    assert gnulib_candidates(ws) is None
    sec = build_report_data(sonuc, ws).section("naming")
    assert "gnulib_candidates" not in sec.extra
    assert "gnulib channel" not in sec.summary
