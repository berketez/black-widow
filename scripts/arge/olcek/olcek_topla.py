#!/usr/bin/env python
"""ÖLÇEK kalem 3: var olan koşulardan ikili başına süre / boyut / fonksiyon / disk künyesi.

Yeni Ghidra koşusu YOK. Yalnız var olan çalışma alanları okunur:
- ``reports/pipeline_result.json``: aşama süreleri, ``reconstruct.stats`` içindeki ``timing_*``;
- ``raw/target_info.json``: hedef türü ve dosya boyutu;
- ``static/ghidra_status.json``: Ghidra süresi, fonksiyon sayıları (program / thunk / dış);
- ``static/ghidra_log.txt``: "Otomatik analiz: N sn";
- ``static/ghidra_output/decompiled.json``: ``duration_seconds`` (toplam decompile süresi);
- ``static/universal_slice.json`` varsa analiz edilen dilim;
- disk: çalışma alanı ve ``out/`` dizini için ayrılan bayt (st_blocks × 512) ve dosya sayısı;
  ``static/ghidra_output`` içindeki büyük JSON'ların boyutu.

Kullanım (depo kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcek/olcek_topla.py \
        --kok ~/karadul_olcum/runs/urun-onarim-a62f15e --etiket a62f15e \
        --cikti ~/karadul_olcum/runs/arge-2026-11-19/olcek/olcek_a62f15e.json

Birden çok ``--kok`` / ``--etiket`` çifti verilebilir (aynı sırada).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

_ANALIZ = re.compile(r"^Otomatik analiz: ([0-9.]+) sn", re.M)
_CFG = re.compile(r"^CFG: (\d+) fonksiyon, (\d+) blok, (\d+) edge", re.M)
_PCODE = re.compile(r"^P-Code: (\d+) fonksiyon, (\d+) op", re.M)
_CG = re.compile(r"^Call graph: (\d+) node, (\d+) edge", re.M)
_DIZGI = re.compile(r"^String'ler: (\d+)", re.M)
# Ghidra köprüsünün adımları ``_save_output`` ile adım biter bitmez yazılır
# (karadul/ghidra/headless.py:_analyze_pyghidra). Dosyaların değişim zamanı arka arkaya
# farkı adımın süresini verir (bir önceki dosyanın yazılışından bu dosyanın yazılışına).
GHIDRA_ADIM_SIRASI = (
    ("functions.json", "otomatik_analiz+fonksiyonlar"),
    ("strings.json", "dizgiler"),
    ("call_graph.json", "cagri_grafigi"),
    ("decompiled.json", "decompile"),
    ("types.json", "tipler"),
    ("xrefs.json", "xref"),
    ("pcode.json", "pcode_yazimi"),
    ("cfg.json", "cfg"),
    ("function_id.json", "function_id"),
    ("bsim_shadow.json", "bsim"),
    ("combined_results.json", "ozet"),
)


def ghidra_adim_sureleri(go: Path, ghidra_sn: float | None) -> dict[str, Any]:
    """``ghidra_output/`` dosyalarının değişim zamanından adım süreleri (sn).

    Başlangıç = ``combined_results.json`` zamanı − ``ghidra_sn`` (köprünün toplam süresi).
    İlk adım (``functions.json``'a kadar) JVM açılışı + içe aktarma + otomatik analiz + fonksiyon
    listesini kapsar. Dosyası olmayan adım atlanır; süresi bir sonrakine eklenir.
    """
    zaman = {}
    for ad, _ in GHIDRA_ADIM_SIRASI:
        try:
            zaman[ad] = (go / ad).stat().st_mtime
        except OSError:
            pass
    if "combined_results.json" not in zaman or not ghidra_sn:
        return {}
    onceki = zaman["combined_results.json"] - float(ghidra_sn)
    out: dict[str, Any] = {}
    for ad, etiket in GHIDRA_ADIM_SIRASI:
        if ad in zaman:
            out[etiket] = round(zaman[ad] - onceki, 3)
            onceki = zaman[ad]
    return out
_BUYUK_JSON = ("cfg.json", "xrefs.json", "functions.json", "call_graph.json", "decompiled.json",
               "pcode.jsonl", "strings.json", "types.json", "bsim_matches.json", "bsim_shadow.json")


def _oku_json(p: Path) -> Any:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _disk(kok: Path) -> dict[str, int]:
    """Ayrılan bayt (st_blocks*512), görünen bayt ve dosya sayısı. Bağlar izlenmez."""
    ayrilan = gorunen = dosya = 0
    if not kok.exists():
        return {"ayrilan": 0, "gorunen": 0, "dosya": 0}
    for dp, dn, fn in os.walk(kok, followlinks=False):
        for f in fn:
            try:
                st = os.lstat(os.path.join(dp, f))
            except OSError:
                continue
            ayrilan += st.st_blocks * 512
            gorunen += st.st_size
            dosya += 1
    return {"ayrilan": ayrilan, "gorunen": gorunen, "dosya": dosya}


def ikili_kunyesi(pr_yolu: Path, etiket: str, kok: Path) -> dict[str, Any]:
    ws = pr_yolu.parent.parent  # .../<zaman>/reports/pipeline_result.json
    pr = _oku_json(pr_yolu) or {}
    k: dict[str, Any] = {"etiket": etiket, "anahtar": str(pr_yolu.relative_to(kok)),
                         "calisma_alani": str(ws)}
    rep = _oku_json(ws / "reports" / "report.json") or {}
    k["surum"] = rep.get("karadul_version")
    ti = _oku_json(ws / "raw" / "target_info.json") or {}
    k["tur"] = ti.get("target_type")
    k["dosya_bayt"] = ti.get("file_size")
    us = _oku_json(ws / "static" / "universal_slice.json")
    k["dilim"] = None
    if isinstance(us, dict) and us.get("path"):
        p = ws / "raw" / us["path"]
        k["dilim"] = us.get("selected")
        try:
            k["analiz_bayt"] = p.stat().st_size
        except OSError:
            k["analiz_bayt"] = None
    else:
        k["analiz_bayt"] = k["dosya_bayt"]
    k["toplam_sn"] = pr.get("total_duration")
    k["basari"] = pr.get("success")
    asamalar = pr.get("stages") or {}
    k["asama_sn"] = {ad: (s or {}).get("duration_seconds") for ad, s in asamalar.items()}
    st_stats = (asamalar.get("static") or {}).get("stats") or {}
    rc_stats = (asamalar.get("reconstruct") or {}).get("stats") or {}
    k["ghidra_sn"] = st_stats.get("ghidra_duration")
    k["fonk_program"] = st_stats.get("ghidra_function_count")
    k["fonk_toplam"] = st_stats.get("ghidra_function_total")
    k["fonk_thunk"] = st_stats.get("ghidra_thunk_count")
    k["dizgi_ghidra"] = st_stats.get("ghidra_string_count")
    k["cg_kenar"] = st_stats.get("ghidra_call_graph_edges")
    k["adim_sn"] = {a[len("timing_"):]: v for a, v in rc_stats.items()
                    if a.startswith("timing_") and isinstance(v, (int, float))}
    gs = _oku_json(ws / "static" / "ghidra_status.json") or {}
    fn = gs.get("functions") or {}
    if k["fonk_toplam"] is None:
        k["fonk_toplam"] = fn.get("total")
    if k["fonk_program"] is None:
        k["fonk_program"] = fn.get("program_function_count")
    if k["ghidra_sn"] is None:
        k["ghidra_sn"] = gs.get("duration_seconds")
    k["proje_saklandi"] = (gs.get("project") or {}).get("kept")
    try:
        log = (ws / "static" / "ghidra_log.txt").read_text(encoding="utf-8", errors="replace")
    except OSError:
        log = ""
    m = _ANALIZ.search(log)
    k["otomatik_analiz_sn"] = float(m.group(1)) if m else None
    m = _CFG.search(log)
    k["cfg_blok"], k["cfg_kenar"] = (int(m.group(2)), int(m.group(3))) if m else (None, None)
    m = _PCODE.search(log)
    k["pcode_op"] = int(m.group(2)) if m else None
    m = _DIZGI.search(log)
    k["dizgi_ghidra_log"] = int(m.group(1)) if m else None
    k["ghidra_adim_sn"] = ghidra_adim_sureleri(ws / "static" / "ghidra_output", k["ghidra_sn"])
    dec = _oku_json(ws / "static" / "ghidra_output" / "decompiled.json") or {}
    k["decompile_sn"] = dec.get("duration_seconds")
    k["decompile_isci"] = dec.get("threads")
    go = ws / "static" / "ghidra_output"
    k["ghidra_json_bayt"] = {}
    for ad in _BUYUK_JSON:
        try:
            k["ghidra_json_bayt"][ad] = (go / ad).stat().st_size
        except OSError:
            pass
    k["decompiled_c_dosya"] = (len(list((go / "decompiled").iterdir()))
                               if (go / "decompiled").is_dir() else 0)
    k["disk_calisma_alani"] = _disk(ws)
    k["disk_static"] = _disk(ws / "static")
    k["disk_reconstructed"] = _disk(ws / "reconstructed")
    k["disk_deobfuscated"] = _disk(ws / "deobfuscated")
    # urun_kos düzeni: <ikili>/{out,ws}
    out = None
    for p in pr_yolu.parents:
        if (p / "out").is_dir() and (p / "ws").is_dir():
            out = p / "out"
            break
    k["disk_out"] = _disk(out) if out else None
    return k


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--kok", action="append", required=True, type=Path)
    ap.add_argument("--etiket", action="append", required=True)
    ap.add_argument("--cikti", required=True, type=Path)
    a = ap.parse_args(argv)
    if len(a.kok) != len(a.etiket):
        ap.error("--kok ve --etiket sayısı eşit olmalı")
    kayitlar = []
    for kok, et in zip(a.kok, a.etiket):
        kok = kok.expanduser().resolve()
        yollar = sorted(kok.rglob("reports/pipeline_result.json"))
        for p in yollar:
            kayitlar.append(ikili_kunyesi(p, et, kok))
        print(f"{et}: {len(yollar)} pipeline_result.json", file=sys.stderr)
    a.cikti.parent.mkdir(parents=True, exist_ok=True)
    a.cikti.write_text(json.dumps({"kayitlar": kayitlar}, ensure_ascii=False, indent=1),
                       encoding="utf-8")
    print(f"yazıldı: {a.cikti} ({len(kayitlar)} kayıt)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
