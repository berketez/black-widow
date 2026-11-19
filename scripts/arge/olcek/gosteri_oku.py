#!/usr/bin/env python
"""ÖLÇEK kalem 3: gösteri koşusunun (Ollama arm64 dilimi) o anki durumunu SALT OKUR çıkar.

Gösteri dizinine hiçbir şey yazılmaz; Ghidra'ya ya da süreçlere dokunulmaz. Okunanlar:
- ``BASLADI``, ``CIKIS``, ``BITTI`` (varsa), ``deneme1_*`` künyeleri ve ``/usr/bin/time -l`` satırları;
- çalışma alanındaki dosyaların değişim zamanı ve boyutu (adım süreleri bunlardan);
- ``ghidra_output`` JSON'larının yalnız BAŞ kısmı (ilk 600 bayt: toplam sayılar);
- ``decompiled.json``'un özet alanları (fonksiyon listesi hariç);
- disk: çalışma alanı, Ghidra projesi, ``decompiled/`` dosya sayısı.

Kullanım (depo kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcek/gosteri_oku.py \
        --gosteri ~/karadul_olcum/runs/gosteri-2026-11-19/ollama \
        --cikti ~/karadul_olcum/runs/arge-2026-11-19/olcek/gosteri_<saat>.json
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from olcek_topla import GHIDRA_ADIM_SIRASI, _disk  # noqa: E402

_TIME_L = re.compile(r"^\s*(\d+(?:\.\d+)?)\s+real\s+(\d+(?:\.\d+)?)\s+user\s+(\d+(?:\.\d+)?)\s+sys", re.M)
_TIME_KV = re.compile(r"^\s*(\d+)\s+(maximum resident set size|peak memory footprint)\s*$", re.M)
_SAYI = re.compile(r'"(total|program_function_count|thunk_count|total_functions|total_blocks|'
                   r'total_edges|total_strings_with_xrefs|total_globals_with_xrefs)": (\d+)')


def _metin(p: Path) -> str | None:
    try:
        return p.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None


def _zaman_damgasi(s: str | None) -> float | None:
    if not s:
        return None
    try:
        return dt.datetime.strptime(s, "%Y-%m-%d %H:%M:%S").timestamp()
    except ValueError:
        return None


def time_l(log: str | None) -> dict[str, Any]:
    if not log:
        return {}
    out: dict[str, Any] = {}
    m = _TIME_L.search(log)
    if m:
        out["real_sn"], out["user_sn"], out["sys_sn"] = (float(x) for x in m.groups())
    for v, ad in _TIME_KV.findall(log):
        out["azami_rss_bayt" if ad.startswith("maximum") else "tepe_ayak_izi_bayt"] = int(v)
    return out


def bas_sayilar(p: Path) -> dict[str, int]:
    try:
        with open(p, "rb") as fh:
            bas = fh.read(600).decode("utf-8", errors="replace")
    except OSError:
        return {}
    return {k: int(v) for k, v in _SAYI.findall(bas)}


def kos(gosteri: Path) -> dict[str, Any]:
    g = gosteri.expanduser().resolve()
    r: dict[str, Any] = {"gosteri": str(g), "okuma_zamani": dt.datetime.now().isoformat(timespec="seconds")}
    for ad in ("BASLADI", "BITTI", "CIKIS", "commit", "deneme1_BASLADI", "deneme1_BITTI", "deneme1_CIKIS"):
        r[ad] = _metin(g / ad)
    r["kosu_suruyor"] = r["CIKIS"] is None
    r["deneme1_time"] = time_l(_metin(g / "deneme1_kosu.log"))
    r["deneme2_time"] = time_l(_metin(g / "kosu.log"))
    r["girdi_bayt"] = (g / "girdi" / "Ollama").stat().st_size if (g / "girdi" / "Ollama").exists() else None
    r["girdi_surum"] = _metin(g / "girdi" / "surum")
    wss = sorted((g / "ws" / "workspaces").glob("*/*"))
    if not wss:
        return r
    ws = wss[-1]
    r["calisma_alani"] = str(ws)
    bas = _zaman_damgasi(r["BASLADI"])
    dosyalar = []
    for p in sorted(list((ws / "raw").glob("*")) + list((ws / "static").glob("*"))
                    + list((ws / "static" / "ghidra_output").glob("*"))
                    + list((ws / "reconstructed").glob("*")) + list((ws / "reports").glob("*"))):
        try:
            st = p.stat()
        except OSError:
            continue
        dosyalar.append({"yol": str(p.relative_to(ws)), "bayt": st.st_size,
                         "bas_sonra_sn": round(st.st_mtime - bas, 1) if bas else None})
    r["dosyalar"] = dosyalar
    # Analiz edilen dilimin kod bölümü (``__text``) boyutu: yalnız bölüm başlığı (açık kaynak, MIT).
    from metin_boyutu import metin  # noqa: E402
    dilim = next((p for p in (ws / "raw").glob("*_arm64") if p.is_file()), None)
    r["metin_bayt"] = metin(dilim) if dilim else None
    go = ws / "static" / "ghidra_output"
    # Köprünün ``scripts_output`` sözlüğünde tuttuğu çıktıların disk boyutu (headless.py:362-605).
    # pcode.jsonl ayrı: ``_all_functions`` listesi yazılınca bırakılır (headless.py:463-465).
    tutulan = ("functions.json", "strings.json", "call_graph.json", "decompiled.json", "types.json",
               "xrefs.json", "pcode.json", "cfg.json", "function_id.json", "bsim_matches.json")
    r["kopru_sozluk_json_bayt"] = sum((go / ad).stat().st_size for ad in tutulan if (go / ad).exists())
    r["pcode_jsonl_bayt"] = (go / "pcode.jsonl").stat().st_size if (go / "pcode.jsonl").exists() else None
    r["ghidra_bas_sayilari"] = {ad: bas_sayilar(go / ad) for ad in
                                ("functions.json", "cfg.json", "call_graph.json", "xrefs.json",
                                 "strings.json")}
    # Adım süreleri: değişim zamanları arka arkaya (ilk adım: Ghidra'dan önceki son dosyadan).
    # Ghidra'dan ÖNCE yazılan dosyalar (macho.py:251-423): ham kopya, dilim, otool, strings, nm, lief.
    on_adlar = ("static/dynamic_libraries.json", "static/load_commands.txt", "static/strings_raw.json",
                "static/symbols.json", "static/lief_analysis.json", "static/universal_slice.json")
    on = [d["bas_sonra_sn"] for d in dosyalar if (d["yol"].startswith("raw/") or d["yol"] in on_adlar)
          and d["bas_sonra_sn"] is not None]
    onceki = max(on) if on else None
    adim: dict[str, float] = {}
    for ad, etiket in GHIDRA_ADIM_SIRASI:
        p = go / ad
        if p.exists() and bas and onceki is not None:
            t = p.stat().st_mtime - bas
            adim[etiket] = round(t - onceki, 1)
            onceki = t
    r["ghidra_on_araclar_bitis_sn"] = max(on) if on else None
    # Statik aşamanın köprü dışı kısmı = Ghidra öncesi araçlar + köprü sonrası (ikili istihbarat,
    # YARA, capa). Köprü sonrası bitişi: capa_scan.json ya da intelligence_report.json'ın en geç olanı.
    zam = {d["yol"]: d["bas_sonra_sn"] for d in dosyalar}
    kopru_bitis = zam.get("static/ghidra_output/combined_results.json")
    sonrasi = [zam[y] for y in ("static/capa_scan.json", "static/intelligence_report.json") if y in zam]
    on_sure = (max(on) if on else 0.0)
    r["static_kopru_disi_sn"] = (round(on_sure + (max(sonrasi) - kopru_bitis), 1)
                                 if kopru_bitis is not None and sonrasi else None)
    r["ghidra_adim_sn_mtime"] = adim
    r["son_dosyadan_beri_sn"] = (round(dt.datetime.now().timestamp() - bas - onceki, 1)
                                 if bas and onceki is not None else None)
    st = ws / "static" / "ghidra_status.json"
    r["ghidra_status"] = json.loads(st.read_text(encoding="utf-8")) if st.exists() else None
    kopru = (r["ghidra_status"] or {}).get("duration_seconds")
    r["ghidra_adim_pay"] = ({k: round(v / kopru, 4) for k, v in adim.items()} if kopru else None)
    lg = ws / "static" / "ghidra_log.txt"
    r["ghidra_log"] = lg.read_text(encoding="utf-8", errors="replace") if lg.exists() else None
    pr = ws / "reports" / "pipeline_result.json"
    r["pipeline_result"] = json.loads(pr.read_text(encoding="utf-8")) if pr.exists() else None
    try:
        dec = json.loads((go / "decompiled.json").read_text(encoding="utf-8"))
        r["decompile_ozet"] = {k: v for k, v in dec.items() if k != "functions"}
    except (OSError, ValueError):
        r["decompile_ozet"] = None
    r["decompiled_c_dosya"] = (sum(1 for _ in os.scandir(go / "decompiled"))
                               if (go / "decompiled").is_dir() else 0)
    r["disk_calisma_alani"] = _disk(ws)
    r["disk_ghidra_projesi"] = _disk(ws / "static" / "ghidra_project")
    r["disk_cache"] = _disk(g / "cache")
    return r


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--gosteri", required=True, type=Path)
    ap.add_argument("--cikti", required=True, type=Path)
    a = ap.parse_args(argv)
    r = kos(a.gosteri)
    a.cikti.parent.mkdir(parents=True, exist_ok=True)
    a.cikti.write_text(json.dumps(r, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps({k: r.get(k) for k in ("okuma_zamani", "kosu_suruyor", "CIKIS",
                                             "ghidra_adim_sn_mtime", "son_dosyadan_beri_sn",
                                             "deneme1_time", "deneme2_time")},
                     ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
