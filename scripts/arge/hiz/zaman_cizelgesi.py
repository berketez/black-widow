#!/usr/bin/env python3
"""HIZ kalem 1: koşu çıktılarından aşama / adım zaman çizelgesi.

Salt okur. Ürün kodunu içe aktarmaz; yalnız çalışma alanındaki dosya zamanlarını ve
ürünün kendi yazdığı süre kayıtlarını (``ghidra_status.json``, ``ghidra_log.txt``,
``bsim_matches.json``, ``reports/pipeline_result.json``) okur.

Kullanım (depo kökünden):
    python scripts/arge/hiz/zaman_cizelgesi.py gosteri \
        --kok ~/karadul_olcum/runs/gosteri-2026-11-19/ollama \
        --cikti ~/karadul_olcum/runs/arge-2026-11-19/hiz/zaman
    python scripts/arge/hiz/zaman_cizelgesi.py taban \
        --kok ~/karadul_olcum/runs/urun-onarim-a62f15e \
        --cikti ~/karadul_olcum/runs/arge-2026-11-19/hiz/zaman

Ghidra iç adımlarının süresi ``static/ghidra_output/`` dosyalarının değişme zamanı
farkıdır: her adım çıktısını ``_save_output`` ile adım bitince yazar
(``karadul/ghidra/headless.py:359-606``). Bir adımın süresi = kendi dosyası − bir önceki
adımın dosyası. Ghidra başlangıcı iki alt sınırın büyüğüdür: ``static/lief_analysis.json``
(Ghidra'dan hemen önce yazılır, ``macho.py:416``) ve ``combined_results.json − süre``.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import statistics
import sys
from pathlib import Path

# headless.py'deki yazım sırası (satır 359-606). (dosya, adım adı)
GHIDRA_ADIMLARI = [
    ("functions.json", "JVM + içe aktarma + otomatik analiz + fonksiyon listesi"),
    ("strings.json", "dizgiler"),
    ("call_graph.json", "çağrı grafı"),
    ("decompiled.json", "decompile (+ .c yazımı)"),
    ("types.json", "tipler"),
    ("xrefs.json", "xref dökümü"),
    ("pcode.json", "pcode JSONL yazımı"),
    ("cfg.json", "CFG dökümü"),
    ("function_id.json", "FunctionID"),
    ("bsim_matches.json", "BSim ingest + sorgu"),
    ("bsim_shadow.json", "BSim gölge dökümü"),
    ("combined_results.json", "birleşik sonuç"),
]

_OTOMATIK = re.compile(r"Otomatik analiz:\s*([0-9.]+)\s*sn")


def _mtime(p: Path) -> float | None:
    try:
        return p.stat().st_mtime
    except OSError:
        return None


def _saat(t: float | None) -> str:
    if t is None:
        return "—"
    return dt.datetime.fromtimestamp(t).strftime("%H:%M:%S")


def _json(p: Path) -> dict | None:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _dizin_mtime_araligi(d: Path, uzanti: str = ".c") -> dict | None:
    """Dizindeki dosyaların (sayı, en erken, ortanca, en geç mtime, toplam bayt)."""
    if not d.is_dir():
        return None
    ts: list[float] = []
    toplam = 0
    with os.scandir(d) as it:
        for e in it:
            if e.name.endswith(uzanti) and e.is_file():
                st = e.stat()
                ts.append(st.st_mtime)
                toplam += st.st_size
    if not ts:
        return {"sayi": 0}
    ts.sort()
    return {
        "sayi": len(ts),
        "ilk": ts[0],
        "ortanca": ts[len(ts) // 2],
        "son": ts[-1],
        "toplam_bayt": toplam,
    }


def ghidra_adimlari(static: Path) -> dict:
    """Bir çalışma alanının ``static/`` dizininden Ghidra iç adım süreleri."""
    go = static / "ghidra_output"
    durum = _json(static / "ghidra_status.json") or {}
    sure = durum.get("duration_seconds")
    zamanlar = [(ad, adim, _mtime(go / ad)) for ad, adim in GHIDRA_ADIMLARI]
    var = [(ad, adim, t) for ad, adim, t in zamanlar if t is not None]
    son = _mtime(go / "combined_results.json")
    alt1 = _mtime(static / "lief_analysis.json")
    alt2 = (son - float(sure)) if (son is not None and isinstance(sure, (int, float))) else None
    adaylar = [t for t in (alt1, alt2) if t is not None]
    bas = max(adaylar) if adaylar else None

    log = ""
    try:
        log = (static / "ghidra_log.txt").read_text(encoding="utf-8")
    except OSError:
        pass
    m = _OTOMATIK.search(log)
    otomatik = float(m.group(1)) if m else None

    bsim = _json(go / "bsim_matches.json") or {}
    bd = bsim.get("bsim_detail") or {}

    adimlar = []
    onceki = bas
    for ad, adim, t in var:
        d = (t - onceki) if (onceki is not None) else None
        adimlar.append({"dosya": ad, "adim": adim, "bitis": t, "sure_sn": d})
        onceki = t
    c = _dizin_mtime_araligi(go / "decompiled")
    return {
        "baslangic": bas,
        "baslangic_kaynagi": {"lief_analysis": alt1, "combined_eksi_sure": alt2},
        "bitis_combined": son,
        "ghidra_sure_sn": sure,
        "otomatik_analiz_sn": otomatik,
        "fonksiyon": (durum.get("functions") or {}).get("total"),
        "decompile_basarili": (durum.get("decompile") or {}).get("success"),
        "adimlar": adimlar,
        "bsim": {
            "ingest_s": bd.get("ingest_s"),
            "query_s": bd.get("query_s"),
            "lock_wait_s": bd.get("lock_wait_s"),
            "ingested_functions": bd.get("ingested_functions"),
            "known_executables": bd.get("known_executables"),
            "total_matches": bsim.get("total_matches"),
            "total_queries": bsim.get("total_queries"),
            "excluded": bd.get("excluded"),
            "already_ingested": bd.get("already_ingested"),
        },
        "c_dosyalari": c,
        "log": log,
    }


def boru_sonucu(ws: Path) -> dict | None:
    """``reports/pipeline_result.json``: aşama süreleri ve yeniden kurma üst düzey adımları."""
    pr = _json(ws / "reports" / "pipeline_result.json")
    if pr is None:
        return None
    asamalar = {}
    adimlar: dict[str, float] = {}
    ic: dict[str, float] = {}
    for ad, s in (pr.get("stages") or {}).items():
        asamalar[ad] = s.get("duration_seconds")
        for k, v in (s.get("stats") or {}).items():
            if not isinstance(v, (int, float)) or isinstance(v, bool):
                continue
            if ad == "reconstruct" and k.endswith("_duration_s"):
                adimlar[k[: -len("_duration_s")]] = float(v)
            elif ad == "reconstruct" and k.startswith("timing_"):
                ic[k[len("timing_"):]] = float(v)
    st = (pr.get("stages") or {}).get("static", {}).get("stats", {})
    return {
        "toplam_sn": pr.get("total_duration"),
        "asamalar": asamalar,
        "yeniden_kurma_adimlari": adimlar,
        "yeniden_kurma_ic": ic,
        "ghidra_sure_sn": st.get("ghidra_duration"),
        "yara_ms": st.get("yara_scan_time_ms"),
    }


def _calisma_alani(birim_dizin: Path) -> Path | None:
    adaylar = sorted(birim_dizin.glob("ws/workspaces/*/*"))
    adaylar = [a for a in adaylar if (a / "static").is_dir()]
    return adaylar[-1] if adaylar else None


# ---------------------------------------------------------------- gösteri

def gosteri(kok: Path, cikti: Path) -> dict:
    ws = _calisma_alani(kok)
    if ws is None:
        sys.exit("çalışma alanı yok: %s" % kok)
    static = ws / "static"
    sonuc: dict = {"kok": str(kok), "calisma_alani": str(ws)}
    basladi = (kok / "BASLADI").read_text().strip() if (kok / "BASLADI").exists() else None
    t0 = dt.datetime.strptime(basladi, "%Y-%m-%d %H:%M:%S").timestamp() if basladi else None
    sonuc["basladi"] = basladi
    sonuc["bitti"] = (kok / "BITTI").read_text().strip() if (kok / "BITTI").exists() else None
    sonuc["cikis"] = (kok / "CIKIS").read_text().strip() if (kok / "CIKIS").exists() else None
    g = ghidra_adimlari(static)
    sonuc["ghidra"] = {k: v for k, v in g.items() if k != "log"}
    sonuc["ghidra_log"] = g["log"]

    # Ghidra sonrası olaylar (dosya zamanı sırasıyla)
    olaylar = []

    def ekle(ad: str, t: float | None, aciklama: str) -> None:
        if t is not None:
            olaylar.append({"olay": ad, "t": t, "aciklama": aciklama})

    ekle("BASLADI", t0, "koşu betiği başladı")
    ekle("static/lief_analysis.json", _mtime(static / "lief_analysis.json"),
         "Ghidra öncesi statik (otool, dizgi, sembol, LIEF) bitti")
    for a in g["adimlar"]:
        ekle("ghidra_output/" + a["dosya"], a["bitis"], a["adim"])
    ekle("static/ghidra_status.json", _mtime(static / "ghidra_status.json"),
         "Ghidra döndü (proje silindi), durum yazıldı")
    kopyalar = [p for p in static.glob("ghidra_*.json") if p.name != "ghidra_status.json"]
    if kopyalar:
        ekle("static/ghidra_*.json (son)", max(_mtime(p) or 0 for p in kopyalar),
             "Ghidra çıktılarının ikinci serileştirmesi (macho.py:434-438)")
    ekle("static/intelligence_report.json", _mtime(static / "intelligence_report.json"),
         "istihbarat taraması (macho.py:472-509)")
    ekle("static/capa_scan.json", _mtime(static / "capa_scan.json"), "YARA + capa (stages.py:573-577)")
    deob = ws / "deobfuscated" / "decompiled"
    dc = _dizin_mtime_araligi(deob)
    if dc and dc.get("sayi"):
        ekle("deobfuscated/decompiled ilk .c", dc["ilk"],
             "copytree + glob bitti, dosya başına döngü başladı (binary_deobfuscator.py:149-177)")
        ekle("deobfuscated/decompiled son .c", dc["son"], "dosya başına döngü (son yazılan)")
    sonuc["deobfuscate_c"] = dc
    rec = ws / "reconstructed"
    if rec.is_dir():
        rec_ts = []
        for root, _dirs, files in os.walk(rec):
            for f in files:
                t = _mtime(Path(root) / f)
                if t is not None:
                    rec_ts.append((t, os.path.relpath(os.path.join(root, f), rec)))
        rec_ts.sort()
        sonuc["reconstructed_dosya_sayisi"] = len(rec_ts)
        if rec_ts:
            ekle("reconstructed ilk dosya", rec_ts[0][0], rec_ts[0][1])
            ekle("reconstructed son dosya", rec_ts[-1][0], rec_ts[-1][1])
    ekle("reports/pipeline_result.json", _mtime(ws / "reports" / "pipeline_result.json"), "koşu raporu")
    olaylar.sort(key=lambda o: o["t"])
    onceki = None
    for o in olaylar:
        o["saat"] = _saat(o["t"])
        o["oncekinden_sn"] = round(o["t"] - onceki, 1) if onceki is not None else None
        o["baslangictan_dk"] = round((o["t"] - t0) / 60.0, 2) if t0 else None
        onceki = o["t"]
    sonuc["olaylar"] = olaylar
    sonuc["boru"] = boru_sonucu(ws)
    log = kok / "kosu.log"
    if log.exists():
        txt = log.read_text(errors="replace")
        m = re.search(r"([0-9.]+) real\s+([0-9.]+) user\s+([0-9.]+) sys", txt)
        m2 = re.search(r"(\d+)\s+maximum resident set size", txt)
        m3 = re.search(r"(\d+)\s+peak memory footprint", txt)
        sonuc["time_l"] = {
            "real": float(m.group(1)) if m else None,
            "user": float(m.group(2)) if m else None,
            "sys": float(m.group(3)) if m else None,
            "max_rss_bayt": int(m2.group(1)) if m2 else None,
            "tepe_bellek_bayt": int(m3.group(1)) if m3 else None,
        }
    cikti.mkdir(parents=True, exist_ok=True)
    (cikti / "gosteri_zaman.json").write_text(json.dumps(sonuc, indent=1, ensure_ascii=False))
    return sonuc


def gosteri_md(s: dict) -> str:
    satir = ["| Saat | Olay | Öncekinden (sn) | Başlangıçtan (dk) | Açıklama |", "|---|---|---|---|---|"]
    for o in s["olaylar"]:
        satir.append("| %s | %s | %s | %s | %s |" % (
            o["saat"], o["olay"],
            "—" if o["oncekinden_sn"] is None else "%.1f" % o["oncekinden_sn"],
            "—" if o["baslangictan_dk"] is None else "%.2f" % o["baslangictan_dk"],
            o["aciklama"]))
    g = s["ghidra"]
    satir.append("")
    satir.append("Ghidra iç adımları (dosya zamanı farkı):")
    satir.append("")
    satir.append("| Adım | Süre (sn) | Ghidra içi pay |")
    satir.append("|---|---|---|")
    toplam = g.get("ghidra_sure_sn") or 0
    for a in g["adimlar"]:
        d = a["sure_sn"]
        satir.append("| %s | %s | %s |" % (
            a["adim"], "—" if d is None else "%.1f" % d,
            "—" if (d is None or not toplam) else "%.1f %%" % (100 * d / toplam)))
    b = g["bsim"]
    satir.append("")
    satir.append("BSim ayrıntısı: ingest %s sn, sorgu %s sn, kilit bekleme %s sn, hash'lenen %s, "
                 "bilinen program %s, eşleşme %s, sorgu %s, dışlanan %s" % (
                     b["ingest_s"], b["query_s"], b["lock_wait_s"], b["ingested_functions"],
                     b["known_executables"], b["total_matches"], b["total_queries"], b["excluded"]))
    satir.append("Otomatik analiz (ghidra_log): %s sn; Ghidra toplam (ghidra_status): %s sn" % (
        g.get("otomatik_analiz_sn"), g.get("ghidra_sure_sn")))
    b = s.get("boru")
    if b and b.get("toplam_sn"):
        top = float(b["toplam_sn"])
        satir.append("")
        satir.append("Aşama payları (pipeline_result, toplam %.1f sn):" % top)
        satir.append("")
        satir.append("| Kalem | sn | toplam payı |")
        satir.append("|---|---|---|")
        asm = b.get("asamalar") or {}
        gs = float(g.get("ghidra_sure_sn") or 0)
        kalem = [("statik: Ghidra köprüsü", gs), ("statik: Ghidra dışı", float(asm.get("static") or 0) - gs)]
        for a in ("deobfuscate", "reconstruct", "report"):
            kalem.append((a, float(asm.get(a) or 0)))
        for ad in g["adimlar"]:
            if ad["sure_sn"] and ad["sure_sn"] > 0.02 * top:
                kalem.append(("  Ghidra: " + ad["adim"], float(ad["sure_sn"])))
        ra = b.get("yeniden_kurma_adimlari") or {}
        for k, v in sorted(ra.items(), key=lambda x: -x[1]):
            if v > 0.01 * top:
                kalem.append(("  yeniden kurma: " + k, float(v)))
        for k, v in sorted((b.get("yeniden_kurma_ic") or {}).items(), key=lambda x: -x[1]):
            if "iter" in k and v > 0.01 * top:
                kalem.append(("    feedback_loop içi: " + k, float(v)))
        for ad, v in kalem:
            satir.append("| %s | %.1f | %.1f %% |" % (ad, v, 100.0 * v / top))
    return "\n".join(satir)


# ---------------------------------------------------------------- taban

def _sinif(fn: int | None) -> str:
    # Sınırlar sayılara bakılmadan önce yazıldı (DEFTER 12:5x).
    if fn is None:
        return "?"
    if fn < 1000:
        return "küçük (<1 000 fn)"
    if fn < 5000:
        return "orta (1 000–4 999 fn)"
    return "büyük (≥5 000 fn)"


def taban(kok: Path, cikti: Path) -> dict:
    kayitlar = []
    for birim_dizin in sorted(kok.glob("*/*/*")) + sorted(kok.glob("mac/*")):
        if not birim_dizin.is_dir():
            continue
        ws = _calisma_alani(birim_dizin)
        if ws is None:
            continue
        rel = str(birim_dizin.relative_to(kok))
        if any(k["anahtar"] == rel for k in kayitlar):
            continue
        g = ghidra_adimlari(ws / "static")
        b = boru_sonucu(ws)
        ti = _json(ws / "raw" / "target_info.json") or {}
        k = {
            "anahtar": rel,
            "boyut_bayt": ti.get("file_size"),
            "fonksiyon": g["fonksiyon"],
            "sinif": _sinif(g["fonksiyon"]),
            "ghidra_sure_sn": g["ghidra_sure_sn"],
            "otomatik_analiz_sn": g["otomatik_analiz_sn"],
            "ghidra_adim": {a["dosya"]: a["sure_sn"] for a in g["adimlar"]},
            "bsim": g["bsim"],
            "boru": b,
        }
        kayitlar.append(k)
    cikti.mkdir(parents=True, exist_ok=True)
    (cikti / "taban_zaman.json").write_text(json.dumps(kayitlar, indent=1, ensure_ascii=False))
    return {"kayitlar": kayitlar}


def _ozet_payi(kayitlar: list[dict]) -> dict:
    """Sınıf başına aşama / adım toplamları (saniye) ve payları."""
    out: dict = {}
    for k in kayitlar:
        s = out.setdefault(k["sinif"], {"n": 0, "toplam": 0.0, "kalem": {}, "fonksiyon": []})
        b = k["boru"] or {}
        top = b.get("toplam_sn") or 0.0
        s["n"] += 1
        s["toplam"] += top
        s["fonksiyon"].append(k["fonksiyon"] or 0)
        kal = s["kalem"]

        def ek(ad: str, v: float | None) -> None:
            if v is None:
                return
            kal[ad] = kal.get(ad, 0.0) + float(v)

        # Ghidra iç adımları
        ga = k["ghidra_adim"]
        oto = k["otomatik_analiz_sn"] or 0.0
        f1 = ga.get("functions.json")
        if f1 is not None:
            ek("G: otomatik analiz", oto)
            ek("G: JVM + içe aktarma + fonksiyon listesi", max(0.0, f1 - oto))
        for dosya, ad in GHIDRA_ADIMLARI[1:]:
            v = ga.get(dosya)
            if dosya == "bsim_matches.json" and v is not None:
                bs = k["bsim"]
                lw = bs.get("lock_wait_s") or 0.0
                ek("G: BSim kilit bekleme", lw)
                ek("G: BSim ingest + sorgu (kilit hariç)", max(0.0, v - lw))
            else:
                ek("G: " + ad, v)
        gsum = sum(x for x in ga.values() if x is not None)
        gs = k["ghidra_sure_sn"] or 0.0
        ek("G: kapanış / ölçülmeyen", max(0.0, gs - gsum))
        asm = b.get("asamalar") or {}
        st = asm.get("static")
        if st is not None:
            ek("statik: Ghidra dışı (istihbarat, kopya, YARA, ön statik)", max(0.0, st - gs))
        for a in ("identify", "deobfuscate", "report"):
            ek(a, asm.get(a))
        for ad, v in (b.get("yeniden_kurma_adimlari") or {}).items():
            ek("R: " + ad, v)
        rsum = sum((b.get("yeniden_kurma_adimlari") or {}).values())
        rc = asm.get("reconstruct")
        if rc is not None:
            ek("R: adım dışı (kabuk, aşama kodu)", max(0.0, rc - rsum))
    return out


def taban_md(kayitlar: list[dict]) -> str:
    oz = _ozet_payi(kayitlar)
    satir = []
    siralar = ["küçük (<1 000 fn)", "orta (1 000–4 999 fn)", "büyük (≥5 000 fn)", "?"]
    for sn in siralar:
        if sn not in oz:
            continue
        s = oz[sn]
        fn = s["fonksiyon"]
        satir.append("### %s — %d ikili, fonksiyon ortanca %d (en az %d, en çok %d), toplam duvar %.0f sn" % (
            sn, s["n"], statistics.median(fn), min(fn), max(fn), s["toplam"]))
        satir.append("")
        satir.append("| Kalem | Toplam (sn) | Toplam duvar payı |")
        satir.append("|---|---|---|")
        kal = sorted(s["kalem"].items(), key=lambda x: -x[1])
        for ad, v in kal[:18]:
            satir.append("| %s | %.1f | %.1f %% |" % (ad, v, 100.0 * v / s["toplam"] if s["toplam"] else 0))
        satir.append("")
    return "\n".join(satir)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("kip", choices=["gosteri", "taban"])
    ap.add_argument("--kok", required=True, type=Path)
    ap.add_argument("--cikti", required=True, type=Path)
    a = ap.parse_args()
    kok = a.kok.expanduser()
    cikti = a.cikti.expanduser()
    if a.kip == "gosteri":
        s = gosteri(kok, cikti)
        md = gosteri_md(s)
        (cikti / "gosteri_zaman.md").write_text(md + "\n")
        print(md)
        if s.get("time_l"):
            print("\n/usr/bin/time -l:", s["time_l"])
        if s.get("boru"):
            print("\npipeline_result:", json.dumps(s["boru"], ensure_ascii=False)[:3000])
        print("\nCIKIS:", s.get("cikis"), "BITTI:", s.get("bitti"))
    else:
        s = taban(kok, cikti)
        md = taban_md(s["kayitlar"])
        (cikti / "taban_zaman.md").write_text(md + "\n")
        print("ikili sayısı:", len(s["kayitlar"]))
        print(md)


if __name__ == "__main__":
    main()
