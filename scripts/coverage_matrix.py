#!/usr/bin/env python3
"""coverage_matrix.py — Karadul motorunun KAPSAM (format×mimari×dil) ölçümü.

Amaç: doğruluk DEĞİL, KAPSAM. Motor çeşitli girdide çalışıyor mu, çöküyor mu,
donuyor mu, çöp mü üretiyor? İyileştirmeden önce nerede kırıldığını dürüstçe ölç.

İki sinyal (her binary için):
  (A) SINIFLANDIRMA (hızlı, Ghidra'sız): container_classifier formatı/mimariyi/dili
      doğru tanıyor mu? Beklenen (manifest) ile karşılaştırılır.
  (B) SAĞLAMLIK (yavaş, Ghidra): `karadul analyze` çalıştı mı?
      OK / CRASH / TIMEOUT / EMPTY + fonksiyon sayısı + isimlendirilen sayısı.

Girdi: corpus_manifest.jsonl (build_coverage_corpus.sh üretir). Her satır:
  {"path","format","arch","lang","symbols","gt_path"}

Kullanım:
  python3 scripts/coverage_matrix.py --classify-only        # anında sınıflandırma matrisi
  python3 scripts/coverage_matrix.py --jobs 3 --timeout 900 # tam sağlamlık koşusu
Çıktı: <OUT>/coverage_matrix.json + terminale tablo.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = Path(os.environ.get("KARADUL_COVERAGE_DIR", str(Path.home() / "karadul_coverage")))
MANIFEST = OUT / "corpus_manifest.jsonl"
RUNS = OUT / "runs"
RESULT = OUT / "coverage_matrix.json"

_FUN_RE = re.compile(r"^(FUN_|sub_|loc_|unk_|thunk_FUN_)", re.IGNORECASE)


def load_corpus() -> list[dict]:
    rows = []
    for ln in MANIFEST.read_text(encoding="utf-8").splitlines():
        ln = ln.strip()
        if ln:
            rows.append(json.loads(ln))
    return rows


def label(row: dict) -> str:
    """Corpus satırı için kısa, dosya-adı-güvenli etiket."""
    return f"{row['lang']}_{row['format']}_{row['arch']}_{Path(row['path']).name}"[:80]


# ---------- (A) SINIFLANDIRMA ----------
# Gerçek identify: TargetDetector().detect() -> TargetInfo(target_type, language).
# container_classifier DEĞİL (o sadece mobil IPA/APK içindir; ELF'e bile UNKNOWN der).
_FMT_ALIAS = {"macho": "macho", "elf": "elf", "pe": "pe", "jvm": "java", "universal": "universal"}


def classify(row: dict) -> dict:
    """TargetDetector ile format/dil tespiti + beklenenle karşılaştır.

    NOT (dürüstlük): düz C stripped binary'de "C" belirteci yoktur; motor bunu
    'unknown' bırakır (Rust/Swift/C++/Go/Java'yı runtime/mangling izinden tanır).
    Bu YANLIŞ değil -> lang beklentisi c/system ise ve 'unknown' geldi ise None
    (değerlendirme dışı), '✗' değil.
    """
    try:
        from karadul.core.target import TargetDetector
        info = TargetDetector().detect(Path(row["path"]))
        tt = info.target_type.value if hasattr(info.target_type, "value") else str(info.target_type)
        lg = info.language.value if hasattr(info.language, "value") else str(info.language)
        meta = info.metadata or {}
        arch = str(meta.get("architecture") or meta.get("arch") or meta.get("cpu") or "")
        exp_fmt, exp_lang = row["format"].lower(), row["lang"].lower()
        # format: beklenen (alias'lı) target_type içinde geçiyor mu (macho->macho_binary)
        exp_f = _FMT_ALIAS.get(exp_fmt, exp_fmt)
        fmt_match = None if exp_fmt in ("system", "unknown") else (exp_f in tt.lower())
        # dil: c/system/unknown beklentisinde 'unknown' cevabı nötr (None), yanlış değil
        if exp_lang in ("c", "system", "unknown"):
            lang_match = None if lg in ("unknown", "") else (exp_lang in lg or lg in exp_lang)
        else:
            lang_match = (exp_lang in lg) or (lg in exp_lang)
        return {"ok": True, "got_type": tt, "got_lang": lg, "got_arch": arch,
                "fmt_match": fmt_match, "lang_match": lang_match}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"[:200]}


# ---------- (B) SAĞLAMLIK ----------
def _count_functions(ws: Path) -> tuple[int, int]:
    """(toplam_fonksiyon, isimlendirilen_fonksiyon).

    naming_map.json yapısı İÇ İÇE: {"global": {FUN_x: isim, DAT_x: ...}, "per_function": {...}}.
    İsimlendirilen = "global" içinde FUN_ ile başlayan + değeri gerçek isim (FUN_/sub_ deseni
    DEĞİL, anahtara eşit DEĞİL) olan girdiler. DAT_ (veri) hariç. FINAL src/ tercih edilir
    (src_iter* ara-tur değil). Toplam: ghidra_functions.json (tüm Ghidra fonksiyonları)."""
    total, named = 0, 0
    gfs = list(ws.rglob("ghidra_functions.json"))
    if gfs:
        try:
            data = json.loads(sorted(gfs, key=lambda p: p.stat().st_mtime)[-1]
                               .read_text(encoding="utf-8"))
            funcs = data.get("functions", data) if isinstance(data, dict) else data
            if isinstance(funcs, list):
                total = len(funcs)
        except Exception:
            pass
    nms = list(ws.rglob("naming_map.json"))
    # FINAL 'src/' tercih (ara-tur 'src_iterN/' değil)
    final = [p for p in nms if p.parent.name == "src"]
    pick = (sorted(final, key=lambda p: p.stat().st_mtime)[-1] if final
            else sorted(nms, key=lambda p: p.stat().st_mtime)[-1] if nms else None)
    if pick:
        try:
            nm = json.loads(pick.read_text(encoding="utf-8"))
            g = nm.get("global", nm) if isinstance(nm, dict) else {}
            if isinstance(g, dict):
                fun_keys = [k for k in g if isinstance(k, str) and k.startswith("FUN_")]
                if not total:
                    total = len(fun_keys)
                for k in fun_keys:
                    v = g[k]
                    name = v.get("name") if isinstance(v, dict) else v
                    if isinstance(name, str) and name and name != k and not _FUN_RE.match(name):
                        named += 1
        except Exception:
            pass
    # JVM/JAR: native değil -> ghidra_functions/naming_map yok. Fonksiyon = metot;
    # bytecode isimleri saklar -> hepsi isimli-kurtarılmış.
    if total == 0:
        jas = list(ws.rglob("java_analysis.json"))
        if jas:
            try:
                d = json.loads(sorted(jas, key=lambda p: p.stat().st_mtime)[-1]
                               .read_text(encoding="utf-8"))
                cds = d.get("class_details", []) if isinstance(d, dict) else []
                m = sum(len(c.get("methods", [])) for c in cds if isinstance(c, dict))
                if not m and isinstance(d.get("class_info"), dict):
                    m = len(d["class_info"].get("methods", []))
                total = named = m
            except Exception:
                pass
    return total, named


def robustness(row: dict, timeout: int) -> dict:
    """Tek binary: karadul analyze koştur, sağlamlık verdict'i döndür."""
    lb = label(row)
    ws = RUNS / f"{lb}_ws"
    log = RUNS / f"{lb}.log"
    ws.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, "-m", "karadul", "analyze", row["path"],
           "--skip-dynamic", "--lmdb-sigdb", "--output-dir", str(ws)]
    t0 = time.time()
    status, errsig = "OK", ""
    try:
        with open(log, "w", encoding="utf-8") as lf:
            p = subprocess.run(cmd, stdout=lf, stderr=subprocess.STDOUT,
                               timeout=timeout, cwd=str(REPO))
        rc = p.returncode
        if rc != 0:
            status = "CRASH"
            errsig = _last_error(log)
    except subprocess.TimeoutExpired:
        status, rc = "TIMEOUT", None
    except Exception as e:
        status, rc, errsig = "CRASH", None, f"{type(e).__name__}: {e}"[:160]
    dt = round(time.time() - t0, 1)
    total, named = _count_functions(ws)
    if status == "OK" and total == 0:
        status = "EMPTY"  # çalıştı ama çıktı yok -> sessiz başarısızlık
    return {"label": lb, "status": status, "rc": rc, "elapsed_sec": dt,
            "func_total": total, "func_named": named,
            "named_pct": round(100 * named / total, 1) if total else 0.0,
            "err": errsig}


def _last_error(log: Path) -> str:
    """Log'un sonundaki en anlamlı hata satırı (traceback tipi / Error)."""
    try:
        lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return ""
    for ln in reversed(lines[-60:]):
        s = ln.strip()
        if re.search(r"Error|Exception|Traceback|assert|FAILED|Killed|abort", s):
            return s[:160]
    return (lines[-1][:160] if lines else "")


# ---------- ANA ----------
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--classify-only", action="store_true",
                    help="Sadece (A) sınıflandırma matrisi (Ghidra yok, anında)")
    ap.add_argument("--rescore", action="store_true",
                    help="Mevcut RUNS/ workspace'lerini yeniden puanla (Ghidra koşmaz)")
    ap.add_argument("--jobs", type=int, default=3, help="Paralel analiz sayısı")
    ap.add_argument("--timeout", type=int, default=900, help="Binary başına saniye")
    args = ap.parse_args()

    if not MANIFEST.is_file():
        print(f"!! manifest yok: {MANIFEST}\n   önce: bash scripts/build_coverage_corpus.sh", file=sys.stderr)
        return 1
    corpus = load_corpus()
    RUNS.mkdir(parents=True, exist_ok=True)
    print(f"corpus: {len(corpus)} binary | manifest: {MANIFEST}\n")

    # (A) sınıflandırma — daima, hızlı
    print("=== (A) SINIFLANDIRMA (format/dil doğru tanınıyor mu — TargetDetector) ===")
    print(f"{'binary':<42}{'beklenen':<16}{'tanınan(type/lang)':<30}{'FMT':<5}{'LANG':<5}")
    ok = lambda m: "✓" if m else ("·" if m is None else "✗")
    for row in corpus:
        c = classify(row)
        row["_classify"] = c
        exp = f"{row['format']}/{row['lang']}"
        if c["ok"]:
            got = f"{c['got_type']}/{c['got_lang']}"
            print(f"{label(row):<42}{exp:<16}{got:<30}"
                  f"{ok(c['fmt_match']):<5}{ok(c['lang_match']):<5}")
        else:
            print(f"{label(row):<42}{exp:<16}{'HATA: '+c['error']:<30}")
    print()

    if args.classify_only:
        RESULT.write_text(json.dumps({"corpus": corpus}, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"-> {RESULT} (sınıflandırma)")
        return 0

    # (B) sağlamlık
    results = {}
    if args.rescore:
        print("=== (B) YENİDEN PUANLA (mevcut workspace'ler, Ghidra koşmaz) ===\n")
        for row in corpus:
            lb = label(row)
            ws = RUNS / f"{lb}_ws"
            total, named = _count_functions(ws) if ws.exists() else (0, 0)
            status = "OK" if total > 0 else ("EMPTY" if ws.exists() else "NORUN")
            r = {"label": lb, "status": status, "rc": None, "elapsed_sec": 0,
                 "func_total": total, "func_named": named,
                 "named_pct": round(100 * named / total, 1) if total else 0.0, "err": ""}
            results[lb] = r
            print(f"  {r['status']:<8} {lb:<44} fn={total:<5} named={named} ({r['named_pct']}%)")
    else:
        print(f"=== (B) SAĞLAMLIK (karadul analyze, {args.jobs} paralel, {args.timeout}s timeout) ===")
        print("koşuyor... (Ghidra; binary başına dakikalar)\n")
        with cf.ThreadPoolExecutor(max_workers=args.jobs) as ex:
            futs = {ex.submit(robustness, row, args.timeout): row for row in corpus}
            for fut in cf.as_completed(futs):
                r = fut.result()
                results[r["label"]] = r
                print(f"  {r['status']:<8} {r['label']:<44} {r['elapsed_sec']:>6}s  "
                      f"fn={r['func_total']:<5} named={r['func_named']} ({r['named_pct']}%)"
                      + (f"  {r['err']}" if r['err'] else ""))

    for row in corpus:
        row["_robustness"] = results.get(label(row), {})
    RESULT.write_text(json.dumps({"corpus": corpus}, indent=2, ensure_ascii=False), encoding="utf-8")

    # özet tablo
    print("\n=== ÖZET (kapsam matrisi) ===")
    print(f"{'binary':<44}{'sınıf':<8}{'sağlamlık':<10}{'fn':<7}{'named':<8}{'süre':<7}")
    for row in corpus:
        c, rb = row.get("_classify", {}), row.get("_robustness", {})
        cls = "OK" if (c.get("fmt_match") is not False and c.get("ok")) else "✗"
        print(f"{label(row):<44}{cls:<8}{rb.get('status','?'):<10}"
              f"{rb.get('func_total',0):<7}{str(rb.get('func_named',0))+'/'+str(rb.get('named_pct',0))+'%':<8}"
              f"{rb.get('elapsed_sec',0)}s")
    n_ok = sum(1 for r in results.values() if r["status"] == "OK")
    n_empty = sum(1 for r in results.values() if r["status"] == "EMPTY")
    n_crash = sum(1 for r in results.values() if r["status"] == "CRASH")
    n_to = sum(1 for r in results.values() if r["status"] == "TIMEOUT")
    print(f"\nOK={n_ok}  EMPTY={n_empty}  CRASH={n_crash}  TIMEOUT={n_to}  / {len(corpus)}")
    print(f"-> {RESULT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
