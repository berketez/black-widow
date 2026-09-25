#!/usr/bin/env python3
"""Fonksiyon-ismi ölçüm orkestratörü: korpus hazırla -> karadul koş -> puanla.

Puanlama mantığı ``function_f1.py``'dedir (tek kaynak); bu dosya yalnız
veriyi hazırlar, karadul'u verilen ağaçtan (worktree veya ana depo) koşar ve
sonuçları tek JSON'da toplar. Tüm ölçüm verisi depo DIŞINDA durur
(varsayılan ``~/karadul_olcum``, ``KARADUL_OLCUM_DIR`` ile değişir).

Alt komutlar
------------
prepare   Paketleri indir (sha256 doğrula), aç, binary + debug çiftini BuildID
          ile eşle, GT JSON üret. İdempotent.
analyze   ``python -m karadul analyze`` komutunu ``--tree`` ağacından koş
          (cwd=ağaç, PYTHONPATH=ağaç, Ghidra sabit). Aynı anda en çok --jobs.
score     Koşuları puanla, per-binary + korpus özetini JSON'a yaz.
compare   İki sonuç JSON'unu (taban vs aday) binary ve fonksiyon bazında kıyasla.
all       prepare + analyze + score.

Örnek (taban):
    python scripts/measurement/measure.py all \
        --tree ~/karadul_olcum/baseline-2304560 --label baseline-2304560 \
        --out scripts/measurement/baseline_2304560.json
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import math
import os
import platform
import shutil
import signal
import subprocess
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Optional

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

import function_f1 as f1  # noqa: E402

MANIFEST_PATH = HERE / "corpus.json"
DEFAULT_DATA_DIR = Path(os.environ.get("KARADUL_OLCUM_DIR", "~/karadul_olcum")).expanduser()
DEFAULT_GHIDRA = Path(os.environ.get(
    "KARADUL_MEAS_GHIDRA", "~/Library/BlackWidowBuild/ghidra_12.1.2_PUBLIC")).expanduser()
DEFAULT_TIMEOUT_S = 900  # bir binary 15 dk'yı geçerse atlanır
DEFAULT_JOBS = 2
# karadul'un proje köküne (cwd) göre aradığı, git'e girmeyen çalışma zamanı verisi.
RUNTIME_DATA = ("sigs", "vendor", "signatures_homebrew.json",
                "signatures_homebrew_bytes.json", "sigs_macos_system.json")


def _now() -> str:
    return _dt.datetime.now().astimezone().isoformat(timespec="seconds")


def _tilde(p: Any) -> str:
    """Mutlak yolu ~ ile kısalt (sonuç JSON'u makineye bağlı olmasın)."""
    s = str(p)
    home = str(Path.home())
    return "~" + s[len(home):] if s.startswith(home) else s


def load_manifest() -> dict[str, Any]:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# prepare
# ---------------------------------------------------------------------------

def _download(url: str, dest: Path, sha256: str) -> None:
    if dest.is_file() and f1.sha256_file(dest) == sha256:
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    print(f"  indir: {url}")
    with urllib.request.urlopen(url, timeout=300) as resp, open(tmp, "wb") as out:
        shutil.copyfileobj(resp, out)
    got = f1.sha256_file(tmp)
    if got != sha256:
        tmp.unlink(missing_ok=True)
        raise RuntimeError(f"sha256 uyuşmuyor: {url}\n beklenen {sha256}\n gelen    {got}")
    tmp.replace(dest)


def _extract_deb(deb: Path, xdir: Path) -> Path:
    """.deb/.ddeb'i aç (macOS bsdtar ar + xz/zstd okur). data/ dizinini döndürür."""
    data = xdir / "data"
    if (xdir / ".extracted").is_file():
        return data
    if xdir.exists():
        shutil.rmtree(xdir)
    xdir.mkdir(parents=True)
    subprocess.run(["tar", "-xf", str(deb)], cwd=xdir, check=True)
    members = sorted(xdir.glob("data.tar*"))
    if not members:
        raise RuntimeError(f"{deb}: data.tar* yok")
    data.mkdir()
    subprocess.run(["tar", "-xf", str(members[0]), "-C", str(data)], check=True)
    (xdir / ".extracted").write_text(_now() + "\n", encoding="utf-8")
    return data


def _find_binary(data: Path, name: str) -> Path:
    for rel in ("usr/bin", "bin"):
        cand = data / rel / name
        if cand.is_file() and not cand.is_symlink():
            return cand
    raise FileNotFoundError(f"{data}: {name} bulunamadı")


def prepare(data_dir: Path) -> dict[str, Any]:
    manifest = load_manifest()
    dl = data_dir / "downloads"
    summary: dict[str, Any] = {"created_at": _now(), "corpora": {}}
    for corpus, spec in manifest["corpora"].items():
        print(f"[prepare] {corpus}")
        pk = spec["packages"]
        datas = {}
        for kind in ("binary", "dbgsym"):
            url, sha = pk[kind]["url"], pk[kind]["sha256"]
            deb = dl / url.rsplit("/", 1)[-1]
            _download(url, deb, sha)
            datas[kind] = _extract_deb(deb, dl / f"x_{deb.stem}")
        cdir = data_dir / "corpus" / corpus
        entries = {}
        for b in manifest["binaries"]:
            src_bin = _find_binary(datas["binary"], b)
            bid = f1.read_elf_info(src_bin)["build_id"]
            src_dbg = datas["dbgsym"] / "usr/lib/debug/.build-id" / bid[:2] / f"{bid[2:]}.debug"
            if not src_dbg.is_file():
                raise FileNotFoundError(f"{corpus}/{b}: BuildID {bid} için debug dosyası yok")
            # Binary ve debug AYRI dizinlerde: karadul yalnız bin/'i görür.
            dst_bin = cdir / "bin" / b
            dst_dbg = cdir / "debug" / f"{b}.debug"
            for s, d in ((src_bin, dst_bin), (src_dbg, dst_dbg)):
                d.parent.mkdir(parents=True, exist_ok=True)
                if not d.is_file() or f1.sha256_file(d) != f1.sha256_file(s):
                    shutil.copyfile(s, d)
            dst_bin.chmod(0o755)
            gt = f1.extract_gt(dst_dbg, dst_bin, corpus=corpus, binary=b)
            gt_path = cdir / "gt" / f"{b}.gt.json"
            gt_path.parent.mkdir(parents=True, exist_ok=True)
            gt_path.write_text(json.dumps(gt, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
            entries[b] = {
                "build_id": gt["build_id"], "stripped_sha256": gt["stripped_sha256"],
                "debug_sha256": gt["debug_sha256"], "package_path": "/" + str(src_bin.relative_to(datas["binary"])),
                "gt_counts": gt["counts"],
            }
            print(f"  {b:5s} BuildID={bid[:16]}.. GT={gt['counts']}")
        summary["corpora"][corpus] = {"distro": spec["distro"], "binaries": entries}
    out = data_dir / "corpus" / "manifest.json"
    out.write_text(json.dumps(summary, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    return summary


def corpus_items(data_dir: Path, only: Optional[list[str]] = None) -> list[tuple[str, str]]:
    manifest = load_manifest()
    items = [(c, b) for c in manifest["corpora"] for b in manifest["binaries"]]
    if only:
        items = [(c, b) for c, b in items if f"{c}/{b}" in only or b in only or c in only]
    return items


# ---------------------------------------------------------------------------
# analyze
# ---------------------------------------------------------------------------

def _git(tree: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(tree), *args], capture_output=True,
                          text=True, check=True).stdout.strip()


def tree_info(tree: Path) -> dict[str, Any]:
    """Ağacın commit'i, kirli dosyaları ve karadul paketinin gerçekten oradan yüklendiği."""
    commit = _git(tree, "rev-parse", "HEAD")
    porcelain = _git(tree, "status", "--porcelain", "--untracked-files=no")
    env = dict(os.environ, PYTHONPATH=str(tree))
    probe = subprocess.run(
        [sys.executable, "-c", "import karadul; print(karadul.__file__); print(karadul.__version__)"],
        cwd=tree, env=env, capture_output=True, text=True, check=True).stdout.split()
    pkg_file, version = Path(probe[0]).resolve(), probe[1]
    if not str(pkg_file).startswith(str(tree.resolve()) + os.sep):
        raise RuntimeError(f"karadul {pkg_file} yükleniyor, {tree} DEĞİL — ölçüm yanlış ağacı koşardı")
    missing = [n for n in RUNTIME_DATA if not (tree / n).exists()]
    return {
        "tree": _tilde(tree.resolve()), "commit": commit,
        "dirty_files": porcelain.splitlines() if porcelain else [],
        "karadul_file": _tilde(pkg_file), "karadul_version": version,
        "runtime_data_missing": missing,
    }


def ghidra_info(ghidra: Path) -> dict[str, Any]:
    props = ghidra / "Ghidra" / "application.properties"
    if not (ghidra / "support" / "analyzeHeadless").is_file() or not props.is_file():
        raise FileNotFoundError(f"Ghidra kurulumu bulunamadı: {ghidra}")
    kv = dict(line.split("=", 1) for line in props.read_text().splitlines()
              if "=" in line and not line.startswith("#"))
    return {"install_dir": _tilde(ghidra), "version": kv.get("application.version"),
            "release": kv.get("application.release.name")}


def cfg_cache_snapshot() -> dict[str, str]:
    """~/.cache/karadul/cfg_cache — karadul'un ÇAPRAZ-BINARY isim aktarım önbelleği.

    Sabit kodlu (HOME), env ile izole edilemiyor; koşular arası bir karıştırıcı
    olduğu için içeriği her analizde kayda geçer (A/B'de iki taraf karşılaştırılır).
    """
    d = Path.home() / ".cache" / "karadul" / "cfg_cache"
    if not d.is_dir():
        return {}
    return {p.name: f1.sha256_file(p)[:16] for p in sorted(d.glob("*.json"))}


def _run_one(tree: Path, ghidra: Path, data_dir: Path, label: str, corpus: str,
             binary: str, timeout: int, force: bool) -> dict[str, Any]:
    run_dir = data_dir / "runs" / label / corpus / binary
    meta_path = run_dir / "run.json"
    if meta_path.is_file() and not force:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if meta.get("status") == "ok":
            print(f"  [atla] {corpus}/{binary} (önceden ok)")
            return meta
    for sub in ("ws", "out"):
        if (run_dir / sub).exists():
            shutil.rmtree(run_dir / sub)
    run_dir.mkdir(parents=True, exist_ok=True)
    target = data_dir / "corpus" / corpus / "bin" / binary
    cmd = [sys.executable, "-m", "karadul", "analyze", str(target), "--skip-dynamic",
           "--output-dir", str(run_dir / "ws"), "--output", str(run_dir / "out")]
    env = dict(os.environ, PYTHONPATH=str(tree), GHIDRA_INSTALL_DIR=str(ghidra))
    meta: dict[str, Any] = {
        "corpus": corpus, "binary": binary, "label": label,
        "command": " ".join(_tilde(c) for c in cmd), "cwd": _tilde(tree),
        "env": {"PYTHONPATH": _tilde(tree), "GHIDRA_INSTALL_DIR": _tilde(ghidra),
                "JAVA_HOME": _tilde(os.environ.get("JAVA_HOME", ""))},
        "target_sha256": f1.sha256_file(target),
        "cfg_cache_before": cfg_cache_snapshot(),
        "started_at": _now(),
    }
    print(f"  [koş] {corpus}/{binary}")
    t0 = time.monotonic()
    with open(run_dir / "karadul.log", "wb") as log:
        proc = subprocess.Popen(cmd, cwd=tree, env=env, stdout=log, stderr=subprocess.STDOUT,
                                start_new_session=True)
        try:
            rc = proc.wait(timeout=timeout)
            status = "ok" if rc == 0 else "failed"
        except subprocess.TimeoutExpired:
            # Tüm süreç grubu (karadul + JVM + alt süreçler) öldürülür.
            for sig, grace in ((signal.SIGTERM, 30), (signal.SIGKILL, None)):
                try:
                    os.killpg(proc.pid, sig)
                except ProcessLookupError:
                    break
                try:
                    proc.wait(timeout=grace)
                    break
                except subprocess.TimeoutExpired:
                    continue
            rc, status = None, "timeout"
    meta.update({"exit_code": rc, "status": status, "finished_at": _now(),
                 "duration_s": round(time.monotonic() - t0, 1)})
    if status == "ok" and f1.find_run_artifacts(run_dir)["ghidra_functions"] is None:
        meta["status"] = "failed"
        meta["error"] = "ghidra_functions.json üretilmedi"
    meta_path.write_text(json.dumps(meta, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"  [bitti] {corpus}/{binary}: {meta['status']} {meta['duration_s']} sn")
    return meta


def analyze(tree: Path, label: str, data_dir: Path, ghidra: Path, jobs: int,
            timeout: int, only: Optional[list[str]], force: bool) -> dict[str, Any]:
    tree = tree.expanduser().resolve()
    info = tree_info(tree)
    if info["runtime_data_missing"]:
        print(f"UYARI: ağaçta çalışma zamanı verisi yok: {info['runtime_data_missing']} "
              "(ana depodakilere symlink verin; bkz. README)")
    gi = ghidra_info(ghidra)
    label_dir = data_dir / "runs" / label
    label_dir.mkdir(parents=True, exist_ok=True)
    session = {"label": label, "tree": info, "ghidra": gi, "python": sys.version.split()[0],
               "python_executable": _tilde(sys.executable), "platform": platform.platform(),
               "started_at": _now(), "jobs": jobs, "timeout_s": timeout}
    (label_dir / "session.json").write_text(json.dumps(session, indent=1, ensure_ascii=False) + "\n",
                                           encoding="utf-8")
    print(f"[analyze] {label}: {info['commit'][:10]} ({info['karadul_file']}), Ghidra {gi['version']}")
    items = corpus_items(data_dir, only)
    with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        metas = list(pool.map(
            lambda cb: _run_one(tree, ghidra, data_dir, label, cb[0], cb[1], timeout, force), items))
    session["finished_at"] = _now()
    (label_dir / "session.json").write_text(json.dumps(session, indent=1, ensure_ascii=False) + "\n",
                                           encoding="utf-8")
    return {"session": session, "runs": metas}


# ---------------------------------------------------------------------------
# score
# ---------------------------------------------------------------------------

def _report_stats(run_dir: Path) -> dict[str, Any]:
    """karadul report.json'dan fonksiyon sayısı + çapraz-binary aday sayısı."""
    rp = run_dir / "out" / "report.json"
    if not rp.is_file():
        return {}
    rep = json.loads(rp.read_text(encoding="utf-8"))
    stages = rep.get("pipeline", {}).get("stages", {})
    static = stages.get("static", {}).get("stats", {})
    recon = stages.get("reconstruct", {}).get("stats", {})
    return {
        "ghidra_function_count": static.get("ghidra_function_count"),
        "statistics_functions": rep.get("statistics", {}).get("functions"),
        # karadul bu sayacı yalnız >0 iken yazar; yoksa None (= aday eklenmedi).
        "cross_binary_candidates": recon.get("cross_binary_candidates"),
        "stages_ok": {k: v.get("success") for k, v in stages.items()},
    }


def _harness_fingerprint() -> dict[str, str]:
    files = [HERE / "function_f1.py", REPO_ROOT / "tests" / "benchmark" / "metrics.py",
             REPO_ROOT / "tests" / "benchmark" / "benchmark_runner.py"]
    return {_tilde(p.relative_to(REPO_ROOT)): f1.sha256_file(p)[:16] for p in files}


def score_label(label: str, data_dir: Path, only: Optional[list[str]] = None) -> dict[str, Any]:
    label_dir = data_dir / "runs" / label
    session = json.loads((label_dir / "session.json").read_text(encoding="utf-8"))
    per_binary: list[dict[str, Any]] = []
    for corpus, b in corpus_items(data_dir, only):
        run_dir = label_dir / corpus / b
        meta_path = run_dir / "run.json"
        meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.is_file() else {}
        entry: dict[str, Any] = {"corpus": corpus, "binary": b,
                                 "run": {k: meta.get(k) for k in (
                                     "status", "exit_code", "duration_s", "command", "cwd",
                                     "started_at", "target_sha256")}}
        if meta.get("status") != "ok":
            entry["error"] = meta.get("error") or f"koşu durumu: {meta.get('status', 'yok')}"
            per_binary.append(entry)
            continue
        gt_path = data_dir / "corpus" / corpus / "gt" / f"{b}.gt.json"
        res = f1.score_run(gt_path, run_dir)
        res["inputs"] = {k: _tilde(v) for k, v in res["inputs"].items()}
        entry.update({k: v for k, v in res.items() if k not in ("corpus", "binary")})
        entry["karadul_report"] = _report_stats(run_dir)
        entry["cfg_cache_before"] = meta.get("cfg_cache_before", {})
        per_binary.append(entry)

    ok = [r for r in per_binary if "strict" in r]
    corpora = sorted({r["corpus"] for r in per_binary})
    agg = {c: f1.aggregate([r for r in ok if r["corpus"] == c]) for c in corpora}
    warnings = []
    for r in ok:
        tag = f"{r['corpus']}/{r['binary']}"
        if r["checks"].get("analyzed_sha256_matches_gt") is not True:
            warnings.append(f"{tag}: analiz edilen binary GT'nin stripped binary'si ile doğrulanamadı")
        if r["ghidra_named_scored"]:
            warnings.append(f"{tag}: Ghidra puanlanan fonksiyonları kendisi isimlendirmiş "
                            f"(sızıntı şüphesi): {r['ghidra_named_scored']}")
        if (r["karadul_report"].get("cross_binary_candidates") or 0) > 0:
            warnings.append(f"{tag}: çapraz-binary önbellek adayı kullanıldı "
                            f"({r['karadul_report']['cross_binary_candidates']})")
    for r in per_binary:
        if "error" in r:
            warnings.append(f"{r['corpus']}/{r['binary']}: ÖLÇÜLEMEDİ — {r['error']}")
    return {
        "schema": "karadul-function-f1-report/1",
        "label": label,
        "scored_at": _now(),
        "karadul": {"commit": session["tree"]["commit"], "tree": session["tree"]["tree"],
                    "dirty_files": session["tree"]["dirty_files"],
                    "version": session["tree"]["karadul_version"]},
        "environment": {"ghidra": session["ghidra"], "python": session["python"],
                        "platform": session["platform"], "jobs": session["jobs"],
                        "timeout_s": session["timeout_s"]},
        "harness": _harness_fingerprint(),
        "corpus_manifest": _tilde(MANIFEST_PATH.relative_to(REPO_ROOT)),
        "definitions": DEFINITIONS,
        "reproduce": [
            "python scripts/measurement/measure.py prepare",
            f"python scripts/measurement/measure.py analyze --tree {session['tree']['tree']} "
            f"--label {label} --jobs {session['jobs']}",
            f"python scripts/measurement/measure.py score --label {label} --out <json>",
        ],
        "aggregate": agg,
        "warnings": warnings,
        "per_binary": per_binary,
    }


DEFINITIONS = {
    "gt": "debug ELF .symtab STT_FUNC (T+t), yürütülebilir bölüm, adres başına bir kayıt; CRT/linker fonksiyonları puanlanmaz",
    "detected_code": "Ghidra fonksiyonlarından yürütülebilir ve PLT olmayan bölüme düşenler (PLT + EXTERNAL thunk hariç)",
    "coverage": "|GT ∩ detected_code| / |detected_code|",
    "prediction": "puanlanan GT fonksiyonuna karadul naming_map'inin verdiği jenerik olmayan isim (FUN_/sub_/adres etiketli isimler jeneriktir)",
    "strict": "TP = normalize(tahmin)==normalize(GT) [metrics.AccuracyCalculator._normalize, FIX-4 sufiks]; FP = yanlış tahmin; FN = puanlanan GT - TP; P=TP/(TP+FP), R=TP/|puanlanan GT|",
    "lenient": "aynı popülasyon, TP = AccuracyCalculator.compare_name exact/semantic/partial",
    "legacy": "eski benchmark_runner Mode 3 tanımı (yalnız tarihsel köprü)",
    "micro": "korpus içi TP/FP/GT toplanıp hesaplanır",
    "macro": "binary F1'lerinin aritmetik ortalaması",
}


def write_report(report: dict[str, Any], path: Path) -> None:
    """Raporu yaz; per_function kayıtları tek satır (diff'lenebilir, kısa)."""
    slots: dict[str, str] = {}
    shadow = json.loads(json.dumps(report))
    for i, r in enumerate(shadow.get("per_binary", [])):
        pf = r.get("per_function")
        if not pf:
            continue
        keys = []
        for j, rec in enumerate(pf):
            key = f"__PF_{i}_{j}__"
            slots[f'"{key}"'] = json.dumps(rec, ensure_ascii=False)
            keys.append(key)
        r["per_function"] = keys
    text = json.dumps(shadow, indent=1, ensure_ascii=False)
    for key, line in slots.items():
        text = text.replace(key, line, 1)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + "\n", encoding="utf-8")


def print_table(report: dict[str, Any]) -> None:
    print(f"\n### {report['label']} — karadul {report['karadul']['commit'][:10]}")
    print("| korpus | binary | GT (puan) | tespit (kod) | kapsama | TP | FP | FN | P | R | F1 | lenient F1 | legacy F1 |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for r in report["per_binary"]:
        if "strict" not in r:
            print(f"| {r['corpus']} | {r['binary']} | ÖLÇÜLEMEDİ: {r.get('error')} |")
            continue
        s, c = r["strict"], r["coverage"]
        leg = r.get("legacy", {}).get("f1", "—")
        print(f"| {r['corpus']} | {r['binary']} | {r['gt']['functions']} ({r['gt']['scored']}) | "
              f"{r['detected']['ghidra_total']} ({r['detected']['code']}) | {c['ratio']:.1%} | "
              f"{s['tp']} | {s['fp']} | {s['fn']} | {s['precision']:.3f} | {s['recall']:.3f} | "
              f"{s['f1']:.3f} | {r['lenient']['f1']:.3f} | {leg} |")
    for c, a in report["aggregate"].items():
        if not a:
            continue
        s = a["strict"]
        print(f"| **{c}** | {a['binaries']} binary | {a['gt_scored']} puan | | "
              f"{a['coverage']['ratio']:.1%} | {s['micro']['tp']} | {s['micro']['fp']} | "
              f"{s['micro']['fn']} | {s['micro']['precision']:.3f} | {s['micro']['recall']:.3f} | "
              f"mikro {s['micro']['f1']:.3f} / makro {s['macro']['f1']:.3f} | "
              f"{a['lenient']['micro']['f1']:.3f} | |")
    for w in report["warnings"]:
        print(f"UYARI: {w}")


# ---------------------------------------------------------------------------
# compare (A/B)
# ---------------------------------------------------------------------------

def sign_test_p(gained: int, lost: int) -> float:
    """Eşleştirilmiş işaret testi (McNemar tam binom), iki yönlü p.

    Aynı fonksiyon A'da ve B'de puanlanır; yalnız durum DEĞİŞTİREN fonksiyonlar
    bilgi taşır (b = kazanılan TP, c = kaybedilen TP). H0: değişim yönü yazı-tura.
    """
    n = gained + lost
    if n == 0:
        return 1.0
    k = min(gained, lost)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * tail)


def compare(a_path: Path, b_path: Path) -> int:
    a = json.loads(a_path.read_text(encoding="utf-8"))
    b = json.loads(b_path.read_text(encoding="utf-8"))
    if a.get("harness") != b.get("harness"):
        print("UYARI: iki rapor farklı harness sürümüyle puanlanmış — önce ikisini de "
              "`score` ile yeniden puanlayın.")
    if a["environment"]["ghidra"] != b["environment"]["ghidra"]:
        print("UYARI: Ghidra sürümü farklı — fark motor değil Ghidra kaynaklı olabilir.")
    bi = {(r["corpus"], r["binary"]): r for r in b["per_binary"]}
    print(f"A={a['label']} ({a['karadul']['commit'][:10]})  B={b['label']} ({b['karadul']['commit'][:10]})")
    print("| korpus | binary | F1 A | F1 B | ΔF1 | P A→B | R A→B | kazanılan TP | kaybedilen TP |")
    print("|---|---|---|---|---|---|---|---|---|")
    pooled: dict[str, list[int]] = {}
    for ra in a["per_binary"]:
        rb = bi.get((ra["corpus"], ra["binary"]))
        if not rb or "strict" not in ra or "strict" not in rb:
            print(f"| {ra['corpus']} | {ra['binary']} | kıyaslanamadı |")
            continue
        sa, sb = ra["strict"], rb["strict"]
        fa = {p["addr"]: p for p in ra["per_function"]}
        fb = {p["addr"]: p for p in rb["per_function"]}
        gained = sorted(str(fb[k]["gt"]) for k in fb if fb[k]["status"] == "tp"
                        and fa.get(k, {}).get("status") != "tp")
        lost = sorted(str(fa[k]["gt"]) for k in fa if fa[k]["status"] == "tp"
                      and fb.get(k, {}).get("status") != "tp")
        acc = pooled.setdefault(ra["corpus"], [0, 0])
        acc[0] += len(gained)
        acc[1] += len(lost)
        print(f"| {ra['corpus']} | {ra['binary']} | {sa['f1']:.3f} | {sb['f1']:.3f} | "
              f"{sb['f1'] - sa['f1']:+.3f} | {sa['precision']:.3f}→{sb['precision']:.3f} | "
              f"{sa['recall']:.3f}→{sb['recall']:.3f} | {', '.join(gained) or '—'} | "
              f"{', '.join(lost) or '—'} |")
    for corpus, (g, lo) in pooled.items():
        ma = a["aggregate"].get(corpus, {}).get("strict", {}).get("micro", {})
        mb = b["aggregate"].get(corpus, {}).get("strict", {}).get("micro", {})
        print(f"{corpus}: mikro F1 {ma.get('f1')} -> {mb.get('f1')}; kazanılan TP={g}, "
              f"kaybedilen TP={lo}, işaret testi p={sign_test_p(g, lo):.3g}")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR,
                    help=f"ölçüm verisi (varsayılan {_tilde(DEFAULT_DATA_DIR)})")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("prepare", help="korpusu indir/aç, GT üret")

    def _run_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("--tree", type=Path, required=True, help="karadul'un koşulacağı ağaç")
        p.add_argument("--label", required=True, help="koşu etiketi (runs/<etiket>/)")
        p.add_argument("--ghidra", type=Path, default=DEFAULT_GHIDRA)
        p.add_argument("--jobs", type=int, default=DEFAULT_JOBS)
        p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_S)
        p.add_argument("--only", nargs="*", default=None,
                       help="yalnız bunlar: 'cat', 'debian-9.4-3', 'debian-9.4-3/cat'")
        p.add_argument("--force", action="store_true", help="ok koşuları da yeniden koş")

    _run_args(sub.add_parser("analyze", help="karadul'u ağaçtan koş"))
    sp = sub.add_parser("score", help="koşuları puanla")
    sp.add_argument("--label", required=True)
    sp.add_argument("--only", nargs="*", default=None)
    sp.add_argument("--out", type=Path, default=None)
    ap_all = sub.add_parser("all", help="prepare + analyze + score")
    _run_args(ap_all)
    ap_all.add_argument("--out", type=Path, default=None)
    cp = sub.add_parser("compare", help="iki sonuç JSON'unu kıyasla")
    cp.add_argument("a", type=Path)
    cp.add_argument("b", type=Path)

    args = ap.parse_args(argv)
    sys.stdout.reconfigure(line_buffering=True)  # arka planda/log'a yönlendirilince ilerleme görünsün
    data_dir = args.data_dir.expanduser()
    if args.cmd == "compare":
        return compare(args.a, args.b)
    if args.cmd in ("prepare", "all"):
        prepare(data_dir)
    if args.cmd in ("analyze", "all"):
        analyze(args.tree, args.label, data_dir, args.ghidra.expanduser(), args.jobs,
                args.timeout, args.only, args.force)
    if args.cmd in ("score", "all"):
        report = score_label(args.label, data_dir, args.only)
        out = args.out or (data_dir / "results" / f"{args.label}.json")
        write_report(report, out)
        print_table(report)
        print(f"\nsonuç: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
