#!/usr/bin/env python3
"""Karadul web arayuzu -- Black Widow konsolu (stdlib http.server, BAGIMLILIKSIZ).

Blackhat (2015) filmindeki Black Widow arayuzu estetiginde, karadul'un UCTAN UCA
akisini surer:
  1. GIRIS   -> analiz edilecek binary (yol VEYA uygulama adi) girilir
  2. ANALIZ  -> karadul pipeline GERCEKTEN calisir (subprocess), 5 stage +
                gnulib fingerprint / call-shape / boilerplate alt-asamalari
  3. SONUC   -> radyal cagri grafigi + isimlendirilmis fonksiyonlar

Endpoint'ler:
    GET  /                      -> index.html
    GET  /api/binaries          -> analiz edilebilir binary listesi (chip onerisi)
    POST /api/analyze           -> {binary} ile pipeline baslat, {job} dondur
    GET  /api/progress?job=ID   -> {stages, substages, finished, workspace, ...}
    GET  /api/model             -> aktif workspace'in fonksiyon+callgraph modeli
    GET  /api/decompiled/FUN_x  -> {addr, code}

Calistirma: python3 ui/server.py [baslangic_workspace_dir]
Tarayici:   http://127.0.0.1:8000
"""
from __future__ import annotations

import glob
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
HOME = Path.home()
WS: str | None = None
_ADDR_RE = re.compile(r"_[0-9a-f]{3,}$")
_FUN_RE = re.compile(r"FUN_[0-9a-fA-F]+")
_PORT = 8000
_CACHE: dict = {}
_CACHE_LOCK = threading.Lock()
_JOBS: dict = {}
_JOBS_LOCK = threading.Lock()
_MAX_RUNS = 6  # ui/_runs altinda tutulacak analiz sayisi (disk sinirlama)

STAGE_ORDER = ["identify", "static", "deobfuscate", "reconstruct", "report"]
STAGE_LABEL = {
    "identify": "HEDEF TESPİT",
    "static": "STATİK ANALİZ · GHIDRA DECOMPILE",
    "deobfuscate": "DEOBFUSKASYON",
    "reconstruct": "YENİDEN İNŞA · İSİMLENDİRME",
    "report": "RAPOR",
}
# reconstruct icindeki deterministik naming kanallari (canli log satirlari;
# --verbose + setup_logging aktifse akar, yoksa finish'te report.json'dan gelir)
SUBSTAGE_PATTERNS = [
    (re.compile(r"main kurtarildi"), "main entry recovery", None),
    (re.compile(r"gnulib fingerprint: (\d+) fonksiyon"), "gnulib string-fingerprint", 1),
    (re.compile(r"gnulib call-shape: (\d+) fonksiyon"), "gnulib call-shape", 1),
    (re.compile(r"ELF boilerplate: (\d+) fonksiyon"), "ELF/CRT boilerplate", 1),
]


# ---------------------------------------------------------------------------
# Yol yardimcilari
# ---------------------------------------------------------------------------
def _under(path: Path, root: Path) -> bool:
    """path, root'un altinda mi? (startswith yerine ayrac-guvenli)."""
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


# ---------------------------------------------------------------------------
# Workspace modeli (fonksiyon listesi + call graph)
# ---------------------------------------------------------------------------
def find_ws(ws_root: str) -> tuple[Path | None, Path | None]:
    p = Path(ws_root)
    nm = next(iter(p.rglob("reconstructed/src/naming_map.json")), None)
    dec = None
    for d in p.rglob("decompiled"):
        if d.is_dir() and next(d.glob("FUN_*.c"), None):
            dec = d
            if "ghidra" in str(d):
                break
    return nm, dec


def _classify(name: str) -> str:
    if name.startswith("FUN_"):
        return "unnamed"
    if _ADDR_RE.search(name):
        return "weak"
    return "named"


def _ws_binary_name(ws: str) -> str:
    parts = Path(ws).parts
    for i, p in enumerate(parts):
        if p == "workspaces" and i + 1 < len(parts):
            return parts[i + 1]
    return Path(ws).name


def build_model() -> dict | None:
    ws = WS  # global degisebilir -> yerel kopya
    if not ws:
        return None
    with _CACHE_LOCK:
        if _CACHE.get("ws") == ws and "model" in _CACHE:
            return _CACHE["model"]
    nm_path, dec = find_ws(ws)
    if not nm_path or not dec:
        return None
    names = json.load(open(nm_path)).get("global", {})
    files = sorted(glob.glob(f"{dec}/FUN_*.c"))
    addrs = [os.path.basename(f)[:-2] for f in files]
    addr_set = set(addrs)

    calls: dict[str, list[str]] = {}
    indeg: dict[str, int] = {a: 0 for a in addrs}
    for f, addr in zip(files, addrs):
        try:
            text = Path(f).read_text(errors="ignore")
        except OSError:
            text = ""
        callees = (set(_FUN_RE.findall(text)) & addr_set)
        callees.discard(addr)
        calls[addr] = sorted(callees)
        for c in callees:
            indeg[c] = indeg.get(c, 0) + 1

    funcs = []
    for addr in addrs:
        name = names.get(addr, addr)
        cls = _classify(name)
        funcs.append({"addr": addr, "name": name, "cls": cls,
                      "out": len(calls[addr]), "in": indeg.get(addr, 0)})
    n_named = sum(1 for x in funcs if x["cls"] == "named")
    n_weak = sum(1 for x in funcs if x["cls"] == "weak")
    n_unnamed = sum(1 for x in funcs if x["cls"] == "unnamed")
    entry = max(funcs, key=lambda x: x["out"])["addr"] if funcs else None
    model = {
        "functions": funcs, "calls": calls, "names": names,
        "total": len(funcs), "named": n_named, "weak": n_weak,
        "unnamed": n_unnamed, "recovered": n_named + n_weak,
        "entry": entry, "workspace": str(ws), "binary": _ws_binary_name(ws),
    }
    with _CACHE_LOCK:
        _CACHE["ws"] = ws
        _CACHE["model"] = model
    return model


def activate_workspace(ws: str) -> None:
    global WS
    with _CACHE_LOCK:
        WS = ws
        _CACHE.pop("model", None)
        _CACHE.pop("ws", None)


# ---------------------------------------------------------------------------
# Analiz edilebilir binary listesi (chip onerisi)
# ---------------------------------------------------------------------------
def list_binaries() -> list[dict]:
    out: list[dict] = []
    seen = set()

    def add(path: Path, tag: str, note: str):
        try:
            rp = path.resolve()
        except OSError:
            return
        if not path.is_file() or rp in seen:
            return
        seen.add(rp)
        size = path.stat().st_size
        out.append({"path": str(rp), "name": path.stem if path.suffix else path.name,
                    "size": size, "size_h": _hsize(size), "tag": tag, "note": note})

    gt = HOME / "coreutils_gt"
    for f in sorted(gt.glob("*.stripped")):
        add(f, "coreutils", "GNU coreutils · stripped ELF")
    fx = PROJECT_ROOT / "tests/fixtures/coreutils/binaries/stripped"
    if fx.is_dir():
        for f in sorted(fx.iterdir()):
            if f.is_file():
                add(f, "fixture", "test fixture · stripped ELF")
    out.sort(key=lambda x: x["size"])
    return out


def _hsize(n: float) -> str:
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TB"


# ---------------------------------------------------------------------------
# Analiz job'i (subprocess) + progress
# ---------------------------------------------------------------------------
def resolve_binary(spec: str) -> str | None:
    """Kullanici girdisini (tam yol VEYA uygulama adi) gercek dosyaya cozumle."""
    spec = (spec or "").strip()
    if not spec:
        return None
    p = Path(spec).expanduser()
    if p.is_file():
        try:
            return str(p.resolve())
        except OSError:
            return None
    cands = [
        HOME / "coreutils_gt" / f"{spec}.stripped",
        HOME / "coreutils_gt" / spec,
        PROJECT_ROOT / "tests/fixtures/coreutils/binaries/stripped" / spec,
    ]
    for c in cands:
        if c.is_file():
            return str(c.resolve())
    w = shutil.which(spec)
    if w and Path(w).is_file():
        try:
            return str(Path(w).resolve())
        except OSError:
            return None
    return None


def _cleanup_runs(keep: int = _MAX_RUNS) -> None:
    """Eski ui/_runs/<job> dizinlerini buda (mtime'a gore son `keep` tut)."""
    base = PROJECT_ROOT / "ui" / "_runs"
    if not base.is_dir():
        return
    dirs = sorted((d for d in base.iterdir() if d.is_dir()),
                  key=lambda p: p.stat().st_mtime, reverse=True)
    for d in dirs[keep:]:
        shutil.rmtree(d, ignore_errors=True)


def _running_job() -> str | None:
    with _JOBS_LOCK:
        for jid, j in _JOBS.items():
            if j["proc"].poll() is None:
                return jid
    return None


def start_analysis(binary: str) -> dict:
    rp_str = resolve_binary(binary)
    if not rp_str:
        return {"error": f"bulunamadı: {binary[:50]}  (yol veya uygulama adı gir)"}
    rp = Path(rp_str)
    allowed_roots = [HOME, PROJECT_ROOT, Path("/usr"), Path("/bin"),
                     Path("/opt"), Path("/sbin")]
    if not any(_under(rp, r) for r in allowed_roots):
        return {"error": "izin verilmeyen konum"}
    if _running_job():
        return {"error": "zaten bir analiz sürüyor — bitmesini bekle"}
    _cleanup_runs()

    job = uuid.uuid4().hex[:10]
    run_dir = PROJECT_ROOT / "ui" / "_runs" / job
    run_dir.mkdir(parents=True, exist_ok=True)
    log_path = run_dir / "analyze.log"
    ws_out = run_dir / "ws"
    clean_out = run_dir / "clean"
    cmd = [sys.executable, "-m", "karadul", "analyze", str(rp),
           "--skip-dynamic", "--lmdb-sigdb", "--verbose",
           "--output-dir", str(ws_out), "--output", str(clean_out)]
    lf = None
    try:
        lf = open(log_path, "w")
        proc = subprocess.Popen(cmd, cwd=str(PROJECT_ROOT), stdout=lf,
                                stderr=subprocess.STDOUT)
    except OSError as e:
        if lf:
            try:
                lf.close()
            except OSError:
                pass
        return {"error": f"analiz başlatılamadı: {e}"}
    with _JOBS_LOCK:
        _JOBS[job] = {"proc": proc, "log": str(log_path), "ws_out": str(ws_out),
                      "run_dir": str(run_dir), "binary": rp.stem,
                      "started": time.time(), "lf": lf, "closed": False}
    return {"job": job, "binary": rp.stem}


def _report_substages(run_dir: str) -> list[dict]:
    """Tamamlanan analizin report.json'undan naming kanali sayilarini cek."""
    rj = Path(run_dir) / "clean" / "report.json"
    if not rj.is_file():
        hits = list(Path(run_dir).rglob("reports/report.json"))
        rj = hits[0] if hits else None
    if not rj or not rj.is_file():
        return []
    try:
        st = json.loads(rj.read_text())["pipeline"]["stages"]["reconstruct"]["stats"]
    except (json.JSONDecodeError, KeyError, OSError, TypeError):
        return []
    out: list[dict] = []
    if st.get("main_recovered"):
        out.append({"label": "main entry recovery", "count": None})
    for key, label in (("gnulib_recovered", "gnulib string-fingerprint"),
                       ("gnulib_callshape_recovered", "gnulib call-shape"),
                       ("elf_boilerplate_recovered", "ELF/CRT boilerplate")):
        v = st.get(key)
        if v:
            out.append({"label": label, "count": v})
    hc = st.get("naming_high_confidence")
    if hc:
        out.append({"label": "yüksek-güven isim", "count": hc})
    return out


def _job_progress(job: str) -> dict:
    with _JOBS_LOCK:
        j = _JOBS.get(job)
    if not j:
        return {"error": "job yok"}
    try:
        log = Path(j["log"]).read_text(errors="ignore")
    except OSError:
        log = ""

    done, times = set(), {}
    for m in re.finditer(r"OK (\w+): ([\d.]+)s", log):
        if m.group(1) in STAGE_ORDER:
            done.add(m.group(1))
            times[m.group(1)] = float(m.group(2))
    failed_stage = None
    mf = re.search(r"(?:FAIL|ERROR) (\w+):", log)
    if mf and mf.group(1) in STAGE_ORDER:
        failed_stage = mf.group(1)
    running = next((s for s in STAGE_ORDER if s not in done and s != failed_stage), None)
    stages = [{"key": s, "label": STAGE_LABEL[s],
               "status": ("done" if s in done else "failed" if s == failed_stage
                          else "running" if s == running else "pending"),
               "time": times.get(s)} for s in STAGE_ORDER]

    # alt-asamalar: canli log parse (setup_logging aktifse)
    substages = []
    for pat, label, grp in SUBSTAGE_PATTERNS:
        m = pat.search(log)
        if m:
            substages.append({"label": label,
                              "count": m.group(grp) if grp else None})

    proc = j["proc"]
    rc = proc.poll()
    finished = rc is not None
    workspace = None
    if finished:
        wsp = Path(j["ws_out"])
        hits = sorted(wsp.rglob("reconstructed/src/naming_map.json"),
                      key=lambda p: p.stat().st_mtime) if wsp.exists() else []
        if hits:
            workspace = str(hits[-1].parents[2])
        # finish'te kesin sayilar report.json'dan (log parse'a guvenme)
        rep_sub = _report_substages(j["run_dir"])
        if rep_sub:
            substages = rep_sub
        # log handle'i idempotent kapat
        with _JOBS_LOCK:
            if not j.get("closed"):
                try:
                    j["lf"].close()
                except OSError:
                    pass
                j["closed"] = True

    return {
        "stages": stages, "substages": substages, "finished": finished,
        "workspace": workspace, "elapsed": round(time.time() - j["started"], 1),
        "binary": j["binary"], "rc": rc,
        "tail": "\n".join(log.splitlines()[-6:]),
    }


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:
        pass

    def _send(self, code, ctype, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, "application/json", json.dumps(obj).encode("utf-8"))

    def do_GET(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            html = (Path(__file__).parent / "index.html").read_text(encoding="utf-8")
            self._send(200, "text/html; charset=utf-8", html.encode("utf-8"))
        elif path == "/favicon.ico":
            # kucuk seffaf favicon (404 gurultusunu onle)
            self._send(200, "image/svg+xml",
                       b'<svg xmlns="http://www.w3.org/2000/svg"/>')
        elif path == "/api/binaries":
            self._json({"binaries": list_binaries()})
        elif path == "/api/progress":
            qs = self.path.split("?", 1)[1] if "?" in self.path else ""
            q = dict(x.split("=", 1) for x in qs.split("&") if "=" in x)
            prog = _job_progress(q.get("job", ""))
            if prog.get("finished") and prog.get("workspace"):
                activate_workspace(prog["workspace"])
            self._json(prog)
        elif path in ("/api/model", "/api/functions"):
            d = build_model()
            self._json(d) if d else self._json({"error": "workspace yok"}, 404)
        elif path.startswith("/api/decompiled/"):
            addr = path.split("/api/decompiled/", 1)[1]
            if not re.fullmatch(r"FUN_[0-9a-fA-F]+", addr):
                self._json({"error": "geçersiz adres"}, 400)
                return
            _, dec = find_ws(WS) if WS else (None, None)
            p = (Path(dec) / f"{addr}.c") if dec else None
            if not p or not p.exists():
                self._json({"error": "decompiled yok"}, 404)
            else:
                self._json({"addr": addr, "code": p.read_text(errors="ignore")})
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):  # noqa: N802
        if self.path.split("?", 1)[0] == "/api/analyze":
            n = int(self.headers.get("Content-Length", 0) or 0)
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
            except json.JSONDecodeError:
                body = {}
            binary = body.get("binary", "")
            if not binary:
                self._json({"error": "binary belirtilmedi"}, 400)
                return
            self._json(start_analysis(binary))
        else:
            self._json({"error": "not found"}, 404)


if __name__ == "__main__":
    WS = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("KARADUL_WS")
    where = WS or "(giriş ekranı — UI'den binary seç)"
    print(f"Black Widow konsolu  ->  http://127.0.0.1:{_PORT}   {where}")
    ThreadingHTTPServer(("127.0.0.1", _PORT), Handler).serve_forever()
