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
    GET  /api/progress?job=ID   -> {stages, substages, finished, workspace, outcome, ...}
    GET  /api/jobs/current      -> süren iş {job, binary, elapsed} ya da {job: null}
    POST /api/cancel            -> {job} süren analizi iptal et (süreç grubu)
    GET  /api/model             -> aktif workspace'in fonksiyon+callgraph modeli
    GET  /api/decompiled/FUN_x  -> {addr, code}
    GET  /api/about             -> surum/Ghidra/JDK/imza DB/yollar (Hakkinda modali)

Calistirma: python3 ui/server.py [baslangic_workspace_dir]
Tarayici:   http://127.0.0.1:8000
"""
from __future__ import annotations

import copy
import dataclasses
import glob
import hashlib
import hmac
import json
import math
import os
import platform
import re
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# karadul içi -- kalıcı manuel-override deposu (Analist İncele & Düzelt) +
# ayar paneli için Config yükleyici (Faz 3). yaml çekirdek bağımlılık (config.py:10).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import yaml  # noqa: E402  (config.py hard-import eder -> her zaman kurulu)
from karadul.config import Config, ConfigValueError  # noqa: E402
from karadul.core import overrides  # noqa: E402
from karadul.reconstruction import name_validity  # noqa: E402
from karadul.core.naming_labels import (  # noqa: E402
    NAME_LABELS,
    PRE_NAME_KIND_MANUAL,
    SOURCE_C_NAMER,
)
# ÖL-4: ILERLEME olaylarının tek ayrıştırıcısı (CLI ile ortak; olay sözleşmesi olcek/PLAN.md §1).
from karadul.core.ilerleme import (  # noqa: E402
    ILERLEME_ONEKI,
    gosterim_alanlari,
    ilerleme_ayristir,
)
# KaradulLM terminali (P22c1): arayüz motor değildir, karadul.lm'i içe aktarabilir (tasarım §3.1 K-M1).
from karadul.lm import repl as lm_repl  # noqa: E402
from karadul.lm import session as lm_session  # noqa: E402
from karadul.lm.audit import AuditLog, session_log_path  # noqa: E402
from karadul.lm.backend import LlamaServerBackend  # noqa: E402
from karadul.lm.modes import ServerBinaryRefused, check_server_binary  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parent.parent
HOME = Path.home()
# Yazılabilir veri kökü: .app bundle'ında PROJECT_ROOT (Resources) READ-ONLY olabilir.
# KARADUL_DATA_DIR set ise yazmalar (karadul.yaml, _runs) oraya gider; yoksa PROJECT_ROOT
# (dev davranışı birebir korunur). Bundle launcher'ı bunu ~/Library/.../BlackWidow'a set eder.
_DATA_ROOT = Path(os.environ.get("KARADUL_DATA_DIR") or PROJECT_ROOT).expanduser().resolve()
try:
    _DATA_ROOT.mkdir(parents=True, exist_ok=True)
except OSError:
    _DATA_ROOT = PROJECT_ROOT  # son çare: yazılamıyorsa dev köküne düş
# Ayar paneli: knob'lar bu YAML'a atomik yazılır; analiz subprocess'i (cwd=_DATA_ROOT)
# --config ile yükler. Repo kökünde normalde YOK -> sıfırdan doğar, hiçbir şeyi ezmez.
_SETTINGS_YAML = _DATA_ROOT / "karadul.yaml"
WS: str | None = None
_ADDR_RE = re.compile(r"_[0-9a-f]{3,}$")
_FUN_RE = re.compile(r"FUN_[0-9a-fA-F]+")
# Decompile dosya adından düğüm kimliği (ARAYUZ-11): Ghidra adları C tanımlayıcısı ya da
# "operator.new" biçiminde; '/' ve baştaki '.' yok (yol geçişi olamaz). Uç doğrulaması ayrıca
# kimliğin o anki modelde olmasını ister.
_NODE_ID_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{0,200}")
_ADDR_HEADER_RE = re.compile(r"^// Address:\s+([0-9a-fA-F]+)\s*$", re.M)
# Port env'den: app_window.py boş bir port seçip burayı öyle başlatır. Sabit 8000
# hem çakışıyor hem de app_window'un KARADUL_PORT'u burada okunmadığı için o
# kaçış yolu fiilen kırıktı. _TOKEN: /api/ping ile "bu gerçekten bizim server"
# doğrulaması (yabancı veya öksüz servise bağlanmayı önler) VE istek jetonu:
# /api/ping dışındaki her /api/* isteği X-Karadul-Token başlığıyla bu jetonu
# taşımalı (Handler._guard). Env'de yoksa (tek başına dev koşusu) rastgele üretilir;
# boş jeton kabul edilmez.
_PORT = int(os.environ.get("KARADUL_PORT", "8000"))
_TOKEN = os.environ.get("KARADUL_TOKEN") or secrets.token_hex(16)
# POST gövdeleri küçük JSON (analiz hedefi, yeniden adlandırma, ayar knob'ları).
_MAX_BODY = 64 * 1024
_CACHE: dict = {}
_CACHE_LOCK = threading.Lock()
_JOBS: dict = {}
_JOBS_LOCK = threading.Lock()
_RENAME_LOCK = threading.Lock()  # naming_map oku-değiştir-yaz serileştirme
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
    """Ad haritası ve decompile dizini AYNI çalışma alanından (ARAYUZ-09, arayüz tarafı).

    Kök birden çok koşu içeriyorsa (ör. aynı hedefin iki zaman damgalı çalışma alanı) eskiden
    ilk rastlanan harita ile ilk rastlanan decompile dizini ayrı koşulardan gelebiliyordu.
    Artık en yeni ad haritası seçilir; decompile dizini yalnız onun çalışma alanında aranır.
    """
    p = Path(ws_root)
    maps = sorted(p.rglob("reconstructed/src/naming_map.json"),
                  key=lambda x: (x.stat().st_mtime, str(x)))
    nm = maps[-1] if maps else None
    root = nm.parents[2] if nm is not None else p
    dec = None
    for d in sorted(root.rglob("decompiled")):
        # ARAYUZ-11: sembollü ikilide FUN_ dosyası olmaz; her .c fonksiyon dosyası sayılır
        if d.is_dir() and next(d.glob("*.c"), None):
            dec = d
            if "ghidra" in str(d):
                break
    return nm, dec


def _report_outcome(report_path: Path) -> dict | None:
    """Analizin durumu report.json'daki aşama sonuçlarından (ARAYUZ-11); rapor yoksa None.

    Durum hesabı CLI'ın kendisidir (``karadul.cli._analysis_outcome``: çıkış kodu 0 tam /
    1 başarısız / 3 kısmi; P15a + P-S1'in ``partial`` / ``partial_reasons``'ı). Eskiden arayüz
    çalışma alanı bulununca aşamalara bakmadan sonuç ekranına geçiyor, başarısız ya da kısmi
    aşamanın izi kalmıyordu.
    """
    try:
        rep = json.loads(report_path.read_text(encoding="utf-8"))
        stages = rep["pipeline"]["stages"]
    except (json.JSONDecodeError, KeyError, OSError, TypeError, ValueError):
        return None
    if not isinstance(stages, dict):
        return None
    from types import SimpleNamespace

    from karadul.cli import _analysis_outcome   # tembel: ~0,5 sn, yalnız bitişte

    def _sr(v: dict):
        return SimpleNamespace(success=v.get("success") is True, skipped=v.get("skipped") is True,
                               errors=v.get("errors") or [], stats=v.get("stats") or {})

    st = {k: v for k, v in stages.items() if isinstance(v, dict)}
    out = _analysis_outcome(SimpleNamespace(stages={k: _sr(v) for k, v in st.items()}))
    rstats = (st.get("reconstruct") or {}).get("stats") or {}
    target = rep.get("target") if isinstance(rep.get("target"), dict) else {}
    return {
        "status": out["status"], "exit_code": out["exit_code"],
        "failed": out["failed"], "partial": out["partial"],
        "skipped": {k: v.get("skip_reason") for k, v in st.items() if v.get("skipped") is True},
        "reconstruct_status": rstats.get("reconstruct_status")
        if isinstance(rstats, dict) else None,
        "target_type": target.get("type"),
    }


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


def _read_static_json(root: Path, name: str):
    """workspace static/<name>.json oku (once dogrudan yol, sonra rglob).

    KISIT: bu artifact'lar static asamanin CIKTISI; yoksa/bozuksa None (uydurma yok).
    """
    direct = root / "static" / f"{name}.json"
    p = direct if direct.is_file() else next(iter(root.rglob(f"static/{name}.json")), None)
    if not p:
        return None
    try:
        return json.loads(p.read_text())
    except (json.JSONDecodeError, OSError, ValueError):
        return None


def _security_info(ws: str | None = None) -> dict:
    """Paketleyici (packer) + anti-debug ozeti -- YALNIZCA workspace static/ artifact'larindan.

    KISIT: build_model'i ASLA bozmaz. Artifact yok/okunamaz/bos ise ilgili alan None
    doner (exception yayilmaz). ``packer`` ANCAK en az bir fingerprint varsa dolar
    -> temiz (paketsiz) binary'de None -> UI banner render EDILMEZ. ``packer_name``
    hem UI icin (name) hem curl/kanit icin (packer_name) ikili anahtarla verilir.
    """
    ws = ws or WS
    out: dict = {"packer": None, "anti_debug": None}
    if not ws:
        return out
    root = Path(ws)
    try:
        pf = _read_static_json(root, "packer_fingerprints")
        if isinstance(pf, dict):
            fps = pf.get("fingerprints") or []
            if isinstance(fps, list) and fps and isinstance(fps[0], dict):
                top = fps[0]  # detect() confidence DESC -> ilk = en yuksek guven
                nm = top.get("packer_name") or top.get("name")
                out["packer"] = {
                    "name": nm,
                    "packer_name": nm,  # kanit/curl: security.packer.packer_name
                    "version": top.get("version"),
                    "confidence": top.get("confidence"),
                    "layers": top.get("layers_matched"),
                    "category": top.get("category"),
                    "evidence": [str(e) for e in (top.get("evidence") or [])][:8],
                }
    except Exception:  # noqa: BLE001 -- security bloku build_model'i cokertemez
        out["packer"] = None
    try:
        ad = _read_static_json(root, "anti_debug_findings")
        if isinstance(ad, dict):
            summ = ad.get("summary") if isinstance(ad.get("summary"), dict) else {}
            count = ad.get("total_findings")
            if count is None:
                count = summ.get("total")
            score = summ.get("anti_debug_score")
            if count:  # yalnizca gercek bulgu varsa
                out["anti_debug"] = {
                    "count": int(count),
                    "score": (float(score) if isinstance(score, (int, float)) else None),
                }
    except Exception:  # noqa: BLE001
        out["anti_debug"] = None
    return out


def _load_call_graph(dec: Path, ws: str):
    """Decompile dizininin yanındaki ``static/ghidra_call_graph.json``; yoksa çalışma alanında ara.

    Okunamazsa ya da JSON bozuksa None.
    """
    root = Path(ws).resolve()
    for parent in list(dec.resolve().parents)[:3]:
        if parent != root and root not in parent.parents:
            break  # çalışma alanının dışına çıkma
        p = parent / "ghidra_call_graph.json"
        if p.is_file():
            try:
                return json.loads(p.read_text())
            except (json.JSONDecodeError, OSError, ValueError):
                return None
    return _read_static_json(Path(ws), "ghidra_call_graph")


def _call_graph_edges(dec: Path, ws: str, addr_set: set[str],
                      extra_hex: dict[str, str] | None = None) -> dict[str, set[str]] | None:
    """Ghidra çağrı grafiğinden düğümler arasındaki çağrı kenarları: ``{çağıran: {çağrılan}}``.

    Grafik adrese anahtarlı (``edges[].from/to`` ya da ``nodes[adres].callees[].address``); adres
    düğüm kimliğine çevrilir: ``FUN_<adres>`` dosyaları adresinden, Ghidra'nın adlandırdığı
    dosyalar (``extra_hex``: adres → dosya adı; dosyanın ``// Address:`` başlığından) da
    ARAYUZ-11'den beri düğümdür. Yalnız iki ucu da decompile dosyası olan kenarlar tutulur.

    Dosya yok, okunamıyor, biçimi beklenen değil ya da grafiğin düğümleri bu decompile dizininin
    fonksiyonlarıyla hiç örtüşmüyorsa (başka bir koşunun grafiği) None: çağıran metin yöntemine
    düşer ve bunu işaretler.
    """
    data = _load_call_graph(dec, ws)
    if not isinstance(data, dict):
        return None
    by_hex = {a[4:].lower(): a for a in addr_set if a.startswith("FUN_")}
    by_hex.update({h.lower(): a for h, a in (extra_hex or {}).items()})

    def fun(address) -> str | None:
        if not isinstance(address, str):
            return None
        h = address.lower()
        if h.startswith("0x"):
            h = h[2:]
        return by_hex.get(h)

    pairs: list[tuple] = []
    nodes = data.get("nodes")
    edges = data.get("edges")
    if isinstance(edges, list):
        pairs = [(e.get("from"), e.get("to")) for e in edges if isinstance(e, dict)]
    elif isinstance(nodes, dict):
        pairs = [(a, c.get("address")) for a, n in nodes.items() if isinstance(n, dict)
                 for c in (n.get("callees") or []) if isinstance(c, dict)]
    else:
        return None
    if isinstance(nodes, dict):
        known = {fun(a) for a in nodes}
    else:
        known = {fun(x) for pair in pairs for x in pair}
    known.discard(None)
    if addr_set and not known:
        return None
    out: dict[str, set[str]] = {}
    for src, dst in pairs:
        s, d = fun(src), fun(dst)
        if s and d:
            out.setdefault(s, set()).add(d)
    return out


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
    try:
        with open(nm_path) as _fh:
            names = json.load(_fh).get("global", {})
    except (json.JSONDecodeError, OSError, AttributeError):
        names = {}
    # ARAYUZ-11: Ghidra'nın adlandırdığı fonksiyonlar (entry, _DT_INIT, ithal taslakları; sembollü
    # ikilide hepsi) de düğümdür: eskiden yalnız FUN_*.c sayılıyor, sembollü ikilide model hiç
    # kurulamıyor, adlı fonksiyonlar açılamıyordu. Kimlik dosya adıdır; Karadul'un ad sayaçlarına
    # girmezler (cls "ghidra").
    files = sorted(f for f in glob.glob(f"{dec}/*.c") if _NODE_ID_RE.fullmatch(Path(f).stem))
    addrs = [Path(f).stem for f in files]
    addr_set = set(addrs)
    texts: dict[str, str] = {}
    extra_hex: dict[str, str] = {}
    for f, addr in zip(files, addrs):
        try:
            texts[addr] = Path(f).read_text(errors="ignore")
        except OSError:
            texts[addr] = ""
        if not addr.startswith("FUN_"):
            m = _ADDR_HEADER_RE.search(texts[addr][:400])
            if m:
                extra_hex[m.group(1)] = addr

    # Çağrı kenarları Ghidra'nın çağrı grafiğinden. Metinde adı geçip grafikte kenarı olmayan FUN_
    # başvurusu (adresin alınması: geri çağrı kaydı, tablo, karşılaştırma) çağrı sayılmaz,
    # ``addr_refs``'e gider. Grafik okunamazsa metin yöntemine düşülür ve bu ``calls_source="text"``
    # ile açıkça işaretlenir (arayüz listeyi "metinde adı geçenler" diye etiketler).
    graph = _call_graph_edges(Path(dec), ws, addr_set, extra_hex)
    calls_source = "ghidra_call_graph" if graph is not None else "text"
    calls: dict[str, list[str]] = {}
    addr_refs: dict[str, list[str]] | None = {} if graph is not None else None
    indeg: dict[str, int] = {a: 0 for a in addrs}
    for f, addr in zip(files, addrs):
        text = texts[addr]
        mentioned = (set(_FUN_RE.findall(text)) & addr_set)
        mentioned.discard(addr)
        if graph is None:
            callees = mentioned
        else:
            callees = set(graph.get(addr, ()))
            callees.discard(addr)
            refs = mentioned - callees
            if refs:
                addr_refs[addr] = sorted(refs)
        calls[addr] = sorted(callees)
        for c in callees:
            indeg[c] = indeg.get(c, 0) + 1

    # Liste etiketi: temiz haritadaki kayıt o anki adı anlatıyorsa kayıttaki etiket; kayıt yoksa,
    # bayatsa ya da etiket taşımıyorsa None (arayüz o satıra işaret çizmez).
    cmap = _clean_mappings(ws)
    funcs = []
    for addr in addrs:
        name = names.get(addr, addr)
        cls = _classify(name) if addr.startswith("FUN_") else "ghidra"
        funcs.append({"addr": addr, "name": name, "cls": cls,
                      "out": len(calls[addr]), "in": indeg.get(addr, 0),
                      "label": (_record_label(_name_record(cmap, addr, name))
                                if cls != "ghidra" else None)})
    # KaradulLM (P22c1): analistin kabul ettiği model adları AYRI katman (motor adı < model adı < elle ad;
    # önceki tasarım §5.3). ``names`` ve ad sayaçları değişmez (model adı Karadul'un adı sayılmaz); elle ad
    # verilmiş düğümde model adı gösterilmez. Depo okunamazsa ``None`` (bilinmiyor; boş sözlük "yok" demektir).
    model_names: dict | None = {}
    bh = _active_binary_hash(ws)
    if bh:
        try:
            manual = overrides.all_names(bh)
            for a, rec in overrides.model_names(bh).items():
                if a in addr_set and a not in manual:
                    model_names[a] = {"name": rec["name"], "oneri_kimligi": rec.get("proposal_id"),
                                      "hukum": rec.get("hukum")}
        except (OSError, ValueError):
            model_names = None
    n_named = sum(1 for x in funcs if x["cls"] == "named")
    n_weak = sum(1 for x in funcs if x["cls"] == "weak")
    n_unnamed = sum(1 for x in funcs if x["cls"] == "unnamed")
    n_ghidra = sum(1 for x in funcs if x["cls"] == "ghidra")
    entry = max(funcs, key=lambda x: x["out"])["addr"] if funcs else None
    # Guvenlik ozeti (packer/anti-debug): DEFANSIF -- patlarsa model bozulmaz,
    # security alanlari None kalir (mevcut alanlar aynen doner).
    try:
        security = _security_info(ws)
    except Exception:  # noqa: BLE001
        security = {"packer": None, "anti_debug": None}
    model = {
        "functions": funcs, "calls": calls, "calls_source": calls_source,
        "addr_refs": addr_refs, "names": names, "model_names": model_names,
        # total: Karadul'un adlandırma işi olan FUN_ fonksiyonları; Ghidra adlıları ayrı
        "total": len(funcs) - n_ghidra, "named": n_named, "weak": n_weak,
        "unnamed": n_unnamed, "recovered": n_named + n_weak, "ghidra_named": n_ghidra,
        "entry": entry, "workspace": str(ws), "binary": _ws_binary_name(ws),
        "security": security,
        # ARAYUZ-11: analizin durumu (tam / kısmi / başarısız) çalışma alanının raporundan
        "run_status": _report_outcome(Path(ws) / "reports" / "report.json"),
    }
    with _CACHE_LOCK:
        _CACHE["ws"] = ws
        _CACHE["model"] = model
    return model


def activate_workspace(ws: str) -> None:
    global WS
    with _CACHE_LOCK:
        changed = ws != WS
        WS = ws
        _CACHE.pop("model", None)
        _CACHE.pop("ws", None)
    # Çalışma alanı DEĞİŞTİYSE açık KaradulLM oturumu kapanır (P22c1; tasarım §4.6): oturumun okuduğu veri
    # artık arayüzün gösterdiği değil. Aynı alanın önbellek tazelemesi (ad düzeltme) oturumu kapatmaz.
    if changed:
        _lm_close_current(lm_session.CLOSE_WORKSPACE, wait=None)


# ---------------------------------------------------------------------------
# Analist İncele & Düzelt -- kanıt sunumu + kalıcı yeniden-adlandırma (Faz 1)
# ---------------------------------------------------------------------------
_STR_LIT_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')     # C string sabiti
_CALL_ID_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")  # cagri sembolu
_DAT_RE = re.compile(r"DAT_[0-9a-fA-F]+")
_HASH_HEX_RE = re.compile(r"[0-9a-f]+")


def _atomic_write_json(path: Path, obj) -> None:
    """obj'i path'e atomik yaz (tmp + os.replace) -> yarim/bozuk JSON olmaz."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass


# Çalışma alanından temiz çıktıya bakılacak en çok üst dizin sayısı. Düzen
# <koşu>/<output-dir>/workspaces/<ad>/<zaman> (arayüz koşusu: <koşu>=ui/_runs/<iş>, temiz çıktı
# <koşu>/clean; CLI koşusu: temiz çıktı --output ile verilen herhangi bir ad, ör. <koşu>/out).
_CLEAN_SEARCH_DEPTH = 4


def _clean_output_dir(ws: str | None) -> Path | None:
    """Bu çalışma alanının temiz çıktı dizini (``report.json`` + ``naming_map.json``) ya da None.

    ARAYUZ-09 (arayüz tarafı): eskiden yalnız ``clean/report.json`` adı aranıyor, bulunamayınca
    üst dizinlere köke kadar çıkılıyordu; CLI'ın ``--output out`` koşusunda etiketler hiç
    okunmuyor, başka bir koşunun ``clean/``'ı da seçilebiliyordu. Artık en çok
    ``_CLEAN_SEARCH_DEPTH`` üst dizinin doğrudan alt dizinlerine bakılır ve yalnız
    ``report.json``'daki ``target.hash`` çalışma alanının kendi özetine eşit olan çıktı kabul
    edilir (başka ikilinin çıktısı karışmaz). Özet bilinmiyorsa hiçbir çıktı kabul edilmez.
    """
    if not ws:
        return None
    want = _workspace_target_hash(ws)
    if not want:
        return None
    want = want.lower()
    try:
        ws_path = Path(ws).resolve()
    except OSError:
        return None
    for anc in [ws_path, *list(ws_path.parents)[:_CLEAN_SEARCH_DEPTH]]:
        try:
            kids = sorted((d for d in anc.iterdir() if d.is_dir()),
                          key=lambda d: (d.name != "clean", d.name))
        except OSError:
            continue
        for d in kids:
            rep = d / "report.json"
            if not (rep.is_file() and (d / "naming_map.json").is_file()):
                continue
            try:
                h = json.loads(rep.read_text(encoding="utf-8"))["target"]["hash"]
            except (json.JSONDecodeError, KeyError, OSError, TypeError, ValueError):
                continue
            if isinstance(h, str) and h.lower() == want:
                return d
        if anc.name == "_runs":  # ui/_runs sinirini gecme
            break
    return None


def _workspace_target_hash(ws: str) -> str | None:
    """Çalışma alanının KENDİ kaydındaki ikili özeti (sha256); bulunamazsa None.

    Sıra: ``reports/report.json`` → ``target.hash``; ``raw/target_info.json`` → ``file_hash``;
    son olarak ``raw/`` altındaki tek ikili kopyanın sha256'sı. Analiz hattı elle verilen adları ``context.target.file_hash`` ile bulur
    (stages.py); aynı değer budur. İkili ADA göre aranmaz (ARAYUZ-14: ``ls`` →
    ``/bin/ls`` gibi başka bir dosyanın özetine yazılıyordu).
    """
    root = Path(ws)

    def _json_field(p: Path, *keys):
        try:
            v = json.loads(p.read_text(encoding="utf-8"))
            for k in keys:
                v = v[k]
            return v if isinstance(v, str) and v else None
        except (json.JSONDecodeError, KeyError, OSError, TypeError, ValueError):
            return None

    h = (_json_field(root / "reports" / "report.json", "target", "hash")
         or _json_field(root / "raw" / "target_info.json", "file_hash"))
    if not h:
        raw = root / "raw"
        bins = [p for p in raw.iterdir() if p.is_file() and p.name != "target_info.json"] \
            if raw.is_dir() else []
        if len(bins) == 1:
            try:
                hh = hashlib.sha256()
                with open(bins[0], "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        hh.update(chunk)
                h = hh.hexdigest()
            except OSError:
                h = None
    return h


def _active_binary_hash(ws: str | None = None) -> str | None:
    """Aktif binary'nin STABIL anahtari (sha256): yalnız çalışma alanının kendi kaydından.

    Ayni WS icin cache'lenir (ayni binary -> ayni hash, rename'de degismez).
    """
    ws = ws or WS
    if not ws:
        return None
    with _CACHE_LOCK:
        if _CACHE.get("bhash_ws") == ws and _CACHE.get("bhash"):
            return _CACHE["bhash"]
    h = _workspace_target_hash(ws)
    if h:
        h = h.lower()
        if not _HASH_HEX_RE.fullmatch(h):  # overrides path guvenligi
            h = None
    if h:
        with _CACHE_LOCK:
            _CACHE["bhash_ws"] = ws
            _CACHE["bhash"] = h
    return h


def _clean_mappings(ws: str | None = None) -> dict:
    """Aktif run'in clean/naming_map.json kayıtları (provenance/hint icin).

    Biçim 1.1'de koda uygulanmamış kayıtlar (imza veritabanının tanıdığı ithal semboller dahil)
    ``candidates`` bölümündedir; kütüphane çağrısı ipucu ``library`` alanını onlardan okur. Bir
    anahtar iki bölümden yalnız birindedir: birleşim 1.0'daki ``mappings`` kümesidir.
    """
    ws = ws or WS
    if not ws:
        return {}
    with _CACHE_LOCK:
        if _CACHE.get("cmap_ws") == ws and "cmap" in _CACHE:
            return _CACHE["cmap"]
    m: dict = {}
    rd = _clean_output_dir(ws)
    if rd:
        try:
            data = json.loads((rd / "naming_map.json").read_text())
            m = {**(data.get("candidates") or {}), **(data.get("mappings") or {})}
        except (json.JSONDecodeError, OSError, TypeError, AttributeError):
            m = {}
    if not isinstance(m, dict):
        m = {}
    with _CACHE_LOCK:
        _CACHE["cmap_ws"] = ws
        _CACHE["cmap"] = m
    return m


# ---------------------------------------------------------------------------
# Ad kökeni: etiket, gerçek puan, kanal, kanıt (temiz haritadaki kayıttan)
#
# KURAL: arayüze giden her alan kayıtta YAZILI olandır. Etiket puandan, kaynaktan ya da kanaldan
# türetilmez; kayıtta etiket yoksa etiket None gider ve rozet çizilmez. Etiketlerin yazımı
# karadul.core.naming_labels'tan gelir.
# ---------------------------------------------------------------------------
def _name_record(cmap, addr: str, current: str) -> dict | None:
    """Temiz haritada ``addr`` kaydı; yalnız kayıt fonksiyonun O ANKİ adını anlatıyorsa döner.

    Bayat kayıt koruması: ad arayüzden değiştirilince ``reconstructed/src/naming_map.json``
    güncellenir, temiz haritadaki kayıt eski adı anlatmayı sürdürür. Kayıttaki ``new_name`` o anki
    adla aynı değilse kaydın etiketi, puanı, kanalı ve kanıtı bu ada ait değildir -> None.
    Adı olmayan fonksiyonun (ad == adres) anlatılacak kökeni yoktur -> None.
    """
    rec = cmap.get(addr) if isinstance(cmap, dict) else None
    if not isinstance(rec, dict) or current == addr:
        return None
    if rec.get("new_name") != current:
        return None
    return rec


def _record_label(rec) -> str | None:
    """Kayıtta yazılı etiket; kayıt ya da sözlükte geçerli bir etiket yoksa None."""
    if not isinstance(rec, dict):
        return None
    label = rec.get("label")
    return label if isinstance(label, str) and label in NAME_LABELS else None


def _record_confidence(rec: dict) -> float | None:
    """Kayıttaki gerçek puan; sayı değilse (``null`` dahil) None.

    Eski biçimli c_namer kaydı ``label`` anahtarını hiç taşımaz ve puanı her ad için sabit 1.0'dı
    (ölçülmüş bir güven değil): o değer gösterilmez.
    """
    value = rec.get("confidence")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(value):
        return None
    if rec.get("source") == SOURCE_C_NAMER and "label" not in rec:
        return None
    return value


def _record_channel(rec: dict) -> str | None:
    channel = rec.get("channel")
    return channel if isinstance(channel, str) and channel else None


def _record_evidence(rec: dict):
    """Kısa kanıt: dizgi ya da ``{rol, kanit_sayisi}`` nesnesi; başka her şey None."""
    evidence = rec.get("evidence")
    if isinstance(evidence, (str, dict)) and evidence:
        return evidence
    return None


def _provenance(cmap, addr: str, current: str) -> dict | None:
    """``addr``'in o anki adının kökeni (kanıt kartı).

    Kayıt yok ya da fonksiyon adsız -> None. Kayıt başka bir adı anlatıyorsa (bayat) ad elle
    verilmiştir: yalnız ``{"source": "elle"}`` döner; etiket, puan, kanal ve kanıt gösterilmez.
    """
    raw = cmap.get(addr) if isinstance(cmap, dict) else None
    if not isinstance(raw, dict) or current == addr:
        return None
    rec = _name_record(cmap, addr, current)
    if rec is None:
        return {"source": PRE_NAME_KIND_MANUAL}
    prov = {
        "source": rec.get("source"),
        "confidence": _record_confidence(rec),
        "label": _record_label(rec),
        "channel": _record_channel(rec),
        "evidence": _record_evidence(rec),
    }
    if rec.get("library"):
        prov["library"] = rec["library"]
    return prov


def _decompiled_text(addr: str) -> str:
    """addr icin decompiled FUN_x.c metnini oku (yoksa bos)."""
    _, dec = find_ws(WS) if WS else (None, None)
    if not dec:
        return ""
    p = Path(dec) / f"{addr}.c"
    if not p.is_file():
        return ""
    try:
        return p.read_text(errors="ignore")
    except OSError:
        return ""


_NAMING_ROLE_FIELDS = ("string_roles", "role_evidence")   # P12b dizgi rolü, P12a geri çağrı rolü
_NAMING_ROLES_MAX = 20


def _naming_roles(addr: str) -> dict | None:
    """addr için köken kaydındaki AD OLMAYAN rol kanıtları (yalnız gerçek veri; yoksa None).

    ``string_roles`` (P12b / AD-01): fonksiyonun kebap dizgisini hangi çağrıya kaçıncı argüman
    olarak verdiği ve o çağrının ikilide kaç farklı anahtar aldığı. ``role_evidence`` (P12a /
    AD-02): fonksiyonun hangi API'ye geri çağrı olarak verildiği.
    """
    nm, _ = find_ws(WS) if WS else (None, None)
    if nm is None:
        return None
    try:
        data = json.loads(nm.with_name("naming_provenance.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    out: dict = {}
    for alan in _NAMING_ROLE_FIELDS:
        rows = data.get(alan)
        if isinstance(rows, dict) and isinstance(rows.get(addr), list):
            kept = [r for r in rows[addr] if isinstance(r, dict)]
            if kept:
                out[alan] = kept[:_NAMING_ROLES_MAX]
    return out or None


def _extract_strings(text: str, cap: int = 20) -> list[str]:
    """Decompiled koddan string sabitlerini cikar (dedup, sirali, cap'li)."""
    out: list[str] = []
    seen: set[str] = set()
    for s in _STR_LIT_RE.findall(text):
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s if len(s) <= 160 else s[:157] + "...")
        if len(out) >= cap:
            break
    return out


# Cok yaygin / ayirt-edici-olmayan cagrilar: gosterilebilir ama sona atilir.
_NOISE_CALLS = {
    "free", "malloc", "calloc", "realloc", "memcpy", "memmove", "memset",
    "strlen", "strcmp", "strcpy", "strchr", "abort", "exit",
    "__stack_chk_fail", "__errno_location", "__assert_fail",
    "__ctype_get_mb_cur_max", "__mempcpy_chk", "__memcpy_chk", "__memset_chk",
}


def _external_call_hints(text: str, cmap: dict, cap: int = 6) -> list[str]:
    """Cagrilan harici/kutuphane sembollerini ADIYLA surface et (yorumsuz).

    DURUSTLUK: imza-DB'nin `library` etiketi GURULTULU (or. __assert_fail->cffi
    yanlis), o yuzden kutuphane ADINI GOSTERMIYORUZ -- sadece "bu recognized bir
    harici cagri" filtresi olarak kullaniyoruz. Gosterilen sembol adi decompiled
    metinden GERCEK. Ayirt-edici cagrilar (or. __gmpz_*) one, jenerikler sona.
    """
    called = set(_CALL_ID_RE.findall(text))
    distinctive: list[str] = []
    common: list[str] = []
    for name in sorted(called):
        rec = cmap.get(name)
        if not isinstance(rec, dict) or not rec.get("library"):
            continue  # yalnizca imza-DB'nin tanidigi harici semboller
        (common if name in _NOISE_CALLS else distinctive).append(f"{name} çağrılıyor")
    return (distinctive + common)[:cap]


def _bsim_shadow() -> dict:
    """bsim_shadow.json: bare-hex adres -> en iyi aday {name, similarity}."""
    ws = WS
    if not ws:
        return {}
    with _CACHE_LOCK:
        if _CACHE.get("bsim_ws") == ws and "bsim" in _CACHE:
            return _CACHE["bsim"]
    out: dict = {}
    p = next(iter(Path(ws).rglob("reconstructed/bsim_shadow.json")), None)
    if p:
        try:
            for m in json.loads(p.read_text()).get("matches", []):
                # placeholder adaylari (FUN_/DAT_/adres-sonekli) ELE -- bunlar
                # golge-DB'nin isimsiz kendi eslesmeleri; "aday" olarak degeri yok.
                cands = [c for c in (m.get("bsim_candidates") or [])
                         if (nm := str(c.get("name") or ""))
                         and not nm.startswith(("FUN_", "DAT_"))
                         and not _ADDR_RE.search(nm)]
                if cands:
                    best = max(cands, key=lambda c: c.get("similarity", 0) or 0)
                    out[str(m.get("function_addr"))] = {
                        "name": best.get("name"), "similarity": best.get("similarity")}
        except (json.JSONDecodeError, OSError, TypeError, ValueError):
            out = {}
    with _CACHE_LOCK:
        _CACHE["bsim_ws"] = ws
        _CACHE["bsim"] = out
    return out


def _signature_candidates() -> set[str] | None:
    """``reconstructed/signature_matches.json``'daki imza adaylarının Ghidra adları (``original``).

    Kayıt yoksa ya da okunamıyorsa None: "aday yok" diye bilinmez.
    """
    ws = WS
    if not ws:
        return None
    with _CACHE_LOCK:
        if _CACHE.get("sig_ws") == ws and "sig" in _CACHE:
            return _CACHE["sig"]
    out: set[str] | None = None
    p = next(iter(Path(ws).rglob("reconstructed/signature_matches.json")), None)
    if p:
        try:
            matches = json.loads(p.read_text()).get("matches")
            if isinstance(matches, list):
                # P15c: dizgi / çağrı deseni kaydı fonksiyonun kimliği değil davranış tahminidir;
                # "imza eşleşmesi var" sayılmaz (yalnız kimlik iddiası: simge / bayt deseni).
                from karadul.analyzers.signature_db import CLAIM_BEHAVIOR, claim_for_method
                out = {str(m.get("original")) for m in matches
                       if isinstance(m, dict) and m.get("original")
                       and (m.get("claim") or claim_for_method(str(m.get("method") or "")))
                       != CLAIM_BEHAVIOR}
        except (json.JSONDecodeError, OSError, TypeError, ValueError, AttributeError):
            out = None
    with _CACHE_LOCK:
        _CACHE["sig_ws"] = ws
        _CACHE["sig"] = out
    return out


def _recon_stats() -> dict:
    """Aktif run'in report.json reconstruct.stats bloku (teshis baglami)."""
    ws = WS
    if not ws:
        return {}
    with _CACHE_LOCK:
        if _CACHE.get("rstats_ws") == ws and "rstats" in _CACHE:
            return _CACHE["rstats"]
    st: dict = {}
    p = next(iter(Path(ws).rglob("reports/report.json")), None)
    if p:
        try:
            st = json.loads(p.read_text())["pipeline"]["stages"]["reconstruct"]["stats"]
        except (json.JSONDecodeError, OSError, KeyError, TypeError):
            st = {}
    if not isinstance(st, dict):
        st = {}
    with _CACHE_LOCK:
        _CACHE["rstats_ws"] = ws
        _CACHE["rstats"] = st
    return st


def _naming_diagnosis(addr: str, text: str, cmap: dict, cls: str) -> dict:
    """Neden isimsiz/zayif kaldi? YALNIZCA gercek sinyallerden teshis (uydurma yok).

    verdict: bsim_shadow | app_wrapper | app_specific | ambiguous
    """
    hexa = addr[4:] if addr.startswith("FUN_") else addr
    signals: list[str] = []

    # 1) imza durumu. "eşleşme yok" yalnız imza eşleşme kaydı okunup bu fonksiyon için aday
    # bulunmadığında yazılır. Aday varsa (ada uygulanmamış olsa da) ya da kayıt okunamıyorsa bu iddia
    # yazılmaz; yerine başka bir iddia da konmaz.
    sig = _signature_candidates()
    no_candidate = sig is not None and addr not in sig
    if cls == "weak":
        signals.append("Yalnızca zayıf/adres-sonekli isim — kesin imza eşleşmesi yok"
                       if no_candidate else "Yalnızca zayıf/adres-sonekli isim")
    elif no_candidate:
        signals.append("Uygulanabilir imza/parmak izi eşleşmesi yok")

    # 2) BSim gölge (bare-hex, sifir-dolgulu da dene)
    bs = _bsim_shadow()
    bsim = bs.get(hexa) or bs.get(hexa.lstrip("0"))
    sim = (bsim or {}).get("similarity") or 0
    strong_bsim = bool(bsim and sim >= 0.80)
    if bsim:
        signals.append(
            f"BSim: '{bsim['name']}' %{round(sim * 100)} benzer — GÖLGE modunda "
            "(isimlendirmeye beslenmiyor)")

    # 3) ayirt edici kutuphane cagrilari (anlamli sinyal)
    ext = _external_call_hints(text, cmap, cap=4)
    if ext:
        signals.append("Çağırdığı bilinen fonksiyonlar: "
                       + ", ".join(h.replace(" çağrılıyor", "") for h in ext))

    # 4) hesaplama motoru -- BINARY GENELI baglam (per-function iddia DEGIL).
    # Yalnizca hesaplama füzyonu HICBIR fonksiyonu isimlendiremediyse (cfa==0)
    # goster; sayisal esik hardcode edilmez (config drift'e karsi).
    rs = _recon_stats()
    cfm = rs.get("computation_fusion_matches")
    cfa = rs.get("computation_fusion_accepted") or 0
    if cfm and not cfa:
        # P11 / BORU-03: füzyon adı ad kanalına yalnız computation.enable_fusion_naming
        # açıkken verir; kabul olasılığı kaynağın ölçülmüş kesinliğidir.
        signals.append(f"Bu binary genelinde hesaplama füzyonu hiçbir adı kabul etmedi "
                       f"({cfm} adreste aday; kabul, kaynağın ölçülmüş kesinliğine bağlı ve "
                       f"füzyon öntanımda ad haritasına bağlı değil)")

    # verdict + insan-okunur neden
    if strong_bsim:
        verdict = "bsim_shadow"
        # ARAYUZ-15: arayüzde karşılığı olmayan ayara ("İmzalar → BSim") yönlendirme ve
        # ölçülmemiş "otomatik isimlenebilir" vaadi yok; yalnız olgu.
        reason = (f"BSim adayı: '{bsim['name']}', %{round(sim * 100)} benzer. Aday ad kanalına "
                  "bağlı değil (gölge kipi) ve bu kanalın doğruluğu ölçülmedi; adı kodla "
                  "karşılaştırıp elle verin.")
    elif ext:
        verdict = "app_wrapper"
        reason = ("Uygulamaya özgü sarmalayıcı: bilinen kütüphane fonksiyonları çağırıyor ama "
                  "kendisi standart bir fonksiyon değil — eşleşecek imza yok. Çağrılarından ne "
                  "yaptığını çıkarıp elle isimlendir.")
    else:
        verdict = "app_specific"
        reason = ("Uygulamaya özgü fonksiyon (programın kendi kodu). Deterministik motor yalnızca "
                  "bilinen kütüphane/derleyici fonksiyonlarını isimlendirir; buna imza/parmak izi "
                  "yok — isim insan analizinden gelmeli.")
    return {"verdict": verdict, "reason": reason, "signals": signals}


def _known_node(addr: str) -> bool:
    """Uçlara gelen düğüm kimliği: biçimi güvenli VE o anki modelde var (FUN_ ya da Ghidra adı).

    Model yoksa yalnız FUN_ biçimi kabul edilir (eski davranış; uç zaten 404 verir).
    """
    if not isinstance(addr, str) or not _NODE_ID_RE.fullmatch(addr):
        return False
    model = build_model()
    if not model:
        return bool(_FUN_RE.fullmatch(addr))
    return any(f["addr"] == addr for f in model["functions"])


def _evidence(addr: str) -> dict:
    """addr icin kanit paketi (yalnizca gercek veri)."""
    model = build_model()
    if not model:
        return {"__code": 404, "error": "workspace yok"}
    names = model["names"]
    calls = model["calls"]
    current = names.get(addr, addr)
    node_cls = next((f["cls"] for f in model["functions"] if f["addr"] == addr), None)

    cls_of = {f["addr"]: f["cls"] for f in model["functions"]}

    def node(a: str) -> dict:
        nm = names.get(a, a)
        return {"addr": a, "name": nm, "cls": cls_of.get(a) or _classify(nm)}

    callees = [node(c) for c in calls.get(addr, [])]
    callers = [node(a) for a in sorted(a for a, cl in calls.items() if addr in cl)]

    text = _decompiled_text(addr)
    cmap = _clean_mappings()
    prov = _provenance(cmap, addr, current)

    cls = node_cls or _classify(current)
    return {
        "addr": addr,
        "current_name": current,
        "cls": cls,
        # "ghidra_call_graph": callers/callees gerçek çağrı; "text": metinde adı geçenler (grafik yok)
        "calls_source": model.get("calls_source"),
        "callers": callers,
        "callees": callees,
        "strings": _extract_strings(text),
        "provenance": prov,
        # ad olmayan rol kanıtı (P12a role_evidence, P12b string_roles); yoksa None
        "naming_roles": _naming_roles(addr),
        "hints": _external_call_hints(text, cmap),
        # neden isimsiz/zayif kaldi? (yalnizca isimli olmayanlar icin)
        # Ghidra'nın kendi adı (ithal taslağı, entry ...) Karadul'un adlandırma işi değil: teşhis yok
        "diagnosis": (_naming_diagnosis(addr, text, cmap, cls)
                      if cls not in ("named", "ghidra") else None),
    }


def _do_rename(addr: str, name: str) -> dict:
    """addr'i name olarak yeniden adlandir: naming_map global patch + kalici override.

    Basarida {"ok":True,"addr","name"}; hata durumunda {"__code":N,"error":..}.
    """
    if not (_FUN_RE.fullmatch(addr) or _DAT_RE.fullmatch(addr)):
        return {"__code": 400, "error": "geçersiz adres (FUN_/DAT_<hex>)"}
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name or ""):
        return {"__code": 400, "error": "geçersiz isim (C tanımlayıcısı olmalı)"}
    ws = WS
    if not ws:
        return {"__code": 404, "error": "workspace yok"}
    nm_path, _ = find_ws(ws)
    if not nm_path:
        return {"__code": 404, "error": "naming_map yok"}
    # Kalıcı kayıt yazılamayacaksa hiçbir şey yazılmaz (ARAYUZ-14): eskiden naming_map
    # güncellenip {"ok": true} dönüyor, özet yoksa ya da kayıt patlarsa ad sessizce kayboluyordu.
    bh = _active_binary_hash(ws)
    if not bh:
        return {"__code": 409, "error": "ad kalıcı kaydedilemez: çalışma alanında ikilinin "
                                        "özeti yok (reports/report.json, raw/) — ad verilmedi"}
    # oku-değiştir-yaz'ı serileştir (ThreadingHTTPServer -> eşzamanlı rename yarışı)
    with _RENAME_LOCK:
        try:
            data = json.loads(Path(nm_path).read_text())
        except (json.JSONDecodeError, OSError):
            return {"__code": 500, "error": "naming_map okunamadı"}
        if not isinstance(data, dict):
            data = {}
        names = data.get("global") if isinstance(data.get("global"), dict) else {}
        reason = _rename_reject_reason(ws, addr, name, names)
        if reason:
            return {"__code": 409 if reason.startswith("çakışma") else 400, "error": reason}
        # önce kalıcı kayıt: yazılamazsa naming_map de değişmez (ikisi birbirini tutar)
        try:
            overrides.set_name(bh, addr, name, binary=_ws_binary_name(ws))
        except (ValueError, OSError) as e:
            return {"__code": 500, "error": f"ad kalıcı kayda yazılamadı ({e}) — ad verilmedi"}
        data.setdefault("global", {})[addr] = name
        try:
            _atomic_write_json(Path(nm_path), data)
        except OSError as e:
            return {"__code": 500, "error": f"naming_map yazılamadı ({e}); ad kalıcı kayda "
                                            "yazıldı, sonraki analizde uygulanır"}

    activate_workspace(ws)  # model cache temizle -> sonraki /api/model taze
    return {"ok": True, "addr": addr, "name": name, "persisted": True,
            "binary_hash": bh}


def _ghidra_function_names(ws: str) -> dict[str, str]:
    """İkilideki Ghidra fonksiyon adları (ithaller dahil): ad → sahibinin Ghidra adı."""
    data = _read_static_json(Path(ws), "ghidra_functions")
    funcs = data.get("functions") if isinstance(data, dict) else None
    if not isinstance(funcs, list):
        return {}
    pairs = [(str(f.get("name") or ""), bool(f.get("is_thunk") or f.get("is_external")))
             for f in funcs if isinstance(f, dict)]
    return name_validity.existing_function_names(pairs)


def _rename_reject_reason(ws: str, addr: str, name: str, names: dict) -> str | None:
    """Elle verilen adın ret nedeni (okunur ileti); verilebilirse None.

    Anahtar sözcük / tip adı (``int``, ``return``, ``uint8_t``) ve başka bir fonksiyonun
    adıyla çakışma reddedilir: sonraki analizde ad zorla uygulanır, çift tanım ya da
    derlenmez kod üretirdi. Kurallar adlandırma hattının tek ad kapısından
    (``karadul.reconstruction.name_validity``).
    """
    lexical = name_validity.lexical_reject_reason(name)
    if lexical == name_validity.REASON_KEYWORD:
        return f"geçersiz isim: '{name}' C anahtar sözcüğü"
    if lexical == name_validity.REASON_TYPE_NAME:
        return f"geçersiz isim: '{name}' bir tip adı"
    if lexical is not None:
        return "geçersiz isim (C tanımlayıcısı olmalı)"
    for other, cur in names.items():
        if other != addr and cur == name:
            return f"çakışma: '{name}' adı zaten {other} fonksiyonunda"
    owner = _ghidra_function_names(ws).get(name)
    if owner is not None and owner != addr:
        return f"çakışma: '{name}' ikilide var olan bir fonksiyonun adı ({owner})"
    return None


# ---------------------------------------------------------------------------
# Ayar paneli (Faz 3) + kendi imza yollari (Faz 4) -- SADE, tek YAML dosyasi
#
# Paneldeki düğmeler karadul.yaml'a BÖLÜMLÜ yazılır ve analiz bu dosyayı --config ile
# yükler (P15a'nın katı yükleyicisi). Kayıt dosyayı BİRLEŞTİREREK yazar (ARAYUZ-06): yalnız
# panelin anahtarları değişir, dosyadaki öbür bölüm ve anahtarlar (Ghidra yolu, deney
# bayrakları, network.allow_reference_download ...) yerinde kalır. Ayrıca:
#   * computation_recovery.enabled -> suffix'siz hedeflerde etkileşimsiz koruma False'a
#     zorlayabildiği için analize ayrıca --compute-recovery / --no-compute-recovery geçilir.
#   * network.enabled -> yükleyici okur (P15a: veri indiren alt izinler ana anahtarı izler);
#     açıksa analize --enable-network de geçilir (CLI bu bayrakla kaynak eşlemeyi de açar).
#     Panel ağın bugünkü etkisini `network_effect` ile gösterir (ARAYUZ-05).
#   * binary_reconstruction.max_functions_to_process panelden kaldırıldı (ARAYUZ-04): boru
#     hattı okumuyor (config.INERT_SETTINGS). Panel eskiden dosyaya yazıyordu; kayıt anahtarı
#     dosyadan siler ve bunu uyarıyla bildirir.
# ---------------------------------------------------------------------------
# Panelin yazdığı anahtarlar (bölüm -> anahtarlar). Kayıt yalnız bunlara dokunur.
_SETTINGS_KEYS = {
    "binary_reconstruction": ("min_naming_confidence", "pipeline_iterations",
                              "external_signature_paths", "ghidra_data_type_archives"),
    "computation_recovery": ("enabled",),
    "network": ("enabled",),
    "name_merger": ("unk_threshold",),
}
# Eskiden panelin yazdığı, bugün etkisiz anahtar: kayıtta dosyadan silinir (ARAYUZ-04).
_SETTINGS_RETIRED = (("binary_reconstruction", "max_functions_to_process"),)


class SettingsFileError(ValueError):
    """karadul.yaml okunamıyor ya da birleştirilemiyor (kayıt dosyayı değiştirmez)."""
def _as_float01(v, default: float) -> float:
    """v'yi [0,1] float'a getir; sayisal degilse/NaN ise default."""
    try:
        f = float(v)
    except (TypeError, ValueError):
        return default
    if f != f:  # NaN
        return default
    return max(0.0, min(1.0, f))


def _as_int(v, lo: int, default: int) -> int:
    """v'yi tamsayiya getir, alt sinir lo; gecersizse default."""
    try:
        i = int(v)
    except (TypeError, ValueError):
        return default
    return max(lo, i)


def _as_bool(v) -> bool:
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _atomic_write_yaml(path: Path, obj) -> None:
    """obj'i path'e atomik YAML yaz (tmp + os.replace) -> yarim/bozuk dosya olmaz.

    Anahtar sırası korunur (sort_keys=False): birleştirilen dosyada kullanıcının sırası kalır.
    """
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            yaml.safe_dump(obj, f, default_flow_style=False,
                           allow_unicode=True, sort_keys=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass


def _settings_raw_yaml() -> dict:
    """karadul.yaml'i HAM oku. Dosya yoksa {}; okunamıyor, ayrıştırılamıyor ya da kökü
    sözlük değilse ``SettingsFileError`` (kayıt böyle bir dosyanın üstüne yazmaz)."""
    p = _SETTINGS_YAML
    if not p.is_file():
        return {}
    try:
        d = yaml.safe_load(p.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as e:
        raise SettingsFileError(f"{p} okunamadı: {e}") from e
    except yaml.YAMLError as e:
        raise SettingsFileError(f"{p} YAML olarak ayrıştırılamadı: {e}") from e
    if d is None:
        return {}
    if not isinstance(d, dict):
        raise SettingsFileError(f"{p}: kök bir sözlük değil ({type(d).__name__})")
    return d


def _settings_config() -> tuple[Config, list[str]]:
    """Analizin yükleyeceği yapılandırma ve yükleyicinin sorunları.

    Dosya yoksa öntanımlar (``Config.load``'un cwd'deki karadul.yaml'a düşmesi istenmez:
    analiz yalnız bu dosyayı --config ile alır). Yükleyici reddederse öntanımlar + sorunlar.
    """
    if not _SETTINGS_YAML.is_file():
        return Config(), []
    try:
        return Config.load(_SETTINGS_YAML), []
    except ConfigValueError as e:
        problems = [str(p) for p in (getattr(e, "problems", None) or [])] or [str(e)]
        return Config(), problems


def _network_effect(cfg: Config) -> dict:
    """Ağ düğmesinin bu ayarlarla analizde açacağı izinler (ARAYUZ-05).

    Düğme açıkken analize --enable-network geçilir; CLI o bayrakla ``network.enable`` ve
    ``source_match.enabled = True`` yapar (karadul/cli.py analyze). Burada aynısı kopya
    yapılandırma üstünde uygulanır; sonuç okuyucuların baktığı koşullardır:
    .d.ts indirme (``naming/pipeline.py``), kaynak eşleme (Layer 1.5), başvuru kaynağını
    indirip derleme (``_feedback_naming_refdiff.reference_download_allowed``).
    """
    net = cfg.network
    enabled = net.enabled is True
    source_match = bool(cfg.source_match.enabled)
    if enabled:
        net = dataclasses.replace(net)
        net.enable(explicit_keys={k.split(".", 1)[1] for k in cfg.yaml_keys
                                  if k.startswith("network.")})
        source_match = True
    return {
        "enabled": enabled,
        "dts_fetch": enabled and net.allow_dts_fetch is True,
        "source_match": enabled and source_match and net.allow_source_match is True,
        "reference_download": enabled and net.allow_reference_download is True,
    }


def _read_settings() -> dict:
    """Panel düğmeleri: değerler yükleyicinin gerçekten kuracağı yapılandırmadan.

    ``warnings``: yükleyicinin etkisiz saydığı anahtarlar (``inert_setting_warnings``);
    ``errors``: yükleyicinin reddettiği anahtarlar (analiz bu dosyayla başlamaz).
    """
    cfg, problems = _settings_config()
    br = cfg.binary_reconstruction
    cr = cfg.computation_recovery
    nm = cfg.name_merger
    # tek UI alani: external + gdt yollarini birlestir (POST tekrar ayirir)
    sig_paths = [str(p) for p in br.external_signature_paths] + \
                [str(p) for p in br.ghidra_data_type_archives]
    try:
        warnings = list(cfg.inert_setting_warnings())
    except Exception:  # noqa: BLE001 -- uyarı listesi paneli düşürmez
        warnings = []
    return {
        "knobs": {
            "min_naming_confidence": round(float(br.min_naming_confidence), 4),
            "unk_threshold": round(float(nm.unk_threshold), 4),
            "pipeline_iterations": int(br.pipeline_iterations),
            "computation_recovery_enabled": bool(cr.enabled),
            "network_enabled": cfg.network.enabled is True,
            "signature_paths": sig_paths,
            # uygulama tercihi (ui_prefs.json; karadul.yaml'a yazılmaz) -- MEK-04
            "update_check": _read_ui_prefs()["update_check"],
        },
        "network_effect": _network_effect(cfg),
        "warnings": warnings,
        "errors": problems,
        "path": str(_SETTINGS_YAML),
        "exists": _SETTINGS_YAML.is_file(),
    }


_SIG_REJECT_EXT = (".fidb", ".sig")   # parser yok -> kapsam disi


def _classify_sig_paths(raw) -> tuple[list, list, list]:
    """Kullanicinin imza yollarini uzantiya gore ayir + uyari uret.

    Donen: (external_signature_paths, ghidra_data_type_archives, warnings).
      .json / dizin / diger  -> external (_load_external_auto tuketir)
      .gdt                    -> ghidra_data_type_archives
      .fidb / .sig            -> reddet (desteklenmiyor)
      tekil .pat              -> external'a ekle + "dizin ver" uyarisi
    """
    ext: list[str] = []
    gdt: list[str] = []
    warns: list[str] = []
    if not isinstance(raw, list):
        return ext, gdt, warns
    seen: set[str] = set()
    for item in raw[:64]:   # makul ust sinir
        s = str(item or "").strip()
        if not s or len(s) > 4096 or s in seen:
            continue
        seen.add(s)
        low = s.lower()
        if low.endswith(_SIG_REJECT_EXT):
            warns.append(f"{s} — .fidb/.sig desteklenmiyor (atlandı)")
            continue
        if low.endswith(".gdt"):
            gdt.append(s)
        else:
            ext.append(s)
            if low.endswith(".pat"):
                warns.append(f"{s} — tekil .pat yüklenmeyebilir; .pat'leri bir DİZİN içinde ver")
    return ext, gdt, warns


def _merge_settings(raw: dict, panel: dict) -> tuple[dict, list[str]]:
    """Paneldeki değerleri mevcut YAML sözlüğüne birleştir (ARAYUZ-06).

    Yalnız ``_SETTINGS_KEYS``'teki anahtarlar yazılır; dosyadaki öbür bölüm ve anahtarlar
    olduğu gibi kalır. ``_SETTINGS_RETIRED`` anahtarları silinir (bildirilir). Bölüm boşsa
    (``tools:`` -> None) sözlük açılır; sözlük olmayan bir değer taşıyorsa ``SettingsFileError``
    (üstüne yazmak kullanıcının değerini siler).
    """
    merged = copy.deepcopy(raw)   # YAML'ın tarih vb. tipleri de korunur
    notes: list[str] = []
    for section, values in panel.items():
        cur = merged.get(section)
        if cur is None:
            cur = {}
        if not isinstance(cur, dict):
            raise SettingsFileError(
                f"karadul.yaml: '{section}' bir bölüm (sözlük) değil; panel bu dosyaya yazmaz")
        for key, value in values.items():
            cur[key] = value
        merged[section] = cur
    for section, key in _SETTINGS_RETIRED:
        sec = merged.get(section)
        if isinstance(sec, dict) and key in sec:
            del sec[key]
            notes.append(f"{section}.{key} dosyadan kaldırıldı: boru hattı bu ayarı okumuyor "
                         "(etkisiz; panelden de kaldırıldı)")
    return merged, notes


def _write_settings(knobs) -> dict:
    """Panel düğmelerini WHITELIST + tip/aralık doğrulamayla karadul.yaml'a BİRLEŞTİREREK yaz.

    Yalnız panelin anahtarları değişir (keyfi/kötü anahtar yazılmaz); dosyanın geri kalanı
    korunur. Dosya ayrıştırılamıyorsa hiçbir şey yazılmaz (409).
    """
    if not isinstance(knobs, dict):
        return {"__code": 400, "error": "knobs sözlük değil"}
    ext_paths, gdt_paths, warns = _classify_sig_paths(knobs.get("signature_paths"))
    base = Config()   # öntanımlar tek kaynaktan (karadul/config.py)
    # WHITELIST: yazılan değerler SADECE bu sabit iskeletten kurulur (injection guard).
    panel = {
        "binary_reconstruction": {
            "min_naming_confidence": _as_float01(
                knobs.get("min_naming_confidence"),
                base.binary_reconstruction.min_naming_confidence),
            "pipeline_iterations": _as_int(
                knobs.get("pipeline_iterations"), 1,
                base.binary_reconstruction.pipeline_iterations),
            "external_signature_paths": ext_paths,
            "ghidra_data_type_archives": gdt_paths,
        },
        "computation_recovery": {
            "enabled": _as_bool(knobs.get("computation_recovery_enabled")),
        },
        "network": {
            "enabled": _as_bool(knobs.get("network_enabled")),
        },
        "name_merger": {
            "unk_threshold": _as_float01(knobs.get("unk_threshold"),
                                         base.name_merger.unk_threshold),
        },
    }
    try:
        merged, notes = _merge_settings(_settings_raw_yaml(), panel)
    except SettingsFileError as e:
        return {"__code": 409, "error": f"{e} — dosya değiştirilmedi"}
    try:
        _atomic_write_yaml(_SETTINGS_YAML, merged)
    except OSError as e:
        return {"__code": 500, "error": f"karadul.yaml yazılamadı: {e}"}
    if "update_check" in knobs:
        try:
            _write_ui_prefs({"update_check": _as_bool(knobs.get("update_check"))})
        except OSError as e:
            return {"__code": 500, "error": f"arayüz tercihi yazılamadı: {e}"}
    out = _read_settings()   # geri-oku: yükleyicinin gerçekten kurduğu değerler
    out["ok"] = True
    out["warnings"] = warns + notes + out.get("warnings", [])
    return out


# ---------------------------------------------------------------------------
# Hakkinda paneli (/api/about) -- SADECE OKUNAN GERCEK
#
# Kural: okunamayan alan null/false doner, UYDURULMAZ. Endpoint ASLA 500 atmaz.
# Pahali isler (java -version subprocess'i, git, Ghidra properties okuma) SUREC
# BASINA BIR KEZ yapilir -> _ABOUT_STATIC; modal her acilista beklemez.
# ---------------------------------------------------------------------------
_ABOUT_STATIC: dict | None = None
_ABOUT_LOCK = threading.Lock()

# Hakkında notlarındaki ad ölçümü (ARAYUZ-03). Sayılar elle seçilmez: tek kaynak son ürün
# ölçümünün JSON'u (`source`; kol `arm`). Paketli uygulamada docs/ yok, bu yüzden değerler
# burada durur; tests/test_p17_hakkinda.py her değerin kaynak JSON'daki değerle aynı olduğunu
# denetler (ölçüm yenilenince bu sözlük ve test birlikte güncellenir). Eski "F1 ~0.45-0.49"
# bandı yalnız LTO'lu Ubuntu coreutils ölçümüydü; bugünkü ürünü anlatmıyordu.
_NAME_MEASUREMENT = {
    "source": "docs/arge/2026-11-10_n1_adim3/urun_olcumu_fark_yeni_yeni2.json",
    "arm": "yeni",            # JSON'daki kol anahtarı (kol adı: yeni2)
    "arm_name": "yeni2",
    "code_version": "1.22.1",
    "date": "2026-11-12",
    "binaries": 118,
    "named": 2261,            # toplam.havuz.ad_verilen
    "wrong": 672,             # toplam.havuz.yanlis
    "macro_wrong": 0.527804,  # toplam.makro.yanlis_orani.makro
    "population": 21371,      # toplam.havuz.dogru_kapsam.n
    "exact_correct": 1120,    # toplam.havuz.dogru_kapsam.k
    "certain_named": 262,     # kesin_etiket.havuz.ad_verilen
    "certain_correct": 249,   # kesin_etiket.havuz.dogru
}


def _tr_int(n: int) -> str:
    """Türkçe binlik ayraç (ölçüm belgeleriyle aynı yazım): 21371 -> '21 371'."""
    return f"{int(n):,}".replace(",", " ")


def _tr_pct(x: float) -> str:
    """Oran -> '%29,7' (bir ondalık, virgüllü)."""
    return "%" + f"{100.0 * float(x):.1f}".replace(".", ",")


def _measurement_notes(m: dict) -> list[str]:
    """Ölçüm künyesinden Hakkında notları. Metindeki her sayı ``m``'den gelir."""
    return [
        (f"Ad ölçümü ({m['date']}; {m['code_version']} kodu; geliştirme setinde "
         f"{m['binaries']} ikili; ölçüt özgün adla tam eşitlik): "
         f"verilen {_tr_int(m['named'])} fonksiyon adından {_tr_int(m['wrong'])} tanesi yanlış "
         f"({_tr_pct(m['wrong'] / m['named'])}; program ortalaması {_tr_pct(m['macro_wrong'])}). "
         f"Ölçüme giren {_tr_int(m['population'])} fonksiyonun yalnız "
         f"{_tr_int(m['exact_correct'])} tanesine ({_tr_pct(m['exact_correct'] / m['population'])}) "
         f"özgün adı verildi."),
        (f"'kesin' etiketli adlar: {_tr_int(m['certain_named'])} adın "
         f"{_tr_int(m['certain_correct'])} tanesi doğru "
         f"({_tr_pct(m['certain_correct'] / m['certain_named'])}). Öbür etiketlerdeki adları "
         f"kanıt kartından denetleyin."),
        f"Sonraki sürümler bu ölçümü yinelemedi. Kaynak: {m['source']}.",
    ]


_ABOUT_NOTES = [
    "Araştırma prototipi — üretim ya da adli kullanım için doğrulanmadı.",
    *_measurement_notes(_NAME_MEASUREMENT),
]
# LMDB imza DB konumu (K-5, P15b): motorla AYNI sıra, tek kaynak
# karadul.config.resolve_sig_lmdb_path (lmdb içe aktarılmaz; DB AÇILMIYOR, yalnız
# data.mdb boyutu okunuyor). Eskiden burada ~/.karadul/signatures.lmdb sabitti:
# motor veri kökündeki yeni veritabanını açarken panel eskisini gösterirdi.


def _safe(fn, default):
    """fn() -> deger; her turlu patlamada default. Hakkinda hicbir sey icin cokmez."""
    try:
        return fn()
    except Exception:  # noqa: BLE001 -- panel bilgi amacli, hata yayilmamali
        return default


def _run_capture(cmd: list[str], timeout: float = 4.0) -> str | None:
    """Kisa komut calistir, stdout+stderr birlesik dondur; patlarsa None.

    DIKKAT: ``java -version`` ciktisini STDOUT'a DEGIL STDERR'e yazar ->
    stderr=STDOUT sart. start_new_session KULLANILMAZ (bkz. start_analysis:847
    fork deadlock notu); subprocess.run varsayilani posix_spawn ile guvenli.
    """
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout, text=True, errors="replace", check=False)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    out = (p.stdout or "").strip()
    return out or None


def _dev_version() -> str | None:
    """Bundle disinda (build-info.json yokken) surum.

    Sira: karadul.__version__ -> importlib.metadata -> pyproject.toml.
    __version__ ONCE gelir cunku importlib.metadata PEP 440'a normalize eder
    ('1.20.0-pre' -> '1.20.0rc0') ve pyproject/Info.plist ile uyusmaz.
    """
    v = _safe(lambda: __import__("karadul").__version__, None)
    if isinstance(v, str) and v.strip():
        return v.strip()
    v = _safe(lambda: __import__("importlib.metadata", fromlist=["version"]).version("karadul"), None)
    if isinstance(v, str) and v.strip():
        return v.strip()

    def _from_pyproject():
        txt = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        m = re.search(r'^\s*version\s*=\s*"([^"]+)"', txt, re.M)
        return m.group(1) if m else None

    return _safe(_from_pyproject, None)


def _git_commit() -> str | None:
    """Dev fallback: repo commit'i. Bundle'da .git YOK -> None (uydurma yok)."""
    if not (PROJECT_ROOT / ".git").exists():
        return None
    out = _run_capture(["git", "-C", str(PROJECT_ROOT), "rev-parse", "--short", "HEAD"], 3.0)
    if not out:
        return None
    line = out.splitlines()[0].strip()
    return line if re.fullmatch(r"[0-9a-f]{6,40}", line) else None


def _build_info() -> dict:
    """build_mac_app.sh'in yazdigi Resources/build-info.json; yoksa dev fallback.

    PROJECT_ROOT bundle icinde Contents/Resources demektir (server.py:46).
    """
    out = {"version": None, "commit": None, "built_at": None, "flavor": None,
           "ghidra_version": None}

    def _read():
        p = PROJECT_ROOT / "build-info.json"
        if not p.is_file():
            return None
        d = json.loads(p.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else None

    d = _safe(_read, None)
    if d is not None:
        for k in out:
            v = d.get(k)
            if isinstance(v, (str, int, float)) and str(v).strip():
                out[k] = str(v).strip()
        if out["flavor"] not in ("full", "core", "dev"):
            out["flavor"] = None       # bilinmeyen etiketi uydurma
        return out
    # dev fallback: build-info.json yok (repo'dan calistiriliyor)
    out["flavor"] = "dev"
    out["version"] = _dev_version()
    out["commit"] = _git_commit()
    return out


# ---------------------------------------------------------------------------
# Guncelleme kontrolu + indirme (bildirim + indir-mount; YERINDE-DEGISTIRMESIZ)
#
# Uzak bir MANIFEST'ten (appcast.json) son surumu okur, mevcut surumle kiyaslar.
# Guncelleme varsa DMG indirilip sha256 DOGRULANIR ve MOUNT edilir -- kullanici
# uygulamayi kendisi surukler. ASLA yerinde degistirmez (DMG ad-hoc/imza muhurunu
# korur). Ag/ayrisma hatasi UI'yi BLOKLAMAZ; status "unknown" doner, istisna yayilmaz.
#
# Manifest semasi (appcast.json):
#   {version, dmg_url, sha256, size_bytes, notes_url, published_at, min_os}
#
# SSRF: dmg_url/notes_url yalnizca IZINLI host'lardan kabul edilir (manifest'in
# kendi host'u + KARADUL_UPDATE_ALLOWED_HOSTS). Keyfi domain reddedilir.
# ---------------------------------------------------------------------------
# Varsayilan: repo'nun GitHub "latest release" kalici baglantisi -- her yeni
# (pre-release OLMAYAN) release'te otomatik en yeni appcast.json asset'ine cozulur;
# host github.com SABIT kalir. Env (KARADUL_UPDATE_MANIFEST_URL) test/self-host'ta ezer.
# dmg_url/notes_url de github.com host'unda olmali (SSRF guard: manifest host == dmg host).
_UPDATE_MANIFEST_URL = (
    os.environ.get("KARADUL_UPDATE_MANIFEST_URL")
    or "https://github.com/berketez/black-widow/releases/latest/download/appcast.json"
)
_RELEASES_URL = os.environ.get(
    "KARADUL_RELEASES_URL", "https://github.com/berketez/black-widow/releases"
)
# Uzak boyut ne olursa olsun bu ustsinir asilmaz (kotu-niyetli manifest diski
# doldurmasin). 8 GiB: bundle ~3.5 GB, genis emniyet payi.
_UPDATE_MAX_BYTES = 8 * 1024 * 1024 * 1024
_UPDATE_THROTTLE_SEC = 24 * 3600


def _version_key(v):
    """Semver benzeri karsilastirma anahtari (Python tuple'lariyla siralanir).

    'v'/'V' onu ve bosluk atilir; '+build' metadata yoksayilir; '-pre' gibi
    on-surum ekleri semver kuralina gore surumlu-surumden DUSUK sayilir
    (1.20.0-pre < 1.20.0). Surumsuz/ayristirilamaz girdi -> None.

    Donus: (core_nums, release_flag, prerelease_ids)
      - release_flag: on-surum YOKSA 1 (release), VARSA 0 -> release > pre.
      - prerelease_ids: her tanimlayici (0,int,'') numerik / (1,0,str) alnum
        (semver: numerik tanimlayici alnum'dan dusuk oncelikli).
    """
    if not isinstance(v, str):
        return None
    s = v.strip()
    if s[:1] in ("v", "V"):
        s = s[1:]
    s = s.strip().split("+", 1)[0]   # build metadata karsilastirmayi etkilemez
    if not s:
        return None
    core, _sep, pre = s.partition("-")
    nums = []
    for part in core.split("."):
        m = re.match(r"^(\d+)", part.strip())
        if not m:
            return None
        nums.append(int(m.group(1)))
    if not nums:
        return None
    while len(nums) < 3:
        nums.append(0)
    core_key = tuple(nums[:3])
    if not pre:
        return (core_key, 1, ())
    ids = []
    for idt in pre.split("."):
        idt = idt.strip()
        if idt.isdigit():
            ids.append((0, int(idt), ""))     # numerik < alnum
        else:
            ids.append((1, 0, idt))
    return (core_key, 0, tuple(ids))


def _current_version() -> str | None:
    """Calisan surum: build-info.json (bundle) -> karadul.__version__ (dev)."""
    bi = _safe(_build_info, {})
    v = bi.get("version") if isinstance(bi, dict) else None
    if isinstance(v, str) and v.strip():
        return v.strip()
    return _safe(_dev_version, None)


def _update_allowed_hosts() -> set[str]:
    """dmg_url/notes_url icin izinli host kumesi (SSRF guard).

    Daima manifest URL'sinin KENDI host'unu icerir ("manifest nereden geliyorsa
    DMG de oradan gelsin") + KARADUL_UPDATE_ALLOWED_HOSTS (virgullu ek host'lar).
    Boylece Berke tek env verince (manifest URL) dmg/notes ayni host'a kilitlenir;
    keyfi domain otomatik reddedilir.
    """
    hosts: set[str] = set()
    mh = _safe(lambda: urllib.parse.urlparse(_UPDATE_MANIFEST_URL).hostname, None)
    if mh:
        hosts.add(mh.lower())
    for h in os.environ.get("KARADUL_UPDATE_ALLOWED_HOSTS", "").split(","):
        h = h.strip().lower()
        if h:
            hosts.add(h)
    return hosts


def _is_allowed_update_url(url) -> bool:
    """url 'https://' + host'u izinli kumede mi? (SSRF / yonlendirme enjeksiyonu).

    urlparse.hostname userinfo ('github.com@evil') ve port'u ayikladigi icin
    'github.com.evil.com' ve 'github.com@evil' TAM-eslesme ile reddedilir.
    http/file/ftp gibi https-disi semalar da reddedilir.
    """
    if not isinstance(url, str) or not url:
        return False
    p = _safe(lambda: urllib.parse.urlparse(url), None)
    if p is None or p.scheme != "https":
        return False
    host = (p.hostname or "").lower()
    if not host:
        return False
    return host in _update_allowed_hosts()


def _update_cache_path() -> Path:
    """Throttle cache dosyasi (_DATA_ROOT altinda; bundle'da yazilabilir kok)."""
    return _DATA_ROOT / "update_check_cache.json"


def _read_update_cache(cache_path: Path):
    """{last_checked, result} oku; bozuk/yoksa None. ASLA raise etmez."""
    def _r():
        d = json.loads(cache_path.read_text(encoding="utf-8"))
        if isinstance(d, dict) and isinstance(d.get("result"), dict):
            return d
        return None
    return _safe(_r, None)


def _write_update_cache(cache_path: Path, result: dict) -> None:
    """{last_checked, result} atomik yaz. ASLA raise etmez."""
    def _w():
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = cache_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps({"last_checked": time.time(), "result": result}),
                       encoding="utf-8")
        os.replace(tmp, cache_path)
    _safe(_w, None)


def _recompute_status(result: dict, current) -> dict:
    """latest vs current -> status. Ayristirilamazsa unknown (result'i mutasyona ugratir)."""
    kc, kl = _version_key(current), _version_key(result.get("latest"))
    if kc is None or kl is None:
        result["status"] = "unknown"
        if not result.get("error"):
            result["error"] = "surum ayristirilamadi"
        return result
    result["status"] = "update_available" if kl > kc else "up_to_date"
    result["error"] = None
    return result


# ---------------------------------------------------------------------------
# Güncelleme sorgusunun izni (MEK-04 / ARAYUZ-16, K-6): öntanımlı KAPALI ve ağ ayarına bağlı.
#   * network.enabled kapalıysa (karadul.yaml) hiçbir güncelleme isteği gitmez; menüden
#     "Güncellemeleri Kontrol Et" de gitmez, kullanıcıya nedeni söylenir.
#   * Açılıştaki otomatik sorgu ayrıca arayüz tercihini ister (``update_check``; öntanım
#     False). Tercih analiz ayarı değil, uygulama ayarıdır: karadul.yaml'a yazılmaz (katı
#     yükleyici bilinmeyen bölümü reddeder), veri kökündeki ui_prefs.json'da durur.
#   * Menüden açıkça istenen sorgu ve "İndir ve Aç" (explicit) yalnız ağ iznini ister.
# ---------------------------------------------------------------------------
_UI_PREFS_DEFAULT = {"update_check": False}


def _ui_prefs_path() -> Path:
    return _DATA_ROOT / "ui_prefs.json"


def _read_ui_prefs() -> dict:
    """Arayüz tercihleri; dosya yok / bozuk / tipe uymuyorsa öntanım (kapalı)."""
    out = dict(_UI_PREFS_DEFAULT)
    try:
        d = json.loads(_ui_prefs_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return out
    if isinstance(d, dict) and isinstance(d.get("update_check"), bool):
        out["update_check"] = d["update_check"]
    return out


def _write_ui_prefs(prefs: dict) -> None:
    data = {**_read_ui_prefs(), **{k: v for k, v in prefs.items() if k in _UI_PREFS_DEFAULT}}
    _atomic_write_json(_ui_prefs_path(), data)


def _update_check_block_reason(explicit: bool) -> str | None:
    """Güncelleme sorgusu şimdi ağa çıkabilir mi? Çıkamazsa okunur neden; çıkabilirse None."""
    cfg, problems = _settings_config()
    if problems or cfg.network.enabled is not True:
        return ("ağ erişimi kapalı (Ayarlar → Ağ erişimi): güncelleme sorgusu gönderilmedi")
    if not explicit and not _read_ui_prefs()["update_check"]:
        return ("açılışta güncelleme denetimi kapalı (Ayarlar → Güncelleme denetimi)")
    return None


def _update_check(timeout: float = 4.0, *, force: bool = False,
                  cache_path: Path | None = None, explicit: bool = False) -> dict:
    """Uzak manifest'ten son surumu al, mevcut surumle kiyasla.

    Donus (sozlesme):
      {status, current, latest, url, error,
       dmg_url, sha256, size_bytes, notes_url, published_at, min_os,
       checked_at, from_cache}
      status: "update_available" | "up_to_date" | "unknown" | "disabled"

    "disabled": izin yok (``_update_check_block_reason``); ağa ÇIKILMAZ, önbellek de
    okunmaz, neden ``error``'da. ``explicit``: kullanıcı açıkça istedi (menü / indirme).
    Throttle: cache 24 saatten yeni ve force=False ise ag ATLANIR (cache doner).
    ?force=1 -> cache atlanir, taze cekilir. ASLA exception yaymaz -- ag/parse
    hatasinda status="unknown". dmg_url/notes_url SSRF guard'dan gecmezse None.
    """
    current = _current_version()
    result: dict = {
        "status": "unknown", "current": current, "latest": None,
        "url": _RELEASES_URL, "error": None,
        "dmg_url": None, "sha256": None, "size_bytes": None,
        "notes_url": None, "published_at": None, "min_os": None,
        "checked_at": None, "from_cache": False,
    }
    blocked = _safe(lambda: _update_check_block_reason(explicit),
                    "güncelleme izni okunamadı: sorgu gönderilmedi")
    if blocked:
        result["status"] = "disabled"
        result["error"] = blocked
        return result
    cp = cache_path or _update_cache_path()

    # --- Throttle: taze cache varsa AG'A HIC CIKMA ---
    if not force:
        cached = _read_update_cache(cp)
        if cached is not None:
            age = _safe(lambda: time.time() - float(cached.get("last_checked", 0)), None)
            if age is not None and 0 <= age < _UPDATE_THROTTLE_SEC:
                out = dict(cached["result"])
                out["current"] = current        # calisan surume gore taze
                out["from_cache"] = True
                return _recompute_status(out, current)

    # --- Ag'dan manifest cek ---
    try:
        req = urllib.request.Request(
            _UPDATE_MANIFEST_URL,
            headers={"Accept": "application/json",
                     "User-Agent": "black-widow-update-check"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", errors="replace"))
    except Exception as e:  # noqa: BLE001 -- ag/parse; UI bloklanmamali
        result["error"] = type(e).__name__
        return result
    if not isinstance(data, dict):
        result["error"] = "beklenmeyen manifest"
        return result

    latest = data.get("version")
    if not isinstance(latest, str) or not latest.strip():
        result["error"] = "manifestte surum yok"
        return result
    result["latest"] = latest.strip()

    # SSRF guard: dmg_url/notes_url YALNIZ izinli host'tan alinir
    if _is_allowed_update_url(data.get("dmg_url")):
        result["dmg_url"] = data["dmg_url"]
    if _is_allowed_update_url(data.get("notes_url")):
        result["notes_url"] = data["notes_url"]
        result["url"] = data["notes_url"]        # banner "notlar" baglantisi

    sha = data.get("sha256")
    if isinstance(sha, str) and re.fullmatch(r"[0-9a-fA-F]{64}", sha.strip()):
        result["sha256"] = sha.strip().lower()
    sz = data.get("size_bytes")
    if isinstance(sz, int) and not isinstance(sz, bool) and 0 < sz <= _UPDATE_MAX_BYTES:
        result["size_bytes"] = sz
    for k in ("published_at", "min_os"):
        v = data.get(k)
        if isinstance(v, str) and v.strip():
            result[k] = v.strip()

    result["checked_at"] = time.time()
    result = _recompute_status(result, current)
    # Yalniz BASARILI kontrolu cache'le -> gecici hatalar 24 saat retry'i bloklamasin.
    if result["status"] != "unknown":
        _write_update_cache(cp, result)
    return result


# ---------------------------------------------------------------------------
# Guncelleme INDIRME (arka plan; sha256 dogrulama; MOUNT, YERINDE-DEGISTIRMESIZ)
#
# Manifest'teki dmg_url'i (SSRF-guard'li) indirir, sha256'yi manifest'le karsilastirir,
# ~/Downloads'a yazar ve `open` ile MOUNT eder. App'i KENDISI DEGISTIRMEZ -- kullanici
# yeni surumu Applications'a surukler (ad-hoc muhur korunur). Worker ASLA raise etmez:
# tum durum _UPDATE_DL'e yazilir, UI bunu /api/update-download-status'tan okur.
# ---------------------------------------------------------------------------
_UPDATE_DL_LOCK = threading.Lock()
_UPDATE_DL: dict = {
    "status": "idle",       # idle|downloading|verifying|verified|mounting|done|error
    "downloaded": 0, "total": 0, "path": None, "error": None,
    "version": None, "started_at": None,
}


def _update_dl_snapshot() -> dict:
    with _UPDATE_DL_LOCK:
        return dict(_UPDATE_DL)


def _update_dl_set(**kw) -> None:
    with _UPDATE_DL_LOCK:
        _UPDATE_DL.update(kw)


def _downloads_dir() -> Path:
    """Indirme hedefi: ~/Downloads; yoksa yazilabilir veri kokune dus."""
    d = HOME / "Downloads"
    return d if d.is_dir() else _DATA_ROOT


def _download_update_worker(dmg_url: str, sha256: str, size_bytes, version) -> None:
    """DMG'yi indir -> sha256 dogrula -> ~/Downloads'a yaz -> MOUNT. ASLA raise etmez."""
    tmp = None
    try:
        dl_dir = _downloads_dir()
        dl_dir.mkdir(parents=True, exist_ok=True)
        name = os.path.basename(urllib.parse.urlparse(dmg_url).path)
        if not name.lower().endswith(".dmg"):
            name = f"BlackWidow-{version or 'update'}.dmg"
        final = dl_dir / name
        tmp = dl_dir / (name + ".part")

        h = hashlib.sha256()
        req = urllib.request.Request(
            dmg_url, headers={"User-Agent": "black-widow-update-download"})
        with urllib.request.urlopen(req, timeout=30) as r, open(tmp, "wb") as fh:
            total = _safe(lambda: int(r.headers.get("Content-Length") or 0), 0) \
                or int(size_bytes or 0)
            _update_dl_set(total=total)
            got = 0
            while True:
                chunk = r.read(256 * 1024)
                if not chunk:
                    break
                got += len(chunk)
                if got > _UPDATE_MAX_BYTES:
                    raise ValueError("indirme ustsinir asildi")
                fh.write(chunk)
                h.update(chunk)
                _update_dl_set(downloaded=got)

        # --- sha256 DOGRULA (uyusmazsa MOUNT ETME, dosyayi sil) ---
        _update_dl_set(status="verifying")
        if h.hexdigest().lower() != (sha256 or "").lower():
            _safe(lambda: tmp.unlink(), None)
            _update_dl_set(status="error",
                           error="sha256 uyusmadi -- indirilen dosya reddedildi")
            return
        os.replace(tmp, final)
        tmp = None
        _update_dl_set(status="verified", path=str(final))

        # MOUNT (yerinde-degistirmesiz): kullanici Applications'a KENDISI surukler.
        _update_dl_set(status="mounting")
        _safe(lambda: subprocess.run(["open", str(final)], check=False, timeout=20), None)
        _update_dl_set(status="done", path=str(final))
    except Exception as e:  # noqa: BLE001 -- UI status alanina yazilir, raise YOK
        if tmp is not None:
            _safe(lambda: tmp.unlink(), None)
        _update_dl_set(status="error", error=type(e).__name__)


def _start_update_download() -> dict:
    """Guncelleme indirmesini baslat (manifest'i cache'ten okur). Non-blocking.

    Once SSRF + sha256 dogrulanabilirlik guard'lari: dmg_url izinli degilse ya da
    sha256 yoksa INDIRME BASLATMAZ (butunluk dogrulanamayacaksa hic inme).
    """
    info = _safe(lambda: _update_check(explicit=True), {}) or {}
    if info.get("status") == "disabled":
        return {"status": "error", "error": info.get("error") or "güncelleme sorgusu kapalı",
                "downloaded": 0, "total": 0}
    if info.get("status") != "update_available":
        return {"status": "error", "error": "guncelleme yok",
                "downloaded": 0, "total": 0}
    dmg_url = info.get("dmg_url")
    sha = info.get("sha256")
    if not _is_allowed_update_url(dmg_url):
        return {"status": "error", "error": "dmg_url izinli degil (SSRF guard)",
                "downloaded": 0, "total": 0}
    if not (isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha)):
        return {"status": "error", "error": "sha256 yok -- indirme reddedildi",
                "downloaded": 0, "total": 0}
    with _UPDATE_DL_LOCK:
        if _UPDATE_DL["status"] in ("downloading", "verifying", "mounting"):
            return dict(_UPDATE_DL)          # zaten calisiyor; ikinci kez baslatma
        _UPDATE_DL.update(status="downloading", downloaded=0,
                          total=int(info.get("size_bytes") or 0), error=None,
                          version=info.get("latest"), path=None,
                          started_at=time.time())
    threading.Thread(
        target=_download_update_worker,
        args=(dmg_url, sha, info.get("size_bytes"), info.get("latest")),
        daemon=True,
    ).start()
    return _update_dl_snapshot()


def _ghidra_dir() -> Path | None:
    """Ghidra kurulum dizini: env -> Config cozumleyicisi. Yoksa None."""
    for ev in ("GHIDRA_INSTALL_DIR", "GHIDRA_HOME"):   # bundle launcher'i bunu set eder
        v = os.environ.get(ev)
        if v:
            p = Path(os.path.expanduser(v))
            if p.is_dir():
                return p
    # dev: config.py::_find_ghidra_tool zaten bilinen yollari tariyor
    hl = _safe(lambda: Path(Config.load(_SETTINGS_YAML).tools.ghidra_headless), None)
    if hl and hl.is_file() and hl.parent.name == "support" and hl.parent.parent.is_dir():
        return hl.parent.parent
    return None


def _ghidra_info(bi: dict) -> dict:
    d = _safe(_ghidra_dir, None)
    if d is None:
        return {"present": False, "version": None, "path": None}

    def _ver():
        txt = (d / "Ghidra" / "application.properties").read_text(encoding="utf-8", errors="replace")
        m = re.search(r"^application\.version\s*=\s*(.+)$", txt, re.M)
        return m.group(1).strip() if m else None

    ver = _safe(_ver, None) or bi.get("ghidra_version")   # son care: build-info
    return {"present": True, "version": ver or None, "path": str(d)}


def _jdk_info() -> dict:
    jh = os.environ.get("JAVA_HOME")
    exe = None
    if jh:
        c = Path(os.path.expanduser(jh)) / "bin" / "java"
        if c.is_file():
            exe = str(c)
    if exe is None:
        exe = shutil.which("java")
    if not exe:
        return {"present": False, "version": None}
    out = _run_capture([exe, "-version"], 5.0)
    if not out:
        return {"present": True, "version": None}   # java var ama konusmadi
    m = re.search(r'version "([^"]+)"', out)
    return {"present": True, "version": (m.group(1) if m else out.splitlines()[0].strip()[:120])}


def _signatures_info() -> dict:
    """Imza DB: SADECE data.mdb boyutu. LMDB ACILMAZ (2 GB mmap etmeye gerek yok)."""
    from karadul.config import resolve_data_root, resolve_sig_lmdb_path

    p, source = resolve_sig_lmdb_path(None, resolve_data_root()[0])
    data = p / "data.mdb"
    size = _safe(lambda: data.stat().st_size if data.is_file() else None, None)
    return {"present": bool(size), "path": str(p), "source": source, "size_bytes": size}


def _runs_count(runs: Path) -> int | None:
    """Saklanan analiz sayisi (ust sinir _MAX_RUNS -> 'toplam gecmis' DEGIL)."""
    def _n():
        if not runs.is_dir():
            return 0
        return sum(1 for x in runs.iterdir() if x.is_dir())   # .DS_Store sayilmasin
    return _safe(_n, None)


def _about_static() -> dict:
    """Surec basina BIR kez: pahali/degismeyen alanlar."""
    bi = _safe(_build_info, {"version": None, "commit": None, "built_at": None,
                             "flavor": None, "ghidra_version": None})

    def _plat():
        mac = platform.mac_ver()[0]
        return f"macOS {mac} ({platform.machine()})" if mac else platform.platform()

    return {
        "app": "Black Widow",
        "engine": "karadul",
        "version": bi.get("version") or _safe(_dev_version, None),
        "build": {"commit": bi.get("commit"), "built_at": bi.get("built_at"),
                  "flavor": bi.get("flavor")},
        "runtime": {"python": _safe(platform.python_version, None), "platform": _safe(_plat, None)},
        "ghidra": _safe(lambda: _ghidra_info(bi), {"present": False, "version": None, "path": None}),
        "jdk": _safe(_jdk_info, {"present": False, "version": None}),
        "signatures": _safe(_signatures_info, {"present": False, "path": None, "size_bytes": None}),
        "notes": list(_ABOUT_NOTES),
    }


def _about_payload() -> dict:
    global _ABOUT_STATIC
    with _ABOUT_LOCK:
        if _ABOUT_STATIC is None:
            _ABOUT_STATIC = _about_static()
        d = json.loads(json.dumps(_ABOUT_STATIC))   # derin kopya: cache mutasyona ugramasin
    runs = _DATA_ROOT / "ui" / "_runs"
    log = _safe(lambda: (_DATA_ROOT / "app.log") if (_DATA_ROOT / "app.log").is_file() else None, None)
    d["paths"] = {"data_dir": str(_DATA_ROOT), "runs": str(runs), "log": str(log) if log else None}
    d["stats"] = {"runs": _runs_count(runs)}
    # Disk erişimi CANLI okunur (cache'lenmez): FDA durumu app yeniden başlayınca
    # değişebilir, _ABOUT_STATIC'e gömülmemeli.
    d["disk_access"] = _safe(_disk_access, {"full_disk_access": False,
                             "protected_folders": {}, "is_macos": _IS_MAC,
                             "probe": str(_TCC_PROBE)})
    return d


def _about_fallback() -> dict:
    """Son savunma: _about_payload bile patlarsa sozlesme sekli + null'lar."""
    return {
        "app": "Black Widow", "engine": "karadul", "version": None,
        "build": {"commit": None, "built_at": None, "flavor": None},
        "runtime": {"python": None, "platform": None},
        "ghidra": {"present": False, "version": None, "path": None},
        "jdk": {"present": False, "version": None},
        "signatures": {"present": False, "path": None, "size_bytes": None},
        "paths": {"data_dir": str(_DATA_ROOT), "runs": None, "log": None},
        "stats": {"runs": None},
        "disk_access": {"full_disk_access": False, "protected_folders": {},
                        "is_macos": _IS_MAC, "probe": str(_TCC_PROBE)},
        "notes": list(_ABOUT_NOTES) + ["Sistem bilgileri okunamadı."],
    }


# ---------------------------------------------------------------------------
# Disk erişimi (antivirüs deseni) -- TCC durumu tespiti + Sistem Ayarları yönlendirme
#
# macOS TCC: Desktop/Documents/Downloads + harici/ağ diski + sistem konumları
# izin olmadan okunamaz. App, Tam Disk Erişimi'ni (FDA) PROGRAMATİK İSTEYEMEZ;
# yalnızca DURUMU tespit edip kullanıcıyı Sistem Ayarları'na yönlendirebilir.
#
# GÜVENİLİR FDA tespiti: FDA-korumalı bir dosyayı (sistem TCC.db) okumayı DENE ->
# FDA yoksa PermissionError, varsa okunur. Bu bölümdeki hiçbir fonksiyon exception
# YAYMAZ (endpoint 500 atmamalı).
# ---------------------------------------------------------------------------
_IS_MAC = sys.platform == "darwin"
# FDA panelini açan derin link. DİKKAT (macOS sürüm riski): "Ayarlar" penceresi
# Ventura'dan beri yeniden yazıldı; pane anahtarı sürüme göre değişebilir.
# Privacy_AllFiles = Gizlilik ve Güvenlik > Tam Disk Erişimi bölmesi. Hangi
# bölmenin gerçekten açıldığı DENEYEREK doğrulanır (bkz. test raporu).
_FDA_PANE_URL = "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
# FDA'nın kanıtı: bu sistem dosyası SADECE Tam Disk Erişimi ile okunabilir.
_TCC_PROBE = Path("/Library/Application Support/com.apple.TCC/TCC.db")


def _full_disk_access() -> bool:
    """Tam Disk Erişimi var mı? FDA-korumalı TCC.db'yi okumayı DENE.

    open() başarılı -> FDA var; PermissionError -> FDA yok. mac dışında TCC
    kavramı yok -> True (kısıtlama yok). Hiçbir durumda exception yaymaz.
    UYARI: Terminal'den çalışan dev python, Terminal'in FDA'sını MİRAS alabilir
    (yanıltıcı True); bundle'da app'in kendi TCC kimliği geçerli olur.
    """
    if not _IS_MAC:
        return True
    try:
        with open(_TCC_PROBE, "rb") as f:
            f.read(1)
        return True
    except PermissionError:
        return False
    except OSError:
        return False   # dosya yok/başka hata -> FDA doğrulanamadı, yok say


def _folder_readable(path: Path) -> bool:
    """path listelenebiliyor mu? TCC reddi opendir'de PermissionError verir."""
    try:
        with os.scandir(path) as it:
            next(it, None)     # boş klasörde bile opendir başarısı yeterli
        return True
    except PermissionError:
        return False
    except OSError:
        return False


def _disk_access() -> dict:
    """FDA durumu + korumalı klasör erişilebilirliği (antivirüs deseni)."""
    folders = {}
    for key, name in (("desktop", "Desktop"), ("documents", "Documents"),
                      ("downloads", "Downloads")):
        folders[key] = _safe(lambda p=HOME / name: _folder_readable(p), False)
    return {
        "full_disk_access": _safe(_full_disk_access, False),
        "protected_folders": folders,
        "is_macos": _IS_MAC,
        "probe": str(_TCC_PROBE),
    }


def _open_fda_settings() -> dict:
    """FDA panelini `open` ile aç. WKWebView içinden x-apple: linki çalışmaz;
    bu yüzden yönlendirme SERVER üzerinden `open` ile yapılır."""
    if not _IS_MAC:
        return {"__code": 400, "error": "yalnızca macOS"}
    try:
        p = subprocess.run(["open", _FDA_PANE_URL], stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=8, text=True,
                           errors="replace", check=False)
    except (OSError, ValueError, subprocess.SubprocessError) as e:
        return {"__code": 500, "error": f"Sistem Ayarları açılamadı: {e}"}
    return {"ok": p.returncode == 0, "returncode": p.returncode,
            "pane": _FDA_PANE_URL, "message": (p.stdout or "").strip() or None}


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
    base = _DATA_ROOT / "ui" / "_runs"
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


# Denetim (süren iş var mı?) ile işin _JOBS'a eklenmesi arasında yarış olmasın: eşzamanlı iki
# POST /api/analyze iki analizi birden başlatıyordu (ARAYUZ Küçükler). Başlatma tek kilitte.
_START_LOCK = threading.Lock()


def start_analysis(binary: str) -> dict:
    with _START_LOCK:
        return _start_analysis_locked(binary)


def _start_analysis_locked(binary: str) -> dict:
    rp_str = resolve_binary(binary)
    if not rp_str:
        return {"error": f"bulunamadı: {binary[:50]}  (yol veya uygulama adı gir)"}
    rp = Path(rp_str)
    allowed_roots = [HOME, PROJECT_ROOT, Path("/usr"), Path("/bin"),
                     Path("/opt"), Path("/sbin")]
    if not any(_under(rp, r) for r in allowed_roots):
        return {"error": "izin verilmeyen konum"}
    running = _running_job()
    if running:
        # ARAYUZ-10: süren işe yeniden bağlanılabilsin diye kimliği döner
        return {"error": "zaten bir analiz sürüyor — bitmesini bekle ya da iptal et",
                "running_job": running}
    cmd_cfg: list[str] = []
    # Ayar paneli (Faz 3): karadul.yaml varsa yukle. computation_recovery ve
    # network CLI flag'iyle deterministik gecilir (bkz. _read_settings notu).
    if _SETTINGS_YAML.is_file():
        cmd_cfg += ["--config", str(_SETTINGS_YAML)]
        try:
            _s = _read_settings()
        except SettingsFileError as e:
            return {"error": f"ayar dosyası okunamadı: {e}"}
        if _s.get("errors"):
            # analiz bu dosyayla çıkış 2 verir; başlatmadan söyle (sessiz başarısızlık yok)
            return {"error": "ayar dosyası yükleyiciden geçmiyor: "
                             + "; ".join(_s["errors"][:3])}
        _k = _s["knobs"]
        cmd_cfg += (["--compute-recovery"] if _k["computation_recovery_enabled"]
                    else ["--no-compute-recovery"])
        if _k["network_enabled"]:
            cmd_cfg += ["--enable-network"]
    _cleanup_runs()

    job = uuid.uuid4().hex[:10]
    run_dir = _DATA_ROOT / "ui" / "_runs" / job
    run_dir.mkdir(parents=True, exist_ok=True)
    log_path = run_dir / "analyze.log"
    ws_out = run_dir / "ws"
    clean_out = run_dir / "clean"
    cmd = [sys.executable, "-m", "karadul", "analyze", str(rp),
           "--skip-dynamic", "--lmdb-sigdb", "--verbose",
           "--output-dir", str(ws_out), "--output", str(clean_out)] + cmd_cfg
    lf = None
    try:
        lf = open(log_path, "w")
        # Kendi süreç grubu: kapanışta killpg ile analizi VE altındaki Ghidra
        # JVM'ini tek hamlede götürebilelim (server'ın grubunu vurmadan).
        # process_group=0 kullan, start_new_session DEĞİL: setsid'i posix_spawn
        # desteklemediği için Python fork_exec'e düşüyor ve çok thread'li süreçte
        # macOS'ta fork deadlock oluyordu (Popen asılı kalıp çocuk hiç doğmuyordu).
        proc = subprocess.Popen(cmd, cwd=str(_DATA_ROOT), stdout=lf,
                                stderr=subprocess.STDOUT, process_group=0)
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
                      "started": time.time(), "lf": lf, "closed": False,
                      "cancelled": False, "activated": False,
                      "gunluk": _GunlukDurumu()}  # ÖL-4: artımlı okuma durumu
    return {"job": job, "binary": rp.stem}


def _kill_proc(proc) -> None:
    """Analiz sürecini ve süreç grubunu (Ghidra JVM dahil) SIGTERM ile sonlandır.

    Süreç grubu sunucunun kendi grubuysa (çocuk ayrı gruba alınamamışsa) killpg sunucuyu da
    vururdu: o durumda yalnız süreç sonlandırılır.
    """
    try:
        pgid = os.getpgid(proc.pid)
        if proc.pid <= 0 or pgid == os.getpgrp():
            raise ProcessLookupError("ortak süreç grubu")
        os.killpg(pgid, signal.SIGTERM)
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass


def cancel_job(job: str) -> dict:
    """ARAYUZ-10: süren analizi iptal et (süreç grubu: Ghidra JVM de gider)."""
    with _JOBS_LOCK:
        j = _JOBS.get(job)
    if not j:
        return {"__code": 404, "error": "job yok"}
    proc = j["proc"]
    if proc.poll() is not None:
        return {"__code": 409, "error": "iş zaten bitti", "rc": proc.returncode}
    j["cancelled"] = True
    _kill_proc(proc)
    return {"ok": True, "job": job}


def current_job() -> dict:
    """ARAYUZ-10: süren iş (sayfa yenilenince / "+ YENİ" sonrası yeniden bağlanmak için)."""
    jid = _running_job()
    if not jid:
        return {"job": None}
    with _JOBS_LOCK:
        j = _JOBS.get(jid) or {}
    return {"job": jid, "binary": j.get("binary"),
            "elapsed": round(time.time() - j.get("started", time.time()), 1)}


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
    # Etiket başına ad sayısı. Eski "yüksek-güven isim" satırı (naming_high_confidence) c_namer'ın
    # ölçülmemiş iç puanına dayanıyordu; yerini kayıttaki etiketlerin sayımı aldı.
    for name_label, count in _label_counts(st, Path(run_dir)):
        out.append({"label": f"etiket: {name_label}", "count": count,
                    "unit": "ad", "name_label": name_label})
    return out


def _label_counts(stats, run_dir: Path) -> list[tuple[str, int]]:
    """Etiket başına ad sayısı, sözlük sırasıyla; veri yoksa boş liste (sayı uydurulmaz).

    Önce rapor istatistiklerindeki ``naming_by_label``; o yoksa temiz haritadaki
    (``clean/naming_map.json``) etiketli kayıtlar sayılır.
    """
    by_label = stats.get("naming_by_label") if isinstance(stats, dict) else None
    if isinstance(by_label, dict):
        counts = {k: v for k, v in by_label.items()
                  if k in NAME_LABELS and isinstance(v, int) and not isinstance(v, bool) and v >= 0}
        if counts:
            return [(lab, counts[lab]) for lab in NAME_LABELS if lab in counts]
    try:
        mappings = json.loads(
            (run_dir / "clean" / "naming_map.json").read_text(encoding="utf-8"))["mappings"]
    except (json.JSONDecodeError, OSError, KeyError, TypeError, ValueError):
        return []
    if not isinstance(mappings, dict):
        return []
    found: dict[str, int] = {}
    for rec in mappings.values():
        label = _record_label(rec)
        if label is not None:
            found[label] = found.get(label, 0) + 1
    return [(lab, found[lab]) for lab in NAME_LABELS if lab in found]


# Asama bitis satiri -- karadul/cli.py::_log_stage_complete'in yazdigi bicim:
#   OK <stage>: <sn>s | FAIL <stage>: <sn>s | SKIP <stage>: <sn>s -- <gerekce>
_STAGE_LINE_RE = re.compile(
    r"\b(OK|FAIL|SKIP) (\w+): (\d+(?:\.\d+)?)s(?: -- ([^\n]*))?")
_STAGE_LINE_STATUS = {"OK": "done", "FAIL": "failed", "SKIP": "skipped"}
# Eski ayristiricinin kabul ettigi sure-siz "FAIL|ERROR <stage>:" bicimi hala
# basarisiz sayilir (yalniz yukaridaki satirla bitmemis asamalar icin).
_STAGE_ERROR_RE = re.compile(r"\b(?:FAIL|ERROR) (\w+):")


def _parse_stage_log(log: str) -> list[dict]:
    """Analiz log'undan asama durumlarini cikar (done/failed/skipped/running/pending).

    skipped: asama HATA degil, uygulanamadigi icin atlandi (StageResult
    skipped=True); gerekce `skip_reason`'da. Eskiden SKIP satiri olmadigindan
    atlanan asama "FAIL" satirina dusup kirmizi "failed" gorunuyordu.
    running: terminal durumu (done/failed/skipped) olmayan ILK asama.
    """
    ended: dict[str, tuple[str, float | None, str | None]] = {}
    errored: set[str] = set()
    _scan_stage_lines(log, ended, errored)
    return _stage_list(ended, errored)


def _scan_stage_lines(text: str, ended: dict, errored: set) -> None:
    """Metindeki aşama satırlarını ``ended`` (son eşleşme kazanır) ve ``errored``'a işle.

    Desenler satır sonunu aşmaz: metnin tamamında ya da satır satır taramak aynı sonucu verir
    (ÖL-4 artımlı okuma bunu kullanır).
    """
    for m in _STAGE_LINE_RE.finditer(text):
        stage = m.group(2)
        if stage in STAGE_ORDER:
            reason = (m.group(4) or "").strip() or None
            ended[stage] = (_STAGE_LINE_STATUS[m.group(1)], float(m.group(3)), reason)
    for m in _STAGE_ERROR_RE.finditer(text):
        if m.group(1) in STAGE_ORDER:
            errored.add(m.group(1))


def _stage_list(ended_lines: dict, errored: set) -> list[dict]:
    """Aşama listesi: süreli satırla bitmemiş ama ``FAIL|ERROR <aşama>:`` görülen aşama başarısız."""
    ended = dict(ended_lines)
    for stage in errored:
        if stage not in ended:
            ended[stage] = ("failed", None, None)
    running = next((s for s in STAGE_ORDER if s not in ended), None)
    stages = []
    for s in STAGE_ORDER:
        status, t, reason = ended.get(s, (None, None, None))
        if status is None:
            status = "running" if s == running else "pending"
        stages.append({"key": s, "label": STAGE_LABEL[s], "status": status,
                       "time": t, "skip_reason": reason})
    return stages


# ÖL-4: iş günlüğü her yoklamada baştan okunmaz. İş kaydında (``gunluk``) dosya ofseti ve birikmiş
# durum saklanır; yalnız yeni baytlar okunur, yarım satır sonraki çağrıya kalır, iş bitince son yarım
# satır da işlenir. Birikmiş durum tam okumanınkiyle aynıdır (``read_text(errors="ignore")``: UTF-8,
# evrensel satır sonu; ``\r\n`` / ``\r`` -> ``\n``): aşama satırları, alt aşama eşleşmeleri, son 6
# satır; ek olarak son ``ILERLEME`` olayı (yeni ``ilerleme`` alanı; olay yoksa ``null``).
_GUNLUK_KODLAMA = "utf-8"
_KUYRUK_SATIR_SAYISI = 6
_GUNLUK_KILIDI = threading.Lock()  # aynı işi iki yoklama birlikte ilerletmesin


class _GunlukDurumu:
    """Bir işin günlüğünden birikmiş durum (artımlı okuma)."""

    def __init__(self) -> None:
        self.kimlik: tuple[int, int] | None = None  # (st_dev, st_ino): dosya değişirse baştan
        self.ofset = 0
        self.artik = b""  # işlenmemiş yarım satır (çevrilmiş) + bekletilen son "\r"
        self.ended: dict = {}
        self.errored: set = set()
        self.alt: dict[int, str | None] = {}  # SUBSTAGE_PATTERNS sırası -> ilk eşleşme
        self.son_olay: dict | None = None
        self.kuyruk: list[str] = []

    def besle(self, veri: bytes, bitti: bool) -> None:
        veri = self.artik + veri
        tut = b""
        if not bitti and veri.endswith(b"\r"):  # ardından "\n" gelebilir: "\r\n" tek satır sonu
            tut, veri = b"\r", veri[:-1]
        veri = veri.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        kes = len(veri) if bitti else veri.rfind(b"\n") + 1
        tam, self.artik = veri[:kes], veri[kes:] + tut
        if not tam:
            return
        metin = tam.decode(_GUNLUK_KODLAMA, errors="ignore")
        satirlar = metin.split("\n")
        sonlu_son = metin.endswith("\n")
        if sonlu_son:
            satirlar.pop()
        for satir in satirlar:
            _scan_stage_lines(satir, self.ended, self.errored)
            if len(self.alt) < len(SUBSTAGE_PATTERNS):
                for i, (pat, _label, grp) in enumerate(SUBSTAGE_PATTERNS):
                    if i not in self.alt:
                        m = pat.search(satir)
                        if m:
                            self.alt[i] = m.group(grp) if grp else None
        # yalnız son geçerli olay gerekir: sondan geriye ilk geçerli ILERLEME satırı
        for satir in reversed(satirlar):
            if ILERLEME_ONEKI in satir:
                olay = ilerleme_ayristir(satir)
                if olay is not None:
                    self.son_olay = olay
                    break
        # son 6 satır: str.splitlines() ile aynı bölme (satır sonuyla biten parça "\n" ile bölünür)
        parcalar: list[str] = []
        for k in range(len(satirlar) - 1, -1, -1):
            sonlu = sonlu_son or k < len(satirlar) - 1
            parcalar[:0] = (satirlar[k] + "\n").splitlines() if sonlu else satirlar[k].splitlines()
            if len(parcalar) >= _KUYRUK_SATIR_SAYISI:
                break
        self.kuyruk = (self.kuyruk + parcalar)[-_KUYRUK_SATIR_SAYISI:]

    def stages(self) -> list[dict]:
        return _stage_list(self.ended, self.errored)

    def substages(self) -> list[dict]:
        return [{"label": label, "count": self.alt[i]}
                for i, (_pat, label, _grp) in enumerate(SUBSTAGE_PATTERNS) if i in self.alt]

    def tail(self) -> str:
        return "\n".join(self.kuyruk)


def _gunluk_ilerlet(j: dict, bitti: bool) -> _GunlukDurumu:
    """İşin günlüğünü yeni baytlarla ilerlet (dosya kısaldıysa / değiştiyse baştan)."""
    with _GUNLUK_KILIDI:
        d = j.get("gunluk")
        try:
            st = os.stat(j["log"])
            kimlik = (st.st_dev, st.st_ino)
            if not isinstance(d, _GunlukDurumu) or d.kimlik != kimlik or st.st_size < d.ofset:
                d = _GunlukDurumu()
                d.kimlik = kimlik
            with open(j["log"], "rb") as f:
                f.seek(d.ofset)
                yeni = f.read()
        except OSError:  # tam okumadaki gibi: okunamayan günlük boş sayılır
            d, yeni = _GunlukDurumu(), b""
        d.ofset += len(yeni)
        if yeni or (bitti and d.artik):
            d.besle(yeni, bitti)
        j["gunluk"] = d
        return d


def _job_progress(job: str) -> dict:
    with _JOBS_LOCK:
        j = _JOBS.get(job)
    if not j:
        return {"error": "job yok"}

    # Önce süreç durumu, sonra günlük: bitmiş sürecin bütün baytları dosyadadır (son yarım satır
    # da işlenir); süren işte yarım satır sonraki yoklamaya kalır.
    proc = j["proc"]
    rc = proc.poll()
    finished = rc is not None
    gunluk = _gunluk_ilerlet(j, finished)
    stages = gunluk.stages()

    # alt-asamalar: canli log parse (setup_logging aktifse)
    substages = gunluk.substages()
    workspace = None
    outcome = None
    clean_dir = None
    if finished:
        wsp = Path(j["ws_out"])
        hits = sorted(wsp.rglob("reconstructed/src/naming_map.json"),
                      key=lambda p: p.stat().st_mtime) if wsp.exists() else []
        if hits:
            workspace = str(hits[-1].parents[2])
        # ARAYUZ-11: bitişte durum raporun aşamalarından (yalnız çıkış koduna değil);
        # çalışma alanı olmayan hedefte (JS / Java / .NET / Python) de rapor okunur.
        reps = sorted(wsp.rglob("reports/report.json"),
                      key=lambda p: p.stat().st_mtime) if wsp.exists() else []
        if reps:
            outcome = _report_outcome(reps[-1])
        cd = Path(j["run_dir"]) / "clean"
        clean_dir = str(cd) if cd.is_dir() else None
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
        "binary": j["binary"], "rc": rc, "cancelled": bool(j.get("cancelled")),
        "outcome": outcome, "clean_dir": clean_dir,
        "tail": gunluk.tail(),
        # ÖL-4: son ILERLEME olayının adim / durum / islenen / toplam / gecen_sn / cozumleyici /
        # neden'i (satırda olmayan alan null); olay yoksa null (sahte ilerleme yok).
        "ilerleme": gosterim_alanlari(gunluk.son_olay),
    }


def _progress_and_activate(job: str) -> dict:
    """``/api/progress``: ilerleme + bitmiş işin çalışma alanını BİR KEZ etkinleştir.

    Eskiden biten bir işin kimliğiyle her yoklama o işin çalışma alanını yeniden etkin
    yapıyordu: başka sekmede açık sonuç sessizce değişiyordu. İptal edilen işin çalışma alanı
    (yarım) hiç etkinleştirilmez.
    """
    prog = _job_progress(job)
    if prog.get("finished") and prog.get("workspace") and not prog.get("cancelled"):
        with _JOBS_LOCK:
            j = _JOBS.get(job) or {}
            first = not j.get("activated")
            j["activated"] = True
        if first:
            activate_workspace(prog["workspace"])
    return prog


# ---------------------------------------------------------------------------
# KaradulLM kısıtlı terminali (P22c1; KaradulLM v2 tasarımı §4.2, §4.3, §4.6)
#
# Terminal kabuk DEĞİLDİR: tek kabul edilen komut tam olarak ``karadullm`` (``lm_repl.is_allowed_command``)
# ve bu komut süreç başlatmaz; bu sürecin içinde bir KaradulLM oturumu açar (``lm_session.open_session``).
# Oturum açıkken girilen satırlar yalnız ``Session.submit``'e (``repl.parse``'ın kapalı komut kümesi) gider.
# Tek alt süreç, model yapılandırılmışsa yerel ``llama-server``'dır (karar 8 (a): yalnız yerel model; ikili
# ``check_server_binary``'den geçer). Bütün uçlar ``/api/lm/`` altında: ``_guard`` (Host + Origin + jeton) her
# istekte koşar, POST gövdesi ``_MAX_BODY`` ile sınırlı.
# ---------------------------------------------------------------------------
# Defter / özet / içerik / denetim deposunun kökü. None: kitaplığın öntanımı (~/.karadul/lm). Testler geçici
# dizin verir (kullanıcının deposuna yazılmaz).
_LM_STORE_ROOT: Path | None = None
# Oturum açma tek kilitte: eşzamanlı iki ``karadullm`` iki oturum açamasın (tek oturum, §4.3 G6).
_LM_OPEN_LOCK = threading.Lock()
# Son açılan oturum: kapandıktan sonra da kalan olaylarını (``oturum_bitti``) verebilmek için tutulur.
_LM_LAST = None
_LM_HEX64_RE = re.compile(r"[0-9a-f]{64}")
# Model yolu ortamdan (karar 8 (a) yalnız yerel model). Kalıcı ayar yeri (``karadul/config.py``) bu paketin
# dosyası değil; ikisi de verilmezse oturum modelsiz açılır (plan, not, öneri listesi çalışır).
_LM_ENV_SERVER, _LM_ENV_MODEL, _LM_ENV_TEMPLATE = "KARADUL_LLAMA_SERVER", "KARADUL_LM_MODEL", "KARADUL_LM_SABLON"
_LM_REFUSED_LINE = "bu terminal yalnız `karadullm` çalıştırır"


def _lm_base() -> Path:
    return _LM_STORE_ROOT if _LM_STORE_ROOT is not None else Path.home() / ".karadul" / "lm"


def _lm_audit_refused(komut) -> None:
    """Reddedilen terminal komutunun denetim kaydı (§4.3 G3): komut metni YAZILMAZ, yalnız uzunluk + sha256."""
    try:
        AuditLog(_lm_base() / "arayuz-komut.jsonl").write("komut_reddedildi", **lm_repl.command_audit_fields(komut))
    except OSError:
        pass  # kayıt yazılamadı diye ret değişmez; ret yine döner


def _lm_workspace_root() -> Path | None:
    """Etkin çalışma alanının kökü (ad haritasının bulunduğu koşu; ``find_ws`` ile aynı seçim)."""
    ws = WS
    if not ws:
        return None
    nm, _ = find_ws(ws)
    return nm.parents[2] if nm is not None else None


def _lm_make_backend(root: Path, sha: str, sid: str):
    """Oturumun arka ucu: yalnız yerel ``llama-server`` (karar 8 (a); bulut ucu yok). Yapılandırılmamışsa
    ``None`` (modelsiz oturum). İkili ``check_server_binary``'den geçer: adı ``llama-server``, çalışma alanının
    dışında, analiz edilen ikili değil (reddedilirse ``ServerBinaryRefused``; süreç açılmaz). Nesne kurmak süreç
    başlatmaz; sunucu ilk model isteğinde başlar."""
    srv_bin = os.environ.get(_LM_ENV_SERVER) or ""
    model = os.environ.get(_LM_ENV_MODEL) or ""
    if not srv_bin and not model:
        return None
    if not (srv_bin and model):
        raise ServerBinaryRefused(f"model için {_LM_ENV_SERVER} ve {_LM_ENV_MODEL} birlikte verilmeli")
    binary = check_server_binary(Path(srv_bin), root, sha)
    tmpl = os.environ.get(_LM_ENV_TEMPLATE) or None
    return LlamaServerBackend(binary, Path(model), _lm_base() / "sunucu",
                              template_path=Path(tmpl) if tmpl else None,
                              audit=AuditLog(session_log_path(sha, sid, _LM_STORE_ROOT)))


def _lm_open(komut) -> dict:
    """``POST /api/lm/terminal/komut``: izin listesi tek öğe (G2); başka her komut 400 + içeriksiz denetim kaydı
    (G3). Kabul edilen komut bu süreçte tek oturumu açar (G6); süreç başlatmaz."""
    global _LM_LAST
    if not lm_repl.is_allowed_command(komut):
        _lm_audit_refused(komut)
        return {"__code": 400, "hata": "izin verilmeyen komut", "satir": _LM_REFUSED_LINE}
    with _LM_OPEN_LOCK:
        if lm_session.current_session() is not None:
            return {"__code": 400, "hata": "oturum zaten açık"}
        root = _lm_workspace_root()
        if root is None:
            return {"__code": 400, "hata": "çalışma alanı yok: önce bir analiz sonucu açın"}
        sha = _active_binary_hash(WS)
        if not sha or not _LM_HEX64_RE.fullmatch(sha):
            return {"__code": 400, "hata": "çalışma alanında ikilinin özeti yok (reports/report.json, raw/): "
                                           "defter ve öneriler ikiliye bağlanamaz"}
        sid = lm_session.new_session_id()
        try:
            backend = _lm_make_backend(root, sha, sid)
        except (ServerBinaryRefused, ValueError) as e:
            return {"__code": 400, "hata": f"model başlatılmaz: {e}"}
        try:
            s = lm_session.open_session(root, backend=backend, binary_sha256=sha, session_id=sid,
                                        store_root=_LM_STORE_ROOT,
                                        analysis_running=lambda: _running_job() is not None)
        except lm_session.SessionError as e:   # SessionExists dahil
            return {"__code": 400, "hata": str(e)}
        _LM_LAST = s
    return {"oturum": s.id}


def _lm_query(raw_path: str) -> dict[str, str]:
    """Sorgu dizgisi → ilk değerler (yüzde kodlaması çözülür)."""
    qs = raw_path.split("?", 1)[1] if "?" in raw_path else ""
    return {k: v[0] for k, v in urllib.parse.parse_qs(qs, keep_blank_values=True).items()}


def _lm_find(oturum, *, open_only: bool):
    """İstekteki oturum kimliğinin oturumu ya da hata sözlüğü. ``open_only``: yalnız açık (güncel) oturum; değilse
    kapanmış son oturum da (kalan olaylarını / sonuçlarını okumak için)."""
    if not isinstance(oturum, str) or not oturum:
        return None, {"__code": 400, "hata": "oturum kimliği yok"}
    cur = lm_session.current_session()
    if cur is not None and cur.id == oturum:
        return cur, None
    last = _LM_LAST
    if not open_only and last is not None and last.id == oturum:
        return last, None
    return None, {"__code": 404, "hata": "böyle bir açık oturum yok"}


# Uzun yoklama (tasarım §4.2 (a)): istek en çok bu kadar bekler (§4.6 ``bekle=25``); bir cevaptaki en çok olay
# [bu iş: halkanın 10 000'i tek cevaba sığmasın; istemci ``son``'dan sürdürür, kayıp olmaz].
_LM_POLL_MAX_SEC = 25
_LM_POLL_LIMIT = 500
_LM_UINT_RE = re.compile(r"[0-9]{1,12}")


def _lm_events(q: dict) -> dict:
    """``GET /api/lm/olaylar?oturum&sonra=N&bekle=S``: ``seq > N`` olaylar (``EventStream.since``). Olay yoksa
    yeni olay gelene, oturum kapanana ya da ``S`` sn (en çok ``_LM_POLL_MAX_SEC``) dolana kadar bekler; beklerken
    hiçbir şey üretilmez. İstemci geride kaldıysa ``tasma: true`` + ``kacan: n`` (kayıp gizlenmez). ``kapali``:
    oturum kapandı ve verilecek olay kalmadı (yoklama durur)."""
    s, err = _lm_find(q.get("oturum"), open_only=False)
    if err:
        return err
    sonra, bekle = q.get("sonra", "0"), q.get("bekle", "0")
    if not (_LM_UINT_RE.fullmatch(sonra) and _LM_UINT_RE.fullmatch(bekle)):
        return {"__code": 400, "hata": "sonra ve bekle eksi olmayan tamsayı olmalı"}
    try:
        return s.stream.since(int(sonra), timeout=min(int(bekle), _LM_POLL_MAX_SEC), limit=_LM_POLL_LIMIT)
    except ValueError as e:
        return {"__code": 400, "hata": str(e)}


def _lm_input(body: dict) -> dict:
    """``POST /api/lm/terminal/girdi``: metin yalnız bu oturumun ``submit``'ine (``repl.parse``'ın kapalı kümesi;
    G4). Reddedilen satırın iletisi akışa ``satir`` olayı olarak da düşer."""
    s, err = _lm_find(body.get("oturum"), open_only=True)
    if err:
        return err
    r = s.submit(body.get("metin"))
    return r if r.get("kabul") else {"__code": 400, **r}


def _lm_stop(body: dict) -> dict:
    """``POST /api/lm/durdur``: süren işi ve kuyruğu durdurur; ``iptal`` olayını oturum yayar."""
    s, err = _lm_find(body.get("oturum"), open_only=True)
    if err:
        return err
    return {"tamam": True, "durduruldu": bool(s.cancel(lm_session.CANCEL_ANALYST))}


def _lm_status() -> dict:
    """``GET /api/lm/durum``: açık oturumun durumu (``Session.status``); oturum yoksa yalnız model ayarı."""
    s = lm_session.current_session()
    if s is not None:
        return s.status()
    model = os.environ.get(_LM_ENV_MODEL) or ""
    return {"oturum": None, "model_ayari": Path(model).name if model else None}


def _lm_result(q: dict) -> dict:
    """``GET /api/lm/sonuc``: araç sonucunun saklı içeriği (arındırılmış; içerik deposundan)."""
    s, err = _lm_find(q.get("oturum"), open_only=False)
    if err:
        return err
    try:
        obj = s.result_content(q.get("kimlik", ""))
    except (ValueError, OSError) as e:
        return {"__code": 400, "hata": f"sonuç açılamadı: {e}"}
    if obj is None:
        return {"__code": 404, "hata": "bu oturumun içerik deposunda böyle bir sonuç yok"}
    return {"kimlik": q.get("kimlik"), "sonuc": obj}


_LM_GUARD_KEYS = ("hukum", "bulgular", "bayraklar", "toplu_kabul", "sinanan", "sinanmayan")


def _lm_proposals(q: dict) -> dict:
    """``GET /api/lm/oneriler``: defterdeki öneriler (bekleyen + karara bağlanmış). Her öneriye arayüz düğüm anahtarı
    (``fn``; düğümü yoksa ``None``) ve bu oturumun akışındaki denetim ayrıntısı (``denetim``: P21 raporu; başka
    oturumun önerisinde akış yok → ``None``, uydurulmaz) eklenir."""
    s, err = _lm_find(q.get("oturum"), open_only=False)
    if err:
        return err
    try:
        props = s.notebook.proposals()
    except OSError as e:
        return {"__code": 500, "hata": f"defter okunamadı: {e}"}
    audits = {e["nesne"]: {k: e[k] for k in _LM_GUARD_KEYS}
              for e in s.stream.since(0)["olaylar"] if e["tur"] == "denetim"}
    out = []
    for p in props:
        out.append({**p, "fn": s.workspace.ui_name(p.get("adres")),
                    "denetim": audits.get(p.get("gorev")) if p.get("oturum") == s.id else None})
    return {"oneriler": out}


def _lm_reject(body: dict) -> dict:
    """``POST /api/lm/oneri/ret``: yalnız öneri kimliği + neden (zorunlu; girdi kuralı). Reddedilen ad ajanın
    D10 listesine girer (``Session.decide``)."""
    s = lm_session.current_session()
    if s is None:
        return {"__code": 409, "hata": "açık oturum yok"}
    r = s.decide(body.get("oneri_kimligi"), lm_session.DECIDE_REJECT, body.get("neden"))
    return {"tamam": True, "oneri": r["oneri"]} if r["tamam"] else {"__code": 400, "tamam": False, "hata": r["hata"]}


_LM_ACCEPT_LOCK = threading.Lock()


def _lm_accept(body: dict) -> dict:
    """``POST /api/lm/oneri/kabul``: YALNIZ öneri kimliği (ad istemciden alınmaz; tasarım §4.6, önceki tasarım §5.3).

    Sıra: (1) öneri defterde bekleyen olmalı; ad önerisinde ön denetim — arayüzün ikili özeti oturumunkiyle aynı
    (çalışma alanı değişmemiş), hedefin arayüz düğümü var, ad P17 kuralından geçer (``overrides._validate_name``),
    denetim hükmü yazılabilir (``ret`` değil), aynı ad başka bir düğüme model adı olarak verilmemiş; (2)
    ``Session.decide(kabul)``: D1 ve D2 bugünkü çalışma alanıyla yeniden koşar, tutmazsa kabul YAZILMAZ; (3) ad
    önerisi ``overrides.set_model_name`` ile deponun ``model`` bölümüne yazılır — ``overrides`` (elle) bölümüne ve
    ``naming_map.json``'a YAZILMAZ: motor okumaz, ürün ölçümüne girmez. Yorum önerisinin kabulü yalnız deftere
    düşer (yazılacak bölüm yok). (3) patlarsa defterde kabul kalır ve bu açıkça söylenir (uydurma başarı yok)."""
    s = lm_session.current_session()
    if s is None:
        return {"__code": 409, "hata": "açık oturum yok"}
    pid = body.get("oneri_kimligi")
    with _LM_ACCEPT_LOCK:
        try:
            p = s.notebook.proposal(pid) if isinstance(pid, str) else None
        except OSError as e:
            return {"__code": 500, "hata": f"defter okunamadı: {e}"}
        if p is None:
            return {"__code": 404, "hata": "böyle bir öneri yok"}
        if p["durum"] != "bekleyen":
            return {"__code": 409, "hata": f"öneri zaten karara bağlanmış: {p['durum']}"}
        key = None
        if p["oneri_turu"] == "ad":
            bh = _active_binary_hash(WS)
            if bh != s.binary_sha256:
                return {"__code": 409, "hata": "çalışma alanının ikilisi oturumunkiyle aynı değil: kabul yazılmadı"}
            key = s.workspace.ui_name(p["adres"])
            if key is None:
                return {"__code": 409, "hata": "fonksiyonun arayüzde düğümü yok: kabul yazılmadı"}
            try:
                overrides._validate_addr(key)
                overrides._validate_name(p["deger"])
            except ValueError as e:
                return {"__code": 400, "hata": f"ad kabul edilemez: {e}"}
            if p.get("hukum") not in overrides._MODEL_VERDICTS:
                return {"__code": 409, "hata": f"denetim hükmü {p.get('hukum')!r}: kabul yazılmadı"}
            for other, rec in overrides.model_names(bh).items():
                if other != key and rec["name"] == p["deger"]:
                    return {"__code": 409, "hata": f"çakışma: '{p['deger']}' model adı olarak {other} düğümünde"}
        r = s.decide(pid, lm_session.DECIDE_ACCEPT)
        if not r["tamam"]:
            return {"__code": 409, "tamam": False, "hata": r["hata"]}
        if key is None:
            return {"tamam": True, "oneri": r["oneri"], "yazildi": None}
        try:
            overrides.set_model_name(bh, key, p["deger"], proposal_id=pid, session_id=s.id, verdict=p["hukum"],
                                     ws_addr=p["adres"], binary=_ws_binary_name(WS))
        except (ValueError, OSError) as e:
            return {"__code": 500, "tamam": False, "oneri": r["oneri"],
                    "hata": f"kabul deftere yazıldı ama ad deponun model bölümüne yazılamadı ({e}): ad uygulanmadı"}
    with _CACHE_LOCK:
        _CACHE.pop("model", None)   # sonraki /api/model model katmanını taze okur
    return {"tamam": True, "oneri": r["oneri"], "yazildi": "model", "fn": key}


def _lm_close(body: dict) -> dict:
    """``POST /api/lm/terminal/kapat``: oturum ve arka uç kapanır (``oturum_bitti``)."""
    s, err = _lm_find(body.get("oturum"), open_only=True)
    if err:
        return err
    s.close(lm_session.CLOSE_EXIT)
    return {"tamam": True}


# --- Yaşam döngüsü (tasarım §4.3 G7; P21 LM-05): arayüz kapanınca oturum ve yerel model sunucusu da kapanır ---
# Süreç kapanırken oturumun kapanmasını en çok bu kadar bekle (sn) [bu iş]: arka uç önce durdurulduğu için süren
# istek hemen hata ile biter; ``Session.close``'un kendi tavanı (30 sn) sinyal işleyicisini bekletmesin.
_LM_SHUTDOWN_JOIN_SEC = 5.0


def _lm_close_current(reason: str, *, wait: float | None) -> bool:
    """Açık oturumu kapatır (``oturum_bitti.neden = reason``); oturum yoksa ``False``. ``wait`` verilirse (süreç
    kapanışı) önce yerel model sunucusu durdurulur (``backend.stop("cikis")``, P21 notu: bekçinin 1 sn'lik
    yoklamasını beklemeden), sonra kapanış en çok ``wait`` sn beklenir. ``wait=None``: kapanış arka planda
    (istek iş parçacığı bekletilmez; ``current_session()`` kapanış başlar başlamaz ``None`` olur)."""
    s = lm_session.current_session()
    if s is None:
        return False
    if wait is not None and s.backend is not None:
        try:
            s.backend.stop("cikis")
        except Exception:  # noqa: BLE001 — kapanışta son çare; oturum yine kapanır
            pass
    t = threading.Thread(target=s.close, args=(reason,), name="karadullm-kapanis", daemon=True)
    t.start()
    if wait is not None:
        t.join(wait)
    return True


def _lm_idle_tick() -> bool:
    """Boşta ``IDLE_SHUTDOWN_SEC``'ten (600 sn) uzun duran yerel model sunucusunu durdurur (G7;
    ``backend.stop_if_idle``). Durduysa oturum ``arka_uc_durumu`` olayını yayar. ``_parent_watchdog`` her turda
    çağırır."""
    s = lm_session.current_session()
    b = s.backend if s is not None else None
    if b is None or not hasattr(b, "stop_if_idle"):
        return False
    try:
        stopped = bool(b.stop_if_idle())
    except Exception:  # noqa: BLE001 — boşta kapatma denetimi bekçiyi düşürmesin
        return False
    if stopped:
        s._backend_state_event()   # oturumun yalnız durum değişince yayan yolu (yineleme yok)
    return stopped


def _lm_reap_orphan(*, run=subprocess.run, kill=os.kill, sleep=time.sleep) -> str:
    """Açılışta yetim yerel model sunucusunu toplar (G7; P21 LM-05 bekçisinin kaçırdığı durum: bekçi de öldüyse).
    Kapatılan süreç PID dosyasındakidir ve (a) kayıtlı ikilinin adı ``llama-server``, (b) ebeveyni ölmüş (ppid 1:
    yaşayan bir CLI oturumunun sunucusuna dokunulmaz), (c) ``ps`` satırında kayıtlı ikili ve kapı var
    (``reap_recorded``; PID yeniden kullanımı). Okunur bir sonuç iletisi döndürür."""
    state = _lm_base() / "sunucu"
    pidf = LlamaServerBackend(Path("llama-server"), Path(os.devnull), state, watchdog=None).pid_file
    try:
        rec = json.loads(pidf.read_text(encoding="utf-8"))
        pid, binary = int(rec["pid"]), Path(str(rec["ikili"]))
    except (OSError, ValueError, KeyError, TypeError):
        return "kayıt yok"
    if binary.name != "llama-server":
        return "kayıttaki ikili llama-server değil: dokunulmadı"
    try:
        r = run(["ps", "-o", "ppid=", "-p", str(pid)], capture_output=True, text=True, timeout=5)
        ppid = (r.stdout or "").strip()
    except (OSError, subprocess.TimeoutExpired):
        return "ps okunamadı: dokunulmadı"
    if ppid and ppid != "1":
        return "ebeveyni yaşıyor: dokunulmadı"
    b = LlamaServerBackend(binary, Path(os.devnull), state, run=run, kill=kill, sleep=sleep, watchdog=None)
    return "yetim sunucu kapatıldı" if b.reap_recorded() else "kayıtlı süreç yok ya da eşleşmedi: kayıt silindi"


# /api/lm/* yönlendirmesi (hepsi Handler'da _guard'dan SONRA çağrılır: Host + Origin + jeton).
_LM_GET = {
    "/api/lm/olaylar": _lm_events,
    "/api/lm/durum": lambda q: _lm_status(),
    "/api/lm/sonuc": _lm_result,
    "/api/lm/oneriler": _lm_proposals,
}
_LM_POST = {
    "/api/lm/terminal/girdi": _lm_input,
    "/api/lm/durdur": _lm_stop,
    "/api/lm/oneri/kabul": _lm_accept,
    "/api/lm/oneri/ret": _lm_reject,
    "/api/lm/terminal/kapat": _lm_close,
}


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
def _json_object(raw: bytes) -> dict:
    """POST gövdesini JSON nesnesi olarak çöz; bozuk ya da nesne olmayan gövde -> {}."""
    try:
        body = json.loads(raw or b"{}")
    except ValueError:  # JSONDecodeError + geçersiz UTF-8
        return {}
    return body if isinstance(body, dict) else {}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:
        pass

    def _send(self, code, ctype, body: bytes, extra_headers: dict | None = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, "application/json", json.dumps(obj).encode("utf-8"))

    def _guard(self, *, needs_token: bool) -> bool:
        """Yerel sunucu koruması; izin yoksa 403 gönderir ve False döner.

        127.0.0.1'e bağlanmak tek başına yetmez: tarayıcıda açık herhangi bir sayfa
        bu porta istek atabilir (CSRF) ve DNS rebinding ile yanıtları okuyabilir.
        - Host yalnız 127.0.0.1:<port> / localhost:<port> (rebinding'de Host,
          saldırganın alan adıdır).
        - Origin varsa aynı köken olmalı (tarayıcı çapraz köken POST'ta gönderir).
        - /api/ping dışındaki /api/* istekleri X-Karadul-Token taşımalı: özel başlık
          çapraz kökende CORS ön-uçuşunu zorlar, bu sunucu ön-uçuşa izin vermez.
        """
        hosts = {f"127.0.0.1:{_PORT}", f"localhost:{_PORT}"}
        if self.headers.get("Host", "") not in hosts:
            self._json({"error": "izin verilmeyen Host"}, 403)
            return False
        origin = self.headers.get("Origin")
        if origin is not None and origin not in {f"http://{h}" for h in hosts}:
            self._json({"error": "izin verilmeyen köken"}, 403)
            return False
        # bayt karşılaştırması: ASCII dışı başlık compare_digest'te TypeError fırlatmasın
        if needs_token and not hmac.compare_digest(
            self.headers.get("X-Karadul-Token", "").encode("utf-8"), _TOKEN.encode("utf-8"),
        ):
            self._json({"error": "geçersiz jeton"}, 403)
            return False
        return True

    def _read_body(self) -> bytes | None:
        """POST gövdesini sınırlı oku; geçersiz/aşırı uzunlukta hata gönderip None döner."""
        try:
            n = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            n = -1
        if n < 0:
            self._json({"error": "geçersiz Content-Length"}, 400)
            return None
        if n > _MAX_BODY:
            self._json({"error": "gövde çok büyük"}, 413)
            return None
        return self.rfile.read(n) if n else b""

    def do_GET(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        if not self._guard(needs_token=path.startswith("/api/") and path != "/api/ping"):
            return
        if path in ("/", "/index.html"):
            html = (Path(__file__).parent / "index.html").read_text(encoding="utf-8")
            # Sayfa kendi istek jetonunu taşır; Host koruması yüzünden yabancı köken
            # bu yanıtı okuyamaz. no-store: yeniden başlatmada eski jetonlu sayfa kalmasın.
            html = html.replace("__KARADUL_TOKEN__", _TOKEN)
            self._send(200, "text/html; charset=utf-8", html.encode("utf-8"),
                       {"Cache-Control": "no-store"})
        elif path == "/favicon.ico":
            # kucuk seffaf favicon (404 gurultusunu onle)
            self._send(200, "image/svg+xml",
                       b'<svg xmlns="http://www.w3.org/2000/svg"/>')
        elif path == "/api/ping":
            # app_window bununla "bu server benim" der; kimlik jetonu.
            self._json({"token": _TOKEN, "ok": True})
        elif path == "/api/binaries":
            self._json({"binaries": list_binaries()})
        elif path == "/api/progress":
            qs = self.path.split("?", 1)[1] if "?" in self.path else ""
            q = dict(x.split("=", 1) for x in qs.split("&") if "=" in x)
            self._json(_progress_and_activate(q.get("job", "")))
        elif path == "/api/jobs/current":
            self._json(current_job())
        elif path in ("/api/model", "/api/functions"):
            d = build_model()
            self._json(d) if d else self._json({"error": "workspace yok"}, 404)
        elif path == "/api/evidence":
            qs = self.path.split("?", 1)[1] if "?" in self.path else ""
            q = dict(x.split("=", 1) for x in qs.split("&") if "=" in x)
            addr = urllib.parse.unquote(q.get("addr", ""))
            if not _known_node(addr):
                self._json({"error": "geçersiz adres"}, 400)
                return
            ev = _evidence(addr)
            self._json(ev, ev.pop("__code", 200))
        elif path == "/api/overrides":
            bh = _active_binary_hash()
            names = overrides.all_names(bh) if bh else {}
            self._json({"overrides": names, "count": len(names)})
        elif path == "/api/settings":
            self._json(_read_settings())
        elif path == "/api/about":
            # ASLA 500: panel bilgi amacli, tek bir okunamayan alan yuzunden
            # modal bos kalmasin (icerideki her alan zaten _safe ile sarili).
            self._json(_safe(_about_payload, None) or _about_fallback())
        elif path == "/api/disk-access":
            # FDA + korumali klasor durumu (antivirus deseni). ASLA 500.
            self._json(_safe(_disk_access, {"full_disk_access": False,
                       "protected_folders": {}, "is_macos": _IS_MAC,
                       "probe": str(_TCC_PROBE)}))
        elif path == "/api/update-check":
            # Uzak manifest ile kiyas (bildirim; yerinde-degistirmesiz).
            # ?force=1 -> 24 saatlik throttle cache'ini atla, taze cek.
            # ASLA 500 / bloklama: ag hatasi -> status "unknown".
            qs = self.path.split("?", 1)[1] if "?" in self.path else ""
            q = dict(x.split("=", 1) for x in qs.split("&") if "=" in x)
            force = q.get("force") in ("1", "true", "yes")
            # force=1 yalnız menünün "Güncellemeleri Kontrol Et"inden gelir: açık istek.
            # Açılıştaki otomatik sorgu (force yok) ayrıca update_check tercihini ister.
            self._json(_safe(lambda: _update_check(force=force, explicit=force),
                             {"status": "unknown",
                       "current": _safe(_current_version, None), "latest": None,
                       "url": _RELEASES_URL, "error": "ic hata"}))
        elif path == "/api/update-download-status":
            # Arka plan indirme ilerlemesi (bytes/total + status). ASLA 500.
            self._json(_safe(_update_dl_snapshot, {"status": "idle",
                       "downloaded": 0, "total": 0, "error": None}))
        elif path in _LM_GET:
            result = _LM_GET[path](_lm_query(self.path))
            self._json(result, result.pop("__code", 200))
        elif path.startswith("/api/decompiled/"):
            addr = urllib.parse.unquote(path.split("/api/decompiled/", 1)[1])
            if not _known_node(addr):
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
        if not self._guard(needs_token=True):
            return
        # Gövde her uçta sınırlı okunur (tetikleyici uçlarda da drain edilir).
        raw = self._read_body()
        if raw is None:
            return
        path = self.path.split("?", 1)[0]
        if path == "/api/analyze":
            body = _json_object(raw)
            binary = body.get("binary", "")
            if not binary:
                self._json({"error": "binary belirtilmedi"}, 400)
                return
            self._json(start_analysis(binary))
        elif path == "/api/cancel":
            body = _json_object(raw)
            result = cancel_job(str(body.get("job", "")))
            self._json(result, result.pop("__code", 200))
        elif path == "/api/rename":
            body = _json_object(raw)
            addr = str(body.get("addr", ""))
            name = str(body.get("name", ""))
            result = _do_rename(addr, name)
            self._json(result, result.pop("__code", 200))
        elif path == "/api/settings":
            try:
                body = json.loads(raw or b"{}")
            except ValueError:  # JSONDecodeError + geçersiz UTF-8
                self._json({"error": "geçersiz JSON"}, 400)
                return
            if not isinstance(body, dict):
                # bozuk/non-object gövde ayarları sessizce default'a sıfırlamasın
                self._json({"error": "gövde bir nesne olmalı"}, 400)
                return
            result = _write_settings(body.get("knobs", {}))
            self._json(result, result.pop("__code", 200))
        elif path == "/api/open-fda-settings":
            # Sistem Ayarları FDA bölmesini aç (gövde kullanılmaz; sadece tetikleyici).
            result = _open_fda_settings()
            self._json(result, result.pop("__code", 200))
        elif path == "/api/update-download":
            # DMG'yi indir -> sha256 dogrula -> mount (arka planda; YERINDE-DEGISTIRMESIZ).
            # Gövde kullanılmaz (JS'ten URL ALINMAZ) -- sadece tetikleyici.
            self._json(_safe(_start_update_download, {"status": "error",
                       "error": "ic hata", "downloaded": 0, "total": 0}))
        elif path == "/api/lm/terminal/komut":
            result = _lm_open(_json_object(raw).get("komut"))
            self._json(result, result.pop("__code", 200))
        elif path in _LM_POST:
            result = _LM_POST[path](_json_object(raw))
            self._json(result, result.pop("__code", 200))
        else:
            self._json({"error": "not found"}, 404)


def _kill_jobs():
    """Çalışan analizleri (ve altlarındaki Ghidra JVM'i) sonlandır; açık KaradulLM oturumunu ve yerel model
    sunucusunu kapat (P22c1; G7: arayüz kapanınca süreç ölür)."""
    with _JOBS_LOCK:
        for j in _JOBS.values():
            proc = j.get("proc")
            if proc is None or proc.poll() is not None:
                continue
            _kill_proc(proc)
    _lm_close_current(lm_session.CLOSE_UI, wait=_LM_SHUTDOWN_JOIN_SEC)


def _terminate_jobs(signum=None, frame=None):  # noqa: ANN001, ARG001
    """SIGTERM/SIGINT: analizleri götür, sonra çık (handler ana thread'de çalışır)."""
    _kill_jobs()
    sys.exit(0)


def _parent_watchdog():
    """Ebeveyn (app_window) öldüyse kendini kapat — öksüz server kalmasın.

    DİKKAT: burası bir thread. ``sys.exit()`` yalnızca thread'i bitirir, süreci
    DEĞİL (test edildi: server ayakta kalıyordu) -> os._exit ile süreci bitir.
    """
    while True:
        if os.getppid() == 1:
            _kill_jobs()
            sys.stderr.flush()
            os._exit(0)
        _lm_idle_tick()
        time.sleep(2)


if __name__ == "__main__":
    WS = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("KARADUL_WS")
    where = WS or "(giriş ekranı — UI'den binary seç)"
    signal.signal(signal.SIGTERM, _terminate_jobs)
    signal.signal(signal.SIGINT, _terminate_jobs)
    threading.Thread(target=_parent_watchdog, daemon=True).start()
    # Önceki çökmeden kalmış yetim model sunucusu (bekleme sunucuyu geciktirmesin: arka planda)
    threading.Thread(target=lambda: print(f"KaradulLM sunucu kaydı: {_lm_reap_orphan()}", file=sys.stderr),
                     daemon=True).start()
    print(f"Black Widow konsolu  ->  http://127.0.0.1:{_PORT}   {where}")
    ThreadingHTTPServer(("127.0.0.1", _PORT), Handler).serve_forever()
