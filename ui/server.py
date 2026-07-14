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
import hashlib
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

# karadul içi -- kalıcı manuel-override deposu (Analist İncele & Düzelt) +
# ayar paneli için Config yükleyici (Faz 3). yaml çekirdek bağımlılık (config.py:10).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import yaml  # noqa: E402  (config.py hard-import eder -> her zaman kurulu)
from karadul.config import Config  # noqa: E402
from karadul.core import overrides  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parent.parent
HOME = Path.home()
# Ayar paneli: knob'lar bu YAML'a atomik yazılır; analiz subprocess'i (cwd=PROJECT_ROOT)
# --config ile yükler. Repo kökünde normalde YOK -> sıfırdan doğar, hiçbir şeyi ezmez.
_SETTINGS_YAML = PROJECT_ROOT / "karadul.yaml"
WS: str | None = None
_ADDR_RE = re.compile(r"_[0-9a-f]{3,}$")
_FUN_RE = re.compile(r"FUN_[0-9a-fA-F]+")
_PORT = 8000
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
    try:
        with open(nm_path) as _fh:
            names = json.load(_fh).get("global", {})
    except (json.JSONDecodeError, OSError, AttributeError):
        names = {}
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


def _active_run_dir(ws: str | None) -> Path | None:
    """WS'ten yukari yuruyerek clean/report.json iceren run dizinini bul."""
    if not ws:
        return None
    p = Path(ws)
    for anc in [p, *p.parents]:
        if (anc / "clean" / "report.json").is_file():
            return anc
        if anc.name == "_runs":  # ui/_runs sinirini gecme
            break
    return None


def _active_binary_hash(ws: str | None = None) -> str | None:
    """Aktif binary'nin STABIL anahtari: report.json target.hash, yoksa sha256.

    Ayni WS icin cache'lenir (ayni binary -> ayni hash, rename'de degismez).
    """
    ws = ws or WS
    if not ws:
        return None
    with _CACHE_LOCK:
        if _CACHE.get("bhash_ws") == ws and _CACHE.get("bhash"):
            return _CACHE["bhash"]
    h: str | None = None
    rd = _active_run_dir(ws)
    if rd:
        try:
            h = json.loads((rd / "clean" / "report.json").read_text())["target"]["hash"]
        except (json.JSONDecodeError, KeyError, OSError, TypeError):
            h = None
    if not h:  # fallback: cozumlenen binary'nin sha256'si
        bin_path = resolve_binary(_ws_binary_name(ws))
        if bin_path:
            try:
                hh = hashlib.sha256()
                with open(bin_path, "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        hh.update(chunk)
                h = hh.hexdigest()
            except OSError:
                h = None
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
    """Aktif run'in clean/naming_map.json 'mappings' bloku (provenance/hint icin)."""
    ws = ws or WS
    if not ws:
        return {}
    with _CACHE_LOCK:
        if _CACHE.get("cmap_ws") == ws and "cmap" in _CACHE:
            return _CACHE["cmap"]
    m: dict = {}
    rd = _active_run_dir(ws)
    if rd:
        try:
            m = json.loads((rd / "clean" / "naming_map.json").read_text()).get("mappings", {})
        except (json.JSONDecodeError, OSError, TypeError):
            m = {}
    if not isinstance(m, dict):
        m = {}
    with _CACHE_LOCK:
        _CACHE["cmap_ws"] = ws
        _CACHE["cmap"] = m
    return m


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

    # 1) imza durumu (isimsiz => uygulanabilir imza tutmamis)
    if cls == "weak":
        signals.append("Yalnızca zayıf/adres-sonekli isim — kesin imza eşleşmesi yok")
    else:
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
        signals.append(f"Bu binary genelinde hesaplama füzyonu hiçbir fonksiyona isim "
                       f"veremedi ({cfm} aday üretildi, hiçbiri güven eşiğini geçemedi)")

    # verdict + insan-okunur neden
    if strong_bsim:
        verdict = "bsim_shadow"
        reason = (f"BSim güçlü benzer buldu ('{bsim['name']}', %{round(sim * 100)}) ama gölge "
                  "modunda kapalı. İmzalar → BSim'i füzyona açarsan otomatik isimlenebilir.")
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


def _evidence(addr: str) -> dict:
    """addr icin kanit paketi (yalnizca gercek veri)."""
    model = build_model()
    if not model:
        return {"__code": 404, "error": "workspace yok"}
    names = model["names"]
    calls = model["calls"]
    current = names.get(addr, addr)

    def node(a: str) -> dict:
        nm = names.get(a, a)
        return {"addr": a, "name": nm, "cls": _classify(nm)}

    callees = [node(c) for c in calls.get(addr, [])]
    callers = [node(a) for a in sorted(a for a, cl in calls.items() if addr in cl)]

    text = _decompiled_text(addr)
    cmap = _clean_mappings()
    prov = None
    rec = cmap.get(addr)
    if isinstance(rec, dict):
        prov = {"source": rec.get("source"), "confidence": rec.get("confidence")}
        if rec.get("library"):
            prov["library"] = rec["library"]

    cls = _classify(current)
    return {
        "addr": addr,
        "current_name": current,
        "cls": cls,
        "callers": callers,
        "callees": callees,
        "strings": _extract_strings(text),
        "provenance": prov,
        "hints": _external_call_hints(text, cmap),
        # neden isimsiz/zayif kaldi? (yalnizca isimli olmayanlar icin)
        "diagnosis": _naming_diagnosis(addr, text, cmap, cls) if cls != "named" else None,
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
    # oku-değiştir-yaz'ı serileştir (ThreadingHTTPServer -> eşzamanlı rename yarışı)
    with _RENAME_LOCK:
        try:
            data = json.loads(Path(nm_path).read_text())
        except (json.JSONDecodeError, OSError):
            return {"__code": 500, "error": "naming_map okunamadı"}
        if not isinstance(data, dict):
            data = {}
        data.setdefault("global", {})[addr] = name
        try:
            _atomic_write_json(Path(nm_path), data)
        except OSError as e:
            return {"__code": 500, "error": f"naming_map yazılamadı: {e}"}

    # kalici override deposu (binary_hash bazli) -- naming_map yeniden
    # uretilse bile isim geri gelsin diye
    bh = _active_binary_hash(ws)
    if bh:
        try:
            overrides.set_name(bh, addr, name, binary=_ws_binary_name(ws))
        except ValueError:
            pass  # naming_map zaten guncellendi; override best-effort

    activate_workspace(ws)  # model cache temizle -> sonraki /api/model taze
    return {"ok": True, "addr": addr, "name": name}


# ---------------------------------------------------------------------------
# Ayar paneli (Faz 3) + kendi imza yollari (Faz 4) -- SADE, tek YAML dosyasi
#
# 7 knob karadul.yaml'a BOLUMLU (sectioned) yazilir. Cogu Config._from_dict ile
# yuklenir; iki istisna DURUSTCE ele alinir:
#   * computation_recovery.enabled  -> YAML yuklenir AMA suffix'siz hedeflerde
#     cli.py:507 non-interactive guard False'a zorlar. Bu yuzden analiz'e ayrica
#     --compute-recovery / --no-compute-recovery CLI flag'i gecilir (deterministik).
#   * network.enabled               -> Config._from_dict "network" bolumunu HIC
#     islemiyor (loader boslugu, config.py'ye dokunamiyoruz). YAML'a yalnizca UI
#     durumu icin yazilir; gercek etki --enable-network CLI flag'iyle saglanir.
# ---------------------------------------------------------------------------
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
    """obj'i path'e atomik YAML yaz (tmp + os.replace) -> yarim/bozuk dosya olmaz."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            yaml.safe_dump(obj, f, default_flow_style=False,
                           allow_unicode=True, sort_keys=True)
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
    """karadul.yaml'i HAM oku (network.enabled gibi loader'in atladigi alanlar icin)."""
    p = _SETTINGS_YAML
    if not p.is_file():
        return {}
    try:
        d = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return {}
    return d if isinstance(d, dict) else {}


def _read_settings() -> dict:
    """Aktif 7 knob'u dondur. Config-yuklu 6 knob Config.load'dan (gercek etkin
    deger), network ham YAML'dan (loader boslugu)."""
    cfg = Config.load(_SETTINGS_YAML)   # dosya yoksa saf default
    br = cfg.binary_reconstruction
    cr = cfg.computation_recovery
    nm = cfg.name_merger
    raw = _settings_raw_yaml()
    net = raw.get("network")
    net_enabled = bool(net.get("enabled")) if isinstance(net, dict) else False
    # tek UI alani: external + gdt yollarini birlestir (POST tekrar ayirir)
    sig_paths = [str(p) for p in br.external_signature_paths] + \
                [str(p) for p in br.ghidra_data_type_archives]
    return {
        "knobs": {
            "min_naming_confidence": round(float(br.min_naming_confidence), 4),
            "unk_threshold": round(float(nm.unk_threshold), 4),
            "pipeline_iterations": int(br.pipeline_iterations),
            "max_functions_to_process": int(br.max_functions_to_process),
            "computation_recovery_enabled": bool(cr.enabled),
            "network_enabled": net_enabled,
            "signature_paths": sig_paths,
        },
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


def _write_settings(knobs) -> dict:
    """7 knob'u WHITELIST + tip/aralik dogrulamayla karadul.yaml'a atomik yaz.

    SADECE bilinen anahtarlar bolumlu dict'e girer (keyfi/kotu anahtar asla yazilmaz).
    """
    if not isinstance(knobs, dict):
        return {"__code": 400, "error": "knobs sözlük değil"}
    ext_paths, gdt_paths, warns = _classify_sig_paths(knobs.get("signature_paths"))
    # WHITELIST: cikti dict'i SADECE bu sabit iskeletten kurulur (injection guard).
    data = {
        "binary_reconstruction": {
            "min_naming_confidence": _as_float01(knobs.get("min_naming_confidence"), 0.7),
            "pipeline_iterations": _as_int(knobs.get("pipeline_iterations"), 1, 3),
            "max_functions_to_process": _as_int(knobs.get("max_functions_to_process"), 0, 0),
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
            "unk_threshold": _as_float01(knobs.get("unk_threshold"), 0.30),
        },
    }
    try:
        _atomic_write_yaml(_SETTINGS_YAML, data)
    except OSError as e:
        return {"__code": 500, "error": f"karadul.yaml yazılamadı: {e}"}
    out = _read_settings()   # geri-oku (round-trip dogrulanmis deger)
    out["ok"] = True
    out["warnings"] = warns
    return out


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
    # Ayar paneli (Faz 3): karadul.yaml varsa yukle. computation_recovery ve
    # network CLI flag'iyle deterministik gecilir (bkz. _read_settings notu).
    if _SETTINGS_YAML.is_file():
        cmd += ["--config", str(_SETTINGS_YAML)]
        try:
            _k = _read_settings()["knobs"]
            cmd += (["--compute-recovery"] if _k["computation_recovery_enabled"]
                    else ["--no-compute-recovery"])
            if _k["network_enabled"]:
                cmd += ["--enable-network"]
        except Exception:
            pass   # ayar okunamazsa --config yeter, best-effort flag'ler
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
        elif path == "/api/evidence":
            qs = self.path.split("?", 1)[1] if "?" in self.path else ""
            q = dict(x.split("=", 1) for x in qs.split("&") if "=" in x)
            addr = q.get("addr", "")
            if not _FUN_RE.fullmatch(addr):
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
        elif self.path.split("?", 1)[0] == "/api/rename":
            n = int(self.headers.get("Content-Length", 0) or 0)
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
            except json.JSONDecodeError:
                body = {}
            addr = str(body.get("addr", ""))
            name = str(body.get("name", ""))
            result = _do_rename(addr, name)
            self._json(result, result.pop("__code", 200))
        elif self.path.split("?", 1)[0] == "/api/settings":
            n = int(self.headers.get("Content-Length", 0) or 0)
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
            except json.JSONDecodeError:
                self._json({"error": "geçersiz JSON"}, 400)
                return
            if not isinstance(body, dict):
                # bozuk/non-object gövde ayarları sessizce default'a sıfırlamasın
                self._json({"error": "gövde bir nesne olmalı"}, 400)
                return
            result = _write_settings(body.get("knobs", {}))
            self._json(result, result.pop("__code", 200))
        else:
            self._json({"error": "not found"}, 404)


if __name__ == "__main__":
    WS = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("KARADUL_WS")
    where = WS or "(giriş ekranı — UI'den binary seç)"
    print(f"Black Widow konsolu  ->  http://127.0.0.1:{_PORT}   {where}")
    ThreadingHTTPServer(("127.0.0.1", _PORT), Handler).serve_forever()
