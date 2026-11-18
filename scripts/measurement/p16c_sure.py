#!/usr/bin/env python3
"""P16c süre ölçümü: Ghidra köprüsünü (``GhidraHeadless.analyze``) aşama aşama zamanlar.

Tek süreçte (tek JVM) verilen ikilileri sırayla koşar. Ürün kodunu değiştirmez: adımları
çalışma anında sarmalar (her adımın duvar saati süresi), Ghidra'nın otomatik analizini ayrı
zamanlar ve ``AutoAnalysisManager``'ın çözümleyici başına zaman raporunu okur. Ürün kodu
otomatik analizi kendisi yürütüyorsa (P16c kalem 1) sonucu ``analysis`` alanından alır.

Her ikili için ``<kök>/<etiket>/<anahtar>.json``: süreler, makine yükü (``uptime``,
eşzamanlı Ghidra süreç sayısı), sayılar (fonksiyon, decompile, tip, BSim eşleşmesi) ve
Ghidra çıktı dosyalarının özetleri (zaman alanları ayıklanmış JSON + ``.c`` dosyaları; iki
kolun çıktısı aynı mı diye ``karsilastir`` alt komutu bakar).

Kullanım (worktree kökünden; BSim deposu koşu köküne özel olsun):

    KARADUL_CACHE_DIR=<kök>/cache PYTHONHASHSEED=0 python scripts/measurement/p16c_sure.py kos \\
        --kok <kök> --etiket once --yalniz debian/coreutils/cat --yalniz mac/htop
    python scripts/measurement/p16c_sure.py ozet --kok <kök> --etiket once
    python scripts/measurement/p16c_sure.py karsilastir --kok <kök> --a once --b sonra
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

DEPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(DEPO))
sys.path.insert(0, str(Path(__file__).resolve().parent))

# Zamanlanan GhidraHeadless adımları (ad -> etiket). Var olmayan ad atlanır.
ADIMLAR = {
    "_load_gdt_archives_pyghidra": "gdt",
    "_load_pdb_if_available": "pdb",
    "_extract_functions": "functions",
    "_extract_strings": "strings",
    "_extract_call_graph": "call_graph",
    "_decompile_functions": "decompile",
    "_extract_types": "types",
    "_extract_xrefs": "xrefs",
    "_write_pcode_jsonl": "pcode",
    "_extract_pcode": "pcode",
    "_extract_pcode_stats_only": "pcode",
    "_extract_cfg": "cfg",
    "_extract_function_id_matches": "function_id",
    "_get_program_info": "program_info",
    "_save_output": "json_yazimi",
    "_run_auto_analysis": "analysis",
}
BSIM_ADIMLARI = {
    "ingest_program": "bsim_ingest",
    "query_all_functions": "bsim_query",
    "close": "bsim_close",
}
# JSON özetinde ayıklanan (koşudan koşuya değişen) alanlar.
ZAMAN_ANAHTARI = re.compile(
    r"(duration|elapsed|_s$|_sn$|time|timestamp|started|finished|wait|retries|lock)", re.I)
GOREV_SATIRI = re.compile(r"^\s*(.+?)\s+([0-9]+(?:\.[0-9]+)?)\s+secs?\s*$")


def yuk() -> dict:
    """``uptime`` yük ortalaması ve eşzamanlı Ghidra süreç sayısı (bu süreç hariç)."""
    out: dict = {}
    try:
        u = subprocess.run(["uptime"], capture_output=True, text=True, check=False).stdout
        m = re.search(r"load averages?:\s*([\d.,]+)[ ,]+([\d.,]+)[ ,]+([\d.,]+)", u)
        if m:
            out["load"] = [float(x.replace(",", ".")) for x in m.groups()]
    except OSError:
        out["load"] = None
    try:
        p = subprocess.run(["pgrep", "-f", "ghidra"], capture_output=True, text=True, check=False)
        pids = [x for x in p.stdout.split() if x.strip() and int(x) != os.getpid()]
        out["ghidra_surec"] = len(pids)
    except OSError:
        out["ghidra_surec"] = None
    return out


def gorev_sureleri(metin: str) -> dict[str, float]:
    """``AutoAnalysisManager.getTaskTimesString()`` → {çözümleyici: sn}."""
    sonuc: dict[str, float] = {}
    for satir in (metin or "").splitlines():
        m = GOREV_SATIRI.match(satir)
        if m and "total" not in m.group(1).lower():
            sonuc[m.group(1).strip()] = float(m.group(2))
    return sonuc


def _sarmala(sinif, ad: str, kayit: dict, etiket: str) -> None:
    ham = sinif.__dict__.get(ad)
    if ham is None:
        return
    statik = isinstance(ham, staticmethod)
    fn = ham.__func__ if statik else ham

    def sarmal(*a, **k):
        t = time.perf_counter()
        try:
            return fn(*a, **k)
        finally:
            kayit["adim"][etiket] = kayit["adim"].get(etiket, 0.0) + time.perf_counter() - t

    setattr(sinif, ad, staticmethod(sarmal) if statik else sarmal)


def kur_sarmallar(kayit: dict, kapali: list[str]) -> None:
    import pyghidra
    import pyghidra.core as pcore

    from karadul.ghidra import bsim as bsim_mod
    from karadul.ghidra.headless import GhidraHeadless

    for ad, et in ADIMLAR.items():
        _sarmala(GhidraHeadless, ad, kayit, et)
    for ad, et in BSIM_ADIMLARI.items():
        _sarmala(bsim_mod.BSimDatabase, ad, kayit, et)

    ozgun_analiz = pcore._analyze_program

    def analiz(flat_api, program):
        from ghidra.app.plugin.core.analysis import AutoAnalysisManager
        if kapali:
            kapat(program, kapali, kayit)
        t = time.perf_counter()
        try:
            ozgun_analiz(flat_api, program)
        finally:
            kayit["adim"]["analysis"] = time.perf_counter() - t
            try:
                mgr = AutoAnalysisManager.getAnalysisManager(program)
                kayit["cozumleyici"] = gorev_sureleri(str(mgr.getTaskTimesString()))
            except Exception as exc:  # noqa: BLE001
                kayit["cozumleyici_hata"] = repr(exc)

    pcore._analyze_program = analiz
    ozgun_ac = pyghidra.open_program

    @contextlib.contextmanager
    def ac(*a, **k):
        t0 = time.perf_counter()
        cm = ozgun_ac(*a, **k)
        api = cm.__enter__()
        kayit["adim"]["open_program"] = time.perf_counter() - t0
        try:
            yield api
        except BaseException:
            t1 = time.perf_counter()
            cm.__exit__(*sys.exc_info())
            kayit["adim"]["save_close"] = time.perf_counter() - t1
            raise
        t1 = time.perf_counter()
        cm.__exit__(None, None, None)
        kayit["adim"]["save_close"] = time.perf_counter() - t1

    pyghidra.open_program = ac


def kapat(program, adlar: list[str], kayit: dict) -> None:
    """Taban kodda kol denemesi: verilen çözümleyicileri analizden önce kapat."""
    from ghidra.program.model.listing import Program
    tx = program.startTransaction("p16c kapali cozumleyiciler")
    try:
        opts = program.getOptions(Program.ANALYSIS_PROPERTIES)
        kayit["kapatilan"] = {}
        for ad in adlar:
            vardi = bool(opts.contains(ad))
            if vardi:
                opts.setBoolean(ad, False)
            kayit["kapatilan"][ad] = vardi
    finally:
        program.endTransaction(tx, True)
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager
    AutoAnalysisManager.getAnalysisManager(program).initializeOptions()


def _ayikla(v):
    if isinstance(v, dict):
        return {k: _ayikla(x) for k, x in v.items() if not ZAMAN_ANAHTARI.search(str(k))}
    if isinstance(v, list):
        return [_ayikla(x) for x in v]
    return v


def cikti_ozeti(cikti: Path) -> dict[str, str]:
    ozet: dict[str, str] = {}
    for p in sorted(cikti.rglob("*")):
        if not p.is_file():
            continue
        ad = str(p.relative_to(cikti))
        if p.suffix == ".json":
            try:
                veri = _ayikla(json.loads(p.read_text(encoding="utf-8")))
                b = json.dumps(veri, sort_keys=True, ensure_ascii=False).encode()
            except (OSError, ValueError):
                b = p.read_bytes()
        else:
            b = p.read_bytes()
        ozet[ad] = hashlib.sha256(b).hexdigest()[:16]
    return ozet


def _anahtar_dosya(anahtar: str) -> str:
    return anahtar.replace("/", "__")


def kos(arg) -> int:
    if arg.agac:
        # Kol ağacı (ör. tabanın `git archive` kopyası): karadul oradan yüklenmeli.
        sys.path.insert(0, str(arg.agac.resolve()))
        import karadul
        if not str(Path(karadul.__file__).resolve()).startswith(str(arg.agac.resolve()) + os.sep):
            raise SystemExit(f"karadul {karadul.__file__} yükleniyor, {arg.agac} DEĞİL")
    from urun_kos import TABAN_DEBIAN, isleri_topla
    isler = {i["anahtar"]: i for i in isleri_topla(TABAN_DEBIAN, arg.taban_mac)}
    secili = arg.yalniz or []
    eksik = [a for a in secili if a not in isler]
    if eksik:
        raise SystemExit(f"bilinmeyen anahtar: {eksik}")
    hedef = arg.kok / arg.etiket
    hedef.mkdir(parents=True, exist_ok=True)

    from karadul.config import Config
    from karadul.ghidra import headless as hl
    cfg = Config.load(arg.config) if arg.config else Config()
    if arg.kapali:
        # P16c kodu: ayar (config alanı yok, getattr ile okunur); taban kodda `analiz` sarmalı kapatır.
        cfg.analysis.ghidra_disabled_analyzers = list(arg.kapali)
    kayit: dict = {"adim": {}}
    kur_sarmallar(kayit, arg.kapali)

    t_jvm = time.perf_counter()
    hl._ensure_pyghidra_started(Path(cfg.tools.ghidra_headless).parent.parent)
    jvm_s = time.perf_counter() - t_jvm

    for anahtar in secili:
        is_ = isler[anahtar]
        kayit.clear()
        kayit["adim"] = {}
        cikti = hedef / _anahtar_dosya(anahtar)
        if cikti.exists():
            shutil.rmtree(cikti)
        cikti.mkdir(parents=True)
        yuk_once = yuk()
        with tempfile.TemporaryDirectory(prefix="p16c_proj_", dir=str(arg.kok)) as proj:
            t = time.perf_counter()
            sonuc = hl.GhidraHeadless(cfg).analyze(
                Path(is_["girdi"]), Path(proj), output_dir=cikti / "ghidra_output")
            toplam = time.perf_counter() - t
        so = sonuc.get("scripts_output", {})
        analiz = sonuc.get("analysis") or {}
        adim = dict(kayit["adim"])
        if "analysis" in adim and "open_program" in adim and not analiz:
            # Taban kod: open_program(analyze=True) içe aktarma + analizi birlikte yapar.
            adim["import"] = adim["open_program"] - adim["analysis"]
        elif "open_program" in adim:
            adim["import"] = adim["open_program"]
        import karadul
        kayit_dosya = {
            "anahtar": anahtar,
            "karadul_dosyasi": karadul.__file__,
            "girdi_boyut": Path(is_["girdi"]).stat().st_size,
            "etiket": arg.etiket,
            "kapali": arg.kapali,
            "jvm_baslatma_s": round(jvm_s, 2),
            "toplam_s": round(toplam, 2),
            "adim_s": {k: round(v, 3) for k, v in sorted(adim.items())},
            "cozumleyici_s": analiz.get("analyzer_times") or kayit.get("cozumleyici") or {},
            "analiz": {k: v for k, v in analiz.items() if k != "analyzer_times"},
            "kapatilan": kayit.get("kapatilan") or analiz.get("disabled_analyzers"),
            "yuk_once": yuk_once,
            "yuk_sonra": yuk(),
            "basari": sonuc.get("success"),
            "hata": sonuc.get("error"),
            "adim_hatalari": sonuc.get("step_errors"),
            "sayilar": {
                "fonksiyon": so.get("functions", {}).get("total"),
                "program_fonksiyonu": so.get("functions", {}).get("program_function_count"),
                "decompile_basarili": so.get("decompiled", {}).get("success"),
                "decompile_denenen": so.get("decompiled", {}).get("total_attempted"),
                "tip": so.get("types", {}).get("total_types"),
                "yapi": so.get("types", {}).get("total_structures"),
                "bsim_eslesme": so.get("bsim", {}).get("total_matches"),
                "bsim_durum": (so.get("bsim", {}).get("bsim_status")),
                "bsim_kip": (so.get("bsim", {}).get("bsim_mode")),
            },
            "bsim_ayrinti": so.get("bsim", {}).get("bsim_detail"),
            "cikti_ozeti": cikti_ozeti(cikti / "ghidra_output"),
        }
        (hedef / f"{_anahtar_dosya(anahtar)}.json").write_text(
            json.dumps(kayit_dosya, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"{anahtar}: {toplam:.1f} sn  " + "  ".join(
            f"{k}={v:.1f}" for k, v in sorted(adim.items(), key=lambda x: -x[1])[:8]), flush=True)
    return 0


def _oku(kok: Path, etiket: str) -> dict[str, list[dict]]:
    """Etiket ya da ``etiket*`` (tekrarlar: once1, once2 …) altındaki kayıtlar."""
    out: dict[str, list[dict]] = {}
    for d in sorted(kok.glob(etiket + "*")):
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.json")):
            k = json.loads(f.read_text(encoding="utf-8"))
            out.setdefault(k["anahtar"], []).append(k)
    return out


def ozet(arg) -> int:
    veri = _oku(arg.kok, arg.etiket)
    satirlar = []
    for anahtar, kayitlar in sorted(veri.items()):
        adimlar = sorted({a for k in kayitlar for a in k["adim_s"]})
        med = {a: statistics.median(k["adim_s"].get(a, 0.0) for k in kayitlar) for a in adimlar}
        top = statistics.median(k["toplam_s"] for k in kayitlar)
        coz: dict[str, list[float]] = {}
        for k in kayitlar:
            for c, s in k["cozumleyici_s"].items():
                coz.setdefault(c, []).append(s)
        coz_med = {c: statistics.median(v) for c, v in coz.items()}
        satirlar.append({"anahtar": anahtar, "n": len(kayitlar), "toplam_s": round(top, 1),
                         "adim_s": {a: round(v, 1) for a, v in med.items()},
                         "adim_pay": {a: round(100 * v / top, 1) for a, v in med.items() if top},
                         "cozumleyici_s": dict(sorted(((c, round(v, 2)) for c, v in coz_med.items()),
                                                       key=lambda x: -x[1])),
                         "yuk": [k["yuk_once"] for k in kayitlar],
                         "sayilar": kayitlar[0]["sayilar"]})
    print(json.dumps(satirlar, indent=1, ensure_ascii=False))
    return 0


def karsilastir(arg) -> int:
    a = _oku(arg.kok, arg.a)
    b = _oku(arg.kok, arg.b)
    rapor = []
    for anahtar in sorted(set(a) & set(b)):
        ka, kb = a[anahtar], b[anahtar]
        ta = statistics.median(k["toplam_s"] for k in ka)
        tb = statistics.median(k["toplam_s"] for k in kb)
        oa, ob = ka[0]["cikti_ozeti"], kb[0]["cikti_ozeti"]
        farkli = sorted(f for f in set(oa) | set(ob) if oa.get(f) != ob.get(f))
        rapor.append({"anahtar": anahtar, "a_s": round(ta, 1), "b_s": round(tb, 1),
                      "oran": round(tb / ta, 3) if ta else None,
                      "sayilar_a": ka[0]["sayilar"], "sayilar_b": kb[0]["sayilar"],
                      "farkli_dosya": len(farkli), "dosya": len(set(oa) | set(ob)),
                      "farkli_ornek": farkli[:15]})
    print(json.dumps(rapor, indent=1, ensure_ascii=False))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    alt = ap.add_subparsers(dest="komut", required=True)
    k = alt.add_parser("kos")
    k.add_argument("--kok", type=Path, required=True)
    k.add_argument("--etiket", required=True)
    k.add_argument("--yalniz", action="append", required=True)
    k.add_argument("--kapali", action="append", default=[],
                   help="analizden önce kapatılacak Ghidra çözümleyicisi (taban kodda kol denemesi)")
    k.add_argument("--config", type=Path, default=None)
    k.add_argument("--agac", type=Path, default=None,
                   help="karadul'un yükleneceği ağaç (öntanım: bu betiğin deposu)")
    k.add_argument("--taban-mac", type=Path,
                   default=Path("/Users/apple/Black_Widow/workspaces/olcum_mac/runs/ol7-c-b7faeac"))
    o = alt.add_parser("ozet")
    o.add_argument("--kok", type=Path, required=True)
    o.add_argument("--etiket", required=True)
    c = alt.add_parser("karsilastir")
    c.add_argument("--kok", type=Path, required=True)
    c.add_argument("--a", required=True)
    c.add_argument("--b", required=True)
    arg = ap.parse_args(argv)
    return {"kos": kos, "ozet": ozet, "karsilastir": karsilastir}[arg.komut](arg)


if __name__ == "__main__":
    raise SystemExit(main())
