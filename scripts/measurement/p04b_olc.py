#!/usr/bin/env python3
"""P04b ölçümü: mühendislik sabit / yapısal katmanı ve alan kapısı (MUH-10), formül (MUH-12),
sanal çağrı çözücüsü (MUH-06), başvuru sürüm tespiti (MUH-09).

Ghidra'sız; kayıtlı koşu yapıtlarını ölçülen ağacın koduyla yeniden oynatır.
Worktree kökünden ``python scripts/measurement/p04b_olc.py <alt komut> ...``.

Alt komutlar
------------
``muh``       ``EngineeringAlgorithmAnalyzer``'ı ürünün girdileriyle (``parallel_algo_eng``:
              ``deobfuscated/decompiled`` yoksa ``static/ghidra_output/decompiled``, fonksiyon
              JSON'u önce ``deobfuscated/``) iki kipte koşar: (1) **ürün kipi**: alan kapısı
              ürünün kendi kararıyla (``_detect_domain``); (2) **zorla açık kip**: kapı açık
              sayılır (``has_domain=True``), yani kapı bir gün açılırsa sabit ve yapısal katmanın
              ne söyleyeceği. Tespitleri yönteme ve algoritmaya göre sayar.
``formul``    ``FormulaReconstructor.reconstruct``'ı kayıtlı ``algorithms.json`` +
              ``engineering_algorithms.json`` ile yeniden oynatır (ürün:
              ``engineering_analysis.py``) ve formül sayısını / adlarını verir.
``dispatch``  ``VirtualDispatchResolver.resolve``'u (``_deep_tracing_helpers.resolve_dispatch``)
              kayıtlı ayrıştırılmış kod + çağrı çizgesi + fonksiyon JSON'uyla koşar.
``refdiff``   ``VersionDetector.detect_from_strings``'i kayıtlı ``ghidra_strings.json`` ile koşar.
``karsilastir`` iki etiketin özetlerini yan yana yazar.

Koşu kökleri: ``--kosu`` ``urun_kos`` düzeni (``<kök>/debian/<program>/<ikili>/ws/workspaces/*/*``,
``<kök>/mac/<ikili>/...``); ``--ws`` tek çalışma dizini (CalculiX ``workspaces/ccx_2/<tarih>``).
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Optional

DEPO = Path(__file__).resolve().parents[2]
if str(DEPO) not in sys.path:
    sys.path.insert(0, str(DEPO))

BITTI = "BITTI"
KOSULAR = {
    "urun": Path("~/karadul_olcum/runs/urun-yeni2-f30ac9a").expanduser(),
    "head": Path("~/karadul_olcum/runs/genel-tarama-2026-11-18").expanduser(),
}
CIKTI = Path("~/karadul_olcum/runs/onarim-2026-11-18/P04b").expanduser()


def karadul_denetle() -> str:
    """``karadul`` bu ağaçtan mı yükleniyor? (editable kurulum ana ağacı gösterir)."""
    import karadul
    yol = Path(karadul.__file__).resolve()
    if not str(yol).startswith(str(DEPO.resolve())):
        raise SystemExit(f"karadul {yol} yükleniyor, {DEPO} değil: ölçüm yanlış ağacı ölçerdi")
    return str(yol)


def ikilileri_bul(kok: Path) -> list[tuple[str, Path]]:
    """``<kök>/debian/<program>/<ikili>`` ve ``<kök>/mac/<ikili>`` → (anahtar, çalışma alanı)."""
    sonuc = []
    for d in sorted(kok.glob("debian/*/*")) + sorted(kok.glob("mac/*")):
        if not d.is_dir() or not (d / "ws").is_dir():
            continue
        if not (d / BITTI).is_file():
            raise SystemExit(f"{d}: {BITTI} yok (yarım koşu ölçülmez)")
        alanlar = sorted((d / "ws" / "workspaces").glob("*/*"))
        if len(alanlar) != 1:
            raise SystemExit(f"{d}: {len(alanlar)} çalışma alanı (tam olarak bir tane olmalı)")
        sonuc.append((str(d.relative_to(kok)), alanlar[0]))
    return sonuc


def _sec(ws: Path, ad: str) -> Path:
    p = ws / "deobfuscated" / ad
    return p if p.exists() else ws / "static" / ad


def _decompiled(ws: Path) -> Path:
    p = ws / "deobfuscated" / "decompiled"
    return p if p.exists() else ws / "static" / "ghidra_output" / "decompiled"


def _json(p: Path) -> Any:
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace")) if p.is_file() else None
    except (OSError, json.JSONDecodeError):
        return None


# ---------------------------------------------------------------------------
# muh: mühendislik sabit / yapısal katmanı ve alan kapısı
# ---------------------------------------------------------------------------

def _sayim(eslesmeler: list) -> dict:
    yontem: Counter = Counter()
    algoritma: Counter = Counter()
    ornek: list[str] = []
    for m in eslesmeler:
        yontem[m.detection_method] += 1
        algoritma[f"{m.name} [{m.detection_method}]"] += 1
        if len(ornek) < 8 and m.detection_method != "api":
            ornek.append(f"{m.function_name}: {m.name} {m.confidence} {list(m.evidence)[:4]}")
    sabit_veya_yapisal = sum(n for y, n in yontem.items() if y != "api")
    return {"toplam": len(eslesmeler), "api_disi": sabit_veya_yapisal,
            "yontem": dict(yontem), "algoritma": dict(algoritma.most_common()), "ornek": ornek}


def muh_bir(kosu: str, anahtar: str, ws: Path, zorla: bool) -> dict:
    from karadul.reconstruction.engineering.analyzer import EngineeringAlgorithmAnalyzer
    kayit: dict[str, Any] = {"kosu": kosu, "anahtar": anahtar, "ws": str(ws)}
    dec = _decompiled(ws)
    fjson = _sec(ws, "ghidra_functions.json")
    if not dec.is_dir():
        kayit["durum"] = "decompiled yok"
        return kayit
    an = EngineeringAlgorithmAnalyzer()
    hatalar: list[str] = []
    meta = an._load_json(fjson, hatalar)
    dosyalar = an._collect_c_files(dec, hatalar)
    t0 = time.monotonic()
    kapi = bool(an._detect_domain(meta, dosyalar))
    kayit["kapi_acik"] = kapi
    ham_urun: list = []
    ham_zorla: list = []
    for f in dosyalar:
        if zorla:
            ham_zorla.extend(an._analyze_file(f, meta, True))
        else:
            ham_urun.extend(an._analyze_file(f, meta, kapi))
    if zorla:
        # ürün kipi = kapı kararı; kapı kapalıysa yalnız API katmanı (zorla koşudan süzülür)
        ham_urun = ham_zorla if kapi else [m for m in ham_zorla if m.detection_method == "api"]
        kayit["zorla"] = _sayim(an._deduplicate(an._combine_evidence(ham_zorla)))
    kayit["urun"] = _sayim(an._deduplicate(an._combine_evidence(ham_urun)))
    kayit["dosya"] = len(dosyalar)
    kayit["sure_sn"] = round(time.monotonic() - t0, 1)
    kayit["durum"] = "calisti"
    return kayit


def _isler(a: argparse.Namespace) -> list[tuple[str, str, Path]]:
    isler = []
    for kosu in a.kosu or []:
        for anahtar, ws in ikilileri_bul(KOSULAR[kosu]):
            if a.yalniz and not any(s in anahtar for s in a.yalniz):
                continue
            isler.append((kosu, anahtar, ws))
    for ws in a.ws or []:
        p = Path(ws).expanduser()
        isler.append(("ws", str(p), p))
    return isler


def _havuz(fn, isler: list[tuple], paralel: int, *ek) -> list[dict]:
    kayitlar = []
    with cf.ProcessPoolExecutor(max_workers=paralel) as havuz:
        gelecek = {havuz.submit(fn, k, an, ws, *ek): (k, an) for k, an, ws in isler}
        for g in cf.as_completed(gelecek):
            k, an = gelecek[g]
            try:
                kayitlar.append(g.result())
            except Exception as exc:  # ölçüm aracı: hatayı kayda yaz, sessiz geçme
                kayitlar.append({"kosu": k, "anahtar": an, "durum": f"hata: {exc!r}"})
    kayitlar.sort(key=lambda r: (r["kosu"], r["anahtar"]))
    return kayitlar


def _muh_ozet(kayitlar: list[dict]) -> dict:
    ozet: dict[str, Any] = {}
    for kip in ("urun", "zorla"):
        rs = [r for r in kayitlar if kip in r]
        if not rs:
            continue
        alg: Counter = Counter()
        yon: Counter = Counter()
        for r in rs:
            alg.update(r[kip]["algoritma"])
            yon.update(r[kip]["yontem"])
        ozet[kip] = {
            "ikili": len(rs),
            "tespit": sum(r[kip]["toplam"] for r in rs),
            "api_disi_tespit": sum(r[kip]["api_disi"] for r in rs),
            "api_disi_ikili": sum(1 for r in rs if r[kip]["api_disi"]),
            "yontem": dict(yon),
            "en_cok_algoritma": dict(alg.most_common(25)),
        }
    ozet["kapi_acik_ikili"] = sorted(r["anahtar"] for r in kayitlar if r.get("kapi_acik"))
    return ozet


def cmd_muh(a: argparse.Namespace) -> int:
    print("karadul:", karadul_denetle())
    isler = _isler(a)
    t0 = time.monotonic()
    kayitlar = _havuz(muh_bir, isler, a.paralel, a.zorla)
    return _yaz(a, "muh", kayitlar, _muh_ozet(kayitlar), t0)


# ---------------------------------------------------------------------------
# formul: formül çıkarıcı (MUH-12)
# ---------------------------------------------------------------------------

def _algoritmalar(ws: Path) -> list:
    """Kayıtlı ``algorithms.json`` + ``engineering_algorithms.json`` → ``AlgorithmMatch`` listesi
    (ürünün ``collect_algorithm_list`` sırasıyla)."""
    from karadul.reconstruction.c_algorithm_id import AlgorithmMatch
    out = []
    for ad in ("algorithms.json", "engineering_algorithms.json"):
        for a in (_json(ws / "reconstructed" / ad) or {}).get("algorithms", []) or []:
            out.append(AlgorithmMatch(
                name=a.get("name", ""), category=a.get("category", ""),
                confidence=float(a.get("confidence", 0.0) or 0.0),
                detection_method=a.get("detection_method", a.get("method", "")),
                evidence=list(a.get("evidence", []) or []),
                function_name=a.get("function_name", a.get("function", "")),
                address=a.get("address", "")))
    return out


def formul_bir(kosu: str, anahtar: str, ws: Path) -> dict:
    from karadul.reconstruction.engineering import FormulaReconstructor
    kayit: dict[str, Any] = {"kosu": kosu, "anahtar": anahtar}
    algos = _algoritmalar(ws)
    fr = FormulaReconstructor()
    formuller = fr.reconstruct(algos)
    kayitli = _json(ws / "reconstructed" / "engineering_analysis.json")
    kayit["kayitli_formul"] = None if kayitli is None else kayitli.get("total_formulas")
    kayit["formul"] = [
        {"algoritma": f.algorithm,
         "kaynak": [a.name for a in algos if fr._match_template(a.name) is not None
                    and FormulaReconstructor._match_template(a.name)
                    == FormulaReconstructor._match_template(f.algorithm)][:3],
         "fonksiyon": list(getattr(f, "functions", []) or [])[:3],
         "ascii_bos": not bool(f.ascii)}
        for f in formuller]
    kayit["durum"] = "calisti"
    return kayit


def cmd_formul(a: argparse.Namespace) -> int:
    print("karadul:", karadul_denetle())
    t0 = time.monotonic()
    kayitlar = _havuz(formul_bir, _isler(a), a.paralel)
    ad: Counter = Counter()
    for r in kayitlar:
        ad.update(f["algoritma"] for f in r.get("formul", []))
    ozet = {"ikili": len(kayitlar),
            "formul": sum(len(r.get("formul", [])) for r in kayitlar),
            "formullu_ikili": sum(1 for r in kayitlar if r.get("formul")),
            "kayitli_ile_ayni": sum(1 for r in kayitlar
                                    if r.get("kayitli_formul") == len(r.get("formul", []))),
            "kayitli_var": sum(1 for r in kayitlar if r.get("kayitli_formul") is not None),
            "algoritma": dict(ad.most_common())}
    return _yaz(a, "formul", kayitlar, ozet, t0)


# ---------------------------------------------------------------------------
# ortak yazım
# ---------------------------------------------------------------------------

def _yaz(a: argparse.Namespace, ad: str, kayitlar: list[dict], ozet: dict, t0: float) -> int:
    hedef = a.cikti / a.etiket
    hedef.mkdir(parents=True, exist_ok=True)
    hatali = [f"{r['kosu']}:{r['anahtar']} {r.get('durum')}" for r in kayitlar
              if r.get("durum") != "calisti"]
    belge = {"etiket": a.etiket, "agac": str(DEPO), "ikili": len(kayitlar), "hatali": hatali,
             "sure_sn": round(time.monotonic() - t0, 1), "ozet": ozet, "kayitlar": kayitlar}
    (hedef / f"{ad}.json").write_text(json.dumps(belge, ensure_ascii=False, indent=1),
                                      encoding="utf-8")
    print(json.dumps({k: v for k, v in belge.items() if k != "kayitlar"},
                     ensure_ascii=False, indent=1)[:6000])
    return 1 if hatali else 0


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("komut", choices=["muh", "formul"])
    ap.add_argument("--etiket", required=True)
    ap.add_argument("--kosu", action="append", choices=sorted(KOSULAR))
    ap.add_argument("--ws", action="append")
    ap.add_argument("--yalniz", action="append", help="anahtarda geçen alt dizgi (süzgeç)")
    ap.add_argument("--zorla", action="store_true", help="muh: kapı zorla açık kipini de koş")
    ap.add_argument("--paralel", type=int, default=6)
    ap.add_argument("--cikti", type=Path, default=CIKTI)
    a = ap.parse_args(argv)
    return {"muh": cmd_muh, "formul": cmd_formul}[a.komut](a)


if __name__ == "__main__":
    raise SystemExit(main())
