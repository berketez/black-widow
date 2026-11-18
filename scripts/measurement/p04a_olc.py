#!/usr/bin/env python3
"""P04a ölçümü: bileşim şablonu (MUH-03), alan sınıflandırıcı (MUH-04), blok yorumu (MUH-07).

Ghidra'sız; kayıtlı koşu yapıtlarını ölçülen ağacın koduyla yeniden oynatır.
Worktree kökünden ``python scripts/measurement/p04a_olc.py <alt komut> ...``.

Alt komutlar
------------
``bilesim``  Bileşim çözümleyicisini masum kapının ``bilesim_yeniden`` katmanıyla aynı girdilerle
             koşar (çağrı çizgesi, ``algorithms.json`` + ``engineering_algorithms.json``,
             ``data_flow/data_flow.json``, ``dispatch_resolution.json``) ve raporlanan şablonu,
             bekleyen şablonu (gerekçesiyle) ve genel çağrı zinciri bileşimini ayrı sayar.
             ``--kosu`` ``urun_kos`` düzenindeki koşu kökü; ``--ws`` tek bir çalışma dizini
             (ör. CalculiX ``workspaces/ccx_2/<tarih>``).
``alan``     ``DomainClassifier.classify``'ı kayıtlı ``engineering_analysis.json``'daki
             tespitlerle (ürünün verdiği aynı listeyle) yeniden koşar; seçilen alanları ve
             "yalnız string_hint kanıtlı alan seçildi" sayısını verir.
``blok``     ``CodeBlockAnnotator._detect_assembly_ops``'u kayıtlı ``reconstructed/annotated/*.c``
             dosyalarında (yorumcunun eklediği ``// --- … ---`` satırları atılarak = yorumcunun
             girdisi) koşar ve betim başına yorum sayısını verir; ürün çıktısındaki
             (``out/src``) sayımı yanında yazar (eski ağaçla ikisi aynı olmalı).
``alan`` ``--alan-kip urun|yama``: ürünün bugünkü çağrısı ya da önerilen yamanınki.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

DEPO = Path(__file__).resolve().parents[2]
if str(DEPO) not in sys.path:
    sys.path.insert(0, str(DEPO))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from masum_kapi import kosu_ikilileri  # noqa: E402  (salt okuma: koşu düzeni)


def _json(p: Path) -> Any:
    return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else None


def _ws_listesi(args: argparse.Namespace) -> list[tuple[str, Path, Path | None]]:
    """(anahtar, ws, out) listesi."""
    sonuc: list[tuple[str, Path, Path | None]] = []
    for kok in args.kosu or []:
        for anahtar, ws, out, _bitti in kosu_ikilileri(Path(kok).expanduser()):
            sonuc.append((f"{Path(kok).name}:{anahtar}", ws, out))
    for ws in args.ws or []:
        p = Path(ws).expanduser()
        sonuc.append((str(p), p, None))
    return sonuc


# ---------------------------------------------------------------------------
# bilesim
# ---------------------------------------------------------------------------

def _tespitleri_yeniden_uret(st: Path) -> list[dict]:
    """Ölçülen ağacın iki tespitçisini kayıtlı Ghidra çıktısında koşar (Ghidra'sız).

    Ürünün ``parallel_algo_eng`` adımıyla aynı çağrılar: ``CAlgorithmIdentifier.identify`` ve
    ``EngineeringAlgorithmAnalyzer.identify`` (``static/ghidra_output/decompiled`` +
    ``ghidra_functions.json`` [+ ``ghidra_strings.json``]).
    """
    from karadul.config import Config
    from karadul.reconstruction.c_algorithm_id import CAlgorithmIdentifier
    from karadul.reconstruction.engineering import EngineeringAlgorithmAnalyzer
    dec = st / "ghidra_output/decompiled"
    c = CAlgorithmIdentifier(Config.load(None)).identify(
        dec, st / "ghidra_functions.json", st / "ghidra_strings.json")
    e = EngineeringAlgorithmAnalyzer().identify(dec, st / "ghidra_functions.json")
    out = []
    for res in (c, e):
        if res and getattr(res, "success", False):
            out.extend(a.to_dict() for a in res.algorithms)
    return out


def bilesim_bir(ws: Path, tespit_yeniden: bool = False) -> dict:
    """Tek çalışma dizininde bileşim yeniden oynatması (masum kapının girdileriyle).

    ``tespit_yeniden``: algoritma listesi kayıtlı JSON'dan değil, ölçülen ağacın
    tespitçilerinden (``_tespitleri_yeniden_uret``) gelir.
    """
    from karadul.reconstruction.engineering import AlgorithmCompositionAnalyzer
    from karadul.reconstruction.engineering.composition_analyzer import KNOWN_COMPOSITIONS
    sablonlar = {t["name_template"] for t in KNOWN_COMPOSITIONS.values()}
    r, st = ws / "reconstructed", ws / "static"
    cg_yol = None
    genis = sorted(r.glob("*augmented*")) + sorted(st.glob("*augmented*"))
    for aday in genis + [st / "ghidra_call_graph.json"]:
        if aday.is_file():
            cg_yol = aday
            break
    if tespit_yeniden:
        if cg_yol is None or not (st / "ghidra_output/decompiled").is_dir():
            return {"durum": "yapit_yok"}
        algos = _tespitleri_yeniden_uret(st)
    else:
        if cg_yol is None or not (r / "algorithms.json").is_file():
            return {"durum": "yapit_yok"}
        algos = ((_json(r / "algorithms.json") or {}).get("algorithms", [])
                 + (_json(r / "engineering_algorithms.json") or {}).get("algorithms", []))
    t0 = time.monotonic()
    sonuc = AlgorithmCompositionAnalyzer().analyze(
        call_graph=_json(cg_yol), algorithms=algos,
        data_flow=_json(r / "data_flow/data_flow.json"),
        dispatch_result=_json(r / "dispatch_resolution.json"))
    sure = time.monotonic() - t0
    raporlanan = [c for c in sonuc.compositions if c.name in sablonlar]
    genel = [c for c in sonuc.compositions if c.name not in sablonlar]
    bekleyen = list(getattr(sonuc, "pending_compositions", []) or [])
    return {
        "durum": "calisti" if sonuc.success else "hata",
        "sure_sn": round(sure, 2),
        "algoritma": len(algos),
        "raporlanan_sablon": [
            {"ad": c.name, "guven": c.confidence,
             "asamalar": [(s.name, s.functions[:3], s.algorithms[:3]) for s in c.stages],
             "kapi": getattr(c, "evidence_gate", None)}  # eski ağaçta alan yok
            for c in raporlanan],
        "bekleyen_sablon": [
            {"ad": c.name, "neden": (getattr(c, "evidence_gate", None) or {}).get("reason", "")}
            for c in bekleyen],
        "genel_bilesim": len(genel),
        "hatalar": sonuc.errors,
    }


def cmd_bilesim(args: argparse.Namespace) -> int:
    kayitlar = {}
    for anahtar, ws, _out in _ws_listesi(args):
        kayitlar[anahtar] = bilesim_bir(ws, tespit_yeniden=args.tespit_yeniden)
    rap = Counter()
    bek = Counter()
    neden = Counter()
    rap_ikili = defaultdict(set)
    for k, v in kayitlar.items():
        for c in v.get("raporlanan_sablon", []):
            rap[c["ad"]] += 1
            rap_ikili[c["ad"]].add(k)
        for c in v.get("bekleyen_sablon", []):
            bek[c["ad"]] += 1
            neden[c["neden"].split(":")[0]] += 1
    ozet = {
        "ikili": len(kayitlar),
        "durum": dict(Counter(v["durum"] for v in kayitlar.values())),
        "raporlanan_sablon_toplam": sum(rap.values()),
        "raporlanan_sablonlu_ikili": sum(1 for v in kayitlar.values()
                                         if v.get("raporlanan_sablon")),
        "raporlanan_sablon": dict(rap.most_common()),
        "bekleyen_sablon_toplam": sum(bek.values()),
        "bekleyen_sablon": dict(bek.most_common()),
        "bekleme_nedeni": dict(neden.most_common()),
        "genel_bilesim_toplam": sum(v.get("genel_bilesim", 0) for v in kayitlar.values()),
    }
    _yaz(args, "bilesim", ozet, kayitlar)
    return 0


# ---------------------------------------------------------------------------
# alan
# ---------------------------------------------------------------------------

def _fonksiyon_dizgileri(st: Path) -> dict[str, list[str]] | None:
    """``ghidra_xrefs.json`` → fonksiyon adı → referans verdiği dizgiler (``strings_used``)."""
    x = _json(st / "ghidra_xrefs.json")
    if not x:
        return None
    out: dict[str, list[str]] = {}
    for v in (x.get("function_xrefs") or {}).values():
        out[v.get("name", "")] = [s.get("value", "") for s in v.get("strings_used") or []]
    return out


def alan_bir(ws: Path, kip: str) -> dict:
    """``engineering_analysis.json``'daki sınıflandırmayı ölçülen ağaçla yeniden üretir.

    Ürün (``pipeline/steps/engineering_analysis.py``): ``classify(algorithms=algo_result +
    eng_result, strings=normalize_strings(strings_data), binary_hints=
    collect_binary_hints(functions_data, static_dir))``. Burada tespitler kayıtlı
    ``algorithms.json`` + ``engineering_algorithms.json``'dan (AlgorithmMatch nesnesi olarak),
    dizgiler ``static/ghidra_strings.json``'dan, ipucu ``ghidra_functions.json`` +
    ``dynamic_libraries.json``'dan gelir.

    ``kip``: ``urun`` = ürünün bugünkü çağrısı (düz dizgi listesi); ``yama`` = önerilen
    yamanın çağrısı (``function_strings`` = ``ghidra_xrefs.json`` ``strings_used``).
    """
    from karadul.pipeline.steps._engineering_helpers import (
        collect_binary_hints,
        normalize_strings,
    )
    from karadul.reconstruction.c_algorithm_id import AlgorithmMatch
    from karadul.reconstruction.engineering.domain_classifier import DomainClassifier
    r, st = ws / "reconstructed", ws / "static"
    kayit = _json(r / "engineering_analysis.json")
    if kayit is None:
        return {"durum": "yapit_yok"}
    ham = ((_json(r / "algorithms.json") or {}).get("algorithms", [])
           + (_json(r / "engineering_algorithms.json") or {}).get("algorithms", []))
    algos = [AlgorithmMatch(
        name=a.get("name", ""), category=a.get("category", ""),
        confidence=float(a.get("confidence", 0.0) or 0.0),
        detection_method=a.get("detection_method", ""), evidence=a.get("evidence", []) or [],
        function_name=a.get("function_name") or a.get("function") or "",
        address=a.get("address", "")) for a in ham]
    dizgiler = normalize_strings(_json(st / "ghidra_strings.json"))
    ipucu = collect_binary_hints(_json(st / "ghidra_functions.json"), st)
    kw: dict[str, Any] = {"algorithms": algos, "strings": dizgiler, "binary_hints": ipucu}
    if kip == "yama":
        fs = _fonksiyon_dizgileri(st)
        if fs is None:
            return {"durum": "yapit_yok", "neden": "ghidra_xrefs.json yok"}
        kw["function_strings"] = fs
    import inspect
    if "function_strings" in kw and "function_strings" not in inspect.signature(
            DomainClassifier.classify).parameters:
        return {"durum": "uygulanmaz", "neden": "eski ağaçta function_strings yok"}
    rapor = DomainClassifier().classify(**kw)
    sec = Counter(c.primary_domain for c in rapor.classifications)
    yalniz_dizgi = 0
    ornek = []
    for c in rapor.classifications:
        # dizgi dışı kanıtın alanları: "category:x->DOMAIN", "category:x->cross[...]",
        # "name_hint:'k'->DOMAIN", "binary_override:DOMAIN"
        guclu = set()
        for e in c.evidence:
            if e.startswith("category:") and "->cross" in e:
                guclu.update(re.findall(r"'(\w+)'", e.split("->cross", 1)[1].split(")")[0]))
            elif e.startswith("category:") or e.startswith("name_hint:"):
                guclu.add(e.split("->", 1)[1].split(" ")[0])
            elif e.startswith("binary_override:"):
                guclu.add(e.split(":", 1)[1].split(" ")[0])
        if c.primary_domain not in guclu:
            yalniz_dizgi += 1
            if len(ornek) < 3:
                ornek.append({"f": c.function_name, "alan": c.primary_domain,
                              "skor": c.domain_scores, "kanit": c.evidence[:4]})
    kay_list = (kayit.get("domain_classification") or {}).get("classifications", []) or []
    kayitli = Counter(x.get("primary_domain") for x in kay_list)
    ornekler = {c.function_name: c.primary_domain for c in rapor.classifications
                if c.function_name in {"ACLHashPassword"}}
    return {"durum": "calisti", "siniflandirma": len(rapor.classifications),
            "secilen": dict(sec), "kayitli_secilen": dict(kayitli),
            "kanitsiz_alan_secildi": yalniz_dizgi, "ornek": ornek, "izlenen": ornekler}


def cmd_alan(args: argparse.Namespace) -> int:
    kayitlar = {anahtar: alan_bir(ws, args.alan_kip) for anahtar, ws, _o in _ws_listesi(args)}
    sec = Counter()
    kay = Counter()
    for v in kayitlar.values():
        sec.update(v.get("secilen", {}))
        kay.update(v.get("kayitli_secilen", {}))
    ozet = {"ikili": len(kayitlar),
            "durum": dict(Counter(v["durum"] for v in kayitlar.values())),
            "siniflandirma": sum(v.get("siniflandirma", 0) for v in kayitlar.values()),
            "secilen": dict(sec.most_common()), "kayitli_secilen": dict(kay.most_common()),
            "kanitsiz_alan_secildi": sum(v.get("kanitsiz_alan_secildi", 0)
                                          for v in kayitlar.values())}
    _yaz(args, "alan", ozet, kayitlar)
    return 0


# ---------------------------------------------------------------------------
# blok
# ---------------------------------------------------------------------------

_BLOK_YORUM_SATIRI = re.compile(r"^\s*// --- .* ---\s*$")
_URUN_BLOK = re.compile(r"^\s*// --- ([^:\n]{3,60}):", re.M)


def blok_bir(ws: Path, out: Path | None) -> dict:
    """Assembly dedektörünün (``_detect_assembly_ops``) yeniden oynatması.

    Girdi: blok yorumcusunun kayıtlı çıktısı ``reconstructed/annotated/*.c``; yorumcunun
    eklediği ``// --- … ---`` satırları atılınca geriye yorumcunun girdisi kalır (yorumcu
    yalnız yorum satırı ekler). Dedektör satır satır çalıştığı ve bağlam olarak yalnız
    alanı (ürün ``domain_report`` geçirmiyor → None) kullandığı için dosyanın bütün
    satırları tek seferde verilir. Ürün çıktısındaki (``out/src``) yorum sayısı yanında
    yazılır: eski ağaçla yeniden oynatma onunla aynı olmalı.
    """
    from karadul.reconstruction.engineering import block_annotator as ba
    girdi = ws / "reconstructed/annotated"
    if not girdi.is_dir():
        return {"durum": "yapit_yok"}
    an = ba.CodeBlockAnnotator(None)
    func_meta = an._load_json(ws / "static/ghidra_functions.json", [])
    sayac: Counter = Counter()
    ornek: dict[str, list] = defaultdict(list)
    for f in sorted(girdi.glob("*.c")):
        icerik = "\n".join(s for s in f.read_text(encoding="utf-8", errors="replace").splitlines()
                           if not _BLOK_YORUM_SATIRI.match(s))
        anlar = []
        # ürünle aynı: yalnız _extract_functions'ın çıkardığı gövdeler taranır
        for fn, govde, bas, _adr in an._extract_functions(icerik, func_meta, f.stem):
            anlar.extend(an._detect_assembly_ops(govde.splitlines(), fn, None, bas))
        for ann in anlar:
            m = _URUN_BLOK.match(ann.text)
            betim = m.group(1).strip() if m else ann.text.strip()
            sayac[betim] += 1
            if len(ornek[betim]) < 2:
                ornek[betim].append(f"{f.stem}: {ann.text.strip()[:90]}")
    urun: Counter = Counter()
    if out is not None and (out / "src").is_dir():
        for f in (out / "src").rglob("*.c"):
            for m in _URUN_BLOK.finditer(f.read_text(encoding="utf-8", errors="replace")):
                urun[m.group(1).strip()] += 1
    return {"durum": "calisti", "yeniden": dict(sayac), "urun_out_src": dict(urun),
            "ornek": dict(ornek)}


def cmd_blok(args: argparse.Namespace) -> int:
    kayitlar = {anahtar: blok_bir(ws, out) for anahtar, ws, out in _ws_listesi(args)}
    yen = Counter()
    urun = Counter()
    yen_ikili = Counter()
    for v in kayitlar.values():
        yen.update(v.get("yeniden", {}))
        urun.update(v.get("urun_out_src", {}))
        for b in v.get("yeniden", {}):
            yen_ikili[b] += 1
    ozet = {"ikili": len(kayitlar),
            "durum": dict(Counter(v["durum"] for v in kayitlar.values())),
            "yeniden_yorum": dict(yen.most_common()),
            "yeniden_ikili": dict(yen_ikili.most_common()),
            "urun_out_src_yorum": dict(urun.most_common())}
    _yaz(args, "blok", ozet, kayitlar)
    return 0


# ---------------------------------------------------------------------------

def _yaz(args: argparse.Namespace, ad: str, ozet: dict, kayitlar: dict) -> None:
    print(json.dumps(ozet, ensure_ascii=False, indent=1))
    if args.cikti:
        d = Path(args.cikti).expanduser()
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{ad}_ozet.json").write_text(
            json.dumps(ozet, ensure_ascii=False, indent=1), encoding="utf-8")
        (d / f"{ad}.json").write_text(
            json.dumps(kayitlar, ensure_ascii=False, indent=1, default=str), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("komut", choices=["bilesim", "alan", "blok"])
    ap.add_argument("--kosu", action="append", help="urun_kos düzeninde koşu kökü (tekrarlanabilir)")
    ap.add_argument("--ws", action="append", help="tek çalışma dizini (tekrarlanabilir)")
    ap.add_argument("--cikti", default=None, help="<komut>.json ve <komut>_ozet.json buraya")
    ap.add_argument("--alan-kip", choices=["urun", "yama"], default="urun",
                    help="alan: urun = bugünkü çağrı (düz dizgi), yama = function_strings")
    ap.add_argument("--tespit-yeniden", action="store_true",
                    help="bilesim: algoritma tespitlerini ölçülen ağaçla yeniden üret")
    args = ap.parse_args(argv)
    if not (args.kosu or args.ws):
        ap.error("--kosu ya da --ws gerekli")
    import karadul
    if not Path(karadul.__file__).resolve().is_relative_to(DEPO):
        print(f"[p04a] yanlış ağaç yüklendi: {karadul.__file__}", file=sys.stderr)
        return 2
    return {"bilesim": cmd_bilesim, "alan": cmd_alan, "blok": cmd_blok}[args.komut](args)


if __name__ == "__main__":
    sys.exit(main())
