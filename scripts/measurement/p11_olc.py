#!/usr/bin/env python3
"""P11 ölçümü: hesaplama kolları (MaxSMT, CFG-iso, füzyon). Ön kayıt: ``docs/arge/2026-11-18_onarim/P11_on_kayit.md``.

Ürün kodu ``--agac`` ağacından yüklenir (``sys.path``'in başına eklenir); böylece aynı betik taban
(dondurulmuş kopya) ve onarılmış ağaçla koşar. Çıktıda ad geçmez, yalnız sayılar (fonksiyon adı
yalnız ``--ornek`` dosyasına, okuma için).

Alt komutlar
------------
``maxsmt``
    P-code (``pcode.jsonl``) üstünde erişim çıkarımı. M1: LOAD/STORE'da eski kuralın ("ilk sabit
    girdi") ofseti ``input0``'dan (adres alanı kimliği) alma oranı. M2/M3: kök varnode'u DWARF'ta
    yapı işaretçisi olan parametrenin giriş yazmacı olan erişimlerin DWARF yerleşimine göre hükmü
    (B1 sınır içi, B2 üye başlangıcı, B3 B2 + genişlik üye aralığında). Adres eşlemesi hizalama
    belgesinin ``pie_tabani``'ndan, yapı yerleşimi T0c DWARF belgesinden.
``cfg``
    CFG-iso: blok komut dökümü denetimi (C1), öntanımlı bankayla eşleşme (C2), gerçek koddan
    şablon fizibilitesi (C3).
``imza``
    İmza eşleşmesi yöntemi başına GT kesinliği (Ghidra'nın adsız bıraktığı fonksiyonlarda; F2).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Optional

ARAC = "p11_olc/1"
DEPO = Path(__file__).resolve().parents[2]
AARCH64_X0 = 0x4000          # Ghidra AArch64: x0 = register 0x4000, xk = 0x4000 + 8k
ARGUMAN_YAZMACI = 8          # x0–x7


def _agac_yukle(agac: Path) -> str:
    sys.path.insert(0, str(agac.resolve()))
    import karadul  # noqa: F401
    yol = str(Path(karadul.__file__).resolve())
    if not yol.startswith(str(agac.resolve())):
        raise SystemExit(f"karadul {yol}'dan yükleniyor, {agac} DEĞİL")
    return yol


def _json(yol: Path) -> Any:
    return json.loads(Path(yol).read_text(encoding="utf-8"))


def _kosu_ws(kosu: Path, ikili: str) -> Optional[Path]:
    """``<kosu>/debian/<program>/<ikili>/ws/workspaces/<ikili>/<zaman>`` (tek)."""
    adaylar = sorted(kosu.glob(f"debian/*/{ikili}/ws/workspaces/*/*/static"))
    return adaylar[0].parent if len(adaylar) == 1 else None


# --------------------------------------------------------------------------- MaxSMT

def _eski_kural_input0(pcode: Path) -> Counter:
    """Taban kuralı: LOAD/STORE girdilerindeki ilk sabit (0 ≤ x < 4096) ofset sayılırdı."""
    c: Counter = Counter()
    for satir in pcode.open(encoding="utf-8"):
        r = json.loads(satir)
        for op in r.get("ops", []):
            if op[0] not in ("LOAD", "STORE"):
                continue
            c["erisim"] += 1
            for j, g in enumerate(op[2]):
                if g[0] == 2 and 0 <= int(g[1]) < 4096:
                    c["ofset_input0" if j == 0 else "ofset_baska"] += 1
                    if j == 0 and int(g[1]) == 433:
                        c["ofset_433"] += 1
                    break
            else:
                c["ofsetsiz"] += 1
    return c


def _yapi_yerlesimi(yapi: dict) -> tuple[int, list[tuple[int, int]]]:
    """(sizeof, [(üye ofseti, üye aralığı)]); aralık = sonraki farklı ofset − ofset (son üyede sizeof)."""
    boyut = int(yapi.get("boyut") or 0)
    ofsetler = sorted({int(u["ofset"]) for u in yapi.get("uyeler", []) if u.get("ofset") is not None})
    uyeler = []
    for i, o in enumerate(ofsetler):
        son = ofsetler[i + 1] if i + 1 < len(ofsetler) else boyut
        uyeler.append((o, max(0, son - o)))
    return boyut, uyeler


def _hukum(ofset: int, genislik: int, boyut: int, uyeler: list[tuple[int, int]]) -> dict[str, bool]:
    b1 = 0 <= ofset and ofset + genislik <= boyut
    aralik = dict(uyeler)
    b2 = ofset in aralik
    b3 = b2 and genislik <= aralik[ofset]
    return {"B1": b1, "B2": b2, "B3": b3}


def _dwarf_yapi_parametreleri(dwarf: dict, pie: int) -> dict[int, dict[int, tuple[int, list]]]:
    """{ghidra giriş adresi: {argüman yazmacı ofseti: (sizeof, üyeler)}} — yalnız ``yapi*`` parametreler."""
    yapilar = dwarf.get("yapilar", {})
    sonuc: dict[int, dict[int, tuple[int, list]]] = {}
    for f in dwarf.get("fonksiyonlar", []):
        if not f.get("adres"):
            continue
        g = int(f["adres"], 16) + pie
        for p in f.get("parametreler", []):
            tip = p.get("tip") or {}
            giris = p.get("giris") or {}
            if tip.get("sinif") != "yapi*" or p.get("tekrar"):
                continue
            if giris.get("tur") != "yazmac" or not giris.get("arguman"):
                continue
            yaz = str(giris.get("yazmac", ""))
            if not yaz.startswith("x"):
                continue
            k = int(yaz[1:])
            if k >= ARGUMAN_YAZMACI:
                continue
            kok = (tip.get("kok") or {}).get("konum")
            yapi = yapilar.get(kok)
            if not yapi or yapi.get("bildirim") or not yapi.get("boyut"):
                continue
            sonuc.setdefault(g, {})[AARCH64_X0 + 8 * k] = _yapi_yerlesimi(yapi)
    return sonuc


def maxsmt_ikili(pcode: Path, dwarf: dict, pie: int, coz: bool) -> dict[str, Any]:
    from karadul.analyzers.pcode_analyzer import PcodeAnalyzer
    mod = __import__("karadul.pipeline.steps.computation_struct_recovery", fromlist=["x"])
    sonuc: dict[str, Any] = {"eski_kural": dict(_eski_kural_input0(pcode))}
    pres = PcodeAnalyzer().analyze_streaming(pcode)
    yapi_param = _dwarf_yapi_parametreleri(dwarf, pie)
    sonuc["dwarf_yapi_parametresi"] = sum(len(v) for v in yapi_param.values())
    fn_adres = {f.name or f.address: int(f.address, 16) for f in pres.functions}
    if not hasattr(mod, "extract_struct_accesses"):
        # Taban: kök kimliği yok (fonksiyon başına ``<fn>_var_<ofset>``); M2 hesaplanamaz.
        per_fn = mod._extract_accesses_per_function(pres)
        ofs = Counter(a.offset for v in per_fn.values() for a in v)
        sonuc["kabul"] = sum(ofs.values())
        sonuc["ofset_433"] = ofs.get(433, 0)
        sonuc["m2"] = None
        return sonuc
    ex = mod.extract_struct_accesses(pres)
    sonuc["erisim_sayimi"] = dict(ex.counts)
    sonuc["kabul"] = ex.counts.get("kabul", 0)
    sonuc["ofset_433"] = sum(1 for v in ex.per_function.values() for a in v if a.offset == 433)
    tekil: dict[tuple, dict[str, bool]] = {}
    kapsanan: set = set()
    for fn_key, erisimler in ex.per_function.items():
        for a in erisimler:
            b = ex.bases[a.var_name]
            if b["definition"] != "in" or b["space"] != "register":
                continue
            g = int(b["function_address"], 16)
            yer = yapi_param.get(g, {}).get(b["offset"])
            if yer is None or b["size"] != 8:
                continue
            anahtar = (g, b["offset"], a.offset, a.width)
            tekil[anahtar] = _hukum(a.offset, a.width, *yer)
            kapsanan.add((g, b["offset"]))
    sonuc["m2"] = {"tekil": len(tekil), **{h: sum(1 for v in tekil.values() if v[h]) for h in ("B1", "B2", "B3")},
                   "kapsanan_parametre": len(kapsanan)}
    if coz:
        sonuc["m3"] = _coz(ex, yapi_param)
    return sonuc


def _coz(ex: Any, yapi_param: dict) -> dict[str, Any]:
    """Fonksiyon başına sıralı Z3 çözümü; DWARF parametre ailesinin aday alanlarını hükme bağla."""
    from karadul.computation.config import ComputationConfig
    from karadul.computation.struct_recovery import StructLayoutSolver
    cfg = ComputationConfig(enable_computation_struct_recovery=True, enable_parallel_solve=False,
                            struct_solver_timeout=10.0)
    s = {"fonksiyon": 0, "alan": 0, "B1": 0, "B2": 0, "B3": 0, "sure_sn": 0.0, "zaman_asimi_yok": True}
    t0 = time.monotonic()
    for fn_key, erisimler in ex.per_function.items():
        ilgili = {}
        for a in erisimler:
            b = ex.bases[a.var_name]
            if b["definition"] == "in" and b["space"] == "register" and b["size"] == 8:
                yer = yapi_param.get(int(b["function_address"], 16), {}).get(b["offset"])
                if yer is not None:
                    ilgili[a.var_name] = yer
        if not ilgili:
            continue
        sonuc = StructLayoutSolver(cfg).solve_from_raw(accesses=erisimler, max_time_seconds=10.0)
        s["fonksiyon"] += 1
        aile = {v: c.type_family for c in sonuc.classes for v in c.variables}
        for var, yer in ilgili.items():
            aday = sonuc.assigned_structs.get(aile.get(var))
            for f in getattr(aday, "fields", []) or []:
                h = _hukum(f.offset, f.size, *yer)
                s["alan"] += 1
                for k in ("B1", "B2", "B3"):
                    s[k] += int(h[k])
    s["sure_sn"] = round(time.monotonic() - t0, 1)
    return s


def maxsmt(a: argparse.Namespace) -> int:
    karadul_yolu = _agac_yukle(a.agac)
    hizalama = Path(a.hizalama).expanduser()
    dwarf_kok = Path(a.dwarf).expanduser()
    kosu = Path(a.kosu).expanduser()
    ikililer: dict[str, Any] = {}
    atlanan: dict[str, str] = {}
    for hz in sorted(hizalama.glob("*.json")):
        if hz.name == "hizalama_indeksi.json":
            continue
        ikili = hz.stem
        doc = _json(hz)
        ws = _kosu_ws(kosu, ikili)
        if ws is None:
            atlanan[ikili] = "koşu yok"
            continue
        hedef = _json(ws / "raw" / "target_info.json")
        if hedef.get("file_hash") != doc["girdi"].get("ghidra_ikili_sha256"):
            atlanan[ikili] = "sha256 tutmadı"
            continue
        dw = sorted(dwarf_kok.glob(f"*/{ikili}.json"))
        if len(dw) != 1:
            atlanan[ikili] = f"DWARF belgesi {len(dw)}"
            continue
        pie = int(doc["pie_tabani"]["secilen"])
        pcode = ws / "static" / "ghidra_output" / "pcode.jsonl"
        ikililer[ikili] = maxsmt_ikili(pcode, _json(dw[0]), pie, a.coz)
    toplam: dict[str, Any] = {"ikili": len(ikililer)}
    for k in ("kabul", "ofset_433"):
        toplam[k] = sum(v.get(k) or 0 for v in ikililer.values())
    eski = Counter()
    for v in ikililer.values():
        eski.update(v["eski_kural"])
    toplam["eski_kural"] = dict(eski)
    toplam["dwarf_yapi_parametresi"] = sum(v["dwarf_yapi_parametresi"] for v in ikililer.values())
    if all(v.get("m2") is not None for v in ikililer.values()) and ikililer:
        m2 = Counter()
        sayim = Counter()
        for v in ikililer.values():
            m2.update(v["m2"])
            sayim.update(v.get("erisim_sayimi", {}))
        toplam["m2"] = dict(m2)
        toplam["m2_oran"] = {h: (round(m2[h] / m2["tekil"], 4) if m2["tekil"] else None) for h in ("B1", "B2", "B3")}
        toplam["erisim_sayimi"] = dict(sayim)
        if a.coz:
            m3 = Counter()
            for v in ikililer.values():
                m3.update({k: v["m3"][k] for k in ("fonksiyon", "alan", "B1", "B2", "B3", "sure_sn")})
            toplam["m3"] = dict(m3)
            toplam["m3_oran"] = {h: (round(m3[h] / m3["alan"], 4) if m3["alan"] else None) for h in ("B1", "B2", "B3")}
    belge = {"arac": ARAC, "karadul": karadul_yolu, "etiket": a.etiket, "toplam": toplam,
             "ikililer": ikililer, "atlanan": atlanan}
    cikti = Path(a.cikti).expanduser()
    cikti.mkdir(parents=True, exist_ok=True)
    (cikti / f"maxsmt_{a.etiket}.json").write_text(json.dumps(belge, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps(toplam, ensure_ascii=False, indent=1))
    return 0


# --------------------------------------------------------------------------- GT yardımcıları

def _ks1():
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import ks1_olc  # noqa: E402
    return ks1_olc


def _gt_haritalari(kosu: Path, indir: Path) -> dict[str, Any]:
    """{ikili: (Elf, GtBirimi | hata metni)} — Debian koşu kökünden (``<kosu>/debian``)."""
    ks1 = _ks1()
    out: dict[str, Any] = {}
    for e in ks1.debian_elfleri(kosu / "debian"):
        if e.static is None:
            continue
        try:
            out[e.ad] = (e, ks1.gt_elf(e, indir))
        except Exception as exc:  # GT kurulamadı: ölçüm dışı, nedeniyle
            out[e.ad] = (e, f"{type(exc).__name__}: {exc}")
    return out


def _wilson_alt(k: int, n: int) -> Optional[float]:
    if n == 0:
        return None
    return _ks1().oran(k, n)["aralik"][0]


# --------------------------------------------------------------------------- CFG-iso

def cfg(a: argparse.Namespace) -> int:
    """C1 döküm tutarlılığı, C2 öntanımlı bankayla eşleşme, C3 gerçek koddan şablon (A → B)."""
    karadul_yolu = _agac_yukle(a.agac)
    from karadul.computation.cfg_iso import HybridCFGMatcher, default_template_bank
    from karadul.computation.cfg_iso.template_db import AlgorithmTemplate
    from karadul.config import ComputationRecoveryConfig
    from karadul.pipeline.steps import cfg_iso_match as cim
    ks1 = _ks1()
    kosu = Path(a.kosu).expanduser()
    cikti = Path(a.cikti).expanduser()
    gt = _gt_haritalari(kosu, Path(a.indir).expanduser())
    belge: dict[str, Any] = {"arac": ARAC, "karadul": karadul_yolu, "kosu": str(kosu),
                             "c1": {}, "c2": {}, "c3": {}}
    crc = ComputationRecoveryConfig()
    banka = default_template_bank()
    dugum = cim.template_node_histograms(banka)
    varsayilan = HybridCFGMatcher(crc, banka)
    fonksiyonlar: dict[str, list[dict]] = {}
    for ad, (e, _g) in sorted(gt.items()):
        veri = _json(Path(e.static) / "ghidra_output" / "cfg.json")
        fonksiyonlar[ad] = veri["functions"]
        c1: Counter = Counter()
        for f in veri["functions"]:
            for b in f.get("blocks", []):
                if int(b.get("instruction_count", 0) or 0) > 0:
                    c1["blok"] += 1
                    c1["dokum_tutarli"] += int(len(b.get("mnemonics") or []) == int(b["instruction_count"]))
        belge["c1"][ad] = dict(c1)
        c2: Counter = Counter()
        t0 = time.monotonic()
        for f in veri["functions"]:
            q = cim.attributed_cfg(f, None)
            if q is None or q.node_count() == 0:
                c2["dokumsuz"] += 1
                continue
            c2["sorgu"] += 1
            if not any(cim._hist_key(n.mnemonic_histogram) in dugum for n in q.nodes):
                continue
            c2["uyumlu"] += 1
            c2["lsh_adayli"] += int(bool(varsayilan.lsh_index.query(q, top_k=10)))
            c2["eslesen"] += int(bool(varsayilan.match(q)))
        c2["sure_sn"] = round(time.monotonic() - t0, 1)
        belge["c2"][ad] = dict(c2)
    for cift in a.cift:
        a_ad, b_ad = cift.split(":")
        (_ea, ga), (_eb, gb) = gt[a_ad], gt[b_ad]
        sablonlar, a_adlari = [], set()
        for f in fonksiyonlar[a_ad]:
            adlar = ga.adlar.get(int(f["address"], 16))
            if not adlar or len(f.get("blocks", [])) < a.en_az_blok:
                continue
            q = cim.attributed_cfg(f, None)
            ad = ks1.platform_adi(adlar[0], ks1.PLATFORM_DEBIAN)
            if a.klon_tabani:
                # Ürün adı derleyici ekini taşımaz (``.part.0`` geçerli C adı değil);
                # ks1 klon kuralı da klon GT'de taban adı bekler.
                ad = ks1.klon_tabani(ad) or ad
            if q is None or ad in a_adlari:
                continue
            a_adlari.add(ad)
            sablonlar.append(AlgorithmTemplate(name=ad, cfg=q, source="gercek_kod"))
        m = HybridCFGMatcher(crc, sablonlar)
        c3: Counter = Counter()
        ornek = []
        t0 = time.monotonic()
        for f in fonksiyonlar[b_ad]:
            if len(f.get("blocks", [])) < a.en_az_blok:
                continue
            q = cim.attributed_cfg(f, None)
            if q is None:
                continue
            adlar = gb.adlar.get(int(f["address"], 16)) or []
            c3["sorgu"] += 1
            ortak = any(ks1.platform_adi(x, ks1.PLATFORM_DEBIAN) in a_adlari for x in adlar)
            c3["ortak_adli"] += int(ortak)
            sonuc = m.match(q)
            if not sonuc:
                continue
            c3["eslesen"] += 1
            dogru = bool(adlar) and ks1.capa_degerlendir(
                sonuc[0].template_name, adlar, ks1.PLATFORM_DEBIAN)["durum"] == ks1.DURUM_DOGRU
            c3["dogru"] += int(dogru)
            c3["dogru_ortakta"] += int(dogru and ortak)
            c3[f"tur_{sonuc[0].match_type}"] += 1
            if len(ornek) < 60:
                ornek.append({"b": f["address"], "sablon": sonuc[0].template_name,
                              "gt": adlar[:1], "dogru": dogru, "guven": sonuc[0].confidence,
                              "tur": sonuc[0].match_type, "blok": q.node_count()})
        c3["sablon"] = len(sablonlar)
        c3["sure_sn"] = round(time.monotonic() - t0, 1)
        belge["c3"][cift] = {
            **dict(c3),
            "kesinlik": round(c3["dogru"] / c3["eslesen"], 4) if c3["eslesen"] else None,
            "kesinlik_wilson_alt": _wilson_alt(c3["dogru"], c3["eslesen"]),
            "duyarlilik": round(c3["dogru_ortakta"] / c3["ortak_adli"], 4) if c3["ortak_adli"] else None,
        }
        (cikti / f"cfg_{a.etiket}_ornek_{a_ad}_{b_ad}.json").write_text(
            json.dumps(ornek, ensure_ascii=False, indent=1), encoding="utf-8")
    (cikti / f"cfg_{a.etiket}.json").write_text(json.dumps(belge, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps({k: belge[k] for k in ("c1", "c2", "c3")}, ensure_ascii=False, indent=1))
    return 0


def cfg_eski(a: argparse.Namespace) -> int:
    """Taban sorgusu (``{"instr": N}``) ile öntanımlı banka: LSH adayı / eşleşme (TIP-01 gösterimi)."""
    karadul_yolu = _agac_yukle(a.agac)
    from karadul.analyzers.cfg_analyzer import CFGAnalyzer
    from karadul.computation.cfg_iso import HybridCFGMatcher, default_template_bank
    from karadul.config import ComputationRecoveryConfig
    from karadul.pipeline.steps import cfg_iso_match as cim
    m = HybridCFGMatcher(ComputationRecoveryConfig(), default_template_bank())
    kok = Path(a.kosu).expanduser()
    dosyalar = sorted(kok.glob("*/*/*/ws/workspaces/*/*/static/ghidra_output/cfg.json"))
    dosyalar += sorted(kok.glob("mac/*/ws/workspaces/*/*/static/ghidra_output/cfg.json"))
    toplam: Counter = Counter()
    for cj in dosyalar:
        res = CFGAnalyzer().analyze(cj)
        toplam["ikili"] += 1
        for fn in res.functions:
            q = cim._ghidra_cfg_to_attributed(fn)
            if q.node_count() == 0:
                continue
            toplam["sorgu"] += 1
            toplam["instr_histogram"] += int(all(set(n.mnemonic_histogram) <= {"instr"} for n in q.nodes))
            toplam["lsh_adayli"] += int(bool(m.lsh_index.query(q, top_k=10)))
            toplam["eslesen"] += int(bool(m.match(q)))
    print(json.dumps({"karadul": karadul_yolu, **toplam}, ensure_ascii=False))
    return 0


# --------------------------------------------------------------------------- imza kesinliği (F2)

def imza(a: argparse.Namespace) -> int:
    """Ghidra'nın adsız bıraktığı fonksiyonlara verilen imza adlarının yöntem başına GT kesinliği."""
    ks1 = _ks1()
    kosu = Path(a.kosu).expanduser()
    gt = _gt_haritalari(kosu, Path(a.indir).expanduser())
    yontem: dict[str, Counter] = defaultdict(Counter)
    atlanan: dict[str, str] = {}
    for ad, (e, g) in sorted(gt.items()):
        if isinstance(g, str):
            atlanan[ad] = g
            continue
        sm = sorted(Path(e.kosu).glob("reconstructed/signature_matches.json"))
        if len(sm) != 1:
            atlanan[ad] = "signature_matches.json yok"
            continue
        for m in _json(sm[0]).get("matches", []):
            orij, eslesen, adres = m.get("original", ""), m.get("matched", ""), m.get("address", "")
            if not orij.startswith("FUN_") or not eslesen or not adres:
                continue
            c = yontem[m.get("method") or "?"]
            c["n"] += 1
            adlar = g.adlar.get(int(adres, 16))
            if not adlar:
                c["eslenemedi"] += 1
                continue
            c["dogru"] += int(ks1.capa_degerlendir(eslesen, adlar, ks1.PLATFORM_DEBIAN)["durum"]
                              == ks1.DURUM_DOGRU)
    tablo = {y: {"n": c["n"], "dogru": c["dogru"], "eslenemedi": c["eslenemedi"],
                 "kesinlik": round(c["dogru"] / c["n"], 4) if c["n"] else None,
                 "wilson_alt": _wilson_alt(c["dogru"], c["n"])}
             for y, c in sorted(yontem.items())}
    belge = {"arac": ARAC, "kosu": str(kosu), "ikili": len(gt) - len(atlanan), "atlanan": atlanan,
             "nufus": "Ghidra'nın adsız bıraktığı (FUN_) fonksiyonlara imza adı; GT'de adres yoksa yanlış",
             "yontem": tablo}
    (Path(a.cikti).expanduser() / f"imza_{a.etiket}.json").write_text(
        json.dumps(belge, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps(belge, ensure_ascii=False, indent=1))
    return 0


def fuzyon(a: argparse.Namespace) -> int:
    """F1/F2: ürün koşusunun imza eşleşmeleri + CFG-iso (öntanımlı banka ya da A'dan gerçek şablon) füzyonu."""
    karadul_yolu = _agac_yukle(a.agac)
    from karadul.analyzers.signature_db import SignatureMatch
    from karadul.computation.cfg_iso import HybridCFGMatcher, default_template_bank
    from karadul.computation.cfg_iso.template_db import AlgorithmTemplate
    from karadul.computation.fusion import measured as fm
    from karadul.config import ComputationRecoveryConfig
    from karadul.pipeline.steps import cfg_iso_match as cim
    from karadul.pipeline.steps import computation_fusion as cf
    ks1 = _ks1()
    kosu = Path(a.kosu).expanduser()
    gt = _gt_haritalari(kosu, Path(a.indir).expanduser())
    crc = ComputationRecoveryConfig()
    tablo = fm.load_measured_precision()
    belge: dict[str, Any] = {"arac": ARAC, "karadul": karadul_yolu, "kosu": str(kosu), "kollar": {}}

    def _sablonlar(a_ad: str) -> list:
        e, g = gt[a_ad]
        out, adlar_ = [], set()
        for f in _json(Path(e.static) / "ghidra_output" / "cfg.json")["functions"]:
            adlar = g.adlar.get(int(f["address"], 16))
            if not adlar or len(f.get("blocks", [])) < a.en_az_blok:
                continue
            q = cim.attributed_cfg(f, None)
            ad = ks1.klon_tabani(ks1.platform_adi(adlar[0], ks1.PLATFORM_DEBIAN)) or adlar[0]
            if q is None or ad in adlar_:
                continue
            adlar_.add(ad)
            out.append(AlgorithmTemplate(name=ad, cfg=q, source="gercek_kod"))
        return out

    kollar = [("varsayilan", None, sorted(gt))] + [
        (f"gercek_{c.replace(':', '_')}", c.split(":")[0], [c.split(":")[1]]) for c in a.cift]
    for kol, a_ad, hedefler in kollar:
        m = HybridCFGMatcher(crc, default_template_bank() if a_ad is None else _sablonlar(a_ad))
        sayac: Counter = Counter()
        for b_ad in hedefler:
            e, g = gt[b_ad]
            sm = _json(Path(e.kosu) / "reconstructed" / "signature_matches.json")["matches"]
            sigs = [SignatureMatch(original_name=x.get("original", ""), matched_name=x.get("matched", ""),
                                   library=x.get("library", ""), confidence=float(x.get("confidence") or 0),
                                   match_method=x.get("method") or "", address=x.get("address", ""))
                    for x in sm]
            cfgm = {}
            for f in _json(Path(e.static) / "ghidra_output" / "cfg.json")["functions"]:
                q = cim.attributed_cfg(f, None)
                if q is None or q.node_count() == 0:
                    continue
                r = m.match(q)
                if r:
                    cfgm[f["address"]] = r[0]
            # Taban anahtarları: imza original_name, CFG adres → kesişim
            sayac["taban_kesisim"] += len({s.original_name for s in sigs} & set(cfgm))
            kan = cf.collect_evidence(sigs, cfgm)
            fused = fm.fuse_by_address(kan, tablo)
            sayac["adres"] += len(kan)
            sayac["iki_kaynakli"] += sum(1 for v in kan.values() if len({x.source.split(':')[0] for x in v}) > 1)
            sayac["cfg_adayi"] += len(cfgm)
            for flist in fused.values():
                for f in flist:
                    sayac[f.decision] += 1
                    if f.decision == fm.ACCEPT:
                        adlar = g.adlar.get(int(f.address, 16)) or []
                        sayac["kabul_dogru"] += int(bool(adlar) and ks1.capa_degerlendir(
                            f.name, adlar, ks1.PLATFORM_DEBIAN)["durum"] == ks1.DURUM_DOGRU)
            # aynı adı veren iki kaynak (ikisi de jenerik fonksiyonda)
            for v in kan.values():
                ad_kaynak: dict[str, set] = defaultdict(set)
                for x in v:
                    ad_kaynak[x.name].add(x.source.split(":")[0])
                sayac["iki_kaynak_ayni_ad"] += sum(1 for s in ad_kaynak.values() if len(s) > 1)
        belge["kollar"][kol] = dict(sayac)
    (Path(a.cikti).expanduser() / f"fuzyon_{a.etiket}.json").write_text(
        json.dumps(belge, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps(belge["kollar"], ensure_ascii=False, indent=1))
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    alt = ap.add_subparsers(dest="komut", required=True)
    m = alt.add_parser("maxsmt")
    m.add_argument("--agac", type=Path, required=True)
    m.add_argument("--kosu", default="~/karadul_olcum/runs/urun-yeni2-f30ac9a")
    m.add_argument("--hizalama", default="~/karadul_olcum/runs/t0b-1acba60/hizalama")
    m.add_argument("--dwarf", default="~/karadul_olcum/runs/t0c-a10fde3/dwarf")
    m.add_argument("--cikti", default="~/karadul_olcum/runs/onarim-2026-11-18/P11")
    m.add_argument("--etiket", required=True)
    m.add_argument("--coz", action="store_true", help="M3: Z3 çözücüsünü de koş")
    m.set_defaults(fn=maxsmt)
    c = alt.add_parser("cfg")
    c.add_argument("--agac", type=Path, required=True)
    c.add_argument("--kosu", required=True, help="yeni dökümlü koşu kökü (debian/<program>/<ikili>)")
    c.add_argument("--indir", default="~/karadul_olcum/downloads/debian13")
    c.add_argument("--cift", action="append", default=[], help="A:B (şablon ikilisi:sorgu ikilisi)")
    c.add_argument("--en-az-blok", type=int, default=5)
    c.add_argument("--klon-tabani", action="store_true",
                   help="şablon adı derleyici eki soyulmuş taban ad (ölçüm düzeltmesi)")
    c.add_argument("--cikti", default="~/karadul_olcum/runs/onarim-2026-11-18/P11")
    c.add_argument("--etiket", required=True)
    c.set_defaults(fn=cfg)
    ce = alt.add_parser("cfg-eski")
    ce.add_argument("--agac", type=Path, required=True)
    ce.add_argument("--kosu", default="~/karadul_olcum/runs/genel-tarama-2026-11-18")
    ce.set_defaults(fn=cfg_eski)
    i = alt.add_parser("imza")
    i.add_argument("--kosu", default="~/karadul_olcum/runs/urun-yeni2-f30ac9a")
    i.add_argument("--indir", default="~/karadul_olcum/downloads/debian13")
    i.add_argument("--cikti", default="~/karadul_olcum/runs/onarim-2026-11-18/P11")
    i.add_argument("--etiket", required=True)
    i.set_defaults(fn=imza)
    f = alt.add_parser("fuzyon")
    f.add_argument("--agac", type=Path, required=True)
    f.add_argument("--kosu", required=True)
    f.add_argument("--indir", default="~/karadul_olcum/downloads/debian13")
    f.add_argument("--cift", action="append", default=[], help="A:B (gerçek şablon ikilisi:hedef)")
    f.add_argument("--en-az-blok", type=int, default=5)
    f.add_argument("--cikti", default="~/karadul_olcum/runs/onarim-2026-11-18/P11")
    f.add_argument("--etiket", required=True)
    f.set_defaults(fn=fuzyon)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
