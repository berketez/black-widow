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
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
