#!/usr/bin/env python3
"""P06 ölçümü: algoritma etiketi (TIP-09) ve ``@security`` etiketi (TIP-08), Ghidra'sız yeniden oynatma.

Ürün iki etiketi şu adımlarda üretir:

- ``pipeline/steps/algorithm_id.py``: ``CAlgorithmIdentifier(config).identify(decompiled_dir,
  functions_json, strings_json)``. ``decompiled_dir`` = ``deobfuscated/decompiled`` (yoksa
  ``static/ghidra_output/decompiled``, ``binary_prep.py``); JSON'lar önce ``deobfuscated/``, yoksa
  ``static/`` altından (``ghidra_metadata.py``). Sonuç ``reconstructed/algorithms.json``'a yazılır.
- ``pipeline/steps/comment_generation.py``: ``CCommentGenerator(config).generate(<semantic_named>,
  reconstructed/commented, functions_json, strings_json, call_graph_json, algorithm_results=...)``.
  Girdi dizini ``semantic_naming`` adımının ``reconstructed/semantic_named`` dizinidir (akış
  sadeleştirme onu yerinde değiştirir). ``@algorithm`` / ``ALGORITHM:`` ve ``@security`` buradan
  ürün koduna (``out/src/**/*.c``) geçer.

Bu betik kayıtlı bir koşunun (``urun_kos.py`` düzeni: ``<kök>/<anahtar>/{ws,out,BITTI}``) bu
girdilerini ölçülen ağacın koduyla aynı biçimde yeniden koşar ve etiketleri sayar. Sadakat denetimi:
yeniden oynatmanın (ad, fonksiyon) çoklu kümesi kayıtlı ``algorithms.json`` ile, ``@security``
(fonksiyon, metin) çoklu kümesi kayıtlı ``reconstructed/commented`` ile karşılaştırılır (kayıt ile
ölçülen ağaç aynı koddaysa eşit çıkmalı).

GT: Debian ikililerinde fonksiyonun gerçek adı, ``~/karadul_olcum/downloads/debian13`` altındaki
dbgsym dosyasının ``.symtab`` FUNC simgelerinden okunur (adres eşlemesi: Ghidra görüntü tabanı −
ikilinin en düşük PT_LOAD adresi). Mac ikililerinde GT okunmaz ("gt yok").

Kullanım (worktree kökünden):
    python scripts/measurement/p06_olc.py kos --etiket once \
        --cikti ~/karadul_olcum/runs/onarim-2026-11-18/P06 [--paralel 6]
    python scripts/measurement/p06_olc.py karsilastir --cikti ... --once once --sonra sonra
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import re
import shutil
import sys
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Optional

DEPO = Path(__file__).resolve().parents[2]
if str(DEPO) not in sys.path:
    sys.path.insert(0, str(DEPO))

KOSULAR = {
    "urun-yeni2": Path.home() / "karadul_olcum/runs/urun-yeni2-f30ac9a",
    "genel-tarama": Path.home() / "karadul_olcum/runs/genel-tarama-2026-11-18",
}
INDIR = Path.home() / "karadul_olcum/downloads/debian13"
BITTI = "BITTI"

_SECURITY_SATIRI = re.compile(r"^\s*\*\s*@security\s+(.+?)\s*$")
_ALGORITMA_BASLIGI = re.compile(r"^\s*\*\s*@algorithm\s+(.+?)\s+\((\w+), confidence: (\d+)%\)\s*$")
_ALGORITMA_SATIRI = re.compile(r"/\*\s*ALGORITHM:\s+(.+?)\s+\(confidence: (\d+)%, via ([\w+]+)\)\s*\*/")
_IMZA_ADI = re.compile(r"(\w+)\s*\(")


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
    adaylar = sorted(kok.glob("debian/*/*")) + sorted(kok.glob("mac/*"))
    for d in adaylar:
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
    """Ürünün seçimi: önce ``deobfuscated/``, yoksa ``static/`` (``ghidra_metadata.py``)."""
    p = ws / "deobfuscated" / ad
    return p if p.exists() else ws / "static" / ad


def _decompiled(ws: Path) -> Path:
    """Ürünün seçimi: ``deobfuscated/decompiled``, yoksa ``static/ghidra_output/decompiled``."""
    p = ws / "deobfuscated" / "decompiled"
    return p if p.exists() else ws / "static" / "ghidra_output" / "decompiled"


def _json(yol: Path) -> Any:
    return json.loads(yol.read_text(encoding="utf-8")) if yol.is_file() else None


# ---------------------------------------------------------------------------
# GT (yalnız değerlendirme için; ürün GT okumaz)
# ---------------------------------------------------------------------------

def gt_adlari(ws: Path) -> tuple[Optional[dict[int, list[str]]], str]:
    """Ghidra adresi → gerçek fonksiyon adları; yoksa (None, neden)."""
    from elftools.elf.elffile import ELFFile

    bilgi = _json(ws / "raw" / "target_info.json") or {}
    soyulmus = Path(bilgi.get("path", ""))
    if not soyulmus.is_file():
        hamlar = [p for p in (ws / "raw").iterdir() if p.is_file() and p.name != "target_info.json"]
        if len(hamlar) != 1:
            return None, "ham ikili bulunamadı"
        soyulmus = hamlar[0]
    with open(soyulmus, "rb") as f:
        if f.read(4) != b"\x7fELF":
            return None, "ELF değil (gt yok)"
    with open(soyulmus, "rb") as f:
        elf = ELFFile(f)
        bid = None
        for bol in elf.iter_sections():
            if bol.name == ".note.gnu.build-id":
                for not_ in bol.iter_notes():
                    if not_["n_type"] == "NT_GNU_BUILD_ID":
                        bid = not_["n_desc"]
        en_dusuk = min(s["p_vaddr"] for s in elf.iter_segments() if s["p_type"] == "PT_LOAD")
    if not bid:
        return None, "build-id yok"
    adaylar = sorted(INDIR.glob(f"x_*-dbgsym_*/usr/lib/debug/.build-id/{bid[:2]}/{bid[2:]}.debug"))
    if len(adaylar) != 1:
        return None, f"build-id {bid} için {len(adaylar)} hata ayıklama dosyası"
    prog = (_json(ws / "static" / "ghidra_combined_results.json") or {}).get("program_info") or {}
    if "image_base" not in prog:
        return None, "Ghidra görüntü tabanı kayıtlı değil"
    ofset = int(str(prog["image_base"]), 16) - en_dusuk
    adlar: dict[int, list[str]] = defaultdict(list)
    with open(adaylar[0], "rb") as f:
        dbg = ELFFile(f)
        symtab = dbg.get_section_by_name(".symtab")
        if symtab is None:
            return None, "dbgsym'de .symtab yok"
        for s in symtab.iter_symbols():
            if s["st_info"]["type"] == "STT_FUNC" and s["st_value"] and s.name:
                adlar[s["st_value"] + ofset].append(s.name)
    return dict(adlar), "gt"


def _adres(ad: str, ad_adres: dict[str, Optional[int]]) -> Optional[int]:
    if ad.startswith("FUN_"):
        try:
            return int(ad[4:], 16)
        except ValueError:
            return None
    return ad_adres.get(ad)


def _ad_adres_tablosu(functions_json: Path) -> dict[str, Optional[int]]:
    """Ghidra fonksiyon adı → adres (ad birden çok fonksiyondaysa None: belirsiz)."""
    veri = _json(functions_json) or {}
    tablo: dict[str, Optional[int]] = {}
    for f in veri.get("functions", []) or []:
        ad, adres = f.get("name"), f.get("address")
        if not ad or not adres:
            continue
        deger = int(str(adres), 16)
        tablo[ad] = None if ad in tablo and tablo[ad] != deger else deger
    return tablo


# ---------------------------------------------------------------------------
# Yeniden oynatma
# ---------------------------------------------------------------------------

def _yontem(m: Any) -> str:
    return str(getattr(m, "detection_method", "?"))


def _yapisal_mi(yontem: str) -> bool:
    return "structural" in yontem.split("+")


def _security_kayitlari(dizin: Path) -> list[tuple[str, str]]:
    """Bir dizindeki ``@security`` satırları → (fonksiyon adı, metin) listesi."""
    kayitlar = []
    for f in sorted(dizin.rglob("*.c")):
        satirlar = f.read_text(encoding="utf-8", errors="replace").split("\n")
        for i, satir in enumerate(satirlar):
            m = _SECURITY_SATIRI.match(satir)
            if not m:
                continue
            ad = "?"
            j = i + 1
            while j < len(satirlar) and "*/" not in satirlar[j]:
                j += 1
            for k in range(j + 1, min(j + 12, len(satirlar))):
                s = satirlar[k].strip()
                if not s or s.startswith(("//", "/*", "*", "#")):
                    continue
                mi = _IMZA_ADI.search(s)
                if mi:
                    ad = mi.group(1)
                break
            kayitlar.append((ad, m.group(1)))
    return kayitlar


def _kod_algoritmalari(dizin: Path) -> tuple[Counter, Counter]:
    """Yorumlanmış koddaki ``@algorithm`` başlıkları ve satır içi ``ALGORITHM:`` (ad, yöntem) sayımı."""
    basliklar, satirlar = Counter(), Counter()
    for f in sorted(dizin.rglob("*.c")):
        metin = f.read_text(encoding="utf-8", errors="replace")
        for satir in metin.split("\n"):
            m = _ALGORITMA_BASLIGI.match(satir)
            if m:
                basliklar[m.group(1)] += 1
        for m in _ALGORITMA_SATIRI.finditer(metin):
            satirlar[(m.group(1), m.group(3))] += 1
    return basliklar, satirlar


def security_turu(metin: str) -> str:
    """Etiket metninin türü: kanıt parantezinden önceki bölüm (``X (calls Y)`` → ``X``)."""
    return metin.split(" (", 1)[0].strip()


def isle(kosu: str, anahtar: str, ws: Path, yorum: bool) -> dict:
    karadul_denetle()
    from karadul.config import Config
    from karadul.reconstruction.c_algorithm_id import CAlgorithmIdentifier

    t0 = time.monotonic()
    cfg = Config.load(None)
    dec = _decompiled(ws)
    fjson, sjson, cg = (_sec(ws, "ghidra_functions.json"), _sec(ws, "ghidra_strings.json"),
                        _sec(ws, "ghidra_call_graph.json"))
    kayit: dict[str, Any] = {"kosu": kosu, "anahtar": anahtar, "ws": str(ws)}
    if not dec.is_dir():
        kayit["durum"] = "decompiled yok"
        return kayit
    sonuc = CAlgorithmIdentifier(cfg).identify(dec, fjson, sjson)
    algos = list(sonuc.algorithms)

    gt, gt_neden = gt_adlari(ws)
    kayit["gt"] = gt_neden
    ad_adres = _ad_adres_tablosu(fjson)
    kayit["algoritmalar"] = []
    for a in algos:
        adres = _adres(a.function_name, ad_adres)
        kayit["algoritmalar"].append({
            "ad": a.name, "yontem": _yontem(a), "fonksiyon": a.function_name,
            "adres": None if adres is None else f"{adres:x}",
            "guven": a.confidence, "kanit": list(a.evidence)[:4],
            "gt": (gt.get(adres) if (gt is not None and adres is not None) else None),
        })
    kayitli = _json(ws / "reconstructed" / "algorithms.json")
    if kayitli is None:
        kayit["algoritma_kayitla_esit"] = None
    else:
        eski = Counter((a.get("name"), a.get("function")) for a in kayitli.get("algorithms", []) or [])
        yeni = Counter((a.name, a.function_name) for a in algos)
        kayit["algoritma_kayitla_esit"] = eski == yeni

    if yorum:
        from karadul.reconstruction.c_comment_generator import CCommentGenerator
        girdi = ws / "reconstructed" / "semantic_named"
        if not girdi.is_dir():
            kayit["yorum"] = {"durum": "semantic_named yok"}
        else:
            gecici = Path(tempfile.mkdtemp(prefix="p06_yorum_"))
            try:
                CCommentGenerator(cfg).generate(
                    decompiled_dir=girdi, output_dir=gecici, functions_json=fjson,
                    strings_json=sjson, call_graph_json=cg, algorithm_results=algos)
                sec_ = _security_kayitlari(gecici)
                basliklar, satirlar = _kod_algoritmalari(gecici)
            finally:
                shutil.rmtree(gecici, ignore_errors=True)
            kayitli_dizin = ws / "reconstructed" / "commented"
            esit = None
            if kayitli_dizin.is_dir():
                esit = Counter(_security_kayitlari(kayitli_dizin)) == Counter(sec_)
            kayit["yorum"] = {
                "durum": "calisti",
                "security": [{"fonksiyon": f, "metin": m} for f, m in sec_],
                "security_kayitla_esit": esit,
                "algoritma_basligi": dict(basliklar),
                "algoritma_satiri": {f"{a} | {y}": n for (a, y), n in satirlar.items()},
            }
    kayit["durum"] = "calisti"
    kayit["sure_sn"] = round(time.monotonic() - t0, 1)
    return kayit


# ---------------------------------------------------------------------------
# Özet
# ---------------------------------------------------------------------------

def ozetle(kayitlar: list[dict]) -> dict:
    """Etiket türü başına ikili ve etiket sayısı."""
    yapisal: dict[str, dict] = defaultdict(lambda: {"ikili": set(), "etiket": 0})
    yontem_say: dict[str, dict] = defaultdict(lambda: {"ikili": set(), "etiket": 0})
    sec_tur: dict[str, dict] = defaultdict(lambda: {"ikili": set(), "etiket": 0})
    kod_baslik: dict[str, dict] = defaultdict(lambda: {"ikili": set(), "etiket": 0})
    esit_alg, esit_sec = Counter(), Counter()
    for k in kayitlar:
        if k.get("durum") != "calisti":
            continue
        ik = f"{k['kosu']}:{k['anahtar']}"
        esit_alg[str(k.get("algoritma_kayitla_esit"))] += 1
        for a in k["algoritmalar"]:
            yontemler = a["yontem"].split("+")
            for y in yontemler:
                yontem_say[y]["ikili"].add(ik)
                yontem_say[y]["etiket"] += 1
            if "structural" in yontemler:
                yapisal[a["ad"]]["ikili"].add(ik)
                yapisal[a["ad"]]["etiket"] += 1
        y = k.get("yorum") or {}
        if y.get("durum") == "calisti":
            esit_sec[str(y.get("security_kayitla_esit"))] += 1
            for s in y["security"]:
                t = security_turu(s["metin"])
                sec_tur[t]["ikili"].add(ik)
                sec_tur[t]["etiket"] += 1
            for ad, n in y["algoritma_basligi"].items():
                kod_baslik[ad]["ikili"].add(ik)
                kod_baslik[ad]["etiket"] += n

    def duz(t: dict) -> dict:
        return {a: {"ikili": len(v["ikili"]), "etiket": v["etiket"]}
                for a, v in sorted(t.items(), key=lambda x: (-x[1]["etiket"], x[0]))}

    return {"yapisal": duz(yapisal), "yontem": duz(yontem_say), "security": duz(sec_tur),
            "kod_algoritma_basligi": duz(kod_baslik),
            "algoritma_kayitla_esit": dict(esit_alg), "security_kayitla_esit": dict(esit_sec)}


def kos(a: argparse.Namespace) -> int:
    print("karadul:", karadul_denetle())
    hedef = a.cikti / a.etiket
    hedef.mkdir(parents=True, exist_ok=True)
    isler = []
    for kosu in a.kosu:
        for anahtar, ws in ikilileri_bul(KOSULAR[kosu]):
            if a.yalniz and not any(s in anahtar for s in a.yalniz):
                continue
            isler.append((kosu, anahtar, ws))
    t0 = time.monotonic()
    kayitlar = []
    with cf.ProcessPoolExecutor(max_workers=a.paralel) as havuz:
        gelecek = {havuz.submit(isle, k, an, ws, not a.yorumsuz): (k, an) for k, an, ws in isler}
        for g in cf.as_completed(gelecek):
            k, an = gelecek[g]
            try:
                kayitlar.append(g.result())
            except Exception as exc:  # ölçüm aracı: hatayı kayda yaz, sessiz geçme
                kayitlar.append({"kosu": k, "anahtar": an, "durum": f"hata: {exc!r}"})
    kayitlar.sort(key=lambda r: (r["kosu"], r["anahtar"]))
    ozet = {kosu: ozetle([r for r in kayitlar if r["kosu"] == kosu]) for kosu in a.kosu}
    hatali = [f"{r['kosu']}:{r['anahtar']} {r['durum']}" for r in kayitlar if r.get("durum") != "calisti"]
    belge = {"etiket": a.etiket, "agac": str(DEPO), "kosular": {k: str(KOSULAR[k]) for k in a.kosu},
             "ikili": len(kayitlar), "hatali": hatali, "sure_sn": round(time.monotonic() - t0, 1),
             "ozet": ozet, "kayitlar": kayitlar}
    (hedef / "p06.json").write_text(json.dumps(belge, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps({k: v for k, v in belge.items() if k != "kayitlar"}, ensure_ascii=False, indent=1))
    return 1 if hatali else 0


# ---------------------------------------------------------------------------
# Karşılaştırma
# ---------------------------------------------------------------------------

def _tablo(baslik: str, once: dict, sonra: dict) -> list[str]:
    satir = [f"| {baslik} | önce ikili | önce etiket | sonra ikili | sonra etiket |",
             "|---|---|---|---|---|"]
    for ad in sorted(set(once) | set(sonra), key=lambda x: (-(once.get(x, {}).get("etiket", 0)), x)):
        o, s = once.get(ad, {"ikili": 0, "etiket": 0}), sonra.get(ad, {"ikili": 0, "etiket": 0})
        satir.append(f"| {ad} | {o['ikili']} | {o['etiket']} | {s['ikili']} | {s['etiket']} |")
    return satir


def karsilastir(a: argparse.Namespace) -> int:
    o = json.loads((a.cikti / a.once / "p06.json").read_text(encoding="utf-8"))
    s = json.loads((a.cikti / a.sonra / "p06.json").read_text(encoding="utf-8"))
    cikti = [f"# P06 karşılaştırma: {a.once} → {a.sonra}", ""]
    for kosu in o["ozet"]:
        oo, ss = o["ozet"][kosu], s["ozet"].get(kosu, {})
        cikti += [f"## {kosu}", ""]
        for anahtar, baslik in (("yapisal", "Yapısal algoritma etiketi"),
                                ("yontem", "Algoritma yöntemi"),
                                ("kod_algoritma_basligi", "Kodda @algorithm"),
                                ("security", "@security türü")):
            cikti += _tablo(baslik, oo.get(anahtar, {}), ss.get(anahtar, {})) + [""]
    # Kaybolan ve yeni çıkan etiketler (fonksiyon düzeyinde, GT adıyla)
    def anahtarla(belge: dict) -> dict:
        d = {}
        for k in belge["kayitlar"]:
            for al in k.get("algoritmalar", []):
                d[(k["kosu"], k["anahtar"], al["fonksiyon"], al["ad"])] = al
        return d
    oa, sa = anahtarla(o), anahtarla(s)
    kayip = sorted(set(oa) - set(sa))
    yeni = sorted(set(sa) - set(oa))
    cikti += [f"## Kaybolan algoritma etiketleri ({len(kayip)})", "",
              "| koşu | ikili | fonksiyon | GT | etiket | yöntem | kanıt |", "|---|---|---|---|---|---|---|"]
    for anahtar in kayip:
        al = oa[anahtar]
        cikti.append(f"| {anahtar[0]} | {anahtar[1]} | {al['fonksiyon']} | {','.join(al['gt'] or []) or '-'} "
                     f"| {al['ad']} | {al['yontem']} | {'; '.join(al['kanit'])[:90].replace('|', '/')} |")
    cikti += ["", f"## Yeni çıkan algoritma etiketleri ({len(yeni)})", ""]
    for anahtar in yeni:
        al = sa[anahtar]
        cikti.append(f"- {anahtar[0]} {anahtar[1]} {al['fonksiyon']} ({','.join(al['gt'] or []) or '-'}): "
                     f"{al['ad']} [{al['yontem']}] {'; '.join(al['kanit'])[:120]}")
    metin = "\n".join(cikti) + "\n"
    (a.cikti / f"karsilastirma_{a.once}_{a.sonra}.md").write_text(metin, encoding="utf-8")
    print(metin)
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    alt = ap.add_subparsers(dest="komut", required=True)
    k = alt.add_parser("kos")
    k.add_argument("--etiket", required=True)
    k.add_argument("--cikti", type=Path, required=True)
    k.add_argument("--kosu", nargs="+", default=list(KOSULAR), choices=list(KOSULAR))
    k.add_argument("--paralel", type=int, default=6)
    k.add_argument("--yalniz", nargs="*", help="yalnız anahtarında bu parçalardan biri geçen ikililer")
    k.add_argument("--yorumsuz", action="store_true", help="yorum üreticiyi koşma (yalnız algoritma)")
    c = alt.add_parser("karsilastir")
    c.add_argument("--cikti", type=Path, required=True)
    c.add_argument("--once", required=True)
    c.add_argument("--sonra", required=True)
    a = ap.parse_args(argv)
    return kos(a) if a.komut == "kos" else karsilastir(a)


if __name__ == "__main__":
    sys.exit(main())
