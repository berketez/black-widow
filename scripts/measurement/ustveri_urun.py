#!/usr/bin/env python3
"""ÜST VERİ ürün düzeyi ölçümü (P-ÜV8 kalem 5–6; P-ÜV6a): kanalın ürün akışındaki davranışı ve ad sayısı.

Alt komutlar
------------
``oynat``     Ghidra'sız yeniden oynatma: var olan bir çalışma alanının ``ghidra_functions.json``'u ve
              ikilisi üstünde ürünün üretici okuyucularını (``go_metadata_recovery``,
              ``objc_metadata_recovery`` ile aynı yol) ve ad kanallarını (``add_k4_channels``, iki bayrak
              açık) çağırır; kanal sayaçları (``tuttu``, ``pcsp_elendi``, ``secici_yerine`` …) ve
              birleştiricinin ad geçerliliği süzgecinden geçen aday sayısı. Ad yazmaz, koşu yapmaz.
``aday-gt``   Ghidra'sız aday listesi ↔ GT: setin soyulmuş kopyasında üretici okuyucu + kanal süzgeçleri
              (Go ``pcsp_kapsama``; ObjC ``ad_yazilabilir`` / ``swift`` / ``imp_paylasimli``) → adres →
              özgün ad; ``ustveri_olc.kanal_olc`` ile GT eşitliği (kalem 2 kuralları). Sınama ikilileri
              ``--sinama-izni`` olmadan reddedilir.
``kos``       Soyulmuş kopyada (ya da verilen girdide) ürün koşusu, bayrak yaml'ıyla; Ghidra kuyruğu
              dışarıdan sarar. Komut ``urun_kos.calistir`` ile aynı, yalnız ``--config`` eklenir.
``urun``      Ürün koşusunun adları ↔ GT (HEDEF kalem 4 tanımı, ``ustveri_olc.urun_olc``) + üst veri
              kaynaklı adlar (``out/naming_map.json`` ``label = üst veriden``): ad haritasında ve
              ``out/src`` kodunda olan, doğru / yanlış / GT'siz, etiket, ``ozgun_ad``, ad bekleyen nüfus.

Hiçbir hedef ikili çalıştırılmaz. Çıktılar depo dışına yazılır; ad listesi basılmaz (yalnız sayı).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Optional

REPO = Path(__file__).resolve().parents[2]
_BURASI = Path(__file__).resolve().parent
for _yol in (str(_BURASI), str(REPO)):
    if _yol not in sys.path:
        sys.path.insert(0, _yol)

import ustveri_olc as uvo  # noqa: E402
import ustveri_set as us  # noqa: E402
from karadul.core import naming_labels as nl  # noqa: E402

SEMA = "karadul-ustveri-urun/1"
KANAL_TURU = {nl.SOURCE_GO_PCLNTAB: uvo.KANAL_GO, nl.SOURCE_OBJC_METHOD: uvo.KANAL_OBJC}
_C_KIMLIK_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


# =============================================================================================
# Üretici okuyucular (ürünün adımlarıyla aynı yol)


def go_kayitlari(ikili: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """``go_metadata_recovery`` ile aynı: ürün dilimi, ``go_pclntab.oku``, liste yalnız ``calisti``'da."""
    from karadul.analyzers.ustveri import go_pclntab
    from karadul.pipeline.steps import go_metadata_recovery as gm
    try:
        g = gm._goruntu_ac(Path(ikili))
    except Exception as exc:  # noqa: BLE001 - adımdaki gibi: durum taşınır
        durum = getattr(exc, "durum", None)
        if durum not in go_pclntab.DURUMLAR:
            durum = go_pclntab.DURUM_HATA
        return [], {"durum": durum, "neden": f"görüntü: {getattr(exc, 'neden', exc)}"}
    s = go_pclntab.oku(g)
    fonk = [f.kayit() for f in s.fonksiyonlar] if s.durum == go_pclntab.DURUM_CALISTI else []
    return fonk, {"durum": s.durum, "neden": s.neden}


def objc_kayitlari(ikili: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """``objc_metadata_recovery`` ile aynı: ``_oku``, ``tutarsiz``'da liste boş."""
    from karadul.analyzers.ustveri import objc
    from karadul.pipeline.steps.objc_metadata_recovery import ObjcMetadataRecoveryStep
    s = ObjcMetadataRecoveryStep._oku(Path(ikili))
    yontem = [] if s.durum == objc.DURUM_TUTARSIZ else [y.as_dict() for y in s.yontemler]
    return yontem, {"durum": s.durum, "neden": s.neden}


# =============================================================================================
# oynat


def goruntu_tabani(ws: Path) -> Optional[int]:
    """Ghidra'nın görüntü tabanı (``ghidra_combined_results.json``; ``ustveri_olc.urun_olc`` ile aynı)."""
    try:
        taban = json.loads((ws / "static" / "ghidra_combined_results.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    v = (taban.get("program_info") or taban.get("summary", {}).get("program") or {}).get("image_base")
    if isinstance(v, int):
        return v
    try:
        return int(str(v), 16)
    except (TypeError, ValueError):
        return None


def oynat(ws: Path, ikili: Path) -> dict[str, Any]:
    """Ghidra'sız yeniden oynatma (iki bayrak açık); sayılar ürün kodunun kendisinden."""
    from karadul.pipeline.steps import _feedback_naming_candidates as FC
    from karadul.pipeline.steps import _feedback_naming_merger as FM
    t0 = time.monotonic()
    go_f, go_d = go_kayitlari(ikili)
    oc_m, oc_d = objc_kayitlari(ikili)
    t_okuma = time.monotonic() - t0
    fj = ws / "static" / "ghidra_functions.json"
    taban = goruntu_tabani(ws)
    index = FC.load_ghidra_index(fj, binary_path=ikili, ghidra_image_base=taban)
    flags = {s: s in nl.METADATA_SOURCES for s in FC.K4_CHANNEL_FLAGS}
    adaylar: dict[str, list[Any]] = {}
    stats: dict[str, Any] = {}
    kayit: dict[str, dict[str, Any]] = {}
    kanit: list[dict[str, Any]] = []
    FC.add_k4_channels(flags=flags, index=index, binary_path=ikili, pdb_symbols=[], pdb_status=None,
                       bn_functions=[], bn_status=None, trex_structs=[], trex_status=None,
                       go_functions=go_f, go_status=go_d, objc_methods=oc_m, objc_status=oc_d,
                       metadata_records=kayit, metadata_evidence=kanit,
                       candidates=adaylar, stats=stats)
    harita = {k: v[0].name for k, v in adaylar.items() if len(v) == 1}
    gecen, ret = FM.validate_merged_names(harita, functions_json=fj, used=[])
    kanal = {}
    for src in nl.METADATA_SOURCES:
        ch = dict(stats.get("naming_channels", {}).get(src, {}))
        anahtar = [k for k, r in kayit.items() if r["kaynak"] == src]
        ch["suzgecten_gecen"] = sum(1 for k in anahtar if k in gecen)
        ch["suzgec_reddi"] = dict(Counter(ret[k] for k in anahtar if k in ret))
        ch["kanit_nedenleri"] = dict(Counter(n for r in kanit if r["kaynak"] == src for n in r["nedenler"]))
        kanal[src] = ch
    return {"schema": SEMA, "olcum": "oynat", "ws": str(ws), "ikili": str(ikili),
            "ikili_sha256": _sha(ikili), "ghidra_goruntu_tabani": taban,
            "ghidra_fonksiyonu": len(index.by_addr) if index else None, "delta": index.delta if index else None,
            "uretici": {"go": {**go_d, "kayit": len(go_f)}, "objc": {**oc_d, "kayit": len(oc_m)}},
            "kanal": kanal, "okuma_sn": round(t_okuma, 3), "yuk": uvo._uptime()}


def _sha(yol: Path) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(yol, "rb") as f:
        for parca in iter(lambda: f.read(1 << 20), b""):
            h.update(parca)
    return h.hexdigest()


# =============================================================================================
# aday-gt


def aday_listesi(ikili: Path) -> dict[str, Any]:
    """Ghidra'sız aday listesi: kanal süzgeçlerinden geçen kayıtların adres → {özgün ad}."""
    from karadul.pipeline.steps import _feedback_naming_candidates as FC
    go_f, go_d = go_kayitlari(ikili)
    oc_m, oc_d = objc_kayitlari(ikili)
    go_ad: dict[int, set[str]] = {}
    go_el: Counter = Counter()
    for f in go_f:
        if not isinstance(f.get("ad"), str) or not f["ad"]:      # ürün kanalı da atlar (adsız giriş)
            go_el["adsiz"] += 1
            continue
        if f.get("pcsp_kapsama") in FC.PCSP_REJECTED:
            go_el[f"pcsp_{f['pcsp_kapsama']}"] += 1
            continue
        go_ad.setdefault(int(f["giris"], 16), set()).add(f["ad"])
    oc_ad: dict[int, set[str]] = {}
    oc_el: Counter = Counter()
    for m in oc_m:
        imp = m.get("imp")
        if not isinstance(imp, int) or imp <= 0 or not m.get("tam_ad"):
            oc_el["imp_yok"] += 1
            continue
        nedenler = FC._objc_rejections(m)
        if nedenler:
            for n in nedenler:
                oc_el[n] += 1
            continue
        oc_ad.setdefault(imp, set()).add(m["tam_ad"])
    return {nl.SOURCE_GO_PCLNTAB: {"durum": go_d, "kayit": len(go_f), "aday": go_ad, "elenen": dict(go_el)},
            nl.SOURCE_OBJC_METHOD: {"durum": oc_d, "kayit": len(oc_m), "aday": oc_ad, "elenen": dict(oc_el)}}


def aday_gt(ad: str, set_kok: Path, sinama_izni: bool = False) -> dict[str, Any]:
    if us.bolme(ad) != us.BOLME_KESIF and not sinama_izni:
        raise SystemExit(f"{ad}: sınama ikilisi — kurallar dondurulmadan ölçülmez (--sinama-izni)")
    y = us.yollar(set_kok, ad)
    gt, _rtti, _b = us.gt_oku(y["gt"])
    liste = aday_listesi(y["bin"])
    out = {}
    for src, v in liste.items():
        olc = uvo.kanal_olc(v["aday"], gt, KANAL_TURU[src])
        out[src] = {"uretici": v["durum"], "kayit": v["kayit"], "elenen": v["elenen"], **olc}
    man = us.manifest_oku(set_kok)["ikililer"][ad]
    return {"schema": SEMA, "olcum": "aday-gt", "ad": ad, "bolme": us.bolme(ad),
            "ikili_sha256": man["stripped_sha256"], "kanallar": out}


# =============================================================================================
# kos


def kos(girdi: Path, sha256: str, agac: Path, kok: Path, config: Optional[Path], zaman_asimi: int,
        anahtar: str) -> dict[str, Any]:
    """Ürün koşusu (``urun_kos.calistir`` ile aynı komut + ``--config``). Ghidra kuyruğu dışarıdan sarar."""
    import urun_kos as uk
    hedef = kok / anahtar
    hedef.mkdir(parents=True, exist_ok=True)
    if _sha(girdi) != sha256:
        return {"anahtar": anahtar, "durum": "girdi_degismis", "sure_sn": 0.0}
    ortam = dict(os.environ, GHIDRA_INSTALL_DIR=str(uk.GHIDRA), PYTHONPATH=str(agac))
    komut = [sys.executable, "-m", "karadul", "analyze", str(girdi), "--skip-dynamic",
             "--output-dir", str(hedef / "ws"), "--output", str(hedef / "out")]
    if config is not None:
        komut += ["--config", str(config)]
    kunye = {"agac": uk.agac_kunyesi(agac), "komut": komut, "config": str(config) if config else None,
             "config_metni": config.read_text(encoding="utf-8") if config else None,
             "girdi_sha256": sha256, "zaman_asimi_sn": zaman_asimi,
             "PYTHONHASHSEED": os.environ.get("PYTHONHASHSEED"),
             "KARADUL_CACHE_DIR": os.environ.get("KARADUL_CACHE_DIR"),
             "yuk_basta": uvo._uptime(), "baslangic": uvo._simdi()}
    t0 = time.monotonic()
    with open(hedef / "kosu.log", "w", encoding="utf-8") as gunluk:
        surec = subprocess.Popen(komut, cwd=agac, env=ortam, stdout=gunluk, stderr=subprocess.STDOUT,
                                 start_new_session=True)
        try:
            kod = surec.wait(timeout=zaman_asimi)
            durum = {0: "tamam", 3: "kismi"}.get(kod, f"cikis_{kod}")
        except subprocess.TimeoutExpired:
            os.killpg(surec.pid, signal.SIGKILL)
            surec.wait()
            durum = "zaman_asimi"
    if durum in ("tamam", "kismi"):
        (hedef / uk.BITTI).write_text("0\n" if durum == "tamam" else "3\n", encoding="utf-8")
    kunye.update({"durum": durum, "sure_sn": round(time.monotonic() - t0, 1), "bitis": uvo._simdi(),
                  "yuk_sonda": uvo._uptime()})
    (hedef / "kunye.json").write_text(json.dumps(kunye, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return {"anahtar": anahtar, "durum": durum, "sure_sn": kunye["sure_sn"]}


# =============================================================================================
# urun


def kod_kimlikleri(src: Path) -> set[str]:
    """``out/src`` altındaki .c / .h kodundaki tanımlayıcılar (yorumlar dahil kaba tarama değil:
    ``output_formatter._scan_c_code`` ile aynı süzgeç)."""
    from karadul.core.output_formatter import OutputFormatter
    kimlik, _tanim = OutputFormatter._scan_c_code(src)
    return kimlik


def ustveri_adlari(harita: dict[str, Any], gfonk: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """``out/naming_map.json`` ``mappings``'teki ``label = üst veriden`` kayıtları + anahtarın adresi.

    Anahtar ``FUN_<adres>`` ise adres ondan; değilse (A-28: Ghidra'nın seçici adının C yazımı) Ghidra
    fonksiyon listesinde o yazımı taşıyan TEK fonksiyonun adresi (birden çoksa adres yok)."""
    from karadul.pipeline.steps._feedback_naming_candidates import code_name
    yazim: dict[str, list[int]] = {}
    for g in gfonk:
        cn = code_name(g["name"])
        if cn is not None:
            yazim.setdefault(cn, []).append(g["addr"])
    out = []
    for k, r in sorted((harita.get("mappings") or {}).items()):
        if not isinstance(r, dict) or r.get("label") != nl.LABEL_METADATA:
            continue
        m = re.fullmatch(r"FUN_([0-9a-fA-F]+)", k)
        if m:
            adres: Optional[int] = int(m.group(1), 16)
        else:
            adlar = yazim.get(k) or []
            adres = adlar[0] if len(adlar) == 1 else None
        out.append({"anahtar": k, "adres": adres, "ad": r.get("new_name"), "ozgun_ad": r.get("ozgun_ad"),
                    "kaynak": r.get("source"), "etiket": r.get("label"), "guven": r.get("confidence"),
                    "a28": not m})
    return out


def urun(ad: str, set_kok: Path, kok: Path, kosu_anahtari: Optional[str] = None) -> dict[str, Any]:
    """HEDEF kalem 4 ölçümü (``ustveri_olc.urun_olc``) + üst veri adları (ad haritası ∧ kod)."""
    import function_f1 as f1
    man = us.manifest_oku(set_kok)["ikililer"][ad]
    kosu = Path(kok) / (kosu_anahtari or uvo.URUN_ANAHTARI.format(ad=ad))
    ws = uvo.calisma_alani(kosu)
    hedef = json.loads((ws / "raw" / "target_info.json").read_text(encoding="utf-8"))
    if hedef.get("file_hash") != man["stripped_sha256"]:
        raise SystemExit(f"{ad}: analiz edilen dosya setin soyulmuş kopyası değil")
    gt, _r, _b = us.gt_oku(us.yollar(set_kok, ad)["gt"])
    gfonk = f1.load_ghidra_functions(ws / "static" / "ghidra_functions.json")
    nufus = uvo.urun_nufusu(gt, gfonk)
    # HEDEF tanımı (c_namer genel haritası): taban ile aynı ölçü
    import urun_olc as uo
    genel, koken, _kimlik = uo.haritayi_oku(ws)
    kayitlar, atlanan = uvo.urun_kayitlari(genel, koken, gfonk, gt, nufus)
    # üst veri adları: ad haritası (out) ∧ kod (out/src)
    harita = json.loads((kosu / "out" / "naming_map.json").read_text(encoding="utf-8"))
    kimlik = kod_kimlikleri(kosu / "out" / "src")
    uv = ustveri_adlari(harita, gfonk)
    say: Counter = Counter()
    uv_nufus_dogru = set()
    for r in uv:
        say["haritada"] += 1
        kodda = r["ad"] in kimlik
        say["kodda"] += int(kodda)
        say[f"etiket:{r['etiket']}"] += 1
        say["ozgun_ad_dolu"] += int(bool(r["ozgun_ad"]))
        say["guven_tablodan"] += int(r["guven"] == nl.metadata_confidence(r["kaynak"]))
        say["a28"] += int(r["a28"])
        if r["adres"] is None:
            say["adres_yok"] += 1
            continue
        gt_adlari = gt.get(r["adres"])
        if not gt_adlari:
            durum = uvo.GT_SIZ
        else:
            durum = uvo.DOGRU if any(uvo.urun_esit(r["ozgun_ad"] or "", x) for x in gt_adlari) else uvo.YANLIS
        say[durum] += 1
        say[f"{durum}+kodda"] += int(kodda)
        if r["adres"] in nufus:
            say["nufusta"] += 1
            if durum == uvo.DOGRU and kodda:
                uv_nufus_dogru.add(r["adres"])
    # ad bekleyen nüfusta doğru ad: c_namer kaydı doğru ∪ üst veri adı doğru (kodda)
    cn_dogru = {k["adres"] for k in kayitlar if k["nufusta"] and k["durum"] == uvo.DOGRU}
    birlesik = cn_dogru | uv_nufus_dogru
    return {"schema": SEMA, "olcum": "urun", "ad": ad, "kosu": str(kosu), "girdi_sha256": man["stripped_sha256"],
            "hedef_tanimi": {"atlanan": dict(atlanan), "ozet": uvo.urun_ozeti(kayitlar, nufus)},
            "ust_veri": dict(say), "nufus": len(nufus),
            "nufusta_dogru": {"c_namer": len(cn_dogru), "ust_veri": len(uv_nufus_dogru),
                              "birlesik": len(birlesik)},
            "ghidra": uvo.ghidra_gt_ozeti(gt, gfonk)}


# =============================================================================================
# CLI


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    alt = ap.add_subparsers(dest="komut", required=True)
    o = alt.add_parser("oynat")
    o.add_argument("--ws", type=Path, required=True, help="çalışma alanı (static/ içeren dizin)")
    o.add_argument("--ikili", type=Path, required=True)
    o.add_argument("--json", type=Path)
    a = alt.add_parser("aday-gt")
    a.add_argument("--ad", required=True)
    a.add_argument("--set-kok", type=Path, default=us.VARSAYILAN_KOK)
    a.add_argument("--sinama-izni", action="store_true")
    a.add_argument("--json", type=Path)
    k = alt.add_parser("kos")
    k.add_argument("--girdi", type=Path, help="girdi yolu (verilmezse --ad'ın soyulmuş kopyası)")
    k.add_argument("--sha256", help="--girdi verildiyse zorunlu")
    k.add_argument("--ad", help="setteki ad")
    k.add_argument("--set-kok", type=Path, default=us.VARSAYILAN_KOK)
    k.add_argument("--anahtar", required=True)
    k.add_argument("--agac", type=Path, required=True)
    k.add_argument("--kok", type=Path, required=True)
    k.add_argument("--config", type=Path)
    k.add_argument("--zaman-asimi", type=int, default=3600)
    u = alt.add_parser("urun")
    u.add_argument("--ad", required=True)
    u.add_argument("--set-kok", type=Path, default=us.VARSAYILAN_KOK)
    u.add_argument("--kok", type=Path, required=True)
    u.add_argument("--anahtar")
    u.add_argument("--json", type=Path)
    x = ap.parse_args(argv)
    if x.komut == "oynat":
        uvo._yaz(x.json, oynat(x.ws.expanduser(), x.ikili.expanduser()))
    elif x.komut == "aday-gt":
        uvo._yaz(x.json, aday_gt(x.ad, x.set_kok.expanduser(), x.sinama_izni))
    elif x.komut == "kos":
        if x.girdi is not None:
            if not x.sha256:
                raise SystemExit("--girdi ile --sha256 zorunlu")
            girdi, sha = x.girdi.expanduser(), x.sha256
        else:
            man = us.manifest_oku(x.set_kok.expanduser())["ikililer"][x.ad]
            if not man["soyma"]["temiz"]:
                raise SystemExit(f"{x.ad}: soyulmuş kopyada sembol kaldı; ürün koşusu GT sızdırır")
            girdi, sha = us.yollar(x.set_kok.expanduser(), x.ad)["bin"], man["stripped_sha256"]
        s = kos(girdi, sha, x.agac.expanduser().resolve(), x.kok.expanduser().resolve(),
                x.config.expanduser().resolve() if x.config else None, x.zaman_asimi, x.anahtar)
        print(json.dumps(s, ensure_ascii=False))
        return 0 if s["durum"] in ("tamam", "kismi") else 1
    elif x.komut == "urun":
        uvo._yaz(x.json, urun(x.ad, x.set_kok.expanduser(), x.kok.expanduser(), x.anahtar))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
