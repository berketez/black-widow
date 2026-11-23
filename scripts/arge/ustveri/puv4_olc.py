"""P-ÜV4 ölçümleri (ön kayıt ``docs/arge/2026-11-19_mythos/ustveri/on_kayit_PUV4.md``).

Alt komutlar (worktree kökünden ``PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ustveri/puv4_olc.py …``):

- ``ornek --kok <dizin>``        H0 + H6 (yerel örnekler; ``cpp_ornek/derle.py`` çıktısı)
- ``say <ad> …``                  H1 / H3 sayıları (``$V/rtti/<ad>.json``'ın YALNIZ ``typeinfo`` / ``vtable`` /
                                  ``ayrik_islev`` alanları okunur; sembol karşılaştırması alanı açılmaz)
- ``h3``                          Ollama iki dilim + zayıf bağ çözümü kapalı (süreç içinde, dosya değişmez)
- ``h4 [--deneme 200]``           bulanık girdi (btop, ayrıca pzstd)
- ``h5``                          ELF pzstd ↔ dbgsym ``.symtab``
- ``h6``                          btop'ta ``Sınıf_vfunc_N`` ↔ sembol tam eşitliği
- ``sinama --sinama-izni``        H2: btop + iTerm2 + llama-server (+ Ollama x86_64 ``_ZTI``), BİR KEZ, dondurmadan sonra

Çıktılar ``--cikti`` dizinine (öntanım ``~/karadul_olcum/runs/dalga1-2026-11-23/PUV4/ozet``). Hiçbir ikili çalıştırılmaz.
Depoya ad listesi yazılmaz; JSON'lar depo dışında.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

KOK = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(KOK))
sys.path.insert(0, str(KOK / "scripts" / "measurement"))

from karadul.analyzers.ustveri import cpp_rtti_tara as rt  # noqa: E402
from karadul.analyzers.ustveri import goruntu as gr  # noqa: E402
from ks1_olc import oran  # noqa: E402  (Wilson %95)

V = Path.home() / "karadul_olcum/runs/arge-2026-11-19/ustveri"
OZET = Path.home() / "karadul_olcum/runs/dalga1-2026-11-23/PUV4/ozet"
PZSTD = Path.home() / "karadul_olcum/downloads/debian13/x_zstd_1.5.7+dfsg-1_arm64/usr/bin/pzstd"
PZSTD_GT = (Path.home() / "karadul_olcum/downloads/debian13/x_zstd-dbgsym_1.5.7+dfsg-1_arm64/usr/lib/debug"
            / ".build-id/7e/170a7ec030c257c2a884cc2bcc4b459ebdad4e.debug")
SINAMA = ("llama-server.arm64", "iTerm2.arm64")
KESIF_HEDEF = ("btop", "Ollama.arm64", "Ollama.x86_64")
THUNK_ONEKLERI = ("_ZTh", "_ZTv", "_ZTc")
SAYI_ALANLARI = ("typeinfo", "vtable", "ayrik_islev")


def _normal(ad: str) -> str:
    return ad[1:] if ad.startswith("__Z") else ad


def _govde(ad: str) -> str:
    return ad[1:-1] if ad.startswith("N") and ad.endswith("E") else ad


def _wilson(k: int, n: int) -> dict[str, Any]:
    if n == 0:
        return {"pay": k, "payda": n, "oran": None, "alt": None, "ust": None}
    o = oran(k, n)
    alt, ust = o["aralik"]
    return {"pay": k, "payda": n, "oran": o["oran"], "alt": alt, "ust": ust}


def _yaz(cikti: Path, ad: str, veri: Any) -> None:
    cikti.mkdir(parents=True, exist_ok=True)
    (cikti / f"{ad}.json").write_text(json.dumps(veri, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


def sembol_gt(g: gr.Goruntu) -> dict[str, Any]:
    """Tanımlı ``_ZTI`` / ``_ZTV`` sembolleri ve kod sembolleri (adres → ad; Mach-O öneki soyulmuş)."""
    zti: dict[int, str] = {}
    ztv: dict[int, str] = {}
    kod: dict[int, list[str]] = {}
    for s in g.semboller():
        if not s.ad or s.tur in (gr.SEMBOL_TANIMSIZ, gr.SEMBOL_HATA_AYIKLAMA, gr.SEMBOL_DIGER):
            continue
        ad = _normal(s.ad)
        if ad.startswith("_ZTI"):
            zti.setdefault(s.adres, ad)
        elif ad.startswith("_ZTV"):
            ztv.setdefault(s.adres, ad)
        if s.tur == gr.SEMBOL_KOD:
            kod.setdefault(s.adres, []).append(ad)
    return {"ZTI": zti, "ZTV": ztv, "kod": kod}


def sinif_turu(t: rt.TypeinfoKaydi, ti: dict[int, rt.TypeinfoKaydi]) -> str:
    if t.yerel_ad or "_GLOBAL__N" in t.ad:
        return "adsiz_ad_alani"
    if "I" in t.ad and t.ad.endswith("E") and ("IE" in t.ad or "EE" in t.ad or "I" in _govde(t.ad)):
        if t.cozulmus and "<" in t.cozulmus:
            return "sablon"
    if any(b.sanal for b in t.tabanlar):
        return "sanal_kalitim"
    return "obur"


def gt_karsilastir(s: rt.RttiSonuc, gt: dict[str, Any], g: gr.Goruntu | None = None) -> dict[str, Any]:
    """Ön kayıt §2: typeinfo adı, vtable (başvuru tanımı), yuva → sınıf (a: başvuru kuralı, b: ürün bağı)."""
    ti = s.ti_sozlugu()
    zti, ztv, kod = gt["ZTI"], gt["ZTV"], gt["kod"]
    # typeinfo adı
    t_pay = t_payda = 0
    t_yanlis: Counter = Counter()
    for t in s.typeinfolar:
        if t.adres in zti:
            t_payda += 1
            if zti[t.adres] == "_ZTI" + t.ad:
                t_pay += 1
            else:
                t_yanlis[sinif_turu(t, ti)] += 1
    kacan_ti: Counter = Counter()
    for a, ad in zti.items():
        if a in ti:
            continue
        tur = "sinif_disi_ya_da_okunamadi"
        if g is not None:
            p = g.gosterici(a)
            if isinstance(p, gr.Bag) and _normal(p.ad) in rt.CXXABI_TI_VTABLE:
                tur = "sinif_typeinfo"
        kacan_ti[tur] += 1
    # vtable (başvuru tanımı: birincil vtable adresi = _ZTV sembolü)
    v_pay = v_payda = 0
    v_yanlis: Counter = Counter()
    birincil_adres = {v.adres for v in s.vtablelar if v.birincil}
    for v in s.vtablelar:
        if v.birincil and v.adres in ztv:
            v_payda += 1
            if ztv[v.adres] == "_ZTV" + ti[v.typeinfo].ad:
                v_pay += 1
            else:
                v_yanlis[sinif_turu(ti[v.typeinfo], ti)] += 1
    kacan_vt = sum(1 for a in ztv if a not in birincil_adres)

    def tabanlar(t: int, gor: set[int] | None = None) -> set[str]:
        gor = gor if gor is not None else set()
        if t in gor or t not in ti:
            return set()
        gor.add(t)
        out = {ti[t].ad}
        for b in ti[t].tabanlar:
            if b.typeinfo is not None:
                out |= tabanlar(b.typeinfo, gor)
        return out

    a_dogru = a_yanlis = b_dogru = b_yanlis = thunk = sembollu = belirsiz_sembollu = 0
    a_yanlis_tur: Counter = Counter()
    b_yanlis_tur: Counter = Counter()
    for i in s.islevler:
        adlar = kod.get(i.adres)
        if not adlar:
            continue
        sembollu += 1
        if any(n.startswith(THUNK_ONEKLERI) for n in adlar):
            thunk += 1
            continue
        govdeler: set[str] = set()
        for c in i.siniflar:
            govdeler |= {_govde(x) for x in tabanlar(c)}
        if any(gv in n for gv in govdeler for n in adlar):
            a_dogru += 1
        else:
            a_yanlis += 1
            a_yanlis_tur[sinif_turu(ti[i.siniflar[0]], ti)] += 1
        if i.sinif is None:
            belirsiz_sembollu += 1
            continue
        bg = {_govde(x) for x in tabanlar(i.sinif)}
        if any(gv in n for gv in bg for n in adlar):
            b_dogru += 1
        else:
            b_yanlis += 1
            b_yanlis_tur[sinif_turu(ti[i.sinif], ti)] += 1
    return {
        "typeinfo_adi": {**_wilson(t_pay, t_payda), "yanlis_sinif_turu": dict(t_yanlis),
                         "kacan_ZTI": dict(kacan_ti), "ZTI_sembolu": len(zti)},
        "vtable": {**_wilson(v_pay, v_payda), "yanlis_sinif_turu": dict(v_yanlis),
                   "ZTV_adresinde_birincil_vtable_yok": kacan_vt, "ZTV_sembolu": len(ztv)},
        "yuva_a_basvuru_kurali": {**_wilson(a_dogru, a_dogru + a_yanlis), "sembollu": sembollu, "thunk": thunk,
                                  "yanlis_sinif_turu": dict(a_yanlis_tur)},
        "yuva_b_urun_bagi": {**_wilson(b_dogru, b_dogru + b_yanlis), "belirsiz_sembollu": belirsiz_sembollu,
                             "yanlis_sinif_turu": dict(b_yanlis_tur)},
    }


def _cikti_ozu(s: rt.RttiSonuc) -> dict[str, Any]:
    """Fark 0 karşılaştırması için tarayıcının tam çıktısı (süre hariç)."""
    ti = s.ti_sozlugu()
    o = s.ozet()
    o.pop("sure_sn", None)
    return {"ozet": o, "typeinfolar": [t.as_dict() for t in s.typeinfolar],
            "vtablelar": [v.as_dict() for v in s.vtablelar], "islevler": [i.as_dict(ti) for i in s.islevler],
            "rtti_classes": s.rtti_classes()}


def h6_say(s: rt.RttiSonuc, kod: dict[int, list[str]]) -> dict[str, Any]:
    """``Sınıf_vfunc_N`` adayının sembolle (ham ya da çözülmüş) tam eşitliği."""
    from karadul.analyzers.cpp_rtti import batch_demangle

    adaylar = []
    for c in s.rtti_classes():
        for n, a in enumerate(c["methods"]):
            if a:
                adaylar.append((a, f"{c['name']}_vfunc_{n}"))
    tum = sorted({n for a, _ in adaylar for n in kod.get(a, [])})
    coz = batch_demangle(tum) if tum else {}
    sembollu = esit = 0
    for a, aday in adaylar:
        adlar = kod.get(a, [])
        if not adlar:
            continue
        sembollu += 1
        if any(aday == n or aday == coz.get(n) for n in adlar):
            esit += 1
    return {"aday": len(adaylar), "sembollu_aday": sembollu, "tam_esit": esit}


# ---- alt komutlar -----------------------------------------------------------------------------------------------

def k_ornek(a: argparse.Namespace) -> dict[str, Any]:
    out: dict[str, Any] = {}
    siniflar: dict[str, set[str]] = {}
    for d in sorted(p for p in a.kok.iterdir() if p.is_dir()):
        g1 = gr.ac(d / "ornek")
        g2 = gr.ac(d / "ornek.soyulmus")
        s1, s2 = rt.tara(g1), rt.tara(g2)
        gt = sembol_gt(g1)
        k = gt_karsilastir(s1, gt, g1)
        fark = _cikti_ozu(s1) != _cikti_ozu(s2)
        siniflar[d.name] = {t.gorunen_ad for t in s1.typeinfolar}
        out[d.name] = {"durum": s1.durum, "ozet": s1.ozet(), "gt": k, "soyulmus_fark_var": fark,
                       "soyulmus_ozet": s2.ozet(), "h6": h6_say(s1, gt["kod"])}
    for o in ("O0", "O2"):
        a64, x64 = siniflar.get(f"arm64_{o}"), siniflar.get(f"x86_64_{o}")
        out[f"sinif_kumesi_ayni_{o}"] = a64 == x64 if a64 is not None and x64 is not None else None
    return out


def _say(ad: str) -> dict[str, Any]:
    g = gr.ac(V / "hedef" / ad)
    t0 = time.monotonic()
    s = rt.tara(g)
    sure = round(time.monotonic() - t0, 3)
    o = s.ozet()
    benim = {"typeinfo": o["typeinfo"], "vtable": o["vtable"], "ayrik_islev": o["ayrik_islev"]}
    bas = json.loads((V / "rtti" / f"{ad}.json").read_text(encoding="utf-8"))
    basvuru = {k: bas.get(k) for k in SAYI_ALANLARI}  # yalnız sayım alanları
    return {"durum": s.durum, "benim": benim, "basvuru": basvuru, "ayni": benim == basvuru, "ozet": o,
            "tarama_suresi_sn": sure}


def k_say(a: argparse.Namespace) -> dict[str, Any]:
    for ad in a.adlar:
        if ad in SINAMA and not a.sinama_izni:
            raise SystemExit(f"{ad} sınama ikilisi: dondurmadan önce açılmaz (--sinama-izni)")
    return {ad: _say(ad) for ad in a.adlar}


class _ZayifsizTarayici(rt.RttiTarayici):
    """H3 mutantı: zayıf bağ adı yerel adrese çevrilmez (süreç içinde; ürün dosyası değişmez)."""

    def _yerel(self) -> dict[str, int]:
        return {}


def k_h3(a: argparse.Namespace) -> dict[str, Any]:
    out = {ad: _say(ad) for ad in ("Ollama.arm64", "Ollama.x86_64")}
    g = gr.ac(V / "hedef" / "Ollama.x86_64")
    s = _ZayifsizTarayici(g).tara()
    out["mutant_x86_64"] = s.ozet()
    out["H3"] = {"iki_dilim_ayni_19_8_68": all(out[d]["benim"] == {"typeinfo": 19, "vtable": 8, "ayrik_islev": 68}
                                               for d in ("Ollama.arm64", "Ollama.x86_64")),
                 "mutant_typeinfo": s.ozet()["typeinfo"], "mutant_en_cok_4": s.ozet()["typeinfo"] <= 4}
    return out


def _fuzz(yol: Path, deneme: int, bayt: int, tohum: int) -> dict[str, Any]:
    veri = yol.read_bytes()
    g = gr.baytlardan(veri)
    s = rt.tara(g)
    if not s.typeinfolar:
        return {"durum": s.durum, "not": "typeinfo yok: bölge seçilemedi"}
    bolum = g.adres_bolumu(s.typeinfolar[0].adres)
    ofs = bolum.dosya_ofseti
    if ofs is None and hasattr(g, "dosya_ofseti"):
        ofs = g.dosya_ofseti(bolum.adres)
    rng = random.Random(tohum)
    istisna = asim = 0
    durumlar: Counter = Counter()
    en_uzun = 0.0
    for _ in range(deneme):
        kopya = bytearray(veri)
        for _ in range(bayt):
            kopya[ofs + rng.randrange(bolum.boyut)] = rng.randrange(256)
        t0 = time.monotonic()
        try:
            gg = gr.baytlardan(bytes(kopya))
            ss = rt.tara(gg, sure_siniri=rt.SURE_SINIRI_SN)
            durumlar[ss.durum] += 1
            if ss.durum == rt.DURUM_HATA and "süre sınırı" in (ss.neden or ""):
                asim += 1
        except Exception:  # tarayıcı istisna atmamalı; görüntü kurulumu da sayılır
            istisna += 1
        gecen = time.monotonic() - t0
        en_uzun = max(en_uzun, gecen)
        if gecen > rt.SURE_SINIRI_SN:
            asim += 1
    return {"bolum": bolum.tam_ad, "bolum_boyutu": bolum.boyut, "deneme": deneme, "bozulan_bayt": bayt,
            "tohum": tohum, "istisna": istisna, "sure_asimi": asim, "durumlar": dict(durumlar),
            "en_uzun_sn": round(en_uzun, 3)}


def k_h4(a: argparse.Namespace) -> dict[str, Any]:
    return {"btop": _fuzz(V / "hedef" / "btop", a.deneme, a.bayt, 20261123),
            "pzstd": _fuzz(PZSTD, a.deneme, a.bayt, 20261124)}


def k_h5(a: argparse.Namespace) -> dict[str, Any]:
    g = gr.ac(PZSTD)
    s = rt.tara(g)
    gtg = gr.ac(PZSTD_GT)
    gt = sembol_gt(gtg)
    k = gt_karsilastir(s, gt, g)
    ta = k["typeinfo_adi"]
    return {"durum": s.durum, "neden": s.neden, "ozet": s.ozet(), "gt": k,
            "H5": {"vtable_en_az_1": s.ozet()["vtable"] >= 1,
                   "ad_esitligi_en_az_yuzde_99": ta["oran"] is not None and ta["oran"] >= 0.99}}


def k_h6(a: argparse.Namespace) -> dict[str, Any]:
    g = gr.ac(V / "hedef" / "btop")
    s = rt.tara(g)
    gt = sembol_gt(g)
    return {"btop": {"h6": h6_say(s, gt["kod"]), "gt": gt_karsilastir(s, gt, g)}}


def k_sinama(a: argparse.Namespace) -> dict[str, Any]:
    if not a.sinama_izni:
        raise SystemExit("H2 yalnız --sinama-izni ile (tarayıcı dondurulduktan sonra, bir kez)")
    out: dict[str, Any] = {}
    toplam = Counter()
    for ad in ("btop", "iTerm2.arm64", "llama-server.arm64"):
        g = gr.ac(V / "hedef" / ad)
        t0 = time.monotonic()
        s = rt.tara(g)
        sure = round(time.monotonic() - t0, 3)
        gt = sembol_gt(g)
        k = gt_karsilastir(s, gt, g)
        out[ad] = {"durum": s.durum, "ozet": s.ozet(), "gt": k, "tarama_suresi_sn": sure}
        for anahtar, alan in (("ti", "typeinfo_adi"), ("vt", "vtable"), ("ya", "yuva_a_basvuru_kurali"),
                              ("yb", "yuva_b_urun_bagi")):
            toplam[anahtar + "_pay"] += k[alan]["pay"]
            toplam[anahtar + "_payda"] += k[alan]["payda"]
    g = gr.ac(V / "hedef" / "Ollama.x86_64")
    s = rt.tara(g)
    k = gt_karsilastir(s, sembol_gt(g), g)
    out["Ollama.x86_64"] = {"durum": s.durum, "gt_typeinfo_adi": k["typeinfo_adi"]}
    toplam["ti_pay"] += k["typeinfo_adi"]["pay"]
    toplam["ti_payda"] += k["typeinfo_adi"]["payda"]
    out["toplam"] = {
        "typeinfo_adi": _wilson(toplam["ti_pay"], toplam["ti_payda"]),
        "vtable": _wilson(toplam["vt_pay"], toplam["vt_payda"]),
        "yuva_a_basvuru_kurali": _wilson(toplam["ya_pay"], toplam["ya_payda"]),
        "yuva_b_urun_bagi": _wilson(toplam["yb_pay"], toplam["yb_payda"]),
    }
    t = out["toplam"]
    out["H2"] = {
        "typeinfo_2028_2028": t["typeinfo_adi"]["pay"] == 2028 and t["typeinfo_adi"]["payda"] == 2028,
        "vtable_1328_1328": t["vtable"]["pay"] == 1328 and t["vtable"]["payda"] == 1328,
        "yuva_a_en_az_7098_7119": t["yuva_a_basvuru_kurali"]["pay"] >= 7098
        and (t["yuva_a_basvuru_kurali"]["alt"] or 0) >= 0.99,
        "yuva_b_wilson_alt_en_az_0_99": (t["yuva_b_urun_bagi"]["alt"] or 0) >= 0.99,
    }
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--cikti", type=Path, default=OZET)
    alt = ap.add_subparsers(dest="komut", required=True)
    p = alt.add_parser("ornek")
    p.add_argument("--kok", type=Path, required=True)
    p = alt.add_parser("say")
    p.add_argument("adlar", nargs="+")
    p.add_argument("--sinama-izni", action="store_true")
    alt.add_parser("h3")
    p = alt.add_parser("h4")
    p.add_argument("--deneme", type=int, default=200)
    p.add_argument("--bayt", type=int, default=200)
    alt.add_parser("h5")
    alt.add_parser("h6")
    p = alt.add_parser("sinama")
    p.add_argument("--sinama-izni", action="store_true")
    a = ap.parse_args(argv)
    islev = {"ornek": k_ornek, "say": k_say, "h3": k_h3, "h4": k_h4, "h5": k_h5, "h6": k_h6, "sinama": k_sinama}
    t0 = time.monotonic()
    sonuc = islev[a.komut](a)
    sonuc = {"komut": a.komut, "sure_sn": round(time.monotonic() - t0, 2), "sonuc": sonuc}
    ad = a.komut if a.komut != "say" else "say_" + "_".join(a.adlar)
    _yaz(a.cikti, ad, sonuc)
    print(json.dumps(sonuc, ensure_ascii=False, indent=1, default=str)[:20000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
