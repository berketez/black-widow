"""P-ÜV3 ölçümleri: Swift okuyucusunun (``karadul.analyzers.ustveri.swift``) keşif ve sınama sayımları.

Alt komutlar (hepsi ikiliyi yalnız okur; hiçbir ikili çalıştırılmaz):

    ornek  <sembollü> <soyulmuş> [--cikti x.json]
        H0: sembollü kopyada GT (``Mn`` / ``Ma`` sembolleri + ``xcrun swift-demangle``) ile okuyucu çıktısı;
        soyulmuş kopyada okuyucu çıktısı sembollüyle aynı mı.
    sayi   <ikili> --basvuru <swift_meta.json> [--cikti x.json]
        H1: H1 sayıları başvuruyla (araştırma ``swift_meta.py`` çıktısı) aynı mı. GT'ye bakmaz.
    veri-yok <ikili> ... [--cikti x.json]
        H5: Swift'siz ikililerde okuyucu durumu ``veri_yok`` mu.
    sinama <ikili> --sinama-izni [--cikti x.json]
        H2 + H3 (SINAMA, okuyucu dondurulduktan sonra BİR kez): erişim / tanık sembol ekleri ve nitelikli ad
        tam eşitliği. Çıktıya ad yazılmaz (yalnız sayı); depo herkese açık.

Kullanım: depo kökünden ``PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ustveri/puv3_olc.py <alt komut> …``.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from karadul.analyzers.ustveri import goruntu, swift  # noqa: E402

DEMANGLE = ["/usr/bin/xcrun", "swift-demangle"]
ON_MN = "nominal type descriptor for "
ON_MA = swift.ACCESSOR_PREFIX


def _oran(k: int, n: int):
    try:
        from scripts.measurement.ks1_olc import oran  # Wilson %95
        return oran(k, n)
    except Exception as exc:  # ölçüm aracı yoksa yalnız ham oran
        return {"k": k, "n": n, "not": f"ks1_olc.oran yok: {exc}"}


def demangle(adlar: list[str]) -> list[str]:
    if not adlar:
        return []
    out = subprocess.run(DEMANGLE, input="\n".join(adlar) + "\n", capture_output=True, text=True,
                         timeout=600).stdout.splitlines()
    if len(out) != len(adlar):
        raise RuntimeError(f"swift-demangle satır sayısı tutmadı: {len(out)} / {len(adlar)}")
    return out


def swift_sembolleri(g) -> tuple[dict[int, list[str]], dict[int, list[str]]]:
    """(``Mn`` adres → demangle edilmiş tip adları, ``Ma`` adres → tip adları)."""
    mn, ma = [], []
    for s in g.semboller():
        ad = s.ad[1:] if s.ad.startswith("_") else s.ad
        if s.tur not in (goruntu.SEMBOL_KOD, goruntu.SEMBOL_VERI) or not ad.startswith("$s"):
            continue
        if ad.endswith("Mn"):
            mn.append((s.adres, ad))
        elif ad.endswith("Ma"):
            ma.append((s.adres, ad))
    d_mn = demangle([a for _, a in mn])
    d_ma = demangle([a for _, a in ma])
    r_mn: dict[int, list[str]] = defaultdict(list)
    r_ma: dict[int, list[str]] = defaultdict(list)
    for (adr, _), d in zip(mn, d_mn):
        if d.startswith(ON_MN):
            r_mn[adr].append(d[len(ON_MN):])
    for (adr, _), d in zip(ma, d_ma):
        if d.startswith(ON_MA):
            r_ma[adr].append(d[len(ON_MA):])
    return r_mn, r_ma


def okuyucu(yol: str):
    g = goruntu.ac(yol)
    t0 = time.monotonic()
    s = swift.oku(g)
    return g, s, round(time.monotonic() - t0, 3)


def imza(s) -> dict:
    """Sembollü / soyulmuş karşılaştırması için okuyucu çıktısının tamamı (adres, tür, ad, erişim, yuvalar)."""
    return {
        "durum": s.durum,
        "tipler": [(t.adres, t.tur, t.genel, t.kisa_ad, t.nitelikli_ad, t.ad_neden, t.alt_kume, t.erisim,
                    t.erisim_kodda, t.erisim_baslangic, t.artci_cozuldu) for t in s.tipler],
        "yuvalar": [tuple(sorted((k, str(v)) for k, v in y.items())) for y in s.yuvalar],
        "sayaclar": dict(s.sayaclar),
    }


def kom_ornek(a) -> dict:
    g, s, sure = okuyucu(a.sembollu)
    _g2, s2, _ = okuyucu(a.soyulmus)
    mn, ma = swift_sembolleri(g)
    ma_ters: dict[str, set[int]] = defaultdict(set)
    for adr, adlar in ma.items():
        for x in adlar:
            ma_ters[x].add(adr)
    tipler = {t.adres: t for t in s.tipler}
    okunan = [adr for adr in mn if adr in tipler]
    alt = defaultdict(Counter)
    yanlis_ornek = []
    erisim_ayni = erisim_bakilan = 0
    for adr in sorted(mn):
        gt_adlar = mn[adr]
        t = tipler.get(adr)
        if t is None:
            continue
        # erişim fonksiyonu adresi = aynı tipin Ma sembolünün adresi
        gt_erisim = set().union(*(ma_ters.get(x, set()) for x in gt_adlar))
        if gt_erisim:
            erisim_bakilan += 1
            if t.erisim in gt_erisim:
                erisim_ayni += 1
        k = alt[t.alt_kume]
        k["tip"] += 1
        if t.nitelikli_ad is None:
            k["adsiz_birakilan"] += 1
            k[f"neden:{t.ad_neden}"] += 1
            continue
        k["ad_verilen"] += 1
        if t.nitelikli_ad in gt_adlar:
            k["dogru"] += 1
        else:
            k["yanlis"] += 1
            yanlis_ornek.append({"adres": f"{adr:#x}", "okuyucu": t.nitelikli_ad, "gt": gt_adlar})
    fark = imza(s) != imza(s2)
    return {
        "sembollu": a.sembollu, "soyulmus": a.soyulmus, "durum": s.durum, "neden": s.neden,
        "okuma_suresi_sn": sure, "tip": len(s.tipler), "Mn_sembollu_tip": len(mn),
        "Mn_okunan": len(okunan), "Mn_okunmayan": len(mn) - len(okunan),
        "okuyucuda_Mn_sembolsuz": len([t for t in s.tipler if t.adres not in mn]),
        "erisim_Ma_ayni": f"{erisim_ayni} / {erisim_bakilan}",
        "alt_kume": {k: dict(v) for k, v in sorted(alt.items())},
        "yanlis": yanlis_ornek,
        "soyulmus_fark": fark,
        "soyulmus_durum": s2.durum,
        "sayaclar": dict(s.sayaclar),
        "denetim": s.denetim,
        "swift_types": len(s.swift_types()),
        "swift_slots": len(s.swift_slots()),
        "swift_slots_ad_alani": sum(1 for y in s.swift_slots() if "ad" in y or "nitelikli_ad" in y),
    }


H1_ALANLARI = [
    ("tip", lambda r: r["tip"], lambda s: len(s.tipler)),
    ("erisim_fonksiyonu", lambda r: r["erisim_fonksiyonu"], lambda s: s.denetim["erisim_fonksiyonu"]),
    ("yontem_betimleyici", lambda r: r["vtable"]["yontem_betimleyici"], lambda s: s.denetim["yontem_betimleyici"]),
    ("impl_kodda", lambda r: r["vtable"]["impl_kodda"], lambda s: s.denetim["impl_kodda"]),
    ("tanik_kod_gostericisi_ayrik", lambda r: r["uyum"]["tanik_kod_gostericisi_ayrik"],
     lambda s: s.denetim["tanik_kod_gostericisi_ayrik"]),
]
BILGI_ALANLARI = [
    ("tur", lambda r: r["tur"], lambda s: dict(Counter(t.tur for t in s.tipler))),
    ("genel_tip", lambda r: r["genel_tip"], lambda s: sum(1 for t in s.tipler if t.genel)),
    ("erisim_kodda", lambda r: r["erisim_kodda"], lambda s: s.denetim["erisim_kodda"]),
    ("erisim_fonksiyon_baslangici", lambda r: r["erisim_fonksiyon_baslangici"],
     lambda s: s.denetim["erisim_fonksiyon_baslangici"]),
    ("cozulen_sinif", lambda r: r["vtable"]["cozulen_sinif"], lambda s: s.denetim["artci_cozulen_sinif"]),
    ("impl_bos", lambda r: r["vtable"]["impl_bos"], lambda s: s.denetim["impl_bos"]),
    ("ayrik_impl", lambda r: r["vtable"]["ayrik_impl"], lambda s: s.denetim["ayrik_impl"]),
    ("vtable_tur", lambda r: r["vtable"]["tur"], lambda s: s.denetim["yontem_turu"]),
    ("gecersiz_kilma_kaydi", lambda r: r["vtable"]["gecersiz_kilma_kaydi"],
     lambda s: s.denetim["gecersiz_kilma_kaydi"]),
    ("gecersiz_kilma_ayrik_impl", lambda r: r["vtable"]["gecersiz_kilma_ayrik_impl"],
     lambda s: s.denetim["gecersiz_kilma_ayrik_impl"]),
    ("uyum_kaydi", lambda r: r["uyum"]["uyum_kaydi"], lambda s: s.denetim["uyum_kaydi"]),
    ("yerel_protokole", lambda r: r["uyum"]["yerel_protokole"], lambda s: s.denetim["yerel_protokole"]),
    ("tanik_tablosu_olan", lambda r: r["uyum"]["tanik_tablosu_olan"], lambda s: s.denetim["tanik_tablosu_olan"]),
    ("ilk_sozcugu_dogrulanan", lambda r: r["uyum"]["ilk_sozcugu_dogrulanan"],
     lambda s: s.denetim["ilk_sozcugu_dogrulanan"]),
    ("tanik_fonksiyon_baslangici", lambda r: r["uyum"]["tanik_fonksiyon_baslangici"],
     lambda s: s.denetim["tanik_fonksiyon_baslangici"]),
]


def kom_sayi(a) -> dict:
    r = json.loads(Path(a.basvuru).read_text())
    _g, s, sure = okuyucu(a.ikili)
    h1 = {ad: {"basvuru": fr(r), "okuyucu": fs(s), "ayni": fr(r) == fs(s)} for ad, fr, fs in H1_ALANLARI}
    bilgi = {ad: {"basvuru": fr(r), "okuyucu": fs(s), "ayni": fr(r) == fs(s)} for ad, fr, fs in BILGI_ALANLARI}
    ozet = s.ozet()
    return {
        "ikili": a.ikili, "durum": s.durum, "neden": s.neden, "okuma_suresi_sn": sure,
        "H1_tuttu": all(v["ayni"] for v in h1.values()), "H1": h1, "bilgi": bilgi,
        "alt_kume": ozet["alt_kume"], "alt_kume_adli": ozet["alt_kume_adli"],
        "nitelikli_ad": ozet["nitelikli_ad"], "ad_yazilabilir": ozet["ad_yazilabilir"],
        "okuma_hatasi": s.okuma_hatasi, "sayaclar": dict(s.sayaclar),
        "H4_swift_types_yuva_kaynakli": sum(1 for x in s.swift_types() if "tur" in x and x["tur"] in
                                            (swift.YUVA_VTABLE, swift.YUVA_GECERSIZ_KILMA, swift.YUVA_TANIK)),
        "H4_swift_slots_ad_alani": sum(1 for y in s.swift_slots() if "ad" in y or "nitelikli_ad" in y),
        "swift_slots": len(s.swift_slots()),
    }


def kom_veri_yok(a) -> dict:
    out = {}
    for yol in a.ikililer:
        try:
            g = goruntu.ac(yol)
            s = swift.oku(g)
            out[yol] = {"durum": s.durum, "neden": s.neden, "tip": len(s.tipler)}
        except goruntu.GoruntuHatasi as exc:
            out[yol] = {"durum": f"goruntu:{exc.durum}", "neden": exc.neden, "tip": None}
    return {"H5_tuttu": all(v["durum"] == swift.DURUM_VERI_YOK and v["tip"] == 0 for v in out.values()),
            "ikililer": out}


def kom_sinama(a) -> dict:
    if not a.sinama_izni:
        raise SystemExit("sınama ikilisi: --sinama-izni olmadan açılmaz (okuyucu dondurulduktan sonra BİR kez)")
    g, s, sure = okuyucu(a.ikili)
    # H2: sembol ekleri (adres başına herhangi bir sembol)
    sym: dict[int, list[str]] = defaultdict(list)
    for x in g.semboller():
        if x.tur == goruntu.SEMBOL_KOD:
            sym[x.adres].append(x.ad[1:] if x.ad.startswith("_") else x.ad)
    erisim = {t.erisim for t in s.tipler if t.erisim is not None}
    tanik = {y["adres"] for y in s.yuvalar if y["tur"] == swift.YUVA_TANIK}

    def ek(adresler, ekler):
        var = uyan = 0
        for adr in adresler:
            if adr not in sym:
                continue
            var += 1
            if any(n.endswith(ekler) for n in sym[adr]):
                uyan += 1
        return var, uyan

    e_var, e_ma = ek(erisim, ("Ma",))
    w_var, w_tw = ek(tanik, ("TW", "TWTm"))
    # H3: nitelikli ad tam eşitliği (Ma sembolünün demangle çıktısı)
    _mn, ma = swift_sembolleri(g)
    alt = defaultdict(Counter)
    for t in s.tipler:
        k = alt[t.alt_kume]
        k["tip"] += 1
        if t.nitelikli_ad is None:
            k["adsiz_birakilan"] += 1
            continue
        k["ad_verilen"] += 1
        gt = ma.get(t.erisim) if t.erisim is not None else None
        if not gt:
            k["gt_yok"] += 1
        elif t.nitelikli_ad in gt:
            k["dogru"] += 1
        else:
            k["yanlis"] += 1
    toplam = Counter()
    for v in alt.values():
        toplam.update(v)
    ad_verilen = toplam["ad_verilen"]
    yanlis = toplam["yanlis"]
    return {
        "ikili": a.ikili, "durum": s.durum, "okuma_suresi_sn": sure, "tip": len(s.tipler),
        "H2_erisim_Ma": f"{e_ma} / {e_var}", "H2_tanik_TW": f"{w_tw} / {w_var}",
        "H2_tuttu": (e_ma, e_var) == (3659, 3659) and (w_tw, w_var) == (741, 741),
        "H3_ad_verilen": ad_verilen, "H3_dogru": toplam["dogru"], "H3_yanlis": yanlis,
        "H3_gt_yok": toplam["gt_yok"],
        "H3_yanlis_orani": (yanlis / ad_verilen) if ad_verilen else None,
        "H3_dogru_wilson": _oran(toplam["dogru"], toplam["dogru"] + yanlis),
        "H3_tuttu": ad_verilen >= 3477 and ad_verilen and yanlis / ad_verilen <= 0.01,
        "alt_kume": {k: dict(v) for k, v in sorted(alt.items())},
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    alt = ap.add_subparsers(dest="komut", required=True)
    p = alt.add_parser("ornek")
    p.add_argument("sembollu")
    p.add_argument("soyulmus")
    p.add_argument("--cikti")
    p = alt.add_parser("sayi")
    p.add_argument("ikili")
    p.add_argument("--basvuru", required=True)
    p.add_argument("--cikti")
    p = alt.add_parser("veri-yok")
    p.add_argument("ikililer", nargs="+")
    p.add_argument("--cikti")
    p = alt.add_parser("sinama")
    p.add_argument("ikili")
    p.add_argument("--sinama-izni", action="store_true")
    p.add_argument("--cikti")
    a = ap.parse_args(argv)
    r = {"ornek": kom_ornek, "sayi": kom_sayi, "veri-yok": kom_veri_yok, "sinama": kom_sinama}[a.komut](a)
    s = json.dumps(r, ensure_ascii=False, indent=1, default=str)
    if a.cikti:
        Path(a.cikti).write_text(s + "\n")
    print(s)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
