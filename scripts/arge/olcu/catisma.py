#!/usr/bin/env python3
"""ÖLÇÜ hattı kalem 5 (B5): kanallar arası çatışma — uygulanan ad ile yedek adayların GT'ye göre dökümü
ve karar kuralının (BULGULAR §5 kural 5) çevrimdışı oynatılması.

Veri: taban koşusunun ``reconstructed/src/naming_provenance.json`` kayıtları (``global[FUN_<adres>]``:
``strategy`` / kanal, ``new_name``, ``confidence``, ``runners_up`` = en çok ``max_runners_up`` yedek aday:
``strategy``, ``new_name``, ``confidence``). Ad verilmeyen fonksiyonların aday listesi kayıtta yoktur
(yalnız ``eliminated_keys`` sayaçları) — o taraf bu veriyle ölçülemez.

Tanımlar:
  - kimlik iddialı yedek: adı jenerik değil (``function_f1.is_generic_name(ad, [adres])`` yanlış) ve geçerli;
  - çatışma: kimlik iddialı yedeğin harf dizisi kazananınkinden farklı (``olcu.harf_dizisi``);
  - doğru: ``ks1_olc.capa_degerlendir`` (tam) ya da ``olcu.harf_tam`` (biçim).
Ürün ağacından koşulur (``taban_dok.py`` ile aynı kural):
    PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=~/karadul_olcum/urun-a62f15e python scripts/arge/olcu/catisma.py \
        --agac ~/karadul_olcum/urun-a62f15e --kok ~/karadul_olcum/runs/urun-onarim-a62f15e \
        --mac-veri /Users/apple/Black_Widow/workspaces/olcum_mac \
        --karar ~/karadul_olcum/runs/arge-2026-11-19/olcu/karar.json \
        --json ~/karadul_olcum/runs/arge-2026-11-19/olcu/catisma.json
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

BURASI = Path(__file__).resolve().parent
sys.path.insert(0, str(BURASI))

import olcu  # noqa: E402
import taban_dok  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--agac", type=Path, required=True)
    ap.add_argument("--kok", type=Path, required=True)
    ap.add_argument("--mac-veri", type=Path, required=True)
    ap.add_argument("--debian-indir", type=Path, default=Path.home() / "karadul_olcum" / "downloads" / "debian13")
    ap.add_argument("--karar", type=Path, required=True, help="karar.json (kanal başına Wilson alt sınırı)")
    ap.add_argument("--json", type=Path, required=True)
    a = ap.parse_args()
    uo = taban_dok.yukle(a.agac.expanduser().resolve())
    ks1 = uo.ks1
    f1 = ks1._f1()
    p_alt = {k: v["tam+bicim"]["aralik"][0] for k, v in json.loads(a.karar.read_text(encoding="utf-8"))["kanal"].items()}
    elfler = uo.haritasizlari_isaretle(ks1.elfleri_topla(a.kok / "mac", a.kok / "debian"))
    say: Counter = Counter()
    cift: dict[str, Counter] = defaultdict(Counter)        # "kazanan kanal > yedek strateji"
    yedek_kanal: dict[str, Counter] = defaultdict(Counter)  # yedek strateji başına (kimlik iddialı)
    yedek_guven: dict[str, Counter] = defaultdict(Counter)
    kurtarilabilir = []
    for e in elfler:
        fonk = uo._json(Path(e.static) / "ghidra_functions.json").get("functions", [])
        if ks1.cpp_ikili_mi(fonk, e.platform):
            continue
        genel, koken, _ = uo.haritayi_oku(e.kosu)
        gt = ks1.gt_mac(e, a.mac_veri) if e.platform == ks1.PLATFORM_MAC else ks1.gt_elf(e, a.debian_indir)
        gfonk = f1.load_ghidra_functions(Path(e.static) / "ghidra_functions.json")
        kayitlar, _ = uo.degerlendir_elf(genel, koken, gfonk, gt, e.platform)
        for k in kayitlar:
            kayit = koken.get(f"FUN_{k['adres']:08x}") or next(
                (v for anahtar, v in koken.items() if uo.anahtar_sinifi(anahtar)[1] == k["adres"]), None)
            say["ad"] += 1
            if kayit is None:
                say["koken_yok"] += 1
                continue
            gt_adlari = [ks1.platform_adi(g, e.platform) for g in (gt.adlar.get(k["adres"]) or [])]
            kazanan_dogru = k["durum"] == uo.DOGRU or olcu.harf_tam(k["ad"], gt_adlari)
            say["kazanan_dogru"] += kazanan_dogru
            say[f"n_candidates={min(kayit.get('n_candidates', 0), 4)}{'+' if kayit.get('n_candidates', 0) >= 4 else ''}"] += 1
            yedekler = kayit.get("runners_up") or []
            say["yedek"] += len(yedekler)
            catisan, dogru_yedek = False, None
            for y in yedekler:
                ad = y.get("new_name")
                if not isinstance(ad, str) or not ad or f1.is_generic_name(ad, [k["adres"]]):
                    say["yedek_jenerik"] += 1
                    continue
                say["yedek_kimlik"] += 1
                strateji = y.get("strategy") or "?"
                ayni = olcu.harf_dizisi(ad) == olcu.harf_dizisi(k["ad"])
                y_dogru = bool(gt_adlari) and (
                    ks1.capa_degerlendir(ad, gt.adlar[k["adres"]], e.platform)["durum"] == uo.DOGRU
                    or olcu.harf_tam(ad, gt_adlari))
                c = yedek_kanal[strateji]
                c["n"] += 1
                c["dogru"] += y_dogru
                c["kazananla_ayni"] += ayni
                yedek_guven[strateji][f"{float(y.get('confidence') or 0):.2f}"] += 1
                if ayni:
                    continue
                catisan = True
                cc = cift[f"{k['kanal']} > {strateji}"]
                cc["catisma"] += 1
                cc["kazanan_dogru"] += kazanan_dogru
                cc["yedek_dogru"] += y_dogru
                cc["ikisi_de_yanlis"] += (not kazanan_dogru) and (not y_dogru)
                if y_dogru and not kazanan_dogru:
                    dogru_yedek = {"strateji": strateji, "ad": ad, "guven": y.get("confidence")}
            say["catismali_ad"] += catisan
            if not kazanan_dogru:
                say["kazanan_yanlis"] += 1
                say["kazanan_yanlis_catismali"] += catisan
                if dogru_yedek:
                    say["kazanan_yanlis_yedek_dogru"] += 1
                    kurtarilabilir.append({"ikili": f"{ks1.birim_anahtari(e)}::{e.ad}", "adres": f"{k['adres']:x}",
                                           "kazanan": k["ad"], "kanal": k["kanal"], "gt": gt_adlari, **dogru_yedek})
    # Kural oynatması: (1) ölçülmemiş yedek kanal p = 0 → kazanan değişmez. (2) Seçenek: yedek kanalın bu
    # veride ölçülen kesinliğinin Wilson alt sınırı p sayılır (aynı veride ölçüm + uygulama: yön gösterici).
    yedek_p = {s: ks1.oran(c["dogru"], c["n"])["aralik"][0] for s, c in yedek_kanal.items()}
    degisen = Counter()
    for anahtar, cc in cift.items():
        kazanan_kanal, strateji = anahtar.split(" > ")
        if yedek_p.get(strateji, 0.0) > p_alt.get(kazanan_kanal, 0.0):
            degisen["karar"] += cc["catisma"]
            degisen["kazanilan_dogru"] += cc["yedek_dogru"] - 0
            degisen["kaybedilen_dogru"] += cc["kazanan_dogru"]
    sonuc = {"sema": "karadul-arge-olcu-catisma/1", "sayim": dict(sorted(say.items())),
             "cift": {k: dict(c) for k, c in sorted(cift.items())},
             "yedek_kanal": {s: {**dict(c), "kesinlik": ks1.oran(c["dogru"], c["n"]),
                                 "guven_dagilimi": dict(sorted(yedek_guven[s].items()))}
                             for s, c in sorted(yedek_kanal.items())},
             "kazanan_p_alt": p_alt, "yedek_p_alt": yedek_p,
             "kural_olculmemis_p0": {"degisen_karar": 0},
             "kural_yedek_olculmus_p": dict(degisen) or {"karar": 0},
             "kurtarilabilir": kurtarilabilir}
    a.json.write_text(json.dumps(sonuc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print("sayım:", dict(sorted(say.items())))
    print("\nkazanan kanal > yedek strateji: çatışma / kazanan doğru / yedek doğru / ikisi de yanlış")
    for kk, c in sorted(cift.items()):
        print(f"  {kk:48s} {c['catisma']:5d} {c['kazanan_dogru']:5d} {c['yedek_dogru']:5d} {c['ikisi_de_yanlis']:5d}")
    print("\nyedek strateji (kimlik iddialı): n / doğru / kazananla aynı / Wilson alt / güven dağılımı")
    for s, c in sorted(yedek_kanal.items()):
        print(f"  {s:20s} {c['n']:5d} {c['dogru']:5d} {c['kazananla_ayni']:5d} {yedek_p[s]:.3f} {dict(sorted(yedek_guven[s].items()))}")
    print("\nkural (yedek ölçülmüş p ile):", dict(degisen) or {"karar": 0})
    print("kurtarılabilir:", len(kurtarilabilir))
    for kr in kurtarilabilir[:15]:
        print("  ", kr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
