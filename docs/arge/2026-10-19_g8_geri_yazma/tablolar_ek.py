"""rapor.md "Ek koşullar" bölümündeki tabloları sonuc_ek.json'dan üretir (Türkçe ondalık virgülü).

Kullanım: python3 -I -B tablolar_ek.py > workspaces/2026-10-19_g8/veri/rapor_tablolari_ek.md
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ortak  # noqa: E402
from tablolar import s, goreli, AD  # noqa: E402

KARS = [("K1-C0", "K1 ↔ C0"), ("K1y-C0", "K1y ↔ C0"), ("K2-C0", "K2 ↔ C0"), ("K2-C2", "K2 ↔ C2"),
        ("K3_C3-K3_C0", "K3-C3 ↔ K3-C0 (client)")]
BIR = ["undefined_100", "ptr_aritmetik_100", "tip_donusumu_100", "ok_erisim_100", "varsayilan_ad_100"]


def main() -> None:
    d = json.loads((ortak.BELGE / "sonuc_ek.json").read_text())
    p = print
    for rol, baslik in (("hedef", "hedefler"), ("cagiran", "doğrudan çağıranlar")):
        p(f"\n**Özet, {baslik}: havuzlanmış 100 satır oranının göreli değişimi (anlamlı kazanç kalın)**\n")
        p("| Karşılaştırma | n | U | P1 | C | A | D | Anlamlı (5'te) |")
        p("|---|---|---|---|---|---|---|---|")
        for k, ad in KARS:
            if k not in d["karsilastirmalar"]:
                continue
            oz = d["karsilastirmalar"][k][rol]
            hucre = []
            for a in BIR:
                v = oz["birincil"][a]
                t = goreli(v) if a != "ok_erisim_100" else f"{s(v['havuz_once'])} → {s(v['havuz_sonra'])}"
                hucre.append(f"**{t}**" if v["anlamli_kazanc"] else t)
            p(f"| {ad} | {oz['birincil']['undefined_100']['n']} | " + " | ".join(hucre) +
              f" | {oz['anlamli_kazanc_sayisi']} |")
    for k, ad in KARS:
        if k not in d["karsilastirmalar"]:
            continue
        oz = d["karsilastirmalar"][k]["hedef"]
        p(f"\n**{ad}, hedefler**\n")
        p("| Ölçüt | Ort. önce | Ort. sonra | Eşli fark [%95 GA] | Havuz önce → sonra (göreli) | İyi / kötü / aynı | Anlamlı kazanç |")
        p("|---|---|---|---|---|---|---|")
        for a, v in oz["birincil"].items():
            p(f"| {AD[a]} | {s(v['ort_once'])} | {s(v['ort_sonra'])} | {s(v['ort_fark'], 1, True)} "
              f"[{s(v['ga95'][0], 1, True)}; {s(v['ga95'][1], 1, True)}] | {s(v['havuz_once'])} → "
              f"{s(v['havuz_sonra'])} ({goreli(v)}) | {v['iyilesen']}/{v['kotulesen']}/{v['degismeyen']} | "
              f"{'**evet**' if v['anlamli_kazanc'] else 'hayır'} |")
    p("\n**Karadul'un hedeflere verdiği bilgi (K1, K1y)**\n")
    p("| Gerçek ad | Karadul adı | Karadul imzası | K1y yapısı |")
    p("|---|---|---|---|")
    for h in d["karadul_kapsami"]["hedefler"]:
        p(f"| `{h['gt_ad']}` | {('`' + h['karadul_ad'] + '`') if h['karadul_ad'] else '—'} | "
          f"`{h['karadul_imza']}` | {h['bagli_yapi'] or '—'} |")
    p("\n**Bağlanan Karadul yapılarının alan doğruluğu (window_pane'e karşı)**\n")
    p("| Yapı | Boyut (gerçek 1760) | Kaynak | Doğru | Ofset doğru, boyut yanlış | Yanlış |")
    p("|---|---|---|---|---|---|")
    for ad, v in d["karadul_yerlesim_dogrulugu"]["yapilar"].items():
        if v["bagli"]:
            sy = v["sayilar"]
            p(f"| {ad} | {v['boyut']} | {', '.join(v['kaynaklar'])} | {sy['dogru']} | "
              f"{sy['ofset_dogru_boyut_yanlis']} | {sy['yanlis']} |")
    b, kl = d["karadul_yerlesim_dogrulugu"]["bagli_toplam"], d["karadul_yerlesim_dogrulugu"]["kaynak_listesindeki_toplam"]
    p(f"\nToplam: bağlı yapılar doğru {b['dogru']}, ofset doğru boyut yanlış {b['ofset_dogru_boyut_yanlis']}, "
      f"yanlış {b['yanlis']}. Hedefleri kaynak listesinde taşıyan bütün yapılar "
      f"({len(d['karadul_yerlesim_dogrulugu']['yapilar'])}): doğru {kl['dogru']}, ofset doğru boyut yanlış "
      f"{kl['ofset_dogru_boyut_yanlis']}, yanlış {kl['yanlis']}.")
    p("\n**Süre (aynı süreçte, iki koşunun ortalaması, toplam ms)**\n")
    for k, ad in KARS:
        if k not in d["karsilastirmalar"]:
            continue
        for rol in ("hedef", "cagiran"):
            t = d["karsilastirmalar"][k][rol]["sure_ayni_surec"]
            p(f"- {ad}, {rol}: {s(1000 * t['sure_toplam_sn'][0], 0)} → {s(1000 * t['sure_toplam_sn'][1], 0)} ms")


if __name__ == "__main__":
    main()
