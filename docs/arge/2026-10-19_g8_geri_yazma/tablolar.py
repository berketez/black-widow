"""rapor.md'deki tabloları sonuc.json'dan üretir (Türkçe ondalık virgülüyle).

Kullanım: python3 -I -B tablolar.py > workspaces/2026-10-19_g8/veri/rapor_tablolari.md
"""

from __future__ import annotations

import json
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ortak  # noqa: E402

AD = {"undefined_100": "U/100", "ptr_aritmetik_100": "P1/100", "tip_donusumu_100": "C/100",
      "ok_erisim_100": "A/100", "varsayilan_ad_100": "D/100", "ptr_aritmetik_genis_100": "P2/100",
      "varsayilan_genel_100": "G/100", "fun_ad_100": "F/100"}
ROL = {"hedef": "20 hedef fonksiyon", "cagiran": "49 doğrudan çağıran"}
KOSUL = {"C1": "C1 ad", "C2": "C2 ad + prototip", "C3": "C3 ad + prototip + yapı",
         "C4": "C4 ad + prototip + bütün yapılar"}


def s(x: float, n: int = 1, isaret: bool = False) -> str:
    t = f"{x:+.{n}f}" if isaret else f"{x:.{n}f}"
    return t.replace(".", ",").replace("-", "−")


def goreli(v: dict) -> str:
    x = v["havuz_goreli_degisim"]
    return "taban 0" if isinstance(x, str) else s(100 * x, 0, True).replace("+", "+") + "%"


def main() -> None:
    d = json.loads((ortak.BELGE / "sonuc.json").read_text())
    p = print
    for rol in ("hedef", "cagiran"):
        oz = d["karsilastirmalar"]["C3-C0"][rol]
        p(f"\n**C3 ↔ C0, {ROL[rol]}**\n")
        p("| Ölçüt | Ort. önce | Ort. sonra | Eşli fark [%95 GA] | Havuz önce → sonra (göreli) | İyi / kötü / aynı | Anlamlı kazanç |")
        p("|---|---|---|---|---|---|---|")
        for grup in ("birincil", "ikincil"):
            for a, v in oz[grup].items():
                an = ("**evet**" if v["anlamli_kazanc"] else "hayır") if grup == "birincil" else "(ikincil)"
                p(f"| {AD[a]} | {s(v['ort_once'])} | {s(v['ort_sonra'])} | {s(v['ort_fark'], 1, True)} "
                  f"[{s(v['ga95'][0], 1, True)}; {s(v['ga95'][1], 1, True)}] | {s(v['havuz_once'])} → "
                  f"{s(v['havuz_sonra'])} ({goreli(v)}) | {v['iyilesen']}/{v['kotulesen']}/{v['degismeyen']} | {an} |")
    for rol in ("hedef", "cagiran"):
        p(f"\n**Ablasyon, {ROL[rol]}: havuzlanmış 100 satır oranı**\n")
        p("| Koşul | U | P1 | C | A | D | F | Satır (toplam) | Decompile medyanı (ms) | Anlamlı kazanç (5'te) |")
        p("|---|---|---|---|---|---|---|---|---|---|")
        oz = d["karsilastirmalar"]["C1-C0"][rol]
        b, i, t = oz["birincil"], oz["ikincil"], oz["tanimlayici"]
        p(f"| C0 taban | {s(b['undefined_100']['havuz_once'])} | {s(b['ptr_aritmetik_100']['havuz_once'])} | "
          f"{s(b['tip_donusumu_100']['havuz_once'])} | {s(b['ok_erisim_100']['havuz_once'])} | "
          f"{s(b['varsayilan_ad_100']['havuz_once'])} | {s(i['fun_ad_100']['havuz_once'])} | {t['satir_toplam'][0]} | "
          f"{s(1000 * t['sure_medyan_sn'][0])} | — |")
        for k in ("C1", "C2", "C3", "C4"):
            oz = d["karsilastirmalar"][f"{k}-C0"][rol]
            b, i, t = oz["birincil"], oz["ikincil"], oz["tanimlayici"]
            p(f"| {KOSUL[k]} | {s(b['undefined_100']['havuz_sonra'])} | {s(b['ptr_aritmetik_100']['havuz_sonra'])} | "
              f"{s(b['tip_donusumu_100']['havuz_sonra'])} | {s(b['ok_erisim_100']['havuz_sonra'])} | "
              f"{s(b['varsayilan_ad_100']['havuz_sonra'])} | {s(i['fun_ad_100']['havuz_sonra'])} | {t['satir_toplam'][1]} | "
              f"{s(1000 * t['sure_medyan_sn'][1])} | {oz['anlamli_kazanc_sayisi']} |")
    h = [f for f in d["fonksiyonlar"] if f["rol"] == "hedef"]
    p("\n**Dağılım: hedeflerde fonksiyon başına 100 satır oranı**\n")
    p("| Ölçüt | C0 medyan [Ç1; Ç3] | C3 medyan [Ç1; Ç3] | C0 en az–en çok | C3 en az–en çok |")
    p("|---|---|---|---|---|")
    for key, ad in (("undefined", "U"), ("ptr_aritmetik", "P1"), ("tip_donusumu", "C"), ("ok_erisim", "A"),
                    ("varsayilan_ad", "D")):
        r0 = [100 * f["kosullar"]["C0"]["sayilar"][key] / f["kosullar"]["C0"]["sayilar"]["satir"] for f in h]
        r3 = [100 * f["kosullar"]["C3"]["sayilar"][key] / f["kosullar"]["C3"]["sayilar"]["satir"] for f in h]
        a = statistics.quantiles(r0, n=4, method="inclusive")
        b = statistics.quantiles(r3, n=4, method="inclusive")
        p(f"| {ad}/100 | {s(a[1])} [{s(a[0])}; {s(a[2])}] | {s(b[1])} [{s(b[0])}; {s(b[2])}] | "
          f"{s(min(r0))}–{s(max(r0))} | {s(min(r3))}–{s(max(r3))} |")
    p("\n**Hedef başına ham sayılar (C0 → C3)**\n")
    p("| # | Gerçek ad | Satır | U | P1 | C | A | D |")
    p("|---|---|---|---|---|---|---|---|")
    for n, f in enumerate(h, 1):
        a = f["kosullar"]["C0"]["sayilar"]
        b = f["kosullar"]["C3"]["sayilar"]
        p(f"| {n} | `{f['gt_ad']}` | {a['satir']} → {b['satir']} | {a['undefined']} → {b['undefined']} | "
          f"{a['ptr_aritmetik']} → {b['ptr_aritmetik']} | {a['tip_donusumu']} → {b['tip_donusumu']} | "
          f"{a['ok_erisim']} → {b['ok_erisim']} | {a['varsayilan_ad']} → {b['varsayilan_ad']} |")

    def top(k, key, liste):
        return sum(f["kosullar"][k]["sayilar"][key] for f in liste)

    p(f"| | **toplam** | {top('C0', 'satir', h)} → {top('C3', 'satir', h)} | {top('C0', 'undefined', h)} → "
      f"{top('C3', 'undefined', h)} | {top('C0', 'ptr_aritmetik', h)} → {top('C3', 'ptr_aritmetik', h)} | "
      f"{top('C0', 'tip_donusumu', h)} → {top('C3', 'tip_donusumu', h)} | {top('C0', 'ok_erisim', h)} → "
      f"{top('C3', 'ok_erisim', h)} | {top('C0', 'varsayilan_ad', h)} → {top('C3', 'varsayilan_ad', h)} |")
    c = [f for f in d["fonksiyonlar"] if f["rol"] == "cagiran"]
    p("\n**Çağıran toplamları (C0 → C3 → C4)**\n")
    for key, ad in (("satir", "satır"), ("undefined", "U"), ("ptr_aritmetik", "P1"), ("tip_donusumu", "C"),
                    ("ok_erisim", "A"), ("varsayilan_ad", "D"), ("fun_ad", "FUN_")):
        p(f"- {ad}: {top('C0', key, c)} → {top('C3', key, c)} → {top('C4', key, c)}")
    p(f"- C3'te en az bir `->` alan çağıran: "
      f"{sum(1 for f in c if f['kosullar']['C3']['sayilar']['ok_erisim'] > 0)} / {len(c)}")
    p("\n**Süre (iki koşunun ortalaması, toplam ms)**\n")
    for k in ("C0", "C1", "C2", "C3", "C4"):
        p(f"- {k}: hedefler {s(1000 * sum(f['kosullar'][k]['sure_ort_sn'] for f in h), 0)} ms, "
          f"çağıranlar {s(1000 * sum(f['kosullar'][k]['sure_ort_sn'] for f in c), 0)} ms; geri yazma uygulaması "
          f"{'—' if d['kosullar'][k]['uygulama']['uygulama_sn'] is None else s(d['kosullar'][k]['uygulama']['uygulama_sn'], 3) + ' sn'}")


if __name__ == "__main__":
    main()
