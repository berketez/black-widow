#!/usr/bin/env python3
"""sonuc.json'dan rapor tablolarını Markdown olarak basar (rapor.md bu çıktıdan derlendi).

Kullanım: python3 -B tablolar.py sonuc.json [yorum_kaynak_tipleri.json]
"""
from __future__ import annotations

import json
import sys


def pc(x: float | None, d: int = 1) -> str:
    return "—" if x is None else f"%{100 * x:.{d}f}".replace(".", ",")


def ci(c: list | None) -> str:
    return "—" if not c else f"[{pc(c[0])}, {pc(c[1])}]"


def rate(r: dict) -> str:
    return f"{pc(r['oran'])} ({r['k']}/{r['n']}) {ci(r['ci95'])}"


def main() -> int:
    r = json.load(open(sys.argv[1]))
    P = r["programlar"]
    print("### Ana tablo (V1)\n")
    print("| Ölçü | tmux | htop |\n|---|---|---|")
    v = {p: P[p]["degiskenler"]["V1"] for p in P}
    def row(label, f):
        print(f"| {label} | {f('tmux')} | {f('htop')} |")
    row("İsim bekleyen (P)", lambda p: str(P[p]["bekleyen"]))
    for L in ("Ö1", "Ö2"):
        row(f"Ağırlıklı saflık {L} [bootstrap %95]", lambda p: f"{pc(v[p]['duzey'][L]['saflik']['agirlikli'])} "
            f"{ci(v[p]['duzey'][L]['saflik_bootstrap_ci95'])}")
        row(f"Medyan / makro saflık {L}", lambda p: f"{pc(v[p]['duzey'][L]['saflik']['medyan'])} / "
            f"{pc(v[p]['duzey'][L]['saflik']['makro'])}")
        row(f"Negatif kontrol {L}: karışık ort. [2,5-97,5], p", lambda p: (
            lambda k: f"{pc(k['karisik_ortalama'])} [{pc(k['karisik_2_5'])}, {pc(k['karisik_97_5'])}], "
            f"p = {k['p']:.4f}".replace(".", ",") + (" geçti" if k["gecerli"] else " GEÇMEDİ"))(
            v[p]["duzey"][L]["negatif_kontrol"]))
    row("Değerlendirilen küme / üye", lambda p: f"{v[p]['duzey']['Ö1']['saflik']['kume_sayisi']} / "
        f"{v[p]['duzey']['Ö1']['saflik']['uye']}")
    row("Tek parçalı adlı bekleyen (öneksiz)", lambda p: str(v[p]["duzey"]["Ö1"]["oneksiz_bekleyen"]))
    row("Kümeye düşen (K0)", lambda p: rate(v[p]["kumeye_dusen"]))
    row("K0, talimat ağırlıklı", lambda p: pc(v[p]["kumeye_dusen_talimat_agirlikli"]))
    for a in ("Ç-G", "Ç-O", "Ç-K", "Ç-K+"):
        row(f"Çapalı kümeye düşen, {a} (çapa sayısı)", lambda p, a=a: (
            f"{rate(v[p]['capali'][a]['kapsam'])}; talimat {pc(v[p]['capali'][a]['kapsam_talimat_agirlikli'])}"
            f" ({v[p]['capali'][a]['capa_sayisi']})"))
    for L in ("Ö1", "Ö2"):
        for a in ("Ç-O", "Ç-K"):
            row(f"Saf (≥%90) ve çapalı, {a}, {L}", lambda p, a=a, L=L: rate(v[p]["duzey"][L]["saf_ve_capali"][a]))
    print()
    print("### Yayılım benzetimi (V1; oybirliği, çelişkide susar)\n")
    print("| Program | Düzey | Çapa | Öneri (P'ye) | Kesinlik | Doğru öneri (P'ye) | Çelişkiden susan |")
    print("|---|---|---|---|---|---|---|")
    for p in P:
        for L in ("Ö1", "Ö2"):
            for a in ("Ç-O", "Ç-K", "Ç-K+"):
                y = v[p]["duzey"][L]["yayilim"][a]
                print(f"| {p} | {L} | {a} | {pc(y['oneri']['oran'])} | "
                      f"{pc(y['kesinlik']['oran'])} ({y['kesinlik']['k']}/{y['kesinlik']['n']}) "
                      f"{ci(y['kesinlik']['ci95'])} | {pc(y['dogru_oneri_kapsami']['oran'])} | "
                      f"{y['celiski_sustu']} |")
    print()
    print("### Değişkenler\n")
    print("| Program | Değişken | Küme (≥2) | En büyük | K0 | Ç-O çapalı | Ç-K çapalı | Ö1 ağırlıklı | Ö2 ağırlıklı | Kontrol Ö1/Ö2 |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    for p in P:
        for name, m in P[p]["degiskenler"].items():
            k1 = m["duzey"]["Ö1"]["negatif_kontrol"]["gecerli"]
            k2 = m["duzey"]["Ö2"]["negatif_kontrol"]["gecerli"]
            print(f"| {p} | {name} | {m['kume_sayisi_2plus']} | {m['en_buyuk_kume']} | "
                  f"{pc(m['kumeye_dusen']['oran'])} | {pc(m['capali']['Ç-O']['kapsam']['oran'])} | "
                  f"{pc(m['capali']['Ç-K']['kapsam']['oran'])} | "
                  f"{pc(m['duzey']['Ö1']['saflik']['agirlikli'])} | {pc(m['duzey']['Ö2']['saflik']['agirlikli'])} | "
                  f"{'geçti' if k1 else 'geçmedi'}/{'geçti' if k2 else 'geçmedi'} |")
    print()
    print("### Boyut dağılımı ve dilim saflığı (V1)\n")
    for p in P:
        m = v[p]
        bd = ", ".join(f"{b['dilim']}: {b['kume']}" for b in m["boyut_dagilimi"])
        print(f"- {p}: küme boyutu (evren üyesi) {bd}; en büyük {m['en_buyuk_kume']}, "
              f"tek kümedeki en büyük bekleyen payı {pc(m['tek_kumedeki_en_buyuk_bekleyen_payi'])}")
        for L in ("Ö1", "Ö2"):
            sl = "; ".join(f"{b['dilim']}: {b['kume']} küme, {b['uye']} üye, {pc(b['agirlikli'])}"
                           for b in m["duzey"][L]["saflik"]["boyut_dilimleri"])
            print(f"  - {L} dilimleri (değerlendirilen üye sayısına göre): {sl}; "
                  f"eşik üstü küme payı {pc(m['duzey'][L]['saflik']['esik_ustu_kume_payi'])}; "
                  f"çeyrekler {[round(x, 3) for x in m['duzey'][L]['saflik']['ceyrekler']]}")
    print()
    print("### En kötü 5 küme (V1, Ö1)\n")
    for p in P:
        for i, w in enumerate(v[p]["duzey"]["Ö1"]["en_kotu_5"], 1):
            on = ", ".join(f"{a} {b}" for a, b in w["onekler"])
            print(f"- {p} #{i}: {w['uye']} üye (boyut {w['boyut']}), Ö1 saflık {pc(w['saflik'])}; "
                  f"önekler: {on}" + (f" (+{w['diger_onek_sayisi']} önek daha)" if w['diger_onek_sayisi'] else ""))
    print()
    print("### En kötü 5 küme (V1, Ö2)\n")
    for p in P:
        for i, w in enumerate(v[p]["duzey"]["Ö2"]["en_kotu_5"], 1):
            on = ", ".join(f"{a} {b}" for a, b in w["onekler"][:6])
            print(f"- {p} #{i}: {w['uye']} üye, Ö2 saflık {pc(w['saflik'])}; önekler: {on}")
    print()
    print("### Tanılar\n")
    for p in P:
        d = P[p]
        print(f"- {p}: evren {d['evren']}, C durum {d['c_durum']}, p1'i olmayan bekleyen "
              f"{d['p1_olmayan_bekleyen']}, p1'i değişen bekleyen {d['p1_degisen_bekleyen']}; "
              f"doğrudan iç çağrı yeri {d['dogrudan_ic_cagri']}, V1 çağrı yeri {d['v1_kenar']} "
              f"({d['v1_kenar_tekil_cift']} ayrı çift), V1-N {d['v1n_kenar']}, V2 {d['v2_kenar']}; "
              f"tablo koşusu {d['tablo_kosusu']} ({d['tablo_kosusundaki_fonksiyon']} fonksiyon); "
              f"p-code uyumu {rate(d['pcode_v1_uyum'])}; Ç-K kesinliği {rate(d['capa_k_kesinlik'])}; "
              f"Karadul'un bugün isim verdiği {rate(d['karadul_bugun_isim_verdigi'])}")
    print()
    print("G8 okuması:", json.dumps(r["g8_okuma"], ensure_ascii=False))
    if len(sys.argv) > 2:
        y = json.load(open(sys.argv[2]))
        print("\n### Yorum: kaynak tipleri\n")
        print(json.dumps(y, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
