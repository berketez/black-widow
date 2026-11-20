#!/usr/bin/env python
"""KİMLİK Dalga 0 — PK-6 ölçümü: dondurulmuş betikleri yeni gruplarda koş, ön kayıtlı hükümleri (a)–(e) ver.

Adımlar (``hepsi`` hepsini sırayla yapar; çıktılar ``<KOK>/olcum/``):
  betikler  ``yayilim_olc`` (dört nokta; x86-64 içeren grupta yalnız v1 noktaları: ``d0_veri.v2_destekli``),
            ``hata_dok`` (koşulan her nokta), ``envanter``, ``ciplak``. Betikler değişmez; ``d0_veri.kur()`` ile
            yeni kökler ve gruplar süreç içinde bağlanır. Metin çıktısı ``<etiket>_<betik>.txt``.
  hukum     ``yayilim_<etiket>.json`` + ``hata_<etiket>_kural.json``'dan yön başına / program başına satırlar,
            A-14 tekil düzeyi (``kural``; eşleme yeniden hesaplanır, belirlenimci) ve PK-6_on_kayit.md §3'ün
            hükümleri → ``hukum_<etiket>.json`` + ``hukum_<etiket>.md``.

Kullanım (worktree kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/kimlik/d0_olc.py hepsi --grup mimari
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import sys
from pathlib import Path
from typing import Any, Optional

_BURASI = Path(__file__).resolve().parent
sys.path.insert(0, str(_BURASI))
import d0_veri  # noqa: E402

d0_veri.kur()
import ciplak  # noqa: E402
import envanter  # noqa: E402
import esle  # noqa: E402
import hata_dok  # noqa: E402
import veri  # noqa: E402
import yayilim_olc  # noqa: E402
from veri import ks1  # noqa: E402

import kimlik_ciftler as kc  # noqa: E402

sys.path.insert(0, str(d0_veri.REPO))
from karadul.core.naming_labels import AD_ESIGI  # noqa: E402  (KARARLAR A-13 / A-25: tek sabit)

OLCUM_DIZINI = d0_veri.KOK / "olcum"
HEDEF_ESIGI = 0.95          # hattın kendi hedefi (PLAN §0)
V1_NOKTALAR = ("kural", "tutucu")
TEK_TARAFLI_DESTEK = 0.20   # (b) ≤ %20 → destek
TEK_TARAFLI_CURUR = 0.50    # (b) > %50 → çürür
TEK_TARAFLI_EN_AZ = 10      # (b) toplam yanlış bundan azsa "sayı yetmedi"
GENELLEME_EN_AZ_PROGRAM = 3  # (e)
GENELLEME_EN_AZ_GECEN = 2    # (e)
BIRINCIL_NOKTA = "kural"
IKINCIL_NOKTA = "tutucu_v2"


def noktalar(grup: str) -> tuple[str, ...]:
    ks = {k for c in kc.grup(grup) for k in c}
    if all(d0_veri.v2_destekli(k) for k in ks):
        return tuple(esle.NOKTALAR)
    return V1_NOKTALAR


@contextlib.contextmanager
def nokta_suzgeci(adlar: tuple[str, ...]):
    eski = esle.NOKTALAR
    esle.NOKTALAR = {k: v for k, v in eski.items() if k in adlar}
    yayilim_olc.esle.NOKTALAR = esle.NOKTALAR
    try:
        yield
    finally:
        esle.NOKTALAR = eski
        yayilim_olc.esle.NOKTALAR = eski


def _yakala(fn, argv: list[str], txt: Path) -> int:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        kod = fn(argv)
    txt.write_text(buf.getvalue(), encoding="utf-8")
    return kod


def betikler(grup: str, etiket: str) -> None:
    OLCUM_DIZINI.mkdir(parents=True, exist_ok=True)
    nk = noktalar(grup)
    _yakala(envanter.main, [grup, "--json", str(OLCUM_DIZINI / f"envanter_{etiket}.json")],
            OLCUM_DIZINI / f"envanter_{etiket}.txt")
    with nokta_suzgeci(nk):
        _yakala(yayilim_olc.main, [grup, "--json", str(OLCUM_DIZINI / f"yayilim_{etiket}.json")],
                OLCUM_DIZINI / f"yayilim_{etiket}.txt")
    for n in nk:
        _yakala(hata_dok.main, [grup, "--nokta", n, "--json", str(OLCUM_DIZINI / f"hata_{etiket}_{n}.json")],
                OLCUM_DIZINI / f"hata_{etiket}_{n}.txt")
    try:   # ek satır (hükme girmez): çökerse nedeni yazılır, ölçüm sürer
        _yakala(ciplak.main, [grup, "--json", str(OLCUM_DIZINI / f"ciplak_{etiket}.json")],
                OLCUM_DIZINI / f"ciplak_{etiket}.txt")
    except Exception as e:  # noqa: BLE001
        (OLCUM_DIZINI / f"ciplak_{etiket}.txt").write_text(f"ciplak koşulamadı: {type(e).__name__}: {e}\n",
                                                          encoding="utf-8")


# ------------------------------------------------------------------------------------------------
# Hüküm

def _alt(o: dict[str, Any]) -> Optional[float]:
    return o["aralik"][0] if o.get("aralik") else None


def sinif_a(alt: Optional[float]) -> str:
    if alt is None:
        return "veri yok"
    if alt >= HEDEF_ESIGI:
        return "hat hedefi tuttu"
    if alt >= AD_ESIGI:
        return "ad yazabilir (A-2)"
    return "kanıt satırı"


def _topla(satirlar: list[dict[str, Any]]) -> dict[str, Any]:
    d = sum(s["dogru"] for s in satirlar)
    y = sum(s["yanlis"] for s in satirlar)
    n = sum(s["nufus"] for s in satirlar)
    tv = sum(s["tavan"] for s in satirlar)
    k = ks1.oran(d, d + y)
    return {"dogru": d, "yanlis": y, "nufus": n, "tavan": tv, "kesinlik": k, "kapsam": ks1.oran(d, n),
            "alt": _alt(k), "a": sinif_a(_alt(k)), "ikili_yon": len(satirlar)}


def yon_adi(grup: str, sorgu: str, basvuru: str) -> str:
    return f"{sorgu.split('/')[0]}→{basvuru.split('/')[0]}"


def ileri_mi(grup: str, sorgu: str, basvuru: str) -> bool:
    return any(c == (sorgu, basvuru) for c in kc.grup(grup))


def tekil_duzey(grup: str, nokta: str) -> dict[str, Any]:
    """A-14 tekil kaynak fonksiyonu düzeyi: (yön sınıfı, program, GT ad kümesi) tek öğe; herhangi bir örneği
    yanlışsa yanlış, hiçbiri yanlış değil ve en az biri doğruysa doğru (PK-6_on_kayit.md §3)."""
    p = esle.NOKTALAR[nokta]
    onbellek: dict[str, veri.Ikili] = {}

    def al(k: str) -> veri.Ikili:
        if k not in onbellek:
            onbellek[k] = veri.yukle(k)
        return onbellek[k]

    ogeler: dict[tuple[str, str, tuple[str, ...]], dict[str, int]] = {}
    for qk, rk in kc.yonler(grup):
        Q, R = al(qk), al(rk)
        s = esle.esle(Q, R, p)
        yon = "ileri" if ileri_mi(grup, qk, rk) else "geri"
        prog = kc.program_adi(qk)
        for q in Q.nufus:
            anahtar = (yon, prog, Q.fonk[q].gt)
            t = ogeler.setdefault(anahtar, {"dogru": 0, "yanlis": 0, "ornek": 0})
            t["ornek"] += 1
            e = s.esler.get(q)
            if e is not None:
                h = esle.hukum(Q, R, q, e.r)
                if h in ("dogru", "yanlis"):
                    t[h] += 1
    out: dict[str, Any] = {}
    for (yon, prog, _), t in ogeler.items():
        for anahtar in (f"{yon}", f"{yon}|{prog}"):
            o = out.setdefault(anahtar, {"dogru": 0, "yanlis": 0, "oge": 0})
            o["oge"] += 1
            if t["yanlis"]:
                o["yanlis"] += 1
            elif t["dogru"]:
                o["dogru"] += 1
    for o in out.values():
        o["kesinlik"] = ks1.oran(o["dogru"], o["dogru"] + o["yanlis"])
        o["alt"] = _alt(o["kesinlik"])
        o["a"] = sinif_a(o["alt"])
    return out


def hukum(grup: str, etiket: str) -> dict[str, Any]:
    yay = json.loads((OLCUM_DIZINI / f"yayilim_{etiket}.json").read_text(encoding="utf-8"))[grup]
    nk = [n for n in esle.NOKTALAR if n in yay]
    sonuc: dict[str, Any] = {"grup": grup, "noktalar": nk, "v2": "koşuldu" if "kural_v2" in nk else
                             "desteklenmiyor (x86-64 yuvası okunmuyor; PK-2 yok)"}
    satirlar_n: dict[str, Any] = {}
    for n in nk:
        satirlar = yay[n]["yonler"]
        for s in satirlar:
            s["_yon"] = "ileri" if ileri_mi(grup, s["sorgu"], s["basvuru"]) else "geri"
            s["_prog"] = kc.program_adi(s["sorgu"])
        tablo = {"havuz_iki_yon": _topla([s["toplam"] for s in satirlar])}
        for yon in ("ileri", "geri"):
            alt_s = [s for s in satirlar if s["_yon"] == yon]
            if alt_s:
                tablo[f"yon:{yon}"] = _topla([s["toplam"] for s in alt_s])
                tablo[f"yon:{yon}"]["ad"] = sorted({yon_adi(grup, s["sorgu"], s["basvuru"]) for s in alt_s})
        programlar = sorted({s["_prog"] for s in satirlar})
        tablo["program"] = {}
        for prog in programlar:
            ps = [s for s in satirlar if s["_prog"] == prog]
            pr = {"havuz_iki_yon": _topla([s["toplam"] for s in ps])}
            for yon in ("ileri", "geri"):
                ys = [s for s in ps if s["_yon"] == yon]
                if ys:
                    pr[yon] = _topla([s["toplam"] for s in ys])
            altlar = [pr[y]["alt"] for y in ("ileri", "geri") if y in pr]
            pr["zayif_yon_alt"] = None if (not altlar or None in altlar) else min(altlar)
            pr["a"] = sinif_a(pr["zayif_yon_alt"])
            pr["ikililer"] = sorted({s["sorgu"] for s in ps})
            tablo["program"][prog] = pr
        yon_altlar = [tablo[k]["alt"] for k in ("yon:ileri", "yon:geri") if k in tablo]
        tablo["grup_zayif_yon_alt"] = None if (not yon_altlar or None in yon_altlar) else min(yon_altlar)
        tablo["a"] = sinif_a(tablo["grup_zayif_yon_alt"])
        satirlar_n[n] = tablo
    sonuc["noktalar_tablo"] = satirlar_n

    # (b) tek taraflı pay (kural, iki yönün havuzu)
    hd = json.loads((OLCUM_DIZINI / f"hata_{etiket}_kural.json").read_text(encoding="utf-8"))[grup]
    toplam_y = sum(hd["siniflar"].values())
    tt = hd["siniflar"]["tavan_disi_tek_tarafli"]
    pay = (tt / toplam_y) if toplam_y else None
    if toplam_y < TEK_TARAFLI_EN_AZ:
        b = "sayı yetmedi"
    elif pay <= TEK_TARAFLI_DESTEK:
        b = "destek buldu"
    elif pay > TEK_TARAFLI_CURUR:
        b = "çürüdü"
    else:
        b = "kararsız"
    sonuc["b"] = {"siniflar": hd["siniflar"], "toplam_yanlis": toplam_y, "tek_tarafli": tt,
                  "pay": None if pay is None else round(pay, 4), "hukum": b,
                  "uygulanir": grup in ("mimari", "surum_esli")}

    # (d) v2 ↔ v1, program başına (iki yönün havuzu)
    if "kural_v2" in nk:
        d: dict[str, Any] = {}
        for prog in satirlar_n["kural"]["program"]:
            d[prog] = {}
            for v1, v2 in (("kural", "kural_v2"), ("tutucu", "tutucu_v2")):
                a1 = satirlar_n[v1]["program"][prog]["havuz_iki_yon"]
                a2 = satirlar_n[v2]["program"][prog]["havuz_iki_yon"]
                k1, k2 = a1["kesinlik"], a2["kesinlik"]
                ortusur = bool(k1["aralik"] and k2["aralik"] and k2["aralik"][1] >= k1["aralik"][0]
                               and k1["aralik"][1] >= k2["aralik"][0])
                v2_iyi = (k2["oran"] or 0) >= (k1["oran"] or 0)
                if a2["dogru"] <= a1["dogru"]:
                    h = "tutmadı (kapsam artmadı)"
                elif not (ortusur or v2_iyi):
                    h = "tutmadı (kesinlik düştü)"
                else:
                    h = "tuttu"
                d[prog][f"{v1}→{v2}"] = {"v1": [a1["dogru"], a1["yanlis"], a1["nufus"]],
                                         "v2": [a2["dogru"], a2["yanlis"], a2["nufus"]],
                                         "v1_kesinlik": k1, "v2_kesinlik": k2, "hukum": h}
        sonuc["d"] = d
    else:
        sonuc["d"] = "desteklenmiyor"

    # (e) genelleme (yalnız surum_esli)
    if grup == "surum_esli":
        e: dict[str, Any] = {}
        for n in (BIRINCIL_NOKTA, IKINCIL_NOKTA):
            if n not in satirlar_n:
                continue
            progs = satirlar_n[n]["program"]
            gecen = sorted(p for p, v in progs.items() if v["zayif_yon_alt"] is not None
                           and v["zayif_yon_alt"] >= AD_ESIGI)
            olculen = sorted(progs)
            if len(olculen) < GENELLEME_EN_AZ_PROGRAM:
                h = "sayı yetmedi"
            elif len(gecen) >= GENELLEME_EN_AZ_GECEN:
                h = "tmux'a özgü değil"
            else:
                h = "tmux'a özgü"
            e[n] = {"olculen": olculen, "gecen": gecen, "oran": f"{len(gecen)}/{len(olculen)}", "hukum": h,
                    "birincil": n == BIRINCIL_NOKTA}
        sonuc["e"] = e
    sonuc["tekil_kural"] = tekil_duzey(grup, BIRINCIL_NOKTA)
    return sonuc


def _f(o: dict[str, Any]) -> str:
    k = o["kesinlik"]
    if not k.get("aralik"):
        return f"{o['dogru']} / {o['yanlis']} (veri yok)"
    return (f"{o['dogru']} / {o['yanlis']} = {k['oran']:.3f} [{k['aralik'][0]:.3f}–{k['aralik'][1]:.3f}]; "
            f"kapsam {o['dogru']} / {o['nufus']} = %{100 * o['dogru'] / o['nufus']:.1f}")


def md(s: dict[str, Any]) -> str:
    g = s["grup"]
    out = [f"### `{g}`", "", f"- Noktalar: {', '.join(s['noktalar'])}; v2: {s['v2']}."]
    if s.get("zaman_asimi_ghidra_tamam"):
        out.append(f"- Süre sınırına takılan (capa adımı; Ghidra çıktısı tamam, `success`): "
                   f"{', '.join(s['zaman_asimi_ghidra_tamam'])}.")
    for n, t in s["noktalar_tablo"].items():
        out.append(f"- **{n}** — iki yön havuzu {_f(t['havuz_iki_yon'])}")
        for y in ("yon:ileri", "yon:geri"):
            if y in t:
                out.append(f"  - {'/'.join(t[y]['ad'])}: {_f(t[y])} → {t[y]['a']}")
        out.append(f"  - grup hükmü (zayıf yön alt {t['grup_zayif_yon_alt'] if t['grup_zayif_yon_alt'] is None else round(t['grup_zayif_yon_alt'], 3)}): **{t['a']}**")
    out += ["", "| Program | Nokta | ileri | geri | zayıf yön alt | (a) |", "|---|---|---|---|---|---|"]
    for n, t in s["noktalar_tablo"].items():
        for prog, pr in t["program"].items():
            za = pr["zayif_yon_alt"]
            out.append(f"| {prog} | {n} | {_f(pr['ileri']) if 'ileri' in pr else '—'} | "
                       f"{_f(pr['geri']) if 'geri' in pr else '—'} | {'—' if za is None else f'{za:.3f}'} | {pr['a']} |")
    b = s["b"]
    out += ["", f"- (b) kural, tek taraflı {b['tek_tarafli']} / {b['toplam_yanlis']} yanlış"
                f" (pay {b['pay']}): {b['hukum']}{'' if b['uygulanir'] else ' (bu grupta ön kayıtlı hüküm yok; bilgi)'}; "
                f"sınıflar {b['siniflar']}"]
    if isinstance(s["d"], dict):
        for prog, v in s["d"].items():
            for cift, x in v.items():
                out.append(f"- (d) {prog} {cift}: v1 {x['v1'][0]}/{x['v1'][1]} → v2 {x['v2'][0]}/{x['v2'][1]} "
                           f"(nüfus {x['v1'][2]}): {x['hukum']}")
    else:
        out.append(f"- (d) {s['d']}")
    if "e" in s:
        for n, x in s["e"].items():
            out.append(f"- (e) {'birincil' if x['birincil'] else 'ikincil'} {n}: geçen {x['oran']} "
                       f"({', '.join(x['gecen']) or '—'}): **{x['hukum']}**")
    tk = s["tekil_kural"]
    for y in ("ileri", "geri"):
        if y in tk:
            o = tk[y]
            out.append(f"- A-14 tekil düzey (kural, {y}): {o['dogru']} / {o['yanlis']} öğe "
                       f"(alt {o['alt'] if o['alt'] is None else round(o['alt'], 3)}) → {o['a']}")
    return "\n".join(out) + "\n"


def kunye() -> dict[str, Any]:
    def sha(p: Path) -> str:
        return hashlib.sha256(p.read_bytes()).hexdigest()
    betik = {p.name: sha(p) for p in sorted(_BURASI.glob("*.py"))}
    betik["kimlik_ciftler.py"] = sha(Path(kc.__file__))
    ak = d0_veri.KOK / "agac_kunyesi.json"
    return {"betikler": betik, "urun_agaci": json.loads(ak.read_text(encoding="utf-8")) if ak.is_file() else None,
            "debian13_tarafi": str(veri.TABAN) + " (ürün a62f15e, tam boru hattı; yeni koşular b6aceb9 --stage static)",
            "noktalar": {k: {"T": p.T, "marj": p.marj, "kutle": p.kutle, "turler": list(p.turler)}
                         for k, p in esle.NOKTALAR.items()}, "AD_ESIGI": AD_ESIGI}


def kosu_durumu(grup: str) -> dict[str, Any]:
    """Grubun Dalga 0 koşuları: işaret (BITTI / ZAMAN_ASIMI / HATA) ve Ghidra'nın kendi başarı kaydı.

    x86-64 koşularında statik aşamanın capa adımı (süreç içi vivisect; ürünün ``capa_timeout``'u bu yolda
    uygulanmıyor) sürücünün süre sınırına takılabiliyor; Ghidra çıktıları o adımdan ÖNCE yazılmış ve
    ``ghidra_status.json`` ``success`` ise eşleyicinin okuduğu olgu tamdır. Ghidra başarısızsa ölçüm durur.
    """
    out: dict[str, Any] = {}
    for k in sorted({k for c in kc.grup(grup) for k in c}):
        d = d0_veri.KOSU / k
        if not d.is_dir():
            continue
        isaret = [i for i in ("BITTI", "ZAMAN_ASIMI", "HATA") if (d / i).exists()]
        st = sorted(d.glob("ws/workspaces/*/*/static/ghidra_status.json"))
        basari = json.loads(st[0].read_text(encoding="utf-8")).get("success") if len(st) == 1 else None
        if basari is not True:
            raise SystemExit(f"{k}: Ghidra çıktısı başarılı değil ya da yok (işaret {isaret}, success {basari})")
        out[k] = {"isaret": isaret, "ghidra_success": basari}
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("adim", choices=("betikler", "hukum", "hepsi"))
    ap.add_argument("--grup", required=True)
    ap.add_argument("--etiket", default=None)
    a = ap.parse_args(argv)
    etiket = a.etiket or a.grup
    durum = kosu_durumu(a.grup)
    if a.adim in ("betikler", "hepsi"):
        betikler(a.grup, etiket)
    if a.adim in ("hukum", "hepsi"):
        s = hukum(a.grup, etiket)
        s["kunye"] = kunye()
        s["kosu_durumu"] = durum
        s["zaman_asimi_ghidra_tamam"] = sorted(k for k, v in durum.items() if "ZAMAN_ASIMI" in v["isaret"])
        (OLCUM_DIZINI / f"hukum_{etiket}.json").write_text(json.dumps(s, ensure_ascii=False, indent=1, default=str),
                                                           encoding="utf-8")
        metin = md(s)
        (OLCUM_DIZINI / f"hukum_{etiket}.md").write_text(metin, encoding="utf-8")
        print(metin)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
