#!/usr/bin/env python3
"""ÖZ KOD kalem 2 — kayıt çifti tavanı (aykırı öncül 1).

"Ad taşıyan kanıt fonksiyonun içinde değil, onu kaydeden yerdedir": (dizgi, fonksiyon işaretçisi)
çiftleri iki yerden toplanır ve GT adıyla ilişkisi sayılır.

Çift tanımları
--------------
V  (veri kaydı)   : veri bölümünde fonksiyon yuvası; aynı KAYITTAKİ dizgi yuvaları. Kayıt = N4'ün
                    tablo tanımı (``tablo_yuvasi_sayim.tablolari_sec``; adım > 1; "kesin" dizgiler:
                    bütün eşit fazlarda aynı kayıtta) ya da tablo dışında çapa nesnesi (iki ardışık
                    çapa arası, ≤ 64 sözcük). Çapa = yer değişimi hedefi ya da kodda hesaplanan adres.
P  (pencere)      : yuvanın ± 4 sözcük komşusundaki dizgi yuvaları (OLGU.md kalem 6 tanımı; kayıt
                    sınırı bilgisi yok, yalnız üst sınır için).
C  (çağrı yeri)   : decompile edilmiş C'de aynı çağrının argümanlarında birlikte geçen dizgi sabiti
                    ve ``FUN_<adres>`` fonksiyon işaretçisi.

İlişki sınıfları (ad dizgisi S, GT adı G; ``norm`` = belirteçler '_' ile)
    tam        : norm(S) == norm(G)
    ekli       : norm(S)'in belirteç dizisi G'nin belirteç dizisinde bitişik geçer, G ≠ S
                 (G = önek + S + sonek; "basit kuralla tam" adayı — ek ayrı ölçülür)
    ortusme    : en az bir ortak belirteç (≥ 2 karakter, rakam dışı)
    ilgisiz    : ortak belirteç yok

Ad dizgisi seçimi (belirlenimci): kayıttaki / çağrıdaki dizgilerden biçimi ``tanimlayici`` ya da
``kisa_ad`` olan (N4 ``dizgi_sinifi``) İLK dizgi (kayıt başına göre en küçük ofset; çağrıda en soldaki).
"Kâhin" sütunu aynı aday kümesinde en iyi sınıfı verir (seçim hatasız olsaydı).

Ek kuralı (sütun eki; v2 — keşifte Mac tmux'ta N4 fazının bir tabloda kaydığı görüldükten sonra)
    Aday grup: V'de (tablo, fonksiyon sütunu, δ) — δ fonksiyon yuvasına göre dizgi yuvasının
    ofseti, −adım < δ < adım, faz varsayımı yok; tablo dışı nesnede (nesne tür dizisi, fonksiyon
    ofseti, dizgi ofseti); C'de (çağrılan, argüman sayısı, fonksiyon argümanı, dizgi argümanı).
    Grubun eki, hedef dışındaki üyelerin ("çapa") adından öğrenilir: ad = önek + norm(S) + sonek.
    En çok oyu alan ek en az MIN_DESTEK çapadan gelmeli ve ikinciden kesin fazla olmalı. Yanlış δ
    çapalarda ek vermez; böylece faz çapayla çözülür. Bir fonksiyon için bütün gruplarından çıkan
    adaylar tek bir ada iniyorsa ad verilir; birden çok farklı aday varsa çekimser.
    Çapa kaynakları: (a) kâhin — öbür üyelerin GT adı (biri dışarıda; üst sınır);
    (b) tek çapa beklentisi; (c) ürünün bugünkü adları (hükmüne bakılmadan);
    (d) eksiz: aday = norm(S) (çapa gerektirmez; yalnız C grubunda ve ad dizgisi tek ise).
    Sayılan: tam eşitlik (norm: belirteç ayracı serbest; ayrıca karakter eşitliği).

Kullanım:
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ozkod/kayit_cifti.py --taraf kesif
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ozkod/kayit_cifti.py --taraf sinama   # kural dondurulduktan sonra
"""
from __future__ import annotations

import argparse
import json
import pickle
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ozkod_veri as V  # noqa: E402

CAGRI_ONBELLEK = V.ARGE_KOKU / "onbellek_cagri"
CIKTI = V.ARGE_KOKU / "kayit_cifti"
ILISKILER = ("tam", "ekli", "ortusme", "ilgisiz")

# --------------------------------------------------------------------------------------------
# Çağrı yeri çiftleri (decompile edilmiş C metninden)

_CAGRI_BASI = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_FN_ARG = re.compile(r"^(?:\([^()]*\)\s*)*&?\s*(?:thunk_)?FUN_([0-9a-fA-F]+)$")
_DIZGI_ARG = re.compile(r'^(?:\([^()]*\)\s*)*"((?:[^"\\]|\\.)*)"$')
_ANAHTAR = frozenset({"if", "while", "for", "switch", "return", "sizeof", "do", "else"})


def _argumanlar(metin: str, bas: int) -> tuple[Optional[list[str]], int]:
    """``metin[bas]`` '(' olmalı. Üst düzey virgüllerden bölünmüş argümanlar ve kapanış konumu."""
    derinlik = 0
    parca_bas = bas + 1
    out: list[str] = []
    i = bas
    n = len(metin)
    while i < n:
        c = metin[i]
        if c == '"':
            i += 1
            while i < n and metin[i] != '"':
                i += 2 if metin[i] == "\\" else 1
        elif c == "'":
            i += 1
            while i < n and metin[i] != "'":
                i += 2 if metin[i] == "\\" else 1
        elif c in "([{":
            derinlik += 1
        elif c in ")]}":
            derinlik -= 1
            if derinlik == 0:
                out.append(metin[parca_bas:i].strip())
                return out, i
        elif c == "," and derinlik == 1:
            out.append(metin[parca_bas:i].strip())
            parca_bas = i + 1
        elif c == ";" and derinlik <= 1:
            return None, i
        i += 1
    return None, n


def _c_dizgisi(ham: str) -> str:
    try:
        return bytes(ham, "utf-8").decode("unicode_escape").encode("latin-1", "replace").decode(
            "utf-8", "replace")
    except (UnicodeDecodeError, UnicodeEncodeError):
        return ham


def cagri_ciftleri_metin(metin: str) -> list[dict[str, Any]]:
    """Bir fonksiyonun C metnindeki (dizgi, fonksiyon işaretçisi) çağrı argümanı çiftleri."""
    kes = metin.find("// --- DISASSEMBLY")
    if kes >= 0:
        metin = metin[:kes]
    out = []
    for m in _CAGRI_BASI.finditer(metin):
        ad = m.group(1)
        if ad in _ANAHTAR:
            continue
        arglar, _son = _argumanlar(metin, m.end() - 1)
        if not arglar or len(arglar) < 2:
            continue
        fnler = [(i, int(mm.group(1), 16)) for i, a in enumerate(arglar)
                 if (mm := _FN_ARG.match(a))]
        if not fnler:
            continue
        dizgiler = [(i, _c_dizgisi(mm.group(1))) for i, a in enumerate(arglar)
                    if (mm := _DIZGI_ARG.match(a))]
        if not dizgiler:
            continue
        for fi, fa in fnler:
            out.append({"cagrilan": ad, "n_arg": len(arglar), "fn_arg": fi, "fn": fa,
                        "dizgiler": dizgiler})
    return out


def cagri_ciftleri(d: dict[str, Any]) -> list[dict[str, Any]]:
    yol = CAGRI_ONBELLEK / V.onbellek_yolu(d["birim"], d["ad"]).name
    if yol.is_file():
        with open(yol, "rb") as f:
            return pickle.load(f)
    dizin = Path(d["static"]) / "ghidra_output" / "decompiled"
    out = []
    for c in sorted(dizin.glob("*.c")):
        metin = c.read_text(encoding="utf-8", errors="replace")
        m = re.search(r"^// Address:\s+([0-9a-fA-F]+)", metin, re.M)
        icinde = int(m.group(1), 16) if m else None
        for r in cagri_ciftleri_metin(metin):
            r["icinde"] = icinde
            out.append(r)
    yol.parent.mkdir(parents=True, exist_ok=True)
    with open(yol, "wb") as f:
        pickle.dump(out, f, protocol=pickle.HIGHEST_PROTOCOL)
    return out


# --------------------------------------------------------------------------------------------
# İlişki


def ad_bicimli(s: str) -> bool:
    return V.n4().dizgi_sinifi(s) in V.n4().AD_KANITI_SINIFLARI and len(s) >= 2


def iliski(dizgi: str, gt_adlari: list[str]) -> str:
    """Dizginin GT adlarından biriyle en iyi ilişkisi."""
    sb = V.belirtecler(dizgi)
    en_iyi = 3
    for g in gt_adlari:
        gb = V.belirtecler(g)
        if sb and sb == gb:
            return "tam"
        if sb and len(sb) < len(gb) and any(gb[i:i + len(sb)] == sb
                                            for i in range(len(gb) - len(sb) + 1)):
            en_iyi = min(en_iyi, 1)
            continue
        ortak = {b for b in sb if len(b) >= 2 and not b.isdigit()} & set(V.ad_belirtecleri(g))
        if ortak:
            en_iyi = min(en_iyi, 2)
    return ILISKILER[en_iyi]


def ek_cikar(dizgi: str, gt_ad: str) -> Optional[tuple[str, str]]:
    """GT = önek + norm(dizgi) + sonek ise (önek, sonek); belirteç sınırında tek geçiş."""
    sb, gb = V.belirtecler(dizgi), V.belirtecler(gt_ad)
    if not sb or len(sb) > len(gb):
        return None
    yerler = [i for i in range(len(gb) - len(sb) + 1) if gb[i:i + len(sb)] == sb]
    if len(yerler) != 1:
        return None
    i = yerler[0]
    return "_".join(gb[:i]), "_".join(gb[i + len(sb):])


def ek_uygula(dizgi: str, ek: tuple[str, str]) -> str:
    return "_".join(p for p in (ek[0], V.norm(dizgi), ek[1]) if p)


def gt_esit(aday: str, gt_adlari: list[str]) -> bool:
    """Tam eşitlik, yalnız belirteç ayracı biçimi serbest (kebap / camel ↔ snake): norm eşitliği.
    Ürün ölçüsündeki karakter eşitliği ayrıca ``karakter_esit`` ile sayılır."""
    return any(V.norm(aday) == V.norm(g) for g in gt_adlari)


def karakter_esit(aday: str, gt_adlari: list[str]) -> bool:
    return aday in gt_adlari


# --------------------------------------------------------------------------------------------
# Bir ikilinin çiftleri


def ikili_ciftleri(d: dict[str, Any]) -> dict[int, dict[str, Any]]:
    """fonksiyon adresi → {"V": [...], "P": [...], "C": [...]} çift kayıtları.

    Her kayıt: {"grup": anahtar, "dizgiler": [metin, ...] (sıralı), "tur": ...}.
    """
    out: dict[int, dict[str, list]] = defaultdict(lambda: {"V": [], "P": [], "C": [], "yuva": 0})
    for y in d["yuvalar"]:
        fa = y["fn"]
        k = out[fa]
        k["yuva"] += 1
        if y["komsu"]:
            k["P"].append({"grup": ("P", y["bolum"]),
                           "dizgiler": [s for _d, _a, s in sorted(y["komsu"], key=lambda z: abs(z[0]))]})
        tb = y["tablo"]
        if tb and tb["adim"] > 1:
            if tb["kesin"]:
                # kayıt başına göre sıralı (ofset küçükten büyüğe = kayıt içi sıra)
                k["V"].append({"grup": ("T", tb["tablo"], tb["sutun"]), "tur": "tablo",
                               "sinif": tb["sinif"], "faz_belirsiz": tb["faz_belirsiz"],
                               "dizgiler": [s for _o, s in tb["kesin"]]})
        elif y["nesne"] and y["nesne"]["dizgi"]:
            ns = y["nesne"]
            k["V"].append({"grup": ("N", ns["turler"], -ns["bas"]), "tur": "nesne",
                           "sinif": "nesne", "faz_belirsiz": False,
                           "dizgiler": [s for _o, s in ns["dizgi"]]})
    for r in cagri_ciftleri(d):
        fa = r["fn"]
        if fa not in d["fonk"]:
            continue
        out[fa]["C"].append({"grup": ("C", r["cagrilan"], r["n_arg"], r["fn_arg"],
                                      tuple(i for i, _ in r["dizgiler"])),
                             "tur": "cagri", "icinde": r["icinde"],
                             "dizgiler": [s for _i, s in r["dizgiler"]]})
    return out


def ad_dizgisi(kayit: dict[str, Any]) -> Optional[str]:
    for s in kayit["dizgiler"]:
        if s and ad_bicimli(s):
            return s
    return None


# --------------------------------------------------------------------------------------------


def say(taraf_: str) -> dict[str, Any]:
    birim_say: dict[str, Counter] = defaultdict(Counter)
    ornek: dict[str, list] = defaultdict(list)
    for d in V.hepsi(taraf_=taraf_):
        c = birim_say[d["birim"]]
        ciftler = ikili_ciftleri(d)
        c["ikili"] += 1
        c["nufus"] += len(d["nufus"])
        for fa in d["nufus"]:
            gt = d["gt_adlar"][fa]
            k = ciftler.get(fa)
            if not k:
                continue
            c["yuva_var"] += bool(k["yuva"])
            c["P_var"] += bool(k["P"])
            c["V_var"] += bool(k["V"])
            c["C_var"] += bool(k["C"])
            c["VC_var"] += bool(k["V"] or k["C"])
            c["PVC_var"] += bool(k["P"] or k["V"] or k["C"])
            for tur in ("P", "V", "C"):
                if not k[tur]:
                    continue
                # kâhin: bütün aday dizgiler içinde en iyi ilişki
                hepsi_ = [s for r in k[tur] for s in r["dizgiler"] if s]
                en_iyi = min((ILISKILER.index(iliski(s, gt)) for s in hepsi_), default=3)
                c[f"{tur}_kahin_{ILISKILER[en_iyi]}"] += 1
            # belirlenimci ad dizgisi: V ve C; fonksiyonun TEK kaydı varsa ("tekil")
            for tur in ("V", "C"):
                kayitlar = k[tur]
                if not kayitlar:
                    continue
                adlar = [(r, ad_dizgisi(r)) for r in kayitlar]
                adlar = [(r, s) for r, s in adlar if s]
                if not adlar:
                    c[f"{tur}_ad_dizgisi_yok"] += 1
                    continue
                farkli = {V.norm(s) for _r, s in adlar}
                tekil = len(farkli) == 1
                c[f"{tur}_ad_dizgili"] += 1
                c[f"{tur}_tekil"] += tekil
                r0, s0 = adlar[0]
                il = iliski(s0, gt)
                c[f"{tur}_{'tekil' if tekil else 'cogul'}_{il}"] += 1
                if tekil:
                    if len(ornek[f"{d['birim']}|{tur}|{il}"]) < 12:
                        ornek[f"{d['birim']}|{tur}|{il}"].append((gt[0], s0))
            # V ya da C'den en az birinde tekil ad dizgisi (birleşik erişim)
    return {"taraf": taraf_, "birim": {b: dict(c) for b, c in sorted(birim_say.items())},
            "ornek": {k: v for k, v in sorted(ornek.items())}}


def _pct(k: int, n: int) -> str:
    return f"{k} (%{100 * k / n:.1f})" if n else f"{k}"


def yaz(s: dict[str, Any], ornekli: bool) -> None:
    print(f"\n## Erişim — taraf: {s['taraf']}  (payda: nüfus)")
    print("| birim | nüfus | veri yuvası | P pencere dizgisi | V kayıt dizgisi | C çağrı çifti | V ∪ C |")
    print("|---|---:|---:|---:|---:|---:|---:|")
    s = dict(s)
    s["birim"] = {b: Counter(c) for b, c in s["birim"].items()}
    top = Counter()
    for b, c in s["birim"].items():
        top.update(c)
    for b, c in list(s["birim"].items()) + [("**toplam**", top)]:
        n = c["nufus"]
        print(f"| {b} | {n} | {_pct(c['yuva_var'], n)} | {_pct(c['P_var'], n)} | {_pct(c['V_var'], n)} "
              f"| {_pct(c['C_var'], n)} | {_pct(c['VC_var'], n)} |")
    for tur, ad in (("V", "veri kaydı"), ("C", "çağrı yeri"), ("P", "pencere ± 4")):
        print(f"\n## İlişki, kâhin (aday dizgiler içinde en iyisi) — {ad}")
        print("| birim | çiftli | tam | ekli | örtüşme | ilgisiz |")
        print("|---|---:|---:|---:|---:|---:|")
        for b, c in list(s["birim"].items()) + [("**toplam**", top)]:
            n = c[f"{tur}_var"]
            print(f"| {b} | {n} | " + " | ".join(_pct(c[f"{tur}_kahin_{i}"], n) for i in ILISKILER) + " |")
    for tur, ad in (("V", "veri kaydı"), ("C", "çağrı yeri")):
        print(f"\n## İlişki, belirlenimci ad dizgisi (ilk ad biçimli dizgi) — {ad}")
        print("| birim | çiftli | ad dizgili | tekil | tekil: tam | ekli | örtüşme | ilgisiz | çoğul: tam | ekli | örtüşme | ilgisiz |")
        print("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
        for b, c in list(s["birim"].items()) + [("**toplam**", top)]:
            n = c[f"{tur}_tekil"]
            print(f"| {b} | {c[f'{tur}_var']} | {c[f'{tur}_ad_dizgili']} | {n} | "
                  + " | ".join(_pct(c[f"{tur}_tekil_{i}"], n) for i in ILISKILER) + " | "
                  + " | ".join(str(c[f"{tur}_cogul_{i}"]) for i in ILISKILER) + " |")
    if ornekli:
        print("\n## Örnekler (GT adı ← ad dizgisi)")
        for k, v in s["ornek"].items():
            print(f"- {k}: " + "; ".join(f"`{g}` ← \"{d}\"" for g, d in v[:8]))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--taraf", choices=("kesif", "sinama"), required=True)
    ap.add_argument("--ornekli", action="store_true", help="ad ve dizgi örnekleri (yalnız keşif)")
    a = ap.parse_args()
    if a.ornekli and a.taraf != "kesif":
        raise SystemExit("örnek dökümü yalnız keşif tarafında")
    s = say(a.taraf)
    CIKTI.mkdir(parents=True, exist_ok=True)
    (CIKTI / f"kayit_cifti_{a.taraf}.json").write_text(
        json.dumps(s, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
    yaz(s, a.ornekli)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
