#!/usr/bin/env python3
"""ÖZ KOD hattı — ortak veri katmanı (ARGE 2026-11-19, tur 1).

Taban ürün koşusunun (a62f15e, 119 ikili) her ikilisi için tek bir sözlük kurar ve önbelleğe
yazar. Ghidra koşmaz; saklı koşu çıktılarını, ikiliyi ve GT'yi okur. Ölçüm betiklerinin
fonksiyonları içe aktarılır (kopyalanmaz): ``ks1_olc.gt_elf`` / ``gt_mac`` / ``capa_degerlendir``,
``urun_olc.degerlendir_elf`` / ``haritayi_oku``; veri sözcükleri için N4'ün okuyucusu
(``docs/arge/2026-11-10_n4/tablo_yuvasi_sayim.py``: ``elf_oku``, ``macho_oku``, ``Hedefci``).

Bölme (DEFTER.md §0; sayılara bakılmadan yazıldı):
    keşif  = debian/coreutils, debian/tmux, mac/tmux, debian/openssl
    sınama = debian/sqlite3, debian/redis-tools, debian/zstd, debian/htop, mac/htop, debian/tree

Kullanım (depo kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ozkod/ozkod_veri.py kur [--birim debian/tmux ...]
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ozkod/ozkod_veri.py ozet
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import pickle
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

REPO = Path(__file__).resolve().parents[3]
OLCUM = REPO / "scripts" / "measurement"
N4 = REPO / "docs" / "arge" / "2026-11-10_n4"
for _p in (str(REPO), str(OLCUM), str(N4)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

EV = Path.home()
KOSU_KOKU = EV / "karadul_olcum" / "runs" / "urun-onarim-a62f15e"
MAC_VERI = REPO / "workspaces" / "olcum_mac"
DEBIAN_INDIR = EV / "karadul_olcum" / "downloads" / "debian13"
ARGE_KOKU = EV / "karadul_olcum" / "runs" / "arge-2026-11-19" / "ozkod"
ONBELLEK = ARGE_KOKU / "onbellek"
SEMA = 5

KESIF_BIRIMLERI = ("debian/coreutils", "debian/tmux", "mac/tmux", "debian/openssl")
SINAMA_BIRIMLERI = ("debian/sqlite3", "debian/redis-tools", "debian/zstd", "debian/htop", "mac/htop",
          "debian/tree")
BIRIMLER = KESIF_BIRIMLERI + SINAMA_BIRIMLERI
# Aynı dosya iki adla (sonuc.md, ``ayni_dosyalar``): yalnız biri sayılır.
AYNI_DOSYA_ATLA = {("debian/redis-tools", "redis-check-rdb")}
PENCERE = 4          # kayıt çifti: fonksiyon yuvasının ± kaç sözcük komşusu (OLGU.md kalem 6 ile aynı)


def taraf(birim: str) -> str:
    if birim in KESIF_BIRIMLERI:
        return "kesif"
    if birim in SINAMA_BIRIMLERI:
        return "sinama"
    raise KeyError(birim)


def _yukle(ad: str, yol: Path):
    spec = importlib.util.spec_from_file_location(ad, yol)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[ad] = mod
    spec.loader.exec_module(mod)
    return mod


_ks1 = None
_urun = None
_n4 = None


def ks1():
    global _ks1
    if _ks1 is None:
        import ks1_olc
        _ks1 = ks1_olc
    return _ks1


def urun():
    global _urun
    if _urun is None:
        import urun_olc
        _urun = urun_olc
    return _urun


def n4():
    global _n4
    if _n4 is None:
        import tablo_yuvasi_sayim
        _n4 = tablo_yuvasi_sayim
    return _n4


# --------------------------------------------------------------------------------------------
# Belirteçler (ad ve dizgi için aynı kural; ölçü değildir, yalnız sayım aracı)

_CAMEL = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|[0-9]+")


def belirtecler(metin: str) -> list[str]:
    """Tanımlayıcı ya da serbest metni küçük harfli belirteçlere böl.

    Ayraç: harf / rakam olmayan her şey; ayrıca camelCase sınırı ve harf ↔ rakam sınırı.
    ``cmd_attach_session_exec`` → cmd, attach, session, exec; ``sqlite3ShellAdd`` → sqlite, 3,
    shell, add. Tek karakterlik belirteçler de döner (çağıran süzer).
    """
    out: list[str] = []
    for parca in re.split(r"[^A-Za-z0-9]+", metin):
        if parca:
            out.extend(m.group(0).lower() for m in _CAMEL.finditer(parca))
    return out


def ad_belirtecleri(ad: str) -> list[str]:
    """GT adının sayıma giren belirteçleri: rakam-dışı, en az 2 karakter."""
    return [b for b in belirtecler(ad) if len(b) >= 2 and not b.isdigit()]


def norm(metin: str) -> str:
    """Karşılaştırma biçimi: belirteçler ``_`` ile birleşik (kebap / camel / snake farkı kalkar)."""
    return "_".join(belirtecler(metin))


# --------------------------------------------------------------------------------------------
# İkililerin listesi


def elfler(birimler: Optional[Iterable[str]] = None) -> list[Any]:
    k = ks1()
    hepsi = k.elfleri_topla(KOSU_KOKU / "mac", KOSU_KOKU / "debian")
    hepsi = urun().haritasizlari_isaretle(hepsi)
    sec = set(birimler) if birimler else set(BIRIMLER)
    out = []
    for e in hepsi:
        b = k.birim_anahtari(e)
        if b not in sec or e.static is None or (b, e.ad) in AYNI_DOSYA_ATLA:
            continue
        out.append(e)
    return out


def onbellek_yolu(birim: str, ad: str) -> Path:
    temiz = re.sub(r"[^A-Za-z0-9_.+-]", "_", ad)
    return ONBELLEK / f"{birim.replace('/', '__')}__{temiz}.pkl"


# --------------------------------------------------------------------------------------------
# Bir ikilinin kaydı


def _json(yol: Path) -> Any:
    return json.loads(Path(yol).read_text(encoding="utf-8"))


def _hex(s: Any) -> Optional[int]:
    try:
        return int(str(s), 16)
    except (TypeError, ValueError):
        return None


def ikili_kur(e: Any) -> dict[str, Any]:
    k, u = ks1(), urun()
    f1 = k._f1()
    birim = k.birim_anahtari(e)
    static = Path(e.static)
    fdoc = _json(static / "ghidra_functions.json").get("functions", [])
    if k.cpp_ikili_mi(fdoc, e.platform):
        return {"sema": SEMA, "birim": birim, "ad": e.ad, "platform": e.platform, "cpp": True}
    gt = k.gt_mac(e, MAC_VERI) if e.platform == k.PLATFORM_MAC else k.gt_elf(e, DEBIAN_INDIR)
    gfonk = f1.load_ghidra_functions(static / "ghidra_functions.json")

    fonk: dict[int, dict[str, Any]] = {}
    for g in fdoc:
        a = _hex(g.get("address"))
        if a is None:
            continue
        fonk[a] = {"ad": g.get("name") or "", "boyut": g.get("size") or 0,
                   "thunk": bool(g.get("is_thunk")), "dis": bool(g.get("is_external"))}

    # GT adları platform biçiminde (Mach-O'da baştaki '_' soyulur), klon ekleri ayrıca soyulmaz
    gt_adlar = {a: [k.platform_adi(n, e.platform) for n in adlar] for a, adlar in gt.adlar.items()}

    # Ürünün adları ve hükmü (urun_olc ile aynı tanım)
    genel, koken, _kimlik = u.haritayi_oku(e.kosu)
    kayitlar, _sayac = u.degerlendir_elf(genel, koken, gfonk, gt, e.platform)
    urun_ad = {}
    for r in kayitlar:
        kk = koken.get(f"FUN_{r['adres']:08x}") or koken.get(f"FUN_{r['adres']:x}") or {}
        urun_ad[r["adres"]] = {"ad": r["ad"], "durum": r["durum"], "satir": r["satir"],
                               "nufusta": r["nufusta"], "etiket": r["etiket"], "kanal": r["kanal"],
                               "koken": kk}
    koken_bulunamayan = sum(1 for v in urun_ad.values() if not v["koken"])

    # Dizgiler: fonksiyon → (dizgi adresi, metin); dizgi → onu anan fonksiyon kümesi
    sdoc = _json(static / "ghidra_strings.json").get("strings", [])
    dizgi_metin: dict[int, str] = {}
    fn_dizgi: dict[int, list[int]] = defaultdict(list)
    dizgi_fn: dict[int, set[int]] = defaultdict(set)
    dizgi_xref_adres: dict[int, list[tuple[int, int]]] = defaultdict(list)  # dizgi → (fn, çağrı yeri)
    for s in sdoc:
        sa = _hex(s.get("address"))
        if sa is None:
            continue
        dizgi_metin[sa] = s.get("value") or ""
        for x in s.get("xrefs") or []:
            fa = _hex(x.get("from_func_addr"))
            if fa is None:
                continue
            if sa not in fn_dizgi[fa]:
                fn_dizgi[fa].append(sa)
            dizgi_fn[sa].add(fa)
            ya = _hex(x.get("from_address"))
            if ya is not None:
                dizgi_xref_adres[sa].append((fa, ya))

    # Çağrı grafiği
    cg = _json(static / "ghidra_call_graph.json")
    cagrilan: dict[int, list[int]] = defaultdict(list)
    cagiran: dict[int, list[int]] = defaultdict(list)
    for kenar in cg.get("edges", []):
        a, b = _hex(kenar.get("from")), _hex(kenar.get("to"))
        if a is None or b is None:
            continue
        if b not in cagrilan[a]:
            cagrilan[a].append(b)
        if a not in cagiran[b]:
            cagiran[b].append(a)

    # Veri sözcükleri (N4 okuyucusu): fonksiyon yuvaları ve komşu dizgi yuvaları
    t = n4()
    ham = Path(_json(e.kosu / "raw" / "target_info.json")["path"])
    giris = {a: ("thunk" if f["thunk"] else "ic") for a, f in fonk.items() if not f["dis"]}
    if e.platform == k.PLATFORM_MAC:
        dis_adlar = {f["ad"].lstrip("_") for f in fonk.values() if f["thunk"] or f["dis"]}
        ik = t.macho_oku(ham, static, giris, dis_adlar)
    else:
        ik = t.elf_oku(ham, static, giris)
    hedefci = t.Hedefci(giris, ik["metin"], ik["ro"])
    yuvalar: list[dict[str, Any]] = []       # fonksiyon yuvası başına bir kayıt
    bolum_dokumu = {}
    nf = t.nufus_oku(static)                 # yalnız kodda hesaplanan adresler için (çapa)
    capa_adresleri = t.capa_kumesi(ik, nf)
    tablo_no = 0
    for bolum_adi, grup, bas, bayt in ik["veri_bolumleri"]:
        ilk, turler, hedefler = t.bolum_turleri(bayt, bas, ik["yer_degisim"], hedefci)
        bolum_dokumu[bolum_adi] = (grup, ilk, turler, hedefler,
                                   {q: hedefci.dizgi(hedefler[q]) for q, tq in enumerate(turler)
                                    if tq == t.TUR_S})
        if grup != "veri":
            continue
        capalar = frozenset((c - ilk) // t.SOZCUK for c in capa_adresleri
                            if ilk <= c < ilk + len(turler) * t.SOZCUK and (c - ilk) % t.SOZCUK == 0)
        sirali_capa = sorted(capalar)
        # N4 tablo tanımı (adım, faz, kayıt dizgisi): tablo_yuvasi_sayim.tablolari_sec
        tablolar, _belirsiz, _sayac = t.tablolari_sec(turler, capalar)
        tablo_bilgisi: dict[int, dict[str, Any]] = {}
        for tb in tablolar:
            tablo_no += 1
            yapi = t.tablo_yapisi(turler, tb)
            sinif_ = t.tablo_sinifi(yapi)
            s_ = tb["adim"]
            b0 = tb["fazlar"][0]
            for p, (kesin, gevsek) in t.kayit_dizgileri(turler, tb).items():
                if turler[p] != t.TUR_F:
                    continue
                tablo_bilgisi[p] = {
                    "tablo": tablo_no, "adim": s_, "sinif": sinif_, "kayit": yapi["kayit"],
                    "bolge": tuple(tb["bolge"]),
                    "faz_belirsiz": yapi["faz_belirsiz"], "capali": yapi["capali"],
                    "kayitta_en_cok_fn": yapi["kayitta_en_cok_fn"],
                    "sutun": (p - b0) % s_,
                    "kesin": [(q - p, hedefci.dizgi(hedefler[q])) for q in sorted(kesin)],
                    "gevsek": [(q - p, hedefci.dizgi(hedefler[q])) for q in sorted(gevsek)]}
        import bisect
        for i, tur in enumerate(turler):
            if tur != t.TUR_F:
                continue
            # çapa nesnesi: yuvadan önceki (ya da yuvadaki) son çapadan sonraki ilk çapaya kadar
            k_ = bisect.bisect_right(sirali_capa, i) - 1
            nb = sirali_capa[k_] if k_ >= 0 else None
            ns = sirali_capa[k_ + 1] if k_ + 1 < len(sirali_capa) else None
            nesne = None
            if nb is not None and ns is not None and ns - nb <= 64:
                nesne = {"bas": nb - i, "uzunluk": ns - nb,
                         "turler": "".join(turler[nb:ns]),
                         "dizgi": [(q - i, hedefci.dizgi(hedefler[q])) for q in range(nb, ns)
                                   if turler[q] == t.TUR_S]}
            komsu = []
            for d in range(-PENCERE, PENCERE + 1):
                j = i + d
                if d == 0 or not 0 <= j < len(turler):
                    continue
                if turler[j] == t.TUR_S:
                    komsu.append((d, hedefler[j], hedefci.dizgi(hedefler[j])))
            yuvalar.append({"bolum": bolum_adi, "yuva": ilk + i * t.SOZCUK, "sira": i,
                            "fn": hedefler[i], "komsu": komsu,
                            "tablo": tablo_bilgisi.get(i), "nesne": nesne,
                            "pencere_turleri": "".join(
                                turler[j] if 0 <= j < len(turler) else "-"
                                for j in range(i - PENCERE, i + PENCERE + 1))})

    return {"sema": SEMA, "birim": birim, "taraf": taraf(birim), "ad": e.ad, "platform": e.platform,
            "cpp": False, "static": str(static), "kosu": str(e.kosu), "ham": str(ham),
            "fonk": fonk, "gt_adlar": gt_adlar, "nufus": set(gt.nufus), "urun": urun_ad,
            "koken_bulunamayan": koken_bulunamayan,
            "dizgi_metin": dizgi_metin, "fn_dizgi": dict(fn_dizgi),
            "dizgi_fn": {a: sorted(v) for a, v in dizgi_fn.items()},
            "dizgi_xref": dict(dizgi_xref_adres),
            "cagrilan": dict(cagrilan), "cagiran": dict(cagiran),
            "yuvalar": yuvalar, "bolum_dokumu": bolum_dokumu,
            "yd_sayac": dict(ik["yd_sayac"]), "kayma": ik["kayma"]}


def yukle(e: Any, yenile: bool = False) -> dict[str, Any]:
    yol = onbellek_yolu(ks1().birim_anahtari(e), e.ad)
    if yol.is_file() and not yenile:
        with open(yol, "rb") as f:
            d = pickle.load(f)
        if d.get("sema") == SEMA:
            return d
    d = ikili_kur(e)
    yol.parent.mkdir(parents=True, exist_ok=True)
    with open(yol, "wb") as f:
        pickle.dump(d, f, protocol=pickle.HIGHEST_PROTOCOL)
    return d


def hepsi(birimler: Optional[Iterable[str]] = None, taraf_: Optional[str] = None,
          yenile: bool = False) -> Iterator[dict[str, Any]]:
    """C ikililerinin kayıtları (C++ ölçü dışı). ``taraf_`` = 'kesif' | 'sinama' | None."""
    if taraf_:
        birimler = [b for b in (birimler or BIRIMLER) if taraf(b) == taraf_]
    for e in elfler(birimler):
        d = yukle(e, yenile)
        if not d.get("cpp"):
            yield d


def wilson(k_: int, n_: int) -> str:
    o = ks1().oran(k_, n_)
    if not n_:
        return "0 / 0"
    a = o["aralik"]
    return f"{k_} / {n_} (%{100 * k_ / n_:.1f}; %{100 * a[0]:.1f}–%{100 * a[1]:.1f})"


# --------------------------------------------------------------------------------------------


def _tutarlilik(kayitlar: list[dict[str, Any]]) -> dict[str, Any]:
    """Taban ölçümüyle (sonuc.md §2) karşılaştırılacak toplamlar."""
    birim: dict[str, Counter] = defaultdict(Counter)
    for d in kayitlar:
        c = birim[d["birim"]]
        c["ikili"] += 1
        c["nufus"] += len(d["nufus"])
        for a, r in d["urun"].items():
            c["ad"] += 1
            c["dogru"] += r["durum"] == "dogru"
            c["yanlis"] += r["durum"] != "dogru"
            c["nufusta_dogru"] += r["nufusta"] and r["durum"] == "dogru"
            c["oz_ad"] += r["kanal"] == "string_context/oz_ad"
            c["oz_ad_dogru"] += r["kanal"] == "string_context/oz_ad" and r["durum"] == "dogru"
    toplam: Counter = Counter()
    for c in birim.values():
        toplam.update(c)
    return {"birim": {b: dict(c) for b, c in sorted(birim.items())}, "toplam": dict(toplam)}


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="komut", required=True)
    kr = sub.add_parser("kur", help="önbelleği kur")
    kr.add_argument("--birim", action="append", default=None)
    kr.add_argument("--yenile", action="store_true")
    sub.add_parser("ozet", help="tutarlılık kapısı: taban ölçümünün toplamları")
    a = ap.parse_args(argv)
    if a.komut == "kur":
        t0 = time.time()
        n = 0
        for e in elfler(a.birim):
            t1 = time.time()
            d = yukle(e, a.yenile)
            n += 1
            print(f"{ks1().birim_anahtari(e)}/{e.ad}: fonk {len(d.get('fonk', {}))} nufus "
                  f"{len(d.get('nufus', ()))} yuva {len(d.get('yuvalar', ()))} "
                  f"cpp {d.get('cpp')} ({time.time() - t1:.1f} sn)", flush=True)
        print(f"toplam {n} ikili, {time.time() - t0:.0f} sn")
        return 0
    t = _tutarlilik(list(hepsi()))
    print(json.dumps(t, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
