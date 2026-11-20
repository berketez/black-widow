#!/usr/bin/env python3
"""ÖZ KOD hattı ÖK-V adım 1–4 ve 7: bağımsız sınama nüfusu (liste, bölme, indirme, sabitleme, ikili seçimi).

Plan: ``docs/arge/2026-11-19_mythos/ozkod/PLAN.md`` "ÖK-V"; kayıt: ``docs/arge/2026-11-19_mythos/ozkod/NUFUS.md``.
Ürün koşusu (adım 5) ve olgu önbelleği (adım 6) bu betiğin işi değil.

KÖRLÜK: "kör" taraftaki paketlerin sembol adları, dizgileri ve kaynak kodu okunmaz, yazılmaz. Bu betik
iki tarafta da yalnız sha256, BuildID, boyut, ELF sayısı ve sembol SAYISI üretir; GT adı yazmaz.
"kör" paketlerde ELF yolları ekrana basılmaz (yalnız veri dosyasına, sonraki koşu için yazılır).
C++ denetimi ``.dynsym`` içe aktarımlarının önekine bakar ve yalnız evet / hayır döndürür.

İndirme, doğrulama ve açma ``scripts/arge/olcu/tabaka_indir.py``'nin sınanmış işlevleriyle yapılır
(resmî arşiv öneki, gpgv ile InRelease imzası, Packages sha256'sı, dosya sha256'sı, güvenli açma).
İndirilen hiçbir dosya çalıştırılmaz. Bu betik ``python -I`` ile ve depo kökünden koşulur.

Kullanım (depo kökünden):
  PYTHONDONTWRITEBYTECODE=1 python -I scripts/measurement/ozkod_nufus_kur.py bolme
  PYTHONDONTWRITEBYTECODE=1 python -I scripts/measurement/ozkod_nufus_kur.py dizin --kok ~/karadul_olcum/ozkod_nufus
  PYTHONDONTWRITEBYTECODE=1 python -I scripts/measurement/ozkod_nufus_kur.py kur --kok ~/karadul_olcum/ozkod_nufus
  PYTHONDONTWRITEBYTECODE=1 python -I scripts/measurement/ozkod_nufus_kur.py rapor --kok ~/karadul_olcum/ozkod_nufus
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
import time
from pathlib import Path
from typing import Any, Optional

REPO = Path(__file__).resolve().parents[2]
OLCUM = REPO / "scripts" / "measurement"
TABAKA_INDIR = REPO / "scripts" / "arge" / "olcu" / "tabaka_indir.py"
SEMA_SECIM = "karadul-ozkod-nufus-secim/1"
SEMA_NUFUS = "karadul-ozkod-nufus/1"
DAGITIM = "debian13_arm64"

ADAY_BETIGI = REPO / "scripts" / "arge" / "ozkod" / "aday_paket.py"
# ÖK-V adım 4: aynı kaynaktan paketler aynı tarafa, ilk paketin tarafına (PLAN'ın açık grupları).
KAYNAK_GRUPLARI = (("tcl8.6", "libtcl8.6"), ("lua-socket", "lua-cjson"),
                   ("python3.13-minimal", "libpython3.13-stdlib"))
AYAR, KOR = "ayar", "kör"
# ELF seçim kuralı (NUFUS.md §3; açmadan önce yazıldı): kitaplık paketinde bütün paylaşımlı nesneler,
# program paketinde paketin en büyük ELF'i.
KITAPLIK_ONEKLERI = ("lib", "lua-")


def _modul(ad: str, yol: Path):
    if ad in sys.modules:
        return sys.modules[ad]
    if str(yol.parent) not in sys.path:
        sys.path.insert(0, str(yol.parent))
    spec = importlib.util.spec_from_file_location(ad, yol)
    m = importlib.util.module_from_spec(spec)
    sys.modules[ad] = m
    spec.loader.exec_module(m)
    return m


def ti():
    return _modul("tabaka_indir", TABAKA_INDIR)


# ÖK-V adım 1'in listesi: ÖZ KOD hattının ``aday_paket.py``'sindeki 24 paket, o betikteki sırayla
# (tek kaynak; A-4 bu 24 paketi onayladı, postgresql-17 dahil).
ADAY_PAKETLER: tuple[str, ...] = tuple(ad for ad, _ in _modul("aday_paket", ADAY_BETIGI).ADAYLAR)


# ---------------------------------------------------------------------------
# Adım 4: bölme (yalnız paket adlarından; veri gerekmez)
# ---------------------------------------------------------------------------

def ilk_bayt(paket: str) -> int:
    return hashlib.sha256(paket.encode("utf-8")).digest()[0]


def ham_taraf(paket: str) -> str:
    return AYAR if ilk_bayt(paket) % 2 == 0 else KOR


def taraflar(adaylar: Optional[tuple[str, ...]] = None,
             gruplar: tuple[tuple[str, ...], ...] = KAYNAK_GRUPLARI) -> dict[str, dict[str, Any]]:
    adaylar = ADAY_PAKETLER if adaylar is None else adaylar
    out = {}
    for p in adaylar:
        grup = next((g for g in gruplar if p in g), None)
        ilk = min(grup, key=adaylar.index) if grup else p
        out[p] = {"ilk_bayt": ilk_bayt(p), "ham_taraf": ham_taraf(p), "grup_ilk": ilk, "taraf": ham_taraf(ilk)}
    return out


# ---------------------------------------------------------------------------
# Adım 2: dizin ve çift seçimi (indirme yok)
# ---------------------------------------------------------------------------

def hata_adaylari(paket: str, kayit: dict[str, Any], hata: list[dict[str, Any]]) -> list[str]:
    """Hata ayıklama paketi adı: ``<paket>-dbgsym``; yoksa aynı kaynağın hata dizinindeki paketleri (bilgi)."""
    src = ti().kaynak_adi(kayit)
    return sorted({h["Package"] for h in hata if ti().kaynak_adi(h) == src})


def secim_yap(kok: Path) -> dict[str, Any]:
    t = ti()
    indeks = kok / "indir" / "indeks"
    d = t.dagitim_dizinleri(DAGITIM, indeks)
    a = t.anahtar_halkasi(DAGITIM, indeks, d["ikili"])
    t.imzalari_dogrula(DAGITIM, indeks, d["bilgiler"], a["halkalar"])
    mimari = t.DAGITIMLAR[DAGITIM]["dizinler"][0].mimari
    taraf = taraflar()
    satirlar = []
    for p in ADAY_PAKETLER:
        c = t.cift_sec(d["ikili"], d["hata"], p, f"{p}-dbgsym", mimari)
        s: dict[str, Any] = {"paket": p, "taraf": taraf[p]["taraf"], "hata_paketi": f"{p}-dbgsym",
                             "dizin_surumleri": c["dizin_surumleri"], "hata_surumleri": c["hata_surumleri"]}
        if c["durum"] == "bulundu":
            s.update(t._dosya_satiri(c["ikili"], "ikili"))
            s.update(t._dosya_satiri(c["hata"], "hata"))
            s["kaynak_adi"] = t.kaynak_adi(c["ikili"])
            s["durum"] = "bulundu"
        else:
            enyuksek = None
            for k in d["ikili"]:
                if k["Package"] == p and k.get("Architecture") == mimari:
                    if enyuksek is None or t.surum_karsilastir(k["Version"], enyuksek["Version"]) > 0:
                        enyuksek = k
            s["durum"] = "dbgsym yok" if enyuksek else "dizinde yok"
            if enyuksek:
                s.update(t._dosya_satiri(enyuksek, "ikili"))
                s["kaynak_adi"] = t.kaynak_adi(enyuksek)
                s["ayni_kaynagin_hata_paketleri"] = hata_adaylari(p, enyuksek, d["hata"])
                # Ana arşivde, aynı kaynaktan ve aynı sürümde ``Build-Ids`` alanı dolu paketler
                # (Debian'da ``dh_strip --dbg-package`` ile üretilen ``-dbg`` paketleri): hangisinin
                # gerektiği ikili açılınca BuildID kesişimiyle seçilir (``kur``).
                s["build_ids_adaylari"] = [
                    {"paket": k["Package"], **t._dosya_satiri(k, "hata")}
                    for k in d["ikili"]
                    if t.kaynak_adi(k) == s["kaynak_adi"] and k["Version"] == enyuksek["Version"]
                    and k.get("Architecture") == mimari and k.get("Build-Ids")]
                if s["build_ids_adaylari"]:
                    s["durum"] = "dbg adayı"
        satirlar.append(s)
    # Kaynak grubu denetimi: aynı Source alanını paylaşıp KAYNAK_GRUPLARI'nda birlikte olmayan çift var mı
    kaynaklar: dict[str, list[str]] = {}
    for s in satirlar:
        if s.get("kaynak_adi"):
            kaynaklar.setdefault(s["kaynak_adi"], []).append(s["paket"])
    tanimsiz = [v for v in kaynaklar.values() if len(v) > 1
                and not any(set(v) <= set(g) for g in KAYNAK_GRUPLARI)]
    kilitli = t.kilitli_adlar()
    adlar = set(ADAY_PAKETLER) | {s["hata_paketi"] for s in satirlar} | {s["kaynak_adi"] for s in satirlar
                                                                     if s.get("kaynak_adi")}
    # Üst sınır: aynı dbg adayı iki pakette sayılmaz
    dbg_aday_bayt = {a["paket"]: a["hata_boyut"] for s in satirlar for a in s.get("build_ids_adaylari", [])}
    toplam = sum(s.get("ikili_boyut", 0) + (s.get("hata_boyut", 0) if s["durum"] == "bulundu" else 0)
                 for s in satirlar) + sum(dbg_aday_bayt.values())
    return {"sema": SEMA_SECIM, "tarih_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "dagitim": DAGITIM, "dizinler": d["bilgiler"], "anahtarlar": a, "paketler": satirlar,
            "kaynak_gruplari": {k: v for k, v in kaynaklar.items()}, "tanimsiz_kaynak_grubu": tanimsiz,
            "kilit_belgeleri": {str(b.relative_to(REPO)): t.sha256_dosya(b) for b in t.KILIT_BELGELERI},
            "kilitli_ad_sayisi": len(kilitli), "kilit_kesisimi": t.kilit_suzgeci(adlar, kilitli),
            "kilit_yakinligi": t.kilit_yakinligi(adlar, kilitli), "toplam_paket_bayt": toplam}


# ---------------------------------------------------------------------------
# Adım 2–3: indir, doğrula, aç, BuildID, ELF seçimi, C++ denetimi, sayılar
# ---------------------------------------------------------------------------

def cpp_mi(yol: Path) -> bool:
    """``ks1_olc.cpp_ikili_mi``'nin GT'siz ELF karşılığı: içe aktarılan dinamik simgelerden biri C++ öneki
    (``CPP_ISARETLERI``) taşıyor mu. Ad döndürmez, yalnız evet / hayır."""
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection

    isaretler = _modul("ks1_olc", OLCUM / "ks1_olc.py").CPP_ISARETLERI
    with open(yol, "rb") as f:
        elf = ELFFile(f)
        sec = elf.get_section_by_name(".dynsym")
        if not isinstance(sec, SymbolTableSection):
            return False
        for sym in sec.iter_symbols():
            if sym["st_shndx"] == "SHN_UNDEF" and sym.name.startswith(isaretler):
                return True
    return False


def kitaplik_mi(paket: str) -> bool:
    return paket.startswith(KITAPLIK_ONEKLERI)


def elf_sec(paket: str, satirlar: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """NUFUS.md §3 kuralı: kitaplık paketinde bütün ET_DYN ELF'ler; program paketinde en büyük ELF."""
    if not satirlar:
        return []
    if kitaplik_mi(paket):
        return [s for s in satirlar if s["tip"] == "ET_DYN"]
    return [max(satirlar, key=lambda s: (s["boyut"], s["yol"]))]


def _indir_kaydet(t, kok: Path, kay: dict[str, Any], on: str, dosyalar: dict[str, Any], anahtar: str) -> dict[str, Any]:
    hedef = kok / "indir" / kay[f"{on}_dosya"]
    d = t.indir(kay[f"{on}_url"], hedef, beklenen_sha256=kay[f"{on}_sha256"], beklenen_boyut=kay[f"{on}_boyut"])
    dosyalar[anahtar] = {"surum": kay[f"{on}_surum"], "dosya": kay[f"{on}_dosya"], "url": kay[f"{on}_url"],
                         "boyut": kay[f"{on}_boyut"], "sha256_dizin": kay[f"{on}_sha256"],
                         "sha256_dosya": d.get("sha256"), "sha256_tuttu": bool(d.get("ok")),
                         "indirme": d.get("durum"), "dizin": kay[f"{on}_dizin"]}
    return d


def kur(kok: Path, secim: dict[str, Any]) -> dict[str, Any]:
    t = ti()
    if secim["kilit_kesisimi"]:
        raise SystemExit(f"kilitli ad kesişimi boş değil: {secim['kilit_kesisimi']}")
    if secim["toplam_paket_bayt"] > t.TOPLAM_SINIR:
        raise SystemExit(f"toplam {secim['toplam_paket_bayt']} bayt > 2 GiB; dur")
    out = []
    for s in secim["paketler"]:
        r: dict[str, Any] = {"paket": s["paket"], "taraf": s["taraf"], "hata_paketi": s["hata_paketi"]}
        if s["durum"] not in ("bulundu", "dbg adayı"):
            r["durum"] = f"indirilmedi: {s['durum']}"
            out.append(r)
            continue
        dosyalar: dict[str, Any] = {}
        d = _indir_kaydet(t, kok, s, "ikili", dosyalar, "ikili")
        if not d["ok"]:
            r.update({"dosyalar": dosyalar, "durum": f"indirilemedi: {s['ikili_dosya']}: {d.get('hata')}"})
            out.append(r)
            continue
        x_i = kok / f"x_{s['paket']}"
        r["acma"] = {"ikili": t.deb_ac(kok / "indir" / s["ikili_dosya"], x_i)}
        if s["durum"] == "bulundu":
            hata_listesi = [(s["hata_paketi"], s)]
        else:
            # BuildID kesişimi: ikilinin ELF'lerinin BuildID'lerini Build-Ids alanında taşıyan aday(lar)
            bids = {e["build_id"] for e in t.elf_envanteri(x_i) if e.get("build_id")}
            hata_listesi = [(a["paket"], a) for a in s["build_ids_adaylari"]
                            if bids & set(a["hata_build_ids"].split())]
            r["hata_paketi"] = ", ".join(a for a, _ in hata_listesi) or "yok (Build-Ids kesişimi boş)"
        dbg_kokler, hata = [], None
        for ad, kay in hata_listesi:
            d = _indir_kaydet(t, kok, kay, "hata", dosyalar, f"hata:{ad}" if s["durum"] != "bulundu" else "hata")
            if not d["ok"]:
                hata = f"indirilemedi: {kay['hata_dosya']}: {d.get('hata')}"
                break
            x_h = kok / f"x_{ad}"
            r["acma"][ad] = t.deb_ac(kok / "indir" / kay["hata_dosya"], x_h)
            dbg_kokler.append(x_h)
        r["dosyalar"] = dosyalar
        if hata or not dbg_kokler:
            r["durum"] = hata or "hata ayıklama paketi bulunamadı"
            out.append(r)
            continue
        e = t.buildid_eslestir(x_i, dbg_kokler, gt_say=False)
        secilen = elf_sec(s["paket"], e["satirlar"])
        f1 = t._f1_modulu()
        for sat in secilen:
            sat["secildi"] = True
            sat["cpp"] = cpp_mi(x_i / sat["yol"])
            if sat["eslesme"] != "eşleşti":
                continue
            try:
                gt = f1.extract_gt(kok / sat["debug_kok"] / sat["debug_yol"], x_i / sat["yol"])
                sat["gt_sayilari"] = gt["counts"]
                sat["extract_gt"] = "tamam"
            except Exception as ex:   # ret nedeni kayda geçer (ad içermez)
                sat["extract_gt"] = f"reddetti: {type(ex).__name__}"
        r["buildid"] = {"elf": e["elf"], "eslesen": e["eslesen"], "hata_dosyasi": e["hata_dosyasi"],
                        "dwz_sayisi": len(e["dwz"]), "satirlar": e["satirlar"]}
        olculur = [x for x in secilen if x["eslesme"] == "eşleşti" and x.get("extract_gt") == "tamam"
                   and not x["cpp"]]
        r["secilen"] = len(secilen)
        r["olculur"] = len(olculur)
        r["durum"] = ("tamam" if olculur and len(olculur) == len(secilen) else
                      ("kısmi" if olculur else "ölçülecek ELF yok"))
        out.append(r)
    return {"sema": SEMA_NUFUS, "tarih_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "secim_sha256": None, "elf_secim_kurali": "kitaplık (lib*, lua-*): bütün ET_DYN; program: en büyük ELF",
            "paketler": out}


# ---------------------------------------------------------------------------
# Rapor (NUFUS.md tabloları; ad ve kör yol yazılmaz)
# ---------------------------------------------------------------------------

def rapor_bolme() -> str:
    t = taraflar()
    sat = ["| # | paket | sha256(ad) ilk bayt | ham taraf | grup ilki | taraf |", "|---:|---|---:|---|---|---|"]
    for i, p in enumerate(ADAY_PAKETLER, 1):
        v = t[p]
        sat.append(f"| {i} | {p} | {v['ilk_bayt']} | {v['ham_taraf']} | {v['grup_ilk']} | **{v['taraf']}** |")
    n_ayar = sum(1 for v in t.values() if v["taraf"] == AYAR)
    sat.append("")
    sat.append(f"Ayar: {n_ayar} paket; kör: {len(t) - n_ayar} paket.")
    return "\n".join(sat)


def rapor_dosyalar(nufus: dict[str, Any]) -> str:
    sat = ["| paket | taraf | dosya | sürüm | bayt | sha256 (dosya) | = dizin |", "|---|---|---|---|---:|---|---|"]
    top = 0
    gorulen: set[str] = set()
    for r in nufus["paketler"]:
        for on, d in r.get("dosyalar", {}).items():
            if d["dosya"] in gorulen:      # iki paketin ortak hata ayıklama paketi bir kez sayılır
                continue
            gorulen.add(d["dosya"])
            top += d["boyut"] if d["sha256_tuttu"] else 0
            sat.append(f"| {r['paket']} | {r['taraf']} | `{d['dosya']}` | {d['surum']} | {d['boyut']} | "
                       f"`{d['sha256_dosya']}` | {'evet' if d['sha256_tuttu'] else 'HAYIR'} |")
    sat.append("")
    sat.append(f"sha256'sı dizinle tutan dosyaların toplamı: {top} bayt ({top / 1048576:.2f} MiB).")
    return "\n".join(sat)


def rapor_elf(nufus: dict[str, Any]) -> str:
    sat = ["| paket | taraf | paketteki ELF | BuildID ↔ .debug eşleşen | seçilen ELF | C++ (ölçü dışı) | "
           "ölçülecek | GT FUNC (seçilen, toplam) | puanlanan (crt / ihraç dışı) | seçilenlerin BuildID'si | durum |",
           "|---|---|---:|---:|---:|---:|---:|---:|---:|---|---|"]
    for r in nufus["paketler"]:
        b = r.get("buildid")
        if not b:
            sat.append(f"| {r['paket']} | {r['taraf']} | — | — | — | — | — | — | — | — | {r['durum']} |")
            continue
        sec = [s for s in b["satirlar"] if s.get("secildi")]
        fn = sum((s.get("gt_sayilari") or {}).get("functions", 0) for s in sec if not s.get("cpp"))
        sc = sum((s.get("gt_sayilari") or {}).get("scored", 0) for s in sec if not s.get("cpp"))
        cpp = sum(1 for s in sec if s.get("cpp"))
        if len(sec) <= 3:
            bids = ", ".join(f"`{s['build_id']}`" for s in sec)
        else:
            h = hashlib.sha256("\n".join(sorted(s["build_id"] or "" for s in sec)).encode()).hexdigest()
            bids = f"{len(sec)} BuildID; sıralı listenin sha256'sı `{h[:16]}…` (nufus.json)"
        sat.append(f"| {r['paket']} | {r['taraf']} | {b['elf']} | {b['eslesen']} | {len(sec)} | {cpp} | "
                   f"{r['olculur']} | {fn} | {sc} | {bids} | {r['durum']} |")
    sat.append("")
    sat.append("| taraf | paket | ölçülecek ELF'i olan paket | ölçülecek ELF | GT FUNC | puanlanan |")
    sat.append("|---|---:|---:|---:|---:|---:|")
    for tr in (AYAR, KOR):
        rs = [r for r in nufus["paketler"] if r["taraf"] == tr]
        olc = [s for r in rs for s in (r.get("buildid") or {}).get("satirlar", [])
               if s.get("secildi") and not s.get("cpp") and s.get("extract_gt") == "tamam"]
        sat.append(f"| {tr} | {len(rs)} | {sum(1 for r in rs if r.get('olculur'))} | {len(olc)} | "
                   f"{sum(s['gt_sayilari']['functions'] for s in olc)} | {sum(s['gt_sayilari']['scored'] for s in olc)} |")
    return "\n".join(sat)


# ---------------------------------------------------------------------------
# ÖK-V adım 5: taban ürün koşusu (Dalga 0, OK5 paketi; 2026-11-20)
# ---------------------------------------------------------------------------
# Her ölçülecek ELF ayrı bir iştir. Koşu ``urun_kos.calistir`` ile yapılır (aynı komut:
# ``python -m karadul analyze <ikili> --skip-dynamic --output-dir <d>/ws --output <d>/out``; cwd ve
# PYTHONPATH ürün ağacı). Yerleşim ``ks1_olc.debian_elfleri``'nin okuduğu biçimdir:
#     <kosu_kok>/debian/<paket>/eNN/{ws,out,kosu.log,BITTI,kunye.json}
# ELF dizini adı paket içindeki sıra numarasıdır (``e00`` …): "kör" ELF'in dosya adı hiçbir yere
# (kuyruk günlüğü dahil) yazılmasın diye. Sıra: paket içinde ``yol``'a göre (belirlenimci).
# Koşu sırası (gönderim metni): önce "ayar", sonra "kör"; her tarafta küçükten büyüğe.

KUYRUK = Path.home() / "karadul_olcum" / "ghidra_kuyruk.sh"
KUYRUK_PAKETI = "OK5"
KOS_ZAMAN_ASIMI_SN = 3600          # gönderim metni: ikili başına 3 600 sn
KOS_KUNYE_DOSYASI = "kunye.json"
SON_DURUMLAR = ("tamam", "kismi", "zaman_asimi", "girdi_degismis")   # yeniden koşulmaz
# TAHMİN modeli (yalnız kuyruk öncesi bildirim için; ölçüm değildir): bugünkü (2026-11-20 sabah,
# yük altında, paralel 1) S8 taban koşularından okunan kaba değerler — küçük ikili ≈ 35–50 sn,
# 1,1 MB ≈ 207 sn, 1,3 MB ≈ 291 sn. Alt / üst: (25 sn + 100 sn/MB) / (60 sn + 250 sn/MB).
TAHMIN_ALT = (25.0, 100.0)
TAHMIN_UST = (60.0, 250.0)


def olculecek_isler(kok: Path, nufus: dict[str, Any]) -> list[dict[str, Any]]:
    """NUFUS.md §3'ün "ölçülecek" ELF'leri (seçilmiş, BuildID eşleşmiş, ``extract_gt`` tamam, C++ değil),
    koşu sırasıyla. Her iş: anahtar, girdi, sha256 (dizinden), boyut, paket, taraf, etiket, debug."""
    out = []
    for r in nufus["paketler"]:
        b = r.get("buildid")
        if not b:
            continue
        olc = sorted((s for s in b["satirlar"] if s.get("secildi") and s.get("eslesme") == "eşleşti"
                      and s.get("extract_gt") == "tamam" and not s.get("cpp")), key=lambda s: s["yol"])
        for i, s in enumerate(olc):
            out.append({"anahtar": f"debian/{r['paket']}/e{i:02d}", "paket": r["paket"], "taraf": r["taraf"],
                        "sira": i, "paket_elf_sayisi": len(olc), "etiket": f"{r['paket']}:e{i:02d}",
                        "girdi": kok / f"x_{r['paket']}" / s["yol"], "sha256": s["sha256"],
                        "boyut": s["boyut"], "build_id": s["build_id"],
                        "debug": kok / s["debug_kok"] / s["debug_yol"], "debug_build_id": s.get("debug_build_id")})
    out.sort(key=lambda i: (0 if i["taraf"] == AYAR else 1, i["boyut"], i["anahtar"]))
    return out


def tahmin_sn(boyut: int) -> tuple[float, float]:
    mb = boyut / 1e6
    return TAHMIN_ALT[0] + TAHMIN_ALT[1] * mb, TAHMIN_UST[0] + TAHMIN_UST[1] * mb


def is_durumu(kosu_kok: Path, is_: dict[str, Any]) -> Optional[str]:
    """Bitmiş işin durumu (``kunye.json``), yoksa None."""
    y = kosu_kok / is_["anahtar"] / KOS_KUNYE_DOSYASI
    if not y.is_file():
        return None
    try:
        return json.loads(y.read_text(encoding="utf-8")).get("durum")
    except (OSError, ValueError):
        return None


def _yuk() -> str:
    import os
    return " ".join(f"{x:.2f}" for x in os.getloadavg())


def kos_tek(kok: Path, kosu_kok: Path, agac: Path, anahtar: str, zaman_asimi: int) -> dict[str, Any]:
    """Tek bir ELF'i koşar (kuyruk sarmalayıcısının İÇİNDE çağrılır) ve künyesini yazar."""
    uk = _modul("urun_kos", OLCUM / "urun_kos.py")
    nufus = json.loads((kok / "nufus.json").read_text(encoding="utf-8"))
    is_ = next((i for i in olculecek_isler(kok, nufus) if i["anahtar"] == anahtar), None)
    if is_ is None:
        raise SystemExit(f"iş yok: {anahtar}")
    agac_k = uk.agac_kunyesi(agac)
    if agac_k["kirli"]:
        raise SystemExit(f"ürün ağacı kirli: {len(agac_k['kirli'])} dosya")
    bas = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    yuk0 = _yuk()
    s = uk.calistir({"anahtar": anahtar, "girdi": is_["girdi"], "sha256": is_["sha256"]}, agac, kosu_kok,
                    zaman_asimi)
    kunye = {"anahtar": anahtar, "paket": is_["paket"], "taraf": is_["taraf"], "durum": s["durum"],
             "sure_sn": s["sure_sn"], "baslangic": bas, "bitis": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
             "yuk_bas": yuk0, "yuk_son": _yuk(), "yuk_notu": "yük altında (gündüz, ortak makine)",
             "boyut": is_["boyut"], "sha256": is_["sha256"], "build_id": is_["build_id"],
             "agac_commit": agac_k["commit"], "karadul_surumu": agac_k["karadul_surumu"],
             "zaman_asimi_sn": zaman_asimi,
             "bitti_dosyasi": (kosu_kok / anahtar / "BITTI").read_text(encoding="utf-8").strip()
             if (kosu_kok / anahtar / "BITTI").is_file() else None}
    (kosu_kok / anahtar / KOS_KUNYE_DOSYASI).write_text(json.dumps(kunye, ensure_ascii=False, indent=1) + "\n",
                                            encoding="utf-8")
    return kunye


def kos_ozet(kosu_kok: Path, isler: list[dict[str, Any]]) -> dict[str, Any]:
    """Taraf başına sayaç: bitti / tamam / kısmi / zaman aşımı / hatalı / bekleyen (yalnız sayı)."""
    out: dict[str, Any] = {}
    for tr in (AYAR, KOR):
        say: dict[str, int] = {"is": 0, "bekleyen": 0}
        sure = 0.0
        for i in isler:
            if i["taraf"] != tr:
                continue
            say["is"] += 1
            d = is_durumu(kosu_kok, i)
            if d is None:
                say["bekleyen"] += 1
                continue
            anah = d if d in ("tamam", "kismi", "zaman_asimi") else "hatali"
            say[anah] = say.get(anah, 0) + 1
            try:
                sure += json.loads((kosu_kok / i["anahtar"] / KOS_KUNYE_DOSYASI).read_text(encoding="utf-8"))["sure_sn"]
            except (OSError, ValueError, KeyError):
                pass
        say["toplam_sure_sn"] = round(sure, 1)
        out[tr] = say
    return out


def kos_hepsi(kok: Path, kosu_kok: Path, agac: Path, zaman_asimi: int, taraf: Optional[str]) -> int:
    """Bekleyen her ELF'i AYRI bir kuyruk çağrısıyla koşar (kilidi tek komutla uzun tutmaz)."""
    import os
    import subprocess
    nufus = json.loads((kok / "nufus.json").read_text(encoding="utf-8"))
    isler = olculecek_isler(kok, nufus)
    if taraf:
        isler = [i for i in isler if i["taraf"] == taraf]
    kosu_kok.mkdir(parents=True, exist_ok=True)
    ortam = dict(os.environ, PYTHONHASHSEED="0", PYTHONDONTWRITEBYTECODE="1",
                 KARADUL_CACHE_DIR=str(kosu_kok / "cache"))
    for n, i in enumerate(isler, 1):
        if is_durumu(kosu_kok, i) in SON_DURUMLAR:
            continue
        komut = [str(KUYRUK), KUYRUK_PAKETI, i["etiket"], sys.executable, "-I", str(Path(__file__).resolve()),
                 "kos", "--kok", str(kok), "--kosu-kok", str(kosu_kok), "--agac", str(agac),
                 "--anahtar", i["anahtar"], "--zaman-asimi", str(zaman_asimi)]
        r = subprocess.run(komut, env=ortam, cwd=str(REPO))
        if is_durumu(kosu_kok, i) is None:   # künye yazılamadıysa (ör. ağaç denetimi): hatalı diye kaydet
            d = kosu_kok / i["anahtar"]
            d.mkdir(parents=True, exist_ok=True)
            (d / KOS_KUNYE_DOSYASI).write_text(json.dumps({"anahtar": i["anahtar"], "paket": i["paket"], "taraf": i["taraf"],
                                               "durum": f"surucu_cikis_{r.returncode}", "sure_sn": 0.0},
                                              ensure_ascii=False) + "\n", encoding="utf-8")
        oz = kos_ozet(kosu_kok, olculecek_isler(kok, nufus))
        (kosu_kok / "ilerleme.json").write_text(json.dumps({"zaman": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                                                            "ozet": oz}, ensure_ascii=False, indent=1) + "\n",
                                                encoding="utf-8")
        # yalnız paket adı, sıra ve sayı (kör ELF'in yolu basılmaz)
        print(f"[{n}/{len(isler)}] {i['etiket']} {is_durumu(kosu_kok, i)} | "
              + "; ".join(f"{tr}: {v}" for tr, v in oz.items()), flush=True)
    return 0


def kos_plan(kok: Path, kosu_kok: Optional[Path]) -> str:
    nufus = json.loads((kok / "nufus.json").read_text(encoding="utf-8"))
    isler = olculecek_isler(kok, nufus)
    sat = ["| taraf | paket | ELF | toplam bayt | en büyük ELF (bayt) | TAHMİN süre (sn; alt–üst) | bitmiş |",
           "|---|---|---:|---:|---:|---|---:|"]
    for tr in (AYAR, KOR):
        paketler = sorted({i["paket"] for i in isler if i["taraf"] == tr},
                          key=lambda p: min(i["boyut"] for i in isler if i["paket"] == p))
        ta = tu = 0.0
        for p in paketler:
            pi = [i for i in isler if i["paket"] == p]
            a = sum(tahmin_sn(i["boyut"])[0] for i in pi)
            u = sum(tahmin_sn(i["boyut"])[1] for i in pi)
            ta, tu = ta + a, tu + u
            bit = sum(1 for i in pi if kosu_kok and is_durumu(kosu_kok, i) in SON_DURUMLAR)
            sat.append(f"| {tr} | {p} | {len(pi)} | {sum(i['boyut'] for i in pi)} | "
                       f"{max(i['boyut'] for i in pi)} | {a:.0f}–{u:.0f} | {bit} |")
        n = sum(1 for i in isler if i["taraf"] == tr)
        sat.append(f"| **{tr} toplam** | {len(paketler)} | {n} | {sum(i['boyut'] for i in isler if i['taraf'] == tr)} "
                   f"| | {ta:.0f}–{tu:.0f} ({ta / 3600:.1f}–{tu / 3600:.1f} sa) | |")
    return "\n".join(sat)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    alt = ap.add_subparsers(dest="komut", required=True)
    alt.add_parser("bolme", help="aday listesi ve taraflar (veri gerekmez)")
    for ad in ("dizin", "kur", "rapor"):
        a = alt.add_parser(ad)
        a.add_argument("--kok", type=Path, required=True)
    a = alt.add_parser("kos-plan", help="ÖK-V adım 5: iş listesi ve TAHMİNİ süre (yalnız sayı)")
    a.add_argument("--kok", type=Path, required=True)
    a.add_argument("--kosu-kok", type=Path)
    for ad in ("kos", "kos-hepsi"):
        a = alt.add_parser(ad, help="ÖK-V adım 5: taban ürün koşusu (tek ELF / bekleyenlerin hepsi)")
        a.add_argument("--kok", type=Path, required=True)
        a.add_argument("--kosu-kok", type=Path, required=True)
        a.add_argument("--agac", type=Path, required=True)
        a.add_argument("--zaman-asimi", type=int, default=KOS_ZAMAN_ASIMI_SN)
        if ad == "kos":
            a.add_argument("--anahtar", required=True)
        else:
            a.add_argument("--taraf", choices=(AYAR, KOR))
    a = alt.add_parser("kos-ozet", help="taraf başına sayaç (yalnız sayı)")
    a.add_argument("--kok", type=Path, required=True)
    a.add_argument("--kosu-kok", type=Path, required=True)
    ns = ap.parse_args(argv)
    if ns.komut == "bolme":
        print(rapor_bolme())
        return 0
    if ns.komut == "kos-plan":
        print(kos_plan(ns.kok.expanduser(), ns.kosu_kok.expanduser() if ns.kosu_kok else None))
        return 0
    if ns.komut == "kos":
        k = kos_tek(ns.kok.expanduser(), ns.kosu_kok.expanduser(), ns.agac.expanduser().resolve(),
                    ns.anahtar, ns.zaman_asimi)
        print(f"{k['anahtar']} {k['durum']} {k['sure_sn']} sn")
        return 0
    if ns.komut == "kos-hepsi":
        return kos_hepsi(ns.kok.expanduser(), ns.kosu_kok.expanduser(), ns.agac.expanduser().resolve(),
                         ns.zaman_asimi, ns.taraf)
    if ns.komut == "kos-ozet":
        kok = ns.kok.expanduser()
        isler = olculecek_isler(kok, json.loads((kok / "nufus.json").read_text(encoding="utf-8")))
        print(json.dumps(kos_ozet(ns.kosu_kok.expanduser(), isler), ensure_ascii=False))
        return 0
    kok = ns.kok.expanduser()
    secim_yolu = kok / "indir" / "secim.json"
    nufus_yolu = kok / "nufus.json"
    t = ti()
    if ns.komut == "dizin":
        s = secim_yap(kok)
        secim_yolu.parent.mkdir(parents=True, exist_ok=True)
        secim_yolu.write_text(json.dumps(s, ensure_ascii=False, indent=1), encoding="utf-8")
        for p in s["paketler"]:
            ek = [(a["paket"], a["hata_boyut"], len(a["hata_build_ids"].split())) for a in p.get("build_ids_adaylari", [])]
            print(f"{p['paket']:22s} {p['taraf']:5s} {p['durum']:12s} {p.get('ikili_surum', '—'):26s} "
                  f"{p.get('ikili_boyut', 0):>9} {p.get('hata_boyut', 0):>10} "
                  f"{p.get('ayni_kaynagin_hata_paketleri', '')} {ek if ek else ''}")
        for b in s["dizinler"]:
            print(f"dizin {b['dizin']['etiket']}: ok={b['ok']} imza={b.get('imza_ok')} "
                  f"imzalı_sha256={b.get('imzali_sha256_tutuyor')} {b.get('hata', '')}")
        print(f"anahtar halkası paketleri: {s['anahtarlar']['paketler']}")
        print(f"tanımsız kaynak grubu: {s['tanimsiz_kaynak_grubu']}")
        print(f"kilitli ad: {s['kilitli_ad_sayisi']}; kesişim: {s['kilit_kesisimi']}; yakınlık: {s['kilit_yakinligi']}")
        print(f"toplam paket baytı (çifti bulunanlar): {s['toplam_paket_bayt']} ({s['toplam_paket_bayt'] / 1048576:.2f} MiB)")
        return 0
    if ns.komut == "kur":
        secim = json.loads(secim_yolu.read_text(encoding="utf-8"))
        v = kur(kok, secim)
        v["secim_sha256"] = t.sha256_dosya(secim_yolu)
        nufus_yolu.write_text(json.dumps(v, ensure_ascii=False, indent=1), encoding="utf-8")
        print(rapor_dosyalar(v))
        print()
        print(rapor_elf(v))
        print(f"\nnufus.json sha256: {t.sha256_dosya(nufus_yolu)}")
        return 0
    if ns.komut == "rapor":
        v = json.loads(nufus_yolu.read_text(encoding="utf-8"))
        print(rapor_dosyalar(v))
        print()
        print(rapor_elf(v))
        print(f"\nnufus.json sha256: {t.sha256_dosya(nufus_yolu)}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
