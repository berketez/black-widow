#!/usr/bin/env python3
"""Proje kurucu (CProjectBuilder) ölçümü: düşen fonksiyon ve yerleşim belirlenimciliği.

Çıktı sağlamlığı denetiminin (rapor.md) kusur 2 ve kusur 14'ünü proje kurucu
düzeyinde ölçer. Karadul'u ya da Ghidra'yı koşturmaz: saklı koşuların ara
çıktısını (`reconstructed/annotated` + `static/ghidra_call_graph.json`)
kurucuya yeniden verir, sonucu geçici bir dizine yazdırır ve diskten sayar.

Ne ölçülür (ikili başına, sonra toplam):
  * düşen fonksiyon   — girdide adresi olan, çıktıda hiçbir dosyada başlığı
                        (`// Address:`) bulunmayan fonksiyon; nedenine göre sınıflı
  * çift tanımlı      — başlığı çıktıda birden çok yerde geçen adres
  * tohum çifti       — iki farklı PYTHONHASHSEED ile aynı yolda çıkan fonksiyon
  * koşu çifti        — aynı kodla yapılmış iki ayrı koşunun girdisiyle aynı yol
  * eski ↔ yeni       — `--onceki-kurucu` verilirse eski kodun yerleşimiyle fark
  * kurucudan önceki kayıp — Ghidra'nın listesinde olup ham decompile dizininde
                        ya da kurucu girdisinde bulunmayan fonksiyon

Sayım kurucunun kendi defterine değil diske dayanır: kurucunun değişmez
denetimi ayrıca raporlanır (`degismez_hatasi`), ikisi birbirini sınar.

Kullanım (worktree kökünden):
  python docs/arge/2026-11-10_cikti_saglamligi/proje_kurucu_olcum.py
  git show 4fba538:karadul/reconstruction/c_project_builder.py > /tmp/x/eski.py
  python docs/arge/2026-11-10_cikti_saglamligi/proje_kurucu_olcum.py \
      --onceki-kurucu /tmp/x/eski.py
  python …/proje_kurucu_olcum.py --yalniz debian/tree/tree --json /tmp/x/t.json

Salt okur: `~/karadul_olcum` ve ana ağaca yazmaz. GT dosyaları açılmaz
(yalnız `ws/workspaces/*/*/{static,reconstructed}` altı okunur).
Çıktı JSON'u fonksiyon adı içermez; yalnız sayılar ve ikili kimlikleri.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path

BETIK = Path(__file__).resolve()
BETIK_DIZINI = BETIK.parent
DEPO = BETIK_DIZINI.parents[2]

# --- Girdi kümeleri (denetle.py ile aynı tanım) ----------------------------
DEBIAN_KOK = Path(os.path.expanduser("~/karadul_olcum/n1_debian13"))
# Mac koşuları ana ağaçta durur (worktree'de yoktur); salt okunur.
MAC_KOK = Path("/Users/apple/Black_Widow/workspaces/olcum_mac/runs")
MAC_ANA_ETIKET = "ol7-c-b7faeac"
MAC_ES_ETIKET = "ol7-d-b7faeac"          # aynı kodla ikinci koşu
MAC_PROGRAMLAR = ("tmux", "htop")
BEKLENEN_IKILI = 119                      # 117 ELF + 2 Mach-O

# Aynı kodla yapılmış, girdisi aynı olması beklenen koşu çiftleri.
KOSU_CIFTLERI = (
    (f"mac/{MAC_ANA_ETIKET}/htop", f"mac/{MAC_ES_ETIKET}/htop"),
    (f"mac/{MAC_ANA_ETIKET}/tmux", f"mac/{MAC_ES_ETIKET}/tmux"),
    ("debian/redis-tools/redis-check-aof", "debian/redis-tools/redis-check-rdb"),
)

VARSAYILAN_TOHUMLAR = ("1", "2")          # PYTHONHASHSEED değerleri
KAYNAK_ALT_DIZIN = ("reconstructed", "annotated")   # ProjectBuildStep girdisi
HAM_ALT_DIZIN = ("static", "ghidra_output", "decompiled")
FONKSIYON_LISTESI = ("static", "ghidra_functions.json")
CIKTI_JSON = BETIK_DIZINI / "proje_kurucu_olcum.json"

RE_ADRES = re.compile(r"^// Address:\s+(\S+)\s*$", re.M)
# Eski kurucunun dosya adı kuralı (düşenleri sınıflamak için yeniden kurulur).
RE_GUVENSIZ = re.compile(r"[^a-zA-Z0-9_\-.]")


# ---------------------------------------------------------------------------
# Koşuların bulunması
# ---------------------------------------------------------------------------
def kosulari_bul() -> list[dict]:
    kosular: list[dict] = []
    if DEBIAN_KOK.is_dir():
        for program in sorted(os.listdir(DEBIAN_KOK)):
            pd = DEBIAN_KOK / program
            if not pd.is_dir():
                continue
            for elf in sorted(os.listdir(pd)):
                kd = pd / elf
                if kd.is_dir():
                    kosular.append({"kimlik": f"debian/{program}/{elf}",
                                    "program": f"debian/{program}",
                                    "kok": str(kd), "ana_kume": True})
    for etiket in (MAC_ANA_ETIKET, MAC_ES_ETIKET):
        for program in MAC_PROGRAMLAR:
            kd = MAC_KOK / etiket / program
            if kd.is_dir():
                kosular.append({"kimlik": f"mac/{etiket}/{program}",
                                "program": f"mac/{program}",
                                "kok": str(kd),
                                "ana_kume": etiket == MAC_ANA_ETIKET})
    return kosular


def calisma_alani(kok: str) -> Path | None:
    """`ws/workspaces/<ad>/<zaman>` — tam bir tane beklenir."""
    wk = Path(kok) / "ws" / "workspaces"
    adaylar = []
    if wk.is_dir():
        for ad in sorted(os.listdir(wk)):
            d = wk / ad
            if d.is_dir():
                adaylar += [d / z for z in sorted(os.listdir(d)) if (d / z).is_dir()]
    return adaylar[0] if len(adaylar) == 1 else None


# ---------------------------------------------------------------------------
# İşçi: tek tohumla bütün koşuları kur ve diskten say
# ---------------------------------------------------------------------------
class SahteCalismaAlani:
    """Kurucunun okuduğu tek arayüz: `get_stage_dir`. Saklı dizinleri gösterir."""

    def __init__(self, kok: Path) -> None:
        self._kok = kok

    def get_stage_dir(self, ad: str) -> Path:
        return self._kok / ad


def kurucuyu_yukle(yol: str | None):
    if yol:
        spec = importlib.util.spec_from_file_location("olculen_kurucu", yol)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["olculen_kurucu"] = mod
        spec.loader.exec_module(mod)
        return mod
    sys.path.insert(0, str(DEPO))
    import karadul.reconstruction.c_project_builder as mod
    return mod


def baslik_adresleri(metin: str) -> list[str]:
    return RE_ADRES.findall(metin)


def eski_guvenli(stem: str) -> str:
    return RE_GUVENSIZ.sub("_", stem).strip("_.") or "unnamed"


def dusme_sinifi(dusen: str, kalan: str) -> str:
    """Düşen ile üstüne yazan girdi adı arasındaki farkın türü."""
    if dusen.lstrip("_") == kalan.lstrip("_"):
        return "bas_alt_cizgi"
    if dusen.rstrip("_.") == kalan.rstrip("_."):
        return "son_alt_cizgi_nokta"
    if dusen.casefold() == kalan.casefold():
        return "harf"
    if RE_GUVENSIZ.sub("_", dusen) == RE_GUVENSIZ.sub("_", kalan):
        return "gecersiz_karakter"
    return "karma"


def dizin_adresleri(dizin: Path) -> dict[str, list[str]]:
    """adres -> [göreli yol]; başlığı olmayan dosyalar '' anahtarında."""
    yerler: dict[str, list[str]] = defaultdict(list)
    if not dizin.is_dir():
        return yerler
    for kok, _dizinler, dosyalar in os.walk(dizin):
        for ad in dosyalar:
            if not ad.endswith(".c"):
                continue
            yol = Path(kok) / ad
            goreli = yol.relative_to(dizin).as_posix()
            adresler = baslik_adresleri(yol.read_text(errors="replace"))
            if not adresler:
                yerler[""].append(goreli)
            for a in adresler:
                yerler[a].append(goreli)
    return yerler


def kosu_olc(mod, kosu: dict, gecici: Path) -> dict:
    s: dict = {"kimlik": kosu["kimlik"]}
    ws = calisma_alani(kosu["kok"])
    if ws is None:
        s["hata"] = "çalışma alanı tek değil"
        return s
    kaynak = ws.joinpath(*KAYNAK_ALT_DIZIN)
    if not kaynak.is_dir():
        s["hata"] = "kurucu girdisi yok"
        return s

    # --- Girdi: dosya başına bir fonksiyon beklenir ------------------------
    girdi_adres: dict[str, str] = {}       # stem -> adres
    adressiz = cok_baslikli = 0
    for cf in sorted(kaynak.rglob("*.c")):
        adresler = baslik_adresleri(cf.read_text(errors="replace"))
        if not adresler:
            adressiz += 1
            continue
        if len(adresler) > 1:
            cok_baslikli += 1
        girdi_adres[cf.stem] = adresler[0]
    adres_stem: dict[str, list[str]] = defaultdict(list)
    for stem, a in girdi_adres.items():
        adres_stem[a].append(stem)
    s["girdi_dosya"] = len(girdi_adres) + adressiz
    s["girdi_fonksiyon"] = len(adres_stem)
    s["girdi_adressiz_dosya"] = adressiz
    s["girdi_cok_baslikli_dosya"] = cok_baslikli
    s["girdi_ayni_adresli_dosya"] = sum(len(v) - 1 for v in adres_stem.values())

    # --- Kurucudan önceki kayıp (Ghidra listesi -> ham -> girdi) -----------
    try:
        fl = json.loads(ws.joinpath(*FONKSIYON_LISTESI).read_text())
        liste = fl.get("functions", []) if isinstance(fl, dict) else fl
    except (OSError, ValueError):
        liste = []
    liste_adres = {f.get("address"): f.get("name") for f in liste if f.get("address")}
    ad_sayisi = Counter(liste_adres.values())
    ham = set(dizin_adresleri(ws.joinpath(*HAM_ALT_DIZIN))) - {""}
    ham_yok = [a for a in liste_adres if a not in ham]
    s["ghidra_listesi"] = len(liste_adres)
    s["ham_decompile"] = len(ham)
    s["ham_yok"] = len(ham_yok)
    s["ham_yok_ayni_adli_baska_var"] = sum(1 for a in ham_yok if ad_sayisi[liste_adres[a]] > 1)
    s["ham_var_girdide_yok"] = len(ham - set(adres_stem))
    s["liste_var_girdide_yok"] = sum(1 for a in liste_adres if a not in adres_stem)

    # --- Kur ---------------------------------------------------------------
    cikti = gecici / "proje"
    if cikti.exists():
        shutil.rmtree(cikti)
    t0 = time.monotonic()
    sonuc = mod.CProjectBuilder(None).build(
        source_dir=kaynak, output_dir=cikti,
        workspace=SahteCalismaAlani(ws), algorithm_results=None,
    )
    s["sure_s"] = round(time.monotonic() - t0, 2)
    s["basarili"] = bool(sonuc.success)
    s["files_written"] = int(sonuc.files_written)
    s["hata_sayisi"] = len(sonuc.errors)
    s["degismez_hatasi"] = sum(1 for e in sonuc.errors if "değişmez" in e.lower()
                               or "degismez" in e.lower())
    s["disk_dosya"] = sum(len(d) for _k, _a, d in os.walk(cikti))
    s["altsistem_dizini"] = len([p for p in (cikti / "src").iterdir() if p.is_dir()])

    # --- Çıktıyı diskten say -----------------------------------------------
    yerler = dizin_adresleri(cikti / "src")
    basliksiz = yerler.pop("", [])
    s["cikti_c_dosya"] = len({y for v in yerler.values() for y in v}) + len(basliksiz)
    s["basliksiz_dosya"] = len(basliksiz)
    dusen = sorted(a for a in adres_stem if a not in yerler)
    cift = sorted(a for a, v in yerler.items() if len(v) > 1)
    s["dusen"] = len(dusen)
    s["cift_tanimli"] = len(cift)
    s["girdide_olmayan_adres"] = sum(1 for a in yerler if a not in adres_stem)

    # Düşenlerin nedeni: üstüne yazan girdi dosyasını bul.
    siniflar: Counter = Counter()
    kalan_anahtar: dict[str, list[str]] = defaultdict(list)
    for stem, a in girdi_adres.items():
        if a in yerler:
            kalan_anahtar[eski_guvenli(stem).casefold()].append(stem)
    for a in dusen:
        for stem in adres_stem[a]:
            adaylar = kalan_anahtar.get(eski_guvenli(stem).casefold(), [])
            ayni_dosya = [
                t for t in adaylar
                if Path(yerler[girdi_adres[t]][0]).stem.casefold()
                == eski_guvenli(stem).casefold()
            ]
            if ayni_dosya:
                siniflar[dusme_sinifi(stem, ayni_dosya[0])] += 1
            elif adaylar:
                siniflar["aday_var_dosya_farkli"] += 1
            else:
                siniflar["aciklanamayan"] += 1
    s["dusme_sinifi"] = dict(sorted(siniflar.items()))

    # Yerleşim haritası (geçici; üst süreç karşılaştırır, JSON'a girmez).
    s["_yer"] = {a: sorted(v) for a, v in yerler.items()}
    shutil.rmtree(cikti)
    return s


def isci(argv_kosular: str, kurucu: str | None, gecici: str, cikti: str) -> int:
    mod = kurucuyu_yukle(kurucu)
    kosular = json.loads(Path(argv_kosular).read_text())
    sonuclar = []
    for kosu in kosular:
        try:
            sonuclar.append(kosu_olc(mod, kosu, Path(gecici)))
        except Exception as exc:  # ölçüm sürsün; hata sayılır
            sonuclar.append({"kimlik": kosu["kimlik"],
                             "hata": f"{type(exc).__name__}: {exc}"})
    Path(cikti).write_text(json.dumps({
        "tohum": os.environ.get("PYTHONHASHSEED"),
        "kurucu": getattr(mod, "__file__", None),
        "sonuclar": sonuclar,
    }))
    return 0


# ---------------------------------------------------------------------------
# Üst süreç: işçileri başlat, karşılaştır, özetle
# ---------------------------------------------------------------------------
def iscileri_kos(etiket: str, kurucu: str | None, tohumlar, kosular, gecici: Path) -> dict:
    kosu_dosyasi = gecici / "kosular.json"
    kosu_dosyasi.write_text(json.dumps(kosular))
    ortam = {k: v for k, v in os.environ.items() if k != "PYTHONHASHSEED"}
    ortam["PYTHONDONTWRITEBYTECODE"] = "1"
    surecler = {}
    for tohum in tohumlar:
        cikti = gecici / f"{etiket}-{tohum}.json"
        calisma = gecici / f"{etiket}-{tohum}"
        calisma.mkdir()
        komut = [sys.executable, str(BETIK), "--isci", str(kosu_dosyasi),
                 "--isci-gecici", str(calisma), "--isci-cikti", str(cikti)]
        if kurucu:
            komut += ["--kurucu", kurucu]
        surecler[tohum] = (cikti, subprocess.Popen(
            komut, cwd=str(DEPO), env={**ortam, "PYTHONHASHSEED": tohum}))
    sonuc = {}
    for tohum, (cikti, surec) in surecler.items():
        if surec.wait() != 0:
            raise SystemExit(f"işçi başarısız: {etiket} tohum {tohum}")
        veri = json.loads(cikti.read_text())
        sonuc[tohum] = {s["kimlik"]: s for s in veri["sonuclar"]}
        sonuc[tohum]["_kurucu"] = veri["kurucu"]
    return sonuc


def yol_karsilastir(a: dict, b: dict) -> dict:
    """İki yerleşim haritası (adres -> [yol]) arasında aynı yolda çıkanlar."""
    ortak = sorted(set(a) & set(b))
    ayni = sum(1 for k in ortak if a[k] == b[k])
    ayni_dizin = sum(
        1 for k in ortak
        if a[k] != b[k] and [os.path.dirname(y) for y in a[k]]
        == [os.path.dirname(y) for y in b[k]]
    )
    ayni_dosya_adi = sum(
        1 for k in ortak
        if a[k] != b[k] and [os.path.basename(y) for y in a[k]]
        == [os.path.basename(y) for y in b[k]]
    )
    return {"ortak_fonksiyon": len(ortak), "ayni_yol": ayni,
            "yalniz_dosya_adi_farkli": ayni_dizin,
            "yalniz_dizin_farkli": ayni_dosya_adi,
            "yalniz_birinde": len(set(a) ^ set(b))}


SAYAC_ALANLARI = (
    "girdi_dosya", "girdi_fonksiyon", "girdi_adressiz_dosya",
    "girdi_cok_baslikli_dosya", "girdi_ayni_adresli_dosya",
    "ghidra_listesi", "ham_decompile", "ham_yok", "ham_yok_ayni_adli_baska_var",
    "ham_var_girdide_yok", "liste_var_girdide_yok",
    "cikti_c_dosya", "basliksiz_dosya", "dusen", "cift_tanimli",
    "girdide_olmayan_adres", "hata_sayisi", "degismez_hatasi",
)


def surum_ozeti(sonuc: dict, tohumlar, kimlikler: list[str], hepsi: list[str]) -> dict:
    """Bir kurucu sürümünün (eski ya da yeni) tohum başına ve tohum çifti özeti."""
    oz: dict = {"kurucu": sonuc[tohumlar[0]].get("_kurucu"), "tohum": {}, "ikili": {}}
    for tohum in tohumlar:
        t = sonuc[tohum]
        top = Counter()
        sinif = Counter()
        etkilenen = Counter()
        sayac_fazla = sayac_eksik = basarisiz = hatali = 0
        for k in kimlikler:
            s = t[k]
            if "hata" in s:
                hatali += 1
                continue
            for alan in SAYAC_ALANLARI:
                top[alan] += s[alan]
                if s[alan]:
                    etkilenen[alan] += 1
            sinif.update(s["dusme_sinifi"])
            # Kurucunun kendi sayacı ↔ disk (algorithms.md bu ölçümde yazılmaz).
            sayac_fazla += s["files_written"] > s["disk_dosya"]
            sayac_eksik += s["files_written"] < s["disk_dosya"]
            basarisiz += not s["basarili"]
        oz["tohum"][tohum] = {
            "ikili": len(kimlikler), "olculemeyen_ikili": hatali,
            "toplam": dict(top),
            "etkilenen_ikili": {a: etkilenen[a] for a in
                                ("dusen", "cift_tanimli", "basliksiz_dosya",
                                 "ham_yok", "liste_var_girdide_yok",
                                 "degismez_hatasi", "hata_sayisi")},
            "dusme_sinifi": dict(sorted(sinif.items())),
            "files_written_diskten_fazla_ikili": sayac_fazla,
            "files_written_diskten_az_ikili": sayac_eksik,
            "basarisiz_diyen_ikili": basarisiz,
        }
    # Tohum çifti: aynı girdi, farklı karma tohumu.
    if len(tohumlar) >= 2:
        a, b = sonuc[tohumlar[0]], sonuc[tohumlar[1]]
        top = Counter()
        tam = 0
        for k in kimlikler:
            if "hata" in a[k] or "hata" in b[k]:
                continue
            kr = yol_karsilastir(a[k]["_yer"], b[k]["_yer"])
            top.update(kr)
            tam += kr["ayni_yol"] == kr["ortak_fonksiyon"] and not kr["yalniz_birinde"]
            oz["ikili"].setdefault(k, {})["tohum_cifti"] = kr
        oz["tohum_cifti"] = {"tohumlar": list(tohumlar[:2]), **dict(top),
                             "tam_ayni_ikili": tam, "ikili": len(kimlikler)}
        # Bütün tohumlar: yolu her tohumda aynı olan fonksiyon.
        hepsinde = fonksiyon = tam = 0
        for k in kimlikler:
            haritalar = [sonuc[t][k].get("_yer") for t in tohumlar]
            if any(h is None for h in haritalar):
                continue
            adresler = set().union(*haritalar)
            ayni = sum(1 for a in adresler
                       if all(h.get(a) == haritalar[0].get(a) for h in haritalar))
            fonksiyon += len(adresler)
            hepsinde += ayni
            tam += ayni == len(adresler)
        oz["butun_tohumlar"] = {"tohumlar": list(tohumlar), "fonksiyon": fonksiyon,
                                "hepsinde_ayni_yol": hepsinde,
                                "tam_ayni_ikili": tam, "ikili": len(kimlikler)}
    # İkili başına sayılar (ilk tohum).
    for k in hepsi:
        s = sonuc[tohumlar[0]][k]
        if "hata" in s:
            oz["ikili"].setdefault(k, {})["hata"] = s["hata"]
            continue
        oz["ikili"].setdefault(k, {}).update({
            a: s[a] for a in ("girdi_fonksiyon", "cikti_c_dosya", "dusen",
                              "cift_tanimli", "basliksiz_dosya", "ham_yok",
                              "liste_var_girdide_yok", "altsistem_dizini",
                              "files_written", "disk_dosya", "basarili",
                              "hata_sayisi", "degismez_hatasi", "sure_s")})
        if len(tohumlar) >= 2 and "hata" not in sonuc[tohumlar[1]][k]:
            oz["ikili"][k]["dusen_ikinci_tohum"] = sonuc[tohumlar[1]][k]["dusen"]
    # Koşu çifti: aynı kod, iki ayrı koşunun girdisi, aynı tohum.
    oz["kosu_cifti"] = []
    t = sonuc[tohumlar[0]]
    for x, y in KOSU_CIFTLERI:
        if x in t and y in t and "hata" not in t[x] and "hata" not in t[y]:
            oz["kosu_cifti"].append({"a": x, "b": y, "tohum": tohumlar[0],
                                     **yol_karsilastir(t[x]["_yer"], t[y]["_yer"])})
    return oz


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--onceki-kurucu", help="karşılaştırılacak eski c_project_builder.py dosyası")
    ap.add_argument("--kurucu", help="ölçülecek kurucu dosyası (varsayılan: depodaki modül)")
    ap.add_argument("--tohum", nargs="+", default=list(VARSAYILAN_TOHUMLAR))
    ap.add_argument("--yalniz", nargs="+", help="yalnız bu kimlikler (ör. debian/tree/tree)")
    ap.add_argument("--json", default=str(CIKTI_JSON))
    ap.add_argument("--gecici-kok", help="geçici dizinin açılacağı yer (varsayılan: sistem)")
    ap.add_argument("--isci", help=argparse.SUPPRESS)
    ap.add_argument("--isci-gecici", help=argparse.SUPPRESS)
    ap.add_argument("--isci-cikti", help=argparse.SUPPRESS)
    args = ap.parse_args(argv)

    if args.isci:
        return isci(args.isci, args.kurucu, args.isci_gecici, args.isci_cikti)

    kosular = kosulari_bul()
    if args.yalniz:
        kosular = [k for k in kosular if k["kimlik"] in set(args.yalniz)]
    ana = [k["kimlik"] for k in kosular if k["ana_kume"]]
    hepsi = [k["kimlik"] for k in kosular]
    if not args.yalniz and len(ana) != BEKLENEN_IKILI:
        raise SystemExit(f"beklenen {BEKLENEN_IKILI} ikili, bulunan {len(ana)}")

    gecici = Path(tempfile.mkdtemp(
        prefix=f"proje-{os.getpid()}-{int(time.time())}-", dir=args.gecici_kok))
    tohumlar = tuple(args.tohum)
    try:
        cikti: dict = {
            "betik": BETIK.name,
            "tarih": time.strftime("%Y-%m-%d"),
            "ikili": len(ana), "ek_kosu": len(hepsi) - len(ana),
            "tohumlar": list(tohumlar),
            "not": ("Sayım diskten: fonksiyon = '// Address:' başlığı. "
                    "algorithm_results verilmedi; analysis/algorithms.md yazılmaz."),
        }
        yeni = iscileri_kos("sonra", args.kurucu, tohumlar, kosular, gecici)
        cikti["sonra"] = surum_ozeti(yeni, tohumlar, ana, hepsi)
        if args.onceki_kurucu:
            eski = iscileri_kos("once", args.onceki_kurucu, tohumlar, kosular, gecici)
            cikti["once"] = surum_ozeti(eski, tohumlar, ana, hepsi)
            # Eski ↔ yeni yerleşim: eski kod tohuma bağlı olduğu için her eski
            # tohum yeni yerleşimle ayrı ayrı karşılaştırılır.
            fark = {}
            for tohum in tohumlar:
                top = Counter()
                for k in ana:
                    e, y = eski[tohum][k], yeni[tohumlar[0]][k]
                    if "hata" in e or "hata" in y:
                        continue
                    top.update(yol_karsilastir(e["_yer"], y["_yer"]))
                    top["altsistem_dizini_eski"] += e["altsistem_dizini"]
                    top["altsistem_dizini_yeni"] += y["altsistem_dizini"]
                fark[tohum] = dict(top)
            cikti["eski_yeni_yerlesim"] = fark
        Path(args.json).write_text(
            json.dumps(cikti, ensure_ascii=False, indent=1, sort_keys=True) + "\n")
    finally:
        shutil.rmtree(gecici, ignore_errors=True)

    for surum in ("once", "sonra"):
        if surum not in cikti:
            continue
        for tohum, t in cikti[surum]["tohum"].items():
            print(f"{surum} tohum={tohum}: fonksiyon {t['toplam'].get('girdi_fonksiyon', 0)}"
                  f" düşen {t['toplam'].get('dusen', 0)} ({t['etkilenen_ikili']['dusen']} ikili)"
                  f" çift {t['toplam'].get('cift_tanimli', 0)}"
                  f" başlıksız {t['toplam'].get('basliksiz_dosya', 0)}"
                  f" sınıf {t['dusme_sinifi']}")
        tc = cikti[surum].get("tohum_cifti")
        if tc:
            print(f"{surum} tohum çifti: aynı yol {tc.get('ayni_yol', 0)}/"
                  f"{tc.get('ortak_fonksiyon', 0)}; tam aynı ikili "
                  f"{tc['tam_ayni_ikili']}/{tc['ikili']}")
            bt = cikti[surum]["butun_tohumlar"]
            print(f"{surum} bütün tohumlar ({len(bt['tohumlar'])}): aynı yol "
                  f"{bt['hepsinde_ayni_yol']}/{bt['fonksiyon']}; tam aynı ikili "
                  f"{bt['tam_ayni_ikili']}/{bt['ikili']}")
        for kc in cikti[surum]["kosu_cifti"]:
            print(f"{surum} koşu çifti {kc['a']} ↔ {kc['b']}: "
                  f"{kc['ayni_yol']}/{kc['ortak_fonksiyon']}")
    print(f"yazıldı: {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
