#!/usr/bin/env python
"""ÇA-0 kuru sayımı: önerilen çıktı ağacı kuralını VAR OLAN bir koşu çıktısına uygular ve sayar.

Ürün kodu değişmez, hiçbir dosya taşınmaz: betik ``<koşu>/out`` ve ``<koşu>/ws`` ağaçlarını salt
okur, her fonksiyonun bugünkü yolunu ve önerilen kurala göre alacağı yolu hesaplar, ikisini sayar.
Kural ``docs/arge/2026-11-19_mythos/cikti/CIKTI_AGACI_TASARIM.md`` §3–§5'tedir; buradaki
``yol_turet`` o metnin çalışan hâlidir.

Girdi (koşu kökü başına):
- ``out/src/src/**/*.c``: bugünkü ağaç; fonksiyon kimliği dosyadaki ``// Address:`` başlığıdır
  (birleşik dosyada birden çok başlık);
- ``out/naming_map.json`` ``mappings``: koda yazılmış adlar (etiket, kaynak, güven, ``ozgun_ad``);
- ``ws/workspaces/*/*/static/go_functions.json`` (varsa): ``buildinfo`` (ana modül) ve bilgi
  amaçlı kaynak dosya sayımı.

Kullanım (worktree kökünden)::

    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/cikti/kuru_agac.py \
        --kosu ollama=<kök> --kosu tmux=<kök> --cikti <dizin>

Çıktı: ``<dizin>/kuru_agac.json`` (koşu başına sayım) ve ``<dizin>/kuru_agac.md`` (tablo). Ad
listesi yazılmaz (depo herkese açık); ``--ornek N`` yalnız standart çıktıya N örnek yol basar.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from karadul.analyzers.ustveri.go_pclntab import (
    SINIF_CALISMA_ZAMANI, SINIF_DERLEYICI, SINIF_KENDI, SINIF_STANDART, SINIF_UCUNCU_TARAF,
    ana_modul_bul, paket_adi, paket_sinifi,
)
from karadul.core.naming_labels import (
    AD_ESIGI, LABEL_CERTAIN, LABEL_METADATA, LABEL_VERIFIED, SOURCE_GO_PCLNTAB,
    SOURCE_OBJC_METHOD, SOURCE_SWIFT_TYPE,
)
from karadul.pipeline.steps._feedback_naming_candidates import c_identifier

# --- Kuralın sabitleri (tasarım belgesi §3, §5) -------------------------------------------------
UYGUN_ETIKETLER = (LABEL_CERTAIN, LABEL_VERIFIED, LABEL_METADATA)   # §4: dosya adına girebilen
GOVDE_SINIRI = 120            # dosya gövdesi (uzantısız) en çok bu kadar karakter
OZET_BOYU = 8                 # kısaltılan gövdenin sonuna eklenen sha1 öneki
DIL_GO, DIL_OBJC, DIL_SWIFT = "go", "objc", "swift"
GO_SINIF_DIZINI = {
    SINIF_KENDI: "kendi",
    SINIF_UCUNCU_TARAF: "bagimlilik",
    SINIF_STANDART: "standart",
    SINIF_CALISMA_ZAMANI: "standart",
    SINIF_DERLEYICI: "standart",
}
GO_BILINMIYOR = "bilinmiyor"  # paketsiz / sınıfı çıkarılamayan
KATEGORI_ONEKI = "cat-"
GIRIS_DOSYASI = "src/main.c"
TASLAK_DIZINI = "src/import_thunks/"
BIRLESIK_RE = re.compile(r"^(?:thunks_and_stubs|import_thunks)(?:_part\d+)?$")
YER_TUTUCU_RE = re.compile(r"^(?:thunk_)?(?:FUN|SUB|LAB|DAT)_[0-9a-fA-F]+$")
ADRES_RE = re.compile(r"^// Address:\s+(\S+)\s*$", re.MULTILINE)
GUVENSIZ_RE = re.compile(r"[^A-Za-z0-9_.\-]")
NOKTA_DIZISI_RE = re.compile(r"\.{2,}")
WINDOWS_AYRILMIS_RE = re.compile(r"^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$", re.IGNORECASE)
OBJC_RE = re.compile(r"^([+-])\[(\S+?)(?:\(([^)]*)\))?\s+(.+)\]$")
SWIFT_ERISIM_RE = re.compile(r"^type metadata accessor for (.+)$")
TASINABILIR_AD_RE = re.compile(r"^[A-Za-z0-9_.]+$")


@dataclass
class Fonksiyon:
    adres: int
    eski: str                      # ``out/src``'ye göre yol (``src/…``)
    birlesik: bool                 # birden çok fonksiyon taşıyan dosyada mı
    yeni: str = ""
    kaynak: str = "eski"           # yol kaynağı: giris / taslak / go_paket / objc_sinif / swift_modul / kume_ad / eski
    sinif: str | None = None       # Go sınıf dizini
    donusum: list[str] = field(default_factory=list)


def onaltilik(deger: Any) -> int | None:
    """``0x100…`` / ``100…`` / ``FUN_100…`` → tamsayı; çevrilemezse ``None``."""
    if not isinstance(deger, str):
        return None
    s = deger.strip().lower()
    if s.startswith("fun_"):
        s = s[4:]
    if s.startswith("0x"):
        s = s[2:]
    try:
        return int(s, 16)
    except ValueError:
        return None


def agac_oku(out_src: Path) -> tuple[list[Fonksiyon], int]:
    """Bugünkü ağaçtaki fonksiyonlar ve adres başlığı taşımayan ``.c`` dosyası sayısı."""
    fonksiyonlar: list[Fonksiyon] = []
    adressiz = 0
    kaynak_koku = out_src / "src"
    for dosya in sorted(kaynak_koku.rglob("*.c")):
        goreli = dosya.relative_to(out_src).as_posix()
        adresler = [onaltilik(m) for m in ADRES_RE.findall(dosya.read_text(errors="replace"))]
        adresler = [a for a in adresler if a is not None]
        if not adresler:
            adressiz += 1
            continue
        birlesik = len(adresler) > 1 or bool(BIRLESIK_RE.match(dosya.stem))
        fonksiyonlar.extend(Fonksiyon(a, goreli, birlesik) for a in adresler)
    return fonksiyonlar, adressiz


def harita_oku(out: Path) -> dict[int, dict[str, Any]]:
    """``naming_map.json`` kayıtları adrese göre (adres alanı ya da ``FUN_<adres>`` anahtarı)."""
    veri = json.loads((out / "naming_map.json").read_text(encoding="utf-8"))
    kayitlar: dict[int, dict[str, Any]] = {}
    for anahtar, kayit in (veri.get("mappings") or {}).items():
        if not isinstance(kayit, dict):
            continue
        adres = onaltilik(kayit.get("address"))
        if adres is None:
            adres = onaltilik(anahtar) if anahtar.startswith("FUN_") else None
        if adres is not None:
            kayitlar[adres] = kayit
    return kayitlar


def go_bilgisi(kosu: Path) -> dict[str, Any] | None:
    """Çalışma alanındaki ``go_functions.json`` (ana modül + bilgi amaçlı kaynak dosya sayımı)."""
    for yol in sorted(kosu.glob("ws/workspaces/*/*/static/go_functions.json")):
        try:
            return json.loads(yol.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
    return None


def uygun(kayit: dict[str, Any] | None) -> bool:
    """§4: ad dosya adına / dizine girebilir mi (etiket + ölçülmüş güven ≥ ``AD_ESIGI``)."""
    if not kayit or kayit.get("label") not in UYGUN_ETIKETLER:
        return False
    guven = kayit.get("confidence")
    return isinstance(guven, (int, float)) and not isinstance(guven, bool) and guven >= AD_ESIGI


def parca(metin: str, donusum: list[str]) -> str:
    """Yol parçası (dizin adı): taşınabilir karakter kümesine indir (§5.1)."""
    s = metin.replace("%2e", ".").replace("%2E", ".")
    temiz = NOKTA_DIZISI_RE.sub(".", GUVENSIZ_RE.sub("_", s)).strip(".")
    if not temiz:
        temiz = "_"
    if WINDOWS_AYRILMIS_RE.match(temiz):
        temiz += "_"
        donusum.append("ayrilmis_ad")
    if temiz != metin:
        donusum.append("dizin_karakteri")
    return temiz


def govde_kisalt(govde: str, tam_ad: str, donusum: list[str]) -> str:
    """Gövde sınırı aşıyorsa kes ve tam adın özetini ekle (§5.3)."""
    if WINDOWS_AYRILMIS_RE.match(govde):
        govde += "_"
        donusum.append("ayrilmis_ad")
    if len(govde) <= GOVDE_SINIRI:
        return govde
    ozet = hashlib.sha1(tam_ad.encode("utf-8", "surrogatepass")).hexdigest()[:OZET_BOYU]
    donusum.append("kisaltma")
    return f"{govde[:GOVDE_SINIRI - OZET_BOYU - 1]}-{ozet}"


def onek_dus(ad: str, onek_kaynagi: str | None) -> str:
    """Koddaki addan dizine giden öneki düş (``net_http_Serve`` − ``net_http`` → ``Serve``)."""
    onek = c_identifier(onek_kaynagi) if onek_kaynagi else None
    if onek and ad.startswith(onek + "_") and len(ad) > len(onek) + 1:
        return ad[len(onek) + 1:]
    return ad


def yol_turet(f: Fonksiyon, kayit: dict[str, Any] | None, ana_modul: str | None,
              go_sinif_dizini: bool) -> None:
    """Fonksiyonun önerilen yolunu yaz (``f.yeni``, ``f.kaynak``, ``f.sinif``, ``f.donusum``)."""
    if f.eski == GIRIS_DOSYASI:
        f.yeni, f.kaynak = f.eski, "giris"
        return
    if f.eski.startswith(TASLAK_DIZINI):
        f.yeni, f.kaynak = f.eski, "taslak"
        return
    if not uygun(kayit):
        f.yeni, f.kaynak = f.eski, "eski"
        return
    ad = kayit.get("new_name")
    if not isinstance(ad, str) or not ad:
        f.yeni, f.kaynak = f.eski, "eski"
        return
    ozgun = kayit.get("ozgun_ad") if isinstance(kayit.get("ozgun_ad"), str) else None
    kanal = kayit.get("source")
    dizin: list[str] | None = None
    onek: str | None = None
    if kanal == SOURCE_GO_PCLNTAB and ozgun:
        paket = paket_adi(ozgun)
        f.sinif = GO_SINIF_DIZINI.get(paket_sinifi(paket, ana_modul), GO_BILINMIYOR)
        dizin = ["src", DIL_GO] + ([f.sinif] if go_sinif_dizini else [])
        dizin += [parca(p, f.donusum) for p in paket.split("/")] if paket else []
        onek, f.kaynak = paket, "go_paket"
    elif kanal == SOURCE_OBJC_METHOD and ozgun:
        m = OBJC_RE.match(ozgun)
        if m:
            _tur, sinif, kategori, _secici = m.groups()
            dizin = ["src", DIL_OBJC, parca(sinif, f.donusum)]
            if kategori:
                dizin.append(KATEGORI_ONEKI + parca(kategori, f.donusum))
            onek, f.kaynak = sinif, "objc_sinif"
    elif kanal == SOURCE_SWIFT_TYPE and ozgun:
        m = SWIFT_ERISIM_RE.match(ozgun)
        if m:
            modul = re.split(r"[.<(\s]", m.group(1), maxsplit=1)[0]
            dizin = ["src", DIL_SWIFT, parca(modul, f.donusum)]
            f.kaynak = "swift_modul"
    if dizin is None:
        # Dilin hiyerarşisi yok (C) ya da özgün ad çözülemedi: bugünkü küme dizini, ad dosya adında.
        dizin = f.eski.split("/")[:-1]
        f.kaynak = "kume_ad"
    govde = govde_kisalt(onek_dus(ad, onek), ad, f.donusum)
    f.yeni = "/".join(dizin + [govde + ".c"])


def cakisma_coz(fonksiyonlar: list[Fonksiyon]) -> dict[str, int]:
    """Aynı yola (harf duyarsız) inen addan türemiş dosyalara adres eki (§5.2). Sayım döner."""
    gruplar: dict[str, list[Fonksiyon]] = defaultdict(list)
    eski_yollar: set[str] = set()
    for f in fonksiyonlar:
        if f.kaynak in ("eski", "giris", "taslak"):
            eski_yollar.add(f.yeni.casefold())
        else:
            gruplar[f.yeni.casefold()].append(f)
    grup = uye = yalniz_harf = eskiyle = 0
    for anahtar, uyeler in sorted(gruplar.items()):
        eski_ile = anahtar in eski_yollar
        if len(uyeler) < 2 and not eski_ile:
            continue
        grup += 1
        uye += len(uyeler)
        eskiyle += int(eski_ile)
        if len({u.yeni for u in uyeler}) > 1:
            yalniz_harf += 1
        for u in uyeler:
            u.yeni = f"{u.yeni[:-2]}_{u.adres:x}.c"
            u.donusum.append("cakisma_eki")
    return {"grup": grup, "uye": uye, "yalniz_harf_farki_olan_grup": yalniz_harf,
            "eski_yolla_cakisan_grup": eskiyle}


def agac_sayimi(yollar: dict[str, int]) -> dict[str, Any]:
    """``yol → fonksiyon sayısı`` sözlüğünden ağaç sayımı."""
    dizin_dosya: Counter[str] = Counter()
    adli = birlesik = 0
    for yol, n in yollar.items():
        dizin, _, dosya = yol.rpartition("/")
        dizin_dosya[dizin] += 1
        govde = dosya[:-2]
        if n > 1 or BIRLESIK_RE.match(govde):
            birlesik += 1
        elif not YER_TUTUCU_RE.match(govde):
            adli += 1
    harf: dict[str, set[str]] = defaultdict(set)
    for dizin in dizin_dosya:
        harf[dizin.casefold()].add(dizin)
    return {
        "dosya": len(yollar),
        "dizin": len(dizin_dosya),
        "en_kalabalik_10": [[d, n] for d, n in dizin_dosya.most_common(10)],
        "adi_addan_gelen_dosya": adli,
        "birlesik_dosya": birlesik,
        "yer_tutucu_adli_dosya": len(yollar) - adli - birlesik,
        "en_uzun_yol": max((len(y) for y in yollar), default=0),
        "harf_duyarsiz_cakisan_dizin": sum(1 for v in harf.values() if len(v) > 1),
        "en_derin": max((y.count("/") for y in yollar), default=0),
    }


def kosu_say(kosu: Path, go_sinif_dizini: bool, ornek: int) -> dict[str, Any]:
    """Bir koşu kökünün sayımı (bugün ↔ önerilen kural)."""
    out = kosu / "out"
    fonksiyonlar, adressiz = agac_oku(out / "src")
    harita = harita_oku(out)
    go = go_bilgisi(kosu)
    ana_modul = ana_modul_bul(go.get("buildinfo")) if go else None
    for f in fonksiyonlar:
        yol_turet(f, harita.get(f.adres), ana_modul, go_sinif_dizini)
    cakisma = cakisma_coz(fonksiyonlar)

    bugun: Counter[str] = Counter(f.eski for f in fonksiyonlar)
    yeni: Counter[str] = Counter(f.yeni for f in fonksiyonlar)
    tasinan = [f for f in fonksiyonlar if f.yeni != f.eski]
    ozgunler = [k.get("ozgun_ad") for a, k in harita.items()
                if uygun(k) and isinstance(k.get("ozgun_ad"), str)]
    karakter: Counter[str] = Counter()
    for o in ozgunler:
        for c in set(GUVENSIZ_RE.findall(o)):
            karakter[c] += 1
    etiketler = Counter((k.get("label"), k.get("source")) for k in harita.values())
    sonuc: dict[str, Any] = {
        "kosu": str(kosu),
        "go_sinif_dizini": go_sinif_dizini,
        "ana_modul_var": ana_modul is not None,
        "fonksiyon": len(fonksiyonlar),
        "tekil_adres": len({f.adres for f in fonksiyonlar}),
        "adres_basliksiz_dosya": adressiz,
        "ad_haritasi_kaydi": len(harita),
        "ad_haritasi_etiket_kaynak": {f"{e} / {k}": n for (e, k), n in sorted(
            etiketler.items(), key=lambda x: (-x[1], str(x[0])))},
        "uygun_kayit": sum(1 for k in harita.values() if uygun(k)),
        "uygun_ama_agacta_adresi_yok": sum(
            1 for a, k in harita.items() if uygun(k) and a not in {f.adres for f in fonksiyonlar}),
        "bugun": agac_sayimi(bugun),
        "yeni": agac_sayimi(yeni),
        "yolu_degisen_fonksiyon": len(tasinan),
        "birlesik_dosyadan_cikan_fonksiyon": sum(1 for f in tasinan if f.birlesik),
        "uyesi_degisen_birlesik_dosya": len({f.eski for f in tasinan if f.birlesik}),
        "yol_kaynagi": dict(Counter(f.kaynak for f in fonksiyonlar)),
        "go_sinif_fonksiyon": dict(Counter(f.sinif for f in fonksiyonlar if f.sinif)),
        "cakisma": cakisma,
        "donusum": dict(Counter(d for f in fonksiyonlar for d in set(f.donusum))),
        "ozgun_adi_tasinabilir_olmayan": sum(1 for o in ozgunler if not TASINABILIR_AD_RE.match(o)),
        "ozgun_ad_karakterleri": {repr(c): n for c, n in karakter.most_common(12)},
        "en_uzun_ozgun_ad": max((len(o) for o in ozgunler), default=0),
    }
    # Değişmez: addan türemiş her dosya tek fonksiyon taşır (çakışma çözümünden sonra).
    turemis = Counter(f.yeni.casefold() for f in fonksiyonlar if f.yeni != f.eski)
    sonuc["cozumden_sonra_cakisan_yol"] = sum(1 for n in turemis.values() if n > 1)
    if go:
        adli = [g for g in go.get("fonksiyonlar", []) if g.get("ad")]
        dosyalar = Counter(g.get("dosya") or "" for g in adli)
        sonuc["go_bilgi"] = {
            "adli_fonksiyon": len(adli),
            "tekil_paket": len({g.get("paket") for g in adli}),
            "tekil_kaynak_dosya": len(dosyalar),
            "autogenerated_fonksiyon": dosyalar.get("<autogenerated>", 0),
            "kaynak_dosyasi_olmayan": dosyalar.get("", 0),
            "okuyucu_sinif": dict(Counter(g.get("sinif") for g in go.get("fonksiyonlar", []))),
        }
    if ornek:
        gosterilen = [f for f in tasinan if f.kaynak == "go_paket" and f.sinif == "standart"][:ornek]
        for f in gosterilen:
            print(f"  örnek: {f.eski}  →  {f.yeni}", file=sys.stderr)
    return sonuc


def tablo(sonuclar: dict[str, dict[str, Any]]) -> str:
    """Koşu başına özet tablo (Markdown)."""
    satirlar = [
        "| Koşu | Fonksiyon | Dosya bugün → yeni | Dizin bugün → yeni | En kalabalık dizin bugün → yeni "
        "| Adı addan gelen dosya bugün → yeni | Yolu değişen fonksiyon | Çakışma grubu / üye "
        "| En uzun yol bugün → yeni | Kısaltılan |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for ad, s in sonuclar.items():
        b, y = s["bugun"], s["yeni"]
        satirlar.append(
            f"| {ad} | {s['fonksiyon']} | {b['dosya']} → {y['dosya']} | {b['dizin']} → {y['dizin']} "
            f"| {b['en_kalabalik_10'][0][1]} → {y['en_kalabalik_10'][0][1]} "
            f"| {b['adi_addan_gelen_dosya']} → {y['adi_addan_gelen_dosya']} "
            f"| {s['yolu_degisen_fonksiyon']} | {s['cakisma']['grup']} / {s['cakisma']['uye']} "
            f"| {b['en_uzun_yol']} → {y['en_uzun_yol']} | {s['donusum'].get('kisaltma', 0)} |")
    return "\n".join(satirlar) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--kosu", action="append", required=True, metavar="AD=KÖK",
                    help="koşu kökü (içinde out/ ve ws/); birden çok verilebilir")
    ap.add_argument("--cikti", required=True, type=Path, help="sayım dosyalarının yazılacağı dizin")
    ap.add_argument("--go-sinif-dizini", choices=("evet", "hayir"), default="evet",
                    help="Go ağacında kendi / bagimlilik / standart düzeyi (§3.1; karar K-2)")
    ap.add_argument("--ornek", type=int, default=0, help="stderr'e N örnek yol (dosyaya yazılmaz)")
    args = ap.parse_args(argv)

    sonuclar: dict[str, dict[str, Any]] = {}
    for girdi in args.kosu:
        ad, _, kok = girdi.partition("=")
        kosu = Path(kok).expanduser()
        if not (kosu / "out" / "naming_map.json").is_file() or not (kosu / "out" / "src" / "src").is_dir():
            print(f"{ad}: ölçülmedi ({kosu}/out eksik)", file=sys.stderr)
            sonuclar[ad] = {"olculmedi": f"{kosu}/out eksik"}
            continue
        sonuclar[ad] = kosu_say(kosu, args.go_sinif_dizini == "evet", args.ornek)
    olculen = {a: s for a, s in sonuclar.items() if "olculmedi" not in s}
    args.cikti.mkdir(parents=True, exist_ok=True)
    ek = "" if args.go_sinif_dizini == "evet" else "_sinifsiz"
    (args.cikti / f"kuru_agac{ek}.json").write_text(
        json.dumps({"kural": {"govde_siniri": GOVDE_SINIRI, "ad_esigi": AD_ESIGI,
                              "uygun_etiketler": list(UYGUN_ETIKETLER),
                              "go_sinif_dizini": args.go_sinif_dizini},
                    "kosular": sonuclar}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    metin = tablo(olculen)
    (args.cikti / f"kuru_agac{ek}.md").write_text(metin, encoding="utf-8")
    print(metin)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
