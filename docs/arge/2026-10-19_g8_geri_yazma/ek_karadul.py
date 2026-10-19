"""G8 ek, K1 ve K1y girdisi: Karadul'un 20 hedef için verdiği bilgi (onkayit_ek.md §1).

Kaynak: workspaces/olcum_mac/runs/taban-v2-62ad154/tmux/ (Karadul 62ad154).
- Ad: out/naming_map.json  mappings["FUN_<adres>"].new_name
- Prototip: out/src/src/**/*.c içinde "// Address:  <adres>" başlıklı dosyadaki imza satırı
- Yapı bağı (K1y): Karadul'un CTypeRecoverer işlevleri reconstructed/merged/ üzerinde yeniden
  koşulur (karadul koduna dokunulmaz); değişken anahtarı -> yapı eşlemesi types.h'deki yapılarla
  içerik (boyut + alan ofsetleri + kaynak listesi) üzerinden doğrulanır.

Çıktı: workspaces/2026-10-19_g8/veri/k1_karadul.json
"""

from __future__ import annotations

import collections
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ortak  # noqa: E402

KOSU = ortak.DEPO / "workspaces/olcum_mac/runs/taban-v2-62ad154/tmux"
REC = KOSU / "ws/workspaces/tmux/20261019_090738/reconstructed"
OUT_SRC = KOSU / "out/src/src"
TYPES_H = KOSU / "out/src/include/types.h"

RE_BLOK = re.compile(r"/\* Size: (0x[0-9A-Fa-f]+) \((\d+) bytes\)\s*\n \* Sources: ([^\n]*)\n \*/\n"
                     r"struct (recovered_struct_\d+) \{(.*?)\n\};", re.S)
RE_ALAN = re.compile(r"^\s+(.*?)\s*;\s+/\* 0x([0-9A-Fa-f]+) \*/", re.M)


def yorum_sil(s: str) -> str:
    return re.sub(r"/\*.*?\*/", " ", s, flags=re.S)


def _kapanis(s: str, i: int) -> int:
    d = 0
    for k in range(i, len(s)):
        if s[k] == "(":
            d += 1
        elif s[k] == ")":
            d -= 1
            if d == 0:
                return k
    return -1


def imza_cozumle(metin: str, ad: str) -> dict | None:
    """Dosyadaki '<dönüş> <ad>(<parametreler>)' satırını bulur; yorumları atar."""
    temiz = yorum_sil(metin)
    m = re.search(r"^([^\n/#{}][^\n]*?)\b" + re.escape(ad) + r"\s*\(", temiz, re.M)
    if not m:
        return None
    ac = m.end() - 1
    kap = _kapanis(temiz, ac)
    if kap == -1:
        return None
    donus = " ".join(m.group(1).split())
    param_metni = " ".join(temiz[ac + 1:kap].split())
    params = []
    if param_metni and param_metni != "void":
        for p in param_metni.split(","):
            p = p.strip()
            mm = re.match(r"^(.*?)([A-Za-z_]\w*)\s*$", p)
            if not mm or not mm.group(1).strip():
                params.append({"tip": p, "ad": None})
            else:
                params.append({"tip": " ".join(mm.group(1).split()), "ad": mm.group(2)})
    return {"donus": donus, "ad": ad, "parametreler": params, "metin": f"{donus} {ad}({param_metni})"}


def dosya_bul(kok: Path, adres_hex: str) -> Path | None:
    hedef = f"// Address:  {adres_hex}"
    for p in kok.rglob("*.c"):
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                for _ in range(6):
                    satir = f.readline()
                    if satir.strip() == hedef:
                        return p
        except OSError:
            continue
    return None


def dosya_fonksiyon_adi(metin: str) -> str | None:
    m = re.search(r"^// Function: (\S+)", metin, re.M)
    return m.group(1) if m else None


def c0_imzasi(adres: str) -> dict | None:
    metin = (ortak.CIKTILAR / "C0" / f"hedef_{adres}.c").read_text()
    ad = "FUN_" + adres[2:]
    return imza_cozumle(metin, ad)


def types_h_yapilari() -> dict:
    out = {}
    for m in RE_BLOK.finditer(TYPES_H.read_text()):
        alanlar = []
        for a in RE_ALAN.finditer(m.group(5)):
            bildirim, ofs = a.group(1), int(a.group(2), 16)
            alanlar.append({"ofset": ofs, "bildirim": " ".join(bildirim.split())})
        out[m.group(4)] = {"ad": m.group(4), "boyut": int(m.group(2)),
                           "kaynaklar": [s.strip() for s in m.group(3).split(",")], "alanlar": alanlar}
    return out


def bag_uret() -> tuple[dict, dict]:
    """Karadul'un sentezini yeniden koşar: {taban_degisken: yapı_adı}, istatistik."""
    if str(ortak.DEPO) not in sys.path:
        sys.path.insert(0, str(ortak.DEPO))
    from karadul.config import Config
    from karadul.reconstruction.c_type_recoverer import CTypeRecoverer, _parse_c_file_worker
    rec = CTypeRecoverer(Config())
    for f in sorted((REC / "merged").rglob("*.c")):
        rec._merge_parse_result(_parse_c_file_worker(str(f)))
    # _synthesize_structs ile aynı süzgeç: yapı üreten değişkenler, aynı sırada
    yapilar = rec._synthesize_structs()
    uretenler = []
    for base, erisim in rec._field_accesses.items():
        vt = {e["offset"] for e in rec._vtable_entries.get(base, [])}
        if sum(1 for a in erisim.values() if a["offset"] not in vt) < rec.min_fields_for_struct:
            continue
        uretenler.append(base)
    if len(uretenler) != len(yapilar):
        raise RuntimeError(f"süzgeç uyuşmazlığı: {len(uretenler)} değişken, {len(yapilar)} yapı")
    gemi = types_h_yapilari()
    anahtar_gemi = collections.defaultdict(list)
    for ad, y in gemi.items():
        anahtar_gemi[(y["boyut"], tuple(a["ofset"] for a in y["alanlar"]), tuple(y["kaynaklar"]))].append(ad)
    bag, esles, eslesmez = {}, 0, 0
    for base, s in zip(uretenler, yapilar):
        k = (s.total_size, tuple(f.offset for f in s.fields), tuple(s.source_functions))
        adaylar = anahtar_gemi.get(k, [])
        if adaylar:
            esles += 1
            bag[base] = adaylar  # içerik aynı birden çok yapı olabilir
        else:
            eslesmez += 1
    return bag, {"yeniden_uretilen": len(yapilar), "types_h_ile_eslesen": esles, "eslesmeyen": eslesmez,
                 "types_h_yapi": len(gemi)}


def main() -> None:
    secim = json.loads((ortak.VERI / "secim.json").read_text())
    nm = json.loads((KOSU / "out/naming_map.json").read_text())["mappings"]
    gemi = types_h_yapilari()
    kaynak_dizini = collections.defaultdict(list)
    for ad, y in gemi.items():
        for s in y["kaynaklar"]:
            kaynak_dizini[s].append(ad)
    bag, bag_ist = bag_uret()

    hedefler = []
    for h in secim["hedefler"]:
        adr = h["adres"]
        hx = adr[2:]
        fun = "FUN_" + hx
        kayit: dict = {"adres": adr, "gt_ad": h["ad"], "ghidra_adi": fun}
        e = nm.get(fun)
        kayit["karadul_ad"] = e["new_name"] if e else None
        kayit["karadul_ad_kaynagi"] = e.get("source") if e else None
        # Son çıktıdaki imza
        p = dosya_bul(OUT_SRC, hx)
        kayit["cikti_dosyasi"] = str(p.relative_to(KOSU)) if p else None
        imza = None
        if p:
            metin = p.read_text(encoding="utf-8", errors="replace")
            dad = dosya_fonksiyon_adi(metin)
            imza = imza_cozumle(metin, dad) if dad else None
        kayit["karadul_imza"] = imza
        c0 = c0_imzasi(adr)
        kayit["c0_imza"] = c0
        if imza and c0:
            ad_farki = [i for i, (a, b) in enumerate(zip(imza["parametreler"], c0["parametreler"]))
                        if a["ad"] != b["ad"]]
            tip_farki = [i for i, (a, b) in enumerate(zip(imza["parametreler"], c0["parametreler"]))
                         if a["tip"].replace(" ", "") != b["tip"].replace(" ", "")]
            sayi_farki = len(imza["parametreler"]) != len(c0["parametreler"])
            donus_farki = imza["donus"].replace(" ", "") != c0["donus"].replace(" ", "")
            kayit["imza_farki"] = {"parametre_adi": ad_farki, "parametre_tipi": tip_farki,
                                   "parametre_sayisi": sayi_farki, "donus_tipi": donus_farki}
            kayit["prototip_yazilir"] = bool(ad_farki or tip_farki or sayi_farki or donus_farki)
        else:
            kayit["imza_farki"] = None
            kayit["prototip_yazilir"] = False
        # K1y: merged/ dosyasındaki ilk parametre adı -> Karadul yapısı
        pm = dosya_bul(REC / "merged", hx)
        kayit["merged_dosyasi"] = str(pm.relative_to(KOSU)) if pm else None
        ilk = None
        if pm:
            mm = pm.read_text(encoding="utf-8", errors="replace")
            dad = dosya_fonksiyon_adi(mm)
            im = imza_cozumle(mm, dad) if dad else None
            if im and im["parametreler"]:
                ilk = im["parametreler"][0]["ad"]
        kayit["merged_ilk_parametre"] = ilk
        bagli = bag.get(ilk) if ilk else None
        kayit["bagli_yapi"] = bagli[0] if bagli else None
        kayit["bagli_yapi_esdeger_adlar"] = bagli or []
        adlar = [fun] + ([kayit["karadul_ad"]] if kayit["karadul_ad"] else [])
        kayit["kaynak_listesinde_gectigi_yapilar"] = sorted(set(sum((kaynak_dizini.get(a, []) for a in adlar), [])))
        hedefler.append(kayit)

    yapilar = {}
    for k in hedefler:
        for ad in set(([k["bagli_yapi"]] if k["bagli_yapi"] else []) + k["kaynak_listesinde_gectigi_yapilar"]):
            yapilar[ad] = gemi[ad]
    kapsam = {
        "ad": sum(1 for k in hedefler if k["karadul_ad"]),
        "imza_bulunan": sum(1 for k in hedefler if k["karadul_imza"]),
        "prototip_yazilir": sum(1 for k in hedefler if k["prototip_yazilir"]),
        "parametre_adi_degisen": sum(1 for k in hedefler if k["imza_farki"] and k["imza_farki"]["parametre_adi"]),
        "parametre_tipi_degisen": sum(1 for k in hedefler if k["imza_farki"] and k["imza_farki"]["parametre_tipi"]),
        "bagli_yapi": sum(1 for k in hedefler if k["bagli_yapi"]),
        "kaynak_listesinde_gecen": sum(1 for k in hedefler if k["kaynak_listesinde_gectigi_yapilar"]),
    }
    cikti = {"kunye": ortak.kunye(), "karadul_kosusu": str(KOSU), "bag_uretimi": bag_ist,
             "kapsam": kapsam, "hedefler": hedefler, "ilgili_yapilar": yapilar}
    ortak.json_yaz(ortak.VERI / "k1_karadul.json", cikti)
    print("bağ üretimi:", bag_ist)
    print("kapsam:", kapsam)


if __name__ == "__main__":
    main()
