#!/usr/bin/env python3
"""ÖZ KOD kalem 1 — ``string_context/oz_ad`` adlarında doğru / yanlışı ayıran kanıt özelliği.

Her ``oz_ad`` adı için (taban koşu a62f15e) GT'siz özellikler çıkarılır ve hükümle çaprazlanır.

Özellikler
  rol       : kanıt dizgisinin fonksiyonun C metninde nasıl kullanıldığı (ilk eşleşen):
              'bicim_dolgusu' — aynı çağrıda ondan ÖNCE '%s' içeren bir dizgi sabiti var
                                (``log("%s: …", "ad")``: __func__ kalıbı);
              'assert'        — çağrılan adı assert ailesinden (``__assert_fail``, ``__assert_rtn``, …);
              'anahtar'       — çağrıda dizgi var ama önünde '%s'li biçim yok (anahtar / etiket argümanı);
              'atama'         — çağrı argümanı değil (atama, karşılaştırma, dizi öğesi);
              'metinde_yok'   — C metninde sabit olarak geçmiyor (dizgi bağı var, metin yok).
  cakisma   : ad ``_<sayı>`` çakışma ekiyle bitiyor ya da aynı kanıt dizgisi ikilide > 1 ada kanıt.
  n_fn      : dizgiyi anan fonksiyon sayısı (Ghidra xref).
  kendi     : dizgi fonksiyonun kendi xref listesinde mi.
  kayitli   : dizgi bir kayıt çiftinde (V ∪ C) BAŞKA bir fonksiyonla eşli mi.
  n_tanim   : fonksiyonun andığı tanımlayıcı biçimli dizgi sayısı.

Kural adayı (keşifte okunur, ``--kural`` ile sayılır): KURAL_TUT koşulunu sağlayan ad tutulur.

Kullanım:
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ozkod/oz_ad_ayrim.py --taraf kesif [--dok]
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
import kayit_cifti as K  # noqa: E402
import ek_kurali as E  # noqa: E402

KANAL = "string_context/oz_ad"
DIZIN_ONBELLEK = V.ARGE_KOKU / "onbellek_c_dizini"
ASSERT_AILESI = re.compile(r"assert", re.I)
CAKISMA_EKI = re.compile(r"_\d+$")


def c_dizini(d: dict[str, Any]) -> dict[int, str]:
    """fonksiyon adresi → decompile edilmiş C dosyasının yolu."""
    yol = DIZIN_ONBELLEK / V.onbellek_yolu(d["birim"], d["ad"]).name
    if yol.is_file():
        with open(yol, "rb") as f:
            return pickle.load(f)
    out = {}
    for c in sorted((Path(d["static"]) / "ghidra_output" / "decompiled").glob("*.c")):
        with open(c, encoding="utf-8", errors="replace") as f:
            bas = f.read(400)
        m = re.search(r"^// Address:\s+([0-9a-fA-F]+)", bas, re.M)
        if m:
            out[int(m.group(1), 16)] = str(c)
    yol.parent.mkdir(parents=True, exist_ok=True)
    with open(yol, "wb") as f:
        pickle.dump(out, f)
    return out


def dizgi_rolu(metin: str, dizgi: str) -> tuple[str, Optional[str]]:
    """(rol, çağrılan adı). Tanım belge dizgisinde."""
    kes = metin.find("// --- DISASSEMBLY")
    if kes >= 0:
        metin = metin[:kes]
    sabit = '"' + dizgi.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if sabit not in metin:
        return "metinde_yok", None
    roller: list[tuple[str, Optional[str]]] = []
    for m in K._CAGRI_BASI.finditer(metin):
        ad = m.group(1)
        if ad in K._ANAHTAR:
            continue
        arglar, _son = K._argumanlar(metin, m.end() - 1)
        if not arglar:
            continue
        soyulmus = [re.sub(r"^(?:\([^()]*\)\s*)+", "", a) for a in arglar]
        if sabit not in soyulmus:
            continue
        i = soyulmus.index(sabit)
        if ASSERT_AILESI.search(ad):
            roller.append(("assert", ad))
        elif any(a.startswith('"') and "%s" in a for a in soyulmus[:i]):
            roller.append(("bicim_dolgusu", ad))
        else:
            roller.append(("anahtar", ad))
    if not roller:
        return "atama", None
    for oncelik in ("assert", "bicim_dolgusu", "anahtar"):
        for r in roller:
            if r[0] == oncelik:
                return r
    return roller[0]


def ozellikler(taraf_: str) -> list[dict[str, Any]]:
    out = []
    for d in V.hepsi(taraf_=taraf_):
        oz = {fa: r for fa, r in d["urun"].items() if r["kanal"] == KANAL}
        if not oz:
            continue
        dizin = c_dizini(d)
        deger_adres: dict[str, list[int]] = defaultdict(list)
        for a, s in d["dizgi_metin"].items():
            deger_adres[s].append(a)
        kanit_sayaci = Counter(str(r["koken"].get("evidence")) for r in oz.values())
        adaylar = E.adaylar(d)
        kayitli_dizgi: dict[str, set[int]] = defaultdict(set)
        for fa, liste in adaylar.items():
            for _g, s in liste:
                kayitli_dizgi[s].add(fa)
        for fa, r in sorted(oz.items()):
            kanit = str(r["koken"].get("evidence") or "")
            adresler = deger_adres.get(kanit, [])
            anan = {f for a in adresler for f in d["dizgi_fn"].get(a, [])}
            kendi = [d["dizgi_metin"][a] for a in d["fn_dizgi"].get(fa, [])]
            c_yolu = dizin.get(fa)
            metin = Path(c_yolu).read_text(encoding="utf-8", errors="replace") if c_yolu else ""
            rol, cagrilan = dizgi_rolu(metin, kanit)
            out.append({
                "birim": d["birim"], "ikili": d["ad"], "adres": fa, "ad": r["ad"],
                "gt": d["gt_adlar"].get(fa, ["—"])[0], "dogru": r["durum"] == "dogru",
                "kanit": kanit, "rol": rol, "cagrilan": cagrilan,
                "cakisma": bool(CAKISMA_EKI.search(r["ad"])) or kanit_sayaci[kanit] > 1,
                "n_fn": len(anan), "kendi": kanit in kendi,
                "kayitli": bool(kayitli_dizgi.get(kanit, set()) - {fa}),
                "n_tanim": sum(1 for s in set(kendi) if K.ad_bicimli(s) and "_" in s),
                "guven": round(float(r["koken"].get("confidence") or 0), 2)})
    return out


# Kural adayı R1 "çift yönlü teklik" (keşifte okundu; DEFTER §7'de donduruldu).
# İlk aday (rol ∈ {bicim_dolgusu, assert}) keşifte tutmadı: __func__ çoğu kez bir yardımcıya
# argüman olarak geçiyor (tmux ``screen_write_collect_flush(ctx, 0, __func__)``), rol 'anahtar'
# görünüyor; Mach-O'da 15 doğru adın dizgisi C metninde sabit olarak hiç geçmiyor.
def kural_tut(o: dict[str, Any]) -> bool:
    return (o["n_fn"] == 1 and o["n_tanim"] <= 1 and not o["cakisma"] and o["kendi"]
            and not o["kayitli"])


def capraz(kayitlar: list[dict[str, Any]], alan: str) -> None:
    c: dict[Any, Counter] = defaultdict(Counter)
    for o in kayitlar:
        deger = o[alan]
        if alan == "n_fn":
            deger = "1" if deger <= 1 else "2" if deger == 2 else "3+"
        if alan == "n_tanim":
            deger = "0-1" if deger <= 1 else "2-3" if deger <= 3 else "4+"
        c[deger][o["dogru"]] += 1
    print(f"\n### {alan}")
    print("| değer | ad | doğru | yanlış | kesinlik (Wilson) |")
    print("|---|---:|---:|---:|---|")
    for deger, s in sorted(c.items(), key=lambda kv: str(kv[0])):
        n = s[True] + s[False]
        print(f"| {deger} | {n} | {s[True]} | {s[False]} | {V.wilson(s[True], n)} |")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--taraf", choices=("kesif", "sinama"), required=True)
    ap.add_argument("--dok", action="store_true", help="ad başına satır (yalnız keşif)")
    a = ap.parse_args()
    if a.dok and a.taraf != "kesif":
        raise SystemExit("döküm yalnız keşif tarafında")
    kayitlar = ozellikler(a.taraf)
    n = len(kayitlar)
    dogru = sum(o["dogru"] for o in kayitlar)
    print(f"## oz_ad — taraf: {a.taraf}: {n} ad, doğru {V.wilson(dogru, n)}")
    by: dict[str, Counter] = defaultdict(Counter)
    for o in kayitlar:
        by[o["birim"]][o["dogru"]] += 1
    for alan in ("rol", "cakisma", "n_fn", "kendi", "kayitli", "n_tanim", "guven"):
        capraz(kayitlar, alan)
    tut = [o for o in kayitlar if kural_tut(o)]
    at = [o for o in kayitlar if not kural_tut(o)]
    print("\n### Kural adayı R1 (çift yönlü teklik): n_fn = 1, n_tanim ≤ 1, çakışma yok, kendi, başka fonksiyonla kayıtlı değil → tut")
    print("| | ad | doğru | yanlış | kesinlik (Wilson) |")
    print("|---|---:|---:|---:|---|")
    for etiket, kume in (("tutulan", tut), ("atılan", at)):
        k_ = sum(o["dogru"] for o in kume)
        print(f"| {etiket} | {len(kume)} | {k_} | {len(kume) - k_} | {V.wilson(k_, len(kume))} |")
    print(f"\ndoğruların tutulan payı: {V.wilson(sum(o['dogru'] for o in tut), dogru)}; "
          f"yanlışların atılan payı: {V.wilson(sum(not o['dogru'] for o in at), n - dogru)}")
    print("\n| birim | ad | doğru | tutulan | tutulan doğru |")
    print("|---|---:|---:|---:|---:|")
    for b in sorted(by):
        kb = [o for o in kayitlar if o["birim"] == b]
        tb = [o for o in kb if kural_tut(o)]
        print(f"| {b} | {len(kb)} | {sum(o['dogru'] for o in kb)} | {len(tb)} | {sum(o['dogru'] for o in tb)} |")
    if a.dok:
        print("\n### Döküm")
        for o in kayitlar:
            print(f"- {o['birim']}/{o['ikili']} {'D' if o['dogru'] else 'Y'} gt `{o['gt']}` ad `{o['ad']}` "
                  f"rol {o['rol']} ({o['cagrilan']}) çakışma {int(o['cakisma'])} n_fn {o['n_fn']} "
                  f"kendi {int(o['kendi'])} kayıtlı {int(o['kayitli'])} n_tanım {o['n_tanim']}")
    (V.ARGE_KOKU / f"oz_ad_ayrim_{a.taraf}.json").write_text(
        json.dumps(kayitlar, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
