"""I4 bozma deneyi: Go `pclntab` adlarını kopya üstünde değiştir, tutarlılık denetimi yakalıyor mu say.

Ön kayıt: `docs/arge/2026-11-19_mythos/ustveri/DEFTER.md` §7.3 (türler A–E, beklentiler).
İkili ÇALIŞTIRILMAZ; özgün dosya değişmez (baytlar bellekte değiştirilir; A türünün kopyası veri dizinine yazılır).

Kullanım:
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ustveri/dusman_deney.py <ince ikili> --cikti-dizini <dizin>
"""
from __future__ import annotations

import argparse
import collections
import json
import math
import os
import random
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import go_pclntab as G  # noqa: E402
import go_tip  # noqa: E402
import go_tutarlilik as T  # noqa: E402
import macho  # noqa: E402

DUSMAN_DENEY_TOHUMU = 20261119  # yalnız bu deneyin örnekleme tohumu (ön kayıt: DEFTER §7.3)
N = 200
GUCLU = {"T1", "T2", "T2p", "T3", "T5", "T6"}


def kaydir(b: bytes) -> bytes:
    """ASCII harfleri bir ileri kaydır (a→b … z→a); uzunluk değişmez."""
    out = bytearray(b)
    for i, c in enumerate(out):
        if 97 <= c <= 122:
            out[i] = 97 + (c - 97 + 1) % 26
        elif 65 <= c <= 90:
            out[i] = 65 + (c - 65 + 1) % 26
    return bytes(out)


def son_bilesen_araligi(ad: str):
    """Adın son bileşeninin (köşeli ayraç dışındaki son noktadan sonrası) bayt aralığı; yoksa None."""
    d = 0
    son_nokta = -1
    bitis = len(ad)
    for i, c in enumerate(ad):
        if c == "[":
            if d == 0 and son_nokta >= 0:
                bitis_aday = i
            d += 1
        elif c == "]":
            d -= 1
        elif c == "." and d == 0:
            son_nokta = i
    if son_nokta < 0:
        return None
    kuyruk = ad[son_nokta + 1:]
    kes = kuyruk.find("[")
    if kes >= 0:
        kuyruk = kuyruk[:kes]
    if kuyruk.endswith("-fm"):
        kuyruk = kuyruk[:-3]
    if not any(c.isascii() and c.isalpha() for c in kuyruk):
        return None
    bas = len(ad[:son_nokta + 1].encode())
    return bas, bas + len(kuyruk.encode())


def k4_isaretleri(p, fs):
    """K4: `pcsp` tablosu fonksiyon boyunu kaplamıyorsa işaretle (derleme hizası içindeki dolgu hariç)."""
    hiza = 0
    for f in fs:
        hiza = math.gcd(hiza, f.entry - fs[0].entry)
    out = set()
    for f in fs:
        if f.pcsp == 0:
            continue
        try:
            tb = p.pc_table(f.pcsp, f.entry)
        except Exception:
            out.add(f.entry)
            continue
        son = tb[-1][2] if tb else f.entry
        if son == f.end or (son < f.end and f.end - son < hiza):
            continue
        out.add(f.entry)
    return out


class Durum:
    def __init__(self, veri: bytes, kaynak: str):
        self.m = macho.MachO(veri, kaynak)
        self.p = G.PclnTab(self.m)
        self.fs = self.p.funcs()
        self.isaret, self.kapsam, self.ozet = T.denetle(self.m, self.p)
        self.k4 = k4_isaretleri(self.p, self.fs)

    def guclu(self, e):
        return bool(self.isaret.get(e, set()) & GUCLU)


def olc(taban: Durum, veri: bytearray, hedefler: set, kaynak: str, yapisal=False):
    """Bozulmuş kopyayı denetle; bozulan fonksiyonların kaçı yeni işaret aldı."""
    try:
        d = Durum(bytes(veri), kaynak)
    except Exception as exc:
        return {"okuyucu_hatasi": f"{type(exc).__name__}: {exc}"[:160], "bozulan": len(hedefler)}
    ikinci = taban.kapsam["T1"] | taban.kapsam["T2"] | taban.kapsam["T5"]
    yak_guclu = {e for e in hedefler if d.guclu(e) and not taban.guclu(e)}
    yak_t4 = {e for e in hedefler if "T4" in d.isaret.get(e, set()) and "T4" not in taban.isaret.get(e, set())}
    yak_k4 = {e for e in hedefler if e in d.k4 and e not in taban.k4}
    r = {
        "bozulan": len(hedefler),
        "ikinci_kaynakli_bozulan": len(hedefler & ikinci),
        "guclu_denetim_yakaladi": len(yak_guclu),
        "ikinci_kaynaklida_yakalanan": len(yak_guclu & ikinci),
        "ikinci_kaynaksizda_yakalanan": len(yak_guclu - ikinci),
        "yalniz_T4_yakaladi": len(yak_t4 - yak_guclu),
        "K4_yakaladi": len(yak_k4),
        "hicbiri_yakalamadi": len(hedefler - yak_guclu - yak_t4 - yak_k4),
        "yakalayan_denetim": dict(collections.Counter(
            k for e in yak_guclu for k in (d.isaret[e] & GUCLU) - taban.isaret.get(e, set()))),
        "bozulmayanda_yeni_guclu_isaret": sum(
            1 for f in d.fs if f.entry not in hedefler and d.guclu(f.entry) and not taban.guclu(f.entry)),
    }
    return r


def deney(path: str, cikti_dizini: str):
    ham = Path(path).read_bytes()
    taban = Durum(ham, path)
    p, fs = taban.p, taban.fs
    rng = random.Random(DUSMAN_DENEY_TOHUMU)
    ad = Path(path).name
    sonuc = {"ikili": path, "tohum": DUSMAN_DENEY_TOHUMU, "fonksiyon": len(fs),
             "taban": {k: taban.ozet[k] for k in ("T1", "T2", "T3", "T4", "T5", "isaret_dagilimi",
                                                  "cift_kaynakli_fonksiyon")},
             "taban_guclu_isaretli": sum(1 for f in fs if taban.guclu(f.entry)),
             "taban_K4_isaretli": len(taban.k4)}
    ad_kullanimi = collections.Counter(f.name_off for f in fs)
    ad_ofs = p.off0 + p.funcname_off
    pcln = p.off0 + p.pcln_off

    def paket(f):
        return T.kacis_coz(G.pkg_of(f.name))

    uygun = [f for f in fs if f.name and not taban.guclu(f.entry)
             and paket(f) and not paket(f).startswith(("type:", "go:"))]

    # ---- A: son bileşeni yerinde değiştir ------------------------------
    adaylar = [f for f in uygun if ad_kullanimi[f.name_off] == 1 and son_bilesen_araligi(f.name)]
    secilen = rng.sample(adaylar, N)
    veri = bytearray(ham)
    yamalar = []
    for f in secilen:
        a, b = son_bilesen_araligi(f.name)
        o = ad_ofs + f.name_off
        eski = bytes(veri[o + a:o + b])
        yeni = kaydir(eski)
        veri[o + a:o + b] = yeni
        yamalar.append({"dosya_ofseti": o + a, "eski": eski.decode("utf-8", "replace"),
                        "yeni": yeni.decode("utf-8", "replace")})
    sonuc["A_son_bilesen"] = olc(taban, veri, {f.entry for f in secilen}, path)
    sonuc["A_son_bilesen"]["aday"] = len(adaylar)
    kopya = Path(cikti_dizini) / f"{ad}.A.bozuk"
    kopya.write_bytes(bytes(veri))
    os.chmod(kopya, 0o444)
    (Path(cikti_dizini) / f"{ad}.A.yamalar.json").write_text(json.dumps(yamalar, ensure_ascii=False, indent=1))
    sonuc["A_son_bilesen"]["kopya"] = str(kopya)

    def takas(ciftler):
        v = bytearray(ham)
        for f, g in ciftler:
            of = pcln + f.func_off + 4
            og = pcln + g.func_off + 4
            v[of:of + 4], v[og:og + 4] = struct.pack("<i", g.name_off), struct.pack("<i", f.name_off)
        return v

    # ---- B: paketler arası takas ----------------------------------------
    ciftler = []
    kullanilan = set()
    havuz = list(uygun)
    while len(ciftler) < N // 2:
        f, g = rng.sample(havuz, 2)
        if f.entry in kullanilan or g.entry in kullanilan or paket(f) == paket(g) or f.name == g.name:
            continue
        kullanilan |= {f.entry, g.entry}
        ciftler.append((f, g))
    sonuc["B_paketler_arasi_takas"] = olc(taban, takas(ciftler), kullanilan, path)

    # ---- C: paket içi takas ---------------------------------------------
    grup = collections.defaultdict(list)
    for f in uygun:
        grup[(f.cu_offset, paket(f))].append(f)
    gruplar = [g for g in grup.values() if len(g) >= 2]
    ciftler = []
    kullanilan = set()
    deneme = 0
    while len(ciftler) < N // 2 and deneme < 100000:
        deneme += 1
        f = rng.choice(havuz)
        g_l = grup[(f.cu_offset, paket(f))]
        if len(g_l) < 2:
            continue
        g = rng.choice(g_l)
        if g.entry == f.entry or f.entry in kullanilan or g.entry in kullanilan \
                or T.son_bilesen(f.name) == T.son_bilesen(g.name):
            continue
        kullanilan |= {f.entry, g.entry}
        ciftler.append((f, g))
    sonuc["C_paket_ici_takas"] = olc(taban, takas(ciftler), kullanilan, path)
    sonuc["C_paket_ici_takas"]["uygun_grup"] = len(gruplar)

    # ---- D: tutarlı sahtecilik (tip verisi + pclntab birlikte) ----------
    bi = G.buildinfo(taban.m) or {}
    tip = go_tip.GoTipleri(taban.m, p, bi.get("surum") or "")
    itablar = tip.itabs() if tip.types else []
    ad_ofseti = {}
    for _a, _inter, typ, ms, _fun in itablar:
        u = tip.uncommon(typ)
        pk = u[0] if u else None
        if not pk or "." not in pk.split("/", 1)[0]:
            continue  # standart kitaplık tipleri dışarıda: saldırganın kendi kodu modellenir
        for mad, off in ms:
            if mad and len(mad) >= 4 and mad.isascii() and mad.isalpha():
                ad_ofseti.setdefault(mad, set()).add(off)
    # aynı adı taşıyan başka ad kayıtları da (somut tip yöntem tablosu) aynı ofseti paylaşır; paylaşmayan varsa ekle
    tipler = tip.ulasilan_tipler(itablar) if tip.types else set()
    for t in tipler:
        u = tip.uncommon(t)
        if not u:
            continue
        for mad, off, _i, _t in u[1]:
            if mad in ad_ofseti:
                ad_ofseti[mad].add(off)
    secili_adlar = rng.sample(sorted(ad_ofseti), min(20, len(ad_ofseti)))
    veri = bytearray(ham)
    hedef = set()
    yazilan = set()
    for mad in secili_adlar:
        for off in ad_ofseti[mad]:
            adr, n = tip.name_bytes_addr(off)
            fo = taban.m.vm_to_off(adr)
            if fo in yazilan:
                continue
            yazilan.add(fo)
            veri[fo:fo + n] = kaydir(bytes(veri[fo:fo + n]))
    for f in fs:
        if f.name and T.son_bilesen(f.name) in secili_adlar:
            ar = son_bilesen_araligi(f.name)
            if not ar:
                continue
            o = ad_ofs + f.name_off
            if o not in yazilan:
                yazilan.add(o)
                veri[o + ar[0]:o + ar[1]] = kaydir(bytes(ham[o + ar[0]:o + ar[1]]))
            hedef.add(f.entry)
    sonuc["D_tutarli_sahtecilik"] = olc(taban, veri, hedef, path)
    sonuc["D_tutarli_sahtecilik"]["degistirilen_yontem_adi"] = len(secili_adlar)
    sonuc["D_tutarli_sahtecilik"]["aday_yontem_adi"] = len(ad_ofseti)

    # ---- E: yapısal — komşu _func kayıtlarını takas et ------------------
    veri = bytearray(ham)
    hedef = set()
    sira = list(range(1, len(fs) - 2))
    rng.shuffle(sira)
    alinan = set()
    say = 0
    for i in sira:
        if say >= N // 2:
            break
        if i in alinan or i + 1 in alinan or i - 1 in alinan:
            continue
        f, g = fs[i], fs[i + 1]
        if not f.name or not g.name or f.pcsp == 0 or g.pcsp == 0:
            continue
        alinan |= {i, i + 1}
        # ftab'da funcoff takası; _func.entryOff yeni adrese uydurulur (çalışma zamanı denetimi geçsin diye)
        struct.pack_into("<I", veri, pcln + 8 * i + 4, g.func_off)
        struct.pack_into("<I", veri, pcln + 8 * (i + 1) + 4, f.func_off)
        struct.pack_into("<I", veri, pcln + g.func_off, f.entry - p.text)
        struct.pack_into("<I", veri, pcln + f.func_off, g.entry - p.text)
        hedef |= {f.entry, g.entry}
        say += 1
    sonuc["E_yapisal_takas"] = olc(taban, veri, hedef, path, yapisal=True)
    return sonuc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ikili")
    ap.add_argument("--cikti-dizini", required=True)
    a = ap.parse_args()
    Path(a.cikti_dizini).mkdir(parents=True, exist_ok=True)
    r = deney(a.ikili, a.cikti_dizini)
    s = json.dumps(r, ensure_ascii=False, indent=1)
    (Path(a.cikti_dizini) / f"{Path(a.ikili).name}.deney.json").write_text(s + "\n")
    print(s)


if __name__ == "__main__":
    main()
