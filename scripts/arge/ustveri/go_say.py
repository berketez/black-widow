"""Go ikililerinde `pclntab` sayımı, iç tutarlılık denetimleri ve sembol tablosuyla karşılaştırma.

Kullanım (depo kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ustveri/go_say.py <ikili> [--dilim arm64] [--cikti dosya.json]

Çıktı: tek JSON (sayılar) ve isteğe bağlı fonksiyon listesi (`--liste dosya.tsv`: adres, bitiş, sınıf, paket, ad, dosya).
İkiliyi çalıştırmaz.
"""
from __future__ import annotations

import argparse
import bisect
import collections
import json
import math
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import go_pclntab as G  # noqa: E402
import macho  # noqa: E402


def bl_hedefleri(m, lo: int, hi: int):
    """arm64: [lo, hi) aralığındaki `bl` komutlarının hedefleri (kaynak pc, hedef pc)."""
    out = []
    for sec in m.text_sections():
        a = max(sec.addr, lo)
        b = min(sec.addr + sec.size, hi)
        if a >= b:
            continue
        a += (-a) % 4
        blob = m.read(a, b - a)
        n = len(blob) // 4
        words = struct.unpack_from(f"<{n}I", blob)
        for i, w in enumerate(words):
            if w & 0xFC000000 == 0x94000000:
                imm = w & 0x03FFFFFF
                if imm & 0x02000000:
                    imm -= 0x04000000
                out.append((a + 4 * i, a + 4 * i + 4 * imm))
    return out


def findfunctab_denetimi(m, p, fs):
    """`findfunctab` kovaları ↔ `ftab` (runtime.findfunc'ın kullandığı tablo)."""
    md = p.md
    if not md or not md.get("findfunctab"):
        return None
    entries = [f.entry for f in fs]
    minpc, maxpc = md["minpc"], md["maxpc"]
    nb = (maxpc - minpc + G.FUNC_TAB_BUCKET - 1) // G.FUNC_TAB_BUCKET
    blob = m.read(md["findfunctab"], nb * 20)
    if blob is None or len(blob) < nb * 20:
        return {"kova": nb, "okunamadi": True}
    uyumlu = 0
    toplam = 0
    for b in range(nb):
        idx = struct.unpack_from("<I", blob, 20 * b)[0]
        for s in range(16):
            pc = minpc + b * G.FUNC_TAB_BUCKET + s * 256
            if pc >= maxpc:
                break
            toplam += 1
            beklenen = bisect.bisect_right(entries, pc) - 1
            basla = idx + blob[20 * b + 4 + s]
            # findfunc basla'dan ileri tarar: basla ≤ beklenen olmalı ve aradaki fark küçük olmalı
            if basla <= beklenen and beklenen - basla <= 256:
                uyumlu += 1
    return {"kova": nb, "alt_kova": toplam, "uyumlu": uyumlu}


def say(path: str, dilim: str | None, liste: str | None):
    m = macho.load(path, dilim)
    p = G.PclnTab(m)
    bi = G.buildinfo(m) or {}
    fs = p.funcs()
    ana_modul = bi.get("mod")
    if not ana_modul and bi.get("path"):
        # `mod` satırı yoksa (eski derleme düzeni) ana paket yolunun ilk üç öğesi modül sayılır
        ana_modul = "/".join(bi["path"].split("/")[:3])
    r = {
        "ikili": path, "dilim": m.cpu, "go_surumu": bi.get("surum"), "ana_paket": bi.get("path"),
        "ana_modul": ana_modul, "bagimlilik_sayisi": bi.get("dep"), "build": bi.get("build"),
        "pclntab": {
            "adres": hex(p.addr), "bulma": p.bulma, "imza": hex(p.magic), "imza_adi": G.MAGIC_ADLARI[p.magic],
            "minLC": p.min_lc, "nfunc": p.nfunc, "nfiles": p.nfiles,
            "basliktaki_textStart": hex(p.text_start_hdr), "text": hex(p.text) if p.text else None,
            "text_kaynagi": p.text_kaynagi, "moduledata_adayi": p.md_adaylari,
            "moduledata": hex(p.md["adres"]) if p.md else None, "notlar": p.notlar[:10],
        },
    }
    # ---- sayım ----------------------------------------------------------
    adli = [f for f in fs if f.name]
    dosyalar = {}
    sinif_say = collections.Counter()
    sinif_bayt = collections.Counter()
    paketler = collections.Counter()
    satirlar = []
    dosyali = 0
    for f in fs:
        dosya = p.file_of(f)
        if dosya:
            dosyali += 1
            dosyalar[dosya] = dosyalar.get(dosya, 0) + 1
        pkg = G.pkg_of(f.name)
        s = G.sinif(pkg, ana_modul) if f.name else "adsiz"
        sinif_say[s] += 1
        sinif_bayt[s] += f.end - f.entry
        paketler[pkg] += 1
        if liste:
            satirlar.append(f"{f.entry:#x}\t{f.end:#x}\t{s}\t{pkg}\t{f.name}\t{dosya or ''}\t{f.func_id}\t{f.flag}")
    tum_adlar = p.funcname_strings()
    kullanilan = {f.name_off for f in fs}
    r["sayim"] = {
        "fonksiyon_girisi": len(fs), "adli": len(adli), "ayrik_ad": len({f.name for f in adli}),
        "dosya_yolu_olan": dosyali, "ayrik_dosya_yolu": len(dosyalar),
        "funcnametab_dizgi": len(tum_adlar),
        "yalniz_satir_ici_ad": len([o for o in tum_adlar if o not in kullanilan]),
        "sarmalayici_funcID": sum(1 for f in fs if f.func_id == 23),
        "asm_bayrakli": sum(1 for f in fs if f.flag & 4),
        "sinif": dict(sinif_say), "sinif_bayt": dict(sinif_bayt), "ayrik_paket": len(paketler),
    }
    if liste:
        Path(liste).write_text("\n".join(satirlar) + "\n")

    # ---- iç tutarlılık --------------------------------------------------
    entries = [f.entry for f in fs]
    text_sec = m.sec("__TEXT", "__text")
    md = p.md or {}
    d = {}
    d["K1_artan"] = {"ihlal": sum(1 for i in range(1, len(entries)) if entries[i] <= entries[i - 1])}
    d["K2_text_icinde"] = {
        "bolum_disi": sum(1 for e in entries if not (text_sec.addr <= e < text_sec.addr + text_sec.size)),
        "moduledata_disi": (sum(1 for e in entries if not (md["text"] <= e < md["etext"]))
                            if md.get("text") and md.get("etext") else None),
    }
    d["K3_hiza"] = {"minLC_ihlali": sum(1 for e in entries if e % p.min_lc),
                    "16_kati": sum(1 for e in entries if e % 16 == 0)}
    # K4: pcsp tablosu fonksiyonun tamamını kaplıyor mu (çalışma zamanı yığın açarken buna muhtaç).
    # Fonksiyonlar hizaya doldurulur: hiza = giriş adreslerinin en büyük ortak böleni (arm64'te 16, amd64'te 32).
    hiza = 0
    for e in entries:
        hiza = math.gcd(hiza, e - entries[0])
    tam = dolgulu = kisa_asm = kisa = tasan = pcspsiz = 0
    for f in fs:
        if f.pcsp == 0:
            pcspsiz += 1
            continue
        tb = p.pc_table(f.pcsp, f.entry)
        son = tb[-1][2] if tb else f.entry
        if son == f.end:
            tam += 1
        elif son < f.end and f.end - son < hiza:
            dolgulu += 1
        elif son < f.end and f.flag & 4:
            kisa_asm += 1
        elif son < f.end:
            kisa += 1
        else:
            tasan += 1
    d["K4_pcsp_kapsama"] = {"hiza": hiza, "tam": tam, "dolguyla": dolgulu, "kisa_asm": kisa_asm, "kisa": kisa,
                            "tasan": tasan, "pcsp_yok": pcspsiz}
    d["K5_findfunctab"] = findfunctab_denetimi(m, p, fs)
    fstarts = m.function_starts()
    if fstarts is not None:
        fset = set(fstarts)
        lo, hi = entries[0], fs[-1].end
        icerde = [a for a in fstarts if lo <= a < hi]
        eset = set(entries)
        d["K6_function_starts"] = {
            "LC_FUNCTION_STARTS": len(fstarts), "go_araliginda": len(icerde),
            "pclntab_girisi_baslangic_mi": sum(1 for e in entries if e in fset),
            "aralikta_pclntabda_olmayan": sum(1 for a in icerde if a not in eset),
            "go_araligi_disinda": len(fstarts) - len(icerde),
        }
    else:
        d["K6_function_starts"] = None
    if m.cpu == "arm64":
        lo, hi = entries[0], fs[-1].end
        bl = bl_hedefleri(m, lo, hi)
        eset = set(entries)
        ic = [(s, t) for s, t in bl if lo <= t < hi]
        isabet = sum(1 for _s, t in ic if t in eset)
        cagrilan = {t for _s, t in ic if t in eset}
        # Go ≤ 1.25 arm64: `runtime.duffzero` / `runtime.duffcopy` gövdesinin ortasına çağrı olağandır (Duff düzeni).
        duff = diger = 0
        for _s, t in ic:
            if t not in eset:
                ad = fs[bisect.bisect_right(entries, t) - 1].name
                if ad in ("runtime.duffzero", "runtime.duffcopy"):
                    duff += 1
                else:
                    diger += 1
        d["K7_bl_hedefi"] = {"bl": len(bl), "hedef_go_araliginda": len(ic), "hedef_giris": isabet,
                             "hedef_duff_ici": duff, "hedef_baska_govde_ici": diger,
                             "dogrudan_cagrilan_giris": len(cagrilan)}
    else:
        d["K7_bl_hedefi"] = None
    # K8: özel funcID taşıyan fonksiyonlar. Numaralandırma sürüme bağlı (1.24'te Wrapper 22, 1.26+'da 23);
    # sürümden bağımsız değişmez: en büyük kimlik (Wrapper) ve 0 dışındaki her kimlik tek bir `runtime.` fonksiyonundadır.
    sarma = max(f.func_id for f in fs)
    ozel = [f for f in fs if 0 < f.func_id < sarma]
    kimlik_say = collections.Counter(f.func_id for f in ozel)
    k8 = {"sarmalayici_kimligi": sarma, "ozel": len(ozel),
          "runtime_onekli": sum(1 for f in ozel if f.name.startswith("runtime.")),
          "yinelenen_kimlik": sum(1 for _k, v in kimlik_say.items() if v > 1)}
    if sarma == 23:  # 1.26 / 1.27 tablosu (internal/abi/symtab.go; dört ikilide doğrulandı)
        k8["tablo_uyan"] = sum(1 for f in ozel if G.FUNC_ID_ADI.get(G.FUNC_ID[f.func_id]) == f.name)
        k8["tablo_uymayan"] = len(ozel) - k8["tablo_uyan"]
    d["K8_funcID_adi"] = k8
    if md.get("minpc"):
        d["K9_minpc_maxpc"] = {"minpc_uyuyor": md["minpc"] == entries[0],
                               "maxpc_uyuyor": md["maxpc"] == (p.text + p.son_entryoff)}
    r["tutarlilik"] = d

    # ---- sembol tablosuyla karşılaştırma -------------------------------
    syms = [s for s in m.defined_symbols() if s.n_sect == text_sec.index]
    go_sym = collections.defaultdict(set)
    for s in syms:
        ad = s.name[1:] if s.name.startswith("_") else s.name
        go_sym[s.value].add(ad)
    gt = {}
    es = {f.entry: f for f in fs}
    ortak = [a for a in go_sym if a in es]
    # Sembol tablosu yazım farkları: ABI0 sembolüne `.abi0` eki; tip adındaki orta nokta (·) sembolde nokta.
    ayni = abi_eki = orta_nokta = 0
    farkli = []
    for a in ortak:
        ad = es[a].name
        adlar = go_sym[a]
        if ad in adlar:
            ayni += 1
        elif ad in {re.sub(r"\.abi(0|internal)$", "", n) for n in adlar}:
            abi_eki += 1
        elif ad.replace("\u00b7", ".") in adlar:
            orta_nokta += 1
        else:
            farkli.append((hex(a), ad, sorted(adlar)[:2]))
    lo, hi = entries[0], fs[-1].end
    gt = {
        "text_sembolu": len(syms), "ayrik_adres": len(go_sym),
        "go_araliginda_sembol_adresi": sum(1 for a in go_sym if lo <= a < hi),
        "pclntab_girisinde_sembol": len(ortak), "ad_ayni": ayni, "ad_abi_ekiyle_ayni": abi_eki,
        "ad_orta_nokta_yazimiyla_ayni": orta_nokta, "ad_farkli": len(farkli),
        "farkli_ornek": farkli[:8],
        "sembolu_olmayan_pclntab_girisi": sum(1 for e in entries if e not in go_sym),
        "go_araliginda_pclntabda_olmayan_sembol": sum(1 for a in go_sym if lo <= a < hi and a not in es),
    }
    r["sembol_tablosu"] = gt
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ikili")
    ap.add_argument("--dilim")
    ap.add_argument("--cikti")
    ap.add_argument("--liste")
    a = ap.parse_args()
    r = say(a.ikili, a.dilim, a.liste)
    s = json.dumps(r, ensure_ascii=False, indent=1)
    if a.cikti:
        Path(a.cikti).write_text(s + "\n")
    print(s)


if __name__ == "__main__":
    main()
