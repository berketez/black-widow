"""BULGULAR.md tabloları: veri dizinindeki JSON çıktılarından markdown üretir (sayıların tek kaynağı).

Kullanım:
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ustveri/tablo.py [veri kökü]
Öntanımlı veri kökü: ~/karadul_olcum/runs/arge-2026-11-19/ustveri
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


def wilson(k: int, n: int, z: float = 1.959964):
    """Wilson %95 aralığı; altı basamak (butce.wilson ile aynı formül, daha ince yuvarlama)."""
    if n == 0:
        return None
    ph = k / n
    payda = 1 + z * z / n
    orta = (ph + z * z / (2 * n)) / payda
    yari = z * ((ph * (1 - ph) / n + z * z / (4 * n * n)) ** 0.5) / payda
    return [round(max(0.0, orta - yari), 6), round(min(1.0, orta + yari), 6)]


def s(n):
    """Binlik ayraçlı sayı (dar boşluk yerine normal boşluk)."""
    return f"{n:,}".replace(",", " ") if isinstance(n, int) else str(n)


def yuzde(k, n):
    if not n:
        return "—"
    w = wilson(k, n)
    # Yuvarlama %100,0 ya da %0,0 gibi yanıltıcı uç değer üretmesin: uçlara yakınsa üç basamak.
    uc = [100 * k / n, 100 * w[0], 100 * w[1]]
    b = 1 if all(x in (0.0, 100.0) or 0.05 <= x <= 99.95 for x in uc) else 3
    return f"%{uc[0]:.{b}f} (%{uc[1]:.{b}f}–%{uc[2]:.{b}f})".replace(".", ",")


def oku(p):
    return json.loads(Path(p).read_text())


def main():
    V = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.home() / "karadul_olcum/runs/arge-2026-11-19/ustveri"

    print("### Envanter\n")
    print("| Hedef | Dilim | Boyut (bayt) | Kod (bayt) | Dil işareti | Go sürümü | Fonksiyon başlangıcı | Sembol | Kod sembollü başlangıç | Hata ayıklama sembolü |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    for k in oku(V / "envanter.json"):
        for d in k["dilimler"]:
            if d["kod_baytı"] < 1000:
                continue
            g = d.get("go") or {}
            print(f"| {Path(k['ikili']).name} | {d['dilim']} | {s(d['boyut'])} | {s(d['kod_baytı'])} | "
                  f"{', '.join(d['dil_isareti']) or 'C'} | {g.get('surum') or '—'} | "
                  f"{s(d['LC_FUNCTION_STARTS']) if d['LC_FUNCTION_STARTS'] is not None else 'yok'} | {s(d['sembol'])} | "
                  f"{s(d.get('baslangici_sembollu')) if d.get('baslangici_sembollu') is not None else '—'} | "
                  f"{s(d['hata_ayiklama_sembolu'])} |")

    print("\n### Go: sayım\n")
    print("| Hedef | Go | Giriş | Adlı | Dosya yolu olan | Ayrık dosya | Yalnız satır içi ad | Çalışma zamanı | Standart | Üçüncü taraf | Kendi | Derleyici | Paketsiz |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    sira = ["gh", "limactl", "Ollama.arm64", "Ollama.x86_64", "ollama-cli.arm64", "ollama-cli.x86_64", "colima",
            "docker-brew", "arduino-cli", "docker-cli", "docker-compose"]
    go = {}
    for ad in sira:
        r = oku(V / "go" / f"{ad}.json")
        go[ad] = r
        c = r["sayim"]
        sn = c["sinif"]
        print(f"| {ad} | {r['go_surumu'][2:]} | {s(c['fonksiyon_girisi'])} | {s(c['adli'])} | {s(c['dosya_yolu_olan'])} | "
              f"{s(c['ayrik_dosya_yolu'])} | {s(c['yalniz_satir_ici_ad'])} | {s(sn.get('calisma_zamani', 0))} | "
              f"{s(sn.get('standart', 0))} | {s(sn.get('ucuncu_taraf', 0))} | {s(sn.get('kendi', 0))} | "
              f"{s(sn.get('derleyici', 0))} | {s(sn.get('paketsiz', 0))} |")

    print("\n### Go: iç tutarlılık (ihlal sayıları)\n")
    print("| Hedef | Go | textStart (başlık) | K1 artan | K2 bölüm dışı | K4 pcsp: tam / dolguyla / kısa (asm) / kısa / taşan | K5 findfunctab uyumlu / alt kova | K6 girişlerin başlangıç olanı / Go aralığında tabloda olmayan | K7 bl hedefi: giriş / Duff içi / başka gövde içi | K8 özel funcID: runtime önekli / toplam |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    for ad in sira:
        r = go[ad]
        t = r["tutarlilik"]
        k4 = t["K4_pcsp_kapsama"]
        k5 = t["K5_findfunctab"]
        k6 = t["K6_function_starts"]
        k7 = t["K7_bl_hedefi"]
        k8 = t["K8_funcID_adi"]
        print(f"| {ad} | {r['go_surumu'][2:]} | {r['pclntab']['basliktaki_textStart']} | {t['K1_artan']['ihlal']} | "
              f"{t['K2_text_icinde']['bolum_disi']} | {s(k4['tam'])} / {s(k4['dolguyla'])} / {k4['kisa_asm']} / {k4['kisa']} / {k4['tasan']} | "
              f"{s(k5['uyumlu'])} / {s(k5['alt_kova'])} | "
              + (f"{s(k6['pclntab_girisi_baslangic_mi'])} / {s(k6['aralikta_pclntabda_olmayan'])}" if k6 else "başlangıç tablosu yok")
              + " | " + (f"{s(k7['hedef_giris'])} / {s(k7['hedef_duff_ici'])} / {k7['hedef_baska_govde_ici']}" if k7 else "ölçülmedi (x86_64)")
              + f" | {k8['runtime_onekli']} / {k8['ozel']} |")

    print("\n### Go: sembol tablosuyla karşılaştırma (sembollü ikililer)\n")
    print("| Hedef | Go | Giriş | Sembolü olan giriş | Ad birebir | `.abi0` ekiyle | Orta nokta yazımıyla | Farklı | Uyum |")
    print("|---|---|---|---|---|---|---|---|---|")
    for ad in ("docker-cli", "docker-compose"):
        r = go[ad]
        g = r["sembol_tablosu"]
        uy = g["ad_ayni"] + g["ad_abi_ekiyle_ayni"] + g["ad_orta_nokta_yazimiyla_ayni"]
        print(f"| {ad} | {r['go_surumu'][2:]} | {s(r['sayim']['fonksiyon_girisi'])} | {s(g['pclntab_girisinde_sembol'])} | "
              f"{s(g['ad_ayni'])} | {g['ad_abi_ekiyle_ayni']} | {g['ad_orta_nokta_yazimiyla_ayni']} | {g['ad_farkli']} | "
              f"{yuzde(uy, g['pclntab_girisinde_sembol'])} |")

    print("\n### Karadul'un var olan Go kodu\n")
    print("| Hedef | Hedef türü | `_extract_gopclntab` yöntemi | Ad | Adresli | Gerçek `pclntab` adı | Fonksiyon adı olmayan | K-4 Go kanalı: `nm` sembolü | `pclntab` girişine denk gelen / giriş |")
    print("|---|---|---|---|---|---|---|---|---|")
    for ad in ("gh", "limactl", "Ollama.arm64", "Ollama.evrensel", "ollama-cli.arm64", "colima", "docker-brew",
               "arduino-cli", "docker-cli", "docker-compose"):
        r = oku(V / "karadul_go" / f"{ad}.json")
        g = r["gopclntab"] or {}
        k = r["k4_go_kanali"]
        print(f"| {ad} | {r['hedef_turu']} | {g.get('yontem')} | {s(g.get('ad', 0))} | {s(g.get('adresli', 0))} | "
              f"{s(g.get('pclntab_adi_olan', 0))} | {s(g.get('pclntab_adi_olmayan', 0))} | {s(k['nm_sembolu'])} | "
              f"{k['pclntab_girisi_kapsami']} |")

    print("\n### Objective-C\n")
    print("| Hedef | Sınıf | Swift sınıfı | Kategori | Yöntem kaydı | Ayrık IMP | Fonksiyon başlangıcı olan | Arite uyan / uymayan | Protokol yöntemi | ObjC sembollü IMP | Ad aynı (birebir + kategori yazımı) | Farklı |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|")
    for ad in ("terminal-notifier", "iTerm2.arm64", "Ollama.arm64", "Ollama.x86_64", "limactl", "Rectangle.arm64"):
        r = oku(V / "objc" / f"{ad}.json")
        g = r["sembol_tablosu"]
        print(f"| {ad} | {s(r['sinif'])} | {s(r['swift_sinifi'])} | {r['kategori']} | {s(r['imp_li_kayit'])} | {s(r['ayrik_imp'])} | "
              f"{s(r['imp_fonksiyon_baslangici'])} | {s(r['arite']['uyan'])} / {r['arite']['uymayan']} | "
              f"{s(r['protokol_yontemi_olan_kayit'])} | {s(g['imp_sembollu'])} | "
              f"{s(g['ad_ayni'])} + {s(g['ad_kategori_yazimiyla_ayni'])} | {g['ad_farkli']} |")

    print("\n### Swift\n")
    print("| Hedef | Tip (sınıf / yapı / enum) | Erişim fonksiyonu | vtable betimleyicisi | Uygulaması boş | Ayrık uygulama (kodda) | Tanık kod göstericisi | Erişim: `Ma` ekli / sembollü | Tanık: `TW` ekli / sembollü | Swift sembollü kod adresi | Üst veriden ulaşılan |")
    print("|---|---|---|---|---|---|---|---|---|---|---|")
    for ad in ("Rectangle.arm64", "iTerm2.arm64"):
        r = oku(V / "swift" / f"{ad}.json")
        v = r["vtable"]
        g = r["sembol_tablosu"]
        t = r["tur"]
        print(f"| {ad} | {s(r['tip'])} ({s(t.get('sinif', 0))} / {s(t.get('yapi', 0))} / {s(t.get('enum', 0))}) | "
              f"{s(r['erisim_fonksiyonu'])} | {s(v['yontem_betimleyici'])} | {s(v['impl_bos'])} | {s(v['impl_kodda'])} | "
              f"{s(r['uyum']['tanik_kod_gostericisi_ayrik'])} | {s(g['erisim_Ma_ekli'])} / {s(g['erisim_sembollu'])} | "
              f"{s(g['tanik_TW_ekli'])} / {s(g['tanik_sembollu'])} | {s(g['swift_sembollu_adres'])} | "
              f"{s(g['ust_veriden_ulasilan_swift_sembollu_adres'])} |")

    print("\n### C++ RTTI\n")
    print("| Hedef | typeinfo (sınıf adı) | vtable | Yuva | İçe aktarım yuvası | Ayrık işlev | Çok sınıfta görünen | `__ZTI` aynı / sembollü | `__ZTV` aynı / sembollü | Yuva işlevi: kendi sınıf / taban / başka / sembollü |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    for ad in ("btop", "iTerm2.arm64", "llama-server.arm64", "Ollama.arm64", "Ollama.x86_64"):
        r = oku(V / "rtti" / f"{ad}.json")
        g = r["sembol_tablosu"]
        y = g.get("yuva_islevi") or {}
        print(f"| {ad} | {s(r['typeinfo'])} | {s(r['vtable'])} | {s(r['yuva'])} | {s(r['ice_aktarim_yuvasi'])} | "
              f"{s(r['ayrik_islev'])} | {r['cok_sinifta_gorunen_islev']} | "
              f"{s(g.get('typeinfo_adi_ayni', 0))} / {s(g.get('typeinfo_sembollu', 0))} | "
              f"{s(g.get('vtable_adi_ayni', 0))} / {s(g.get('birincil_vtable_sembollu', 0))} | "
              + (f"{s(y['sinifin_kendi_adi'])} / {y['taban_sinif_adi']} / {y['baska']} / {s(y['sembollu'])}" if y else "—") + " |")
    print("\nKaradul `cpp_rtti.CppRttiAnalyzer` (aynı ikililer):\n")
    print("| Hedef | Sınıf | vtable'ı olan | Yöntem |")
    print("|---|---|---|---|")
    for satir in (V / "rtti" / "karadul_cpp_rtti.jsonl").read_text().splitlines():
        r = json.loads(satir)
        print(f"| {Path(r['ikili']).name} | {s(r.get('sinif', 0))} | {s(r.get('vtable_olan', 0))} | {s(r.get('yontem', 0))} |")

    print("\n### Mach-O `main` (I2)\n")
    print("| İkili | `LC_MAIN` girişi = GT `_main` | Ghidra'nın o adresteki adı | Ürünün `main` verdiği fonksiyon | `main_recovered` | `__libc_start_main` geçen dosya |")
    print("|---|---|---|---|---|---|")
    gt = oku(V / "main" / "gt.json")
    for r in gt:
        print(f"| {r['ikili']} | {'evet' if r['giris_gt_main_mi'] else 'hayır'} | {r.get('ghidra_giristeki_ad')}"
              f"{' (thunk)' if r.get('ghidra_giris_thunk') else ''} | {len(r.get('urun_main_verilen') or [])} | "
              f"{r.get('main_recovered')} | {r.get('libc_start_main_gecen_dosya')} |")
    k = sum(1 for r in gt if r["giris_gt_main_mi"])
    print(f"\nToplam: {k} / {len(gt)}; {yuzde(k, len(gt))}.")
    nf = oku(V / "main" / "nufus_homebrew.json")["sayim"]
    print(f"\nHomebrew nüfusu: çalıştırılabilir {s(nf['calistirilabilir'])}; `_main` sembollü {s(nf['main_sembollu'])}; "
          f"giriş = `_main` {s(nf['giris_main'])} ({yuzde(nf['giris_main'], nf['main_sembollu'])}); "
          f"`_main` sembolü olmayan {nf['main_sembolu_yok']} (Go {nf.get('main_sembolu_yok_go', 0)}).")


    print("\n### Kanal kesinliği (sembollü ikililerde, sembol tablosuna karşı)\n")
    print("| Kanal | Doğrulayıcı ikililer | Doğru / sembolü olan | Kesinlik (Wilson %95) | Wilson alt sınırı ≥ 0,909 (A-2) |")
    print("|---|---|---|---|---|")

    def satir(ad, ikili, k, n):
        w = wilson(k, n)
        print(f"| {ad} | {ikili} | {s(k)} / {s(n)} | {yuzde(k, n)} | {'evet' if w and w[0] >= 0.909 else 'hayır'} ({str(w[0]).replace('.', ',')}) |")

    gk = gn = 0
    for ad in ("docker-cli", "docker-compose"):
        g = go[ad]["sembol_tablosu"]
        # adı boş olan tek giriş (runtime.text başlangıcı) kanalın ad vermediği giriştir: paydadan düşülür
        gn += g["pclntab_girisinde_sembol"] - 1
        gk += g["ad_ayni"] + g["ad_abi_ekiyle_ayni"] + g["ad_orta_nokta_yazimiyla_ayni"]
    satir("Go `pclntab` adı (yazım kuralları dahil)", "docker-cli 1.24.4, docker-compose 1.23.8", gk, gn)
    ok = on = 0
    for ad in ("terminal-notifier", "iTerm2.arm64"):
        g = oku(V / "objc" / f"{ad}.json")["sembol_tablosu"]
        ok += g["ad_ayni"] + g["ad_kategori_yazimiyla_ayni"]
        on += g["imp_sembollu"]
    satir("ObjC yöntem listesi (`±[Sınıf seçici]`)", "terminal-notifier, iTerm2 arm64", ok, on)
    sw = oku(V / "swift" / "iTerm2.arm64.json")["sembol_tablosu"]
    satir("Swift erişim fonksiyonu (tür: sembol `Ma` ekli)", "iTerm2 arm64", sw["erisim_Ma_ekli"], sw["erisim_sembollu"])
    sa = oku(V / "swift" / "iTerm2.arm64.ad.json")
    satir("Swift tip adı, nitelikli ad tam eşit (bugünkü araştırma okuyucusu)", "iTerm2 arm64", sa["ad_tam_ayni"], sa["sembollu"])
    tk = tn = vk = vn = yk = yn = 0
    for ad in ("btop", "iTerm2.arm64", "llama-server.arm64", "Ollama.x86_64"):
        g = oku(V / "rtti" / f"{ad}.json")["sembol_tablosu"]
        tk += g.get("typeinfo_adi_ayni", 0)
        tn += g.get("typeinfo_sembollu", 0)
        vk += g.get("vtable_adi_ayni", 0)
        vn += g.get("birincil_vtable_sembollu", 0)
        y = g.get("yuva_islevi")
        if y:
            yk += y["sinifin_kendi_adi"] + y["taban_sinif_adi"]
            yn += y["sembollu"]
    satir("C++ typeinfo sınıf adı", "btop, iTerm2, llama-server arm64, Ollama x86_64", tk, tn)
    satir("C++ vtable ↔ sınıf adı", "btop, iTerm2, llama-server arm64", vk, vn)
    satir("C++ yuva işlevi sınıfa (ya da tabanına) ait", "btop, iTerm2, llama-server arm64", yk, yn)
    gt8 = oku(V / "main" / "gt.json")
    satir("Mach-O `LC_MAIN` girişi = `main` (GT'li)", "htop, tmux + P-S3b kabul seti (6)", sum(1 for r in gt8 if r["giris_gt_main_mi"]), len(gt8))
    nf2 = oku(V / "main" / "nufus_homebrew.json")["sayim"]
    satir("Mach-O `LC_MAIN` girişi = `_main` sembolü", "Homebrew çalıştırılabilirleri", nf2["giris_main"], nf2["main_sembollu"])

    print("\n### Düşman girdi deneyi (I4)\n")
    print("| İkili | Tür | Bozulan | İkinci kaynaklı | Güçlü denetim yakaladı | İkinci kaynaklıda | İkinci kaynaksızda | Yalnız T4 | K4 | Hiçbiri | Bozulmayanda yeni işaret |")
    print("|---|---|---|---|---|---|---|---|---|---|---|")
    for ad in ("gh", "limactl"):
        r = oku(V / "dusman" / f"{ad}.deney.json")
        for tur in ("A_son_bilesen", "B_paketler_arasi_takas", "C_paket_ici_takas", "D_tutarli_sahtecilik",
                    "E_yapisal_takas"):
            x = r[tur]
            print(f"| {ad} | {tur} | {x['bozulan']} | {x['ikinci_kaynakli_bozulan']} | "
                  f"{x['guclu_denetim_yakaladi']} ({yuzde(x['guclu_denetim_yakaladi'], x['bozulan'])}) | "
                  f"{x['ikinci_kaynaklida_yakalanan']} | {x['ikinci_kaynaksizda_yakalanan']} | {x['yalniz_T4_yakaladi']} | "
                  f"{x['K4_yakaladi']} | {x['hicbiri_yakalamadi']} | {x['bozulmayanda_yeni_guclu_isaret']} |")
    print("\nBozulmamış ikilide denetimler (taban):\n")
    print("| İkili | Fonksiyon | T1 uyan / bakılan | T2 uyan / bakılan | T2 paket uyan / bakılan | T3 uyan / bakılan | T4 uyan / bakılan | T5 | İkinci kaynaklı fonksiyon |")
    print("|---|---|---|---|---|---|---|---|---|")
    for ad in ("gh", "limactl"):
        r = oku(V / "dusman" / f"{ad}_taban.json")
        print(f"| {ad} | {s(r['fonksiyon'])} | {s(r['T1']['uyan'])} / {s(r['T1']['bakilan_yuva'])} | "
              f"{s(r['T2']['uyan'])} / {s(r['T2']['bakilan'])} | {s(r['T2']['paket_uyan'])} / {s(r['T2']['paket_bakilan'])} | "
              f"{s(r['T3']['uyan'])} / {s(r['T3']['bakilan'])} | {s(r['T4']['uyan'])} / {s(r['T4']['bakilan'])} | "
              f"{r['T5']['uyan']} / {r['T5']['bakilan']} | {s(r['cift_kaynakli_fonksiyon'])} "
              f"({yuzde(r['cift_kaynakli_fonksiyon'], r['fonksiyon'])}) |")

    print("\n### Bütçe\n")
    print("| Hedef | Fonksiyon | Go adı | ObjC yöntemi | Swift erişim | **Üst veriden kesin** | Tip + yuva (ad yok) | Sembol tablosunda (soyulmuş hâliyle) | Kesin ∪ sembol | **Kalan** | Kalanın yuvalısı |")
    print("|---|---|---|---|---|---|---|---|---|---|---|")
    for r in oku(V / "butce.json"):
        print(f"| {r['ad']} | {s(r['nufus'])} | {s(r['go_adi'])} | {s(r['objc_yontemi'])} | {s(r['swift_erisim'])} | "
              f"{s(r['kesin'])} ({yuzde(r['kesin'], r['nufus'])}) | {s(r['yuva'])} | {s(r['sembol'])} | "
              f"{s(r['kesin_veya_sembol'])} | {s(r['kalan'])} ({yuzde(r['kalan'], r['nufus'])}) | {s(r['kalanin_yuvalisi'])} |")
    print("\nGo ikililerinde Go dışı kod (C / C++ / ObjC) ve Go adlarının paket sınıfı:\n")
    print("| Hedef | Go dışı fonksiyon | ObjC'den kesin | Sembollü | Kalan | Go: kendi | Go: üçüncü taraf | Go: standart + çalışma zamanı | Go: derleyici + paketsiz |")
    print("|---|---|---|---|---|---|---|---|---|")
    for r in oku(V / "butce.json"):
        if "go_sinif" not in r:
            continue
        g = r["go_sinif"]
        print(f"| {r['ad']} | {s(r['go_disi_nufus'])} | {r['go_disi_kesin']} | {r['go_disi_sembol']} | {s(r['go_disi_kalan'])} | "
              f"{s(g.get('kendi', 0))} | {s(g.get('ucuncu_taraf', 0))} | {s(g.get('standart', 0) + g.get('calisma_zamani', 0))} | "
              f"{s(g.get('derleyici', 0) + g.get('paketsiz', 0))} |")


if __name__ == "__main__":
    main()
