# ÖK-5 ön kaydı (2026-11-20; ayar okumasından ve kör sayımdan ÖNCE commit'lendi)

Paket: OK5 (Dalga 0). Plan: `ozkod/PLAN.md` "ÖK-5". Ölçüm betiği: `scripts/measurement/ozkod_olc.py` (kurallar `scripts/arge/ozkod/`'dan içe aktarılır; sha256'lar betiğin içinde denetlenir). Bu belge commit'lendiğinde: kör tarafın hiçbir sayısı hesaplanmadı ve olgu önbelleği kurulmadı; ayar tarafında hiçbir kural ölçüsü okunmadı (ayar ürün koşuları sürüyordu); geliştirme setinde eşdeğerlik 10 / 10 tuttu (`OK5.md` §3). Tanımların kodu: `ozkod_olc.py` commit `06ef538`.

## 1. Planın metni (aynen)

> ÖK-5 ön kaydı. Nüfus: ÖK-V'nin "kör" tarafı. Kurallar: `scripts/arge/ozkod/ek_kurali.py` (sha256 7d02a6b5…), `oz_ad_ayrim.py` (ccc73f5c…), `oz_ad_uretici.py` (7ee4edfc…), değiştirilmeden. Geliştirme setinde ölçülen: K1 kâhin keşif %98,1, sınama %81,7; G1 keşif %93,8, sınama %79,7.
> - K1-a (kâhin çapa, norm eşitliği): havuz kesinliği ≥ %85 ve Wilson alt sınırı ≥ %80; ad sayısı ≥ 200; en az 5 pakette ≥ 10 ad. Beklentim %85–%95. **Tutarsa** ÖK-4b açılır. Wilson alt sınırı %70–%80 arasındaysa K1 yalnız "ek yüzey biçimi + tablo türü" kısıtlarıyla yeniden ön kayıtlanır; < %70 ise K1 ad kanalı olarak bırakılır (kanıt satırı kalır).
> - K1-b (erişim): nüfusun V ∪ C çiftli payı, paketlerin en az yarısında ≥ %5. Beklentim: kabuk, sunucu ve GTK programlarında var; kitaplıklarda değişken.
> - K1-c (çapa, kip A): ad sayısı küçük (beklenti: nüfusun < %2'si); kesinlik ≥ %90 (n ≥ 30 ise hükme girer).
> - G1-a (düz G1): kesinlik ≥ %85. Beklentim tutmaz (sınamada tutmadı).
> - G1-b (kapılı G1; kapı "ayar" tarafında dondurulur): kesinlik ≥ %90 ve Wilson alt sınırı ≥ %85; ad ≥ 50. **Tutarsa** ÖK-3 açılır.
> - Ö-a (sandviç, aralık ≤ 32): önek kesinliği ≥ %85. Geliştirme setinde 1 212 / 1 454 (%83,4). **Tutarsa** ÖK-6 açılır.
> - Tutmayan beklenti silinmez; eşikler ölçümden sonra değişmez.

## 2. Ek sayım (KARŞI İ-1 düzeltme 3; gönderim metni)

> Hedef setinde erişim — Ollama'nın Go dışı fonksiyonları, gösteri çıktısı salt okur: sayı raporlanır, eşik yok. (K1 / G1 / R1'in erişimi: kayıt çifti olan fonksiyon payı; `~/karadul_olcum/runs/gosteri-2026-11-19/ollama/ws`.)

## 3. Uygulama tanımları (planın eşiklerini değiştirmez; yalnız sayımın nasıl yapılacağını sabitler)

1. **Nüfus ve birim.** Birim = paket (`debian/<paket>`). Kör tarafta ölçülecek ELF'i olan 14 paket, 76 ELF (`NUFUS.md` §7; geany C++ olduğu için ölçü dışı). Ürün: sabit ağaç `b6aceb9` (1.24.1), bayraklar öntanımlı (ÖK-V adım 5). Zaman aşımına uğrayan (3 600 sn), hata veren ya da GT / ofset kanıtı kurulamayan ELF ölçüme girmez; taraf başına ayrı sayılır ve hükümle birlikte yazılır. "Nüfus" = `ks1_olc.GtBirimi.nufus` (ad bekleyen: GT'li, Ghidra'da adsız, CRT / ihraç / klon değil).
2. **Havuz kesinliği** = kör paketlerin toplam doğrusu / toplam adı (örnek düzeyi). Wilson %95: `ks1_olc.oran`.
3. **K1-a**: `ek_kurali.olc` (kâhin çapa; `MIN_DESTEK` = 2, `MIN_ORAN` = 0,5; norm eşitliği `kayit_cifti.gt_esit`). "Ad sayısı" = `kahin_ad` (havuz), "en az 5 pakette ≥ 10 ad" = `kahin_ad` ≥ 10 olan paket sayısı. Karar kolları planın metnindeki gibidir; planın üç kolunun dışında kalan durum (kesinlik ve Wilson şartı tutar, hacim şartı tutmaz) "tutmadı; ÖK-4b kapalı kalır, yeniden ön kayıt ana oturumun kararı" diye yazılır.
4. **K1-b**: `kayit_cifti.say` (`VC_var` / `nufus`). Payda: nüfusu > 0 olan kör paketler. "En az yarısı": eşiği geçen paket sayısı ≥ paket sayısının yarısı.
5. **K1-c**: çapa kaynağı kip A (`ek_kurali_capa.py` "A on_ad+ks1"): ürünün `on_ad:*` ve `ks1:*` adları + Ghidra'nın jenerik olmayan adları; hedef: nüfusta, kip A'da çapa adı olmayan fonksiyon. "Nüfus payı" = ad / nüfus. Ad < 30 ise kesinlik hükme girmez ("hükme girmedi" yazılır); "nüfusun < %2'si" beklentisi ayrıca yazılır.
6. **G1-a / G1-b**: `oz_ad_uretici.g1`; hüküm `ks1_olc.capa_degerlendir` (tam eşitlik), yalnız nüfustaki adlar. Kapı ikili düzeyindedir; tanımı PLAN ÖK-5 adım 4 (a): ikilinin `reconstructed/kesin_capalar.json`'ında KS-1 çapası ≥ 1 ya da `__assert_fail` / `__assert_rtn` içe aktarımı (`ozkod_olc.g1_kapisi`). Ayar tarafında hesaplanır, kayda geçer ve **aynen** dondurulur (seçenek yok: ayar okuması yalnız kapının hesaplanabildiğini ve ayar tarafındaki davranışını kayda geçirir). Kapılı G1'in ayar tarafında düz G1'den kötü çıkması bulgu olarak yazılır; kapı değişmez.
7. **Ö-a**: `tavan.py` sandviç (bugünkü adlar = Ghidra'nın jenerik olmayan adları + ürün adları), aralık ≤ 32; havuz (`sinama|hepsi`).
8. **Körlük ve taraf ayrımı.** Kör sayım yalnız kör birimleri görünür kılarak yapılır (`ozkod_olc.etkin`: ayar birim listesi boş). Ayar okuması yalnız ayar birimleriyle ve yalnız iki şey: G1 kapısı (yukarıda) ve K1 karakter eki (aşağıda).

## 4. K1 karakter eki (ÖK-7 A): ayarda dondurma kuralı (okumadan önce)

- K1'in kararı (hangi fonksiyona ad verileceği) **değişmez**: norm kararı `ek_kurali.tahmin`. Yalnız yazım çapadan öğrenilir (`ozkod_olc.karakter_adi`): kazanan norm ekini destekleyen her çapa adında dizginin bir dönüşümünün tek geçtiği yer aranır; önek ve sonek çapanın harfleriyle alınır (norm biçimi ekle tutarlı olmalı); hedefin aday karakter adı çapa oylarıyla seçilir (en az 2 oy, ikinciden fazla). Öğrenilemezse norm adı yazılır.
- Aday dönüşümler (öncelik sırası; `ozkod_olc.DONUSUM_ADAYLARI`): `aynen`, `alt_cizgi`, `bitisik`, `kucuk_alt_cizgi`, `kucuk_bitisik`, `deve`, `pascal`, `buyuk_alt_cizgi`.
- **Dondurma kuralı:** ayar tarafında kâhin çapayla, kullanıldığı ad ≥ 5 ve o adlarda karakter doğruluğu < %50 olan dönüşüm listeden çıkarılır; kalanlar aynı sırayla dondurulur. Başka ayar yok.
- Kör tarafta karakter eşitliği hüküm dışıdır (eşik yok); ÖK-4b'nin H5'ine girdi olarak raporlanır.

## 5. Ek raporlama (hüküm yok, eşik yok)

- KARARLAR A-14: K1-a ve G1'in tekil düzeyi (kaynak grubu + GT adı başına bir öğe; `NUFUS.md` §2 grupları). KARŞI İ-7: program (kaynak grubu) düzeyinde kesinlik ve makro ortalama.
- K1: karakter / norm / ayraçsız eşitlik, belirteç kesinliği ve duyarlılığı (`ek_kurali_belirtec.py` tanımları); kip C (A + düz G1), kip C-kapılı (A + kapılı G1), kip D (ürünün bütün adları); çapa benzetimi (`ek_kurali.olc`).
- R1 + harf koruma (kör tarafta `oz_ad` adı varsa): `oz_ad_ayrim.kural_tut`, kanıt harfleriyle hüküm (`oz_ad_harf.py` tanımı). PLAN ÖK-2 "Ürüne girişi" şartı (R1 kesinliği ≥ %90) bilgi olarak yanına yazılır.
- Sandviç aralık sınırsız; ayrıca paket başına bütün sayılar.
- Ürün koşusunun taraf başına durumu: koşulan / tamam / kısmi / zaman aşımı / hatalı ELF, GT kurulamayan ELF.
