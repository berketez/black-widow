# N1 adım 3: ürün adlarının GT'ye karşı ölçümü — sonuç

- **Tarih:** 2026-11-11.
- **Ön kayıt:** `urun_olcumu_onkayit.md` (commit 1e3a5b2; yeni kol okunmadan önce). Sapma yok.
- **Ölçülen ürün:** commit 93a2956 (`karadul` 1.21.1; kanıtlı adlandırma öntanımlı açık).
- **Nüfus:** geliştirme seti; 8 açık kaynak program, 10 birim, 119 ikili (ölçüye giren 118). Hüküm tam eşitlik.
- **Çıktılar:** `urun_olcumu_yeni.json` / `.md` (yeni kol), `urun_olcumu_fark.json` / `.md` (karşılaştırma), `kol_butunlugu.json` (GT'siz zemin denetimi).
- Bu belgede fonksiyon adı geçmez. **[hesap]** işaretli sayılar çıktıdaki sayılardan aritmetiktir, ölçüm değildir.

## 1. Sonuç

| | Eski ürün (taban) | Yeni ürün |
|---|---|---|
| Ad verilen fonksiyon | 6 394 | 2 270 |
| Doğru (tam ad) | 1 185 | 1 363 |
| Yanlış | 5 209 | 907 |
| Yanlış ad oranı, havuz | %81,5 | %40,0 (Wilson %38,0-%42,0) |
| Yanlış ad oranı, program düzeyi makro | %92,2 | %60,8 |
| Kapsam (ad bekleyen 21 371 fonksiyonda ad verilen) | %25,2 | %8,3 |
| Tam ad kapsamı (doğru ad verilen) | 945 (%4,4) | 1 120 (%5,2) |
| "kesin" etiketli ad | yok | 262; doğru 249 (%95,0; makro %97,3) |

- Giderilen yanlış ad 4 304; yeni yanlış 2. Kaybedilen doğru ad 16; kazanılan doğru ad 194.
- Ürün daha az ad veriyor ama daha çok doğru ad veriyor: doğru ad sayısı 1 185 → 1 363.
- Mac htop'ta yeni ürün hiç fonksiyon adı vermiyor (tabanda 101 ad, 0 doğru).

## 2. Önceden yazılmış kararlar

| Karar | Ölçü | Eşik | Sonuç | Beklenti (ölçümden önce) |
|---|---|---|---|---|
| (a) yanlış ad oranı | makro %60,8 | ≤ %10 | `tutmuyor` | Tutmaması bekleniyordu (H3) |
| (a) yön koşulu | 7 birimin 7'sinde tabandan düşük | her birimde düşük | tuttu | Tutması bekleniyordu (H2) |
| (b) "kesin" etiketli adların kesinliği | makro %97,3 (openssl %100, tmux %94,6) | ≥ %95 | `tutuyor` | Tutması bekleniyordu, sınırda (H1) |
| (c) kaybedilen doğru ad | 16 / 1 185 (%1,4); sınırı aşan birim yok | > %15 → incele | `beklenen_aralikta` | Tutması bekleniyordu (H4) |

- **Dal (ön kayıt §7 d):** dal 4, yani beklenen durum. Derleme yapılabilir; adlar etiketleriyle gösterilir. Sürüm notunda ve arayüzde "ürün yanlış ad vermiyor" DENMEZ. Yazılabilecek iddia: "kesin" etiketli adların ölçülen kesinliği (geliştirme setinde %95,0; makro %97,3) ve kapsamı (ad bekleyenlerin %1,2'si). "doğrulanmadı" adlar için ölçülen tam ad kesinliği sayıyla yazılır: %55,5 (havuz), makro %30,5.
- (b)'de Wilson ihlali yok (giren üç birimde üst sınır ≥ %95). Debian tmux tek başına 91/97 (%93,8).
- **Adım 2 ile fark (ön kayıt §7 b):** yok. Üründeki "kesin" adlar 262, doğru 249; KS-1 adım 2'nin `func_kalibi` satırı da 249/262 idi.
- (a) rubrikli (gevşek) yanlış oranı hakkında bir şey söylemez; o ölçüm N2'dedir.

## 3. Yanlış adlar nereden geliyor

| Kanal | Ad | Doğru | Yanlış | Etiket |
|---|---|---|---|---|
| `on_ad:gnulib` | 852 | 621 | 231 | doğrulanmadı |
| `on_ad:elf_onyuk` | 458 | 232 | 226 | doğrulanmadı |
| `ks1:func_kalibi` (+ `func_aktarma` ile 3) | 262 | 249 | 13 | kesin |
| `string_context/kebap_ad` | 239 | 0 | 239 | doğrulanmadı |
| `string_context/oz_ad` | 224 | 112 | 112 | doğrulanmadı |
| `on_ad:main_giris` | 110 | 110 | 0 | doğrulanmadı |
| `api_param_reverse` | 85 | 1 | 84 | doğrulanmadı |
| `ks1:func_aktarma` | 33 | 33 | 0 | doğrulanmadı |
| `ks1:assert_ust` | 7 | 5 | 2 | doğrulanmadı |

907 yanlışın 780'i dört kanaldan: `kebap_ad` 239, `on_ad:gnulib` 231, `on_ad:elf_onyuk` 226, `api_param_reverse` 84 **[hesap]**.

**Bugün bilinenlerle ne kadarı giderilebilir (geliştirme setinde keşif; ölçüm değil) [hesap]:**
1. ELF önyük adları 1.21.2'de temizlenmeden yazılıyor (commit 4b5e940). Bu kanalın 226 yanlışının hepsi temizleyiciden geliyordu (`kalan_kanal_dokumu.md`); düzelince 458/458 beklenir. Yanlış 907 → 681, doğru 1 363 → 1 589; yanlış oranı %30,0.
2. `xstrtol_error` parmak izi çıkarıldı (204f5c4): 9 yanlış ad düşer. Yanlış 672 / 2 261: %29,7.
3. `kebap_ad` ve `api_param_reverse` susarsa (karar Berke'de): 324 ad düşer (323 yanlış, 1 doğru). Yanlış 349 / 1 937: %18,0.
4. Derlemeye bağlı üç gnulib girdisi (`version_etc`, `hard_locale`, `full_write`; LTO'suz Debian'da 219 yanlış) çözülürse: yanlış 130 / 1 718: %7,6.

Bu dört adım tam eşitlikle havuzdaki yanlış oranını %10'un altına indirebilir görünüyor; makro oran ayrıca ölçülmeli ve her adım aynı sette bulunduğu için taze veride sınanmalıdır. 3. adım "gevşek mod" kararıyla çelişebilir: `kebap_ad` rubrikli ölçümde %10,8 yanlıştı (N0b), tam eşitlikte %100.

## 4. Bütünlük koşulları (ön kayıt §7; GT'siz)

| # | Koşul | Sonuç |
|---|---|---|
| B1 | 119 ikili bitti, sorun yok; `--eksik-izinli` kullanılmadı | tuttu (koşucu: 118 + 1 tamam, 0 bitmeyen) |
| B2 | Kol kimliği 118 ikilide aynı: susturma açık, genel eşik 0,7 | tuttu |
| B3 | Susan grupta ad yok | tuttu (kanal grubu tablosunda yalnız `kalan`) |
| B4 | Alt kanal kaydı sınıflayıcıyla aynı; sonradan sınıflanan 0 | tuttu (463 `string_context` kaydının 463'ü kayıttan; başka sayaç yok) |
| B5 | "kesin" etiketli her adın kanalı `ks1:` ile başlıyor ve `func_kalibi` içeriyor | tuttu (259 + 3) |
| B6 | İki kol aynı dosyaları ölçtü; Ghidra sürümleri aynı | tuttu (eşleme sorunu yok) |

**Ek denetimler (ön kayıtta yoktu; hepsi GT okunmadan önce yapıldı):**
- **Sabitlenen dosyalar:** ön kayıttaki 12 özetin 12'si ölçümden hemen önce yeniden hesaplandı, hepsi aynı.
- **Ürün ağacı:** koşu boyunca commit ve kirli dosya listesi değişmedi (`kosu_kunyesi.json`: `agac_degisti` false). Koşu 08:09-09:39.
- **Ghidra zemini iki kolda aynı** (`kol_butunlugu.py`): 119 ikilide fonksiyon sayısı 66 983 = 66 983, adres kümeleri aynı, derleme başarısızı 0 = 0. Yeni kol makine yükü altında koşuldu (yük ortalaması 5-21); Ghidra'nın fonksiyon başına 30 sn'lik derleme sınırına takılan fonksiyon yok.
- **Geçersiz kılma deposu** (`~/.karadul/overrides`) koşu sırasında ve sonunda boştu (0 dosya). Koşucu bu depoyu kapatmıyor; dolu olsaydı elle verilen adlar ölçüme girerdi (`docs/arge/2026-11-11_karadullm/onuncu_adam.md` R1).
- **BSim:** paralel koşuda ortak BSim veritabanı kilitli olduğu için bazı ikililer hafif kipe düştü (taban kol da 3 paralel koşulmuştu). Ölçülen ad haritasında BSim kaynaklı kanal yok (§3 tablosu bütün kanalları sayıyor).

## 5. Sınırlar

- Geliştirme seti. KS-1 kuralları ve susturma kararı bu programlarda kuruldu; buradaki kesinlik bağımsız bir sınama değildir (Kapı 1 ve Kapı 2).
- Tam eşitlik katıdır: yakın ad, doğru tarif ve yalnız alan adı yanlış sayılır. Proje normalleştirmesiyle doğru 1 592 / 2 270 (%70,1); karar dışı.
- "kesin" kanıtı iki programa dayanıyor (tmux, openssl).
- Ölçülen harita ilk yinelemeninkidir; temiz çıktının son yineleme haritasıyla farkı bu ölçümde görünmez.
- Öbür sınırlar ön kayıt taslağı §9'da.

## 6. Yapılmayanlar

- Çıktı sağlamlığı denetiminin (`docs/arge/2026-11-10_cikti_saglamligi/denetle.py`) yeni koşuda yinelenmesi.
- 1.21.2 ile (ön ad onarımı) yeniden koşu ve ölçüm; §3'teki sayılar o koşuyla sınanmalı.
- Rubrikli (kör etiketli) yanlış oranı (N2).

## 7. Komutlar

```
python scripts/measurement/urun_kos.py --agac ~/karadul_olcum/urun-93a2956 --kok ~/karadul_olcum/runs/urun-yeni-93a2956 --paralel 3
python3 docs/arge/2026-11-10_n1_adim3/kol_butunlugu.py --taban-debian ~/karadul_olcum/n1_debian13 \
    --taban-mac workspaces/olcum_mac/runs/ol7-c-b7faeac --yeni ~/karadul_olcum/runs/urun-yeni-93a2956 \
    --json docs/arge/2026-11-10_n1_adim3/kol_butunlugu.json
python scripts/measurement/urun_olc.py olc --kok-debian <kök>/debian --kok-mac <kök>/mac --kol yeni --json … --md …
python scripts/measurement/urun_olc.py karsilastir --taban urun_olcumu_taban_ol7c.json --yeni urun_olcumu_yeni.json --json … --md …
```

Ölçüm ana ağaçtan koşuldu (HEAD 07c3f86); ölçüm betiğinin içe aktardığı ürün dosyaları (`alt_kanal.py`, `naming_labels.py`) ön kayıttaki özetlerdeydi.
