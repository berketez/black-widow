# Birleşik ürün ölçümü (onarım sonrası, a62f15e) — sonuç

- **Tarih:** 2026-11-19.
- **Ön kayıt:** `on_kayit.md`. OLCUM dalında commit 17d8f63, main'de 7d548d1. GT karşılaştırmasından önce commit'lendi.
- **Kollar:**
  - taban `yeni2`: f30ac9a, 1.22.1, `urun-yeni2-f30ac9a`;
  - yeni `onarim`: a62f15e, 1.24.1, `urun-onarim-a62f15e`.
- **Koşu** (ana oturum, künyeden):
  - 2026-11-19 08:10:08 → 09:19:51, `urun_kos.py --paralel 3`, çıkış 0, 119 / 119 `tamam`;
  - `PYTHONHASHSEED=0`;
  - `KARADUL_CACHE_DIR=/Users/apple/karadul_olcum/runs/urun-onarim-a62f15e/cache` (ana oturumun beyanı; künyede alan yok, ön kayıt §9 kusur 3);
  - ağaçtaki `signatures.lmdb` → `~/karadul_olcum/sigdb/s2-20261118/signatures.lmdb` (şema 2, 9 092 473 ad).
  - Koşu ortak makinede yapıldı: aynı anda 5–7 ajan çalışıyordu (test, mutasyon, sıralı Ghidra koşuları).
- **Ölçümün koşulduğu ağaç:** `urun_olc`, `masum_kapi`, `saglamlik_denetle` ve `p05_olc` ürün ağacından (`~/karadul_olcum/urun-a62f15e/scripts/measurement/…`) koşuldu. `PYTHONPATH` bu ağaç, `PYTHONDONTWRITEBYTECODE=1` (ön kayıt §2.2).
- Bu belgede GT'den fonksiyon adı geçmez.

## 0. Özet

1. **Onarımlar ölçülen etkiyi 119 ikilide verdi.**
   - Yanlış ad 672 → 119: havuz %29,7 → %6,6; Wilson %5,5–%7,8.
   - Doğru ad 1 589 → 1 681.
   - Yeni yanlış 0.
   - Ön kayıtlı 16 beklentinin 14'ü tuttu. Nokta beklentisi 1 827 / 1 700 / 127 idi; ölçülen 1 800 / 1 681 / 119.
2. **Hedef (makro yanlış ≤ %10) tutmadı: %31,0.**
   - Kalan yanlışların 104 / 119'u tek kanaldan, `string_context/oz_ad`'dan (kesinlik %47,2).
   - Makroyu iki küçük birim taşıyor: zstd %83,6 ve sqlite3 %58,3.
   - Yanlışın geri kalanı KS-1 `func_kalibi` (13) ve `assert_ust` (2).
3. **Yeni kusur: 19 doğru ad kayboldu** (H8, H10 tutmadı).
   - Neden üç parçanın birleşimi:
     - GHIDRA-16'nın açtığı dizgi bağı;
     - `c_namer`'ın agresif dizgi eşleşmesinde erken dönüşü;
     - `agresif` alt kanalının susturulması.
   - Sonuç: klasik dizgi kuralı hiç koşmuyor. Ayrıntı §4.1.
4. **Masum kapı (çıktı kipi, 119) geçti.** Bileşim 451 → 0, `types.h` 117 → 0, YARA 70 → 0, istihbarat 1 965 → 455.
5. **gnulib ön ad kanalı 733 / 733.** Geliştirme seti içi; `MEASURED_PRE_NAME_PRECISION` önerisi 0,995.
6. **İki ölçüm aracı kusuru bulundu** (§11). Biri `sarif` izleyicisinde, öbürü sağlamlık denetiminin günlük ifadesinde.

## 1. Bütünlük denetimleri (B1–B9)

Sabitlenen 14 dosyanın sha256'sı ölçümden hemen önce yeniden hesaplandı. OLCUM worktree'sinde ve ürün ağacında 14 / 14 ön kayıttaki değerle **aynı**.

| # | Koşul | Sonuç |
|---|---|---|
| B1 | 119 dizin, anahtarlar tabanla aynı, `BITTI` = `0` × 119, künye `sonuclar` 119 `tamam`, `bitmeyen` boş | **tuttu**. Kısmi 0, `BITTI`'siz 0 (`butunluk.json`) |
| B2 | commit a62f15e…, kirli değil, `karadul` ağaçtan, 1.24.1, ağaç koşu boyunca değişmedi, `PYTHONHASHSEED` = 0 | **tuttu** |
| B3 | Girdi sha256'ları tabanla aynı | **tuttu** (119 / 119) |
| B4 | İmza VT künyesi: şema 2, 9 092 473 ad, `s2-b32ee9f65b1a-20261118`, `data_root:signatures.lmdb`, uyarı ve hata yok | **tuttu** (119 / 119) |
| B5 | Ghidra 12.1.2, `matches_pinned` | **tuttu** (119 / 119) |
| B6 | Ghidra zemini (`kol_butunlugu.json`): fonksiyon sayısı, adres kümesi, derleme sayaçları | **tuttu**. 119 / 119 aynı; fonksiyon 66 983 = 66 983, derlenen 66 983, başarısız 0, atlanan 0 (iki kolda) |
| B7 | Kol kimliği `{"genel_esik": 0.7, "koken_var": true, "susturma": true}` × 118 | **tuttu** |
| B8 | `~/.karadul/overrides` ölçüm anında boş | **tuttu**. Koşudan önceki durumu geriye dönük denetlenemez |
| B9 | `alt_kanal: uyuşmuyor` = 0, `koken_yok` 0 | **tuttu**. Uyuşmazlık 0 (her birimde); kanal kırılımında `koken_yok` yok |

İki kolun Ghidra zemini bayt düzeyinde aynı. Yük altındaki koşu Ghidra'da hiçbir fonksiyonu düşürmedi; aşağıdaki bütün farklar ürünün Ghidra sonrası katmanlarından geliyor.

## 2. Ana sonuç

| | yeni2 (1.22.1) | onarim (a62f15e) | Ön kayıt beklentisi |
|---|---|---|---|
| Ad verilen | 2 261 | **1 800** | 1 827 |
| Doğru | 1 589 (%70,3; %68,4–%72,1) | **1 681 (%93,4; %92,2–%94,5)** | 1 700 |
| Yanlış | 672 (%29,7; %27,9–%31,6) | **119 (%6,6; %5,5–%7,8)** | 127 (%7,0) |
| Program düzeyi makro yanlış | %52,8 | **%31,0** | %31,9 |
| Kapsam (nüfusta ad verilen / 21 371) | 1 764 (%8,3) | **1 315 (%6,2; %5,8–%6,5)** | 1 342 |
| Doğru ad kapsamı | 1 120 (%5,2) | **1 212 (%5,7; %5,4–%6,0)** | 1 231 |
| Makro kapsam / makro doğru ad kapsamı | %4,9 / %2,3 | **%3,3 / %2,4** | %3,4 / %2,4 |
| "kesin" etiketli doğru / ad | 249 / 262 (%95,0; %91,7–%97,1) | **249 / 262 (aynı)**; makro %97,3 | aynı |
| Karar (a) makro yanlış ≤ %10 | `tutmuyor` | **`tutmuyor`** (%31,0) | `tutmuyor` |
| Karar (b) "kesin" makro ≥ %95 | `tutuyor` | **`tutuyor`** (%97,3) | `tutuyor` |
| Karar (c) kayıp > %15 | — | **`beklenen_aralikta`**: 20 / 1 589 (%1,3; %0,8–%1,9) | `beklenen_aralikta` |
| Yön koşulu | — | **`beklenen_aralikta`**: 7 / 7 birimde düştü | 7 / 7 |

**Duyarlılık (karar dışı):**
- nüfus içi kesinlik 1 212 / 1 315 (%92,2);
- proje normalleştirmesiyle doğru 1 684 / 1 800 (%93,6);
- tekil adla kesinlik 422 / 535 (%78,9).

**Karar (d):** taslak §7 (d) tablosu.
- (b) tuttu, (a) tutmadı → derleme var, "yanlış ad vermiyor" iddiası yok.
- Havuzda yanlış oranı %6,6. Program düzeyi makroda %31,0: yanlışın çoğu iki küçük birimde (zstd %83,6; sqlite3 %58,3), ikisi de `string_context/oz_ad` kanalından.

**Birim başına (yeni2 → onarim; ad / doğru / yanlış):**

| Birim | yeni2 | onarim | Yanlış oranı | Beklenti (`beklenti.json`) |
|---|---|---|---|---|
| debian/coreutils (106) | 1 411 / 1 178 / 233 | 1 281 / 1 271 / 10 | %16,5 → %0,8 | 1 300 / 1 290 / 10 |
| debian/tmux | 295 / 148 / 147 | 166 / 148 / 18 | %49,8 → %10,8 | 167 / 148 / 19 |
| mac/tmux | 395 / 205 / 190 | 236 / 205 / 31 | %48,1 → %13,1 | 236 / 205 / 31 |
| debian/zstd (`pzstd` ölçü dışı) | 65 / 9 / 56 | 55 / 9 / 46 | %86,2 → %83,6 | 61 / 9 / 52 |
| debian/openssl | 35 / 24 / 11 | 26 / 23 / 3 | %31,4 → %11,5 | 27 / 23 / 4 |
| debian/redis-tools (4) | 29 / 12 / 17 | 15 / 12 / 3 | %58,6 → %20,0 | 15 / 12 / 3 |
| debian/sqlite3 | 20 / 5 / 15 | 12 / 5 / 7 | %75,0 → %58,3 | 12 / 5 / 7 |
| debian/htop | 6 / 3 / 3 | 4 / 3 / 1 | — (n < 10) | 4 / 3 / 1 |
| debian/tree | 5 / 5 / 0 | 5 / 5 / 0 | — | 5 / 5 / 0 |
| mac/htop | 0 / 0 / 0 | 0 / 0 / 0 | — | 0 |

## 3. Ön kayıtlı beklentiler (H1–H16)

| # | Ölçü | Eşik (ön kayıt §4.2) | Ölçülen | Hüküm |
|---|---|---|---|---|
| H1 | Havuz ad / doğru / yanlış | ad 1 780–1 880; doğru 1 650–1 750; yanlış 100–165 | 1 800 / 1 681 / 119 | **tuttu** |
| H2 | Havuz yanlış oranı | %5,5–%9,0 | %6,6 (%5,5–%7,8) | **tuttu** |
| H3 | Makro yanlış oranı; karar (a) | %25–%38; `tutmuyor` | %31,0; `tutmuyor` | **tuttu** |
| H4 | `on_ad:gnulib` | doğru ≥ 725, yanlış ≤ 2, ad ≤ 740 | 733 / 733 / 0 | **tuttu** |
| H5 | `string_context/kebap_ad` adı | = 0 | 0 | **tuttu** |
| H6 | `api_param_reverse` adı | = 0 | 0 | **tuttu** |
| H7 | Değişmez kanallar | `on_ad:*` tam aynı; KS-1 ±3 | `elf_onyuk` 458 / 458, `main_giris` 110 / 110; `ks1:func_kalibi` 259 / 246, `func_aktarma` 33 / 33, `func_kalibi+func_aktarma` 3 / 3, `assert_ust` 7 / 5 (hepsi aynı) | **tuttu** |
| H8 | `string_context/oz_ad` ad / doğru | ad 200–246, doğru 100–124 | **197 / 93** | **tutmadı** (§4.1) |
| H9 | "kesin" ad / doğru; karar (b) | ad 256–268; `tutuyor` | 262 / 249; `tutuyor` | **tuttu** |
| H10 | Kaybedilen doğru; karar (c) | ≤ 5; `beklenen_aralikta` | **20** (19 `oz_ad` + 1 `api_param_reverse`); karar (c) `beklenen_aralikta` | **tutmadı** (§4.1) |
| H11 | Kazanılan doğru | 105–120, en az %95'i `on_ad:gnulib` | 112, 112 / 112 `on_ad:gnulib` | **tuttu** |
| H12 | Giderilen yanlış / yeni yanlış | 520–560 / ≤ 10 | 553 / 0 | **tuttu** |
| H13 | Yön koşulu | `beklenen_aralikta` | `beklenen_aralikta` (zstd %86,2 → %83,6) | **tuttu** |
| H14 | Kapsam (havuz) | 1 300–1 390 | 1 315 | **tuttu** |
| H15 | Doğru ad kapsamı (havuz) | ≥ 1 200 | 1 212 | **tuttu** |
| H16 | Makro kapsam / makro doğru ad kapsamı | %3,4 ± 0,5 / %2,4 ± 0,5 | %3,3 / %2,4 | **tuttu** |

**Özet:** 16 beklentinin 14'ü tuttu, 2'si (H8, H10) tutmadı. İkisinin nedeni aynı (§4.1). Ölçüt, bant ve eşik değiştirilmedi. Sapma yok (§8).

## 4. Tutmayanların nedeni (ölçüm sonrası açıklama)

### 4.1 H8 ve H10: `string_context/oz_ad` 27 ad kaybetti, bunların 19'u doğruydu

**Ne oldu:**
- `oz_ad` 224 / 112 → 197 / 93: 27 ad gitti, 19 doğru + 8 yanlış.
- Kanal başka hiçbir anahtarda ad kazanmadı ya da değiştirmedi.
- 19 doğru kaybın 19'u coreutils'te, 18 ikiliye dağılmış. 8 yanlış kaybın yerleri: zstd 6, openssl 1, debian/tmux 1.
- Kaybedilen anahtarların hepsi yeni kolda adsız (`kaybedilen_silinen` 20, `yanlisa_donen` 0).

**Konum.** 19 doğru kaybın 19'unda şunlar birlikte görülüyor:
- tabanda ad c_namer'ın klasik dizgi kuralından geliyor (`code_path = classic`, `rule = keywords`);
- yeni kolda Faz 1 çıkarıcısı (`reconstructed/binary_names.json`) aynı anahtara aynı adı `string_intel` adayı olarak öneriyor;
- ad haritasında anahtarın adı yok, o ad başka bir anahtarda da yok.

**Mekanizma** (bir anahtarda kodla ve çıktıyla izlendi; öbür 18'i aynı imzayı taşıyor):
1. GHIDRA-16 (P13a'da alındı) dizgi → fonksiyon bağını açtı. İzlenen fonksiyona tabanda 0 dizgi bağlıydı, yeni kolda 7 (hata iletileri ve kaynak dosya yolu dahil; `static/ghidra_strings.json` `xrefs`).
2. `c_namer._strategy_string_context` artık bu bağlı dizgileri de tarıyor (`self._string_refs_by_func`). Bunlardan biri agresif kalıba uyuyor ve güveni ≥ 0,75 olunca strateji `return` ediyor; klasik anahtar sözcük aşamasına hiç geçilmiyor (`c_namer.py` "Agresif match bulduysa … Ama confidence zaten yuksekse atla").
3. Agresif aday, N0b susturmasında `agresif` alt kanalı olarak atılıyor. Faz 1'in aynı ada verdiği aday da AD-09 gereği `aggressive` kod yoluyla geliyor ve o da susuyor.
4. Anahtar adsız kalıyor.

**Düzeltme (P12d, 2026-11-19; ayrıntı `docs/arge/2026-11-18_onarim/P12d.md` Kalem 0):** 2. adım bu 27 anahtarda işlemiyor.
- 27 / 27'de agresif eşleşmenin en yüksek güveni 0,75'in altında (en çok 0,65); erken dönüş yok, klasik aşama koşuyor.
- Kayıp klasik aşamanın kanıt seçiminde. Eşit puanlı dizgilerden ilk görülen kanıt oluyor. GHIDRA-16'dan sonra dizgi bağları dizgi adresi sırasıyla yükleniyor; dosya yolu ya da hata iletisi, aynı puanı veren öz-ad dizgisinin önüne geçiyor ve aday susuyor.
- Doğruların 17 / 19'unda öz-ad dizgisi aynı adı veriyor; yanlışların 0 / 8'inde.
- 19 doğru kayıp 18 değil 16 ikiliye dağılmış (`kayip27.json`).

**Ölçek:** 119 ikilide susturulan `agresif` aday 1 495 → 2 824 (+1 329). Öbür alt kanallarda değişim küçük. `kebap_ad` 0 → 266 yeni bir satır: P12b'nin kanıt satırı adayları, beklenen.

**Neden önceden görülmedi:**
- P13a'nın GHIDRA-16 ölçümü 10 ikilide yapıldı. Coreutils'ten yalnız 4 ikili vardı (cat, expr, ls, sort) ve kaybın düştüğü 18 ikilinin hiçbiri yoktu.
- Ön kayıtta bu belirsizlik bantla yazılmıştı (V3, "en büyük belirsizlik GHIDRA-16"), ama yön ve büyüklük öngörülmedi.

**Yorum:**
- Bir K-2 kusuru: "susturma yok, düzelt" kararına aykırı olarak doğru ad üreten klasik kural, susturulan bir kuralın erken dönüşüyle bastırılıyor.
- Ürün onarımı ayrı, ön kayıtlı bir paket ister: erken dönüş, susturulan alt kanalı hesaba katmalı ya da klasik aşamayı her durumda koşmalı. Ölçüt: kaybedilen 19 doğru geri gelsin, 8 giden yanlış geri gelmesin.
- Kaybın büyüklüğü küçük (doğru adların %1,2'si), ama yönü önemli: analiste gösterilmeyen doğru ad.

## 5. Kanal kırılımı ve 1.22.1 → a62f15e farkı

**Kanal başına (havuz):**

| Kanal | yeni2 ad / doğru / yanlış | onarim ad / doğru / yanlış | Fark | Paket |
|---|---|---|---|---|
| `on_ad:gnulib` | 843 / 621 / 222 | 733 / 733 / 0 | +112 doğru, −222 yanlış | P-S3, P-S3b |
| `string_context/kebap_ad` | 239 / 0 / 239 | 0 | −239 yanlış | P12b |
| `api_param_reverse` | 85 / 1 / 84 | 0 | −84 yanlış, −1 doğru | P12a AD-02 |
| `string_context/oz_ad` | 224 / 112 / 112 | 197 / 93 / 104 | −19 doğru, −8 yanlış | GHIDRA-16 × c_namer erken dönüşü (§4.1) |
| `on_ad:elf_onyuk` | 458 / 458 / 0 | 458 / 458 / 0 | 0 | — |
| `on_ad:main_giris` | 110 / 110 / 0 | 110 / 110 / 0 | 0 | — |
| `ks1:func_kalibi` | 259 / 246 / 13 | 259 / 246 / 13 | 0 | — |
| `ks1:func_aktarma` | 33 / 33 / 0 | 33 / 33 / 0 | 0 | — |
| `ks1:func_kalibi+func_aktarma` | 3 / 3 / 0 | 3 / 3 / 0 | 0 | — |
| `ks1:assert_ust` | 7 / 5 / 2 | 7 / 5 / 2 | 0 | — |
| **Toplam** | 2 261 / 1 589 / 672 | 1 800 / 1 681 / 119 | +92 doğru net, −553 yanlış | |

**Öğe düzeyinde fark** (`urun_olcumu_fark_yeni2_onarim.md`; birim, ikili ve adresle eşleme; Ghidra sürümü aynı, eşleme sorunu yok):
- **Kazanılan doğru 112:** hepsi `on_ad:gnulib`, LTO'suz yerleşim iç adları.
- **Kaybedilen doğru 20:**
  - `string_context/oz_ad` 19 (coreutils);
  - `api_param_reverse` 1 (openssl; P12a'da ölçülmüş ve kabul edilmiş bedel).
- **Giderilen yanlış 553:**
  - coreutils 223;
  - mac/tmux 159;
  - debian/tmux 129;
  - redis-tools 14;
  - zstd 10;
  - openssl 8;
  - sqlite3 8;
  - debian/htop 2.
- **Yeni yanlış:** 0.
- **Yanlışa dönen doğru:** 0.

`MEASURED_PRE_NAME_PRECISION` önerisi için kanal başına ölçülmüş kesinlik §7'de.

## 6. Masum kapı, çıktı kipi (119 çıktı)

**Koşum:**
- `masum_kapi.py --agac ~/karadul_olcum/urun-a62f15e --kosu <yeni kök>`;
- karşılaştırma tabanı `P00/taban_cikti_urun_yeni2/masum_kapi.json` (1.22.1, 119);
- 78,9 sn;
- tam tablo `masum_kapi_cikti.md`; ham JSON `~/karadul_olcum/runs/onarim-2026-11-19/OLCUM/masum_cikti/`.

**K0 (kapı çıkış 0):** **tuttu**. Eşikli 14 ikilide hiçbir katman eşiği aşmadı. Zorunlu gerçek pozitifler yerinde.

| Katman | 1.22.1 (119): iddia / yanlış | a62f15e (119): iddia / yanlış / yanlışlı ikili | Ön kayıt beklentisi | Hüküm | Önerilen eşik (119) |
|---|---|---|---|---|---|
| `bilesim` | 451 / 451 | 0 / 0 / 0 | 0 | tuttu | 0 |
| `bilesim_yeniden` | 451 / 451 | 0 / 0 / 0 | 0 | tuttu | 0 |
| `blok_yorumu` | 112 / 112 | 1 / 1 / 1 (6 adet) | ≤ 1 | tuttu | 1 |
| `types_h` | 117 / 117 | 0 / 0 / 0 | 0 | tuttu | 0 |
| `yara_cikti` | 81 / 70 (`bilinmiyor` 88) | 12 / 0 / 0 (12 doğru bilinen; `calisti` 119) | yanlış 0; iddia ≈ 11; `bilinmiyor` 0 | tuttu | 0 |
| `antidebug_cikti` | 23 / 23 | 7 / 7 / 5 | 7 | tuttu | 7 |
| `packer_cikti` | 0 / 0 | 0 / 0 / 0 | 0 | tuttu | 0 |
| `intel` | 2 130 / 1 965 | 611 / 455 / 118 (156 doğru bilinen) | ≈ 455 (400–520) | tuttu | 455 |
| `security_etiketi` | 47 / 47; adet 4 327 | 47 / 47 / 13; adet 3 352 | adet ≈ 3 352; iddia: yön düşer | adet tuttu; **iddia yönü tutmadı** (47 → 47) | 47 |
| `algoritma_json` | 109 / 109 | 56 / 56 / 13 (178 adet) | yön düşer | tuttu | 56 |
| `algoritma_yeniden` | 109 / 109 | 56 / 56 / 13 | yön düşer | tuttu | 56 |
| `algoritma_kod` | 66 / 66 | 41 / 41 / 8 (84 adet) | yön düşer | tuttu | 41 |
| `sarif` | 81 / 81 | 12 / 12 / 8 | yön düşer | tuttu | 12 (aşağıdaki nota bakın) |

**`security_etiketi`:**
- İddia sayısı (ikili × etiket) 47'de kaldı, ama etiketlerin içeriği değişti. Çağrı kanıtı olmayanlar artık "By name only … (no call evidence)" diye ayrı etiket taşıyor: 26 iddia.
- Adet 4 327 → 3 352 (P06 TIP-08'in sayısıyla tam aynı).
- Kapı kanıt düzeyini ayırmadan sayıyor. Bu yüzden "yanlış" sütunu iddia içeriğindeki iyileşmeyi göstermiyor; kapının bir sınırı.

**`sarif` notu (araç kusuru adayı):**
- 12 yanlış iddianın etiketleri `KRDL001:OpenSSL_Library` 5, `KRDL007:*_Library` / `GCC_Compiler` 7. Bunlar `yara_cikti` katmanında "doğru bilinen" sayılan 12 kuralla aynı (OpenSSL 5, GCC 2, Zlib 2, Zstd 2, LZ4 1).
- Kapının `sarif` katmanı `dogru_iddialar` listesini P07'den sonra gelen KRDL001 / KRDL007 kodlarına uygulamıyor gibi görünüyor. Kapının kendisine bakılmadı.
- Eşik 12 yazılırsa doğru iddialar yanlış sayılmış olur. Öneri: önce izleyici düzeltilsin, sonra `sarif` eşiği ölçülen yanlışla yazılsın (beklenti 0).

**Eşik önerisi (ön kayıt §5.1; dosyaya YAZILMADI):**
- Üç koşulun üçü de tuttu:
  1. K0 tuttu;
  2. hiçbir katman 1.22.1 değerini aşmadı (`security_etiketi` eşit);
  3. sayısal beklentisi olan katmanlar üst ucun içinde.
- Bu yüzden ana oturum `masum_kapi.py --esik-yaz ~/karadul_olcum/runs/onarim-2026-11-19/OLCUM/masum_cikti/masum_kapi.json` ile 119 ikilinin eşiklerini yazabilir. Önerilen değerler yukarıdaki son sütunda.
- Tek istisna `sarif`: izleyici düzeltilene kadar 12 ile yazılması, doğru iddiaları "yanlış" diye kilitler.

### 6.1 Sağlamlık denetimi (119)

**Koşum:** `saglamlik_denetle.py --kok <yeni kök> --is 6`, ürün ağacından, 100,9 sn. Tablo `saglamlik.md`; ham JSON `…/OLCUM/saglamlik/`. Taban `P00/saglamlik_urun_yeni2.md`.

| Kusur | 1.22.1: ikili / toplam | a62f15e: ikili / toplam | Ön kayıt | Hüküm |
|---|---|---|---|---|
| `sayi:fonksiyon_sayisi` | 0 | 0 | 0 | tuttu |
| `decompiled_json_kirpik` | 21 / 25 640 | 0 | 0 | tuttu |
| `cift_tanim_adres` | 1 / 5 | 0 | 0 | tuttu |
| `bsim_yedege_dustu` | 78 / 78 | 0 | yön: düşer | tuttu |
| `sayi:log_kaynak_dosya`, `sayi:log_yazilan_dosya` | 1 / 1 | **119 / 119** | 0 | **tutmadı. Araç kusuru, ürün kusuru değil** (aşağıda) |
| `log_yazildi_satiri_yok` | 0 | **119 / 119** | — | araç kusuru (aynı neden) |
| `eski_fonksiyon_adi_yorumda_kalan` | 117 / 1 927 | 118 / 1 533 | yalnız yazılır | — |
| `fonksiyon_anahtari_ghidrada_yok` | 117 / 234 | 117 / 233 | yalnız yazılır | — |
| `yerel_ad_uygulanmamis_fonksiyon` | 116 / 2 458 | 3 / 7 | yalnız yazılır | — |
| `yerel_son_tur_baska_adla_fonksiyon` | 37 / 5 356 | 6 / 62 | yalnız yazılır | — |
| `yerel_ilk_tur_baska_adla_fonksiyon` | 34 / 122 | 5 / 5 | yalnız yazılır | — |
| `baslik_tanim_farkli` | 5 / 20 | 5 / 20 | yalnız yazılır | — |
| `yeni_ad_var_olan_fonksiyonla_cakisiyor` | 5 / 6 | 5 / 5 | yalnız yazılır | — |
| `eski_fonksiyon_adi_kodda_kalan` | 1 / 2 | 1 / 1 | yalnız yazılır | — |
| `turlar_arasi_fonksiyon_adi_farki` | 1 / 2 | 1 / 1 | yalnız yazılır | — |
| `out_proje_agacindan_farkli` | 1 / 1 | 0 | yalnız yazılır | — |

**Log satırı kusuru:**
- `saglamlik_denetle.py:608` ürünün analiz günlüğünde ASCII `"OK N dosya yazildi (…)"` satırını arıyor.
- P15b ürünün Türkçe metinlerini düzeltti; günlük artık `"OK 280 dosya yazıldı (275 kaynak, 2 rapor)"` yazıyor (`debian/tree/tree/kosu.log`). Taban günlüğünde `yazildi`.
- Bu yüzden 119 ikilinin 119'unda `log_yazildi_satiri_yok`, ve ondan türeyen iki `sayi:log_*` "kusuru" çıkıyor. Ürünün yazdığı dosya sayısı denetlenemedi.
- Onarım: düzenli ifade iki yazımı da kabul etmeli (ör. `yaz[iı]ld[iı]`). Ölçüt değiştirilmedi; ön kayıtlı satır "tutmadı" yazıldı.

### 6.2 Parametre adları (P05, P05b; ikincil)

**Koşum:**
- `p05_olc.py kos --hizalama ~/karadul_olcum/runs/t0b-1acba60/hizalama`, ürün ağacının betiği ve koduyla;
- yeni koşunun kayıtlı girdileri, 119 ikili, yaklaşık 2 dk;
- özet `~/karadul_olcum/runs/onarim-2026-11-19/OLCUM/p05/birlesik/ozet.json`.

| Ölçü | Ön kayıt (§5.3) | Ölçülen | Hüküm |
|---|---|---|---|
| Doğrulama: yeniden oynatılan ad haritası = kayıtlı | 119 / 119 aynı | 119 / 119 `ayni` | tuttu |
| Kusurlu ad (geçersiz / anahtar sözcük / tip / Ghidra biçimi / gövde çakışması) | 0 | 0 (7 471 / 7 471 geçerli) | tuttu |
| İşaretçiye skaler ad | 0 | 0 | tuttu |
| Tip sezgisinin kanıtsız `str` ailesi | 0 | 0 (`type_heuristic`: `char *` 141, kanıtlı 1) | tuttu |
| D (22 DWARF'lı ikili) doğru (tam + yakın) | 120–150 | **85** (41 + 44) | **tutmadı** |
| D yanlış | ≤ 5 287 | 3 004 | tuttu |

**Ölçüm sonrası açıklama** (hipotez; neden ölçülmedi):
- Toplam parametre adı 13 710'dan (P05b son kol, 1.22.1 girdileriyle yeniden oynatma) 7 471'e düştü (−%46).
- D'de hükümlü ad 5 100 → 3 089 oldu. Kesinlik aynı kaldı: P05b %2,7, burada 85 / 3 089 = %2,8.
- Yani kanalın doğruluğu değişmedi, hacmi azaldı.
- Olası neden: girdinin değişmesi. Adlandırıcının girdisi `struct_recovered/*.c`; P09 (Ghidra'nın somut tipini ezen tip yazımı kalktı), P10 ve P11 bu dosyalardaki parametre tiplerini değiştirdi, şablonlar tipe bağlı.
- Bakılmadı.

**Bilgi için** (ön kayıtta satırı yoktu): yayılım kanalında (`call_graph_propagation`) kanıtsız `str` 63.

## 7. Kanal başına ölçülmüş kesinlik → `MEASURED_PRE_NAME_PRECISION` önerisi (koda yazılmadı)

Değer biçimi (doğru, ad verilen, Wilson %95 alt sınırı; 3 basamak); `ks1_olc.oran` ile hesaplandı.

| Kanal | Bugünkü tablo (yeni2) | Bu ölçüm | Öneri |
|---|---|---|---|
| `on_ad:gnulib` | (621, 843, 0,706) | 733 / 733; Wilson %99,48–%100 | **(733, 733, 0,995)** |
| `on_ad:elf_onyuk` | (458, 458, 0,992) | 458 / 458; %99,17–%100 | (458, 458, 0,992), değişmez |
| `on_ad:main_giris` | (110, 110, 0,966) | 110 / 110; %96,63–%100 | (110, 110, 0,966), değişmez |
| `ks1:func_kalibi` | (246, 259, 0,916) | 246 / 259; %91,60–%97,04 | (246, 259, 0,916), değişmez |
| `ks1:func_aktarma` | (33, 33, 0,896) | 33 / 33; %89,57–%100 | (33, 33, 0,896), değişmez |
| `ks1:func_kalibi+func_aktarma` | (3, 3, 0,438) | 3 / 3; %43,85–%100 | (3, 3, 0,438), değişmez |
| `ks1:assert_ust` | (5, 7, 0,359) | 5 / 7; %35,89–%91,78 | (5, 7, 0,359), değişmez |

- **Kaynak dizgisi:** `MEASURED_PRECISION_SOURCE = "docs/arge/2026-11-19_birlesik_olcum/sonuc.md@<bu commit>"`. Değişen tek satır gnulib.
- **Sınama:** `tests/test_p12a_on_ad_guveni.py` tabloyu belgedeki satırla ve `baglama.wilson` alt sınırıyla karşılaştırıyor; kaynak değişince test de güncellenmeli.
- **Kural (ön kayıt §5.2):**
  - bu ölçümle hiçbir kanal "kesin" etiketine yükseltilmez: ölçüm geliştirme seti içi, gnulib kuralları bu setin GT'sine bakılarak kuruldu;
  - gnulib satırı kanalın üç kararını (parmak izi; gelenek, n = 1; LTO'suz iç ad, 112) birlikte sayar.
- `string_context/oz_ad` ön ad kanalı değil; tabloya girmez. Bilgi için: 93 / 197; Wilson %40,4–%54,2.

## 8. Sapmalar

Ön kayıttaki ölçüt, eşik, bant, makro kuralı, nüfus ve hüküm değiştirilmedi. Komutlarda yalnız şu uygulama ayrıntıları var (ölçüyü etkilemez):
- `urun_olc karsilastir`'ın `--taban` yolu mutlak verildi.
- Ürün ağacından koşulan bütün betiklere `PYTHONPATH=<ürün ağacı>` eklendi; ön kayıt §2.2'nin "ürün ağacından koşulur" kuralının uygulanışı.

## 9. Süre (kaba; karar dışı)

**Yeni kol** (künye `sonuclar[].sure_sn`, 119 / 119 `tamam`):
- duvar saati 08:10:08 → 09:19:51 (69,7 dk), `--paralel 3`;
- ikili süreleri toplamı 12 536 sn;
- ikili başına medyan 80,9 sn;
- Mac: htop 107 sn, tmux 412 sn.

**Taban:**
- Yalnız ikinci çağrının 83 ikilisinin süresi kayıtlı (künye 2026-11-12 08:04–08:28).
- İlk (yarım) çağrının künyesinde (`kosu_kunyesi.ilk-kosu.json`) süre yok. Büyük ikililerin (tmux, openssl, zstd, Mac) taban süresi yok.

**Ortak 83 ikili** (hepsi küçük Debian ikilisi):

| | Taban | Yeni |
|---|---|---|
| Medyan | 47,0 sn | 73,4 sn |
| Toplam | 4 173 sn | 6 469 sn |

Medyan oran (yeni / taban) **1,49**.

**Ön kayıtlı yön beklentisi** (medyan oran < 1): **tutmadı**. Karar dışı.

**Okuma:** Bu sayı ürün hızı hakkında hüküm taşımaz.
- Yeni koşu sırasında makinede 5–7 ajan çalışıyordu (pytest, mutasyon, sıralı Ghidra koşuları); 36 GB RAM ve 14 çekirdek paylaşıldı.
- Taban koşusunun yük durumu kayıtlı değil.
- Yeni ürün koşu başına daha çok iş yapıyor: GHIDRA-16 dizgi xref'leri, capa / YARA durumları, kanıt satırları.
- P16c'nin BSim hızlanması (köprüde 2,8–6,7 kat) tek başına ölçülmüş ve yükten bağımsız bir A/B'dir. Bu koşu onu ne doğrular ne çürütür.
- Hız iddiası için iki kol aynı yükte, sıralı ve aynı günde koşulmalı.

## 10. ARGE listesi için ⟨ÖLÇÜM⟩ değerleri

Ürün a62f15e (1.24.1), geliştirme seti 119 ikili (118 C ikilisi ölçüldü, `pzstd` C++ ölçü dışı). Hüküm tam eşitlik; GA = Wilson %95 güven aralığı. Geliştirme seti içi ölçümdür (ön kayıt §8.1): genelleme iddiası değil.

| Yer tutucu | Değer |
|---|---|
| havuz | 1 800 ad verilen fonksiyon (118 C ikilisi, 10 birim); 1.22.1'de 2 261 |
| doğru (%; %95 GA) | 1 681 (%93,4; %92,2–%94,5); 1.22.1'de 1 589 (%70,3) |
| yanlış (%; %95 GA); makro yanlış | 119 (%6,6; %5,5–%7,8); program düzeyi makro yanlış %31,0 (1.22.1: 672, %29,7; makro %52,8) |
| nüfus | 21 371 ad bekleyen fonksiyon (Ghidra'nın jenerik bıraktığı ve GT'de adı olan; 10 birim) |
| ad verilen kapsam | 1 315 / 21 371 (%6,2; %5,8–%6,5); makro %3,3 (1.22.1: %8,3; düşüş yanlış adların kalkmasından) |
| doğru ad kapsamı | 1 212 / 21 371 (%5,7; %5,4–%6,0); makro %2,4 (1.22.1: 1 120, %5,2) |
| kesin etiketli doğru / toplam; kapsam | 249 / 262 (%95,0; %91,7–%97,1), makro %97,3; kapsam 252 / 21 371 (%1,2), doğru kapsam 240 / 21 371 (%1,1); 1.22.1 ile aynı |
| tuttu / tutmadı (hedef yanlış ≤ %10) | **tutmadı** (karar program düzeyi makroyla: %31,0). Havuz %6,6 hedefin altında; makroyu zstd (%83,6) ve sqlite3 (%58,3) taşıyor, ikisinde de yanlışlar `string_context/oz_ad`'dan. "kesin" kararı (≥ %95) **tuttu** |
| kanal kırılımı farkı | `on_ad:gnulib` 843 / 621 / 222 → 733 / 733 / 0 (+112 doğru, −222 yanlış); `kebap_ad` 239 yanlış → 0; `api_param_reverse` 85 (1 doğru) → 0; `string_context/oz_ad` 224 / 112 → 197 / 93 (−19 doğru, −8 yanlış; GHIDRA-16 × erken dönüş, §4.1); öbür 6 kanal aynı. Toplam: kazanılan doğru 112, kaybedilen doğru 20, giderilen yanlış 553, yeni yanlış 0 |
| urun_kos süresi (119 ikili, --paralel 3) | 69,7 dk duvar saati (2026-11-19 08:10:08 → 09:19:51), 119 / 119 tamam; ortak makinede, aynı anda 5–7 ajanla |
| masum kapı çıktı kipi, 119 ikili | **GEÇTİ** (çıkış 0). Yanlış iddia 1.22.1 → a62f15e: bileşim 451 → 0, `types.h` yapısı 117 → 0, blok yorumu 112 → 1, YARA 70 → 0 (12 doğru iddia), anti-debug 23 → 7, paketleyici 0 → 0, istihbarat 1 965 → 455, algoritma (JSON) 109 → 56, algoritma (kod) 66 → 41, SARIF 81 → 12 (12'si YARA'da doğru bilinen kurallar; kapı izleyicisi kusuru), güvenlik etiketi 47 → 47 (adet 4 327 → 3 352) |
| sağlamlık denetimi kusur sayıları, 119 ikili | koşuldu. `decompiled_json_kirpik` 25 640 → 0, `bsim_yedege_dustu` 78 → 0, `cift_tanim_adres` 5 → 0, `yerel_ad_uygulanmamis_fonksiyon` 2 458 → 7, `yerel_son_tur_baska_adla_fonksiyon` 5 356 → 62, `eski_fonksiyon_adi_yorumda_kalan` 1 927 → 1 533, `fonksiyon_anahtari_ghidrada_yok` 234 → 233. `log_yazildi_satiri_yok` / `sayi:log_*` 119: denetim betiğinin kusuru (Türkçe `yazıldı`), ürün kusuru değil |
| gnulib ön ad kanalının yeni kesinliği | 733 / 733 (%100; Wilson %99,48–%100) → `MEASURED_PRE_NAME_PRECISION` önerisi (733, 733, 0,995); eski 621 / 843 (0,706). Geliştirme seti içi; "kesin" etiketine yükseltme yok |
| Mac htop / tmux ad sayısı ve doğrusu | htop: 0 ad (nüfus 597; 1.22.1'de de 0); tmux: 236 ad, 205 doğru (%86,9; %82,0–%90,6), nüfus 2 545, doğru ad kapsamı 205 / 2 545 (%8,1) — 1.22.1'de 395 / 205 |
| süre — toplam; varsa ikili başına medyan | ikili süreleri toplamı 12 536 sn (duvar 69,7 dk, `--paralel 3`); ikili başına medyan 80,9 sn; Mac tmux 412 sn, Mac htop 107 sn. 1.22.1 ile kıyas yalnız 83 küçük ikilide mümkün (medyan 47,0 → 73,4 sn) ve yük farkı yüzünden hükümsüz |

## 11. Ölçüm araçlarında bu aşamada bulunan kusurlar (değiştirilmedi)

1. **`masum_kapi.py` `sarif` katmanı** KRDL001 / KRDL007 kodlu 12 iddiayı yanlış sayıyor. Aynı kurallar `yara_cikti`'de "doğru bilinen". `dogru_iddialar` P07'nin yeni SARIF kodlarına uygulanmıyor gibi; kapının kodu incelenmedi (§6).
2. **`saglamlik_denetle.py:608`** ürün günlüğündeki `yazıldı` satırını tanımıyor (ASCII `yazildi` arıyor). 119 ikilide sahte `log_yazildi_satiri_yok` ve `sayi:log_*` kusuru üretiyor (§6.1).
3. **Ön kayıt §9'daki kusurlar** (`BITTI` içeriği, Mac'te `BITTI`, künyede önbellek ve VT şeması) geçerli. Bu ölçümde `butunluk.py` ile denetlendi: kısmi 0.
