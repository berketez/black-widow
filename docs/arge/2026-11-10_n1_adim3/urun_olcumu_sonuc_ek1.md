# N1 adım 3: ürün adlarının GT'ye karşı ölçümü — sonuç eki 1 (`yeni2` kolu, 1.22.1)

- **Tarih:** 2026-11-12.
- **Ön kayıt:** `urun_olcumu_onkayit_ek1.md` (commit a19ce66; `yeni2` kolu GT'ye karşı okunmadan önce). Ölçü, hüküm ve kararlar `urun_olcumu_onkayit.md` (1e3a5b2) ile aynı.
- **Ölçülen ürün:** commit f30ac9a (`karadul` 1.22.1), ayrık ağaç `~/karadul_olcum/urun-f30ac9a`.
- **Nüfus:** ilk ölçümle aynı geliştirme seti; 10 birim, 119 ikili (ölçüye giren 118). Hüküm tam eşitlik.
- **Çıktılar:** `urun_olcumu_yeni2.json` / `.md` (kol), `urun_olcumu_fark_taban_yeni2.json` / `.md` (taban ↔ `yeni2`; kararlar buradan), `urun_olcumu_fark_yeni_yeni2.json` / `.md` (`yeni` ↔ `yeni2`; yalnız iki düzeltmenin etkisi), `kol_butunlugu_yeni2.json` (GT'siz zemin denetimi).
- Bu belgede fonksiyon adı geçmez.

## 1. Sonuç

Ön kayıtta ölçümden önce yazılan sayısal beklentilerin hepsi birebir tuttu.

| Ölçü | `yeni` (1.21.1; ölçüldü) | `yeni2` beklenti | `yeni2` ölçüldü |
|---|---|---|---|
| Ad verilen | 2 270 | 2 261 | 2 261 |
| Doğru | 1 363 | 1 589 | 1 589 |
| Yanlış | 907 | 672 | 672 |
| Yanlış oranı, havuz | %40,0 | %29,7 | %29,7 (Wilson %27,9-%31,6) |
| Yanlış oranı, program düzeyi makro | %60,8 | yalnız yön: daha düşük | %52,8 |
| "kesin" etiketli ad / doğru | 262 / 249 | 262 / 249 | 262 / 249 (havuz %95,0; makro %97,3) |
| `on_ad:elf_onyuk` doğru / ad | 232 / 458 | 458 / 458 | 458 / 458 |
| `on_ad:gnulib` doğru / ad | 621 / 852 | 621 / 843 | 621 / 843 |
| Öbür kanallar (ad, doğru) | — | değişmez | değişmedi (kanal tablosunun iki kol arasındaki tek farkı yukarıdaki iki satır) |

`yeni` ↔ `yeni2` karşılaştırması (karar okunmaz): kazanılan doğru 226 (beklenti 226; hepsi `on_ad:elf_onyuk`), giderilen yanlış 235 (beklenti 235), kaybedilen doğru 0 (beklenti 0), yeni yanlış 0 (beklenti 0).

Tabana (eski ürün) göre: ad 6 394 → 2 261; doğru 1 185 → 1 589; yanlış 5 209 → 672; yanlış oranı havuzda %81,5 → %29,7, makroda %92,2 → %52,8; kapsam %25,2 → %8,3; tam ad kapsamı %4,4 → %5,2.

## 2. Önceden yazılmış kararlar (taban ↔ `yeni2`)

| Karar | Ölçü | Eşik | Sonuç | Beklenti (ölçümden önce) |
|---|---|---|---|---|
| (a) yanlış ad oranı | makro %52,8 | ≤ %10 | `tutmuyor` | `tutmuyor` |
| (b) "kesin" etiketli adların kesinliği | makro %97,3 (openssl %100, tmux %94,6) | ≥ %95 | `tutuyor` | `tutuyor` |
| (c) kaybedilen doğru ad | 16 / 1 185 (%1,4); sınırı aşan birim yok | > %15 değil | `beklenen_aralikta` | `beklenen_aralikta` |
| Yön | yanlış oranı tabandan düşük olmayan birim | yok | `beklenen_aralikta` | tutar |

Hüküm değişmedi (ilk ölçümün dalı): derleme yapılabilir; "yanlış ad vermiyor" denmez. "Açıklanamayan fark" yok.

## 3. Kalan 672 yanlışın kaynağı

| Kanal | Ad | Doğru | Yanlış |
|---|---|---|---|
| `string_context/kebap_ad` | 239 | 0 | 239 |
| `on_ad:gnulib` | 843 | 621 | 222 |
| `string_context/oz_ad` | 224 | 112 | 112 |
| `api_param_reverse` | 85 | 1 | 84 |
| `ks1:func_kalibi` | 259 | 246 | 13 |
| `ks1:assert_ust` | 7 | 5 | 2 |

Birim başına yanlış oranı: coreutils %16,5; openssl %31,4; mac/tmux %48,1; debian/tmux %49,8; redis-tools %58,6; sqlite3 %75,0; zstd %86,2. Mac htop'ta yine hiç ad yok (0 / 597). Mac tmux bu iki düzeltmeden etkilenmedi (ELF önyükü yok): 395 / 205 / 190 aynı.

**[hesap]** (ölçüm değil; ilk sonuç belgesinin 3. ve 4. adımı): `kebap_ad` ve `api_param_reverse` susarsa 324 ad düşer (323 yanlış, 1 doğru) → yanlış 349 / 1 937 = %18,0. Bu adım Berke'nin kararını bekliyor; `kebap_ad` rubrikli ölçümde %10,8 yanlıştı, tam eşitlikte %100 ("gevşek mod" kararıyla çelişebilir).

## 4. Bütünlük (ön kayıt eki §4; GT okunmadan önce yapıldı)

1. Sabitlenen 12 dosyanın sha256 özeti ön kayıttaki tabloyla aynı (12 / 12; ölçümden hemen önce yeniden hesaplandı). Ölçüm ana ağaçtan koşuldu (HEAD 2be12ed, 1.22.2); ölçüm betiğinin içe aktardığı `alt_kanal.py` ve `naming_labels.py` bu 12 dosyanın içinde ve aynı.
2. `kol_butunlugu.py`: 119 ikili, okunamayan 0, farklı 0; iki kolda 66 983 fonksiyon, derleme 66 983 başarılı / 0 başarısız / 0 atlanan.
3. Koşu künyesi: commit f30ac9a, kirli dosya yok, koşu sonunda ağaç aynı (`agac_degisti: false`); ürün `~/karadul_olcum/urun-f30ac9a/karadul/` altından yüklendi.
4. `~/.karadul/overrides` koşudan önce ve sonra boş.
5. 119 / 119 `BITTI`; bitmeyen 0; `--eksik-izinli` kullanılmadı.

## 5. Koşunun kaydı (ön kayıtta öngörülmeyen)

- Koşu iki parçada yapıldı. İlk parça 2026-11-11 14:49'da başladı ve 15:43'te Berke'nin isteğiyle durduruldu (36 ikili bitmişti). İkinci parça 2026-11-12 08:04–08:28'de kalan 83 ikiliyi koştu (83 tamam, 0 bitmeyen). Koşucu `BITTI` dosyası olan ikilileri atlar; ürün ağacı iki parçada aynı commit'te ve temizdi.
- Durdurma anında yarım kalan üç ikilinin dizini (`debian/coreutils/` altında üç ikili; `BITTI` yok) ikinci parçadan önce kök dışına taşındı (`~/karadul_olcum/runs/urun-yeni2-f30ac9a-yarim-20261111/`; silinmedi) ve bu üç ikili baştan koşuldu. Taşınmasalardı aynı dizinde ikinci bir çalışma alanı açılır ve ölçüm betiği dururdu.
- `kosu_kunyesi.json` ikinci parçada yeniden yazıldı; yalnız 83 ikilinin süresini taşır. İlk parçanın künyesi aynı yarım dizinine kopyalandı (`kosu_kunyesi.ilk-kosu.json`). Süreler bu ölçümün konusu değil.
- İkinci parça sırasında makinede üç ajan (test ve mutasyon koşuları) çalışıyordu. Yük altında Ghidra'nın fonksiyon düşürmesi riski 2. bütünlük denetimiyle sınandı: fark yok.

## 6. Sınırlar

- Geliştirme seti: iki düzeltme bu setin sonuçlarına bakılarak yapıldı. Sayıların birebir tutması düzeltmelerin öngörülen işi yaptığını gösterir; taze veride aynı oranı göstermez.
- Hüküm tam eşitlik; amacı doğru anlatan ama GT'den farklı yazılan ad yanlış sayılır.
- Mac htop'ta ad yok; Mac tmux'ta yanlış oranı %48,1 ve bu ölçümde değişmedi.

**Yazan:** ana oturum (Claude), 2026-11-12.
