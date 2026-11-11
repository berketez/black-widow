# N1 adım 3: ürün ölçümü — ön kayıt eki 1 (1.22.1 kolu)

- **Tarih:** 2026-11-11.
- **Durum:** KESİN. Bu ek, 1.22.1 kolu GT'ye karşı okunmadan önce commit'lendi.
- **Kapsam:** `urun_olcumu_onkayit.md` (commit 1e3a5b2) ve onun dayandığı taslak aynen geçerlidir: hüküm, ölçüler, makro kuralı, kararlar (a)–(d), bütünlük koşulları B1–B6, sabitlenen dosyalar. Bu ek yalnız yeni bir kol tanımlar ve onun için ölçümden önceki beklentileri yazar. Yeni eşik yok.
- Bu belgede fonksiyon adı geçmez.

## 1. Neden yeni kol

İlk ölçüm (`urun_olcumu_sonuc.md`; ürün 93a2956 = 1.21.1) yanlışların kaynağını gösterdi. O ölçümden sonra ürüne giren ve ad haritasını değiştirmesi beklenen iki düzeltme var:

| Düzeltme | Commit | Beklenen etki |
|---|---|---|
| ELF önyük adları temizlenmeden yazılıyor | 4b5e940 | `on_ad:elf_onyuk` kanalındaki 226 yanlışın hepsi doğruya döner |
| `xstrtol_error` gnulib parmak izi çıkarıldı | 204f5c4 | `on_ad:gnulib` kanalından 9 yanlış ad düşer |

Aynı aralıkta giren öbür değişikliklerin ölçülen ad haritasını (`reconstructed/src/naming_map.json`) değiştirmemesi beklenir: arayüz düzeltmeleri, rapor sayaçları, temiz çıktının ad haritası ve README'si, yeni `karadul/lm/` paketi (motor içe aktarmaz). Debian `tree`'de bu commit'lerle ölçülen haritadaki fark yalnız iki önyük anahtarıdır (GT'siz denetim; `docs/arge/2026-11-11_rapor_sayaclari/sonuc.md`, `2026-11-11_temiz_harita/sonuc.md`).

## 2. Kol

| | |
|---|---|
| Kol adı | `yeni2` |
| Ürün commit'i | f30ac9a (`karadul` 1.22.1) |
| Ürünün yüklendiği ağaç | `~/karadul_olcum/urun-f30ac9a` (o commit'te ayrık git ağacı; çalışma zamanı verisi ana depodakilere bağ) |
| Koşucu, girdi, komut, ortam | İlk kolla aynı (`urun_olcumu_onkayit.md` §3): `scripts/measurement/urun_kos.py`, 3 paralel, ikili başına 3 600 sn, `PYTHONHASHSEED` verilmedi |
| Koşu kökü | `~/karadul_olcum/runs/urun-yeni2-f30ac9a` |
| Karşılaştırmalar | (i) taban (`urun_olcumu_taban_ol7c.json`) ↔ `yeni2`: kararlar (a)–(d) bu karşılaştırmadan okunur. (ii) `yeni` (`urun_olcumu_yeni.json`) ↔ `yeni2`: yalnız iki düzeltmenin etkisini ayırmak için; karar okunmaz |

## 3. Ölçümden önceki beklentiler

İlk ölçümün sayılarından aritmetik (`urun_olcumu_sonuc.md` §3, adım 1 ve 2):

| Ölçü | `yeni` (ölçüldü) | `yeni2` (beklenti) |
|---|---|---|
| Ad verilen | 2 270 | 2 261 |
| Doğru | 1 363 | 1 589 |
| Yanlış | 907 | 672 |
| Yanlış oranı, havuz | %40,0 | %29,7 |
| "kesin" etiketli ad / doğru | 262 / 249 | 262 / 249 (değişmez) |
| `on_ad:elf_onyuk` doğru / ad | 232 / 458 | 458 / 458 |
| `on_ad:gnulib` doğru / ad | 621 / 852 | 621 / 843 |
| Öbür kanallar | — | ad ve doğru sayıları değişmez |

- (a) yanlış ≤ %10 yine `tutmuyor` çıkar; (b) `tutuyor`; (c) `beklenen_aralikta`; yön koşulu tutar.
- (ii) karşılaştırmasında: kazanılan doğru 226, giderilen yanlış 235 (226 + 9), kaybedilen doğru 0, yeni yanlış 0.
- Makro yanlış oranı için sayısal beklenti yazılmıyor (önyük adları her birimde var, etkisi birim büyüklüğüne göre değişir); yalnız yön: %60,8'den düşük.

**Beklentiden sapma nasıl okunur:** önyük kanalında 458'den az doğru çıkarsa neden sayılır (çakışma yüzünden reddedilen ön ad, Ghidra'nın zaten adlandırdığı fonksiyon, ad geçerliliği süzgeci). Öbür kanallarda ad ya da doğru sayısı değişirse, hangi commit'in değiştirdiği bulunana kadar sonuç "açıklanamayan fark" diye yazılır ve derleme kararı verilmez.

## 4. Ek bütünlük denetimleri (ilk ölçümde ön kayıtsız yapılmıştı; burada ön kayıtlı)

GT okunmadan önce:
1. Sabitlenen 12 dosyanın özetleri yeniden hesaplanır (`urun_olcumu_onkayit.md` §4); biri farklıysa ölçüm yapılmaz.
2. `kol_butunlugu.py`: `yeni2` ile taban kolun Ghidra zemini aynı olmalı (fonksiyon sayısı, adres kümeleri, derleme başarısızı). Farklı ikili varsa ölçüm yapılmaz, neden incelenir.
3. Koşu künyesi: commit f30ac9a, kirli dosya yok, koşu boyunca ağaç değişmedi.
4. Geçersiz kılma deposu (`~/.karadul/overrides`) koşudan önce ve sonra boş.

## 5. Bu ek yazılırken bakılanlar

- `yeni2` kolunun hiçbir çıktısı yok (koşu başlamadı).
- İlk ölçümün sonuçları (`urun_olcumu_sonuc.md`) görüldü; beklentiler oradan türetildi.
- Debian `tree`'nin ana ağaçtan (f30ac9a öncesi commit'lerle) GT'siz koşuları: ölçülen haritada 93a2956'ya göre yalnız iki önyük anahtarı farklı.

**Yazan:** ana oturum (Claude). Berke'nin 2026-11-11 tarihli "kaldığımız yerden devam" talimatı altında; yeni eşik ya da seçim içermediği için ayrıca sorulmadı.
