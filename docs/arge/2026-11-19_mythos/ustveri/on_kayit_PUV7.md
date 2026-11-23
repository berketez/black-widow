# P-ÜV7 — Go tutarlılık denetimi: ön kayıt (2026-11-23, ölçümden önce)

Plan: `ustveri/PLAN.md` "P-ÜV7"; gönderim metni `docs/arge/2026-11-23_dalga1/gonderim/PUV7.md`.
Bu metin ölçümden önce commit'lenir. Tutmayan beklenti silinmez; eşik sonradan değişmez.

## Hipotezler (plandaki H1–H6 aynen)

> H1: bozulmamış `gh` ve `limactl` sayıları başvuruyla aynı. H2: aynı tohumla A–E sonuçları
> başvuruyla aynı. H3: Go 1.26 (`__itablink` yolu) ve 1.24 ikililerinde T1 / T2 uyumu ≥ %99,9;
> tutmazsa okuyucu o sürüm için `desteklenmiyor` der. H4 (beklenen olumsuz, yinelenir): D türünde
> yakalanan 0. H5 (açık): K10 içerik denetimi bozulmamış ikilide ≥ %99 uyum verirse E'de yakalama
> ≥ %95'e çıkar; vermezse eklenmez. H6: T3'ün yanlış alarm oranı ikiliden ikiliye ≥ 10 kat
> değişir (153 / 31 483 ↔ 2 365 / 32 532); bu yüzden T3 kararı etkilemez.

## Gönderim metninin ekleri (aynen)

> H3-sınama (bir kez; denetimler dondurulduktan sonra): docker-compose'da (Go 1.23.8) bozulmamış
> hâlde T1 ve T2 uyumu ≥ %99,9; tutmazsa o sürüm için `desteklenmiyor`.
>
> H7 (ikili düzeyi eşik): bozulmamış 11 dilimde güçlü işaretli fonksiyon oranının en büyüğü
> ölçülür; `ust_veri_supheli` eşiği (%1) bu en büyük değerin en az 10 katıysa eşik kalır, değilse
> eşik ön kayıtta yazılı kuralla yükseltilmez — bulgu olarak yazılır ve karar ana oturuma bırakılır.

## Başvuru sayıları (`$V/dusman/`, araştırma 2026-11-19)

| | gh | limactl |
|---|---|---|
| T1 uyan / bakılan | 6 333 / 6 333 | 8 426 / 8 426 |
| T2 uyan / bakılan | 26 258 / 26 258 | 31 105 / 31 105 |
| T2p uyan / bakılan | 26 236 / 26 238 | 30 891 / 31 057 |
| T3 uyan / bakılan | 31 330 / 31 483 | 30 167 / 32 532 |
| T4 uyan / bakılan | 38 356 / 39 697 | 38 372 / 39 647 |
| T5 uyan / bakılan | 19 / 19 | 20 / 20 |
| İkinci kaynaklı (T1 ∪ T2 ∪ T5) | 13 188 | 15 608 |
| A yakalanan | 66 / 200 | 84 / 200 |
| B yakalanan | 181 / 200 | 192 / 200 |
| C yakalanan | 73 / 200 | 82 / 200 |
| D yakalanan | 0 / 86 | 0 / 451 |
| E K4 yakalanan | 160 / 200 | 166 / 200 |

## İşlemsel tanımlar (ölçümden önce sabit)

- **Güçlü denetim:** T1, T2, T2p, T5, T6. **Zayıf:** T3, T4 (hesaplanır, ayrı raporlanır, damgaya
  ve ikili kararına girmez).
- **Damga (fonksiyon başına):** `tutarsiz` = güçlü işaret var **ya da** P-ÜV1'in fonksiyon başına
  K4 sonucu (`pcsp_kapsama`) `kisa` / `tasan` (P-ÜV1 raporunun notu: üst verisi gövdesine uymayan
  fonksiyona ad yazılmaz); `cift_kaynak` = T1 ∪ T2 ∪ T5 kapsamında ve tutarsız değil;
  `tek_kaynak` = öbürleri (ikinci kaynak yok).
- **İkili kararı:** güçlü işaretli fonksiyon sayısı > 0 → `uyari`; güçlü işaretli fonksiyon /
  bütün `ftab` girişleri > %1 → `ust_veri_supheli`; P-ÜV1'in yapı kararı (`tutarsizlik_nedeni`)
  ihlal veriyorsa da `ust_veri_supheli`. Öbür durum `temiz`. Eşik %1 modülde adlandırılmış sabit.
- **Tip verisi desteklenen sürümler:** Go 1.20–1.27 (`moduledata` 37. sözcük `types`; 1.27'de
  itab'lar `types + itaboffset`, ≤ 1.26'da `__itablink` / `.itablink`). Sürüm okunamıyorsa ya da bu
  aralık dışındaysa tip verisi `desteklenmiyor` (T1 / T2 kapsamı 0 → damga en çok `tek_kaynak`);
  tahmin edilmez.
- **Bozma deneyi:** örneklem araştırma betiğinin örneklemiyle aynı olsun diye aday dışlaması
  araştırmanın tanımıyla yapılır (T3 dahil güçlü işaret). Raporda iki sütun: "araştırma tanımı"
  (T3 dahil; H2'nin başvuruyla karşılaştırılan sayısı) ve "ürün damgası" (`tutarsiz` damgası;
  dönüş mesajındaki "tür başına yakalanan"). K4 de iki sütun: araştırma kuralı (H2) ve ürünün
  `pcsp_kapsama` sonucu.
- **K10 (kalem 6):** yalnız arm64. Ölçü: `pcsp` değeri ilk kez sıfırdan farklı olduğu pc'den önceki
  komut, değeri o sayıya eşit yığın ayarlaması (`str x30, [sp, #-N]!`, `stp …, [sp, #-N]!`,
  `sub sp, sp, #N`; büyük çerçevede `sub xN, sp, #N` + `mov sp, xN`). Bakılan: `pcsp` tablosu
  sıfırdan farklı değer içeren, birleştirici dili bayraklı olmayan fonksiyonlar. Uyum ≥ %99 (gh ve
  limactl ayrı ayrı) → K10 eklenir ve E yeniden ölçülür; altında → eklenmez, neden yazılır.

## Ek ikililer (ilk ölçüm; yalnız yön)

Ollama arm64 (1.26.0), colima (1.26.4), docker-cli (1.24.4): bozulmamış hâlde T1 ve T2 uyumu
≥ %99,9 beklenir. docker-compose SINAMA: dondurma commit'inden sonra bir kez.
