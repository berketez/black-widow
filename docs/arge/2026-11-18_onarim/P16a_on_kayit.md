# P16a — ön kayıt: Ghidra köprüsünde belirlenimcilik ve dizgi bağı

- **Tarih:** 2026-11-18. **Durum:** KESİN (ürün kodu değişmeden önce commit'lendi; taban commit `650b469`).
- **Şablon:** `docs/arge/2026-11-10_n1_adim3/urun_olcumu_onkayit_taslak.md` (kısaltılmış: burada yeni ad üreten kanal yok; soru "değişiklik adları bozuyor mu").
- **Kapsam:** ad / tip davranışını değiştirebilecek iki P16a kalemi. Öbür kalemler (GHIDRA-09 hata nedeni, GHIDRA-10 sayaç, B-B4 kayıp sayacı, evrensel ikili dilimi, GHIDRA-06/08, MEK-02, B-C4, legacy silme) yalnız sayaç, durum kaydı ya da geliştirme setinde olmayan girdi (evrensel Mach-O) değiştirir; onların sayımı ilerleme dosyasında (`P16a.md`), ad ölçümü onlar için yapılmaz.
- Bu belgede fonksiyon adı geçmez.

## 1. Değişiklikler ve neden ada dokunabilecekleri

**Kol A (belirlenimcilik; GHIDRA-05 + "Küçükler" decompile dosya adı):**
1. `decompiled.json` `functions` listesi iş parçacığı bitiş sırası yerine Ghidra'nın adres sırasıyla (fonksiyon yineleyicisinin sırası) yazılır; 500 sınırı kalır ama adres sırasında ilk 500'dür ve kırpma sayacı yazılır. Tüketici: `CTypeRecoverer` `pcode_high_vars`'ı yalnız bu listeden okur. 500'den çok fonksiyonlu ikilide Ghidra tip katmanının uygulandığı fonksiyon altkümesi değişir → `types.h` ve gövdedeki değişken tipleri, dolaylı olarak ad adayları değişebilir.
2. Aynı adlı (ya da büyük/küçük harf duyarsız dosya sisteminde aynı dosya adlı) fonksiyonlardan eksiz `ad.c` dosya adını adres sırasında ilk gelen alır, öbürleri `ad_<adres8>.c`. Bugün bu iş parçacığı zamanlamasına bağlı: taban koşuda (`urun-yeni2-f30ac9a`) 10 938 çakışma grubunun 4 695'inde eksiz adı adres sırasında ilk olmayan fonksiyon almış (116 / 119 ikili; sayım betiği `~/karadul_olcum/runs/onarim-2026-11-18/P16a/dosya_adi_say.py`). Dosya adını kullanan aşağı akış adımları başka girdi görebilir.

**Kol B (GHIDRA-16; ancak vakit kalırsa koşulur):** PyGhidra dizgi kaydına (`ghidra_strings.json`) dizgiye başvuran fonksiyonlar `xrefs` listesi (`from_address`, `from_function`, `from_func_addr`) ve ilk başvuranın adı / adresi (`function`, `function_addr`) olarak yazılır (bugün 80 545 kaydın 0'ında dolu). Tüketiciler: `c_namer` (`function` alanını ve `xrefs[].from_func_addr`'ı dizgi→fonksiyon bağına ekler; aynı bilgiyi bugün `ghidra_xrefs.json`'dan da alıyor) ve `c_comment_generator` (dizgi yorumları; ad değil).

## 2. Ölçüm düzeni

- **Girdi alt kümesi (8 ikili, kilitli):** `debian/coreutils/cat`, `debian/coreutils/expr`, `debian/coreutils/ls`, `debian/coreutils/sort`, `debian/tree/tree`, `debian/htop/htop`, `debian/sqlite3/sqlite3`, `mac/htop`. Gerekçe: 5'i 500'den çok fonksiyonlu (kırpma bugün ls 165, sort 125, htop 648, sqlite3 644, Mac htop 290 kayıt), 3'ü küçük (kırpma yok; yalnız sıra ve dosya adı değişir); iki platform; toplam koşu süresi `--paralel 1` ile ~20 dk.
- **Taban kol:** `~/karadul_olcum/runs/urun-yeni2-f30ac9a` (1.22.1; ad davranışı HEAD ile aynı), aynı anahtarlar.
- **Yeni kol A:** `python scripts/measurement/urun_kos.py --agac <worktree> --kok ~/karadul_olcum/runs/onarim-2026-11-18/P16a/kolA --paralel 1 --yalniz <8 anahtar>`; kol A commit'i ilerleme dosyasına yazılır. Belirlenimcilik için `debian/coreutils/ls` ve `debian/tree/tree` ikinci kez ayrı köke (`kolA_tekrar`) koşulur.
- **Yeni kol B:** aynı komut, kök `kolB`, kol B commit'i.
- **Ad ölçüsü:** `python scripts/measurement/urun_olc.py olc` (taban: tam kök; yeni: `--eksik-izinli`) ve `karsilastir --eksik-izinli` (yalnız iki kolda da olan ikililer). Okunan: alt kümede toplam ad, doğru, yanlış; kaybedilen ve kazanılan doğru ad; yeni yanlış ad.
- **Belirlenimcilik ölçüsü (GT'siz):** `say.py` (`decompiled.json` adres sırası kırılması, kayıt sayısı, kırpma sayacı) ve `dosya_adi_say.py`; ayrıca iki tekrar koşu arasında `static/ghidra_output/decompiled.json` `functions` adres listesi ve `decompiled/` dosya adı → başlık adresi eşlemesi karşılaştırılır.
- Bilinen gürültü: BSim deposu ortak ve koşudan koşuya büyür (GHIDRA-01/02; gölge kip, ad kanalına bağlı değil); başka ajanların koşusuyla çakışırsa günlükte "Database already in use" görülür, not edilir. Taban 1.22.1 ile HEAD arasında ad davranışı değişmedi (brif); yine de taban ile kol A arasındaki her fark bu pakete yazılmaz: kol B'nin etkisi kol A'ya göre okunur.

## 3. Beklentiler (ölçümden önce)

| # | Ölçü | Beklenti | "Tutmadı" denir, eğer |
|---|---|---|---|
| A1 | Kol A'da `decompiled.json` adres sırası kırılması (8 ikili toplamı) | 0 (taban: alt kümede 27; ikili başına ls 3, sort 5, cat 5, expr 5, tree 5, htop 1, sqlite3 1, Mac htop 2) | > 0 |
| A2 | Kol A'da `decompiled.json` kayıt sayısı = min(500, denenen fonksiyon) ve kırpılan sayı dosyada yazılı | 8 / 8 ikili | herhangi birinde tutmazsa |
| A3 | Kol A tekrarında (`ls`, `tree`) `functions` adres listesi ve dosya adı → adres eşlemesi | iki koşuda bayt bayt aynı | herhangi bir fark |
| A4 | Kol A'da eksiz dosya adını adres sırasında ilk olmayan fonksiyonun aldığı grup | 0 | > 0 |
| A5 | Ad: alt kümede yanlış ad sayısı (havuz) | tabandakinden en çok %5 fazla (küçük oynama beklenir; yön önceden bilinmiyor) | taban yanlış × 1,05'i aşarsa |
| A6 | Ad: kaybedilen doğru ad | tabandaki doğru adların en çok %5'i | %5'i aşarsa |
| B1 | Kol B'de dizgi kaydında fonksiyon bağı dolu (8 ikili) | dizgilerin çoğunda (> %50) `xrefs` dolu; `function` = ilk başvuranın adı | ≤ %50 |
| B2 | Kol B ad: yanlış ad, kol A'ya göre | en çok %5 fazla | aşarsa |
| B3 | Kol B ad: kaybedilen doğru ad, kol A'ya göre | en çok %5 | aşarsa |

- A5/A6/B2/B3 "tutmadı" çıkarsa değişiklik geri alınmaz (belirlenimcilik ve dürüst kayıt ölçütün önünde); fark kanal kanal ve ikili ikili yazılır, ana oturuma bildirilir, hangi aşağı akış adımının dosya adına / sıraya / dizgi bağına duyarlı olduğu ayrı iş kalemi olur.
- A5/A6 tutsa bile bu, Ghidra tip katmanının bütün fonksiyonlara ulaştığı anlamına gelmez: 500 sınırı kalıyor (kırpma artık yazılı); sınırın kaldırılması ayrı ölçüm ister.
