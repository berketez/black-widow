# G7 alıcı tip kümesi saflığı: rapor

- **Tarih:** 2026-10-19.
- **Plan kalemi:** plan v2 §5 G7 (alıcı tip kümesi saflık deneyi), G8 karar kuralları 3. satır, §5 G16-G17; Onuncu Adam İ7 yöntem 1.
- **Ön kayıt:** `onkayit.md`, ölçümden önce yazıldı ve 13:35:40'ta mühürlendi (SHA-256 `d6828667…b743db45`). Betikler de mühürde. İlk ölçüm 13:35:46. Sapma ve eklemeler `onkayit_notlari.md`'de; hiçbiri kuralı, ölçütü ya da eşiği değiştirmedi.
- **Girdi:** taban v2 koşusu `taban-v2-62ad154` (Ghidra 12.1.2), tmux ve htop. Ghidra yeniden çalıştırılmadı.
- **Belirlenimcilik:** İkinci koşu bayt bayt aynı çıktı (`onkayit_notlari.md`).

## Özet

1. **G8 karar kuralı (3. satır): saf değil, iki programda da.** V1'in ağırlıklı saflığı Ö1'de (ilk ad parçası) tmux'ta %77,4, htop'ta %55,9. Bootstrap aralıkları: tmux [%64,7, %88,3], htop [%46,7, %69,4]. İkisinin de üst ucu %90'ın altında. Ö2'de (nesne öneki) tmux %52,2, htop %55,3.
2. **Kümeler rastlantı değil.** Negatif kontrol dört ölçümde de geçti: karışık kümelerde saflık %18-28, gerçek kümelerde %52-77; p ≈ 0,001.
3. **Kapsam.**
   - tmux: isim bekleyenlerin %40,4'ü bir kümeye düşüyor. %24,8'i kâhin çapalı (Ç-O), %24,5'i Karadul çapalı (Ç-K) bir kümeye düşüyor.
   - htop: %31,7'si bir kümeye düşüyor ama çapa yok. Ç-O 0; Ç-K'de tek çapa var, o da yanlış.
4. **Yorum (ön kayıt dışı, kaynağa bakılarak).** Kümeler tip olarak neredeyse saf: kaynaktaki 1. parametre tipine göre ağırlıklı saflık tmux'ta %99,1, htop'ta %87,1. Saflığı düşük en büyük 5 tmux kümesinin beşi de tek tipli: `struct client *`, `struct screen_write_ctx *`, `struct window *`, `struct grid *`, `char *`.
   - Yani birleştirme, bakılan kümelerde tipi doğru buluyor. C programları ise fonksiyonu alıcı tipine göre değil modülüne göre adlandırıyor: `struct client *` alan fonksiyonlar `server_client_*`, `status_*`, `control_*`, `file_*` modüllerine dağılmış. htop'ta kalıtım var: `MainPanel_*` yöntemleri `Panel *` alıyor.
   - Bu yüzden ad öneki saflığı burada büyük ölçüde adlandırma geleneğiyle alıcı tipi arasındaki uyumsuzluğu ölçüyor (yorum).
5. **G16-G17 için sonuç.** Alıcı tip kümeleri ad önekinin (modülün) kaynağı olamaz. Tip ve yapı taşıyıcısı olarak umut veriyorlar; ama bu ancak ayrı bir ön kayıtla ölçüldükten sonra söylenebilir (§10, öneri 2).

## 1. Yöntem (kısaca; tam tanım `onkayit.md`)

- **V1 (birincil):** Kaynak decompile C'dir.
  - A kendi 1. parametresini hiç değiştirmiyorsa ve doğrudan çağırdığı iç fonksiyon B'ye **aynen** 1. argüman olarak veriyorsa A.p1 ≡ B.p1.
  - Değişmiyor demek: atama, artırma ya da adres alma yok. Dönüşümler (`(long)p1`) aynen sayılır.
  - Alan yükleme ve ofsetli adres sayılmaz. İç thunk'lar hedefine çözülür; içe aktarmalar kenar üretmez.
  - p-code yalnız tanıdır, çünkü SSA kimliği taşımıyor.
- **Değişkenler:**
  - V1-N: yalnız p1'inde alan erişimi olan çağrılana giden kenarlar.
  - V2: bütün parametre konumları.
  - V1+T: `dyld_info -fixups` rebase yuvalarının bitişik koşularındaki fonksiyonlar birleştirilir. Ucuz tablo kardeşliği; dolaylı çağrı çözümü değildir.
- **Önek:**
  - Ö1: ilk parça.
  - Ö2: son parça hariç en çok iki parça (`window_pane_resize` → `window_pane`, `window_resize` → `window`).
  - Tek parçalı adlar saflığa girmez.
- **Saflık:** en sık önekin payı; ağırlıklı (mikro) ortalama karar ölçüsüdür. Kümeler yerine konarak yeniden örneklenir (B = 1000).
- **Çapalar:**
  - Ç-G: Ghidra/export.
  - Ç-O (kâhin): GT adı ikilinin dizelerinde aynen geçiyor. KS-1'in tavanıdır.
  - Ç-K (Karadul): `tarif_olc.reliable_names`.
  - Ç-K+: Ç-K'nin doğru olanları.
- **Yayılım benzetimi:** Çapaların öneki oybirliğiyle önerilir; çelişkide öneri yapılmaz.
- **Negatif kontrol:** Boyutlar korunarak karıştırma, R = 1000. Geçme koşulu: p < 0,01 ve fark ≥ 10 puan.

## 2. Sonuç tablosu (V1, birincil)

| Ölçü | tmux | htop |
|---|---|---|
| İsim bekleyen (P) | 2545 | 597 |
| **Ağırlıklı saflık Ö1** [bootstrap %95] | **%77,4** [%64,7, %88,3] | **%55,9** [%46,7, %69,4] |
| Medyan / makro saflık Ö1 | %100,0 / %84,0 | %50,0 / %62,8 |
| Negatif kontrol Ö1: karışık ortalama [2,5-97,5] | %27,5 [%26,4, %28,7], p = 0,001, geçti | %27,6 [%25,3, %30,0], p = 0,001, geçti |
| **Ağırlıklı saflık Ö2** [bootstrap %95] | **%52,2** [%42,1, %65,4] | **%55,3** [%46,6, %68,6] |
| Medyan / makro saflık Ö2 | %66,7 / %68,0 | %50,0 / %61,5 |
| Negatif kontrol Ö2 | %18,4 [%17,6, %19,3], p = 0,001, geçti | %27,6 [%25,3, %30,0], p = 0,001, geçti |
| Değerlendirilen küme / üye | 128 / 1009 | 37 / 170 |
| Eşik (%90) üstü küme payı, Ö1 / Ö2 | %65,6 / %38,3 | %29,7 / %27,0 |
| Tek parçalı adlı bekleyen (öneksiz) | 44 | 76 |
| **Kümeye düşen (K0)** | **%40,4** (1027/2545) [%38,5, %42,3] | **%31,7** (189/597) [%28,1, %35,5] |
| K0, talimat ağırlıklı | %57,1 | %40,5 |
| Tekil | %59,6 | %68,3 |
| Çapalı kümeye düşen, Ç-G | %0,0 (çapa 0) | %0,0 (çapa 0) |
| **Çapalı kümeye düşen, Ç-O** (kâhin) | **%24,8** (631) [%23,2, %26,5]; talimat %36,9; çapa 272 | **%0,0**; çapa 0 |
| **Çapalı kümeye düşen, Ç-K** (Karadul) | **%24,5** (624) [%22,9, %26,2]; talimat %38,0; çapa 129 | **%0,2** (1); çapa 1 |
| Çapalı kümeye düşen, Ç-K+ (doğru Karadul) | %19,9 (507) [%18,4, %21,5]; çapa 94 | %0,0 |
| Saf (≥ %90) ve çapalı küme, Ç-O, Ö1 / Ö2 | %9,4 / %1,9 | %0 / %0 |
| Saf ve çapalı küme, Ç-K, Ö1 / Ö2 | %10,3 / %2,2 | %0 / %0 |
| Ç-K'nin kesinliği | %73,4 (94/128) | 0/1 |
| p-code uyumu (tanı) | %100 (1781/1781) | %100 (270/270) |

Kıyas çizgisi (bilgi için): Karadul taban v2'de tmux'ta isim bekleyenlerin %33,7'sine, htop'ta %16,9'una isim veriyor. Bu tam isim; buradaki sayılar ise yalnız önek. Doğrudan kıyaslanmaz.

## 3. Yayılım benzetimi (V1; oybirliği, çelişkide susar)

| Program | Düzey | Çapa | Öneri (P'ye) | Kesinlik [%95] | Doğru öneri (P'ye) | Çelişkiden susan |
|---|---|---|---|---|---|---|
| tmux | Ö1 | Ç-O | %10,5 | %83,5 (222/266) [%78,5, %87,4] | %8,7 | 213 |
| tmux | Ö1 | Ç-K | %13,8 | %39,1 (137/350) [%34,2, %44,3] | %5,4 | 205 |
| tmux | Ö1 | Ç-K+ | %14,4 | %67,9 (248/365) [%63,0, %72,5] | %9,7 | 89 |
| tmux | Ö2 | Ç-O | %4,3 | %36,7 (40/109) | %1,6 | 370 |
| tmux | Ö2 | Ç-K | %8,9 | %23,1 (52/225) | %2,0 | 330 |
| tmux | Ö2 | Ç-K+ | %5,9 | %34,9 (52/149) | %2,0 | 305 |
| htop | — | hepsi | ≤ %0,2 | — (çapa yok) | %0 | 0 |

- Kâhin çapalarla bile modül öneki (Ö1) isim bekleyenlerin yalnız %8,7'sine doğru gidiyor; nesne önekinde (Ö2) bu %1,6.
- Karadul'un bugünkü çapalarıyla Ö1 kesinliği %39'a düşüyor. Çapaların %27'si yanlış ve yanlış çapa bütün kümeye yayılıyor.
- Yalnız doğru çapalar kullanılınca (Ç-K+) kesinlik %68.
- "Çelişkide sus" kuralı çok iş görüyor: Ç-O'da 213 isim bekleyen çelişkiden susturuldu. Çapalar büyük kümelerde farklı modüllerden geliyor.

## 4. Değişkenler

| Program | Değişken | Küme (≥ 2) | En büyük | K0 | Ç-O çapalı | Ç-K çapalı | Ö1 ağırlıklı | Ö2 ağırlıklı | Kontrol Ö1/Ö2 |
|---|---|---|---|---|---|---|---|---|---|
| tmux | **V1** | 135 | 95 | %40,4 | %24,8 | %24,5 | %77,4 | %52,2 | geçti/geçti |
| tmux | V1-N | 98 | 79 | %29,5 | %18,3 | %18,4 | %79,5 | %56,0 | geçti/geçti |
| tmux | V2 | 123 | 124 | %45,6 | %30,1 | %30,2 | %73,8 | %47,7 | geçti/geçti |
| tmux | V1+T | 140 | 95 | %41,9 | %25,0 | %24,9 | %78,3 | %52,9 | geçti/geçti |
| htop | **V1** | 41 | 50 | %31,7 | %0,0 | %0,2 | %55,9 | %55,3 | geçti/geçti |
| htop | V1-N | 33 | 48 | %27,0 | %0,0 | %0,2 | %57,8 | %57,1 | geçti/geçti |
| htop | V2 | 43 | 53 | %34,3 | %0,0 | %0,2 | %55,2 | %54,6 | geçti/geçti |
| htop | V1+T | 41 | 52 | %40,9 | %0,0 | %0,2 | %50,9 | %50,4 | geçti/geçti |

- **V1-N (nesne koruması):** saflık +2 puan, kapsam −11 puan (tmux). Çok biçimli çağrılan sorunu küçük; ana sorun o değil.
- **V2 (bütün konumlar):** kapsamı 5 puan artırıyor, saflığı 4 puan düşürüyor.
- **V1+T (tablo kardeşliği, yan sınama):** tmux'ta etkisi küçük (14 koşu, 60 fonksiyon). htop'ta kapsam +9 puan, saflık −5 puan (60 koşu, 86 fonksiyon). Tablolar taban sınıfın ortak yöntemleri üstünden alt sınıf ailelerini birleştiriyor.
- Hiçbir değişken eşiğe yaklaşmıyor.

## 5. Boyut ve saflık

- **tmux V1:** 135 küme (≥ 2 üye). Boyut dağılımı: 2 üyeli 63, 3-5 üyeli 40, 6-10 üyeli 9, 11-50 üyeli 18, 51-200 üyeli 5. En büyük küme 95 üye, P'nin %3,7'si.
- **htop V1:** 41 küme. Boyut dağılımı: 21 / 13 / 5 / 2 / 0 (aynı dilimler). En büyük küme 50 üye.
- **Ö1 saflığının boyuta göre değişimi (tmux):** 2 üyede %86,1, 3-5 üyede %86,8, 6-10 üyede %75,4, 11-50 üyede %79,9, 51-200 üyede %69,2. Küçük kümeler bile %90'a ulaşmıyor.
- **htop'ta aynı dilimler:** %61,1 / %71,1 / %46,4 / %45,9.
- **Medyan ile ağırlıklı ortalama arasındaki fark:** tmux'ta medyan küme saf (%100), ama ağırlıklı ortalama %77. Saf olmayanlar, üyelerin çoğunu taşıyan büyük kümeler.

## 6. Saflığı düşük en büyük 5 küme (V1, Ö1) ve kaynak tipi (yorum)

Kaynak tipi sütunu ön kayıt dışıdır, yalnız yorum içindir (`yorum_kaynak_tipleri.py`). Bulunan tanımlarda, kaynaktaki 1. parametre tipi verilmiştir.

| # | Program | Üye | Ö1 saflık | Önek dağılımı (ilk 8) | Kaynakta 1. parametre tipi |
|---|---|---|---|---|---|
| 1 | tmux | 91 | %19,8 | server 18, status 18, control 16, window 10, file 8, redraw 5, cmd 4, cmdq 3 (+6) | `struct client *` 91/91 |
| 2 | tmux | 67 | %85,1 | screen 57, format 5, window 3, mode 1, prompt 1 | `struct screen_write_ctx *` 67/67 |
| 3 | tmux | 56 | %51,8 | layout 29, window 17, server 3, menu 2, alerts 1, resize 1, recalculate 1, redraw 1 (+1) | `struct window *` 56/56 |
| 4 | tmux | 50 | %80,0 | grid 40, window 6, format 3, screen 1 | `struct grid *` 50/50 |
| 5 | tmux | 24 | %25,0 | key 6, args 2, options 2, utf8 2, cmd 1, events 1, format 1, hooks 1 (+8) | `char *` 24/24 (`const` atıldı) |
| 1 | htop | 45 | %40,0 | Panel 18, MainPanel 4, ScreensPanel 4, AffinityPanel 3, ColumnsPanel 3, ScreenNamesPanel 3, DisplayOptionsPanel 2, MetersPanel 2 (+6) | `Panel *` 32, `Object *` 7, alt sınıf işaretçileri 6 |
| 2 | htop | 16 | %62,5 | RichString 10, Row 6 | `RichString *` 16/16 |
| 3 | htop | 7 | %28,6 | InfoScreen 2, CommandScreen, EnvScreen, OpenFilesScreen, ProcessLocksScreen, TraceScreen 1'er | `InfoScreen *` 7/7 |
| 4 | htop | 7 | %28,6 | CheckItem 2, NumberItem 2, History, ListItem, TextItem 1'er | `char *` 7/7 |
| 5 | htop | 6 | %16,7 | CommandScreen, EnvScreen, InfoScreen, OpenFilesScreen, ProcessLocksScreen, TraceScreen 1'er | `InfoScreen *` 6/6 |

**Örnek adlar (GT, geliştirme seti).**
- #1 tmux: `server_client_check_exit`, `status_free`, `control_add_pane`, `window_customize_add_key_callback`, `file_error`. Hepsi `struct client *c` alıyor.
- #3 tmux: `layout_fix_panes`, `window_add_pane`, `server_kill_window`, `menu_close`. tmux 3.8'de `menu_close(struct window *w)`.
- #2 htop: `Row_printBytes(RichString* str, …)` ile `RichString_appendWide`.

**Ö2'nin en kötü kümesi tmux'taki 95 üyeli `struct tty *` kümesi.** Ö1'de saf (hepsi `tty`), ama Ö2'de `tty_cmd` 22, `tty` 16, `tty_keys` 13, `tty_set` 5 … diye bölünüyor, saflık %23,2. Bunun nedeni Ö2'de fiil ve alt modül parçası (`tty_set_*`, `tty_cmd_*`).

**Bütün V1 kümelerinde kaynak tipi saflığı (yorum).**
- tmux: 123 küme, tipi bulunan 990 üye, ağırlıklı **%99,1**.
- htop: 37 küme, 170 üye, **%87,1**. Taban ve alt sınıf işaretçileri ayrı tip sayıldı; kalıtım ailesi tek tip sayılsaydı oran daha yüksek olurdu (ölçülmedi).

Bu beklenen bir durum. C'de değişmemiş bir argümanı parametreye vermek, iki tarafın tiplerinin uyumlu olmasını gerektirir ve derleyici bunu denetler. İstisnalar `void *`, açık dönüşümler ve kalıtım taklidi (taban sınıf işaretçisi).

## 7. G8 karar kuralının okunuşu

Kural: "Alıcı tip kümeleri saf (≥ %90) ve kapsamlı → Faz 1'de tarifin nesne kaynağı bu kümelerdir (G16-G17)."

| Program | Ö1 ağırlıklı | Ö2 ağırlıklı | Kontroller | Ön kayıtlı okuma |
|---|---|---|---|---|
| tmux | %77,4 [%64,7, %88,3] | %52,2 | geçti / geçti | **saf değil** |
| htop | %55,9 [%46,7, %69,4] | %55,3 | geçti / geçti | **saf değil** |
| Genel | | | | **saf değil** |

- Kuralın saflık koşulu iki programda da sağlanmadı. Bootstrap aralıklarının üst ucu da eşiğin altında.
- Plan §7 gereği eşik düşürülmez. Bu kurala göre Faz 1'de tarifin nesne kaynağı bu kümeler olmaz.
- Ön kayıt §8 gereği kapsam yarısı için okuma yazılmadı. "Kapsamlı"nın eşiği planda yok. Saflık koşulu tutmadığı için kararı değiştirmiyor.

## 8. Beklentilerle kıyas (ön kayıt §1)

| Ölçü | Beklenti | Ölçülen | |
|---|---|---|---|
| tmux Ö1 saflık | %85-95 | %77,4 | beklentinin altında |
| tmux Ö2 saflık | %60-75 | %52,2 | altında |
| htop Ö1 saflık | %60-80 | %55,9 | altında |
| tmux K0 | %40-60 | %40,4 | aralıkta (alt uç) |
| htop K0 | %30-50 | %31,7 | aralıkta (alt uç) |
| tmux Ç-O çapalı | %20-40 | %24,8 | aralıkta |
| htop Ç-O çapalı | < %10 | %0,0 | aralıkta |
| tmux Ç-K çapalı | %10-25 | %24,5 | aralıkta (üst uç) |
| htop Ç-K çapalı | ~%0 | %0,2 | aralıkta |

Üç saflık tahmininin üçü de iyimserdi. Kaçırılan şey, aynı tipin birden çok modülde alıcı olmasıydı: `client`, `window`, `grid`.

## 9. Sınırlamalar

1. **Örneklem.** Yalnız iki program var, ikisi de geliştirme setinden. Sayılar yöntem tasarımı içindir, makale iddiası değildir.
2. **Önek tip değildir.** Bölüm 6'nın yorumu, ad öneki saflığının yöntemi değil adlandırma geleneğini ölçtüğünü gösteriyor.
   - Tip saflığı ön kayıt dışıdır, kaynaktan düzenli ifadeyle çıkarıldı ve yalnız geliştirme setinde bakıldı. Karar dayanağı olamaz.
3. **Ö2'nin fiil parçası** (`window_set`, `layout_set`, `tty_cmd`) Ö2 saflığını tip doğru olsa da düşürüyor. Ön kayıtta öngörülmüştü.
4. **Tutucu çıkarım.**
   - Yerel kopya üstünden geçen p1 kaçırılıyor.
   - p1'i değişen isim bekleyenler kenar üretmiyor: tmux 80, htop 15. p1'i hiç olmayanlar: tmux 138, htop 55.
   - V1 çağrı yeri, doğrudan iç çağrı yerlerinin yalnız %14,8'i (tmux, 1781/11996) ve %15,6'sı (htop, 270/1733).
5. **Yalnız doğrudan çağrılar.** V1+T dolaylı çağrı hedefi çözmüyor, kaba bir tablo kardeşliği.
6. **Çapalar.** Ç-O bir tavandır; bugün dizenin hangi fonksiyona ait olduğunu söyleyen bir kanal yok (KS-1, G11-G12). Ç-K'nin %27'si yanlış. htop derlemesinde assert ve `__func__` dizesi yok, bu yüzden "kendi adı" kanalı orada boş.
7. **Ghidra gövdeleri.** tmux'ta 240 "Could not recover jumptable" uyarısı var; bazı gövdeler eksik olabilir.

## 10. G16-G17 için öneriler

1. **Kümeleri ad önekinin kaynağı yapma.**
   - Ön kayıtlı kural sağlanmadı.
   - Kâhin çapalarla bile modül öneki isim bekleyenlerin yalnız %8,7'sine doğru gidiyor (Ö1). Nesne öneki (Ö2) %1,6'sına.
2. **Kümeleri tip ve yapı taşıyıcısı olarak sına (yeni ön kayıtla).**
   - Önerilen kısıt: "aynı küme = aynı p1 tipi". Bir üyede kurtarılan yapı yerleşimi, alan erişimleri ve parametre adı (DG-2) bütün kümeye yayılabilir. Bu G14-G15 geri yazma, TP-5/TK-13 ve G22 ile doğrudan ilgili.
   - Plan §4'e göre tip gerçeği Debian'da DWARF'tır. Ölçüt: Debian geliştirme programlarında V1 kümelerinin DWARF'a karşı 1. parametre tip saflığı (`struct` adı düzeyinde). Ayrıca kümeye yayılan alan ofsetlerinin kesinliği.
   - Bölüm 6'daki %99,1 bunun için bir sinyaldir, kanıt değildir.
3. **İsimde kullanılacaksa iki kanalı ayır.**
   - Modül öneki adres komşuluğundan gelir (TR-6, `module.py`; modülün belgesindeki 15 Ekim tmux ölçümü: isimsizlerin %22'sinde önek, %96'sı doğru).
   - Nesne (tip adı) kümeden yalnız ipucu ya da parametre adı olarak gelir.
   - Değerlendirme önek saflığıyla değil, kör rubrikle (yakın isim, yanlış) yapılır.
4. **Önce çapa kalitesi.**
   - Yayılım kesinliği çapanın kesinliğiyle sınırlı: Ç-K'de %39, doğru çapalarla %68, kâhin çapalarla %84 (Ö1).
   - Bu yüzden KS-1 (kendi adı ve `__func__` tespiti, G11-G12) yayılımdan önce gelmeli. "Çelişkide sus" kuralı korunmalı.
5. **htop türü programlar.** Çapa yok, kalıtım var. Bu yöntem orada isim üretmez; ancak tip kanalı olarak işe yarayabilir.

## 11. Ana oturumun vermesi gereken kararlar

1. **G8 3. satırın okunuşu.** "Saf değil" kabul edilirse G16-G17'deki "alıcı tip kümeleri (nesne kaynağı)" kalemi bu biçimiyle düşer. Yerine ne konacağı plan v2.1 kararıdır: tip kanalı (öneri 2), ipucu kanalı (öneri 3) ya da hiçbiri.
2. **Tip saflığı deneyi.** Debian DWARF'la yeni bir ön kayıt yapılsın mı? Yapılacaksa ölçüt ve eşik, sonuç görülmeden yazılmalı. Bu raporda kaynaktan bakılan %99,1 artık görüldü; aynı programlarda (tmux, htop) karar ölçüsü olarak kullanılmamalı.
3. **"Kapsamlı" eşiği.** Hâlâ tanımsız. Kural ileride başka bir saflık tanımıyla yeniden okunacaksa önceden yazılmalı.
4. **Sıralama.** KS-1'in (G11-G12) yayılım işlerinden önce gelmesi.
5. **Commit ve takip.** Commit yapılmadı. `docs/arge/2026-10-19_g7_alici_tip/` altındaki 11 dosya commit'lenmeli. Plan §13 takip tablosuna G7 (alıcı tip) satırı eklenmeli. `workspaces/2026-10-19_g7/` git dışı.

## 12. Dosyalar

- **Bu dizin:**
  - `onkayit.md` (mühürlü), `onkayit_notlari.md`, `rapor.md`, `sonuc.json`;
  - `cikar.py`, `olcut.py`, `deney.py`, `sinama_cikar.py`, `sinama_olcut.py` (mühürlü);
  - `yorum_kaynak_tipleri.py`, `tablolar.py` (ön kayıt dışı, yorum ve biçim).
- **`workspaces/2026-10-19_g7/` (git dışı):**
  - `veri/onkayit_muhur.txt`;
  - `veri/{tmux,htop}_cikti.json` (kenarlar, çapalar, fonksiyon dökümü);
  - `veri/<program>_<değişken>_kumeler.json` (küme üyelikleri ve GT adları);
  - `veri/yorum_kaynak_tipleri.json`, `veri/tablolar.md`, `log/`.
- **Yeniden üretim:**
  ```
  python3 -B cikar.py tmux <veri>/tmux_cikti.json
  python3 -B cikar.py htop <veri>/htop_cikti.json
  python3 -B deney.py <veri> sonuc.json
  ```
  Sınamalar: `python3 -B sinama_cikar.py` ve `python3 -B sinama_olcut.py <geçici_dizin>`.
