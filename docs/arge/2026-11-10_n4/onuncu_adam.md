# N4 fiil ön kayıt taslağı: Onuncu Adam incelemesi

- **Tarih:** 2026-11-10.
- **İncelenen:** `fiil_onkayit_taslak.md` (685 satır), `on_sayim.json`, `on_sayim.py` (bu dizin).
- **Görev:** Taslağın yaklaşımının yanlış ya da yetersiz olduğunu en güçlü biçimde savunmak. Onay değil, çürütme denemesi.
- **Yöntem:** Belgeler, kod ve toplu sonuç tabloları okundu. GT ve kilitli veri açılmadı. Karadul, Ghidra, test ve ölçüm betiği koşulmadı.
- **Codex:** iki kez çağrıldı; ikisi de nihai yanıt vermedi (`xhigh` zaman aşımı, `high` kullanım sınırı). İtirazları Claude yazdı; codex'in ara notlarından yalnız dosyadan doğrulananlar alındı (§9).
- **İşaretler:** **[hesap]** kaynak sayılardan aritmetik. **[tahmin]** açıkça yazılmış bir varsayıma dayanır. **doğrulanmadı** dosyadan teyit edilemedi.
- Bu belgede gerçek program fonksiyonu adı yoktur. Kod kalıpları genel C deyimleridir.

## 0. En güçlü üç itiraz

1. **Üç aile, Kapı 1'i ve %75 hedefini taşıyacak kapsamın yanına bile yaklaşamaz.**
   - N4'ün kusursuz çalıştığı durumda bile tavanı K ∪ Y'dir: Mac tmux %52,8, Mac htop %55,6 **[hesap; `on_sayim.json` sinif_K + sinif_Y]**. %75 bu tavanın üstündedir.
   - İlk sürümdeki F-ETKİ yalnız `create` ve `destroy` verir (`fiil_onkayit_taslak.md:295`). İkisi de ayırıcı ya da bırakıcı çağrısı ister (`:306-307`). Yapraklar hiçbir şey çağırmaz. Yani §6.8'deki "yaprak + bellek/dizgi" havuzunun yaprak kısmı (%16,1 / %17,1; `:538`) ilk sürüme kapalıdır.
   - Gerçekçi senaryolarda N4'ün eklediği yakın kapsam Mac tmux'ta ≈ %3-11, Mac htop'ta ≈ %5-11'dir **[tahmin, §1.3]**.
2. **Yanlış fiil korumaları C'nin en sık deyimlerini görmüyor; M1 bu hataların çoğunu ölçemiyor.**
   - "Başarıda 1, hatada 0 dön", "alanları bırak ve sıfırla", "argümanı kullan ve bırak", "hata kodu dönen yolda bırak" kalıpları `is`, `init`, `destroy` kurallarını tetikler (§3).
   - FK3 yalnız dönmeyen çağrıya ulaşan blokları hata yolu sayar (`:73`, `:326`). Dönmeyen çağrı içeren isim bekleyen fonksiyon Mac tmux'ta 28 (%1,1), Mac htop'ta 7 (%1,2) **[`on_sayim.json` K_donmez]**. Koruma Mac'te neredeyse hiç çalışmaz.
   - M1 yalnız 10 karşıt çifti eşikler; "farklı" sonuç eşik değildir (`:461`). Yukarıdaki hataların çoğu karşıt çift değildir: `is`'in hiç karşıtı yok; `destroy` yalnız `create`'e karşıttır (`on_sayim.json` → `kunye.karsitlar`).
3. **htop türünde başarı yolu en az bilgi taşıyan adlardan geçiyor; asıl kanıt dışarıda bırakılmış.**
   - Taslak, htop'ta Kapı 1'in ancak genel nesneli adlar (B4) yakın sayılırsa tutabileceğini kendisi yazıyor (`:541`). Bu kararı yazılı bir rubrik kuralı değil, aynı model ailesinden bir değerlendiricinin takdiri verecek (S8, `:240`; §4).
   - Debian htop'ta isim bekleyenlerin %77,8'inin, Mac htop'ta %36,2'sinin doğrudan çağıranı yok (`:144`, `:176`). Bunlar büyük olasılıkla veri tablolarından çağrılıyor (`2026-10-15_isimlendirme_plani.md:48`). Taslak tablo yuvası rolünü N4 dışında bırakıyor (`:409`). Oysa önceki planlama htop'un tavanını tam bu kanala bağlamıştı (`2026-10-15_makale/derleyici_sentez.md:259, :381, :409`). Tablo yuvalarını çıkaracak T1 de N4 ile aynı günlere yazılı (`2026-10-21_plan_v2_2.md:83, :139-140`).

**Zayıf ya da taslakta kısmen karşılanmış itirazlar (dürüstlük için):**
- Taslak M1'in seçilmiş bir alt küme olduğunu (`:593`), tutma okumasının Mac htop tazeliğine dokunduğunu (`:596`) ve B4 riskini (`:541`, `:606`) kendisi yazıyor. Buradaki itiraz, bu sınırların karar kuralına yansımamasıdır; sınırların gizlenmesi değil.
- v0'ın önce ölçülmesi (S2), sözlüğün ölçümden önce dondurulması (S3), `kesin.py`'ye dokunulmaması (`:346`) ve "ölçülmemiş aile ad vermez" (`:255`) doğru kararlardır; bu belgede itiraz edilmiyor.
- Mac derleyicisinin dışarı aldığı kod parçalarının F-ETKİ kalıplarını bozması (§2.1) doğrulanmadı; olasılık olarak yazıldı.
- §3 kalıp 8 ve §5 A2, A3 zayıftır; yerlerinde öyle işaretlendi.

**Taslağın en zayıf varsayımı:** "Export fonksiyonlarındaki fiil uyumu (M1), ad bekleyen static fonksiyonlarda kuralların doğruluğunu temsil eder." M1 ailenin ölüp ölmeyeceğine karar veriyor. Ama evreni farklı bir nüfus (çapraz modül API'si), farklı bir derleyici (gcc -O2, ELF) ve gevşek bir başvuru (sözlük sınıfı) taşıyor (§2).

## 1. Üç aile ad bekleyenlerin ne kadarına doğru ad verebilir?

### 1.1 Taslağın kendi ön sayımıyla erişim

| | Mac tmux | Mac htop | Kaynak |
|---|---|---|---|
| İsim bekleyen (vekil nüfus) | 2 587 | 597 | `on_sayim.json` isim_bekleyen |
| K / I / Y | 951 / 1 220 / 416 | 230 / 265 / 102 | sinif_K, sinif_I, sinif_Y |
| N4'ün mutlak tavanı: K ∪ Y, kusursuz doğrulukla | %52,8 | %55,6 | **[hesap]** |
| F-API erişimi (ayırt edici API, iç çağrı ≤ 3) | 229 (%8,9) | 82 (%13,7) | `fiil_onkayit_taslak.md:537` |
| `free`'yi doğrudan çağıran isim bekleyen | 493 (%19,1) | 84 (%14,1) | import.en_sik |
| `malloc`'u doğrudan çağıran isim bekleyen | ≤ 15 (ilk 25'te yok; 25. sıra 15) | 5 | import.en_sik |
| Yaprak (ilk sürüm `create`/`destroy` için erişilemez) | 416 (%16,1) | 102 (%17,1) | sinif_Y |
| Dönmeyen çağrı içeren (FK3'ün iş gördüğü) | 28 (%1,1) | 7 (%1,2) | K_donmez |
| Doğrudan çağıranı olmayan | 787 (%30,4) | 216 (%36,2) | cagiran_*_0 toplamı |

- Taslağın §6.8'deki havuzları (F-API + yaprak + yalnız bellek/dizgi), hepsi doğru sayılsa bile Mac tmux'ta %43,8, Mac htop'ta %49,7 eder **[hesap; codex'in ara notu, §9]**. Bu sayı kesin bir tavan değildir: F-ROL sayılmadı, sarmalayıcı erişimi havuzlarla örtüşmüyor.

### 1.2 Taslağın iyimser olduğu yerler

1. **Yaprakları F-ETKİ havuzuna katıyor** (`:538`). İlk sürüm kuralları (`:306-307`) çağrı ister; yaprak çağırmaz. AD1 de "Y" sınıfına ulaştığını yazıyor (`:398`). Yapraklara ancak `get`, `set`, `is`, `init` erişir; bunlar "ölçüm adayı"dır (`:295`).
2. **`create` Mac'te neredeyse doğrudan kanıtsız.** `malloc` Mac tmux'ta ilk 25 import arasında yok, Mac htop'ta 5 fonksiyonda. Ayırma iç sarmalayıcıdan geçiyor olmalı **[tahmin]**. O zaman `create` bütünüyle FK1'e bağlıdır. FK1 "gövdenin çağrıları tek bir hedefe iniyor" der (`:324`). Başarısızlıkta programı durduran tipik sarmalayıcı iki hedef çağırır: ayırıcı ve hata bildirimi. Bu sarmalayıcıyı FK1'in tanıyıp tanımadığı doğrulanmadı.
3. **F-ROL listenin başında ama sayılmadı** (`:293`). Üstelik ürettiği rol adlarının çoğu genel fiil sınıfında: `rules.py:213-248`'deki 14 farklı rol adından yalnız üçü (`compare_for_sort`, `compare_for_search`, `cleanup_at_exit`) genel olmayan bir fiil taşıyor. `on_*` ve `handle_signal` genel sınıftadır (`:216`); `thread_main`'in fiili yok. FK8 genel sınıftan ad çıkmasını yasaklar (`:331`). Rubrik, modül + rol adlarında genel rolü `yalniz_alan` sayar (`etiket_rehberi.md:51`); bağlam önekli geri çağrı adları (Y1, `propagate.py:4-5`) tam bu biçimdedir. Fiilsiz ad en çok `yalniz_alan` olur (`etiket_rehberi.md:40`).
4. **"İç çağrı ≤ 3" asıl iş vekili ölçülmemiş** (`:333`). H-N4-4 bunu sınayacak; ama FK2 aynı fonksiyonları F-API'den önceden eliyor (`:325`). Yani hipotezin bir tabakası ürün çıktısında hiç oluşmayabilir. (Bu noktayı codex de buldu; §9.)
5. **F-API'nin nesnesi çoğu zaman yok.** Mac tmux'ta K'nin %57,3'ünde en seçici import ≥ 21 fonksiyonda geçiyor (`:156`). Aynı fiil adı onlarca kez yinelenir; ekler (`_2` …) normalize gösterimde silinir (`etiket_protokolu_v2.md:383`).
6. **Yakın oranının tek dayanağı v1.** API kuralları için "~%50" ve geri çağrı için "%83" sürüm 1 rubriğiyle, yanlış fiil `yalniz_alan` sayılırken ölçüldü (`rules.py:13-14`; `propagate.py:5`; taslak `:274`). v2'de bu oranların düşmesi beklenir; ne kadar düşeceği bilinmiyor.

### 1.3 Senaryolar [tahmin]

Varsayımlar açık yazılı; hiçbiri ölçüm değildir.

| Senaryo | F-API | F-ETKİ (`create`/`destroy`) | F-ROL | N4 toplam | KS-1 ile | 
|---|---|---|---|---|---|
| İyimser: F-API erişiminin %50'si yakın; `free` çağıranların %30'u doğru `destroy` alır ve B4 yakın sayılır; F-ROL %1 | tmux %4,4, htop %6,9 | tmux %5,7, htop %4,2 | tmux %1, htop %0 | tmux ≈ %11, htop ≈ %11 | tmux ≈ %17, htop ≈ %11 |
| Kötümser: F-API %35 yakın; B4 yakın sayılmaz; F-ROL genel fiil | tmux %3,1, htop %4,8 | 0 | 0 | tmux ≈ %3, htop ≈ %5 | tmux ≈ %9, htop ≈ %5 |

- KS-1 kapsamı Mac tmux'ta %5,9, Mac htop'ta 0 (`ks1_olcum.md:43`; `ks1_sonuc.md:34`).
- **%75 hedefi:** N4 ile aritmetik olarak olanaksız. Kusursuz N4'ün tavanı %52,8 / %55,6. Kalan I sınıfı (%47,2 / %44,4) yalnız yayılımla ya da tablo yuvasıyla açılır. Yayılan modül önekinin kesinliği kâhin çapalarla bile %83,5, Karadul çapalarıyla %39,1 (`2026-10-19_g7_alici_tip/rapor.md:77-78`).
- **Kapı 1:** yakın kapsam ≥ tavanın %50'si, yani tavan ≤ 2 × kapsam (`2026-10-21_plan_v2_2.md:72`). Senaryolarla bu, tmux'ta tavanın ≤ %18-34, htop'ta ≤ %10-22 olmasını ister **[hesap]**. Vekil, kütüphane çağrılarını ve dizgileri görüyor (`2026-10-21_n2_onkayit_taslak.md:59-66`). htop'ta tavanın %10'un altında kalacağını gösteren bir veri yok.

## 2. M1, M2, M3 neyi ölçmüyor?

### 2.1 Export fonksiyonları ad bekleyenleri temsil etmiyor

- **Nüfus farklı.** Export'lar static olmayan, yani başka modüllerden çağrılan fonksiyonlardır; isim bekleyenler static'tir (taslak `:593`). Debian htop'ta isim bekleyen 239 fonksiyonun 186'sının doğrudan çağıranı yok (%77,8; `on_sayim.json` cagiran_*_0). Export'ların çağıranı olmayan payı ön sayımda yok; ölçülmedi.
- **Taslağın benzerlik kanıtı yanlış ölçekte.** "K/I/Y dağılımı yakın" diyor (`:593`). K/I/Y çağrı yapısını sayar; fiil dağılımını değil. Y payı da yakın değil: bütün export'larda 71/366 (%19,4), isim bekleyenlerde 29/239 (%12,1) **[hesap; `adli.export_sinif_Y`, sinif_Y]**.
- **Kolay vakalar fazla temsil ediliyor.** Tek sınıflı export adlarında `create` + `destroy` Debian htop'ta 73/263 (%27,8), redis-tools'ta 334/2 127 (%15,7) **[hesap; `export_tekil_fiil_sinifi`]**. Kurucu ve yıkıcılar modül API'sinin doğal parçasıdır, bu yüzden export'ta yoğunlaşır **[tahmin]**. F-ETKİ'nin en kolay hedefi tam da bunlar.
- **Derleyici ve biçim farklı.** M1 yalnız ELF'te (Debian, gcc -O2), M3 yalnız Mac'te (clang -Os) (`:426`; `2026-10-21_plan_v2_2.md:41`). Disassembly kalıplarının aktarımı hiç ölçülmüyor. Mac'te Mach-O'ya özgü kalıplar (ör. derleyicinin dışarı aldığı kod parçaları) plan v2.2'de Faz 2'ye bırakılmış (`:156`); N4 kurallarını nasıl etkilediği doğrulanmadı.
- **F-ROL M1'de ölçülemez.** Kütüphaneye geri çağrı olarak verilen fonksiyonlar genelde static'tir; export'ta az olmaları beklenir **[tahmin]**. n < 10 olursa D4 aileyi mekanik ölçüm olmadan M3'e gönderir (`:518`).

### 2.2 M1'in öldürme ölçütü neyi görmez?

- **Güç düşük.** Gerçekçi n'de M1 yalnız kaba başarısızlığı öldürür: n = 10'da 2 (%20), n = 20'de 3 (%15), n = 35'te 5 (%14,3) karşıt gerekir (`:465-467`). Debian htop'ta ailelerin ad vereceği export sayısı 263'ün çok altında olacak **[tahmin]**.
- **"Farklı" görünmez.** Rubrik yalnız karşıt çiftleri değil, hazırla/uygula karışmasını, ters eylemi ve okuyanı yanıltan her fiili `yanlis` sayar (`etiket_rehberi.md:35, :41-46`). M1'de bunlar "farklı"dır ve eşik değildir (`:461`).
- **"Aynı sınıf ≥ %50" gevşek.** Ailenin yarısı başka fiil verse de aile yaşar.
- **Başvurunun geçerliliği ölçülmedi.** "Export adları 4 224/4 224 doğru" (`:469`) adın GT'ye eşit olduğunu söyler, ad içindeki fiilin davranışı anlattığını değil. Sözlük kaba: `is` sınıfı `check`, `validate`, `verify` gibi denetle-ve-durdur fiillerini `is`, `has` ile birleştiriyor; `set` sınıfı `update`, `store`, `modify`'ı içeriyor (`:188-189`). Kaba sınıf "aynı sınıf" oranını şişirir **[tahmin]**.
- **Nesne, B4 değeri ve "asıl iş" M1'de yok.** M1 yalnız fiil sınıfını karşılaştırır. Yan ayrıntı fiili (`yalniz_alan`) M1'de "aynı sınıf" olarak geçer.

### 2.3 Sızıntı ve kendini doğrulama

- **Tutma okuması M3'ün tazeliğine dokunur.** Debian htop export'ları Mac htop'un isim bekleyenleriyle aynı kaynak fonksiyonlardır (`:460`). Taslak bunu kabul ediyor ve etkisini ölçmüyor (`:596`).
- **Ayar, sözlüğe uyuma göre yapılıyor.** Kurallar redis-tools'ta M1 sonucuna bakılarak düzeltilebilir (`:460`). Ölçüt sözlük sınıfı uyumu olduğu için kurallar rubriğe değil sözlüğe ayarlanır.
- **Aynı model ailesi.** Kural yazarı, değerlendirici ve vekil aynı aileden; programları tanıyor olabilirler (`:598-600`; `2026-10-19_g4_etiketleme/sonuc.md:95`).
- **M2 ile M3 aynı fonksiyonlarda kesişebilir.** Taslak, M2'nin 482 G4 fonksiyonunun N2'nin taze havuzu dışında olduğunu yazıyor (`:475`). Ama N2'nin halef istisnası, N1 sonrası adı değişen ve yeni adı KS-1'den gelmeyen G4 fonksiyonunu yeniden taze sayıyor (`2026-10-21_n2_onkayit_taslak.md:119`). Fiil adı alan bir G4 fonksiyonu bu tanıma girer. Yani kuralların M2'de ayarlandığı fonksiyonlar M3'ün "taze" örnekleminde yeniden çıkabilir. (Codex buldu; dosyadan doğrulandı.)
- **M2'nin evreni dizgiden ad almış 482 fonksiyon** (`:479`). F-ETKİ'nin ateşlediği fonksiyonlarla örtüşmesi bilinmiyor; B4 sorusunu yanlı bir kümede yanıtlar. Değerlendirici tek (`:477`).
- **M3'te htop gücü yok.** Karar aile düzeyinde, iki program birleşik (`:506`); karar tabakalarının çoğu tmux'tan gelir (`:597`; `2026-10-21_n2_onkayit_taslak.md:336`).
- **Karar kuralı ad vermeye eğilimli.** `belirsiz` ad verir (`:502`). n = 35'te 6 yanlış (%17,1) L = %8,1 verir; n = 100'de 15 yanlış (%15) L = %9,3 verir. İkisi de ad verir **[hesap; Wilson, z = 1,96]**. Bu kural N0b'den devralındı (`alt_kanal_onkayit.md:232-239`); yeni değil, ama fiil ailelerinde ürünün %10 bütçesini kolayca aşar.

## 3. "Yanlış fiil": dokuz korumanın yetmediği kalıplar

Hepsi genel C deyimidir. "Kural" sütunu taslaktaki satırı, "M1" sütunu `kunye.karsitlar`'a göre sonucu verir.

| # | Kod kalıbı | Tetiklenen kural | Neden kaçar | Rubrikte | M1'de |
|---|---|---|---|---|---|
| 1 | `int f(T *d, const T *s) { if (!s) return 0; memcpy(d, s, sizeof *d); return 1; }` ya da yan etkisi `memset`, `strlcpy`, `write` gibi bir çağrının içinde kalan, 0/1 dönen her fonksiyon | AD2(a): dönüş 0/1 → `is` (`:399`, "ilk sürümde"); F-ETKİ `is` satırı yalnız "yığın dışına yazma yok" ister (`:311`) | Fonksiyonun kendisi saklama komutu çalıştırmaz; yazma çağrının içindedir. Bellek/dizgi çağrısı F-API'den fiil üretmez, FK2'nin ikinci fiili yoktur (`:325`) | Değiştiren fonksiyona sorgu adı: getter/setter karışması, `yanlis` (`etiket_rehberi.md:42`) | `is`'in karşıtı yok: "farklı" |
| 2 | `void f(T *p) { free(p->a); p->a = NULL; free(p->b); p->b = NULL; p->n = 0; }` (savunmacı temizlik) | `init`: "ayırma yok; parametrenin birden çok ofsetine sabit yazılıyor" (`:308`) | `init` koşulu bırakma çağrısını dışlamıyor. `destroy` ateşlemez, çünkü parametrenin kendisi bırakılmıyor (`:306`); FK2'ye ikinci fiil gelmez | `init` ile `fini` ters eylem: `yanlis` | `init`↔`fini` karşıt. Yakalanır, ama `init` "ölçüm adayı"dır ve `reset` sınıfına düşerse "farklı" olur |
| 3 | `void f(M *m) { dispatch(m); record(m); free(m->buf); free(m); }` (argümanı kullanıp bırakan; olay döngüsü geri çağrılarında yaygın) | `destroy`: alanlar ve sonunda parametre bırakılıyor (`:306`) | FK2'nin büyük gövde sınırı yalnız F-API'ye uygulanır (`:325`). İç çağrılar fiil üretmez; FK2'ye ikinci fiil gelmez | Asıl iş gönderme: `yalniz_alan` (`etiket_rehberi.md:46`); okuyan "yalnız siler" anlarsa `yanlis` | "farklı" |
| 4 | `int f(T *p) { if (setup(p) < 0) { free(p); return -1; } insert(p); return 0; }` (hata kodu dönen yolda sahiplik) | `destroy`: ana yolda bırakma (`:306`) | FK3 hata yolunu yalnız dönmeyen çağrıyla tanımlar (`:73`, `:326`). AD2(b) "hata dalı"nı ayrıca tanımlamıyor, FK3'e gönderiyor (`:399`). Sabit negatif dönüşü hata yolu sayan kural yok; `return -1` yolu ana yol kalır | Ekleyen fonksiyona `destroy`: okuyanı yanıltır, `yanlis` | `add`↔`destroy` karşıt değil: "farklı" |
| 5 | Yönü sabit argüman belirleyen API: `setlocale(c, NULL)` sorgu, `sigaction(s, NULL, &old)` sorgu, `lseek(fd, 0, SEEK_CUR)` konum okuma, `ioctl` istek kodu, `kill(pid, 0)` varlık sınaması | F-API tablosu | AY7 korumasının tablosu yazılmadı (`:300`, `:375`). v0 bu API'leri yönden bağımsız eşliyor: `setlocale` → `set_locale`, `sigaction` → `install_signal_handler`, `kill` → `send_signal`, `sigprocmask` → `block_signals` (`rules.py:104, :97, :92, :110`). `ioctl` istek kodları Darwin ve Linux'ta farklı | get/set karışması: `yanlis` | Yalnız başvuru adında `get`/`set` varsa karşıt |
| 6 | Yeni yığın nesnesi dönen her fonksiyon: ayrıştırıcı, dosyadan okuyup yapı kuran, biçimleyip `malloc`'lu dizgi dönen (sonuna `'\0'` yazan), `realloc` ile büyütüp yeni işaretçiyi dönen | `create`: ayırıcının sonucu dönüyor ve alanlarına yazılıyor (`:307`) | Koşul "dönen nesneyi kim kurdu" ile "işin ne olduğu"nu ayırmıyor; FK1 sarmalayıcıları da ayırıcı sayar (`:314`) | Ayrıştırma ve okumada `yalniz_alan`; büyütmede ve biçimlemede okuyanı yanıltır, `yanlis` olabilir | `parse`, `read`, `resize`↔`create` karşıt değil: "farklı" |
| 7 | Tek çağıranına tümüyle inline edilmiş küçük kurucu ya da yıkıcı | `create` / `destroy`, çağıranda | KS-1'de assert'in yanlış 42 çapasının 40'ı tam bu durumdu (`ks1_sonuc.md:46`). FK5 yalnız yinelenen birliktelik imzasını durdurur (`:328`); tek kullanımlık inline imza tekildir | Çağıranın asıl işi başka: `yalniz_alan` ya da `yanlis` | "farklı" |
| 8 | `void f(N *n, L *l) { n->next = l->head; l->head = n; }` (başa ekleme) | `set`: bir parametre öbürünün sabit ofsetine yazılıyor (`:310`) | `set` koşulu bağlı liste işlemini ayırmıyor | `set_field` ekleyen fonksiyona: büyük olasılıkla `yalniz_alan`, `yanlis` olabilir | `set`↔`add` karşıt değil: "farklı" |

- Kalıp 1, 2 ve 4 en güçlüleri: rubrikte `yanlis`, M1'de çoğu görünmez.
- Kalıp 8 zayıf: `set` ilk sürümde yok (`:295`) ve rubrik sonucu belirsiz.

## 4. Genel nesneli adlar (`free_object`, `get_field`): değer mi, gürültü mü?

- **Rubrik bu biçimi tanımlamıyor.** `dogru_tarif` "fiil ve nesne" ister (`etiket_rehberi.md:33`). `yalniz_alan` "nesne doğru, iş yok" durumudur (`:34`); kural 3 yalnız fiilsiz adı kapsar (`:40`). "İş doğru, nesne yer tutucu" için bir sınıf yok. Sonuç değerlendiricinin takdirine kalır. S8 rubriği B4 kuralı olmadan donduruyor (`:240`); H-N4-5 rubriği değil değerlendiricinin hoşgörüsünü ölçer (`:57`).
- **Simetri bozuk.** Nesnesi doğru ama fiilsiz `kebap_ad` adları %81,1 `yalniz_alan` çıktı (`kesinlik_tablosu.md:19`). Fiili doğru ama nesnesiz B4 adı yakın sayılırsa rubrik fiil lehine asimetrik olur.
- **Değerlendirici yinelenmeyi görmez.** Normalize gösterim `_2` ekini siler (`etiket_protokolu_v2.md:383`). Her yıkıcı kendi paketinde `free_object` olarak görünür; yüz fonksiyonun aynı adı taşıdığı bilinmez.
- **Bilgi miktarı küçük.** İlk sürümde F-ETKİ iki fiil verir (`:295`). B4 adı fonksiyon başına aşağı yukarı bir bitlik bir etiket taşır **[hesap: log2 2]**. Aynı bilgi yorum satırında (ipucu) da verilebilir. Kullanıcıya etkisi ölçülmedi; "değer yok" iddiası doğrulanmadı.
- **Yakın sayılırsa Kapı 1 neyi ödüllendirir?** Fiil sınıfı etiketlemesini ad gibi sayar. Bir ürün kurucu ve yıkıcıların hepsine nesnesiz ad vererek kapsamı büyütebilir. Vekile "kanıt zayıfsa da en iyi adı ver" deniyor (`2026-10-21_n2_onkayit_taslak.md:47`); hoşgörü pay ve paydayı birlikte şişirebilir, oranın yönü bilinmez **[tahmin]**.
- **Öneri:** Kapı 1'de birincil sayı "bilgi taşıyan yakın" olsun: yakın, nesnesi genel listede değil ve ekten önceki adı ikilide tek. B4'lü sayı ikincil raporlansın. Bu bir ölçü tanımı değişikliğidir; Berke'nin kararıdır.

## 5. Aynı emeğe daha çok kapsam ya da kesinlik getiren yollar

| # | Yol | Gerekçe ve dayanak | Mekanik öldürme ölçütü | Taslakla karşılaştırma |
|---|---|---|---|---|
| A1 | **Tablo yuvası rolü** (T1'in işaretçi haritası üstünde) | Doğrudan çağıranı olmayan isim bekleyen: Mac htop %36,2, Mac tmux %30,4, Debian htop %77,8 (`on_sayim.json`). htop'un açığı tablolardan çağrılma (`2026-10-15_isimlendirme_plani.md:48`). T1 yuvaları çıkarıyor (`plan_v2_2.md:83`) ve takvimde N4'le aynı ya da önceki günde (`:139-140`). Aynı yerleşimli tabloların aynı yuvasındaki fonksiyonlar aynı rolü taşır; yuva fiili üyelerin F-ETKİ kanıtının oylamasıyla bulunur. Oylama tek fonksiyonluk hataları (§3 kalıp 1-4) seyreltir ve I sınıfına erişir | (a) GT'siz: Mac htop'ta isim bekleyenlerin yalnız tablolardan başvurulan payı < %15 ise bırak. (b) Geliştirme seti: ≥ 3 üyeli yuvalarda üyelerin GT fiil sınıfının yuva çoğunluğuyla uyumu < %80 ise bırak. (c) M3'te öbür aileler gibi | htop türünde taslağın hiçbir ailesinin erişemediği nüfusa erişir. Riski: T1'in gecikmesi; genel yuva rolleri kural 7 yüzünden `yalniz_alan` olur (`etiket_rehberi.md:51`) |
| A2 | **Assert çapalarını ad değil "içerir" kanıtı olarak kullanmak**; `__FILE__`'dan modül öneki | Assert'in yanlış 42 çapasının 40'ı inline edilmiş fonksiyonun adı (`ks1_sonuc.md:46`). "Bu gövde X'in kodunu içerir" önermesi o 40'ta da doğru; 228 çapanın en az 226'sında doğru **[hesap; kalan 2 doğrulanmadı]**. Assert iletisi kaynak dosyayı da taşır; inline edilen static yardımcı çoğunlukla aynı dosyadandır **[tahmin]** | Geliştirme seti: `__FILE__`'dan çıkan modül, GT'nin bildirim dosyasıyla uyumu < %95 ise bırak. On birimde kapsam < %3 ise bırak | Kesinlik kazandırır; kapsamı küçük: zstd %15,7, redis-tools %3,5, coreutils %0,5; tmux ve htop'ta 0 (`ks1_sonuc.md:26-34`). Kapı 1'in iki Mac programına katkısı yok. **Zayıf alternatif** |
| A3 | **Kesin çapalardan kısıtlı yayılım** (tek çağıranlı yardımcıya modül öneki) | `func_kalibi` Mac tmux'ta 150 çapa, %95,3 (`ks1_olcum.md:43`). Ama tip kümesiyle yayılan modül önekinin kesinliği kâhin çapayla %83,5, Karadul çapasıyla %39,1 (`g7 rapor.md:77-78`); fiil ailesi yayılımı %0 (`propagate.py:11`) | Geliştirme seti: tek çağıranlı yardımcıya yayılan önekin kesinliği < %90 ise bırak | htop'ta çapa yok, etki 0. tmux'ta küçük. Önceki olumsuz sonuçlar yüzünden **zayıf** |
| A4 | **Kütüphane kodunu gövde imzasıyla tanımak** (referans derleme + BSim ya da FID) | Statik bağlı üçüncü taraf kodda ad kesin kurtarılır. Bugünkü 9,2M imza deposu gövdesiz (hafıza `karadul-kullanilabilirlik-2026-10-14.md:35`) | Geliştirme seti: Mac birimlerinde isim bekleyenlerin ≥ %99 kesinlikle eşlenen payı < %5 ise Kapı 1 için bırak | Mac tmux ve htop kütüphaneleri dinamik çağırıyor (`event_*`, `w*` import'ları; `on_sayim.json` en_sik). Kapı 1'e katkısı küçük **[tahmin]**; "IDA'yı geçmek" için ise asıl kaldıraç (§6) |
| A5 | Tip izine öncelik | Tip kümesinden nesne adı %1,6 doğru (`g7 rapor.md:80`); N5 ≥ %90 olmadan girdi yok (`plan_v2_2.md:18`) | N5 < %90 | Mevcut olumsuz sonuç. **Önerilmez** |

- **Sonuç:** htop türü için tek güçlü alternatif A1'dir. A2-A5 Mac programlarında Kapı 1'i değiştirmez. Taslağın F-API'si tmux'ta A2/A3'ten daha çok kapsam getirir; bu noktada taslak haklıdır.

## 6. "IDA Pro'yu geçmek" hangi tanımla gerçekçi?

| Tanım | Gerçekçi mi | Neden |
|---|---|---|
| Strip'li program kodunda üretilen ad sayısı | Evet, ama anlamsız | IDA ve Ghidra strip'li fonksiyona kendiliğinden ad üretmez (`sub_`, `FUN_`); hafıza `karadul-ida-level-zorunluluk.md:35`. KS-1 tek başına Mac tmux'ta %5,9'u %95,3 kesinlikle adlandırıyor (`ks1_olcum.md:43`) |
| Kütüphane kodunda FLIRT + Lumina'yı geçmek | Evet, referans karşılaştırmayla (A4) | Asıl rakip budur (hafıza aynı dosya `:36`). N4 bu tanımda rol oynamaz |
| Program fonksiyonlarının %75'ine yakın ad | Hayır | N4'ün tavanı %52,8 / %55,6 (§1). Hafızaya göre çapraz proje öğrenmeli adlandırmada F1 ≈ 0,46 (`karadul-ida-level-zorunluluk.md:37`; birincil kaynak bu incelemede doğrulanmadı) |

**Önerilen ölçülebilir tanım (öneri; karar Berke'nin):** Kilitli test setinde, strip'li Mac ve Debian arm64 ikililerinde, aynı ikilide IDA 9.x (FLIRT, Lumina erişilebiliyorsa o da) ile Karadul yan yana koşulur. İki katman ayrı raporlanır:
1. **Kütüphane katmanı:** statik bağlı üçüncü taraf fonksiyonlarda tam ad duyarlılığı, kesinlik ≥ %95 iken. Hedef: IDA'nın duyarlılığından yüksek.
2. **Program katmanı:** isim bekleyen program fonksiyonlarında, kör rubrik v2 ile yanlış ≤ %10 iken "bilgi taşıyan yakın" kapsam (§4), program başına ve makro. IDA'nın aynı ölçüdeki değeri (büyük olasılıkla ≈ 0) yanında yazılır.

"IDA'yı geçti" iddiası iki katmanda birlikte geçerse kurulur. %75 program katmanında hedef olarak yazılırsa N4 ve N6'nın aritmetik tavanıyla birlikte yazılmalıdır.

## 7. Karar öncesi en ucuz üç ölçüm

1. **Riskli deyim sayımı (GT'siz, ajansız; `on_sayim.py`'ye sayaç).** İsim bekleyenlerde: (a) bütün dönüşleri 0/1 olan ve en az bir çağrı yapan fonksiyonlar (kalıp 1); (b) parametre alanını bırakıp en az iki ofsetine sabit yazan, parametreyi bırakmayanlar (kalıp 2); (c) parametreyi bırakan ve başka çağrı da yapanlar (kalıp 3); (d) parametreyi yalnız dönen bir hata yolunda bırakanlar (kalıp 4); (e) `create`/`destroy` kurallarının ateşleme sayısı ve ekten önceki adların tekil oranı. **Ölçüt:** (a)-(d) bir ailenin ateşlemelerinin > %25'iyse aile M1'e girmeden yeni koruma alır. Mac htop'ta `create` + `destroy` ateşlemesi isim bekleyenlerin < %5'iyse B4 sorusu htop'un Kapı 1 sonucunu değiştirmez.
2. **M1 temsil denetimi (GT'siz; ad gerekmez).** Debian htop ve redis-tools export'larında, Debian htop ve Mac htop isim bekleyenlerinde aynı yapısal sayaçlar: doğrudan çağıranı olmayan pay, boyut, (1)'deki deyim oranları. **Ölçüt:** bir ailenin ateşleme oranı export ile isim bekleyen arasında [0,5; 2] dışındaysa ya da çağıransız pay 30 puandan çok farklıysa M1 yalnız akıl sağlığı denetimi olur, öldürme dayanağı olmaz. Ek: Mac tarafında mekanik evren olarak `func_kalibi` çapaları (Mac tmux 150; `ks1_olcum.md:43`). Bunlar static, Mach-O ve ürünün kendi adlarıdır; taslakta "isteğe bağlı" (`:471`).
3. **Geliştirme setinde fiil tavanı (ayrı oturum, yalnız toplu sayı).** Mac tmux ve Mac htop isim bekleyenlerinde GT adının tek sözlük sınıfı taşıdığı pay; sınıf × K/I/Y kırılımıyla. Taslağın export'larda yaptığı sayımın aynısı. **Ölçüt:** Mac htop'ta `create` + `destroy` sınıflı ad payı küçükse (eşik önceden yazılır; öneri %8) F-ETKİ'nin ilk sürümü htop'ta Kapı 1'i değiştiremez; iki gün A1'e verilir.

## 8. Taslak yine de sürdürülecekse değişmesi gereken beş şey

1. **Karşıt listesini rubriğin yanlış saydığı karışmalara genişlet; önceden kaydet.** Önerilen ek çiftler: `is` ↔ değiştiren her sınıf (`set`, `write`, `add`, `remove`, `create`, `destroy`, `init`, `start`, `stop`, `run`); `init` ↔ `reset`; `destroy` ↔ `add`, `remove`, `set`; `create` ↔ `resize`. M1'de "farklı" çift başına raporlansın; riskli çiftler öldürme ölçütüne girsin.
2. **Korumaları deyimlere göre sıkılaştır.** AD2(a) `is`'i ilk sürümden çıkar ya da çağrısız ve saklamasız yapraklarla sınırla. `init` koşuluna "bırakma çağrısı yok" ekle. FK2'nin büyük gövde sınırını ve hata yolunu F-ETKİ'ye de uygula. FK3'ün hata yolu tanımına "başarısız sınamadan sonra sabit hata değeri dönen yol"u ekle. FK1'i "ayırıcı + hata bildirimi" sarmalayıcısını kapsayacak biçimde yaz.
3. **B4 kararını ölçümden önce ver** (S7, S8). Ya B4 yalnız ipucu olur, ya rubrik sürüm 3'e "nesnesiz fiil en çok `yalniz_alan`" kuralı girer. Kapı 1'de "bilgi taşıyan yakın" birincil sayı olur (§4).
4. **İç çelişkileri gider.**
   - B5 örneği `handle_signal` (`:232`) ile FK8 ve sözlükte genel sınıf (`:216`, `:331`).
   - AD2(a) "ilk sürümde" (`:399`) ile F-ETKİ'nin ilk sürümü yalnız `create`, `destroy` (`:295`, `:315`).
   - §6.8'deki F-ETKİ havuzunda yapraklar (`:538`) ile ilk sürüm kurallarının çağrı istemesi (`:306-307`); AD1'de "Y" (`:398`).
   - "Fiilin hiç ulaşamadığı I sınıfı" (`:539`) ile FK1 sarmalayıcılarının bırakıcı/ayırıcı sayılması (`:314`).
5. **htop türünü ayrıca ele al.** Tablo yuvası rolünü T1 çıktısıyla dördüncü aile yap ya da en az GT'siz erişimini ölç (§5 A1). M1'e Mac tarafında `func_kalibi` çapalarını zorunlu evren olarak ekle. §6.8'e Kapı 1'in aritmetik koşulunu (tavan ≤ 2 × kapsam) ve %75'in N4 tavanının üstünde kaldığını yaz.

## 9. Codex çağrısı ve denetim

**Durum: codex nihai yanıt üretemedi. Bu belgedeki itirazları Claude (Opus) yazdı.** Codex'in ara notlarından yalnız dosyadan doğrulananlar alındı ve yerinde "codex buldu" diye işaretlendi.

| Çağrı | Çalışma dizini (depo dışı) | Ayar | Çıkış | Sonuç |
|---|---|---|---|---|
| 1 | `/tmp/codex-80406-1794311596-7257/` | `xhigh`, `timeout 600`, `-s read-only`, `< /dev/null` | 124 (zaman aşımı) | `response.txt` yok. Okumayı bitirdi, son yanıtı yazarken durdu (günlüğün son yazımı 15:01, sonlanma 15:03). Günlük: `stderr_xhigh.log` |
| 2 | `/tmp/codex-95405-1794312260-23650/` | `high`, aynı sarmalama, daha kısa çıktı istemi | 1 | Kullanım sınırı hatası ("usage limit … try again at 8:01 PM"); yanıt yok. Günlük: `stderr.log` |

- Kural gereği 124'ten sonra bir kez `high` ile yinelendi; ikinci çağrı da düştüğü için üçüncü deneme yapılmadı.
- **Komut denetimi:** iki günlükte 25 + 14 kabuk komutu var. Hepsi istemde izin verilen belgeleri ve kodu okuyor (`nl`, `sed`, `rg`, `wc`). GT, kilitli veri, `static/`, `workspaces/` ya da yasak dizinlere erişim yok. Betik, Karadul ya da Ghidra koşulmadı.
- **Codex'in ara notlarından alınanlar** (birinci çağrının günlüğü):
  1. Taslağın §6.8 havuzlarının toplamı, hepsi doğru sayılsa bile Mac tmux'ta %43,8, Mac htop'ta %49,7. Doğrulandı: (229 + 416 + 489) / 2 587 ve (82 + 102 + 113) / 597 **[hesap]**. Codex'in uyarısı yerinde: F-ROL sayılmadığı ve sarmalayıcı erişimi bu havuzla örtüşmediği için bu kesin bir tavan değildir. Bu belgedeki tavan (K ∪ Y, §1.1) daha geniştir.
  2. Karar kuralı yanlış oranının %10'un altında olduğunu kanıtlamayı değil, %10'u aştığı kanıtlanmayan aileyi açmayı öngörüyor. Doğrulandı (`fiil_onkayit_taslak.md:502`); §2.3'teki hesap.
  3. M2 ile M3'ün halef istisnası üzerinden kesişmesi. Doğrulandı (`:475`; `2026-10-21_n2_onkayit_taslak.md:119`); §2.3.
  4. H-N4-4 (`:56`), FK2 büyük gövdeleri F-API'den önceden elediği için (`:325`, `:333`) önerilen örneklemde sınanamayabilir. Doğrulandı; §1.2 madde 4.
  5. Veri akışı bağı çağrının asıl iş olduğunu kanıtlamaz: sonunda `free` olan yerinde güncelleme, yeni nesne dönen ayrıştırıcı, `return -1` ile biten hata dalı. §3'teki kalıp 3, 4 ve 6 ile aynı.
- **Takım tartışma dosyası:** `~/.claude/team-state/discussion.md`'nin son 80 satırı okundu; başka işlere ait. Görevin "tek dosya" kısıtı gereği o dosyaya yazılmadı.
